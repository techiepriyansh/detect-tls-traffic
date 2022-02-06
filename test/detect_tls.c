#include <uapi/linux/ptrace.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

// contains information about a TCP connection
struct tcpaddr_t {
	u16 family; // AF_INET or AF_INET6
	u8 saddr[16];
	u8 daddr[16];
	u16 lport;
	u16 dport;

};

// struct for storing the trace output to be sent to the userspace 
struct perf_output_t {
	u32 pid;
	char name[TASK_COMM_LEN];	
	struct tcpaddr_t tcpaddr;
	u8 flags;
		// flags = 1 if using not using OpenSSL for sending TLS data
};

BPF_HASH(inside_ssl_io_fn, u32, u8);
BPF_HASH(pid_tcpaddr_map, u32, struct tcpaddr_t);

BPF_PERF_OUTPUT(tls_trace_event);

// hook to SSL_read[_ex], SSL_write[_ex], SSL_do_handshake, SSL_peek[_ex], SSL_shutdown
int hook_to_SSL_IO_fn(struct pt_regs *ctx) {
	u32 pid;
	pid = bpf_get_current_pid_tgid();

	// due to a bug in the map.update function for kernel versions before 4.8
	u8 *val = inside_ssl_io_fn.lookup(&pid);
	if (val != NULL) 
		inside_ssl_io_fn.delete(&pid);

	u8 _true = 1;
	inside_ssl_io_fn.update(&pid, &_true);
	
	// reset the tcpaddr value
	struct tcpaddr_t *tcpaddr = pid_tcpaddr_map.lookup(&pid); 
	if (tcpaddr != NULL)
		pid_tcpaddr_map.delete(&pid);

	return 0;
}

// hook to SSL_read[_ex], SSL_write[_ex], SSL_do_handshake, SSL_peek[_ex], SSL_shutdown return
int hookret_to_SSL_IO_fn(struct pt_regs *ctx) {
	u32 pid;
	pid = bpf_get_current_pid_tgid();

	u8 *val = inside_ssl_io_fn.lookup(&pid);
	if (val == NULL)
		return 1;

	u8 _false = 0;
	inside_ssl_io_fn.delete(&pid); // has to be done due to a bug in map.update
	inside_ssl_io_fn.update(&pid, &_false);

	struct tcpaddr_t *tcpaddr = pid_tcpaddr_map.lookup(&pid);
	if (tcpaddr != NULL) {
		struct perf_output_t perf_output = {};

		perf_output.pid = pid;
		bpf_get_current_comm(&perf_output.name, sizeof(perf_output.name));
		perf_output.tcpaddr = *tcpaddr;
		perf_output.flags = 0;

		tls_trace_event.perf_submit(ctx, &perf_output, sizeof(perf_output));
	}

	return 0;
}

// helper function to determine if the packet is (should be) a TLS packet or not
// currently just checks if any of the dport or lport is 443
int static inline is_tls(struct sock *sk) 
{
    u16 dport = 0, lport = 0, family = sk->__sk_common.skc_family;

	if (family == AF_INET || family == AF_INET6) {
		lport = sk->__sk_common.skc_num;

		dport = sk->__sk_common.skc_dport;
		dport = ntohs(dport);
		
		if (dport == 443 || lport == 443)
			return 1;
	}

	return 0;
}

static inline int parse_tcpaddr(struct sock *sk, struct tcpaddr_t *tcpaddr)
{
	u16 dport = 0, family = sk->__sk_common.skc_family;
	
	tcpaddr->family = family;

	if (family == AF_INET) {
		bpf_probe_read_kernel(&tcpaddr->saddr, 4, &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&tcpaddr->daddr, 4, &sk->__sk_common.skc_daddr);
		tcpaddr->lport = sk->__sk_common.skc_num;
		
		dport = sk->__sk_common.skc_dport;
		tcpaddr->dport = ntohs(dport);
		
		return 1; // parsed successfully 
	} else if (family == AF_INET6) {
		bpf_probe_read_kernel(&tcpaddr->saddr, sizeof(tcpaddr->saddr),
			&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&tcpaddr->daddr, sizeof(tcpaddr->daddr),
			&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		tcpaddr->lport = sk->__sk_common.skc_num;

		dport = sk->__sk_common.skc_dport;
		tcpaddr->dport = ntohs(dport);

		return 1; // parsed successfully 
	}

	return 0; // could not parse successfully
}

// internal function for kprobing tcp kernel calls: tcp_sendmsg and tcp_clean_rbuf
static inline int hook_to_tcp_kernel_call_internal(struct pt_regs *ctx, struct sock *sk)
{
	if (!is_tls(sk))
		return 0;

	u32 pid;
	pid = bpf_get_current_pid_tgid();
	
	u8 *is_inside_ssl_io_fn  = inside_ssl_io_fn.lookup(&pid);
	if (is_inside_ssl_io_fn == NULL || !(*is_inside_ssl_io_fn)) {
		// not using the OpenSSL library for TLS
		// send this information to userspace
		struct tcpaddr_t tcpaddr = {};
		if (parse_tcpaddr(sk, &tcpaddr)) {
			struct perf_output_t perf_output = {};

			perf_output.pid = pid;
			bpf_get_current_comm(&perf_output.name, sizeof(perf_output.name));
			perf_output.tcpaddr = tcpaddr;
			perf_output.flags = 1;

			tls_trace_event.perf_submit(ctx, &perf_output, sizeof(perf_output));
		}
		return 0;
	}

	struct tcpaddr_t *val = pid_tcpaddr_map.lookup(&pid);
	if (val != NULL)
		return 0; // already accounted for the current ssl fn's tcpaddr

	// if this tcp kernel call is the first one inside the current ssl fn's invocation,
	// store the tcpaddr information
	struct tcpaddr_t tcpaddr = {};
	if (parse_tcpaddr(sk, &tcpaddr)) {
		pid_tcpaddr_map.update(&pid, &tcpaddr);
	}

    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
	return hook_to_tcp_kernel_call_internal(ctx, sk);
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
	return hook_to_tcp_kernel_call_internal(ctx, sk);   
}

//XDP filter helper functions
static inline void handle_tcp(void *data, void *data_end) 
{
	struct tcphdr *tcph = data;
	if ((void*)&tcph[1] <= data_end) {
		if (tcph->source == htons(443)) {
			bpf_trace_printk("    Raw Packet\n");	
		}
	}
}

static inline void handle_ipv4(void *data, void *data_end) 
{
    struct iphdr *iph = data;
    if ((void*)&iph[1] <= data_end) {
		if (iph->protocol == IPPROTO_TCP) {
			handle_tcp((void*)&iph[1], data_end);
		}
	}
}

static inline void handle_ipv6(void *data, void *data_end) 
{
    struct ipv6hdr *ip6h = data;
    if ((void*)&ip6h[1] <= data_end) {
		if (ip6h->nexthdr == IPPROTO_TCP) {
			handle_tcp((void*)&ip6h[1], data_end);
		}
	}
}

// XDP filter functions
int ingress_tls_filter(struct xdp_md *ctx)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    u64 nh_off = 0;
    nh_off = sizeof(*eth);

    if (data + nh_off  <= data_end) {
		u16 h_proto;
		h_proto = eth->h_proto;
		
		// parse vlan header
		#pragma unroll
		for (int i=0; i<2; i++) {
			if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
				struct vlan_hdr *vhdr;
				vhdr = data + nh_off;
				nh_off += sizeof(struct vlan_hdr);
				if (data + nh_off <= data_end) {
					h_proto = vhdr->h_vlan_encapsulated_proto;
				}
			}
		}

		if (h_proto == htons(ETH_P_IP)) {
			handle_ipv4(data + nh_off, data_end);
		} else if (h_proto == ETH_P_IPV6) {
			handle_ipv6(data + nh_off, data_end);
		}
	}
	
	return XDP_PASS;
}

/*
// Hooks to OpenSSL library functions
int hook_to_SSL_CTX_new(struct pt_regs *ctx) {
    bpf_trace_printk("New SSL Context\n");
    return 0;
}

int hook_to_SSL_set_fd(struct pt_regs *ctx) {
    int socket_fd = PT_REGS_PARM2(ctx); 
    bpf_trace_printk("Set Socket %d\n", socket_fd);
    return 0;
}

int hook_to_SSL_do_handshake(struct pt_regs *ctx) {
    bpf_trace_printk("Handshake\n");
    return 0;
}

int hookret_to_SSL_do_handshake(struct pt_regs *ctx) {
    bpf_trace_printk("Handshake Return\n");
    return 0;
}

int hook_to_SSL_read(struct pt_regs *ctx, void * ssl, void *buf, int num) {
    bpf_trace_printk("Read\n");
    return 0;
}

int hookret_to_SSL_read(struct pt_regs *ctx) {
    bpf_trace_printk("Read Return %d\n", PT_REGS_RC(ctx));
    return 0;
}

int hook_to_SSL_read_ex(struct pt_regs *ctx) {
    bpf_trace_printk("Read (ex)\n");
    return 0;
}

int hook_to_SSL_peek(struct pt_regs *ctx, void * ssl, void *buf, int num) {
    bpf_trace_printk("Peek\n");
    return 0;
}

int hookret_to_SSL_peek(struct pt_regs *ctx) {
    bpf_trace_printk("Peek Return\n");
    return 0;
}

int hook_to_SSL_write(struct pt_regs *ctx) {
    bpf_trace_printk("Write\n");
    return 0;
}

int hookret_to_SSL_write(struct pt_regs *ctx) {
    bpf_trace_printk("Write Return\n");
    return 0;
}

int hook_to_SSL_write_ex(struct pt_regs *ctx) {
    bpf_trace_printk("Write (ex)\n");
    return 0;
}

// Hooks to kernel tcp functions
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    bpf_trace_printk("TCP Connect\n");
    return 0;
}
*/





