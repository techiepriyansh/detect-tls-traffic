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

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);

    if (dport == 443) {
        bpf_trace_printk("  Sent to server\n");
    }

    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);

    if (dport == 443) {
        bpf_trace_printk("  Recvd from server %d\n", copied);
    }

    return 0;   
}

//XDP filter helper functions
static inline void parse_tcp(void *data, void *data_end) {
	struct tcphdr *tcph = data;
	if ((void*)&tcph[1] <= data_end) {
		if (tcph->source == htons(443)) {
			bpf_trace_printk("    Raw Packet\n");	
		}
	}
}

static inline void parse_ipv4(void *data, void *data_end) {
    struct iphdr *iph = data;
    if ((void*)&iph[1] <= data_end) {
		if (iph->protocol == IPPROTO_TCP) {
			parse_tcp((void*)&iph[1], data_end);
		}
	}
}

static inline void parse_ipv6(void *data, void *data_end) {
    struct ipv6hdr *ip6h = data;
    if ((void*)&ip6h[1] <= data_end) {
		if (ip6h->nexthdr == IPPROTO_TCP) {
			parse_tcp((void*)&ip6h[1], data_end);
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
			parse_ipv4(data + nh_off, data_end);
		} else if (h_proto == ETH_P_IPV6) {
			parse_ipv6(data + nh_off, data_end);
		}
	}
	
	return XDP_PASS;
}
