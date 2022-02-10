#include <linux/sched.h>
#include <linux/tcp.h>
#include <net/sock.h>

#define PERF_EVENT_TLS_LIB_FN_ENTER  1
#define PERF_EVENT_TLS_LIB_FN_EXIT   2
#define PERF_EVENT_TCP_SEND          3
#define PERF_EVENT_TCP_RECV          4

struct perf_output_t {
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 fn_id;
	u8 perf_event;
};

BPF_PERF_OUTPUT(tls_libfn_trace_event);

static inline void send_perf_output(struct pt_regs *ctx, u32 fn_id, u8 perf_event)
{
	struct perf_output_t perf_output = {};

	perf_output.pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&perf_output.comm, sizeof(perf_output.comm));
	perf_output.fn_id = fn_id;
	perf_output.perf_event = perf_event;

	tls_libfn_trace_event.perf_submit(ctx, &perf_output, sizeof(perf_output)); 

}

// helper function to determine if the packet is (should be) a TLS packet or not
// currently just checks if any of the rport or lport is 443
static inline int is_tls(struct sock *sk) 
{
    u16 rport = 0, lport = 0, family = sk->__sk_common.skc_family;

	if (family == AF_INET || family == AF_INET6) {
		lport = sk->__sk_common.skc_num;

		rport = sk->__sk_common.skc_dport;
		rport = ntohs(rport);
		
		if (rport == 443 || lport == 443)
			return 1;
	}

	return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size) 
{
	if (!is_tls(sk))
		return 0;

	send_perf_output(ctx, 0, PERF_EVENT_TCP_SEND); 
	return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
	if (!is_tls(sk))
		return 0;

	send_perf_output(ctx, 0, PERF_EVENT_TCP_RECV);
	return 0;
}

__PY_EXTERNAL_WRAPPERS__

