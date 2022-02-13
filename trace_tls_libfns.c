#include <linux/bpf.h>
#include <linux/sched.h>
#include <linux/tcp.h>
#include <net/sock.h>

#define PERF_EVENT_TLS_LIB_FN_ENTER  1
#define PERF_EVENT_TLS_LIB_FN_EXIT   2

__PY_ARRAY_OF_STACKS_DEFINITION__

// map holding the index of function stacks of processes corresponding to their PIDs
// in the array of functions stacks map
BPF_HASH(pid_fn_stack_arr_idx_map, u32, int);

// global variable to hold the next index available in pid_fn_stack_arr_idx_map
BPF_ARRAY(next_idx, int, 1);

// a set containing possible library functions responsible for TLS read/write
BPF_HASH(possible_rw_fns, u32, u8);

// struct for storing the trace output to be sent to the userspace
struct perf_output_t {
	u32 fn_id;
};

BPF_PERF_OUTPUT(tls_libfn_trace_event);

// generic internal handler for TLS library function uprobes and uretprobes 
static inline void on_tls_lib_fn_enter_exit(struct pt_regs *ctx, u32 fn_id, u8 perf_event)
{
	u32 pid = bpf_get_current_pid_tgid();

	// get the fn_stack for this process
	// if it doesn't exist, assign one
	void *fn_stack;
	int *val;
	val = pid_fn_stack_arr_idx_map.lookup(&pid);
	if (val == NULL) {
		// don't assign a stack if this event is a lib fn exit
		if (perf_event == PERF_EVENT_TLS_LIB_FN_EXIT)
			return;

		int key_zero = 0;
		int *curr_idx = next_idx.lookup(&key_zero);
		if (curr_idx == NULL)
			return;

		fn_stack = fn_stack_arr.lookup(curr_idx);
		if (fn_stack == NULL)
			return;

		pid_fn_stack_arr_idx_map.update(&pid, curr_idx);
		next_idx.increment(key_zero);
	} else {
		fn_stack = fn_stack_arr.lookup(val);
		if (fn_stack == NULL)
			return;
	}

	// update the fn_stack depending upon the event
	if (perf_event == PERF_EVENT_TLS_LIB_FN_ENTER) {
		bpf_map_push_elem(fn_stack, &fn_id, 0);
	} else if (perf_event == PERF_EVENT_TLS_LIB_FN_EXIT) {
		u32 fn_stack_top;
		int ret;
		int ctr = 0;
		do {
			ret = bpf_map_pop_elem(fn_stack, &fn_stack_top);
			if (ret != 0)
				return;
			ctr++;
		} while (fn_stack_top != fn_id && ctr <= MAX_STACK_DEPTH);
	} 
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

// generic internal handler for tcp_sendmsg and tcp_cleanup_rbuf kprobes
static inline void on_tcp_send_recv(struct pt_regs *ctx, struct sock *sk)
{
	if (!is_tls(sk))
		return;

	u32 pid = bpf_get_current_pid_tgid();
	int *idx = pid_fn_stack_arr_idx_map.lookup(&pid);
	if (idx == NULL)
		return;

	void *fn_stack;
	fn_stack = fn_stack_arr.lookup(idx);
	if (fn_stack == NULL)
		return;
	
	u32 fn_id;
	int ret = bpf_map_peek_elem(fn_stack, &fn_id);
	if (ret != 0)
		return;

	u8 *val = possible_rw_fns.lookup(&fn_id);
	if (val != NULL)
		return;

	u8 _true = 1;
	possible_rw_fns.update(&fn_id, &_true);

	struct perf_output_t perf_output = {};
	perf_output.fn_id = fn_id;
	tls_libfn_trace_event.perf_submit(ctx, &perf_output, sizeof(perf_output));
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size) 
{
	on_tcp_send_recv(ctx, sk);
	return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
	on_tcp_send_recv(ctx, sk);
	return 0;
}

__PY_EXTERNAL_WRAPPERS__

