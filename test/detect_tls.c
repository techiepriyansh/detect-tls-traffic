#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>


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

