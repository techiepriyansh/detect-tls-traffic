#!/usr/bin/python3

from bcc import BPF
from bcc.utils import printb

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>


int hook_to_SSL_CTX_new(struct pt_regs *ctx) {
    bpf_trace_printk("New SSL Context\\n");
    return 0;
}

int hook_to_SSL_set_fd(struct pt_regs *ctx) {
    int socket_fd = PT_REGS_PARM2(ctx); 
    bpf_trace_printk("Set Socket %d\\n", socket_fd);
    return 0;
}

int hook_to_SSL_do_handshake(struct pt_regs *ctx) {
    bpf_trace_printk("Handshake\\n");
    return 0;
}

int hookret_to_SSL_do_handshake(struct pt_regs *ctx) {
    bpf_trace_printk("Handshake Return\\n");
    return 0;
}

int hook_to_SSL_read(struct pt_regs *ctx, void * ssl, void *buf, int num) {
    bpf_trace_printk("Read\\n");
    return 0;
}

int hookret_to_SSL_read(struct pt_regs *ctx) {
    bpf_trace_printk("Read Return %d\\n", PT_REGS_RC(ctx));
    return 0;
}

int hook_to_SSL_read_ex(struct pt_regs *ctx) {
    bpf_trace_printk("Read (ex)\\n");
    return 0;
}

int hook_to_SSL_write(struct pt_regs *ctx) {
    bpf_trace_printk("Write\\n");
    return 0;
}

int hookret_to_SSL_write(struct pt_regs *ctx) {
    bpf_trace_printk("Write Return\\n");
    return 0;
}

int hook_to_SSL_write_ex(struct pt_regs *ctx) {
    bpf_trace_printk("Write (ex)\\n");
    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    bpf_trace_printk("TCP Connect\\n");
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);

    if (dport == 443) {
        bpf_trace_printk("  Sent to server\\n");
    }

    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);

    if (dport == 443) {
        bpf_trace_printk("  Recvd from server\\n");
    }

    return 0;   
}
"""

libfns = [
    "SSL_CTX_new", 
    "SSL_set_fd", 
    "SSL_do_handshake", 
    "SSL_get_verify_result", 
    "SSL_read", 
    "SSL_read_ex",
    "SSL_write",
    "SSL_write_ex",
    "SSL_accept",
]

'''
Simply detecting these functions calls would only ascertain that these functions were called.
To make sure that a connection happened successfully, we can use these approaches:
    - Detect one of SSL_get_peer_certificate of SSL_get_verify_result after we detect SSL_do_handshake
    - Detect SSL_read(s)
'''

b = BPF(text=prog)
b.attach_uprobe(name="ssl", sym=libfns[0], fn_name="hook_to_SSL_CTX_new")
b.attach_uprobe(name="ssl", sym=libfns[1], fn_name="hook_to_SSL_set_fd")
b.attach_uprobe(name="ssl", sym=libfns[2], fn_name="hook_to_SSL_do_handshake")
b.attach_uprobe(name="ssl", sym=libfns[4], fn_name="hook_to_SSL_read")
b.attach_uprobe(name="ssl", sym=libfns[5], fn_name="hook_to_SSL_read_ex")
b.attach_uprobe(name="ssl", sym=libfns[6], fn_name="hook_to_SSL_write")
b.attach_uprobe(name="ssl", sym=libfns[7], fn_name="hook_to_SSL_write_ex")

b.attach_uretprobe(name="ssl", sym=libfns[2], fn_name="hookret_to_SSL_do_handshake");
b.attach_uretprobe(name="ssl", sym=libfns[4], fn_name="hookret_to_SSL_read")
b.attach_uretprobe(name="ssl", sym=libfns[6], fn_name="hookret_to_SSL_write")

print("Starting to trace...", flush=True)
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
