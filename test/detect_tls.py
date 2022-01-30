#!/usr/bin/python3

from bcc import BPF
from bcc.utils import printb

prog = """
int hook_to_SSL_CTX_new(void *ctx) {
    bpf_trace_printk("New Context\\n");
    return 0;
}

int hook_to_SSL_do_handshake(void *ctx) {
    bpf_trace_printk("Handshake\\n");
    return 0;
}

int hook_to_SSL_read(void *ctx) {
    bpf_trace_printk("Read\\n");
    return 0;
}

int hook_to_SSL_read_ex(void *ctx) {
    bpf_trace_printk("Read (ex)\\n");
    return 0;
}
"""

libfns = ["SSL_CTX_new", "SSL_do_handshake", "SSL_get_verify_result", "SSL_read", "SSL_read_ex", "SSL_accept"]

'''
Simply detecting these functions calls would only ascertain that these functions were called.
To make sure that a connection happened successfully, we can use these approaches:
    - Detect one of SSL_get_peer_certificate of SSL_get_verify_result after we detect SSL_do_handshake
    - Detect SSL_read(s)
'''

b = BPF(text=prog)
b.attach_uprobe(name="ssl", sym=libfns[0], fn_name="hook_to_SSL_CTX_new")
b.attach_uprobe(name="ssl", sym=libfns[1], fn_name="hook_to_SSL_do_handshake")
b.attach_uprobe(name="ssl", sym=libfns[3], fn_name="hook_to_SSL_read")
b.attach_uprobe(name="ssl", sym=libfns[4], fn_name="hook_to_SSL_read_ex")


print("Starting to trace...")

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
