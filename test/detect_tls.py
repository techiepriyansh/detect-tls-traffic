#!/usr/bin/python3

import sys

from bcc import BPF
from bcc.utils import printb

libfns = [
    "SSL_CTX_new", 
    "SSL_set_fd", 
    "SSL_do_handshake", 
    "SSL_get_verify_result", 
    "SSL_read", 
    "SSL_read_ex",
    "SSL_write",
    "SSL_write_ex",
    "SSL_peek",
    "SSL_accept",
]

'''
Simply detecting these functions calls would only ascertain that these functions were called.
To make sure that a connection happened successfully, we can use these approaches:
    - Detect one of SSL_get_peer_certificate of SSL_get_verify_result after we detect SSL_do_handshake
    - Detect SSL_read(s)
'''
device = sys.argv[1]

b = BPF(src_file="detect_tls.c")
b.attach_uprobe(name="ssl", sym=libfns[0], fn_name="hook_to_SSL_CTX_new")
b.attach_uprobe(name="ssl", sym=libfns[1], fn_name="hook_to_SSL_set_fd")
b.attach_uprobe(name="ssl", sym=libfns[2], fn_name="hook_to_SSL_do_handshake")
b.attach_uprobe(name="ssl", sym=libfns[4], fn_name="hook_to_SSL_read")
b.attach_uprobe(name="ssl", sym=libfns[5], fn_name="hook_to_SSL_read_ex")
b.attach_uprobe(name="ssl", sym=libfns[6], fn_name="hook_to_SSL_write")
b.attach_uprobe(name="ssl", sym=libfns[7], fn_name="hook_to_SSL_write_ex")
b.attach_uprobe(name="ssl", sym=libfns[8], fn_name="hook_to_SSL_peek")

b.attach_uretprobe(name="ssl", sym=libfns[2], fn_name="hookret_to_SSL_do_handshake");
b.attach_uretprobe(name="ssl", sym=libfns[4], fn_name="hookret_to_SSL_read")
b.attach_uretprobe(name="ssl", sym=libfns[6], fn_name="hookret_to_SSL_write")
b.attach_uretprobe(name="ssl", sym=libfns[8], fn_name="hookret_to_SSL_peek")

fn = b.load_func("ingress_tls_filter", BPF.XDP)
b.attach_xdp(device, fn)

print("Starting to trace...", flush=True)
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

b.remove_xdp(device)
