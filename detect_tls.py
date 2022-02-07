#!/usr/bin/python3

import sys
import os
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
import ctypes as ct
import json

# get the directory of the folder which contains this script
base_path = os.path.dirname(os.path.realpath(__file__))

# read bpf c source code
with open(base_path + "/detect_tls.c", "rt") as f:
    bpf_prog_text = f.read()

# read and parse config.json
with open(base_path + "/config.json") as f:
    tls_libs = json.load(f)

# compile bpf program and attach probes
b = BPF(text=bpf_prog_text)

for lib in tls_libs:
    libname = lib["name"]
    for libfn in lib["functions"]:
        b.attach_uprobe(name=libname, sym=libfn, fn_name="hook_to_SSL_IO_fn")
        b.attach_uretprobe(name=libname, sym=libfn, fn_name="hookret_to_SSL_IO_fn")

# attach XDP Filter if opted
device = None
if len(sys.argv) > 1:
    device = sys.argv[1]
    fn = b.load_func("ingress_tls_filter", BPF.XDP)
    b.attach_xdp(device, fn)

# handle print event coming from the bpf program
def print_event(cpu, data, size):
    TASK_COMM_LEN = 16 # in linux/sched.h

    class tcpaddr_t(ct.Structure):
        _fields_ = [ ("family", ct.c_uint16),
                     ("laddr", ct.c_uint8 * 16),
                     ("raddr", ct.c_uint8 * 16),
                     ("lport", ct.c_uint16),
                     ("rport", ct.c_uint16) ]

    class perf_output_t(ct.Structure):
        _fields_ = [ ("pid", ct.c_uint32),
                     ("name", ct.c_char * TASK_COMM_LEN),
                     ("tcpaddr", tcpaddr_t),
                     ("flags", ct.c_uint8) ]

    event = ct.cast(data, ct.POINTER(perf_output_t)).contents
    
    local_ip, remote_ip = None, None
    if event.tcpaddr.family == AF_INET:
        local_ip = inet_ntop(event.tcpaddr.family, bytes(event.tcpaddr.laddr[:4]))
        remote_ip = inet_ntop(event.tcpaddr.family, bytes(event.tcpaddr.raddr[:4]))
    else:
        assert event.tcpaddr.family == AF_INET6
        local_ip = inet_ntop(event.tcpaddr.family, bytes(event.tcpaddr.laddr))
        remote_ip = inet_ntop(event.tcpaddr.family, bytes(event.tcpaddr.raddr))

    tls_lib = "OpenSSL" if event.flags == 0 else "Other"

    print("%-6d %-12s %-10s %-24s %-24s" % (event.pid, 
                                           event.name.decode('ascii'), 
                                           tls_lib,
                                           "%s:%d" % (local_ip, event.tcpaddr.lport),
                                           "%s:%d" % (remote_ip, event.tcpaddr.rport)))

b["tls_trace_event"].open_perf_buffer(print_event)

print("Starting to trace...", flush=True)
print("%-6s %-12s %-10s %-24s %-24s" % ("PID", "COMM", "LIB", "LOCAL", "REMOTE"))
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

if device:
    b.remove_xdp(device)
