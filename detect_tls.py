#!/usr/bin/python3

import sys
import os
import argparse
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
import ctypes as ct
import json

def trace_and_blacklist(args, base_path):
    # read bpf c source code
    with open(base_path + "/detect_tls.c", "rt") as f:
        bpf_prog_text = f.read()

    # read and parse config.json
    with open(base_path + "/config.json") as f:
        tls_libs = json.load(f)

    # create external wrapper functions and place them in the bpf c source code
    wrapper_enter_fn_template = """
    int hook_to_tls_lib_%s_fn(struct pt_regs *ctx)
    {
        return tls_lib_fn_enter(ctx, %d);
    }
    """

    wrapper_exit_fn_template = """
    int hookret_to_tls_lib_%s_fn(struct pt_regs *ctx)
    {
        return tls_lib_fn_exit(ctx);
    }
    """

    wrapper_fns = []
    for i, lib in enumerate(tls_libs):
        wrapper_fns.append(wrapper_enter_fn_template % (lib["name"], i))
        wrapper_fns.append(wrapper_exit_fn_template % lib["name"])

    bpf_prog_text = bpf_prog_text.replace("__PY_EXTERNAL_WRAPPERS__", '\n'.join(wrapper_fns))

    # substitute blacklisting option inside the bpf c source code
    should_blacklist = "1" if args.subcommand == "blacklist" else "0"
    bpf_prog_text = bpf_prog_text.replace("__PY_SHOULD_BLACKLIST__", should_blacklist)

    # compile bpf program
    b = BPF(text=bpf_prog_text)

    # populate allowed_libs map allowed libs inside the bpf c source code
    allowed_libs = list(range(len(tls_libs)))
    if "allowed_libs" in args and args.allowed_libs:
        tls_lib_name_to_id = {}
        for i, lib in enumerate(tls_libs):
            tls_lib_name_to_id[lib["name"]] = i 
            
        allowed_libs = [tls_lib_name_to_id[libname] for libname in args.allowed_libs]
    
    bpf_allowed_libs_map = b["allowed_libs"]
    for allowed_lib_id in allowed_libs:
        bpf_allowed_libs_map[ct.c_int(allowed_lib_id)] = ct.c_uint8(1)

    # attach uprobes and uretprobes
    for lib in tls_libs:
        libname = lib["name"]
        for libfn in lib["functions"]:
            b.attach_uprobe(name=libname, sym=libfn, fn_name="hook_to_tls_lib_%s_fn"%libname)
            b.attach_uretprobe(name=libname, sym=libfn, fn_name="hookret_to_tls_lib_%s_fn"%libname)

    # attach XDP Filter if opted
    device = None
    if args.subcommand == "blacklist":
        device = args.if_name 
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
                         ("lib_id", ct.c_uint8),
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

        tls_lib_name = "Other"
        if event.lib_id != 255:
            lib = tls_libs[event.lib_id]
            tls_lib_name = lib.get("verboseName", lib["name"])

        print("%-6d %-12s %-10s %-24s %-24s" % (event.pid, 
                                               event.name.decode('ascii'), 
                                               tls_lib_name,
                                               "%s:%d" % (local_ip, event.tcpaddr.lport),
                                               "%s:%d" % (remote_ip, event.tcpaddr.rport)))

        if event.flags & 1:
            print("^ BLACKLISTED")

    b["tls_trace_event"].open_perf_buffer(print_event)

    print("Starting to trace...", flush=True)
    print("%-6s %-12s %-10s %-24s %-24s" % ("PID", "COMM", "LIB", "LOCAL", "REMOTE"))
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break
    
    if device:
        b.remove_xdp(device)

    b.cleanup()


if __name__ == "__main__":
    examples = r"""examples:
        ./detect_tls.py               # Trace TLS read/write by the libraries listed in config.json
        ./detect_tls.py blacklist \   # Trace and also blacklist connections 
            --if_name eno1        \     - network interface device name
            --allowed_libs ssl          - allowed libraries list (space separated names)
    """

    parser = argparse.ArgumentParser(
        description="Detect TLS traffic and the library used for processing it",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)

    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')

    blacklist_command = subparsers.add_parser('blacklist', help='blacklist connections')
    blacklist_command.add_argument('--if_name', required=True, help='network interface device name', metavar='dev')
    blacklist_command.add_argument('--allowed_libs', nargs='+', help='allowed libraries list', metavar='lib') 

    args = parser.parse_args()

    # get the directory of the folder which contains this script
    base_path = os.path.dirname(os.path.realpath(__file__))

    if not args.subcommand or args.subcommand == 'blacklist':
        trace_and_blacklist(args, base_path)

