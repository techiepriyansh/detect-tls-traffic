#!/usr/bin/python3

import os
import sys
import subprocess
from bcc import BPF
import ctypes as ct

def trace_tls_libfns(base_path, lib, start, end):
    with open(base_path + "/trace_tls_libfns.c", "rt") as f:
        bpf_prog_text = f.read()

    if not lib.startswith('lib'):
        lib = 'lib' + lib
    if not 'so' in lib.split('.'):
        lib += '.so'

    def shell_cmd(cmd):
        return subprocess.check_output(cmd, shell=True, text=True)

    try:
        libs = shell_cmd(f'ldconfig -p | grep {lib}')
        libpath = libs.strip().split('\n\t')[0].split(' => ')[1]
    except:
        print("library not found!")
        return

    print(f"using the library at: {libpath}")

    libfns = shell_cmd(f'nm -D {libpath}').split('\n')

    libfns_to_trace = []
    for libfn in libfns:
        fn_info = libfn.split()
        if 'T' in fn_info:
            libfns_to_trace.append(fn_info[-1])
    libfns_to_trace = libfns_to_trace[start:end]

    wrapper_enter_fn_template = """
    int hook_to_tls_lib_%s_fn(struct pt_regs *ctx)
    {
        send_perf_output(ctx, %d, PERF_EVENT_TLS_LIB_FN_ENTER);
        return 0;
    }
    """

    wrapper_exit_fn_template = """
    int hookret_to_tls_lib_%s_fn(struct pt_regs *ctx)
    {
        send_perf_output(ctx, %d, PERF_EVENT_TLS_LIB_FN_EXIT);
        return 0;
    }
    """
    
    wrapper_fns = []
    for i, libfn in enumerate(libfns_to_trace):
        wrapper_fns.append(wrapper_enter_fn_template % (libfn, i))
        wrapper_fns.append(wrapper_exit_fn_template % (libfn, i))

    bpf_prog_text = bpf_prog_text.replace("__PY_EXTERNAL_WRAPPERS__", '\n'.join(wrapper_fns))
    
    b = BPF(text=bpf_prog_text)
    
    for libfn in libfns_to_trace:
        try:
            b.attach_uprobe(name=libpath, sym=libfn, fn_name="hook_to_tls_lib_%s_fn"%libfn)
            b.attach_uretprobe(name=libpath, sym=libfn, fn_name="hookret_to_tls_lib_%s_fn"%libfn)
        except:
            continue
    
    indent_level = {}

    def print_event(cpu, data, size):
        TASK_COMM_LEN = 16 # in linux/sched.h

        class perf_output_t(ct.Structure):
            _fields_ = [ ("pid", ct.c_uint32),
                         ("comm", ct.c_char * TASK_COMM_LEN),
                         ("fn_id", ct.c_uint32),
                         ("perf_event", ct.c_uint8) ]

        event = ct.cast(data, ct.POINTER(perf_output_t)).contents
        
        log = None
        curr_indent_level = indent_level.get(event.pid, 0)

        if event.perf_event == 1:
            # PERF_EVENT_TLS_LIB_FN_ENTER
            log = " " * curr_indent_level + libfns_to_trace[event.fn_id]
            curr_indent_level += 2 
        elif event.perf_event == 2:
            # PERF_EVENT_TLS_LIB_FN_EXIT
            curr_indent_level -= 2
            log = " " * curr_indent_level + libfns_to_trace[event.fn_id] + " Return"
        elif event.perf_event == 3:
            # PERF_EVENT_TCP_SEND
            log = " " * curr_indent_level + "TCP Send"
        elif event.perf_event == 4:
            # PERF_EVENT_TCP_RECV
            log = " " * curr_indent_level + "TCP Recv"

        indent_level[event.pid] = curr_indent_level

        print("%-6d %-12s %-24s" % (event.pid, event.comm.decode('ascii'), log)) 

    b["tls_libfn_trace_event"].open_perf_buffer(print_event)

    print("Starting to trace...",  flush=True)
    print("%-6s %-12s %-24s" % ("PID", "COMM", "LOGS"))
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break


    
    
if __name__ == "__main__":
    lib = sys.argv[1]
    start = int(sys.argv[2])
    end = int(sys.argv[3])
    base_path = os.path.dirname(os.path.realpath(__file__))
    trace_tls_libfns(base_path, lib, start, end)
