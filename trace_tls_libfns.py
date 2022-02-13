#!/usr/bin/python3

import os
import sys
import argparse
import subprocess
from multiprocessing import Process, Queue
from bcc import BPF
import ctypes as ct
import time

MAX_PROBES = 200
MAX_STACKS = 64

def trace_tls_libfns(base_path, lib, command):
    # read the bpf c source code
    with open(base_path + "/trace_tls_libfns.c", "rt") as f:
        base_bpf_prog_text = f.read()
    
    # insert the array of stacks defintion into the bpf c source code
    stack_definition_template = f'BPF_STACK(fn_stack_%d, u32, {MAX_PROBES});' 

    array_of_stacks_definition = [f'#define MAX_STACK_DEPTH {MAX_PROBES}']
    for i in range(MAX_STACKS):
        array_of_stacks_definition.append(stack_definition_template % i)

    array_of_stacks_definition.append(
        f'BPF_ARRAY_OF_MAPS(fn_stack_arr, "fn_stack_0", {MAX_STACKS});'
    )

    base_bpf_prog_text = base_bpf_prog_text.replace(
        "__PY_ARRAY_OF_STACKS_DEFINITION__",
        "\n".join(array_of_stacks_definition)
    )

    # augment the lib name provided by user
    if not lib.startswith('lib'):
        lib = 'lib' + lib
    if not 'so' in lib.split('.'):
        lib += '.so'

    # runs the given cmd in shell and returns its output
    def shell_cmd(cmd):
        return subprocess.check_output(cmd, shell=True, text=True)

    # try to get the library path from the lib name provided using ldconfig command
    try:
        libs = shell_cmd(f'ldconfig -p | grep {lib}')
        libpath = libs.strip().split('\n\t')[0].split(' => ')[1]
    except:
        print("library not found!")
        return

    print(f"using the library at: {libpath}")

    # get a list of all the functions the library
    libfns = shell_cmd(f'nm -D {libpath}').split('\n')

    # get a list of all the global symbols which are present in the text (code) section of the library
    libfns_to_trace = []
    for libfn in libfns:
        fn_info = libfn.split()
        if 'T' in fn_info:
            libfns_to_trace.append(fn_info[-1])
    libfns_to_trace = libfns_to_trace

    # define the wrapper function templates to be substituted in the c bpf source code
    wrapper_enter_fn_template = """
    int hook_to_tls_lib_%s_fn(struct pt_regs *ctx)
    {
        on_tls_lib_fn_enter_exit(ctx, %d, PERF_EVENT_TLS_LIB_FN_ENTER);
        return 0;
    }
    """

    wrapper_exit_fn_template = """
    int hookret_to_tls_lib_%s_fn(struct pt_regs *ctx)
    {
        on_tls_lib_fn_enter_exit(ctx, %d, PERF_EVENT_TLS_LIB_FN_EXIT);
        return 0;
    }
    """
    
    # define a list to hold all the detected library TLS read/write functions
    possible_rw_fns = []

    # helper function for printing all the detected library functions responsible for TLS read/write
    def print_detected_fns():
        print("\nFound these library functions responsible for TLS read/write:")
        print("=============================================================\n")
        for possible_rw_fn in possible_rw_fns:
            print(libfns_to_trace[possible_rw_fn])
        print("\n")

    # there may be thousands of symbols in a library, but we cannot attach these many u[ret]probes all at once
    # so we break the functions in chunks of size MAX_PROBES and scan each chunk individually
    # this will trace the library functions stored in libfns_to_trace starting from index base index
    def scan_iteration(base_index):
        # substitute the wrapper functions in the bpf c source code
        wrapper_fns = []
        for i, libfn in enumerate(libfns_to_trace[base_index:base_index+MAX_PROBES]):
            wrapper_fns.append(wrapper_enter_fn_template % (libfn, i+base_index))
            wrapper_fns.append(wrapper_exit_fn_template % (libfn, i+base_index))
        
        bpf_prog_text = base_bpf_prog_text.replace("__PY_EXTERNAL_WRAPPERS__", '\n'.join(wrapper_fns))

        # compile the bpf c source code
        print("  - compiling bpf program...", end="", flush=True)
        b = BPF(text=bpf_prog_text)
        print("done!")

        # helper function to assign the declared stacks to the array of stacks
        def assign_stacks_to_array_of_stacks():
            array_of_stacks = b["fn_stack_arr"]
            for i in range(MAX_STACKS):
                array_of_stacks[ct.c_int(i)] = ct.c_int(b[f"fn_stack_{i}"].map_fd)

            b["next_idx"][ct.c_int(0)] = ct.c_int(0)

        assign_stacks_to_array_of_stacks()
        
        # helper function to attach uprobes and uretprobes corresponding to all the library functions 
        # being traced in this scan iteration
        def attach_uprobes_uretprobes():
            print("  - attaching uprobes and uretprobes...", end="", flush=True)
            for libfn in libfns_to_trace[base_index:base_index+MAX_PROBES]:
                try:
                    b.attach_uprobe(name=libpath, sym=libfn, fn_name="hook_to_tls_lib_%s_fn"%libfn)
                    b.attach_uretprobe(name=libpath, sym=libfn, fn_name="hookret_to_tls_lib_%s_fn"%libfn)
                except Exception as e:
                    print(e)
                    continue
            print("done!")
        
        # helper function to detach uprobes and uretprobes attached through the attach_uprobe_uretprobes function
        def detach_uprobes_uretprobes():
            print("  - detaching uprobes and uretprobes...", end="", flush=True)
            for libfn in libfns_to_trace[base_index:base_index+MAX_PROBES]:
                try:
                    b.detach_uretprobe(name=libpath, sym=libfn)
                    b.detach_uprobe(name=libpath, sym=libfn)
                except Exception as e:
                    print(e)
                    continue
            print("done!")
        
        # attach uprobes and uretprobes
        attach_uprobes_uretprobes()

        # receive information from bpf program
        def trace_event(cpu, data, size):
            class perf_output_t(ct.Structure):
                _fields_ = [ ("fn_id", ct.c_uint32), ]

            event = ct.cast(data, ct.POINTER(perf_output_t)).contents
            possible_rw_fns.append(event.fn_id)
            print(f"  - found: {libfns_to_trace[event.fn_id]}")
            
        b["tls_libfn_trace_event"].open_perf_buffer(trace_event)
        
        # helper function to run the command to be traced
        def run_command(q):
            time.sleep(1)
            subprocess.Popen(command, shell=True, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).wait()
            q.put(True)

        # poll the bpf perf buffer periodically and exit when the command to be traced terminates
        def poll_perf_buffer(q):
            while q.empty():
                try:
                    b.perf_buffer_poll(1000)
                except KeyboardInterrupt:
                    print("\nattmepting to exit gracefully")
                    detach_uprobes_uretprobes()
                    b.cleanup()
                    print_detected_fns()
                    sys.exit()

        # run the command to be traced and bpf event retriever as two separate processes
        # use the Queue to indicate the run_command function's termination to the poll_perf_buffer function 
        q = Queue()
        p = Process(name='command_to_trace', target=run_command, args=(q,))
        p.start()
        poll_perf_buffer(q)
        p.join()
        
        # finally detach the uprobes and uretprobes attached earlier and cleanup
        detach_uprobes_uretprobes()
        b.cleanup()

    # start scanning the library functions in chunks
    for j in range(0, len(libfns_to_trace), MAX_PROBES): 
        print(f"scanning {MAX_PROBES} library functions starting from index {j}")
        scan_iteration(j)

    # print all the detected fns responsible for TLS read/write
    print_detected_fns()

    
if __name__ == "__main__":
    examples = r"""example:
  ./trace_tls_libfns.py       \  # Detects the libssl library functions
      -l ssl                  \    responsible for TLS read/write during 
      -c curl https://ebpf.io      the execution of the program
                                   curl https://ebpf.io
    """

    parser = argparse.ArgumentParser(
        description="Detect the functions of a TLS library responsible for TLS read/write(s) of the given program",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)

    parser.add_argument('-l', metavar='lib', required=True, help='name/path of the library to trace functions of')
    parser.add_argument('-c', metavar=('command', 'arg'), nargs='+', required=True, help='program to be traced') 

    args = parser.parse_args()

    base_path = os.path.dirname(os.path.realpath(__file__))
    trace_tls_libfns(base_path, args.l, " ".join(args.c))
