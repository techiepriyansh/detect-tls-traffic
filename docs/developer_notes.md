# Developer Notes

## Detecting processes making calls to TLS library functions
This is the easiest bit of the puzzle, just attach some uprobes and uretprobes and we're done.

## Getting the TCP connection information
This is not as straightforward as it seems because the TLS protocol does not need to know about the underlying TCP information. And most TLS libraries also abstract away the TCP connection information by just taking a file descriptor to read/write from. So just attaching some uprobes and scanning arguments to the library function calls is not gonna work. 

This is where we exploit the sequentiality of the library's TLS data read/write function calls (for eg. `SSL_write` and `SSL_read` in OpenSSL) with the kernel TCP send/recv function calls. It turns out that whenever a library function call is invoked to read/write TLS data, internally the kernel functions of `tcp_sendmsg` or `tcp_cleanup_rbuf`  are also invoked.  
> **_NOTE:_**  We use `tcp_cleanup_rbuf` instead of `tcp_recvmsg` because it also accounts for `tcp_read_sock`.

For each process (thread), whenever a TLS read/write function enters we set a variable signifying that we are currently inside the execution of this function. Now if we detect any kernel TCP read/write function call (inside the same process), we extract the TCP connection information from the arguments passed to the kernel function and store it mapping it to the PID of the process. Now when the same TLS function exits, we lookup the TCP information by PID and send this information to userspace.

## Blacklisting
Once we detect a connection not using the specified allowed libs, we add it to a `blacklist` map. We also have an XDP filter attached to our network interfaces which allows packets only from those connections which are not present in the `blacklist` map.  
An important thing to note here is that XDP is ingress only, so effectively, we are only blocking the incoming packets but not the outgoing packets. This still kind of works, because we will not be receiving any malicious data but a better approach would be to use `tc` (Linux Traffic Control).

## Tracing TLS library functions responsible for TLS read/write
To use the above described approach for tracing and blacklisting TLS connections, one will need to figure out the functions responsible for TLS data read/write for every TLS library they wish to trace. For this, one might be tempted to trace the function graph of the TLS library functions + kernel TCP functions of `tcp_sendmsg`/`tcp_cleanup_rbuf` of a process which will make it quite easy to spot the desired functions.  

Using eBPF, we can automate this process. We attach uprobes and uretprobes to all the library functions' entry and exit, and kprobes to the kernel TCP functions of `tcp_sendmsg` and `tcp_cleanup_rbuf`. We also maintain a function call stack of the library functions which  is updated on each library function's entry and exit. Whenever we encounter a `tcp_sendmsg` or `tcp_cleanup_rbuf`, we add the function currently on the top of the function call stack to a set of possible library functions for TLS read/write and report this to the userspace.  

But there's one small problem: there can be thousands of functions in a library and we cannot attach these many probes simultaneously. The solution is to do this scan in chunks. A final scan with uprobes/uretprobes attached to the detected library functions from the scan in chunks can also be done to eliminate the redundant functions.


