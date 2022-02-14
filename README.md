

# detect-tls-traffic
Detect processes communicating via the TLS protocol and the libraries used for processing this TLS traffic

## Installation
### Requirements
* `python3.8+`
* `bcc`
	*	Install the latest version by following this [installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md).
	*	Make sure to install the `python3` bindings.
	*  If you're on Ubuntu, you may need to [build from source](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source), as currently, the BCC packages for the Ubuntu Universe are outdated.

## Usage
> **_NOTE:_**  You will need to run these commands with superuser privileges

### Trace
* Trace all the processes communicating via the TLS protocol, printing their PID, name, TLS library used, local address and remote address:  

    ```bash
    $ sudo ./detect_tls.py
    ```  
  Example: [examples/example_detect_tls_vanilla.txt](examples/example_detect_tls_vanilla.txt)  
* You can extend the  TLS libraries to trace by adding new entries in [config.json](config.json) as follows:
	* `name`: name to identify the library with
	* `verboseName`: name to print while tracing
	* `functions`: a list of all library functions which are responsible for reading/writing TLS data  
* To identify the functions responsible for TLS read/write(s), the [`tls_trace_libfns`](#trace-tls-library-functions) tool can be used.

### Blacklist
* Blacklist all TLS connections not using the TLS libraries specified in `config.json`:  
	   
    ```bash 
    $ sudo ./detect_tls.py blacklist --if_name [network-interface] 
    ```  
    
	Example: [examples/example_detect_tls_blacklist_other.txt](examples/example_detect_tls_blacklist_other.txt)  
* Blacklist all TLS connections allowing only those which use the specified TLS libraries:  

    ```bash
    $ sudo ./detect_tls.py blacklist --if_name [network-interface] --allowed_libs [lib-name ...]
    ```
    
  Example: [examples/example_detect_tls_blacklist_libs.txt](examples/example_detect_tls_blacklist_libs.txt)  

### Trace TLS library functions
* Identify the library functions which may be responsible for reading/writing TLS data during the execution of a given program  

	```bash
	$ sudo ./trace_tls_libfns.py -l [lib-name] -c command [args...]
	```
  Examples: [examples/example_trace_tls_libfns_ssl.txt](examples/example_trace_tls_libfns_ssl.txt), [examples/example_trace_tls_libfns_gnutls.txt](examples/example_trace_tls_libfns_gnutls.txt)

## Working
To learn about the working and design of the tool, please refer to the [developer notes](docs/developer_notes.md).
