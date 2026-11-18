#include "vmlinux.h"
#include <bpf/bpf_helpers.h>



/*
To run and test the file
1. compile
clang -O2 -g -target bpf -c trace_kernel_func.c -o trace.o

2.Load and attach
use bfptool to load and attach, autoattach flag automatically
binds it to sys_enter_openat tracepoint in c code

sudo bpftool prog load trace.o /sys/fs/bpf/trace_openat autoattach

3. Test
to test, open another terminal and run commands like cat or ls
you will see output streams as kernel intercepts call
sudo cat /sys/kernel/debug/tracing/trace_pipe

4. Unload
remove the pinned file from VFS to dettach program
sudo rm /sys/fs/bpf/trace_openat

*/

// Define a map to share data with user space (optional, but standard practice)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Attach to the static tracepoint for the 'openat' system call
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    // bpf_printk writes to /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("A file was opened!\n");
    
    // You can also extract the file name from the tracepoint context
    // and send it to user space via the ring buffer (rb).
    
    return 0;
}

char _license[] SEC("license") = "GPL";
