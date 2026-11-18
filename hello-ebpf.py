#!/usr/bin/env python3

"""
To test this ebpf, run the program
sudo python3 hello_ebpf.py

and then open another terminal and then
run command like 'ls', 'date'

in previous terminal you should see prints
"""


from bcc import BPF

# 1. The Kernel Space Program (C)
# This C code is compiled dynamically by BCC and injected into the kernel.
bpf_program = """
int hello_world(void *ctx) {
    // bpf_trace_printk writes to a shared kernel trace pipe
    bpf_trace_printk("Hello from eBPF! A new process started.\\n");
    return 0;
}
"""

# 2. Compile and load the program into the kernel
b = BPF(text=bpf_program)

# 3. Attach the C function to a kernel event
# We attach it to the 'execve' system call (triggered when a new app runs).
# get_syscall_fnname safely resolves the exact CPU architecture name for the syscall.
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello_world")

print("eBPF program loaded. Run some commands in another terminal...")
print("Press Ctrl+C to stop.")

# 4. Read the kernel's trace pipe and print it to the user's terminal
b.trace_print()
