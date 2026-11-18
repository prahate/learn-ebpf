# learn-ebpf
Trying to learn ebpf

## Installation requirements for python based programs

```
sudo apt update

sudo apt install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```


## Installation requirements for c based programs
```
sudo apt update

sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool

sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```


# eBPF Overview

## Understand what eBPF is? Why do we need it? Can't we use kernel modules?

eBPF is a revolutionary sandboxed runtime environment built directly into the Linux kernel. It allows you to write custom code (usually in C or Rust) and run it at the lowest levels of the operating system without needing to modify the kernel's source code or reboot the machine. 

If web browsers have JavaScript to dynamically change how a webpage behaves without altering the browser's C++ codebase, the Linux kernel has eBPF to dynamically change how the OS behaves.

### Why Do We Need It?

Historically, if you needed the OS to do something it wasn't designed to do, you had to either write a user-space program (which is slow due to constant context switching) or modify the kernel itself. eBPF gives you the performance of kernel-level execution with the ease of user-space programming. 

It is primarily used to solve three massive engineering challenges:

*   **Programmable Observability:** Standard tools like `perf` and `ftrace` are fantastic, but they rely on static, pre-defined tracepoints. eBPF allows you to write custom logic to aggregate metrics (like generating a latency histogram of NVMe reads) directly inside the kernel, saving the massive overhead of dumping raw event logs to user space.
*   **High-Performance Networking:** Features like XDP (eXpress Data Path) use eBPF to inspect, route, or drop network packets inside the network card's driver before the kernel even allocates memory for them. This is how modern infrastructure absorbs terabit-scale DDoS attacks.
*   **Security & Enforcement:** Because eBPF can intercept any system call instantly, it can evaluate arguments and block malicious actions before the kernel executes them, acting as a programmable firewall for the operating system itself.

### Why Not Just Use Kernel Modules?

A kernel module is a piece of compiled C code loaded directly into the kernel using `insmod` or `modprobe`. While modules can technically do everything eBPF can, **eBPF was invented specifically to fix the fundamental dangers of kernel modules.**

Here is exactly why the industry has shifted away from modules for observability and networking:

#### 1. The Blast Radius (Safety vs. Panics)
Kernel modules operate with unrestricted ring-0 privileges. There are no guardrails. A single null-pointer dereference, infinite loop, or memory leak in a custom kernel module will cause an immediate kernel panic, crashing the entire server. 

eBPF solves this using the **Verifier**. Before an eBPF program is allowed to execute, the kernel statically analyzes the bytecode. The Verifier guarantees mathematically that the program:
*   Will not crash.
*   Does not contain infinite loops (it must execute within a strict instruction limit).
*   Only accesses initialized, permitted memory.

If the code isn't provably safe, the Verifier rejects it. A bug in an eBPF program just stops the program; it never brings down the system.

#### 2. Portability (CO-RE vs. Strict Headers)
Kernel modules must be compiled against the exact kernel headers (the specific version of the Linux kernel) running on the target machine. If you upgrade your OS from kernel 5.15 to 6.1, the internal memory layouts change, and your kernel module will instantly break or cause data corruption until you recompile it.

Modern eBPF uses **CO-RE (Compile Once - Run Everywhere)**. It leverages BPF Type Format (BTF) data to understand how kernel data structures change across different kernel versions. You can compile an eBPF C program once on your build machine, and it will dynamically adjust its memory offsets to run seamlessly on a completely different kernel version in production.

#### 3. Dynamic Lifecycle
Loading a kernel module is a heavy, privileged operation that is difficult to audit (using `lsmod`). Removing one can be tricky if it is currently in use. eBPF programs, however, are event-driven. They can be dynamically loaded and attached to hooks by a user-space application, and the moment that user-space application closes, the kernel automatically detaches and cleans up the eBPF program.

## What functions does it have? What can it do in the Linux kernel? What are the types of eBPF programs and helpers (not all of them need to be known, but need to know where to find them)?

eBPF operates across three primary functional domains, transforming the Linux kernel into a programmable environment:

1. **Observability & Tracing:** It can extract highly granular metrics (like I/O latencies, CPU scheduling, or memory allocation) and pre-aggregate them in the kernel. This eliminates the overhead of dumping thousands of events to user space.
2. **High-Performance Networking:** It can inspect, route, or drop packets at the earliest possible stage (even inside the network card driver), enabling terabit-scale load balancing and DDoS mitigation.
3. **Security:** It can enforce runtime security policies by intercepting system calls and evaluating their arguments before the kernel acts on them.

### What It Can Do in the Linux Kernel

eBPF allows you to safely attach custom bytecode to almost any event in the kernel. Instead of writing a risky kernel module, the eBPF Verifier mathematically guarantees your code won't crash the system. 

It executes by attaching to specific kernel hooks:
* **Kprobes and Kretprobes:** Allows you to hook into the entry or exit of almost any function within the kernel dynamically.
* **Uprobes:** Similar to Kprobes, but hooks into user-space application functions (e.g., tracing a specific function in a running Python or Java app).
* **Tracepoints:** Stable, predefined static hooks planted by kernel developers for system events (like `sys_enter_openat`).
* **XDP (eXpress Data Path):** Hooks directly into the network card (NIC) driver, processing packets before the kernel network stack even knows they exist.
* **LSM (Linux Security Modules):** Hooks designed specifically to accept or reject operations for access control.

### Types of eBPF Programs

When you write an eBPF program, you must declare its **Program Type**. The type determines where it can be attached and what data context it is allowed to see (e.g., an XDP program gets raw packet data, while a Kprobe gets CPU registers).

*Examples:*
* `BPF_PROG_TYPE_KPROBE`: Used for dynamic function tracing.
* `BPF_PROG_TYPE_XDP`: Used for raw, bare-metal network packet processing.
* `BPF_PROG_TYPE_SOCKET_FILTER`: Used for inspecting network traffic on standard sockets.
* `BPF_PROG_TYPE_CGROUP_SKB`: Used to filter or monitor network traffic specific to a cgroup (often used for Docker/Kubernetes networking).

**Where to find the full list:**
The exhaustive, up-to-date list of program types is defined in the Linux kernel source code under the `enum bpf_prog_type` in `include/uapi/linux/bpf.h`. You can also read the official [Linux Kernel libbpf Documentation](https://docs.kernel.org/bpf/libbpf/program_types.html).

### eBPF Helper Functions

Because eBPF is strictly sandboxed, your program is completely blind and isolated—it cannot call arbitrary kernel functions (like a normal C module could). To interact with the system, the kernel provides a strict whitelist of stable APIs called **Helper Functions**.

*Examples:*
* `bpf_map_lookup_elem()` / `bpf_map_update_elem()`: Allows the program to read or write to shared eBPF Maps (to communicate with user space).
* `bpf_ktime_get_ns()`: Retrieves the current high-precision kernel time (crucial for calculating latency).
* `bpf_get_current_pid_tgid()`: Identifies the Process ID and Thread ID that triggered the event.
* `bpf_trace_printk()`: Prints debugging statements to the kernel trace pipe (`/sys/kernel/tracing/trace`).

**Where to find the full list:**
The canonical documentation for all available helpers is maintained in the **`bpf-helpers(7)`** man page (type `man bpf-helpers` in your Linux terminal). These manual pages are automatically generated directly from the developer comments inside the `include/uapi/linux/bpf.h` header file.

## What can it be used for? For example, in which scenarios can it be used? Networking, security, observability?

eBPF has completely transformed how enterprise Linux environments handle infrastructure, primarily breaking down into three major pillars: Observability, Networking, and Security. Because it runs natively inside the kernel with extremely low overhead, it solves problems that were previously impossible without custom hardware or risky kernel modifications.

### 1. Observability and Performance Profiling
Traditional tools like `perf`, `ftrace`, or `trace-cmd` are excellent for collecting data, but they often require copying massive amounts of event logs from the kernel to user space for processing, which creates CPU overhead. eBPF allows you to write custom logic to aggregate this data *inside* the kernel and only output the final results (like a histogram).

**Real-world scenarios:**
*   **Storage I/O Latency Tracking:** Instead of logging every single NVMe disk read, an eBPF program can hook into the block layer, calculate the time between a request and its completion, and populate a latency histogram directly in an eBPF Map. User space only reads the tiny histogram array.
*   **CPU Scheduler Profiling:** If a C/C++ benchmarking framework is experiencing random latency spikes, eBPF can measure exactly how long threads spend waiting in the kernel's run queue (runqueue latency) without slowing down the application itself.
*   **Memory Leak Detection:** Hooking into `malloc()` and `free()` (via uprobes) inside a Python or C application to track exactly which lines of code are allocating memory that never gets freed.

### 2. High-Performance Networking
eBPF—specifically through XDP (eXpress Data Path) and TC (Traffic Control)—allows the kernel to process network packets at the lowest possible level, often directly inside the network card driver.

**Real-world scenarios:**
*   **DDoS Mitigation:** When millions of malicious packets hit a server, XDP can inspect the raw packet headers and issue an `XDP_DROP` command inside the NIC driver. The packet is destroyed before the kernel even allocates an `sk_buff` or processes iptables rules, saving massive amounts of CPU cycles.
*   **Zero-Copy Hardware Routing (AF_XDP):** Bypassing the kernel entirely to route raw TCP/UDP streams (like IPCAM video data) directly into a user-space memory buffer. This allows AI accelerators or custom user-space daemons to read network data with zero CPU copy overhead.
*   **Container and Kubernetes Networking:** Traditional Docker/Kubernetes networking relies on complex, CPU-heavy iptables routing. Modern networking interfaces (like Cilium) use eBPF to route packets directly between container namespaces, significantly reducing network latency between microservices.

### 3. Runtime Security
Because eBPF can safely intercept any system call or kernel function instantly, it acts as a programmable firewall for the operating system's internal behavior.

**Real-world scenarios:**
*   **Threat Detection:** You can write an eBPF program to monitor the `execve` system call. If a web server daemon (like Nginx) suddenly tries to spawn a bash shell (`/bin/sh`), the eBPF program detects this anomalous behavior instantly and alerts an intrusion detection system.
*   **File Access Enforcement:** Before the kernel opens a sensitive file (like `/etc/shadow`), an eBPF program can evaluate the process ID, the user ID, and the container context. If the access is unauthorized, the eBPF program can block the system call and return a "Permission Denied" error before the kernel touches the disk.
*   **Network Isolation:** Enforcing dynamic network policies by dropping packets from specific unauthorized IP addresses or blocking applications from binding to specific ports, operating much faster than traditional firewalls.
