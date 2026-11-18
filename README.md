# learn-ebpf
Trying to learn ebpf

Installation requirements for python based programs
sudo apt update
sudo apt install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc

Installation requirements for c based programs
sudo apt update
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
