#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>

/*
Steps to run a program
1. compile
clang -O2 -g -target bpf -c xdp.c -o xdp.o

2. Load
Attach it to your network interface (replace eth0 with your actual interface name, such as enp3s0 or wlan0)
xdpgeneric forces it to load even if your network card lacks native hardware support.

sudo ip link set dev wlp0s20f3 xdpgeneric obj xdp.o sec xdp

3. Test

Verify the program is attached (you will see prog/xdp in the output). 
Then, attempt to ping an IPv6 address (which your eBPF program will drop) and 
an IPv4 address (which will succeed).

ip link show dev eth0
ping6 ipv6.google.com
ping 8.8.8.8

4. Unload

sudo ip link set dev wlp0s20f3 xdpgeneric off

*/


SEC("xdp")
int xdp_drop_ipv6(struct xdp_md *ctx) {
    // Cast the raw packet memory pointers
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ensure the packet is large enough to contain an Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Check if the Ethernet frame contains an IPv6 payload
    if (eth->h_proto == htons(ETH_P_IPV6)) {
        bpf_printk("Dropping IPv6 packet\n");
        return XDP_DROP;
    }

    // Pass all other traffic (like IPv4, ARP)
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
