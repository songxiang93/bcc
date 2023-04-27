#!/usr/bin/env python
from bcc import BPF
import socket
import ctypes
import os
import sys


bpf_prog = """
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_HASH(dropcnt, u32, u64, 256);

int ip_filter(struct __sk_buff *skb) {
    struct iphdr *ip = (struct iphdr *)(skb->data + sizeof(struct ethhdr));

    u32 src = ip->saddr;
    u32 dst = ip->daddr;
    if (src == {{src_ip}} && dst == {{dst_ip}}) {
        bpf_trace_printk("IP packet: src=%d.%d.%d.%d, dst=%d.%d.%d.%d\\n",
            (src & 0xff), ((src >> 8) & 0xff), ((src >> 16) & 0xff), ((src >> 24) & 0xff),
            (dst & 0xff), ((dst >> 8) & 0xff), ((dst >> 16) & 0xff), ((dst >> 24) & 0xff));
    }

    return 0;
}
"""


if len(sys.argv) != 4:
    print("Usage: %s <iface> <src_ip> <dst_ip>" % sys.argv[0])
    exit(1)

iface = sys.argv[1]
src_ip = ctypes.c_uint32(int.from_bytes(socket.inet_aton(sys.argv[2]), byteorder="big"))
dst_ip = ctypes.c_uint32(int.from_bytes(socket.inet_aton(sys.argv[3]), byteorder="big"))


bpf = BPF(text=bpf_prog.replace("{{src_ip}}", str(src_ip.value)).replace("{{dst_ip}}", str(dst_ip.value)))
function_ip_filter = bpf.load_func("ip_filter", BPF.SOCKET_FILTER)


