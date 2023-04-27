# coding=utf-8
# !/usr/bin/python
#
# tc_perf_event.py  Output skb and meta data through perf event
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
import ctypes as ct
import netaddr
import socket
import struct
import sys
import traceback
from bcc import BPF

import pyroute2
from pyroute2 import NetNS
from pyroute2 import netns

bpf_txt = """
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>
BPF_PERF_OUTPUT(skb_events);
BPF_HASH(dst_map,u32,u32);

struct info{
    u32 src_ip;
    u32 dst_ip;
    u64 src_mac;
    u64 dst_mac;
};

static __always_inline __u16 csum_fold_helper(__u64 csum)

{

int i;

#pragma unroll

for (i = 0; i < 4; i++)

{

if (csum >> 16)

csum = (csum & 0xffff) + (csum >> 16);

}

return ~csum;

}

 

static __always_inline __u16 ipv4_csum(struct iphdr *iph)

{

iph->check = 0;

unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);

return csum_fold_helper(csum);

}

int handle_egress(struct __sk_buff *skb)
{
    bpf_trace_printk("start");
    struct info info;
    u32 src_ip = 0;
    u32 dst_ip = 0;
    u64 src_mac = 0;
    u64 dst_mac = 0;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph = data + sizeof(*eth);
    u32 magic = 0xfaceb00c;

    /* single length check */
    if (data + sizeof(*eth) + sizeof(*iph) > data_end){
    
        bpf_trace_printk(">data end");
        
        return TC_ACT_OK;
    }
        

    /* if proto is ipv4  */
    if (eth->h_proto != htons(ETH_P_IP)){
        bpf_trace_printk("no ETH_P_IP");
        return TC_ACT_OK;
    }
    
    u32 new_dst_ip = htonl(167772161);  // Replace DEST_IP with the user-specified IP
   
    info.src_ip = ntohl(iph->saddr);
    info.dst_ip = ntohl(iph->daddr);
    info.src_mac = *((u64 *)(eth->h_source));
    info.dst_mac = *((u64 *)(eth->h_dest));
    //skb_events.perf_submit_skb(skb, skb->len,&info,sizeof(info));
   
     if (iph->protocol == IPPROTO_TCP) {
       // Recalculate TCP checksum
        iph->check = ipv4_csum(iph);  
     } else if (iph->protocol == IPPROTO_UDP) {
       return TC_ACT_OK;
      }
    
    iph->daddr = new_dst_ip;

        // Find the corresponding output interface
    u32  * ifindex = dst_map.lookup(&new_dst_ip);
  
    bpf_trace_printk("new_dst_ip is %d\\n", new_dst_ip);
    if (ifindex) {
        bpf_trace_printk("if index is %d\\n", *ifindex);
       // Redirect the packet to the output interface
        bpf_clone_redirect(skb, *ifindex, 0);
    }
    return TC_ACT_OK;
    
}
"""
def getIpInt(ip_string):
    ip_bin = socket.inet_pton(socket.AF_INET, ip_string)
    print("ip_bin---------------------", ip_bin)
    arrIp = struct.unpack("BBBB", ip_bin)
    ipInt = 0
    i = 0
    for item in arrIp:
        print(item)
        ipInt += item * 2 ** (24 - 8 * i)
        i = i + 1

    return ipInt
global docker
global host
host = None
docker = None
global ns1

def print_skb_event(cpu, data, size):
    class SkbEvent(ct.Structure):
        _fields_ = [("src_ip", ct.c_uint32),
                    ("dst_ip", ct.c_uint32),
                    ("src_mac", ct.c_uint64),
                    ("dst_mac", ct.c_uint64),
                    # sub src_up dst ip src mac dst ip size
                    ("raw", ct.c_ubyte * (size - 2 * ct.sizeof(ct.c_uint32) - 2 * ct.sizeof(ct.c_uint64)))]

    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents

    # change mac to string
    source_mac = skb_event.src_mac
    eui = netaddr.EUI(source_mac)
    source_mac_str = str(eui)
    dest_mac = skb_event.dst_mac
    eui = netaddr.EUI(dest_mac)
    dest_mac_str = str(eui)

    src_ip = socket.inet_ntoa(struct.pack("!I", skb_event.src_ip))
    dst_ip = socket.inet_ntoa(struct.pack("!I", skb_event.dst_ip))

    print(src_ip, dst_ip, source_mac_str, dest_mac_str)

    # icmp_type = int(skb_event.raw[34])
    #
    # # Only print for echo request
    source_mac_str = ":".join("{:02x}".format(c) for c in skb_event.raw[6:12])
    dest_mac_str = ":".join("{:02x}".format(c) for c in skb_event.raw[0:6])

    src_ip = bytes(bytearray(skb_event.raw[26:30]))
    dst_ip = bytes(bytearray(skb_event.raw[30:34]))
    print("%-3s %-15s %-15s %s,%s" % (
        cpu, socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip), source_mac_str, dest_mac_str))
try:

    # 1、 load bpf text to bin
    b = BPF(text=bpf_txt)
    fn = b.load_func("handle_egress", BPF.SCHED_CLS)

    ipr = pyroute2.IPRoute()

    ipr.link("add", ifname="veth", kind="veth", peer="eth333")
    host = ipr.link_lookup(ifname="veth")[0]
    docker = ipr.link_lookup(ifname="eth333")[0]

    # 2、create ns and set docker to ns1:
    ipr.addr('add', index=docker, address='192.168.50.3', prefixlen=24)
    netns.create("ns1")
    ipr.link('set',
            index=docker,
            net_ns_fd='ns1')

    ns1=NetNS('ns1')
    docker= ns1.link_lookup(ifname="eth333")[0]
    ns1.addr('add', index=docker, address='192.168.50.3', prefixlen=24)
    ipr.addr('add', index=host, address='192.168.50.2', prefixlen=24)

    # 3、up interface

    ns1.link('set', index=docker, state='up', netns="ns1")
    ipr.link('set', index=host, state='up')

    # 4、add bpf to tc ingress
    ipr.tc("add", "ingress", host, "ffff:")
    res = ipr.tc("add-filter", "bpf", host, ":1", fd=fn.fd, name=fn.name, parent="ffff:", classid=1, direct_action=True)
    print("result", res)

    # b["skb_events"].open_perf_buffer(print_skb_event)

    # 5、set dest_ip_str and interface name
    dest_ip = '10.0.0.1'
    ifname = 'enp7s0'

    # 6、Convert destination IP to network byte order

    # Add IP-to-interface mapping to the BPF map
    dst_map = b.get_table("dst_map")
    ifindex = ipr.link_lookup(ifname=ifname)[0]
    c_ifindex = ct.c_uint32(ifindex)
    ip_address = '10.0.0.1'

    ipInt = getIpInt(ip_address)

    print("host-network", socket.htonl(ipInt))
    print("host", str(ipInt))
    print("ifindex", str(ifindex))



    dst_map[ct.c_uint32(socket.htonl(ipInt))] = c_ifindex
    b.trace_print()
    # try:
    #     while True:
    #         b.perf_buffer_poll()
    # except KeyboardInterrupt:
    #     pass
except Exception as e:
    exc_type, exc_obj, exc_tb = sys.exc_info()
    traceback.print_exception(exc_type, exc_obj, exc_tb)
finally:
    netns.remove('ns1')



