#!/usr/bin/python
#
# tc_perf_event.py  Output skb and meta data through perf event
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
import struct
from bcc import BPF
import ctypes as ct
import pyroute2
import socket
import netaddr

import ipaddress

bpf_txt = """
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>

BPF_PERF_OUTPUT(skb_events);


struct info{
    u32 src_ip;
    u32 dst_ip;
    u64 src_mac;
    u64 dst_mac;
};


int handle_egress(struct __sk_buff *skb)
{

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
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return TC_ACT_OK;

    /* if proto is ipv4  */
    //if (eth->h_proto == htons(ETH_P_IP)){
    
        info.src_ip = ntohl(iph->saddr);
        info.dst_ip = ntohl(iph->daddr);
        info.src_mac = *((u64 *)(eth->h_source));
        info.dst_mac = *((u64 *)(eth->h_dest));
        skb_events.perf_submit_skb(skb, skb->len,&info,sizeof(info));
   // }
            

    return TC_ACT_OK;
}"""


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
    print("%-3s %-15s %-15s %s,%s" % (cpu, socket.inet_ntoa(src_ip),socket.inet_ntoa(dst_ip),source_mac_str,dest_mac_str))


try:
    b = BPF(text=bpf_txt)
    fn = b.load_func("handle_egress", BPF.SCHED_CLS)

    ipr = pyroute2.IPRoute()
    ipr.link("add", ifname="me", kind="veth", peer="you")
    me = ipr.link_lookup(ifname="me")[0]
    you = ipr.link_lookup(ifname="you")[0]
    ipr.addr('add', index=me, address='192.168.50.2', prefixlen=24)
    ipr.addr('add', index=you, address='192.168.50.3', prefixlen=24)

    for idx in (me, you):
        ipr.link('set', index=idx, state='up')

    ipr.tc("add", "clsact", me)
    res = ipr.tc("add-filter", "bpf", me, ":1", fd=fn.fd, name=fn.name,
           parent="ffff:fff3", classid=1, direct_action=True)
    print("res is",res)

    b["skb_events"].open_perf_buffer(print_skb_event)
    print('Try: "ping -c 1 IP"\n')
    print("%-3s %-15s %-15s %-10s" % ("CPU", "SRC IP", "DST IP", "Magic"))
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
finally:
    if "me" in locals(): ipr.link("del", index=me)
