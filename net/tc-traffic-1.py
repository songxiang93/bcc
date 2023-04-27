#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen

import sys
from time import sleep
from builtins import input

ipr = IPRoute()
ipdb = IPDB(nl=ipr)
b = BPF(src_file="tc_neighbor_sharing.c", debug=0)

wan_fn = b.load_func("classify_wan", BPF.SCHED_CLS)
pass_fn = b.load_func("pass", BPF.SCHED_CLS)
neighbor_fn = b.load_func("classify_neighbor", BPF.SCHED_CLS)

num_neighbors = 3
num_locals = 2

# create a namespace and load the specified eBPF program in it
def create_ns_and_load_bpf(ns_name, ip_addr, bpf_fn):
    with NetNS(ns_name) as ns:
        # create a virtual network interface in the given namespace
        netif = ns.create_interface(name="eth0", kind="veth",
                                    peer={"target": "xeth0"})
        # set the IP address of the interface
        ns.interfaces.eth0.add_ip(ip_addr)

    # attach the BPF program to the virtual network interface in the given namespace
    fd = bpf_fn.load()
    ipr.tc("add-filter", "bpf", netif["index"], ":1", fd=fd, prio=1,
           name=fd.name, parent="ffff:", action="drop", classid=1,
           rate="128kbit", burst=1024 * 32, mtu=16 * 1024)

    return (ns_name, netif)

# start the namespaces that compose the network, interconnect them with the
# bridge, and attach the tc filters
def start():
    neighbor_list = []
    local_list = []

    cmd = ["netserver", "-D"]
    for i in range(0, num_neighbors):
        ipaddr = "172.16.1.%d/24" % (i + 100)
        ret = create_ns_and_load_bpf("neighbor%d" % i, ipaddr, neighbor_fn)
        neighbor_list.append(ret)

    for i in range(0, num_locals):
        ipaddr = "172.16.1.%d/24" % (i + 150)
        ret = create_ns_and_load_bpf("local%d" % i, ipaddr, pass_fn)
        local_list.append(ret)

    # create the wan namespace, and attach an ingress filter for throttling
    # inbound (download) traffic
    with NetNS("wan0") as wan_ns:
        wan_if = wan_ns.create_interface(name="eth0", kind="veth",
                                          peer={"target": "xeth0"})
        wan_ns.interfaces.eth0.add_ip("172.16.1.5/24")
        fd = wan_fn.load()
        ipr.tc("add", "ingress", wan_if["index"], "ffff:")
        ipr.tc("add-filter", "bpf", wan_if["index"], ":1", fd=fd, prio=1,
               name=fd.name, parent="ffff:", action="drop", classid=1,
               rate="128kbit", burst=1024 * 32, mtu=16 * 1024)
        ipr.tc("add-filter", "bpf", wan_if["index"], ":2", fd=pass_fn.fd,
               prio=2, name=pass_fn.name, parent="ffff:", action="drop",
               classid=2, rate="1024kbit", burst=1024 * 32, mtu=16 * 1024)

    # create a virtual bridge and attach all the network interfaces to it
    with ipdb.create(ifname="br100", kind="bridge") as br100:
        for x in neighbor_list:
            br100.add_port(x[1])
        for x in local_list:
            br100.add_port(x[1])
        wan_netif = ipdb.interfaces.get_by_name("wan0").wireless
        br100.add_port(wan_netif)
        br100.up()

try:
    start()
    print("Network ready. Create a shell in the wan0 namespace and test with netperf")
    print("   (Neighbors are 172.16.1.100-%d, and LAN clients are 172.16.1.150-%d)"
            % (100 + num_neighbors - 1, 150 + num_locals - 1))
    print(" e.g.: ip netns exec wan0 netperf -H 172.16.1.100 -l 2")
    input("Press enter when finished: ")
finally:
    if "br100" in ipdb.interfaces:
        ipdb.interfaces.br100.remove().commit()
    for i in range(0, num_neighbors):
        NSPopen(["ip", "netns", "delete", "neighbor%d" % i]).wait()
    for i in range(0, num_locals):
        NSPopen(["ip", "netns", "delete", "local%d" % i]).wait()
    NSPopen(["ip", "netns", "delete", "wan0"]).wait()
    ipdb.release()