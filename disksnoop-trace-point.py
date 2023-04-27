#!/usr/bin/python
#
# disksnoop.py  Trace block device I/O: basic version of iosnoop.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015   Brendan Gregg   Created this.
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
REQ_WRITE = 1   # from include/linux/blk_types.h
# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
struct data_t {
    u64 len;
    char rwbs[8];
    u64 ts;
};
BPF_HASH(start,u64,struct data_t); //定义一个名为start的哈希，key类型为u64，value类型为struct data_t,注意此处非指针
TRACEPOINT_PROBE(block,block_rq_issue){
    u64 key = 0;
    struct data_t data = {}; //在跟踪block_rq_issue的时候赋值
    data.len = args->bytes;
    bpf_probe_read(&data.rwbs,sizeof(data.rwbs),(void *)args->rwbs);
    data.ts = bpf_ktime_get_ns();
    start.update(&key, &data);
    return 0;
}
TRACEPOINT_PROBE(block,block_rq_complete){
    u64 delta, key = 0;
    struct data_t* datap;
    datap = start.lookup(&key); //在跟踪block_rq_complete时取出保存的值
    if (datap != NULL) {
        delta = bpf_ktime_get_ns() - datap->ts;
        bpf_trace_printk("%d %x %d\\n", datap->len,
        datap->rwbs, delta / 1000);
        start.delete(&key);
    }
    return 0;
}
""")
# header
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))
# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (bytes_s, bflags_s, us_s) = msg.split()
        if int(bflags_s, 16) & REQ_WRITE:
            type_s = b"W"
        elif bytes_s == "0":    # see blk_fill_rwbs() for logic
            type_s = b"M"
        else:
            type_s = b"R"
            ms = float(int(us_s, 10)) / 1000
            printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))
    except KeyboardInterrupt:
        exit()