#!/usr/bin/python
#
# sync_timing.py    Trace time between syncs.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time between events.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import ctypes as ct
# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
BPF_HASH(last);
struct data_t {
    u64 cur_ts;
	u64 diff_ts;
};
BPF_PERF_OUTPUT(events);
int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, key = 0;
    struct data_t data = {};
    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
	    data.cur_ts = bpf_ktime_get_ns() / 1000000000;
	    data.diff_ts = bpf_ktime_get_ns() - *tsp;
        if (data.diff_ts < 1000000000) {
            // output if time is less than 1 second
            events.perf_submit(ctx, &data, sizeof(data));
        }
        last.delete(&key);
    }
    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")

class Data(ct.Structure):
    _fields_ = [("cur_ts", ct.c_uint),
                ("diff_ts", ct.c_ulonglong)
                ]

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")
# format output
start = 0
def print_event(cpu, data, size):
    global start


    #event = b["events"].event(data)

    event = ct.cast(data, ct.POINTER(Data)).contents

    if start == 0:
        start = event.cur_ts
    ts = event.cur_ts - start
    printb(b"At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, event.diff_ts / 1000000))
# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()