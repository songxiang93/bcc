#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
from time import sleep
# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
BPF_HISTOGRAM(dist);
BPF_HASH(start, struct request *);
void trace_start(struct pt_regs *ctx, struct request *req) {
    // stash start timestamp by request ptr
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
}
void trace_completion(struct pt_regs *ctx, struct request *req) {
    u64 *tsp, delta;
    tsp = start.lookup(&req);
    if (tsp != 0) {
        delta = (bpf_ktime_get_ns() - *tsp)/1000;
        dist.increment(bpf_log2l(delta));
        //dist.increment((delta)); /*直接使用非bpf_log2l将无法输出结果，原因是本机延迟普遍大于250us，直方图无法输出这么多行，可以减少delta的比例即可，如设置delta = (bpf_ktime_get_ns() - *tsp)/100000;*/
        start.delete(&req);
    }
}
""")
# header
if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_account_io_completion", fn_name="trace_completion")
print("Tracing... Hit Ctrl-C to end.")
# trace until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    print()
# output
b["dist"].print_log2_hist("LAT-us")