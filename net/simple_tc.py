# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

#  pip install pyroute2==0.5.0 -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com


from bcc import BPF
from pyroute2 import IPRoute

ipr = IPRoute()

text = """
int hello(struct __sk_buff *skb) {
  return 1;
}
"""

try:
    b = BPF(text=text, debug=0)
    fn = b.load_func("hello", BPF.SCHED_CLS)
    ipr.link_create(ifname="t1a", kind="veth", peer="t1b")
    idx = ipr.link_lookup(ifname="t1a")[0]


    # in qdisc
    #ipr.tc("add", "ingress", idx, "ffff:")
    #res1=ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd,
           #name=fn.name, parent="ffff:", action="ok", classid=1)
   # print(res1)
    # out qdisc
    #ipr.tc("add", "sfq", idx, "1:")
    #res2=ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd,
           #name=fn.name, parent="1:", action="ok", classid=1)
   # print(res2)
finally:
    print(1)
    #if "idx" in locals(): ipr.link_remove(idx)
print("BPF tc functionsudoality - SCHED_CLS: OK")