#!/usr/python3
from bcc import BPF

device = "lo"
b = BPF(src_file="pingpong.bpf.c")
fn = b.load_func("xdp_pingpong", BPF.XDP)
b.attach_xdp(device, fn, 0)

try:
    b.trace_print()
except KeyboardInterrupt:
    print("detaching ebpf program")

b.remove_xdp(device, 0)

