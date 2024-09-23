#!/usr/python3
from bcc import BPF
import time

device = "enp6s18"
b = BPF(src_file="pingpong.bpf.c")
fn = b.load_func("xdp_pingpong", BPF.XDP)
b.attach_xdp(device, fn, 0)

while 1:
	try:
		#b.trace_print()
		for addr,cnt in b.get_table("ip_count").items():
			addr = int.from_bytes(addr, byteorder='big')
			cnt = int.from_bytes(cnt, byteorder='little')
			print(f"{addr>>24 & 0xFF}.{addr>>16 & 0xFF}.{addr>>8 & 0xFF}.{addr & 0xFF}={cnt}")
		print("=====")
		time.sleep(1)
	except KeyboardInterrupt:
		break

print("detaching ebpf program")
b.remove_xdp(device, 0)
