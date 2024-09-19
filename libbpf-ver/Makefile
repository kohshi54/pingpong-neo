TARGETS = pingpong

all: $(TARGETS)
.PHONY: all

$(TARGETS): %: %.bpf.o 

%.bpf.o: %_kern.c
	clang \
	    -target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -O2 -o $@ -c $<

clean: 
	- rm *.bpf.o
	- rm -f /sys/fs/bpf/pingpong 

load: 
	sudo bpftool prog load pingpong.bpf.o /sys/fs/bpf/pingpong

attach:
	sudo bpftool net attach xdp id 5671 dev enp6s18
	#@ID=$$(sudo bpftool prog show name xdp_pingpong | grep xdp_pingpong | awk '{print $$1}' | sed 's/://') && \
	#echo $$ID && \
	#sudo bpftool net attach xdp id $$ID dev lo

watch:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

detach:
	sudo bpftool net detach xdp dev enp6s18

unload::
	sudo rm -f /sys/fs/bpf/pingpong

list:
	sudo bpftool prog show name xdp_pingpong

