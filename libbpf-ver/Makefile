TARGETS = pingpong
DEV=enp6s18

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
	- rm -f pingpong_user

up: load list attach watch

down: detach unload

load: 
	sudo bpftool prog load pingpong.bpf.o /sys/fs/bpf/pingpong

attach:
	#sudo bpftool net attach xdp id 5707 dev enp6s18 #id changes on every load
	ID=$$(sudo bpftool prog show name xdp_pingpong | grep xdp_pingpong | awk '{print $$1}' | sed 's/://') && \
	echo $$ID && \
	sudo bpftool net attach xdp id $$ID dev $(DEV)

watch:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

detach:
	sudo bpftool net detach xdp dev $(DEV)

unload::
	sudo rm -f /sys/fs/bpf/pingpong

list:
	sudo bpftool prog show name xdp_pingpong

user:
	gcc -O2 -g -Wall -I/usr/include -o pingpong_user pingpong_user.c -lbpf -lelf -lz

