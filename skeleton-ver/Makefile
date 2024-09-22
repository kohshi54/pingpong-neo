all: pingpong.bpf.o pingpong.skel.h pingpong.o

pingpong.bpf.o: pingpong.bpf.c
	clang -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -g -O -o pingpong.bpf.o -c pingpong.bpf.c

pingpong.skel.h: pingpong.bpf.o
	bpftool gen skeleton pingpong.bpf.o > pingpong.skel.h

pingpong.o: pingpong.c
	clang -g -O2 -I/usr/include/x86_64-linux-gnu/ -lbpf pingpong.c -o pingpong

clean:
	rm -f pingpong pingpong.o pingpong.bpf.o

