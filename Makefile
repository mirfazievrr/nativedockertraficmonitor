all: monitor

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

monitor.bpf.o: monitor.bpf.c common.h vmlinux.h
	clang -O2 -g -Wno-missing-declarations -target bpf -D__TARGET_ARCH_x86 -c monitor.bpf.c -o monitor.bpf.o

monitor.skel.h: monitor.bpf.o
	bpftool gen skeleton monitor.bpf.o > monitor.skel.h

monitor: main.cpp monitor.skel.h common.h
	g++ -O2 -std=c++17 main.cpp -lbpf -lelf -lz -o monitor

clean:
	rm -f monitor.bpf.o monitor.skel.h monitor vmlinux.h
