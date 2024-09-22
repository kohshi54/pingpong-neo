#include <unistd.h>
#include "pingpong.skel.h"
//#include <bpf/libbpf.h>

int main(void) {
    struct pingpong_bpf *obj;

    obj = pingpong_bpf__open();
    if (!obj) {
        write(2, "failed to open BPF object\n", 26);
        return 1;
    }
    if (pingpong_bpf__load(obj)) {
        write(2, "failed to load BPF object\n", 26);
        goto cleanup;
    }
    if (pingpong_bpf__attach(obj)) {
        write(2, "failed to attach BPF object\n", 28);
        goto cleanup;
    }
    for (;;) {
        sleep(1);
    }

cleanup:
    pingpong_bpf__destroy(obj);
    return 0;
}

