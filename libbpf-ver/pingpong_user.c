#include <stdio.h>
//#include <stdlib.h>
//#include <errno.h>
//#include <string.h>
//#include <unistd.h>
//#include <bpf/bpf.h>
#include <net/if.h>
#include <bpf/libbpf.h>
//#include <linux/if_link.h>

int main(int argc, char **argv) {
    int ifindex;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;

    ifindex = if_nametoindex("enp6s18");
    obj = bpf_object__open_file("pingpong.bpf.o", NULL);
    bpf_object__load(obj);
    prog = bpf_object__find_program_by_title(obj, "xdp");
    prog_fd = bpf_program__fd(prog);
    bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    bpf_object__close(obj);
    printf("load and attached pingpong program\n");

    return 0;

/*
    const char *prog_file = "pingpong.bpf.o";
    const char *ifname = "enp6s18";
    int ifindex;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    int err;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return EXIT_FAILURE;
    }
    
    obj = bpf_object__open_file(prog_file, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file %s\n", prog_file);
        return EXIT_FAILURE;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }
    
    prog = bpf_object__find_program_by_title(obj, "xdp");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program in %s\n", prog_file);
        err = -ENOENT;
        goto cleanup;
    }
    
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        err = prog_fd;
        goto cleanup;
    }
    
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (err < 0) {
        fprintf(stderr, "Failed to attach XDP program to interface %s: %s\n", ifname, strerror(-err));
        goto cleanup;
    }
    
    printf("Successfully attached XDP program %s to interface %s (ifindex %d)\n", prog_file, ifname, ifindex);
    
    bpf_object__close(obj);
    return EXIT_SUCCESS;

cleanup:
    bpf_object__close(obj);
    return EXIT_FAILURE;
*/
}

