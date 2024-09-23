#include <stdio.h>
//#include <stdlib.h>
//#include <errno.h>
//#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <bpf/libbpf.h>
//#include <linux/if_link.h>
#include <signal.h>
#include <arpa/inet.h>

static volatile int stopflg = 0;

static void	signal_handler(int signum, siginfo_t *info, void *context) {
	if (signum == SIGINT) {
		stopflg = 1;
	}
}

void	set_sigaction(struct sigaction *act, void (*signal_handler) \
						(int signum, siginfo_t *info, void *context))
{
	bzero(act, sizeof(*act));
	sigemptyset(&(act->sa_mask));
	sigaddset(&(act->sa_mask), SIGINT);
	act->sa_flags = SA_SIGINFO;
	act->sa_sigaction = signal_handler;
	sigaction(SIGINT, act, NULL) == -1;
}

int main(int argc, char **argv) {
    int ifindex;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
	struct sigaction act;

    ifindex = if_nametoindex("enp6s18");
    obj = bpf_object__open_file("pingpong.bpf.o", NULL);
    bpf_object__load(obj);
    prog = bpf_object__find_program_by_title(obj, "xdp");
    prog_fd = bpf_program__fd(prog);
    bpf_set_link_xdp_fd(ifindex, prog_fd, 0);

    printf("load and attached pingpong program\n");

	set_sigaction(&act, signal_handler);

	struct bpf_map *map = bpf_object__find_map_by_name(obj, "rcv_ipcnt");
	if (!map) write(2, "no map\n", 7);
	int map_fd = bpf_map__fd(map);
	if (map_fd < 0) write(2, "no map fd\n", 10);
	while (!stopflg) {
		int prev_key = -1;
		int cur_key = 0;
		write(2, "=====\n", 6);
		while (1) {
			int err;
			if (prev_key == -1)	
				err = bpf_map_get_next_key(map_fd, NULL, &cur_key);
			else
				err = bpf_map_get_next_key(map_fd, &prev_key, &cur_key);
			if (err)
				break;

			int value = 0;
			int a = bpf_map_lookup_elem(map_fd, &cur_key, &value);
			if (a == 0) {
				long b = htonl(cur_key);
				int c = (b >> 24) & 0xFF;
				int d = (b >> 16) & 0xFF;
				int e = (b >> 8) & 0xFF;
				int f = b & 0xFF;
				printf("%d.%d.%d.%d=%d\n", c, d, e, f, value);
			}
			prev_key = cur_key;
			//write(2, "--\n", 3);
		}
		sleep(1);
	}

cleanup:
	printf("cleaning up\n");
	bpf_set_link_xdp_fd(ifindex, -1, 0); //-1=detach
    bpf_object__close(obj); //unlaod

    return 0;
}

