//#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include <stdint.h>
//#include <linux/checksum.h>

#define ICMP_PROTO 1
#define ICMP_REQUEST 8
#define ICMP_REPLY 0
//#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, int);
	__uint(max_entries, 2);
} rcv_ipcnt SEC(".maps");

static __always_inline __u16 csum_fold_helper(__u32 csum) {
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static __always_inline __u16 icmp_checksum_diff(struct icmphdr *icmphdr_old, struct icmphdr *icmphdr_new, __u16 seed) {
	__u32 csum;
    __u32 size = sizeof(struct icmphdr);

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}

static __always_inline __u16 ip_checksum_diff(struct iphdr *iphdr_old, struct iphdr *iphdr_new, __u16 seed) {
	__u32 csum;
    __u32 size = sizeof(struct iphdr);

	csum = bpf_csum_diff((__be32 *)iphdr_old, size, (__be32 *)iphdr_new, size, seed);
	return csum_fold_helper(csum);
}

SEC("xdp")
int xdp_pingpong(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;  
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    struct iphdr *ip = (void *)eth + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return XDP_PASS;
    if (ip->protocol != ICMP_PROTO)
        return XDP_PASS;
    struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
    if ((void *)icmp + sizeof(struct icmphdr) > data_end)
        return XDP_PASS;
    if (icmp->type != ICMP_REQUEST)
        return XDP_PASS;

    bpf_printk("icmp echo request arrived");

/* swap l2 */
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    memcpy(src_mac, eth->h_source, 6);
    memcpy(dst_mac, eth->h_dest, 6);
    memcpy(eth->h_source, dst_mac, 6);
    memcpy(eth->h_dest, src_mac, 6);

/* swap l3 */
    __be32 src_ip = ip->saddr;
    __be32 dst_ip = ip->daddr;
	int *a = bpf_map_lookup_elem(&rcv_ipcnt, &src_ip);
	if (a) {
		int tmp = *a + 1;
		bpf_map_update_elem(&rcv_ipcnt, &src_ip, &tmp, BPF_EXIST);
	} else {
		int tmp = 1;
		bpf_map_update_elem(&rcv_ipcnt, &src_ip, &tmp, BPF_NOEXIST);
		//bpf_map_update_elem(&rcv_ipcnt, &src_ip, &tmp, BPF_ANY);
	}
    ip->saddr = dst_ip;
    ip->daddr = src_ip;

	//uint8_t old_ttl = ip->ttl;
	//ip->ttl = 125;
	//csum_replace2(&ip->check, old_ttl, ip->ttl);

    __u16 old_check = ip->check;
    ip->check = 0;
    struct iphdr iphdr_old = *ip;
    ip->ttl = 125;
    ip->check = ip_checksum_diff(&iphdr_old, ip, ~old_check);

/* update l4 (icmp type and csum) */
    //csum_replace2(&icmp->checksum, ICMP_REQUEST, ICMP_REPLY);

    __u16 old_csum = icmp->checksum;
    icmp->checksum = 0;
    struct icmphdr icmphdr_old = *icmp;
    icmp->type = ICMP_REPLY;
    icmp->checksum = icmp_checksum_diff(&icmphdr_old, icmp, ~old_csum);
    
    return XDP_TX;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

