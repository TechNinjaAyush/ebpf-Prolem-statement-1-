//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u16));
    __uint(max_entries, 1);
} port_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_dropper(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    __u32 key = 0;
    __u16 *allowed_port = bpf_map_lookup_elem(&port_map, &key);
    if (!allowed_port) return XDP_PASS;

    // Flip logic: allow only the allowed port
    if (tcp->dest != bpf_htons(*allowed_port)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
