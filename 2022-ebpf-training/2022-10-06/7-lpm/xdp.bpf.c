// +build ignore

// Based on https://github.com/cilium/ebpf/tree/master/examples/xdp

#include "vmlinux.h"
#include "bpf_endian.h"
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800

char __license[] SEC("license") = "GPL";

struct v4_lpm_key {
	u32 prefix_len;
	u32 addr;
} __attribute__((packed));

/* Define an LPM map for storing packet count by subnet */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct v4_lpm_key);   // int + IPv4
	__type(value, __u32); // packet count
	__uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_stats SEC(".maps");

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);
	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	__u32 ip;
	if (!parse_ip_src_addr(ctx, &ip)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}

	struct v4_lpm_key lpm_key = {32, ip};

	__u32 *pkt_count = bpf_map_lookup_elem(&lpm_stats, &lpm_key);
	if (!pkt_count) {
		// we're not interested on this!
		goto done;
	}

	// Entry already exists for this IP address,
	// so increment it atomically using an LLVM built-in.
	__sync_fetch_and_add(pkt_count, 1);

done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
