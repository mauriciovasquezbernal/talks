// +build ignore

// Based on https://github.com/cilium/ebpf/tree/master/examples/xdp

#include "vmlinux.h"
#include "bpf_endian.h"
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800

char __license[] SEC("license") = "Dual MIT/GPL";

/* Define an LPM map for storing packet and bytes count */
struct value_type {
	u32 pkt_count;
	u32 bytes_count;
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct value_type);
} counter SEC(".maps");

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
	u32 zero = 0;

	struct value_type *valp = bpf_map_lookup_elem(&counter, &zero);
	if (!valp) {
		goto done;
	}

	bpf_spin_lock(&valp->lock);
	valp->pkt_count += 1;
	valp->bytes_count += ctx->data_end - ctx->data;
	bpf_spin_unlock(&valp->lock);

done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
