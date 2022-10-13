// +build ignore

#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/swab.h>
#include <linux/pkt_cls.h>

#include "bpf_endian.h"

char __license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); // ipv4
	__type(value, __u8); // not used
} ips SEC(".maps");

SEC("classifier_egress_drop")
int egress_drop(struct __sk_buff *skb) {
	bpf_printk("Packet on egress");

	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

	// Check if the packet is not malformed
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	// Check that this is an IP packet
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return TC_ACT_OK;

	// Check if the packet is not malformed
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return TC_ACT_SHOT;

	// Drop packet if in map
	__u8 *dummy = bpf_map_lookup_elem(&ips, &ip->daddr);
	if (dummy) {
		bpf_printk("Dropping in egress");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("classifier_ingress_drop")
int ingress_drop(struct __sk_buff *skb) {
	bpf_printk("Packet on ingress");

	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

	// Check if the packet is not malformed
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	// Check that this is an IP packet
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return TC_ACT_OK;

	// Check if the packet is not malformed
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return TC_ACT_SHOT;

	// Drop packet if in map
	__u8 *dummy = bpf_map_lookup_elem(&ips, &ip->saddr);
	if (dummy)
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}
