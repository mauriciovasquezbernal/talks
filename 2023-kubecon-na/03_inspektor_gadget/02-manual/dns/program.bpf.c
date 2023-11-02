// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <sys/socket.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <gadget/macros.h>
#include <gadget/types.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

struct __attribute__((__packed__)) labels_t {
	// User spaces uses it to enrich the metric with container metadata
	mnt_ns_id_t mntns;
	// request = 0, response = 1
	__u8 qr;
};

struct values_t {
	__u32 dns_packets;
};

#define METRICS_MAX_ENTRIES 1024

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, METRICS_MAX_ENTRIES);
	__type(key, struct labels_t);
	__type(value, struct values_t);
} dns SEC(".maps");

#define DNS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
union dnsflags {
	struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		__u8 rcode : 4; // response code
		__u8 z : 3; // reserved
		__u8 ra : 1; // recursion available
		__u8 rd : 1; // recursion desired
		__u8 tc : 1; // truncation
		__u8 aa : 1; // authoritive answer
		__u8 opcode : 4; // kind of query
		__u8 qr : 1; // 0=query; 1=response
#elif __BYTE_ORDER == __ORDER_BIG_ENDIAN__
		__u8 qr : 1; // 0=query; 1=response
		__u8 opcode : 4; // kind of query
		__u8 aa : 1; // authoritive answer
		__u8 tc : 1; // truncation
		__u8 rd : 1; // recursion desired
		__u8 ra : 1; // recursion available
		__u8 z : 3; // reserved
		__u8 rcode : 4; // response code
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif
	};
	__u16 flags;
};

struct dnshdr {
	__u16 id;

	union dnsflags flags;

	__u16 qdcount; // number of question entries
	__u16 ancount; // number of answer entries
	__u16 nscount; // number of authority records
	__u16 arcount; // number of additional records
};

SEC("socket1")
int ig_trace_dns(struct __sk_buff *skb)
{
	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	// Skip non-UDP packets
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) !=
		IPPROTO_UDP)
		return 0;

	union dnsflags flags;
	flags.flags = load_half(skb, DNS_OFF + offsetof(struct dnshdr, flags));

	struct labels_t key = {};
	key.qr = flags.qr;

	// Enrich event with process metadata
	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	if (skb_val != NULL) {
		key.mntns = skb_val->mntns;
	}

	struct values_t* values = bpf_map_lookup_elem(&dns, &key);
	if (!values) {
		struct values_t emptyMetrics = {};
		bpf_map_update_elem(&dns, &key, &emptyMetrics, BPF_NOEXIST);
		values = bpf_map_lookup_elem(&dns, &key);
	}
	if (values) {
		__sync_fetch_and_add(&values->dns_packets, 1);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
