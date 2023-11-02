// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

struct __attribute__((__packed__)) labels_t {
	// User spaces uses it to enrich the metric with container metadata
	mnt_ns_id_t mntns;
	__u64 syscall_nr;
};

struct values_t {
	__u64 syscall_counter;
};

#define METRICS_MAX_ENTRIES 1024

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, METRICS_MAX_ENTRIES);
	__type(key, struct labels_t);
	__type(value, struct values_t);
} syscalls SEC(".maps");


SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	struct labels_t key = {};

	key.syscall_nr = ctx->args[1];
	key.mntns = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(key.mntns))
		return 0;

	struct values_t* values = bpf_map_lookup_elem(&syscalls, &key);
	if (!values) {
		struct values_t empty = {};
		bpf_map_update_elem(&syscalls, &key, &empty, BPF_NOEXIST);
		values = bpf_map_lookup_elem(&syscalls, &key);
	}
	if (values) {
		__sync_fetch_and_add(&values->syscall_counter, 1);
	}

	return 0;

}

char _license[] SEC("license") = "GPL";
