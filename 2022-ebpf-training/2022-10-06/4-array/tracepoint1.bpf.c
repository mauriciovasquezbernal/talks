// +build ignore

#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} pidmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u32);
} counter SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;
	u32 initval = 1, *valp;
	u32 zero = 0, *pid_of_interest;

	/* check if we want to filter by this PID */
	pid_of_interest = bpf_map_lookup_elem(&pidmap, &zero);
	if (pid_of_interest == NULL || *pid_of_interest != pid) {
		return 0;
	}

	valp = bpf_map_lookup_elem(&counter, &pid);
	if (!valp) {
		bpf_map_update_elem(&counter, &pid, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
