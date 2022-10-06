// +build ignore

#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
	bpf_printk("execve() called. syscall number is %d", ctx->id);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";