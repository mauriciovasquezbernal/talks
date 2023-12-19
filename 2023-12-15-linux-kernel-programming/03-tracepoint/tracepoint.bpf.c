// +build ignore

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"

SEC("tracepoint/syscalls/sys_enter_shutdown")
int sys_enter_shutdown(struct trace_event_raw_sys_enter* ctx) {
	int fd = (int)ctx->args[0];
	int how = (int)ctx->args[1];

	bpf_printk("shutdown() called. fd:%d, how:%d", fd, how);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";