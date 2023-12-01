// +build ignore

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
	char filename[255];

	bpf_core_read_user_str(filename, sizeof(filename), (const char *)ctx->args[0]);
	bpf_printk("execve() called: %s", filename);

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int sys_exit_execve(struct trace_event_raw_sys_exit* ctx) {

	bpf_printk("execve() returned: %d", ctx->ret);

	return 0;
}


char LICENSE[] SEC("license") = "GPL";