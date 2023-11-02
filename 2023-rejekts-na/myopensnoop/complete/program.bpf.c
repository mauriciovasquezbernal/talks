#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Inspektor Gadget macros
#include <gadget/macros.h>

#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define NAME_MAX 255

struct event {
	gadget_mntns_id mntns;
	__u32 pid;
	__u8 name[NAME_MAX];
	__u8 comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event evt = {};

	evt.mntns = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(evt.mntns)) {
		return 0;
	}

	evt.pid = bpf_get_current_pid_tgid() >> 32;

	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
	bpf_probe_read_user_str(&evt.name, sizeof(evt.name), (const char *)ctx->args[1]);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
