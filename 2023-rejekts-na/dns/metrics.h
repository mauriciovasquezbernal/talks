#ifndef GADGET_METRICS
#define GADGET_METRICS

#ifndef METRICS_MAX_ENTRIES
#define METRICS_MAX_ENTRIES 10240
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((unsigned long)&((TYPE *)0)->MEMBER)
#endif

// stats
//////////////////////////////////
const volatile __u32 metrics_key_stats_mnt_ns_id_enabled = 1;
const volatile __u32 metrics_key_stats_pid_enabled = 1;
const volatile __u32 metrics_key_stats_tid_enabled = 1;
const volatile __u32 metrics_key_stats_uid_enabled = 1;
const volatile __u32 metrics_key_stats_gid_enabled = 1;
const volatile __u32 metrics_key_stats_task_enabled = 1;

// Key for "stats"
struct __attribute__((__packed__)) metrics_key_stats_t {
	mnt_ns_id_t mnt_ns_id;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	task task;
};

// Value for "stats"
struct metrics_val_stats_t {
	__u32 count;
	__u32 count2;
};

// Map for storing "stats"
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, METRICS_MAX_ENTRIES);
	__type(key, struct metrics_key_stats_t);
	__type(value, struct metrics_val_stats_t);
} metrics_map_stats SEC(".maps");

// Reference structs to keep them alive
const struct metrics_key_stats_t *unused_metrics_key_stats_t __attribute__((unused));
const struct metrics_val_stats_t *unused_metrics_val_stats_t __attribute__((unused));

// Scratch map for "stats" key
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct metrics_key_stats_t);
} tmp_metrics_key_stats_t SEC(".maps");

// metrics_stats_get_entry gets the metric entry for the given keys
// always inline due to param limit restriction
static __always_inline struct metrics_val_stats_t* metrics_stats_get_entry(
	mnt_ns_id_t* mnt_ns_id,
	__u32* pid,
	__u32* tid,
	__u32* uid,
	__u32* gid,
	task* task
) {
	const int metric_len =
		(metrics_key_stats_mnt_ns_id_enabled * sizeof(mnt_ns_id_t))
		+ (metrics_key_stats_pid_enabled * sizeof(__u32))
		+ (metrics_key_stats_tid_enabled * sizeof(__u32))
		+ (metrics_key_stats_uid_enabled * sizeof(__u32))
		+ (metrics_key_stats_gid_enabled * sizeof(__u32))
		+ (metrics_key_stats_task_enabled * sizeof(task));
	__u32 zero = 0;
	const unsigned char* key = bpf_map_lookup_elem(&tmp_metrics_key_stats_t, &zero);
	if (!key) return NULL;

	// prepare key
	int offs = 0;
	if (metrics_key_stats_mnt_ns_id_enabled) {
		__builtin_memcpy((void*)key + offs, (void*)mnt_ns_id, sizeof(mnt_ns_id_t));
		offs += sizeof(mnt_ns_id_t);
	}
	if (metrics_key_stats_pid_enabled) {
		__builtin_memcpy((void*)key + offs, (void*)pid, sizeof(__u32));
		offs += sizeof(__u32);
	}
	if (metrics_key_stats_tid_enabled) {
		__builtin_memcpy((void*)key + offs, (void*)tid, sizeof(__u32));
		offs += sizeof(__u32);
	}
	if (metrics_key_stats_uid_enabled) {
		__builtin_memcpy((void*)key + offs, (void*)uid, sizeof(__u32));
		offs += sizeof(__u32);
	}
	if (metrics_key_stats_gid_enabled) {
		__builtin_memcpy((void*)key + offs, (void*)gid, sizeof(__u32));
		offs += sizeof(__u32);
	}
	if (metrics_key_stats_task_enabled) {
		__builtin_memcpy((void*)key + offs, (void*)task, sizeof(task));
		offs += sizeof(task);
	};

	// fetch entry
	struct metrics_val_stats_t* values = bpf_map_lookup_elem(&metrics_map_stats, key);
	if (values == NULL) {
		struct metrics_val_stats_t emptyMetrics = {};
		bpf_map_update_elem(&metrics_map_stats, key, &emptyMetrics, BPF_NOEXIST);
		values = bpf_map_lookup_elem(&metrics_map_stats, key);
	}
	return values;
};

void metrics_stats_set_count(struct metrics_val_stats_t* values, __u32* val) {
	__builtin_memcpy((void*)values + offsetof(struct metrics_val_stats_t, count), val, sizeof(__u32));
}

void metrics_stats_add_count(struct metrics_val_stats_t* values, __u32 val) {
	__sync_fetch_and_add((__u32*)((void*)values + offsetof(struct metrics_val_stats_t, count)), val);
}

void metrics_stats_set_count2(struct metrics_val_stats_t* values, __u32* val) {
	__builtin_memcpy((void*)values + offsetof(struct metrics_val_stats_t, count2), val, sizeof(__u32));
}

void metrics_stats_add_count2(struct metrics_val_stats_t* values, __u32 val) {
	__sync_fetch_and_add((__u32*)((void*)values + offsetof(struct metrics_val_stats_t, count2)), val);
}

#endif