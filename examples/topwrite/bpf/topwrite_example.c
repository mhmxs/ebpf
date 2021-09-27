#include "vmlinux.h"
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
	u32 pid;
	char comm[80];
	char fname[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/generic_write_end")
int kprobe_generic_write_end(struct pt_regs *ctx) {
	struct event_t *task_info;
	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&task_info->comm, 80);

	struct file* file = (struct file *)ctx->di;
	BPF_CORE_READ_INTO(&task_info->fname, file, f_path.dentry, d_iname);

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}

