// SPDX-License-Identifier: GPL-2.0
//
// Sentinel in-kernel telemetry + tamper-protection (libbpf CO-RE).
//
// Why C + libbpf (not aya): struct-field reads (task_struct->tgid, linux_binprm->filename)
// need CO-RE field relocations, which clang emits natively via preserve_access_index and
// libbpf relocates against the target kernel's BTF at load — one object runs on every dev-PC
// kernel. (aya's field-CO-RE is still experimental.) This is the Cilium/Tracee/Datadog path.
//
// Programs:
//   tracepoint/sched/sched_process_exec  -> real-time exec telemetry (path + uid + ppid)
//   lsm/task_kill                        -> deny kill of the agent (root included)
//   lsm/ptrace_access_check              -> deny debugger attach to the agent
//   lsm/bprm_check_security              -> exec allow/deny gate (blocklist by path hash)
//   lsm/inode_unlink / inode_rename      -> deny delete/rename of agent binary, key, config
//
// Enforcement is gated by the ENFORCE map (0 audit / 1 enforce-allow-init / 2 enforce-all) so
// it can be armed live and a bad policy can't wedge the host before we trust it.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define FNAME_LEN 256
#define EPERM 1

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8 comm[TASK_COMM_LEN];
    __u8 filename[FNAME_LEN];
};

// Telemetry channel (ring buffer; userspace polls).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} EXEC_EVENTS SEC(".maps");

// PIDs the agent protects (its own pid + the guardian). Userspace writes these at startup.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} PROTECTED_PIDS SEC(".maps");

// Enforcement level: 0 = audit only, 1 = enforce but allow init(pid1) to manage,
// 2 = enforce, deny everyone but the agent itself. Single slot.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ENFORCE SEC(".maps");

// Exec blocklist: fnv-1a(path) -> 1. The bprm gate denies these when enforcing.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} BLOCKED_EXEC SEC(".maps");

// Inodes to protect from delete/rename (agent binary, pinned key, config). Userspace fills.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u8);
} PROTECTED_INODES SEC(".maps");

static __always_inline __u32 enforce_level(void)
{
    __u32 k = 0;
    __u32 *v = bpf_map_lookup_elem(&ENFORCE, &k);
    return v ? *v : 0;
}

static __always_inline int is_protected_pid(__u32 pid)
{
    return bpf_map_lookup_elem(&PROTECTED_PIDS, &pid) != 0;
}

// fnv-1a over a NUL-terminated path (bounded for the verifier). MUST match the userspace hash.
static __always_inline __u64 fnv1a(const __u8 *s, int max)
{
    __u64 h = 0xcbf29ce484222325ULL;
#pragma unroll
    for (int i = 0; i < max; i++) {
        __u8 c = s[i];
        if (c == 0)
            break;
        h ^= c;
        h *= 0x100000001b3ULL;
    }
    return h;
}

// ---------------- telemetry: process exec ----------------

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&EXEC_EVENTS, sizeof(*e), 0);
    if (!e)
        return 0;
    __u64 pt = bpf_get_current_pid_tgid();
    e->pid = pt >> 32;
    e->uid = (__u32)bpf_get_current_uid_gid();
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(t, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // filename via the tracepoint __data_loc offset (low 16 bits).
    unsigned short off = (unsigned short)(ctx->__data_loc_filename & 0xFFFF);
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + off);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------- enforcement: kill protection ----------------

SEC("lsm/task_kill")
int BPF_PROG(sentinel_task_kill, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred)
{
    __u32 level = enforce_level();
    if (level == 0)
        return 0;
    __u32 target = BPF_CORE_READ(p, tgid);
    if (!is_protected_pid(target))
        return 0;
    __u32 caller = bpf_get_current_pid_tgid() >> 32;
    if (is_protected_pid(caller))
        return 0; // the agent / guardian may signal themselves
    if (level == 1 && caller == 1)
        return 0; // allow systemd(init) to manage at level 1
    return -EPERM; // deny: root cannot kill the agent
}

// ---------------- enforcement: anti-debug ----------------

SEC("lsm/ptrace_access_check")
int BPF_PROG(sentinel_ptrace, struct task_struct *child, unsigned int mode)
{
    if (enforce_level() == 0)
        return 0;
    __u32 target = BPF_CORE_READ(child, tgid);
    if (!is_protected_pid(target))
        return 0;
    __u32 caller = bpf_get_current_pid_tgid() >> 32;
    if (is_protected_pid(caller))
        return 0;
    return -EPERM;
}

// ---------------- enforcement: exec gate ----------------

SEC("lsm/bprm_check_security")
int BPF_PROG(sentinel_bprm, struct linux_binprm *bprm)
{
    if (enforce_level() == 0)
        return 0;
    const char *fn = BPF_CORE_READ(bprm, filename);
    if (!fn)
        return 0;
    __u8 buf[FNAME_LEN];
    long n = bpf_probe_read_kernel_str(buf, sizeof(buf), fn);
    if (n <= 0)
        return 0;
    __u64 h = fnv1a(buf, FNAME_LEN);
    if (bpf_map_lookup_elem(&BLOCKED_EXEC, &h))
        return -EPERM; // blocked binary cannot execute
    return 0;
}

// ---------------- enforcement: protect agent files ----------------

static __always_inline int deny_if_protected_inode(struct dentry *dentry)
{
    if (enforce_level() == 0)
        return 0;
    __u64 ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    if (ino && bpf_map_lookup_elem(&PROTECTED_INODES, &ino)) {
        __u32 caller = bpf_get_current_pid_tgid() >> 32;
        if (is_protected_pid(caller))
            return 0; // the agent may replace its own files (self-update)
        return -EPERM;
    }
    return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(sentinel_unlink, struct inode *dir, struct dentry *dentry)
{
    return deny_if_protected_inode(dentry);
}

SEC("lsm/inode_rename")
int BPF_PROG(sentinel_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry)
{
    return deny_if_protected_inode(old_dentry);
}
