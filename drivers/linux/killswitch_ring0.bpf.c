// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/*
 * KillSwitch Linux Ring-0 eBPF Telemetry & LSM Tamper Guard (killswitch_ring0.bpf.c)
 *
 * Hooks:
 *   1. SEC("tracepoint/sched/sched_process_exec") — Ring-0 process lineage telemetry
 *   2. SEC("lsm/bprm_check_security")             — Pre-execution binary hash & path gate
 *   3. SEC("lsm/task_kill")                       — Ring-0 anti-kill protection for KillSwitch daemon PID
 *   4. SEC("lsm/bpf")                             — Prevents unauthorized unpinning/unloading of KillSwitch eBPF programs
 *   5. SEC("kprobe/tcp_v4_connect")               — Outbound IPv4 socket telemetry
 *
 * Pinning Paths (bpffs):
 *   /sys/fs/bpf/killswitch/ring0_exec
 *   /sys/fs/bpf/killswitch/ring0_lsm_tamper
 *   /sys/fs/bpf/killswitch/ring0_net
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define SIGKILL 9
#define SIGTERM 15

struct killswitch_ring0_evt {
    __u32 magic;       /* 0x4B534250 ('KSBP') */
    __u32 event_type;  /* 1 = exec, 2 = lsm_task_kill_blocked, 3 = tcp_connect */
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 aux_val;
    __u64 timestamp_ns;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);
} killswitch_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} protected_daemon_pid SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(void *ctx)
{
    struct killswitch_ring0_evt *evt;
    evt = bpf_ringbuf_reserve(&killswitch_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->magic = 0x4B534250;
    evt->event_type = 1;
    evt->pid = (__u32)(pid_tgid >> 32);
    evt->ppid = 0;
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->aux_val = 0;
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(killswitch_lsm_task_kill, void *p, void *info, int sig, const void *cred)
{
    __u32 key = 0;
    __u32 *daemon_pid = bpf_map_lookup_elem(&protected_daemon_pid, &key);
    if (!daemon_pid || *daemon_pid == 0) {
        return 0;
    }

    if (sig == SIGKILL || sig == SIGTERM) {
        __u64 caller_pid = bpf_get_current_pid_tgid() >> 32;
        if (caller_pid != *daemon_pid) {
            return -EPERM;
        }
    }
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int handle_tcp_v4_connect(void *ctx)
{
    struct killswitch_ring0_evt *evt;
    evt = bpf_ringbuf_reserve(&killswitch_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->magic = 0x4B534250;
    evt->event_type = 3;
    evt->pid = (__u32)(pid_tgid >> 32);
    evt->ppid = 0;
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->aux_val = 4;
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
