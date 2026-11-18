#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define AF_INET 2
#define WRITE_FLAGS_MASK (1 | 2 | 64 | 512)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct traffic_key_t);
    __type(value, struct traffic_val_t);
} traffic_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct sock *);
} udp_recv_socks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events_rb SEC(".maps");

static __always_inline int record_traffic(
    struct sock *sk, int bytes, bool is_tx, __u8 proto,
    __u32 override_daddr, __u16 override_dport)
{
    if (!sk || bytes <= 0)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    struct traffic_key_t key = {};
    key.cgroup_id = bpf_get_current_cgroup_id();
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr = override_daddr ? override_daddr : BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.dport = override_dport ? override_dport : bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    key.proto = proto;

    struct traffic_val_t *val = bpf_map_lookup_elem(&traffic_map, &key);
    if (!val) {
        struct traffic_val_t init_val = {};
        if (is_tx) init_val.tx_bytes = bytes;
        else       init_val.rx_bytes = bytes;
        bpf_map_update_elem(&traffic_map, &key, &init_val, BPF_NOEXIST);
    } else {
        if (is_tx) __sync_fetch_and_add(&val->tx_bytes, bytes);
        else       __sync_fetch_and_add(&val->rx_bytes, bytes);
    }
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    return record_traffic(sk, (int)size, true, PROTO_TCP, 0, 0);
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(handle_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    return record_traffic(sk, copied, false, PROTO_TCP, 0, 0);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dport = 0;

    if (daddr == 0 && msg) {
        struct sockaddr_in *sin = (struct sockaddr_in *)BPF_CORE_READ(msg, msg_name);
        if (sin) {
            __u16 fam = BPF_CORE_READ(sin, sin_family);
            if (fam == AF_INET) {
                daddr = BPF_CORE_READ(sin, sin_addr.s_addr);
                dport = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
            }
        }
    }
    return record_traffic(sk, (int)len, true, PROTO_UDP, daddr, dport);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(handle_udp_recv_enter, struct sock *sk) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&udp_recv_socks, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(handle_udp_recv_exit, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&udp_recv_socks, &pid_tgid);
    if (!skp)
        return 0;

    struct sock *sk = *skp;
    bpf_map_delete_elem(&udp_recv_socks, &pid_tgid);

    if (ret > 0 && sk) {
        return record_traffic(sk, ret, false, PROTO_UDP, 0, 0);
    }
    return 0;
}

static __always_inline bool starts_with(const char *s, const char *prefix, int len) {
    #pragma unroll
    for (int i = 0; i < len; i++) {
        if (s[i] != prefix[i])
            return false;
    }
    return true;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event_t *ev = bpf_ringbuf_reserve(&file_events_rb, sizeof(*ev), 0);
    if (!ev)
        return 0;

    long ret = bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (const void *)ctx->args[1]);
    if (ret <= 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    __u32 flags = (__u32)ctx->args[2];
    bool is_write = (flags & WRITE_FLAGS_MASK) != 0;
    bool is_critical = false;

    if (starts_with(ev->filename, "/etc/shadow", 11) ||
        starts_with(ev->filename, "/etc/passwd", 11) ||
        starts_with(ev->filename, "/etc/sudoers", 12) ||
        starts_with(ev->filename, "/etc/cron", 9) ||
        starts_with(ev->filename, "/etc/ld.so.preload", 18) ||
        starts_with(ev->filename, "/var/run/docker.sock", 20) ||
        starts_with(ev->filename, "/root/.ssh", 10) ||
        starts_with(ev->filename, "/sys/fs/cgroup", 14) ||
        starts_with(ev->filename, "/proc/sys", 9) ||
        starts_with(ev->filename, "/boot/", 6)) {
        is_critical = true;
    }

    if (is_write && (
        starts_with(ev->filename, "/etc/", 5) ||
        starts_with(ev->filename, "/bin/", 5) ||
        starts_with(ev->filename, "/sbin/", 6) ||
        starts_with(ev->filename, "/usr/bin/", 9) ||
        starts_with(ev->filename, "/usr/sbin/", 10) ||
        starts_with(ev->filename, "/lib/", 5))) {
        is_critical = true;
    }

    if (!is_critical) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    ev->cgroup_id = bpf_get_current_cgroup_id();
    ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    ev->flags = flags;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
