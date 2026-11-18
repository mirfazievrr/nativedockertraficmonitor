#ifndef COMMON_H
#define COMMON_H

#ifndef __BPF__
#include <linux/types.h>
#endif

#define MAX_FILENAME_LEN 128
#define TASK_COMM_LEN 16

#define PROTO_TCP 6
#define PROTO_UDP 17

struct traffic_key_t {
    __u64 cgroup_id;
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __u8  proto;
    __u8  pad[5];
};

struct traffic_val_t {
    __u64 tx_bytes;
    __u64 rx_bytes;
};

struct file_event_t {
    __u64 cgroup_id;
    __u32 pid;
    __u32 flags;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif
