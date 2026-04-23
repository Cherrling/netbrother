//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_INET  2
#define AF_INET6 10

#define EVENT_CONNECT 1
#define EVENT_ACCEPT  2
#define EVENT_CLOSE   3

struct event {
	__u32 type;		// EVENT_CONNECT | EVENT_ACCEPT | EVENT_CLOSE
	__u32 pid;
	__u32 tid;
	char comm[16];
	__u16 family;		// AF_INET or AF_INET6
	__u16 sport;		// local port (host byte order)
	__u16 dport;		// dest port (network byte order)
	__u32 saddr_v4;		// local IPv4
	__u32 daddr_v4;		// dest IPv4
	__u8  saddr_v6[16];	// local IPv6
	__u8  daddr_v6[16];	// dest IPv6
	__u64 inode;		// socket inode
};

struct pid_info {
	__u32 pid;
	char comm[16];
};

// Map: socket inode -> {PID, comm} for PID persistence across TIME_WAIT / process exit
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct pid_info);
} pid_by_inode SEC(".maps");

// Perf event array for connection events
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 256);
} events SEC(".maps");

static __always_inline void read_sock_info(struct sock *sk, struct event *evt)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	evt->pid = (__u32)(pid_tgid >> 32);
	evt->tid = (__u32)pid_tgid;
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	BPF_CORE_READ_INTO(&evt->family, sk, __sk_common.skc_family);

	if (evt->family == AF_INET) {
		BPF_CORE_READ_INTO(&evt->saddr_v4, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&evt->daddr_v4, sk, __sk_common.skc_daddr);
	} else if (evt->family == AF_INET6) {
		BPF_CORE_READ_INTO(&evt->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&evt->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	} else {
		return;
	}

	BPF_CORE_READ_INTO(&evt->sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&evt->dport, sk, __sk_common.skc_dport);

	// Read socket inode: sk->sk_socket->file->f_inode->i_ino
	struct socket *sockp;
	BPF_CORE_READ_INTO(&sockp, sk, sk_socket);
	if (sockp) {
		struct file *fp;
		BPF_CORE_READ_INTO(&fp, sockp, file);
		if (fp) {
			struct inode *inodep;
			BPF_CORE_READ_INTO(&inodep, fp, f_inode);
			if (inodep) {
				BPF_CORE_READ_INTO(&evt->inode, inodep, i_ino);
			}
		}
	}
}

// Store PID in map so it survives TIME_WAIT and process exit
static __always_inline void save_pid(__u64 inode, struct event *evt)
{
	if (inode == 0)
		return;
	struct pid_info info = {
		.pid = evt->pid,
	};
	__builtin_memcpy(info.comm, evt->comm, sizeof(info.comm));
	bpf_map_update_elem(&pid_by_inode, &inode, &info, BPF_ANY);
}

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk)
{
	struct event evt = {};
	read_sock_info(sk, &evt);
	if (evt.family != AF_INET && evt.family != AF_INET6)
		return 0;
	evt.type = EVENT_CONNECT;
	save_pid(evt.inode, &evt);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(inet_csk_accept, struct sock *sk, struct proto_accept_arg *arg, struct sock *ret)
{
	if (!ret)
		return 0;
	struct event evt = {};
	read_sock_info(ret, &evt);
	if (evt.family != AF_INET && evt.family != AF_INET6)
		return 0;
	evt.type = EVENT_ACCEPT;
	save_pid(evt.inode, &evt);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk)
{
	struct event evt = {};
	read_sock_info(sk, &evt);
	if (evt.family != AF_INET && evt.family != AF_INET6)
		return 0;
	evt.type = EVENT_CLOSE;

	// Look up PID from map (may have been saved by connect/accept earlier)
	__u64 inode = evt.inode;
	if (inode != 0) {
		struct pid_info *info = bpf_map_lookup_elem(&pid_by_inode, &inode);
		if (info) {
			evt.pid = info->pid;
			__builtin_memcpy(&evt.comm, info->comm, sizeof(evt.comm));
			bpf_map_delete_elem(&pid_by_inode, &inode);
		}
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

char __license[] SEC("license") = "GPL";
