//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define AF_INET  2
#define AF_INET6 10

struct connect_event {
	__u64 pid;
	__u32 tid;
	char comm[16];
	__u16 family;
	__u16 sport;		// local port (host byte order)
	__u16 dport;		// dest port (network byte order)
	__u32 saddr_v4;		// local IPv4
	__u32 daddr_v4;		// dest IPv4
	__u8  saddr_v6[16];	// local IPv6
	__u8  daddr_v6[16];	// dest IPv6
	__u64 inode;		// socket inode
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 256);
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx)
{
	// On x86_64, first argument (struct sock *sk) is in di register.
	struct sock *sk = (struct sock *)ctx->di;

	__u16 family;
	bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

	if (family != AF_INET && family != AF_INET6)
		return 0;

	struct connect_event evt = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	evt.pid = pid_tgid >> 32;
	evt.tid = (__u32)pid_tgid;
	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
	evt.family = family;

	if (family == AF_INET) {
		bpf_probe_read_kernel(&evt.saddr_v4, sizeof(evt.saddr_v4),
			&sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&evt.daddr_v4, sizeof(evt.daddr_v4),
			&sk->__sk_common.skc_daddr);
	} else {
		bpf_probe_read_kernel(&evt.saddr_v6, sizeof(evt.saddr_v6),
			&sk->__sk_common.skc_v6_rcv_saddr);
		bpf_probe_read_kernel(&evt.daddr_v6, sizeof(evt.daddr_v6),
			&sk->__sk_common.skc_v6_daddr);
	}

	bpf_probe_read_kernel(&evt.sport, sizeof(evt.sport),
		&sk->__sk_common.skc_num);
	bpf_probe_read_kernel(&evt.dport, sizeof(evt.dport),
		&sk->__sk_common.skc_dport);

	// Read socket inode: sk->sk_socket->file->f_inode->i_ino
	struct socket *sockp;
	bpf_probe_read_kernel(&sockp, sizeof(sockp), &sk->sk_socket);
	if (sockp) {
		struct file *fp;
		bpf_probe_read_kernel(&fp, sizeof(fp), &sockp->file);
		if (fp) {
			struct inode *inodep;
			bpf_probe_read_kernel(&inodep, sizeof(inodep), &fp->f_inode);
			if (inodep) {
				bpf_probe_read_kernel(&evt.inode, sizeof(evt.inode),
					&inodep->i_ino);
			}
		}
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

char __license[] SEC("license") = "GPL";
