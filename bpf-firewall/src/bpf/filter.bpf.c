// SPDX-License-Identifier: GPL-2.0
// CO-RE friendly includes
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "filter.h"
// Minimal kernel-like typedefs and constants to avoid linux/bpf.h dependency
typedef int __s32;
typedef __u32 __wsum;



#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef XDP_TX
#define XDP_TX 3
#endif
#ifndef XDP_REDIRECT
#define XDP_REDIRECT 4
#endif

#ifndef BPF_ANY
#define BPF_ANY 0
#endif
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif

char LICENSE[] SEC("license") = "GPL";

// Two maps: permanently banned and recently banned
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
	__type(key, __u32);           // IPv4 address in network byte order
	__type(value, ip_flag_t);     // presence flag (1)
} banned_ips SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
	__type(key, __u32);
	__type(value, ip_flag_t);
} recently_banned_ips SEC(".maps");

static __always_inline int parse_ipv4(void *data, void *data_end, __u32 *src, __u8 *proto, void **l4_hdr)
{
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	__u16 h_proto = bpf_ntohs(eth->h_proto);
	// 0x0800 == IPv4 EtherType
	if (h_proto != 0x0800)
		return -1;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return -1;

	__u32 ihl_len = iph->ihl * 4;
	if (ihl_len < sizeof(*iph))
		return -1;
	if ((void *)iph + ihl_len > data_end)
		return -1;

	*src = iph->saddr;            // network byte order
	*proto = iph->protocol; // 6 == TCP
	*l4_hdr = (void *)iph + ihl_len;
	return 0;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	__u32 src_ip = 0;
	__u8 proto = 0;
	void *l4 = NULL;
	if (parse_ipv4(data, data_end, &src_ip, &proto, &l4) < 0)
		return XDP_PASS; // Not IPv4; ignore

	// 1) Drop immediately if in banned list
	ip_flag_t *flag = bpf_map_lookup_elem(&banned_ips, &src_ip);
	if (flag)
		return XDP_DROP;

	// 2) If in recently_banned, allow packets through for now
	ip_flag_t *recent = bpf_map_lookup_elem(&recently_banned_ips, &src_ip);
	if (recent) {
		// If TCP and FIN/RST is observed, move to banned
		if (proto == 6 /* TCP */) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end) {
				if (tcp->fin || tcp->rst) {
					ip_flag_t one = 1;
					bpf_map_update_elem(&banned_ips, &src_ip, &one, BPF_ANY);
					bpf_map_delete_elem(&recently_banned_ips, &src_ip);
				}
			}
		}
		return XDP_PASS;
	}

	// 3) Otherwise allow
	return XDP_PASS;
}

// Optional: helper program to promote keys from recently_banned to banned
// could be implemented via a userspace sweeper or a BPF timer. Not included here.

