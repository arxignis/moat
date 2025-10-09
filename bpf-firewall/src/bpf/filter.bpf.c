#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "filter.h"

#define NF_DROP         0
#define NF_ACCEPT       1
#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
#define IP_MF           0x2000
#define IP_OFFSET       0x1FFF
#define NEXTHDR_FRAGMENT    44


struct lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

// Two maps: permanently banned and recently banned
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
	__type(key, struct lpm_key);           // IPv4 address in network byte order
	__type(value, ip_flag_t);     // presence flag (1)
} banned_ips SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
	__type(key, struct lpm_key);
	__type(value, ip_flag_t);
} recently_banned_ips SEC(".maps");

extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
                  struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, uint32_t offset,
                  void *buffer, uint32_t buffer__sz) __ksym;

volatile int shootdowns = 0;

static bool is_frag_v4(struct iphdr *iph)
{
    int offset;
    int flags;

    offset = bpf_ntohs(iph->frag_off);
    flags = offset & ~IP_OFFSET;
    offset &= IP_OFFSET;
    offset <<= 3;

    return (flags & IP_MF) || offset;
}

static bool is_frag_v6(struct ipv6hdr *ip6h)
{
    /* Simplifying assumption that there are no extension headers
     * between fixed header and fragmentation header. This assumption
     * is only valid in this test case. It saves us the hassle of
     * searching all potential extension headers.
     */
    return ip6h->nexthdr == NEXTHDR_FRAGMENT;
}

static int handle_v4(struct __sk_buff *skb)
{
    struct bpf_dynptr ptr;
    u8 iph_buf[20] = {};
    struct iphdr *iph;

    if (bpf_dynptr_from_skb(skb, 0, &ptr))
        return NF_DROP;

    iph = bpf_dynptr_slice(&ptr, 0, iph_buf, sizeof(iph_buf));
    if (!iph)
        return NF_DROP;

    /* Shootdown any frags first (preserve original behavior/metric) */
    if (is_frag_v4(iph)) {
        shootdowns++;
        return NF_DROP;
    }

    // Check banned/recently banned maps by source IP (exact /32 match)
    struct lpm_key key = {
        .prefixlen = 32,
        .addr = iph->saddr,
    };

    ip_flag_t *ban = bpf_map_lookup_elem(&banned_ips, &key);
    if (ban)
        return NF_DROP;

    ip_flag_t *recent = bpf_map_lookup_elem(&recently_banned_ips, &key);
    if (recent) {
        // Allow packets to pass while in recently-banned.
        // If this is TCP FIN/RST, promote to banned and remove from recently.
        if (iph->protocol == 6 /* TCP */) {
            __u32 ihl_len = iph->ihl * 4;
            u8 tcph_buf[20] = {};
            struct tcphdr *tcph = bpf_dynptr_slice(&ptr, ihl_len, tcph_buf, sizeof(tcph_buf));
            if (tcph) {
                if (tcph->fin || tcph->rst) {
                    ip_flag_t one = 1;
                    bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
                    bpf_map_delete_elem(&recently_banned_ips, &key);
                }
            }
        }
        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

static int handle_v6(struct __sk_buff *skb)
{
    struct bpf_dynptr ptr;
    struct ipv6hdr *ip6h;
    u8 ip6h_buf[40] = {};

    if (bpf_dynptr_from_skb(skb, 0, &ptr))
        return NF_DROP;

    ip6h = bpf_dynptr_slice(&ptr, 0, ip6h_buf, sizeof(ip6h_buf));
    if (!ip6h)
        return NF_DROP;

    /* Shootdown any frags */
    if (is_frag_v6(ip6h)) {
        shootdowns++;
        return NF_DROP;
    }

    return NF_ACCEPT;
}

SEC("netfilter")
int defrag(struct bpf_nf_ctx *ctx)
{
    struct __sk_buff *skb = (struct __sk_buff *)ctx->skb;

    switch (bpf_ntohs(ctx->skb->protocol)) {
    case ETH_P_IP:
        return handle_v4(skb);
    case ETH_P_IPV6:
        return handle_v6(skb);
    default:
        return NF_ACCEPT;
    }
}

char _license[] SEC("license") = "GPL";