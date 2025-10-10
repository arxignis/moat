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


static inline bool is_frag_v4(const struct iphdr *iph)
{
	return (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0;
}

static inline bool is_frag_v6(const struct ipv6hdr *ip6h)
{
	return ip6h->nexthdr == NEXTHDR_FRAGMENT;
}


struct lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

// Two maps: permanently banned and recently banned
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);           // IPv4 address in network byte order
	__type(value, ip_flag_t);     // presence flag (1)
} banned_ips SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, ip_flag_t);
} recently_banned_ips SEC(".maps");

// Remove dynptr helpers, not used in XDP manual parsing
// extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
//                   struct bpf_dynptr *ptr__uninit) __ksym;
// extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, uint32_t offset,
//                   void *buffer, uint32_t buffer__sz) __ksym;

volatile int shootdowns = 0;

/*
 * Helper for bounds checking and advancing a cursor.
 *
 * @cursor: pointer to current parsing position
 * @end:    pointer to end of packet data
 * @len:    length of the struct to read
 *
 * Returns a pointer to the struct if it's within bounds,
 * and advances the cursor. Returns NULL otherwise.
 */
static void *parse_and_advance(void **cursor, void *end, __u32 len)
{
    void *current = *cursor;
    if (current + len > end)
        return NULL;
    *cursor = current + len;
    return current;
}

SEC("xdp")
int firewall(struct xdp_md *ctx)
{

    bpf_printk("XDP: got packet from IP: ");
    
    // return XDP_PASS;
    return XDP_DROP;
    void *data_end = (void *)(long)ctx->data_end;
    void *cursor = (void *)(long)ctx->data;

    // 1. Parse Ethernet header
    struct ethhdr *eth = parse_and_advance(&cursor, data_end, sizeof(*eth));
    if (!eth)
        return XDP_PASS; // Not enough data for Ethernet header

    __u16 h_proto = eth->h_proto;

    // 2. Handle IPv4 packets
    if (h_proto == bpf_htons(ETH_P_IP)) {
        // Parse IP header
        struct iphdr *iph = parse_and_advance(&cursor, data_end, sizeof(*iph));
        bpf_printk("XDP: got packet from IP: %pI4", &iph->saddr);
        if (!iph)
            return XDP_PASS; // Not enough data for IP header

        

        // Check for fragments (same logic as before)
        if (is_frag_v4(iph)) {
            shootdowns++;
            return XDP_DROP;
        }

        // Check banned/recently banned maps by source IP
        struct lpm_key key = {
            .prefixlen = 32,
            .addr = iph->saddr,
        };

        if (bpf_map_lookup_elem(&banned_ips, &key))
            return XDP_DROP;

        if (bpf_map_lookup_elem(&recently_banned_ips, &key)) {
            // If TCP FIN/RST, promote to banned list
            if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = parse_and_advance(&cursor, data_end, sizeof(*tcph));
                if (tcph) {
                    if (tcph->fin || tcph->rst) {
                        ip_flag_t one = 1;
                        bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
                        bpf_map_delete_elem(&recently_banned_ips, &key);
                    }
                }
            }
            return XDP_PASS; // Allow if recently banned
        }

        return XDP_PASS; // Default action for IPv4 is to pass
    }
    // 3. Handle IPv6 packets (fragment check only)
    else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = parse_and_advance(&cursor, data_end, sizeof(*ip6h));
        if (!ip6h)
            return XDP_PASS;

        if (is_frag_v6(ip6h)) {
            shootdowns++;
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";