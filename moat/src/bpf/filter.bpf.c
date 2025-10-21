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

struct lpm_key_v6 {
    __u32 prefixlen;
    __u8 addr[16];
};

// IPv4 maps: permanently banned and recently banned
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

// IPv6 maps: permanently banned and recently banned
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key_v6);
	__type(value, ip_flag_t);
} banned_ips_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key_v6);
	__type(value, ip_flag_t);
} recently_banned_ips_v6 SEC(".maps");

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
    // This filter is designed to only block incoming traffic
    // It should be attached only to ingress hooks, not egress
    // The filtering logic below blocks packets based on source IP addresses

    void *data_end = (void *)(long)ctx->data_end;
    void *cursor = (void *)(long)ctx->data;

    struct ethhdr *eth = parse_and_advance(&cursor, data_end, sizeof(*eth));
    if (!eth)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = parse_and_advance(&cursor, data_end, sizeof(*iph));
        if (!iph)
            return XDP_PASS;

        struct lpm_key key = {
            .prefixlen = 32,
            .addr = iph->saddr,
        };

        if (bpf_map_lookup_elem(&banned_ips, &key)) {
            bpf_printk("XDP: BLOCKED incoming permanently banned IPv4 %pI4", &iph->saddr);
            return XDP_DROP;
        }

        if (bpf_map_lookup_elem(&recently_banned_ips, &key)) {
            // Block UDP and ICMP from recently banned IPs, but allow DNS
            if (iph->protocol == IPPROTO_UDP) {
                struct udphdr *udph = parse_and_advance(&cursor, data_end, sizeof(*udph));
                if (udph && udph->dest == bpf_htons(53)) {
                    return XDP_PASS; // Allow DNS responses
                }
                // Block other UDP traffic
                ip_flag_t one = 1;
                bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
                bpf_map_delete_elem(&recently_banned_ips, &key);
                bpf_printk("XDP: BLOCKED incoming UDP from recently banned IPv4 %pI4, promoted to permanent ban", &iph->saddr);
                return XDP_DROP;
            }
            if (iph->protocol == IPPROTO_ICMP) {
                ip_flag_t one = 1;
                bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
                bpf_map_delete_elem(&recently_banned_ips, &key);
                bpf_printk("XDP: BLOCKED incoming ICMP from recently banned IPv4 %pI4, promoted to permanent ban", &iph->saddr);
                return XDP_DROP;
            }
            // For TCP, only promote to banned on FIN/RST
            if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = parse_and_advance(&cursor, data_end, sizeof(*tcph));
                if (tcph) {
                    if (tcph->fin || tcph->rst) {
                        ip_flag_t one = 1;
                        bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
                        bpf_map_delete_elem(&recently_banned_ips, &key);
                        bpf_printk("XDP: TCP FIN/RST from incoming recently banned IPv4 %pI4, promoted to permanent ban", &iph->saddr);
                    }
                }
            }
            return XDP_PASS;
        }

        return XDP_PASS;
    }
    else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = parse_and_advance(&cursor, data_end, sizeof(*ip6h));
        if (!ip6h)
            return XDP_PASS;

        // Always allow DNS traffic (UDP port 53) to pass through
        if (ip6h->nexthdr == IPPROTO_UDP) {
            struct udphdr *udph = parse_and_advance(&cursor, data_end, sizeof(*udph));
            if (udph && (udph->dest == bpf_htons(53) || udph->source == bpf_htons(53))) {
                return XDP_PASS; // Always allow DNS traffic
            }
        }

        // Skip blocking for IPv6 localhost (::1)
        if (__builtin_memcmp(&ip6h->saddr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16) == 0) {
            return XDP_PASS;
        }

        // Check banned/recently banned maps by source IPv6
        struct lpm_key_v6 key6 = {
            .prefixlen = 128,
        };
        __builtin_memcpy(key6.addr, &ip6h->saddr, 16);

        if (bpf_map_lookup_elem(&banned_ips_v6, &key6)) {
            bpf_printk("XDP: BLOCKED incoming permanently banned IPv6");
            return XDP_DROP;
        }

        if (bpf_map_lookup_elem(&recently_banned_ips_v6, &key6)) {
            // Block UDP and ICMP from recently banned IPv6 IPs, but allow DNS
            if (ip6h->nexthdr == IPPROTO_UDP) {
                struct udphdr *udph = parse_and_advance(&cursor, data_end, sizeof(*udph));
                if (udph && udph->dest == bpf_htons(53)) {
                    return XDP_PASS; // Allow DNS responses
                }
                // Block other UDP traffic
                ip_flag_t one = 1;
                bpf_map_update_elem(&banned_ips_v6, &key6, &one, BPF_ANY);
                bpf_map_delete_elem(&recently_banned_ips_v6, &key6);
                bpf_printk("XDP: BLOCKED incoming UDP from recently banned IPv6, promoted to permanent ban");
                return XDP_DROP;
            }
            if (ip6h->nexthdr == 58) { // 58 = IPPROTO_ICMPV6
                ip_flag_t one = 1;
                bpf_map_update_elem(&banned_ips_v6, &key6, &one, BPF_ANY);
                bpf_map_delete_elem(&recently_banned_ips_v6, &key6);
                bpf_printk("XDP: BLOCKED incoming ICMPv6 from recently banned IPv6, promoted to permanent ban");
                return XDP_DROP;
            }
            // For TCP, only promote to banned on FIN/RST
            if (ip6h->nexthdr == IPPROTO_TCP) {
                struct tcphdr *tcph = parse_and_advance(&cursor, data_end, sizeof(*tcph));
                if (tcph) {
                    if (tcph->fin || tcph->rst) {
                        ip_flag_t one = 1;
                        bpf_map_update_elem(&banned_ips_v6, &key6, &one, BPF_ANY);
                        bpf_map_delete_elem(&recently_banned_ips_v6, &key6);
                        bpf_printk("XDP: TCP FIN/RST from incoming recently banned IPv6, promoted to permanent ban");
                    }
                }
            }
            return XDP_PASS; // Allow if recently banned
        }

        return XDP_PASS;
    }

    return XDP_PASS;
    // return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
