/* SPDX-License-Identifier: GPL-2.0 */
/* Wicket SOCKMAP - SK_MSG zero-copy proxy
 *
 * Redirects data between paired sockets entirely in the kernel,
 * bypassing userspace for L4 passthrough and websocket traffic.
 *
 * Originally from https://github.com/GEverding/volt
 */

#include "include/common.h"

/* Connection pair for sockmap */
struct sock_key {
    __be32 local_ip;
    __be32 remote_ip;
    __be16 local_port;
    __be16 remote_port;
    __u8   family;      /* AF_INET = 2 */
    __u8   pad[3];
};

/* Sockmap statistics */
struct sockmap_stats {
    __u64 msgs_received;
    __u64 msgs_redirected;
    __u64 msgs_dropped;
    __u64 bytes_forwarded;
    __u64 lookup_failures;
};

/* Maps */

/* Socket hash for connection pairs
 * Key: 5-tuple identifying the connection
 * Value: socket fd (managed by kernel)
 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __type(key, struct sock_key);
    __type(value, __u64);
    __uint(max_entries, 500000);
} sock_hash SEC(".maps");

/* Statistics */
DEFINE_BPF_MAP_PERCPU(stats, __u32, struct sockmap_stats, 1);

/* Helper to get stats */
static __always_inline struct sockmap_stats *get_stats(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&stats, &key);
}

/* Build peer key by swapping local/remote */
static __always_inline void make_peer_key(struct sock_key *key, struct sock_key *peer) {
    peer->local_ip = key->remote_ip;
    peer->remote_ip = key->local_ip;
    peer->local_port = key->remote_port;
    peer->remote_port = key->local_port;
    peer->family = key->family;
}

/*
 * SK_MSG program - runs when data is sent on a socket in the sockmap
 *
 * Redirects data to the paired socket via the sockhash map,
 * enabling zero-copy kernel-level proxying.
 */
SEC("sk_msg")
int sockmap_redir(struct sk_msg_md *msg)
{
    struct sockmap_stats *st = get_stats();

    if (st) {
        st->msgs_received += 1;
        st->bytes_forwarded += msg->size;
    }

    /* Build key for current socket */
    struct sock_key key = {
        .local_ip = msg->local_ip4,
        .remote_ip = msg->remote_ip4,
        .local_port = bpf_htons(msg->local_port),
        .remote_port = msg->remote_port,  /* Already network order */
        .family = 2,  /* AF_INET */
    };

    /* Build peer key (swap src/dst) */
    struct sock_key peer_key = {};
    make_peer_key(&key, &peer_key);

    /* Redirect to peer socket */
    long ret = bpf_msg_redirect_hash(msg, &sock_hash, &peer_key, BPF_F_INGRESS);

    if (ret == SK_PASS) {
        if (st) st->msgs_redirected += 1;
        return SK_PASS;
    }

    /* Lookup failed - peer socket not in map */
    if (st) st->lookup_failures += 1;

    /* Pass through to original destination */
    return SK_PASS;
}

/*
 * SK_SKB stream parser - identifies message boundaries
 * For TLS/TCP, we just pass through (stream-oriented)
 */
SEC("sk_skb/stream_parser")
int sockmap_parser(struct __sk_buff *skb)
{
    /* Return full length - treat as single message */
    return skb->len;
}

/*
 * SK_SKB stream verdict - decides where to send the message
 * Alternative to SK_MSG for older kernels
 */
SEC("sk_skb/stream_verdict")
int sockmap_verdict(struct __sk_buff *skb)
{
    struct sockmap_stats *st = get_stats();

    if (st)
        st->msgs_received += 1;

    /* Build key from skb */
    struct sock_key key = {
        .local_ip = skb->local_ip4,
        .remote_ip = skb->remote_ip4,
        .local_port = bpf_htons(skb->local_port),
        .remote_port = skb->remote_port,
        .family = 2,
    };

    /* Build peer key */
    struct sock_key peer_key = {};
    make_peer_key(&key, &peer_key);

    /* Redirect to peer */
    long ret = bpf_sk_redirect_hash(skb, &sock_hash, &peer_key, BPF_F_INGRESS);

    if (ret == SK_PASS) {
        if (st) st->msgs_redirected += 1;
        return SK_PASS;
    }

    if (st) st->lookup_failures += 1;
    return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
