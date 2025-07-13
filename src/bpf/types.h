/**
 * DPIT
 *
 * Copyright (C) 2025 Vadim Vetrov <vetrovvd@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the 
 * GNU General Public License as published by the Free Software Foundation, 
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program. 
 * If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef TYPES_H
#define TYPES_H

#include "vmlinux.h" // IWYU pragma: export
#include <bpf/bpf_helpers.h> // IWYU pragma: export
#include <bpf/bpf_core_read.h> // IWYU pragma: export
#include <bpf/bpf_endian.h> // IWYU pragma: export

#define __inline inline __attribute__((always_inline))

#undef bpf_printk
#define bpf_printk(...) ;

#define bpf_tt_printk(fmt, args...) ___bpf_pick_printk(args)(fmt, ##args)
#define bpf_e_printk bpf_tt_printk

#define panic while(1) { }
#define unreachable panic

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_SHOT	2

#define CT_SEQ_WINSIZE 5000

const u32 RAWSOCKET_MARK = 1 << 15;

// This key may be used for percpu array representing single buffer.
static const u32 PCP_KEY = 0;

struct ip_entry {
	union {
		struct {
			__be32 ip4saddr;
			__be32 ip4daddr;
		};
		struct {
			struct in6_addr ip6saddr;
			struct in6_addr ip6daddr;
		};
	};
};

struct transport_entry {
	union {
		struct {
			u16 sport;
			u16 dport;
			u32 seq_hash;
		};
	};
};

struct ct_entry {
	struct ip_entry ipe;
	struct transport_entry tpe;
};

enum dpit_action_type {
	DPIT_ACT_APPROVE,
	DPIT_ACT_BLOCK,
	DPIT_ACT_BLOCK_OVERWRITTEN,
	DPIT_ACT_THROTTLE,
	DPIT_ACT_CONTINUE,
};

/**
 * DPIT-regulated action type. typically, per-connection
 */
struct dpit_action {
	enum dpit_action_type type;

	/**
	 * A throttling percent from 0 to 100 (larger is more throttling)
	 */
	int throttling_percent;
};

/**
 * Action per-packet
 */
enum pkt_action {
	PKT_ACT_PASS,
	PKT_ACT_DROP,
	PKT_ACT_CONTINUE /* Continue in internal program flow */
};

enum pkt_type {
	XDP_PKT,
	SKB_PKT,
	CT_PKT
};

struct pkt {
	enum pkt_type type;
	union {
		struct xdp_md *xdp;
		struct __sk_buff *skb;
		struct ct_value *ctv;
	};
};

static __inline enum pkt_action get_pkt_action(struct dpit_action act) {
	switch (act.type) {
		case DPIT_ACT_APPROVE:
			return PKT_ACT_PASS;
		case DPIT_ACT_BLOCK:
		case DPIT_ACT_BLOCK_OVERWRITTEN:
			return PKT_ACT_DROP;
		case DPIT_ACT_THROTTLE: {
			u32 randn = bpf_get_prandom_u32();
			// randn [0; 99]; throttling_percent [0; 100]
			randn %= 100;
			return (randn < act.throttling_percent) ? PKT_ACT_DROP : PKT_ACT_PASS;
		}
		case DPIT_ACT_CONTINUE:
		default:
			return PKT_ACT_CONTINUE;
	}
}
static __inline int get_return_code(enum pkt_action act, enum pkt_type pktt) {
	switch (act) {
		case PKT_ACT_DROP:
			bpf_printk("drop");
			goto drop;

		case PKT_ACT_PASS:
		case PKT_ACT_CONTINUE:
		default:
			goto pass;
	}

pass:
	return (pktt == XDP_PKT) ? XDP_PASS : TC_ACT_UNSPEC;
drop:
	return (pktt == XDP_PKT) ? XDP_DROP : TC_ACT_SHOT;
}

enum chlo_tls_atype {
	SNI_FOUND,
	SNI_NOT_FOUND,
	TLS_NOT_MAPPED,
	MEM_ERROR,
};

#define CT_FLAG_TLS_HANDSHAKE	(1 << 0)
#define CT_FLAG_TLS_VMAJOR	(1 << 1)
#define CT_FLAG_TLS_CHLO	(1 << 2)
#define CT_FLAG_OVERWRITTEN	(1 << 3)
#define CT_FLAG_SENT_TO_USER	(1 << 4)

struct ct_value {
	u32 seq;
	// Used for early exit if the connection is approved/dropped
	struct dpit_action fast_action;
	// Additional information encoded in bitmask CT_FLAG_
	u32 flags;
	enum chlo_tls_atype	chlo_state;
	struct dpit_action	sni_action;
	u8 buf[CT_SEQ_WINSIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct ct_entry);
	__type(value, struct ct_value);
} ct_map SEC(".maps");

// dtype, struct pkt pkt, int offset, dtype *dst
#define get_val(dtype, pkt, offset, dst, ret)		\
if (pkt.type == SKB_PKT) {				\
	ret = bpf_skb_load_bytes(pkt.skb, offset,	\
		&dst, sizeof(dst));			\
} else if (pkt.type == XDP_PKT) {			\
	ret = bpf_xdp_load_bytes(pkt.xdp, offset,	\
		&dst, sizeof(dst));			\
} else if (pkt.type == CT_PKT) {			\
	if (offset + sizeof(dtype) > sizeof(pkt.ctv->buf)) {	\
		ret = -1;					\
	} else {						\
		dst = *(dtype *)(pkt.ctv->buf + offset);	\
		ret = 0;					\
	}							\
} else {							\
	unreachable;						\
}

enum lnetwork_type {
	IPV4,
	IPV6
};
enum ltranposrt_type {
	TCP,
	UDP
};

struct lnetwork_data {
	enum lnetwork_type protocol_type;
	size_t transport_offset;
	u8 transport_protocol;
	union {
		struct iphdr iph;
		struct ipv6hdr ip6h;
	};
};

struct ltransport_data {
	enum ltranposrt_type transport_type;
	size_t payload_offset;

	union {
		struct udphdr udph;
		struct tcphdr tcph;
	};
};

#define ETH_P_IPV6  0x86DD      /* IPv6 over bluebook       */
#define ETH_P_IP    0x0800      /* Internet Protocol packet */

#define IPPROTO_TCP 0x06
#define IPPROTO_UDP 0x11

static __inline int get_network_data(
	struct pkt pkt,
	struct lnetwork_data *lnd
) {
	int ret;
	u16 h_proto;

	{
		struct ethhdr eth;
		get_val(struct ethhdr, pkt, 0, eth, ret);
		if (ret) {
			return -1;
		}
		h_proto = bpf_ntohs(eth.h_proto);
	}

	if (h_proto == ETH_P_IP) {
		lnd->protocol_type = IPV4;
		get_val(struct iphdr, pkt, sizeof(struct ethhdr), lnd->iph, ret);
		if (ret) {
			return -1;
		}
		lnd->transport_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
		lnd->transport_protocol = lnd->iph.protocol;
	} else if (h_proto == ETH_P_IPV6) {
		lnd->protocol_type = IPV6;
		get_val(struct ipv6hdr, pkt, sizeof(struct ethhdr), lnd->ip6h, ret);
		if (ret) {
			return -1;
		}
		lnd->transport_offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
		lnd->transport_protocol = lnd->ip6h.nexthdr;
	} else {
		bpf_printk("Unknown network protocol %04x", h_proto);
		return -1;
	}

	return 0;
}

static __inline int get_transport_data(
	struct pkt pkt,
	const struct lnetwork_data *lnd,
	struct ltransport_data *ltd
) {
	int ret;

	if (lnd->transport_protocol == IPPROTO_TCP) {
		ltd->transport_type = TCP;
		get_val(struct tcphdr, pkt, lnd->transport_offset, ltd->tcph, ret);
		if (ret) {
			return -1;
		}
		int doff = ltd->tcph.doff * 4;
		ltd->payload_offset = lnd->transport_offset + doff;
	} else if (lnd->transport_protocol == IPPROTO_UDP) {
		ltd->transport_type = UDP;
		get_val(struct udphdr, pkt, lnd->transport_offset, ltd->udph, ret);
		if (ret) {
			return -1;
		}
		ltd->payload_offset = lnd->transport_offset + sizeof(struct udphdr);
	} else {
		bpf_printk("Unknown transport protocol %d", lnd->transport_protocol);
		return -1;
	}

	return 0;
}

struct packet_data {
	struct lnetwork_data lnd;
	struct ltransport_data ltd;
	struct pkt pkt;
};

/**
 * Used to transfer state between tail calls
 */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, struct packet_data);
        __uint(max_entries, 1);
} pktd_storage SEC(".maps");

/**
 * May be (and inteneded to) used across tail calls
 */
static __inline int get_pktd(struct pkt pkt, struct packet_data *pktd) {
	struct packet_data *ppktd = bpf_map_lookup_elem(&pktd_storage, &PCP_KEY);
	if (ppktd == NULL) {
		// should be unreachable
		bpf_e_printk("FATAL: Cannot get state packet data");
		return -1;
	}
	*pktd = *ppktd;
	pktd->pkt = pkt;

	return 0;
}

/**
 * Used for more advanced parsing of the pkt buffer.
 * Use this when get_val on CT_PKT leads to verifier issues.
 */
static __inline int pkt_read_u8(struct pkt pkt, u32 offset, u8 *dst) {
	int ret;
	u8 c;

	if (pkt.type == CT_PKT) {
		asm volatile(
			"r2 = %[offset]\n\t"
			"r2 += 1\n\t"
			"if r2 > %[bsz] goto .cte_%=\n\t"
			"r1 = %[buf]\n\t"
			"r1 += %[offset]\n\t"
			"%[ret] = 0\n\t"
			"%[c] = *(u8 *)(r1 + 0)\n\t"
			"goto +2\n\t"
			".cte_%=:\n\t"
			"%[ret] = 1\n\t"
			"%[c] = 0\n\t"
			: [ret]"=r"(ret),
			  [c]"=r"(c)
			: [bsz]"i"(CT_SEQ_WINSIZE),
			  [buf]"r"(pkt.ctv->buf),
			  [offset]"r"(offset)
			: "r1", "r2"
		);
	} else {
		get_val(u8, pkt, offset, c, ret);
	}

	*dst = c;

	return ret;
}

struct rscb_ctx {
	u8 *buf;
	u32 len;
	u64 buflen;
};

/**
 * Reverses the two buffer symbols
 * Usage:
 * ```
 *	struct rscb_ctx rsctx = {
 *		.len = sni_length,
 *		.buflen = SNI_BUF_LEN,
 *		.buf = (u8 *)sni_buf
 *	};
 *	// reverse sni buffer for trie mapping
 *	// bpf_loop increases insns cap
 *	ret = bpf_loop(sni_length, reverse_syms_cb, &rsctx, 0);
 *	if (ret < 0) {
 *		return ret;
 *	}
 * ```
 *
 */
static long reverse_syms_cb(u64 index, void *ctx) {
	struct rscb_ctx *rctx = ctx;
	if (index >= rctx->buflen) {
		return 1;
	}

	if (rctx->len < index + 1) {
		return 1;
	}
	u32 j = rctx->len - index - 1;
	if (j >= rctx->buflen) {
		return 1;
	}
	if (index < j) {
		u8 c = rctx->buf[index];
		rctx->buf[index] = rctx->buf[j];
		rctx->buf[j] = c;
	} else {
		return 1;
	}

	return 0;
}

/**
 *
 * Builds a ct entry universal for any conntract mechanism.
 * Note, that seq_hash is initialized with raw TCP SEQ,
 * you will need to divide it by window later.
 *
 */
static __inline int build_ct_entry(struct packet_data *pktd, struct ct_entry *ctep) {
	struct ct_entry cte = {0};
	struct ip_entry *ipe = &cte.ipe;
	struct transport_entry *tpe = &cte.tpe; 

	if (pktd->ltd.transport_type != TCP)
		return -1;

	if (pktd->lnd.protocol_type == IPV4) {
		ipe->ip4saddr = pktd->lnd.iph.saddr;
		ipe->ip4daddr = pktd->lnd.iph.daddr;
	} else {
		ipe->ip6saddr = pktd->lnd.ip6h.saddr;
		ipe->ip6daddr = pktd->lnd.ip6h.daddr;
	}
	
	u32 seq = bpf_ntohl(pktd->ltd.tcph.seq);

	tpe->sport = bpf_ntohs(pktd->ltd.tcph.source);
	tpe->dport = bpf_ntohs(pktd->ltd.tcph.dest);
	tpe->seq_hash = seq;

	*ctep = cte;

	return 0;
}

/**
 *
 * Builds a ct entry universal for any conntract mechanism.
 * Note, that seq_hash is initialized with raw TCP SEQ,
 * you will need to divide it by window later.
 *
 */
static __inline int build_server_ct_entry(struct packet_data *pktd, struct ct_entry *ctep) {
	struct ct_entry cte = {0};
	struct ip_entry *ipe = &cte.ipe;
	struct transport_entry *tpe = &cte.tpe; 

	if (pktd->ltd.transport_type != TCP)
		return -1;

	if (pktd->lnd.protocol_type == IPV4) {
		ipe->ip4saddr = pktd->lnd.iph.daddr;
		ipe->ip4daddr = pktd->lnd.iph.saddr;
	} else {
		ipe->ip6saddr = pktd->lnd.ip6h.daddr;
		ipe->ip6daddr = pktd->lnd.ip6h.saddr;
	}
	
	u32 seq = bpf_ntohl(pktd->ltd.tcph.ack_seq);

	tpe->sport = bpf_ntohs(pktd->ltd.tcph.dest);
	tpe->dport = bpf_ntohs(pktd->ltd.tcph.source);
	tpe->seq_hash = seq;

	*ctep = cte;

	return 0;
}

#define tail_entry_fun(fn_name)			\
SEC("xdp")					\
int xdp_##fn_name(struct xdp_md *xdp) {		\
	struct pkt pkt = {			\
		.xdp = xdp,			\
		.type = XDP_PKT			\
	};					\
	return fn_name(pkt);			\
}						\
SEC("tc")					\
int tc_##fn_name(struct __sk_buff *skb) {	\
	struct pkt pkt = {			\
		.skb = skb,			\
		.type = SKB_PKT,		\
	};					\
	return fn_name(pkt);			\
}


#define tail_entry_map(fn_name)			\
struct {					\
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);	\
    __uint(max_entries, 1);			\
    __uint(key_size, sizeof(__u32));		\
    __array(values, int (void *));		\
} fn_name##_map SEC(".maps") = {		\
    .values = {					\
        [0] = (void *)&fn_name,			\
    },						\
}

#define tail_entry_call(fn_name)					\
static __inline int call_##fn_name(struct pkt pkt) {			\
	if (pkt.type == XDP_PKT) {					\
		bpf_tail_call_static(pkt.xdp, &xdp_##fn_name##_map, 0);	\
	} else if (pkt.type == SKB_PKT) {				\
		bpf_tail_call_static(pkt.skb, &tc_##fn_name##_map, 0);	\
	} else { return -1; }						\
	return 0;							\
}


#define tail_entries(fn_name)			\
tail_entry_fun(fn_name)				\
tail_entry_map(xdp_##fn_name);			\
tail_entry_map(tc_##fn_name);			\
tail_entry_call(fn_name);

#endif /* TYPES_H */
