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

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_SHOT	2

#define CT_SEQ_WINSIZE 5000

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



enum pkt_action {
	PKT_ACT_PASS,
	PKT_ACT_DROP,
	PKT_ACT_CONTINUE /* Continue in internal program flow */
};


#define CT_FLAG_TLS_HANDSHAKE	(1 << 0)
#define CT_FLAG_TLS_VMAJOR	(1 << 1)
#define CT_FLAG_TLS_CHLO	(1 << 2)
#define CT_FLAG_OVERWRITTEN	(1 << 3)

struct ct_value {
	u32 seq;
	// Used for early exit if the connection is approved/dropped
	enum pkt_action fast_action;
	// Additional information encoded in bitmask CT_FLAG_
	u32 flags;
	u8 buf[CT_SEQ_WINSIZE];
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

struct packet_data {
	struct lnetwork_data lnd;
	struct ltransport_data ltd;
	struct pkt pkt;
};

#define panic while(1) { }
#define unreachable panic


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



	// void *data = (void *)pkt.xdp->data;		\
	// void *data_end = (void *)pkt.xdp->data_end;	\
	// 						\
	// void *tdata = data + offset;			\
	// if (tdata + sizeof(dtype) > data_end) {		\
	// 	ret = -1;				\
	// } else {					\
	// 	dst = *(dtype *)tdata;			\
	// 	ret = 0;				\
	// }						\
	//


/**
 * Used for more advanced parsing of the pkt buffer.
 * Use this when get_val on CT_PKT leads to verifier issues.
 */
static __inline int pkt_read_u8(struct pkt pkt, u32 offset, u8 *dst) {
	int ret;
	u8 c = 0;

	if (pkt.type == CT_PKT) {
		asm volatile(
			"r2 = %[offset]\n\t"
			"r2 += 1\n\t"
			"if r2 > %[bsz] goto .cte_%=\n\t"
			"r1 = %[buf]\n\t"
			"r1 += %[offset]\n\t"
			"%[ret] = 0\n\t"
			"%[c] = *(u8 *)(r1 + 0)\n\t"
			"goto +1\n\t"
			".cte_%=:\n\t"
			"%[ret] = 1\n\t"
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

#undef bpf_printk
#define bpf_printk(...) ;

#define bpf_tt_printk(fmt, args...) ___bpf_pick_printk(args)(fmt, ##args)

#endif /* TYPES_H */
