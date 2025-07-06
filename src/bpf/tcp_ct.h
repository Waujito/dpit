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


#ifndef TCP_CT_H
#define TCP_CT_H

#include "types.h"
#include "tls.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct ct_entry);
	__type(value, struct ct_value);
} ct_map SEC(".maps");

/**
 * Secure storage for ct_entry preventing any stack overflows
 */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, struct ct_value);
        __uint(max_entries, 1);
} ct_value_storage SEC(".maps");

enum cbl_type {
	CBL_TYPE_CT,
	CBL_TYPE_XDP,
};

struct cbl_cts {
	enum cbl_type type;
	struct xdp_md *ctx;
	struct ct_value *src;
	struct ct_value *dst;
	u32 src_off;
	u32 dst_off;
	u32 len;
	u16 urg;
};

static long copy_ctvs_with_offset_callback(u64 index, void *ctx) {
	struct cbl_cts *cbtx = ctx;	
	if (index >= cbtx->len) {
		return 1;
	}
	int ret;

	if (cbtx->urg != 0) {
		if (index + 1 == cbtx->urg) {
			bpf_tt_printk("URGENT detected");
			return 0;
		} else if (index >= cbtx->urg && index > 0) {
			index--;
		}
	}

	u8 c;

	if (cbtx->type == CBL_TYPE_CT) {
		asm volatile(
			"r5 = %[src_off]\n\t"
			"r5 += %[idx]\n\t"
			"if r5 >= %[ct_ws] goto .cp_errex_%=\n\t"
			"r2 = %[sbuf]\n\t"
			"r2 += r5\n\t"
			"%[c] = *(u8 *)(r2 + 0)\n\t"
			"%[ret] = 0\n\t"
			"goto +1\n\t"
			".cp_errex_%=:\n\t"
			"%[ret] = -1\n\t"
			:	[ret]"=r"(ret),
				[c]"=r"(c)
			:	[ct_ws]"i"(CT_SEQ_WINSIZE), 
				[dst_off]"r"(cbtx->dst_off),
				[src_off]"r"(cbtx->src_off),
				[sbuf]"r"(cbtx->src->buf),
				[idx]"r"((u32)index)
			: "r2", "r5"
		);

		if (ret == 1) {
			bpf_printk("Error in ctcpy");
			return 1;
		}
	} else if (cbtx->type == CBL_TYPE_XDP) {
		asm volatile(
			"if %[idx] > 0x1fff goto .cp_errex_%=\n\t"
			"if %[doff] > 0x1fff goto .cp_errex_%=\n\t"
			"r5 = %[dstart]\n\t"
			"r5 += %[idx]\n\t"
			"r5 += %[doff]\n\t"
			"r2 = r5\n\t"
			"r2 += 1\n\t"
			"if r2 > %[dend] goto .cp_errex_%=\n\t"
			"%[c] = *(u8 *)(r5 + 0)\n\t"
			"%[ret] = 0\n\t"
			"goto +1\n\t"
			".cp_errex_%=:\n\t"
			"%[ret] = -1\n\t"
			:	[ret]"=r"(ret),
				[c]"=r"(c)
			:	[ct_ws]"i"(CT_SEQ_WINSIZE), 
				[dstart]"r"(cbtx->ctx->data),
				[dend]"r"(cbtx->ctx->data_end),
				[idx]"r"((u32)index),
				[doff]"r"(cbtx->src_off)
			: "r2", "r5"
		);

		if (ret == 1) {
			bpf_printk("Error in xdcpy");
			return 1;
		}
	} else {
		unreachable;
	}

	asm volatile(
		"r6 = %[dst_off]\n\t"
		"r6 += %[idx]\n\t"
		"if r6 >= %[ct_ws] goto .cp_errex_%=\n\t"
		"r2 = %[dbuf]\n\t"
		"r2 += r6\n\t"
		"r5 = *(u8 *)(r2 + 0)\n\t"
		"*(u8 *)(r2 + 0) = %[c]\n\t"
		"if r5 == 0 goto +3\n\t"
		"if r5 == %[c] goto +2\n\t"
		"%[ret] = 2\n\t"
		"goto +1\n\t"
		"%[ret] = 0\n\t"
		"goto +1\n\t"
		".cp_errex_%=:\n\t"
		"%[ret] = 1\n\t"
		:	[ret]"=r"(ret)
		:	[ct_ws]"i"(CT_SEQ_WINSIZE), 
			[c]"r"(c),
			[dst_off]"r"(cbtx->dst_off),
			[dbuf]"r"(cbtx->dst->buf),
			[idx]"r"((u32)index)
		: "r2", "r5", "r6"
	);

	
	if (ret == 2) {
		cbtx->dst->flags |= CT_FLAG_OVERWRITTEN;
		ret = 0;
	}

	return ret;
}

static __inline int copy_ctvs_with_offset(struct cbl_cts cbts) {
	int ret;

	ret = bpf_loop(CT_SEQ_WINSIZE, copy_ctvs_with_offset_callback, &cbts, 0);

	bpf_printk("ret %d", ret);

	return -(ret >= 0);
}

/**
 *
 * Builds a ct entry universal for any conntract mechanism.
 * Note, that seq_hash is initialized with raw TCP SEQ,
 * you will need to divide it by window later.
 *
 */
static __inline struct ct_entry build_ct_entry(struct packet_data *pktd) {
	struct ct_entry cte = {0};
	struct ip_entry *ipe = &cte.ipe;
	struct transport_entry *tpe = &cte.tpe; 

	if (pktd->ltd.transport_type != TCP)
		unreachable;

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

	return cte;
}

/**
 * Initializes an empty ct_value. Note, that you will need to set seq manually
 */
static __inline void initialize_ct_value(struct ct_value *ctv) {
	ctv->seq = 0;
	ctv->fast_action = PKT_ACT_CONTINUE;
	ctv->chlo_state = MEM_ERROR;
	ctv->sni_action = SNI_APPROVE;
	for (int i = 0; i < CT_SEQ_WINSIZE; i++) {
		// Clang replaces this with memset by default
		asm volatile(
			"r1 = %[buf]\n\t"
			"r1 += %[idx]\n\t"
			"*(u8 *)(r1 + 0) = 0\n\t"
			:: [buf]"r"(ctv->buf),
				[idx]"r"(i)
			: "r1"
		);
	}
}

static __inline int tcp_ctv_update(struct packet_data *pktd, struct ct_value *ctv) {
	int ret;

	if (pktd->ltd.transport_type != TCP)
		return -1;
	u32 seq = bpf_ntohl(pktd->ltd.tcph.seq);

	if (ctv->seq >= seq) {
		u32 otdiff = ctv->seq - seq;
		otdiff += 1;
		bpf_tt_printk("otdiff %d", otdiff);
		if (otdiff > CT_SEQ_WINSIZE) {
			return -1;
		}

		pktd->ltd.payload_offset += otdiff;
		seq += otdiff;
	}

	u32 seq_diff = seq - ctv->seq;
	u16 seq_offset = seq_diff - 1;
	if (seq_offset >= CT_SEQ_WINSIZE) {
		return -1;
	}
	exchange_tls_flags(pktd, ctv);

	struct cbl_cts cbts = {	
		.dst = ctv,
		.dst_off = seq_offset,
	};

	if (pktd->ltd.tcph.urg) {
		cbts.urg = bpf_ntohs(pktd->ltd.tcph.urg_ptr);
	}

	if (pktd->pkt.type == SKB_PKT) {
		struct ct_value *ctvb;

		if (pktd->pkt.skb->len < pktd->ltd.payload_offset) {
			ret = -1;
			goto step_out;
		}
		u32 copy_len = pktd->pkt.skb->len - pktd->ltd.payload_offset;
		u32 lbuf_len = CT_SEQ_WINSIZE - seq_offset;
		if (copy_len > lbuf_len) {
			copy_len = lbuf_len;
		}

		if (copy_len == 0) {
			ret = -1;
			goto step_out;
		}

		ctvb = bpf_map_lookup_elem(&ct_value_storage, &PCP_KEY);
		if (ctvb == NULL) {
			// should be unreachable
			bpf_printk("FATAL: Cannot get value storage");

			ret = -1;
			goto step_out;
		}
		ret = bpf_skb_load_bytes(
			pktd->pkt.skb, pktd->ltd.payload_offset, ctvb->buf, copy_len);
		if (ret) {
			bpf_printk("FATAL: ctvb copy error %d", ret);
		} else {
			bpf_printk("Copied %d", copy_len);
		}
		
		cbts.type = CBL_TYPE_CT;
		cbts.src = ctvb;
		cbts.len = copy_len;
		cbts.src_off = 0;

		copy_ctvs_with_offset(cbts);
	} else {
		u64 dstart = pktd->pkt.xdp->data;
		u64 dend = pktd->pkt.xdp->data_end;
		u32 doff = pktd->ltd.payload_offset;
		if (doff > 0x0fff) {
			ret = -1;
			goto step_out;
		}

		dstart += doff;
		if (dstart > dend) {
			ret = -1;
			goto step_out;
		}

		u32 copy_len = dend - dstart;
		u32 lbuf_len = CT_SEQ_WINSIZE - seq_offset;
		if (copy_len > lbuf_len) {
			copy_len = lbuf_len;
		}

		cbts.type = CBL_TYPE_XDP;
		cbts.ctx = pktd->pkt.xdp;
		cbts.src_off = pktd->ltd.payload_offset;
		cbts.len = copy_len;

		copy_ctvs_with_offset(cbts);
	}

step_out:
	if (cbts.urg) {
		ctv->seq += 1;
	}

	return ret;
}

static __inline enum pkt_action tcp_process_conntrack(struct packet_data *pktd)
{	
	int ret;
	enum pkt_action act;

	struct ct_entry cte = build_ct_entry(pktd);

	if (pktd->ltd.transport_type != TCP)
		unreachable;

	u32 seq = cte.tpe.seq_hash;
	u32 seqp = seq / CT_SEQ_WINSIZE;
	cte.tpe.seq_hash = seqp;
	
	if (pktd->ltd.tcph.syn && !pktd->ltd.tcph.ack) {
		// Connection initiation
		struct ct_value *ctv;
		ctv = bpf_map_lookup_elem(&ct_value_storage, &PCP_KEY);
		if (ctv == NULL) {
			// should be unreachable
			bpf_printk("FATAL: Cannot get value storage");
			return PKT_ACT_CONTINUE;
		}
	
		initialize_ct_value(ctv);
		ctv->seq = seq;

		bpf_printk("TCP Client SYN", seq);
		ret = bpf_map_update_elem(&ct_map, &cte, ctv, BPF_ANY);

		if (ret) {
			bpf_printk("Failed to extend map: %d", ret);
		}
	} else if (pktd->ltd.tcph.syn) {
		bpf_printk("TCP Server SYN ACK", seq);
	} else {
		// Try to find an existing connection
		struct ct_value *ctv = bpf_map_lookup_elem(&ct_map, &cte);	
		if (ctv == NULL) {
			cte.tpe.seq_hash = seqp - 1;
			ctv = bpf_map_lookup_elem(&ct_map, &cte);	
		}

		if (ctv == NULL) {
			return PKT_ACT_CONTINUE;
		}	

		if (ctv->fast_action != PKT_ACT_CONTINUE) {
			bpf_printk("Fast action %d", ctv->fast_action);
			return ctv->fast_action;
		}

		//ctv update
		tcp_ctv_update(pktd, ctv);

		struct pkt pkt = {
			.type = CT_PKT,
			.ctv = ctv
		};
		act = process_tls(pkt, pktd, 0);
		if (act == PKT_ACT_DROP) {
			ctv->fast_action = act;
		}

		return act;

		bpf_printk("seq difference %u", seq_diff);
	}


	return PKT_ACT_CONTINUE;
}

#endif /* TCP_CT_H */
