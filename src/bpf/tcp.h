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


#ifndef TCP_H
#define TCP_H

#include "types.h"
const char uwu[] SEC(".rodata") = "uwu %d";

static __inline enum pkt_action process_tls(struct pkt pkt, u32 offset);

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
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

static const u32 CTVS_KEY = 0;

static __inline int copy_ctvs_with_offset(struct ct_value *src, 
					  struct ct_value *dst,
					  u32 src_off,
					  u32 dst_off,
					  u32 len
) {
	int ret;

	asm volatile(
		"if %[src_off] > %[ct_ws] goto .cp_errex_%=\n\t"
		"if %[dst_off] > %[ct_ws] goto .cp_errex_%=\n\t"
		"if %[len] > %[ct_ws] goto .cp_errex_%=\n\t"
		"r5 = %[src_off]\n\t"
		"r5 += %[len]\n\t"
		"if r5 > %[ct_ws] goto .cp_errex_%=\n\t"
		"r5 = %[dst_off]\n\t"
		"r5 += %[len]\n\t"
		"if r5 > %[ct_ws] goto .cp_errex_%=\n\t"
		"r1 = 0\n\t"
		".loop_rst_%=:\n\t"
		"if r1 >= %[len] goto .ct_sucex_%=\n\t"
		"r5 = %[src_off]\n\t"
		"r5 += r1\n\t"
		"r6 = %[dst_off]\n\t"
		"r6 += r1\n\t"
		"if r5 >= %[ct_ws] goto .cp_errex_%=\n\t"
		"if r6 >= %[ct_ws] goto .cp_errex_%=\n\t"
		"r2 = %[sbuf]\n\t"
		"r2 += r5\n\t"
		"r3 = *(u8 *)(r2 + 0)\n\t"
		"r2 = %[dbuf]\n\t"
		"r2 += r6\n\t"
		"*(u8 *)(r2 + 0) = r3\n\t"
		"r1 += 1\n\t"
		"goto .loop_rst_%=\n\t"
		".ct_sucex_%=:\n\t"
		"%[ret] = 0\n\t"
		"goto +1\n\t"
		".cp_errex_%=:\n\t"
		"%[ret] = -1\n\t"
		: [ret]"=r"(ret)
		:	[ct_ws]"i"(CT_SEQ_WINSIZE), 
			[src_off]"r"(src_off),
			[dst_off]"r"(dst_off),
			[len]"r"(len),
			[dbuf]"r"(dst->buf),
			[sbuf]"r"(src->buf)
		: "r1", "r2", "r3", "r5", "r6"
	);

	bpf_printk("ret %d", ret);

	return ret;
}

static __inline enum pkt_action tcp_process_conntrack(struct packet_data *pktd)
{	
	int ret;
	struct ct_entry cte = {0};
	struct ip_entry *ipe = &cte.ipe;
	struct transport_entry *tpe = &cte.tpe; 
	enum pkt_action act;

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
	u32 seqp = seq / CT_SEQ_WINSIZE;

	tpe->sport = bpf_ntohs(pktd->ltd.tcph.source);
	tpe->dport = bpf_ntohs(pktd->ltd.tcph.dest);
	tpe->seq_hash = seqp;



	if (pktd->ltd.tcph.syn) {
		struct ct_value *ctv;
		ctv = bpf_map_lookup_elem(&ct_value_storage, &CTVS_KEY);
		if (ctv == NULL) {
			// should be unreachable
			bpf_printk("FATAL: Cannot get value storage");
			return PKT_ACT_CONTINUE;
		}

		ctv->seq = seq;

		// Connection initiation
		if (!pktd->ltd.tcph.ack) {
			bpf_printk("TCP Client SYN", seq);
			ret = bpf_map_update_elem(&ct_map, &cte, ctv, BPF_ANY);

			if (ret) {
				bpf_printk("Failed to extend map: %d", ret);
			}

		} else {
			bpf_printk("TCP Server SYN ACK", seq);
		}
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

		u32 seq_diff = seq - ctv->seq;
		u16 seq_offset = seq_diff - 1;
		if (seq_offset >= CT_SEQ_WINSIZE) {
			return PKT_ACT_CONTINUE;
		}

		if (pktd->pkt.type == SKB_PKT) {
			struct ct_value *ctvb;

			if (pktd->pkt.skb->len < pktd->ltd.payload_offset) {
				return PKT_ACT_CONTINUE;
			}
			u32 copy_len = pktd->pkt.skb->len - pktd->ltd.payload_offset;
			u32 lbuf_len = CT_SEQ_WINSIZE - seq_offset;
			if (copy_len > lbuf_len) {
				copy_len = lbuf_len;
			}

			if (copy_len == 0) {
				return PKT_ACT_CONTINUE;
			}

			ctvb = bpf_map_lookup_elem(&ct_value_storage, &CTVS_KEY);
			if (ctvb == NULL) {
				// should be unreachable
				bpf_printk("FATAL: Cannot get value storage");
				return PKT_ACT_CONTINUE;
			}
			ret = bpf_skb_load_bytes(pktd->pkt.skb, pktd->ltd.payload_offset, ctvb->buf, copy_len);
			if (ret) {
				bpf_printk("FATAL: ctvb copy error %d", ret);
			} else {
				bpf_printk("Copied %d", copy_len);
			}

			copy_ctvs_with_offset(ctvb, ctv, 0, seq_offset, copy_len);
		} else {
			u8 *dstart = (void *)pktd->pkt.xdp->data;
			u8 *dend = (void *)pktd->pkt.xdp->data_end;
			if (pktd->ltd.payload_offset > 0xffff) {
				return PKT_ACT_CONTINUE;
			}

			dstart += pktd->ltd.payload_offset;
			if (dstart > dend) {
				return PKT_ACT_CONTINUE;
			}

			u32 copy_len = dend - dstart;
			u32 lbuf_len = CT_SEQ_WINSIZE - seq_offset;
			if (copy_len > lbuf_len) {
				copy_len = lbuf_len;
			}

			u16 ofmax = seq_offset + copy_len;
			if (ofmax > CT_SEQ_WINSIZE) {
				ofmax = CT_SEQ_WINSIZE;
			}

			// u16 boff = 0;
			// for (; dstart + boff + sizeof(u8) <= dend && boff <= CT_SEQ_WINSIZE && seq_offset + boff < CT_SEQ_WINSIZE && seq_offset + boff < copy_len; boff++) {
			// 	ctv->buf[seq_offset + boff] = dstart[boff];
			// }
		}

		struct pkt pkt = {
			.type = CT_PKT,
			.ctv = ctv
		};
		act = process_tls(pkt, 0);
		return act;

		bpf_printk("seq difference %u", seq_diff);
	}


	return PKT_ACT_CONTINUE;
}

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_EXTENSION_SNI 0x0000
#define TLS_EXTENSION_CLIENT_HELLO_ENCRYPTED 0xfe0d

#define TLS_MESSAGE_ANALYZE_INVALID	-1
#define TLS_MESSAGE_ANALYZE_FOUND	0
#define TLS_MESSAGE_ANALYZE_GOTO_NEXT	1

/**
 * Helper for get_val in tls. Reads and declares a variable of dtype and name.
 * Increments offset on dtype. Opens branch closure on error
 */
#define read_prc_tls(dtype, name)		\
dtype name;					\
get_val(dtype, pkt, offset, name, ret);		\
offset += sizeof(dtype);			\
if (ret)

	
#define pkt_len(pkt)\
(pkt.type == XDP_PKT ? pkt.xdp->data_end - pkt.xdp->data : (pkt.type == SKB_PKT ? pkt.skb->len : CT_SEQ_WINSIZE))

enum chlo_tls_atype {
	TLS_FOUND,
	TLS_NOT_FOUND,
	TLS_MEM_ERROR
};

struct chlo_tls_anres {
	enum chlo_tls_atype type;
	union {
		struct {
			u32 sni_offset;
			u32 sni_length;
		};
	};
};

static __inline struct chlo_tls_anres analyze_tls_chlo(struct pkt pkt, u64 offset) {
	int ret;
	struct chlo_tls_anres res = {
		.type = TLS_MEM_ERROR
	};

	read_prc_tls(u16, version) {
		return res;
	}

	// random data offset
	offset += 32;

	read_prc_tls(u8, session_id_len) {
		return res;
	}
	offset += session_id_len;

	read_prc_tls(u16, cipher_suites_len) {
		return res;
	}
	cipher_suites_len = bpf_ntohs(cipher_suites_len);
	if (cipher_suites_len > CT_SEQ_WINSIZE) {
		return res;
	}
	offset += cipher_suites_len;

	read_prc_tls(u8, compression_methods_size) {
		return res;
	}
	offset += compression_methods_size;

	read_prc_tls(u16, extensions_size) {
		return res;
	}
	extensions_size = bpf_ntohs(extensions_size);
	u32 ext_read = 0;

	int i = 0;
	while (i < 50 && ext_read != extensions_size) {
		if (offset > CT_SEQ_WINSIZE) {
			return res;
		}
		read_prc_tls(u16, extension_type) {
			return res;
		}
		read_prc_tls(u16, extension_size) {
			return res;
		}	
		extension_type = bpf_ntohs(extension_type);
		extension_size = bpf_ntohs(extension_size);

		if (offset + extension_size > pkt_len(pkt) ||
			extension_size > CT_SEQ_WINSIZE
		) {
			return res;
		}

		if (extension_type != TLS_EXTENSION_SNI) {
			offset = offset + extension_size;
			i += 1;
			ext_read += 4 + extension_size;
			continue;
		}

		read_prc_tls(u16, sni_list_len) {
			return res;
		}
		sni_list_len = bpf_ntohs(sni_list_len);
		// TODO: right now it goes up to only one SNI name
		read_prc_tls(u8, sni_type) {
			return res;
		}
		read_prc_tls(u16, sni_length) {
			return res;
		}
		sni_length = bpf_ntohs(sni_length);
		res.type = TLS_FOUND;
		res.sni_length = sni_length;
		res.sni_offset = offset;

		return res;
	}
	res.type = TLS_NOT_FOUND;
	return res;
}
static __inline enum pkt_action process_tls(struct pkt pkt, u32 offset) {
	int ret;

	read_prc_tls(u8, tls_content_type) {
		return PKT_ACT_CONTINUE;
	}
	
	if (tls_content_type != TLS_CONTENT_TYPE_HANDSHAKE) {
		return PKT_ACT_CONTINUE;
	}

	read_prc_tls(u8, tls_vmajor) {
		return PKT_ACT_CONTINUE;
	}

	if (tls_vmajor != 0x03) {
		return PKT_ACT_CONTINUE;
	}

	read_prc_tls(u8, tls_vminor) {
		return PKT_ACT_CONTINUE;
	}
	read_prc_tls(u16, record_length) {
		return PKT_ACT_CONTINUE;
	}

	read_prc_tls(u8, message_type) {
		return PKT_ACT_CONTINUE;
	}
	if (message_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
		return PKT_ACT_CONTINUE;
	}
	offset -= 1;

	read_prc_tls(u32, message_length) {
		return PKT_ACT_CONTINUE;
	}
	message_length = bpf_ntohl(message_length);
	message_length &= 0x00ffffff;
	
	bpf_printk("Message length: %u of %u", message_length, pkt_len(pkt) - offset);

	int possibly_truncated = offset + message_length > pkt_len(pkt);
	struct chlo_tls_anres chlo_res = analyze_tls_chlo(pkt, offset);

	if (chlo_res.type == TLS_FOUND) {
		bpf_printk("Found SNI in TLS in off %d and len %d", chlo_res.sni_offset, chlo_res.sni_length);
	}

	return PKT_ACT_PASS;
}

static __inline enum pkt_action process_tcp(struct packet_data *pktd)
{
	enum pkt_action act;

	act = tcp_process_conntrack(pktd);
	// u32 offset = pktd->ltd.payload_offset;
	// act = process_tls(pktd->pkt, offset);
	return act;
}

#endif /* TCP_H */
