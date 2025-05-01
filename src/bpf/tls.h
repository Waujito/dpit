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


#ifndef TLS_H
#define TLS_H

#include "types.h"

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
	SNI_FOUND,
	SNI_NOT_FOUND,
	TLS_NOT_MAPPED,
	MEM_ERROR,
};

struct tls_rec_headers {
	u8 tls_content_type;
	u8 tls_vmajor;
	u8 tls_vminor;
	u16 record_length;
} __attribute__((packed));
struct tls_rec_header {
	u8 tls_content_type;
	u8 tls_vmajor;
	u8 tls_vminor;
	u16 record_length;
};

struct sni_tls_anres {
	enum chlo_tls_atype type;
	union {
		struct {
			u32 sni_offset;
			u32 sni_length;
			// Record header in start of SNI Name
			struct tls_rec_header rhdr;
		};
	};
};

#define SNI_BUF_LEN 128
/**
 * May also be used for LPM TRIE
 */
struct sni_buf {
	u32	prefixlen;
	u8	data[SNI_BUF_LEN];
};

enum sni_action {
	SNI_APPROVE,
	SNI_BLOCK,
	SNI_LOG
};

/**
 * Memory storage allocated for sni buffer
 */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, struct sni_buf);
        __uint(max_entries, 1);
} sni_buf_map SEC(".maps");

#define TLS_CONTENT_TYPE_POS	0
#define TLS_VMAJOR_POS		1
#define TLS_HMESSAGE_TYPE_POS	5	

static __inline int exchange_tls_flags(struct packet_data *pktd, struct ct_value *ctv) {
	int ret;
	struct pkt pkt = pktd->pkt;
	if (pktd->ltd.transport_type != TCP) {
		unreachable;
	}

	u32 seq = bpf_ntohl(pktd->ltd.tcph.seq);
	u32 seq_diff = seq - ctv->seq;
	u16 seq_offset = seq_diff - 1;
	int so = seq_offset;
	
	int content_type_off = TLS_CONTENT_TYPE_POS - so;
	int vmajor_off = TLS_VMAJOR_POS - so;
	int message_type_off = TLS_HMESSAGE_TYPE_POS - so;
	if (content_type_off >= 0) {
		u32 offset = pktd->ltd.payload_offset + content_type_off;
		read_prc_tls(u8, tls_content_type) {
		} else {
			if (tls_content_type == TLS_CONTENT_TYPE_HANDSHAKE) {
				ctv->flags |= CT_FLAG_TLS_HANDSHAKE;
			}
		}
	}
	if (vmajor_off >= 0) {
		u32 offset = pktd->ltd.payload_offset + vmajor_off;
		read_prc_tls(u8, tls_vmajor) {
		} else {
			if (tls_vmajor == 0x03) {
				ctv->flags |= CT_FLAG_TLS_VMAJOR;
			}
		}
	}
	if (message_type_off >= 0) {
		u32 offset = pktd->ltd.payload_offset + message_type_off;
		read_prc_tls(u8, message_type) {
		} else {
			if (message_type == TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
				ctv->flags |= CT_FLAG_TLS_CHLO;
			}
		}
	}

	return 0;
}

/**
 * It seems like trie for IP mapping also works great with SNI domains mapping.
 * One notice is that it should be reversed for the most significant part
 * of the domain to go first. But when reversed it works pretty cool and 
 * supports not only mapping of full domain but also mapping from bottom 
 * of it (like qwerty.google.com will be mapped to .google.com and gle.com)
 *
 * If you want to escape to map google.com to gle.com use point-terminator
 * Pass .gle.com to this map and it will map only *.gle.com, gle.com including
 */
struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct sni_buf);
        __type(value, enum sni_action);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 255);
} sni_lpm_map SEC(".maps");


static __inline int read_tls_record_header(struct pkt pkt, u32 *offset, struct tls_rec_header *hdr) {
	int ret = 0;
	u32 toffset = *offset;
	struct tls_rec_headers shdr;
	u8 *rbuf = (u8 *)&shdr;

	for (int i = 0; i < sizeof(struct tls_rec_headers); i++) {
		ret = pkt_read_u8(pkt, toffset, rbuf + i);
		if (ret) {
			return ret;
		}
		toffset += 1;
	}

	hdr->tls_content_type = shdr.tls_content_type;
	hdr->tls_vmajor = shdr.tls_vmajor;
	hdr->tls_vminor = shdr.tls_vminor;
	hdr->record_length = bpf_ntohs(shdr.record_length);
	// u32 uwu = hdr->record_length;
	// bpf_tt_printk("Read rec length %d", 23);
	*offset = toffset;

	if (hdr->tls_content_type != TLS_CONTENT_TYPE_HANDSHAKE) {
		return -1;
	}
	
	if (hdr->tls_vmajor != 0x03) {
		return -1;
	}

	return 0;
}

struct rlch_cb_ctx {
	struct pkt pkt;
	struct tls_rec_header *rhdr;
	u32 *offset;
	int ret;
};

static long read_tls_rch_callback(u64 index, void *ctx) {
	struct rlch_cb_ctx *rctx = ctx;
	struct pkt pkt = rctx->pkt;
	int ret = read_tls_record_header(pkt, rctx->offset, rctx->rhdr);
	if (ret) {
		rctx->ret = -1;
		return 1;
	}

	if (rctx->rhdr->record_length == 0) {
		rctx->ret = -1;
		return 0;
	}

	rctx->ret = 0;
	return 1;
}

static __inline int read_tls_rch_loop(struct pkt pkt, u32 *offset, struct tls_rec_header *hdr) {
	struct rlch_cb_ctx ctx = {
		.offset = offset,
		.pkt = pkt,
		.rhdr = hdr
	};


	long ret = bpf_loop(CT_SEQ_WINSIZE, read_tls_rch_callback, &ctx, 0);
	if (ret < 0) {
		return ret;
	}

	return ctx.ret;
}

static __inline int tls_rch_read_u8(
	struct pkt pkt, 
	u32 *offset, 
	struct tls_rec_header *rhdr, 
	u8 *dst
) { 

	int ret;
	if (rhdr->record_length == 0) {
		ret = read_tls_rch_loop(pkt, offset, rhdr);
		if (ret) {
			return ret;
		}
	}

	ret = pkt_read_u8(pkt, *offset, dst);
	if (ret) {
		return ret;
	}
	(*offset)++;
	rhdr->record_length -= 1;

	return 0;
}

static __inline int tls_rch_read_u16(
	struct pkt pkt,
	u32 *offset,
	struct tls_rec_header *rhdr,
	u16 *dst
) {
	int ret;

	u16 sst;
	u8 d8s[2];
	for (int i = 0; i < 2; i++) {
		ret = tls_rch_read_u8(pkt, offset, rhdr, d8s + i);
		if (ret) {
			return ret;
		}
	}

	sst = d8s[0];
	sst <<= 8;
	sst += d8s[1];
	sst = bpf_htons(sst);
	*dst = sst;

	return 0;
}

static __inline int tls_rch_jmjoff_iter(struct pkt pkt, struct tls_rec_header *rhdr, u32 *jumped, u32 joff, u32 *offset) {
	int ret;	
	if (rhdr->record_length == 0) {
		ret = read_tls_rch_loop(pkt, offset, rhdr);
		if (ret) {
			return ret;
		}
	}

	u32 jump_pit = joff - *jumped;
	if (rhdr->record_length < jump_pit) {
		jump_pit = rhdr->record_length;
	}
	rhdr->record_length -= jump_pit;
	*offset += jump_pit;
	*jumped += jump_pit;

	return 0;
}


struct tls_rch_jmjoff_iter_ctx {
	struct pkt pkt;
	struct tls_rec_header *rhdr;
	u32 *jumped;
	u32 joff;
	u32 *offset;
	int cret;
};

static long tls_rch_jmjoff_iter_callback(u64 index, void *ctx) {
	struct tls_rch_jmjoff_iter_ctx *rctx = ctx;
	int ret;

	if (*rctx->jumped >= rctx->joff) {
		rctx->cret = 0;
		return 1;
	}
	ret = tls_rch_jmjoff_iter(rctx->pkt, rctx->rhdr, rctx->jumped, rctx->joff, rctx->offset);
	if (ret) {
		rctx->cret = -1;
		return 1;
	}

	rctx->cret = 0;
	if (*rctx->jumped >= rctx->joff) {
		return 1;
	} else {
		return 0;
	}
}
static __inline int tls_rch_jump_joff(
	struct pkt pkt, 
	u32 *offset, 
	struct tls_rec_header *rhdr, 
	u32 joff
) { 

	int ret;
	u32 jumped = 0;
	int i = 0;

	while (jumped < joff && i < 4) {
		ret = tls_rch_jmjoff_iter(pkt, rhdr, &jumped, joff, offset);
		if (ret) {
			return ret;
		}
		i++;
	}

	if (jumped == joff) {
		return 0;
	} else {
		return -1;
	}

	return 0;
}

static __inline struct sni_tls_anres analyze_tls_record(struct pkt pkt, u32 offset) {
	int ret;
	struct sni_tls_anres res = {
		.type = MEM_ERROR
	};
	struct tls_rec_header rhdr;
	rhdr.record_length = 0;

	u8 message_type;
	ret = tls_rch_read_u8(pkt, &offset, &rhdr, &message_type);
	if (ret) {
		return res;
	}

	if (message_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
		res.type = TLS_NOT_MAPPED;
		return res;
	}

	u32 message_length = 0;
	u8 mglb;
	ret = tls_rch_read_u8(pkt, &offset, &rhdr, &mglb);
	if (ret) {
		return res;
	}
	message_length <<= 8;
	message_length += mglb;
	ret = tls_rch_read_u8(pkt, &offset, &rhdr, &mglb);
	if (ret) {
		return res;
	}
	message_length <<= 8;
	message_length += mglb;
	ret = tls_rch_read_u8(pkt, &offset, &rhdr, &mglb);
	if (ret) {
		return res;
	}
	message_length <<= 8;
	message_length += mglb;

	// It is already in the host byte order
	// message_length = bpf_ntohl(message_length);
	
	bpf_printk("Message length: %u of %u", message_length, pkt_len(pkt) - offset);

	int possibly_truncated = offset + message_length > pkt_len(pkt);


	u16 version;
	tls_rch_read_u16(pkt, &offset, &rhdr, &version);
	if (ret) {
		return res;
	}

	// random data offset
	ret = tls_rch_jump_joff(pkt, &offset, &rhdr, 32);
	if (ret) {
		return res;
	}

	u8 session_id_len;
	ret = tls_rch_read_u8(pkt, &offset, &rhdr, &session_id_len);
	if (ret) {
		return res;
	}

	ret = tls_rch_jump_joff(pkt, &offset, &rhdr, session_id_len);
	if (ret) {
		return res;
	}

	u16 cipher_suites_len;
	tls_rch_read_u16(pkt, &offset, &rhdr, &cipher_suites_len);
	if (ret) {
		return res;
	}

	cipher_suites_len = bpf_ntohs(cipher_suites_len);
	ret = tls_rch_jump_joff(pkt, &offset, &rhdr, cipher_suites_len);
	if (ret) {
		return res;
	}

	u8 compression_methods_size;
	ret = tls_rch_read_u8(pkt, &offset, &rhdr, &compression_methods_size);
	if (ret) {
		return res;
	}

	ret = tls_rch_jump_joff(pkt, &offset, &rhdr, compression_methods_size);
	if (ret) {
		return res;
	}

	u16 extensions_size;
	tls_rch_read_u16(pkt, &offset, &rhdr, &extensions_size);
	if (ret) {
		return res;
	}

	extensions_size = bpf_ntohs(extensions_size);
	u32 ext_read = 0;

	int i = 0;
	while (i < 50 && ext_read != extensions_size) {
		u16 extension_type;
		tls_rch_read_u16(pkt, &offset, &rhdr, &extension_type);
		if (ret) {
			return res;
		}

		u16 extension_size;
		tls_rch_read_u16(pkt, &offset, &rhdr, &extension_size);
		if (ret) {
			return res;
		}

		extension_type = bpf_ntohs(extension_type);
		extension_size = bpf_ntohs(extension_size);


		if (extension_type != TLS_EXTENSION_SNI) {
			ret = tls_rch_jump_joff(pkt, &offset, &rhdr, extension_size);
			if (ret) {
				return res;
			}

			i += 1;
			ext_read += 4 + extension_size;
			continue;
		}

		u16 sni_list_len;
		tls_rch_read_u16(pkt, &offset, &rhdr, &sni_list_len);
		if (ret) {
			return res;
		}

		sni_list_len = bpf_ntohs(sni_list_len);

		// TODO: right now it goes up to only one SNI name
		u8 sni_type;
		tls_rch_read_u8(pkt, &offset, &rhdr, &sni_type);
		if (ret) {
			return res;
		}

		u16 sni_length;
		tls_rch_read_u16(pkt, &offset, &rhdr, &sni_length);
		if (ret) {
			return res;
		}
		sni_length = bpf_ntohs(sni_length);
		res.sni_length = sni_length;
		res.type = SNI_FOUND;
		res.sni_length = sni_length;
		res.sni_offset = offset;
		res.rhdr = rhdr;

		return res;
	}

	res.type = SNI_NOT_FOUND;
	return res;
}

static __inline enum pkt_action process_tls(struct pkt pkt, u32 offset) {
	int ret;

	struct sni_tls_anres chres = analyze_tls_record(pkt, offset);
	if (chres.type == SNI_FOUND) {
		bpf_printk("Found SNI in TLS in off %d and len %d", chres.sni_offset, chres.sni_length);
		u32 sni_length = chres.sni_length;
		u32 sni_offset = chres.sni_offset;
		struct sni_buf *sni_tbuf;

		sni_tbuf = bpf_map_lookup_elem(&sni_buf_map, &PCP_KEY);
		if (sni_tbuf == NULL) {
			// should be unreachable
			bpf_printk("FATAL: Cannot get value storage");
			return PKT_ACT_CONTINUE;
		}

		char *sni_buf = (char *)(sni_tbuf->data);

		// one for NULL-terminator and one for point-terminator 
		// (see the description of sni_lpm_map)
		if (sni_length > SNI_BUF_LEN - 2) {
			bpf_printk("SNI is too large");
			return PKT_ACT_CONTINUE;
		}

		u32 soffset = chres.sni_offset;
		struct tls_rec_header rhdr = chres.rhdr;
		int sni_length2 = sni_length;

		for (int i = 0; i < sni_length; i++) {
			ret = tls_rch_read_u8(pkt, &chres.sni_offset, &chres.rhdr, (u8 *)sni_buf + i);

			if (ret) {
				bpf_printk("sni copy error");
				return PKT_ACT_CONTINUE;
			}
		}
		// point-terminator
		sni_buf[sni_length]	= '.';
		// NULL-terminator
		sni_buf[sni_length + 1] = '\0';
		bpf_tt_printk("SNI %s", sni_buf);

		struct rscb_ctx rsctx = {
			.len = sni_length,
			.buflen = SNI_BUF_LEN,
			.buf = (u8 *)sni_buf
		};
		// reverse sni buffer for trie mapping
		// bpf_loop increases insns cap
		ret = bpf_loop(sni_length, reverse_syms_cb, &rsctx, 0);
		if (ret < 0) {
			return PKT_ACT_CONTINUE;
		}


		sni_tbuf->prefixlen = (sni_length + 1) * 8;
		enum sni_action *act = bpf_map_lookup_elem(&sni_lpm_map, sni_tbuf);
		if (act == NULL) {
			bpf_printk("Action not found");
		} else {
			bpf_printk("Action %d", (int)*act);

			if (*act == SNI_BLOCK) {
				bpf_tt_printk("Blocked SNI %s", sni_buf);
				return PKT_ACT_DROP;
			}
		}


	} else if (chres.type == SNI_NOT_FOUND) {
		bpf_printk("SNI extension not found");
	} else if (chres.type == TLS_NOT_MAPPED) {
		bpf_printk("NOT a TLS");
	} else {
		bpf_printk("Mem error");
	}

	if (pkt.type == CT_PKT) {
		u32 flags = pkt.ctv->flags;
		if (
			(flags & CT_FLAG_OVERWRITTEN) == CT_FLAG_OVERWRITTEN) {
			bpf_tt_printk("TCP MESSAGE IS OVERWRITTEN");

			if (	(flags & CT_FLAG_TLS_HANDSHAKE) == 
					CT_FLAG_TLS_HANDSHAKE &&
				(flags & CT_FLAG_TLS_VMAJOR) == 
					CT_FLAG_TLS_VMAJOR &&
				(flags & CT_FLAG_TLS_CHLO) == 
					CT_FLAG_TLS_CHLO) {
				bpf_tt_printk("TLS CHLO MESSAGE IS OVERWRITTEN");
				return PKT_ACT_DROP;
			}
		}
	}

	return PKT_ACT_CONTINUE;
}

#endif /* TLS_H */
