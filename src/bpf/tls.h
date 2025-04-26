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

struct sni_tls_anres {
	enum chlo_tls_atype type;
	union {
		struct {
			u32 sni_offset;
			u32 sni_length;
		};
	};
};

static __inline struct sni_tls_anres analyze_tls_chlo(struct pkt pkt, u64 offset) {
	int ret;
	struct sni_tls_anres res = {
		.type = MEM_ERROR
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
		res.type = SNI_FOUND;
		res.sni_length = sni_length;
		res.sni_offset = offset;

		return res;
	}
	res.type = SNI_NOT_FOUND;
	return res;
}

#define SNI_BUF_LEN 128
/**
 * Memory storage allocated for sni buffer
 */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, char[SNI_BUF_LEN]);
        __uint(max_entries, 1);
} sni_buf_map SEC(".maps");

static __inline struct sni_tls_anres analyze_tls_record(struct pkt pkt, u64 offset) {
	int ret;
	struct sni_tls_anres res = {
		.type = MEM_ERROR
	};

	read_prc_tls(u8, tls_content_type) {
		return res;
	}
	
	if (tls_content_type != TLS_CONTENT_TYPE_HANDSHAKE) {
		res.type = TLS_NOT_MAPPED;
		return res;
	}

	read_prc_tls(u8, tls_vmajor) {
		return res;
	}

	if (tls_vmajor != 0x03) {
		return res;
	}

	read_prc_tls(u8, tls_vminor) {
		return res;
	}
	read_prc_tls(u16, record_length) {
		return res;
	}

	read_prc_tls(u8, message_type) {
		return res;
	}
	if (message_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
		res.type = TLS_NOT_MAPPED;
		return res;
	}
	offset -= 1;

	read_prc_tls(u32, message_length) {
		return res;
	}
	message_length = bpf_ntohl(message_length);
	message_length &= 0x00ffffff;
	
	bpf_printk("Message length: %u of %u", message_length, pkt_len(pkt) - offset);

	int possibly_truncated = offset + message_length > pkt_len(pkt);
	res = analyze_tls_chlo(pkt, offset);

	return res;
}

static __inline enum pkt_action process_tls(struct pkt pkt, u32 offset) {
	int ret;

	struct sni_tls_anres chres = analyze_tls_record(pkt, offset);
	if (chres.type == SNI_FOUND) {
		bpf_printk("Found SNI in TLS in off %d and len %d", chres.sni_offset, chres.sni_length);
		u32 sni_length = chres.sni_length;
		u32 sni_offset = chres.sni_offset;
		char *sni_buf;

		sni_buf = bpf_map_lookup_elem(&sni_buf_map, &PCP_KEY);
		if (sni_buf == NULL) {
			// should be unreachable
			bpf_printk("FATAL: Cannot get value storage");
			return PKT_ACT_CONTINUE;
		}
		// one for NULL-terminator
		if (sni_length > SNI_BUF_LEN - 1) {
			bpf_printk("SNI is too large");
			return PKT_ACT_CONTINUE;
		}
		for (int i = 0; i < sni_length; i++) {
			ret = pkt_read_u8(pkt, sni_offset + i, (u8 *)sni_buf + i);

			if (ret) {
				bpf_printk("sni copy error");
				return PKT_ACT_CONTINUE;
			}
		}
		sni_buf[sni_length] = '\0';

		bpf_printk("SNI %s", sni_buf);
	} else if (chres.type == SNI_NOT_FOUND) {
		bpf_printk("SNI extension not found");
	} else if (chres.type == TLS_NOT_MAPPED) {
		bpf_printk("NOT a TLS");
	} else {
		bpf_printk("Mem error");
	}

	return PKT_ACT_CONTINUE;
}

#endif /* TLS_H */
