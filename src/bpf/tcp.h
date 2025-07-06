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
#include "tls.h"
#include "tcp_ct.h"

/**
 * Used to transfer state between tail calls
 */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, struct packet_data);
        __uint(max_entries, 1);
} pktd_storage SEC(".maps");

static __inline int tail_tcppct(struct pkt pkt){
	struct packet_data *ppktd = bpf_map_lookup_elem(&pktd_storage, &PCP_KEY);
	if (ppktd == NULL) {
		// should be unreachable
		bpf_printk("FATAL: Cannot get state packet data");
		return -1;
	}
	struct packet_data pktd = *ppktd;
	pktd.pkt = pkt;

	if (pktd.ltd.transport_type != TCP) {
		return -1;
	}

	enum pkt_action act = tcp_process_conntrack(&pktd);

	return get_return_code(act, pkt.type);
}

tail_entries(tail_tcppct);

static __inline enum pkt_action process_tcp(struct packet_data *pktd, struct pkt pkt)
{
	int ret;
	enum pkt_action act;

	ret = bpf_map_update_elem(&pktd_storage, &PCP_KEY, pktd, BPF_ANY);
	if (ret) {
		// Should be unreachable
		return PKT_ACT_CONTINUE;
	}

	ret = call_tail_tcppct(pkt);

	return PKT_ACT_CONTINUE;
}

#endif /* TCP_H */
