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
#include "tcp_ct.h"

static __inline int tail_tcppct(struct pkt pkt){	
	struct packet_data pktd;

	if (get_pktd(pkt, &pktd)) {
		return -1;
	}

	if (pktd.ltd.transport_type != TCP) {
		return -1;
	}

	struct dpit_action act = tcp_process_conntrack(pkt, &pktd);

	enum pkt_action pact = get_pkt_action(act);

	return get_return_code(pact, pkt.type);
}

tail_entries(tail_tcppct);

static __inline enum pkt_action process_tcp(struct pkt pkt)
{
	int ret;
	enum pkt_action act;	

	ret = call_tail_tcppct(pkt);

	return PKT_ACT_CONTINUE;
}

#endif /* TCP_H */
