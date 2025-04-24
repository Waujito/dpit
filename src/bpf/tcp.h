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

static __inline enum pkt_action process_tcp(struct packet_data *pktd)
{
	enum pkt_action act;

	act = tcp_process_conntrack(pktd);

	// u32 offset = pktd->ltd.payload_offset;
	// act = process_tls(pktd->pkt, offset);
	return act;
}

#endif /* TCP_H */
