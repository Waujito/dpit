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


#include "types.h"
#include "tcp.h"

static __inline enum pkt_action handle_pkt(struct pkt pkt) 
{
	int ret;
	struct packet_data pktd;
	enum pkt_action act = PKT_ACT_PASS;

	pktd.pkt = pkt;

	ret = get_network_data(pkt, &pktd.lnd);
	if (ret) {
		bpf_printk("load_network_error");
		return PKT_ACT_PASS;
	}
	
	ret = get_transport_data(pkt, &pktd.lnd, &pktd.ltd);
	if (ret) {
		bpf_printk("load_transport_error");
		return PKT_ACT_PASS;
	}

	ret = bpf_map_update_elem(&pktd_storage, &PCP_KEY, &pktd, BPF_ANY);
	if (ret) {
		// Should be unreachable
		return PKT_ACT_CONTINUE;
	}

	if (pktd.ltd.transport_type == TCP) {
		act = process_tcp(pkt);
	}
	
	return act;
}

SEC("classifier")
int handle_tc(struct __sk_buff *skb) 
{
	if ((skb->mark & RAWSOCKET_MARK) == RAWSOCKET_MARK) {
		return TC_ACT_UNSPEC;
	}

	struct pkt pkt = {
		.skb = skb,
		.type = SKB_PKT
	};

	enum pkt_action action = handle_pkt(pkt);

	switch (action) {
		case PKT_ACT_DROP:
			bpf_printk("drop");
			return TC_ACT_SHOT;

		case PKT_ACT_PASS:
		case PKT_ACT_CONTINUE:
		default:
			return TC_ACT_UNSPEC;
	}
}

SEC("xdp")
int handle_xdp(struct xdp_md *xdp) 
{
	struct pkt pkt = {
		.xdp = xdp,
		.type = XDP_PKT
	};

	enum pkt_action action = handle_pkt(pkt);
	switch (action) {
		case PKT_ACT_DROP:
			return XDP_DROP;

		case PKT_ACT_PASS:
		case PKT_ACT_CONTINUE:
		default:
			return XDP_PASS;
	}
}

char _license[] SEC("license") = "GPL";
