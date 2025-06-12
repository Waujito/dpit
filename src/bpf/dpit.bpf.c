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

	if (pktd.ltd.transport_type == TCP) {
		act = process_tcp(&pktd, pkt);
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
