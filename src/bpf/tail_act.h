#ifndef TAIL_ACT_H
#define TAIL_ACT_H

#include "types.h"

#define FCT_SEQ_WINSIZE 32768

/**
 * Ct entry for fast action with bigger window.
 */
struct fct_value {
	// Used for early exit if the connection is approved/dropped
	struct dpit_action fast_action;
	u64 timestamp;
	u64 seq;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 20000);
	__type(key, struct ct_entry);
	__type(value, struct fct_value);
} fct_map SEC(".maps");

static __inline struct dpit_action tcp_fct_lookup(struct ct_entry cte)
{	
	int ret;
	struct dpit_action act = {0};
	act.type = DPIT_ACT_CONTINUE;

	u32 seq = cte.tpe.seq_hash;
	u32 seqp = seq / FCT_SEQ_WINSIZE;
	cte.tpe.seq_hash = seqp;
	
	// Try to find an existing connection
	struct fct_value *ctv = bpf_map_lookup_elem(&fct_map, &cte);	
	if (ctv == NULL) {
		struct ct_entry ncte = cte;
		ncte.tpe.seq_hash = cte.tpe.seq_hash - 1;
		ctv = bpf_map_lookup_elem(&fct_map, &ncte);
		if (ctv == NULL) {
			return act;
		}

		// If in the end, slide the window right
		ret = bpf_map_update_elem(&fct_map, &cte, ctv, BPF_ANY);
		if (ret) {
			return act;
		}

		bpf_map_delete_elem(&fct_map, &ncte);

		ctv = bpf_map_lookup_elem(&fct_map, &cte);
		if (ctv == NULL) {
			return act;
		}
	}

	// bpf_tt_printk("Found smthing seq diff %u seqp %u", seq - ctv->seq, seqp);

	u64 ktime = bpf_ktime_get_boot_ns();
	if (	ktime < ctv->timestamp || 
		(ktime - ctv->timestamp) > 1000LL * 1000 * 1000 * 120) {
		bpf_map_delete_elem(&fct_map, &cte);
		return act;
	}

	ctv->timestamp = ktime;
	
	if (ctv->fast_action.type != DPIT_ACT_CONTINUE) {
		bpf_printk("Fast action %d", ctv->fast_action);
		return ctv->fast_action;
	}


	return act;
}

static __inline struct dpit_action tcp_fct_lookup_client(struct packet_data *pktd)
{
	int ret;
	struct dpit_action act = {0};
	act.type = DPIT_ACT_CONTINUE;

	if (pktd->ltd.transport_type != TCP)
		return act;

	struct ct_entry cte;
	ret = build_ct_entry(pktd, &cte);
	if (ret) {
		return act;
	}

	return tcp_fct_lookup(cte);
}

static __inline struct dpit_action tcp_fct_lookup_server(struct packet_data *pktd)
{
	int ret;
	struct dpit_action act = {0};
	act.type = DPIT_ACT_CONTINUE;

	if (pktd->ltd.transport_type != TCP)
		return act;

	struct ct_entry cte;
	ret = build_server_ct_entry(pktd, &cte);
	if (ret) {
		return act;
	}

	return tcp_fct_lookup(cte);
}

static __inline int tcp_fct_insert(struct packet_data *pktd, struct dpit_action act) {
	int ret;

	struct ct_entry cte;
	ret = build_ct_entry(pktd, &cte);
	if (ret) {
		return -1;
	}

	
	u32 seq = cte.tpe.seq_hash;
	u32 seqp = seq / FCT_SEQ_WINSIZE;
	cte.tpe.seq_hash = seqp;

	u64 ktime = bpf_ktime_get_boot_ns();
	struct fct_value ctv = {
		.fast_action = act,
		.timestamp = ktime,
		.seq = seq,
	};

	return bpf_map_update_elem(&fct_map, &cte, &ctv, BPF_ANY);
}

/**
 * Used to transfer state between tail calls
 */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, struct dpit_action);
        __uint(max_entries, 1);
} acttl_storage SEC(".maps");

static __inline int tail_cb_acttl(struct pkt pkt){
	struct packet_data pktd;
	if (get_pktd(pkt, &pktd)) {
		return -1;
	}

	struct dpit_action *actp = bpf_map_lookup_elem(&acttl_storage, &PCP_KEY);
	if (actp == NULL) {
		// should be unreachable
		bpf_e_printk("FATAL tail_acttl: Cannot get state dpit_action");
		return -1;
	}
	struct dpit_action act = *actp;

	if (act.type == DPIT_ACT_THROTTLE) {
		tcp_fct_insert(&pktd, act);
	}

	enum pkt_action pact = get_pkt_action(act);

	return get_return_code(pact, pkt.type);
}

tail_entries(tail_cb_acttl);

static __inline struct dpit_action tail_acttl(struct pkt pkt, struct dpit_action acttl) {
	int ret;
	struct dpit_action act = {
		.type = DPIT_ACT_CONTINUE
	};
	ret = bpf_map_update_elem(&acttl_storage, &PCP_KEY, &acttl, BPF_ANY);
	if (ret) {
		// Should be unreachable
		return act;
	}
	ret = call_tail_cb_acttl(pkt);
	
	return act;
}

#endif /* TAIL_ACT_H */
