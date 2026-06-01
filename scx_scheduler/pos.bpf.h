#ifndef __POS_BPF_H
#define __POS_BPF_H

/*
 * POS (Priority-based OS scheduling) algorithm: assign random priority
 * to each enqueueing task, then re-randomise any other task in the group
 * that is racing on the same memory address (write-write or write-read).
 */

static __always_inline u32 rand_pos_priority(void)
{
	return bpf_get_prandom_u32() % 50 + 1;
}

struct pos_callback_ctx {
	u32  eid;
	pid_t pid;
	u64  next_event_addrs;
	bool is_write;
};

/*
 * For every task in the group, if it accesses the same address as the
 * currently-enqueueing task and at least one access is a write, re-randomise
 * its priority to increase the probability of hitting the race.
 */
static int update_all_prios_pos(struct bpf_map *map, pid_t *pid,
				struct task_ctx *tctx,
				struct pos_callback_ctx *ctx)
{
	if (tctx->eid != ctx->eid)
		return 0;

	if (tctx->next_event_addrs != 0
	    && tctx->next_event_addrs == ctx->next_event_addrs
	    && (tctx->is_write || ctx->is_write)) {
		dbg("[pos] race with %d @%p", ctx->pid, tctx->next_event_addrs);
		u32 priority = rand_pos_priority();
		bpf_spin_lock(&tctx->lock);
		tctx->priority = priority;
		bpf_spin_unlock(&tctx->lock);
	}
	return 0;
}

static __always_inline s32 update_priorities_pos(u32 eid, pid_t pid)
{
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx) {
		dbg("[pos] task context not found for pid %d", pid);
		return -1;
	}

	u32 priority = rand_pos_priority();
	bpf_spin_lock(&tctx->lock);
	tctx->priority = priority;
	bpf_spin_unlock(&tctx->lock);

	struct pos_callback_ctx ctx = {
		.eid             = eid,
		.pid             = pid,
		.next_event_addrs = tctx->next_event_addrs,
		.is_write        = tctx->is_write,
	};
	bpf_for_each_map_elem(&task_ctx_map, update_all_prios_pos, &ctx, 0);
	return 0;
}

static __always_inline s32 init_pos(void)
{
	return 0;
}

#endif /* __POS_BPF_H */
