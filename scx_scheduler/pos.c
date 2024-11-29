
/* 
 * Random Walk implementation. @use_random_walk is set in the corresponding
 * C program based on user-defined parameters.
 */

/*
 * Assign the priority for a thread based on a completely random number.
 */
static inline u32 rand_pos_priority()
{
	// s32 priority = xorshift32(&rng_state) % 2147483647;
	u32 priority = bpf_get_prandom_u32() % 50 + 1;
	// dbg("[assign_rw_priority] prio new %d", priority);
	return priority;
}

struct pos_tctx_callback_ctx {
	u32 eid;
	pid_t pid;
	u64 next_event_addrs;
	bool is_write;
};

/*
 * Callback function to update all priorities in tctx_map for random_walk_2
 */
static int update_all_prios_pos(struct bpf_map *map, pid_t *pid,
			      struct task_ctx *tctx,
			      struct pos_tctx_callback_ctx *tcallbackctx)
{
	if (tctx->eid != tcallbackctx->eid)
		return 0;
	
	// reset racy priorities
	if (tctx->next_event_addrs != 0 
	    && tctx->next_event_addrs == tcallbackctx->next_event_addrs 
	    && (tctx->is_write || tcallbackctx->is_write)) {
			dbg("[pos] race with %d @%p", tcallbackctx->pid, tctx->next_event_addrs);
			u32 priority = rand_pos_priority();
			bpf_spin_lock(&tctx->lock);
			tctx->priority = priority;
			bpf_spin_unlock(&tctx->lock);
			return 0;
	}

	return 0;
}

static s32 update_priorities_pos(u32 eid, pid_t pid) {

		struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
		if (!tctx) {
			dbg("[update_priority] task context not found");
			return -1;
		}

		u32 priority = rand_pos_priority();
		bpf_spin_lock(&tctx->lock);
		tctx->priority = priority;
		bpf_spin_unlock(&tctx->lock);		

		/* Update the priorities of all *racing* threads */
		struct pos_tctx_callback_ctx tcallbackctx = {
			.eid = eid,
			.pid = pid,
			.next_event_addrs = tctx->next_event_addrs,
			.is_write = tctx->is_write
		};

		bpf_for_each_map_elem(&task_ctx_map, update_all_prios_pos,
				&tcallbackctx, 0);

		return 0;
}

static inline s32 init_pos() {
	  return 0;
}


