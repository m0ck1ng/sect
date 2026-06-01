#ifndef __PCT_BPF_H
#define __PCT_BPF_H

/*
 * PCT (Probabilistic Concurrency Testing) algorithm.
 *
 * Each iteration assigns a random permutation of priorities to threads
 * (via shuffle_prios) and selects `depth-1` random "change points".
 * When the event count crosses a change point, the currently-running
 * task is demoted to a lower priority stratum so a different thread
 * gets the CPU next, increasing the chance of hitting concurrency bugs.
 *
 * Reference: Burckhardt et al., "A Randomized Scheduler with Probabilistic
 * Guarantees of Finding Bugs", ASPLOS 2010.
 */

#define S32_MAX ((__s32)(((__u32)-1) >> 1))
const volatile u32 depth = 3;

/* Pack (eid, det_id) into a single 32-bit map key */
static __always_inline u32 get_combined_key(u32 eid, u32 det_id)
{
	return (eid << 16) | (det_id % MAX_CYCLE_THREADS);
}

static __always_inline u32 get_combined_changepoint_key(u32 eid, u32 cp)
{
	return (eid << 16) | cp;
}

/* Pre-assigned per-thread priorities (shuffled each iteration) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_EXECUTOR_GROUPS * MAX_CYCLE_THREADS);
} pct_priorities SEC(".maps");

/* Change points: indices into the event sequence where priority demotions fire */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_EXECUTOR_GROUPS * MAX_CYCLE_THREADS);
} pct_change_points SEC(".maps");

/* Strata base: higher strata = lower priority range */
static __always_inline s32 get_strata_base(u32 strata)
{
	return S32_MAX - ((strata + 2) * MAX_CYCLE_THREADS);
}

static __always_inline void swap_u32(u32 *a, u32 *b)
{
	u32 tmp = *a;
	*a = *b;
	*b = tmp;
}

/*
 * Reset priorities for all `MAX_CYCLE_THREADS` slots and shuffle them using
 * the Fisher-Yates algorithm to produce a random permutation.
 */
static __always_inline void shuffle_prios(u32 eid, u32 strata)
{
	u32 i, index;

	if (depth < 1 || depth > MAX_CYCLE_THREADS + 1) {
		warn("[pct] invalid depth %d", depth);
		return;
	}

	bpf_for(i, depth, depth + MAX_CYCLE_THREADS) {
		index = get_combined_key(eid, i - depth);
		u32 val = get_strata_base(strata) + i;
		bpf_map_update_elem(&pct_priorities, &index, &val, BPF_ANY);
	}

	bpf_for(i, 1, MAX_CYCLE_THREADS) {
		u32 ai = get_combined_key(eid, MAX_CYCLE_THREADS - i);
		u32 aj = get_combined_key(eid, bpf_get_prandom_u32() % (MAX_CYCLE_THREADS - i + 1));
		u32 *va = bpf_map_lookup_elem(&pct_priorities, &ai);
		u32 *vb = bpf_map_lookup_elem(&pct_priorities, &aj);
		if (va && vb)
			swap_u32(va, vb);
		else
			warn("[shuffle_prios] failed to swap at %d and %d", ai, aj);
	}
}

/*
 * Choose `depth-1` random change points in [1, max_events].
 * Duplicate change points are allowed (they collapse to a single demotion).
 */
static __always_inline void choose_change_points(u32 eid, u32 max_events)
{
	u32 i, n;

	if (depth < 1 || depth > MAX_CYCLE_THREADS + 1) {
		scx_bpf_error("[pct] invalid depth %d", depth);
		return;
	}
	n = depth - 1;

	bpf_for(i, 0, n) {
		u32 cp_key = get_combined_changepoint_key(eid, i);
		u32 cp_val;

		if (max_events == 0)
			cp_val = i;   /* fallback: 0, 1, 2, ... */
		else
			cp_val = (bpf_get_prandom_u32() % max_events) + 1;

		long ret = bpf_map_update_elem(&pct_change_points, &cp_key,
					       &cp_val, BPF_ANY);
		if (ret)
			warn("[pct] failed to set change_point[%d]=%d", i, cp_val);
		else
			dbg("[pct] change_point[%d] = %d", i, cp_val);
	}
}

static __always_inline s32 init_pct(u32 eid)
{
	struct sched_cycle *cycle = bpf_map_lookup_elem(&sched_cycle_map, &eid);
	if (!cycle) {
		warn("[pct] init: cycle not found for eid %d", eid);
		return -1;
	}
	dbg("[pct] init depth=%d", depth);
	shuffle_prios(eid, cycle->pct_strata);
	choose_change_points(eid, cycle->expected_events_per_cycle);
	return 0;
}

/*
 * Look up the pre-shuffled priority assigned to this thread's det_id slot.
 */
static __always_inline s32 assign_pct_priority(u32 eid, u32 det_id)
{
	u32 index = get_combined_key(eid, det_id);
	s32 *val = bpf_map_lookup_elem(&pct_priorities, &index);
	return val ? *val : -1;
}

static __always_inline s32 update_priorities_pct(u32 eid, pid_t pid)
{
	struct sched_cycle *cycle = bpf_map_lookup_elem(&sched_cycle_map, &eid);
	if (!cycle) {
		warn("[pct] update: cycle not found for eid %d", eid);
		return -1;
	}

	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx) {
		dbg("[pct] task context not found for pid %d", pid);
		return -1;
	}

	u32 n;
	if (depth < 1 || depth > MAX_CYCLE_THREADS + 1) {
		warn("[pct] invalid depth %d", depth);
		return -1;
	}
	n = depth - 1;

	bpf_spin_lock(&cycle->lock);
	u32 num_events_seen = cycle->num_events_seen;
	u32 max_events = cycle->expected_events_per_cycle;
	u32 strata = cycle->pct_strata;
	bpf_spin_unlock(&cycle->lock);

	if (max_events == 0)
		return 0;

	bpf_spin_lock(&tctx->lock);
	bool pct_initialized = tctx->pct_initialized;
	u32 det_id = tctx->det_id;
	bpf_spin_unlock(&tctx->lock);

	if (!pct_initialized) {
		s32 prio = assign_pct_priority(eid, det_id);
		if (prio >= 0) {
			bpf_spin_lock(&tctx->lock);
			tctx->priority = prio;
			tctx->pct_initialized = true;
			bpf_spin_unlock(&tctx->lock);
			dbg("[pct] initial priority: pid=%d priority=%d", pid, prio);
		}
	}

	u32 i;
	bpf_for(i, 0, n) {
		u32 cp_key = get_combined_changepoint_key(eid, i);
		u32 *cp    = bpf_map_lookup_elem(&pct_change_points, &cp_key);

		if (cp) {
			if ((num_events_seen % max_events) == *cp) {
				/*
				 * Change point hit: optionally advance strata if
				 * we have seen more events than one full "lap".
				 * Bug fix: original compared num_events_seen with itself;
				 * corrected to compare against max_events * (strata+1).
				 */
				if (num_events_seen > max_events * (strata + 1)) {
					strata += 1;
					/* Write back so future calls see the new strata */
					bpf_spin_lock(&cycle->lock);
					cycle->pct_strata = strata;
					bpf_spin_unlock(&cycle->lock);
					dbg("[pct] new strata %d", strata);
				}

				s32 priority = get_strata_base(strata) + i + 1;
				update_priority(pid, priority);
				dbg("[pct] change point: pid=%d priority=%d", pid, priority);
				break;
			}
		}
	}
	return 0;
}

#endif /* __PCT_BPF_H */
