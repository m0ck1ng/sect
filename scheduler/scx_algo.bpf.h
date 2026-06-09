#ifndef __SCX_ALGO_BPF_H
#define __SCX_ALGO_BPF_H

/*
 * Scheduling algorithm interface.
 *
 * A single `sched_algorithm` rodata variable selects which algorithm is
 * active.  This replaces the previous four independent boolean flags
 * (use_pct / use_pos / use_random_priority_walk / use_random_walk) which
 * produced undefined behaviour when more than one was set to 1.
 */

enum sched_algo {
	ALGO_PCT = 0,   /* Probabilistic Concurrency Testing              */
	ALGO_POS = 1,   /* Priority-based OS scheduling (memory-race aware) */
	ALGO_RW  = 2,   /* Random Walk: re-randomise all tasks each event  */
	ALGO_RP  = 3,   /* Random Priority: re-randomise only this task    */
};

const volatile u32 sched_algorithm = ALGO_PCT;

#include "pct.bpf.h"
#include "pos.bpf.h"
#include "random_walk.bpf.h"
#include "random_priority.bpf.h"

/*
 * algo_init() — called once per cycle when the first events are observed.
 */
static __always_inline s32 algo_init(u32 eid)
{
	switch (sched_algorithm) {
	case ALGO_PCT: return init_pct(eid);
	case ALGO_POS: return init_pos();
	case ALGO_RW:  return init_rw();
	case ALGO_RP:  return init_rp();
	default:       return -1;
	}
}

/*
 * algo_update_priority() — called on every enqueue event for a task.
 *
 * @initial_run: true before the scheduling algorithm has been initialised
 *               (i.e. before the first complete event count is known).
 *               PCT uses a random-walk pass for this warm-up phase.
 */
static __always_inline s32 algo_update_priority(pid_t pid, u32 eid,
						bool initial_run)
{
	switch (sched_algorithm) {
	case ALGO_PCT:
		/* Warm-up: use random walk until expected_events_per_cycle is known */
		if (initial_run)
			return update_priorities_rw(eid);
		return update_priorities_pct(eid, pid);
	case ALGO_POS:
		return update_priorities_pos(eid, pid);
	case ALGO_RW:
		return update_priorities_rw(eid);
	case ALGO_RP:
		return (pid > 0) ? update_priorities_rp(pid) : 0;
	default:
		return -1;
	}
}

#endif /* __SCX_ALGO_BPF_H */
