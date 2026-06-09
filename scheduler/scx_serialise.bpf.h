#ifndef __SCX_SERIALISE_BPF_H
#define __SCX_SERIALISE_BPF_H

/*
 * scx_serialise shared definitions: enums, structs, maps, and utility
 * functions used by both the main scheduler and the algorithm headers.
 *
 * Include order in scx_serialise.bpf.c:
 *   1. <scx/common.bpf.h>
 *   2. "scx_serialise.bpf.h"   ← this file (maps + helpers)
 *   3. "scx_algo.bpf.h"        ← algorithm interface (uses maps/helpers above)
 */

/* ─── Constants ──────────────────────────────────────────────────────────── */

#ifndef U32_MAX
#define U32_MAX ((u32)~0U)
#endif

enum {
	SCHED_EXT_POLICY	= 7,
	MAX_CYCLE_THREADS	= 200,
	MAX_EXECUTOR_GROUPS	= 10,
	/*
	 * Sentinel returned by identify_executor_group() for tasks that are NOT
	 * syz-executor participants.  Eliminates the previous ambiguity
	 * where non-executor tasks and syz-executor.0 both returned 0.
	 */
	INVALID_EID		= MAX_EXECUTOR_GROUPS + 1,

	MS_TO_NS		= 1000LLU * 1000,
	TIMER_INTERVAL_NS	= 30 * MS_TO_NS,
	TIMEOUT_BUDGET		= 60 * MS_TO_NS,

	/*
	 * Task state machine:
	 *
	 *   init_task()     → REGISTERED
	 *   yield() 1st     → RUNNING   (joins group, gets det_id)
	 *   enqueue()       → ENQUEUED  (inserted into GROUP_DSQ)
	 *   running() cb    → RUNNING   (task on CPU)
	 *   timeout         → TIMEOUT   (dispatch gate is forced open)
	 *   exit_task()     → (deleted from task_ctx_map)
	 */
	THREAD_REGISTERED	= 0,	/* init_task done, not yet in group   */
	THREAD_ENQUEUED		= 1,	/* in GROUP_DSQ, waiting for dispatch */
	THREAD_RUNNING		= 2,	/* on CPU (set by serialise_running)  */
	THREAD_TIMEOUT		= 3,	/* timed out while ENQUEUED           */
	THREAD_IGNORED		= 4,	/* late joiner; not in current cycle   */

	/*
	 * Cycle state machine:
	 *
	 *   UNAVAILABLE → (all tasks alive)     → READY
	 *   READY       → (all tasks enqueued)  → RUNNING
	 *   RUNNING     → (timeout)             → TIMEOUT
	 *   RUNNING / TIMEOUT → (all exited)    → UNAVAILABLE (reset)
	 *
	 * Dispatch invariants:
	 *   num_alive - num_asleep == num_queued  ⟺  ready to dispatch
	 *   num_alive == num_expected_threads     ⟹  cycle entered READY
	 *   num_alive == num_asleep               ⟹  cycle is deadlocked
	 *   num_alive == 0                        ⟹  cycle is finished
	 */
	CYCLE_UNAVAILABLE	= 1,
	CYCLE_READY		= 2,
	CYCLE_RUNNING		= 3,
	CYCLE_TIMEOUT		= 4,
};

/*
 * Per-group DSQ IDs (0 .. MAX_EXECUTOR_GROUPS-1).
 * These small integers do not collide with SCX_DSQ_GLOBAL or SCX_DSQ_LOCAL.
 * Tasks are inserted with vtime = U32_MAX - priority so that higher numeric
 * priority means lower vtime (dispatched first by the DSQ).
 */
#define GROUP_DSQ(eid) ((u64)(eid))

/* ─── Debugging ──────────────────────────────────────────────────────────── */

const volatile u32 debug = 0;

extern u64 nr_dispatch_enqueue_failed;

#define warn(fmt, args...)  bpf_printk(fmt, ##args)

#define dbg(fmt, args...)					\
	do {							\
		if (debug)					\
			bpf_printk(fmt, ##args);		\
	} while (0)

#define trace(fmt, args...)					\
	do {							\
		if (debug > 1)					\
			bpf_printk(fmt, ##args);		\
	} while (0)

/* ─── Scheduler configuration ────────────────────────────────────────────── */

/* Expected number of syz-executor participants per cycle; set by -n. */
const volatile int cycle_thread_count = 2;

/* ─── Structs ────────────────────────────────────────────────────────────── */

/*
 * One scheduling cycle for a syz-executor.N group: from the first participant
 * yield until all participating tasks exit.  A new cycle reuses the same eid.
 */
struct sched_cycle {
	int  num_expected_threads;	/* threads expected in this cycle        */
	int  num_queued;		/* tasks parked in GROUP_DSQ             */
	int  num_asleep;		/* participating tasks blocked/sleeping  */
	int  num_alive;			/* participating tasks not yet exited    */
	u32  next_det_id;		/* deterministic-ID allocation cursor    */
	u32  expected_events_per_cycle;	/* event count learned from warm-up run   */
	u32  num_events_seen;		/* enqueue events seen in this cycle     */
	u32  pct_strata;		/* current PCT demotion stratum          */
	bool algo_initialized;		/* scheduling algorithm initialized      */
	bool pending_dispatch;		/* eid is already in dispatch queue      */
	u64  state;			/* CYCLE_* enum value                    */
	struct bpf_spin_lock lock;
};

/* Per-task state for syz-executor participants. */
struct task_ctx {
	u32  priority;
	u32  eid;		/* executor group ID                          */
	u32  det_id;		/* deterministic thread ID (for PCT)          */
	bool is_asleep;
	bool pct_initialized;
	u64  next_event_addrs;	/* memory address of next access (for POS)    */
	bool is_write;		/* whether next access is a write (for POS)   */
	u64  state;		/* THREAD_* enum value                        */
	u64  last_enqueue_time;	/* ktime_ns at last THREAD_ENQUEUED transition */
	struct bpf_spin_lock lock;
};

struct dispatch_timer {
	struct bpf_timer timer;
};

/* ─── BPF Maps ───────────────────────────────────────────────────────────── */

/* Current cycle state for each syz-executor.N group */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);		/* eid */
	__type(value, struct sched_cycle);
	__uint(max_entries, MAX_EXECUTOR_GROUPS);
} sched_cycle_map SEC(".maps");

/* Per-task scheduler state; iterated by algorithms (POS, RW) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, struct task_ctx);
	__uint(max_entries, MAX_EXECUTOR_GROUPS * MAX_CYCLE_THREADS);
} task_ctx_map SEC(".maps");

/*
 * PID → deterministic ID mapping.
 *
 * The scheduler keys task_ctx_map by TID (task_struct::pid).  Keep this map
 * large enough for all supported executor groups and delete entries on task
 * exit so PID reuse doesn't inherit a stale deterministic ID.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u32);	/* pid (truncated to u32) */
	__type(value, u32);	/* det_id */
	__uint(max_entries, MAX_EXECUTOR_GROUPS * MAX_CYCLE_THREADS);
} pid_to_det_id SEC(".maps");

/*
 * Dispatch gate queue: holds eids whose current cycle is dispatchable.
 * Atomic queue pop lets only one CPU drain one GROUP_DSQ task per push,
 * preserving the per-cycle serialisation invariant.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 64);
	__type(value, u32);	/* eid */
} cycle_dispatch_queue SEC(".maps");

/* Global dispatch timer for timeout detection */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct dispatch_timer);
} dispatch_timer SEC(".maps");

/* ─── Utility functions ──────────────────────────────────────────────────── */

static __always_inline bool is_kthread(const struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
}

static __always_inline bool is_sched_ext(const struct task_struct *p)
{
	return p->policy == SCHED_EXT_POLICY;
}

/*
 * Push @eid's current cycle onto the dispatch gate queue.
 * @timeout: set cycle state to CYCLE_TIMEOUT instead of CYCLE_RUNNING.
 *
 * Idempotent: if this eid is already queued (pending_dispatch == true) the
 * call is a no-op.  This prevents the timer path and the normal enqueue path
 * from both pushing the same eid before the first dispatch consumes it,
 * which would cause two tasks from the same group to be dispatched
 * simultaneously and break the serialisation invariant.
 * pending_dispatch is cleared by serialise_dispatch after the pop.
 */
static __always_inline void enqueue_cycle_for_dispatch(u32 eid, bool timeout)
{
	struct sched_cycle *cycle = bpf_map_lookup_elem(&sched_cycle_map, &eid);
	if (!cycle)
		return;

	bpf_spin_lock(&cycle->lock);
	u64 prev_state = cycle->state;
	if (cycle->pending_dispatch) {
		bpf_spin_unlock(&cycle->lock);
		return;
	}
	cycle->state            = timeout ? CYCLE_TIMEOUT : CYCLE_RUNNING;
	cycle->pending_dispatch = true;
	bpf_spin_unlock(&cycle->lock);

	if (bpf_map_push_elem(&cycle_dispatch_queue, &eid, BPF_EXIST) < 0) {
		bpf_spin_lock(&cycle->lock);
		cycle->pending_dispatch = false;
		cycle->state = prev_state;
		bpf_spin_unlock(&cycle->lock);
		__sync_fetch_and_add(&nr_dispatch_enqueue_failed, 1);
		dbg("[enqueue_cycle_for_dispatch] failed to push eid %d", eid);
	}
}

/* Pop the next dispatchable cycle's eid; returns -1 if the queue is empty. */
static __always_inline s32 dequeue_cycle_for_dispatch(void)
{
	u32 eid;
	if (bpf_map_pop_elem(&cycle_dispatch_queue, &eid) < 0)
		return -1;
	return (s32)eid;
}

/*
 * Update @pid's priority in task_ctx_map under the task's spin lock.
 * Called by algorithm implementations.
 */
static __always_inline void update_priority(pid_t pid, s32 priority)
{
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx) {
		dbg("[update_priority] task context not found for pid %d", pid);
		return;
	}
	bpf_spin_lock(&tctx->lock);
	tctx->priority = priority;
	bpf_spin_unlock(&tctx->lock);
}

/*
 * Look up the sched_cycle for @eid, creating a new one if it does not exist.
 * New cycles start in CYCLE_UNAVAILABLE and wait for cycle_thread_count
 * participants to join through their first sched_yield().
 */
static __always_inline struct sched_cycle *get_or_create_sched_cycle(u32 eid)
{
	struct sched_cycle *cycle = bpf_map_lookup_elem(&sched_cycle_map, &eid);
	if (cycle)
		return cycle;

	struct sched_cycle new_cycle = {
		.num_expected_threads		= cycle_thread_count,
		.num_alive			= 0,
		.num_asleep			= 0,
		.num_queued			= 0,
		.num_events_seen		= 0,
		.next_det_id			= 0,
		.pct_strata			= 0,
		.expected_events_per_cycle	= 0,
		.algo_initialized		= false,
		.pending_dispatch		= false,
		.state				= CYCLE_UNAVAILABLE,
		.lock				= {},
	};
	bpf_map_update_elem(&sched_cycle_map, &eid, &new_cycle, BPF_NOEXIST);
	return bpf_map_lookup_elem(&sched_cycle_map, &eid);
}

#endif /* __SCX_SERIALISE_BPF_H */
