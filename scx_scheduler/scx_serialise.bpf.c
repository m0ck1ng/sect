/*
 * scx_serialise: temporal-isolation scheduler for concurrency testing.
 *
 * Serialises syz-executor thread groups so that at most one task runs at a
 * time within a group, exposing concurrency bugs more reliably.
 *
 * Include order:
 *   1. <scx/common.bpf.h>    — SCX helpers, types, macros
 *   2. "scx_serialise.bpf.h" — shared enums, structs, maps, helpers
 *   3. "scx_algo.bpf.h"      — scheduling algorithm interface
 */
#include <scx/common.bpf.h>
#include "scx_serialise.bpf.h"
#include "scx_algo.bpf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

bool timer_pinned = true;
u64  nr_cycles, nr_dispatch, nr_timeout;
u64  nr_dispatch_empty, nr_dispatch_enqueue_failed;
u64  nr_late_join, nr_ignored_enqueue;

/* ─── Group identifier ───────────────────────────────────────────────────── */

/*
 * Match comm against "syz-executor.[0-9]\0".
 * Returns the digit as eid (0–9), or INVALID_EID for non-participants.
 * Eliminates the prior ambiguity where non-executor tasks and
 * syz-executor.0 both returned eid=0.
 */
static u32 identify_executor_group(const struct task_struct *p)
{
	char comm[TASK_COMM_LEN] = {};

	if (bpf_probe_read_kernel(comm, sizeof(comm), p->comm))
		return INVALID_EID;

	if (comm[0]  != 's' || comm[1]  != 'y' || comm[2]  != 'z' ||
	    comm[3]  != '-' || comm[4]  != 'e' || comm[5]  != 'x' ||
	    comm[6]  != 'e' || comm[7]  != 'c' || comm[8]  != 'u' ||
	    comm[9]  != 't' || comm[10] != 'o' || comm[11] != 'r' ||
	    comm[12] != '.')
		return INVALID_EID;

	if (comm[13] < '0' || comm[13] > '9' || comm[14] != '\0')
		return INVALID_EID;

	return (u32)(comm[13] - '0');
}

/*
 * Create task_ctx lazily for syz-executor target tasks.
 *
 * syzkaller's schedule_thread marks only the temporary syscall thread as
 * SCHED_EXT immediately before its first sched_yield().  In switch-partial
 * mode this keeps persistent worker_thread and executor housekeeping threads
 * outside scx_serialise.  The context is still created lazily from yield/enqueue
 * because task creation, comm assignment, and policy transition ordering is not
 * something the scheduler should rely on.
 */
static int ensure_task_ctx(struct task_struct *p, u32 eid)
{
	pid_t pid = p->pid;
	u32 pid32 = (u32)pid;
	u32 det_id_val;

	if (bpf_map_lookup_elem(&task_ctx_map, &pid))
		return 0;

	struct sched_cycle *cycle = get_or_create_sched_cycle(eid);
	if (!cycle)
		return -ENOMEM;

	u32 *existing = bpf_map_lookup_elem(&pid_to_det_id, &pid32);
	if (existing) {
		det_id_val = *existing;
	} else {
		bpf_spin_lock(&cycle->lock);
		cycle->next_det_id++;
		det_id_val = cycle->next_det_id;
		bpf_spin_unlock(&cycle->lock);
		bpf_map_update_elem(&pid_to_det_id, &pid32, &det_id_val, BPF_NOEXIST);
	}

	struct task_ctx new_ctx = {
		.priority          = 0,
		.eid               = eid,
		.det_id            = det_id_val,
		.is_asleep         = false,
		.pct_initialized   = false,
		.is_write          = false,
		.next_event_addrs  = 0,
		.state             = THREAD_REGISTERED,
		.last_enqueue_time = 0,
		.lock              = {},
	};

	long ret = bpf_map_update_elem(&task_ctx_map, &pid, &new_ctx, BPF_NOEXIST);
	return ret == -EEXIST ? 0 : ret;
}

/* ─── Cycle lifecycle helpers ──────────────────────────────────────────────── */

static void reset_cycle_state(struct sched_cycle *cycle)
{
	int num_events_seen;

	bpf_spin_lock(&cycle->lock);
	cycle->num_expected_threads = cycle_thread_count;
	cycle->num_alive = 0;
	cycle->num_queued = 0;
	cycle->num_asleep = 0;
	cycle->next_det_id = 0;
	cycle->pct_strata = 0;
	num_events_seen = cycle->num_events_seen;
	if (cycle->expected_events_per_cycle == 0)
		cycle->expected_events_per_cycle = num_events_seen;
	cycle->num_events_seen = 0;
	cycle->algo_initialized = false;
	cycle->pending_dispatch = false;
	cycle->state = CYCLE_UNAVAILABLE;
	bpf_spin_unlock(&cycle->lock);

	dbg("[reset_cycle_state] finished cycle with %d events", num_events_seen);
}

/* ─── Core enqueue logic ─────────────────────────────────────────────────── */

/*
 * Insert @p into the current cycle's private DSQ.
 * vtime = U32_MAX - priority, so higher priority is dispatched first.
 */
static __always_inline void insert_into_cycle_dsq(struct task_struct *p,
						   u32 eid, u32 priority)
{
	u64 vtime = (u64)U32_MAX - (u64)priority;

	scx_bpf_dsq_insert_vtime(p, GROUP_DSQ(eid), SCX_SLICE_DFL, vtime, 0);
}

/*
 * Enqueue policy:
 *   - non syz-executor tasks stay on the global DSQ;
 *   - participants that have not joined via first yield are ignored here;
 *   - joined participants are parked in GROUP_DSQ until the cycle gate opens.
 */
static void handle_serialise_enqueue(struct task_struct *p)
{
	pid_t pid = p->pid;
	u32 eid = identify_executor_group(p);

	if (eid == INVALID_EID) {
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
		return;
	}

	if (!is_sched_ext(p)) {
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
		return;
	}

	struct sched_cycle *cycle = bpf_map_lookup_elem(&sched_cycle_map, &eid);
	if (!cycle || cycle->state == CYCLE_TIMEOUT) {
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
		return;
	}

	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx) {
		if (ensure_task_ctx(p, eid)) {
			scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
			return;
		}
		tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
		if (!tctx) {
			scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
			return;
		}
	}

	bpf_spin_lock(&tctx->lock);
	u64 task_state = tctx->state;
	bpf_spin_unlock(&tctx->lock);
	if (task_state == THREAD_REGISTERED || task_state == THREAD_IGNORED) {
		__sync_fetch_and_add(&nr_ignored_enqueue, 1);
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
		return;
	}

	/*
	 * Initialise the scheduling algorithm once expected_events_per_cycle is
	 * known (learned when the warm-up cycle completes).
	 */
	bpf_spin_lock(&cycle->lock);
	bool need_init = (!cycle->algo_initialized &&
			  cycle->expected_events_per_cycle != 0);
	if (need_init)
		cycle->algo_initialized = true;
	bpf_spin_unlock(&cycle->lock);

	if (need_init)
		algo_init(eid);

	/* Read next-access metadata piggy-backed in task_struct fields */
	u64 msg = 0, addr = 0;
	int is_write = 0;
	long st = bpf_probe_read_kernel(&msg, sizeof(msg), &p->rt.timeout);
	st |= bpf_probe_read_kernel(&addr, sizeof(addr), &p->rt.back);
	st |= bpf_probe_read_kernel(&is_write, sizeof(is_write), &p->rt.time_slice);
	if (st != 0 || msg != 0xdeadbeef) {
		addr     = 0;
		is_write = 0;
	}

	u64 now = bpf_ktime_get_ns();

	bpf_spin_lock(&tctx->lock);
	tctx->state             = THREAD_ENQUEUED;
	tctx->is_write          = (is_write != 0);
	tctx->next_event_addrs  = addr;
	tctx->last_enqueue_time = now;
	bpf_spin_unlock(&tctx->lock);

	/*
	 * Capture initial_run (warm-up flag for PCT) and bump counters.
	 * initial_run = true while expected_events_per_cycle == 0 (algorithm not
	 * yet initialised); PCT uses a random-walk pass during warm-up.
	 */
	bool initial_run;
	bpf_spin_lock(&cycle->lock);
	initial_run = !cycle->algo_initialized;
	cycle->num_queued++;
	cycle->num_events_seen++;
	bpf_spin_unlock(&cycle->lock);

	algo_update_priority(pid, eid, initial_run);

	/* Read the priority that the algorithm just assigned */
	u32 priority = 1;
	bpf_spin_lock(&tctx->lock);
	if (tctx->priority > 0)
		priority = tctx->priority;
	bpf_spin_unlock(&tctx->lock);

	insert_into_cycle_dsq(p, eid, priority);

	/* Check dispatch invariant: num_alive − num_asleep == num_queued */
	bool cycle_dispatchable = false;
	int num_queued, num_alive, num_asleep, num_expected_threads;
	u64 state;
	bpf_spin_lock(&cycle->lock);
	num_queued  = cycle->num_queued;
	num_alive  = cycle->num_alive;
	num_asleep = cycle->num_asleep;
	num_expected_threads = cycle->num_expected_threads;
	state = cycle->state;
	if (state == CYCLE_READY || state == CYCLE_UNAVAILABLE)
		cycle_dispatchable = (num_queued == num_expected_threads);
	else if (state == CYCLE_RUNNING)
		cycle_dispatchable = (num_queued == num_alive - num_asleep);
	bpf_spin_unlock(&cycle->lock);

	dbg("[handle_serialise_enqueue] eid:%d state:%llu alive:%d queued:%d expected:%d",
	    eid, state, num_alive, num_queued, num_expected_threads);

	if (cycle_dispatchable) {
		dbg("[handle_serialise_enqueue] enqueueing eid %d for dispatch", eid);
		enqueue_cycle_for_dispatch(eid, false);
	}
}

/* ─── SCX callbacks ──────────────────────────────────────────────────────── */

/*
 * Allocate task_ctx and assign a deterministic thread ID when the task is
 * already named "syz-executor.N" at SCX init time.  ensure_task_ctx() is also
 * called lazily from enqueue/yield to cover tasks whose comm changes later.
 */
s32 BPF_STRUCT_OPS(serialise_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	if (is_kthread(p))
		return 0;

	u32 eid = identify_executor_group(p);
	if (eid == INVALID_EID)
		return 0;

	if (!is_sched_ext(p))
		return 0;

	return ensure_task_ctx(p, eid);
}

void BPF_STRUCT_OPS(serialise_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (is_kthread(p)) {
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
		return;
	}
	handle_serialise_enqueue(p);
}

void BPF_STRUCT_OPS(serialise_dequeue, struct task_struct *p, u64 deq_flags)
{
	dbg("[dequeue] pid:%d flags:%llu", p->pid, deq_flags);
}

/*
 * O(1) dispatch: pop the next dispatchable eid from the gate queue and move one
 * task from GROUP_DSQ(eid) to the local DSQ.  The DSQ's vtime ordering
 * ensures the highest-priority task is selected automatically — no iteration.
 */
void BPF_STRUCT_OPS(serialise_dispatch, s32 cpu, struct task_struct *p)
{
	s32 eid = dequeue_cycle_for_dispatch();
	if (eid < 0)
		return;

	dbg("[dispatch] eid:%d", eid);

	u32 eid_u32 = (u32)eid;
	struct sched_cycle *cycle = bpf_map_lookup_elem(&sched_cycle_map, &eid_u32);
	if (!cycle)
		return;

	/* Move highest-priority task (lowest vtime) to this CPU's local DSQ */
	if (!scx_bpf_dsq_move_to_local(GROUP_DSQ((u32)eid))) {
		/* DSQ was empty (task exited between enqueue and dispatch) */
		int num_queued;
		u64 state;
		bpf_spin_lock(&cycle->lock);
		cycle->pending_dispatch = false;
		state = cycle->state;
		if (state == CYCLE_TIMEOUT)
			cycle->num_queued = 0;
		num_queued = cycle->num_queued;
		bpf_spin_unlock(&cycle->lock);
		__sync_fetch_and_add(&nr_dispatch_empty, 1);
		if (num_queued > 0)
			enqueue_cycle_for_dispatch(eid_u32, state == CYCLE_TIMEOUT);
		dbg("[dispatch] DSQ empty for eid:%d", eid);
		return;
	}

	int num_queued;
	u64 state;
	bpf_spin_lock(&cycle->lock);
	if (cycle->num_queued > 0)
		cycle->num_queued--;
	num_queued = cycle->num_queued;
	state = cycle->state;
	cycle->pending_dispatch = false;
	bpf_spin_unlock(&cycle->lock);

	__sync_fetch_and_add(&nr_dispatch, 1);

	/*
	 * Once a cycle times out, stop enforcing the all-ready gate and drain the
	 * group DSQ.  The timeout path can mark several THREAD_ENQUEUED tasks as
	 * THREAD_TIMEOUT while pending_dispatch allows only one eid push.  If we
	 * dispatched just one task and left the rest in GROUP_DSQ, sched_ext's
	 * watchdog would later report a runnable-task stall.
	 */
	if (state == CYCLE_TIMEOUT && num_queued > 0)
		enqueue_cycle_for_dispatch(eid_u32, true);
}

void BPF_STRUCT_OPS(serialise_runnable, struct task_struct *p, u64 enq_flags)
{
	u32 eid = identify_executor_group(p);
	if (eid == INVALID_EID)
		return;

	struct sched_cycle *cycle = bpf_map_lookup_elem(&sched_cycle_map, &eid);
	if (!cycle)
		return;

	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx)
		return;

	bool was_asleep;
	bpf_spin_lock(&tctx->lock);
	was_asleep      = tctx->is_asleep;
	tctx->is_asleep = false;
	bpf_spin_unlock(&tctx->lock);

	if (was_asleep) {
		bool should_dispatch = false;
		bpf_spin_lock(&cycle->lock);
		if (cycle->num_asleep > 0)
			cycle->num_asleep--;
		if (cycle->state == CYCLE_RUNNING &&
		    cycle->num_queued == cycle->num_alive - cycle->num_asleep)
			should_dispatch = true;
		bpf_spin_unlock(&cycle->lock);
		if (should_dispatch)
			enqueue_cycle_for_dispatch(eid, false);
	}

	dbg("[runnable] pid:%d", pid);
}

/*
 * Task starts running on a CPU.  Only tasks that actually came from GROUP_DSQ
 * (ENQUEUED/TIMEOUT) are moved to RUNNING here; REGISTERED must stay intact so
 * the first yield can account the task into the cycle exactly once.
 */
void BPF_STRUCT_OPS(serialise_running, struct task_struct *p)
{
	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (tctx) {
		bpf_spin_lock(&tctx->lock);
		if (tctx->state == THREAD_ENQUEUED ||
		    tctx->state == THREAD_TIMEOUT) {
			tctx->state = THREAD_RUNNING;
			tctx->last_enqueue_time = 0;
		}
		bpf_spin_unlock(&tctx->lock);
	}
	dbg("[running] pid:%d", pid);
}

void BPF_STRUCT_OPS(serialise_stopping, struct task_struct *p, bool runnable)
{
	dbg("[stopping] pid:%d", p->pid);
}

static void handle_executor_sleep(struct task_struct *p)
{
	pid_t pid = p->pid;
	u32 eid = identify_executor_group(p);
	if (eid == INVALID_EID)
		return;

	struct sched_cycle *cycle = bpf_map_lookup_elem(&sched_cycle_map, &eid);
	if (!cycle)
		return;

	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx)
		return;

	bpf_spin_lock(&tctx->lock);
	u64 task_state  = tctx->state;
	bool was_asleep = tctx->is_asleep;
	if (task_state != THREAD_REGISTERED && task_state != THREAD_IGNORED &&
	    !was_asleep) {
		tctx->is_asleep = true;
		if (task_state == THREAD_ENQUEUED || task_state == THREAD_TIMEOUT)
			tctx->last_enqueue_time = 0;
	}
	bpf_spin_unlock(&tctx->lock);

	if (task_state == THREAD_REGISTERED || task_state == THREAD_IGNORED)
		return;

	if (was_asleep)
		return;

	int num_alive, num_queued, num_asleep, num_expected_threads;
	u64 state;
	bpf_spin_lock(&cycle->lock);
	/*
	 * If an enqueued task sleeps, the kernel removes it from GROUP_DSQ.
	 * Keep the dispatch invariant in sync with that implicit removal.
	 */
	if ((task_state == THREAD_ENQUEUED || task_state == THREAD_TIMEOUT) &&
	    cycle->num_queued > 0)
		cycle->num_queued--;
	cycle->num_asleep++;
	num_asleep = cycle->num_asleep;
	num_expected_threads = cycle->num_expected_threads;
	num_alive = cycle->num_alive;
	num_queued = cycle->num_queued;
	state = cycle->state;
	bpf_spin_unlock(&cycle->lock);

	dbg("[handle_executor_sleep] alive:%d asleep:%d queued:%d expected:%d",
	    num_alive, num_asleep, num_queued, num_expected_threads);

	if (state == CYCLE_RUNNING && num_queued == num_alive - num_asleep)
		enqueue_cycle_for_dispatch(eid, false);
}

/*
 * Sleep is reported through deq_flags.  The kernel may OR multiple SCX_DEQ_*
 * bits, so test SCX_DEQ_SLEEP with bitwise AND instead of matching constants.
 */
void BPF_STRUCT_OPS(serialise_quiescent, struct task_struct *p, u64 deq_flags)
{
	dbg("[quiescent] pid:%d flags:%llu", p->pid, deq_flags);
	if (deq_flags & SCX_DEQ_SLEEP)
		handle_executor_sleep(p);
}

/*
 * First yield() after sched_setscheduler(SCHED_EXT) signals that the temporary
 * syscall thread is ready to join its scheduling cycle.  task_ctx may have been
 * created in init_task(), but yield creates it lazily as well; only the first
 * REGISTERED → RUNNING transition contributes num_alive accounting.
 */
bool BPF_STRUCT_OPS(serialise_yield, struct task_struct *from,
		    struct task_struct *to)
{
	if (is_kthread(from))
		return true;

	u32 eid = identify_executor_group(from);
	if (eid == INVALID_EID)
		return true;

	if (!is_sched_ext(from))
		return true;

	if (ensure_task_ctx(from, eid))
		return true;

	struct sched_cycle *cycle = bpf_map_lookup_elem(&sched_cycle_map, &eid);
	if (!cycle)
		return true;

	pid_t pid = from->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx)
		return true;

	/* Only the first yield (REGISTERED → group join) does accounting */
	bpf_spin_lock(&tctx->lock);
	u64 task_state = tctx->state;
	bpf_spin_unlock(&tctx->lock);

	if (task_state != THREAD_REGISTERED)
		return true;	/* subsequent yields: just preempt */

	bpf_spin_lock(&cycle->lock);
	u64 cycle_state = cycle->state;
	bpf_spin_unlock(&cycle->lock);

	if (cycle_state != CYCLE_UNAVAILABLE) {
		dbg("[yield] pid %d joined late; cycle %d already running", pid, eid);
		bpf_spin_lock(&tctx->lock);
		tctx->state = THREAD_IGNORED;
		bpf_spin_unlock(&tctx->lock);
		__sync_fetch_and_add(&nr_late_join, 1);
		return true;
	}

	/* REGISTERED → RUNNING: task is now alive in the group */
	bpf_spin_lock(&tctx->lock);
	tctx->state = THREAD_RUNNING;
	bpf_spin_unlock(&tctx->lock);

	/* Force re-enqueue so the task goes through serialise_enqueue */
	from->scx.slice = 0;

	bpf_spin_lock(&cycle->lock);
	cycle->num_alive++;
	if (cycle->num_alive == cycle->num_expected_threads)
		cycle->state = CYCLE_READY;
	bpf_spin_unlock(&cycle->lock);

	dbg("[yield] pid:%d joined group eid:%d", pid, eid);
	return true;
}

/*
 * Remove a participant from its cycle and reset the cycle once the last
 * participating thread exits.  REGISTERED/IGNORED tasks never joined.
 */
static void handle_executor_exit(struct task_struct *p)
{
	pid_t pid = p->pid;
	u32 eid = identify_executor_group(p);
	if (eid == INVALID_EID)
		return;

	struct sched_cycle *cycle = bpf_map_lookup_elem(&sched_cycle_map, &eid);
	if (!cycle)
		return;

	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx)
		return;

	bpf_spin_lock(&tctx->lock);
	u64 task_state = tctx->state;
	bool was_asleep = tctx->is_asleep;
	bpf_spin_unlock(&tctx->lock);

	bpf_map_delete_elem(&task_ctx_map, &pid);
	u32 pid32 = (u32)pid;
	bpf_map_delete_elem(&pid_to_det_id, &pid32);

	/* REGISTERED tasks never joined the group; skip num_alive accounting */
	if (task_state == THREAD_REGISTERED || task_state == THREAD_IGNORED)
		return;

	int num_alive, num_queued, num_asleep, num_expected_threads;
	u64 state;
	bpf_spin_lock(&cycle->lock);
	state = cycle->state;
	if (state == CYCLE_READY || state == CYCLE_UNAVAILABLE)
		cycle->num_expected_threads--;
	if (task_state == THREAD_ENQUEUED || task_state == THREAD_TIMEOUT) {
		if (cycle->num_queued > 0)
			cycle->num_queued--;
	}
	if (was_asleep && cycle->num_asleep > 0)
		cycle->num_asleep--;
	if (cycle->num_alive > 0)
		cycle->num_alive--;
	num_expected_threads = cycle->num_expected_threads;
	num_alive = cycle->num_alive;
	num_queued = cycle->num_queued;
	num_asleep = cycle->num_asleep;
	bpf_spin_unlock(&cycle->lock);

	dbg("[handle_executor_exit] alive:%d asleep:%d queued:%d expected:%d",
	    num_alive, num_asleep, num_queued, num_expected_threads);

	if (num_alive && num_queued == num_alive - num_asleep)
		enqueue_cycle_for_dispatch(eid, state == CYCLE_TIMEOUT);

	if (!num_expected_threads || (!num_alive && state != CYCLE_UNAVAILABLE)) {
		reset_cycle_state(cycle);
		__sync_fetch_and_add(&nr_cycles, 1);
		if (state == CYCLE_TIMEOUT)
			__sync_fetch_and_add(&nr_timeout, 1);
	}
}

void BPF_STRUCT_OPS(serialise_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	dbg("[exit_task] pid:%d", p->pid);
	handle_executor_exit(p);
}

/* ─── Timeout watchdog ───────────────────────────────────────────────────── */

static bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

/*
 * Timer callback: scan task_ctx_map for tasks that are still parked in a
 * GROUP_DSQ after TIMEOUT_BUDGET.  Mark them THREAD_TIMEOUT and push their
 * eid onto the dispatch gate queue so the group gets unblocked.  THREAD_TIMEOUT
 * tasks remain eligible for repeated nudges until serialise_running() clears
 * last_enqueue_time; this recovers from stale num_queued accounting without
 * leaving runnable tasks in a private DSQ until the sched_ext watchdog fires.
 */
static u64 check_dispatch_timeout(struct bpf_map *map, pid_t *pid,
				  struct task_ctx *tctx, u64 *now)
{
	u32 eid;
	u64 enqueue_time, expire_at;
	bool is_asleep;

	bpf_spin_lock(&tctx->lock);
	u64 state = tctx->state;
	enqueue_time = tctx->last_enqueue_time;
	expire_at = enqueue_time + TIMEOUT_BUDGET;
	eid       = tctx->eid;
	is_asleep = tctx->is_asleep;
	bpf_spin_unlock(&tctx->lock);

	if ((state != THREAD_ENQUEUED && state != THREAD_TIMEOUT) ||
	    is_asleep || enqueue_time == 0 || !vtime_before(expire_at, *now))
		return 0;

	bpf_spin_lock(&tctx->lock);
	if ((tctx->state != THREAD_ENQUEUED && tctx->state != THREAD_TIMEOUT) ||
	    tctx->is_asleep || tctx->last_enqueue_time == 0) {
		bpf_spin_unlock(&tctx->lock);
		return 0;
	}
	tctx->state = THREAD_TIMEOUT;
	bpf_spin_unlock(&tctx->lock);

	enqueue_cycle_for_dispatch(eid, true);
	dbg("[check_dispatch_timeout] pid:%d eid:%d", *pid, eid);
	return 0;
}

static int dispatch_timer_fn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = bpf_ktime_get_ns();

	bpf_for_each_map_elem(&task_ctx_map, check_dispatch_timeout, &now, 0);
	bpf_timer_start(timer, TIMER_INTERVAL_NS,
			timer_pinned ? BPF_F_TIMER_CPU_PIN : 0);
	return 0;
}

/* ─── Init / exit ────────────────────────────────────────────────────────── */

s32 BPF_STRUCT_OPS_SLEEPABLE(serialise_init)
{
	/* Create one vtime-ordered DSQ per executor group */
	u32 i;
	bpf_for(i, 0, MAX_EXECUTOR_GROUPS) {
		s32 ret = scx_bpf_create_dsq(GROUP_DSQ(i), -1);
		if (ret) {
			scx_bpf_error("failed to create DSQ %d: %d", i, ret);
			return ret;
		}
	}

	/* Start the timeout watchdog timer */
	u32 key = 0;
	struct dispatch_timer *dt = bpf_map_lookup_elem(&dispatch_timer, &key);
	if (!dt)
		return -ESRCH;

	bpf_timer_init(&dt->timer, &dispatch_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&dt->timer, dispatch_timer_fn);

	int ret = bpf_timer_start(&dt->timer, TIMER_INTERVAL_NS,
				  BPF_F_TIMER_CPU_PIN);
	if (ret == -EINVAL) {
		timer_pinned = false;
		ret = bpf_timer_start(&dt->timer, TIMER_INTERVAL_NS, 0);
	}
	if (ret)
		scx_bpf_error("bpf_timer_start failed (%d)", ret);

	return 0;
}

void BPF_STRUCT_OPS(serialise_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* ─── Ops registration ───────────────────────────────────────────────────── */

SEC(".struct_ops.link")
struct sched_ext_ops serialise_ops = {
	.init_task  = (void *)serialise_init_task,
	.enqueue    = (void *)serialise_enqueue,
	.dequeue    = (void *)serialise_dequeue,
	.dispatch   = (void *)serialise_dispatch,
	.runnable   = (void *)serialise_runnable,
	.running    = (void *)serialise_running,
	.stopping   = (void *)serialise_stopping,
	.quiescent  = (void *)serialise_quiescent,
	.yield      = (void *)serialise_yield,
	.exit_task  = (void *)serialise_exit_task,
	.init       = (void *)serialise_init,
	.exit       = (void *)serialise_exit,
	.flags      = SCX_OPS_ENQ_LAST | SCX_OPS_SWITCH_PARTIAL,
	.timeout_ms = 30000,
	.name       = "serialise",
};
