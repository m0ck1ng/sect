/*
 * scx_serialise: simple scheduler to serialise the execution of threads
 *
 * This scheduler attempts to serialise the execution of threads by 
 * dispatching the highest priority thread in the system, only when all
 * threads have been enqueued.
 * 
 */
#include <scx/common.bpf.h>
#include <string.h>
#include <limits.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

enum {
	SCHED_EXT			= 7,
	MAX_THREADS			= 200,
	MAX_JOBS                        = 10,

	MS_TO_NS			= 1000LLU * 1000,
	TIMER_INTERVAL_NS	= 30 * MS_TO_NS,
	TIMEOUT_BUDGET		= 60 * MS_TO_NS,

	THREAD_ENQUEUED 	= 1,
	THREAD_RUNNING		= 2,
	THREAD_TIMEOUT		= 3,

	JOB_UNAVAILABLE		= 1,
	JOB_READY           = 2,
	JOB_RUNNING         = 3,
	JOB_TIMEOUT			= 4,
};

/* Debugging macros */
const volatile u32 debug = 1;
/* Scheduling algorithm macros */
const volatile int use_pct = 1;
const volatile int use_pos = 0;
const volatile int use_random_priority_walk = 0;
const volatile int use_random_walk = 0;
const volatile int num_sched_thread = 2;

bool timer_pinned = true;
u64 nr_jobs, nr_dispatch;
u64 nr_timeout;

#define warn(fmt, args...) bpf_printk(fmt, ##args)

#define dbg(fmt, args...)                        \
	do {                                     \
		if (debug)                       \
			bpf_printk(fmt, ##args); \
	} while (0)

#define trace(fmt, args...)                      \
	do {                                     \
		if (debug > 1)                   \
			bpf_printk(fmt, ##args); \
	} while (0)

// INVARIANTS:
// 	num_alive - num_asleep == num_ready <==> we can dispatch
// 	num_alive == num_total               ==> the job is ready for scheduling 
// 	num_alive == num_asleep              ==> the job is deadlocked 
// 	num_alive == 0                       ==> the job is finished 
struct sched_job {
	int num_total;  // NUMBER OF TOTAL TASKS EXPECTED TO BE CREATED
	int num_ready;  // NUMBER OF ENQUEUED TASKS THAT COULD BE DISPATCHED
	int num_asleep; // NUMBER OF TASKS THAT ARE ASLEEP 
	int num_alive;  // NUMBER OF TASKS THAT HAVE NOT YET EXITED
	u32 num_threads_created;
	u32 num_expected_events;
	u32 num_events;
	u32 iterations;
	u32 pct_strata;
	bool initialized_sched_algo;
	u64 state;
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct sched_job);
	__uint(max_entries, MAX_JOBS);
} sched_job_map SEC(".maps");

/* can't use percpu map due to bad lookups */
bool RESIZABLE_ARRAY(data, cpu_gimme_task);
u64 RESIZABLE_ARRAY(data, cpu_started_at);

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_THREADS);
} pid_to_det_id SEC(".maps");

struct dispatch_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct dispatch_timer);
} dispatch_timer SEC(".maps");

/*
 * Task context that is used to store the priority and enqueued status of
 * each task. These variables are protected by a spin lock to sieve out
 * concurrent updates.
 */
struct task_ctx {
	u32 priority;
	u32 eid; // id of executor
	u32 det_id;
	bool is_asleep;
	u64 next_event_addrs;
	bool is_write;
	u64 state;
	u64 last_enqueue_time;
	struct bpf_spin_lock lock;
};

/*
 * The map used to store the task context of each task. The key is the pid
 * of the task and the value is the task context.
 * 
 * This map is iterated in dispatch() to determine the total number of runnable
 * tasks, the number of enqueued tasks, and the highest priority task.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t); /* pid of the task */
	__type(value, struct task_ctx);
	__uint(max_entries, MAX_THREADS);
} task_ctx_map SEC(".maps");

/*
 * The queue is used to manage the dispatch ordering of task groups. Each 
 * task group represents a test case that originates from an executor identified by `eid`. 
 * 
 * `eid` are enqueued into this map using the `enqueue_eid_for_dispatch()` function when tasks are ready.
 * `eid` are dequeued using `dequeue_eid_for_dispatch()` to dispatch tasks from specific groups.
 *   in the group is dispatched.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 64);
	__type(value, u32);
} group_dispatch_queue SEC(".maps");

/*
 * The callback context used in dispatch() to store the highest priority task
 * and the number of enqueued tasks.
 */
struct tctx_callback_ctx {
	pid_t highest_priority_pid;
	u32 highest_priority;
	u32 eid;
};

static void enqueue_eid_for_dispatch(u32 eid, bool timeout) {
	struct sched_job *job = bpf_map_lookup_elem(&sched_job_map, &eid);
	if (!job)
		return;
	
	bpf_spin_lock(&job->lock);
	job->state = timeout ? JOB_TIMEOUT : JOB_RUNNING;
	bpf_spin_unlock(&job->lock);

	int status = bpf_map_push_elem(&group_dispatch_queue, &eid, BPF_EXIST);
	if (status < 0)
        dbg("[enqueue_eid_for_dispatch] Failed to update group_dispatch_queue");
}

static s32 dequeue_eid_for_dispatch() {
	u32 eid;
	if (bpf_map_pop_elem(&group_dispatch_queue, &eid) < 0) {
		// dbg("[dequeue_eid_for_dispatch] Failed to dequeue group_dispatch_queue");
		return -1;
	}
	return (s32)eid;
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
}

/*
 * Return true if the target task @p is a sched_ext task.
 */
static inline bool is_sched_ext(const struct task_struct *p)
{
	return p->policy == SCHED_EXT;
}

static u32 identify_group(const struct task_struct *p) {
	char comm[TASK_COMM_LEN] = {};
	u32 eid = 0;
	long status;

	status = bpf_probe_read_kernel(comm, sizeof(comm), p->comm);
	if (status) {
		dbg("[identify_group] error reading p->comm");
		return 0;
	}

	// comm: `syz-executor.X`
	if (comm[13] != '\0')
		eid = (u32)comm[13]-48;
	return eid;
}

static void update_priority(pid_t pid, s32 priority) {
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx) {
		dbg("[update_priority] task context not found");
		return;
	}

	bpf_spin_lock(&tctx->lock);
	tctx->priority = priority;
	bpf_spin_unlock(&tctx->lock);
}

#include "scx_scheduling_algorithms.c"

static struct sched_job* get_or_create_sched_job(u32 eid) {
    struct sched_job *job = bpf_map_lookup_elem(&sched_job_map, &eid);
    if (!job) {
        // Create a new scheduling job
        struct sched_job new_job = {
						.num_total = num_sched_thread,
            .num_alive = 0,
            .num_asleep = 0,
            .num_ready = 0,
            .num_events = 0,
	    .num_threads_created = 0,
            .iterations = 0,
            .pct_strata = 0,
            .num_expected_events = 0,
            .initialized_sched_algo = false,
						.state = JOB_UNAVAILABLE,
            .lock = {},
        };
        bpf_map_update_elem(&sched_job_map, &eid, &new_job, BPF_NOEXIST);
        job = bpf_map_lookup_elem(&sched_job_map, &eid);
        if (!job) {
            dbg("[handle_sched_ext] Failed to retrieve sched job for eid: %d", eid);
            return NULL;
        }
    }
    return job;
}

struct time_callback_ctx {
	u32 eid;
	u64 now;
};

static u64 update_last_enqueue_time(struct bpf_map *map, pid_t *pid,
				  struct task_ctx *tctx,
				  struct time_callback_ctx *tcallbackctx)
{
	bpf_spin_lock(&tctx->lock);
	if (tctx->state == THREAD_ENQUEUED && (tcallbackctx->eid == tctx->eid)) 
		tctx->last_enqueue_time = tcallbackctx->now;
	bpf_spin_unlock(&tctx->lock);
	return 0;
}

static void handle_sched_ext(struct task_struct *p)
{
    pid_t pid = p->pid;
    dbg("[handle_sched_ext] pid: %d", pid);
    u32 eid = identify_group(p);

	// Retrieve or create scheduling job
    struct sched_job *job = bpf_map_lookup_elem(&sched_job_map, &eid);
    if (!job || job->state == JOB_TIMEOUT) {
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
        return;
	}

    struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);

    // If we haven't already, initialize the scheduling algorithm
    bpf_spin_lock(&job->lock);
    if (!job->initialized_sched_algo && job->num_expected_events != 0) {
    	job->initialized_sched_algo = true;
	    bpf_spin_unlock(&job->lock);
			init_scheduling_algo(eid);
		} else {
	    bpf_spin_unlock(&job->lock);
    }

	if (!tctx) {
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
		return;
	}

  	u64 msg = 0;
  	u64 addr = 0;
  	int is_write = 0; // 1 true, 0 false
	long status = bpf_probe_read_kernel(&msg, sizeof(msg), &p->rt.timeout);
	status = status | bpf_probe_read_kernel(&addr, sizeof(addr), &p->rt.back);
	status = status | bpf_probe_read_kernel(&is_write, sizeof(is_write), &p->rt.time_slice);
	if (status != 0 || msg != 0xdeadbeef) {
		addr = 0;
		is_write = 0;
		warn("failed to read message from task_struct");
	}

    bpf_spin_lock(&tctx->lock);
    tctx->state = THREAD_ENQUEUED;
    tctx->is_write = (is_write != 0);
    tctx->next_event_addrs =  addr;
    bpf_spin_unlock(&tctx->lock);

	// Update timestamp
	struct time_callback_ctx tcallbackctx = {
		.eid = eid,
		.now = bpf_ktime_get_ns()
	};
	bpf_for_each_map_elem(&task_ctx_map, update_last_enqueue_time, &tcallbackctx, 0);

	bool all_tasks_ready = false;
	int num_ready, num_alive, num_total;
	u64 state;
    bpf_spin_lock(&job->lock);
    job->num_ready++;
    job->num_events += 1;
	if (job->state == JOB_READY || job->state == JOB_UNAVAILABLE)
		all_tasks_ready = job->num_ready == job->num_total;
	else if (job->state == JOB_RUNNING)
		all_tasks_ready = job->num_ready == job->num_alive - job->num_asleep;

	num_ready = job->num_ready;
	num_alive = job->num_alive;
	num_total = job->num_total;
	state = job->state;
    bpf_spin_unlock(&job->lock);

	dbg("[handle_sched_ext] eid: %d, state: %d, num_alive: %d, num_ready: %d, num total: %d", eid, state, num_alive, num_ready, num_total);

	update_priorities(pid, eid, !job->initialized_sched_algo);
    // If all tasks are ready, proceed to update priorities and enqueue for dispatch
    if (all_tasks_ready) {
        dbg("[handle_sched_ext] enqueueing eid: %d for dispatch", eid);
        enqueue_eid_for_dispatch(eid, false);
    }
}

/*
 * Task @p becomes ready to run. We update the task's priority and 
 * the task context to indicate that the task is enqueued.
 * 
 * - For tasks using the SCHED_EXT policy, it calls `handle_sched_ext()` 
 *   to manage the task’s scheduling process, including updating the task 
 *   context and managing task priorities.
 * - If the task does not use SCHED_EXT, it is dispatched immediately using 
 *   the default scheduling slice.
 */
void BPF_STRUCT_OPS(serialise_enqueue, struct task_struct *p, u64 enq_flags)
{
	/*
	 * Always dispatch per-CPU kthreads on the same CPU, bypassing our scheduler.
	 *
	 * In this way we can prioritize critical kernel threads that may
	 * potentially slow down the entire system if they are blocked for too
	 * long (i.e., ksoftirqd/N, rcuop/N, etc.).
	 */
	if (!is_sched_ext(p) || is_kthread(p)) {
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
		return;
	}

    handle_sched_ext(p);
}

/*
 * Task @p is being removed from the scheduler. We remove the task context
 * of the task from the task context map.
 */
void BPF_STRUCT_OPS(serialise_dequeue, struct task_struct *p, u64 deq_flags)
{
	if (!is_sched_ext(p))
		return;
	
	dbg("[dequeue] pid: %d, flag: %d", p->pid, deq_flags);
}

/*
 * Callback function used in dispatch() to iterate over the task context map
 * to determine the highest priority task and the number of enqueued tasks.
 */
static u64 get_highest_priority(struct bpf_map *map, pid_t *pid,
				  struct task_ctx *tctx,
				  struct tctx_callback_ctx *tcallbackctx)
{
	bpf_spin_lock(&tctx->lock);
	if (tctx->eid != tcallbackctx->eid | tctx->state == THREAD_RUNNING) {
		bpf_spin_unlock(&tctx->lock);
		return 0;
	}

	/* 
	* If two tasks have the same priority, the one that is stored 
	* first in the map will be dispatched first. Random Walk may
	* have this issue, but PCT should not have this issue.
	*/
	if (tctx->state == THREAD_TIMEOUT) {
		tcallbackctx->highest_priority_pid = *pid;
		bpf_spin_unlock(&tctx->lock);
		return 1;
	}

	if (tctx->priority >= tcallbackctx->highest_priority) {
		tcallbackctx->highest_priority = tctx->priority;
		tcallbackctx->highest_priority_pid = *pid;
	}
	bpf_spin_unlock(&tctx->lock);

	return 0;
}

/* 
 * Dispatch the highest priority thread in the process. Called when all
 * threads have been enqueued, or when a thread has yielded by dispatch()
 */
static void
dispatch_highest_priority_thread(struct tctx_callback_ctx *tcallbackctx)
{
	struct task_struct *highest_prio_p;
	pid_t dispatched_pid = tcallbackctx->highest_priority_pid;

	/* Get reference to highest priority task */
	highest_prio_p = bpf_task_from_pid(dispatched_pid);
	if (!highest_prio_p) {
		dbg("[dispatch] failed to get task_struct from pid: %d",
				dispatched_pid);
		return;
	}

	/* Update the task context map */
	struct task_ctx* tctx = bpf_map_lookup_elem(&task_ctx_map, &dispatched_pid);
	if (tctx) {
		bpf_spin_lock(&tctx->lock);
		tctx->state = THREAD_RUNNING;
		bpf_spin_unlock(&tctx->lock);
	}

	// dbg("[dispatch] dispatching pid: %d, with priority: %d\n",
		// dispatched_pid, tcallbackctx->highest_priority);

	/* Dispatch the task */
	scx_bpf_dispatch(highest_prio_p, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
				0);

	/* Clean up and release reference to the task */
	bpf_task_release(highest_prio_p);
}

/*
 * Dispatch the highest priority thread in the system. This function is called
 * very frequently by the kernel, so we should keep it as lightweight as possible.
 * 
 * - First, it dequeues the next `eid` (executor ID) from the `group_dispatch_queue`. It means tasks
 * 	 labeled with `eid` is under test and should be prioritized when dispatching tasks.
 * 
 * - It then iterates over all tasks in the `task_ctx_map` using `bpf_for_each_map_elem()` and 
 *   calls the `get_highest_priority` function to find the task with the highest priority within 
 *   the specified `eid` group. If iteration fails, a dbging is logged.
 * 
 * - Once the highest priority task is found, `dispatch_highest_priority_thread()` is called to 
 *   dispatch that task for execution on the specified CPU.
 */
void BPF_STRUCT_OPS(serialise_dispatch, s32 cpu, struct task_struct *p)
{
	s32 eid = dequeue_eid_for_dispatch();
	if (eid < 0)
		return;

	struct tctx_callback_ctx tcallbackctx = {
		.highest_priority_pid = -1,
		.highest_priority = 0,
		.eid = eid,
	};

	if (bpf_for_each_map_elem(&task_ctx_map, get_highest_priority, &tcallbackctx, 0) == -EINVAL) {
		dbg("[dispatch] failed to iterate over task_ctx_map");
		return;
	}

	if (tcallbackctx.highest_priority_pid == -1)
		return;

	dbg("[dispatch] highest pid: %d, priority: %d", tcallbackctx.highest_priority_pid, tcallbackctx.highest_priority);

	dispatch_highest_priority_thread(&tcallbackctx);

	struct sched_job *job = bpf_map_lookup_elem(&sched_job_map, &eid);
	if (!job) {
		dbg("[dispatch] job not found");
		return;
	}
	
	bpf_spin_lock(&job->lock);
	// there are some unknow racy conditions that may lead `num_alive` to negative.
	if (job->num_ready)
		job->num_ready--;
	bpf_spin_unlock(&job->lock);
	
	__sync_fetch_and_add(&nr_dispatch, 1);
}

void BPF_STRUCT_OPS(serialise_runnable, struct task_struct *p, u64 enq_flags)
{	
	if (!is_sched_ext(p))
		return;

	u32 eid = identify_group(p);

	// Retrieve or create scheduling job
  struct sched_job *job = bpf_map_lookup_elem(&sched_job_map, &eid);
  if (!job)
	  return;

  pid_t pid = p->pid;

  struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
  if (!tctx) {
  	return;
	}

	bpf_spin_lock(&tctx->lock);
  if (tctx->is_asleep) {
  	tctx->is_asleep = false;
  	job->num_asleep -= 1;
  }
	bpf_spin_unlock(&tctx->lock);

	dbg("[runnable] pid: %d", p->pid);
}

void BPF_STRUCT_OPS(serialise_running, struct task_struct *p)
{
	if (!is_sched_ext(p))
		return;

	dbg("[running] pid: %d", p->pid);
}

void BPF_STRUCT_OPS(serialise_stopping, struct task_struct *p, bool runnable)
{
	if (!is_sched_ext(p))
		return;

	dbg("[stopping] pid: %d", p->pid);
}

static void handle_sleep(struct task_struct *p)
{
	pid_t pid = p->pid;
	u32 eid = identify_group(p);
	struct sched_job *job = bpf_map_lookup_elem(&sched_job_map, &eid);
	if (!job) 
		return;

	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx)
		return;

	tctx->is_asleep = true;

	int num_alive, num_ready, num_total;
	u64 state;
	bpf_spin_lock(&job->lock);
	state = job->state;
	job->num_asleep += 1;
	num_total = job->num_total;
	num_alive = job->num_alive;
	num_ready = job->num_ready;
	bpf_spin_unlock(&job->lock);

	dbg("[handle_sleep] num_alive: %d (%d asleep), num_ready: %d, num total: %d", num_alive, job->num_asleep, num_ready, num_total);

	if (num_ready == num_alive - job->num_asleep && state == JOB_RUNNING) {
		dbg("[handle_sleep] enqueue_eid_for_dispatch");
		enqueue_eid_for_dispatch(eid, false);
	}
}

static void reset_job_state(struct sched_job *job)
{
	int num_events = 0;
	bpf_spin_lock(&job->lock);
	job->num_total = num_sched_thread;
	job->num_alive = 0;
	job->num_ready = 0;
	job->iterations = 0;
	job->num_threads_created = 0;
	job->pct_strata = 0;

	num_events = job->num_events;
	if (job->num_expected_events == 0) {
		job->num_expected_events = job->num_events;
	}

	job->num_events = 0;
	job->initialized_sched_algo = false;

	job->state = JOB_UNAVAILABLE;
	bpf_spin_unlock(&job->lock);
	dbg("[reset_job_state] finished job with %d events", num_events);
}

static void handle_exit(struct task_struct *p)
{
	pid_t pid = p->pid;
	u32 eid = identify_group(p);
	struct sched_job *job = bpf_map_lookup_elem(&sched_job_map, &eid);
	if (!job) 
		return;

	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx)
		return;

	int num_alive, num_ready, num_total;
	u64 state;
	bpf_spin_lock(&job->lock);
	state = job->state;
	if (state == JOB_READY || state == JOB_UNAVAILABLE)
		job->num_total--;
	job->num_alive--;
	num_total = job->num_total;
	num_alive = job->num_alive;
	num_ready = job->num_ready;
	bpf_spin_unlock(&job->lock);

	dbg("[handle_exit] num_alive: %d, num_ready: %d, num total: %d", num_alive, num_ready, num_total);

	// Delete task context
	if (bpf_map_delete_elem(&task_ctx_map, &pid) < 0)
		dbg("[handle_exit] failed to delete task context");

	// Enqueue for dispatch if conditions are met
	if (num_alive && num_alive == num_ready) {
		dbg("[handle_exit] enqueue_eid_for_dispatch");
		enqueue_eid_for_dispatch(eid, false);
	}

	// Handle job reset if no alive tasks remain
	if (!num_total || (!num_alive && state !=JOB_UNAVAILABLE)) {
		reset_job_state(job);
		__sync_fetch_and_add(&nr_jobs, 1);
		if (state == JOB_TIMEOUT)
			__sync_fetch_and_add(&nr_timeout, 1);
	}
}

/*
 * A task is becoming unavailable for scheduling. We remove the task context
 * of the task from the task context map. We do this also when the task calls
 * sleep(), since there is no guarantee when the task will wake up.
 * 
 * Note that once a (sleeping) task is ready to be called again, it will be
 * enqueued again, and its task context will be updated. This way, we will always 
 * get the most up-to-date number of tasks alive. 
 */
void BPF_STRUCT_OPS(serialise_quiescent, struct task_struct *p, u64 deq_flags)
{
	if (!is_sched_ext(p))
		return;

	dbg("[quiescent] pid: %d, deq_flags: %d", p->pid, deq_flags);

	switch (deq_flags)
	{
	case 25:
		handle_exit(p);
		break;
	case 9:	
		handle_sleep(p);
		break;
	default:
		break;
	}
	return;
}

/*
 * A task has yielded. Set the yield flag to true, and its time slice to 0.
 */
bool BPF_STRUCT_OPS(serialise_yield, struct task_struct *from,
		    struct task_struct *to)
{
	if (!is_sched_ext(from))
		return true;

	u32 eid = identify_group(from);
    struct sched_job *job = get_or_create_sched_job(eid);
    if (!job)
		return true;

	u64 state;
	int num_alive;
	bpf_spin_lock(&job->lock);
	state = job->state;
	num_alive = job->num_alive;
	bpf_spin_unlock(&job->lock);

	if (state == JOB_RUNNING && num_alive == 1)
		return false;

	/* Set slice to 0 so that dispatch() will be called when its timeslot is up */
	from->scx.slice = 0;
	pid_t pid = from->pid;

	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (tctx)
		return true;

	if (state != JOB_UNAVAILABLE) {
		dbg("[yield] pid %d come late, job %d is running", pid, eid);
		return true;
	}

	dbg("[yield] from: %d", from->pid);
	u32 pid32 = ((u32) pid);
	u32 *det_id = bpf_map_lookup_elem(&pid_to_det_id, &pid32);
	u32 det_id_val; 
	if (det_id) {
		det_id_val = *det_id;
	} else {
		bpf_spin_lock(&job->lock);
		job->num_threads_created += 1;
		det_id_val = job->num_threads_created;
		bpf_spin_unlock(&job->lock);
		bpf_map_update_elem(&pid_to_det_id, &pid, &det_id_val, BPF_NOEXIST);
	}
		
		

	// Create a new task context
	struct task_ctx new_ctx = {
		.priority = 0,
		.eid = eid,
		.det_id = det_id_val,
		.is_asleep = false,
		.is_write = false,
		.next_event_addrs = 0,
		.state = THREAD_RUNNING,
		.lock = {},
	};
	bpf_map_update_elem(&task_ctx_map, &pid, &new_ctx, BPF_NOEXIST);
	tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx) {
		dbg("[yield] Failed to insert task context for pid: %d", pid);
		return true;
	}

	bpf_spin_lock(&job->lock);
	job->num_alive++;
	if (job->num_alive == job->num_total)
		job->state = JOB_READY;
	bpf_spin_unlock(&job->lock);

	return true;
}

/*
 * A task is exiting. Update the statistics required for the scheduling algorithm.
 */
void BPF_STRUCT_OPS(serialise_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	if (!is_sched_ext(p))
		return;

	pid_t pid = p->pid;
	dbg("[exit_task] pid: %d", pid);
}

static bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static u64 dispatch_timeout(struct bpf_map *map, pid_t *pid,
				  struct task_ctx *tctx,
				  u64 *now)
{
	bpf_spin_lock(&tctx->lock);
	u64 state = tctx->state;
	u64 expire_at = tctx->last_enqueue_time+TIMEOUT_BUDGET;
	bpf_spin_unlock(&tctx->lock);
	if (state == THREAD_ENQUEUED && vtime_before(expire_at, *now)) {
		bpf_spin_lock(&tctx->lock);
		tctx->state = THREAD_TIMEOUT;
		bpf_spin_unlock(&tctx->lock);
		enqueue_eid_for_dispatch(tctx->eid, true);
		dbg("[dispatch_timeout] pid %d", *pid);
	}
	return 0;
}

static int dispatch_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = bpf_ktime_get_ns();
	bpf_for_each_map_elem(&task_ctx_map, dispatch_timeout, &now, 0);
	bpf_timer_start(timer, TIMER_INTERVAL_NS, BPF_F_TIMER_CPU_PIN);
	return 0;
}

/*
 * Initialize our scheduler
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(serialise_init)
{
	u32 key = 0;
	struct bpf_timer *timer;

	timer = bpf_map_lookup_elem(&dispatch_timer, &key);
	if (!timer)
		return -ESRCH;

	bpf_timer_init(timer, &dispatch_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, dispatch_timerfn);

	int ret = bpf_timer_start(timer, TIMER_INTERVAL_NS, BPF_F_TIMER_CPU_PIN);
	if (ret == -EINVAL) {
		timer_pinned = false;
		ret = bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
	}
	if (ret)
		scx_bpf_error("bpf_timer_start failed (%d)", ret);

	return 0;
}

/*
 * Unregister our scheduler
 */
void BPF_STRUCT_OPS(serialise_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Scheduling class declaration.
 */
SEC(".struct_ops.link")
struct sched_ext_ops serialise_ops = {
	.enqueue = (void *)serialise_enqueue,
	.dequeue = (void *)serialise_dequeue,
	.dispatch = (void *)serialise_dispatch,
	.runnable = (void *)serialise_runnable,
	.running = (void *)serialise_running,
	.stopping = (void *)serialise_stopping,
	.quiescent = (void *)serialise_quiescent,
	.yield = (void *)serialise_yield,
	.exit_task = (void *)serialise_exit_task,
	.init = (void *)serialise_init,
	.exit = (void *)serialise_exit,
	.flags = SCX_OPS_ENQ_LAST,
	.timeout_ms = 30000,
	.name = "serialise",
};
