
/*
 * Variables for PCT implementation
 *
 * The following variables are set in the corresponding C program
 * based on user-defined parameters.
 * 
 * @depth: the depth of the concurrency bug to find (i.e., the number of
 * 	   interleavings that would trigger the bug)
 * @use_pct: flag to indicate whether to use PCT
 */ 

const volatile u32 depth = 3;

u32 get_combined_key(u32 eid, u32 det_id) {
	return ((eid) << 16) | (det_id % MAX_THREADS);
}

u32 get_combined_changepoint_key(u32 eid, u32 change_point) {
	return ((eid) << 16) | (change_point);
}

/*
 * Map to store the pre-determined priorities for each thread.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_THREADS);
} pct_priorities SEC(".maps");


/* Swaps two elements in an array */
static inline void swap(u32 *a, u32 *b)
{
	u32 temp = *a;
	*a = *b;
	*b = temp;
}

/* Get strata base for PCT */
inline s32 get_strata_base(u32 strata)
{
	return S32_MAX - ((strata + 2) * MAX_THREADS);
}



/* 
 * Assign the priority for a thread based on the pre-determined priorities
 * in the pct_priorities map.
 * 
 * We use % MAX_THREADS to ensure that the index is within the range of the
 * map, and also allow for subsequent processes to get different priorities.
 */
s32 assign_pct_priority(u32 eid, u32 det_id)
{
	dbg("[pct] assign initial priority");
	u32 index = get_combined_key(eid, det_id);
	s32 *prio_value = bpf_map_lookup_elem(&pct_priorities, &index);
	if (prio_value)
		return *prio_value;

	return -1;
}


/*
 * Map to store the pre-determined change points for each iteration.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries,
	       MAX_THREADS); // should be depth - 1 tho, but this needs a constant
} pct_change_points SEC(".maps");


/* 
 * Shuffle the priorities in the pct_priorities map. This function is called
 * during init() of the scheduler, and after each iteration.
 */
static void shuffle_prios(u32 eid, u32 strata)
{
	u32 *prio_value, *value_i, *value_j;
	u32 index, i, actual_i, actual_j;

	/* Reset the priorities for the new iteration */
	bpf_for(i, depth, depth + MAX_THREADS)
	{
		index = get_combined_key(eid, i - depth);
		u32 val = get_strata_base(strata) + i; 
		bpf_map_update_elem(&pct_priorities, &index, &val, BPF_ANY);
	}

	/* Shuffle the resetted priorities using Fisher–Yates algorithm */
	bpf_for(i, 1, MAX_THREADS)
	{
		actual_i = get_combined_key(eid, MAX_THREADS - i);
		actual_j = get_combined_key(eid, bpf_get_prandom_u32() % actual_i);
		value_i = bpf_map_lookup_elem(&pct_priorities, &actual_i);
		value_j = bpf_map_lookup_elem(&pct_priorities, &actual_j);
		if (value_i && value_j) {
			swap(value_i, value_j);
		} else {
			warn("[shuffle_prios] failed to swap values at index: %d and %d\n",
			    actual_i, actual_j);
		}
	}
}

/*
 * Choose the change points for the next iteration. This function is called
 * during init() of the scheduler, and after each iteration.
 */
static void choose_change_points(u32 eid, u32 max_num_events)
{
	/* 
	 * This occurs in a multi-process environment, where the main threads
	 * of each process exit one after another, with no enqueue()s called
	 * in between.
	 */
	if (max_num_events == 0) {
		/*
		 * If no events have occurred for the prev iteration, we don't make
		 * any assumptions about num_events and set the change points to 1, 
		 * 2, ... for the next iteration. TODO: this may not be the best approach.
		 */
		u32 i, n = depth - 1;
		bpf_for(i, 0, n)
		{
			u32 change_point = i;
			u32 change_point_key = get_combined_changepoint_key(eid, i);
			long status = bpf_map_update_elem(
				&pct_change_points, &change_point_key, &change_point, BPF_ANY);
			if (status)
				warn("[choose_change_points] failed to update change_point[%d]: %d\n",
				     i, change_point);
		}
		return;
	}

	u32 i, n, change_point;
	long status;

	n = depth - 1;
	if (n > MAX_THREADS) {
		scx_bpf_error("[choose_change_points] n: %d, MAX_THREADS: %d\n",
			      n, MAX_THREADS);
		return;
	}

	bpf_for(i, 0, n)
	{
		/* NOTE: THERE MAY BE DUPLICATE CHANGE POINTS */
		change_point = (bpf_get_prandom_u32() % max_num_events) +
			       1; // [1, max_num_events]
		u32 change_point_key = get_combined_changepoint_key(eid, i);
		status = bpf_map_update_elem(&pct_change_points, &change_point_key,
					     &change_point, BPF_ANY);
		if (status)
			warn("[choose_change_points] failed to update change_point[%d]: %d\n",
			     i, change_point);

		dbg("[choose_change_points] change_point[%d]: %d\n", i,
		    change_point);
	}
}

s32 init_pct(u32 eid) {
	/* Initialise PCT variables */

	struct sched_job* job = bpf_map_lookup_elem(&sched_job_map, &eid);
	if (!job) {
		bpf_printk("[pct-init] job not found\n");
		return -1;
	}

	dbg("[init] depth: %d\n", depth);
	shuffle_prios(eid, job->pct_strata);
	choose_change_points(eid, job->num_expected_events);
	return 0;
}

static s32 update_priorities_pct(u32 eid, pid_t pid) {
	s32 priority = -1;
	/* 
	 * For PCT, check if a change_point is incurred. If so, update the
	 * priority of the task.
	 */
	u32 n = depth - 1, i;

	struct sched_job* job = bpf_map_lookup_elem(&sched_job_map, &eid);
	if (!job) {
		bpf_printk("[pct-init] job not found\n");
		return -1;
	}

	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx) {
		dbg("[update_pct_priority] task context not found");
		return -1;
	}

	if (n > MAX_THREADS) {
		bpf_printk("[enqueue] n: %d, MAX_THREADS: %d\n", n,
			   MAX_THREADS);
		return -1;
	}

	bpf_spin_lock(&job->lock);
	u32 num_events = job->num_events;
	u32 max_num_events = job->num_expected_events;
	u32 strata = job->pct_strata;
	bpf_spin_unlock(&job->lock);

	bpf_for(i, 0, n)
	{
		u32 change_point_key = get_combined_changepoint_key(eid, i);
		u32 *change_point = bpf_map_lookup_elem(&pct_change_points, &change_point_key);
		if (change_point) {
			// dbg("[enqueue] %d until change \n",
			//     *change_point - (num_events %
			// 		     num_events));
			if ((num_events % max_num_events) ==
			    *change_point) {
				// If we have observed more events than expected, resume PCT with a
				// new "strata" -- this allows for threads set to low priority to recover
				if (num_events >
				    num_events * (strata + 1)) {
					strata += 1;
					dbg("[enqueue] NEW STRATA %d\n",
					    strata);
				}

				priority = get_strata_base(strata) + i + 1;
				update_priority(pid, priority);
				dbg("[enqueue] UPDATE pid: %d, priority: %d\n",
				    pid, priority);
				break;
			}
		} else if (tctx->priority == 0) {
			tctx->priority = assign_pct_priority(eid, tctx->det_id);
		}
	}
	return 0;
}
