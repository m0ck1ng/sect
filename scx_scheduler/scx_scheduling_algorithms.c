
/* The following variables are set by the BPF program.
 * 
 * @iterations: the number of times the main thread has exited
 * @max_num_events: the maximum number of enqueue()s that have occurred
 * 		over one iteration. 
 * @num_events: the number of enqueue()s that have occurred
 */

u32 iterations, initial_max_num_events, task_count, max_num_events,
	num_events;

#include "pct.c"
#include "random-walk.c"
#include "random-priority.c"

s32 update_priorities(pid_t pid, u32 eid, bool initial_run) {
	if (use_random_walk || (initial_run && use_pct)) {
		update_priorities_rw(eid);			
	} else if (use_random_priority_walk && pid > 0) {
		update_priorities_rp(pid);
	} else if (use_pct) {
		update_priorities_pct(pid);
	} else {
		return -1;
	}

	return 0;
}

int init_scheduling_algo(u32 eid) {
	if (use_random_walk) {
		return init_rw();			
	} else if (use_random_priority_walk) {
		return init_rp();
	} else if (use_pct) {
		return init_pct(eid);
	} else {
		return -1;
	}
}
