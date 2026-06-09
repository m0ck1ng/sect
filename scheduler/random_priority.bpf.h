#ifndef __RANDOM_PRIORITY_BPF_H
#define __RANDOM_PRIORITY_BPF_H

/*
 * Random Priority algorithm: assign each enqueueing task a fresh
 * uniformly-random priority in [1, 50].
 */

static __always_inline int update_priorities_rp(pid_t pid)
{
	u32 priority = bpf_get_prandom_u32() % 50 + 1;
	dbg("[update_priorities_rp] prio new %d", priority);
	update_priority(pid, priority);
	return 0;
}

static __always_inline s32 init_rp(void)
{
	return 0;
}

#endif /* __RANDOM_PRIORITY_BPF_H */
