#include <bpf/bpf.h>
#include <errno.h>
#include <libgen.h>
#include <sched.h>
#include <scx/common.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#include "scx_serialise.bpf.skel.h"

#define USER_MAX_CYCLE_THREADS 200

/*
 * Algorithm values for -r (must match enum sched_algo in scx_algo.bpf.h):
 *   1 = ALGO_RP  (Random Priority)
 *   2 = ALGO_RW  (Random Walk)
 *   3 = ALGO_PCT (Probabilistic Concurrency Testing, default)
 *   4 = ALGO_POS (Priority-based OS scheduling)
 */
enum sched_algo {
	ALGO_PCT = 0,
	ALGO_POS = 1,
	ALGO_RW  = 2,
	ALGO_RP  = 3,
};

const char help_fmt[] =
	"A scheduler to serialise the thread schedules of a process.\n"
	"\n"
	"Usage: %s [-n NUM_THREADS] [-d DEPTH] [-r ALGO]\n"
	"\n"
	"  -n NUM   Threads expected in each syz-executor cycle (default: 2).\n"
	"  -d DEPTH PCT search depth (default: 3).\n"
	"  -r ALGO  Scheduling algorithm:\n"
	"             1 = Random Priority\n"
	"             2 = Random Walk\n"
	"             3 = PCT (default)\n"
	"             4 = POS\n"
	"  -h       Display this help and exit.\n";

static volatile int exit_req;

static void sigint_handler(int simple)
{
	exit_req = 1;
}

static void print_stats(struct scx_serialise *skel)
{
	printf("cycles:%10" PRIu64 "  dispatch:%10" PRIu64
	       "  timeout:%10" PRIu64
	       "  empty:%10" PRIu64 "  push_fail:%10" PRIu64
	       "  late:%10" PRIu64 "  ignored:%10" PRIu64 "\n",
	       skel->bss->nr_cycles,
	       skel->bss->nr_dispatch,
	       skel->bss->nr_timeout,
	       skel->bss->nr_dispatch_empty,
	       skel->bss->nr_dispatch_enqueue_failed,
	       skel->bss->nr_late_join,
	       skel->bss->nr_ignored_enqueue);
	fflush(stdout);
}

static unsigned long parse_ulong_arg(const char *opt, const char *arg)
{
	char *end = NULL;
	unsigned long val;

	errno = 0;
	val = strtoul(arg, &end, 10);
	SCX_BUG_ON(errno || !end || *end != '\0',
		   "Invalid %s value: %s", opt, arg);
	return val;
}

int main(int argc, char **argv)
{
	struct scx_serialise *skel;
	struct bpf_link *link;
	int opt;
	unsigned long cycle_thread_count = 2;
	unsigned long depth = 3;
	enum sched_algo sched_algorithm = ALGO_PCT;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	while ((opt = getopt(argc, argv, "n:d:hr:")) != -1) {
		switch (opt) {
		case 'n': {
			unsigned long v = parse_ulong_arg("-n", optarg);
			SCX_BUG_ON(v < 1 || v > USER_MAX_CYCLE_THREADS,
				   "-n must be in [1, %d]", USER_MAX_CYCLE_THREADS);
			cycle_thread_count = v;
			break;
		}
		case 'd': {
			unsigned long v = parse_ulong_arg("-d", optarg);
			SCX_BUG_ON(v < 1 || v > USER_MAX_CYCLE_THREADS + 1,
				   "-d must be in [1, %d]", USER_MAX_CYCLE_THREADS + 1);
			depth = v;
			break;
		}
		case 'r': {
			unsigned long v = parse_ulong_arg("-r", optarg);
			switch (v) {
			case 1:
				printf("using strategy: random priority\n");
				sched_algorithm = ALGO_RP;
				break;
			case 2:
				printf("using strategy: random walk\n");
				sched_algorithm = ALGO_RW;
				break;
			case 3:
				printf("using strategy: pct\n");
				sched_algorithm = ALGO_PCT;
				break;
			case 4:
				printf("using strategy: pos\n");
				sched_algorithm = ALGO_POS;
				break;
			default:
				SCX_BUG_ON(1, "Invalid -r value (1=RP, 2=RW, 3=PCT, 4=POS)");
			}
			break;
		}
		case 'h':
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_BUG_ON(cycle_thread_count < 1 ||
		   cycle_thread_count > USER_MAX_CYCLE_THREADS,
		   "-n must be in [1, %d]", USER_MAX_CYCLE_THREADS);
	SCX_BUG_ON(depth < 1 ||
		   depth > USER_MAX_CYCLE_THREADS + 1,
		   "-d must be in [1, %d]", USER_MAX_CYCLE_THREADS + 1);

	skel = SCX_OPS_OPEN(serialise_ops, scx_serialise);
	SCX_BUG_ON(!skel, "Failed to open skel");

	skel->rodata->cycle_thread_count = cycle_thread_count;
	skel->rodata->depth = depth;
	skel->rodata->sched_algorithm = sched_algorithm;

	SCX_OPS_LOAD(skel, serialise_ops, scx_serialise, uei);
	link = SCX_OPS_ATTACH(skel, serialise_ops, scx_serialise);

	if (!skel->data->timer_pinned)
		printf("WARNING: BPF_F_TIMER_CPU_PIN not available, timer not pinned\n");

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		print_stats(skel);
		sleep(10);
	}

	print_stats(skel);
	bpf_link__destroy(link);
	UEI_REPORT(skel, uei);
	scx_serialise__destroy(skel);
	return 0;
}
