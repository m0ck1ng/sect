#include <bpf/bpf.h>
#include <libgen.h>
#include <sched.h>
#include <scx/common.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#include "scx_serialise.bpf.skel.h"

const char help_fmt[] =
	"A scheduler to serialise the thread schedules of a process.\n"
	"\n"
	"See the top-level comment in .bpf.c for more details.\n"
	"\n"
	"Usage: %s [-s NUM_SCHED_TASK] [-s SEED] [-d DEPTH]\n"
	"\n"
	"  -n            Enter number of tasks involved in scheduling.\n"
	"  -s            Enter seed for the RNG. Default: 0xdeadbeef.\n"
	"  -d            Enter depth of bug to search for. Default: 3.\n"
	"  -h            Display this help and exit\n"
	"  -r            (PCT disabled) 1 for random priority walk, 2 for random walk 2, Default: 2. \n";

static volatile int exit_req;

static void sigint_handler(int simple)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_serialise *skel;
	struct bpf_link *link;
	u32 opt;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	skel = SCX_OPS_OPEN(serialise_ops, scx_serialise);
	SCX_BUG_ON(!skel, "Failed to open skel");

	while ((opt = getopt(argc, argv, "n:d:hr:")) != -1) {
		switch (opt) {
		case 'n':
			skel->rodata->num_sched_thread = strtoul(optarg, NULL, 10);
			break;
		case 'r':
			unsigned long v = strtoul(optarg, NULL, 10);
			if (v) {
				printf("use random walk: %lu\n", v);
				skel->rodata->use_pct = 0;

				if (v == 1) {
					skel->rodata->use_random_priority_walk = 1;
					skel->rodata->use_random_walk = 0;
				} else if (v == 2) {
					skel->rodata->use_random_priority_walk = 0;
					skel->rodata->use_random_walk = 1;
				} else {
					SCX_BUG_ON(1, "Invalid option for -r");
				}
			}
			break;
		case 'h':
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, serialise_ops, scx_serialise, uei);
	link = SCX_OPS_ATTACH(skel, serialise_ops, scx_serialise);

	if (!skel->data->timer_pinned)
		printf("WARNING : BPF_F_TIMER_CPU_PIN not available, timer not pinned to central\n");
	
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		printf("job   :%10" PRIu64 "    dispatch:%10" PRIu64 "   timeout:%10" PRIu64 "\n",
		       skel->bss->nr_jobs,
		       skel->bss->nr_dispatch,
		       skel->bss->nr_timeout);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	UEI_REPORT(skel, uei);
	scx_serialise__destroy(skel);
	return 0;
}
