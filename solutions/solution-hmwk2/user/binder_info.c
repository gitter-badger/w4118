#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/syscall.h>
#include <errno.h>

#define __NR_binder_rec		244
#define __NR_binder_stats	245

#define BUFFER_SIZE	4096

struct binder_peer {
	uid_t uid;		/* UID of the communicating process */
	pid_t pid;		/* PID of the communicating process */
	char comm[16];		/* Name of communicating process */
};

struct binder_stats {
	char comm[16];		/* Name of recorded process */
	unsigned int nr_trans;	/* Total number of Binder transactions */
	unsigned int bytes;	/* Total number of bytes transferred */
};

static long sys_binder_rec(pid_t pid, int state)
{
	return syscall(__NR_binder_rec, pid, state);
}

static long sys_binder_stats(pid_t pid, struct binder_stats *stats,
			     void *buf, size_t *size)
{
	return syscall(__NR_binder_stats, pid, stats, buf, size);
}

static int do_binder_rec_state(int argc, char **argv, int state)
{
	unsigned int i;
	pid_t pid;
	int err;

	for (i = 0; i < argc; i++) {
		pid = (pid_t)atoi(argv[i]);
		err = sys_binder_rec(pid, state);
		if (err < 0) {
			fprintf(stderr, "Error processing pid %u: %s\n",
					pid, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

static int start_rec(int argc, char **argv)
{
	return do_binder_rec_state(argc, argv, 1);
}

static int stop_rec(int argc, char **argv)
{
	return do_binder_rec_state(argc, argv, 0);
}

static void print_peers(struct binder_peer *peer, size_t nr_peers,
			long total_peers)
{
	unsigned int i;

	for (i = 0; i < nr_peers; i++) {
		printf("\t\t%s\t%u\t%u\n", peer->comm, peer->pid, peer->uid);
		peer++;
	}
	if (nr_peers < total_peers)
		printf("\t\t... (%ld more peers)\n", total_peers - nr_peers);
}

static int print_rec(int argc, char **argv)
{
	struct binder_stats stats;
	char buffer[BUFFER_SIZE];
	size_t size;
	unsigned int i;
	pid_t pid;
	int err;

	for (i = 0; i < argc; i++) {
		size = BUFFER_SIZE;
		pid = (pid_t)atoi(argv[i]);
		err = sys_binder_stats(pid, &stats, buffer, &size);
		if (err < 0) {
			fprintf(stderr, "Error processing pid %u: %s\n",
					pid, strerror(errno));
			return EXIT_FAILURE;
		} else {
			printf("%s (%u):\t%u bytes\t%u transactions\n",
				stats.comm, pid, stats.bytes, stats.nr_trans);
			print_peers((struct binder_peer *)buffer,
				    size / sizeof(struct binder_peer),
				    err);
			printf("\n");
		}
	}

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		printf("Usage: %s (start|stop|print) pid0 [pid1 [...]]\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	if (strcmp(argv[1], "start") == 0)
		return start_rec(argc - 2, argv + 2);

	if (strcmp(argv[1], "stop") == 0)
		return stop_rec(argc - 2, argv + 2);

	if (strcmp(argv[1], "print") == 0)
		return print_rec(argc - 2, argv + 2);

	fprintf(stderr, "Invalid command '%s', exiting\n", argv[1]);
	return EXIT_FAILURE;
}
