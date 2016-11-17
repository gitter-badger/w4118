#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#define __NR_get_wrr_info 244
#define MAX_CPUS 8

struct wrr_info {
	int num_cpus;
	int nr_running[MAX_CPUS];
	int total_weight[MAX_CPUS];
};

int main(void)
{
	for (;;) {
		struct wrr_info user_wrr_info;
		int ret_val = 0;
		int i = 0;

		ret_val = syscall(__NR_get_wrr_info, &user_wrr_info);
		if (ret_val < 0) {
			printf("Error %d\n", errno);
			return 1;
		}

		for (i = 0; i < ret_val; i++)
			printf("%d %d\t", user_wrr_info.nr_running[i],
					user_wrr_info.total_weight[i]);
		printf("\n");

		usleep(100000);
	}

	return 0;
}
