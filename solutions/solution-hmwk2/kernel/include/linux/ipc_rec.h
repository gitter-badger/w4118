#ifndef _LINUX_IPC_REC_H
#define _LINUX_IPC_REC_H
/*
 * All sorts of IPC subsystems could have their hooks here, which would be
 * called on every instance of every IPC mechanism.
 *
 * For the Fall 2016 w4118 course we only focus on Binder IPC.
 */

#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/list.h>

extern struct mutex ipc_rec_lock;

struct binder_trans_proc {
	pid_t uid;
	uid_t pid;
	char comm[16];
	struct list_head list;
};

struct binder_trans_log {
	int data_size;
	unsigned long nr_trans;
	int nr_peers;
	struct list_head procs_list;
};


void binder_trans_notify(int from_proc, int to_proc, int data_size);
int get_binder_trans_log(void *buf, size_t *size);
void free_tsk_ipc_rec(struct task_struct *tsk);

#endif /* _LINUX_IPC_REC_H */
