/*
 *  Copyright (C) 2016 Columbia University
 *
 *  Author: W4118 Staff <w4118@lists.cs.columbia.edu>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 *
 *  OS w4118 fall 2016 IPC stats recording functionality.
 */
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/ipc_rec.h>
#include <linux/binder_stats.h>

DEFINE_MUTEX(ipc_rec_lock);

void free_tsk_ipc_rec(struct task_struct *tsk)
{
	struct binder_trans_proc *proc, *ps;

	spin_lock(&tsk->binder_log_lock);
	tsk->ipc_recording = false;

	/* It's safe to do this since we know that no-one else will be
	 * referencing this data at this point
	 */
	list_for_each_entry_safe(proc, ps, &tsk->binder_log.procs_list, list) {
		list_del(&proc->list);
		kfree(proc);
	}
	spin_unlock(&tsk->binder_log_lock);
}

static int binder_log_add_proc(struct binder_trans_log *log,
	struct task_struct *peer, struct binder_trans_proc *peer_entry)
{
	peer_entry->pid = task_pid_nr(peer);
	peer_entry->uid = peer->cred->uid;
	get_task_comm(peer_entry->comm, peer);
	list_add_tail(&peer_entry->list, &log->procs_list);

	return 0;
}

static inline struct task_struct * get_task(pid_t pid)
{
	struct task_struct *tsk;

	tsk = find_task_by_vpid(pid);
	return tsk;
}

static inline void add_peer(struct task_struct *curr,
	struct task_struct *peer, struct binder_trans_proc *peer_entry)
{
	struct binder_trans_log *log;
	struct binder_trans_proc *proc;

	bool is_new = true;

	if (!peer) {
		kfree(peer_entry);
		return;
	}

	log = &curr->binder_log;
	list_for_each_entry(proc, &log->procs_list, list) {
		if (proc->pid == task_pid_nr(peer))
			is_new = false;
	}

	/* Add the proc if it wasn't already there */
	if (is_new) {
		binder_log_add_proc(log, peer, peer_entry);
		curr->binder_log.nr_peers = curr->binder_log.nr_peers + 1;
	} else
		kfree(peer_entry);
}

void binder_trans_notify(int from_proc, int to_proc, int data_size)
{
	struct task_struct *to_task, *from_task;
	struct binder_trans_proc *to_peer = NULL, *from_peer = NULL;

	/* Pragmatically allocate memory since once we start
	 * locking we won't have the ability to kmalloc
	 */
	to_peer = kmalloc(sizeof(struct binder_trans_proc), GFP_KERNEL);
	if (!to_peer)
		goto out;
	from_peer = kmalloc(sizeof(struct binder_trans_proc), GFP_KERNEL);
	if (!from_peer)
		goto out;

	rcu_read_lock();
	from_task = get_task(from_proc);
	to_task = get_task(to_proc);

	if (from_task) {
		spin_lock(&from_task->binder_log_lock);
		if (from_task->ipc_recording) {
			from_task->binder_log.nr_trans++;
			from_task->binder_log.data_size += data_size;
			add_peer(from_task, to_task, from_peer);
			/* Memory consumed by add_peer */
			from_peer = NULL;
		}
		spin_unlock(&from_task->binder_log_lock);
	}
	if (to_task) {
		spin_lock(&to_task->binder_log_lock);
		if (to_task->ipc_recording) {
			add_peer(to_task, from_task, to_peer);
			/* Memory consumed by add_peer */
			to_peer = NULL;
		}
		spin_unlock(&to_task->binder_log_lock);
	}
	rcu_read_unlock();

out:
	kfree(from_peer);
	kfree(to_peer);
}
