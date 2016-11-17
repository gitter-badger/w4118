/*
 *  Copyright (C) 2016 Columbia University
 *
 *  Author: W4118 staff <w4118@lists.cs.columbia.edu>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 *
 *  OS w4118 fall 2016 Binder solution.
 */
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/ipc_rec.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/binder_stats.h>
#include <linux/uaccess.h>

SYSCALL_DEFINE2(binder_rec, pid_t, pid, int, state)
{
	struct task_struct *tsk = NULL;
	struct binder_trans_log *log;
	struct binder_trans_proc *proc, *ps;
	int old_state;
	int err = 0;

	if (pid < 0)
		return -EINVAL;

	if (state < 0 || state > 1)
		return -EINVAL;

	/* We need to take the rcu_read_lock since, it's required by
	 * find_task_by_vpid - otherwise the task struct may be freed from under
	 * us
	 */
	rcu_read_lock();
	tsk = (pid == 0) ? current : find_task_by_vpid(pid);
	if (!tsk) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(tsk);
	spin_lock(&tsk->binder_log_lock);
	rcu_read_unlock();

	old_state = tsk->ipc_recording;
	tsk->ipc_recording = state;

	/* When recording is cleared we reset counters and free data */
	if (!state && old_state) {
		log = &tsk->binder_log;
		log->data_size = 0;
		log->nr_trans = 0;
		log->nr_peers = 0;
		list_for_each_entry_safe(proc, ps, &log->procs_list, list) {
			list_del(&proc->list);
			kfree(proc);
		}
	}
	spin_unlock(&tsk->binder_log_lock);
	put_task_struct(tsk);
	return err;
}

static int acquire_task_locks(pid_t pid)
{
	/* We need to take the rcu_read_lock since, it's required by
	 * find_task_by_vpid - otherwise the task struct may be freed from under
	 * us
	 */
	struct task_struct *tsk;

	rcu_read_lock();
	tsk = (pid == 0) ? current : find_task_by_vpid(pid);
	if (!tsk) {
		rcu_read_unlock();
		return -ESRCH;
	}

	spin_lock(&tsk->binder_log_lock);
	if (!tsk->ipc_recording) {
		spin_unlock(&tsk->binder_log_lock);
		rcu_read_unlock();
		return -ESRCH;
	}
	return 0;
}

static void release_task_locks(struct task_struct *tsk)
{
	/* Guaranteed to succeed */
	spin_unlock(&tsk->binder_log_lock);
	rcu_read_unlock();
}

static void fill_binder_peer(void *dst, struct binder_trans_proc *src)
{
	struct binder_peer peer;

	peer.uid = src->uid;
	peer.pid = src->pid;
	memcpy(&peer.comm, src->comm, sizeof(src->comm));
	memcpy(dst, &peer, sizeof(struct binder_peer));
}

SYSCALL_DEFINE4(binder_stats, pid_t, pid, struct binder_stats __user *, ustats,
		void __user *, buf, size_t __user *, usize)
{
	struct task_struct *tsk = NULL;
	struct binder_stats stats;
	struct binder_trans_proc *proc;
	int kbuf_nr_peers = 0;
	int kbuf_size = 0;
	void *kbuf_peers = NULL;
	size_t size, koffset;
	int nr_peers;
	int err = 0;

	if (pid < 0)
		return -EINVAL;
	if (get_user(size, usize))
		return -EFAULT;
	if (size < sizeof(struct binder_peer))
		return -EINVAL;
	if (buf == NULL)
		return -EINVAL;

	/* First pass, we have to figure out how many peers we have
	 * so we can allocate a kernel buffer big enough to store peers
	 * the alternative would be to allocate a buffer usize big
	 * but a malicious task could crash the kernel by requesting
	 * too much
	 */
	err = acquire_task_locks(pid);
	if (err)
		return err;

	tsk = (pid == 0) ? current : find_task_by_vpid(pid);
	get_task_struct(tsk);
	kbuf_nr_peers = tsk->binder_log.nr_peers;
	release_task_locks(tsk);

	kbuf_peers = kmalloc(
		sizeof(struct binder_peer)*kbuf_nr_peers, GFP_KERNEL);
	if (!kbuf_peers)
	{
		err = -ENOMEM;
		goto free_kbuf_out;
	}
	kbuf_size = sizeof(struct binder_peer)*kbuf_nr_peers;

	/* Second pass, we have memory (hooray), do the copy into kbuf_peers */
	err = acquire_task_locks(pid);
	if (err)
		goto free_kbuf_out;

	/* First, let's return the aggregate data */
	stats.nr_trans = tsk->binder_log.nr_trans;
	stats.bytes = tsk->binder_log.data_size;
	get_task_comm(stats.comm, tsk);

	/* Then we handle all the Binder peers */
	nr_peers = 0;
	koffset = 0;
	list_for_each_entry(proc, &tsk->binder_log.procs_list, list) {
		nr_peers++;
		if (nr_peers > kbuf_nr_peers)
			continue;

		fill_binder_peer(kbuf_peers + koffset, proc);
		koffset += sizeof(struct binder_peer);
	}

	/* phew, that was messy. now let's unlock everything and start
	 * copying to user.
	 */
	release_task_locks(tsk);

	size = size > kbuf_size ?
		kbuf_size :
		(size/sizeof(struct binder_peer))*sizeof(struct binder_peer);

	if (copy_to_user(buf, kbuf_peers, size)) {
		err = -EFAULT;
		goto free_kbuf_out;
	}
	/* Return the number of bytes written to buf */
	if (put_user(size, usize)) {
		err = -EFAULT;
		goto free_kbuf_out;
	}

	if (copy_to_user(ustats, &stats, sizeof(stats))) {
		err = -EFAULT;
		goto free_kbuf_out;
	}

	err = nr_peers;

free_kbuf_out:
	put_task_struct(tsk);
	kfree(kbuf_peers);
	return err;
}
