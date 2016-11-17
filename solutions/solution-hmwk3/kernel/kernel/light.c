/*
 *	COMS W4118 Fall 2016
 *	Homework 3 Solution
 *
 *	Bo Gan <gan.bo@columbia.edu>
 */

#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/light.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/compiler.h>

/*#pragma GCC push_options
#pragma GCC optimize ("O0")*/

/*static void delay(unsigned long cycle)
{
	int f = 0;
	while (cycle-- && !ACCESS_ONCE(f))
		;
}*/

static void schedule_delay(void)
{
	schedule();
	/* delay(0x100000000ULL); */
}
#define schedule schedule_delay

static struct light_intensity k_intensity = {
	.cur_intensity = 0,
};

static struct {
	spinlock_t lock;
	unsigned long count;
	int window[WINDOW];
} k_intensity_window = {
	.lock = __SPIN_LOCK_UNLOCKED(k_intensity_window.lock),
	.count = 0,
	.window = {0},
};

static struct {
	rwlock_t lock;
	int next;
	struct list_head list;
} k_light_events = {
	.lock = __RW_LOCK_UNLOCKED(k_light_events.lock),
	.next = 0,
	.list = LIST_HEAD_INIT(k_light_events.list),
};

SYSCALL_DEFINE1(set_light_intensity, struct light_intensity __user *,
		user_light_intensity)
{
	struct light_intensity k_li;

	if (current_uid())
		return -EACCES;

	if (copy_from_user(&k_li, user_light_intensity, sizeof(k_li)))
		return -EFAULT;

	ACCESS_ONCE(k_intensity) = k_li;

	return 0;
}

SYSCALL_DEFINE1(get_light_intensity, struct light_intensity __user *,
		user_light_intensity)
{
	struct light_intensity k_li;

	k_li = ACCESS_ONCE(k_intensity);

	if (copy_to_user(user_light_intensity, &k_li, sizeof(k_li)))
		return -EFAULT;

	return 0;
}

SYSCALL_DEFINE1(light_evt_create, struct event_requirements __user *,
		intensity_params)
{
	struct light_event *new_event = NULL;
	int id;
	long err = 0;

	/* zero initialize the new event */
	new_event = kcalloc(1, sizeof(*new_event), GFP_KERNEL);

	if (new_event == NULL) {
		err = -ENOMEM;
		goto out;
	}

	if (copy_from_user(&new_event->params, intensity_params,
		sizeof(struct event_requirements))) {
		err = -EFAULT;
		goto fault;
	}

	if (new_event->params.frequency > WINDOW)
		new_event->params.frequency = WINDOW;

	/* initialize */
	INIT_LIST_HEAD(&new_event->list);
	init_waitqueue_head(&new_event->waitq);

	write_lock(&k_light_events.lock);
	/*
	 * XXX: A hack to generate next event id.
	 *
	 * k_light_events.next will overflow eventually.
	 * You may refer to the way linux allocate 
	 * file descriptors for a good design.
	 */
	id = new_event->id = k_light_events.next++;
	list_add(&new_event->list, &k_light_events.list);
	write_unlock(&k_light_events.lock);

	return id;
fault:
	kfree(new_event);
out:
	return err;
}

SYSCALL_DEFINE1(light_evt_wait, int, event_id)
{
	struct light_event *event;
	/* ts_old: old timestamp, ts_new: new timestamp */
	long err = 0, ts_old, ts_new;
	unsigned refcnt;

	/* lock section to find event */
	read_lock(&k_light_events.lock);
	list_for_each_entry(event, &k_light_events.list, list) {
		if (event->id == event_id) {
			/*
			 * increase the refcnt
			 * races with the atomic_dec below but there is no
			 * race with evt_destory since evt_destroy would
			 * have already remove the signal event and we
			 * should not be able to find it.
			 */
			atomic_inc(&event->refcnt);
			break;
		}
	}
	read_unlock(&k_light_events.lock);

	if (&event->list == &k_light_events.list)
		return -EINVAL;

	/* delay(0x100000000ULL); */

	/* lock section to wait for event */
	spin_lock(&event->waitq.lock);
	ts_new = ts_old = event->timestamp;
	if (ts_new >= 0) {
		/* Since the waitq lock is held, we call the locked version */
		err = wait_event_interruptible_locked(event->waitq,
			(ts_new = event->timestamp) != ts_old);
		/*
		 * The above statement is nothing but:
		 *
		 * DEFINE_WAIT(wait);
		 * err = 0;
		 * do {
		 *	if (list_empty(&wait.task_list))
		 *		__add_wait_queue_tail(&event->waitq, &wait);
		 *	set_current_state(TASK_INTERRUPTIBLE);
		 *	if (signal_pending(current)) {
		 *		err = -ERESTARTSYS;
		 *		break;
		 *	}
		 *	spin_unlock(&event->waitq.lock);
		 *	schedule();
		 *	spin_lock(&event->waitq.lock);
		 * } while((ts_new = event->timestamp) == ts_old);
		 * __remove_wait_queue(&event->waitq, &wait);
		 * __set_current_state(TASK_RUNNING);
		 *
		 */
	}
	/*
	 * Drop the refcnt before release the lock. If we drop refcnt
	 * after spin_unlock, memory leak happens when evt_destroy kicks
	 * in right after spin_unlock, and right before we do atomic_dec.
	 * In this case evt_destroy will not kfree and we will not kfree.
	 * It is still safe since we are holding the spin lock.
	 * evt_destroy would be waiting for spin lock at this time.
	 *
	 * races with the atomic_inc above but there is no race
	 * with evt_destory since we hold the waitq spinlock.
	*/
	refcnt = atomic_dec_return(&event->refcnt);
	spin_unlock(&event->waitq.lock);
/*
 * All possible combinations:
 * ---------------------------------------------------------------------------
 * | ts_old | ts_new | err | reason                                  |  ret  |
 * |--------------------------------------------------------------------------
 * |   ~T   |   ~T   |  0  | event destroyed before wait             |-EINVAL|
 * |    T   |    T   |  E  | linux signal received                   |-EINTR |
 * |    T   |   ~T   |  0  | event destroyed after wait              |-EINVAL|
 * |    T   |    T'  |  0  | event signaled after wait               |   0   |
 * |    T   |   ~T'  |  0  | event destroyed after signal after wait |   0   |
 * ---------------------------------------------------------------------------
 *
 * For case 1, 3, 5, kfree is necessary if refcnt == 0
 */

	/* case 2 and 4 */
	if (ts_new >= 0) {

		/* case 2, convert -ERESTARTSYS to -EINTR */
		if (ts_old == ts_new)
			err = -EINTR;

		return err;
	}

	/* merge case 1 into 3 */
	if (ts_old < 0)
		ts_old = ~ts_old;

	/* case 1 and 3 */
	if (~ts_new == ts_old)
		err = -EINVAL;

	/* case 1, 3 and 5*/
	if (!refcnt)
		kfree(event);

	return err;
}

SYSCALL_DEFINE1(light_evt_signal, struct light_intensity __user *,
		user_light_intensity)
{
	int local_window[WINDOW];
	struct light_intensity k_li;
	struct light_event *event;
	unsigned end, curr, new;

	if (current_uid())
		return -EACCES;

	if (copy_from_user(&k_li, user_light_intensity, sizeof(k_li)))
		return -EFAULT;

	/* lock section to update and copy global window to local window */
	spin_lock(&k_intensity_window.lock);
	for (curr = 0, end = ++k_intensity_window.count > WINDOW ?
				WINDOW : k_intensity_window.count,
		new = (k_intensity_window.count - 1) % WINDOW;
		curr != end; ++curr) {
		if (curr == new)
			local_window[curr] =
				k_intensity_window.window[curr] =
				k_li.cur_intensity;
		else
			local_window[curr] =
				k_intensity_window.window[curr];
	}
	spin_unlock(&k_intensity_window.lock);

	/* lock section to iterate through the events and signal */
	read_lock(&k_light_events.lock);
	list_for_each_entry(event, &k_light_events.list, list) {
		int freq = 0;
		for (curr = 0; curr != end; ++curr) {
			freq += local_window[curr] >
				event->params.req_intensity - NOISE;
		}

		/*
		 * acquire waitq.lock so we can ++timestamp. Such nested
		 * lock (light_events.lock -> waitq.lock) is ok, since
		 * we've never acquire (waitq.lock -> light_events.lock).
		 * Do not need to worry about evt_destroy, since we are
		 * holding read lock of light_events.lock.
		 */
		if (freq >= event->params.frequency) {
			spin_lock(&event->waitq.lock);
			++event->timestamp;
			wake_up_all_locked(&event->waitq);
			spin_unlock(&event->waitq.lock);
			/*
			 * Or:
			 * ++event->timestamp;
			 * wake_up_all(&event->waitq);
			 *
			 * In this case timestamp must be a atomic type
			 */
		}
	}
	read_unlock(&k_light_events.lock);

	return 0;
}

SYSCALL_DEFINE1(light_evt_destroy, int, event_id)
{
	struct light_event *event = NULL, *tmp;
	unsigned refcnt;

	/* lock section to find event to destroy */
	write_lock(&k_light_events.lock);
	list_for_each_entry_safe(event, tmp, &k_light_events.list, list) {
		if (event->id == event_id) {
			list_del(&event->list);
			break;
		}
	}
	write_unlock(&k_light_events.lock);

	if (&event->list == &k_light_events.list)
		return -EINVAL;

	/*
	 * we can safely access event without inc the refcnt,
	 * since we have removed event from the event list.
	 * No new thread can find the event now, however there
	 * might still be thread waiting for event. At this point
	 * event cannot be kfree'ed by waiting thread since timestamp
	 * isn't set to negative yet.
	 */

	spin_lock(&event->waitq.lock);
	/*
	 * load refcnt from event and store the bitwise NOT of timestamp
	 * to event. event->timestamp = ~event->timestamp MUST be inside
	 * spinlock and above wake_up_all, even if it's a atomic type.
	 * If it's above spin_lock, we can no longer take the spinlock
	 * safely, since evt_wait may have already kfree'ed the event.
	 * If it's below wake_up_all, evt_wait may not wake up.
	 */
	event->timestamp = ~event->timestamp;
	refcnt = atomic_read(&event->refcnt);
	wake_up_all_locked(&event->waitq);
	spin_unlock(&event->waitq.lock);

	/*
	 * At this point we can be sure that no thread is accessing and we
	 * should be responsible for kfree it. Given the fact that
	 * refcnt cannot increase, because we have already removed
	 * the event from the global event list. refcnt == 0 indicates
	 * all threads have already left the spin_lock(waitq.lock) section
	 * and for them, timestamp is not negative yet.
	 */
	if (!refcnt)
		kfree(event);

	return 0;
}

/* #pragma GCC pop_options */
