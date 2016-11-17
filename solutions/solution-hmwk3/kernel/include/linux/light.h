#ifndef __LINUX_LIGHT_H
#define __LINUX_LIGHT_H

#include <linux/list.h>
#include <linux/wait.h>
#include <linux/atomic.h>

struct light_intensity {
	int cur_intensity;
};

#define NOISE 12
#define WINDOW 20

struct event_requirements {
	int req_intensity;
	int frequency;
};

struct light_event {
	struct list_head list;
	int id;
	long timestamp;
	atomic_t refcnt;
	struct event_requirements params;
	wait_queue_head_t waitq; /*blocked processes*/
};

#endif
