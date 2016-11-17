#include "sched.h"

#define APP_UID_START 10000
#define DEFAULT_WEIGHT 1

static int BOOSTED_WEIGHT = 10;

DEFINE_RAW_SPINLOCK(wrr_weight_lock);

int get_boosted_weight(void)
{
	int cur_weight = 0;

	raw_spin_lock(&wrr_weight_lock);
	cur_weight = BOOSTED_WEIGHT;
	raw_spin_unlock(&wrr_weight_lock);
	return cur_weight;
}

void set_boosted_weight(int boosted_weight)
{
	raw_spin_lock(&wrr_weight_lock);
	BOOSTED_WEIGHT = boosted_weight;
	raw_spin_unlock(&wrr_weight_lock);
}

int get_task_weight_wrr(struct task_struct *p)
{
	if (p->cred->uid >= APP_UID_START)
		return get_boosted_weight();

	return DEFAULT_WEIGHT;
}

static void check_preempt_curr_wrr(struct rq *rq,
struct task_struct *p, int flags)
{
}

static struct task_struct *pick_next_task_wrr(struct rq *rq)
{
	struct wrr_rq *wrr_rq = &rq->wrr;
	struct sched_wrr_entity *entity;
	struct task_struct *p;

	if (list_empty(&wrr_rq->wrr_rq_list))
		return NULL;

	entity = list_first_entry(&wrr_rq->wrr_rq_list,
			struct sched_wrr_entity, entity_list_head);

	p = container_of(entity, struct task_struct, wrr);
	return p;
}

static void dequeue_task_wrr(struct rq *rq, struct task_struct *p, int flags)
{
	struct wrr_rq *wrr_rq = &rq->wrr;
	struct sched_wrr_entity *entity = &p->wrr;
	int cur_task_weight = entity->weight;

	if (wrr_rq->nr_running) {
		wrr_rq->nr_running--;
		wrr_rq->total_weight -= cur_task_weight;
		list_del(&entity->entity_list_head);
	}
}

static void yield_task_wrr(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	struct sched_wrr_entity *entity = &curr->wrr;

	entity->time_slice = 0;
}

static void enqueue_task_wrr(struct rq *rq, struct task_struct *p, int flags)
{
	struct wrr_rq *wrr_rq = &rq->wrr;
	struct sched_wrr_entity *entity = &p->wrr;
	int cur_task_weight = entity->weight;

	wrr_rq->nr_running++;
	wrr_rq->total_weight += cur_task_weight;

	list_add_tail(&entity->entity_list_head, &wrr_rq->wrr_rq_list);
}

static void put_prev_task_wrr(struct rq *rq, struct task_struct *p)
{
}

static void task_tick_wrr(struct rq *rq, struct task_struct *p, int queued)
{
	struct sched_wrr_entity *entity = &p->wrr;
	int cur_task_weight = entity->weight;

	if (!cur_task_weight)
		entity->weight = DEFAULT_WEIGHT;

	cur_task_weight = entity->weight;

	entity->time_slice--;

	if (entity->time_slice &&
			entity->time_slice <= cur_task_weight * WRR_TIMESLICE)
		return;

	if (cur_task_weight > DEFAULT_WEIGHT) {
		rq->wrr.total_weight = rq->wrr.total_weight - cur_task_weight;
		cur_task_weight--;
		entity->weight = cur_task_weight;
		rq->wrr.total_weight = rq->wrr.total_weight + cur_task_weight;
	}

	entity->time_slice = cur_task_weight * WRR_TIMESLICE;

	if (rq->wrr.nr_running > 1) {
		list_move_tail(&entity->entity_list_head, &rq->wrr.wrr_rq_list);
		resched_task(p);
	}
}

static void prio_changed_wrr(struct rq *rq, struct task_struct *p, int oldprio)
{
}

static void switched_to_wrr(struct rq *rq, struct task_struct *p)
{
}

int can_migrate_task_wrr(struct task_struct *p, struct rq *rq, int dest_cpu)
{
	if (!cpumask_test_cpu(dest_cpu, tsk_cpus_allowed(p)))
		return 0;

	if (task_running(rq, p))
		return 0;

	return 1;
}

#ifdef CONFIG_SMP

static int select_task_rq_wrr(struct task_struct *p, int sd_flag, int flags)
{
	int cpu = 0;
	struct rq *rq = NULL;
	int min_weight = INT_MAX;
	int lightest_cpu = 0;

	for_each_possible_cpu(cpu) {
		rq = cpu_rq(cpu);
		raw_spin_lock(&rq->lock);

		if (rq->wrr.total_weight < min_weight) {
			min_weight = rq->wrr.total_weight;
			lightest_cpu = cpu_of(rq);
		}

		raw_spin_unlock(&rq->lock);
	}

	return lightest_cpu;
}

static void pre_schedule_wrr(struct rq *rq, struct task_struct *prev)
{

	int cpu;
	struct rq *src_rq;
	struct sched_wrr_entity *entity;

	struct wrr_rq *wrr_rq = &rq->wrr;
	struct task_struct *p;

	if (wrr_rq->nr_running)
		return;

	for_each_possible_cpu(cpu) {
		src_rq = cpu_rq(cpu);
		if (src_rq == rq || src_rq->wrr.nr_running <= 1)
			continue;

		double_lock_balance(rq, src_rq);

		if (unlikely(wrr_rq->nr_running)) {
			double_unlock_balance(rq, src_rq);
			return;
		}

		if (unlikely(src_rq->wrr.nr_running <= 1))
			goto skip;

		list_for_each_entry(entity,
				&src_rq->wrr.wrr_rq_list,
				entity_list_head) {
			p = container_of(entity, struct task_struct, wrr);

			if (!can_migrate_task_wrr(p, src_rq, cpu_of(rq)))
				continue;

			if (likely(p->on_rq)) {
				raw_spin_lock(&p->pi_lock);
				deactivate_task(src_rq, p, 0);
				set_task_cpu(p, cpu_of(rq));
				activate_task(rq, p, 0);
				raw_spin_unlock(&p->pi_lock);
			}

			if (unlikely(rq->curr == rq->idle) &&
					likely(rq->wrr.nr_running))
				resched_task(rq->curr);

			double_unlock_balance(rq, src_rq);
			return;
		}

skip:
		double_unlock_balance(rq, src_rq);
	}
}

#endif

static void set_curr_task_wrr(struct rq *rq)
{
	struct task_struct *p = rq->curr;
	int cur_weight = get_task_weight_wrr(p);

	p->se.exec_start = rq->clock_task;
	p->wrr.weight = cur_weight;
	p->wrr.time_slice = cur_weight * WRR_TIMESLICE;
}

static unsigned int get_rr_interval_wrr(struct rq *rq, struct task_struct *p)
{
	return 0;
}

void init_wrr_rq(struct wrr_rq *wrr_rq, struct rq *rq)
{
	wrr_rq->nr_running = 0;
	wrr_rq->total_weight = 0;
	INIT_LIST_HEAD(&wrr_rq->wrr_rq_list);
}

const struct sched_class wrr_sched_class = {
	.next			= &fair_sched_class,
	.enqueue_task		= enqueue_task_wrr,
	.dequeue_task		= dequeue_task_wrr,
	.yield_task		= yield_task_wrr,
	.check_preempt_curr	= check_preempt_curr_wrr,
	.pick_next_task		= pick_next_task_wrr,
	.put_prev_task		= put_prev_task_wrr,
	.set_curr_task		= set_curr_task_wrr,
	.task_tick		= task_tick_wrr,
	.get_rr_interval	= get_rr_interval_wrr,
	.prio_changed		= prio_changed_wrr,
	.switched_to		= switched_to_wrr,
#ifdef CONFIG_SMP
	.select_task_rq		= select_task_rq_wrr,
	.pre_schedule		= pre_schedule_wrr,
#endif
};
