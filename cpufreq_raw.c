/*
 *  drivers/cpufreq/cpufreq_raw.c
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/jiffies.h>
#include <linux/kernel_stat.h>
#include <linux/mutex.h>
#include <linux/tick.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/kthread.h>

struct raw_gov_info_struct {
	u64 prev_cpu_idle;
	u64 prev_cpu_wall;

	struct cpufreq_policy *policy;
	struct kthread_worker kraw_worker;
	struct kthread_work work;

	struct mutex timer_mutex;

	struct task_struct *tarefa_sinalizada;
	unsigned long long deadline_tarefa_sinalizada;
	unsigned long long tick_timer_rtai_ns;

	/* Os atributos abaixo indicam o intervalo de tempo que o RAW MONITOR levou para ser ativado. */
	unsigned long long start_timer_delay_monitor;
	unsigned long long end_timer_delay_monitor;
};

static DEFINE_PER_CPU(struct raw_gov_info_struct, raw_gov_info);

static DEFINE_MUTEX(raw_mutex);

struct cpufreq_frequency_table *freq_table;

#define dprintk(msg...) cpufreq_debug_printk(CPUFREQ_DEBUG_GOVERNOR, "raw", msg)

unsigned int get_max_frequency_table(struct cpufreq_policy *policy)
{
	//OBS.: as frequencias comecam do MAIOR para o MENOR. Logo a posicao ZERO do vetor possui a maior frequencia.
	return policy->freq_table[0].frequency;
}

unsigned int get_frequency_table_target(struct cpufreq_policy *policy, unsigned int target_freq)
{
	unsigned int new_freq;
	unsigned int i;
	struct cpufreq_frequency_table *freq_table = policy->freq_table;

	if (!cpu_online(policy->cpu))
		return -EINVAL;

	//OBS.: as frequencias comecam do MAIOR para o MENOR.
	new_freq = freq_table[0].frequency;
	for (i = 0; (freq_table[i].frequency != CPUFREQ_TABLE_END); i++) {
		unsigned int freq = freq_table[i].frequency;

		if (freq == CPUFREQ_ENTRY_INVALID)
			continue;

		if ((freq < policy->min) || (freq > policy->max))
			continue;

		if (freq < target_freq) {
			break;
		}
		new_freq = freq;
	}

	printk("DEBUG:RAWLINSON - RAW GOVERNOR - get_frequency_table_target(%u) kHz for cpu %u => NOVA FREQ(%u kHz)\n", target_freq, policy->cpu, new_freq);

	return new_freq;
}


/**
 * Sets the CPU frequency to freq.
 */
static int cpufreq_raw_set(struct cpufreq_policy *policy, unsigned int freq)
{
	unsigned int valid_freq = 0;
	int ret = -EINVAL;

	mutex_lock(&raw_mutex);

	valid_freq = get_frequency_table_target(policy, freq);
	ret = __cpufreq_driver_target(policy, valid_freq, CPUFREQ_RELATION_H);

	printk("DEBUG:RAWLINSON - cpufreq_raw_set(%u) for cpu %u, freq %u kHz\n", freq, policy->cpu, policy->cur);

	mutex_unlock(&raw_mutex);
	return ret;
}

// FIXME: This needs to be removed
#define CPUID_RTAI 0

static void raw_gov_init_work(struct raw_gov_info_struct *info)
{
	info->tarefa_sinalizada = NULL;
	info->deadline_tarefa_sinalizada = 0;

	kthread_init_worker(&info->kraw_worker);
	info->kraw_worker.task = kthread_create(kthread_worker_fn, &info->kraw_worker, "raw_monitor/%d", info->policy->cpu);
	if (IS_ERR(info->kraw_worker.task)) {
		printk(KERN_ERR "Creation of raw_monitor/%d failed\n", info->policy->cpu);
	}
	printk("DEBUG:RAWLINSON - RAW GOVERNOR - raw_gov_init_work -> PID (%d)\n", info->kraw_worker.task->pid);

//	get_task_struct(info->kraw_worker.task);
	set_cpus_allowed_ptr(info->kraw_worker.task, cpumask_of(CPUID_RTAI));
	kthread_bind(info->kraw_worker.task, info->policy->cpu);

	/* must use the FIFO scheduler as it is realtime sensitive */
	sched_set_fifo(info->kraw_worker.task);

	kthread_flush_work(&info->work);
	kthread_queue_work(&info->kraw_worker, &info->work);
}

static void raw_gov_cancel_work(struct raw_gov_info_struct *info)
{
	/* Kill irq worker */
	kthread_flush_worker(&info->kraw_worker);
	kthread_stop(info->kraw_worker.task);
	printk("DEBUG:RAWLINSON - raw_gov_cancel_work - Removendo o raw_monitor\n");
}

static int raw_start(struct cpufreq_policy *policy)
{
	int i;
	struct raw_gov_info_struct *info, *affected_info;
	unsigned int cpu = policy->cpu;

	info = &per_cpu(raw_gov_info, cpu);

	if (!cpu_online(cpu))
		return -EINVAL;

	/* initialize raw_gov_info for all affected cpus */
	for_each_cpu(i, policy->cpus) {
		affected_info = &per_cpu(raw_gov_info, i);
		affected_info->policy = policy;
		affected_info->prev_cpu_idle = get_cpu_idle_time_us(i, &affected_info->prev_cpu_wall);
	}

	BUG_ON(!policy->cur);

	/* setup timer */
	mutex_init(&info->timer_mutex);
	raw_gov_init_work(info);

	return 0;
}

static void raw_stop(struct cpufreq_policy *policy)
{
	int i;
	struct raw_gov_info_struct *info = &per_cpu(raw_gov_info, policy->cpu);

	/* cancel timer */
	raw_gov_cancel_work(info);
	mutex_destroy(&info->timer_mutex);

	/* clean raw_gov_info for all affected cpus */
	for_each_cpu (i, policy->cpus) {
		info = &per_cpu(raw_gov_info, i);
		info->policy = NULL;
	}
}

static void raw_limits(struct cpufreq_policy *policy)
{
	struct raw_gov_info_struct *info = &per_cpu(raw_gov_info, policy->cpu);

	mutex_lock(&raw_mutex);
	if (policy->max < info->policy->cur)
		__cpufreq_driver_target(info->policy, policy->max, CPUFREQ_RELATION_H);
	else if (policy->min > info->policy->cur)
		__cpufreq_driver_target(info->policy, policy->min, CPUFREQ_RELATION_L);
	mutex_unlock(&raw_mutex);
}

struct cpufreq_governor cpufreq_gov_raw = {
	.name = "raw",
	.start = raw_start,
	.stop = raw_stop,
	.limits = raw_limits,
	.store_setspeed = cpufreq_raw_set,
	.owner = THIS_MODULE,
};

MODULE_AUTHOR("Rawlinson <rawlinson.goncalves@gmail.com>");
MODULE_AUTHOR("Marcos Paulo de Souza <marcos.souza.org@gmail.com>");
MODULE_DESCRIPTION("CPUfreq policy governor 'raw'");
MODULE_LICENSE("GPL");

cpufreq_governor_init(cpufreq_gov_raw);
cpufreq_governor_exit(cpufreq_gov_raw);
