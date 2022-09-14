/*
 *  drivers/cpufreq/cpufreq_raw.c
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

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

	struct mutex timer_mutex;
};

static DEFINE_PER_CPU(struct raw_gov_info_struct, raw_gov_info);

static DEFINE_MUTEX(raw_mutex);

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

	pr_debug("(%u) kHz for cpu %u => NOVA FREQ(%u kHz)\n", target_freq, policy->cpu, new_freq);

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

	ret = __cpufreq_driver_target(policy, freq, CPUFREQ_RELATION_H);

	pr_debug("(%u) for cpu %u, freq %u kHz\n", freq, policy->cpu, policy->cur);

	mutex_unlock(&raw_mutex);
	return ret;
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

	return 0;
}

static void raw_stop(struct cpufreq_policy *policy)
{
	int i;
	struct raw_gov_info_struct *info = &per_cpu(raw_gov_info, policy->cpu);

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
