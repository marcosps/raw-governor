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

/**
 * Sets the CPU frequency to freq.
 */
static int set_speed(struct cpufreq_policy *policy, unsigned int freq)
{
	int ret;

	pr_info("setting freq to %u\n", freq);

	/*
	 * If cpufreq_driver_target is used there is a kernel oops about
	 * scheduling while atomic
	 */
	mutex_lock(&raw_mutex);
	ret = __cpufreq_driver_target(policy, freq, CPUFREQ_RELATION_H);
	mutex_unlock(&raw_mutex);

	return ret;
}

static ssize_t show_speed(struct cpufreq_policy *policy, char *buf)
{
	pr_info("\n");
	return sprintf(buf, "%u\n", policy->cur);
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

struct cpufreq_governor cpufreq_gov_raw = {
	.name = "raw",
	.start = raw_start,
	.stop = raw_stop,
	.limits = cpufreq_policy_apply_limits,
	.store_setspeed = set_speed,
	.show_setspeed = show_speed,
	.owner = THIS_MODULE,
};

MODULE_AUTHOR("Rawlinson <rawlinson.goncalves@gmail.com>");
MODULE_AUTHOR("Marcos Paulo de Souza <marcos.souza.org@gmail.com>");
MODULE_DESCRIPTION("CPUfreq policy governor 'raw'");
MODULE_LICENSE("GPL");

cpufreq_governor_init(cpufreq_gov_raw);
cpufreq_governor_exit(cpufreq_gov_raw);
