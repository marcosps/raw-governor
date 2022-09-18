/*
 *  drivers/cpufreq/cpufreq_raw.c
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/mutex.h>
#include <linux/slab.h>

struct raw_gov_info_struct {
	struct cpufreq_policy *policy;

	struct mutex timer_mutex;
};

static DEFINE_PER_CPU(struct raw_gov_info_struct, raw_gov_info);
static DEFINE_MUTEX(raw_mutex);

/* Sets the CPU frequency to freq. */
static int set_speed(struct cpufreq_policy *policy, unsigned int freq)
{
	int ret;

	pr_info("cpu %u: setting freq to %u\n", policy->cpu, freq);

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
	pr_info("cpu %u\n", policy->cpu);
	return sprintf(buf, "%u\n", policy->cur);
}

static int raw_init(struct cpufreq_policy *policy)
{
	unsigned int *def_freq;

	def_freq = kzalloc(sizeof(*def_freq), GFP_KERNEL);
	if (!def_freq)
		return -ENOMEM;

	/* Store the current frequency of the cpu */
	*def_freq = policy->cur;

	policy->governor_data = def_freq;
	return 0;
}

static void raw_exit(struct cpufreq_policy *policy)
{
	mutex_lock(&raw_mutex);
	kfree(policy->governor_data);
	policy->governor_data = NULL;
	mutex_unlock(&raw_mutex);
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
	}

	BUG_ON(!policy->cur);

	/* setup timer */
	mutex_init(&info->timer_mutex);

	return 0;
}

static void raw_stop(struct cpufreq_policy *policy)
{
	int i;
	unsigned int *def_freq = policy->governor_data;
	struct raw_gov_info_struct *info = &per_cpu(raw_gov_info, policy->cpu);

	mutex_destroy(&info->timer_mutex);

	*def_freq = 0;

	/* clean raw_gov_info for all affected cpus */
	for_each_cpu (i, policy->cpus) {
		info = &per_cpu(raw_gov_info, i);
		info->policy = NULL;
	}
}

struct cpufreq_governor cpufreq_gov_raw = {
	.name = "raw",
	.owner = THIS_MODULE,
	.flags = CPUFREQ_GOV_DYNAMIC_SWITCHING,
	.init = raw_init,
	.exit = raw_exit,
	.start = raw_start,
	.stop = raw_stop,
	.limits = cpufreq_policy_apply_limits,
	.store_setspeed = set_speed,
	.show_setspeed = show_speed,
};

MODULE_AUTHOR("Rawlinson <rawlinson.goncalves@gmail.com>");
MODULE_AUTHOR("Marcos Paulo de Souza <marcos.souza.org@gmail.com>");
MODULE_DESCRIPTION("CPUfreq policy governor 'raw'");
MODULE_LICENSE("GPL");

cpufreq_governor_init(cpufreq_gov_raw);
cpufreq_governor_exit(cpufreq_gov_raw);
