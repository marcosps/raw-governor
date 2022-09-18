/*
 *  drivers/cpufreq/cpufreq_raw.c
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/mutex.h>
#include <linux/slab.h>

struct raw_police_data {
	unsigned int pol_def_freq;
	struct mutex pol_mutex;
};

/* Sets the CPU frequency to freq. */
static int set_speed(struct cpufreq_policy *policy, unsigned int freq)
{
	int ret;
	struct raw_police_data *data = policy->governor_data;

	pr_info("CPU %u: setting freq to %u\n", policy->cpu, freq);

	/*
	 * If cpufreq_driver_target is used there is a kernel oops about
	 * scheduling while atomic
	 */
	mutex_lock(&data->pol_mutex);
	ret = __cpufreq_driver_target(policy, freq, CPUFREQ_RELATION_H);
	mutex_unlock(&data->pol_mutex);

	return ret;
}

static ssize_t show_speed(struct cpufreq_policy *policy, char *buf)
{
	pr_info("CPU %u\n", policy->cpu);
	return sprintf(buf, "%u\n", policy->cur);
}

static int raw_init(struct cpufreq_policy *policy)
{
	struct raw_police_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/*
	 * Store the current frequency of the cpu. It will be used whenever aprocess
	 * doesn't have a preferred frequency.
	 */
	pr_info("CPU %u, default frequency %u\n", policy->cpu, policy->cur);

	data->pol_def_freq = policy->cur;
	mutex_init(&data->pol_mutex);

	policy->governor_data = data;
	return 0;
}

static void raw_exit(struct cpufreq_policy *policy)
{
	struct raw_police_data *data = policy->governor_data;

	/* Return the frequency to it's original value */
	pr_info("CPU %u, setting back frequency from %u to %u\n", policy->cpu,
			policy->cur, data->pol_def_freq);
	set_speed(policy, data->pol_def_freq);

	mutex_lock(&data->pol_mutex);
	kfree(policy->governor_data);
	policy->governor_data = NULL;
	mutex_unlock(&data->pol_mutex);
}

struct cpufreq_governor cpufreq_gov_raw = {
	.name = "raw",
	.owner = THIS_MODULE,
	.flags = CPUFREQ_GOV_DYNAMIC_SWITCHING,
	.init = raw_init,
	.exit = raw_exit,
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
