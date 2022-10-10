// SPDX-License-Identifier: GPL-2.0-only

/* Test frequency changes for processes that specify a desirable frequency */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/cpufreq.h>

static char func_name[KSYM_NAME_LEN] = "kernel_clone";
module_param_string(func, func_name, KSYM_NAME_LEN, 0644);
MODULE_PARM_DESC(func, "Function to kretprobe; this module will report the"
			" function's execution time");

/*
 * TODO:
 * store the default frequency on kretprobe registration time.
 * 	this impacts in the cases of processes without any freq set being 0, setting to minumum.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	//unsigned long retval = regs_return_value(regs);
	struct cpufreq_policy *policy;
	unsigned int cpu;
	unsigned int target_freq, cur;
	int ret = 0;

	/* Skip kernel threadds */
	if (!current->mm)
		return 0;

	/*
	 * Only deal with DEADLINE tasks.
	 * IMPORTANT: Do not be confused between task policy and cpufreq policies.
	 * Disable for now, testing!
	 */
	/*
	if (current->policy != SCHED_DEADLINE)
		return 0;
	*/

	/* Return earlier if the process don't set a preffered freq */
	/* FIXME: set pref_freq to the value before changing the first time */
	/*
	if (!current->pref_freq)
		return 0;
	*/

	cpu = smp_processor_id();
	policy = cpufreq_cpu_get(cpu);

	cur = policy->cur;
	target_freq = current->pref_freq;

	/* Return earlier if the frequency is already the desired one */
	if (target_freq == cur)
		return 0;

	/* Only deal with userspace governor */
	if (strcmp(policy->governor->name, "userspace"))
		return 0;

	/* calling setspeed from cpufreq_userspace governor */
	ret = policy->governor->store_setspeed(policy, target_freq);

	pr_info("CPU: %u, governor %s, %u -> %u? ret: %d, current freq: %u, cmd: %s(%u), running? %d\n",
			cpu, policy->governor->name, cur, target_freq, ret, policy->cur,
			current->comm, current->pid, task_is_running(current));
	return 0;
}
NOKPROBE_SYMBOL(ret_handler);

static struct kretprobe my_kretprobe = {
	.handler		= ret_handler,
	/* Probe up to 100 instances concurrently. */
	.maxactive		= 100,
};

static int __init kretprobe_init(void)
{
	int ret;

	my_kretprobe.kp.symbol_name = func_name;
	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted return probe at %s: %p\n",
			my_kretprobe.kp.symbol_name, my_kretprobe.kp.addr);
	return 0;
}

static void __exit kretprobe_exit(void)
{
	unregister_kretprobe(&my_kretprobe);
	pr_info("kretprobe at %p unregistered\n", my_kretprobe.kp.addr);

	/* nmissed > 0 suggests that maxactive was set too low. */
	pr_info("Missed probing %d instances of %s\n",
		my_kretprobe.nmissed, my_kretprobe.kp.symbol_name);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
