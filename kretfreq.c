// SPDX-License-Identifier: GPL-2.0-only
/*
 * kretprobe_example.c
 *
 * Here's a sample kernel module showing the use of return probes to
 * report the return value and total time taken for probed function
 * to run.
 *
 * usage: insmod kretprobe_example.ko func=<func_name>
 *
 * If no func_name is specified, kernel_clone is instrumented
 *
 * For more information on theory of operation of kretprobes, see
 * Documentation/trace/kprobes.rst
 *
 * Build and insert the kernel module as done in the kprobe example.
 * You will see the trace data in /var/log/messages and on the console
 * whenever the probed function returns. (Some messages may be suppressed
 * if syslogd is configured to eliminate duplicate messages.)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/cpufreq.h>

static char func_name[KSYM_NAME_LEN] = "kernel_clone";
module_param_string(func, func_name, KSYM_NAME_LEN, 0644);
MODULE_PARM_DESC(func, "Function to kretprobe; this module will report the"
			" function's execution time");

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	//unsigned long retval = regs_return_value(regs);
	struct cpufreq_policy *policy;
	unsigned int cpu;
	unsigned int target_freq, cur;
	char *gov_name;
	int ret;

	/* Only deal with DEADLINE tasks */
	if (!task_has_dl_policy(current))
		return 0;

	/* Return earlier if the process don't set a preffered freq */
	if (!current->pref_freq)
		return 0;

	target_freq = current->pref_freq;

	cpu = smp_processor_id();
	policy = cpufreq_cpu_get(cpu);
	gov_name = policy->governor->name;

	/* Only deal with userspace governor */
	if (strcmp(gov_name, "userspace"))
		return 0;

	 policy->cur;

	/* Invert frequencies */
	if (cur == policy->min)
		target_freq = policy->max;
	else if (cur == policy->max)
		target_freq = policy->min;

	/* calling setspeed from cpufreq_userspace governor */
	ret = policy->governor->store_setspeed(policy, target_freq);

	pr_info("CPU: %u, governor %s, %u -> %u? ret: %d, current cmd: %s, running? %d\n",
			cpu, policy->governor->name, cur, target_freq, ret,
			current->comm, task_is_running(current));
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
