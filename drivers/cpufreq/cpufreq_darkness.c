/*
<<<<<<< HEAD
 * Darkness - Load Sensitive CPU Frequency Governor
 *
 * Copyright (c) 2010-2016, Alucard24 <dmbaoh2@gmail.com>
=======
 *  drivers/cpufreq/cpufreq_darkness.c
 *
 *  Copyright (C)  2011 Samsung Electronics co. ltd
 *    ByungChang Cha <bc.cha@samsung.com>
 *
 *  Based on ondemand governor
 *  Copyright (C)  2001 Russell King
 *            (C)  2003 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>.
 *                      Jun Nakajima <jun.nakajima@intel.com>
>>>>>>> fbcc943a684b... :wolf: add darkness governor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
<<<<<<< HEAD
 *
 */

#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/cpufreq.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/display_state.h>
#include <asm/cputime.h>

struct cpufreq_darkness_policyinfo {
	struct timer_list policy_timer;
	struct timer_list policy_slack_timer;
	spinlock_t load_lock; /* protects load tracking stat */
	u64 last_evaluated_jiffy;
	struct cpufreq_policy *policy;
	struct cpufreq_frequency_table *freq_table;
	spinlock_t target_freq_lock; /*protects target freq */
	unsigned int target_freq;
	unsigned int min_freq;
	struct rw_semaphore enable_sem;
	bool reject_notification;
	int governor_enabled;
	struct cpufreq_darkness_tunables *cached_tunables;
	unsigned long *cpu_busy_times;
};

/* Protected by per-policy load_lock */
struct cpufreq_darkness_cpuinfo {
	u64 time_in_idle;
	u64 time_in_idle_timestamp;
	unsigned int load;
};

static DEFINE_PER_CPU(struct cpufreq_darkness_policyinfo *, polinfo);
static DEFINE_PER_CPU(struct cpufreq_darkness_cpuinfo, cpuinfo);

/* realtime thread handles frequency scaling */
static struct task_struct *speedchange_task;
static cpumask_t speedchange_cpumask;
static spinlock_t speedchange_cpumask_lock;
static struct mutex gov_lock;

#define DEFAULT_TIMER_RATE (20 * USEC_PER_MSEC)
#define DEFAULT_TIMER_RATE_SUSP ((unsigned long)(50 * USEC_PER_MSEC))

struct cpufreq_darkness_tunables {
	int usage_count;
	/*
	 * The sample rate of the timer used to increase frequency
	 */
	unsigned long timer_rate;
	unsigned long timer_rate_prev;

	/*
	 * Max additional time to wait in idle, beyond timer_rate, at speeds
	 * above minimum before wakeup to reduce speed, or -1 if unnecessary.
	 */
#define DEFAULT_TIMER_SLACK (4 * DEFAULT_TIMER_RATE)
	int timer_slack_val;
	bool io_is_busy;
	/*
	 * Whether to align timer windows across all CPUs.
	 */
	bool align_windows;
};

/* For cases where we have single governor instance for system */
static struct cpufreq_darkness_tunables *common_tunables;
static struct cpufreq_darkness_tunables *cached_common_tunables;

static struct attribute_group *get_sysfs_attr(void);

/* Round to starting jiffy of next evaluation window */
static u64 round_to_nw_start(u64 jif,
			     struct cpufreq_darkness_tunables *tunables)
{
	unsigned long step = usecs_to_jiffies(tunables->timer_rate);
	u64 ret;

	if (tunables->align_windows) {
		do_div(jif, step);
		ret = (jif + 1) * step;
	} else {
		ret = jiffies + usecs_to_jiffies(tunables->timer_rate);
	}

	return ret;
}

static void cpufreq_darkness_timer_resched(unsigned long cpu,
					      bool slack_only)
{
	struct cpufreq_darkness_policyinfo *ppol = per_cpu(polinfo, cpu);
	struct cpufreq_darkness_cpuinfo *pcpu;
	struct cpufreq_darkness_tunables *tunables =
		ppol->policy->governor_data;
	u64 expires;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&ppol->load_lock, flags);
	expires = round_to_nw_start(ppol->last_evaluated_jiffy, tunables);
	if (!slack_only) {
		for_each_cpu(i, ppol->policy->cpus) {
			pcpu = &per_cpu(cpuinfo, i);
			pcpu->time_in_idle = get_cpu_idle_time(i,
						&pcpu->time_in_idle_timestamp,
						tunables->io_is_busy);
		}
		del_timer(&ppol->policy_timer);
		ppol->policy_timer.expires = expires;
		add_timer(&ppol->policy_timer);
	}

	if (tunables->timer_slack_val >= 0 &&
	    ppol->target_freq > ppol->policy->min) {
		expires += usecs_to_jiffies(tunables->timer_slack_val);
		del_timer(&ppol->policy_slack_timer);
		ppol->policy_slack_timer.expires = expires;
		add_timer(&ppol->policy_slack_timer);
	}

	spin_unlock_irqrestore(&ppol->load_lock, flags);
}

/* The caller shall take enable_sem write semaphore to avoid any timer race.
 * The policy_timer and policy_slack_timer must be deactivated when calling
 * this function.
 */
static void cpufreq_darkness_timer_start(
	struct cpufreq_darkness_tunables *tunables, int cpu)
{
	struct cpufreq_darkness_policyinfo *ppol = per_cpu(polinfo, cpu);
	struct cpufreq_darkness_cpuinfo *pcpu;
	u64 expires = round_to_nw_start(ppol->last_evaluated_jiffy, tunables);
	unsigned long flags;
	int i;

	spin_lock_irqsave(&ppol->load_lock, flags);
	ppol->policy_timer.expires = expires;
	add_timer(&ppol->policy_timer);
	if (tunables->timer_slack_val >= 0 &&
	    ppol->target_freq > ppol->policy->min) {
		expires += usecs_to_jiffies(tunables->timer_slack_val);
		ppol->policy_slack_timer.expires = expires;
		add_timer(&ppol->policy_slack_timer);
	}

	for_each_cpu(i, ppol->policy->cpus) {
		pcpu = &per_cpu(cpuinfo, i);
		pcpu->time_in_idle =
			get_cpu_idle_time(i, &pcpu->time_in_idle_timestamp,
					  tunables->io_is_busy);
	}
	spin_unlock_irqrestore(&ppol->load_lock, flags);
}

static unsigned int choose_freq(struct cpufreq_darkness_policyinfo *pcpu,
					unsigned int tmp_freq)
{
	struct cpufreq_policy *policy = pcpu->policy;
	struct cpufreq_frequency_table *table = pcpu->freq_table;
	struct cpufreq_frequency_table *pos;
	unsigned int i = 0, l_freq = 0, h_freq = 0, target_freq = 0, freq;

	if (tmp_freq < policy->min)
		tmp_freq = policy->min;
	if (tmp_freq > policy->max)
		tmp_freq = policy->max;

	cpufreq_for_each_valid_entry(pos, table) {
		freq = pos->frequency;
		i = pos - table;
		if (freq < tmp_freq) {
			h_freq = freq;
		}
		if (freq == tmp_freq) {
			target_freq = freq;
			break;
		}
		if (freq > tmp_freq) {
			l_freq = freq;
			break;
		}
	}
	if (!target_freq) {
		if (policy->cur >= h_freq
			 && policy->cur <= l_freq)
			target_freq = policy->cur;
		else
			target_freq = l_freq;
	}

	return target_freq;
}

static bool update_load(int cpu)
{
	struct cpufreq_darkness_policyinfo *ppol = per_cpu(polinfo, cpu);
	struct cpufreq_darkness_cpuinfo *pcpu = &per_cpu(cpuinfo, cpu);
	struct cpufreq_darkness_tunables *tunables =
		ppol->policy->governor_data;
	u64 now;
	u64 now_idle;
	unsigned int delta_idle;
	unsigned int delta_time;
	bool ignore = false;

	now_idle = get_cpu_idle_time(cpu, &now, tunables->io_is_busy);
	delta_idle = (unsigned int)(now_idle - pcpu->time_in_idle);
	delta_time = (unsigned int)(now - pcpu->time_in_idle_timestamp);

	WARN_ON_ONCE(!delta_time);

	if (delta_time < delta_idle) {
		pcpu->load = 0;
		ignore = true;
	} else {
		pcpu->load = 100 * (delta_time - delta_idle);
		do_div(pcpu->load, delta_time);
	}
	pcpu->time_in_idle = now_idle;
	pcpu->time_in_idle_timestamp = now;

	return ignore;
}

static void cpufreq_darkness_timer(unsigned long data)
{
	struct cpufreq_darkness_policyinfo *ppol = per_cpu(polinfo, data);
	struct cpufreq_darkness_tunables *tunables =
		ppol->policy->governor_data;
	struct cpufreq_darkness_cpuinfo *pcpu;
	struct cpufreq_govinfo govinfo;
	unsigned int new_freq;
	unsigned int max_load = 0;
	unsigned long flags;
	unsigned long max_cpu;
	int i, fcpu;

	if (!down_read_trylock(&ppol->enable_sem))
		return;
	if (!ppol->governor_enabled)
		goto exit;

	fcpu = cpumask_first(ppol->policy->related_cpus);
	spin_lock_irqsave(&ppol->load_lock, flags);
	ppol->last_evaluated_jiffy = get_jiffies_64();

	if (is_display_on() &&
		tunables->timer_rate != tunables->timer_rate_prev)
		tunables->timer_rate = tunables->timer_rate_prev;
	else if (!is_display_on() &&
		tunables->timer_rate != DEFAULT_TIMER_RATE_SUSP) {
		tunables->timer_rate_prev = tunables->timer_rate;
		tunables->timer_rate
			= max(tunables->timer_rate,
				DEFAULT_TIMER_RATE_SUSP);
	}

	max_cpu = cpumask_first(ppol->policy->cpus);
	for_each_cpu(i, ppol->policy->cpus) {
		pcpu = &per_cpu(cpuinfo, i);
		if (update_load(i))
			continue;

		if (pcpu->load > max_load) {
			max_load = pcpu->load;
			max_cpu = i;
		}
	}
	spin_unlock_irqrestore(&ppol->load_lock, flags);

	/*
	 * Send govinfo notification.
	 * Govinfo notification could potentially wake up another thread
	 * managed by its clients. Thread wakeups might trigger a load
	 * change callback that executes this function again. Therefore
	 * no spinlock could be held when sending the notification.
	 */
	for_each_cpu(i, ppol->policy->cpus) {
		pcpu = &per_cpu(cpuinfo, i);
		govinfo.cpu = i;
		govinfo.load = pcpu->load;
		atomic_notifier_call_chain(&cpufreq_govinfo_notifier_list,
					   CPUFREQ_LOAD_CHANGE, &govinfo);
	}

	spin_lock_irqsave(&ppol->target_freq_lock, flags);
	new_freq = choose_freq(ppol, max_load * (ppol->policy->max / 100));
	if (!new_freq) {
		spin_unlock_irqrestore(&ppol->target_freq_lock, flags);
		goto rearm;
	}

	ppol->target_freq = new_freq;
	spin_unlock_irqrestore(&ppol->target_freq_lock, flags);
	spin_lock_irqsave(&speedchange_cpumask_lock, flags);
	cpumask_set_cpu(max_cpu, &speedchange_cpumask);
	spin_unlock_irqrestore(&speedchange_cpumask_lock, flags);
	wake_up_process_no_notif(speedchange_task);

rearm:
	if (!timer_pending(&ppol->policy_timer))
		cpufreq_darkness_timer_resched(data, false);

exit:
	up_read(&ppol->enable_sem);
	return;
}

static int cpufreq_darkness_speedchange_task(void *data)
{
	unsigned int cpu;
	cpumask_t tmp_mask;
	unsigned long flags;
	struct cpufreq_darkness_policyinfo *ppol;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_irqsave(&speedchange_cpumask_lock, flags);

		if (cpumask_empty(&speedchange_cpumask)) {
			spin_unlock_irqrestore(&speedchange_cpumask_lock,
					       flags);
			schedule();

			if (kthread_should_stop())
				break;

			spin_lock_irqsave(&speedchange_cpumask_lock, flags);
		}

		set_current_state(TASK_RUNNING);
		tmp_mask = speedchange_cpumask;
		cpumask_clear(&speedchange_cpumask);
		spin_unlock_irqrestore(&speedchange_cpumask_lock, flags);

		for_each_cpu(cpu, &tmp_mask) {
			ppol = per_cpu(polinfo, cpu);
			if (!down_read_trylock(&ppol->enable_sem))
				continue;
			if (!ppol->governor_enabled) {
				up_read(&ppol->enable_sem);
				continue;
			}

 			if (ppol->target_freq != ppol->policy->cur) {
				__cpufreq_driver_target(ppol->policy,
							ppol->target_freq,
							CPUFREQ_RELATION_L);
			}
			up_read(&ppol->enable_sem);
		}
	}

	return 0;
}

static int cpufreq_darkness_notifier(
	struct notifier_block *nb, unsigned long val, void *data)
{
	struct cpufreq_freqs *freq = data;
	struct cpufreq_darkness_policyinfo *ppol;
	int cpu;
	unsigned long flags;

	if (val == CPUFREQ_POSTCHANGE) {
		ppol = per_cpu(polinfo, freq->cpu);
		if (!ppol)
			return 0;
		if (!down_read_trylock(&ppol->enable_sem))
			return 0;
		if (!ppol->governor_enabled) {
			up_read(&ppol->enable_sem);
			return 0;
		}

		if (cpumask_first(ppol->policy->cpus) != freq->cpu) {
			up_read(&ppol->enable_sem);
			return 0;
		}
		spin_lock_irqsave(&ppol->load_lock, flags);
		for_each_cpu(cpu, ppol->policy->cpus)
			update_load(cpu);
		spin_unlock_irqrestore(&ppol->load_lock, flags);

		up_read(&ppol->enable_sem);
	}
	return 0;
}

static struct notifier_block cpufreq_notifier_block = {
	.notifier_call = cpufreq_darkness_notifier,
};

#define show_store_one(file_name)					\
static ssize_t show_##file_name(					\
	struct cpufreq_darkness_tunables *tunables, char *buf)	\
{									\
	return snprintf(buf, PAGE_SIZE, "%u\n", tunables->file_name);	\
}									\
static ssize_t store_##file_name(					\
		struct cpufreq_darkness_tunables *tunables,		\
		const char *buf, size_t count)				\
{									\
	int ret;							\
	long unsigned int val;						\
									\
	ret = kstrtoul(buf, 0, &val);				\
	if (ret < 0)							\
		return ret;						\
	tunables->file_name = val;					\
	return count;							\
}
show_store_one(align_windows);

static ssize_t show_timer_rate(struct cpufreq_darkness_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%lu\n", tunables->timer_rate);
}

static ssize_t store_timer_rate(struct cpufreq_darkness_tunables *tunables,
		const char *buf, size_t count)
{
	int ret;
	unsigned long val, val_round;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;

	val_round = jiffies_to_usecs(usecs_to_jiffies(val));
	if (val != val_round)
		pr_warn("timer_rate not aligned to jiffy. Rounded up to %lu\n",
			val_round);
	tunables->timer_rate = val_round;
	tunables->timer_rate_prev = val_round;
=======
 * 
 * Created by Alucard_24@xda
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/jiffies.h>
#include <linux/kernel_stat.h>
#include <linux/mutex.h>
#include <linux/hrtimer.h>
#include <linux/tick.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/slab.h>
/*
 * dbs is used in this file as a shortform for demandbased switching
 * It helps to keep variable names smaller, simpler
 */

#define MAX_HOTPLUG_RATE		(40)
#define HOTPLUG_DOWN_INDEX		(0)
#define HOTPLUG_UP_INDEX		(1)

#ifndef CONFIG_CPU_EXYNOS4210
static atomic_t hotplug_freq[4][2] = {
	{ATOMIC_INIT(0), ATOMIC_INIT(500000)},
	{ATOMIC_INIT(200000), ATOMIC_INIT(500000)},
	{ATOMIC_INIT(200000), ATOMIC_INIT(500000)},
	{ATOMIC_INIT(200000), ATOMIC_INIT(0)}
};
#else
static atomic_t hotplug_freq[2][2] = {
	{ATOMIC_INIT(0), ATOMIC_INIT(500000)},
	{ATOMIC_INIT(200000), ATOMIC_INIT(0)}
};
#endif

static void do_darkness_timer(struct work_struct *work);
static int cpufreq_governor_darkness(struct cpufreq_policy *policy,
				unsigned int event);

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_DARKNESS
static
#endif
struct cpufreq_governor cpufreq_gov_darkness = {
	.name                   = "darkness",
	.governor               = cpufreq_governor_darkness,
	.owner                  = THIS_MODULE,
};

struct cpufreq_darkness_cpuinfo {
	unsigned long prev_cpu_user;
	unsigned long prev_cpu_system;
	unsigned long prev_cpu_others;
	unsigned long prev_cpu_idle;
	unsigned long prev_cpu_iowait;
	struct delayed_work work;
	int cpu;
};
/*
 * mutex that serializes governor limit change with
 * do_darkness_timer invocation. We do not want do_darkness_timer to run
 * when user is changing the governor or limits.
 */
static DEFINE_PER_CPU(struct cpufreq_darkness_cpuinfo, od_darkness_cpuinfo);
static DEFINE_PER_CPU(struct cpufreq_policy *, cpufreq_cpu_data);

static unsigned int darkness_enable;	/* number of CPUs using this policy */
/*
 * darkness_mutex protects darkness_enable in governor start/stop.
 */
static DEFINE_MUTEX(darkness_mutex);
static struct mutex timer_mutex;

/* darkness tuners */
static struct darkness_tuners {
	atomic_t sampling_rate;
	atomic_t hotplug_enable;
	atomic_t cpu_up_rate;
	atomic_t cpu_down_rate;
	atomic_t up_load;
	atomic_t down_load;
	atomic_t up_sf_step;
	atomic_t down_sf_step;
	atomic_t force_freqs_step;
	atomic_t onecoresuspend;
	atomic_t min_freq_limit;
	atomic_t max_freq_limit;
} darkness_tuners_ins = {
	.sampling_rate = ATOMIC_INIT(60000),
	.hotplug_enable = ATOMIC_INIT(0),
	.cpu_up_rate = ATOMIC_INIT(10),
	.cpu_down_rate = ATOMIC_INIT(5),
	.up_load = ATOMIC_INIT(65),
	.up_sf_step = ATOMIC_INIT(0),
	.down_sf_step = ATOMIC_INIT(0),
	.force_freqs_step = ATOMIC_INIT(0),
	.onecoresuspend = ATOMIC_INIT(0),
};

static int num_rate;

static int freqs_step[16][4]={
    {1600000,1500000,1500000,1500000},
    {1500000,1400000,1300000,1300000},
    {1400000,1300000,1200000,1200000},
    {1300000,1200000,1000000,1000000},
    {1200000,1100000, 800000, 800000},
    {1100000,1000000, 600000, 500000},
    {1000000, 800000, 500000, 200000},
    { 900000, 600000, 400000, 100000},
    { 800000, 500000, 200000, 100000},
    { 700000, 400000, 100000, 100000},
    { 600000, 200000, 100000, 100000},
    { 500000, 100000, 100000, 100000},
    { 400000, 100000, 100000, 100000},
    { 300000, 100000, 100000, 100000},
    { 200000, 100000, 100000, 100000},
	{ 100000, 100000, 100000, 100000}
};

/************************** sysfs interface ************************/

/* cpufreq_darkness Governor Tunables */
#define show_one(file_name, object)					\
static ssize_t show_##file_name						\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return sprintf(buf, "%d\n", atomic_read(&darkness_tuners_ins.object));		\
}
show_one(sampling_rate, sampling_rate);
show_one(hotplug_enable, hotplug_enable);
show_one(cpu_up_rate, cpu_up_rate);
show_one(cpu_down_rate, cpu_down_rate);
show_one(up_load, up_load);
show_one(down_load, down_load);
show_one(up_sf_step, up_sf_step);
show_one(down_sf_step, down_sf_step);
show_one(force_freqs_step, force_freqs_step);
show_one(onecoresuspend, onecoresuspend);
show_one(min_freq_limit, min_freq_limit);
show_one(max_freq_limit, max_freq_limit);

#define show_hotplug_param(file_name, num_core, up_down)		\
static ssize_t show_##file_name##_##num_core##_##up_down		\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return sprintf(buf, "%d\n", atomic_read(&file_name[num_core - 1][up_down]));	\
}

#define store_hotplug_param(file_name, num_core, up_down)		\
static ssize_t store_##file_name##_##num_core##_##up_down		\
(struct kobject *kobj, struct attribute *attr,				\
	const char *buf, size_t count)					\
{									\
	unsigned int input;						\
	int ret;							\
	ret = sscanf(buf, "%u", &input);				\
	if (ret != 1)							\
		return -EINVAL;						\
	if (input == atomic_read(&file_name[num_core - 1][up_down])) {		\
		return count;	\
	}	\
	atomic_set(&file_name[num_core - 1][up_down], input);			\
	return count;							\
}

show_hotplug_param(hotplug_freq, 1, 1);
show_hotplug_param(hotplug_freq, 2, 0);
#ifndef CONFIG_CPU_EXYNOS4210
show_hotplug_param(hotplug_freq, 2, 1);
show_hotplug_param(hotplug_freq, 3, 0);
show_hotplug_param(hotplug_freq, 3, 1);
show_hotplug_param(hotplug_freq, 4, 0);
#endif

store_hotplug_param(hotplug_freq, 1, 1);
store_hotplug_param(hotplug_freq, 2, 0);
#ifndef CONFIG_CPU_EXYNOS4210
store_hotplug_param(hotplug_freq, 2, 1);
store_hotplug_param(hotplug_freq, 3, 0);
store_hotplug_param(hotplug_freq, 3, 1);
store_hotplug_param(hotplug_freq, 4, 0);
#endif

define_one_global_rw(hotplug_freq_1_1);
define_one_global_rw(hotplug_freq_2_0);
#ifndef CONFIG_CPU_EXYNOS4210
define_one_global_rw(hotplug_freq_2_1);
define_one_global_rw(hotplug_freq_3_0);
define_one_global_rw(hotplug_freq_3_1);
define_one_global_rw(hotplug_freq_4_0);
#endif

/* sampling_rate */
static ssize_t store_sampling_rate(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(input,10000);
	
	if (input == atomic_read(&darkness_tuners_ins.sampling_rate))
		return count;

	atomic_set(&darkness_tuners_ins.sampling_rate,input);

	return count;
}

/* hotplug_enable */
static ssize_t store_hotplug_enable(struct kobject *a, struct attribute *b,
				  const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = input > 0; 

	if (atomic_read(&darkness_tuners_ins.hotplug_enable) == input)
		return count;

	atomic_set(&darkness_tuners_ins.hotplug_enable, input);

	return count;
}

/* cpu_up_rate */
static ssize_t store_cpu_up_rate(struct kobject *a, struct attribute *b,
				 const char *buf, size_t count)
{
	int input;
	int ret;
	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,MAX_HOTPLUG_RATE),1);

	if (input == atomic_read(&darkness_tuners_ins.cpu_up_rate))
		return count;

	atomic_set(&darkness_tuners_ins.cpu_up_rate,input);

	return count;
}

/* cpu_down_rate */
static ssize_t store_cpu_down_rate(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,MAX_HOTPLUG_RATE),1);

	if (input == atomic_read(&darkness_tuners_ins.cpu_down_rate))
		return count;

	atomic_set(&darkness_tuners_ins.cpu_down_rate,input);
	return count;
}

/* up_load */
static ssize_t store_up_load(struct kobject *a, struct attribute *b,
					const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,101),0);

	if (input == atomic_read(&darkness_tuners_ins.up_load))
		return count;

	atomic_set(&darkness_tuners_ins.up_load,input);

	return count;
}

/* down_load */
static ssize_t store_down_load(struct kobject *a, struct attribute *b,
					const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;
	
	input = max(min(input,101),0);

	if (input == atomic_read(&darkness_tuners_ins.down_load))
		return count;

	atomic_set(&darkness_tuners_ins.down_load,input);
>>>>>>> fbcc943a684b... :wolf: add darkness governor

	return count;
}

<<<<<<< HEAD
static ssize_t show_timer_slack(struct cpufreq_darkness_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->timer_slack_val);
}

static ssize_t store_timer_slack(struct cpufreq_darkness_tunables *tunables,
		const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtol(buf, 10, &val);
	if (ret < 0)
		return ret;

	tunables->timer_slack_val = val;
	return count;
}

static ssize_t show_io_is_busy(struct cpufreq_darkness_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%u\n", tunables->io_is_busy);
}

static ssize_t store_io_is_busy(struct cpufreq_darkness_tunables *tunables,
		const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	tunables->io_is_busy = val;

	return count;
}

/*
 * Create show/store routines
 * - sys: One governor instance for complete SYSTEM
 * - pol: One governor instance per struct cpufreq_policy
 */
#define show_gov_pol_sys(file_name)					\
static ssize_t show_##file_name##_gov_sys				\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return show_##file_name(common_tunables, buf);			\
}									\
									\
static ssize_t show_##file_name##_gov_pol				\
(struct cpufreq_policy *policy, char *buf)				\
{									\
	return show_##file_name(policy->governor_data, buf);		\
}

#define store_gov_pol_sys(file_name)					\
static ssize_t store_##file_name##_gov_sys				\
(struct kobject *kobj, struct attribute *attr, const char *buf,		\
	size_t count)							\
{									\
	return store_##file_name(common_tunables, buf, count);		\
}									\
									\
static ssize_t store_##file_name##_gov_pol				\
(struct cpufreq_policy *policy, const char *buf, size_t count)		\
{									\
	return store_##file_name(policy->governor_data, buf, count);	\
}

#define show_store_gov_pol_sys(file_name)				\
show_gov_pol_sys(file_name);						\
store_gov_pol_sys(file_name)

show_store_gov_pol_sys(timer_rate);
show_store_gov_pol_sys(timer_slack);
show_store_gov_pol_sys(io_is_busy);
show_store_gov_pol_sys(align_windows);

#define gov_sys_attr_rw(_name)						\
static struct global_attr _name##_gov_sys =				\
__ATTR(_name, 0644, show_##_name##_gov_sys, store_##_name##_gov_sys)

#define gov_pol_attr_rw(_name)						\
static struct freq_attr _name##_gov_pol =				\
__ATTR(_name, 0644, show_##_name##_gov_pol, store_##_name##_gov_pol)

#define gov_sys_pol_attr_rw(_name)					\
	gov_sys_attr_rw(_name);						\
	gov_pol_attr_rw(_name)

gov_sys_pol_attr_rw(timer_rate);
gov_sys_pol_attr_rw(timer_slack);
gov_sys_pol_attr_rw(io_is_busy);
gov_sys_pol_attr_rw(align_windows);

/* One Governor instance for entire system */
static struct attribute *darkness_attributes_gov_sys[] = {
	&timer_rate_gov_sys.attr,
	&timer_slack_gov_sys.attr,
	&io_is_busy_gov_sys.attr,
	&align_windows_gov_sys.attr,
	NULL,
};

static struct attribute_group darkness_attr_group_gov_sys = {
	.attrs = darkness_attributes_gov_sys,
	.name = "darkness",
};

/* Per policy governor instance */
static struct attribute *darkness_attributes_gov_pol[] = {
	&timer_rate_gov_pol.attr,
	&timer_slack_gov_pol.attr,
	&io_is_busy_gov_pol.attr,
	&align_windows_gov_pol.attr,
	NULL,
};

static struct attribute_group darkness_attr_group_gov_pol = {
	.attrs = darkness_attributes_gov_pol,
	.name = "darkness",
};

static struct attribute_group *get_sysfs_attr(void)
{
	if (have_governor_per_policy())
		return &darkness_attr_group_gov_pol;
	else
		return &darkness_attr_group_gov_sys;
}

static void cpufreq_darkness_nop_timer(unsigned long data)
{
}

static struct cpufreq_darkness_tunables *alloc_tunable(
					struct cpufreq_policy *policy)
{
	struct cpufreq_darkness_tunables *tunables;

	tunables = kzalloc(sizeof(*tunables), GFP_KERNEL);
	if (!tunables)
		return ERR_PTR(-ENOMEM);

	tunables->timer_rate = DEFAULT_TIMER_RATE;
	tunables->timer_rate_prev = DEFAULT_TIMER_RATE;
	tunables->timer_slack_val = DEFAULT_TIMER_SLACK;

	return tunables;
}

static struct cpufreq_darkness_policyinfo *get_policyinfo(
					struct cpufreq_policy *policy)
{
	struct cpufreq_darkness_policyinfo *ppol =
				per_cpu(polinfo, policy->cpu);
	int i;
	unsigned long *busy;

	/* polinfo already allocated for policy, return */
	if (ppol)
		return ppol;

	ppol = kzalloc(sizeof(*ppol), GFP_KERNEL);
	if (!ppol)
		return ERR_PTR(-ENOMEM);

	busy = kcalloc(cpumask_weight(policy->related_cpus), sizeof(*busy),
		       GFP_KERNEL);
	if (!busy) {
		kfree(ppol);
		return ERR_PTR(-ENOMEM);
	}
	ppol->cpu_busy_times = busy;

	init_timer_deferrable(&ppol->policy_timer);
	ppol->policy_timer.function = cpufreq_darkness_timer;
	init_timer(&ppol->policy_slack_timer);
	ppol->policy_slack_timer.function = cpufreq_darkness_nop_timer;
	spin_lock_init(&ppol->load_lock);
	spin_lock_init(&ppol->target_freq_lock);
	init_rwsem(&ppol->enable_sem);

	for_each_cpu(i, policy->related_cpus)
		per_cpu(polinfo, i) = ppol;
	return ppol;
}

/* This function is not multithread-safe. */
static void free_policyinfo(int cpu)
{
	struct cpufreq_darkness_policyinfo *ppol = per_cpu(polinfo, cpu);
	int j;

	if (!ppol)
		return;

	for_each_possible_cpu(j)
		if (per_cpu(polinfo, j) == ppol)
			per_cpu(polinfo, cpu) = NULL;
	kfree(ppol->cached_tunables);
	kfree(ppol->cpu_busy_times);
	kfree(ppol);
}

static struct cpufreq_darkness_tunables *get_tunables(
				struct cpufreq_darkness_policyinfo *ppol)
{
	if (have_governor_per_policy())
		return ppol->cached_tunables;
	else
		return cached_common_tunables;
}

static int cpufreq_governor_darkness(struct cpufreq_policy *policy,
		unsigned int event)
{
	int rc;
	struct cpufreq_darkness_policyinfo *ppol;
	struct cpufreq_frequency_table *freq_table;
	struct cpufreq_darkness_tunables *tunables;
	unsigned long flags;

	if (have_governor_per_policy())
		tunables = policy->governor_data;
	else
		tunables = common_tunables;

	BUG_ON(!tunables && (event != CPUFREQ_GOV_POLICY_INIT));

	switch (event) {
	case CPUFREQ_GOV_POLICY_INIT:
		ppol = get_policyinfo(policy);
		if (IS_ERR(ppol))
			return PTR_ERR(ppol);

		if (have_governor_per_policy()) {
			WARN_ON(tunables);
		} else if (tunables) {
			tunables->usage_count++;
			policy->governor_data = tunables;
			return 0;
		}

		tunables = get_tunables(ppol);
		if (!tunables) {
			tunables = alloc_tunable(policy);
			if (IS_ERR(tunables))
				return PTR_ERR(tunables);
		}

		tunables->usage_count = 1;
		policy->governor_data = tunables;
		if (!have_governor_per_policy()) {
			common_tunables = tunables;
			WARN_ON(cpufreq_get_global_kobject());
		}

		rc = sysfs_create_group(get_governor_parent_kobj(policy),
				get_sysfs_attr());
		if (rc) {
			kfree(tunables);
			policy->governor_data = NULL;
			if (!have_governor_per_policy()) {
				common_tunables = NULL;
				cpufreq_put_global_kobject();
			}
			return rc;
		}

		if (!policy->governor->initialized)
			cpufreq_register_notifier(&cpufreq_notifier_block,
					CPUFREQ_TRANSITION_NOTIFIER);

		if (have_governor_per_policy())
			ppol->cached_tunables = tunables;
		else
			cached_common_tunables = tunables;

		break;

	case CPUFREQ_GOV_POLICY_EXIT:
		if (!--tunables->usage_count) {
			if (policy->governor->initialized == 1)
				cpufreq_unregister_notifier(&cpufreq_notifier_block,
						CPUFREQ_TRANSITION_NOTIFIER);

			sysfs_remove_group(get_governor_parent_kobj(policy),
					get_sysfs_attr());

			if (!have_governor_per_policy())
				cpufreq_put_global_kobject();
			common_tunables = NULL;
		}

		policy->governor_data = NULL;

		break;

	case CPUFREQ_GOV_START:
		mutex_lock(&gov_lock);

		freq_table = cpufreq_frequency_get_table(policy->cpu);

		ppol = per_cpu(polinfo, policy->cpu);
		ppol->policy = policy;
		ppol->target_freq = policy->cur;
		ppol->freq_table = freq_table;
		ppol->min_freq = policy->min;
		ppol->reject_notification = true;
		down_write(&ppol->enable_sem);
		del_timer_sync(&ppol->policy_timer);
		del_timer_sync(&ppol->policy_slack_timer);
		ppol->policy_timer.data = policy->cpu;
		ppol->last_evaluated_jiffy = get_jiffies_64();
		cpufreq_darkness_timer_start(tunables, policy->cpu);
		ppol->governor_enabled = 1;
		up_write(&ppol->enable_sem);
		ppol->reject_notification = false;

		mutex_unlock(&gov_lock);
		break;

	case CPUFREQ_GOV_STOP:
		mutex_lock(&gov_lock);

		ppol = per_cpu(polinfo, policy->cpu);
		ppol->reject_notification = true;
		down_write(&ppol->enable_sem);
		ppol->governor_enabled = 0;
		ppol->target_freq = 0;
		del_timer_sync(&ppol->policy_timer);
		del_timer_sync(&ppol->policy_slack_timer);
		up_write(&ppol->enable_sem);
		ppol->reject_notification = false;

		mutex_unlock(&gov_lock);
		break;

	case CPUFREQ_GOV_LIMITS:
		ppol = per_cpu(polinfo, policy->cpu);

		__cpufreq_driver_target(policy,
				policy->cur, CPUFREQ_RELATION_L);

		down_read(&ppol->enable_sem);
		if (ppol->governor_enabled) {
			spin_lock_irqsave(&ppol->target_freq_lock, flags);
			if (policy->max < ppol->target_freq)
				ppol->target_freq = policy->max;
			else if (policy->min >= ppol->target_freq)
				ppol->target_freq = policy->min;
			spin_unlock_irqrestore(&ppol->target_freq_lock, flags);

			if (policy->min < ppol->min_freq)
				cpufreq_darkness_timer_resched(policy->cpu,
								  true);
			ppol->min_freq = policy->min;
		}

		up_read(&ppol->enable_sem);
=======
/* up_sf_step */
static ssize_t store_up_sf_step(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,99),0);

	if (input == atomic_read(&darkness_tuners_ins.up_sf_step))
		return count;

	 atomic_set(&darkness_tuners_ins.up_sf_step,input);

	return count;
}

/* down_sf_step */
static ssize_t store_down_sf_step(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,99),0);

	if (input == atomic_read(&darkness_tuners_ins.down_sf_step))
		return count;

	atomic_set(&darkness_tuners_ins.down_sf_step,input);

	return count;
}

/* force_freqs_step */
static ssize_t store_force_freqs_step(struct kobject *a, struct attribute *b,
					const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;
	
	input = max(min(input,3),0);

	if (input == atomic_read(&darkness_tuners_ins.force_freqs_step))
		return count;

	atomic_set(&darkness_tuners_ins.force_freqs_step,input);

	return count;
}

/* onecoresuspend */
static ssize_t store_onecoresuspend(struct kobject *a, struct attribute *b,
				  const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = input > 0; 

	if (atomic_read(&darkness_tuners_ins.onecoresuspend) == input)
		return count;

	atomic_set(&darkness_tuners_ins.onecoresuspend, input);

	return count;
}

/* min_freq_limit */
static ssize_t store_min_freq_limit(struct kobject *a, struct attribute *b,
					const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;
	
	input = max(min(input,atomic_read(&darkness_tuners_ins.max_freq_limit)),0);

	if (input == atomic_read(&darkness_tuners_ins.min_freq_limit))
		return count;

	atomic_set(&darkness_tuners_ins.min_freq_limit,input);

	return count;
}

/* max_freq_limit */
static ssize_t store_max_freq_limit(struct kobject *a, struct attribute *b,
					const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;
	
	input = max(min(input,1600000),atomic_read(&darkness_tuners_ins.min_freq_limit));

	if (input == atomic_read(&darkness_tuners_ins.max_freq_limit))
		return count;

	atomic_set(&darkness_tuners_ins.max_freq_limit,input);

	return count;
}

define_one_global_rw(sampling_rate);
define_one_global_rw(hotplug_enable);
define_one_global_rw(cpu_up_rate);
define_one_global_rw(cpu_down_rate);
define_one_global_rw(up_load);
define_one_global_rw(down_load);
define_one_global_rw(up_sf_step);
define_one_global_rw(down_sf_step);
define_one_global_rw(force_freqs_step);
define_one_global_rw(onecoresuspend);
define_one_global_rw(min_freq_limit);
define_one_global_rw(max_freq_limit);

static struct attribute *darkness_attributes[] = {
	&sampling_rate.attr,
	&hotplug_enable.attr,
	&hotplug_freq_1_1.attr,
	&hotplug_freq_2_0.attr,
#ifndef CONFIG_CPU_EXYNOS4210
	&hotplug_freq_2_1.attr,
	&hotplug_freq_3_0.attr,
	&hotplug_freq_3_1.attr,
	&hotplug_freq_4_0.attr,
#endif
	&cpu_up_rate.attr,
	&cpu_down_rate.attr,
	&up_load.attr,
	&down_load.attr,
	&up_sf_step.attr,
	&down_sf_step.attr,
	&force_freqs_step.attr,
	&onecoresuspend.attr,
	&min_freq_limit.attr,
	&max_freq_limit.attr,
	NULL
};

static struct attribute_group darkness_attr_group = {
	.attrs = darkness_attributes,
	.name = "darkness",
};

/************************** sysfs end ************************/

static void darkness_check_cpu(struct cpufreq_darkness_cpuinfo *this_darkness_cpuinfo)
{
	int up_rate = atomic_read(&darkness_tuners_ins.cpu_up_rate);
	int down_rate = atomic_read(&darkness_tuners_ins.cpu_down_rate);
	bool onecoresuspend = atomic_read(&darkness_tuners_ins.onecoresuspend) > 0;
	bool hotplug_enable = atomic_read(&darkness_tuners_ins.hotplug_enable) > 0;
	int force_freq_steps = atomic_read(&darkness_tuners_ins.force_freqs_step);
	unsigned int min_freq = atomic_read(&darkness_tuners_ins.min_freq_limit);
	unsigned int max_freq = atomic_read(&darkness_tuners_ins.max_freq_limit);
	int up_sf_step = atomic_read(&darkness_tuners_ins.up_sf_step);
	int down_sf_step = atomic_read(&darkness_tuners_ins.down_sf_step);
	unsigned int next_freq[NR_CPUS];
	int cur_load[NR_CPUS];
	int num_core = num_online_cpus();
	unsigned int j,i;

	for_each_cpu(j, cpu_online_mask) {
		struct cpufreq_darkness_cpuinfo *j_darkness_cpuinfo = &per_cpu(od_darkness_cpuinfo, j);
		struct cpufreq_policy *cpu_policy = per_cpu(cpufreq_cpu_data, j);
		unsigned long cur_user_time, cur_system_time, cur_others_time, cur_idle_time, cur_iowait_time;
		unsigned int busy_time, idle_time;
		unsigned int tmp_freq;
		unsigned long flags;

		local_irq_save(flags);
		cur_user_time = (__force unsigned long)(kcpustat_cpu(j).cpustat[CPUTIME_USER]);
		cur_system_time = (__force unsigned long)(kcpustat_cpu(j).cpustat[CPUTIME_SYSTEM]);
		cur_others_time = (__force unsigned long)(kcpustat_cpu(j).cpustat[CPUTIME_IRQ] + kcpustat_cpu(j).cpustat[CPUTIME_SOFTIRQ]
																		+ kcpustat_cpu(j).cpustat[CPUTIME_STEAL] + kcpustat_cpu(j).cpustat[CPUTIME_NICE]);

		cur_idle_time = (__force unsigned long)(kcpustat_cpu(j).cpustat[CPUTIME_IDLE]);
		cur_iowait_time = (__force unsigned long)(kcpustat_cpu(j).cpustat[CPUTIME_IOWAIT]);
		local_irq_restore(flags);

		busy_time = (unsigned int)
				((cur_user_time - j_darkness_cpuinfo->prev_cpu_user) +
				 (cur_system_time - j_darkness_cpuinfo->prev_cpu_system) +
				 (cur_others_time - j_darkness_cpuinfo->prev_cpu_others));
		j_darkness_cpuinfo->prev_cpu_user = cur_user_time;
		j_darkness_cpuinfo->prev_cpu_system = cur_system_time;
		j_darkness_cpuinfo->prev_cpu_others = cur_others_time;

		idle_time = (unsigned int)
				((cur_idle_time - j_darkness_cpuinfo->prev_cpu_idle) + 
				 (cur_iowait_time - j_darkness_cpuinfo->prev_cpu_iowait));
		j_darkness_cpuinfo->prev_cpu_idle = cur_idle_time;
		j_darkness_cpuinfo->prev_cpu_iowait = cur_iowait_time;

		/*printk(KERN_ERR "TIMER CPU[%u], wall[%u], idle[%u]\n",j, busy_time + idle_time, idle_time);*/
		if (!cpu_policy || busy_time + idle_time == 0) { /*if busy_time and idle_time are 0, evaluate cpu load next time*/
			hotplug_enable = false;
			continue;
		}
		cur_load[j] = busy_time ? (100 * busy_time) / (busy_time + idle_time) : 1;/*if busy_time is 0 cpu_load is equal to 1*/
		/* Checking Frequency Limit */
		if (max_freq > cpu_policy->max || max_freq < cpu_policy->min)
			max_freq = cpu_policy->max;
		if (min_freq < cpu_policy->min || min_freq > cpu_policy->max)
			min_freq = cpu_policy->min;
		/* CPUs Online Scale Frequency*/
		tmp_freq = max(min(cur_load[j] * (max_freq / 100), max_freq), min_freq);
		if (force_freq_steps == 0) {
			next_freq[j] = (tmp_freq / 100000) * 100000;
			if ((next_freq[j] > cpu_policy->cur
				&& (tmp_freq % 100000 > up_sf_step * 1000))
				|| (next_freq[j] < cpu_policy->cur 
				&& (tmp_freq % 100000 > down_sf_step * 1000))) {
					next_freq[j] += 100000;
			}
		} else {
			for (i = 0; i < 16; i++) {
				if (tmp_freq >= freqs_step[i][force_freq_steps]) {
					next_freq[j] = freqs_step[i][force_freq_steps];
					break;
				}
			}
		}		
		/*printk(KERN_ERR "FREQ CALC.: CPU[%u], load[%d], target freq[%u], cur freq[%u], min freq[%u], max_freq[%u]\n",j, cur_load[j], next_freq[j], cpu_policy->cur, cpu_policy->min, max_freq); */
		if (next_freq[j] != cpu_policy->cur) {
			__cpufreq_driver_target(cpu_policy, next_freq[j], CPUFREQ_RELATION_L);
		}
	}

	/* set num_rate used */
	++num_rate;

	if (hotplug_enable) {
		/*Check for CPU hotplug*/
		if (!onecoresuspend && num_rate % up_rate == 0 && num_core < NR_CPUS) {
#ifndef CONFIG_CPU_EXYNOS4210
			if (cur_load[num_core - 1] >= atomic_read(&darkness_tuners_ins.up_load)
				&& next_freq[num_core - 1] >= atomic_read(&hotplug_freq[num_core - 1][HOTPLUG_UP_INDEX])) {
				/* printk(KERN_ERR "[HOTPLUG IN] %s %u>=%u\n",
					__func__, cur_freq, up_freq); */
				if (!cpu_online(num_core)) {
					cpu_up(num_core);
					num_rate = 0;
				}
			}
#else
			if (cur_load[0] >= atomic_read(&darkness_tuners_ins.up_load)
				&& next_freq[0] >= atomic_read(&hotplug_freq[0][HOTPLUG_UP_INDEX])) {
				/* printk(KERN_ERR "[HOTPLUG IN] %s %u>=%u\n",
					__func__, cur_freq, up_freq); */
				if (!cpu_online(1)) {
					cpu_up(1);
					num_rate = 0;
				}
			}
#endif
		} else if (num_rate % down_rate == 0 && num_core > 1) {
#ifndef CONFIG_CPU_EXYNOS4210	
			if (onecoresuspend 
				|| cur_load[num_core - 1] < atomic_read(&darkness_tuners_ins.down_load) 
				|| next_freq[num_core - 1] <= atomic_read(&hotplug_freq[num_core - 1][HOTPLUG_DOWN_INDEX])) {
				/* printk(KERN_ERR "[HOTPLUG OUT] %s %u<=%u\n",
					__func__, cur_freq, down_freq); */
				if (cpu_online(num_core - 1)) {
					cpu_down(num_core - 1);
					num_rate = 0;
				}
			}
#else
			if (onecoresuspend 
				|| cur_load[1] < atomic_read(&darkness_tuners_ins.down_load)
				|| next_freq[1] <= atomic_read(&hotplug_freq[1][HOTPLUG_DOWN_INDEX])) {
				/* printk(KERN_ERR "[HOTPLUG OUT] %s %u<=%u\n",
					__func__, cur_freq, down_freq); */
				if (cpu_online(1)) {
					cpu_down(1);
					num_rate = 0;
				}
			}
#endif
		}
	}
	if (num_rate == max(up_rate, down_rate)) {
		num_rate = 0;
	}
}

static void do_darkness_timer(struct work_struct *work)
{
	struct cpufreq_darkness_cpuinfo *darkness_cpuinfo =
		container_of(work, struct cpufreq_darkness_cpuinfo, work.work);
	int delay;

	mutex_lock(&timer_mutex);
	darkness_check_cpu(darkness_cpuinfo);
	/* We want all CPUs to do sampling nearly on
	 * same jiffy
	 */
	delay = usecs_to_jiffies(atomic_read(&darkness_tuners_ins.sampling_rate));
	if (num_online_cpus() > 1) {
		delay -= jiffies % delay;
	}

	mod_delayed_work_on(darkness_cpuinfo->cpu, system_wq, &darkness_cpuinfo->work, delay);
	mutex_unlock(&timer_mutex);
}

static int cpufreq_governor_darkness(struct cpufreq_policy *policy,
				unsigned int event)
{
	unsigned int cpu = policy->cpu;
	struct cpufreq_darkness_cpuinfo *this_darkness_cpuinfo = &per_cpu(od_darkness_cpuinfo, cpu);
	struct cpufreq_policy *cpu_policy = per_cpu(cpufreq_cpu_data, cpu);
	unsigned int j;
	int rc, delay;

	switch (event) {
	case CPUFREQ_GOV_START:
		if ((!cpu_online(cpu)) || (!policy->cur))
			return -EINVAL;

		mutex_lock(&darkness_mutex);
		num_rate = 0;
		darkness_enable=1;
		for_each_cpu(j, cpu_possible_mask) {
			struct cpufreq_darkness_cpuinfo *j_darkness_cpuinfo = &per_cpu(od_darkness_cpuinfo, j);
			unsigned long flags;
			per_cpu(cpufreq_cpu_data, j) = policy;
			local_irq_save(flags);
			j_darkness_cpuinfo->prev_cpu_user = (__force unsigned long)(kcpustat_cpu(j).cpustat[CPUTIME_USER]);
			j_darkness_cpuinfo->prev_cpu_system = (__force unsigned long)(kcpustat_cpu(j).cpustat[CPUTIME_SYSTEM]);
			j_darkness_cpuinfo->prev_cpu_others = (__force unsigned long)(kcpustat_cpu(j).cpustat[CPUTIME_IRQ] + kcpustat_cpu(j).cpustat[CPUTIME_SOFTIRQ]
																		+ kcpustat_cpu(j).cpustat[CPUTIME_STEAL] + kcpustat_cpu(j).cpustat[CPUTIME_NICE]);

			j_darkness_cpuinfo->prev_cpu_idle = (__force unsigned long)(kcpustat_cpu(j).cpustat[CPUTIME_IDLE]);
			j_darkness_cpuinfo->prev_cpu_iowait = (__force unsigned long)(kcpustat_cpu(j).cpustat[CPUTIME_IOWAIT]);
			local_irq_restore(flags);
		}
		this_darkness_cpuinfo->cpu = cpu;
		mutex_init(&timer_mutex);
		INIT_DEFERRABLE_WORK(&this_darkness_cpuinfo->work, do_darkness_timer);
		/*
		 * Start the timerschedule work, when this governor
		 * is used for first time
		 */
		if (darkness_enable == 1) {
			rc = sysfs_create_group(cpufreq_global_kobject,
						&darkness_attr_group);
			if (rc) {
				mutex_unlock(&darkness_mutex);
				return rc;
			}
			atomic_set(&darkness_tuners_ins.min_freq_limit,policy->min);
			atomic_set(&darkness_tuners_ins.max_freq_limit,policy->max);
		}
		delay=usecs_to_jiffies(atomic_read(&darkness_tuners_ins.sampling_rate));
		if (num_online_cpus() > 1) {
			delay -= jiffies % delay;
		}
		mutex_unlock(&darkness_mutex);
		mod_delayed_work_on(this_darkness_cpuinfo->cpu, system_wq, &this_darkness_cpuinfo->work, delay);

		break;

	case CPUFREQ_GOV_STOP:
		cancel_delayed_work_sync(&this_darkness_cpuinfo->work);
		mutex_destroy(&timer_mutex);
		mutex_lock(&darkness_mutex);
		darkness_enable=0;
		for_each_cpu(j, cpu_possible_mask) {
			per_cpu(cpufreq_cpu_data, j) = NULL;
		}

		if (!darkness_enable) {
			sysfs_remove_group(cpufreq_global_kobject,
					   &darkness_attr_group);
		}
		mutex_unlock(&darkness_mutex);
		
		break;

	case CPUFREQ_GOV_LIMITS:
		if(!cpu_policy) {
			break;
		}
		mutex_lock(&timer_mutex);
		if (policy->max < cpu_policy->cur)
			__cpufreq_driver_target(cpu_policy,
				policy->max, CPUFREQ_RELATION_H);
		else if (policy->min > cpu_policy->cur)
			__cpufreq_driver_target(cpu_policy,
				policy->min, CPUFREQ_RELATION_L);
		mutex_unlock(&timer_mutex);
>>>>>>> fbcc943a684b... :wolf: add darkness governor

		break;
	}
	return 0;
}

<<<<<<< HEAD
#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_DARKNESS
static
#endif
struct cpufreq_governor cpufreq_gov_darkness = {
	.name = "darkness",
	.governor = cpufreq_governor_darkness,
	.max_transition_latency = 10000000,
	.owner = THIS_MODULE,
};

static int __init cpufreq_darkness_init(void)
{
	struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 };

	spin_lock_init(&speedchange_cpumask_lock);
	mutex_init(&gov_lock);
	speedchange_task =
		kthread_create(cpufreq_darkness_speedchange_task, NULL,
			       "cfdarkness");
	if (IS_ERR(speedchange_task))
		return PTR_ERR(speedchange_task);

	sched_setscheduler_nocheck(speedchange_task, SCHED_FIFO, &param);
	get_task_struct(speedchange_task);

	/* NB: wake up so the thread does not look hung to the freezer */
	wake_up_process_no_notif(speedchange_task);

	return cpufreq_register_governor(&cpufreq_gov_darkness);
}

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_DARKNESS
fs_initcall(cpufreq_darkness_init);
#else
module_init(cpufreq_darkness_init);
#endif

static void __exit cpufreq_darkness_exit(void)
{
	int cpu;

	cpufreq_unregister_governor(&cpufreq_gov_darkness);
	kthread_stop(speedchange_task);
	put_task_struct(speedchange_task);

	for_each_possible_cpu(cpu)
		free_policyinfo(cpu);
}

module_exit(cpufreq_darkness_exit);

MODULE_AUTHOR("Alucard24 <dmbaoh2@gmail.com>");
MODULE_DESCRIPTION("'cpufreq_darkness' - A dynamic cpufreq governor v7.0");
MODULE_LICENSE("GPLv2");
=======
static int __init cpufreq_gov_darkness_init(void)
{
	int ret;

	ret = cpufreq_register_governor(&cpufreq_gov_darkness);
	if (ret)
		goto err_free;

	return ret;

err_free:
	kfree(&darkness_tuners_ins);
	kfree(&hotplug_freq);
	return ret;
}

static void __exit cpufreq_gov_darkness_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_darkness);
	kfree(&darkness_tuners_ins);
	kfree(&hotplug_freq);
}

MODULE_AUTHOR("Alucard24@XDA");
MODULE_DESCRIPTION("'cpufreq_darkness' - A dynamic cpufreq/cpuhotplug governor v.1.5");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_darkness
fs_initcall(cpufreq_gov_darkness_init);
#else
module_init(cpufreq_gov_darkness_init);
#endif
module_exit(cpufreq_gov_darkness_exit);
>>>>>>> fbcc943a684b... :wolf: add darkness governor
