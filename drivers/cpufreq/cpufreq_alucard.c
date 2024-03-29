/*
<<<<<<< HEAD
 *  drivers/cpufreq/cpufreq_alucard.c
 *
 *  Copyright (C)  2011 Samsung Electronics co. ltd
 *    ByungChang Cha <bc.cha@samsung.com>
 *
 *  Based on ondemand governor
 *  Copyright (C)  2001 Russell King
 *            (C)  2003 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>.
 *                      Jun Nakajima <jun.nakajima@intel.com>
=======
 * Alucard - Load Sensitive CPU Frequency Governor
 *
 * Copyright (c) 2011-2016, Alucard24 <dmbaoh2@gmail.com>
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
<<<<<<< HEAD
 * Created by Alucard_24@xda
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
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

/* Tuning Interface */
#ifdef CONFIG_MACH_LGE
#define FREQ_RESPONSIVENESS		2265600
#else
#define FREQ_RESPONSIVENESS		998400
#endif

#define CPUS_DOWN_RATE			3
#define CPUS_UP_RATE			1

#define DEC_CPU_LOAD			90
#define DEC_CPU_LOAD_AT_MIN_FREQ	60

#define INC_CPU_LOAD			90
#define INC_CPU_LOAD_AT_MIN_FREQ	60

/* Pump Inc/Dec for all cores */
#define PUMP_INC_STEP_AT_MIN_FREQ	3
#define PUMP_INC_STEP			2
#define PUMP_DEC_STEP_AT_MIN_FREQ	2
#define PUMP_DEC_STEP			1

/* sample rate */
#define MIN_SAMPLING_RATE		10000
#define SAMPLING_RATE			50000

static void do_alucard_timer(struct work_struct *work);

struct cpufreq_alucard_cpuinfo {
	u64 prev_cpu_wall;
	u64 prev_cpu_idle;
	struct cpufreq_frequency_table *freq_table;
	struct delayed_work work;
	struct cpufreq_policy *cur_policy;
=======
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

struct cpufreq_alucard_policyinfo {
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
	struct cpufreq_alucard_tunables *cached_tunables;
	unsigned long *cpu_busy_times;
	unsigned int up_rate;
	unsigned int down_rate;
};

/* Protected by per-policy load_lock */
struct cpufreq_alucard_cpuinfo {
	u64 time_in_idle;
	u64 time_in_idle_timestamp;
	unsigned int load;
};

static DEFINE_PER_CPU(struct cpufreq_alucard_policyinfo *, polinfo);
static DEFINE_PER_CPU(struct cpufreq_alucard_cpuinfo, cpuinfo);

/* realtime thread handles frequency scaling */
static struct task_struct *speedchange_task;
static cpumask_t speedchange_cpumask;
static spinlock_t speedchange_cpumask_lock;
static struct mutex gov_lock;

#define DEFAULT_TIMER_RATE (20 * USEC_PER_MSEC)
#define DEFAULT_TIMER_RATE_SUSP ((unsigned long)(50 * USEC_PER_MSEC))

#define FREQ_RESPONSIVENESS		 768000
#define FREQ_RESPONSIVENESS_MAX		1094400
#define FREQ_RESPONSIVENESS_BIGC	 960000
#define FREQ_RESPONSIVENESS_MAX_BIGC	1401000

#define CPUS_DOWN_RATE				1
#define CPUS_UP_RATE				1

#define PUMP_INC_STEP_AT_MIN_FREQ	2
#define PUMP_INC_STEP				1
#define PUMP_DEC_STEP_AT_MIN_FREQ	1
#define PUMP_DEC_STEP				2

struct cpufreq_alucard_tunables {
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
	/*
	 * CPUs frequency scaling
	 */
	int freq_responsiveness;
	int freq_responsiveness_max;
	unsigned int cpus_up_rate_at_max_freq;
	unsigned int cpus_up_rate;
	unsigned int cpus_down_rate_at_max_freq;
	unsigned int cpus_down_rate;
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors
	int pump_inc_step;
	int pump_inc_step_at_min_freq;
	int pump_dec_step;
	int pump_dec_step_at_min_freq;
<<<<<<< HEAD
	bool governor_enabled;
	unsigned int up_rate;
	unsigned int down_rate;
	unsigned int cpu;
	unsigned int min_index;
	unsigned int max_index;
	/*
	 * mutex that serializes governor limit change with
	 * do_alucard_timer invocation. We do not want do_alucard_timer to run
	 * when user is changing the governor or limits.
	 */
	struct mutex timer_mutex;
};

static DEFINE_PER_CPU(struct cpufreq_alucard_cpuinfo, od_alucard_cpuinfo);

static unsigned int alucard_enable;	/* number of CPUs using this policy */
/*
 * alucard_mutex protects alucard_enable in governor start/stop.
 */
static DEFINE_MUTEX(alucard_mutex);

static struct workqueue_struct *alucard_wq;

/* alucard tuners */
static struct alucard_tuners {
	unsigned int sampling_rate;
	int inc_cpu_load_at_min_freq;
	int inc_cpu_load;
	int dec_cpu_load_at_min_freq;
	int dec_cpu_load;
	int freq_responsiveness;
	unsigned int cpus_up_rate;
	unsigned int cpus_down_rate;
} alucard_tuners_ins = {
	.sampling_rate = SAMPLING_RATE,
	.inc_cpu_load_at_min_freq = INC_CPU_LOAD_AT_MIN_FREQ,
	.inc_cpu_load = INC_CPU_LOAD,
	.dec_cpu_load_at_min_freq = DEC_CPU_LOAD_AT_MIN_FREQ,
	.dec_cpu_load = DEC_CPU_LOAD,
	.freq_responsiveness = FREQ_RESPONSIVENESS,
	.cpus_up_rate = CPUS_UP_RATE,
	.cpus_down_rate = CPUS_DOWN_RATE,
};

/************************** sysfs interface ************************/

/* cpufreq_alucard Governor Tunables */
#define show_one(file_name, object)					\
static ssize_t show_##file_name						\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return sprintf(buf, "%d\n", alucard_tuners_ins.object);		\
}
show_one(sampling_rate, sampling_rate);
show_one(inc_cpu_load_at_min_freq, inc_cpu_load_at_min_freq);
show_one(inc_cpu_load, inc_cpu_load);
show_one(dec_cpu_load_at_min_freq, dec_cpu_load_at_min_freq);
show_one(dec_cpu_load, dec_cpu_load);
show_one(freq_responsiveness, freq_responsiveness);
show_one(cpus_up_rate, cpus_up_rate);
show_one(cpus_down_rate, cpus_down_rate);

#define show_pcpu_param(file_name, num_core)		\
static ssize_t show_##file_name##_##num_core		\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	struct cpufreq_alucard_cpuinfo *this_alucard_cpuinfo = &per_cpu(od_alucard_cpuinfo, num_core - 1); \
	return sprintf(buf, "%d\n", \
			this_alucard_cpuinfo->file_name);		\
}

show_pcpu_param(pump_inc_step_at_min_freq, 1);
show_pcpu_param(pump_inc_step_at_min_freq, 2);
show_pcpu_param(pump_inc_step_at_min_freq, 3);
show_pcpu_param(pump_inc_step_at_min_freq, 4);
show_pcpu_param(pump_inc_step, 1);
show_pcpu_param(pump_inc_step, 2);
show_pcpu_param(pump_inc_step, 3);
show_pcpu_param(pump_inc_step, 4);
show_pcpu_param(pump_dec_step_at_min_freq, 1);
show_pcpu_param(pump_dec_step_at_min_freq, 2);
show_pcpu_param(pump_dec_step_at_min_freq, 3);
show_pcpu_param(pump_dec_step_at_min_freq, 4);
show_pcpu_param(pump_dec_step, 1);
show_pcpu_param(pump_dec_step, 2);
show_pcpu_param(pump_dec_step, 3);
show_pcpu_param(pump_dec_step, 4);

#define store_pcpu_param(file_name, num_core)		\
static ssize_t store_##file_name##_##num_core		\
(struct kobject *kobj, struct attribute *attr,				\
	const char *buf, size_t count)					\
{									\
	int input;						\
	struct cpufreq_alucard_cpuinfo *this_alucard_cpuinfo; \
	int ret;							\
														\
	ret = sscanf(buf, "%d", &input);					\
	if (ret != 1)											\
		return -EINVAL;										\
														\
	this_alucard_cpuinfo = &per_cpu(od_alucard_cpuinfo, num_core - 1); \
														\
	if (input == this_alucard_cpuinfo->file_name) {		\
		return count;						\
	}								\
										\
	this_alucard_cpuinfo->file_name = input;			\
	return count;							\
}


#define store_pcpu_pump_param(file_name, num_core)		\
static ssize_t store_##file_name##_##num_core		\
(struct kobject *kobj, struct attribute *attr,				\
	const char *buf, size_t count)					\
{									\
	int input;						\
	struct cpufreq_alucard_cpuinfo *this_alucard_cpuinfo; \
	int ret;							\
														\
	ret = sscanf(buf, "%d", &input);					\
	if (ret != 1)											\
		return -EINVAL;										\
														\
	input = min(max(1, input), 6);							\
														\
	this_alucard_cpuinfo = &per_cpu(od_alucard_cpuinfo, num_core - 1); \
														\
	if (input == this_alucard_cpuinfo->file_name) {		\
		return count;						\
	}								\
										\
	this_alucard_cpuinfo->file_name = input;			\
	return count;							\
}

store_pcpu_pump_param(pump_inc_step_at_min_freq, 1);
store_pcpu_pump_param(pump_inc_step_at_min_freq, 2);
store_pcpu_pump_param(pump_inc_step_at_min_freq, 3);
store_pcpu_pump_param(pump_inc_step_at_min_freq, 4);
store_pcpu_pump_param(pump_inc_step, 1);
store_pcpu_pump_param(pump_inc_step, 2);
store_pcpu_pump_param(pump_inc_step, 3);
store_pcpu_pump_param(pump_inc_step, 4);
store_pcpu_pump_param(pump_dec_step_at_min_freq, 1);
store_pcpu_pump_param(pump_dec_step_at_min_freq, 2);
store_pcpu_pump_param(pump_dec_step_at_min_freq, 3);
store_pcpu_pump_param(pump_dec_step_at_min_freq, 4);
store_pcpu_pump_param(pump_dec_step, 1);
store_pcpu_pump_param(pump_dec_step, 2);
store_pcpu_pump_param(pump_dec_step, 3);
store_pcpu_pump_param(pump_dec_step, 4);

define_one_global_rw(pump_inc_step_at_min_freq_1);
define_one_global_rw(pump_inc_step_at_min_freq_2);
define_one_global_rw(pump_inc_step_at_min_freq_3);
define_one_global_rw(pump_inc_step_at_min_freq_4);
define_one_global_rw(pump_inc_step_1);
define_one_global_rw(pump_inc_step_2);
define_one_global_rw(pump_inc_step_3);
define_one_global_rw(pump_inc_step_4);
define_one_global_rw(pump_dec_step_at_min_freq_1);
define_one_global_rw(pump_dec_step_at_min_freq_2);
define_one_global_rw(pump_dec_step_at_min_freq_3);
define_one_global_rw(pump_dec_step_at_min_freq_4);
define_one_global_rw(pump_dec_step_1);
define_one_global_rw(pump_dec_step_2);
define_one_global_rw(pump_dec_step_3);
define_one_global_rw(pump_dec_step_4);

/* sampling_rate */
static ssize_t store_sampling_rate(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	int input;
	int ret = 0;
	int mpd = strcmp(current->comm, "mpdecision");

	if (mpd == 0)
		return ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(input, 10000);

	if (input == alucard_tuners_ins.sampling_rate)
		return count;

	alucard_tuners_ins.sampling_rate = input;
=======
};

/* For cases where we have single governor instance for system */
static struct cpufreq_alucard_tunables *common_tunables;
static struct cpufreq_alucard_tunables *cached_common_tunables;

static struct attribute_group *get_sysfs_attr(void);

/* Round to starting jiffy of next evaluation window */
static u64 round_to_nw_start(u64 jif,
			     struct cpufreq_alucard_tunables *tunables)
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

static void cpufreq_alucard_timer_resched(unsigned long cpu,
					      bool slack_only)
{
	struct cpufreq_alucard_policyinfo *ppol = per_cpu(polinfo, cpu);
	struct cpufreq_alucard_cpuinfo *pcpu;
	struct cpufreq_alucard_tunables *tunables =
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
static void cpufreq_alucard_timer_start(
	struct cpufreq_alucard_tunables *tunables, int cpu)
{
	struct cpufreq_alucard_policyinfo *ppol = per_cpu(polinfo, cpu);
	struct cpufreq_alucard_cpuinfo *pcpu;
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

static unsigned int choose_target_freq(struct cpufreq_alucard_policyinfo *pcpu,
					unsigned int step, bool isup)
{
	struct cpufreq_policy *policy = pcpu->policy;
	struct cpufreq_frequency_table *table = pcpu->freq_table;
	struct cpufreq_frequency_table *pos;
	unsigned int target_freq = 0, freq;
	int i = 0, t = 0;

	if (!policy || !table || !step)
		return 0;

	cpufreq_for_each_valid_entry(pos, table) {
		freq = pos->frequency;
		i = pos - table;
		if (isup) {
			if (freq > policy->cur) {
				target_freq = freq;
				step--;
				if (step == 0) {
					break;
				}
			}
		} else {
			if (freq == policy->cur) {
				for (t = (i - 1); t >= 0; t--) {
					if (table[t].frequency != CPUFREQ_ENTRY_INVALID) {
						target_freq = table[t].frequency;
						step--;
						if (step == 0) {
							break;
						}
					}
				}
				break;
			}
		}
	}
	
	return target_freq;
}

static bool update_load(int cpu)
{
	struct cpufreq_alucard_policyinfo *ppol = per_cpu(polinfo, cpu);
	struct cpufreq_alucard_cpuinfo *pcpu = &per_cpu(cpuinfo, cpu);
	struct cpufreq_alucard_tunables *tunables =
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

static void cpufreq_alucard_timer(unsigned long data)
{
	struct cpufreq_alucard_policyinfo *ppol = per_cpu(polinfo, data);
	struct cpufreq_alucard_tunables *tunables =
		ppol->policy->governor_data;
	struct cpufreq_alucard_cpuinfo *pcpu;
	struct cpufreq_govinfo govinfo;
	unsigned int freq_responsiveness = tunables->freq_responsiveness;
	unsigned int freq_responsiveness_max = tunables->freq_responsiveness_max;
	int target_cpu_load;
	int pump_inc_step = tunables->pump_inc_step;
	int pump_dec_step = tunables->pump_dec_step;
	unsigned int cpus_up_rate = tunables->cpus_up_rate;
	unsigned int cpus_down_rate = tunables->cpus_down_rate;
	unsigned int new_freq = 0;
	unsigned int max_load = 0;
	unsigned long flags;
	unsigned long max_cpu;
	int i, fcpu;
	bool display_on = is_display_on();

	if (!down_read_trylock(&ppol->enable_sem))
		return;
	if (!ppol->governor_enabled)
		goto exit;

	fcpu = cpumask_first(ppol->policy->related_cpus);
	spin_lock_irqsave(&ppol->load_lock, flags);
	ppol->last_evaluated_jiffy = get_jiffies_64();

	if (display_on &&
		tunables->timer_rate != tunables->timer_rate_prev)
		tunables->timer_rate = tunables->timer_rate_prev;
	else if (!display_on &&
		tunables->timer_rate != DEFAULT_TIMER_RATE_SUSP) {
		tunables->timer_rate_prev = tunables->timer_rate;
		tunables->timer_rate
			= max(tunables->timer_rate,
				DEFAULT_TIMER_RATE_SUSP);
	}

	/* CPUs Online Scale Frequency*/
	target_cpu_load = (ppol->policy->cur * 100) / ppol->policy->max;
	if (ppol->policy->cur < freq_responsiveness) {
		pump_inc_step = tunables->pump_inc_step_at_min_freq;
		pump_dec_step = tunables->pump_dec_step_at_min_freq;
	} else if (ppol->policy->cur > freq_responsiveness_max) {
		cpus_up_rate = tunables->cpus_up_rate_at_max_freq;
		cpus_down_rate = tunables->cpus_down_rate_at_max_freq;
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
		govinfo.sampling_rate_us = tunables->timer_rate;
		atomic_notifier_call_chain(&cpufreq_govinfo_notifier_list,
					   CPUFREQ_LOAD_CHANGE, &govinfo);
	}

	/* Check for frequency increase or for frequency decrease */
	spin_lock_irqsave(&ppol->target_freq_lock, flags);
	if (ppol->up_rate > cpus_up_rate)
		ppol->up_rate = 1;
	if (ppol->down_rate > cpus_down_rate)
		ppol->down_rate = 1;

	if (max_load >= target_cpu_load
		 && ppol->policy->cur < ppol->policy->max) {
		if (ppol->up_rate % cpus_up_rate == 0) {
			new_freq = choose_target_freq(ppol,
				pump_inc_step, true);
		} else {
			++ppol->up_rate;
		}
	} else if (max_load < target_cpu_load
				 && ppol->policy->cur > ppol->policy->min) {
		if (ppol->down_rate % cpus_down_rate == 0) {
			new_freq = choose_target_freq(ppol,
				pump_dec_step, false);
		} else {
			++ppol->down_rate;
		}
	} else {
		ppol->up_rate = 1;
		ppol->down_rate = 1;
	}
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
		cpufreq_alucard_timer_resched(data, false);

exit:
	up_read(&ppol->enable_sem);
	return;
}

static int cpufreq_alucard_speedchange_task(void *data)
{
	unsigned int cpu;
	cpumask_t tmp_mask;
	unsigned long flags;
	struct cpufreq_alucard_policyinfo *ppol;

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

static int cpufreq_alucard_notifier(
	struct notifier_block *nb, unsigned long val, void *data)
{
	struct cpufreq_freqs *freq = data;
	struct cpufreq_alucard_policyinfo *ppol;
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
		spin_lock_irqsave(&ppol->target_freq_lock, flags);
		ppol->up_rate = 1;
		ppol->down_rate = 1;
		spin_unlock_irqrestore(&ppol->target_freq_lock, flags);

		up_read(&ppol->enable_sem);
	}
	return 0;
}

static struct notifier_block cpufreq_notifier_block = {
	.notifier_call = cpufreq_alucard_notifier,
};

#define show_store_one(file_name)					\
static ssize_t show_##file_name(					\
	struct cpufreq_alucard_tunables *tunables, char *buf)	\
{									\
	return snprintf(buf, PAGE_SIZE, "%u\n", tunables->file_name);	\
}									\
static ssize_t store_##file_name(					\
		struct cpufreq_alucard_tunables *tunables,		\
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

static ssize_t show_timer_rate(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%lu\n", tunables->timer_rate);
}

static ssize_t store_timer_rate(struct cpufreq_alucard_tunables *tunables,
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

	return count;
}

static ssize_t show_timer_slack(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->timer_slack_val);
}

static ssize_t store_timer_slack(struct cpufreq_alucard_tunables *tunables,
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

static ssize_t show_io_is_busy(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%u\n", tunables->io_is_busy);
}

static ssize_t store_io_is_busy(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	tunables->io_is_busy = val;
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors

	return count;
}

<<<<<<< HEAD
/* inc_cpu_load_at_min_freq */
static ssize_t store_inc_cpu_load_at_min_freq(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
=======
/* freq_responsiveness */
static ssize_t show_freq_responsiveness(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->freq_responsiveness);
}

static ssize_t store_freq_responsiveness(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
<<<<<<< HEAD
	if (ret != 1) {
		return -EINVAL;
	}

	input = min(input, alucard_tuners_ins.inc_cpu_load);

	if (input == alucard_tuners_ins.inc_cpu_load_at_min_freq)
		return count;

	alucard_tuners_ins.inc_cpu_load_at_min_freq = input;
=======
	if (ret != 1)
		return -EINVAL;

	if (input == tunables->freq_responsiveness)
		return count;

	tunables->freq_responsiveness = input;
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors

	return count;
}

<<<<<<< HEAD
/* inc_cpu_load */
static ssize_t store_inc_cpu_load(struct kobject *a, struct attribute *b,
					const char *buf, size_t count)
=======
/* freq_responsiveness_max */
static ssize_t show_freq_responsiveness_max(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->freq_responsiveness_max);
}

static ssize_t store_freq_responsiveness_max(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

<<<<<<< HEAD
	input = max(min(input, 100),0);

	if (input == alucard_tuners_ins.inc_cpu_load)
		return count;

	alucard_tuners_ins.inc_cpu_load = input;
=======
	if (input == tunables->freq_responsiveness_max)
		return count;

	tunables->freq_responsiveness_max = input;
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors

	return count;
}

<<<<<<< HEAD
/* dec_cpu_load_at_min_freq */
static ssize_t store_dec_cpu_load_at_min_freq(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1) {
		return -EINVAL;
	}

	input = min(input, alucard_tuners_ins.dec_cpu_load);

	if (input == alucard_tuners_ins.dec_cpu_load_at_min_freq)
		return count;

	alucard_tuners_ins.dec_cpu_load_at_min_freq = input;
=======

/* cpus_up_rate */
static ssize_t show_cpus_up_rate(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%u\n", tunables->cpus_up_rate);
}

static ssize_t store_cpus_up_rate(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
{
	unsigned int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == tunables->cpus_up_rate)
		return count;

	tunables->cpus_up_rate = input;
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors

	return count;
}

<<<<<<< HEAD
/* dec_cpu_load */
static ssize_t store_dec_cpu_load(struct kobject *a, struct attribute *b,
					const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input, 95),5);

	if (input == alucard_tuners_ins.dec_cpu_load)
		return count;

	alucard_tuners_ins.dec_cpu_load = input;
=======
/* cpus_up_rate_at_max_freq */
static ssize_t show_cpus_up_rate_at_max_freq(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%u\n", tunables->cpus_up_rate_at_max_freq);
}

static ssize_t store_cpus_up_rate_at_max_freq(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
{
	unsigned int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == tunables->cpus_up_rate_at_max_freq)
		return count;

	tunables->cpus_up_rate_at_max_freq = input;
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors

	return count;
}

<<<<<<< HEAD
/* freq_responsiveness */
static ssize_t store_freq_responsiveness(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == alucard_tuners_ins.freq_responsiveness)
		return count;

	alucard_tuners_ins.freq_responsiveness = input;
=======
/* cpus_down_rate */
static ssize_t show_cpus_down_rate(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%u\n", tunables->cpus_down_rate);
}

static ssize_t store_cpus_down_rate(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
{
	unsigned int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == tunables->cpus_down_rate)
		return count;

	tunables->cpus_down_rate = input;
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors

	return count;
}

<<<<<<< HEAD
/* cpus_up_rate */
static ssize_t store_cpus_up_rate(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
=======
/* cpus_down_rate_at_max_freq */
static ssize_t show_cpus_down_rate_at_max_freq(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%u\n", tunables->cpus_down_rate_at_max_freq);
}

static ssize_t store_cpus_down_rate_at_max_freq(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors
{
	unsigned int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

<<<<<<< HEAD
	if (input == alucard_tuners_ins.cpus_up_rate)
		return count;

	alucard_tuners_ins.cpus_up_rate = input;
=======
	if (input == tunables->cpus_down_rate_at_max_freq)
		return count;

	tunables->cpus_down_rate_at_max_freq = input;
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors

	return count;
}

<<<<<<< HEAD
/* cpus_down_rate */
static ssize_t store_cpus_down_rate(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == alucard_tuners_ins.cpus_down_rate)
		return count;

	alucard_tuners_ins.cpus_down_rate = input;
=======
/* pump_inc_step_at_min_freq */
static ssize_t show_pump_inc_step_at_min_freq(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->pump_inc_step_at_min_freq);
}

static ssize_t store_pump_inc_step_at_min_freq(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = min(max(1, input), 6);

	if (input == tunables->pump_inc_step_at_min_freq)
		return count;

	tunables->pump_inc_step_at_min_freq = input;
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors

	return count;
}

<<<<<<< HEAD
define_one_global_rw(sampling_rate);
define_one_global_rw(inc_cpu_load_at_min_freq);
define_one_global_rw(inc_cpu_load);
define_one_global_rw(dec_cpu_load_at_min_freq);
define_one_global_rw(dec_cpu_load);
define_one_global_rw(freq_responsiveness);
define_one_global_rw(cpus_up_rate);
define_one_global_rw(cpus_down_rate);

static struct attribute *alucard_attributes[] = {
	&sampling_rate.attr,
	&inc_cpu_load_at_min_freq.attr,
	&inc_cpu_load.attr,
	&dec_cpu_load_at_min_freq.attr,
	&dec_cpu_load.attr,
	&freq_responsiveness.attr,
	&pump_inc_step_at_min_freq_1.attr,
	&pump_inc_step_at_min_freq_2.attr,
	&pump_inc_step_at_min_freq_3.attr,
	&pump_inc_step_at_min_freq_4.attr,
	&pump_inc_step_1.attr,
	&pump_inc_step_2.attr,
	&pump_inc_step_3.attr,
	&pump_inc_step_4.attr,
	&pump_dec_step_at_min_freq_1.attr,
	&pump_dec_step_at_min_freq_2.attr,
	&pump_dec_step_at_min_freq_3.attr,
	&pump_dec_step_at_min_freq_4.attr,
	&pump_dec_step_1.attr,
	&pump_dec_step_2.attr,
	&pump_dec_step_3.attr,
	&pump_dec_step_4.attr,
	&cpus_up_rate.attr,
	&cpus_down_rate.attr,
	NULL
};

static struct attribute_group alucard_attr_group = {
	.attrs = alucard_attributes,
	.name = "alucard",
};

/************************** sysfs end ************************/

static void cpufreq_frequency_table_policy_minmax_limits(struct cpufreq_policy *policy,
					struct cpufreq_alucard_cpuinfo *this_alucard_cpuinfo)
{
	struct cpufreq_frequency_table *table = this_alucard_cpuinfo->freq_table;
	unsigned int i = 0;

	for (i = 0; (table[i].frequency != CPUFREQ_TABLE_END); i++) {
		unsigned int freq = table[i].frequency;
		if (freq == CPUFREQ_ENTRY_INVALID) {
			continue;
		}
		if (freq == policy->min)
			this_alucard_cpuinfo->min_index = i;
		if (freq == policy->max)
			this_alucard_cpuinfo->max_index = i;

		if (freq >= policy->min &&
			freq >= policy->max)
			break;
	}
}

static void cpufreq_frequency_table_policy_cur_limit(struct cpufreq_policy *policy,
					struct cpufreq_frequency_table *table,
					unsigned int *index)
{
	unsigned int i = 0;

	for (i = 0; (table[i].frequency != CPUFREQ_TABLE_END); i++) {
		unsigned int freq = table[i].frequency;
		if (freq == CPUFREQ_ENTRY_INVALID) {
			continue;
		}
		if (freq == policy->cur) {
			*index = i;
			break;
		}
	}
}

static void alucard_check_cpu(struct cpufreq_alucard_cpuinfo *this_alucard_cpuinfo)
{
	struct cpufreq_policy *policy;
	unsigned int freq_responsiveness = alucard_tuners_ins.freq_responsiveness;
	int dec_cpu_load = alucard_tuners_ins.dec_cpu_load;
	int inc_cpu_load = alucard_tuners_ins.inc_cpu_load;
	int pump_inc_step = this_alucard_cpuinfo->pump_inc_step;
	int pump_dec_step = this_alucard_cpuinfo->pump_dec_step;
	unsigned int max_load = 0;
	unsigned int cpus_up_rate = alucard_tuners_ins.cpus_up_rate;
	unsigned int cpus_down_rate = alucard_tuners_ins.cpus_down_rate;
	unsigned int index = 0;
	unsigned int j;

	policy = this_alucard_cpuinfo->cur_policy;
	if (!policy)
		return;

	/* Get min, current, max indexes from current cpu policy */
	cpufreq_frequency_table_policy_cur_limit(policy,
				this_alucard_cpuinfo->freq_table,
				&index);

	for_each_cpu(j, policy->cpus) {
		struct cpufreq_alucard_cpuinfo *j_alucard_cpuinfo = &per_cpu(od_alucard_cpuinfo, j);
		u64 cur_wall_time, cur_idle_time;
		unsigned int idle_time, wall_time;
		unsigned int load;
		
		cur_idle_time = get_cpu_idle_time(j, &cur_wall_time, 0);

		wall_time = (unsigned int)
			(cur_wall_time - j_alucard_cpuinfo->prev_cpu_wall);
		j_alucard_cpuinfo->prev_cpu_wall = cur_wall_time;

		idle_time = (unsigned int)
			(cur_idle_time - j_alucard_cpuinfo->prev_cpu_idle);
		j_alucard_cpuinfo->prev_cpu_idle = cur_idle_time;

		if (unlikely(!wall_time || wall_time < idle_time))
			continue;

		load = 100 * (wall_time - idle_time) / wall_time;

		if (load > max_load)
			max_load = load;
	}

	/* CPUs Online Scale Frequency*/
	if (policy->cur < freq_responsiveness
		 && policy->cur > 0) {
		inc_cpu_load = alucard_tuners_ins.inc_cpu_load_at_min_freq;
		dec_cpu_load = alucard_tuners_ins.dec_cpu_load_at_min_freq;
		pump_inc_step = this_alucard_cpuinfo->pump_inc_step_at_min_freq;
		pump_dec_step = this_alucard_cpuinfo->pump_dec_step_at_min_freq;
	}
	/* Check for frequency increase or for frequency decrease */
	if (max_load >= inc_cpu_load && index < this_alucard_cpuinfo->max_index) {
		if (this_alucard_cpuinfo->up_rate % cpus_up_rate == 0) {
			if ((index + pump_inc_step) <= this_alucard_cpuinfo->max_index)
				index += pump_inc_step;
			else
				index = this_alucard_cpuinfo->max_index;

			this_alucard_cpuinfo->up_rate = 1;
			this_alucard_cpuinfo->down_rate = 1;

			if (this_alucard_cpuinfo->freq_table[index].frequency != CPUFREQ_ENTRY_INVALID)
				__cpufreq_driver_target(policy,
										this_alucard_cpuinfo->freq_table[index].frequency,
										CPUFREQ_RELATION_L);
		} else {
			if (this_alucard_cpuinfo->up_rate < cpus_up_rate)
				++this_alucard_cpuinfo->up_rate;
			else
				this_alucard_cpuinfo->up_rate = 1;
		}
	} else if (max_load < dec_cpu_load && index > this_alucard_cpuinfo->min_index) {
		if (this_alucard_cpuinfo->down_rate % cpus_down_rate == 0) {
			if ((index - this_alucard_cpuinfo->min_index) >= pump_dec_step)
				index -= pump_dec_step;
			else
				index = this_alucard_cpuinfo->min_index;

			this_alucard_cpuinfo->up_rate = 1;
			this_alucard_cpuinfo->down_rate = 1;

			if (this_alucard_cpuinfo->freq_table[index].frequency != CPUFREQ_ENTRY_INVALID)
				__cpufreq_driver_target(policy,
										this_alucard_cpuinfo->freq_table[index].frequency,
										CPUFREQ_RELATION_L);
		} else {
			if (this_alucard_cpuinfo->down_rate < cpus_down_rate)
				++this_alucard_cpuinfo->down_rate;
			else
				this_alucard_cpuinfo->down_rate = 1;
		}
	}
}

static void do_alucard_timer(struct work_struct *work)
{
	struct cpufreq_alucard_cpuinfo *this_alucard_cpuinfo = 
		container_of(work, struct cpufreq_alucard_cpuinfo, work.work);
	int delay;

	mutex_lock(&this_alucard_cpuinfo->timer_mutex);

	alucard_check_cpu(this_alucard_cpuinfo);

	delay = usecs_to_jiffies(alucard_tuners_ins.sampling_rate);

	/* We want all CPUs to do sampling nearly on same jiffy */
	if (num_online_cpus() > 1) {
		delay -= jiffies % delay;
	}

	queue_delayed_work_on(this_alucard_cpuinfo->cpu, alucard_wq,
			&this_alucard_cpuinfo->work, delay);
	mutex_unlock(&this_alucard_cpuinfo->timer_mutex);
}

static int cpufreq_governor_alucard(struct cpufreq_policy *policy,
				unsigned int event)
{
	struct cpufreq_alucard_cpuinfo *this_alucard_cpuinfo;
	unsigned int cpu = policy->cpu, j;
	int rc, delay;

	this_alucard_cpuinfo = &per_cpu(od_alucard_cpuinfo, cpu);

	switch (event) {
	case CPUFREQ_GOV_START:
		if (!policy)
			return -EINVAL;

		mutex_lock(&alucard_mutex);
		this_alucard_cpuinfo->freq_table = cpufreq_frequency_get_table(cpu);
		if (!this_alucard_cpuinfo->freq_table) {
			mutex_unlock(&alucard_mutex);
			return -EINVAL;
		}
		cpufreq_frequency_table_policy_minmax_limits(policy,
				this_alucard_cpuinfo);	

		for_each_cpu(j, policy->cpus) {
			struct cpufreq_alucard_cpuinfo *j_alucard_cpuinfo = &per_cpu(od_alucard_cpuinfo, j);

			j_alucard_cpuinfo->prev_cpu_idle = get_cpu_idle_time(j,
				&j_alucard_cpuinfo->prev_cpu_wall, 0);
		}

		alucard_enable++;
		/*
		 * Start the timerschedule work, when this governor
		 * is used for first time
		 */
		if (alucard_enable == 1) {
			rc = sysfs_create_group(cpufreq_global_kobject,
						&alucard_attr_group);
			if (rc) {
				alucard_enable--;
				mutex_unlock(&alucard_mutex);
				return rc;
			}
		}
		this_alucard_cpuinfo->cpu = cpu;
		this_alucard_cpuinfo->cur_policy = policy;
		this_alucard_cpuinfo->up_rate = 1;
		this_alucard_cpuinfo->down_rate = 1;
		this_alucard_cpuinfo->governor_enabled = true;
		mutex_unlock(&alucard_mutex);

		mutex_init(&this_alucard_cpuinfo->timer_mutex);

		delay = usecs_to_jiffies(alucard_tuners_ins.sampling_rate);
		/* We want all CPUs to do sampling nearly on same jiffy */
		if (num_online_cpus() > 1) {
			delay -= jiffies % delay;
		}

		INIT_DEFERRABLE_WORK(&this_alucard_cpuinfo->work, do_alucard_timer);
		queue_delayed_work_on(cpu,
			alucard_wq, &this_alucard_cpuinfo->work, delay);

		break;
	case CPUFREQ_GOV_STOP:
		cancel_delayed_work_sync(&this_alucard_cpuinfo->work);

		mutex_lock(&alucard_mutex);
		mutex_destroy(&this_alucard_cpuinfo->timer_mutex);

		this_alucard_cpuinfo->governor_enabled = false;

		this_alucard_cpuinfo->cur_policy = NULL;

		alucard_enable--;
		if (!alucard_enable) {
			sysfs_remove_group(cpufreq_global_kobject,
					   &alucard_attr_group);
		}

		mutex_unlock(&alucard_mutex);

		break;
	case CPUFREQ_GOV_LIMITS:
		if (!this_alucard_cpuinfo->cur_policy
			 || !policy) {
			pr_debug("Unable to limit cpu freq due to cur_policy == NULL\n");
			return -EPERM;
		}
		mutex_lock(&this_alucard_cpuinfo->timer_mutex);
		__cpufreq_driver_target(this_alucard_cpuinfo->cur_policy,
				policy->cur, CPUFREQ_RELATION_L);

		cpufreq_frequency_table_policy_minmax_limits(policy,
				this_alucard_cpuinfo);
		mutex_unlock(&this_alucard_cpuinfo->timer_mutex);
=======
/* pump_inc_step */
static ssize_t show_pump_inc_step(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->pump_inc_step);
}

static ssize_t store_pump_inc_step(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = min(max(1, input), 6);

	if (input == tunables->pump_inc_step)
		return count;

	tunables->pump_inc_step = input;

	return count;
}

/* pump_dec_step_at_min_freq */
static ssize_t show_pump_dec_step_at_min_freq(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->pump_dec_step_at_min_freq);
}

static ssize_t store_pump_dec_step_at_min_freq(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = min(max(1, input), 6);

	if (input == tunables->pump_dec_step_at_min_freq)
		return count;

	tunables->pump_dec_step_at_min_freq = input;

	return count;
}

/* pump_dec_step */
static ssize_t show_pump_dec_step(struct cpufreq_alucard_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->pump_dec_step);
}

static ssize_t store_pump_dec_step(struct cpufreq_alucard_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = min(max(1, input), 6);

	if (input == tunables->pump_dec_step)
		return count;

	tunables->pump_dec_step = input;

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
show_store_gov_pol_sys(freq_responsiveness);
show_store_gov_pol_sys(freq_responsiveness_max);
show_store_gov_pol_sys(cpus_up_rate_at_max_freq);
show_store_gov_pol_sys(cpus_up_rate);
show_store_gov_pol_sys(cpus_down_rate_at_max_freq);
show_store_gov_pol_sys(cpus_down_rate);
show_store_gov_pol_sys(pump_inc_step_at_min_freq);
show_store_gov_pol_sys(pump_inc_step);
show_store_gov_pol_sys(pump_dec_step_at_min_freq);
show_store_gov_pol_sys(pump_dec_step);

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
gov_sys_pol_attr_rw(freq_responsiveness);
gov_sys_pol_attr_rw(freq_responsiveness_max);
gov_sys_pol_attr_rw(cpus_up_rate_at_max_freq);
gov_sys_pol_attr_rw(cpus_up_rate);
gov_sys_pol_attr_rw(cpus_down_rate_at_max_freq);
gov_sys_pol_attr_rw(cpus_down_rate);
gov_sys_pol_attr_rw(pump_inc_step_at_min_freq);
gov_sys_pol_attr_rw(pump_inc_step);
gov_sys_pol_attr_rw(pump_dec_step_at_min_freq);
gov_sys_pol_attr_rw(pump_dec_step);

/* One Governor instance for entire system */
static struct attribute *alucard_attributes_gov_sys[] = {
	&timer_rate_gov_sys.attr,
	&timer_slack_gov_sys.attr,
	&io_is_busy_gov_sys.attr,
	&align_windows_gov_sys.attr,
	&freq_responsiveness_gov_sys.attr,
	&freq_responsiveness_max_gov_sys.attr,
	&cpus_up_rate_at_max_freq_gov_sys.attr,
	&cpus_up_rate_gov_sys.attr,
	&cpus_down_rate_at_max_freq_gov_sys.attr,
	&cpus_down_rate_gov_sys.attr,
	&pump_inc_step_at_min_freq_gov_sys.attr,
	&pump_inc_step_gov_sys.attr,
	&pump_dec_step_at_min_freq_gov_sys.attr,
	&pump_dec_step_gov_sys.attr,
	NULL,
};

static struct attribute_group alucard_attr_group_gov_sys = {
	.attrs = alucard_attributes_gov_sys,
	.name = "alucard",
};

/* Per policy governor instance */
static struct attribute *alucard_attributes_gov_pol[] = {
	&timer_rate_gov_pol.attr,
	&timer_slack_gov_pol.attr,
	&io_is_busy_gov_pol.attr,
	&align_windows_gov_pol.attr,
	&freq_responsiveness_gov_pol.attr,
	&freq_responsiveness_max_gov_pol.attr,
	&cpus_up_rate_at_max_freq_gov_pol.attr,
	&cpus_up_rate_gov_pol.attr,
	&cpus_down_rate_at_max_freq_gov_pol.attr,
	&cpus_down_rate_gov_pol.attr,
	&pump_inc_step_at_min_freq_gov_pol.attr,
	&pump_inc_step_gov_pol.attr,
	&pump_dec_step_at_min_freq_gov_pol.attr,
	&pump_dec_step_gov_pol.attr,
	NULL,
};

static struct attribute_group alucard_attr_group_gov_pol = {
	.attrs = alucard_attributes_gov_pol,
	.name = "alucard",
};

static struct attribute_group *get_sysfs_attr(void)
{
	if (have_governor_per_policy())
		return &alucard_attr_group_gov_pol;
	else
		return &alucard_attr_group_gov_sys;
}

static void cpufreq_alucard_nop_timer(unsigned long data)
{
}

static struct cpufreq_alucard_tunables *alloc_tunable(
					struct cpufreq_policy *policy)
{
	struct cpufreq_alucard_tunables *tunables;

	tunables = kzalloc(sizeof(*tunables), GFP_KERNEL);
	if (!tunables)
		return ERR_PTR(-ENOMEM);

	tunables->timer_rate = DEFAULT_TIMER_RATE;
	tunables->timer_rate_prev = DEFAULT_TIMER_RATE;
	tunables->timer_slack_val = DEFAULT_TIMER_SLACK;
	if (policy->cpu > 3) {
		tunables->freq_responsiveness = FREQ_RESPONSIVENESS;
		tunables->freq_responsiveness_max = FREQ_RESPONSIVENESS_MAX;
	} else {
		tunables->freq_responsiveness = FREQ_RESPONSIVENESS_BIGC;
		tunables->freq_responsiveness_max = FREQ_RESPONSIVENESS_MAX_BIGC;
	}
	tunables->cpus_up_rate_at_max_freq = CPUS_UP_RATE;
	tunables->cpus_up_rate = CPUS_UP_RATE;
	tunables->cpus_down_rate_at_max_freq = CPUS_DOWN_RATE;
	tunables->cpus_down_rate = CPUS_DOWN_RATE;
	tunables->pump_inc_step_at_min_freq = PUMP_INC_STEP_AT_MIN_FREQ;
	tunables->pump_inc_step = PUMP_INC_STEP;
	tunables->pump_dec_step = PUMP_DEC_STEP;
	tunables->pump_dec_step_at_min_freq = PUMP_DEC_STEP_AT_MIN_FREQ;

	return tunables;
}

static struct cpufreq_alucard_policyinfo *get_policyinfo(
					struct cpufreq_policy *policy)
{
	struct cpufreq_alucard_policyinfo *ppol =
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
	ppol->policy_timer.function = cpufreq_alucard_timer;
	init_timer(&ppol->policy_slack_timer);
	ppol->policy_slack_timer.function = cpufreq_alucard_nop_timer;
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
	struct cpufreq_alucard_policyinfo *ppol = per_cpu(polinfo, cpu);
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

static struct cpufreq_alucard_tunables *get_tunables(
				struct cpufreq_alucard_policyinfo *ppol)
{
	if (have_governor_per_policy())
		return ppol->cached_tunables;
	else
		return cached_common_tunables;
}

static int cpufreq_governor_alucard(struct cpufreq_policy *policy,
		unsigned int event)
{
	int rc;
	struct cpufreq_alucard_policyinfo *ppol;
	struct cpufreq_frequency_table *freq_table;
	struct cpufreq_alucard_tunables *tunables;
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
		ppol->up_rate = 1;
		ppol->down_rate = 1;
		ppol->reject_notification = true;
		down_write(&ppol->enable_sem);
		del_timer_sync(&ppol->policy_timer);
		del_timer_sync(&ppol->policy_slack_timer);
		ppol->policy_timer.data = policy->cpu;
		ppol->last_evaluated_jiffy = get_jiffies_64();
		cpufreq_alucard_timer_start(tunables, policy->cpu);
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
				cpufreq_alucard_timer_resched(policy->cpu,
								  true);
			ppol->min_freq = policy->min;
		}

		up_read(&ppol->enable_sem);
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors

		break;
	}
	return 0;
}

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_ALUCARD
static
#endif
struct cpufreq_governor cpufreq_gov_alucard = {
<<<<<<< HEAD
	.name                   = "alucard",
	.governor               = cpufreq_governor_alucard,
	.owner                  = THIS_MODULE,
};


static int __init cpufreq_gov_alucard_init(void)
{
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		struct cpufreq_alucard_cpuinfo *this_alucard_cpuinfo = &per_cpu(od_alucard_cpuinfo, cpu);

		this_alucard_cpuinfo->pump_inc_step_at_min_freq = PUMP_INC_STEP_AT_MIN_FREQ;
		this_alucard_cpuinfo->pump_inc_step = PUMP_INC_STEP;
		this_alucard_cpuinfo->pump_dec_step = PUMP_DEC_STEP;
		this_alucard_cpuinfo->pump_dec_step_at_min_freq = PUMP_DEC_STEP_AT_MIN_FREQ;
	}

	alucard_wq = alloc_workqueue("alucard_wq", WQ_HIGHPRI, 0);
	if (!alucard_wq) {
		printk(KERN_ERR "Failed to create alucard_wq workqueue\n");
		return -EFAULT;
	}
=======
	.name = "alucard",
	.governor = cpufreq_governor_alucard,
	.max_transition_latency = 10000000,
	.owner = THIS_MODULE,
};

static int __init cpufreq_alucard_init(void)
{
	struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 };

	spin_lock_init(&speedchange_cpumask_lock);
	mutex_init(&gov_lock);
	speedchange_task =
		kthread_create(cpufreq_alucard_speedchange_task, NULL,
			       "cfalucard");
	if (IS_ERR(speedchange_task))
		return PTR_ERR(speedchange_task);

	sched_setscheduler_nocheck(speedchange_task, SCHED_FIFO, &param);
	get_task_struct(speedchange_task);

	/* NB: wake up so the thread does not look hung to the freezer */
	wake_up_process_no_notif(speedchange_task);
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors

	return cpufreq_register_governor(&cpufreq_gov_alucard);
}

<<<<<<< HEAD
static void __exit cpufreq_gov_alucard_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_alucard);
}

MODULE_AUTHOR("Alucard24@XDA");
MODULE_DESCRIPTION("'cpufreq_alucard' - A dynamic cpufreq governor v3.0 (SnapDragon)");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_ALUCARD
fs_initcall(cpufreq_gov_alucard_init);
#else
module_init(cpufreq_gov_alucard_init);
#endif
module_exit(cpufreq_gov_alucard_exit);
=======
#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_ALUCARD
fs_initcall(cpufreq_alucard_init);
#else
module_init(cpufreq_alucard_init);
#endif

static void __exit cpufreq_alucard_exit(void)
{
	int cpu;

	cpufreq_unregister_governor(&cpufreq_gov_alucard);
	kthread_stop(speedchange_task);
	put_task_struct(speedchange_task);

	for_each_possible_cpu(cpu)
		free_policyinfo(cpu);
}

module_exit(cpufreq_alucard_exit);

MODULE_AUTHOR("Alucard24 <dmbaoh2@gmail.com>");
MODULE_DESCRIPTION("'cpufreq_alucard' - A dynamic cpufreq governor v5.0");
MODULE_LICENSE("GPLv2");
>>>>>>> f677faed32cd... cpufreq: add latest alucard/darkness/nightmare governors
