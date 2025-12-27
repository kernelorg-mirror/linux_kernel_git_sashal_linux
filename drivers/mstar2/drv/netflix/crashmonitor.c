/* SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause */
/******************************************************************************
 *
 * This file is provided under a dual license.  When you use or
 * distribute this software, you may choose to be licensed under
 * version 2 of the GNU General Public License ("GPLv2 License")
 * or BSD License.
 *
 * GPLv2 License
 *
 * Copyright(C) 2019 MediaTek Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See http://www.gnu.org/licenses/gpl-2.0.html for more details.
 *
 * BSD LICENSE
 *
 * Copyright(C) 2019 MediaTek Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/


#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/rcupdate.h>
#include <linux/profile.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <crashmonitor.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,53)
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/signal.h>
#include <asm/processor.h>
#endif

#define MAX_TARGET_NUM   10
#define STRINGIFY(x)     #x
#define MAX_PID_LEN     sizeof(STRINGIFY(PID_MAX_LIMIT))
#define MAX_PROC_SIZE    MAX_TARGET_NUM * (MAX_PID_LEN + 1)

static DEFINE_SPINLOCK(crashlist_lock);
static LIST_HEAD(crash_list);
static LIST_HEAD(process_list);

struct crashinfo {
	enum crash_reason reason;
	int pid;
	unsigned long terminalAddress;
	struct list_head node;
};

struct target_process{
	char pid[MAX_PID_LEN];
	struct list_head node;
};

static unsigned long monitor_id = 0;

static int add_crashinfo_list(struct task_struct *victim , enum crash_reason reason)
{
	struct pt_regs *regs;
	unsigned long pc;
	struct crashinfo* victiminfo;

	task_lock(victim);
	regs = task_pt_regs(victim);
	pc = profile_pc(regs);
	task_unlock(victim);
	victiminfo = kmalloc(sizeof(struct crashinfo),GFP_KERNEL);
	if(victiminfo == NULL)
	{
		pr_err("\033[1;31m crash info allocate memory fail \033[m\n");
		return -ENOMEM;
	}
	victiminfo->pid = task_pid_nr(victim);
	victiminfo->reason = reason;
	victiminfo->terminalAddress = pc;
	spin_lock(&crashlist_lock);
	list_add_tail(&victiminfo->node,&crash_list);
	spin_unlock(&crashlist_lock);
	return 0;
}

static int send_signal_to_monitor(void)
{
	struct task_struct *p;
	struct pid * kpid;
	if(monitor_id == 0){
		pr_info("There is no crash monitor \n");
		return 0;
	}

	read_lock(&tasklist_lock);
	kpid = find_get_pid((pid_t)monitor_id);
	rcu_read_lock();
	p = pid_task(kpid,PIDTYPE_PID);
	rcu_read_unlock();
	if (p){
		send_sig(SIGMTR,p,0);
	}else{
		read_unlock(&tasklist_lock);
		return -EFAULT;
	}
	read_unlock(&tasklist_lock);
	return 0;
}

static bool process_monitored(struct task_struct *process){
	char task_id[MAX_PID_LEN]={0};
	struct target_process *process_iterator;

	if(list_empty(&process_list))
		return true;

	sprintf(task_id,"%d",task_pid_nr(process));
	list_for_each_entry(process_iterator, &process_list, node)
	{
		if(strcmp(process_iterator->pid,task_id) == 0)
                        return true;
	}

	return false;
}

static ssize_t crashinfo_proc_write(struct file *file, const char *buf, size_t count, loff_t * p)
{
	struct crashinfo *tmp_crashinfo;
	struct crashinfo *crashinfo_iterator;
	char pid[MAX_PID_LEN] = {0};

	if(count > MAX_PID_LEN)
		count = MAX_PID_LEN;
	if(copy_from_user(pid, buf, count))
		return -EFAULT;

	monitor_id = simple_strtol(pid,NULL,10);
	if(monitor_id)
		pr_info("Register crash monitor successful!!\n");
	else
		pr_info("Unregister crash monitor successful!!\n");

	return count;
}

static int crashinfo_proc_show(struct seq_file *m, void *v)
{
	struct crashinfo *crashinfo_iterator;
	struct crashinfo *tmp_crashinfo;

	spin_lock(&crashlist_lock);
	if (!list_empty(&crash_list)) {
		//read one data at a time
		crashinfo_iterator = list_first_entry(&crash_list, struct crashinfo, node);
		seq_printf(m, "[%d,%d,0x%lx]",crashinfo_iterator->reason,crashinfo_iterator->pid,crashinfo_iterator->terminalAddress);
		list_del(&crashinfo_iterator->node);
		kfree(crashinfo_iterator);
	}
	spin_unlock(&crashlist_lock);
	return 0;
}

static int crashinfo_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, crashinfo_proc_show, NULL);
}

static const struct file_operations crashinfo_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= crashinfo_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= crashinfo_proc_write,
};

static ssize_t process_proc_write(struct file *file, const char *buf, size_t count, loff_t *p)
{
	char *ptr;
	char *substr = NULL;
	struct target_process *process_iterator;
	struct target_process *tmp_process;
	char process_buf[MAX_PROC_SIZE];

	memset(process_buf,0,MAX_PROC_SIZE);
	if(count > MAX_PROC_SIZE)
		count = MAX_PROC_SIZE - 1;
	if(copy_from_user(process_buf, buf, count))
		return -EFAULT;

	if(process_buf[count-1] == '\n')
		process_buf[count-1] = '\0';
	else
		process_buf[count] = '\0';

	list_for_each_entry_safe(process_iterator, tmp_process, &process_list, node)
	{
		list_del(&process_iterator->node);
		kfree(process_iterator);
	}

	if(strcmp(process_buf,"0") != 0)
	{
		ptr = process_buf;
		while (substr = strsep(&ptr, ",")) {
			struct target_process *pid_node;
			pid_node = kmalloc(sizeof(struct target_process),GFP_KERNEL);
			if(pid_node == NULL)
			{
				pr_err("\033[1;31m monitored process %s allocate memory fail \033[m\n",substr);
				return -ENOMEM;
			}
			strncpy(pid_node->pid, substr, MAX_PID_LEN);
			pid_node->pid [MAX_PID_LEN-1] = '\0';
			list_add(&pid_node->node,&process_list);
		}
	}

	return count;
}

static int process_proc_show(struct seq_file *m, void *v)
{
	struct target_process *process_iterator;
	struct target_process *tmp_process;
	char print_buf[MAX_PROC_SIZE] = {0};

	if(list_empty(&process_list)){
		seq_printf(m, "%s\n","all");
	}else{
		list_for_each_entry(process_iterator, &process_list, node)
		{
			strcat(print_buf,process_iterator->pid);
			strcat(print_buf,",");
		}
		print_buf[strlen(print_buf) - 1] = '\0';
		seq_printf(m, "%s",print_buf);
	}
	return 0;
}

static int process_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, process_proc_show, NULL);
}

static const struct file_operations process_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= process_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= process_proc_write,
};

static int __init monitor_proc_init(void)
{
	struct proc_dir_entry *crashinfo_entry;
	struct proc_dir_entry *process_entry;
	struct proc_dir_entry *proc_monitor_dir;

	proc_monitor_dir = proc_mkdir("monitor", NULL);
	if(!proc_monitor_dir)
	{
		pr_err("Error creating proc dir: monitor\n");
		return -ENOMEM;
	}

	crashinfo_entry = proc_create("crashinfo", S_IRUSR | S_IWUSR, proc_monitor_dir, &crashinfo_proc_fops);
	if(!crashinfo_entry)
	{
		pr_err("Error creating proc entry: monitor/crashinfo\n");
		return -ENOMEM;
	}

	process_entry = proc_create("process", S_IRUSR | S_IWUSR, proc_monitor_dir, &process_proc_fops);
	if(!process_entry)
	{
		pr_err("Error creating proc entry: monitor/process\n");
		return -ENOMEM;
	}

	pr_info("Netflix crash moniter proc initialized\n");
	return 0;
}

device_initcall(monitor_proc_init);

void crash_monitor(struct task_struct * process, enum crash_reason reason)
{
        if(monitor_id == 0)
                return ;

	if(process_monitored(process)){
		add_crashinfo_list(process,reason);
		send_signal_to_monitor();
	}
}

