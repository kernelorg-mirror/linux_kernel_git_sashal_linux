// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * fs/inotify_user.c - inotify support for userspace
 *
 * Authors:
 *	John McCutchan	<ttb@tentacle.dhs.org>
 *	Robert Love	<rml@novell.com>
 *
 * Copyright (C) 2005 John McCutchan
 * Copyright 2006 Hewlett-Packard Development Company, L.P.
 *
 * Copyright (C) 2009 Eric Paris <Red Hat Inc>
 * inotify was largely rewriten to make use of the fsnotify infrastructure
 */

#include <linux/file.h>
#include <linux/fs.h> /* struct inode */
#include <linux/fsnotify_backend.h>
#include <linux/idr.h>
#include <linux/init.h> /* fs_initcall */
#include <linux/inotify.h>
#include <linux/kernel.h> /* roundup() */
#include <linux/namei.h> /* LOOKUP_FOLLOW */
#include <linux/sched/signal.h>
#include <linux/slab.h> /* struct kmem_cache */
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/memcontrol.h>
#include <linux/security.h>

#include "inotify.h"
#include "../fdinfo.h"

#include <asm/ioctls.h>

/*
 * An inotify watch requires allocating an inotify_inode_mark structure as
 * well as pinning the watched inode. Doubling the size of a VFS inode
 * should be more than enough to cover the additional filesystem inode
 * size increase.
 */
#define INOTIFY_WATCH_COST	(sizeof(struct inotify_inode_mark) + \
				 2 * sizeof(struct inode))

/* configurable via /proc/sys/fs/inotify/ */
static int inotify_max_queued_events __read_mostly;

struct kmem_cache *inotify_inode_mark_cachep __ro_after_init;

#ifdef CONFIG_SYSCTL

#include <linux/sysctl.h>

static long it_zero = 0;
static long it_int_max = INT_MAX;

static const struct ctl_table inotify_table[] = {
	{
		.procname	= "max_user_instances",
		.data		= &init_user_ns.ucount_max[UCOUNT_INOTIFY_INSTANCES],
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
		.extra1		= &it_zero,
		.extra2		= &it_int_max,
	},
	{
		.procname	= "max_user_watches",
		.data		= &init_user_ns.ucount_max[UCOUNT_INOTIFY_WATCHES],
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
		.extra1		= &it_zero,
		.extra2		= &it_int_max,
	},
	{
		.procname	= "max_queued_events",
		.data		= &inotify_max_queued_events,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO
	},
};

static void __init inotify_sysctls_init(void)
{
	register_sysctl("fs/inotify", inotify_table);
}

#else
#define inotify_sysctls_init() do { } while (0)
#endif /* CONFIG_SYSCTL */

static inline __u32 inotify_arg_to_mask(struct inode *inode, u32 arg)
{
	__u32 mask;

	/*
	 * Everything should receive events when the inode is unmounted.
	 * All directories care about children.
	 */
	mask = (FS_UNMOUNT);
	if (S_ISDIR(inode->i_mode))
		mask |= FS_EVENT_ON_CHILD;

	/* mask off the flags used to open the fd */
	mask |= (arg & INOTIFY_USER_MASK);

	return mask;
}

#define INOTIFY_MARK_FLAGS \
	(FSNOTIFY_MARK_FLAG_EXCL_UNLINK | FSNOTIFY_MARK_FLAG_IN_ONESHOT)

static inline unsigned int inotify_arg_to_flags(u32 arg)
{
	unsigned int flags = 0;

	if (arg & IN_EXCL_UNLINK)
		flags |= FSNOTIFY_MARK_FLAG_EXCL_UNLINK;
	if (arg & IN_ONESHOT)
		flags |= FSNOTIFY_MARK_FLAG_IN_ONESHOT;

	return flags;
}

static inline u32 inotify_mask_to_arg(__u32 mask)
{
	return mask & (IN_ALL_EVENTS | IN_ISDIR | IN_UNMOUNT | IN_IGNORED |
		       IN_Q_OVERFLOW);
}

/* inotify userspace file descriptor functions */
static __poll_t inotify_poll(struct file *file, poll_table *wait)
{
	struct fsnotify_group *group = file->private_data;
	__poll_t ret = 0;

	poll_wait(file, &group->notification_waitq, wait);
	spin_lock(&group->notification_lock);
	if (!fsnotify_notify_queue_is_empty(group))
		ret = EPOLLIN | EPOLLRDNORM;
	spin_unlock(&group->notification_lock);

	return ret;
}

static int round_event_name_len(struct fsnotify_event *fsn_event)
{
	struct inotify_event_info *event;

	event = INOTIFY_E(fsn_event);
	if (!event->name_len)
		return 0;
	return roundup(event->name_len + 1, sizeof(struct inotify_event));
}

/*
 * Get an inotify_kernel_event if one exists and is small
 * enough to fit in "count". Return an error pointer if
 * not large enough.
 *
 * Called with the group->notification_lock held.
 */
static struct fsnotify_event *get_one_event(struct fsnotify_group *group,
					    size_t count)
{
	size_t event_size = sizeof(struct inotify_event);
	struct fsnotify_event *event;

	event = fsnotify_peek_first_event(group);
	if (!event)
		return NULL;

	pr_debug("%s: group=%p event=%p\n", __func__, group, event);

	event_size += round_event_name_len(event);
	if (event_size > count)
		return ERR_PTR(-EINVAL);

	/* held the notification_lock the whole time, so this is the
	 * same event we peeked above */
	fsnotify_remove_first_event(group);

	return event;
}

/*
 * Copy an event to user space, returning how much we copied.
 *
 * We already checked that the event size is smaller than the
 * buffer we had in "get_one_event()" above.
 */
static ssize_t copy_event_to_user(struct fsnotify_group *group,
				  struct fsnotify_event *fsn_event,
				  char __user *buf)
{
	struct inotify_event inotify_event;
	struct inotify_event_info *event;
	size_t event_size = sizeof(struct inotify_event);
	size_t name_len;
	size_t pad_name_len;

	pr_debug("%s: group=%p event=%p\n", __func__, group, fsn_event);

	event = INOTIFY_E(fsn_event);
	name_len = event->name_len;
	/*
	 * round up name length so it is a multiple of event_size
	 * plus an extra byte for the terminating '\0'.
	 */
	pad_name_len = round_event_name_len(fsn_event);
	inotify_event.len = pad_name_len;
	inotify_event.mask = inotify_mask_to_arg(event->mask);
	inotify_event.wd = event->wd;
	inotify_event.cookie = event->sync_cookie;

	/* send the main event */
	if (copy_to_user(buf, &inotify_event, event_size))
		return -EFAULT;

	buf += event_size;

	/*
	 * fsnotify only stores the pathname, so here we have to send the pathname
	 * and then pad that pathname out to a multiple of sizeof(inotify_event)
	 * with zeros.
	 */
	if (pad_name_len) {
		/* copy the path name */
		if (copy_to_user(buf, event->name, name_len))
			return -EFAULT;
		buf += name_len;

		/* fill userspace with 0's */
		if (clear_user(buf, pad_name_len - name_len))
			return -EFAULT;
		event_size += pad_name_len;
	}

	return event_size;
}

static ssize_t inotify_read(struct file *file, char __user *buf,
			    size_t count, loff_t *pos)
{
	struct fsnotify_group *group;
	struct fsnotify_event *kevent;
	char __user *start;
	int ret;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	start = buf;
	group = file->private_data;

	add_wait_queue(&group->notification_waitq, &wait);
	while (1) {
		spin_lock(&group->notification_lock);
		kevent = get_one_event(group, count);
		spin_unlock(&group->notification_lock);

		pr_debug("%s: group=%p kevent=%p\n", __func__, group, kevent);

		if (kevent) {
			ret = PTR_ERR(kevent);
			if (IS_ERR(kevent))
				break;
			ret = copy_event_to_user(group, kevent, buf);
			fsnotify_destroy_event(group, kevent);
			if (ret < 0)
				break;
			buf += ret;
			count -= ret;
			continue;
		}

		ret = -EAGAIN;
		if (file->f_flags & O_NONBLOCK)
			break;
		ret = -ERESTARTSYS;
		if (signal_pending(current))
			break;

		if (start != buf)
			break;

		wait_woken(&wait, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
	}
	remove_wait_queue(&group->notification_waitq, &wait);

	if (start != buf && ret != -EFAULT)
		ret = buf - start;
	return ret;
}

static int inotify_release(struct inode *ignored, struct file *file)
{
	struct fsnotify_group *group = file->private_data;

	pr_debug("%s: group=%p\n", __func__, group);

	/* free this group, matching get was inotify_init->fsnotify_obtain_group */
	fsnotify_destroy_group(group);

	return 0;
}

static long inotify_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct fsnotify_group *group;
	struct fsnotify_event *fsn_event;
	void __user *p;
	int ret = -ENOTTY;
	size_t send_len = 0;

	group = file->private_data;
	p = (void __user *) arg;

	pr_debug("%s: group=%p cmd=%u\n", __func__, group, cmd);

	switch (cmd) {
	case FIONREAD:
		spin_lock(&group->notification_lock);
		list_for_each_entry(fsn_event, &group->notification_list,
				    list) {
			send_len += sizeof(struct inotify_event);
			send_len += round_event_name_len(fsn_event);
		}
		spin_unlock(&group->notification_lock);
		ret = put_user(send_len, (int __user *) p);
		break;
#ifdef CONFIG_CHECKPOINT_RESTORE
	case INOTIFY_IOC_SETNEXTWD:
		ret = -EINVAL;
		if (arg >= 1 && arg <= INT_MAX) {
			struct inotify_group_private_data *data;

			data = &group->inotify_data;
			spin_lock(&data->idr_lock);
			idr_set_cursor(&data->idr, (unsigned int)arg);
			spin_unlock(&data->idr_lock);
			ret = 0;
		}
		break;
#endif /* CONFIG_CHECKPOINT_RESTORE */
	}

	return ret;
}

static const struct file_operations inotify_fops = {
	.show_fdinfo	= inotify_show_fdinfo,
	.poll		= inotify_poll,
	.read		= inotify_read,
	.fasync		= fsnotify_fasync,
	.release	= inotify_release,
	.unlocked_ioctl	= inotify_ioctl,
	.compat_ioctl	= inotify_ioctl,
	.llseek		= noop_llseek,
};


/*
 * find_inode - resolve a user-given path to a specific inode
 */
static int inotify_find_inode(const char __user *dirname, struct path *path,
						unsigned int flags, __u64 mask)
{
	int error;

	error = user_path_at(AT_FDCWD, dirname, flags, path);
	if (error)
		return error;
	/* you can only watch an inode if you have read permissions on it */
	error = path_permission(path, MAY_READ);
	if (error) {
		path_put(path);
		return error;
	}
	error = security_path_notify(path, mask,
				FSNOTIFY_OBJ_TYPE_INODE);
	if (error)
		path_put(path);

	return error;
}

static int inotify_add_to_idr(struct idr *idr, spinlock_t *idr_lock,
			      struct inotify_inode_mark *i_mark)
{
	int ret;

	idr_preload(GFP_KERNEL);
	spin_lock(idr_lock);

	ret = idr_alloc_cyclic(idr, i_mark, 1, 0, GFP_NOWAIT);
	if (ret >= 0) {
		/* we added the mark to the idr, take a reference */
		i_mark->wd = ret;
		fsnotify_get_mark(&i_mark->fsn_mark);
	}

	spin_unlock(idr_lock);
	idr_preload_end();
	return ret < 0 ? ret : 0;
}

static struct inotify_inode_mark *inotify_idr_find_locked(struct fsnotify_group *group,
								int wd)
{
	struct idr *idr = &group->inotify_data.idr;
	spinlock_t *idr_lock = &group->inotify_data.idr_lock;
	struct inotify_inode_mark *i_mark;

	assert_spin_locked(idr_lock);

	i_mark = idr_find(idr, wd);
	if (i_mark) {
		struct fsnotify_mark *fsn_mark = &i_mark->fsn_mark;

		fsnotify_get_mark(fsn_mark);
		/* One ref for being in the idr, one ref we just took */
		BUG_ON(refcount_read(&fsn_mark->refcnt) < 2);
	}

	return i_mark;
}

static struct inotify_inode_mark *inotify_idr_find(struct fsnotify_group *group,
							 int wd)
{
	struct inotify_inode_mark *i_mark;
	spinlock_t *idr_lock = &group->inotify_data.idr_lock;

	spin_lock(idr_lock);
	i_mark = inotify_idr_find_locked(group, wd);
	spin_unlock(idr_lock);

	return i_mark;
}

/*
 * Remove the mark from the idr (if present) and drop the reference
 * on the mark because it was in the idr.
 */
static void inotify_remove_from_idr(struct fsnotify_group *group,
				    struct inotify_inode_mark *i_mark)
{
	struct idr *idr = &group->inotify_data.idr;
	spinlock_t *idr_lock = &group->inotify_data.idr_lock;
	struct inotify_inode_mark *found_i_mark = NULL;
	int wd;

	spin_lock(idr_lock);
	wd = i_mark->wd;

	/*
	 * does this i_mark think it is in the idr?  we shouldn't get called
	 * if it wasn't....
	 */
	if (wd == -1) {
		WARN_ONCE(1, "%s: i_mark=%p i_mark->wd=%d i_mark->group=%p\n",
			__func__, i_mark, i_mark->wd, i_mark->fsn_mark.group);
		goto out;
	}

	/* Lets look in the idr to see if we find it */
	found_i_mark = inotify_idr_find_locked(group, wd);
	if (unlikely(!found_i_mark)) {
		WARN_ONCE(1, "%s: i_mark=%p i_mark->wd=%d i_mark->group=%p\n",
			__func__, i_mark, i_mark->wd, i_mark->fsn_mark.group);
		goto out;
	}

	/*
	 * We found an mark in the idr at the right wd, but it's
	 * not the mark we were told to remove.  eparis seriously
	 * fucked up somewhere.
	 */
	if (unlikely(found_i_mark != i_mark)) {
		WARN_ONCE(1, "%s: i_mark=%p i_mark->wd=%d i_mark->group=%p "
			"found_i_mark=%p found_i_mark->wd=%d "
			"found_i_mark->group=%p\n", __func__, i_mark,
			i_mark->wd, i_mark->fsn_mark.group, found_i_mark,
			found_i_mark->wd, found_i_mark->fsn_mark.group);
		goto out;
	}

	/*
	 * One ref for being in the idr
	 * one ref grabbed by inotify_idr_find
	 */
	if (unlikely(refcount_read(&i_mark->fsn_mark.refcnt) < 2)) {
		printk(KERN_ERR "%s: i_mark=%p i_mark->wd=%d i_mark->group=%p\n",
			 __func__, i_mark, i_mark->wd, i_mark->fsn_mark.group);
		/* we can't really recover with bad ref cnting.. */
		BUG();
	}

	idr_remove(idr, wd);
	/* Removed from the idr, drop that ref. */
	fsnotify_put_mark(&i_mark->fsn_mark);
out:
	i_mark->wd = -1;
	spin_unlock(idr_lock);
	/* match the ref taken by inotify_idr_find_locked() */
	if (found_i_mark)
		fsnotify_put_mark(&found_i_mark->fsn_mark);
}

/*
 * Send IN_IGNORED for this wd, remove this wd from the idr.
 */
void inotify_ignored_and_remove_idr(struct fsnotify_mark *fsn_mark,
				    struct fsnotify_group *group)
{
	struct inotify_inode_mark *i_mark;

	/* Queue ignore event for the watch */
	inotify_handle_inode_event(fsn_mark, FS_IN_IGNORED, NULL, NULL, NULL,
				   0);

	i_mark = container_of(fsn_mark, struct inotify_inode_mark, fsn_mark);
	/* remove this mark from the idr */
	inotify_remove_from_idr(group, i_mark);

	dec_inotify_watches(group->inotify_data.ucounts);
}

static int inotify_update_existing_watch(struct fsnotify_group *group,
					 struct inode *inode,
					 u32 arg)
{
	struct fsnotify_mark *fsn_mark;
	struct inotify_inode_mark *i_mark;
	__u32 old_mask, new_mask;
	int replace = !(arg & IN_MASK_ADD);
	int create = (arg & IN_MASK_CREATE);
	int ret;

	fsn_mark = fsnotify_find_inode_mark(inode, group);
	if (!fsn_mark)
		return -ENOENT;
	else if (create) {
		ret = -EEXIST;
		goto out;
	}

	i_mark = container_of(fsn_mark, struct inotify_inode_mark, fsn_mark);

	spin_lock(&fsn_mark->lock);
	old_mask = fsn_mark->mask;
	if (replace) {
		fsn_mark->mask = 0;
		fsn_mark->flags &= ~INOTIFY_MARK_FLAGS;
	}
	fsn_mark->mask |= inotify_arg_to_mask(inode, arg);
	fsn_mark->flags |= inotify_arg_to_flags(arg);
	new_mask = fsn_mark->mask;
	spin_unlock(&fsn_mark->lock);

	if (old_mask != new_mask) {
		/* more bits in old than in new? */
		int dropped = (old_mask & ~new_mask);
		/* more bits in this fsn_mark than the inode's mask? */
		int do_inode = (new_mask & ~READ_ONCE(inode->i_fsnotify_mask));

		/* update the inode with this new fsn_mark */
		if (dropped || do_inode)
			fsnotify_recalc_mask(inode->i_fsnotify_marks);

	}

	/* return the wd */
	ret = i_mark->wd;

out:
	/* match the get from fsnotify_find_mark() */
	fsnotify_put_mark(fsn_mark);

	return ret;
}

static int inotify_new_watch(struct fsnotify_group *group,
			     struct inode *inode,
			     u32 arg)
{
	struct inotify_inode_mark *tmp_i_mark;
	int ret;
	struct idr *idr = &group->inotify_data.idr;
	spinlock_t *idr_lock = &group->inotify_data.idr_lock;

	tmp_i_mark = kmem_cache_alloc(inotify_inode_mark_cachep, GFP_KERNEL);
	if (unlikely(!tmp_i_mark))
		return -ENOMEM;

	fsnotify_init_mark(&tmp_i_mark->fsn_mark, group);
	tmp_i_mark->fsn_mark.mask = inotify_arg_to_mask(inode, arg);
	tmp_i_mark->fsn_mark.flags = inotify_arg_to_flags(arg);
	tmp_i_mark->wd = -1;

	ret = inotify_add_to_idr(idr, idr_lock, tmp_i_mark);
	if (ret)
		goto out_err;

	/* increment the number of watches the user has */
	if (!inc_inotify_watches(group->inotify_data.ucounts)) {
		inotify_remove_from_idr(group, tmp_i_mark);
		ret = -ENOSPC;
		goto out_err;
	}

	/* we are on the idr, now get on the inode */
	ret = fsnotify_add_inode_mark_locked(&tmp_i_mark->fsn_mark, inode, 0);
	if (ret) {
		/* we failed to get on the inode, get off the idr */
		inotify_remove_from_idr(group, tmp_i_mark);
		goto out_err;
	}


	/* return the watch descriptor for this new mark */
	ret = tmp_i_mark->wd;

out_err:
	/* match the ref from fsnotify_init_mark() */
	fsnotify_put_mark(&tmp_i_mark->fsn_mark);

	return ret;
}

static int inotify_update_watch(struct fsnotify_group *group, struct inode *inode, u32 arg)
{
	int ret = 0;

	fsnotify_group_lock(group);
	/* try to update and existing watch with the new arg */
	ret = inotify_update_existing_watch(group, inode, arg);
	/* no mark present, try to add a new one */
	if (ret == -ENOENT)
		ret = inotify_new_watch(group, inode, arg);
	fsnotify_group_unlock(group);

	return ret;
}

static struct fsnotify_group *inotify_new_group(unsigned int max_events)
{
	struct fsnotify_group *group;
	struct inotify_event_info *oevent;

	group = fsnotify_alloc_group(&inotify_fsnotify_ops,
				     FSNOTIFY_GROUP_USER);
	if (IS_ERR(group))
		return group;

	oevent = kmalloc(sizeof(struct inotify_event_info), GFP_KERNEL_ACCOUNT);
	if (unlikely(!oevent)) {
		fsnotify_destroy_group(group);
		return ERR_PTR(-ENOMEM);
	}
	group->overflow_event = &oevent->fse;
	fsnotify_init_event(group->overflow_event);
	oevent->mask = FS_Q_OVERFLOW;
	oevent->wd = -1;
	oevent->sync_cookie = 0;
	oevent->name_len = 0;

	group->max_events = max_events;
	group->memcg = get_mem_cgroup_from_mm(current->mm);

	spin_lock_init(&group->inotify_data.idr_lock);
	idr_init(&group->inotify_data.idr);
	group->inotify_data.ucounts = inc_ucount(current_user_ns(),
						 current_euid(),
						 UCOUNT_INOTIFY_INSTANCES);

	if (!group->inotify_data.ucounts) {
		fsnotify_destroy_group(group);
		return ERR_PTR(-EMFILE);
	}

	return group;
}


/* inotify syscalls */
static int do_inotify_init(int flags)
{
	struct fsnotify_group *group;
	int ret;

	/* Check the IN_* constants for consistency.  */
	BUILD_BUG_ON(IN_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON(IN_NONBLOCK != O_NONBLOCK);

	if (flags & ~(IN_CLOEXEC | IN_NONBLOCK))
		return -EINVAL;

	/* fsnotify_obtain_group took a reference to group, we put this when we kill the file in the end */
	group = inotify_new_group(inotify_max_queued_events);
	if (IS_ERR(group))
		return PTR_ERR(group);

	ret = anon_inode_getfd("inotify", &inotify_fops, group,
				  O_RDONLY | flags);
	if (ret < 0)
		fsnotify_destroy_group(group);

	return ret;
}

/**
 * sys_inotify_init1 - Initialize an inotify instance with flags
 * @flags: Flags controlling the behavior of the inotify instance
 *
 * long-desc: Creates a new inotify instance and returns a file descriptor
 *   referring to the inotify event queue. The inotify subsystem provides a
 *   mechanism for monitoring filesystem events. Applications can add watches
 *   to the inotify instance using inotify_add_watch(2), and events are read
 *   from the returned file descriptor using read(2).
 *
 *   The @flags parameter allows the caller to modify the default behavior:
 *   IN_CLOEXEC sets the close-on-exec (FD_CLOEXEC) flag on the new file
 *   descriptor, ensuring it is automatically closed during exec(). IN_NONBLOCK
 *   sets the O_NONBLOCK file status flag, causing read() to return EAGAIN
 *   instead of blocking when no events are available.
 *
 *   The inotify file descriptor can be used with poll(2), select(2), or
 *   epoll(7) to monitor for available events. Events are delivered as
 *   variable-length inotify_event structures when read from the descriptor.
 *
 *   When the file descriptor is closed (either explicitly or via close-on-exec),
 *   all watches associated with the inotify instance are automatically removed,
 *   and the resources are freed. The inotify instance persists as long as at
 *   least one file descriptor referring to it is open.
 *
 *   This syscall is functionally equivalent to inotify_init() when @flags is 0,
 *   but provides a race-free way to set O_CLOEXEC and O_NONBLOCK that is
 *   important for multi-threaded applications.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: flags
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: IN_CLOEXEC | IN_NONBLOCK
 *   constraint: Only IN_CLOEXEC (equivalent to O_CLOEXEC, 0x80000) and
 *     IN_NONBLOCK (equivalent to O_NONBLOCK, 0x800) are valid. Any other bits
 *     set will result in EINVAL. Pass 0 for default behavior (blocking reads,
 *     file descriptor not closed on exec).
 *
 * return:
 *   type: KAPI_TYPE_FD
 *   check-type: KAPI_RETURN_FD
 *   success: >= 0
 *   desc: On success, returns a new file descriptor for the inotify instance.
 *     This file descriptor can be used with inotify_add_watch(2) to add
 *     watches, and read(2) to retrieve inotify events. The descriptor is
 *     readable (O_RDONLY) and supports poll/select/epoll.
 *
 * error: EINVAL, Invalid flags
 *   desc: The @flags argument contains bits other than IN_CLOEXEC and
 *     IN_NONBLOCK. The kernel validates flags with (flags & ~(IN_CLOEXEC |
 *     IN_NONBLOCK)) and rejects any unknown flags. This allows future kernel
 *     versions to add new flags without breaking existing programs.
 *
 * error: EMFILE, Per-process file descriptor limit reached
 *   desc: The per-process limit on the number of open file descriptors has
 *     been reached. This limit is determined by RLIMIT_NOFILE, which can be
 *     queried via getrlimit(2) and modified via setrlimit(2) or prlimit(2).
 *     The default soft limit is typically 1024. This error is returned from
 *     get_unused_fd_flags() when alloc_fd() cannot find an available slot
 *     below the limit.
 *
 * error: EMFILE, Per-user inotify instance limit reached
 *   desc: The per-user limit on the number of inotify instances has been
 *     reached. This limit is controlled by /proc/sys/fs/inotify/max_user_instances
 *     (default 128). The limit is tracked via the user namespace ucount
 *     mechanism (UCOUNT_INOTIFY_INSTANCES) and applies per-user across all
 *     processes owned by that user. The check is performed in inotify_new_group()
 *     via inc_ucount().
 *
 * error: ENFILE, System-wide file limit reached
 *   desc: The system-wide limit on the total number of open files has been
 *     reached. This limit is controlled by /proc/sys/fs/file-max. Users with
 *     CAP_SYS_ADMIN capability can bypass this limit. This error is returned
 *     from alloc_empty_file() when the global file count (nr_files) exceeds
 *     files_stat.max_files.
 *
 * error: ENOMEM, Insufficient kernel memory
 *   desc: The kernel could not allocate memory for the required data
 *     structures. Memory is allocated for the fsnotify_group structure,
 *     the overflow event (inotify_event_info), the ucounts structure for
 *     resource tracking, the anonymous inode dentry, and the file structure.
 *     All allocations use GFP_KERNEL or GFP_KERNEL_ACCOUNT flags and can
 *     therefore trigger memory reclaim.
 *
 * lock: files->file_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The process's file descriptor table spinlock is acquired briefly
 *     during file descriptor allocation in alloc_fd(). This lock protects
 *     the fd table from concurrent modifications. The lock is held only
 *     during fd slot reservation and bitmap updates.
 *
 * lock: ucounts_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The global ucounts lock is acquired during user count tracking
 *     operations. It protects the per-user inotify instance count incremented
 *     by inc_ucount() in inotify_new_group(). The lock is held briefly with
 *     interrupts disabled.
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: inotify instance (fsnotify_group)
 *   desc: Creates a new fsnotify_group structure representing the inotify
 *     instance. The group contains the event queue, watch list (via IDR),
 *     and associated metadata. Memory is allocated via kzalloc() with
 *     GFP_KERNEL or GFP_KERNEL_ACCOUNT flags.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: File descriptor
 *   desc: Allocates and installs a new file descriptor in the calling
 *     process's file descriptor table. The descriptor refers to an
 *     anonymous inode with inotify-specific file operations. The descriptor
 *     is marked as open in the process's fd bitmap.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Per-user inotify instance count
 *   desc: Increments the per-user count of inotify instances tracked via
 *     the user namespace ucount mechanism. This count is decremented when
 *     the inotify instance is destroyed (file descriptor closed and all
 *     references released).
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: System-wide open file count
 *   desc: Increments the global nr_files counter via percpu_counter_inc()
 *     when the file structure is allocated. This count is tracked against
 *     the system-wide limit /proc/sys/fs/file-max.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: Memory cgroup
 *   desc: Memory allocations are charged to the calling process's memory
 *     cgroup via GFP_KERNEL_ACCOUNT. The group holds a reference to the
 *     memcg obtained via get_mem_cgroup_from_mm().
 *   reversible: yes
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass system-wide file limit check
 *   without: Subject to /proc/sys/fs/file-max limit (returns ENFILE when
 *     exceeded)
 *   condition: Checked in alloc_empty_file() when system file count exceeds
 *     files_stat.max_files
 *
 * constraint: max_user_instances
 *   desc: The per-user limit /proc/sys/fs/inotify/max_user_instances
 *     (default 128) limits how many inotify instances a single user can
 *     create across all processes. This limit is namespace-aware and can
 *     be configured per user namespace.
 *
 * constraint: RLIMIT_NOFILE
 *   desc: The per-process file descriptor limit controls the maximum file
 *     descriptor number that can be allocated. The soft limit defaults to
 *     1024 and can be raised up to the hard limit via setrlimit(2).
 *
 * constraint: /proc/sys/fs/file-max
 *   desc: The system-wide limit on total open files. When this limit is
 *     reached, only processes with CAP_SYS_ADMIN can create new files.
 *     Default value depends on system memory.
 *
 * constraint: /proc/sys/fs/nr_open
 *   desc: The system-wide maximum value for RLIMIT_NOFILE. Defaults to
 *     approximately 1M. This provides an upper bound on per-process file
 *     descriptor limits.
 *
 * examples: fd = inotify_init1(IN_CLOEXEC);  // Create with close-on-exec
 *   fd = inotify_init1(IN_NONBLOCK);  // Create with non-blocking reads
 *   fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);  // Both flags
 *   fd = inotify_init1(0);  // Equivalent to inotify_init()
 *   // Error handling: if (fd < 0) { perror("inotify_init1"); }
 *
 * notes: inotify_init1() was introduced in Linux 2.6.27 to provide atomic
 *   flag setting. The older inotify_init() syscall is equivalent to
 *   inotify_init1(0) and remains available for compatibility.
 *
 *   The IN_CLOEXEC flag is particularly important in multi-threaded programs
 *   to prevent file descriptor leaks across fork()/exec() sequences. Without
 *   this flag, there is a race window where another thread could fork()
 *   before fcntl(F_SETFD, FD_CLOEXEC) is called.
 *
 *   The max_user_instances limit (default 128) is per user, not per process.
 *   Applications creating many inotify instances should be aware of this limit.
 *   The limit can be increased via /proc/sys/fs/inotify/max_user_instances.
 *
 *   Unlike some syscalls, inotify_init1() does not use interruptible waits
 *   and therefore cannot return EINTR. Memory allocation uses GFP_KERNEL
 *   which may block but is not signal-interruptible.
 *
 *   The returned file descriptor supports read(), poll(), select(), and
 *   epoll(). It does not support write(), lseek(), or mmap(). The FIONREAD
 *   ioctl can be used to determine the number of bytes available to read.
 *
 *   Historical note: Early inotify implementations had memory leak and
 *   double-free bugs on error paths (fixed in commits a2ae4cc9a16e and
 *   d0de4dc584ec). Current implementations properly clean up resources
 *   on all error paths.
 *
 * since-version: 2.6.27
 */
SYSCALL_DEFINE1(inotify_init1, int, flags)
{
	return do_inotify_init(flags);
}

SYSCALL_DEFINE0(inotify_init)
{
	return do_inotify_init(0);
}

SYSCALL_DEFINE3(inotify_add_watch, int, fd, const char __user *, pathname,
		u32, mask)
{
	struct fsnotify_group *group;
	struct inode *inode;
	struct path path;
	int ret;
	unsigned flags = 0;

	/*
	 * We share a lot of code with fs/dnotify.  We also share
	 * the bit layout between inotify's IN_* and the fsnotify
	 * FS_*.  This check ensures that only the inotify IN_*
	 * bits get passed in and set in watches/events.
	 */
	if (unlikely(mask & ~ALL_INOTIFY_BITS))
		return -EINVAL;
	/*
	 * Require at least one valid bit set in the mask.
	 * Without _something_ set, we would have no events to
	 * watch for.
	 */
	if (unlikely(!(mask & ALL_INOTIFY_BITS)))
		return -EINVAL;

	CLASS(fd, f)(fd);
	if (fd_empty(f))
		return -EBADF;

	/* IN_MASK_ADD and IN_MASK_CREATE don't make sense together */
	if (unlikely((mask & IN_MASK_ADD) && (mask & IN_MASK_CREATE)))
		return -EINVAL;

	/* verify that this is indeed an inotify instance */
	if (unlikely(fd_file(f)->f_op != &inotify_fops))
		return -EINVAL;

	if (!(mask & IN_DONT_FOLLOW))
		flags |= LOOKUP_FOLLOW;
	if (mask & IN_ONLYDIR)
		flags |= LOOKUP_DIRECTORY;

	ret = inotify_find_inode(pathname, &path, flags,
			(mask & IN_ALL_EVENTS));
	if (ret)
		return ret;

	/* inode held in place by reference to path; group by fget on fd */
	inode = path.dentry->d_inode;
	group = fd_file(f)->private_data;

	/* create/update an inode mark */
	ret = inotify_update_watch(group, inode, mask);
	path_put(&path);
	return ret;
}

SYSCALL_DEFINE2(inotify_rm_watch, int, fd, __s32, wd)
{
	struct fsnotify_group *group;
	struct inotify_inode_mark *i_mark;
	CLASS(fd, f)(fd);

	if (fd_empty(f))
		return -EBADF;

	/* verify that this is indeed an inotify instance */
	if (unlikely(fd_file(f)->f_op != &inotify_fops))
		return -EINVAL;

	group = fd_file(f)->private_data;

	i_mark = inotify_idr_find(group, wd);
	if (unlikely(!i_mark))
		return -EINVAL;

	fsnotify_destroy_mark(&i_mark->fsn_mark, group);

	/* match ref taken by inotify_idr_find */
	fsnotify_put_mark(&i_mark->fsn_mark);
	return 0;
}

/*
 * inotify_user_setup - Our initialization function.  Note that we cannot return
 * error because we have compiled-in VFS hooks.  So an (unlikely) failure here
 * must result in panic().
 */
static int __init inotify_user_setup(void)
{
	unsigned long watches_max;
	struct sysinfo si;

	si_meminfo(&si);
	/*
	 * Allow up to 1% of addressable memory to be allocated for inotify
	 * watches (per user) limited to the range [8192, 1048576].
	 */
	watches_max = (((si.totalram - si.totalhigh) / 100) << PAGE_SHIFT) /
			INOTIFY_WATCH_COST;
	watches_max = clamp(watches_max, 8192UL, 1048576UL);

	BUILD_BUG_ON(IN_ACCESS != FS_ACCESS);
	BUILD_BUG_ON(IN_MODIFY != FS_MODIFY);
	BUILD_BUG_ON(IN_ATTRIB != FS_ATTRIB);
	BUILD_BUG_ON(IN_CLOSE_WRITE != FS_CLOSE_WRITE);
	BUILD_BUG_ON(IN_CLOSE_NOWRITE != FS_CLOSE_NOWRITE);
	BUILD_BUG_ON(IN_OPEN != FS_OPEN);
	BUILD_BUG_ON(IN_MOVED_FROM != FS_MOVED_FROM);
	BUILD_BUG_ON(IN_MOVED_TO != FS_MOVED_TO);
	BUILD_BUG_ON(IN_CREATE != FS_CREATE);
	BUILD_BUG_ON(IN_DELETE != FS_DELETE);
	BUILD_BUG_ON(IN_DELETE_SELF != FS_DELETE_SELF);
	BUILD_BUG_ON(IN_MOVE_SELF != FS_MOVE_SELF);
	BUILD_BUG_ON(IN_UNMOUNT != FS_UNMOUNT);
	BUILD_BUG_ON(IN_Q_OVERFLOW != FS_Q_OVERFLOW);
	BUILD_BUG_ON(IN_IGNORED != FS_IN_IGNORED);
	BUILD_BUG_ON(IN_ISDIR != FS_ISDIR);

	BUILD_BUG_ON(HWEIGHT32(ALL_INOTIFY_BITS) != 22);

	inotify_inode_mark_cachep = KMEM_CACHE(inotify_inode_mark,
					       SLAB_PANIC|SLAB_ACCOUNT);

	inotify_max_queued_events = 16384;
	init_user_ns.ucount_max[UCOUNT_INOTIFY_INSTANCES] = 128;
	init_user_ns.ucount_max[UCOUNT_INOTIFY_WATCHES] = watches_max;
	inotify_sysctls_init();

	return 0;
}
fs_initcall(inotify_user_setup);
