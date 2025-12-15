// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  fs/eventpoll.c (Efficient event retrieval implementation)
 *  Copyright (C) 2001,...,2009	 Davide Libenzi
 *
 *  Davide Libenzi <davidel@xmailserver.org>
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/eventpoll.h>
#include <linux/mount.h>
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/anon_inodes.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/mman.h>
#include <linux/atomic.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/compat.h>
#include <linux/rculist.h>
#include <linux/capability.h>
#include <net/busy_poll.h>

/*
 * LOCKING:
 * There are three level of locking required by epoll :
 *
 * 1) epnested_mutex (mutex)
 * 2) ep->mtx (mutex)
 * 3) ep->lock (spinlock)
 *
 * The acquire order is the one listed above, from 1 to 3.
 * We need a spinlock (ep->lock) because we manipulate objects
 * from inside the poll callback, that might be triggered from
 * a wake_up() that in turn might be called from IRQ context.
 * So we can't sleep inside the poll callback and hence we need
 * a spinlock. During the event transfer loop (from kernel to
 * user space) we could end up sleeping due a copy_to_user(), so
 * we need a lock that will allow us to sleep. This lock is a
 * mutex (ep->mtx). It is acquired during the event transfer loop,
 * during epoll_ctl(EPOLL_CTL_DEL) and during eventpoll_release_file().
 * The epnested_mutex is acquired when inserting an epoll fd onto another
 * epoll fd. We do this so that we walk the epoll tree and ensure that this
 * insertion does not create a cycle of epoll file descriptors, which
 * could lead to deadlock. We need a global mutex to prevent two
 * simultaneous inserts (A into B and B into A) from racing and
 * constructing a cycle without either insert observing that it is
 * going to.
 * It is necessary to acquire multiple "ep->mtx"es at once in the
 * case when one epoll fd is added to another. In this case, we
 * always acquire the locks in the order of nesting (i.e. after
 * epoll_ctl(e1, EPOLL_CTL_ADD, e2), e1->mtx will always be acquired
 * before e2->mtx). Since we disallow cycles of epoll file
 * descriptors, this ensures that the mutexes are well-ordered. In
 * order to communicate this nesting to lockdep, when walking a tree
 * of epoll file descriptors, we use the current recursion depth as
 * the lockdep subkey.
 * It is possible to drop the "ep->mtx" and to use the global
 * mutex "epnested_mutex" (together with "ep->lock") to have it working,
 * but having "ep->mtx" will make the interface more scalable.
 * Events that require holding "epnested_mutex" are very rare, while for
 * normal operations the epoll private "ep->mtx" will guarantee
 * a better scalability.
 */

/* Epoll private bits inside the event mask */
#define EP_PRIVATE_BITS (EPOLLWAKEUP | EPOLLONESHOT | EPOLLET | EPOLLEXCLUSIVE)

#define EPOLLINOUT_BITS (EPOLLIN | EPOLLOUT)

#define EPOLLEXCLUSIVE_OK_BITS (EPOLLINOUT_BITS | EPOLLERR | EPOLLHUP | \
				EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE)

/* Maximum number of nesting allowed inside epoll sets */
#define EP_MAX_NESTS 4

#define EP_MAX_EVENTS (INT_MAX / sizeof(struct epoll_event))

#define EP_UNACTIVE_PTR ((void *) -1L)

#define EP_ITEM_COST (sizeof(struct epitem) + sizeof(struct eppoll_entry))

struct epoll_filefd {
	struct file *file;
	int fd;
} __packed;

/* Wait structure used by the poll hooks */
struct eppoll_entry {
	/* List header used to link this structure to the "struct epitem" */
	struct eppoll_entry *next;

	/* The "base" pointer is set to the container "struct epitem" */
	struct epitem *base;

	/*
	 * Wait queue item that will be linked to the target file wait
	 * queue head.
	 */
	wait_queue_entry_t wait;

	/* The wait queue head that linked the "wait" wait queue item */
	wait_queue_head_t *whead;
};

/*
 * Each file descriptor added to the eventpoll interface will
 * have an entry of this type linked to the "rbr" RB tree.
 * Avoid increasing the size of this struct, there can be many thousands
 * of these on a server and we do not want this to take another cache line.
 */
struct epitem {
	union {
		/* RB tree node links this structure to the eventpoll RB tree */
		struct rb_node rbn;
		/* Used to free the struct epitem */
		struct rcu_head rcu;
	};

	/* List header used to link this structure to the eventpoll ready list */
	struct list_head rdllink;

	/*
	 * Works together "struct eventpoll"->ovflist in keeping the
	 * single linked chain of items.
	 */
	struct epitem *next;

	/* The file descriptor information this item refers to */
	struct epoll_filefd ffd;

	/*
	 * Protected by file->f_lock, true for to-be-released epitem already
	 * removed from the "struct file" items list; together with
	 * eventpoll->refcount orchestrates "struct eventpoll" disposal
	 */
	bool dying;

	/* List containing poll wait queues */
	struct eppoll_entry *pwqlist;

	/* The "container" of this item */
	struct eventpoll *ep;

	/* List header used to link this item to the "struct file" items list */
	struct hlist_node fllink;

	/* wakeup_source used when EPOLLWAKEUP is set */
	struct wakeup_source __rcu *ws;

	/* The structure that describe the interested events and the source fd */
	struct epoll_event event;
};

/*
 * This structure is stored inside the "private_data" member of the file
 * structure and represents the main data structure for the eventpoll
 * interface.
 */
struct eventpoll {
	/*
	 * This mutex is used to ensure that files are not removed
	 * while epoll is using them. This is held during the event
	 * collection loop, the file cleanup path, the epoll file exit
	 * code and the ctl operations.
	 */
	struct mutex mtx;

	/* Wait queue used by sys_epoll_wait() */
	wait_queue_head_t wq;

	/* Wait queue used by file->poll() */
	wait_queue_head_t poll_wait;

	/* List of ready file descriptors */
	struct list_head rdllist;

	/* Lock which protects rdllist and ovflist */
	spinlock_t lock;

	/* RB tree root used to store monitored fd structs */
	struct rb_root_cached rbr;

	/*
	 * This is a single linked list that chains all the "struct epitem" that
	 * happened while transferring ready events to userspace w/out
	 * holding ->lock.
	 */
	struct epitem *ovflist;

	/* wakeup_source used when ep_send_events or __ep_eventpoll_poll is running */
	struct wakeup_source *ws;

	/* The user that created the eventpoll descriptor */
	struct user_struct *user;

	struct file *file;

	/* used to optimize loop detection check */
	u64 gen;
	struct hlist_head refs;
	u8 loop_check_depth;

	/*
	 * usage count, used together with epitem->dying to
	 * orchestrate the disposal of this struct
	 */
	refcount_t refcount;

#ifdef CONFIG_NET_RX_BUSY_POLL
	/* used to track busy poll napi_id */
	unsigned int napi_id;
	/* busy poll timeout */
	u32 busy_poll_usecs;
	/* busy poll packet budget */
	u16 busy_poll_budget;
	bool prefer_busy_poll;
#endif

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/* tracks wakeup nests for lockdep validation */
	u8 nests;
#endif
};

/* Wrapper struct used by poll queueing */
struct ep_pqueue {
	poll_table pt;
	struct epitem *epi;
};

/*
 * Configuration options available inside /proc/sys/fs/epoll/
 */
/* Maximum number of epoll watched descriptors, per user */
static long max_user_watches __read_mostly;

/* Used for cycles detection */
static DEFINE_MUTEX(epnested_mutex);

static u64 loop_check_gen = 0;

/* Used to check for epoll file descriptor inclusion loops */
static struct eventpoll *inserting_into;

/* Slab cache used to allocate "struct epitem" */
static struct kmem_cache *epi_cache __ro_after_init;

/* Slab cache used to allocate "struct eppoll_entry" */
static struct kmem_cache *pwq_cache __ro_after_init;

/*
 * List of files with newly added links, where we may need to limit the number
 * of emanating paths. Protected by the epnested_mutex.
 */
struct epitems_head {
	struct hlist_head epitems;
	struct epitems_head *next;
};
static struct epitems_head *tfile_check_list = EP_UNACTIVE_PTR;

static struct kmem_cache *ephead_cache __ro_after_init;

static inline void free_ephead(struct epitems_head *head)
{
	if (head)
		kmem_cache_free(ephead_cache, head);
}

static void list_file(struct file *file)
{
	struct epitems_head *head;

	head = container_of(file->f_ep, struct epitems_head, epitems);
	if (!head->next) {
		head->next = tfile_check_list;
		tfile_check_list = head;
	}
}

static void unlist_file(struct epitems_head *head)
{
	struct epitems_head *to_free = head;
	struct hlist_node *p = rcu_dereference(hlist_first_rcu(&head->epitems));
	if (p) {
		struct epitem *epi= container_of(p, struct epitem, fllink);
		spin_lock(&epi->ffd.file->f_lock);
		if (!hlist_empty(&head->epitems))
			to_free = NULL;
		head->next = NULL;
		spin_unlock(&epi->ffd.file->f_lock);
	}
	free_ephead(to_free);
}

#ifdef CONFIG_SYSCTL

#include <linux/sysctl.h>

static long long_zero;
static long long_max = LONG_MAX;

static const struct ctl_table epoll_table[] = {
	{
		.procname	= "max_user_watches",
		.data		= &max_user_watches,
		.maxlen		= sizeof(max_user_watches),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
		.extra1		= &long_zero,
		.extra2		= &long_max,
	},
};

static void __init epoll_sysctls_init(void)
{
	register_sysctl("fs/epoll", epoll_table);
}
#else
#define epoll_sysctls_init() do { } while (0)
#endif /* CONFIG_SYSCTL */

static const struct file_operations eventpoll_fops;

static inline int is_file_epoll(struct file *f)
{
	return f->f_op == &eventpoll_fops;
}

/* Setup the structure that is used as key for the RB tree */
static inline void ep_set_ffd(struct epoll_filefd *ffd,
			      struct file *file, int fd)
{
	ffd->file = file;
	ffd->fd = fd;
}

/* Compare RB tree keys */
static inline int ep_cmp_ffd(struct epoll_filefd *p1,
			     struct epoll_filefd *p2)
{
	return (p1->file > p2->file ? +1:
	        (p1->file < p2->file ? -1 : p1->fd - p2->fd));
}

/* Tells us if the item is currently linked */
static inline int ep_is_linked(struct epitem *epi)
{
	return !list_empty(&epi->rdllink);
}

static inline struct eppoll_entry *ep_pwq_from_wait(wait_queue_entry_t *p)
{
	return container_of(p, struct eppoll_entry, wait);
}

/* Get the "struct epitem" from a wait queue pointer */
static inline struct epitem *ep_item_from_wait(wait_queue_entry_t *p)
{
	return container_of(p, struct eppoll_entry, wait)->base;
}

/**
 * ep_events_available - Checks if ready events might be available.
 *
 * @ep: Pointer to the eventpoll context.
 *
 * Return: a value different than %zero if ready events are available,
 *          or %zero otherwise.
 */
static inline int ep_events_available(struct eventpoll *ep)
{
	return !list_empty_careful(&ep->rdllist) ||
		READ_ONCE(ep->ovflist) != EP_UNACTIVE_PTR;
}

#ifdef CONFIG_NET_RX_BUSY_POLL
/**
 * busy_loop_ep_timeout - check if busy poll has timed out. The timeout value
 * from the epoll instance ep is preferred, but if it is not set fallback to
 * the system-wide global via busy_loop_timeout.
 *
 * @start_time: The start time used to compute the remaining time until timeout.
 * @ep: Pointer to the eventpoll context.
 *
 * Return: true if the timeout has expired, false otherwise.
 */
static bool busy_loop_ep_timeout(unsigned long start_time,
				 struct eventpoll *ep)
{
	unsigned long bp_usec = READ_ONCE(ep->busy_poll_usecs);

	if (bp_usec) {
		unsigned long end_time = start_time + bp_usec;
		unsigned long now = busy_loop_current_time();

		return time_after(now, end_time);
	} else {
		return busy_loop_timeout(start_time);
	}
}

static bool ep_busy_loop_on(struct eventpoll *ep)
{
	return !!READ_ONCE(ep->busy_poll_usecs) ||
	       READ_ONCE(ep->prefer_busy_poll) ||
	       net_busy_loop_on();
}

static bool ep_busy_loop_end(void *p, unsigned long start_time)
{
	struct eventpoll *ep = p;

	return ep_events_available(ep) || busy_loop_ep_timeout(start_time, ep);
}

/*
 * Busy poll if globally on and supporting sockets found && no events,
 * busy loop will return if need_resched or ep_events_available.
 *
 * we must do our busy polling with irqs enabled
 */
static bool ep_busy_loop(struct eventpoll *ep)
{
	unsigned int napi_id = READ_ONCE(ep->napi_id);
	u16 budget = READ_ONCE(ep->busy_poll_budget);
	bool prefer_busy_poll = READ_ONCE(ep->prefer_busy_poll);

	if (!budget)
		budget = BUSY_POLL_BUDGET;

	if (napi_id_valid(napi_id) && ep_busy_loop_on(ep)) {
		napi_busy_loop(napi_id, ep_busy_loop_end,
			       ep, prefer_busy_poll, budget);
		if (ep_events_available(ep))
			return true;
		/*
		 * Busy poll timed out.  Drop NAPI ID for now, we can add
		 * it back in when we have moved a socket with a valid NAPI
		 * ID onto the ready list.
		 */
		if (prefer_busy_poll)
			napi_resume_irqs(napi_id);
		ep->napi_id = 0;
		return false;
	}
	return false;
}

/*
 * Set epoll busy poll NAPI ID from sk.
 */
static inline void ep_set_busy_poll_napi_id(struct epitem *epi)
{
	struct eventpoll *ep = epi->ep;
	unsigned int napi_id;
	struct socket *sock;
	struct sock *sk;

	if (!ep_busy_loop_on(ep))
		return;

	sock = sock_from_file(epi->ffd.file);
	if (!sock)
		return;

	sk = sock->sk;
	if (!sk)
		return;

	napi_id = READ_ONCE(sk->sk_napi_id);

	/* Non-NAPI IDs can be rejected
	 *	or
	 * Nothing to do if we already have this ID
	 */
	if (!napi_id_valid(napi_id) || napi_id == ep->napi_id)
		return;

	/* record NAPI ID for use in next busy poll */
	ep->napi_id = napi_id;
}

static long ep_eventpoll_bp_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	struct eventpoll *ep = file->private_data;
	void __user *uarg = (void __user *)arg;
	struct epoll_params epoll_params;

	switch (cmd) {
	case EPIOCSPARAMS:
		if (copy_from_user(&epoll_params, uarg, sizeof(epoll_params)))
			return -EFAULT;

		/* pad byte must be zero */
		if (epoll_params.__pad)
			return -EINVAL;

		if (epoll_params.busy_poll_usecs > S32_MAX)
			return -EINVAL;

		if (epoll_params.prefer_busy_poll > 1)
			return -EINVAL;

		if (epoll_params.busy_poll_budget > NAPI_POLL_WEIGHT &&
		    !capable(CAP_NET_ADMIN))
			return -EPERM;

		WRITE_ONCE(ep->busy_poll_usecs, epoll_params.busy_poll_usecs);
		WRITE_ONCE(ep->busy_poll_budget, epoll_params.busy_poll_budget);
		WRITE_ONCE(ep->prefer_busy_poll, epoll_params.prefer_busy_poll);
		return 0;
	case EPIOCGPARAMS:
		memset(&epoll_params, 0, sizeof(epoll_params));
		epoll_params.busy_poll_usecs = READ_ONCE(ep->busy_poll_usecs);
		epoll_params.busy_poll_budget = READ_ONCE(ep->busy_poll_budget);
		epoll_params.prefer_busy_poll = READ_ONCE(ep->prefer_busy_poll);
		if (copy_to_user(uarg, &epoll_params, sizeof(epoll_params)))
			return -EFAULT;
		return 0;
	default:
		return -ENOIOCTLCMD;
	}
}

static void ep_suspend_napi_irqs(struct eventpoll *ep)
{
	unsigned int napi_id = READ_ONCE(ep->napi_id);

	if (napi_id_valid(napi_id) && READ_ONCE(ep->prefer_busy_poll))
		napi_suspend_irqs(napi_id);
}

static void ep_resume_napi_irqs(struct eventpoll *ep)
{
	unsigned int napi_id = READ_ONCE(ep->napi_id);

	if (napi_id_valid(napi_id) && READ_ONCE(ep->prefer_busy_poll))
		napi_resume_irqs(napi_id);
}

#else

static inline bool ep_busy_loop(struct eventpoll *ep)
{
	return false;
}

static inline void ep_set_busy_poll_napi_id(struct epitem *epi)
{
}

static long ep_eventpoll_bp_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	return -EOPNOTSUPP;
}

static void ep_suspend_napi_irqs(struct eventpoll *ep)
{
}

static void ep_resume_napi_irqs(struct eventpoll *ep)
{
}

#endif /* CONFIG_NET_RX_BUSY_POLL */

/*
 * As described in commit 0ccf831cb lockdep: annotate epoll
 * the use of wait queues used by epoll is done in a very controlled
 * manner. Wake ups can nest inside each other, but are never done
 * with the same locking. For example:
 *
 *   dfd = socket(...);
 *   efd1 = epoll_create();
 *   efd2 = epoll_create();
 *   epoll_ctl(efd1, EPOLL_CTL_ADD, dfd, ...);
 *   epoll_ctl(efd2, EPOLL_CTL_ADD, efd1, ...);
 *
 * When a packet arrives to the device underneath "dfd", the net code will
 * issue a wake_up() on its poll wake list. Epoll (efd1) has installed a
 * callback wakeup entry on that queue, and the wake_up() performed by the
 * "dfd" net code will end up in ep_poll_callback(). At this point epoll
 * (efd1) notices that it may have some event ready, so it needs to wake up
 * the waiters on its poll wait list (efd2). So it calls ep_poll_safewake()
 * that ends up in another wake_up(), after having checked about the
 * recursion constraints. That are, no more than EP_MAX_NESTS, to avoid
 * stack blasting.
 *
 * When CONFIG_DEBUG_LOCK_ALLOC is enabled, make sure lockdep can handle
 * this special case of epoll.
 */
#ifdef CONFIG_DEBUG_LOCK_ALLOC

static void ep_poll_safewake(struct eventpoll *ep, struct epitem *epi,
			     unsigned pollflags)
{
	struct eventpoll *ep_src;
	unsigned long flags;
	u8 nests = 0;

	/*
	 * To set the subclass or nesting level for spin_lock_irqsave_nested()
	 * it might be natural to create a per-cpu nest count. However, since
	 * we can recurse on ep->poll_wait.lock, and a non-raw spinlock can
	 * schedule() in the -rt kernel, the per-cpu variable are no longer
	 * protected. Thus, we are introducing a per eventpoll nest field.
	 * If we are not being call from ep_poll_callback(), epi is NULL and
	 * we are at the first level of nesting, 0. Otherwise, we are being
	 * called from ep_poll_callback() and if a previous wakeup source is
	 * not an epoll file itself, we are at depth 1 since the wakeup source
	 * is depth 0. If the wakeup source is a previous epoll file in the
	 * wakeup chain then we use its nests value and record ours as
	 * nests + 1. The previous epoll file nests value is stable since its
	 * already holding its own poll_wait.lock.
	 */
	if (epi) {
		if ((is_file_epoll(epi->ffd.file))) {
			ep_src = epi->ffd.file->private_data;
			nests = ep_src->nests;
		} else {
			nests = 1;
		}
	}
	spin_lock_irqsave_nested(&ep->poll_wait.lock, flags, nests);
	ep->nests = nests + 1;
	wake_up_locked_poll(&ep->poll_wait, EPOLLIN | pollflags);
	ep->nests = 0;
	spin_unlock_irqrestore(&ep->poll_wait.lock, flags);
}

#else

static void ep_poll_safewake(struct eventpoll *ep, struct epitem *epi,
			     __poll_t pollflags)
{
	wake_up_poll(&ep->poll_wait, EPOLLIN | pollflags);
}

#endif

static void ep_remove_wait_queue(struct eppoll_entry *pwq)
{
	wait_queue_head_t *whead;

	rcu_read_lock();
	/*
	 * If it is cleared by POLLFREE, it should be rcu-safe.
	 * If we read NULL we need a barrier paired with
	 * smp_store_release() in ep_poll_callback(), otherwise
	 * we rely on whead->lock.
	 */
	whead = smp_load_acquire(&pwq->whead);
	if (whead)
		remove_wait_queue(whead, &pwq->wait);
	rcu_read_unlock();
}

/*
 * This function unregisters poll callbacks from the associated file
 * descriptor.  Must be called with "mtx" held.
 */
static void ep_unregister_pollwait(struct eventpoll *ep, struct epitem *epi)
{
	struct eppoll_entry **p = &epi->pwqlist;
	struct eppoll_entry *pwq;

	while ((pwq = *p) != NULL) {
		*p = pwq->next;
		ep_remove_wait_queue(pwq);
		kmem_cache_free(pwq_cache, pwq);
	}
}

/* call only when ep->mtx is held */
static inline struct wakeup_source *ep_wakeup_source(struct epitem *epi)
{
	return rcu_dereference_check(epi->ws, lockdep_is_held(&epi->ep->mtx));
}

/* call only when ep->mtx is held */
static inline void ep_pm_stay_awake(struct epitem *epi)
{
	struct wakeup_source *ws = ep_wakeup_source(epi);

	if (ws)
		__pm_stay_awake(ws);
}

static inline bool ep_has_wakeup_source(struct epitem *epi)
{
	return rcu_access_pointer(epi->ws) ? true : false;
}

/* call when ep->mtx cannot be held (ep_poll_callback) */
static inline void ep_pm_stay_awake_rcu(struct epitem *epi)
{
	struct wakeup_source *ws;

	rcu_read_lock();
	ws = rcu_dereference(epi->ws);
	if (ws)
		__pm_stay_awake(ws);
	rcu_read_unlock();
}


/*
 * ep->mutex needs to be held because we could be hit by
 * eventpoll_release_file() and epoll_ctl().
 */
static void ep_start_scan(struct eventpoll *ep, struct list_head *txlist)
{
	/*
	 * Steal the ready list, and re-init the original one to the
	 * empty list. Also, set ep->ovflist to NULL so that events
	 * happening while looping w/out locks, are not lost. We cannot
	 * have the poll callback to queue directly on ep->rdllist,
	 * because we want the "sproc" callback to be able to do it
	 * in a lockless way.
	 */
	lockdep_assert_irqs_enabled();
	spin_lock_irq(&ep->lock);
	list_splice_init(&ep->rdllist, txlist);
	WRITE_ONCE(ep->ovflist, NULL);
	spin_unlock_irq(&ep->lock);
}

static void ep_done_scan(struct eventpoll *ep,
			 struct list_head *txlist)
{
	struct epitem *epi, *nepi;

	spin_lock_irq(&ep->lock);
	/*
	 * During the time we spent inside the "sproc" callback, some
	 * other events might have been queued by the poll callback.
	 * We re-insert them inside the main ready-list here.
	 */
	for (nepi = READ_ONCE(ep->ovflist); (epi = nepi) != NULL;
	     nepi = epi->next, epi->next = EP_UNACTIVE_PTR) {
		/*
		 * We need to check if the item is already in the list.
		 * During the "sproc" callback execution time, items are
		 * queued into ->ovflist but the "txlist" might already
		 * contain them, and the list_splice() below takes care of them.
		 */
		if (!ep_is_linked(epi)) {
			/*
			 * ->ovflist is LIFO, so we have to reverse it in order
			 * to keep in FIFO.
			 */
			list_add(&epi->rdllink, &ep->rdllist);
			ep_pm_stay_awake(epi);
		}
	}
	/*
	 * We need to set back ep->ovflist to EP_UNACTIVE_PTR, so that after
	 * releasing the lock, events will be queued in the normal way inside
	 * ep->rdllist.
	 */
	WRITE_ONCE(ep->ovflist, EP_UNACTIVE_PTR);

	/*
	 * Quickly re-inject items left on "txlist".
	 */
	list_splice(txlist, &ep->rdllist);
	__pm_relax(ep->ws);

	if (!list_empty(&ep->rdllist)) {
		if (waitqueue_active(&ep->wq))
			wake_up(&ep->wq);
	}

	spin_unlock_irq(&ep->lock);
}

static void ep_get(struct eventpoll *ep)
{
	refcount_inc(&ep->refcount);
}

/*
 * Returns true if the event poll can be disposed
 */
static bool ep_refcount_dec_and_test(struct eventpoll *ep)
{
	if (!refcount_dec_and_test(&ep->refcount))
		return false;

	WARN_ON_ONCE(!RB_EMPTY_ROOT(&ep->rbr.rb_root));
	return true;
}

static void ep_free(struct eventpoll *ep)
{
	ep_resume_napi_irqs(ep);
	mutex_destroy(&ep->mtx);
	free_uid(ep->user);
	wakeup_source_unregister(ep->ws);
	kfree(ep);
}

/*
 * Removes a "struct epitem" from the eventpoll RB tree and deallocates
 * all the associated resources. Must be called with "mtx" held.
 * If the dying flag is set, do the removal only if force is true.
 * This prevents ep_clear_and_put() from dropping all the ep references
 * while running concurrently with eventpoll_release_file().
 * Returns true if the eventpoll can be disposed.
 */
static bool __ep_remove(struct eventpoll *ep, struct epitem *epi, bool force)
{
	struct file *file = epi->ffd.file;
	struct epitems_head *to_free;
	struct hlist_head *head;

	lockdep_assert_irqs_enabled();

	/*
	 * Removes poll wait queue hooks.
	 */
	ep_unregister_pollwait(ep, epi);

	/* Remove the current item from the list of epoll hooks */
	spin_lock(&file->f_lock);
	if (epi->dying && !force) {
		spin_unlock(&file->f_lock);
		return false;
	}

	to_free = NULL;
	head = file->f_ep;
	if (head->first == &epi->fllink && !epi->fllink.next) {
		/* See eventpoll_release() for details. */
		WRITE_ONCE(file->f_ep, NULL);
		if (!is_file_epoll(file)) {
			struct epitems_head *v;
			v = container_of(head, struct epitems_head, epitems);
			if (!smp_load_acquire(&v->next))
				to_free = v;
		}
	}
	hlist_del_rcu(&epi->fllink);
	spin_unlock(&file->f_lock);
	free_ephead(to_free);

	rb_erase_cached(&epi->rbn, &ep->rbr);

	spin_lock_irq(&ep->lock);
	if (ep_is_linked(epi))
		list_del_init(&epi->rdllink);
	spin_unlock_irq(&ep->lock);

	wakeup_source_unregister(ep_wakeup_source(epi));
	/*
	 * At this point it is safe to free the eventpoll item. Use the union
	 * field epi->rcu, since we are trying to minimize the size of
	 * 'struct epitem'. The 'rbn' field is no longer in use. Protected by
	 * ep->mtx. The rcu read side, reverse_path_check_proc(), does not make
	 * use of the rbn field.
	 */
	kfree_rcu(epi, rcu);

	percpu_counter_dec(&ep->user->epoll_watches);
	return true;
}

/*
 * ep_remove variant for callers owing an additional reference to the ep
 */
static void ep_remove_safe(struct eventpoll *ep, struct epitem *epi)
{
	if (__ep_remove(ep, epi, false))
		WARN_ON_ONCE(ep_refcount_dec_and_test(ep));
}

static void ep_clear_and_put(struct eventpoll *ep)
{
	struct rb_node *rbp, *next;
	struct epitem *epi;

	/* We need to release all tasks waiting for these file */
	if (waitqueue_active(&ep->poll_wait))
		ep_poll_safewake(ep, NULL, 0);

	mutex_lock(&ep->mtx);

	/*
	 * Walks through the whole tree by unregistering poll callbacks.
	 */
	for (rbp = rb_first_cached(&ep->rbr); rbp; rbp = rb_next(rbp)) {
		epi = rb_entry(rbp, struct epitem, rbn);

		ep_unregister_pollwait(ep, epi);
		cond_resched();
	}

	/*
	 * Walks through the whole tree and try to free each "struct epitem".
	 * Note that ep_remove_safe() will not remove the epitem in case of a
	 * racing eventpoll_release_file(); the latter will do the removal.
	 * At this point we are sure no poll callbacks will be lingering around.
	 * Since we still own a reference to the eventpoll struct, the loop can't
	 * dispose it.
	 */
	for (rbp = rb_first_cached(&ep->rbr); rbp; rbp = next) {
		next = rb_next(rbp);
		epi = rb_entry(rbp, struct epitem, rbn);
		ep_remove_safe(ep, epi);
		cond_resched();
	}

	mutex_unlock(&ep->mtx);
	if (ep_refcount_dec_and_test(ep))
		ep_free(ep);
}

static long ep_eventpoll_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	int ret;

	if (!is_file_epoll(file))
		return -EINVAL;

	switch (cmd) {
	case EPIOCSPARAMS:
	case EPIOCGPARAMS:
		ret = ep_eventpoll_bp_ioctl(file, cmd, arg);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int ep_eventpoll_release(struct inode *inode, struct file *file)
{
	struct eventpoll *ep = file->private_data;

	if (ep)
		ep_clear_and_put(ep);

	return 0;
}

static __poll_t ep_item_poll(const struct epitem *epi, poll_table *pt, int depth);

static __poll_t __ep_eventpoll_poll(struct file *file, poll_table *wait, int depth)
{
	struct eventpoll *ep = file->private_data;
	LIST_HEAD(txlist);
	struct epitem *epi, *tmp;
	poll_table pt;
	__poll_t res = 0;

	init_poll_funcptr(&pt, NULL);

	/* Insert inside our poll wait queue */
	poll_wait(file, &ep->poll_wait, wait);

	/*
	 * Proceed to find out if wanted events are really available inside
	 * the ready list.
	 */
	mutex_lock_nested(&ep->mtx, depth);
	ep_start_scan(ep, &txlist);
	list_for_each_entry_safe(epi, tmp, &txlist, rdllink) {
		if (ep_item_poll(epi, &pt, depth + 1)) {
			res = EPOLLIN | EPOLLRDNORM;
			break;
		} else {
			/*
			 * Item has been dropped into the ready list by the poll
			 * callback, but it's not actually ready, as far as
			 * caller requested events goes. We can remove it here.
			 */
			__pm_relax(ep_wakeup_source(epi));
			list_del_init(&epi->rdllink);
		}
	}
	ep_done_scan(ep, &txlist);
	mutex_unlock(&ep->mtx);
	return res;
}

/*
 * The ffd.file pointer may be in the process of being torn down due to
 * being closed, but we may not have finished eventpoll_release() yet.
 *
 * Normally, even with the atomic_long_inc_not_zero, the file may have
 * been free'd and then gotten re-allocated to something else (since
 * files are not RCU-delayed, they are SLAB_TYPESAFE_BY_RCU).
 *
 * But for epoll, users hold the ep->mtx mutex, and as such any file in
 * the process of being free'd will block in eventpoll_release_file()
 * and thus the underlying file allocation will not be free'd, and the
 * file re-use cannot happen.
 *
 * For the same reason we can avoid a rcu_read_lock() around the
 * operation - 'ffd.file' cannot go away even if the refcount has
 * reached zero (but we must still not call out to ->poll() functions
 * etc).
 */
static struct file *epi_fget(const struct epitem *epi)
{
	struct file *file;

	file = epi->ffd.file;
	if (!file_ref_get(&file->f_ref))
		file = NULL;
	return file;
}

/*
 * Differs from ep_eventpoll_poll() in that internal callers already have
 * the ep->mtx so we need to start from depth=1, such that mutex_lock_nested()
 * is correctly annotated.
 */
static __poll_t ep_item_poll(const struct epitem *epi, poll_table *pt,
				 int depth)
{
	struct file *file = epi_fget(epi);
	__poll_t res;

	/*
	 * We could return EPOLLERR | EPOLLHUP or something, but let's
	 * treat this more as "file doesn't exist, poll didn't happen".
	 */
	if (!file)
		return 0;

	pt->_key = epi->event.events;
	if (!is_file_epoll(file))
		res = vfs_poll(file, pt);
	else
		res = __ep_eventpoll_poll(file, pt, depth);
	fput(file);
	return res & epi->event.events;
}

static __poll_t ep_eventpoll_poll(struct file *file, poll_table *wait)
{
	return __ep_eventpoll_poll(file, wait, 0);
}

#ifdef CONFIG_PROC_FS
static void ep_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct eventpoll *ep = f->private_data;
	struct rb_node *rbp;

	mutex_lock(&ep->mtx);
	for (rbp = rb_first_cached(&ep->rbr); rbp; rbp = rb_next(rbp)) {
		struct epitem *epi = rb_entry(rbp, struct epitem, rbn);
		struct inode *inode = file_inode(epi->ffd.file);

		seq_printf(m, "tfd: %8d events: %8x data: %16llx "
			   " pos:%lli ino:%lx sdev:%x\n",
			   epi->ffd.fd, epi->event.events,
			   (long long)epi->event.data,
			   (long long)epi->ffd.file->f_pos,
			   inode->i_ino, inode->i_sb->s_dev);
		if (seq_has_overflowed(m))
			break;
	}
	mutex_unlock(&ep->mtx);
}
#endif

/* File callbacks that implement the eventpoll file behaviour */
static const struct file_operations eventpoll_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= ep_show_fdinfo,
#endif
	.release	= ep_eventpoll_release,
	.poll		= ep_eventpoll_poll,
	.llseek		= noop_llseek,
	.unlocked_ioctl	= ep_eventpoll_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
};

/*
 * This is called from eventpoll_release() to unlink files from the eventpoll
 * interface. We need to have this facility to cleanup correctly files that are
 * closed without being removed from the eventpoll interface.
 */
void eventpoll_release_file(struct file *file)
{
	struct eventpoll *ep;
	struct epitem *epi;
	bool dispose;

	/*
	 * Use the 'dying' flag to prevent a concurrent ep_clear_and_put() from
	 * touching the epitems list before eventpoll_release_file() can access
	 * the ep->mtx.
	 */
again:
	spin_lock(&file->f_lock);
	if (file->f_ep && file->f_ep->first) {
		epi = hlist_entry(file->f_ep->first, struct epitem, fllink);
		epi->dying = true;
		spin_unlock(&file->f_lock);

		/*
		 * ep access is safe as we still own a reference to the ep
		 * struct
		 */
		ep = epi->ep;
		mutex_lock(&ep->mtx);
		dispose = __ep_remove(ep, epi, true);
		mutex_unlock(&ep->mtx);

		if (dispose && ep_refcount_dec_and_test(ep))
			ep_free(ep);
		goto again;
	}
	spin_unlock(&file->f_lock);
}

static int ep_alloc(struct eventpoll **pep)
{
	struct eventpoll *ep;

	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (unlikely(!ep))
		return -ENOMEM;

	mutex_init(&ep->mtx);
	spin_lock_init(&ep->lock);
	init_waitqueue_head(&ep->wq);
	init_waitqueue_head(&ep->poll_wait);
	INIT_LIST_HEAD(&ep->rdllist);
	ep->rbr = RB_ROOT_CACHED;
	ep->ovflist = EP_UNACTIVE_PTR;
	ep->user = get_current_user();
	refcount_set(&ep->refcount, 1);

	*pep = ep;

	return 0;
}

/*
 * Search the file inside the eventpoll tree. The RB tree operations
 * are protected by the "mtx" mutex, and ep_find() must be called with
 * "mtx" held.
 */
static struct epitem *ep_find(struct eventpoll *ep, struct file *file, int fd)
{
	int kcmp;
	struct rb_node *rbp;
	struct epitem *epi, *epir = NULL;
	struct epoll_filefd ffd;

	ep_set_ffd(&ffd, file, fd);
	for (rbp = ep->rbr.rb_root.rb_node; rbp; ) {
		epi = rb_entry(rbp, struct epitem, rbn);
		kcmp = ep_cmp_ffd(&ffd, &epi->ffd);
		if (kcmp > 0)
			rbp = rbp->rb_right;
		else if (kcmp < 0)
			rbp = rbp->rb_left;
		else {
			epir = epi;
			break;
		}
	}

	return epir;
}

#ifdef CONFIG_KCMP
static struct epitem *ep_find_tfd(struct eventpoll *ep, int tfd, unsigned long toff)
{
	struct rb_node *rbp;
	struct epitem *epi;

	for (rbp = rb_first_cached(&ep->rbr); rbp; rbp = rb_next(rbp)) {
		epi = rb_entry(rbp, struct epitem, rbn);
		if (epi->ffd.fd == tfd) {
			if (toff == 0)
				return epi;
			else
				toff--;
		}
		cond_resched();
	}

	return NULL;
}

struct file *get_epoll_tfile_raw_ptr(struct file *file, int tfd,
				     unsigned long toff)
{
	struct file *file_raw;
	struct eventpoll *ep;
	struct epitem *epi;

	if (!is_file_epoll(file))
		return ERR_PTR(-EINVAL);

	ep = file->private_data;

	mutex_lock(&ep->mtx);
	epi = ep_find_tfd(ep, tfd, toff);
	if (epi)
		file_raw = epi->ffd.file;
	else
		file_raw = ERR_PTR(-ENOENT);
	mutex_unlock(&ep->mtx);

	return file_raw;
}
#endif /* CONFIG_KCMP */

/*
 * This is the callback that is passed to the wait queue wakeup
 * mechanism. It is called by the stored file descriptors when they
 * have events to report.
 */
static int ep_poll_callback(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
	int pwake = 0;
	struct epitem *epi = ep_item_from_wait(wait);
	struct eventpoll *ep = epi->ep;
	__poll_t pollflags = key_to_poll(key);
	unsigned long flags;
	int ewake = 0;

	spin_lock_irqsave(&ep->lock, flags);

	ep_set_busy_poll_napi_id(epi);

	/*
	 * If the event mask does not contain any poll(2) event, we consider the
	 * descriptor to be disabled. This condition is likely the effect of the
	 * EPOLLONESHOT bit that disables the descriptor when an event is received,
	 * until the next EPOLL_CTL_MOD will be issued.
	 */
	if (!(epi->event.events & ~EP_PRIVATE_BITS))
		goto out_unlock;

	/*
	 * Check the events coming with the callback. At this stage, not
	 * every device reports the events in the "key" parameter of the
	 * callback. We need to be able to handle both cases here, hence the
	 * test for "key" != NULL before the event match test.
	 */
	if (pollflags && !(pollflags & epi->event.events))
		goto out_unlock;

	/*
	 * If we are transferring events to userspace, we can hold no locks
	 * (because we're accessing user memory, and because of linux f_op->poll()
	 * semantics). All the events that happen during that period of time are
	 * chained in ep->ovflist and requeued later on.
	 */
	if (READ_ONCE(ep->ovflist) != EP_UNACTIVE_PTR) {
		if (epi->next == EP_UNACTIVE_PTR) {
			epi->next = READ_ONCE(ep->ovflist);
			WRITE_ONCE(ep->ovflist, epi);
			ep_pm_stay_awake_rcu(epi);
		}
	} else if (!ep_is_linked(epi)) {
		/* In the usual case, add event to ready list. */
		list_add_tail(&epi->rdllink, &ep->rdllist);
		ep_pm_stay_awake_rcu(epi);
	}

	/*
	 * Wake up ( if active ) both the eventpoll wait list and the ->poll()
	 * wait list.
	 */
	if (waitqueue_active(&ep->wq)) {
		if ((epi->event.events & EPOLLEXCLUSIVE) &&
					!(pollflags & POLLFREE)) {
			switch (pollflags & EPOLLINOUT_BITS) {
			case EPOLLIN:
				if (epi->event.events & EPOLLIN)
					ewake = 1;
				break;
			case EPOLLOUT:
				if (epi->event.events & EPOLLOUT)
					ewake = 1;
				break;
			case 0:
				ewake = 1;
				break;
			}
		}
		if (sync)
			wake_up_sync(&ep->wq);
		else
			wake_up(&ep->wq);
	}
	if (waitqueue_active(&ep->poll_wait))
		pwake++;

out_unlock:
	spin_unlock_irqrestore(&ep->lock, flags);

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(ep, epi, pollflags & EPOLL_URING_WAKE);

	if (!(epi->event.events & EPOLLEXCLUSIVE))
		ewake = 1;

	if (pollflags & POLLFREE) {
		/*
		 * If we race with ep_remove_wait_queue() it can miss
		 * ->whead = NULL and do another remove_wait_queue() after
		 * us, so we can't use __remove_wait_queue().
		 */
		list_del_init(&wait->entry);
		/*
		 * ->whead != NULL protects us from the race with
		 * ep_clear_and_put() or ep_remove(), ep_remove_wait_queue()
		 * takes whead->lock held by the caller. Once we nullify it,
		 * nothing protects ep/epi or even wait.
		 */
		smp_store_release(&ep_pwq_from_wait(wait)->whead, NULL);
	}

	return ewake;
}

/*
 * This is the callback that is used to add our wait queue to the
 * target file wakeup lists.
 */
static void ep_ptable_queue_proc(struct file *file, wait_queue_head_t *whead,
				 poll_table *pt)
{
	struct ep_pqueue *epq = container_of(pt, struct ep_pqueue, pt);
	struct epitem *epi = epq->epi;
	struct eppoll_entry *pwq;

	if (unlikely(!epi))	// an earlier allocation has failed
		return;

	pwq = kmem_cache_alloc(pwq_cache, GFP_KERNEL);
	if (unlikely(!pwq)) {
		epq->epi = NULL;
		return;
	}

	init_waitqueue_func_entry(&pwq->wait, ep_poll_callback);
	pwq->whead = whead;
	pwq->base = epi;
	if (epi->event.events & EPOLLEXCLUSIVE)
		add_wait_queue_exclusive(whead, &pwq->wait);
	else
		add_wait_queue(whead, &pwq->wait);
	pwq->next = epi->pwqlist;
	epi->pwqlist = pwq;
}

static void ep_rbtree_insert(struct eventpoll *ep, struct epitem *epi)
{
	int kcmp;
	struct rb_node **p = &ep->rbr.rb_root.rb_node, *parent = NULL;
	struct epitem *epic;
	bool leftmost = true;

	while (*p) {
		parent = *p;
		epic = rb_entry(parent, struct epitem, rbn);
		kcmp = ep_cmp_ffd(&epi->ffd, &epic->ffd);
		if (kcmp > 0) {
			p = &parent->rb_right;
			leftmost = false;
		} else
			p = &parent->rb_left;
	}
	rb_link_node(&epi->rbn, parent, p);
	rb_insert_color_cached(&epi->rbn, &ep->rbr, leftmost);
}



#define PATH_ARR_SIZE 5
/*
 * These are the number paths of length 1 to 5, that we are allowing to emanate
 * from a single file of interest. For example, we allow 1000 paths of length
 * 1, to emanate from each file of interest. This essentially represents the
 * potential wakeup paths, which need to be limited in order to avoid massive
 * uncontrolled wakeup storms. The common use case should be a single ep which
 * is connected to n file sources. In this case each file source has 1 path
 * of length 1. Thus, the numbers below should be more than sufficient. These
 * path limits are enforced during an EPOLL_CTL_ADD operation, since a modify
 * and delete can't add additional paths. Protected by the epnested_mutex.
 */
static const int path_limits[PATH_ARR_SIZE] = { 1000, 500, 100, 50, 10 };
static int path_count[PATH_ARR_SIZE];

static int path_count_inc(int nests)
{
	/* Allow an arbitrary number of depth 1 paths */
	if (nests == 0)
		return 0;

	if (++path_count[nests] > path_limits[nests])
		return -1;
	return 0;
}

static void path_count_init(void)
{
	int i;

	for (i = 0; i < PATH_ARR_SIZE; i++)
		path_count[i] = 0;
}

static int reverse_path_check_proc(struct hlist_head *refs, int depth)
{
	int error = 0;
	struct epitem *epi;

	if (depth > EP_MAX_NESTS) /* too deep nesting */
		return -1;

	/* CTL_DEL can remove links here, but that can't increase our count */
	hlist_for_each_entry_rcu(epi, refs, fllink) {
		struct hlist_head *refs = &epi->ep->refs;
		if (hlist_empty(refs))
			error = path_count_inc(depth);
		else
			error = reverse_path_check_proc(refs, depth + 1);
		if (error != 0)
			break;
	}
	return error;
}

/**
 * reverse_path_check - The tfile_check_list is list of epitem_head, which have
 *                      links that are proposed to be newly added. We need to
 *                      make sure that those added links don't add too many
 *                      paths such that we will spend all our time waking up
 *                      eventpoll objects.
 *
 * Return: %zero if the proposed links don't create too many paths,
 *	    %-1 otherwise.
 */
static int reverse_path_check(void)
{
	struct epitems_head *p;

	for (p = tfile_check_list; p != EP_UNACTIVE_PTR; p = p->next) {
		int error;
		path_count_init();
		rcu_read_lock();
		error = reverse_path_check_proc(&p->epitems, 0);
		rcu_read_unlock();
		if (error)
			return error;
	}
	return 0;
}

static int ep_create_wakeup_source(struct epitem *epi)
{
	struct name_snapshot n;
	struct wakeup_source *ws;

	if (!epi->ep->ws) {
		epi->ep->ws = wakeup_source_register(NULL, "eventpoll");
		if (!epi->ep->ws)
			return -ENOMEM;
	}

	take_dentry_name_snapshot(&n, epi->ffd.file->f_path.dentry);
	ws = wakeup_source_register(NULL, n.name.name);
	release_dentry_name_snapshot(&n);

	if (!ws)
		return -ENOMEM;
	rcu_assign_pointer(epi->ws, ws);

	return 0;
}

/* rare code path, only used when EPOLL_CTL_MOD removes a wakeup source */
static noinline void ep_destroy_wakeup_source(struct epitem *epi)
{
	struct wakeup_source *ws = ep_wakeup_source(epi);

	RCU_INIT_POINTER(epi->ws, NULL);

	/*
	 * wait for ep_pm_stay_awake_rcu to finish, synchronize_rcu is
	 * used internally by wakeup_source_remove, too (called by
	 * wakeup_source_unregister), so we cannot use call_rcu
	 */
	synchronize_rcu();
	wakeup_source_unregister(ws);
}

static int attach_epitem(struct file *file, struct epitem *epi)
{
	struct epitems_head *to_free = NULL;
	struct hlist_head *head = NULL;
	struct eventpoll *ep = NULL;

	if (is_file_epoll(file))
		ep = file->private_data;

	if (ep) {
		head = &ep->refs;
	} else if (!READ_ONCE(file->f_ep)) {
allocate:
		to_free = kmem_cache_zalloc(ephead_cache, GFP_KERNEL);
		if (!to_free)
			return -ENOMEM;
		head = &to_free->epitems;
	}
	spin_lock(&file->f_lock);
	if (!file->f_ep) {
		if (unlikely(!head)) {
			spin_unlock(&file->f_lock);
			goto allocate;
		}
		/* See eventpoll_release() for details. */
		WRITE_ONCE(file->f_ep, head);
		to_free = NULL;
	}
	hlist_add_head_rcu(&epi->fllink, file->f_ep);
	spin_unlock(&file->f_lock);
	free_ephead(to_free);
	return 0;
}

/*
 * Must be called with "mtx" held.
 */
static int ep_insert(struct eventpoll *ep, const struct epoll_event *event,
		     struct file *tfile, int fd, int full_check)
{
	int error, pwake = 0;
	__poll_t revents;
	struct epitem *epi;
	struct ep_pqueue epq;
	struct eventpoll *tep = NULL;

	if (is_file_epoll(tfile))
		tep = tfile->private_data;

	lockdep_assert_irqs_enabled();

	if (unlikely(percpu_counter_compare(&ep->user->epoll_watches,
					    max_user_watches) >= 0))
		return -ENOSPC;
	percpu_counter_inc(&ep->user->epoll_watches);

	if (!(epi = kmem_cache_zalloc(epi_cache, GFP_KERNEL))) {
		percpu_counter_dec(&ep->user->epoll_watches);
		return -ENOMEM;
	}

	/* Item initialization follow here ... */
	INIT_LIST_HEAD(&epi->rdllink);
	epi->ep = ep;
	ep_set_ffd(&epi->ffd, tfile, fd);
	epi->event = *event;
	epi->next = EP_UNACTIVE_PTR;

	if (tep)
		mutex_lock_nested(&tep->mtx, 1);
	/* Add the current item to the list of active epoll hook for this file */
	if (unlikely(attach_epitem(tfile, epi) < 0)) {
		if (tep)
			mutex_unlock(&tep->mtx);
		kmem_cache_free(epi_cache, epi);
		percpu_counter_dec(&ep->user->epoll_watches);
		return -ENOMEM;
	}

	if (full_check && !tep)
		list_file(tfile);

	/*
	 * Add the current item to the RB tree. All RB tree operations are
	 * protected by "mtx", and ep_insert() is called with "mtx" held.
	 */
	ep_rbtree_insert(ep, epi);
	if (tep)
		mutex_unlock(&tep->mtx);

	/*
	 * ep_remove_safe() calls in the later error paths can't lead to
	 * ep_free() as the ep file itself still holds an ep reference.
	 */
	ep_get(ep);

	/* now check if we've created too many backpaths */
	if (unlikely(full_check && reverse_path_check())) {
		ep_remove_safe(ep, epi);
		return -EINVAL;
	}

	if (epi->event.events & EPOLLWAKEUP) {
		error = ep_create_wakeup_source(epi);
		if (error) {
			ep_remove_safe(ep, epi);
			return error;
		}
	}

	/* Initialize the poll table using the queue callback */
	epq.epi = epi;
	init_poll_funcptr(&epq.pt, ep_ptable_queue_proc);

	/*
	 * Attach the item to the poll hooks and get current event bits.
	 * We can safely use the file* here because its usage count has
	 * been increased by the caller of this function. Note that after
	 * this operation completes, the poll callback can start hitting
	 * the new item.
	 */
	revents = ep_item_poll(epi, &epq.pt, 1);

	/*
	 * We have to check if something went wrong during the poll wait queue
	 * install process. Namely an allocation for a wait queue failed due
	 * high memory pressure.
	 */
	if (unlikely(!epq.epi)) {
		ep_remove_safe(ep, epi);
		return -ENOMEM;
	}

	/* We have to drop the new item inside our item list to keep track of it */
	spin_lock_irq(&ep->lock);

	/* record NAPI ID of new item if present */
	ep_set_busy_poll_napi_id(epi);

	/* If the file is already "ready" we drop it inside the ready list */
	if (revents && !ep_is_linked(epi)) {
		list_add_tail(&epi->rdllink, &ep->rdllist);
		ep_pm_stay_awake(epi);

		/* Notify waiting tasks that events are available */
		if (waitqueue_active(&ep->wq))
			wake_up(&ep->wq);
		if (waitqueue_active(&ep->poll_wait))
			pwake++;
	}

	spin_unlock_irq(&ep->lock);

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(ep, NULL, 0);

	return 0;
}

/*
 * Modify the interest event mask by dropping an event if the new mask
 * has a match in the current file status. Must be called with "mtx" held.
 */
static int ep_modify(struct eventpoll *ep, struct epitem *epi,
		     const struct epoll_event *event)
{
	int pwake = 0;
	poll_table pt;

	lockdep_assert_irqs_enabled();

	init_poll_funcptr(&pt, NULL);

	/*
	 * Set the new event interest mask before calling f_op->poll();
	 * otherwise we might miss an event that happens between the
	 * f_op->poll() call and the new event set registering.
	 */
	epi->event.events = event->events; /* need barrier below */
	epi->event.data = event->data; /* protected by mtx */
	if (epi->event.events & EPOLLWAKEUP) {
		if (!ep_has_wakeup_source(epi))
			ep_create_wakeup_source(epi);
	} else if (ep_has_wakeup_source(epi)) {
		ep_destroy_wakeup_source(epi);
	}

	/*
	 * The following barrier has two effects:
	 *
	 * 1) Flush epi changes above to other CPUs.  This ensures
	 *    we do not miss events from ep_poll_callback if an
	 *    event occurs immediately after we call f_op->poll().
	 *    We need this because we did not take ep->lock while
	 *    changing epi above (but ep_poll_callback does take
	 *    ep->lock).
	 *
	 * 2) We also need to ensure we do not miss _past_ events
	 *    when calling f_op->poll().  This barrier also
	 *    pairs with the barrier in wq_has_sleeper (see
	 *    comments for wq_has_sleeper).
	 *
	 * This barrier will now guarantee ep_poll_callback or f_op->poll
	 * (or both) will notice the readiness of an item.
	 */
	smp_mb();

	/*
	 * Get current event bits. We can safely use the file* here because
	 * its usage count has been increased by the caller of this function.
	 * If the item is "hot" and it is not registered inside the ready
	 * list, push it inside.
	 */
	if (ep_item_poll(epi, &pt, 1)) {
		spin_lock_irq(&ep->lock);
		if (!ep_is_linked(epi)) {
			list_add_tail(&epi->rdllink, &ep->rdllist);
			ep_pm_stay_awake(epi);

			/* Notify waiting tasks that events are available */
			if (waitqueue_active(&ep->wq))
				wake_up(&ep->wq);
			if (waitqueue_active(&ep->poll_wait))
				pwake++;
		}
		spin_unlock_irq(&ep->lock);
	}

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(ep, NULL, 0);

	return 0;
}

static int ep_send_events(struct eventpoll *ep,
			  struct epoll_event __user *events, int maxevents)
{
	struct epitem *epi, *tmp;
	LIST_HEAD(txlist);
	poll_table pt;
	int res = 0;

	/*
	 * Always short-circuit for fatal signals to allow threads to make a
	 * timely exit without the chance of finding more events available and
	 * fetching repeatedly.
	 */
	if (fatal_signal_pending(current))
		return -EINTR;

	init_poll_funcptr(&pt, NULL);

	mutex_lock(&ep->mtx);
	ep_start_scan(ep, &txlist);

	/*
	 * We can loop without lock because we are passed a task private list.
	 * Items cannot vanish during the loop we are holding ep->mtx.
	 */
	list_for_each_entry_safe(epi, tmp, &txlist, rdllink) {
		struct wakeup_source *ws;
		__poll_t revents;

		if (res >= maxevents)
			break;

		/*
		 * Activate ep->ws before deactivating epi->ws to prevent
		 * triggering auto-suspend here (in case we reactive epi->ws
		 * below).
		 *
		 * This could be rearranged to delay the deactivation of epi->ws
		 * instead, but then epi->ws would temporarily be out of sync
		 * with ep_is_linked().
		 */
		ws = ep_wakeup_source(epi);
		if (ws) {
			if (ws->active)
				__pm_stay_awake(ep->ws);
			__pm_relax(ws);
		}

		list_del_init(&epi->rdllink);

		/*
		 * If the event mask intersect the caller-requested one,
		 * deliver the event to userspace. Again, we are holding ep->mtx,
		 * so no operations coming from userspace can change the item.
		 */
		revents = ep_item_poll(epi, &pt, 1);
		if (!revents)
			continue;

		events = epoll_put_uevent(revents, epi->event.data, events);
		if (!events) {
			list_add(&epi->rdllink, &txlist);
			ep_pm_stay_awake(epi);
			if (!res)
				res = -EFAULT;
			break;
		}
		res++;
		if (epi->event.events & EPOLLONESHOT)
			epi->event.events &= EP_PRIVATE_BITS;
		else if (!(epi->event.events & EPOLLET)) {
			/*
			 * If this file has been added with Level
			 * Trigger mode, we need to insert back inside
			 * the ready list, so that the next call to
			 * epoll_wait() will check again the events
			 * availability. At this point, no one can insert
			 * into ep->rdllist besides us. The epoll_ctl()
			 * callers are locked out by
			 * ep_send_events() holding "mtx" and the
			 * poll callback will queue them in ep->ovflist.
			 */
			list_add_tail(&epi->rdllink, &ep->rdllist);
			ep_pm_stay_awake(epi);
		}
	}
	ep_done_scan(ep, &txlist);
	mutex_unlock(&ep->mtx);

	return res;
}

static struct timespec64 *ep_timeout_to_timespec(struct timespec64 *to, long ms)
{
	struct timespec64 now;

	if (ms < 0)
		return NULL;

	if (!ms) {
		to->tv_sec = 0;
		to->tv_nsec = 0;
		return to;
	}

	to->tv_sec = ms / MSEC_PER_SEC;
	to->tv_nsec = NSEC_PER_MSEC * (ms % MSEC_PER_SEC);

	ktime_get_ts64(&now);
	*to = timespec64_add_safe(now, *to);
	return to;
}

/*
 * autoremove_wake_function, but remove even on failure to wake up, because we
 * know that default_wake_function/ttwu will only fail if the thread is already
 * woken, and in that case the ep_poll loop will remove the entry anyways, not
 * try to reuse it.
 */
static int ep_autoremove_wake_function(struct wait_queue_entry *wq_entry,
				       unsigned int mode, int sync, void *key)
{
	int ret = default_wake_function(wq_entry, mode, sync, key);

	/*
	 * Pairs with list_empty_careful in ep_poll, and ensures future loop
	 * iterations see the cause of this wakeup.
	 */
	list_del_init_careful(&wq_entry->entry);
	return ret;
}

static int ep_try_send_events(struct eventpoll *ep,
			      struct epoll_event __user *events, int maxevents)
{
	int res;

	/*
	 * Try to transfer events to user space. In case we get 0 events and
	 * there's still timeout left over, we go trying again in search of
	 * more luck.
	 */
	res = ep_send_events(ep, events, maxevents);
	if (res > 0)
		ep_suspend_napi_irqs(ep);
	return res;
}

static int ep_schedule_timeout(ktime_t *to)
{
	if (to)
		return ktime_after(*to, ktime_get());
	else
		return 1;
}

/**
 * ep_poll - Retrieves ready events, and delivers them to the caller-supplied
 *           event buffer.
 *
 * @ep: Pointer to the eventpoll context.
 * @events: Pointer to the userspace buffer where the ready events should be
 *          stored.
 * @maxevents: Size (in terms of number of events) of the caller event buffer.
 * @timeout: Maximum timeout for the ready events fetch operation, in
 *           timespec. If the timeout is zero, the function will not block,
 *           while if the @timeout ptr is NULL, the function will block
 *           until at least one event has been retrieved (or an error
 *           occurred).
 *
 * Return: the number of ready events which have been fetched, or an
 *          error code, in case of error.
 */
static int ep_poll(struct eventpoll *ep, struct epoll_event __user *events,
		   int maxevents, struct timespec64 *timeout)
{
	int res, eavail, timed_out = 0;
	u64 slack = 0;
	wait_queue_entry_t wait;
	ktime_t expires, *to = NULL;

	lockdep_assert_irqs_enabled();

	if (timeout && (timeout->tv_sec | timeout->tv_nsec)) {
		slack = select_estimate_accuracy(timeout);
		to = &expires;
		*to = timespec64_to_ktime(*timeout);
	} else if (timeout) {
		/*
		 * Avoid the unnecessary trip to the wait queue loop, if the
		 * caller specified a non blocking operation.
		 */
		timed_out = 1;
	}

	/*
	 * This call is racy: We may or may not see events that are being added
	 * to the ready list under the lock (e.g., in IRQ callbacks). For cases
	 * with a non-zero timeout, this thread will check the ready list under
	 * lock and will add to the wait queue.  For cases with a zero
	 * timeout, the user by definition should not care and will have to
	 * recheck again.
	 */
	eavail = ep_events_available(ep);

	while (1) {
		if (eavail) {
			res = ep_try_send_events(ep, events, maxevents);
			if (res)
				return res;
		}

		if (timed_out)
			return 0;

		eavail = ep_busy_loop(ep);
		if (eavail)
			continue;

		if (signal_pending(current))
			return -EINTR;

		/*
		 * Internally init_wait() uses autoremove_wake_function(),
		 * thus wait entry is removed from the wait queue on each
		 * wakeup. Why it is important? In case of several waiters
		 * each new wakeup will hit the next waiter, giving it the
		 * chance to harvest new event. Otherwise wakeup can be
		 * lost. This is also good performance-wise, because on
		 * normal wakeup path no need to call __remove_wait_queue()
		 * explicitly, thus ep->lock is not taken, which halts the
		 * event delivery.
		 *
		 * In fact, we now use an even more aggressive function that
		 * unconditionally removes, because we don't reuse the wait
		 * entry between loop iterations. This lets us also avoid the
		 * performance issue if a process is killed, causing all of its
		 * threads to wake up without being removed normally.
		 */
		init_wait(&wait);
		wait.func = ep_autoremove_wake_function;

		spin_lock_irq(&ep->lock);
		/*
		 * Barrierless variant, waitqueue_active() is called under
		 * the same lock on wakeup ep_poll_callback() side, so it
		 * is safe to avoid an explicit barrier.
		 */
		__set_current_state(TASK_INTERRUPTIBLE);

		/*
		 * Do the final check under the lock. ep_start/done_scan()
		 * plays with two lists (->rdllist and ->ovflist) and there
		 * is always a race when both lists are empty for short
		 * period of time although events are pending, so lock is
		 * important.
		 */
		eavail = ep_events_available(ep);
		if (!eavail)
			__add_wait_queue_exclusive(&ep->wq, &wait);

		spin_unlock_irq(&ep->lock);

		if (!eavail)
			timed_out = !ep_schedule_timeout(to) ||
				!schedule_hrtimeout_range(to, slack,
							  HRTIMER_MODE_ABS);
		__set_current_state(TASK_RUNNING);

		/*
		 * We were woken up, thus go and try to harvest some events.
		 * If timed out and still on the wait queue, recheck eavail
		 * carefully under lock, below.
		 */
		eavail = 1;

		if (!list_empty_careful(&wait.entry)) {
			spin_lock_irq(&ep->lock);
			/*
			 * If the thread timed out and is not on the wait queue,
			 * it means that the thread was woken up after its
			 * timeout expired before it could reacquire the lock.
			 * Thus, when wait.entry is empty, it needs to harvest
			 * events.
			 */
			if (timed_out)
				eavail = list_empty(&wait.entry);
			__remove_wait_queue(&ep->wq, &wait);
			spin_unlock_irq(&ep->lock);
		}
	}
}

/**
 * ep_loop_check_proc - verify that adding an epoll file @ep inside another
 *                      epoll file does not create closed loops, and
 *                      determine the depth of the subtree starting at @ep
 *
 * @ep: the &struct eventpoll to be currently checked.
 * @depth: Current depth of the path being checked.
 *
 * Return: depth of the subtree, or INT_MAX if we found a loop or went too deep.
 */
static int ep_loop_check_proc(struct eventpoll *ep, int depth)
{
	int result = 0;
	struct rb_node *rbp;
	struct epitem *epi;

	if (ep->gen == loop_check_gen)
		return ep->loop_check_depth;

	mutex_lock_nested(&ep->mtx, depth + 1);
	ep->gen = loop_check_gen;
	for (rbp = rb_first_cached(&ep->rbr); rbp; rbp = rb_next(rbp)) {
		epi = rb_entry(rbp, struct epitem, rbn);
		if (unlikely(is_file_epoll(epi->ffd.file))) {
			struct eventpoll *ep_tovisit;
			ep_tovisit = epi->ffd.file->private_data;
			if (ep_tovisit == inserting_into || depth > EP_MAX_NESTS)
				result = INT_MAX;
			else
				result = max(result, ep_loop_check_proc(ep_tovisit, depth + 1) + 1);
			if (result > EP_MAX_NESTS)
				break;
		} else {
			/*
			 * If we've reached a file that is not associated with
			 * an ep, then we need to check if the newly added
			 * links are going to add too many wakeup paths. We do
			 * this by adding it to the tfile_check_list, if it's
			 * not already there, and calling reverse_path_check()
			 * during ep_insert().
			 */
			list_file(epi->ffd.file);
		}
	}
	ep->loop_check_depth = result;
	mutex_unlock(&ep->mtx);

	return result;
}

/* ep_get_upwards_depth_proc - determine depth of @ep when traversed upwards */
static int ep_get_upwards_depth_proc(struct eventpoll *ep, int depth)
{
	int result = 0;
	struct epitem *epi;

	if (ep->gen == loop_check_gen)
		return ep->loop_check_depth;
	hlist_for_each_entry_rcu(epi, &ep->refs, fllink)
		result = max(result, ep_get_upwards_depth_proc(epi->ep, depth + 1) + 1);
	ep->gen = loop_check_gen;
	ep->loop_check_depth = result;
	return result;
}

/**
 * ep_loop_check - Performs a check to verify that adding an epoll file (@to)
 *                 into another epoll file (represented by @ep) does not create
 *                 closed loops or too deep chains.
 *
 * @ep: Pointer to the epoll we are inserting into.
 * @to: Pointer to the epoll to be inserted.
 *
 * Return: %zero if adding the epoll @to inside the epoll @from
 * does not violate the constraints, or %-1 otherwise.
 */
static int ep_loop_check(struct eventpoll *ep, struct eventpoll *to)
{
	int depth, upwards_depth;

	inserting_into = ep;
	/*
	 * Check how deep down we can get from @to, and whether it is possible
	 * to loop up to @ep.
	 */
	depth = ep_loop_check_proc(to, 0);
	if (depth > EP_MAX_NESTS)
		return -1;
	/* Check how far up we can go from @ep. */
	rcu_read_lock();
	upwards_depth = ep_get_upwards_depth_proc(ep, 0);
	rcu_read_unlock();

	return (depth+1+upwards_depth > EP_MAX_NESTS) ? -1 : 0;
}

static void clear_tfile_check_list(void)
{
	rcu_read_lock();
	while (tfile_check_list != EP_UNACTIVE_PTR) {
		struct epitems_head *head = tfile_check_list;
		tfile_check_list = head->next;
		unlist_file(head);
	}
	rcu_read_unlock();
}

/*
 * Open an eventpoll file descriptor.
 */
static int do_epoll_create(int flags)
{
	int error;
	struct eventpoll *ep;

	/* Check the EPOLL_* constant for consistency.  */
	BUILD_BUG_ON(EPOLL_CLOEXEC != O_CLOEXEC);

	if (flags & ~EPOLL_CLOEXEC)
		return -EINVAL;
	/*
	 * Create the internal data structure ("struct eventpoll").
	 */
	error = ep_alloc(&ep);
	if (error < 0)
		return error;
	/*
	 * Creates all the items needed to setup an eventpoll file. That is,
	 * a file structure and a free file descriptor.
	 */
	FD_PREPARE(fdf, O_RDWR | (flags & O_CLOEXEC),
		   anon_inode_getfile("[eventpoll]", &eventpoll_fops, ep,
				      O_RDWR | (flags & O_CLOEXEC)));
	if (fdf.err) {
		ep_clear_and_put(ep);
		return fdf.err;
	}
	ep->file = fd_prepare_file(fdf);
	return fd_publish(fdf);
}

/**
 * sys_epoll_create1 - Create an epoll file descriptor
 * @flags: Bitmask of flags controlling the epoll instance behavior
 *
 * long-desc: Creates an epoll instance and returns a file descriptor referring
 *   to it. The epoll instance provides a scalable I/O event notification
 *   mechanism that is more efficient than poll(2) or select(2) for monitoring
 *   large numbers of file descriptors.
 *
 *   The epoll interface consists of three syscalls: epoll_create1() (or the
 *   deprecated epoll_create()) to create an epoll instance, epoll_ctl() to
 *   add, modify, or remove file descriptors from the interest list, and
 *   epoll_wait() or epoll_pwait() to wait for I/O events on the registered
 *   file descriptors.
 *
 *   When the epoll instance is no longer needed, the file descriptor should
 *   be closed using close(2). When all file descriptors referring to an epoll
 *   instance have been closed, the kernel destroys the instance and releases
 *   the associated resources.
 *
 *   The epoll instance maintains two lists internally:
 *   - Interest list: A red-black tree of file descriptors being monitored,
 *     added via epoll_ctl(EPOLL_CTL_ADD).
 *   - Ready list: A linked list of file descriptors that are ready for I/O,
 *     returned to userspace via epoll_wait().
 *
 *   The returned file descriptor itself supports poll/select/epoll, allowing
 *   epoll instances to be nested (one epoll fd monitored by another). However,
 *   the kernel limits nesting depth to prevent stack overflow and deadlock.
 *
 *   epoll_create1() supersedes epoll_create(), which required an ignored size
 *   argument and did not support flags. New applications should use
 *   epoll_create1() exclusively.
 *
 *   The epoll file descriptor can be inherited across fork(2) (unless
 *   EPOLL_CLOEXEC is set), but the child process shares the same epoll
 *   instance with the parent. This is typically not useful since both
 *   processes would compete for events.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: flags
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: EPOLL_CLOEXEC
 *   constraint: Bitmask of zero or EPOLL_CLOEXEC. EPOLL_CLOEXEC sets the
 *     close-on-exec (FD_CLOEXEC) flag on the new file descriptor, ensuring
 *     it is automatically closed when execve(2) is called. This prevents
 *     file descriptor leaks to child processes. EPOLL_CLOEXEC is defined
 *     as O_CLOEXEC (0x80000). Passing 0 creates an epoll fd without the
 *     close-on-exec flag. Any bits other than EPOLL_CLOEXEC cause EINVAL.
 *
 * return:
 *   type: KAPI_TYPE_FD
 *   check-type: KAPI_RETURN_FD
 *   success: >= 0
 *   desc: On success, returns a new file descriptor referring to the epoll
 *     instance. The file descriptor will be the lowest-numbered available fd
 *     in the process's file descriptor table. The fd should be closed with
 *     close(2) when no longer needed. The returned fd can be used with
 *     epoll_ctl() to add/modify/remove monitored file descriptors and with
 *     epoll_wait() to wait for events.
 *
 * error: EINVAL, Invalid flags
 *   desc: The @flags argument contains bits other than EPOLL_CLOEXEC. The
 *     kernel validates flags before any resource allocation using the check
 *     (flags & ~EPOLL_CLOEXEC). This error is returned immediately, before
 *     any memory is allocated. This validation prevents undefined behavior
 *     from unknown flag bits that might have different meanings in future
 *     kernel versions.
 *
 * error: EMFILE, Per-process fd limit exceeded
 *   desc: The per-process limit on the number of open file descriptors has
 *     been reached. This limit is controlled by RLIMIT_NOFILE (default soft
 *     limit typically 1024) and can be viewed with getrlimit(RLIMIT_NOFILE)
 *     or "ulimit -n". The limit can be increased using setrlimit() or
 *     "ulimit -n <value>" up to the hard limit. The kernel checks this in
 *     get_unused_fd_flags() -> alloc_fd(). Additionally, EMFILE is returned
 *     if the fd number would exceed sysctl_nr_open (/proc/sys/fs/nr_open).
 *
 * error: ENFILE, System-wide fd limit exceeded
 *   desc: The system-wide limit on the total number of open files has been
 *     reached. This limit is controlled by /proc/sys/fs/file-max and affects
 *     all processes. Processes with CAP_SYS_ADMIN capability can exceed this
 *     limit. This error is returned from alloc_empty_file() when the global
 *     nr_files counter reaches files_stat.max_files.
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory was available. Can occur when allocating:
 *     (1) struct eventpoll via kzalloc in ep_alloc(), (2) struct file via
 *     alloc_empty_file(), (3) dentry via d_alloc_pseudo(), or (4) expanding
 *     the fd table via alloc_fdtable(). All use GFP_KERNEL allowing sleeping.
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: eventpoll structure, struct file, dentry
 *   desc: Allocates a struct eventpoll containing the internal epoll state
 *     including a mutex (ep->mtx) for synchronization, a spinlock (ep->lock)
 *     for IRQ-safe operations, wait queues for poll and epoll_wait, a
 *     red-black tree root for the interest list, and various other fields.
 *     Also allocates a struct file and associated dentry for the anonymous
 *     inode. Additionally allocates a user_struct reference via
 *     get_current_user(). All memory is freed when the last reference to
 *     the file descriptor is released.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: File descriptor
 *   desc: Allocates a new file descriptor in the calling process's file
 *     descriptor table. The fd number is chosen as the lowest available value
 *     starting from 0. If the fd table needs expansion, additional memory is
 *     allocated. The file descriptor remains valid until explicitly closed
 *     with close(2) or the process exits.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: Anonymous inode file
 *   desc: Creates an anonymous inode file with the name "[eventpoll]" visible
 *     in /proc/[pid]/fd/ and /proc/[pid]/fdinfo/. The file is created via
 *     anon_inode_getfile() and shares a common anonymous inode with other
 *     epoll instances to save memory. The file supports poll operations,
 *     allowing the epoll fd to be monitored by another epoll instance or
 *     by poll()/select().
 *   reversible: yes
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Exceeding the system-wide file-max limit
 *   without: Returns ENFILE if system-wide file limit (/proc/sys/fs/file-max)
 *     is reached
 *   condition: Checked in alloc_empty_file() when nr_files >= files_stat.max_files
 *
 * constraint: File Descriptor Limits
 *   desc: The calling process must not have exhausted its per-process file
 *     descriptor limit (RLIMIT_NOFILE). The system must not have exhausted
 *     its system-wide file limit (/proc/sys/fs/file-max) unless the caller
 *     has CAP_SYS_ADMIN capability. Additionally, the per-process fd number
 *     cannot exceed /proc/sys/fs/nr_open (default 1048576).
 *
 * constraint: Memory Availability
 *   desc: Sufficient kernel memory must be available for allocation of the
 *     eventpoll structure and associated file structures. Allocations use
 *     GFP_KERNEL which allows the kernel to reclaim memory and sleep if
 *     necessary, but may still fail under extreme memory pressure.
 *
 * examples: epfd = epoll_create1(0);  // Basic epoll without close-on-exec
 *   epfd = epoll_create1(EPOLL_CLOEXEC);  // With close-on-exec flag
 *   if (epfd < 0) { perror("epoll_create1"); exit(1); }  // Error handling
 *
 * notes: epoll_create1() was introduced in Linux 2.6.27 to replace the older
 *   epoll_create() syscall. The original epoll_create() required a "size"
 *   hint argument that was ignored since Linux 2.6.8, making it vestigial.
 *   epoll_create1() eliminates this unused argument and adds flags support.
 *
 *   The EPOLL_CLOEXEC flag is equivalent to O_CLOEXEC and follows the same
 *   pattern as other *_CLOEXEC flags (e.g., SOCK_CLOEXEC, TFD_CLOEXEC) added
 *   in the 2.6.27 kernel to support atomic close-on-exec semantics. Using
 *   EPOLL_CLOEXEC is strongly recommended for security, as it prevents
 *   accidental file descriptor inheritance to exec'd programs.
 *
 *   The epoll instance internally uses a red-black tree for O(log n) lookup
 *   of monitored file descriptors and maintains a ready list for O(1) access
 *   to events. This makes epoll particularly efficient for applications
 *   monitoring thousands of connections where only a small subset are active.
 *
 *   The maximum number of file descriptors that can be registered with a
 *   single epoll instance is limited only by available memory and the
 *   per-user watch limit (/proc/sys/fs/epoll/max_user_watches). This limit
 *   is calculated based on available low memory (1/25 of lowmem divided by
 *   the cost per watch, approximately 160 bytes on 64-bit systems).
 *
 *   The file descriptor returned by epoll_create1() can itself be monitored
 *   using poll(), select(), or another epoll instance. It reports POLLIN
 *   when there are events pending. This allows integration with external
 *   event loops or nesting of epoll instances, though nesting depth is
 *   limited to EP_MAX_NESTS (4) to prevent stack overflow.
 *
 *   Historical note: A use-after-free bug in epoll_create1() was fixed in
 *   commit 98022748f6c7b (2012) where the ep->file assignment could race
 *   with another thread closing the fd. The current implementation uses
 *   FD_PREPARE() pattern to safely handle this race.
 *
 * since-version: 2.6.27
 */
SYSCALL_DEFINE1(epoll_create1, int, flags)
{
	return do_epoll_create(flags);
}

SYSCALL_DEFINE1(epoll_create, int, size)
{
	if (size <= 0)
		return -EINVAL;

	return do_epoll_create(0);
}

#ifdef CONFIG_PM_SLEEP
static inline void ep_take_care_of_epollwakeup(struct epoll_event *epev)
{
	if ((epev->events & EPOLLWAKEUP) && !capable(CAP_BLOCK_SUSPEND))
		epev->events &= ~EPOLLWAKEUP;
}
#else
static inline void ep_take_care_of_epollwakeup(struct epoll_event *epev)
{
	epev->events &= ~EPOLLWAKEUP;
}
#endif

static inline int epoll_mutex_lock(struct mutex *mutex, int depth,
				   bool nonblock)
{
	if (!nonblock) {
		mutex_lock_nested(mutex, depth);
		return 0;
	}
	if (mutex_trylock(mutex))
		return 0;
	return -EAGAIN;
}

int do_epoll_ctl(int epfd, int op, int fd, struct epoll_event *epds,
		 bool nonblock)
{
	int error;
	int full_check = 0;
	struct eventpoll *ep;
	struct epitem *epi;
	struct eventpoll *tep = NULL;

	CLASS(fd, f)(epfd);
	if (fd_empty(f))
		return -EBADF;

	/* Get the "struct file *" for the target file */
	CLASS(fd, tf)(fd);
	if (fd_empty(tf))
		return -EBADF;

	/* The target file descriptor must support poll */
	if (!file_can_poll(fd_file(tf)))
		return -EPERM;

	/* Check if EPOLLWAKEUP is allowed */
	if (ep_op_has_event(op))
		ep_take_care_of_epollwakeup(epds);

	/*
	 * We have to check that the file structure underneath the file descriptor
	 * the user passed to us _is_ an eventpoll file. And also we do not permit
	 * adding an epoll file descriptor inside itself.
	 */
	error = -EINVAL;
	if (fd_file(f) == fd_file(tf) || !is_file_epoll(fd_file(f)))
		goto error_tgt_fput;

	/*
	 * epoll adds to the wakeup queue at EPOLL_CTL_ADD time only,
	 * so EPOLLEXCLUSIVE is not allowed for a EPOLL_CTL_MOD operation.
	 * Also, we do not currently supported nested exclusive wakeups.
	 */
	if (ep_op_has_event(op) && (epds->events & EPOLLEXCLUSIVE)) {
		if (op == EPOLL_CTL_MOD)
			goto error_tgt_fput;
		if (op == EPOLL_CTL_ADD && (is_file_epoll(fd_file(tf)) ||
				(epds->events & ~EPOLLEXCLUSIVE_OK_BITS)))
			goto error_tgt_fput;
	}

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	ep = fd_file(f)->private_data;

	/*
	 * When we insert an epoll file descriptor inside another epoll file
	 * descriptor, there is the chance of creating closed loops, which are
	 * better be handled here, than in more critical paths. While we are
	 * checking for loops we also determine the list of files reachable
	 * and hang them on the tfile_check_list, so we can check that we
	 * haven't created too many possible wakeup paths.
	 *
	 * We do not need to take the global 'epumutex' on EPOLL_CTL_ADD when
	 * the epoll file descriptor is attaching directly to a wakeup source,
	 * unless the epoll file descriptor is nested. The purpose of taking the
	 * 'epnested_mutex' on add is to prevent complex toplogies such as loops and
	 * deep wakeup paths from forming in parallel through multiple
	 * EPOLL_CTL_ADD operations.
	 */
	error = epoll_mutex_lock(&ep->mtx, 0, nonblock);
	if (error)
		goto error_tgt_fput;
	if (op == EPOLL_CTL_ADD) {
		if (READ_ONCE(fd_file(f)->f_ep) || ep->gen == loop_check_gen ||
		    is_file_epoll(fd_file(tf))) {
			mutex_unlock(&ep->mtx);
			error = epoll_mutex_lock(&epnested_mutex, 0, nonblock);
			if (error)
				goto error_tgt_fput;
			loop_check_gen++;
			full_check = 1;
			if (is_file_epoll(fd_file(tf))) {
				tep = fd_file(tf)->private_data;
				error = -ELOOP;
				if (ep_loop_check(ep, tep) != 0)
					goto error_tgt_fput;
			}
			error = epoll_mutex_lock(&ep->mtx, 0, nonblock);
			if (error)
				goto error_tgt_fput;
		}
	}

	/*
	 * Try to lookup the file inside our RB tree. Since we grabbed "mtx"
	 * above, we can be sure to be able to use the item looked up by
	 * ep_find() till we release the mutex.
	 */
	epi = ep_find(ep, fd_file(tf), fd);

	error = -EINVAL;
	switch (op) {
	case EPOLL_CTL_ADD:
		if (!epi) {
			epds->events |= EPOLLERR | EPOLLHUP;
			error = ep_insert(ep, epds, fd_file(tf), fd, full_check);
		} else
			error = -EEXIST;
		break;
	case EPOLL_CTL_DEL:
		if (epi) {
			/*
			 * The eventpoll itself is still alive: the refcount
			 * can't go to zero here.
			 */
			ep_remove_safe(ep, epi);
			error = 0;
		} else {
			error = -ENOENT;
		}
		break;
	case EPOLL_CTL_MOD:
		if (epi) {
			if (!(epi->event.events & EPOLLEXCLUSIVE)) {
				epds->events |= EPOLLERR | EPOLLHUP;
				error = ep_modify(ep, epi, epds);
			}
		} else
			error = -ENOENT;
		break;
	}
	mutex_unlock(&ep->mtx);

error_tgt_fput:
	if (full_check) {
		clear_tfile_check_list();
		loop_check_gen++;
		mutex_unlock(&epnested_mutex);
	}
	return error;
}

/**
 * sys_epoll_ctl - Control interface for an epoll file descriptor
 * @epfd: File descriptor referring to the epoll instance
 * @op: Operation to perform (EPOLL_CTL_ADD, EPOLL_CTL_MOD, or EPOLL_CTL_DEL)
 * @fd: Target file descriptor to add, modify, or remove from the interest list
 * @event: Pointer to epoll_event structure specifying events and user data
 *
 * long-desc: Manages entries in the interest list of an epoll file descriptor.
 *   This syscall allows adding, modifying, or removing file descriptors from
 *   the set of descriptors being monitored by an epoll instance.
 *
 *   The supported operations are:
 *   - EPOLL_CTL_ADD (1): Register @fd on the epoll instance @epfd. The events
 *     to monitor and user data are specified in @event. The kernel always adds
 *     EPOLLERR and EPOLLHUP to the monitored events regardless of the mask.
 *   - EPOLL_CTL_MOD (3): Change the settings associated with @fd to the new
 *     settings in @event. This re-arms EPOLLONESHOT file descriptors.
 *   - EPOLL_CTL_DEL (2): Remove @fd from the interest list. The @event argument
 *     is ignored and can be NULL on kernels >= 2.6.9. Earlier kernels required
 *     a non-NULL pointer even though it was unused.
 *
 *   The epoll_event structure contains:
 *   - events: Bitmask of events to monitor (EPOLLIN, EPOLLOUT, etc.)
 *   - data: User data that is returned unchanged by epoll_wait()
 *
 *   When adding a file descriptor, the kernel performs loop detection to
 *   prevent circular epoll chains (an epoll fd monitoring another epoll fd
 *   that monitors the first). The nesting depth is limited to EP_MAX_NESTS (4)
 *   and the number of wakeup paths is also constrained to prevent wakeup
 *   storms.
 *
 *   Edge-triggered mode (EPOLLET) delivers events only when the state changes,
 *   while level-triggered mode (default) reports events as long as the
 *   condition persists. EPOLLONESHOT disables the fd after one event is
 *   delivered, requiring EPOLL_CTL_MOD to re-arm it.
 *
 *   EPOLLEXCLUSIVE provides exclusive wakeup semantics to avoid thundering
 *   herd problems when multiple processes/threads monitor the same fd. This
 *   flag can only be used with EPOLL_CTL_ADD and not on epoll fds themselves.
 *
 *   EPOLLWAKEUP keeps the system awake while the event is pending, useful for
 *   power management. It requires CAP_BLOCK_SUSPEND capability; without it,
 *   the flag is silently removed from the events mask rather than returning
 *   an error.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: epfd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid file descriptor referring to an epoll instance
 *     created by epoll_create() or epoll_create1(). Cannot be the same as @fd.
 *     The kernel verifies the underlying file has eventpoll_fops file_operations.
 *
 * param: op
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_ENUM
 *   valid-mask: EPOLL_CTL_ADD | EPOLL_CTL_DEL | EPOLL_CTL_MOD
 *   constraint: Must be one of EPOLL_CTL_ADD (1), EPOLL_CTL_DEL (2), or
 *     EPOLL_CTL_MOD (3). EPOLL_CTL_ADD requires @fd not already be registered.
 *     EPOLL_CTL_DEL and EPOLL_CTL_MOD require @fd to already be registered.
 *     Any other value results in EINVAL at the switch statement default case.
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid file descriptor supporting poll operations
 *     (file->f_op->poll must be non-NULL). Regular files, directories, and
 *     some special files that don't support poll return EPERM. Cannot be the
 *     same as @epfd. Pipes, sockets, eventfds, timerfd, signalfd, and most
 *     device files are valid targets. An epoll fd can monitor another epoll
 *     fd, but nesting depth is limited to prevent loops and stack overflow.
 *
 * param: event
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: For EPOLL_CTL_ADD and EPOLL_CTL_MOD, must point to a readable
 *     struct epoll_event in user space. The events field is a bitmask of
 *     EPOLLIN, EPOLLOUT, EPOLLRDHUP, EPOLLPRI, EPOLLERR, EPOLLHUP, EPOLLET,
 *     EPOLLONESHOT, EPOLLWAKEUP, and EPOLLEXCLUSIVE. The data field is an
 *     opaque 64-bit value returned by epoll_wait(). For EPOLL_CTL_DEL, this
 *     argument is ignored and may be NULL on Linux >= 2.6.9. EPOLLEXCLUSIVE
 *     is only valid with EPOLL_CTL_ADD and cannot be used with epoll fds or
 *     combined with flags other than EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP,
 *     EPOLLWAKEUP, or EPOLLET. If EPOLLEXCLUSIVE is used with EPOLL_CTL_MOD,
 *     the operation returns EINVAL.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: On success, returns zero. The requested operation has been completed.
 *     For EPOLL_CTL_ADD, the fd is now registered and will be monitored. For
 *     EPOLL_CTL_MOD, the event mask and data have been updated. For
 *     EPOLL_CTL_DEL, the fd has been removed from the interest list.
 *
 * error: EBADF, Invalid epfd or fd file descriptor
 *   desc: Either @epfd is not a valid file descriptor, @fd is not a valid
 *     file descriptor, or both are invalid. The kernel obtains file pointers
 *     via fdget() for both descriptors; if either fd is not allocated in the
 *     process's file descriptor table, this error is returned. This check
 *     occurs early, before any locking or validation.
 *
 * error: EEXIST, File descriptor already registered (EPOLL_CTL_ADD)
 *   desc: The @fd is already registered in the interest list of @epfd. Each
 *     (file descriptor, file pointer) pair can only be registered once per
 *     epoll instance. Note that if the same underlying file is opened via
 *     different file descriptors (e.g., via dup()), each can be separately
 *     registered since they have different file pointers. To modify an
 *     existing registration, use EPOLL_CTL_MOD instead.
 *
 * error: EINVAL, Invalid arguments or operation
 *   desc: Returned for multiple invalid conditions: (1) @epfd is not an epoll
 *     file descriptor (the file's f_op is not eventpoll_fops), (2) @fd is
 *     the same as @epfd (an epoll instance cannot monitor itself), (3) @op
 *     is not EPOLL_CTL_ADD, EPOLL_CTL_DEL, or EPOLL_CTL_MOD, (4) EPOLLEXCLUSIVE
 *     is specified with EPOLL_CTL_MOD, (5) EPOLLEXCLUSIVE is used when adding
 *     an epoll fd to another epoll instance, (6) EPOLLEXCLUSIVE is combined
 *     with flags other than EPOLLIN, EPOLLOUT, EPOLLWAKEUP, EPOLLERR, EPOLLHUP,
 *     or EPOLLET, (7) adding an epoll fd would create too many wakeup paths
 *     (checked by reverse_path_check()).
 *
 * error: ELOOP, Loop detected or nesting too deep
 *   desc: Adding @fd to @epfd would create a circular dependency of epoll file
 *     descriptors, or the nesting depth exceeds EP_MAX_NESTS (4). The kernel
 *     performs a graph traversal via ep_loop_check() when adding one epoll fd
 *     to another to detect cycles. The combined upward and downward depth
 *     from the insertion point must not exceed 4 to prevent stack overflow
 *     during wakeup cascades. This error only occurs for EPOLL_CTL_ADD when
 *     @fd is itself an epoll file descriptor.
 *
 * error: ENOENT, File descriptor not registered (EPOLL_CTL_MOD/DEL)
 *   desc: The @fd is not registered in the interest list of @epfd. This
 *     error occurs when trying to modify or delete a file descriptor that
 *     was never added, or was previously removed. The kernel searches for
 *     the (fd, file pointer) pair in a red-black tree via ep_find(); if not
 *     found, this error is returned.
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory to complete the operation. For
 *     EPOLL_CTL_ADD, this can occur when: (1) allocating struct epitem
 *     (~128 bytes on 64-bit) via kmem_cache_zalloc(epi_cache), (2) allocating
 *     struct eppoll_entry for wait queue hooks via kmem_cache_alloc(pwq_cache),
 *     (3) allocating struct epitems_head for tracking file associations via
 *     kmem_cache_zalloc(ephead_cache), (4) allocating wakeup_source when
 *     EPOLLWAKEUP is set. For EPOLL_CTL_MOD, this can occur when adding a
 *     wakeup_source that wasn't previously allocated. All allocations use
 *     GFP_KERNEL which allows sleeping and memory reclaim.
 *
 * error: ENOSPC, User watches limit exceeded
 *   desc: The per-user limit on the number of watched file descriptors has
 *     been reached. This limit is set by /proc/sys/fs/epoll/max_user_watches
 *     (default is approximately 4% of lowmem divided by ~160 bytes per watch).
 *     The limit is per-user (tracked via ep->user->epoll_watches), not per
 *     epoll instance. The error is returned early in ep_insert() before
 *     allocating the epitem structure. The limit can be increased by root via
 *     the sysctl interface. This error only occurs for EPOLL_CTL_ADD.
 *
 * error: EPERM, File descriptor does not support poll
 *   desc: The @fd refers to a file that does not support poll operations
 *     (file->f_op->poll is NULL). Regular files, directories, and certain
 *     special files cannot be monitored by epoll. This check is performed
 *     via file_can_poll() early in do_epoll_ctl(). Files that support poll
 *     include: sockets, pipes, FIFOs, terminals, eventfd, signalfd, timerfd,
 *     and most character devices. Note that inotify and fanotify fds support
 *     poll and can be monitored by epoll.
 *
 * error: EFAULT, Invalid event pointer
 *   desc: For EPOLL_CTL_ADD and EPOLL_CTL_MOD, the @event pointer is invalid
 *     or points to memory that is not readable. The kernel uses copy_from_user()
 *     to copy the 12-byte (or 16-byte on some architectures) epoll_event
 *     structure. If the copy fails, this error is returned. This check happens
 *     in the syscall wrapper before calling do_epoll_ctl(). For EPOLL_CTL_DEL,
 *     @event is not accessed so EFAULT cannot occur.
 *
 * lock: ep->mtx
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: The per-epoll instance mutex is acquired via mutex_lock_nested() at
 *     the start of the operation and released at the end. This mutex serializes
 *     all EPOLL_CTL operations and protects the red-black tree (ep->rbr),
 *     the ready list (ep->rdllist), and epitem structures. The mutex allows
 *     sleeping while held, which is necessary for copy_from_user operations
 *     and memory allocation in called helper functions.
 *
 * lock: epnested_mutex
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: A global mutex acquired only during EPOLL_CTL_ADD operations when
 *     potential nesting is detected (adding an epoll fd to another epoll, or
 *     when the target file is already being monitored by other epoll instances).
 *     This mutex prevents race conditions during loop detection that could
 *     allow creation of cycles. It is released after the operation completes.
 *     The loop_check_gen counter is incremented under this lock to track
 *     which eventpoll instances have been visited during cycle detection.
 *
 * lock: ep->lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The per-epoll spinlock is acquired briefly when modifying the ready
 *     list (ep->rdllist) or checking/modifying ovflist. This spinlock can be
 *     taken from IRQ context in ep_poll_callback(), so it's acquired with
 *     spin_lock_irq/spin_lock_irqsave. In ep_insert() and ep_modify(), it's
 *     used when adding items to the ready list after polling shows readiness.
 *
 * lock: file->f_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The target file's f_lock spinlock is acquired when adding or removing
 *     the epitem from the file's f_ep list (a list of all epoll items monitoring
 *     this file). This enables eventpoll_release_file() to clean up when a file
 *     is closed. The lock is taken briefly in attach_epitem() and __ep_remove().
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: epitem structure (EPOLL_CTL_ADD only)
 *   desc: Allocates a struct epitem from the epi_cache slab cache. This
 *     structure tracks the monitored file descriptor, associated events, and
 *     linkage in the red-black tree and ready list. The epitem is inserted into
 *     ep->rbr (red-black tree) for O(log n) lookup by file descriptor. It may
 *     also be added to ep->rdllist if the fd is already ready.
 *   condition: EPOLL_CTL_ADD operation succeeds
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: eppoll_entry structure (EPOLL_CTL_ADD only)
 *   desc: Allocates struct eppoll_entry from pwq_cache to hook into the target
 *     file's wait queue. This enables the file to wake up epoll when events
 *     occur. Multiple eppoll_entry structures may be allocated if the file has
 *     multiple wait queues.
 *   condition: EPOLL_CTL_ADD and target file has wait queues
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: wakeup_source (conditional)
 *   desc: If EPOLLWAKEUP is set in the events mask and the caller has
 *     CAP_BLOCK_SUSPEND capability, a wakeup_source is allocated and registered
 *     to prevent system suspend while events are pending. The wakeup source
 *     name is derived from the file's dentry name.
 *   condition: EPOLLWAKEUP flag set and CAP_BLOCK_SUSPEND held
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_DESTROY
 *   target: epitem and associated structures (EPOLL_CTL_DEL only)
 *   desc: For EPOLL_CTL_DEL, the epitem is removed from the red-black tree and
 *     ready list, wait queue hooks are removed via ep_unregister_pollwait(),
 *     and the epitem is freed via kfree_rcu() after an RCU grace period. The
 *     per-user epoll watch counter is decremented.
 *   condition: EPOLL_CTL_DEL operation succeeds
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: epitem event mask and data (EPOLL_CTL_MOD only)
 *   desc: Updates the events mask and user data in the existing epitem. If the
 *     monitored fd is now ready according to the new mask, it is added to the
 *     ready list. If EPOLLWAKEUP is added, a wakeup_source is created. If
 *     EPOLLWAKEUP is removed, the wakeup_source is destroyed (via
 *     synchronize_rcu() followed by wakeup_source_unregister()).
 *   condition: EPOLL_CTL_MOD operation succeeds
 *   reversible: yes
 *
 * state-trans: epoll_interest_list
 *   from: fd not registered
 *   to: fd registered with events mask
 *   condition: EPOLL_CTL_ADD succeeds
 *   desc: The file descriptor transitions from not being monitored to being
 *     in the epoll instance's interest list, stored in the red-black tree.
 *
 * state-trans: epoll_interest_list
 *   from: fd registered with events mask A
 *   to: fd registered with events mask B
 *   condition: EPOLL_CTL_MOD succeeds
 *   desc: The file descriptor's monitored events and user data are updated.
 *     The fd remains in the interest list with different settings.
 *
 * state-trans: epoll_interest_list
 *   from: fd registered
 *   to: fd not registered
 *   condition: EPOLL_CTL_DEL succeeds
 *   desc: The file descriptor is removed from the interest list and will no
 *     longer generate events. The epitem is freed after RCU grace period.
 *
 * state-trans: epitem_oneshot
 *   from: events monitored
 *   to: events disabled (mask cleared except EP_PRIVATE_BITS)
 *   condition: EPOLLONESHOT set and event delivered via epoll_wait
 *   desc: After epoll_wait delivers an event for an EPOLLONESHOT fd, the
 *     events mask is cleared (except private bits). EPOLL_CTL_MOD must be
 *     used to re-enable event monitoring for this fd.
 *
 * capability: CAP_BLOCK_SUSPEND
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Using EPOLLWAKEUP flag to prevent system suspend during event handling
 *   without: The EPOLLWAKEUP flag is silently removed from the events mask.
 *     No error is returned, but the wakeup functionality is disabled.
 *   condition: Checked in ep_take_care_of_epollwakeup() when EPOLLWAKEUP is set
 *
 * constraint: User Watch Limit
 *   desc: The total number of file descriptors watched across all epoll
 *     instances by a single user is limited by max_user_watches, configurable
 *     via /proc/sys/fs/epoll/max_user_watches. Default is approximately 4% of
 *     available lowmem divided by EP_ITEM_COST (~160 bytes). Exceeding this
 *     limit returns ENOSPC on EPOLL_CTL_ADD.
 *
 * constraint: Nesting Depth
 *   desc: When epoll file descriptors monitor other epoll file descriptors,
 *     the nesting depth is limited to EP_MAX_NESTS (4) to prevent stack
 *     overflow during wakeup cascades. Additionally, the number of wakeup
 *     paths emanating from any single file is limited by path_limits[] array.
 *     Exceeding these limits returns ELOOP on EPOLL_CTL_ADD.
 *
 * constraint: Poll Support
 *   desc: The target file descriptor must refer to a file type that supports
 *     poll operations (f_op->poll is non-NULL). Regular files, directories,
 *     and some special files do not support poll and return EPERM.
 *
 * constraint: EPOLLEXCLUSIVE Restrictions
 *   desc: The EPOLLEXCLUSIVE flag has several restrictions: (1) only valid
 *     with EPOLL_CTL_ADD, not EPOLL_CTL_MOD, (2) cannot be used when @fd is
 *     an epoll file descriptor, (3) can only be combined with EPOLLIN,
 *     EPOLLOUT, EPOLLWAKEUP, EPOLLERR, EPOLLHUP, and EPOLLET. Violating any
 *     of these returns EINVAL.
 *
 * examples: epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);  // Add socket
 *   epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);  // Modify events or re-arm
 *   epoll_ctl(epfd, EPOLL_CTL_DEL, sockfd, NULL);  // Remove (Linux >= 2.6.9)
 *   ev.events = EPOLLIN | EPOLLET;  // Edge-triggered read
 *   ev.events = EPOLLOUT | EPOLLONESHOT;  // One-shot write notification
 *   ev.events = EPOLLIN | EPOLLEXCLUSIVE;  // Exclusive wakeup (Linux 4.5+)
 *
 * notes: The epoll_event structure has different alignment on x86-64 to match
 *   the 32-bit structure layout, using __attribute__((packed)). This enables
 *   32-bit applications to work correctly on 64-bit kernels without compat
 *   syscall handling for epoll_ctl.
 *
 *   Closing a file descriptor automatically removes it from all epoll instances
 *   via eventpoll_release_file(). However, if the same underlying file is
 *   opened multiple times (e.g., via dup()), the descriptor must be explicitly
 *   removed from each epoll instance or all file descriptors must be closed.
 *
 *   The distinction between file descriptors and file descriptions (struct file)
 *   is important: epoll tracks (fd number, struct file pointer) pairs. Two
 *   different fd numbers pointing to the same struct file (via dup()) are
 *   considered the same entry. But the same fd number after close() and a new
 *   open() will have a different struct file and thus be a different entry.
 *
 *   When using EPOLLEXCLUSIVE, only one of the threads/processes waiting on
 *   the same event source will be woken up when the event occurs, avoiding
 *   the thundering herd problem. This is particularly useful for accept()
 *   on listening sockets shared between multiple processes.
 *
 *   Level-triggered mode (default) will keep reporting an event as long as
 *   the condition persists. Edge-triggered mode (EPOLLET) only reports when
 *   the state changes. Edge-triggered requires careful programming to avoid
 *   missing events - applications should read/write until EAGAIN after each
 *   notification.
 *
 *   The operation is atomic with respect to other epoll_ctl calls on the same
 *   epoll instance - the ep->mtx mutex ensures serialization. However, events
 *   can be delivered via epoll_wait() concurrently.
 *
 *   Historical note: Before Linux 2.6.9, EPOLL_CTL_DEL required a non-NULL
 *   @event pointer even though the value was ignored. This was fixed to accept
 *   NULL. Portable applications targeting ancient kernels may still pass a
 *   dummy pointer for compatibility.
 *
 *   EPOLL_CTL_DISABLE was proposed but rejected in favor of the current design.
 *   The proposed flag would have allowed disabling a registration without
 *   removing it, but this added complexity without sufficient benefit.
 *
 * since-version: 2.6
 */
SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd,
		struct epoll_event __user *, event)
{
	struct epoll_event epds;

	if (ep_op_has_event(op) &&
	    copy_from_user(&epds, event, sizeof(struct epoll_event)))
		return -EFAULT;

	return do_epoll_ctl(epfd, op, fd, &epds, false);
}

static int ep_check_params(struct file *file, struct epoll_event __user *evs,
			   int maxevents)
{
	/* The maximum number of event must be greater than zero */
	if (maxevents <= 0 || maxevents > EP_MAX_EVENTS)
		return -EINVAL;

	/* Verify that the area passed by the user is writeable */
	if (!access_ok(evs, maxevents * sizeof(struct epoll_event)))
		return -EFAULT;

	/*
	 * We have to check that the file structure underneath the fd
	 * the user passed to us _is_ an eventpoll file.
	 */
	if (!is_file_epoll(file))
		return -EINVAL;

	return 0;
}

int epoll_sendevents(struct file *file, struct epoll_event __user *events,
		     int maxevents)
{
	struct eventpoll *ep;
	int ret;

	ret = ep_check_params(file, events, maxevents);
	if (unlikely(ret))
		return ret;

	ep = file->private_data;
	/*
	 * Racy call, but that's ok - it should get retried based on
	 * poll readiness anyway.
	 */
	if (ep_events_available(ep))
		return ep_try_send_events(ep, events, maxevents);
	return 0;
}

/*
 * Implement the event wait interface for the eventpoll file. It is the kernel
 * part of the user space epoll_wait(2).
 */
static int do_epoll_wait(int epfd, struct epoll_event __user *events,
			 int maxevents, struct timespec64 *to)
{
	struct eventpoll *ep;
	int ret;

	/* Get the "struct file *" for the eventpoll file */
	CLASS(fd, f)(epfd);
	if (fd_empty(f))
		return -EBADF;

	ret = ep_check_params(fd_file(f), events, maxevents);
	if (unlikely(ret))
		return ret;

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	ep = fd_file(f)->private_data;

	/* Time to fish for events ... */
	return ep_poll(ep, events, maxevents, to);
}

SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events,
		int, maxevents, int, timeout)
{
	struct timespec64 to;

	return do_epoll_wait(epfd, events, maxevents,
			     ep_timeout_to_timespec(&to, timeout));
}

/*
 * Implement the event wait interface for the eventpoll file. It is the kernel
 * part of the user space epoll_pwait(2).
 */
static int do_epoll_pwait(int epfd, struct epoll_event __user *events,
			  int maxevents, struct timespec64 *to,
			  const sigset_t __user *sigmask, size_t sigsetsize)
{
	int error;

	/*
	 * If the caller wants a certain signal mask to be set during the wait,
	 * we apply it here.
	 */
	error = set_user_sigmask(sigmask, sigsetsize);
	if (error)
		return error;

	error = do_epoll_wait(epfd, events, maxevents, to);

	restore_saved_sigmask_unless(error == -EINTR);

	return error;
}

SYSCALL_DEFINE6(epoll_pwait, int, epfd, struct epoll_event __user *, events,
		int, maxevents, int, timeout, const sigset_t __user *, sigmask,
		size_t, sigsetsize)
{
	struct timespec64 to;

	return do_epoll_pwait(epfd, events, maxevents,
			      ep_timeout_to_timespec(&to, timeout),
			      sigmask, sigsetsize);
}

SYSCALL_DEFINE6(epoll_pwait2, int, epfd, struct epoll_event __user *, events,
		int, maxevents, const struct __kernel_timespec __user *, timeout,
		const sigset_t __user *, sigmask, size_t, sigsetsize)
{
	struct timespec64 ts, *to = NULL;

	if (timeout) {
		if (get_timespec64(&ts, timeout))
			return -EFAULT;
		to = &ts;
		if (poll_select_set_timeout(to, ts.tv_sec, ts.tv_nsec))
			return -EINVAL;
	}

	return do_epoll_pwait(epfd, events, maxevents, to,
			      sigmask, sigsetsize);
}

#ifdef CONFIG_COMPAT
static int do_compat_epoll_pwait(int epfd, struct epoll_event __user *events,
				 int maxevents, struct timespec64 *timeout,
				 const compat_sigset_t __user *sigmask,
				 compat_size_t sigsetsize)
{
	long err;

	/*
	 * If the caller wants a certain signal mask to be set during the wait,
	 * we apply it here.
	 */
	err = set_compat_user_sigmask(sigmask, sigsetsize);
	if (err)
		return err;

	err = do_epoll_wait(epfd, events, maxevents, timeout);

	restore_saved_sigmask_unless(err == -EINTR);

	return err;
}

COMPAT_SYSCALL_DEFINE6(epoll_pwait, int, epfd,
		       struct epoll_event __user *, events,
		       int, maxevents, int, timeout,
		       const compat_sigset_t __user *, sigmask,
		       compat_size_t, sigsetsize)
{
	struct timespec64 to;

	return do_compat_epoll_pwait(epfd, events, maxevents,
				     ep_timeout_to_timespec(&to, timeout),
				     sigmask, sigsetsize);
}

COMPAT_SYSCALL_DEFINE6(epoll_pwait2, int, epfd,
		       struct epoll_event __user *, events,
		       int, maxevents,
		       const struct __kernel_timespec __user *, timeout,
		       const compat_sigset_t __user *, sigmask,
		       compat_size_t, sigsetsize)
{
	struct timespec64 ts, *to = NULL;

	if (timeout) {
		if (get_timespec64(&ts, timeout))
			return -EFAULT;
		to = &ts;
		if (poll_select_set_timeout(to, ts.tv_sec, ts.tv_nsec))
			return -EINVAL;
	}

	return do_compat_epoll_pwait(epfd, events, maxevents, to,
				     sigmask, sigsetsize);
}

#endif

static int __init eventpoll_init(void)
{
	struct sysinfo si;

	si_meminfo(&si);
	/*
	 * Allows top 4% of lomem to be allocated for epoll watches (per user).
	 */
	max_user_watches = (((si.totalram - si.totalhigh) / 25) << PAGE_SHIFT) /
		EP_ITEM_COST;
	BUG_ON(max_user_watches < 0);

	/*
	 * We can have many thousands of epitems, so prevent this from
	 * using an extra cache line on 64-bit (and smaller) CPUs
	 */
	BUILD_BUG_ON(sizeof(void *) <= 8 && sizeof(struct epitem) > 128);

	/* Allocates slab cache used to allocate "struct epitem" items */
	epi_cache = kmem_cache_create("eventpoll_epi", sizeof(struct epitem),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);

	/* Allocates slab cache used to allocate "struct eppoll_entry" */
	pwq_cache = kmem_cache_create("eventpoll_pwq",
		sizeof(struct eppoll_entry), 0, SLAB_PANIC|SLAB_ACCOUNT, NULL);
	epoll_sysctls_init();

	ephead_cache = kmem_cache_create("ep_head",
		sizeof(struct epitems_head), 0, SLAB_PANIC|SLAB_ACCOUNT, NULL);

	return 0;
}
fs_initcall(eventpoll_init);
