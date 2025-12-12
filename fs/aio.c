/*
 *	An async IO implementation for Linux
 *	Written by Benjamin LaHaise <bcrl@kvack.org>
 *
 *	Implements an efficient asynchronous io interface.
 *
 *	Copyright 2000, 2001, 2002 Red Hat, Inc.  All Rights Reserved.
 *	Copyright 2018 Christoph Hellwig.
 *
 *	See ../COPYING for licensing terms.
 */
#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/aio_abi.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/backing-dev.h>
#include <linux/refcount.h>
#include <linux/uio.h>

#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/aio.h>
#include <linux/highmem.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/eventfd.h>
#include <linux/blkdev.h>
#include <linux/compat.h>
#include <linux/migrate.h>
#include <linux/ramfs.h>
#include <linux/percpu-refcount.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>

#include <linux/uaccess.h>
#include <linux/nospec.h>

#include "internal.h"

#define KIOCB_KEY		0

#define AIO_RING_MAGIC			0xa10a10a1
#define AIO_RING_COMPAT_FEATURES	1
#define AIO_RING_INCOMPAT_FEATURES	0
struct aio_ring {
	unsigned	id;	/* kernel internal index number */
	unsigned	nr;	/* number of io_events */
	unsigned	head;	/* Written to by userland or under ring_lock
				 * mutex by aio_read_events_ring(). */
	unsigned	tail;

	unsigned	magic;
	unsigned	compat_features;
	unsigned	incompat_features;
	unsigned	header_length;	/* size of aio_ring */


	struct io_event		io_events[];
}; /* 128 bytes + ring size */

/*
 * Plugging is meant to work with larger batches of IOs. If we don't
 * have more than the below, then don't bother setting up a plug.
 */
#define AIO_PLUG_THRESHOLD	2

#define AIO_RING_PAGES	8

struct kioctx_table {
	struct rcu_head		rcu;
	unsigned		nr;
	struct kioctx __rcu	*table[] __counted_by(nr);
};

struct kioctx_cpu {
	unsigned		reqs_available;
};

struct ctx_rq_wait {
	struct completion comp;
	atomic_t count;
};

struct kioctx {
	struct percpu_ref	users;
	atomic_t		dead;

	struct percpu_ref	reqs;

	unsigned long		user_id;

	struct kioctx_cpu __percpu *cpu;

	/*
	 * For percpu reqs_available, number of slots we move to/from global
	 * counter at a time:
	 */
	unsigned		req_batch;
	/*
	 * This is what userspace passed to io_setup(), it's not used for
	 * anything but counting against the global max_reqs quota.
	 *
	 * The real limit is nr_events - 1, which will be larger (see
	 * aio_setup_ring())
	 */
	unsigned		max_reqs;

	/* Size of ringbuffer, in units of struct io_event */
	unsigned		nr_events;

	unsigned long		mmap_base;
	unsigned long		mmap_size;

	struct folio		**ring_folios;
	long			nr_pages;

	struct rcu_work		free_rwork;	/* see free_ioctx() */

	/*
	 * signals when all in-flight requests are done
	 */
	struct ctx_rq_wait	*rq_wait;

	struct {
		/*
		 * This counts the number of available slots in the ringbuffer,
		 * so we avoid overflowing it: it's decremented (if positive)
		 * when allocating a kiocb and incremented when the resulting
		 * io_event is pulled off the ringbuffer.
		 *
		 * We batch accesses to it with a percpu version.
		 */
		atomic_t	reqs_available;
	} ____cacheline_aligned_in_smp;

	struct {
		spinlock_t	ctx_lock;
		struct list_head active_reqs;	/* used for cancellation */
	} ____cacheline_aligned_in_smp;

	struct {
		struct mutex	ring_lock;
		wait_queue_head_t wait;
	} ____cacheline_aligned_in_smp;

	struct {
		unsigned	tail;
		unsigned	completed_events;
		spinlock_t	completion_lock;
	} ____cacheline_aligned_in_smp;

	struct folio		*internal_folios[AIO_RING_PAGES];
	struct file		*aio_ring_file;

	unsigned		id;
};

/*
 * First field must be the file pointer in all the
 * iocb unions! See also 'struct kiocb' in <linux/fs.h>
 */
struct fsync_iocb {
	struct file		*file;
	struct work_struct	work;
	bool			datasync;
	struct cred		*creds;
};

struct poll_iocb {
	struct file		*file;
	struct wait_queue_head	*head;
	__poll_t		events;
	bool			cancelled;
	bool			work_scheduled;
	bool			work_need_resched;
	struct wait_queue_entry	wait;
	struct work_struct	work;
};

/*
 * NOTE! Each of the iocb union members has the file pointer
 * as the first entry in their struct definition. So you can
 * access the file pointer through any of the sub-structs,
 * or directly as just 'ki_filp' in this struct.
 */
struct aio_kiocb {
	union {
		struct file		*ki_filp;
		struct kiocb		rw;
		struct fsync_iocb	fsync;
		struct poll_iocb	poll;
	};

	struct kioctx		*ki_ctx;
	kiocb_cancel_fn		*ki_cancel;

	struct io_event		ki_res;

	struct list_head	ki_list;	/* the aio core uses this
						 * for cancellation */
	refcount_t		ki_refcnt;

	/*
	 * If the aio_resfd field of the userspace iocb is not zero,
	 * this is the underlying eventfd context to deliver events to.
	 */
	struct eventfd_ctx	*ki_eventfd;
};

/*------ sysctl variables----*/
static DEFINE_SPINLOCK(aio_nr_lock);
static unsigned long aio_nr;		/* current system wide number of aio requests */
static unsigned long aio_max_nr = 0x10000; /* system wide maximum number of aio requests */
/*----end sysctl variables---*/
#ifdef CONFIG_SYSCTL
static const struct ctl_table aio_sysctls[] = {
	{
		.procname	= "aio-nr",
		.data		= &aio_nr,
		.maxlen		= sizeof(aio_nr),
		.mode		= 0444,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "aio-max-nr",
		.data		= &aio_max_nr,
		.maxlen		= sizeof(aio_max_nr),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
};

static void __init aio_sysctl_init(void)
{
	register_sysctl_init("fs", aio_sysctls);
}
#else
#define aio_sysctl_init() do { } while (0)
#endif

static struct kmem_cache	*kiocb_cachep;
static struct kmem_cache	*kioctx_cachep;

static struct vfsmount *aio_mnt;

static const struct file_operations aio_ring_fops;
static const struct address_space_operations aio_ctx_aops;

static struct file *aio_private_file(struct kioctx *ctx, loff_t nr_pages)
{
	struct file *file;
	struct inode *inode = alloc_anon_inode(aio_mnt->mnt_sb);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	inode->i_mapping->a_ops = &aio_ctx_aops;
	inode->i_mapping->i_private_data = ctx;
	inode->i_size = PAGE_SIZE * nr_pages;

	file = alloc_file_pseudo(inode, aio_mnt, "[aio]",
				O_RDWR, &aio_ring_fops);
	if (IS_ERR(file))
		iput(inode);
	return file;
}

static int aio_init_fs_context(struct fs_context *fc)
{
	if (!init_pseudo(fc, AIO_RING_MAGIC))
		return -ENOMEM;
	fc->s_iflags |= SB_I_NOEXEC;
	return 0;
}

/* aio_setup
 *	Creates the slab caches used by the aio routines, panic on
 *	failure as this is done early during the boot sequence.
 */
static int __init aio_setup(void)
{
	static struct file_system_type aio_fs = {
		.name		= "aio",
		.init_fs_context = aio_init_fs_context,
		.kill_sb	= kill_anon_super,
	};
	aio_mnt = kern_mount(&aio_fs);
	if (IS_ERR(aio_mnt))
		panic("Failed to create aio fs mount.");

	kiocb_cachep = KMEM_CACHE(aio_kiocb, SLAB_HWCACHE_ALIGN|SLAB_PANIC);
	kioctx_cachep = KMEM_CACHE(kioctx,SLAB_HWCACHE_ALIGN|SLAB_PANIC);
	aio_sysctl_init();
	return 0;
}
__initcall(aio_setup);

static void put_aio_ring_file(struct kioctx *ctx)
{
	struct file *aio_ring_file = ctx->aio_ring_file;
	struct address_space *i_mapping;

	if (aio_ring_file) {
		truncate_setsize(file_inode(aio_ring_file), 0);

		/* Prevent further access to the kioctx from migratepages */
		i_mapping = aio_ring_file->f_mapping;
		spin_lock(&i_mapping->i_private_lock);
		i_mapping->i_private_data = NULL;
		ctx->aio_ring_file = NULL;
		spin_unlock(&i_mapping->i_private_lock);

		fput(aio_ring_file);
	}
}

static void aio_free_ring(struct kioctx *ctx)
{
	int i;

	/* Disconnect the kiotx from the ring file.  This prevents future
	 * accesses to the kioctx from page migration.
	 */
	put_aio_ring_file(ctx);

	for (i = 0; i < ctx->nr_pages; i++) {
		struct folio *folio = ctx->ring_folios[i];

		if (!folio)
			continue;

		pr_debug("pid(%d) [%d] folio->count=%d\n", current->pid, i,
			 folio_ref_count(folio));
		ctx->ring_folios[i] = NULL;
		folio_put(folio);
	}

	if (ctx->ring_folios && ctx->ring_folios != ctx->internal_folios) {
		kfree(ctx->ring_folios);
		ctx->ring_folios = NULL;
	}
}

static int aio_ring_mremap(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct mm_struct *mm = vma->vm_mm;
	struct kioctx_table *table;
	int i, res = -EINVAL;

	spin_lock(&mm->ioctx_lock);
	rcu_read_lock();
	table = rcu_dereference(mm->ioctx_table);
	if (!table)
		goto out_unlock;

	for (i = 0; i < table->nr; i++) {
		struct kioctx *ctx;

		ctx = rcu_dereference(table->table[i]);
		if (ctx && ctx->aio_ring_file == file) {
			if (!atomic_read(&ctx->dead)) {
				ctx->user_id = ctx->mmap_base = vma->vm_start;
				res = 0;
			}
			break;
		}
	}

out_unlock:
	rcu_read_unlock();
	spin_unlock(&mm->ioctx_lock);
	return res;
}

static const struct vm_operations_struct aio_ring_vm_ops = {
	.mremap		= aio_ring_mremap,
#if IS_ENABLED(CONFIG_MMU)
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= filemap_page_mkwrite,
#endif
};

static int aio_ring_mmap_prepare(struct vm_area_desc *desc)
{
	desc->vm_flags |= VM_DONTEXPAND;
	desc->vm_ops = &aio_ring_vm_ops;
	return 0;
}

static const struct file_operations aio_ring_fops = {
	.mmap_prepare = aio_ring_mmap_prepare,
};

#if IS_ENABLED(CONFIG_MIGRATION)
static int aio_migrate_folio(struct address_space *mapping, struct folio *dst,
			struct folio *src, enum migrate_mode mode)
{
	struct kioctx *ctx;
	unsigned long flags;
	pgoff_t idx;
	int rc = 0;

	/* mapping->i_private_lock here protects against the kioctx teardown.  */
	spin_lock(&mapping->i_private_lock);
	ctx = mapping->i_private_data;
	if (!ctx) {
		rc = -EINVAL;
		goto out;
	}

	/* The ring_lock mutex.  The prevents aio_read_events() from writing
	 * to the ring's head, and prevents page migration from mucking in
	 * a partially initialized kiotx.
	 */
	if (!mutex_trylock(&ctx->ring_lock)) {
		rc = -EAGAIN;
		goto out;
	}

	idx = src->index;
	if (idx < (pgoff_t)ctx->nr_pages) {
		/* Make sure the old folio hasn't already been changed */
		if (ctx->ring_folios[idx] != src)
			rc = -EAGAIN;
	} else
		rc = -EINVAL;

	if (rc != 0)
		goto out_unlock;

	/* Writeback must be complete */
	BUG_ON(folio_test_writeback(src));
	folio_get(dst);

	rc = folio_migrate_mapping(mapping, dst, src, 1);
	if (rc) {
		folio_put(dst);
		goto out_unlock;
	}

	/* Take completion_lock to prevent other writes to the ring buffer
	 * while the old folio is copied to the new.  This prevents new
	 * events from being lost.
	 */
	spin_lock_irqsave(&ctx->completion_lock, flags);
	folio_copy(dst, src);
	folio_migrate_flags(dst, src);
	BUG_ON(ctx->ring_folios[idx] != src);
	ctx->ring_folios[idx] = dst;
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	/* The old folio is no longer accessible. */
	folio_put(src);

out_unlock:
	mutex_unlock(&ctx->ring_lock);
out:
	spin_unlock(&mapping->i_private_lock);
	return rc;
}
#else
#define aio_migrate_folio NULL
#endif

static const struct address_space_operations aio_ctx_aops = {
	.dirty_folio	= noop_dirty_folio,
	.migrate_folio	= aio_migrate_folio,
};

static int aio_setup_ring(struct kioctx *ctx, unsigned int nr_events)
{
	struct aio_ring *ring;
	struct mm_struct *mm = current->mm;
	unsigned long size, unused;
	int nr_pages;
	int i;
	struct file *file;

	/* Compensate for the ring buffer's head/tail overlap entry */
	nr_events += 2;	/* 1 is required, 2 for good luck */

	size = sizeof(struct aio_ring);
	size += sizeof(struct io_event) * nr_events;

	nr_pages = PFN_UP(size);
	if (nr_pages < 0)
		return -EINVAL;

	file = aio_private_file(ctx, nr_pages);
	if (IS_ERR(file)) {
		ctx->aio_ring_file = NULL;
		return -ENOMEM;
	}

	ctx->aio_ring_file = file;
	nr_events = (PAGE_SIZE * nr_pages - sizeof(struct aio_ring))
			/ sizeof(struct io_event);

	ctx->ring_folios = ctx->internal_folios;
	if (nr_pages > AIO_RING_PAGES) {
		ctx->ring_folios = kcalloc(nr_pages, sizeof(struct folio *),
					   GFP_KERNEL);
		if (!ctx->ring_folios) {
			put_aio_ring_file(ctx);
			return -ENOMEM;
		}
	}

	for (i = 0; i < nr_pages; i++) {
		struct folio *folio;

		folio = __filemap_get_folio(file->f_mapping, i,
					    FGP_LOCK | FGP_ACCESSED | FGP_CREAT,
					    GFP_USER | __GFP_ZERO);
		if (IS_ERR(folio))
			break;

		pr_debug("pid(%d) [%d] folio->count=%d\n", current->pid, i,
			 folio_ref_count(folio));
		folio_end_read(folio, true);

		ctx->ring_folios[i] = folio;
	}
	ctx->nr_pages = i;

	if (unlikely(i != nr_pages)) {
		aio_free_ring(ctx);
		return -ENOMEM;
	}

	ctx->mmap_size = nr_pages * PAGE_SIZE;
	pr_debug("attempting mmap of %lu bytes\n", ctx->mmap_size);

	if (mmap_write_lock_killable(mm)) {
		ctx->mmap_size = 0;
		aio_free_ring(ctx);
		return -EINTR;
	}

	ctx->mmap_base = do_mmap(ctx->aio_ring_file, 0, ctx->mmap_size,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED, 0, 0, &unused, NULL);
	mmap_write_unlock(mm);
	if (IS_ERR((void *)ctx->mmap_base)) {
		ctx->mmap_size = 0;
		aio_free_ring(ctx);
		return -ENOMEM;
	}

	pr_debug("mmap address: 0x%08lx\n", ctx->mmap_base);

	ctx->user_id = ctx->mmap_base;
	ctx->nr_events = nr_events; /* trusted copy */

	ring = folio_address(ctx->ring_folios[0]);
	ring->nr = nr_events;	/* user copy */
	ring->id = ~0U;
	ring->head = ring->tail = 0;
	ring->magic = AIO_RING_MAGIC;
	ring->compat_features = AIO_RING_COMPAT_FEATURES;
	ring->incompat_features = AIO_RING_INCOMPAT_FEATURES;
	ring->header_length = sizeof(struct aio_ring);
	flush_dcache_folio(ctx->ring_folios[0]);

	return 0;
}

#define AIO_EVENTS_PER_PAGE	(PAGE_SIZE / sizeof(struct io_event))
#define AIO_EVENTS_FIRST_PAGE	((PAGE_SIZE - sizeof(struct aio_ring)) / sizeof(struct io_event))
#define AIO_EVENTS_OFFSET	(AIO_EVENTS_PER_PAGE - AIO_EVENTS_FIRST_PAGE)

void kiocb_set_cancel_fn(struct kiocb *iocb, kiocb_cancel_fn *cancel)
{
	struct aio_kiocb *req;
	struct kioctx *ctx;
	unsigned long flags;

	/*
	 * kiocb didn't come from aio or is neither a read nor a write, hence
	 * ignore it.
	 */
	if (!(iocb->ki_flags & IOCB_AIO_RW))
		return;

	req = container_of(iocb, struct aio_kiocb, rw);

	if (WARN_ON_ONCE(!list_empty(&req->ki_list)))
		return;

	ctx = req->ki_ctx;

	spin_lock_irqsave(&ctx->ctx_lock, flags);
	list_add_tail(&req->ki_list, &ctx->active_reqs);
	req->ki_cancel = cancel;
	spin_unlock_irqrestore(&ctx->ctx_lock, flags);
}
EXPORT_SYMBOL(kiocb_set_cancel_fn);

/*
 * free_ioctx() should be RCU delayed to synchronize against the RCU
 * protected lookup_ioctx() and also needs process context to call
 * aio_free_ring().  Use rcu_work.
 */
static void free_ioctx(struct work_struct *work)
{
	struct kioctx *ctx = container_of(to_rcu_work(work), struct kioctx,
					  free_rwork);
	pr_debug("freeing %p\n", ctx);

	aio_free_ring(ctx);
	free_percpu(ctx->cpu);
	percpu_ref_exit(&ctx->reqs);
	percpu_ref_exit(&ctx->users);
	kmem_cache_free(kioctx_cachep, ctx);
}

static void free_ioctx_reqs(struct percpu_ref *ref)
{
	struct kioctx *ctx = container_of(ref, struct kioctx, reqs);

	/* At this point we know that there are no any in-flight requests */
	if (ctx->rq_wait && atomic_dec_and_test(&ctx->rq_wait->count))
		complete(&ctx->rq_wait->comp);

	/* Synchronize against RCU protected table->table[] dereferences */
	INIT_RCU_WORK(&ctx->free_rwork, free_ioctx);
	queue_rcu_work(system_percpu_wq, &ctx->free_rwork);
}

/*
 * When this function runs, the kioctx has been removed from the "hash table"
 * and ctx->users has dropped to 0, so we know no more kiocbs can be submitted -
 * now it's safe to cancel any that need to be.
 */
static void free_ioctx_users(struct percpu_ref *ref)
{
	struct kioctx *ctx = container_of(ref, struct kioctx, users);
	struct aio_kiocb *req;

	spin_lock_irq(&ctx->ctx_lock);

	while (!list_empty(&ctx->active_reqs)) {
		req = list_first_entry(&ctx->active_reqs,
				       struct aio_kiocb, ki_list);
		req->ki_cancel(&req->rw);
		list_del_init(&req->ki_list);
	}

	spin_unlock_irq(&ctx->ctx_lock);

	percpu_ref_kill(&ctx->reqs);
	percpu_ref_put(&ctx->reqs);
}

static int ioctx_add_table(struct kioctx *ctx, struct mm_struct *mm)
{
	unsigned i, new_nr;
	struct kioctx_table *table, *old;
	struct aio_ring *ring;

	spin_lock(&mm->ioctx_lock);
	table = rcu_dereference_raw(mm->ioctx_table);

	while (1) {
		if (table)
			for (i = 0; i < table->nr; i++)
				if (!rcu_access_pointer(table->table[i])) {
					ctx->id = i;
					rcu_assign_pointer(table->table[i], ctx);
					spin_unlock(&mm->ioctx_lock);

					/* While kioctx setup is in progress,
					 * we are protected from page migration
					 * changes ring_folios by ->ring_lock.
					 */
					ring = folio_address(ctx->ring_folios[0]);
					ring->id = ctx->id;
					return 0;
				}

		new_nr = (table ? table->nr : 1) * 4;
		spin_unlock(&mm->ioctx_lock);

		table = kzalloc(struct_size(table, table, new_nr), GFP_KERNEL);
		if (!table)
			return -ENOMEM;

		table->nr = new_nr;

		spin_lock(&mm->ioctx_lock);
		old = rcu_dereference_raw(mm->ioctx_table);

		if (!old) {
			rcu_assign_pointer(mm->ioctx_table, table);
		} else if (table->nr > old->nr) {
			memcpy(table->table, old->table,
			       old->nr * sizeof(struct kioctx *));

			rcu_assign_pointer(mm->ioctx_table, table);
			kfree_rcu(old, rcu);
		} else {
			kfree(table);
			table = old;
		}
	}
}

static void aio_nr_sub(unsigned nr)
{
	spin_lock(&aio_nr_lock);
	if (WARN_ON(aio_nr - nr > aio_nr))
		aio_nr = 0;
	else
		aio_nr -= nr;
	spin_unlock(&aio_nr_lock);
}

/* ioctx_alloc
 *	Allocates and initializes an ioctx.  Returns an ERR_PTR if it failed.
 */
static struct kioctx *ioctx_alloc(unsigned nr_events)
{
	struct mm_struct *mm = current->mm;
	struct kioctx *ctx;
	int err = -ENOMEM;

	/*
	 * Store the original nr_events -- what userspace passed to io_setup(),
	 * for counting against the global limit -- before it changes.
	 */
	unsigned int max_reqs = nr_events;

	/*
	 * We keep track of the number of available ringbuffer slots, to prevent
	 * overflow (reqs_available), and we also use percpu counters for this.
	 *
	 * So since up to half the slots might be on other cpu's percpu counters
	 * and unavailable, double nr_events so userspace sees what they
	 * expected: additionally, we move req_batch slots to/from percpu
	 * counters at a time, so make sure that isn't 0:
	 */
	nr_events = max(nr_events, num_possible_cpus() * 4);
	nr_events *= 2;

	/* Prevent overflows */
	if (nr_events > (0x10000000U / sizeof(struct io_event))) {
		pr_debug("ENOMEM: nr_events too high\n");
		return ERR_PTR(-EINVAL);
	}

	if (!nr_events || (unsigned long)max_reqs > aio_max_nr)
		return ERR_PTR(-EAGAIN);

	ctx = kmem_cache_zalloc(kioctx_cachep, GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->max_reqs = max_reqs;

	spin_lock_init(&ctx->ctx_lock);
	spin_lock_init(&ctx->completion_lock);
	mutex_init(&ctx->ring_lock);
	/* Protect against page migration throughout kiotx setup by keeping
	 * the ring_lock mutex held until setup is complete. */
	mutex_lock(&ctx->ring_lock);
	init_waitqueue_head(&ctx->wait);

	INIT_LIST_HEAD(&ctx->active_reqs);

	if (percpu_ref_init(&ctx->users, free_ioctx_users, 0, GFP_KERNEL))
		goto err;

	if (percpu_ref_init(&ctx->reqs, free_ioctx_reqs, 0, GFP_KERNEL))
		goto err;

	ctx->cpu = alloc_percpu(struct kioctx_cpu);
	if (!ctx->cpu)
		goto err;

	err = aio_setup_ring(ctx, nr_events);
	if (err < 0)
		goto err;

	atomic_set(&ctx->reqs_available, ctx->nr_events - 1);
	ctx->req_batch = (ctx->nr_events - 1) / (num_possible_cpus() * 4);
	if (ctx->req_batch < 1)
		ctx->req_batch = 1;

	/* limit the number of system wide aios */
	spin_lock(&aio_nr_lock);
	if (aio_nr + ctx->max_reqs > aio_max_nr ||
	    aio_nr + ctx->max_reqs < aio_nr) {
		spin_unlock(&aio_nr_lock);
		err = -EAGAIN;
		goto err_ctx;
	}
	aio_nr += ctx->max_reqs;
	spin_unlock(&aio_nr_lock);

	percpu_ref_get(&ctx->users);	/* io_setup() will drop this ref */
	percpu_ref_get(&ctx->reqs);	/* free_ioctx_users() will drop this */

	err = ioctx_add_table(ctx, mm);
	if (err)
		goto err_cleanup;

	/* Release the ring_lock mutex now that all setup is complete. */
	mutex_unlock(&ctx->ring_lock);

	pr_debug("allocated ioctx %p[%ld]: mm=%p mask=0x%x\n",
		 ctx, ctx->user_id, mm, ctx->nr_events);
	return ctx;

err_cleanup:
	aio_nr_sub(ctx->max_reqs);
err_ctx:
	atomic_set(&ctx->dead, 1);
	if (ctx->mmap_size)
		vm_munmap(ctx->mmap_base, ctx->mmap_size);
	aio_free_ring(ctx);
err:
	mutex_unlock(&ctx->ring_lock);
	free_percpu(ctx->cpu);
	percpu_ref_exit(&ctx->reqs);
	percpu_ref_exit(&ctx->users);
	kmem_cache_free(kioctx_cachep, ctx);
	pr_debug("error allocating ioctx %d\n", err);
	return ERR_PTR(err);
}

/* kill_ioctx
 *	Cancels all outstanding aio requests on an aio context.  Used
 *	when the processes owning a context have all exited to encourage
 *	the rapid destruction of the kioctx.
 */
static int kill_ioctx(struct mm_struct *mm, struct kioctx *ctx,
		      struct ctx_rq_wait *wait)
{
	struct kioctx_table *table;

	spin_lock(&mm->ioctx_lock);
	if (atomic_xchg(&ctx->dead, 1)) {
		spin_unlock(&mm->ioctx_lock);
		return -EINVAL;
	}

	table = rcu_dereference_raw(mm->ioctx_table);
	WARN_ON(ctx != rcu_access_pointer(table->table[ctx->id]));
	RCU_INIT_POINTER(table->table[ctx->id], NULL);
	spin_unlock(&mm->ioctx_lock);

	/* free_ioctx_reqs() will do the necessary RCU synchronization */
	wake_up_all(&ctx->wait);

	/*
	 * It'd be more correct to do this in free_ioctx(), after all
	 * the outstanding kiocbs have finished - but by then io_destroy
	 * has already returned, so io_setup() could potentially return
	 * -EAGAIN with no ioctxs actually in use (as far as userspace
	 *  could tell).
	 */
	aio_nr_sub(ctx->max_reqs);

	if (ctx->mmap_size)
		vm_munmap(ctx->mmap_base, ctx->mmap_size);

	ctx->rq_wait = wait;
	percpu_ref_kill(&ctx->users);
	return 0;
}

/*
 * exit_aio: called when the last user of mm goes away.  At this point, there is
 * no way for any new requests to be submited or any of the io_* syscalls to be
 * called on the context.
 *
 * There may be outstanding kiocbs, but free_ioctx() will explicitly wait on
 * them.
 */
void exit_aio(struct mm_struct *mm)
{
	struct kioctx_table *table = rcu_dereference_raw(mm->ioctx_table);
	struct ctx_rq_wait wait;
	int i, skipped;

	if (!table)
		return;

	atomic_set(&wait.count, table->nr);
	init_completion(&wait.comp);

	skipped = 0;
	for (i = 0; i < table->nr; ++i) {
		struct kioctx *ctx =
			rcu_dereference_protected(table->table[i], true);

		if (!ctx) {
			skipped++;
			continue;
		}

		/*
		 * We don't need to bother with munmap() here - exit_mmap(mm)
		 * is coming and it'll unmap everything. And we simply can't,
		 * this is not necessarily our ->mm.
		 * Since kill_ioctx() uses non-zero ->mmap_size as indicator
		 * that it needs to unmap the area, just set it to 0.
		 */
		ctx->mmap_size = 0;
		kill_ioctx(mm, ctx, &wait);
	}

	if (!atomic_sub_and_test(skipped, &wait.count)) {
		/* Wait until all IO for the context are done. */
		wait_for_completion(&wait.comp);
	}

	RCU_INIT_POINTER(mm->ioctx_table, NULL);
	kfree(table);
}

static void put_reqs_available(struct kioctx *ctx, unsigned nr)
{
	struct kioctx_cpu *kcpu;
	unsigned long flags;

	local_irq_save(flags);
	kcpu = this_cpu_ptr(ctx->cpu);
	kcpu->reqs_available += nr;

	while (kcpu->reqs_available >= ctx->req_batch * 2) {
		kcpu->reqs_available -= ctx->req_batch;
		atomic_add(ctx->req_batch, &ctx->reqs_available);
	}

	local_irq_restore(flags);
}

static bool __get_reqs_available(struct kioctx *ctx)
{
	struct kioctx_cpu *kcpu;
	bool ret = false;
	unsigned long flags;

	local_irq_save(flags);
	kcpu = this_cpu_ptr(ctx->cpu);
	if (!kcpu->reqs_available) {
		int avail = atomic_read(&ctx->reqs_available);

		do {
			if (avail < ctx->req_batch)
				goto out;
		} while (!atomic_try_cmpxchg(&ctx->reqs_available,
					     &avail, avail - ctx->req_batch));

		kcpu->reqs_available += ctx->req_batch;
	}

	ret = true;
	kcpu->reqs_available--;
out:
	local_irq_restore(flags);
	return ret;
}

/* refill_reqs_available
 *	Updates the reqs_available reference counts used for tracking the
 *	number of free slots in the completion ring.  This can be called
 *	from aio_complete() (to optimistically update reqs_available) or
 *	from aio_get_req() (the we're out of events case).  It must be
 *	called holding ctx->completion_lock.
 */
static void refill_reqs_available(struct kioctx *ctx, unsigned head,
                                  unsigned tail)
{
	unsigned events_in_ring, completed;

	/* Clamp head since userland can write to it. */
	head %= ctx->nr_events;
	if (head <= tail)
		events_in_ring = tail - head;
	else
		events_in_ring = ctx->nr_events - (head - tail);

	completed = ctx->completed_events;
	if (events_in_ring < completed)
		completed -= events_in_ring;
	else
		completed = 0;

	if (!completed)
		return;

	ctx->completed_events -= completed;
	put_reqs_available(ctx, completed);
}

/* user_refill_reqs_available
 *	Called to refill reqs_available when aio_get_req() encounters an
 *	out of space in the completion ring.
 */
static void user_refill_reqs_available(struct kioctx *ctx)
{
	spin_lock_irq(&ctx->completion_lock);
	if (ctx->completed_events) {
		struct aio_ring *ring;
		unsigned head;

		/* Access of ring->head may race with aio_read_events_ring()
		 * here, but that's okay since whether we read the old version
		 * or the new version, and either will be valid.  The important
		 * part is that head cannot pass tail since we prevent
		 * aio_complete() from updating tail by holding
		 * ctx->completion_lock.  Even if head is invalid, the check
		 * against ctx->completed_events below will make sure we do the
		 * safe/right thing.
		 */
		ring = folio_address(ctx->ring_folios[0]);
		head = ring->head;

		refill_reqs_available(ctx, head, ctx->tail);
	}

	spin_unlock_irq(&ctx->completion_lock);
}

static bool get_reqs_available(struct kioctx *ctx)
{
	if (__get_reqs_available(ctx))
		return true;
	user_refill_reqs_available(ctx);
	return __get_reqs_available(ctx);
}

/* aio_get_req
 *	Allocate a slot for an aio request.
 * Returns NULL if no requests are free.
 *
 * The refcount is initialized to 2 - one for the async op completion,
 * one for the synchronous code that does this.
 */
static inline struct aio_kiocb *aio_get_req(struct kioctx *ctx)
{
	struct aio_kiocb *req;

	req = kmem_cache_alloc(kiocb_cachep, GFP_KERNEL);
	if (unlikely(!req))
		return NULL;

	if (unlikely(!get_reqs_available(ctx))) {
		kmem_cache_free(kiocb_cachep, req);
		return NULL;
	}

	percpu_ref_get(&ctx->reqs);
	req->ki_ctx = ctx;
	INIT_LIST_HEAD(&req->ki_list);
	refcount_set(&req->ki_refcnt, 2);
	req->ki_eventfd = NULL;
	return req;
}

static struct kioctx *lookup_ioctx(unsigned long ctx_id)
{
	struct aio_ring __user *ring  = (void __user *)ctx_id;
	struct mm_struct *mm = current->mm;
	struct kioctx *ctx, *ret = NULL;
	struct kioctx_table *table;
	unsigned id;

	if (get_user(id, &ring->id))
		return NULL;

	rcu_read_lock();
	table = rcu_dereference(mm->ioctx_table);

	if (!table || id >= table->nr)
		goto out;

	id = array_index_nospec(id, table->nr);
	ctx = rcu_dereference(table->table[id]);
	if (ctx && ctx->user_id == ctx_id) {
		if (percpu_ref_tryget_live(&ctx->users))
			ret = ctx;
	}
out:
	rcu_read_unlock();
	return ret;
}

static inline void iocb_destroy(struct aio_kiocb *iocb)
{
	if (iocb->ki_eventfd)
		eventfd_ctx_put(iocb->ki_eventfd);
	if (iocb->ki_filp)
		fput(iocb->ki_filp);
	percpu_ref_put(&iocb->ki_ctx->reqs);
	kmem_cache_free(kiocb_cachep, iocb);
}

struct aio_waiter {
	struct wait_queue_entry	w;
	size_t			min_nr;
};

/* aio_complete
 *	Called when the io request on the given iocb is complete.
 */
static void aio_complete(struct aio_kiocb *iocb)
{
	struct kioctx	*ctx = iocb->ki_ctx;
	struct aio_ring	*ring;
	struct io_event	*ev_page, *event;
	unsigned tail, pos, head, avail;
	unsigned long	flags;

	/*
	 * Add a completion event to the ring buffer. Must be done holding
	 * ctx->completion_lock to prevent other code from messing with the tail
	 * pointer since we might be called from irq context.
	 */
	spin_lock_irqsave(&ctx->completion_lock, flags);

	tail = ctx->tail;
	pos = tail + AIO_EVENTS_OFFSET;

	if (++tail >= ctx->nr_events)
		tail = 0;

	ev_page = folio_address(ctx->ring_folios[pos / AIO_EVENTS_PER_PAGE]);
	event = ev_page + pos % AIO_EVENTS_PER_PAGE;

	*event = iocb->ki_res;

	flush_dcache_folio(ctx->ring_folios[pos / AIO_EVENTS_PER_PAGE]);

	pr_debug("%p[%u]: %p: %p %Lx %Lx %Lx\n", ctx, tail, iocb,
		 (void __user *)(unsigned long)iocb->ki_res.obj,
		 iocb->ki_res.data, iocb->ki_res.res, iocb->ki_res.res2);

	/* after flagging the request as done, we
	 * must never even look at it again
	 */
	smp_wmb();	/* make event visible before updating tail */

	ctx->tail = tail;

	ring = folio_address(ctx->ring_folios[0]);
	head = ring->head;
	ring->tail = tail;
	flush_dcache_folio(ctx->ring_folios[0]);

	ctx->completed_events++;
	if (ctx->completed_events > 1)
		refill_reqs_available(ctx, head, tail);

	avail = tail > head
		? tail - head
		: tail + ctx->nr_events - head;
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	pr_debug("added to ring %p at [%u]\n", iocb, tail);

	/*
	 * Check if the user asked us to deliver the result through an
	 * eventfd. The eventfd_signal() function is safe to be called
	 * from IRQ context.
	 */
	if (iocb->ki_eventfd)
		eventfd_signal(iocb->ki_eventfd);

	/*
	 * We have to order our ring_info tail store above and test
	 * of the wait list below outside the wait lock.  This is
	 * like in wake_up_bit() where clearing a bit has to be
	 * ordered with the unlocked test.
	 */
	smp_mb();

	if (waitqueue_active(&ctx->wait)) {
		struct aio_waiter *curr, *next;
		unsigned long flags;

		spin_lock_irqsave(&ctx->wait.lock, flags);
		list_for_each_entry_safe(curr, next, &ctx->wait.head, w.entry)
			if (avail >= curr->min_nr) {
				wake_up_process(curr->w.private);
				list_del_init_careful(&curr->w.entry);
			}
		spin_unlock_irqrestore(&ctx->wait.lock, flags);
	}
}

static inline void iocb_put(struct aio_kiocb *iocb)
{
	if (refcount_dec_and_test(&iocb->ki_refcnt)) {
		aio_complete(iocb);
		iocb_destroy(iocb);
	}
}

/* aio_read_events_ring
 *	Pull an event off of the ioctx's event ring.  Returns the number of
 *	events fetched
 */
static long aio_read_events_ring(struct kioctx *ctx,
				 struct io_event __user *event, long nr)
{
	struct aio_ring *ring;
	unsigned head, tail, pos;
	long ret = 0;
	int copy_ret;

	/*
	 * The mutex can block and wake us up and that will cause
	 * wait_event_interruptible_hrtimeout() to schedule without sleeping
	 * and repeat. This should be rare enough that it doesn't cause
	 * peformance issues. See the comment in read_events() for more detail.
	 */
	sched_annotate_sleep();
	mutex_lock(&ctx->ring_lock);

	/* Access to ->ring_folios here is protected by ctx->ring_lock. */
	ring = folio_address(ctx->ring_folios[0]);
	head = ring->head;
	tail = ring->tail;

	/*
	 * Ensure that once we've read the current tail pointer, that
	 * we also see the events that were stored up to the tail.
	 */
	smp_rmb();

	pr_debug("h%u t%u m%u\n", head, tail, ctx->nr_events);

	if (head == tail)
		goto out;

	head %= ctx->nr_events;
	tail %= ctx->nr_events;

	while (ret < nr) {
		long avail;
		struct io_event *ev;
		struct folio *folio;

		avail = (head <= tail ?  tail : ctx->nr_events) - head;
		if (head == tail)
			break;

		pos = head + AIO_EVENTS_OFFSET;
		folio = ctx->ring_folios[pos / AIO_EVENTS_PER_PAGE];
		pos %= AIO_EVENTS_PER_PAGE;

		avail = min(avail, nr - ret);
		avail = min_t(long, avail, AIO_EVENTS_PER_PAGE - pos);

		ev = folio_address(folio);
		copy_ret = copy_to_user(event + ret, ev + pos,
					sizeof(*ev) * avail);

		if (unlikely(copy_ret)) {
			ret = -EFAULT;
			goto out;
		}

		ret += avail;
		head += avail;
		head %= ctx->nr_events;
	}

	ring = folio_address(ctx->ring_folios[0]);
	ring->head = head;
	flush_dcache_folio(ctx->ring_folios[0]);

	pr_debug("%li  h%u t%u\n", ret, head, tail);
out:
	mutex_unlock(&ctx->ring_lock);

	return ret;
}

static bool aio_read_events(struct kioctx *ctx, long min_nr, long nr,
			    struct io_event __user *event, long *i)
{
	long ret = aio_read_events_ring(ctx, event + *i, nr - *i);

	if (ret > 0)
		*i += ret;

	if (unlikely(atomic_read(&ctx->dead)))
		ret = -EINVAL;

	if (!*i)
		*i = ret;

	return ret < 0 || *i >= min_nr;
}

static long read_events(struct kioctx *ctx, long min_nr, long nr,
			struct io_event __user *event,
			ktime_t until)
{
	struct hrtimer_sleeper	t;
	struct aio_waiter	w;
	long ret = 0, ret2 = 0;

	/*
	 * Note that aio_read_events() is being called as the conditional - i.e.
	 * we're calling it after prepare_to_wait() has set task state to
	 * TASK_INTERRUPTIBLE.
	 *
	 * But aio_read_events() can block, and if it blocks it's going to flip
	 * the task state back to TASK_RUNNING.
	 *
	 * This should be ok, provided it doesn't flip the state back to
	 * TASK_RUNNING and return 0 too much - that causes us to spin. That
	 * will only happen if the mutex_lock() call blocks, and we then find
	 * the ringbuffer empty. So in practice we should be ok, but it's
	 * something to be aware of when touching this code.
	 */
	aio_read_events(ctx, min_nr, nr, event, &ret);
	if (until == 0 || ret < 0 || ret >= min_nr)
		return ret;

	hrtimer_setup_sleeper_on_stack(&t, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	if (until != KTIME_MAX) {
		hrtimer_set_expires_range_ns(&t.timer, until, current->timer_slack_ns);
		hrtimer_sleeper_start_expires(&t, HRTIMER_MODE_REL);
	}

	init_wait(&w.w);

	while (1) {
		unsigned long nr_got = ret;

		w.min_nr = min_nr - ret;

		ret2 = prepare_to_wait_event(&ctx->wait, &w.w, TASK_INTERRUPTIBLE);
		if (!ret2 && !t.task)
			ret2 = -ETIME;

		if (aio_read_events(ctx, min_nr, nr, event, &ret) || ret2)
			break;

		if (nr_got == ret)
			schedule();
	}

	finish_wait(&ctx->wait, &w.w);
	hrtimer_cancel(&t.timer);
	destroy_hrtimer_on_stack(&t.timer);

	return ret;
}

/**
 * sys_io_setup - Create an asynchronous I/O context
 * @nr_events: Minimum number of concurrent AIO operations the context should support
 * @ctxp: Pointer to aio_context_t variable to receive the context handle
 *
 * long-desc: Creates an asynchronous I/O context capable of receiving at least
 *   nr_events concurrent operations. The context handle is returned via ctxp,
 *   which must be initialized to 0 prior to the call. The returned context
 *   handle is used with subsequent AIO operations (io_submit, io_getevents,
 *   io_cancel, io_destroy).
 *
 *   The AIO context consists of a memory-mapped ring buffer shared between
 *   kernel and userspace for efficient completion notification. The kernel
 *   internally allocates more capacity than requested to account for percpu
 *   batching (approximately nr_events * 2, but at least num_cpus * 8).
 *
 *   The context is bound to the calling process and cannot be shared across
 *   processes. Each process can have multiple AIO contexts, limited only by
 *   the system-wide aio-max-nr sysctl.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: nr_events
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 1, 8388608
 *   constraint: Must be greater than 0. Internal limit of approximately 8M events
 *     prevents overflow when calculating ring buffer size (0x10000000 / 32 bytes
 *     per io_event). The kernel may allocate more capacity than requested to
 *     optimize for percpu batching.
 *
 * param: ctxp
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_INOUT | KAPI_PARAM_USER
 *   size: sizeof(aio_context_t)
 *   constraint-type: KAPI_CONSTRAINT_USER_PTR
 *   constraint: Must be a valid userspace pointer to an aio_context_t variable.
 *     The memory pointed to MUST be initialized to 0 before the call. On success,
 *     receives the context handle (actually the mmap address of the ring buffer).
 *     The context handle is opaque and should not be interpreted by userspace
 *     except to pass to other io_* syscalls.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. On success, *ctxp contains the new context handle.
 *
 * error: EFAULT, Invalid pointer
 *   desc: The ctxp pointer is invalid, not accessible, or points to memory that
 *     cannot be read or written. Returned from get_user() when reading the
 *     initial value or from put_user() when storing the context handle.
 *
 * error: EINVAL, Invalid parameter
 *   desc: Either *ctxp is not initialized to 0 (indicating an existing context or
 *     uninitialized memory), or nr_events is 0, or nr_events is too large causing
 *     internal overflow when calculating ring buffer size. The internal limit is
 *     approximately 0x10000000 / sizeof(struct io_event) events.
 *
 * error: EAGAIN, Resource limit exceeded
 *   desc: The system-wide limit on AIO contexts would be exceeded. The limit is
 *     controlled by /proc/sys/fs/aio-max-nr (default 65536). Each context counts
 *     as nr_events toward this limit. Also returned if nr_events exceeds the
 *     current aio-max-nr value. Unlike ENOMEM, this error indicates a policy
 *     limit rather than physical resource exhaustion.
 *
 * error: ENOMEM, Insufficient memory
 *   desc: Kernel could not allocate required memory for the AIO context. This
 *     includes the kioctx structure, percpu data, ring buffer pages, or the
 *     anonymous file backing the ring buffer. Also returned if the kernel could
 *     not establish the memory mapping for the ring buffer, or if ioctx_table
 *     expansion failed.
 *
 * error: EINTR, Interrupted by signal
 *   desc: A fatal signal was received while attempting to acquire the mmap_lock
 *     for the ring buffer memory mapping. The operation was aborted before any
 *     state was modified. Only fatal signals (SIGKILL) can cause this error;
 *     normal signals like SIGINT do not interrupt the operation.
 *
 * lock: aio_nr_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   desc: Global spinlock protecting the system-wide aio_nr counter. Held briefly
 *     to check and update the system-wide AIO context count.
 *
 * lock: mm->ioctx_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   desc: Per-mm spinlock protecting the ioctx_table. Held while adding the new
 *     context to the process's AIO context table.
 *
 * lock: ctx->ring_lock
 *   type: KAPI_LOCK_MUTEX
 *   desc: Per-context mutex protecting ring buffer setup. Held throughout context
 *     initialization to prevent page migration during setup, then released once
 *     the context is fully initialized.
 *
 * lock: mmap_lock
 *   type: KAPI_LOCK_RWLOCK
 *   desc: Process memory map write lock. Acquired via mmap_write_lock_killable()
 *     during ring buffer mmap operation. This is where EINTR can occur.
 *
 * signal: SIGKILL
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: Fatal signal pending during mmap_write_lock_killable
 *   desc: Fatal signals can interrupt the context creation during the mmap phase.
 *     The mmap_write_lock_killable() function checks for fatal signals and returns
 *     -EINTR if one is pending. Non-fatal signals do not interrupt this syscall.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   priority: 0
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: kioctx structure
 *   desc: Allocates the main AIO context structure from kioctx_cachep slab cache.
 *     Contains ring buffer metadata, locks, and request tracking.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: percpu kioctx_cpu structures
 *   desc: Allocates per-CPU structures for request batching via alloc_percpu().
 *     Used to reduce contention on the global request counter.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: ring buffer pages
 *   desc: Allocates pages for the completion event ring buffer. The ring is backed
 *     by an anonymous file on the internal "aio" filesystem and memory-mapped into
 *     the process address space.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: anonymous inode and file
 *   desc: Creates an anonymous inode and file on the internal aio filesystem to
 *     back the ring buffer mapping. This enables proper page migration support.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: process virtual memory
 *   desc: Creates a new memory mapping (VMA) for the ring buffer in the process
 *     address space. The mapping is marked VM_DONTEXPAND and uses aio_ring_vm_ops.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: mm->ioctx_table
 *   desc: Adds the new context to the process's AIO context table. The table is
 *     dynamically expanded if needed (grows by 4x each time).
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: aio_nr (global counter)
 *   desc: Increments the system-wide AIO context counter by nr_events. This counter
 *     is visible via /proc/sys/fs/aio-nr and counts toward the aio-max-nr limit.
 *   reversible: yes
 *
 * state-trans: process AIO state
 *   from: no AIO context (or fewer contexts)
 *   to: has AIO context
 *   condition: successful io_setup
 *   desc: Process gains an AIO context that can be used for asynchronous I/O
 *     operations. The context remains until explicitly destroyed via io_destroy
 *     or process exit.
 *
 * state-trans: system AIO resources
 *   from: aio_nr = N
 *   to: aio_nr = N + nr_events
 *   condition: successful io_setup
 *   desc: System-wide AIO resource counter increases. The counter tracks total
 *     requested AIO capacity across all processes.
 *
 * constraint: System-wide AIO limit (aio-max-nr)
 *   desc: The /proc/sys/fs/aio-max-nr sysctl (default 65536) limits the total
 *     number of AIO events system-wide. Each io_setup call adds nr_events to
 *     the aio_nr counter. If aio_nr + nr_events would exceed aio_max_nr, the
 *     call fails with EAGAIN. Administrators can increase aio-max-nr if needed.
 *   expr: aio_nr + nr_events <= aio_max_nr
 *
 * constraint: Per-process context limit
 *   desc: Each process can have multiple AIO contexts, limited only by the
 *     system-wide aio-max-nr limit and available memory. The ioctx_table grows
 *     dynamically to accommodate new contexts.
 *
 * constraint: CONFIG_AIO required
 *   desc: The kernel must be compiled with CONFIG_AIO=y for this syscall to be
 *     available. If not configured, the syscall returns -ENOSYS. This is typically
 *     enabled by default but may be disabled on embedded systems.
 *
 * constraint: Memory for ring buffer
 *   desc: The kernel must be able to allocate sufficient contiguous pages for the
 *     ring buffer and establish the memory mapping. Large nr_events values require
 *     more memory and may fail with ENOMEM on memory-constrained systems.
 *
 * examples: aio_context_t ctx = 0; io_setup(128, &ctx);  // Create context for 128 events
 *   aio_context_t ctx = 0; io_setup(1024, &ctx);  // Create context for 1024 events
 *
 * notes: The returned context handle is actually the virtual address of the ring
 *   buffer mapping in the process address space. This allows userspace libraries
 *   to directly access completion events without syscall overhead in some cases.
 *
 *   The kernel internally doubles nr_events and ensures a minimum of num_cpus * 8
 *   events for percpu batching efficiency. This means the actual ring capacity may
 *   be significantly larger than requested.
 *
 *   Historical note: A race condition between io_setup and io_destroy was fixed
 *   in commit 86b62a2cb4fc ("aio: fix io_setup/io_destroy race"). Earlier kernels
 *   could have the context freed while io_setup was still completing.
 *
 *   io_uring (since Linux 5.1) is a more modern alternative that provides better
 *   performance and more features. Consider using io_uring for new applications.
 *
 *   There is no glibc wrapper for this syscall. Use syscall(SYS_io_setup, ...) or
 *   the libaio library wrapper (note: libaio has slightly different error semantics,
 *   returning negative error numbers directly instead of -1 with errno).
 *
 * since-version: 2.5
 */
SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
{
	struct kioctx *ioctx = NULL;
	unsigned long ctx;
	long ret;

	ret = get_user(ctx, ctxp);
	if (unlikely(ret))
		goto out;

	ret = -EINVAL;
	if (unlikely(ctx || nr_events == 0)) {
		pr_debug("EINVAL: ctx %lu nr_events %u\n",
		         ctx, nr_events);
		goto out;
	}

	ioctx = ioctx_alloc(nr_events);
	ret = PTR_ERR(ioctx);
	if (!IS_ERR(ioctx)) {
		ret = put_user(ioctx->user_id, ctxp);
		if (ret)
			kill_ioctx(current->mm, ioctx, NULL);
		percpu_ref_put(&ioctx->users);
	}

out:
	return ret;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(io_setup, unsigned, nr_events, u32 __user *, ctx32p)
{
	struct kioctx *ioctx = NULL;
	unsigned long ctx;
	long ret;

	ret = get_user(ctx, ctx32p);
	if (unlikely(ret))
		goto out;

	ret = -EINVAL;
	if (unlikely(ctx || nr_events == 0)) {
		pr_debug("EINVAL: ctx %lu nr_events %u\n",
		         ctx, nr_events);
		goto out;
	}

	ioctx = ioctx_alloc(nr_events);
	ret = PTR_ERR(ioctx);
	if (!IS_ERR(ioctx)) {
		/* truncating is ok because it's a user address */
		ret = put_user((u32)ioctx->user_id, ctx32p);
		if (ret)
			kill_ioctx(current->mm, ioctx, NULL);
		percpu_ref_put(&ioctx->users);
	}

out:
	return ret;
}
#endif

/**
 * sys_io_destroy - Destroy an asynchronous I/O context
 * @ctx: AIO context handle returned by io_setup
 *
 * long-desc: Destroys the asynchronous I/O context identified by ctx. This
 *   syscall will attempt to cancel all outstanding asynchronous I/O operations
 *   against the context and block until all operations have completed. Once
 *   this syscall returns successfully, the context handle becomes invalid and
 *   must not be used with any other io_* syscalls.
 *
 *   The context's memory-mapped ring buffer is unmapped from the process address
 *   space, and all associated kernel resources are freed. The system-wide AIO
 *   event counter (aio_nr) is decremented by the original nr_events value that
 *   was passed to io_setup when creating this context.
 *
 *   This syscall blocks until all in-flight I/O operations have completed. This
 *   ensures that userspace buffers passed to io_submit are no longer accessed
 *   by the kernel after io_destroy returns. The wait is NOT interruptible by
 *   signals, so callers cannot cancel this blocking behavior.
 *
 *   If two threads call io_destroy on the same context simultaneously, only the
 *   first call will succeed; subsequent calls return -EINVAL as the context is
 *   already marked as dead.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: ctx
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid context handle previously returned by io_setup.
 *     The handle is actually the virtual address of the ring buffer mapping in
 *     the calling process's address space. A value of 0 is always invalid.
 *     The context must not have been previously destroyed.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. After successful return, the context handle is
 *     invalid and all resources have been released. All outstanding I/O
 *     operations have completed.
 *
 * error: EINVAL, Invalid context
 *   desc: The ctx argument does not refer to a valid AIO context in the calling
 *     process. This can occur if: (1) ctx was never returned by io_setup,
 *     (2) ctx was returned by io_setup in a different process, (3) ctx was
 *     already destroyed by a previous io_destroy call, (4) ctx is 0 or an
 *     arbitrary invalid value, or (5) the ring buffer at the ctx address has
 *     been corrupted (e.g., the id field no longer matches).
 *
 * lock: mm->ioctx_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   desc: Per-mm spinlock protecting the ioctx_table. Held briefly while
 *     marking the context as dead and removing it from the process's AIO
 *     context table.
 *
 * lock: RCU read lock
 *   type: KAPI_LOCK_RCU
 *   desc: RCU read-side critical section held during context lookup in
 *     lookup_ioctx(). Protects against concurrent modification of the
 *     ioctx_table.
 *
 * lock: ctx->ctx_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   desc: Per-context spinlock held while cancelling outstanding I/O requests
 *     in free_ioctx_users(). Protects the active_reqs list.
 *
 * lock: mmap_lock
 *   type: KAPI_LOCK_RWLOCK
 *   desc: Process memory map write lock acquired during vm_munmap() when
 *     unmapping the ring buffer. May contend with other memory operations
 *     in the same process.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: ctx->dead flag
 *   desc: Atomically sets the context's dead flag to 1, marking it as being
 *     destroyed. This prevents new I/O submissions and ensures subsequent
 *     io_destroy calls return -EINVAL.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: mm->ioctx_table
 *   desc: Removes the context from the process's AIO context table by setting
 *     the corresponding table entry to NULL. After this, lookup_ioctx will
 *     no longer find this context.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: aio_nr (global counter)
 *   desc: Decrements the system-wide AIO context counter by the context's
 *     max_reqs value (the nr_events originally passed to io_setup). This
 *     counter is visible via /proc/sys/fs/aio-nr.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: process virtual memory
 *   desc: Unmaps the ring buffer from the process's address space via
 *     vm_munmap(). The memory region at ctx becomes invalid.
 *   condition: ctx->mmap_size > 0
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_FREE_MEMORY
 *   target: kioctx structure and associated resources
 *   desc: Frees the AIO context structure, percpu data, ring buffer pages, and
 *     the anonymous file backing the ring buffer. Deferred via RCU work queue
 *     to ensure safe cleanup after all references are dropped.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_SIGNAL_SEND
 *   target: outstanding AIO operations
 *   desc: Cancels all outstanding asynchronous I/O operations by invoking their
 *     ki_cancel callbacks. The specific effect depends on the operation type
 *     (read, write, fsync, poll).
 *   condition: active_reqs list is not empty
 *   reversible: no
 *
 * state-trans: AIO context state
 *   from: alive (ctx->dead == 0)
 *   to: dead (ctx->dead == 1)
 *   condition: successful atomic exchange in kill_ioctx
 *   desc: The context transitions from usable to destroyed. Once dead, the
 *     context cannot be used for any operations and will be freed after all
 *     references are dropped.
 *
 * state-trans: process AIO state
 *   from: has AIO context(s)
 *   to: context removed (or no contexts)
 *   condition: successful io_destroy
 *   desc: The destroyed context is removed from the process's context table.
 *     If this was the only context, the process no longer has any active
 *     AIO contexts.
 *
 * state-trans: system AIO resources
 *   from: aio_nr = N
 *   to: aio_nr = N - max_reqs
 *   condition: successful io_destroy
 *   desc: System-wide AIO resource counter decreases, making room for other
 *     processes to create new AIO contexts.
 *
 * constraint: CONFIG_AIO required
 *   desc: The kernel must be compiled with CONFIG_AIO=y for this syscall to be
 *     available. If not configured, the syscall returns -ENOSYS. This is
 *     typically enabled by default but may be disabled on embedded systems.
 *
 * constraint: Context must belong to calling process
 *   desc: Each AIO context is bound to a specific process (mm_struct). A context
 *     created by one process cannot be destroyed by another process, even if
 *     the context handle value is somehow known.
 *   expr: ctx belongs to current->mm
 *
 * examples: io_destroy(ctx);  // Destroy context and wait for completion
 *   if (io_destroy(ctx) == -EINVAL) handle_error();  // Invalid context
 *
 * notes: The man page documents EFAULT as a possible error, but code analysis
 *   shows that EFAULT conditions (e.g., invalid ring buffer pointer) actually
 *   result in EINVAL being returned, as lookup_ioctx returns NULL on any
 *   failure to access the ring buffer header.
 *
 *   This syscall blocks in TASK_UNINTERRUPTIBLE state while waiting for
 *   outstanding I/O operations to complete. This means the process cannot be
 *   interrupted by signals during this wait. In extreme cases with very slow
 *   I/O devices, this could cause the process to appear hung.
 *
 *   Historical note: Before kernel 3.11, io_destroy blocked waiting for I/O
 *   completion. A refactoring in 3.11 accidentally removed this behavior,
 *   creating a race where userspace buffers could be freed while the kernel
 *   was still using them. This was fixed by commit e02ba72aabfa that blocks
 *   io_destroy until all context requests are completed.
 *
 *   Race condition handling: A race between io_destroy and io_submit was fixed
 *   by commit 7137c6bd4552. A race between io_setup and io_destroy was fixed
 *   by commit 86b62a2cb4fc. Both fixes ensure proper synchronization via
 *   reference counting.
 *
 *   io_uring (since Linux 5.1) is a more modern alternative that provides better
 *   performance and more features. Consider using io_uring for new applications.
 *
 *   There is no glibc wrapper for this syscall. Use syscall(SYS_io_destroy, ctx)
 *   or the libaio library wrapper io_destroy(). Note: libaio has slightly
 *   different error semantics, returning negative error numbers directly instead
 *   of -1 with errno.
 *
 * since-version: 2.5
 */
SYSCALL_DEFINE1(io_destroy, aio_context_t, ctx)
{
	struct kioctx *ioctx = lookup_ioctx(ctx);
	if (likely(NULL != ioctx)) {
		struct ctx_rq_wait wait;
		int ret;

		init_completion(&wait.comp);
		atomic_set(&wait.count, 1);

		/* Pass requests_done to kill_ioctx() where it can be set
		 * in a thread-safe way. If we try to set it here then we have
		 * a race condition if two io_destroy() called simultaneously.
		 */
		ret = kill_ioctx(current->mm, ioctx, &wait);
		percpu_ref_put(&ioctx->users);

		/* Wait until all IO for the context are done. Otherwise kernel
		 * keep using user-space buffers even if user thinks the context
		 * is destroyed.
		 */
		if (!ret)
			wait_for_completion(&wait.comp);

		return ret;
	}
	pr_debug("EINVAL: invalid context id\n");
	return -EINVAL;
}

static void aio_remove_iocb(struct aio_kiocb *iocb)
{
	struct kioctx *ctx = iocb->ki_ctx;
	unsigned long flags;

	spin_lock_irqsave(&ctx->ctx_lock, flags);
	list_del(&iocb->ki_list);
	spin_unlock_irqrestore(&ctx->ctx_lock, flags);
}

static void aio_complete_rw(struct kiocb *kiocb, long res)
{
	struct aio_kiocb *iocb = container_of(kiocb, struct aio_kiocb, rw);

	if (!list_empty_careful(&iocb->ki_list))
		aio_remove_iocb(iocb);

	if (kiocb->ki_flags & IOCB_WRITE) {
		struct inode *inode = file_inode(kiocb->ki_filp);

		if (S_ISREG(inode->i_mode))
			kiocb_end_write(kiocb);
	}

	iocb->ki_res.res = res;
	iocb->ki_res.res2 = 0;
	iocb_put(iocb);
}

static int aio_prep_rw(struct kiocb *req, const struct iocb *iocb, int rw_type)
{
	int ret;

	req->ki_write_stream = 0;
	req->ki_complete = aio_complete_rw;
	req->private = NULL;
	req->ki_pos = iocb->aio_offset;
	req->ki_flags = req->ki_filp->f_iocb_flags | IOCB_AIO_RW;
	if (iocb->aio_flags & IOCB_FLAG_RESFD)
		req->ki_flags |= IOCB_EVENTFD;
	if (iocb->aio_flags & IOCB_FLAG_IOPRIO) {
		/*
		 * If the IOCB_FLAG_IOPRIO flag of aio_flags is set, then
		 * aio_reqprio is interpreted as an I/O scheduling
		 * class and priority.
		 */
		ret = ioprio_check_cap(iocb->aio_reqprio);
		if (ret) {
			pr_debug("aio ioprio check cap error: %d\n", ret);
			return ret;
		}

		req->ki_ioprio = iocb->aio_reqprio;
	} else
		req->ki_ioprio = get_current_ioprio();

	ret = kiocb_set_rw_flags(req, iocb->aio_rw_flags, rw_type);
	if (unlikely(ret))
		return ret;

	req->ki_flags &= ~IOCB_HIPRI; /* no one is going to poll for this I/O */
	return 0;
}

static ssize_t aio_setup_rw(int rw, const struct iocb *iocb,
		struct iovec **iovec, bool vectored, bool compat,
		struct iov_iter *iter)
{
	void __user *buf = (void __user *)(uintptr_t)iocb->aio_buf;
	size_t len = iocb->aio_nbytes;

	if (!vectored) {
		ssize_t ret = import_ubuf(rw, buf, len, iter);
		*iovec = NULL;
		return ret;
	}

	return __import_iovec(rw, buf, len, UIO_FASTIOV, iovec, iter, compat);
}

static inline void aio_rw_done(struct kiocb *req, ssize_t ret)
{
	switch (ret) {
	case -EIOCBQUEUED:
		break;
	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
	case -ERESTART_RESTARTBLOCK:
		/*
		 * There's no easy way to restart the syscall since other AIO's
		 * may be already running. Just fail this IO with EINTR.
		 */
		ret = -EINTR;
		fallthrough;
	default:
		req->ki_complete(req, ret);
	}
}

static int aio_read(struct kiocb *req, const struct iocb *iocb,
			bool vectored, bool compat)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct iov_iter iter;
	struct file *file;
	int ret;

	ret = aio_prep_rw(req, iocb, READ);
	if (ret)
		return ret;
	file = req->ki_filp;
	if (unlikely(!(file->f_mode & FMODE_READ)))
		return -EBADF;
	if (unlikely(!file->f_op->read_iter))
		return -EINVAL;

	ret = aio_setup_rw(ITER_DEST, iocb, &iovec, vectored, compat, &iter);
	if (ret < 0)
		return ret;
	ret = rw_verify_area(READ, file, &req->ki_pos, iov_iter_count(&iter));
	if (!ret)
		aio_rw_done(req, file->f_op->read_iter(req, &iter));
	kfree(iovec);
	return ret;
}

static int aio_write(struct kiocb *req, const struct iocb *iocb,
			 bool vectored, bool compat)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct iov_iter iter;
	struct file *file;
	int ret;

	ret = aio_prep_rw(req, iocb, WRITE);
	if (ret)
		return ret;
	file = req->ki_filp;

	if (unlikely(!(file->f_mode & FMODE_WRITE)))
		return -EBADF;
	if (unlikely(!file->f_op->write_iter))
		return -EINVAL;

	ret = aio_setup_rw(ITER_SOURCE, iocb, &iovec, vectored, compat, &iter);
	if (ret < 0)
		return ret;
	ret = rw_verify_area(WRITE, file, &req->ki_pos, iov_iter_count(&iter));
	if (!ret) {
		if (S_ISREG(file_inode(file)->i_mode))
			kiocb_start_write(req);
		req->ki_flags |= IOCB_WRITE;
		aio_rw_done(req, file->f_op->write_iter(req, &iter));
	}
	kfree(iovec);
	return ret;
}

static void aio_fsync_work(struct work_struct *work)
{
	struct aio_kiocb *iocb = container_of(work, struct aio_kiocb, fsync.work);

	scoped_with_creds(iocb->fsync.creds)
		iocb->ki_res.res = vfs_fsync(iocb->fsync.file, iocb->fsync.datasync);

	put_cred(iocb->fsync.creds);
	iocb_put(iocb);
}

static int aio_fsync(struct fsync_iocb *req, const struct iocb *iocb,
		     bool datasync)
{
	if (unlikely(iocb->aio_buf || iocb->aio_offset || iocb->aio_nbytes ||
			iocb->aio_rw_flags))
		return -EINVAL;

	if (unlikely(!req->file->f_op->fsync))
		return -EINVAL;

	req->creds = prepare_creds();
	if (!req->creds)
		return -ENOMEM;

	req->datasync = datasync;
	INIT_WORK(&req->work, aio_fsync_work);
	schedule_work(&req->work);
	return 0;
}

static void aio_poll_put_work(struct work_struct *work)
{
	struct poll_iocb *req = container_of(work, struct poll_iocb, work);
	struct aio_kiocb *iocb = container_of(req, struct aio_kiocb, poll);

	iocb_put(iocb);
}

/*
 * Safely lock the waitqueue which the request is on, synchronizing with the
 * case where the ->poll() provider decides to free its waitqueue early.
 *
 * Returns true on success, meaning that req->head->lock was locked, req->wait
 * is on req->head, and an RCU read lock was taken.  Returns false if the
 * request was already removed from its waitqueue (which might no longer exist).
 */
static bool poll_iocb_lock_wq(struct poll_iocb *req)
{
	wait_queue_head_t *head;

	/*
	 * While we hold the waitqueue lock and the waitqueue is nonempty,
	 * wake_up_pollfree() will wait for us.  However, taking the waitqueue
	 * lock in the first place can race with the waitqueue being freed.
	 *
	 * We solve this as eventpoll does: by taking advantage of the fact that
	 * all users of wake_up_pollfree() will RCU-delay the actual free.  If
	 * we enter rcu_read_lock() and see that the pointer to the queue is
	 * non-NULL, we can then lock it without the memory being freed out from
	 * under us, then check whether the request is still on the queue.
	 *
	 * Keep holding rcu_read_lock() as long as we hold the queue lock, in
	 * case the caller deletes the entry from the queue, leaving it empty.
	 * In that case, only RCU prevents the queue memory from being freed.
	 */
	rcu_read_lock();
	head = smp_load_acquire(&req->head);
	if (head) {
		spin_lock(&head->lock);
		if (!list_empty(&req->wait.entry))
			return true;
		spin_unlock(&head->lock);
	}
	rcu_read_unlock();
	return false;
}

static void poll_iocb_unlock_wq(struct poll_iocb *req)
{
	spin_unlock(&req->head->lock);
	rcu_read_unlock();
}

static void aio_poll_complete_work(struct work_struct *work)
{
	struct poll_iocb *req = container_of(work, struct poll_iocb, work);
	struct aio_kiocb *iocb = container_of(req, struct aio_kiocb, poll);
	struct poll_table_struct pt = { ._key = req->events };
	struct kioctx *ctx = iocb->ki_ctx;
	__poll_t mask = 0;

	if (!READ_ONCE(req->cancelled))
		mask = vfs_poll(req->file, &pt) & req->events;

	/*
	 * Note that ->ki_cancel callers also delete iocb from active_reqs after
	 * calling ->ki_cancel.  We need the ctx_lock roundtrip here to
	 * synchronize with them.  In the cancellation case the list_del_init
	 * itself is not actually needed, but harmless so we keep it in to
	 * avoid further branches in the fast path.
	 */
	spin_lock_irq(&ctx->ctx_lock);
	if (poll_iocb_lock_wq(req)) {
		if (!mask && !READ_ONCE(req->cancelled)) {
			/*
			 * The request isn't actually ready to be completed yet.
			 * Reschedule completion if another wakeup came in.
			 */
			if (req->work_need_resched) {
				schedule_work(&req->work);
				req->work_need_resched = false;
			} else {
				req->work_scheduled = false;
			}
			poll_iocb_unlock_wq(req);
			spin_unlock_irq(&ctx->ctx_lock);
			return;
		}
		list_del_init(&req->wait.entry);
		poll_iocb_unlock_wq(req);
	} /* else, POLLFREE has freed the waitqueue, so we must complete */
	list_del_init(&iocb->ki_list);
	iocb->ki_res.res = mangle_poll(mask);
	spin_unlock_irq(&ctx->ctx_lock);

	iocb_put(iocb);
}

/* assumes we are called with irqs disabled */
static int aio_poll_cancel(struct kiocb *iocb)
{
	struct aio_kiocb *aiocb = container_of(iocb, struct aio_kiocb, rw);
	struct poll_iocb *req = &aiocb->poll;

	if (poll_iocb_lock_wq(req)) {
		WRITE_ONCE(req->cancelled, true);
		if (!req->work_scheduled) {
			schedule_work(&aiocb->poll.work);
			req->work_scheduled = true;
		}
		poll_iocb_unlock_wq(req);
	} /* else, the request was force-cancelled by POLLFREE already */

	return 0;
}

static int aio_poll_wake(struct wait_queue_entry *wait, unsigned mode, int sync,
		void *key)
{
	struct poll_iocb *req = container_of(wait, struct poll_iocb, wait);
	struct aio_kiocb *iocb = container_of(req, struct aio_kiocb, poll);
	__poll_t mask = key_to_poll(key);
	unsigned long flags;

	/* for instances that support it check for an event match first: */
	if (mask && !(mask & req->events))
		return 0;

	/*
	 * Complete the request inline if possible.  This requires that three
	 * conditions be met:
	 *   1. An event mask must have been passed.  If a plain wakeup was done
	 *	instead, then mask == 0 and we have to call vfs_poll() to get
	 *	the events, so inline completion isn't possible.
	 *   2. The completion work must not have already been scheduled.
	 *   3. ctx_lock must not be busy.  We have to use trylock because we
	 *	already hold the waitqueue lock, so this inverts the normal
	 *	locking order.  Use irqsave/irqrestore because not all
	 *	filesystems (e.g. fuse) call this function with IRQs disabled,
	 *	yet IRQs have to be disabled before ctx_lock is obtained.
	 */
	if (mask && !req->work_scheduled &&
	    spin_trylock_irqsave(&iocb->ki_ctx->ctx_lock, flags)) {
		struct kioctx *ctx = iocb->ki_ctx;

		list_del_init(&req->wait.entry);
		list_del(&iocb->ki_list);
		iocb->ki_res.res = mangle_poll(mask);
		if (iocb->ki_eventfd && !eventfd_signal_allowed()) {
			iocb = NULL;
			INIT_WORK(&req->work, aio_poll_put_work);
			schedule_work(&req->work);
		}
		spin_unlock_irqrestore(&ctx->ctx_lock, flags);
		if (iocb)
			iocb_put(iocb);
	} else {
		/*
		 * Schedule the completion work if needed.  If it was already
		 * scheduled, record that another wakeup came in.
		 *
		 * Don't remove the request from the waitqueue here, as it might
		 * not actually be complete yet (we won't know until vfs_poll()
		 * is called), and we must not miss any wakeups.  POLLFREE is an
		 * exception to this; see below.
		 */
		if (req->work_scheduled) {
			req->work_need_resched = true;
		} else {
			schedule_work(&req->work);
			req->work_scheduled = true;
		}

		/*
		 * If the waitqueue is being freed early but we can't complete
		 * the request inline, we have to tear down the request as best
		 * we can.  That means immediately removing the request from its
		 * waitqueue and preventing all further accesses to the
		 * waitqueue via the request.  We also need to schedule the
		 * completion work (done above).  Also mark the request as
		 * cancelled, to potentially skip an unneeded call to ->poll().
		 */
		if (mask & POLLFREE) {
			WRITE_ONCE(req->cancelled, true);
			list_del_init(&req->wait.entry);

			/*
			 * Careful: this *must* be the last step, since as soon
			 * as req->head is NULL'ed out, the request can be
			 * completed and freed, since aio_poll_complete_work()
			 * will no longer need to take the waitqueue lock.
			 */
			smp_store_release(&req->head, NULL);
		}
	}
	return 1;
}

struct aio_poll_table {
	struct poll_table_struct	pt;
	struct aio_kiocb		*iocb;
	bool				queued;
	int				error;
};

static void
aio_poll_queue_proc(struct file *file, struct wait_queue_head *head,
		struct poll_table_struct *p)
{
	struct aio_poll_table *pt = container_of(p, struct aio_poll_table, pt);

	/* multiple wait queues per file are not supported */
	if (unlikely(pt->queued)) {
		pt->error = -EINVAL;
		return;
	}

	pt->queued = true;
	pt->error = 0;
	pt->iocb->poll.head = head;
	add_wait_queue(head, &pt->iocb->poll.wait);
}

static int aio_poll(struct aio_kiocb *aiocb, const struct iocb *iocb)
{
	struct kioctx *ctx = aiocb->ki_ctx;
	struct poll_iocb *req = &aiocb->poll;
	struct aio_poll_table apt;
	bool cancel = false;
	__poll_t mask;

	/* reject any unknown events outside the normal event mask. */
	if ((u16)iocb->aio_buf != iocb->aio_buf)
		return -EINVAL;
	/* reject fields that are not defined for poll */
	if (iocb->aio_offset || iocb->aio_nbytes || iocb->aio_rw_flags)
		return -EINVAL;

	INIT_WORK(&req->work, aio_poll_complete_work);
	req->events = demangle_poll(iocb->aio_buf) | EPOLLERR | EPOLLHUP;

	req->head = NULL;
	req->cancelled = false;
	req->work_scheduled = false;
	req->work_need_resched = false;

	apt.pt._qproc = aio_poll_queue_proc;
	apt.pt._key = req->events;
	apt.iocb = aiocb;
	apt.queued = false;
	apt.error = -EINVAL; /* same as no support for IOCB_CMD_POLL */

	/* initialized the list so that we can do list_empty checks */
	INIT_LIST_HEAD(&req->wait.entry);
	init_waitqueue_func_entry(&req->wait, aio_poll_wake);

	mask = vfs_poll(req->file, &apt.pt) & req->events;
	spin_lock_irq(&ctx->ctx_lock);
	if (likely(apt.queued)) {
		bool on_queue = poll_iocb_lock_wq(req);

		if (!on_queue || req->work_scheduled) {
			/*
			 * aio_poll_wake() already either scheduled the async
			 * completion work, or completed the request inline.
			 */
			if (apt.error) /* unsupported case: multiple queues */
				cancel = true;
			apt.error = 0;
			mask = 0;
		}
		if (mask || apt.error) {
			/* Steal to complete synchronously. */
			list_del_init(&req->wait.entry);
		} else if (cancel) {
			/* Cancel if possible (may be too late though). */
			WRITE_ONCE(req->cancelled, true);
		} else if (on_queue) {
			/*
			 * Actually waiting for an event, so add the request to
			 * active_reqs so that it can be cancelled if needed.
			 */
			list_add_tail(&aiocb->ki_list, &ctx->active_reqs);
			aiocb->ki_cancel = aio_poll_cancel;
		}
		if (on_queue)
			poll_iocb_unlock_wq(req);
	}
	if (mask) { /* no async, we'd stolen it */
		aiocb->ki_res.res = mangle_poll(mask);
		apt.error = 0;
	}
	spin_unlock_irq(&ctx->ctx_lock);
	if (mask)
		iocb_put(aiocb);
	return apt.error;
}

static int __io_submit_one(struct kioctx *ctx, const struct iocb *iocb,
			   struct iocb __user *user_iocb, struct aio_kiocb *req,
			   bool compat)
{
	req->ki_filp = fget(iocb->aio_fildes);
	if (unlikely(!req->ki_filp))
		return -EBADF;

	if (iocb->aio_flags & IOCB_FLAG_RESFD) {
		struct eventfd_ctx *eventfd;
		/*
		 * If the IOCB_FLAG_RESFD flag of aio_flags is set, get an
		 * instance of the file* now. The file descriptor must be
		 * an eventfd() fd, and will be signaled for each completed
		 * event using the eventfd_signal() function.
		 */
		eventfd = eventfd_ctx_fdget(iocb->aio_resfd);
		if (IS_ERR(eventfd))
			return PTR_ERR(eventfd);

		req->ki_eventfd = eventfd;
	}

	if (unlikely(put_user(KIOCB_KEY, &user_iocb->aio_key))) {
		pr_debug("EFAULT: aio_key\n");
		return -EFAULT;
	}

	req->ki_res.obj = (u64)(unsigned long)user_iocb;
	req->ki_res.data = iocb->aio_data;
	req->ki_res.res = 0;
	req->ki_res.res2 = 0;

	switch (iocb->aio_lio_opcode) {
	case IOCB_CMD_PREAD:
		return aio_read(&req->rw, iocb, false, compat);
	case IOCB_CMD_PWRITE:
		return aio_write(&req->rw, iocb, false, compat);
	case IOCB_CMD_PREADV:
		return aio_read(&req->rw, iocb, true, compat);
	case IOCB_CMD_PWRITEV:
		return aio_write(&req->rw, iocb, true, compat);
	case IOCB_CMD_FSYNC:
		return aio_fsync(&req->fsync, iocb, false);
	case IOCB_CMD_FDSYNC:
		return aio_fsync(&req->fsync, iocb, true);
	case IOCB_CMD_POLL:
		return aio_poll(req, iocb);
	default:
		pr_debug("invalid aio operation %d\n", iocb->aio_lio_opcode);
		return -EINVAL;
	}
}

static int io_submit_one(struct kioctx *ctx, struct iocb __user *user_iocb,
			 bool compat)
{
	struct aio_kiocb *req;
	struct iocb iocb;
	int err;

	if (unlikely(copy_from_user(&iocb, user_iocb, sizeof(iocb))))
		return -EFAULT;

	/* enforce forwards compatibility on users */
	if (unlikely(iocb.aio_reserved2)) {
		pr_debug("EINVAL: reserve field set\n");
		return -EINVAL;
	}

	/* prevent overflows */
	if (unlikely(
	    (iocb.aio_buf != (unsigned long)iocb.aio_buf) ||
	    (iocb.aio_nbytes != (size_t)iocb.aio_nbytes) ||
	    ((ssize_t)iocb.aio_nbytes < 0)
	   )) {
		pr_debug("EINVAL: overflow check\n");
		return -EINVAL;
	}

	req = aio_get_req(ctx);
	if (unlikely(!req))
		return -EAGAIN;

	err = __io_submit_one(ctx, &iocb, user_iocb, req, compat);

	/* Done with the synchronous reference */
	iocb_put(req);

	/*
	 * If err is 0, we'd either done aio_complete() ourselves or have
	 * arranged for that to be done asynchronously.  Anything non-zero
	 * means that we need to destroy req ourselves.
	 */
	if (unlikely(err)) {
		iocb_destroy(req);
		put_reqs_available(ctx, 1);
	}
	return err;
}

/**
 * sys_io_submit - Submit asynchronous I/O operations for processing
 * @ctx_id: AIO context handle returned by io_setup
 * @nr: Number of I/O control blocks to submit
 * @iocbpp: Array of pointers to iocb structures describing the operations
 *
 * long-desc: Submits one or more asynchronous I/O operations for processing
 *   against a previously created AIO context. Each iocb structure describes
 *   a single I/O operation including the operation type, file descriptor,
 *   buffer, size, and offset.
 *
 *   The syscall processes iocbs sequentially from the array. If an error
 *   occurs while processing an iocb, submission stops at that point and
 *   the number of successfully submitted operations is returned. This means
 *   partial submission is possible: if submitting 10 iocbs and the 5th fails,
 *   4 is returned and iocbs 0-3 are queued for processing.
 *
 *   Supported operations (specified via aio_lio_opcode):
 *   - IOCB_CMD_PREAD (0): Positioned read from file
 *   - IOCB_CMD_PWRITE (1): Positioned write to file
 *   - IOCB_CMD_FSYNC (2): Sync file data and metadata
 *   - IOCB_CMD_FDSYNC (3): Sync file data only
 *   - IOCB_CMD_POLL (5): Poll for events on file descriptor
 *   - IOCB_CMD_NOOP (6): No operation (useful for testing)
 *   - IOCB_CMD_PREADV (7): Positioned scatter read
 *   - IOCB_CMD_PWRITEV (8): Positioned gather write
 *
 *   The iocb structure fields include:
 *   - aio_data: User data copied to io_event on completion
 *   - aio_lio_opcode: Operation type (one of IOCB_CMD_*)
 *   - aio_fildes: File descriptor for the operation
 *   - aio_buf: Buffer address (or iovec array for vectored ops)
 *   - aio_nbytes: Buffer size (or iovec count for vectored ops)
 *   - aio_offset: File offset for positioned operations
 *   - aio_flags: Optional flags (IOCB_FLAG_RESFD, IOCB_FLAG_IOPRIO)
 *   - aio_resfd: eventfd to signal on completion (if IOCB_FLAG_RESFD set)
 *   - aio_rw_flags: Per-operation RWF_* flags
 *   - aio_reqprio: I/O priority (if IOCB_FLAG_IOPRIO set)
 *
 *   After successful submission, operations complete asynchronously. Results
 *   are delivered to the completion ring buffer and can be retrieved via
 *   io_getevents(). If aio_resfd specifies a valid eventfd, it is signaled
 *   when each operation completes.
 *
 *   The actual I/O may complete synchronously if the data is cached or if
 *   the underlying filesystem doesn't support truly asynchronous I/O. In
 *   such cases, the operation is still reported via the completion ring.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: ctx_id
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid AIO context handle previously returned by
 *     io_setup() for the current process. The context must not have been
 *     destroyed. A value of 0 is always invalid. The handle is actually
 *     the virtual address of the ring buffer mapping.
 *
 * param: nr
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, LONG_MAX
 *   constraint: Must be >= 0. If 0, the syscall returns immediately with 0.
 *     The actual number processed is capped to ctx->nr_events (the context's
 *     capacity). Very large values are effectively limited by the context
 *     capacity and available ring buffer slots.
 *
 * param: iocbpp
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid userspace pointer to an array of nr pointers
 *     to struct iocb. Each iocb pointer must itself be valid and point to a
 *     properly initialized iocb structure. The iocb structures must have
 *     aio_reserved2 set to 0 for forward compatibility.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: >= 0
 *   desc: Returns the number of iocbs successfully submitted (0 to nr). If
 *     partial submission occurs due to an error, returns the count of
 *     successfully submitted operations. Returns 0 if nr is 0.
 *
 * error: EINVAL, Invalid context or parameter
 *   desc: Returned if ctx_id is invalid, nr is negative, aio_reserved2 is
 *     non-zero, aio_lio_opcode is invalid, aio_buf/aio_nbytes overflow,
 *     aio_resfd is not an eventfd, conflicting aio_rw_flags, file lacks
 *     required operation support, invalid POLL/FSYNC parameters, or
 *     invalid aio_reqprio class.
 *
 * error: EFAULT, Invalid memory access
 *   desc: Returned if: (1) iocbpp is not a valid userspace pointer, (2) any
 *     pointer in the iocbpp array is invalid, (3) the iocb data cannot be
 *     copied from userspace, (4) aio_buf points to invalid memory, or
 *     (5) the kernel cannot write the aio_key field back to userspace.
 *
 * error: EBADF, Bad file descriptor
 *   desc: Returned if: (1) aio_fildes in an iocb does not refer to an open
 *     file, (2) aio_resfd does not refer to a valid file descriptor when
 *     IOCB_FLAG_RESFD is set, (3) the file is not opened with appropriate
 *     mode for the operation (e.g., read on write-only file).
 *
 * error: EAGAIN, Resource temporarily unavailable
 *   desc: Returned if insufficient slots are available in the completion
 *     ring buffer. This typically means too many operations are already
 *     in flight and the application should call io_getevents() to consume
 *     completed events before submitting more.
 *
 * error: EPERM, Operation not permitted
 *   desc: Returned if: (1) IOCB_FLAG_IOPRIO is set and aio_reqprio specifies
 *     IOPRIO_CLASS_RT (real-time I/O priority) but the process lacks
 *     CAP_SYS_ADMIN or CAP_SYS_NICE capability, or (2) RWF_NOAPPEND is
 *     specified but the file has the append-only attribute (IS_APPEND).
 *
 * error: EOPNOTSUPP, Operation not supported
 *   desc: Returned if: (1) unsupported aio_rw_flags are specified, (2)
 *     RWF_NOWAIT is specified but the file doesn't support non-blocking I/O
 *     (FMODE_NOWAIT not set), (3) RWF_ATOMIC is specified for a read or
 *     the file doesn't support atomic writes, or (4) RWF_DONTCACHE is
 *     specified but not supported by the filesystem or file is DAX-mapped.
 *
 * error: EOVERFLOW, Value too large
 *   desc: Returned if aio_offset plus aio_nbytes would overflow and the
 *     file does not support unsigned offsets. This check prevents reading
 *     or writing past the maximum representable file position.
 *
 * error: ENOMEM, Out of memory
 *   desc: Returned if memory allocation fails when preparing credentials
 *     for IOCB_CMD_FSYNC operations, or if vectored I/O (preadv/pwritev)
 *     requires allocating iovec arrays larger than the stack buffer.
 *
 * lock: RCU read lock
 *   type: KAPI_LOCK_RCU
 *   desc: Acquired during context lookup in lookup_ioctx(). Protects against
 *     concurrent modification of the ioctx_table while looking up the
 *     context. Released before processing any iocbs.
 *
 * lock: ctx->completion_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   desc: Per-context spinlock acquired briefly during request slot allocation
 *     via user_refill_reqs_available() if the percpu request counter is empty.
 *     Protects the ring buffer tail and completed_events counters.
 *
 * lock: ctx->ctx_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   desc: Per-context spinlock acquired when adding cancellable requests to
 *     the active_reqs list. This enables io_cancel() to find and cancel
 *     in-flight operations.
 *
 * lock: blk_plug
 *   type: KAPI_LOCK_CUSTOM
 *   desc: Block layer plugging is enabled when nr > 2 (AIO_PLUG_THRESHOLD)
 *     to batch block I/O requests for better performance. This is not a
 *     traditional lock but affects I/O scheduling.
 *
 * signal: any
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_TRANSFORM
 *   condition: Signal arrives during underlying read/write operation
 *   desc: If a signal arrives during the underlying file read/write operation
 *     and the operation returns ERESTARTSYS/ERESTARTNOINTR/etc., the error
 *     is transformed to EINTR for the completion event. AIO operations cannot
 *     be restarted in the traditional sense because other operations may have
 *     already been submitted. The syscall itself (io_submit) is NOT interrupted
 *     by signals - only the individual async operations can be.
 *   error: -EINTR (in io_event.res, not syscall return)
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: aio_kiocb structures
 *   desc: Allocates one aio_kiocb structure per submitted operation from the
 *     kiocb_cachep slab cache. These structures track the in-flight operations
 *     and are freed after completion is recorded in the ring buffer.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: AIO context request counters
 *   desc: Decrements the available request slot counter in the context.
 *     Slots are reclaimed when completion events are consumed from the ring
 *     buffer via io_getevents().
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: ctx->active_reqs list
 *   desc: Cancellable operations (reads, writes, polls) are added to the
 *     context's active_reqs list, enabling cancellation via io_cancel().
 *   condition: Operation supports cancellation
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: iocb->aio_key field
 *   desc: The kernel writes KIOCB_KEY (0) to the aio_key field of each
 *     submitted iocb in userspace memory. This marks the iocb as submitted
 *     and is checked by io_cancel() to validate the iocb.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: file reference count
 *   desc: Increments the reference count of the file descriptor's struct file
 *     via fget() for each submitted operation. The reference is released
 *     when the operation completes (via fput() in iocb_destroy()).
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: target file(s)
 *   desc: For write operations, the file content may be modified. For fsync
 *     operations, dirty data is flushed to storage. The actual I/O may
 *     complete synchronously or asynchronously depending on the filesystem.
 *   condition: IOCB_CMD_PWRITE, IOCB_CMD_PWRITEV, IOCB_CMD_FSYNC, IOCB_CMD_FDSYNC
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: fsync work queue
 *   desc: FSYNC and FDSYNC operations are scheduled to run on a workqueue
 *     because vfs_fsync() can block. The operation runs asynchronously and
 *     completion is signaled via the ring buffer.
 *   condition: IOCB_CMD_FSYNC or IOCB_CMD_FDSYNC
 *   reversible: no
 *
 * state-trans: iocb state
 *   from: user-prepared iocb
 *   to: submitted (aio_key set to KIOCB_KEY)
 *   condition: successful submission of each iocb
 *   desc: Each successfully submitted iocb transitions from user-prepared
 *     state to submitted state, marked by the kernel writing KIOCB_KEY to
 *     aio_key. The iocb remains in submitted state until completion.
 *
 * state-trans: AIO context slot availability
 *   from: slots_available = N
 *   to: slots_available = N - submitted_count
 *   condition: successful submission
 *   desc: Available slots in the context decrease by the number of successfully
 *     submitted operations. Slots are reclaimed when io_getevents() consumes
 *     completion events.
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Use of IOPRIO_CLASS_RT (real-time I/O priority class)
 *   without: Returns EPERM when attempting to use RT I/O priority
 *   condition: IOCB_FLAG_IOPRIO set and aio_reqprio specifies IOPRIO_CLASS_RT
 *
 * capability: CAP_SYS_NICE
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Use of IOPRIO_CLASS_RT (alternative to CAP_SYS_ADMIN)
 *   without: Returns EPERM when attempting to use RT I/O priority
 *   condition: IOCB_FLAG_IOPRIO set and aio_reqprio specifies IOPRIO_CLASS_RT
 *
 * constraint: Ring buffer slot availability
 *   desc: There must be available slots in the completion ring buffer for
 *     each operation to be submitted. If all slots are occupied by pending
 *     completion events, submission fails with EAGAIN. The number of slots
 *     is determined by nr_events passed to io_setup(), though internal
 *     doubling means more slots may be available.
 *   expr: available_slots >= 1 for each submission
 *
 * constraint: Valid file descriptor per iocb
 *   desc: Each iocb must reference a valid, open file descriptor via
 *     aio_fildes. The file must be opened with appropriate access mode
 *     for the requested operation (read access for PREAD, write access
 *     for PWRITE, etc.).
 *
 * constraint: File must support operation
 *   desc: For read/write operations, the underlying file must implement
 *     read_iter/write_iter file operations. For fsync, the file must
 *     implement fsync. For poll, the file must support vfs_poll().
 *
 * constraint: CONFIG_AIO required
 *   desc: The kernel must be compiled with CONFIG_AIO=y for this syscall
 *     to be available. If not configured, returns -ENOSYS.
 *
 * examples: struct iocb iocb, *iocbp = &iocb; io_submit(ctx, 1, &iocbp);
 *   struct iocb iocbs[10], *ptrs[10]; io_submit(ctx, 10, ptrs);  // Batch submit
 *
 * notes: Unlike traditional synchronous I/O, errors from io_submit() indicate
 *   submission failures, not I/O errors. Actual I/O errors are reported via
 *   the res field of struct io_event when retrieved via io_getevents().
 *
 *   The return value indicates how many iocbs were successfully submitted.
 *   If this is less than nr, the application should check which operation
 *   failed (it's the one at index = return_value) and handle the error.
 *   Previously submitted operations in the batch are still queued.
 *
 *   For vectored operations (PREADV/PWRITEV), aio_buf points to an array
 *   of struct iovec and aio_nbytes contains the iovec count. The maximum
 *   iovec count is UIO_MAXIOV (1024).
 *
 *   Block layer plugging is automatically enabled for batches larger than
 *   2 operations, improving I/O merging and reducing per-I/O overhead.
 *
 *   The COMPAT_SYSCALL variant handles 32-bit userspace on 64-bit kernels,
 *   using compat_uptr_t for the iocbpp array elements.
 *
 *   Historical note: commit d6b2615f7d31d ("aio: simplify - and fix - fget/fput
 *   for io_submit()") fixed file descriptor reference counting issues. Earlier
 *   kernels could leak file references on certain error paths.
 *
 *   io_uring (since Linux 5.1) is a more modern and performant alternative.
 *   Consider using io_uring_enter() for new applications requiring async I/O.
 *
 *   There is no glibc wrapper; use syscall(SYS_io_submit, ...) or the libaio
 *   library. The libaio wrapper io_submit() returns negative error numbers
 *   directly rather than returning -1 and setting errno.
 *
 * since-version: 2.5
 */
SYSCALL_DEFINE3(io_submit, aio_context_t, ctx_id, long, nr,
		struct iocb __user * __user *, iocbpp)
{
	struct kioctx *ctx;
	long ret = 0;
	int i = 0;
	struct blk_plug plug;

	if (unlikely(nr < 0))
		return -EINVAL;

	ctx = lookup_ioctx(ctx_id);
	if (unlikely(!ctx)) {
		pr_debug("EINVAL: invalid context id\n");
		return -EINVAL;
	}

	if (nr > ctx->nr_events)
		nr = ctx->nr_events;

	if (nr > AIO_PLUG_THRESHOLD)
		blk_start_plug(&plug);
	for (i = 0; i < nr; i++) {
		struct iocb __user *user_iocb;

		if (unlikely(get_user(user_iocb, iocbpp + i))) {
			ret = -EFAULT;
			break;
		}

		ret = io_submit_one(ctx, user_iocb, false);
		if (ret)
			break;
	}
	if (nr > AIO_PLUG_THRESHOLD)
		blk_finish_plug(&plug);

	percpu_ref_put(&ctx->users);
	return i ? i : ret;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE3(io_submit, compat_aio_context_t, ctx_id,
		       int, nr, compat_uptr_t __user *, iocbpp)
{
	struct kioctx *ctx;
	long ret = 0;
	int i = 0;
	struct blk_plug plug;

	if (unlikely(nr < 0))
		return -EINVAL;

	ctx = lookup_ioctx(ctx_id);
	if (unlikely(!ctx)) {
		pr_debug("EINVAL: invalid context id\n");
		return -EINVAL;
	}

	if (nr > ctx->nr_events)
		nr = ctx->nr_events;

	if (nr > AIO_PLUG_THRESHOLD)
		blk_start_plug(&plug);
	for (i = 0; i < nr; i++) {
		compat_uptr_t user_iocb;

		if (unlikely(get_user(user_iocb, iocbpp + i))) {
			ret = -EFAULT;
			break;
		}

		ret = io_submit_one(ctx, compat_ptr(user_iocb), true);
		if (ret)
			break;
	}
	if (nr > AIO_PLUG_THRESHOLD)
		blk_finish_plug(&plug);

	percpu_ref_put(&ctx->users);
	return i ? i : ret;
}
#endif

/* sys_io_cancel:
 *	Attempts to cancel an iocb previously passed to io_submit.  If
 *	the operation is successfully cancelled, the resulting event is
 *	copied into the memory pointed to by result without being placed
 *	into the completion queue and 0 is returned.  May fail with
 *	-EFAULT if any of the data structures pointed to are invalid.
 *	May fail with -EINVAL if aio_context specified by ctx_id is
 *	invalid.  May fail with -EAGAIN if the iocb specified was not
 *	cancelled.  Will fail with -ENOSYS if not implemented.
 */
SYSCALL_DEFINE3(io_cancel, aio_context_t, ctx_id, struct iocb __user *, iocb,
		struct io_event __user *, result)
{
	struct kioctx *ctx;
	struct aio_kiocb *kiocb;
	int ret = -EINVAL;
	u32 key;
	u64 obj = (u64)(unsigned long)iocb;

	if (unlikely(get_user(key, &iocb->aio_key)))
		return -EFAULT;
	if (unlikely(key != KIOCB_KEY))
		return -EINVAL;

	ctx = lookup_ioctx(ctx_id);
	if (unlikely(!ctx))
		return -EINVAL;

	spin_lock_irq(&ctx->ctx_lock);
	list_for_each_entry(kiocb, &ctx->active_reqs, ki_list) {
		if (kiocb->ki_res.obj == obj) {
			ret = kiocb->ki_cancel(&kiocb->rw);
			list_del_init(&kiocb->ki_list);
			break;
		}
	}
	spin_unlock_irq(&ctx->ctx_lock);

	if (!ret) {
		/*
		 * The result argument is no longer used - the io_event is
		 * always delivered via the ring buffer. -EINPROGRESS indicates
		 * cancellation is progress:
		 */
		ret = -EINPROGRESS;
	}

	percpu_ref_put(&ctx->users);

	return ret;
}

static long do_io_getevents(aio_context_t ctx_id,
		long min_nr,
		long nr,
		struct io_event __user *events,
		struct timespec64 *ts)
{
	ktime_t until = ts ? timespec64_to_ktime(*ts) : KTIME_MAX;
	struct kioctx *ioctx = lookup_ioctx(ctx_id);
	long ret = -EINVAL;

	if (likely(ioctx)) {
		if (likely(min_nr <= nr && min_nr >= 0))
			ret = read_events(ioctx, min_nr, nr, events, until);
		percpu_ref_put(&ioctx->users);
	}

	return ret;
}

/* io_getevents:
 *	Attempts to read at least min_nr events and up to nr events from
 *	the completion queue for the aio_context specified by ctx_id. If
 *	it succeeds, the number of read events is returned. May fail with
 *	-EINVAL if ctx_id is invalid, if min_nr is out of range, if nr is
 *	out of range, if timeout is out of range.  May fail with -EFAULT
 *	if any of the memory specified is invalid.  May return 0 or
 *	< min_nr if the timeout specified by timeout has elapsed
 *	before sufficient events are available, where timeout == NULL
 *	specifies an infinite timeout. Note that the timeout pointed to by
 *	timeout is relative.  Will fail with -ENOSYS if not implemented.
 */
#ifdef CONFIG_64BIT

SYSCALL_DEFINE5(io_getevents, aio_context_t, ctx_id,
		long, min_nr,
		long, nr,
		struct io_event __user *, events,
		struct __kernel_timespec __user *, timeout)
{
	struct timespec64	ts;
	int			ret;

	if (timeout && unlikely(get_timespec64(&ts, timeout)))
		return -EFAULT;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &ts : NULL);
	if (!ret && signal_pending(current))
		ret = -EINTR;
	return ret;
}

#endif

struct __aio_sigset {
	const sigset_t __user	*sigmask;
	size_t		sigsetsize;
};

SYSCALL_DEFINE6(io_pgetevents,
		aio_context_t, ctx_id,
		long, min_nr,
		long, nr,
		struct io_event __user *, events,
		struct __kernel_timespec __user *, timeout,
		const struct __aio_sigset __user *, usig)
{
	struct __aio_sigset	ksig = { NULL, };
	struct timespec64	ts;
	bool interrupted;
	int ret;

	if (timeout && unlikely(get_timespec64(&ts, timeout)))
		return -EFAULT;

	if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
		return -EFAULT;

	ret = set_user_sigmask(ksig.sigmask, ksig.sigsetsize);
	if (ret)
		return ret;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &ts : NULL);

	interrupted = signal_pending(current);
	restore_saved_sigmask_unless(interrupted);
	if (interrupted && !ret)
		ret = -ERESTARTNOHAND;

	return ret;
}

#if defined(CONFIG_COMPAT_32BIT_TIME) && !defined(CONFIG_64BIT)

SYSCALL_DEFINE6(io_pgetevents_time32,
		aio_context_t, ctx_id,
		long, min_nr,
		long, nr,
		struct io_event __user *, events,
		struct old_timespec32 __user *, timeout,
		const struct __aio_sigset __user *, usig)
{
	struct __aio_sigset	ksig = { NULL, };
	struct timespec64	ts;
	bool interrupted;
	int ret;

	if (timeout && unlikely(get_old_timespec32(&ts, timeout)))
		return -EFAULT;

	if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
		return -EFAULT;


	ret = set_user_sigmask(ksig.sigmask, ksig.sigsetsize);
	if (ret)
		return ret;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &ts : NULL);

	interrupted = signal_pending(current);
	restore_saved_sigmask_unless(interrupted);
	if (interrupted && !ret)
		ret = -ERESTARTNOHAND;

	return ret;
}

#endif

#if defined(CONFIG_COMPAT_32BIT_TIME)

SYSCALL_DEFINE5(io_getevents_time32, __u32, ctx_id,
		__s32, min_nr,
		__s32, nr,
		struct io_event __user *, events,
		struct old_timespec32 __user *, timeout)
{
	struct timespec64 t;
	int ret;

	if (timeout && get_old_timespec32(&t, timeout))
		return -EFAULT;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &t : NULL);
	if (!ret && signal_pending(current))
		ret = -EINTR;
	return ret;
}

#endif

#ifdef CONFIG_COMPAT

struct __compat_aio_sigset {
	compat_uptr_t		sigmask;
	compat_size_t		sigsetsize;
};

#if defined(CONFIG_COMPAT_32BIT_TIME)

COMPAT_SYSCALL_DEFINE6(io_pgetevents,
		compat_aio_context_t, ctx_id,
		compat_long_t, min_nr,
		compat_long_t, nr,
		struct io_event __user *, events,
		struct old_timespec32 __user *, timeout,
		const struct __compat_aio_sigset __user *, usig)
{
	struct __compat_aio_sigset ksig = { 0, };
	struct timespec64 t;
	bool interrupted;
	int ret;

	if (timeout && get_old_timespec32(&t, timeout))
		return -EFAULT;

	if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
		return -EFAULT;

	ret = set_compat_user_sigmask(compat_ptr(ksig.sigmask), ksig.sigsetsize);
	if (ret)
		return ret;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &t : NULL);

	interrupted = signal_pending(current);
	restore_saved_sigmask_unless(interrupted);
	if (interrupted && !ret)
		ret = -ERESTARTNOHAND;

	return ret;
}

#endif

COMPAT_SYSCALL_DEFINE6(io_pgetevents_time64,
		compat_aio_context_t, ctx_id,
		compat_long_t, min_nr,
		compat_long_t, nr,
		struct io_event __user *, events,
		struct __kernel_timespec __user *, timeout,
		const struct __compat_aio_sigset __user *, usig)
{
	struct __compat_aio_sigset ksig = { 0, };
	struct timespec64 t;
	bool interrupted;
	int ret;

	if (timeout && get_timespec64(&t, timeout))
		return -EFAULT;

	if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
		return -EFAULT;

	ret = set_compat_user_sigmask(compat_ptr(ksig.sigmask), ksig.sigsetsize);
	if (ret)
		return ret;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &t : NULL);

	interrupted = signal_pending(current);
	restore_saved_sigmask_unless(interrupted);
	if (interrupted && !ret)
		ret = -ERESTARTNOHAND;

	return ret;
}
#endif
