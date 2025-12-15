// SPDX-License-Identifier: GPL-2.0-only
/*
 * "splice": joining two ropes together by interweaving their strands.
 *
 * This is the "extended pipe" functionality, where a pipe is used as
 * an arbitrary in-memory buffer. Think of a pipe as a small kernel
 * buffer that you can use to transfer data from one end to the other.
 *
 * The traditional unix read/write is extended with a "splice()" operation
 * that transfers data buffers to or from a pipe buffer.
 *
 * Named by Larry McVoy, original implementation from Linus, extended by
 * Jens to support splicing to files, network, direct splicing, etc and
 * fixing lots of bugs.
 *
 * Copyright (C) 2005-2006 Jens Axboe <axboe@kernel.dk>
 * Copyright (C) 2005-2006 Linus Torvalds <torvalds@osdl.org>
 * Copyright (C) 2006 Ingo Molnar <mingo@elte.hu>
 *
 */
#include <linux/bvec.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/splice.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/uio.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/gfp.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sched/signal.h>

#include "internal.h"

/*
 * Splice doesn't support FMODE_NOWAIT. Since pipes may set this flag to
 * indicate they support non-blocking reads or writes, we must clear it
 * here if set to avoid blocking other users of this pipe if splice is
 * being done on it.
 */
static noinline void pipe_clear_nowait(struct file *file)
{
	fmode_t fmode = READ_ONCE(file->f_mode);

	do {
		if (!(fmode & FMODE_NOWAIT))
			break;
	} while (!try_cmpxchg(&file->f_mode, &fmode, fmode & ~FMODE_NOWAIT));
}

/*
 * Attempt to steal a page from a pipe buffer. This should perhaps go into
 * a vm helper function, it's already simplified quite a bit by the
 * addition of remove_mapping(). If success is returned, the caller may
 * attempt to reuse this page for another destination.
 */
static bool page_cache_pipe_buf_try_steal(struct pipe_inode_info *pipe,
		struct pipe_buffer *buf)
{
	struct folio *folio = page_folio(buf->page);
	struct address_space *mapping;

	folio_lock(folio);

	mapping = folio_mapping(folio);
	if (mapping) {
		WARN_ON(!folio_test_uptodate(folio));

		/*
		 * At least for ext2 with nobh option, we need to wait on
		 * writeback completing on this folio, since we'll remove it
		 * from the pagecache.  Otherwise truncate wont wait on the
		 * folio, allowing the disk blocks to be reused by someone else
		 * before we actually wrote our data to them. fs corruption
		 * ensues.
		 */
		folio_wait_writeback(folio);

		if (!filemap_release_folio(folio, GFP_KERNEL))
			goto out_unlock;

		/*
		 * If we succeeded in removing the mapping, set LRU flag
		 * and return good.
		 */
		if (remove_mapping(mapping, folio)) {
			buf->flags |= PIPE_BUF_FLAG_LRU;
			return true;
		}
	}

	/*
	 * Raced with truncate or failed to remove folio from current
	 * address space, unlock and return failure.
	 */
out_unlock:
	folio_unlock(folio);
	return false;
}

static void page_cache_pipe_buf_release(struct pipe_inode_info *pipe,
					struct pipe_buffer *buf)
{
	put_page(buf->page);
	buf->flags &= ~PIPE_BUF_FLAG_LRU;
}

/*
 * Check whether the contents of buf is OK to access. Since the content
 * is a page cache page, IO may be in flight.
 */
static int page_cache_pipe_buf_confirm(struct pipe_inode_info *pipe,
				       struct pipe_buffer *buf)
{
	struct folio *folio = page_folio(buf->page);
	int err;

	if (!folio_test_uptodate(folio)) {
		folio_lock(folio);

		/*
		 * Folio got truncated/unhashed. This will cause a 0-byte
		 * splice, if this is the first page.
		 */
		if (!folio->mapping) {
			err = -ENODATA;
			goto error;
		}

		/*
		 * Uh oh, read-error from disk.
		 */
		if (!folio_test_uptodate(folio)) {
			err = -EIO;
			goto error;
		}

		/* Folio is ok after all, we are done */
		folio_unlock(folio);
	}

	return 0;
error:
	folio_unlock(folio);
	return err;
}

const struct pipe_buf_operations page_cache_pipe_buf_ops = {
	.confirm	= page_cache_pipe_buf_confirm,
	.release	= page_cache_pipe_buf_release,
	.try_steal	= page_cache_pipe_buf_try_steal,
	.get		= generic_pipe_buf_get,
};

static bool user_page_pipe_buf_try_steal(struct pipe_inode_info *pipe,
		struct pipe_buffer *buf)
{
	if (!(buf->flags & PIPE_BUF_FLAG_GIFT))
		return false;

	buf->flags |= PIPE_BUF_FLAG_LRU;
	return generic_pipe_buf_try_steal(pipe, buf);
}

static const struct pipe_buf_operations user_page_pipe_buf_ops = {
	.release	= page_cache_pipe_buf_release,
	.try_steal	= user_page_pipe_buf_try_steal,
	.get		= generic_pipe_buf_get,
};

static void wakeup_pipe_readers(struct pipe_inode_info *pipe)
{
	smp_mb();
	if (waitqueue_active(&pipe->rd_wait))
		wake_up_interruptible(&pipe->rd_wait);
	kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
}

/**
 * splice_to_pipe - fill passed data into a pipe
 * @pipe:	pipe to fill
 * @spd:	data to fill
 *
 * Description:
 *    @spd contains a map of pages and len/offset tuples, along with
 *    the struct pipe_buf_operations associated with these pages. This
 *    function will link that data to the pipe.
 *
 */
ssize_t splice_to_pipe(struct pipe_inode_info *pipe,
		       struct splice_pipe_desc *spd)
{
	unsigned int spd_pages = spd->nr_pages;
	unsigned int tail = pipe->tail;
	unsigned int head = pipe->head;
	ssize_t ret = 0;
	int page_nr = 0;

	if (!spd_pages)
		return 0;

	if (unlikely(!pipe->readers)) {
		send_sig(SIGPIPE, current, 0);
		ret = -EPIPE;
		goto out;
	}

	while (!pipe_full(head, tail, pipe->max_usage)) {
		struct pipe_buffer *buf = pipe_buf(pipe, head);

		buf->page = spd->pages[page_nr];
		buf->offset = spd->partial[page_nr].offset;
		buf->len = spd->partial[page_nr].len;
		buf->private = spd->partial[page_nr].private;
		buf->ops = spd->ops;
		buf->flags = 0;

		head++;
		pipe->head = head;
		page_nr++;
		ret += buf->len;

		if (!--spd->nr_pages)
			break;
	}

	if (!ret)
		ret = -EAGAIN;

out:
	while (page_nr < spd_pages)
		spd->spd_release(spd, page_nr++);

	return ret;
}
EXPORT_SYMBOL_GPL(splice_to_pipe);

ssize_t add_to_pipe(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
{
	unsigned int head = pipe->head;
	unsigned int tail = pipe->tail;
	int ret;

	if (unlikely(!pipe->readers)) {
		send_sig(SIGPIPE, current, 0);
		ret = -EPIPE;
	} else if (pipe_full(head, tail, pipe->max_usage)) {
		ret = -EAGAIN;
	} else {
		*pipe_buf(pipe, head) = *buf;
		pipe->head = head + 1;
		return buf->len;
	}
	pipe_buf_release(pipe, buf);
	return ret;
}
EXPORT_SYMBOL(add_to_pipe);

/*
 * Check if we need to grow the arrays holding pages and partial page
 * descriptions.
 */
int splice_grow_spd(const struct pipe_inode_info *pipe, struct splice_pipe_desc *spd)
{
	unsigned int max_usage = READ_ONCE(pipe->max_usage);

	spd->nr_pages_max = max_usage;
	if (max_usage <= PIPE_DEF_BUFFERS)
		return 0;

	spd->pages = kmalloc_array(max_usage, sizeof(struct page *), GFP_KERNEL);
	spd->partial = kmalloc_array(max_usage, sizeof(struct partial_page),
				     GFP_KERNEL);

	if (spd->pages && spd->partial)
		return 0;

	kfree(spd->pages);
	kfree(spd->partial);
	return -ENOMEM;
}

void splice_shrink_spd(struct splice_pipe_desc *spd)
{
	if (spd->nr_pages_max <= PIPE_DEF_BUFFERS)
		return;

	kfree(spd->pages);
	kfree(spd->partial);
}

/**
 * copy_splice_read -  Copy data from a file and splice the copy into a pipe
 * @in: The file to read from
 * @ppos: Pointer to the file position to read from
 * @pipe: The pipe to splice into
 * @len: The amount to splice
 * @flags: The SPLICE_F_* flags
 *
 * This function allocates a bunch of pages sufficient to hold the requested
 * amount of data (but limited by the remaining pipe capacity), passes it to
 * the file's ->read_iter() to read into and then splices the used pages into
 * the pipe.
 *
 * Return: On success, the number of bytes read will be returned and *@ppos
 * will be updated if appropriate; 0 will be returned if there is no more data
 * to be read; -EAGAIN will be returned if the pipe had no space, and some
 * other negative error code will be returned on error.  A short read may occur
 * if the pipe has insufficient space, we reach the end of the data or we hit a
 * hole.
 */
ssize_t copy_splice_read(struct file *in, loff_t *ppos,
			 struct pipe_inode_info *pipe,
			 size_t len, unsigned int flags)
{
	struct iov_iter to;
	struct bio_vec *bv;
	struct kiocb kiocb;
	struct page **pages;
	ssize_t ret;
	size_t used, npages, chunk, remain, keep = 0;
	int i;

	/* Work out how much data we can actually add into the pipe */
	used = pipe_buf_usage(pipe);
	npages = max_t(ssize_t, pipe->max_usage - used, 0);
	len = min_t(size_t, len, npages * PAGE_SIZE);
	npages = DIV_ROUND_UP(len, PAGE_SIZE);

	bv = kzalloc(array_size(npages, sizeof(bv[0])) +
		     array_size(npages, sizeof(struct page *)), GFP_KERNEL);
	if (!bv)
		return -ENOMEM;

	pages = (struct page **)(bv + npages);
	npages = alloc_pages_bulk(GFP_USER, npages, pages);
	if (!npages) {
		kfree(bv);
		return -ENOMEM;
	}

	remain = len = min_t(size_t, len, npages * PAGE_SIZE);

	for (i = 0; i < npages; i++) {
		chunk = min_t(size_t, PAGE_SIZE, remain);
		bv[i].bv_page = pages[i];
		bv[i].bv_offset = 0;
		bv[i].bv_len = chunk;
		remain -= chunk;
	}

	/* Do the I/O */
	iov_iter_bvec(&to, ITER_DEST, bv, npages, len);
	init_sync_kiocb(&kiocb, in);
	kiocb.ki_pos = *ppos;
	ret = in->f_op->read_iter(&kiocb, &to);

	if (ret > 0) {
		keep = DIV_ROUND_UP(ret, PAGE_SIZE);
		*ppos = kiocb.ki_pos;
	}

	/*
	 * Callers of ->splice_read() expect -EAGAIN on "can't put anything in
	 * there", rather than -EFAULT.
	 */
	if (ret == -EFAULT)
		ret = -EAGAIN;

	/* Free any pages that didn't get touched at all. */
	if (keep < npages)
		release_pages(pages + keep, npages - keep);

	/* Push the remaining pages into the pipe. */
	remain = ret;
	for (i = 0; i < keep; i++) {
		struct pipe_buffer *buf = pipe_head_buf(pipe);

		chunk = min_t(size_t, remain, PAGE_SIZE);
		*buf = (struct pipe_buffer) {
			.ops	= &default_pipe_buf_ops,
			.page	= bv[i].bv_page,
			.offset	= 0,
			.len	= chunk,
		};
		pipe->head++;
		remain -= chunk;
	}

	kfree(bv);
	return ret;
}
EXPORT_SYMBOL(copy_splice_read);

const struct pipe_buf_operations default_pipe_buf_ops = {
	.release	= generic_pipe_buf_release,
	.try_steal	= generic_pipe_buf_try_steal,
	.get		= generic_pipe_buf_get,
};

/* Pipe buffer operations for a socket and similar. */
const struct pipe_buf_operations nosteal_pipe_buf_ops = {
	.release	= generic_pipe_buf_release,
	.get		= generic_pipe_buf_get,
};
EXPORT_SYMBOL(nosteal_pipe_buf_ops);

static void wakeup_pipe_writers(struct pipe_inode_info *pipe)
{
	smp_mb();
	if (waitqueue_active(&pipe->wr_wait))
		wake_up_interruptible(&pipe->wr_wait);
	kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
}

/**
 * splice_from_pipe_feed - feed available data from a pipe to a file
 * @pipe:	pipe to splice from
 * @sd:		information to @actor
 * @actor:	handler that splices the data
 *
 * Description:
 *    This function loops over the pipe and calls @actor to do the
 *    actual moving of a single struct pipe_buffer to the desired
 *    destination.  It returns when there's no more buffers left in
 *    the pipe or if the requested number of bytes (@sd->total_len)
 *    have been copied.  It returns a positive number (one) if the
 *    pipe needs to be filled with more data, zero if the required
 *    number of bytes have been copied and -errno on error.
 *
 *    This, together with splice_from_pipe_{begin,end,next}, may be
 *    used to implement the functionality of __splice_from_pipe() when
 *    locking is required around copying the pipe buffers to the
 *    destination.
 */
static int splice_from_pipe_feed(struct pipe_inode_info *pipe, struct splice_desc *sd,
			  splice_actor *actor)
{
	unsigned int head = pipe->head;
	unsigned int tail = pipe->tail;
	int ret;

	while (!pipe_empty(head, tail)) {
		struct pipe_buffer *buf = pipe_buf(pipe, tail);

		sd->len = buf->len;
		if (sd->len > sd->total_len)
			sd->len = sd->total_len;

		ret = pipe_buf_confirm(pipe, buf);
		if (unlikely(ret)) {
			if (ret == -ENODATA)
				ret = 0;
			return ret;
		}

		ret = actor(pipe, buf, sd);
		if (ret <= 0)
			return ret;

		buf->offset += ret;
		buf->len -= ret;

		sd->num_spliced += ret;
		sd->len -= ret;
		sd->pos += ret;
		sd->total_len -= ret;

		if (!buf->len) {
			pipe_buf_release(pipe, buf);
			tail++;
			pipe->tail = tail;
			if (pipe->files)
				sd->need_wakeup = true;
		}

		if (!sd->total_len)
			return 0;
	}

	return 1;
}

/* We know we have a pipe buffer, but maybe it's empty? */
static inline bool eat_empty_buffer(struct pipe_inode_info *pipe)
{
	unsigned int tail = pipe->tail;
	struct pipe_buffer *buf = pipe_buf(pipe, tail);

	if (unlikely(!buf->len)) {
		pipe_buf_release(pipe, buf);
		pipe->tail = tail+1;
		return true;
	}

	return false;
}

/**
 * splice_from_pipe_next - wait for some data to splice from
 * @pipe:	pipe to splice from
 * @sd:		information about the splice operation
 *
 * Description:
 *    This function will wait for some data and return a positive
 *    value (one) if pipe buffers are available.  It will return zero
 *    or -errno if no more data needs to be spliced.
 */
static int splice_from_pipe_next(struct pipe_inode_info *pipe, struct splice_desc *sd)
{
	/*
	 * Check for signal early to make process killable when there are
	 * always buffers available
	 */
	if (signal_pending(current))
		return -ERESTARTSYS;

repeat:
	while (pipe_is_empty(pipe)) {
		if (!pipe->writers)
			return 0;

		if (sd->num_spliced)
			return 0;

		if (sd->flags & SPLICE_F_NONBLOCK)
			return -EAGAIN;

		if (signal_pending(current))
			return -ERESTARTSYS;

		if (sd->need_wakeup) {
			wakeup_pipe_writers(pipe);
			sd->need_wakeup = false;
		}

		pipe_wait_readable(pipe);
	}

	if (eat_empty_buffer(pipe))
		goto repeat;

	return 1;
}

/**
 * splice_from_pipe_begin - start splicing from pipe
 * @sd:		information about the splice operation
 *
 * Description:
 *    This function should be called before a loop containing
 *    splice_from_pipe_next() and splice_from_pipe_feed() to
 *    initialize the necessary fields of @sd.
 */
static void splice_from_pipe_begin(struct splice_desc *sd)
{
	sd->num_spliced = 0;
	sd->need_wakeup = false;
}

/**
 * splice_from_pipe_end - finish splicing from pipe
 * @pipe:	pipe to splice from
 * @sd:		information about the splice operation
 *
 * Description:
 *    This function will wake up pipe writers if necessary.  It should
 *    be called after a loop containing splice_from_pipe_next() and
 *    splice_from_pipe_feed().
 */
static void splice_from_pipe_end(struct pipe_inode_info *pipe, struct splice_desc *sd)
{
	if (sd->need_wakeup)
		wakeup_pipe_writers(pipe);
}

/**
 * __splice_from_pipe - splice data from a pipe to given actor
 * @pipe:	pipe to splice from
 * @sd:		information to @actor
 * @actor:	handler that splices the data
 *
 * Description:
 *    This function does little more than loop over the pipe and call
 *    @actor to do the actual moving of a single struct pipe_buffer to
 *    the desired destination. See pipe_to_file, pipe_to_sendmsg, or
 *    pipe_to_user.
 *
 */
ssize_t __splice_from_pipe(struct pipe_inode_info *pipe, struct splice_desc *sd,
			   splice_actor *actor)
{
	int ret;

	splice_from_pipe_begin(sd);
	do {
		cond_resched();
		ret = splice_from_pipe_next(pipe, sd);
		if (ret > 0)
			ret = splice_from_pipe_feed(pipe, sd, actor);
	} while (ret > 0);
	splice_from_pipe_end(pipe, sd);

	return sd->num_spliced ? sd->num_spliced : ret;
}
EXPORT_SYMBOL(__splice_from_pipe);

/**
 * splice_from_pipe - splice data from a pipe to a file
 * @pipe:	pipe to splice from
 * @out:	file to splice to
 * @ppos:	position in @out
 * @len:	how many bytes to splice
 * @flags:	splice modifier flags
 * @actor:	handler that splices the data
 *
 * Description:
 *    See __splice_from_pipe. This function locks the pipe inode,
 *    otherwise it's identical to __splice_from_pipe().
 *
 */
ssize_t splice_from_pipe(struct pipe_inode_info *pipe, struct file *out,
			 loff_t *ppos, size_t len, unsigned int flags,
			 splice_actor *actor)
{
	ssize_t ret;
	struct splice_desc sd = {
		.total_len = len,
		.flags = flags,
		.pos = *ppos,
		.u.file = out,
	};

	pipe_lock(pipe);
	ret = __splice_from_pipe(pipe, &sd, actor);
	pipe_unlock(pipe);

	return ret;
}

/**
 * iter_file_splice_write - splice data from a pipe to a file
 * @pipe:	pipe info
 * @out:	file to write to
 * @ppos:	position in @out
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will either move or copy pages (determined by @flags options) from
 *    the given pipe inode to the given file.
 *    This one is ->write_iter-based.
 *
 */
ssize_t
iter_file_splice_write(struct pipe_inode_info *pipe, struct file *out,
			  loff_t *ppos, size_t len, unsigned int flags)
{
	struct splice_desc sd = {
		.total_len = len,
		.flags = flags,
		.pos = *ppos,
		.u.file = out,
	};
	int nbufs = pipe->max_usage;
	struct bio_vec *array;
	ssize_t ret;

	if (!out->f_op->write_iter)
		return -EINVAL;

	array = kcalloc(nbufs, sizeof(struct bio_vec), GFP_KERNEL);
	if (unlikely(!array))
		return -ENOMEM;

	pipe_lock(pipe);

	splice_from_pipe_begin(&sd);
	while (sd.total_len) {
		struct kiocb kiocb;
		struct iov_iter from;
		unsigned int head, tail;
		size_t left;
		int n;

		ret = splice_from_pipe_next(pipe, &sd);
		if (ret <= 0)
			break;

		if (unlikely(nbufs < pipe->max_usage)) {
			kfree(array);
			nbufs = pipe->max_usage;
			array = kcalloc(nbufs, sizeof(struct bio_vec),
					GFP_KERNEL);
			if (!array) {
				ret = -ENOMEM;
				break;
			}
		}

		head = pipe->head;
		tail = pipe->tail;

		/* build the vector */
		left = sd.total_len;
		for (n = 0; !pipe_empty(head, tail) && left && n < nbufs; tail++) {
			struct pipe_buffer *buf = pipe_buf(pipe, tail);
			size_t this_len = buf->len;

			/* zero-length bvecs are not supported, skip them */
			if (!this_len)
				continue;
			this_len = min(this_len, left);

			ret = pipe_buf_confirm(pipe, buf);
			if (unlikely(ret)) {
				if (ret == -ENODATA)
					ret = 0;
				goto done;
			}

			bvec_set_page(&array[n], buf->page, this_len,
				      buf->offset);
			left -= this_len;
			n++;
		}

		iov_iter_bvec(&from, ITER_SOURCE, array, n, sd.total_len - left);
		init_sync_kiocb(&kiocb, out);
		kiocb.ki_pos = sd.pos;
		ret = out->f_op->write_iter(&kiocb, &from);
		sd.pos = kiocb.ki_pos;
		if (ret <= 0)
			break;
		WARN_ONCE(ret > sd.total_len - left,
			  "Splice Exceeded! ret=%zd tot=%zu left=%zu\n",
			  ret, sd.total_len, left);

		sd.num_spliced += ret;
		sd.total_len -= ret;
		*ppos = sd.pos;

		/* dismiss the fully eaten buffers, adjust the partial one */
		tail = pipe->tail;
		while (ret) {
			struct pipe_buffer *buf = pipe_buf(pipe, tail);
			if (ret >= buf->len) {
				ret -= buf->len;
				buf->len = 0;
				pipe_buf_release(pipe, buf);
				tail++;
				pipe->tail = tail;
				if (pipe->files)
					sd.need_wakeup = true;
			} else {
				buf->offset += ret;
				buf->len -= ret;
				ret = 0;
			}
		}
	}
done:
	kfree(array);
	splice_from_pipe_end(pipe, &sd);

	pipe_unlock(pipe);

	if (sd.num_spliced)
		ret = sd.num_spliced;

	return ret;
}

EXPORT_SYMBOL(iter_file_splice_write);

#ifdef CONFIG_NET
/**
 * splice_to_socket - splice data from a pipe to a socket
 * @pipe:	pipe to splice from
 * @out:	socket to write to
 * @ppos:	position in @out
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will send @len bytes from the pipe to a network socket. No data copying
 *    is involved.
 *
 */
ssize_t splice_to_socket(struct pipe_inode_info *pipe, struct file *out,
			 loff_t *ppos, size_t len, unsigned int flags)
{
	struct socket *sock = sock_from_file(out);
	struct bio_vec bvec[16];
	struct msghdr msg = {};
	ssize_t ret = 0;
	size_t spliced = 0;
	bool need_wakeup = false;

	pipe_lock(pipe);

	while (len > 0) {
		unsigned int head, tail, bc = 0;
		size_t remain = len;

		/*
		 * Check for signal early to make process killable when there
		 * are always buffers available
		 */
		ret = -ERESTARTSYS;
		if (signal_pending(current))
			break;

		while (pipe_is_empty(pipe)) {
			ret = 0;
			if (!pipe->writers)
				goto out;

			if (spliced)
				goto out;

			ret = -EAGAIN;
			if (flags & SPLICE_F_NONBLOCK)
				goto out;

			ret = -ERESTARTSYS;
			if (signal_pending(current))
				goto out;

			if (need_wakeup) {
				wakeup_pipe_writers(pipe);
				need_wakeup = false;
			}

			pipe_wait_readable(pipe);
		}

		head = pipe->head;
		tail = pipe->tail;

		while (!pipe_empty(head, tail)) {
			struct pipe_buffer *buf = pipe_buf(pipe, tail);
			size_t seg;

			if (!buf->len) {
				tail++;
				continue;
			}

			seg = min_t(size_t, remain, buf->len);

			ret = pipe_buf_confirm(pipe, buf);
			if (unlikely(ret)) {
				if (ret == -ENODATA)
					ret = 0;
				break;
			}

			bvec_set_page(&bvec[bc++], buf->page, seg, buf->offset);
			remain -= seg;
			if (remain == 0 || bc >= ARRAY_SIZE(bvec))
				break;
			tail++;
		}

		if (!bc)
			break;

		msg.msg_flags = MSG_SPLICE_PAGES;
		if (flags & SPLICE_F_MORE)
			msg.msg_flags |= MSG_MORE;
		if (remain && pipe_occupancy(pipe->head, tail) > 0)
			msg.msg_flags |= MSG_MORE;
		if (out->f_flags & O_NONBLOCK)
			msg.msg_flags |= MSG_DONTWAIT;

		iov_iter_bvec(&msg.msg_iter, ITER_SOURCE, bvec, bc,
			      len - remain);
		ret = sock_sendmsg(sock, &msg);
		if (ret <= 0)
			break;

		spliced += ret;
		len -= ret;
		tail = pipe->tail;
		while (ret > 0) {
			struct pipe_buffer *buf = pipe_buf(pipe, tail);
			size_t seg = min_t(size_t, ret, buf->len);

			buf->offset += seg;
			buf->len -= seg;
			ret -= seg;

			if (!buf->len) {
				pipe_buf_release(pipe, buf);
				tail++;
			}
		}

		if (tail != pipe->tail) {
			pipe->tail = tail;
			if (pipe->files)
				need_wakeup = true;
		}
	}

out:
	pipe_unlock(pipe);
	if (need_wakeup)
		wakeup_pipe_writers(pipe);
	return spliced ?: ret;
}
#endif

static int warn_unsupported(struct file *file, const char *op)
{
	pr_debug_ratelimited(
		"splice %s not supported for file %pD4 (pid: %d comm: %.20s)\n",
		op, file, current->pid, current->comm);
	return -EINVAL;
}

/*
 * Attempt to initiate a splice from pipe to file.
 */
static ssize_t do_splice_from(struct pipe_inode_info *pipe, struct file *out,
			      loff_t *ppos, size_t len, unsigned int flags)
{
	if (unlikely(!out->f_op->splice_write))
		return warn_unsupported(out, "write");
	return out->f_op->splice_write(pipe, out, ppos, len, flags);
}

/*
 * Indicate to the caller that there was a premature EOF when reading from the
 * source and the caller didn't indicate they would be sending more data after
 * this.
 */
static void do_splice_eof(struct splice_desc *sd)
{
	if (sd->splice_eof)
		sd->splice_eof(sd);
}

/*
 * Callers already called rw_verify_area() on the entire range.
 * No need to call it for sub ranges.
 */
static ssize_t do_splice_read(struct file *in, loff_t *ppos,
			      struct pipe_inode_info *pipe, size_t len,
			      unsigned int flags)
{
	unsigned int p_space;

	if (unlikely(!(in->f_mode & FMODE_READ)))
		return -EBADF;
	if (!len)
		return 0;

	/* Don't try to read more the pipe has space for. */
	p_space = pipe->max_usage - pipe_buf_usage(pipe);
	len = min_t(size_t, len, p_space << PAGE_SHIFT);

	if (unlikely(len > MAX_RW_COUNT))
		len = MAX_RW_COUNT;

	if (unlikely(!in->f_op->splice_read))
		return warn_unsupported(in, "read");
	/*
	 * O_DIRECT and DAX don't deal with the pagecache, so we allocate a
	 * buffer, copy into it and splice that into the pipe.
	 */
	if ((in->f_flags & O_DIRECT) || IS_DAX(in->f_mapping->host))
		return copy_splice_read(in, ppos, pipe, len, flags);
	return in->f_op->splice_read(in, ppos, pipe, len, flags);
}

/**
 * vfs_splice_read - Read data from a file and splice it into a pipe
 * @in:		File to splice from
 * @ppos:	Input file offset
 * @pipe:	Pipe to splice to
 * @len:	Number of bytes to splice
 * @flags:	Splice modifier flags (SPLICE_F_*)
 *
 * Splice the requested amount of data from the input file to the pipe.  This
 * is synchronous as the caller must hold the pipe lock across the entire
 * operation.
 *
 * If successful, it returns the amount of data spliced, 0 if it hit the EOF or
 * a hole and a negative error code otherwise.
 */
ssize_t vfs_splice_read(struct file *in, loff_t *ppos,
			struct pipe_inode_info *pipe, size_t len,
			unsigned int flags)
{
	ssize_t ret;

	ret = rw_verify_area(READ, in, ppos, len);
	if (unlikely(ret < 0))
		return ret;

	return do_splice_read(in, ppos, pipe, len, flags);
}
EXPORT_SYMBOL_GPL(vfs_splice_read);

/**
 * splice_direct_to_actor - splices data directly between two non-pipes
 * @in:		file to splice from
 * @sd:		actor information on where to splice to
 * @actor:	handles the data splicing
 *
 * Description:
 *    This is a special case helper to splice directly between two
 *    points, without requiring an explicit pipe. Internally an allocated
 *    pipe is cached in the process, and reused during the lifetime of
 *    that process.
 *
 */
ssize_t splice_direct_to_actor(struct file *in, struct splice_desc *sd,
			       splice_direct_actor *actor)
{
	struct pipe_inode_info *pipe;
	ssize_t ret, bytes;
	size_t len;
	int i, flags, more;

	/*
	 * We require the input to be seekable, as we don't want to randomly
	 * drop data for eg socket -> socket splicing. Use the piped splicing
	 * for that!
	 */
	if (unlikely(!(in->f_mode & FMODE_LSEEK)))
		return -EINVAL;

	/*
	 * neither in nor out is a pipe, setup an internal pipe attached to
	 * 'out' and transfer the wanted data from 'in' to 'out' through that
	 */
	pipe = current->splice_pipe;
	if (unlikely(!pipe)) {
		pipe = alloc_pipe_info();
		if (!pipe)
			return -ENOMEM;

		/*
		 * We don't have an immediate reader, but we'll read the stuff
		 * out of the pipe right after the splice_to_pipe(). So set
		 * PIPE_READERS appropriately.
		 */
		pipe->readers = 1;

		current->splice_pipe = pipe;
	}

	/*
	 * Do the splice.
	 */
	bytes = 0;
	len = sd->total_len;

	/* Don't block on output, we have to drain the direct pipe. */
	flags = sd->flags;
	sd->flags &= ~SPLICE_F_NONBLOCK;

	/*
	 * We signal MORE until we've read sufficient data to fulfill the
	 * request and we keep signalling it if the caller set it.
	 */
	more = sd->flags & SPLICE_F_MORE;
	sd->flags |= SPLICE_F_MORE;

	WARN_ON_ONCE(!pipe_is_empty(pipe));

	while (len) {
		size_t read_len;
		loff_t pos = sd->pos, prev_pos = pos;

		ret = do_splice_read(in, &pos, pipe, len, flags);
		if (unlikely(ret <= 0))
			goto read_failure;

		read_len = ret;
		sd->total_len = read_len;

		/*
		 * If we now have sufficient data to fulfill the request then
		 * we clear SPLICE_F_MORE if it was not set initially.
		 */
		if (read_len >= len && !more)
			sd->flags &= ~SPLICE_F_MORE;

		/*
		 * NOTE: nonblocking mode only applies to the input. We
		 * must not do the output in nonblocking mode as then we
		 * could get stuck data in the internal pipe:
		 */
		ret = actor(pipe, sd);
		if (unlikely(ret <= 0)) {
			sd->pos = prev_pos;
			goto out_release;
		}

		bytes += ret;
		len -= ret;
		sd->pos = pos;

		if (ret < read_len) {
			sd->pos = prev_pos + ret;
			goto out_release;
		}
	}

done:
	pipe->tail = pipe->head = 0;
	file_accessed(in);
	return bytes;

read_failure:
	/*
	 * If the user did *not* set SPLICE_F_MORE *and* we didn't hit that
	 * "use all of len" case that cleared SPLICE_F_MORE, *and* we did a
	 * "->splice_in()" that returned EOF (ie zero) *and* we have sent at
	 * least 1 byte *then* we will also do the ->splice_eof() call.
	 */
	if (ret == 0 && !more && len > 0 && bytes)
		do_splice_eof(sd);
out_release:
	/*
	 * If we did an incomplete transfer we must release
	 * the pipe buffers in question:
	 */
	for (i = 0; i < pipe->ring_size; i++) {
		struct pipe_buffer *buf = &pipe->bufs[i];

		if (buf->ops)
			pipe_buf_release(pipe, buf);
	}

	if (!bytes)
		bytes = ret;

	goto done;
}
EXPORT_SYMBOL(splice_direct_to_actor);

static int direct_splice_actor(struct pipe_inode_info *pipe,
			       struct splice_desc *sd)
{
	struct file *file = sd->u.file;
	long ret;

	file_start_write(file);
	ret = do_splice_from(pipe, file, sd->opos, sd->total_len, sd->flags);
	file_end_write(file);
	return ret;
}

static int splice_file_range_actor(struct pipe_inode_info *pipe,
					struct splice_desc *sd)
{
	struct file *file = sd->u.file;

	return do_splice_from(pipe, file, sd->opos, sd->total_len, sd->flags);
}

static void direct_file_splice_eof(struct splice_desc *sd)
{
	struct file *file = sd->u.file;

	if (file->f_op->splice_eof)
		file->f_op->splice_eof(file);
}

static ssize_t do_splice_direct_actor(struct file *in, loff_t *ppos,
				      struct file *out, loff_t *opos,
				      size_t len, unsigned int flags,
				      splice_direct_actor *actor)
{
	struct splice_desc sd = {
		.len		= len,
		.total_len	= len,
		.flags		= flags,
		.pos		= *ppos,
		.u.file		= out,
		.splice_eof	= direct_file_splice_eof,
		.opos		= opos,
	};
	ssize_t ret;

	if (unlikely(!(out->f_mode & FMODE_WRITE)))
		return -EBADF;

	if (unlikely(out->f_flags & O_APPEND))
		return -EINVAL;

	ret = splice_direct_to_actor(in, &sd, actor);
	if (ret > 0)
		*ppos = sd.pos;

	return ret;
}
/**
 * do_splice_direct - splices data directly between two files
 * @in:		file to splice from
 * @ppos:	input file offset
 * @out:	file to splice to
 * @opos:	output file offset
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    For use by do_sendfile(). splice can easily emulate sendfile, but
 *    doing it in the application would incur an extra system call
 *    (splice in + splice out, as compared to just sendfile()). So this helper
 *    can splice directly through a process-private pipe.
 *
 * Callers already called rw_verify_area() on the entire range.
 */
ssize_t do_splice_direct(struct file *in, loff_t *ppos, struct file *out,
			 loff_t *opos, size_t len, unsigned int flags)
{
	return do_splice_direct_actor(in, ppos, out, opos, len, flags,
				      direct_splice_actor);
}
EXPORT_SYMBOL(do_splice_direct);

/**
 * splice_file_range - splices data between two files for copy_file_range()
 * @in:		file to splice from
 * @ppos:	input file offset
 * @out:	file to splice to
 * @opos:	output file offset
 * @len:	number of bytes to splice
 *
 * Description:
 *    For use by ->copy_file_range() methods.
 *    Like do_splice_direct(), but vfs_copy_file_range() already holds
 *    start_file_write() on @out file.
 *
 * Callers already called rw_verify_area() on the entire range.
 */
ssize_t splice_file_range(struct file *in, loff_t *ppos, struct file *out,
			  loff_t *opos, size_t len)
{
	lockdep_assert(file_write_started(out));

	return do_splice_direct_actor(in, ppos, out, opos,
				      min_t(size_t, len, MAX_RW_COUNT),
				      0, splice_file_range_actor);
}
EXPORT_SYMBOL(splice_file_range);

static int wait_for_space(struct pipe_inode_info *pipe, unsigned flags)
{
	for (;;) {
		if (unlikely(!pipe->readers)) {
			send_sig(SIGPIPE, current, 0);
			return -EPIPE;
		}
		if (!pipe_is_full(pipe))
			return 0;
		if (flags & SPLICE_F_NONBLOCK)
			return -EAGAIN;
		if (signal_pending(current))
			return -ERESTARTSYS;
		pipe_wait_writable(pipe);
	}
}

static int splice_pipe_to_pipe(struct pipe_inode_info *ipipe,
			       struct pipe_inode_info *opipe,
			       size_t len, unsigned int flags);

ssize_t splice_file_to_pipe(struct file *in,
			    struct pipe_inode_info *opipe,
			    loff_t *offset,
			    size_t len, unsigned int flags)
{
	ssize_t ret;

	pipe_lock(opipe);
	ret = wait_for_space(opipe, flags);
	if (!ret)
		ret = do_splice_read(in, offset, opipe, len, flags);
	pipe_unlock(opipe);
	if (ret > 0)
		wakeup_pipe_readers(opipe);
	return ret;
}

/*
 * Determine where to splice to/from.
 */
ssize_t do_splice(struct file *in, loff_t *off_in, struct file *out,
		  loff_t *off_out, size_t len, unsigned int flags)
{
	struct pipe_inode_info *ipipe;
	struct pipe_inode_info *opipe;
	loff_t offset;
	ssize_t ret;

	if (unlikely(!(in->f_mode & FMODE_READ) ||
		     !(out->f_mode & FMODE_WRITE)))
		return -EBADF;

	ipipe = get_pipe_info(in, true);
	opipe = get_pipe_info(out, true);

	if (ipipe && opipe) {
		if (off_in || off_out)
			return -ESPIPE;

		/* Splicing to self would be fun, but... */
		if (ipipe == opipe)
			return -EINVAL;

		if ((in->f_flags | out->f_flags) & O_NONBLOCK)
			flags |= SPLICE_F_NONBLOCK;

		ret = splice_pipe_to_pipe(ipipe, opipe, len, flags);
	} else if (ipipe) {
		if (off_in)
			return -ESPIPE;
		if (off_out) {
			if (!(out->f_mode & FMODE_PWRITE))
				return -EINVAL;
			offset = *off_out;
		} else {
			offset = out->f_pos;
		}

		if (unlikely(out->f_flags & O_APPEND))
			return -EINVAL;

		ret = rw_verify_area(WRITE, out, &offset, len);
		if (unlikely(ret < 0))
			return ret;

		if (in->f_flags & O_NONBLOCK)
			flags |= SPLICE_F_NONBLOCK;

		file_start_write(out);
		ret = do_splice_from(ipipe, out, &offset, len, flags);
		file_end_write(out);

		if (!off_out)
			out->f_pos = offset;
		else
			*off_out = offset;
	} else if (opipe) {
		if (off_out)
			return -ESPIPE;
		if (off_in) {
			if (!(in->f_mode & FMODE_PREAD))
				return -EINVAL;
			offset = *off_in;
		} else {
			offset = in->f_pos;
		}

		ret = rw_verify_area(READ, in, &offset, len);
		if (unlikely(ret < 0))
			return ret;

		if (out->f_flags & O_NONBLOCK)
			flags |= SPLICE_F_NONBLOCK;

		ret = splice_file_to_pipe(in, opipe, &offset, len, flags);

		if (!off_in)
			in->f_pos = offset;
		else
			*off_in = offset;
	} else {
		ret = -EINVAL;
	}

	if (ret > 0) {
		/*
		 * Generate modify out before access in:
		 * do_splice_from() may've already sent modify out,
		 * and this ensures the events get merged.
		 */
		fsnotify_modify(out);
		fsnotify_access(in);
	}

	return ret;
}

static ssize_t __do_splice(struct file *in, loff_t __user *off_in,
			   struct file *out, loff_t __user *off_out,
			   size_t len, unsigned int flags)
{
	struct pipe_inode_info *ipipe;
	struct pipe_inode_info *opipe;
	loff_t offset, *__off_in = NULL, *__off_out = NULL;
	ssize_t ret;

	ipipe = get_pipe_info(in, true);
	opipe = get_pipe_info(out, true);

	if (ipipe) {
		if (off_in)
			return -ESPIPE;
		pipe_clear_nowait(in);
	}
	if (opipe) {
		if (off_out)
			return -ESPIPE;
		pipe_clear_nowait(out);
	}

	if (off_out) {
		if (copy_from_user(&offset, off_out, sizeof(loff_t)))
			return -EFAULT;
		__off_out = &offset;
	}
	if (off_in) {
		if (copy_from_user(&offset, off_in, sizeof(loff_t)))
			return -EFAULT;
		__off_in = &offset;
	}

	ret = do_splice(in, __off_in, out, __off_out, len, flags);
	if (ret < 0)
		return ret;

	if (__off_out && copy_to_user(off_out, __off_out, sizeof(loff_t)))
		return -EFAULT;
	if (__off_in && copy_to_user(off_in, __off_in, sizeof(loff_t)))
		return -EFAULT;

	return ret;
}

static ssize_t iter_to_pipe(struct iov_iter *from,
			    struct pipe_inode_info *pipe,
			    unsigned int flags)
{
	struct pipe_buffer buf = {
		.ops = &user_page_pipe_buf_ops,
		.flags = flags
	};
	size_t total = 0;
	ssize_t ret = 0;

	while (iov_iter_count(from)) {
		struct page *pages[16];
		ssize_t left;
		size_t start;
		int i, n;

		left = iov_iter_get_pages2(from, pages, ~0UL, 16, &start);
		if (left <= 0) {
			ret = left;
			break;
		}

		n = DIV_ROUND_UP(left + start, PAGE_SIZE);
		for (i = 0; i < n; i++) {
			int size = min_t(int, left, PAGE_SIZE - start);

			buf.page = pages[i];
			buf.offset = start;
			buf.len = size;
			ret = add_to_pipe(pipe, &buf);
			if (unlikely(ret < 0)) {
				iov_iter_revert(from, left);
				// this one got dropped by add_to_pipe()
				while (++i < n)
					put_page(pages[i]);
				goto out;
			}
			total += ret;
			left -= size;
			start = 0;
		}
	}
out:
	return total ? total : ret;
}

static int pipe_to_user(struct pipe_inode_info *pipe, struct pipe_buffer *buf,
			struct splice_desc *sd)
{
	int n = copy_page_to_iter(buf->page, buf->offset, sd->len, sd->u.data);
	return n == sd->len ? n : -EFAULT;
}

/*
 * For lack of a better implementation, implement vmsplice() to userspace
 * as a simple copy of the pipe's pages to the user iov.
 */
static ssize_t vmsplice_to_user(struct file *file, struct iov_iter *iter,
				unsigned int flags)
{
	struct pipe_inode_info *pipe = get_pipe_info(file, true);
	struct splice_desc sd = {
		.total_len = iov_iter_count(iter),
		.flags = flags,
		.u.data = iter
	};
	ssize_t ret = 0;

	if (!pipe)
		return -EBADF;

	pipe_clear_nowait(file);

	if (sd.total_len) {
		pipe_lock(pipe);
		ret = __splice_from_pipe(pipe, &sd, pipe_to_user);
		pipe_unlock(pipe);
	}

	if (ret > 0)
		fsnotify_access(file);

	return ret;
}

/*
 * vmsplice splices a user address range into a pipe. It can be thought of
 * as splice-from-memory, where the regular splice is splice-from-file (or
 * to file). In both cases the output is a pipe, naturally.
 */
static ssize_t vmsplice_to_pipe(struct file *file, struct iov_iter *iter,
				unsigned int flags)
{
	struct pipe_inode_info *pipe;
	ssize_t ret = 0;
	unsigned buf_flag = 0;

	if (flags & SPLICE_F_GIFT)
		buf_flag = PIPE_BUF_FLAG_GIFT;

	pipe = get_pipe_info(file, true);
	if (!pipe)
		return -EBADF;

	pipe_clear_nowait(file);

	pipe_lock(pipe);
	ret = wait_for_space(pipe, flags);
	if (!ret)
		ret = iter_to_pipe(iter, pipe, buf_flag);
	pipe_unlock(pipe);
	if (ret > 0) {
		wakeup_pipe_readers(pipe);
		fsnotify_modify(file);
	}
	return ret;
}

/**
 * sys_vmsplice - Splice user memory pages into or out of a pipe
 * @fd: Pipe file descriptor
 * @uiov: Pointer to array of iovec structures describing user memory regions
 * @nr_segs: Number of iovec segments in the array
 * @flags: Behavioral flags (SPLICE_F_* constants)
 *
 * long-desc: Transfers data between user memory and a pipe without copying
 *   through an intermediate kernel buffer (zero-copy in one direction).
 *
 *   When fd refers to the write end of a pipe (opened with O_WRONLY or O_RDWR),
 *   vmsplice() maps the user memory pages described by the iovec array directly
 *   into the pipe's internal buffer. This is a true zero-copy operation where
 *   the same physical pages are shared between user space and the pipe.
 *
 *   When fd refers to the read end of a pipe (opened with O_RDONLY or O_RDWR),
 *   vmsplice() copies data from the pipe into the user memory regions described
 *   by iov. Note that despite the splice name, this direction is implemented
 *   as a memory copy, not a zero-copy operation, due to VM complexity issues.
 *
 *   The direction of data transfer is determined automatically by checking the
 *   file mode of fd. If FMODE_WRITE is set, data flows from user memory to pipe.
 *   If FMODE_READ is set, data flows from pipe to user memory.
 *
 *   For user-to-pipe transfers, the pages are pinned using get_user_pages_fast()
 *   and added to the pipe buffer. The calling process must not modify these
 *   pages until the data has been consumed from the pipe, as this could corrupt
 *   the pipe contents. Using SPLICE_F_GIFT indicates the pages are donated to
 *   the kernel and should not be modified afterward.
 *
 *   This syscall is commonly used for high-performance I/O where minimizing
 *   memory copies is critical, such as in web servers or media streaming
 *   applications. It pairs naturally with splice(2) to move data from memory
 *   through a pipe to a socket or file without intermediate copies.
 *
 *   Double-buffering is a common pattern: fill half of a buffer while the other
 *   half is being transferred via vmsplice, then switch. This allows continuous
 *   data flow without synchronization complexity.
 *
 *   Note: vmsplice() was the subject of serious security vulnerabilities in 2008
 *   (CVE-2008-0009, CVE-2008-0010, CVE-2008-0600) that allowed local privilege
 *   escalation. These were caused by missing permission checks and integer
 *   overflow issues in early implementations.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid file descriptor that refers to a pipe. The
 *     direction of data transfer is determined by the file mode: if FMODE_WRITE
 *     is set, data is transferred from user memory to the pipe; if FMODE_READ
 *     is set, data is transferred from the pipe to user memory. If the file
 *     descriptor is invalid, EBADF is returned. If the file descriptor does
 *     not reference a pipe, EBADF is returned. If the file descriptor has
 *     neither FMODE_READ nor FMODE_WRITE set, EBADF is returned.
 *
 * param: uiov
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Pointer to an array of struct iovec in user space. Each iovec
 *     specifies a memory region with iov_base (starting address) and iov_len
 *     (length in bytes). The iov_base pointers must reference valid, accessible
 *     user memory. For transfers to pipe, the memory must be readable. For
 *     transfers from pipe, the memory must be writable. Invalid addresses cause
 *     EFAULT. If iov_len when cast to ssize_t is negative, EINVAL is returned.
 *     The total bytes across all segments is capped at MAX_RW_COUNT (~2GB).
 *     NULL pointer or inaccessible memory returns EFAULT.
 *
 * param: nr_segs
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, UIO_MAXIOV
 *   constraint: Number of iovec structures in the uiov array. Must be between
 *     0 and UIO_MAXIOV (1024) inclusive. If nr_segs is 0, the syscall returns 0
 *     immediately with no data transferred. If nr_segs exceeds UIO_MAXIOV,
 *     EINVAL is returned. For efficiency, if nr_segs <= UIO_FASTIOV (8), a
 *     stack-allocated array is used; otherwise heap allocation is required.
 *
 * param: flags
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT
 *   constraint: Bitwise OR of zero or more SPLICE_F_* flags. SPLICE_F_MOVE
 *     (0x01) is currently unused for vmsplice. SPLICE_F_NONBLOCK (0x02) causes
 *     the call to return EAGAIN instead of blocking when the pipe is full
 *     (for to-pipe) or empty (for to-user). SPLICE_F_MORE (0x04) indicates more
 *     data will follow; currently has no effect but reserved for future use.
 *     SPLICE_F_GIFT (0x08) indicates the user pages are a "gift" to the kernel
 *     and the caller promises not to modify them; enables potential optimization
 *     in subsequent splice operations. Any bits outside this mask cause EINVAL.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: >= 0
 *   desc: On success, returns the number of bytes transferred (non-negative).
 *     This may be less than requested if the pipe buffer is full (to-pipe),
 *     the pipe is empty (to-user), or partial data was available. A return
 *     value of 0 indicates no data was transferred, which occurs when nr_segs
 *     is 0 or all iovec segments have zero length. On error, returns a negative
 *     error code.
 *
 * error: EINVAL, Invalid flags or segment count
 *   desc: Returned when flags contains bits not in SPLICE_F_ALL mask (i.e.,
 *     bits other than SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, and
 *     SPLICE_F_GIFT are set), when nr_segs exceeds UIO_MAXIOV (1024), or when
 *     any iov_len field is negative when interpreted as ssize_t.
 *
 * error: EBADF, Bad file descriptor
 *   desc: Returned when fd is not a valid open file descriptor, when fd does
 *     not reference a pipe, or when the file has neither FMODE_READ nor
 *     FMODE_WRITE set. For vmsplice to work, fd must be specifically a pipe
 *     file descriptor (created by pipe() or pipe2()), not a regular file,
 *     socket, or other file type.
 *
 * error: EFAULT, Bad address
 *   desc: The uiov pointer is outside the accessible address space, one of
 *     the iov_base pointers in the iovec array is invalid, or the memory
 *     region is not accessible for the required operation (read for to-pipe,
 *     write for to-user). The check uses access_ok() and copy_from_user().
 *
 * error: ENOMEM, Out of memory
 *   desc: Kernel memory allocation failed. This can occur when nr_segs exceeds
 *     UIO_FASTIOV (8) requiring heap allocation for the iovec array, when
 *     allocating the page array for get_user_pages_fast(), or when internal
 *     pipe buffer structures cannot be allocated. Uses GFP_KERNEL allocation.
 *
 * error: EPIPE, Broken pipe
 *   desc: When transferring data to pipe, returned if there are no readers
 *     on the pipe (pipe->readers == 0). This indicates no process has the
 *     read end of the pipe open. SIGPIPE is also sent to the calling process
 *     before returning this error. Can be avoided by blocking or ignoring
 *     SIGPIPE.
 *
 * error: EAGAIN, Resource temporarily unavailable
 *   desc: SPLICE_F_NONBLOCK was set in flags and the operation would block.
 *     For to-pipe transfers, this means the pipe buffer is full and no space
 *     is available. For to-user transfers, this means the pipe is empty and
 *     no data is available. Without SPLICE_F_NONBLOCK, the syscall would
 *     block until space/data becomes available.
 *
 * error: ERESTARTSYS, Interrupted by signal (restartable)
 *   desc: The syscall was waiting for pipe space (to-pipe) or data (to-user)
 *     and a signal was delivered to the calling thread. This error is handled
 *     by the syscall restart mechanism: if the signal handler was registered
 *     with SA_RESTART, the syscall is automatically restarted after the signal
 *     handler returns. Otherwise, the syscall returns -EINTR to user space.
 *
 * lock: pipe->mutex
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: The pipe's mutex is acquired via pipe_lock() before accessing or
 *     modifying the pipe buffer. For to-pipe transfers, the lock is held while
 *     waiting for space (if blocking), adding pages to the pipe buffer, and
 *     updating head/tail pointers. For to-user transfers, the lock is held
 *     while reading data from pipe buffers. The lock is always released before
 *     the syscall returns, and is temporarily released during blocking waits
 *     in pipe_wait_readable() or pipe_wait_writable().
 *
 * signal: SIGPIPE
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: Writing to pipe with no readers (pipe->readers == 0)
 *   desc: When attempting to transfer data to a pipe that has no readers
 *     (all read ends have been closed), SIGPIPE is sent to the calling
 *     process before returning EPIPE. The default action for SIGPIPE is
 *     to terminate the process. Applications can ignore or handle this
 *     signal to receive the EPIPE error instead of being terminated.
 *   error: -EPIPE
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * signal: Any
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: Waiting for pipe space or data
 *   desc: While blocked waiting for the pipe to become writable (to-pipe)
 *     or readable (to-user), any signal delivered to the thread will cause
 *     the wait to be interrupted. The syscall returns ERESTARTSYS which is
 *     converted to EINTR or triggers automatic restart depending on SA_RESTART.
 *   error: -ERESTARTSYS
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Pipe buffer contents
 *   desc: For to-pipe transfers, user memory pages are added to the pipe's
 *     internal ring buffer, incrementing pipe->head. For to-user transfers,
 *     data is consumed from the pipe buffer, advancing pipe->tail and
 *     releasing pipe_buffer entries. The pipe occupancy changes accordingly.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: Page references
 *   desc: For to-pipe transfers, get_user_pages_fast() pins the user pages
 *     and takes references on them. These references are released when the
 *     pipe buffer entry is consumed (via pipe_buf_release). The pages remain
 *     pinned in memory until read from the pipe.
 *   condition: Only for user-to-pipe transfers
 *   reversible: yes (when pipe data is consumed)
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: Pipe waiters
 *   desc: For to-pipe transfers, pipe readers blocked in read() or poll()
 *     are woken via wake_up_interruptible(&pipe->rd_wait). For to-user
 *     transfers, pipe writers are woken via wake_up_interruptible(&pipe->wr_wait).
 *     Also triggers fasync notifications (SIGIO via kill_fasync).
 *   condition: When data is added or consumed from pipe
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: fsnotify events
 *   desc: On successful transfer, fsnotify events are generated. For to-pipe
 *     transfers, fsnotify_modify() is called on the pipe file. For to-user
 *     transfers, fsnotify_access() is called. This allows inotify and fanotify
 *     watchers to detect pipe activity.
 *   condition: Only on successful transfer (return > 0)
 *
 * state-trans: pipe buffer
 *   from: empty or partially filled
 *   to: contains new data (to-pipe) or less data (to-user)
 *   condition: Successful transfer of any bytes
 *   desc: The pipe's ring buffer state changes. For to-pipe: pipe->head
 *     increments and new pipe_buffer entries reference the user pages.
 *     For to-user: pipe->tail increments and consumed buffers are released.
 *
 * constraint: Pipe capacity limit
 *   desc: The amount of data that can be transferred to a pipe in a single
 *     call is limited by the pipe's available buffer space. Default pipe
 *     capacity is 16 pages (65536 bytes) but can be changed via F_SETPIPE_SZ
 *     fcntl up to /proc/sys/fs/pipe-max-size (default 1MB). If pipe is full,
 *     the call blocks (without SPLICE_F_NONBLOCK) or returns EAGAIN.
 *
 * constraint: Maximum iovec segments
 *   desc: The nr_segs parameter cannot exceed UIO_MAXIOV (1024). This limit
 *     is imposed by the iovec handling code and matches limits on other
 *     vectored I/O syscalls like readv() and writev().
 *
 * constraint: Maximum transfer size
 *   desc: Total bytes transferred is capped at MAX_RW_COUNT (~2GB) per call.
 *     Individual iov_len values that would exceed this when summed are
 *     truncated. This prevents integer overflow in size calculations.
 *
 * examples: vmsplice(pipefd[1], iov, 2, 0);  // Block until space available
 *   vmsplice(pipefd[1], iov, 2, SPLICE_F_NONBLOCK);  // Return EAGAIN if full
 *   vmsplice(pipefd[1], iov, 2, SPLICE_F_GIFT);  // Donate pages to kernel
 *   vmsplice(pipefd[0], iov, 1, 0);  // Read from pipe to user buffer
 *
 * notes: vmsplice only achieves true zero-copy for user-to-pipe transfers.
 *   The pipe-to-user direction is implemented as a memcpy internally due to
 *   VM complexity. For best performance, use vmsplice to put data into a pipe,
 *   then splice(2) to move it to a socket or file.
 *
 *   The SPLICE_F_GIFT flag is important for correctness when the user buffer
 *   will be reused: it tells the kernel that subsequent splice operations may
 *   reuse the pages. Without this flag, modifying the user buffer while data
 *   is still in the pipe can cause data corruption.
 *
 *   FMODE_NOWAIT is explicitly cleared from pipe files when vmsplice is used
 *   to prevent interference with other pipe operations.
 *
 * since-version: 2.6.17
 */
SYSCALL_DEFINE4(vmsplice, int, fd, const struct iovec __user *, uiov,
		unsigned long, nr_segs, unsigned int, flags)
{
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	ssize_t error;
	int type;

	if (unlikely(flags & ~SPLICE_F_ALL))
		return -EINVAL;

	CLASS(fd, f)(fd);
	if (fd_empty(f))
		return -EBADF;
	if (fd_file(f)->f_mode & FMODE_WRITE)
		type = ITER_SOURCE;
	else if (fd_file(f)->f_mode & FMODE_READ)
		type = ITER_DEST;
	else
		return -EBADF;

	error = import_iovec(type, uiov, nr_segs,
			     ARRAY_SIZE(iovstack), &iov, &iter);
	if (error < 0)
		return error;

	if (!iov_iter_count(&iter))
		error = 0;
	else if (type == ITER_SOURCE)
		error = vmsplice_to_pipe(fd_file(f), &iter, flags);
	else
		error = vmsplice_to_user(fd_file(f), &iter, flags);

	kfree(iov);
	return error;
}

SYSCALL_DEFINE6(splice, int, fd_in, loff_t __user *, off_in,
		int, fd_out, loff_t __user *, off_out,
		size_t, len, unsigned int, flags)
{
	if (unlikely(!len))
		return 0;

	if (unlikely(flags & ~SPLICE_F_ALL))
		return -EINVAL;

	CLASS(fd, in)(fd_in);
	if (fd_empty(in))
		return -EBADF;

	CLASS(fd, out)(fd_out);
	if (fd_empty(out))
		return -EBADF;

	return __do_splice(fd_file(in), off_in, fd_file(out), off_out,
					    len, flags);
}

/*
 * Make sure there's data to read. Wait for input if we can, otherwise
 * return an appropriate error.
 */
static int ipipe_prep(struct pipe_inode_info *pipe, unsigned int flags)
{
	int ret;

	/*
	 * Check the pipe occupancy without the inode lock first. This function
	 * is speculative anyways, so missing one is ok.
	 */
	if (!pipe_is_empty(pipe))
		return 0;

	ret = 0;
	pipe_lock(pipe);

	while (pipe_is_empty(pipe)) {
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		if (!pipe->writers)
			break;
		if (flags & SPLICE_F_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		pipe_wait_readable(pipe);
	}

	pipe_unlock(pipe);
	return ret;
}

/*
 * Make sure there's writeable room. Wait for room if we can, otherwise
 * return an appropriate error.
 */
static int opipe_prep(struct pipe_inode_info *pipe, unsigned int flags)
{
	int ret;

	/*
	 * Check pipe occupancy without the inode lock first. This function
	 * is speculative anyways, so missing one is ok.
	 */
	if (!pipe_is_full(pipe))
		return 0;

	ret = 0;
	pipe_lock(pipe);

	while (pipe_is_full(pipe)) {
		if (!pipe->readers) {
			send_sig(SIGPIPE, current, 0);
			ret = -EPIPE;
			break;
		}
		if (flags & SPLICE_F_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		pipe_wait_writable(pipe);
	}

	pipe_unlock(pipe);
	return ret;
}

/*
 * Splice contents of ipipe to opipe.
 */
static int splice_pipe_to_pipe(struct pipe_inode_info *ipipe,
			       struct pipe_inode_info *opipe,
			       size_t len, unsigned int flags)
{
	struct pipe_buffer *ibuf, *obuf;
	unsigned int i_head, o_head;
	unsigned int i_tail, o_tail;
	int ret = 0;
	bool input_wakeup = false;


retry:
	ret = ipipe_prep(ipipe, flags);
	if (ret)
		return ret;

	ret = opipe_prep(opipe, flags);
	if (ret)
		return ret;

	/*
	 * Potential ABBA deadlock, work around it by ordering lock
	 * grabbing by pipe info address. Otherwise two different processes
	 * could deadlock (one doing tee from A -> B, the other from B -> A).
	 */
	pipe_double_lock(ipipe, opipe);

	i_tail = ipipe->tail;
	o_head = opipe->head;

	do {
		size_t o_len;

		if (!opipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		i_head = ipipe->head;
		o_tail = opipe->tail;

		if (pipe_empty(i_head, i_tail) && !ipipe->writers)
			break;

		/*
		 * Cannot make any progress, because either the input
		 * pipe is empty or the output pipe is full.
		 */
		if (pipe_empty(i_head, i_tail) ||
		    pipe_full(o_head, o_tail, opipe->max_usage)) {
			/* Already processed some buffers, break */
			if (ret)
				break;

			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}

			/*
			 * We raced with another reader/writer and haven't
			 * managed to process any buffers.  A zero return
			 * value means EOF, so retry instead.
			 */
			pipe_unlock(ipipe);
			pipe_unlock(opipe);
			goto retry;
		}

		ibuf = pipe_buf(ipipe, i_tail);
		obuf = pipe_buf(opipe, o_head);

		if (len >= ibuf->len) {
			/*
			 * Simply move the whole buffer from ipipe to opipe
			 */
			*obuf = *ibuf;
			ibuf->ops = NULL;
			i_tail++;
			ipipe->tail = i_tail;
			input_wakeup = true;
			o_len = obuf->len;
			o_head++;
			opipe->head = o_head;
		} else {
			/*
			 * Get a reference to this pipe buffer,
			 * so we can copy the contents over.
			 */
			if (!pipe_buf_get(ipipe, ibuf)) {
				if (ret == 0)
					ret = -EFAULT;
				break;
			}
			*obuf = *ibuf;

			/*
			 * Don't inherit the gift and merge flags, we need to
			 * prevent multiple steals of this page.
			 */
			obuf->flags &= ~PIPE_BUF_FLAG_GIFT;
			obuf->flags &= ~PIPE_BUF_FLAG_CAN_MERGE;

			obuf->len = len;
			ibuf->offset += len;
			ibuf->len -= len;
			o_len = len;
			o_head++;
			opipe->head = o_head;
		}
		ret += o_len;
		len -= o_len;
	} while (len);

	pipe_unlock(ipipe);
	pipe_unlock(opipe);

	/*
	 * If we put data in the output pipe, wakeup any potential readers.
	 */
	if (ret > 0)
		wakeup_pipe_readers(opipe);

	if (input_wakeup)
		wakeup_pipe_writers(ipipe);

	return ret;
}

/*
 * Link contents of ipipe to opipe.
 */
static ssize_t link_pipe(struct pipe_inode_info *ipipe,
			 struct pipe_inode_info *opipe,
			 size_t len, unsigned int flags)
{
	struct pipe_buffer *ibuf, *obuf;
	unsigned int i_head, o_head;
	unsigned int i_tail, o_tail;
	ssize_t ret = 0;

	/*
	 * Potential ABBA deadlock, work around it by ordering lock
	 * grabbing by pipe info address. Otherwise two different processes
	 * could deadlock (one doing tee from A -> B, the other from B -> A).
	 */
	pipe_double_lock(ipipe, opipe);

	i_tail = ipipe->tail;
	o_head = opipe->head;

	do {
		if (!opipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		i_head = ipipe->head;
		o_tail = opipe->tail;

		/*
		 * If we have iterated all input buffers or run out of
		 * output room, break.
		 */
		if (pipe_empty(i_head, i_tail) ||
		    pipe_full(o_head, o_tail, opipe->max_usage))
			break;

		ibuf = pipe_buf(ipipe, i_tail);
		obuf = pipe_buf(opipe, o_head);

		/*
		 * Get a reference to this pipe buffer,
		 * so we can copy the contents over.
		 */
		if (!pipe_buf_get(ipipe, ibuf)) {
			if (ret == 0)
				ret = -EFAULT;
			break;
		}

		*obuf = *ibuf;

		/*
		 * Don't inherit the gift and merge flag, we need to prevent
		 * multiple steals of this page.
		 */
		obuf->flags &= ~PIPE_BUF_FLAG_GIFT;
		obuf->flags &= ~PIPE_BUF_FLAG_CAN_MERGE;

		if (obuf->len > len)
			obuf->len = len;
		ret += obuf->len;
		len -= obuf->len;

		o_head++;
		opipe->head = o_head;
		i_tail++;
	} while (len);

	pipe_unlock(ipipe);
	pipe_unlock(opipe);

	/*
	 * If we put data in the output pipe, wakeup any potential readers.
	 */
	if (ret > 0)
		wakeup_pipe_readers(opipe);

	return ret;
}

/*
 * This is a tee(1) implementation that works on pipes. It doesn't copy
 * any data, it simply references the 'in' pages on the 'out' pipe.
 * The 'flags' used are the SPLICE_F_* variants, currently the only
 * applicable one is SPLICE_F_NONBLOCK.
 */
ssize_t do_tee(struct file *in, struct file *out, size_t len,
	       unsigned int flags)
{
	struct pipe_inode_info *ipipe = get_pipe_info(in, true);
	struct pipe_inode_info *opipe = get_pipe_info(out, true);
	ssize_t ret = -EINVAL;

	if (unlikely(!(in->f_mode & FMODE_READ) ||
		     !(out->f_mode & FMODE_WRITE)))
		return -EBADF;

	/*
	 * Duplicate the contents of ipipe to opipe without actually
	 * copying the data.
	 */
	if (ipipe && opipe && ipipe != opipe) {
		if ((in->f_flags | out->f_flags) & O_NONBLOCK)
			flags |= SPLICE_F_NONBLOCK;

		/*
		 * Keep going, unless we encounter an error. The ipipe/opipe
		 * ordering doesn't really matter.
		 */
		ret = ipipe_prep(ipipe, flags);
		if (!ret) {
			ret = opipe_prep(opipe, flags);
			if (!ret)
				ret = link_pipe(ipipe, opipe, len, flags);
		}
	}

	if (ret > 0) {
		fsnotify_access(in);
		fsnotify_modify(out);
	}

	return ret;
}

SYSCALL_DEFINE4(tee, int, fdin, int, fdout, size_t, len, unsigned int, flags)
{
	if (unlikely(flags & ~SPLICE_F_ALL))
		return -EINVAL;

	if (unlikely(!len))
		return 0;

	CLASS(fd, in)(fdin);
	if (fd_empty(in))
		return -EBADF;

	CLASS(fd, out)(fdout);
	if (fd_empty(out))
		return -EBADF;

	return do_tee(fd_file(in), fd_file(out), len, flags);
}
