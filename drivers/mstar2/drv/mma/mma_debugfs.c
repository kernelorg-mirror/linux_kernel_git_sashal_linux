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

#include <linux/seq_file.h>
#include <linux/file.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
#include <linux/uaccess.h>
#endif

#include "mma_common.h"
#include "mma_core.h"
#include "mma_api.h"

extern struct mma_device mma_dev;

/*
1. list all memory info allocated by mma api
echo 1 > debug/mma/record_time   //record alloc time
cat debug/mma/meminfo //list mem info
format:
serial    buf_tag    addr    size    pid    secure  alloc_time(us)

*/

/*
2. open call trace
echo 1> /debug/mma/calltrace_enable
*/

/*
3. dump memory content allocated by mma api
cat /debug/mma/buffer/xxx, xxx 代表要显示calltrace的buffer handle serial。

*/


static int mma_meminfo_show(struct seq_file *s, void *unused)
{
	struct mma_device* mma_dev = s->private;
    struct mma_buf_handle* handle;

    mutex_lock(&mma_dev->buf_lock);
    if(mma_dev->record_alloc_time) {
        seq_printf(s, "%16.s %16.s %16.s %16.s %16.s %16.s %16.s %16.s\n", "serial", "buf_tag", "addr", "size", "pid", "secure", "iova", "alloc_time(us)");

        list_for_each_entry(handle, &mma_dev->buf_list_head, buf_list_node) {
            seq_printf(s, "%16d %16.s %16llx %16x %16d %16d %16d %16d\n", handle->serial, handle->buf_tag, handle->addr,
                       (u32)handle->length, handle->tpid, handle->auth_count>0?1:0, handle->is_iova?1:0, handle->alloc_time_ms);
        }
    } else {
        seq_printf(s, "%16.s %16.s %16.s %16.s %16.s %16.s %16.s\n", "serial", "buf_tag", "addr", "size", "pid", "secure", "iova");

        list_for_each_entry(handle, &mma_dev->buf_list_head, buf_list_node) {
            seq_printf(s,  "%16d %16.s %16llx %16x %16d %16d %16d\n", handle->serial, handle->buf_tag, handle->addr,
                       (u32)handle->length, handle->tpid, handle->auth_count>0?1:0, handle->is_iova?1:0);
        }
    }

    mutex_unlock(&mma_dev->buf_lock);
	return 0;
}

static int mma_meminfo_open(struct inode *inode, struct file *file)
{
	return single_open(file, mma_meminfo_show, inode->i_private);
}

static const struct file_operations mma_meminfo_ops = {
	.open = mma_meminfo_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static unsigned long mma_interrupt_debug = 1;

unsigned long mma_get_interrupt_debug(void)
{
	return mma_interrupt_debug;
}

static ssize_t mma_interrupt_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *ppos)
{
	char buf[10];
	if(count > 10)
		return -EINVAL;
	if (copy_from_user(buf, buffer, count))
		return -EFAULT;

	mma_interrupt_debug = simple_strtoul(buf,(char **)&buf,10);
	if(mma_interrupt_debug == 1){
		printk("interrupt = 1:enable interrupt\n");
	}

	return count;
}


static int mma_interrupt_show(struct seq_file *s, void *unused)
{
	seq_printf(s, "%d\n", mma_interrupt_debug);

	return 0;
}

static int mma_interrupt_open(struct inode *inode, struct file *file)
{
	return single_open(file, mma_interrupt_show, inode->i_private);
}


static const struct file_operations mma_interrupt_ops = {
	.open = mma_interrupt_open,
	.write = mma_interrupt_write,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


static int mma_buf_dump_open(struct inode *inode, struct file *file)
{
    int ret;
    void* vaddr;
    struct dma_buf *db;
    struct mma_buf_handle* handle;
    struct file* filep;
    loff_t pos =0;

    simple_open(inode, file);

	handle = file->private_data;
    CHECK_POINTER(handle, -EFAULT);

    if(handle->is_secure)
        return -EACCES;

    db = handle->dmabuf;
    CHECK_POINTER(handle, -EFAULT);

    if(handle->kvaddr == NULL) {
        vaddr = __mma_kmap_internel(db, 0, handle->length);
        if(vaddr == NULL)
            goto out;
        handle->kvaddr = vaddr;
    }
    //todo, save memory to file
    //memset(vaddr, 0x55, handle->length);
    filep = filp_open("/data/mmabuf/1.bin", O_CREAT | O_RDWR | O_NOFOLLOW | O_LARGEFILE | O_EXCL, 0660);
    if (IS_ERR(filep)) {
        printk("mma_buf_dump_open: file opten failed, err=%d \n", PTR_ERR(filep));
    }
	ret = __kernel_write(filep, vaddr, handle->length, &pos);

    if(handle->kvaddr != NULL) {
        __mma_kunmap_internel(db, vaddr, handle->length);
        handle->kvaddr = NULL;
    }

    filp_close(filep, NULL);
out:
    return 0;
}

static ssize_t mma_buf_dump_read(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct mma_buf_handle* handle = file->private_data;
	int ret;

    CHECK_POINTER(user_buf, -EFAULT);

    if(handle->is_secure)
        return -EACCES;

    if(handle->kvaddr == NULL)
        return -EFAULT;

    //mutex_lock(&mma_dev.buf_lock);
	//ret = simple_read_from_buffer(user_buf, count, ppos, handle->kvaddr, handle->length);
    //mutex_unlock(&mma_dev.buf_lock);
    //CHECK_RETURN(ret);
    printk("mma_buf_dump_read: sucess \n");

    return 0;
}

static ssize_t mma_buf_dump_write(struct file *file,
				      const char __user *user_buf, size_t count,
				      loff_t *ppos)
{
	struct mma_buf_handle* handle = file->private_data;


	return count;
}


static const struct file_operations mma_buffer_dump_ops = {
	.open = mma_buf_dump_open,
	.read = mma_buf_dump_read,
	.write = mma_buf_dump_write,

};

int mma_creat_buffer_file(struct mma_buf_handle* handle, struct dentry* parent)
{
	struct dentry *entry;

    char strbuf[64];
    snprintf(strbuf, sizeof(strbuf), "%u", handle->serial);

    //printk("mma_creat_buffer_file handle = %p\n", handle);
    entry = debugfs_create_file(strbuf, 0664, parent, handle, &mma_buffer_dump_ops);
	if (!entry)
		printk("mma: failed to create calltrace file.\n");
    handle->entry = entry;
    return 0;
}

int mma_debugfs_init(struct mma_device* mma_dev)
{
	struct dentry *entry;

	mma_dev->debug_root = debugfs_create_dir("mma", NULL);
	if (!mma_dev->debug_root) {
		printk("mma: failed to create debugfs root directory.\n");
	}
	mma_dev->buf_debug_root = debugfs_create_dir("buffer", mma_dev->debug_root);
	if (!mma_dev->buf_debug_root) {
		printk("mma: failed to create debugfs buffer directory.\n");
	}

    entry = debugfs_create_file("meminfo", 0664, mma_dev->debug_root, mma_dev, &mma_meminfo_ops);
	if (!entry)
		printk("mma: failed to create meminfo file.\n");

	entry = debugfs_create_file("interrupt", 0664, mma_dev->debug_root, mma_dev, &mma_interrupt_ops);
	if (!entry)
		printk("mma: failed to create interrupt file.\n");

    entry  = debugfs_create_bool("record_time", 0664, mma_dev->debug_root, (bool *)&mma_dev->record_alloc_time);
	if (!entry)
		printk("mma: failed to create record_time file.\n");

    entry  = debugfs_create_u32("calltrace_enable", 0664, mma_dev->debug_root, &mma_dev->calltrace_enable);
	if (!entry)
		printk("mma: failed to create record_time file.\n");

    return 0;
}

int mma_debugfs_destroy(struct mma_device* mma_dev)
{
    if (mma_dev->debugfs_root)
        debugfs_remove_recursive(mma_dev->debug_root);
    return 0;
}
