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

#include <linux/random.h>
#include <linux/vmalloc.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/dnotify.h>

#include "mma_common.h"
#include "mma_core.h"
#include "mma_api.h"
#include "mma_ion.h"
#include "mma_of.h"
#include "mma_tee_inf.h"
#include "power.h"
//#include "mdrv_bdma.h"


extern struct mma_device mma_dev;

#if 0
int  mma_open(void)
{
    kref_get(&mma_dev->ref);
    return mma_ion_open(&mma_dev);
}
EXPORT_SYMBOL(mma_open);

static void __mma_ref_relase(struct kref * kref)
{
    struct mma_device *dev = container_of(kref, struct mma_device, ref);

    mma_ion_close(dev);
}

int  mma_release(void)
{
    kref_put(&mma_dev->ref, __mma_ref_relase);

    return 0;
}
EXPORT_SYMBOL(mma_release);
#else
int  mma_open(void)
{
    return 0;
}
EXPORT_SYMBOL(mma_open);


int  mma_release(void)
{
    return 0;
}
EXPORT_SYMBOL(mma_release);

#endif

int	mma_alloc(const char* buf_tag, u32 size, u64* addr_out, int* dmabuf_fd)
{
    int ret;

    ret = __mma_alloc_internal(buf_tag, size, false, addr_out, dmabuf_fd, MMA_FLAG_IOVA);

    return ret;
}
EXPORT_SYMBOL(mma_alloc);


int	mma_alloc_sec(const char* buf_tag, u32 size, u64* addr_out, int* dmabuf_fd)
{
    int ret;

    ret = __mma_alloc_internal(buf_tag, size, true, addr_out, dmabuf_fd, MMA_FLAG_IOVA);

    return ret;
}
EXPORT_SYMBOL(mma_alloc_sec);

int	mma_alloc_v2(const char* buf_tag, u32 size, u64* addr_out, int* dmabuf_fd, int flag)
{
    int ret;

    ret = __mma_alloc_internal(buf_tag, size, false, addr_out, dmabuf_fd, flag);

    return ret;
}
EXPORT_SYMBOL(mma_alloc_v2);

int	mma_map_iova(u64* addr_out, int dmabuf_fd)
{
    int ret = 0;
    struct mma_buf_handle *handle;
    struct dma_buf *db = NULL;
    char* space_tag = NULL;
    u64 addr = 0;
    struct timeval tv0, tv1;
    u32 maptime = 0;

    db = dma_buf_get(dmabuf_fd);
    CHECK_POINTER(db, -EINVAL);
    dma_buf_put(db);

    handle = (struct mma_buf_handle*)db->priv;
    CHECK_POINTER(handle, -EINVAL);
    CHECK_POINTER(handle->sgt, -EINVAL);
    if(mma_dev.record_alloc_time){
        memset(&tv0, 0, sizeof(struct timeval));
        memset(&tv1, 0, sizeof(struct timeval));
        do_gettimeofday(&tv0);
    }

    mutex_lock(&handle->handle_lock);
    if(handle->addr > 0){
        *addr_out = handle->addr;
        goto out;
    }
    __mma_get_space_tag(handle->buf_tag, &space_tag);

    ret = mma_tee_map(MMA_ADDR_TYPE_IOVA, space_tag, handle->sgt, false, &addr);
    if(ret != 0){
        printk(KERN_ERR"%s  %d,bugtag=%s Failed! \n",__FUNCTION__, __LINE__,handle->buf_tag);
        goto out;
    }

    handle->is_iova = addr & IOVA_START_ADDR;
    handle->addr = addr;
    *addr_out = handle->addr;

out:
    if(mma_dev.record_alloc_time){
        do_gettimeofday(&tv1);
        maptime = (tv1.tv_sec - tv0.tv_sec)*1000*1000 + (tv1.tv_usec - tv0.tv_usec);
        printk(KERN_ERR "%s  %d,handle addr=0x%llx ,addr=0x%llx, maptime(us) =%d!\n",__FUNCTION__, __LINE__,handle->addr,addr,maptime);
    }

    mutex_unlock(&handle->handle_lock);

    return ret;
}
EXPORT_SYMBOL(mma_map_iova);


int mma_reserve_iova_space(const char *space_tag, u64 size, u64* addr_out, int tag_num,  ...)
{
    int i, ret;
    char *temp;
    va_list ap;
    struct mma_reserve_iova_data data;

    CHECK_POINTER(space_tag, -EINVAL);
    CHECK_POINTER(addr_out, -EINVAL);
    if(size > MAX_IOVA_SIZE)
        return -EINVAL;
    if(tag_num > MAX_TAG_NUM)
        return -EINVAL;

    //fill data
    strncpy(data.space_tag, space_tag, MAX_NAME_SIZE);
    data.space_tag[MAX_NAME_SIZE - 1] = '\0';
    data.size = size;
    data.buf_tag_num = tag_num;

    va_start(ap, tag_num);
    for (i = 0; i < tag_num; i++) {
        temp = va_arg(ap, char*);
        strncpy(data.buf_tag_array[i], temp, MAX_NAME_SIZE);
        data.buf_tag_array[i][MAX_NAME_SIZE - 1] = '\0';
    }
    va_end(ap);

    ret = __mma_reserve_iova_internal(&data);
    CHECK_RETURN(ret);

    *addr_out = data.base_addr;
    MMA_DEBUG("space_tag:%s, base_addr=0x%llx\n",space_tag, *addr_out);

    return 0;
}
EXPORT_SYMBOL(mma_reserve_iova_space);


int mma_free_iova_space(const char *space_tag)
{
    CHECK_POINTER(space_tag, -EINVAL);
    MMA_DEBUG("space_tag:%s\n",space_tag);

    return __mma_free_iova_internal(space_tag);
}

EXPORT_SYMBOL(mma_free_iova_space);

int mma_get_pipeid(int *pipeid)
{
    int pipeid_tee;
    int ret;
    ret = mma_tee_get_pipeid(&pipeid_tee);
    CHECK_RETURN(ret);
    *pipeid = pipeid_tee;
    return 0;
}
EXPORT_SYMBOL(mma_get_pipeid);


int mma_buffer_authorize(int dmabuf_fd, int pipe_id)
{
    int ret = 0;
    enum mma_addr_type addr_type;
    struct mma_buf_handle *handle;
    struct dma_buf *db;

    db = dma_buf_get(dmabuf_fd);
    CHECK_POINTER(db, -EINVAL);
    dma_buf_put(db);

    handle = (struct mma_buf_handle*)db->priv;
    CHECK_POINTER(handle, -EINVAL);
    MMA_DEBUG("tag:%s,size=0x%x ,pipe_id=%d,addr=0x%llx\n",
        handle->buf_tag, handle->length, pipe_id, handle->addr);

    if(handle->auth_count > 0){
        handle->auth_count ++;
    }else{
        ret = mma_tee_authorize(handle->addr, handle->length,handle->buf_tag, (int)pipe_id);
        if(0 == ret){
            handle->pipe_id = pipe_id;
            handle->auth_count = 1;
        }
    }
    CHECK_RETURN(ret);

    return 0;
}
EXPORT_SYMBOL(mma_buffer_authorize);

int mma_buffer_unauthorize(int dmabuf_fd)
{
    struct dma_buf *dmabuf;
    int ret;
    struct mma_buf_handle *handle;
    enum mma_addr_type addr_type;
    struct mma_range_t range_out,range_out2;

    dmabuf = dma_buf_get(dmabuf_fd);
    CHECK_POINTER(dmabuf, -EINVAL);

    handle = (struct mma_buf_handle*)dmabuf->priv;
    CHECK_POINTER(handle, -EINVAL);
    MMA_DEBUG("tag:%s, addr=0x%llx\n",handle->buf_tag, handle->addr);

    //unauthorize
    if(handle->auth_count == 1){
        if(handle->is_secure) {
            ret = mma_tee_unauthorize(handle->addr,handle->length,handle->buf_tag,handle->pipe_id,&range_out);
            if (MMA_UNAUTH_DELAY_FREE == ret) {
                list_add(&handle->dfree_list_node, &mma_dev.dfree_list_head);
            } else if (MMA_UNAUTH_FREE_RANGE == ret){
                handle->auth_count = 0;
                list_for_each_entry(handle, &mma_dev.dfree_list_head, dfree_list_node) {
                    if((handle->addr >= range_out.start) &&(handle->addr < (range_out.start+ range_out.size))) {
                       list_del(&handle->dfree_list_node);
                       ret = mma_tee_unauthorize(handle->addr,handle->length,handle->buf_tag,handle->pipe_id,&range_out2);
                       handle->auth_count = 0;
                    }
                }
            }else if (MMA_UNAUTH_SUCCESS == ret){
                handle->auth_count = 0;
            }
        }
    }else if(handle->auth_count > 1){
        handle->auth_count--;
    }
    dma_buf_put(dmabuf);
    return 0;
}
EXPORT_SYMBOL(mma_buffer_unauthorize);

int mma_physical_buffer_authorize(const char* buf_tag,u64 addr, u32 size,u32 pipe_id)
{
    int ret = 0,found = 0;
    struct mma_buf_handle *handle;

    mutex_lock(&mma_dev.buf_lock);
    list_for_each_entry(handle, &mma_dev.physical_buf_list_head, buf_list_node) {
        if(handle->addr <= addr && (handle->addr + handle->length) > addr){
            found = 1;
            break;
        }
    }
    mutex_unlock(&mma_dev.buf_lock);

    if(found){
        handle->auth_count++;
    }else{
        ret = mma_tee_authorize(addr, size,buf_tag, (int)pipe_id);
        if(0 == ret){
            handle = kzalloc(sizeof(*handle), GFP_KERNEL);
            if (IS_ERR_OR_NULL(handle))
            {
                printk("%s  %d,pointer is NULL or Error\n",__FUNCTION__, __LINE__);
                return ERR_PTR(ENOMEM);
            }
            handle->pipe_id = pipe_id;
            handle->auth_count = 1;
            handle->addr = addr;
            handle->length = size;
            strncpy(handle->buf_tag, buf_tag, MAX_NAME_SIZE);
            handle->buf_tag[MAX_NAME_SIZE - 1] = '\0';
            mutex_lock(&mma_dev.buf_lock);
            list_add(&handle->buf_list_node, &mma_dev.physical_buf_list_head);
            mutex_unlock(&mma_dev.buf_lock);
        }
    }

    CHECK_RETURN(ret);

    return 0;
}
EXPORT_SYMBOL(mma_physical_buffer_authorize);

int mma_physical_buffer_unauthorize(u64 addr,bool force)
{
    int ret = 0,found = 0;
    struct mma_buf_handle *handle,*tmp;
    struct mma_range_t range_out,range_out2;
    MMA_DEBUG("addr=0x%llx ,force=%d\n", addr,force);
    mutex_lock(&mma_dev.buf_lock);
    list_for_each_entry(handle, &mma_dev.physical_buf_list_head, buf_list_node) {
        if(handle->addr <= addr && (handle->addr + handle->length) > addr){
            found = 1;
            break;
        }
    }
    mutex_unlock(&mma_dev.buf_lock);

    if(found){
        if((force && handle->auth_count != 0) || handle->auth_count == 1){
            handle->auth_count = 0;
            ret = mma_tee_unauthorize(handle->addr,handle->length,handle->buf_tag,handle->pipe_id,&range_out);
            if (MMA_UNAUTH_DELAY_FREE == ret) {
                mutex_lock(&mma_dev.buf_lock);
                list_del(&handle->buf_list_node);
                list_add(&handle->dfree_list_node, &mma_dev.physical_dfree_list_head);
                mutex_unlock(&mma_dev.buf_lock);
                goto out;
            } else if (MMA_UNAUTH_FREE_RANGE == ret){
                mutex_lock(&mma_dev.buf_lock);
                list_for_each_entry(tmp, &mma_dev.physical_dfree_list_head, dfree_list_node) {
                    if((tmp->addr >= range_out.start) &&(tmp->addr < (range_out.start+ range_out.size))) {
                        list_del(&tmp->dfree_list_node);
                        mutex_unlock(&mma_dev.buf_lock);
                        ret = mma_tee_unauthorize(tmp->addr,tmp->length,tmp->buf_tag,tmp->pipe_id,&range_out2);
                        mutex_lock(&mma_dev.buf_lock);
                        kfree(tmp);
                        tmp = NULL;
                    }
                }
                mutex_unlock(&mma_dev.buf_lock);
            }
        }else if(handle->auth_count > 1){
            handle->auth_count--;
            goto out;
        }else{
            //handle->auth_count == 0,do nothing
        }
        mutex_lock(&mma_dev.buf_lock);
        list_del(&handle->buf_list_node);
        mutex_unlock(&mma_dev.buf_lock);
        kfree(handle);
    }
out:

    return 0;
}
EXPORT_SYMBOL(mma_physical_buffer_unauthorize);

int mma_free(int dmabuf_fd)
{
#if defined(CONFIG_MP_MSTAR_STR_BASE)
	struct task_struct *task = current;
	int ret = 0;
	struct file *file;
	struct fdtable *fdt;
	struct files_struct *files = current->files;
	struct mma_buf_handle *handle;
	struct dma_buf *db = dma_buf_get(dmabuf_fd);

	if(IS_ERR_OR_NULL(db))
		goto out;
	dma_buf_put(db);
	handle = (struct mma_buf_handle*)db->priv;

	if((get_state_value() != STENT_RESUME_FROM_SUSPEND)) {
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		if (dmabuf_fd >= fdt->max_fds){
			spin_unlock(&files->file_lock);
			goto out;
		}
		file = fdt->fd[dmabuf_fd];
		if (!file){
			spin_unlock(&files->file_lock);
			goto out;
		}
		rcu_assign_pointer(fdt->fd[dmabuf_fd], NULL);
		spin_unlock(&files->file_lock);
		set_close_on_exec(dmabuf_fd, 0);
		put_unused_fd(dmabuf_fd);
		MMA_DEBUG("file count=%d\n", file_count(file));
		if (!file_count(file)) {
			printk(KERN_ERR " mma_free: file count is 0\n");
			return 0;
		}
		if (file->f_op->flush)
			ret = file->f_op->flush(file, files);
		if (likely(!(file->f_mode & FMODE_PATH))) {
			dnotify_flush(file, files);
			locks_remove_posix(file, files);
		}
		if(task->flags & PF_KTHREAD){
			MMA_DEBUG("fd=%d\n", dmabuf_fd);
			__fput_sync(file);
		}else{
			MMA_DEBUG("fd=%d\n", dmabuf_fd);
			if(file_count(file) == 1){
				__mma_handle_release(handle);
			}
			fput(file);
		}
		return 0;
	}
out:
#endif

	MMA_DEBUG("fd=%d\n", dmabuf_fd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
	ksys_close(dmabuf_fd);
#else
	sys_close(dmabuf_fd);
#endif
	return 0;
}
EXPORT_SYMBOL(mma_free);

void mma_dmabuf_put(struct dma_buf *db)
{
#if defined(CONFIG_MP_MSTAR_STR_BASE)
	struct mma_buf_handle *handle;
	struct file *file;
	struct task_struct *task = current;

	if(IS_ERR_OR_NULL(db))
		return;
	handle = (struct mma_buf_handle*)db->priv;
	file = db->file;
	if(IS_ERR_OR_NULL(file))
		return;
	MMA_DEBUG("addr=0x%llx, file count=%d\n", handle->addr, file_count(file));
	if((get_state_value() != STENT_RESUME_FROM_SUSPEND)) {
		if(task->flags & PF_KTHREAD)
			__fput_sync(file);
		else{
			if(file_count(file) == 1){
				__mma_handle_release(handle);
			}
			dma_buf_put(db);
		}
	}else
		dma_buf_put(db);

#else
	MMA_DEBUG("put");
	dma_buf_put(db);
#endif
	return;
}
EXPORT_SYMBOL(mma_dmabuf_put);

void* mma_map(int dmabuf_fd, bool cached, u32 offset, u32 size)
{
    void* vaddr;
	unsigned long page_offset = offset >> PAGE_SHIFT;
    struct mma_buf_handle *handle;
    struct dma_buf *db = dma_buf_get(dmabuf_fd);
    CHECK_POINTER(db, -EINVAL);
    dma_buf_put(db); //dereference count

    handle = (struct mma_buf_handle*)db->priv;
    CHECK_POINTER(handle, -EINVAL);
    MMA_DEBUG("fd=%d,addr=0x%llx ,offset=0x%x,size=0x%x\n", dmabuf_fd,handle->addr,offset,size);
    if(handle->kvaddr){
        handle->kmap_cnt ++;
        return handle->kvaddr;
    }

    __mma_set_cache_flag(dmabuf_fd, cached);

    vaddr = __mma_kmap_internel(db, offset, size);
    handle->kvaddr = vaddr;
    handle->kmap_cnt = 1;

    return vaddr;
}
EXPORT_SYMBOL(mma_map);

extern void Chip_Flush_Cache_Range(unsigned long vaddr, unsigned long u32Size); //Clean & Invalid L1/L2 cache

int mma_flush(void* vadrr, u32 size)
{
    Chip_Flush_Cache_Range((unsigned long)vadrr, size);

    return 0;
}
EXPORT_SYMBOL(mma_flush);


int mma_unmap (void* vaddr, u32 size)
{
    int ret;
	struct mma_buf_handle* handle;

    handle = __mma_find_buf_handle(vaddr);
    CHECK_POINTER(handle, -EINVAL);
    MMA_DEBUG("addr=0x%llx ,va=%p\n", handle->addr,vaddr);
    handle->kmap_cnt --;
    if(handle->kmap_cnt)
        return 0;

    ret = __mma_kunmap_internel(handle->dmabuf, vaddr, size);
    CHECK_RETURN(ret);

    handle->kvaddr = NULL;
    return 0;
}
EXPORT_SYMBOL(mma_unmap);


int mma_export_globalname(int dmabuf_fd)
{
    int ret;
    struct dma_buf *db;
    struct mma_buf_handle *handle;

    db = dma_buf_get(dmabuf_fd);
    CHECK_POINTER(db, -EINVAL);
    handle = (struct mma_buf_handle*)db->priv;

    mutex_lock(&mma_dev.buf_lock);
    if (handle->global_name <0) {
        ret = idr_alloc(&mma_dev.global_name_idr, db, 1, 0, GFP_KERNEL);
        if (ret < 0) {
            mutex_unlock(&mma_dev.buf_lock);
            dma_buf_put(db);
            PRINT_AND_RETURN(ret);
        }
        handle->global_name = ret;
    }
    mutex_unlock(&mma_dev.buf_lock);
	dma_buf_put(db);
    return handle->global_name;
}
EXPORT_SYMBOL(mma_export_globalname);

int mma_import_globalname(int name)
{
    struct dma_buf *db;
    int fd = -1;

    mutex_lock(&mma_dev.buf_lock);
    db = idr_find(&mma_dev.global_name_idr, name);
    if (IS_ERR_OR_NULL(db)) {
        mutex_unlock(&mma_dev.buf_lock);
        PRINT_AND_RETURN(ERR_PTR(-ENOENT));
    }
    fd = dma_buf_fd(db, O_CLOEXEC);
    if (fd < 0) {
        mutex_unlock(&mma_dev.buf_lock);
        PRINT_AND_RETURN(ERR_PTR(fd));
    }

    db = dma_buf_get(fd);
    mutex_unlock(&mma_dev.buf_lock);

    return fd;
}
EXPORT_SYMBOL(mma_import_globalname);


int mma_get_meminfo(int dmabuf_fd, struct mma_meminfo_t *mem_info)
{
    int ret;
    u64 addr;
    struct dma_buf_attachment *attach;
    struct sg_table *sgt;
    struct mma_buf_handle *handle;
    struct dma_buf *db;

    db = dma_buf_get(dmabuf_fd);
    CHECK_POINTER(db, -EINVAL);

    if(__is_mma_dmabuf(db)) {
        handle = db->priv;
    } else {
        attach = dma_buf_attach(db, mma_dev.misc_dev.this_device);
        if (IS_ERR(attach)) {
            dma_buf_put(db);
            PRINT_AND_RETURN(PTR_ERR(attach));
        }

        sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
        if (IS_ERR(sgt)) {
            dma_buf_detach(db, attach);
            dma_buf_put(db);
            PRINT_AND_RETURN(PTR_ERR(sgt));
        }

        ret = mma_tee_map(MMA_ADDR_TYPE_IOVA, NULL, sgt, false, &addr);
        if (ret < 0) {
            dma_buf_detach(db, attach);
            dma_buf_put(db);
            PRINT_AND_RETURN(ret);
        }

        handle = __mma_create_buf_handle(db->size, "import_buf");
        if (IS_ERR(handle)) {
            dma_buf_detach(db, attach);
            dma_buf_put(db);
            PRINT_AND_RETURN(PTR_ERR(handle));
        }
		
        handle->db_ion = db;
        handle->addr = addr;
        handle->is_secure = false;
        mutex_lock(&mma_dev.buf_lock);
        list_add(&handle->buf_list_node, &mma_dev.buf_list_head);
        mutex_unlock(&mma_dev.buf_lock);
    }
    mem_info->addr = handle->addr;
    mem_info->size = handle->length;
    mem_info->secure = handle->is_secure;
    mem_info->iova = handle->is_iova;
    mem_info->miu_select = (char)handle->miu_select;

    dma_buf_put(db);
    return 0;
}
EXPORT_SYMBOL(mma_get_meminfo);

#ifdef CONFIG_MP_MMA_CMA_ENABLE
extern int mma_get_heap_info(unsigned int miu,unsigned long *phy,unsigned long *size);
#endif
int mma_get_heapinfo(const char* buf_tag, struct mma_heapinfo_t* heap_info)
{
    int ret, miu;
    uint64_t maxsize;
    char heapname[16];
    enum mma_of_heap_type heap_type;

    CHECK_POINTER(buf_tag, -EINVAL);
    CHECK_POINTER(heap_info, -EINVAL);

    ret = mma_of_get_buftag_info(buf_tag, &heap_type, &miu, &maxsize,NULL);
    CHECK_RETURN(ret);

    if((miu >3 )|| (heap_type>HEAP_TYPE_MAX))
        return -1;

    if(heap_type ==HEAP_TYPE_CMA ) {
#ifdef CONFIG_MP_MMA_CMA_ENABLE
        mma_get_heap_info( miu, &heap_info->base_addr, &heap_info->size);
        snprintf(heapname, sizeof(heapname), "cma_heap_%d", miu);
        strncpy(heap_info->name, heapname, sizeof(heapname));
        heap_info->name[15] = '\0';
#else
        printk("MMA CMA not support\n");
        return -1;
#endif
    } else {
        heap_info->base_addr = IOVA_START_ADDR;
        heap_info->size = MAX_IOVA_SIZE;
        snprintf(heapname, sizeof(heapname), "iommu_heap_%d", miu);
        strncpy(heap_info->name, heapname, sizeof(heapname));
        heap_info->name[15] = '\0';
    }
    return 0;
}
EXPORT_SYMBOL(mma_get_heapinfo);


int mma_query_buf_tag(const char* buf_tag, u32* heap_type, u32* miu_number, u32* max_size)
{
    int ret, miu;
    uint64_t maxsize;
    enum mma_of_heap_type heaptype;

    ret = mma_of_get_buftag_info(buf_tag, &heaptype, &miu, &maxsize,NULL);
    if(ret < 0)
		return ret;

    *heap_type = heaptype;
    *miu_number = miu;
    *max_size = (u32)maxsize;
    return 0;
}
EXPORT_SYMBOL(mma_query_buf_tag);

int mma_pipelineID_query(u64 addr, u32* u32pipelineID)
{
    int ret;

    CHECK_POINTER(u32pipelineID, -EINVAL);

    ret = mma_tee_pipelineID_query (addr,u32pipelineID);
    CHECK_RETURN(ret);

    return 0;
}
EXPORT_SYMBOL(mma_pipelineID_query);

int mma_globalname_query(u64 addr, u32* name,u64 *buf_start)
{
    int ret;
    struct mma_buf_handle* handle;

    CHECK_POINTER(name, -EINVAL);
    mutex_lock(&mma_dev.buf_lock);
    list_for_each_entry(handle, &mma_dev.buf_list_head, buf_list_node) {
        if(handle->addr <= addr && addr < (handle->addr + handle->length)){
            if(handle->global_name < 0){
                mutex_unlock(&mma_dev.buf_lock);
                return -1;
            }else{
                *name = handle->global_name;
                *buf_start = handle->addr;
                mutex_unlock(&mma_dev.buf_lock);
                return 0;
            }
        }
    }
    mutex_unlock(&mma_dev.buf_lock);
    return -1;
}
EXPORT_SYMBOL(mma_globalname_query);
