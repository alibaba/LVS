/****************************************************************************
 *  flashcache_subr.c
 *  FlashCache: Device mapper target for block-level disk caching
 *
 *  Copyright 2010 Facebook, Inc.
 *  Author: Mohan Srinivasan (mohan@fb.com)
 *
 *  Based on DM-Cache:
 *   Copyright (C) International Business Machines Corp., 2006
 *   Author: Ming Zhao (mingzhao@ufl.edu)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ****************************************************************************/

#include <asm/atomic.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/hardirq.h>
#include <linux/sysctl.h>
#include <linux/version.h>
#include <linux/sort.h>
#include <linux/time.h>
#include <asm/kmap_types.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#include "dm.h"
#include "dm-io.h"
#include "dm-bio-list.h"
#include "kcopyd.h"
#else
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,27)
#include "dm.h"
#endif
#include <linux/device-mapper.h>
#include <linux/bio.h>
#include <linux/dm-kcopyd.h>
#endif
#include "flashcache.h"

static DEFINE_SPINLOCK(_job_lock);

extern mempool_t *_job_pool;
extern mempool_t *_pending_job_pool;

extern atomic_t nr_cache_jobs;
extern atomic_t nr_pending_jobs;

LIST_HEAD(_pending_jobs);
LIST_HEAD(_io_jobs);
LIST_HEAD(_md_io_jobs);
LIST_HEAD(_md_complete_jobs);
LIST_HEAD(_uncached_io_complete_jobs);

int
flashcache_pending_empty(void)
{
	return list_empty(&_pending_jobs);
}

int
flashcache_io_empty(void)
{
	return list_empty(&_io_jobs);
}

int
flashcache_md_io_empty(void)
{
	return list_empty(&_md_io_jobs);
}

int
flashcache_md_complete_empty(void)
{
	return list_empty(&_md_complete_jobs);
}

int
flashcache_uncached_io_complete_empty(void)
{
	return list_empty(&_uncached_io_complete_jobs);
}

struct kcached_job *
flashcache_alloc_cache_job(void)
{
	struct kcached_job *job;

	job = mempool_alloc(_job_pool, GFP_NOIO);
	if (likely(job))
		atomic_inc(&nr_cache_jobs);
	return job;
}

void
flashcache_free_cache_job(struct kcached_job *job)
{
	mempool_free(job, _job_pool);
	atomic_dec(&nr_cache_jobs);
}

struct pending_job *
flashcache_alloc_pending_job(struct cache_c *dmc)
{
	struct pending_job *job;

	job = mempool_alloc(_pending_job_pool, GFP_ATOMIC);
	if (likely(job))
		atomic_inc(&nr_pending_jobs);
	else
		dmc->flashcache_errors.memory_alloc_errors++;
	return job;
}

void
flashcache_free_pending_job(struct pending_job *job)
{
	mempool_free(job, _pending_job_pool);
	atomic_dec(&nr_pending_jobs);
}

#define FLASHCACHE_PENDING_JOB_HASH(INDEX)		((INDEX) % PENDING_JOB_HASH_SIZE)

void
flashcache_enq_pending(struct cache_c *dmc, struct bio* bio,
		       int index, int action, struct pending_job *job)
{
	struct pending_job **head;

	head = &dmc->pending_job_hashbuckets[FLASHCACHE_PENDING_JOB_HASH(index)];
	DPRINTK("flashcache_enq_pending: Queue to pending Q Index %d %llu",
		index, bio->bi_sector);
	VERIFY(job != NULL);
	job->action = action;
	job->index = index;
	job->bio = bio;
	job->prev = NULL;
	job->next = *head;
	if (*head)
		(*head)->prev = job;
	*head = job;
	dmc->cache[index].nr_queued++;
	dmc->flashcache_stats.enqueues++;
	dmc->pending_jobs_count++;
}

/*
 * Deq and move all pending jobs that match the index for this slot to list returned
 */
struct pending_job *
flashcache_deq_pending(struct cache_c *dmc, int index)
{
	struct pending_job *node, *next, *movelist = NULL;
	int moved = 0;
	struct pending_job **head;

	VERIFY(spin_is_locked(&dmc->cache_spin_lock));
	head = &dmc->pending_job_hashbuckets[FLASHCACHE_PENDING_JOB_HASH(index)];
	for (node = *head ; node != NULL ; node = next) {
		next = node->next;
		if (node->index == index) {
			/*
			 * Remove pending job from the global list of
			 * jobs and move it to the private list for freeing
			 */
			if (node->prev == NULL) {
				*head = node->next;
				if (node->next)
					node->next->prev = NULL;
			} else
				node->prev->next = node->next;
			if (node->next == NULL) {
				if (node->prev)
					node->prev->next = NULL;
			} else
				node->next->prev = node->prev;
			node->prev = NULL;
			node->next = movelist;
			movelist = node;
			moved++;
		}
	}
	VERIFY(dmc->pending_jobs_count >= moved);
	dmc->pending_jobs_count -= moved;
	return movelist;
}

#ifdef FLASHCACHE_DO_CHECKSUMS
int
flashcache_read_compute_checksum(struct cache_c *dmc, int index, void *block)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	struct io_region where;
#else
	struct dm_io_region where;
#endif
	int error;
	u_int64_t sum = 0, *idx;
	int cnt;

	where.bdev = dmc->cache_dev->bdev;
	where.sector = INDEX_TO_CACHE_ADDR(dmc, index);
	where.count = dmc->block_size;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	error = flashcache_dm_io_sync_vm(dmc, &where, READ, block);
#else
	error = flashcache_dm_io_sync_vm(dmc, &where, READ, block);
#endif
	if (error)
		return error;
	cnt = dmc->block_size * 512;
	idx = (u_int64_t *)block;
	while (cnt > 0) {
		sum += *idx++;
		cnt -= sizeof(u_int64_t);
	}
	dmc->cache[index].checksum = sum;
	return 0;
}

u_int64_t
flashcache_compute_checksum(struct bio *bio)
{
	int i;
	u_int64_t sum = 0, *idx;
	int cnt;
	int kmap_type;
	void *kvaddr;

	if (in_interrupt())
		kmap_type = KM_SOFTIRQ0;
	else
		kmap_type = KM_USER0;
	for (i = bio->bi_idx ; i < bio->bi_vcnt ; i++) {
		kvaddr = kmap_atomic(bio->bi_io_vec[i].bv_page, kmap_type);
		idx = (u_int64_t *)
			((char *)kvaddr + bio->bi_io_vec[i].bv_offset);
		cnt = bio->bi_io_vec[i].bv_len;
		while (cnt > 0) {
			sum += *idx++;
			cnt -= sizeof(u_int64_t);
		}
		kunmap_atomic(kvaddr, kmap_type);
	}
	return sum;
}

void
flashcache_store_checksum(struct kcached_job *job)
{
	u_int64_t sum;
	unsigned long flags;

	sum = flashcache_compute_checksum(job->bio);
	spin_lock_irqsave(&job->dmc->cache_spin_lock, flags);
	job->dmc->cache[job->index].checksum = sum;
	spin_unlock_irqrestore(&job->dmc->cache_spin_lock, flags);
}

int
flashcache_validate_checksum(struct kcached_job *job)
{
	u_int64_t sum;
	int retval;
	unsigned long flags;

	sum = flashcache_compute_checksum(job->bio);
	spin_lock_irqsave(&job->dmc->cache_spin_lock, flags);
	if (likely(job->dmc->cache[job->index].checksum == sum)) {
		job->dmc->flashcache_stats.checksum_valid++;
		retval = 0;
	} else {
		job->dmc->flashcache_stats.checksum_invalid++;
		retval = 1;
	}
	spin_unlock_irqrestore(&job->dmc->cache_spin_lock, flags);
	return retval;
}
#endif

/*
 * Functions to push and pop a job onto the head of a given job list.
 */
struct kcached_job *
pop(struct list_head *jobs)
{
	struct kcached_job *job = NULL;
	unsigned long flags;

	spin_lock_irqsave(&_job_lock, flags);
	if (!list_empty(jobs)) {
		job = list_entry(jobs->next, struct kcached_job, list);
		list_del(&job->list);
	}
	spin_unlock_irqrestore(&_job_lock, flags);
	return job;
}

void
push(struct list_head *jobs, struct kcached_job *job)
{
	unsigned long flags;

	spin_lock_irqsave(&_job_lock, flags);
	list_add_tail(&job->list, jobs);
	spin_unlock_irqrestore(&_job_lock, flags);
}

void
push_pending(struct kcached_job *job)
{
	push(&_pending_jobs, job);
}

void
push_io(struct kcached_job *job)
{
	push(&_io_jobs, job);
}

void
push_uncached_io_complete(struct kcached_job *job)
{
	push(&_uncached_io_complete_jobs, job);
}

void
push_md_io(struct kcached_job *job)
{
	push(&_md_io_jobs, job);
}

void
push_md_complete(struct kcached_job *job)
{
	push(&_md_complete_jobs, job);
}

static void
process_jobs(struct list_head *jobs,
	     void (*fn) (struct kcached_job *))
{
	struct kcached_job *job;

	while ((job = pop(jobs)))
		(void)fn(job);
}

void
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
do_work(void *unused)
#else
do_work(struct work_struct *unused)
#endif
{
	process_jobs(&_md_complete_jobs, flashcache_md_write_done);
	process_jobs(&_pending_jobs, flashcache_do_pending);
	process_jobs(&_md_io_jobs, flashcache_md_write_kickoff);
	process_jobs(&_io_jobs, flashcache_do_io);
	process_jobs(&_uncached_io_complete_jobs, flashcache_uncached_io_complete);
}

extern int sysctl_flashcache_lat_hist;

struct kcached_job *
new_kcached_job(struct cache_c *dmc, struct bio* bio, int index)
{
	struct kcached_job *job;

	job = flashcache_alloc_cache_job();
	if (unlikely(job == NULL)) {
		dmc->flashcache_errors.memory_alloc_errors++;
		return NULL;
	}
	job->dmc = dmc;
	job->index = index;
	job->cache.bdev = dmc->cache_dev->bdev;
	if (index != -1) {
		job->cache.sector = INDEX_TO_CACHE_ADDR(dmc, index);
		job->cache.count = dmc->block_size;
	}
	job->error = 0;
	job->bio = bio;
	job->disk.bdev = dmc->disk_dev->bdev;
	if (index != -1) {
		job->disk.sector = dmc->cache[index].dbn;
		job->disk.count = dmc->block_size;
	} else {
		job->disk.sector = bio->bi_sector;
		job->disk.count = to_sector(bio->bi_size);
	}
	job->next = NULL;
	job->md_block = NULL;
	if (sysctl_flashcache_lat_hist)
		do_gettimeofday(&job->io_start_time);
	else {
		job->io_start_time.tv_sec = 0;
		job->io_start_time.tv_usec = 0;
	}
	return job;
}

static void
flashcache_record_latency(struct cache_c *dmc, struct timeval *start_tv)
{
	struct timeval latency;
	int64_t us;

	do_gettimeofday(&latency);
	latency.tv_sec -= start_tv->tv_sec;
	latency.tv_usec -= start_tv->tv_usec;
	us = latency.tv_sec * USEC_PER_SEC + latency.tv_usec;
	us /= IO_LATENCY_GRAN_USECS;	/* histogram 250us gran, scale 10ms total */
	if (us < IO_LATENCY_BUCKETS)
		/* < 10ms latency, track it */
		dmc->latency_hist[us]++;
	else
		/* else count it in 10ms+ bucket */
		dmc->latency_hist_10ms++;
}

void
flashcache_bio_endio(struct bio *bio, int error,
		     struct cache_c *dmc, struct timeval *start_time)
{
	if (unlikely(sysctl_flashcache_lat_hist &&
		     start_time != NULL &&
		     start_time->tv_sec != 0))
		flashcache_record_latency(dmc, start_time);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	bio_endio(bio, bio->bi_size, error);
#else
	bio_endio(bio, error);
#endif
}

void
flashcache_reclaim_lru_movetail(struct cache_c *dmc, int index)
{
	int set = index / dmc->assoc;
	int start_index = set * dmc->assoc;
	int my_index = index - start_index;
	struct cacheblock *cacheblk = &dmc->cache[index];

	/* Remove from LRU */
	if (likely((cacheblk->lru_prev != FLASHCACHE_LRU_NULL) ||
		   (cacheblk->lru_next != FLASHCACHE_LRU_NULL))) {
		if (cacheblk->lru_prev != FLASHCACHE_LRU_NULL)
			dmc->cache[cacheblk->lru_prev + start_index].lru_next =
				cacheblk->lru_next;
		else
			dmc->cache_sets[set].lru_head = cacheblk->lru_next;
		if (cacheblk->lru_next != FLASHCACHE_LRU_NULL)
			dmc->cache[cacheblk->lru_next + start_index].lru_prev =
				cacheblk->lru_prev;
		else
			dmc->cache_sets[set].lru_tail = cacheblk->lru_prev;
	}
	/* And add it to LRU Tail */
	cacheblk->lru_next = FLASHCACHE_LRU_NULL;
	cacheblk->lru_prev = dmc->cache_sets[set].lru_tail;
	if (dmc->cache_sets[set].lru_tail == FLASHCACHE_LRU_NULL)
		dmc->cache_sets[set].lru_head = my_index;
	else
		dmc->cache[dmc->cache_sets[set].lru_tail + start_index].lru_next =
			my_index;
	dmc->cache_sets[set].lru_tail = my_index;
}

static int
cmp_dbn(const void *a, const void *b)
{
	if (((struct dbn_index_pair *)a)->dbn < ((struct dbn_index_pair *)b)->dbn)
		return -1;
	else
		return 1;
}

static void
swap_dbn_index_pair(void *a, void *b, int size)
{
	struct dbn_index_pair temp;

	temp = *(struct dbn_index_pair *)a;
	*(struct dbn_index_pair *)a = *(struct dbn_index_pair *)b;
	*(struct dbn_index_pair *)b = temp;
}

extern int sysctl_flashcache_write_merge;

/*
 * We have a list of blocks to write out to disk.
 * 1) Sort the blocks by dbn.
 * 2) (sysctl'able) See if there are any other blocks in the same set
 * that are contig to any of the blocks in step 1. If so, include them
 * in our "to write" set, maintaining sorted order.
 * Has to be called under the cache spinlock !
 */
void
flashcache_merge_writes(struct cache_c *dmc, struct dbn_index_pair *writes_list,
			int *nr_writes, int set)
{
	int start_index = set * dmc->assoc;
	int end_index = start_index + dmc->assoc;
	int old_writes = *nr_writes;
	int new_inserts = 0;
	struct dbn_index_pair *set_dirty_list = NULL;
	int ix, nr_set_dirty;
	struct cacheblock *cacheblk;

	if (unlikely(*nr_writes == 0))
		return;
	sort(writes_list, *nr_writes, sizeof(struct dbn_index_pair),
	     cmp_dbn, swap_dbn_index_pair);
	if (sysctl_flashcache_write_merge == 0)
		return;
	set_dirty_list = kmalloc(dmc->assoc * sizeof(struct dbn_index_pair), GFP_ATOMIC);
	if (set_dirty_list == NULL) {
		dmc->flashcache_errors.memory_alloc_errors++;
		goto out;
	}
	nr_set_dirty = 0;
	for (ix = start_index ; ix < end_index ; ix++) {
		cacheblk = &dmc->cache[ix];
		/*
		 * Any DIRTY block in "writes_list" will be marked as
		 * DISKWRITEINPROG already, so we'll skip over those here.
		 */
		if ((cacheblk->cache_state & (DIRTY | BLOCK_IO_INPROG)) == DIRTY) {
			set_dirty_list[nr_set_dirty].dbn = cacheblk->dbn;
			set_dirty_list[nr_set_dirty].index = ix;
			nr_set_dirty++;
		}
	}
	if (nr_set_dirty == 0)
		goto out;
	sort(set_dirty_list, nr_set_dirty, sizeof(struct dbn_index_pair),
	     cmp_dbn, swap_dbn_index_pair);
	for (ix = 0 ; ix < nr_set_dirty ; ix++) {
		int back_merge, k;
		int i;

		cacheblk = &dmc->cache[set_dirty_list[ix].index];
		back_merge = -1;
		VERIFY((cacheblk->cache_state & (DIRTY | BLOCK_IO_INPROG)) == DIRTY);
		for (i = 0 ; i < *nr_writes ; i++) {
			int insert;
			int j = 0;

			insert = 0;
			if (cacheblk->dbn + dmc->block_size == writes_list[i].dbn) {
				/* cacheblk to be inserted above i */
				insert = 1;
				j = i;
				back_merge = j;
			}
			if (cacheblk->dbn - dmc->block_size == writes_list[i].dbn ) {
				/* cacheblk to be inserted after i */
				insert = 1;
				j = i + 1;
			}
			VERIFY(j < dmc->assoc);
			if (insert) {
				cacheblk->cache_state |= DISKWRITEINPROG;
				flashcache_clear_fallow(dmc, set_dirty_list[ix].index);
				/*
				 * Shift down everthing from j to ((*nr_writes) - 1) to
				 * make room for the new entry. And add the new entry.
				 */
				for (k = (*nr_writes) - 1 ; k >= j ; k--)
					writes_list[k + 1] = writes_list[k];
				writes_list[j].dbn = cacheblk->dbn;
				writes_list[j].index = cacheblk - &dmc->cache[0];
				(*nr_writes)++;
				VERIFY(*nr_writes <= dmc->assoc);
				new_inserts++;
				if (back_merge == -1)
					dmc->flashcache_stats.front_merge++;
				else
					dmc->flashcache_stats.back_merge++;
				VERIFY(*nr_writes <= dmc->assoc);
				break;
			}
		}
		/*
		 * If we did a back merge, we need to walk back in the set's dirty list
		 * to see if we can pick off any more contig blocks. Forward merges don't
		 * need this special treatment since we are walking the 2 lists in that
		 * direction. It would be nice to roll this logic into the above.
		 */
		if (back_merge != -1) {
			for (k = ix - 1 ; k >= 0 ; k--) {
				int n;

				if (set_dirty_list[k].dbn + dmc->block_size !=
				    writes_list[back_merge].dbn)
					break;
				dmc->cache[set_dirty_list[k].index].cache_state |= DISKWRITEINPROG;
				flashcache_clear_fallow(dmc, set_dirty_list[k].index);
				for (n = (*nr_writes) - 1 ; n >= back_merge ; n--)
					writes_list[n + 1] = writes_list[n];
				writes_list[back_merge].dbn = set_dirty_list[k].dbn;
				writes_list[back_merge].index = set_dirty_list[k].index;
				(*nr_writes)++;
				VERIFY(*nr_writes <= dmc->assoc);
				new_inserts++;
				dmc->flashcache_stats.back_merge++;
				VERIFY(*nr_writes <= dmc->assoc);
			}
		}
	}
	VERIFY((*nr_writes) == (old_writes + new_inserts));
out:
	if (set_dirty_list)
		kfree(set_dirty_list);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
int
flashcache_dm_io_async_vm(struct cache_c *dmc, unsigned int num_regions,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
			  struct io_region *where,
#else
			  struct dm_io_region *where,
#endif
			  int rw,
			  void *data, io_notify_fn fn, void *context)
{
	unsigned long error_bits = 0;
	int error;
	struct dm_io_request io_req = {
		.bi_rw = rw,
		.mem.type = DM_IO_VMA,
		.mem.ptr.vma = data,
		.mem.offset = 0,
		.notify.fn = fn,
		.notify.context = context,
		.client = dmc->io_client,
	};

	error = dm_io(&io_req, 1, where, &error_bits);
	if (error)
		return error;
	if (error_bits)
		return error_bits;
	return 0;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,29)
/*
 * Wrappers for doing DM sync IO, using DM async IO.
 * It is a shame we need do this, but DM sync IO is interruptible :(
 * And we want uninterruptible disk IO :)
 *
 * This is fixed in 2.6.30, where sync DM IO is uninterruptible.
 */
#define FLASHCACHE_DM_IO_SYNC_INPROG	0x01

static DECLARE_WAIT_QUEUE_HEAD(flashcache_dm_io_sync_waitqueue);
static DEFINE_SPINLOCK(flashcache_dm_io_sync_spinlock);

struct flashcache_dm_io_sync_state {
	int			error;
	int			flags;
};

static void
flashcache_dm_io_sync_vm_callback(unsigned long error, void *context)
{
	struct flashcache_dm_io_sync_state *state =
		(struct flashcache_dm_io_sync_state *)context;
	unsigned long flags;

	spin_lock_irqsave(&flashcache_dm_io_sync_spinlock, flags);
	state->flags &= ~FLASHCACHE_DM_IO_SYNC_INPROG;
	state->error = error;
	wake_up(&flashcache_dm_io_sync_waitqueue);
	spin_unlock_irqrestore(&flashcache_dm_io_sync_spinlock, flags);
}

int
flashcache_dm_io_sync_vm(struct cache_c *dmc,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
			 struct io_region *where,
#else
			  struct dm_io_region *where,
#endif
			 int rw, void *data)
{
        DEFINE_WAIT(wait);
	struct flashcache_dm_io_sync_state state;

	state.error = -EINTR;
	state.flags = FLASHCACHE_DM_IO_SYNC_INPROG;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
	dm_io_async_vm(1, where, rw, data, flashcache_dm_io_sync_vm_callback, &state);
#else
	flashcache_dm_io_async_vm(dmc, 1, where, rw, data, flashcache_dm_io_sync_vm_callback, &state);
#endif
	flashcache_unplug_device(where->bdev);
	spin_lock_irq(&flashcache_dm_io_sync_spinlock);
	while (state.flags & FLASHCACHE_DM_IO_SYNC_INPROG) {
		prepare_to_wait(&flashcache_dm_io_sync_waitqueue, &wait,
				TASK_UNINTERRUPTIBLE);
		spin_unlock_irq(&flashcache_dm_io_sync_spinlock);
		schedule();
		spin_lock_irq(&flashcache_dm_io_sync_spinlock);
	}
	finish_wait(&flashcache_dm_io_sync_waitqueue, &wait);
	spin_unlock_irq(&flashcache_dm_io_sync_spinlock);
	return state.error;
}
#else
int
flashcache_dm_io_sync_vm(struct cache_c *dmc, struct dm_io_region *where, int rw, void *data)
{
	unsigned long error_bits = 0;
	int error;
	struct dm_io_request io_req = {
		.bi_rw = rw,
		.mem.type = DM_IO_VMA,
		.mem.ptr.vma = data,
		.mem.offset = 0,
		.notify.fn = NULL,
		.client = dmc->io_client,
	};

	error = dm_io(&io_req, 1, where, &error_bits);
	if (error)
		return error;
	if (error_bits)
		return error_bits;
	return 0;
}
#endif

void
flashcache_update_sync_progress(struct cache_c *dmc)
{
	u_int64_t dirty_pct;

	if (dmc->flashcache_stats.cleanings % 1000)
		return;
	if (!dmc->nr_dirty || !dmc->size || !printk_ratelimit())
		return;
	dirty_pct = ((u_int64_t)dmc->nr_dirty * 100) / dmc->size;
	printk(KERN_INFO "Flashcache: Cleaning %d Dirty blocks, Dirty Blocks pct %llu%%",
	       dmc->nr_dirty, dirty_pct);
	printk(KERN_INFO "\r");
}

void
flashcache_unplug_device(struct block_device *bdev)
{
	struct backing_dev_info *bdi;

	bdi = blk_get_backing_dev_info(bdev);
	if (bdi) {
		if (bdi->unplug_io_fn)
			blk_run_backing_dev(bdi, NULL);
	}
}

EXPORT_SYMBOL(flashcache_alloc_cache_job);
EXPORT_SYMBOL(flashcache_free_cache_job);
EXPORT_SYMBOL(flashcache_alloc_pending_job);
EXPORT_SYMBOL(flashcache_free_pending_job);
EXPORT_SYMBOL(pop);
EXPORT_SYMBOL(push);
EXPORT_SYMBOL(push_pending);
EXPORT_SYMBOL(push_io);
EXPORT_SYMBOL(push_md_io);
EXPORT_SYMBOL(push_md_complete);
EXPORT_SYMBOL(process_jobs);
EXPORT_SYMBOL(do_work);
EXPORT_SYMBOL(new_kcached_job);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
EXPORT_SYMBOL(flashcache_dm_io_sync_vm_callback);
#endif
EXPORT_SYMBOL(flashcache_dm_io_sync_vm);
EXPORT_SYMBOL(flashcache_reclaim_lru_movetail);
EXPORT_SYMBOL(flashcache_merge_writes);
EXPORT_SYMBOL(flashcache_enq_pending);
