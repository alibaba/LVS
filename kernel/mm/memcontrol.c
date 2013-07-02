/* memcontrol.c - Memory Controller
 *
 * Copyright IBM Corporation, 2007
 * Author Balbir Singh <balbir@linux.vnet.ibm.com>
 *
 * Copyright 2007 OpenVZ SWsoft Inc
 * Author: Pavel Emelianov <xemul@openvz.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/res_counter.h>
#include <linux/memcontrol.h>
#include <linux/cgroup.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/smp.h>
#include <linux/page-flags.h>
#include <linux/backing-dev.h>
#include <linux/bit_spinlock.h>
#include <linux/rcupdate.h>
#include <linux/limits.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <linux/mm_inline.h>
#include <linux/page_cgroup.h>
#include "internal.h"

#include <asm/uaccess.h>

struct cgroup_subsys mem_cgroup_subsys __read_mostly;
#define MEM_CGROUP_RECLAIM_RETRIES	5
struct mem_cgroup *root_mem_cgroup __read_mostly;

#ifdef CONFIG_CGROUP_MEM_RES_CTLR_SWAP
/* Turned on only when memory cgroup is enabled && really_do_swap_account = 1 */
int do_swap_account __read_mostly;
static int really_do_swap_account __initdata = 1; /* for remember boot option*/
#else
#define do_swap_account		(0)
#endif

#define SOFTLIMIT_EVENTS_THRESH (1000)

/*
 * Statistics for memory cgroup.
 */
enum mem_cgroup_stat_index {
	/*
	 * For MEM_CONTAINER_TYPE_ALL, usage = pagecache + rss.
	 */
	MEM_CGROUP_STAT_CACHE, 	   /* # of pages charged as cache */
	MEM_CGROUP_STAT_RSS,	   /* # of pages charged as anon rss */
	MEM_CGROUP_STAT_FILE_MAPPED,  /* # of pages charged as file rss */
	MEM_CGROUP_STAT_PGPGIN_COUNT,	/* # of pages paged in */
	MEM_CGROUP_STAT_PGPGOUT_COUNT,	/* # of pages paged out */
	MEM_CGROUP_STAT_EVENTS,	/* sum of pagein + pageout for internal use */
	MEM_CGROUP_STAT_SWAPOUT, /* # of pages, swapped out */

	MEM_CGROUP_STAT_NSTATS,
};

struct mem_cgroup_stat_cpu {
	s64 count[MEM_CGROUP_STAT_NSTATS];
} ____cacheline_aligned_in_smp;

struct mem_cgroup_stat {
	struct mem_cgroup_stat_cpu cpustat[0];
};

static inline void
__mem_cgroup_stat_reset_safe(struct mem_cgroup_stat_cpu *stat,
				enum mem_cgroup_stat_index idx)
{
	stat->count[idx] = 0;
}

static inline s64
__mem_cgroup_stat_read_local(struct mem_cgroup_stat_cpu *stat,
				enum mem_cgroup_stat_index idx)
{
	return stat->count[idx];
}

/*
 * For accounting under irq disable, no need for increment preempt count.
 */
static inline void __mem_cgroup_stat_add_safe(struct mem_cgroup_stat_cpu *stat,
		enum mem_cgroup_stat_index idx, int val)
{
	stat->count[idx] += val;
}

static s64 mem_cgroup_read_stat(struct mem_cgroup_stat *stat,
		enum mem_cgroup_stat_index idx)
{
	int cpu;
	s64 ret = 0;
	for_each_possible_cpu(cpu)
		ret += stat->cpustat[cpu].count[idx];
	return ret;
}

static s64 mem_cgroup_local_usage(struct mem_cgroup_stat *stat)
{
	s64 ret;

	ret = mem_cgroup_read_stat(stat, MEM_CGROUP_STAT_CACHE);
	ret += mem_cgroup_read_stat(stat, MEM_CGROUP_STAT_RSS);
	return ret;
}

/*
 * per-zone information in memory controller.
 */
struct mem_cgroup_per_zone {
	/*
	 * spin_lock to protect the per cgroup LRU
	 */
	struct list_head	lists[NR_LRU_LISTS];
	unsigned long		count[NR_LRU_LISTS];

	struct zone_reclaim_stat reclaim_stat;
	struct rb_node		tree_node;	/* RB tree node */
	unsigned long long	usage_in_excess;/* Set to the value by which */
						/* the soft limit is exceeded*/
	bool			on_tree;
	struct mem_cgroup	*mem;		/* Back pointer, we cannot */
						/* use container_of	   */
};
/* Macro for accessing counter */
#define MEM_CGROUP_ZSTAT(mz, idx)	((mz)->count[(idx)])

struct mem_cgroup_per_node {
	struct mem_cgroup_per_zone zoneinfo[MAX_NR_ZONES];
};

struct mem_cgroup_lru_info {
	struct mem_cgroup_per_node *nodeinfo[MAX_NUMNODES];
};

/*
 * Cgroups above their limits are maintained in a RB-Tree, independent of
 * their hierarchy representation
 */

struct mem_cgroup_tree_per_zone {
	struct rb_root rb_root;
	spinlock_t lock;
};

struct mem_cgroup_tree_per_node {
	struct mem_cgroup_tree_per_zone rb_tree_per_zone[MAX_NR_ZONES];
};

struct mem_cgroup_tree {
	struct mem_cgroup_tree_per_node *rb_tree_per_node[MAX_NUMNODES];
};

static struct mem_cgroup_tree soft_limit_tree __read_mostly;

/*
 * The memory controller data structure. The memory controller controls both
 * page cache and RSS per cgroup. We would eventually like to provide
 * statistics based on the statistics developed by Rik Van Riel for clock-pro,
 * to help the administrator determine what knobs to tune.
 *
 * TODO: Add a water mark for the memory controller. Reclaim will begin when
 * we hit the water mark. May be even add a low water mark, such that
 * no reclaim occurs from a cgroup at it's low water mark, this is
 * a feature that will be implemented much later in the future.
 */
struct mem_cgroup {
	struct cgroup_subsys_state css;
	/*
	 * the counter to account for memory usage
	 */
	struct res_counter res;
	/*
	 * the counter to account for mem+swap usage.
	 */
	struct res_counter memsw;
	/*
	 * Per cgroup active and inactive list, similar to the
	 * per zone LRU lists.
	 */
	struct mem_cgroup_lru_info info;

	/*
	  protect against reclaim related member.
	*/
	spinlock_t reclaim_param_lock;

	int	prev_priority;	/* for recording reclaim priority */

	/*
	 * While reclaiming in a hiearchy, we cache the last child we
	 * reclaimed from.
	 */
	int last_scanned_child;
	/*
	 * Should the accounting and control be hierarchical, per subtree?
	 */
	bool use_hierarchy;
	atomic_t	oom_lock;
	atomic_t	refcnt;

	unsigned int	swappiness;

	/* set when res.limit == memsw.limit */
	bool		memsw_is_minimum;

	/*
	 * Should we move charges of a task when a task is moved into this
	 * mem_cgroup ? And what type of charges should we move ?
	 */
	unsigned long 	move_charge_at_immigrate;

	/*
	 * statistics. This must be placed at the end of memcg.
	 */
	struct mem_cgroup_stat stat;
};

/* Stuffs for move charges at task migration. */
/*
 * Types of charges to be moved. "move_charge_at_immitgrate" is treated as a
 * left-shifted bitmap of these types.
 */
enum move_type {
	MOVE_CHARGE_TYPE_ANON,	/* private anonymous page and swap of it */
	MOVE_CHARGE_TYPE_FILE,	/* file page(including tmpfs) and swap of it */
	NR_MOVE_TYPE,
};

/* "mc" and its members are protected by cgroup_mutex */
static struct move_charge_struct {
	struct mem_cgroup *from;
	struct mem_cgroup *to;
	unsigned long precharge;
	unsigned long moved_charge;
	unsigned long moved_swap;
	struct task_struct *moving_task;	/* a task moving charges */
	struct mm_struct *mm;
	wait_queue_head_t waitq;		/* a waitq for other context */
} mc = {
	.waitq = __WAIT_QUEUE_HEAD_INITIALIZER(mc.waitq),
};

static bool move_anon(void)
{
	return test_bit(MOVE_CHARGE_TYPE_ANON,
					&mc.to->move_charge_at_immigrate);
}

static bool move_file(void)
{
	return test_bit(MOVE_CHARGE_TYPE_FILE,
					&mc.to->move_charge_at_immigrate);
}

/*
 * Maximum loops in mem_cgroup_hierarchical_reclaim(), used for soft
 * limit reclaim to prevent infinite loops, if they ever occur.
 */
#define	MEM_CGROUP_MAX_RECLAIM_LOOPS		(100)
#define	MEM_CGROUP_MAX_SOFT_LIMIT_RECLAIM_LOOPS	(2)

enum charge_type {
	MEM_CGROUP_CHARGE_TYPE_CACHE = 0,
	MEM_CGROUP_CHARGE_TYPE_MAPPED,
	MEM_CGROUP_CHARGE_TYPE_SHMEM,	/* used by page migration of shmem */
	MEM_CGROUP_CHARGE_TYPE_FORCE,	/* used by force_empty */
	MEM_CGROUP_CHARGE_TYPE_SWAPOUT,	/* for accounting swapcache */
	MEM_CGROUP_CHARGE_TYPE_DROP,	/* a page was unused swap cache */
	NR_CHARGE_TYPE,
};

/* only for here (for easy reading.) */
#define PCGF_CACHE	(1UL << PCG_CACHE)
#define PCGF_USED	(1UL << PCG_USED)
#define PCGF_LOCK	(1UL << PCG_LOCK)
/* Not used, but added here for completeness */
#define PCGF_ACCT	(1UL << PCG_ACCT)

/* for encoding cft->private value on file */
#define _MEM			(0)
#define _MEMSWAP		(1)
#define MEMFILE_PRIVATE(x, val)	(((x) << 16) | (val))
#define MEMFILE_TYPE(val)	(((val) >> 16) & 0xffff)
#define MEMFILE_ATTR(val)	((val) & 0xffff)

/*
 * Reclaim flags for mem_cgroup_hierarchical_reclaim
 */
#define MEM_CGROUP_RECLAIM_NOSWAP_BIT	0x0
#define MEM_CGROUP_RECLAIM_NOSWAP	(1 << MEM_CGROUP_RECLAIM_NOSWAP_BIT)
#define MEM_CGROUP_RECLAIM_SHRINK_BIT	0x1
#define MEM_CGROUP_RECLAIM_SHRINK	(1 << MEM_CGROUP_RECLAIM_SHRINK_BIT)
#define MEM_CGROUP_RECLAIM_SOFT_BIT	0x2
#define MEM_CGROUP_RECLAIM_SOFT		(1 << MEM_CGROUP_RECLAIM_SOFT_BIT)

static void mem_cgroup_get(struct mem_cgroup *mem);
static void mem_cgroup_put(struct mem_cgroup *mem);
static struct mem_cgroup *parent_mem_cgroup(struct mem_cgroup *mem);

static struct mem_cgroup_per_zone *
mem_cgroup_zoneinfo(struct mem_cgroup *mem, int nid, int zid)
{
	return &mem->info.nodeinfo[nid]->zoneinfo[zid];
}

struct cgroup_subsys_state *mem_cgroup_css(struct mem_cgroup *mem)
{
	return &mem->css;
}

static struct mem_cgroup_per_zone *
page_cgroup_zoneinfo(struct page_cgroup *pc)
{
	struct mem_cgroup *mem = pc->mem_cgroup;
	int nid = page_cgroup_nid(pc);
	int zid = page_cgroup_zid(pc);

	if (!mem)
		return NULL;

	return mem_cgroup_zoneinfo(mem, nid, zid);
}

static struct mem_cgroup_tree_per_zone *
soft_limit_tree_node_zone(int nid, int zid)
{
	return &soft_limit_tree.rb_tree_per_node[nid]->rb_tree_per_zone[zid];
}

static struct mem_cgroup_tree_per_zone *
soft_limit_tree_from_page(struct page *page)
{
	int nid = page_to_nid(page);
	int zid = page_zonenum(page);

	return &soft_limit_tree.rb_tree_per_node[nid]->rb_tree_per_zone[zid];
}

static void
__mem_cgroup_insert_exceeded(struct mem_cgroup *mem,
				struct mem_cgroup_per_zone *mz,
				struct mem_cgroup_tree_per_zone *mctz,
				unsigned long long new_usage_in_excess)
{
	struct rb_node **p = &mctz->rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct mem_cgroup_per_zone *mz_node;

	if (mz->on_tree)
		return;

	mz->usage_in_excess = new_usage_in_excess;
	if (!mz->usage_in_excess)
		return;
	while (*p) {
		parent = *p;
		mz_node = rb_entry(parent, struct mem_cgroup_per_zone,
					tree_node);
		if (mz->usage_in_excess < mz_node->usage_in_excess)
			p = &(*p)->rb_left;
		/*
		 * We can't avoid mem cgroups that are over their soft
		 * limit by the same amount
		 */
		else if (mz->usage_in_excess >= mz_node->usage_in_excess)
			p = &(*p)->rb_right;
	}
	rb_link_node(&mz->tree_node, parent, p);
	rb_insert_color(&mz->tree_node, &mctz->rb_root);
	mz->on_tree = true;
}

static void
__mem_cgroup_remove_exceeded(struct mem_cgroup *mem,
				struct mem_cgroup_per_zone *mz,
				struct mem_cgroup_tree_per_zone *mctz)
{
	if (!mz->on_tree)
		return;
	rb_erase(&mz->tree_node, &mctz->rb_root);
	mz->on_tree = false;
}

static void
mem_cgroup_remove_exceeded(struct mem_cgroup *mem,
				struct mem_cgroup_per_zone *mz,
				struct mem_cgroup_tree_per_zone *mctz)
{
	spin_lock(&mctz->lock);
	__mem_cgroup_remove_exceeded(mem, mz, mctz);
	spin_unlock(&mctz->lock);
}

static bool mem_cgroup_soft_limit_check(struct mem_cgroup *mem)
{
	bool ret = false;
	int cpu;
	s64 val;
	struct mem_cgroup_stat_cpu *cpustat;

	cpu = get_cpu();
	cpustat = &mem->stat.cpustat[cpu];
	val = __mem_cgroup_stat_read_local(cpustat, MEM_CGROUP_STAT_EVENTS);
	if (unlikely(val > SOFTLIMIT_EVENTS_THRESH)) {
		__mem_cgroup_stat_reset_safe(cpustat, MEM_CGROUP_STAT_EVENTS);
		ret = true;
	}
	put_cpu();
	return ret;
}

static void mem_cgroup_update_tree(struct mem_cgroup *mem, struct page *page)
{
	unsigned long long excess;
	struct mem_cgroup_per_zone *mz;
	struct mem_cgroup_tree_per_zone *mctz;
	int nid = page_to_nid(page);
	int zid = page_zonenum(page);
	mctz = soft_limit_tree_from_page(page);

	/*
	 * Necessary to update all ancestors when hierarchy is used.
	 * because their event counter is not touched.
	 */
	for (; mem; mem = parent_mem_cgroup(mem)) {
		mz = mem_cgroup_zoneinfo(mem, nid, zid);
		excess = res_counter_soft_limit_excess(&mem->res);
		/*
		 * We have to update the tree if mz is on RB-tree or
		 * mem is over its softlimit.
		 */
		if (excess || mz->on_tree) {
			spin_lock(&mctz->lock);
			/* if on-tree, remove it */
			if (mz->on_tree)
				__mem_cgroup_remove_exceeded(mem, mz, mctz);
			/*
			 * Insert again. mz->usage_in_excess will be updated.
			 * If excess is 0, no tree ops.
			 */
			__mem_cgroup_insert_exceeded(mem, mz, mctz, excess);
			spin_unlock(&mctz->lock);
		}
	}
}

static void mem_cgroup_remove_from_trees(struct mem_cgroup *mem)
{
	int node, zone;
	struct mem_cgroup_per_zone *mz;
	struct mem_cgroup_tree_per_zone *mctz;

	for_each_node_state(node, N_POSSIBLE) {
		for (zone = 0; zone < MAX_NR_ZONES; zone++) {
			mz = mem_cgroup_zoneinfo(mem, node, zone);
			mctz = soft_limit_tree_node_zone(node, zone);
			mem_cgroup_remove_exceeded(mem, mz, mctz);
		}
	}
}

static inline unsigned long mem_cgroup_get_excess(struct mem_cgroup *mem)
{
	return res_counter_soft_limit_excess(&mem->res) >> PAGE_SHIFT;
}

static struct mem_cgroup_per_zone *
__mem_cgroup_largest_soft_limit_node(struct mem_cgroup_tree_per_zone *mctz)
{
	struct rb_node *rightmost = NULL;
	struct mem_cgroup_per_zone *mz;

retry:
	mz = NULL;
	rightmost = rb_last(&mctz->rb_root);
	if (!rightmost)
		goto done;		/* Nothing to reclaim from */

	mz = rb_entry(rightmost, struct mem_cgroup_per_zone, tree_node);
	/*
	 * Remove the node now but someone else can add it back,
	 * we will to add it back at the end of reclaim to its correct
	 * position in the tree.
	 */
	__mem_cgroup_remove_exceeded(mz->mem, mz, mctz);
	if (!res_counter_soft_limit_excess(&mz->mem->res) ||
		!css_tryget(&mz->mem->css))
		goto retry;
done:
	return mz;
}

static struct mem_cgroup_per_zone *
mem_cgroup_largest_soft_limit_node(struct mem_cgroup_tree_per_zone *mctz)
{
	struct mem_cgroup_per_zone *mz;

	spin_lock(&mctz->lock);
	mz = __mem_cgroup_largest_soft_limit_node(mctz);
	spin_unlock(&mctz->lock);
	return mz;
}

static void mem_cgroup_swap_statistics(struct mem_cgroup *mem,
					 bool charge)
{
	int val = (charge) ? 1 : -1;
	struct mem_cgroup_stat *stat = &mem->stat;
	struct mem_cgroup_stat_cpu *cpustat;
	int cpu = get_cpu();

	cpustat = &stat->cpustat[cpu];
	__mem_cgroup_stat_add_safe(cpustat, MEM_CGROUP_STAT_SWAPOUT, val);
	put_cpu();
}

static void mem_cgroup_charge_statistics(struct mem_cgroup *mem,
					 struct page_cgroup *pc,
					 long size)
{
	struct mem_cgroup_stat *stat = &mem->stat;
	struct mem_cgroup_stat_cpu *cpustat;
	long numpages = size >> PAGE_SHIFT;
	int cpu = get_cpu();

	cpustat = &stat->cpustat[cpu];
	if (PageCgroupCache(pc))
		__mem_cgroup_stat_add_safe(cpustat,
			MEM_CGROUP_STAT_CACHE, numpages);
	else
		__mem_cgroup_stat_add_safe(cpustat, MEM_CGROUP_STAT_RSS,
			numpages);

	if (numpages > 0)
		__mem_cgroup_stat_add_safe(cpustat,
				MEM_CGROUP_STAT_PGPGIN_COUNT, 1);
	else
		__mem_cgroup_stat_add_safe(cpustat,
				MEM_CGROUP_STAT_PGPGOUT_COUNT, 1);
	__mem_cgroup_stat_add_safe(cpustat, MEM_CGROUP_STAT_EVENTS, 1);
	put_cpu();
}

static unsigned long mem_cgroup_get_local_zonestat(struct mem_cgroup *mem,
					enum lru_list idx)
{
	int nid, zid;
	struct mem_cgroup_per_zone *mz;
	u64 total = 0;

	for_each_online_node(nid)
		for (zid = 0; zid < MAX_NR_ZONES; zid++) {
			mz = mem_cgroup_zoneinfo(mem, nid, zid);
			total += MEM_CGROUP_ZSTAT(mz, idx);
		}
	return total;
}

static struct mem_cgroup *mem_cgroup_from_cont(struct cgroup *cont)
{
	return container_of(cgroup_subsys_state(cont,
				mem_cgroup_subsys_id), struct mem_cgroup,
				css);
}

struct mem_cgroup *mem_cgroup_from_task(struct task_struct *p)
{
	/*
	 * mm_update_next_owner() may clear mm->owner to NULL
	 * if it races with swapoff, page migration, etc.
	 * So this can be called with p == NULL.
	 */
	if (unlikely(!p))
		return NULL;

	return container_of(task_subsys_state(p, mem_cgroup_subsys_id),
				struct mem_cgroup, css);
}

static struct mem_cgroup *try_get_mem_cgroup_from_mm(struct mm_struct *mm)
{
	struct mem_cgroup *mem = NULL;

	if (!mm)
		return NULL;
	/*
	 * Because we have no locks, mm->owner's may be being moved to other
	 * cgroup. We use css_tryget() here even if this looks
	 * pessimistic (rather than adding locks here).
	 */
	rcu_read_lock();
	do {
		mem = mem_cgroup_from_task(rcu_dereference(mm->owner));
		if (unlikely(!mem))
			break;
	} while (!css_tryget(&mem->css));
	rcu_read_unlock();
	return mem;
}

/*
 * Call callback function against all cgroup under hierarchy tree.
 */
static int mem_cgroup_walk_tree(struct mem_cgroup *root, void *data,
			  int (*func)(struct mem_cgroup *, void *))
{
	int found, ret, nextid;
	struct cgroup_subsys_state *css;
	struct mem_cgroup *mem;

	if (!root->use_hierarchy)
		return (*func)(root, data);

	nextid = 1;
	do {
		ret = 0;
		mem = NULL;

		rcu_read_lock();
		css = css_get_next(&mem_cgroup_subsys, nextid, &root->css,
				   &found);
		if (css && css_tryget(css))
			mem = container_of(css, struct mem_cgroup, css);
		rcu_read_unlock();

		if (mem) {
			ret = (*func)(mem, data);
			css_put(&mem->css);
		}
		nextid = found + 1;
	} while (!ret && css);

	return ret;
}

static inline bool mem_cgroup_is_root(struct mem_cgroup *mem)
{
	return (mem == root_mem_cgroup);
}

/*
 * Following LRU functions are allowed to be used without PCG_LOCK.
 * Operations are called by routine of global LRU independently from memcg.
 * What we have to take care of here is validness of pc->mem_cgroup.
 *
 * Changes to pc->mem_cgroup happens when
 * 1. charge
 * 2. moving account
 * In typical case, "charge" is done before add-to-lru. Exception is SwapCache.
 * It is added to LRU before charge.
 * If PCG_USED bit is not set, page_cgroup is not added to this private LRU.
 * When moving account, the page is not on LRU. It's isolated.
 */

void mem_cgroup_del_lru_list(struct page *page, enum lru_list lru)
{
	struct page_cgroup *pc;
	struct mem_cgroup_per_zone *mz;
	int numpages = 1;

	if (mem_cgroup_disabled())
		return;
	pc = lookup_page_cgroup(page);
	/* can happen while we handle swapcache. */
	if (!TestClearPageCgroupAcctLRU(pc))
		return;
	VM_BUG_ON(!pc->mem_cgroup);
	/*
	 * We don't check PCG_USED bit. It's cleared when the "page" is finally
	 * removed from global LRU.
	 */
	if (unlikely(PageTransHuge(page)))
		numpages = 1 << compound_order(page);
	mz = page_cgroup_zoneinfo(pc);
	MEM_CGROUP_ZSTAT(mz, lru) -= numpages;
	if (mem_cgroup_is_root(pc->mem_cgroup))
		return;
	VM_BUG_ON(list_empty(&pc->lru));
	list_del_init(&pc->lru);
	return;
}

void mem_cgroup_del_lru(struct page *page)
{
	mem_cgroup_del_lru_list(page, page_lru(page));
}

void mem_cgroup_rotate_lru_list(struct page *page, enum lru_list lru)
{
	struct mem_cgroup_per_zone *mz;
	struct page_cgroup *pc;

	if (mem_cgroup_disabled())
		return;

	pc = lookup_page_cgroup(page);
	/* unused or root page is not rotated. */
	if (!PageCgroupUsed(pc))
		return;
	/* Ensure pc->mem_cgroup is visible after reading PCG_USED. */
	smp_rmb();
	if (mem_cgroup_is_root(pc->mem_cgroup))
		return;
	mz = page_cgroup_zoneinfo(pc);
	list_move(&pc->lru, &mz->lists[lru]);
}

void mem_cgroup_add_lru_list(struct page *page, enum lru_list lru)
{
	struct page_cgroup *pc;
	struct mem_cgroup_per_zone *mz;
	int numpages = 1;

	if (mem_cgroup_disabled())
		return;
	pc = lookup_page_cgroup(page);
	VM_BUG_ON(PageCgroupAcctLRU(pc));
	if (!PageCgroupUsed(pc))
		return;
	/* Ensure pc->mem_cgroup is visible after reading PCG_USED. */
	smp_rmb();
	mz = page_cgroup_zoneinfo(pc);
	if (unlikely(PageTransHuge(page)))
		numpages = 1 << compound_order(page);
	MEM_CGROUP_ZSTAT(mz, lru) += numpages;
	SetPageCgroupAcctLRU(pc);
	if (mem_cgroup_is_root(pc->mem_cgroup))
		return;
	list_add(&pc->lru, &mz->lists[lru]);
}

/*
 * At handling SwapCache, pc->mem_cgroup may be changed while it's linked to
 * lru because the page may.be reused after it's fully uncharged (because of
 * SwapCache behavior).To handle that, unlink page_cgroup from LRU when charge
 * it again. This function is only used to charge SwapCache. It's done under
 * lock_page and expected that zone->lru_lock is never held.
 */
static void mem_cgroup_lru_del_before_commit_swapcache(struct page *page)
{
	unsigned long flags;
	struct zone *zone = page_zone(page);
	struct page_cgroup *pc = lookup_page_cgroup(page);

	spin_lock_irqsave(&zone->lru_lock, flags);
	/*
	 * Forget old LRU when this page_cgroup is *not* used. This Used bit
	 * is guarded by lock_page() because the page is SwapCache.
	 */
	if (!PageCgroupUsed(pc))
		mem_cgroup_del_lru_list(page, page_lru(page));
	spin_unlock_irqrestore(&zone->lru_lock, flags);
}

static void mem_cgroup_lru_add_after_commit_swapcache(struct page *page)
{
	unsigned long flags;
	struct zone *zone = page_zone(page);
	struct page_cgroup *pc = lookup_page_cgroup(page);

	spin_lock_irqsave(&zone->lru_lock, flags);
	/* link when the page is linked to LRU but page_cgroup isn't */
	if (PageLRU(page) && !PageCgroupAcctLRU(pc))
		mem_cgroup_add_lru_list(page, page_lru(page));
	spin_unlock_irqrestore(&zone->lru_lock, flags);
}


void mem_cgroup_move_lists(struct page *page,
			   enum lru_list from, enum lru_list to)
{
	if (mem_cgroup_disabled())
		return;
	mem_cgroup_del_lru_list(page, from);
	mem_cgroup_add_lru_list(page, to);
}

int task_in_mem_cgroup(struct task_struct *task, const struct mem_cgroup *mem)
{
	int ret;
	struct mem_cgroup *curr = NULL;

	task_lock(task);
	rcu_read_lock();
	curr = try_get_mem_cgroup_from_mm(task->mm);
	rcu_read_unlock();
	task_unlock(task);
	if (!curr)
		return 0;
	/*
	 * We should check use_hierarchy of "mem" not "curr". Because checking
	 * use_hierarchy of "curr" here make this function true if hierarchy is
	 * enabled in "curr" and "curr" is a child of "mem" in *cgroup*
	 * hierarchy(even if use_hierarchy is disabled in "mem").
	 */
	if (mem->use_hierarchy)
		ret = css_is_ancestor(&curr->css, &mem->css);
	else
		ret = (curr == mem);
	css_put(&curr->css);
	return ret;
}

/*
 * prev_priority control...this will be used in memory reclaim path.
 */
int mem_cgroup_get_reclaim_priority(struct mem_cgroup *mem)
{
	int prev_priority;

	spin_lock(&mem->reclaim_param_lock);
	prev_priority = mem->prev_priority;
	spin_unlock(&mem->reclaim_param_lock);

	return prev_priority;
}

void mem_cgroup_note_reclaim_priority(struct mem_cgroup *mem, int priority)
{
	spin_lock(&mem->reclaim_param_lock);
	if (priority < mem->prev_priority)
		mem->prev_priority = priority;
	spin_unlock(&mem->reclaim_param_lock);
}

void mem_cgroup_record_reclaim_priority(struct mem_cgroup *mem, int priority)
{
	spin_lock(&mem->reclaim_param_lock);
	mem->prev_priority = priority;
	spin_unlock(&mem->reclaim_param_lock);
}

static int calc_inactive_ratio(struct mem_cgroup *memcg, unsigned long *present_pages)
{
	unsigned long active;
	unsigned long inactive;
	unsigned long gb;
	unsigned long inactive_ratio;

	inactive = mem_cgroup_get_local_zonestat(memcg, LRU_INACTIVE_ANON);
	active = mem_cgroup_get_local_zonestat(memcg, LRU_ACTIVE_ANON);

	gb = (inactive + active) >> (30 - PAGE_SHIFT);
	if (gb)
		inactive_ratio = int_sqrt(10 * gb);
	else
		inactive_ratio = 1;

	if (present_pages) {
		present_pages[0] = inactive;
		present_pages[1] = active;
	}

	return inactive_ratio;
}

int mem_cgroup_inactive_anon_is_low(struct mem_cgroup *memcg)
{
	unsigned long active;
	unsigned long inactive;
	unsigned long present_pages[2];
	unsigned long inactive_ratio;

	inactive_ratio = calc_inactive_ratio(memcg, present_pages);

	inactive = present_pages[0];
	active = present_pages[1];

	if (inactive * inactive_ratio < active)
		return 1;

	return 0;
}

int mem_cgroup_inactive_file_is_low(struct mem_cgroup *memcg)
{
	unsigned long active;
	unsigned long inactive;

	inactive = mem_cgroup_get_local_zonestat(memcg, LRU_INACTIVE_FILE);
	active = mem_cgroup_get_local_zonestat(memcg, LRU_ACTIVE_FILE);

	return (active > inactive);
}

unsigned long mem_cgroup_zone_nr_pages(struct mem_cgroup *memcg,
				       struct zone *zone,
				       enum lru_list lru)
{
	int nid = zone->zone_pgdat->node_id;
	int zid = zone_idx(zone);
	struct mem_cgroup_per_zone *mz = mem_cgroup_zoneinfo(memcg, nid, zid);

	return MEM_CGROUP_ZSTAT(mz, lru);
}

struct zone_reclaim_stat *mem_cgroup_get_reclaim_stat(struct mem_cgroup *memcg,
						      struct zone *zone)
{
	int nid = zone->zone_pgdat->node_id;
	int zid = zone_idx(zone);
	struct mem_cgroup_per_zone *mz = mem_cgroup_zoneinfo(memcg, nid, zid);

	return &mz->reclaim_stat;
}

struct zone_reclaim_stat *
mem_cgroup_get_reclaim_stat_from_page(struct page *page)
{
	struct page_cgroup *pc;
	struct mem_cgroup_per_zone *mz;

	if (mem_cgroup_disabled())
		return NULL;

	pc = lookup_page_cgroup(page);
	if (!PageCgroupUsed(pc))
		return NULL;
	/* Ensure pc->mem_cgroup is visible after reading PCG_USED. */
	smp_rmb();
	mz = page_cgroup_zoneinfo(pc);
	if (!mz)
		return NULL;

	return &mz->reclaim_stat;
}

unsigned long mem_cgroup_isolate_pages(unsigned long nr_to_scan,
					struct list_head *dst,
					unsigned long *scanned, int order,
					int mode, struct zone *z,
					struct mem_cgroup *mem_cont,
					int active, int file)
{
	unsigned long nr_taken = 0;
	struct page *page;
	unsigned long scan;
	LIST_HEAD(pc_list);
	struct list_head *src;
	struct page_cgroup *pc, *tmp;
	int nid = z->zone_pgdat->node_id;
	int zid = zone_idx(z);
	struct mem_cgroup_per_zone *mz;
	int lru = LRU_FILE * file + active;
	int ret;

	BUG_ON(!mem_cont);
	mz = mem_cgroup_zoneinfo(mem_cont, nid, zid);
	src = &mz->lists[lru];

	scan = 0;
	list_for_each_entry_safe_reverse(pc, tmp, src, lru) {
		if (scan >= nr_to_scan)
			break;

		page = pc->page;
		if (unlikely(!PageCgroupUsed(pc)))
			continue;
		if (unlikely(!PageLRU(page)))
			continue;

		scan++;
		ret = __isolate_lru_page(page, mode, file);
		switch (ret) {
		case 0:
			list_move(&page->lru, dst);
			mem_cgroup_del_lru(page);
			nr_taken += hpage_nr_pages(page);
			break;
		case -EBUSY:
			/* we don't affect global LRU but rotate in our LRU */
			mem_cgroup_rotate_lru_list(page, page_lru(page));
			break;
		default:
			break;
		}
	}

	*scanned = scan;
	return nr_taken;
}

#define mem_cgroup_from_res_counter(counter, member)	\
	container_of(counter, struct mem_cgroup, member)

static bool mem_cgroup_check_under_limit(struct mem_cgroup *mem)
{
	if (do_swap_account) {
		if (res_counter_check_under_limit(&mem->res) &&
			res_counter_check_under_limit(&mem->memsw))
			return true;
	} else
		if (res_counter_check_under_limit(&mem->res))
			return true;
	return false;
}

static bool mem_cgroup_check_room(struct mem_cgroup *mem, unsigned long room)
{
	if (!res_counter_check_room(&mem->res, room))
		return false;
	if (!do_swap_account)
		return true;
	return res_counter_check_room(&mem->memsw, room);
}

static unsigned int get_swappiness(struct mem_cgroup *memcg)
{
	struct cgroup *cgrp = memcg->css.cgroup;
	unsigned int swappiness;

	/* root ? */
	if (cgrp->parent == NULL)
		return vm_swappiness;

	spin_lock(&memcg->reclaim_param_lock);
	swappiness = memcg->swappiness;
	spin_unlock(&memcg->reclaim_param_lock);

	return swappiness;
}

static int mem_cgroup_count_children_cb(struct mem_cgroup *mem, void *data)
{
	int *val = data;
	(*val)++;
	return 0;
}

/**
 * mem_cgroup_print_mem_info: Called from OOM with tasklist_lock held in read mode.
 * @memcg: The memory cgroup that went over limit
 * @p: Task that is going to be killed
 *
 * NOTE: @memcg and @p's mem_cgroup can be different when hierarchy is
 * enabled
 */
void mem_cgroup_print_oom_info(struct mem_cgroup *memcg, struct task_struct *p)
{
	struct cgroup *task_cgrp;
	struct cgroup *mem_cgrp;
	/*
	 * Need a buffer in BSS, can't rely on allocations. The code relies
	 * on the assumption that OOM is serialized for memory controller.
	 * If this assumption is broken, revisit this code.
	 */
	static char memcg_name[PATH_MAX];
	int ret;

	if (!memcg)
		return;


	rcu_read_lock();

	mem_cgrp = memcg->css.cgroup;
	task_cgrp = task_cgroup(p, mem_cgroup_subsys_id);

	ret = cgroup_path(task_cgrp, memcg_name, PATH_MAX);
	if (ret < 0) {
		/*
		 * Unfortunately, we are unable to convert to a useful name
		 * But we'll still print out the usage information
		 */
		rcu_read_unlock();
		goto done;
	}
	rcu_read_unlock();

	printk(KERN_INFO "Task in %s killed", memcg_name);

	rcu_read_lock();
	ret = cgroup_path(mem_cgrp, memcg_name, PATH_MAX);
	if (ret < 0) {
		rcu_read_unlock();
		goto done;
	}
	rcu_read_unlock();

	/*
	 * Continues from above, so we don't need an KERN_ level
	 */
	printk(KERN_CONT " as a result of limit of %s\n", memcg_name);
done:

	printk(KERN_INFO "memory: usage %llukB, limit %llukB, failcnt %llu\n",
		res_counter_read_u64(&memcg->res, RES_USAGE) >> 10,
		res_counter_read_u64(&memcg->res, RES_LIMIT) >> 10,
		res_counter_read_u64(&memcg->res, RES_FAILCNT));
	printk(KERN_INFO "memory+swap: usage %llukB, limit %llukB, "
		"failcnt %llu\n",
		res_counter_read_u64(&memcg->memsw, RES_USAGE) >> 10,
		res_counter_read_u64(&memcg->memsw, RES_LIMIT) >> 10,
		res_counter_read_u64(&memcg->memsw, RES_FAILCNT));
}

/*
 * This function returns the number of memcg under hierarchy tree. Returns
 * 1(self count) if no children.
 */
static int mem_cgroup_count_children(struct mem_cgroup *mem)
{
	int num = 0;
 	mem_cgroup_walk_tree(mem, &num, mem_cgroup_count_children_cb);
	return num;
}

/*
 * Visit the first child (need not be the first child as per the ordering
 * of the cgroup list, since we track last_scanned_child) of @mem and use
 * that to reclaim free pages from.
 */
static struct mem_cgroup *
mem_cgroup_select_victim(struct mem_cgroup *root_mem)
{
	struct mem_cgroup *ret = NULL;
	struct cgroup_subsys_state *css;
	int nextid, found;

	if (!root_mem->use_hierarchy) {
		css_get(&root_mem->css);
		ret = root_mem;
	}

	while (!ret) {
		rcu_read_lock();
		nextid = root_mem->last_scanned_child + 1;
		css = css_get_next(&mem_cgroup_subsys, nextid, &root_mem->css,
				   &found);
		if (css && css_tryget(css))
			ret = container_of(css, struct mem_cgroup, css);

		rcu_read_unlock();
		/* Updates scanning parameter */
		spin_lock(&root_mem->reclaim_param_lock);
		if (!css) {
			/* this means start scan from ID:1 */
			root_mem->last_scanned_child = 0;
		} else
			root_mem->last_scanned_child = found;
		spin_unlock(&root_mem->reclaim_param_lock);
	}

	return ret;
}

/*
 * Scan the hierarchy if needed to reclaim memory. We remember the last child
 * we reclaimed from, so that we don't end up penalizing one child extensively
 * based on its position in the children list.
 *
 * root_mem is the original ancestor that we've been reclaim from.
 *
 * We give up and return to the caller when we visit root_mem twice.
 * (other groups can be removed while we're walking....)
 *
 * If shrink==true, for avoiding to free too much, this returns immedieately.
 */
static int mem_cgroup_hierarchical_reclaim(struct mem_cgroup *root_mem,
						struct zone *zone,
						gfp_t gfp_mask,
						unsigned long reclaim_options)
{
	struct mem_cgroup *victim;
	int ret, total = 0;
	int loop = 0;
	bool noswap = reclaim_options & MEM_CGROUP_RECLAIM_NOSWAP;
	bool shrink = reclaim_options & MEM_CGROUP_RECLAIM_SHRINK;
	bool check_soft = reclaim_options & MEM_CGROUP_RECLAIM_SOFT;
	unsigned long excess = mem_cgroup_get_excess(root_mem);

	/* If memsw_is_minimum==1, swap-out is of-no-use. */
	if (root_mem->memsw_is_minimum)
		noswap = true;

	while (1) {
		victim = mem_cgroup_select_victim(root_mem);
		if (victim == root_mem) {
			loop++;
			if (loop >= 2) {
				/*
				 * If we have not been able to reclaim
				 * anything, it might because there are
				 * no reclaimable pages under this hierarchy
				 */
				if (!check_soft || !total) {
					css_put(&victim->css);
					break;
				}
				/*
				 * We want to do more targetted reclaim.
				 * excess >> 2 is not to excessive so as to
				 * reclaim too much, nor too less that we keep
				 * coming back to reclaim from this cgroup
				 */
				if (total >= (excess >> 2) ||
					(loop > MEM_CGROUP_MAX_RECLAIM_LOOPS)) {
					css_put(&victim->css);
					break;
				}
			}
		}
		if (!mem_cgroup_local_usage(&victim->stat)) {
			/* this cgroup's local usage == 0 */
			css_put(&victim->css);
			continue;
		}
		/* we use swappiness of local cgroup */
		if (check_soft)
			ret = mem_cgroup_shrink_node_zone(victim, gfp_mask,
				noswap, get_swappiness(victim), zone,
				zone->zone_pgdat->node_id);
		else
			ret = try_to_free_mem_cgroup_pages(victim, gfp_mask,
						noswap, get_swappiness(victim));
		css_put(&victim->css);
		/*
		 * At shrinking usage, we can't check we should stop here or
		 * reclaim more. It's depends on callers. last_scanned_child
		 * will work enough for keeping fairness under tree.
		 */
		if (shrink)
			return ret;
		total += ret;
		if (check_soft) {
			if (res_counter_check_under_soft_limit(&root_mem->res))
				return total;
		} else if (mem_cgroup_check_under_limit(root_mem))
			return 1 + total;
	}
	return total;
}

static int mem_cgroup_oom_lock_cb(struct mem_cgroup *mem, void *data)
{
	int *val = (int *)data;
	int x;
	/*
	 * Logically, we can stop scanning immediately when we find
	 * a memcg is already locked. But condidering unlock ops and
	 * creation/removal of memcg, scan-all is simple operation.
	 */
	x = atomic_inc_return(&mem->oom_lock);
	*val = max(x, *val);
	return 0;
}
/*
 * Check OOM-Killer is already running under our hierarchy.
 * If someone is running, return false.
 */
static bool mem_cgroup_oom_lock(struct mem_cgroup *mem)
{
	int lock_count = 0;

	mem_cgroup_walk_tree(mem, &lock_count, mem_cgroup_oom_lock_cb);

	if (lock_count == 1)
		return true;
	return false;
}

static int mem_cgroup_oom_unlock_cb(struct mem_cgroup *mem, void *data)
{
	/*
	 * When a new child is created while the hierarchy is under oom,
	 * mem_cgroup_oom_lock() may not be called. We have to use
	 * atomic_add_unless() here.
	 */
	atomic_add_unless(&mem->oom_lock, -1, 0);
	return 0;
}

static void mem_cgroup_oom_unlock(struct mem_cgroup *mem)
{
	mem_cgroup_walk_tree(mem, NULL,	mem_cgroup_oom_unlock_cb);
}

static DEFINE_MUTEX(memcg_oom_mutex);
static DECLARE_WAIT_QUEUE_HEAD(memcg_oom_waitq);

/*
 * try to call OOM killer. returns false if we should exit memory-reclaim loop.
 */
bool mem_cgroup_handle_oom(struct mem_cgroup *mem, gfp_t mask)
{
	DEFINE_WAIT(wait);
	bool locked;

	/* At first, try to OOM lock hierarchy under mem.*/
	mutex_lock(&memcg_oom_mutex);
	locked = mem_cgroup_oom_lock(mem);
	/*
	 * Even if signal_pending(), we can't quit charge() loop without
	 * accounting. So, UNINTERRUPTIBLE is appropriate. But SIGKILL
	 * under OOM is always welcomed, use TASK_KILLABLE here.
	 */
	if (!locked)
		prepare_to_wait(&memcg_oom_waitq, &wait, TASK_KILLABLE);
	mutex_unlock(&memcg_oom_mutex);

	if (locked)
		mem_cgroup_out_of_memory(mem, mask);
	else {
		schedule();
		finish_wait(&memcg_oom_waitq, &wait);
	}
	mutex_lock(&memcg_oom_mutex);
	mem_cgroup_oom_unlock(mem);
	/*
	 * Here, we use global waitq .....more fine grained waitq ?
	 * Assume following hierarchy.
	 * A/
	 *   01
	 *   02
	 * assume OOM happens both in A and 01 at the same time. Tthey are
	 * mutually exclusive by lock. (kill in 01 helps A.)
	 * When we use per memcg waitq, we have to wake up waiters on A and 02
	 * in addtion to waiters on 01. We use global waitq for avoiding mess.
	 * It will not be a big problem.
	 * (And a task may be moved to other groups while it's waiting for OOM.)
	 */
	wake_up_all(&memcg_oom_waitq);
	mutex_unlock(&memcg_oom_mutex);

	if (test_thread_flag(TIF_MEMDIE) || fatal_signal_pending(current))
		return false;
	/* Give chance to dying process */
	schedule_timeout(1);
	return true;
}

/*
 * Currently used to update mapped file statistics, but the routine can be
 * generalized to update other statistics as well.
 */
void mem_cgroup_update_file_mapped(struct page *page, int val)
{
	struct mem_cgroup *mem;
	struct mem_cgroup_stat *stat;
	struct mem_cgroup_stat_cpu *cpustat;
	int cpu;
	struct page_cgroup *pc;

	pc = lookup_page_cgroup(page);
	if (unlikely(!pc))
		return;

	lock_page_cgroup(pc);
	mem = pc->mem_cgroup;
	if (!mem)
		goto done;

	if (!PageCgroupUsed(pc))
		goto done;

	/*
	 * Preemption is already disabled, we don't need get_cpu()
	 */
	cpu = smp_processor_id();
	stat = &mem->stat;
	cpustat = &stat->cpustat[cpu];

	__mem_cgroup_stat_add_safe(cpustat, MEM_CGROUP_STAT_FILE_MAPPED, val);
	if (val > 0)
		SetPageCgroupFileMapped(pc);
	else if (!page_mapped(page)) /* page could have been remapped */
		ClearPageCgroupFileMapped(pc);
done:
	unlock_page_cgroup(pc);
}

/*
 * Unlike exported interface, "oom" parameter is added. if oom==true,
 * oom-killer can be invoked.
 */
static int __mem_cgroup_try_charge(struct mm_struct *mm,
				   gfp_t gfp_mask, struct mem_cgroup **memcg,
				   bool oom, struct page *page, int page_size)
{
	struct mem_cgroup *mem, *mem_over_limit;
	int nr_retries = MEM_CGROUP_RECLAIM_RETRIES;
	struct res_counter *fail_res;

	/*
	 * Unlike gloval-vm's OOM-kill, we're not in memory shortage
	 * in system level. So, allow to go ahead dying process in addition to
	 * MEMDIE process.
	 */
	if (unlikely(test_thread_flag(TIF_MEMDIE)
		     || fatal_signal_pending(current)))
		goto bypass;

	/*
	 * We always charge the cgroup the mm_struct belongs to.
	 * The mm_struct's mem_cgroup changes on task migration if the
	 * thread group leader migrates. It's possible that mm is not
	 * set, if so charge the init_mm (happens for pagecache usage).
	 */
	mem = *memcg;
	if (likely(!mem)) {
		mem = try_get_mem_cgroup_from_mm(mm);
		*memcg = mem;
	} else {
		css_get(&mem->css);
	}
	if (unlikely(!mem))
		return 0;

	VM_BUG_ON(css_is_removed(&mem->css));

	while (1) {
		int ret = 0;
		unsigned long flags = 0;

		if (mem_cgroup_is_root(mem))
			goto done;
		ret = res_counter_charge(&mem->res, page_size, &fail_res);
		if (likely(!ret)) {
			if (!do_swap_account)
				break;
			ret = res_counter_charge(&mem->memsw, page_size,
							&fail_res);
			if (likely(!ret))
				break;
			/* mem+swap counter fails */
			res_counter_uncharge(&mem->res, page_size);
			flags |= MEM_CGROUP_RECLAIM_NOSWAP;
			mem_over_limit = mem_cgroup_from_res_counter(fail_res,
									memsw);
		} else
			/* mem counter fails */
			mem_over_limit = mem_cgroup_from_res_counter(fail_res,
									res);

		if (!(gfp_mask & __GFP_WAIT))
			goto nomem;

		mem_cgroup_hierarchical_reclaim(mem_over_limit, NULL,
						gfp_mask, flags);

		if (mem_cgroup_check_room(mem_over_limit, page_size))
			continue;
		/* try to avoid oom while someone is moving charge */
		if (mc.moving_task && current != mc.moving_task) {
			struct mem_cgroup *from, *to;
			bool do_continue = false;
			/*
			 * There is a small race that "from" or "to" can be
			 * freed by rmdir, so we use css_tryget().
			 */
			rcu_read_lock();
			from = mc.from;
			to = mc.to;
			if (from && css_tryget(&from->css)) {
				if (mem_over_limit->use_hierarchy)
					do_continue = css_is_ancestor(
							&from->css,
							&mem_over_limit->css);
				else
					do_continue = (from == mem_over_limit);
				css_put(&from->css);
			}
			if (!do_continue && to && css_tryget(&to->css)) {
				if (mem_over_limit->use_hierarchy)
					do_continue = css_is_ancestor(
							&to->css,
							&mem_over_limit->css);
				else
					do_continue = (to == mem_over_limit);
				css_put(&to->css);
			}
			rcu_read_unlock();
			if (do_continue) {
				DEFINE_WAIT(wait);
				prepare_to_wait(&mc.waitq, &wait,
							TASK_INTERRUPTIBLE);
				/* moving charge context might have finished. */
				if (mc.moving_task)
					schedule();
				finish_wait(&mc.waitq, &wait);
				continue;
			}
		}

                if (!nr_retries--) {
			if (!oom)
				goto nomem;
			if (mem_cgroup_handle_oom(mem_over_limit, gfp_mask)) {
				nr_retries = MEM_CGROUP_RECLAIM_RETRIES;
				continue;
			}
			/* When we reach here, current task is dying .*/
			css_put(&mem->css);
			goto bypass;
                }

	}
	/*
	 * Insert ancestor (and ancestor's ancestors), to softlimit RB-tree.
	 * if they exceeds softlimit.
	 */
	if (page && mem_cgroup_soft_limit_check(mem))
		mem_cgroup_update_tree(mem, page);
done:
	return 0;
nomem:
	css_put(&mem->css);
	return -ENOMEM;
bypass:
	*memcg = NULL;
	return 0;
}

/*
 * Somemtimes we have to undo a charge we got by try_charge().
 * This function is for that and do uncharge, put css's refcnt.
 * gotten by try_charge().
 */
static void __mem_cgroup_cancel_charge(struct mem_cgroup *mem,
							unsigned long count)
{
	if (!mem_cgroup_is_root(mem)) {
		res_counter_uncharge(&mem->res, PAGE_SIZE * count);
		if (do_swap_account)
			res_counter_uncharge(&mem->memsw, PAGE_SIZE * count);
	}
}

static void mem_cgroup_cancel_charge(struct mem_cgroup *mem,
				     int page_size, unsigned long charge_count)
{
	__mem_cgroup_cancel_charge(mem,
				(page_size >> PAGE_SHIFT) * charge_count);
	/* we don't need css_put for root */
	if (!mem_cgroup_is_root(mem)) {
		WARN_ON_ONCE(charge_count > INT_MAX);
		__css_put(&mem->css, (int)charge_count);
	}
}

/*
 * A helper function to get mem_cgroup from ID. must be called under
 * rcu_read_lock(). The caller must check css_is_removed() or some if
 * it's concern. (dropping refcnt from swap can be called against removed
 * memcg.)
 */
static struct mem_cgroup *mem_cgroup_lookup(unsigned short id)
{
	struct cgroup_subsys_state *css;

	/* ID 0 is unused ID */
	if (!id)
		return NULL;
	css = css_lookup(&mem_cgroup_subsys, id);
	if (!css)
		return NULL;
	return container_of(css, struct mem_cgroup, css);
}

struct mem_cgroup *try_get_mem_cgroup_from_page(struct page *page)
{
	struct mem_cgroup *mem = NULL;
	struct page_cgroup *pc;
	unsigned short id;
	swp_entry_t ent;

	VM_BUG_ON(!PageLocked(page));

	pc = lookup_page_cgroup(page);
	lock_page_cgroup(pc);
	if (PageCgroupUsed(pc)) {
		mem = pc->mem_cgroup;
		if (mem && !css_tryget(&mem->css))
			mem = NULL;
	} else if (PageSwapCache(page)) {
		ent.val = page_private(page);
		id = lookup_swap_cgroup(ent);
		rcu_read_lock();
		mem = mem_cgroup_lookup(id);
		if (mem && !css_tryget(&mem->css))
			mem = NULL;
		rcu_read_unlock();
	}
	unlock_page_cgroup(pc);
	return mem;
}

/*
 * commit a charge got by __mem_cgroup_try_charge() and makes page_cgroup to be
 * USED state. If already USED, uncharge and return.
 */

static void __mem_cgroup_commit_charge(struct mem_cgroup *mem,
				       struct page_cgroup *pc,
				       enum charge_type ctype,
				       int page_size)
{
	/* try_charge() can return NULL to *memcg, taking care of it. */
	if (!mem)
		return;

	lock_page_cgroup(pc);
	if (unlikely(PageCgroupUsed(pc))) {
		unlock_page_cgroup(pc);
		mem_cgroup_cancel_charge(mem, page_size, 1);
		return;
	}

	pc->mem_cgroup = mem;
	/*
	 * We access a page_cgroup asynchronously without lock_page_cgroup().
	 * Especially when a page_cgroup is taken from a page, pc->mem_cgroup
	 * is accessed after testing USED bit. To make pc->mem_cgroup visible
	 * before USED bit, we need memory barrier here.
	 * See mem_cgroup_add_lru_list(), etc.
 	 */
	smp_wmb();
	switch (ctype) {
	case MEM_CGROUP_CHARGE_TYPE_CACHE:
	case MEM_CGROUP_CHARGE_TYPE_SHMEM:
		SetPageCgroupCache(pc);
		SetPageCgroupUsed(pc);
		break;
	case MEM_CGROUP_CHARGE_TYPE_MAPPED:
		ClearPageCgroupCache(pc);
		SetPageCgroupUsed(pc);
		break;
	default:
		break;
	}

	mem_cgroup_charge_statistics(mem, pc, page_size);

	unlock_page_cgroup(pc);
}

/**
 * mem_cgroup_move_account - move account of the page
 * @pc:	page_cgroup of the page.
 * @from: mem_cgroup which the page is moved from.
 * @to:	mem_cgroup which the page is moved to. @from != @to.
 * @uncharge: whether we should call uncharge and css_put against @from
 *
 * The caller must confirm following.
 * - page is not on LRU (isolate_page() is useful.)
 *
 * returns 0 at success,
 * returns -EBUSY when lock is busy or "pc" is unstable.
 *
 * This function doesn't do "charge" nor css_get to @to, this should
 * be done by the caller (__mem_cgroup_try_charge would be useful).
 *
 * If @uncharge is true, this function does "uncharge" from @from,
 * otherwise this is up to the caller as well.
 */

static int mem_cgroup_move_account(struct page_cgroup *pc,
				   struct mem_cgroup *from,
				   struct mem_cgroup *to,
				   int page_size, bool uncharge)
{
	int ret;

	VM_BUG_ON(from == to);
	VM_BUG_ON(PageLRU(pc->page));

	lock_page_cgroup(pc);

	ret = -EINVAL;
	if (!PageCgroupUsed(pc) || pc->mem_cgroup != from)
		goto out;

	if (PageCgroupFileMapped(pc)) {
		struct mem_cgroup_stat_cpu *cpustat;
		struct mem_cgroup_stat *stat;
		int cpu;
		/*
		 * We don't tace care of page_size bacause the page is file cache.
		 */
		cpu = smp_processor_id();
		/* Update mapped_file data for mem_cgroup "from" */
		stat = &from->stat;
		cpustat = &stat->cpustat[cpu];
		__mem_cgroup_stat_add_safe(cpustat, MEM_CGROUP_STAT_FILE_MAPPED,
						-1);

		/* Update mapped_file data for mem_cgroup "to" */
		stat = &to->stat;
		cpustat = &stat->cpustat[cpu];
		__mem_cgroup_stat_add_safe(cpustat, MEM_CGROUP_STAT_FILE_MAPPED,
						1);
	}

	mem_cgroup_charge_statistics(from, pc, -page_size);
	if (uncharge)
		/* This is not "cancel", but cancel_charge does all we need. */
		mem_cgroup_cancel_charge(from, page_size, 1);

	/* caller should have done css_get */
	pc->mem_cgroup = to;
	mem_cgroup_charge_statistics(to, pc, page_size);
	ret = 0;
out:
	unlock_page_cgroup(pc);
	/*
	 * We charges against "to" which may not have any tasks. Then, "to"
	 * can be under rmdir(). But in current implementation, caller of
	 * this function is just force_empty() and move charge, so it's
	 * garanteed that "to" is never removed. So, we don't check rmdir
	 * status here.
	 */
	return ret;
}

/*
 * move charges to its parent.
 */

static int mem_cgroup_move_parent(struct page_cgroup *pc,
				  struct mem_cgroup *child,
				  gfp_t gfp_mask)
{
	struct page *page = pc->page;
	struct cgroup *cg = child->css.cgroup;
	struct cgroup *pcg = cg->parent;
	struct mem_cgroup *parent;
	int page_size = PAGE_SIZE;
	int ret;
	unsigned long flags;

	/* Is ROOT ? */
	if (!pcg)
		return -EINVAL;

	ret = -EBUSY;
	if (!get_page_unless_zero(page))
		goto out;
	if (isolate_lru_page(page))
		goto put;

	if (PageTransHuge(page)) {
		/*
		 * Do not use compound_order(), the page may be split
		 * concurrently.
		 */
		page_size = HPAGE_SIZE;
	}

	parent = mem_cgroup_from_cont(pcg);
	ret = __mem_cgroup_try_charge(NULL, gfp_mask, &parent, false, page,
				      page_size);
	if (ret || !parent)
		goto put_back;

	flags = compound_lock_irqsave(page);
	/* re-check under compound_lock because the page might be split */
	if (unlikely(page_size != PAGE_SIZE && !PageTransHuge(page))) {
		unsigned long extra = (page_size - PAGE_SIZE) >> PAGE_SHIFT;
		/* uncharge extra charges from parent */
		__mem_cgroup_cancel_charge(parent, extra);
		page_size = PAGE_SIZE;
	}
	ret = mem_cgroup_move_account(pc, child, parent, page_size, true);
	compound_unlock_irqrestore(page, flags);

	if (ret)
		mem_cgroup_cancel_charge(parent, page_size, 1);
put_back:
	putback_lru_page(page);
put:
	put_page(page);
out:
	return ret;
}

/*
 * Charge the memory controller for page usage.
 * Return
 * 0 if the charge was successful
 * < 0 if the cgroup is over its limit
 */
static int mem_cgroup_charge_common(struct page *page, struct mm_struct *mm,
				gfp_t gfp_mask, enum charge_type ctype,
				struct mem_cgroup *memcg)
{
	struct mem_cgroup *mem;
	struct page_cgroup *pc;
	int ret;
	int page_size = PAGE_SIZE;
	bool oom = true;

	if (PageTransHuge(page)) {
		page_size <<= compound_order(page);
		/*
		 * Never OOM-kill a process for a huge page.  The
		 * fault handler will fall back to regular pages.
		 */
		oom = false;
	}

	pc = lookup_page_cgroup(page);
	/* can happen at boot */
	if (unlikely(!pc))
		return 0;
	prefetchw(pc);

	mem = memcg;
	ret = __mem_cgroup_try_charge(mm, gfp_mask, &mem, oom, page,
				      page_size);
	if (ret || !mem)
		return ret;

	__mem_cgroup_commit_charge(mem, pc, ctype, page_size);
	return 0;
}

int mem_cgroup_newpage_charge(struct page *page,
			      struct mm_struct *mm, gfp_t gfp_mask)
{
	if (mem_cgroup_disabled())
		return 0;
	/*
	 * If already mapped, we don't have to account.
	 * If page cache, page->mapping has address_space.
	 * But page->mapping may have out-of-use anon_vma pointer,
	 * detecit it by PageAnon() check. newly-mapped-anon's page->mapping
	 * is NULL.
  	 */
	if (page_mapped(page) || (page->mapping && !PageAnon(page)))
		return 0;
	if (unlikely(!mm))
		mm = &init_mm;
	return mem_cgroup_charge_common(page, mm, gfp_mask,
					MEM_CGROUP_CHARGE_TYPE_MAPPED, NULL);
}

static void
__mem_cgroup_commit_charge_swapin(struct page *page, struct mem_cgroup *ptr,
					enum charge_type ctype);

int mem_cgroup_cache_charge(struct page *page, struct mm_struct *mm,
				gfp_t gfp_mask)
{
	struct mem_cgroup *mem = NULL;
	int ret;

	if (mem_cgroup_disabled())
		return 0;
	if (PageCompound(page))
		return 0;
	/*
	 * Corner case handling. This is called from add_to_page_cache()
	 * in usual. But some FS (shmem) precharges this page before calling it
	 * and call add_to_page_cache() with GFP_NOWAIT.
	 *
	 * For GFP_NOWAIT case, the page may be pre-charged before calling
	 * add_to_page_cache(). (See shmem.c) check it here and avoid to call
	 * charge twice. (It works but has to pay a bit larger cost.)
	 * And when the page is SwapCache, it should take swap information
	 * into account. This is under lock_page() now.
	 */
	if (!(gfp_mask & __GFP_WAIT)) {
		struct page_cgroup *pc;


		pc = lookup_page_cgroup(page);
		if (!pc)
			return 0;
		lock_page_cgroup(pc);
		if (PageCgroupUsed(pc)) {
			unlock_page_cgroup(pc);
			return 0;
		}
		unlock_page_cgroup(pc);
	}

	if (unlikely(!mm && !mem))
		mm = &init_mm;

	if (page_is_file_cache(page))
		return mem_cgroup_charge_common(page, mm, gfp_mask,
				MEM_CGROUP_CHARGE_TYPE_CACHE, NULL);

	/* shmem */
	if (PageSwapCache(page)) {
		ret = mem_cgroup_try_charge_swapin(mm, page, gfp_mask, &mem);
		if (!ret)
			__mem_cgroup_commit_charge_swapin(page, mem,
					MEM_CGROUP_CHARGE_TYPE_SHMEM);
	} else
		ret = mem_cgroup_charge_common(page, mm, gfp_mask,
					MEM_CGROUP_CHARGE_TYPE_SHMEM, mem);

	return ret;
}

/*
 * While swap-in, try_charge -> commit or cancel, the page is locked.
 * And when try_charge() successfully returns, one refcnt to memcg without
 * struct page_cgroup is aquired. This refcnt will be cumsumed by
 * "commit()" or removed by "cancel()"
 */
int mem_cgroup_try_charge_swapin(struct mm_struct *mm,
				 struct page *page,
				 gfp_t mask, struct mem_cgroup **ptr)
{
	struct mem_cgroup *mem;
	int ret;

	if (mem_cgroup_disabled())
		return 0;

	if (!do_swap_account)
		goto charge_cur_mm;
	/*
	 * A racing thread's fault, or swapoff, may have already updated
	 * the pte, and even removed page from swap cache: in those cases
	 * do_swap_page()'s pte_same() test will fail; but there's also a
	 * KSM case which does need to charge the page.
	 */
	if (!PageSwapCache(page))
		goto charge_cur_mm;
	mem = try_get_mem_cgroup_from_page(page);
	if (!mem)
		goto charge_cur_mm;
	*ptr = mem;
	ret = __mem_cgroup_try_charge(NULL, mask, ptr, true, page, PAGE_SIZE);
	/* drop extra refcnt from tryget */
	css_put(&mem->css);
	return ret;
charge_cur_mm:
	if (unlikely(!mm))
		mm = &init_mm;
	return __mem_cgroup_try_charge(mm, mask, ptr, true, page, PAGE_SIZE);
}

static void
__mem_cgroup_commit_charge_swapin(struct page *page, struct mem_cgroup *ptr,
					enum charge_type ctype)
{
	struct page_cgroup *pc;

	if (mem_cgroup_disabled())
		return;
	if (!ptr)
		return;
	cgroup_exclude_rmdir(&ptr->css);
	pc = lookup_page_cgroup(page);
	mem_cgroup_lru_del_before_commit_swapcache(page);
	__mem_cgroup_commit_charge(ptr, pc, ctype, PAGE_SIZE);
	mem_cgroup_lru_add_after_commit_swapcache(page);
	/*
	 * Now swap is on-memory. This means this page may be
	 * counted both as mem and swap....double count.
	 * Fix it by uncharging from memsw. Basically, this SwapCache is stable
	 * under lock_page(). But in do_swap_page()::memory.c, reuse_swap_page()
	 * may call delete_from_swap_cache() before reach here.
	 */
	if (do_swap_account && PageSwapCache(page)) {
		swp_entry_t ent = {.val = page_private(page)};
		unsigned short id;
		struct mem_cgroup *memcg;

		id = swap_cgroup_record(ent, 0);
		rcu_read_lock();
		memcg = mem_cgroup_lookup(id);
		if (memcg) {
			/*
			 * This recorded memcg can be obsolete one. So, avoid
			 * calling css_tryget
			 */
			if (!mem_cgroup_is_root(memcg))
				res_counter_uncharge(&memcg->memsw, PAGE_SIZE);
			mem_cgroup_swap_statistics(memcg, false);
			mem_cgroup_put(memcg);
		}
		rcu_read_unlock();
	}
	/*
	 * At swapin, we may charge account against cgroup which has no tasks.
	 * So, rmdir()->pre_destroy() can be called while we do this charge.
	 * In that case, we need to call pre_destroy() again. check it here.
	 */
	cgroup_release_and_wakeup_rmdir(&ptr->css);
}

void mem_cgroup_commit_charge_swapin(struct page *page, struct mem_cgroup *ptr)
{
	__mem_cgroup_commit_charge_swapin(page, ptr,
					MEM_CGROUP_CHARGE_TYPE_MAPPED);
}

void mem_cgroup_cancel_charge_swapin(struct mem_cgroup *mem)
{
	if (mem_cgroup_disabled())
		return;
	if (!mem)
		return;
	mem_cgroup_cancel_charge(mem, PAGE_SIZE, 1);
}


/*
 * uncharge if !page_mapped(page)
 */
static struct mem_cgroup *
__mem_cgroup_uncharge_common(struct page *page, enum charge_type ctype)
{
	struct page_cgroup *pc;
	struct mem_cgroup *mem = NULL;
	struct mem_cgroup_per_zone *mz;
	int page_size = PAGE_SIZE;

	if (PageTransHuge(page))
		page_size <<= compound_order(page);

	if (mem_cgroup_disabled())
		return NULL;

	if (PageSwapCache(page))
		return NULL;

	/*
	 * Check if our page_cgroup is valid
	 */
	pc = lookup_page_cgroup(page);
	if (unlikely(!pc || !PageCgroupUsed(pc)))
		return NULL;

	lock_page_cgroup(pc);

	mem = pc->mem_cgroup;

	if (!PageCgroupUsed(pc))
		goto unlock_out;

	switch (ctype) {
	case MEM_CGROUP_CHARGE_TYPE_MAPPED:
	case MEM_CGROUP_CHARGE_TYPE_DROP:
		/* See mem_cgroup_prepare_migration() */
		if (page_mapped(page) || PageCgroupMigration(pc))
			goto unlock_out;
		break;
	case MEM_CGROUP_CHARGE_TYPE_SWAPOUT:
		if (!PageAnon(page)) {	/* Shared memory */
			if (page->mapping && !page_is_file_cache(page))
				goto unlock_out;
		} else if (page_mapped(page)) /* Anon */
				goto unlock_out;
		break;
	default:
		break;
	}

	if (!mem_cgroup_is_root(mem)) {
		res_counter_uncharge(&mem->res, page_size);
		if (do_swap_account &&
				(ctype != MEM_CGROUP_CHARGE_TYPE_SWAPOUT))
			res_counter_uncharge(&mem->memsw, page_size);
	}
	if (ctype == MEM_CGROUP_CHARGE_TYPE_SWAPOUT)
		mem_cgroup_swap_statistics(mem, true);
	mem_cgroup_charge_statistics(mem, pc, -page_size);

	ClearPageCgroupUsed(pc);
	/*
	 * pc->mem_cgroup is not cleared here. It will be accessed when it's
	 * freed from LRU. This is safe because uncharged page is expected not
	 * to be reused (freed soon). Exception is SwapCache, it's handled by
	 * special functions.
	 */

	mz = page_cgroup_zoneinfo(pc);
	unlock_page_cgroup(pc);

	if (mem_cgroup_soft_limit_check(mem))
		mem_cgroup_update_tree(mem, page);
	/* at swapout, this memcg will be accessed to record to swap */
	if (ctype != MEM_CGROUP_CHARGE_TYPE_SWAPOUT)
		css_put(&mem->css);

	return mem;

unlock_out:
	unlock_page_cgroup(pc);
	return NULL;
}

void mem_cgroup_uncharge_page(struct page *page)
{
	/* early check. */
	if (page_mapped(page))
		return;
	if (page->mapping && !PageAnon(page))
		return;
	__mem_cgroup_uncharge_common(page, MEM_CGROUP_CHARGE_TYPE_MAPPED);
}

void mem_cgroup_uncharge_cache_page(struct page *page)
{
	VM_BUG_ON(page_mapped(page));
	VM_BUG_ON(page->mapping);
	__mem_cgroup_uncharge_common(page, MEM_CGROUP_CHARGE_TYPE_CACHE);
}
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/*
 * When a hugepage is charged, PCG_USED bit (see mem_cgroup_commit_charge())
 * is set only onto the head of pages in hugepage. When we split it, we
 * have to set all page_cgroups for all pages to have proper page_cgroup.
 *
 * The caller must guarantee all pages under splitting will never be used
 * for other purpose than we currently use it now.
 */

void mem_cgroup_split_hugepage_commit(struct page *tail, struct page *head)
{
	struct mem_cgroup *mem;
	struct page_cgroup *target, *origin;
	struct mem_cgroup_per_zone *mz;

	/* compound lock is held and we're safe */
	origin = lookup_page_cgroup(head);
	if (!origin)
		return;
	if (!origin || !PageCgroupUsed(origin))
		return;
	target = lookup_page_cgroup(tail);
	BUG_ON(!target);
	mem = origin->mem_cgroup;

	BUG_ON(mem != origin->mem_cgroup);
	/*
  	 * Because css_get() is called only against the head, we need to
 	 * call this against tails
 	 */
	css_get(&mem->css);
	target->flags = 0;
	target->mem_cgroup =  mem;
	smp_wmb();
	SetPageCgroupUsed(target);
	/*
	 * LRU accounting should be decremented, because it's updated when
 	 * the target is added to lru. we're under zone->lru_lock
 	 */
	if (PageCgroupAcctLRU(origin)) {
		mz = page_cgroup_zoneinfo(origin);
		MEM_CGROUP_ZSTAT(mz, page_lru(head)) -= 1;
	}
}

#endif
#ifdef CONFIG_SWAP
/*
 * called after __delete_from_swap_cache() and drop "page" account.
 * memcg information is recorded to swap_cgroup of "ent"
 */
void
mem_cgroup_uncharge_swapcache(struct page *page, swp_entry_t ent, bool swapout)
{
	struct mem_cgroup *memcg;
	int ctype = MEM_CGROUP_CHARGE_TYPE_SWAPOUT;

	if (!swapout) /* this was a swap cache but the swap is unused ! */
		ctype = MEM_CGROUP_CHARGE_TYPE_DROP;

	memcg = __mem_cgroup_uncharge_common(page, ctype);

	/* record memcg information */
	if (do_swap_account && swapout && memcg) {
		swap_cgroup_record(ent, css_id(&memcg->css));
		mem_cgroup_get(memcg);
	}
	if (swapout && memcg)
		css_put(&memcg->css);
}
#endif

#ifdef CONFIG_CGROUP_MEM_RES_CTLR_SWAP
/*
 * called from swap_entry_free(). remove record in swap_cgroup and
 * uncharge "memsw" account.
 */
void mem_cgroup_uncharge_swap(swp_entry_t ent)
{
	struct mem_cgroup *memcg;
	unsigned short id;

	if (!do_swap_account)
		return;

	id = swap_cgroup_record(ent, 0);
	rcu_read_lock();
	memcg = mem_cgroup_lookup(id);
	if (memcg) {
		/*
		 * We uncharge this because swap is freed.
		 * This memcg can be obsolete one. We avoid calling css_tryget
		 */
		if (!mem_cgroup_is_root(memcg))
			res_counter_uncharge(&memcg->memsw, PAGE_SIZE);
		mem_cgroup_swap_statistics(memcg, false);
		mem_cgroup_put(memcg);
	}
	rcu_read_unlock();
}

/**
 * mem_cgroup_move_swap_account - move swap charge and swap_cgroup's record.
 * @entry: swap entry to be moved
 * @from:  mem_cgroup which the entry is moved from
 * @to:  mem_cgroup which the entry is moved to
 * @need_fixup: whether we should fixup res_counters and refcounts.
 *
 * It succeeds only when the swap_cgroup's record for this entry is the same
 * as the mem_cgroup's id of @from.
 *
 * Returns 0 on success, -EINVAL on failure.
 *
 * The caller must have charged to @to, IOW, called res_counter_charge() about
 * both res and memsw, and called css_get().
 */
static int mem_cgroup_move_swap_account(swp_entry_t entry,
		struct mem_cgroup *from, struct mem_cgroup *to, bool need_fixup)
{
	unsigned short old_id, new_id;

	old_id = css_id(&from->css);
	new_id = css_id(&to->css);

	if (swap_cgroup_cmpxchg(entry, old_id, new_id) == old_id) {
		mem_cgroup_swap_statistics(from, false);
		mem_cgroup_swap_statistics(to, true);
		/*
		 * This function is only called from task migration context now.
		 * It postpones res_counter and refcount handling till the end
		 * of task migration(mem_cgroup_clear_mc()) for performance
		 * improvement. But we cannot postpone mem_cgroup_get(to)
		 * because if the process that has been moved to @to does
		 * swap-in, the refcount of @to might be decreased to 0.
		 */
		mem_cgroup_get(to);
		if (need_fixup) {
			if (!mem_cgroup_is_root(from))
				res_counter_uncharge(&from->memsw, PAGE_SIZE);
			mem_cgroup_put(from);
			/*
			 * we charged both to->res and to->memsw, so we should
			 * uncharge to->res.
			 */
			if (!mem_cgroup_is_root(to))
				res_counter_uncharge(&to->res, PAGE_SIZE);
			css_put(&to->css);
		}
		return 0;
	}
	return -EINVAL;
}
#else
static inline int mem_cgroup_move_swap_account(swp_entry_t entry,
		struct mem_cgroup *from, struct mem_cgroup *to, bool need_fixup)
{
	return -EINVAL;
}
#endif

/*
 * Before starting migration, account PAGE_SIZE to mem_cgroup that the old
 * page belongs to.
 */
int mem_cgroup_prepare_migration(struct page *page,
	struct page *newpage, struct mem_cgroup **ptr)
{
	struct page_cgroup *pc;
	struct mem_cgroup *mem = NULL;
	enum charge_type ctype;
	int ret = 0;

	if (mem_cgroup_disabled())
		return 0;

	pc = lookup_page_cgroup(page);
	lock_page_cgroup(pc);
	if (PageCgroupUsed(pc)) {
		mem = pc->mem_cgroup;
		css_get(&mem->css);
		/*
		 * At migrating an anonymous page, its mapcount goes down
		 * to 0 and uncharge() will be called. But, even if it's fully
		 * unmapped, migration may fail and this page has to be
		 * charged again. We set MIGRATION flag here and delay uncharge
		 * until end_migration() is called
		 *
		 * Corner Case Thinking
		 * A)
		 * When the old page was mapped as Anon and it's unmap-and-freed
		 * while migration was ongoing.
		 * If unmap finds the old page, uncharge() of it will be delayed
		 * until end_migration(). If unmap finds a new page, it's
		 * uncharged when it make mapcount to be 1->0. If unmap code
		 * finds swap_migration_entry, the new page will not be mapped
		 * and end_migration() will find it(mapcount==0).
		 *
		 * B)
		 * When the old page was mapped but migraion fails, the kernel
		 * remaps it. A charge for it is kept by MIGRATION flag even
		 * if mapcount goes down to 0. We can do remap successfully
		 * without charging it again.
		 *
		 * C)
		 * The "old" page is under lock_page() until the end of
		 * migration, so, the old page itself will not be swapped-out.
		 * If the new page is swapped out before end_migraton, our
		 * hook to usual swap-out path will catch the event.
		 */
		if (PageAnon(page))
			SetPageCgroupMigration(pc);
	}
	unlock_page_cgroup(pc);
	/*
	 * If the page is not charged at this point,
	 * we return here.
	 */
	if (!mem)
		return 0;

	*ptr = mem;
	ret = __mem_cgroup_try_charge(NULL, GFP_KERNEL, ptr, false,
							page, PAGE_SIZE);
	css_put(&mem->css);/* drop extra refcnt */
	if (ret || *ptr == NULL) {
		if (PageAnon(page)) {
			lock_page_cgroup(pc);
			ClearPageCgroupMigration(pc);
			unlock_page_cgroup(pc);
			/*
			 * The old page may be fully unmapped while we kept it.
			 */
			mem_cgroup_uncharge_page(page);
		}
		return -ENOMEM;
	}
	/*
	 * We charge new page before it's used/mapped. So, even if unlock_page()
	 * is called before end_migration, we can catch all events on this new
	 * page. In the case new page is migrated but not remapped, new page's
	 * mapcount will be finally 0 and we call uncharge in end_migration().
	 */
	pc = lookup_page_cgroup(newpage);
	if (PageAnon(page))
		ctype = MEM_CGROUP_CHARGE_TYPE_MAPPED;
	else if (page_is_file_cache(page))
		ctype = MEM_CGROUP_CHARGE_TYPE_CACHE;
	else
		ctype = MEM_CGROUP_CHARGE_TYPE_SHMEM;
	__mem_cgroup_commit_charge(mem, pc, ctype, PAGE_SIZE);
	return ret;
}

/* remove redundant charge if migration failed*/
void mem_cgroup_end_migration(struct mem_cgroup *mem,
	struct page *oldpage, struct page *newpage, bool migration_ok)
{
	struct page *used, *unused;
	struct page_cgroup *pc;

	if (!mem)
		return;
	/* blocks rmdir() */
	cgroup_exclude_rmdir(&mem->css);
	if (!migration_ok) {
		used = oldpage;
		unused = newpage;
	} else {
		used = newpage;
		unused = oldpage;
	}
	/*
	 * We disallowed uncharge of pages under migration because mapcount
	 * of the page goes down to zero, temporarly.
	 * Clear the flag and check the page should be charged.
	 */
	pc = lookup_page_cgroup(oldpage);
	lock_page_cgroup(pc);
	ClearPageCgroupMigration(pc);
	unlock_page_cgroup(pc);

	if (unused != oldpage)
		pc = lookup_page_cgroup(unused);
	__mem_cgroup_uncharge_common(unused, MEM_CGROUP_CHARGE_TYPE_FORCE);

	pc = lookup_page_cgroup(used);
	/*
	 * If a page is a file cache, radix-tree replacement is very atomic
	 * and we can skip this check. When it was an Anon page, its mapcount
	 * goes down to 0. But because we added MIGRATION flage, it's not
	 * uncharged yet. There are several case but page->mapcount check
	 * and USED bit check in mem_cgroup_uncharge_page() will do enough
	 * check. (see prepare_charge() also)
	 */
	if (PageAnon(used))
		mem_cgroup_uncharge_page(used);
	/*
	 * At migration, we may charge account against cgroup which has no
	 * tasks.
	 * So, rmdir()->pre_destroy() can be called while we do this charge.
	 * In that case, we need to call pre_destroy() again. check it here.
	 */
	cgroup_release_and_wakeup_rmdir(&mem->css);
}

/*
 * A call to try to shrink memory usage on charge failure at shmem's swapin.
 * Calling hierarchical_reclaim is not enough because we should update
 * last_oom_jiffies to prevent pagefault_out_of_memory from invoking global OOM.
 * Moreover considering hierarchy, we should reclaim from the mem_over_limit,
 * not from the memcg which this page would be charged to.
 * try_charge_swapin does all of these works properly.
 */
int mem_cgroup_shmem_charge_fallback(struct page *page,
			    struct mm_struct *mm,
			    gfp_t gfp_mask)
{
	struct mem_cgroup *mem = NULL;
	int ret;

	if (mem_cgroup_disabled())
		return 0;

	ret = mem_cgroup_try_charge_swapin(mm, page, gfp_mask, &mem);
	if (!ret)
		mem_cgroup_cancel_charge_swapin(mem); /* it does !mem check */

	return ret;
}

static DEFINE_MUTEX(set_limit_mutex);

static int mem_cgroup_resize_limit(struct mem_cgroup *memcg,
				unsigned long long val)
{
	int retry_count;
	int progress;
	u64 memswlimit;
	int ret = 0;
	int children = mem_cgroup_count_children(memcg);
	u64 curusage, oldusage;

	/*
	 * For keeping hierarchical_reclaim simple, how long we should retry
	 * is depends on callers. We set our retry-count to be function
	 * of # of children which we should visit in this loop.
	 */
	retry_count = MEM_CGROUP_RECLAIM_RETRIES * children;

	oldusage = res_counter_read_u64(&memcg->res, RES_USAGE);

	while (retry_count) {
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		/*
		 * Rather than hide all in some function, I do this in
		 * open coded manner. You see what this really does.
		 * We have to guarantee mem->res.limit < mem->memsw.limit.
		 */
		mutex_lock(&set_limit_mutex);
		memswlimit = res_counter_read_u64(&memcg->memsw, RES_LIMIT);
		if (memswlimit < val) {
			ret = -EINVAL;
			mutex_unlock(&set_limit_mutex);
			break;
		}
		ret = res_counter_set_limit(&memcg->res, val);
		if (!ret) {
			if (memswlimit == val)
				memcg->memsw_is_minimum = true;
			else
				memcg->memsw_is_minimum = false;
		}
		mutex_unlock(&set_limit_mutex);

		if (!ret)
			break;

		progress = mem_cgroup_hierarchical_reclaim(memcg, NULL,
						GFP_KERNEL,
						MEM_CGROUP_RECLAIM_SHRINK);
		curusage = res_counter_read_u64(&memcg->res, RES_USAGE);
		/* Usage is reduced ? */
  		if (curusage >= oldusage)
			retry_count--;
		else
			oldusage = curusage;
	}

	return ret;
}

static int mem_cgroup_resize_memsw_limit(struct mem_cgroup *memcg,
					unsigned long long val)
{
	int retry_count;
	u64 memlimit, oldusage, curusage;
	int children = mem_cgroup_count_children(memcg);
	int ret = -EBUSY;

	/* see mem_cgroup_resize_res_limit */
 	retry_count = children * MEM_CGROUP_RECLAIM_RETRIES;
	oldusage = res_counter_read_u64(&memcg->memsw, RES_USAGE);
	while (retry_count) {
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		/*
		 * Rather than hide all in some function, I do this in
		 * open coded manner. You see what this really does.
		 * We have to guarantee mem->res.limit < mem->memsw.limit.
		 */
		mutex_lock(&set_limit_mutex);
		memlimit = res_counter_read_u64(&memcg->res, RES_LIMIT);
		if (memlimit > val) {
			ret = -EINVAL;
			mutex_unlock(&set_limit_mutex);
			break;
		}
		ret = res_counter_set_limit(&memcg->memsw, val);
		if (!ret) {
			if (memlimit == val)
				memcg->memsw_is_minimum = true;
			else
				memcg->memsw_is_minimum = false;
		}
		mutex_unlock(&set_limit_mutex);

		if (!ret)
			break;

		mem_cgroup_hierarchical_reclaim(memcg, NULL, GFP_KERNEL,
						MEM_CGROUP_RECLAIM_NOSWAP |
						MEM_CGROUP_RECLAIM_SHRINK);
		curusage = res_counter_read_u64(&memcg->memsw, RES_USAGE);
		/* Usage is reduced ? */
		if (curusage >= oldusage)
			retry_count--;
		else
			oldusage = curusage;
	}
	return ret;
}

unsigned long mem_cgroup_soft_limit_reclaim(struct zone *zone, int order,
						gfp_t gfp_mask, int nid,
						int zid)
{
	unsigned long nr_reclaimed = 0;
	struct mem_cgroup_per_zone *mz, *next_mz = NULL;
	unsigned long reclaimed;
	int loop = 0;
	struct mem_cgroup_tree_per_zone *mctz;
	unsigned long long excess;

	if (order > 0)
		return 0;

	mctz = soft_limit_tree_node_zone(nid, zid);
	/*
	 * This loop can run a while, specially if mem_cgroup's continuously
	 * keep exceeding their soft limit and putting the system under
	 * pressure
	 */
	do {
		if (next_mz)
			mz = next_mz;
		else
			mz = mem_cgroup_largest_soft_limit_node(mctz);
		if (!mz)
			break;

		reclaimed = mem_cgroup_hierarchical_reclaim(mz->mem, zone,
						gfp_mask,
						MEM_CGROUP_RECLAIM_SOFT);
		nr_reclaimed += reclaimed;
		spin_lock(&mctz->lock);

		/*
		 * If we failed to reclaim anything from this memory cgroup
		 * it is time to move on to the next cgroup
		 */
		next_mz = NULL;
		if (!reclaimed) {
			do {
				/*
				 * Loop until we find yet another one.
				 *
				 * By the time we get the soft_limit lock
				 * again, someone might have aded the
				 * group back on the RB tree. Iterate to
				 * make sure we get a different mem.
				 * mem_cgroup_largest_soft_limit_node returns
				 * NULL if no other cgroup is present on
				 * the tree
				 */
				next_mz =
				__mem_cgroup_largest_soft_limit_node(mctz);
				if (next_mz == mz) {
					css_put(&next_mz->mem->css);
					next_mz = NULL;
				} else /* next_mz == NULL or other memcg */
					break;
			} while (1);
		}
		__mem_cgroup_remove_exceeded(mz->mem, mz, mctz);
		excess = res_counter_soft_limit_excess(&mz->mem->res);
		/*
		 * One school of thought says that we should not add
		 * back the node to the tree if reclaim returns 0.
		 * But our reclaim could return 0, simply because due
		 * to priority we are exposing a smaller subset of
		 * memory to reclaim from. Consider this as a longer
		 * term TODO.
		 */
		/* If excess == 0, no tree ops */
		__mem_cgroup_insert_exceeded(mz->mem, mz, mctz, excess);
		spin_unlock(&mctz->lock);
		css_put(&mz->mem->css);
		loop++;
		/*
		 * Could not reclaim anything and there are no more
		 * mem cgroups to try or we seem to be looping without
		 * reclaiming anything.
		 */
		if (!nr_reclaimed &&
			(next_mz == NULL ||
			loop > MEM_CGROUP_MAX_SOFT_LIMIT_RECLAIM_LOOPS))
			break;
	} while (!nr_reclaimed);
	if (next_mz)
		css_put(&next_mz->mem->css);
	return nr_reclaimed;
}

/*
 * This routine traverse page_cgroup in given list and drop them all.
 * *And* this routine doesn't reclaim page itself, just removes page_cgroup.
 */
static int mem_cgroup_force_empty_list(struct mem_cgroup *mem,
				int node, int zid, enum lru_list lru)
{
	struct zone *zone;
	struct mem_cgroup_per_zone *mz;
	struct page_cgroup *pc, *busy;
	unsigned long flags, loop;
	struct list_head *list;
	int ret = 0;

	zone = &NODE_DATA(node)->node_zones[zid];
	mz = mem_cgroup_zoneinfo(mem, node, zid);
	list = &mz->lists[lru];

	loop = MEM_CGROUP_ZSTAT(mz, lru);
	/* give some margin against EBUSY etc...*/
	loop += 256;
	busy = NULL;
	while (loop--) {
		ret = 0;
		spin_lock_irqsave(&zone->lru_lock, flags);
		if (list_empty(list)) {
			spin_unlock_irqrestore(&zone->lru_lock, flags);
			break;
		}
		pc = list_entry(list->prev, struct page_cgroup, lru);
		if (busy == pc) {
			list_move(&pc->lru, list);
			busy = 0;
			spin_unlock_irqrestore(&zone->lru_lock, flags);
			continue;
		}
		spin_unlock_irqrestore(&zone->lru_lock, flags);

		ret = mem_cgroup_move_parent(pc, mem, GFP_KERNEL);
		if (ret == -ENOMEM)
			break;

		if (ret == -EBUSY || ret == -EINVAL) {
			/* found lock contention or "pc" is obsolete. */
			busy = pc;
			cond_resched();
		} else
			busy = NULL;
	}

	if (!ret && !list_empty(list))
		return -EBUSY;
	return ret;
}

/*
 * make mem_cgroup's charge to be 0 if there is no task.
 * This enables deleting this mem_cgroup.
 */
static int mem_cgroup_force_empty(struct mem_cgroup *mem, bool free_all)
{
	int ret;
	int node, zid, shrink;
	int nr_retries = MEM_CGROUP_RECLAIM_RETRIES;
	struct cgroup *cgrp = mem->css.cgroup;

	css_get(&mem->css);

	shrink = 0;
	/* should free all ? */
	if (free_all)
		goto try_to_free;
move_account:
	do {
		ret = -EBUSY;
		if (cgroup_task_count(cgrp) || !list_empty(&cgrp->children))
			goto out;
		ret = -EINTR;
		if (signal_pending(current))
			goto out;
		/* This is for making all *used* pages to be on LRU. */
		lru_add_drain_all();
		ret = 0;
		for_each_node_state(node, N_HIGH_MEMORY) {
			for (zid = 0; !ret && zid < MAX_NR_ZONES; zid++) {
				enum lru_list l;
				for_each_lru(l) {
					ret = mem_cgroup_force_empty_list(mem,
							node, zid, l);
					if (ret)
						break;
				}
			}
			if (ret)
				break;
		}
		/* it seems parent cgroup doesn't have enough mem */
		if (ret == -ENOMEM)
			goto try_to_free;
		cond_resched();
	/* "ret" should also be checked to ensure all lists are empty. */
	} while (mem->res.usage > 0 || ret);
out:
	css_put(&mem->css);
	return ret;

try_to_free:
	/* returns EBUSY if there is a task or if we come here twice. */
	if (cgroup_task_count(cgrp) || !list_empty(&cgrp->children) || shrink) {
		ret = -EBUSY;
		goto out;
	}
	/* we call try-to-free pages for make this cgroup empty */
	lru_add_drain_all();
	/* try to free all pages in this cgroup */
	shrink = 1;
	while (nr_retries && mem->res.usage > 0) {
		int progress;

		if (signal_pending(current)) {
			ret = -EINTR;
			goto out;
		}
		progress = try_to_free_mem_cgroup_pages(mem, GFP_KERNEL,
						false, get_swappiness(mem));
		if (!progress) {
			nr_retries--;
			/* maybe some writeback is necessary */
			congestion_wait(BLK_RW_ASYNC, HZ/10);
		}

	}
	lru_add_drain();
	/* try move_account...there may be some *locked* pages. */
	goto move_account;
}

int mem_cgroup_force_empty_write(struct cgroup *cont, unsigned int event)
{
	return mem_cgroup_force_empty(mem_cgroup_from_cont(cont), true);
}


static u64 mem_cgroup_hierarchy_read(struct cgroup *cont, struct cftype *cft)
{
	return mem_cgroup_from_cont(cont)->use_hierarchy;
}

static int mem_cgroup_hierarchy_write(struct cgroup *cont, struct cftype *cft,
					u64 val)
{
	int retval = 0;
	struct mem_cgroup *mem = mem_cgroup_from_cont(cont);
	struct cgroup *parent = cont->parent;
	struct mem_cgroup *parent_mem = NULL;

	if (parent)
		parent_mem = mem_cgroup_from_cont(parent);

	cgroup_lock();
	/*
	 * If parent's use_hiearchy is set, we can't make any modifications
	 * in the child subtrees. If it is unset, then the change can
	 * occur, provided the current cgroup has no children.
	 *
	 * For the root cgroup, parent_mem is NULL, we allow value to be
	 * set if there are no children.
	 */
	if ((!parent_mem || !parent_mem->use_hierarchy) &&
				(val == 1 || val == 0)) {
		if (list_empty(&cont->children))
			mem->use_hierarchy = val;
		else
			retval = -EBUSY;
	} else
		retval = -EINVAL;
	cgroup_unlock();

	return retval;
}

struct mem_cgroup_idx_data {
	s64 val;
	enum mem_cgroup_stat_index idx;
};

static int
mem_cgroup_get_idx_stat(struct mem_cgroup *mem, void *data)
{
	struct mem_cgroup_idx_data *d = data;
	d->val += mem_cgroup_read_stat(&mem->stat, d->idx);
	return 0;
}

static void
mem_cgroup_get_recursive_idx_stat(struct mem_cgroup *mem,
				enum mem_cgroup_stat_index idx, s64 *val)
{
	struct mem_cgroup_idx_data d;
	d.idx = idx;
	d.val = 0;
	mem_cgroup_walk_tree(mem, &d, mem_cgroup_get_idx_stat);
	*val = d.val;
}

static u64 mem_cgroup_read(struct cgroup *cont, struct cftype *cft)
{
	struct mem_cgroup *mem = mem_cgroup_from_cont(cont);
	u64 idx_val, val;
	int type, name;

	type = MEMFILE_TYPE(cft->private);
	name = MEMFILE_ATTR(cft->private);
	switch (type) {
	case _MEM:
		if (name == RES_USAGE && mem_cgroup_is_root(mem)) {
			mem_cgroup_get_recursive_idx_stat(mem,
				MEM_CGROUP_STAT_CACHE, &idx_val);
			val = idx_val;
			mem_cgroup_get_recursive_idx_stat(mem,
				MEM_CGROUP_STAT_RSS, &idx_val);
			val += idx_val;
			val <<= PAGE_SHIFT;
		} else
			val = res_counter_read_u64(&mem->res, name);
		break;
	case _MEMSWAP:
		if (name == RES_USAGE && mem_cgroup_is_root(mem)) {
			mem_cgroup_get_recursive_idx_stat(mem,
				MEM_CGROUP_STAT_CACHE, &idx_val);
			val = idx_val;
			mem_cgroup_get_recursive_idx_stat(mem,
				MEM_CGROUP_STAT_RSS, &idx_val);
			val += idx_val;
			mem_cgroup_get_recursive_idx_stat(mem,
				MEM_CGROUP_STAT_SWAPOUT, &idx_val);
			val += idx_val;
			val <<= PAGE_SHIFT;
		} else
			val = res_counter_read_u64(&mem->memsw, name);
		break;
	default:
		BUG();
		break;
	}
	return val;
}
/*
 * The user of this function is...
 * RES_LIMIT.
 */
static int mem_cgroup_write(struct cgroup *cont, struct cftype *cft,
			    const char *buffer)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	int type, name;
	unsigned long long val;
	int ret;

	type = MEMFILE_TYPE(cft->private);
	name = MEMFILE_ATTR(cft->private);
	switch (name) {
	case RES_LIMIT:
		if (mem_cgroup_is_root(memcg)) { /* Can't set limit on root */
			ret = -EINVAL;
			break;
		}
		/* This function does all necessary parse...reuse it */
		ret = res_counter_memparse_write_strategy(buffer, &val);
		if (ret)
			break;
		if (type == _MEM)
			ret = mem_cgroup_resize_limit(memcg, val);
		else
			ret = mem_cgroup_resize_memsw_limit(memcg, val);
		break;
	case RES_SOFT_LIMIT:
		ret = res_counter_memparse_write_strategy(buffer, &val);
		if (ret)
			break;
		/*
		 * For memsw, soft limits are hard to implement in terms
		 * of semantics, for now, we support soft limits for
		 * control without swap
		 */
		if (type == _MEM)
			ret = res_counter_set_soft_limit(&memcg->res, val);
		else
			ret = -EINVAL;
		break;
	default:
		ret = -EINVAL; /* should be BUG() ? */
		break;
	}
	return ret;
}

static void memcg_get_hierarchical_limit(struct mem_cgroup *memcg,
		unsigned long long *mem_limit, unsigned long long *memsw_limit)
{
	struct cgroup *cgroup;
	unsigned long long min_limit, min_memsw_limit, tmp;

	min_limit = res_counter_read_u64(&memcg->res, RES_LIMIT);
	min_memsw_limit = res_counter_read_u64(&memcg->memsw, RES_LIMIT);
	cgroup = memcg->css.cgroup;
	if (!memcg->use_hierarchy)
		goto out;

	while (cgroup->parent) {
		cgroup = cgroup->parent;
		memcg = mem_cgroup_from_cont(cgroup);
		if (!memcg->use_hierarchy)
			break;
		tmp = res_counter_read_u64(&memcg->res, RES_LIMIT);
		min_limit = min(min_limit, tmp);
		tmp = res_counter_read_u64(&memcg->memsw, RES_LIMIT);
		min_memsw_limit = min(min_memsw_limit, tmp);
	}
out:
	*mem_limit = min_limit;
	*memsw_limit = min_memsw_limit;
	return;
}

static int mem_cgroup_reset(struct cgroup *cont, unsigned int event)
{
	struct mem_cgroup *mem;
	int type, name;

	mem = mem_cgroup_from_cont(cont);
	type = MEMFILE_TYPE(event);
	name = MEMFILE_ATTR(event);
	switch (name) {
	case RES_MAX_USAGE:
		if (type == _MEM)
			res_counter_reset_max(&mem->res);
		else
			res_counter_reset_max(&mem->memsw);
		break;
	case RES_FAILCNT:
		if (type == _MEM)
			res_counter_reset_failcnt(&mem->res);
		else
			res_counter_reset_failcnt(&mem->memsw);
		break;
	}

	return 0;
}

static u64 mem_cgroup_move_charge_read(struct cgroup *cgrp,
					struct cftype *cft)
{
	return mem_cgroup_from_cont(cgrp)->move_charge_at_immigrate;
}

#ifdef CONFIG_MMU
static int mem_cgroup_move_charge_write(struct cgroup *cgrp,
					struct cftype *cft, u64 val)
{
	struct mem_cgroup *mem = mem_cgroup_from_cont(cgrp);

	if (val >= (1 << NR_MOVE_TYPE))
		return -EINVAL;
	/*
	 * We check this value several times in both in can_attach() and
	 * attach(), so we need cgroup lock to prevent this value from being
	 * inconsistent.
	 */
	cgroup_lock();
	mem->move_charge_at_immigrate = val;
	cgroup_unlock();

	return 0;
}
#else
static int mem_cgroup_move_charge_write(struct cgroup *cgrp,
					struct cftype *cft, u64 val)
{
	return -ENOSYS;
}
#endif


/* For read statistics */
enum {
	MCS_CACHE,
	MCS_RSS,
	MCS_FILE_MAPPED,
	MCS_PGPGIN,
	MCS_PGPGOUT,
	MCS_SWAP,
	MCS_INACTIVE_ANON,
	MCS_ACTIVE_ANON,
	MCS_INACTIVE_FILE,
	MCS_ACTIVE_FILE,
	MCS_UNEVICTABLE,
	NR_MCS_STAT,
};

struct mcs_total_stat {
	s64 stat[NR_MCS_STAT];
};

struct {
	char *local_name;
	char *total_name;
} memcg_stat_strings[NR_MCS_STAT] = {
	{"cache", "total_cache"},
	{"rss", "total_rss"},
	{"mapped_file", "total_mapped_file"},
	{"pgpgin", "total_pgpgin"},
	{"pgpgout", "total_pgpgout"},
	{"swap", "total_swap"},
	{"inactive_anon", "total_inactive_anon"},
	{"active_anon", "total_active_anon"},
	{"inactive_file", "total_inactive_file"},
	{"active_file", "total_active_file"},
	{"unevictable", "total_unevictable"}
};


static int mem_cgroup_get_local_stat(struct mem_cgroup *mem, void *data)
{
	struct mcs_total_stat *s = data;
	s64 val;

	/* per cpu stat */
	val = mem_cgroup_read_stat(&mem->stat, MEM_CGROUP_STAT_CACHE);
	s->stat[MCS_CACHE] += val * PAGE_SIZE;
	val = mem_cgroup_read_stat(&mem->stat, MEM_CGROUP_STAT_RSS);
	s->stat[MCS_RSS] += val * PAGE_SIZE;
	val = mem_cgroup_read_stat(&mem->stat, MEM_CGROUP_STAT_FILE_MAPPED);
	s->stat[MCS_FILE_MAPPED] += val * PAGE_SIZE;
	val = mem_cgroup_read_stat(&mem->stat, MEM_CGROUP_STAT_PGPGIN_COUNT);
	s->stat[MCS_PGPGIN] += val;
	val = mem_cgroup_read_stat(&mem->stat, MEM_CGROUP_STAT_PGPGOUT_COUNT);
	s->stat[MCS_PGPGOUT] += val;
	if (do_swap_account) {
		val = mem_cgroup_read_stat(&mem->stat, MEM_CGROUP_STAT_SWAPOUT);
		s->stat[MCS_SWAP] += val * PAGE_SIZE;
	}

	/* per zone stat */
	val = mem_cgroup_get_local_zonestat(mem, LRU_INACTIVE_ANON);
	s->stat[MCS_INACTIVE_ANON] += val * PAGE_SIZE;
	val = mem_cgroup_get_local_zonestat(mem, LRU_ACTIVE_ANON);
	s->stat[MCS_ACTIVE_ANON] += val * PAGE_SIZE;
	val = mem_cgroup_get_local_zonestat(mem, LRU_INACTIVE_FILE);
	s->stat[MCS_INACTIVE_FILE] += val * PAGE_SIZE;
	val = mem_cgroup_get_local_zonestat(mem, LRU_ACTIVE_FILE);
	s->stat[MCS_ACTIVE_FILE] += val * PAGE_SIZE;
	val = mem_cgroup_get_local_zonestat(mem, LRU_UNEVICTABLE);
	s->stat[MCS_UNEVICTABLE] += val * PAGE_SIZE;
	return 0;
}

static void
mem_cgroup_get_total_stat(struct mem_cgroup *mem, struct mcs_total_stat *s)
{
	mem_cgroup_walk_tree(mem, s, mem_cgroup_get_local_stat);
}

static int mem_control_stat_show(struct cgroup *cont, struct cftype *cft,
				 struct cgroup_map_cb *cb)
{
	struct mem_cgroup *mem_cont = mem_cgroup_from_cont(cont);
	struct mcs_total_stat mystat;
	int i;

	memset(&mystat, 0, sizeof(mystat));
	mem_cgroup_get_local_stat(mem_cont, &mystat);

	for (i = 0; i < NR_MCS_STAT; i++) {
		if (i == MCS_SWAP && !do_swap_account)
			continue;
		cb->fill(cb, memcg_stat_strings[i].local_name, mystat.stat[i]);
	}

	/* Hierarchical information */
	{
		unsigned long long limit, memsw_limit;
		memcg_get_hierarchical_limit(mem_cont, &limit, &memsw_limit);
		cb->fill(cb, "hierarchical_memory_limit", limit);
		if (do_swap_account)
			cb->fill(cb, "hierarchical_memsw_limit", memsw_limit);
	}

	memset(&mystat, 0, sizeof(mystat));
	mem_cgroup_get_total_stat(mem_cont, &mystat);
	for (i = 0; i < NR_MCS_STAT; i++) {
		if (i == MCS_SWAP && !do_swap_account)
			continue;
		cb->fill(cb, memcg_stat_strings[i].total_name, mystat.stat[i]);
	}

#ifdef CONFIG_DEBUG_VM
	cb->fill(cb, "inactive_ratio", calc_inactive_ratio(mem_cont, NULL));

	{
		int nid, zid;
		struct mem_cgroup_per_zone *mz;
		unsigned long recent_rotated[2] = {0, 0};
		unsigned long recent_scanned[2] = {0, 0};

		for_each_online_node(nid)
			for (zid = 0; zid < MAX_NR_ZONES; zid++) {
				mz = mem_cgroup_zoneinfo(mem_cont, nid, zid);

				recent_rotated[0] +=
					mz->reclaim_stat.recent_rotated[0];
				recent_rotated[1] +=
					mz->reclaim_stat.recent_rotated[1];
				recent_scanned[0] +=
					mz->reclaim_stat.recent_scanned[0];
				recent_scanned[1] +=
					mz->reclaim_stat.recent_scanned[1];
			}
		cb->fill(cb, "recent_rotated_anon", recent_rotated[0]);
		cb->fill(cb, "recent_rotated_file", recent_rotated[1]);
		cb->fill(cb, "recent_scanned_anon", recent_scanned[0]);
		cb->fill(cb, "recent_scanned_file", recent_scanned[1]);
	}
#endif

	return 0;
}

static u64 mem_cgroup_swappiness_read(struct cgroup *cgrp, struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);

	return get_swappiness(memcg);
}

static int mem_cgroup_swappiness_write(struct cgroup *cgrp, struct cftype *cft,
				       u64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);
	struct mem_cgroup *parent;

	if (val > 100)
		return -EINVAL;

	if (cgrp->parent == NULL)
		return -EINVAL;

	parent = mem_cgroup_from_cont(cgrp->parent);

	cgroup_lock();

	/* If under hierarchy, only empty-root can set this value */
	if ((parent->use_hierarchy) ||
	    (memcg->use_hierarchy && !list_empty(&cgrp->children))) {
		cgroup_unlock();
		return -EINVAL;
	}

	spin_lock(&memcg->reclaim_param_lock);
	memcg->swappiness = val;
	spin_unlock(&memcg->reclaim_param_lock);

	cgroup_unlock();

	return 0;
}


static struct cftype mem_cgroup_files[] = {
	{
		.name = "usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_USAGE),
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "max_usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_MAX_USAGE),
		.trigger = mem_cgroup_reset,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "limit_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_LIMIT),
		.write_string = mem_cgroup_write,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "soft_limit_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_SOFT_LIMIT),
		.write_string = mem_cgroup_write,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "failcnt",
		.private = MEMFILE_PRIVATE(_MEM, RES_FAILCNT),
		.trigger = mem_cgroup_reset,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "stat",
		.read_map = mem_control_stat_show,
	},
	{
		.name = "force_empty",
		.trigger = mem_cgroup_force_empty_write,
	},
	{
		.name = "use_hierarchy",
		.write_u64 = mem_cgroup_hierarchy_write,
		.read_u64 = mem_cgroup_hierarchy_read,
	},
	{
		.name = "swappiness",
		.read_u64 = mem_cgroup_swappiness_read,
		.write_u64 = mem_cgroup_swappiness_write,
	},
	{
		.name = "move_charge_at_immigrate",
		.read_u64 = mem_cgroup_move_charge_read,
		.write_u64 = mem_cgroup_move_charge_write,
	},
};

#ifdef CONFIG_CGROUP_MEM_RES_CTLR_SWAP
static struct cftype memsw_cgroup_files[] = {
	{
		.name = "memsw.usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_USAGE),
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "memsw.max_usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_MAX_USAGE),
		.trigger = mem_cgroup_reset,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "memsw.limit_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_LIMIT),
		.write_string = mem_cgroup_write,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "memsw.failcnt",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_FAILCNT),
		.trigger = mem_cgroup_reset,
		.read_u64 = mem_cgroup_read,
	},
};

static int register_memsw_files(struct cgroup *cont, struct cgroup_subsys *ss)
{
	if (!do_swap_account)
		return 0;
	return cgroup_add_files(cont, ss, memsw_cgroup_files,
				ARRAY_SIZE(memsw_cgroup_files));
};
#else
static int register_memsw_files(struct cgroup *cont, struct cgroup_subsys *ss)
{
	return 0;
}
#endif

static int alloc_mem_cgroup_per_zone_info(struct mem_cgroup *mem, int node)
{
	struct mem_cgroup_per_node *pn;
	struct mem_cgroup_per_zone *mz;
	enum lru_list l;
	int zone, tmp = node;
	/*
	 * This routine is called against possible nodes.
	 * But it's BUG to call kmalloc() against offline node.
	 *
	 * TODO: this routine can waste much memory for nodes which will
	 *       never be onlined. It's better to use memory hotplug callback
	 *       function.
	 */
	if (!node_state(node, N_NORMAL_MEMORY))
		tmp = -1;
	pn = kmalloc_node(sizeof(*pn), GFP_KERNEL, tmp);
	if (!pn)
		return 1;

	mem->info.nodeinfo[node] = pn;
	memset(pn, 0, sizeof(*pn));

	for (zone = 0; zone < MAX_NR_ZONES; zone++) {
		mz = &pn->zoneinfo[zone];
		for_each_lru(l)
			INIT_LIST_HEAD(&mz->lists[l]);
		mz->usage_in_excess = 0;
		mz->on_tree = false;
		mz->mem = mem;
	}
	return 0;
}

static void free_mem_cgroup_per_zone_info(struct mem_cgroup *mem, int node)
{
	kfree(mem->info.nodeinfo[node]);
}

static int mem_cgroup_size(void)
{
	int cpustat_size = nr_cpu_ids * sizeof(struct mem_cgroup_stat_cpu);
	return sizeof(struct mem_cgroup) + cpustat_size;
}

static struct mem_cgroup *mem_cgroup_alloc(void)
{
	struct mem_cgroup *mem;
	int size = mem_cgroup_size();

	if (size < PAGE_SIZE)
		mem = kmalloc(size, GFP_KERNEL);
	else
		mem = vmalloc(size);

	if (mem)
		memset(mem, 0, size);
	return mem;
}

/*
 * At destroying mem_cgroup, references from swap_cgroup can remain.
 * (scanning all at force_empty is too costly...)
 *
 * Instead of clearing all references at force_empty, we remember
 * the number of reference from swap_cgroup and free mem_cgroup when
 * it goes down to 0.
 *
 * Removal of cgroup itself succeeds regardless of refs from swap.
 */

static void __mem_cgroup_free(struct mem_cgroup *mem)
{
	int node;

	mem_cgroup_remove_from_trees(mem);
	free_css_id(&mem_cgroup_subsys, &mem->css);

	for_each_node_state(node, N_POSSIBLE)
		free_mem_cgroup_per_zone_info(mem, node);

	if (mem_cgroup_size() < PAGE_SIZE)
		kfree(mem);
	else
		vfree(mem);
}

static void mem_cgroup_get(struct mem_cgroup *mem)
{
	atomic_inc(&mem->refcnt);
}

static void __mem_cgroup_put(struct mem_cgroup *mem, int count)
{
	if (atomic_sub_and_test(count, &mem->refcnt)) {
		struct mem_cgroup *parent = parent_mem_cgroup(mem);
		__mem_cgroup_free(mem);
		if (parent)
			mem_cgroup_put(parent);
	}
}

static void mem_cgroup_put(struct mem_cgroup *mem)
{
	__mem_cgroup_put(mem, 1);
}

/*
 * Returns the parent mem_cgroup in memcgroup hierarchy with hierarchy enabled.
 */
static struct mem_cgroup *parent_mem_cgroup(struct mem_cgroup *mem)
{
	if (!mem->res.parent)
		return NULL;
	return mem_cgroup_from_res_counter(mem->res.parent, res);
}

#ifdef CONFIG_CGROUP_MEM_RES_CTLR_SWAP
static void __init enable_swap_cgroup(void)
{
	if (!mem_cgroup_disabled() && really_do_swap_account)
		do_swap_account = 1;
}
#else
static void __init enable_swap_cgroup(void)
{
}
#endif

static int mem_cgroup_soft_limit_tree_init(void)
{
	struct mem_cgroup_tree_per_node *rtpn;
	struct mem_cgroup_tree_per_zone *rtpz;
	int tmp, node, zone;

	for_each_node_state(node, N_POSSIBLE) {
		tmp = node;
		if (!node_state(node, N_NORMAL_MEMORY))
			tmp = -1;
		rtpn = kzalloc_node(sizeof(*rtpn), GFP_KERNEL, tmp);
		if (!rtpn)
			return 1;

		soft_limit_tree.rb_tree_per_node[node] = rtpn;

		for (zone = 0; zone < MAX_NR_ZONES; zone++) {
			rtpz = &rtpn->rb_tree_per_zone[zone];
			rtpz->rb_root = RB_ROOT;
			spin_lock_init(&rtpz->lock);
		}
	}
	return 0;
}

static struct cgroup_subsys_state * __ref
mem_cgroup_create(struct cgroup_subsys *ss, struct cgroup *cont)
{
	struct mem_cgroup *mem, *parent;
	long error = -ENOMEM;
	int node;

	mem = mem_cgroup_alloc();
	if (!mem)
		return ERR_PTR(error);

	for_each_node_state(node, N_POSSIBLE)
		if (alloc_mem_cgroup_per_zone_info(mem, node))
			goto free_out;

	/* root ? */
	if (cont->parent == NULL) {
		enable_swap_cgroup();
		parent = NULL;
		root_mem_cgroup = mem;
		if (mem_cgroup_soft_limit_tree_init())
			goto free_out;

	} else {
		parent = mem_cgroup_from_cont(cont->parent);
		mem->use_hierarchy = parent->use_hierarchy;
	}

	if (parent && parent->use_hierarchy) {
		res_counter_init(&mem->res, &parent->res);
		res_counter_init(&mem->memsw, &parent->memsw);
		/*
		 * We increment refcnt of the parent to ensure that we can
		 * safely access it on res_counter_charge/uncharge.
		 * This refcnt will be decremented when freeing this
		 * mem_cgroup(see mem_cgroup_put).
		 */
		mem_cgroup_get(parent);
	} else {
		res_counter_init(&mem->res, NULL);
		res_counter_init(&mem->memsw, NULL);
	}
	mem->last_scanned_child = 0;
	spin_lock_init(&mem->reclaim_param_lock);

	if (parent)
		mem->swappiness = get_swappiness(parent);
	atomic_set(&mem->refcnt, 1);
	mem->move_charge_at_immigrate = 0;
	return &mem->css;
free_out:
	__mem_cgroup_free(mem);
	root_mem_cgroup = NULL;
	return ERR_PTR(error);
}

static int mem_cgroup_pre_destroy(struct cgroup_subsys *ss,
					struct cgroup *cont)
{
	struct mem_cgroup *mem = mem_cgroup_from_cont(cont);

	return mem_cgroup_force_empty(mem, false);
}

static void mem_cgroup_destroy(struct cgroup_subsys *ss,
				struct cgroup *cont)
{
	struct mem_cgroup *mem = mem_cgroup_from_cont(cont);

	mem_cgroup_put(mem);
}

static int mem_cgroup_populate(struct cgroup_subsys *ss,
				struct cgroup *cont)
{
	int ret;

	ret = cgroup_add_files(cont, ss, mem_cgroup_files,
				ARRAY_SIZE(mem_cgroup_files));

	if (!ret)
		ret = register_memsw_files(cont, ss);
	return ret;
}

#ifdef CONFIG_MMU
/* Handlers for move charge at task migration. */
#define PRECHARGE_COUNT_AT_ONCE	256
static int mem_cgroup_do_precharge(unsigned long count)
{
	int ret = 0;
	int batch_count = PRECHARGE_COUNT_AT_ONCE;
	struct mem_cgroup *mem = mc.to;

	if (mem_cgroup_is_root(mem)) {
		mc.precharge += count;
		/* we don't need css_get for root */
		return ret;
	}
	/* try to charge at once */
	if (count > 1) {
		struct res_counter *dummy;
		/*
		 * "mem" cannot be under rmdir() because we've already checked
		 * by cgroup_lock_live_cgroup() that it is not removed and we
		 * are still under the same cgroup_mutex. So we can postpone
		 * css_get().
		 */
		if (res_counter_charge(&mem->res, PAGE_SIZE * count, &dummy))
			goto one_by_one;
		if (do_swap_account && res_counter_charge(&mem->memsw,
						PAGE_SIZE * count, &dummy)) {
			res_counter_uncharge(&mem->res, PAGE_SIZE * count);
			goto one_by_one;
		}
		mc.precharge += count;
		VM_BUG_ON(test_bit(CSS_ROOT, &mem->css.flags));
		WARN_ON_ONCE(count > INT_MAX);
		__css_get(&mem->css, (int)count);
		return ret;
	}
one_by_one:
	/* fall back to one by one charge */
	while (count--) {
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		if (!batch_count--) {
			batch_count = PRECHARGE_COUNT_AT_ONCE;
			cond_resched();
		}
		ret = __mem_cgroup_try_charge(NULL, GFP_KERNEL, &mem,
							false, NULL, PAGE_SIZE);
		if (ret || !mem)
			/* mem_cgroup_clear_mc() will do uncharge later */
			return -ENOMEM;
		mc.precharge++;
	}
	return ret;
}

/**
 * is_target_pte_for_mc - check a pte whether it is valid for move charge
 * @vma: the vma the pte to be checked belongs
 * @addr: the address corresponding to the pte to be checked
 * @ptent: the pte to be checked
 * @target: the pointer the target page or swap ent will be stored(can be NULL)
 *
 * Returns
 *   0(MC_TARGET_NONE): if the pte is not a target for move charge.
 *   1(MC_TARGET_PAGE): if the page corresponding to this pte is a target for
 *     move charge. if @target is not NULL, the page is stored in target->page
 *     with extra refcnt got(Callers should handle it).
 *   2(MC_TARGET_SWAP): if the swap entry corresponding to this pte is a
 *     target for charge migration. if @target is not NULL, the entry is stored
 *     in target->ent.
 *
 * Called with pte lock held.
 */
union mc_target {
	struct page	*page;
	swp_entry_t	ent;
};

enum mc_target_type {
	MC_TARGET_NONE,	/* not used */
	MC_TARGET_PAGE,
	MC_TARGET_SWAP,
};

static struct page *mc_handle_present_pte(struct vm_area_struct *vma,
						unsigned long addr, pte_t ptent)
{
	struct page *page = vm_normal_page(vma, addr, ptent);

	if (!page || !page_mapped(page))
		return NULL;
	if (PageAnon(page)) {
		/* we don't move shared anon */
		if (!move_anon() || page_mapcount(page) > 2)
			return NULL;
	} else if (!move_file())
		/* we ignore mapcount for file pages */
		return NULL;
	if (!get_page_unless_zero(page))
		return NULL;

	return page;
}

static struct page *mc_handle_swap_pte(struct vm_area_struct *vma,
			unsigned long addr, pte_t ptent, swp_entry_t *entry)
{
	int usage_count;
	struct page *page = NULL;
	swp_entry_t ent = pte_to_swp_entry(ptent);

	if (!move_anon() || non_swap_entry(ent))
		return NULL;
	usage_count = mem_cgroup_count_swap_user(ent, &page);
	if (usage_count > 1) { /* we don't move shared anon */
		if (page)
			put_page(page);
		return NULL;
	}
	if (do_swap_account)
		entry->val = ent.val;

	return page;
}

static struct page *mc_handle_file_pte(struct vm_area_struct *vma,
			unsigned long addr, pte_t ptent, swp_entry_t *entry)
{
	struct page *page = NULL;
	struct inode *inode;
	struct address_space *mapping;
	pgoff_t pgoff;

	if (!vma->vm_file) /* anonymous vma */
		return NULL;
	if (!move_file())
		return NULL;

	inode = vma->vm_file->f_path.dentry->d_inode;
	mapping = vma->vm_file->f_mapping;
	if (pte_none(ptent))
		pgoff = linear_page_index(vma, addr);
	else /* pte_file(ptent) is true */
		pgoff = pte_to_pgoff(ptent);

	/* page is moved even if it's not RSS of this task(page-faulted). */
	if (!mapping_cap_swap_backed(mapping)) { /* normal file */
		page = find_get_page(mapping, pgoff);
	} else { /* shmem/tmpfs file. we should take account of swap too. */
		swp_entry_t ent;
		mem_cgroup_get_shmem_target(inode, pgoff, &page, &ent);
		if (do_swap_account)
			entry->val = ent.val;
	}

	return page;
}

static int is_target_pte_for_mc(struct vm_area_struct *vma,
		unsigned long addr, pte_t ptent, union mc_target *target)
{
	struct page *page = NULL;
	struct page_cgroup *pc;
	int ret = 0;
	swp_entry_t ent = { .val = 0 };

	if (pte_present(ptent))
		page = mc_handle_present_pte(vma, addr, ptent);
	else if (is_swap_pte(ptent))
		page = mc_handle_swap_pte(vma, addr, ptent, &ent);
	else if (pte_none(ptent) || pte_file(ptent))
		page = mc_handle_file_pte(vma, addr, ptent, &ent);

	if (!page && !ent.val)
		return 0;
	if (page) {
		pc = lookup_page_cgroup(page);
		/*
		 * Do only loose check w/o page_cgroup lock.
		 * mem_cgroup_move_account() checks the pc is valid or not under
		 * the lock.
		 */
		if (PageCgroupUsed(pc) && pc->mem_cgroup == mc.from) {
			ret = MC_TARGET_PAGE;
			if (target)
				target->page = page;
		}
		if (!ret || !target)
			put_page(page);
	}
	/* There is a swap entry and a page doesn't exist or isn't charged */
	if (ent.val && !ret &&
			css_id(&mc.from->css) == lookup_swap_cgroup(ent)) {
		ret = MC_TARGET_SWAP;
		if (target)
			target->ent = ent;
	}
	return ret;
}

static int mem_cgroup_count_precharge_pte_range(pmd_t *pmd,
					unsigned long addr, unsigned long end,
					struct mm_walk *walk)
{
	struct vm_area_struct *vma = walk->private;
	pte_t *pte;
	spinlock_t *ptl;

	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	for (; addr != end; pte++, addr += PAGE_SIZE)
		if (is_target_pte_for_mc(vma, addr, *pte, NULL))
			mc.precharge++;	/* increment precharge temporarily */
	pte_unmap_unlock(pte - 1, ptl);
	cond_resched();

	return 0;
}

static unsigned long mem_cgroup_count_precharge(struct mm_struct *mm)
{
	unsigned long precharge;
	struct vm_area_struct *vma;

	/* We've already held the mmap_sem */
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		struct mm_walk mem_cgroup_count_precharge_walk = {
			.pmd_entry = mem_cgroup_count_precharge_pte_range,
			.mm = mm,
			.private = vma,
		};
		if (is_vm_hugetlb_page(vma))
			continue;
		walk_page_range(vma->vm_start, vma->vm_end,
					&mem_cgroup_count_precharge_walk);
	}

	precharge = mc.precharge;
	mc.precharge = 0;

	return precharge;
}

static int mem_cgroup_precharge_mc(struct mm_struct *mm)
{
	return mem_cgroup_do_precharge(mem_cgroup_count_precharge(mm));
}

static void mem_cgroup_clear_mc(void)
{
	/* we must uncharge all the leftover precharges from mc.to */
	while (mc.precharge) {
		mem_cgroup_cancel_charge(mc.to, PAGE_SIZE, mc.precharge);
		mc.precharge = 0;
	}
	/*
	 * we didn't uncharge from mc.from at mem_cgroup_move_account(), so
	 * we must uncharge here.
	 */
	if (mc.moved_charge) {
		mem_cgroup_cancel_charge(mc.from, PAGE_SIZE, mc.moved_charge);
		mc.moved_charge = 0;
	}
	/* we must fixup refcnts and charges */
	if (mc.moved_swap) {
		WARN_ON_ONCE(mc.moved_swap > INT_MAX);
		/* uncharge swap account from the old cgroup */
		if (!mem_cgroup_is_root(mc.from))
			res_counter_uncharge(&mc.from->memsw,
						PAGE_SIZE * mc.moved_swap);
		__mem_cgroup_put(mc.from, mc.moved_swap);

		if (!mem_cgroup_is_root(mc.to)) {
			/*
			 * we charged both to->res and to->memsw, so we should
			 * uncharge to->res.
			 */
			res_counter_uncharge(&mc.to->res,
						PAGE_SIZE * mc.moved_swap);
			VM_BUG_ON(test_bit(CSS_ROOT, &mc.to->css.flags));
			__css_put(&mc.to->css, mc.moved_swap);
		}
		/* we've already done mem_cgroup_get(mc.to) */

		mc.moved_swap = 0;
	}
	if (mc.mm) {
		up_read(&mc.mm->mmap_sem);
		mmput(mc.mm);
	}
	mc.from = NULL;
	mc.to = NULL;
	mc.moving_task = NULL;
	mc.mm = NULL;
	wake_up_all(&mc.waitq);
}

static int mem_cgroup_can_attach(struct cgroup_subsys *ss,
				struct cgroup *cgroup,
				struct task_struct *p,
				bool threadgroup)
{
	int ret = 0;
	struct mem_cgroup *mem = mem_cgroup_from_cont(cgroup);

	if (mem->move_charge_at_immigrate) {
		struct mm_struct *mm;
		struct mem_cgroup *from = mem_cgroup_from_task(p);

		VM_BUG_ON(from == mem);

		mm = get_task_mm(p);
		if (!mm)
			return 0;
		/* We move charges only when we move a owner of the mm */
		if (mm->owner == p) {
			/*
			 * We do all the move charge works under one mmap_sem to
			 * avoid deadlock with down_write(&mmap_sem)
			 * -> try_charge() -> if (mc.moving_task) -> sleep.
			 */
			down_read(&mm->mmap_sem);

			VM_BUG_ON(mc.from);
			VM_BUG_ON(mc.to);
			VM_BUG_ON(mc.precharge);
			VM_BUG_ON(mc.moved_charge);
			VM_BUG_ON(mc.moved_swap);
			VM_BUG_ON(mc.moving_task);
			VM_BUG_ON(mc.mm);

			mc.from = from;
			mc.to = mem;
			mc.precharge = 0;
			mc.moved_charge = 0;
			mc.moved_swap = 0;
			mc.moving_task = current;
			mc.mm = mm;

			ret = mem_cgroup_precharge_mc(mm);
			if (ret)
				mem_cgroup_clear_mc();
			/* We call up_read() and mmput() in clear_mc(). */
		} else
			mmput(mm);
	}
	return ret;
}

static void mem_cgroup_cancel_attach(struct cgroup_subsys *ss,
				struct cgroup *cgroup,
				struct task_struct *p,
				bool threadgroup)
{
	mem_cgroup_clear_mc();
}

static int mem_cgroup_move_charge_pte_range(pmd_t *pmd,
				unsigned long addr, unsigned long end,
				struct mm_walk *walk)
{
	int ret = 0;
	struct vm_area_struct *vma = walk->private;
	pte_t *pte;
	spinlock_t *ptl;

retry:
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	for (; addr != end; addr += PAGE_SIZE) {
		pte_t ptent = *(pte++);
		union mc_target target;
		int type;
		struct page *page;
		struct page_cgroup *pc;
		swp_entry_t ent;

		if (!mc.precharge)
			break;

		type = is_target_pte_for_mc(vma, addr, ptent, &target);
		switch (type) {
		case MC_TARGET_PAGE:
			page = target.page;
			if (isolate_lru_page(page))
				goto put;
			pc = lookup_page_cgroup(page);
			if (!mem_cgroup_move_account(pc, mc.from, mc.to,
							PAGE_SIZE, false)) {
				mc.precharge--;
				/* we uncharge from mc.from later. */
				mc.moved_charge++;
			}
			putback_lru_page(page);
put:			/* is_target_pte_for_mc() gets the page */
			put_page(page);
			break;
		case MC_TARGET_SWAP:
			ent = target.ent;
			if (!mem_cgroup_move_swap_account(ent,
						mc.from, mc.to, false)) {
				mc.precharge--;
				/* we fixup refcnts and charges later. */
				mc.moved_swap++;
			}
			break;
		default:
			break;
		}
	}
	pte_unmap_unlock(pte - 1, ptl);
	cond_resched();

	if (addr != end) {
		/*
		 * We have consumed all precharges we got in can_attach().
		 * We try charge one by one, but don't do any additional
		 * charges to mc.to if we have failed in charge once in attach()
		 * phase.
		 */
		ret = mem_cgroup_do_precharge(1);
		if (!ret)
			goto retry;
	}

	return ret;
}

static void mem_cgroup_move_charge(struct mm_struct *mm)
{
	struct vm_area_struct *vma;

	lru_add_drain_all();
	/* We've already held the mmap_sem */
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		int ret;
		struct mm_walk mem_cgroup_move_charge_walk = {
			.pmd_entry = mem_cgroup_move_charge_pte_range,
			.mm = mm,
			.private = vma,
		};
		if (is_vm_hugetlb_page(vma))
			continue;
		ret = walk_page_range(vma->vm_start, vma->vm_end,
						&mem_cgroup_move_charge_walk);
		if (ret)
			/*
			 * means we have consumed all precharges and failed in
			 * doing additional charge. Just abandon here.
			 */
			break;
	}
}

static void mem_cgroup_move_task(struct cgroup_subsys *ss,
				struct cgroup *cont,
				struct cgroup *old_cont,
				struct task_struct *p,
				bool threadgroup)
{
	if (!mc.mm)
		/* no need to move charge */
		return;

	mem_cgroup_move_charge(mc.mm);
	mem_cgroup_clear_mc();
}
#else	/* !CONFIG_MMU */
static int mem_cgroup_can_attach(struct cgroup_subsys *ss,
				struct cgroup *cgroup,
				struct task_struct *p,
				bool threadgroup)
{
	return 0;
}
static void mem_cgroup_cancel_attach(struct cgroup_subsys *ss,
				struct cgroup *cgroup,
				struct task_struct *p,
				bool threadgroup)
{
}
static void mem_cgroup_move_task(struct cgroup_subsys *ss,
				struct cgroup *cont,
				struct cgroup *old_cont,
				struct task_struct *p,
				bool threadgroup)
{
}
#endif

struct cgroup_subsys mem_cgroup_subsys = {
	.name = "memory",
	.subsys_id = mem_cgroup_subsys_id,
	.create = mem_cgroup_create,
	.pre_destroy = mem_cgroup_pre_destroy,
	.destroy = mem_cgroup_destroy,
	.populate = mem_cgroup_populate,
	.can_attach = mem_cgroup_can_attach,
	.cancel_attach = mem_cgroup_cancel_attach,
	.attach = mem_cgroup_move_task,
	.early_init = 0,
	.use_id = 1,
};

#ifdef CONFIG_CGROUP_MEM_RES_CTLR_SWAP

static int __init disable_swap_account(char *s)
{
	really_do_swap_account = 0;
	return 1;
}
__setup("noswapaccount", disable_swap_account);
#endif
