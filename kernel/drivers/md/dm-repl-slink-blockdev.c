/*
 * Copyright (C) 2009 Red Hat, Inc. All rights reserved.
 *
 * Module Author: Heinz Mauelshagen (heinzm@redhat.com)
 *
 * This file is released under the GPL.
 *
 *
 * "blockdev" site link handler for the replicator target supporting
 * devices on block transports with device node access abstracting
 * the nature of the access to the caller.
 *
 * It handles the fallbehind thresholds, temporary transport failures,
 * their recovery and initial/partial device resynchronization.
 *
 * Locking Hierarchy:
 * 1) repl_slinks->lock
 * 2) sl->lock
 *
 */

static const char version[] = "v0.022";

#include "dm.h"
#include "dm-repl.h"
#include "dm-registry.h"
#include "dm-repl-log.h"
#include "dm-repl-slink.h"

#include <linux/dm-dirty-log.h>
#include <linux/dm-kcopyd.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#define	DM_MSG_PREFIX	"dm-repl-slink-blockdev"
#define	DAEMON		DM_MSG_PREFIX	"d"
#define	COPY_PAGES	BIO_MAX_PAGES
#define	RESYNC_PAGES	(BIO_MAX_PAGES / 2)
#define	RESYNC_SIZE	(to_sector(PAGE_SIZE) * RESYNC_PAGES)
#define	MIN_IOS		1

/* Jiffies to wait before retrying a device. */
#define	SLINK_TEST_JIFFIES	(15 * HZ)
#define	SLINK_TEST_SIZE		4096

#define _SET_AND_BUG_ON_SL(sl, slink) \
	do { \
		_BUG_ON_PTR(slink); \
		(sl) = slink_check(slink); \
		_BUG_ON_PTR(sl); \
	} while (0);

/* An slink device. */
enum sdev_list_type {
	SDEV_SLINK,	/* To put on slink's device list. */
	SDEV_RESYNC,	/* To put on slink's resynchronization list. */
	SDEV_TEST,	/* To put on so_slink_test()'s test list. */
	NR_SDEV_LISTS,
};
struct test_buffer;
struct sdev {
	struct kref ref;	/* Reference counter. */

	/* Lists to hang off slink, resync and flush lists */
	struct list_head lists[NR_SDEV_LISTS];
	struct dm_target *ti;
	struct slink *sl;	/* Backpointer for callback. */

	struct {
		struct sdev_resync {
			sector_t region; /* Region being resynchronized. */
			sector_t writer_region; /* region being written to. */
			sector_t start;	/* Start of actual resync copy. */
			sector_t end;	/* End of actual resync copy. */
			unsigned len;	/* Length of actual copy. */
			/* Source device pointer for resync callback. */
			struct sdev *from;
		} resync;

		struct {
			unsigned long time;
			struct test_buffer *buffer;
		} test;


		/* kcopyd resynchronization client. */
		struct dm_kcopyd_client *kcopyd_client;

		/* Teardown synchronization. */
		wait_queue_head_t waiters;

		sector_t split_io;

		unsigned long flags;
	} io;

	/* Device properties. */
	struct sdev_dev {
		struct {
			unsigned count;	/* Ctr parameters count. */
			const char *path; /* Device path/major:minor. */
		} params;

		struct dm_dev *dm_dev;
		struct dm_dirty_log *dl;
		unsigned number;
	} dev;
};

/* Macros to access sdev lists. */
#define	SDEV_SLINK_LIST(sl)	(sl->lists + SDEV_SLINK)
#define	SDEV_RESYNC_LIST(sl)	(sl->lists + SDEV_RESYNC)

/* Status flags for device. */
enum dev_flags {
	DEV_ERROR_READ,		/* Read error on device. */
	DEV_ERROR_WRITE,	/* Write error on device. */
	DEV_IO_QUEUED,		/* Request(s) to device queued. */
	DEV_IO_UNPLUG,		/* Unplug device queue. */
	DEV_OPEN,		/* Device got opend during ctr. */
	DEV_RESYNC,		/* Device may resync. */
	DEV_RESYNC_END,		/* Flag device resynchronization end. */
	DEV_RESYNCING,		/* Device has active resync. */
	DEV_SUSPENDED,		/* Device suspended. */
	DEV_TEARDOWN,		/* Device is being deleted. */
};

/* Create slink bitfield (io.flags) access inline definitions. */
DM_BITOPS(DevErrorRead, sdev, DEV_ERROR_READ)
DM_BITOPS(DevErrorWrite, sdev, DEV_ERROR_WRITE)
DM_BITOPS(DevIOQueued, sdev, DEV_IO_QUEUED)
DM_BITOPS(DevIOUnplug, sdev, DEV_IO_UNPLUG)
DM_BITOPS(DevOpen, sdev, DEV_OPEN)
DM_BITOPS(DevResync, sdev, DEV_RESYNC)
DM_BITOPS(DevResyncEnd, sdev, DEV_RESYNC_END)
DM_BITOPS(DevResyncing, sdev, DEV_RESYNCING)
DM_BITOPS(DevSuspended, sdev, DEV_SUSPENDED)
DM_BITOPS(DevTeardown, sdev, DEV_TEARDOWN)

/* Internal site link representation. */
enum slink_list_type { SLINK_DEVS, SLINK_REPLOG, SLINK_RESYNC, NR_SLINK_LISTS };
enum cache_type { COPY_CACHE, TEST_CACHE, NR_CACHES };
struct slink {
	struct kref ref;	/* Reference count. */
	/*
	 * Protect slink lists.
	 *
	 * Has to be spinlock, because the global replog lock
	 * needs to be one to be used from interrupt context
	 * and they are both taken in some places.
	 */
	rwlock_t lock;		/* Protect slink lists. */

	/* Devices on this slink, on replog list and on resync list. */
	struct list_head lists[NR_SLINK_LISTS];

	/* List of all slinks for a replog. */
	struct dm_repl_log_slink_list *repl_slinks;

	unsigned number; /* slink number. */

	struct slink_params {
		unsigned count;
		struct dm_repl_slink_fallbehind fallbehind;
		enum dm_repl_slink_policy_type policy;
	} params;

	struct dm_repl_slink *slink;

	struct slink_io {
		unsigned long flags;
		struct dm_kcopyd_client *kcopyd_client;
		struct dm_io_client *dm_io_client;

		/* Copy context and test buffer mempools. */
		mempool_t *pool[NR_CACHES];

		/* io work. */
		struct workqueue_struct *wq;
		struct delayed_work dws;

		struct sdev *dev_test;
	} io;

	/* Callback for slink recovered. */
	struct dm_repl_slink_notify_ctx recover;
};

/* Macros to access slink lists. */
#define	SLINK_DEVS_LIST(sl)	(sl->lists + SLINK_DEVS)
#define	SLINK_REPLOG_LIST(sl)	(sl->lists + SLINK_REPLOG)
#define	SLINK_RESYNC_LIST(sl)	(sl->lists + SLINK_RESYNC)

/* Status flags for slink. */
enum slink_flags {
	SLINK_ERROR_READ,	/* Read error on site link. */
	SLINK_ERROR_WRITE,	/* Write error on site link. */
	SLINK_IMMEDIATE_WORK,	/* Flag immediate worker run. */
	SLINK_RESYNC_PROCESSING,/* Resync is being processed on slink. */
	SLINK_TEST_ACTIVE,	/* Device test active on slink. */
	SLINK_WRITER,		/* Slink is being written to. */
};

/* Create slink bitfield (io.flags) access inline definitions. */
DM_BITOPS(SlinkErrorRead, slink, SLINK_ERROR_READ)
DM_BITOPS(SlinkErrorWrite, slink, SLINK_ERROR_WRITE)
DM_BITOPS(SlinkImmediateWork, slink, SLINK_IMMEDIATE_WORK)
DM_BITOPS(SlinkResyncProcessing, slink, SLINK_RESYNC_PROCESSING)
DM_BITOPS(SlinkTestActive, slink, SLINK_TEST_ACTIVE)
DM_BITOPS(SlinkWriter, slink, SLINK_WRITER)

/* Copy context to carry from blockdev_copy() to copy_endio(). */
struct copy_context {
	struct sdev *dev_to;	/* Device to copy to. */

	/* Callback for data in RAM (noop for 'blockdev' type). */
	struct dm_repl_slink_notify_ctx ram;

	/* Callback for data on disk. */
	struct dm_repl_slink_notify_ctx disk;
};

/* Allocate/free blockdev copy context. */
static inline struct copy_context *alloc_copy_context(struct slink *sl)
{
	return mempool_alloc(sl->io.pool[COPY_CACHE], GFP_KERNEL);
}

static inline void free_copy_context(struct copy_context *cc, struct slink *sl)
{
	mempool_free(cc, sl->io.pool[COPY_CACHE]);
}

/* Allocate/free blockdev test io buffer. */
static inline struct test_buffer *alloc_test_buffer(struct slink *sl)
{
	return mempool_alloc(sl->io.pool[TEST_CACHE], GFP_KERNEL);
}

static inline void free_test_buffer(struct test_buffer *tb, struct slink *sl)
{
	mempool_free(tb, sl->io.pool[TEST_CACHE]);
}

/* Destcriptor type <-> name mapping. */
static const struct dm_str_descr policies[] = {
	{ DM_REPL_SLINK_ASYNC, "asynchronous" },
	{ DM_REPL_SLINK_SYNC, "synchronous" },
	{ DM_REPL_SLINK_STALL, "stall" },
};

/* Get slink policy flags. */
static int _slink_policy_type(char *name)
{
	int r = dm_descr_type(policies, ARRAY_SIZE(policies), name);

	if (r < 0)
		DMERR("Invalid site link policy %s", name);

	return r;
}

/* Get slink policy name. */
static const char *
_slink_policy_name(const int type)
{
	return dm_descr_name(policies, ARRAY_SIZE(policies), type);
}

#define	SEPARATOR	'+'
static int
get_slink_policy(char *arg)
{
	int policy = 0, r;
	char *sep;

	DMDEBUG_LIMIT("%s arg=%s", __func__, arg);

	/*
	 * Check substrings of the compound policy
	 * string separated by SEPARATOR.
	 */
	do {
		sep = strchr(arg, SEPARATOR);
		if (sep)
			*sep = 0;
		else
			sep = arg;

		r = _slink_policy_type(arg);
		if (sep != arg) {
			arg = sep + 1;
			*sep = SEPARATOR;
		}

		if (r < 0)
			return r;
		else
			set_bit(r, (unsigned long *) &policy);
	} while (sep != arg);

	smp_mb();
	return policy;
}

/* String print policies. */
static char *
snprint_policies(enum dm_repl_slink_policy_type policies,
		 char *result, size_t maxlen)
{
	int bits = sizeof(policies) * 8, i;
	size_t sz = 0;

	*result = 0;
	for (i = 0; i < bits; i++) {
		if (test_bit(i, (unsigned long *) &policies)) {
			const char *name = _slink_policy_name(i);

			if (name) {
				if (*result)
					DMEMIT("%c", SEPARATOR);

				DMEMIT("%s", name);
			}
		}
	}

	return result;
}

/* Fallbehind type <-> name mappings. */
static const struct dm_str_descr fb_types[] = {
	{ DM_REPL_SLINK_FB_IOS, "ios" },
	{ DM_REPL_SLINK_FB_SIZE, "size" },
	{ DM_REPL_SLINK_FB_TIMEOUT, "timeout" },
};

/* Return name of fallbehind parameter by type. */
static const char *
fb_name(enum dm_repl_slink_fallbehind_type type)
{
	return dm_descr_name(fb_types, ARRAY_SIZE(fb_types), type);
}

/* String print fallbehind. */
static char *
snprint_fallbehind(struct dm_repl_slink_fallbehind *fallbehind,
		   char *result, size_t maxlen)
{
	size_t sz = 0;
	sector_t value = fallbehind->value;

	sector_div(value, fallbehind->multiplier);
	DMEMIT("%s %llu%c", fb_name(fallbehind->type),
	       (unsigned long long) value, fallbehind->unit);
	return result;
}

/*
 * Check and get fallbehind value and type.
 * Pay attention to unit qualifiers.
 */
static int
_get_slink_fallbehind(int argc, char **argv,
		      enum dm_repl_slink_fallbehind_type fb_type,
		      struct dm_repl_slink_fallbehind *fb)
{
	int arg = 0, r;
	unsigned multi = 1;
	long long tmp;
	char *unit;
	const char *name = fb_name(fb_type);

	fb->unit = 0;

	/* Old syntax e.g. "ios=1000". */
	r = sscanf(argv[arg] + strlen(name), "=%lld", &tmp) != 1 || tmp < 0;
	if (r) {
		if (argc < 2)
			goto bad_value;

		/* New syntax e.g. "ios 1000". */
		r = sscanf(argv[++arg], "%lld", &tmp) != 1 || tmp < 0;
	}

	unit = argv[arg] + strlen(argv[arg]) - 1;
	unit = (*unit < '0' || *unit > '9') ? unit : NULL;

	if (r)
		goto bad_value;

	if (unit) {
		const struct units {
			const char *chars;
			const sector_t multiplier[];
		} *u = NULL;
		static const struct units size = {
			"sSkKmMgGtTpPeE",
			#define TWO	(sector_t) 2
		/*  sectors, KB,MB,      GB,      TB,      PB,      EB */
			{ 1, 2, TWO<<10, TWO<<20, TWO<<30, TWO<<40, TWO<<50 },
			#undef	TWO
		}, timeout = {
			"tTsSmMhHdD",
			/*ms, sec, minute,  hour,       day */
			{ 1, 1000, 60*1000, 60*60*1000, 24*60*60*1000 },
		};
		const char *c;

		switch (fb_type) {
		case DM_REPL_SLINK_FB_SIZE:
			u = &size;
			goto retrieve;
		case DM_REPL_SLINK_FB_TIMEOUT:
			u = &timeout;
retrieve:
			/* Skip to unit identifier character. */
			for (c = u->chars, multi = 0;
			     *c && *c != *unit;
			     c++, multi++)
				;

			if (*c) {
				fb->unit = *c;
				multi = u->multiplier[(multi + 2) / 2];
			} else
				goto bad_unit;
		case DM_REPL_SLINK_FB_IOS:
			break;

		default:
			BUG();
		}
	}

	fb->type = fb_type;
	fb->multiplier = multi;
	fb->value = tmp * multi;
	return 0;

bad_value:
	DMERR("invalid fallbehind %s value", argv[0]);
	return -EINVAL;

bad_unit:
	DMERR("invalid slink fallbehind unit");
	return -EINVAL;
}

static int
get_slink_fallbehind(int argc, char **argv, struct dm_repl_slink_fallbehind *fb)
{
	const struct dm_str_descr *f = ARRAY_END(fb_types);

	while (f-- > fb_types) {
		/* Check for fallbehind argument. */
		if (!strnicmp(STR_LEN(fb_name(f->type), argv[0])))
			return _get_slink_fallbehind(argc, argv, f->type, fb);
	}

	DMERR("invalid fallbehind type %s", argv[0]);
	return -EINVAL;
}

/* Return region on device fro given sector. */
static sector_t
sector_to_region(struct sdev *dev, sector_t sector)
{
	sector_div(sector, dev->ti->split_io);
	return sector;
}

/* Check dm_repl_slink and slink ok. */
static struct slink *
slink_check(struct dm_repl_slink *slink)
{
	struct slink *sl;

	if (unlikely(!slink))
		return ERR_PTR(-EINVAL);

	if (unlikely(IS_ERR(slink)))
		return (struct slink *) slink;

	sl = slink->context;
	return sl ? sl : ERR_PTR(-EINVAL);
}

struct cache_defs {
	enum cache_type type;
	const int min;
	struct kmem_cache *cache;
	const char *name;
	const size_t size;
};

/* Slabs for the copy context structures and for device test I/O buffers. */
static struct cache_defs cache_defs[] = {
	{ COPY_CACHE, MIN_IOS, NULL,
	  "dm_repl_slink_copy", sizeof(struct copy_context) },
	{ TEST_CACHE, MIN_IOS, NULL,
	  "dm_repl_slink_test", SLINK_TEST_SIZE },
};

/*
 * Release resources when last reference dropped.
 *
 * Gets called with lock hold to atomically delete slink from list.
 */
static void
slink_release(struct kref *ref)
{
	struct slink *sl = container_of(ref, struct slink, ref);

	DMDEBUG("%s slink=%d released", __func__, sl->number);
	kfree(sl);
}

/* Take out reference on slink. */
static struct slink *
slink_get(struct slink *sl)
{
	kref_get(&sl->ref);
	return sl;
}

/* Drop reference on slink and destroy it on last release. */
static int
slink_put(struct slink *sl)
{
	return kref_put(&sl->ref, slink_release);
}

/* Find slink on global slink list by number. */
static struct slink *
slink_get_by_number(struct dm_repl_log_slink_list *repl_slinks,
		    unsigned slink_number)
{
	struct slink *sl;

	BUG_ON(!repl_slinks);

	list_for_each_entry(sl, &repl_slinks->list, lists[SLINK_REPLOG]) {
		if (slink_number == sl->number)
			return slink_get(sl);
	}

	return ERR_PTR(-ENOENT);
}

/* Destroy slink object. */
static void
slink_destroy(struct slink *sl)
{
	struct slink_io *io;
	struct cache_defs *cd;

	_BUG_ON_PTR(sl);
	_BUG_ON_PTR(sl->repl_slinks);
	io = &sl->io;

	write_lock(&sl->repl_slinks->lock);
	if (!list_empty(SLINK_REPLOG_LIST(sl)))
		list_del(SLINK_REPLOG_LIST(sl));
	write_unlock(&sl->repl_slinks->lock);

	/* Destroy workqueue before freeing resources. */
	if (io->wq)
		destroy_workqueue(io->wq);

	if (io->kcopyd_client)
		dm_kcopyd_client_destroy(io->kcopyd_client);

	if (io->dm_io_client)
		dm_io_client_destroy(io->dm_io_client);

	cd = ARRAY_END(cache_defs);
	while (cd-- > cache_defs) {
		if (io->pool[cd->type]) {
			mempool_destroy(io->pool[cd->type]);
			io->pool[cd->type] = NULL;
		}
	}
}

/*
 * Get slink from global slink list by number or create
 * new one and put it on list; take out reference.
 */
static void do_slink(struct work_struct *ws);
static struct slink *
slink_create(struct dm_repl_slink *slink,
	     struct dm_repl_log_slink_list *repl_slinks,
	     struct slink_params *params, unsigned slink_number)
{
	int i, r;
	struct slink *sl;

	DMDEBUG_LIMIT("%s %u", __func__, slink_number);

	/* Make sure, slink0 exists when creating slink > 0. */
	if (slink_number) {
		struct slink *sl0;

		read_lock(&repl_slinks->lock);
		sl0 = slink_get_by_number(repl_slinks, 0);
		read_unlock(&repl_slinks->lock);

		if (IS_ERR(sl0)) {
			DMERR("Can't create slink=%u w/o slink0.",
			      slink_number);
			return ERR_PTR(-EPERM);
		}

		BUG_ON(slink_put(sl0));
	}

	read_lock(&repl_slinks->lock);
	sl = slink_get_by_number(repl_slinks, slink_number);
	read_unlock(&repl_slinks->lock);

	if (IS_ERR(sl)) {
		struct slink *sl_tmp;
		struct slink_io *io;
		struct cache_defs *cd;

		if (!params)
			return sl;

		/* Preallocate internal slink struct. */
		sl = kzalloc(sizeof(*sl), GFP_KERNEL);
		if (unlikely(!sl))
			return ERR_PTR(-ENOMEM);

		rwlock_init(&sl->lock);
		kref_init(&sl->ref);

#ifdef CONFIG_LOCKDEP
		{
			static struct lock_class_key slink_number_lock;

			lockdep_set_class_and_subclass(&sl->lock,
						       &slink_number_lock,
						       slink_number);
		}
#endif

		i = ARRAY_SIZE(sl->lists);
		while (i--)
			INIT_LIST_HEAD(sl->lists + i);

		/* Copy (parsed) fallbehind arguments accross. */
		io = &sl->io;
		sl->params = *params;
		sl->number = slink_number;
		sl->repl_slinks = repl_slinks;
		sl->slink = slink;
		slink->context = sl;

		/* Create kcopyd client for data copies to slinks. */
		r = dm_kcopyd_client_create(COPY_PAGES, &io->kcopyd_client);
		if (unlikely(r < 0)) {
			io->kcopyd_client = NULL;
			goto bad;
		}

		/* Create dm-io client context for test I/Os on slinks. */
		io->dm_io_client = dm_io_client_create(1);
		if (unlikely(IS_ERR(io->dm_io_client))) {
			r = PTR_ERR(io->dm_io_client);
			io->dm_io_client = NULL;
			goto bad;
		}

		r = -ENOMEM;

		/* Create slab mempools for copy contexts and test buffers. */
		cd = ARRAY_END(cache_defs);
		while (cd-- > cache_defs) {
			io->pool[cd->type] =
				mempool_create_slab_pool(cd->min, cd->cache);
			if (unlikely(!io->pool[cd->type])) {
				DMERR("Failed to create mempool %p",
				       io->pool[cd->type]);
				goto bad;
			}
		}

		io->wq = create_singlethread_workqueue(DAEMON);
		if (likely(io->wq))
			INIT_DELAYED_WORK(&sl->io.dws, do_slink);
		else
			goto bad;

		/* Add to replog list. */
		write_lock(&repl_slinks->lock);
		sl_tmp = slink_get_by_number(repl_slinks, slink_number);
		if (likely(IS_ERR(sl_tmp))) {
			/* We won the race -> add to list. */
			list_add_tail(SLINK_REPLOG_LIST(sl),
				      &repl_slinks->list);
			write_unlock(&repl_slinks->lock);
		} else {
			/* We lost the race, take the winner. */
			write_unlock(&repl_slinks->lock);
			/* Will release sl. */
			slink_destroy(sl);
			sl = sl_tmp;
		}

		return sl;
	}

	slink_put(sl);
	return ERR_PTR(-EEXIST);

bad:
	slink_destroy(sl);
	return ERR_PTR(r);
}

/* Return slink count. */
static unsigned
slink_count(struct slink *sl)
{
	unsigned count = 0;
	struct slink *sl_cur;

	_BUG_ON_PTR(sl);

	list_for_each_entry(sl_cur, &sl->repl_slinks->list, lists[SLINK_REPLOG])
		count++;

	return count;
}

/* Return number of regions for device. */
static inline sector_t
region_count(struct sdev *dev)
{
	return dm_sector_div_up(dev->ti->len, dev->ti->split_io);
}


/*
 * Site link worker.
 */
/* Queue (optionally delayed) io work. */
static void
wake_do_slink_delayed(struct slink *sl, unsigned long delay)
{
	struct delayed_work *dws = &sl->io.dws;

	if (delay) {
		/* Avoid delaying if immediate worker run already requested. */
		if (SlinkImmediateWork(sl))
			return;
	} else
		SetSlinkImmediateWork(sl);

	if (delayed_work_pending(dws))
		cancel_delayed_work(dws);

	queue_delayed_work(sl->io.wq, dws, delay);
}

/* Queue io work immediately. */
static void
wake_do_slink(void *context)
{
	wake_do_slink_delayed(context, 0);
}

/* Set/get device test timeouts. */
/* FIXME: algorithm to have flexible test timing? */
static inline void
set_dev_test_time(struct sdev *dev)
{
	unsigned long time = jiffies + SLINK_TEST_JIFFIES;

	/* Check jiffies wrap. */
	if (unlikely(time < jiffies))
		time = SLINK_TEST_JIFFIES;

	dev->io.test.time = time;
}

static inline unsigned long
get_dev_test_time(struct sdev *dev)
{
	return dev->io.test.time;
}

/*
 * Get device object reference count.
 *
 * A reference count > 1 indicates IO in flight on the device.
 *
 */
static int dev_io(struct sdev *dev)
{
	return atomic_read(&dev->ref.refcount) > 1;
}

/* Take device object reference out. */
static struct sdev *dev_get(struct sdev *dev)
{
	kref_get(&dev->ref);
	return dev;
}

/* Release sdev object. */
static void
dev_release(struct kref *ref)
{
	struct sdev *dev = container_of(ref, struct sdev, ref);
	struct slink *sl = dev->sl;

	_BUG_ON_PTR(sl);

	kfree(dev->dev.params.path);
	DMDEBUG("%s dev=%d slink=%d released", __func__,
		dev->dev.number, sl->number);
	kfree(dev);
}

/* Drop device object reference. */
static int dev_put(struct sdev *dev)
{
	int r = kref_put(&dev->ref, dev_release);

	if (!r) {
		if (!dev_io(dev))
			wake_up(&dev->io.waiters);
	}

	return r;
}

/* Find device by device number. */
static struct sdev *dev_get_by_number(struct slink *sl, int dev_number)
{
	struct sdev *dev;

	_BUG_ON_PTR(sl);

	list_for_each_entry(dev, SLINK_DEVS_LIST(sl), lists[SDEV_SLINK]) {
		if (dev_number == dev->dev.number)
			return dev_get(dev);
	}

	return ERR_PTR(-ENODEV);
}

/* Find device by bdev. */
static struct sdev *dev_get_by_bdev(struct slink *sl,
				   struct block_device *bdev)
{
	struct sdev *dev;

	_BUG_ON_PTR(sl);

	list_for_each_entry(dev, SLINK_DEVS_LIST(sl), lists[SDEV_SLINK]) {
		struct mapped_device *md = dm_table_get_md(dev->ti->table);
		struct gendisk *gd = dm_disk(md);

		if (bdev->bd_disk == gd)
			return dev_get(dev);
	}

	return ERR_PTR(-ENODEV);
}

/* Find device by path. */
static struct sdev *dev_get_by_path(struct slink *sl,
				     const char *path)
{
	struct sdev *dev;

	_BUG_ON_PTR(sl);

	list_for_each_entry(dev, SLINK_DEVS_LIST(sl), lists[SDEV_SLINK]) {
		if (!strcmp(dev->dev.params.path, path))
			return dev_get(dev);
	}

	return ERR_PTR(-ENODEV);
}

static struct sdev *
dev_get_on_any_slink(struct slink *sl, struct sdev *dev)
{
	struct slink *sl_cur = NULL;
	struct sdev *dev_r;

	list_for_each_entry(sl_cur, &sl->repl_slinks->list,
			    lists[SLINK_REPLOG]) {
		/* Check by path if device already present. */
		if (sl_cur != sl)
			read_lock(&sl_cur->lock);

		/* Check by bdev/number depending on device open or not. */
		dev_r = DevOpen(dev) ?
			dev_get_by_bdev(sl_cur, dev->dev.dm_dev->bdev) :
			dev_get_by_path(sl_cur, dev->dev.params.path);

		if (sl_cur != sl)
			read_unlock(&sl_cur->lock);

		if (unlikely(!IS_ERR(dev_r)))
			return dev_r;
	}

	return ERR_PTR(-ENOENT);
}

/* Callback for site link accessibility tests. */
static void
dev_test_endio(unsigned long error, void *context)
{
	struct sdev *dev = context;
	struct slink *sl;

	_BUG_ON_PTR(dev);
	sl = dev->sl;
	_BUG_ON_PTR(sl);

	if (error)
		set_dev_test_time(dev);
	else {
		ClearDevErrorRead(dev);
		ClearDevErrorWrite(dev);
	}

	/* Release test io buffer. */
	free_test_buffer(dev->io.test.buffer, sl);

	ClearSlinkTestActive(sl);
	BUG_ON(dev_put(dev)); /* Release reference. */
	wake_do_slink(sl);
}

/* Submit a read to sector 0 of a remote device to test access to it. */
static void
dev_test(struct slink *sl, struct sdev *dev)
{
	struct dm_io_region region = {
		.bdev = dev->dev.dm_dev->bdev,
		.sector = 0,
		.count = 1,
	};
	struct dm_io_request req = {
		.bi_rw = READ,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = alloc_test_buffer(sl),
		.notify.fn = dev_test_endio,
		.notify.context = dev,
		.client = sl->io.dm_io_client,
	};

	/* FIXME: flush_workqueue should care for race. */
	sl->io.dev_test = dev;
	dev->io.test.buffer = req.mem.ptr.addr;
	set_dev_test_time(dev);
	BUG_ON(dm_io(&req, 1, &region, NULL));
}


/*
 * Callback replog handler in case of a region
 * resynchronized or a device recovered.
 */
static inline void
recover_callback(struct slink *sl, int read_err, int write_err)
{
	struct dm_repl_slink_notify_ctx recover;

	_BUG_ON_PTR(sl);
	read_lock(&sl->lock);
	recover = sl->recover;
	read_unlock(&sl->lock);

	/* Optionally call back site link recovery. */
	if (likely(recover.fn))
		recover.fn(read_err, write_err, recover.context);
}

/* Try to open device. */
static int
try_dev_open(struct sdev *dev)
{
	int r = 0;

	if (!DevOpen(dev)) {
		/* Try getting device with limit checks. */
		r = dm_get_device(dev->ti, dev->dev.params.path,
				  dm_table_get_mode(dev->ti->table),
				  &dev->dev.dm_dev);
		if (r) {
			set_dev_test_time(dev);
			SetDevErrorRead(dev);
		} else {
			SetDevOpen(dev);
			ClearDevErrorRead(dev);
		}
	}

	return r;
}

/* Check devices for error condition and initiate test io on those. */
static void
do_slink_test(struct slink *sl)
{
	int r;
	unsigned error_count = 0;
	/* FIXME: jiffies may differ on MP ? */
	unsigned long delay = ~0, j = jiffies;
	struct sdev *dev, *dev_t = NULL;

	read_lock(&sl->lock);
	list_for_each_entry(dev, SLINK_DEVS_LIST(sl), lists[SDEV_SLINK]) {
		if ((DevErrorRead(dev) || DevErrorWrite(dev))) {
			error_count++;

			if (!DevTeardown(dev) && !DevSuspended(dev)) {
				unsigned long t = get_dev_test_time(dev);

				/* Check we didn't reach the test time jet. */
				if (time_before(j, t)) {
					unsigned long d = t - j;

					if (d < delay)
						delay = d;
				} else {
					dev_t = dev;
					slink_get(sl);
					break;
				}
			}
		}
	}

	read_unlock(&sl->lock);

	if (!error_count) {
		/*
		 * If all are ok -> reset site link error state.
		 *
		 * We can't allow submission of writes
		 * before all devices are accessible.
		 */
		/*
		 * FIXME: I actually test the remote device only so
		 * I shouldn't update state on the local reader side!
		 *
		 * Question is, where to update this or leave it
		 * to the caller to fail fataly when it can't read data
		 * of off the log or the replicated device any more.
		 */
		if (TestClearSlinkErrorRead(sl))
			error_count++;

		if (TestClearSlinkErrorWrite(sl))
			error_count++;

		if (error_count)
			recover_callback(sl, 0, 0);

		return;
	}

	j = jiffies;

	/* Check for jiffies overrun. */
	if (unlikely(j < SLINK_TEST_JIFFIES))
		set_dev_test_time(dev);

	if (!TestSetSlinkTestActive(sl)) {
		dev_get(dev); /* Take out device reference. */

		/* Check device is open or open it. */
		r = try_dev_open(dev_t);
		if (r) {
			ClearSlinkTestActive(sl);
			BUG_ON(dev_put(dev_t));
		} else
			/* If open, do test. */
			dev_test(sl, dev_t);
	}

	if (!SlinkTestActive(sl) && delay < ~0)
		wake_do_slink_delayed(sl, delay);

	slink_put(sl);
}

/* Set device error state and throw a dm event. */
static void
resync_error_dev(struct sdev *dev)
{
	SetDevErrorRead(dev);
	dm_table_event(dev->ti->table);
}

/* Resync copy callback. */
static void
resync_endio(int read_err, unsigned long write_err, void *context)
{
	struct sdev *dev_from, *dev_to = context;
	struct sdev_resync *resync;

	_BUG_ON_PTR(dev_to);
	resync = &dev_to->io.resync;
	dev_from = resync->from;
	_BUG_ON_PTR(dev_from);

	if (unlikely(read_err))
		resync_error_dev(dev_from);

	if (unlikely(write_err))
		resync_error_dev(dev_to);

	resync->start += resync->len;
	ClearDevResyncing(dev_to);
	dev_put(dev_from);
	dev_put(dev_to);
	wake_do_slink(dev_to->sl);
}

/* Unplug a block devices queue. */
static inline void
dev_unplug(struct block_device *bdev)
{
	blk_unplug(bdev_get_queue(bdev));
}

/* Resync copy function. */
static void
resync_copy(struct sdev *dev_to, struct sdev *dev_from,
	    struct sdev_resync *resync)
{
	sector_t max_len = dev_from->ti->len;
	struct dm_io_region src = {
		.bdev = dev_from->dev.dm_dev->bdev,
		.sector = resync->start,
	}, dst = {
		.bdev = dev_to->dev.dm_dev->bdev,
		.sector = resync->start,
	};

	src.count = dst.count = unlikely(src.sector + resync->len > max_len) ?
				max_len - src.sector : resync->len;
	BUG_ON(!src.count);
	BUG_ON(src.sector + src.count > max_len);
	dev_to->io.resync.from = dev_from;
	SetDevResyncing(dev_to);
	BUG_ON(dm_kcopyd_copy(dev_to->io.kcopyd_client, &src, 1, &dst, 0,
			      resync_endio, dev_to));
	dev_unplug(src.bdev);
	dev_unplug(dst.bdev);
}

/* Return length of segment to resynchronoze. */
static inline sector_t
resync_len(struct sdev *dev)
{
	sector_t r = RESYNC_SIZE, region_size = dev->ti->split_io;
	struct sdev_resync *resync = &dev->io.resync;

	if (unlikely(r > region_size))
		r = region_size;

	if (unlikely(resync->start + r > resync->end))
		r = resync->end - resync->start;

	return r;
}

/* Initiate recovery on all site links registered for. */
static void
do_slink_resync(struct slink *sl)
{
	struct slink *sl0;
	struct sdev *dev_from, *dev_n, *dev_to;
	struct list_head resync_list;

	_BUG_ON_PTR(sl);

	if (!sl->number)
		return;

	/*
	 * Protect the global site link list from
	 * changes while getting slink 0.
	 */
	read_lock(&sl->repl_slinks->lock);
	sl0 = slink_get_by_number(sl->repl_slinks, 0);
	read_unlock(&sl->repl_slinks->lock);

	_BUG_ON_PTR(sl0);

	/*
	 * Quickly take out resync list for local unlocked processing
	 * and take references per device for suspend/delete race prevention
	 */
	INIT_LIST_HEAD(&resync_list);
	read_lock(&sl0->lock);
	write_lock(&sl->lock);
	SetSlinkResyncProcessing(sl);

	list_splice(SLINK_RESYNC_LIST(sl), &resync_list);
	INIT_LIST_HEAD(SLINK_RESYNC_LIST(sl));

	list_for_each_entry(dev_to, &resync_list, lists[SDEV_RESYNC]) {
		dev_from = dev_get_by_number(sl0, dev_to->dev.number);
		_BUG_ON_PTR(dev_from);
		dev_get(dev_to);
		/* Memorize device to copy from. */
		dev_to->io.resync.from = dev_from;
	}

	write_unlock(&sl->lock);
	read_unlock(&sl0->lock);

	/*
	 * Process all devvices needing
	 * resynchronization on the private list.
	 *
	 * "dev_to" is device to copy to.
	 */
	list_for_each_entry(dev_to, &resync_list, lists[SDEV_RESYNC]) {
		unsigned region_size;
		struct sdev_resync *resync;
		struct dm_dirty_log *dl = dev_to->dev.dl;

		/* Can't resync w/o dirty log. */
		_BUG_ON_PTR(dl);

		/* Device closed/copy active/suspended/being torn down/error. */
		if (!DevOpen(dev_to) ||
		    DevResyncing(dev_to) ||
		    DevSuspended(dev_to) ||
		    DevTeardown(dev_to) ||
		    DevErrorWrite(dev_to))
			continue;

		/* Device to copy from. */
		resync = &dev_to->io.resync;
		dev_from = resync->from;

		/* slink0 device suspended/being torn down or I/O error. */
		if (DevSuspended(dev_from) ||
		    DevTeardown(dev_from) ||
		    DevErrorRead(dev_from))
			continue;

		/* No copy active if resync->end == 0. */
		if (!resync->end) {
			int r;
			sector_t region;

			/* Ask dirty region log for another region to sync. */
			r = dl->type->get_resync_work(dl, &region);
			if (r) {
				write_lock(&sl0->lock);

				/* Region is being written to -> postpone. */
				if (unlikely(SlinkWriter(sl0) &&
					     resync->writer_region == region)) {
					write_unlock(&sl0->lock);
					continue;
				}

				region_size = dev_to->ti->split_io;
				resync->region = region;
				resync->start = region * region_size;
				resync->end = resync->start + region_size;
				if (unlikely(resync->end > dev_to->ti->len))
					resync->end = dev_to->ti->len;

				write_unlock(&sl0->lock);
			} else {
				/* No more regions to recover. */
				SetDevResyncEnd(dev_to);
				continue;
			}
		}

		/* More to copy for this region. */
		if (resync->start < resync->end) {
			resync->len = resync_len(dev_to);
			BUG_ON(!resync->len);

			/*
			 * Take out references in order
			 * to not race with deletion.
			 *
			 * resync_endio will release them.
			 */
			dev_get(dev_from);
			dev_get(dev_to);
			resync_copy(dev_to, dev_from, resync);

		/*
		 * Done with copying this region:
		 * mark in sync and flush dirty log.
		 */
		} else {
			dl->type->set_region_sync(dl, resync->region, 1);
			dl->type->flush(dl);

			/* Optionally call back site link recovery. */
			recover_callback(sl, 0, 0);
			resync->end = 0;

			/* Another run to check for more resync work. */
			wake_do_slink(sl);
		}
	}

	/* Put race device references. */
	read_lock(&sl0->lock);
	write_lock(&sl->lock);
	list_for_each_entry_safe(dev_to, dev_n, &resync_list,
				 lists[SDEV_RESYNC]) {
		if (TestClearDevResyncEnd(dev_to))
			list_del_init(SDEV_RESYNC_LIST(dev_to));

		dev_from = dev_get_by_number(sl0, dev_to->dev.number);
		/* 1 put just taken, 1 put for the one initially taken. */
		_BUG_ON_PTR(dev_from);
		BUG_ON(dev_put(dev_from));
		BUG_ON(dev_put(dev_from));
		BUG_ON(dev_put(dev_to));
	}

	list_splice(&resync_list, SLINK_RESYNC_LIST(sl));
	ClearSlinkResyncProcessing(sl);

	write_unlock(&sl->lock);
	read_unlock(&sl0->lock);

	BUG_ON(slink_put(sl0));
}

/* Main worker thread function. */
static void
do_slink(struct work_struct *ws)
{
	int must_resync;
	struct slink *sl = container_of(ws, struct slink, io.dws.work);

	if (!SlinkTestActive(sl))
		do_slink_test(sl);

	write_lock(&sl->lock);
	must_resync = !list_empty(SLINK_RESYNC_LIST(sl));
	write_unlock(&sl->lock);

	if (must_resync)
		do_slink_resync(sl);

	ClearSlinkImmediateWork(sl);
}

/*
 * End site link worker.
 */

/* Allocate/init an sdev structure and dm_get_device(). */
static struct sdev *
dev_create(struct slink *sl, struct dm_target *ti,
	   char *path, unsigned dev_number)
{
	int i, r;
	struct sdev *dev;

	_BUG_ON_PTR(sl);
	_BUG_ON_PTR(ti);
	_BUG_ON_PTR(path);

	/* Preallocate site link device structure. */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (unlikely(!dev))
		goto bad_dev_alloc;

	dev->ti = ti;
	dev->dev.number = dev_number;
	init_waitqueue_head(&dev->io.waiters);
	kref_init(&dev->ref);

	i = ARRAY_SIZE(dev->lists);
	while (i--)
		INIT_LIST_HEAD(dev->lists + i);

	dev->dev.params.path = kstrdup(path, GFP_KERNEL);
	if (unlikely(!dev->dev.params.path))
		goto bad_dev_path_alloc;

	/* FIXME: closed device handling 29.09.2009
	 *
	 * Allow inaccessible devices to be created, hence
	 * opening them during transport failure discovery.
	 */
	ClearDevOpen(dev);
	try_dev_open(dev);

	/*
	 * Create kcopyd client for resynchronization copies to slinks.
	 * Only needed for remote devices and hence slinks > 0.
	 */
	if (sl->number) {
		r = dm_kcopyd_client_create(RESYNC_PAGES,
					    &dev->io.kcopyd_client);
		if (unlikely(r < 0))
			goto bad_kcopyd_client;
	}

	dev->sl = sl;
	SetDevSuspended(dev);
	return dev;

bad_dev_alloc:
	DMERR("site link device allocation failed");
	return ERR_PTR(-ENOMEM);

bad_dev_path_alloc:
	DMERR("site link device path allocation failed");
	r = -ENOMEM;
	goto bad;

bad_kcopyd_client:
	DMERR("site link device allocation failed");
bad:
	dev_release(&dev->ref);
	return ERR_PTR(r);
}

/* Add an sdev to an slink. */
static int
dev_add(struct slink *sl, struct sdev *dev)
{
	int r;
	struct slink *sl0;
	struct sdev *dev_tmp;

	_BUG_ON_PTR(sl);
	_BUG_ON_PTR(dev);

	/* Check by number if device got already added to this site link. */
	dev_tmp = dev_get_by_number(sl, dev->dev.number);
	if (unlikely(!IS_ERR(dev_tmp)))
		goto bad_device;

	/* Check by bdev/path if device got already added to any site link. */
	dev_tmp = dev_get_on_any_slink(sl, dev);
	if (unlikely(!IS_ERR(dev_tmp)))
		goto bad_device;

	/* Sibling device on local slink 0 registered yet ? */
	if (sl->number) {
		sl0 = slink_get_by_number(sl->repl_slinks, 0);
		if (unlikely(IS_ERR(sl0)))
			goto bad_slink0;

		read_lock(&sl0->lock);
		dev_tmp = dev_get_by_number(sl0, dev->dev.number);
		read_unlock(&sl0->lock);

		BUG_ON(slink_put(sl0));

		if (unlikely(IS_ERR(dev_tmp)))
			goto bad_sibling;

		BUG_ON(dev_put(dev_tmp));
	}

	/* Add to slink's list of devices. */
	list_add_tail(SDEV_SLINK_LIST(dev), SLINK_DEVS_LIST(sl));

	/* All ok, add to list of remote devices to resync. */
	if (sl->number) {
		SetDevResync(dev);
		list_add_tail(SDEV_RESYNC_LIST(dev), SLINK_RESYNC_LIST(sl));
	}

	return 0;

bad_device:
	DMERR("device already exists");
	BUG_ON(dev_put(dev_tmp));
	return -EBUSY;

bad_slink0:
	DMERR("SLINK0 doesn't exit!");
	r = PTR_ERR(sl0);
	return r;

bad_sibling:
	DMERR("Sibling device=%d on SLINK0 doesn't exist!", dev->dev.number);
	r = PTR_ERR(dev_tmp);
	return r;
}

/*
 * Set up dirty log for new device.
 *
 * For local devices, no dirty log is allowed.
 * For remote devices, a dirty log is mandatory.
 *
 * dirtylog_type = "nolog"/"core"/"disk",
 * #dirtylog_params = 0-3 (1-2 for core dirty log type, 3 for
 * 			   disk dirty log only)
 * dirtylog_params = [dirty_log_path] region_size [[no]sync])
 */
static int
dirty_log_create(struct slink *sl, struct sdev *dev, unsigned argc, char **argv)
{
	struct dm_dirty_log *dl;

	SHOW_ARGV;

	_BUG_ON_PTR(sl);
	_BUG_ON_PTR(dev);

	if (unlikely(argc < 2))
		goto bad_params;

	/* Check for no dirty log with local devices. */
	if (!strcmp(argv[0], "nolog") ||
	    !strcmp(argv[0], "-")) {
		if (argc != 2 ||
		    strcmp(argv[1], "0"))
			goto bad_params;

		dev->dev.dl = NULL;
		dev->io.split_io = DM_REPL_MIN_SPLIT_IO;

		/* Mandatory dirty logs on SLINK > 0. */
		if (sl->number)
			goto bad_need_dl;

		return 0;
	}

	/* No dirty logs on SLINK0. */
	if (unlikely(!sl->number))
		goto bad_site_link;

	dl = dm_dirty_log_create(argv[0], dev->ti, NULL, argc - 2, argv + 2);
	if (unlikely(!dl))
		goto bad_dirty_log;

	dev->dev.dl = dl;
	dev->io.split_io = dl->type->get_region_size(dl);
	if (dev->io.split_io < BIO_MAX_SECTORS)
		DM_EINVAL("Invalid dirty log region size");

	return 0;

bad_params:
	DMERR("invalid dirty log parameter count");
	return -EINVAL;

bad_need_dl:
	DMERR("dirty log mandatory on SLINKs > 0");
	return -EINVAL;

bad_site_link:
	DMERR("no dirty log allowed on SLINK0");
	return -EINVAL;

bad_dirty_log:
	DMERR("failed to create dirty log");
	return -ENXIO;
}

/*
 * Check and adjust split_io on all replicated devices.
 *
 * Called with write repl_slinks->lock and write sl->lock hold.
 *
 * All remote devices must go by the same dirty log
 * region size in order to keep the caller simple.
 *
 * @sl = slink > 0
 * @dev = device to check and use to set ti->split_io
 *
 */
static int
set_split_io(struct slink *sl, struct sdev *dev)
{
	sector_t split_io_1st, split_io_ref = 0;
	struct slink *sl_cur, *sl0;
	struct sdev *dev_cur;

	/* Nonsense to proceed on SLINK0. */
	_BUG_ON_PTR(sl);
	if (!sl->number)
		return 0;

	_BUG_ON_PTR(dev);

	sl0 = slink_get_by_number(sl->repl_slinks, 0);
	_BUG_ON_PTR(sl0);

	/* Get split_io from any existing dev on this actual slink. */
	if (list_empty(SLINK_DEVS_LIST(sl)))
		split_io_1st = 0;
	else {
		dev_cur = list_first_entry(SLINK_DEVS_LIST(sl), struct sdev,
					   lists[SDEV_SLINK]);
		split_io_1st = dev_cur->io.split_io;
	}

	/* Find any preset split_io on any (slink > 0 && slink != sl) device. */
	list_for_each_entry(sl_cur, &sl0->repl_slinks->list,
			    lists[SLINK_REPLOG]) {
		if (!sl_cur->number ||
		    sl_cur->number == sl->number)
			continue;

		if (!list_empty(SLINK_DEVS_LIST(sl_cur))) {
			dev_cur = list_first_entry(SLINK_DEVS_LIST(sl_cur),
						   struct sdev,
						   lists[SDEV_SLINK]);
			split_io_ref = dev_cur->io.split_io;
			break;
		}
	}


	/*
	 * The region size *must* be the same for all devices
	 * in order to simplify the related caller logic.
	 */
	if ((split_io_ref && split_io_1st && split_io_ref != split_io_1st) ||
	    (split_io_1st && split_io_1st != dev->io.split_io) ||
	    (split_io_ref && split_io_ref != dev->io.split_io))
		DM_EINVAL("region size argument must be the "
			  "same for all devices");

	/* Lock sl0, because we ain't get here with sl == sl0. */
	write_lock(&sl0->lock);
	list_for_each_entry(dev_cur, SLINK_DEVS_LIST(sl0), lists[SDEV_SLINK])
		dev_cur->ti->split_io = dev->io.split_io;

	write_unlock(&sl0->lock);

	BUG_ON(slink_put(sl0));
	return 0;
}

/* Wait on device in flight device I/O before allowing device destroy. */
static void
slink_wait_on_io(struct sdev *dev)
{
	while (dev_io(dev)) {
		flush_workqueue(dev->sl->io.wq);
		wait_event(dev->io.waiters, !dev_io(dev));
	}
}

/* Postsuspend method. */
static int
blockdev_postsuspend(struct dm_repl_slink *slink, int dev_number)
{
	struct slink *sl;
	struct sdev *dev;

	DMDEBUG_LIMIT("%s dev_number=%d", __func__, dev_number);
	_SET_AND_BUG_ON_SL(sl, slink);

	if (dev_number < 0)
		return -EINVAL;

	write_lock(&sl->lock);
	dev = dev_get_by_number(sl, dev_number);
	if (unlikely(IS_ERR(dev))) {
		write_unlock(&sl->lock);
		return PTR_ERR(dev);
	}

	/* Set device suspended. */
	SetDevSuspended(dev);
	write_unlock(&sl->lock);

	dev_put(dev);

	/* Wait for any device io to finish. */
	slink_wait_on_io(dev);
	return 0;
}

/* Resume method. */
static int
blockdev_resume(struct dm_repl_slink *slink, int dev_number)
{
	struct slink *sl;
	struct sdev *dev;

	_SET_AND_BUG_ON_SL(sl, slink);
	DMDEBUG("%s sl_number=%d dev_number=%d", __func__,
		sl->number, dev_number);

	if (dev_number < 0)
		return -EINVAL;

	read_lock(&sl->lock);
	dev = dev_get_by_number(sl, dev_number);
	read_unlock(&sl->lock);

	if (unlikely(IS_ERR(dev)))
		return PTR_ERR(dev);

	/* Clear device suspended. */
	ClearDevSuspended(dev);
	BUG_ON(dev_put(dev));
	wake_do_slink(sl);
	return 0;
}

/* Destroy device resources. */
static void
dev_destroy(struct sdev *dev)
{
	if (dev->dev.dl)
		dm_dirty_log_destroy(dev->dev.dl);

	if (dev->io.kcopyd_client)
		dm_kcopyd_client_destroy(dev->io.kcopyd_client);

	if (dev->dev.dm_dev)
		dm_put_device(dev->ti, dev->dev.dm_dev);

	BUG_ON(!dev_put(dev));
}

/*
 * Method to add a device to a given site link
 * and optionally create a dirty log for it.
 *
 * @dev_number = unsigned int stored in the REPLOG to associate to a dev_path
 * @ti = dm_target ptr (needed for dm functions)
 * @argc = 4...
 * @argv = dev_params# dev_path dirty_log_args
 */
#define	MIN_DEV_ARGS	4
static int
blockdev_dev_add(struct dm_repl_slink *slink, int dev_number,
		 struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	unsigned dev_params, params, sl_count;
	long long tmp;
	struct slink *sl;
	struct sdev *dev;

	SHOW_ARGV;

	if (dev_number < 0)
		return -EINVAL;

	/* Two more because of the following dirty log parameters. */
	if (unlikely(argc < MIN_DEV_ARGS))
		DM_EINVAL("invalid device parameters count");

	/* Get #dev_params. */
	if (unlikely(sscanf(argv[0], "%lld", &tmp) != 1 ||
		     tmp != 1)) {
		DM_EINVAL("invalid device parameters argument");
	} else
		dev_params = tmp;

	_SET_AND_BUG_ON_SL(sl, slink);
	_BUG_ON_PTR(sl->repl_slinks);

	dev = dev_create(sl, ti, argv[1], dev_number);
	if (unlikely(IS_ERR(dev)))
		return PTR_ERR(dev);

	dev->dev.params.count = dev_params;

	/* Work on dirty log paramaters. */
	params = dev_params + 1;
	r = dirty_log_create(sl, dev, argc - params, argv + params);
	if (unlikely(r < 0))
		goto bad;

	/* Take out global and local lock to update the configuration. */
	write_lock(&sl->repl_slinks->lock);
	write_lock(&sl->lock);

	/* Set split io value on all replicated devices. */
	r = set_split_io(sl, dev);
	if (unlikely(r < 0))
		goto bad_unlock;

	/*
	 * Now that dev is all set, add it to the slink.
	 *
	 * If callers are racing for the same device,
	 * dev_add() will catch that case too.
	 */
	r = dev_add(sl, dev);
	if (unlikely(r < 0))
		goto bad_unlock;

	write_unlock(&sl->lock);

	sl_count = slink_count(sl);
	write_unlock(&sl->repl_slinks->lock);

	/* Ignore any resize problem and live with what we got. */
	if (sl_count > 1)
		dm_io_client_resize(sl_count, sl->io.dm_io_client);

	DMDEBUG("%s added device=%u to slink=%u",
		__func__, dev_number, sl->number);
	return dev_number;

bad_unlock:
	write_unlock(&sl->lock);
	write_unlock(&sl->repl_slinks->lock);
bad:
	BUG_ON(dev_io(dev));
	dev_destroy(dev);
	return r;
}

/* Method to delete a device from a given site link. */
static int
blockdev_dev_del(struct dm_repl_slink *slink, int dev_number)
{
	int i;
	unsigned sl_count;
	struct slink *sl;
	struct sdev *dev;

	_SET_AND_BUG_ON_SL(sl, slink);

	if (dev_number < 0)
		return -EINVAL;

	/* Check if device is active! */
	write_lock(&sl->lock);
	dev = dev_get_by_number(sl, dev_number);
	if (unlikely(IS_ERR(dev))) {
		write_unlock(&sl->lock);
		return PTR_ERR(dev);
	}

	SetDevTeardown(dev);
	write_unlock(&sl->lock);

	/* Release the new reference taken out via dev_get_by_number() .*/
	BUG_ON(dev_put(dev));

	/* Wait for any device I/O to finish. */
	slink_wait_on_io(dev);
	BUG_ON(dev_io(dev));

	/* Take device off any lists. */
	write_lock(&sl->lock);
	i = ARRAY_SIZE(dev->lists);
	while (i--) {
		if (!list_empty(dev->lists + i))
			list_del(dev->lists + i);
	}

	write_unlock(&sl->lock);

	/* Destroy device. */
	dev_destroy(dev);

	/* Ignore any resize problem. */
	sl_count = slink_count(sl);
	dm_io_client_resize(sl_count ? sl_count : 1, sl->io.dm_io_client);
	DMDEBUG("%s deleted device=%u from slink=%u",
		__func__, dev_number, sl->number);
	return 0;
}

/* Check slink properties for consistency. */
static int slink_check_properties(struct slink_params *params)
{
	enum dm_repl_slink_policy_type policy = params->policy;

	if (slink_policy_synchronous(policy) &&
	    slink_policy_asynchronous(policy))
		DM_EINVAL("synchronous and asynchronous slink "
			  "policies are mutually exclusive!");

	if (slink_policy_synchronous(policy) &&
	    params->fallbehind.value)
		DM_EINVAL("synchronous slink policy and fallbehind "
			  "are mutually exclusive!");
	return 0;
}

/*
 * Start methods of "blockdev" slink type.
 */
/* Method to destruct a site link context. */
static void
blockdev_dtr(struct dm_repl_slink *slink)
{
	struct slink *sl;

	_BUG_ON_PTR(slink);
	sl = slink->context;
	_BUG_ON_PTR(sl);

	slink_destroy(sl);
	BUG_ON(!slink_put(sl));
}

/*
 * Method to construct a site link context.
 *
 * #slink_params = 1-4
 * <slink_params> = slink# [slink_policy [fall_behind value]]
 * slink# = used to tie the host+dev_path to a particular SLINK; 0 is used
 *          for the local site link and 1-M are for remote site links.
 * slink_policy = policy to set on the slink (eg. async/sync)
 * fall_behind = # of ios the SLINK can fall behind before switching to
 * 		 synchronous mode (ios N, data N[kmgtpe], timeout N[smhd])
 */
static int
blockdev_ctr(struct dm_repl_slink *slink, struct dm_repl_log *replog,
	     unsigned argc, char **argv)
{
	int check, r;
	long long tmp;
	unsigned slink_number, slink_params;
	struct slink *sl;
	struct slink_params params;
	/* Makes our task to keep a unique list of slinks per replog easier. */
	struct dm_repl_log_slink_list *repl_slinks =
		replog->ops->slinks(replog);

	SHOW_ARGV;
	_BUG_ON_PTR(repl_slinks);

	memset(&params, 0, sizeof(params));
	params.policy = DM_REPL_SLINK_ASYNC;
	params.fallbehind.type = DM_REPL_SLINK_FB_IOS;
	params.fallbehind.multiplier = 1;

	if (unlikely(argc < 2))
		DM_EINVAL("invalid number of slink arguments");

	/* Get # of slink parameters. */
	if (unlikely(sscanf(argv[0], "%lld", &tmp) != 1 ||
		     tmp < 1 || tmp > argc))
		DM_EINVAL("invalid slink parameter argument");
	else
		params.count = slink_params = tmp;


	/* Get slink#. */
	if (unlikely(sscanf(argv[1], "%lld", &tmp) != 1 ||
		     tmp < 0 || tmp >= replog->ops->slink_max(replog))) {
		DM_EINVAL("invalid slink number argument");
	} else
		slink_number = tmp;

	if (slink_params > 1) {
		/* Handle policy argument. */
		r = get_slink_policy(argv[2]);
		if (unlikely(r < 0))
			return r;

		params.policy = r;
		check = 1;

		/* Handle fallbehind argument. */
		if (slink_params > 2) {
			r = get_slink_fallbehind(slink_params,
						 argv + 3, &params.fallbehind);
			if (unlikely(r < 0))
				return r;
		}
	} else
		check = 0;

	/* Check that policies make sense vs. fallbehind. */
	if (check) {
		r = slink_check_properties(&params);
		if (r < 0)
			return r;
	}

	/* Get/create an slink context. */
	sl = slink_create(slink, repl_slinks, &params, slink_number);
	return unlikely(IS_ERR(sl)) ? PTR_ERR(sl) : 0;
}

/*
 * Initiate data copy across a site link.
 *
 * This function may be used to copy a buffer entry *or*
 * for resynchronizing regions initially or when an SLINK
 * has fallen back to dirty log (bitmap) mode.
 */
/* Get sdev ptr from copy address. */
static struct sdev *
dev_get_by_addr(struct slink *sl, struct dm_repl_slink_copy_addr *addr)
{
	BUG_ON(addr->type != DM_REPL_SLINK_BLOCK_DEVICE &&
	       addr->type != DM_REPL_SLINK_DEV_NUMBER);
	return addr->type == DM_REPL_SLINK_BLOCK_DEVICE ?
	       dev_get_by_bdev(sl, addr->dev.bdev) :
	       dev_get_by_number(sl, addr->dev.number.dev);
}

/*
 * Needs to be called with sl->lock held.
 *
 * Return 0 in case io is allowed to the region the sector
 * is in and take out an I/O reference on the device.
 *
 * If I/O isn't allowd, no I/O reference will be taken out
 * and the follwoing return codes apply to caller actions:
 *
 * o -EAGAIN in case of prohibiting I/O because of device suspension
 *    or device I/O errors (i.e. link temporarilly down) ->
 *    caller is allowed to retry the I/O later once
 *    he'll have received a callback.
 *
 * o -EACCES in case a region is being resynchronized and the source
 *    region is being read to copy data accross to the same region
 *    of the replica (RD) ->
 *    caller is allowed to retry the I/O later once
 *    he'll have received a callback.
 *
 * o -ENODEV in case a device is not configured
 *    caller must drop the I/O to the device/slink pair.
 *
 * o -EPERM in case a region is out of sync ->
 *    caller must drop the I/O to the device/slink pair.
 */
static int
may_io(int rw, struct slink *sl, struct sdev *dev,
       sector_t sector, const char *action)
{
	int r;
	sector_t region;
	struct slink *sl_cur;
	struct sdev *dev_tmp;
	struct sdev_resync *resync;

	_BUG_ON_PTR(sl);

	if (IS_ERR(dev))
		return PTR_ERR(dev);

	region = sector_to_region(dev, sector);

	/*
	 * It's a caller error to call for multiple copies per slink.
	 */
	if (rw == WRITE &&
	    SlinkWriter(sl)) {
		DMERR_LIMIT("%s %s to slink%d, dev%d, region=%llu "
			    "while write pending to region=%llu!",
			    __func__, action, sl->number, dev->dev.number,
			    (unsigned long long) region,
			    (unsigned long long) dev->io.resync.writer_region);
		return -EPERM;
	}

	/*
	 * If the device is suspended, being torn down,
	 * closed or errored, retry again later.
	 */
	if (!DevOpen(dev) ||
	    DevSuspended(dev) ||
	    DevTeardown(dev) ||
	    DevErrorRead(dev) ||
	    DevErrorWrite(dev))
		return -EAGAIN;

	/* slink > 0 may read and write in case region is in sync. */
	if (sl->number) {
		struct dm_dirty_log *dl = dev->dev.dl;

		/*
		 * Ask dirty log for region in sync.
		 *
		 * In sync -> allow reads and writes.
		 * Out of sync -> prohibit them.
		 */
		_BUG_ON_PTR(dl);
		r = dl->type->in_sync(dl, region, 0); /* Don't block. */
		r = r ? 0 : -EPERM;
	} else {
		/* slink0 may always read. */
		if (rw == READ)
			return 0;

		read_lock(&sl->repl_slinks->lock);

		/*
		 * Walk all slinks and check if anyone is syncing this region,
		 * in which case no write is allowed to it on slink0.
		 */
		list_for_each_entry(sl_cur, &sl->repl_slinks->list,
				    lists[SLINK_REPLOG]) {
			/* Avoid local devices. */
			if (!sl_cur->number)
				continue;

			/*
			 * If device exists and the LD is
			 * being read off for resync.
			 */
			read_lock(&sl_cur->lock);
			dev_tmp = dev_get_by_number(sl_cur, dev->dev.number);
			read_unlock(&sl_cur->lock);

			if (!IS_ERR(dev_tmp)) {
				resync = &dev_tmp->io.resync;
				if (resync->end &&
				    resync->region == region) {
					BUG_ON(dev_put(dev_tmp));
					r = -EACCES;
					goto out;
				}

				BUG_ON(dev_put(dev_tmp));
			}
		}

		/* We're allowed to write to this LD -> indicate we do. */
		r = 0;
out:
		read_unlock(&sl->repl_slinks->lock);
	}

	if (!r && rw == WRITE) {
		write_lock(&sl->lock);
		/*
		 * Memorize region being synchronized
		 * to check in do_slink_resync().
		 */
		dev->io.resync.writer_region = region;
		SetSlinkWriter(sl);
		write_unlock(&sl->lock);
	}

	return r;
}

/* Set source/destination address of the copy. */
static int
copy_addr_init(struct slink *sl, struct dm_io_region *io,
	      struct dm_repl_slink_copy_addr *addr, unsigned size)
{

	if (addr->type == DM_REPL_SLINK_BLOCK_DEVICE) {
		io->bdev = addr->dev.bdev;
	} else if (addr->type == DM_REPL_SLINK_DEV_NUMBER) {
		struct sdev *dev;
		struct slink *sl_tmp;

		/* Check that slink number is correct. */
		read_lock(&sl->repl_slinks->lock);
		sl_tmp = slink_get_by_number(sl->repl_slinks,
					     addr->dev.number.slink);
		if (unlikely(IS_ERR(sl_tmp))) {
			int r = PTR_ERR(sl_tmp);

			read_unlock(&sl->repl_slinks->lock);
			return r;
		}

		read_unlock(&sl->repl_slinks->lock);

		if (unlikely(sl != sl_tmp))
			return -EINVAL;

		read_lock(&sl_tmp->lock);
		dev = dev_get_by_number(sl_tmp, addr->dev.number.dev);
		read_unlock(&sl_tmp->lock);

		BUG_ON(slink_put(sl_tmp));

		if (unlikely(IS_ERR(dev)))
			return PTR_ERR(dev);

		io->bdev = dev->dev.dm_dev->bdev;
		BUG_ON(dev_put(dev));
	} else
		BUG();

	io->sector = addr->sector;
	io->count = dm_div_up(size, to_bytes(1));
	return 0;
}

/*
 * Copy endio function.
 *
 * For the "blockdev" type, both states (data in (remote) ram and data
 * on (remote) disk) are reported here at once. For future transports
 * those will be reported seperately.
 */
static void
copy_endio(int read_err, unsigned long write_err, void *context)
{
	struct copy_context *ctx = context;
	struct slink *sl;
	struct sdev *dev_to;

	_BUG_ON_PTR(ctx);
	dev_to = ctx->dev_to;
	_BUG_ON_PTR(dev_to);
	sl = dev_to->sl;
	_BUG_ON_PTR(sl);

	/* Throw a table event in case of a site link device copy error. */
	if (unlikely(read_err || write_err)) {
		if (read_err) {
			if (!TestSetDevErrorRead(dev_to)) {
				SetSlinkErrorRead(sl);
				dm_table_event(dev_to->ti->table);
			}
		} else if (!TestSetDevErrorWrite(dev_to)) {
			SetSlinkErrorWrite(sl);
			dm_table_event(dev_to->ti->table);
		}

		set_dev_test_time(dev_to);
	}

	/* Must clear before calling back. */
	ClearSlinkWriter(sl);

	/*
	 * FIXME: check if caller has set region to NOSYNC and
	 *        and if so, avoid calling callbacks completely.
	 */
	if (ctx->ram.fn)
		ctx->ram.fn(read_err, write_err ? -EIO : 0, ctx->ram.context);

	/* Only call when no error or when no ram callback defined. */
	if (likely((!read_err && !write_err) || !ctx->ram.fn))
		ctx->disk.fn(read_err, write_err, ctx->disk.context);

	/* Copy done slinkX device. */
	free_copy_context(ctx, sl);

	/* Release device reference. */
	BUG_ON(dev_put(dev_to));

	/* Wake slink worker to reschedule any postponed resynchronization. */
	wake_do_slink(sl);
}

/* Site link copy method. */
static int
blockdev_copy(struct dm_repl_slink *slink, struct dm_repl_slink_copy *copy,
	      unsigned long long tag)
{
	int r;
	struct slink *sl;
	struct sdev *dev_to;
	struct copy_context *ctx = NULL;
	static struct dm_io_region src, dst;

	_SET_AND_BUG_ON_SL(sl, slink);
	if (unlikely(SlinkErrorRead(sl) || SlinkErrorWrite(sl)))
		return -EAGAIN;

	/* Get device by address taking out reference. */
	read_lock(&sl->lock);
	dev_to = dev_get_by_addr(sl, &copy->dst);
	read_unlock(&sl->lock);

	/* Check if io is allowed or a resync is active. */
	r = may_io(WRITE, sl, dev_to, copy->dst.sector, "copy");
	if (r < 0)
		goto bad;

	ctx = alloc_copy_context(sl);
	BUG_ON(!ctx);

	/* Device to copy to. */
	ctx->dev_to = dev_to;

	/* Save caller context. */
	ctx->ram = copy->ram;
	ctx->disk = copy->disk;

	/* Setup copy source. */
	r = copy_addr_init(sl, &src, &copy->src, copy->size);
	if (unlikely(r < 0))
		goto bad;

	/* Setup copy destination. */
	r = copy_addr_init(sl, &dst, &copy->dst, copy->size);
	if (unlikely(r < 0))
		goto bad;

	/* FIXME: can we avoid reading per copy on multiple slinks ? */
	r = dm_kcopyd_copy(sl->io.kcopyd_client, &src, 1, &dst, 0,
			   copy_endio, ctx);
	BUG_ON(r); /* dm_kcopyd_copy() may never fail. */
	SetDevIOQueued(dev_to); /* dev_unplug(src.bdev); */
	return r;

bad:
	if (!IS_ERR(dev_to))
		BUG_ON(dev_put(dev_to));

	if (ctx)
		free_copy_context(ctx, sl);

	return r;
}

/* Method to get site link policy. */
static enum dm_repl_slink_policy_type
blockdev_policy(struct dm_repl_slink *slink)
{
	struct slink *sl = slink_check(slink);

	return IS_ERR(sl) ? PTR_ERR(sl) : sl->params.policy;
}

/* Method to get site link State. */
static enum dm_repl_slink_state_type
blockdev_state(struct dm_repl_slink *slink)
{
	enum dm_repl_slink_state_type state = 0;
	struct slink *sl = slink_check(slink);

	if (unlikely(IS_ERR(sl)))
		return PTR_ERR(sl);

	if (SlinkErrorRead(sl))
		set_bit(DM_REPL_SLINK_READ_ERROR, (unsigned long *) &state);

	if (SlinkErrorWrite(sl))
		set_bit(DM_REPL_SLINK_DOWN, (unsigned long *) &state);

	return state;
}

/* Method to get reference to site link fallbehind parameters. */
static struct dm_repl_slink_fallbehind *
blockdev_fallbehind(struct dm_repl_slink *slink)
{
	struct slink *sl = slink_check(slink);

	return IS_ERR(sl) ? ((struct dm_repl_slink_fallbehind *) sl) :
			    &sl->params.fallbehind;
}

/* Return # of the device. */
static int
blockdev_dev_number(struct dm_repl_slink *slink, struct block_device *bdev)
{
	struct slink *sl = slink_check(slink);
	struct sdev *dev;
	struct mapped_device *md;

	if (unlikely(IS_ERR(sl)))
		return PTR_ERR(sl);

	if (unlikely(sl->number)) {
		DMERR("Can't retrieve device number from slink > 0");
		return -EINVAL;
	}

	read_lock(&sl->lock);
	list_for_each_entry(dev, SLINK_DEVS_LIST(sl), lists[SDEV_SLINK]) {
		md = dm_table_get_md(dev->ti->table);
		if (bdev->bd_disk == dm_disk(md)) {
			read_unlock(&sl->lock);
			return dev->dev.number;
		}
	}

	read_unlock(&sl->lock);

	/*
	 * The caller might have removed the device from SLINK0 but
	 * have an order to copy to the device in its metadata still,
	 * so he has to react accordingly (ie. remove device copy request).
	 */
	return -ENOENT;
}

/* Method to remap bio to underlying device on slink0. */
static int
blockdev_io(struct dm_repl_slink *slink, struct bio *bio,
	    unsigned long long tag)
{
	int r, rw = bio_data_dir(bio);
	struct slink *sl;
	struct sdev *dev;

	_SET_AND_BUG_ON_SL(sl, slink);

	/*
	 * Prohibit slink > 0 I/O, because the resync
	 * code can't cope with it for now...
	 */
	if (sl->number)
		DM_EPERM("I/O to slink > 0 prohibited!");

	if (rw == WRITE)
		DM_EPERM("Writes to slink0 prohibited!");

	read_lock(&sl->lock);
	dev = dev_get_by_bdev(sl, bio->bi_bdev);
	read_unlock(&sl->lock);

	/* Check if io is allowed or a resync is active. */
	r = may_io(rw, sl, dev, bio->bi_sector, "io");
	if (likely(!r)) {
		bio->bi_bdev = dev->dev.dm_dev->bdev;
		generic_make_request(bio);
		SetDevIOQueued(dev);
	}

	if (!IS_ERR(dev))
		BUG_ON(dev_put(dev));

	return r;
}

/* Method to unplug all device queues on a site link. */
static int
blockdev_unplug(struct dm_repl_slink *slink)
{
	struct slink *sl = slink_check(slink);
	struct sdev *dev, *dev_n;

	if (unlikely(IS_ERR(sl)))
		return PTR_ERR(sl);

	/* Take out device references for all devices with IO queued. */
	read_lock(&sl->lock);
	list_for_each_entry(dev, SLINK_DEVS_LIST(sl), lists[SDEV_SLINK]) {
		if (TestClearDevIOQueued(dev)) {
			dev_get(dev);
			SetDevIOUnplug(dev);
		}
	}

	read_unlock(&sl->lock);

	list_for_each_entry_safe(dev, dev_n,
				 SLINK_DEVS_LIST(sl), lists[SDEV_SLINK]) {
		if (TestClearDevIOUnplug(dev)) {
			if (DevOpen(dev) &&
			    !DevSuspended(dev) &&
			    !DevTeardown(dev))
				dev_unplug(dev->dev.dm_dev->bdev);

			BUG_ON(dev_put(dev));
		}
	}

	return 0;
}

/* Method to set global recovery function and context. */
static void
blockdev_recover_notify_fn_set(struct dm_repl_slink *slink,
			       dm_repl_notify_fn fn, void *context)
{
	struct slink *sl;

	_SET_AND_BUG_ON_SL(sl, slink);

	write_lock(&sl->lock);
	sl->recover.fn = fn;
	sl->recover.context = context;
	write_unlock(&sl->lock);
}

/* Method to return # of the SLINK. */
static int
blockdev_slink_number(struct dm_repl_slink *slink)
{
	struct slink *sl = slink_check(slink);

	return unlikely(IS_ERR(sl)) ? PTR_ERR(sl) : sl->number;
}

/* Method to return SLINK by number. */
static struct dm_repl_slink *
blockdev_slink(struct dm_repl_log *replog, unsigned slink_number)
{
	struct slink *sl;
	struct dm_repl_slink *slink;
	struct dm_repl_log_slink_list *repl_slinks;

	_BUG_ON_PTR(replog);
	repl_slinks = replog->ops->slinks(replog);
	_BUG_ON_PTR(repl_slinks);

	read_lock(&repl_slinks->lock);
	sl = slink_get_by_number(repl_slinks, slink_number);
	if (IS_ERR(sl))
		slink = (struct dm_repl_slink *) sl;
	else {
		slink = sl->slink;
		BUG_ON(slink_put(sl));
	}

	read_unlock(&repl_slinks->lock);
	return slink;
}

/* Method to set SYNC state of a region of a device. */
static int
blockdev_set_sync(struct dm_repl_slink *slink, int dev_number,
	       sector_t sector, int in_sync)
{
	struct sdev *dev;
	struct sdev_dev *sd;
	struct dm_dirty_log *dl;
	struct slink *sl;

	_SET_AND_BUG_ON_SL(sl, slink);

	if (dev_number < 0)
		return -EINVAL;

	read_lock(&sl->lock);
	dev = dev_get_by_number(sl, dev_number);
	read_unlock(&sl->lock);

	if (IS_ERR(dev))
		return PTR_ERR(dev);

	sd = &dev->dev;
	dl = sd->dl;
	if (dl)
		dl->type->set_region_sync(dl, sector_to_region(dev, sector),
					  in_sync);
	BUG_ON(dev_put(dev));
	return 0;
}

/* Method to flush all dirty logs on slink's devices. */
static int
blockdev_flush_sync(struct dm_repl_slink *slink)
{
	int r = 0;
	struct slink *sl;
	struct sdev *dev;
	struct list_head resync_list;

	_SET_AND_BUG_ON_SL(sl, slink);
	if (!sl->number)
		return -EINVAL;

	INIT_LIST_HEAD(&resync_list);

	write_lock(&sl->lock);
	if (SlinkResyncProcessing(sl)) {
		write_unlock(&sl->lock);
		return -EAGAIN;
	}

	/* Take out resync list in order to process flushs unlocked. */
	list_splice(SLINK_RESYNC_LIST(sl), &resync_list);
	INIT_LIST_HEAD(SLINK_RESYNC_LIST(sl));

	/* Get race references on devices. */
	list_for_each_entry(dev, &resync_list, lists[SDEV_RESYNC]) {
		_BUG_ON_PTR(dev->dev.dl);
		dev_get(dev);
	}

	write_unlock(&sl->lock);

	list_for_each_entry(dev, &resync_list, lists[SDEV_RESYNC]) {
		if (DevOpen(dev) &&
		    !(DevSuspended(dev) || DevTeardown(dev))) {
			int rr;
			struct dm_dirty_log *dl = dev->dev.dl;

			rr = dl->type->flush(dl);
			if (rr && !r)
				r = rr;
		}
	}

	/* Put race device references. */
	write_lock(&sl->lock);
	list_for_each_entry(dev, &resync_list, lists[SDEV_RESYNC])
		BUG_ON(dev_put(dev));

	list_splice(&resync_list, SLINK_RESYNC_LIST(sl));
	write_unlock(&sl->lock);

	return r;
}

/*
 * Method to trigger/prohibit resynchronzation on all devices by
 * adding to the slink resync list and waking up the worker.
 *
 * We may *not* remove from the slink resync list here,
 * because we'd end up with partitally resynchronized
 * regions in do_slink_resync() otherwise.
 */
static int
blockdev_resync(struct dm_repl_slink *slink, int resync)
{
	struct slink *sl;
	struct sdev *dev;

	_SET_AND_BUG_ON_SL(sl, slink);

	/* Don't proceed on site link 0. */
	if (!sl->number)
		return -EINVAL;

	/* If resync processing, we need to postpone. */
	write_lock(&sl->lock);
	if (SlinkResyncProcessing(sl)) {
		write_unlock(&sl->lock);
		return -EAGAIN;
	}

	list_for_each_entry(dev, SLINK_DEVS_LIST(sl), lists[SDEV_SLINK]) {
		BUG_ON(IS_ERR(dev));

		if (resync) {
			SetDevResync(dev);

			/* Add to resync list if not yet on. */
			if (list_empty(SDEV_RESYNC_LIST(dev))) {
				list_add_tail(SDEV_RESYNC_LIST(dev),
					      SLINK_RESYNC_LIST(sl));
				break;
			}
		} else {
			ClearDevResync(dev);

			/* emove from resync list if on. */
			if (!list_empty(SDEV_RESYNC_LIST(dev)))
				list_del_init(SDEV_RESYNC_LIST(dev));
		}
	}

	write_unlock(&sl->lock);
	wake_do_slink(sl);
	return 0;
}

/*
 * Method to check if a region is in sync
 * by sector on all devices on all slinks.
 */
static int
blockdev_in_sync(struct dm_repl_slink *slink, int dev_number, sector_t sector)
{
	int nosync = 0;
	sector_t region = 0;
	struct slink *sl = slink_check(slink);

	if (IS_ERR(sl) ||
	    dev_number < 0)
		return -EINVAL;

	BUG_ON(!sl->repl_slinks);

	read_lock(&sl->repl_slinks->lock);
	list_for_each_entry(sl, &sl->repl_slinks->list, lists[SLINK_REPLOG]) {
		int r;
		struct dm_dirty_log *dl;
		struct sdev *dev;

		if (!sl->number)
			continue;

		read_lock(&sl->lock);
		dev = dev_get_by_number(sl, dev_number);
		read_unlock(&sl->lock);

		if (IS_ERR(dev))
			continue;

		dl = dev->dev.dl;
		_BUG_ON_PTR(dl);

		/* Calculate region once for all devices on any slinks. */
		if (!region)
			region = sector_to_region(dev, sector);

		r = dl->type->in_sync(dl, region, 0);
		BUG_ON(dev_put(dev));
		if (!r) {
			nosync = 1;
			break;
		}
	}

	read_unlock(&sl->repl_slinks->lock);
	return nosync;
}

/*
 * Method for site link messages.
 *
 * fallbehind ios/size/timeout=X[unit]
 * policy X
 */
static int
blockdev_message(struct dm_repl_slink *slink, unsigned argc, char **argv)
{
	int r;
	struct slink_params params;
	struct slink *sl = slink_check(slink);

	if (IS_ERR(sl))
		return PTR_ERR(sl);

	if (unlikely(argc < 2))
		goto bad_arguments;

	/* Preserve parameters. */
	params = sl->params;

	if (!strnicmp(STR_LEN(argv[0], "fallbehind"))) {
		if (argc != 2)
			DM_EINVAL("wrong fallbehind argument count");

		r = get_slink_fallbehind(argc - 1, argv + 1,
					 &params.fallbehind);
		if (r < 0)
			return r;
	} else if (!strnicmp(STR_LEN(argv[0], "policy"))) {
		if (argc != 2)
			DM_EINVAL("wrong policy argument count");

		r = get_slink_policy(argv[1]);
		if (r < 0)
			return r;

		params.policy = r;
	} else
		DM_EINVAL("invalid message received");

	/* Check properties' consistency. */
	r = slink_check_properties(&params);
	if (r < 0)
		return r;

	/* Set parameters. */
	sl->params = params;
	return 0;

bad_arguments:
	DM_EINVAL("too few message arguments");
}

/* String print site link error state. */
static const char *
snprint_slink_error(struct slink *sl, char *result, size_t maxlen)
{
	size_t sz = 0;

	*result = 0;
	if (SlinkErrorRead(sl))
		DMEMIT("R");

	if (SlinkErrorWrite(sl))
		DMEMIT("W");

	if (!*result)
		DMEMIT("A");

	return result;
}

/* String print device status. */
static const char *
snprint_device(struct slink *sl, struct sdev *dev,
	      status_type_t type, char *result, unsigned maxlen)
{
	size_t sz = 0;
	static char buf[BDEVNAME_SIZE];
	struct sdev_dev *sd;
	struct dm_dirty_log *dl;

	*result = 0;
	if (IS_ERR(dev))
		goto out;

	sd = &dev->dev;
	DMEMIT("%u %s ", sd->params.count,
	       sd->dm_dev ?
	       format_dev_t(buf, sd->dm_dev->bdev->bd_dev) :
	       sd->params.path);
	dl = sd->dl;
	if (dl)
		dl->type->status(dl, type, result + sz, maxlen - sz);
	else
		DMEMIT("nolog 0");

out:
	return result;
}

/* String print device resynchronization state. */
static const char *
snprint_sync_count(struct slink *sl, struct sdev *dev,
		   char *result, unsigned maxlen)
{
	size_t sz = 0;
	struct dm_dirty_log *dl;

	if (IS_ERR(dev))
		goto no_dev;

	dl = dev->dev.dl;
	if (dl) {
		DMEMIT("%llu%s/%llu",
		       (unsigned long long) dl->type->get_sync_count(dl),
		       DevResyncing(dev) ? "+" : "",
		       (unsigned long long) region_count(dev));
	} else {
no_dev:
		DMEMIT("-");
	}

	return result;
}

/* Method for site link status requests. */
static struct dm_repl_slink_type blockdev_type;
static int
blockdev_status(struct dm_repl_slink *slink, int dev_number,
	     status_type_t type, char *result, unsigned int maxlen)
{
	size_t sz = 0;
	static char buffer[256];
	struct slink *sl_cur, *sl = slink_check(slink);
	struct sdev *dev;
	struct slink_params *p;
	struct list_head *sl_list;

	if (unlikely(IS_ERR(sl)))
		return PTR_ERR(sl);

	if (dev_number < -1)
		return -EINVAL;

	BUG_ON(!sl->repl_slinks);
	sl_list = &sl->repl_slinks->list;

	read_lock(&sl->repl_slinks->lock);

	switch (type) {
	case STATUSTYPE_INFO:
		list_for_each_entry(sl_cur, sl_list, lists[SLINK_REPLOG]) {
			read_lock(&sl_cur->lock);
			dev = dev_get_by_number(sl_cur, dev_number);
			read_unlock(&sl_cur->lock);

			if (!IS_ERR(dev)) {
				DMEMIT("%s,",
				       snprint_slink_error(sl_cur, buffer,
							   sizeof(buffer)));

				DMEMIT("%s ",
				       snprint_sync_count(sl_cur, dev, buffer,
							  sizeof(buffer)));
				BUG_ON(dev_put(dev));
			}
		}

		break;

	case STATUSTYPE_TABLE:
		list_for_each_entry(sl_cur, sl_list, lists[SLINK_REPLOG]) {
			read_lock(&sl_cur->lock);
			if (dev_number < 0) {
				p = &sl_cur->params;
				DMEMIT("%s %u %u ",
				       blockdev_type.type.name,
				       p->count, sl_cur->number);

				if (p->count > 1) {
					snprint_policies(p->policy, buffer,
							 sizeof(buffer));
					DMEMIT("%s ", buffer);
					snprint_fallbehind(&p->fallbehind,
							   buffer,
							   sizeof(buffer));
					if (p->count > 2)
						DMEMIT("%s ", buffer);
				}
			} else {
				dev = dev_get_by_number(sl_cur, dev_number);
				if (!IS_ERR(dev)) {
					DMEMIT("%u %s ", sl_cur->number,
					       snprint_device(sl_cur, dev, type,
							      buffer,
							      sizeof(buffer)));
					BUG_ON(dev_put(dev));
				}
			}

			read_unlock(&sl_cur->lock);
		}
	}

	read_unlock(&sl->repl_slinks->lock);
	return 0;
}

/*
 * End methods of "blockdev" slink type.
 */

/* "blockdev" SLINK handler interface type. */
static struct dm_repl_slink_type blockdev_type = {
	.type.name = "blockdev",
	.type.module = THIS_MODULE,

	.ctr = blockdev_ctr,
	.dtr = blockdev_dtr,

	.postsuspend = blockdev_postsuspend,
	.resume = blockdev_resume,

	.dev_add = blockdev_dev_add,
	.dev_del = blockdev_dev_del,

	.copy = blockdev_copy,
	.io = blockdev_io,
	.unplug = blockdev_unplug,
	.recover_notify_fn_set = blockdev_recover_notify_fn_set,
	.set_sync = blockdev_set_sync,
	.flush_sync = blockdev_flush_sync,
	.resync = blockdev_resync,
	.in_sync = blockdev_in_sync,

	.policy = blockdev_policy,
	.state = blockdev_state,
	.fallbehind = blockdev_fallbehind,
	.dev_number = blockdev_dev_number,
	.slink_number = blockdev_slink_number,
	.slink = blockdev_slink,

	.message = blockdev_message,
	.status = blockdev_status,
};

/* Destroy kmem caches on module unload. */
static void
slink_kmem_caches_exit(void)
{
	struct cache_defs *cd = ARRAY_END(cache_defs);

	while (cd-- > cache_defs) {
		if (cd->cache) {
			kmem_cache_destroy(cd->cache);
			cd->cache = NULL;
		}
	}
}

/* Create kmem caches on module load. */
static int
slink_kmem_caches_init(void)
{
	int r = 0;
	struct cache_defs *cd = ARRAY_END(cache_defs);

	while (cd-- > cache_defs) {
		cd->cache = kmem_cache_create(cd->name, cd->size, 0, 0, NULL);

		if (unlikely(!cd->cache)) {
			DMERR("failed to create %s slab for site link "
			      "handler %s %s",
			      cd->name, blockdev_type.type.name, version);
			slink_kmem_caches_exit();
			r = -ENOMEM;
			break;
		}
	}

	return r;
}

int __init
dm_repl_slink_init(void)
{
	int r;

	/* Create slabs for the copy contexts and test buffers. */
	r = slink_kmem_caches_init();
	if (r) {
		DMERR("failed to init %s kmem caches", blockdev_type.type.name);
		return r;
	}

	r = dm_register_type(&blockdev_type, DM_SLINK);
	if (unlikely(r < 0)) {
		DMERR("failed to register replication site "
		      "link handler %s %s [%d]",
		      blockdev_type.type.name, version, r);
		slink_kmem_caches_exit();
	} else
		DMINFO("registered replication site link handler %s %s",
		       blockdev_type.type.name, version);

	return r;
}

void __exit
dm_repl_slink_exit(void)
{
	int r = dm_unregister_type(&blockdev_type, DM_SLINK);

	slink_kmem_caches_exit();

	if (r)
		DMERR("failed to unregister replication site "
		      "link handler %s %s [%d]",
		       blockdev_type.type.name, version, r);
	else
		DMINFO("unregistered replication site link handler %s %s",
		       blockdev_type.type.name, version);

}

/* Module hooks. */
module_init(dm_repl_slink_init);
module_exit(dm_repl_slink_exit);

MODULE_DESCRIPTION(DM_NAME " remote replication target \"blockdev\" "
			   "site link (SLINK) handler");
MODULE_AUTHOR("Heinz Mauelshagen <heinzm@redhat.com>");
MODULE_LICENSE("GPL");
