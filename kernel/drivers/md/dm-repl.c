/*
 * Copyright (C) 2009 Red Hat, Inc. All rights reserved.
 *
 * Module Author: Heinz Mauelshagen <HeinzM@redhat.com>
 *
 * This file is released under the GPL.
 *
 * Remote Replication target.
 *
 * Features:
 * o Logs writes to circular buffer keeping persistent state metadata.
 * o Writes data from log synchronuously or asynchronuously
 *   to multiple (1-N) remote replicas.
 * o stores CRCs with metadata for integrity checks
 * o stores versions with metadata to support future metadata migration
 *
 *
 * For disk layout of backing store see dm-repl-log implementation.
 *
 *
 * This file is the control module of the replication target, which
 * controls the construction/destruction and mapping of replication
 * mappings interfacing into seperate log and site link (transport)
 * handler modules.
 *
 * That architecture allows the control module to be log *and* transport
 * implementation agnostic.
 */

static const char version[] = "v0.028";

#include "dm.h"
#include "dm-repl.h"
#include "dm-repl-log.h"
#include "dm-repl-slink.h"

#include <stdarg.h>
#include <linux/dm-dirty-log.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/crc32.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#define	DM_MSG_PREFIX	"dm-repl"
#define	DAEMON	DM_MSG_PREFIX	"d"

/* Default local device read ahead pages. */
#define	LD_RA_PAGES_DEFAULT	8

/* Factor out to dm.[ch] */
/* Return type for name. */
int
dm_descr_type(const struct dm_str_descr *descr, unsigned len, const char *name)
{
	while (len--) {
		if (!strncmp(STR_LEN(name, descr[len].name)))
			return descr[len].type;
	}

	return -ENOENT;
}
EXPORT_SYMBOL_GPL(dm_descr_type);

/* Return name for type. */
const char *
dm_descr_name(const struct dm_str_descr *descr, unsigned len, const int type)
{
	while (len--) {
		if (type == descr[len].type)
			return descr[len].name;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(dm_descr_name);
/* END Factor out to dm.[ch] */

/* Global list of replication log contexts for ctr/dtr and lock. */
static LIST_HEAD(replog_c_list);
static struct mutex replog_c_list_mutex;

/* Statistics. */
struct stats {
	atomic_t io[2];
	atomic_t submitted_io[2];
	atomic_t congested_fn[2];
};

/* Reset statistics variables. */
static void
stats_reset(struct stats *stats)
{
	int i = 2;

	while (i--) {
		atomic_set(stats->io + i, 0);
		atomic_set(stats->submitted_io + i, 0);
		atomic_set(stats->congested_fn + i, 0);
	}
}

/* Per site link context. */
struct slink_c {
	struct {
		struct list_head slink_c;
		struct list_head dc; /* List of replication device contexts. */
	} lists;

	/* Reference count (ie. number of devices on this site link) */
	struct kref ref;

	/* Slink handle. */
	struct dm_repl_slink *slink;

	/* Replog context. */
	struct replog_c *replog_c;
};

/* Global context kept with replicator log. */
enum replog_c_flags {
	REPLOG_C_BLOCKED,
	REPLOG_C_DEVEL_STATS,
	REPLOG_C_IO_INFLIGHT,
	REPLOG_C_RESUME_TWICE,
	REPLOG_C_DEV_RESUME_TWICE,
};
struct replog_c {
	struct {
		struct list_head replog_c;/* To add to global replog_c list. */
		struct list_head slink_c; /* Site link context elements. */
	} lists;

	struct dm_target *ti;

	/* Reference count (ie. # of slinks * # of devices on this replog) */
	struct kref ref;

	/* Back pointer to replication log. */
	struct dm_repl_log *replog;
	dev_t dev;	/* Replicator control device major:minor. */

	/* Global io housekeeping on site link 0. */
	struct repl_io {
		unsigned long flags;	/* I/O state flags. */

		struct bio_list in;	/* Pending bios (central input list).*/
		spinlock_t in_lock;	/* Protects central input list.*/
		atomic_t in_flight;	/* In flight io counter. */

		/* IO workqueue. */
		struct workqueue_struct *wq;
		struct work_struct ws;

		/* Statistics. */
		struct stats stats;

		/* slink+I/O teardown synchronization. */
		wait_queue_head_t waiters;
	} io;
};
DM_BITOPS(ReplBlocked, replog_c, REPLOG_C_BLOCKED);
DM_BITOPS(ReplDevelStats, replog_c, REPLOG_C_DEVEL_STATS);
DM_BITOPS(ReplIoInflight, replog_c, REPLOG_C_IO_INFLIGHT);
DM_BITOPS(ReplResumeTwice, replog_c, REPLOG_C_RESUME_TWICE);
DM_BITOPS(ReplDevResumeTwice, replog_c, REPLOG_C_DEV_RESUME_TWICE);

/*
 * Per device replication context kept with any mapped device and
 * any associated remote device, which doesn't have a local mapping.
 */
struct device_c {
	struct list_head list; /* To add to slink_c rc list. */

	/* Local device ti (i.e. head). */
	struct dm_target *ti;

	/* replicator control device reference. */
	struct dm_dev *replicator_dev;

	/* SLINK handle. */
	struct slink_c *slink_c;

	/* This device's number. */
	int number;
};

/* IO in flight wait qeue handling during suspension. */
static void
replog_c_io_get(struct replog_c *replog_c)
{
	SetReplIoInflight(replog_c);
	atomic_inc(&replog_c->io.in_flight);
}

/* Drop io in flight reference. */
static void
replog_c_io_put(struct replog_c *replog_c)
{
	if (atomic_dec_and_test(&replog_c->io.in_flight)) {
		ClearReplIoInflight(replog_c);
		wake_up(&replog_c->io.waiters);
	}
}

/* Get a handle on a replicator log. */
static struct dm_repl_log *
repl_log_ctr(const char *name, struct dm_target *ti,
	     unsigned int argc, char **argv)
{
	int r;
	struct dm_repl_log_type *type;
	struct dm_repl_log *log;

	log = kzalloc(sizeof(*log), GFP_KERNEL);
	if (unlikely(!log))
		return ERR_PTR(-ENOMEM);

	/* Load requested replication log module. */
	r = request_module("dm-repl-log-%s", name);
	if (r < 0) {
		DMERR("replication log module for \"%s\" not found", name);
		kfree(log);
		return ERR_PTR(-ENOENT);
	}

	type = dm_get_type(name, DM_REPLOG);
	if (unlikely(IS_ERR(type))) {
		DMERR("replication log registry type not found");
		kfree(log);
		return (struct dm_repl_log *) type;
	}

	log->ops = type;
	r = type->ctr(log, ti, argc, argv);
	if (unlikely(r < 0)) {
		DMERR("%s: constructor failed", __func__);
		dm_put_type(type, DM_REPLOG);
		kfree(log);
		log = ERR_PTR(r);
	}

	return log;
}

/* Put a handle on a replicator log. */
static void
repl_log_dtr(struct dm_repl_log *log, struct dm_target *ti)
{
	/* Frees log on last drop. */
	log->ops->dtr(log, ti);
	dm_put_type(log->ops, DM_REPLOG);
	kfree(log);
}

/*
 * Create/destroy a transient replicator site link on initial get/last out.
 */
static struct dm_repl_slink *
repl_slink_ctr(char *name, struct dm_repl_log *replog,
	       unsigned argc, char **argv)
{
	int r;
	struct dm_repl_slink_type *type;
	struct dm_repl_slink *slink;

	slink = kzalloc(sizeof(*slink), GFP_KERNEL);
	if (unlikely(!slink))
		return ERR_PTR(-ENOMEM);

	/* Load requested replication site link module. */
	r = request_module("dm-repl-slink-%s", name);
	if (r < 0) {
		DMERR("replication slink module for \"%s\" not found", name);
		kfree(slink);
		return ERR_PTR(-ENOENT);
	}

	type = dm_get_type(name, DM_SLINK);
	if (unlikely(IS_ERR(type))) {
		DMERR("replication slink registry type not found");
		kfree(slink);
		return (struct dm_repl_slink *) type;
	}

	r = type->ctr(slink, replog, argc, argv);
	if (unlikely(r < 0)) {
		DMERR("%s: constructor failed", __func__);
		dm_put_type(type, DM_SLINK);
		kfree(slink);
		return ERR_PTR(r);
	}

	slink->ops = type;
	return slink;
}

static void
slink_destroy(struct dm_repl_slink *slink)
{
	/* Frees slink on last reference drop. */
	slink->ops->dtr(slink);
	dm_put_type(slink->ops, DM_SLINK);
	kfree(slink);
}


/* Wake worker. */
static void do_repl(struct work_struct *ws);
static void
wake_do_repl(struct replog_c *replog_c)
{
	queue_work(replog_c->io.wq, &replog_c->io.ws);
}

/* Called from the replog in case we can queue more bios. */
static void
io_callback(int read_err, int write_err, void *context)
{
	struct replog_c *replog_c = context;

	DMDEBUG_LIMIT("%s", __func__);
	_BUG_ON_PTR(replog_c);
	ClearReplBlocked(replog_c);
	wake_do_repl(replog_c);
}

/* Get a reference on a replog_c by replog reference. */
static struct replog_c *
replog_c_get(struct replog_c *replog_c)
{
	kref_get(&replog_c->ref);
	return replog_c;
}

/* Destroy replog_c object. */
static int slink_c_put(struct slink_c *slink_c);
static void
replog_c_release(struct kref *ref)
{
	struct replog_c *replog_c = container_of(ref, struct replog_c, ref);

	BUG_ON(!list_empty(&replog_c->lists.replog_c));
	BUG_ON(!list_empty(&replog_c->lists.slink_c));
	kfree(replog_c);
}

/* Release reference on replog_c, releasing resources on last drop. */
static int
replog_c_put(struct replog_c *replog_c)
{
	_BUG_ON_PTR(replog_c);
	return kref_put(&replog_c->ref, replog_c_release);
}

/*
 * Find a replog_c by replog reference in the global replog context list.
 *
 * Call with replog_c_list_mutex held.
 */
static struct replog_c *
replog_c_get_by_dev(dev_t dev)
{
	struct replog_c *replog_c;

	list_for_each_entry(replog_c, &replog_c_list, lists.replog_c) {
		if (dev == replog_c->dev)
			return replog_c_get(replog_c);
	}

	return ERR_PTR(-ENOENT);
}

/* Get replicator control device major:minor. */
static dev_t
get_ctrl_dev(struct dm_target *ti)
{
	dev_t dev;
	struct mapped_device *md = dm_table_get_md(ti->table);
	struct block_device *bdev = bdget_disk(dm_disk(md), 0);

	dev = bdev->bd_dev;
	bdput(bdev);
	return dev;
}

/* Allocate a replication control context. */
static struct replog_c *
replog_c_alloc(void)
{
	struct replog_c *replog_c = kzalloc(sizeof(*replog_c), GFP_KERNEL);
	struct repl_io *io;

	if (unlikely(!replog_c))
		return ERR_PTR(-ENOMEM);

	io = &replog_c->io;

	/* Create singlethread workqueue for this replog's io. */
	io->wq = create_singlethread_workqueue(DAEMON);
	if (unlikely(!io->wq)) {
		kfree(replog_c);
		return ERR_PTR(-ENOMEM);
	}

	kref_init(&replog_c->ref);
	INIT_LIST_HEAD(&replog_c->lists.slink_c);
	ClearReplDevelStats(replog_c);
	ClearReplBlocked(replog_c);
	spin_lock_init(&io->in_lock);
	bio_list_init(&io->in);
	atomic_set(&io->in_flight, 0);
	INIT_WORK(&io->ws, do_repl);
	stats_reset(&io->stats);
	init_waitqueue_head(&io->waiters);
	return replog_c;
}

/* Create replog_c context. */
static struct replog_c *
replog_c_create(struct dm_target *ti, struct dm_repl_log *replog)
{
	dev_t replicator_dev;
	struct replog_c *replog_c, *replog_c_tmp;

	/* Get replicator control device major:minor. */
	replicator_dev = get_ctrl_dev(ti);

	/* Allcate and init replog_c object. */
	replog_c = replog_c_alloc();
	if (IS_ERR(replog_c))
		return replog_c;

	/* Add to global replog_c list. */
	mutex_lock(&replog_c_list_mutex);
	replog_c_tmp = replog_c_get_by_dev(replicator_dev);
	if (likely(IS_ERR(replog_c_tmp))) {
		/* We won any potential race. */
		/* Set replog global I/O callback and context. */
		replog->ops->io_notify_fn_set(replog, io_callback,
					      replog_c);
		replog_c->dev = replicator_dev;
		replog_c->ti = ti;
		replog_c->replog = replog;
		list_add_tail(&replog_c->lists.replog_c,
			      &replog_c_list);
		mutex_unlock(&replog_c_list_mutex);
	} else {
		/* Lost a potential race. */
		mutex_unlock(&replog_c_list_mutex);

		destroy_workqueue(replog_c->io.wq);
		kfree(replog_c);
		replog_c = replog_c_tmp;
	}

	return replog_c;
}

/* Find dc on slink_c list by dev_nr. */
static struct device_c *
device_c_find(struct slink_c *slink_c, unsigned dev_nr)
{
	struct device_c *dc;

	list_for_each_entry(dc, &slink_c->lists.dc, list) {
		if (dev_nr == dc->number)
			return dc;
	}

	return ERR_PTR(-ENOENT);
}

/* Get a reference on an slink_c by slink reference. */
static struct slink_c *
slink_c_get(struct slink_c *slink_c)
{
	kref_get(&slink_c->ref);
	return slink_c;
}

/* Find an slink_c by slink number on the replog slink list. */
static struct slink_c *
slink_c_get_by_number(struct replog_c *replog_c, int slink_nr)
{
	struct slink_c *slink_c;

	list_for_each_entry(slink_c, &replog_c->lists.slink_c, lists.slink_c) {
		int slink_nr_tmp =
			slink_c->slink->ops->slink_number(slink_c->slink);

		if (slink_nr == slink_nr_tmp)
			return slink_c_get(slink_c);
	}

	return ERR_PTR(-ENOENT);
}

/* Site link constructor helper to create a slink_c object. */
static struct slink_c *
slink_c_create(struct replog_c *replog_c, struct dm_repl_slink *slink)
{
	int r, slink_nr = slink->ops->slink_number(slink);
	struct slink_c *slink_c, *slink_c_tmp;
	struct dm_repl_log *replog = replog_c->replog;

	BUG_ON(slink_nr < 0);
	DMDEBUG("%s creating slink_c for site link=%d", __func__, slink_nr);

	slink_c = kzalloc(sizeof(*slink_c), GFP_KERNEL);
	if (unlikely(!slink_c))
		return ERR_PTR(-ENOMEM);

	r = replog->ops->slink_add(replog, slink);
	if (unlikely(r < 0)) {
		kfree(slink_c);
		return ERR_PTR(r);
	}

	DMDEBUG("%s added site link=%d", __func__,
		slink->ops->slink_number(slink));

	kref_init(&slink_c->ref);
	INIT_LIST_HEAD(&slink_c->lists.dc);
	slink_c->replog_c = replog_c;
	slink_c->slink = slink;

	/* Check creation race and add to per replog_c slink_c list. */
	mutex_lock(&replog_c_list_mutex);
	slink_c_tmp = slink_c_get_by_number(replog_c, slink_nr);
	if (likely(IS_ERR(slink_c_tmp)))
		list_add_tail(&slink_c->lists.slink_c,
			      &replog_c->lists.slink_c);
	else {
		kfree(slink_c);
		slink_c = slink_c_tmp;
	}

	mutex_unlock(&replog_c_list_mutex);
	return slink_c;
}

/*
 * Release reference on slink_c, removing dc from
 * it and releasing resources on last drop.
 */
static void
slink_c_release(struct kref *ref)
{
	struct slink_c *slink_c = container_of(ref, struct slink_c, ref);

	BUG_ON(!list_empty(&slink_c->lists.dc));
	kfree(slink_c);
}

/*
 * Release reference on slink_c, removing dc from
 * it and releasing resources on last drop.
 */
static int
slink_c_put(struct slink_c *slink_c)
{
	return kref_put(&slink_c->ref, slink_c_release);
}

/* Either set ti->error or call DMERR() depending on ctr call type. */
enum ctr_call_type { CTR_CALL, MESSAGE_CALL };
static void
ti_or_dmerr(enum ctr_call_type call_type, struct dm_target *ti, char *msg)
{
	if (call_type == CTR_CALL)
		ti->error = msg;
	else
		DMERR("%s", msg);
}

/*
 * Check, if @str is listed on variable (const char *) list of strings.
 *
 * Returns 1 for found on list and 0 for failure.
 */
static int
str_listed(const char *str, ...)
{
	int r = 0;
	const char *s;
	va_list str_list;

	va_start(str_list, str);

	while ((s = va_arg(str_list, const char *))) {
		if (!strncmp(str, s, strlen(str))) {
			r = 1;
			break;
		}
	}

	va_end(str_list);
	return r;
}

/*
 * Worker thread.
 *
 * o work on all new queued bios io'ing them to the REPLOG
 * o break out if replog reports -EWOULDBLOCK until called back
 */
static void
do_repl(struct work_struct *ws)
{
	struct replog_c *replog_c = container_of(ws, struct replog_c, io.ws);
	struct dm_repl_log *replog = replog_c->replog;
	struct bio *bio;
	struct bio_list ios;

	_BUG_ON_PTR(replog);

	if (ReplBlocked(replog_c))
		return;

	bio_list_init(&ios);

	/* Quickly grab all (new) input bios queued. */
	spin_lock(&replog_c->io.in_lock);
	bio_list_merge(&ios, &replog_c->io.in);
	bio_list_init(&replog_c->io.in);
	spin_unlock(&replog_c->io.in_lock);

	/* Work all deferred or new bios on work list. */
	while ((bio = bio_list_pop(&ios))) {
		int r = replog->ops->io(replog, bio, 0);

		if (r == -EWOULDBLOCK) {
			SetReplBlocked(replog_c);
			DMDEBUG_LIMIT("%s SetReplBlocked", __func__);

			/* Push non-processed bio back to the work list. */
			bio_list_push(&ios, bio);

			/*
			 * Merge non-processed bios
			 * back to the input list head.
			 */
			spin_lock(&replog_c->io.in_lock);
			bio_list_merge_head(&replog_c->io.in, &ios);
			spin_unlock(&replog_c->io.in_lock);

			break;
		} else
			BUG_ON(r);
	}
}

/* Replication congested function. */
static int
repl_congested(void *congested_data, int bdi_bits)
{
	int r;
	struct device_c *dc = congested_data;
	struct replog_c *replog_c;

	_BUG_ON_PTR(dc);
	_BUG_ON_PTR(dc->slink_c);
	replog_c = dc->slink_c->replog_c;
	_BUG_ON_PTR(replog_c);
	r = !!ReplBlocked(replog_c);
	atomic_inc(&replog_c->io.stats.congested_fn[r]);
	return r;
}

/* Set backing device congested function of a local replicated device. */
static void
dc_set_bdi(struct device_c *dc)
{
	struct mapped_device *md = dm_table_get_md(dc->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = repl_congested;
	bdi->congested_data = dc;
}

/* Get device on slink and unlink it from the list of devices. */
static struct device_c *
dev_get_del(struct device_c *dc, int slink_nr, struct list_head *dc_list)
{
	int dev_nr;
	struct slink_c *slink_c;
	struct dm_repl_slink *slink;
	struct dm_repl_log *replog;
	struct replog_c *replog_c;

	_BUG_ON_PTR(dc);
	dev_nr = dc->number;
	BUG_ON(dev_nr < 0);
	slink_c = dc->slink_c;
	_BUG_ON_PTR(slink_c);
	slink = slink_c->slink;
	_BUG_ON_PTR(slink);
	replog_c = slink_c->replog_c;
	_BUG_ON_PTR(replog_c);
	replog = replog_c->replog;
	_BUG_ON_PTR(replog);

	/* Get the slink by number. */
	slink = slink->ops->slink(replog, slink_nr);
	if (IS_ERR(slink))
		return (struct device_c *) slink;

	slink_c = slink_c_get_by_number(replog_c, slink_nr);
	if (IS_ERR(slink_c))
		return (struct device_c *) slink_c;

	dc = device_c_find(slink_c, dev_nr);
	if (IS_ERR(dc))
		DMERR("No device %d on slink %d", dev_nr, slink_nr);
	else
		list_move(&dc->list, dc_list);

	BUG_ON(slink_c_put(slink_c));
	return dc;
}

/* Free device and put references. */
static int
dev_free_put(struct device_c *dc, int slink_nr)
{
	int r;
	struct slink_c *slink_c;
	struct dm_repl_slink *slink;

	_BUG_ON_PTR(dc);
	BUG_ON(dc->number < 0);
	BUG_ON(slink_nr < 0);
	slink_c = dc->slink_c;
	_BUG_ON_PTR(slink_c);
	slink = slink_c->slink;
	_BUG_ON_PTR(slink);

	/* Delete device from slink. */
	r = slink->ops->dev_del(slink, dc->number);
	if (r < 0) {
		DMERR("Error %d deleting device %d from "
		      "site link %d", r, dc->number, slink_nr);
	} else
		/* Drop reference on replicator control device. */
		dm_put_device(dc->ti, dc->replicator_dev);

	kfree(dc);

	if (!r)
		/* Drop reference on slink_c, freeing it on last one. */
		BUG_ON(slink_c_put(slink_c));

	return r;
}

/*
 * Replication device "replicator-dev" destructor method.
 *
 * Either on slink0 in case slink_nr == 0 for mapped devices;
 * the whole chain of LD + its RDs will be deleted
 * -or-
 * on slink > 0 in case of message interface calls (just one RD)
 */
static int
_replicator_dev_dtr(struct dm_target *ti, int slink_nr)
{
	int r;
	struct device_c *dc = ti->private, *dc_tmp, *dc_n;
	struct slink_c *slink_c, *slink_c_n;
	struct replog_c *replog_c;
	struct dm_repl_slink *slink;
	struct list_head dc_list;

	BUG_ON(slink_nr < 0);
	_BUG_ON_PTR(dc);
	INIT_LIST_HEAD(&dc_list);
	slink_c = dc->slink_c;
	_BUG_ON_PTR(slink_c);
	replog_c = slink_c->replog_c;
	_BUG_ON_PTR(replog_c);

	/* First pull device out on all slinks holding lock. */
	mutex_lock(&replog_c_list_mutex);
	/* Call from message interface wih slink_nr > 0. */
	if (slink_nr)
		dev_get_del(dc, slink_nr, &dc_list);
	else {
		/* slink number 0 -> delete LD and any RDs. */
		list_for_each_entry_safe(slink_c, slink_c_n,
					 &replog_c->lists.slink_c,
					 lists.slink_c) {
			slink = slink_c->slink;
			_BUG_ON_PTR(slink);
			slink_nr = slink->ops->slink_number(slink);
			BUG_ON(slink_nr < 0);
			dev_get_del(dc, slink_nr, &dc_list);
		}
	}

	mutex_unlock(&replog_c_list_mutex);

	r = !list_empty(&dc_list);

	/* Now delete devices on pulled out list. */
	list_for_each_entry_safe(dc_tmp, dc_n, &dc_list, list) {
		slink = dc_tmp->slink_c->slink;
		dev_free_put(dc_tmp, slink->ops->slink_number(slink));
	}

	ti->private = NULL;
	return r;
}

/* Replicator device destructor. Autodestructs devices on slink > 0. */
static void
replicator_dev_dtr(struct dm_target *ti)
{
	_replicator_dev_dtr(ti, 0); /* Slink 0 device destruction. */
}

/* Construct a local/remote device. */
/*
 * slink_nr dev_nr dev_path dirty_log_params
 *
 * [0 1 /dev/mapper/local_device \	# local device being replicated
 * nolog 0]{1..N}			# no dirty log with local devices
 */
#define	MIN_DEV_ARGS	5
static int
device_ctr(enum ctr_call_type call_type, struct dm_target *ti,
	   struct replog_c *replog_c,
	   const char *replicator_path, unsigned dev_nr,
	   unsigned argc, char **argv, unsigned *args_used)
{
	int dev_params, dirtylog_params, params, r, slink_nr;
	struct dm_repl_slink *slink;	/* Site link handle. */
	struct slink_c *slink_c;	/* Site link context. */
	struct device_c *dc;		/* Replication device context. */

	SHOW_ARGV;

	if (argc < MIN_DEV_ARGS) {
		ti_or_dmerr(call_type, ti, "Not enough device arguments");
		return -EINVAL;
	}

	/* Get slink number. */
	params = 0;
	if (unlikely(sscanf(argv[params], "%d", &slink_nr) != 1 ||
		     slink_nr < 0)) {
		ti_or_dmerr(call_type, ti,
			    "Invalid site link number argument");
		return -EINVAL;
	}

	/* Get #dev_params. */
	params++;
	if (unlikely(sscanf(argv[params], "%d", &dev_params) != 1 ||
		     dev_params < 0 ||
		     dev_params  + 4 > argc)) {
		ti_or_dmerr(call_type, ti,
			    "Invalid device parameter number argument");
		return -EINVAL;
	}

	/* Get #dirtylog_params. */
	params += dev_params + 2;
	if (unlikely(sscanf(argv[params], "%d", &dirtylog_params) != 1 ||
		     dirtylog_params < 0 ||
		     params + dirtylog_params + 1 > argc)) {
		ti_or_dmerr(call_type, ti,
			    "Invalid dirtylog parameter number argument");
		return -EINVAL;
	}

	/* Check that all parameters are sane. */
	params = dev_params + dirtylog_params + 3;
	if (params > argc) {
		ti_or_dmerr(call_type, ti,
			    "Invalid device/dirtylog argument count");
		return -EINVAL;
	}

	/* Get SLINK handle. */
	mutex_lock(&replog_c_list_mutex);
	slink_c = slink_c_get_by_number(replog_c, slink_nr);
	mutex_unlock(&replog_c_list_mutex);

	if (unlikely(IS_ERR(slink_c))) {
		ti_or_dmerr(call_type, ti, "Cannot find site link context");
		return -ENOENT;
	}

	slink = slink_c->slink;
	_BUG_ON_PTR(slink);

	/* Allocate replication context for new device. */
	dc = kzalloc(sizeof(*dc), GFP_KERNEL);
	if (unlikely(!dc)) {
		ti_or_dmerr(call_type, ti, "Cannot allocate device context");
		BUG_ON(slink_c_put(slink_c));
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&dc->list);
	dc->slink_c = slink_c;
	dc->ti = ti;

	/*
	 * Get reference on replicator control device.
	 *
	 * Dummy start/size sufficient here.
	 */
	r = dm_get_device(ti, replicator_path, 
			  FMODE_WRITE, &dc->replicator_dev);
	if (unlikely(r < 0)) {
		ti_or_dmerr(call_type, ti,
			    "Can't access replicator control device");
		goto err_slink_put;
	}

	/* Add device to slink. */
	/*
	 * ti->split_io for all local devices must be set
	 * to the unique region_size of the remote devices.
	 */
	r = slink->ops->dev_add(slink, dev_nr, ti, params, argv + 1);
	if (unlikely(r < 0)) {
		ti_or_dmerr(call_type, ti, r == -EEXIST ?
			"device already in use on site link" :
			"Failed to add device to site link");
		goto err_device_put;
	}

	dc->number = r;

	/* Only set bdi properties on local devices. */
	if (!slink_nr) {
		/* Preset, will be set to region size in the slink code. */
		ti->split_io = DM_REPL_MIN_SPLIT_IO;

		/*
		 * Init ti reference on slink0 devices only,
		 * because they only have a local mapping!
		 */
		ti->private = dc;
		dc_set_bdi(dc);
	}

	/* Add rc to slink_c list. */
	mutex_lock(&replog_c_list_mutex);
	list_add_tail(&dc->list, &slink_c->lists.dc);
	mutex_unlock(&replog_c_list_mutex);

	*args_used = dev_params + dirtylog_params + 4;
	DMDEBUG("%s added device=%d to site link=%u", __func__,
		r, slink->ops->slink_number(slink));
	return 0;

err_device_put:
	dm_put_device(ti, dc->replicator_dev);
err_slink_put:
	BUG_ON(slink_c_put(slink_c));
	kfree(dc);
	return r;
}

/*
 * Replication device "replicator-dev" constructor method.
 *
 * <start> <length> replicator-dev
 *         <replicator_device> <dev_nr>		\
 *         [<slink_nr> <#dev_params> <dev_params>
 *          <dlog_type> <#dlog_params> <dlog_params>]{1..N}
 *
 * <replicator_device> = device previously constructed via "replication" target
 * <dev_nr>	    = An integer that is used to 'tag' write requests as
 *		      belonging to a particular set of devices - specifically,
 *		      the devices that follow this argument (i.e. the site
 *		      link devices).
 * <slink_nr>	    = This number identifies the site/location where the next
 *		      device to be specified comes from.  It is exactly the
 *		      same number used to identify the site/location (and its
 *		      policies) in the "replicator" target.  Interestingly,
 *		      while one might normally expect a "dev_type" argument
 *		      here, it can be deduced from the site link number and
 *		      the 'slink_type' given in the "replication" target.
 * <#dev_params>    = '1'  (The number of allowed parameters actually depends
 *		      on the 'slink_type' given in the "replication" target.
 *		      Since our only option there is "blockdev", the only
 *		      allowable number here is currently '1'.)
 * <dev_params>	    = 'dev_path'  (Again, since "blockdev" is the only
 *		      'slink_type' available, the only allowable argument here
 *		      is the path to the device.)
 * <dlog_type>	    = Not to be confused with the "replicator log", this is
 *		      the type of dirty log associated with this particular
 *		      device.  Dirty logs are used for synchronization, during
 *		      initialization or fall behind conditions, to bring devices
 *		      into a coherent state with its peers - analogous to
 *		      rebuilding a RAID1 (mirror) device.  Available dirty
 *		      log types include: 'nolog', 'core', and 'disk'
 * <#dlog_params>   = The number of arguments required for a particular log
 *		      type - 'nolog' = 0, 'core' = 1/2, 'disk' = 2/3.
 * <dlog_params>    = 'nolog' => ~no arguments~
 *		      'core'  => <region_size> [sync | nosync]
 *		      'disk'  => <dlog_dev_path> <region_size> [sync | nosync]
 *	<region_size>   = This sets the granularity at which the dirty log
 *			  tracks what areas of the device is in-sync.
 *	[sync | nosync] = Optionally specify whether the sync should be forced
 *			  or avoided initially.
 */
#define LOG_ARGS 2
#define DEV_MIN_ARGS 5
static int
_replicator_dev_ctr(enum ctr_call_type call_type, struct dm_target *ti,
		    unsigned argc, char **argv)
{
	int args_used, r, tmp;
	unsigned dev_nr;
	char *replicator_path = argv[0];
	struct dm_dev *ctrl_dev;
	struct replog_c *replog_c;

	SHOW_ARGV;

	if (argc < LOG_ARGS + DEV_MIN_ARGS)
		goto err_args;

	/*
	 * Get reference on replicator control device.
	 */
	r = dm_get_device(ti, replicator_path, FMODE_WRITE, &ctrl_dev);
	if (unlikely(r < 0)) {
		ti_or_dmerr(CTR_CALL, ti,
			    "Can't access replicator control device");
		return r;
	}

	if (sscanf(argv[1], "%d", &tmp) != 1 ||
	    tmp < 0) {
		dm_put_device(ti, ctrl_dev);
		ti_or_dmerr(call_type, ti, "Invalid device number argument");
		return -EINVAL;
	}

	dev_nr = tmp;

	/* Find precreated replog context by device, taking out a reference. */
	mutex_lock(&replog_c_list_mutex);
	replog_c = replog_c_get_by_dev(ctrl_dev->bdev->bd_dev);
	mutex_unlock(&replog_c_list_mutex);

	if (unlikely(IS_ERR(replog_c))) {
		dm_put_device(ti, ctrl_dev);
		ti_or_dmerr(call_type, ti, "Failed to find replication log");
		return PTR_ERR(replog_c);
	}

	_BUG_ON_PTR(replog_c->replog);
	argc -= LOG_ARGS;
	argv += LOG_ARGS;

	/*
	 * Iterate all slinks/rds if multiple device/dirty
	 * log tuples present on mapping table line.
	 */
	while (argc >= DEV_MIN_ARGS) {
		/* Create slink+device context. */
		r = device_ctr(call_type, ti, replog_c, replicator_path,
			       dev_nr, argc, argv, &args_used);
		if (unlikely(r))
			goto device_ctr_err;

		BUG_ON(args_used > argc);
		argc -= args_used;
		argv += args_used;
	}

	/* All arguments consumed? */
	if (argc) {
		r = -EINVAL;
		goto invalid_args;
	}

	/* Drop initially taken replog reference. */
	BUG_ON(replog_c_put(replog_c));
	dm_put_device(ti, ctrl_dev);
	return 0;

invalid_args:
	ti_or_dmerr(call_type, ti, "Invalid device arguments");
device_ctr_err:
	/* Drop the initially taken replog reference. */
	BUG_ON(replog_c_put(replog_c));
	dm_put_device(ti, ctrl_dev);

	/* If we get an error in ctr -> tear down. */
	if (call_type == CTR_CALL)
		replicator_dev_dtr(ti);

	return r;

err_args:
	ti_or_dmerr(call_type, ti, "Not enough device arguments");
	return -EINVAL;
}
//
/* Constructor method. */
static int
replicator_dev_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	return _replicator_dev_ctr(CTR_CALL, ti, argc, argv);
}

/* Device flush method. */
static void
replicator_dev_flush(struct dm_target *ti)
{
	struct device_c *dc = ti->private;
	struct dm_repl_log *replog;

	_BUG_ON_PTR(dc);
	_BUG_ON_PTR(dc->slink_c);
	_BUG_ON_PTR(dc->slink_c->replog_c);
	replog = dc->slink_c->replog_c->replog;
	_BUG_ON_PTR(replog);
	BUG_ON(!replog->ops->flush);
	replog->ops->flush(replog);
}

/* Queues bios to the cache and wakes up worker thread. */
static inline void
queue_bio(struct device_c *dc, struct bio *bio)
{
	struct replog_c *replog_c = dc->slink_c->replog_c;

	atomic_inc(replog_c->io.stats.io + !!(bio_data_dir(bio) == WRITE));

	spin_lock(&replog_c->io.in_lock);
	bio_list_add(&replog_c->io.in, bio);
	replog_c_io_get(replog_c);
	spin_unlock(&replog_c->io.in_lock);

	/* Wakeup worker to deal with bio input list. */
	wake_do_repl(replog_c);
}

/*
 * Map a replicated device io by handling it in the worker
 * thread in order to avoid delays in the fast path.
 */
static int
replicator_dev_map(struct dm_target *ti, struct bio *bio,
		   union map_info *map_context)
{
	map_context->ptr = bio->bi_private;
	bio->bi_sector -= ti->begin;	/* Remap sector to target begin. */
	queue_bio(ti->private, bio);	/* Queue bio to the worker. */
	return DM_MAPIO_SUBMITTED;	/* Handle later. */
}


/* Replication device suspend/resume helper. */
static void replicator_resume(struct dm_target *ti);
enum suspend_resume_type { POSTSUSPEND, RESUME };
static void
_replicator_dev_suspend_resume(struct dm_target *ti,
			       enum suspend_resume_type type)
{
	struct device_c *dc = ti->private;
	struct replog_c *replog_c;
	struct slink_c *slink_c, *n;
	int dev_nr = dc->number, slinks = 0;

	DMDEBUG("%s %s", __func__, type == RESUME ? "resume" : "postsusend");
	_BUG_ON_PTR(dc);
	_BUG_ON_PTR(dc->slink_c);
	replog_c = dc->slink_c->replog_c;
	_BUG_ON_PTR(replog_c);
	BUG_ON(dev_nr < 0);

	/* Suspend/resume device on all slinks. */
	list_for_each_entry_safe(slink_c, n, &replog_c->lists.slink_c,
				 lists.slink_c) {
		int r;
		struct dm_repl_slink *slink = slink_c->slink;

		_BUG_ON_PTR(slink);

		r = type == RESUME ?
			slink->ops->resume(slink, dev_nr) :
			slink->ops->postsuspend(slink, dev_nr);
		if (r < 0)
			DMERR("Error %d %s device=%d on site link %u",
			      r, type == RESUME ?
			      "resuming" : "postsuspending",
			      dev_nr, slink->ops->slink_number(slink));
		else
			slinks++;
	}

	if (type == RESUME && slinks) {
		if (!TestSetReplDevResumeTwice(replog_c))
			replicator_resume(replog_c->ti);

		wake_do_repl(replog_c);
	}
}

/* Replication device post suspend method. */
static void
replicator_dev_postsuspend(struct dm_target *ti)
{
	_replicator_dev_suspend_resume(ti, POSTSUSPEND);
}

/* Replicatin device resume method. */
static void
replicator_dev_resume(struct dm_target *ti)
{
	_replicator_dev_suspend_resume(ti, RESUME);
}

/* Pass endio calls down to the replicator log if requested. */
static int
replicator_dev_endio(struct dm_target *ti, struct bio *bio,
		     int error, union map_info *map_context)
{
	int rr, rs;
	struct device_c *dc = ti->private;
	struct replog_c *replog_c;
	struct dm_repl_log *replog;
	struct dm_repl_slink *slink;

	_BUG_ON_PTR(dc);
	_BUG_ON_PTR(dc->slink_c);
	slink = dc->slink_c->slink;
	replog_c = dc->slink_c->replog_c;
	_BUG_ON_PTR(replog_c);
	replog = dc->slink_c->replog_c->replog;
	_BUG_ON_PTR(replog);

	rr = replog->ops->endio ?
	     replog->ops->endio(replog, bio, error, map_context) : 0;
	rs = slink->ops->endio ?
	     slink->ops->endio(slink, bio, error, map_context) : 0;
	replog_c_io_put(replog_c);
	return rs < 0 ? rs : rr;
}

/*
 * Replication device message method.
 *
 * Arguments:
 * device add/del \
 * 63:4 0 \		# replication log on 63:4 and device number '0'
 * [0 1 /dev/mapper/local_device \	# local device being replicated
 * nolog 0]{1..N}			# no dirty log with local devices
 *
 * start/resume all/device		# Resume whole replicator/
 * 					# a single device
 */
static int
replicator_dev_message(struct dm_target *ti, unsigned argc, char **argv)
{
	int slink_nr;
	struct device_c *dc = ti->private;
	struct replog_c *replog_c;
	struct dm_repl_log *replog;

	SHOW_ARGV;

	_BUG_ON_PTR(dc);
	_BUG_ON_PTR(dc->slink_c);
	replog_c = dc->slink_c->replog_c;
	_BUG_ON_PTR(replog_c);
	replog = dc->slink_c->replog_c->replog;
	_BUG_ON_PTR(replog);

	/* Check minimum arguments. */
	if (unlikely(argc < 1))
		goto err_args;

	/* Add/delete a device to/from a site link. */
	if (str_listed(argv[0], "device", NULL)) {
		if (argc < 2)
			goto err_args;

		/* We've got the target index of an SLINK0 device here. */
		if (str_listed(argv[1], "add", NULL))
			return _replicator_dev_ctr(MESSAGE_CALL, ti,
						   argc - 2, argv + 2);
		else if (str_listed(argv[1], "del", NULL)) {
			if (argc < 3)
				goto err_args;

			if (sscanf(argv[2], "%d", &slink_nr) != 1 ||
			    slink_nr < 1)
				DM_EINVAL("invalid site link number "
					  "argument; must be > 0");

			return _replicator_dev_dtr(ti, slink_nr);
		} else
			DM_EINVAL("invalid device command argument");

	/* Start replication on single device on all slinks. */
	} else if (str_listed(argv[0], "start", "resume", NULL))
		replicator_dev_resume(ti);

	/* Stop replication for single device on all slinks. */
	else if (str_listed(argv[0], "stop", "suspend", "postsuspend", NULL))
		replicator_dev_postsuspend(ti);
	else
		DM_EINVAL("invalid message command");

	return 0;

err_args:
	DM_EINVAL("too few message arguments");
}

/* Replication device status output method. */
static int
replicator_dev_status(struct dm_target *ti, status_type_t type,
		      char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	static char buffer[2048];
	struct device_c *dc = ti->private;
	struct replog_c *replog_c;
	struct dm_repl_slink *slink;

	mutex_lock(&replog_c_list_mutex);
	_BUG_ON_PTR(dc);
	_BUG_ON_PTR(dc->slink_c);
	slink = dc->slink_c->slink;
	_BUG_ON_PTR(slink);
	replog_c = dc->slink_c->replog_c;
	_BUG_ON_PTR(replog_c);

	DMEMIT("%s %d ", format_dev_t(buffer, replog_c->dev), dc->number);
	mutex_unlock(&replog_c_list_mutex);
	slink->ops->status(slink, dc->number, type, buffer, sizeof(buffer));
	DMEMIT("%s", buffer);
	return 0;
}

/* Replicator device interface. */
static struct target_type replicator_dev_target = {
	.name = "replicator-dev",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = replicator_dev_ctr,
	.dtr = replicator_dev_dtr,
	.flush = replicator_dev_flush,
	.map = replicator_dev_map,
	.postsuspend = replicator_dev_postsuspend,
	.resume = replicator_dev_resume,
	.end_io = replicator_dev_endio,
	.message = replicator_dev_message,
	.status = replicator_dev_status,
};


/*
 * Replication log destructor.
 */
static void
replicator_dtr(struct dm_target *ti)
{
	int r, slink_nr;
	struct replog_c *replog_c = ti->private;
	struct dm_repl_log *replog;
	struct slink_c *slink_c, *n;
	struct dm_repl_slink *slink;

	_BUG_ON_PTR(replog_c);
	replog = replog_c->replog;
	_BUG_ON_PTR(replog);

	/* Check if any devices still exist. */
	if (!list_empty(&replog_c->lists.slink_c) &&
	    !list_empty(&(list_first_entry(&replog_c->lists.slink_c,
					   struct slink_c,
					   lists.slink_c)->lists.dc))) {
		DMERR("Destruction of replication log with devices rejected.");
		return;
	}

	/* Pull out replog_c to process destruction cleanly. */
	mutex_lock(&replog_c_list_mutex);
	list_del_init(&replog_c->lists.replog_c);
	mutex_unlock(&replog_c_list_mutex);

	/* Put all replog's slink contexts. */
	list_for_each_entry_safe(slink_c, n, &replog_c->lists.slink_c,
				 lists.slink_c) {
		list_del_init(&slink_c->lists.slink_c);
		slink = slink_c->slink;
		_BUG_ON_PTR(slink);
		slink_nr = slink->ops->slink_number(slink);
		r = replog->ops->slink_del(replog, slink);
		BUG_ON(r < 0);
		slink_destroy(slink);
		BUG_ON(replog_c_put(replog_c));
		BUG_ON(!slink_c_put(slink_c));
	}

	/* Drop work queue. */
	destroy_workqueue(replog_c->io.wq);

	/* Drop reference on replog. */
	repl_log_dtr(replog_c->replog, replog_c->ti);

	BUG_ON(!replog_c_put(replog_c));
}

/*
 * Replication constructor helpers.
 */
/* Create a site link tying it to the replication log. */
/*
 * E.g.: "local 4 1 async ios 10000"
 */
#define	MIN_SLINK_ARGS	3
static int
_replicator_slink_ctr(enum ctr_call_type call_type, struct dm_target *ti,
		      struct replog_c *replog_c,
		      unsigned argc, char **argv, unsigned *args_used)
{
	int first_slink, slink_nr, slink_params;
	struct dm_repl_slink *slink;	/* Site link handle. */
	struct slink_c *slink_c;	/* Site link context. */

	SHOW_ARGV;

	if (argc < MIN_SLINK_ARGS)
		return -EINVAL;

	/* Get #slink_params. */
	if (unlikely(sscanf(argv[1], "%d", &slink_params) != 1 ||
		     slink_params < 0 ||
		     slink_params + 2 > argc)) {
		ti_or_dmerr(call_type, ti,
			   "Invalid site link parameter number argument");
		return -EINVAL;
	}

	/* Get slink #. */
	if (unlikely(sscanf(argv[2], "%d", &slink_nr) != 1 ||
		     slink_nr < 0)) {
		ti_or_dmerr(call_type, ti,
			   "Invalid site link number argument");
		return -EINVAL;
	}

	/* Check first slink is slink 0. */
	mutex_lock(&replog_c_list_mutex);
	first_slink = !list_first_entry(&replog_c->lists.slink_c,
					struct slink_c, lists.slink_c);
	if (first_slink && slink_nr) {
		mutex_unlock(&replog_c_list_mutex);
		ti_or_dmerr(call_type, ti, "First site link must be 0");
		return -EINVAL;
	}

	slink_c = slink_c_get_by_number(replog_c, slink_nr);
	mutex_unlock(&replog_c_list_mutex);

	if (!IS_ERR(slink_c)) {
		ti_or_dmerr(call_type, ti, "slink already existing");
		BUG_ON(slink_c_put(slink_c));
		return -EPERM;
	}

	/* Get SLINK handle. */
	slink = repl_slink_ctr(argv[0], replog_c->replog,
			       slink_params + 1, argv + 1);
	if (unlikely(IS_ERR(slink))) {
		ti_or_dmerr(call_type, ti, "Cannot create site link context");
		return PTR_ERR(slink);
	}

	slink_c = slink_c_create(replog_c, slink);
	if (unlikely(IS_ERR(slink_c))) {
		ti_or_dmerr(call_type, ti, "Cannot allocate site link context");
		slink_destroy(slink);
		return PTR_ERR(slink_c);
	}

	*args_used = slink_params + 2;
	DMDEBUG("%s added site link=%d", __func__, slink_nr);
	return 0;
}

/*
 * Construct a replicator mapping to log writes of one or more local mapped
 * devices in a local replicator log (REPLOG) in order to replicate them to
 * one or multiple site links (SLINKs) while ensuring write order fidelity.
 *
 *******************************
 *
 * "replicator" constructor table:
 *
 * <start> <length> replicator \
 *	<replog_type> <#replog_params> <replog_params> \
 *	[<slink_type_0> <#slink_params_0> <slink_params_0>]{1..N}
 *
 * <replog_type>    = "ringbuffer" is currently the only available type
 * <#replog_params> = # of args intended for the replog (2 or 4)
 * <replog_params>  = <dev_path> <dev_start> [auto/create/open <size>]
 *	<dev_path>  = device path of replication log (REPLOG) backing store
 *	<dev_start> = offset to REPLOG header
 *	create	    = The replication log will be initialized if not active
 *		      and sized to "size".  (If already active, the create
 *		      will fail.)  Size is always in sectors.
 *	open	    = The replication log must be initialized and valid or
 *		      the constructor will fail.
 *	auto        = If a valid replication log header is found on the
 *		      replication device, this will behave like 'open'.
 *		      Otherwise, this option behaves like 'create'.
 *
 * <slink_type>    = "blockdev" is currently the only available type
 * <#slink_params> = 1/2/4
 * <slink_params>  = <slink_nr> [<slink_policy> [<fall_behind> <N>]]
 *	<slink_nr>     = This is a unique number that is used to identify a
 *			 particular site/location.  '0' is always used to
 *			 identify the local site, while increasing integers
 *			 are used to identify remote sites.
 *	<slink_policy> = The policy can be either 'sync' or 'async'.
 *			 'sync' means write requests will not return until
 *			 the data is on the storage device.  'async' allows
 *			 a device to "fall behind"; that is, outstanding
 *			 write requests are waiting in the replication log
 *			 to be processed for this site, but it is not delaying
 *			 the writes of other sites.
 *	<fall_behind>  = This field is used to specify how far the user is
 *			 willing to allow write requests to this specific site
 *			 to "fall behind" in processing before switching to
 *			 a 'sync' policy.  This "fall behind" threshhold can
 *			 be specified in three ways: ios, size, or timeout.
 *			 'ios' is the number of pending I/Os allowed (e.g.
 *			 "ios 10000").  'size' is the amount of pending data
 *			 allowed (e.g. "size 200m").  Size labels include:
 *			 s (sectors), k, m, g, t, p, and e.  'timeout' is
 *			 the amount of time allowed for writes to be
 *			 outstanding.  Time labels include: s, m, h, and d.
 */
#define	MIN_CONTROL_ARGS	3
static int
replicator_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int args_used = 0, params, r;
	struct dm_dev *backing_dev;
	struct dm_repl_log *replog;	/* Replicator log handle. */
	struct replog_c *replog_c;	/* Replication log context. */

	SHOW_ARGV;

	if (unlikely(argc < MIN_CONTROL_ARGS)) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	/* Get # of replog params. */
	if (unlikely(sscanf(argv[1], "%d", &params) != 1 ||
		     params < 2 ||
		     params + 3 > argc)) {
		ti->error = "Invalid replicator log parameter number";
		return -EINVAL;
	}

	/* Check for site link 0 parameter count. */
	if (params + 4 > argc) {
		ti->error = "Invalid replicator site link parameter number";
		return -EINVAL;
	}

	/*
	 * Get reference on replicator control device.
	 *
	 * Dummy start/size sufficient here.
	 */
	r = dm_get_device(ti, argv[2], FMODE_WRITE, &backing_dev);
	if (unlikely(r < 0)) {
		ti->error = "Can't access replicator control device";
		return r;
	}


	/* Lookup replog_c by dev_t. */
	mutex_lock(&replog_c_list_mutex);
	replog_c = replog_c_get_by_dev(backing_dev->bdev->bd_dev);
	mutex_unlock(&replog_c_list_mutex);

	if (unlikely(!IS_ERR(replog_c))) {
		BUG_ON(replog_c_put(replog_c));
		dm_put_device(ti, backing_dev);
		ti->error = "Recreating replication log prohibited";
		return -EPERM;
	}

	/* Get a reference on the replication log. */
	replog = repl_log_ctr(argv[0], ti, params, argv + 1);
	dm_put_device(ti, backing_dev);
	if (unlikely(IS_ERR(replog))) {
		ti->error = "Cannot create replication log context";
		return PTR_ERR(replog);
	}

	_BUG_ON_PTR(replog->ops->postsuspend);
	_BUG_ON_PTR(replog->ops->resume);

	/* Create global replication control context. */
	replog_c = replog_c_create(ti, replog);
	if (unlikely(IS_ERR(replog_c))) {
		ti->error = "Cannot allocate replication device context";
		return PTR_ERR(replog_c);
	} else
		ti->private = replog_c;

	/* Work any slink parameter tupels. */
	params += 2;
	BUG_ON(argc < params);
	argc -= params;
	argv += params;
	r = 0;

	while (argc > 0) {
		r = _replicator_slink_ctr(CTR_CALL, ti, replog_c,
					  argc, argv, &args_used);
		if (r) {
			/* Free all resources in case of error. */
			replicator_dtr(ti);
			break;
		}

		/* Take per site link reference out. */
		replog_c_get(replog_c);

		BUG_ON(argc < args_used);
		argc -= args_used;
		argv += args_used;
	}

	return r;
}

/*
 * Replication log map function.
 *
 * No io to replication log device allowed: ignore it
 * by returning zeroes on read and ignoring writes silently.
 */
static int
replicator_map(struct dm_target *ti, struct bio *bio,
	       union map_info *map_context)
{
	/* Readahead of null bytes only wastes buffer cache. */
	if (bio_rw(bio) == READA)
		return -EIO;
	else if (bio_rw(bio) == READ)
		zero_fill_bio(bio);

	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED; /* Accepted bio, don't make new request. */
}

/* Replication log suspend/resume helper. */
static void
_replicator_suspend_resume(struct replog_c *replog_c,
			   enum suspend_resume_type type)
{
	struct dm_repl_log *replog;

	DMDEBUG("%s %s", __func__, type == RESUME ? "resume" : "postsusend");
	_BUG_ON_PTR(replog_c);
	replog = replog_c->replog;
	_BUG_ON_PTR(replog);

	/* FIXME: device number not utilized yet. */
	switch (type) {
	case POSTSUSPEND:
		ClearReplBlocked(replog_c);
		flush_workqueue(replog_c->io.wq);
		wait_event(replog_c->io.waiters, !ReplIoInflight(replog_c));
		replog->ops->postsuspend(replog, -1);
		break;
	case RESUME:
		/* Initially avoid resuming and wait for second call. */
		if (!TestSetReplResumeTwice(replog_c))
			return;

		replog->ops->resume(replog, -1);
		ClearReplBlocked(replog_c);
		wake_do_repl(replog_c);
		break;
	default:
		BUG();
	}
}


/* Suspend/Resume all. */
static void
_replicator_suspend_resume_all(struct replog_c *replog_c,
			       enum suspend_resume_type type)
{
	struct device_c *dc;
	struct slink_c *slink_c0;

	_BUG_ON_PTR(replog_c);

	/* First entry on replog_c slink_c list is slink0. */
	slink_c0 = list_first_entry(&replog_c->lists.slink_c,
				    struct slink_c, lists.slink_c);
	_BUG_ON_PTR(slink_c0);

	/* Walk all slink device_c dc and resume slinks. */
	if (type == RESUME)
		list_for_each_entry(dc, &slink_c0->lists.dc, list)
			_replicator_dev_suspend_resume(dc->ti, type);

	_replicator_suspend_resume(replog_c, type);

	/* Walk all slink device_c dc and resume slinks. */
	if (type == POSTSUSPEND)
		list_for_each_entry(dc, &slink_c0->lists.dc, list)
			_replicator_dev_suspend_resume(dc->ti, type);
}

/* Replication control post suspend method. */
static void
replicator_postsuspend(struct dm_target *ti)
{
	_replicator_suspend_resume(ti->private, POSTSUSPEND);
}

/* Replication control resume method. */
static void
replicator_resume(struct dm_target *ti)
{
	_replicator_suspend_resume(ti->private, RESUME);
}

/*
 * Replication log message method.
 *
 * Arguments: start/resume/stop/suspend/statistics/replog
 */
static int
_replicator_slink_message(struct dm_target *ti, int argc, char **argv)
{
	int args_used, tmp;
	int r = -EINVAL;
	unsigned slink_nr;
	struct replog_c *replog_c = ti->private;
	struct dm_repl_slink *slink;
	struct slink_c *slink_c;

	if (sscanf(argv[2], "%d", &tmp) != 1 ||	tmp < 1)
		DM_EINVAL("site link number invalid");

	slink_nr = tmp;

	if (str_listed(argv[1], "add", "del", NULL) &&
	    !slink_nr)
		DM_EPERM("Can't add/delete site link 0 via message");

	mutex_lock(&replog_c_list_mutex);
	slink_c = slink_c_get_by_number(replog_c, slink_nr);
	mutex_unlock(&replog_c_list_mutex);

	if (str_listed(argv[1], "add", NULL)) {
		if (IS_ERR(slink_c)) {
			r = _replicator_slink_ctr(MESSAGE_CALL, ti,
						 replog_c,
						  argc - 2, argv + 2,
						  &args_used);
			if (r)
				DMERR("Error creating site link");

			return r;
		} else {
			BUG_ON(slink_c_put(slink_c));
			DM_EPERM("site link already exists");
		}
	} else if (str_listed(argv[1], "del", NULL)) {
		if (IS_ERR(slink_c))
			DM_EPERM("site link doesn't exist");
		else {
			if (!list_empty(&slink_c->lists.dc)) {
				slink_c_put(slink_c);
				DM_EPERM("site link still has devices");
			}

			slink_c_put(slink_c);
			r = slink_c_put(slink_c);
			if (!r)
				DMERR("site link still exists (race)!");

			return r;
		}
	} else if (str_listed(argv[1], "message", NULL)) {
		slink = slink_c->slink;
		_BUG_ON_PTR(slink);

		if (slink->ops->message)
			return slink->ops->message(slink,
						   argc - 2, argv + 2);
		else
			DM_EPERM("no site link message interface");
	}

	return r;
}

static int
replicator_message(struct dm_target *ti, unsigned argc, char **argv)
{
	int r, resume, suspend;
	struct replog_c *replog_c = ti->private;
	struct dm_repl_log *replog;

	SHOW_ARGV;
	_BUG_ON_PTR(replog_c);
	replog = replog_c->replog;
	_BUG_ON_PTR(replog);

	/* Check minimum arguments. */
	if (unlikely(argc < 1))
		goto err_args;

	resume  = str_listed(argv[0], "resume", "start", NULL);
	/* Hrm, bogus: need a NULL end arg to make it work!? */
	suspend = !resume &&
		  str_listed(argv[0], "suspend", "postsuspend", "stop", NULL);

	/*
	 * Start/resume replicaton log or
	 * start/resume it and all slinks+devices.
	 */
	if (suspend || resume) {
		int all;

		if (!range_ok(argc, 1, 2)) {
			DMERR("Invalid suspend/resume argument count");
			return -EINVAL;
		}

		all = (argc == 2 && str_listed(argv[1], "all", NULL));

		if (resume) {
			if (all)
				_replicator_suspend_resume_all(replog_c,
							       RESUME);
			else
				_replicator_suspend_resume(replog_c,
							   RESUME);

		/* Stop replication log. */
		} else  {
			if (all) {
				_replicator_suspend_resume_all(replog_c,
							       POSTSUSPEND);
			} else
				_replicator_suspend_resume(replog_c,
							   POSTSUSPEND);
		}

	/* Site link message. */
	} else if (str_listed(argv[0], "slink", NULL)) {
		/* E.g.: "local 4 1 async ios 10000" */
		/* Check minimum arguments. */
		if (unlikely(argc < 3))
			goto err_args;

		r = _replicator_slink_message(ti, argc, argv);
		if (r)
			return r;
	/* Statistics. */
	} else if (str_listed(argv[0], "statistics", NULL)) {
		if (argc != 2)
			DM_EINVAL("too many message arguments");

		_BUG_ON_PTR(replog_c);
		if (str_listed(argv[1], "on", NULL))
			SetReplDevelStats(replog_c);
		else if (str_listed(argv[1], "off", NULL))
			ClearReplDevelStats(replog_c);
		else if (str_listed(argv[1], "reset", NULL))
			stats_reset(&replog_c->io.stats);

	/* Replication log message. */
	} else if (str_listed(argv[0], "replog", NULL)) {
		if (argc < 2)
			goto err_args;

		if (replog->ops->message)
			return replog->ops->message(replog, argc - 1, argv + 1);
		else
			DM_EPERM("no replication log message interface");
	} else
		DM_EINVAL("invalid message received");

	return 0;

err_args:
	DM_EINVAL("too few message arguments");
}

/* Replication log status output method. */
static int
replicator_status(struct dm_target *ti, status_type_t type,
		    char *result, unsigned maxlen)
{
	unsigned dev_nr = 0;
	ssize_t sz = 0;
	static char buffer[2048];
	struct replog_c *replog_c = ti->private;
	struct dm_repl_log *replog;
	struct slink_c *slink_c0;
	struct dm_repl_slink *slink;

	mutex_lock(&replog_c_list_mutex);
	_BUG_ON_PTR(replog_c);
	replog = replog_c->replog;
	_BUG_ON_PTR(replog);

	if (type == STATUSTYPE_INFO) {
		if (ReplDevelStats(replog_c)) {
			struct stats *s = &replog_c->io.stats;

			DMEMIT("v=%s r=%u w=%u rs=%u "
			       "ws=%u nc=%u c=%u ",
			       version,
			       atomic_read(s->io), atomic_read(s->io + 1),
			       atomic_read(s->submitted_io),
			       atomic_read(s->submitted_io + 1),
			       atomic_read(s->congested_fn),
			       atomic_read(s->congested_fn + 1));
		}
	}

	mutex_unlock(&replog_c_list_mutex);

	/* Get status from replog. */
	/* FIXME: dev_nr superfluous? */
	replog->ops->status(replog, dev_nr, type, buffer, sizeof(buffer));
	DMEMIT("%s", buffer);

	slink_c0 = list_first_entry(&replog_c->lists.slink_c,
				    struct slink_c, lists.slink_c);
	slink = slink_c0->slink;
	_BUG_ON_PTR(slink);
	/* Get status from slink. */
	*buffer = 0;
	slink->ops->status(slink, -1, type, buffer, sizeof(buffer));
	DMEMIT(" %s", buffer);
	return 0;
}

/* Replicator control interface. */
static struct target_type replicator_target = {
	.name = "replicator",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = replicator_ctr,
	.dtr = replicator_dtr,
	.map = replicator_map,
	.postsuspend = replicator_postsuspend,
	.resume = replicator_resume,
	.message = replicator_message,
	.status = replicator_status,
};

static int __init dm_repl_init(void)
{
	int r;

	INIT_LIST_HEAD(&replog_c_list);
	mutex_init(&replog_c_list_mutex);

	r = dm_register_target(&replicator_target);
	if (r < 0)
		DMERR("failed to register %s %s [%d]",
		      replicator_target.name, version, r);
	else {
		DMINFO("registered %s target %s",
		       replicator_target.name, version);
		r = dm_register_target(&replicator_dev_target);
		if (r < 0) {
			DMERR("Failed to register %s %s [%d]",
			      replicator_dev_target.name, version, r);
			dm_unregister_target(&replicator_target);
		} else
			DMINFO("registered %s target %s",
			       replicator_dev_target.name, version);
	}

	return r;
}

static void __exit
dm_repl_exit(void)
{
	dm_unregister_target(&replicator_dev_target);
	DMINFO("unregistered target %s %s",
	       replicator_dev_target.name, version);
	dm_unregister_target(&replicator_target);
	DMINFO("unregistered target %s %s", replicator_target.name, version);
}

/* Module hooks */
module_init(dm_repl_init);
module_exit(dm_repl_exit);

MODULE_DESCRIPTION(DM_NAME " remote replication target");
MODULE_AUTHOR("Heinz Mauelshagen <heinzm@redhat.com>");
MODULE_LICENSE("GPL");
