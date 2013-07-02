/*
 * Copyright (C) 2009 Red Hat, Inc. All rights reserved.
 *
 * Module Author: Heinz Mauelshagen (heinzm@redhat.com)
 *
 * This file is released under the GPL.
 */

/*
 * API calling convention to create a replication mapping:
 *
 * 1. get a replicator log handle, hence creating a new persistent
 *    log or accessing an existing one
 * 2. get an slink handle, hence creating a new transient
 *    slink or accessing an existing one
 * 2(cont). repeat the previous step for multiple slinks (eg. one for
 *    local and one for remote device access)
 * 3. bind a (remote) device to a particlar slink created in a previous step
 * 3(cont). repeat the device binding for any additional devices on that slink
 * 4. bind the created slink which has device(s) bound to it to the replog
 * 4(cont). repeat the slink binding to the replog for all created slinks
 * 5. call the replog write function for each write IO and the replog hit
 *    function for each read IO..
 *
 * Reverse steps 1-4 to tear a replication mapping down, hence freeing all
 * transient resources allocated to it.
 */

#ifndef _DM_REPL_SLINK_IO_H
#define _DM_REPL_SLINK_IO_H

#include "dm.h"
#include "dm-repl.h"
#include "dm-registry.h"

#include <linux/dm-io.h>

/* Handle to access a site link. */
struct dm_repl_slink {
	struct dm_repl_slink_type *ops;
	void *context;	/* Private slink (callee) context. */
	void *caller;	/* Caller context to (optionally) tie to slink. */
};

/*
 * Start copy function parameters.
 */
/* Copy device address union content type. */
enum dm_repl_slink_dev_type {
	DM_REPL_SLINK_BLOCK_DEVICE,	/* Copying from/to block_device. */
	DM_REPL_SLINK_DEV_NUMBER,	/* Copying from/to device number. */
};

/* Copy device address. */
struct dm_repl_slink_copy_addr {
	/* Union content type. */
	enum dm_repl_slink_dev_type type;

	/* Either address is block_device or slink/device # pair. */
	union {
		struct block_device *bdev;
		struct {
			unsigned slink;
			unsigned dev;
		} number;
	} dev;

	/* Sector offset on device to copy to/from. */
	sector_t sector;
};

/* Copy notification callback parameters. */
struct dm_repl_slink_notify_ctx {
	dm_repl_notify_fn fn;
	void *context;
};

/* Copy function structure to pass in from caller. */
struct dm_repl_slink_copy {
	struct dm_repl_slink_copy_addr src; /* Source address of copy. */
	struct dm_repl_slink_copy_addr dst; /* Destination address of copy. */
	unsigned size;			    /* Size of copy [bytes]. */

	/* Notification callback for data transfered to (remote) RAM. */
	struct dm_repl_slink_notify_ctx ram;
	/* Notification callback for data transfered to (remote) disk. */
	struct dm_repl_slink_notify_ctx disk;
};
/*
 * End copy function parameters.
 */

/* SLINK policies */
enum dm_repl_slink_policy_type {
	DM_REPL_SLINK_ASYNC,
	DM_REPL_SLINK_SYNC,
	DM_REPL_SLINK_STALL,
};

/* SLINK states */
enum dm_repl_slink_state_type {
	DM_REPL_SLINK_DOWN,
	DM_REPL_SLINK_READ_ERROR,
	DM_REPL_SLINK_WRITE_ERROR,
};

/* SLINK fallbehind information. */
/* Definition of fall behind values. */
enum dm_repl_slink_fallbehind_type {
	DM_REPL_SLINK_FB_IOS,		/* Number of IOs. */
	DM_REPL_SLINK_FB_SIZE,		/* In sectors unless unit. */
	DM_REPL_SLINK_FB_TIMEOUT,	/* In ms unless unit. */
};
struct dm_repl_slink_fallbehind {
	enum dm_repl_slink_fallbehind_type type;
	sector_t value;
	sector_t multiplier;
	char unit;
};

struct dm_repl_log;

/* SLINK handler interface type. */
struct dm_repl_slink_type {
	/* Must be first to allow for registry abstraction! */
	struct dm_registry_type type;

	/* Construct/destruct a site link. */
	int (*ctr)(struct dm_repl_slink *, struct dm_repl_log *,
		   unsigned argc, char **argv);
	void (*dtr)(struct dm_repl_slink *);

	/*
	 * There are times when we want the slink to be quiet.
	 * Ie. no checks will run on slinks and no initial
	 * resynchronization will be performed.
	 */
	int (*postsuspend)(struct dm_repl_slink *slink, int dev_number);
	int (*resume)(struct dm_repl_slink *slink, int dev_number);

	/* Add a device to a site link. */
	int (*dev_add)(struct dm_repl_slink *, int dev_number,
		       struct dm_target *ti, unsigned argc, char **argv);

	/* Delete a device from a site link. */
	int (*dev_del)(struct dm_repl_slink *, int dev_number);

	/*
	 * Initiate data copy across a site link.
	 *
	 * This function may be used to copy a buffer entry *or*
	 * for resynchronizing regions initially or when an SLINK
	 * has fallen back to dirty log (bitmap) mode.
	 *
	 * The dm_repl_slink_copy can be allocated on the stack,
	 * because copies of its members are taken before the function returns.
	 *
	 * The function will call 2 callbacks, one to report data in (remote)
	 * RAM and another one to report data on (remote) disk
	 * (see dm_repl_slink_copy structure for details).
	 *
	 * Tag is a unique tag to identify a data set.
	 *
	 *
	 * The return codes are defined as follows:
	 *
	 * o -EAGAIN in case of prohibiting I/O because
	 *    of device inaccessibility/suspension
	 *    or device I/O errors
	 *    (i.e. link temporarilly down) ->
	 *    caller is allowed to retry the I/O later once
	 *    he'll have received a callback.
	 *
	 * o -EACCES in case a region is being resynchronized
	 *    and the source region is being read to copy data
	 *    accross to the same region of the replica (RD) ->
	 *    caller is allowed to retry the I/O later once
	 *    he'll have received a callback.
	 *
	 * o -ENODEV in case a device is not configured
	 *    caller must drop the I/O to the device/slink pair.
	 *
	 * o -EPERM in case a region is out of sync ->
	 *    caller must drop the I/O to the device/slink pair.
	 */
	int (*copy)(struct dm_repl_slink *, struct dm_repl_slink_copy *,
		    unsigned long long tag);

	/* Submit bio to underlying transport. */
	int (*io)(struct dm_repl_slink *, struct bio *,
		  unsigned long long tag);

	/* Endio function to call from dm_repl core on bio endio processing. */
	int (*endio) (struct dm_repl_slink *, struct bio *bio, int error,
		      union map_info *map_context);

	/* Unplug request queues on all devices on slink. */
	int (*unplug)(struct dm_repl_slink *);

	/* Set global recovery notification function and context- */
	void (*recover_notify_fn_set)(struct dm_repl_slink *,
				      dm_repl_notify_fn, void *context);

	/* Set/clear sync status of sector. */
	int (*set_sync)(struct dm_repl_slink *, int dev_number,
			sector_t sector, int in_sync);

	/* Flush any dirty logs on slink. */
	int (*flush_sync)(struct dm_repl_slink *);

	/* Trigger resynchronization of devices on slink. */
	int (*resync)(struct dm_repl_slink *slink, int resync);

	/* Return > 0 if region is in sync on all slinks. */
	int (*in_sync)(struct dm_repl_slink *slink, int dev_number,
		       sector_t region);

	/* Site link policies. */
	enum dm_repl_slink_policy_type (*policy)(struct dm_repl_slink *);

	/* Site link state. */
	enum dm_repl_slink_state_type (*state)(struct dm_repl_slink *);

	/* Return reference to fallbehind information. */
	struct dm_repl_slink_fallbehind *(*fallbehind)(struct dm_repl_slink *);

	/* Return device number for block_device on slink if any. */
	int (*dev_number)(struct dm_repl_slink *, struct block_device *);

	/* Return # of the SLINK. */
	int (*slink_number)(struct dm_repl_slink *);

	/* Return SLINK by number. */
	struct dm_repl_slink *(*slink)(struct dm_repl_log *,
				       unsigned slink_number);

	/* SLINK status requests. */
	int (*status)(struct dm_repl_slink *, int dev_number,
		      status_type_t, char *result, unsigned int maxlen);

	/* SLINK messages (eg. change policy). */
	int (*message)(struct dm_repl_slink *, unsigned argc, char **argv);
};

/* Policy and state access inlines. */
/* Policy synchronous. */
static inline int
slink_policy_synchronous(enum dm_repl_slink_policy_type policy)
{
	return test_bit(DM_REPL_SLINK_SYNC, (unsigned long *) &policy);
}

/* Slink synchronous. */
static inline int
slink_synchronous(struct dm_repl_slink *slink)
{
	return slink_policy_synchronous(slink->ops->policy(slink));
}

/* Policy asynchronous. */
static inline int
slink_policy_asynchronous(enum dm_repl_slink_policy_type policy)
{
	return test_bit(DM_REPL_SLINK_ASYNC, (unsigned long *) &policy);
}

/* Slink asynchronous. */
static inline int
slink_asynchronous(struct dm_repl_slink *slink)
{
	return slink_policy_asynchronous(slink->ops->policy(slink));
}

/* Policy stall. */
static inline int
slink_policy_stall(enum dm_repl_slink_policy_type policy)
{
	return test_bit(DM_REPL_SLINK_STALL, (unsigned long *) &policy);
}

/* Slink stall. */
static inline int
slink_stall(struct dm_repl_slink *slink)
{
	return slink_policy_stall(slink->ops->policy(slink));
}

/* State down.*/
static inline int
slink_state_down(enum dm_repl_slink_state_type state)
{
	return test_bit(DM_REPL_SLINK_DOWN, (unsigned long *) &state);
}

/* Slink down.*/
static inline int
slink_down(struct dm_repl_slink *slink)
{
	return slink_state_down(slink->ops->state(slink));
}

/* Setup of site links. */
/* Create/destroy a transient replicator site link */
struct dm_repl_slink *
dm_repl_slink_get(char *name, struct dm_repl_log *,
		  unsigned argc, char **argv);
void dm_repl_slink_put(struct dm_repl_slink *);

/* init/exit functions. */
int dm_repl_slink_init(void);
void dm_repl_slink_exit(void);

#endif
