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
 * 5. call the replog io function for each IO.
 *
 * Reverse steps 1-4 to tear a replication mapping down, hence freeing all
 * transient resources allocated to it.
 */

#ifndef _DM_REPL_LOG_H
#define _DM_REPL_LOG_H

#include "dm-repl.h"
#include "dm-registry.h"
#include "dm-repl-slink.h"

/* Handle to access a replicator log. */
struct dm_repl_log {
	struct dm_repl_log_type *ops;
	void *context;
};

/* List of site links hanging off of each replicator log. */
struct dm_repl_log_slink_list {
	rwlock_t lock;
	struct list_head list; /* List of site links hanging of off this log. */
	void *context; /* Caller context. */
};

struct dm_repl_log_type {
	struct dm_registry_type type;

	/* Construct/destruct a replicator log. */
	int (*ctr)(struct dm_repl_log *, struct dm_target *,
		   unsigned argc, char **argv);
	void (*dtr)(struct dm_repl_log *, struct dm_target *);

	/*
	 * There are times when we want the log to be quiet.
	 * Ie. no entries of the log will be copied accross site links.
	 */
	int (*postsuspend)(struct dm_repl_log *log, int dev_number);
	int (*resume)(struct dm_repl_log *log, int dev_number);

	/* Flush the current log contents. This function may block. */
	int (*flush)(struct dm_repl_log *log);

	/*
	 * Read a bio either from a replicator logs backing store
	 * (if supported) or from the replicated device if no buffer entry.
	 * - or-
	 * write a bio to a replicator logs backing store buffer.
	 *
	 * This includes buffer allocation in case of a write and
	 * inititation of copies accross an/multiple site link(s).
	 *
	 * In case of a read with (partial) writes in the buffer,
	 * the replog may postpone the read until the buffer content has
	 * been copied accross the local site link *or* optimize by reading
	 * (parts of) the bio off the buffer.
	 *
	 * Tag us a unique tag identifying a data set.
	 */
	int (*io)(struct dm_repl_log *, struct bio *, unsigned long long tag);

	/* Endio function to call from dm_repl core on bio endio processing. */
	int (*endio) (struct dm_repl_log *, struct bio *bio, int error,
		      union map_info *map_context);

	/* Set global I/O completion notification function and context- */
	void (*io_notify_fn_set)(struct dm_repl_log *,
				 dm_repl_notify_fn, void *context);

	/*
	 * Add (tie) a site link to a replication
	 * log for site link copy processing.
	 */
	int (*slink_add)(struct dm_repl_log *, struct dm_repl_slink *);

	/* Remove (untie) a site link from a replication log. */
	int (*slink_del)(struct dm_repl_log *, struct dm_repl_slink *);

	/*
	 * Return list of site links added to a replication log.
	 *
	 * This method eases slink handler coding to
	 * keep such replication log site link list.
	 */
	struct dm_repl_log_slink_list *(*slinks)(struct dm_repl_log *);

	/* Return maximum number of supported site links. */
	int (*slink_max)(struct dm_repl_log *);

	/* REPLOG messages. */
	int (*message)(struct dm_repl_log *, unsigned argc, char **argv);

	/* Support function for replicator log status requests. */
	int (*status)(struct dm_repl_log *, int dev_number, status_type_t,
		      char *result, unsigned maxlen);
};

#endif /* #ifndef _DM_REPL_LOG_H */
