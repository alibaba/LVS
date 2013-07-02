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

#ifndef _DM_REPL_H
#define _DM_REPL_H

#include <linux/device-mapper.h>

/* FIXME: factor these macros out to dm.h */
#define	STR_LEN(ptr, str)	ptr, str, strlen(ptr)
#define ARRAY_END(a)    ((a) + ARRAY_SIZE(a))
#define	range_ok(i, min, max)   (i >= min && i <= max)

#define	TI_ERR_RET(str, ret) \
do { \
	ti->error = DM_MSG_PREFIX ": " str; \
	return ret; } \
while (0)
#define	TI_ERR(str)	TI_ERR_RET(str, -EINVAL)

#define	DM_ERR_RET(ret, x...)	do { DMERR(x); return ret; } while (0)
#define	DM_EINVAL(x...)	DM_ERR_RET(-EINVAL, x)
#define	DM_EPERM(x...)	DM_ERR_RET(-EPERM, x)

/*
 * Minimum split_io of target to preset for local devices in repl_ctr().
 * Will be adjusted while constructing (a) remote device(s).
 */
#define	DM_REPL_MIN_SPLIT_IO	BIO_MAX_SECTORS

/* REMOVEME: devel testing. */
#if	0
#define	SHOW_ARGV \
	do { \
		int i; \
\
		DMINFO("%s: called with the following args:", __func__); \
		for (i = 0; i < argc; i++) \
			DMINFO("%d: %s", i, argv[i]); \
	} while (0)
#else
#define	SHOW_ARGV
#endif


/* Factor out to dm-bio-list.h */
static inline void
bio_list_push(struct bio_list *bl, struct bio *bio)
{
	bio->bi_next = bl->head;
	bl->head = bio;

	if (!bl->tail)
		bl->tail = bio;
}

/* REMOVEME: development */
#define	_BUG_ON_PTR(ptr) \
	do { \
		BUG_ON(!ptr); \
		BUG_ON(IS_ERR(ptr)); \
	} while (0)

/* Callback function. */
typedef void
(*dm_repl_notify_fn)(int read_err, int write_err, void *context);

/*
 * Macros to access bitfields in the structures io.flags member.
 * Mixed case naming examples are in the page cache as well.
 */
#define	DM_BITOPS(name, var, flag) \
static inline int \
TestClear ## name(struct var *v) \
{ return test_and_clear_bit(flag, &v->io.flags); } \
static inline int \
TestSet ## name(struct var *v) \
{ return test_and_set_bit(flag, &v->io.flags); } \
static inline void \
Clear ## name(struct var *v) \
{ clear_bit(flag, &v->io.flags); smp_mb(); } \
static inline void \
Set ## name(struct var *v) \
{ set_bit(flag, &v->io.flags); smp_mb(); } \
static inline int \
name(struct var *v) \
{ return test_bit(flag, &v->io.flags); }

/* FIXME: move to dm core. */
/* Search routines for descriptor arrays. */
struct dm_str_descr {
	const int type;
	const char *name;
};

/* Return type for name. */
extern int
dm_descr_type(const struct dm_str_descr *descr, unsigned len, const char *name);
/* Return name for type. */
extern const char *
dm_descr_name(const struct dm_str_descr *descr, unsigned len, const int type);

#endif
