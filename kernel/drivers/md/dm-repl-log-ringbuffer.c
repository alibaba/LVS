/*
 * Copyright (C) 2009 Red Hat, Inc. All rights reserved.
 *
 * Module Authors: Jeff Moyer (jmoyer@redhat.com)
 *		   Heinz Mauelshagen (heinzm@redhat.com)
 *
 * This file is released under the GPL.
 *
 * "default" device-mapper replication log type implementing a ring buffer
 * for write IOs, which will be copied accross site links to devices.
 *
 * A log like this allows for write coalescing enhancements in order
 * to reduce network traffic at the cost of larger fallbehind windows.
 */

/*
 * Locking:
 * l->io.lock for io (de)queueing / slink manipulation
 * l->lists.lock for copy contexts moved around lists
 *
 * The ringbuffer lock does not need to be held in order to take the io.lock,
 * but if they are both acquired, the ordering must be as indicated above.
 */

#include "dm-repl.h"
#include "dm-registry.h"
#include "dm-repl-log.h"
#include "dm-repl-slink.h"

#include <linux/crc32.h>
#include <linux/dm-io.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h>

static const char version[] = "v0.028";
static struct dm_repl_log_type ringbuffer_type;

static struct mutex list_mutex;

#define	DM_MSG_PREFIX	"dm-repl-log-ringbuffer"
#define	DAEMON		DM_MSG_PREFIX	"d"

/* Maximum number of site links supported. */
#define MAX_DEFAULT_SLINKS 	2048

#define DEFAULT_BIOS	16 /* Default number of max bios -> ring buffer */

#define	LOG_SIZE_MIN	(2 * BIO_MAX_SECTORS)
#define	REGIONS_MAX	32768

/* Later kernels have this macro in bitops.h */
#ifndef for_each_bit
#define for_each_bit(bit, addr, size) \
	for ((bit) = find_first_bit((void *)(addr), (size)); \
	     (bit) < (size); \
	     (bit) = find_next_bit((void *)(addr), (size), (bit) + 1))
#endif

#define	_BUG_ON_SLINK_NR(l, slink_nr) \
	do { \
		BUG_ON(slink_nr < 0); \
	} while (0);

/* Replicator log metadata version. */
struct repl_log_version {
	unsigned major;
	unsigned minor;
	unsigned subminor;
};

/*
 *  Each version of the log code may get a separate source module, so
 *  we store the version information in the .c file.
 */
#define DM_REPL_LOG_MAJOR	0
#define DM_REPL_LOG_MINOR	0
#define DM_REPL_LOG_MICRO	1

#define DM_REPL_LOG_VERSION			\
	{ DM_REPL_LOG_MAJOR,			\
	  DM_REPL_LOG_MINOR,			\
	  DM_REPL_LOG_MICRO, }

static struct version {
	uint16_t	major;
	uint16_t	minor;
	uint16_t	subminor;
} my_version = DM_REPL_LOG_VERSION;

/* 1 */
/* Shall be 16 bytes long */
static const char log_header_magic[] = "dm-replicatorHJM";
#define	MAGIC_LEN	(sizeof(log_header_magic) - 1)
#define	HANDLER_LEN	MAGIC_LEN

/* Header format on disk */
struct log_header_disk {
	uint8_t			magic[MAGIC_LEN];
	uint32_t		crc;
	struct version		version;
	uint64_t		size;
	uint64_t		buffer_header; /* sector of first
						* buffer_header_disk */
	uint8_t			handler_name[HANDLER_LEN];
	/* Free space. */
} __attribute__((__packed__));

/* Macros for bitmap access. */
#define	BITMAP_SIZE(l)	((l)->slink.bitmap_size)
#define	BITMAP_ELEMS(l)	((l)->slink.bitmap_elems)
#define	BITMAP_ELEMS_MAX	32

/* Header format in core (only one of these per log device). */
struct log_header {
	struct repl_log_version version;
	sector_t size;
	sector_t buffer_header;

	/* Bitarray of configured slinks to copy accross and those to I/O to. */
	struct {
		uint64_t slinks[BITMAP_ELEMS_MAX];
		uint64_t ios[BITMAP_ELEMS_MAX];
		uint64_t set_accessible[BITMAP_ELEMS_MAX];
		uint64_t inaccessible[BITMAP_ELEMS_MAX];
	} slink_bits;
};
#define LOG_SLINKS(l) ((void *) (l)->header.log->slink_bits.slinks)
#define LOG_SLINKS_IO(l) ((void *) (l)->header.log->slink_bits.ios)
#define LOG_SLINKS_INACCESSIBLE(l) \
	((void *)(l)->header.log->slink_bits.inaccessible)
#define LOG_SLINKS_SET_ACCESSIBLE(l) \
	((void *)(l)->header.log->slink_bits.set_accessible)

static void
log_header_to_disk(unsigned slinks, void *d_ptr, void *c_ptr)
{
	struct log_header_disk *d = d_ptr;
	struct log_header *c = c_ptr;

	strncpy((char *) d->magic, log_header_magic, MAGIC_LEN);
	strncpy((char *) d->handler_name,
			 ringbuffer_type.type.name, HANDLER_LEN);
	d->version.major = cpu_to_le16(c->version.major);
	d->version.minor = cpu_to_le16(c->version.minor);
	d->version.subminor = cpu_to_le16(c->version.subminor);
	d->size = cpu_to_le64(c->size);
	d->buffer_header = cpu_to_le64(c->buffer_header);
	d->crc = 0;
	d->crc = crc32(~0, d, sizeof(d));
}

static int
log_header_to_core(unsigned slinks, void *c_ptr, void *d_ptr)
{
	int r;
	uint32_t crc;
	struct log_header *c = c_ptr;
	struct log_header_disk *d = d_ptr;

	r = strncmp((char *) d->magic, log_header_magic, MAGIC_LEN);
	if (r)
		return -EINVAL;

	/* Check, if acceptible to this replication log handler. */
	r = strncmp((char *) d->handler_name, ringbuffer_type.type.name,
		    HANDLER_LEN);
	if (r)
		return -EINVAL;

	c->version.major = le16_to_cpu(d->version.major);
	c->version.minor = le16_to_cpu(d->version.minor);
	c->version.subminor = le16_to_cpu(d->version.subminor);
	c->size = le64_to_cpu(d->size);
	c->buffer_header = le64_to_cpu(d->buffer_header);
	crc = d->crc;
	d->crc = 0;
	return (crc == crc32(~0, d, sizeof(d))) ? 0 : -EINVAL;
}

/* 1a */
static const char *buffer_header_magic = "dm-replbufferHJM";

/*
 * meta-data for the ring buffer, one per replog:
 *
 *   start: location on disk
 *   head:  ring buffer head, first data item to be replicated
 *   tail:  points to one after the last data item to be replicated
 *
 * The ring buffer is full of data_header(_disk) entries.
 */
struct buffer_header_disk {
	uint8_t			magic[MAGIC_LEN];
	uint32_t		crc;
	struct buffer_disk {
		uint64_t	start;
		uint64_t	head;
		uint64_t	tail;
	} buffer;

	uint64_t	flags;
	/* Free space. */
} __attribute__((__packed__));

/*
 * In-core format of the buffer_header_disk structure
 *
 * start, head, and tail are as described above for buffer_header_disk.
 *
 * next_avail points to the next available sector for placing a log entry.
 *   It is important to distinguish this from tail, as we can issue I/O to
 *   multiple log entries at a time.
 *
 * end is the end sector of the log device
 *
 * len is the total length of the log device, handy to keep around for maths
 *   free represents the amount of free space in the log. This number
 *   reflects the free space in the log given the current outstanding I/O's.
 *   In other words, it is the distance between next_avail and head.
 */
/*
 *  My guess is that this should be subsumed by the repl_log structure, as
 *  much of the data is copied from there, anyway.  The question is just
 *  how to organize it in a readable and efficient way.
 */
/* Ring state flag(s). */
enum ring_status_type {
	RING_BLOCKED,
	RING_BUFFER_ERROR,
	RING_BUFFER_DATA_ERROR,
	RING_BUFFER_HEADER_ERROR,
	RING_BUFFER_HEAD_ERROR,
	RING_BUFFER_TAIL_ERROR,
	RING_BUFFER_FULL,
	RING_BUFFER_IO_QUEUED,
	RING_SUSPENDED
};

/*
 * Pools types for:
 * o ring buffer entries
 * o data headers.
 * o disk data headers.
 * o slink copy contexts
 */
enum ring_pool_type {
	ENTRY,			/* Ring buffer entries. */
	DATA_HEADER,		/* Ring buffer data headers. */
	DATA_HEADER_DISK,	/* Ring buffer ondisk data headers. */
	COPY_CONTEXT,		/* Context for any single slink copy. */
	NR_RING_POOLS,
};

struct sector_range {
	sector_t start;
	sector_t end;
};

struct ringbuffer {
	sector_t	start;	/* Start sector of the log space on disk. */
	sector_t	head;	/* Sector of the first log entry. */
	sector_t	tail;	/* Sector of the last valid log entry. */

	struct mutex	mutex;	/* Mutex hold on member updates below. */

	/* The following fields are useful to keep track of in-core state. */
	sector_t	next_avail;	/* In-memory tail of the log. */
	sector_t	end;		/* 1st sector past end of log device. */
	sector_t	free;		/* Free space left in the log. */
	sector_t	pending;	/* sectors queued but not allocated */

	struct {
		unsigned long flags;	/* Buffer state flags. */
	} io;

	/* Dirty sectors for slink0. */
	struct sector_hash {
		struct list_head *hash;
		unsigned buckets;
		unsigned mask;
	} busy_sectors;

	/* Waiting for all I/O to be flushed. */
	wait_queue_head_t flushq;
	mempool_t *pools[NR_RING_POOLS];
};

DM_BITOPS(RingBlocked, ringbuffer, RING_BLOCKED)
DM_BITOPS(RingBufferError, ringbuffer, RING_BUFFER_ERROR)
DM_BITOPS(RingBufferDataError, ringbuffer, RING_BUFFER_DATA_ERROR)
DM_BITOPS(RingBufferHeaderError, ringbuffer, RING_BUFFER_HEADER_ERROR)
DM_BITOPS(RingBufferHeadError, ringbuffer, RING_BUFFER_HEAD_ERROR)
DM_BITOPS(RingBufferTailError, ringbuffer, RING_BUFFER_TAIL_ERROR)
DM_BITOPS(RingBufferFull, ringbuffer, RING_BUFFER_FULL)
DM_BITOPS(RingBufferIOQueued, ringbuffer, RING_BUFFER_IO_QUEUED)
DM_BITOPS(RingSuspended, ringbuffer, RING_SUSPENDED)

#define CC_POOL_MIN 4
#define HEADER_POOL_MIN 32
#define ENTRY_POOL_MIN 32

static void
buffer_header_to_disk(unsigned slinks, void *d_ptr, void *c_ptr)
{
	struct buffer_header_disk *d = d_ptr;
	struct ringbuffer *c = c_ptr;

	strncpy((char *) d->magic, buffer_header_magic, MAGIC_LEN);
	d->buffer.start = cpu_to_le64(to_bytes(c->start));
	d->buffer.head = cpu_to_le64(to_bytes(c->head));
	d->buffer.tail = cpu_to_le64(to_bytes(c->tail));
	d->flags = cpu_to_le64(c->io.flags);
	d->crc = 0;
	d->crc = crc32(~0, d, sizeof(d));
}

static int
buffer_header_to_core(unsigned slinks, void *c_ptr, void *d_ptr)
{
	int r;
	uint32_t crc;
	struct ringbuffer *c = c_ptr;
	struct buffer_header_disk *d = d_ptr;

	r = strncmp((char *) d->magic, buffer_header_magic, MAGIC_LEN);
	if (r)
		return -EINVAL;

	c->start = to_sector(le64_to_cpu(d->buffer.start));
	c->head = to_sector(le64_to_cpu(d->buffer.head));
	c->tail = to_sector(le64_to_cpu(d->buffer.tail));
	c->io.flags = le64_to_cpu(d->flags);
	crc = d->crc;
	d->crc = 0;
	return likely(crc == crc32(~0, d, sizeof(d))) ? 0 : -EINVAL;
}

/* 3 */
/* The requirement is to support devices with 4k sectors. */
#define HEADER_SECTORS	to_sector(4096)

static const char *data_header_magic = "dm-replicdataHJM";

/* FIXME: XXX adjust for larger sector size! */
#define	DATA_HEADER_DISK_SIZE	512
enum entry_wrap_type { WRAP_NONE, WRAP_DATA, WRAP_NEXT };
struct data_header_disk {
	uint8_t	 magic[MAGIC_LEN];
	uint32_t crc;
	uint32_t filler;

	struct {
		/* Internal namespace to get rid of major/minor. -HJM */
		uint64_t dev;
		uint64_t offset;
		uint64_t size;
	} region;

	/* Position of header and data on disk in bytes. */
	struct {
		uint64_t header; /* Offset of this header */
		uint64_t data; /* Offset of data (ie. the bio). */
	} pos;

	uint8_t valid; /* FIXME: XXX this needs to be in memory copy, too */
	uint8_t wrap;  /* Above enum entry_wrap_type. */
	uint8_t barrier;/* Be prepared for write barrier support. */

	/*
	 * Free space: fill up to offset 256.
	 */
	uint8_t	filler1[189];

	/* Offset 256! */
	/* Bitmap, bit position set to 0 for uptodate slink */
	uint64_t slink_bits[BITMAP_ELEMS_MAX];

	/* Free space. */
} __attribute__((__packed__));

struct data_header {
	struct list_head list;

	/* Bitmap, bit position set to 0 for uptodate slink. */
	uint64_t slink_bits[BITMAP_ELEMS_MAX];

	/*
	 * Reference count indicating the number of endios
	 * expected while writing the header and bitmap.
	 */
	atomic_t cnt;

	struct data_header_region {
		/* dev, sector, and size are taken from the initial bio. */
		unsigned long dev;
		sector_t sector;
		unsigned size;
	} region;

	/* Position of header and data on disk and size in sectors. */
	struct {
		sector_t header; /* sector of this header on disk */
		sector_t data; /* Offset of data (ie. the bio). */
		unsigned data_sectors; /* Useful for sector calculation. */
	} pos;

	/* Next data or complete entry wraps. */
	enum entry_wrap_type wrap;
};

/* Round size in bytes up to multiples of HEADER_SECTORS. */
enum distance_type { FULL_SECTORS, DATA_SECTORS };
static inline sector_t
_roundup_sectors(unsigned sectors, enum distance_type type)
{
	return HEADER_SECTORS *
		(!!(type == FULL_SECTORS) + dm_div_up(sectors, HEADER_SECTORS));
}

/* Header + data. */
static inline sector_t
roundup_sectors(unsigned sectors)
{
	return _roundup_sectors(sectors, FULL_SECTORS);
}

/* Data only. */
static inline sector_t
roundup_data_sectors(unsigned sectors)
{
	return _roundup_sectors(sectors, DATA_SECTORS);
}

static void
data_header_to_disk(unsigned bitmap_elems, void *d_ptr, void *c_ptr)
{
	unsigned i = bitmap_elems;
	struct data_header_disk *d = d_ptr;
	struct data_header *c = c_ptr;

	BUG_ON(!i);

	strncpy((char *) d->magic, data_header_magic, MAGIC_LEN);
	d->region.dev =  cpu_to_le64(c->region.dev);
	d->region.offset = cpu_to_le64(to_bytes(c->region.sector));
	d->region.size = cpu_to_le64(c->region.size);

	/* Xfer bitmap. */
	while (i--)
		d->slink_bits[i] = cpu_to_le64(c->slink_bits[i]);

	d->valid = 1;
	d->wrap = c->wrap;
	d->pos.header = cpu_to_le64(to_bytes(c->pos.header));
	d->pos.data = cpu_to_le64(to_bytes(c->pos.data));
	d->crc = 0;
	d->crc = crc32(~0, d, sizeof(d));
}

static int
data_header_to_core(unsigned bitmap_elems, void *c_ptr, void *d_ptr)
{
	int r;
	unsigned i = bitmap_elems;
	uint32_t crc;
	struct data_header *c = c_ptr;
	struct data_header_disk *d = d_ptr;

	BUG_ON(!i);

	r = strncmp((char *) d->magic, data_header_magic, MAGIC_LEN);
	if (r)
		return -EINVAL;

	c->region.dev =  le64_to_cpu(d->region.dev);
	c->region.sector = to_sector(le64_to_cpu(d->region.offset));
	c->region.size =  le64_to_cpu(d->region.size);

	/* Xfer bitmap. */
	while (i--)
		c->slink_bits[i] = le64_to_cpu(d->slink_bits[i]);

	c->pos.header = to_sector(le64_to_cpu(d->pos.header));
	c->pos.data = to_sector(le64_to_cpu(d->pos.data));
	c->pos.data_sectors = roundup_data_sectors(to_sector(c->region.size));
	c->wrap = d->wrap;

	if (unlikely(!d->valid) ||
		     !c->region.size)
		return -EINVAL;

	crc = d->crc;
	d->crc = 0;
	return likely(crc == crc32(~0, d, sizeof(d))) ? 0 : -EINVAL;
}

static inline void
slink_set_bit(int bit, uint64_t *ptr)
{
	set_bit(bit, (unsigned long *)ptr);
	smp_mb();
}

static inline void
slink_clear_bit(int bit, uint64_t *ptr)
{
	clear_bit(bit, (unsigned long *)ptr);
	smp_mb();
}

static inline int
slink_test_bit(int bit, uint64_t *ptr)
{
	return test_bit(bit, (unsigned long *)ptr);
}


/* entry list types and access macros. */
enum entry_list_type {
	E_BUSY_HASH,	/* Busys entries hash. */
	E_COPY_CONTEXT,	/* Copyies accross slinks in progress for entry. */
	E_ORDERED,	/* Ordered for advancing the ring buffer head. */
	E_WRITE_OR_COPY,/* Add to l->lists.l[L_ENTRY_RING_WRITE/L_SLINK_COPY] */
	E_NR_LISTS,
};
#define	E_BUSY_HASH_LIST(entry)		(entry->lists.l + E_BUSY_HASH)
#define	E_COPY_CONTEXT_LIST(entry)	(entry->lists.l + E_COPY_CONTEXT)
#define	E_ORDERED_LIST(entry)		(entry->lists.l + E_ORDERED)
#define	E_WRITE_OR_COPY_LIST(entry)	(entry->lists.l + E_WRITE_OR_COPY)

/*
 * Container for the data_header and the associated data pages.
 */
struct ringbuffer_entry {
	struct {
		struct list_head l[E_NR_LISTS];
	} lists;

	struct ringbuffer *ring; /* Back pointer. */

	/* Reference count. */
	atomic_t ref;

	/*
	 * Reference count indicating the number of endios expected
	 * while writing its header and data to the ring buffer log
	 * -or- future use:
	 * how many copies accross site links are active and how many
	 * reads are being sattisfied from the entry.
	 */
	atomic_t endios;

	struct entry_data {
		struct data_header *header;
		struct data_header_disk *disk_header;
		struct {
			unsigned long data;
			unsigned long header;
		} error;
	} data;

	struct {
		struct bio *read;	/* bio to read. */
		struct bio *write;	/* Original bio to write. */
	} bios;

	struct {
		/* Bitmask of slinks the entry has active copies accross. */
		uint64_t ios[BITMAP_ELEMS_MAX];
		/* Bitmask of synchronuous slinks for endio. */
		/* FIXME: drop in favour of slink inquiry of sync state ? */
		uint64_t sync[BITMAP_ELEMS_MAX];
		/* Bitmask of slinks with errors. */
		uint64_t error[BITMAP_ELEMS_MAX];
	} slink_bits;
};
#define ENTRY_SLINKS(l) ((void *) (entry)->data.header->slink_bits)
#define ENTRY_IOS(entry) ((void *) (entry)->slink_bits.ios)
#define ENTRY_SYNC(entry) ((entry)->slink_bits.sync)
#define ENTRY_ERROR(entry) ((entry)->slink_bits.error)

/* FIXME: XXX
 * For now, the copy context has a backpointer to the ring buffer entry.
 * This means that a ring buffer entry has to remain in memory until all
 * of the slink copies have finished.  Heinz, you mentioned that this was
 * not a good idea.  I'm open to suggestions on how better to organize this.
 */
enum error_type { ERR_DISK, ERR_RAM, NR_ERR_TYPES };
struct slink_copy_error {
	int read;
	int write;
};

struct slink_copy_context {
	/*
	 * List first points to the copy context list in the ring buffer
	 * entry.  Then, upon completion it gets moved to the slink endios
	 * list.
	 */
	struct list_head list;
	atomic_t cnt;
	struct ringbuffer_entry *entry;
	struct dm_repl_slink *slink;
	struct slink_copy_error error[NR_ERR_TYPES];
	unsigned long start_jiffies;
};

/* Development statistics. */
struct stats {
	atomic_t io[2];
	atomic_t writes_pending;
	atomic_t hash_elem;

	unsigned copy[2];
	unsigned wrap;
	unsigned hash_insert;
	unsigned hash_insert_max;
	unsigned stall;
};

/* Per site link measure/state. */
enum slink_status_type {
	SS_SYNC,	/* slink fell behind an I/O threshold. */
	SS_TEARDOWN,	/* Flag site link teardown. */
};
struct slink_state {
	unsigned slink_nr;
	struct repl_log *l;

	struct {

		/*
		 * Difference of time (measured in jiffies) between the
		 * first outstanding copy for this slink and the last
		 * outstanding copy.
		 */
		unsigned long head_jiffies;

		/* Number of ios/sectors currently copy() to this slink. */
		struct {
			sector_t sectors;
			uint64_t ios;
		} outstanding;
	} fb;

	struct {
		unsigned long flags; /* slink_state flags._*/

		/* slink+I/O teardown synchronization. */
		wait_queue_head_t waiters;
		atomic_t in_flight;
	} io;
};
DM_BITOPS(SsSync, slink_state, SS_SYNC)
DM_BITOPS(SsTeardown, slink_state, SS_TEARDOWN)

enum open_type { OT_AUTO, OT_OPEN, OT_CREATE };
enum replog_status_type {
	LOG_DEVEL_STATS,	/* Turn on development stats. */
	LOG_INITIALIZED,	/* Log initialization finished. */
	LOG_RESIZE,		/* Log resize requested. */
};

/* repl_log list types and access macros. */
enum replog_list_type {
	L_REPLOG,		/* Linked list of replogs. */
	L_SLINK_COPY,		/* Entries to copy accross slinks. */
	L_SLINK_ENDIO,		/* Entries to endio process. */
	L_ENTRY_RING_WRITE,	/* Entries to write to ring buffer */
	L_ENTRY_ORDERED,	/* Ordered list of entries (write fidelity). */
	L_NR_LISTS,
};
#define	L_REPLOG_LIST(l)		(l->lists.l + L_REPLOG)
#define	L_SLINK_COPY_LIST(l)		(l->lists.l + L_SLINK_COPY)
#define	L_SLINK_ENDIO_LIST(l)		(l->lists.l + L_SLINK_ENDIO)
#define	L_ENTRY_RING_WRITE_LIST(l)	(l->lists.l + L_ENTRY_RING_WRITE)
#define	L_ENTRY_ORDERED_LIST(l)		(l->lists.l + L_ENTRY_ORDERED)

/* The replication log in core. */
struct repl_log {
	struct dm_repl_log *log;

	struct kref ref;	/* Pin count. */

	struct dm_repl_log *replog;
	struct dm_repl_slink *slink0;

	struct stats stats;	/* Development statistics. */

	struct repl_params {
		enum open_type open_type;
		unsigned count;
		struct repl_dev {
			struct dm_dev *dm_dev;
			sector_t start;
			sector_t size;
		} dev;
	} params;

	struct {
		spinlock_t lock; /* Lock on pending list below. */
		struct bio_list in; /* pending list of bios */
		struct dm_io_client *io_client;
		struct workqueue_struct *wq;
		struct work_struct ws;
		unsigned long flags;	/* State flags. */
		/* Preallocated header. We only need one at a time.*/
		struct buffer_header_disk *buffer_header_disk;
	} io;

	struct ringbuffer ringbuffer;

	/* Useful for runtime performance on bitmap accesses. */
	struct {
		int count;	/* Actual # of slinks in this replog. */
		unsigned max;	/* Actual maximum added site link #. */
		unsigned bitmap_elems;	/* Actual used elements in bitmaps. */
		unsigned bitmap_size;	/* Actual bitmap size (for memcpy). */
	} slink;

	struct {
		struct log_header *log;
	} header;

	struct {
		/* List of site links. */
		struct dm_repl_log_slink_list slinks;

		/*
		 * A single lock for all of these lists should be sufficient
		 * given that each list is processed in-turn (see do_log()).
		 *
		 * The lock has to protect the L_SLINK_ENDIO list
		 * and the entry ring write lists below.
		 *
		 * We got to streamline these lists vs. the lock. -HJM
		 * The others are accessed by one thread only. -HJM
		 */
		rwlock_t	lock;

		/*
		 * Lists for entry slink copies, entry endios,
		 * ring buffer writes and ordered entries.
		 */
		struct list_head l[L_NR_LISTS];
	} lists;

	/* Caller callback function and context. */
	struct replog_notify {
		dm_repl_notify_fn fn;
		void *context;
	} notify;
};

#define _SET_AND_BUG_ON_L(l, log) \
	do { \
		_BUG_ON_PTR(log); \
		(l) = (log)->context; \
		_BUG_ON_PTR(l); \
	} while (0);

/* Define log bitops. */
DM_BITOPS(LogDevelStats, repl_log, LOG_DEVEL_STATS);
DM_BITOPS(LogInitialized, repl_log, LOG_INITIALIZED);
DM_BITOPS(LogResize, repl_log, LOG_RESIZE);

static inline struct repl_log *
ringbuffer_repl_log(struct ringbuffer *ring)
{
	return container_of(ring, struct repl_log, ringbuffer);
}

static inline struct block_device *
repl_log_bdev(struct repl_log *l)
{
	return l->params.dev.dm_dev->bdev;
}

static inline struct block_device *
ringbuffer_bdev(struct ringbuffer *ring)
{
	return repl_log_bdev(ringbuffer_repl_log(ring));
}

/* Check MAX_SLINKS bit array for busy bits. */
static inline int
entry_busy(struct repl_log *l, void *bits)
{
	return find_first_bit(bits, l->slink.max) < l->slink.max;
}

static inline int
entry_endios_pending(struct ringbuffer_entry *entry)
{
	return entry_busy(ringbuffer_repl_log(entry->ring), ENTRY_IOS(entry));
}

static inline int
ss_io(struct slink_state *ss)
{
	_BUG_ON_PTR(ss);
	return atomic_read(&ss->io.in_flight);
}

static void
ss_io_get(struct slink_state *ss)
{
	BUG_ON(!ss || IS_ERR(ss));
	atomic_inc(&ss->io.in_flight);
}

static void
ss_io_put(struct slink_state *ss)
{
	_BUG_ON_PTR(ss);
	if (atomic_dec_and_test((&ss->io.in_flight)))
		wake_up(&ss->io.waiters);
	else
		BUG_ON(ss_io(ss) < 0);
}

static void
ss_wait_on_io(struct slink_state *ss)
{
	_BUG_ON_PTR(ss);
	while (ss_io(ss)) {
		flush_workqueue(ss->l->io.wq);
		wait_event(ss->io.waiters, !ss_io(ss));
	}
}

/* Wait for I/O to finish on all site links. */
static inline void
ss_all_wait_on_ios(struct repl_log *l)
{
	unsigned long slink_nr;

	for_each_bit(slink_nr, LOG_SLINKS(l), l->slink.max) {
		struct dm_repl_slink *slink =
			l->slink0->ops->slink(l->replog, slink_nr);
		struct slink_state *ss;

		if (IS_ERR(slink)) {
			DMERR_LIMIT("%s slink error", __func__);
			continue;
		}

		ss = slink->caller;
		_BUG_ON_PTR(ss);
		ss_wait_on_io(ss);
	}
}

static inline struct dm_io_client *
replog_io_client(struct repl_log *l)
{
	return l->io.io_client;
}

static inline struct repl_log *
dev_repl_log(struct repl_dev *dev)
{
	return container_of(dev, struct repl_log, params.dev);
}

/* Define mempool_{alloc,free}() functions for the ring buffer pools. */
#define	ALLOC_FREE_ELEM(name, type) \
static void *\
alloc_ ## name(struct ringbuffer *ring) \
{ \
	return mempool_alloc(ring->pools[(type)], GFP_KERNEL); \
} \
\
static inline void \
free_ ## name(void *ptr, struct ringbuffer *ring) \
{ \
	_BUG_ON_PTR(ptr); \
	mempool_free(ptr, ring->pools[(type)]); \
}

ALLOC_FREE_ELEM(entry, ENTRY)
ALLOC_FREE_ELEM(header, DATA_HEADER)
ALLOC_FREE_ELEM(data_header_disk, DATA_HEADER_DISK)
ALLOC_FREE_ELEM(copy_context, COPY_CONTEXT)
#undef ALLOC_FREE_ELEM

/* Additional alloc/free functions for header_io() abstraction. */
/* No need to allocate bitmaps, because they are transient. */
static void *
alloc_log_header_disk(struct ringbuffer *ring)
{
	return kmalloc(to_bytes(1), GFP_KERNEL);
}

static void
free_log_header_disk(void *ptr, struct ringbuffer *ring)
{
	kfree(ptr);
}

/* Dummies to allow for abstraction. */
static void *
alloc_buffer_header_disk(struct ringbuffer *ring)
{
	return ringbuffer_repl_log(ring)->io.buffer_header_disk;
}

static void
free_buffer_header_disk(void *ptr, struct ringbuffer *ring)
{
}

/*********************************************************************
 * Busys entries hash.
 */
/* Initialize/destroy sector hash. */
static int
sector_hash_init(struct sector_hash *hash, sector_t size)
{
	unsigned buckets = roundup_pow_of_two(size / BIO_MAX_SECTORS);

	if (buckets > 4) {
		if (buckets > REGIONS_MAX)
			buckets = REGIONS_MAX;

		buckets /= 4;
	}

	/* Allocate stripe hash. */
	hash->hash = vmalloc(buckets * sizeof(*hash->hash));
	if (!hash->hash)
		return -ENOMEM;

	hash->buckets = hash->mask = buckets;
	hash->mask--;

	/* Initialize buckets. */
	while (buckets--)
		INIT_LIST_HEAD(hash->hash + buckets);

	return 0;
}

static void
sector_hash_exit(struct sector_hash *hash)
{
	if (hash->hash) {
		vfree(hash->hash);
		hash->hash = NULL;
	}
}

/* Hash function. */
static inline struct list_head *
hash_bucket(struct sector_hash *hash, sector_t sector)
{
	sector_div(sector, BIO_MAX_SECTORS);
	return hash->hash + (unsigned) (sector & hash->mask);
}

/* Insert an entry into a sector hash. */
static inline void
sector_hash_elem_insert(struct sector_hash *hash,
			struct ringbuffer_entry *entry)
{
	struct repl_log *l;
	struct stats *s;
	struct list_head *bucket =
		hash_bucket(hash, entry->data.header->region.sector);

	BUG_ON(!bucket);
	_BUG_ON_PTR(entry->ring);
	l = ringbuffer_repl_log(entry->ring);
	s = &l->stats;

	BUG_ON(!list_empty(E_BUSY_HASH_LIST(entry)));
	list_add_tail(E_BUSY_HASH_LIST(entry), bucket);

	atomic_inc(&s->hash_elem);
	if (++s->hash_insert > s->hash_insert_max)
		s->hash_insert_max = s->hash_insert;
}

/* Return first sector # of bio. */
static inline sector_t
bio_begin(struct bio *bio)
{
	return bio->bi_sector;
}

/* Return last sector # of bio. */
static inline sector_t bio_end(struct bio *bio)
{
	return bio_begin(bio) + bio_sectors(bio);
}

/* Roundup size to sectors. */
static inline sector_t round_up_to_sector(unsigned size)
{
	return to_sector(dm_round_up(size, to_bytes(1)));
}

/* Check if a bio and a range overlap. */
static inline int
_ranges_overlap(struct sector_range *r1, struct sector_range *r2)
{
	return r1->start >= r2->start &&
	       r1->start < r2->end;
}

static inline int
ranges_overlap(struct sector_range *elem_range, struct sector_range *bio_range)
{
	return _ranges_overlap(elem_range, bio_range) ||
	       _ranges_overlap(bio_range, elem_range);
}

/* Take an entry ref reference out. */
static inline void
entry_get(struct ringbuffer_entry *entry)
{
	atomic_inc(&entry->ref);
}

/*
 * Check if bio's address range has writes pending.
 *
 * Must be called with the read hash lock held.
 */
static int
ringbuffer_writes_pending(struct sector_hash *hash, struct bio *bio,
			   struct list_head *buckets[2])
{
	int r = 0;
	unsigned end, i;
	struct ringbuffer_entry *entry;
	/* Setup a range for the bio. */
	struct sector_range bio_range = {
		.start = bio_begin(bio),
		.end = bio_end(bio),
	}, entry_range;

	buckets[0] = hash_bucket(hash, bio_range.start);
	buckets[1] = hash_bucket(hash, bio_range.end);
	if (buckets[0] == buckets[1]) {
		end = 1;
		buckets[1] = NULL;
	} else
		end = 2;

	for (i = 0; i < end; i++) {
		/* Walk the entries checking for overlaps. */
		list_for_each_entry_reverse(entry, buckets[i],
					    lists.l[E_BUSY_HASH]) {
			entry_range.start = entry->data.header->region.sector;
			entry_range.end = entry_range.start +
			round_up_to_sector(entry->data.header->region.size);

			if (ranges_overlap(&entry_range, &bio_range))
				return atomic_read(&entry->endios) ? -EBUSY : 1;
		}
	}

	return r;
}

/* Clear a sector range busy. */
static void
entry_put(struct ringbuffer_entry *entry)
{
	_BUG_ON_PTR(entry);

	if (atomic_dec_and_test(&entry->ref)) {
		struct ringbuffer *ring = entry->ring;
		struct stats *s;
		struct repl_log *l;

		_BUG_ON_PTR(ring);
		l = ringbuffer_repl_log(ring);
		s = &l->stats;

		/*
		 * We don't need locking here because the last
		 * put is carried out in daemon context.
		 */
		BUG_ON(list_empty(E_BUSY_HASH_LIST(entry)));
		list_del_init(E_BUSY_HASH_LIST(entry));

		atomic_dec(&s->hash_elem);
		s->hash_insert--;
	} else
		BUG_ON(atomic_read(&entry->ref) < 0);
}

static inline void
sector_range_clear_busy(struct ringbuffer_entry *entry)
{
	entry_put(entry);
}

/*
 * Mark a sector range start and length busy.
 *
 * Caller has to serialize calls.
 */
static void
sector_range_mark_busy(struct ringbuffer_entry *entry)
{
	_BUG_ON_PTR(entry);
	entry_get(entry);

	/* Insert new element into hash. */
	sector_hash_elem_insert(&entry->ring->busy_sectors, entry);
}

static void
stats_init(struct repl_log *l)
{
	unsigned i = 2;
	struct stats *s = &l->stats;

	memset(s, 0, sizeof(*s));

	while (i--)
		atomic_set(s->io + i, 0);

	atomic_set(&s->writes_pending, 0);
	atomic_set(&s->hash_elem, 0);
}

/* Global replicator log list. */
static LIST_HEAD(replog_list);

/* Wake worker. */
static void
wake_do_log(struct repl_log *l)
{
	queue_work(l->io.wq, &l->io.ws);
}

struct dm_repl_slink *
slink_find(struct repl_log *l, int slink_nr)
{
	struct dm_repl_slink *slink0 = l->slink0;

	if (!slink0)
		return ERR_PTR(-ENOENT);

	_BUG_ON_SLINK_NR(l, slink_nr);
	return slink_nr ? slink0->ops->slink(l->replog, slink_nr) : slink0;
}

/*
 * If an slink is asynchronous, check to see if it needs to fall
 * back to synchronous mode due to falling too far behind.
 *
 * Declare a bunch of fallbehind specific small functions in order
 * to avoid conditions in the fast path by accessing them via
 * function pointers.
 */
/* True if slink exceeds fallbehind threshold. */
static int
slink_fallbehind_exceeded(struct repl_log *l, struct slink_state *ss,
			  struct dm_repl_slink_fallbehind *fallbehind,
			  unsigned amount)
{
	sector_t *sectors;
	uint64_t *ios;
	unsigned long *head_jiffies;

	_BUG_ON_PTR(l);
	_BUG_ON_PTR(ss);
	_BUG_ON_PTR(fallbehind);
	ios = &ss->fb.outstanding.ios;
	sectors = &ss->fb.outstanding.sectors;

	spin_lock(&l->io.lock);
	(*ios)++;
	(*sectors) += amount;
	spin_unlock(&l->io.lock);

	if (!fallbehind->value)
		return 0;

	switch (fallbehind->type) {
	case DM_REPL_SLINK_FB_IOS:
		return *ios > fallbehind->value;

	case DM_REPL_SLINK_FB_SIZE:
		return *sectors > fallbehind->value;

	case DM_REPL_SLINK_FB_TIMEOUT:
		head_jiffies = &ss->fb.head_jiffies;
		if (unlikely(!*head_jiffies))
			*head_jiffies = jiffies;

		return time_after(jiffies, *head_jiffies +
				  msecs_to_jiffies(fallbehind->value));

	default:
		BUG();
	}

	return 0;
}

/*
 * True if slink falls below fallbehind threshold.
 *
 * Can be called from interrupt context.
 */
static int
slink_fallbehind_recovered(struct repl_log *l, struct slink_state *ss,
			   struct dm_repl_slink_fallbehind *fallbehind,
			   unsigned amount)
{
	sector_t *sectors;
	uint64_t *ios;

	_BUG_ON_PTR(ss);
	_BUG_ON_PTR(fallbehind);
	ios = &ss->fb.outstanding.ios;
	sectors = &ss->fb.outstanding.sectors;

	/* Need the non-irq versions here, because IRQs are already disabled. */
	spin_lock(&l->io.lock);
	(*ios)--;
	(*sectors) -= amount;
	spin_unlock(&l->io.lock);

	if (!fallbehind->value)
		return 0;

	switch (fallbehind->type) {
	case DM_REPL_SLINK_FB_IOS:
		return *ios <= fallbehind->value;

	case DM_REPL_SLINK_FB_SIZE:
		return *sectors <= fallbehind->value;

	case DM_REPL_SLINK_FB_TIMEOUT:
		return time_before(jiffies, ss->fb.head_jiffies +
				   msecs_to_jiffies(fallbehind->value));
	default:
		BUG();
	}

	return 0;
}

/*
 * Update fallbehind account.
 *
 * Has to be called with rw lock held.
 */
/* FIXME: account for resynchronization. */
enum fb_update_type { UPD_INC, UPD_DEC };
static void
slink_fallbehind_update(enum fb_update_type type,
			struct dm_repl_slink *slink,
			struct ringbuffer_entry *entry)
{
	int slink_nr, sync;
	struct repl_log *l;
	struct slink_state *ss;
	struct data_header_region *region;
	struct dm_repl_slink_fallbehind *fallbehind;
	struct ringbuffer_entry *pos;

	_BUG_ON_PTR(slink);
	fallbehind = slink->ops->fallbehind(slink);
	_BUG_ON_PTR(fallbehind);
	_BUG_ON_PTR(entry);
	l = ringbuffer_repl_log(entry->ring);
	_BUG_ON_PTR(l);
	slink_nr = slink->ops->slink_number(slink);
	_BUG_ON_SLINK_NR(l, slink_nr);
	region = &entry->data.header->region;
	_BUG_ON_PTR(region);

	/*
	 * We can access ss w/o a lock, because it's referenced by
	 * inflight I/Os and by the running worker which processes
	 * this function.
	 */
	ss = slink->caller;
	if (!ss)
		return;

	_BUG_ON_PTR(ss);
	sync = SsSync(ss);

	switch (type) {
	case UPD_INC:
		if (slink_fallbehind_exceeded(l, ss, fallbehind,
					      region->size) &&
		    !TestSetSsSync(ss) &&
		    !sync)
			DMINFO("enforcing fallbehind sync on slink=%d at %u",
			       slink_nr, jiffies_to_msecs(jiffies));
		break;

	case UPD_DEC:
		/*
		 * Walk the list of outstanding copy I/Os and update the
		 * start_jiffies value with the first entry found.
		 */
		list_for_each_entry(pos, L_SLINK_COPY_LIST(l),
				    lists.l[E_WRITE_OR_COPY]) {
			struct slink_copy_context *cc;

			list_for_each_entry(cc, E_COPY_CONTEXT_LIST(pos),
					    list) {
				if (cc->slink->ops->slink_number(cc->slink) ==
				    slink_nr) {
					ss->fb.head_jiffies = cc->start_jiffies;
					break;
				}
			}
		}

		if (slink_fallbehind_recovered(l, ss, fallbehind,
					       region->size)) {
			ss->fb.head_jiffies = 0;

			if (TestClearSsSync(ss) && sync) {
				DMINFO("releasing fallbehind sync on slink=%d"
				       " at %u",
				       slink_nr, jiffies_to_msecs(jiffies));
				wake_do_log(l);
			}
		}

		break;

	default:
		BUG();
	}
}

static inline void
slink_fallbehind_inc(struct dm_repl_slink *slink,
		     struct ringbuffer_entry *entry)
{
	slink_fallbehind_update(UPD_INC, slink, entry);
}

static inline void
slink_fallbehind_dec(struct dm_repl_slink *slink,
		     struct ringbuffer_entry *entry)
{
	slink_fallbehind_update(UPD_DEC, slink, entry);
}

/* Caller properties definition for dev_io(). */
struct dev_io_params {
	struct repl_dev *dev;
	sector_t sector;
	unsigned size;
	struct dm_io_memory mem;
	struct dm_io_notify notify;
	unsigned long flags;
};

/*
 * Read/write device items.
 *
 * In case of dio->fn, an asynchronous dm_io()
 * call will be performed, else synchronous.
 */
static int
dev_io(int rw, struct ringbuffer *ring, struct dev_io_params *dio)
{
	BUG_ON(dio->size > BIO_MAX_SIZE);
	DMDEBUG_LIMIT("%s: rw: %d, %u sectors at sector %llu, dev %p",
		      __func__, rw, dio->size,
		      (unsigned long long) dio->sector,
		      dio->dev->dm_dev->bdev);

	/* Flag IO queued on asynchronous calls. */
	if (dio->notify.fn)
		SetRingBufferIOQueued(ring);

	return dm_io(
		&(struct dm_io_request) {
			.bi_rw = rw,
			.mem = dio->mem,
			.notify = dio->notify,
			.client = replog_io_client(dev_repl_log(dio->dev))
		}, 1 /* 1 region following */,
		&(struct dm_io_region) {
			.bdev = dio->dev->dm_dev->bdev,
			.sector = dio->sector,
			.count = round_up_to_sector(dio->size),
		},
		NULL
	);
}

/* Definition of properties/helper functions for header IO. */
struct header_io_spec {
	const char *name;	/* Header identifier (eg. 'data'). */
	unsigned size;		/* Size of ondisk structure. */
	/* Disk structure allocation helper. */
	void *(*alloc_disk)(struct ringbuffer *);
	/* Disk structure deallocation helper. */
	void (*free_disk)(void *, struct ringbuffer *);
	/* Disk structure to core structure xfer helper. */
	int (*to_core_fn)(unsigned bitmap_elems, void *, void *);
	/* Core structure to disk structure xfer helper. */
	void (*to_disk_fn)(unsigned bitmap_elems, void *, void *);
};
/* Macro to initialize type specific header_io_spec structure. */
#define	IO_SPEC(header) \
	{ .name = # header, \
	  .size = sizeof(struct header ## _header_disk), \
	  .alloc_disk = alloc_ ## header ## _header_disk, \
	  .free_disk = free_ ## header ## _header_disk, \
	  .to_core_fn = header ## _header_to_core, \
	  .to_disk_fn = header ## _header_to_disk }

enum header_type { IO_LOG, IO_BUFFER, IO_DATA };
struct header_io_params {
	enum header_type type;
	struct repl_log *l;
	void *core_header;
	sector_t sector;
	void (*disk_header_fn)(void *);
};

/* Read /write a {log,buffer,data} header to disk. */
static int
header_io(int rw, struct header_io_params *hio)
{
	int r;
	struct repl_log *l = hio->l;
	struct ringbuffer *ring = &l->ringbuffer;
	/* Specs of all log headers. Must be in 'enum header_type' order! */
	static const struct header_io_spec io_specs[] = {
		IO_SPEC(log),
		IO_SPEC(buffer),
		IO_SPEC(data),
	};
	const struct header_io_spec *io = io_specs + hio->type;
	void *disk_header = io->alloc_disk(ring);
	struct dev_io_params dio = {
		&l->params.dev, hio->sector, io->size,
		.mem = {
			.type = DM_IO_KMEM,
			.offset = 0,
			.ptr.addr = disk_header,
		},
		.notify = { NULL, NULL}
	};

	BUG_ON(io < io_specs || io >= ARRAY_END(io_specs));
	BUG_ON(!hio->core_header);
	BUG_ON(!disk_header);
	memset(disk_header, 0, io->size);

	if (rw == WRITE) {
		io->to_disk_fn(BITMAP_ELEMS(l), disk_header, hio->core_header);

		/*  If disk header needs special handling before write. */
		if (hio->disk_header_fn)
			hio->disk_header_fn(disk_header);
	}

	r = dev_io(rw, ring, &dio);
	if (unlikely(r)) {
		SetRingBufferError(ring);
		DMERR("Failed to %s %s header!",
		      rw == WRITE ? "write" : "read", io->name);
	} else if (rw == READ) {
		r = io->to_core_fn(BITMAP_ELEMS(l), hio->core_header,
				   disk_header);
		if (unlikely(r))
			DMERR("invalid %s header/sector=%llu",
			      io->name, (unsigned long long) hio->sector);
	}

	io->free_disk(disk_header, ring);
	return r;
}

/* Read/write the log header synchronously. */
static inline int
log_header_io(int rw, struct repl_log *l)
{
	return header_io(rw, &(struct header_io_params) {
			 IO_LOG, l, l->header.log, l->params.dev.start, NULL });
}

/* Read/write the ring buffer header synchronously. */
static inline int
buffer_header_io(int rw, struct repl_log *l)
{
	return header_io(rw, &(struct header_io_params) {
			 IO_BUFFER, l, &l->ringbuffer,
			 l->header.log->buffer_header, NULL });
}

/* Read/write a data header to/from the ring buffer synchronously. */
static inline int
data_header_io(int rw, struct repl_log *l,
	       struct data_header *header, sector_t sector)
{
	return header_io(rw, &(struct header_io_params) {
			 IO_DATA, l, header, sector, NULL });
}

/* Notify dm-repl.c to submit more IO. */
static void
notify_caller(struct repl_log *l, int rw, int error)
{
	struct replog_notify notify;

	_BUG_ON_PTR(l);

	spin_lock(&l->io.lock);
	notify = l->notify;
	spin_unlock(&l->io.lock);

	if (likely(notify.fn)) {
		if (rw == READ)
			notify.fn(error, 0, notify.context);
		else
			notify.fn(0, error, notify.context);
	}
}

/*
 * Ring buffer routines.
 *
 * The ring buffer needs to keep track of arbitrarily-sized data items.
 * HEAD points to the first data header that needs to be replicated.  This
 * can mean it has been partially replicated or not replicated at all.
 * The ring buffer is empty if HEAD == TAIL.
 * The ring buffer is full if HEAD == TAIL + len(TAIL) modulo device size.
 *
 * An entry in the buffer is not valid until both the data header and the
 * associated data items are on disk.  Multiple data headers and data items
 * may be written in parallel.  This means that, in addition to the
 * traditional HEAD and TAIL pointers, we need to keep track of an in-core
 * variable reflecting the next area in the log that is unallocated.  We also
 * need to keep an ordered list of pending and completd buffer entry writes.
 */
/*
 * Check and wrap a ring buffer offset around ring buffer end.
 *
 * There are three cases to distinguish here:
 * 1. header and data fit before ring->end
 * 2. header fits before ring->end, data doesn't -> remap data to ring->start
 * 3. header doesn't fit before ring->end -> remap both to ring->start
 *
 * Function returns the next rounded offset *after* any
 * conditional remapping of the actual header.
 *
 */
static sector_t
sectors_unused(struct ringbuffer *ring, sector_t first_free)
{
	return (ring->end < first_free) ? 0 : ring->end - first_free;
}

/*
 * Return the first sector past the end of the header
 * (i.e. the first data sector).
 */
static inline sector_t
data_start(struct data_header *header)
{
	return header->pos.header + HEADER_SECTORS;
}

/*
 * Return the first sector past the end of the entry.
 * (i.e.(the first unused sector).
 */
static inline sector_t
next_start(struct data_header *header)
{
	return header->pos.data + header->pos.data_sectors;
}

static inline sector_t
next_start_adjust(struct ringbuffer *ring, struct data_header *header)
{
	sector_t next_sector = next_start(header);

	return likely(sectors_unused(ring, next_sector) < HEADER_SECTORS) ?
	       ring->start : next_sector;
}

/* True if entry doesn't wrap. */
static inline int
not_wrapped(struct data_header *header)
{
	return header->wrap == WRAP_NONE;
}

/* True if header at ring end and data wrapped to ring start. */
static inline int
data_wrapped(struct data_header *header)
{
	return header->wrap == WRAP_DATA;
}

/* True if next entry wraps to ring start. */
static inline int
next_entry_wraps(struct data_header *header)
{
	return header->wrap == WRAP_NEXT;
}

/* Return amount of skipped sectors in case of wrapping. */
static unsigned
sectors_skipped(struct ringbuffer *ring, struct data_header *header)
{
	if (likely(not_wrapped(header)))
		/* noop */ ;
	else if (data_wrapped(header))
		return sectors_unused(ring, data_start(header));
	else if (next_entry_wraps(header))
		return sectors_unused(ring, next_start(header));

	return 0;
}

/* Emmit only once log error messages. */
static void
ringbuffer_error(enum ring_status_type type,
		  struct ringbuffer *ring, int error)
{
	struct error {
		enum ring_status_type type;
		int (*f)(struct ringbuffer *);
		const char *msg;
	};
	static const struct error errors[] = {
		{ RING_BUFFER_DATA_ERROR, TestSetRingBufferDataError, "data" },
		{ RING_BUFFER_HEAD_ERROR, TestSetRingBufferHeadError, "head" },
		{ RING_BUFFER_HEADER_ERROR, TestSetRingBufferHeaderError,
		  "header" },
		{ RING_BUFFER_TAIL_ERROR, TestSetRingBufferTailError, "tail" },
	};
	const struct error *e = ARRAY_END(errors);

	while (e-- > errors) {
		if (type == e->type) {
			if (!e->f(ring))
				DMERR("ring buffer %s I/O error %d",
				      e->msg, error);

			return SetRingBufferError(ring);
		}
	}

	BUG();
}

/*
 * Allocate space for a data item in the ring buffer.
 *
 * header->pos is filled in with the sectors for the header and data in
 * the ring buffer. The free space in the ring buffer is decremented to
 * account for this entry. The return value is the sector address for the
 * next data_header_disk.
 */

/* Increment buffer offset past actual header, optionaly wrapping data. */
static sector_t
ringbuffer_inc(struct ringbuffer *ring, struct data_header *header)
{
	sector_t sectors;

	/* Initialize the header with the common case */
	header->pos.header = ring->next_avail;
	header->pos.data = data_start(header);

	/*
	 * Header doesn't fit before ring->end.
	 *
	 * This can only happen when we are started with an empty ring
	 * buffer that has its tail near the end of the device.
	 */
	if (unlikely(data_start(header) > ring->end)) {
		/*
		 * Wrap an entire entry (header + data) to the beginning of
		 * the log device. This will update the ring free sector
		 * count to account for the unused sectors at the end
		 * of the device.
		 */
		header->pos.header = ring->start;
		header->pos.data = data_start(header);
	/* Data doesn't fit before ring->end. */
	} else if (unlikely(next_start(header) > ring->end)) {
		/*
		 * Wrap the data portion of a ring buffer entry to the
		 * beginning of the log device. This will update the ring
		 * free sector count to account for the unused sectors at
		 * the end of the device.
		 */
		header->pos.data = ring->start;
		header->wrap = WRAP_DATA;

		ringbuffer_repl_log(ring)->stats.wrap++;
	} else
		header->wrap = WRAP_NONE;

	sectors = roundup_sectors(header->pos.data_sectors);
	BUG_ON(sectors > ring->pending);
	ring->pending -= sectors;

	sectors = next_start_adjust(ring, header);
	if (sectors == ring->start) {
		header->wrap = WRAP_NEXT;

		ringbuffer_repl_log(ring)->stats.wrap++;
	}

	return sectors;
}

/* Slab and mempool definition. */
struct cache_defs {
	const enum ring_pool_type type;
	const int min;
	const size_t size;
	struct kmem_cache *slab_pool;
	const char *slab_name;
	const size_t align;
};

/* Slab and mempool declarations. */
static struct cache_defs cache_defs[] = {
	{ ENTRY, ENTRY_POOL_MIN, sizeof(struct ringbuffer_entry),
	  NULL, "dm_repl_log_entry", 0 },
	{ DATA_HEADER, HEADER_POOL_MIN, sizeof(struct data_header),
	  NULL, "dm_repl_log_header", 0 },
	{ DATA_HEADER_DISK, HEADER_POOL_MIN, DATA_HEADER_DISK_SIZE,
	  NULL, "dm_repl_log_disk_header", DATA_HEADER_DISK_SIZE },
	{ COPY_CONTEXT, CC_POOL_MIN, sizeof(struct slink_copy_context),
	  NULL, "dm_repl_log_copy", 0 },
};

/* Destroy all memory pools for a ring buffer. */
static void
ringbuffer_exit(struct ringbuffer *ring)
{
	mempool_t **pool = ARRAY_END(ring->pools);

	sector_hash_exit(&ring->busy_sectors);

	while (pool-- > ring->pools) {
		if (likely(*pool)) {
			mempool_destroy(*pool);
			*pool = NULL;
		}
	}
}

/* Create all mempools for a ring buffer. */
static int
ringbuffer_init(struct ringbuffer *ring)
{
	int r;
	struct repl_log *l = ringbuffer_repl_log(ring);
	struct cache_defs *pd = ARRAY_END(cache_defs);


	mutex_init(&l->ringbuffer.mutex);
	init_waitqueue_head(&ring->flushq);

	/* Create slab pools. */
	while (pd-- > cache_defs) {
		/* Bitmap is not a slab pool. */
		if (!pd->size)
			continue;

		ring->pools[pd->type] =
			mempool_create_slab_pool(pd->min, pd->slab_pool);

		if (unlikely(!ring->pools[pd->type])) {
			DMERR("Error creating mempool %s", pd->slab_name);
			goto bad;
		}
	}

	/* Initialize busy sector hash. */
	r = sector_hash_init(&ring->busy_sectors, l->params.dev.size);
	if (r < 0) {
		DMERR("Failed to allocate sector busy hash!");
		goto bad;
	}

	return 0;

bad:
	ringbuffer_exit(ring);
	return -ENOMEM;
}

/*
 * Reserve space in the ring buffer for the
 * given bio data and associated header.
 *
 * Correct ring->free by any skipped sectors at the end of the ring buffer.
 */
static int
ringbuffer_reserve_space(struct ringbuffer *ring, struct bio *bio)
{
	unsigned nsectors = roundup_sectors(bio_sectors(bio));
	sector_t end_space, start_sector;

	if (!nsectors)
		return -EPERM;

	BUG_ON(!mutex_is_locked(&ring->mutex));

	if (unlikely(ring->free < nsectors)) {
		SetRingBufferFull(ring);
		return -EBUSY;
	}

	/*
	 * Account for the sectors that are queued for do_log()
	 * but have not been accounted for on the disk.  We need this
	 * calculation to see if any sectors will be lost from our
	 * free pool at the end of ring buffer.
	 */
	start_sector = ring->next_avail + ring->pending;
	end_space = sectors_unused(ring, start_sector);

	/* if the whole I/O won't fit before the end of the disk. */
	if (unlikely(end_space && end_space < nsectors)) {
		sector_t skipped = end_space >= HEADER_SECTORS ?
			sectors_unused(ring, start_sector + HEADER_SECTORS) :
			end_space;

		/* Don't subtract skipped sectors in case the bio won't fit. */
		if (ring->free - skipped < nsectors)
			return -EBUSY;

		/*
		 * We subtract the amount of skipped sectors
		 * from ring->free here..
		 *
		 * ringbuffer_advance_head() will add them back on.
		 */
		ring->free -= skipped;
	}

	ring->free -= nsectors;
	ring->pending += nsectors;
	return 0;
}

static int
ringbuffer_empty_nolock(struct ringbuffer *ring)
{
	return (ring->head == ring->tail) && !RingBufferFull(ring);
}

static int
ringbuffer_empty(struct ringbuffer *ring)
{
	int r;

	mutex_lock(&ring->mutex);
	r = ringbuffer_empty_nolock(ring);
	mutex_unlock(&ring->mutex);

	return r;
}

static void
set_sync_mask(struct repl_log *l, struct ringbuffer_entry *entry)
{
	unsigned long slink_nr;

	/* Bitmask of slinks with synchronous I/O completion policy. */
	for_each_bit(slink_nr, ENTRY_SLINKS(entry), l->slink.max) {
		struct dm_repl_slink *slink = slink_find(l, slink_nr);

		/* Slink not configured. */
		if (unlikely(IS_ERR(slink)))
			continue;

		/* If an slink has fallen behind an I/O threshold, it
		 * must be marked for synchronous I/O completion. */
		if (slink_synchronous(slink) ||
		    SsSync(slink->caller))
			slink_set_bit(slink_nr, ENTRY_SYNC(entry));
	}
}

/*
 * Always returns an initialized write entry,
 * unless fatal memory allocation happens.
 */
static struct ringbuffer_entry *
ringbuffer_alloc_entry(struct ringbuffer *ring, struct bio *bio)
{
	int dev_number, i;
	struct repl_log *l = ringbuffer_repl_log(ring);
	struct ringbuffer_entry *entry = alloc_entry(ring);
	struct data_header *header = alloc_header(ring);
	struct data_header_region *region;

	BUG_ON(!entry);
	BUG_ON(!header);
	memset(entry, 0, sizeof(*entry));
	memset(header, 0, sizeof(*header));

	/* Now setup the ringbuffer_entry. */
	atomic_set(&entry->endios, 0);
	atomic_set(&entry->ref, 0);
	entry->ring = ring;
	entry->data.header = header;
	header->wrap = WRAP_NONE;

	i = ARRAY_SIZE(entry->lists.l);
	while (i--)
		INIT_LIST_HEAD(entry->lists.l + i);

	/*
	 * In case we're called with a bio, we're creating a new entry
	 * or we're allocating it for reading the header in during init.
	 */
	if (bio) {
		struct dm_repl_slink *slink0 = slink_find(l, 0);

		_BUG_ON_PTR(slink0);

		/* Setup the header region. */
		dev_number = slink0->ops->dev_number(slink0, bio->bi_bdev);
		BUG_ON(dev_number < 0);
		region = &header->region;
		region->dev = dev_number;
		region->sector = bio_begin(bio);
		region->size = bio->bi_size;
		BUG_ON(!region->size);
		header->pos.data_sectors =
			roundup_data_sectors(bio_sectors(bio));

		entry->bios.write = bio;
		sector_range_mark_busy(entry);

		/*
		 * Successfully allocated space in the ring buffer
		 * for this entry. Advance our in-memory tail pointer.
		 * Round up to HEADER_SECTORS boundary for supporting
		 * up to 4k sector sizes.
		 */
		mutex_lock(&ring->mutex);
		ring->next_avail = ringbuffer_inc(ring, header);
		mutex_unlock(&ring->mutex);

		/* Bitmask of slinks to initiate copies accross. */
		memcpy(ENTRY_SLINKS(entry), LOG_SLINKS(l), BITMAP_SIZE(l));

		/* Set synchronous I/O policy mask. */
		set_sync_mask(l, entry);
	}

	/* Add header to the ordered list of headers. */
	list_add_tail(E_ORDERED_LIST(entry), L_ENTRY_ORDERED_LIST(l));

	DMDEBUG_LIMIT("%s header->pos.header=%llu header->pos.data=%llu "
		      "advancing ring->next_avail=%llu", __func__,
		      (unsigned long long) header->pos.header,
		      (unsigned long long) header->pos.data,
		      (unsigned long long) ring->next_avail);
	return entry;
}

/* Free a ring buffer entry and the data header hanging off it. */
static void
ringbuffer_free_entry(struct ringbuffer_entry *entry)
{
	struct ringbuffer *ring;

	_BUG_ON_PTR(entry);
	_BUG_ON_PTR(entry->data.header);

	ring = entry->ring;
	_BUG_ON_PTR(ring);

	/*
	 * Will need to change once ringbuffer_entry is
	 * not kept around as long as the data header.
	 */
	if (!list_empty(E_BUSY_HASH_LIST(entry))) {
		DMERR("%s E_BUSY_HAS_LIST not empty!", __func__);
		BUG();
	}

	if (!list_empty(E_COPY_CONTEXT_LIST(entry))) {
		DMERR("%s E_COPY_CONTEXT_LIST not empty!", __func__);
		BUG();
	}

	if (!list_empty(E_ORDERED_LIST(entry)))
		list_del(E_ORDERED_LIST(entry));

	if (!list_empty(E_WRITE_OR_COPY_LIST(entry)))
		list_del(E_WRITE_OR_COPY_LIST(entry));

	free_header(entry->data.header, ring);
	free_entry(entry, ring);
}

/* Mark a ring buffer entry invalid on the backing store device. */
static void
disk_header_set_invalid(void *ptr)
{
	((struct data_header_disk *) ptr)->valid = 0;
}

static int
ringbuffer_mark_entry_invalid(struct ringbuffer *ring,
			       struct ringbuffer_entry *entry)
{
	struct data_header *header = entry->data.header;

	return header_io(WRITE, &(struct header_io_params) {
			 DATA_HEADER, ringbuffer_repl_log(ring),
			 header, header->pos.header, disk_header_set_invalid });
}

enum endio_type { HEADER_ENDIO = 0, DATA_ENDIO, NR_ENDIOS };
static void
endio(struct ringbuffer_entry *entry,
      enum endio_type type, unsigned long error)
{
	*(type == DATA_ENDIO ? &entry->data.error.data :
			       &entry->data.error.header) = error;

	if (atomic_dec_and_test(&entry->endios))
		/*
		 * Endio processing requires disk writes to advance the log
		 * tail pointer. So, we need to defer this to process context.
		 * The endios are processed from the l->lists.entry.io list,
		 * and the entry is already on that list.
		 */
		wake_do_log(ringbuffer_repl_log(entry->ring));
	else
		BUG_ON(atomic_read(&entry->endios) < 0);
}

/* Endio routine for data header io. */
static void
header_endio(unsigned long error, void *context)
{
	endio(context, HEADER_ENDIO, error);
}

/* Endio routine for data io (ie. the bio data written for an entry). */
static void
data_endio(unsigned long error, void *context)
{
	endio(context, DATA_ENDIO, error);
}

/*
 * Place the data contained in bio asynchronously
 * into the replog's ring buffer.
 *
 * This can be void, because any allocation failure is fatal and any
 * IO errors will be reported asynchronously via dm_io() callbacks.
 */
static void
ringbuffer_write_entry(struct repl_log *l, struct bio *bio)
{
	int i;
	struct ringbuffer *ring = &l->ringbuffer;
	/*
	 * ringbuffer_alloc_entry returns an entry,
	 * including an initialized data_header.
	 */
	struct ringbuffer_entry *entry = ringbuffer_alloc_entry(ring, bio);
	struct data_header_disk *disk_header = alloc_data_header_disk(ring);
	struct data_header *header = entry->data.header;
	struct dev_io_params dio[] = {
		{ /* Data IO specs. */
		  &l->params.dev, header->pos.data, bio->bi_size,
		  .mem = {
			.type = DM_IO_BVEC,
			.offset = bio_offset(bio),
			.ptr.bvec = bio_iovec(bio),
		  },
		  .notify = { data_endio, entry }
		},
		{ /* Header IO specs. */
		  &l->params.dev, header->pos.header, DATA_HEADER_DISK_SIZE,
		  .mem = {
			.type = DM_IO_KMEM,
			.offset = 0,
			.ptr.addr = disk_header,
		  },
		  .notify = { header_endio, entry }
		},
	};

	DMDEBUG_LIMIT("in  %s %u", __func__, jiffies_to_msecs(jiffies));
	BUG_ON(!disk_header);
	entry->data.disk_header = disk_header;
	data_header_to_disk(BITMAP_ELEMS(l), disk_header, header);

	/* Take ringbuffer IO reference out vs. slink0. */
	ss_io_get(l->slink0->caller);

	/* Add to ordered list of active entries. */
	list_add_tail(E_WRITE_OR_COPY_LIST(entry), L_ENTRY_RING_WRITE_LIST(l));

	DMDEBUG_LIMIT("%s writing header to offset=%llu and bio for "
		      "sector=%llu to sector=%llu/size=%llu", __func__,
		      (unsigned long long) entry->data.header->pos.header,
		      (unsigned long long) bio_begin(bio),
		      (unsigned long long) entry->data.header->pos.data,
		      (unsigned long long) to_sector(dio[1].size));

	/*
	 * Submit the writes.
	 *
	 * 1 I/O count for header + 1 for data
	 */
	i = ARRAY_SIZE(dio);
	atomic_set(&entry->endios, i);
	while (i--)
		BUG_ON(dev_io(WRITE, ring, dio + i));

	DMDEBUG_LIMIT("out %s %u", __func__, jiffies_to_msecs(jiffies));
}

/* Endio routine for bio data reads of off the ring buffer. */
static void
read_bio_vec_endio(unsigned long error, void *context)
{
	struct ringbuffer_entry *entry = context;
	struct ringbuffer *ring = entry->ring;
	struct repl_log *l = ringbuffer_repl_log(ring);

	atomic_dec(&entry->endios);
	BUG_ON(!entry->bios.read);
	bio_endio(entry->bios.read, error ? -EIO : 0);
	entry->bios.read = NULL;
	entry_put(entry);
	wake_do_log(l);

	/* Release IO reference on slink0. */
	ss_io_put(l->slink0->caller);
}

/* Read bio data of off the ring buffer. */
static void
ringbuffer_read_bio_vec(struct repl_log *l,
			 struct ringbuffer_entry *entry, sector_t offset,
			 struct bio *bio)
{
	/* Data IO specs. */
	struct dev_io_params dio = {
		&l->params.dev,
		entry->data.header->pos.data + offset, bio->bi_size,
		.mem = {
			.type = DM_IO_BVEC,
			.offset = bio_offset(bio),
			.ptr.bvec = bio_iovec(bio),
		},
		.notify = { read_bio_vec_endio, entry }
	};

	DMDEBUG_LIMIT("in  %s %u", __func__, jiffies_to_msecs(jiffies));
	_BUG_ON_PTR(entry);
	entry_get(entry);
	atomic_inc(&entry->endios);

	/* Take IO reference out vs. slink0. */
	ss_io_get(l->slink0->caller);

	DMDEBUG("%s reading bio data bio for sector=%llu/size=%llu",
		__func__, (unsigned long long) bio_begin(bio),
		(unsigned long long) to_sector(dio.size));

	/*
	 * Submit the read.
	 */
	BUG_ON(dev_io(READ, &l->ringbuffer, &dio));
	DMDEBUG_LIMIT("out %s %u", __func__, jiffies_to_msecs(jiffies));
}

/*
 * Advances the ring buffer head pointer, updating the in-core data
 * and writing it to the backing store device, but only if there are
 * inactive entries (ie. those with copies to all slinks) at the head.
 *
 * Returns -ve errno on failure, otherwise the number of entries freed.
 */
static int
ringbuffer_advance_head(const char *caller, struct ringbuffer *ring)
{
	int r;
	unsigned entries_freed = 0;
	sector_t sectors_freed = 0;
	struct repl_log *l = ringbuffer_repl_log(ring);
	struct ringbuffer_entry *entry, *entry_last = NULL, *n;

	/* Count any freeable entries and remeber last one. */
	list_for_each_entry(entry, L_ENTRY_ORDERED_LIST(l),
			    lists.l[E_ORDERED]) {
		/* Can't advance past dirty entry. */
		if (entry_busy(l, ENTRY_SLINKS(entry)) ||
		    atomic_read(&entry->endios))
			break;

		BUG_ON(entry_endios_pending(entry));
		entry_last = entry;
		entries_freed++;
	}

	/* No entries to free. */
	if (!entries_freed)
		return 0;

	BUG_ON(!entry_last);

	/* Need safe version, because ringbuffer_free_entry removes entry. */
	list_for_each_entry_safe(entry, n, L_ENTRY_ORDERED_LIST(l),
				 lists.l[E_ORDERED]) {
		struct data_header *header = entry->data.header;

		BUG_ON(entry_busy(l, ENTRY_SLINKS(entry)) ||
		       entry_endios_pending(entry) ||
		       atomic_read(&entry->endios));

		/*
		 * If the entry wrapped around between the header and
		 * the data or if the next entry wraps, free the
		 * unused sectors at the end of the device.
		 */
		mutex_lock(&ring->mutex);
		sectors_freed += roundup_sectors(header->pos.data_sectors)
				 + sectors_skipped(ring, header);
		if (likely(ring->head != ring->tail))
			ring->head = next_start_adjust(ring, header);
		BUG_ON(ring->head >= ring->end);
		mutex_unlock(&ring->mutex);

		/* Don't access entry after this call! */
		ringbuffer_free_entry(entry);

		if (entry == entry_last)
			break;
	}

	DMDEBUG_LIMIT("%s (%s) advancing ring buffer head for %u "
		      "entries to %llu",
		      __func__, caller, entries_freed,
		      (unsigned long long) ring->head);

	/* Update ring buffer pointers in buffer header. */
	r = buffer_header_io(WRITE, l);
	if (likely(!r)) {
		/* Buffer header written... */
		mutex_lock(&ring->mutex);
		ring->free += sectors_freed;
		mutex_unlock(&ring->mutex);
	}

	/* Inform caller, that we're willing to receive more I/Os. */
	ClearRingBlocked(ring);
	ClearRingBufferFull(ring);
	notify_caller(l, WRITE, 0);
	if (unlikely(r < 0))
		ringbuffer_error(RING_BUFFER_HEAD_ERROR, ring, r);

	return r ? r : entries_freed;
}

/*
 * Advances the tail pointer after a successful
 * write of an entry to the log.
 */
static int
ringbuffer_advance_tail(struct ringbuffer_entry *entry)
{
	int r;
	sector_t new_tail, old_tail;
	struct ringbuffer *ring = entry->ring;
	struct repl_log *l = ringbuffer_repl_log(ring);
	struct data_header *header = entry->data.header;

/*
	if (unlikely(ring->tail != header->pos.header)) {
		DMERR("ring->tail %llu header->pos.header %llu",
		      (unsigned long long) ring->tail,
		      (unsigned long long) header->pos.header);
		BUG();
	}
*/

	mutex_lock(&ring->mutex);
	old_tail = ring->tail;
	/* Should we let this get out of sync? */
	new_tail = ring->tail = next_start_adjust(ring, header);
	BUG_ON(ring->tail >= ring->end);
	mutex_unlock(&ring->mutex);

	DMDEBUG_LIMIT("%s header->pos.header=%llu header->pos.data=%llu "
		      "ring->tail=%llu; "
		      "advancing ring tail pointer to %llu",
		      __func__,
		      (unsigned long long) header->pos.header,
		      (unsigned long long) header->pos.data,
		      (unsigned long long) ring->tail,
		      (unsigned long long) ring->tail);

	r = buffer_header_io(WRITE, l);
	if (unlikely(r < 0)) {
		/* Return the I/O size to ring->free. */
		mutex_lock(&ring->mutex);
		/* Make sure it wasn't changed. */
		BUG_ON(ring->tail != new_tail);
		ring->tail = old_tail;
		mutex_unlock(&ring->mutex);

		ringbuffer_error(RING_BUFFER_TAIL_ERROR, ring, r);
	}

	return r;
}

/* Open type <-> name mapping. */
static const struct dm_str_descr open_types[] = {
	{ OT_AUTO, "auto" },
	{ OT_OPEN, "open" },
	{ OT_CREATE, "create" },
};

/* Get slink policy flags. */
static inline int
_open_type(const char *name)
{
	return dm_descr_type(open_types, ARRAY_SIZE(open_types), name);
}

/* Get slink policy name. */
static inline const char *
_open_str(const int type)
{
	return dm_descr_name(open_types, ARRAY_SIZE(open_types), type);
}

/*
 * Amount of free sectors in ring buffer.  This function does not take
 * into account unused sectors at the end of the log device.
 */
static sector_t
ring_free(struct ringbuffer *ring)
{
	if (unlikely(ring->head == ring->next_avail))
		return ring->end - ring->start;
	else
		return ring->head > ring->tail ?
		       ring->head - ring->tail :
		       (ring->head - ring->start) + (ring->end - ring->tail);
}

static struct log_header *
alloc_log_header(struct repl_log *l)
{
	struct log_header *log_header =
		kzalloc(sizeof(*log_header), GFP_KERNEL);

	if (log_header)
		l->header.log = log_header;

	return log_header;
}

static void free_log_header(struct log_header *log_header,
			    struct ringbuffer *ring)
{
	kfree(log_header);
}

/* Create a new dirty log. */
static int
log_create(struct repl_log *l)
{
	int r;
	struct log_header *log_header = l->header.log;
	struct repl_dev *dev = &l->params.dev;
	struct repl_params *params = &l->params;
	struct ringbuffer *ring = &l->ringbuffer;

	DMINFO("%s: creating new log", __func__);
	_BUG_ON_PTR(log_header);

	/* First, create the in-memory representation */
	log_header->version.major = DM_REPL_LOG_MAJOR;
	log_header->version.minor =  DM_REPL_LOG_MINOR;
	log_header->version.subminor =  DM_REPL_LOG_MICRO;
	log_header->size = params->dev.size;
	log_header->buffer_header = dev->start + HEADER_SECTORS;

	/* Write log header to device. */
	r = log_header_io(WRITE, l);
	if (unlikely(r < 0)) {
		free_log_header(log_header, ring);
		l->header.log = NULL;
		return r;
	}

	/*
	 * Initialize the ring buffer.
	 *
	 * Start is behind the buffer header which follows the log header.
	 */
	ring->start = params->dev.start;
	ring->end = ring->start + params->dev.size;
	ring->start += 2 * HEADER_SECTORS;
	ring->head = ring->tail = ring->next_avail = ring->start;
	ring->free = ring_free(ring);

	DMDEBUG("%s start=%llu end=%llu free=%llu", __func__,
		(unsigned long long) ring->start,
		(unsigned long long) ring->end,
		(unsigned long long) ring->free);

	r = buffer_header_io(WRITE, l);
	if (unlikely(r < 0)) {
		free_log_header(log_header, ring);
		l->header.log = NULL;
		return r;
	}

	return 0;
}

/* Allocate a log_header and read header in from disk. */
static int
log_read(struct repl_log *l)
{
	int r;
	struct log_header *log_header = l->header.log;
	struct repl_dev *dev;
	struct ringbuffer *ring;
	char buf[BDEVNAME_SIZE];

	_BUG_ON_PTR(log_header);
	r = log_header_io(READ, l);
	if (unlikely(r < 0))
		return r;

	format_dev_t(buf, l->params.dev.dm_dev->bdev->bd_dev);

	/* Make sure that we can handle this version of the log. */
	if (memcmp(&log_header->version, &my_version, sizeof(my_version)))
		DMINFO("Found valid log header on %s", buf);
	else
		DM_EINVAL("On-disk version (%d.%d.%d) is "
			  "not supported by this module.",
			  log_header->version.major, log_header->version.minor,
			  log_header->version.subminor);

	/*
	 * Read in the buffer_header_disk
	 */
	r = buffer_header_io(READ, l);
	if (unlikely(r < 0))
		return r;

	dev = &l->params.dev;
	ring = &l->ringbuffer;

	/*
	 * We'll go with the size in the log header and
	 * adjust it in the worker thread when possible.
	 */
	ring->end = dev->start + log_header->size;
	ring->next_avail = ring->tail;

	/*
	 * The following call to ring_free is incorrect as the free
	 * space in the ring has to take into account the potential
	 * for unused sectors at the end of the device.  However, once
	 * do_log_init is called, any discrepencies are fixed there.
	 */
	ring->free = ring_free(ring);
	return 0;
}

/*
 * Open and read/initialize a replicator log backing store device.
 *
 * Must be called with dm_io client set up, because we dm_io to the device.
 */
/* Try to read an existing log or create a new one. */
static int
log_init(struct repl_log *l)
{
	int r;
	struct repl_params *p = &l->params;
	struct log_header *log_header = alloc_log_header(l);

	BUG_ON(!log_header);

	/* Read the log header in from disk. */
	r = log_read(l);
	switch (r) {
	case 0:
		/* Sucessfully read in the log. */
		if (p->open_type == OT_CREATE)
			DMERR("OT_CREATE requested: "
			      "initializing existing log!");
		else
			p->dev.size = l->header.log->size;

		break;
	case -EINVAL:
		/*
		 * Most likely this is the initial create of the log.
		 * But, if this is an open, return failure.
		 */
		if (p->open_type == OT_OPEN)
			DMWARN("Can't create new replog on open!");
		else
			/* Try to create a new log. */
			r = log_create(l);

		break;
	case -EIO:
		DMERR("log_read IO error!");
		break;
	default:
		DMERR("log_read failed with %d?", r);
	}

	return r;
}

/* Find a replog on the global list checking for bdev and start offset. */
static struct repl_log *
replog_find(dev_t dev, sector_t dev_start)
{
	struct repl_log *replog;

	list_for_each_entry(replog, &replog_list, lists.l[L_REPLOG]) {
		if (replog->params.dev.dm_dev->bdev->bd_dev == dev)
			return likely(replog->params.dev.start == dev_start) ?
				replog : ERR_PTR(-EINVAL);
	}

	return ERR_PTR(-ENOENT);
}

/* Clear all allocated slab objects in case of busys teardown. */
static void
ringbuffer_free_entries(struct ringbuffer *ring)
{
	struct ringbuffer_entry *entry, *n;
	struct repl_log *l = ringbuffer_repl_log(ring);

	list_for_each_entry_safe(entry, n, L_ENTRY_ORDERED_LIST(l),
				 lists.l[E_ORDERED]) {
		if (atomic_read(&entry->ref))
			sector_range_clear_busy(entry);

		ringbuffer_free_entry(entry);
	}
}

static void
replog_release(struct kref *ref)
{
	struct repl_log *l = container_of(ref, struct repl_log, ref);

	BUG_ON(!list_empty(L_REPLOG_LIST(l)));
	kfree(l);
}

/* Destroy replication log. */
static void
replog_destroy(struct repl_log *l)
{
	_BUG_ON_PTR(l);

	if (l->io.wq)
		destroy_workqueue(l->io.wq);

	free_log_header(l->header.log, &l->ringbuffer);
	ringbuffer_free_entries(&l->ringbuffer);
	ringbuffer_exit(&l->ringbuffer);
	kfree(l->io.buffer_header_disk);

	if (l->io.io_client)
		dm_io_client_destroy(l->io.io_client);
}

/* Release a reference on a replog freeing its resources on last drop. */
static int
replog_put(struct dm_repl_log *log, struct dm_target *ti)
{
	struct repl_log *l;

	_SET_AND_BUG_ON_L(l, log);
	dm_put_device(ti, l->params.dev.dm_dev);
	return kref_put(&l->ref, replog_release);
}

/* Return ringbuffer log device size. */
static sector_t
replog_dev_size(struct dm_dev *dm_dev, sector_t size_wanted)
{
	sector_t dev_size = i_size_read(dm_dev->bdev->bd_inode) >> SECTOR_SHIFT;

	return (!dev_size || size_wanted > dev_size) ? 0 : dev_size;
}

/* Get a reference on a replicator log. */
static void do_log(struct work_struct *ws);
static struct repl_log *
replog_get(struct dm_repl_log *log, struct dm_target *ti,
	   const char *path, struct repl_params *params)
{
	int i, r;
	dev_t dev;
	sector_t dev_size;
	struct dm_dev *dm_dev;
	char buf[BDEVNAME_SIZE];
	struct repl_log *l;
	struct dm_io_client *io_client;

	/* Get device with major:minor or device path. */
	r = dm_get_device(ti, path, FMODE_WRITE, &dm_dev);
	if (r) {
		DMERR("Failed to open replicator log device \"%s\" [%d]",
		      path, r);
		return ERR_PTR(r);
	}

	dev = dm_dev->bdev->bd_dev;
	dev_size = replog_dev_size(dm_dev, params->dev.size);
	if (!dev_size)
		return ERR_PTR(-EINVAL);

	/* Check if we already have a handle to this device. */
	mutex_lock(&list_mutex);
	l = replog_find(dev, params->dev.start);
	if (IS_ERR(l)) {
		mutex_unlock(&list_mutex);

		if (unlikely(l == ERR_PTR(-EINVAL))) {
			DMERR("Device open with different start offset!");
			dm_put_device(ti, dm_dev);
			return l;
		}
	} else {
		/* Cannot create if there is an open reference. */
		if (params->open_type == OT_CREATE) {
			mutex_unlock(&list_mutex);
			DMERR("OT_CREATE requested, but existing log found!");
			dm_put_device(ti, dm_dev);
			return ERR_PTR(-EPERM);
		}

		/* Take reference on replication log out. */
		kref_get(&l->ref);
		mutex_unlock(&list_mutex);

		DMINFO("Found existing replog=%s", format_dev_t(buf, dev));

		/* Found one, return it. */
		log->context = l;
		return l;
	}

	/*
	 * There is no open log, so time to look for one on disk.
	 */
	l = kzalloc(sizeof(*l), GFP_KERNEL);
	if (unlikely(!l)) {
		DMERR("failed to allocate replicator log context");
		dm_put_device(ti, dm_dev);
		return ERR_PTR(-ENOMEM);
	}

	/* Preserve constructor parameters. */
	l->params = *params;
	l->params.dev.dm_dev = dm_dev;

	log->context = l;
	l->replog = log;

	/* Init basic members. */
	rwlock_init(&l->lists.lock);
	rwlock_init(&l->lists.slinks.lock);
	INIT_LIST_HEAD(&l->lists.slinks.list);

	i = L_NR_LISTS;
	while (i--)
		INIT_LIST_HEAD(l->lists.l + i);

	spin_lock_init(&l->io.lock);
	bio_list_init(&l->io.in);

	/* Take first reference out. */
	kref_init(&l->ref);

	/* Initialize ring buffer. */
	r = ringbuffer_init(&l->ringbuffer);
	if (unlikely(r < 0)) {
		DMERR("failed to initialize ring buffer %d", r);
		goto bad;
	}

	/* Preallocate to avoid stalling on OOM. */
	l->io.buffer_header_disk =
		kzalloc(dm_round_up(sizeof(l->io.buffer_header_disk),
			to_bytes(1)), GFP_KERNEL);
	if (unlikely(!l->io.buffer_header_disk)) {
		DMERR("failed to allocate ring buffer disk header");
		r = -ENOMEM;
		goto bad;
	}

	/*
	 * ringbuffer_io will only be called with I/O sizes of ti->split_io
	 * or fewer bytes, which are boundary checked too.
	 *
	 * The io_client needs to be setup before we can call log_init below.
	 */
	io_client = dm_io_client_create(DEFAULT_BIOS * (1 + BIO_MAX_PAGES));
	if (unlikely(IS_ERR(io_client))) {
		DMERR("dm_io_client_create failed!");
		r = PTR_ERR(io_client);
		goto bad;
	} else
		l->io.io_client = io_client;

	/* Create one worker per replog. */
	l->io.wq = create_singlethread_workqueue(DAEMON);
	if (unlikely(!l->io.wq)) {
		DMERR("failed to create workqueue");
		r = -ENOMEM;
		goto bad;
	} else
		INIT_WORK(&l->io.ws, do_log);

	/* Try to read an existing log or create a new one. */
	r = log_init(l);
	if (unlikely(r < 0))
		goto bad;

	stats_init(l);
	ClearLogDevelStats(l);

	/* Start out suspended, dm core will resume us. */
	SetRingSuspended(&l->ringbuffer);
	SetRingBlocked(&l->ringbuffer);

	/* Link the new replog into the global list */
	mutex_lock(&list_mutex);
	list_add_tail(L_REPLOG_LIST(l), &replog_list);
	mutex_unlock(&list_mutex);

	return l;

bad:
	replog_destroy(l);
	return ERR_PTR(r);
}

/* Account and entry for fallbehind and put on copy list. */
static void
entry_account_and_copy(struct ringbuffer_entry *entry)
{
	unsigned long slink_nr;
	struct repl_log *l;

	_BUG_ON_PTR(entry);
	l = ringbuffer_repl_log(entry->ring);
	_BUG_ON_PTR(l);

	/* If there's no outstanding copies for this entry -> bail out. */
	if (!entry_busy(l, ENTRY_SLINKS(entry)))
		return;

	_BUG_ON_PTR(entry->ring);

	/* Account for fallbehind. */
	for_each_bit(slink_nr, ENTRY_SLINKS(entry), l->slink.max) {
		struct dm_repl_slink *slink = slink_find(l, slink_nr);

		if (!IS_ERR(slink))
			slink_fallbehind_inc(slink, entry);
	}

	/*
	 * Initiate copies across all SLINKS by moving to
	 * copy list in order. Because we are already processing
	 * do_log before do_slink_ios(), we need not call wake_do_log.
	 */
	list_move_tail(E_WRITE_OR_COPY_LIST(entry), L_SLINK_COPY_LIST(l));
}

/* Adjust the log size. */
static void
do_log_resize(struct repl_log *l)
{
	int r = 0;
	sector_t size_cur = l->header.log->size,
		 size_dev = l->params.dev.size;

	/* If size change requested, adjust when possible. */
	if (size_cur != size_dev) {
		int write = 0;
		int grow = size_dev > size_cur;
		struct ringbuffer *ring = &l->ringbuffer;

		mutex_lock(&ring->mutex);

		/* Ringbuffer empty easy case. */
		r = ringbuffer_empty_nolock(ring);
		if (r) {
			ring->head = ring->tail = \
			ring->next_avail = ring->start;
			write = true;
		/* Ringbuffer grow easy case. */
		/* FIXME: check for device size valid! */
		} else if (grow) {
			write = true;
		/* Ringbuffer shrink case. */
		} else if (ring->head < ring->tail &&
			   max(ring->tail, ring->next_avail) < size_dev)
			write = true;

		if (write) {
			ring->end = l->header.log->size = size_dev;
			ring->free = ring_free(ring);
			mutex_unlock(&ring->mutex);

			r = log_header_io(WRITE, l);
			if (r)
				DMERR("failed to write log header "
				      "while resizing!");
			else
				DMINFO("%sing ringbuffer to %llu sectors",
				       grow ? "grow" : "shrink",
				       (unsigned long long) size_dev);
		} else {
			mutex_unlock(&ring->mutex);
			r = 0;
		}

		ClearLogResize(l);
	}
}

/*
 * Initialize logs incore metadata.
 */
static void
do_log_init(struct repl_log *l)
{
	int entries = 0, r;
	sector_t sector;
	struct ringbuffer *ring = &l->ringbuffer;
	struct ringbuffer_entry *entry;

	/* NOOP in case we're initialized already. */
	if (TestSetLogInitialized(l))
		return;

	DMDEBUG("%s ring->head=%llu ring->tail=%llu",
		__func__,
		(unsigned long long) ring->head,
		(unsigned long long) ring->tail);

	/* Nothing to do if the log is empty */
	if (ringbuffer_empty(ring))
		goto out;

	/*
	 * Start at head and walk to tail, queuing I/O to slinks.
	 */
	for (sector = ring->head; sector != ring->tail;) {
		struct data_header *header;

		entry = ringbuffer_alloc_entry(ring, NULL); /* No bio alloc. */
		header = entry->data.header;
		r = data_header_io(READ, l, header, sector);
		if (unlikely(r < 0)) {
			/*
			 * FIXME: as written, this is not recoverable.
			 * 	  All ios have to be errored because
			 * 	  of RingBufferError().
			 */
			ringbuffer_error(RING_BUFFER_HEADER_ERROR, ring,
					  PTR_ERR(entry));
			ringbuffer_free_entry(entry);
			break;
		} else {
			/* Set synchronous I/O policy mask. */
			set_sync_mask(l, entry);

			/* Adjust ring->free for any skipped sectors. */
			ring->free -= sectors_skipped(ring, header);

			/*
			 * Mark sector range busy in case the
			 * entry hasn't been copied to slink0 yet.
			 */
			if (slink_test_bit(0, ENTRY_SLINKS(entry)))
				sector_range_mark_busy(entry);

			/*
			 * Account entry for fallbehind and
			 * put on slink copy list if needed.
			 */
			entry_account_and_copy(entry);

			/* Advance past this entry. */
			sector = unlikely(next_entry_wraps(header)) ?
				 ring->start : next_start(header);
			entries++;
		}
	}

	DMINFO("found %d entries in the log", entries);

	/* Advance head past any already copied entries. */
	r = ringbuffer_advance_head(__func__, ring);
	if (r >= 0)
		DMINFO("%d entries freed", r);
	else
		DMERR_LIMIT("Error %d advancing ring buffer head!", r);

out:
	ClearRingBlocked(ring);
	notify_caller(l, READ, 0);
}

/*
 * Conditionally endio a bio, when no copies on sync slinks are pending.
 *
 * In case an error on site link 0 occured, the bio will be errored!
 */
/*
 * FIXME: in case of no synchronous site links, the entry hasn't hit
 * 	  the local device yet, so a potential io error on it ain't
 * 	  available while endio processing the bio.
 */
static void
entry_nosync_endio(struct ringbuffer_entry *entry)
{
	struct bio *bio = entry->bios.write;

	/* If all sync slinks processed (if any). */
	if (bio && !entry_busy(ringbuffer_repl_log(entry->ring),
			       ENTRY_SYNC(entry))) {
		DMDEBUG_LIMIT("Calling bio_endio with %u, bi_endio %p",
			      entry->data.header->region.size, bio->bi_end_io);

		/* Only error in case of site link 0 errors. */
		bio_endio(bio,
			  slink_test_bit(0, ENTRY_ERROR(entry)) ? -EIO : 0);
		entry->bios.write = NULL;
	}
}

/*
 * Error endio the entries bio, mark the ring
 * buffer entry invalid and advance the tail.
 */
static void
entry_endio_invalid(struct repl_log *l, struct ringbuffer_entry *entry)
{
	int r;

	DMDEBUG_LIMIT("entry %p header_err %lu, data_err %lu", entry,
		      entry->data.error.header, entry->data.error.data);
	BUG_ON(!entry->bios.write);
	bio_endio(entry->bios.write, -EIO);

	/* Mark the header as invalid so it is not queued for slink copies. */
	r = ringbuffer_mark_entry_invalid(&l->ringbuffer, entry);
	if (unlikely(r < 0)) {
		/* FIXME: XXX
		 * Take the device offline?
		 */
		DMERR("%s: I/O to sector %llu of log device "
				"failed, and failed to mark header "
				"invalid.  Taking device off-line.",
				__func__,
				(unsigned long long)
				entry->data.header->region.sector);
	}

	ringbuffer_free_entry(entry);
}

static inline int
cc_error_read(struct slink_copy_context *cc)
{
	return cc->error[ERR_DISK].read ||
	       cc->error[ERR_RAM].read;
}

static inline int
cc_error_write(struct slink_copy_context *cc)
{
	return cc->error[ERR_DISK].write ||
	       cc->error[ERR_RAM].write;
}

static inline int
cc_error(struct slink_copy_context *cc)
{
	return cc_error_read(cc) ||
	       cc_error_write(cc);
}

/*
 * Set state of slink_copy_context to completion.
 *
 * slink_copy_conmtext is the object describing a *single* copy
 * of a particular ringbuffer entry to *one* site link.
 *
 * Called with list lock held.
 */
static void
slink_copy_complete(struct slink_copy_context *cc)
{
	int slink_nr;
	struct dm_repl_slink *slink = cc->slink;
	struct ringbuffer_entry *entry = cc->entry;
	struct repl_log *l = ringbuffer_repl_log(entry->ring);

	_BUG_ON_PTR(slink);
	_BUG_ON_PTR(slink->caller);
	_BUG_ON_PTR(entry);
	_BUG_ON_PTR(l);
	slink_nr = slink->ops->slink_number(slink);
	_BUG_ON_SLINK_NR(l, slink_nr);

	/* The entry is no longer under I/O accross this slink. */
	slink_clear_bit(slink_nr, ENTRY_IOS(entry));

	/* The slink is no longer under I/O. */
	slink_clear_bit(slink_nr, LOG_SLINKS_IO(l));

	/* Update the I/O threshold counters */
	slink_fallbehind_dec(slink, entry);

	DMDEBUG_LIMIT("processing I/O completion for slink%d", slink_nr);

	if (unlikely(cc_error(cc)) &&
		     slink_test_bit(slink_nr, LOG_SLINKS(l))) {
		slink_set_bit(slink_nr, ENTRY_ERROR(entry));
		DMERR_LIMIT("copy on slink%d failed", slink_nr);
	} else {
		/* Flag entry copied to slink_nr. */
		slink_clear_bit(slink_nr, ENTRY_SLINKS(entry));

		/* Reset any sync copy request on entry to slink_nr. */
		slink_clear_bit(slink_nr, ENTRY_SYNC(entry));
	}

	free_copy_context(cc, entry->ring);

	/* Release slink state reference after completion. */
	ss_io_put(slink->caller);
}

/* Check for entry with endios pending at ring buffer head. */
static int
ringbuffer_head_busy(struct repl_log *l)
{
	int r;
	struct ringbuffer_entry *entry;

	mutex_lock(&l->ringbuffer.mutex);

	/*
	 * This shouldn't happen.  Presumably this function is called
	 * when the ring buffer is overflowing, so you would expect
	 * at least one entry on the list!
	 */
	if (unlikely(list_empty(L_ENTRY_ORDERED_LIST(l))))
		goto out_unlock;

	/* The first entry on this list is the ring head. */
	entry = list_first_entry(L_ENTRY_ORDERED_LIST(l),
				 struct ringbuffer_entry,
				 lists.l[E_ORDERED]);
	r = entry_endios_pending(entry);
	mutex_unlock(&l->ringbuffer.mutex);
	return r;

out_unlock:
	mutex_unlock(&l->ringbuffer.mutex);
	DMERR_LIMIT("%s called with an empty ring!", __func__);
	return 0;
}

/*
 * Find the first ring buffer entry with outstanding copies
 * and record each slink that hasn't completed the copy I/O.
 */
static int
find_slow_slinks(struct repl_log *l, uint64_t *slow_slinks)
{
	int r = 0;
	struct ringbuffer_entry *entry;

	DMDEBUG("%s", __func__);
	/* Needed for E_COPY_CONTEXT_LIST() access. */
	list_for_each_entry(entry, L_SLINK_COPY_LIST(l),
			    lists.l[E_WRITE_OR_COPY]) {
		int slink_nr;
		struct slink_copy_context *cc;

		/*
		 * There may or may not be slink copy contexts hanging
		 * off of the entry. If there aren't any, it means the
		 * copy has already completed.
		 */
		list_for_each_entry(cc, E_COPY_CONTEXT_LIST(entry), list) {
			struct dm_repl_slink *slink = cc->slink;

			slink_nr = slink->ops->slink_number(slink);
			_BUG_ON_SLINK_NR(l, slink_nr);
			slink_set_bit(slink_nr, slow_slinks);
			r = 1;
			break;
		}

	}

	if (r) {
		/*
		 * Check to see if all slinks are slow!  slink0 should
		 * not be slow, one would hope!  But, we need to deal
		 * with that case.
		 */
		if (slink_test_bit(0, slow_slinks)) {
			struct slink_state *ss;

			_BUG_ON_PTR(l->slink0);
			ss = l->slink0->caller;
			_BUG_ON_PTR(ss);

			/*
			 * If slink0 is slow, there is
			 * obviously some other problem!
			 */
			DMWARN("%s: slink0 copy taking a long time "
			       "(%u ms)", __func__,
			       jiffies_to_msecs(jiffies) -
			       jiffies_to_msecs(ss->fb.head_jiffies));
			r = 0;
		} else if (!memcmp(slow_slinks, LOG_SLINKS(l),
				   sizeof(LOG_SLINKS(l))))
			r = 0;

		if (!r)
			memset(slow_slinks, 0, BITMAP_SIZE(l));
	}

	return r;
}

/* Check if entry has ios scheduled on slow slinks. */
static int
entry_is_slow(struct ringbuffer_entry *entry, uint64_t *slow_slinks)
{
	unsigned long slink_nr;

	for_each_bit(slink_nr, ENTRY_IOS(entry),
		     ringbuffer_repl_log(entry->ring)->slink.max) {
		if (test_bit(slink_nr, (void *) slow_slinks))
			return 1;
	}

	return 0;
}

/*
 * Cancel slink_copies to the slinks specified in the slow_slinks bitmask.
 *
 * This function starts at the beginning of the ordered slink copy list
 * and frees up ring buffer entries which are waiting only for the slow
 * slinks.  This is accomplished by marking the regions under I/O as
 * dirty in the slink dirty logs and advancing the ring head pointer.
 * Once a ring buffer entry is encountered that is waiting for more
 * than just the slinks specified, the function terminates.
 */
static void
repl_log_cancel_copies(struct repl_log *l, uint64_t *slow_slinks)
{
	int r;
	unsigned long slink_nr;
	struct ringbuffer *ring = &l->ringbuffer;
	struct ringbuffer_entry *entry;
	struct dm_repl_slink *slink;
	struct data_header_region *region;
	struct slink_copy_context *cc, *n;
	static uint64_t flush_slinks[BITMAP_ELEMS_MAX],
			flush_error[BITMAP_ELEMS_MAX],
			stall_slinks[BITMAP_ELEMS_MAX];

	DMDEBUG("%s", __func__);
	memset(flush_slinks, 0, BITMAP_SIZE(l));
	memset(flush_error, 0, BITMAP_SIZE(l));
	memset(stall_slinks, 0, BITMAP_SIZE(l));

	/* First walk the entry list setting region nosync state. */
	list_for_each_entry(entry, L_SLINK_COPY_LIST(l),
			    lists.l[E_WRITE_OR_COPY]) {
		if (!entry_is_slow(entry, slow_slinks) ||
		    entry_endios_pending(entry))
			break;

		region = &entry->data.header->region;

		/* Needed for E_COPY_CONTEXT_LIST() access. */
		read_lock_irq(&l->lists.lock);

		/* Walk the copy context list. */
		list_for_each_entry_safe(cc, n, E_COPY_CONTEXT_LIST(entry),
					 list) {
			slink = cc->slink;
			_BUG_ON_PTR(slink);
			slink_nr = slink->ops->slink_number(slink);
			_BUG_ON_SLINK_NR(l, slink_nr);

			/* Stall IO policy set. */
			if (slink_stall(slink)) {
				DMINFO_LIMIT("slink=%lu stall", slink_nr);
				/*
				 * Keep stall policy in bitarray
				 * to avoid policy change race.
				 */
				slink_set_bit(slink_nr, stall_slinks);
				l->stats.stall++;
				continue;
			}

			r = slink->ops->in_sync(slink,
						region->dev, region->sector);
			if (r)
				slink_set_bit(slink_nr, flush_slinks);

			r = slink->ops->set_sync(slink, region->dev,
						 region->sector, 0);
			BUG_ON(r);
		}

		read_unlock_irq(&l->lists.lock);
	}

	/*
	 * The dirty logs of all devices on this slink must be flushed in
	 * this second step for performance reasons before advancing the
	 * ring head.
	 */
	for_each_bit(slink_nr, (void *) flush_slinks, l->slink.max) {
		slink = slink_find(l, slink_nr);
		r = slink->ops->flush_sync(slink);

		if (unlikely(r)) {
			/*
			 * What happens when the region is
			 * marked but not flushed? Will we
			 * still get an endio?
			 * This code assumes not. -JEM
			 *
			 * If a region is marked sync, the slink
			 * code won't select it for resync,
			 * Hence we got to keep the buffer entries,
			 * because we can't assume resync is
			 * ever going to happen. -HJM
			 */
			DMERR_LIMIT("error flushing dirty logs "
				    "on slink=%d",
				    slink->ops->slink_number(slink));
			slink_set_bit(slink_nr, flush_error);
		} else {
			/* Trigger resynchronization on slink. */
			r = slink->ops->resync(slink, 1);
			BUG_ON(r);
		}
	}

	/* Now release copy contexts, declaring copy completion. */
	list_for_each_entry(entry, L_SLINK_COPY_LIST(l),
			    lists.l[E_WRITE_OR_COPY]) {
		if (!entry_is_slow(entry, slow_slinks) ||
		    entry_endios_pending(entry))
			break;

		/* Needed for E_COPY_CONTEXT_LIST() access. */
		write_lock_irq(&l->lists.lock);

		/* Walk the copy context list. */
		list_for_each_entry_safe(cc, n, E_COPY_CONTEXT_LIST(entry),
					 list) {
			slink = cc->slink;
			slink_nr = slink->ops->slink_number(slink);

			/* Stall IO policy set. */
			if (slink_test_bit(slink_nr, stall_slinks))
				continue;

			/* Error flushing dirty log, keep entry. */
			if (unlikely(slink_test_bit(slink_nr, flush_error)))
				continue;

			BUG_ON(list_empty(&cc->list));
			list_del_init(&cc->list);

			/* Do not reference cc after this call. */
			slink_copy_complete(cc);
		}

		write_unlock_irq(&l->lists.lock);
	}

	/*
	 * Now advance the head pointer to free up room in the ring buffer.
	 * In case we fail here, we've got both entries in the ring buffer
	 * *and* nosync regions to recover.
	 */
	ringbuffer_advance_head(__func__, ring);
}

/*
 * This function is called to free up some ring buffer space when a
 * full condition is encountered.  The basic idea is to walk through
 * the list of outstanding copies and see which slinks are slow to
 * respond.  Then, we free up as many of the entries as possible and
 * advance the ring head.
 */
static void
ring_check_fallback(struct ringbuffer *ring)
{
	int r;
	struct repl_log *l = ringbuffer_repl_log(ring);
	static uint64_t slow_slinks[BITMAP_ELEMS_MAX];

	DMDEBUG("%s", __func__);
	/*
	 * First, check to see if we can simply
	 * free entries at the head of the ring.
	 */
	r = ringbuffer_advance_head(__func__, ring);
	if (r > 0) {
		DMINFO_LIMIT("%s: able to advance head", __func__);
		return;
	}

	/*
	 * Check to see if any entries at the head of the ring buffer
	 * are currently queued for completion.  If they are, then
	 * don't do anything here; simply allow the I/O completion to
	 * proceed.
	 */
	r = ringbuffer_head_busy(l);
	if (r) {
		DMINFO_LIMIT("%s: endios pending.", __func__);
		return;
	}

	/*
	 * Take a look at the first entry in the copy list with outstanding
	 * I/O and figure out which slinks are holding up progress.
	 */
	memset(slow_slinks, 0, BITMAP_SIZE(l));

	r = find_slow_slinks(l, slow_slinks);
	if (r) {
		DMINFO_LIMIT("%s: slow slinks found.", __func__);
		/*
		 * Now, walk the copy list from the beginning and free
		 * any entry which is awaiting copy completion from the
		 * slow slinks. Once we hit an entry which is awaiting
		 * completion from an slink other than the slow ones, we stop.
		 */
		repl_log_cancel_copies(l, slow_slinks);
	} else
		DMINFO_LIMIT("%s: no slow slinks found.", __func__);
}

static int
entry_error(struct ringbuffer_entry *entry)
{
	struct entry_data *data = &entry->data;

	if (unlikely(data->error.header ||
		     data->error.data)) {
		if (data->error.header)
			ringbuffer_error(RING_BUFFER_HEADER_ERROR,
					  entry->ring, -EIO);

		if (data->error.data)
			ringbuffer_error(RING_BUFFER_DATA_ERROR,
					  entry->ring, -EIO);

		return -EIO;
	}

	return 0;
}

/*
 *  Ring buffer endio processing.  The ring buffer tail cannot be
 *  advanced until both the data and data_header portions are written
 *  to the log, AND all of the buffer I/O's preceding this one are in
 *  the log have completed.
 */
#define	MIN_ENTRIES_INACTIVE	128
static void
do_ringbuffer_endios(struct repl_log *l)
{
	int r;
	unsigned count = 0;
	struct ringbuffer *ring = &l->ringbuffer;
	struct ringbuffer_entry *entry, *entry_last = NULL, *n;

	DMDEBUG_LIMIT("%s", __func__);

	/*
	 * The l->lists.entry.io list is sorted by on-disk order. The first
	 * entry in the list will correspond to the current ring buffer tail
	 * plus the size of the last valid entry.  We process endios in
	 * order so that the tail is not advanced past unfinished entries.
	 */

	list_for_each_entry(entry, L_ENTRY_RING_WRITE_LIST(l),
			    lists.l[E_WRITE_OR_COPY]) {
		if (atomic_read(&entry->endios))
			break;

		count++;
		entry_last = entry;
	}

	/* No inactive entries on list -> bail out. */
	if (!count)
		return;

	BUG_ON(!entry_last);

	/* Update the tail pointer once for a list of entries. */
	DMDEBUG_LIMIT("%s advancing ring buffer tail %u entries",
		      __func__, count);
	r = ringbuffer_advance_tail(entry_last);

	/* Now check for any errored entries. */
	list_for_each_entry_safe(entry, n, L_ENTRY_RING_WRITE_LIST(l),
				 lists.l[E_WRITE_OR_COPY]) {
		struct entry_data *data = &entry->data;

		_BUG_ON_PTR(data->disk_header);
		free_data_header_disk(data->disk_header, ring);
		data->disk_header = NULL;

		ss_io_put(l->slink0->caller);

		/*
		 * Tail update error before or header/data
		 * ring buffer write error -> error bio.
		 */
		if (unlikely(r || entry_error(entry)))
			entry_endio_invalid(l, entry);
		else {
			/*
			 * Handle the slink policy for sync vs. async here.
			 *
			 * Synchronous link means, that endio needs to be
			 * reported *after* the slink copy of the entry
			 * succeeded and *not* after the entry got stored
			 * in the ring buffer. -HJM
			 */
			/* Endio bio in case of no sync slinks. */
			entry_nosync_endio(entry);

			/*
			 * Account entry for fallbehind
			 * and put on slink copy list.
			 *
			 * WARNING: removes entry from write list!
			 */
			entry_account_and_copy(entry);
		}

		if (entry == entry_last)
			break;
	}

	/* On ring full, check if we need to fall back to bitmap mode. */
	if (RingBufferFull(ring))
		ring_check_fallback(ring);

	/* Wake up any waiters. */
	wake_up(&ring->flushq);
}

/*
 * Work all site link endios (i.e. all slink_copy contexts).
 */
static struct slink_copy_context *
cc_pop(struct repl_log *l)
{
	struct slink_copy_context *cc;

	/* Pop copy_context from copy contexts list. */
	if (list_empty(L_SLINK_ENDIO_LIST(l)))
		cc = NULL;
	else {
		cc = list_first_entry(L_SLINK_ENDIO_LIST(l),
				      struct slink_copy_context, list);
		list_del(&cc->list);
	}

	return cc;
}

static void
do_slink_endios(struct repl_log *l)
{
	int r;
	LIST_HEAD(slink_endios);
	struct ringbuffer *ring = &l->ringbuffer;
	struct ringbuffer_entry *entry = NULL;
	struct data_header *header;

	DMDEBUG_LIMIT("%s", __func__);

	while (1) {
		int slink_nr;
		struct slink_copy_context *cc;
		struct dm_repl_slink *slink;

		/* Pop copy_context from copy contexts list. */
		write_lock_irq(&l->lists.lock);
		cc = cc_pop(l);
		if (!cc) {
			write_unlock_irq(&l->lists.lock);
			break;
		}

		/* No active copy on endios list! */
		BUG_ON(atomic_read(&cc->cnt));

		slink = cc->slink;
		entry = cc->entry;

		/* Do not reference cc after this call. */
		slink_copy_complete(cc);

		write_unlock_irq(&l->lists.lock);

		_BUG_ON_PTR(slink);
		_BUG_ON_PTR(slink->ops);
		_BUG_ON_PTR(entry);

		/*
		 * All reads are serviced from slink0 (for now), so mark
		 * sectors as no longer under I/O once the copy to slink0
		 * is complete.
		 */
		slink_nr = slink->ops->slink_number(slink);
		_BUG_ON_SLINK_NR(l, slink_nr);
		if (!slink_nr)
			sector_range_clear_busy(entry);

		/* If all synchronous site links processed, endio here. */
		entry_nosync_endio(entry);

		/*
		 * Update data header on disk to reflect the ENTRY_SLINK
		 * change so that we don't pick up a copy which has
		 * finished again on restart.
		 *
		 * FIXME: this throttles throughput on fast site links.
		 */
		header = entry->data.header;
		_BUG_ON_PTR(header);
		r = data_header_io(WRITE, l, header, header->pos.header);
		if (unlikely(r < 0)) {
			DMERR_LIMIT("Writing data header at %llu",
				    (unsigned long long) header->pos.header);

			/* Flag error on all slinks because we can't recover. */
			for_each_bit(slink_nr, LOG_SLINKS(l), l->slink.max)
				slink_set_bit(slink_nr, ENTRY_ERROR(entry));
		}
	}

	/*
	 * If all slinks are up-to-date, then we can advance
	 * the ring buffer head pointer and remove the entry
	 * from the slink copy list.
	 */
	r = ringbuffer_advance_head(__func__, ring);
	if (r < 0)
		DMERR_LIMIT("Error %d advancing ring buffer head!", r);
}

/*
 * Read a bio (partially) of off log:
 *
 * o check if bio's data is completely in the log
 *   -> redirect N reads to the log
 *   (N = 1 for simple cases to N > 1)
 * o check if bio's data is split between log and LD
 *   -> redirect N parts to the log
 *   -> redirect 1 part to the LD
 * o if bio'data is on the LD
 */
#define DO_INFO1 \
DMDEBUG_LIMIT("%s overlap for bio_range.start=%llu bio_range.end=%llu " \
	      "entry_range.start=%llu entry_range.end=%llu", __func__, \
	      (unsigned long long) bio_range.start, \
	      (unsigned long long) bio_range.end, \
	      (unsigned long long) entry_range.start, \
	      (unsigned long long) entry_range.end);
#define DO_INFO2 \
DMDEBUG_LIMIT("%s NO overlap for bio_range.start=%llu bio_range.end=%llu " \
	      "entry_range.start=%llu entry_range.end=%llu", __func__, \
	      (unsigned long long) bio_range.start, \
	      (unsigned long long) bio_range.end, \
	      (unsigned long long) entry_range.start, \
	      (unsigned long long) entry_range.end);
static int
bio_read(struct repl_log *l, struct bio *bio, struct list_head *buckets[2])
{
	int r;
	unsigned i;
	struct ringbuffer_entry *entry;
	struct sector_range bio_range = {
		.start = bio_begin(bio),
		.end = bio_end(bio),
	}, entry_range;

	/* Figure overlapping areas. */
	r = 0;
	for (i = 0; buckets[i] && i < 2; i++) {
		/* Find entry from end of bucket. */
		list_for_each_entry_reverse(entry, buckets[i],
					    lists.l[E_BUSY_HASH]) {
			entry_range.start = entry->data.header->region.sector;
			entry_range.end = entry_range.start +
			round_up_to_sector(entry->data.header->region.size);

			if (ranges_overlap(&bio_range, &entry_range)) {
				if (bio_range.start >= entry_range.start &&
				    bio_range.end <= entry_range.end) {
					sector_t off;

					entry->bios.read = bio;
					DO_INFO1;
					off = bio_range.start -
					      entry_range.start;
					ringbuffer_read_bio_vec(l, entry,
								 off, bio);
					return 0;
				} else
					DO_INFO2;
			} else
				goto out;
		}
	}

	/*
	 * slink->ops->io() will check if region is in sync
	 * and return -EAGAIN in case the I/O needs
	 * to be delayed. Returning -ENODEV etc. is fatal.
	 *
	 * WARNING: bio->bi_bdev changed after return!
	 */
	/*
	 * Reading of off log:
	 * o check if bio's data is completely in the log
	 *   -> redirect N reads to the log
	 *   (N = 1 for simple cases to N > 1)
	 * o check if bio's data is split between log and LD
	 *   -> redirect N parts to the log
	 *   -> redirect 1 part to the LD
	 * o if bio'data is on the LD
	 */
out:
	return -EAGAIN;
}
#undef DO_INFO1
#undef DO_INFO2

static int
ringbuffer_read_bio(struct repl_log *l, struct bio *bio)
{
	int r;
	struct ringbuffer *ring = &l->ringbuffer;
	struct dm_repl_slink *slink0 = slink_find(l, 0);
	struct list_head *buckets[2];

	if (IS_ERR(slink0))
		return PTR_ERR(slink0);

	/*
	 * Check if there's writes pending to the area the bio intends
	 * to read and if so, satisfy request from ring buffer.
	 */
	/* We've got writes in the log for this bio. */
	r = ringbuffer_writes_pending(&ring->busy_sectors, bio, buckets);
	if (r) {
		atomic_inc(&l->stats.writes_pending);
		r = bio_read(l, bio, buckets);
	/* Simple case: no writes in the log for this bio. */
	} else {
		/*
		 * slink->ops->io() will check if region is in sync
		 * and return -EAGAIN in case the I/O needs
		 * to be delayed. Returning -ENODEV etc. is fatal.
		 *
		 * WARNING: bio->bi_bdev changed after return!
		 */
		r = slink0->ops->io(slink0, bio, 0);
		if (r < 0)
			/* No retry possibility is fatal. */
			BUG_ON(unlikely(r != -EAGAIN));
	}

	return r;
}

/* Work on any IOS queued into the ring buffer. */
static void
do_ringbuffer_ios(struct repl_log *l)
{
	int r;
	struct bio *bio;
	struct bio_list ios_in;

	DMDEBUG_LIMIT("%s %u start", __func__, jiffies_to_msecs(jiffies));

	bio_list_init(&ios_in);

	/* Quickly grab the bio input list. */
	spin_lock(&l->io.lock);
	bio_list_merge(&ios_in, &l->io.in);
	bio_list_init(&l->io.in);
	spin_unlock(&l->io.lock);

	while ((bio = bio_list_pop(&ios_in))) {
		/* FATAL: ring buffer I/O error ocurred! */
		if (unlikely(RingBufferError(&l->ringbuffer)))
			bio_endio(bio, -EIO);
		else if (bio_data_dir(bio) == READ) {
			r = ringbuffer_read_bio(l, bio);
			/* We have to wait. */
			if (r < 0) {
				bio_list_push(&ios_in, bio);
				break;
			}
		} else
			/* Insert new write bio into ring buffer. */
			ringbuffer_write_entry(l, bio);
	}

	DMDEBUG_LIMIT("%s %u end ", __func__, jiffies_to_msecs(jiffies));

	if (!bio_list_empty(&ios_in)) {
		spin_lock(&l->io.lock);
		bio_list_merge_head(&l->io.in, &ios_in);
		spin_unlock(&l->io.lock);
	}
}

/*
 * Set any slinks requested by the recovery callback to accessible.
 *
 * Needs doing in the main worker thread in order to avoid
 * a race between do_slink_ios() and slink_recover_callback(),
 * which is being called asynchrnously from the slink module.
 */
static void
do_slinks_accessible(struct repl_log *l)
{
	unsigned long slink_nr;

	/* Reset any requested inaccessible bits. */
	for_each_bit(slink_nr, LOG_SLINKS(l), l->slink.max) {
		if (slink_test_bit(slink_nr, LOG_SLINKS_SET_ACCESSIBLE(l))) {
			slink_clear_bit(slink_nr, LOG_SLINKS_INACCESSIBLE(l));
			slink_clear_bit(slink_nr, LOG_SLINKS_SET_ACCESSIBLE(l));
		}
	}
}

/* Drop reference on a copy context and put on endio list on last drop. */
static void
slink_copy_context_put(struct slink_copy_context *cc)
{
	DMDEBUG_LIMIT("%s", __func__);

	if (atomic_dec_and_test(&cc->cnt)) {
		int slink_nr;
		unsigned long flags;
		struct repl_log *l = ringbuffer_repl_log(cc->entry->ring);
		struct dm_repl_slink *slink = cc->slink;

		/* last put, schedule completion */
		DMDEBUG_LIMIT("last put, scheduling do_log");

		_BUG_ON_PTR(l);
		_BUG_ON_PTR(slink);
		slink_nr = slink->ops->slink_number(slink);
		_BUG_ON_SLINK_NR(l, slink_nr);

		write_lock_irqsave(&l->lists.lock, flags);
		BUG_ON(list_empty(&cc->list));
		list_move_tail(&cc->list, L_SLINK_ENDIO_LIST(l));
		write_unlock_irqrestore(&l->lists.lock, flags);

		wake_do_log(l);
	} else
		BUG_ON(atomic_read(&cc->cnt) < 0);
}

enum slink_endio_type { SLINK_ENDIO_RAM, SLINK_ENDIO_DISK };
static void
slink_copy_endio(enum slink_endio_type type, int read_err, int write_err,
		 void *context)
{
	struct slink_copy_context *cc = context;
	struct slink_copy_error *error;

	DMDEBUG_LIMIT("%s", __func__);
	_BUG_ON_PTR(cc);
	error = cc->error;

	if (type == SLINK_ENDIO_RAM) {
		/* On RAM endio error, no disk callback will be performed. */
		if (unlikely(read_err || write_err))
			atomic_dec(&cc->cnt);

		error += ERR_RAM;
	} else
		error += ERR_DISK;

	error->read = read_err;
	error->write = write_err;
	slink_copy_context_put(cc);
}

/* Callback for copy in RAM. */
static void
slink_copy_ram_endio(int read_err, int write_err, void *context)
{
	slink_copy_endio(SLINK_ENDIO_RAM, read_err, write_err, context);
}

/* Callback for copy on disk. */
static void
slink_copy_disk_endio(int read_err, int write_err, void *context)
{
	slink_copy_endio(SLINK_ENDIO_DISK, read_err, write_err, context);
}

/*
 * Called back when:
 *
 * o site link recovered from failure
 * o site link recovered a region.
 */
static void
slink_recover_callback(int read_err, int write_err, void *context)
{
	unsigned slink_nr;
	struct repl_log *l;
	struct slink_state *ss = context;

	_BUG_ON_PTR(ss);
	l = ss->l;
	_BUG_ON_PTR(l);
	slink_nr = ss->slink_nr;
	_BUG_ON_SLINK_NR(l, slink_nr);

	DMDEBUG_LIMIT("%s slink=%d", __func__, slink_nr);

	if (!read_err && !write_err)
		slink_set_bit(slink_nr, LOG_SLINKS_SET_ACCESSIBLE(l));

	/* Inform caller, that we're willing to receive more I/Os. */
	notify_caller(l, WRITE, 0);

	/* Wakeup worker to allow for further IO. */
	wake_do_log(l);
}

/* Initialize slink_copy global properties independent of entry. */
static void
slink_copy_init(struct dm_repl_slink_copy *slink_copy, struct repl_log *l)
{
	/*
	 * The source block device (ie. the ring buffer device)
	 * is the same for all I/Os.
	 */
	slink_copy->src.type = DM_REPL_SLINK_BLOCK_DEVICE;
	slink_copy->src.dev.bdev = repl_log_bdev(l);

	/* The destination is identified by slink and device number. */
	slink_copy->dst.type = DM_REPL_SLINK_DEV_NUMBER;

	/* RAM, disk, slink recovery callbacks. */
	slink_copy->ram.fn = slink_copy_ram_endio;
	slink_copy->disk.fn = slink_copy_disk_endio;
}

/* Initialize slink_copy global properties dependent of entry. */
static void
slink_copy_addr(struct dm_repl_slink_copy *slink_copy,
		struct ringbuffer_entry *entry)
{
	struct data_header *header = entry->data.header;
	struct data_header_region *region;

	_BUG_ON_PTR(header);
	region = &header->region;
	_BUG_ON_PTR(region);

	/* The offset/size to copy from is given by the entry. */
	slink_copy->src.sector = header->pos.data;

	/* Most of the destination is the same across slinks. */
	slink_copy->dst.dev.number.dev = region->dev;
	slink_copy->dst.sector = region->sector;
	slink_copy->size = region->size;
}

/* Allocate and initialize and slink_copy_context structure. */
static inline struct slink_copy_context *
slink_copy_context_alloc(struct ringbuffer_entry *entry,
			 struct dm_repl_slink *slink)
{
	struct slink_copy_context *cc = alloc_copy_context(entry->ring);

	BUG_ON(!cc);
	memset(cc, 0, sizeof(*cc));

	/* NR_ENDIOS # of endios callbacks per copy (RAM and disk). */
	atomic_set(&cc->cnt, NR_ENDIOS);
	cc->entry = entry;
	cc->slink = slink;
	cc->start_jiffies = jiffies;
	return cc;
}

/* Trigger/prohibit resynchronization on all site links. */
enum resync_switch { RESYNC_OFF = 0, RESYNC_ON };
static void
resync_on_off(struct repl_log *l, enum resync_switch resync)
{
	unsigned long slink_nr;
	struct dm_repl_slink *slink;

	for_each_bit(slink_nr, LOG_SLINKS(l), l->slink.max) {
		slink = slink_find(l, slink_nr);
		if (!IS_ERR(slink))
			slink->ops->resync(slink, resync);
	}
}

/* Return true if all slinks processed (either active or inaccessible). */
static int
all_slinks_processed(struct repl_log *l)
{
	unsigned slinks = 0;
	unsigned long slink_nr;

	for_each_bit(slink_nr, LOG_SLINKS_IO(l), l->slink.max)
		slinks++;

	for_each_bit(slink_nr, LOG_SLINKS_INACCESSIBLE(l), l->slink.max)
		slinks++;

	return slinks >= l->slink.count;
}

/*
 * Work all site link copy orders.
 */
static void
do_slink_ios(struct repl_log *l)
{
	unsigned long slink_nr;
	struct ringbuffer_entry *entry;
	struct dm_repl_slink *slink;
	static struct dm_repl_slink_copy slink_copy;

	/* If there's no entries on the copy list, allow resync. */
	if (list_empty(L_SLINK_COPY_LIST(l)))
		return resync_on_off(l, RESYNC_ON);

	/*
	 * ...else prohibit resync.
	 *
	 * We'll deal with any active resynchronization based
	 * on the return code of slink->ops->copy() below.
	 */
	resync_on_off(l, RESYNC_OFF);

	/*
	 * This list is ordered, how do we keep it so that endio processing
	 * is ordered?  We need this so that head pointer advances in order.
	 *
	 * We do that by changing ringbuffer_advance_head() to check
	 * for entry_busy(l, ENTRY_SLINKS(entry))) and stop processing. -HJM
	 */

	/* Initialize global properties, which are independent of the entry. */
	slink_copy_init(&slink_copy, l);

	/* Walk all entries on the slink copy list. */
	list_for_each_entry(entry, L_SLINK_COPY_LIST(l),
			    lists.l[E_WRITE_OR_COPY]) {
		int r;
		unsigned copies = 0;

		/* Check, if all slinks processed now. */
		r = all_slinks_processed(l);
		if (r)
			break;

		/* Set common parts independent of slink up. */
		slink_copy_addr(&slink_copy, entry);

		/* Walk all slinks, which still need this entry. */
		for_each_bit(slink_nr, ENTRY_SLINKS(entry), l->slink.max) {
			int teardown;
			struct slink_copy_context *cc;
			struct slink_state *ss;

			/*
			 * One maximum write pending to slink already
			 * -or-
			 * slink is recovering this region.
			 */
			if (slink_test_bit(slink_nr, LOG_SLINKS_IO(l)) ||
			    slink_test_bit(slink_nr,
					   LOG_SLINKS_INACCESSIBLE(l)))
				continue;

			/*
			 * Check for deleted or being torn down site link.
			 */
			slink = slink_find(l, slink_nr);
			if (unlikely(IS_ERR(slink))) {
				DMERR_LIMIT("%s no slink!", __func__);
				ss = NULL;
				teardown = 0;
			} else {
				ss = slink->caller;
				_BUG_ON_PTR(ss);
				teardown = SsTeardown(ss);
			}

			if (unlikely(IS_ERR(slink) ||
				     teardown ||
				     !slink_test_bit(slink_nr,
						     LOG_SLINKS(l)))) {
drop_copy:
				if (IS_ERR(slink))
					DMERR_LIMIT("%s: slink %lu not "
						    "configured!",
						    __func__, slink_nr);
				else
					/* Correct fallbehind account. */
					slink_fallbehind_dec(slink, entry);

				/* Flag entry copied to slink_nr. */
				slink_clear_bit(slink_nr, ENTRY_SLINKS(entry));

				/* Reset any sync copy request to slink_nr. */
				slink_clear_bit(slink_nr, ENTRY_SYNC(entry));

				if (!slink_nr)
					sector_range_clear_busy(entry);

				continue;
			}

			/* Take slink reference out. */
			ss_io_get(ss);

			/* Flag active copy to slink+entry, */
			slink_set_bit(slink_nr, LOG_SLINKS_IO(l));
			slink_set_bit(slink_nr, ENTRY_IOS(entry));

			/* Fill in the destination slink number. */
			slink_copy.dst.dev.number.slink = slink_nr;

			/* Setup the callback data. */
			cc = slink_copy_context_alloc(entry, slink);
			BUG_ON(!cc);
			slink_copy.ram.context = slink_copy.disk.context = cc;

			/*
			 * Add to entrys copy list of active copies in
			 * order to avoid race with ->copy() endio function
			 * accessing cc->list.
			 */
			write_lock_irq(&l->lists.lock);
			list_add_tail(&cc->list, E_COPY_CONTEXT_LIST(entry));
			write_unlock_irq(&l->lists.lock);

			DMDEBUG("slink0->ops->copy() from log, sector=%llu, "
				"size=%u to dev_number=%d, sector=%llu "
				"on slink=%u",
				(unsigned long long) slink_copy.src.sector,
				slink_copy.size,
				slink_copy.dst.dev.number.dev,
				(unsigned long long) slink_copy.dst.sector,
				slink_copy.dst.dev.number.slink);


			/*
			 * slink->ops->copy() may return:
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
			r = slink->ops->copy(slink, &slink_copy, 0);
			if (unlikely(r < 0)) {
				DMDEBUG_LIMIT("Copy to slink%d/dev%d/"
					      "sector=%llu failed with %d.",
					      slink_copy.dst.dev.number.slink,
					      slink_copy.dst.dev.number.dev,
					      (unsigned long long)
					      slink_copy.dst.sector, r);

				/*
				 * Failed -> take off entrys copies list
				 * 	     and free copy contrext.
				 */
				write_lock_irq(&l->lists.lock);
				list_del_init(&cc->list);
				write_unlock_irq(&l->lists.lock);

				free_copy_context(cc, entry->ring);

				/* Reset active I/O on slink+entry. */
				slink_clear_bit(slink_nr, LOG_SLINKS_IO(l));
				slink_clear_bit(slink_nr, ENTRY_IOS(entry));

				/* Release slink reference. */
				ss_io_put(ss);

				/*
				 * Source region is being read for recovery
				 * or device is temporarilly inaccessible ->
				 * retry later once accessible again.
				 */
				if (r == -EACCES ||
				    r == -EAGAIN) {
					slink_set_bit(slink_nr,
						LOG_SLINKS_INACCESSIBLE(l));

				/*
				 * Device not on slink
				 * -or-
				 * region not in sync -> avoid copy.
				 */
				} else if (r == -ENODEV ||
					   r == -EPERM)
					goto drop_copy;
				else
					BUG();
			} else
				copies++;
		}

		if (copies)
			l->stats.copy[copies > 1]++;
	}
}

/* Unplug device queues with entries on all site links. */
static void
do_unplug(struct repl_log *l)
{
	struct dm_repl_slink *slink;
	unsigned long slink_nr;

	/* Conditionally unplug ring buffer. */
	if (TestClearRingBufferIOQueued(&l->ringbuffer))
		blk_unplug(bdev_get_queue(ringbuffer_bdev(&l->ringbuffer)));

	/* Unplug any devices with queued IO on site links. */
	for_each_bit(slink_nr, LOG_SLINKS(l), l->slink.max) {
		slink = slink_find(l, slink_nr);
		if (!IS_ERR(slink))
			slink->ops->unplug(slink);
	}
}

/* Take out/drop slink state references to synchronize with slink delition. */
enum reference_type { REF_GET, REF_PUT };
static inline void
ss_ref(enum reference_type type, struct repl_log *l)
{
	unsigned long slink_nr;
	void (*f)(struct slink_state *) =
		type == REF_GET ? ss_io_get : ss_io_put;

	if (!l->slink0)
		return;

	for_each_bit(slink_nr, LOG_SLINKS(l), l->slink.max) {
		struct dm_repl_slink *slink =
			l->slink0->ops->slink(l->replog, slink_nr);

		_BUG_ON_PTR(slink);
		f(slink->caller);
	}
}

/*
 * Worker thread.
 *
 * Belabour any:
 * o replicator log ring buffer initialization
 * o endios on the ring buffer
 * o endios on any site links
 * o I/O on site links (copies of buffer entries via site links to [LR]Ds
 * o I/O to the ring buffer
 *
 */
static void
do_log(struct work_struct *ws)
{
	struct repl_log *l = container_of(ws, struct repl_log, io.ws);

	/* Take out references vs. removal races. */
	spin_lock(&l->io.lock);
	ss_ref(REF_GET, l);
	spin_unlock(&l->io.lock);

	if (!RingSuspended(&l->ringbuffer)) {
		do_log_init(l);
		do_log_resize(l);
	}

	/* Allow for endios at any time, even while suspended. */
	do_ringbuffer_endios(l); /* Must be called before do_slink_ios. */

	/* Don't allow for new I/Os while suspended. */
	if (!RingSuspended(&l->ringbuffer)) {
		int r;

		do_slink_endios(l);
		do_ringbuffer_ios(l);

		/*
		 * Set any slinks requested to accessible
		 * before checking all_slinks_processed().
		 */
		do_slinks_accessible(l);

		/* Only initiate slink copies if not all slinks active. */
		r = all_slinks_processed(l);
		if (!r)
			do_slink_ios(l);

		do_unplug(l);
	}

	ss_ref(REF_PUT, l);
}

/*
 * Start methods of "default" type
 */
/* Destroy a replicator log context. */
static void
ringbuffer_dtr(struct dm_repl_log *log, struct dm_target *ti)
{
	struct repl_log *l;

	DMDEBUG("%s: log %p", __func__, log);
	_SET_AND_BUG_ON_L(l, log);

	/* Remove from the global list of replogs. */
	mutex_lock(&list_mutex);
	list_del_init(L_REPLOG_LIST(l));
	mutex_unlock(&list_mutex);

	replog_destroy(l);
	BUG_ON(!replog_put(log, ti));
}

/*
 * Construct a replicator log context.
 *
 * Arguments:
 * 	#replog_params dev_path dev_start [auto/create/open [size]
 *
 * dev_path = device path of replication log (REPLOG) backing store
 * dev_start = offset in sectors to REPLOG header
 *
 * auto = causes open of an REPLOG with a valid header or
 *        creation of a new REPLOG in case the header's invalid.
 * <#replog_params> = 2 or (3 and "open")
 *      -> the cache device must be initialized or the constructor will fail.
 * <#replog_params> = 4 and "auto"
 * 	-> if not already initialized, the log device will get initialized
 * 	   and sized to "size", otherwise it'll be opened.
 * <#replog_params> = 4 and 'create'
 * 	-> the log device will get initialized if not active and sized to
 *         "size"; if the REPLOG is active 'create' will fail.
 *
 * The above roughly translates to:
 *  argv[0] == #params
 *  argv[1] == dev_name
 *  argv[2] == dev_start
 *  argv[3] == OT_OPEN|OT_CREATE|OT_AUTO
 *  argv[4] == size in sectors
 */
#define	MIN_ARGS	3
static int
ringbuffer_ctr(struct dm_repl_log *log, struct dm_target *ti,
	       unsigned argc, char **argv)
{
	int open_type, params;
	unsigned long long tmp;
	struct repl_log *l;
	struct repl_params p;

	SHOW_ARGV;

	if (unlikely(argc < MIN_ARGS))
		DM_EINVAL("%s: at least 3 args required, only got %d\n",
			  __func__, argc);

	memset(&p, 0, sizeof(p));

	/* Get # of parameters. */
	if (unlikely(sscanf(argv[0], "%d", &params) != 1 ||
	    params < 2 ||
	    params > 5)) {
		DM_EINVAL("invalid replicator log device start");
	} else
		p.count = params;

	if (params == 2)
		open_type = OT_OPEN;
	else {
		open_type = _open_type(argv[3]);
		if (unlikely(open_type < 0))
			return -EINVAL;
		else if (unlikely(open_type == OT_OPEN && params > 3))
			DM_EINVAL("3 arguments required for open, %d given.",
				  params);
	}

	p.open_type = open_type;

	if (params > 3) {
		/* Get device size argument. */
		if (unlikely(sscanf(argv[4], "%llu", &tmp) != 1 ||
		    tmp < LOG_SIZE_MIN)) {
			DM_EINVAL("invalid replicator log device size");
		} else
			p.dev.size = tmp;

	} else
		p.dev.size = LOG_SIZE_MIN;

	if (unlikely((open_type == OT_AUTO || open_type == OT_CREATE) &&
		     params < 4))
		DM_EINVAL("4 arguments required for auto and create");

	/* Get device start argument. */
	if (unlikely(sscanf(argv[2], "%llu", &tmp) != 1))
		DM_EINVAL("invalid replicator log device start");
	else
		p.dev.start = tmp;

	/* Get a reference on the replog. */
	l = replog_get(log, ti, argv[1], &p);
	if (unlikely(IS_ERR(l)))
		return PTR_ERR(l);

	return 0;
}

/* Flush the current log contents. This function may block. */
static int
ringbuffer_flush(struct dm_repl_log *log)
{
	struct repl_log *l;
	struct ringbuffer *ring;

	DMDEBUG("%s", __func__);
	_SET_AND_BUG_ON_L(l, log);
	ring = &l->ringbuffer;

	wake_do_log(l);
	wait_event(ring->flushq, ringbuffer_empty(ring));
	return 0;
}

/* Suspend method. */
/*
 * FIXME: we're suspending/resuming the whole ring buffer,
 *	  not just the device requested. Avoiding this complete
 *	  suspension would afford knowledge on the reason for the suspension.
 *	  E.g. in case of device removal, we could avoid suspending completely.
 *	  Don't know how we can optimize this w/o a bitmap
 *	  for the devices, hence limiting dev_numbers. -HJM
 */
static int
ringbuffer_postsuspend(struct dm_repl_log *log, int dev_number)
{
	struct repl_log *l;

	_SET_AND_BUG_ON_L(l, log);
	flush_workqueue(l->io.wq);

	if (TestSetRingSuspended(&l->ringbuffer))
		DMWARN("%s ring buffer already suspended", __func__);

	flush_workqueue(l->io.wq);
	SetRingBlocked(&l->ringbuffer);
	ss_all_wait_on_ios(l);
	return 0;
}

/* Resume method. */
static int
ringbuffer_resume(struct dm_repl_log *log, int dev_number)
{
	struct repl_log *l;
	struct ringbuffer *ring;

	_SET_AND_BUG_ON_L(l, log);

	ring = &l->ringbuffer;
	if (!TestClearRingSuspended(ring))
		DMWARN("%s ring buffer already resumed", __func__);

	ClearRingBlocked(ring);
	notify_caller(l, WRITE, 0);
	wake_do_log(l);
	return 0;
}

/*
 * Queue a bio to the worker thread ensuring, that
 * there's enough space for writes in the ring buffer.
 */
static inline int
queue_bio(struct repl_log *l, struct bio *bio)
{
	int rw = bio_data_dir(bio);
	struct ringbuffer *ring = &l->ringbuffer;

	/*
	 * Try reserving space for the bio in the
	 * buffer and mark the sector range busy.
	 */
	if (rw == WRITE) {
		int r;

		mutex_lock(&ring->mutex);
		r = ringbuffer_reserve_space(ring, bio);
		mutex_unlock(&ring->mutex);

		/* Ring buffer full. */
		if (r < 0)
			return r;
	}

	spin_lock(&l->io.lock);
	bio_list_add(&l->io.in, bio);
	spin_unlock(&l->io.lock);

	atomic_inc(l->stats.io + !!rw);
	wake_do_log(l);
	return 0;
}

/*
 * Read a bio either from a replicator log's ring buffer
 * or from the replicated device if no buffer entry.
 * - or-
 * write a bio to a replicator log's ring
 * buffer (increments buffer tail).
 *
 * This includes buffer allocation in case of a write and
 * inititation of copies accross an/multiple SLINK(s).
 *
 * In case of a read with (partial) writes in the buffer,
 * the replog may postpone the read until the buffer content has
 * been copied accross the local SLINK *or* optimize by reading
 * (parts of) the bio off the buffer.
 */
/*
 * Returns 0 on success, -EWOULDBLOCK if this is a WRITE request
 * and buffer space could not be allocated.  Returns -EWOULDBLOCK if
 * this is a READ request and the call would block due to the
 * requested region being currently under WRITE I/O.
 */
static int
ringbuffer_io(struct dm_repl_log *log, struct bio *bio, unsigned long long tag)
{
	int r = 0;
	struct repl_log *l;
	struct ringbuffer *ring;

	_SET_AND_BUG_ON_L(l, log);
	ring = &l->ringbuffer;

	if (RingBlocked(ring) ||
	    !LogInitialized(l))
		goto out_blocked;

	if (unlikely(RingSuspended(ring)))
		goto set_blocked;

	/*
	 * Queue writes to the daemon in order to avoid sleeping
	 * on allocations. queue_bio() checks to see if there is
	 * enough space in the log for this bio and all of the
	 * other bios currently queued for the daemon.
	 */
	r = queue_bio(l, bio);
	if (!r)
		return r;

set_blocked:
	SetRingBlocked(ring);
out_blocked:
	DMDEBUG_LIMIT("%s Ring blocked", __func__);
	return -EWOULDBLOCK;
}

/* Set maximum slink # for bitarray access optimization. */
static void replog_set_slink_max(struct repl_log *l)
{
	unsigned long bit_nr;

	l->slink.max = 0;
	for_each_bit(bit_nr, LOG_SLINKS(l), MAX_DEFAULT_SLINKS)
		l->slink.max = bit_nr;

	l->slink.max++;
	BITMAP_ELEMS(l) = dm_div_up(dm_div_up(l->slink.max, BITS_PER_BYTE),
				    sizeof(uint64_t));
	BITMAP_SIZE(l) = BITMAP_ELEMS(l) * sizeof(uint64_t);
}

/* Set replog global I/O notification function and context. */
static void
ringbuffer_io_notify_fn_set(struct dm_repl_log *log,
			 dm_repl_notify_fn fn, void *notify_context)
{
	struct repl_log *l;

	_SET_AND_BUG_ON_L(l, log);

	spin_lock(&l->io.lock);
	l->notify.fn = fn;
	l->notify.context = notify_context;
	spin_unlock(&l->io.lock);
}

/* Add (tie) a site link to a replication log for SLINK copy processing. */
static int
ringbuffer_slink_add(struct dm_repl_log *log, struct dm_repl_slink *slink)
{
	int slink_nr;
	struct repl_log *l;
	struct slink_state *ss;

	/* FIXME: XXX lock the repl_log */
	DMDEBUG("ringbuffer_slink_add");
	_BUG_ON_PTR(slink);
	_SET_AND_BUG_ON_L(l, log);

	/* See if slink was already added. */
	slink_nr = slink->ops->slink_number(slink);
	if (slink_nr >= MAX_DEFAULT_SLINKS)
		DM_EINVAL("slink number larger than maximum "
			  "for 'default' replication log.");

	DMDEBUG("%s: attempting to add slink%d", __func__, slink_nr);

	/* No entry -> add a new one. */
	ss = kzalloc(sizeof(*ss), GFP_KERNEL);
	if (unlikely(!ss))
		return -ENOMEM;

	ss->slink_nr = slink_nr;
	ss->l = l;
	atomic_set(&ss->io.in_flight, 0);
	init_waitqueue_head(&ss->io.waiters);

	spin_lock(&l->io.lock);

	if (unlikely(slink->caller)) {
		spin_unlock(&l->io.lock);
		kfree(ss);
		DMERR("slink already exists.");
		return -EEXIST;
	}

	ClearSsTeardown(ss);

	/* Keep slink state reference. */
	slink->caller = ss;

	if (!slink_nr)
		l->slink0 = slink;

	l->slink.count++;

	/* Set site link recovery notification. */
	slink->ops->recover_notify_fn_set(slink, slink_recover_callback, ss);

	/* Update log_header->slinks bit mask before setting max slink #! */
	slink_set_bit(slink_nr, LOG_SLINKS(l));

	/* Set maximum slink # for bitarray access optimization. */
	replog_set_slink_max(l);

	spin_unlock(&l->io.lock);
	return 0;
}

/* Remove (untie) a site link from a replication log. */
/*
 * How do we tell if this is a configuration change or just a shutdown?
 * After _repl_ctr, the RDs on the site link are either there or not.
 */
static int
ringbuffer_slink_del(struct dm_repl_log *log, struct dm_repl_slink *slink)
{
	int r, slink_nr;
	struct repl_log *l;
	struct ringbuffer *ring;
	struct slink_state *ss;

	DMDEBUG("%s", __func__);
	_BUG_ON_PTR(slink);
	_SET_AND_BUG_ON_L(l, log);
	ring = &l->ringbuffer;

	/* Find entry to be deleted. */
	slink_nr = slink->ops->slink_number(slink);
	DMDEBUG("%s slink_nr=%d", __func__, slink_nr);

	spin_lock(&l->io.lock);
	ss = slink->caller;
	if (likely(ss)) {
		BUG_ON(atomic_read(&ss->io.in_flight));

		/* No new I/Os on this slink and no duplicate deletion calls. */
		if (TestSetSsTeardown(ss)) {
			spin_unlock(&l->io.lock);
			return -EPERM;
		}

		/* Wait on worker and any async I/O to finish on site link. */
		do {
			spin_unlock(&l->io.lock);
			ss_wait_on_io(ss);
			spin_lock(&l->io.lock);

			if (!ss_io(ss)) {
				slink_clear_bit(slink_nr, LOG_SLINKS(l));
				slink->caller = NULL;
				slink->ops->recover_notify_fn_set(slink,
								  NULL, NULL);
				if (!slink_nr)
					l->slink0 = NULL;

				l->slink.count--;
				replog_set_slink_max(l); /* Set l->slink.max. */
			}
		} while (slink->caller);

		spin_unlock(&l->io.lock);

		BUG_ON(l->slink.count < 0);
		kfree(ss);
		DMDEBUG("%s removed slink=%u", __func__, slink_nr);
		r = 0;
	} else {
		spin_unlock(&l->io.lock);
		r = -EINVAL;
	}

	wake_do_log(l);
	return r;
}

/* Return head of the list of site links for this replicator log. */
static struct dm_repl_log_slink_list
*ringbuffer_slinks(struct dm_repl_log *log)
{
	struct repl_log *l;

	_SET_AND_BUG_ON_L(l, log);
	return &l->lists.slinks;
}

/* Return maximum number of supported site links. */
static int
ringbuffer_slink_max(struct dm_repl_log *log)
{
	return MAX_DEFAULT_SLINKS;
}

/*
 * Message interface
 *
 * 'sta[tistics] {on,of[f],r[eset]}'		# e.g. 'stat of'
 */
static int
ringbuffer_message(struct dm_repl_log *log, unsigned argc, char **argv)
{
	static const char stat[] = "statistics";
	static const char resize[] = "resize";
	struct repl_log *l;

	_SET_AND_BUG_ON_L(l, log);

	if (argc != 2)
		DM_EINVAL("Invalid number of arguments.");

	if (!strnicmp(STR_LEN(argv[0], stat))) {
		if (!strnicmp(STR_LEN(argv[1], "on")))
			set_bit(LOG_DEVEL_STATS, &l->io.flags);
		else if (!strnicmp(STR_LEN(argv[1], "off")))
			clear_bit(LOG_DEVEL_STATS, &l->io.flags);
		else if (!strnicmp(STR_LEN(argv[1], "reset")))
			stats_init(l);
		else
			DM_EINVAL("Invalid '%s' arguments.", stat);
	} else if (!strnicmp(STR_LEN(argv[0], resize))) {
		if (TestSetLogResize(l))
			DM_EPERM("Log resize already in progress");
		else {
			unsigned long long tmp;
			sector_t dev_size;

			if (unlikely(sscanf(argv[1], "%llu", &tmp) != 1) ||
				tmp < LOG_SIZE_MIN)
				DM_EINVAL("Invalid log %s argument.", resize);

			dev_size = replog_dev_size(l->params.dev.dm_dev, tmp);
			if (!dev_size)
				DM_EINVAL("Invalid log size requested.");

			l->params.dev.size = tmp;
			wake_do_log(l); /* Let the worker do the resize. */
		}
	} else
		DM_EINVAL("Invalid argument.");

	return 0;
}

/* Support function for replicator log status requests. */
static int
ringbuffer_status(struct dm_repl_log *log, int dev_number,
		  status_type_t type, char *result, unsigned int maxlen)
{
	unsigned long slink_nr;
	size_t sz = 0;
	sector_t ios, sectors;
	char buf[BDEVNAME_SIZE];
	struct repl_log *l;
	struct stats *s;
	struct ringbuffer *ring;
	struct repl_params *p;

	_SET_AND_BUG_ON_L(l, log);
	s = &l->stats;
	ring = &l->ringbuffer;
	p = &l->params;

	switch (type) {
	case STATUSTYPE_INFO:
		ios = sectors = 0;

		/* Output ios/sectors stats. */
		spin_lock(&l->io.lock);
		for_each_bit(slink_nr, LOG_SLINKS(l), l->slink.max) {
			struct dm_repl_slink *slink = slink_find(l, slink_nr);
			struct slink_state *ss;

			_BUG_ON_PTR(slink);
			ss = slink->caller;
			_BUG_ON_PTR(ss);

			DMEMIT(" %s,%llu,%llu",
			       SsSync(ss) ? "S" : "A",
			       (unsigned long long) ss->fb.outstanding.ios,
			       (unsigned long long) ss->fb.outstanding.sectors);
			ios += ss->fb.outstanding.ios;
			sectors += ss->fb.outstanding.sectors;
		}

		DMEMIT(" %llu/%llu/%llu",
		       (unsigned long long) ios,
		       (unsigned long long) sectors,
		       (unsigned long long) l->params.dev.size);

		spin_unlock(&l->io.lock);

		if (LogDevelStats(l))
			DMEMIT(" ring->start=%llu "
			       "ring->head=%llu ring->tail=%llu "
			       "ring->next_avail=%llu ring->end=%llu "
			       "ring_free=%llu wrap=%d r=%d w=%d wp=%d he=%d "
			       "hash_insert=%u hash_insert_max=%u "
			       "single=%u multi=%u stall=%u",
			       (unsigned long long) ring->start,
			       (unsigned long long) ring->head,
			       (unsigned long long) ring->tail,
			       (unsigned long long) ring->next_avail,
			       (unsigned long long) ring->end,
			       (unsigned long long) ring_free(ring),
			       s->wrap,
			       atomic_read(s->io + 0), atomic_read(s->io + 1),
			       atomic_read(&s->writes_pending),
			       atomic_read(&s->hash_elem),
			       s->hash_insert, s->hash_insert_max,
			       s->copy[0], s->copy[1],
			       s->stall);

		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s %d %s %llu", ringbuffer_type.type.name, p->count,
		       format_dev_t(buf, p->dev.dm_dev->bdev->bd_dev),
		       (unsigned long long) p->dev.start);

		if (p->count > 2) {
			DMEMIT(" %s", _open_str(p->open_type));

			if (p->count > 3)
				DMEMIT(" %llu",
				       (unsigned long long) p->dev.size);
		}
	}

	return 0;
}

/*
 * End methods of "ring-buffer" type
 */

/* "ring-buffer" replication log type. */
static struct dm_repl_log_type ringbuffer_type = {
	.type.name = "ringbuffer",
	.type.module = THIS_MODULE,

	.ctr = ringbuffer_ctr,
	.dtr = ringbuffer_dtr,

	.postsuspend = ringbuffer_postsuspend,
	.resume = ringbuffer_resume,
	.flush = ringbuffer_flush,
	.io = ringbuffer_io,
	.io_notify_fn_set = ringbuffer_io_notify_fn_set,

	.slink_add = ringbuffer_slink_add,
	.slink_del = ringbuffer_slink_del,
	.slinks = ringbuffer_slinks,
	.slink_max = ringbuffer_slink_max,

	.message = ringbuffer_message,
	.status = ringbuffer_status,
};

/* Destroy kmem caches on module unload. */
static int
replog_kmem_caches_exit(void)
{
	struct cache_defs *pd = ARRAY_END(cache_defs);

	while (pd-- > cache_defs) {
		if (unlikely(!pd->slab_pool))
			continue;

		DMDEBUG("Destroying kmem_cache %p", pd->slab_pool);
		kmem_cache_destroy(pd->slab_pool);
		pd->slab_pool = NULL;
	}

	return 0;
}

/* Create kmem caches on module load. */
static int
replog_kmem_caches_init(void)
{
	int r = 0;
	struct cache_defs *pd = ARRAY_END(cache_defs);

	while (pd-- > cache_defs) {
		BUG_ON(pd->slab_pool);

		/* No slab pool. */
		if (!pd->size)
			continue;

		pd->slab_pool = kmem_cache_create(pd->slab_name, pd->size,
						  pd->align, 0, NULL);
		if (likely(pd->slab_pool))
			DMDEBUG("Created kmem_cache %p", pd->slab_pool);
		else {
			DMERR("failed to create slab %s for replication log "
			      " handler %s %s",
			      pd->slab_name, ringbuffer_type.type.name,
			      version);
			replog_kmem_caches_exit();
			r = -ENOMEM;
			break;
		}
	}

	return r;
}

int __init
dm_repl_log_init(void)
{
	int r;

	if (sizeof(struct data_header_disk) != DATA_HEADER_DISK_SIZE)
		DM_EINVAL("invalid size of 'struct data_header_disk' for %s %s",
			  ringbuffer_type.type.name, version);

	mutex_init(&list_mutex);

	r = replog_kmem_caches_init();
	if (r < 0) {
		DMERR("failed to init %s kmem caches %s",
		      ringbuffer_type.type.name, version);
		return r;
	}

	r = dm_register_type(&ringbuffer_type, DM_REPLOG);
	if (r < 0) {
		DMERR("failed to register replication log %s handler %s [%d]",
		      ringbuffer_type.type.name, version, r);
		replog_kmem_caches_exit();
	} else
		DMINFO("registered replication log %s handler %s",
		       ringbuffer_type.type.name, version);

	return r;
}

void __exit
dm_repl_log_exit(void)
{
	int r = dm_unregister_type(&ringbuffer_type, DM_REPLOG);

	replog_kmem_caches_exit();

	if (r)
		DMERR("failed to unregister replication log %s handler %s [%d]",
		       ringbuffer_type.type.name, version, r);
	else
		DMINFO("unregistered replication log %s handler %s",
		       ringbuffer_type.type.name, version);
}

/* Module hooks */
module_init(dm_repl_log_init);
module_exit(dm_repl_log_exit);

MODULE_DESCRIPTION(DM_NAME " remote replication target \"ringbuffer\" "
			   "log handler");
MODULE_AUTHOR("Jeff Moyer <jmoyer@redhat.com>, "
	      "Heinz Mauelshagen <heinzm@redhat.com");
MODULE_LICENSE("GPL");
