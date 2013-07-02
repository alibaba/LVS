#ifndef _TRACE_MM_H
#define _TRACE_MM_H

#include <linux/fs.h>
#include <linux/tracepoint.h>

DECLARE_TRACE(page_cache_acct_readpages,
	TP_PROTO(struct super_block *sb, int nr_pages),
	TP_ARGS(sb, nr_pages));

DECLARE_TRACE(page_cache_acct_hits,
	TP_PROTO(struct super_block *sb, int rw, int nr_pages),
	TP_ARGS(sb, rw, nr_pages));

DECLARE_TRACE(page_cache_acct_hit,
	TP_PROTO(struct super_block *sb, int rw),
	TP_ARGS(sb, rw));

DECLARE_TRACE(page_cache_acct_misses,
	TP_PROTO(struct super_block *sb, int rw, int nr_pages),
	TP_ARGS(sb, rw, nr_pages));

DECLARE_TRACE(page_cache_acct_miss,
	TP_PROTO(struct super_block *sb, int rw),
	TP_ARGS(sb, rw));

#endif
