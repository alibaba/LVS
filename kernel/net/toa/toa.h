#ifndef __NET__TOA_H__
#define __NET__TOA_H__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/time.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/kallsyms.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>

#define TOA_VERSION "1.0.0.0"

#define TOA_DBG(msg...)				\
	do {					\
		printk(KERN_DEBUG "[DEBUG] TOA: " msg); \
	} while (0)

#define TOA_INFO(msg...)				\
	do {						\
		if (net_ratelimit())			\
			printk(KERN_INFO "TOA: " msg);	\
	} while (0)

#define TCPOPT_TOA  254

/* MUST be 4n !!!! */
#define TCPOLEN_TOA 8		/* |opcode|size|ip+port| = 1 + 1 + 6 */

/* MUST be 4 bytes alignment */
struct toa_data {
	__u8 opcode;
	__u8 opsize;
	__u16 port;
	__u32 ip;
};

/* statistics about toa in proc /proc/net/toa_stat */
enum {
	SYN_RECV_SOCK_TOA_CNT = 1,
	SYN_RECV_SOCK_NO_TOA_CNT,
	GETNAME_TOA_OK_CNT,
	GETNAME_TOA_MISMATCH_CNT,
	GETNAME_TOA_BYPASS_CNT,
	GETNAME_TOA_EMPTY_CNT,
	TOA_STAT_LAST
};

struct toa_stats_entry {
	char *name;
	int entry;
};

#define TOA_STAT_ITEM(_name, _entry) { \
	.name = _name,		\
	.entry = _entry,	\
}

#define TOA_STAT_END {	\
	NULL,		\
	0,		\
}

struct toa_stat_mib {
	unsigned long mibs[TOA_STAT_LAST];
};

#define DEFINE_TOA_STAT(type, name)       \
	(__typeof__(type) *name)
#define TOA_INC_STATS(mib, field)         \
	(per_cpu_ptr(mib, smp_processor_id())->mibs[field]++)

#endif
