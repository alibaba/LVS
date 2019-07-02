/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Healthcheckers dynamic data structure definition.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2011 Alexandre Cassen, <acassen@linux-vs.org>
 */

#ifndef _CHECK_DATA_H
#define _CHECK_DATA_H

/* system includes */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#ifdef _WITH_LVS_
  #ifdef _KRNL_2_4_
    #include <net/ip_vs.h>
  #elif _KRNL_2_6_
    #include "../libipvs-2.6/ip_vs.h"
  #endif
  #define SCHED_MAX_LENGTH IP_VS_SCHEDNAME_MAXLEN
#else
  #define SCHED_MAX_LENGTH   1
#endif

/* local includes */
#include "list.h"
#include "vector.h"
#include "timer.h"

/* Typedefs */
typedef unsigned int checker_id_t;

/* Daemon dynamic data structure definition */
#define MAX_TIMEOUT_LENGTH		5
#define KEEPALIVED_DEFAULT_DELAY	(60 * TIMER_HZ) 

/* SSL specific data */
typedef struct _ssl_data SSL_DATA;
typedef struct _ssl_data {
	int enable;
	int strong_check;
	SSL_CTX *ctx;
	SSL_METHOD *meth;
	char *password;
	char *cafile;
	char *certfile;
	char *keyfile;
} ssl_data;

/* Real Server definition */
typedef struct _real_server {
	struct sockaddr_storage	addr;
	int weight;
	int iweight;		/* Initial weight */
#ifdef _KRNL_2_6_
	uint32_t u_threshold;   /* Upper connection limit. */
	uint32_t l_threshold;   /* Lower connection limit. */
#endif
	int inhibit;		/* Set weight to 0 instead of removing
				 * the service from IPVS topology.
				 */
	char *notify_up;	/* Script to launch when RS is added to LVS */
	char *notify_down;	/* Script to launch when RS is removed from LVS */
	int alive;
	list failed_checkers;	/* List of failed checkers */
	int set;		/* in the IPVS table */
	int reload_alive;	/* alpha mode will reset rs to unalive. So save the status before reload here */
} real_server;


/* snat rule definetion */
typedef struct __snat_rule {
	union nf_inet_addr saddr;
	uint32_t smask;
	union nf_inet_addr daddr;
	uint32_t dmask;
	union nf_inet_addr gw;
	union nf_inet_addr minip;
	union nf_inet_addr maxip;
	uint32_t conn_flags;
	uint16_t af;
	uint8_t algo;
	union nf_inet_addr new_gw;
	char out_dev[IP_VS_IFNAME_MAXLEN];
	int alive;
	int set;
} snat_rule;

/* local ip address group definition */
typedef struct _local_addr_entry {
	struct sockaddr_storage addr;
	uint8_t range;
} local_addr_entry;

typedef struct _local_addr_group {
	char *gname;
	list addr_ip;
	list range;
} local_addr_group;

/* Virtual Server group definition */
typedef struct _virtual_server_group_entry {
	struct sockaddr_storage	addr;
	uint8_t range;
	uint32_t vfwmark;
	int alive;
} virtual_server_group_entry;

typedef struct _virtual_server_group {
	char *gname;
	list addr_ip;
	list range;
	list vfwmark;
} virtual_server_group;

/* Virtual Server definition */
typedef struct _virtual_server {
	char *vsgname;
	struct sockaddr_storage	addr;
	real_server *s_svr;
	uint32_t vfwmark;
	uint16_t service_type;
	long delay_loop;
	int ha_suspend;
	int abs_priority;
	int cur_max_weight;
	char sched[SCHED_MAX_LENGTH];
	char timeout_persistence[MAX_TIMEOUT_LENGTH];
	unsigned loadbalancing_kind;
	uint32_t nat_mask;
	uint32_t granularity_persistence;
	char *virtualhost;
	list rs;
	int alive;
	unsigned alpha;			/* Alpha mode enabled. */
	unsigned omega;			/* Omega mode enabled. */
	unsigned syn_proxy;		/* Syn_proxy mode enabled. */
	char *quorum_up;		/* A hook to call when the VS gains quorum. */
	char * quorum_down;		/* A hook to call when the VS loses quorum. */
	long unsigned quorum;		/* Minimum live RSs to consider VS up. */

	long unsigned hysteresis;	/* up/down events "lag" WRT quorum. */
	unsigned quorum_state;		/* Reflects result of the last transition done. */

	char *local_addr_gname;		/* local ip address group name */
	char *vip_bind_dev;		/* the interface name,vip bindto */
} virtual_server;

/* Configuration data root */
typedef struct _check_conf_data {
	SSL_DATA *ssl;
	list vs_group;
	list vs;
	list laddr_group;
} check_conf_data;

/* inline stuff */
static inline int __ip6_addr_equal(const struct in6_addr *a1,
				   const struct in6_addr *a2)
{
	return (((a1->s6_addr32[0] ^ a2->s6_addr32[0]) |
		 (a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
		 (a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
		 (a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0);
}


static inline int addr_equal(int af, const union nf_inet_addr *s1, 
	               const union nf_inet_addr *s2)
{
	if (af == AF_INET) {
		if (s1->in.s_addr == s2->in.s_addr) {
			return 1;
		}
	} else if (af == AF_INET6) {
		if (__ip6_addr_equal(&s1->in6, &s2->in6)) {
			return 1;
		}
	}

	return 0;
}

static inline int sockstorage_equal(const struct sockaddr_storage *s1,
				    const struct sockaddr_storage *s2)
{
	if (s1->ss_family != s2->ss_family)
		return 0;

	if (s1->ss_family == AF_INET6) {
		struct sockaddr_in6 *a1 = (struct sockaddr_in6 *) s1;
		struct sockaddr_in6 *a2 = (struct sockaddr_in6 *) s2;

//		if (IN6_ARE_ADDR_EQUAL(a1, a2) && (a1->sin6_port == a2->sin6_port))
		if (__ip6_addr_equal(&a1->sin6_addr, &a2->sin6_addr) &&
		    (a1->sin6_port == a2->sin6_port))
			return 1;
	} else if (s1->ss_family == AF_INET) {
		struct sockaddr_in *a1 = (struct sockaddr_in *) s1;
		struct sockaddr_in *a2 = (struct sockaddr_in *) s2;

		if ((a1->sin_addr.s_addr == a2->sin_addr.s_addr) &&
		    (a1->sin_port == a2->sin_port))
			return 1;
	}

	if (memcmp(s1, s2, sizeof(struct sockaddr_storage)) == 0)
		return 1;

	return 0;
}

static inline int inaddr_equal(sa_family_t family, void *addr1, void *addr2)
{
	if (family == AF_INET6) {
		struct in6_addr *a1 = (struct in6_addr *) addr1;
		struct in6_addr *a2 = (struct in6_addr *) addr2;

		if (__ip6_addr_equal(a1, a2))
			return 1;
	} else if (family == AF_INET) {
		struct in_addr *a1 = (struct in_addr *) addr1;
		struct in_addr *a2 = (struct in_addr *) addr2;

		if (a1->s_addr == a2->s_addr)
			return 1;
	}

	return 0;
}

#define SNAT_NONE               0x0000
#define SNAT_ADDR               0x0001
#define SNAT_MASK               0x0002

typedef struct _snat_rule_addr_mask {
	union nf_inet_addr addr;
	uint16_t af;
	uint32_t mask;
} snat_rule_addr_mask;

/* macro utility */
#define IS_SNAT_SVC(S) (((S)->vfwmark) == 1)
#define NOT_SNAT_SVC(s) (((s)->vfwmark) != 1)

#define ISALIVE(S)	((S)->alive)
#define SET_ALIVE(S)	((S)->alive = 1)
#define UNSET_ALIVE(S)	((S)->alive = 0)
#define VHOST(V)	((V)->virtualhost)

#define DEFAULT_SNAT_SCHED "snat_sched"

#define VS_ISEQ(X,Y)	(sockstorage_equal(&(X)->addr,&(Y)->addr)			&&\
			 (X)->vfwmark                 == (Y)->vfwmark			&&\
			 (X)->service_type            == (Y)->service_type		&&\
			 (X)->loadbalancing_kind      == (Y)->loadbalancing_kind	&&\
			 (X)->abs_priority            == (Y)->abs_priority		&&\
			 (X)->nat_mask                == (Y)->nat_mask			&&\
			 (X)->granularity_persistence == (Y)->granularity_persistence	&&\
			 (X)->syn_proxy		      == (Y)->syn_proxy			&&\
			 !strcmp((X)->sched, (Y)->sched)				&&\
			 !strcmp((X)->timeout_persistence, (Y)->timeout_persistence)	&&\
			 (((X)->vsgname && (Y)->vsgname &&				\
			   !strcmp((X)->vsgname, (Y)->vsgname)) || 			\
			  (!(X)->vsgname && !(Y)->vsgname))				&&\
			 (((X)->local_addr_gname && (Y)->local_addr_gname &&		\
			   !strcmp((X)->local_addr_gname, (Y)->local_addr_gname)) ||	\
			  (!(X)->local_addr_gname && !(Y)->local_addr_gname)))

#define VSGE_ISEQ(X,Y)	(sockstorage_equal(&(X)->addr,&(Y)->addr) &&	\
			 (X)->range     == (Y)->range &&		\
			 (X)->vfwmark   == (Y)->vfwmark)

#define RS_ISEQ(X,Y)	(sockstorage_equal(&(X)->addr,&(Y)->addr) &&	\
			 (X)->iweight   == (Y)->iweight)

#define SNAT_RS_ISEQ(X, Y) (addr_equal((X)->af, &(X)->saddr, &(Y)->saddr) && (X)->smask == (Y)->smask && \
		addr_equal((X)->af, &(X)->daddr, &(Y)->daddr) &&  (X)->dmask == (Y)->dmask && \
		addr_equal((X)->af, &(X)->gw, &(Y)->gw) && !strcmp((X)->out_dev, (Y)->out_dev) && \
		addr_equal((X)->af, &(X)->minip, &(Y)->minip)  && \
		addr_equal((X)->af, &(X)->maxip, &(Y)->maxip) && \
		addr_equal((X)->af, &(X)->new_gw, &(Y)->new_gw)  && \
		(X)->algo == (Y)->algo)

/* Global vars exported */
extern check_conf_data *check_data;
extern check_conf_data *old_check_data;

/* prototypes */
extern SSL_DATA *alloc_ssl(void);
extern void free_ssl(void);
extern void alloc_laddr_group(char *);
extern void alloc_laddr_entry(vector);
extern void alloc_vsg(char *);
extern void alloc_vsg_entry(vector);
extern void alloc_vs(char *, char *);
extern void alloc_rs(char *, char *);
extern void alloc_ssvr(char *, char *);
extern void alloc_group(char *);
extern void alloc_rsgroup(char *, char *);
extern void set_rsgroup(char *);
extern check_conf_data *alloc_check_data(void);
extern void free_check_data(check_conf_data *);
extern void dump_check_data(check_conf_data *);

extern void alloc_snat_rule(void);

#endif
