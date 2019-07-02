/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Checkers registration.
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

#include <dirent.h>
#include <dlfcn.h>
#include "check_api.h"
#include "main.h"
#include "parser.h"
#include "memory.h"
#include "utils.h"
#include "logger.h"
#include "global_data.h"
#include "check_misc.h"
#include "check_smtp.h"
#include "check_tcp.h"
#include "check_http.h"
#include "check_ssl.h"

/* Global vars */
static checker_id_t ncheckers = 0;
list checkers_queue;

/* free checker data */
static void
free_checker(void *data)
{
	checker_t *checker= data;
	(*checker->free_func) (checker);
}

/* dump checker data */
static void
dump_checker(void *data)
{
	checker_t *checker = data;
	log_message(LOG_INFO, " %s:%d"
			    , inet_sockaddrtos(&checker->rs->addr)
			    , ntohs(inet_sockaddrport(&checker->rs->addr)));
	(*checker->dump_func) (checker);
}

/* Queue a checker into the checkers_queue */
void
queue_checker(void (*free_func) (void *), void (*dump_func) (void *)
	      , int (*launch) (thread_t *)
	      , void *data)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);
	checker_t *checker = (checker_t *) MALLOC(sizeof (checker_t));

	checker->free_func = free_func;
	checker->dump_func = dump_func;
	checker->launch = launch;
	checker->vs = vs;
	checker->rs = rs;
	checker->data = data;
	checker->id = ncheckers++;
	checker->enabled = (vs->vfwmark) ? 1 : 0;
#ifdef _WITHOUT_VRRP_
	checker->enabled = 1;
#endif

	/* queue the checker */
	list_add(checkers_queue, checker);

	/* In Alpha mode also mark the check as failed. */
	if (vs->alpha) {
		list fc = rs->failed_checkers;
		checker_id_t *id = (checker_id_t *) MALLOC(sizeof(checker_id_t));
		*id = checker->id;
		list_add (fc, id);
	}
}

/* Set dst */
void
checker_set_dst(struct sockaddr_storage *dst)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);

	*dst = rs->addr;
}

void
checker_set_dst_port(struct sockaddr_storage *dst, uint16_t port)
{
	if (dst->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) dst;
		addr6->sin6_port = port;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) dst;
		addr4->sin_port = port;
	}
}

/* dump the checkers_queue */
void
dump_checkers_queue(void)
{
	if (!LIST_ISEMPTY(checkers_queue)) {
		log_message(LOG_INFO, "------< Health checkers >------");
		dump_list(checkers_queue);
	}
}

/* init the global checkers queue */
void
init_checkers_queue(void)
{
	checkers_queue = alloc_list(free_checker, dump_checker);
}

/* release the checkers_queue */
void
free_checkers_queue(void)
{
	free_list(checkers_queue);
	checkers_queue = NULL;
	ncheckers = 0;
}

/* register checkers to the global I/O scheduler */
void
register_checkers_thread(void)
{
	checker_t *checker;
	element e;

	for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
		checker = ELEMENT_DATA(e);
		log_message(LOG_INFO, "Activating healtchecker for service [%s]:%d"
				    , inet_sockaddrtos(&checker->rs->addr)
				    , ntohs(inet_sockaddrport(&checker->rs->addr)));
		CHECKER_ENABLE(checker);
		if (checker->launch)
			thread_add_timer(master, checker->launch, checker,
					 BOOTSTRAP_DELAY);
	}
}

/* Sync checkers activity with netlink kernel reflection */
void
update_checker_activity(sa_family_t family, void *address, int enable)
{
	checker_t *checker;
	sa_family_t vip_family;
	element e;
	char addr_str[INET6_ADDRSTRLEN];
	void *addr;

	/* Display netlink operation */
	if (debug & 32) {
		inet_ntop(family, address, addr_str, sizeof(addr_str));
		log_message(LOG_INFO, "Netlink reflector reports IP %s %s"
				    , addr_str, (enable) ? "added" : "removed");
	}

	/* Processing Healthcheckers queue */
	if (!LIST_ISEMPTY(checkers_queue)) {
		for (e = LIST_HEAD(checkers_queue); e; ELEMENT_NEXT(e)) {
			checker = ELEMENT_DATA(e);
			vip_family = checker->vs->addr.ss_family;

			if (vip_family != family)
				continue;

			if (family == AF_INET6) {
				addr = (void *) &((struct sockaddr_in6 *)&checker->vs->addr)->sin6_addr;
			} else {
				addr = (void *) &((struct sockaddr_in *)&checker->vs->addr)->sin_addr;
			}

			if (inaddr_equal(family, addr, address) &&
			    CHECKER_HA_SUSPEND(checker)) {
				if (!CHECKER_ENABLED(checker) && enable)
					log_message(LOG_INFO, "Activating healtchecker for service [%s]:%d"
							    , inet_sockaddrtos(&checker->rs->addr)
							    , ntohs(inet_sockaddrport(&checker->rs->addr)));
				if (CHECKER_ENABLED(checker) && !enable)
					log_message(LOG_INFO, "Suspending healtchecker for service [%s]:%d"
							    , inet_sockaddrtos(&checker->rs->addr)
							    , ntohs(inet_sockaddrport(&checker->rs->addr)));
				checker->enabled = enable;
			}
		}
	}
}

/* Install checkers keywords */
void
install_checkers_keyword(void)
{
	install_misc_check_keyword();
	install_smtp_check_keyword();
	install_tcp_check_keyword();
	install_http_check_keyword();
	install_ssl_check_keyword();
}

static char *
ip_select_algo_name(unsigned algo)
{
	char *algo_name = NULL;
	
	switch (algo) {
	case IPVS_SNAT_IPS_NORMAL:
		algo_name = "sdh";
		break;
	case IPVS_SNAT_IPS_PERSITENT:
		algo_name = "sh";
		break;
	case IPVS_SNAT_IPS_RANDOM:
		algo_name = "random";
		break;
	}
	
	return algo_name;
}

static void 
addrmask_to_str(int af, const union nf_inet_addr *addr,
	                            unsigned short mask, char *output)
{                
	char pbuf[INET6_ADDRSTRLEN] = {0};
	if (af == AF_INET) {
		inet_ntop(af, &addr->in, pbuf, sizeof(pbuf));
		sprintf(output, "%s/%d", pbuf, mask);  
	} else {
		inet_ntop(af, &addr->in6, pbuf, sizeof(pbuf));
		sprintf(output, "[%s]/%d",  pbuf,  mask);  
	}
}

static void
addr_to_str(int af, const union nf_inet_addr *addr, char *output)
{
	char pbuf[INET6_ADDRSTRLEN]; 
	if (af == AF_INET) {
		sprintf(output, "%s", inet_ntop(af, (void *)&(addr->in), pbuf, sizeof(pbuf)));  
	} else {
		sprintf(output, "[%s]",  inet_ntop(af, (void *)&(addr->in6), pbuf, sizeof(pbuf)));  
	}
}

static void
addrpool_to_str(int af, const union nf_inet_addr* minaddr, 
	                                const union nf_inet_addr* maxaddr, char *output)
{
	char min_buf[INET6_ADDRSTRLEN] = {0};
	char max_buf[INET6_ADDRSTRLEN] = {0};
	if (af == AF_INET) {
		inet_ntop(af, (void *)&(minaddr->in), min_buf, sizeof(min_buf));
		inet_ntop(af, (void *)&(maxaddr->in), max_buf, sizeof(max_buf));
	} else {
		inet_ntop(af, (void *)&(minaddr->in6), min_buf, sizeof(min_buf));
		inet_ntop(af, (void *)&(maxaddr->in6), max_buf, sizeof(max_buf));  
	}
	
	 if (!strcmp(min_buf, max_buf)) {
		sprintf(output, "%s", min_buf); 
	 } else {
		sprintf(output, "%s-%s", min_buf, max_buf); 
	 }
}

void 
print_snat_rule(int cmd, snat_rule *rs)
{
	char output[512] = {0};
	
	char src_mask[128] = {0};
	char dst_mask[128] = {0};
	char gw[128] = {0};
	char new_gw[128] = {0};
	char snatip[256] = {0};

	addrmask_to_str(rs->af, &rs->saddr, rs->smask, src_mask);
	addrmask_to_str(rs->af, &rs->daddr, rs->dmask, dst_mask);
	addr_to_str(rs->af, &rs->gw, gw);
	addrpool_to_str(rs->af, &rs->minip, &rs->maxip, snatip);
	addr_to_str(rs->af, &rs->new_gw, new_gw);
	sprintf(output,
	    "snat rule[-F %s -T %s -W %s --oif %s -U %s -O %s -N %s]",
	    src_mask,
	    dst_mask,
	    gw,
	    rs->out_dev,
	    snatip,
	    ip_select_algo_name(rs->algo),
	    new_gw);

	if (cmd == LVS_CMD_DEL_SNATDEST) {
		log_message(LOG_INFO, "Removing %s", output);
	} else if (cmd == LVS_CMD_ADD_SNATDEST) {
		log_message(LOG_INFO, "Adding %s", output);
	} else {
		log_message(LOG_INFO, "%s", output);
	}
}

