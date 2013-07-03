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

#include <netdb.h>
#include "check_data.h"
#include "check_api.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "ipwrapper.h"

/* global vars */
check_conf_data *check_data = NULL;
check_conf_data *old_check_data = NULL;

/* SSL facility functions */
SSL_DATA *
alloc_ssl(void)
{
	SSL_DATA *ssl = (SSL_DATA *) MALLOC(sizeof (SSL_DATA));
	return ssl;
}
void
free_ssl(void)
{
	SSL_DATA *ssl = check_data->ssl;

	if (!ssl)
		return;
	FREE_PTR(ssl->password);
	FREE_PTR(ssl->cafile);
	FREE_PTR(ssl->certfile);
	FREE_PTR(ssl->keyfile);
	FREE(ssl);
}
static void
dump_ssl(void)
{
	SSL_DATA *ssl = check_data->ssl;

	if (ssl->password)
		log_message(LOG_INFO, " Password : %s", ssl->password);
	if (ssl->cafile)
		log_message(LOG_INFO, " CA-file : %s", ssl->cafile);
	if (ssl->certfile)
		log_message(LOG_INFO, " Certificate file : %s", ssl->certfile);
	if (ssl->keyfile)
		log_message(LOG_INFO, " Key file : %s", ssl->keyfile);
	if (!ssl->password && !ssl->cafile && !ssl->certfile && !ssl->keyfile)
		log_message(LOG_INFO, " Using autogen SSL context");
}

/* local IP address group facility functions */
static void
free_laddr_group(void *data)
{
	local_addr_group *laddr_group = data;
	FREE_PTR(laddr_group->gname);
	free_list(laddr_group->addr_ip);
	free_list(laddr_group->range);
	FREE(laddr_group);
}
static void
dump_laddr_group(void *data)
{
	local_addr_group *laddr_group = data;

	log_message(LOG_INFO, " local IP address group = %s", laddr_group->gname);
	dump_list(laddr_group->addr_ip);
	dump_list(laddr_group->range);
}
static void
free_laddr_entry(void *data)
{
	FREE(data);
}
static void
dump_laddr_entry(void *data)
{
	local_addr_entry *laddr_entry = data;

	if (laddr_entry->range)
		log_message(LOG_INFO, "   IP Range = %s-%d"
				    , inet_sockaddrtos(&laddr_entry->addr)
				    , laddr_entry->range);
	else
		log_message(LOG_INFO, "   IP = %s"
				    , inet_sockaddrtos(&laddr_entry->addr));
}
void
alloc_laddr_group(char *gname)
{
	int size = strlen(gname);
	local_addr_group *new;

	new = (local_addr_group *) MALLOC(sizeof (local_addr_group));
	new->gname = (char *) MALLOC(size + 1);
	memcpy(new->gname, gname, size);
	new->addr_ip = alloc_list(free_laddr_entry, dump_laddr_entry);
	new->range = alloc_list(free_laddr_entry, dump_laddr_entry);

	list_add(check_data->laddr_group, new);
}
void
alloc_laddr_entry(vector strvec)
{
	local_addr_group *laddr_group = LIST_TAIL_DATA(check_data->laddr_group);
	local_addr_entry *new;

	new = (local_addr_entry *) MALLOC(sizeof (local_addr_entry));


	new->range = inet_stor(VECTOR_SLOT(strvec, 0));
	inet_stosockaddr(VECTOR_SLOT(strvec, 0), NULL, &new->addr);
	if (!new->range)
		list_add(laddr_group->addr_ip, new);
	else if ( (0 < new->range) && (new->range < 255) )
		list_add(laddr_group->range, new);
	else
		log_message(LOG_INFO, "invalid: local IP address range %d", new->range);
}

/* Virtual server group facility functions */
static void
free_vsg(void *data)
{
	virtual_server_group *vsg = data;
	FREE_PTR(vsg->gname);
	free_list(vsg->addr_ip);
	free_list(vsg->range);
	free_list(vsg->vfwmark);
	FREE(vsg);
}
static void
dump_vsg(void *data)
{
	virtual_server_group *vsg = data;

	log_message(LOG_INFO, " Virtual Server Group = %s", vsg->gname);
	dump_list(vsg->addr_ip);
	dump_list(vsg->range);
	dump_list(vsg->vfwmark);
}
static void
free_vsg_entry(void *data)
{
	FREE(data);
}
static void
dump_vsg_entry(void *data)
{
	virtual_server_group_entry *vsg_entry = data;

	if (vsg_entry->vfwmark)
		log_message(LOG_INFO, "   FWMARK = %d", vsg_entry->vfwmark);
	else if (vsg_entry->range)
		log_message(LOG_INFO, "   VIP Range = %s-%d, VPORT = %d"
				    , inet_sockaddrtos(&vsg_entry->addr)
				    , vsg_entry->range
				    , ntohs(inet_sockaddrport(&vsg_entry->addr)));
	else
		log_message(LOG_INFO, "   VIP = %s, VPORT = %d"
				    , inet_sockaddrtos(&vsg_entry->addr)
				    , ntohs(inet_sockaddrport(&vsg_entry->addr)));
}
void
alloc_vsg(char *gname)
{
	int size = strlen(gname);
	virtual_server_group *new;

	new = (virtual_server_group *) MALLOC(sizeof (virtual_server_group));
	new->gname = (char *) MALLOC(size + 1);
	memcpy(new->gname, gname, size);
	new->addr_ip = alloc_list(free_vsg_entry, dump_vsg_entry);
	new->range = alloc_list(free_vsg_entry, dump_vsg_entry);
	new->vfwmark = alloc_list(free_vsg_entry, dump_vsg_entry);

	list_add(check_data->vs_group, new);
}
void
alloc_vsg_entry(vector strvec)
{
	virtual_server_group *vsg = LIST_TAIL_DATA(check_data->vs_group);
	virtual_server_group_entry *new;

	new = (virtual_server_group_entry *) MALLOC(sizeof (virtual_server_group_entry));

	if (!strcmp(VECTOR_SLOT(strvec, 0), "fwmark")) {
		new->vfwmark = atoi(VECTOR_SLOT(strvec, 1));
		list_add(vsg->vfwmark, new);
	} else {
		new->range = inet_stor(VECTOR_SLOT(strvec, 0));
		inet_stosockaddr(VECTOR_SLOT(strvec, 0), VECTOR_SLOT(strvec, 1), &new->addr);
		if (!new->range)
			list_add(vsg->addr_ip, new);
		else if ((0 < new->range) && (new->range < 255))
			list_add(vsg->range, new);
		else
			log_message(LOG_INFO, "invalid: VSG IP address range %d", new->range);
	}
}

/* Virtual server facility functions */
static void
free_vs(void *data)
{
	virtual_server *vs = data;
	FREE_PTR(vs->vsgname);
	FREE_PTR(vs->virtualhost);
	FREE_PTR(vs->s_svr);
	free_list(vs->rs);
	FREE_PTR(vs->quorum_up);
	FREE_PTR(vs->quorum_down);
	FREE_PTR(vs->local_addr_gname);
	FREE_PTR(vs->vip_bind_dev);
	FREE(vs);
}
static void
dump_vs(void *data)
{
	virtual_server *vs = data;

	if (vs->vsgname)
		log_message(LOG_INFO, " VS GROUP = %s", vs->vsgname);
	else if (vs->vfwmark)
		log_message(LOG_INFO, " VS FWMARK = %d", vs->vfwmark);
	else
		log_message(LOG_INFO, " VIP = %s, VPORT = %d"
				    , inet_sockaddrtos(&vs->addr), ntohs(inet_sockaddrport(&vs->addr)));
	if (vs->virtualhost)
		log_message(LOG_INFO, "   VirtualHost = %s", vs->virtualhost);
	log_message(LOG_INFO, "   delay_loop = %lu, lb_algo = %s",
	       (vs->delay_loop >= TIMER_MAX_SEC) ? vs->delay_loop/TIMER_HZ :
						   vs->delay_loop,
	       vs->sched);
	if (atoi(vs->timeout_persistence) > 0)
		log_message(LOG_INFO, "   persistence timeout = %s",
		       vs->timeout_persistence);
	if (vs->granularity_persistence)
		log_message(LOG_INFO, "   persistence granularity = %s",
		       inet_ntop2(vs->granularity_persistence));
	log_message(LOG_INFO, "   protocol = %s",
	       (vs->service_type == IPPROTO_TCP) ? "TCP" : "UDP");
	log_message(LOG_INFO, "   alpha is %s, omega is %s",
		    vs->alpha ? "ON" : "OFF", vs->omega ? "ON" : "OFF");
	log_message(LOG_INFO, "   SYN proxy is %s", 
		    vs->syn_proxy ? "ON" : "OFF");
	log_message(LOG_INFO, "   quorum = %lu, hysteresis = %lu", vs->quorum, vs->hysteresis);
	if (vs->quorum_up)
		log_message(LOG_INFO, "   -> Notify script UP = %s",
			    vs->quorum_up);
	if (vs->quorum_down)
		log_message(LOG_INFO, "   -> Notify script DOWN = %s",
			    vs->quorum_down);
	if (vs->ha_suspend)
		log_message(LOG_INFO, "   Using HA suspend");

	switch (vs->loadbalancing_kind) {
#ifdef _WITH_LVS_
	case IP_VS_CONN_F_MASQ:
		log_message(LOG_INFO, "   lb_kind = NAT");
		break;
	case IP_VS_CONN_F_DROUTE:
		log_message(LOG_INFO, "   lb_kind = DR");
		break;
	case IP_VS_CONN_F_TUNNEL:
		log_message(LOG_INFO, "   lb_kind = TUN");
		break;
	case IP_VS_CONN_F_FULLNAT:
		log_message(LOG_INFO, "   lb_kind = FNAT");
		break;
#endif
	}

	if (vs->s_svr) {
		log_message(LOG_INFO, "   sorry server = %s:%d"
				    , inet_sockaddrtos(&vs->s_svr->addr)
				    , ntohs(inet_sockaddrport(&vs->s_svr->addr)));
	}
	if (!LIST_ISEMPTY(vs->rs))
		dump_list(vs->rs);
	if (vs->local_addr_gname)
		log_message(LOG_INFO, " LOCAL_ADDR GROUP = %s", vs->local_addr_gname);
	if (vs->vip_bind_dev)
		log_message(LOG_INFO, " vip_bind_dev = %s", vs->vip_bind_dev);
}

void
alloc_vs(char *ip, char *port)
{
	int size = strlen(port);
	virtual_server *new;

	new = (virtual_server *) MALLOC(sizeof (virtual_server));

	if (!strcmp(ip, "group")) {
		new->vsgname = (char *) MALLOC(size + 1);
		memcpy(new->vsgname, port, size);
	} else if (!strcmp(ip, "fwmark")) {
		new->vfwmark = atoi(port);
	} else {
		inet_stosockaddr(ip, port, &new->addr);
	}

	new->delay_loop = KEEPALIVED_DEFAULT_DELAY;
	strncpy(new->timeout_persistence, "0", 1);
	new->virtualhost = NULL;
	new->alpha = 0;
	new->omega = 0;
	new->syn_proxy = 0;
	new->quorum_up = NULL;
	new->quorum_down = NULL;
	new->quorum = 1;
	new->hysteresis = 0;
	new->quorum_state = UP;
	new->local_addr_gname = NULL;
	new->vip_bind_dev = NULL;

	list_add(check_data->vs, new);
}

/* Sorry server facility functions */
void
alloc_ssvr(char *ip, char *port)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);

	vs->s_svr = (real_server *) MALLOC(sizeof (real_server));
	vs->s_svr->weight = 1;
	vs->s_svr->iweight = 1;
	inet_stosockaddr(ip, port, &vs->s_svr->addr);
}

/* Real server facility functions */
static void
free_rs(void *data)
{
	real_server *rs = data;
	FREE_PTR(rs->notify_up);
	FREE_PTR(rs->notify_down);
	free_list(rs->failed_checkers);
	FREE(rs);
}
static void
dump_rs(void *data)
{
	real_server *rs = data;

	log_message(LOG_INFO, "   RIP = %s, RPORT = %d, WEIGHT = %d"
			    , inet_sockaddrtos(&rs->addr)
			    , ntohs(inet_sockaddrport(&rs->addr))
			    , rs->weight);
	if (rs->inhibit)
		log_message(LOG_INFO, "     -> Inhibit service on failure");
	if (rs->notify_up)
		log_message(LOG_INFO, "     -> Notify script UP = %s",
		       rs->notify_up);
	if (rs->notify_down)
		log_message(LOG_INFO, "     -> Notify script DOWN = %s",
		       rs->notify_down);
}

static void
free_failed_checkers(void *data)
{
	FREE(data);
}

void
alloc_rs(char *ip, char *port)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *new;

	new = (real_server *) MALLOC(sizeof (real_server));
	inet_stosockaddr(ip, port, &new->addr);

	new->weight = 1;
	new->iweight = 1;
	new->failed_checkers = alloc_list(free_failed_checkers, NULL);

	if (LIST_ISEMPTY(vs->rs))
		vs->rs = alloc_list(free_rs, dump_rs);
	list_add(vs->rs, new);
}

/* data facility functions */
check_conf_data *
alloc_check_data(void)
{
	check_conf_data *new;

	new = (check_conf_data *) MALLOC(sizeof (check_conf_data));
	new->vs = alloc_list(free_vs, dump_vs);
	new->vs_group = alloc_list(free_vsg, dump_vsg);
	new->laddr_group = alloc_list(free_laddr_group, dump_laddr_group);

	return new;
}

void
free_check_data(check_conf_data *check_data)
{
	free_list(check_data->vs);
	free_list(check_data->vs_group);
	free_list(check_data->laddr_group);
	FREE(check_data);
}

void
dump_check_data(check_conf_data *check_data)
{
	if (check_data->ssl) {
		log_message(LOG_INFO, "------< SSL definitions >------");
		dump_ssl();
	}
	if (!LIST_ISEMPTY(check_data->vs)) {
		log_message(LOG_INFO, "------< LVS Topology >------");
		log_message(LOG_INFO, " System is compiled with LVS v%d.%d.%d",
		       NVERSION(IP_VS_VERSION_CODE));
		if (!LIST_ISEMPTY(check_data->laddr_group))
			dump_list(check_data->laddr_group);
		if (!LIST_ISEMPTY(check_data->vs_group))
			dump_list(check_data->vs_group);
		dump_list(check_data->vs);
	}
	dump_checkers_queue();
}
