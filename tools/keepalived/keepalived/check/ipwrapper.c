/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Manipulation functions for IPVS & IPFW wrappers.
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

#include "ipwrapper.h"
#include "ipvswrapper.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "notify.h"
#include "main.h"

#include "vrrp_if.h"
#include "vrrp_netlink.h"


static struct {
	struct nlmsghdr n;
	struct ifaddrmsg ifa;
	char buf[256];
} req;

vip_data *
get_vip_by_addr(struct sockaddr_storage *addr)
{
	vip_data *ip_entry;
	element e;

	for (e = LIST_HEAD(vip_queue); e; ELEMENT_NEXT(e)) {
		ip_entry = ELEMENT_DATA(e);
		if (sockstorage_equal(&ip_entry->addr, addr))
			return ip_entry;
	}

	return NULL;
}

static int
vip_check(struct nlmsghdr *n)
{
	struct ifaddrmsg *ifa;
	vip_data *ip_entry;
	int ret = 0;
	struct sockaddr_storage addr;

	/* vip_queue has not been init */
	if (vip_queue == NULL)
		return 1;

	ifa = NLMSG_DATA(n);
	addr.ss_family = ifa->ifa_family;
	if (ifa->ifa_family == AF_INET) {
		((struct sockaddr_in *) &addr)->sin_addr =
		*(struct in_addr *)RTA_DATA((void*)n + NLMSG_SPACE(sizeof(struct ifaddrmsg)));
		((struct sockaddr_in *) &addr)->sin_port = 0;	/* clear port */
	} else {
		((struct sockaddr_in6 *) &addr)->sin6_addr =
		*(struct in6_addr *)RTA_DATA((void*)n + NLMSG_SPACE(sizeof(struct ifaddrmsg)));
		((struct sockaddr_in6 *) &addr)->sin6_port = 0;
	}

	ip_entry = get_vip_by_addr(&addr);
	if (ip_entry == NULL) {
		log_message(LOG_INFO,"unexpected vip:%s"
				,inet_sockaddrtos(&addr));
		return ret;
	}

	switch(n->nlmsg_type) {
	/* add vip */
	case RTM_NEWADDR:
		if (ip_entry->set_cnt < ip_entry->entry_cnt) {
			ret = (ip_entry->set_cnt? 0 : 1);
			ip_entry->set_cnt++;
			log_message(LOG_INFO, "%s VIP %s"
					,ret ? "ADD":"HOLD"
					,inet_sockaddrtos(&addr));
		} else {
			ret = 0;
			log_message(LOG_INFO,"vip=%s has been set too many times(%d)"
					,inet_sockaddrtos(&addr)
					,ip_entry->entry_cnt);
		}
		break;
	/* del vip */
	case RTM_DELADDR:
		if (ip_entry->set_cnt > 0 ) {
			ip_entry->set_cnt--;
			/* reference counter is 0, then del vip */
			ret = (ip_entry->set_cnt ? 0 : 1);
			log_message(LOG_INFO, "%s VIP %s"
					,ret ? "DEL":"UNHOLD"
					,inet_sockaddrtos(&addr));
		} else {
			ret = 0;
			log_message(LOG_INFO,"vip=%s has been deleted"
					,inet_sockaddrtos(&addr));
		}
		break;
	default:
		log_message(LOG_INFO,"unknown opcode:%d , vip=%s"
				,n->nlmsg_type
				,inet_sockaddrtos(&addr));
	}

	return ret;
}

/* send message to netlink kernel socket, ignore response */
int
netlink_cmd(struct nl_handle *nl, struct nlmsghdr *n)
{
	int status;
	struct sockaddr_nl snl;
	struct iovec iov = { (void *) n, n->nlmsg_len };
	struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };

	status = vip_check(n);
	if (status <= 0)
		return status;

	memset(&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;

	n->nlmsg_seq = ++nl->seq;

	/* Request Netlink acknowledgement */
//	n->nlmsg_flags |= NLM_F_ACK;

	/* Send message to netlink interface. */
	status = sendmsg(nl->fd, &msg, 0);
	if (status < 0) {
		log_message(LOG_INFO, "Netlink: sendmsg() error: %s",
		       strerror(errno));
		return -1;
	}

	return status;
}

/* ip range handle. the req messgage must be set */
void
netlink_range_cmd(int cmd, virtual_server_group_entry *vsg_entry)
{
	uint32_t addr_ip, ip;
	struct in6_addr addr_v6;
	struct in_addr addr_v4;
	struct sockaddr_storage *addr = &vsg_entry->addr;

	log_message(LOG_INFO, "%s VIP Range %s-%d"
			    , cmd ? "ADD":"DEL"
			    , inet_sockaddrtos(&vsg_entry->addr)
			    , vsg_entry->range);

	req.n.nlmsg_type = cmd ? RTM_NEWADDR : RTM_DELADDR;
	req.ifa.ifa_family = addr->ss_family;
	if(req.ifa.ifa_family == AF_INET6) {
		req.ifa.ifa_prefixlen = 128;
		inet_sockaddrip6(addr, &addr_v6);
		ip = addr_v6.s6_addr32[3];

		/* Parse the whole range */
		for (addr_ip = ip;
				((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
				addr_ip += 0x01000000) {
			/* nlmsg_len will modify by addattr_l(). 
			 * It must be reset in each circle.
			 */
			req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));

			addr_v6.s6_addr32[3] = addr_ip;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL,
					&addr_v6, sizeof(struct in6_addr));
			if (netlink_cmd(&nl_cmd, &req.n) < 0)
				log_message(LOG_INFO, "%s VIP range failed, at %d",
						cmd ? "ADD":"DEL",
						((addr_ip >> 24) & 0xFF));

		}
	} else {
		req.ifa.ifa_prefixlen = 32;
		addr_v4 = ((struct sockaddr_in *)addr)->sin_addr;
		ip = addr_v4.s_addr;

		/* Parse the whole range */
		for (addr_ip = ip;
				((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
				addr_ip += 0x01000000) {
			req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));
			addr_v4.s_addr = addr_ip;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL,
					&addr_v4, sizeof(struct in_addr));
			if (netlink_cmd(&nl_cmd, &req.n) < 0)
				log_message(LOG_INFO, "%s VIP range failed, at %d",
						cmd ? "ADD":"DEL",
						((addr_ip >> 24) & 0xFF));
		}
	}
}

/* call by netlink_vipaddress() only */
int
netlink_group_vipaddress(list vs_group, char * vsgname, int cmd)
{
	virtual_server_group *vsg = ipvs_get_group_by_name(vsgname, vs_group);
	virtual_server_group_entry *vsg_entry;
	struct sockaddr_storage *addr;
	list l;
	element e;
	int err = 1;

	if (!vsg) return -1;

	/* visit addr_ip list */
	l = vsg->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		addr = &vsg_entry->addr;
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));
		req.ifa.ifa_family = addr->ss_family;
		if(req.ifa.ifa_family == AF_INET6) {
			req.ifa.ifa_prefixlen = 128;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL,
				&((struct sockaddr_in6 *)addr)->sin6_addr,
						sizeof(struct in6_addr));
		} else {
			req.ifa.ifa_prefixlen = 32;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL,
				&((struct sockaddr_in *)addr)->sin_addr,
						sizeof(struct in_addr));
		}

		if (netlink_cmd(&nl_cmd, &req.n) < 0)
			log_message(LOG_INFO, "%s VIP = %s failed",
						cmd ? "ADD":"DEL",
						inet_sockaddrtos(addr));
	}

	/* visit range list */
	l = vsg->range;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		netlink_range_cmd(cmd, vsg_entry);
	}

	return err;
}

/* add/del VIP from a VS */
int
netlink_vipaddress(list vs_group, virtual_server *vs, int cmd)
{
	unsigned int ifa_idx;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = cmd ? RTM_NEWADDR : RTM_DELADDR;

	if (vs->vip_bind_dev) {
		ifa_idx = if_nametoindex(vs->vip_bind_dev);
//		log_message(LOG_INFO, "vip_bind_dev: %s", vs->vip_bind_dev);
	} else {
		return 0;
//		ifa_idx = if_nametoindex("lo");
//		log_message(LOG_INFO, "vip_bind_dev isn't set.
//						Use default interface lo");
	}
	if (!ifa_idx) {
		log_message(LOG_INFO, "interface %s does not exist",
							vs->vip_bind_dev);
		return 0;
	}

	req.ifa.ifa_index = ifa_idx;

	if (vs->vfwmark)
		 log_message(LOG_INFO, " VS FWMARK, skip");
	else if(vs->vsgname) {
		netlink_group_vipaddress(vs_group, vs->vsgname, cmd);
	} else {
		req.ifa.ifa_family = vs->addr.ss_family;
		if(req.ifa.ifa_family == AF_INET6) {
			req.ifa.ifa_prefixlen = 128;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL,
				&((struct sockaddr_in6 *)&vs->addr)->sin6_addr,
						sizeof(struct in6_addr));
		} else {
			req.ifa.ifa_prefixlen = 32;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL,
				&((struct sockaddr_in *)&vs->addr)->sin_addr,
						sizeof(struct in_addr));
		}

		if (netlink_cmd(&nl_cmd, &req.n) < 0)
			log_message(LOG_INFO, "%s VIP = %s failed",
						cmd ? "ADD":"DEL",
						inet_sockaddrtos(&vs->addr));
	}

	return 1;
}

/* Remove  IP of the specific vs group entry */
void
netlink_group_remove_entry(virtual_server *vs, virtual_server_group_entry *vsge)
{
	unsigned int ifa_idx;
	struct sockaddr_storage *addr;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELADDR;

	if (!vs->vip_bind_dev)
		return;

	ifa_idx = if_nametoindex(vs->vip_bind_dev);
	if (!ifa_idx) {
		log_message(LOG_INFO, "interface %s does not exist",
							vs->vip_bind_dev);
		return;
	}

	req.ifa.ifa_index = ifa_idx;

	if (vsge->range) {
		netlink_range_cmd(DOWN, vsge);
	} else {
		addr = &vsge->addr;
		req.ifa.ifa_family = addr->ss_family;
		if(req.ifa.ifa_family == AF_INET6) {
			req.ifa.ifa_prefixlen = 128;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL,
				&((struct sockaddr_in6 *)addr)->sin6_addr,
						sizeof(struct in6_addr));
		} else {
			req.ifa.ifa_prefixlen = 32;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL,
				&((struct sockaddr_in *)addr)->sin_addr,
						sizeof(struct in_addr));
		}

		if (netlink_cmd(&nl_cmd, &req.n) < 0)
			log_message(LOG_INFO, "DEL VIP = %s failed",
						inet_sockaddrtos(addr));
	}
}

/* add the vip of new vsg_entry, in reload mode only */
void
add_new_vsge_vip(list vs_group, virtual_server *vs)
{
	unsigned int ifa_idx;
	virtual_server_group *vsg = ipvs_get_group_by_name(vs->vsgname, vs_group);
	virtual_server_group_entry *vsg_entry;
	struct sockaddr_storage *addr;
	list l;
	element e;

	if (!vs->vsgname || !vs->vip_bind_dev || !vsg)
		return;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWADDR;

	ifa_idx = if_nametoindex(vs->vip_bind_dev);

	if (!ifa_idx) {
		log_message(LOG_INFO, "interface %s does not exist",
							vs->vip_bind_dev);
		return;
	}

	req.ifa.ifa_index = ifa_idx;

	/* visit addr_ip list */
	l = vsg->addr_ip;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		if (ISALIVE(vsg_entry))
			continue;

		addr = &vsg_entry->addr;
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));
		req.ifa.ifa_family = addr->ss_family;
		if(req.ifa.ifa_family == AF_INET6) {
			req.ifa.ifa_prefixlen = 128;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL,
				&((struct sockaddr_in6 *)addr)->sin6_addr,
						sizeof(struct in6_addr));
		} else {
			req.ifa.ifa_prefixlen = 32;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL,
				&((struct sockaddr_in *)addr)->sin_addr,
						sizeof(struct in_addr));
		}

		log_message(LOG_INFO, "ADD VIP %s", inet_sockaddrtos(addr));
		if (netlink_cmd(&nl_cmd, &req.n) < 0)
			log_message(LOG_INFO, "ADD VIP = %s failed", inet_sockaddrtos(addr));
	}

	/* visit range list */
	l = vsg->range;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsg_entry = ELEMENT_DATA(e);

		if (ISALIVE(vsg_entry))
			continue;

		netlink_range_cmd(UP, vsg_entry);
	}
}

/* Returns the sum of all RS weight in a virtual server. */
long unsigned
weigh_live_realservers(virtual_server * vs)
{
	element e;
	real_server *svr;
	long unsigned count = 0;

	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		svr = ELEMENT_DATA(e);
		if (ISALIVE(svr))
			count += svr->weight;
	}
	return count;
}

/* Remove a realserver IPVS rule */
static int
clear_service_rs(list vs_group, virtual_server * vs, list l)
{
	element e;
	real_server *rs;
	char rsip[INET6_ADDRSTRLEN];

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (ISALIVE(rs)) {
			if (!ipvs_cmd(LVS_CMD_DEL_DEST, vs_group, vs, rs))
				return 0;
			UNSET_ALIVE(rs);
			if (!vs->omega)
				continue;

			/* In Omega mode we call VS and RS down notifiers
			 * all the way down the exit, as necessary.
			 */
			if (rs->notify_down) {
				log_message(LOG_INFO, "Executing [%s] for service [%s]:%d in VS [%s]:%d"
						    , rs->notify_down
						    , inet_sockaddrtos2(&rs->addr, rsip)
						    , ntohs(inet_sockaddrport(&rs->addr))
						    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
						    , ntohs(inet_sockaddrport(&vs->addr)));
				notify_exec(rs->notify_down);
			}

			/* Sooner or later VS will lose the quorum (if any). However,
			 * we don't push in a sorry server then, hence the regression
			 * is intended.
			 */
			if (vs->quorum_state == UP &&
			    weigh_live_realservers(vs) < vs->quorum - vs->hysteresis) {
				vs->quorum_state = DOWN;
				netlink_vipaddress(vs_group, vs, DOWN);
				if (vs->quorum_down) {
					log_message(LOG_INFO, "Executing [%s] for VS [%s]:%d"
						    , vs->quorum_down
						    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
						    , ntohs(inet_sockaddrport(&vs->addr)));
					notify_exec(vs->quorum_down);
				}
			}
		}
	}

	return 1;
}

/* Remove a virtualserver IPVS rule */
static int
clear_service_vs(list vs_group, virtual_server * vs)
{
	/* Processing real server queue */
	if (!LIST_ISEMPTY(vs->rs)) {
		if (vs->s_svr) {
			if (ISALIVE(vs->s_svr))
				if (!ipvs_cmd(LVS_CMD_DEL_DEST, vs_group, vs, vs->s_svr))
					return 0;
		} else if (!clear_service_rs(vs_group, vs, vs->rs))
			return 0;
		/* The above will handle Omega case for VS as well. */
	}

	if (!ipvs_cmd(LVS_CMD_DEL, vs_group, vs, NULL))
		return 0;

	UNSET_ALIVE(vs);
	return 1;
}

/* IPVS cleaner processing */
int
clear_services(void)
{
	element e;
	list l = check_data->vs;
	virtual_server *vs;
	real_server *rs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		rs = ELEMENT_DATA(LIST_HEAD(vs->rs));
		if (!clear_service_vs(check_data->vs_group, vs))
			return 0;
	}
	return 1;
}

/* only for alpha & reload mode !!! */
void inline
alpha_reload_handle(virtual_server *vs, real_server *rs)
{
	if (ISALIVE(rs)) {
		/*
		 * In alpha mode, rs has been set failed_checkers
		 * we must do a clean in reload to make alive rs
		 * in consistent state
		 */
		list l = rs->failed_checkers;
		element next, tmp;

		for (tmp = LIST_HEAD(l); tmp; tmp = next) {
			next = tmp->next;
			free_list_element(l, tmp);
		}
		l->head = NULL;
		l->tail = NULL;

		/*
		 * vsgroup may has new entry after reload
		 * so add the alive rs to the new one
		 */
		if (vs->vsgname) {
			UNSET_ALIVE(rs);
			ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs);
			SET_ALIVE(rs);
		}
	}
}

/* Set a realserver IPVS rules */
static int
init_service_rs(virtual_server * vs)
{
	element e;
	real_server *rs;

	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		/* In alpha mode, be pessimistic (or realistic?) and don't
		 * add real servers into the VS pool. They will get there
		 * later upon healthchecks recovery (if ever).
		 */
		if (vs->alpha) {
			if (!reload)
				UNSET_ALIVE(rs);
			else
				alpha_reload_handle(vs, rs);
			continue;
		}
		if (!ISALIVE(rs)) {
			if (!ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs))
				return 0;
			else
				SET_ALIVE(rs);
		} else if (vs->vsgname) {
			UNSET_ALIVE(rs);
			if (!ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs))
				return 0;
			SET_ALIVE(rs);
		}
	}

	return 1;
}

static int
init_service_laddr(virtual_server * vs)
{
	/*Set local ip address in "FNAT" mode of IPVS */
	if ((vs->loadbalancing_kind == IP_VS_CONN_F_FULLNAT) && vs->local_addr_gname) {
		if (!ipvs_cmd(LVS_CMD_ADD_LADDR, check_data->vs_group, vs, NULL))
			return 0;
	}

	return 1;
}

static void
add_new_laddr(virtual_server *vs)
{
	local_addr_group *laddr_group;

	laddr_group = ipvs_get_laddr_group_by_name(vs->local_addr_gname,
						check_data->laddr_group);
	if (laddr_group)
		ipvs_new_laddr_add(vs, laddr_group);
}

/* Set a virtualserver IPVS rules */
static int
init_service_vs(virtual_server * vs)
{
	/*
	 * In reloading, bind the new vip(vsge) to make a consistent state.
	 * It's meaningful to virtual_server_group.
	 */

	if (reload && vs->alpha && (vs->quorum_state == UP) && vs->vsgname)
		add_new_vsge_vip(check_data->vs_group, vs);

	if (reload && vs->local_addr_gname)
		add_new_laddr(vs);

	/* Init the VS root */
	if (!ISALIVE(vs) || vs->vsgname) {
		if (!ipvs_cmd(LVS_CMD_ADD, check_data->vs_group, vs, NULL) ||
					!init_service_laddr(vs))
			return 0;
		else
			SET_ALIVE(vs);
	}

	/* Processing real server queue */
	if (!LIST_ISEMPTY(vs->rs)) {
		if (!init_service_rs(vs))
			return 0;

		if (!vs->alpha)
			netlink_vipaddress(check_data->vs_group, vs, UP);

		/* In fact vs quorum_state has been DOWN with conf reading */
		if (vs->alpha && !reload)
			vs->quorum_state = DOWN;
	}
	return 1;
}

/* Set IPVS rules */
int
init_services(void)
{
	element e;
	list l = check_data->vs;
	virtual_server *vs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (!init_service_vs(vs))
			return 0;
	}
	return 1;
}

/* add or remove _alive_ real servers from a virtual server */
void
perform_quorum_state(virtual_server *vs, int add)
{
	element e;
	real_server *rs;

	if (LIST_ISEMPTY(vs->rs))
		return;

	log_message(LOG_INFO, "%s the pool for VS [%s]:%d"
			    , add?"Adding alive servers to":"Removing alive servers from"
			    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
			    , ntohs(inet_sockaddrport(&vs->addr)));
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (!ISALIVE(rs)) /* We only handle alive servers */
			continue;
		if (add)
			rs->alive = 0;
		ipvs_cmd(add?LVS_CMD_ADD_DEST:LVS_CMD_DEL_DEST, check_data->vs_group, vs, rs);
		rs->alive = 1;
	}
}

/* set quorum state depending on current weight of real servers */
void
update_quorum_state(virtual_server * vs)
{
	long unsigned weigh_count;
	char rsip[INET6_ADDRSTRLEN];

	weigh_count = weigh_live_realservers(vs);

	/* If we have just gained quorum, it's time to consider notify_up. */
	if (vs->quorum_state == DOWN &&
			weigh_count >= vs->quorum + vs->hysteresis) {
		vs->quorum_state = UP;
		log_message(LOG_INFO, "Gained quorum %lu+%lu=%lu <= %u for VS [%s]:%d"
				    , vs->quorum
				    , vs->hysteresis
				    , vs->quorum + vs->hysteresis
				    , weigh_count
				    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
				    , ntohs(inet_sockaddrport(&vs->addr)));
		if (vs->s_svr && ISALIVE(vs->s_svr)) {
			log_message(LOG_INFO, "Removing sorry server [%s]:%d from VS [%s]:%d"
					    , inet_sockaddrtos2(&vs->s_svr->addr, rsip)
					    , ntohs(inet_sockaddrport(&vs->s_svr->addr))
					    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
					    , ntohs(inet_sockaddrport(&vs->addr)));

			ipvs_cmd(LVS_CMD_DEL_DEST, check_data->vs_group, vs, vs->s_svr);
			vs->s_svr->alive = 0;

			/* Adding back alive real servers */
			perform_quorum_state(vs, 1);
		}
		netlink_vipaddress(check_data->vs_group, vs, UP);
		if (vs->quorum_up) {
			log_message(LOG_INFO, "Executing [%s] for VS [%s]:%d"
					    , vs->quorum_up
					    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
					    , ntohs(inet_sockaddrport(&vs->addr)));
			notify_exec(vs->quorum_up);
		}
		return;
	}

	/* If we have just lost quorum for the VS, we need to consider
	 * VS notify_down and sorry_server cases
	 */
	if (vs->quorum_state == UP &&
			weigh_count < vs->quorum - vs->hysteresis) {
		vs->quorum_state = DOWN;
		log_message(LOG_INFO, "Lost quorum %lu-%lu=%lu > %u for VS [%s]:%d"
				    , vs->quorum
				    , vs->hysteresis
				    , vs->quorum - vs->hysteresis
				    , weigh_count
				    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
				    , ntohs(inet_sockaddrport(&vs->addr)));
		netlink_vipaddress(check_data->vs_group, vs, DOWN);
		if (vs->quorum_down) {
			log_message(LOG_INFO, "Executing [%s] for VS [%s]:%d"
					    , vs->quorum_down
					    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
					    , ntohs(inet_sockaddrport(&vs->addr)));
			notify_exec(vs->quorum_down);
		}
		if (vs->s_svr) {
			log_message(LOG_INFO, "Adding sorry server [%s]:%d to VS [%s]:%d"
					    , inet_sockaddrtos2(&vs->s_svr->addr, rsip)
					    , ntohs(inet_sockaddrport(&vs->s_svr->addr))
					    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
					    , ntohs(inet_sockaddrport(&vs->addr)));

			/* the sorry server is now up in the pool, we flag it alive */
			ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, vs->s_svr);
			vs->s_svr->alive = 1;

			/* Remove remaining alive real servers */
			perform_quorum_state(vs, 0);
		}
		return;
	}
}

/* manipulate add/remove rs according to alive state */
void
perform_svr_state(int alive, virtual_server * vs, real_server * rs)
{
	char rsip[INET6_ADDRSTRLEN];

	/*
	 * | ISALIVE(rs) | alive | context
	 * | 0           | 0     | first check failed under alpha mode, unreachable here
	 * | 0           | 1     | RS went up, add it to the pool
	 * | 1           | 0     | RS went down, remove it from the pool
	 * | 1           | 1     | first check succeeded w/o alpha mode, unreachable here
	 */
	if (!ISALIVE(rs) && alive) {
		log_message(LOG_INFO, "%s service [%s]:%d to VS [%s]:%d"
				    , (rs->inhibit) ? "Enabling" : "Adding"
				    , inet_sockaddrtos2(&rs->addr, rsip)
				    , ntohs(inet_sockaddrport(&rs->addr))
				    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
				    , ntohs(inet_sockaddrport(&vs->addr)));
		/* Add only if we have quorum or no sorry server */
		if (vs->quorum_state == UP || !vs->s_svr || !ISALIVE(vs->s_svr)) {
			ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs);
		}
		rs->alive = alive;
		if (rs->notify_up) {
			log_message(LOG_INFO, "Executing [%s] for service [%s]:%d in VS [%s]:%d"
					    , rs->notify_up
					    , inet_sockaddrtos2(&rs->addr, rsip)
					    , ntohs(inet_sockaddrport(&rs->addr))
					    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
					    , ntohs(inet_sockaddrport(&vs->addr)));
			notify_exec(rs->notify_up);
		}

		/* We may have gained quorum */
		if (vs->quorum_state == DOWN)
			update_quorum_state(vs);
	}

	if (ISALIVE(rs) && !alive) {
		log_message(LOG_INFO, "%s service [%s]:%d from VS [%s]:%d"
				    , (rs->inhibit) ? "Disabling" : "Removing"
				    , inet_sockaddrtos2(&rs->addr, rsip)
				    , ntohs(inet_sockaddrport(&rs->addr))
				    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
				    , ntohs(inet_sockaddrport(&vs->addr)));

		/* server is down, it is removed from the LVS realserver pool
		 * Remove only if we have quorum or no sorry server
		 */
		if (vs->quorum_state == UP || !vs->s_svr || !ISALIVE(vs->s_svr)) {
			ipvs_cmd(LVS_CMD_DEL_DEST, check_data->vs_group, vs, rs);
		}
		rs->alive = alive;
		if (rs->notify_down) {
			log_message(LOG_INFO, "Executing [%s] for service [%s]:%d in VS [%s]:%d"
					    , rs->notify_down
					    , inet_sockaddrtos2(&rs->addr, rsip)
					    , ntohs(inet_sockaddrport(&rs->addr))
					    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
					    , ntohs(inet_sockaddrport(&vs->addr)));
			notify_exec(rs->notify_down);
		}

		/* We may have lost quorum */
		if (vs->quorum_state == UP)
			update_quorum_state(vs);
	}
}

/* Store new weight in real_server struct and then update kernel. */
void
update_svr_wgt(int weight, virtual_server * vs, real_server * rs)
{
	char rsip[INET6_ADDRSTRLEN];

	if (weight != rs->weight) {
		log_message(LOG_INFO, "Changing weight from %d to %d for %s service [%s]:%d of VS [%s]:%d"
				    , rs->weight
				    , weight
				    , ISALIVE(rs) ? "active" : "inactive"
				    , inet_sockaddrtos2(&rs->addr, rsip)
				    , ntohs(inet_sockaddrport(&rs->addr))
				    , (vs->vsgname) ? vs->vsgname : inet_sockaddrtos(&vs->addr)
				    , ntohs(inet_sockaddrport(&vs->addr)));
		rs->weight = weight;
		/*
		 * Have weight change take effect now only if rs is in
		 * the pool and alive and the quorum is met (or if
		 * there is no sorry server). If not, it will take
		 * effect later when it becomes alive.
		 */
		if (rs->set && ISALIVE(rs) &&
		    (vs->quorum_state == UP || !vs->s_svr || !ISALIVE(vs->s_svr)))
			ipvs_cmd(LVS_CMD_EDIT_DEST, check_data->vs_group, vs, rs);
		update_quorum_state(vs);
	}
}

/* Test if realserver is marked UP for a specific checker */
int
svr_checker_up(checker_id_t cid, real_server *rs)
{
	element e;
	list l = rs->failed_checkers;
	checker_id_t *id;

	/*
	 * We assume there is not too much checker per
	 * real server, so we consider this lookup as
	 * o(1).
	 */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		id = ELEMENT_DATA(e);
		if (*id == cid)
			return 0;
	}

	return 1;
}

/* Update checker's state */
void
update_svr_checker_state(int alive, checker_id_t cid, virtual_server *vs, real_server *rs)
{
	element e;
	list l = rs->failed_checkers;
	checker_id_t *id;

	/* Handle alive state. Depopulate failed_checkers and call
	 * perform_svr_state() independently, letting the latter sort
	 * things out itself.
	 */
	if (alive) {
		/* Remove the succeeded check from failed_checkers list. */
		for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
			id = ELEMENT_DATA(e);
			if (*id == cid) {
				free_list_element(l, e);
				/* If we don't break, the next iteration will trigger
				 * a SIGSEGV.
				 */
				break;
			}
		}
		if (LIST_SIZE(l) == 0)
			perform_svr_state(alive, vs, rs);
	}
	/* Handle not alive state */
	else {
		id = (checker_id_t *) MALLOC(sizeof(checker_id_t));
		*id = cid;
		list_add(l, id);
		if (LIST_SIZE(l) == 1)
			perform_svr_state(alive, vs, rs);
	}
}

/* Check if a vsg entry is in new data */
static int
vsge_exist(virtual_server_group_entry *vsg_entry, list l)
{
	element e;
	virtual_server_group_entry *vsge;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsge = ELEMENT_DATA(e);
		if (VSGE_ISEQ(vsg_entry, vsge)) {
			/*
			 * If vsge exist this entry
			 * is alive since only rs entries
			 * are changing from alive state.
			 */
			SET_ALIVE(vsge);
			vsge->laddr_set = vsg_entry->laddr_set;
			return 1;
		}
	}

	return 0;
}

/* Clear the diff vsge of old group */
static int
clear_diff_vsge(list old, list new, virtual_server * old_vs)
{
	virtual_server_group_entry *vsge;
	element e;

	for (e = LIST_HEAD(old); e; ELEMENT_NEXT(e)) {
		vsge = ELEMENT_DATA(e);
		if (!vsge_exist(vsge, new)) {
			log_message(LOG_INFO, "VS [%s:%d:%d:%d] in group %s no longer exist\n" 
					    , inet_sockaddrtos(&vsge->addr)
					    , ntohs(inet_sockaddrport(&vsge->addr))
					    , vsge->range
					    , vsge->vfwmark
					    , old_vs->vsgname);

			if (!ipvs_group_remove_entry(old_vs, vsge))
				return 0;

			if (old_vs->vip_bind_dev && (old_vs->quorum_state == UP))
				netlink_group_remove_entry(old_vs, vsge);
		}
	}

	return 1;
}

/* Clear the diff vsg of the old vs */
static int
clear_diff_vsg(virtual_server * old_vs)
{
	virtual_server_group *old;
	virtual_server_group *new;

	/* Fetch group */
	old = ipvs_get_group_by_name(old_vs->vsgname, old_check_data->vs_group);
	new = ipvs_get_group_by_name(old_vs->vsgname, check_data->vs_group);

	/* Diff the group entries */
	if (!clear_diff_vsge(old->addr_ip, new->addr_ip, old_vs))
		return 0;
	if (!clear_diff_vsge(old->range, new->range, old_vs))
		return 0;
	if (!clear_diff_vsge(old->vfwmark, new->vfwmark, old_vs))
		return 0;

	return 1;
}

/* Check if a vs exist in new data */
static int
vs_exist(virtual_server * old_vs)
{
	element e;
	list l = check_data->vs;
	virtual_server *vs;
	virtual_server_group *vsg;

	if (LIST_ISEMPTY(l))
		return 0;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (VS_ISEQ(old_vs, vs)) {
			/* Check if dev change */
			if (((old_vs->vip_bind_dev && vs->vip_bind_dev &&
				strcmp(old_vs->vip_bind_dev, vs->vip_bind_dev)) ||
				(old_vs->vip_bind_dev != NULL && vs->vip_bind_dev == NULL)) &&
				(old_vs->quorum_state == UP)) {
				char *tmp = old_vs->vip_bind_dev;
				netlink_vipaddress(old_check_data->vs_group, old_vs, DOWN);
				old_vs->vip_bind_dev = vs->vip_bind_dev;
				netlink_vipaddress(old_check_data->vs_group, old_vs, UP);
				old_vs->vip_bind_dev = tmp;
			}

			/* Check if group exist */
			if (vs->vsgname) {
				vsg = ipvs_get_group_by_name(old_vs->vsgname,
							    check_data->vs_group);
				if (!vsg)
					return 0;
				else
					if (!clear_diff_vsg(old_vs))
						return 0;	
			}

			/*
			 * Exist so set alive.
			 */
			SET_ALIVE(vs);
			/* save the quorum_state  */
			if (reload && vs->alpha)
				vs->quorum_state = old_vs->quorum_state;
			return 1;
		}
	}

	return 0;
}

/* Check if rs is in new vs data */
static int
rs_exist(real_server * old_rs, list l)
{
	element e;
	real_server *rs;

	if (LIST_ISEMPTY(l))
		return 0;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (RS_ISEQ(rs, old_rs)) {
			/*
			 * We reflect the previous alive
			 * flag value to not try to set
			 * already set IPVS rule.
			 */
			rs->alive = old_rs->alive;
			rs->set = old_rs->set;
			rs->weight = old_rs->weight;
			return 1;
		}
	}

	return 0;
}

/* get rs list for a specific vs */
static list
get_rs_list(virtual_server * vs)
{
	element e;
	list l = check_data->vs;
	virtual_server *vsvr;

	if (LIST_ISEMPTY(l))
		return NULL;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsvr = ELEMENT_DATA(e);
		if (VS_ISEQ(vs, vsvr))
			return vsvr->rs;
	}

	/* most of the time never reached */
	return NULL;
}

/* Clear the diff rs of the old vs */
static int
clear_diff_rs(virtual_server * old_vs)
{
	element e;
	list l = old_vs->rs;
	list new = get_rs_list(old_vs);
	real_server *rs;
	char rsip[INET6_ADDRSTRLEN];

	/* If old vs didn't own rs then nothing return */
	if (LIST_ISEMPTY(l))
		return 1;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (!rs_exist(rs, new)) {
			/* Reset inhibit flag to delete inhibit entries */
			log_message(LOG_INFO, "service [%s]:%d no longer exist"
					    , inet_sockaddrtos(&rs->addr)
					    , ntohs(inet_sockaddrport(&rs->addr)));
			log_message(LOG_INFO, "Removing service [%s]:%d from VS [%s]:%d"
					    , inet_sockaddrtos2(&rs->addr, rsip)
					    , ntohs(inet_sockaddrport(&rs->addr))
					    , (old_vs->vsgname) ? old_vs->vsgname : inet_sockaddrtos(&old_vs->addr)
					    , ntohs(inet_sockaddrport(&old_vs->addr)));
			rs->inhibit = 0;
			/* Set alive flag to delete the failed inhibit entries */
			if (old_vs->vsgname)
				SET_ALIVE(rs);
			if (!ipvs_cmd(LVS_CMD_DEL_DEST, check_data->vs_group, old_vs, rs))
				return 0;
		}
	}

	return 1;
}

/* Check if a local address entry is in list */
static int
laddr_entry_exist(local_addr_entry *laddr_entry, list l)
{
	element e;
	local_addr_entry *entry;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		entry = ELEMENT_DATA(e);
		if (sockstorage_equal(&entry->addr, &laddr_entry->addr) && 
					entry->range == laddr_entry->range) {
			SET_ALIVE(entry);
			return 1;
		}
	}

	return 0;
}

/* Clear the diff local address entry of eth old vs */
static int
clear_diff_laddr_entry(list old, list new, virtual_server * old_vs)
{
	element e;
	local_addr_entry *laddr_entry;

	for (e = LIST_HEAD(old); e; ELEMENT_NEXT(e)) {
		laddr_entry = ELEMENT_DATA(e);
		if (!laddr_entry_exist(laddr_entry, new)) {
			log_message(LOG_INFO, "VS [%s-%d] in local address group %s no longer exist\n" 
					    , inet_sockaddrtos(&laddr_entry->addr)
					    , laddr_entry->range
					    , old_vs->local_addr_gname);

			if (!ipvs_laddr_remove_entry(old_vs, laddr_entry))
				return 0;
		}
	}

	return 1;
}

/* Clear the diff local address of the old vs */
static int
clear_diff_laddr(virtual_server * old_vs)
{
	local_addr_group *old;
	local_addr_group *new;

	/*
 	 *  If old vs was not in fulllnat mod or didn't own local address group, 
 	 * then do nothing and return 
 	 */
	if ((old_vs->loadbalancing_kind != IP_VS_CONN_F_FULLNAT) || 
						!old_vs->local_addr_gname)
		return 1;

	/* Fetch local address group */
	old = ipvs_get_laddr_group_by_name(old_vs->local_addr_gname, 
							old_check_data->laddr_group);
	new = ipvs_get_laddr_group_by_name(old_vs->local_addr_gname, 
							check_data->laddr_group);

	if (!clear_diff_laddr_entry(old->addr_ip, new->addr_ip, old_vs))
		return 0;
	if (!clear_diff_laddr_entry(old->range, new->range, old_vs))
		return 0;

	return 1;
}

/* When reloading configuration, remove negative diff entries */
int
clear_diff_services(void)
{
	element e;
	list l = old_check_data->vs;
	virtual_server *vs;

	/* If old config didn't own vs then nothing return */
	if (LIST_ISEMPTY(l))
		return 1;

	/* Remove diff entries from previous IPVS rules */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);

		/*
		 * Try to find this vs into the new conf data
		 * reloaded.
		 */
		if (!vs_exist(vs)) {
			if (vs->vsgname)
				log_message(LOG_INFO, "Removing Virtual Server Group [%s]"
						    , vs->vsgname);
			else
				log_message(LOG_INFO, "Removing Virtual Server [%s]:%d"
						    , inet_sockaddrtos(&vs->addr)
						    , ntohs(inet_sockaddrport(&vs->addr)));

			/* Clear VS entry */
			if (!clear_service_vs(old_check_data->vs_group, vs))
				return 0;
		} else {
			/* If vs exist, perform rs pool diff */
			if (!clear_diff_rs(vs))
				return 0;
			if (vs->s_svr)
				if (ISALIVE(vs->s_svr))
					if (!ipvs_cmd(LVS_CMD_DEL_DEST
						      , check_data->vs_group
						      , vs
						      , vs->s_svr))
						return 0;
			/* perform local address diff */
			if (!clear_diff_laddr(vs))
				return 0;
		}
	}

	return 1;
}
