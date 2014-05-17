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
#include "check_api.h"
#include "vrrp_if.h"
#include "vrrp_netlink.h"

static struct {
	struct nlmsghdr n;
	struct ifaddrmsg ifa;
	char buf[256];
} req;

/* send message to netlink kernel socket, ignore response */
int
netlink_cmd(struct nl_handle *nl, struct nlmsghdr *n)
{
	int status;
	struct sockaddr_nl snl;
	struct iovec iov = { (void *) n, n->nlmsg_len };
	struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };

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

		log_message(LOG_INFO, "%s VIP %s",
					cmd ? "ADD":"DEL", inet_sockaddrtos(addr));
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

		log_message(LOG_INFO, "%s VIP %s to %s",
					cmd ? "ADD":"DEL",
					inet_sockaddrtos(&vs->addr),
					vs->vip_bind_dev);
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

		log_message(LOG_INFO, "DEL VIP %s", inet_sockaddrtos(addr));
		if (netlink_cmd(&nl_cmd, &req.n) < 0)
			log_message(LOG_INFO, "DEL VIP = %s failed",
						inet_sockaddrtos(addr));
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

	if (IS_SNAT_SVC(vs)) {
	    snat_rule *sr;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		sr = ELEMENT_DATA(e);
		if (ISALIVE(sr)) {
			if (!ipvs_snat_cmd(LVS_CMD_DEL_SNATDEST, vs, sr)) {
				return 0;
			}
			UNSET_ALIVE(sr);
		}
	}
		return 1;
	}
	
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
		} else if (!clear_service_rs(vs_group, vs, vs->rs)) {
			return 0;
		/* The above will handle Omega case for VS as well. */
	}
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

/* select max weight of rs from vs 
	* flag == 1: select max weight of alive rs from vs
	*/
int
get_max_weight(int flag, list rs)
{
	element e;
	real_server *crs;
	int max_weight = -1;
	
	for (e = LIST_HEAD(rs); e; ELEMENT_NEXT(e)) {
		crs = ELEMENT_DATA(e);
		if (flag == 1 && crs->alive == 0) {
			continue;
		}
		if (max_weight > -1) {
			max_weight = crs->weight > max_weight ? crs->weight : max_weight;
		} else {
			max_weight = crs->weight;
		}
	}

	return max_weight;
}


static int
init_service_snat_rs(virtual_server *vs)
{
	element e;
	snat_rule *rs;
	
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (!ISALIVE(rs)) {
			print_snat_rule(LVS_CMD_ADD_SNATDEST, rs);
			if (!ipvs_snat_cmd(LVS_CMD_ADD_SNATDEST, vs, rs)) {
				return 0;
			}
			SET_ALIVE(rs);
		}
	}

	return 1;
}

/* Set a realserver IPVS rules */
static int
init_service_rs(virtual_server * vs)
{
	element e;
	real_server *rs;

	if (vs->abs_priority == 0) {
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		/* In alpha mode, be pessimistic (or realistic?) and don't
		 * add real servers into the VS pool. They will get there
		 * later upon healthchecks recovery (if ever).
		 */
		if (vs->alpha) {
			UNSET_ALIVE(rs);
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
	} else {
		if (!vs->alpha) {
			vs->cur_max_weight = get_max_weight(0, vs->rs);
		}
		for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
			rs = ELEMENT_DATA(e);
		if (vs->alpha) {
			UNSET_ALIVE(rs);
			continue;
		}

		if (!ISALIVE(rs)) {
			if (rs->weight == vs->cur_max_weight && 
			    !ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs)) {
				return 0;
			} else {
				SET_ALIVE(rs);
			}
		} else if (vs->vsgname) {
			UNSET_ALIVE(rs);
			if (rs->weight == vs->cur_max_weight && 
			    !ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs)) {
				return 0;
			}
			SET_ALIVE(rs);
			}
		}
	}

	return 1;
}

/* Set a virtualserver IPVS rules */
static int
init_service_vs(virtual_server * vs)
{
	/* Init the VS root */
	if (!ISALIVE(vs) || vs->vsgname) {
		if (!ipvs_cmd(LVS_CMD_ADD, check_data->vs_group, vs, NULL)) {
			return 0;
		}  else {
			SET_ALIVE(vs);
	}
	}

	/*Set local ip address in "FNAT" mode of IPVS */
	if ((vs->loadbalancing_kind == IP_VS_CONN_F_FULLNAT) && vs->local_addr_gname) { 
		if (!ipvs_cmd(LVS_CMD_ADD_LADDR, check_data->vs_group, vs, NULL))
			return 0; 
	}

	/* Processing real server queue */
	if (NOT_SNAT_SVC(vs) && !LIST_ISEMPTY(vs->rs)) {
		if (!init_service_rs(vs)) {
			return 0;
		}
	    
		if (vs->alpha) {
			vs->quorum_state = DOWN;
		}  else {
			netlink_vipaddress(check_data->vs_group, vs, UP);
	}
	}

	if (IS_SNAT_SVC(vs) && !LIST_ISEMPTY(vs->rs)) {
		//log_message(LOG_INFO, "before init_service_snat_rs\n");
		if (!init_service_snat_rs(vs)) {
			return 0;
		}
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
	char rsip[INET6_ADDRSTRLEN];

	/* If we have just gained quorum, it's time to consider notify_up. */
	if (vs->quorum_state == DOWN &&
	    weigh_live_realservers(vs) >= vs->quorum + vs->hysteresis) {
		vs->quorum_state = UP;
		log_message(LOG_INFO, "Gained quorum %lu+%lu=%lu <= %u for VS [%s]:%d"
				    , vs->quorum
				    , vs->hysteresis
				    , vs->quorum + vs->hysteresis
				    , weigh_live_realservers(vs)
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
	    weigh_live_realservers(vs) < vs->quorum - vs->hysteresis) {
		vs->quorum_state = DOWN;
		log_message(LOG_INFO, "Lost quorum %lu-%lu=%lu > %u for VS [%s]:%d"
				    , vs->quorum
				    , vs->hysteresis
				    , vs->quorum - vs->hysteresis
				    , weigh_live_realservers(vs)
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

static void
handle_abspriority_rs_down2up(virtual_server *vs, real_server *rs)
{
	element e;
	real_server *tmp_rs;
	char rsip[INET6_ADDRSTRLEN];
	
	log_message(LOG_INFO, "down2up: vs.alive=%d, vs.max_weight=%d, rs.weight=%d", 
	                       vs->alive,  vs->cur_max_weight, rs->weight);
	if ((rs->weight == vs->cur_max_weight || vs->cur_max_weight == -1) && !ISALIVE(rs)) {
		log_message(LOG_INFO, "down2up: add(%s:%d, %d)", 
		                       inet_sockaddrtos2(&rs->addr, rsip), 
		                       ntohs(inet_sockaddrport(&rs->addr)), rs->weight);
		if (vs->cur_max_weight == -1) {
			vs->cur_max_weight = rs->weight;
		}
		ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs);
	} else if (rs->weight > vs->cur_max_weight) {
		/* first: del all rs in lvs */
		log_message(LOG_INFO, "down2up: del all alive and setted rs in lvs");
		for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
			tmp_rs = ELEMENT_DATA(e);
			if (ISALIVE(tmp_rs) && (tmp_rs->set == 1) && tmp_rs->weight == vs->cur_max_weight) {
				log_message(LOG_INFO, "down2up: del(%s:%d, %d)", 
				                        inet_sockaddrtos2(&tmp_rs->addr, rsip), 
				                        ntohs(inet_sockaddrport(&tmp_rs->addr)), tmp_rs->weight);
				ipvs_cmd(LVS_CMD_DEL_DEST, check_data->vs_group, vs, tmp_rs);
			}
		}
		
		/*then: add current rs of max weight to lvs */
		vs->cur_max_weight = rs->weight;
		log_message(LOG_INFO, "down2up: add(%s:%d, %d)", 
		                       inet_sockaddrtos2(&rs->addr, rsip), 
		                       ntohs(inet_sockaddrport(&rs->addr)), 
		                       rs->weight);
		ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs);
	} else {
		log_message(LOG_INFO, "down2up: nothing todo");
	}
	
	SET_ALIVE(rs);
	log_message(LOG_INFO, "ALLRS_STAT:");
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		tmp_rs = ELEMENT_DATA(e);
		log_message(LOG_INFO, "  (%s:%d), alived=%d, weight=%d, set=%d",  
		                        inet_sockaddrtos2(&tmp_rs->addr, rsip),
		                        ntohs(inet_sockaddrport(&tmp_rs->addr)),
		                        tmp_rs->alive, tmp_rs->weight, tmp_rs->set);
	}
	return;
}

/* Returns the num of alive rs */
static int 
alive_num_with_weight(virtual_server *vs, int weight)
{
	element e;
	real_server *svr;
	int count = 0;

	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		svr = ELEMENT_DATA(e);
		if (ISALIVE(svr) && svr->weight == weight) {
			count += 1;
		}
	}
	
	return count;
}

static void
handle_abspriority_rs_up2down(virtual_server *vs, real_server *rs)
{
	element e;
	real_server *svr;
	int max_weight = -1;
	char rsip[INET6_ADDRSTRLEN];
	
	log_message(LOG_INFO, "up2down: vs.alive=%d, vs.max_weight=%d, rs.weight=%d",  
	                        vs->alive, vs->cur_max_weight, rs->weight);
	if (ISALIVE(rs) && (rs->set == 1) && rs->weight == vs->cur_max_weight) {
		log_message(LOG_INFO, "up2down: del(%s:%d, %d)", inet_sockaddrtos2(&rs->addr, rsip), 
		                        ntohs(inet_sockaddrport(&rs->addr)), rs->weight);
		ipvs_cmd(LVS_CMD_DEL_DEST, check_data->vs_group, vs, rs);
		UNSET_ALIVE(rs);
		if (alive_num_with_weight(vs, vs->cur_max_weight) == 0) {
			max_weight = get_max_weight(1, vs->rs);
			if (max_weight != -1) {
				log_message(LOG_INFO, "up2down: max weight of cur alive rs: %d",  max_weight);
				for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
					svr = ELEMENT_DATA(e);
					if (ISALIVE(svr) && (svr->set == 0) && svr->weight == max_weight) {
						UNSET_ALIVE(svr);
						log_message(LOG_INFO, "up2down: add(%s:%d, %d)",
						                        inet_sockaddrtos2(&svr->addr, rsip), 
						                        ntohs(inet_sockaddrport(&svr->addr)), 
						                        svr->weight);
						ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, svr);
						SET_ALIVE(svr);
					}
				}
			} else {
				log_message(LOG_INFO, "up2down: all rs unusable");
			}
			vs->cur_max_weight = max_weight;
		}
	} else {
		UNSET_ALIVE(rs);
		log_message(LOG_INFO, "up2down: nothing todo");
	}
	
	log_message(LOG_INFO, "ALLRS_STAT:");
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		svr = ELEMENT_DATA(e);
		log_message(LOG_INFO, " (%s:%d) alived=%d, weight=%d, set=%d",   
		                        inet_sockaddrtos2(&svr->addr, rsip), 
		                        ntohs(inet_sockaddrport(&svr->addr)), 
		                        svr->alive, svr->weight, svr->set);
	}
	return;
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
			if (vs->abs_priority == 0) {
			ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs);
		rs->alive = alive;
			} else {
				log_message(LOG_INFO, "abs_priority mode: down2up");
				handle_abspriority_rs_down2up(vs, rs);
			}
		}
		
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
			if (vs->abs_priority == 0) {
			ipvs_cmd(LVS_CMD_DEL_DEST, check_data->vs_group, vs, rs);
		rs->alive = alive;
			} else {
				log_message(LOG_INFO, "abs_priority mode:up2down");
				handle_abspriority_rs_up2down(vs, rs);
			}
		}

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
svr_checker_up(int alive,  checker_id_t cid, real_server *rs)
{
	element e;
	list l = rs->failed_checkers;
	checker_id_t *id;

	if (rs->reload_alive) {
		/* first check failed under alpha mode
		 * and the rs is alive before reload
		 */
		if (!alive && !ISALIVE(rs)) {
			element next;

			for (e = LIST_HEAD(l); e; e = next) {
				next = e->next;
				free_list_element(l, e);
			}
			l->head = NULL;
			l->tail = NULL;

			SET_ALIVE(rs);
		}
		/* make sure we do not go here next time */
		rs->reload_alive = 0;
	}

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
			if ((old_vs->vip_bind_dev && vs->vip_bind_dev &&
				strcmp(old_vs->vip_bind_dev, vs->vip_bind_dev)) ||
				(old_vs->vip_bind_dev != NULL && vs->vip_bind_dev == NULL))
				netlink_vipaddress(old_check_data->vs_group, old_vs, DOWN);
			return 1;
		}
	}

	return 0;
}


static int
snat_rs_exist(snat_rule *old_rs, list l)
{
	element e;
	snat_rule *rs;

	if (LIST_ISEMPTY(l)) {
		return 0;
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (SNAT_RS_ISEQ(rs, old_rs)) {
			rs->alive = old_rs->alive;
			rs->set = old_rs->set;
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
			/*
			 * The alpha mode will reset rs to unalive.
			 * We save the status before reload here
			 */
			rs->reload_alive = rs->alive;
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

/* Clear the diff rs of the old snat vs */
static int
clear_diff_snat_rs(virtual_server *old_vs)
{
	element e;
	list l = old_vs->rs;
	list new = get_rs_list(old_vs);
	snat_rule *rs;

	if (LIST_ISEMPTY(l)) {
		return 1;
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (!snat_rs_exist(rs, new)) {
			print_snat_rule(LVS_CMD_DEL_SNATDEST, rs);
			/* Set alive flag to delete the failed inhibit entries */
			if (!ipvs_snat_cmd(LVS_CMD_DEL_SNATDEST, old_vs, rs)) {
				return 0;
			}
		}
	}

	return 1;
}

/* Clear the diff rs of the old vs */
static int
clear_diff_rs(virtual_server * old_vs)
{
	element e;
	list l = old_vs->rs;
	int new_max_weight = -1;
	list new = get_rs_list(old_vs);
	real_server *rs;
	char rsip[INET6_ADDRSTRLEN];

	/* If old vs didn't own rs then nothing return */
	if (LIST_ISEMPTY(l))
		return 1;

	if (old_vs->abs_priority) {
		new_max_weight = get_max_weight(0, new);
		log_message(LOG_INFO, "abs_priority_mode: reload: max_weight=%d", new_max_weight);
	}
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (((old_vs->abs_priority == 1) && ISALIVE(rs) && (rs->set == 1) && rs->weight < new_max_weight)
			|| !rs_exist(rs, new)) {
			if ((old_vs->abs_priority == 1) && ISALIVE(rs) && (rs->set == 1) && rs->weight < new_max_weight) {
				log_message(LOG_INFO, "abs_priority_mode:%d(weight of rs[%s:%d]) < %d(weight of new_rs_list)", rs->weight, 
					inet_sockaddrtos(&rs->addr), ntohs(inet_sockaddrport(&rs->addr)), new_max_weight);
			} else {
			/* Reset inhibit flag to delete inhibit entries */
			log_message(LOG_INFO, "service [%s]:%d no longer exist"
					    , inet_sockaddrtos(&rs->addr)
					    , ntohs(inet_sockaddrport(&rs->addr)));
			}
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
						entry->range == laddr_entry->range)
			return 1;
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
			if (vs->vsgname) {
				log_message(LOG_INFO, "Removing Virtual Server Group [%s]", 
							vs->vsgname);
			} else {
				if (vs->vfwmark) {
					log_message(LOG_INFO, "Removing Virtual Server -f [%d]",
							vs->vfwmark);
				} else {
					log_message(LOG_INFO, "Removing Virtual Server [%s]:%d",
							inet_sockaddrtos(&vs->addr),
							ntohs(inet_sockaddrport(&vs->addr)));
				}
			}

			/* Clear VS entry */
			if (!clear_service_vs(old_check_data->vs_group, vs)) {
				return 0;
			}
		} else {
			/* If vs exist, perform rs pool diff */
		if (NOT_SNAT_SVC(vs) && !clear_diff_rs(vs)) {
			return 0;
		}
        
		if (IS_SNAT_SVC(vs) && !clear_diff_snat_rs(vs)) {
				return 0;
		}
        
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

