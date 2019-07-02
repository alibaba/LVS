/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
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

#include "check_parser.h"
#include "check_data.h"
#include "check_api.h"
#include "global_data.h"
#include "global_parser.h"
#include "logger.h"
#include "parser.h"
#include "memory.h"
#include "utils.h"
#include "ipwrapper.h"

static int
str2number(const char *s, int min, int max)
{
	int number;
	char *end;

	number = (int) strtol(s, &end, 10);
	if (*end == '\0' && end != s) {
		/*
		 * We parsed a number, let's see if we want this.
		 * If max <= min then ignore ranges
		 */
		if (max <= min || (min <= number && number <= max)) {
			return number;
		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

static int str_is_digit(const char *str)
{
	size_t offset;
	size_t top;

	top = strlen(str);
	for (offset=0; offset<top; offset++) {
		if (!isdigit((int)*(str+offset))) {
			break;
		}
	}

	return (offset<top)?0:1;
}

/* 
 * Get source ip and mask from the argument
 */
static int parse_address_mask(char* buf, snat_rule_addr_mask *addrmask)
{
	char *portp = NULL;
	int portn;
	int result = SNAT_NONE;
	struct in_addr inaddr;
	struct in6_addr inaddr6;

	if (buf == NULL || str_is_digit(buf)) {
		return SNAT_NONE;
	}
	
	if (buf[0] == '[') {
		buf++;
		portp = strchr(buf, ']');
		if (portp == NULL) {
			return SNAT_NONE;
		}
		*portp = '\0';
		portp++;
		if (*portp == '/') {
			*portp = '\0';
		}  else {
			return SNAT_NONE;
		}
	}

	if (inet_pton(AF_INET6, buf, &inaddr6) > 0) {
		//addrmask->addr.in6 = inaddr6;
		//addrmask->mask = 128;
		//addrmask->af = AF_INET6;
		log_message(LOG_ERR, "Not support IPv6");
		return SNAT_NONE;
	} else {
		portp = strrchr(buf, '/');
		if (portp != NULL) {
			*portp = '\0';
		}
		addrmask->af = AF_INET;
		if (inet_aton(buf, &inaddr) != 0) {
			addrmask->addr.ip = inaddr.s_addr;
		} else {
			return SNAT_NONE;
		}
	}

	result |= SNAT_ADDR;
	if (portp != NULL) { 
		if ((portn = str2number(portp+1, 0, 32)) != -1) {
		addrmask->mask= portn;
		result |= SNAT_MASK;
		} else {
			return SNAT_NONE;
		}
	}

	return result;
}


/* SSL handlers */
static void
ssl_handler(vector strvec)
{
	check_data->ssl = alloc_ssl();
}
static void
sslpass_handler(vector strvec)
{
	check_data->ssl->password = set_value(strvec);
}
static void
sslca_handler(vector strvec)
{
	check_data->ssl->cafile = set_value(strvec);
}
static void
sslcert_handler(vector strvec)
{
	check_data->ssl->certfile = set_value(strvec);
}
static void
sslkey_handler(vector strvec)
{
	check_data->ssl->keyfile = set_value(strvec);
}

/* Virtual Servers handlers */
static void
vsg_handler(vector strvec)
{
	/* Fetch queued vsg */
	alloc_vsg(VECTOR_SLOT(strvec, 1));
	alloc_value_block(strvec, alloc_vsg_entry);
}
static void
laddr_group_handler(vector strvec)
{
	alloc_laddr_group(VECTOR_SLOT(strvec, 1));
	alloc_value_block(strvec, alloc_laddr_entry);
}
static void
vs_handler(vector strvec)
{
	alloc_vs(VECTOR_SLOT(strvec, 1), VECTOR_SLOT(strvec, 2));
}
static void
delay_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	vs->delay_loop = atoi(VECTOR_SLOT(strvec, 1)) * TIMER_HZ;;
}

/* new add 20140319 : for keyword abs_priority  */
static void
abspriority_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	log_message(LOG_INFO, "abs_priority mode open");
	vs->abs_priority = 1;
}

static void
lbalgo_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = VECTOR_SLOT(strvec, 1);
	int size = sizeof (vs->sched);
	int str_len = strlen(str);

	if (size > str_len)
		size = str_len;

	memcpy(vs->sched, str, size);
}
static void
lbkind_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = VECTOR_SLOT(strvec, 1);

	if (!strcmp(str, "NAT"))
		vs->loadbalancing_kind = IP_VS_CONN_F_MASQ;
	else if (!strcmp(str, "DR"))
		vs->loadbalancing_kind = IP_VS_CONN_F_DROUTE;
	else if (!strcmp(str, "TUN"))
		vs->loadbalancing_kind = IP_VS_CONN_F_TUNNEL;
	else if (!strcmp(str, "FNAT"))
		vs->loadbalancing_kind = IP_VS_CONN_F_FULLNAT;
	else
		log_message(LOG_INFO, "PARSER : unknown [%s] routing method.", str);
}
static void
natmask_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	inet_ston(VECTOR_SLOT(strvec, 1), &vs->nat_mask);
}
static void
pto_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = VECTOR_SLOT(strvec, 1);
	int size = sizeof (vs->timeout_persistence);
	int str_len = strlen(str);

	if (size > str_len)
		size = str_len;

	memcpy(vs->timeout_persistence, str, size);
}
static void
pgr_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	if (vs->addr.ss_family == AF_INET6)
		vs->granularity_persistence = atoi(VECTOR_SLOT(strvec, 1));
	else
		inet_ston(VECTOR_SLOT(strvec, 1), &vs->granularity_persistence);
}
static void
proto_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);

	char *str = VECTOR_SLOT(strvec, 1);
	vs->service_type = (!strcmp(str, "TCP")) ? IPPROTO_TCP : IPPROTO_UDP;
}
static void
hasuspend_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	vs->ha_suspend = 1;
}
static void
virtualhost_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	vs->virtualhost = set_value(strvec);
}

/* Sorry Servers handlers */
static void
ssvr_handler(vector strvec)
{
	alloc_ssvr(VECTOR_SLOT(strvec, 1), VECTOR_SLOT(strvec, 2));
}

static void
snat_rule_handler(vector strvec)
{
	alloc_snat_rule();
}

static void
snat_from_handler(vector strvec)
{
	snat_rule *rule = NULL;
	snat_rule_addr_mask addrmask;
	
	char *str = VECTOR_SLOT(strvec, 1);
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	if (IS_SNAT_SVC(vs)) {
		rule = LIST_TAIL_DATA(vs->rs);
		int result = parse_address_mask(str, &addrmask);
		if (result & SNAT_ADDR) {
			rule->saddr = addrmask.addr;
		}
		if (result & SNAT_MASK) {
			rule->smask = addrmask.mask;
		}
		rule->af = addrmask.af;
	}
}

static void
snat_to_handler(vector strvec)
{
	snat_rule *rule = NULL;
	snat_rule_addr_mask addrmask;
	
	char *str = VECTOR_SLOT(strvec, 1);
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	if (IS_SNAT_SVC(vs)) {
		rule = LIST_TAIL_DATA(vs->rs);
		int result = parse_address_mask(str, &addrmask);
		if (result & SNAT_ADDR) {
			rule->daddr = addrmask.addr;
		}
		if (result & SNAT_MASK) {
			rule->dmask = addrmask.mask;
		}
	}
}

static void
snat_gw_handler(vector strvec)
{
	snat_rule *rule = NULL;
	snat_rule_addr_mask addrmask;
	
	char *str = VECTOR_SLOT(strvec, 1);
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	if (IS_SNAT_SVC(vs)) {
		rule = LIST_TAIL_DATA(vs->rs);
		int result = parse_address_mask(str, &addrmask);
		if (result & SNAT_ADDR) {
			rule->gw = addrmask.addr;
		}
	}
}

static void
snat_oif_handler(vector strvec)
{
	snat_rule *rule = NULL;
	char *str = VECTOR_SLOT(strvec, 1);
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	if (IS_SNAT_SVC(vs)) {
		rule = LIST_TAIL_DATA(vs->rs);
		if (strlen(str) < IP_VS_IFNAME_MAXLEN) {
			strcpy(rule->out_dev, str);
		} else {
			log_message(LOG_ERR, "out dev name too long\n");
		}
	}
}

static void
snat_algo_handler(vector strvec)
{
	snat_rule *rule = NULL;
	char *str = VECTOR_SLOT(strvec, 1);
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	if (IS_SNAT_SVC(vs)) {
		rule = LIST_TAIL_DATA(vs->rs);
		if (!memcmp(str , "sh" , strlen("sh"))) {
			rule->algo = IPVS_SNAT_IPS_PERSITENT;
		}  else if(!memcmp(str , "sdh" , strlen("sdh"))) {
			rule->algo = IPVS_SNAT_IPS_NORMAL;
		} else if (!memcmp(str, "random", strlen("random"))) {
			rule->algo = IPVS_SNAT_IPS_RANDOM;
		} else {
			log_message(LOG_ERR, "unkown algo,shoule be one of [sh, sdh, ramdom]\n");
		}
	}
}

static void
snat_newgw_handler(vector strvec)
{
	snat_rule *rule = NULL;
	snat_rule_addr_mask addrmask;
	
	char *str = VECTOR_SLOT(strvec, 1);
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	if (IS_SNAT_SVC(vs)) {
		rule = LIST_TAIL_DATA(vs->rs);
		int result = parse_address_mask(str, &addrmask);
		if (result & SNAT_ADDR) {
			rule->new_gw= addrmask.addr;
		}
	}
}

static void
snat_snatip_handler(vector strvec)
{
	char *portp = NULL;
	snat_rule *rule = NULL;
	snat_rule_addr_mask addrmask;
	int result;
	
	char *str = VECTOR_SLOT(strvec, 1);
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	if (IS_SNAT_SVC(vs)) {
		rule = LIST_TAIL_DATA(vs->rs);
		portp = strchr(str, '-');
		if (portp == NULL) {
			result = parse_address_mask(str, &addrmask);
			if (result & SNAT_ADDR) {
				rule->minip = addrmask.addr;
				rule->maxip = rule->minip;
			} else {
				log_message(LOG_ERR, "snatip illegal\n");
				return;
			}
		} else {
			*portp = '\0';
			portp++;
			result = parse_address_mask(str, &addrmask);
			if (result & SNAT_ADDR) {
			rule->minip = addrmask.addr;
			} else {
				log_message(LOG_ERR, "snatip minip illegal\n");
				return;
			}

			result = parse_address_mask(portp, &addrmask);
			if (result & SNAT_ADDR) {
				rule->maxip = addrmask.addr;
			} else {
				log_message(LOG_ERR, "snatip maxip illegal\n");
				return;
			}

			if (rule->af == AF_INET) {
				if (rule->maxip.ip < rule->minip.ip) {
					log_message(LOG_ERR, "maxip smaller than minip\n");
				}
			}
		}
	}
}

/* Real Servers handlers */
static void
rs_handler(vector strvec)
{
	alloc_rs(VECTOR_SLOT(strvec, 1), VECTOR_SLOT(strvec, 2));
}
static void
weight_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);
	rs->weight = atoi(VECTOR_SLOT(strvec, 1));
	rs->iweight = rs->weight;
}
#ifdef _KRNL_2_6_
static void
uthreshold_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);
	rs->u_threshold = atoi(VECTOR_SLOT(strvec, 1));
}
static void
lthreshold_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);
	rs->l_threshold = atoi(VECTOR_SLOT(strvec, 1));
}
#endif
static void
inhibit_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);
	rs->inhibit = 1;
}
static void
notify_up_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);
	rs->notify_up = set_value(strvec);
}
static void
notify_down_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	real_server *rs = LIST_TAIL_DATA(vs->rs);
	rs->notify_down = set_value(strvec);
}
static void
alpha_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	vs->alpha = 1;
	vs->quorum_state = DOWN;
}
static void
omega_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	vs->omega = 1;
}
static void
quorum_up_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	vs->quorum_up = set_value(strvec);
}
static void
quorum_down_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	vs->quorum_down = set_value(strvec);
}
static void
quorum_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	long tmp = atol (VECTOR_SLOT(strvec, 1));
	if (tmp < 1) {
		log_message(LOG_ERR, "Condition not met: Quorum >= 1");
		log_message(LOG_ERR, "Ignoring requested value %s, using 1 instead",
		  (char *) VECTOR_SLOT(strvec, 1));
		tmp = 1;
	}
	vs->quorum = tmp;
}
static void
hysteresis_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	long tmp = atol (VECTOR_SLOT(strvec, 1));
	if (tmp < 0 || tmp >= vs->quorum) {
		log_message(LOG_ERR, "Condition not met: 0 <= Hysteresis <= Quorum - 1");
		log_message(LOG_ERR, "Ignoring requested value %s, using 0 instead",
		       (char *) VECTOR_SLOT(strvec, 1));
		log_message(LOG_ERR, "Hint: try defining hysteresis after quorum");
		tmp = 0;
	}
	vs->hysteresis = tmp;
}
static void 
laddr_gname_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	vs->local_addr_gname = set_value(strvec);
}
static void 
syn_proxy_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	vs->syn_proxy = 1;
}
static void
bind_dev_handler(vector strvec)
{
	virtual_server *vs = LIST_TAIL_DATA(check_data->vs);
	vs->vip_bind_dev = set_value(strvec);
}

vector
check_init_keywords(void)
{
	/* global definitions mapping */
	global_init_keywords();

	/* SSL mapping */
	install_keyword_root("SSL", &ssl_handler);
	install_keyword("password", &sslpass_handler);
	install_keyword("ca", &sslca_handler);
	install_keyword("certificate", &sslcert_handler);
	install_keyword("key", &sslkey_handler);

	/* local IP address mapping */
	install_keyword_root("local_address_group", &laddr_group_handler);

	/* Virtual server mapping */
	install_keyword_root("virtual_server_group", &vsg_handler);
	install_keyword_root("virtual_server", &vs_handler);
	install_keyword("abs_priority", &abspriority_handler); /* new add 20140319 */
	install_keyword("delay_loop", &delay_handler);
	install_keyword("lb_algo", &lbalgo_handler);
	install_keyword("lvs_sched", &lbalgo_handler);
	install_keyword("lb_kind", &lbkind_handler);
	install_keyword("lvs_method", &lbkind_handler);
	install_keyword("nat_mask", &natmask_handler);
	install_keyword("persistence_timeout", &pto_handler);
	install_keyword("persistence_granularity", &pgr_handler);
	install_keyword("protocol", &proto_handler);
	install_keyword("ha_suspend", &hasuspend_handler);
	install_keyword("virtualhost", &virtualhost_handler);

	/* Pool regression detection and handling. */
	install_keyword("alpha", &alpha_handler);
	install_keyword("omega", &omega_handler);
	install_keyword("quorum_up", &quorum_up_handler);
	install_keyword("quorum_down", &quorum_down_handler);
	install_keyword("quorum", &quorum_handler);
	install_keyword("hysteresis", &hysteresis_handler);

	/* snat rule mapping */
	install_keyword("snat_rule", &snat_rule_handler);
	install_sublevel();
	install_keyword("from", &snat_from_handler);
	install_keyword("to", &snat_to_handler);
	install_keyword("gw", &snat_gw_handler);
	install_keyword("oif", &snat_oif_handler);
	install_keyword("snat_ip", &snat_snatip_handler);
	install_keyword("algo", &snat_algo_handler);
	install_keyword("new_gw", &snat_newgw_handler);
	install_sublevel_end();

	/* Real server mapping */
	install_keyword("sorry_server", &ssvr_handler);
	install_keyword("real_server", &rs_handler);
	install_sublevel();
	install_keyword("weight", &weight_handler);
#ifdef _KRNL_2_6_
	install_keyword("uthreshold", &uthreshold_handler);
	install_keyword("lthreshold", &lthreshold_handler);
#endif
	install_keyword("inhibit_on_failure", &inhibit_handler);
	install_keyword("notify_up", &notify_up_handler);
	install_keyword("notify_down", &notify_down_handler);

	/* Checkers mapping */
	install_checkers_keyword();
	install_sublevel_end();

	install_keyword("laddr_group_name", &laddr_gname_handler);
	install_keyword("syn_proxy", &syn_proxy_handler);
	install_keyword("vip_bind_dev", &bind_dev_handler);

	return keywords;
}
