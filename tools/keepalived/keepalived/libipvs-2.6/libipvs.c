/*
 * libipvs:	Library for manipulating IPVS through [gs]etsockopt
 *
 * Version:     $Id: libipvs.c,v 1.7 2003/06/08 09:31:39 wensong Exp $
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "libipvs.h"

typedef struct ipvs_servicedest_s {
	struct ip_vs_service_kern	svc;
	struct ip_vs_dest_kern		dest;
} ipvs_servicedest_t;

typedef struct ipvs_serviceladdr_s {
	struct ip_vs_service_kern	svc;
	struct ip_vs_laddr_kern		laddr;
} ipvs_serviceladdr_t;


static int sockfd = -1;
static void* ipvs_func = NULL;
struct ip_vs_getinfo ipvs_info;

#ifdef LIBIPVS_USE_NL
static struct nl_handle *sock = NULL;
static int family, try_nl = 1;
#endif

#define CHECK_IPV4(s, ret) if (s->af && s->af != AF_INET)	\
	{ errno = EAFNOSUPPORT; return ret; }			\
	s->__addr_v4 = s->addr.ip;				\

#define CHECK_PE(s, ret) if (s->pe_name[0] != 0)			\
	{ errno = EAFNOSUPPORT; return ret; }

#define CHECK_COMPAT_DEST(s, ret) CHECK_IPV4(s, ret)

#define CHECK_COMPAT_SVC(s, ret)				\
	CHECK_IPV4(s, ret);					\
	CHECK_PE(s, ret);

#define CHECK_COMPAT_LADDR(s, ret) CHECK_IPV4(s, ret)

#ifdef LIBIPVS_USE_NL
struct nl_msg *ipvs_nl_message(int cmd, int flags)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, flags,
		    cmd, IPVS_GENL_VERSION);

	return msg;
}

static int ipvs_nl_noop_cb(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

int ipvs_nl_send_message(struct nl_msg *msg, nl_recvmsg_msg_cb_t func, void *arg)
{
	int err = EINVAL;
	sock = nl_handle_alloc();
	if (!sock) {
		nlmsg_free(msg);
		return -1;
	}

	if (genl_connect(sock) < 0) {
		goto fail_genl;
	}

	family = genl_ctrl_resolve(sock, IPVS_GENL_NAME);
	if (family < 0) {
		goto fail_genl;
	}

	/* To test connections and set the family */
	if (msg == NULL) {
		nl_handle_destroy(sock);
		sock = NULL;
		return 0;
	}

	if (nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, func, arg) != 0) {
		goto fail_genl;
	}

	if (nl_send_auto_complete(sock, msg) < 0) {
		goto fail_genl;
	}

	if ((err = -nl_recvmsgs_default(sock)) > 0) {
		goto fail_genl;
	}

	nlmsg_free(msg);

	nl_handle_destroy(sock);
	return 0;

fail_genl:
	nl_handle_destroy(sock);
	sock = NULL;
	nlmsg_free(msg);
	errno = err;
	return -1;
}
#endif

int ipvs_init(void)
{
	socklen_t len;

	ipvs_func = ipvs_init;

#ifdef LIBIPVS_USE_NL
	if (ipvs_nl_send_message(NULL, NULL, NULL) == 0) {
		try_nl = 1;
		return ipvs_getinfo();
	}

	try_nl = 0;
#endif

	len = sizeof(ipvs_info);
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
		return -1;

	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_INFO,
		       (char *)&ipvs_info, &len))
		return -1;

	return 0;
}

#ifdef LIBIPVS_USE_NL
static int ipvs_getinfo_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPVS_INFO_ATTR_MAX + 1];

	if (genlmsg_parse(nlh, 0, attrs, IPVS_INFO_ATTR_MAX, ipvs_info_policy) != 0)
		return -1;

	if (!(attrs[IPVS_INFO_ATTR_VERSION] &&
	      attrs[IPVS_INFO_ATTR_CONN_TAB_SIZE]))
		return -1;

	ipvs_info.version = nla_get_u32(attrs[IPVS_INFO_ATTR_VERSION]);
	ipvs_info.size = nla_get_u32(attrs[IPVS_INFO_ATTR_CONN_TAB_SIZE]);

	return NL_OK;
}
#endif

int ipvs_getinfo(void)
{
	socklen_t len;
	ipvs_func = ipvs_getinfo;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg;
		msg = ipvs_nl_message(IPVS_CMD_GET_INFO, 0);
		if (msg)
			return ipvs_nl_send_message(msg, ipvs_getinfo_parse_cb,
						    NULL);
		return -1;
	}
#endif

	len = sizeof(ipvs_info);
	return getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_INFO,
			  (char *)&ipvs_info, &len);
}


unsigned int ipvs_version(void)
{
	return ipvs_info.version;
}


int ipvs_flush(void)
{
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_FLUSH, 0);
		if (msg && (ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL) == 0))
			return 0;

		return -1;
	}
#endif
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_FLUSH, NULL, 0);
}

#ifdef LIBIPVS_USE_NL
static int ipvs_nl_fill_service_attr(struct nl_msg *msg, ipvs_service_t *svc)
{
	struct nlattr *nl_service;
	struct ip_vs_flags flags = { .flags = svc->flags,
				     .mask = ~0 };

	nl_service = nla_nest_start(msg, IPVS_CMD_ATTR_SERVICE);
	if (!nl_service) {
		return -1;
	}

	NLA_PUT_U16(msg, IPVS_SVC_ATTR_AF, svc->af);

	if (svc->fwmark) {
		NLA_PUT_U32(msg, IPVS_SVC_ATTR_FWMARK, svc->fwmark);
	} else {
		NLA_PUT_U16(msg, IPVS_SVC_ATTR_PROTOCOL, svc->protocol);
		NLA_PUT(msg, IPVS_SVC_ATTR_ADDR, sizeof(svc->addr), &(svc->addr));
		NLA_PUT_U16(msg, IPVS_SVC_ATTR_PORT, svc->port);
	}

	NLA_PUT_STRING(msg, IPVS_SVC_ATTR_SCHED_NAME, svc->sched_name);
	if (svc->pe_name)
		NLA_PUT_STRING(msg, IPVS_SVC_ATTR_PE_NAME, svc->pe_name);
	NLA_PUT(msg, IPVS_SVC_ATTR_FLAGS, sizeof(flags), &flags);
	NLA_PUT_U32(msg, IPVS_SVC_ATTR_TIMEOUT, svc->timeout);
	NLA_PUT_U32(msg, IPVS_SVC_ATTR_NETMASK, svc->netmask);

	nla_nest_end(msg, nl_service);
	return 0;

nla_put_failure:
	return -1;
}
#endif

int ipvs_add_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_add_service;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_NEW_SERVICE, 0);
		if (!msg) return -1;
		if (ipvs_nl_fill_service_attr(msg, svc)) {
			nlmsg_free(msg);
			return -1;
		}
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);
	}
#endif
	CHECK_COMPAT_SVC(svc, -1);
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_ADD, (char *)svc,
			  sizeof(struct ip_vs_service_kern));
}


int ipvs_update_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_update_service;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_SET_SERVICE, 0);
		if (!msg) return -1;
		if (ipvs_nl_fill_service_attr(msg, svc)) {
			nlmsg_free(msg);
			return -1;
		}
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);
	}
#endif
	CHECK_COMPAT_SVC(svc, -1);
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_EDIT, (char *)svc,
			  sizeof(struct ip_vs_service_kern));
}

int ipvs_update_service_by_options(ipvs_service_t *svc, unsigned int options)
{
	ipvs_service_entry_t *entry;
	ipvs_service_t user;

	if (!(entry = ipvs_get_service(svc->fwmark, svc->af, svc->protocol,
				       svc->addr, svc->port))) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		exit(1);
	}

	ipvs_service_entry_2_user(entry, &user);
	if( options & OPT_SCHEDULER ) {
		strcpy(user.sched_name, svc->sched_name);
	}

	if( options & OPT_PERSISTENT ) {
		user.flags  |= IP_VS_SVC_F_PERSISTENT;
		user.timeout = svc->timeout;
	}

	if( options & OPT_NETMASK ) {
		user.netmask = svc->netmask;
	}

	if( options & OPT_SYNPROXY ) {
		if( svc->flags & IP_VS_CONN_F_SYNPROXY ) {
			user.flags |= IP_VS_CONN_F_SYNPROXY;
		} else {
			user.flags &= ~IP_VS_CONN_F_SYNPROXY;
		}
	}

	if( options & OPT_ONEPACKET ) {
		user.flags |= IP_VS_SVC_F_ONEPACKET;
	}

	return ipvs_update_service(&user);
}

int ipvs_update_service_synproxy(ipvs_service_t *svc , int enable)
{
	ipvs_service_entry_t *entry;

	if (!(entry = ipvs_get_service(svc->fwmark, svc->af, svc->protocol,
				       svc->addr, svc->port))) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		exit(1);
	}
	
	strcpy(svc->sched_name , entry->sched_name);
	strcpy(svc->pe_name , entry->pe_name);
	svc->flags = entry->flags;
	svc->timeout = entry->timeout;
	svc->netmask = entry->netmask;
	
	if(enable)
		svc->flags = svc->flags | IP_VS_CONN_F_SYNPROXY;
	else
		svc->flags = svc->flags & (~IP_VS_CONN_F_SYNPROXY);
	
	return ipvs_update_service(svc);	
}

int ipvs_del_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_del_service;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_DEL_SERVICE, 0);
		if (!msg) return -1;
		if (ipvs_nl_fill_service_attr(msg, svc)) {
			nlmsg_free(msg);
			return -1;
		}
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);
	}
#endif
	CHECK_COMPAT_SVC(svc, -1);
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_DEL, (char *)svc,
			  sizeof(struct ip_vs_service_kern));
}


int ipvs_zero_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_zero_service;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_ZERO, 0);
		if (!msg) return -1;

		if (svc->fwmark
		    || memcmp(&in6addr_any, &svc->addr.in6, sizeof(struct in6_addr))
		    || svc->port) {
			if (ipvs_nl_fill_service_attr(msg, svc)) {
				nlmsg_free(msg);
				return -1;
			}
		}
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);
	}
#endif
	CHECK_COMPAT_SVC(svc, -1);
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_ZERO, (char *)svc,
			  sizeof(struct ip_vs_service_kern));
}

#ifdef LIBIPVS_USE_NL
static int ipvs_nl_fill_dest_attr(struct nl_msg *msg, ipvs_dest_t *dst)
{
	struct nlattr *nl_dest;

	nl_dest = nla_nest_start(msg, IPVS_CMD_ATTR_DEST);
	if (!nl_dest)
		return -1;

	NLA_PUT(msg, IPVS_DEST_ATTR_ADDR, sizeof(dst->addr), &(dst->addr));
	NLA_PUT_U16(msg, IPVS_DEST_ATTR_PORT, dst->port);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_FWD_METHOD, dst->conn_flags & IP_VS_CONN_F_FWD_MASK);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_WEIGHT, dst->weight);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_U_THRESH, dst->u_threshold);
	NLA_PUT_U32(msg, IPVS_DEST_ATTR_L_THRESH, dst->l_threshold);

	nla_nest_end(msg, nl_dest);
	return 0;

nla_put_failure:
	return -1;
}

static int ipvs_nl_fill_snat_dest_attr(struct nl_msg *msg, ipvs_snat_dest_t *dst)
{
	struct nlattr *nl_snat_dest;

	nl_snat_dest = nla_nest_start(msg, IPVS_CMD_ATTR_SNATDEST);
	if (!nl_snat_dest) {
		return -1;
	}

	/* add special attr */
	NLA_PUT(msg, IPVS_SNAT_DEST_ATTR_FADDR, sizeof(dst->saddr), &dst->saddr);
	NLA_PUT_U32(msg, IPVS_SNAT_DEST_ATTR_FMASK, dst->smask);
	NLA_PUT(msg, IPVS_SNAT_DEST_ATTR_DADDR, sizeof(dst->daddr), &dst->daddr);
	NLA_PUT_U32(msg, IPVS_SNAT_DEST_ATTR_DMASK, dst->dmask);
	NLA_PUT(msg, IPVS_SNAT_DEST_ATTR_GW, sizeof(dst->gw), &dst->gw);
	NLA_PUT(msg, IPVS_SNAT_DEST_ATTR_MINIP, sizeof(dst->min_ip), &dst->min_ip);
	NLA_PUT(msg, IPVS_SNAT_DEST_ATTR_MAXIP, sizeof(dst->max_ip), &dst->max_ip);
	NLA_PUT_U8(msg, IPVS_SNAT_DEST_ATTR_ALGO,  dst->algo);
	NLA_PUT(msg, IPVS_SNAT_DEST_ATTR_NEWGW, sizeof(dst->new_gw), &dst->new_gw);
	NLA_PUT_U32(msg, IPVS_SNAT_DEST_ATTR_CONNFLAG, dst->conn_flags & IP_VS_CONN_F_FWD_MASK);
	NLA_PUT_STRING(msg, IPVS_SNAT_DEST_ATTR_OUTDEV, dst->out_dev);

	nla_nest_end(msg, nl_snat_dest);
	return 0;
	
nla_put_failure:
	return -1;
}
#endif

int ipvs_add_snat_dest(ipvs_service_t *svc, ipvs_snat_dest_t *snat_dest)
{
	ipvs_func = ipvs_add_snat_dest;
 #ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_NEW_SNATDEST, 0);
		if (!msg) {
			return -1;
		}
    
		if (ipvs_nl_fill_service_attr(msg, svc)) {
			goto nla_put_failure;
		}

		if (ipvs_nl_fill_snat_dest_attr(msg, snat_dest)) {
			goto nla_put_failure;
		}
   
		int ret = ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);
		return ret;
	    
nla_put_failure:
		nlmsg_free(msg);
		return -1;       
	}
#endif

	return -1;
}

int ipvs_update_snat_dest(ipvs_service_t *svc, ipvs_snat_dest_t *snat_dest)
{
	ipvs_func = ipvs_update_snat_dest;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_SET_SNATDEST, 0);
		if (!msg) {
			return -1;
		}
    
		if (ipvs_nl_fill_service_attr(msg, svc)) {
			goto nla_put_failure;
		}

		if (ipvs_nl_fill_snat_dest_attr(msg, snat_dest)) {
			goto nla_put_failure;
		}

		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);
  
nla_put_failure:
		nlmsg_free(msg);
		return -1;       
	}
#endif

	return -1;
}

int ipvs_del_snat_dest(ipvs_service_t *svc, ipvs_snat_dest_t *snat_dest)
{
	ipvs_func = ipvs_del_snat_dest;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_DEL_SNATDEST, 0);
		if (!msg) {
			return -1;
		}
		if (ipvs_nl_fill_service_attr(msg, svc)) {
			goto nla_put_failure;
		}
     
		if (ipvs_nl_fill_snat_dest_attr(msg, snat_dest)) {
			goto nla_put_failure;
		}

		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif
		return -1;
}

int ipvs_add_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_servicedest_t svcdest;
	ipvs_func = ipvs_add_dest;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_NEW_DEST, 0);
		if (!msg) return -1;
		if (ipvs_nl_fill_service_attr(msg, svc))
			goto nla_put_failure;
		if (ipvs_nl_fill_dest_attr(msg, dest))
			goto nla_put_failure;
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif

	CHECK_COMPAT_SVC(svc, -1);
	CHECK_COMPAT_DEST(dest, -1);
	memcpy(&svcdest.svc, svc, sizeof(svcdest.svc));
	memcpy(&svcdest.dest, dest, sizeof(svcdest.dest));
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_ADDDEST,
			  (char *)&svcdest, sizeof(svcdest));
}


int ipvs_update_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_servicedest_t svcdest;

	ipvs_func = ipvs_update_dest;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_SET_DEST, 0);
		if (!msg) return -1;
		if (ipvs_nl_fill_service_attr(msg, svc))
			goto nla_put_failure;
		if (ipvs_nl_fill_dest_attr(msg, dest))
			goto nla_put_failure;
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif
	CHECK_COMPAT_SVC(svc, -1);
	CHECK_COMPAT_DEST(dest, -1);
	memcpy(&svcdest.svc, svc, sizeof(svcdest.svc));
	memcpy(&svcdest.dest, dest, sizeof(svcdest.dest));
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_EDITDEST,
			  (char *)&svcdest, sizeof(svcdest));
}


int ipvs_del_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_servicedest_t svcdest;

	ipvs_func = ipvs_del_dest;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_DEL_DEST, 0);
		if (!msg) return -1;
		if (ipvs_nl_fill_service_attr(msg, svc))
			goto nla_put_failure;
		if (ipvs_nl_fill_dest_attr(msg, dest))
			goto nla_put_failure;
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif

	CHECK_COMPAT_SVC(svc, -1);
	CHECK_COMPAT_DEST(dest, -1);
	memcpy(&svcdest.svc, svc, sizeof(svcdest.svc));
	memcpy(&svcdest.dest, dest, sizeof(svcdest.dest));
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_DELDEST,
			  (char *)&svcdest, sizeof(svcdest));
}

#ifdef LIBIPVS_USE_NL
static int ipvs_nl_fill_laddr_attr(struct nl_msg *msg, ipvs_laddr_t * laddr)
{
	struct nlattr *nl_laddr;

	nl_laddr = nla_nest_start(msg, IPVS_CMD_ATTR_LADDR);
	if (!nl_laddr)
		return -1;

	NLA_PUT(msg, IPVS_LADDR_ATTR_ADDR , sizeof(laddr->addr), &(laddr->addr));

	nla_nest_end(msg, nl_laddr);
	return 0;

nla_put_failure:
	return -1;
}
#endif

int ipvs_add_laddr(ipvs_service_t *svc, ipvs_laddr_t * laddr)
{
	ipvs_serviceladdr_t svcladdr;
	ipvs_func = ipvs_add_laddr;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_NEW_LADDR , 0);
		if (!msg) return -1;
		if (ipvs_nl_fill_service_attr(msg, svc))
			goto nla_put_failure;
		if (ipvs_nl_fill_laddr_attr(msg, laddr))
			goto nla_put_failure;
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif
	
	CHECK_COMPAT_SVC(svc, -1);
	CHECK_COMPAT_LADDR(laddr, -1);

	memcpy(&svcladdr.svc, svc, sizeof(svcladdr.svc));
	memcpy(&svcladdr.laddr, laddr, sizeof(svcladdr.laddr));

	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_ADDLADDR,
			  (char *)&svcladdr, sizeof(svcladdr));
}

int ipvs_del_laddr(ipvs_service_t *svc, ipvs_laddr_t * laddr)
{
        ipvs_serviceladdr_t svcladdr;
	ipvs_func = ipvs_del_laddr;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_DEL_LADDR , 0);
		if (!msg) return -1;
		if (ipvs_nl_fill_service_attr(msg, svc))
			goto nla_put_failure;
		if (ipvs_nl_fill_laddr_attr(msg, laddr))
			goto nla_put_failure;
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif

	CHECK_COMPAT_SVC(svc, -1);
	CHECK_COMPAT_LADDR(laddr, -1);

	memcpy(&svcladdr.svc, svc, sizeof(svcladdr.svc));
	memcpy(&svcladdr.laddr, laddr, sizeof(svcladdr.laddr));

        return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_DELLADDR,
                          (char *)&svcladdr, sizeof(svcladdr));
}


int ipvs_set_timeout(ipvs_timeout_t *to)
{
	ipvs_func = ipvs_set_timeout;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_SET_TIMEOUT, 0);
		if (!msg) return -1;
		NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_TCP, to->tcp_timeout);
		NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_TCP_FIN, to->tcp_fin_timeout);
		NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_UDP, to->udp_timeout);
		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_TIMEOUT, (char *)to,
			  sizeof(*to));
}


int ipvs_start_daemon(ipvs_daemon_t *dm)
{
	ipvs_func = ipvs_start_daemon;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nlattr *nl_daemon;
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_NEW_DAEMON, 0);
		if (!msg) return -1;

		nl_daemon = nla_nest_start(msg, IPVS_CMD_ATTR_DAEMON);
		if (!nl_daemon)
			goto nla_put_failure;

		NLA_PUT_U32(msg, IPVS_DAEMON_ATTR_STATE, dm->state);
		NLA_PUT_STRING(msg, IPVS_DAEMON_ATTR_MCAST_IFN, dm->mcast_ifn);
		NLA_PUT_U32(msg, IPVS_DAEMON_ATTR_SYNC_ID, dm->syncid);

		nla_nest_end(msg, nl_daemon);

		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STARTDAEMON,
			  (char *)dm, sizeof(*dm));
}


int ipvs_stop_daemon(ipvs_daemon_t *dm)
{
	ipvs_func = ipvs_stop_daemon;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nlattr *nl_daemon;
		struct nl_msg *msg = ipvs_nl_message(IPVS_CMD_DEL_DAEMON, 0);
		if (!msg) return -1;

		nl_daemon = nla_nest_start(msg, IPVS_CMD_ATTR_DAEMON);
		if (!nl_daemon)
			goto nla_put_failure;

		NLA_PUT_U32(msg, IPVS_DAEMON_ATTR_STATE, dm->state);
		NLA_PUT_STRING(msg, IPVS_DAEMON_ATTR_MCAST_IFN, dm->mcast_ifn);
		NLA_PUT_U32(msg, IPVS_DAEMON_ATTR_SYNC_ID, dm->syncid);

		nla_nest_end(msg, nl_daemon);

		return ipvs_nl_send_message(msg, ipvs_nl_noop_cb, NULL);

nla_put_failure:
		nlmsg_free(msg);
		return -1;
	}
#endif
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STOPDAEMON,
			  (char *)dm, sizeof(*dm));
}

#ifdef LIBIPVS_USE_NL
static int ipvs_parse_stats(struct ip_vs_stats_user *stats, struct nlattr *nla)
{
	struct nlattr *attrs[IPVS_STATS_ATTR_MAX + 1];

	if (nla_parse_nested(attrs, IPVS_STATS_ATTR_MAX, nla, ipvs_stats_policy))
		return -1;

	if (!(attrs[IPVS_STATS_ATTR_CONNS] &&
	      attrs[IPVS_STATS_ATTR_INPKTS] &&
	      attrs[IPVS_STATS_ATTR_OUTPKTS] &&
	      attrs[IPVS_STATS_ATTR_INBYTES] &&
	      attrs[IPVS_STATS_ATTR_OUTBYTES] &&
	      attrs[IPVS_STATS_ATTR_CPS] &&
	      attrs[IPVS_STATS_ATTR_INPPS] &&
	      attrs[IPVS_STATS_ATTR_OUTPPS] &&
	      attrs[IPVS_STATS_ATTR_INBPS] &&
	      attrs[IPVS_STATS_ATTR_OUTBPS]))
		return -1;

	stats->conns = nla_get_u64(attrs[IPVS_STATS_ATTR_CONNS]);
	stats->inpkts = nla_get_u64(attrs[IPVS_STATS_ATTR_INPKTS]);
	stats->outpkts = nla_get_u64(attrs[IPVS_STATS_ATTR_OUTPKTS]);
	stats->inbytes = nla_get_u64(attrs[IPVS_STATS_ATTR_INBYTES]);
	stats->outbytes = nla_get_u64(attrs[IPVS_STATS_ATTR_OUTBYTES]);
	stats->cps = nla_get_u32(attrs[IPVS_STATS_ATTR_CPS]);
	stats->inpps = nla_get_u32(attrs[IPVS_STATS_ATTR_INPPS]);
	stats->outpps = nla_get_u32(attrs[IPVS_STATS_ATTR_OUTPPS]);
	stats->inbps = nla_get_u32(attrs[IPVS_STATS_ATTR_INBPS]);
	stats->outbps = nla_get_u32(attrs[IPVS_STATS_ATTR_OUTBPS]);

	return 0;

}

static int ipvs_parse_snat_rule(struct ip_vs_dest_snat_user* snat_rule, struct nlattr *nla) 
{
	struct nlattr *attrs[IPVS_SNAT_DEST_ATTR_MAX + 1];
	if (nla_parse_nested(attrs, IPVS_SNAT_DEST_ATTR_MAX, nla, ip_vs_snat_dest_policy)) {
		return -1;
	}

	if (!(attrs[IPVS_SNAT_DEST_ATTR_FADDR] &&
		attrs[IPVS_SNAT_DEST_ATTR_FMASK] &&
		attrs[IPVS_SNAT_DEST_ATTR_DADDR] &&
		attrs[IPVS_SNAT_DEST_ATTR_DMASK] &&
		attrs[IPVS_SNAT_DEST_ATTR_GW] &&
		attrs[IPVS_SNAT_DEST_ATTR_MINIP] &&
		attrs[IPVS_SNAT_DEST_ATTR_MAXIP] &&
		attrs[IPVS_SNAT_DEST_ATTR_ALGO] &&
		attrs[IPVS_SNAT_DEST_ATTR_NEWGW] &&
		attrs[IPVS_SNAT_DEST_ATTR_OUTDEV] && 
		attrs[IPVS_SNAT_DEST_ATTR_CONNFLAG])) {
		return -1;
	}

	memcpy(&snat_rule->saddr, nla_data(attrs[IPVS_SNAT_DEST_ATTR_FADDR]), sizeof(snat_rule->saddr));    
	snat_rule->smask= nla_get_u32(attrs[IPVS_SNAT_DEST_ATTR_FMASK]);
	memcpy(&snat_rule->daddr, nla_data(attrs[IPVS_SNAT_DEST_ATTR_DADDR]), sizeof(snat_rule->daddr));
	snat_rule->dmask= nla_get_u32(attrs[IPVS_SNAT_DEST_ATTR_DMASK]);
	memcpy(&snat_rule->gw, nla_data(attrs[IPVS_SNAT_DEST_ATTR_GW]), sizeof(snat_rule->gw));
	memcpy(&snat_rule->min_ip, nla_data(attrs[IPVS_SNAT_DEST_ATTR_MINIP]), sizeof(snat_rule->min_ip));
	memcpy(&snat_rule->max_ip, nla_data(attrs[IPVS_SNAT_DEST_ATTR_MAXIP]), sizeof(snat_rule->max_ip));
	snat_rule->algo= nla_get_u8(attrs[IPVS_SNAT_DEST_ATTR_ALGO]);
	memcpy(&snat_rule->new_gw, nla_data(attrs[IPVS_SNAT_DEST_ATTR_NEWGW]), sizeof(snat_rule->new_gw));
	snat_rule->conn_flags = nla_get_u32(attrs[IPVS_SNAT_DEST_ATTR_CONNFLAG]);
	strncpy(snat_rule->out_dev, nla_get_string(attrs[IPVS_SNAT_DEST_ATTR_OUTDEV]), IP_VS_IFNAME_MAXLEN);
	return 0;
}

static int ipvs_services_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];
	struct nlattr *svc_attrs[IPVS_SVC_ATTR_MAX + 1];
	struct ip_vs_get_services **getp = (struct ip_vs_get_services **)arg;
	struct ip_vs_get_services *get = (struct ip_vs_get_services *)*getp;
	struct ip_vs_flags flags;
	int i = get->num_services;

	if (genlmsg_parse(nlh, 0, attrs, IPVS_CMD_ATTR_MAX, ipvs_cmd_policy) != 0)
		return -1;

	if (!attrs[IPVS_CMD_ATTR_SERVICE])
		return -1;

	if (nla_parse_nested(svc_attrs, IPVS_SVC_ATTR_MAX, attrs[IPVS_CMD_ATTR_SERVICE], ipvs_service_policy))
		return -1;

	memset(&(get->entrytable[i]), 0, sizeof(get->entrytable[i]));

	if (!(svc_attrs[IPVS_SVC_ATTR_AF] &&
	      (svc_attrs[IPVS_SVC_ATTR_FWMARK] ||
	       (svc_attrs[IPVS_SVC_ATTR_PROTOCOL] &&
		svc_attrs[IPVS_SVC_ATTR_ADDR] &&
		svc_attrs[IPVS_SVC_ATTR_PORT])) &&
	      svc_attrs[IPVS_SVC_ATTR_SCHED_NAME] &&
	      svc_attrs[IPVS_SVC_ATTR_NETMASK] &&
	      svc_attrs[IPVS_SVC_ATTR_TIMEOUT] &&
	      svc_attrs[IPVS_SVC_ATTR_FLAGS]))
		return -1;

	get->entrytable[i].af = nla_get_u16(svc_attrs[IPVS_SVC_ATTR_AF]);

	if (svc_attrs[IPVS_SVC_ATTR_FWMARK])
		get->entrytable[i].fwmark = nla_get_u32(svc_attrs[IPVS_SVC_ATTR_FWMARK]);
	else {
		get->entrytable[i].protocol = nla_get_u16(svc_attrs[IPVS_SVC_ATTR_PROTOCOL]);
		memcpy(&(get->entrytable[i].addr), nla_data(svc_attrs[IPVS_SVC_ATTR_ADDR]),
		       sizeof(get->entrytable[i].addr));
		get->entrytable[i].port = nla_get_u16(svc_attrs[IPVS_SVC_ATTR_PORT]);
	}

	strncpy(get->entrytable[i].sched_name,
		nla_get_string(svc_attrs[IPVS_SVC_ATTR_SCHED_NAME]),
		IP_VS_SCHEDNAME_MAXLEN);

	if (svc_attrs[IPVS_SVC_ATTR_PE_NAME])
		strncpy(get->entrytable[i].pe_name,
			nla_get_string(svc_attrs[IPVS_SVC_ATTR_PE_NAME]),
			IP_VS_PENAME_MAXLEN);

	get->entrytable[i].netmask = nla_get_u32(svc_attrs[IPVS_SVC_ATTR_NETMASK]);
	get->entrytable[i].timeout = nla_get_u32(svc_attrs[IPVS_SVC_ATTR_TIMEOUT]);
	nla_memcpy(&flags, svc_attrs[IPVS_SVC_ATTR_FLAGS], sizeof(flags));
	get->entrytable[i].flags = flags.flags & flags.mask;

	if (ipvs_parse_stats(&(get->entrytable[i].stats),
			     svc_attrs[IPVS_SVC_ATTR_STATS]) != 0)
		return -1;

	get->entrytable[i].num_dests = 0;

	i++;

	get->num_services = i;
	get = realloc(get, sizeof(*get)
	      + sizeof(ipvs_service_entry_t) * (get->num_services + 1));
	*getp = get;
	return 0;
}
#endif

struct ip_vs_get_services *ipvs_get_services(void)
{
	struct ip_vs_get_services *get;
	struct ip_vs_get_services_kern *getk;
	socklen_t len;
	int i;

	ipvs_func = ipvs_get_services;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg;
		len = sizeof(*get) +
			sizeof(ipvs_service_entry_t);
		if (!(get = malloc(len)))
			return NULL;
		get->num_services = 0;

		msg = ipvs_nl_message(IPVS_CMD_GET_SERVICE, NLM_F_DUMP);
		if (msg && (ipvs_nl_send_message(msg, ipvs_services_parse_cb, &get) == 0))
			return get;

		free(get);
		return NULL;
	}
#endif

	len = sizeof(*get) +
		sizeof(ipvs_service_entry_t) * ipvs_info.num_services;
	if (!(get = malloc(len)))
		return NULL;
	len = sizeof(*getk) +
		sizeof(struct ip_vs_service_entry_kern) * ipvs_info.num_services;
	if (!(getk = malloc(len)))
		return NULL;

	getk->num_services = ipvs_info.num_services;
	if (getsockopt(sockfd, IPPROTO_IP,
		       IP_VS_SO_GET_SERVICES, getk, &len) < 0) {
		free(get);
		free(getk);
		return NULL;
	}
	memcpy(get, getk, sizeof(struct ip_vs_get_services));
	for (i = 0; i < getk->num_services; i++) {
		memcpy(&get->entrytable[i], &getk->entrytable[i],
		       sizeof(struct ip_vs_service_entry_kern));
		get->entrytable[i].af = AF_INET;
		get->entrytable[i].addr.ip = get->entrytable[i].__addr_v4;
	}
	free(getk);
	return get;
}


void ipvs_free_services(struct ip_vs_get_services * p)
{
	free(p);
}


typedef int (*qsort_cmp_t)(const void *, const void *);

int
ipvs_cmp_services(ipvs_service_entry_t *s1, ipvs_service_entry_t *s2)
{
	int r, i;

	r = s1->fwmark - s2->fwmark;
	if (r != 0)
		return r;

	r = s1->af - s2->af;
	if (r != 0)
		return r;

	r = s1->protocol - s2->protocol;
	if (r != 0)
		return r;

	if (s1->af == AF_INET6)
		for (i = 0; !r && (i < 4); i++)
			r = ntohl(s1->addr.in6.s6_addr32[i]) - ntohl(s2->addr.in6.s6_addr32[i]);
	else
		r = ntohl(s1->addr.ip) - ntohl(s2->addr.ip);
	if (r != 0)
		return r;

	return ntohs(s1->port) - ntohs(s2->port);
}


void
ipvs_sort_services(struct ip_vs_get_services *s, ipvs_service_cmp_t f)
{
	qsort(s->entrytable, s->num_services,
	      sizeof(ipvs_service_entry_t), (qsort_cmp_t)f);
}

#ifdef LIBIPVS_USE_NL
static int ipvs_dests_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	//struct nlattr *attrs[IPVS_DEST_ATTR_MAX + 1];
	    //struct nlattr *dest_attrs[IPVS_SVC_ATTR_MAX + 1];
	    
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];
	struct nlattr *dest_attrs[IPVS_DEST_ATTR_MAX + 1];
	
	struct ip_vs_get_dests **dp = (struct ip_vs_get_dests **)arg;
	struct ip_vs_get_dests *d = (struct ip_vs_get_dests *)*dp;
	int i = d->num_dests;

	if (genlmsg_parse(nlh, 0, attrs, 
			IPVS_CMD_ATTR_MAX, ipvs_cmd_policy) != 0) {
		return -1;
	}

	if (!attrs[IPVS_CMD_ATTR_DEST]) {
		return -1;
	}

	if (nla_parse_nested(dest_attrs, IPVS_DEST_ATTR_MAX, 
			attrs[IPVS_CMD_ATTR_DEST], ipvs_dest_policy)) {
		return -1;
	}

	memset(&(d->entrytable[i]), 0, sizeof(d->entrytable[i]));

	if (!(dest_attrs[IPVS_DEST_ATTR_ADDR] &&
	      dest_attrs[IPVS_DEST_ATTR_PORT] &&
	      dest_attrs[IPVS_DEST_ATTR_FWD_METHOD] &&
	      dest_attrs[IPVS_DEST_ATTR_WEIGHT] &&
	      dest_attrs[IPVS_DEST_ATTR_U_THRESH] &&
	      dest_attrs[IPVS_DEST_ATTR_L_THRESH] &&
	      dest_attrs[IPVS_DEST_ATTR_ACTIVE_CONNS] &&
	      dest_attrs[IPVS_DEST_ATTR_INACT_CONNS] &&
	      dest_attrs[IPVS_DEST_ATTR_PERSIST_CONNS])) {
		return -1;
	}

	memcpy(&(d->entrytable[i].addr),
	       nla_data(dest_attrs[IPVS_DEST_ATTR_ADDR]),
	       sizeof(d->entrytable[i].addr));
	d->entrytable[i].port = nla_get_u16(dest_attrs[IPVS_DEST_ATTR_PORT]);
	d->entrytable[i].conn_flags = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_FWD_METHOD]);
	d->entrytable[i].weight = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_WEIGHT]);
	d->entrytable[i].u_threshold = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_U_THRESH]);
	d->entrytable[i].l_threshold = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_L_THRESH]);
	d->entrytable[i].activeconns = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_ACTIVE_CONNS]);
	d->entrytable[i].inactconns = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_INACT_CONNS]);
	d->entrytable[i].persistconns = nla_get_u32(dest_attrs[IPVS_DEST_ATTR_PERSIST_CONNS]);
	d->entrytable[i].af = d->af;

	if (ipvs_parse_stats(&(d->entrytable[i].stats),
			     dest_attrs[IPVS_DEST_ATTR_STATS]) != 0) {
		return -1;
	}

	if (d->fwmark == 1 && dest_attrs[IPVS_DEST_ATTR_SNATRULE] ) {
		if (ipvs_parse_snat_rule(&(d->entrytable[i].snat_rule), 
				dest_attrs[IPVS_DEST_ATTR_SNATRULE]) != 0) {
			return -1;
		}
	}

	i++;
	d->num_dests = i;
	d = realloc(d, sizeof(*d) + sizeof(ipvs_dest_entry_t) * (d->num_dests + 1));
	*dp = d;
	return 0;
}

static int ipvs_laddrs_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];
	struct nlattr *laddr_attrs[IPVS_LADDR_ATTR_MAX + 1];
	struct ip_vs_get_laddrs **lp = (struct ip_vs_get_laddrs **)arg;
	struct ip_vs_get_laddrs *l = (struct ip_vs_get_laddrs *)*lp;
	int i = l->num_laddrs;

	if (genlmsg_parse(nlh, 0, attrs, IPVS_CMD_ATTR_MAX, ipvs_cmd_policy) != 0){
		return -1;
	}

	if (!attrs[IPVS_CMD_ATTR_LADDR])
		return -1;

	if (nla_parse_nested(laddr_attrs, IPVS_LADDR_ATTR_MAX, attrs[IPVS_CMD_ATTR_LADDR], ipvs_laddr_policy)){
		return -1;
	}

	memset(&(l->entrytable[i]), 0, sizeof(l->entrytable[i]));

	if (!(laddr_attrs[IPVS_LADDR_ATTR_ADDR] &&
		laddr_attrs[IPVS_LADDR_ATTR_PORT_CONFLICT] &&
		laddr_attrs[IPVS_LADDR_ATTR_CONN_COUNTS])){
		return -1;
	}

	memcpy(&(l->entrytable[i].addr), 
		nla_data(laddr_attrs[IPVS_LADDR_ATTR_ADDR]),
		sizeof(l->entrytable[i].addr));
	l->entrytable[i].port_conflict = nla_get_u64(laddr_attrs[IPVS_LADDR_ATTR_PORT_CONFLICT]);
	l->entrytable[i].conn_counts = nla_get_u32(laddr_attrs[IPVS_LADDR_ATTR_CONN_COUNTS]);
	l->num_laddrs++;

	l = realloc(l, sizeof(*l) + sizeof(ipvs_laddr_entry_t) * (l->num_laddrs + 1));
	*lp = l;

	return 0;
}
#endif

struct ip_vs_get_laddrs *ipvs_get_laddrs(ipvs_service_entry_t *svc)
{
	struct ip_vs_get_laddrs 	*l;
	struct ip_vs_get_laddrs_kern 	*lk;
	socklen_t 			len;
	int i;

	len = sizeof(*l) + sizeof(ipvs_laddr_entry_t) * svc->num_laddrs;
	if (!(l = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_laddrs;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *                 msg;
        	struct nlattr *                 nl_service;
		if (svc->num_laddrs == 0)
			l = realloc(l,sizeof(*l) + sizeof(ipvs_laddr_entry_t));
		l->fwmark = svc->fwmark;
		l->protocol = svc->protocol;
		l->addr = svc->addr;
		l->port = svc->port;
		l->num_laddrs = svc->num_laddrs;
		l->af = svc->af;

		msg = ipvs_nl_message(IPVS_CMD_GET_LADDR , NLM_F_DUMP);
		if (!msg)
			goto ipvs_nl_laddr_failure;

		nl_service = nla_nest_start(msg, IPVS_CMD_ATTR_SERVICE);
		if (!nl_service)
			goto nla_put_failure;

		NLA_PUT_U16(msg, IPVS_SVC_ATTR_AF, svc->af);

		if (svc->fwmark) {
			NLA_PUT_U32(msg, IPVS_SVC_ATTR_FWMARK, svc->fwmark);
		} else {
			NLA_PUT_U16(msg, IPVS_SVC_ATTR_PROTOCOL, svc->protocol);
			NLA_PUT(msg, IPVS_SVC_ATTR_ADDR, sizeof(svc->addr),
				&svc->addr);
			NLA_PUT_U16(msg, IPVS_SVC_ATTR_PORT, svc->port);
		}

		nla_nest_end(msg, nl_service);
		if (ipvs_nl_send_message(msg, ipvs_laddrs_parse_cb, &l))
			goto ipvs_nl_laddr_failure;

		return l;

nla_put_failure:
		nlmsg_free(msg);
ipvs_nl_laddr_failure:
		free(l);
		return NULL;
	}
#endif
	if (svc->af != AF_INET) {
	  errno = EAFNOSUPPORT;
	  free(l);
	  return NULL;
	}

	len = sizeof(*lk) + sizeof(struct ip_vs_laddr_entry_kern) * svc->num_laddrs;
	if (!(lk = malloc(len)))
		return NULL;

	lk->fwmark = svc->fwmark;
	lk->protocol = svc->protocol;
	lk->addr = svc->addr.ip;
	lk->port = svc->port;
	lk->num_laddrs = svc->num_laddrs;

	if (getsockopt(sockfd, IPPROTO_IP,
		       IP_VS_SO_GET_LADDRS, lk, &len) < 0) {
		free(l);
		free(lk);
		return NULL;
	}
	memcpy(l, lk, sizeof(struct ip_vs_get_laddrs_kern));
	l->af = AF_INET;
	l->addr.ip = l->__addr_v4;
	for (i = 0; i < lk->num_laddrs; i++) {
		memcpy(&l->entrytable[i], &lk->entrytable[i],
		       sizeof(struct ip_vs_laddr_entry_kern));
		l->entrytable[i].af = AF_INET;
		l->entrytable[i].addr.ip = l->entrytable[i].__addr_v4;
	}
	free(lk);
	return l;
}


void ipvs_free_lddrs(struct ip_vs_get_laddrs* p)
{
	free(p);
}


struct ip_vs_get_dests *ipvs_get_dests(ipvs_service_entry_t *svc)
{
	struct ip_vs_get_dests *d;
	struct ip_vs_get_dests_kern *dk;
	socklen_t len;
	int i;

	len = sizeof(*d) + sizeof(ipvs_dest_entry_t) * svc->num_dests;
	if (!(d = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_dests;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg;
		struct nlattr *nl_service;
		if (svc->num_dests == 0)
			d = realloc(d,sizeof(*d) + sizeof(ipvs_dest_entry_t));
		d->fwmark = svc->fwmark;
		d->protocol = svc->protocol;
		d->addr = svc->addr;
		d->port = svc->port;
		d->num_dests = svc->num_dests;
		d->af = svc->af;

		msg = ipvs_nl_message(IPVS_CMD_GET_DEST, NLM_F_DUMP);
		if (!msg)
			goto ipvs_nl_dest_failure;

		nl_service = nla_nest_start(msg, IPVS_CMD_ATTR_SERVICE);
		if (!nl_service)
			goto nla_put_failure;

		NLA_PUT_U16(msg, IPVS_SVC_ATTR_AF, svc->af);

		if (svc->fwmark) {
			NLA_PUT_U32(msg, IPVS_SVC_ATTR_FWMARK, svc->fwmark);
		} else {
			NLA_PUT_U16(msg, IPVS_SVC_ATTR_PROTOCOL, svc->protocol);
			NLA_PUT(msg, IPVS_SVC_ATTR_ADDR, sizeof(svc->addr),
				&svc->addr);
			NLA_PUT_U16(msg, IPVS_SVC_ATTR_PORT, svc->port);
		}

		nla_nest_end(msg, nl_service);
		if (ipvs_nl_send_message(msg, ipvs_dests_parse_cb, &d))
			goto ipvs_nl_dest_failure;

		return d;

nla_put_failure:
		nlmsg_free(msg);
ipvs_nl_dest_failure:
		free(d);
		return NULL;
	}
#endif

	if (svc->af != AF_INET) {
	  errno = EAFNOSUPPORT;
	  free(d);
	  return NULL;
	}

	len = sizeof(*dk) + sizeof(struct ip_vs_dest_entry_kern) * svc->num_dests;
	if (!(dk = malloc(len)))
		return NULL;

	dk->fwmark = svc->fwmark;
	dk->protocol = svc->protocol;
	dk->addr = svc->addr.ip;
	dk->port = svc->port;
	dk->num_dests = svc->num_dests;

	if (getsockopt(sockfd, IPPROTO_IP,
		       IP_VS_SO_GET_DESTS, dk, &len) < 0) {
		free(d);
		free(dk);
		return NULL;
	}
	memcpy(d, dk, sizeof(struct ip_vs_get_dests_kern));
	d->af = AF_INET;
	d->addr.ip = d->__addr_v4;
	for (i = 0; i < dk->num_dests; i++) {
		memcpy(&d->entrytable[i], &dk->entrytable[i],
		       sizeof(struct ip_vs_dest_entry_kern));
		d->entrytable[i].af = AF_INET;
		d->entrytable[i].addr.ip = d->entrytable[i].__addr_v4;
	}
	free(dk);
	return d;
}


int ipvs_cmp_dests(ipvs_dest_entry_t *d1, ipvs_dest_entry_t *d2)
{
	int r = 0, i;

	if (d1->af == AF_INET6)
		for (i = 0; !r && (i < 4); i++)
			r = ntohl(d1->addr.in6.s6_addr32[i]) -
			    ntohl(d2->addr.in6.s6_addr32[i]);
	else
		r = ntohl(d1->addr.ip) - ntohl(d2->addr.ip);
	if (r != 0)
		return r;

	return ntohs(d1->port) - ntohs(d2->port);
}


void ipvs_sort_dests(struct ip_vs_get_dests *d, ipvs_dest_cmp_t f)
{
	qsort(d->entrytable, d->num_dests,
	      sizeof(ipvs_dest_entry_t), (qsort_cmp_t)f);
}


ipvs_service_entry_t *
ipvs_get_service(__u32 fwmark, __u16 af, __u16 protocol, union nf_inet_addr addr, __u16 port)
{
	ipvs_service_entry_t *svc;
	socklen_t len;

	ipvs_func = ipvs_get_service;

	len = sizeof(*svc);
	if (!(svc = malloc(len)))
		return NULL;
	memset((void *)svc, 0x00, len);

	svc->fwmark = fwmark;
	svc->af = af;
	svc->protocol = protocol;
	svc->addr = addr;
	svc->port = port;
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct ip_vs_get_services *get;
		struct nl_msg *msg;
		ipvs_service_t tsvc;
		tsvc.fwmark = fwmark;
		tsvc.af = af;
		tsvc.protocol= protocol;
		tsvc.addr = addr;
		tsvc.port = port;

		if (!(get = malloc(sizeof(*get) + sizeof(ipvs_service_entry_t))))
			goto ipvs_get_service_err2;

		get->num_services = 0;

		msg = ipvs_nl_message(IPVS_CMD_GET_SERVICE, 0);
		if (!msg) goto ipvs_get_service_err;
		if (ipvs_nl_fill_service_attr(msg, &tsvc))
			goto nla_put_failure;
		if (ipvs_nl_send_message(msg, ipvs_services_parse_cb, &get))
			goto ipvs_get_service_err;

		memcpy(svc, &(get->entrytable[0]), sizeof(*svc));
		free(get);
		return svc;

nla_put_failure:
		nlmsg_free(msg);
ipvs_get_service_err:
		free(get);
ipvs_get_service_err2:
		free(svc);
		return NULL;
	}
#endif

	CHECK_COMPAT_SVC(svc, NULL);
	CHECK_PE(svc, NULL);
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_SERVICE,
		       (char *)svc, &len)) {
		free(svc);
		return NULL;
	}
	svc->af = AF_INET;
	svc->addr.ip = svc->__addr_v4;
	svc->pe_name[0] = '\0';
	return svc;
}


void ipvs_free_service(ipvs_service_entry_t* p)
{
	free(p);
}

#ifdef LIBIPVS_USE_NL
static int ipvs_timeout_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];
	ipvs_timeout_t *u = (ipvs_timeout_t *)arg;

	if (genlmsg_parse(nlh, 0, attrs, IPVS_CMD_ATTR_MAX, ipvs_cmd_policy) != 0)
		return -1;

	if (attrs[IPVS_CMD_ATTR_TIMEOUT_TCP])
		u->tcp_timeout = nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_TCP]);
	if (attrs[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN])
		u->tcp_fin_timeout = nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN]);
	if (attrs[IPVS_CMD_ATTR_TIMEOUT_UDP])
		u->udp_timeout = nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_UDP]);

	return NL_OK;
}
#endif

ipvs_timeout_t *ipvs_get_timeout(void)
{
	ipvs_timeout_t *u;
	socklen_t len;

	ipvs_func = ipvs_get_timeout;
	
	len = sizeof(*u);
	if (!(u = malloc(len)))
		return NULL;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg;
		memset(u, 0, sizeof(*u));
		msg = ipvs_nl_message(IPVS_CMD_GET_TIMEOUT, 0);
		if (msg && (ipvs_nl_send_message(msg, ipvs_timeout_parse_cb, u) == 0))
			return u;

		free(u);
		return NULL;
	}
#endif
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_TIMEOUT,
		       (char *)u, &len)) {
		free(u);
		return NULL;
	}
	return u;
}

#ifdef LIBIPVS_USE_NL
static int ipvs_daemon_parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];
	struct nlattr *daemon_attrs[IPVS_DAEMON_ATTR_MAX + 1];
	ipvs_daemon_t *u = (ipvs_daemon_t *)arg;
	int i = 0;

	/* We may get two daemons.  If we've already got one, this is the second */
	if (u[0].state)
		i = 1;

	if (genlmsg_parse(nlh, 0, attrs, IPVS_CMD_ATTR_MAX, ipvs_cmd_policy) != 0)
		return -1;

	if (nla_parse_nested(daemon_attrs, IPVS_DAEMON_ATTR_MAX,
			     attrs[IPVS_CMD_ATTR_DAEMON], ipvs_daemon_policy))
		return -1;

	if (!(daemon_attrs[IPVS_DAEMON_ATTR_STATE] &&
	      daemon_attrs[IPVS_DAEMON_ATTR_MCAST_IFN] &&
	      daemon_attrs[IPVS_DAEMON_ATTR_SYNC_ID]))
		return -1;

	u[i].state = nla_get_u32(daemon_attrs[IPVS_DAEMON_ATTR_STATE]);
	strncpy(u[i].mcast_ifn,
		nla_get_string(daemon_attrs[IPVS_DAEMON_ATTR_MCAST_IFN]),
		IP_VS_IFNAME_MAXLEN);
	u[i].syncid = nla_get_u32(daemon_attrs[IPVS_DAEMON_ATTR_SYNC_ID]);

	return NL_OK;
}
#endif

ipvs_daemon_t *ipvs_get_daemon(void)
{
	ipvs_daemon_t *u;
	socklen_t len;

	ipvs_func = ipvs_get_daemon;
	
	/* note that we need to get the info about two possible
	   daemons, master and backup. */
	len = sizeof(*u) * 2;
	if (!(u = malloc(len)))
		return NULL;

#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		struct nl_msg *msg;
		memset(u, 0, len);
		msg = ipvs_nl_message(IPVS_CMD_GET_DAEMON, NLM_F_DUMP);
		if (msg && (ipvs_nl_send_message(msg, ipvs_daemon_parse_cb, u) == 0))
			return u;

		free(u);
		return NULL;
	}
#endif
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_DAEMON, (char *)u, &len)) {
		free(u);
		return NULL;
	}
	return u;
}


void ipvs_close(void)
{
#ifdef LIBIPVS_USE_NL
	if (try_nl) {
		return;
	}
#endif
	close(sockfd);
}


const char *ipvs_strerror(int err)
{
	unsigned int i;
	struct table_struct {
		void *func;
		int err;
		const char *message;
	} table [] = {
		{ ipvs_add_service, EEXIST, "Service already exists" },
		{ ipvs_add_service, ENOENT, "Scheduler or persistence engine not found" },
		{ ipvs_update_service, ESRCH, "No such service" },
		{ ipvs_update_service, ENOENT, "Scheduler or persistence engine not found" },
		{ ipvs_del_service, ESRCH, "No such service" },
		{ ipvs_zero_service, ESRCH, "No such service" },
		{ ipvs_add_dest, ESRCH, "Service not defined" },
		{ ipvs_add_dest, EEXIST, "Destination already exists" },
		{ ipvs_update_dest, ESRCH, "Service not defined" },
		{ ipvs_update_dest, ENOENT, "No such destination" },
		{ ipvs_del_dest, ESRCH, "Service not defined" },
		{ ipvs_del_dest, ENOENT, "No such destination" },
		{ ipvs_start_daemon, EEXIST, "Daemon has already run" },
		{ ipvs_stop_daemon, ESRCH, "No daemon is running" },
		{ ipvs_get_services, ESRCH, "No such service" },
		{ ipvs_get_dests, ESRCH, "No such service" },
		{ ipvs_get_service, ESRCH, "No such service" },
		{ ipvs_add_laddr, ESRCH, "Service not defined" },
		{ ipvs_add_laddr, EEXIST, "Local address already exists" },
		{ ipvs_del_laddr, ESRCH, "Service not defined" },
		{ ipvs_del_laddr, ENOENT, "No such Local address" },
		{ ipvs_get_laddrs, ESRCH, "Service not defined" },
		{ 0, EPERM, "Permission denied (you must be root)" },
		{ 0, EINVAL, "Invalid operation.  Possibly wrong module version, address not unicast, ..." },
		{ 0, ENOPROTOOPT, "Protocol not available" },
		{ 0, ENOMEM, "Memory allocation problem" },
		{ 0, EOPNOTSUPP, "Operation not supported with IPv6" },
		{ 0, EAFNOSUPPORT, "Operation not supported with specified address family" },
		{ 0, EMSGSIZE, "Module is wrong version" },
	};

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].func || table[i].func == ipvs_func)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}


void ipvs_service_entry_2_user(const ipvs_service_entry_t *entry, ipvs_service_t *user)
{
	user->protocol  = entry->protocol;
	user->__addr_v4 = entry->__addr_v4;
	user->port      = entry->port;
	user->fwmark    = entry->fwmark;
	strcpy(user->sched_name, entry->sched_name);
	user->flags     = entry->flags;
	user->timeout   = entry->timeout;
	user->netmask   = entry->netmask;
	user->af        = entry->af;
	user->addr      = entry->addr;
	strcpy(user->pe_name, entry->pe_name);
}

