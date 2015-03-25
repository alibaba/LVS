/*
 * IPVS         An implementation of the IP virtual server support for the
 *              LINUX operating system.  IPVS is now implemented as a module
 *              over the Netfilter framework. IPVS can be used to build a
 *              high-performance and highly available server based on a
 *              cluster of servers.
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Peter Kese <peter.kese@ijs.si>
 *              Julian Anastasov <ja@ssi.bg>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * The IPVS code for kernel 2.2 was done by Wensong Zhang and Peter Kese,
 * with changes/fixes from Julian Anastasov, Lars Marowsky-Bree, Horms
 * and others.
 *
 * Changes:
 *	Paul `Rusty' Russell		properly handle non-linear skbs
 *	Harald Welte			don't use nfcache
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>		/* for icmp_send */
#include <net/route.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#ifdef CONFIG_IP_VS_IPV6
#include <net/ipv6.h>
#include <linux/netfilter_ipv6.h>
#endif

#include <net/ip_vs.h>
#include <net/ip_vs_synproxy.h>

EXPORT_SYMBOL(register_ip_vs_scheduler);
EXPORT_SYMBOL(unregister_ip_vs_scheduler);
EXPORT_SYMBOL(ip_vs_skb_replace);
EXPORT_SYMBOL(ip_vs_proto_name);
EXPORT_SYMBOL(ip_vs_conn_new);
EXPORT_SYMBOL(ip_vs_conn_get);
#ifdef CONFIG_IP_VS_PROTO_TCP
EXPORT_SYMBOL(ip_vs_tcp_conn_listen);
#endif
EXPORT_SYMBOL(ip_vs_conn_put);
#ifdef CONFIG_IP_VS_DEBUG
EXPORT_SYMBOL(ip_vs_get_debug_level);
#endif

/* ID used in ICMP lookups */
#define icmp_id(icmph)          (((icmph)->un).echo.id)
#define icmpv6_id(icmph)        (icmph->icmp6_dataun.u_echo.identifier)

const char *ip_vs_proto_name(unsigned proto)
{
	static char buf[20];

	switch (proto) {
	case IPPROTO_IP:
		return "IP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_ICMP:
		return "ICMP";
#ifdef CONFIG_IP_VS_IPV6
	case IPPROTO_ICMPV6:
		return "ICMPv6";
#endif
	default:
		sprintf(buf, "IP_%d", proto);
		return buf;
	}
}

void ip_vs_init_hash_table(struct list_head *table, int rows)
{
	while (--rows >= 0)
		INIT_LIST_HEAD(&table[rows]);
}

static inline int
ip_vs_set_state(struct ip_vs_conn *cp, int direction,
		const struct sk_buff *skb, struct ip_vs_protocol *pp)
{
	if (unlikely(!pp->state_transition))
		return 0;
	return pp->state_transition(cp, direction, skb, pp);
}

static inline __u16
ip_vs_onepacket_enabled(struct ip_vs_service *svc, struct ip_vs_iphdr *iph)
{
	return (svc->flags & IP_VS_SVC_F_ONEPACKET
		&& iph->protocol == IPPROTO_UDP)
	    ? IP_VS_CONN_F_ONE_PACKET : 0;
}

/*
 *  IPVS persistent scheduling function
 *  It creates a connection entry according to its template if exists,
 *  or selects a server and creates a connection entry plus a template.
 *  Locking: we are svc user (svc->refcnt), so we hold all dests too
 *  Protocols supported: TCP, UDP
 */
static struct ip_vs_conn *ip_vs_sched_persist(struct ip_vs_service *svc,
					      struct sk_buff *skb,
					      __be16 ports[2],
					      int is_synproxy_on)
{
	struct ip_vs_conn *cp = NULL;
	struct ip_vs_iphdr iph;
	struct ip_vs_dest *dest;
	struct ip_vs_conn *ct;
	__be16 dport;		/* destination port to forward */
	union nf_inet_addr snet;	/* source network of the client,
					   after masking */

	ip_vs_fill_iphdr(svc->af, skb_network_header(skb), &iph);

	/* Mask saddr with the netmask to adjust template granularity */
#ifdef CONFIG_IP_VS_IPV6
	if (svc->af == AF_INET6)
		ipv6_addr_prefix(&snet.in6, &iph.saddr.in6, svc->netmask);
	else
#endif
		snet.ip = iph.saddr.ip & svc->netmask;

	IP_VS_DBG_BUF(6, "p-schedule: src %s:%u dest %s:%u "
		      "mnet %s\n",
		      IP_VS_DBG_ADDR(svc->af, &iph.saddr), ntohs(ports[0]),
		      IP_VS_DBG_ADDR(svc->af, &iph.daddr), ntohs(ports[1]),
		      IP_VS_DBG_ADDR(svc->af, &snet));

	/*
	 * As far as we know, FTP is a very complicated network protocol, and
	 * it uses control connection and data connections. For active FTP,
	 * FTP server initialize data connection to the client, its source port
	 * is often 20. For passive FTP, FTP server tells the clients the port
	 * that it passively listens to,  and the client issues the data
	 * connection. In the tunneling or direct routing mode, the load
	 * balancer is on the client-to-server half of connection, the port
	 * number is unknown to the load balancer. So, a conn template like
	 * <caddr, 0, vaddr, 0, daddr, 0> is created for persistent FTP
	 * service, and a template like <caddr, 0, vaddr, vport, daddr, dport>
	 * is created for other persistent services.
	 */
	if (ports[1] == svc->port) {
		/* Check if a template already exists */
		if (svc->port != FTPPORT)
			ct = ip_vs_ct_in_get(svc->af, iph.protocol, &snet, 0,
					     &iph.daddr, ports[1]);
		else
			ct = ip_vs_ct_in_get(svc->af, iph.protocol, &snet, 0,
					     &iph.daddr, 0);

		if (!ct || !ip_vs_check_template(ct)) {
			/*
			 * No template found or the dest of the connection
			 * template is not available.
			 */
			dest = svc->scheduler->schedule(svc, skb);
			if (dest == NULL) {
				IP_VS_DBG(1, "p-schedule: no dest found.\n");
				return NULL;
			}

			/*
			 * Create a template like <protocol,caddr,0,
			 * vaddr,vport,daddr,dport> for non-ftp service,
			 * and <protocol,caddr,0,vaddr,0,daddr,0>
			 * for ftp service.
			 */
			if (svc->port != FTPPORT)
				ct = ip_vs_conn_new(svc->af, iph.protocol,
						    &snet, 0,
						    &iph.daddr,
						    ports[1],
						    &dest->addr, dest->port,
						    IP_VS_CONN_F_TEMPLATE,
						    dest, NULL, 0);
			else
				ct = ip_vs_conn_new(svc->af, iph.protocol,
						    &snet, 0,
						    &iph.daddr, 0,
						    &dest->addr, 0,
						    IP_VS_CONN_F_TEMPLATE,
						    dest, NULL, 0);
			if (ct == NULL)
				return NULL;

			ct->timeout = svc->timeout;
		} else {
			/* set destination with the found template */
			dest = ct->dest;
		}
		dport = dest->port;
	} else {
		/*
		 * Note: persistent fwmark-based services and persistent
		 * port zero service are handled here.
		 * fwmark template: <IPPROTO_IP,caddr,0,fwmark,0,daddr,0>
		 * port zero template: <protocol,caddr,0,vaddr,0,daddr,0>
		 */
		if (svc->fwmark) {
			union nf_inet_addr fwmark = {
				.ip = htonl(svc->fwmark)
			};

			ct = ip_vs_ct_in_get(svc->af, IPPROTO_IP, &snet, 0,
					     &fwmark, 0);
		} else
			ct = ip_vs_ct_in_get(svc->af, iph.protocol, &snet, 0,
					     &iph.daddr, 0);

		if (!ct || !ip_vs_check_template(ct)) {
			/*
			 * If it is not persistent port zero, return NULL,
			 * otherwise create a connection template.
			 */
			if (svc->port)
				return NULL;

			dest = svc->scheduler->schedule(svc, skb);
			if (dest == NULL) {
				IP_VS_DBG(1, "p-schedule: no dest found.\n");
				return NULL;
			}

			/*
			 * Create a template according to the service
			 */
			if (svc->fwmark) {
				union nf_inet_addr fwmark = {
					.ip = htonl(svc->fwmark)
				};

				ct = ip_vs_conn_new(svc->af, IPPROTO_IP,
						    &snet, 0,
						    &fwmark, 0,
						    &dest->addr, 0,
						    IP_VS_CONN_F_TEMPLATE,
						    dest, NULL, 0);
			} else
				ct = ip_vs_conn_new(svc->af, iph.protocol,
						    &snet, 0,
						    &iph.daddr, 0,
						    &dest->addr, 0,
						    IP_VS_CONN_F_TEMPLATE,
						    dest, NULL, 0);
			if (ct == NULL)
				return NULL;

			ct->timeout = svc->timeout;
		} else {
			/* set destination with the found template */
			dest = ct->dest;
		}
		dport = ports[1];
	}

	/*
	 *    Create a new connection according to the template
	 */
	cp = ip_vs_conn_new(svc->af, iph.protocol,
			    &iph.saddr, ports[0],
			    &iph.daddr, ports[1],
			    &dest->addr, dport,
			    ip_vs_onepacket_enabled(svc, &iph),
			    dest, skb, is_synproxy_on);
	if (cp == NULL) {
		ip_vs_conn_put(ct);
		return NULL;
	}

	/*
	 *    Add its control
	 */
	ip_vs_control_add(cp, ct);
	ip_vs_conn_put(ct);

	ip_vs_conn_stats(cp, svc);
	return cp;
}

/*
 *  IPVS main scheduling function
 *  It selects a server according to the virtual service, and
 *  creates a connection entry.
 *  Protocols supported: TCP, UDP
 */
struct ip_vs_conn *ip_vs_schedule(struct ip_vs_service *svc,
				  struct sk_buff *skb, int is_synproxy_on)
{
	struct ip_vs_conn *cp = NULL;
	struct ip_vs_iphdr iph;
	struct ip_vs_dest *dest;
	__be16 _ports[2], *pptr;

	ip_vs_fill_iphdr(svc->af, skb_network_header(skb), &iph);
	pptr = skb_header_pointer(skb, iph.len, sizeof(_ports), _ports);
	if (pptr == NULL)
		return NULL;

	/*
	 *    Persistent service
	 */
	if (svc->flags & IP_VS_SVC_F_PERSISTENT)
		return ip_vs_sched_persist(svc, skb, pptr, is_synproxy_on);

	/*
	 *    Non-persistent service
	 */
	if (!svc->fwmark && pptr[1] != svc->port) {
		if (!svc->port)
			pr_err("Schedule: port zero only supported "
			       "in persistent services, "
			       "check your ipvs configuration\n");
		return NULL;
	}

	dest = svc->scheduler->schedule(svc, skb);
	if (dest == NULL) {
		IP_VS_DBG(1, "Schedule: no dest found.\n");
		return NULL;
	}

	/*
	 *    Create a connection entry.
	 */
	
	if (IS_SNAT_SVC(svc))
	cp = ip_vs_conn_new(svc->af, iph.protocol,
			    &iph.saddr, pptr[0],
			    &iph.daddr, pptr[1],
			    &iph.daddr, pptr[1],
			    ip_vs_onepacket_enabled(svc, &iph),
			    dest, skb, is_synproxy_on);
	else
	cp = ip_vs_conn_new(svc->af, iph.protocol,
			    &iph.saddr, pptr[0],
			    &iph.daddr, pptr[1],
			    &dest->addr, dest->port ? dest->port : pptr[1],
			    ip_vs_onepacket_enabled(svc, &iph),
			    dest, skb, is_synproxy_on);
	if (cp == NULL)
		return NULL;

	IP_VS_DBG_BUF(6, "Schedule fwd:%c c:%s:%u v:%s:%u "
		      "d:%s:%u conn->flags:%X conn->refcnt:%d\n",
		      ip_vs_fwd_tag(cp),
		      IP_VS_DBG_ADDR(svc->af, &cp->caddr), ntohs(cp->cport),
		      IP_VS_DBG_ADDR(svc->af, &cp->vaddr), ntohs(cp->vport),
		      IP_VS_DBG_ADDR(svc->af, &cp->daddr), ntohs(cp->dport),
		      cp->flags, atomic_read(&cp->refcnt));

	ip_vs_conn_stats(cp, svc);
	return cp;
}

/*
 *  Pass or drop the packet.
 *  Called by ip_vs_in, when the virtual service is available but
 *  no destination is available for a new connection.
 */
int ip_vs_leave(struct ip_vs_service *svc, struct sk_buff *skb,
		struct ip_vs_protocol *pp)
{
	__be16 _ports[2], *pptr;
	struct ip_vs_iphdr iph;
	int unicast;
	ip_vs_fill_iphdr(svc->af, skb_network_header(skb), &iph);

	pptr = skb_header_pointer(skb, iph.len, sizeof(_ports), _ports);
	if (pptr == NULL) {
		ip_vs_service_put(svc);
		return NF_DROP;
	}
#ifdef CONFIG_IP_VS_IPV6
	if (svc->af == AF_INET6)
		unicast = ipv6_addr_type(&iph.daddr.in6) & IPV6_ADDR_UNICAST;
	else
#endif
		unicast =
		    (inet_addr_type(&init_net, iph.daddr.ip) == RTN_UNICAST);

	/* if it is fwmark-based service, the cache_bypass sysctl is up
	   and the destination is a non-local unicast, then create
	   a cache_bypass connection entry */
	if (sysctl_ip_vs_cache_bypass && svc->fwmark && unicast) {
		int ret, cs;
		struct ip_vs_conn *cp;
		union nf_inet_addr daddr = {.all = {0, 0, 0, 0} };

		ip_vs_service_put(svc);

		/* create a new connection entry */
		IP_VS_DBG(6, "%s(): create a cache_bypass entry\n", __func__);
		cp = ip_vs_conn_new(svc->af, iph.protocol,
				    &iph.saddr, pptr[0],
				    &iph.daddr, pptr[1],
				    &daddr, 0,
				    IP_VS_CONN_F_BYPASS |
				    ip_vs_onepacket_enabled(svc, &iph),
				    NULL, NULL, 0);
		if (cp == NULL)
			return NF_DROP;

		/* statistics */
		ip_vs_in_stats(cp, skb);

		/* set state */
		cs = ip_vs_set_state(cp, IP_VS_DIR_INPUT, skb, pp);

		/* transmit the first SYN packet */
		ret = cp->packet_xmit(skb, cp, pp);
		/* do not touch skb anymore */

		atomic_inc(&cp->in_pkts);
		ip_vs_conn_put(cp);
		return ret;
	}

	/*
	 * When the virtual ftp service is presented, packets destined
	 * for other services on the VIP may get here (except services
	 * listed in the ipvs table), pass the packets, because it is
	 * not ipvs job to decide to drop the packets.
	 */
	if ((svc->port == FTPPORT) && (pptr[1] != FTPPORT)) {
		ip_vs_service_put(svc);
		return NF_ACCEPT;
	}

	ip_vs_service_put(svc);

	/*
	 * Notify the client that the destination is unreachable, and
	 * release the socket buffer.
	 * Since it is in IP layer, the TCP socket is not actually
	 * created, the TCP RST packet cannot be sent, instead that
	 * ICMP_PORT_UNREACH is sent here no matter it is TCP/UDP. --WZ
	 */
#ifdef CONFIG_IP_VS_IPV6
	if (svc->af == AF_INET6)
		icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0,
			    skb->dev);
	else
#endif
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	IP_VS_INC_ESTATS(ip_vs_esmib, CONN_SCHED_UNREACH);

	return NF_DROP;
}

/*
 *      It is hooked before NF_IP_PRI_NAT_SRC at the NF_INET_POST_ROUTING
 *      chain, and is used for VS/NAT.
 *      It detects packets for VS/NAT connections and sends the packets
 *      immediately. This can avoid that iptable_nat mangles the packets
 *      for VS/NAT.
 */
static unsigned int ip_vs_post_routing(unsigned int hooknum,
				       struct sk_buff *skb,
				       const struct net_device *in,
				       const struct net_device *out,
				       int (*okfn) (struct sk_buff *))
{
	if (!skb->ipvs_property)
		return NF_ACCEPT;
	/* The packet was sent from IPVS, exit this chain */
	return NF_STOP;
}

__sum16 ip_vs_checksum_complete(struct sk_buff * skb, int offset)
{
	return csum_fold(skb_checksum(skb, offset, skb->len - offset, 0));
}

static inline int ip_vs_gather_frags(struct sk_buff *skb, u_int32_t user)
{
	int err = ip_defrag(skb, user);

	if (!err)
		ip_send_check(ip_hdr(skb));

	return err;
}

#ifdef CONFIG_IP_VS_IPV6
static inline int ip_vs_gather_frags_v6(struct sk_buff *skb, u_int32_t user)
{
	/* TODO IPv6: Find out what to do here for IPv6 */
	return 0;
}
#endif

/* Handle relevant response ICMP messages - forward to the right
 * destination host. Used for NAT / local client / FULLNAT.
 */
static int handle_response_icmp(int af, struct sk_buff *skb,
				union nf_inet_addr *snet,
				__u8 protocol, struct ip_vs_conn *cp,
				struct ip_vs_protocol *pp,
				unsigned int offset, unsigned int ihl)
{
	unsigned int verdict = NF_DROP;

	if ((IP_VS_FWD_METHOD(cp) != IP_VS_CONN_F_MASQ)
	    && (IP_VS_FWD_METHOD(cp) != IP_VS_CONN_F_FULLNAT)) {
		pr_err("shouldn't reach here, because the box is on the "
		       "half connection in the tun/dr module.\n");
	}

	/* Ensure the checksum is correct */
	if (!skb_csum_unnecessary(skb) && ip_vs_checksum_complete(skb, ihl)) {
		/* Failed checksum! */
		IP_VS_DBG_BUF(1, "Forward ICMP: failed checksum from %s!\n",
			      IP_VS_DBG_ADDR(af, snet));
		goto out;
	}

	if (IPPROTO_TCP == protocol || IPPROTO_UDP == protocol)
		offset += 2 * sizeof(__u16);

	/* do the statistics and put it back */
	ip_vs_out_stats(cp, skb);

	if (IP_VS_FWD_METHOD(cp) == IP_VS_CONN_F_FULLNAT) {
#ifdef CONFIG_IP_VS_IPV6
		if (af == AF_INET6)
			verdict =
			    ip_vs_fnat_response_icmp_xmit_v6(skb, pp, cp,
							     offset);
		else
#endif
			verdict =
			    ip_vs_fnat_response_icmp_xmit(skb, pp, cp, offset);

	} else {
#ifdef CONFIG_IP_VS_IPV6
		if (af == AF_INET6)
			verdict =
			    ip_vs_normal_response_icmp_xmit_v6(skb, pp, cp,
							       offset);
		else
#endif
			verdict =
			    ip_vs_normal_response_icmp_xmit(skb, pp, cp,
							    offset);
	}

      out:
	__ip_vs_conn_put(cp);

	return verdict;
}

/*
 *	Handle ICMP messages in the inside-to-outside direction (outgoing).
 *	Find any that might be relevant, check against existing connections.
 *	Currently handles error types - unreachable, quench, ttl exceeded.
 */
static int ip_vs_out_icmp(struct sk_buff *skb, int *related)
{
	struct iphdr *iph;
	struct icmphdr _icmph, *ic;
	struct iphdr _ciph, *cih;	/* The ip header contained within the ICMP */
	struct ip_vs_iphdr ciph;
	struct ip_vs_conn *cp;
	struct ip_vs_protocol *pp;
	unsigned int offset, ihl;
	union nf_inet_addr snet;
	int res_dir;

	*related = 1;

	/* reassemble IP fragments */
	if (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)) {
		if (ip_vs_gather_frags(skb, IP_DEFRAG_VS_OUT))
			return NF_STOLEN;
	}

	iph = ip_hdr(skb);
	offset = ihl = iph->ihl * 4;
	ic = skb_header_pointer(skb, offset, sizeof(_icmph), &_icmph);
	if (ic == NULL)
		return NF_DROP;

	IP_VS_DBG(12, "Outgoing ICMP (%d,%d) %pI4->%pI4\n",
		  ic->type, ntohs(icmp_id(ic)), &iph->saddr, &iph->daddr);

	/*
	 * Work through seeing if this is for us.
	 * These checks are supposed to be in an order that means easy
	 * things are checked first to speed up processing.... however
	 * this means that some packets will manage to get a long way
	 * down this stack and then be rejected, but that's life.
	 */
	if ((ic->type != ICMP_DEST_UNREACH) &&
	    (ic->type != ICMP_SOURCE_QUENCH) &&
	    (ic->type != ICMP_TIME_EXCEEDED)) {
		*related = 0;
		return NF_ACCEPT;
	}

	/* Now find the contained IP header */
	offset += sizeof(_icmph);
	cih = skb_header_pointer(skb, offset, sizeof(_ciph), &_ciph);
	if (cih == NULL)
		return NF_ACCEPT;	/* The packet looks wrong, ignore */

	pp = ip_vs_proto_get(cih->protocol);
	if (!pp)
		return NF_ACCEPT;

	/* Is the embedded protocol header present? */
	if (unlikely(cih->frag_off & htons(IP_OFFSET) && pp->dont_defrag))
		return NF_ACCEPT;

	IP_VS_DBG_PKT(11, pp, skb, offset, "Checking outgoing ICMP for");

	offset += cih->ihl * 4;

	ip_vs_fill_iphdr(AF_INET, cih, &ciph);
	/* The embedded headers contain source and dest in reverse order */
	cp = pp->conn_out_get(AF_INET, skb, pp, &ciph, offset, 1, &res_dir);
	if (!cp)
		return NF_ACCEPT;

	snet.ip = iph->saddr;
	return handle_response_icmp(AF_INET, skb, &snet, cih->protocol, cp,
				    pp, offset, ihl);
}

#ifdef CONFIG_IP_VS_IPV6
static int ip_vs_out_icmp_v6(struct sk_buff *skb, int *related)
{
	struct ipv6hdr *iph;
	struct icmp6hdr _icmph, *ic;
	struct ipv6hdr _ciph, *cih;	/* The ip header contained
					   within the ICMP */
	struct ip_vs_iphdr ciph;
	struct ip_vs_conn *cp;
	struct ip_vs_protocol *pp;
	unsigned int offset;
	union nf_inet_addr snet;
	int res_dir;

	*related = 1;

	/* reassemble IP fragments */
	if (ipv6_hdr(skb)->nexthdr == IPPROTO_FRAGMENT) {
		if (ip_vs_gather_frags_v6(skb, IP_DEFRAG_VS_OUT))
			return NF_STOLEN;
	}

	iph = ipv6_hdr(skb);
	offset = sizeof(struct ipv6hdr);
	ic = skb_header_pointer(skb, offset, sizeof(_icmph), &_icmph);
	if (ic == NULL)
		return NF_DROP;

	IP_VS_DBG(12, "Outgoing ICMPv6 (%d,%d) %pI6->%pI6\n",
		  ic->icmp6_type, ntohs(icmpv6_id(ic)),
		  &iph->saddr, &iph->daddr);

	/*
	 * Work through seeing if this is for us.
	 * These checks are supposed to be in an order that means easy
	 * things are checked first to speed up processing.... however
	 * this means that some packets will manage to get a long way
	 * down this stack and then be rejected, but that's life.
	 */
	if ((ic->icmp6_type != ICMPV6_DEST_UNREACH) &&
	    (ic->icmp6_type != ICMPV6_PKT_TOOBIG) &&
	    (ic->icmp6_type != ICMPV6_TIME_EXCEED)) {
		*related = 0;
		return NF_ACCEPT;
	}

	/* Now find the contained IP header */
	offset += sizeof(_icmph);
	cih = skb_header_pointer(skb, offset, sizeof(_ciph), &_ciph);
	if (cih == NULL)
		return NF_ACCEPT;	/* The packet looks wrong, ignore */

	pp = ip_vs_proto_get(cih->nexthdr);
	if (!pp)
		return NF_ACCEPT;

	/* Is the embedded protocol header present? */
	/* TODO: we don't support fragmentation at the moment anyways */
	if (unlikely(cih->nexthdr == IPPROTO_FRAGMENT && pp->dont_defrag))
		return NF_ACCEPT;

	IP_VS_DBG_PKT(11, pp, skb, offset, "Checking outgoing ICMPv6 for");

	offset += sizeof(struct ipv6hdr);

	ip_vs_fill_iphdr(AF_INET6, cih, &ciph);
	/* The embedded headers contain source and dest in reverse order */
	cp = pp->conn_out_get(AF_INET6, skb, pp, &ciph, offset, 1, &res_dir);
	if (!cp)
		return NF_ACCEPT;

	ipv6_addr_copy(&snet.in6, &iph->saddr);
	return handle_response_icmp(AF_INET6, skb, &snet, cih->nexthdr, cp,
				    pp, offset, sizeof(struct ipv6hdr));
}
#endif

static inline int is_tcp_reset(const struct sk_buff *skb, int nh_len)
{
	struct tcphdr _tcph, *th;

	th = skb_header_pointer(skb, nh_len, sizeof(_tcph), &_tcph);
	if (th == NULL)
		return 0;
	return th->rst;
}

/* Handle response packets: rewrite addresses and send away...
 * Used for NAT / local client / FULLNAT.
 */
static unsigned int
handle_response(int af, struct sk_buff *skb, struct ip_vs_protocol *pp,
		struct ip_vs_conn *cp, int ihl)
{
	unsigned int ret = NF_DROP;

	/* statistics */
	ip_vs_out_stats(cp, skb);

	/*
	 * Syn-proxy step 3 logic: receive syn-ack from rs.
	 */
	if (pp->protocol == IPPROTO_TCP && ip_vs_synproxy_synack_rcv(skb, cp, pp, ihl, &ret) == 0) {
		goto out;
	}

	/* state transition */
	ip_vs_set_state(cp, IP_VS_DIR_OUTPUT, skb, pp);
	/* transmit */

	if (cp->flags & IP_VS_CONN_F_FULLNAT) {
#ifdef CONFIG_IP_VS_IPV6
		if (af == AF_INET6) {
			ret = ip_vs_fnat_response_xmit_v6(skb, pp, cp, ihl);
		} else
#endif
		{
			ret = ip_vs_fnat_response_xmit(skb, pp, cp, ihl);
		}
	} else {
#ifdef CONFIG_IP_VS_IPV6
		if (af == AF_INET6) {
			ret = ip_vs_normal_response_xmit_v6(skb, pp, cp, ihl);
		} else
#endif
		{
			ret = ip_vs_normal_response_xmit(skb, pp, cp, ihl);
		}

	}

      out:
	ip_vs_conn_put(cp);
	return ret;
}

static unsigned int
ip_vs_snat_out(int af, struct sk_buff *skb, struct ip_vs_protocol *pp,
		int *v, struct ip_vs_conn *cp)
{
	if (af != AF_INET)
		return 1;

	if (cp && NOT_SNAT_CP(cp))
		return 1;

	EnterFunction(11);
	if (!cp) {
		skb->mark = 1;
		if (!pp->conn_schedule(af, skb, pp, v, &cp))
			return 0;

		if (unlikely(!cp)) {
			/* sorry, all this trouble for a no-hit :) */
			IP_VS_DBG_PKT(12, pp, skb, 0,
				      "packet continues traversal as normal");
			*v = NF_ACCEPT;
			return 0;
		}
	}

	IP_VS_DBG_PKT(11, pp, skb, 0, "Forward packet");
	ip_vs_in_stats(cp, skb);

	ip_vs_set_state(cp, IP_VS_DIR_INPUT, skb, pp);

	if (cp->packet_xmit)
		*v = cp->packet_xmit(skb, cp, pp);
	/* do not touch skb anymore */
	else {
		IP_VS_DBG_RL("warning: packet_xmit is null");
		*v = NF_ACCEPT;
	}
	
	cp->old_state = cp->state;
	ip_vs_conn_put(cp);
	return 0;
}

/*
 *	It is hooked at the NF_INET_FORWARD chain, used only for VS/NAT.
 *	Check if outgoing packet belongs to the established ip_vs_conn.
 */
static unsigned int
ip_vs_out(unsigned int hooknum, struct sk_buff *skb,
	  const struct net_device *in, const struct net_device *out,
	  int (*okfn) (struct sk_buff *))
{
	struct ip_vs_iphdr iph;
	struct ip_vs_protocol *pp;
	struct ip_vs_conn *cp;
	int af;
	int res_dir;
	int verdict;

	EnterFunction(11);

	af = (skb->protocol == htons(ETH_P_IP)) ? AF_INET : AF_INET6;

	if (skb->ipvs_property)
		return NF_ACCEPT;

	ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6) {
		if (unlikely(iph.protocol == IPPROTO_ICMPV6)) {
			int related, verdict = ip_vs_out_icmp_v6(skb, &related);

			if (related)
				return verdict;
			ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);
		}
	} else
#endif
	if (unlikely(iph.protocol == IPPROTO_ICMP)) {
		int related, verdict = ip_vs_out_icmp(skb, &related);

		if (related)
			return verdict;
		ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);
	}

	pp = ip_vs_proto_get(iph.protocol);
	if (unlikely(!pp))
		return NF_ACCEPT;

	/* reassemble IP fragments */
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6) {
		if (unlikely(iph.protocol == IPPROTO_ICMPV6)) {
			int related, verdict = ip_vs_out_icmp_v6(skb, &related);

			if (related)
				return verdict;

			ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);
		}
	} else
#endif
	if (unlikely(ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET) &&
			     !pp->dont_defrag)) {
		if (ip_vs_gather_frags(skb, IP_DEFRAG_VS_OUT))
			return NF_STOLEN;

		ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);
	}

	/*
	 * Check if the packet belongs to an existing entry
	 */
	cp = pp->conn_out_get(af, skb, pp, &iph, iph.len, 0, &res_dir);

	if (0 == ip_vs_snat_out(af, skb, pp, &verdict, cp)) {
		return verdict;
	}

	if (unlikely(!cp)) {
		if (sysctl_ip_vs_nat_icmp_send &&
		    (pp->protocol == IPPROTO_TCP ||
		     pp->protocol == IPPROTO_UDP)) {
			__be16 _ports[2], *pptr;

			pptr = skb_header_pointer(skb, iph.len,
						  sizeof(_ports), _ports);
			if (pptr == NULL)
				return NF_ACCEPT;	/* Not for me */
			if (ip_vs_lookup_real_service(af, iph.protocol,
						      &iph.saddr, pptr[0])) {
				/*
				 * Notify the real server: there is no
				 * existing entry if it is not RST
				 * packet or not TCP packet.
				 */
				if (iph.protocol != IPPROTO_TCP
				    || !is_tcp_reset(skb, iph.len)) {
#ifdef CONFIG_IP_VS_IPV6
					if (af == AF_INET6)
						icmpv6_send(skb,
							    ICMPV6_DEST_UNREACH,
							    ICMPV6_PORT_UNREACH,
							    0, skb->dev);
					else
#endif
						icmp_send(skb,
							  ICMP_DEST_UNREACH,
							  ICMP_PORT_UNREACH, 0);
					return NF_DROP;
				}
			}
		}
		IP_VS_DBG_PKT(12, pp, skb, 0,
			      "packet continues traversal as normal");
		return NF_ACCEPT;
	}

	return handle_response(af, skb, pp, cp, iph.len);
}

/*
 *	Handle ICMP messages in the outside-to-inside direction (incoming).
 *	Find any that might be relevant, check against existing connections,
 *	forward to the right destination host if relevant.
 *	Currently handles error types - unreachable, quench, ttl exceeded.
 */
static int
ip_vs_in_icmp(struct sk_buff *skb, int *related, unsigned int hooknum)
{
	struct iphdr *iph;
	struct icmphdr _icmph, *ic;
	struct iphdr _ciph, *cih;	/* The ip header contained within the ICMP */
	struct ip_vs_iphdr ciph;
	struct ip_vs_conn *cp;
	struct ip_vs_protocol *pp;
	unsigned int offset, ihl, verdict;
	union nf_inet_addr snet;
	int res_dir;

	*related = 1;

	/* reassemble IP fragments */
	if (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)) {
		if (ip_vs_gather_frags(skb, hooknum == NF_INET_LOCAL_IN ?
				       IP_DEFRAG_VS_IN : IP_DEFRAG_VS_FWD))
			return NF_STOLEN;
	}

	iph = ip_hdr(skb);
	offset = ihl = iph->ihl * 4;
	ic = skb_header_pointer(skb, offset, sizeof(_icmph), &_icmph);
	if (ic == NULL)
		return NF_DROP;

	IP_VS_DBG(12, "Incoming ICMP (%d,%d) %pI4->%pI4\n",
		  ic->type, ntohs(icmp_id(ic)), &iph->saddr, &iph->daddr);

	/*
	 * Work through seeing if this is for us.
	 * These checks are supposed to be in an order that means easy
	 * things are checked first to speed up processing.... however
	 * this means that some packets will manage to get a long way
	 * down this stack and then be rejected, but that's life.
	 */
	if ((ic->type != ICMP_DEST_UNREACH) &&
	    (ic->type != ICMP_SOURCE_QUENCH) &&
	    (ic->type != ICMP_TIME_EXCEEDED)) {
		*related = 0;
		return NF_ACCEPT;
	}

	/* Now find the contained IP header */
	offset += sizeof(_icmph);
	cih = skb_header_pointer(skb, offset, sizeof(_ciph), &_ciph);
	if (cih == NULL)
		return NF_ACCEPT;	/* The packet looks wrong, ignore */

	pp = ip_vs_proto_get(cih->protocol);
	if (!pp)
		return NF_ACCEPT;

	/* Is the embedded protocol header present? */
	if (unlikely(cih->frag_off & htons(IP_OFFSET) && pp->dont_defrag))
		return NF_ACCEPT;

	IP_VS_DBG_PKT(11, pp, skb, offset, "Checking incoming ICMP for");

	offset += cih->ihl * 4;

	ip_vs_fill_iphdr(AF_INET, cih, &ciph);
	/* The embedded headers contain source and dest in reverse order */
	cp = pp->conn_in_get(AF_INET, skb, pp, &ciph, offset, 1, &res_dir);
	if (!cp) {
		return NF_ACCEPT;
	}

	if (res_dir == IP_VS_CIDX_F_IN2OUT) {
		/* The packet belong to a local client / fullnat */
		snet.ip = iph->saddr;
		return handle_response_icmp(AF_INET, skb, &snet,
					    cih->protocol, cp, pp, offset, ihl);
	}

	verdict = NF_DROP;

	/* Ensure the checksum is correct */
	if (!skb_csum_unnecessary(skb) && ip_vs_checksum_complete(skb, ihl)) {
		/* Failed checksum! */
		IP_VS_DBG(1, "Incoming ICMP: failed checksum from %pI4!\n",
			  &iph->saddr);
		goto out;
	}

	/* do the statistics and put it back */
	ip_vs_in_stats(cp, skb);
	if (IPPROTO_TCP == cih->protocol || IPPROTO_UDP == cih->protocol)
		offset += 2 * sizeof(__u16);
	verdict = ip_vs_icmp_xmit(skb, cp, pp, offset);
	/* do not touch skb anymore */

      out:
	__ip_vs_conn_put(cp);

	return verdict;
}

#ifdef CONFIG_IP_VS_IPV6
static int
ip_vs_in_icmp_v6(struct sk_buff *skb, int *related, unsigned int hooknum)
{
	struct ipv6hdr *iph;
	struct icmp6hdr _icmph, *ic;
	struct ipv6hdr _ciph, *cih;	/* The ip header contained
					   within the ICMP */
	struct ip_vs_iphdr ciph;
	struct ip_vs_conn *cp;
	struct ip_vs_protocol *pp;
	unsigned int offset, verdict;
	union nf_inet_addr snet;
	int res_dir;

	*related = 1;

	/* reassemble IP fragments */
	if (ipv6_hdr(skb)->nexthdr == IPPROTO_FRAGMENT) {
		if (ip_vs_gather_frags_v6(skb, hooknum == NF_INET_LOCAL_IN ?
					  IP_DEFRAG_VS_IN : IP_DEFRAG_VS_FWD))
			return NF_STOLEN;
	}

	iph = ipv6_hdr(skb);
	offset = sizeof(struct ipv6hdr);
	ic = skb_header_pointer(skb, offset, sizeof(_icmph), &_icmph);
	if (ic == NULL)
		return NF_DROP;

	IP_VS_DBG(12, "Incoming ICMPv6 (%d,%d) %pI6->%pI6\n",
		  ic->icmp6_type, ntohs(icmpv6_id(ic)),
		  &iph->saddr, &iph->daddr);

	/*
	 * Work through seeing if this is for us.
	 * These checks are supposed to be in an order that means easy
	 * things are checked first to speed up processing.... however
	 * this means that some packets will manage to get a long way
	 * down this stack and then be rejected, but that's life.
	 */
	if ((ic->icmp6_type != ICMPV6_DEST_UNREACH) &&
	    (ic->icmp6_type != ICMPV6_PKT_TOOBIG) &&
	    (ic->icmp6_type != ICMPV6_TIME_EXCEED)) {
		*related = 0;
		return NF_ACCEPT;
	}

	/* Now find the contained IP header */
	offset += sizeof(_icmph);
	cih = skb_header_pointer(skb, offset, sizeof(_ciph), &_ciph);
	if (cih == NULL)
		return NF_ACCEPT;	/* The packet looks wrong, ignore */

	pp = ip_vs_proto_get(cih->nexthdr);
	if (!pp)
		return NF_ACCEPT;

	/* Is the embedded protocol header present? */
	/* TODO: we don't support fragmentation at the moment anyways */
	if (unlikely(cih->nexthdr == IPPROTO_FRAGMENT && pp->dont_defrag))
		return NF_ACCEPT;

	IP_VS_DBG_PKT(11, pp, skb, offset, "Checking incoming ICMPv6 for");

	offset += sizeof(struct ipv6hdr);

	ip_vs_fill_iphdr(AF_INET6, cih, &ciph);
	/* The embedded headers contain source and dest in reverse order */
	cp = pp->conn_in_get(AF_INET6, skb, pp, &ciph, offset, 1, &res_dir);
	if (!cp) {
		return NF_ACCEPT;
	}

	if (res_dir == IP_VS_CIDX_F_IN2OUT) {
		ipv6_addr_copy(&snet.in6, &iph->saddr);
		return handle_response_icmp(AF_INET6, skb, &snet,
					    cih->nexthdr,
					    cp, pp, offset,
					    sizeof(struct ipv6hdr));
	}

	verdict = NF_DROP;

	/* do the statistics and put it back */
	ip_vs_in_stats(cp, skb);
	if (IPPROTO_TCP == cih->nexthdr || IPPROTO_UDP == cih->nexthdr)
		offset += 2 * sizeof(__u16);
	verdict = ip_vs_icmp_xmit_v6(skb, cp, pp, offset);
	/* do not touch skb anymore */

	__ip_vs_conn_put(cp);

	return verdict;
}
#endif

/*
 *	Check if it's for virtual services, look it up,
 *	and send it on its way...
 */
static unsigned int
ip_vs_in(unsigned int hooknum, struct sk_buff *skb,
	 const struct net_device *in, const struct net_device *out,
	 int (*okfn) (struct sk_buff *))
{
	struct ip_vs_iphdr iph;
	struct ip_vs_protocol *pp;
	struct ip_vs_conn *cp;
	int ret, restart, af, pkts;
	int v = NF_DROP;
	int res_dir;

	af = (skb->protocol == htons(ETH_P_IP)) ? AF_INET : AF_INET6;

	ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);

	/*
	 *      Big tappo: only PACKET_HOST, including loopback for local client
	 *      Don't handle local packets on IPv6 for now
	 */
	if (unlikely(skb->pkt_type != PACKET_HOST)) {
		IP_VS_DBG_BUF(12, "packet type=%d proto=%d daddr=%s ignored\n",
			      skb->pkt_type,
			      iph.protocol, IP_VS_DBG_ADDR(af, &iph.daddr));
		return NF_ACCEPT;
	}
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6) {
		if (unlikely(iph.protocol == IPPROTO_ICMPV6)) {
			int related, verdict =
			    ip_vs_in_icmp_v6(skb, &related, hooknum);

			if (related)
				return verdict;
			ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);
		}
	} else
#endif
	if (unlikely(iph.protocol == IPPROTO_ICMP)) {
		int related, verdict = ip_vs_in_icmp(skb, &related, hooknum);

		if (related)
			return verdict;
		ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);
	}

	/* Protocol supported? */
	pp = ip_vs_proto_get(iph.protocol);
	if (unlikely(!pp))
		return NF_ACCEPT;

	/*
	 * Check if the packet belongs to an existing connection entry
	 */
	cp = pp->conn_in_get(af, skb, pp, &iph, iph.len, 0, &res_dir);

	if (likely(cp)) {
		/* For full-nat/local-client packets, it could be a response */
		if (res_dir == IP_VS_CIDX_F_IN2OUT) {
			return handle_response(af, skb, pp, cp, iph.len);
		}
	} else {
		/* create a new connection */
		int v;

		if (!pp->conn_schedule(af, skb, pp, &v, &cp))
			return v;
	}

	if (unlikely(!cp)) {
		/* sorry, all this trouble for a no-hit :) */
		IP_VS_DBG_PKT(12, pp, skb, 0,
			      "packet continues traversal as normal");
		return NF_ACCEPT;
	}

	IP_VS_DBG_PKT(11, pp, skb, 0, "Incoming packet");

	/* Check the server status */
	if (cp->dest && !(cp->dest->flags & IP_VS_DEST_F_AVAILABLE)) {
		/* the destination server is not available */

		if (sysctl_ip_vs_expire_nodest_conn) {
			/* try to expire the connection immediately */
			ip_vs_conn_expire_now(cp);
		}
		/* don't restart its timer, and silently
		   drop the packet. */
		__ip_vs_conn_put(cp);
		return NF_DROP;
	}

	ip_vs_in_stats(cp, skb);

	/*
	 * Filter out-in ack packet when cp is at SYN_SENT state.
	 * DROP it if not a valid packet, STORE it if we have 
	 * space left. 
	 */
	if ((cp->flags & IP_VS_CONN_F_SYNPROXY) &&
	    (0 == ip_vs_synproxy_filter_ack(skb, cp, pp, &iph, &v))) {
		ip_vs_conn_put(cp);
		return v;
	}

	/*
	 * "Reuse" syn-proxy sessions.
	 * "Reuse" means update syn_proxy_seq struct and clean ack_skb etc.
	 */
	if ((cp->flags & IP_VS_CONN_F_SYNPROXY) &&
	    (0 != sysctl_ip_vs_synproxy_conn_reuse)) {
		int v = NF_DROP;

		if (0 == ip_vs_synproxy_reuse_conn(af, skb, cp, pp, &iph, &v)) {
			ip_vs_conn_put(cp);
			return v;
		}
	}

	restart = ip_vs_set_state(cp, IP_VS_DIR_INPUT, skb, pp);
	if (cp->packet_xmit)
		ret = cp->packet_xmit(skb, cp, pp);
	/* do not touch skb anymore */
	else {
		IP_VS_DBG_RL("warning: packet_xmit is null");
		ret = NF_ACCEPT;
	}

	/* Increase its packet counter and check if it is needed
	 * to be synchronized
	 *
	 * Sync connection if it is about to close to
	 * encorage the standby servers to update the connections timeout
	 */
	pkts = atomic_add_return(1, &cp->in_pkts);
	if (af == AF_INET &&
	    (ip_vs_sync_state & IP_VS_STATE_MASTER) &&
	    (((cp->protocol != IPPROTO_TCP ||
	       cp->state == IP_VS_TCP_S_ESTABLISHED) &&
	      (pkts % sysctl_ip_vs_sync_threshold[1]
	       == sysctl_ip_vs_sync_threshold[0])) ||
	     ((cp->protocol == IPPROTO_TCP) && (cp->old_state != cp->state) &&
	      ((cp->state == IP_VS_TCP_S_FIN_WAIT) ||
	       (cp->state == IP_VS_TCP_S_CLOSE_WAIT) ||
	       (cp->state == IP_VS_TCP_S_TIME_WAIT)))))
		ip_vs_sync_conn(cp);
	cp->old_state = cp->state;

	ip_vs_conn_put(cp);
	return ret;
}

/*
 *	It is hooked at the NF_INET_FORWARD chain, in order to catch ICMP
 *      related packets destined for 0.0.0.0/0.
 *      When fwmark-based virtual service is used, such as transparent
 *      cache cluster, TCP packets can be marked and routed to ip_vs_in,
 *      but ICMP destined for 0.0.0.0/0 cannot not be easily marked and
 *      sent to ip_vs_in_icmp. So, catch them at the NF_INET_FORWARD chain
 *      and send them to ip_vs_in_icmp.
 */
static unsigned int
ip_vs_forward_icmp(unsigned int hooknum, struct sk_buff *skb,
		   const struct net_device *in, const struct net_device *out,
		   int (*okfn) (struct sk_buff *))
{
	int r;

	if (ip_hdr(skb)->protocol != IPPROTO_ICMP)
		return NF_ACCEPT;

	return ip_vs_in_icmp(skb, &r, hooknum);
}

#ifdef CONFIG_IP_VS_IPV6
static unsigned int
ip_vs_forward_icmp_v6(unsigned int hooknum, struct sk_buff *skb,
		      const struct net_device *in, const struct net_device *out,
		      int (*okfn) (struct sk_buff *))
{
	int r;

	if (ipv6_hdr(skb)->nexthdr != IPPROTO_ICMPV6)
		return NF_ACCEPT;

	return ip_vs_in_icmp_v6(skb, &r, hooknum);
}
#endif

#define IPPROTO_OSPF 89
static unsigned int
ip_vs_pre_routing(unsigned int hooknum, struct sk_buff *skb,
		  const struct net_device *in, const struct net_device *out,
		  int (*okfn) (struct sk_buff *))
{
	struct ip_vs_iphdr iph;
	int af;
	struct ip_vs_service *svc;

	af = (skb->protocol == htons(ETH_P_IP)) ? AF_INET : AF_INET6;

	ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);

	/* drop all ip fragment except ospf */
	if ((af == AF_INET)
	    && (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET))
	    && (iph.protocol != IPPROTO_OSPF)) {
		if(sysctl_ip_vs_frag_drop_entry == 1) {
			IP_VS_INC_ESTATS(ip_vs_esmib, DEFENCE_IP_FRAG_DROP);
			return NF_DROP;
		} else {
			if (ip_vs_gather_frags(skb, IP_DEFRAG_VS_IN))
				return NF_STOLEN;

			IP_VS_INC_ESTATS(ip_vs_esmib, DEFENCE_IP_FRAG_GATHER);
			ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);
		}
	}

	/* drop udp packet which send to tcp-vip */
	if ((sysctl_ip_vs_udp_drop_entry == 1) && (iph.protocol == IPPROTO_UDP)) {
		if ((svc =
		     ip_vs_lookup_vip(af, IPPROTO_TCP, &iph.daddr)) != NULL) {
			IP_VS_INC_ESTATS(ip_vs_esmib, DEFENCE_UDP_DROP);
			return NF_DROP;
		}
	}

	/* synproxy: defence synflood */
	if (iph.protocol == IPPROTO_TCP) {
		int v = NF_ACCEPT;
		if (0 == ip_vs_synproxy_syn_rcv(af, skb, &iph, &v)) {
			return v;
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops ip_vs_ops[] __read_mostly = {
	/* After packet filtering, forward packet through VS/DR, VS/TUN,
	 * or VS/NAT(change destination), so that filtering rules can be
	 * applied to IPVS. */
	{
	 .hook = ip_vs_in,
	 .owner = THIS_MODULE,
	 .pf = PF_INET,
	 .hooknum = NF_INET_PRE_ROUTING,
	 .priority = NF_IP_PRI_CONNTRACK - 1,
	 },
	/* After packet filtering, change source only for VS/NAT */
	{
	 .hook = ip_vs_out,
	 .owner = THIS_MODULE,
	 .pf = PF_INET,
	 .hooknum = NF_INET_FORWARD,
	 .priority = 100,
	 },
	/* After packet filtering (but before ip_vs_out_icmp), catch icmp
	 * destined for 0.0.0.0/0, which is for incoming IPVS connections */
	{
	 .hook = ip_vs_forward_icmp,
	 .owner = THIS_MODULE,
	 .pf = PF_INET,
	 .hooknum = NF_INET_FORWARD,
	 .priority = 99,
	 },
	/* Before the netfilter connection tracking, exit from POST_ROUTING */
	{
	 .hook = ip_vs_post_routing,
	 .owner = THIS_MODULE,
	 .pf = PF_INET,
	 .hooknum = NF_INET_POST_ROUTING,
	 .priority = NF_IP_PRI_NAT_SRC - 1,
	 },
	/* Before the netfilter connection tracking, only deal with FULLNAT/NAT-SynProxy */
	{
	 .hook = ip_vs_pre_routing,
	 .owner = THIS_MODULE,
	 .pf = PF_INET,
	 .hooknum = NF_INET_PRE_ROUTING,
	 .priority = NF_IP_PRI_CONNTRACK - 2,
	 },
#ifdef CONFIG_IP_VS_IPV6
	/* After packet filtering, forward packet through VS/DR, VS/TUN,
	 * or VS/NAT(change destination), so that filtering rules can be
	 * applied to IPVS. */
	{
	 .hook = ip_vs_in,
	 .owner = THIS_MODULE,
	 .pf = PF_INET6,
	 .hooknum = NF_INET_PRE_ROUTING,
	 .priority = NF_IP6_PRI_CONNTRACK - 1,
	 },
	/* After packet filtering, change source only for VS/NAT */
	{
	 .hook = ip_vs_out,
	 .owner = THIS_MODULE,
	 .pf = PF_INET6,
	 .hooknum = NF_INET_FORWARD,
	 .priority = 100,
	 },
	/* After packet filtering (but before ip_vs_out_icmp), catch icmp
	 * destined for 0.0.0.0/0, which is for incoming IPVS connections */
	{
	 .hook = ip_vs_forward_icmp_v6,
	 .owner = THIS_MODULE,
	 .pf = PF_INET6,
	 .hooknum = NF_INET_FORWARD,
	 .priority = 99,
	 },
	/* Before the netfilter connection tracking, exit from POST_ROUTING */
	{
	 .hook = ip_vs_post_routing,
	 .owner = THIS_MODULE,
	 .pf = PF_INET6,
	 .hooknum = NF_INET_POST_ROUTING,
	 .priority = NF_IP6_PRI_NAT_SRC - 1,
	 },
	/* Before the netfilter connection tracking, only deal with FULLNAT/NAT-SynProxy */
	{
	 .hook = ip_vs_pre_routing,
	 .owner = THIS_MODULE,
	 .pf = PF_INET6,
	 .hooknum = NF_INET_PRE_ROUTING,
	 .priority = NF_IP6_PRI_CONNTRACK - 2,
	 },
#endif
};

/*
 *	Initialize IP Virtual Server
 */
static int __init ip_vs_init(void)
{
	int ret;

	ret = ip_vs_control_init();
	if (ret < 0) {
		pr_err("can't setup control.\n");
		goto out_err;
	}

	ip_vs_protocol_init();

	ret = ip_vs_app_init();
	if (ret < 0) {
		pr_err("can't setup application helper.\n");
		goto cleanup_protocol;
	}

	ret = ip_vs_conn_init();
	if (ret < 0) {
		pr_err("can't setup connection table.\n");
		goto cleanup_app;
	}

	ret = nf_register_hooks(ip_vs_ops, ARRAY_SIZE(ip_vs_ops));
	if (ret < 0) {
		pr_err("can't register hooks.\n");
		goto cleanup_conn;
	}

	pr_info("ipvs loaded.\n");
	return ret;

cleanup_conn:
	ip_vs_conn_cleanup();
cleanup_app:
	ip_vs_app_cleanup();
cleanup_protocol:
	ip_vs_protocol_cleanup();
	ip_vs_control_cleanup();
out_err:
	return ret;
}

static void __exit ip_vs_cleanup(void)
{
	nf_unregister_hooks(ip_vs_ops, ARRAY_SIZE(ip_vs_ops));
	ip_vs_conn_cleanup();
	ip_vs_app_cleanup();
	ip_vs_protocol_cleanup();
	ip_vs_control_cleanup();
	pr_info("ipvs unloaded.\n");
}

module_init(ip_vs_init);
module_exit(ip_vs_cleanup);
MODULE_LICENSE("GPL");
