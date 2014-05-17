/*
 * ip_vs_xmit.c: various packet transmitters for IPVS
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Julian Anastasov <ja@ssi.bg>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Changes:
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/kernel.h>
#include <linux/tcp.h>		/* for tcphdr */
#include <net/ip.h>
#include <net/tcp.h>		/* for csum_tcpudp_magic */
#include <net/udp.h>
#include <net/icmp.h>		/* for icmp_send */
#include <net/route.h>		/* for ip_route_output */
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <linux/icmpv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include <net/ip_vs.h>
#include <linux/if_arp.h>

/*
 *      Destination cache to speed up outgoing route lookup
 */
static inline void
__ip_vs_dst_set(struct ip_vs_dest *dest, u32 rtos, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	old_dst = dest->dst_cache;
	dest->dst_cache = dst;
	dest->dst_rtos = rtos;
	dst_release(old_dst);
}

static inline struct dst_entry *__ip_vs_dst_check(struct ip_vs_dest *dest,
						  u32 rtos, u32 cookie)
{
	struct dst_entry *dst = dest->dst_cache;

	if (!dst)
		return NULL;
	if ((dst->obsolete
	     || (dest->af == AF_INET && rtos != dest->dst_rtos)) &&
	    dst->ops->check(dst, cookie) == NULL) {
		dest->dst_cache = NULL;
		dst_release(dst);
		return NULL;
	}
	dst_hold(dst);
	return dst;
}

static struct rtable *__ip_vs_get_out_rt(struct ip_vs_conn *cp, u32 rtos)
{
	struct rtable *rt;	/* Route to the other host */
	struct ip_vs_dest *dest = cp->dest;

	if (dest) {
		spin_lock(&dest->dst_lock);
		if (!(rt = (struct rtable *)
		      __ip_vs_dst_check(dest, rtos, 0))) {
			struct flowi fl = {
				.oif = 0,
				.nl_u = {
					 .ip4_u = {
						   .daddr = dest->addr.ip,
						   .saddr = 0,
						   .tos = rtos,}},
			};

			if (ip_route_output_key(&init_net, &rt, &fl)) {
				spin_unlock(&dest->dst_lock);
				IP_VS_DBG_RL
				    ("ip_route_output error, dest: %pI4\n",
				     &dest->addr.ip);
				return NULL;
			}
			__ip_vs_dst_set(dest, rtos, dst_clone(&rt->u.dst));
			IP_VS_DBG(10, "new dst %pI4, refcnt=%d, rtos=%X\n",
				  &dest->addr.ip,
				  atomic_read(&rt->u.dst.__refcnt), rtos);
		}
		spin_unlock(&dest->dst_lock);
	} else {
		struct flowi fl = {
			.oif = 0,
			.nl_u = {
				 .ip4_u = {
					   .daddr = cp->daddr.ip,
					   .saddr = 0,
					   .tos = rtos,}},
		};

		if (ip_route_output_key(&init_net, &rt, &fl)) {
			IP_VS_DBG_RL("ip_route_output error, dest: %pI4\n",
				     &cp->daddr.ip);
			return NULL;
		}
	}

	return rt;
}

static struct rtable *
__ip_vs_get_snat_out_rt(struct rtable *old_rt,
	struct ip_vs_conn *cp, u32 rtos)
{
	struct rtable *rt;	/* Route to the other host */
	struct ip_vs_dest *dest = cp->dest;
	struct ip_vs_dest_snat *rule = (struct ip_vs_dest_snat *)cp->dest;

	if (dest) {
		__be32 dst_ip = rule->new_gateway.ip?rule->new_gateway.ip:dest->addr.ip;

		if (old_rt &&
		    (old_rt->rt_gateway == rule->new_gateway.ip ||
		    rule->new_gateway.ip == 0))
			return old_rt;

		if (!dst_ip)
			dst_ip = cp->vaddr.ip;

		spin_lock(&dest->dst_lock);
		if (!(rt = (struct rtable *)
		      __ip_vs_dst_check(dest, rtos, 0))) {
			struct flowi fl = {
				.oif = 0,
				.nl_u = {
					 .ip4_u = {
						   .daddr = dst_ip,
						   .saddr = 0,
						   .tos = rtos,}},
			};

			if (ip_route_output_key(&init_net, &rt, &fl)) {
				spin_unlock(&dest->dst_lock);
				IP_VS_DBG_RL
				    ("ip_route_output error, dest: %pI4\n",
				     &dest->addr.ip);
				return NULL;
			}
			__ip_vs_dst_set(dest, rtos, dst_clone(&rt->u.dst));
			IP_VS_DBG(10, "SNAT old dst %pI4 new dst %pI4, refcnt=%d, rtos=%X\n",
				  old_rt?&old_rt->rt_gateway:0,
				  &rt->rt_gateway,
				  atomic_read(&rt->u.dst.__refcnt), rtos);
		}
		spin_unlock(&dest->dst_lock);
	} else {
		struct flowi fl = {
			.oif = 0,
			.nl_u = {
				 .ip4_u = {
					   .daddr = cp->daddr.ip,
					   .saddr = 0,
					   .tos = rtos,}},
		};

		if (old_rt)
			return old_rt;

		if (ip_route_output_key(&init_net, &rt, &fl)) {
			IP_VS_DBG_RL("ip_route_output error, dest: %pI4\n",
				     &cp->daddr.ip);
			return NULL;
		}
	}

	return rt;
}

struct rtable *ip_vs_get_rt(union nf_inet_addr *addr, u32 rtos)
{
	struct rtable *rt;	/* Route to the other host */

	struct flowi fl = {
		.oif = 0,
		.nl_u = {
			 .ip4_u = {
				   .daddr = addr->ip,
				   .saddr = 0,
				   .tos = rtos,}},
	};

	if (ip_route_output_key(&init_net, &rt, &fl)) {
		IP_VS_DBG_RL("ip_route_output error, dest: %pI4\n", &addr->ip);
		return NULL;
	}

	return rt;
}

#ifdef CONFIG_IP_VS_IPV6
static struct rt6_info *__ip_vs_get_out_rt_v6(struct ip_vs_conn *cp)
{
	struct rt6_info *rt;	/* Route to the other host */
	struct ip_vs_dest *dest = cp->dest;

	if (dest) {
		spin_lock(&dest->dst_lock);
		rt = (struct rt6_info *)__ip_vs_dst_check(dest, 0, 0);
		if (!rt) {
			struct flowi fl = {
				.oif = 0,
				.nl_u = {
					 .ip6_u = {
						   .daddr = dest->addr.in6,
						   .saddr = {
							     .s6_addr32 =
							     {0, 0, 0, 0},
							     },
						   },
					 },
			};

			rt = (struct rt6_info *)ip6_route_output(&init_net,
								 NULL, &fl);
			if (!rt) {
				spin_unlock(&dest->dst_lock);
				IP_VS_DBG_RL
				    ("ip6_route_output error, dest: %pI6\n",
				     &dest->addr.in6);
				return NULL;
			}
			__ip_vs_dst_set(dest, 0, dst_clone(&rt->u.dst));
			IP_VS_DBG(10, "new dst %pI6, refcnt=%d\n",
				  &dest->addr.in6,
				  atomic_read(&rt->u.dst.__refcnt));
		}
		spin_unlock(&dest->dst_lock);
	} else {
		struct flowi fl = {
			.oif = 0,
			.nl_u = {
				 .ip6_u = {
					   .daddr = cp->daddr.in6,
					   .saddr = {
						     .s6_addr32 = {0, 0, 0, 0},
						     },
					   },
				 },
		};

		rt = (struct rt6_info *)ip6_route_output(&init_net, NULL, &fl);
		if (!rt) {
			IP_VS_DBG_RL("ip6_route_output error, dest: %pI6\n",
				     &cp->daddr.in6);
			return NULL;
		}
	}

	return rt;
}

struct rt6_info *ip_vs_get_rt_v6(union nf_inet_addr *addr)
{
	struct rt6_info *rt;	/* Route to the other host */

	struct flowi fl = {
		.oif = 0,
		.nl_u = {
			 .ip6_u = {
				   .daddr = addr->in6,
				   .saddr = {
					     .s6_addr32 = {0, 0, 0, 0},
					     },
				   },
			 },
	};

	rt = (struct rt6_info *)ip6_route_output(&init_net, NULL, &fl);
	if (!rt) {
		IP_VS_DBG_RL("ip6_route_output error, dest: %pI6\n",
			     &addr->in6);
		return NULL;
	}

	return rt;
}
#endif

/*
 *	Release dest->dst_cache before a dest is removed
 */
void ip_vs_dst_reset(struct ip_vs_dest *dest)
{
	struct dst_entry *old_dst;

	old_dst = dest->dst_cache;
	dest->dst_cache = NULL;
	dst_release(old_dst);
}

#define IP_VS_XMIT(pf, skb, rt)				\
do {							\
	(skb)->ipvs_property = 1;			\
	skb_forward_csum(skb);				\
	NF_HOOK(pf, NF_INET_LOCAL_OUT, (skb), NULL,	\
		(rt)->u.dst.dev, dst_output);		\
} while (0)

/* check if gso can handle the skb */
static int gso_ok(struct sk_buff *skb, struct net_device *dev)
{
	if (skb_is_gso(skb)) {
		/* LRO check */
		if (unlikely(skb_shinfo(skb)->gso_type == 0)) {
			IP_VS_ERR_RL("%s:LRO is enabled."
					"Cannot be forwarded\n", dev->name);
			IP_VS_INC_ESTATS(ip_vs_esmib, LRO_REJECT);
			goto gso_err;
		}

		/* GRO check */
		if (net_gso_ok(dev->features, skb_shinfo(skb)->gso_type)) {
			/* the skb has frag_list, need do sth here */
			if (skb_has_frags(skb) &&
					!(dev->features & NETIF_F_FRAGLIST) &&
							__skb_linearize(skb))
				goto gso_err;

			IP_VS_DBG_RL("skb length: %d . GSO is ok."
					"can be forwarded\n", skb->len);
			IP_VS_INC_ESTATS(ip_vs_esmib, GRO_PASS);
			goto gso_ok;
		}
	}

gso_err:
	return 0;
gso_ok:
	return 1;
}

/*
 * Packet has been made sufficiently writable in caller
 * - inout: 1=in->out, 0=out->in
 */
static void ip_vs_nat_icmp(struct sk_buff *skb, struct ip_vs_protocol *pp,
			   struct ip_vs_conn *cp, int inout)
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned int icmp_offset = iph->ihl * 4;
	struct icmphdr *icmph = (struct icmphdr *)(skb_network_header(skb) +
						   icmp_offset);
	struct iphdr *ciph = (struct iphdr *)(icmph + 1);
	__u32 fullnat = (IP_VS_FWD_METHOD(cp) == IP_VS_CONN_F_FULLNAT);

	if (fullnat) {
		if (inout) {
			iph->daddr = cp->caddr.ip;
			ciph->saddr = cp->caddr.ip;
		} else {
			iph->saddr = cp->laddr.ip;
			ciph->daddr = cp->laddr.ip;
		}
	}

	if (inout) {
		if (NOT_SNAT_CP(cp))
		iph->saddr = cp->vaddr.ip;
		ip_send_check(iph);
		ciph->daddr = cp->vaddr.ip;
		ip_send_check(ciph);
	} else {
		iph->daddr = cp->daddr.ip;
		ip_send_check(iph);
		ciph->saddr = cp->daddr.ip;
		ip_send_check(ciph);
	}

	/* the TCP/UDP port */
	if (IPPROTO_TCP == ciph->protocol || IPPROTO_UDP == ciph->protocol) {
		__be16 *ports = (void *)ciph + ciph->ihl * 4;

		if (fullnat) {
			if (inout) {
				ports[0] = cp->cport;
				/* The seq of packet form client
				 *  has been changed by fullnat.
				 * we must fix here to
				 * ensure a valid icmp PKT */
				if (IPPROTO_TCP == ciph->protocol) {
					__be32 *seqs = (__be32 *)ports;
					seqs[1] = htonl(ntohl(seqs[1]) -
							cp->fnat_seq.delta);
				}
			} else
				ports[1] = cp->lport;
		}

		if (inout)
			ports[1] = cp->vport;
		else {
			ports[0] = cp->dport;
			/* synproxy may modify the seq of packet form RS.
			 * we fix here to ensure a valid icmp PKT*/
			if (IPPROTO_TCP == ciph->protocol) {
				__be32 *seqs = (__be32 *)ports;
				seqs[1] = htonl(ntohl(seqs[1]) -
						cp->syn_proxy_seq.delta);
			}
		}
	}

	/* And finally the ICMP checksum */
	icmph->checksum = 0;
	icmph->checksum = ip_vs_checksum_complete(skb, icmp_offset);
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (inout)
		IP_VS_DBG_PKT(11, pp, skb, (void *)ciph - (void *)iph,
			      "Forwarding altered outgoing ICMP");
	else
		IP_VS_DBG_PKT(11, pp, skb, (void *)ciph - (void *)iph,
			      "Forwarding altered incoming ICMP");
}

#ifdef CONFIG_IP_VS_IPV6
static void ip_vs_nat_icmp_v6(struct sk_buff *skb, struct ip_vs_protocol *pp,
			      struct ip_vs_conn *cp, int inout)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	unsigned int icmp_offset = sizeof(struct ipv6hdr);
	struct icmp6hdr *icmph = (struct icmp6hdr *)(skb_network_header(skb) +
						     icmp_offset);
	struct ipv6hdr *ciph = (struct ipv6hdr *)(icmph + 1);
	__u32 fullnat = (IP_VS_FWD_METHOD(cp) == IP_VS_CONN_F_FULLNAT);

	if (fullnat) {
		if (inout) {
			iph->daddr = cp->caddr.in6;
			ciph->saddr = cp->caddr.in6;
		} else {
			iph->saddr = cp->laddr.in6;
			ciph->daddr = cp->laddr.in6;
		}
	}

	if (inout) {
		iph->saddr = cp->vaddr.in6;
		ciph->daddr = cp->vaddr.in6;
	} else {
		iph->daddr = cp->daddr.in6;
		ciph->saddr = cp->daddr.in6;
	}

	/* the TCP/UDP port */
	if (IPPROTO_TCP == ciph->nexthdr || IPPROTO_UDP == ciph->nexthdr) {
		__be16 *ports = (void *)ciph + sizeof(struct ipv6hdr);

		if (fullnat) {
			if (inout) {
				ports[0] = cp->cport;
				if (IPPROTO_TCP == ciph->nexthdr) {
					__be32 *seqs = (__be32 *)ports;
					seqs[1] = htonl(ntohl(seqs[1]) -
							cp->fnat_seq.delta);
				}
			} else
				ports[1] = cp->lport;
		}

		if (inout)
			ports[1] = cp->vport;
		else {
			ports[0] = cp->dport;
			if (IPPROTO_TCP == ciph->nexthdr) {
				__be32 *seqs = (__be32 *)ports;
				seqs[1] = htonl(ntohl(seqs[1]) -
						cp->syn_proxy_seq.delta);
			}
		}
	}

	/* And finally the ICMP checksum */
	icmph->icmp6_cksum = 0;
	/* TODO IPv6: is this correct for ICMPv6? */
	ip_vs_checksum_complete(skb, icmp_offset);
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (inout)
		IP_VS_DBG_PKT(11, pp, skb, (void *)ciph - (void *)iph,
			      "Forwarding altered outgoing ICMPv6");
	else
		IP_VS_DBG_PKT(11, pp, skb, (void *)ciph - (void *)iph,
			      "Forwarding altered incoming ICMPv6");
}
#endif

/* Response transmit icmp to client
 * Used for NAT/LOCAL.
 */
int
ip_vs_normal_response_icmp_xmit(struct sk_buff *skb, struct ip_vs_protocol *pp,
				struct ip_vs_conn *cp, int offset)
{
	struct rtable *rt;	/* Route to the other host */
	int mtu;
	struct iphdr *iph = ip_hdr(skb);

	if (!skb_make_writable(skb, offset))
		goto out;

	/* lookup route table */
	if (!(rt = ip_vs_get_rt(&cp->caddr, RT_TOS(iph->tos))))
		goto out;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if ((skb->len > mtu) && (iph->frag_off & htons(IP_DF))) {
		ip_rt_put(rt);
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "nat_response_icmp(): frag needed for");
		goto out;
	}

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto error_put;

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	ip_vs_nat_icmp(skb, pp, cp, 1);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET, skb, rt);

	return NF_STOLEN;

error_put:
	ip_rt_put(rt);
out:
	return NF_DROP;
}

#ifdef CONFIG_IP_VS_IPV6

int
ip_vs_normal_response_icmp_xmit_v6(struct sk_buff *skb,
				   struct ip_vs_protocol *pp,
				   struct ip_vs_conn *cp, int offset)
{
	struct rt6_info *rt;	/* Route to the other host */
	int mtu;

	if (!skb_make_writable(skb, offset))
		goto out;

	/* lookup route table */
	if (!(rt = ip_vs_get_rt_v6(&cp->caddr)))
		goto out;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (skb->len > mtu) {
		dst_release(&rt->u.dst);
		IP_VS_DBG_RL("%s(): frag needed\n", __func__);
		goto out;
	}

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto error_put;

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	ip_vs_nat_icmp_v6(skb, pp, cp, 1);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET6, skb, rt);

	return NF_STOLEN;

error_put:
	dst_release(&rt->u.dst);
out:
	return NF_DROP;
}

#endif

/* Response transmit icmp to client
 * Used for NAT / local client / FULLNAT.
 */
int
ip_vs_fnat_response_icmp_xmit(struct sk_buff *skb, struct ip_vs_protocol *pp,
			      struct ip_vs_conn *cp, int offset)
{
	struct rtable *rt;	/* Route to the other host */
	int mtu;
	struct iphdr *iph = ip_hdr(skb);

	/* lookup route table */
	if (!(rt = ip_vs_get_rt(&cp->caddr, RT_TOS(iph->tos))))
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if ((skb->len > mtu) && (iph->frag_off & htons(IP_DF))) {
		ip_rt_put(rt);
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "fnat_response_icmp(): frag needed for");
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, offset))
		goto tx_error_put;

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	ip_vs_nat_icmp(skb, pp, cp, 1);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET, skb, rt);

	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	kfree_skb(skb);
	return NF_STOLEN;
      tx_error_put:
	ip_rt_put(rt);
	goto tx_error;
}

#ifdef CONFIG_IP_VS_IPV6

int
ip_vs_fnat_response_icmp_xmit_v6(struct sk_buff *skb, struct ip_vs_protocol *pp,
				 struct ip_vs_conn *cp, int offset)
{
	struct rt6_info *rt;	/* Route to the other host */
	int mtu;

	/* lookup route table */
	if (!(rt = ip_vs_get_rt_v6(&cp->caddr)))
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (skb->len > mtu) {
		dst_release(&rt->u.dst);
		IP_VS_DBG_RL("%s(): frag needed\n", __func__);
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, offset))
		goto tx_error_put;

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	ip_vs_nat_icmp_v6(skb, pp, cp, 1);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET6, skb, rt);

	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	kfree_skb(skb);
	return NF_STOLEN;
      tx_error_put:
	dst_release(&rt->u.dst);
	goto tx_error;
}

#endif

/* just for nat/fullnat mode */
int
ip_vs_fast_response_xmit(struct sk_buff *skb, struct ip_vs_protocol *pp,
						struct ip_vs_conn *cp)
{
	int ret;
	struct ethhdr *eth;

	if (!cp->indev)
		goto err;
	if (!gso_ok(skb, cp->indev) && (skb->len > cp->indev->mtu))
		goto err;

	/* Try to reuse skb */
	if (unlikely(skb_shared(skb) || skb_cloned(skb))) {
		struct sk_buff *new_skb = skb_copy(skb, GFP_ATOMIC);
		if(unlikely(new_skb == NULL))
			goto err;

		/* Drop old skb */
		kfree_skb(skb);
		skb = new_skb;
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_SKB_COPY);
	}

	/* change ip, port. */
	if (cp->flags & IP_VS_CONN_F_FULLNAT) {
		if (pp->fnat_out_handler && !pp->fnat_out_handler(skb, pp, cp))
			goto err;

		ip_hdr(skb)->saddr = cp->vaddr.ip;
		ip_hdr(skb)->daddr = cp->caddr.ip;
	} else {
	/*
		IP_VS_ERR_RL("L2 fast xmit support fullnat only!\n");
		goto err;
	*/
		if (pp->snat_handler && !pp->snat_handler(skb, pp, cp))
			goto err;

		ip_hdr(skb)->saddr = cp->vaddr.ip;
	}

	ip_send_check(ip_hdr(skb));

	skb->dev = cp->indev;

	if(unlikely(skb_headroom(skb) < LL_RESERVED_SPACE(skb->dev))){
		struct sk_buff *skb2;

		IP_VS_ERR_RL("need more headroom! realloc skb\n");
		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(skb->dev));
		if (skb2 == NULL)
			goto err;
		kfree_skb(skb);
		skb = skb2;
	}

	if(likely(skb_mac_header_was_set(skb))) {
		eth = eth_hdr(skb);
		memcpy(eth->h_dest, cp->src_hwaddr, ETH_ALEN);
		memcpy(eth->h_source, cp->dst_hwaddr, ETH_ALEN);
		skb->data = (unsigned char *)eth_hdr(skb);
		skb->len += sizeof(struct ethhdr);
	} else {
		eth = (struct ethhdr *)skb_push(skb, sizeof(struct ethhdr));
		skb_reset_mac_header(skb);
		memcpy(eth->h_dest, cp->src_hwaddr, ETH_ALEN);
		memcpy(eth->h_source, cp->dst_hwaddr, ETH_ALEN);
	}
	skb->protocol = eth->h_proto = htons(ETH_P_IP);
	skb->pkt_type = PACKET_OUTGOING;

	IP_VS_DBG_RL("%s: send skb to client!\n", __func__);

	/* Send the packet out */
	ret = dev_queue_xmit(skb);
	if (ret != 0) {
		IP_VS_DBG_RL("dev_queue_xmit failed! code:%d\n", ret);
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_FAILED);
		return 0;
	}

	IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_PASS);
	return 0;
err:
	IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_REJECT);
	return 1;
}

#ifdef CONFIG_IP_VS_IPV6
/* just for nat/fullnat mode */
int
ip_vs_fast_response_xmit_v6(struct sk_buff *skb, struct ip_vs_protocol *pp,
						struct ip_vs_conn *cp)
{
	int ret;
	struct ethhdr *eth;

	if (!cp->indev)
		goto err;
	if (!gso_ok(skb, cp->indev) && (skb->len > cp->indev->mtu))
		goto err;

	/* Try to reuse skb if possible */
	if (unlikely(skb_shared(skb) || skb_cloned(skb))) {
		struct sk_buff *new_skb = skb_copy(skb, GFP_ATOMIC);
		if(unlikely(new_skb == NULL))
			goto err;

		/* Drop old skb */
		kfree_skb(skb);
		skb = new_skb;
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_SKB_COPY);
	}

	/* change ip, port. */
	if (cp->flags & IP_VS_CONN_F_FULLNAT) {
		if (pp->fnat_out_handler && !pp->fnat_out_handler(skb, pp, cp))
			goto err;

		ipv6_hdr(skb)->saddr = cp->vaddr.in6;
		ipv6_hdr(skb)->daddr = cp->caddr.in6;
	} else {
		IP_VS_ERR_RL("L2 fast xmit support fullnat only!\n");
		goto err;
		/*if (pp->snat_handler && !pp->snat_handler(skb, pp, cp))
			goto err;

		ipv6_hdr(skb)->saddr = cp->vaddr.in6;*/
	}

	skb->dev = cp->indev;

	if(unlikely(skb_headroom(skb) < LL_RESERVED_SPACE(skb->dev))){
		struct sk_buff *skb2;

		IP_VS_ERR_RL("need more headroom! realloc skb\n");
		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(skb->dev));
		if (skb2 == NULL)
			goto err;
		kfree_skb(skb);
		skb = skb2;
	}

	if(likely(skb_mac_header_was_set(skb))) {
		eth = eth_hdr(skb);
		memcpy(eth->h_dest, cp->src_hwaddr, ETH_ALEN);
		memcpy(eth->h_source, cp->dst_hwaddr, ETH_ALEN);
		skb->data = (unsigned char *)eth_hdr(skb);
		skb->len += sizeof(struct ethhdr);
	} else {
		eth = (struct ethhdr *)skb_push(skb, sizeof(struct ethhdr));
		skb_reset_mac_header(skb);
		memcpy(eth->h_dest, cp->src_hwaddr, ETH_ALEN);
		memcpy(eth->h_source, cp->dst_hwaddr, ETH_ALEN);
	}
	skb->protocol = eth->h_proto = htons(ETH_P_IPV6);
	skb->pkt_type = PACKET_OUTGOING;

	IP_VS_DBG_RL("%s: send skb to client!\n", __func__);
	/* Send the packet out */
	ret = dev_queue_xmit(skb);
	if (ret != 0) {
		IP_VS_DBG_RL("dev_queue_xmit failed! code:%d\n", ret);
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_FAILED);
		return 0;
	}

	IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_PASS);
	return 0;
err:
	IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_REJECT);
	return 1;
}
#endif

static inline void
ip_vs_save_xmit_inside_info(struct sk_buff *skb, struct ip_vs_conn *cp)
{
	if(!sysctl_ip_vs_fast_xmit_inside)
		return;

	if(!skb->dev) {
		IP_VS_DBG_RL("%s(): skb->dev is NULL. \n", __func__);
		return;
	}
	IP_VS_DBG_RL("%s(): netdevice:%s\n", netdev_name(skb->dev), __func__);

	if(likely((skb->dev->type == ARPHRD_ETHER) &&
					skb_mac_header_was_set(skb))) {
		struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);

		if(unlikely(cp->dev_inside == NULL)) {
			cp->dev_inside = skb->dev;
			dev_hold(cp->dev_inside);
		}

		if (unlikely(cp->dev_inside != skb->dev)) {
			dev_put(cp->dev_inside);
			cp->dev_inside = skb->dev;
			dev_hold(cp->dev_inside);
		}

		memcpy(cp->src_hwaddr_inside, eth->h_source, ETH_ALEN);
		memcpy(cp->dst_hwaddr_inside, eth->h_dest, ETH_ALEN);
	} else {
		IP_VS_DBG_RL("%s():save dev and mac failed!\n", __func__);
	}
}

/* Response transmit to client
 * Used for NAT/Local.
 */
int
ip_vs_normal_response_xmit(struct sk_buff *skb, struct ip_vs_protocol *pp,
			   struct ip_vs_conn *cp, int ihl)
{
	struct rtable *rt;
	int mtu;

	ip_vs_save_xmit_inside_info(skb, cp);

	if(sysctl_ip_vs_fast_xmit && !ip_vs_fast_response_xmit(skb, pp, cp))
		return NF_STOLEN; 

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, ihl))
		goto drop;

	/* mangle the packet */
	if (pp->snat_handler && !pp->snat_handler(skb, pp, cp))
		goto drop;

	ip_hdr(skb)->saddr = cp->vaddr.ip;
	ip_send_check(ip_hdr(skb));

	/* For policy routing, packets originating from this
	 * machine itself may be routed differently to packets
	 * passing through.  We want this packet to be routed as
	 * if it came from this machine itself.  So re-compute
	 * the routing information.
	 */
//	if (ip_route_me_harder(skb, RTN_LOCAL) != 0)
//		goto drop;

	/* lookup route table */
	if(!(rt = ip_vs_get_rt(&cp->caddr, RT_TOS(ip_hdr(skb)->tos))))
		goto drop;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if ((skb->len > mtu) && (ip_hdr(skb)->frag_off & htons(IP_DF))) {
		ip_rt_put(rt);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "handle_nat_response(): frag needed for");
		goto drop;
	}

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len)) {
		ip_rt_put(rt);
		goto drop;
	}

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET, skb, rt);

	return NF_STOLEN;

drop:
	kfree_skb(skb);
	return NF_STOLEN;
}

#ifdef CONFIG_IP_VS_IPV6

int
ip_vs_normal_response_xmit_v6(struct sk_buff *skb, struct ip_vs_protocol *pp,
			      struct ip_vs_conn *cp, int ihl)
{
	struct rt6_info *rt;
	int mtu;

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, ihl))
		goto drop;

	/* mangle the packet */
	if (pp->snat_handler && !pp->snat_handler(skb, pp, cp))
		goto drop;

	ipv6_hdr(skb)->saddr = cp->vaddr.in6;

	/* For policy routing, packets originating from this
	 * machine itself may be routed differently to packets
	 * passing through.  We want this packet to be routed as
	 * if it came from this machine itself.  So re-compute
	 * the routing information.
	 */
//	if (ip6_route_me_harder(skb) != 0)
//		goto drop;

	/* lookup route table */
	if (!(rt = ip_vs_get_rt_v6(&cp->caddr)))
		goto drop;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (skb->len > mtu) {
		dst_release(&rt->u.dst);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, skb->dev);
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "handle_fnat_response_v6(): frag needed for");
		goto drop;
	}

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len)) {
		dst_release(&rt->u.dst);
		goto drop;
	}

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET6, skb, rt);

	return NF_STOLEN;

drop:
	kfree_skb(skb);
	return NF_STOLEN;
}

#endif

/* Response transmit to client
 * Used for FULLNAT.
 */
int
ip_vs_fnat_response_xmit(struct sk_buff *skb, struct ip_vs_protocol *pp,
			 struct ip_vs_conn *cp, int ihl)
{
	struct rtable *rt;	/* Route to the other host */
	int mtu;
	struct iphdr *iph = ip_hdr(skb);

	ip_vs_save_xmit_inside_info(skb, cp);

	if(sysctl_ip_vs_fast_xmit && !ip_vs_fast_response_xmit(skb, pp, cp))
		return NF_STOLEN;

	/* lookup route table */
	if (!(rt = ip_vs_get_rt(&cp->caddr, RT_TOS(iph->tos))))
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (!gso_ok(skb, rt->u.dst.dev) && (skb->len > mtu) &&
					(iph->frag_off & htons(IP_DF))) {
		ip_rt_put(rt);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "handle_fnat_response(): frag needed for");
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, ihl))
		goto tx_error_put;

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* mangle the packet */
	if (pp->fnat_out_handler && !pp->fnat_out_handler(skb, pp, cp))
		goto tx_error;

	ip_hdr(skb)->saddr = cp->vaddr.ip;
	ip_hdr(skb)->daddr = cp->caddr.ip;
	ip_send_check(ip_hdr(skb));

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET, skb, rt);

	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	kfree_skb(skb);
	return NF_STOLEN;
      tx_error_put:
	ip_rt_put(rt);
	goto tx_error;
}

#ifdef CONFIG_IP_VS_IPV6

int
ip_vs_fnat_response_xmit_v6(struct sk_buff *skb, struct ip_vs_protocol *pp,
			    struct ip_vs_conn *cp, int ihl)
{
	struct rt6_info *rt;	/* Route to the other host */
	int mtu;

	ip_vs_save_xmit_inside_info(skb, cp);

	if(sysctl_ip_vs_fast_xmit && !ip_vs_fast_response_xmit_v6(skb, pp, cp))
		return NF_STOLEN;

	/* lookup route table */
	if (!(rt = ip_vs_get_rt_v6(&cp->caddr)))
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (!gso_ok(skb, rt->u.dst.dev) && (skb->len > mtu)) {
		dst_release(&rt->u.dst);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, skb->dev);
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "handle_fnat_response_v6(): frag needed for");
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, ihl))
		goto tx_error_put;

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* mangle the packet */
	if (pp->fnat_out_handler && !pp->fnat_out_handler(skb, pp, cp))
		goto tx_error;

	ipv6_hdr(skb)->saddr = cp->vaddr.in6;
	ipv6_hdr(skb)->daddr = cp->caddr.in6;

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET6, skb, rt);

	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	kfree_skb(skb);
	return NF_STOLEN;
      tx_error_put:
	dst_release(&rt->u.dst);
	goto tx_error;
}

#endif

/*
 *      NULL transmitter (do nothing except return NF_ACCEPT)
 */
int
ip_vs_null_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		struct ip_vs_protocol *pp)
{
	/* we do not touch skb and do not need pskb ptr */
	return NF_ACCEPT;
}

/*
 *      Bypass transmitter
 *      Let packets bypass the destination when the destination is not
 *      available, it may be only used in transparent cache cluster.
 */
int
ip_vs_bypass_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		  struct ip_vs_protocol *pp)
{
	struct rtable *rt;	/* Route to the other host */
	struct iphdr *iph = ip_hdr(skb);
	u8 tos = iph->tos;
	int mtu;
	struct flowi fl = {
		.oif = 0,
		.nl_u = {
			 .ip4_u = {
				   .daddr = iph->daddr,
				   .saddr = 0,
				   .tos = RT_TOS(tos),}},
	};

	EnterFunction(10);

	if (ip_route_output_key(&init_net, &rt, &fl)) {
		IP_VS_DBG_RL("%s(): ip_route_output error, dest: %pI4\n",
			     __func__, &iph->daddr);
		goto tx_error_icmp;
	}

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if ((skb->len > mtu) && (iph->frag_off & htons(IP_DF))) {
		ip_rt_put(rt);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		IP_VS_DBG_RL("%s(): frag needed\n", __func__);
		goto tx_error;
	}

	/*
	 * Call ip_send_check because we are not sure it is called
	 * after ip_defrag. Is copy-on-write needed?
	 */
	if (unlikely((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)) {
		ip_rt_put(rt);
		return NF_STOLEN;
	}
	ip_send_check(ip_hdr(skb));

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET, skb, rt);

	LeaveFunction(10);
	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	kfree_skb(skb);
	LeaveFunction(10);
	return NF_STOLEN;
}

#ifdef CONFIG_IP_VS_IPV6
int
ip_vs_bypass_xmit_v6(struct sk_buff *skb, struct ip_vs_conn *cp,
		     struct ip_vs_protocol *pp)
{
	struct rt6_info *rt;	/* Route to the other host */
	struct ipv6hdr *iph = ipv6_hdr(skb);
	int mtu;
	struct flowi fl = {
		.oif = 0,
		.nl_u = {
			 .ip6_u = {
				   .daddr = iph->daddr,
				   .saddr = {.s6_addr32 = {0, 0, 0, 0}},}},
	};

	EnterFunction(10);

	rt = (struct rt6_info *)ip6_route_output(&init_net, NULL, &fl);
	if (!rt) {
		IP_VS_DBG_RL("%s(): ip6_route_output error, dest: %pI6\n",
			     __func__, &iph->daddr);
		goto tx_error_icmp;
	}

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (skb->len > mtu) {
		dst_release(&rt->u.dst);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, skb->dev);
		IP_VS_DBG_RL("%s(): frag needed\n", __func__);
		goto tx_error;
	}

	/*
	 * Call ip_send_check because we are not sure it is called
	 * after ip_defrag. Is copy-on-write needed?
	 */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(skb == NULL)) {
		dst_release(&rt->u.dst);
		return NF_STOLEN;
	}

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET6, skb, rt);

	LeaveFunction(10);
	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	kfree_skb(skb);
	LeaveFunction(10);
	return NF_STOLEN;
}
#endif

/* fullnat mode */
int
ip_vs_fast_xmit(struct sk_buff *skb, struct ip_vs_protocol *pp,
						struct ip_vs_conn *cp)
{
	int ret;
	struct ethhdr *eth;

	if (!cp->dev_inside)
		goto err;
	if (!gso_ok(skb, cp->dev_inside) && (skb->len > cp->dev_inside->mtu))
		goto err;

	/* Try to reuse skb */
	if (unlikely(skb_shared(skb) || skb_cloned(skb))) {
		struct sk_buff *new_skb = skb_copy(skb, GFP_ATOMIC);
		if(unlikely(new_skb == NULL))
			goto err;

		/* Drop old skb */
		kfree_skb(skb);
		skb = new_skb;
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_SKB_COPY);
	}

	/* change ip, port. */
	if ((cp->flags & IP_VS_CONN_F_FWD_MASK) == IP_VS_CONN_F_FULLNAT) {
		if (pp->fnat_in_handler && !pp->fnat_in_handler(&skb, pp, cp))
			goto err;

		ip_hdr(skb)->saddr = cp->laddr.ip;
		ip_hdr(skb)->daddr = cp->daddr.ip;
	} else {
	/*
		IP_VS_ERR_RL("L2 fast xmit support fullnat only!\n");
		goto err;
	*/
		if (pp->dnat_handler && !pp->dnat_handler(skb, pp, cp))
			goto err;

		ip_hdr(skb)->daddr = cp->daddr.ip;
	}

	ip_send_check(ip_hdr(skb));

	skb->dev = cp->dev_inside;

	if(unlikely(skb_headroom(skb) < LL_RESERVED_SPACE(skb->dev))){
		struct sk_buff *skb2;

		IP_VS_ERR_RL("need more headroom! realloc skb\n");
		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(skb->dev));
		if (skb2 == NULL)
			goto err;
		kfree_skb(skb);
		skb = skb2;
	}

	if(likely(skb_mac_header_was_set(skb))) {
		eth = eth_hdr(skb);
		memcpy(eth->h_dest, cp->src_hwaddr_inside, ETH_ALEN);
		memcpy(eth->h_source, cp->dst_hwaddr_inside, ETH_ALEN);
		skb->data = (unsigned char *)eth_hdr(skb);
		skb->len += sizeof(struct ethhdr);
	} else {
		eth = (struct ethhdr *)skb_push(skb, sizeof(struct ethhdr));
		skb_reset_mac_header(skb);
		memcpy(eth->h_dest, cp->src_hwaddr_inside, ETH_ALEN);
		memcpy(eth->h_source, cp->dst_hwaddr_inside, ETH_ALEN);
	}
	skb->protocol = eth->h_proto = htons(ETH_P_IP);
	skb->pkt_type = PACKET_OUTGOING;

	IP_VS_DBG_RL("%s: send skb to RS!\n", __func__);
	/* Send the packet out */
	ret = dev_queue_xmit(skb);
	if (ret != 0) {
		IP_VS_DBG_RL("dev_queue_xmit failed! code:%d\n", ret);
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_FAILED_INSIDE);
		return 0;
	}

	IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_PASS_INSIDE);
	return 0;
err:
	IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_REJECT_INSIDE);
	return 1;
}

#ifdef CONFIG_IP_VS_IPV6
/* just for fullnat mode */
int
ip_vs_fast_xmit_v6(struct sk_buff *skb, struct ip_vs_protocol *pp,
						struct ip_vs_conn *cp)
{
	int ret;
	struct ethhdr *eth;

	if (!cp->dev_inside)
		goto err;
	if (!gso_ok(skb, cp->dev_inside) && (skb->len > cp->dev_inside->mtu))
		goto err;

	/* Try to reuse skb if possible */
	if (unlikely(skb_shared(skb) || skb_cloned(skb))) {
		struct sk_buff *new_skb = skb_copy(skb, GFP_ATOMIC);
		if(unlikely(new_skb == NULL))
			goto err;

		/* Drop old skb */
		kfree_skb(skb);
		skb = new_skb;
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_SKB_COPY);
	}

	/* change ip, port. */
	if ((cp->flags & IP_VS_CONN_F_FWD_MASK) == IP_VS_CONN_F_FULLNAT) {
		if (pp->fnat_in_handler && !pp->fnat_in_handler(&skb, pp, cp))
			goto err;

		ipv6_hdr(skb)->saddr = cp->laddr.in6;
		ipv6_hdr(skb)->daddr = cp->daddr.in6;
	} else {
		IP_VS_ERR_RL("L2 fast xmit support fullnat only!\n");
		goto err;
		/*if (pp->dnat_handler && !pp->dnat_handler(skb, pp, cp))
			goto err;

		ipv6_hdr(skb)->daddr = cp->daddr.in6;*/
	}

	skb->dev = cp->dev_inside;

	if(unlikely(skb_headroom(skb) < LL_RESERVED_SPACE(skb->dev))){
		struct sk_buff *skb2;

		IP_VS_ERR_RL("need more headroom! realloc skb\n");
		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(skb->dev));
		if (skb2 == NULL)
			goto err;
		kfree_skb(skb);
		skb = skb2;
	}

	if(likely(skb_mac_header_was_set(skb))) {
		eth = eth_hdr(skb);
		memcpy(eth->h_dest, cp->src_hwaddr_inside, ETH_ALEN);
		memcpy(eth->h_source, cp->dst_hwaddr_inside, ETH_ALEN);
		skb->data = (unsigned char *)eth_hdr(skb);
		skb->len += sizeof(struct ethhdr);
	} else {
		eth = (struct ethhdr *)skb_push(skb, sizeof(struct ethhdr));
		skb_reset_mac_header(skb);
		memcpy(eth->h_dest, cp->src_hwaddr_inside, ETH_ALEN);
		memcpy(eth->h_source, cp->dst_hwaddr_inside, ETH_ALEN);
	}
	skb->protocol = eth->h_proto = htons(ETH_P_IPV6);
	skb->pkt_type = PACKET_OUTGOING;

	IP_VS_DBG_RL("%s: send skb to RS!\n", __func__);
	/* Send the packet out */
	ret = dev_queue_xmit(skb);
	if (ret != 0) {
		IP_VS_DBG_RL("dev_queue_xmit failed! code:%d\n", ret);
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_FAILED_INSIDE);
		return 0;
	}

	IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_PASS_INSIDE);
	return 0;
err:
	IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_REJECT_INSIDE);
	return 1;
}
#endif

void
ip_vs_save_xmit_info(struct sk_buff *skb, struct ip_vs_protocol *pp,
					struct ip_vs_conn *cp)
{
	if(!sysctl_ip_vs_fast_xmit)
		return;

	if(!skb->dev) {
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_DEV_LOST);
		IP_VS_DBG_RL("save_xmit_info, skb->dev is NULL. \n");
		return;
	}
	IP_VS_DBG_RL("save_xmit_info, netdevice:%s\n", netdev_name(skb->dev));

	if(likely((skb->dev->type == ARPHRD_ETHER) &&
					skb_mac_header_was_set(skb))) {
		struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);

		if(unlikely(cp->indev == NULL)) {
			cp->indev = skb->dev;
			dev_hold(cp->indev);
		}

		if (unlikely(cp->indev != skb->dev)) {
			dev_put(cp->indev);
			cp->indev = skb->dev;
			dev_hold(cp->indev);
		}

		memcpy(cp->src_hwaddr, eth->h_source, ETH_ALEN);
		memcpy(cp->dst_hwaddr, eth->h_dest, ETH_ALEN);
	} else {
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_NO_MAC);
		IP_VS_DBG_RL("save dev and mac failed!\n");
	}
}

/*
 *      NAT transmitter (only for outside-to-inside nat forwarding)
 *      Not used for related ICMP
 */
int
ip_vs_nat_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
	       struct ip_vs_protocol *pp)
{
	struct rtable *rt;	/* Route to the other host */
	int mtu;
	struct iphdr *iph = ip_hdr(skb);

	EnterFunction(10);

	/* check if it is a connection of no-client-port */
	if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
		__be16 _pt, *p;
		p = skb_header_pointer(skb, iph->ihl * 4, sizeof(_pt), &_pt);
		if (p == NULL)
			goto tx_error;
		ip_vs_conn_fill_cport(cp, *p);
		IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
	}

	ip_vs_save_xmit_info(skb, pp, cp);

	if(sysctl_ip_vs_fast_xmit_inside && !ip_vs_fast_xmit(skb, pp, cp))
		return NF_STOLEN;

	if (!(rt = __ip_vs_get_out_rt(cp, RT_TOS(iph->tos))))
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if ((skb->len > mtu) && (iph->frag_off & htons(IP_DF))) {
		ip_rt_put(rt);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "ip_vs_nat_xmit(): frag needed for");
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, sizeof(struct iphdr)))
		goto tx_error_put;

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* mangle the packet */
	if (pp->dnat_handler && !pp->dnat_handler(skb, pp, cp))
		goto tx_error;
	ip_hdr(skb)->daddr = cp->daddr.ip;
	ip_send_check(ip_hdr(skb));

	IP_VS_DBG_PKT(10, pp, skb, 0, "After DNAT");

	/* FIXME: when application helper enlarges the packet and the length
	   is larger than the MTU of outgoing device, there will be still
	   MTU problem. */

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET, skb, rt);

	LeaveFunction(10);
	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	LeaveFunction(10);
	kfree_skb(skb);
	return NF_STOLEN;
      tx_error_put:
	ip_rt_put(rt);
	goto tx_error;
}

#ifdef CONFIG_IP_VS_IPV6
int
ip_vs_nat_xmit_v6(struct sk_buff *skb, struct ip_vs_conn *cp,
		  struct ip_vs_protocol *pp)
{
	struct rt6_info *rt;	/* Route to the other host */
	int mtu;

	EnterFunction(10);

	/* check if it is a connection of no-client-port */
	if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
		__be16 _pt, *p;
		p = skb_header_pointer(skb, sizeof(struct ipv6hdr),
				       sizeof(_pt), &_pt);
		if (p == NULL)
			goto tx_error;
		ip_vs_conn_fill_cport(cp, *p);
		IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
	}

	rt = __ip_vs_get_out_rt_v6(cp);
	if (!rt)
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (skb->len > mtu) {
		dst_release(&rt->u.dst);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, skb->dev);
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "ip_vs_nat_xmit_v6(): frag needed for");
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, sizeof(struct ipv6hdr)))
		goto tx_error_put;

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* mangle the packet */
	if (pp->dnat_handler && !pp->dnat_handler(skb, pp, cp))
		goto tx_error;
	ipv6_hdr(skb)->daddr = cp->daddr.in6;

	IP_VS_DBG_PKT(10, pp, skb, 0, "After DNAT");

	/* FIXME: when application helper enlarges the packet and the length
	   is larger than the MTU of outgoing device, there will be still
	   MTU problem. */

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET6, skb, rt);

	LeaveFunction(10);
	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	LeaveFunction(10);
	kfree_skb(skb);
	return NF_STOLEN;
      tx_error_put:
	dst_release(&rt->u.dst);
	goto tx_error;
}
#endif

/*
 *      FULLNAT transmitter (only for outside-to-inside fullnat forwarding)
 *      Not used for related ICMP
 */
int
ip_vs_fnat_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		struct ip_vs_protocol *pp)
{
	struct rtable *rt;	/* Route to the other host */
	int mtu;
	struct iphdr *iph = ip_hdr(skb);

	EnterFunction(10);

	/* check if it is a connection of no-client-port */
	if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
		__be16 _pt, *p;
		p = skb_header_pointer(skb, iph->ihl * 4, sizeof(_pt), &_pt);
		if (p == NULL)
			goto tx_error;
		ip_vs_conn_fill_cport(cp, *p);
		IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
	}

	ip_vs_save_xmit_info(skb, pp, cp);
	
	if(sysctl_ip_vs_fast_xmit_inside && !ip_vs_fast_xmit(skb, pp, cp))
		return NF_STOLEN;

	if (!(rt = __ip_vs_get_out_rt(cp, RT_TOS(iph->tos))))
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (!gso_ok(skb, rt->u.dst.dev) && (skb->len > mtu) &&
					(iph->frag_off & htons(IP_DF))) {
		ip_rt_put(rt);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "ip_vs_fnat_xmit(): frag needed for");
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, sizeof(struct iphdr)))
		goto tx_error_put;

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* mangle the packet */
	if (pp->fnat_in_handler && !pp->fnat_in_handler(&skb, pp, cp))
		goto tx_error;
	ip_hdr(skb)->saddr = cp->laddr.ip;
	ip_hdr(skb)->daddr = cp->daddr.ip;
	ip_send_check(ip_hdr(skb));

	IP_VS_DBG_PKT(10, pp, skb, 0, "After FNAT-IN");

	/* FIXME: when application helper enlarges the packet and the length
	   is larger than the MTU of outgoing device, there will be still
	   MTU problem. */

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET, skb, rt);

	LeaveFunction(10);
	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	LeaveFunction(10);
	kfree_skb(skb);
	return NF_STOLEN;
      tx_error_put:
	ip_rt_put(rt);
	goto tx_error;
}

#ifdef CONFIG_IP_VS_IPV6
int
ip_vs_fnat_xmit_v6(struct sk_buff *skb, struct ip_vs_conn *cp,
		   struct ip_vs_protocol *pp)
{
	struct rt6_info *rt;	/* Route to the other host */
	int mtu;

	EnterFunction(10);

	/* check if it is a connection of no-client-port */
	if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
		__be16 _pt, *p;
		p = skb_header_pointer(skb, sizeof(struct ipv6hdr),
				       sizeof(_pt), &_pt);
		if (p == NULL)
			goto tx_error;
		ip_vs_conn_fill_cport(cp, *p);
		IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
	}

	ip_vs_save_xmit_info(skb, pp, cp);

	if(sysctl_ip_vs_fast_xmit_inside && !ip_vs_fast_xmit_v6(skb, pp, cp))
		return NF_STOLEN;

	rt = __ip_vs_get_out_rt_v6(cp);
	if (!rt)
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (!gso_ok(skb, rt->u.dst.dev) && (skb->len > mtu)) {
		dst_release(&rt->u.dst);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, skb->dev);
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "ip_vs_fnat_xmit_v6(): frag needed for");
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, sizeof(struct ipv6hdr)))
		goto tx_error_put;

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* mangle the packet */
	if (pp->fnat_in_handler && !pp->fnat_in_handler(&skb, pp, cp))
		goto tx_error;
	ipv6_hdr(skb)->saddr = cp->laddr.in6;
	ipv6_hdr(skb)->daddr = cp->daddr.in6;

	IP_VS_DBG_PKT(10, pp, skb, 0, "After FNAT-IN");

	/* FIXME: when application helper enlarges the packet and the length
	   is larger than the MTU of outgoing device, there will be still
	   MTU problem. */

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET6, skb, rt);

	LeaveFunction(10);
	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	LeaveFunction(10);
	kfree_skb(skb);
	return NF_STOLEN;
      tx_error_put:
	dst_release(&rt->u.dst);
	goto tx_error;
}
#endif

/*
 *   IP Tunneling transmitter
 *
 *   This function encapsulates the packet in a new IP packet, its
 *   destination will be set to cp->daddr. Most code of this function
 *   is taken from ipip.c.
 *
 *   It is used in VS/TUN cluster. The load balancer selects a real
 *   server from a cluster based on a scheduling algorithm,
 *   encapsulates the request packet and forwards it to the selected
 *   server. For example, all real servers are configured with
 *   "ifconfig tunl0 <Virtual IP Address> up". When the server receives
 *   the encapsulated packet, it will decapsulate the packet, processe
 *   the request and return the response packets directly to the client
 *   without passing the load balancer. This can greatly increase the
 *   scalability of virtual server.
 *
 *   Used for ANY protocol
 */
int
ip_vs_tunnel_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		  struct ip_vs_protocol *pp)
{
	struct rtable *rt;	/* Route to the other host */
	struct net_device *tdev;	/* Device to other host */
	struct iphdr *old_iph = ip_hdr(skb);
	u8 tos = old_iph->tos;
	__be16 df = old_iph->frag_off;
	sk_buff_data_t old_transport_header = skb->transport_header;
	struct iphdr *iph;	/* Our new IP header */
	unsigned int max_headroom;	/* The extra header space needed */
	int mtu;

	EnterFunction(10);

	if (skb->protocol != htons(ETH_P_IP)) {
		IP_VS_DBG_RL("%s(): protocol error, "
			     "ETH_P_IP: %d, skb protocol: %d\n",
			     __func__, htons(ETH_P_IP), skb->protocol);
		goto tx_error;
	}

	if (!(rt = __ip_vs_get_out_rt(cp, RT_TOS(tos))))
		goto tx_error_icmp;

	tdev = rt->u.dst.dev;

	mtu = dst_mtu(&rt->u.dst) - sizeof(struct iphdr);
	if (mtu < 68) {
		ip_rt_put(rt);
		IP_VS_DBG_RL("%s(): mtu less than 68\n", __func__);
		goto tx_error;
	}
	if (skb_dst(skb))
		skb_dst(skb)->ops->update_pmtu(skb_dst(skb), mtu);

	df |= (old_iph->frag_off & htons(IP_DF));

	if ((old_iph->frag_off & htons(IP_DF))
	    && mtu < ntohs(old_iph->tot_len)) {
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		ip_rt_put(rt);
		IP_VS_DBG_RL("%s(): frag needed\n", __func__);
		goto tx_error;
	}

	/*
	 * Okay, now see if we can stuff it in the buffer as-is.
	 */
	max_headroom = LL_RESERVED_SPACE(tdev) + sizeof(struct iphdr);

	if (skb_headroom(skb) < max_headroom
	    || skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *new_skb =
		    skb_realloc_headroom(skb, max_headroom);
		if (!new_skb) {
			ip_rt_put(rt);
			kfree_skb(skb);
			IP_VS_ERR_RL("%s(): no memory\n", __func__);
			return NF_STOLEN;
		}
		kfree_skb(skb);
		skb = new_skb;
		old_iph = ip_hdr(skb);
	}

	skb->transport_header = old_transport_header;

	/* fix old IP header checksum */
	ip_send_check(old_iph);

	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/*
	 *      Push down and install the IPIP header.
	 */
	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->frag_off = df;
	iph->protocol = IPPROTO_IPIP;
	iph->tos = tos;
	iph->daddr = rt->rt_dst;
	iph->saddr = rt->rt_src;
	iph->ttl = old_iph->ttl;
	ip_select_ident(iph, &rt->u.dst, NULL);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	ip_local_out(skb);

	LeaveFunction(10);

	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	kfree_skb(skb);
	LeaveFunction(10);
	return NF_STOLEN;
}

#ifdef CONFIG_IP_VS_IPV6
int
ip_vs_tunnel_xmit_v6(struct sk_buff *skb, struct ip_vs_conn *cp,
		     struct ip_vs_protocol *pp)
{
	struct rt6_info *rt;	/* Route to the other host */
	struct net_device *tdev;	/* Device to other host */
	struct ipv6hdr *old_iph = ipv6_hdr(skb);
	sk_buff_data_t old_transport_header = skb->transport_header;
	struct ipv6hdr *iph;	/* Our new IP header */
	unsigned int max_headroom;	/* The extra header space needed */
	int mtu;

	EnterFunction(10);

	if (skb->protocol != htons(ETH_P_IPV6)) {
		IP_VS_DBG_RL("%s(): protocol error, "
			     "ETH_P_IPV6: %d, skb protocol: %d\n",
			     __func__, htons(ETH_P_IPV6), skb->protocol);
		goto tx_error;
	}

	rt = __ip_vs_get_out_rt_v6(cp);
	if (!rt)
		goto tx_error_icmp;

	tdev = rt->u.dst.dev;

	mtu = dst_mtu(&rt->u.dst) - sizeof(struct ipv6hdr);
	/* TODO IPv6: do we need this check in IPv6? */
	if (mtu < 1280) {
		dst_release(&rt->u.dst);
		IP_VS_DBG_RL("%s(): mtu less than 1280\n", __func__);
		goto tx_error;
	}
	if (skb_dst(skb))
		skb_dst(skb)->ops->update_pmtu(skb_dst(skb), mtu);

	if (mtu < ntohs(old_iph->payload_len) + sizeof(struct ipv6hdr)) {
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, skb->dev);
		dst_release(&rt->u.dst);
		IP_VS_DBG_RL("%s(): frag needed\n", __func__);
		goto tx_error;
	}

	/*
	 * Okay, now see if we can stuff it in the buffer as-is.
	 */
	max_headroom = LL_RESERVED_SPACE(tdev) + sizeof(struct ipv6hdr);

	if (skb_headroom(skb) < max_headroom
	    || skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *new_skb =
		    skb_realloc_headroom(skb, max_headroom);
		if (!new_skb) {
			dst_release(&rt->u.dst);
			kfree_skb(skb);
			IP_VS_ERR_RL("%s(): no memory\n", __func__);
			return NF_STOLEN;
		}
		kfree_skb(skb);
		skb = new_skb;
		old_iph = ipv6_hdr(skb);
	}

	skb->transport_header = old_transport_header;

	skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/*
	 *      Push down and install the IPIP header.
	 */
	iph = ipv6_hdr(skb);
	iph->version = 6;
	iph->nexthdr = IPPROTO_IPV6;
	iph->payload_len = old_iph->payload_len;
	be16_add_cpu(&iph->payload_len, sizeof(*old_iph));
	iph->priority = old_iph->priority;
	memset(&iph->flow_lbl, 0, sizeof(iph->flow_lbl));
	iph->daddr = rt->rt6i_dst.addr;
	iph->saddr = cp->vaddr.in6;	/* rt->rt6i_src.addr; */
	iph->hop_limit = old_iph->hop_limit;

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	ip6_local_out(skb);

	LeaveFunction(10);

	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	kfree_skb(skb);
	LeaveFunction(10);
	return NF_STOLEN;
}
#endif

/*
 *      Direct Routing transmitter
 *      Used for ANY protocol
 */
int
ip_vs_dr_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
	      struct ip_vs_protocol *pp)
{
	struct rtable *rt;	/* Route to the other host */
	struct iphdr *iph = ip_hdr(skb);
	int mtu;

	EnterFunction(10);

	if (!(rt = __ip_vs_get_out_rt(cp, RT_TOS(iph->tos))))
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if ((iph->frag_off & htons(IP_DF)) && skb->len > mtu) {
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		ip_rt_put(rt);
		IP_VS_DBG_RL("%s(): frag needed\n", __func__);
		goto tx_error;
	}

	/*
	 * Call ip_send_check because we are not sure it is called
	 * after ip_defrag. Is copy-on-write needed?
	 */
	if (unlikely((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)) {
		ip_rt_put(rt);
		return NF_STOLEN;
	}
	ip_send_check(ip_hdr(skb));

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET, skb, rt);

	LeaveFunction(10);
	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	kfree_skb(skb);
	LeaveFunction(10);
	return NF_STOLEN;
}

#ifdef CONFIG_IP_VS_IPV6
int
ip_vs_dr_xmit_v6(struct sk_buff *skb, struct ip_vs_conn *cp,
		 struct ip_vs_protocol *pp)
{
	struct rt6_info *rt;	/* Route to the other host */
	int mtu;

	EnterFunction(10);

	rt = __ip_vs_get_out_rt_v6(cp);
	if (!rt)
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (skb->len > mtu) {
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, skb->dev);
		dst_release(&rt->u.dst);
		IP_VS_DBG_RL("%s(): frag needed\n", __func__);
		goto tx_error;
	}

	/*
	 * Call ip_send_check because we are not sure it is called
	 * after ip_defrag. Is copy-on-write needed?
	 */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(skb == NULL)) {
		dst_release(&rt->u.dst);
		return NF_STOLEN;
	}

	/* drop old route */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET6, skb, rt);

	LeaveFunction(10);
	return NF_STOLEN;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	kfree_skb(skb);
	LeaveFunction(10);
	return NF_STOLEN;
}
#endif

/*
 *	ICMP packet transmitter
 *	called by the ip_vs_in_icmp
 */
int
ip_vs_icmp_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		struct ip_vs_protocol *pp, int offset)
{
	struct rtable *rt;	/* Route to the other host */
	int mtu;
	int rc;

	EnterFunction(10);

	/* The ICMP packet for VS/TUN, VS/DR and LOCALNODE will be
	   forwarded directly here, because there is no need to
	   translate address/port back */
	if ((IP_VS_FWD_METHOD(cp) != IP_VS_CONN_F_MASQ) &&
	    (IP_VS_FWD_METHOD(cp) != IP_VS_CONN_F_FULLNAT)) {
		if (cp->packet_xmit)
			rc = cp->packet_xmit(skb, cp, pp);
		else
			rc = NF_ACCEPT;
		/* do not touch skb anymore */
		atomic_inc(&cp->in_pkts);
		goto out;
	}

	/*
	 * mangle and send the packet here (only for VS/NAT)
	 */

	if (!(rt = __ip_vs_get_out_rt(cp, RT_TOS(ip_hdr(skb)->tos))))
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if ((skb->len > mtu) && (ip_hdr(skb)->frag_off & htons(IP_DF))) {
		ip_rt_put(rt);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		IP_VS_DBG_RL("%s(): frag needed\n", __func__);
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, offset))
		goto tx_error_put;

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop the old route when skb is not shared */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	ip_vs_nat_icmp(skb, pp, cp, 0);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET, skb, rt);

	rc = NF_STOLEN;
	goto out;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	dev_kfree_skb(skb);
	rc = NF_STOLEN;
      out:
	LeaveFunction(10);
	return rc;
      tx_error_put:
	ip_rt_put(rt);
	goto tx_error;
}

#ifdef CONFIG_IP_VS_IPV6
int
ip_vs_icmp_xmit_v6(struct sk_buff *skb, struct ip_vs_conn *cp,
		   struct ip_vs_protocol *pp, int offset)
{
	struct rt6_info *rt;	/* Route to the other host */
	int mtu;
	int rc;

	EnterFunction(10);

	/* The ICMP packet for VS/TUN, VS/DR and LOCALNODE will be
	   forwarded directly here, because there is no need to
	   translate address/port back */
	if ((IP_VS_FWD_METHOD(cp) != IP_VS_CONN_F_MASQ) &&
	    (IP_VS_FWD_METHOD(cp) != IP_VS_CONN_F_FULLNAT)) {
		if (cp->packet_xmit)
			rc = cp->packet_xmit(skb, cp, pp);
		else
			rc = NF_ACCEPT;
		/* do not touch skb anymore */
		atomic_inc(&cp->in_pkts);
		goto out;
	}

	/*
	 * mangle and send the packet here (only for VS/NAT)
	 */

	rt = __ip_vs_get_out_rt_v6(cp);
	if (!rt)
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (skb->len > mtu) {
		dst_release(&rt->u.dst);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, skb->dev);
		IP_VS_DBG_RL("%s(): frag needed\n", __func__);
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, offset))
		goto tx_error_put;

	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop the old route when skb is not shared */
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	ip_vs_nat_icmp_v6(skb, pp, cp, 0);

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET6, skb, rt);

	rc = NF_STOLEN;
	goto out;

      tx_error_icmp:
	dst_link_failure(skb);
      tx_error:
	dev_kfree_skb(skb);
	rc = NF_STOLEN;
      out:
	LeaveFunction(10);
	return rc;
      tx_error_put:
	dst_release(&rt->u.dst);
	goto tx_error;
}
#endif

int
ip_vs_snat_out_xmit(struct sk_buff *skb, struct ip_vs_conn *cp,
		struct ip_vs_protocol *pp)
{
	struct rtable *rt;	/* Route to the other host */
	struct rtable *old_rt = skb_rtable(skb);
	int mtu;
	struct iphdr *iph = ip_hdr(skb);

	EnterFunction(10);

	/* check if it is a connection of no-client-port */
	if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
		__be16 _pt, *p;
		p = skb_header_pointer(skb, iph->ihl * 4, sizeof(_pt), &_pt);
		if (p == NULL)
			goto tx_error;
		ip_vs_conn_fill_cport(cp, *p);
		IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
	}
	
	ip_vs_save_xmit_info(skb, pp, cp);
	
	if(sysctl_ip_vs_fast_xmit_inside && !ip_vs_fast_xmit(skb, pp, cp))
		return NF_STOLEN;

	if (!(rt = __ip_vs_get_snat_out_rt(old_rt, cp, RT_TOS(iph->tos))))
		goto tx_error_icmp;

	/* MTU checking */
	mtu = dst_mtu(&rt->u.dst);
	if (!gso_ok(skb, rt->u.dst.dev) && (skb->len > mtu) &&
					(iph->frag_off & htons(IP_DF))) {
		ip_rt_put(rt);
		IP_VS_INC_ESTATS(ip_vs_esmib, XMIT_UNEXPECTED_MTU);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		IP_VS_DBG_RL_PKT(0, pp, skb, 0,
				 "ip_vs_snat_out_xmit(): frag needed for");
		goto tx_error;
	}

	/* copy-on-write the packet before mangling it */
	if (!skb_make_writable(skb, sizeof(struct iphdr)))
		goto tx_error_put;
	
	if (skb_cow(skb, rt->u.dst.dev->hard_header_len))
		goto tx_error_put;

	/* drop old route */
	if (rt != old_rt) {
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);
	}

	/* mangle the packet */
	if (pp->fnat_in_handler && !pp->fnat_in_handler(&skb, pp, cp))
		goto tx_error;
	ip_hdr(skb)->saddr = cp->laddr.ip;
	ip_hdr(skb)->daddr = cp->daddr.ip;
	ip_send_check(ip_hdr(skb));

	IP_VS_DBG_PKT(10, pp, skb, 0, "After SNAT-OUT");

	/* FIXME: when application helper enlarges the packet and the length
	   is larger than the MTU of outgoing device, there will be still
	   MTU problem. */

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;

	IP_VS_XMIT(PF_INET, skb, rt);

	LeaveFunction(10);
	return NF_STOLEN;

	  tx_error_icmp:
	dst_link_failure(skb);
	  tx_error:
	LeaveFunction(10);
	kfree_skb(skb);
	return NF_STOLEN;
	  tx_error_put:
	ip_rt_put(rt);
	goto tx_error;
}
