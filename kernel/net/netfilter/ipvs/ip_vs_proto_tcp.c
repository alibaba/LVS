/*
 * ip_vs_proto_tcp.c:	TCP load balancing support for IPVS
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
#include <linux/ip.h>
#include <linux/tcp.h>		/* for tcphdr */
#include <net/ip.h>
#include <net/tcp.h>		/* for csum_tcpudp_magic */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/secure_seq.h>

#ifdef CONFIG_IP_VS_IPV6
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#endif

#include <net/ip_vs.h>
#include <net/ip_vs_synproxy.h>

static struct ip_vs_conn *tcp_conn_in_get(int af, const struct sk_buff *skb,
					  struct ip_vs_protocol *pp,
					  const struct ip_vs_iphdr *iph,
					  unsigned int proto_off, int inverse,
					  int *res_dir)
{
	__be16 _ports[2], *pptr;

	pptr = skb_header_pointer(skb, proto_off, sizeof(_ports), _ports);
	if (pptr == NULL)
		return NULL;

	if (likely(!inverse)) {
		return ip_vs_conn_get(af, iph->protocol,
				      &iph->saddr, pptr[0],
				      &iph->daddr, pptr[1], res_dir);
	} else {
		return ip_vs_conn_get(af, iph->protocol,
				      &iph->daddr, pptr[1],
				      &iph->saddr, pptr[0], res_dir);
	}
}

static struct ip_vs_conn *tcp_conn_out_get(int af, const struct sk_buff *skb,
					   struct ip_vs_protocol *pp,
					   const struct ip_vs_iphdr *iph,
					   unsigned int proto_off, int inverse,
					   int *res_dir)
{
	__be16 _ports[2], *pptr;

	pptr = skb_header_pointer(skb, proto_off, sizeof(_ports), _ports);
	if (pptr == NULL)
		return NULL;

	if (likely(!inverse)) {
		return ip_vs_conn_get(af, iph->protocol,
				      &iph->saddr, pptr[0],
				      &iph->daddr, pptr[1], res_dir);
	} else {
		return ip_vs_conn_get(af, iph->protocol,
				      &iph->daddr, pptr[1],
				      &iph->saddr, pptr[0], res_dir);
	}
}

static int
tcp_conn_schedule(int af, struct sk_buff *skb, struct ip_vs_protocol *pp,
		  int *verdict, struct ip_vs_conn **cpp)
{
	struct ip_vs_service *svc;
	struct tcphdr _tcph, *th;
	struct ip_vs_iphdr iph;

	ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);

	th = skb_header_pointer(skb, iph.len, sizeof(_tcph), &_tcph);
	if (th == NULL) {
		*verdict = NF_DROP;
		return 0;
	}

	/*
	 * Syn-proxy step 2 logic: receive client's
	 * 3-handshake Ack packet
	 */
	if (ip_vs_synproxy_ack_rcv(af, skb, th, pp, cpp, &iph, verdict) == 0) {
		return 0;
	}

	if (th->syn && !th->ack && !th->fin && !th->rst &&
	    (svc = ip_vs_service_get(af, skb->mark, iph.protocol, &iph.daddr,
				     th->dest))) {
		if (ip_vs_todrop()) {
			/*
			 * It seems that we are very loaded.
			 * We have to drop this packet :(
			 */
			ip_vs_service_put(svc);
			*verdict = NF_DROP;
			return 0;
		}

		/*
		 * Let the virtual server select a real server for the
		 * incoming connection, and create a connection entry.
		 */
		*cpp = ip_vs_schedule(svc, skb, 0);
		if (!*cpp) {
			*verdict = ip_vs_leave(svc, skb, pp);
			return 0;
		}

		/*
		 * Set private establish state timeout into cp from svc,
		 * due cp may use its user establish state timeout
		 * different from sysctl_ip_vs_tcp_timeouts
		 */
		(*cpp)->est_timeout = svc->est_timeout;

		ip_vs_service_put(svc);
		return 1;
	}

	/* drop tcp packet which send to vip and !vport */
	if (sysctl_ip_vs_tcp_drop_entry &&
	    (svc = ip_vs_lookup_vip(af, iph.protocol, &iph.daddr))) {
		IP_VS_INC_ESTATS(ip_vs_esmib, DEFENCE_TCP_DROP);
		*verdict = NF_DROP;
		return 0;
	}

	return 1;
}

static inline void
tcp_fast_csum_update(int af, struct tcphdr *tcph,
		     const union nf_inet_addr *oldip,
		     const union nf_inet_addr *newip,
		     __be16 oldport, __be16 newport)
{
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		tcph->check =
		    csum_fold(ip_vs_check_diff16(oldip->ip6, newip->ip6,
						 ip_vs_check_diff2(oldport,
								   newport,
								   ~csum_unfold
								   (tcph->
								    check))));
	else
#endif
		tcph->check =
		    csum_fold(ip_vs_check_diff4(oldip->ip, newip->ip,
						ip_vs_check_diff2(oldport,
								  newport,
								  ~csum_unfold
								  (tcph->
								   check))));
}

static inline void
tcp_partial_csum_update(int af, struct tcphdr *tcph,
			const union nf_inet_addr *oldip,
			const union nf_inet_addr *newip,
			__be16 oldlen, __be16 newlen)
{
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		tcph->check =
			~csum_fold(ip_vs_check_diff16(oldip->ip6, newip->ip6,
					ip_vs_check_diff2(oldlen, newlen,
						csum_unfold(tcph->check))));
	else
#endif
		tcph->check =
			~csum_fold(ip_vs_check_diff4(oldip->ip, newip->ip,
					ip_vs_check_diff2(oldlen, newlen,
						csum_unfold(tcph->check))));
}

/* Calculate TCP checksum, only for PARTICAL */
static inline void
tcp_partial_csum_reset(int af, int len, struct tcphdr *tcph,
				const union nf_inet_addr *saddr,
				const union nf_inet_addr *daddr)
{
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		tcph->check = ~csum_ipv6_magic(&saddr->in6, &daddr->in6,
							len, IPPROTO_TCP, 0);
        else
#endif
		tcph->check = ~tcp_v4_check(len, saddr->ip, daddr->ip, 0);
}

static inline void
tcp_seq_csum_update(struct tcphdr *tcph, __u32 oldseq, __u32 newseq)
{
	/* do checksum later */
	if (!sysctl_ip_vs_csum_offload)
		tcph->check = csum_fold(ip_vs_check_diff4(oldseq, newseq,
						~csum_unfold(tcph->check)));
}

static inline void
tcp_mss_csum_update(struct tcphdr *tcph, __be16 oldmss, __be16 newmss)
{
	/* do checksum later */
	if (!sysctl_ip_vs_csum_offload)
		tcph->check = csum_fold(ip_vs_check_diff2(oldmss, newmss,
						~csum_unfold(tcph->check)));
}

/* adjust tcp opt mss, sub TCPOLEN_CIP */
static void tcp_opt_adjust_mss(int af, struct tcphdr *tcph)
{
	unsigned char *ptr;
	int length;

	if (sysctl_ip_vs_mss_adjust_entry == 0)
		return;

	ptr = (unsigned char *)(tcph + 1);
	length = (tcph->doff * 4) - sizeof(struct tcphdr);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2)	/* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			if ((opcode == TCPOPT_MSS) && (opsize == TCPOLEN_MSS)) {
				__be16 old = *(__be16 *) ptr;
				__u16 in_mss = ntohs(*(__be16 *) ptr);
#ifdef CONFIG_IP_VS_IPV6
				if (af == AF_INET6)
					in_mss -= TCPOLEN_ADDR_V6;
				else
#endif
					in_mss -= TCPOLEN_ADDR;
				/* set mss, 16bit */
				*((__be16 *) ptr) = htons(in_mss);
				tcp_mss_csum_update(tcph, old, *(__be16 *)ptr);
				return;
			}

			ptr += opsize - 2;
			length -= opsize;
		}
	}
}

/* save tcp sequense for fullnat/nat, INside to OUTside */
static void
tcp_save_out_seq(struct sk_buff *skb, struct ip_vs_conn *cp,
		 struct tcphdr *th, int ihl)
{
	if (unlikely(th == NULL) || unlikely(cp == NULL) ||
	    unlikely(skb == NULL))
		return;

	if (sysctl_ip_vs_conn_expire_tcp_rst && !th->rst) {

		/* seq out of order. just skip */
		if (before(ntohl(th->ack_seq), ntohl(cp->rs_ack_seq)) &&
							(cp->rs_ack_seq != 0))
			return;

		if (th->syn && th->ack)
			cp->rs_end_seq = htonl(ntohl(th->seq) + 1);
		else
			cp->rs_end_seq = htonl(ntohl(th->seq) + skb->len
					       - ihl - (th->doff << 2));
		cp->rs_ack_seq = th->ack_seq;
		IP_VS_DBG_RL("packet from RS, seq:%u ack_seq:%u.",
			     ntohl(th->seq), ntohl(th->ack_seq));
		IP_VS_DBG_RL("port:%u->%u", ntohs(th->source), ntohs(th->dest));
	}
}

/*
 * 1. adjust tcp ack/sack sequence for FULL-NAT, INside to OUTside
 * 2. adjust tcp sequence for SYNPROXY, OUTside to INside
 */
static int tcp_out_adjust_seq(struct ip_vs_conn *cp, struct tcphdr *tcph)
{
	__u8 i;
	__u8 *ptr;
	int length;
	__be32 old_seq;

	/*
	 * Syn-proxy seq change, include tcp hdr and
	 * check ack storm.
	 */
	if (ip_vs_synproxy_snat_handler(tcph, cp) == 0) {
		return 0;
	}

	/*
	 * FULLNAT ack-seq change
	 */

	old_seq = tcph->ack_seq;
	/* adjust ack sequence */
	tcph->ack_seq = htonl(ntohl(tcph->ack_seq) - cp->fnat_seq.delta);
	/* update checksum */
	tcp_seq_csum_update(tcph, old_seq, tcph->ack_seq);

	/* adjust sack sequence */
	ptr = (__u8 *) (tcph + 1);
	length = (tcph->doff * 4) - sizeof(struct tcphdr);

	/* Fast path for timestamp-only option */
	if (length == TCPOLEN_TSTAMP_ALIGNED &&
		*(__be32 *) ptr == htonl((TCPOPT_NOP << 24) |
					(TCPOPT_NOP << 16) |
					(TCPOPT_TIMESTAMP << 8) |
					TCPOLEN_TIMESTAMP))
		return 1;

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return 1;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2)	/* "silly options" */
				return 1;
			if (opsize > length)
				return 1;	/* don't parse partial options */
			if ((opcode == TCPOPT_SACK) &&
			(opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK))
			&& !((opsize - TCPOLEN_SACK_BASE) %
						TCPOLEN_SACK_PERBLOCK)) {
				for (i = 0; i < opsize - TCPOLEN_SACK_BASE;
						i += TCPOLEN_SACK_PERBLOCK) {
					__be32 *tmp = (__be32 *) (ptr + i);
					old_seq = *tmp;
					*tmp = htonl(ntohl(*tmp) -
							cp->fnat_seq.delta);
					tcp_seq_csum_update(tcph, old_seq, *tmp);

					tmp++;

					old_seq = *tmp;
					*tmp = htonl(ntohl(*tmp) -
							cp->fnat_seq.delta);
					tcp_seq_csum_update(tcph, old_seq, *tmp);
				}
				return 1;
			}

			ptr += opsize - 2;
			length -= opsize;
		}
	}

	return 1;
}

static int
tcp_snat_handler(struct sk_buff *skb,
		 struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct tcphdr *tcph;
	unsigned int tcphoff;
	int oldlen;

#ifdef CONFIG_IP_VS_IPV6
	if (cp->af == AF_INET6)
		tcphoff = sizeof(struct ipv6hdr);
	else
#endif
		tcphoff = ip_hdrlen(skb);
	oldlen = skb->len - tcphoff;

	/* csum_check requires unshared skb */
	if (!skb_make_writable(skb, tcphoff + sizeof(*tcph)))
		return 0;

	if (unlikely(cp->app != NULL)) {
		/* Some checks before mangling */
		if (pp->csum_check && !pp->csum_check(cp->af, skb, pp))
			return 0;

		/* Call application helper if needed */
		if (!ip_vs_app_pkt_out(cp, skb))
			return 0;
	}

	tcph = (void *)skb_network_header(skb) + tcphoff;
	tcp_save_out_seq(skb, cp, tcph, tcphoff);
	tcph->source = cp->vport;

	/*
	 * Syn-proxy seq change, include tcp hdr and
	 * check ack storm.
	 */
	if (ip_vs_synproxy_snat_handler(tcph, cp) == 0) {
		return 0;
	}

	if (sysctl_ip_vs_csum_offload) {
		skb->csum_start = skb_network_header(skb) -
				skb->head + (ip_hdr(skb)->ihl << 2);
		skb->csum_offset = offsetof(struct tcphdr, check);
		skb->ip_summed = CHECKSUM_PARTIAL;
	}

	/* Adjust TCP checksums */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		tcp_partial_csum_reset(cp->af, (skb->len - tcphoff),
					tcph, &cp->vaddr, &cp->caddr);
	} else if (!cp->app) {
		/* Only port and addr are changed, do fast csum update */
		tcp_fast_csum_update(cp->af, tcph, &cp->daddr, &cp->vaddr,
				     cp->dport, cp->vport);
		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->ip_summed = CHECKSUM_NONE;
	} else {
		/* full checksum calculation */
		tcph->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			tcph->check = csum_ipv6_magic(&cp->vaddr.in6,
						      &cp->caddr.in6,
						      skb->len - tcphoff,
						      cp->protocol, skb->csum);
		else
#endif
			tcph->check = csum_tcpudp_magic(cp->vaddr.ip,
							cp->caddr.ip,
							skb->len - tcphoff,
							cp->protocol,
							skb->csum);

		IP_VS_DBG(11, "O-pkt: %s O-csum=%d (+%zd)\n",
			  pp->name, tcph->check,
			  (char *)&(tcph->check) - (char *)tcph);
	}
	return 1;
}

/*
 * init first data sequence, INside to OUTside;
 */
static inline void
tcp_out_init_seq(struct ip_vs_conn *cp, struct tcphdr *tcph)
{
	cp->fnat_seq.fdata_seq = ntohl(tcph->seq) + 1;
}


static int
tcp_fnat_out_handler(struct sk_buff *skb,
		     struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct tcphdr *tcph;
	unsigned int tcphoff;
	int oldlen;

#ifdef CONFIG_IP_VS_IPV6
	if (cp->af == AF_INET6)
		tcphoff = sizeof(struct ipv6hdr);
	else
#endif
		tcphoff = ip_hdrlen(skb);
	oldlen = skb->len - tcphoff;

	/* csum_check requires unshared skb */
	if (!skb_make_writable(skb, tcphoff + sizeof(*tcph)))
		return 0;

	if (unlikely(cp->app != NULL)) {
		/* Some checks before mangling */
		if (pp->csum_check && !pp->csum_check(cp->af, skb, pp))
			return 0;

		/* Call application helper if needed */
		if (!ip_vs_app_pkt_out(cp, skb))
			return 0;
	}

	tcph = (void *)skb_network_header(skb) + tcphoff;
	tcp_save_out_seq(skb, cp, tcph, tcphoff);
	tcph->source = cp->vport;
	tcph->dest = cp->cport;

	/*
	 * for syn_ack
	 * 1. adjust tcp opt mss in rs->client
	 */
	if (tcph->syn && tcph->ack) {
		tcp_opt_adjust_mss(cp->af, tcph);
	}

	/* adjust tcp ack/sack sequence */
	if (tcp_out_adjust_seq(cp, tcph) == 0) {
		return 0;
	}

	/*
	 * for syn_ack
	 * 2. init sequence
	 */
	if (tcph->syn && tcph->ack) {
		tcp_out_init_seq(cp, tcph);
	}

	/* do csum later */
	if (sysctl_ip_vs_csum_offload) {
		skb->csum_start = skb_network_header(skb) -
				skb->head + (ip_hdr(skb)->ihl << 2);
		skb->csum_offset = offsetof(struct tcphdr, check);
		skb->ip_summed = CHECKSUM_PARTIAL;
	}

	/* Adjust TCP checksums */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		tcp_partial_csum_reset(cp->af, (skb->len - tcphoff),
					tcph, &cp->vaddr, &cp->caddr);
	} else if (!cp->app) {
		/* Only port and addr are changed, do fast csum update */
		tcp_fast_csum_update(cp->af, tcph, &cp->daddr, &cp->vaddr,
				     cp->dport, cp->vport);
		tcp_fast_csum_update(cp->af, tcph, &cp->laddr, &cp->caddr,
				     cp->lport, cp->cport);
		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->ip_summed = CHECKSUM_NONE;
	} else {
		/* full checksum calculation */
		tcph->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			tcph->check = csum_ipv6_magic(&cp->vaddr.in6,
						      &cp->caddr.in6,
						      skb->len - tcphoff,
						      cp->protocol, skb->csum);
		else
#endif
			tcph->check = csum_tcpudp_magic(cp->vaddr.ip,
							cp->caddr.ip,
							skb->len - tcphoff,
							cp->protocol, skb->csum);

		IP_VS_DBG(11, "O-pkt: %s O-csum=%d (+%zd)\n",
			pp->name, tcph->check,
			(char *)&(tcph->check) - (char *)tcph);
	}
	return 1;
}

/*
 * remove tcp timestamp opt in one packet, just set it to TCPOPT_NOP
 * reference to tcp_parse_options in tcp_input.c
 */
static void tcp_opt_remove_timestamp(struct tcphdr *tcph)
{
	unsigned char *ptr;
	__be32 old[4], new[4];
	int length;
	int i;

	if (sysctl_ip_vs_timestamp_remove_entry == 0)
		return;

	ptr = (unsigned char *)(tcph + 1);
	length = (tcph->doff * 4) - sizeof(struct tcphdr);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2)	/* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			if ((opcode == TCPOPT_TIMESTAMP)
			    && (opsize == TCPOLEN_TIMESTAMP)) {
				/* the length of buf is 16Byte,
				 * but data is 10Byte. zero the buf
				 */
				memset((__u8*)old, 0, sizeof(old));
				memcpy((__u8*)old, ptr - 2, TCPOLEN_TIMESTAMP);
				for (i = 0; i < TCPOLEN_TIMESTAMP; i++) {
					*(ptr - 2 + i) = TCPOPT_NOP;	/* TCPOPT_NOP replace timestamp opt */
				}

				if (!sysctl_ip_vs_csum_offload) {
					memset((__u8*)new, 0, sizeof(new));
					memcpy((__u8*)new, ptr - 2, TCPOLEN_TIMESTAMP);
					tcph->check = csum_fold(
						ip_vs_check_diff16(old, new,
						~csum_unfold(tcph->check)));
				}
				return;
			}

			ptr += opsize - 2;
			length -= opsize;
		}
	}
}

/*
 * recompute tcp sequence, OUTside to INside;
 */
static void
tcp_in_init_seq(struct ip_vs_conn *cp, struct sk_buff *skb, struct tcphdr *tcph)
{
	struct ip_vs_seq *fseq = &(cp->fnat_seq);
	__u32 seq = ntohl(tcph->seq);
	int conn_reused_entry;

	if ((fseq->delta == fseq->init_seq - seq) && (fseq->init_seq != 0)) {
		/* retransmit */
		return;
	}

	/* init syn seq, lvs2rs */
	conn_reused_entry = (sysctl_ip_vs_conn_reused_entry == 1)
	    && (fseq->init_seq != 0)
	    && ((cp->state == IP_VS_TCP_S_SYN_RECV)
		|| (cp->state == IP_VS_TCP_S_SYN_SENT));
	if ((fseq->init_seq == 0) || conn_reused_entry) {
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			fseq->init_seq =
			    secure_tcpv6_sequence_number(cp->laddr.ip6,
							 cp->daddr.ip6,
							 cp->lport, cp->dport);
		else
#endif
			fseq->init_seq =
			    secure_tcp_sequence_number(cp->laddr.ip,
						       cp->daddr.ip, cp->lport,
						       cp->dport);
		fseq->delta = fseq->init_seq - seq;

		if (conn_reused_entry) {
			IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_CONN_REUSED);
			switch (cp->old_state) {
			case IP_VS_TCP_S_CLOSE:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_CLOSE);
				break;
			case IP_VS_TCP_S_TIME_WAIT:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_TIMEWAIT);
				break;
			case IP_VS_TCP_S_FIN_WAIT:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_FINWAIT);
				break;
			case IP_VS_TCP_S_CLOSE_WAIT:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_CLOSEWAIT);
				break;
			case IP_VS_TCP_S_LAST_ACK:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_LASTACK);
				break;
			case IP_VS_TCP_S_ESTABLISHED:
				IP_VS_INC_ESTATS(ip_vs_esmib,
						 FULLNAT_CONN_REUSED_ESTAB);
				break;
			}
		}
	}
}

/* adjust tcp sequence, OUTside to INside */
static void tcp_in_adjust_seq(struct ip_vs_conn *cp, struct tcphdr *tcph)
{
	__be32 old_seq = tcph->seq;
	/* adjust seq for FULLNAT */
	tcph->seq = htonl(ntohl(tcph->seq) + cp->fnat_seq.delta);
	/* update checksum */
	tcp_seq_csum_update(tcph, old_seq, tcph->seq);

	/* adjust ack_seq for SYNPROXY, include tcp hdr and sack opt */
	ip_vs_synproxy_dnat_handler(tcph, &cp->syn_proxy_seq);
}

/*
 * add client (ip and port) in tcp option
 * return 0 if success
 */
static int tcp_opt_add_toa(struct ip_vs_conn *cp,
				       struct sk_buff *skb,
				       struct tcphdr **tcph)
{
	__u32 mtu;
	struct ip_vs_tcpo_addr *toa;
	unsigned int tcphoff;
	struct tcphdr *th;
	__u8 *p, *q;

	/* now only process IPV4 */
	if (cp->af != AF_INET) {
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_FAIL_PROTO);
		return 1;
	}

	/* skb length and tcp option length checking */
	if (skb->_skb_dst)
		mtu = dst_mtu((struct dst_entry *)skb->_skb_dst);
	else		 /* fast_xmit can reach here */
		mtu = cp->dev_inside ? cp->dev_inside->mtu :
				sizeof(struct ip_vs_tcpo_addr);

	if (skb->len > (mtu - sizeof(struct ip_vs_tcpo_addr))) {
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_FAIL_LEN);
		return 1;
	}

	/* the maximum length of TCP head is 60 bytes, so only 40 bytes for options */
	if ((60 - ((*tcph)->doff << 2)) < sizeof(struct ip_vs_tcpo_addr)) {
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_HEAD_FULL);
		return 1;
	}

	/* expand skb if needed */
	if ((sizeof(struct ip_vs_tcpo_addr) > skb_tailroom(skb)) &&
			pskb_expand_head(skb, 0,
			sizeof(struct ip_vs_tcpo_addr), GFP_ATOMIC)){
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_FAIL_MEM);
		return 1;
	}

	/*
	 * add client ip
	 */
	tcphoff = ip_hdrlen(skb);
	/* get new tcp header */
	*tcph = th =
	    (struct tcphdr *)((void *)skb_network_header(skb) + tcphoff);

	/* ptr to old opts */
	p = skb_tail_pointer(skb) - 1;
	q = p + sizeof(struct ip_vs_tcpo_addr);

	/* move data down, offset is sizeof(struct ip_vs_tcpo_addr) */
	while (p >= ((__u8 *) th + sizeof(struct tcphdr))) {
		*q = *p;
		p--;
		q--;
	}

	/* move tail to new postion */
	skb->tail += sizeof(struct ip_vs_tcpo_addr);

	/* put client ip opt , ptr point to opts */
	toa = (struct ip_vs_tcpo_addr *)(th + 1);
	toa->opcode = TCPOPT_ADDR;
	toa->opsize = TCPOLEN_ADDR;
	toa->port = cp->cport;
	toa->addr = cp->caddr.ip;

	/* reset tcp header length */
	th->doff += sizeof(struct ip_vs_tcpo_addr) / 4;
	/* reset ip header totoal length */
	ip_hdr(skb)->tot_len =
	    htons(ntohs(ip_hdr(skb)->tot_len) +
		  sizeof(struct ip_vs_tcpo_addr));
	/* reset skb length */
	skb->len += sizeof(struct ip_vs_tcpo_addr);

	/* re-calculate tcp csum, if no csum_offload */
	if (!sysctl_ip_vs_csum_offload) {
		th->check = 0;
		skb->csum = skb_checksum(skb, tcphoff,
					skb->len - tcphoff, 0);
		th->check = csum_tcpudp_magic(cp->caddr.ip,
					cp->vaddr.ip,
					skb->len - tcphoff,
					cp->protocol, skb->csum);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			skb->ip_summed = CHECKSUM_COMPLETE;
			skb_shinfo(skb)->gso_size = 0;
		}
	}

	/* re-calculate ip head csum, tot_len has been adjusted */
	ip_send_check(ip_hdr(skb));


	IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_OK);

	return 0;
}

#ifdef CONFIG_IP_VS_IPV6
static int tcp_opt_add_toa_v6(struct ip_vs_conn *cp,
				       struct sk_buff *skb,
				       struct tcphdr **tcph)
{
	__u32 mtu;
	struct ip_vs_tcpo_addr_v6 *toa;
	unsigned int tcphoff;
	struct tcphdr *th;
	__u8 *p, *q;

	/* IPV6 */
	if (cp->af != AF_INET6) {
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_FAIL_PROTO);
		return 1;
	}

	/* skb length and tcph length checking */
	if (skb->_skb_dst)
		mtu = dst_mtu((struct dst_entry *)skb->_skb_dst);
	else		/* fast_xmit can reach here */
		mtu = cp->dev_inside ? cp->dev_inside->mtu :
				sizeof(struct ip_vs_tcpo_addr_v6);

	if (skb->len > (mtu - sizeof(struct ip_vs_tcpo_addr_v6))) {
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_FAIL_LEN);
		return 1;
	}

	/* the maximum length of TCP head is 60 bytes, so only 40 bytes for options */
	if ((60 - ((*tcph)->doff << 2)) < sizeof(struct ip_vs_tcpo_addr_v6)) {
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_HEAD_FULL);
		return 1;
	}

	/* expand skb if needed */
	if ((sizeof(struct ip_vs_tcpo_addr_v6) > skb_tailroom(skb)) &&
			pskb_expand_head(skb, 0,
			sizeof(struct ip_vs_tcpo_addr_v6), GFP_ATOMIC)){
		IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_FAIL_MEM);
		return 1;
	}

	/*
	 * add client ip
	 */
	tcphoff = sizeof(struct ipv6hdr);
	/* get new tcp header */
	*tcph = th =
	    (struct tcphdr *)((void *)skb_network_header(skb) + tcphoff);

	/* ptr to old opts */
	p = skb_tail_pointer(skb) - 1;
	q = p + sizeof(struct ip_vs_tcpo_addr_v6);

	/* move data down, offset is sizeof(struct ip_vs_tcpo_addr) */
	while (p >= ((__u8 *) th + sizeof(struct tcphdr))) {
		*q = *p;
		p--;
		q--;
	}

	/* move tail to new postion */
	skb->tail += sizeof(struct ip_vs_tcpo_addr_v6);

	/* put client ip opt , ptr point to opts */
	toa = (struct ip_vs_tcpo_addr_v6 *)(th + 1);
	toa->opcode = TCPOPT_ADDR_V6;
	toa->opsize = TCPOLEN_ADDR_V6;
	toa->port = cp->cport;
	toa->addr = cp->caddr.in6;

	/* reset tcp header length */
	th->doff += sizeof(struct ip_vs_tcpo_addr_v6) >> 2;
	/* reset ip header totoal length */
	ipv6_hdr(skb)->payload_len =
	    htons(ntohs(ipv6_hdr(skb)->payload_len) +
		  sizeof(struct ip_vs_tcpo_addr_v6));
	/* reset skb length */
	skb->len += sizeof(struct ip_vs_tcpo_addr_v6);

	/* re-calculate tcp csum, if no csum_offload */
	if (!sysctl_ip_vs_csum_offload) {
		th->check = 0;
		skb->csum = skb_checksum(skb, tcphoff,
					skb->len - tcphoff, 0);
		th->check = csum_ipv6_magic(&cp->caddr.in6,
					&cp->vaddr.in6,
					skb->len - tcphoff,
					cp->protocol, skb->csum);

		if(skb->ip_summed == CHECKSUM_PARTIAL) {
			skb->ip_summed = CHECKSUM_COMPLETE;
			skb_shinfo(skb)->gso_size = 0;
		}
	}
	IP_VS_INC_ESTATS(ip_vs_esmib, FULLNAT_ADD_TOA_OK);

	return 0;
}
#endif

static int
tcp_dnat_handler(struct sk_buff *skb,
		 struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct tcphdr *tcph;
	unsigned int tcphoff;
	int oldlen;

#ifdef CONFIG_IP_VS_IPV6
	if (cp->af == AF_INET6)
		tcphoff = sizeof(struct ipv6hdr);
	else
#endif
		tcphoff = ip_hdrlen(skb);
	oldlen = skb->len - tcphoff;

	/* csum_check requires unshared skb */
	if (!skb_make_writable(skb, tcphoff + sizeof(*tcph)))
		return 0;

	if (unlikely(cp->app != NULL)) {
		/* Some checks before mangling */
		if (pp->csum_check && !pp->csum_check(cp->af, skb, pp))
			return 0;

		/*
		 *      Attempt ip_vs_app call.
		 *      It will fix ip_vs_conn and iph ack_seq stuff
		 */
		if (!ip_vs_app_pkt_in(cp, skb))
			return 0;
	}

	tcph = (void *)skb_network_header(skb) + tcphoff;
	tcph->dest = cp->dport;

	/*
	 * Syn-proxy ack_seq change, include tcp hdr and sack opt.
	 */
	ip_vs_synproxy_dnat_handler(tcph, &cp->syn_proxy_seq);

	if (sysctl_ip_vs_csum_offload) {
		skb->csum_start = skb_network_header(skb) -
				skb->head + (ip_hdr(skb)->ihl << 2);
		skb->csum_offset = offsetof(struct tcphdr, check);
		skb->ip_summed = CHECKSUM_PARTIAL;
	}

	/*
	 *      Adjust TCP checksums
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		tcp_partial_csum_reset(cp->af, (skb->len - tcphoff),
					tcph, &cp->caddr, &cp->daddr);
	} else if (!cp->app) {
		/* Only port and addr are changed, do fast csum update */
		tcp_fast_csum_update(cp->af, tcph, &cp->vaddr, &cp->daddr,
				     cp->vport, cp->dport);
		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->ip_summed = CHECKSUM_NONE;
	} else {
		/* full checksum calculation */
		tcph->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			tcph->check = csum_ipv6_magic(&cp->caddr.in6,
						      &cp->daddr.in6,
						      skb->len - tcphoff,
						      cp->protocol, skb->csum);
		else
#endif
			tcph->check = csum_tcpudp_magic(cp->caddr.ip,
							cp->daddr.ip,
							skb->len - tcphoff,
							cp->protocol,
							skb->csum);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	return 1;
}

static int
tcp_fnat_in_handler(struct sk_buff *skb,
		    struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct tcphdr *tcph;
	unsigned int tcphoff;
	int oldlen;

#ifdef CONFIG_IP_VS_IPV6
	if (cp->af == AF_INET6)
		tcphoff = sizeof(struct ipv6hdr);
	else
#endif
		tcphoff = ip_hdrlen(skb);
	oldlen = skb->len - tcphoff;

	/* csum_check requires unshared skb */
	if (!skb_make_writable(skb, tcphoff + sizeof(*tcph)))
		return 0;

	if (unlikely(cp->app != NULL)) {
		/* Some checks before mangling */
		if (pp->csum_check && !pp->csum_check(cp->af, skb, pp))
			return 0;

		/*
		 *      Attempt ip_vs_app call.
		 *      It will fix ip_vs_conn and iph ack_seq stuff
		 */
		if (!ip_vs_app_pkt_in(cp, skb))
			return 0;
	}

	tcph = (void *)skb_network_header(skb) + tcphoff;
	/*
	 * for syn packet
	 * 1. remove tcp timestamp opt,
	 *    because local address with diffrent client have the diffrent timestamp;
	 * 2. recompute tcp sequence
	 * 3. add toa
	 */
	if (tcph->syn & !tcph->ack) {
		tcp_opt_remove_timestamp(tcph);
		tcp_in_init_seq(cp, skb, tcph);
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			tcp_opt_add_toa_v6(cp, skb, &tcph);
		else
#endif
			tcp_opt_add_toa(cp, skb, &tcph);
	}

	/* TOA: add client ip */
	if ((sysctl_ip_vs_toa_entry == 1)
	    && (ntohl(tcph->ack_seq) == cp->fnat_seq.fdata_seq)
	    && !tcph->syn && !tcph->rst && !tcph->fin) {
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			tcp_opt_add_toa_v6(cp, skb, &tcph);
		else
#endif
			tcp_opt_add_toa(cp, skb, &tcph);
	}

	/*
	 * adjust tcp sequence, becase
	 * 1. FULLNAT: local address with diffrent client have the diffrent sequence
	 * 2. SYNPROXY: dont know rs->client synack sequence
	 */
	tcp_in_adjust_seq(cp, tcph);

	/* adjust src/dst port */
	tcph->source = cp->lport;
	tcph->dest = cp->dport;

	if (sysctl_ip_vs_csum_offload) {
		skb->csum_start = skb_network_header(skb) -
				skb->head + (ip_hdr(skb)->ihl << 2);
		skb->csum_offset = offsetof(struct tcphdr, check);
		skb->ip_summed = CHECKSUM_PARTIAL;
	}

	/* Adjust TCP checksums */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		tcp_partial_csum_reset(cp->af, (skb->len - tcphoff),
					tcph, &cp->laddr, &cp->daddr);
	} else if (!cp->app) {
		/* Only port and addr are changed, do fast csum update */
		tcp_fast_csum_update(cp->af, tcph, &cp->vaddr, &cp->daddr,
				     cp->vport, cp->dport);
		tcp_fast_csum_update(cp->af, tcph, &cp->caddr, &cp->laddr,
				     cp->cport, cp->lport);
		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->ip_summed = CHECKSUM_NONE;
	} else {
		/* full checksum calculation */
		tcph->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			tcph->check = csum_ipv6_magic(&cp->laddr.in6,
						      &cp->daddr.in6,
						      skb->len - tcphoff,
						      cp->protocol, skb->csum);
		else
#endif
			tcph->check = csum_tcpudp_magic(cp->laddr.ip,
							cp->daddr.ip,
							skb->len - tcphoff,
							cp->protocol, skb->csum);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	return 1;
}

/* send reset packet to RS */
static void tcp_send_rst_in(struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct sk_buff *skb = NULL;
	struct sk_buff *tmp_skb = NULL;
	struct tcphdr *th;
	unsigned int tcphoff;

	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (unlikely(skb == NULL)) {
		IP_VS_ERR_RL("alloc skb failed when send rs RST packet\n");
		return;
	}

	skb_reserve(skb, MAX_TCP_HEADER);
	th = (struct tcphdr *)skb_push(skb, sizeof(struct tcphdr));
	skb_reset_transport_header(skb);
	skb->csum = 0;

	/* set tcp head */
	memset(th, 0, sizeof(struct tcphdr));
	th->source = cp->cport;
	th->dest = cp->vport;

	/* set the reset seq of tcp head */
	if ((cp->state == IP_VS_TCP_S_SYN_SENT) &&
			((tmp_skb = skb_dequeue(&cp->ack_skb)) != NULL)) {
		struct tcphdr *tcph;
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			tcphoff = sizeof(struct ipv6hdr);
		else
#endif
			tcphoff = ip_hdrlen(tmp_skb);
		tcph = (void *)skb_network_header(tmp_skb) + tcphoff;

		th->seq = tcph->seq;
		/* put back. Just for sending reset packet to client */
		skb_queue_head(&cp->ack_skb, tmp_skb);
		IP_VS_INC_ESTATS(ip_vs_esmib, RST_IN_SYN_SENT);
	} else if (cp->state == IP_VS_TCP_S_ESTABLISHED) {
		th->seq = cp->rs_ack_seq;
		/* Be careful! fullnat */
		if (cp->flags & IP_VS_CONN_F_FULLNAT)
			th->seq = htonl(ntohl(th->seq) - cp->fnat_seq.delta);

		IP_VS_INC_ESTATS(ip_vs_esmib, RST_IN_ESTABLISHED);
	} else {
		kfree_skb(skb);
		IP_VS_DBG_RL("IPVS: Is SYN_SENT or ESTABLISHED ?");
		return;
	}

	IP_VS_DBG_RL("IPVS: rst to rs seq: %u", htonl(th->seq));
	th->ack_seq = 0;
	th->doff = sizeof(struct tcphdr) >> 2;
	th->rst = 1;

	/*
	 * Set ip hdr
	 * Attention: set source and dest addr to ack skb's.
	 * we rely on packet_xmit func to do NATs thing.
	 */
#ifdef CONFIG_IP_VS_IPV6
	if (cp->af == AF_INET6) {
		struct ipv6hdr *iph =
		    (struct ipv6hdr *)skb_push(skb, sizeof(struct ipv6hdr));

		tcphoff = sizeof(struct ipv6hdr);
		skb_reset_network_header(skb);
		memcpy(&iph->saddr, &cp->caddr.in6, sizeof(struct in6_addr));
		memcpy(&iph->daddr, &cp->vaddr.in6, sizeof(struct in6_addr));

		iph->version = 6;
		iph->nexthdr = NEXTHDR_TCP;
		iph->hop_limit = IPV6_DEFAULT_HOPLIMIT;
		iph->payload_len = htons(sizeof(struct tcphdr));

		th->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
		th->check = csum_ipv6_magic(&iph->saddr, &iph->daddr,
					    skb->len - tcphoff,
					    IPPROTO_TCP, skb->csum);
	} else
#endif
	{
		struct iphdr *iph =
		    (struct iphdr *)skb_push(skb, sizeof(struct iphdr));

		tcphoff = sizeof(struct iphdr);
		skb_reset_network_header(skb);
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = 0;
		iph->tot_len = htons(skb->len);
		iph->frag_off = htons(IP_DF);
		iph->ttl = IPDEFTTL;
		iph->protocol = IPPROTO_TCP;
		iph->saddr = cp->caddr.ip;
		iph->daddr = cp->vaddr.ip;

		ip_send_check(iph);

		th->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
		th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					      skb->len - tcphoff,
					      IPPROTO_TCP, skb->csum);
	}

	cp->packet_xmit(skb, cp, pp);
}

/* send reset packet to client */
static void tcp_send_rst_out(struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct sk_buff *skb = NULL;
	struct sk_buff *tmp_skb = NULL;
	struct tcphdr *th;
	unsigned int tcphoff;

	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (unlikely(skb == NULL)) {
		IP_VS_ERR_RL("alloc skb failed when send client RST packet\n");
		return;
	}

	skb_reserve(skb, MAX_TCP_HEADER);
	th = (struct tcphdr *)skb_push(skb, sizeof(struct tcphdr));
	skb_reset_transport_header(skb);
	skb->csum = 0;

	/* set tcp head */
	memset(th, 0, sizeof(struct tcphdr));
	th->source = cp->dport;
	if (cp->flags & IP_VS_CONN_F_FULLNAT)
		th->dest = cp->lport;
	else
		th->dest = cp->cport;

	/* set the reset seq of tcp head*/
	if ((cp->state == IP_VS_TCP_S_SYN_SENT) &&
			((tmp_skb = skb_dequeue(&cp->ack_skb)) != NULL)) {
		struct tcphdr *tcph;
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			tcphoff = sizeof(struct ipv6hdr);
		else
#endif
			tcphoff = ip_hdrlen(tmp_skb);
		tcph = (void *)skb_network_header(tmp_skb) + tcphoff;
		/* Perhaps delta is 0 */
		th->seq = htonl(ntohl(tcph->ack_seq) - cp->syn_proxy_seq.delta);
		/* put back. Just for sending reset packet to RS */
		skb_queue_head(&cp->ack_skb, tmp_skb);
		IP_VS_INC_ESTATS(ip_vs_esmib, RST_OUT_SYN_SENT);
	} else if (cp->state == IP_VS_TCP_S_ESTABLISHED) {
		th->seq = cp->rs_end_seq;
		IP_VS_INC_ESTATS(ip_vs_esmib, RST_OUT_ESTABLISHED);
	} else {
		kfree_skb(skb);
		IP_VS_DBG_RL("IPVS: Is in SYN_SENT or ESTABLISHED ?");
		return;
	}

	IP_VS_DBG_RL("IPVS: rst to client seq: %u", htonl(th->seq));
	th->ack_seq = 0;
	th->doff = sizeof(struct tcphdr) >> 2;
	th->rst = 1;

	/*
	 * Set ip hdr
	 * Attention: set source and dest addr to ack skb's.
	 * we rely on response_xmit func to do NATs thing.
	 */
#ifdef CONFIG_IP_VS_IPV6
	if (cp->af == AF_INET6) {
		struct ipv6hdr *iph =
		    (struct ipv6hdr *)skb_push(skb, sizeof(struct ipv6hdr));

		tcphoff = sizeof(struct ipv6hdr);
		skb_reset_network_header(skb);
		memcpy(&iph->saddr, &cp->daddr.in6, sizeof(struct in6_addr));
		memcpy(&iph->daddr, &cp->laddr.in6, sizeof(struct in6_addr));

		iph->version = 6;
		iph->nexthdr = NEXTHDR_TCP;
		iph->hop_limit = IPV6_DEFAULT_HOPLIMIT;
		iph->payload_len = htons(sizeof(struct tcphdr));

		th->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
		th->check = csum_ipv6_magic(&iph->saddr, &iph->daddr,
					    skb->len - tcphoff,
					    IPPROTO_TCP, skb->csum);

		if (cp->flags & IP_VS_CONN_F_FULLNAT)
			ip_vs_fnat_response_xmit_v6(skb, pp, cp,
						    sizeof(struct ipv6hdr));
		else
			ip_vs_normal_response_xmit_v6(skb, pp, cp,
						      sizeof(struct ipv6hdr));
	} else
#endif
	{
		struct iphdr *iph =
		    (struct iphdr *)skb_push(skb, sizeof(struct iphdr));

		tcphoff = sizeof(struct iphdr);
		skb_reset_network_header(skb);
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = 0;
		iph->tot_len = htons(skb->len);
		iph->frag_off = htons(IP_DF);
		iph->ttl = IPDEFTTL;
		iph->protocol = IPPROTO_TCP;
		iph->saddr = cp->daddr.ip;
		iph->daddr = cp->laddr.ip;

		ip_send_check(iph);

		th->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
		th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					      skb->len - tcphoff,
					      IPPROTO_TCP, skb->csum);

		if (cp->flags & IP_VS_CONN_F_FULLNAT)
			ip_vs_fnat_response_xmit(skb, pp, cp, iph->ihl << 2);
		else
			ip_vs_normal_response_xmit(skb, pp, cp, iph->ihl << 2);
	}
}

static void
tcp_conn_expire_handler(struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	/* support fullnat and nat */
	if (sysctl_ip_vs_conn_expire_tcp_rst &&
	    (cp->flags & (IP_VS_CONN_F_FULLNAT | IP_VS_CONN_F_MASQ))) {
		/* send reset packet to RS */
		tcp_send_rst_in(pp, cp);
		/* send reset packet to client */
		tcp_send_rst_out(pp, cp);
	}
}

static int
tcp_csum_check(int af, struct sk_buff *skb, struct ip_vs_protocol *pp)
{
	unsigned int tcphoff;

#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		tcphoff = sizeof(struct ipv6hdr);
	else
#endif
		tcphoff = ip_hdrlen(skb);

	switch (skb->ip_summed) {
	case CHECKSUM_NONE:
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
	case CHECKSUM_COMPLETE:
#ifdef CONFIG_IP_VS_IPV6
		if (af == AF_INET6) {
			if (csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
					    &ipv6_hdr(skb)->daddr,
					    skb->len - tcphoff,
					    ipv6_hdr(skb)->nexthdr,
					    skb->csum)) {
				IP_VS_DBG_RL_PKT(0, pp, skb, 0,
						 "Failed checksum for");
				return 0;
			}
		} else
#endif
		if (csum_tcpudp_magic(ip_hdr(skb)->saddr,
					      ip_hdr(skb)->daddr,
					      skb->len - tcphoff,
					      ip_hdr(skb)->protocol,
					      skb->csum)) {
			IP_VS_DBG_RL_PKT(0, pp, skb, 0, "Failed checksum for");
			return 0;
		}
		break;
	default:
		/* No need to checksum. */
		break;
	}

	return 1;
}

#define TCP_DIR_INPUT		0
#define TCP_DIR_OUTPUT		4
#define TCP_DIR_INPUT_ONLY	8

static const int tcp_state_off[IP_VS_DIR_LAST] = {
	[IP_VS_DIR_INPUT] = TCP_DIR_INPUT,
	[IP_VS_DIR_OUTPUT] = TCP_DIR_OUTPUT,
	[IP_VS_DIR_INPUT_ONLY] = TCP_DIR_INPUT_ONLY,
};

/*
 *	Timeout table[state]
 */
int sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_LAST + 1] = {
	[IP_VS_TCP_S_NONE] = 2 * HZ,
	[IP_VS_TCP_S_ESTABLISHED] = 90 * HZ,
	[IP_VS_TCP_S_SYN_SENT] = 3 * HZ,
	[IP_VS_TCP_S_SYN_RECV] = 30 * HZ,
	[IP_VS_TCP_S_FIN_WAIT] = 7 * HZ,
	[IP_VS_TCP_S_TIME_WAIT] = 7 * HZ,
	[IP_VS_TCP_S_CLOSE] = 3 * HZ,
	[IP_VS_TCP_S_CLOSE_WAIT] = 7 * HZ,
	[IP_VS_TCP_S_LAST_ACK] = 7 * HZ,
	[IP_VS_TCP_S_LISTEN] = 2 * 60 * HZ,
	[IP_VS_TCP_S_SYNACK] = 30 * HZ,
	[IP_VS_TCP_S_LAST] = 2 * HZ,
};

static const char *const tcp_state_name_table[IP_VS_TCP_S_LAST + 1] = {
	[IP_VS_TCP_S_NONE] = "NONE",
	[IP_VS_TCP_S_ESTABLISHED] = "ESTABLISHED",
	[IP_VS_TCP_S_SYN_SENT] = "SYN_SENT",
	[IP_VS_TCP_S_SYN_RECV] = "SYN_RECV",
	[IP_VS_TCP_S_FIN_WAIT] = "FIN_WAIT",
	[IP_VS_TCP_S_TIME_WAIT] = "TIME_WAIT",
	[IP_VS_TCP_S_CLOSE] = "CLOSE",
	[IP_VS_TCP_S_CLOSE_WAIT] = "CLOSE_WAIT",
	[IP_VS_TCP_S_LAST_ACK] = "LAST_ACK",
	[IP_VS_TCP_S_LISTEN] = "LISTEN",
	[IP_VS_TCP_S_SYNACK] = "SYNACK",
	[IP_VS_TCP_S_LAST] = "BUG!",
};

#define sNO IP_VS_TCP_S_NONE
#define sES IP_VS_TCP_S_ESTABLISHED
#define sSS IP_VS_TCP_S_SYN_SENT
#define sSR IP_VS_TCP_S_SYN_RECV
#define sFW IP_VS_TCP_S_FIN_WAIT
#define sTW IP_VS_TCP_S_TIME_WAIT
#define sCL IP_VS_TCP_S_CLOSE
#define sCW IP_VS_TCP_S_CLOSE_WAIT
#define sLA IP_VS_TCP_S_LAST_ACK
#define sLI IP_VS_TCP_S_LISTEN
#define sSA IP_VS_TCP_S_SYNACK

struct tcp_states_t {
	int next_state[IP_VS_TCP_S_LAST];
};

static const char *tcp_state_name(int state)
{
	if (state >= IP_VS_TCP_S_LAST)
		return "ERR!";
	return tcp_state_name_table[state] ? tcp_state_name_table[state] : "?";
}

static struct tcp_states_t tcp_states[] = {
/*	INPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR}},
/*fin*/ {{sCL, sCW, sSS, sTW, sTW, sTW, sCL, sCW, sLA, sLI, sTW}},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sSR}},

/*	OUTPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSS, sES, sSS, sSR, sSS, sSS, sSS, sSS, sSS, sLI, sSR}},
/*fin*/ {{sTW, sFW, sSS, sTW, sFW, sTW, sCL, sTW, sLA, sLI, sTW}},
/*ack*/ {{sES, sES, sSS, sES, sFW, sTW, sCL, sCW, sLA, sES, sES}},
/*rst*/ {{sCL, sCL, sSS, sCL, sCL, sTW, sCL, sCL, sCL, sCL, sCL}},

/*	INPUT-ONLY */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR}},
/*fin*/ {{sCL, sFW, sSS, sTW, sFW, sTW, sCL, sCW, sLA, sLI, sTW}},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sCL}},
};

static struct tcp_states_t tcp_states_dos[] = {
/*	INPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSA}},
/*fin*/ {{sCL, sCW, sSS, sTW, sTW, sTW, sCL, sCW, sLA, sLI, sSA}},
/*ack*/ {{sCL, sES, sSS, sSR, sFW, sTW, sCL, sCW, sCL, sLI, sSA}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sCL}},

/*	OUTPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSS, sES, sSS, sSA, sSS, sSS, sSS, sSS, sSS, sLI, sSA}},
/*fin*/ {{sTW, sFW, sSS, sTW, sFW, sTW, sCL, sTW, sLA, sLI, sTW}},
/*ack*/ {{sES, sES, sSS, sES, sFW, sTW, sCL, sCW, sLA, sES, sES}},
/*rst*/ {{sCL, sCL, sSS, sCL, sCL, sTW, sCL, sCL, sCL, sCL, sCL}},

/*	INPUT-ONLY */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSA, sES, sES, sSR, sSA, sSA, sSA, sSA, sSA, sSA, sSA}},
/*fin*/ {{sCL, sFW, sSS, sTW, sFW, sTW, sCL, sCW, sLA, sLI, sTW}},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sCL}},
};

static struct tcp_states_t *tcp_state_table = tcp_states;

static void tcp_timeout_change(struct ip_vs_protocol *pp, int flags)
{
	int on = (flags & 1);	/* secure_tcp */

	/*
	 ** FIXME: change secure_tcp to independent sysctl var
	 ** or make it per-service or per-app because it is valid
	 ** for most if not for all of the applications. Something
	 ** like "capabilities" (flags) for each object.
	 */
	tcp_state_table = (on ? tcp_states_dos : tcp_states);
}

static int tcp_set_state_timeout(struct ip_vs_protocol *pp, char *sname, int to)
{
	return ip_vs_set_state_timeout(pp->timeout_table, IP_VS_TCP_S_LAST,
				       tcp_state_name_table, sname, to);
}

static inline int tcp_state_idx(struct tcphdr *th)
{
	if (th->rst)
		return 3;
	if (th->syn)
		return 0;
	if (th->fin)
		return 1;
	if (th->ack)
		return 2;
	return -1;
}

static inline void
set_tcp_state(struct ip_vs_protocol *pp, struct ip_vs_conn *cp,
	      int direction, struct tcphdr *th)
{
	int state_idx;
	int new_state = IP_VS_TCP_S_CLOSE;
	int state_off = tcp_state_off[direction];

	/*
	 *    Update state offset to INPUT_ONLY if necessary
	 *    or delete NO_OUTPUT flag if output packet detected
	 */
	if (cp->flags & IP_VS_CONN_F_NOOUTPUT) {
		if (state_off == TCP_DIR_OUTPUT)
			cp->flags &= ~IP_VS_CONN_F_NOOUTPUT;
		else
			state_off = TCP_DIR_INPUT_ONLY;
	}

	if ((state_idx = tcp_state_idx(th)) < 0) {
		IP_VS_DBG(8, "tcp_state_idx=%d!!!\n", state_idx);
		goto tcp_state_out;
	}

	new_state =
	    tcp_state_table[state_off + state_idx].next_state[cp->state];

      tcp_state_out:
	if (new_state != cp->state) {
		struct ip_vs_dest *dest = cp->dest;

		IP_VS_DBG_BUF(8, "%s %s [%c%c%c%c] %s:%d->"
			      "%s:%d state: %s->%s conn->refcnt:%d\n",
			      pp->name,
			      ((state_off == TCP_DIR_OUTPUT) ?
			       "output " : "input "),
			      th->syn ? 'S' : '.',
			      th->fin ? 'F' : '.',
			      th->ack ? 'A' : '.',
			      th->rst ? 'R' : '.',
			      IP_VS_DBG_ADDR(cp->af, &cp->daddr),
			      ntohs(cp->dport),
			      IP_VS_DBG_ADDR(cp->af, &cp->caddr),
			      ntohs(cp->cport),
			      tcp_state_name(cp->state),
			      tcp_state_name(new_state),
			      atomic_read(&cp->refcnt));

		if (dest) {
			if (!(cp->flags & IP_VS_CONN_F_INACTIVE) &&
			    (new_state != IP_VS_TCP_S_ESTABLISHED)) {
				atomic_dec(&dest->activeconns);
				atomic_inc(&dest->inactconns);
				cp->flags |= IP_VS_CONN_F_INACTIVE;
			} else if ((cp->flags & IP_VS_CONN_F_INACTIVE) &&
				   (new_state == IP_VS_TCP_S_ESTABLISHED)) {
				atomic_inc(&dest->activeconns);
				atomic_dec(&dest->inactconns);
				cp->flags &= ~IP_VS_CONN_F_INACTIVE;
			}
		}
	}

	cp->old_state = cp->state;	// old_state called when connection reused
	cp->timeout = ((cp->state = new_state) == IP_VS_TCP_S_ESTABLISHED) ?
							cp->est_timeout : sysctl_ip_vs_tcp_timeouts[new_state];
}

/*
 *	Handle state transitions
 */
static int
tcp_state_transition(struct ip_vs_conn *cp, int direction,
		     const struct sk_buff *skb, struct ip_vs_protocol *pp)
{
	struct tcphdr _tcph, *th;

#ifdef CONFIG_IP_VS_IPV6
	int ihl = cp->af == AF_INET ? ip_hdrlen(skb) : sizeof(struct ipv6hdr);
#else
	int ihl = ip_hdrlen(skb);
#endif

	th = skb_header_pointer(skb, ihl, sizeof(_tcph), &_tcph);
	if (th == NULL)
		return 0;

	spin_lock(&cp->lock);
	set_tcp_state(pp, cp, direction, th);
	spin_unlock(&cp->lock);

	return 1;
}

/*
 *	Hash table for TCP application incarnations
 */
#define	TCP_APP_TAB_BITS	4
#define	TCP_APP_TAB_SIZE	(1 << TCP_APP_TAB_BITS)
#define	TCP_APP_TAB_MASK	(TCP_APP_TAB_SIZE - 1)

static struct list_head tcp_apps[TCP_APP_TAB_SIZE];
static DEFINE_SPINLOCK(tcp_app_lock);

static inline __u16 tcp_app_hashkey(__be16 port)
{
	return (((__force u16) port >> TCP_APP_TAB_BITS) ^ (__force u16) port)
	    & TCP_APP_TAB_MASK;
}

static int tcp_register_app(struct ip_vs_app *inc)
{
	struct ip_vs_app *i;
	__u16 hash;
	__be16 port = inc->port;
	int ret = 0;

	hash = tcp_app_hashkey(port);

	spin_lock_bh(&tcp_app_lock);
	list_for_each_entry(i, &tcp_apps[hash], p_list) {
		if (i->port == port) {
			ret = -EEXIST;
			goto out;
		}
	}
	list_add(&inc->p_list, &tcp_apps[hash]);
	atomic_inc(&ip_vs_protocol_tcp.appcnt);

      out:
	spin_unlock_bh(&tcp_app_lock);
	return ret;
}

static void tcp_unregister_app(struct ip_vs_app *inc)
{
	spin_lock_bh(&tcp_app_lock);
	atomic_dec(&ip_vs_protocol_tcp.appcnt);
	list_del(&inc->p_list);
	spin_unlock_bh(&tcp_app_lock);
}

static int tcp_app_conn_bind(struct ip_vs_conn *cp)
{
	int hash;
	struct ip_vs_app *inc;
	int result = 0;

	/* Default binding: bind app only for NAT */
	if (IP_VS_FWD_METHOD(cp) != IP_VS_CONN_F_MASQ)
		return 0;

	/* Lookup application incarnations and bind the right one */
	hash = tcp_app_hashkey(cp->vport);

	spin_lock(&tcp_app_lock);
	list_for_each_entry(inc, &tcp_apps[hash], p_list) {
		if (inc->port == cp->vport) {
			if (unlikely(!ip_vs_app_inc_get(inc)))
				break;
			spin_unlock(&tcp_app_lock);

			IP_VS_DBG_BUF(9, "%s(): Binding conn %s:%u->"
				      "%s:%u to app %s on port %u\n",
				      __func__,
				      IP_VS_DBG_ADDR(cp->af, &cp->caddr),
				      ntohs(cp->cport),
				      IP_VS_DBG_ADDR(cp->af, &cp->vaddr),
				      ntohs(cp->vport),
				      inc->name, ntohs(inc->port));

			cp->app = inc;
			if (inc->init_conn)
				result = inc->init_conn(inc, cp);
			goto out;
		}
	}
	spin_unlock(&tcp_app_lock);

      out:
	return result;
}

/*
 *	Set LISTEN timeout. (ip_vs_conn_put will setup timer)
 */
void ip_vs_tcp_conn_listen(struct ip_vs_conn *cp)
{
	spin_lock(&cp->lock);
	cp->state = IP_VS_TCP_S_LISTEN;
	cp->timeout = ip_vs_protocol_tcp.timeout_table[IP_VS_TCP_S_LISTEN];
	spin_unlock(&cp->lock);
}

static void ip_vs_tcp_init(struct ip_vs_protocol *pp)
{
	IP_VS_INIT_HASH_TABLE(tcp_apps);
	pp->timeout_table = sysctl_ip_vs_tcp_timeouts;
}

static void ip_vs_tcp_exit(struct ip_vs_protocol *pp)
{
}

struct ip_vs_protocol ip_vs_protocol_tcp = {
	.name = "TCP",
	.protocol = IPPROTO_TCP,
	.num_states = IP_VS_TCP_S_LAST,
	.dont_defrag = 0,
	.appcnt = ATOMIC_INIT(0),
	.init = ip_vs_tcp_init,
	.exit = ip_vs_tcp_exit,
	.register_app = tcp_register_app,
	.unregister_app = tcp_unregister_app,
	.conn_schedule = tcp_conn_schedule,
	.conn_in_get = tcp_conn_in_get,
	.conn_out_get = tcp_conn_out_get,
	.snat_handler = tcp_snat_handler,
	.dnat_handler = tcp_dnat_handler,
	.fnat_in_handler = tcp_fnat_in_handler,
	.fnat_out_handler = tcp_fnat_out_handler,
	.csum_check = tcp_csum_check,
	.state_name = tcp_state_name,
	.state_transition = tcp_state_transition,
	.app_conn_bind = tcp_app_conn_bind,
	.debug_packet = ip_vs_tcpudp_debug_packet,
	.timeout_change = tcp_timeout_change,
	.set_state_timeout = tcp_set_state_timeout,
	.conn_expire_handler = tcp_conn_expire_handler,
};
