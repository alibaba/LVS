#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/tcp.h>
#include <linux/if_arp.h>
#include <linux/cryptohash.h>
#include <linux/random.h>

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

/*
 * syncookies using MD5 algorithm
 */
static u32 net_secret[2][MD5_MESSAGE_BYTES / 4] ____cacheline_aligned;

int ip_vs_net_secret_init(void)
{
        get_random_bytes(net_secret, sizeof(net_secret));
        return 0;
}

#define COOKIEBITS 24   /* Upper bits store count */
#define COOKIEMASK (((__u32)1 << COOKIEBITS) - 1)

static u32 cookie_hash(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
                        u32 count, int c)
{
        u32 hash[MD5_DIGEST_WORDS];
        hash[0] = (__force u32)saddr;
        hash[1] = (__force u32)daddr;
        hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
        hash[3] = count;

        md5_transform(hash, net_secret[c]);

        return hash[0];
}

static __u32 secure_tcp_syn_cookie(__be32 saddr, __be32 daddr, __be16 sport,
                                   __be16 dport, __u32 sseq, __u32 count,
                                   __u32 data)
{
        /*
         * Compute the secure sequence number.
         * The output should be:
         *   HASH(sec1,saddr,sport,daddr,dport,sec1) + sseq + (count * 2^24)
         *      + (HASH(sec2,saddr,sport,daddr,dport,count,sec2) % 2^24).
         * Where sseq is their sequence number and count increases every
         * minute by 1.
         * As an extra hack, we add a small "data" value that encodes the
         * MSS into the second hash value.
         */

        return (cookie_hash(saddr, daddr, sport, dport, 0, 0) +
                sseq + (count << COOKIEBITS) +
                ((cookie_hash(saddr, daddr, sport, dport, count, 1) + data)
                 & COOKIEMASK));
}

/*
 * This retrieves the small "data" value from the syncookie.
 * If the syncookie is bad, the data returned will be out of
 * range.  This must be checked by the caller.
 *
 * The count value used to generate the cookie must be within
 * "maxdiff" if the current (passed-in) "count".  The return value
 * is (__u32)-1 if this test fails.
 */
static __u32 check_tcp_syn_cookie(__u32 cookie, __be32 saddr, __be32 daddr,
                                  __be16 sport, __be16 dport, __u32 sseq,
                                  __u32 count, __u32 maxdiff)
{
        __u32 diff;

        /* Strip away the layers from the cookie */
        cookie -= cookie_hash(saddr, daddr, sport, dport, 0, 0) + sseq;

        /* Cookie is now reduced to (count * 2^24) ^ (hash % 2^24) */
        diff = (count - (cookie >> COOKIEBITS)) & ((__u32) - 1 >> COOKIEBITS);
        if (diff >= maxdiff)
                return (__u32)-1;

        return (cookie -
                cookie_hash(saddr, daddr, sport, dport, count - diff, 1))
                & COOKIEMASK;   /* Leaving the data behind */
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static u32 cookie_hash_v6(struct in6_addr *saddr, struct in6_addr *daddr,
                       __be16 sport, __be16 dport, u32 count, int c)
{
        u32 secret[MD5_MESSAGE_BYTES / 4];
        u32 hash[MD5_DIGEST_WORDS];
        u32 i;

        memcpy(hash, saddr, 16);
        for (i = 0; i < 4; i++)
                secret[i] = net_secret[c][i] + ((__force u32 *)daddr)[i];

        secret[4] = net_secret[c][4] +
                (((__force u16)sport << 16) + (__force u16)dport);

        secret[5] = net_secret[c][5] + count;

        for (i = 6; i < MD5_MESSAGE_BYTES / 4; i++)
                secret[i] = net_secret[c][i];

        md5_transform(hash, secret);

        return hash[0];
}

static __u32 secure_tcp_syn_cookie_v6(struct in6_addr *saddr, struct in6_addr *daddr,
                                   __be16 sport, __be16 dport, __u32 sseq,
                                   __u32 count, __u32 data)
{
        return (cookie_hash_v6(saddr, daddr, sport, dport, 0, 0) +
                sseq + (count << COOKIEBITS) +
                ((cookie_hash_v6(saddr, daddr, sport, dport, count, 1) + data)
                & COOKIEMASK));
}

static __u32 check_tcp_syn_cookie_v6(__u32 cookie, struct in6_addr *saddr,
                                  struct in6_addr *daddr, __be16 sport,
                                  __be16 dport, __u32 sseq, __u32 count,
                                  __u32 maxdiff)
{
        __u32 diff;

        cookie -= cookie_hash_v6(saddr, daddr, sport, dport, 0, 0) + sseq;

        diff = (count - (cookie >> COOKIEBITS)) & ((__u32) -1 >> COOKIEBITS);
        if (diff >= maxdiff)
                return (__u32)-1;

        return (cookie -
                cookie_hash_v6(saddr, daddr, sport, dport, count - diff, 1))
                & COOKIEMASK;
}
#endif

/*
 * This table has to be sorted and terminated with (__u16)-1.
 * XXX generate a better table.
 * Unresolved Issues: HIPPI with a 64k MSS is not well supported.
 */
static __u16 const msstab[] = {
        64 - 1,
        256 - 1,
        512 - 1,
        536 - 1,
        1024 - 1,
        1280 - 1,
        1440 - 1,
        1452 - 1,
        1460 - 1,
        4312 - 1,
        (__u16)-1
};
/* The number doesn't include the -1 terminator */
#define NUM_MSS (ARRAY_SIZE(msstab) - 1)

/*
 * This (misnamed) value is the age of syncookie which is permitted.
 * Its ideal value should be dependent on TCP_TIMEOUT_INIT and
 * sysctl_tcp_retries1. It's a rather complicated formula (exponential
 * backoff) to compute at runtime so it's currently hardcoded here.
 */
#define COUNTER_TRIES 4

/*
 * Generate a syncookie for ip_vs module.
 * Besides mss, we store additional tcp options in cookie "data".
 *
 * Cookie "data" format:
 * |[21][20][19-16][15-0]|
 * [21] SACKOK
 * [20] TimeStampOK
 * [19-16] snd_wscale
 * [15-12] MSSIND
 */
static __u32 syn_proxy_cookie_v4_init_sequence(struct sk_buff *skb,
                                             struct ip_vs_synproxy_opt *opts)
{
        const struct iphdr *iph = ip_hdr(skb);
        const struct tcphdr *th = tcp_hdr(skb);
        int mssind;
        const __u16 mss = opts->mss_clamp;
        __u32 data = 0;

        /* XXX sort msstab[] by probability?  Binary search? */
        for (mssind = 0; mss > msstab[mssind + 1]; mssind++)
                ;
        opts->mss_clamp = msstab[mssind] + 1;

        data = ((mssind & 0x0f) << IP_VS_SYNPROXY_MSS_BITS);
        data |= opts->sack_ok << IP_VS_SYNPROXY_SACKOK_BIT;
        data |= opts->tstamp_ok << IP_VS_SYNPROXY_TSOK_BIT;
        data |= ((opts->snd_wscale & 0x0f) << IP_VS_SYNPROXY_SND_WSCALE_BITS);

        return secure_tcp_syn_cookie(iph->saddr, iph->daddr,
                                     th->source, th->dest, ntohl(th->seq),
                                     jiffies / (HZ * 60), data);
}

/*
 * when syn_proxy_cookie_v4_init_sequence is used, we check
 * cookie as follow:
 *  1. mssind check.
 *  2. get sack/timestamp/wscale options.
 */
static int syn_proxy_v4_cookie_check(struct sk_buff *skb, __u32 cookie,
                              struct ip_vs_synproxy_opt *opt)
{
        const struct iphdr *iph = ip_hdr(skb);
        const struct tcphdr *th = tcp_hdr(skb);
        __u32 seq = ntohl(th->seq) - 1;
        __u32 mssind;
        int   ret = 0;
        __u32 res = check_tcp_syn_cookie(cookie, iph->saddr, iph->daddr,
                                         th->source, th->dest, seq,
                                         jiffies / (HZ * 60),
                                         COUNTER_TRIES);

        if(res == (__u32)-1) /* count is invalid, jiffies' >> jiffies */
                goto out;

        mssind = (res & IP_VS_SYNPROXY_MSS_MASK) >> IP_VS_SYNPROXY_MSS_BITS;

        memset(opt, 0, sizeof(struct ip_vs_synproxy_opt));
        if ((mssind < NUM_MSS) && ((res & IP_VS_SYNPROXY_OTHER_MASK) == 0)) {
                opt->mss_clamp = msstab[mssind] + 1;
                opt->sack_ok = (res & IP_VS_SYNPROXY_SACKOK_MASK) >>
                                        IP_VS_SYNPROXY_SACKOK_BIT;
                opt->tstamp_ok = (res & IP_VS_SYNPROXY_TSOK_MASK) >>
                                        IP_VS_SYNPROXY_TSOK_BIT;
                opt->snd_wscale = (res & IP_VS_SYNPROXY_SND_WSCALE_MASK) >>
                                        IP_VS_SYNPROXY_SND_WSCALE_BITS;
                if (opt->snd_wscale > 0 &&
                    opt->snd_wscale <= IP_VS_SYNPROXY_WSCALE_MAX)
                        opt->wscale_ok = 1;
                else if (opt->snd_wscale == 0)
                        opt->wscale_ok = 0;
                else
                        goto out;

                ret = 1;
        }

out:    return ret;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static __u32 syn_proxy_cookie_v6_init_sequence(struct sk_buff *skb,
                                             struct ip_vs_synproxy_opt *opts)
{
        struct ipv6hdr *iph = ipv6_hdr(skb);
        const struct tcphdr *th = tcp_hdr(skb);
        int mssind;
        const __u16 mss = opts->mss_clamp;
        __u32 data = 0;

        /* XXX sort msstab[] by probability?  Binary search? */
        for (mssind = 0; mss > msstab[mssind + 1]; mssind++)
                ;
        opts->mss_clamp = msstab[mssind] + 1;

        data = ((mssind & 0x0f) << IP_VS_SYNPROXY_MSS_BITS);
        data |= opts->sack_ok << IP_VS_SYNPROXY_SACKOK_BIT;
        data |= opts->tstamp_ok << IP_VS_SYNPROXY_TSOK_BIT;
        data |= ((opts->snd_wscale & 0x0f) << IP_VS_SYNPROXY_SND_WSCALE_BITS);

        return secure_tcp_syn_cookie_v6(&iph->saddr, &iph->daddr,
                                     th->source, th->dest, ntohl(th->seq),
                                     jiffies / (HZ * 60), data);
}

int syn_proxy_v6_cookie_check(struct sk_buff * skb, __u32 cookie,
                              struct ip_vs_synproxy_opt * opt)
{
        struct ipv6hdr *iph = ipv6_hdr(skb);
        const struct tcphdr *th = tcp_hdr(skb);
        __u32 seq = ntohl(th->seq) - 1;
        __u32 mssind;
        int   ret = 0;
        __u32 res = check_tcp_syn_cookie_v6(cookie, &iph->saddr, &iph->daddr,
                                         th->source, th->dest, seq,
                                         jiffies / (HZ * 60),
                                         COUNTER_TRIES);

        if(res == (__u32)-1) /* count is invalid, jiffies' >> jiffies */
                goto out;

        mssind = (res & IP_VS_SYNPROXY_MSS_MASK) >> IP_VS_SYNPROXY_MSS_BITS;

        memset(opt, 0, sizeof(struct ip_vs_synproxy_opt));

        if ((mssind < NUM_MSS) && ((res & IP_VS_SYNPROXY_OTHER_MASK) == 0)) {
                opt->mss_clamp = msstab[mssind] + 1;
                opt->sack_ok = (res & IP_VS_SYNPROXY_SACKOK_MASK) >>
                                        IP_VS_SYNPROXY_SACKOK_BIT;
                opt->tstamp_ok = (res & IP_VS_SYNPROXY_TSOK_MASK) >>
                                        IP_VS_SYNPROXY_TSOK_BIT;
                opt->snd_wscale = (res & IP_VS_SYNPROXY_SND_WSCALE_MASK) >>
                                        IP_VS_SYNPROXY_SND_WSCALE_BITS;
                if (opt->snd_wscale > 0 &&
                    opt->snd_wscale <= IP_VS_SYNPROXY_WSCALE_MAX)
                        opt->wscale_ok = 1;
                else if (opt->snd_wscale == 0)
                        opt->wscale_ok = 0;
                else
                        goto out;

                ret = 1;
        }

out:    return ret;
}
#endif

/*
 * synproxy implementation
 */


static inline void
syn_proxy_seq_csum_update(struct tcphdr *tcph, __u32 old_seq, __u32 new_seq)
{
	/* do checksum later */
	if (!sysctl_ip_vs_csum_offload)
		tcph->check = csum_fold(ip_vs_check_diff4(old_seq, new_seq,
						  ~csum_unfold(tcph->check)));
}

/*
 * Replace tcp options in tcp header, called by syn_proxy_reuse_skb()
 *
 */
static void
syn_proxy_parse_set_opts(struct sk_buff *skb, struct tcphdr *th,
			 struct ip_vs_synproxy_opt *opt)
{
	/* mss in received packet */
	__u16 in_mss;
	__u32 *tmp;
	unsigned char *ptr;
	int length = (th->doff * 4) - sizeof(struct tcphdr);
	/*tcp_sk(sk)->user_mss. set from proc */
	__u16 user_mss = sysctl_ip_vs_synproxy_init_mss;

	memset(opt, '\0', sizeof(struct ip_vs_synproxy_opt));
	opt->mss_clamp = 536;
	ptr = (unsigned char *)(th + 1);

	while (length > 0) {
		unsigned char *tmp_opcode = ptr;
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2)	/* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			switch (opcode) {
			case TCPOPT_MSS:
				if (opsize == TCPOLEN_MSS) {
					in_mss = ntohs(*(__u16 *) ptr);
					if (in_mss) {
						if (user_mss < in_mss) {
							in_mss = user_mss;
						}
						opt->mss_clamp = in_mss;
					}
					*(__u16 *) ptr = htons(opt->mss_clamp);
				}
				break;
			case TCPOPT_WINDOW:
				if (opsize == TCPOLEN_WINDOW) {
					if (sysctl_ip_vs_synproxy_wscale) {
						opt->wscale_ok = 1;
						opt->snd_wscale = *(__u8 *) ptr;
						if (opt->snd_wscale >
						    IP_VS_SYNPROXY_WSCALE_MAX) {
							IP_VS_DBG(6,
								  "tcp_parse_options: Illegal window "
								  "scaling value %d > %d received.",
								  opt->
								  snd_wscale,
								  IP_VS_SYNPROXY_WSCALE_MAX);
							opt->snd_wscale =
							    IP_VS_SYNPROXY_WSCALE_MAX;
						}
						*(__u8 *) ptr = (__u8)
						    sysctl_ip_vs_synproxy_wscale;
					} else {
						memset(tmp_opcode, TCPOPT_NOP,
						       TCPOLEN_WINDOW);
					}
				}
				break;
			case TCPOPT_TIMESTAMP:
				if (opsize == TCPOLEN_TIMESTAMP) {
					if (sysctl_ip_vs_synproxy_timestamp) {
						opt->tstamp_ok = 1;
						tmp = (__u32 *) ptr;
						*(tmp + 1) = *tmp;
						*tmp = htonl(tcp_time_stamp);
					} else {
						memset(tmp_opcode, TCPOPT_NOP,
						       TCPOLEN_TIMESTAMP);
					}
				}
				break;
			case TCPOPT_SACK_PERM:
				if (opsize == TCPOLEN_SACK_PERM) {
					if (sysctl_ip_vs_synproxy_sack) {
						opt->sack_ok = 1;
					} else {
						memset(tmp_opcode, TCPOPT_NOP,
						       TCPOLEN_SACK_PERM);
					}
				}
				break;
			}
			ptr += opsize - 2;
			length -= opsize;
		}
	}
}

/*
 * Reuse skb for syn proxy, called by syn_proxy_syn_rcv().
 * do following things:
 * 1) set tcp options;
 * 2) compute seq with cookie func.
 * 3) set tcp seq and ack_seq;
 * 4) exchange ip addr and tcp port;
 * 5) compute iphdr and tcp check.
 *
 */
static void
syn_proxy_reuse_skb(int af, struct sk_buff *skb, struct ip_vs_synproxy_opt *opt)
{
	__u32 isn;
	unsigned short tmpport;
	unsigned int tcphoff;
	struct tcphdr *th;

#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		tcphoff = sizeof(struct ipv6hdr);
	else
#endif
		tcphoff = ip_hdrlen(skb);

	th = (void *)skb_network_header(skb) + tcphoff;

	/* deal with tcp options */
	syn_proxy_parse_set_opts(skb, th, opt);

	/* get cookie */
	skb_set_transport_header(skb, tcphoff);
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		isn = syn_proxy_cookie_v6_init_sequence(skb, opt);
	else
#endif
		isn = syn_proxy_cookie_v4_init_sequence(skb, opt);

	/* Set syn-ack flag
	 * the tcp opt in syn/ack packet : 00010010 = 0x12
	 */
	((u_int8_t *) th)[13] = 0x12;

	/* Exchange ports */
	tmpport = th->dest;
	th->dest = th->source;
	th->source = tmpport;

	/* Set seq(cookie) and ack_seq */
	th->ack_seq = htonl(ntohl(th->seq) + 1);
	th->seq = htonl(isn);

	/* Exchange addresses and compute checksums */
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6) {
		struct ipv6hdr *iph = ipv6_hdr(skb);
		struct in6_addr tmpAddr;

		memcpy(&tmpAddr, &iph->saddr, sizeof(struct in6_addr));
		memcpy(&iph->saddr, &iph->daddr, sizeof(struct in6_addr));
		memcpy(&iph->daddr, &tmpAddr, sizeof(struct in6_addr));

		iph->hop_limit = sysctl_ip_vs_synproxy_synack_ttl;

		th->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
		th->check = csum_ipv6_magic(&iph->saddr, &iph->daddr,
					    skb->len - tcphoff,
					    IPPROTO_TCP, skb->csum);
	} else
#endif
	{
		struct iphdr *iph = ip_hdr(skb);
		__be32 tmpAddr;

		tmpAddr = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = tmpAddr;

		iph->ttl = sysctl_ip_vs_synproxy_synack_ttl;
		iph->tos = 0;

		ip_send_check(iph);

		th->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
		th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					      skb->len - tcphoff,
					      IPPROTO_TCP, skb->csum);
	}
}

/*
 *  syn-proxy step 1 logic:
 *  Check if synproxy is enabled for this skb, and
 *  send Syn/Ack back.
 *
 *  Synproxy is enabled when:
 *  1) skb is a Syn packet.
 *  2) And the service is synproxy-enable.
 *  3) And ip_vs_todrop return false.
 *
 *  @return 0 means the caller should return at once and use
 *   verdict as return value, return 1 for nothing.
 */
int
ip_vs_synproxy_syn_rcv(int af, struct sk_buff *skb,
		       struct ip_vs_iphdr *iph, int *verdict)
{
	struct ip_vs_service *svc = NULL;
	struct tcphdr _tcph, *th;
	struct ip_vs_synproxy_opt tcp_opt;

	th = skb_header_pointer(skb, iph->len, sizeof(_tcph), &_tcph);
	if (unlikely(th == NULL)) {
		goto syn_rcv_out;
	}

	if (th->syn && !th->ack && !th->rst && !th->fin &&
	    (svc =
	     ip_vs_service_get(af, skb->mark, iph->protocol, &iph->daddr,
			       th->dest))
	    && (svc->flags & IP_VS_SVC_F_SYNPROXY)) {
		/*
		 * if service's weight is zero (no active realserver),
		 * then do nothing and drop the packet.
		 */
		if(svc->weight == 0) {
			IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_NO_DEST);
			ip_vs_service_put(svc);
			goto syn_rcv_out;
		}
		// release service here, because don't use it any all.
		ip_vs_service_put(svc);

		if (ip_vs_todrop()) {
			/*
			 * It seems that we are very loaded.
			 * We have to drop this packet :(
			 */
			goto syn_rcv_out;
		}
	} else {
		/*
		 * release service.
		 */
		if (svc != NULL) {
			ip_vs_service_put(svc);
		}
		return 1;
	}

	/* update statistics */
	IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_SYN_CNT);

	/* Try to reuse skb if possible */
	if (unlikely(skb_shared(skb) || skb_cloned(skb))) {
		struct sk_buff *new_skb = skb_copy(skb, GFP_ATOMIC);
		if (unlikely(new_skb == NULL)) {
			goto syn_rcv_out;
		}
		/* Drop old skb */
		kfree_skb(skb);
		skb = new_skb;
	}

	/* reuse skb here: deal with tcp options, exchage ip, port. */
	syn_proxy_reuse_skb(af, skb, &tcp_opt);

	if (unlikely(skb->dev == NULL)) {
		IP_VS_ERR_RL("%s: skb->dev is null !!!\n", __func__);
		goto syn_rcv_out;
	}

	/* Send the packet out */
	if (likely(skb->dev->type == ARPHRD_ETHER)) {
		unsigned char t_hwaddr[ETH_ALEN];

		/* Move the data pointer to point to the link layer header */
		struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);
		skb->data = (unsigned char *)skb_mac_header(skb);
		skb->len += ETH_HLEN;	//sizeof(skb->mac.ethernet);

		memcpy(t_hwaddr, (eth->h_dest), ETH_ALEN);
		memcpy((eth->h_dest), (eth->h_source), ETH_ALEN);
		memcpy((eth->h_source), t_hwaddr, ETH_ALEN);
		skb->pkt_type = PACKET_OUTGOING;
	} else if (skb->dev->type == ARPHRD_LOOPBACK) {
		/* set link layer */
		if (likely(skb_mac_header_was_set(skb))) {
			skb->data = skb_mac_header(skb);
			skb->len += sizeof(struct ethhdr);
		} else {
			skb_push(skb, sizeof(struct ethhdr));
			skb_reset_mac_header(skb);
		}
	}

	dev_queue_xmit(skb);
	*verdict = NF_STOLEN;
	return 0;
syn_rcv_out:
	/* Drop the packet when all things are right also,
	 * then we needn't to kfree_skb() */
	*verdict = NF_DROP;
	return 0;
}

/*
 * Check if skb has user data.
 * Attention: decrease iph len also.
 */
static inline int
syn_proxy_ack_has_data(struct sk_buff *skb, struct ip_vs_iphdr *iph,
		       struct tcphdr *th)
{
	IP_VS_DBG(6, "tot_len = %u, iph_len = %u, tcph_len = %u\n",
		  skb->len, iph->len, th->doff * 4);
	return (skb->len - iph->len - th->doff * 4) != 0;
}

static inline void
syn_proxy_syn_build_options(__be32 * ptr, struct ip_vs_synproxy_opt *opt)
{
	*ptr++ =
	    htonl((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) | opt->mss_clamp);
	if (opt->tstamp_ok) {
		if (opt->sack_ok)
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
				       (TCPOLEN_SACK_PERM << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		else
			*ptr++ = htonl((TCPOPT_NOP << 24) |
				       (TCPOPT_NOP << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		*ptr++ = htonl(tcp_time_stamp);	/* TSVAL */
		*ptr++ = 0;	/* TSECR */
	} else if (opt->sack_ok)
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) | TCPOLEN_SACK_PERM);
	if (opt->wscale_ok)
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) | (opt->snd_wscale));
}

/*
 * Create syn packet and send it to rs.
 * ATTENTION: we also store syn skb in cp if syn retransimition
 * is tured on.
 */
static int
syn_proxy_send_rs_syn(int af, const struct tcphdr *th,
		      struct ip_vs_conn *cp, struct sk_buff *skb,
		      struct ip_vs_protocol *pp, struct ip_vs_synproxy_opt *opt)
{
	struct sk_buff *syn_skb;
	int tcp_hdr_size;
	__u8 tcp_flags = TCPCB_FLAG_SYN;
	unsigned int tcphoff;
	struct tcphdr *new_th;

	if (!cp->packet_xmit) {
		IP_VS_ERR_RL("warning: packet_xmit is null");
		return 0;
	}

	syn_skb = alloc_skb(MAX_TCP_HEADER + 15, GFP_ATOMIC);
	if (unlikely(syn_skb == NULL)) {
		IP_VS_ERR_RL("alloc skb failed when send rs syn packet\n");
		return 0;
	}

	/* Reserve space for headers */
	skb_reserve(syn_skb, MAX_TCP_HEADER);
	tcp_hdr_size = (sizeof(struct tcphdr) + TCPOLEN_MSS +
			(opt->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0) +
			(opt->wscale_ok ? TCPOLEN_WSCALE_ALIGNED : 0) +
			/* SACK_PERM is in the place of NOP NOP of TS */
			((opt->sack_ok
			  && !opt->tstamp_ok) ? TCPOLEN_SACKPERM_ALIGNED : 0));

	new_th = (struct tcphdr *)skb_push(syn_skb, tcp_hdr_size);
	/* Compose tcp header */
	skb_reset_transport_header(syn_skb);
	syn_skb->csum = 0;

	/* Set tcp hdr */
	new_th->source = th->source;
	new_th->dest = th->dest;
	new_th->seq = htonl(ntohl(th->seq) - 1);
	new_th->ack_seq = 0;
	*(((__u16 *) new_th) + 6) =
	    htons(((tcp_hdr_size >> 2) << 12) | tcp_flags);
	/* FIX_ME: what window should we use */
	new_th->window = htons(5000);
	new_th->check = 0;
	new_th->urg_ptr = 0;
	new_th->urg = 0;
	new_th->ece = 0;
	new_th->cwr = 0;

	syn_proxy_syn_build_options((__be32 *) (new_th + 1), opt);

	/*
	 * Set ip hdr
	 * Attention: set source and dest addr to ack skb's.
	 * we rely on packet_xmit func to do NATs thing.
	 */
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6) {
		struct ipv6hdr *ack_iph = ipv6_hdr(skb);
		struct ipv6hdr *iph =
		    (struct ipv6hdr *)skb_push(syn_skb, sizeof(struct ipv6hdr));

		tcphoff = sizeof(struct ipv6hdr);
		skb_reset_network_header(syn_skb);
		memcpy(&iph->saddr, &ack_iph->saddr, sizeof(struct in6_addr));
		memcpy(&iph->daddr, &ack_iph->daddr, sizeof(struct in6_addr));

		iph->version = 6;
		iph->nexthdr = NEXTHDR_TCP;
		iph->payload_len = htons(tcp_hdr_size);
		iph->hop_limit = IPV6_DEFAULT_HOPLIMIT;

		new_th->check = 0;
		syn_skb->csum =
		    skb_checksum(syn_skb, tcphoff, syn_skb->len - tcphoff, 0);
		new_th->check =
		    csum_ipv6_magic(&iph->saddr, &iph->daddr,
				    syn_skb->len - tcphoff, IPPROTO_TCP,
				    syn_skb->csum);
	} else
#endif
	{
		struct iphdr *ack_iph = ip_hdr(skb);
		u32 rtos = RT_TOS(ack_iph->tos);
		struct iphdr *iph =
		    (struct iphdr *)skb_push(syn_skb, sizeof(struct iphdr));

		tcphoff = sizeof(struct iphdr);
		skb_reset_network_header(syn_skb);
		*((__u16 *) iph) = htons((4 << 12) | (5 << 8) | (rtos & 0xff));
		iph->tot_len = htons(syn_skb->len);
		iph->frag_off = htons(IP_DF);
		/* FIX_ME: what ttl shoule we use */
		iph->ttl = IPDEFTTL;
		iph->protocol = IPPROTO_TCP;
		iph->saddr = ack_iph->saddr;
		iph->daddr = ack_iph->daddr;

		ip_send_check(iph);

		new_th->check = 0;
		syn_skb->csum =
		    skb_checksum(syn_skb, tcphoff, syn_skb->len - tcphoff, 0);
		new_th->check =
		    csum_tcpudp_magic(iph->saddr, iph->daddr,
				      syn_skb->len - tcphoff, IPPROTO_TCP,
				      syn_skb->csum);
	}

	/* Save syn_skb if syn retransmission is on  */
	if (sysctl_ip_vs_synproxy_syn_retry > 0) {
		cp->syn_skb = skb_copy(syn_skb, GFP_ATOMIC);
		atomic_set(&cp->syn_retry_max, sysctl_ip_vs_synproxy_syn_retry);
	}

	/* Save info for fast_response_xmit */
	if(sysctl_ip_vs_fast_xmit && skb->dev &&
				likely(skb->dev->type == ARPHRD_ETHER) &&
				skb_mac_header_was_set(skb)) {
		struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);

		if(likely(cp->indev == NULL)) {
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
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_SYNPROXY_SAVE);
		IP_VS_DBG_RL("syn_proxy_send_rs_syn netdevice:%s\n",
						netdev_name(skb->dev));
	}

	/* count in the syn packet */
	ip_vs_in_stats(cp, skb);

	/* If xmit failed, syn_skb will be freed correctly. */
	cp->packet_xmit(syn_skb, cp, pp);

	return 1;
}

/*
 * Syn-proxy step 2 logic
 * Receive client's 3-handshakes  Ack packet, do cookie check
 * and then send syn to rs after creating a session.
 *
 */
int
ip_vs_synproxy_ack_rcv(int af, struct sk_buff *skb, struct tcphdr *th,
		       struct ip_vs_protocol *pp, struct ip_vs_conn **cpp,
		       struct ip_vs_iphdr *iph, int *verdict)
{
	struct ip_vs_synproxy_opt opt;
	struct ip_vs_service *svc;
	int res_cookie_check;

	/*
	 * Don't check svc syn-proxy flag, as it may
	 * be changed after syn-proxy step 1.
	 */
	if (!th->syn && th->ack && !th->rst && !th->fin &&
	    (svc =
	     ip_vs_service_get(af, skb->mark, iph->protocol, &iph->daddr,
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

		if (sysctl_ip_vs_synproxy_defer &&
		    !syn_proxy_ack_has_data(skb, iph, th)) {
			/* update statistics */
			IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_NULL_ACK);
			/*
			 * When expecting ack packet with payload,
			 * we get a pure ack, so have to drop it.
			 */
			ip_vs_service_put(svc);
			*verdict = NF_DROP;
			return 0;
		}

		/*
		 * Import: set tcp hdr before cookie check, as it
		 * will be used in cookie_check funcs.
		 */
		skb_set_transport_header(skb, iph->len);
#ifdef CONFIG_IP_VS_IPV6
		if (af == AF_INET6) {
			res_cookie_check = syn_proxy_v6_cookie_check(skb,
									  ntohl
									  (th->
									   ack_seq)
									  - 1,
									  &opt);
		} else
#endif
		{
			res_cookie_check = syn_proxy_v4_cookie_check(skb,
									  ntohl
									  (th->
									   ack_seq)
									  - 1,
									  &opt);
		}

		if (!res_cookie_check) {
			/* update statistics */
			IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_BAD_ACK);
			/*
			 * Cookie check fail, drop it.
			 */
			IP_VS_DBG(6, "syn_cookie check failed seq=%u\n",
				  ntohl(th->ack_seq) - 1);
			ip_vs_service_put(svc);
			*verdict = NF_DROP;
			return 0;
		}

		/* update statistics */
		IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_OK_ACK);

		/*
		 * Let the virtual server select a real server for the
		 * incoming connection, and create a connection entry.
		 */
		*cpp = ip_vs_schedule(svc, skb, 1);
		if (!*cpp) {
			IP_VS_DBG(6, "ip_vs_schedule failed\n");
			*verdict = ip_vs_leave(svc, skb, pp);
			return 0;
		}

		/*
		 * Set private establish state timeout into cp from svc,
		 * due cp may use its user establish state timeout
		 * different from sysctl_ip_vs_tcp_timeouts
		 */
		(*cpp)->est_timeout = svc->est_timeout;

		/*
		 * Release service, we don't need it any more.
		 */
		ip_vs_service_put(svc);

		/*
		 * Do anything but print a error msg when fail.
		 * Because session will be correctly freed in ip_vs_conn_expire.
		 */
		if (!syn_proxy_send_rs_syn(af, th, *cpp, skb, pp, &opt)) {
			IP_VS_ERR_RL("syn_proxy_send_rs_syn failed!\n");
		}

		/* count in the ack packet (STOLEN by synproxy) */
		ip_vs_in_stats(*cpp, skb);

		/*
		 * Active sesion timer, and dec refcnt.
		 * Also stole the skb, and let caller return immediately.
		 */
		ip_vs_conn_put(*cpp);
		*verdict = NF_STOLEN;
		return 0;
	}

	return 1;
}

/*
 * Update out-in sack seqs, and also correct th->check
 */
static inline void
syn_proxy_filter_opt_outin(struct tcphdr *th, struct ip_vs_seq *sp_seq)
{
	unsigned char *ptr;
	int length = (th->doff * 4) - sizeof(struct tcphdr);
	__be32 *tmp;
	__u32 old_ack_seq;

	if (!length)
		return;

	ptr = (unsigned char *)(th + 1);

	/* Fast path for timestamp-only option */
	if (length == TCPOLEN_TSTAMP_ALIGNED
	    && *(__be32 *) ptr == __constant_htonl((TCPOPT_NOP << 24)
						   | (TCPOPT_NOP << 16)
						   | (TCPOPT_TIMESTAMP << 8) |
						   TCPOLEN_TIMESTAMP))
		return;

	while (length > 0) {
		int opcode = *ptr++;
		int opsize, i;

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
				break;	/* don't parse partial options */

			if (opcode == TCPOPT_SACK
			    && opsize >= (TCPOLEN_SACK_BASE
					  + TCPOLEN_SACK_PERBLOCK)
			    && !((opsize - TCPOLEN_SACK_BASE) %
				 TCPOLEN_SACK_PERBLOCK)) {
				for (i = 0; i < (opsize - TCPOLEN_SACK_BASE);
				     i += TCPOLEN_SACK_PERBLOCK) {
					tmp = (__be32 *) (ptr + i);
					old_ack_seq = ntohl(*tmp);
					*tmp = htonl((__u32)
						     (old_ack_seq -
						      sp_seq->delta));
					syn_proxy_seq_csum_update(th,
								  htonl
								  (old_ack_seq),
								  *tmp);
					IP_VS_DBG(6,
						  "syn_proxy_filter_opt_outin: sack_left_seq %u => %u, delta = %u \n",
						  old_ack_seq, ntohl(*tmp),
						  sp_seq->delta);
					tmp++;
					old_ack_seq = ntohl(*tmp);
					*tmp = htonl((__u32)
						     (old_ack_seq -
						      sp_seq->delta));
					syn_proxy_seq_csum_update(th,
								  htonl
								  (old_ack_seq),
								  *tmp);
					IP_VS_DBG(6,
						  "syn_proxy_filter_opt_outin: sack_right_seq %u => %u, delta = %u \n",
						  old_ack_seq, ntohl(*tmp),
						  sp_seq->delta);
				}
				return;
			}
			ptr += opsize - 2;
			length -= opsize;
		}
	}
}

/*
 * Update out-in ack_seqs: include th->ack_seq, sack opt
 * and also correct tcph->check.
 */
void ip_vs_synproxy_dnat_handler(struct tcphdr *tcph, struct ip_vs_seq *sp_seq)
{
	__u32 old_ack_seq;

	if (sp_seq->delta != 0) {
		old_ack_seq = ntohl(tcph->ack_seq);
		tcph->ack_seq = htonl((__u32) (old_ack_seq - sp_seq->delta));
		syn_proxy_seq_csum_update(tcph, htonl(old_ack_seq),
					  tcph->ack_seq);
		syn_proxy_filter_opt_outin(tcph, sp_seq);
		IP_VS_DBG(6,
			  "tcp_dnat_handler: tcph->ack_seq %u => %u, delta = %u \n",
			  old_ack_seq, htonl(tcph->ack_seq), sp_seq->delta);
	}
}

static inline void
ip_vs_synproxy_save_fast_xmit_info(struct sk_buff *skb, struct ip_vs_conn *cp)
{
	/* Save info for L2 fast xmit */
	if(sysctl_ip_vs_fast_xmit_inside && skb->dev &&
				likely(skb->dev->type == ARPHRD_ETHER) &&
				skb_mac_header_was_set(skb)) {
		struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);

		if(likely(cp->dev_inside == NULL)) {
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
		IP_VS_INC_ESTATS(ip_vs_esmib, FAST_XMIT_SYNPROXY_SAVE_INSIDE);
		IP_VS_DBG_RL("synproxy_save_fast_xmit netdevice:%s\n",
						netdev_name(skb->dev));
	}
}

/*
 * Syn-proxy step 3 logic: receive syn-ack from rs
 * Update syn_proxy_seq.delta and send stored ack skbs
 * to rs.
 */
int
ip_vs_synproxy_synack_rcv(struct sk_buff *skb, struct ip_vs_conn *cp,
			  struct ip_vs_protocol *pp, int ihl, int *verdict)
{
	struct tcphdr _tcph, *th;
	struct sk_buff_head save_skb;
	struct sk_buff *tmp_skb = NULL;
	struct ip_vs_dest *dest = cp->dest;

	th = skb_header_pointer(skb, ihl, sizeof(_tcph), &_tcph);
	if (th == NULL) {
		*verdict = NF_DROP;
		return 0;
	}

	IP_VS_DBG(6, "in syn_proxy_synack_rcv, "
		  "seq = %u ack_seq = %u %c%c%c cp->is_synproxy = %u cp->state = %u\n",
		  ntohl(th->seq),
		  ntohl(th->ack_seq),
		  (th->syn) ? 'S' : '-',
		  (th->ack) ? 'A' : '-',
		  (th->rst) ? 'R' : '-',
		  cp->flags & IP_VS_CONN_F_SYNPROXY, cp->state);

	skb_queue_head_init(&save_skb);
	spin_lock(&cp->lock);
	if ((th->syn) && (th->ack) && (!th->rst) &&
	    (cp->flags & IP_VS_CONN_F_SYNPROXY) &&
	    cp->state == IP_VS_TCP_S_SYN_SENT) {
		cp->syn_proxy_seq.delta =
		    htonl(cp->syn_proxy_seq.init_seq) - htonl(th->seq);
		cp->state = IP_VS_TCP_S_ESTABLISHED;
		cp->timeout = cp->est_timeout;
		if (dest) {
			atomic_inc(&dest->activeconns);
			atomic_dec(&dest->inactconns);
			cp->flags &= ~IP_VS_CONN_F_INACTIVE;
		}

		/* save tcp sequense for fullnat/nat, INside to OUTside */
		if (sysctl_ip_vs_conn_expire_tcp_rst == 1) {
			cp->rs_end_seq = htonl(ntohl(th->seq) + 1);
			cp->rs_ack_seq = th->ack_seq;
			IP_VS_DBG_RL("packet from RS, seq:%u ack_seq:%u.",
				     ntohl(th->seq), ntohl(th->ack_seq));
			IP_VS_DBG_RL("port:%u->%u", ntohs(th->source),
				     ntohs(th->dest));
		}

		ip_vs_synproxy_save_fast_xmit_info(skb, cp);

		/* First: free stored syn skb */
		if ((tmp_skb = xchg(&cp->syn_skb, NULL)) != NULL) {
			kfree_skb(tmp_skb);
			tmp_skb = NULL;
		}

		if (skb_queue_len(&cp->ack_skb) <= 0) {
			/*
			 * FIXME: maybe a bug here, print err msg and go.
			 * Attention: cp->state has been changed and we
			 * should still DROP the Syn/Ack skb.
			 */
			IP_VS_ERR_RL
			    ("Got ack_skb NULL pointer in syn_proxy_synack_rcv\n");
			spin_unlock(&cp->lock);
			*verdict = NF_DROP;
			return 0;
		}

		while ((tmp_skb = skb_dequeue(&cp->ack_skb)) != NULL) {
			skb_queue_tail(&save_skb, tmp_skb);
		}

		/*
		 * Release the lock, because we don't
		 * touch session any more.
		 */
		spin_unlock(&cp->lock);

		while ((tmp_skb = skb_dequeue(&save_skb)) != NULL) {
			/* If xmit failed, syn_skb will be freed correctly. */
			cp->packet_xmit(tmp_skb, cp, pp);
		}

		*verdict = NF_DROP;
		return 0;
	} else if ((th->rst) &&
		   (cp->flags & IP_VS_CONN_F_SYNPROXY) &&
		   cp->state == IP_VS_TCP_S_SYN_SENT) {
		__u32 temp_seq;
		temp_seq = ntohl(th->seq);
		IP_VS_DBG(6, "get rst from rs, seq = %u ack_seq= %u\n",
			  ntohl(th->seq), ntohl(th->ack_seq));
		/* coute the delta of seq */
		cp->syn_proxy_seq.delta =
		    ntohl(cp->syn_proxy_seq.init_seq) - ntohl(th->seq);
		cp->timeout = pp->timeout_table[cp->state = IP_VS_TCP_S_CLOSE];
		spin_unlock(&cp->lock);
		th->seq = htonl(ntohl(th->seq) + 1);
		syn_proxy_seq_csum_update(th, htonl(temp_seq), th->seq);

		return 1;
	}
	spin_unlock(&cp->lock);

	return 1;
}

static inline void
__syn_proxy_reuse_conn(struct ip_vs_conn *cp,
		       struct sk_buff *ack_skb,
		       struct tcphdr *th, struct ip_vs_protocol *pp)
{
	struct sk_buff *tmp_skb = NULL;

	/* Free stored ack packet */
	while ((tmp_skb = skb_dequeue(&cp->ack_skb)) != NULL) {
		kfree_skb(tmp_skb);
		tmp_skb = NULL;
	}

	/* Free stored syn skb */
	if ((tmp_skb = xchg(&cp->syn_skb, NULL)) != NULL) {
		kfree_skb(tmp_skb);
		tmp_skb = NULL;
	}

	/* Store new ack_skb */
	skb_queue_head_init(&cp->ack_skb);
	skb_queue_tail(&cp->ack_skb, ack_skb);

	/* Save ack_seq - 1 */
	cp->syn_proxy_seq.init_seq = htonl((__u32) ((htonl(th->ack_seq) - 1)));
	/* don't change delta here, so original flow can still be valid */

	/* Save ack_seq */
	cp->fnat_seq.fdata_seq = ntohl(th->ack_seq);

	cp->fnat_seq.init_seq = 0;

	/* Clean dup ack cnt */
	atomic_set(&cp->dup_ack_cnt, 0);

	/* Set timeout value */
	cp->timeout = pp->timeout_table[cp->state = IP_VS_TCP_S_SYN_SENT];
}

/*
 * Syn-proxy session reuse function.
 * Update syn_proxy_seq struct and clean syn-proxy related
 * members.
 */
int
ip_vs_synproxy_reuse_conn(int af, struct sk_buff *skb,
			  struct ip_vs_conn *cp,
			  struct ip_vs_protocol *pp,
			  struct ip_vs_iphdr *iph, int *verdict)
{
	struct tcphdr _tcph, *th = NULL;
	struct ip_vs_synproxy_opt opt;
	int res_cookie_check;
	u32 tcp_conn_reuse_states = 0;

	th = skb_header_pointer(skb, iph->len, sizeof(_tcph), &_tcph);
	if (unlikely(NULL == th)) {
		IP_VS_ERR_RL("skb has a invalid tcp header\n");
		*verdict = NF_DROP;
		return 0;
	}

	tcp_conn_reuse_states =
	    ((sysctl_ip_vs_synproxy_conn_reuse_cl << IP_VS_TCP_S_CLOSE) |
	     (sysctl_ip_vs_synproxy_conn_reuse_tw << IP_VS_TCP_S_TIME_WAIT) |
	     (sysctl_ip_vs_synproxy_conn_reuse_fw << IP_VS_TCP_S_FIN_WAIT) |
	     (sysctl_ip_vs_synproxy_conn_reuse_cw << IP_VS_TCP_S_CLOSE_WAIT) |
	     (sysctl_ip_vs_synproxy_conn_reuse_la << IP_VS_TCP_S_LAST_ACK));

	if (((1 << (cp->state)) & tcp_conn_reuse_states) &&
	    (cp->flags & IP_VS_CONN_F_SYNPROXY) &&
	    (!th->syn && th->ack && !th->rst && !th->fin) &&
	    (cp->syn_proxy_seq.init_seq !=
	     htonl((__u32) ((ntohl(th->ack_seq) - 1))))) {
		/*
		 * Import: set tcp hdr before cookie check, as it
		 * will be used in cookie_check funcs.
		 */
		skb_set_transport_header(skb, iph->len);
#ifdef CONFIG_IP_VS_IPV6
		if (af == AF_INET6) {
			res_cookie_check = syn_proxy_v6_cookie_check(skb,
									  ntohl
									  (th->
									   ack_seq)
									  - 1,
									  &opt);
		} else
#endif
		{
			res_cookie_check = syn_proxy_v4_cookie_check(skb,
									  ntohl
									  (th->
									   ack_seq)
									  - 1,
									  &opt);
		}

		if (!res_cookie_check) {
			/* update statistics */
			IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_BAD_ACK);
			/*
			 * Cookie check fail, let it go.
			 */
			return 1;
		}

		/* update statistics */
		IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_OK_ACK);
		IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_CONN_REUSED);
		switch (cp->old_state) {
		case IP_VS_TCP_S_CLOSE:
			IP_VS_INC_ESTATS(ip_vs_esmib,
					 SYNPROXY_CONN_REUSED_CLOSE);
			break;
		case IP_VS_TCP_S_TIME_WAIT:
			IP_VS_INC_ESTATS(ip_vs_esmib,
					 SYNPROXY_CONN_REUSED_TIMEWAIT);
			break;
		case IP_VS_TCP_S_FIN_WAIT:
			IP_VS_INC_ESTATS(ip_vs_esmib,
					 SYNPROXY_CONN_REUSED_FINWAIT);
			break;
		case IP_VS_TCP_S_CLOSE_WAIT:
			IP_VS_INC_ESTATS(ip_vs_esmib,
					 SYNPROXY_CONN_REUSED_CLOSEWAIT);
			break;
		case IP_VS_TCP_S_LAST_ACK:
			IP_VS_INC_ESTATS(ip_vs_esmib,
					 SYNPROXY_CONN_REUSED_LASTACK);
			break;
		}

		spin_lock(&cp->lock);
		__syn_proxy_reuse_conn(cp, skb, th, pp);
		spin_unlock(&cp->lock);

		if (unlikely(!syn_proxy_send_rs_syn(af, th, cp, skb, pp, &opt))) {
			IP_VS_ERR_RL
			    ("syn_proxy_send_rs_syn failed when reuse conn!\n");
			/* release conn immediately */
			spin_lock(&cp->lock);
			cp->timeout = 0;
			spin_unlock(&cp->lock);
		}

		*verdict = NF_STOLEN;
		return 0;
	}

	return 1;
}

/*
 * Check and stop ack storm.
 * Return 0 if ack storm is found.
 */
static int syn_proxy_is_ack_storm(struct tcphdr *tcph, struct ip_vs_conn *cp)
{
	/* only for syn-proxy sessions */
	if (!(cp->flags & IP_VS_CONN_F_SYNPROXY) || !tcph->ack)
		return 1;

	if (unlikely(sysctl_ip_vs_synproxy_dup_ack_thresh == 0))
		return 1;

	if (unlikely(tcph->seq == cp->last_seq &&
		     tcph->ack_seq == cp->last_ack_seq)) {
		atomic_inc(&cp->dup_ack_cnt);
		if (atomic_read(&cp->dup_ack_cnt) >=
		    sysctl_ip_vs_synproxy_dup_ack_thresh) {
			atomic_set(&cp->dup_ack_cnt,
				   sysctl_ip_vs_synproxy_dup_ack_thresh);
			/* update statistics */
			IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_ACK_STORM);
			return 0;
		}

		return 1;
	}

	cp->last_seq = tcph->seq;
	cp->last_ack_seq = tcph->ack_seq;
	atomic_set(&cp->dup_ack_cnt, 0);

	return 1;
}

/*
 * Syn-proxy snat handler:
 * 1) check and stop ack storm.
 * 2)Update in-out seqs: include th->seq
 * and also correct tcph->check.
 *
 * Return 0 if ack storm is found and stoped.
 */
int ip_vs_synproxy_snat_handler(struct tcphdr *tcph, struct ip_vs_conn *cp)
{
	__u32 old_seq;

	if (syn_proxy_is_ack_storm(tcph, cp) == 0) {
		return 0;
	}

	if (cp->syn_proxy_seq.delta != 0) {
		old_seq = ntohl(tcph->seq);
		tcph->seq = htonl((__u32) (old_seq + cp->syn_proxy_seq.delta));
		syn_proxy_seq_csum_update(tcph, htonl(old_seq), tcph->seq);
		IP_VS_DBG(6,
			  "tcp_snat_handler: tcph->seq %u => %u, delta = %u \n",
			  old_seq, htonl(tcph->seq), cp->syn_proxy_seq.delta);
	}

	return 1;
}

int
ip_vs_synproxy_filter_ack(struct sk_buff *skb, struct ip_vs_conn *cp,
			  struct ip_vs_protocol *pp,
			  struct ip_vs_iphdr *iph, int *verdict)
{
	struct tcphdr _tcph, *th;

	th = skb_header_pointer(skb, iph->len, sizeof(_tcph), &_tcph);

	if (unlikely(NULL == th)) {
		IP_VS_ERR_RL("skb has a invalid tcp header\n");
		*verdict = NF_DROP;
		return 0;
	}

	spin_lock(&cp->lock);
	if ((cp->flags & IP_VS_CONN_F_SYNPROXY) &&
	    cp->state == IP_VS_TCP_S_SYN_SENT) {
		/*
		 * Not a ack packet, drop it.
		 */
		if (!th->ack) {
			spin_unlock(&cp->lock);
			*verdict = NF_DROP;
			return 0;
		}

		if (sysctl_ip_vs_synproxy_skb_store_thresh <
		    skb_queue_len(&cp->ack_skb)) {
			spin_unlock(&cp->lock);
			/* update statistics */
			IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_SYNSEND_QLEN);
			*verdict = NF_DROP;
			return 0;
		}

		/*
		 * Still some space left, store it.
		 */
		skb_queue_tail(&cp->ack_skb, skb);
		spin_unlock(&cp->lock);
		*verdict = NF_STOLEN;
		return 0;
	}

	spin_unlock(&cp->lock);
	return 1;
}
