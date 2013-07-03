/*
 *     IP Virtual Server Syn-Proxy
 *     data structure and functionality definitions
 */

#ifndef _NET_IP_VS_SYNPROXY_H
#define _NET_IP_VS_SYNPROXY_H

#include <net/ip_vs.h>

/* Add MASKs for TCP OPT in "data" coded in cookie */
/* |[21][20][19-16][15-0]|
 * [21]    SACK
 * [20]    TimeStamp
 * [19-16] snd_wscale
 * [15-0]  MSSIND
 */
#define IP_VS_SYNPROXY_MSS_BITS 16
#define IP_VS_SYNPROXY_MSS_MASK (((__u32)1 << IP_VS_SYNPROXY_MSS_BITS) - 1)

#define IP_VS_SYNPROXY_SACKOK_BIT 21
#define IP_VS_SYNPROXY_SACKOK_MASK ((__u32)1 << IP_VS_SYNPROXY_SACKOK_BIT)

#define IP_VS_SYNPROXY_TSOK_BIT 20
#define IP_VS_SYNPROXY_TSOK_MASK ((__u32)1 << IP_VS_SYNPROXY_TSOK_BIT)

#define IP_VS_SYNPROXY_SND_WSCALE_BITS 16
#define IP_VS_SYNPROXY_SND_WSCALE_MASK ((__u32)0xf << IP_VS_SYNPROXY_SND_WSCALE_BITS)

#define IP_VS_SYNPROXY_WSCALE_MAX          14

/* add for supporting tcp options' in syn-proxy */
struct ip_vs_synproxy_opt {
	u16 snd_wscale:8,	/* Window scaling received from sender          */
	 tstamp_ok:1,		/* TIMESTAMP seen on SYN packet                 */
	 wscale_ok:1,		/* Wscale seen on SYN packet                    */
	 sack_ok:1;		/* SACK seen on SYN packet                      */
	u16 mss_clamp;		/* Maximal mss, negotiated at connection setup  */
};

/* 
 * For syncookie compute and check 
 */
extern __u32 ip_vs_synproxy_cookie_v4_init_sequence(struct sk_buff *skb,
						    struct ip_vs_synproxy_opt
						    *opts);
extern int ip_vs_synproxy_v4_cookie_check(struct sk_buff *skb, __u32 cookie,
					  struct ip_vs_synproxy_opt *opt);

extern __u32 ip_vs_synproxy_cookie_v6_init_sequence(struct sk_buff *skb,
						    struct ip_vs_synproxy_opt
						    *opts);
extern int ip_vs_synproxy_v6_cookie_check(struct sk_buff *skb, __u32 cookie,
					  struct ip_vs_synproxy_opt *opt);

/*
 * Syn-proxy step 1 logic: receive client's Syn.
 */
extern int ip_vs_synproxy_syn_rcv(int af, struct sk_buff *skb,
				  struct ip_vs_iphdr *iph, int *verdict);
/*
 * Syn-proxy step 2 logic: receive client's Ack.
 */
extern int ip_vs_synproxy_ack_rcv(int af, struct sk_buff *skb,
				  struct tcphdr *th, struct ip_vs_protocol *pp,
				  struct ip_vs_conn **cpp,
				  struct ip_vs_iphdr *iph, int *verdict);
/*
 * Syn-proxy step 3 logic: receive rs's Syn/Ack.
 */
extern int ip_vs_synproxy_synack_rcv(struct sk_buff *skb, struct ip_vs_conn *cp,
				     struct ip_vs_protocol *pp,
				     int ihl, int *verdict);
/*
 * Syn-proxy conn reuse logic: receive client's Ack.
 */
extern int ip_vs_synproxy_reuse_conn(int af, struct sk_buff *skb,
				     struct ip_vs_conn *cp,
				     struct ip_vs_protocol *pp,
				     struct ip_vs_iphdr *iph, int *verdict);
/*
 * Store or drop client's ack packet, when lvs is waiting for 
 * rs's Syn/Ack packet.
 */
extern int ip_vs_synproxy_filter_ack(struct sk_buff *skb, struct ip_vs_conn *cp,
				     struct ip_vs_protocol *pp,
				     struct ip_vs_iphdr *iph, int *verdict);

/*
 * Tranfer ack seq and sack opt for Out-In packet.
 */
extern void ip_vs_synproxy_dnat_handler(struct tcphdr *tcph,
					struct ip_vs_seq *sp_seq);
/*
 * Tranfer seq for In-Out packet.
 */
extern int ip_vs_synproxy_snat_handler(struct tcphdr *tcph,
				       struct ip_vs_conn *cp);

/* syn-proxy sysctl variables */
#define IP_VS_SYNPROXY_INIT_MSS_DEFAULT		1452
#define IP_VS_SYNPROXY_TTL_DEFAULT		63
#define IP_VS_SYNPROXY_TTL_MIN			1
#define IP_VS_SYNPROXY_TTL_MAX			255
#define IP_VS_SYNPROXY_SACK_DEFAULT		1
#define IP_VS_SYNPROXY_WSCALE_DEFAULT		0
#define IP_VS_SYNPROXY_TIMESTAMP_DEFAULT	0
#define IP_VS_SYNPROXY_DEFER_DEFAULT		0
#define IP_VS_SYNPROXY_DUP_ACK_DEFAULT		10
#define IP_VS_SYNPROXY_SKB_STORE_DEFAULT	3
#define IP_VS_SYNPROXY_CONN_REUSE_DEFAULT	1
#define	IP_VS_SYNPROXY_CONN_REUSE_CL_DEFAULT	1
#define	IP_VS_SYNPROXY_CONN_REUSE_TW_DEFAULT	1
#define	IP_VS_SYNPROXY_CONN_REUSE_FW_DEFAULT	0
#define	IP_VS_SYNPROXY_CONN_REUSE_CW_DEFAULT	0
#define	IP_VS_SYNPROXY_CONN_REUSE_LA_DEFAULT	0
#define	IP_VS_SYNPROXY_SYN_RETRY_DEFAULT	3

extern int sysctl_ip_vs_synproxy_sack;
extern int sysctl_ip_vs_synproxy_wscale;
extern int sysctl_ip_vs_synproxy_timestamp;
extern int sysctl_ip_vs_synproxy_synack_ttl;
extern int sysctl_ip_vs_synproxy_init_mss;
extern int sysctl_ip_vs_synproxy_defer;
extern int sysctl_ip_vs_synproxy_dup_ack_thresh;
extern int sysctl_ip_vs_synproxy_skb_store_thresh;
extern int sysctl_ip_vs_synproxy_syn_retry;
extern int sysctl_ip_vs_synproxy_conn_reuse;
extern int sysctl_ip_vs_synproxy_conn_reuse_cl;
extern int sysctl_ip_vs_synproxy_conn_reuse_tw;
extern int sysctl_ip_vs_synproxy_conn_reuse_fw;
extern int sysctl_ip_vs_synproxy_conn_reuse_cw;
extern int sysctl_ip_vs_synproxy_conn_reuse_la;

#endif
