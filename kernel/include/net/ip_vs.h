/*
 *      IP Virtual Server
 *      data structure and functionality definitions
 */

#ifndef _NET_IP_VS_H
#define _NET_IP_VS_H

#include <linux/ip_vs.h>	/* definitions shared with userland */

/* old ipvsadm versions still include this file directly */
#ifdef __KERNEL__

#include <asm/types.h>		/* for __uXX types */

#include <linux/sysctl.h>	/* for ctl_path */
#include <linux/list.h>		/* for struct list_head */
#include <linux/spinlock.h>	/* for struct rwlock_t */
#include <asm/atomic.h>		/* for struct atomic_t */
#include <linux/compiler.h>
#include <linux/timer.h>

#include <net/checksum.h>
#include <linux/netfilter.h>	/* for union nf_inet_addr */
#include <linux/ip.h>
#include <linux/ipv6.h>		/* for struct ipv6hdr */
#include <net/ipv6.h>		/* for ipv6_addr_copy */

struct ip_vs_iphdr {
	int len;
	__u8 protocol;
	union nf_inet_addr saddr;
	union nf_inet_addr daddr;
};

static inline void
ip_vs_fill_iphdr(int af, const void *nh, struct ip_vs_iphdr *iphdr)
{
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6) {
		const struct ipv6hdr *iph = nh;
		iphdr->len = sizeof(struct ipv6hdr);
		iphdr->protocol = iph->nexthdr;
		ipv6_addr_copy(&iphdr->saddr.in6, &iph->saddr);
		ipv6_addr_copy(&iphdr->daddr.in6, &iph->daddr);
	} else
#endif
	{
		const struct iphdr *iph = nh;
		iphdr->len = iph->ihl * 4;
		iphdr->protocol = iph->protocol;
		iphdr->saddr.ip = iph->saddr;
		iphdr->daddr.ip = iph->daddr;
	}
}

static inline void ip_vs_addr_copy(int af, union nf_inet_addr *dst,
				   const union nf_inet_addr *src)
{
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		ipv6_addr_copy(&dst->in6, &src->in6);
	else
#endif
		dst->ip = src->ip;
}

static inline int ip_vs_addr_equal(int af, const union nf_inet_addr *a,
				   const union nf_inet_addr *b)
{
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		return ipv6_addr_equal(&a->in6, &b->in6);
#endif
	return a->ip == b->ip;
}

#ifdef CONFIG_IP_VS_DEBUG
#include <linux/net.h>

extern int ip_vs_get_debug_level(void);

static inline const char *ip_vs_dbg_addr(int af, char *buf, size_t buf_len,
					 const union nf_inet_addr *addr,
					 int *idx)
{
	int len;
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		len = snprintf(&buf[*idx], buf_len - *idx, "[%pI6]",
			       &addr->in6) + 1;
	else
#endif
		len = snprintf(&buf[*idx], buf_len - *idx, "%pI4",
			       &addr->ip) + 1;

	*idx += len;
	BUG_ON(*idx > buf_len + 1);
	return &buf[*idx - len];
}

#define IP_VS_DBG_BUF(level, msg, ...)					\
	do {								\
		char ip_vs_dbg_buf[160];				\
		int ip_vs_dbg_idx = 0;					\
		if (level <= ip_vs_get_debug_level())			\
			printk(KERN_DEBUG pr_fmt(msg), ##__VA_ARGS__);	\
	} while (0)
#define IP_VS_ERR_BUF(msg...)						\
	do {								\
		char ip_vs_dbg_buf[160];				\
		int ip_vs_dbg_idx = 0;					\
		pr_err(msg);						\
	} while (0)

/* Only use from within IP_VS_DBG_BUF() or IP_VS_ERR_BUF macros */
#define IP_VS_DBG_ADDR(af, addr)					\
	ip_vs_dbg_addr(af, ip_vs_dbg_buf,				\
		       sizeof(ip_vs_dbg_buf), addr,			\
		       &ip_vs_dbg_idx)

#define IP_VS_DBG(level, msg, ...)					\
	do {								\
		if (level <= ip_vs_get_debug_level())			\
			printk(KERN_DEBUG pr_fmt(msg), ##__VA_ARGS__);	\
	} while (0)
#define IP_VS_DBG_RL(msg, ...)						\
	do {								\
		if (net_ratelimit())					\
			printk(KERN_DEBUG pr_fmt(msg), ##__VA_ARGS__);	\
	} while (0)
#define IP_VS_DBG_PKT(level, pp, skb, ofs, msg)				\
	do {								\
		if (level <= ip_vs_get_debug_level())			\
			pp->debug_packet(pp, skb, ofs, msg);		\
	} while (0)
#define IP_VS_DBG_RL_PKT(level, pp, skb, ofs, msg)			\
	do {								\
		if (level <= ip_vs_get_debug_level() &&			\
		    net_ratelimit())					\
			pp->debug_packet(pp, skb, ofs, msg);		\
	} while (0)
#else				/* NO DEBUGGING at ALL */
#define IP_VS_DBG_BUF(level, msg...)  do {} while (0)
#define IP_VS_ERR_BUF(msg...)  do {} while (0)
#define IP_VS_DBG(level, msg...)  do {} while (0)
#define IP_VS_DBG_RL(msg...)  do {} while (0)
#define IP_VS_DBG_PKT(level, pp, skb, ofs, msg)		do {} while (0)
#define IP_VS_DBG_RL_PKT(level, pp, skb, ofs, msg)	do {} while (0)
#endif

#define IP_VS_BUG() BUG()
#define IP_VS_ERR_RL(msg, ...)						\
	do {								\
		if (net_ratelimit())					\
			pr_err(msg, ##__VA_ARGS__);			\
	} while (0)

#ifdef CONFIG_IP_VS_DEBUG
#define EnterFunction(level)						\
	do {								\
		if (level <= ip_vs_get_debug_level())			\
			printk(KERN_DEBUG				\
			       pr_fmt("Enter: %s, %s line %i\n"),	\
			       __func__, __FILE__, __LINE__);		\
	} while (0)
#define LeaveFunction(level)						\
	do {								\
		if (level <= ip_vs_get_debug_level())			\
			printk(KERN_DEBUG				\
			       pr_fmt("Leave: %s, %s line %i\n"),	\
			       __func__, __FILE__, __LINE__);		\
	} while (0)
#else
#define EnterFunction(level)   do {} while (0)
#define LeaveFunction(level)   do {} while (0)
#endif

#define	IP_VS_WAIT_WHILE(expr)	while (expr) { cpu_relax(); }

/*
 *      The port number of FTP service (in network order).
 */
#define FTPPORT  cpu_to_be16(21)
#define FTPDATA  cpu_to_be16(20)

/*
 *      TCP State Values
 */
enum {
	IP_VS_TCP_S_NONE = 0,
	IP_VS_TCP_S_ESTABLISHED,
	IP_VS_TCP_S_SYN_SENT,
	IP_VS_TCP_S_SYN_RECV,
	IP_VS_TCP_S_FIN_WAIT,
	IP_VS_TCP_S_TIME_WAIT,
	IP_VS_TCP_S_CLOSE,
	IP_VS_TCP_S_CLOSE_WAIT,
	IP_VS_TCP_S_LAST_ACK,
	IP_VS_TCP_S_LISTEN,
	IP_VS_TCP_S_SYNACK,
	IP_VS_TCP_S_LAST
};

/*
 *	UDP State Values
 */
enum {
	IP_VS_UDP_S_NORMAL,
	IP_VS_UDP_S_LAST,
};

/*
 *	ICMP State Values
 */
enum {
	IP_VS_ICMP_S_NORMAL,
	IP_VS_ICMP_S_LAST,
};

/*
 *	Delta sequence info structure
 *	Each ip_vs_conn has 2 (output AND input seq. changes).
 *      Only used in the VS/NAT.
 */
struct ip_vs_seq {
	__u32 init_seq;		/* Add delta from this seq */
	__u32 delta;		/* Delta in sequence numbers */
	__u32 previous_delta;	/* Delta in sequence numbers
				   before last resized pkt */
	__u32 fdata_seq;	/* sequence of first data packet */
};

/*
 *	IPVS statistics objects
 */
struct ip_vs_stats {
	__u64 conns;		/* connections scheduled */
	__u64 inpkts;		/* incoming packets */
	__u64 outpkts;		/* outgoing packets */
	__u64 inbytes;		/* incoming bytes */
	__u64 outbytes;		/* outgoing bytes */
};

struct dst_entry;
struct iphdr;
struct ip_vs_conn;
struct ip_vs_app;
struct sk_buff;

struct ip_vs_protocol {
	struct ip_vs_protocol *next;
	char *name;
	u16 protocol;
	u16 num_states;
	int dont_defrag;
	atomic_t appcnt;	/* counter of proto app incs */
	int *timeout_table;	/* protocol timeout table */

	void (*init) (struct ip_vs_protocol * pp);

	void (*exit) (struct ip_vs_protocol * pp);

	int (*conn_schedule) (int af, struct sk_buff * skb,
			      struct ip_vs_protocol * pp,
			      int *verdict, struct ip_vs_conn ** cpp);

	struct ip_vs_conn *
	    (*conn_in_get) (int af,
			    const struct sk_buff * skb,
			    struct ip_vs_protocol * pp,
			    const struct ip_vs_iphdr * iph,
			    unsigned int proto_off, int inverse, int *res_dir);

	struct ip_vs_conn *
	    (*conn_out_get) (int af,
			     const struct sk_buff * skb,
			     struct ip_vs_protocol * pp,
			     const struct ip_vs_iphdr * iph,
			     unsigned int proto_off, int inverse, int *res_dir);

	int (*snat_handler) (struct sk_buff * skb,
			     struct ip_vs_protocol * pp,
			     struct ip_vs_conn * cp);

	int (*dnat_handler) (struct sk_buff * skb,
			     struct ip_vs_protocol * pp,
			     struct ip_vs_conn * cp);

	int (*fnat_in_handler) (struct sk_buff * skb,
				struct ip_vs_protocol * pp,
				struct ip_vs_conn * cp);

	int (*fnat_out_handler) (struct sk_buff * skb,
				 struct ip_vs_protocol * pp,
				 struct ip_vs_conn * cp);

	int (*csum_check) (int af, struct sk_buff * skb,
			   struct ip_vs_protocol * pp);

	const char *(*state_name) (int state);

	int (*state_transition) (struct ip_vs_conn * cp, int direction,
				 const struct sk_buff * skb,
				 struct ip_vs_protocol * pp);

	int (*register_app) (struct ip_vs_app * inc);

	void (*unregister_app) (struct ip_vs_app * inc);

	int (*app_conn_bind) (struct ip_vs_conn * cp);

	void (*debug_packet) (struct ip_vs_protocol * pp,
			      const struct sk_buff * skb,
			      int offset, const char *msg);

	void (*timeout_change) (struct ip_vs_protocol * pp, int flags);

	int (*set_state_timeout) (struct ip_vs_protocol * pp, char *sname,
				  int to);

	void (*conn_expire_handler) (struct ip_vs_protocol * pp,
				     struct ip_vs_conn * cp);
};

extern struct ip_vs_protocol *ip_vs_proto_get(unsigned short proto);

/*
 *      Connection Index Flags
 */
#define IP_VS_CIDX_F_OUT2IN     0x0001	/* packet director, OUTside2INside */
#define IP_VS_CIDX_F_IN2OUT     0x0002	/* packet director, INside2OUTside */
#define IP_VS_CIDX_F_DIR_MASK	0x0003	/* packet director mask */

/*
 *      Connection index in HASH TABLE, each connection has two index
 */
struct ip_vs_conn_idx {
	struct list_head c_list;	/* hashed list heads */

	u16 af;			/* address family */
	__u16 protocol;		/* Which protocol (TCP/UDP) */
	union nf_inet_addr s_addr;	/* source address */
	union nf_inet_addr d_addr;	/* destination address */
	__be16 s_port;		/* source port */
	__be16 d_port;		/* destination port */

	struct ip_vs_conn *cp;	/* point to connection */
	volatile __u16 flags;	/* status flags */
};

/*
 *	IP_VS structure allocated for each dynamically scheduled connection
 */
struct ip_vs_conn {
	struct ip_vs_conn_idx *in_idx;	/* client-vs hash index */
	struct ip_vs_conn_idx *out_idx;	/* rs-vs hash index */

	/* Protocol, addresses and port numbers */
	u16 af;			/* address family */
	__u16 protocol;		/* Which protocol (TCP/UDP) */
	union nf_inet_addr caddr;	/* client address */
	union nf_inet_addr vaddr;	/* virtual address */
	union nf_inet_addr laddr;	/* local address */
	union nf_inet_addr daddr;	/* destination address */
	__be16 cport;
	__be16 vport;
	__be16 lport;
	__be16 dport;

	/* counter and timer */
	atomic_t refcnt;	/* reference count */
	struct timer_list timer;	/* Expiration timer */
	volatile unsigned long timeout;	/* timeout */

	/* Flags and state transition */
	spinlock_t lock;	/* lock for state transition */
	volatile __u16 flags;	/* status flags */
	volatile __u16 state;	/* state info */
	volatile __u16 old_state;	/* old state, to be used for
					 * state transition triggerd
					 * synchronization
					 */
	u16 cpuid;

	/* Control members */
	struct ip_vs_conn *control;	/* Master control connection */
	atomic_t n_control;	/* Number of controlled ones */
	struct ip_vs_dest *dest;	/* real server */
	struct ip_vs_laddr *local;	/* local address */
	atomic_t in_pkts;	/* incoming packet counter */

	/* for fullnat */
	struct ip_vs_seq fnat_seq;

	/* packet transmitter for different forwarding methods.  If it
	   mangles the packet, it must return NF_DROP or better NF_STOLEN,
	   otherwise this must be changed to a sk_buff **.
	 */
	int (*packet_xmit) (struct sk_buff * skb, struct ip_vs_conn * cp,
			    struct ip_vs_protocol * pp);

	/* Note: we can group the following members into a structure,
	   in order to save more space, and the following members are
	   only used in VS/NAT anyway */
	struct ip_vs_app *app;	/* bound ip_vs_app object */
	void *app_data;		/* Application private data */
	struct ip_vs_seq in_seq;	/* incoming seq. struct */
	struct ip_vs_seq out_seq;	/* outgoing seq. struct */

	/* syn-proxy related members
	 */
	struct ip_vs_seq syn_proxy_seq;	/* seq. used in syn proxy */
	struct sk_buff_head ack_skb;	/* ack skb, save in step2 */
	struct sk_buff *syn_skb;	/* saved rs syn packet */
	atomic_t syn_retry_max;	/* syn retransmition max count */

	/* add for stopping ack storm */
	__u32 last_seq;		/* seq of the last ack packet */
	__u32 last_ack_seq;	/* ack seq of the last ack packet */
	atomic_t dup_ack_cnt;	/* count of repeated ack packets */

	/* for RST */
	__u32 rs_end_seq;	/* end seq(seq+datalen) of the last ack packet from rs */
	__u32 rs_ack_seq;	/* ack seq of the last ack packet from rs */

	/* L2 direct response xmit */
	struct net_device	*indev;
	unsigned char		src_hwaddr[ETH_ALEN];
	unsigned char		dst_hwaddr[ETH_ALEN];
	struct net_device	*dev_inside;
	unsigned char		src_hwaddr_inside[ETH_ALEN];
	unsigned char		dst_hwaddr_inside[ETH_ALEN];

	int est_timeout;	/* Now, we decide that every VS
				 * should have its private
				 * establish state timeout for user requirement.
				 * Each conn inherit this value from VS and
				 * set this value into conn timer
				 * when state change to establishment
				 */
};

/*
 *	Extended internal versions of struct ip_vs_service_user and
 *	ip_vs_dest_user for IPv6 support.
 *
 *	We need these to conveniently pass around service and destination
 *	options, but unfortunately, we also need to keep the old definitions to
 *	maintain userspace backwards compatibility for the setsockopt interface.
 */
struct ip_vs_service_user_kern {
	/* virtual service addresses */
	u16 af;
	u16 protocol;
	union nf_inet_addr addr;	/* virtual ip address */
	u16 port;
	u32 fwmark;		/* firwall mark of service */

	/* virtual service options */
	char *sched_name;
	unsigned flags;		/* virtual service flags */
	unsigned timeout;	/* persistent timeout in sec */
	u32 netmask;		/* persistent netmask */
	unsigned est_timeout;	/* vs private establish state timeout */
};

struct ip_vs_dest_user_kern {
	/* destination server address */
	union nf_inet_addr addr;
	u16 port;

	/* real server options */
	unsigned conn_flags;	/* connection flags */
	int weight;		/* destination weight */

	/* thresholds for active connections */
	u32 u_threshold;	/* upper threshold */
	u32 l_threshold;	/* lower threshold */
};

struct ip_vs_laddr_user_kern {
	union nf_inet_addr addr;	/* ip address */
};

/*
 *	The information about the virtual service offered to the net
 *	and the forwarding entries
 */
struct ip_vs_service {
	struct list_head s_list;	/* for normal service table */
	struct list_head f_list;	/* for fwmark-based service table */
	atomic_t refcnt;	/* reference counter */

	u16 af;			/* address family */
	__u16 protocol;		/* which protocol (TCP/UDP) */
	union nf_inet_addr addr;	/* IP address for virtual service */
	__be16 port;		/* port number for the service */
	__u32 fwmark;		/* firewall mark of the service */
	unsigned flags;		/* service status flags */
	unsigned timeout;	/* persistent timeout in ticks */
	__be32 netmask;		/* grouping granularity */

	/* for realservers list */
	struct list_head destinations;	/* real server d-linked list */
	__u32 num_dests;	/* number of servers */
	long weight;           /* sum of servers weight */

	/* for local ip address list, now only used in FULL NAT model */
	struct list_head laddr_list;	/* local ip address list */
	rwlock_t laddr_lock;	/* lock for protect curr_laddr */
	__u32 num_laddrs;	/* number of local ip address */
	struct list_head *curr_laddr;	/* laddr data list head */

	struct ip_vs_stats stats;	/* statistics for the service */
	struct ip_vs_app *inc;	/* bind conns to this app inc */

	/* for scheduling */
	struct ip_vs_scheduler *scheduler;	/* bound scheduler object */
	rwlock_t sched_lock;	/* lock sched_data */
	void *sched_data;	/* scheduler application data */

	/* for VS private establish state timeout, it should be inherited by every connection data structure */
	unsigned est_timeout;

	struct ip_vs_service *svc0;	/* the svc of cpu0 */
};

/*
 *	The real server destination forwarding entry
 *	with ip address, port number, and so on.
 */
struct ip_vs_dest {
	struct list_head n_list;	/* for the dests in the service */
	struct list_head d_list;	/* for table with all the dests */

	u16 af;			/* address family */
	union nf_inet_addr addr;	/* IP address of the server */
	__be16 port;		/* port number of the server */
	volatile unsigned flags;	/* dest status flags */
	atomic_t conn_flags;	/* flags to copy to conn */
	atomic_t weight;	/* server weight */

	atomic_t refcnt;	/* reference counter */
	struct ip_vs_stats stats;	/* statistics for destination server */

	/* connection counters and thresholds */
	atomic_t activeconns;	/* active connections */
	atomic_t inactconns;	/* inactive connections */
	atomic_t persistconns;	/* persistent connections */
	__u32 u_threshold;	/* upper threshold */
	__u32 l_threshold;	/* lower threshold */

	/* for destination cache */
	spinlock_t dst_lock;	/* lock of dst_cache */
	struct dst_entry *dst_cache;	/* destination cache entry */
	u32 dst_rtos;		/* RT_TOS(tos) for dst */

	/* for virtual service */
	struct ip_vs_service *svc;	/* service it belongs to */
	__u16 protocol;		/* which protocol (TCP/UDP) */
	union nf_inet_addr vaddr;	/* virtual IP address */
	__be16 vport;		/* virtual port number */
	__u32 vfwmark;		/* firewall mark of service */
};

/*
 *	Local ip address object, now only used in FULL NAT model
 */
struct ip_vs_laddr {
	struct list_head n_list;	/* for the local address in the service */
	u16 af;			/* address family */
	u16 cpuid;		/* record the cpu laddr has been assigned */
	union nf_inet_addr addr;	/* ip address */
	atomic64_t port;	/* port counts */
	atomic_t refcnt;	/* reference count */

	atomic64_t port_conflict;	/* conflict counts */
	atomic_t conn_counts;	/* connects counts */
};

/*
 *	The scheduler object
 */
struct ip_vs_scheduler {
	struct list_head n_list;	/* d-linked list head */
	char *name;		/* scheduler name */
	atomic_t refcnt;	/* reference counter */
	struct module *module;	/* THIS_MODULE/NULL */

	/* scheduler initializing service */
	int (*init_service) (struct ip_vs_service * svc);
	/* scheduling service finish */
	int (*done_service) (struct ip_vs_service * svc);
	/* scheduler updating service */
	int (*update_service) (struct ip_vs_service * svc);

	/* selecting a server from the given service */
	struct ip_vs_dest *(*schedule) (struct ip_vs_service * svc,
					const struct sk_buff * skb);
};

/*
 *	The application module object (a.k.a. app incarnation)
 */
struct ip_vs_app {
	struct list_head a_list;	/* member in app list */
	int type;		/* IP_VS_APP_TYPE_xxx */
	char *name;		/* application module name */
	__u16 protocol;
	struct module *module;	/* THIS_MODULE/NULL */
	struct list_head incs_list;	/* list of incarnations */

	/* members for application incarnations */
	struct list_head p_list;	/* member in proto app list */
	struct ip_vs_app *app;	/* its real application */
	__be16 port;		/* port number in net order */
	atomic_t usecnt;	/* usage counter */

	/* output hook: return false if can't linearize. diff set for TCP.  */
	int (*pkt_out) (struct ip_vs_app *, struct ip_vs_conn *,
			struct sk_buff *, int *diff);

	/* input hook: return false if can't linearize. diff set for TCP. */
	int (*pkt_in) (struct ip_vs_app *, struct ip_vs_conn *,
		       struct sk_buff *, int *diff);

	/* ip_vs_app initializer */
	int (*init_conn) (struct ip_vs_app *, struct ip_vs_conn *);

	/* ip_vs_app finish */
	int (*done_conn) (struct ip_vs_app *, struct ip_vs_conn *);

	/* not used now */
	int (*bind_conn) (struct ip_vs_app *, struct ip_vs_conn *,
			  struct ip_vs_protocol *);

	void (*unbind_conn) (struct ip_vs_app *, struct ip_vs_conn *);

	int *timeout_table;
	int *timeouts;
	int timeouts_size;

	int (*conn_schedule) (struct sk_buff * skb, struct ip_vs_app * app,
			      int *verdict, struct ip_vs_conn ** cpp);

	struct ip_vs_conn *
	    (*conn_in_get) (const struct sk_buff * skb, struct ip_vs_app * app,
			    const struct iphdr * iph, unsigned int proto_off,
			    int inverse);

	struct ip_vs_conn *
	    (*conn_out_get) (const struct sk_buff * skb, struct ip_vs_app * app,
			     const struct iphdr * iph, unsigned int proto_off,
			     int inverse);

	int (*state_transition) (struct ip_vs_conn * cp, int direction,
				 const struct sk_buff * skb,
				 struct ip_vs_app * app);

	void (*timeout_change) (struct ip_vs_app * app, int flags);
};

#define TCPOPT_ADDR  254
#define TCPOLEN_ADDR 8		/* |opcode|size|ip+port| = 1 + 1 + 6 */

/*
 * insert client ip in tcp option, now only support IPV4,
 * must be 4 bytes alignment.
 */
struct ip_vs_tcpo_addr {
	__u8 opcode;
	__u8 opsize;
	__u16 port;
	__u32 addr;
};

#ifdef CONFIG_IP_VS_IPV6
#define TCPOPT_ADDR_V6	253
#define TCPOLEN_ADDR_V6	20	/* |opcode|size|port|ipv6| = 1 + 1 + 2 + 16 */

/*
 * insert client ip in tcp option, for IPv6
 * must be 4 bytes alignment.
 */
struct ip_vs_tcpo_addr_v6 {
	__u8	opcode;
	__u8	opsize;
	__be16	port;
	struct in6_addr addr;
};
#endif

/*
 * statistics for FULLNAT and SYNPROXY
 * in /proc/net/ip_vs_ext_stats
 */
enum {
	FULLNAT_ADD_TOA_OK = 1,
	FULLNAT_ADD_TOA_FAIL_LEN,
	FULLNAT_ADD_TOA_HEAD_FULL,
	FULLNAT_ADD_TOA_FAIL_MEM,
	FULLNAT_ADD_TOA_FAIL_PROTO,
	FULLNAT_CONN_REUSED,
	FULLNAT_CONN_REUSED_CLOSE,
	FULLNAT_CONN_REUSED_TIMEWAIT,
	FULLNAT_CONN_REUSED_FINWAIT,
	FULLNAT_CONN_REUSED_CLOSEWAIT,
	FULLNAT_CONN_REUSED_LASTACK,
	FULLNAT_CONN_REUSED_ESTAB,
	SYNPROXY_RS_ERROR,
	SYNPROXY_NULL_ACK,
	SYNPROXY_BAD_ACK,
	SYNPROXY_OK_ACK,
	SYNPROXY_SYN_CNT,
	SYNPROXY_ACK_STORM,
	SYNPROXY_SYNSEND_QLEN,
	SYNPROXY_CONN_REUSED,
	SYNPROXY_CONN_REUSED_CLOSE,
	SYNPROXY_CONN_REUSED_TIMEWAIT,
	SYNPROXY_CONN_REUSED_FINWAIT,
	SYNPROXY_CONN_REUSED_CLOSEWAIT,
	SYNPROXY_CONN_REUSED_LASTACK,
	DEFENCE_IP_FRAG_DROP,
	DEFENCE_TCP_DROP,
	DEFENCE_UDP_DROP,
	FAST_XMIT_REJECT,
	FAST_XMIT_PASS,
	FAST_XMIT_SKB_COPY,
	FAST_XMIT_NO_MAC,
	FAST_XMIT_SYNPROXY_SAVE,
	FAST_XMIT_DEV_LOST,
	FAST_XMIT_REJECT_INSIDE,
	FAST_XMIT_PASS_INSIDE,
	FAST_XMIT_SYNPROXY_SAVE_INSIDE,
	RST_IN_SYN_SENT,
	RST_OUT_SYN_SENT,
	RST_IN_ESTABLISHED,
	RST_OUT_ESTABLISHED,
	GRO_PASS,
	LRO_REJECT,
	XMIT_UNEXPECTED_MTU,
	CONN_SCHED_UNREACH,
	SYNPROXY_NO_DEST,
	CONN_EXCEEDED,
	IP_VS_EXT_STAT_LAST
};

struct ip_vs_estats_entry {
	char *name;
	int entry;
};

#define IP_VS_ESTATS_ITEM(_name, _entry) { \
        .name = _name,            \
        .entry = _entry,          \
}

#define IP_VS_ESTATS_LAST {    \
        NULL,           \
        0,              \
}

struct ip_vs_estats_mib {
	unsigned long mibs[IP_VS_EXT_STAT_LAST];
};

#define IP_VS_INC_ESTATS(mib, field)         \
        (per_cpu_ptr(mib, smp_processor_id())->mibs[field]++)

extern struct ip_vs_estats_mib *ip_vs_esmib;

/*
 *      IPVS core functions
 *      (from ip_vs_core.c)
 */
extern const char *ip_vs_proto_name(unsigned proto);
extern void ip_vs_init_hash_table(struct list_head *table, int rows);
#define IP_VS_INIT_HASH_TABLE(t) ip_vs_init_hash_table((t), ARRAY_SIZE((t)))

#define IP_VS_APP_TYPE_FTP	1

/*
 *     ip_vs_conn handling functions
 *     (from ip_vs_conn.c)
 */

/*
 *     IPVS connection entry hash table
 */
#ifndef CONFIG_IP_VS_TAB_BITS
#define CONFIG_IP_VS_TAB_BITS   22
#endif

//#define IP_VS_CONN_TAB_BITS	CONFIG_IP_VS_TAB_BITS
#define IP_VS_CONN_TAB_BITS	20
#define IP_VS_CONN_TAB_SIZE     (1 << IP_VS_CONN_TAB_BITS)
#define IP_VS_CONN_TAB_MASK     (IP_VS_CONN_TAB_SIZE - 1)

enum {
	IP_VS_DIR_INPUT = 0,
	IP_VS_DIR_OUTPUT,
	IP_VS_DIR_INPUT_ONLY,
	IP_VS_DIR_LAST,
};

extern struct ip_vs_conn *ip_vs_conn_get
    (int af, int protocol, const union nf_inet_addr *s_addr, __be16 s_port,
     const union nf_inet_addr *d_addr, __be16 d_port, int *res_dir);

extern struct ip_vs_conn *ip_vs_ct_in_get
    (int af, int protocol, const union nf_inet_addr *s_addr, __be16 s_port,
     const union nf_inet_addr *d_addr, __be16 d_port);

/* put back the conn without restarting its timer */
static inline void __ip_vs_conn_put(struct ip_vs_conn *cp)
{
	atomic_dec(&cp->refcnt);
}
extern void ip_vs_conn_put(struct ip_vs_conn *cp);
extern void ip_vs_conn_fill_cport(struct ip_vs_conn *cp, __be16 cport);

extern struct ip_vs_conn *ip_vs_conn_new(int af, int proto,
					 const union nf_inet_addr *caddr,
					 __be16 cport,
					 const union nf_inet_addr *vaddr,
					 __be16 vport,
					 const union nf_inet_addr *daddr,
					 __be16 dport, unsigned flags,
					 struct ip_vs_dest *dest,
					 struct sk_buff *skb,
					 int is_synproxy_on);
extern void ip_vs_conn_expire_now(struct ip_vs_conn *cp);

extern const char *ip_vs_state_name(__u16 proto, int state);

extern void ip_vs_tcp_conn_listen(struct ip_vs_conn *cp);
extern int ip_vs_check_template(struct ip_vs_conn *ct);
extern void ip_vs_random_dropentry(void);
extern int ip_vs_conn_init(void);
extern void ip_vs_conn_cleanup(void);

static inline void ip_vs_control_del(struct ip_vs_conn *cp)
{
	struct ip_vs_conn *ctl_cp = cp->control;
	if (!ctl_cp) {
		IP_VS_ERR_BUF("request control DEL for uncontrolled: "
			      "%s:%d to %s:%d\n",
			      IP_VS_DBG_ADDR(cp->af, &cp->caddr),
			      ntohs(cp->cport),
			      IP_VS_DBG_ADDR(cp->af, &cp->vaddr),
			      ntohs(cp->vport));

		return;
	}

	IP_VS_DBG_BUF(7, "DELeting control for: "
		      "cp.dst=%s:%d ctl_cp.dst=%s:%d\n",
		      IP_VS_DBG_ADDR(cp->af, &cp->caddr),
		      ntohs(cp->cport),
		      IP_VS_DBG_ADDR(cp->af, &ctl_cp->caddr),
		      ntohs(ctl_cp->cport));

	cp->control = NULL;
	if (atomic_read(&ctl_cp->n_control) == 0) {
		IP_VS_ERR_BUF("BUG control DEL with n=0 : "
			      "%s:%d to %s:%d\n",
			      IP_VS_DBG_ADDR(cp->af, &cp->caddr),
			      ntohs(cp->cport),
			      IP_VS_DBG_ADDR(cp->af, &cp->vaddr),
			      ntohs(cp->vport));

		return;
	}
	atomic_dec(&ctl_cp->n_control);
}

static inline void
ip_vs_control_add(struct ip_vs_conn *cp, struct ip_vs_conn *ctl_cp)
{
	if (cp->control) {
		IP_VS_ERR_BUF("request control ADD for already controlled: "
			      "%s:%d to %s:%d\n",
			      IP_VS_DBG_ADDR(cp->af, &cp->caddr),
			      ntohs(cp->cport),
			      IP_VS_DBG_ADDR(cp->af, &cp->vaddr),
			      ntohs(cp->vport));

		ip_vs_control_del(cp);
	}

	IP_VS_DBG_BUF(7, "ADDing control for: "
		      "cp.dst=%s:%d ctl_cp.dst=%s:%d\n",
		      IP_VS_DBG_ADDR(cp->af, &cp->caddr),
		      ntohs(cp->cport),
		      IP_VS_DBG_ADDR(cp->af, &ctl_cp->caddr),
		      ntohs(ctl_cp->cport));

	cp->control = ctl_cp;
	atomic_inc(&ctl_cp->n_control);
}

/*
 *      IPVS application functions
 *      (from ip_vs_app.c)
 */
#define IP_VS_APP_MAX_PORTS  8
extern int register_ip_vs_app(struct ip_vs_app *app);
extern void unregister_ip_vs_app(struct ip_vs_app *app);
extern int ip_vs_bind_app(struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern void ip_vs_unbind_app(struct ip_vs_conn *cp);
extern int
register_ip_vs_app_inc(struct ip_vs_app *app, __u16 proto, __u16 port);
extern int ip_vs_app_inc_get(struct ip_vs_app *inc);
extern void ip_vs_app_inc_put(struct ip_vs_app *inc);

extern int ip_vs_app_pkt_out(struct ip_vs_conn *, struct sk_buff *skb);
extern int ip_vs_app_pkt_in(struct ip_vs_conn *, struct sk_buff *skb);
extern int ip_vs_skb_replace(struct sk_buff *skb, gfp_t pri,
			     char *o_buf, int o_len, char *n_buf, int n_len);
extern int ip_vs_app_init(void);
extern void ip_vs_app_cleanup(void);

/*
 *	IPVS protocol functions (from ip_vs_proto.c)
 */
extern int ip_vs_protocol_init(void);
extern void ip_vs_protocol_cleanup(void);
extern void ip_vs_protocol_timeout_change(int flags);
extern int *ip_vs_create_timeout_table(int *table, int size);
extern int
ip_vs_set_state_timeout(int *table, int num, const char *const *names,
			const char *name, int to);
extern void
ip_vs_tcpudp_debug_packet(struct ip_vs_protocol *pp, const struct sk_buff *skb,
			  int offset, const char *msg);

extern struct ip_vs_protocol ip_vs_protocol_tcp;
extern struct ip_vs_protocol ip_vs_protocol_udp;
extern struct ip_vs_protocol ip_vs_protocol_icmp;
extern struct ip_vs_protocol ip_vs_protocol_esp;
extern struct ip_vs_protocol ip_vs_protocol_ah;

/*
 *      Registering/unregistering scheduler functions
 *      (from ip_vs_sched.c)
 */
extern int register_ip_vs_scheduler(struct ip_vs_scheduler *scheduler);
extern int unregister_ip_vs_scheduler(struct ip_vs_scheduler *scheduler);
extern int ip_vs_bind_scheduler(struct ip_vs_service *svc,
				struct ip_vs_scheduler *scheduler);
extern int ip_vs_unbind_scheduler(struct ip_vs_service *svc);
extern struct ip_vs_scheduler *ip_vs_scheduler_get(const char *sched_name);
extern void ip_vs_scheduler_put(struct ip_vs_scheduler *scheduler);
extern struct ip_vs_conn *ip_vs_schedule(struct ip_vs_service *svc,
					 struct sk_buff *skb,
					 int is_synproxy_on);
extern int ip_vs_leave(struct ip_vs_service *svc, struct sk_buff *skb,
		       struct ip_vs_protocol *pp);

/*
 *      IPVS control data and functions (from ip_vs_ctl.c)
 */
extern int sysctl_ip_vs_cache_bypass;
extern int sysctl_ip_vs_expire_nodest_conn;
extern int sysctl_ip_vs_expire_quiescent_template;
extern int sysctl_ip_vs_sync_threshold[2];
extern int sysctl_ip_vs_nat_icmp_send;
extern struct ip_vs_stats *ip_vs_stats;
extern const struct ctl_path net_vs_ctl_path[];
extern int sysctl_ip_vs_timestamp_remove_entry;
extern int sysctl_ip_vs_mss_adjust_entry;
extern int sysctl_ip_vs_conn_reused_entry;
extern int sysctl_ip_vs_toa_entry;
extern int sysctl_ip_vs_lport_max;
extern int sysctl_ip_vs_lport_min;
extern int sysctl_ip_vs_lport_tries;
extern int sysctl_ip_vs_frag_drop_entry;
extern int sysctl_ip_vs_tcp_drop_entry;
extern int sysctl_ip_vs_udp_drop_entry;
extern int sysctl_ip_vs_conn_expire_tcp_rst;
extern int sysctl_ip_vs_fast_xmit;
extern int sysctl_ip_vs_fast_xmit_inside;
extern int sysctl_ip_vs_csum_offload;
extern int sysctl_ip_vs_reserve_core;
extern int sysctl_ip_vs_conn_max_num;

DECLARE_PER_CPU(spinlock_t, ip_vs_svc_lock);

extern struct ip_vs_service *ip_vs_service_get(int af, __u32 fwmark,
					       __u16 protocol,
					       const union nf_inet_addr *vaddr,
					       __be16 vport);
extern struct ip_vs_service *ip_vs_lookup_vip(int af, __u16 protocol,
					      const union nf_inet_addr *vaddr);

static inline void ip_vs_service_put(struct ip_vs_service *svc)
{
	if (likely(svc != NULL))
		spin_unlock(&__get_cpu_var(ip_vs_svc_lock));
}

extern struct ip_vs_dest *ip_vs_lookup_real_service(int af, __u16 protocol,
						    const union nf_inet_addr
						    *daddr, __be16 dport);

extern int ip_vs_use_count_inc(void);
extern void ip_vs_use_count_dec(void);
extern int ip_vs_control_init(void);
extern void ip_vs_control_cleanup(void);
extern struct ip_vs_dest *ip_vs_find_dest(int af,
					  const union nf_inet_addr *daddr,
					  __be16 dport,
					  const union nf_inet_addr *vaddr,
					  __be16 vport, __u16 protocol);
extern struct ip_vs_dest *ip_vs_try_bind_dest(struct ip_vs_conn *cp);

extern void ip_vs_laddr_hold(struct ip_vs_laddr *addr);
extern void ip_vs_laddr_put(struct ip_vs_laddr *addr);

/*
 *      IPVS sync daemon data and function prototypes
 *      (from ip_vs_sync.c)
 */
extern volatile int ip_vs_sync_state;
extern volatile int ip_vs_master_syncid;
extern volatile int ip_vs_backup_syncid;
extern char ip_vs_master_mcast_ifn[IP_VS_IFNAME_MAXLEN];
extern char ip_vs_backup_mcast_ifn[IP_VS_IFNAME_MAXLEN];
extern int start_sync_thread(int state, char *mcast_ifn, __u8 syncid);
extern int stop_sync_thread(int state);
extern void ip_vs_sync_conn(struct ip_vs_conn *cp);

/*
 *      IPVS statistic prototypes (from ip_vs_stats.c)
 */
#define ip_vs_stats_cpu(stats,cpu)  \
	(*per_cpu_ptr((stats), (cpu)))

#define ip_vs_stats_this_cpu(stats) \
	(*this_cpu_ptr((stats)))

extern int ip_vs_new_stats(struct ip_vs_stats** p);
extern void ip_vs_del_stats(struct ip_vs_stats* p);
extern void ip_vs_zero_stats(struct ip_vs_stats* stats);
extern void ip_vs_in_stats(struct ip_vs_conn *cp, struct sk_buff *skb);
extern void ip_vs_out_stats(struct ip_vs_conn *cp, struct sk_buff *skb);
extern void ip_vs_conn_stats(struct ip_vs_conn *cp, struct ip_vs_service *svc);

/*
 *	Lookup route table
 */
extern struct rtable *ip_vs_get_rt(union nf_inet_addr *addr, u32 rtos);

#ifdef CONFIG_IP_VS_IPV6
extern struct rt6_info *ip_vs_get_rt_v6(union nf_inet_addr *addr);
#endif

/*
 *	Various IPVS packet transmitters (from ip_vs_xmit.c)
 */
extern int ip_vs_null_xmit
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_bypass_xmit
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_nat_xmit
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_fnat_xmit
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_tunnel_xmit
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_dr_xmit
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_icmp_xmit
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp,
     int offset);
extern void ip_vs_dst_reset(struct ip_vs_dest *dest);
extern int ip_vs_normal_response_xmit
    (struct sk_buff *skb, struct ip_vs_protocol *pp, struct ip_vs_conn *cp,
     int ihl);
extern int ip_vs_fnat_response_xmit(struct sk_buff *skb,
				    struct ip_vs_protocol *pp,
				    struct ip_vs_conn *cp, int ihl);
extern int ip_vs_normal_response_icmp_xmit(struct sk_buff *skb,
					   struct ip_vs_protocol *pp,
					   struct ip_vs_conn *cp, int offset);
extern int ip_vs_fnat_response_icmp_xmit(struct sk_buff *skb,
					 struct ip_vs_protocol *pp,
					 struct ip_vs_conn *cp, int offset);

#ifdef CONFIG_IP_VS_IPV6
extern int ip_vs_bypass_xmit_v6
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_nat_xmit_v6
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_fnat_xmit_v6
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_tunnel_xmit_v6
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_dr_xmit_v6
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp);
extern int ip_vs_icmp_xmit_v6
    (struct sk_buff *skb, struct ip_vs_conn *cp, struct ip_vs_protocol *pp,
     int offset);
extern int ip_vs_normal_response_xmit_v6
    (struct sk_buff *skb, struct ip_vs_protocol *pp, struct ip_vs_conn *cp,
     int ihl);
extern int ip_vs_fnat_response_xmit_v6(struct sk_buff *skb,
				       struct ip_vs_protocol *pp,
				       struct ip_vs_conn *cp, int ihl);
extern int ip_vs_normal_response_icmp_xmit_v6(struct sk_buff *skb,
					      struct ip_vs_protocol *pp,
					      struct ip_vs_conn *cp,
					      int offset);
extern int ip_vs_fnat_response_icmp_xmit_v6(struct sk_buff *skb,
					    struct ip_vs_protocol *pp,
					    struct ip_vs_conn *cp, int offset);
#endif

/*
 *	This is a simple mechanism to ignore packets when
 *	we are loaded. Just set ip_vs_drop_rate to 'n' and
 *	we start to drop 1/rate of the packets
 */
extern int ip_vs_drop_rate;
extern int ip_vs_drop_counter;

static __inline__ int ip_vs_todrop(void)
{
	if (!ip_vs_drop_rate)
		return 0;
	if (--ip_vs_drop_counter > 0)
		return 0;
	ip_vs_drop_counter = ip_vs_drop_rate;
	return 1;
}

/*
 *      ip_vs_fwd_tag returns the forwarding tag of the connection
 */
#define IP_VS_FWD_METHOD(cp)  (cp->flags & IP_VS_CONN_F_FWD_MASK)

static inline char ip_vs_fwd_tag(struct ip_vs_conn *cp)
{
	char fwd;

	switch (IP_VS_FWD_METHOD(cp)) {
	case IP_VS_CONN_F_MASQ:
		fwd = 'M';
		break;
	case IP_VS_CONN_F_LOCALNODE:
		fwd = 'L';
		break;
	case IP_VS_CONN_F_TUNNEL:
		fwd = 'T';
		break;
	case IP_VS_CONN_F_DROUTE:
		fwd = 'R';
		break;
	case IP_VS_CONN_F_BYPASS:
		fwd = 'B';
		break;
	case IP_VS_CONN_F_FULLNAT:
		fwd = 'F';
		break;
	default:
		fwd = '?';
		break;
	}
	return fwd;
}

extern __sum16 ip_vs_checksum_complete(struct sk_buff *skb, int offset);

static inline __wsum ip_vs_check_diff4(__be32 old, __be32 new, __wsum oldsum)
{
	__be32 diff[2] = { ~old, new };

	return csum_partial(diff, sizeof(diff), oldsum);
}

#ifdef CONFIG_IP_VS_IPV6
static inline __wsum ip_vs_check_diff16(const __be32 * old, const __be32 * new,
					__wsum oldsum)
{
	__be32 diff[8] = { ~old[3], ~old[2], ~old[1], ~old[0],
		new[3], new[2], new[1], new[0]
	};

	return csum_partial(diff, sizeof(diff), oldsum);
}
#endif

static inline __wsum ip_vs_check_diff2(__be16 old, __be16 new, __wsum oldsum)
{
	__be16 diff[2] = { ~old, new };

	return csum_partial(diff, sizeof(diff), oldsum);
}

#endif				/* __KERNEL__ */

#endif				/* _NET_IP_VS_H */
