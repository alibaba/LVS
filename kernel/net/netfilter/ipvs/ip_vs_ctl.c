/*
 * IPVS         An implementation of the IP virtual server support for the
 *              LINUX operating system.  IPVS is now implemented as a module
 *              over the NetFilter framework. IPVS can be used to build a
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
 * Changes:
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/workqueue.h>
#include <linux/swap.h>
#include <linux/seq_file.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/mutex.h>

#include <net/net_namespace.h>
#include <net/ip.h>
#ifdef CONFIG_IP_VS_IPV6
#include <net/ipv6.h>
#include <net/ip6_route.h>
#endif
#include <net/route.h>
#include <net/sock.h>
#include <net/genetlink.h>

#include <asm/uaccess.h>

#include <net/ip_vs.h>
#include <net/ip_vs_synproxy.h>

/* semaphore for IPVS sockopts. And, [gs]etsockopt may sleep. */
static DEFINE_MUTEX(__ip_vs_mutex);

/* percpu lock for service table */
DEFINE_PER_CPU(spinlock_t, ip_vs_svc_lock);

/* lock for state and timeout tables */
static DEFINE_RWLOCK(__ip_vs_securetcp_lock);

/* lock for drop entry handling */
static DEFINE_SPINLOCK(__ip_vs_dropentry_lock);

/* lock for drop packet handling */
static DEFINE_SPINLOCK(__ip_vs_droppacket_lock);

/* 1/rate drop and drop-entry variables */
int ip_vs_drop_rate = 0;
int ip_vs_drop_counter = 0;
static atomic_t ip_vs_dropentry = ATOMIC_INIT(0);

/* number of virtual services */
static int ip_vs_num_services = 0;

/* sysctl variables */
static int sysctl_ip_vs_drop_entry = 0;
static int sysctl_ip_vs_drop_packet = 0;
static int sysctl_ip_vs_secure_tcp = 0;
static int sysctl_ip_vs_amemthresh = 1024;
static int sysctl_ip_vs_am_droprate = 10;
int sysctl_ip_vs_cache_bypass = 0;
int sysctl_ip_vs_expire_nodest_conn = 0;
int sysctl_ip_vs_expire_quiescent_template = 0;
int sysctl_ip_vs_sync_threshold[2] = { 3, 50 };
int sysctl_ip_vs_nat_icmp_send = 0;
/*
 * sysctl for FULLNAT
 */
int sysctl_ip_vs_timestamp_remove_entry = 1;
int sysctl_ip_vs_mss_adjust_entry = 1;
int sysctl_ip_vs_conn_reused_entry = 1;
int sysctl_ip_vs_toa_entry = 1;
static int ip_vs_entry_min = 0;
static int ip_vs_entry_max = 1;
extern int sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_LAST + 1];
/*
 * sysctl for SYNPROXY
 */
/* syn-proxy sysctl variables */
int sysctl_ip_vs_synproxy_init_mss = IP_VS_SYNPROXY_INIT_MSS_DEFAULT;
int sysctl_ip_vs_synproxy_sack = IP_VS_SYNPROXY_SACK_DEFAULT;
int sysctl_ip_vs_synproxy_wscale = IP_VS_SYNPROXY_WSCALE_DEFAULT;
int sysctl_ip_vs_synproxy_timestamp = IP_VS_SYNPROXY_TIMESTAMP_DEFAULT;
int sysctl_ip_vs_synproxy_synack_ttl = IP_VS_SYNPROXY_TTL_DEFAULT;
int sysctl_ip_vs_synproxy_defer = IP_VS_SYNPROXY_DEFER_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse = IP_VS_SYNPROXY_CONN_REUSE_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse_cl = IP_VS_SYNPROXY_CONN_REUSE_CL_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse_tw = IP_VS_SYNPROXY_CONN_REUSE_TW_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse_fw = IP_VS_SYNPROXY_CONN_REUSE_FW_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse_cw = IP_VS_SYNPROXY_CONN_REUSE_CW_DEFAULT;
int sysctl_ip_vs_synproxy_conn_reuse_la = IP_VS_SYNPROXY_CONN_REUSE_LA_DEFAULT;
int sysctl_ip_vs_synproxy_dup_ack_thresh = IP_VS_SYNPROXY_DUP_ACK_DEFAULT;
int sysctl_ip_vs_synproxy_skb_store_thresh = IP_VS_SYNPROXY_SKB_STORE_DEFAULT;
int sysctl_ip_vs_synproxy_syn_retry = IP_VS_SYNPROXY_SYN_RETRY_DEFAULT;

static int ip_vs_synproxy_switch_min = 0;
static int ip_vs_synproxy_switch_max = 1;
static int ip_vs_synproxy_wscale_min = 0;
static int ip_vs_synproxy_wscale_max = IP_VS_SYNPROXY_WSCALE_MAX;
static int ip_vs_synproxy_init_mss_min = 0;
static int ip_vs_synproxy_init_mss_max = 65535;
static int ip_vs_synproxy_synack_ttl_min = IP_VS_SYNPROXY_TTL_MIN;
static int ip_vs_synproxy_synack_ttl_max = IP_VS_SYNPROXY_TTL_MAX;
static int ip_vs_synproxy_dup_ack_cnt_min = 0;
static int ip_vs_synproxy_dup_ack_cnt_max = 65535;
static int ip_vs_synproxy_syn_retry_min = 0;
static int ip_vs_synproxy_syn_retry_max = 6;
static int ip_vs_synproxy_skb_store_thresh_min = 0;
static int ip_vs_synproxy_skb_store_thresh_max = 5;
/* local address port range */
int sysctl_ip_vs_lport_max = 65535;
int sysctl_ip_vs_lport_min = 5000;
int sysctl_ip_vs_lport_tries = 10000;
static int ip_vs_port_min = 1025;
static int ip_vs_port_max = 65535;
static int ip_vs_port_try_min = 10;
static int ip_vs_port_try_max = 60000;
/*
 * sysctl for DEFENCE ATTACK
 */
int sysctl_ip_vs_frag_drop_entry = 1;
int sysctl_ip_vs_tcp_drop_entry = 1;
int sysctl_ip_vs_udp_drop_entry = 1;
/* send rst when tcp session expire */
int sysctl_ip_vs_conn_expire_tcp_rst = 1;
/* L2 fast xmit, response only (to client) */
int sysctl_ip_vs_fast_xmit = 1;
/* L2 fast xmit, inside (to RS) */
int sysctl_ip_vs_fast_xmit_inside = 1;
/* skb csum offload */
int sysctl_ip_vs_csum_offload = 1;

/* reserve core for the control flow */
int sysctl_ip_vs_reserve_core = 0;
static int ip_vs_reserve_core_min = 0;
static int ip_vs_reserve_core_max = 6;

#ifdef CONFIG_IP_VS_DEBUG
static int sysctl_ip_vs_debug_level = 0;

int ip_vs_get_debug_level(void)
{
	return sysctl_ip_vs_debug_level;
}
#endif

#ifdef CONFIG_IP_VS_IPV6
/* Taken from rt6_fill_node() in net/ipv6/route.c, is there a better way? */
static int __ip_vs_addr_is_local_v6(const struct in6_addr *addr)
{
	struct rt6_info *rt;
	struct flowi fl = {
		.oif = 0,
		.nl_u = {
			 .ip6_u = {
				   .daddr = *addr,
				   .saddr = {.s6_addr32 = {0, 0, 0, 0}},}},
	};

	rt = (struct rt6_info *)ip6_route_output(&init_net, NULL, &fl);
	if (rt && rt->rt6i_dev && (rt->rt6i_dev->flags & IFF_LOOPBACK))
		return 1;

	return 0;
}
#endif
/*
 *	update_defense_level is called from keventd and from sysctl,
 *	so it needs to protect itself from softirqs
 */
static void update_defense_level(void)
{
	struct sysinfo i;
	static int old_secure_tcp = 0;
	int availmem;
	int nomem;
	int to_change = -1;

	/* we only count free and buffered memory (in pages) */
	si_meminfo(&i);
	availmem = i.freeram + i.bufferram;
	/* however in linux 2.5 the i.bufferram is total page cache size,
	   we need adjust it */
	/* si_swapinfo(&i); */
	/* availmem = availmem - (i.totalswap - i.freeswap); */

	nomem = (availmem < sysctl_ip_vs_amemthresh);

	local_bh_disable();

	/* drop_entry */
	spin_lock(&__ip_vs_dropentry_lock);
	switch (sysctl_ip_vs_drop_entry) {
	case 0:
		atomic_set(&ip_vs_dropentry, 0);
		break;
	case 1:
		if (nomem) {
			atomic_set(&ip_vs_dropentry, 1);
			sysctl_ip_vs_drop_entry = 2;
		} else {
			atomic_set(&ip_vs_dropentry, 0);
		}
		break;
	case 2:
		if (nomem) {
			atomic_set(&ip_vs_dropentry, 1);
		} else {
			atomic_set(&ip_vs_dropentry, 0);
			sysctl_ip_vs_drop_entry = 1;
		};
		break;
	case 3:
		atomic_set(&ip_vs_dropentry, 1);
		break;
	}
	spin_unlock(&__ip_vs_dropentry_lock);

	/* drop_packet */
	spin_lock(&__ip_vs_droppacket_lock);
	switch (sysctl_ip_vs_drop_packet) {
	case 0:
		ip_vs_drop_rate = 0;
		break;
	case 1:
		if (nomem) {
			ip_vs_drop_rate = ip_vs_drop_counter
			    = sysctl_ip_vs_amemthresh /
			    (sysctl_ip_vs_amemthresh - availmem);
			sysctl_ip_vs_drop_packet = 2;
		} else {
			ip_vs_drop_rate = 0;
		}
		break;
	case 2:
		if (nomem) {
			ip_vs_drop_rate = ip_vs_drop_counter
			    = sysctl_ip_vs_amemthresh /
			    (sysctl_ip_vs_amemthresh - availmem);
		} else {
			ip_vs_drop_rate = 0;
			sysctl_ip_vs_drop_packet = 1;
		}
		break;
	case 3:
		ip_vs_drop_rate = sysctl_ip_vs_am_droprate;
		break;
	}
	spin_unlock(&__ip_vs_droppacket_lock);

	/* secure_tcp */
	write_lock(&__ip_vs_securetcp_lock);
	switch (sysctl_ip_vs_secure_tcp) {
	case 0:
		if (old_secure_tcp >= 2)
			to_change = 0;
		break;
	case 1:
		if (nomem) {
			if (old_secure_tcp < 2)
				to_change = 1;
			sysctl_ip_vs_secure_tcp = 2;
		} else {
			if (old_secure_tcp >= 2)
				to_change = 0;
		}
		break;
	case 2:
		if (nomem) {
			if (old_secure_tcp < 2)
				to_change = 1;
		} else {
			if (old_secure_tcp >= 2)
				to_change = 0;
			sysctl_ip_vs_secure_tcp = 1;
		}
		break;
	case 3:
		if (old_secure_tcp < 2)
			to_change = 1;
		break;
	}
	old_secure_tcp = sysctl_ip_vs_secure_tcp;
	if (to_change >= 0)
		ip_vs_protocol_timeout_change(sysctl_ip_vs_secure_tcp > 1);
	write_unlock(&__ip_vs_securetcp_lock);

	local_bh_enable();
}

int ip_vs_use_count_inc(void)
{
	return try_module_get(THIS_MODULE);
}

void ip_vs_use_count_dec(void)
{
	module_put(THIS_MODULE);
}

/*
 *	Hash table: for virtual service lookups
 */
#define IP_VS_SVC_TAB_BITS 12
#define IP_VS_SVC_TAB_SIZE (1 << IP_VS_SVC_TAB_BITS)
#define IP_VS_SVC_TAB_MASK (IP_VS_SVC_TAB_SIZE - 1)

/* the service table hashed by <protocol, addr, port> */
DEFINE_PER_CPU(struct list_head *, ip_vs_svc_tab_percpu);
/* the service table hashed by fwmark */
DEFINE_PER_CPU(struct list_head *, ip_vs_svc_fwm_tab_percpu);

/*
 *	Trash for destinations
 */
DEFINE_PER_CPU(struct list_head, ip_vs_dest_trash_percpu);

/*
 *	FTP & NULL virtual service counters
 */
static atomic_t ip_vs_ftpsvc_counter = ATOMIC_INIT(0);
static atomic_t ip_vs_nullsvc_counter = ATOMIC_INIT(0);

/*
 *	Returns hash value for virtual service
 */
static __inline__ unsigned
ip_vs_svc_hashkey(int af, unsigned proto, const union nf_inet_addr *addr)
{
	__be32 addr_fold = addr->ip;

#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		addr_fold = addr->ip6[0] ^ addr->ip6[1] ^
		    addr->ip6[2] ^ addr->ip6[3];
#endif

	return (proto ^ ntohl(addr_fold)) & IP_VS_SVC_TAB_MASK;
}

/*
 *	Returns hash value of fwmark for virtual service lookup
 */
static __inline__ unsigned ip_vs_svc_fwm_hashkey(__u32 fwmark)
{
	return fwmark & IP_VS_SVC_TAB_MASK;
}

static int ip_vs_svc_hash_cpuid(struct ip_vs_service *svc, int cpu)
{
	unsigned hash;
	struct list_head *ip_vs_svc_tab;

	if (svc->flags & IP_VS_SVC_F_HASHED) {
		pr_err("%s(): request for already hashed, called from %pF\n",
		       __func__, __builtin_return_address(0));
		return 0;
	}

	if (svc->fwmark == 0) {
		/*
		 *  Hash it by <protocol,addr,port> in ip_vs_svc_table
		 */
		hash = ip_vs_svc_hashkey(svc->af, svc->protocol, &svc->addr);
		ip_vs_svc_tab = per_cpu(ip_vs_svc_tab_percpu, cpu);
		list_add(&svc->s_list, ip_vs_svc_tab + hash);
	} else {
		/*
		 *  Hash it by fwmark in ip_vs_svc_fwm_table
		 */
		hash = ip_vs_svc_fwm_hashkey(svc->fwmark);
		ip_vs_svc_tab = per_cpu(ip_vs_svc_fwm_tab_percpu, cpu);
		list_add(&svc->f_list, ip_vs_svc_tab + hash);
	}

	svc->flags |= IP_VS_SVC_F_HASHED;
	/* increase its refcnt because it is referenced by the svc table */
	atomic_inc(&svc->refcnt);
	return 1;
}

/*
 *	Unhashes a service from ip_vs_svc_table/ip_vs_svc_fwm_table.
 *	Should be called with locked tables.
 */
static int ip_vs_svc_unhash(struct ip_vs_service *svc)
{
	if (!(svc->flags & IP_VS_SVC_F_HASHED)) {
		pr_err("%s(): request for unhash flagged, called from %pF\n",
		       __func__, __builtin_return_address(0));
		return 0;
	}

	if (svc->fwmark == 0) {
		/* Remove it from the ip_vs_svc_table table */
		list_del(&svc->s_list);
	} else {
		/* Remove it from the ip_vs_svc_fwm_table table */
		list_del(&svc->f_list);
	}

	svc->flags &= ~IP_VS_SVC_F_HASHED;
	atomic_dec(&svc->refcnt);
	return 1;
}

/*
 *	Get service by {proto,addr,port} in the service table.
 */
static inline struct ip_vs_service *__ip_vs_service_get(int af, __u16 protocol,
							const union nf_inet_addr
							*vaddr, __be16 vport)
{
	unsigned hash;
	struct ip_vs_service *svc;
	struct list_head *ip_vs_svc_tab;

	ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_tab_percpu);
	/* Check for "full" addressed entries */
	hash = ip_vs_svc_hashkey(af, protocol, vaddr);

	list_for_each_entry(svc, ip_vs_svc_tab + hash, s_list) {
		if ((svc->af == af)
		    && ip_vs_addr_equal(af, &svc->addr, vaddr)
		    && (svc->port == vport)
		    && (svc->protocol == protocol)) {
			/* HIT */
			//atomic_inc(&svc->usecnt);
			return svc;
		}
	}

	return NULL;
}

/*
 *	Get service by {fwmark} in the service table.
 */
static inline struct ip_vs_service *__ip_vs_svc_fwm_get(int af, __u32 fwmark)
{
	unsigned hash;
	struct ip_vs_service *svc;
	struct list_head *ip_vs_svc_fwm_tab;

	ip_vs_svc_fwm_tab = __get_cpu_var(ip_vs_svc_fwm_tab_percpu);
	/* Check for fwmark addressed entries */
	hash = ip_vs_svc_fwm_hashkey(fwmark);

	list_for_each_entry(svc, ip_vs_svc_fwm_tab + hash, f_list) {
		if (svc->fwmark == fwmark && svc->af == af) {
			/* HIT */
			return svc;
		}
	}

	return NULL;
}

struct ip_vs_service *ip_vs_service_get(int af, __u32 fwmark, __u16 protocol,
					const union nf_inet_addr *vaddr,
					__be16 vport)
{
	struct ip_vs_service *svc;

	spin_lock(&__get_cpu_var(ip_vs_svc_lock));

	/*
	 *      Check the table hashed by fwmark first
	 */
	if (fwmark && (svc = __ip_vs_svc_fwm_get(af, fwmark)))
		goto out;

	/*
	 *      Check the table hashed by <protocol,addr,port>
	 *      for "full" addressed entries
	 */
	svc = __ip_vs_service_get(af, protocol, vaddr, vport);

	if (svc == NULL
	    && protocol == IPPROTO_TCP && atomic_read(&ip_vs_ftpsvc_counter)
	    && (vport == FTPDATA || ntohs(vport) >= PROT_SOCK)) {
		/*
		 * Check if ftp service entry exists, the packet
		 * might belong to FTP data connections.
		 */
		svc = __ip_vs_service_get(af, protocol, vaddr, FTPPORT);
	}

	if (svc == NULL && atomic_read(&ip_vs_nullsvc_counter)) {
		/*
		 * Check if the catch-all port (port zero) exists
		 */
		svc = __ip_vs_service_get(af, protocol, vaddr, 0);
	}

      out:
	/* unlock by ip_vs_service_put */
	if (svc == NULL)
		spin_unlock(&__get_cpu_var(ip_vs_svc_lock));

	IP_VS_DBG_BUF(9, "lookup service: fwm %u %s %s:%u %s\n",
		      fwmark, ip_vs_proto_name(protocol),
		      IP_VS_DBG_ADDR(af, vaddr), ntohs(vport),
		      svc ? "hit" : "not hit");

	return svc;
}

struct ip_vs_service *ip_vs_lookup_vip(int af, __u16 protocol,
				       const union nf_inet_addr *vaddr)
{
	struct ip_vs_service *svc;
	struct list_head *ip_vs_svc_tab;
	unsigned hash;

	spin_lock(&__get_cpu_var(ip_vs_svc_lock));

	ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_tab_percpu);
	hash = ip_vs_svc_hashkey(af, protocol, vaddr);
	list_for_each_entry(svc, ip_vs_svc_tab + hash, s_list) {
		if ((svc->af == af)
		    && ip_vs_addr_equal(af, &svc->addr, vaddr)
		    && (svc->protocol == protocol)) {
			/* HIT */
			spin_unlock(&__get_cpu_var(ip_vs_svc_lock));
			return svc;
		}
	}

	spin_unlock(&__get_cpu_var(ip_vs_svc_lock));
	return NULL;
}

static inline void
__ip_vs_bind_svc(struct ip_vs_dest *dest, struct ip_vs_service *svc)
{
	atomic_inc(&svc->refcnt);
	dest->svc = svc;
}

static inline void __ip_vs_unbind_svc(struct ip_vs_dest *dest)
{
	int cpu;
	struct ip_vs_service *svc = dest->svc;
	struct ip_vs_service *this_svc;

	dest->svc = NULL;
//	if (atomic_dec_and_test(&svc->refcnt))
//		kfree(svc);

	atomic_dec(&svc->refcnt);

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		if (atomic_read(&this_svc->refcnt)) {
			IP_VS_DBG_BUF(2, "%s(): cpu%d refers to svc %s:%d,"
					"refcnt=%d\n", __func__, cpu,
					IP_VS_DBG_ADDR(svc->af, &svc->addr),
					ntohs(svc->port),
					atomic_read(&this_svc->refcnt));
			break;
                }
	}

	if (cpu == num_possible_cpus())
		kfree(svc->svc0);
}

/*
 *	Lookup destination by {addr,port} in the given service
 */
static struct ip_vs_dest *ip_vs_lookup_dest(struct ip_vs_service *svc,
					    const union nf_inet_addr *daddr,
					    __be16 dport)
{
	struct ip_vs_dest *dest;

	/*
	 * Find the destination for the given service
	 */
	list_for_each_entry(dest, &svc->destinations, n_list) {
		if ((dest->af == svc->af)
		    && ip_vs_addr_equal(svc->af, &dest->addr, daddr)
		    && (dest->port == dport)) {
			/* HIT */
			return dest;
		}
	}

	return NULL;
}

/*
 * Find destination by {daddr,dport,vaddr,protocol}
 * Cretaed to be used in ip_vs_process_message() in
 * the backup synchronization daemon. It finds the
 * destination to be bound to the received connection
 * on the backup.
 *
 * ip_vs_lookup_real_service() looked promissing, but
 * seems not working as expected.
 */
struct ip_vs_dest *ip_vs_find_dest(int af, const union nf_inet_addr *daddr,
				   __be16 dport,
				   const union nf_inet_addr *vaddr,
				   __be16 vport, __u16 protocol)
{
	struct ip_vs_dest *dest;
	struct ip_vs_service *svc;

	svc = ip_vs_service_get(af, 0, protocol, vaddr, vport);
	if (!svc)
		return NULL;
	dest = ip_vs_lookup_dest(svc, daddr, dport);
	if (dest)
		atomic_inc(&dest->refcnt);
	ip_vs_service_put(svc);
	return dest;
}

/*
 *  Lookup dest by {svc,addr,port} in the destination trash.
 *  The destination trash is used to hold the destinations that are removed
 *  from the service table but are still referenced by some conn entries.
 *  The reason to add the destination trash is when the dest is temporary
 *  down (either by administrator or by monitor program), the dest can be
 *  picked back from the trash, the remaining connections to the dest can
 *  continue, and the counting information of the dest is also useful for
 *  scheduling.
 */
static struct ip_vs_dest *ip_vs_trash_get_dest_cpuid(struct ip_vs_service *svc,
					       const union nf_inet_addr *daddr,
					       __be16 dport, int cpu)
{
	struct ip_vs_dest *dest, *nxt;

	/*
	 * Find the destination in trash
	 */
	list_for_each_entry_safe(dest, nxt,
			&per_cpu(ip_vs_dest_trash_percpu, cpu), n_list) {
		IP_VS_DBG_BUF(3, "Destination %u/%s:%u still in trash-%d, "
			      "dest->refcnt=%d\n",
			      dest->vfwmark,
			      IP_VS_DBG_ADDR(svc->af, &dest->addr),
			      ntohs(dest->port),
				cpu, atomic_read(&dest->refcnt));
		if (dest->af == svc->af &&
		    ip_vs_addr_equal(svc->af, &dest->addr, daddr) &&
		    dest->port == dport &&
		    dest->vfwmark == svc->fwmark &&
		    dest->protocol == svc->protocol &&
		    (svc->fwmark ||
		     (ip_vs_addr_equal(svc->af, &dest->vaddr, &svc->addr) &&
		      dest->vport == svc->port))) {
			/* HIT */
			return dest;
		}

		/*
		 * Try to purge the destination from trash if not referenced
		 */
		if (atomic_read(&dest->refcnt) == 1) {
			IP_VS_DBG_BUF(3, "Removing destination %u/%s:%u "
				      "from trash-%d\n",
				      dest->vfwmark,
				      IP_VS_DBG_ADDR(svc->af, &dest->addr),
				      ntohs(dest->port), cpu);
			list_del(&dest->n_list);
			ip_vs_dst_reset(dest);
			__ip_vs_unbind_svc(dest);
			kfree(dest);
		}
	}

	return NULL;
}

/*
 *  Clean up all the destinations in the trash
 *  Called by the ip_vs_control_cleanup()
 *
 *  When the ip_vs_control_clearup is activated by ipvs module exit,
 *  the service tables must have been flushed and all the connections
 *  are expired, and the refcnt of each destination in the trash must
 *  be 1, so we simply release them here.
 */
static void ip_vs_trash_cleanup(void)
{
	int cpu;
	struct ip_vs_dest *dest, *nxt;

	for_each_possible_cpu(cpu) {
		list_for_each_entry_safe(dest, nxt,
				&per_cpu(ip_vs_dest_trash_percpu, cpu),
				n_list) {
			list_del(&dest->n_list);
			ip_vs_dst_reset(dest);
			__ip_vs_unbind_svc(dest);
			kfree(dest);
		}
	}
}

/*
 *	Update a destination in the given service
 */
static void
__ip_vs_update_dest(struct ip_vs_service *svc,
		    struct ip_vs_dest *dest, struct ip_vs_dest_user_kern *udest)
{
	int conn_flags;

	/* set the weight and the flags */
	atomic_set(&dest->weight, udest->weight);
	conn_flags = udest->conn_flags | IP_VS_CONN_F_INACTIVE;

	/* check if local node and update the flags */
#ifdef CONFIG_IP_VS_IPV6
	if (svc->af == AF_INET6) {
		if (__ip_vs_addr_is_local_v6(&udest->addr.in6)) {
			conn_flags = (conn_flags & ~IP_VS_CONN_F_FWD_MASK)
			    | IP_VS_CONN_F_LOCALNODE;
		}
	} else
#endif
	if (inet_addr_type(&init_net, udest->addr.ip) == RTN_LOCAL) {
		conn_flags = (conn_flags & ~IP_VS_CONN_F_FWD_MASK)
		    | IP_VS_CONN_F_LOCALNODE;
	}

	/* set the IP_VS_CONN_F_NOOUTPUT flag if not masquerading/NAT */
	if ((conn_flags & IP_VS_CONN_F_FWD_MASK) != 0) {
		conn_flags |= IP_VS_CONN_F_NOOUTPUT;
	}
	atomic_set(&dest->conn_flags, conn_flags);

	/* bind the service */
	if (!dest->svc) {
		__ip_vs_bind_svc(dest, svc);
	} else {
		if (dest->svc != svc) {
			__ip_vs_unbind_svc(dest);
			memset(&dest->stats, 0, sizeof(struct ip_vs_stats));
			__ip_vs_bind_svc(dest, svc);
		}
	}

	/* set the dest status flags */
	dest->flags |= IP_VS_DEST_F_AVAILABLE;

	if (udest->u_threshold == 0 || udest->u_threshold > dest->u_threshold)
		dest->flags &= ~IP_VS_DEST_F_OVERLOAD;
	dest->u_threshold = udest->u_threshold;
	dest->l_threshold = udest->l_threshold;
}

/*
 *	Create a destination for the given service
 */
static int
ip_vs_new_dest(struct ip_vs_service *svc, struct ip_vs_dest_user_kern *udest,
	       struct ip_vs_dest **dest_p)
{
	struct ip_vs_dest *dest;
	unsigned atype;

	EnterFunction(2);

#ifdef CONFIG_IP_VS_IPV6
	if (svc->af == AF_INET6) {
		atype = ipv6_addr_type(&udest->addr.in6);
		if ((!(atype & IPV6_ADDR_UNICAST) ||
		     atype & IPV6_ADDR_LINKLOCAL) &&
		    !__ip_vs_addr_is_local_v6(&udest->addr.in6))
			return -EINVAL;
	} else
#endif
	{
		atype = inet_addr_type(&init_net, udest->addr.ip);
		if (atype != RTN_LOCAL && atype != RTN_UNICAST)
			return -EINVAL;
	}

	dest = kzalloc(sizeof(struct ip_vs_dest), GFP_ATOMIC);
	if (dest == NULL) {
		pr_err("%s(): no memory.\n", __func__);
		return -ENOMEM;
	}

	dest->af = svc->af;
	dest->protocol = svc->protocol;
	dest->vaddr = svc->addr;
	dest->vport = svc->port;
	dest->vfwmark = svc->fwmark;
	ip_vs_addr_copy(svc->af, &dest->addr, &udest->addr);
	dest->port = udest->port;

	atomic_set(&dest->activeconns, 0);
	atomic_set(&dest->inactconns, 0);
	atomic_set(&dest->persistconns, 0);
	atomic_set(&dest->refcnt, 0);

	INIT_LIST_HEAD(&dest->d_list);
	spin_lock_init(&dest->dst_lock);

	__ip_vs_update_dest(svc, dest, udest);

	*dest_p = dest;

	LeaveFunction(2);
	return 0;
}

static void
ip_vs_add_dest_rollback(struct ip_vs_service *,
			const union nf_inet_addr *,
			__be16, int);

/*
 *	Add a destination into an existing service
 */
static int
ip_vs_add_dest(struct ip_vs_service *svc, struct ip_vs_dest_user_kern *udest)
{
	struct ip_vs_dest *dest;
	union nf_inet_addr daddr;
	__be16 dport = udest->port;
	int ret;
	int cpu = 0;
	struct ip_vs_service *this_svc = NULL;

	EnterFunction(2);

	if (udest->weight < 0) {
		pr_err("%s(): server weight less than zero\n", __func__);
		return -ERANGE;
	}

	if (udest->l_threshold > udest->u_threshold) {
		pr_err("%s(): lower threshold is higher than upper threshold\n",
		       __func__);
		return -ERANGE;
	}

	ip_vs_addr_copy(svc->af, &daddr, &udest->addr);

	/*
	 * Check if the dest already exists in the list
	 */
	dest = ip_vs_lookup_dest(svc, &daddr, dport);

	if (dest != NULL) {
		IP_VS_DBG(1, "%s(): dest already exists\n", __func__);
		return -EEXIST;
	}


	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		/*
		 * Check if the dest already exists in the trash and
		 * is from the same service
		 */
		dest = ip_vs_trash_get_dest_cpuid(this_svc,
					&daddr, dport, cpu);

		if (dest != NULL) {
			IP_VS_DBG_BUF(3, "Get destination %s:%u from trash, "
			      "dest->refcnt=%d, service %u/%s:%u\n",
			      IP_VS_DBG_ADDR(svc->af, &daddr), ntohs(dport),
			      atomic_read(&dest->refcnt),
			      dest->vfwmark,
			      IP_VS_DBG_ADDR(svc->af, &dest->vaddr),
			      ntohs(dest->vport));

			__ip_vs_update_dest(this_svc, dest, udest);

			/*
			 * Get the destination from the trash
			 */
			list_del(&dest->n_list);

			/* Reset the statistic value */
			memset(&dest->stats, 0, sizeof(struct ip_vs_stats));

			spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

			list_add(&dest->n_list, &this_svc->destinations);
			this_svc->num_dests++;
			this_svc->weight += udest->weight;

			/* call the update_service function of its scheduler */
			if (this_svc->scheduler->update_service)
				this_svc->scheduler->update_service(this_svc);

			spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
			continue;
		}

		/*
		 * Allocate and initialize the dest structure
		 */
		ret = ip_vs_new_dest(this_svc, udest, &dest);
		if (ret) {
			ip_vs_add_dest_rollback(svc, &daddr, dport, cpu);
			return ret;
		}

		/*
		 * Add the dest entry into the list
		 */
		atomic_inc(&dest->refcnt);

		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		list_add(&dest->n_list, &this_svc->destinations);
		this_svc->num_dests++;
		this_svc->weight += udest->weight;

		/* call the update_service function of its scheduler */
		if (this_svc->scheduler->update_service)
			this_svc->scheduler->update_service(this_svc);

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		LeaveFunction(2);
	}

	return 0;
}

/*
 *	Edit a destination in the given service
 */
static int
ip_vs_edit_dest(struct ip_vs_service *svc, struct ip_vs_dest_user_kern *udest)
{
	struct ip_vs_dest *dest;
	union nf_inet_addr daddr;
	__be16 dport = udest->port;
	__u32 old_weight;
	int cpu;
	struct ip_vs_service *this_svc;

	EnterFunction(2);

	if (udest->weight < 0) {
		pr_err("%s(): server weight less than zero\n", __func__);
		return -ERANGE;
	}

	if (udest->l_threshold > udest->u_threshold) {
		pr_err("%s(): lower threshold is higher than upper threshold\n",
		       __func__);
		return -ERANGE;
	}

	ip_vs_addr_copy(svc->af, &daddr, &udest->addr);

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		/*
		 *  Lookup the destination list
		 */
		dest = ip_vs_lookup_dest(this_svc, &daddr, dport);

		if (dest == NULL) {
			IP_VS_DBG(1, "%s(): dest doesn't exist\n", __func__);
			return -ENOENT;
		}

		/* save old weight */
		old_weight = atomic_read(&dest->weight);

		__ip_vs_update_dest(this_svc, dest, udest);

		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		 /* update service weight */
		this_svc->weight = this_svc->weight -
				old_weight + udest->weight;
		if(this_svc->weight < 0) {
			struct ip_vs_dest *tdest;
			this_svc->weight = 0;
			list_for_each_entry(tdest, &this_svc->destinations, n_list) {
				this_svc->weight += atomic_read(&tdest->weight);
			}
			IP_VS_ERR_RL("ip_vs_edit_dest:vs weight < 0\n");
		}

		/* update service, because server weight may be changed */
		if (this_svc->scheduler->update_service)
			this_svc->scheduler->update_service(this_svc);

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
	}
	LeaveFunction(2);

	return 0;
}

/*
 *	Delete a destination (must be already unlinked from the service)
 */
static void __ip_vs_del_dest(struct ip_vs_dest *dest)
{
	/*
	 *  Decrease the refcnt of the dest, and free the dest
	 *  if nobody refers to it (refcnt=0). Otherwise, throw
	 *  the destination into the trash.
	 */
	if (atomic_dec_and_test(&dest->refcnt)) {
		ip_vs_dst_reset(dest);
		/* simply decrease svc->refcnt here, let the caller check
		   and release the service if nobody refers to it.
		   Only user context can release destination and service,
		   and only one user context can update virtual service at a
		   time, so the operation here is OK */
		atomic_dec(&dest->svc->refcnt);

		kfree(dest);
	} else {
		IP_VS_DBG_BUF(3, "Moving dest %s:%u into trash, "
			      "dest->refcnt=%d\n",
			      IP_VS_DBG_ADDR(dest->af, &dest->addr),
			      ntohs(dest->port), atomic_read(&dest->refcnt));
		list_add(&dest->n_list, &per_cpu(ip_vs_dest_trash_percpu,
				(dest->svc - dest->svc->svc0)));
		atomic_inc(&dest->refcnt);
	}
}

/*
 *	Unlink a destination from the given service
 */
static void __ip_vs_unlink_dest(struct ip_vs_service *svc,
				struct ip_vs_dest *dest, int svcupd)
{
	dest->flags &= ~IP_VS_DEST_F_AVAILABLE;

	/*
	 *  Remove it from the d-linked destination list.
	 */
	list_del(&dest->n_list);
	svc->num_dests--;
	svc->weight -= atomic_read(&dest->weight);
	if(svc->weight < 0) {
		struct ip_vs_dest *tdest;
                svc->weight = 0;
		list_for_each_entry(tdest, &svc->destinations, n_list) {
			svc->weight += atomic_read(&tdest->weight);
		}
                IP_VS_ERR_RL("__ip_vs_unlink_dest:vs weight < 0\n");
	}

	/*
	 *  Call the update_service function of its scheduler
	 */
	if (svcupd && svc->scheduler->update_service)
		svc->scheduler->update_service(svc);
}

static void
ip_vs_add_dest_rollback(struct ip_vs_service *svc,
			const union nf_inet_addr *daddr,
			__be16 dport, int cpu)
{
	int i;
	struct ip_vs_dest *dest;
	struct ip_vs_service *this_svc;

	for(i = 0; i < cpu; i++)
	{
		this_svc = svc->svc0 + i;
		dest = ip_vs_lookup_dest(this_svc, daddr, dport);
		if(dest == NULL)
			continue;

		spin_lock_bh(&per_cpu(ip_vs_svc_lock, i));
		__ip_vs_unlink_dest(this_svc, dest, 1);
		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, i));

		__ip_vs_del_dest(dest);
	}
}

/*
 *	Delete a destination server in the given service
 */
static int
ip_vs_del_dest(struct ip_vs_service *svc, struct ip_vs_dest_user_kern *udest)
{
	struct ip_vs_dest *dest;
	__be16 dport = udest->port;
	int cpu;
	struct ip_vs_service *this_svc;

	EnterFunction(2);

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		dest = ip_vs_lookup_dest(this_svc, &udest->addr, dport);

		if (dest == NULL) {
			IP_VS_DBG(1, "%s(): destination not found!\n",
							__func__);
			return -ENOENT;
		}

		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		/*
		 *      Unlink dest from the service
		 */
		__ip_vs_unlink_dest(this_svc, dest, 1);

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		/*
		 *      Delete the destination
		 */
		__ip_vs_del_dest(dest);
	}

	LeaveFunction(2);

	return 0;
}

#define LADDR_MASK 0x000000ff
static inline int laddr_to_cpuid(int af, const union nf_inet_addr *addr)
{
	u32 seed;

	if(af == AF_INET6)
		seed = ntohl(addr->in6.s6_addr32[3]) & LADDR_MASK;
	else
		seed = ntohl(addr->ip) & LADDR_MASK;

	return seed % (num_online_cpus() - sysctl_ip_vs_reserve_core) +
					sysctl_ip_vs_reserve_core;
}

struct laddr_cpu_t
{
	struct hlist_node hlist;
	struct rcu_head  rcu_head;
	int cpuid;
	int refcnt;
	__be32 addr;
};

#define LADDR_CPU_HASH_SIZE LADDR_MASK + 1
static struct hlist_head laddr_cpu_map[LADDR_CPU_HASH_SIZE];
static DEFINE_SPINLOCK(laddr_cpu_map_lock);

static struct laddr_cpu_t *lookup_laddr_cpu(__be32 addr)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct laddr_cpu_t *p;

	head = &laddr_cpu_map[ntohl(addr) & LADDR_MASK];
	hlist_for_each_entry_rcu(p, node, head, hlist) {
		if (p->addr == addr)
			return p;
	}

	return NULL;
}

void ip_vs_laddr_hold(struct ip_vs_laddr *laddr)
{
	atomic_inc(&laddr->refcnt);
}

static void rcu_free_laddr_cpu(struct rcu_head *head)
{
	struct laddr_cpu_t *laddr_cpu = container_of(head, struct laddr_cpu_t, rcu_head);
#ifdef CONFIG_IP_VS_DEBUG
	IP_VS_DBG(0, "%s,%pI4,cpu %d,refcnt %d\n", __func__, &laddr_cpu->addr, laddr_cpu->cpuid, laddr_cpu->refcnt);
#endif
	kfree(laddr_cpu);
}

void ip_vs_laddr_put(struct ip_vs_laddr *laddr)
{
	if (atomic_dec_and_test(&laddr->refcnt)) {
		struct laddr_cpu_t *laddr_cpu;

		spin_lock(&laddr_cpu_map_lock);
		laddr_cpu = lookup_laddr_cpu(laddr->addr.ip);
		if (laddr_cpu) {
			if ((--laddr_cpu->refcnt) <= 0) {
				hlist_del_rcu(&laddr_cpu->hlist);
				call_rcu(&laddr_cpu->rcu_head, rcu_free_laddr_cpu);
			}
#ifdef CONFIG_IP_VS_DEBUG
			IP_VS_DBG(0, "%s,%pI4,cpu %d,refcnt %d\n", __func__, &laddr_cpu->addr, laddr_cpu->cpuid, laddr_cpu->refcnt);
#endif
		}
		spin_unlock(&laddr_cpu_map_lock);

		kfree(laddr);
	}
}

static int
ip_vs_new_laddr(struct ip_vs_service *svc, struct ip_vs_laddr_user_kern *uladdr,
		struct ip_vs_laddr **laddr_p)
{
	struct ip_vs_laddr *laddr;

	laddr = kzalloc(sizeof(struct ip_vs_laddr), GFP_ATOMIC);
	if (!laddr) {
		pr_err("%s(): no memory.\n", __func__);
		return -ENOMEM;
	}

	laddr->af = svc->af;
	ip_vs_addr_copy(svc->af, &laddr->addr, &uladdr->addr);
	atomic64_set(&laddr->port_conflict, 0);
	atomic64_set(&laddr->port, 0);
	atomic_set(&laddr->refcnt, 0);
	atomic_set(&laddr->conn_counts, 0);
	laddr->cpuid = laddr_to_cpuid(svc->af, &uladdr->addr);
	IP_VS_DBG_BUF(0, "local address %s is assigned to cpu%d\n",
			IP_VS_DBG_ADDR(svc->af, &uladdr->addr), laddr->cpuid);

	*laddr_p = laddr;

	return 0;
}

static struct ip_vs_laddr *ip_vs_lookup_laddr(struct ip_vs_service *svc,
					      const union nf_inet_addr *addr)
{
	int cpu;
	struct ip_vs_service *this_svc;
	struct ip_vs_laddr *laddr;

	this_svc = svc->svc0;
	for_each_possible_cpu(cpu) {
		/*
		 * Find the local address for the given service
		 */
		list_for_each_entry(laddr, &this_svc->laddr_list, n_list) {
			if ((laddr->af == svc->af)
			    && ip_vs_addr_equal(svc->af, &laddr->addr, addr)) {
				/* HIT */
				return laddr;
			}
		}
		this_svc++;
	}

	return NULL;
}

static int
ip_vs_add_laddr(struct ip_vs_service *svc, struct ip_vs_laddr_user_kern *uladdr)
{
	struct ip_vs_laddr *laddr;
	struct ip_vs_service *this_svc;
	int cpu;
	int ret;
	struct laddr_cpu_t *laddr_cpu;

	IP_VS_DBG_BUF(0, "vip %s:%d add local address %s\n",
		      IP_VS_DBG_ADDR(svc->af, &svc->addr), ntohs(svc->port),
		      IP_VS_DBG_ADDR(svc->af, &uladdr->addr));

	/*
	 * Check if the local address already exists in the list
	 */
	laddr = ip_vs_lookup_laddr(svc, &uladdr->addr);
	if (laddr) {
		IP_VS_DBG(1, "%s(): local address already exists\n", __func__);
		return -EEXIST;
	}

	/*
	 * Allocate and initialize the dest structure
	 */
	ret = ip_vs_new_laddr(svc, uladdr, &laddr);
	if (ret) {
		return ret;
	}

	spin_lock(&laddr_cpu_map_lock);
	laddr_cpu = lookup_laddr_cpu(laddr->addr.ip);
	if (laddr_cpu) {
		++(laddr_cpu->refcnt);
	}
	spin_unlock(&laddr_cpu_map_lock);

	if (!laddr_cpu) {
		laddr_cpu = kzalloc(sizeof(struct laddr_cpu_t), GFP_ATOMIC);
		if (!laddr_cpu) {
			kfree(laddr);
			pr_err("%s():no memory.\n", __func__);
			return -ENOMEM;
		}

		laddr_cpu->cpuid = laddr->cpuid;
		laddr_cpu->addr = laddr->addr.ip;
		laddr_cpu->refcnt = 1;
		
		spin_lock(&laddr_cpu_map_lock);
		hlist_add_head_rcu(&laddr_cpu->hlist, &laddr_cpu_map[ntohl(laddr_cpu->addr) & LADDR_MASK]);
		spin_unlock(&laddr_cpu_map_lock);
	}

	/*
	 * Add the local adress entry into the list
	 */
	ip_vs_laddr_hold(laddr);

	cpu = laddr->cpuid;
	this_svc = svc->svc0 + cpu;

	spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

	list_add_tail(&laddr->n_list, &this_svc->laddr_list);
	this_svc->num_laddrs++;

#ifdef CONFIG_IP_VS_DEBUG
	/* Dump the destinations */
	IP_VS_DBG_BUF(0, "	cpu%d svc %s:%d num %d curr %p \n",
			cpu, IP_VS_DBG_ADDR(svc->af, &svc->addr),
			ntohs(this_svc->port), this_svc->num_laddrs,
			this_svc->curr_laddr);
	list_for_each_entry(laddr, &this_svc->laddr_list, n_list) {
		IP_VS_DBG_BUF(0, "		laddr %p %s:%d \n",
			      laddr, IP_VS_DBG_ADDR(svc->af, &laddr->addr), 0);
	}
#endif

	spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

	return 0;
}

static int
ip_vs_del_laddr(struct ip_vs_service *svc, struct ip_vs_laddr_user_kern *uladdr)
{
	struct ip_vs_laddr *laddr;
	struct ip_vs_service *this_svc;
	int cpu;

	IP_VS_DBG_BUF(0, "vip %s:%d del local address %s\n",
		      IP_VS_DBG_ADDR(svc->af, &svc->addr), ntohs(svc->port),
		      IP_VS_DBG_ADDR(svc->af, &uladdr->addr));

	laddr = ip_vs_lookup_laddr(svc, &uladdr->addr);

	if (laddr == NULL) {
		IP_VS_DBG(1, "%s(): local address not found!\n", __func__);
		return -ENOENT;
	}

	cpu = laddr->cpuid;
	this_svc = svc->svc0 + cpu;

	spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

	/* update svc->curr_laddr */
	if (this_svc->curr_laddr == &laddr->n_list)
		this_svc->curr_laddr = laddr->n_list.next;
	/*
	 *      Unlink dest from the service
	 */
	list_del(&laddr->n_list);
	this_svc->num_laddrs--;

#ifdef CONFIG_IP_VS_DEBUG
	IP_VS_DBG_BUF(0, "	cpu%d svc %s:%d num %d curr %p \n",
			cpu, IP_VS_DBG_ADDR(svc->af, &svc->addr),
			ntohs(svc->port), this_svc->num_laddrs,
			this_svc->curr_laddr);
	list_for_each_entry(laddr, &this_svc->laddr_list, n_list) {
		IP_VS_DBG_BUF(0, "		laddr %p %s:%d \n",
			      laddr, IP_VS_DBG_ADDR(svc->af, &laddr->addr), 0);
	}
#endif

	ip_vs_laddr_put(laddr);

	spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

	return 0;
}

/*
 *	Add a service into the service hash table
 */
static int
ip_vs_add_service(struct ip_vs_service_user_kern *u,
		  struct ip_vs_service **svc_p)
{
	int ret = 0, cpu = 0;
	struct ip_vs_scheduler *sched = NULL;
	struct ip_vs_service *svc = NULL;
	struct ip_vs_service *this_svc = NULL;

	/* increase the module use count */
	ip_vs_use_count_inc();

	/* Lookup the scheduler by 'u->sched_name' */
	sched = ip_vs_scheduler_get(u->sched_name);
	if (sched == NULL) {
		pr_info("Scheduler module ip_vs_%s not found\n", u->sched_name);
		ret = -ENOENT;
		goto out_mod_dec;
	}
#ifdef CONFIG_IP_VS_IPV6
	if (u->af == AF_INET6 && (u->netmask < 1 || u->netmask > 128)) {
		ret = -EINVAL;
		goto out_sched;
	}
#endif

	svc = kzalloc(sizeof(struct ip_vs_service) * num_possible_cpus(),
							GFP_ATOMIC);
	if (svc == NULL) {
		IP_VS_DBG(1, "%s(): no memory\n", __func__);
		ret = -ENOMEM;
		goto out_sched;
	}

	for_each_possible_cpu(cpu) {
		this_svc = svc + cpu;
		atomic_set(&this_svc->refcnt, 0);

		this_svc->af = u->af;
		this_svc->protocol = u->protocol;
		ip_vs_addr_copy(u->af, &this_svc->addr, &u->addr);
		this_svc->port = u->port;
		this_svc->fwmark = u->fwmark;
		this_svc->flags = u->flags;
		this_svc->timeout = u->timeout * HZ;
		this_svc->netmask = u->netmask;
		this_svc->est_timeout = u->est_timeout * HZ;

		/* Init the local address stuff */
		rwlock_init(&this_svc->laddr_lock);
		INIT_LIST_HEAD(&this_svc->laddr_list);
		this_svc->num_laddrs = 0;
		this_svc->curr_laddr = &this_svc->laddr_list;

		INIT_LIST_HEAD(&this_svc->destinations);
		rwlock_init(&this_svc->sched_lock);

		/* Bind the scheduler */
		ret = ip_vs_bind_scheduler(this_svc, sched);
		if (ret)
			goto out_err;

		/* Hash the service into the service table */
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));
		ip_vs_svc_hash_cpuid(this_svc, cpu);
		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		this_svc->svc0 = svc;	/* save the first svc */
	}

	sched = NULL;
	/* Update the virtual service counters */
	if (svc->port == FTPPORT)
		atomic_inc(&ip_vs_ftpsvc_counter);
	else if (svc->port == 0)
		atomic_inc(&ip_vs_nullsvc_counter);

	/* Count only IPv4 services for old get/setsockopt interface */
	if (svc->af == AF_INET)
		ip_vs_num_services++;

	/* svc is percpu, NULL is OK */
	*svc_p = NULL;
	return 0;

out_err:
	for_each_possible_cpu(cpu) {
		this_svc = svc + cpu;
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));
		ip_vs_svc_unhash(this_svc);
		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
		if (this_svc->scheduler)
			ip_vs_unbind_scheduler(this_svc);
		if (this_svc->inc) {
			local_bh_disable();
			ip_vs_app_inc_put(this_svc->inc);
			local_bh_enable();
		}
	}
	kfree(svc);
out_sched:
	ip_vs_scheduler_put(sched);
out_mod_dec:
	/* decrease the module use count */
	ip_vs_use_count_dec();

	return ret;
}

/*
 *	Edit a service and bind it with a new scheduler
 */
static int
ip_vs_edit_service(struct ip_vs_service *svc, struct ip_vs_service_user_kern *u)
{
	struct ip_vs_scheduler *sched, *old_sched;
	struct ip_vs_service *this_svc;
	int ret = 0;
	int cpu = 0;

	/*
	 * Lookup the scheduler, by 'u->sched_name'
	 */
	sched = ip_vs_scheduler_get(u->sched_name);
	if (sched == NULL) {
		pr_info("Scheduler module ip_vs_%s not found\n", u->sched_name);
		return -ENOENT;
	}
	old_sched = sched;

#ifdef CONFIG_IP_VS_IPV6
	if (u->af == AF_INET6 && (u->netmask < 1 || u->netmask > 128)) {
		ret = -EINVAL;
		goto out;
	}
#endif

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));
		/*
		 * Set the flags and timeout value
		 */
		this_svc->flags = u->flags | IP_VS_SVC_F_HASHED;
		this_svc->timeout = u->timeout * HZ;
		this_svc->netmask = u->netmask;
		this_svc->est_timeout = u->est_timeout * HZ;

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
	}

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		old_sched = this_svc->scheduler;
		if (sched != old_sched) {
			/*
			 * Unbind the old scheduler
			 */
			if ((ret = ip_vs_unbind_scheduler(this_svc))) {
				old_sched = sched;
				spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
				goto out_sched;
			}

			/*
			 * Bind the new scheduler
			 */
			if ((ret = ip_vs_bind_scheduler(this_svc, sched))) {
				/*
				 * If ip_vs_bind_scheduler fails, restore
				 * the old scheduler.
				 * The main reason of failure is out of memory.
				 *
				 * The question is if the old scheduler can be
				 * restored all the time. TODO: if it cannot be
				 * restored some time, we must delete the
				 * service, otherwise the system may crash.
				 */
				ip_vs_bind_scheduler(this_svc, old_sched);
				old_sched = sched;
				spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
				goto out_sched;
			}
		}
		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
	}

out_sched:
	/* todo: rollback scheduler if error */

#ifdef CONFIG_IP_VS_IPV6
      out:
#endif

	if (old_sched)
		ip_vs_scheduler_put(old_sched);

	return ret;
}

/*
 *	Delete a service from the service list
 *	- The service must be unlinked, unlocked and not referenced!
 *	- We are called under _bh lock
 */
static void __ip_vs_del_service(struct ip_vs_service *svc)
{
	struct ip_vs_dest *dest, *nxt;
	struct ip_vs_laddr *laddr, *laddr_next;
	struct ip_vs_scheduler *old_sched = NULL;
	struct ip_vs_service *this_svc;
	int cpu = 0;

	/* Count only IPv4 services for old get/setsockopt interface */
	if (svc->af == AF_INET)
		ip_vs_num_services--;

	for_each_possible_cpu(cpu) {
		this_svc = svc->svc0 + cpu;
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		/* Unbind scheduler */
		old_sched = this_svc->scheduler;
		ip_vs_unbind_scheduler(this_svc);

		/* Unbind app inc */
		if (this_svc->inc) {
			ip_vs_app_inc_put(this_svc->inc);
			this_svc->inc = NULL;
		}

		/* Unlink the whole local address list */
		list_for_each_entry_safe(laddr, laddr_next,
				&this_svc->laddr_list, n_list) {
			list_del(&laddr->n_list);
			ip_vs_laddr_put(laddr);
		}

		/*
		 *    Unlink the whole destination list
		 */
		list_for_each_entry_safe(dest, nxt,
				&this_svc->destinations, n_list) {
			__ip_vs_unlink_dest(this_svc, dest, 0);
			__ip_vs_del_dest(dest);
		}

		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));
	}

	if (old_sched)
		ip_vs_scheduler_put(old_sched);
	/*
	 *    Update the virtual service counters
	 */
	if (svc->port == FTPPORT)
		atomic_dec(&ip_vs_ftpsvc_counter);
	else if (svc->port == 0)
		atomic_dec(&ip_vs_nullsvc_counter);

	/*
	 *    Free the service if nobody refers to it
	 */
	this_svc = svc->svc0;
	for_each_possible_cpu(cpu) {
		if (atomic_read(&this_svc->refcnt)) {
			IP_VS_DBG_BUF(2, "%s(): cpu%d refers to svc %s:%d,"
					"refcnt=%d\n", __func__, cpu,
					IP_VS_DBG_ADDR(svc->af, &svc->addr),
					ntohs(svc->port),
					atomic_read(&this_svc->refcnt));
			break;
		}
		this_svc++;
	}

	if (cpu == num_possible_cpus())
		kfree(svc->svc0);

	/* decrease the module use count */
	ip_vs_use_count_dec();
}

/*
 *	Delete a service from the service list
 */
static int ip_vs_del_service(struct ip_vs_service *svc)
{
	struct ip_vs_service *this_svc;
	int cpu = 0;

	if (svc == NULL)
		return -EEXIST;

	/*
	 * Unhash it from the service table
	 */
	this_svc = svc->svc0;
	for_each_possible_cpu(cpu) {
		spin_lock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		ip_vs_svc_unhash(this_svc);
		spin_unlock_bh(&per_cpu(ip_vs_svc_lock, cpu));

		this_svc++;
	}

	__ip_vs_del_service(svc);

	return 0;
}

/*
 *	Flush all the virtual services
 */
static int ip_vs_flush(void)
{
	int idx;
	struct ip_vs_service *svc, *nxt;
	struct list_head *ip_vs_svc_tab;
	struct list_head *ip_vs_svc_fwm_tab;

	/*
	 * Flush the service table hashed by <protocol,addr,port>
	 */
	for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
		ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_tab_percpu);
		list_for_each_entry_safe(svc, nxt, ip_vs_svc_tab + idx,
					 s_list) {
			ip_vs_del_service(svc);
		}
	}

	/*
	 * Flush the service table hashed by fwmark
	 */
	for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
		ip_vs_svc_fwm_tab = __get_cpu_var(ip_vs_svc_fwm_tab_percpu);
		list_for_each_entry_safe(svc, nxt,
					 ip_vs_svc_fwm_tab + idx, f_list) {
			ip_vs_del_service(svc);
		}
	}

	return 0;
}

/*
 *	Zero counters in a service or all services
 *	disable in v3
 */
/*static int ip_vs_zero_service(struct ip_vs_service *svc)
{
	struct ip_vs_dest *dest;

	write_lock_bh(&__ip_vs_svc_lock);
	list_for_each_entry(dest, &svc->destinations, n_list) {
		ip_vs_zero_stats(dest->stats);
	}
	ip_vs_zero_stats(svc->stats);
	write_unlock_bh(&__ip_vs_svc_lock);
	return 0;
}

static int ip_vs_zero_all(void)
{
	int idx;
	struct ip_vs_service *svc;

	for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
		list_for_each_entry(svc, &ip_vs_svc_table[idx], s_list) {
			ip_vs_zero_service(svc);
		}
	}

	for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
		list_for_each_entry(svc, &ip_vs_svc_fwm_table[idx], f_list) {
			ip_vs_zero_service(svc);
		}
	}

	ip_vs_zero_stats(ip_vs_stats);
	return 0;
}*/

static int
proc_do_defense_mode(ctl_table * table, int write,
		     void __user * buffer, size_t * lenp, loff_t * ppos)
{
	int *valp = table->data;
	int val = *valp;
	int rc;

	rc = proc_dointvec(table, write, buffer, lenp, ppos);
	if (write && (*valp != val)) {
		if ((*valp < 0) || (*valp > 3)) {
			/* Restore the correct value */
			*valp = val;
		} else {
			update_defense_level();
		}
	}
	return rc;
}

static int
proc_do_sync_threshold(ctl_table * table, int write,
		       void __user * buffer, size_t * lenp, loff_t * ppos)
{
	int *valp = table->data;
	int val[2];
	int rc;

	/* backup the value first */
	memcpy(val, valp, sizeof(val));

	rc = proc_dointvec(table, write, buffer, lenp, ppos);
	if (write && (valp[0] < 0 || valp[1] < 0 || valp[0] >= valp[1])) {
		/* Restore the correct value */
		memcpy(valp, val, sizeof(val));
	}
	return rc;
}

/*
 *	IPVS sysctl table (under the /proc/sys/net/ipv4/vs/)
 */

static struct ctl_table vs_vars[] = {
	{
	 .procname = "amemthresh",
	 .data = &sysctl_ip_vs_amemthresh,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec,
	 },
#ifdef CONFIG_IP_VS_DEBUG
	{
	 .procname = "debug_level",
	 .data = &sysctl_ip_vs_debug_level,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec,
	 },
#endif
	{
	 .procname = "am_droprate",
	 .data = &sysctl_ip_vs_am_droprate,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec,
	 },
	{
	 .procname = "drop_entry",
	 .data = &sysctl_ip_vs_drop_entry,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_do_defense_mode,
	 },
	{
	 .procname = "drop_packet",
	 .data = &sysctl_ip_vs_drop_packet,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_do_defense_mode,
	 },
	{
	 .procname = "secure_tcp",
	 .data = &sysctl_ip_vs_secure_tcp,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_do_defense_mode,
	 },
	{
	 .procname = "timeout_established",
	 .data = &sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_ESTABLISHED],
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname = "timeout_synsent",
	 .data = &sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_SYN_SENT],
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname = "timeout_synrecv",
	 .data = &sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_SYN_RECV],
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname = "timeout_finwait",
	 .data = &sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_FIN_WAIT],
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname = "timeout_timewait",
	 .data = &sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_TIME_WAIT],
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname = "timeout_close",
	 .data = &sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_CLOSE],
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname = "timeout_closewait",
	 .data = &sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_CLOSE_WAIT],
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname = "timeout_lastack",
	 .data = &sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_LAST_ACK],
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname = "timeout_listen",
	 .data = &sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_LISTEN],
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname = "timeout_synack",
	 .data = &sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_SYNACK],
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname = "cache_bypass",
	 .data = &sysctl_ip_vs_cache_bypass,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec,
	 },
	{
	 .procname = "expire_nodest_conn",
	 .data = &sysctl_ip_vs_expire_nodest_conn,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec,
	 },
	{
	 .procname = "expire_quiescent_template",
	 .data = &sysctl_ip_vs_expire_quiescent_template,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec,
	 },
	{
	 .procname = "sync_threshold",
	 .data = &sysctl_ip_vs_sync_threshold,
	 .maxlen = sizeof(sysctl_ip_vs_sync_threshold),
	 .mode = 0644,
	 .proc_handler = proc_do_sync_threshold,
	 }
	,
	{
	 .procname = "nat_icmp_send",
	 .data = &sysctl_ip_vs_nat_icmp_send,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec,
	 },
	{
	 .procname = "fullnat_timestamp_remove_entry",
	 .data = &sysctl_ip_vs_timestamp_remove_entry,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,
	 .extra2 = &ip_vs_entry_max,
	 },
	{
	 .procname = "fullnat_mss_adjust_entry",
	 .data = &sysctl_ip_vs_mss_adjust_entry,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,
	 .extra2 = &ip_vs_entry_max,
	 },
	{
	 .procname = "fullnat_conn_reused_entry",
	 .data = &sysctl_ip_vs_conn_reused_entry,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,
	 .extra2 = &ip_vs_entry_max,
	 },
	{
	 .procname = "fullnat_toa_entry",
	 .data = &sysctl_ip_vs_toa_entry,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,
	 .extra2 = &ip_vs_entry_max,
	 },
	{
	 .procname = "fullnat_lport_max",
	 .data = &sysctl_ip_vs_lport_max,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_port_min,
	 .extra2 = &ip_vs_port_max,
	 },
	{
	 .procname = "fullnat_lport_min",
	 .data = &sysctl_ip_vs_lport_min,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_port_min,
	 .extra2 = &ip_vs_port_max,
	 },
	{
	 .procname = "fullnat_lport_tries",
	 .data = &sysctl_ip_vs_lport_tries,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_port_try_min,
	 .extra2 = &ip_vs_port_try_max,
	 },
	/* syn-proxy sysctl variables */
	{
	 .procname = "synproxy_init_mss",
	 .data = &sysctl_ip_vs_synproxy_init_mss,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_init_mss_min,
	 .extra2 = &ip_vs_synproxy_init_mss_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_sack",
	 .data = &sysctl_ip_vs_synproxy_sack,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_switch_min,
	 .extra2 = &ip_vs_synproxy_switch_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_wscale",
	 .data = &sysctl_ip_vs_synproxy_wscale,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_wscale_min,
	 .extra2 = &ip_vs_synproxy_wscale_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_timestamp",
	 .data = &sysctl_ip_vs_synproxy_timestamp,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_switch_min,
	 .extra2 = &ip_vs_synproxy_switch_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_synack_ttl",
	 .data = &sysctl_ip_vs_synproxy_synack_ttl,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_synack_ttl_min,
	 .extra2 = &ip_vs_synproxy_synack_ttl_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_defer",
	 .data = &sysctl_ip_vs_synproxy_defer,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_switch_min,
	 .extra2 = &ip_vs_synproxy_switch_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_conn_reuse",
	 .data = &sysctl_ip_vs_synproxy_conn_reuse,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_switch_min,
	 .extra2 = &ip_vs_synproxy_switch_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_conn_reuse_close",
	 .data = &sysctl_ip_vs_synproxy_conn_reuse_cl,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_switch_min,
	 .extra2 = &ip_vs_synproxy_switch_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_conn_reuse_time_wait",
	 .data = &sysctl_ip_vs_synproxy_conn_reuse_tw,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_switch_min,
	 .extra2 = &ip_vs_synproxy_switch_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_conn_reuse_fin_wait",
	 .data = &sysctl_ip_vs_synproxy_conn_reuse_fw,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_switch_min,
	 .extra2 = &ip_vs_synproxy_switch_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_conn_reuse_close_wait",
	 .data = &sysctl_ip_vs_synproxy_conn_reuse_cw,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_switch_min,
	 .extra2 = &ip_vs_synproxy_switch_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_conn_reuse_last_ack",
	 .data = &sysctl_ip_vs_synproxy_conn_reuse_la,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_switch_min,
	 .extra2 = &ip_vs_synproxy_switch_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_ack_skb_store_thresh",
	 .data = &sysctl_ip_vs_synproxy_skb_store_thresh,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_skb_store_thresh_min,
	 .extra2 = &ip_vs_synproxy_skb_store_thresh_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_ack_storm_thresh",
	 .data = &sysctl_ip_vs_synproxy_dup_ack_thresh,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_dup_ack_cnt_min,
	 .extra2 = &ip_vs_synproxy_dup_ack_cnt_max,
	 .strategy = &sysctl_intvec,
	 },
	{
	 .procname = "synproxy_syn_retry",
	 .data = &sysctl_ip_vs_synproxy_syn_retry,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &ip_vs_synproxy_syn_retry_min,
	 .extra2 = &ip_vs_synproxy_syn_retry_max,
	 .strategy = &sysctl_intvec,
	 },
	/* attack-defence sysctl variables */
	{
	 .procname = "defence_tcp_drop",
	 .data = &sysctl_ip_vs_tcp_drop_entry,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,
	 .extra2 = &ip_vs_entry_max,
	 },
	{
	 .procname = "defence_udp_drop",
	 .data = &sysctl_ip_vs_udp_drop_entry,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,
	 .extra2 = &ip_vs_entry_max,
	 },
	{
	 .procname = "defence_frag_drop",
	 .data = &sysctl_ip_vs_frag_drop_entry,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,
	 .extra2 = &ip_vs_entry_max,
	 },
	/* send rst sysctl variables */
	{
	 .procname = "conn_expire_tcp_rst",
	 .data = &sysctl_ip_vs_conn_expire_tcp_rst,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,	/* zero */
	 .extra2 = &ip_vs_entry_max,	/* one */
	 },
	{
	 .procname = "fast_response_xmit",
	 .data = &sysctl_ip_vs_fast_xmit,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,	/* zero */
	 .extra2 = &ip_vs_entry_max,	/* one */
	 },
	{
	 .procname = "fast_response_xmit_inside",
	 .data = &sysctl_ip_vs_fast_xmit_inside,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,	/* zero */
	 .extra2 = &ip_vs_entry_max,	/* one */
	 },
	{
	 .procname = "csum_offload",
	 .data = &sysctl_ip_vs_csum_offload,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_entry_min,	/* zero */
	 .extra2 = &ip_vs_entry_max,	/* one */
	 },
	{
	 .procname = "reserve_core",
	 .data = &sysctl_ip_vs_reserve_core,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .strategy = &sysctl_intvec,
	 .extra1 = &ip_vs_reserve_core_min,	/* zero */
	 .extra2 = &ip_vs_reserve_core_max,	/* six */
	 },
	{
	 .procname = "conn_max_num",
	 .data = &sysctl_ip_vs_conn_max_num,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec,
	 },
	{.ctl_name = 0}
};

const struct ctl_path net_vs_ctl_path[] = {
	{.procname = "net",.ctl_name = CTL_NET,},
	{.procname = "ipv4",.ctl_name = NET_IPV4,},
	{.procname = "vs",},
	{}
};

EXPORT_SYMBOL_GPL(net_vs_ctl_path);

static struct ctl_table_header *sysctl_header;

/* NOT support by v3 */
#ifdef CONFIG_PROC_FS_NO_EXIST

struct ip_vs_iter {
	struct list_head *table;
	int bucket;
};

/*
 *	Write the contents of the VS rule table to a PROCfs file.
 *	(It is kept just for backward compatibility)
 */
static inline const char *ip_vs_fwd_name(unsigned flags)
{
	switch (flags & IP_VS_CONN_F_FWD_MASK) {
	case IP_VS_CONN_F_LOCALNODE:
		return "Local";
	case IP_VS_CONN_F_TUNNEL:
		return "Tunnel";
	case IP_VS_CONN_F_DROUTE:
		return "Route";
	case IP_VS_CONN_F_FULLNAT:
		return "FullNat";
	default:
		return "Masq";
	}
}

/* Get the Nth entry in the two lists */
static struct ip_vs_service *ip_vs_info_array(struct seq_file *seq, loff_t pos)
{
	struct ip_vs_iter *iter = seq->private;
	int idx;
	struct ip_vs_service *svc;

	/* look in hash by protocol */
	for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
		list_for_each_entry(svc, &ip_vs_svc_table[idx], s_list) {
			if (pos-- == 0) {
				iter->table = ip_vs_svc_table;
				iter->bucket = idx;
				return svc;
			}
		}
	}

	/* keep looking in fwmark */
	for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
		list_for_each_entry(svc, &ip_vs_svc_fwm_table[idx], f_list) {
			if (pos-- == 0) {
				iter->table = ip_vs_svc_fwm_table;
				iter->bucket = idx;
				return svc;
			}
		}
	}

	return NULL;
}

static void *ip_vs_info_seq_start(struct seq_file *seq, loff_t * pos)
__acquires(__ip_vs_svc_lock)
{

	read_lock_bh(&__ip_vs_svc_lock);
	return *pos ? ip_vs_info_array(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *ip_vs_info_seq_next(struct seq_file *seq, void *v, loff_t * pos)
{
	struct list_head *e;
	struct ip_vs_iter *iter;
	struct ip_vs_service *svc;

	++*pos;
	if (v == SEQ_START_TOKEN)
		return ip_vs_info_array(seq, 0);

	svc = v;
	iter = seq->private;

	if (iter->table == ip_vs_svc_table) {
		/* next service in table hashed by protocol */
		if ((e = svc->s_list.next) != &ip_vs_svc_table[iter->bucket])
			return list_entry(e, struct ip_vs_service, s_list);

		while (++iter->bucket < IP_VS_SVC_TAB_SIZE) {
			list_for_each_entry(svc, &ip_vs_svc_table[iter->bucket],
					    s_list) {
				return svc;
			}
		}

		iter->table = ip_vs_svc_fwm_table;
		iter->bucket = -1;
		goto scan_fwmark;
	}

	/* next service in hashed by fwmark */
	if ((e = svc->f_list.next) != &ip_vs_svc_fwm_table[iter->bucket])
		return list_entry(e, struct ip_vs_service, f_list);

      scan_fwmark:
	while (++iter->bucket < IP_VS_SVC_TAB_SIZE) {
		list_for_each_entry(svc, &ip_vs_svc_fwm_table[iter->bucket],
				    f_list)
		    return svc;
	}

	return NULL;
}

static void ip_vs_info_seq_stop(struct seq_file *seq, void *v)
__releases(__ip_vs_svc_lock)
{
	read_unlock_bh(&__ip_vs_svc_lock);
}

static int ip_vs_info_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_printf(seq,
			   "IP Virtual Server version %d.%d.%d (size=%d)\n",
			   NVERSION(IP_VS_VERSION_CODE), IP_VS_CONN_TAB_SIZE);
		seq_puts(seq, "Prot LocalAddress:Port Scheduler Flags\n");
		seq_puts(seq,
			 "  -> RemoteAddress:Port Forward Weight ActiveConn InActConn\n");
	} else {
		const struct ip_vs_service *svc = v;
		const struct ip_vs_iter *iter = seq->private;
		const struct ip_vs_dest *dest;

		if (iter->table == ip_vs_svc_table) {
#ifdef CONFIG_IP_VS_IPV6
			if (svc->af == AF_INET6)
				seq_printf(seq, "%s  [%pI6]:%04X %s%s ",
					   ip_vs_proto_name(svc->protocol),
					   &svc->addr.in6,
					   ntohs(svc->port),
					   svc->scheduler->name,
					   (svc->
					    flags & IP_VS_SVC_F_ONEPACKET) ?
					   " ops" : "");
			else
#endif
				seq_printf(seq, "%s  %08X:%04X %s%s ",
					   ip_vs_proto_name(svc->protocol),
					   ntohl(svc->addr.ip),
					   ntohs(svc->port),
					   svc->scheduler->name,
					   (svc->
					    flags & IP_VS_SVC_F_ONEPACKET) ?
					   " ops" : "");
		} else {
			seq_printf(seq, "FWM  %08X %s%s ",
				   svc->fwmark, svc->scheduler->name,
				   (svc->flags & IP_VS_SVC_F_ONEPACKET) ?
				   " ops" : "");
		}

		if (svc->flags & IP_VS_SVC_F_PERSISTENT)
			seq_printf(seq, "persistent %d %08X\n",
				   svc->timeout, ntohl(svc->netmask));
		else
			seq_putc(seq, '\n');

		list_for_each_entry(dest, &svc->destinations, n_list) {
#ifdef CONFIG_IP_VS_IPV6
			if (dest->af == AF_INET6)
				seq_printf(seq,
					   "  -> [%pI6]:%04X"
					   "      %-7s %-6d %-10d %-10d\n",
					   &dest->addr.in6,
					   ntohs(dest->port),
					   ip_vs_fwd_name(atomic_read
							  (&dest->conn_flags)),
					   atomic_read(&dest->weight),
					   atomic_read(&dest->activeconns),
					   atomic_read(&dest->inactconns));
			else
#endif
				seq_printf(seq,
					   "  -> %08X:%04X      "
					   "%-7s %-6d %-10d %-10d\n",
					   ntohl(dest->addr.ip),
					   ntohs(dest->port),
					   ip_vs_fwd_name(atomic_read
							  (&dest->conn_flags)),
					   atomic_read(&dest->weight),
					   atomic_read(&dest->activeconns),
					   atomic_read(&dest->inactconns));

		}
	}
	return 0;
}

static const struct seq_operations ip_vs_info_seq_ops = {
	.start = ip_vs_info_seq_start,
	.next = ip_vs_info_seq_next,
	.stop = ip_vs_info_seq_stop,
	.show = ip_vs_info_seq_show,
};

static int ip_vs_info_open(struct inode *inode, struct file *file)
{
	return seq_open_private(file, &ip_vs_info_seq_ops,
				sizeof(struct ip_vs_iter));
}

static const struct file_operations ip_vs_info_fops = {
	.owner = THIS_MODULE,
	.open = ip_vs_info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};

#endif

struct ip_vs_stats *ip_vs_stats;

#ifdef CONFIG_PROC_FS
static int ip_vs_stats_show(struct seq_file *seq, void *v)
{
	int i = 0;

	seq_puts(seq,
	       /* ++++01234567890123456++++01234567890123456++++01234567890123456++++01234567890123456++++01234567890123456*/
		"	          Total             Incoming             Outgoing             Incoming             Outgoing\n");
	seq_puts(seq,
		"	          Conns	             Packets		  Packets                Bytes                Bytes\n");

	for_each_online_cpu(i) {
		seq_printf(seq, "CPU%2d:%17Ld    %17Ld    %17Ld    %17Ld    %17Ld\n", i,
			ip_vs_stats_cpu(ip_vs_stats, i).conns,
			ip_vs_stats_cpu(ip_vs_stats, i).inpkts,
			ip_vs_stats_cpu(ip_vs_stats, i).outpkts,
			ip_vs_stats_cpu(ip_vs_stats, i).inbytes,
			ip_vs_stats_cpu(ip_vs_stats, i).outbytes);
	}

	return 0;
}

static int ip_vs_stats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, ip_vs_stats_show, NULL);
}

static const struct file_operations ip_vs_stats_fops = {
	.owner = THIS_MODULE,
	.open = ip_vs_stats_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

#endif

#ifdef CONFIG_PROC_FS
/*
 * Statistics for FULLNAT and SYNPROXY
 * in /proc/net/ip_vs_ext_stats
 */

struct ip_vs_estats_mib *ip_vs_esmib;

static struct ip_vs_estats_entry ext_stats[] = {
	IP_VS_ESTATS_ITEM("fullnat_add_toa_ok", FULLNAT_ADD_TOA_OK),
	IP_VS_ESTATS_ITEM("fullnat_add_toa_fail_len", FULLNAT_ADD_TOA_FAIL_LEN),
	IP_VS_ESTATS_ITEM("fullnat_add_toa_head_full", FULLNAT_ADD_TOA_HEAD_FULL),
	IP_VS_ESTATS_ITEM("fullnat_add_toa_fail_mem", FULLNAT_ADD_TOA_FAIL_MEM),
	IP_VS_ESTATS_ITEM("fullnat_add_toa_fail_proto",
			  FULLNAT_ADD_TOA_FAIL_PROTO),
	IP_VS_ESTATS_ITEM("fullnat_conn_reused", FULLNAT_CONN_REUSED),
	IP_VS_ESTATS_ITEM("fullnat_conn_reused_close",
			  FULLNAT_CONN_REUSED_CLOSE),
	IP_VS_ESTATS_ITEM("fullnat_conn_reused_timewait",
			  FULLNAT_CONN_REUSED_TIMEWAIT),
	IP_VS_ESTATS_ITEM("fullnat_conn_reused_finwait",
			  FULLNAT_CONN_REUSED_FINWAIT),
	IP_VS_ESTATS_ITEM("fullnat_conn_reused_closewait",
			  FULLNAT_CONN_REUSED_CLOSEWAIT),
	IP_VS_ESTATS_ITEM("fullnat_conn_reused_lastack",
			  FULLNAT_CONN_REUSED_LASTACK),
	IP_VS_ESTATS_ITEM("fullnat_conn_reused_estab",
			  FULLNAT_CONN_REUSED_ESTAB),
	IP_VS_ESTATS_ITEM("synproxy_rs_error", SYNPROXY_RS_ERROR),
	IP_VS_ESTATS_ITEM("synproxy_null_ack", SYNPROXY_NULL_ACK),
	IP_VS_ESTATS_ITEM("synproxy_bad_ack", SYNPROXY_BAD_ACK),
	IP_VS_ESTATS_ITEM("synproxy_ok_ack", SYNPROXY_OK_ACK),
	IP_VS_ESTATS_ITEM("synproxy_syn_cnt", SYNPROXY_SYN_CNT),
	IP_VS_ESTATS_ITEM("synproxy_ackstorm", SYNPROXY_ACK_STORM),
	IP_VS_ESTATS_ITEM("synproxy_synsend_qlen", SYNPROXY_SYNSEND_QLEN),
	IP_VS_ESTATS_ITEM("synproxy_conn_reused", SYNPROXY_CONN_REUSED),
	IP_VS_ESTATS_ITEM("synproxy_conn_reused_close",
			  SYNPROXY_CONN_REUSED_CLOSE),
	IP_VS_ESTATS_ITEM("synproxy_conn_reused_timewait",
			  SYNPROXY_CONN_REUSED_TIMEWAIT),
	IP_VS_ESTATS_ITEM("synproxy_conn_reused_finwait",
			  SYNPROXY_CONN_REUSED_FINWAIT),
	IP_VS_ESTATS_ITEM("synproxy_conn_reused_closewait",
			  SYNPROXY_CONN_REUSED_CLOSEWAIT),
	IP_VS_ESTATS_ITEM("synproxy_conn_reused_lastack",
			  SYNPROXY_CONN_REUSED_LASTACK),
	IP_VS_ESTATS_ITEM("defence_ip_frag_drop", DEFENCE_IP_FRAG_DROP),
	IP_VS_ESTATS_ITEM("defence_tcp_drop", DEFENCE_TCP_DROP),
	IP_VS_ESTATS_ITEM("defence_udp_drop", DEFENCE_UDP_DROP),
	IP_VS_ESTATS_ITEM("fast_xmit_reject", FAST_XMIT_REJECT),
	IP_VS_ESTATS_ITEM("fast_xmit_pass", FAST_XMIT_PASS),
	IP_VS_ESTATS_ITEM("fast_xmit_skb_copy", FAST_XMIT_SKB_COPY),
	IP_VS_ESTATS_ITEM("fast_xmit_no_mac", FAST_XMIT_NO_MAC),
	IP_VS_ESTATS_ITEM("fast_xmit_synproxy_save", FAST_XMIT_SYNPROXY_SAVE),
	IP_VS_ESTATS_ITEM("fast_xmit_dev_lost", FAST_XMIT_DEV_LOST),
	IP_VS_ESTATS_ITEM("fast_xmit_reject_inside", FAST_XMIT_REJECT_INSIDE),
	IP_VS_ESTATS_ITEM("fast_xmit_pass_inside", FAST_XMIT_PASS_INSIDE),
	IP_VS_ESTATS_ITEM("fast_xmit_synproxy_save_inside",
			FAST_XMIT_SYNPROXY_SAVE_INSIDE),
	IP_VS_ESTATS_ITEM("rst_in_syn_sent", RST_IN_SYN_SENT),
	IP_VS_ESTATS_ITEM("rst_out_syn_sent", RST_OUT_SYN_SENT),
	IP_VS_ESTATS_ITEM("rst_in_established", RST_IN_ESTABLISHED),
	IP_VS_ESTATS_ITEM("rst_out_established", RST_OUT_ESTABLISHED),
	IP_VS_ESTATS_ITEM("gro_pass", GRO_PASS),
	IP_VS_ESTATS_ITEM("lro_reject", LRO_REJECT),
	IP_VS_ESTATS_ITEM("xmit_unexpected_mtu", XMIT_UNEXPECTED_MTU),
	IP_VS_ESTATS_ITEM("conn_sched_unreach", CONN_SCHED_UNREACH),
	IP_VS_ESTATS_ITEM("synproxy_no_dest", SYNPROXY_NO_DEST),
	IP_VS_ESTATS_ITEM("conn_exceeded", CONN_EXCEEDED),
	IP_VS_ESTATS_LAST
};

static int ip_vs_estats_show(struct seq_file *seq, void *v)
{
	int i, j;

	/* print CPU first */
	seq_printf(seq, "                                  ");
	for (i = 0; i < NR_CPUS; i++)
		if (cpu_online(i))
			seq_printf(seq, "CPU%d       ", i);
	seq_putc(seq, '\n');

	i = 0;
	while (NULL != ext_stats[i].name) {
		seq_printf(seq, "%-25s:", ext_stats[i].name);
		for (j = 0; j < NR_CPUS; j++) {
			if (cpu_online(j)) {
				seq_printf(seq, "%10lu ",
					   *(((unsigned long *)
					      per_cpu_ptr(ip_vs_esmib,
							  j)) +
					     ext_stats[i].entry));
			}
		}
		seq_putc(seq, '\n');
		i++;
	}
	return 0;
}

static int ip_vs_estats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, ip_vs_estats_show, NULL);
}

static const struct file_operations ip_vs_estats_fops = {
	.owner = THIS_MODULE,
	.open = ip_vs_estats_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

/*
 *	Set timeout values for tcp tcpfin udp in the timeout_table.
 */
static int ip_vs_set_timeout(struct ip_vs_timeout_user *u)
{
	IP_VS_DBG(2, "Setting timeout tcp:%d tcpfin:%d udp:%d\n",
		  u->tcp_timeout, u->tcp_fin_timeout, u->udp_timeout);

#ifdef CONFIG_IP_VS_PROTO_TCP
	if (u->tcp_timeout) {
		ip_vs_protocol_tcp.timeout_table[IP_VS_TCP_S_ESTABLISHED]
		    = u->tcp_timeout * HZ;
	}

	if (u->tcp_fin_timeout) {
		ip_vs_protocol_tcp.timeout_table[IP_VS_TCP_S_FIN_WAIT]
		    = u->tcp_fin_timeout * HZ;
	}
#endif

#ifdef CONFIG_IP_VS_PROTO_UDP
	if (u->udp_timeout) {
		ip_vs_protocol_udp.timeout_table[IP_VS_UDP_S_NORMAL]
		    = u->udp_timeout * HZ;
	}
#endif
	return 0;
}

#define SET_CMDID(cmd)		(cmd - IP_VS_BASE_CTL)
#define SERVICE_ARG_LEN		(sizeof(struct ip_vs_service_user))
#define SVCDEST_ARG_LEN		(sizeof(struct ip_vs_service_user) +	\
				 sizeof(struct ip_vs_dest_user))
#define SVCLADDR_ARG_LEN	(sizeof(struct ip_vs_service_user) +	\
				 sizeof(struct ip_vs_laddr_user))
#define TIMEOUT_ARG_LEN		(sizeof(struct ip_vs_timeout_user))
#define DAEMON_ARG_LEN		(sizeof(struct ip_vs_daemon_user))
#define MAX_ARG_LEN		SVCDEST_ARG_LEN

static const unsigned char set_arglen[SET_CMDID(IP_VS_SO_SET_MAX) + 1] = {
	[SET_CMDID(IP_VS_SO_SET_ADD)] = SERVICE_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_EDIT)] = SERVICE_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_DEL)] = SERVICE_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_FLUSH)] = 0,
	[SET_CMDID(IP_VS_SO_SET_ADDDEST)] = SVCDEST_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_DELDEST)] = SVCDEST_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_EDITDEST)] = SVCDEST_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_TIMEOUT)] = TIMEOUT_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_STARTDAEMON)] = DAEMON_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_STOPDAEMON)] = DAEMON_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_ZERO)] = SERVICE_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_ADDLADDR)] = SVCLADDR_ARG_LEN,
	[SET_CMDID(IP_VS_SO_SET_DELLADDR)] = SVCLADDR_ARG_LEN,
};

static void ip_vs_copy_usvc_compat(struct ip_vs_service_user_kern *usvc,
				   struct ip_vs_service_user *usvc_compat)
{
	usvc->af = AF_INET;
	usvc->protocol = usvc_compat->protocol;
	usvc->addr.ip = usvc_compat->addr;
	usvc->port = usvc_compat->port;
	usvc->fwmark = usvc_compat->fwmark;

	/* Deep copy of sched_name is not needed here */
	usvc->sched_name = usvc_compat->sched_name;

	usvc->flags = usvc_compat->flags;
	usvc->timeout = usvc_compat->timeout;
	usvc->netmask = usvc_compat->netmask;
}

static void ip_vs_copy_udest_compat(struct ip_vs_dest_user_kern *udest,
				    struct ip_vs_dest_user *udest_compat)
{
	udest->addr.ip = udest_compat->addr;
	udest->port = udest_compat->port;
	udest->conn_flags = udest_compat->conn_flags;
	udest->weight = udest_compat->weight;
	udest->u_threshold = udest_compat->u_threshold;
	udest->l_threshold = udest_compat->l_threshold;
}

static void ip_vs_copy_uladdr_compat(struct ip_vs_laddr_user_kern *uladdr,
				     struct ip_vs_laddr_user *uladdr_compat)
{
	uladdr->addr.ip = uladdr_compat->addr;
}

static int
do_ip_vs_set_ctl(struct sock *sk, int cmd, void __user * user, unsigned int len)
{
	int ret;
	unsigned char arg[MAX_ARG_LEN];
	struct ip_vs_service_user *usvc_compat;
	struct ip_vs_service_user_kern usvc;
	struct ip_vs_service *svc;
	struct ip_vs_dest_user *udest_compat;
	struct ip_vs_dest_user_kern udest;
	struct ip_vs_laddr_user *uladdr_compat;
	struct ip_vs_laddr_user_kern uladdr;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (len != set_arglen[SET_CMDID(cmd)]) {
		pr_err("set_ctl: len %u != %u\n",
		       len, set_arglen[SET_CMDID(cmd)]);
		return -EINVAL;
	}

	if (copy_from_user(arg, user, len) != 0)
		return -EFAULT;

	/* increase the module use count */
	ip_vs_use_count_inc();

	if (mutex_lock_interruptible(&__ip_vs_mutex)) {
		ret = -ERESTARTSYS;
		goto out_dec;
	}

	if (cmd == IP_VS_SO_SET_FLUSH) {
		/* Flush the virtual service */
		ret = ip_vs_flush();
		goto out_unlock;
	} else if (cmd == IP_VS_SO_SET_TIMEOUT) {
		/* Set timeout values for (tcp tcpfin udp) */
		ret = ip_vs_set_timeout((struct ip_vs_timeout_user *)arg);
		goto out_unlock;
	} else if (cmd == IP_VS_SO_SET_STARTDAEMON) {
		struct ip_vs_daemon_user *dm = (struct ip_vs_daemon_user *)arg;
		ret = start_sync_thread(dm->state, dm->mcast_ifn, dm->syncid);
		goto out_unlock;
	} else if (cmd == IP_VS_SO_SET_STOPDAEMON) {
		struct ip_vs_daemon_user *dm = (struct ip_vs_daemon_user *)arg;
		ret = stop_sync_thread(dm->state);
		goto out_unlock;
	}

	usvc_compat = (struct ip_vs_service_user *)arg;
	udest_compat = (struct ip_vs_dest_user *)(usvc_compat + 1);
	uladdr_compat = (struct ip_vs_laddr_user *)(usvc_compat + 1);

	/* We only use the new structs internally, so copy userspace compat
	 * structs to extended internal versions */
	ip_vs_copy_usvc_compat(&usvc, usvc_compat);

	if (cmd == IP_VS_SO_SET_ZERO) {
		/* if no service address is set, zero counters in all */
		if (!usvc.fwmark && !usvc.addr.ip && !usvc.port) {
			ret = -EACCES;	//ip_vs_zero_all();
			goto out_unlock;
		}
	}

	/* Check for valid protocol: TCP or UDP, even for fwmark!=0 */
	if (usvc.protocol != IPPROTO_TCP && usvc.protocol != IPPROTO_UDP) {
		pr_err("set_ctl: invalid protocol: %d %pI4:%d %s\n",
		       usvc.protocol, &usvc.addr.ip,
		       ntohs(usvc.port), usvc.sched_name);
		ret = -EFAULT;
		goto out_unlock;
	}

	/* Lookup the exact service by <protocol, addr, port> or fwmark */
	if (usvc.fwmark == 0)
		svc = __ip_vs_service_get(usvc.af, usvc.protocol,
					  &usvc.addr, usvc.port);
	else
		svc = __ip_vs_svc_fwm_get(usvc.af, usvc.fwmark);

	if (cmd != IP_VS_SO_SET_ADD
	    && (svc == NULL || svc->protocol != usvc.protocol)) {
		ret = -ESRCH;
		goto out_unlock;
	}

	switch (cmd) {
	case IP_VS_SO_SET_ADD:
		if (svc != NULL)
			ret = -EEXIST;
		else
			ret = ip_vs_add_service(&usvc, &svc);
		break;
	case IP_VS_SO_SET_EDIT:
		ret = ip_vs_edit_service(svc, &usvc);
		break;
	case IP_VS_SO_SET_DEL:
		ret = ip_vs_del_service(svc);
		if (!ret)
			goto out_unlock;
		break;
	case IP_VS_SO_SET_ZERO:
		ret = -EACCES;	//ip_vs_zero_service(svc);
		break;
	case IP_VS_SO_SET_ADDDEST:
		ip_vs_copy_udest_compat(&udest, udest_compat);
		ret = ip_vs_add_dest(svc, &udest);
		break;
	case IP_VS_SO_SET_EDITDEST:
		ip_vs_copy_udest_compat(&udest, udest_compat);
		ret = ip_vs_edit_dest(svc, &udest);
		break;
	case IP_VS_SO_SET_DELDEST:
		ip_vs_copy_udest_compat(&udest, udest_compat);
		ret = ip_vs_del_dest(svc, &udest);
		break;
	case IP_VS_SO_SET_ADDLADDR:
		ip_vs_copy_uladdr_compat(&uladdr, uladdr_compat);
		ret = ip_vs_add_laddr(svc, &uladdr);
		break;
	case IP_VS_SO_SET_DELLADDR:
		ip_vs_copy_uladdr_compat(&uladdr, uladdr_compat);
		ret = ip_vs_del_laddr(svc, &uladdr);
		break;
	default:
		ret = -EINVAL;
	}

//	if (svc)
//		ip_vs_service_put(svc);

      out_unlock:
	mutex_unlock(&__ip_vs_mutex);
      out_dec:
	/* decrease the module use count */
	ip_vs_use_count_dec();

	return ret;
}

static void
ip_vs_copy_service(struct ip_vs_service_entry *dst, struct ip_vs_service *src)
{
	int cpu = 0;

	dst->protocol = src->protocol;
	dst->addr = src->addr.ip;
	dst->port = src->port;
	dst->fwmark = src->fwmark;
	strlcpy(dst->sched_name, src->scheduler->name, sizeof(dst->sched_name));
	dst->flags = src->flags;
	dst->timeout = src->timeout / HZ;
	dst->netmask = src->netmask;
	dst->num_dests = src->num_dests;
	dst->num_laddrs = src->num_laddrs;
	for_each_online_cpu(cpu) {
		dst->stats.conns += (src->svc0 + cpu)->stats.conns;
		dst->stats.inpkts += (src->svc0 + cpu)->stats.inpkts;
		dst->stats.outpkts += (src->svc0 + cpu)->stats.outpkts;
		dst->stats.inbytes += (src->svc0 + cpu)->stats.inbytes;
		dst->stats.outbytes += (src->svc0 + cpu)->stats.outbytes;
	}
}

static inline int
__ip_vs_get_service_entries(const struct ip_vs_get_services *get,
			    struct ip_vs_get_services __user * uptr)
{
	int idx, count = 0;
	struct ip_vs_service *svc;
	struct list_head *ip_vs_svc_tab;
	struct ip_vs_service_entry entry;
	int ret = 0;

	ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_tab_percpu);
	for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
		list_for_each_entry(svc, ip_vs_svc_tab + idx, s_list) {
			/* Only expose IPv4 entries to old interface */
			if (svc->af != AF_INET)
				continue;

			if (count >= get->num_services)
				goto out;
			memset(&entry, 0, sizeof(entry));
			ip_vs_copy_service(&entry, svc);
			if (copy_to_user(&uptr->entrytable[count],
					 &entry, sizeof(entry))) {
				ret = -EFAULT;
				goto out;
			}
			count++;
		}
	}

	ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_fwm_tab_percpu);
	for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
		list_for_each_entry(svc, ip_vs_svc_tab + idx, f_list) {
			/* Only expose IPv4 entries to old interface */
			if (svc->af != AF_INET)
				continue;

			if (count >= get->num_services)
				goto out;
			memset(&entry, 0, sizeof(entry));
			ip_vs_copy_service(&entry, svc);
			if (copy_to_user(&uptr->entrytable[count],
					 &entry, sizeof(entry))) {
				ret = -EFAULT;
				goto out;
			}
			count++;
		}
	}
      out:
	return ret;
}

static inline int
__ip_vs_get_dest_entries(const struct ip_vs_get_dests *get,
			 struct ip_vs_get_dests __user * uptr)
{
	struct ip_vs_service *svc;
	union nf_inet_addr addr = {.ip = get->addr };
	int ret = 0;

	if (get->fwmark)
		svc = __ip_vs_svc_fwm_get(AF_INET, get->fwmark);
	else
		svc = __ip_vs_service_get(AF_INET, get->protocol, &addr,
					  get->port);

	if (svc) {
		int count = 0;
		int cpu;
		struct ip_vs_dest *per_dest;
		struct ip_vs_service *this_svc;
		struct ip_vs_dest *dest;
		struct ip_vs_dest_entry entry;

		list_for_each_entry(dest, &svc->destinations, n_list) {
			if (count >= get->num_dests)
				break;

			memset(&entry, 0, sizeof(entry));
			entry.addr = dest->addr.ip;
			entry.port = dest->port;
			entry.conn_flags = atomic_read(&dest->conn_flags);
			entry.weight = atomic_read(&dest->weight);
			entry.u_threshold = dest->u_threshold;
			entry.l_threshold = dest->l_threshold;

			/* percpu counter */
			this_svc = dest->svc->svc0;
			for_each_online_cpu(cpu) {
				per_dest = ip_vs_lookup_dest(this_svc,
						&dest->addr, dest->port);
				if(per_dest == NULL) {
					IP_VS_ERR_RL("%s():dest doesn't exist "
						"on cpu%d\n", __func__, cpu);
					ret = -EFAULT;
					goto out;
				}

				entry.activeconns +=
					atomic_read(&per_dest->activeconns);
				entry.inactconns +=
					atomic_read(&per_dest->inactconns);
				entry.persistconns +=
					atomic_read(&per_dest->persistconns);

				entry.stats.conns += per_dest->stats.conns;
				entry.stats.inpkts += per_dest->stats.inpkts;
				entry.stats.outpkts += per_dest->stats.outpkts;
				entry.stats.inbytes += per_dest->stats.inbytes;
				entry.stats.outbytes +=
						per_dest->stats.outbytes;

				this_svc++;
			}

			if (copy_to_user(&uptr->entrytable[count],
					 &entry, sizeof(entry))) {
				ret = -EFAULT;
				break;
			}
			count++;
		}
	//	ip_vs_service_put(svc);
	} else
		ret = -ESRCH;
out:
	return ret;
}

static inline int
__ip_vs_get_laddr_entries(const struct ip_vs_get_laddrs *get,
			  struct ip_vs_get_laddrs __user * uptr)
{
	struct ip_vs_service *svc;
	union nf_inet_addr addr = {.ip = get->addr };
	int ret = 0;

	if (get->fwmark)
		svc = __ip_vs_svc_fwm_get(AF_INET, get->fwmark);
	else
		svc = __ip_vs_service_get(AF_INET, get->protocol, &addr,
					  get->port);

	if (svc) {
		int cpu;
		int count = 0;
		struct ip_vs_laddr *laddr;
		struct ip_vs_service *svc_per;
		struct ip_vs_laddr_entry entry;

		svc_per = svc->svc0;
		for_each_online_cpu(cpu) {
			list_for_each_entry(laddr,
					&svc_per->laddr_list, n_list) {
				if (count >= get->num_laddrs)
					break;

				entry.addr = laddr->addr.ip;
				entry.port_conflict =
				    atomic64_read(&laddr->port_conflict);
				entry.conn_counts = atomic_read(&laddr->conn_counts);
				if (copy_to_user(&uptr->entrytable[count],
						 &entry, sizeof(entry))) {
					ret = -EFAULT;
					break;
				}
				count++;
			}
			svc_per++;
		}
		//ip_vs_service_put(svc);
	} else
		ret = -ESRCH;
	return ret;
}

static inline void __ip_vs_get_timeouts(struct ip_vs_timeout_user *u)
{
#ifdef CONFIG_IP_VS_PROTO_TCP
	u->tcp_timeout =
	    ip_vs_protocol_tcp.timeout_table[IP_VS_TCP_S_ESTABLISHED] / HZ;
	u->tcp_fin_timeout =
	    ip_vs_protocol_tcp.timeout_table[IP_VS_TCP_S_FIN_WAIT] / HZ;
#endif
#ifdef CONFIG_IP_VS_PROTO_UDP
	u->udp_timeout =
	    ip_vs_protocol_udp.timeout_table[IP_VS_UDP_S_NORMAL] / HZ;
#endif
}

#define GET_CMDID(cmd)		(cmd - IP_VS_BASE_CTL)
#define GET_INFO_ARG_LEN	(sizeof(struct ip_vs_getinfo))
#define GET_SERVICES_ARG_LEN	(sizeof(struct ip_vs_get_services))
#define GET_SERVICE_ARG_LEN	(sizeof(struct ip_vs_service_entry))
#define GET_DESTS_ARG_LEN	(sizeof(struct ip_vs_get_dests))
#define GET_LADDRS_ARG_LEN	(sizeof(struct ip_vs_get_laddrs))
#define GET_TIMEOUT_ARG_LEN	(sizeof(struct ip_vs_timeout_user))
#define GET_DAEMON_ARG_LEN	(sizeof(struct ip_vs_daemon_user) * 2)

static const unsigned char get_arglen[GET_CMDID(IP_VS_SO_GET_MAX) + 1] = {
	[GET_CMDID(IP_VS_SO_GET_VERSION)] = 64,
	[GET_CMDID(IP_VS_SO_GET_INFO)] = GET_INFO_ARG_LEN,
	[GET_CMDID(IP_VS_SO_GET_SERVICES)] = GET_SERVICES_ARG_LEN,
	[GET_CMDID(IP_VS_SO_GET_SERVICE)] = GET_SERVICE_ARG_LEN,
	[GET_CMDID(IP_VS_SO_GET_DESTS)] = GET_DESTS_ARG_LEN,
	[GET_CMDID(IP_VS_SO_GET_LADDRS)] = GET_LADDRS_ARG_LEN,
	[GET_CMDID(IP_VS_SO_GET_TIMEOUT)] = GET_TIMEOUT_ARG_LEN,
	[GET_CMDID(IP_VS_SO_GET_DAEMON)] = GET_DAEMON_ARG_LEN,
};

static int
do_ip_vs_get_ctl(struct sock *sk, int cmd, void __user * user, int *len)
{
	unsigned char arg[128];
	int ret = 0;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (*len < get_arglen[GET_CMDID(cmd)]) {
		pr_err("get_ctl: len %u < %u\n",
		       *len, get_arglen[GET_CMDID(cmd)]);
		return -EINVAL;
	}

	if (copy_from_user(arg, user, get_arglen[GET_CMDID(cmd)]) != 0)
		return -EFAULT;

	if (mutex_lock_interruptible(&__ip_vs_mutex))
		return -ERESTARTSYS;

	switch (cmd) {
	case IP_VS_SO_GET_VERSION:
		{
			char buf[64];

			sprintf(buf,
				"IP Virtual Server version %d.%d.%d (size=%d)",
				NVERSION(IP_VS_VERSION_CODE),
				IP_VS_CONN_TAB_SIZE);
			if (copy_to_user(user, buf, strlen(buf) + 1) != 0) {
				ret = -EFAULT;
				goto out;
			}
			*len = strlen(buf) + 1;
		}
		break;

	case IP_VS_SO_GET_INFO:
		{
			struct ip_vs_getinfo info;
			info.version = IP_VS_VERSION_CODE;
			info.size = IP_VS_CONN_TAB_SIZE;
			info.num_services = ip_vs_num_services;
			if (copy_to_user(user, &info, sizeof(info)) != 0)
				ret = -EFAULT;
		}
		break;

	case IP_VS_SO_GET_SERVICES:
		{
			struct ip_vs_get_services *get;
			int size;

			get = (struct ip_vs_get_services *)arg;
			size = sizeof(*get) +
			    sizeof(struct ip_vs_service_entry) *
			    get->num_services;
			if (*len != size) {
				pr_err("length: %u != %u\n", *len, size);
				ret = -EINVAL;
				goto out;
			}
			ret = __ip_vs_get_service_entries(get, user);
		}
		break;

	case IP_VS_SO_GET_SERVICE:
		{
			struct ip_vs_service_entry *entry;
			struct ip_vs_service *svc;
			union nf_inet_addr addr;

			entry = (struct ip_vs_service_entry *)arg;
			addr.ip = entry->addr;
			if (entry->fwmark)
				svc =
				    __ip_vs_svc_fwm_get(AF_INET, entry->fwmark);
			else
				svc =
				    __ip_vs_service_get(AF_INET,
							entry->protocol, &addr,
							entry->port);
			if (svc) {
				ip_vs_copy_service(entry, svc);
				if (copy_to_user(user, entry, sizeof(*entry)) !=
				    0)
					ret = -EFAULT;
				//ip_vs_service_put(svc);
			} else
				ret = -ESRCH;
		}
		break;

	case IP_VS_SO_GET_DESTS:
		{
			struct ip_vs_get_dests *get;
			int size;

			get = (struct ip_vs_get_dests *)arg;
			size = sizeof(*get) +
			    sizeof(struct ip_vs_dest_entry) * get->num_dests;
			if (*len != size) {
				pr_err("length: %u != %u\n", *len, size);
				ret = -EINVAL;
				goto out;
			}
			ret = __ip_vs_get_dest_entries(get, user);
		}
		break;

	case IP_VS_SO_GET_LADDRS:
		{
			struct ip_vs_get_laddrs *get;
			int size;

			get = (struct ip_vs_get_laddrs *)arg;
			size = sizeof(*get) +
			    sizeof(struct ip_vs_laddr_entry) * get->num_laddrs;
			if (*len != size) {
				pr_err("length: %u != %u\n", *len, size);
				ret = -EINVAL;
				goto out;
			}
			ret = __ip_vs_get_laddr_entries(get, user);
		}
		break;
	case IP_VS_SO_GET_TIMEOUT:
		{
			struct ip_vs_timeout_user t;

			__ip_vs_get_timeouts(&t);
			if (copy_to_user(user, &t, sizeof(t)) != 0)
				ret = -EFAULT;
		}
		break;

	case IP_VS_SO_GET_DAEMON:
		{
			struct ip_vs_daemon_user d[2];

			memset(&d, 0, sizeof(d));
			if (ip_vs_sync_state & IP_VS_STATE_MASTER) {
				d[0].state = IP_VS_STATE_MASTER;
				strlcpy(d[0].mcast_ifn, ip_vs_master_mcast_ifn,
					sizeof(d[0].mcast_ifn));
				d[0].syncid = ip_vs_master_syncid;
			}
			if (ip_vs_sync_state & IP_VS_STATE_BACKUP) {
				d[1].state = IP_VS_STATE_BACKUP;
				strlcpy(d[1].mcast_ifn, ip_vs_backup_mcast_ifn,
					sizeof(d[1].mcast_ifn));
				d[1].syncid = ip_vs_backup_syncid;
			}
			if (copy_to_user(user, &d, sizeof(d)) != 0)
				ret = -EFAULT;
		}
		break;

	default:
		ret = -EINVAL;
	}

      out:
	mutex_unlock(&__ip_vs_mutex);
	return ret;
}

static struct nf_sockopt_ops ip_vs_sockopts = {
	.pf = PF_INET,
	.set_optmin = IP_VS_BASE_CTL,
	.set_optmax = IP_VS_SO_SET_MAX + 1,
	.set = do_ip_vs_set_ctl,
	.get_optmin = IP_VS_BASE_CTL,
	.get_optmax = IP_VS_SO_GET_MAX + 1,
	.get = do_ip_vs_get_ctl,
	.owner = THIS_MODULE,
};

/*
 * Generic Netlink interface
 */

/* IPVS genetlink family */
static struct genl_family ip_vs_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = IPVS_GENL_NAME,
	.version = IPVS_GENL_VERSION,
	.maxattr = IPVS_CMD_MAX,
};

/* Policy used for first-level command attributes */
static const struct nla_policy ip_vs_cmd_policy[IPVS_CMD_ATTR_MAX + 1] = {
	[IPVS_CMD_ATTR_SERVICE] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_DEST] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_DAEMON] = {.type = NLA_NESTED},
	[IPVS_CMD_ATTR_TIMEOUT_TCP] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_TIMEOUT_UDP] = {.type = NLA_U32},
	[IPVS_CMD_ATTR_LADDR] = {.type = NLA_NESTED},
};

/* Policy used for attributes in nested attribute IPVS_CMD_ATTR_DAEMON */
static const struct nla_policy ip_vs_daemon_policy[IPVS_DAEMON_ATTR_MAX + 1] = {
	[IPVS_DAEMON_ATTR_STATE] = {.type = NLA_U32},
	[IPVS_DAEMON_ATTR_MCAST_IFN] = {.type = NLA_NUL_STRING,
					.len = IP_VS_IFNAME_MAXLEN},
	[IPVS_DAEMON_ATTR_SYNC_ID] = {.type = NLA_U32},
};

/* Policy used for attributes in nested attribute IPVS_CMD_ATTR_SERVICE */
static const struct nla_policy ip_vs_svc_policy[IPVS_SVC_ATTR_MAX + 1] = {
	[IPVS_SVC_ATTR_AF] = {.type = NLA_U16},
	[IPVS_SVC_ATTR_PROTOCOL] = {.type = NLA_U16},
	[IPVS_SVC_ATTR_ADDR] = {.type = NLA_BINARY,
				.len = sizeof(union nf_inet_addr)},
	[IPVS_SVC_ATTR_PORT] = {.type = NLA_U16},
	[IPVS_SVC_ATTR_FWMARK] = {.type = NLA_U32},
	[IPVS_SVC_ATTR_SCHED_NAME] = {.type = NLA_NUL_STRING,
				      .len = IP_VS_SCHEDNAME_MAXLEN},
	[IPVS_SVC_ATTR_FLAGS] = {.type = NLA_BINARY,
				 .len = sizeof(struct ip_vs_flags)},
	[IPVS_SVC_ATTR_TIMEOUT] = {.type = NLA_U32},
	[IPVS_SVC_ATTR_NETMASK] = {.type = NLA_U32},
	[IPVS_SVC_ATTR_STATS] = {.type = NLA_NESTED},
};

/* Policy used for attributes in nested attribute IPVS_CMD_ATTR_DEST */
static const struct nla_policy ip_vs_dest_policy[IPVS_DEST_ATTR_MAX + 1] = {
	[IPVS_DEST_ATTR_ADDR] = {.type = NLA_BINARY,
				 .len = sizeof(union nf_inet_addr)},
	[IPVS_DEST_ATTR_PORT] = {.type = NLA_U16},
	[IPVS_DEST_ATTR_FWD_METHOD] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_WEIGHT] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_U_THRESH] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_L_THRESH] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_ACTIVE_CONNS] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_INACT_CONNS] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_PERSIST_CONNS] = {.type = NLA_U32},
	[IPVS_DEST_ATTR_STATS] = {.type = NLA_NESTED},
};

static const struct nla_policy ip_vs_laddr_policy[IPVS_LADDR_ATTR_MAX + 1] = {
	[IPVS_LADDR_ATTR_ADDR] = {.type = NLA_BINARY,
				  .len = sizeof(union nf_inet_addr)},
	[IPVS_LADDR_ATTR_PORT_CONFLICT] = {.type = NLA_U64},
	[IPVS_LADDR_ATTR_CONN_COUNTS] = {.type = NLA_U32},
};

static int ip_vs_genl_fill_stats(struct sk_buff *skb, int container_type,
				 struct ip_vs_stats *stats)
{
	struct nlattr *nl_stats = nla_nest_start(skb, container_type);

	if (!nl_stats)
		return -EMSGSIZE;

	NLA_PUT_U64(skb, IPVS_STATS_ATTR_CONNS, stats->conns);
	NLA_PUT_U64(skb, IPVS_STATS_ATTR_INPKTS, stats->inpkts);
	NLA_PUT_U64(skb, IPVS_STATS_ATTR_OUTPKTS, stats->outpkts);
	NLA_PUT_U64(skb, IPVS_STATS_ATTR_INBYTES, stats->inbytes);
	NLA_PUT_U64(skb, IPVS_STATS_ATTR_OUTBYTES, stats->outbytes);
	NLA_PUT_U32(skb, IPVS_STATS_ATTR_CPS, 0);
	NLA_PUT_U32(skb, IPVS_STATS_ATTR_INPPS, 0);
	NLA_PUT_U32(skb, IPVS_STATS_ATTR_OUTPPS, 0);
	NLA_PUT_U32(skb, IPVS_STATS_ATTR_INBPS, 0);
	NLA_PUT_U32(skb, IPVS_STATS_ATTR_OUTBPS, 0);

	nla_nest_end(skb, nl_stats);

	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nl_stats);
	return -EMSGSIZE;
}

static int ip_vs_genl_fill_service(struct sk_buff *skb,
				   struct ip_vs_service *svc)
{
	int cpu;
	struct ip_vs_stats tmp_stats;
	struct ip_vs_service *this_svc;
	struct nlattr *nl_service;
	struct ip_vs_flags flags = {.flags = svc->flags,
		.mask = ~0
	};

	nl_service = nla_nest_start(skb, IPVS_CMD_ATTR_SERVICE);
	if (!nl_service)
		return -EMSGSIZE;

	NLA_PUT_U16(skb, IPVS_SVC_ATTR_AF, svc->af);

	if (svc->fwmark) {
		NLA_PUT_U32(skb, IPVS_SVC_ATTR_FWMARK, svc->fwmark);
	} else {
		NLA_PUT_U16(skb, IPVS_SVC_ATTR_PROTOCOL, svc->protocol);
		NLA_PUT(skb, IPVS_SVC_ATTR_ADDR, sizeof(svc->addr), &svc->addr);
		NLA_PUT_U16(skb, IPVS_SVC_ATTR_PORT, svc->port);
	}

	NLA_PUT_STRING(skb, IPVS_SVC_ATTR_SCHED_NAME, svc->scheduler->name);
	NLA_PUT(skb, IPVS_SVC_ATTR_FLAGS, sizeof(flags), &flags);
	NLA_PUT_U32(skb, IPVS_SVC_ATTR_TIMEOUT, svc->timeout / HZ);
	NLA_PUT_U32(skb, IPVS_SVC_ATTR_NETMASK, svc->netmask);
	NLA_PUT_U32(skb, IPVS_SVC_ATTR_EST_TIMEOUT, svc->est_timeout / HZ);

	memset((void*)(&tmp_stats), 0, sizeof(struct ip_vs_stats));
	this_svc = svc->svc0;
	for_each_possible_cpu(cpu) {
		tmp_stats.conns += this_svc->stats.conns;
		tmp_stats.inpkts += this_svc->stats.inpkts;
		tmp_stats.outpkts += this_svc->stats.outpkts;
		tmp_stats.inbytes += this_svc->stats.inbytes;
		tmp_stats.outbytes += this_svc->stats.outbytes;

		this_svc++;
	}

	if (ip_vs_genl_fill_stats(skb, IPVS_SVC_ATTR_STATS, &tmp_stats))
		goto nla_put_failure;

	nla_nest_end(skb, nl_service);

	return 0;

      nla_put_failure:
	nla_nest_cancel(skb, nl_service);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_service(struct sk_buff *skb,
				   struct ip_vs_service *svc,
				   struct netlink_callback *cb)
{
	void *hdr;

	if (!svc) {
		printk("ip_vs_genl_dump_service:svc is NULL\n");
		return -EMSGSIZE;
	}

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq,
			  &ip_vs_genl_family, NLM_F_MULTI,
			  IPVS_CMD_NEW_SERVICE);
	if (!hdr)
		return -EMSGSIZE;

	if (ip_vs_genl_fill_service(skb, svc) < 0)
		goto nla_put_failure;

	return genlmsg_end(skb, hdr);

      nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_services(struct sk_buff *skb,
				    struct netlink_callback *cb)
{
	int idx = 0, i;
	int start = cb->args[0];
	struct ip_vs_service *svc;
	struct list_head *ip_vs_svc_tab;

	mutex_lock(&__ip_vs_mutex);
	for (i = 0; i < IP_VS_SVC_TAB_SIZE; i++) {
		ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_tab_percpu);
		list_for_each_entry(svc, ip_vs_svc_tab + i, s_list) {
			if (++idx <= start)
				continue;
			if (ip_vs_genl_dump_service(skb, svc, cb) < 0) {
				idx--;
				goto nla_put_failure;
			}
		}
	}

	for (i = 0; i < IP_VS_SVC_TAB_SIZE; i++) {
		ip_vs_svc_tab = __get_cpu_var(ip_vs_svc_fwm_tab_percpu);
		list_for_each_entry(svc, ip_vs_svc_tab + i, f_list) {
			if (++idx <= start)
				continue;
			if (ip_vs_genl_dump_service(skb, svc, cb) < 0) {
				idx--;
				goto nla_put_failure;
			}
		}
	}

      nla_put_failure:
	mutex_unlock(&__ip_vs_mutex);
	cb->args[0] = idx;

	return skb->len;
}

static int ip_vs_genl_parse_service(struct ip_vs_service_user_kern *usvc,
				    struct nlattr *nla, int full_entry)
{
	struct nlattr *attrs[IPVS_SVC_ATTR_MAX + 1];
	struct nlattr *nla_af, *nla_port, *nla_fwmark, *nla_protocol, *nla_addr;

	/* Parse mandatory identifying service fields first */
	if (nla == NULL ||
	    nla_parse_nested(attrs, IPVS_SVC_ATTR_MAX, nla, ip_vs_svc_policy))
		return -EINVAL;

	nla_af = attrs[IPVS_SVC_ATTR_AF];
	nla_protocol = attrs[IPVS_SVC_ATTR_PROTOCOL];
	nla_addr = attrs[IPVS_SVC_ATTR_ADDR];
	nla_port = attrs[IPVS_SVC_ATTR_PORT];
	nla_fwmark = attrs[IPVS_SVC_ATTR_FWMARK];

	if (!(nla_af && (nla_fwmark || (nla_port && nla_protocol && nla_addr))))
		return -EINVAL;

	memset(usvc, 0, sizeof(*usvc));

	usvc->af = nla_get_u16(nla_af);
#ifdef CONFIG_IP_VS_IPV6
	if (usvc->af != AF_INET && usvc->af != AF_INET6)
#else
	if (usvc->af != AF_INET)
#endif
		return -EAFNOSUPPORT;

	if (nla_fwmark) {
		usvc->protocol = IPPROTO_TCP;
		usvc->fwmark = nla_get_u32(nla_fwmark);
	} else {
		usvc->protocol = nla_get_u16(nla_protocol);
		nla_memcpy(&usvc->addr, nla_addr, sizeof(usvc->addr));
		usvc->port = nla_get_u16(nla_port);
		usvc->fwmark = 0;
	}

	/* If a full entry was requested, check for the additional fields */
	if (full_entry) {
		struct nlattr *nla_sched, *nla_flags, *nla_timeout,
		    *nla_netmask, *nla_est_timeout;
		struct ip_vs_flags flags;
		struct ip_vs_service *svc;

		nla_sched = attrs[IPVS_SVC_ATTR_SCHED_NAME];
		nla_flags = attrs[IPVS_SVC_ATTR_FLAGS];
		nla_timeout = attrs[IPVS_SVC_ATTR_TIMEOUT];
		nla_netmask = attrs[IPVS_SVC_ATTR_NETMASK];
		nla_est_timeout = attrs[IPVS_SVC_ATTR_EST_TIMEOUT];

		if (!(nla_sched && nla_flags && nla_timeout && nla_netmask))
			return -EINVAL;

		nla_memcpy(&flags, nla_flags, sizeof(flags));

		/* prefill flags from service if it already exists */
		if (usvc->fwmark)
			svc = __ip_vs_svc_fwm_get(usvc->af, usvc->fwmark);
		else
			svc = __ip_vs_service_get(usvc->af, usvc->protocol,
						  &usvc->addr, usvc->port);
		if (svc) {
			usvc->flags = svc->flags;
			//ip_vs_service_put(svc);
		} else
			usvc->flags = 0;

		/* set new flags from userland */
		usvc->flags = (usvc->flags & ~flags.mask) |
		    (flags.flags & flags.mask);
		usvc->sched_name = nla_data(nla_sched);
		usvc->timeout = nla_get_u32(nla_timeout);
		usvc->netmask = nla_get_u32(nla_netmask);
		if(IPPROTO_TCP == usvc->protocol) {
			if(nla_est_timeout) /* Be compatible with different version of libipvs2.6 */
				usvc->est_timeout = nla_get_u32(nla_est_timeout);
			if(!usvc->est_timeout)
				usvc->est_timeout = sysctl_ip_vs_tcp_timeouts[IP_VS_TCP_S_ESTABLISHED] / HZ;
		}
	}

	return 0;
}

static struct ip_vs_service *ip_vs_genl_find_service(struct nlattr *nla)
{
	struct ip_vs_service_user_kern usvc;
	int ret;

	ret = ip_vs_genl_parse_service(&usvc, nla, 0);
	if (ret)
		return ERR_PTR(ret);

	if (usvc.fwmark)
		return __ip_vs_svc_fwm_get(usvc.af, usvc.fwmark);
	else
		return __ip_vs_service_get(usvc.af, usvc.protocol,
					   &usvc.addr, usvc.port);
}

static int ip_vs_genl_fill_dest(struct sk_buff *skb, struct ip_vs_dest *dest)
{
	u32 activeconns, inactconns, persistconns;
	int cpu;
	struct ip_vs_stats tmp_stats;
	struct nlattr *nl_dest;
	struct ip_vs_dest *per_dest;
	struct ip_vs_service *svc;

	nl_dest = nla_nest_start(skb, IPVS_CMD_ATTR_DEST);
	if (!nl_dest)
		return -EMSGSIZE;

	NLA_PUT(skb, IPVS_DEST_ATTR_ADDR, sizeof(dest->addr), &dest->addr);
	NLA_PUT_U16(skb, IPVS_DEST_ATTR_PORT, dest->port);

	NLA_PUT_U32(skb, IPVS_DEST_ATTR_FWD_METHOD,
		    atomic_read(&dest->conn_flags) & IP_VS_CONN_F_FWD_MASK);
	NLA_PUT_U32(skb, IPVS_DEST_ATTR_WEIGHT, atomic_read(&dest->weight));
	NLA_PUT_U32(skb, IPVS_DEST_ATTR_U_THRESH, dest->u_threshold);
	NLA_PUT_U32(skb, IPVS_DEST_ATTR_L_THRESH, dest->l_threshold);

	activeconns = 0;
	inactconns = 0;
	persistconns = 0;
	memset((void*)(&tmp_stats), 0, sizeof(struct ip_vs_stats));
	svc = dest->svc->svc0;
	for_each_possible_cpu(cpu) {
		per_dest = ip_vs_lookup_dest(svc, &dest->addr, dest->port);
		if(per_dest == NULL) {
			IP_VS_ERR_RL("%s():dest doesn't exist on cpu%d\n",
					__func__, cpu);
			goto nla_put_failure;
		}

		activeconns += atomic_read(&per_dest->activeconns);
		inactconns += atomic_read(&per_dest->inactconns);
		persistconns += atomic_read(&per_dest->persistconns);

		tmp_stats.conns += per_dest->stats.conns;
		tmp_stats.inpkts += per_dest->stats.inpkts;
		tmp_stats.outpkts += per_dest->stats.outpkts;
		tmp_stats.inbytes += per_dest->stats.inbytes;
		tmp_stats.outbytes += per_dest->stats.outbytes;

		svc++;
	}

	NLA_PUT_U32(skb, IPVS_DEST_ATTR_ACTIVE_CONNS, activeconns);
	NLA_PUT_U32(skb, IPVS_DEST_ATTR_INACT_CONNS, inactconns);
	NLA_PUT_U32(skb, IPVS_DEST_ATTR_PERSIST_CONNS, persistconns);

	if (ip_vs_genl_fill_stats(skb, IPVS_DEST_ATTR_STATS, &tmp_stats))
		goto nla_put_failure;

	nla_nest_end(skb, nl_dest);

	return 0;

      nla_put_failure:
	nla_nest_cancel(skb, nl_dest);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_dest(struct sk_buff *skb, struct ip_vs_dest *dest,
				struct netlink_callback *cb)
{
	void *hdr;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq,
			  &ip_vs_genl_family, NLM_F_MULTI, IPVS_CMD_NEW_DEST);
	if (!hdr)
		return -EMSGSIZE;

	if (ip_vs_genl_fill_dest(skb, dest) < 0)
		goto nla_put_failure;

	return genlmsg_end(skb, hdr);

      nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_dests(struct sk_buff *skb,
				 struct netlink_callback *cb)
{
	int idx = 0;
	int start = cb->args[0];
	struct ip_vs_service *svc;
	struct ip_vs_dest *dest;
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];

	mutex_lock(&__ip_vs_mutex);

	/* Try to find the service for which to dump destinations */
	if (nlmsg_parse(cb->nlh, GENL_HDRLEN, attrs,
			IPVS_CMD_ATTR_MAX, ip_vs_cmd_policy))
		goto out_err;

	svc = ip_vs_genl_find_service(attrs[IPVS_CMD_ATTR_SERVICE]);
	if (IS_ERR(svc) || svc == NULL)
		goto out_err;

	/* Dump the destinations */
	list_for_each_entry(dest, &svc->destinations, n_list) {
		if (++idx <= start)
			continue;
		if (ip_vs_genl_dump_dest(skb, dest, cb) < 0) {
			idx--;
			goto nla_put_failure;
		}
	}

      nla_put_failure:
	cb->args[0] = idx;
//	ip_vs_service_put(svc);

      out_err:
	mutex_unlock(&__ip_vs_mutex);

	return skb->len;
}

static int ip_vs_genl_fill_laddr(struct sk_buff *skb, struct ip_vs_laddr *laddr)
{
	struct nlattr *nl_laddr;

	nl_laddr = nla_nest_start(skb, IPVS_CMD_ATTR_LADDR);
	if (!nl_laddr)
		return -EMSGSIZE;

	NLA_PUT(skb, IPVS_LADDR_ATTR_ADDR, sizeof(laddr->addr), &laddr->addr);
	NLA_PUT_U64(skb, IPVS_LADDR_ATTR_PORT_CONFLICT,
		    atomic64_read(&laddr->port_conflict));
	NLA_PUT_U32(skb, IPVS_LADDR_ATTR_CONN_COUNTS,
		    atomic_read(&laddr->conn_counts));

	nla_nest_end(skb, nl_laddr);

	return 0;

      nla_put_failure:
	nla_nest_cancel(skb, nl_laddr);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_laddr(struct sk_buff *skb, struct ip_vs_laddr *laddr,
				 struct netlink_callback *cb)
{
	void *hdr;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq,
			  &ip_vs_genl_family, NLM_F_MULTI, IPVS_CMD_NEW_LADDR);
	if (!hdr)
		return -EMSGSIZE;

	if (ip_vs_genl_fill_laddr(skb, laddr) < 0)
		goto nla_put_failure;

	return genlmsg_end(skb, hdr);

      nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_laddrs(struct sk_buff *skb,
				  struct netlink_callback *cb)
{
	int idx = 0;
	int cpu;
	int start = cb->args[0];
	struct ip_vs_service *svc;
	struct ip_vs_service *svc_per;
	struct ip_vs_laddr *laddr;
	struct nlattr *attrs[IPVS_CMD_ATTR_MAX + 1];

	mutex_lock(&__ip_vs_mutex);

	/* Try to find the service for which to dump destinations */
	if (nlmsg_parse(cb->nlh, GENL_HDRLEN, attrs,
			IPVS_CMD_ATTR_MAX, ip_vs_cmd_policy))
		goto out_err;

	svc = ip_vs_genl_find_service(attrs[IPVS_CMD_ATTR_SERVICE]);
	if (IS_ERR(svc) || svc == NULL)
		goto out_err;

	IP_VS_DBG_BUF(0, "vip %s:%d get local address \n",
		      IP_VS_DBG_ADDR(svc->af, &svc->addr), ntohs(svc->port));

	svc_per = svc->svc0;
	for_each_online_cpu(cpu){
		/* Dump the destinations */
		list_for_each_entry(laddr, &svc_per->laddr_list, n_list) {
			if (++idx <= start)
				continue;

			if (ip_vs_genl_dump_laddr(skb, laddr, cb) < 0) {
				idx--;
				goto nla_put_failure;
			}
		}
		svc_per++;
	}
      nla_put_failure:
	cb->args[0] = idx;
	//ip_vs_service_put(svc);

      out_err:
	mutex_unlock(&__ip_vs_mutex);
	return skb->len;
}

static int ip_vs_genl_parse_laddr(struct ip_vs_laddr_user_kern *uladdr,
				  struct nlattr *nla, int full_entry)
{
	struct nlattr *attrs[IPVS_LADDR_ATTR_MAX + 1];
	struct nlattr *nla_addr;

	/* Parse mandatory identifying destination fields first */
	if (nla == NULL ||
	    nla_parse_nested(attrs, IPVS_LADDR_ATTR_MAX, nla,
			     ip_vs_laddr_policy))
		return -EINVAL;

	nla_addr = attrs[IPVS_LADDR_ATTR_ADDR];
	if (!nla_addr)
		return -EINVAL;

	memset(uladdr, 0, sizeof(*uladdr));
	nla_memcpy(&uladdr->addr, nla_addr, sizeof(uladdr->addr));

	return 0;
}

static int ip_vs_genl_parse_dest(struct ip_vs_dest_user_kern *udest,
				 struct nlattr *nla, int full_entry)
{
	struct nlattr *attrs[IPVS_DEST_ATTR_MAX + 1];
	struct nlattr *nla_addr, *nla_port;

	/* Parse mandatory identifying destination fields first */
	if (nla == NULL ||
	    nla_parse_nested(attrs, IPVS_DEST_ATTR_MAX, nla, ip_vs_dest_policy))
		return -EINVAL;

	nla_addr = attrs[IPVS_DEST_ATTR_ADDR];
	nla_port = attrs[IPVS_DEST_ATTR_PORT];

	if (!(nla_addr && nla_port))
		return -EINVAL;

	memset(udest, 0, sizeof(*udest));

	nla_memcpy(&udest->addr, nla_addr, sizeof(udest->addr));
	udest->port = nla_get_u16(nla_port);

	/* If a full entry was requested, check for the additional fields */
	if (full_entry) {
		struct nlattr *nla_fwd, *nla_weight, *nla_u_thresh,
		    *nla_l_thresh;

		nla_fwd = attrs[IPVS_DEST_ATTR_FWD_METHOD];
		nla_weight = attrs[IPVS_DEST_ATTR_WEIGHT];
		nla_u_thresh = attrs[IPVS_DEST_ATTR_U_THRESH];
		nla_l_thresh = attrs[IPVS_DEST_ATTR_L_THRESH];

		if (!(nla_fwd && nla_weight && nla_u_thresh && nla_l_thresh))
			return -EINVAL;

		udest->conn_flags = nla_get_u32(nla_fwd)
		    & IP_VS_CONN_F_FWD_MASK;
		udest->weight = nla_get_u32(nla_weight);
		udest->u_threshold = nla_get_u32(nla_u_thresh);
		udest->l_threshold = nla_get_u32(nla_l_thresh);
	}

	return 0;
}

static int ip_vs_genl_fill_daemon(struct sk_buff *skb, __be32 state,
				  const char *mcast_ifn, __be32 syncid)
{
	struct nlattr *nl_daemon;

	nl_daemon = nla_nest_start(skb, IPVS_CMD_ATTR_DAEMON);
	if (!nl_daemon)
		return -EMSGSIZE;

	NLA_PUT_U32(skb, IPVS_DAEMON_ATTR_STATE, state);
	NLA_PUT_STRING(skb, IPVS_DAEMON_ATTR_MCAST_IFN, mcast_ifn);
	NLA_PUT_U32(skb, IPVS_DAEMON_ATTR_SYNC_ID, syncid);

	nla_nest_end(skb, nl_daemon);

	return 0;

      nla_put_failure:
	nla_nest_cancel(skb, nl_daemon);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_daemon(struct sk_buff *skb, __be32 state,
				  const char *mcast_ifn, __be32 syncid,
				  struct netlink_callback *cb)
{
	void *hdr;
	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq,
			  &ip_vs_genl_family, NLM_F_MULTI, IPVS_CMD_NEW_DAEMON);
	if (!hdr)
		return -EMSGSIZE;

	if (ip_vs_genl_fill_daemon(skb, state, mcast_ifn, syncid))
		goto nla_put_failure;

	return genlmsg_end(skb, hdr);

      nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ip_vs_genl_dump_daemons(struct sk_buff *skb,
				   struct netlink_callback *cb)
{
	mutex_lock(&__ip_vs_mutex);
	if ((ip_vs_sync_state & IP_VS_STATE_MASTER) && !cb->args[0]) {
		if (ip_vs_genl_dump_daemon(skb, IP_VS_STATE_MASTER,
					   ip_vs_master_mcast_ifn,
					   ip_vs_master_syncid, cb) < 0)
			goto nla_put_failure;

		cb->args[0] = 1;
	}

	if ((ip_vs_sync_state & IP_VS_STATE_BACKUP) && !cb->args[1]) {
		if (ip_vs_genl_dump_daemon(skb, IP_VS_STATE_BACKUP,
					   ip_vs_backup_mcast_ifn,
					   ip_vs_backup_syncid, cb) < 0)
			goto nla_put_failure;

		cb->args[1] = 1;
	}

      nla_put_failure:
	mutex_unlock(&__ip_vs_mutex);

	return skb->len;
}

static int ip_vs_genl_new_daemon(struct nlattr **attrs)
{
	if (!(attrs[IPVS_DAEMON_ATTR_STATE] &&
	      attrs[IPVS_DAEMON_ATTR_MCAST_IFN] &&
	      attrs[IPVS_DAEMON_ATTR_SYNC_ID]))
		return -EINVAL;

	return start_sync_thread(nla_get_u32(attrs[IPVS_DAEMON_ATTR_STATE]),
				 nla_data(attrs[IPVS_DAEMON_ATTR_MCAST_IFN]),
				 nla_get_u32(attrs[IPVS_DAEMON_ATTR_SYNC_ID]));
}

static int ip_vs_genl_del_daemon(struct nlattr **attrs)
{
	if (!attrs[IPVS_DAEMON_ATTR_STATE])
		return -EINVAL;

	return stop_sync_thread(nla_get_u32(attrs[IPVS_DAEMON_ATTR_STATE]));
}

static int ip_vs_genl_set_config(struct nlattr **attrs)
{
	struct ip_vs_timeout_user t;

	__ip_vs_get_timeouts(&t);

	if (attrs[IPVS_CMD_ATTR_TIMEOUT_TCP])
		t.tcp_timeout = nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_TCP]);

	if (attrs[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN])
		t.tcp_fin_timeout =
		    nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN]);

	if (attrs[IPVS_CMD_ATTR_TIMEOUT_UDP])
		t.udp_timeout = nla_get_u32(attrs[IPVS_CMD_ATTR_TIMEOUT_UDP]);

	return ip_vs_set_timeout(&t);
}

static int ip_vs_genl_set_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct ip_vs_service *svc = NULL;
	struct ip_vs_service_user_kern usvc;
	struct ip_vs_dest_user_kern udest;
	struct ip_vs_laddr_user_kern uladdr;

	int ret = 0, cmd;
	int need_full_svc = 0, need_full_dest = 0;

	cmd = info->genlhdr->cmd;

	mutex_lock(&__ip_vs_mutex);

	if (cmd == IPVS_CMD_FLUSH) {
		ret = ip_vs_flush();
		goto out;
	} else if (cmd == IPVS_CMD_SET_CONFIG) {
		ret = ip_vs_genl_set_config(info->attrs);
		goto out;
	} else if (cmd == IPVS_CMD_NEW_DAEMON || cmd == IPVS_CMD_DEL_DAEMON) {

		struct nlattr *daemon_attrs[IPVS_DAEMON_ATTR_MAX + 1];

		if (!info->attrs[IPVS_CMD_ATTR_DAEMON] ||
		    nla_parse_nested(daemon_attrs, IPVS_DAEMON_ATTR_MAX,
				     info->attrs[IPVS_CMD_ATTR_DAEMON],
				     ip_vs_daemon_policy)) {
			ret = -EINVAL;
			goto out;
		}

		if (cmd == IPVS_CMD_NEW_DAEMON)
			ret = ip_vs_genl_new_daemon(daemon_attrs);
		else
			ret = ip_vs_genl_del_daemon(daemon_attrs);
		goto out;
	} else if (cmd == IPVS_CMD_ZERO && !info->attrs[IPVS_CMD_ATTR_SERVICE]) {
		ret = -EACCES;	//ip_vs_zero_all();
		goto out;
	}

	/* All following commands require a service argument, so check if we
	 * received a valid one. We need a full service specification when
	 * adding / editing a service. Only identifying members otherwise. */
	if (cmd == IPVS_CMD_NEW_SERVICE || cmd == IPVS_CMD_SET_SERVICE)
		need_full_svc = 1;

	ret = ip_vs_genl_parse_service(&usvc,
				       info->attrs[IPVS_CMD_ATTR_SERVICE],
				       need_full_svc);
	if (ret)
		goto out;

	/* Lookup the exact service by <protocol, addr, port> or fwmark */
	if (usvc.fwmark == 0)
		svc = __ip_vs_service_get(usvc.af, usvc.protocol,
					  &usvc.addr, usvc.port);
	else
		svc = __ip_vs_svc_fwm_get(usvc.af, usvc.fwmark);

	/* Unless we're adding a new service, the service must already exist */
	if ((cmd != IPVS_CMD_NEW_SERVICE) && (svc == NULL)) {
		ret = -ESRCH;
		goto out;
	}

	/* Destination commands require a valid destination argument. For
	 * adding / editing a destination, we need a full destination
	 * specification. */
	if (cmd == IPVS_CMD_NEW_DEST || cmd == IPVS_CMD_SET_DEST ||
	    cmd == IPVS_CMD_DEL_DEST) {
		if (cmd != IPVS_CMD_DEL_DEST)
			need_full_dest = 1;

		ret = ip_vs_genl_parse_dest(&udest,
					    info->attrs[IPVS_CMD_ATTR_DEST],
					    need_full_dest);
		if (ret)
			goto out;
	}

	if (cmd == IPVS_CMD_NEW_LADDR || cmd == IPVS_CMD_DEL_LADDR) {
		ret = ip_vs_genl_parse_laddr(&uladdr,
					     info->attrs[IPVS_CMD_ATTR_LADDR],
					     1);
		if (ret)
			goto out;
	}

	switch (cmd) {
	case IPVS_CMD_NEW_SERVICE:
		if (svc == NULL)
			ret = ip_vs_add_service(&usvc, &svc);
		else
			ret = -EEXIST;
		break;
	case IPVS_CMD_SET_SERVICE:
		ret = ip_vs_edit_service(svc, &usvc);
		break;
	case IPVS_CMD_DEL_SERVICE:
		ret = ip_vs_del_service(svc);
		break;
	case IPVS_CMD_NEW_DEST:
		ret = ip_vs_add_dest(svc, &udest);
		break;
	case IPVS_CMD_SET_DEST:
		ret = ip_vs_edit_dest(svc, &udest);
		break;
	case IPVS_CMD_DEL_DEST:
		ret = ip_vs_del_dest(svc, &udest);
		break;
	case IPVS_CMD_ZERO:
		ret = -EACCES;	//ip_vs_zero_service(svc);
		break;
	case IPVS_CMD_NEW_LADDR:
		ret = ip_vs_add_laddr(svc, &uladdr);
		break;
	case IPVS_CMD_DEL_LADDR:
		ret = ip_vs_del_laddr(svc, &uladdr);
		break;
	default:
		ret = -EINVAL;
	}

      out:
//	if (svc)
//		ip_vs_service_put(svc);
	mutex_unlock(&__ip_vs_mutex);

	return ret;
}

static int ip_vs_genl_get_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *reply;
	int ret, cmd, reply_cmd;

	cmd = info->genlhdr->cmd;

	if (cmd == IPVS_CMD_GET_SERVICE)
		reply_cmd = IPVS_CMD_NEW_SERVICE;
	else if (cmd == IPVS_CMD_GET_INFO)
		reply_cmd = IPVS_CMD_SET_INFO;
	else if (cmd == IPVS_CMD_GET_CONFIG)
		reply_cmd = IPVS_CMD_SET_CONFIG;
	else {
		pr_err("unknown Generic Netlink command\n");
		return -EINVAL;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	mutex_lock(&__ip_vs_mutex);

	reply = genlmsg_put_reply(msg, info, &ip_vs_genl_family, 0, reply_cmd);
	if (reply == NULL)
		goto nla_put_failure;

	switch (cmd) {
	case IPVS_CMD_GET_SERVICE:
		{
			struct ip_vs_service *svc;

			svc =
			    ip_vs_genl_find_service(info->
						    attrs
						    [IPVS_CMD_ATTR_SERVICE]);
			if (IS_ERR(svc)) {
				ret = PTR_ERR(svc);
				goto out_err;
			} else if (svc) {
				ret = ip_vs_genl_fill_service(msg, svc);
			//	ip_vs_service_put(svc);
				if (ret)
					goto nla_put_failure;
			} else {
				ret = -ESRCH;
				goto out_err;
			}

			break;
		}

	case IPVS_CMD_GET_CONFIG:
		{
			struct ip_vs_timeout_user t;

			__ip_vs_get_timeouts(&t);
#ifdef CONFIG_IP_VS_PROTO_TCP
			NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_TCP,
				    t.tcp_timeout);
			NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_TCP_FIN,
				    t.tcp_fin_timeout);
#endif
#ifdef CONFIG_IP_VS_PROTO_UDP
			NLA_PUT_U32(msg, IPVS_CMD_ATTR_TIMEOUT_UDP,
				    t.udp_timeout);
#endif

			break;
		}

	case IPVS_CMD_GET_INFO:
		NLA_PUT_U32(msg, IPVS_INFO_ATTR_VERSION, IP_VS_VERSION_CODE);
		NLA_PUT_U32(msg, IPVS_INFO_ATTR_CONN_TAB_SIZE,
			    IP_VS_CONN_TAB_SIZE);
		break;
	}

	genlmsg_end(msg, reply);
	ret = genlmsg_reply(msg, info);
	goto out;

      nla_put_failure:
	pr_err("not enough space in Netlink message\n");
	ret = -EMSGSIZE;

      out_err:
	nlmsg_free(msg);
      out:
	mutex_unlock(&__ip_vs_mutex);

	return ret;
}

static struct genl_ops ip_vs_genl_ops[] __read_mostly = {
	{
	 .cmd = IPVS_CMD_NEW_SERVICE,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_SET_SERVICE,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_DEL_SERVICE,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_GET_SERVICE,
	 .flags = GENL_ADMIN_PERM,
	 .doit = ip_vs_genl_get_cmd,
	 .dumpit = ip_vs_genl_dump_services,
	 .policy = ip_vs_cmd_policy,
	 },
	{
	 .cmd = IPVS_CMD_NEW_DEST,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_SET_DEST,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_DEL_DEST,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_GET_DEST,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .dumpit = ip_vs_genl_dump_dests,
	 },
	{
	 .cmd = IPVS_CMD_NEW_DAEMON,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_DEL_DAEMON,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_GET_DAEMON,
	 .flags = GENL_ADMIN_PERM,
	 .dumpit = ip_vs_genl_dump_daemons,
	 },
	{
	 .cmd = IPVS_CMD_SET_CONFIG,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_GET_CONFIG,
	 .flags = GENL_ADMIN_PERM,
	 .doit = ip_vs_genl_get_cmd,
	 },
	{
	 .cmd = IPVS_CMD_GET_INFO,
	 .flags = GENL_ADMIN_PERM,
	 .doit = ip_vs_genl_get_cmd,
	 },
	{
	 .cmd = IPVS_CMD_ZERO,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_FLUSH,
	 .flags = GENL_ADMIN_PERM,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_NEW_LADDR,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_DEL_LADDR,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .doit = ip_vs_genl_set_cmd,
	 },
	{
	 .cmd = IPVS_CMD_GET_LADDR,
	 .flags = GENL_ADMIN_PERM,
	 .policy = ip_vs_cmd_policy,
	 .dumpit = ip_vs_genl_dump_laddrs,
	 },
};

static int __init ip_vs_genl_register(void)
{
	return genl_register_family_with_ops(&ip_vs_genl_family,
					     ip_vs_genl_ops,
					     ARRAY_SIZE(ip_vs_genl_ops));
}

static void ip_vs_genl_unregister(void)
{
	genl_unregister_family(&ip_vs_genl_family);
}

static void free_svc_tab(void)
{
	int cpu;
	struct list_head *ip_vs_svc_tab;
	struct list_head *ip_vs_svc_fwm_tab;

	for_each_possible_cpu(cpu) {
		ip_vs_svc_tab = per_cpu(ip_vs_svc_tab_percpu, cpu);
		ip_vs_svc_fwm_tab = per_cpu(ip_vs_svc_fwm_tab_percpu, cpu);

		/* free NULL is OK  */
		kfree(ip_vs_svc_tab);
		kfree(ip_vs_svc_fwm_tab);
	}
}

static int __init alloc_svc_tab(void)
{
	int cpu;
	struct list_head *tmp;

	/* clear percpu svc_tab */
	for_each_possible_cpu(cpu) {
		per_cpu(ip_vs_svc_tab_percpu, cpu) = NULL;
		per_cpu(ip_vs_svc_fwm_tab_percpu, cpu) = NULL;
	}

	for_each_possible_cpu(cpu) {
		tmp = kmalloc(sizeof(struct list_head) *
				IP_VS_SVC_TAB_SIZE, GFP_ATOMIC);
		if (!tmp) {
			pr_err("cannot allocate svc_tab.\n");
			return -ENOMEM;
		}
		per_cpu(ip_vs_svc_tab_percpu, cpu) = tmp;

		/* svc tab for fwmark */
		tmp = kmalloc(sizeof(struct list_head) *
				IP_VS_SVC_TAB_SIZE, GFP_ATOMIC);
		if (!tmp) {
			pr_err("cannot allocate svc_tab.\n");
			return -ENOMEM;
		}
		per_cpu(ip_vs_svc_fwm_tab_percpu, cpu) = tmp;
	}

	return 0;
}

/* End of Generic Netlink interface definitions */

static int process_laddr_rps(struct sk_buff *skb)
{
	struct iphdr *iph = (struct iphdr *)skb->data;
	struct laddr_cpu_t *laddr_cpu;
	int cpu = -1;

	rcu_read_lock();
	laddr_cpu = lookup_laddr_cpu(iph->daddr);
	if (laddr_cpu)
		cpu = laddr_cpu->cpuid;
	rcu_read_unlock();

	return cpu;
}

static struct netif_rps_entry tcp_laddr_rps_entry = {
	.proto = IPPROTO_TCP,
	.flags = RPS_CONTINUE,
	.rps_process = process_laddr_rps,
	.rps_init = NULL,
	.rps_uninit = NULL,
	.list = LIST_HEAD_INIT(tcp_laddr_rps_entry.list),
};

static struct netif_rps_entry udp_laddr_rps_entry = {
	.proto = IPPROTO_UDP,
	.flags = RPS_STOP,
	.rps_process = process_laddr_rps,
	.rps_init = NULL,
	.rps_uninit = NULL,
	.list = LIST_HEAD_INIT(udp_laddr_rps_entry.list),
};

int __init ip_vs_control_init(void)
{
	int ret;
	int idx;
	int cpu;

	EnterFunction(2);

	ret = nf_register_sockopt(&ip_vs_sockopts);
	if (ret) {
		pr_err("cannot register sockopt.\n");
		goto out_err;
	}

	ret = ip_vs_genl_register();
	if (ret) {
		pr_err("cannot register Generic Netlink interface.\n");
		goto cleanup_sockopt;
	}

	if (NULL == (ip_vs_esmib = alloc_percpu(struct ip_vs_estats_mib))) {
		pr_err("cannot allocate percpu struct ip_vs_estats_mib.\n");
		ret = 1;
		goto cleanup_genl;
	}

	ret = ip_vs_new_stats(&(ip_vs_stats));
	if(ret) {
		pr_err("cannot allocate percpu struct ip_vs_stats.\n");
		goto cleanup_percpu;
	}

	ret = alloc_svc_tab();
	if (ret) {
		goto cleanup_svctab;
	}

	proc_net_fops_create(&init_net, "ip_vs_ext_stats", 0, &ip_vs_estats_fops);
//	proc_net_fops_create(&init_net, "ip_vs", 0, &ip_vs_info_fops);
	proc_net_fops_create(&init_net, "ip_vs_stats", 0, &ip_vs_stats_fops);

	sysctl_header = register_sysctl_paths(net_vs_ctl_path, vs_vars);

	for_each_possible_cpu(cpu) {
		struct list_head *ip_vs_svc_tab;
		struct list_head *ip_vs_svc_fwm_tab;

		spin_lock_init(&per_cpu(ip_vs_svc_lock, cpu));
		ip_vs_svc_tab = per_cpu(ip_vs_svc_tab_percpu, cpu);
		ip_vs_svc_fwm_tab = per_cpu(ip_vs_svc_fwm_tab_percpu, cpu);

		/* Initialize ip_vs_svc_table, ip_vs_svc_fwm_table */
		for (idx = 0; idx < IP_VS_SVC_TAB_SIZE; idx++) {
			INIT_LIST_HEAD(ip_vs_svc_tab + idx);
			INIT_LIST_HEAD(ip_vs_svc_fwm_tab + idx);
		}

		INIT_LIST_HEAD(&per_cpu(ip_vs_dest_trash_percpu, cpu));
	}

	for (idx = 0; idx < LADDR_CPU_HASH_SIZE; ++idx)
		INIT_HLIST_HEAD(&laddr_cpu_map[idx]);

	rps_register(&tcp_laddr_rps_entry);
	rps_register(&udp_laddr_rps_entry);

	LeaveFunction(2);
	return 0;

cleanup_svctab:
	free_svc_tab();
cleanup_percpu:
	free_percpu(ip_vs_esmib);
cleanup_genl:
	ip_vs_genl_unregister();
cleanup_sockopt:
	nf_unregister_sockopt(&ip_vs_sockopts);
out_err:
	return ret;
}

void ip_vs_control_cleanup(void)
{
	EnterFunction(2);
	rps_unregister(&udp_laddr_rps_entry);
	rps_unregister(&tcp_laddr_rps_entry);
	ip_vs_trash_cleanup();
	ip_vs_del_stats(ip_vs_stats);
	unregister_sysctl_table(sysctl_header);
	proc_net_remove(&init_net, "ip_vs_stats");
//	proc_net_remove(&init_net, "ip_vs");
	proc_net_remove(&init_net, "ip_vs_ext_stats");
	free_percpu(ip_vs_esmib);
	ip_vs_genl_unregister();
	nf_unregister_sockopt(&ip_vs_sockopts);
	free_svc_tab();
	/* Wait all rcu callback to complete */
	rcu_barrier();
	LeaveFunction(2);
}
