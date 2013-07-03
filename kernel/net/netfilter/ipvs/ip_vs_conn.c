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
 * and others. Many code here is taken from IP MASQ code of kernel 2.2.
 *
 * Changes:
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>	/* for proc_net_* */
#include <linux/seq_file.h>
#include <linux/jhash.h>
#include <linux/random.h>

#include <net/net_namespace.h>
#include <net/ip_vs.h>

/*
 *  Connection hash table: for input and output packets lookups of IPVS
 */
static struct list_head *ip_vs_conn_tab;

/*  SLAB cache for IPVS connections */
static struct kmem_cache *ip_vs_conn_cachep __read_mostly;

/*  counter for current IPVS connections */
static atomic_t ip_vs_conn_count = ATOMIC_INIT(0);

/*  counter for no client port connections */
static atomic_t ip_vs_conn_no_cport_cnt = ATOMIC_INIT(0);

/* random value for IPVS connection hash */
static unsigned int ip_vs_conn_rnd;

/*
 *  Fine locking granularity for big connection hash table
 */
#define CT_LOCKARRAY_BITS  8
#define CT_LOCKARRAY_SIZE  (1<<CT_LOCKARRAY_BITS)
#define CT_LOCKARRAY_MASK  (CT_LOCKARRAY_SIZE-1)

struct ip_vs_aligned_lock {
	rwlock_t l;
} __attribute__ ((__aligned__(SMP_CACHE_BYTES)));

/* lock array for conn table */
static struct ip_vs_aligned_lock
    __ip_vs_conntbl_lock_array[CT_LOCKARRAY_SIZE] __cacheline_aligned;

static inline void ct_read_lock(unsigned key)
{
	read_lock(&__ip_vs_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_read_unlock(unsigned key)
{
	read_unlock(&__ip_vs_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_lock(unsigned key)
{
	write_lock(&__ip_vs_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_unlock(unsigned key)
{
	write_unlock(&__ip_vs_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_read_lock_bh(unsigned key)
{
	read_lock_bh(&__ip_vs_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_read_unlock_bh(unsigned key)
{
	read_unlock_bh(&__ip_vs_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_lock_bh(unsigned key)
{
	write_lock_bh(&__ip_vs_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_unlock_bh(unsigned key)
{
	write_unlock_bh(&__ip_vs_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

/*
 *	Returns hash value for IPVS connection entry
 */
static unsigned int ip_vs_conn_hashkey(int af, const union nf_inet_addr *s_addr,
				       __be16 s_port,
				       const union nf_inet_addr *d_addr,
				       __be16 d_port)
{
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		return jhash_3words(jhash(s_addr, 16, ip_vs_conn_rnd),
				    jhash(d_addr, 16, ip_vs_conn_rnd),
				    ((__force u32) s_port) << 16 | (__force u32)
				    d_port, ip_vs_conn_rnd)
		    & IP_VS_CONN_TAB_MASK;
#endif
	return jhash_3words((__force u32) s_addr->ip, (__force u32) d_addr->ip,
			    ((__force u32) s_port) << 16 | (__force u32) d_port,
			    ip_vs_conn_rnd)
	    & IP_VS_CONN_TAB_MASK;
}

/*
 * Lock two buckets of ip_vs_conn_tab
 */
static inline void ip_vs_conn_lock2(unsigned ihash, unsigned ohash)
{
	unsigned ilock, olock;

	ilock = ihash & CT_LOCKARRAY_MASK;
	olock = ohash & CT_LOCKARRAY_MASK;

	/* lock the conntab bucket */
	if (ilock < olock) {
		ct_write_lock(ihash);
		ct_write_lock(ohash);
	} else if (ilock > olock) {
		ct_write_lock(ohash);
		ct_write_lock(ihash);
	} else {
		ct_write_lock(ihash);
	}
}

/*
 * Unlock two buckets of ip_vs_conn_tab
 */
static inline void ip_vs_conn_unlock2(unsigned ihash, unsigned ohash)
{
	unsigned ilock, olock;

	ilock = ihash & CT_LOCKARRAY_MASK;
	olock = ohash & CT_LOCKARRAY_MASK;

	/* lock the conntab bucket */
	if (ilock < olock) {
		ct_write_unlock(ohash);
		ct_write_unlock(ihash);
	} else if (ilock > olock) {
		ct_write_unlock(ihash);
		ct_write_unlock(ohash);
	} else {
		ct_write_unlock(ihash);
	}
}

/*
 *      Hashed ip_vs_conn into ip_vs_conn_tab
 *	returns bool success.
 */

static inline int __ip_vs_conn_hash(struct ip_vs_conn *cp, unsigned ihash,
				    unsigned ohash)
{
	struct ip_vs_conn_idx *ci_idx, *co_idx;
	int ret;

	if (!(cp->flags & IP_VS_CONN_F_HASHED)) {
		ci_idx = cp->in_idx;
		co_idx = cp->out_idx;
		list_add(&ci_idx->c_list, &ip_vs_conn_tab[ihash]);
		list_add(&co_idx->c_list, &ip_vs_conn_tab[ohash]);
		cp->flags |= IP_VS_CONN_F_HASHED;
		atomic_inc(&cp->refcnt);
		ret = 1;
	} else {
		pr_err("%s(): request for already hashed, called from %pF\n",
		       __func__, __builtin_return_address(0));
		ret = 0;
	}

	return ret;
}

/*
 *	Hashed ip_vs_conn in two buckets of ip_vs_conn_tab
 *	by caddr/cport/vaddr/vport and raddr/rport/laddr/lport,
 *	returns bool success.
 */
static inline int ip_vs_conn_hash(struct ip_vs_conn *cp)
{
	unsigned ihash, ohash;
	int ret;

	if (cp->flags & IP_VS_CONN_F_ONE_PACKET)
		return 0;

	/*OUTside2INside: hashed by client address and port, virtual address and port */
	ihash =
	    ip_vs_conn_hashkey(cp->af, &cp->caddr, cp->cport, &cp->vaddr,
			       cp->vport);
	/*INside2OUTside: hashed by destination address and port, local address and port */
	ohash =
	    ip_vs_conn_hashkey(cp->af, &cp->daddr, cp->dport, &cp->laddr,
			       cp->lport);

	/* locked */
	ip_vs_conn_lock2(ihash, ohash);

	/* hashed */
	ret = __ip_vs_conn_hash(cp, ihash, ohash);

	/* unlocked */
	ip_vs_conn_unlock2(ihash, ohash);

	return ret;
}

/*
 *	UNhashes ip_vs_conn from ip_vs_conn_tab.
 *	cp->refcnt must be equal 2,
 *	returns bool success.
 */
static inline int ip_vs_conn_unhash(struct ip_vs_conn *cp)
{
	unsigned ihash, ohash;
	struct ip_vs_conn_idx *ci_idx, *co_idx;
	int ret;

	/* OUTside2INside: unhash it and decrease its reference counter */
	ihash =
	    ip_vs_conn_hashkey(cp->af, &cp->caddr, cp->cport, &cp->vaddr,
			       cp->vport);
	/* INside2OUTside: unhash it and decrease its reference counter */
	ohash =
	    ip_vs_conn_hashkey(cp->af, &cp->daddr, cp->dport, &cp->laddr,
			       cp->lport);

	/* locked */
	ip_vs_conn_lock2(ihash, ohash);

	/* unhashed */
	if ((cp->flags & IP_VS_CONN_F_HASHED)
	    && (atomic_read(&cp->refcnt) == 2)) {
		ci_idx = cp->in_idx;
		co_idx = cp->out_idx;
		list_del(&ci_idx->c_list);
		list_del(&co_idx->c_list);
		cp->flags &= ~IP_VS_CONN_F_HASHED;
		atomic_dec(&cp->refcnt);
		ret = 1;
	} else {
		ret = 0;
	}

	/* unlocked */
	ip_vs_conn_unlock2(ihash, ohash);

	return ret;
}

/*
 *  Gets ip_vs_conn associated with supplied parameters in the ip_vs_conn_tab.
 *  Return director: OUTside-to-INside or INside-to-OUTside in res_dir.
 *	s_addr, s_port: pkt source address (foreign host/realserver)
 *	d_addr, d_port: pkt dest address (virtual address/local address)
 */
static inline struct ip_vs_conn *__ip_vs_conn_get
    (int af, int protocol, const union nf_inet_addr *s_addr, __be16 s_port,
     const union nf_inet_addr *d_addr, __be16 d_port, int *res_dir) {
	unsigned hash;
	struct ip_vs_conn *cp;
	struct ip_vs_conn_idx *cidx;

	hash = ip_vs_conn_hashkey(af, s_addr, s_port, d_addr, d_port);

	ct_read_lock(hash);

	list_for_each_entry(cidx, &ip_vs_conn_tab[hash], c_list) {
		cp = cidx->cp;
		if (cidx->af == af &&
		    ip_vs_addr_equal(af, s_addr, &cidx->s_addr) &&
		    ip_vs_addr_equal(af, d_addr, &cidx->d_addr) &&
		    s_port == cidx->s_port && d_port == cidx->d_port &&
		    ((!s_port) ^ (!(cp->flags & IP_VS_CONN_F_NO_CPORT))) &&
		    protocol == cidx->protocol) {
			/* HIT */
			atomic_inc(&cp->refcnt);
			*res_dir = cidx->flags & IP_VS_CIDX_F_DIR_MASK;
			ct_read_unlock(hash);
			return cp;
		}
	}

	ct_read_unlock(hash);

	return NULL;
}

struct ip_vs_conn *ip_vs_conn_get
    (int af, int protocol, const union nf_inet_addr *s_addr, __be16 s_port,
     const union nf_inet_addr *d_addr, __be16 d_port, int *res_dir) {
	struct ip_vs_conn *cp;

	cp = __ip_vs_conn_get(af, protocol, s_addr, s_port, d_addr, d_port,
			      res_dir);
	if (!cp && atomic_read(&ip_vs_conn_no_cport_cnt))
		cp = __ip_vs_conn_get(af, protocol, s_addr, 0, d_addr, d_port,
				      res_dir);

	IP_VS_DBG_BUF(9, "lookup %s %s:%d->%s:%d %s\n",
		      ip_vs_proto_name(protocol),
		      IP_VS_DBG_ADDR(af, s_addr), ntohs(s_port),
		      IP_VS_DBG_ADDR(af, d_addr), ntohs(d_port),
		      cp ? "hit" : "not hit");

	return cp;
}

/* Get reference to connection template */
struct ip_vs_conn *ip_vs_ct_in_get
    (int af, int protocol, const union nf_inet_addr *s_addr, __be16 s_port,
     const union nf_inet_addr *d_addr, __be16 d_port) {
	unsigned hash;
	struct ip_vs_conn_idx *cidx;
	struct ip_vs_conn *cp;

	hash = ip_vs_conn_hashkey(af, s_addr, s_port, d_addr, d_port);

	ct_read_lock(hash);

	list_for_each_entry(cidx, &ip_vs_conn_tab[hash], c_list) {
		cp = cidx->cp;
		if (cidx->af == af &&
		    ip_vs_addr_equal(af, s_addr, &cidx->s_addr) &&
		    /* protocol should only be IPPROTO_IP if
		     * d_addr is a fwmark */
		    ip_vs_addr_equal(protocol == IPPROTO_IP ? AF_UNSPEC : af,
				     d_addr, &cidx->d_addr) &&
		    s_port == cidx->s_port && d_port == cidx->d_port &&
		    cp->flags & IP_VS_CONN_F_TEMPLATE &&
		    protocol == cidx->protocol) {
			/* HIT */
			atomic_inc(&cp->refcnt);
			goto out;
		}
	}
	cp = NULL;

      out:
	ct_read_unlock(hash);

	IP_VS_DBG_BUF(9, "template lookup %s %s:%d->%s:%d %s\n",
		      ip_vs_proto_name(protocol),
		      IP_VS_DBG_ADDR(af, s_addr), ntohs(s_port),
		      IP_VS_DBG_ADDR(af, d_addr), ntohs(d_port),
		      cp ? "hit" : "not hit");

	return cp;
}

/*
 *      Put back the conn and restart its timer with its timeout
 */
void ip_vs_conn_put(struct ip_vs_conn *cp)
{
	unsigned long timeout = cp->timeout;

	if (cp->flags & IP_VS_CONN_F_ONE_PACKET)
		timeout = 0;

	/* reset it expire in its timeout */
	mod_timer(&cp->timer, jiffies + timeout);

	__ip_vs_conn_put(cp);
}

/*
 *	Fill a no_client_port connection with a client port number
 */
void ip_vs_conn_fill_cport(struct ip_vs_conn *cp, __be16 cport)
{
	if (ip_vs_conn_unhash(cp)) {
		spin_lock(&cp->lock);
		if (cp->flags & IP_VS_CONN_F_NO_CPORT) {
			atomic_dec(&ip_vs_conn_no_cport_cnt);
			cp->flags &= ~IP_VS_CONN_F_NO_CPORT;
			cp->cport = cport;
		}
		spin_unlock(&cp->lock);

		/* hash on new dport */
		ip_vs_conn_hash(cp);
	}
}

/*
 *	Bind a connection entry with the corresponding packet_xmit.
 *	Called by ip_vs_conn_new.
 */
static inline void ip_vs_bind_xmit(struct ip_vs_conn *cp)
{
	switch (IP_VS_FWD_METHOD(cp)) {
	case IP_VS_CONN_F_MASQ:
		cp->packet_xmit = ip_vs_nat_xmit;
		break;

	case IP_VS_CONN_F_FULLNAT:
		cp->packet_xmit = ip_vs_fnat_xmit;
		break;

	case IP_VS_CONN_F_TUNNEL:
		cp->packet_xmit = ip_vs_tunnel_xmit;
		break;

	case IP_VS_CONN_F_DROUTE:
		cp->packet_xmit = ip_vs_dr_xmit;
		break;

	case IP_VS_CONN_F_LOCALNODE:
		cp->packet_xmit = ip_vs_null_xmit;
		break;

	case IP_VS_CONN_F_BYPASS:
		cp->packet_xmit = ip_vs_bypass_xmit;
		break;
	}
}

#ifdef CONFIG_IP_VS_IPV6
static inline void ip_vs_bind_xmit_v6(struct ip_vs_conn *cp)
{
	switch (IP_VS_FWD_METHOD(cp)) {
	case IP_VS_CONN_F_MASQ:
		cp->packet_xmit = ip_vs_nat_xmit_v6;
		break;

	case IP_VS_CONN_F_FULLNAT:
		cp->packet_xmit = ip_vs_fnat_xmit_v6;
		break;

	case IP_VS_CONN_F_TUNNEL:
		cp->packet_xmit = ip_vs_tunnel_xmit_v6;
		break;

	case IP_VS_CONN_F_DROUTE:
		cp->packet_xmit = ip_vs_dr_xmit_v6;
		break;

	case IP_VS_CONN_F_LOCALNODE:
		cp->packet_xmit = ip_vs_null_xmit;
		break;

	case IP_VS_CONN_F_BYPASS:
		cp->packet_xmit = ip_vs_bypass_xmit_v6;
		break;
	}
}
#endif

static inline int ip_vs_dest_totalconns(struct ip_vs_dest *dest)
{
	return atomic_read(&dest->activeconns)
	    + atomic_read(&dest->inactconns);
}

/*
 *	Bind a connection entry with a virtual service destination
 *	Called just after a new connection entry is created.
 */
static inline void
ip_vs_bind_dest(struct ip_vs_conn *cp, struct ip_vs_dest *dest)
{
	/* if dest is NULL, then return directly */
	if (!dest)
		return;

	/* Increase the refcnt counter of the dest */
	atomic_inc(&dest->refcnt);

	/* Bind with the destination and its corresponding transmitter */
	if ((cp->flags & IP_VS_CONN_F_SYNC) &&
	    (!(cp->flags & IP_VS_CONN_F_TEMPLATE)))
		/* if the connection is not template and is created
		 * by sync, preserve the activity flag.
		 */
		cp->flags |= atomic_read(&dest->conn_flags) &
		    (~IP_VS_CONN_F_INACTIVE);
	else
		cp->flags |= atomic_read(&dest->conn_flags);
	cp->dest = dest;

	IP_VS_DBG_BUF(7, "Bind-dest %s c:%s:%d v:%s:%d "
		      "d:%s:%d fwd:%c s:%u conn->flags:%X conn->refcnt:%d "
		      "dest->refcnt:%d\n",
		      ip_vs_proto_name(cp->protocol),
		      IP_VS_DBG_ADDR(cp->af, &cp->caddr), ntohs(cp->cport),
		      IP_VS_DBG_ADDR(cp->af, &cp->vaddr), ntohs(cp->vport),
		      IP_VS_DBG_ADDR(cp->af, &cp->daddr), ntohs(cp->dport),
		      ip_vs_fwd_tag(cp), cp->state,
		      cp->flags, atomic_read(&cp->refcnt),
		      atomic_read(&dest->refcnt));

	/* Update the connection counters */
	if (!(cp->flags & IP_VS_CONN_F_TEMPLATE)) {
		/* It is a normal connection, so increase the inactive
		   connection counter because it is in TCP SYNRECV
		   state (inactive) or other protocol inacive state */
		if ((cp->flags & IP_VS_CONN_F_SYNC) &&
		    (!(cp->flags & IP_VS_CONN_F_INACTIVE)))
			atomic_inc(&dest->activeconns);
		else
			atomic_inc(&dest->inactconns);
	} else {
		/* It is a persistent connection/template, so increase
		   the peristent connection counter */
		atomic_inc(&dest->persistconns);
	}

	if (dest->u_threshold != 0 &&
	    ip_vs_dest_totalconns(dest) >= dest->u_threshold)
		dest->flags |= IP_VS_DEST_F_OVERLOAD;
}

/*
 * Check if there is a destination for the connection, if so
 * bind the connection to the destination.
 */
struct ip_vs_dest *ip_vs_try_bind_dest(struct ip_vs_conn *cp)
{
	struct ip_vs_dest *dest;

	if ((cp) && (!cp->dest)) {
		dest = ip_vs_find_dest(cp->af, &cp->daddr, cp->dport,
				       &cp->vaddr, cp->vport, cp->protocol);
		ip_vs_bind_dest(cp, dest);
		return dest;
	} else
		return NULL;
}

/*
 *	Unbind a connection entry with its VS destination
 *	Called by the ip_vs_conn_expire function.
 */
static inline void ip_vs_unbind_dest(struct ip_vs_conn *cp)
{
	struct ip_vs_dest *dest = cp->dest;

	if (!dest)
		return;

	IP_VS_DBG_BUF(7, "Unbind-dest %s c:%s:%d v:%s:%d "
		      "d:%s:%d fwd:%c s:%u conn->flags:%X conn->refcnt:%d "
		      "dest->refcnt:%d\n",
		      ip_vs_proto_name(cp->protocol),
		      IP_VS_DBG_ADDR(cp->af, &cp->caddr), ntohs(cp->cport),
		      IP_VS_DBG_ADDR(cp->af, &cp->vaddr), ntohs(cp->vport),
		      IP_VS_DBG_ADDR(cp->af, &cp->daddr), ntohs(cp->dport),
		      ip_vs_fwd_tag(cp), cp->state,
		      cp->flags, atomic_read(&cp->refcnt),
		      atomic_read(&dest->refcnt));

	/* Update the connection counters */
	if (!(cp->flags & IP_VS_CONN_F_TEMPLATE)) {
		/* It is a normal connection, so decrease the inactconns
		   or activeconns counter */
		if (cp->flags & IP_VS_CONN_F_INACTIVE) {
			atomic_dec(&dest->inactconns);
		} else {
			atomic_dec(&dest->activeconns);
		}
	} else {
		/* It is a persistent connection/template, so decrease
		   the peristent connection counter */
		atomic_dec(&dest->persistconns);
	}

	if (dest->l_threshold != 0) {
		if (ip_vs_dest_totalconns(dest) < dest->l_threshold)
			dest->flags &= ~IP_VS_DEST_F_OVERLOAD;
	} else if (dest->u_threshold != 0) {
		if (ip_vs_dest_totalconns(dest) * 4 < dest->u_threshold * 3)
			dest->flags &= ~IP_VS_DEST_F_OVERLOAD;
	} else {
		if (dest->flags & IP_VS_DEST_F_OVERLOAD)
			dest->flags &= ~IP_VS_DEST_F_OVERLOAD;
	}

	/*
	 * Simply decrease the refcnt of the dest, because the
	 * dest will be either in service's destination list
	 * or in the trash.
	 */
	atomic_dec(&dest->refcnt);
}

/*
 * get a local address from given virtual service
 */
static struct ip_vs_laddr *ip_vs_get_laddr(struct ip_vs_service *svc)
{
	struct ip_vs_laddr *local;
	struct list_head *p, *q;

	write_lock(&svc->laddr_lock);
	p = svc->curr_laddr;
	p = p->next;
	q = p;
	do {
		/* skip list head */
		if (q == &svc->laddr_list) {
			q = q->next;
			continue;
		}
		local = list_entry(q, struct ip_vs_laddr, n_list);
		goto out;
	} while (q != p);
	write_unlock(&svc->laddr_lock);
	return NULL;

      out:
	svc->curr_laddr = q;
	write_unlock(&svc->laddr_lock);
	return local;
}

/*
 *	Bind a connection entry with a local address
 *	and hashed it in connection table.
 *	Called just after a new connection entry is created and destination has binded.
 *	returns bool success.
 */
static inline int ip_vs_hbind_laddr(struct ip_vs_conn *cp)
{
	struct ip_vs_dest *dest = cp->dest;
	struct ip_vs_service *svc = dest->svc;
	struct ip_vs_laddr *local;
	int ret = 0;
	int remaining, i, tport, hit = 0;
	unsigned ihash, ohash;
	struct ip_vs_conn_idx *cidx;

	/* fwd methods: not IP_VS_CONN_F_FULLNAT */
	switch (IP_VS_FWD_METHOD(cp)) {
	case IP_VS_CONN_F_MASQ:
	case IP_VS_CONN_F_TUNNEL:
	case IP_VS_CONN_F_DROUTE:
	case IP_VS_CONN_F_LOCALNODE:
	case IP_VS_CONN_F_BYPASS:
		ip_vs_addr_copy(cp->af, &cp->out_idx->d_addr, &cp->caddr);
		cp->out_idx->d_port = cp->cport;
		ip_vs_addr_copy(cp->af, &cp->laddr, &cp->caddr);
		cp->lport = cp->cport;
		cp->local = NULL;
		ip_vs_conn_hash(cp);
		ret = 1;
		goto out;
	}

	if (cp->flags & IP_VS_CONN_F_TEMPLATE) {
		ip_vs_addr_copy(cp->af, &cp->out_idx->d_addr, &cp->caddr);
		cp->out_idx->d_port = cp->cport;
		ip_vs_addr_copy(cp->af, &cp->laddr, &cp->caddr);
		cp->lport = cp->cport;
		cp->local = NULL;
		ip_vs_conn_hash(cp);
		ret = 1;
		goto out;
	}
	/*
	 * fwd methods: IP_VS_CONN_F_FULLNAT
	 */
	/* choose a local address by round-robin */
	local = ip_vs_get_laddr(svc);
	if (local != NULL) {
		/*OUTside2INside: hashed by client address and port, virtual address and port */
		ihash =
		    ip_vs_conn_hashkey(cp->af, &cp->caddr, cp->cport,
				       &cp->vaddr, cp->vport);

		/* increase the refcnt counter of the local address */
		ip_vs_laddr_hold(local);
		ip_vs_addr_copy(cp->af, &cp->out_idx->d_addr, &local->addr);
		ip_vs_addr_copy(cp->af, &cp->laddr, &local->addr);
		remaining = sysctl_ip_vs_lport_max - sysctl_ip_vs_lport_min + 1;
		for (i = 0; i < sysctl_ip_vs_lport_tries; i++) {
			/* choose a port */
			tport =
			    sysctl_ip_vs_lport_min +
			    atomic64_inc_return(&local->port) % remaining;
			cp->out_idx->d_port = cp->lport = htons(tport);

			/* init hit everytime before lookup the tuple */
			hit = 0;

			/*INside2OUTside: hashed by destination address and port, local address and port */
			ohash =
			    ip_vs_conn_hashkey(cp->af, &cp->daddr, cp->dport,
					       &cp->laddr, cp->lport);
			/* lock the conntab bucket */
			ip_vs_conn_lock2(ihash, ohash);
			/*
			 * check local address and port is valid by lookup connection table
			 */
			list_for_each_entry(cidx, &ip_vs_conn_tab[ohash],
					    c_list) {
				if (cidx->af == cp->af
				    && ip_vs_addr_equal(cp->af, &cp->daddr,
							&cidx->s_addr)
				    && ip_vs_addr_equal(cp->af, &cp->laddr,
							&cidx->d_addr)
				    && cp->dport == cidx->s_port
				    && cp->lport == cidx->d_port
				    && cp->protocol == cidx->protocol) {
					/* HIT */
					atomic64_inc(&local->port_conflict);
					hit = 1;
					break;
				}
			}
			if (hit == 0) {
				cp->local = local;
				/* hashed */
				__ip_vs_conn_hash(cp, ihash, ohash);
				ip_vs_conn_unlock2(ihash, ohash);
				atomic_inc(&local->conn_counts);
				ret = 1;
				goto out;
			}
			ip_vs_conn_unlock2(ihash, ohash);
		}
		if (ret == 0) {
			ip_vs_laddr_put(local);
		}
	}
	ret = 0;

      out:
	return ret;
}

/*
 *	Unbind a connection entry with its local address
 *	Called by the ip_vs_conn_expire function.
 */
static inline void ip_vs_unbind_laddr(struct ip_vs_conn *cp)
{
	struct ip_vs_laddr *local = cp->local;

	if (!local)
		return;

	IP_VS_DBG_BUF(7, "Unbind-laddr %s c:%s:%d v:%s:%d l:%s:%d "
		      "d:%s:%d fwd:%c s:%u conn->flags:%X conn->refcnt:%d "
		      "local->refcnt:%d\n",
		      ip_vs_proto_name(cp->protocol),
		      IP_VS_DBG_ADDR(cp->af, &cp->caddr), ntohs(cp->cport),
		      IP_VS_DBG_ADDR(cp->af, &cp->vaddr), ntohs(cp->vport),
		      IP_VS_DBG_ADDR(cp->af, &cp->laddr), ntohs(cp->lport),
		      IP_VS_DBG_ADDR(cp->af, &cp->daddr), ntohs(cp->dport),
		      ip_vs_fwd_tag(cp), cp->state,
		      cp->flags, atomic_read(&cp->refcnt),
		      atomic_read(&local->refcnt));

	/* Update the connection counters */
	atomic_dec(&local->conn_counts);

	/*
	 * Simply decrease the refcnt of the local address;
	 */
	ip_vs_laddr_put(local);
}

/*
 *	Checking if the destination of a connection template is available.
 *	If available, return 1, otherwise invalidate this connection
 *	template and return 0.
 */
int ip_vs_check_template(struct ip_vs_conn *ct)
{
	struct ip_vs_dest *dest = ct->dest;

	/*
	 * Checking the dest server status.
	 */
	if ((dest == NULL) ||
	    !(dest->flags & IP_VS_DEST_F_AVAILABLE) ||
	    (sysctl_ip_vs_expire_quiescent_template &&
	     (atomic_read(&dest->weight) == 0))) {
		IP_VS_DBG_BUF(9, "check_template: dest not available for "
			      "protocol %s s:%s:%d v:%s:%d "
			      "-> l:%s:%d d:%s:%d\n",
			      ip_vs_proto_name(ct->protocol),
			      IP_VS_DBG_ADDR(ct->af, &ct->caddr),
			      ntohs(ct->cport),
			      IP_VS_DBG_ADDR(ct->af, &ct->vaddr),
			      ntohs(ct->vport),
			      IP_VS_DBG_ADDR(ct->af, &ct->laddr),
			      ntohs(ct->lport),
			      IP_VS_DBG_ADDR(ct->af, &ct->daddr),
			      ntohs(ct->dport));

		/*
		 * Invalidate the connection template
		 */
		if (ct->vport != htons(0xffff)) {
			if (ip_vs_conn_unhash(ct)) {
				ct->dport = htons(0xffff);
				ct->vport = htons(0xffff);
				ct->lport = 0;
				ct->cport = 0;
				ip_vs_conn_hash(ct);
			}
		}

		/*
		 * Simply decrease the refcnt of the template,
		 * don't restart its timer.
		 */
		atomic_dec(&ct->refcnt);
		return 0;
	}
	return 1;
}

/* Warning: only be allowed call in ip_vs_conn_new */
static void ip_vs_conn_del(struct ip_vs_conn *cp)
{
	if (cp == NULL)
		return;

	/* delete the timer if it is activated by other users */
	if (timer_pending(&cp->timer))
		del_timer(&cp->timer);

	/* does anybody control me? */
	if (cp->control)
		ip_vs_control_del(cp);

	if (unlikely(cp->app != NULL))
		ip_vs_unbind_app(cp);
	ip_vs_unbind_dest(cp);
	ip_vs_unbind_laddr(cp);
	if (cp->flags & IP_VS_CONN_F_NO_CPORT)
		atomic_dec(&ip_vs_conn_no_cport_cnt);
	atomic_dec(&ip_vs_conn_count);

	kmem_cache_free(ip_vs_conn_cachep, cp);
	cp = NULL;
}

static void ip_vs_conn_expire(unsigned long data)
{
	struct ip_vs_conn *cp = (struct ip_vs_conn *)data;
	struct sk_buff *tmp_skb = NULL;
	struct ip_vs_protocol *pp = ip_vs_proto_get(cp->protocol);

	/*
	 * Set proper timeout.
	 */
	if ((pp != NULL) && (pp->timeout_table != NULL)) {
		cp->timeout = pp->timeout_table[cp->state];
	} else {
		cp->timeout = 60 * HZ;
	}

	/*
	 *      hey, I'm using it
	 */
	atomic_inc(&cp->refcnt);

	/*
	 * Retransmit syn packet to rs.
	 * We just check syn_skb is not NULL, as syn_skb 
	 * is stored only if syn-proxy is enabled.
	 */
	spin_lock(&cp->lock);
	if (cp->syn_skb != NULL && atomic_read(&cp->syn_retry_max) > 0) {
		atomic_dec(&cp->syn_retry_max);
		if (cp->packet_xmit) {
			tmp_skb = skb_copy(cp->syn_skb, GFP_ATOMIC);
			cp->packet_xmit(tmp_skb, cp, pp);
		}
		/* statistics */
		IP_VS_INC_ESTATS(ip_vs_esmib, SYNPROXY_RS_ERROR);
		spin_unlock(&cp->lock);
		goto expire_later;
	}
	spin_unlock(&cp->lock);

	/*
	 *      do I control anybody?
	 */
	if (atomic_read(&cp->n_control))
		goto expire_later;

	/*
	 *      unhash it if it is hashed in the conn table
	 */
	if (!ip_vs_conn_unhash(cp) && !(cp->flags & IP_VS_CONN_F_ONE_PACKET))
		goto expire_later;

	/*
	 *      refcnt==1 implies I'm the only one referrer
	 */
	if (likely(atomic_read(&cp->refcnt) == 1)) {
		/* delete the timer if it is activated by other users */
		if (timer_pending(&cp->timer))
			del_timer(&cp->timer);

		/* does anybody control me? */
		if (cp->control)
			ip_vs_control_del(cp);

		if (pp->conn_expire_handler)
			pp->conn_expire_handler(pp, cp);

		if (unlikely(cp->app != NULL))
			ip_vs_unbind_app(cp);
		ip_vs_unbind_dest(cp);
		ip_vs_unbind_laddr(cp);
		if (cp->flags & IP_VS_CONN_F_NO_CPORT)
			atomic_dec(&ip_vs_conn_no_cport_cnt);
		atomic_dec(&ip_vs_conn_count);

		/* free stored ack packet */
		while ((tmp_skb = skb_dequeue(&cp->ack_skb)) != NULL) {
			kfree_skb(tmp_skb);
			tmp_skb = NULL;
		}

		/* free stored syn skb */
		if ((tmp_skb = xchg(&cp->syn_skb, NULL)) != NULL) {
			kfree_skb(tmp_skb);
			tmp_skb = NULL;
		}

		if (cp->indev != NULL)
			dev_put(cp->indev);

		kmem_cache_free(ip_vs_conn_cachep, cp);
		return;
	}

	/* hash it back to the table */
	ip_vs_conn_hash(cp);

      expire_later:
	IP_VS_DBG(7, "delayed: conn->refcnt-1=%d conn->n_control=%d\n",
		  atomic_read(&cp->refcnt) - 1, atomic_read(&cp->n_control));

	ip_vs_conn_put(cp);
}

void ip_vs_conn_expire_now(struct ip_vs_conn *cp)
{
	if (del_timer(&cp->timer))
		mod_timer(&cp->timer, jiffies);
}

/*
 *	Create a new connection entry and hash it into the ip_vs_conn_tab
 */
struct ip_vs_conn *ip_vs_conn_new(int af, int proto,
				  const union nf_inet_addr *caddr, __be16 cport,
				  const union nf_inet_addr *vaddr, __be16 vport,
				  const union nf_inet_addr *daddr, __be16 dport,
				  unsigned flags, struct ip_vs_dest *dest,
				  struct sk_buff *skb, int is_synproxy_on)
{
	struct ip_vs_conn *cp;
	struct ip_vs_protocol *pp = ip_vs_proto_get(proto);
	struct ip_vs_conn_idx *ci_idx, *co_idx;
	struct tcphdr _tcph, *th;

	cp = kmem_cache_zalloc(ip_vs_conn_cachep, GFP_ATOMIC);
	if (cp == NULL) {
		IP_VS_ERR_RL("%s(): no memory\n", __func__);
		return NULL;
	}

	/* init connection index of OUTside2INside */
	ci_idx =
	    (struct ip_vs_conn_idx *)(((__u8 *) cp) +
				      sizeof(struct ip_vs_conn));
	INIT_LIST_HEAD(&ci_idx->c_list);
	ci_idx->af = af;
	ci_idx->protocol = proto;
	ip_vs_addr_copy(af, &ci_idx->s_addr, caddr);
	ci_idx->s_port = cport;
	ip_vs_addr_copy(af, &ci_idx->d_addr, vaddr);
	ci_idx->d_port = vport;
	ci_idx->flags |= IP_VS_CIDX_F_OUT2IN;
	ci_idx->cp = cp;

	/* init connection index of INside2OUTside */
	co_idx =
	    (struct ip_vs_conn_idx *)(((__u8 *) cp) +
				      sizeof(struct ip_vs_conn) +
				      sizeof(struct ip_vs_conn_idx));
	INIT_LIST_HEAD(&co_idx->c_list);
	co_idx->af = af;
	co_idx->protocol = proto;
	ip_vs_addr_copy(proto == IPPROTO_IP ? AF_UNSPEC : af,
			&co_idx->s_addr, daddr);
	co_idx->s_port = dport;
	co_idx->flags |= IP_VS_CIDX_F_IN2OUT;
	co_idx->cp = cp;

	/* now init connection */
	setup_timer(&cp->timer, ip_vs_conn_expire, (unsigned long)cp);
	cp->af = af;
	cp->protocol = proto;
	ip_vs_addr_copy(af, &cp->caddr, caddr);
	cp->cport = cport;
	ip_vs_addr_copy(af, &cp->vaddr, vaddr);
	cp->vport = vport;
	/* proto should only be IPPROTO_IP if d_addr is a fwmark */
	ip_vs_addr_copy(proto == IPPROTO_IP ? AF_UNSPEC : af,
			&cp->daddr, daddr);
	cp->dport = dport;
	cp->flags = flags;
	spin_lock_init(&cp->lock);
	cp->in_idx = ci_idx;
	cp->out_idx = co_idx;

	/*
	 * Set the entry is referenced by the current thread before hashing
	 * it in the table, so that other thread run ip_vs_random_dropentry
	 * but cannot drop this entry.
	 */
	atomic_set(&cp->refcnt, 1);

	atomic_set(&cp->n_control, 0);
	atomic_set(&cp->in_pkts, 0);

	atomic_inc(&ip_vs_conn_count);
	if (flags & IP_VS_CONN_F_NO_CPORT)
		atomic_inc(&ip_vs_conn_no_cport_cnt);

	/* Bind the connection with a destination server */
	ip_vs_bind_dest(cp, dest);

	/* Set its state and timeout */
	cp->state = 0;
	cp->timeout = 3 * HZ;

	/* Bind its packet transmitter */
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		ip_vs_bind_xmit_v6(cp);
	else
#endif
		ip_vs_bind_xmit(cp);

	if (unlikely(pp && atomic_read(&pp->appcnt)))
		ip_vs_bind_app(cp, pp);

	/* Set syn-proxy members 
	 * Set cp->flag manually to avoid svn->flags change when 
	 * ack_skb is on the way
	 */
	skb_queue_head_init(&cp->ack_skb);
	atomic_set(&cp->syn_retry_max, 0);
	if (is_synproxy_on == 1 && skb != NULL) {
		unsigned int tcphoff;

#ifdef CONFIG_IP_VS_IPV6
		if (af == AF_INET6)
			tcphoff = sizeof(struct ipv6hdr);
		else
#endif
			tcphoff = ip_hdr(skb)->ihl * 4;
		th = skb_header_pointer(skb, tcphoff, sizeof(_tcph), &_tcph);
		if (th == NULL) {
			IP_VS_ERR_RL("%s(): get tcphdr failed\n", __func__);
			ip_vs_conn_del(cp);
			return NULL;
		}
		/* Set syn-proxy flag */
		cp->flags |= IP_VS_CONN_F_SYNPROXY;

		/* Save ack packet */
		skb_queue_tail(&cp->ack_skb, skb);
		/* Save ack_seq - 1 */
		cp->syn_proxy_seq.init_seq =
		    htonl((__u32) ((htonl(th->ack_seq) - 1)));
		/* Save ack_seq */
		cp->fnat_seq.fdata_seq = htonl(th->ack_seq);
		/* Use IP_VS_TCP_S_SYN_SENT for syn */
		cp->timeout = pp->timeout_table[cp->state =
						IP_VS_TCP_S_SYN_SENT];
	} else {
		/* Unset syn-proxy flag */
		cp->flags &= ~IP_VS_CONN_F_SYNPROXY;
	}

	/*
	 * bind the connection with a local address
	 * and hash it in the ip_vs_conn_tab finally.
	 */
	if (unlikely(ip_vs_hbind_laddr(cp) == 0)) {
		IP_VS_ERR_RL("bind local address: no port available\n");
		ip_vs_conn_del(cp);
		return NULL;
	}

	return cp;
}

/*
 *	/proc/net/ip_vs_conn entries
 */
#ifdef CONFIG_PROC_FS

static void *ip_vs_conn_array(struct seq_file *seq, loff_t pos)
{
	int idx;
	struct ip_vs_conn_idx *cidx;

	for (idx = 0; idx < IP_VS_CONN_TAB_SIZE; idx++) {
		ct_read_lock_bh(idx);
		list_for_each_entry(cidx, &ip_vs_conn_tab[idx], c_list) {
			if ((cidx->flags & IP_VS_CIDX_F_OUT2IN) && (pos-- == 0)) {
				seq->private = &ip_vs_conn_tab[idx];
				return cidx->cp;
			}
		}
		ct_read_unlock_bh(idx);
	}

	return NULL;
}

static void *ip_vs_conn_seq_start(struct seq_file *seq, loff_t * pos)
{
	seq->private = NULL;
	return *pos ? ip_vs_conn_array(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *ip_vs_conn_seq_next(struct seq_file *seq, void *v, loff_t * pos)
{
	struct ip_vs_conn *cp = v;
	struct list_head *e, *l = seq->private;
	struct ip_vs_conn_idx *cidx;
	int idx;

	++*pos;
	if (v == SEQ_START_TOKEN)
		return ip_vs_conn_array(seq, 0);

	cidx = cp->in_idx;
	/* more on same hash chain? */
	while ((e = cidx->c_list.next) != l) {
		cidx = list_entry(e, struct ip_vs_conn_idx, c_list);
		if (cidx->flags & IP_VS_CIDX_F_OUT2IN) {
			return cidx->cp;
		}
	}

	idx = l - ip_vs_conn_tab;
	ct_read_unlock_bh(idx);

	while (++idx < IP_VS_CONN_TAB_SIZE) {
		ct_read_lock_bh(idx);
		list_for_each_entry(cidx, &ip_vs_conn_tab[idx], c_list) {
			if (cidx->flags & IP_VS_CIDX_F_OUT2IN) {
				seq->private = &ip_vs_conn_tab[idx];
				return cidx->cp;
			}
		}
		ct_read_unlock_bh(idx);
	}
	seq->private = NULL;
	return NULL;
}

static void ip_vs_conn_seq_stop(struct seq_file *seq, void *v)
{
	struct list_head *l = seq->private;

	if (l)
		ct_read_unlock_bh(l - ip_vs_conn_tab);
}

static int ip_vs_conn_seq_show(struct seq_file *seq, void *v)
{

	if (v == SEQ_START_TOKEN)
		seq_puts(seq,
			 "Pro FromIP   FPrt ToIP     TPrt LocalIP  LPrt DestIP   DPrt State       Expires\n");
	else {
		const struct ip_vs_conn *cp = v;

#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			seq_printf(seq,
				   "%-3s %pI6 %04X %pI6 %04X %pI6 %04X %pI6 %04X %-11s %7lu\n",
				   ip_vs_proto_name(cp->protocol),
				   &cp->caddr.in6, ntohs(cp->cport),
				   &cp->vaddr.in6, ntohs(cp->vport),
				   &cp->laddr.in6, ntohs(cp->lport),
				   &cp->daddr.in6, ntohs(cp->dport),
				   ip_vs_state_name(cp->protocol, cp->state),
				   (cp->timer.expires - jiffies) / HZ);
		else
#endif
			seq_printf(seq,
				   "%-3s %08X %04X %08X %04X"
				   " %08X %04X %08X %04X %-11s %7lu\n",
				   ip_vs_proto_name(cp->protocol),
				   ntohl(cp->caddr.ip), ntohs(cp->cport),
				   ntohl(cp->vaddr.ip), ntohs(cp->vport),
				   ntohl(cp->laddr.ip), ntohs(cp->lport),
				   ntohl(cp->daddr.ip), ntohs(cp->dport),
				   ip_vs_state_name(cp->protocol, cp->state),
				   (cp->timer.expires - jiffies) / HZ);
	}
	return 0;
}

static const struct seq_operations ip_vs_conn_seq_ops = {
	.start = ip_vs_conn_seq_start,
	.next = ip_vs_conn_seq_next,
	.stop = ip_vs_conn_seq_stop,
	.show = ip_vs_conn_seq_show,
};

static int ip_vs_conn_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ip_vs_conn_seq_ops);
}

static const struct file_operations ip_vs_conn_fops = {
	.owner = THIS_MODULE,
	.open = ip_vs_conn_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static const char *ip_vs_origin_name(unsigned flags)
{
	if (flags & IP_VS_CONN_F_SYNC)
		return "SYNC";
	else
		return "LOCAL";
}

static int ip_vs_conn_sync_seq_show(struct seq_file *seq, void *v)
{

	if (v == SEQ_START_TOKEN)
		seq_puts(seq,
			 "Pro FromIP   FPrt ToIP     TPrt LocalIP  LPrt DestIP   DPrt State       Origin Expires\n");
	else {
		const struct ip_vs_conn *cp = v;

#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			seq_printf(seq,
				   "%-3s %pI6 %04X %pI6 %04X %pI6 %04X %pI6 %04X %-11s %-6s %7lu\n",
				   ip_vs_proto_name(cp->protocol),
				   &cp->caddr.in6, ntohs(cp->cport),
				   &cp->vaddr.in6, ntohs(cp->vport),
				   &cp->laddr.in6, ntohs(cp->lport),
				   &cp->daddr.in6, ntohs(cp->dport),
				   ip_vs_state_name(cp->protocol, cp->state),
				   ip_vs_origin_name(cp->flags),
				   (cp->timer.expires - jiffies) / HZ);
		else
#endif
			seq_printf(seq,
				   "%-3s %08X %04X %08X %04X "
				   "%08X %04X %08X %04X %-11s %-6s %7lu\n",
				   ip_vs_proto_name(cp->protocol),
				   ntohl(cp->caddr.ip), ntohs(cp->cport),
				   ntohl(cp->vaddr.ip), ntohs(cp->vport),
				   ntohl(cp->laddr.ip), ntohs(cp->lport),
				   ntohl(cp->daddr.ip), ntohs(cp->dport),
				   ip_vs_state_name(cp->protocol, cp->state),
				   ip_vs_origin_name(cp->flags),
				   (cp->timer.expires - jiffies) / HZ);
	}
	return 0;
}

static const struct seq_operations ip_vs_conn_sync_seq_ops = {
	.start = ip_vs_conn_seq_start,
	.next = ip_vs_conn_seq_next,
	.stop = ip_vs_conn_seq_stop,
	.show = ip_vs_conn_sync_seq_show,
};

static int ip_vs_conn_sync_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ip_vs_conn_sync_seq_ops);
}

static const struct file_operations ip_vs_conn_sync_fops = {
	.owner = THIS_MODULE,
	.open = ip_vs_conn_sync_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

#endif

/*
 *      Randomly drop connection entries before running out of memory
 */
static inline int todrop_entry(struct ip_vs_conn *cp)
{
	/*
	 * The drop rate array needs tuning for real environments.
	 * Called from timer bh only => no locking
	 */
	static const char todrop_rate[9] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
	static char todrop_counter[9] = { 0 };
	int i;

	/* if the conn entry hasn't lasted for 60 seconds, don't drop it.
	   This will leave enough time for normal connection to get
	   through. */
	if (time_before(cp->timeout + jiffies, cp->timer.expires + 60 * HZ))
		return 0;

	/* Don't drop the entry if its number of incoming packets is not
	   located in [0, 8] */
	i = atomic_read(&cp->in_pkts);
	if (i > 8 || i < 0)
		return 0;

	if (!todrop_rate[i])
		return 0;
	if (--todrop_counter[i] > 0)
		return 0;

	todrop_counter[i] = todrop_rate[i];
	return 1;
}

/* Called from keventd and must protect itself from softirqs */
void ip_vs_random_dropentry(void)
{
	int idx;
	struct ip_vs_conn *cp;
	struct ip_vs_conn_idx *cidx;

	/*
	 * Randomly scan 1/32 of the whole table every second
	 */
	for (idx = 0; idx < (IP_VS_CONN_TAB_SIZE >> 5); idx++) {
		unsigned hash = net_random() & IP_VS_CONN_TAB_MASK;

		/*
		 *  Lock is actually needed in this loop.
		 */
		ct_write_lock_bh(hash);

		list_for_each_entry(cidx, &ip_vs_conn_tab[hash], c_list) {
			cp = cidx->cp;
			if (cp->flags & IP_VS_CONN_F_TEMPLATE)
				/* connection template */
				continue;

			if (cp->protocol == IPPROTO_TCP) {
				switch (cp->state) {
				case IP_VS_TCP_S_SYN_RECV:
				case IP_VS_TCP_S_SYNACK:
					break;

				case IP_VS_TCP_S_ESTABLISHED:
					if (todrop_entry(cp))
						break;
					continue;

				default:
					continue;
				}
			} else {
				if (!todrop_entry(cp))
					continue;
			}

			IP_VS_DBG(4, "del connection\n");
			ip_vs_conn_expire_now(cp);
			if (cp->control) {
				IP_VS_DBG(4, "del conn template\n");
				ip_vs_conn_expire_now(cp->control);
			}
		}
		ct_write_unlock_bh(hash);
	}
}

/*
 *      Flush all the connection entries in the ip_vs_conn_tab
 */
static void ip_vs_conn_flush(void)
{
	int idx;
	struct ip_vs_conn *cp;
	struct ip_vs_conn_idx *cidx;

      flush_again:
	for (idx = 0; idx < IP_VS_CONN_TAB_SIZE; idx++) {
		/*
		 *  Lock is actually needed in this loop.
		 */
		ct_write_lock_bh(idx);

		list_for_each_entry(cidx, &ip_vs_conn_tab[idx], c_list) {
			IP_VS_DBG(4, "del connection\n");
			cp = cidx->cp;
			ip_vs_conn_expire_now(cp);
			if (cp->control) {
				IP_VS_DBG(4, "del conn template\n");
				ip_vs_conn_expire_now(cp->control);
			}
		}
		ct_write_unlock_bh(idx);
	}

	/* the counter may be not NULL, because maybe some conn entries
	   are run by slow timer handler or unhashed but still referred */
	if (atomic_read(&ip_vs_conn_count) != 0) {
		schedule();
		goto flush_again;
	}
}

int __init ip_vs_conn_init(void)
{
	int idx;

	/*
	 * Allocate the connection hash table and initialize its list heads
	 */
	ip_vs_conn_tab =
	    vmalloc(IP_VS_CONN_TAB_SIZE * (sizeof(struct list_head)));
	if (!ip_vs_conn_tab)
		return -ENOMEM;

	/* Allocate ip_vs_conn slab cache */
	ip_vs_conn_cachep = kmem_cache_create("ip_vs_conn",
					      sizeof(struct ip_vs_conn) +
					      2 * sizeof(struct ip_vs_conn_idx),
					      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!ip_vs_conn_cachep) {
		vfree(ip_vs_conn_tab);
		return -ENOMEM;
	}

	pr_info("Connection hash table configured "
		"(size=%d, memory=%ldKbytes)\n",
		IP_VS_CONN_TAB_SIZE,
		(long)(IP_VS_CONN_TAB_SIZE * sizeof(struct list_head)) / 1024);
	IP_VS_DBG(0, "Each connection entry needs %Zd bytes at least\n",
		  sizeof(struct ip_vs_conn) +
		  2 * sizeof(struct ip_vs_conn_idx));

	for (idx = 0; idx < IP_VS_CONN_TAB_SIZE; idx++) {
		INIT_LIST_HEAD(&ip_vs_conn_tab[idx]);
	}

	for (idx = 0; idx < CT_LOCKARRAY_SIZE; idx++) {
		rwlock_init(&__ip_vs_conntbl_lock_array[idx].l);
	}

	proc_net_fops_create(&init_net, "ip_vs_conn", 0, &ip_vs_conn_fops);
	proc_net_fops_create(&init_net, "ip_vs_conn_sync", 0,
			     &ip_vs_conn_sync_fops);

	/* calculate the random value for connection hash */
	get_random_bytes(&ip_vs_conn_rnd, sizeof(ip_vs_conn_rnd));

	return 0;
}

void ip_vs_conn_cleanup(void)
{
	/* flush all the connection entries first */
	ip_vs_conn_flush();

	/* Release the empty cache */
	kmem_cache_destroy(ip_vs_conn_cachep);
	proc_net_remove(&init_net, "ip_vs_conn");
	proc_net_remove(&init_net, "ip_vs_conn_sync");
	vfree(ip_vs_conn_tab);
}
