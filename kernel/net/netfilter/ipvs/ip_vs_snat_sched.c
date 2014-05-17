/*
 * IPVS:        SNAT gateway scheduling module
 * Authors:     lijian <jlijian3@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Changes:
 *
 */


/*
 *      IPVS SNAT Scheduler structure
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/ip.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <net/route.h>

#include <net/ip_vs.h>


struct ip_vs_snat_node {
	struct hlist_node n_hash;
	__be32 n_key;
	struct list_head rules;
};

struct ip_vs_snat_zone {
	struct ip_vs_snat_zone *z_next;
	struct hlist_head *z_hash;
	int z_order;
	__be32 z_mask;
#define Z_MASK(z) ((z)->z_mask)
};

struct ip_vs_snat_table {
	struct ip_vs_snat_zone *zones[33];
	struct ip_vs_snat_zone *zone_list;
};

#define IP_VS_SNAT_TAB_BITS 8
#define IP_VS_SNAT_TAB_SIZE (1 << IP_VS_SNAT_TAB_BITS)
#define IP_VS_SNAT_TAB_MASK (IP_VS_SNAT_TAB_SIZE - 1)

static inline u32 ip_vs_node_hash(__be32 key, struct ip_vs_snat_zone *z)
{
	u32 h = ntohl(key)>>(32 - z->z_order);
	h ^= (h>>20);
	h ^= (h>>10);
	h ^= (h>>5);
	h &= IP_VS_SNAT_TAB_MASK;
	return h;
}

static inline __be32 ip_vs_snat_zone_key(__be32 addr, struct ip_vs_snat_zone *z)
{
	return addr & Z_MASK(z);
}

static inline unsigned long ip_vs_ifname_cmp(const char *_a,
					      const char *_b,
					      const char *_mask)
{
	const unsigned long *a = (const unsigned long *)_a;
	const unsigned long *b = (const unsigned long *)_b;
	const unsigned long *mask = (const unsigned long *)_mask;
	unsigned long ret;

	ret = (a[0] ^ b[0]) & mask[0];
	if (IP_VS_IFNAME_MAXLEN > sizeof(unsigned long))
		ret |= (a[1] ^ b[1]) & mask[1];
	if (IP_VS_IFNAME_MAXLEN > 2 * sizeof(unsigned long))
		ret |= (a[2] ^ b[2]) & mask[2];
	if (IP_VS_IFNAME_MAXLEN > 3 * sizeof(unsigned long))
		ret |= (a[3] ^ b[3]) & mask[3];
	BUILD_BUG_ON(IP_VS_IFNAME_MAXLEN > 4 * sizeof(unsigned long));
	return ret;
}

static struct ip_vs_dest *ip_vs_snat_rule_find(struct list_head *head,
	          __be32 saddr,
	          __be32 daddr,
	          __be32 rt_gateway,
	          const char *out_dev)
{
	struct ip_vs_dest_snat *rule = NULL; 
	struct ip_vs_dest *dest = NULL;

	list_for_each_entry(rule, head, rule_list) {
		dest = (struct ip_vs_dest *)rule;
	
		if ((saddr & rule->smask.ip) != rule->saddr.ip)
			continue;

		if ((daddr & rule->dmask.ip) != rule->daddr.ip)
			continue;

		if (out_dev && rule->out_dev_mask[0] &&
		    !ip_vs_ifname_cmp(out_dev, rule->out_dev, rule->out_dev_mask)){
			IP_VS_DBG(7, "SNAT rule_find gw:%pI4 rt_gw:%pI4;new_gw:%pI4\n", 
				&dest->addr.ip, &rt_gateway, &rule->new_gateway.ip);
				return dest;
		}
	
		if (!rule->out_dev_mask[0] &&
		    (rt_gateway == dest->addr.ip || dest->addr.ip == 0)) {
			IP_VS_DBG(7, "SNAT rule_find gw:%pI4 rt_gw:%pI4;new_gw:%pI4\n",
				&dest->addr.ip, &rt_gateway, &rule->new_gateway.ip);
				return dest;
		}
	}

	return NULL;
}

static struct ip_vs_dest *
ip_vs_snat_rule_find_by_skb(struct list_head *head, const struct sk_buff *skb)
{
	struct rtable *rt = skb_rtable(skb);
	struct iphdr *iph = ip_hdr(skb);
	__be32 rt_gateway = 0;
	const char *out_dev = NULL;

	if (rt) {
		rt_gateway = rt->rt_gateway;
		if (rt->u.dst.dev)
			out_dev = rt->u.dst.dev->name; 
	}

	IP_VS_DBG(6, "SNAT lookup rule s:%pI4 d:%pI4 g:%pI4 oif:%s\n",
		&iph->saddr, &iph->daddr, &rt_gateway, out_dev); 
	
	return ip_vs_snat_rule_find(head, iph->saddr,
		iph->daddr, rt_gateway, out_dev);
}


static struct ip_vs_snat_node *
ip_vs_snat_node_find(struct ip_vs_snat_zone *z, __be32 key)
{
	struct hlist_head *head = &z->z_hash[ip_vs_node_hash(key, z)];
	struct hlist_node *hnode;
	struct ip_vs_snat_node *node;

	hlist_for_each_entry(node, hnode, head, n_hash) {
	IP_VS_DBG(6, "SNAT lookup node z:%d nk:%pI4 k:%pI4\n",
		z->z_order, &node->n_key, &key);
	if (node->n_key == key)
		return node;
	}

	return NULL;
}

static struct ip_vs_snat_node *
ip_vs_snat_node_new(struct ip_vs_snat_zone *z, __be32 key)
{
	struct ip_vs_snat_node *node;
	struct hlist_head *head = &z->z_hash[ip_vs_node_hash(key, z)];
	
	node = kmalloc(sizeof(struct ip_vs_snat_node), GFP_ATOMIC);
	if (!node)
		return NULL;

	INIT_LIST_HEAD(&node->rules);
	node->n_key = key;
 
	hlist_add_head(&node->n_hash, head);
	return node;
}

static struct ip_vs_snat_zone *
ip_vs_snat_zone_new(struct ip_vs_snat_table * tbl, int smask_len)
{
	int i;
	struct ip_vs_snat_zone *z;
	
	if (!tbl)
		return NULL;
	
	z = kmalloc(sizeof(struct ip_vs_snat_zone), GFP_ATOMIC);

	if (!z)
		return NULL;

	z->z_hash = kzalloc(sizeof(struct hlist_head) * IP_VS_SNAT_TAB_SIZE, GFP_ATOMIC);
	if (!z->z_hash) {
		kfree(z);
		return NULL;
	}

	z->z_order = smask_len;
	z->z_mask = inet_make_mask(smask_len);

	for (i = smask_len+1; i <= 32; i++)
	if (tbl->zones[i])
		break;

	if (i > 32) {
		z->z_next = tbl->zone_list;
		tbl->zone_list = z;
	} else {
		z->z_next = tbl->zones[i]->z_next;
		tbl->zones[i]->z_next = z;
	}
	tbl->zones[smask_len] = z;
	return z;
}

static void ip_vs_snat_node_free(struct hlist_head *head)
{
	struct hlist_node *hnode, *next;
	struct ip_vs_snat_node *node;

	if (!head)
		return;

	hlist_for_each_entry_safe(node, hnode, next, head, n_hash) {
		hlist_del(hnode);
		kfree(node);
	}
}

static void ip_vs_snat_zone_free(struct ip_vs_snat_zone *z) {
	int i;

	if (!z)
		return;

	if (z->z_hash) {
		for (i = 0; i < IP_VS_SNAT_TAB_SIZE; i++) {
			ip_vs_snat_node_free(&z->z_hash[i]);
		}
		kfree(z->z_hash);
	}
}

static void ip_vs_snat_table_free(struct ip_vs_snat_table *tbl)
{
	int i;

	if (!tbl)
		return;

	for (i = 0; i <= 32; i++) {
		ip_vs_snat_zone_free(tbl->zones[i]);
	}

	kfree(tbl);
}

static struct ip_vs_dest *ip_vs_snat_get(int af,
		struct ip_vs_snat_table *tbl,
		const struct sk_buff *skb)
{
	struct ip_vs_dest *dest;
	struct ip_vs_snat_zone *z;
	struct iphdr *iph = ip_hdr(skb);

	for (z = tbl->zone_list; z; z = z->z_next) {
		struct ip_vs_snat_node *node;
		__be32 key = ip_vs_snat_zone_key(iph->saddr, z);

		node = ip_vs_snat_node_find(z, key);

		IP_VS_DBG(6, "SNAT lookup zone i:%d mask:%pI4 k:%pI4 %s\n",
			z->z_order, &z->z_mask, &key,
			node?"hit":"not hit");

	if (!node)
		continue;

	if ((dest = ip_vs_snat_rule_find_by_skb(&node->rules, skb)))
		return dest;
	}

	return NULL;
}

static void ip_vs_node_flush(struct hlist_head *head)
{
	struct hlist_node *hnode, *next;
	struct ip_vs_snat_node *node;

	if (!head)
		return;

	hlist_for_each_entry_safe(node, hnode, next, head, n_hash) {
		struct ip_vs_dest_snat *rule, *rule_next;

		list_for_each_entry_safe(rule, rule_next, &node->rules, rule_list) {
			atomic_dec(&rule->dest.refcnt);
			list_del(&rule->rule_list);
		}

		hlist_del(hnode);
		kfree(node);
	}
}

static void ip_vs_zone_flush(struct ip_vs_snat_zone *z)
{
	int i;

	if (!z || !z->z_hash)
		return;

	for (i = 0; i < IP_VS_SNAT_TAB_SIZE; i++) {
		ip_vs_node_flush(&z->z_hash[i]);
	}
}

static void ip_vs_snat_flush(struct ip_vs_snat_table *tbl)
{
	int i;

	if (!tbl)
		return;

	for (i = 0; i <= 32; i++) {
		struct ip_vs_snat_zone *z = tbl->zones[i];

		if (!z)
			continue;

		ip_vs_zone_flush(z);
	}
}


static inline void ip_vs_snat_rule_add(struct ip_vs_dest_snat *new_rule, 
	               struct ip_vs_snat_node * node_head)
{
	__be32 dmask_ip = new_rule->dmask.ip;
	struct ip_vs_dest_snat *rule_pt = NULL; 

	list_for_each_entry(rule_pt, &node_head->rules, rule_list) {
		if (dmask_ip >= rule_pt->dmask.ip) {
			break;
		}
	}

	if (rule_pt)
		list_add_tail(&new_rule->rule_list, &rule_pt->rule_list);
}

static int
ip_vs_snat_assign(struct ip_vs_snat_table *tbl, struct ip_vs_service *svc)
{
	struct ip_vs_dest *dest;  

	list_for_each_entry(dest, &svc->destinations, n_list) {
		struct ip_vs_snat_zone *z;
		struct ip_vs_snat_node *node;
		struct ip_vs_dest_snat *rule = (struct ip_vs_dest_snat *)dest;
		__be32 key = 0;
		int smask_len = inet_mask_len(rule->smask.ip);

		z = tbl->zones[smask_len];
		if (!z && !(z = ip_vs_snat_zone_new(tbl, smask_len))) {
			IP_VS_ERR_RL("ip_vs_snat_zone_new return NULL\n");
			return -ENOMEM;
		}

		if (rule->saddr.ip) {
			struct ip_vs_dest *old_dest;

			if (rule->saddr.ip & ~Z_MASK(z)) {
				IP_VS_ERR_RL("SNAT rule saddr %pI4 not match zmask %pI4\n",
					&rule->saddr.ip, &Z_MASK(z));
				return -EINVAL;
			}

			key = ip_vs_snat_zone_key(rule->saddr.ip, z); 
			node = ip_vs_snat_node_find(z, key);

			if (!node) {
				node = ip_vs_snat_node_new(z, key);
				if (!node) {
					IP_VS_ERR_RL("ip_vs_snat_zone_new return NULL\n");
					return -ENOMEM;
				}
			}

			old_dest = ip_vs_snat_rule_find(&node->rules,
				rule->saddr.ip, rule->daddr.ip,
				dest->addr.ip, rule->out_dev);
			if (!old_dest) {
				atomic_inc(&dest->refcnt);
				//list_add(&rule->rule_list, &node->rules);
				ip_vs_snat_rule_add(rule, node);
			}

		IP_VS_DBG(6, "SNAT rule %s s:%pI4/%d d:%pI4/%d g:%pI4 k:%pI4 new_gw:%pI4\n",
			old_dest?"exists":"added", &rule->saddr.ip, smask_len,
			&rule->daddr.ip, inet_mask_len(rule->dmask.ip),
			&dest->addr.ip, &key, &rule->new_gateway.ip);
		}
	}

	return 0;
}

static int ip_vs_snat_init_svc(struct ip_vs_service *svc)
{
	struct ip_vs_snat_table *tbl;

	tbl = kzalloc(sizeof(struct ip_vs_snat_table), GFP_ATOMIC);
	if (tbl == NULL) {
		pr_err("%s(): no memory\n", __func__);
		return -ENOMEM;
	}

	IP_VS_DBG(6, "SNAT hash table allocated for current service\n");

	svc->sched_data = tbl;

	return ip_vs_snat_assign(tbl, svc);
}

static int ip_vs_snat_update_svc(struct ip_vs_service *svc)
{
	struct ip_vs_snat_table *tbl = svc->sched_data;

	IP_VS_DBG(6, "SNAT update hash table\n");
	ip_vs_snat_flush(tbl);
	return ip_vs_snat_assign(tbl, svc);
}

static int ip_vs_snat_done_svc(struct ip_vs_service *svc)
{
	struct ip_vs_snat_table *tbl = svc->sched_data;

	ip_vs_snat_flush(tbl);
	ip_vs_snat_table_free(tbl);
	IP_VS_DBG(6, "SNAT hash table released\n");
	return 0;
}
	    
static struct ip_vs_dest *ip_vs_snat_schedule(struct ip_vs_service *svc,
					    const struct sk_buff *skb)
{
	struct ip_vs_dest *dest; 
	struct ip_vs_snat_table *tbl;

	if (svc->af != AF_INET)
		return NULL;
	
	tbl = (struct ip_vs_snat_table *)svc->sched_data;
	dest = ip_vs_snat_get(svc->af, tbl, skb);

	if (!dest) {
		IP_VS_ERR_RL("SNAT: no destination available\n");
		return NULL;
	}
	
	return dest;
}

static struct ip_vs_scheduler ip_vs_snat_scheduler = {
	.name = "snat_sched",
	.refcnt = ATOMIC_INIT(0),
	.module = THIS_MODULE,
	.n_list = LIST_HEAD_INIT(ip_vs_snat_scheduler.n_list),
	.init_service = ip_vs_snat_init_svc,
	.done_service = ip_vs_snat_done_svc,
	.update_service = ip_vs_snat_update_svc,
	.schedule = ip_vs_snat_schedule,
};

static int __init ip_vs_snat_init(void)
{
	return register_ip_vs_scheduler(&ip_vs_snat_scheduler);
}

static void __exit ip_vs_snat_cleanup(void)
{
	unregister_ip_vs_scheduler(&ip_vs_snat_scheduler);
}

module_init(ip_vs_snat_init);
module_exit(ip_vs_snat_cleanup);
MODULE_LICENSE("GPL");
