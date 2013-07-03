#include <linux/types.h>
#include <linux/percpu.h>
#include <net/ip_vs.h>


int ip_vs_new_stats(struct ip_vs_stats **p)
{
	if(NULL == p)
		return -EINVAL;

	*p = alloc_percpu(struct ip_vs_stats);
	if(NULL == *p) {
		pr_err("%s: allocate per cpu varible failed \n", __func__);
		return -ENOMEM;
	}

	/* Initial stats */
	ip_vs_zero_stats(*p);

	return 0;
}

void ip_vs_del_stats(struct ip_vs_stats* p)
{
	if(NULL == p)
		return;

	free_percpu(p);

	return;
}

void ip_vs_zero_stats(struct ip_vs_stats* stats)
{
	int i = 0;

	if(NULL == stats) {
		pr_err("%s: Invaild point \n", __func__);
		return;
	}

	for_each_online_cpu(i) {
		ip_vs_stats_cpu(stats, i).conns    = 0;
		ip_vs_stats_cpu(stats, i).inpkts   = 0;
		ip_vs_stats_cpu(stats, i).outpkts  = 0;
		ip_vs_stats_cpu(stats, i).inbytes  = 0;
		ip_vs_stats_cpu(stats, i).outbytes = 0;
	}

	return;
}

void ip_vs_in_stats(struct ip_vs_conn *cp, struct sk_buff *skb)
{
	struct ip_vs_dest *dest = cp->dest;
	if (dest && (dest->flags & IP_VS_DEST_F_AVAILABLE)) {
		ip_vs_stats_this_cpu(dest->stats).inpkts++;
		ip_vs_stats_this_cpu(dest->stats).inbytes += skb->len;

		ip_vs_stats_this_cpu(dest->svc->stats).inpkts++;
		ip_vs_stats_this_cpu(dest->svc->stats).inbytes += skb->len;

		ip_vs_stats_this_cpu(ip_vs_stats).inpkts++;
		ip_vs_stats_this_cpu(ip_vs_stats).inbytes += skb->len;
	}

	return;
}

void ip_vs_out_stats(struct ip_vs_conn *cp, struct sk_buff *skb)
{
	struct ip_vs_dest *dest = cp->dest;
	if (dest && (dest->flags & IP_VS_DEST_F_AVAILABLE)) {
		ip_vs_stats_this_cpu(dest->stats).outpkts++;
		ip_vs_stats_this_cpu(dest->stats).outbytes += skb->len;

		ip_vs_stats_this_cpu(dest->svc->stats).outpkts++;
		ip_vs_stats_this_cpu(dest->svc->stats).outbytes += skb->len;

		ip_vs_stats_this_cpu(ip_vs_stats).outpkts++;
		ip_vs_stats_this_cpu(ip_vs_stats).outbytes += skb->len;
	}
	return;
}

void ip_vs_conn_stats(struct ip_vs_conn *cp, struct ip_vs_service *svc)
{
	struct ip_vs_dest *dest = cp->dest;
	if(dest) {
		ip_vs_stats_this_cpu(dest->stats).conns++;

		ip_vs_stats_this_cpu(dest->svc->stats).conns++;

		ip_vs_stats_this_cpu(ip_vs_stats).conns++;
	}

	return;
}

