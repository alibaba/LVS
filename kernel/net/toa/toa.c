#include "toa.h"

/*
 *	TOA: Address is a new TCP Option
 *	Address include ip+port, Now only support IPV4
 */

unsigned long sk_data_ready_addr = 0;

/*
 * Statistics of toa in proc /proc/net/toa_stats
 */

struct toa_stats_entry toa_stats[] = {
	TOA_STAT_ITEM("syn_recv_sock_toa", SYN_RECV_SOCK_TOA_CNT),
	TOA_STAT_ITEM("syn_recv_sock_no_toa", SYN_RECV_SOCK_NO_TOA_CNT),
	TOA_STAT_ITEM("getname_toa_ok", GETNAME_TOA_OK_CNT),
	TOA_STAT_ITEM("getname_toa_mismatch", GETNAME_TOA_MISMATCH_CNT),
	TOA_STAT_ITEM("getname_toa_bypass", GETNAME_TOA_BYPASS_CNT),
	TOA_STAT_ITEM("getname_toa_empty", GETNAME_TOA_EMPTY_CNT),
	TOA_STAT_END
};

DEFINE_TOA_STAT(struct toa_stat_mib, ext_stats);

/*
 * Funcs for toa hooks
 */

/* Parse TCP options in skb, try to get client ip, port
 * @param skb [in] received skb, it should be a ack/get-ack packet.
 * @return NULL if we don't get client ip/port;
 *         value of toa_data in ret_ptr if we get client ip/port.
 */
static void *get_toa_data(struct sk_buff *skb)
{
	struct tcphdr *th;
	int length;
	unsigned char *ptr;

	struct toa_data tdata;

	void *ret_ptr = NULL;

	TOA_DBG("get_toa_data called\n");

	if (NULL != skb) {
		th = tcp_hdr(skb);
		length = (th->doff * 4) - sizeof(struct tcphdr);
		ptr = (unsigned char *) (th + 1);

		while (length > 0) {
			int opcode = *ptr++;
			int opsize;
			switch (opcode) {
			case TCPOPT_EOL:
				return NULL;
			case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
				length--;
				continue;
			default:
				opsize = *ptr++;
				if (opsize < 2)	/* "silly options" */
					return NULL;
				if (opsize > length)
					/* don't parse partial options */
					return NULL;
				if (TCPOPT_TOA == opcode &&
				    TCPOLEN_TOA == opsize) {
					memcpy(&tdata, ptr - 2, sizeof(tdata));
					TOA_DBG("find toa data: ip = "
						"%u.%u.%u.%u, port = %u\n",
						NIPQUAD(tdata.ip),
						ntohs(tdata.port));
					memcpy(&ret_ptr, &tdata,
						sizeof(ret_ptr));
					TOA_DBG("coded toa data: %p\n",
						ret_ptr);
					return ret_ptr;
				}
				ptr += opsize - 2;
				length -= opsize;
			}
		}
	}
	return NULL;
}

/* get client ip from socket
 * @param sock [in] the socket to getpeername() or getsockname()
 * @param uaddr [out] the place to put client ip, port
 * @param uaddr_len [out] lenth of @uaddr
 * @peer [in] if(peer), try to get remote address; if(!peer),
 *  try to get local address
 * @return return what the original inet_getname() returns.
 */
static int
inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,
		int *uaddr_len, int peer)
{
	int retval = 0;
	struct sock *sk = sock->sk;
	struct sockaddr_in *sin = (struct sockaddr_in *) uaddr;
	struct toa_data tdata;

	TOA_DBG("inet_getname_toa called, sk->sk_user_data is %p\n",
		sk->sk_user_data);

	/* call orginal one */
	retval = inet_getname(sock, uaddr, uaddr_len, peer);

	/* set our value if need */
	if (retval == 0 && NULL != sk->sk_user_data && peer) {
		if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready) {
			memcpy(&tdata, &sk->sk_user_data, sizeof(tdata));
			if (TCPOPT_TOA == tdata.opcode &&
			    TCPOLEN_TOA == tdata.opsize) {
				TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
				TOA_DBG("inet_getname_toa: set new sockaddr, "
					"ip %u.%u.%u.%u -> %u.%u.%u.%u, port "
					"%u -> %u\n",
					NIPQUAD(sin->sin_addr.s_addr),
					NIPQUAD(tdata.ip), ntohs(sin->sin_port),
					ntohs(tdata.port));
				sin->sin_port = tdata.port;
				sin->sin_addr.s_addr = tdata.ip;
			} else { /* sk_user_data doesn't belong to us */
				TOA_INC_STATS(ext_stats,
						GETNAME_TOA_MISMATCH_CNT);
				TOA_DBG("inet_getname_toa: invalid toa data, "
					"ip %u.%u.%u.%u port %u opcode %u "
					"opsize %u\n",
					NIPQUAD(tdata.ip), ntohs(tdata.port),
					tdata.opcode, tdata.opsize);
			}
		} else {
			TOA_INC_STATS(ext_stats, GETNAME_TOA_BYPASS_CNT);
		}
	} else { /* no need to get client ip */
		TOA_INC_STATS(ext_stats, GETNAME_TOA_EMPTY_CNT);
	}

	return retval;
}

#ifdef CONFIG_IP_VS_IPV6
static int
inet6_getname_toa(struct socket *sock, struct sockaddr *uaddr,
		  int *uaddr_len, int peer)
{
	int retval = 0;
	struct sock *sk = sock->sk;
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *) uaddr;
	struct toa_data tdata;

	TOA_DBG("inet6_getname_toa called, sk->sk_user_data is %p\n",
		sk->sk_user_data);

	/* call orginal one */
	retval = inet6_getname(sock, uaddr, uaddr_len, peer);

	/* set our value if need */
	if (retval == 0 && NULL != sk->sk_user_data && peer) {
		if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready) {
			memcpy(&tdata, &sk->sk_user_data, sizeof(tdata));
			if (TCPOPT_TOA == tdata.opcode &&
			    TCPOLEN_TOA == tdata.opsize) {
				TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
				sin->sin6_port = tdata.port;
				ipv6_addr_set(&sin->sin6_addr, 0, 0,
					      htonl(0x0000FFFF), tdata.ip);
			} else { /* sk_user_data doesn't belong to us */
				TOA_INC_STATS(ext_stats,
					      GETNAME_TOA_MISMATCH_CNT);
			}
		} else {
			TOA_INC_STATS(ext_stats, GETNAME_TOA_BYPASS_CNT);
		}
	} else { /* no need to get client ip */
		TOA_INC_STATS(ext_stats, GETNAME_TOA_EMPTY_CNT);
	}

	return retval;
}
#endif

/* The three way handshake has completed - we got a valid synack -
 * now create the new socket.
 * We need to save toa data into the new socket.
 * @param sk [out]  the socket
 * @param skb [in] the ack/ack-get packet
 * @param req [in] the open request for this connection
 * @param dst [out] route cache entry
 * @return NULL if fail new socket if succeed.
 */
static struct sock *
tcp_v4_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
			struct request_sock *req, struct dst_entry *dst)
{
	struct sock *newsock = NULL;

	TOA_DBG("tcp_v4_syn_recv_sock_toa called\n");

	/* call orginal one */
	newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst);

	/* set our value if need */
	if (NULL != newsock && NULL == newsock->sk_user_data) {
		newsock->sk_user_data = get_toa_data(skb);
		if (NULL != newsock->sk_user_data)
			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_TOA_CNT);
		else
			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_TOA_CNT);
		TOA_DBG("tcp_v4_syn_recv_sock_toa: set "
			"sk->sk_user_data to %p\n",
			newsock->sk_user_data);
	}
	return newsock;
}

#ifdef CONFIG_IP_VS_IPV6
static struct sock *
tcp_v6_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
			 struct request_sock *req, struct dst_entry *dst)
{
	struct sock *newsock = NULL;

	TOA_DBG("tcp_v4_syn_recv_sock_toa called\n");

	/* call orginal one */
	newsock = tcp_v6_syn_recv_sock(sk, skb, req, dst);

	/* set our value if need */
	if (NULL != newsock && NULL == newsock->sk_user_data) {
		newsock->sk_user_data = get_toa_data(skb);
		if (NULL != newsock->sk_user_data) {
			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_TOA_CNT);
		else
			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_TOA_CNT);
	}
	return newsock;
}
#endif

/*
 * HOOK FUNCS
 */

/* replace the functions with our functions */
static inline int
hook_toa_functions(void)
{
	/* hook inet_getname for ipv4 */
	struct proto_ops *inet_stream_ops_p =
			(struct proto_ops *)&inet_stream_ops;
	/* hook tcp_v4_syn_recv_sock for ipv4 */
	struct inet_connection_sock_af_ops *ipv4_specific_p =
			(struct inet_connection_sock_af_ops *)&ipv4_specific;
#ifdef CONFIG_IP_VS_IPV6
	/* hook inet6_getname for ipv6 */
	struct proto_ops *inet6_stream_ops_p =
			struct proto_ops *)&inet6_stream_ops;
	/* hook tcp_v6_syn_recv_sock for ipv6 */
	struct inet_connection_sock_af_ops *ipv6_specific_p =
			(struct inet_connection_sock_af_ops *)&ipv6_specific;
#endif

	inet_stream_ops_p->getname = inet_getname_toa;
	TOA_INFO("CPU [%u] hooked inet_getname <%p> --> <%p>\n",
		smp_processor_id(), inet_getname, inet_stream_ops_p->getname);

#ifdef CONFIG_IP_VS_IPV6
	inet6_stream_ops_p->getname = inet6_getname_toa;
	TOA_INFO("CPU [%u] hooked inet6_getname <%p> --> <%p>\n",
		smp_processor_id(), inet6_getname, inet6_stream_ops_p->getname);
#endif

	ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock_toa;
	TOA_INFO("CPU [%u] hooked tcp_v4_syn_recv_sock <%p> --> <%p>\n",
		smp_processor_id(), tcp_v4_syn_recv_sock,
		ipv4_specific_p->syn_recv_sock);

#ifdef CONFIG_IP_VS_IPV6
	ipv6_specific_p->syn_recv_sock = tcp_v6_syn_recv_sock_toa;
	TOA_INFO("CPU [%u] hooked tcp_v6_syn_recv_sock <%p> --> <%p>\n",
		smp_processor_id(), tcp_v6_syn_recv_sock,
		ipv6_specific_p->syn_recv_sock);
#endif

	return 0;
}

/* replace the functions to original ones */
static int
unhook_toa_functions(void)
{
	/* unhook inet_getname for ipv4 */
	struct proto_ops *inet_stream_ops_p =
			(struct proto_ops *)&inet_stream_ops;
	/* unhook tcp_v4_syn_recv_sock for ipv4 */
	struct inet_connection_sock_af_ops *ipv4_specific_p =
			(struct inet_connection_sock_af_ops *)&ipv4_specific;

#ifdef CONFIG_IP_VS_IPV6
	/* unhook inet6_getname for ipv6 */
	struct proto_ops *inet6_stream_ops_p =
			(struct proto_ops *)&inet6_stream_ops;
	/* unhook tcp_v6_syn_recv_sock for ipv6 */
	struct inet_connection_sock_af_ops *ipv6_specific_p =
			(struct inet_connection_sock_af_ops *)&ipv6_specific;
#endif
	inet_stream_ops_p->getname = inet_getname;
	TOA_INFO("CPU [%u] unhooked inet_getname\n",
		smp_processor_id());

#ifdef CONFIG_IP_VS_IPV6
	inet6_stream_ops_p->getname = inet6_getname;
	TOA_INFO("CPU [%u] unhooked inet6_getname\n",
		smp_processor_id());
#endif

	ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock;
	TOA_INFO("CPU [%u] unhooked tcp_v4_syn_recv_sock\n",
		smp_processor_id());

#ifdef CONFIG_IP_VS_IPV6
	ipv6_specific_p->syn_recv_sock = tcp_v6_syn_recv_sock;
	TOA_INFO("CPU [%u] unhooked tcp_v6_syn_recv_sock\n",
		smp_processor_id());
#endif

	return 0;
}

/*
 * Statistics of toa in proc /proc/net/toa_stats
 */
static int toa_stats_show(struct seq_file *seq, void *v)
{
	int i, j, cpu_nr;

	/* print CPU first */
	seq_printf(seq, "                                  ");
	cpu_nr = num_possible_cpus();
	for (i = 0; i < cpu_nr; i++)
		if (cpu_online(i))
			seq_printf(seq, "CPU%d       ", i);
	seq_putc(seq, '\n');

	i = 0;
	while (NULL != toa_stats[i].name) {
		seq_printf(seq, "%-25s:", toa_stats[i].name);
		for (j = 0; j < cpu_nr; j++) {
			if (cpu_online(j)) {
				seq_printf(seq, "%10lu ", *(
					((unsigned long *) per_cpu_ptr(
					ext_stats, j)) + toa_stats[i].entry
					));
			}
		}
		seq_putc(seq, '\n');
		i++;
	}
	return 0;
}

static int toa_stats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, toa_stats_show, NULL);
}

static const struct file_operations toa_stats_fops = {
	.owner = THIS_MODULE,
	.open = toa_stats_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 * TOA module init and destory
 */

/* module init */
static int __init
toa_init(void)
{

	TOA_INFO("TOA " TOA_VERSION " by pukong.wjm\n");

	/* alloc statistics array for toa */
	ext_stats = alloc_percpu(struct toa_stat_mib);
	if (NULL == ext_stats)
		return 1;
	proc_net_fops_create(&init_net, "toa_stats", 0, &toa_stats_fops);

	/* get the address of function sock_def_readable
	 * so later we can know whether the sock is for rpc, tux or others
	 */
	sk_data_ready_addr = kallsyms_lookup_name("sock_def_readable");
	TOA_INFO("CPU [%u] sk_data_ready_addr = "
		"kallsyms_lookup_name(sock_def_readable) = %lu\n",
		 smp_processor_id(), sk_data_ready_addr);
	if (0 == sk_data_ready_addr) {
		TOA_INFO("cannot find sock_def_readable.\n");
		goto err;
	}

	/* hook funcs for parse and get toa */
	hook_toa_functions();

	TOA_INFO("toa loaded\n");
	return 0;

err:
	proc_net_remove(&init_net, "toa_stats");
	if (NULL != ext_stats) {
		free_percpu(ext_stats);
		ext_stats = NULL;
	}

	return 1;
}

/* module cleanup*/
static void __exit
toa_exit(void)
{
	unhook_toa_functions();
	synchronize_net();

	proc_net_remove(&init_net, "toa_stats");
	if (NULL != ext_stats) {
		free_percpu(ext_stats);
		ext_stats = NULL;
	}
	TOA_INFO("toa unloaded\n");
}

module_init(toa_init);
module_exit(toa_exit);
MODULE_LICENSE("GPL");
