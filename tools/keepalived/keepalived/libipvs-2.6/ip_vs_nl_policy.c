#include "libipvs.h"

#ifdef LIBIPVS_USE_NL
/* Policy definitions */
struct nla_policy ipvs_cmd_policy[IPVS_CMD_ATTR_MAX + 1] = {
	[IPVS_CMD_ATTR_SERVICE]		= { .type = NLA_NESTED },
	[IPVS_CMD_ATTR_DEST]		= { .type = NLA_NESTED },
	[IPVS_CMD_ATTR_DAEMON]		= { .type = NLA_NESTED },
	[IPVS_CMD_ATTR_TIMEOUT_TCP]	= { .type = NLA_U32 },
	[IPVS_CMD_ATTR_TIMEOUT_TCP_FIN]	= { .type = NLA_U32 },
	[IPVS_CMD_ATTR_TIMEOUT_UDP]	= { .type = NLA_U32 },
	[IPVS_CMD_ATTR_LADDR]		= { .type = NLA_NESTED},
	[IPVS_CMD_ATTR_SNATDEST]	= { .type = NLA_NESTED},
};

struct nla_policy ipvs_service_policy[IPVS_SVC_ATTR_MAX + 1] = {
	[IPVS_SVC_ATTR_AF]		= { .type = NLA_U16 },
	[IPVS_SVC_ATTR_PROTOCOL]	= { .type = NLA_U16 },
	[IPVS_SVC_ATTR_ADDR]		= { .type = NLA_UNSPEC,
					    .maxlen = sizeof(struct in6_addr) },
	[IPVS_SVC_ATTR_PORT]		= { .type = NLA_U16 },
	[IPVS_SVC_ATTR_FWMARK]		= { .type = NLA_U32 },
	[IPVS_SVC_ATTR_SCHED_NAME]	= { .type = NLA_STRING,
					    .maxlen = IP_VS_SCHEDNAME_MAXLEN },
	[IPVS_SVC_ATTR_FLAGS]		= { .type = NLA_UNSPEC,
					    .minlen = sizeof(struct ip_vs_flags),
					    .maxlen = sizeof(struct ip_vs_flags) },
	[IPVS_SVC_ATTR_TIMEOUT]		= { .type = NLA_U32 },
	[IPVS_SVC_ATTR_NETMASK]		= { .type = NLA_U32 },
	[IPVS_SVC_ATTR_STATS]		= { .type = NLA_NESTED },
};

struct nla_policy ipvs_dest_policy[IPVS_DEST_ATTR_MAX + 1] = {
	[IPVS_DEST_ATTR_ADDR]		= { .type = NLA_UNSPEC,
					    .maxlen = sizeof(struct in6_addr) },
	[IPVS_DEST_ATTR_PORT]		= { .type = NLA_U16 },
	[IPVS_DEST_ATTR_FWD_METHOD]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_WEIGHT]		= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_U_THRESH]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_L_THRESH]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_ACTIVE_CONNS]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_INACT_CONNS]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_PERSIST_CONNS]	= { .type = NLA_U32 },
	[IPVS_DEST_ATTR_STATS]		= { .type = NLA_NESTED },
	[IPVS_DEST_ATTR_SNATRULE] = {.type = NLA_NESTED},
};

/* Policy used for attributes in nested attribute IPVS_CMD_ATTR_SNAT_DEAST */
struct nla_policy ip_vs_snat_dest_policy[IPVS_SNAT_DEST_ATTR_MAX + 1] = {
	[IPVS_SNAT_DEST_ATTR_FADDR] = {.type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr)},
	[IPVS_SNAT_DEST_ATTR_FMASK] = {.type = NLA_U32},
	[IPVS_SNAT_DEST_ATTR_DADDR] = {.type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr)},
	[IPVS_SNAT_DEST_ATTR_DMASK] = {.type = NLA_U32},
	[IPVS_SNAT_DEST_ATTR_GW] = {.type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr)},
	[IPVS_SNAT_DEST_ATTR_MINIP] = {.type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr)},
	[IPVS_SNAT_DEST_ATTR_MAXIP] = {.type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr)},
	[IPVS_SNAT_DEST_ATTR_ALGO] = {.type = NLA_U8},
	[IPVS_SNAT_DEST_ATTR_NEWGW] = {.type = NLA_UNSPEC, .maxlen = sizeof(struct in6_addr)},
	[IPVS_SNAT_DEST_ATTR_CONNFLAG] = {.type = NLA_U32},
	[IPVS_SNAT_DEST_ATTR_OUTDEV] = {.type = NLA_STRING, .maxlen = IP_VS_IFNAME_MAXLEN},
};

struct nla_policy ipvs_laddr_policy[IPVS_LADDR_ATTR_MAX + 1] = {
	[IPVS_LADDR_ATTR_ADDR]		= { .type = NLA_UNSPEC,
					    .maxlen = sizeof(struct in6_addr) },
	[IPVS_LADDR_ATTR_PORT_CONFLICT]   = { .type = NLA_U64 },
	[IPVS_LADDR_ATTR_CONN_COUNTS]   = { .type = NLA_U32 },
};

struct nla_policy ipvs_stats_policy[IPVS_STATS_ATTR_MAX + 1] = {
	[IPVS_STATS_ATTR_CONNS]		= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_INPKTS]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_OUTPKTS]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_INBYTES]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_OUTBYTES]	= { .type = NLA_U64 },
	[IPVS_STATS_ATTR_CPS]		= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_INPPS]		= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_OUTPPS]	= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_INBPS]		= { .type = NLA_U32 },
	[IPVS_STATS_ATTR_OUTBPS]	= { .type = NLA_U32 },
};

struct nla_policy ipvs_info_policy[IPVS_INFO_ATTR_MAX + 1] = {
	[IPVS_INFO_ATTR_VERSION]	= { .type = NLA_U32 },
	[IPVS_INFO_ATTR_CONN_TAB_SIZE]	= { .type = NLA_U32 },
};

struct nla_policy ipvs_daemon_policy[IPVS_DAEMON_ATTR_MAX + 1] = {
	[IPVS_DAEMON_ATTR_STATE]	= { .type = NLA_U32 },
	[IPVS_DAEMON_ATTR_MCAST_IFN]	= { .type = NLA_STRING,
					    .maxlen = IP_VS_IFNAME_MAXLEN },
	[IPVS_DAEMON_ATTR_SYNC_ID]	= { .type = NLA_U32 },
};

#endif /* LIBIPVS_USE_NL */
