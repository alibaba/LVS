#ifndef _LINUX_NETPOLL_TARGETS_H
#define _LINUX_NETPOLL_TARGETS_H

#include <linux/netpoll.h>

#include <linux/configfs.h>
#include <linux/slab.h>
#include <linux/string.h>

struct netpoll_targets {
	struct list_head list;
	spinlock_t lock;
	u16 default_local_port, default_remote_port;
#ifdef	CONFIG_NETPOLL_TARGETS_DYNAMIC
	struct configfs_subsystem configfs_subsys;
#endif
	struct notifier_block netdev_notifier;
	char *subsys_name;
};
#define DEFINE_NETPOLL_TARGETS(x) struct netpoll_targets x = \
	{ .list = LIST_HEAD_INIT(x.list), \
	  .lock = __SPIN_LOCK_UNLOCKED(x.lock) }

#define NETPOLL_DISABLED	0
#define NETPOLL_SETTINGUP	1
#define NETPOLL_ENABLED		2
#define NETPOLL_CLEANING	3

/**
 * struct netpoll_target - Represents a configured netpoll target.
 * @list:	Links this target into the netpoll_targets.list.
 * @item:	Links us into the configfs subsystem hierarchy.
 * @np_state:	Enabled / Disabled / SettingUp / Cleaning
 *		Visible from userspace (read-write) as "enabled".
 *		We maintain a state machine here of the valid states.  Either a
 *		target is enabled or disabled, but it may also be in a
 *		transitional state whereby nobody is allowed to act on the
 *		target other than whoever owns the transition.
 *
 *		Also, other parameters of a target may be modified at
 *		runtime only when it is disabled (np_state == NETPOLL_ENABLED).
 * @np:		The netpoll structure for this target.
 *		Contains the other userspace visible parameters:
 *		dev_name	(read-write)
 *		local_port	(read-write)
 *		remote_port	(read-write)
 *		local_ip	(read-write)
 *		remote_ip	(read-write)
 *		local_mac	(read-only)
 *		remote_mac	(read-write)
 */
struct netpoll_target {
	struct netpoll_targets *nts;
	struct list_head	list;
#ifdef	CONFIG_NETPOLL_TARGETS_DYNAMIC
	struct config_item	item;
#endif
	int			np_state;
	struct netpoll		np;
	struct work_struct	cleanup_work;
};

#ifdef	CONFIG_NETPOLL_TARGETS_DYNAMIC
void netpoll_target_get(struct netpoll_target *nt);
void netpoll_target_put(struct netpoll_target *nt);
#else
static void netpoll_target_get(struct netpoll_target *nt) {}
static void netpoll_target_put(struct netpoll_target *nt) {}
#endif

int register_netpoll_targets(const char *subsys_name,
			     struct netpoll_targets *nts,
			     char *static_targets);
void unregister_netpoll_targets(struct netpoll_targets *nts);

#endif /* _LINUX_NETPOLL_TARGETS_H */
