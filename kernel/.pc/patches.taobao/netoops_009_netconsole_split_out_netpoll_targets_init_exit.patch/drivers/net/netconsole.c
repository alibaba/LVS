/*
 *  linux/drivers/net/netconsole.c
 *
 *  Copyright (C) 2001  Ingo Molnar <mingo@redhat.com>
 *
 *  This file contains the implementation of an IRQ-safe, crash-safe
 *  kernel console implementation that outputs kernel messages to the
 *  network.
 *
 * Modification history:
 *
 * 2001-09-17    started by Ingo Molnar.
 * 2003-08-11    2.6 port by Matt Mackall
 *               simplified options
 *               generic card hooks
 *               works non-modular
 * 2003-09-07    rewritten with netpoll api
 */

/****************************************************************
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2, or (at your option)
 *      any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************/

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/netpoll.h>
#include <linux/inet.h>
#include <linux/configfs.h>

MODULE_AUTHOR("Maintainer: Matt Mackall <mpm@selenic.com>");
MODULE_DESCRIPTION("Console driver for network interfaces");
MODULE_LICENSE("GPL");

#define MAX_PARAM_LENGTH	256
#define MAX_PRINT_CHUNK		1000

static char config[MAX_PARAM_LENGTH];
module_param_string(netconsole, config, MAX_PARAM_LENGTH, 0);
MODULE_PARM_DESC(netconsole, " netconsole=[src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr]");

#ifndef	MODULE
static int __init option_setup(char *opt)
{
	strlcpy(config, opt, MAX_PARAM_LENGTH);
	return 1;
}
__setup("netconsole=", option_setup);
#endif	/* MODULE */

struct netpoll_targets {
	struct list_head list;
	spinlock_t lock;
#ifdef	CONFIG_NETCONSOLE_DYNAMIC
	struct configfs_subsystem configfs_subsys;
#endif
	struct notifier_block netdev_notifier;
};
#define DEFINE_NETPOLL_TARGETS(x) struct netpoll_targets x = \
	{ .list = LIST_HEAD_INIT(x.list), \
	  .lock = __SPIN_LOCK_UNLOCKED(x.lock) }
static DEFINE_NETPOLL_TARGETS(targets);

#define NETPOLL_DISABLED	0
#define NETPOLL_SETTINGUP	1
#define NETPOLL_ENABLED		2
#define NETPOLL_CLEANING	3

/**
 * struct netconsole_target - Represents a configured netconsole target.
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
struct netconsole_target {
	struct list_head	list;
#ifdef	CONFIG_NETCONSOLE_DYNAMIC
	struct config_item	item;
#endif
	int			np_state;
	struct netpoll		np;
	struct work_struct	cleanup_work;
};

static void netconsole_target_get(struct netconsole_target *nt);
static void netconsole_target_put(struct netconsole_target *nt);

static void deferred_netpoll_cleanup(struct work_struct *work)
{
	struct netconsole_target *nt;
	unsigned long flags;

	nt = container_of(work, struct netconsole_target, cleanup_work);
	netpoll_cleanup(&nt->np);

	spin_lock_irqsave(&targets.lock, flags);
	BUG_ON(nt->np_state != NETPOLL_CLEANING);
	nt->np_state = NETPOLL_DISABLED;
	spin_unlock_irqrestore(&targets.lock, flags);

	netconsole_target_put(nt);
}

/* Allocate new target (from boot/module param) and setup netpoll for it */
static struct netconsole_target *alloc_param_target(char *target_config)
{
	int err = -ENOMEM;
	struct netconsole_target *nt;

	/*
	 * Allocate and initialize with defaults.
	 * Note that these targets get their config_item fields zeroed-out.
	 */
	nt = kzalloc(sizeof(*nt), GFP_KERNEL);
	if (!nt) {
		printk(KERN_ERR "netconsole: failed to allocate memory\n");
		goto fail;
	}

	nt->np.name = "netconsole";
	strlcpy(nt->np.dev_name, "eth0", IFNAMSIZ);
	nt->np.local_port = 6665;
	nt->np.remote_port = 6666;
	memset(nt->np.remote_mac, 0xff, ETH_ALEN);
	INIT_WORK(&nt->cleanup_work, deferred_netpoll_cleanup);

	/* Parse parameters and setup netpoll */
	err = netpoll_parse_options(&nt->np, target_config);
	if (err)
		goto fail;

	err = netpoll_setup(&nt->np);
	if (err)
		goto fail;

	nt->np_state = NETPOLL_ENABLED;

	return nt;

fail:
	kfree(nt);
	return ERR_PTR(err);
}

/* Cleanup netpoll for given target (from boot/module param) and free it */
static void free_param_target(struct netconsole_target *nt)
{
	cancel_work_sync(&nt->cleanup_work);
	if (nt->np_state == NETPOLL_CLEANING || nt->np_state == NETPOLL_ENABLED)
		netpoll_cleanup(&nt->np);
	kfree(nt);
}

#ifdef	CONFIG_NETCONSOLE_DYNAMIC

/*
 * Our subsystem hierarchy is:
 *
 * /sys/kernel/config/netconsole/
 *				|
 *				<target>/
 *				|	enabled
 *				|	dev_name
 *				|	local_port
 *				|	remote_port
 *				|	local_ip
 *				|	remote_ip
 *				|	local_mac
 *				|	remote_mac
 *				|
 *				<target>/...
 */

struct netconsole_target_attr {
	struct configfs_attribute	attr;
	ssize_t				(*show)(struct netconsole_target *nt,
						char *buf);
	ssize_t				(*store)(struct netconsole_target *nt,
						 const char *buf,
						 size_t count);
};

static struct netconsole_target *to_target(struct config_item *item)
{
	return item ?
		container_of(item, struct netconsole_target, item) :
		NULL;
}

/*
 * Wrapper over simple_strtol (base 10) with sanity and range checking.
 * We return (signed) long only because we may want to return errors.
 * Do not use this to convert numbers that are allowed to be negative.
 */
static long strtol10_check_range(const char *cp, long min, long max)
{
	long ret;
	char *p = (char *) cp;

	WARN_ON(min < 0);
	WARN_ON(max < min);

	ret = simple_strtol(p, &p, 10);

	if (*p && (*p != '\n')) {
		printk(KERN_ERR "netconsole: invalid input\n");
		return -EINVAL;
	}
	if ((ret < min) || (ret > max)) {
		printk(KERN_ERR "netconsole: input %ld must be between "
				"%ld and %ld\n", ret, min, max);
		return -EINVAL;
	}

	return ret;
}

/*
 * Attribute operations for netconsole_target.
 */

static ssize_t show_enabled(struct netconsole_target *nt, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n",
			nt->np_state == NETPOLL_ENABLED);
}

static ssize_t show_dev_name(struct netconsole_target *nt, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", nt->np.dev_name);
}

static ssize_t show_local_port(struct netconsole_target *nt, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", nt->np.local_port);
}

static ssize_t show_remote_port(struct netconsole_target *nt, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", nt->np.remote_port);
}

static ssize_t show_local_ip(struct netconsole_target *nt, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%pI4\n", &nt->np.local_ip);
}

static ssize_t show_remote_ip(struct netconsole_target *nt, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%pI4\n", &nt->np.remote_ip);
}

static ssize_t show_local_mac(struct netconsole_target *nt, char *buf)
{
	struct net_device *dev = nt->np.dev;
	static const u8 bcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	return snprintf(buf, PAGE_SIZE, "%pM\n", dev ? dev->dev_addr : bcast);
}

static ssize_t show_remote_mac(struct netconsole_target *nt, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%pM\n", nt->np.remote_mac);
}

/*
 * This one is special -- targets created through the configfs interface
 * are not enabled (and the corresponding netpoll activated) by default.
 * The user is expected to set the desired parameters first (which
 * would enable him to dynamically add new netpoll targets for new
 * network interfaces as and when they come up).
 */
static ssize_t store_enabled(struct netconsole_target *nt,
			     const char *buf,
			     size_t count)
{
	unsigned long flags;
	int err;
	long enabled;

	enabled = strtol10_check_range(buf, 0, 1);
	if (enabled < 0)
		return enabled;

	if (enabled) {	/* 1 */
		spin_lock_irqsave(&targets.lock, flags);
		if (nt->np_state != NETPOLL_DISABLED)
			goto busy;
		else {
			nt->np_state = NETPOLL_SETTINGUP;
			/*
			 * Nominally, we would grab an extra reference on the
			 * config_item here for dynamic targets while we let go
			 * of the lock, but this isn't required in this case
			 * because there is a reference implicitly held by the
			 * caller of the store operation.
			 */
			spin_unlock_irqrestore(&targets.lock, flags);
		}

		/*
		 * Skip netpoll_parse_options() -- all the attributes are
		 * already configured via configfs. Just print them out.
		 */
		netpoll_print_options(&nt->np);

		err = netpoll_setup(&nt->np);
		spin_lock_irqsave(&targets.lock, flags);
		if (err)
			nt->np_state = NETPOLL_DISABLED;
		else
			nt->np_state = NETPOLL_ENABLED;
		spin_unlock_irqrestore(&targets.lock, flags);
		if (err)
			return err;

		printk(KERN_INFO "netconsole: network logging started\n");
	} else {	/* 0 */
		spin_lock_irqsave(&targets.lock, flags);
		if (nt->np_state == NETPOLL_ENABLED)
			nt->np_state = NETPOLL_CLEANING;
		else if (nt->np_state != NETPOLL_DISABLED)
			goto busy;
		spin_unlock_irqrestore(&targets.lock, flags);

		netpoll_cleanup(&nt->np);

		spin_lock_irqsave(&targets.lock, flags);
		nt->np_state = NETPOLL_DISABLED;
		spin_unlock_irqrestore(&targets.lock, flags);
	}

	return strnlen(buf, count);
busy:
	spin_unlock_irqrestore(&targets.lock, flags);
	return -EBUSY;
}

static ssize_t store_dev_name(struct netconsole_target *nt,
			      const char *buf,
			      size_t count)
{
	size_t len;

	strlcpy(nt->np.dev_name, buf, IFNAMSIZ);

	/* Get rid of possible trailing newline from echo(1) */
	len = strnlen(nt->np.dev_name, IFNAMSIZ);
	if (nt->np.dev_name[len - 1] == '\n')
		nt->np.dev_name[len - 1] = '\0';

	return strnlen(buf, count);
}

static ssize_t store_local_port(struct netconsole_target *nt,
				const char *buf,
				size_t count)
{
	long local_port;
#define __U16_MAX	((__u16) ~0U)

	local_port = strtol10_check_range(buf, 0, __U16_MAX);
	if (local_port < 0)
		return local_port;

	nt->np.local_port = local_port;

	return strnlen(buf, count);
}

static ssize_t store_remote_port(struct netconsole_target *nt,
				 const char *buf,
				 size_t count)
{
	long remote_port;
#define __U16_MAX	((__u16) ~0U)

	remote_port = strtol10_check_range(buf, 0, __U16_MAX);
	if (remote_port < 0)
		return remote_port;

	nt->np.remote_port = remote_port;

	return strnlen(buf, count);
}

static ssize_t store_local_ip(struct netconsole_target *nt,
			      const char *buf,
			      size_t count)
{
	nt->np.local_ip = in_aton(buf);

	return strnlen(buf, count);
}

static ssize_t store_remote_ip(struct netconsole_target *nt,
			       const char *buf,
			       size_t count)
{
	nt->np.remote_ip = in_aton(buf);

	return strnlen(buf, count);
}

static ssize_t store_remote_mac(struct netconsole_target *nt,
				const char *buf,
				size_t count)
{
	u8 remote_mac[ETH_ALEN];
	char *p = (char *) buf;
	int i;

	for (i = 0; i < ETH_ALEN - 1; i++) {
		remote_mac[i] = simple_strtoul(p, &p, 16);
		if (*p != ':')
			goto invalid;
		p++;
	}
	remote_mac[ETH_ALEN - 1] = simple_strtoul(p, &p, 16);
	if (*p && (*p != '\n'))
		goto invalid;

	memcpy(nt->np.remote_mac, remote_mac, ETH_ALEN);

	return strnlen(buf, count);

invalid:
	printk(KERN_ERR "netconsole: invalid input\n");
	return -EINVAL;
}

/*
 * Attribute definitions for netconsole_target.
 */

#define __NETCONSOLE_TARGET_ATTR_RO(_name, _prefix_...)			\
static struct netconsole_target_attr netconsole_target_##_name =	\
	__CONFIGFS_ATTR(_name, S_IRUGO, show_##_prefix_##_name, NULL)

#define __NETCONSOLE_TARGET_ATTR_RW(_name, _prefix_...)			\
static struct netconsole_target_attr netconsole_target_##_name =	\
	__CONFIGFS_ATTR(_name, S_IRUGO | S_IWUSR,			\
			show_##_prefix_##_name, store_##_prefix_##_name)

#define NETCONSOLE_WRAP_ATTR_STORE(_name)				\
static ssize_t store_locked_##_name(struct netconsole_target *nt,	\
				    const char *buf,			\
				    size_t count)			\
{									\
	unsigned long flags;						\
	ssize_t ret;							\
	spin_lock_irqsave(&targets.lock, flags);			\
	if (nt->np_state != NETPOLL_DISABLED) {				\
		printk(KERN_ERR "netconsole: target (%s) is enabled, "	\
				"disable to update parameters\n",	\
				config_item_name(&nt->item));		\
		spin_unlock_irqrestore(&targets.lock, flags);		\
		return -EBUSY;						\
	}								\
	ret = store_##_name(nt, buf, count);				\
	spin_unlock_irqrestore(&targets.lock, flags);			\
	return ret;							\
}

#define NETCONSOLE_WRAP_ATTR_SHOW(_name)				\
static ssize_t show_locked_##_name(struct netconsole_target *nt, char *buf) \
{									\
	unsigned long flags;						\
	ssize_t ret;							\
	spin_lock_irqsave(&targets.lock, flags);			\
	ret = show_##_name(nt, buf);					\
	spin_unlock_irqrestore(&targets.lock, flags);			\
	return ret;							\
}

#define NETCONSOLE_TARGET_ATTR_RW(_name)				\
		NETCONSOLE_WRAP_ATTR_STORE(_name)			\
		NETCONSOLE_WRAP_ATTR_SHOW(_name)			\
		__NETCONSOLE_TARGET_ATTR_RW(_name, locked_)

#define NETCONSOLE_TARGET_ATTR_RO(_name)				\
		NETCONSOLE_WRAP_ATTR_SHOW(_name)			\
		__NETCONSOLE_TARGET_ATTR_RO(_name, locked_)

__NETCONSOLE_TARGET_ATTR_RW(enabled);
NETCONSOLE_TARGET_ATTR_RW(dev_name);
NETCONSOLE_TARGET_ATTR_RW(local_port);
NETCONSOLE_TARGET_ATTR_RW(remote_port);
NETCONSOLE_TARGET_ATTR_RW(local_ip);
NETCONSOLE_TARGET_ATTR_RW(remote_ip);
NETCONSOLE_TARGET_ATTR_RO(local_mac);
NETCONSOLE_TARGET_ATTR_RW(remote_mac);

static struct configfs_attribute *netconsole_target_attrs[] = {
	&netconsole_target_enabled.attr,
	&netconsole_target_dev_name.attr,
	&netconsole_target_local_port.attr,
	&netconsole_target_remote_port.attr,
	&netconsole_target_local_ip.attr,
	&netconsole_target_remote_ip.attr,
	&netconsole_target_local_mac.attr,
	&netconsole_target_remote_mac.attr,
	NULL,
};

/*
 * Item operations and type for netconsole_target.
 */

static void netconsole_target_release(struct config_item *item)
{
	kfree(to_target(item));
}

static ssize_t netconsole_target_attr_show(struct config_item *item,
					   struct configfs_attribute *attr,
					   char *buf)
{
	ssize_t ret = -EINVAL;
	struct netconsole_target *nt = to_target(item);
	struct netconsole_target_attr *na =
		container_of(attr, struct netconsole_target_attr, attr);

	if (na->show)
		ret = na->show(nt, buf);

	return ret;
}

static ssize_t netconsole_target_attr_store(struct config_item *item,
					    struct configfs_attribute *attr,
					    const char *buf,
					    size_t count)
{
	ssize_t ret = -EINVAL;
	struct netconsole_target *nt = to_target(item);
	struct netconsole_target_attr *na =
		container_of(attr, struct netconsole_target_attr, attr);

	if (na->store)
		ret = na->store(nt, buf, count);

	return ret;
}

static struct configfs_item_operations netconsole_target_item_ops = {
	.release		= netconsole_target_release,
	.show_attribute		= netconsole_target_attr_show,
	.store_attribute	= netconsole_target_attr_store,
};

static struct config_item_type netconsole_target_type = {
	.ct_attrs		= netconsole_target_attrs,
	.ct_item_ops		= &netconsole_target_item_ops,
	.ct_owner		= THIS_MODULE,
};

/*
 * Group operations and type for netconsole_subsys.
 */

static struct config_item *make_netconsole_target(struct config_group *group,
						  const char *name)
{
	unsigned long flags;
	struct netconsole_target *nt;

	/*
	 * Allocate and initialize with defaults.
	 * Target is disabled at creation (enabled == 0).
	 */
	nt = kzalloc(sizeof(*nt), GFP_KERNEL);
	if (!nt) {
		printk(KERN_ERR "netconsole: failed to allocate memory\n");
		return ERR_PTR(-ENOMEM);
	}

	nt->np.name = "netconsole";
	strlcpy(nt->np.dev_name, "eth0", IFNAMSIZ);
	nt->np.local_port = 6665;
	nt->np.remote_port = 6666;
	memset(nt->np.remote_mac, 0xff, ETH_ALEN);
	INIT_WORK(&nt->cleanup_work, deferred_netpoll_cleanup);

	/* Initialize the config_item member */
	config_item_init_type_name(&nt->item, name, &netconsole_target_type);

	/* Adding, but it is disabled */
	spin_lock_irqsave(&targets.lock, flags);
	list_add(&nt->list, &targets.list);
	spin_unlock_irqrestore(&targets.lock, flags);

	return &nt->item;
}

static void drop_netconsole_target(struct config_group *group,
				   struct config_item *item)
{
	unsigned long flags;
	struct netconsole_target *nt = to_target(item);

	spin_lock_irqsave(&targets.lock, flags);
	list_del(&nt->list);
	spin_unlock_irqrestore(&targets.lock, flags);

	/*
	 * The target may have never been disabled, or was disabled due
	 * to a netdev event, but we haven't had the chance to clean
	 * things up yet.
	 *
	 * We can't wait for the target to be cleaned up by its
	 * scheduled work however, as that work doesn't pin this module
	 * in place.
	 */
	cancel_work_sync(&nt->cleanup_work);
	if (nt->np_state == NETPOLL_ENABLED || nt->np_state == NETPOLL_CLEANING)
		netpoll_cleanup(&nt->np);

	netconsole_target_put(nt);
}

static struct configfs_group_operations netconsole_subsys_group_ops = {
	.make_item	= make_netconsole_target,
	.drop_item	= drop_netconsole_target,
};

static struct config_item_type netconsole_subsys_type = {
	.ct_group_ops	= &netconsole_subsys_group_ops,
	.ct_owner	= THIS_MODULE,
};

static int __init dynamic_netpoll_targets_init(struct netpoll_targets *nts)
{
	struct configfs_subsystem *subsys = &nts->configfs_subsys;

	config_group_init(&subsys->su_group);
	mutex_init(&subsys->su_mutex);
	strncpy((char *)&subsys->su_group.cg_item.ci_namebuf, "netconsole",
		CONFIGFS_ITEM_NAME_LEN);
	subsys->su_group.cg_item.ci_type = &netconsole_subsys_type;
	return configfs_register_subsystem(subsys);
}

static void __exit dynamic_netpoll_targets_exit(struct netpoll_targets *nts)
{
	configfs_unregister_subsystem(&nts->configfs_subsys);
}

/*
 * Targets that were created by parsing the boot/module option string
 * do not exist in the configfs hierarchy (and have NULL names) and will
 * never go away, so make these a no-op for them.
 */
static void netconsole_target_get(struct netconsole_target *nt)
{
	if (config_item_name(&nt->item))
		config_item_get(&nt->item);
}

static void netconsole_target_put(struct netconsole_target *nt)
{
	if (config_item_name(&nt->item))
		config_item_put(&nt->item);
}

#else	/* !CONFIG_NETCONSOLE_DYNAMIC */

static int __init dynamic_netpoll_targets_init(const char *subsys_name,
					       struct netpoll_targets *nts)
{
	return 0;
}

static void __exit dynamic_netpoll_targets_exit(struct netpoll_targets *nts)
{
}

/*
 * No danger of targets going away from under us when dynamic
 * reconfigurability is off.
 */
static void netconsole_target_get(struct netconsole_target *nt)
{
}

static void netconsole_target_put(struct netconsole_target *nt)
{
}

#endif	/* CONFIG_NETCONSOLE_DYNAMIC */

/*
 * Call netpoll_cleanup on this target asynchronously.
 * targets.lock is required.
 */
static void defer_netpoll_cleanup(struct netconsole_target *nt)
{
	if (nt->np_state != NETPOLL_ENABLED)
		return;
	netconsole_target_get(nt);
	nt->np_state = NETPOLL_CLEANING;
	schedule_work(&nt->cleanup_work);
}

/* Handle network interface device notifications */
static int netconsole_netdev_event(struct notifier_block *this,
				   unsigned long event,
				   void *ptr)
{
	struct netpoll_targets *nts = container_of(this, struct netpoll_targets,
						   netdev_notifier);
	unsigned long flags;
	struct netconsole_target *nt;
	struct net_device *dev = ptr;

	if (!(event == NETDEV_CHANGENAME || event == NETDEV_UNREGISTER ||
	      event == NETDEV_BONDING_DESLAVE))
		goto done;

	spin_lock_irqsave(&nts->lock, flags);
	list_for_each_entry(nt, &nts->list, list) {
		if (nt->np_state == NETPOLL_ENABLED && nt->np.dev == dev) {
			switch (event) {
			case NETDEV_CHANGENAME:
				strlcpy(nt->np.dev_name, dev->name, IFNAMSIZ);
				break;
			case NETDEV_BONDING_DESLAVE:
			case NETDEV_UNREGISTER:
				/*
				 * We can't cleanup netpoll in atomic context.
				 * Kick it off as deferred work.
				 */
				defer_netpoll_cleanup(nt);
			}
		}
	}
	spin_unlock_irqrestore(&nts->lock, flags);
	if (event == NETDEV_UNREGISTER || event == NETDEV_BONDING_DESLAVE)
		printk(KERN_INFO "netconsole: network logging stopped, "
			"interface %s %s\n",  dev->name,
			event == NETDEV_UNREGISTER ? "unregistered" : "released slaves");

done:
	return NOTIFY_DONE;
}

static void write_msg(struct console *con, const char *msg, unsigned int len)
{
	int frag, left;
	unsigned long flags;
	struct netconsole_target *nt;
	const char *tmp;

	/* Avoid taking lock and disabling interrupts unnecessarily */
	if (list_empty(&targets.list))
		return;

	spin_lock_irqsave(&targets.lock, flags);
	list_for_each_entry(nt, &targets.list, list) {
		if (nt->np_state == NETPOLL_ENABLED
		    && netif_running(nt->np.dev)) {
			/*
			 * We nest this inside the for-each-target loop above
			 * so that we're able to get as much logging out to
			 * at least one target if we die inside here, instead
			 * of unnecessarily keeping all targets in lock-step.
			 */
			tmp = msg;
			for (left = len; left;) {
				frag = min(left, MAX_PRINT_CHUNK);
				netpoll_send_udp(&nt->np, tmp, frag);
				tmp += frag;
				left -= frag;
			}
		}
	}
	spin_unlock_irqrestore(&targets.lock, flags);
}

static struct console netconsole = {
	.name	= "netcon",
	.flags	= CON_ENABLED,
	.write	= write_msg,
};

static int __init init_netconsole(void)
{
	int err;
	struct netconsole_target *nt, *tmp;
	unsigned long flags;
	char *target_config;
	char *input = config;

	if (strnlen(input, MAX_PARAM_LENGTH)) {
		while ((target_config = strsep(&input, ";"))) {
			nt = alloc_param_target(target_config);
			if (IS_ERR(nt)) {
				err = PTR_ERR(nt);
				goto fail;
			}
			/* Dump existing printks when we register */
			netconsole.flags |= CON_PRINTBUFFER;

			spin_lock_irqsave(&targets.lock, flags);
			list_add(&nt->list, &targets.list);
			spin_unlock_irqrestore(&targets.lock, flags);
		}
	}

	targets.netdev_notifier.notifier_call = netconsole_netdev_event;
	err = register_netdevice_notifier(&targets.netdev_notifier);
	if (err)
		goto fail;

	err = dynamic_netpoll_targets_init(&targets);
	if (err)
		goto undonotifier;

	register_console(&netconsole);
	printk(KERN_INFO "netconsole: network logging started\n");

	return err;

undonotifier:
	unregister_netdevice_notifier(&targets.netdev_notifier);

fail:
	printk(KERN_ERR "netconsole: cleaning up\n");

	/*
	 * Remove all targets and destroy them (only targets created
	 * from the boot/module option exist here). Skipping the list
	 * lock is safe here, and netpoll_cleanup() will sleep.
	 */
	list_for_each_entry_safe(nt, tmp, &targets.list, list) {
		list_del(&nt->list);
		free_param_target(nt);
	}

	return err;
}

static void __exit cleanup_netconsole(void)
{
	struct netconsole_target *nt, *tmp;

	unregister_console(&netconsole);
	dynamic_netpoll_targets_exit(&targets);
	unregister_netdevice_notifier(&targets.netdev_notifier);

	/*
	 * Targets created via configfs pin references on our module
	 * and would first be rmdir(2)'ed from userspace. We reach
	 * here only when they are already destroyed, and only those
	 * created from the boot/module option are left, so remove and
	 * destroy them. Skipping the list lock is safe here, and
	 * netpoll_cleanup() will sleep.
	 */
	list_for_each_entry_safe(nt, tmp, &targets.list, list) {
		list_del(&nt->list);
		free_param_target(nt);
	}
}

module_init(init_netconsole);
module_exit(cleanup_netconsole);
