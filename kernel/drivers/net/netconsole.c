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
#include <linux/netpoll.h>
#include <linux/netpoll_targets.h>
#include <linux/inet.h>

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

static DEFINE_NETPOLL_TARGETS(targets);

static void write_msg(struct console *con, const char *msg, unsigned int len)
{
	int frag, left;
	unsigned long flags;
	struct netpoll_target *nt;
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

	targets.default_local_port = 6665;
	targets.default_remote_port = 6666;

	config[MAX_PARAM_LENGTH - 1] = '\0';
	err = register_netpoll_targets("netconsole", &targets, config);
	if (err)
		return err;
	/* Dump existing printks if we registered any targets */
	if (!list_empty(&targets.list))
		netconsole.flags |= CON_PRINTBUFFER;
	register_console(&netconsole);
	printk(KERN_INFO "netconsole: network logging started\n");

	return 0;
}

static void __exit cleanup_netconsole(void)
{
	unregister_console(&netconsole);
	unregister_netpoll_targets(&targets);
}

module_init(init_netconsole);
module_exit(cleanup_netconsole);
