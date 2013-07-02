/*
 * drivers/net/netoops.c
 * Copyright (C) 2004 and beyond Google Inc.
 *
 * Original Author Ross Biro
 * Revisions Rebecca Schultz
 * Cleaned up by Mike Waychison <mikew@google.com>
 *
 * This is very simple code to use the polling
 * mode of the network drivers to send the
 * contents of the printk buffer via udp w/o
 * checksum to a unicast address.
 */

#include <linux/in.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/netpoll.h>
#include <linux/nmi.h>
#include <linux/utsname.h>
#include <linux/watchdog.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/kmsg_dump.h>
#include <linux/netpoll_targets.h>

#define NETOOPS_TYPE_PRINTK_BUFFER 1
#define NETOOPS_TYPE_PRINTK_BUFFER_SOFT 3
#define NETOOPS_VERSION 0x0003
#define NETOOPS_PORT 2004
#define NETOOPS_RETRANSMIT_COUNT 3

static DEFINE_NETPOLL_TARGETS(targets);

#define MAX_PARAM_LENGTH	256
static char __initdata config[MAX_PARAM_LENGTH];
module_param_string(netoops, config, MAX_PARAM_LENGTH, 0);
MODULE_PARM_DESC(netoops, " netoops=[src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr]");

#ifndef	MODULE
static int __init option_setup(char *opt)
{
	strlcpy(config, opt, MAX_PARAM_LENGTH);
	return 1;
}
__setup("netoops=", option_setup);
#endif	/* MODULE */

/*
 * Architecture specific support.
 */
#if defined(__i386__) || defined(__x86_64__)
#define NETOOPS_ARCH 2
struct netoops_arch_data {
	u8 x86_vendor;
	u8 x86_family;
	u8 x86_model;
	u8 x86_stepping;
	/* NOTE: regs is 60 or 168 bytes */
	struct pt_regs regs;
} __attribute__((packed));

static void setup_packet_arch_data(struct netoops_arch_data *arch_data,
				   struct pt_regs *regs) {
	arch_data->x86_vendor   = current_cpu_data.x86_vendor;
	arch_data->x86_family   = current_cpu_data.x86;
	arch_data->x86_model    = current_cpu_data.x86_model;
	arch_data->x86_stepping = current_cpu_data.x86_mask;
	if (regs != NULL)
		memcpy(&arch_data->regs, regs, sizeof(arch_data->regs));
	else
		memset(&arch_data->regs, 0, sizeof(arch_data->regs));
}
#else
#error "unsupported architecture"
#endif

/*
 * Architecture independent support.
 */
#define NETOOPS_DATA_BYTES 1024
struct netoops_msg {
	struct {
		__le16 version;    /* MUST be @ offset 0 */
		__le16 dump_id;
		/* Offset into packet before data[] starts.  */
		__le16 data_offset;
		__le16 arch;
		/* Offset into packet before struct arch_data starts. */
		__le16 arch_offset;
		__le16 type;
		__le32 packet_count;
		__le32 packet_no;
		__le32 boot_id;
		/*
		 * NOTE: fixed length strings for a packet.  NULL
		 * termination not required.
		 */
		char kernel_version[64];
	} __attribute__ ((packed)) header;
	struct netoops_arch_data arch_data;
	char data[NETOOPS_DATA_BYTES];
} __attribute__ ((packed));

static struct netoops_msg msg;

static u32 netoops_boot_id;

static void setup_packet_header(int packet_count, struct pt_regs *regs,
				int soft_dump)
{
	typeof(msg.header) *h = &msg.header;

	h->version = cpu_to_le16(NETOOPS_VERSION);
	h->data_offset = cpu_to_le16(offsetof(struct netoops_msg, data));
	h->arch = cpu_to_le16(NETOOPS_ARCH);
	h->arch_offset = cpu_to_le16(offsetof(struct netoops_msg, arch_data));
	h->dump_id = cpu_to_le16((jiffies/HZ) & 0xffff);
	h->type = cpu_to_le16(soft_dump ? NETOOPS_TYPE_PRINTK_BUFFER_SOFT :
					  NETOOPS_TYPE_PRINTK_BUFFER);
	h->packet_count = cpu_to_le32(packet_count);
	h->boot_id = cpu_to_le32(netoops_boot_id);
	strncpy(h->kernel_version, utsname()->release,
		min(sizeof(msg.header.kernel_version),
		    sizeof(utsname()->release)));

	setup_packet_arch_data(&msg.arch_data, regs);
}

static int packet_count_from_length(unsigned long l)
{
	return (l + NETOOPS_DATA_BYTES - 1) / NETOOPS_DATA_BYTES;
}

/* Send the packet to all targets */
static void netoops_send_packet(int packet_nr)
{
	struct netpoll_target *nt;

	msg.header.packet_no = cpu_to_le32(packet_nr);

	list_for_each_entry(nt, &targets.list, list) {
		if (nt->np_state == NETPOLL_ENABLED
		    && netif_running(nt->np.dev)) {
			netpoll_send_udp(&nt->np, (char *)&msg, sizeof(msg));
		}
	}

}

/*
 * Send the passed in segment of kmsg via netpoll.  Packets are sent in reverse
 * order, with the tail packet (the first one transmitted) zero-padded.
 */
static void netoops_send_segment(int packet_offset,
				 const char *s, unsigned long l)
{
	int packet_count = packet_count_from_length(l);
	size_t data_length;
	int i;

	for (i = packet_count - 1; i >= 0; i--) {
		/* Usually messages completely fill the data field */
		data_length = NETOOPS_DATA_BYTES;
		if (i == packet_count - 1) {
			/* Except the tail packet, which is zero-padded */
			data_length = l % NETOOPS_DATA_BYTES;
			memset(msg.data + data_length, 0,
			       NETOOPS_DATA_BYTES - data_length);
		}
		BUG_ON(data_length > NETOOPS_DATA_BYTES);

		/* Copy the payload into the packet and send */
		memcpy(msg.data, s + (i * NETOOPS_DATA_BYTES), data_length);
		netoops_send_packet((packet_count - i - 1) + packet_offset);

		touch_nmi_watchdog();
	}
}

/*
 * Callback used by the kmsg_dumper.
 *
 * Called with interrupts disabled locally.
 */
static void netoops(struct kmsg_dumper *dumper, enum kmsg_dump_reason reason,
		    struct pt_regs *regs,
		    const char *s1, unsigned long l1,
		    const char *s2, unsigned long l2) {
	unsigned long flags;
	int packet_count_1, packet_count_2;
	int soft_dump = 0;
	int i;

	/* Only handle fatal problems */
	if (reason != KMSG_DUMP_OOPS
	 && reason != KMSG_DUMP_PANIC
	 && reason != KMSG_DUMP_SOFT)
		return;

	if (reason == KMSG_DUMP_SOFT)
		soft_dump = 1;

	spin_lock_irqsave(&targets.lock, flags);

	/* compute total length of the message we are going to send */
	packet_count_1 = packet_count_from_length(l1);
	packet_count_2 = packet_count_from_length(l2);

	/* setup the non varying parts of the message */
	memset(&msg, 0, sizeof(msg));
	setup_packet_header(packet_count_1 + packet_count_2, regs, soft_dump);

	/* Transmission loop */
	for (i = 0; i < NETOOPS_RETRANSMIT_COUNT; i++) {
		/* Send the full packets from the second segment */
		netoops_send_segment(0, s2, l2);
		netoops_send_segment(packet_count_2, s1, l1);
	}

	spin_unlock_irqrestore(&targets.lock, flags);
}

static ssize_t netoops_show(struct kobject *kobj,
			    struct kobj_attribute *attr,
			    char *buf) {
	if (!strcmp(attr->attr.name, "netoops_boot_id"))
		snprintf(buf, PAGE_SIZE, "%d\n", netoops_boot_id);
	buf[PAGE_SIZE - 1] = '\0';
	return strnlen(buf, PAGE_SIZE);
}

static ssize_t netoops_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf,
			     size_t count) {
	if (!count)
		return count;

	if (!strcmp(attr->attr.name, "netoops_boot_id")) {
		unsigned long tmp;
		if (strict_strtoul(buf, 0, &tmp))
			return -EINVAL;
		if (tmp > UINT_MAX)
			printk("Warning: truncating boot_id to 32bits.");
		netoops_boot_id = tmp;
	} else
		return -EINVAL;

	return count;
}

static struct kobj_attribute netoops_boot_number_attribute =
	__ATTR(netoops_boot_id, 0666, netoops_show, netoops_store);

static struct attribute *attrs[] = {
	&netoops_boot_number_attribute.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static struct kobject *netoops_kobj;

static struct kmsg_dumper netoops_dumper = {
	.dump = netoops,
};

static int __init netoops_init(void)
{
	int retval = -EINVAL;

	BUILD_BUG_ON(offsetof(struct netoops_msg, header.version) != 0);
	BUILD_BUG_ON(offsetof(struct netoops_msg, header.dump_id) != 2);
	BUILD_BUG_ON(offsetof(struct netoops_msg, header.data_offset) != 4);
	BUILD_BUG_ON(offsetof(struct netoops_msg, header.arch) != 6);
	BUILD_BUG_ON(offsetof(struct netoops_msg, header.arch_offset) != 8);
	BUILD_BUG_ON(offsetof(struct netoops_msg, header.type) != 10);
	BUILD_BUG_ON(offsetof(struct netoops_msg, header.packet_count) != 12);
	BUILD_BUG_ON(offsetof(struct netoops_msg, header.packet_no) != 16);
	BUILD_BUG_ON(offsetof(struct netoops_msg, header.boot_id) != 20);

	targets.default_local_port = NETOOPS_PORT;
	targets.default_remote_port = NETOOPS_PORT;

	config[MAX_PARAM_LENGTH - 1] = '\0';
	retval = register_netpoll_targets("netoops", &targets, config);
	if (retval)
		goto out;

	netoops_kobj = kobject_create_and_add("netoops", kernel_kobj);
	if (!netoops_kobj)
		goto out_targets;

	retval = sysfs_create_group(netoops_kobj, &attr_group);
	if (retval)
		goto out_kobj;

	retval = kmsg_dump_register(&netoops_dumper);
	if (retval)
		goto out_sysfs_group;

	return 0;
out_sysfs_group:
	sysfs_remove_group(netoops_kobj, &attr_group);
out_kobj:
	kobject_put(netoops_kobj);
out_targets:
	unregister_netpoll_targets(&targets);
out:
	return retval;
}

static void __exit netoops_exit(void)
{
	kmsg_dump_unregister(&netoops_dumper);
	sysfs_remove_group(netoops_kobj, &attr_group);
	kobject_put(netoops_kobj);
	unregister_netpoll_targets(&targets);
}

module_init(netoops_init);
module_exit(netoops_exit);
MODULE_LICENSE("GPL");
