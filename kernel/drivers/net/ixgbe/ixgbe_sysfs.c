/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright(c) 1999 - 2012 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#include "ixgbe.h"
#include "ixgbe_common.h"
#include "ixgbe_type.h"

#ifdef IXGBE_SYSFS

#include <linux/module.h>
#include <linux/types.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/device.h>
#include <linux/netdevice.h>

/*
 * This file provides a sysfs interface to export information from the
 * driver.  The information presented is READ-ONLY.
 */

static struct net_device_stats *sysfs_get_stats(struct net_device *netdev)
{
#ifndef HAVE_NETDEV_STATS_IN_NETDEV
	struct ixgbe_adapter *adapter;
#endif
	if (netdev == NULL)
		return NULL;

#ifdef HAVE_NETDEV_STATS_IN_NETDEV
	/* only return the current stats */
	return &netdev->stats;
#else
	adapter = netdev_priv(netdev);

	/* only return the current stats */
	return &adapter->net_stats;
#endif /* HAVE_NETDEV_STATS_IN_NETDEV */
}

static struct net_device *ixgbe_get_netdev(struct kobject *kobj)
{
	struct net_device *netdev;
	struct kobject *parent = kobj->parent;
	struct device *device_info_kobj;

	if (kobj == NULL)
		return NULL;

	device_info_kobj = container_of(parent, struct device, kobj);
	if (device_info_kobj == NULL)
		return NULL;

	netdev = container_of(device_info_kobj, struct net_device, dev);
	return netdev;
}

static struct ixgbe_adapter *ixgbe_get_adapter(struct kobject *kobj)
{
	struct ixgbe_adapter *adapter;
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return NULL;
	adapter = netdev_priv(netdev);
	return adapter;
}

static bool ixgbe_thermal_present(struct kobject *kobj)
{
	s32 status;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);

	if (adapter == NULL)
		return false;

	status = ixgbe_init_thermal_sensor_thresh_generic(&(adapter->hw));
	if (status != 0)
		return false;

	return true;
}

/*
 * ixgbe_name_to_idx - Convert the directory name to the sensor offset.
 * @ c: pointer to the directory name string
 *
 * The directory name is in the form "sensor_n" where n is '0' -
 * 'IXGBE_MAX_SENSORS'.  IXGBE_MAX_SENSORS will never be greater than
 * 9.  This function takes advantage of that to keep it simple.
 */
static int ixgbe_name_to_idx(const char *c)
{
	/* find first digit */
	while (*c < '0' || *c > '9') {
		if (*c == '\n')
			return -1;
		c++;
	}

	return ((int)(*c - '0'));
}

static ssize_t ixgbe_fwbanner(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	int nvm_track_id;

	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");
	nvm_track_id = (adapter->eeprom_verh << 16) | adapter->eeprom_verl;

	return snprintf(buf, PAGE_SIZE, "0x%08x\n", nvm_track_id);
}

static ssize_t ixgbe_porttype(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");
	return snprintf(buf, PAGE_SIZE, "%d\n",
			test_bit(__IXGBE_DOWN, &adapter->state));
}

static ssize_t ixgbe_portspeed(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	int speed = 0;

	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	switch (adapter->link_speed) {
	case IXGBE_LINK_SPEED_100_FULL:
		speed = 1;
		break;
	case IXGBE_LINK_SPEED_1GB_FULL:
		speed = 10;
		break;
	case IXGBE_LINK_SPEED_10GB_FULL:
		speed = 100;
		break;
	}
	return snprintf(buf, PAGE_SIZE, "%d\n", speed);
}

static ssize_t ixgbe_wqlflag(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", adapter->wol);
}

static ssize_t ixgbe_xflowctl(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	struct ixgbe_hw *hw;

	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", hw->fc.current_mode);
}

static ssize_t ixgbe_rxdrops(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct net_device_stats *net_stats;
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	net_stats  = sysfs_get_stats(netdev);
	if (net_stats == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net stats\n");

	return snprintf(buf, PAGE_SIZE, "%lu\n",
			net_stats->rx_dropped);
}

static ssize_t ixgbe_rxerrors(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct net_device_stats *net_stats;
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	net_stats  = sysfs_get_stats(netdev);
	if (net_stats == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net stats\n");
	return snprintf(buf, PAGE_SIZE, "%lu\n", net_stats->rx_errors);
}

static ssize_t ixgbe_rxupacks(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", IXGBE_READ_REG(hw, IXGBE_TPR));
}

static ssize_t ixgbe_rxmpacks(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", IXGBE_READ_REG(hw, IXGBE_MPRC));
}

static ssize_t ixgbe_rxbpacks(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", IXGBE_READ_REG(hw, IXGBE_BPRC));
}

static ssize_t ixgbe_txupacks(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", IXGBE_READ_REG(hw, IXGBE_TPT));
}

static ssize_t ixgbe_txmpacks(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", IXGBE_READ_REG(hw, IXGBE_MPTC));
}

static ssize_t ixgbe_txbpacks(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", IXGBE_READ_REG(hw, IXGBE_BPTC));
}

static ssize_t ixgbe_txerrors(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct net_device_stats *net_stats;
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	net_stats  = sysfs_get_stats(netdev);
	if (net_stats == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net stats\n");

	return snprintf(buf, PAGE_SIZE, "%lu\n",
			net_stats->tx_errors);
}

static ssize_t ixgbe_txdrops(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct net_device_stats *net_stats;
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	net_stats  = sysfs_get_stats(netdev);
	if (net_stats == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net stats\n");
	return snprintf(buf, PAGE_SIZE, "%lu\n",
			net_stats->tx_dropped);
}

static ssize_t ixgbe_rxframes(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct net_device_stats *net_stats;
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	net_stats  = sysfs_get_stats(netdev);
	if (net_stats == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net stats\n");

	return snprintf(buf, PAGE_SIZE, "%lu\n",
			net_stats->rx_packets);
}

static ssize_t ixgbe_rxbytes(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct net_device_stats *net_stats;
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	net_stats  = sysfs_get_stats(netdev);
	if (net_stats == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net stats\n");

	return snprintf(buf, PAGE_SIZE, "%lu\n",
			net_stats->rx_bytes);
}

static ssize_t ixgbe_txframes(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct net_device_stats *net_stats;
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	net_stats  = sysfs_get_stats(netdev);
	if (net_stats == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net stats\n");

	return snprintf(buf, PAGE_SIZE, "%lu\n",
			net_stats->tx_packets);
}

static ssize_t ixgbe_txbytes(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct net_device_stats *net_stats;
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	net_stats  = sysfs_get_stats(netdev);
	if (net_stats == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net stats\n");

	return snprintf(buf, PAGE_SIZE, "%lu\n",
			net_stats->tx_bytes);
}

static ssize_t ixgbe_linkstat(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	u32 link_speed;
	bool link_up = false;
	int bitmask = 0;
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");


	if (test_bit(__IXGBE_DOWN, &adapter->state))
		bitmask |= 1;

	if (hw->mac.ops.check_link)
		hw->mac.ops.check_link(hw, &link_speed, &link_up, false);
	else
		/* always assume link is up, if no check link function */
		link_up = true;
	if (link_up)
		bitmask |= 2;
	return snprintf(buf, PAGE_SIZE, "0x%X\n", bitmask);
}

static ssize_t ixgbe_funcid(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	struct ixgbe_hw *hw;

	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	return snprintf(buf, PAGE_SIZE, "0x%X\n", hw->bus.func);
}

static ssize_t ixgbe_funcvers(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", ixgbe_driver_version);
}

static ssize_t ixgbe_macburn(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	return snprintf(buf, PAGE_SIZE, "0x%X%X%X%X%X%X\n",
		       (unsigned int)hw->mac.perm_addr[0],
		       (unsigned int)hw->mac.perm_addr[1],
		       (unsigned int)hw->mac.perm_addr[2],
		       (unsigned int)hw->mac.perm_addr[3],
		       (unsigned int)hw->mac.perm_addr[4],
		       (unsigned int)hw->mac.perm_addr[5]);
}

static ssize_t ixgbe_macadmn(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	return snprintf(buf, PAGE_SIZE, "0x%X%X%X%X%X%X\n",
		       (unsigned int)hw->mac.addr[0],
		       (unsigned int)hw->mac.addr[1],
		       (unsigned int)hw->mac.addr[2],
		       (unsigned int)hw->mac.addr[3],
		       (unsigned int)hw->mac.addr[4],
		       (unsigned int)hw->mac.addr[5]);
}

static ssize_t ixgbe_maclla1(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_hw *hw;
	u16 eeprom_buff[6];
	int first_word = 0x37;
	int word_count = 6;
	int rc;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no hw data\n");

	rc = ixgbe_read_eeprom_buffer(hw, first_word, word_count,
				      eeprom_buff);
	if (rc != 0)
		return snprintf(buf, PAGE_SIZE, "error: reading buffer\n");

	switch (hw->bus.func) {
	case 0:
		return snprintf(buf, PAGE_SIZE, "0x%04X%04X%04X\n",
				eeprom_buff[0],
				eeprom_buff[1],
				eeprom_buff[2]);
	case 1:
		return snprintf(buf, PAGE_SIZE, "0x%04X%04X%04X\n",
				eeprom_buff[3],
				eeprom_buff[4],
				eeprom_buff[5]);
	}
	return snprintf(buf, PAGE_SIZE, "unexpected port %d\n", hw->bus.func);
}

static ssize_t ixgbe_mtusize(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", netdev->mtu);
}

static ssize_t ixgbe_featflag(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	int bitmask = 0;
#ifndef HAVE_NDO_SET_FEATURES
	struct ixgbe_ring *ring;
#endif
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

#ifndef HAVE_NDO_SET_FEATURES
	/* ixgbe_get_rx_csum(netdev) doesn't compile so hard code */
	ring = adapter->rx_ring[0];
	bitmask = test_bit(__IXGBE_RX_CSUM_ENABLED, &ring->state);
	return snprintf(buf, PAGE_SIZE, "%d\n", bitmask);
#else
	if (netdev->features & NETIF_F_RXCSUM)
		bitmask |= 1;
	return snprintf(buf, PAGE_SIZE, "%d\n", bitmask);
#endif
}

static ssize_t ixgbe_lsominct(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", 1);
}

static ssize_t ixgbe_prommode(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct net_device *netdev = ixgbe_get_netdev(kobj);
	if (netdev == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no net device\n");

	return snprintf(buf, PAGE_SIZE, "%d\n",
			netdev->flags & IFF_PROMISC);
}

static ssize_t ixgbe_txdscqsz(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", adapter->tx_ring[0]->count);
}

static ssize_t ixgbe_rxdscqsz(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", adapter->rx_ring[0]->count);
}

static ssize_t ixgbe_rxqavg(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	int index;
	int diff = 0;
	u16 ntc;
	u16 ntu;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	for (index = 0; index < adapter->num_rx_queues; index++) {
		ntc = adapter->rx_ring[index]->next_to_clean;
		ntu = adapter->rx_ring[index]->next_to_use;

		if (ntc >= ntu)
			diff += (ntc - ntu);
		else
			diff += (adapter->rx_ring[index]->count - ntu + ntc);
	}
	if (adapter->num_rx_queues <= 0)
		return snprintf(buf, PAGE_SIZE,
				"can't calculate, number of queues %d\n",
				adapter->num_rx_queues);
	return snprintf(buf, PAGE_SIZE, "%d\n", diff/adapter->num_rx_queues);
}

static ssize_t ixgbe_txqavg(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	int index;
	int diff = 0;
	u16 ntc;
	u16 ntu;
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	for (index = 0; index < adapter->num_tx_queues; index++) {
		ntc = adapter->tx_ring[index]->next_to_clean;
		ntu = adapter->tx_ring[index]->next_to_use;

		if (ntc >= ntu)
			diff += (ntc - ntu);
		else
			diff += (adapter->tx_ring[index]->count - ntu + ntc);
	}
	if (adapter->num_tx_queues <= 0)
		return snprintf(buf, PAGE_SIZE,
				"can't calculate, number of queues %d\n",
				adapter->num_tx_queues);
	return snprintf(buf, PAGE_SIZE, "%d\n",
			diff/adapter->num_tx_queues);
}

static ssize_t ixgbe_iovotype(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "2\n");
}

static ssize_t ixgbe_funcnbr(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", adapter->num_vfs);
}

static ssize_t ixgbe_pciebnbr(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj);
	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	return snprintf(buf, PAGE_SIZE, "%d\n", adapter->pdev->bus->number);
}

static s32 ixgbe_sysfs_get_thermal_data(struct kobject *kobj, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj->parent);
	s32 status;

	if (adapter == NULL) {
		snprintf(buf, PAGE_SIZE, "error: missing adapter\n");
		return 0;
	}

	if (&adapter->hw == NULL) {
		snprintf(buf, PAGE_SIZE, "error: missing hw\n");
		return 0;
	}

	status = ixgbe_get_thermal_sensor_data_generic(&adapter->hw);

	return status;
}

static ssize_t ixgbe_sysfs_location(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj->parent);
	int idx;

	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	idx = ixgbe_name_to_idx(kobj->name);
	if (idx == -1)
		return snprintf(buf, PAGE_SIZE,
				"error: invalid sensor name %s\n", kobj->name);

	return snprintf(buf, PAGE_SIZE, "%d\n",
		adapter->hw.mac.thermal_sensor_data.sensor[idx].location);
}

static ssize_t ixgbe_sysfs_temp(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj->parent);
	int idx;

	s32 status = ixgbe_sysfs_get_thermal_data(kobj, buf);

	if (status != 0)
		return snprintf(buf, PAGE_SIZE, "error: status %d returned",
				status);

	idx = ixgbe_name_to_idx(kobj->name);
	if (idx == -1)
		return snprintf(buf, PAGE_SIZE,
				"error: invalid sensor name %s\n", kobj->name);

	return snprintf(buf, PAGE_SIZE, "%d\n",
		adapter->hw.mac.thermal_sensor_data.sensor[idx].temp);
}

static ssize_t ixgbe_sysfs_maxopthresh(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj->parent);
	int idx;

	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	idx = ixgbe_name_to_idx(kobj->name);
	if (idx == -1)
		return snprintf(buf, PAGE_SIZE,
				"error: invalid sensor name %s\n", kobj->name);

	return snprintf(buf, PAGE_SIZE, "%d\n",
		adapter->hw.mac.thermal_sensor_data.sensor[idx].max_op_thresh);
}

static ssize_t ixgbe_sysfs_cautionthresh(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	struct ixgbe_adapter *adapter = ixgbe_get_adapter(kobj->parent);
	int idx;

	if (adapter == NULL)
		return snprintf(buf, PAGE_SIZE, "error: no adapter\n");

	idx = ixgbe_name_to_idx(kobj->name);
	if (idx == -1)
		return snprintf(buf, PAGE_SIZE,
				"error: invalid sensor name %s\n", kobj->name);

	return snprintf(buf, PAGE_SIZE, "%d\n",
		adapter->hw.mac.thermal_sensor_data.sensor[idx].caution_thresh);
}

/* Initialize the attributes */
static struct kobj_attribute ixgbe_sysfs_location_attr =
	__ATTR(location, 0444, ixgbe_sysfs_location, NULL);
static struct kobj_attribute ixgbe_sysfs_temp_attr =
	__ATTR(temp, 0444, ixgbe_sysfs_temp, NULL);
static struct kobj_attribute ixgbe_sysfs_cautionthresh_attr =
	__ATTR(cautionthresh, 0444, ixgbe_sysfs_cautionthresh, NULL);
static struct kobj_attribute ixgbe_sysfs_maxopthresh_attr =
	__ATTR(maxopthresh, 0444, ixgbe_sysfs_maxopthresh, NULL);

static struct kobj_attribute ixgbe_sysfs_fwbanner_attr =
	__ATTR(fwbanner, 0444, ixgbe_fwbanner, NULL);
static struct kobj_attribute ixgbe_sysfs_porttype_attr =
	__ATTR(porttype, 0444, ixgbe_porttype, NULL);
static struct kobj_attribute ixgbe_sysfs_portspeed_attr =
	__ATTR(portspeed, 0444, ixgbe_portspeed, NULL);
static struct kobj_attribute ixgbe_sysfs_wqlflag_attr =
	__ATTR(wqlflag, 0444, ixgbe_wqlflag, NULL);
static struct kobj_attribute ixgbe_sysfs_xflowctl_attr =
	__ATTR(xflowctl, 0444, ixgbe_xflowctl, NULL);
static struct kobj_attribute ixgbe_sysfs_rxdrops_attr =
	__ATTR(rxdrops, 0444, ixgbe_rxdrops, NULL);
static struct kobj_attribute ixgbe_sysfs_rxerrors_attr =
	__ATTR(rxerrors, 0444, ixgbe_rxerrors, NULL);
static struct kobj_attribute ixgbe_sysfs_rxupacks_attr =
	__ATTR(rxupacks, 0444, ixgbe_rxupacks, NULL);
static struct kobj_attribute ixgbe_sysfs_rxmpacks_attr =
	__ATTR(rxmpacks, 0444, ixgbe_rxmpacks, NULL);
static struct kobj_attribute ixgbe_sysfs_rxbpacks_attr =
	__ATTR(rxbpacks, 0444, ixgbe_rxbpacks, NULL);
static struct kobj_attribute ixgbe_sysfs_txupacks_attr =
	__ATTR(txupacks, 0444, ixgbe_txupacks, NULL);
static struct kobj_attribute ixgbe_sysfs_txmpacks_attr =
	__ATTR(txmpacks, 0444, ixgbe_txmpacks, NULL);
static struct kobj_attribute ixgbe_sysfs_txbpacks_attr =
	__ATTR(txbpacks, 0444, ixgbe_txbpacks, NULL);
static struct kobj_attribute ixgbe_sysfs_txerrors_attr =
	__ATTR(txerrors, 0444, ixgbe_txerrors, NULL);
static struct kobj_attribute ixgbe_sysfs_txdrops_attr =
	__ATTR(txdrops, 0444, ixgbe_txdrops, NULL);
static struct kobj_attribute ixgbe_sysfs_rxframes_attr =
	__ATTR(rxframes, 0444, ixgbe_rxframes, NULL);
static struct kobj_attribute ixgbe_sysfs_rxbytes_attr =
	__ATTR(rxbytes, 0444, ixgbe_rxbytes, NULL);
static struct kobj_attribute ixgbe_sysfs_txframes_attr =
	__ATTR(txframes, 0444, ixgbe_txframes, NULL);
static struct kobj_attribute ixgbe_sysfs_txbytes_attr =
	__ATTR(txbytes, 0444, ixgbe_txbytes, NULL);
static struct kobj_attribute ixgbe_sysfs_linkstat_attr =
	__ATTR(linkstat, 0444, ixgbe_linkstat, NULL);
static struct kobj_attribute ixgbe_sysfs_funcid_attr =
	__ATTR(funcid, 0444, ixgbe_funcid, NULL);
static struct kobj_attribute ixgbe_sysfs_funvers_attr =
	__ATTR(funcvers, 0444, ixgbe_funcvers, NULL);
static struct kobj_attribute ixgbe_sysfs_macburn_attr =
	__ATTR(macburn, 0444, ixgbe_macburn, NULL);
static struct kobj_attribute ixgbe_sysfs_macadmn_attr =
	__ATTR(macadmn, 0444, ixgbe_macadmn, NULL);
static struct kobj_attribute ixgbe_sysfs_maclla1_attr =
	__ATTR(maclla1, 0444, ixgbe_maclla1, NULL);
static struct kobj_attribute ixgbe_sysfs_mtusize_attr =
	__ATTR(mtusize, 0444, ixgbe_mtusize, NULL);
static struct kobj_attribute ixgbe_sysfs_featflag_attr =
	__ATTR(featflag, 0444, ixgbe_featflag, NULL);
static struct kobj_attribute ixgbe_sysfs_lsominct_attr =
	__ATTR(lsominct, 0444, ixgbe_lsominct, NULL);
static struct kobj_attribute ixgbe_sysfs_prommode_attr =
	__ATTR(prommode, 0444, ixgbe_prommode, NULL);
static struct kobj_attribute ixgbe_sysfs_txdscqsz_attr =
	__ATTR(txdscqsz, 0444, ixgbe_txdscqsz, NULL);
static struct kobj_attribute ixgbe_sysfs_rxdscqsz_attr =
	__ATTR(rxdscqsz, 0444, ixgbe_rxdscqsz, NULL);
static struct kobj_attribute ixgbe_sysfs_txqavg_attr =
	__ATTR(txqavg, 0444, ixgbe_txqavg, NULL);
static struct kobj_attribute ixgbe_sysfs_rxqavg_attr =
	__ATTR(rxqavg, 0444, ixgbe_rxqavg, NULL);
static struct kobj_attribute ixgbe_sysfs_iovotype_attr =
	__ATTR(iovotype, 0444, ixgbe_iovotype, NULL);
static struct kobj_attribute ixgbe_sysfs_funcnbr_attr =
	__ATTR(funcnbr, 0444, ixgbe_funcnbr, NULL);
static struct kobj_attribute ixgbe_sysfs_pciebnbr_attr =
	__ATTR(pciebnbr, 0444, ixgbe_pciebnbr, NULL);

/* Add the attributes into an array, to be added to a group */
static struct attribute *therm_attrs[] = {
	&ixgbe_sysfs_location_attr.attr,
	&ixgbe_sysfs_temp_attr.attr,
	&ixgbe_sysfs_cautionthresh_attr.attr,
	&ixgbe_sysfs_maxopthresh_attr.attr,
	NULL
};

static struct attribute *attrs[] = {
	&ixgbe_sysfs_fwbanner_attr.attr,
	&ixgbe_sysfs_porttype_attr.attr,
	&ixgbe_sysfs_portspeed_attr.attr,
	&ixgbe_sysfs_wqlflag_attr.attr,
	&ixgbe_sysfs_xflowctl_attr.attr,
	&ixgbe_sysfs_rxdrops_attr.attr,
	&ixgbe_sysfs_rxerrors_attr.attr,
	&ixgbe_sysfs_rxupacks_attr.attr,
	&ixgbe_sysfs_rxmpacks_attr.attr,
	&ixgbe_sysfs_rxbpacks_attr.attr,
	&ixgbe_sysfs_txdrops_attr.attr,
	&ixgbe_sysfs_txerrors_attr.attr,
	&ixgbe_sysfs_txupacks_attr.attr,
	&ixgbe_sysfs_txmpacks_attr.attr,
	&ixgbe_sysfs_txbpacks_attr.attr,
	&ixgbe_sysfs_rxframes_attr.attr,
	&ixgbe_sysfs_rxbytes_attr.attr,
	&ixgbe_sysfs_txframes_attr.attr,
	&ixgbe_sysfs_txbytes_attr.attr,
	&ixgbe_sysfs_linkstat_attr.attr,
	&ixgbe_sysfs_funcid_attr.attr,
	&ixgbe_sysfs_funvers_attr.attr,
	&ixgbe_sysfs_macburn_attr.attr,
	&ixgbe_sysfs_macadmn_attr.attr,
	&ixgbe_sysfs_maclla1_attr.attr,
	&ixgbe_sysfs_mtusize_attr.attr,
	&ixgbe_sysfs_featflag_attr.attr,
	&ixgbe_sysfs_lsominct_attr.attr,
	&ixgbe_sysfs_prommode_attr.attr,
	&ixgbe_sysfs_txdscqsz_attr.attr,
	&ixgbe_sysfs_rxdscqsz_attr.attr,
	&ixgbe_sysfs_txqavg_attr.attr,
	&ixgbe_sysfs_rxqavg_attr.attr,
	&ixgbe_sysfs_iovotype_attr.attr,
	&ixgbe_sysfs_funcnbr_attr.attr,
	&ixgbe_sysfs_pciebnbr_attr.attr,
	NULL
};

/* add attributes to a group */
static struct attribute_group therm_attr_group = {
	.attrs = therm_attrs,
};

/* add attributes to a group */
static struct attribute_group attr_group = {
	.attrs = attrs,
};

static void ixgbe_del_adapter(struct ixgbe_adapter *adapter)
{
	int i;

	if (adapter == NULL)
		return;

	for (i = 0; i < IXGBE_MAX_SENSORS; i++) {
		if (adapter->therm_kobj[i] == NULL)
			continue;
		sysfs_remove_group(adapter->therm_kobj[i], &therm_attr_group);
		kobject_put(adapter->therm_kobj[i]);
	}
	if (adapter->info_kobj != NULL) {
		sysfs_remove_group(adapter->info_kobj, &attr_group);
		kobject_put(adapter->info_kobj);
	}
}

/* called from ixgbe_main.c */
void ixgbe_sysfs_exit(struct ixgbe_adapter *adapter)
{
	ixgbe_del_adapter(adapter);
}

/* called from ixgbe_main.c */
int ixgbe_sysfs_init(struct ixgbe_adapter *adapter)
{
	struct net_device *netdev;
	int rc = 0;
	int i;
	char buf[16];

	if (adapter == NULL)
		goto err;
	netdev = adapter->netdev;
	if (netdev == NULL)
		goto err;

	adapter->info_kobj = NULL;
	for (i = 0; i < IXGBE_MAX_SENSORS; i++)
		adapter->therm_kobj[i] = NULL;

	/* create info kobj and attribute listings in kobj */
	adapter->info_kobj = kobject_create_and_add("info",
					&(netdev->dev.kobj));
	if (adapter->info_kobj == NULL)
		goto err;
	if (sysfs_create_group(adapter->info_kobj, &attr_group))
		goto err;

	/* Don't create thermal subkobjs if no data present */
	if (ixgbe_thermal_present(adapter->info_kobj) != true)
		goto exit;

	for (i = 0; i < IXGBE_MAX_SENSORS; i++) {

		/*
		 * Likewise only create individual kobjs that have
		 * meaningful data.
		 */
		if (adapter->hw.mac.thermal_sensor_data.sensor[i].location == 0)
			continue;

		/* directory named after sensor offset */
		snprintf(buf, sizeof(buf), "sensor_%d", i);
		adapter->therm_kobj[i] =
			kobject_create_and_add(buf, adapter->info_kobj);
		if (adapter->therm_kobj[i] == NULL)
			goto err;
		if (sysfs_create_group(adapter->therm_kobj[i],
				       &therm_attr_group))
			goto err;
	}

	goto exit;

err:
	ixgbe_del_adapter(adapter);
	rc = -1;
exit:
	return rc;
}

#endif /* IXGBE_SYSFS */
