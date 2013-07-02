#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xe933d6a0, "module_layout" },
	{ 0xcac34552, "pci_bus_read_config_byte" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0xf9a482f9, "msleep" },
	{ 0xc4dc87, "timecounter_init" },
	{ 0x38894d18, "pci_enable_sriov" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x6980fe91, "param_get_int" },
	{ 0x91eb9b4, "round_jiffies" },
	{ 0x50d1149a, "qdisc_reset" },
	{ 0xd2db4503, "skb_pad" },
	{ 0x1ba70a2, "dev_set_drvdata" },
	{ 0xfa2e111f, "slab_buffer_size" },
	{ 0x950ffff2, "cpu_online_mask" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0xb712ef1d, "dma_set_mask" },
	{ 0x5afb0aac, "napi_complete" },
	{ 0xd691cba2, "malloc_sizes" },
	{ 0xf71687bf, "pci_disable_device" },
	{ 0x6079b814, "pci_disable_msix" },
	{ 0x3582bc7b, "netif_carrier_on" },
	{ 0x7d5774cc, "pci_disable_sriov" },
	{ 0xb813ce5a, "timecompare_transform" },
	{ 0x403f0eb3, "ethtool_op_get_sg" },
	{ 0xa28e76e6, "schedule_work" },
	{ 0xc0a3d105, "find_next_bit" },
	{ 0x43ab66c3, "param_array_get" },
	{ 0x105e2727, "__tracepoint_kmalloc" },
	{ 0x1337c4e2, "netif_carrier_off" },
	{ 0x264f510b, "x86_dma_fallback_dev" },
	{ 0xfbc5ad18, "driver_for_each_device" },
	{ 0xeae3dfd6, "__const_udelay" },
	{ 0x6a9f26c9, "init_timer_key" },
	{ 0x5284a002, "pci_enable_wake" },
	{ 0x999e8297, "vfree" },
	{ 0xf0b8c647, "pci_bus_write_config_word" },
	{ 0x2447533c, "ktime_get_real" },
	{ 0xff964b25, "param_set_int" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0x45947727, "param_array_set" },
	{ 0xbb370841, "netif_napi_del" },
	{ 0x7d11c268, "jiffies" },
	{ 0x27c33efe, "csum_ipv6_magic" },
	{ 0x8a04551b, "__pskb_pull_tail" },
	{ 0x9629486a, "per_cpu__cpu_number" },
	{ 0xfe7c4287, "nr_cpu_ids" },
	{ 0x704515ec, "pci_set_master" },
	{ 0xefe21a96, "dca3_get_tag" },
	{ 0xe83fea1, "del_timer_sync" },
	{ 0xde0bdcff, "memset" },
	{ 0xb839a8a3, "alloc_etherdev_mq" },
	{ 0xba86a02e, "pci_enable_pcie_error_reporting" },
	{ 0x2e471f01, "dca_register_notify" },
	{ 0xf85ccdae, "kmem_cache_alloc_notrace" },
	{ 0x39871739, "pci_enable_msix" },
	{ 0x67e09a7, "pci_restore_state" },
	{ 0x8006c614, "dca_unregister_notify" },
	{ 0xc16fe12d, "__memcpy" },
	{ 0xea147363, "printk" },
	{ 0x204f5677, "free_netdev" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0x85f8a266, "copy_to_user" },
	{ 0xd524c41a, "register_netdev" },
	{ 0xb4390f9a, "mcount" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0x6dcaeb88, "per_cpu__kernel_stack" },
	{ 0xd917c158, "per_cpu__node_number" },
	{ 0x847922c2, "dev_close" },
	{ 0x45450063, "mod_timer" },
	{ 0x1902adf, "netpoll_trap" },
	{ 0x9b199c2b, "netif_napi_add" },
	{ 0x859c6dc7, "request_threaded_irq" },
	{ 0x2c1979b3, "dca_add_requester" },
	{ 0x2857afb8, "skb_pull" },
	{ 0x24120b03, "dev_kfree_skb_any" },
	{ 0x347a6db9, "dev_open" },
	{ 0xe523ad75, "synchronize_irq" },
	{ 0x4d1adc97, "pci_find_capability" },
	{ 0x567dab76, "pci_select_bars" },
	{ 0x7dceceac, "capable" },
	{ 0xc0bf6ead, "timecounter_cyc2time" },
	{ 0x645d1480, "netif_device_attach" },
	{ 0x751393aa, "napi_gro_receive" },
	{ 0x78764f4e, "pv_irq_ops" },
	{ 0xbe886a37, "netif_device_detach" },
	{ 0x58da9460, "__alloc_skb" },
	{ 0x42c8de35, "ioremap_nocache" },
	{ 0x9f5adb22, "pci_bus_read_config_word" },
	{ 0x38b20616, "ethtool_op_set_sg" },
	{ 0x56d9f8a6, "__napi_schedule" },
	{ 0xac4301f6, "pci_cleanup_aer_uncorrect_error_status" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x91390534, "kfree_skb" },
	{ 0x36875389, "__timecompare_update" },
	{ 0x65ef7ee6, "eth_type_trans" },
	{ 0x616040f2, "dev_driver_string" },
	{ 0x6c0cea99, "pskb_expand_head" },
	{ 0xe912fd46, "pci_unregister_driver" },
	{ 0xcc5005fe, "msleep_interruptible" },
	{ 0xa7ec84ac, "kmem_cache_alloc_node_notrace" },
	{ 0xc4061f09, "node_states" },
	{ 0x77cfcfde, "__tracepoint_kmalloc_node" },
	{ 0xe52947e7, "__phys_addr" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0x135fb6e0, "pci_set_power_state" },
	{ 0xdd5c9680, "eth_validate_addr" },
	{ 0x3fc1959c, "pci_disable_pcie_error_reporting" },
	{ 0x3aa1dbcf, "_spin_unlock_bh" },
	{ 0x37a0cba, "kfree" },
	{ 0x6067a146, "memcpy" },
	{ 0x801678, "flush_scheduled_work" },
	{ 0xf35e574c, "___pskb_trim" },
	{ 0xca7bb8ec, "pci_disable_msi" },
	{ 0xedc03953, "iounmap" },
	{ 0xec4bb178, "pci_prepare_to_sleep" },
	{ 0x2df398a3, "__pci_register_driver" },
	{ 0x2288378f, "system_state" },
	{ 0x52734205, "put_page" },
	{ 0xb352177e, "find_first_bit" },
	{ 0x4cbbd171, "__bitmap_weight" },
	{ 0x64a0bccb, "unregister_netdev" },
	{ 0xae3c276d, "__netdev_alloc_page" },
	{ 0x1675606f, "bad_dma_address" },
	{ 0x98b15475, "get_page" },
	{ 0xc50a8cdc, "ethtool_op_get_tso" },
	{ 0x9edbecae, "snprintf" },
	{ 0x119c335a, "pci_enable_msi_block" },
	{ 0xf18815a8, "__netif_schedule" },
	{ 0x958ed654, "consume_skb" },
	{ 0xd181b278, "dca_remove_requester" },
	{ 0xeb754399, "pci_enable_device_mem" },
	{ 0x117944c7, "vlan_gro_receive" },
	{ 0xee290a5a, "skb_tstamp_tx" },
	{ 0x93cbd1ec, "_spin_lock_bh" },
	{ 0x9c839d3a, "skb_put" },
	{ 0x97636cc5, "pci_wake_from_d3" },
	{ 0x2a5507d9, "pci_set_consistent_dma_mask" },
	{ 0xe7ba4eea, "pci_release_selected_regions" },
	{ 0x9c2bf4b8, "pci_request_selected_regions" },
	{ 0x3302b500, "copy_from_user" },
	{ 0xfc44cbc7, "dev_get_drvdata" },
	{ 0x23fd3028, "vmalloc_node" },
	{ 0x9e7d6bd0, "__udelay" },
	{ 0xd7d46dfe, "dma_ops" },
	{ 0xf20dabd8, "free_irq" },
	{ 0x405e56c3, "pci_save_state" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=dca";

MODULE_ALIAS("pci:v00008086d00001521sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001522sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001523sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001524sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000150Esv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000150Fsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001527sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001510sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001511sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001516sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00000438sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000043Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000043Csv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00000440sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C9sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000150Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001518sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010E6sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010E7sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000150Dsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001526sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010E8sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010A7sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010A9sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010D6sv*sd*bc*sc*i*");

MODULE_INFO(srcversion, "BAAD5948059DD794C854151");
