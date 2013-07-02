#include <linux/genhd.h>
#include <trace/events/mm.h>

DEFINE_TRACE(page_cache_acct_hits);
DEFINE_TRACE(page_cache_acct_misses);
DEFINE_TRACE(page_cache_acct_hit);
DEFINE_TRACE(page_cache_acct_miss);
DEFINE_TRACE(page_cache_acct_readpages);

#ifdef CONFIG_PAGE_CACHE_ACCT

static bool pagecache_tracer_enabled __read_mostly;

static void page_cache_acct_readpages(struct super_block *sb, int nr_pages)
{
	struct block_device *bdev = sb->s_bdev;
	struct hd_struct *part;
	int cpu;
	if (likely(bdev) && likely(part = bdev->bd_part)) {
		cpu = part_stat_lock();
		part_stat_add(cpu, part, page_cache_readpages, nr_pages);
		part_stat_unlock();
	}
}

static inline void __page_cache_acct_hit(struct super_block *sb, int rw, int nr_pages)
{
	struct block_device *bdev = sb->s_bdev;
	struct hd_struct *part;
	int cpu;
	if (likely(bdev) && likely(part = bdev->bd_part)) {
		cpu = part_stat_lock();
		part_stat_add(cpu, part, page_cache_hit[rw], nr_pages);
		part_stat_unlock();
	}
}

static void page_cache_acct_hit(struct super_block *sb, int rw)
{
	__page_cache_acct_hit(sb, rw, 1);
}

static void page_cache_acct_hits(struct super_block *sb ,int rw, int nr_pages)
{
	__page_cache_acct_hit(sb, rw, nr_pages);
}

static inline void __page_cache_acct_miss(struct super_block *sb, int rw, int nr_pages)
{
	struct block_device *bdev = sb->s_bdev;
	struct hd_struct *part;
	int cpu;
	if (likely(bdev) && likely(part = bdev->bd_part)) {
		cpu = part_stat_lock();
		part_stat_add(cpu, part, page_cache_missed[rw], nr_pages);
		part_stat_unlock();
	}
}

static void page_cache_acct_miss(struct super_block *sb, int rw)
{
	__page_cache_acct_miss(sb, rw, 1);
}

static void page_cache_acct_misses(struct super_block *sb, int rw, int nr_pages)
{
	__page_cache_acct_miss(sb, rw, nr_pages);
}

static void pagecache_acct_setup(void)
{
	int ret;
	if (pagecache_tracer_enabled)
		return;

	ret = register_trace_page_cache_acct_readpages(page_cache_acct_readpages);
	WARN_ON(ret);
	ret = register_trace_page_cache_acct_hit(page_cache_acct_hit);
	WARN_ON(ret);
	ret = register_trace_page_cache_acct_hits(page_cache_acct_hits);
	WARN_ON(ret);
	ret = register_trace_page_cache_acct_miss(page_cache_acct_miss);
	WARN_ON(ret);
	ret = register_trace_page_cache_acct_misses(page_cache_acct_misses);
	WARN_ON(ret);

	if (!ret)
		pagecache_tracer_enabled = 1;
}

static void pagecache_acct_remove(void)
{
	unregister_trace_page_cache_acct_readpages(page_cache_acct_readpages);
	unregister_trace_page_cache_acct_hit(page_cache_acct_hit);
	unregister_trace_page_cache_acct_hits(page_cache_acct_hits);
	unregister_trace_page_cache_acct_miss(page_cache_acct_miss);
	unregister_trace_page_cache_acct_misses(page_cache_acct_misses);

	pagecache_tracer_enabled = 0;
	tracepoint_synchronize_unregister();
}

static ssize_t sysfs_pagecache_trace_attr_show(struct device *dev,
                                        struct device_attribute *attr,
                                        char *buf);

static ssize_t sysfs_pagecache_trace_attr_store(struct device *dev,
                                        struct device_attribute *attr,
                                        const char *buf, size_t count);

#define PAGECACHE_TRACE_DEVICE_ATTR(_name) \
        DEVICE_ATTR(_name, S_IRUGO | S_IWUSR, \
                    sysfs_pagecache_trace_attr_show, \
                    sysfs_pagecache_trace_attr_store)

static PAGECACHE_TRACE_DEVICE_ATTR(stat);
static PAGECACHE_TRACE_DEVICE_ATTR(enable);

static struct attribute *pagecache_trace_attrs[] = {
	&dev_attr_stat.attr,
	&dev_attr_enable.attr,
	NULL
};

struct attribute_group pagecache_trace_attr_group = {
	.name = "pagecache",
	.attrs = pagecache_trace_attrs,
};

int pagecache_trace_init_sysfs(struct device *dev)
{
	return sysfs_create_group(&dev->kobj, &pagecache_trace_attr_group);
}

void pagecache_trace_remove_sysfs(struct device *dev)
{
	sysfs_remove_group(&dev->kobj, &pagecache_trace_attr_group);
}

static ssize_t sysfs_pagecache_trace_attr_show(struct device *dev,
                                        struct device_attribute *attr,
                                        char *buf)
{
	int ret = -EINVAL;

	if (!pagecache_tracer_enabled) {
		ret = sprintf(buf, "disabled\n");
		goto out;
	}
	if (attr == &dev_attr_stat) {
	       struct hd_struct  *p = dev_to_part(dev);

	       ret = sprintf(buf,
			       "%8lu %8lu %8lu %8lu %8lu\n",
			       part_stat_read(p, page_cache_readpages),
			       part_stat_read(p, page_cache_missed[READ]),
			       part_stat_read(p, page_cache_hit[READ]),
			       part_stat_read(p, page_cache_missed[WRITE]),
			       part_stat_read(p, page_cache_hit[WRITE]));
		goto out;
	}
	if (attr == &dev_attr_enable)
		ret = sprintf(buf, "%u\n", pagecache_tracer_enabled);
out:
	return ret;
}

static ssize_t sysfs_pagecache_trace_attr_store(struct device *dev,
                                        struct device_attribute *attr,
                                        const char *buf, size_t count)
{
	u64 value;
	ssize_t ret = -EINVAL;

	if (count == 0)
		goto out;
	if (attr == &dev_attr_stat)
		goto out;
	if (attr == &dev_attr_enable) {
		ret = sscanf(buf, "%llu", &value);
		if (ret != 1)
			goto out;
		if (value)
			pagecache_acct_setup();
		else
			pagecache_acct_remove();
	}
out:
	return ret ? ret : count;
}

#endif
