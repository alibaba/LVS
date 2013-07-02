#ifndef PAGECACHE_API_H
#define PAGECACHE_API_H

#ifdef CONFIG_PAGE_CACHE_ACCT

extern int pagecache_trace_init_sysfs(struct device *dev);
extern void pagecache_trace_remove_sysfs(struct device *dev);
extern struct attribute_group pagecache_trace_attr_group;

#else /* !CONFIG_PAGE_CACHE_ACCT */
# define pagecache_trace_remove_sysfs(dev)      do { } while (0)
static inline int pagecache_trace_init_sysfs(struct device *dev)
{
	return 0;
}

#endif /* CONFIG_PAGE_CACHE_ACCT */
#endif
