/*
 * Copyright (C) 2009 Red Hat, Inc. All rights reserved.
 *
 * Module Author: Heinz Mauelshagen (heinzm@redhat.com)
 *
 * Generic registry for arbitrary structures
 * (needs dm_registry_type structure upfront each registered structure).
 *
 * This file is released under the GPL.
 *
 * FIXME: use as registry for e.g. dirty log types as well.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "dm-registry.h"

#define	DM_MSG_PREFIX	"dm-registry"

static const char *version = "0.001";

/* Sizable class registry. */
static unsigned num_classes;
static struct list_head *_classes;
static rwlock_t *_locks;

void *
dm_get_type(const char *type_name, enum dm_registry_class class)
{
	struct dm_registry_type *t;

	read_lock(_locks + class);
	list_for_each_entry(t, _classes + class, list) {
		if (!strcmp(type_name, t->name)) {
			if (!t->use_count && !try_module_get(t->module)) {
				read_unlock(_locks + class);
				return ERR_PTR(-ENOMEM);
			}

			t->use_count++;
			read_unlock(_locks + class);
			return t;
		}
	}

	read_unlock(_locks + class);
	return ERR_PTR(-ENOENT);
}
EXPORT_SYMBOL(dm_get_type);

void
dm_put_type(void *type, enum dm_registry_class class)
{
	struct dm_registry_type *t = type;

	read_lock(_locks + class);
	if (!--t->use_count)
		module_put(t->module);

	read_unlock(_locks + class);
}
EXPORT_SYMBOL(dm_put_type);

/* Add a type to the registry. */
int
dm_register_type(void *type, enum dm_registry_class class)
{
	struct dm_registry_type *t = type, *tt;

	if (unlikely(class >= num_classes))
		return -EINVAL;

	tt = dm_get_type(t->name, class);
	if (unlikely(!IS_ERR(tt))) {
		dm_put_type(t, class);
		return -EEXIST;
	}

	write_lock(_locks + class);
	t->use_count = 0;
	list_add(&t->list, _classes + class);
	write_unlock(_locks + class);

	return 0;
}
EXPORT_SYMBOL(dm_register_type);

/* Remove a type from the registry. */
int
dm_unregister_type(void *type, enum dm_registry_class class)
{
	struct dm_registry_type *t = type;

	if (unlikely(class >= num_classes)) {
		DMERR("Attempt to unregister invalid class");
		return -EINVAL;
	}

	write_lock(_locks + class);

	if (unlikely(t->use_count)) {
		write_unlock(_locks + class);
		DMWARN("Attempt to unregister a type that is still in use");
		return -ETXTBSY;
	} else
		list_del(&t->list);

	write_unlock(_locks + class);
	return 0;
}
EXPORT_SYMBOL(dm_unregister_type);

/*
 * Return kmalloc'ed NULL terminated pointer
 * array of all type names of the given class.
 *
 * Caller has to kfree the array!.
 */
const char **dm_types_list(enum dm_registry_class class)
{
	unsigned i = 0, count = 0;
	const char **r;
	struct dm_registry_type *t;

	/* First count the registered types in the class. */
	read_lock(_locks + class);
	list_for_each_entry(t, _classes + class, list)
		count++;
	read_unlock(_locks + class);

	/* None registered in this class. */
	if (!count)
		return NULL;

	/* One member more for array NULL termination. */
	r = kzalloc((count + 1) * sizeof(*r), GFP_KERNEL);
	if (!r)
		return ERR_PTR(-ENOMEM);

	/*
	 * Go with the counted ones.
	 * Any new added ones after we counted will be ignored!
	 */
	read_lock(_locks + class);
	list_for_each_entry(t, _classes + class, list) {
		r[i++] = t->name;
		if (!--count)
			break;
	}
	read_unlock(_locks + class);

	return r;
}
EXPORT_SYMBOL(dm_types_list);

int __init
dm_registry_init(void)
{
	unsigned n;

	BUG_ON(_classes);
	BUG_ON(_locks);

	/* Module parameter given ? */
	if (!num_classes)
		num_classes = DM_REGISTRY_CLASS_END;

	n = num_classes;
	_classes = kmalloc(n * sizeof(*_classes), GFP_KERNEL);
	if (!_classes) {
		DMERR("Failed to allocate classes registry");
		return -ENOMEM;
	}

	_locks = kmalloc(n * sizeof(*_locks), GFP_KERNEL);
	if (!_locks) {
		DMERR("Failed to allocate classes locks");
		kfree(_classes);
		_classes = NULL;
		return -ENOMEM;
	}

	while (n--) {
		INIT_LIST_HEAD(_classes + n);
		rwlock_init(_locks + n);
	}

	DMINFO("initialized %s for max %u classes", version, num_classes);
	return 0;
}

void __exit
dm_registry_exit(void)
{
	BUG_ON(!_classes);
	BUG_ON(!_locks);

	kfree(_classes);
	_classes = NULL;
	kfree(_locks);
	_locks = NULL;
	DMINFO("exit %s", version);
}

/* Module hooks */
module_init(dm_registry_init);
module_exit(dm_registry_exit);
module_param(num_classes, uint, 0);
MODULE_PARM_DESC(num_classes, "Maximum number of classes");
MODULE_DESCRIPTION(DM_NAME "device-mapper registry");
MODULE_AUTHOR("Heinz Mauelshagen <heinzm@redhat.com>");
MODULE_LICENSE("GPL");

#ifndef MODULE
static int __init num_classes_setup(char *str)
{
	num_classes = simple_strtol(str, NULL, 0);
	return num_classes ? 1 : 0;
}

__setup("num_classes=", num_classes_setup);
#endif
