/*
 * Copyright (C) 2009 Red Hat, Inc. All rights reserved.
 *
 * Module Author: Heinz Mauelshagen (heinzm@redhat.com)
 *
 * Generic registry for arbitrary structures.
 * (needs dm_registry_type structure upfront each registered structure).
 *
 * This file is released under the GPL.
 */

#include "dm.h"

#ifndef DM_REGISTRY_H
#define DM_REGISTRY_H

enum dm_registry_class {
	DM_REPLOG = 0,
	DM_SLINK,
	DM_LOG,
	DM_REGION_HASH,
	DM_REGISTRY_CLASS_END,
};

struct dm_registry_type {
	struct list_head list;	/* Linked list of types in this class. */
	const char *name;
	struct module *module;
	unsigned int use_count;
};

void *dm_get_type(const char *type_name, enum dm_registry_class class);
void dm_put_type(void *type, enum dm_registry_class class);
int dm_register_type(void *type, enum dm_registry_class class);
int dm_unregister_type(void *type, enum dm_registry_class class);
const char **dm_types_list(enum dm_registry_class class);

#endif
