// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */

#include <fnmatch.h>

#include <libubox/kvlist.h>
#include <libubus.h>

#include "bridger.h"

static struct ubus_auto_conn conn;
static KVLIST(blacklist, kvlist_blob_len);
static bool bridge_local_tx = true;
static struct udebug_ubus udebug;
bool bridge_local_rx;
bool isolation_only;

#define BRIDGER_MAX_ISOLATED_VLANS BRIDGER_ISOLATION_MAP_SIZE

struct isolation_entry {
	uint16_t vid;
	uint8_t gateway_mac[6];
};

static struct isolation_entry isolated_vlans[BRIDGER_MAX_ISOLATED_VLANS];
static int n_isolated_vlans;

static struct isolation_entry *isolation_vlan_find(uint16_t vid)
{
	int i;

	for (i = 0; i < n_isolated_vlans; i++)
		if (isolated_vlans[i].vid == vid)
			return &isolated_vlans[i];

	return NULL;
}

bool bridger_vlan_isolated(uint16_t vid)
{
	return isolation_vlan_find(vid) != NULL;
}

bool bridger_isolation_active(void)
{
	return n_isolated_vlans > 0;
}

static struct isolation_entry *isolation_vlan_add(uint16_t vid)
{
	struct isolation_entry *entry;

	entry = isolation_vlan_find(vid);
	if (entry)
		return entry;

	if (n_isolated_vlans >= BRIDGER_MAX_ISOLATED_VLANS)
		return NULL;

	entry = &isolated_vlans[n_isolated_vlans++];
	memset(entry, 0, sizeof(*entry));
	entry->vid = vid;
	return entry;
}

static void isolation_vlan_del(uint16_t vid)
{
	struct isolation_entry *entry = isolation_vlan_find(vid);

	if (!entry)
		return;

	*entry = isolated_vlans[--n_isolated_vlans];
}

bool bridger_isolation_gateway_mac(const uint8_t *addr)
{
	int i;

	for (i = 0; i < n_isolated_vlans; i++)
		if (!memcmp(isolated_vlans[i].gateway_mac, addr, ETH_ALEN))
			return true;

	return false;
}

void bridger_isolation_update_upstream(struct bridge *br)
{
	int i;

	if (!br->vlan_enabled)
		return;

	for (i = 0; i < n_isolated_vlans; i++) {
		struct isolation_entry *entry = &isolated_vlans[i];
		struct bridger_vlan_isolation iso = {};
		struct fdb_key fkey = {};
		struct fdb_entry *f;
		uint32_t new_ifindex;

		memcpy(fkey.addr, entry->gateway_mac, ETH_ALEN);
		fkey.vlan = entry->vid;
		f = fdb_get(br, &fkey);
		new_ifindex = (f && f->dev) ? device_ifindex(f->dev) : 0;

		if (bridger_bpf_get_vlan_isolation(entry->vid, &iso) == 0 &&
		    iso.upstream_ifindex == new_ifindex &&
		    !memcmp(iso.gateway_mac, entry->gateway_mac, ETH_ALEN))
			continue;

		memcpy(iso.gateway_mac, entry->gateway_mac, ETH_ALEN);
		iso.upstream_ifindex = new_ifindex;
		bridger_bpf_set_vlan_isolation(entry->vid, &iso);

		D("VLAN %u upstream changed to ifindex %u\n",
		  entry->vid, new_ifindex);
	}
}

static void bridger_isolation_devices_update(void)
{
	struct device *dev;

	avl_for_each_element(&devices, dev, node)
		device_update(dev);
}

bool bridger_ubus_dev_blacklisted(struct device *dev)
{
	struct blob_attr *list, *cur;
	const char *name;
	int rem;

	kvlist_for_each(&blacklist, name, list)
		blobmsg_for_each_attr(cur, list, rem) {
			if (!fnmatch(blobmsg_get_string(cur), dev->ifname, 0))
				return true;
			if (dev->master &&
			    !fnmatch(blobmsg_get_string(cur), dev->master->ifname, 0))
				return true;
			if (!bridge_local_tx && dev->br)
				return true;
		}

	return false;
}

static void bridger_blacklist_update(void)
{
	struct device *dev;

	avl_for_each_element(&devices, dev, node) {
		if (dev->attached ==
		    ((dev->master || dev->br) && !bridger_ubus_dev_blacklisted(dev)))
			continue;

		device_update(dev);
	}
}

enum {
	BRIDGER_BLACKLIST_NAME,
	BRIDGER_BLACKLIST_DEVICES,
	__BRIDGER_BLACKLIST_MAX
};

static const struct blobmsg_policy blacklist_policy[__BRIDGER_BLACKLIST_MAX] = {
	[BRIDGER_BLACKLIST_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[BRIDGER_BLACKLIST_DEVICES] = { "devices", BLOBMSG_TYPE_ARRAY },
};

static int
bridger_set_blacklist(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[__BRIDGER_BLACKLIST_MAX];
	const char *name;
	void *prev;
	bool changed;

	blobmsg_parse(blacklist_policy, __BRIDGER_BLACKLIST_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[BRIDGER_BLACKLIST_NAME] || !tb[BRIDGER_BLACKLIST_DEVICES])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (blobmsg_check_array(tb[BRIDGER_BLACKLIST_DEVICES], BLOBMSG_TYPE_STRING) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	name = blobmsg_get_string(tb[BRIDGER_BLACKLIST_NAME]);
	prev = kvlist_get(&blacklist, name);
	changed = !blob_attr_equal(prev, tb[BRIDGER_BLACKLIST_DEVICES]);
	kvlist_set(&blacklist, name, tb[BRIDGER_BLACKLIST_DEVICES]);

	if (changed)
		bridger_blacklist_update();

	return 0;
}

enum {
	BRIDGER_DEVCFG_NAME,
	BRIDGER_DEVCFG_REDIRECT,
	__BRIDGER_DEVCFG_MAX,
};

static const struct blobmsg_policy devcfg_policy[__BRIDGER_DEVCFG_MAX] = {
	[BRIDGER_DEVCFG_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[BRIDGER_DEVCFG_REDIRECT] = { "redirect", BLOBMSG_TYPE_STRING },
};

static int
bridger_set_device_config(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	struct blob_attr *tb[__BRIDGER_DEVCFG_MAX], *cur;
	unsigned int redirect_dev = 0;
	struct device *dev;


	blobmsg_parse(devcfg_policy, __BRIDGER_DEVCFG_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if ((cur = tb[BRIDGER_DEVCFG_NAME]) == NULL)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if ((dev = device_get_by_name(blobmsg_get_string(cur))) == NULL)
		return UBUS_STATUS_NOT_FOUND;

	if ((cur = tb[BRIDGER_DEVCFG_REDIRECT]) != NULL &&
	    !(redirect_dev = if_nametoindex(blobmsg_get_string(cur))))
		return UBUS_STATUS_NOT_FOUND;

	if (device_set_redirect(dev, redirect_dev))
		return UBUS_STATUS_INVALID_ARGUMENT;

	return 0;
}

enum {
	BRIDGER_ISOLATION_VID,
	BRIDGER_ISOLATION_GATEWAY_MAC,
	BRIDGER_ISOLATION_ENABLED,
	__BRIDGER_ISOLATION_MAX,
};

static const struct blobmsg_policy isolation_policy[__BRIDGER_ISOLATION_MAX] = {
	[BRIDGER_ISOLATION_VID] = { "vid", BLOBMSG_TYPE_INT32 },
	[BRIDGER_ISOLATION_GATEWAY_MAC] = { "gateway_mac", BLOBMSG_TYPE_STRING },
	[BRIDGER_ISOLATION_ENABLED] = { "enabled", BLOBMSG_TYPE_BOOL },
};

static int
bridger_set_vlan_isolation(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	struct blob_attr *tb[__BRIDGER_ISOLATION_MAX];
	struct isolation_entry *entry;
	bool was_active = bridger_isolation_active();
	struct device *dev;
	const char *mac_str;
	uint16_t vid;
	uint8_t mac[6];

	blobmsg_parse(isolation_policy, __BRIDGER_ISOLATION_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[BRIDGER_ISOLATION_VID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	vid = blobmsg_get_u32(tb[BRIDGER_ISOLATION_VID]);
	if (!vid || vid > 4094)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[BRIDGER_ISOLATION_ENABLED] &&
	    !blobmsg_get_bool(tb[BRIDGER_ISOLATION_ENABLED])) {
		isolation_vlan_del(vid);
		bridger_bpf_del_vlan_isolation(vid);
		D("Removed VLAN %u isolation\n", vid);
		if (was_active != bridger_isolation_active())
			bridger_isolation_devices_update();
		return 0;
	}

	if (!tb[BRIDGER_ISOLATION_GATEWAY_MAC])
		return UBUS_STATUS_INVALID_ARGUMENT;

	mac_str = blobmsg_get_string(tb[BRIDGER_ISOLATION_GATEWAY_MAC]);
	if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6)
		return UBUS_STATUS_INVALID_ARGUMENT;

	entry = isolation_vlan_add(vid);
	if (!entry)
		return UBUS_STATUS_UNKNOWN_ERROR;

	memcpy(entry->gateway_mac, mac, sizeof(mac));

	D("Set VLAN %u isolation: gateway=%s\n", vid, mac_str);

	bridger_isolation_devices_update();

	avl_for_each_element(&devices, dev, node)
		if (dev->br)
			bridger_isolation_update_upstream(dev->br);

	return 0;
}

enum {
	BRIDGER_CONFIG_LOCAL_TX,
	BRIDGER_CONFIG_LOCAL_RX,
	BRIDGER_CONFIG_BLACKLIST,
	BRIDGER_CONFIG_ISOLATION_ONLY,
	__BRIDGER_CONFIG_MAX
};

static const struct blobmsg_policy config_policy[__BRIDGER_CONFIG_MAX] = {
	[BRIDGER_CONFIG_LOCAL_RX] = { "bridge_local_rx", BLOBMSG_TYPE_BOOL },
	[BRIDGER_CONFIG_LOCAL_TX] = { "bridge_local_tx", BLOBMSG_TYPE_BOOL },
	[BRIDGER_CONFIG_BLACKLIST] = { "blacklist", BLOBMSG_TYPE_ARRAY },
	[BRIDGER_CONFIG_ISOLATION_ONLY] = { "isolation_only", BLOBMSG_TYPE_BOOL },
};

static int
bridger_set_config(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__BRIDGER_CONFIG_MAX];
	struct blob_attr *cur;
	struct device *dev;
	bool changed = true;
	bool local;

	blobmsg_parse(config_policy, __BRIDGER_CONFIG_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	cur = tb[BRIDGER_CONFIG_BLACKLIST];
	changed = !blob_attr_equal(kvlist_get(&blacklist, "config"), cur);
	if (cur != NULL) {
		if (blobmsg_check_array(cur, BLOBMSG_TYPE_STRING) < 0)
			return UBUS_STATUS_INVALID_ARGUMENT;
		kvlist_set(&blacklist, "config", cur);
	} else {
		kvlist_delete(&blacklist, "config");
	}

	cur = tb[BRIDGER_CONFIG_LOCAL_TX];
	local = !cur || blobmsg_get_bool(cur);
	if (bridge_local_tx != local) {
		bridge_local_tx = local;
		changed = true;
	}

	cur = tb[BRIDGER_CONFIG_LOCAL_RX];
	local = cur && blobmsg_get_bool(cur);
	if (bridge_local_rx != local) {
		bridge_local_rx = local;
		avl_for_each_element(&devices, dev, node)
			if (dev->br)
				device_clear_flows(dev);
	}

	cur = tb[BRIDGER_CONFIG_ISOLATION_ONLY];
	if (cur) {
		bool val = blobmsg_get_bool(cur);

		if (isolation_only != val) {
			isolation_only = val;
			if (val)
				bridger_bpf_poll_disable();
			else
				bridger_bpf_poll_enable();
		}
	}

	if (changed)
		bridger_blacklist_update();

	return 0;
}


static const struct ubus_method bridger_methods[] = {
	UBUS_METHOD("set_config", bridger_set_config, config_policy),
	UBUS_METHOD("set_blacklist", bridger_set_blacklist, blacklist_policy),
	UBUS_METHOD("set_device_config", bridger_set_device_config, devcfg_policy),
	UBUS_METHOD("set_vlan_isolation", bridger_set_vlan_isolation, isolation_policy),
};

static struct ubus_object_type bridger_object_type =
	UBUS_OBJECT_TYPE("bridger", bridger_methods);

static struct ubus_object bridger_object = {
	.name = "bridger",
	.type = &bridger_object_type,
	.methods = bridger_methods,
	.n_methods = ARRAY_SIZE(bridger_methods),
};

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &bridger_object);
	udebug_ubus_init(&udebug, &conn.ctx, "bridger", bridger_udebug_config);
}

int bridger_ubus_init(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);

	return 0;
}

void bridger_ubus_stop(void)
{
	ubus_auto_shutdown(&conn);
}
