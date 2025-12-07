// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <errno.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/timeout.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/crypto.h"

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#define MAX_CHAR_DECL_VALUE_LEN 19
#define MAX_INCLUDED_VALUE_LEN 6
#define ATTRIBUTE_TIMEOUT 5000
#define HASH_UPDATE_TIMEOUT 100

static const bt_uuid_t primary_service_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_PRIM_SVC_UUID };
static const bt_uuid_t secondary_service_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_SND_SVC_UUID };
static const bt_uuid_t characteristic_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_CHARAC_UUID };
static const bt_uuid_t included_service_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_INCLUDE_UUID };
static const bt_uuid_t ext_desc_uuid = { .type = BT_UUID16,
				.value.u16 = GATT_CHARAC_EXT_PROPER_UUID };
static const bt_uuid_t ccc_uuid = { .type = BT_UUID16,
				.value.u16 = GATT_CLIENT_CHARAC_CFG_UUID };

struct gatt_db_ccc {
	gatt_db_read_t read_func;
	gatt_db_write_t write_func;
	gatt_db_notify_t notify_func;
	void *user_data;
};

struct gatt_db {
	int ref_count;/*引用计数*/
	struct bt_crypto *crypto;
	uint8_t hash[16];
	unsigned int hash_id;
	uint16_t last_handle;/*负责分配handle*/
	struct queue *services;

	struct queue *notify_list;/*串连notify*/
	unsigned int next_notify_id;/*负责分配notify id*/

	gatt_db_authorize_cb_t authorize;
	void *authorize_data;

	struct gatt_db_ccc *ccc;
};

struct notify {
	unsigned int id;/*notify唯一id*/
	gatt_db_attribute_cb_t service_added;/*服务添加*/
	gatt_db_attribute_cb_t service_removed;/*服务移除*/
	gatt_db_authorize_cb_t authorize_cb;
	gatt_db_destroy_func_t destroy;
	void *user_data;/*回调参数*/
};

struct attribute_notify {
	unsigned int id;
	gatt_db_attribute_cb_t removed;
	gatt_db_destroy_func_t destroy;
	void *user_data;
};

struct pending_read {
	struct gatt_db_attribute *attrib;
	unsigned int id;
	unsigned int timeout_id;/*定时器*/
	gatt_db_attribute_read_t func;
	void *user_data;
};

struct pending_write {
	struct gatt_db_attribute *attrib;
	unsigned int id;
	unsigned int timeout_id;
	gatt_db_attribute_write_t func;
	void *user_data;
};

struct gatt_db_attribute {
	struct gatt_db_service *service;/*所属service*/
	uint16_t handle;/*attribute[0]时记录service handle; 属性handle*/
	bt_uuid_t uuid;/*属性类型（uuid类型），例如primary_service_uuid*/
	uint32_t permissions;/*属性权限*/
	uint16_t value_len;/*value数组长度*/
	uint8_t *value;/*attribute[0]时记录的是service uuid; 属性值*/

	gatt_db_read_t read_func;
	gatt_db_write_t write_func;
	gatt_db_notify_t notify_func;
	void *user_data;/*回调参数*/

	unsigned int read_id;/*用于分配pending_read编号*/
	struct queue *pending_reads;

	unsigned int write_id;
	struct queue *pending_writes;

	unsigned int next_notify_id;
	struct queue *notify_list;
};

struct gatt_db_service {
	struct gatt_db *db;/*所属的db*/
	bool active;/*此serivce是否已活跃*/
	bool claimed;
	uint16_t num_handles;/*attributes数组长度-1(0被用于特殊属性）*/
	struct gatt_db_attribute **attributes;
};

static void set_attribute_data(struct gatt_db_attribute *attribute,
						gatt_db_read_t read_func,
						gatt_db_write_t write_func,
						uint32_t permissions/*权限*/,
						void *user_data)
{
	attribute->permissions = permissions;
	attribute->read_func = read_func;
	attribute->write_func = write_func;
	attribute->user_data = user_data;
}

static void pending_read_result(struct pending_read *p, int err,
					const uint8_t *data, size_t length)
{
	if (p->timeout_id > 0)
		timeout_remove(p->timeout_id);

	p->func(p->attrib, err, data, length, p->user_data);

	free(p);
}

static void pending_read_free(void *data)
{
	struct pending_read *p = data;

	pending_read_result(p, -ECANCELED, NULL, 0);
}

static void pending_write_result(struct pending_write *p, int err)
{
	if (p->timeout_id > 0)
		timeout_remove(p->timeout_id);

	p->func(p->attrib, err, p->user_data);

	free(p);
}

static void pending_write_free(void *data)
{
	struct pending_write *p = data;

	pending_write_result(p, -ECANCELED);
}

static void attribute_notify_destroy(void *data)
{
	struct attribute_notify *notify = data;

	if (notify->destroy)
		notify->destroy(notify->user_data);

	free(notify);
}

static void attribute_destroy(struct gatt_db_attribute *attribute)
{
	/* Attribute was not initialized by user */
	if (!attribute)
		return;

	queue_destroy(attribute->pending_reads, pending_read_free);
	queue_destroy(attribute->pending_writes, pending_write_free);
	queue_destroy(attribute->notify_list, attribute_notify_destroy);

	free(attribute->value);
	free(attribute);
}

/*创建attribute*/
static struct gatt_db_attribute *new_attribute(struct gatt_db_service *service,
							uint16_t handle/*属性handle*/,
							const bt_uuid_t *type/*属性type*/,
							const uint8_t *val/*属性value*/,
							uint16_t len/*val长度*/)
{
	struct gatt_db_attribute *attribute;

	attribute = new0(struct gatt_db_attribute, 1);

	attribute->service = service;
	attribute->handle = handle;
	attribute->uuid = *type;
	attribute->value_len = len;
	if (len) {
		attribute->value = malloc0(len);
		if (!attribute->value)
			goto failed;

		memcpy(attribute->value, val, len);/*填充val*/
	}

	attribute->pending_reads = queue_new();
	attribute->pending_writes = queue_new();
	attribute->notify_list = queue_new();

	return attribute;

failed:
	attribute_destroy(attribute);
	return NULL;
}

/*增加gatt_db引用计数*/
struct gatt_db *gatt_db_ref(struct gatt_db *db)
{
	if (!db)
		return NULL;

	__sync_fetch_and_add(&db->ref_count, 1);

	return db;
}

/*创建gatt_db*/
struct gatt_db *gatt_db_new(void)
{
	struct gatt_db *db;

	db = new0(struct gatt_db, 1);
	db->crypto = bt_crypto_new();
	db->services = queue_new();/*初始化services队列*/
	db->notify_list = queue_new();/*初始化notify list*/
	db->last_handle = 0x0000;

	return gatt_db_ref(db);
}

static void service_clone(void *data, void *user_data)
{
	struct gatt_db_service *service = data;
	struct gatt_db *db = user_data;
	struct gatt_db_service *clone;
	int i;

	clone = new0(struct gatt_db_service, 1);
	clone->db = db;
	clone->active = service->active;
	clone->num_handles = service->num_handles;
	clone->attributes = new0(struct gatt_db_attribute *,
					service->num_handles);/*申请指针数组，并初始化为0*/

	/* Clone attributes */
	for (i = 0; i < service->num_handles; i++) {
		/*取service的i号attributes*/
		struct gatt_db_attribute *attr = service->attributes[i];

		if (!attr)
			continue;

		/* Only clone values for characteristics declaration since that
		 * is considered when calculating the db hash.
		 */
		if (bt_uuid_len(&attr->uuid) != 2) {
			clone->attributes[i] = new_attribute(clone,
							attr->handle,
							&attr->uuid,
							NULL, 0);
			continue;
		}

		/* Attribute values that are used for generating the hash needs
		 * to be cloned as well.
		 */
		switch (attr->uuid.value.u16) {
		case GATT_PRIM_SVC_UUID:
		case GATT_SND_SVC_UUID:
		case GATT_INCLUDE_UUID:
		case GATT_CHARAC_UUID:
			clone->attributes[i] = new_attribute(clone,
							attr->handle,
							&attr->uuid,
							attr->value,
							attr->value_len);
			break;
		default:
			clone->attributes[i] = new_attribute(clone,
							attr->handle,
							&attr->uuid,
							NULL, 0);
			break;
		}
	}

	queue_push_tail(db->services, clone);/*添加serivce*/
}

/*利用db创建一个副本*/
struct gatt_db *gatt_db_clone(struct gatt_db *db)
{
	struct gatt_db *clone;

	if (!db)
		return NULL;

	clone = gatt_db_new();
	if (!clone)
		return NULL;

	queue_foreach(db->services, service_clone, clone);

	return clone;
}

/*释放notify*/
static void notify_destroy(void *data)
{
	struct notify *notify = data;

	if (notify->destroy)
		/*调用destroy*/
		notify->destroy(notify->user_data);

	free(notify);
}

static bool match_notify_id(const void *a, const void *b)
{
	const struct notify *notify = a;
	unsigned int id = PTR_TO_UINT(b);

	return notify->id == id;
}

struct notify_data {
	struct gatt_db_attribute *attr;
	bool added;
};

static void handle_notify(void *data, void *user_data)
{
	struct notify *notify = data;
	struct notify_data *notify_data = user_data;

	if (notify_data->added)
		notify->service_added(notify_data->attr, notify->user_data);
	else
		notify->service_removed(notify_data->attr, notify->user_data);
}

struct hash_data {
	struct iovec *iov;
	uint16_t i;
};

static void gen_hash_m(struct gatt_db_attribute *attr, void *user_data)
{
	struct hash_data *hash = user_data;
	uint8_t *data;
	size_t len;

	if (!attr || !attr->value)
		return;

	if (bt_uuid_len(&attr->uuid) != 2)
		return;

	switch (attr->uuid.value.u16) {
	case GATT_PRIM_SVC_UUID:
	case GATT_SND_SVC_UUID:
	case GATT_INCLUDE_UUID:
	case GATT_CHARAC_UUID:
		/* Allocate space for handle + type + value */
		len = 2 + 2 + attr->value_len;
		data = malloc(2 + 2 + attr->value_len);
		put_le16(attr->handle, data);
		bt_uuid_to_le(&attr->uuid, data + 2);
		memcpy(data + 4, attr->value, attr->value_len);
		break;
	case GATT_CHARAC_USER_DESC_UUID:
	case GATT_CLIENT_CHARAC_CFG_UUID:
	case GATT_SERVER_CHARAC_CFG_UUID:
	case GATT_CHARAC_FMT_UUID:
	case GATT_CHARAC_AGREG_FMT_UUID:
		/* Allocate space for handle + type  */
		len = 2 + 2;
		data = malloc(2 + 2 + attr->value_len);
		put_le16(attr->handle, data);
		bt_uuid_to_le(&attr->uuid, data + 2);
		break;
	default:
		return;
	}

	hash->iov[hash->i].iov_base = data;
	hash->iov[hash->i].iov_len = len;

	hash->i++;

	return;
}

static void service_gen_hash_m(struct gatt_db_attribute *attr, void *user_data)
{
	gatt_db_service_foreach(attr, NULL, gen_hash_m, user_data);
}

static bool db_hash_update(void *user_data)
{
	struct gatt_db *db = user_data;
	struct hash_data hash;
	uint16_t i;

	db->hash_id = 0;

	if (gatt_db_isempty(db))
		return false;

	hash.iov = new0(struct iovec, db->last_handle + 1);
	hash.i = 0;

	gatt_db_foreach_service(db, NULL, service_gen_hash_m, &hash);
	bt_crypto_gatt_hash(db->crypto, hash.iov, db->last_handle + 1,
				db->hash);

	for (i = 0; i < hash.i; i++)
		free(hash.iov[i].iov_base);

	free(hash.iov);

	return false;
}

static void handle_attribute_notify(void *data, void *user_data)
{
	struct attribute_notify *notify = data;
	struct gatt_db_attribute *attrib = user_data;

	if (notify->removed)
		notify->removed(attrib, notify->user_data);
}

static void notify_attribute_changed(struct gatt_db_service *service)
{
	int i;

	for (i = 0; i < service->num_handles; i++) {
		struct gatt_db_attribute *attr = service->attributes[i];

		if (!attr)
			continue;

		queue_foreach(attr->notify_list, handle_attribute_notify, attr);
	}
}

static void notify_service_changed(struct gatt_db *db,
						struct gatt_db_service *service,
						bool added)
{
	struct notify_data data;

	if (!added)
		notify_attribute_changed(service);

	if (queue_isempty(db->notify_list))
		return;/*队列为空，返回*/

	data.attr = service->attributes[0];
	data.added = added;

	gatt_db_ref(db);

	queue_foreach(db->notify_list, handle_notify, &data);

	/* Trigger hash update */
	if (!db->hash_id && db->crypto)
		db->hash_id = timeout_add(HASH_UPDATE_TIMEOUT, db_hash_update,
								db, NULL);

	gatt_db_unref(db);
}

static void gatt_db_service_destroy(void *data)
{
	struct gatt_db_service *service = data;
	int i;

	if (service->active)
		notify_service_changed(service->db, service, false);

	for (i = 0; i < service->num_handles; i++)
		attribute_destroy(service->attributes[i]);

	free(service->attributes);
	free(service);
}

static void gatt_db_destroy(struct gatt_db *db)
{
	if (!db)
		return;

	bt_crypto_unref(db->crypto);

	/*
	 * Clear the notify list before clearing the services to prevent the
	 * latter from sending service_removed events.
	 */
	queue_destroy(db->notify_list, notify_destroy);
	db->notify_list = NULL;

	if (db->hash_id)
		timeout_remove(db->hash_id);

	queue_destroy(db->services, gatt_db_service_destroy);
	free(db->ccc);
	free(db);
}

void gatt_db_unref(struct gatt_db *db)
{
	if (!db)
		return;

	if (__sync_sub_and_fetch(&db->ref_count, 1))
		return;

	gatt_db_destroy(db);
}

bool gatt_db_isempty(struct gatt_db *db)
{
	if (!db)
		return true;

	return queue_isempty(db->services);/*检查services是否为空*/
}

/*利用uuid填充dst，并返回内容长度*/
static int uuid_to_le(const bt_uuid_t *uuid, uint8_t *dst)
{
	bt_uuid_t uuid128;

	if (uuid->type == BT_UUID16) {
		put_le16(uuid->value.u16, dst);
		return bt_uuid_len(uuid);
	}

	bt_uuid_to_uuid128(uuid, &uuid128);
	bswap_128(&uuid128.value.u128, dst);
	return bt_uuid_len(&uuid128);
}

static bool le_to_uuid(const uint8_t *src, size_t len, bt_uuid_t *uuid)
{
	uint128_t u128;

	if (len == 2) {
		bt_uuid16_create(uuid, get_le16(src));
		return true;
	}

	if (len == 4) {
		bt_uuid32_create(uuid, get_le32(src));
		return true;
	}

	if (len != 16)
		return false;

	bswap_128(src, &u128);
	bt_uuid128_create(uuid, u128);

	return true;
}

/*创建db_service*/
static struct gatt_db_service *gatt_db_service_create(const bt_uuid_t *uuid,
							uint16_t handle,
							bool primary/*是否为主uuid*/,
							uint16_t num_handles)
{
	struct gatt_db_service *service;
	const bt_uuid_t *type;
	uint8_t value[16];
	uint16_t len;

	if (num_handles < 1)
		return NULL;

	service = new0(struct gatt_db_service, 1);
	service->attributes = new0(struct gatt_db_attribute *, num_handles);

	if (primary)
		/*主uuid*/
		type = &primary_service_uuid;
	else
		/*从uuid*/
		type = &secondary_service_uuid;

	/*利用uuid填充value,并返回填充长度*/
	len = uuid_to_le(uuid, value);

	service->attributes[0] = new_attribute(service, handle, type, value,
									len);
	if (!service->attributes[0]) {
		gatt_db_service_destroy(service);
		return NULL;
	}

	set_attribute_data(service->attributes[0], NULL, NULL, BT_ATT_PERM_READ, NULL);

	return service;
}


bool gatt_db_remove_service(struct gatt_db *db,
					struct gatt_db_attribute *attrib)
{
	struct gatt_db_service *service;

	if (!db || !attrib)
		return false;

	service = attrib->service;

	queue_remove(db->services, service);/*移除此serivce*/

	gatt_db_service_destroy(service);

	return true;
}

bool gatt_db_clear(struct gatt_db *db)
{
	return gatt_db_clear_range(db, 1, UINT16_MAX);
}

/*attributes[0]中保存的是起始handle，取start_handle,end_handle*/
static void gatt_db_service_get_handles(const struct gatt_db_service *service,
							uint16_t *start_handle,
							uint16_t *end_handle)
{
	if (start_handle)
		*start_handle = service->attributes[0]->handle;/*attributes[0]的handle指向首个handle*/

	if (end_handle)
		*end_handle = service->attributes[0]->handle +
						service->num_handles - 1;
}

struct clear_range {
	uint16_t start, end;
};

static bool match_range(const void *a, const void *b)
{
	const struct gatt_db_service *service = a;
	const struct clear_range *range = b;
	uint16_t svc_start, svc_end;

	gatt_db_service_get_handles(service, &svc_start, &svc_end);

	return svc_start <= range->end && svc_end >= range->start;
}

bool gatt_db_clear_range(struct gatt_db *db, uint16_t start_handle,
							uint16_t end_handle)
{
	struct clear_range range;

	if (!db || start_handle > end_handle)
		return false;

	/* Check if it is a full clear */
	if (start_handle == 1 && end_handle == UINT16_MAX) {
		queue_remove_all(db->services, NULL, NULL,
						gatt_db_service_destroy);
		goto done;
	}

	range.start = start_handle;
	range.end = end_handle;

	queue_remove_all(db->services, match_range, &range,
						gatt_db_service_destroy);

done:
	if (gatt_db_isempty(db))
		db->last_handle = 0;

	return true;
}

uint8_t *gatt_db_get_hash(struct gatt_db *db)
{
	uint8_t hash[16] = {};

	if (!db || !db->crypto)
		return NULL;

	/* Generate hash if if has not been generated yet */
	if (db->hash_id || !memcmp(db->hash, hash, 16)) {
		timeout_remove(db->hash_id);
		db_hash_update(db);
	}

	return db->hash;
}

bool gatt_db_hash_support(struct gatt_db *db)
{
	if (!db || !db->crypto)
		return false;

	return true;
}

static struct gatt_db_service *find_insert_loc(struct gatt_db *db,
						uint16_t start, uint16_t end,
						struct gatt_db_service **after)
{
	const struct queue_entry *services_entry;
	struct gatt_db_service *service;
	uint16_t cur_start, cur_end;

	*after = NULL;

	/*遍历db->services队列*/
	services_entry = queue_get_entries(db->services);
	while (services_entry) {
		service = services_entry->data;

		/*取cur_start,cur_end*/
		gatt_db_service_get_handles(service, &cur_start, &cur_end);

		if (start >= cur_start && start <= cur_end)
			return service;/*start在此service之内，使用此service*/

		if (end >= cur_start && end <= cur_end)
			return service;/*end在此service之内，使用此service*/

		if (end < cur_start)
			return NULL;/*必不包含，直接返回NULL*/

		*after = service;/*记录上一次查找过的service*/
		services_entry = services_entry->next;
	}

	return NULL;/*没有找到*/
}

struct gatt_db_attribute *gatt_db_insert_service(struct gatt_db *db,
							uint16_t handle,
							const bt_uuid_t *uuid/*做为service属性的值uuid*/,
							bool primary/*是否为主serive uuid插入*/,
							uint16_t num_handles)
{
	struct gatt_db_service *service, *after;

	after = NULL;

	if (!db)
		return NULL;

	if (!handle)
		/*未指定handle,分配handle*/
		handle = db->last_handle + 1;

	if (num_handles < 1 || (handle + num_handles - 1) > UINT16_MAX)
		return NULL;/*num_handles有误*/

	service = find_insert_loc(db, handle/*起始handle*/, handle + num_handles - 1/*结束handle*/, &after);
	if (service) {
		const bt_uuid_t *type;
		bt_uuid_t value;
		struct gatt_db_attribute *attr = service->attributes[0];

		if (!attr)
			return NULL;

		if (primary)
			/*primary对应的type*/
			type = &primary_service_uuid;
		else
			type = &secondary_service_uuid;

		gatt_db_attribute_get_service_uuid(attr, &value);/*取service_uuid*/

		/* Check if service match */
		if (!bt_uuid_cmp(&attr->uuid, type) &&
				!bt_uuid_cmp(&value, uuid) &&
				service->num_handles == num_handles &&
				attr->handle == handle)
			return attr;/*匹配，直接返回此attr*/

		return NULL;
	}

	/*此service还未创建，这里创建*/
	service = gatt_db_service_create(uuid, handle, primary, num_handles);

	if (!service)
		return NULL;

	if (after) {
		if (!queue_push_after(db->services, after, service))
			goto fail;
	} else if (!queue_push_head(db->services, service)/*after为空，即队列为空，加入head*/) {
		goto fail;
	}

	service->db = db;
	service->attributes[0]->handle = handle;
	service->num_handles = num_handles;

	/* Fast-forward last_handle if the new service was added to the end */
	db->last_handle = MAX(handle + num_handles - 1, db->last_handle);/*更新last handle*/

	return service->attributes[0];

fail:
	gatt_db_service_destroy(service);
	return NULL;
}

struct gatt_db_attribute *gatt_db_add_service(struct gatt_db *db,
						const bt_uuid_t *uuid,
						bool primary,
						uint16_t num_handles)
{
	return gatt_db_insert_service(db, 0, uuid, primary, num_handles);
}

/*创建并注册notify,产生notify id*/
unsigned int gatt_db_register(struct gatt_db *db,
					gatt_db_attribute_cb_t service_added,
					gatt_db_attribute_cb_t service_removed,
					void *user_data,
					gatt_db_destroy_func_t destroy)
{
	struct notify *notify;

	if (!db || !(service_added || service_removed))
		return 0;

	notify = new0(struct notify, 1);
	notify->service_added = service_added;
	notify->service_removed = service_removed;
	notify->destroy = destroy;
	notify->user_data = user_data;

	if (db->next_notify_id < 1)
		db->next_notify_id = 1;

	notify->id = db->next_notify_id++;

	/*添加notify*/
	if (!queue_push_tail(db->notify_list, notify)) {
		free(notify);
		return 0;
	}

	return notify->id;
}

bool gatt_db_unregister(struct gatt_db *db, unsigned int id)
{
	struct notify *notify;

	if (!db || !id)
		return false;

	/*通过id查找notify*/
	notify = queue_find(db->notify_list, match_notify_id, UINT_TO_PTR(id));
	if (!notify)
		return false;

	/*自链表上移除此notify*/
	queue_remove(db->notify_list, notify);
	notify_destroy(notify);

	return true;
}

bool gatt_db_set_authorize(struct gatt_db *db, gatt_db_authorize_cb_t cb,
							void *user_data)
{
	if (!db)
		return false;

	db->authorize = cb;
	db->authorize_data = user_data;

	return true;
}

static uint16_t service_get_attribute_index(struct gatt_db_service *service,
							uint16_t *handle,
							int end_offset)
{
	int i = 0;

	if (!service || !service->attributes[0] || !handle)
		return 0;

	if (*handle) {
		/* Check if handle is in within service range */
		if (*handle < service->attributes[0]->handle)
			return 0;

		/* Return index based on given handle */
		i = *handle - service->attributes[0]->handle;
	} else {
		/* Here we look for first free attribute index with given
		 * offset.
		 */
		while (i < (service->num_handles - end_offset) &&
						service->attributes[i])
			i++;
	}

	if (i >= (service->num_handles - end_offset))
		return 0;

	/* Set handle based on the index */
	if (!(*handle))
		*handle = service->attributes[0]->handle + i;

	return i;
}

static struct gatt_db_attribute *
service_insert_characteristic(struct gatt_db_service *service,
					uint16_t handle,
					uint16_t value_handle,
					const bt_uuid_t *uuid/*属性type*/,
					uint32_t permissions,
					uint8_t properties,
					gatt_db_read_t read_func,
					gatt_db_write_t write_func,
					void *user_data)
{
	struct gatt_db_attribute **chrc;
	uint8_t value[MAX_CHAR_DECL_VALUE_LEN];
	uint16_t len = 0;
	int i;

	/* Check if handle is in within service range */
	if (handle && handle <= service->attributes[0]->handle)
		return NULL;

	/*
	 * It is not possible to allocate last handle for a Characteristic
	 * since it would not have space for its value:
	 * 3.3.2 Characteristic Value Declaration
	 * The Characteristic Value declaration contains the value of the
	 * characteristic. It is the first Attribute after the characteristic
	 * declaration. All characteristic definitions shall have a
	 * Characteristic Value declaration.
	 */
	if ((handle == UINT16_MAX) || (value_handle && handle &&
					value_handle <= handle))
		return NULL;

	i = service_get_attribute_index(service, &handle, 1);
	if (!i)
		return NULL;

	value[0] = properties;
	len += sizeof(properties);

	/* We set handle of characteristic value, which will be added next */
	put_le16(value_handle, &value[1]);
	len += sizeof(uint16_t);
	len += uuid_to_le(uuid, &value[3]);

	service->attributes[i] = new_attribute(service, handle,
							&characteristic_uuid,
							value, len);
	if (!service->attributes[i])
		return NULL;

	chrc = &service->attributes[i];
	set_attribute_data(service->attributes[i], NULL, NULL, BT_ATT_PERM_READ,
				NULL);

	i = service_get_attribute_index(service, &value_handle, 0);
	if (!i) {
		free(*chrc);
		*chrc = NULL;
		return NULL;
	}

	/*创建type为uuid的属性*/
	service->attributes[i] = new_attribute(service, value_handle, uuid,
						NULL, 0);
	if (!service->attributes[i]) {
		free(*chrc);
		*chrc = NULL;
		return NULL;
	}

	/* Update handle of characteristic value_handle if it has changed */
	put_le16(value_handle, &value[1]);

	if (!(*chrc)->value) {
		free(*chrc);
		*chrc = NULL;
		return NULL;
	}

	if (memcmp((*chrc)->value, value, len))
		memcpy((*chrc)->value, value, len);

	set_attribute_data(service->attributes[i], read_func, write_func,
							permissions, user_data);

	return service->attributes[i];
}

struct gatt_db_attribute *
gatt_db_insert_characteristic(struct gatt_db *db,
					uint16_t handle,
					uint16_t value_handle,
					const bt_uuid_t *uuid,
					uint32_t permissions,
					uint8_t properties,
					gatt_db_read_t read_func,
					gatt_db_write_t write_func,
					void *user_data)
{
	struct gatt_db_attribute *attrib;

	attrib = gatt_db_get_service(db, handle);
	if (!attrib)
		return NULL;

	return service_insert_characteristic(attrib->service, handle,
						value_handle, uuid,
						permissions, properties,
						read_func, write_func,
						user_data);
}

struct gatt_db_attribute *
gatt_db_service_insert_characteristic(struct gatt_db_attribute *attrib,
					uint16_t handle,
					uint16_t value_handle,
					const bt_uuid_t *uuid,
					uint32_t permissions,
					uint8_t properties,
					gatt_db_read_t read_func,
					gatt_db_write_t write_func,
					void *user_data)
{
	if (!attrib)
		return NULL;

	return service_insert_characteristic(attrib->service, handle,
						value_handle, uuid,
						permissions, properties,
						read_func, write_func,
						user_data);
}

struct gatt_db_attribute *
gatt_db_service_add_characteristic(struct gatt_db_attribute *attrib,
					const bt_uuid_t *uuid,
					uint32_t permissions,
					uint8_t properties,
					gatt_db_read_t read_func,
					gatt_db_write_t write_func,
					void *user_data)
{
	if (!attrib)
		return NULL;

	return service_insert_characteristic(attrib->service, 0, 0, uuid,
						permissions, properties,
						read_func, write_func,
						user_data);
}

static struct gatt_db_attribute *
service_insert_descriptor(struct gatt_db_service *service,
					uint16_t handle,
					const bt_uuid_t *uuid,
					uint32_t permissions,
					gatt_db_read_t read_func,
					gatt_db_write_t write_func,
					void *user_data)
{
	int i;

	i = service_get_attribute_index(service, &handle, 0);
	if (!i)
		return NULL;

	service->attributes[i] = new_attribute(service, handle, uuid, NULL, 0);
	if (!service->attributes[i])
		return NULL;

	set_attribute_data(service->attributes[i], read_func, write_func,
							permissions, user_data);

	return service->attributes[i];
}

struct gatt_db_attribute *
gatt_db_insert_descriptor(struct gatt_db *db,
					uint16_t handle,
					const bt_uuid_t *uuid,
					uint32_t permissions,
					gatt_db_read_t read_func,
					gatt_db_write_t write_func,
					void *user_data)
{
	struct gatt_db_attribute *attrib;

	attrib = gatt_db_get_service(db, handle);
	if (!attrib)
		return NULL;

	return service_insert_descriptor(attrib->service, handle, uuid,
					permissions, read_func, write_func,
					user_data);
}

struct gatt_db_attribute *
gatt_db_service_insert_descriptor(struct gatt_db_attribute *attrib,
					uint16_t handle,
					const bt_uuid_t *uuid,
					uint32_t permissions,
					gatt_db_read_t read_func,
					gatt_db_write_t write_func,
					void *user_data)
{
	if (!attrib)
		return NULL;

	return service_insert_descriptor(attrib->service, handle, uuid,
					permissions, read_func, write_func,
					user_data);
}

struct gatt_db_attribute *
gatt_db_service_add_descriptor(struct gatt_db_attribute *attrib,
					const bt_uuid_t *uuid,
					uint32_t permissions,
					gatt_db_read_t read_func,
					gatt_db_write_t write_func,
					void *user_data)
{
	if (!attrib)
		return NULL;

	return service_insert_descriptor(attrib->service, 0, uuid,
					permissions, read_func, write_func,
					user_data);
}

static void find_ccc_value(struct gatt_db_attribute *attrib, void *user_data)
{
	uint16_t *handle = user_data;

	gatt_db_attribute_get_char_data(attrib, NULL, handle, NULL, NULL, NULL);
}

struct gatt_db_attribute *
gatt_db_service_add_ccc(struct gatt_db_attribute *attrib, uint32_t permissions)
{
	struct gatt_db *db;
	struct gatt_db_attribute *ccc;
	struct gatt_db_attribute *value;
	uint16_t handle = 0;

	if (!attrib || !permissions)
		return NULL;

	db = attrib->service->db;

	if (!db->ccc)
		return NULL;

	/* Locate value handle */
	gatt_db_service_foreach_char(attrib, find_ccc_value, &handle);

	if (!handle)
		return NULL;

	value = gatt_db_get_attribute(db, handle);
	if (!value || value->notify_func)
		return NULL;

	ccc = service_insert_descriptor(attrib->service, 0, &ccc_uuid,
					permissions,
					db->ccc->read_func,
					db->ccc->write_func,
					db->ccc->user_data);
	if (!ccc)
		return ccc;

	gatt_db_attribute_set_fixed_length(ccc, 2);
	ccc->notify_func = db->ccc->notify_func;
	value->notify_func = db->ccc->notify_func;

	return ccc;
}

void gatt_db_ccc_register(struct gatt_db *db, gatt_db_read_t read_func,
				gatt_db_write_t write_func,
				gatt_db_notify_t notify_func,
				void *user_data)
{
	if (!db)
		return;

	if (!db->ccc)
		db->ccc = new0(struct gatt_db_ccc, 1);

	db->ccc->read_func = read_func;
	db->ccc->write_func = write_func;
	db->ccc->notify_func = notify_func;
	db->ccc->user_data = user_data;
}

static struct gatt_db_attribute *
service_insert_included(struct gatt_db_service *service, uint16_t handle,
					struct gatt_db_attribute *include)
{
	struct gatt_db_service *included;
	uint8_t value[MAX_INCLUDED_VALUE_LEN];
	uint16_t included_handle, len = 0;
	int index;

	if (!include || !include->value || !include->service || !service)
		return NULL;

	included = include->service;

	/* Adjust include to point to the first attribute */
	if (include != included->attributes[0])
		include = included->attributes[0];

	included_handle = include->handle;

	put_le16(included_handle, &value[len]);
	len += sizeof(uint16_t);

	put_le16(included_handle + included->num_handles - 1, &value[len]);
	len += sizeof(uint16_t);

	/* The Service UUID shall only be present when the UUID is a 16-bit
	 * Bluetooth UUID. Vol 2. Part G. 3.2
	 */
	if (include->value_len == sizeof(uint16_t)) {
		memcpy(&value[len], include->value, include->value_len);
		len += include->value_len;
	}

	index = service_get_attribute_index(service, &handle, 0);
	if (!index)
		return NULL;

	service->attributes[index] = new_attribute(service, handle,
							&included_service_uuid,
							value, len);
	if (!service->attributes[index])
		return NULL;

	/* The Attribute Permissions shall be read only and not require
	 * authentication or authorization. Vol 2. Part G. 3.2
	 *
	 * TODO handle permissions
	 */
	set_attribute_data(service->attributes[index], NULL, NULL,
					BT_ATT_PERM_READ, NULL);

	return service->attributes[index];
}

struct gatt_db_attribute *
gatt_db_service_add_included(struct gatt_db_attribute *attrib,
					struct gatt_db_attribute *include)
{
	if (!attrib || !include)
		return NULL;

	return service_insert_included(attrib->service, 0, include);
}

struct gatt_db_attribute *
gatt_db_service_insert_included(struct gatt_db_attribute *attrib,
				uint16_t handle,
				struct gatt_db_attribute *include)
{
	if (!attrib || !handle || !include)
		return NULL;

	return service_insert_included(attrib->service, handle, include);
}

struct gatt_db_attribute *
gatt_db_insert_included(struct gatt_db *db, uint16_t handle,
			struct gatt_db_attribute *include)
{
	struct gatt_db_attribute *attrib;

	attrib = gatt_db_get_service(db, handle);
	if (!attrib)
		return NULL;

	return service_insert_included(attrib->service, handle, include);
}

bool gatt_db_service_set_active(struct gatt_db_attribute *attrib, bool active)
{
	struct gatt_db_service *service;

	if (!attrib)
		return false;

	service = attrib->service;

	if (service->active == active)
		return true;

	service->active = active;

	notify_service_changed(service->db, service, active);

	return true;
}

bool gatt_db_service_get_active(struct gatt_db_attribute *attrib)
{
	if (!attrib)
		return false;

	return attrib->service->active;
}

bool gatt_db_service_set_claimed(struct gatt_db_attribute *attrib,
								bool claimed)
{
	if (!attrib)
		return false;

	attrib->service->claimed = claimed;

	return true;
}

bool gatt_db_service_get_claimed(struct gatt_db_attribute *attrib)
{
	if (!attrib)
		return false;

	return attrib->service->claimed;
}

static void read_by_group_type(struct gatt_db_attribute *attribute,
						void *user_data)
{
	struct queue *queue = user_data;

	queue_push_tail(queue, attribute);
}

void gatt_db_read_by_group_type(struct gatt_db *db, uint16_t start_handle,
							uint16_t end_handle,
							const bt_uuid_t type,
							struct queue *queue)
{
	gatt_db_foreach_service_in_range(db, &type, read_by_group_type, queue,
						start_handle, end_handle);
}

struct find_by_type_value_data {
	gatt_db_attribute_cb_t func;
	void *user_data;
	const void *value;/*属性value匹配字段*/
	size_t value_len;/*属性value匹配字段长度*/
	unsigned int num_of_res;/*记录命中的记录数*/
};

static void find_by_type(struct gatt_db_attribute *attribute, void *user_data)
{
	struct find_by_type_value_data *search_data = user_data;

	if (!attribute)
		return;

	/* TODO: fix for read-callback based attributes */
	if (search_data->value) {
		if (search_data->value_len != attribute->value_len)
			return;/*长度不相等，跳过*/

		if (!attribute->value)
			return;/*命中的属性无value,非命中情况*/

		if (memcmp(attribute->value, search_data->value,
					search_data->value_len))
			return;/*查询的value与属性value不匹配，非命中情况*/
	}

	search_data->num_of_res++;/*命中数增加*/
	search_data->func(attribute, search_data->user_data);
}

unsigned int gatt_db_find_by_type(struct gatt_db *db, uint16_t start_handle,
						uint16_t end_handle,
						const bt_uuid_t *type/*属性type*/,
						gatt_db_attribute_cb_t func,
						void *user_data)
{
	struct find_by_type_value_data data;

	memset(&data, 0, sizeof(data));

	data.func = func;
	data.user_data = user_data;

	/*查service handle在（start_handle,end_handle）在范围内的情况*/
	gatt_db_foreach_in_range(db, type, find_by_type, &data,
						start_handle, end_handle);

	return data.num_of_res;
}

unsigned int gatt_db_find_by_type_value(struct gatt_db *db,
						uint16_t start_handle,
						uint16_t end_handle,
						const bt_uuid_t *type,
						const void *value,
						size_t value_len,
						gatt_db_attribute_cb_t func,
						void *user_data)
{
	struct find_by_type_value_data data;

	memset(&data, 0, sizeof(data));
	data.func = func;
	data.user_data = user_data;
	data.value = value;
	data.value_len = value_len;

	gatt_db_foreach_in_range(db, type, find_by_type, &data,
						start_handle, end_handle);

	return data.num_of_res;
}

static void read_by_type(struct gatt_db_attribute *attribute, void *user_data)
{
	struct queue *queue = user_data;

	queue_push_tail(queue, attribute);
}

void gatt_db_read_by_type(struct gatt_db *db, uint16_t start_handle,
						uint16_t end_handle,
						const bt_uuid_t type,
						struct queue *queue)
{
	gatt_db_foreach_in_range(db, &type, read_by_type, queue,
						start_handle, end_handle);
}


static void find_information(struct gatt_db_attribute *attribute,
						void *user_data)
{
	struct queue *queue = user_data;

	queue_push_tail(queue, attribute);
}

void gatt_db_find_information(struct gatt_db *db, uint16_t start_handle,
							uint16_t end_handle,
							struct queue *queue)
{
	gatt_db_foreach_in_range(db, NULL, find_information, queue,
						start_handle, end_handle);
}

void gatt_db_foreach_service(struct gatt_db *db, const bt_uuid_t *uuid,
						gatt_db_attribute_cb_t func,
						void *user_data)
{
	gatt_db_foreach_service_in_range(db, uuid, func, user_data, 0x0001,
									0xffff);
}

struct foreach_data {
	gatt_db_attribute_cb_t func;/*回调函数*/
	const bt_uuid_t *uuid;/*属性type*/
	void *user_data;/*回调函数参数*/
	uint16_t start/*起始handle*/, end/*终止handle*/;
	bool attr;/*是否为属性*/
};

static void foreach_service_in_range(void *data, void *user_data)
{
	struct gatt_db_service *service = data;
	struct gatt_db_attribute *attribute = service->attributes[0];
	struct foreach_data *foreach_data = user_data;
	bt_uuid_t uuid;

	if (foreach_data->uuid) {
		gatt_db_attribute_get_service_uuid(attribute, &uuid);
		if (bt_uuid_cmp(&uuid, foreach_data->uuid)) {
			/* Compare with attribute UUID in case it is a lookup
			 * by group type.
			 */
			if (bt_uuid_cmp(&attribute->uuid, foreach_data->uuid))
				return;
		}
	}

	foreach_data->func(service->attributes[0], foreach_data->user_data);
}

static void foreach_in_range(void *data, void *user_data)
{
	struct gatt_db_service *service = data;
	struct foreach_data *foreach_data = user_data;
	uint16_t svc_start, svc_end;
	int i;

	if (!service->active)
		return;

	/*取此service的start-handle,end-handle*/
	gatt_db_service_get_handles(service, &svc_start, &svc_end);

	/* Check if service is within requested range */
	if (svc_start > foreach_data->end || svc_end < foreach_data->start)
		/*svc_start,svc_end与foreach_data中的范围无重叠,忽略*/
		return;

	if (!foreach_data->attr) {
		/*仅实现非attr查询时*/
		if (svc_start < foreach_data->start)
			return;

		return foreach_service_in_range(data, user_data);
	}

	for (i = 0; i < service->num_handles; i++) {
		struct gatt_db_attribute *attribute = service->attributes[i];

		if (!attribute)
			continue;/*跳过不存在的属性*/

		if (attribute->handle < foreach_data->start)
			continue;/*跳过起点未包含的情况*/

		if (attribute->handle > foreach_data->end)
			return;/*已完成查询，返回*/

		if (foreach_data->uuid && bt_uuid_cmp(foreach_data->uuid,
							&attribute->uuid))
			continue;/*如果指定了uuid,则要求属性的type必须与所给uuid一致*/

		/*命中，执行参数指定的回调*/
		foreach_data->func(attribute, foreach_data->user_data);
	}
}

void gatt_db_foreach_service_in_range(struct gatt_db *db,
						const bt_uuid_t *uuid,
						gatt_db_attribute_cb_t func,
						void *user_data,
						uint16_t start_handle,
						uint16_t end_handle)
{
	struct foreach_data data;

	if (!db || !func || start_handle > end_handle)
		return;

	/*构造遍历函数参数*/
	data.func = func;
	data.uuid = uuid;
	data.user_data = user_data;
	data.start = start_handle;
	data.end = end_handle;
	data.attr = false;

	/*遍历db->services*/
	queue_foreach(db->services, foreach_in_range, &data);
}

void gatt_db_foreach_in_range(struct gatt_db *db, const bt_uuid_t *uuid,
						gatt_db_attribute_cb_t func,
						void *user_data,
						uint16_t start_handle,
						uint16_t end_handle)
{
	struct foreach_data data;

	if (!db || !func || start_handle > end_handle)
		return;

	/*准备查询参数*/
	data.func = func;
	data.uuid = uuid;/*类型type*/
	data.user_data = user_data;
	data.start = start_handle;
	data.end = end_handle;
	data.attr = true;

	queue_foreach(db->services, foreach_in_range, &data);
}

/*利用函数func遍历service->attributes*/
void gatt_db_service_foreach(struct gatt_db_attribute *attrib,
						const bt_uuid_t *uuid/*如非空，则为需匹配的属性uuid*/,
						gatt_db_attribute_cb_t func/*遍历函数*/,
						void *user_data/*函数参数*/)
{
	struct gatt_db_service *service;
	struct gatt_db_attribute *attr;
	uint16_t i;

	if (!attrib || !func)
		return;

	service = attrib->service;

	/*遍历所有attributes*/
	for (i = 0; i < service->num_handles; i++) {
		attr = service->attributes[i];
		if (!attr)
			continue;

		if (uuid && bt_uuid_cmp(uuid, &attr->uuid))
			continue;/*跳过与uuid相等的attr*/

		/*使用func进行遍历*/
		func(attr, user_data);
	}
}

/*仅遍历characteristic_uuid类型的属性*/
void gatt_db_service_foreach_char(struct gatt_db_attribute *attrib,
						gatt_db_attribute_cb_t func,
						void *user_data)
{
	gatt_db_service_foreach(attrib, &characteristic_uuid, func, user_data);
}

static int gatt_db_attribute_get_index(const struct gatt_db_attribute *attrib)
{
	struct gatt_db_service *service;
	int index;

	if (!attrib)
		return -1;

	service = attrib->service;
	for (index = 0; index < service->num_handles; index++) {
		if (service->attributes[index] == attrib)
			return index;
	}

	return -1;
}

struct gatt_db_attribute *
gatt_db_attribute_get_value(struct gatt_db_attribute *attrib)
{
	struct gatt_db_service *service;
	int index;

	if (!attrib)
		return NULL;

	index = gatt_db_attribute_get_index(attrib);
	if (index <= 0)
		return NULL;

	service = attrib->service;

	if (!bt_uuid_cmp(&characteristic_uuid, &attrib->uuid))
		return service->attributes[index + 1];
	else if (service->attributes[index - 1] == NULL)
		return NULL;
	else if (!bt_uuid_cmp(&characteristic_uuid,
				&service->attributes[index - 1]->uuid))
		return service->attributes[index];

	return gatt_db_attribute_get_value(service->attributes[index - 1]);
}

void gatt_db_service_foreach_desc(struct gatt_db_attribute *attrib,
						gatt_db_attribute_cb_t func,
						void *user_data)
{
	struct gatt_db_service *service;
	struct gatt_db_attribute *attr;
	int index;
	uint16_t i;

	if (!attrib || !func)
		return;

	attrib = gatt_db_attribute_get_value(attrib);
	if (!attrib)
		return;

	index = gatt_db_attribute_get_index(attrib);
	if (index < 0)
		return;

	service = attrib->service;

	/* Start from the attribute following the value handle */
	for (i = index + 1; i < service->num_handles; i++) {
		attr = service->attributes[i];
		if (!attr)
			continue;

		/* Return if we reached the end of this characteristic */
		if (!bt_uuid_cmp(&characteristic_uuid, &attr->uuid) ||
			!bt_uuid_cmp(&included_service_uuid, &attr->uuid))
			return;

		func(attr, user_data);
	}
}

/*仅遍历included_service_uuid类型的属性*/
void gatt_db_service_foreach_incl(struct gatt_db_attribute *attrib,
						gatt_db_attribute_cb_t func,
						void *user_data)
{
	gatt_db_service_foreach(attrib, &included_service_uuid, func,
								user_data);
}

static bool find_service_for_handle(const void *data, const void *user_data)
{
	const struct gatt_db_service *service = data;
	uint16_t handle = PTR_TO_UINT(user_data);
	uint16_t start, end;

	/*取得此service对应的start handle,end handle*/
	gatt_db_service_get_handles(service, &start, &end);

	/*要查找的handle在start,end之间，认为命中*/
	return (start <= handle) && (handle <= end);
}

struct gatt_db_attribute *gatt_db_get_service(struct gatt_db *db,
							uint16_t handle)
{
	struct gatt_db_service *service;

	if (!db || !handle)
		return NULL;

	/*通过handle查找services*/
	service = queue_find(db->services, find_service_for_handle,
						UINT_TO_PTR(handle));
	if (!service)
		return NULL;

	return service->attributes[0];/*返回首个attribute*/
}

struct gatt_db_attribute *gatt_db_get_attribute(struct gatt_db *db,
							uint16_t handle)
{
	struct gatt_db_attribute *attrib;
	struct gatt_db_service *service;
	int i;

	/*通过handle获取service*/
	attrib = gatt_db_get_service(db, handle);
	if (!attrib)
		return NULL;

	service = attrib->service;

	for (i = 0; i < service->num_handles; i++) {
		if (!service->attributes[i])
			continue;

		if (service->attributes[i]->handle == handle)
			return service->attributes[i];
	}

	return NULL;
}

static bool find_service_with_uuid(const void *data, const void *user_data)
{
	const struct gatt_db_service *service = data;
	const bt_uuid_t *uuid = user_data;
	bt_uuid_t svc_uuid;

	gatt_db_attribute_get_service_uuid(service->attributes[0], &svc_uuid);

	return bt_uuid_cmp(uuid, &svc_uuid) == 0;
}

struct gatt_db_attribute *gatt_db_get_service_with_uuid(struct gatt_db *db,
							const bt_uuid_t *uuid)
{
	struct gatt_db_service *service;

	if (!db || !uuid)
		return NULL;

	service = queue_find(db->services, find_service_with_uuid, uuid);
	if (!service)
		return NULL;

	return service->attributes[0];
}

/*取此属性type*/
const bt_uuid_t *gatt_db_attribute_get_type(
					const struct gatt_db_attribute *attrib)
{
	if (!attrib)
		return NULL;

	return &attrib->uuid;
}

uint16_t gatt_db_attribute_get_handle(const struct gatt_db_attribute *attrib)
{
	if (!attrib)
		return 0;

	return attrib->handle;
}

struct gatt_db_attribute *
gatt_db_attribute_get_service(const struct gatt_db_attribute *attrib)
{
	if (!attrib)
		return NULL;

	return attrib->service->attributes[0];
}

bool gatt_db_attribute_get_service_uuid(const struct gatt_db_attribute *attrib,
							bt_uuid_t *uuid)
{
	struct gatt_db_service *service;

	if (!attrib || !uuid)
		return false;

	service = attrib->service;

	if (service->attributes[0]->value_len == sizeof(uint16_t)) {
		/*属性0中存的是uuid*/
		uint16_t value;

		value = get_le16(service->attributes[0]->value);
		bt_uuid16_create(uuid, value);

		return true;
	}

	if (service->attributes[0]->value_len == sizeof(uint128_t)) {
		uint128_t value;

		bswap_128(service->attributes[0]->value, &value);
		bt_uuid128_create(uuid, value);

		return true;
	}

	/*未填充*/
	return false;
}

bool gatt_db_attribute_get_service_handles(
					const struct gatt_db_attribute *attrib,
					uint16_t *start_handle,
					uint16_t *end_handle)
{
	struct gatt_db_service *service;

	if (!attrib)
		return false;

	service = attrib->service;

	gatt_db_service_get_handles(service, start_handle, end_handle);

	return true;
}

bool gatt_db_attribute_get_service_data(const struct gatt_db_attribute *attrib,
							uint16_t *start_handle/*出参，service start handle终止值*/,
							uint16_t *end_handle/*出参，service end handle终止值*/,
							bool *primary,
							bt_uuid_t *uuid/*出参，service uuid*/)
{
	struct gatt_db_service *service;
	struct gatt_db_attribute *decl;

	if (!attrib)
		return false;

	service = attrib->service;
	decl = service->attributes[0];

	/*取start_handle,end_handle*/
	gatt_db_service_get_handles(service, start_handle, end_handle);

	if (primary)
		/*不是secondary uuid即为primary*/
		*primary = bt_uuid_cmp(&decl->uuid, &secondary_service_uuid);

	if (!uuid)
		return true;

	/*
	 * The service declaration attribute value is the 16 or 128 bit service
	 * UUID.
	 */
	return le_to_uuid(decl->value, decl->value_len, uuid);/*转换为uuid*/
}

static void read_ext_prop_value(struct gatt_db_attribute *attrib,
						int err, const uint8_t *value,
						size_t length, void *user_data)
{
	uint16_t *ext_prop = user_data;

	if (err || (length != sizeof(uint16_t)))
		return;

	*ext_prop = (uint16_t) value[0];
}

static void read_ext_prop(struct gatt_db_attribute *attrib,
							void *user_data)
{
	uint16_t *ext_prop = user_data;

	/*
	 * If ext_prop is set that means extended properties descriptor
	 * has been already found
	 */
	if (*ext_prop != 0)
		return;

	if (bt_uuid_cmp(&ext_desc_uuid, &attrib->uuid))
		return;

	gatt_db_attribute_read(attrib, 0, BT_ATT_OP_READ_REQ, NULL,
						read_ext_prop_value, ext_prop);
}

static uint8_t get_char_extended_prop(const struct gatt_db_attribute *attrib)
{
	uint16_t ext_prop;

	if (!attrib)
		return 0;

	if (bt_uuid_cmp(&characteristic_uuid, &attrib->uuid))
		return 0;

	/* Check properties first */
	if (!(attrib->value[0] & BT_GATT_CHRC_PROP_EXT_PROP))
		return 0;

	ext_prop = 0;

	/*
	 * Cast needed for foreach function. We do not change attrib during
	 * this call
	 */
	gatt_db_service_foreach_desc((struct gatt_db_attribute *) attrib,
						read_ext_prop, &ext_prop);

	return ext_prop;
}

bool gatt_db_attribute_get_char_data(const struct gatt_db_attribute *attrib,
							uint16_t *handle,
							uint16_t *value_handle,
							uint8_t *properties,
							uint16_t *ext_prop,
							bt_uuid_t *uuid)
{
	if (!attrib)
		return false;

	if (bt_uuid_cmp(&characteristic_uuid, &attrib->uuid)) {
		int index;

		/* Check if Characteristic Value was passed instead */
		index = gatt_db_attribute_get_index(attrib);
		if (index <= 0)
			return false;

		attrib = attrib->service->attributes[index - 1];
		if (bt_uuid_cmp(&characteristic_uuid, &attrib->uuid))
			return false;
	}

	/*
	 * Characteristic declaration value:
	 * 1 octet: Characteristic properties
	 * 2 octets: Characteristic value handle
	 * 2 or 16 octets: characteristic UUID
	 */
	if (!attrib->value || (attrib->value_len != 5 &&
						attrib->value_len != 19))
		return false;

	if (handle)
		*handle = attrib->handle;

	if (properties)
		*properties = attrib->value[0];

	if (ext_prop)
		*ext_prop = get_char_extended_prop(attrib);

	if (value_handle)
		*value_handle = get_le16(attrib->value + 1);

	if (!uuid)
		return true;

	return le_to_uuid(attrib->value + 3, attrib->value_len - 3, uuid);
}

bool gatt_db_attribute_get_incl_data(const struct gatt_db_attribute *attrib,
							uint16_t *handle,
							uint16_t *start_handle,
							uint16_t *end_handle)
{
	if (!attrib)
		return false;

	if (bt_uuid_cmp(&included_service_uuid, &attrib->uuid))
		return false;/*不为included_service_uuid属性*/

	/*
	 * Include definition value:
	 * 2 octets: start handle of included service
	 * 2 octets: end handle of included service
	 * optional 2 octets: 16-bit Bluetooth UUID
	 */
	if (!attrib->value || attrib->value_len < 4 || attrib->value_len > 6)
		return false;

	/*
	 * We only return the handles since the UUID can be easily obtained
	 * from the corresponding attribute.
	 */
	if (handle)
		*handle = attrib->handle;

	if (start_handle)
		*start_handle = get_le16(attrib->value);

	if (end_handle)
		*end_handle = get_le16(attrib->value + 2);

	return true;
}

uint32_t
gatt_db_attribute_get_permissions(const struct gatt_db_attribute *attrib)
{
	if (!attrib)
		return 0;

	return attrib->permissions;
}

static bool read_timeout(void *user_data)
{
	struct pending_read *p = user_data;

	p->timeout_id = 0;

	queue_remove(p->attrib->pending_reads, p);

	pending_read_result(p, -ETIMEDOUT, NULL, 0);

	return false;
}

static uint8_t attribute_authorize(struct gatt_db_attribute *attrib,
					uint8_t opcode, struct bt_att *att)
{
	struct gatt_db *db = attrib->service->db;

	if (!db->authorize)
		return 0;

	return db->authorize(attrib, opcode, att, db->authorize_data);
}

bool gatt_db_attribute_set_fixed_length(struct gatt_db_attribute *attrib,
						uint16_t len)
{
	struct gatt_db_service *service;

	if (!attrib)
		return false;

	service = attrib->service;

	/* Don't allow overwriting length of service attribute */
	if (attrib->service->attributes[0] == attrib)
		return false;

	/* If attribute is a characteristic declaration adjust to its value */
	if (!bt_uuid_cmp(&characteristic_uuid, &attrib->uuid)) {
		int i;

		/* Start from the attribute following the value handle */
		for (i = 0; i < service->num_handles; i++) {
			if (service->attributes[i] == attrib) {
				attrib = service->attributes[i + 1];
				break;
			}
		}
	}

	attrib->value_len = len;

	return true;
}

bool gatt_db_attribute_read(struct gatt_db_attribute *attrib, uint16_t offset,
				uint8_t opcode, struct bt_att *att,
				gatt_db_attribute_read_t func, void *user_data)
{
	uint8_t *value;

	if (!attrib || !func)
		return false;

	/* Check boundaries if value_len is set */
	if (attrib->value_len && offset > attrib->value_len) {
		/*offset超过属性value长度*/
		func(attrib, BT_ATT_ERROR_INVALID_OFFSET, NULL, 0, user_data);
		return true;
	}

	if (attrib->read_func) {
		/*有read_func的，通过read_func进行处理*/
		struct pending_read *p;
		uint8_t err;

		err = attribute_authorize(attrib, opcode, att);
		if (err) {
			func(attrib, err, NULL, 0, user_data);
			return true;
		}

		p = new0(struct pending_read, 1);
		p->attrib = attrib;
		p->id = ++attrib->read_id;
		p->timeout_id = timeout_add(ATTRIBUTE_TIMEOUT, read_timeout,
								p, NULL);/*启动定时器*/
		p->func = func;
		p->user_data = user_data;

		queue_push_tail(attrib->pending_reads, p);

		attrib->read_func(attrib, p->id, offset, opcode, att,
							attrib->user_data);
		return true;
	}

	/* Guard against invalid access if offset equals to value length */
	value = offset == attrib->value_len ? NULL/*到达结尾，返回NULL*/ : &attrib->value[offset]/*从起始位置取*/;

	func(attrib, 0, value, attrib->value_len - offset, user_data);/*触发回调获取*/

	return true;
}

static bool find_pending(const void *a, const void *b)
{
	const struct pending_read *p = a;
	unsigned int id = PTR_TO_UINT(b);

	return p->id == id;
}

bool gatt_db_attribute_read_result(struct gatt_db_attribute *attrib,
					unsigned int id, int err,
					const uint8_t *value, size_t length)
{
	struct pending_read *p;

	if (!attrib || !id)
		return false;

	p = queue_remove_if(attrib->pending_reads, find_pending,
							UINT_TO_PTR(id));
	if (!p)
		return false;

	pending_read_result(p, err, value, length);

	return true;
}

static bool write_timeout(void *user_data)
{
	struct pending_write *p = user_data;

	p->timeout_id = 0;

	queue_remove(p->attrib->pending_writes, p);

	pending_write_result(p, -ETIMEDOUT);

	return false;
}

bool gatt_db_attribute_write(struct gatt_db_attribute *attrib, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					gatt_db_attribute_write_t func,
					void *user_data)
{
	uint8_t err = 0;

	if (!attrib || (!func && attrib->write_func))
		return false;

	if (attrib->write_func) {
		struct pending_write *p;

		/* Check boundaries if value_len is set */
		if (attrib->value_len) {
			if (offset > attrib->value_len) {
				err = BT_ATT_ERROR_INVALID_OFFSET;
				goto done;
			}

			if (offset + len > attrib->value_len) {
				err = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
				goto done;
			}
		}

		err = attribute_authorize(attrib, opcode, att);
		if (err)
			goto done;

		p = new0(struct pending_write, 1);
		p->attrib = attrib;
		p->id = ++attrib->write_id;
		p->timeout_id = timeout_add(ATTRIBUTE_TIMEOUT, write_timeout,
								p, NULL);
		p->func = func;
		p->user_data = user_data;

		queue_push_tail(attrib->pending_writes, p);

		attrib->write_func(attrib, p->id, offset, value, len, opcode,
							att, attrib->user_data);
		return true;
	}

	/* Nothing to write just skip */
	if (len == 0)
		goto done;

	/* For values stored in db allocate on demand */
	if (!attrib->value || offset >= attrib->value_len ||
				len > (unsigned) (attrib->value_len - offset)) {
		void *buf;

		buf = realloc(attrib->value, len + offset);
		if (!buf)
			return false;

		attrib->value = buf;

		/* Init data in the first allocation */
		if (!attrib->value_len)
			memset(attrib->value, 0, offset);

		attrib->value_len = len + offset;
	}

	memcpy(&attrib->value[offset], value, len);

done:
	if (func)
		func(attrib, err, user_data);

	return true;
}

bool gatt_db_attribute_write_result(struct gatt_db_attribute *attrib,
						unsigned int id, int err)
{
	struct pending_write *p;

	if (!attrib || !id)
		return false;

	p = queue_remove_if(attrib->pending_writes, find_pending,
							UINT_TO_PTR(id));
	if (!p)
		return false;

	pending_write_result(p, err);

	return true;
}

static void find_ccc(struct gatt_db_attribute *attrib, void *user_data)
{
	struct gatt_db_attribute **ccc = user_data;

	if (*ccc)
		return;

	if (bt_uuid_cmp(&ccc_uuid, &attrib->uuid))
		return;

	*ccc = attrib;
}

struct gatt_db_attribute *
gatt_db_attribute_get_ccc(struct gatt_db_attribute *attrib)
{
	struct gatt_db_attribute *ccc = NULL;

	if (!attrib)
		return NULL;

	gatt_db_service_foreach_desc(attrib, find_ccc, &ccc);

	return ccc;
}

bool gatt_db_attribute_notify(struct gatt_db_attribute *attrib,
					const uint8_t *value, size_t len,
					struct bt_att *att)
{
	struct gatt_db_attribute *ccc;

	if (!attrib || !attrib->notify_func)
		return false;

	attrib = gatt_db_attribute_get_value(attrib);
	if (!attrib)
		return false;

	ccc = gatt_db_attribute_get_ccc(attrib);
	if (!ccc)
		return false;

	attrib->notify_func(attrib, ccc, value, len, att, ccc->user_data);

	return true;
}

bool gatt_db_attribute_reset(struct gatt_db_attribute *attrib)
{
	if (!attrib)
		return false;

	if (!attrib->value || !attrib->value_len)
		return true;

	free(attrib->value);
	attrib->value = NULL;
	attrib->value_len = 0;

	return true;
}

void *gatt_db_attribute_get_user_data(struct gatt_db_attribute *attrib)
{
	if (!attrib)
		return NULL;

	return attrib->user_data;
}

static bool match_attribute_notify_id(const void *a, const void *b)
{
	const struct attribute_notify *notify = a;
	unsigned int id = PTR_TO_UINT(b);

	return notify->id == id;
}

unsigned int gatt_db_attribute_register(struct gatt_db_attribute *attrib,
					gatt_db_attribute_cb_t removed,
					void *user_data,
					gatt_db_destroy_func_t destroy)
{
	struct attribute_notify *notify;

	if (!attrib || !removed)
		return 0;

	notify = new0(struct attribute_notify, 1);
	notify->removed = removed;
	notify->destroy = destroy;
	notify->user_data = user_data;

	if (attrib->next_notify_id < 1)
		attrib->next_notify_id = 1;

	notify->id = attrib->next_notify_id++;

	if (!queue_push_tail(attrib->notify_list, notify)) {
		free(notify);
		return 0;
	}

	return notify->id;
}

bool gatt_db_attribute_unregister(struct gatt_db_attribute *attrib,
						unsigned int id)
{
	struct attribute_notify *notify;

	if (!attrib || !id)
		return false;

	notify = queue_find(attrib->notify_list, match_attribute_notify_id,
						UINT_TO_PTR(id));
	if (!notify)
		return false;

	queue_remove(attrib->notify_list, notify);
	attribute_notify_destroy(notify);

	return true;
}
