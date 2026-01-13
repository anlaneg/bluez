// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <time.h>

#include <ell/ell.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/mgmt.h"
#include "src/shared/ad.h"
#include "src/shared/mgmt.h"

#include "mesh/mesh-defs.h"
#include "mesh/mesh-mgmt.h"
#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"

/* List of Mesh-IO Type headers */
#include "mesh/mesh-io-mgmt.h"
#include "mesh/mesh-io-generic.h"
#include "mesh/mesh-io-unit.h"

struct loop_data {
	uint16_t len;
	uint8_t data[];
};

/* List of Supported Mesh-IO Types */
static const struct mesh_io_table table[] = {
	{MESH_IO_TYPE_MGMT,	&mesh_io_mgmt},/*MESH_IO_TYPE_MGMT类型对应的api*/
	{MESH_IO_TYPE_GENERIC,	&mesh_io_generic},
	{MESH_IO_TYPE_UNIT_TEST, &mesh_io_unit},
};

static const uint8_t unprv_filter[] = { BT_AD_MESH_BEACON, 0 };

static struct mesh_io *default_io;
static struct l_timeout *loop_adv_to;

/*通过type查找mesh_io_api*/
static const struct mesh_io_api *io_api(enum mesh_io_type type)
{
	uint16_t i;

	for (i = 0; i < L_ARRAY_SIZE(table); i++) {
		if (table[i].type == type)
			return table[i].api;
	}

	return NULL;
}

static void refresh_rx(void *a, void *b)
{
	struct mesh_io_reg *rx_reg = a;
	struct mesh_io *io = b;

	/*重新注册filter*/
	if (io->api && io->api->reg)
		io->api->reg(io, rx_reg->filter, rx_reg->len, rx_reg->cb,
							rx_reg->user_data);
}

/*重要流程,用于处理ctrl检测后的情况反馈*/
static void ctl_alert(int index, bool up, bool pwr, bool mesh/*是否支持mesh*/, void *user_data)
{
	enum mesh_io_type type = L_PTR_TO_UINT(user_data);
	const struct mesh_io_api *api = NULL;

	l_warn("index %u up:%d pwr: %d mesh: %d", index, up, pwr, mesh);/*指明此controller的MESH状态*/

	/* If specific IO controller requested, honor it */
	if (default_io->favored_index != MGMT_INDEX_NONE) {
		/*我们关注了具体的一个controller,但当前controller与我们关注的不同,则忽略*/
		if (default_io->favored_index != index)
			return;

		if (!up | pwr) {
			l_warn("HCI%u failed to start generic IO %s",
				index, pwr ? ": already powered on" : "");
			if (default_io->ready)
				default_io->ready(default_io->user_data, false/*指明失败*/);
		}
	}

	if (!up && default_io->index == index) {
		/* Our controller has disappeared */
		if (default_io->api && default_io->api->destroy) {
			default_io->api->destroy(default_io);
			default_io->api = NULL;
		}

		/* Re-enumerate controllers */
		mesh_mgmt_list(ctl_alert, user_data);
		return;
	}

	/* If we already have an API, keep using it */
	if (!up || default_io->api)
		return;/*没有UP或者我们已经有api了,直接返回*/

	/*依据类型,选择不同的API*/
	if (mesh && type != MESH_IO_TYPE_GENERIC)
		api = io_api(MESH_IO_TYPE_MGMT);/*对于非generic的类型,使用此api*/
	else if (!pwr)
		api = io_api(MESH_IO_TYPE_GENERIC);

	if (api) {
		default_io->index = index;/*指明controller索引*/
		default_io->api = api;
		api->init(default_io, &index, default_io->user_data);
		l_queue_foreach(default_io->rx_regs, refresh_rx, default_io);
	}
}

static void free_io(struct mesh_io *io)
{
	if (io) {
		if (io->api && io->api->destroy)
			io->api->destroy(io);

		l_queue_destroy(io->rx_regs, l_free);
		io->rx_regs = NULL;
		l_free(io);
		l_warn("Destroy %p", io);
	}
}

static struct mesh_io_reg *find_by_filter(struct l_queue *rx_regs,
					const uint8_t *filter, uint8_t len)
{
	const struct l_queue_entry *entry;

	entry = l_queue_get_entries(rx_regs);

	/*遍历entry,通过len,filter查找mesh_io_reg*/
	for (; entry; entry = entry->next) {
		struct mesh_io_reg *rx_reg = entry->data;

		if (rx_reg->len == len && !memcmp(rx_reg->filter, filter, len))
			return rx_reg;
	}

	return NULL;
}

/*创建并初始化default_io*/
struct mesh_io *mesh_io_new(enum mesh_io_type type/*io类型*/, void *opts/*此类型对应的参数*/,
				mesh_io_ready_func_t cb/*当完成api初始化后,此CB会被调用*/, void *user_data)
{
	const struct mesh_io_api *api = NULL;

	/* Only allow one IO */
	if (default_io)
		return NULL;/*已初始化,返回NULL*/

	default_io = l_new(struct mesh_io, 1);
	default_io->ready = cb;/*当完成api初始化后,此CB会被调用*/
	default_io->user_data = user_data;
	default_io->favored_index = *(int *) opts;
	default_io->rx_regs = l_queue_new();

	if (type >= MESH_IO_TYPE_AUTO) {
		if (!mesh_mgmt_list(ctl_alert, L_UINT_TO_PTR(type)))
			goto fail;

		return default_io;/*针对这类type,直接返回default_io*/
	}

	api = io_api(type);

	if (!api || !api->init)
		goto fail;/*api不存在或者api没有init函数*/

	default_io->api = api;/*设置default_io对应的api*/

	/*执行API初始化*/
	if (!api->init(default_io, opts, user_data))
		goto fail;

	return default_io;

fail:
	free_io(default_io);
	default_io = NULL;
	return NULL;
}

void mesh_io_destroy(struct mesh_io *io)
{
}

bool mesh_io_get_caps(struct mesh_io *io, struct mesh_io_caps *caps)
{
	if (io != default_io)
		return false;/*与default_io不同,直接返失败*/

	if (io && io->api && io->api->caps)
		return io->api->caps(io, caps);

	return false;/*无API直接返回失败*/
}

/*注册收包回调*/
bool mesh_io_register_recv_cb(struct mesh_io *io, const uint8_t *filter/*AD Structure结构体匹配(用于确定对应的收包函数)*/,
				uint8_t len/*结构体filter长度*/, mesh_io_recv_func_t cb/*收包函数*/,
				void *user_data/*收包函数参数*/)
{
	struct mesh_io_reg *rx_reg;

	if (io == NULL)
		io = default_io;

	if (io != default_io || !cb || !filter || !len)
		return false;

	rx_reg = find_by_filter(io->rx_regs, filter, len);/*查找旧的filter注册情况*/

	l_free(rx_reg);
	l_queue_remove(io->rx_regs, rx_reg);/*移除旧的*/

	/*创建rx_reg*/
	rx_reg = l_malloc(sizeof(struct mesh_io_reg) + len);
	rx_reg->cb = cb;
	rx_reg->len = len;
	rx_reg->user_data = user_data;
	memcpy(rx_reg->filter, filter, len);/*填写filter*/

	l_queue_push_head(io->rx_regs, rx_reg);/*增加新的filter*/

	/*注册此filter*/
	if (io && io->api && io->api->reg)
		return io->api->reg(io, filter, len, cb, user_data);

	return false;
}

bool mesh_io_deregister_recv_cb(struct mesh_io *io, const uint8_t *filter,
								uint8_t len)
{
	struct mesh_io_reg *rx_reg;

	if (io != default_io)
		return false;

	rx_reg = find_by_filter(io->rx_regs,  filter, len);

	l_queue_remove(io->rx_regs, rx_reg);
	l_free(rx_reg);

	if (io && io->api && io->api->dereg)
		return io->api->dereg(io, filter, len);

	return false;
}

static void loop_foreach(void *data, void *user_data)
{
	struct mesh_io_reg *rx_reg = data;
	struct loop_data *rx = user_data;

	if (!memcmp(rx_reg->filter, unprv_filter, sizeof(unprv_filter)))
		rx_reg->cb(rx_reg->user_data, NULL, rx->data, rx->len);
}

static void loop_rx(struct l_timeout *timeout, void *user_data)
{
	struct loop_data *rx = user_data;

	l_queue_foreach(default_io->rx_regs, loop_foreach, rx);
	l_timeout_modify_ms(loop_adv_to, 500);
}

static void loop_destroy(void *user_data)
{
	l_free(user_data);
}

static void loop_unprv_beacon(const uint8_t *data, uint16_t len)
{
	struct loop_data *pkt = l_malloc(len + sizeof(struct loop_data));

	memcpy(pkt->data, data, len);
	pkt->len = len;
	l_timeout_remove(loop_adv_to);
	loop_adv_to = l_timeout_create_ms(500, loop_rx, pkt, loop_destroy);
}

bool mesh_io_send(struct mesh_io *io, struct mesh_io_send_info *info,
					const uint8_t *data/*要发送的内容*/, uint16_t len/*data长度*/)
{
	if (io && io != default_io)
		return false;/*指明IO时,必须是default_io*/

	if (!io)
		io = default_io;/*不指明io时,使用default_io*/

	/* Loop unprovisioned beacons for local clients */
	if (!memcmp(data, unprv_filter, sizeof(unprv_filter)))
		/*前两个字节是unprv_filter*/
		loop_unprv_beacon(data, len);

	if (io && io->api && io->api->send)
		/*发送data*/
		return io->api->send(io, info, data, len);

	return false;
}

bool mesh_io_send_cancel(struct mesh_io *io, const uint8_t *pattern,
								uint8_t len)
{
	if (io && io != default_io)
		return false;

	if (!io)
		io = default_io;

	if (loop_adv_to && len >= 2 && !memcmp(pattern, unprv_filter, 2)) {
		l_timeout_remove(loop_adv_to);
		loop_adv_to = NULL;
	}

	if (io && io->api && io->api->cancel)
		return io->api->cancel(io, pattern, len);

	return false;
}
