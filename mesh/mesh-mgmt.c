// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  SILVAIR sp. z o.o. All rights reserved.
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
#include "src/shared/mgmt.h"

#include "mesh/mesh-mgmt.h"

struct mesh_controler {
	int	index;/*指明controller索引*/
	bool	mesh_support;/*指明是否支持mesh*/
	bool	powered;
};

static mesh_mgmt_read_info_func_t ctl_info;
static struct mgmt *mgmt_mesh;
static struct l_queue *ctl_list;/*用于串连发现的controller*/
static void *list_user_data;
static bool mesh_detected;/*是否已执行mesh监测*/

/*mesh对应的uuid并指明0x1,即"开启"*/
static const uint8_t set_exp_feat_param_mesh[] = {
	0x76, 0x6e, 0xf3, 0xe8, 0x24, 0x5f, 0x05, 0xbf, /* UUID - Mesh */
	0x8d, 0x4d, 0x03, 0x7a, 0xd7, 0x63, 0xe4, 0x2c,
	0x01,                                           /* Action - enable */
};

static bool by_index(const void *a, const void *b)
{
	const struct mesh_controler *ctl = a;
	int index = L_PTR_TO_UINT(b);

	return ctl->index == index;
}

static void index_removed(uint16_t index, uint16_t length, const void *param,
							void *user_data);
static void features_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);
	struct mesh_controler *ctl;


	ctl = l_queue_find(ctl_list, by_index, L_UINT_TO_PTR(index));
	if (!ctl)
		return;/*此controller不存在,返回*/

	l_debug("Status: %d, Length: %d", status, length);
	if (status != MGMT_STATUS_NOT_SUPPORTED &&
					status != MGMT_STATUS_UNKNOWN_COMMAND) {
		ctl->mesh_support = true;
		if (!mesh_detected) {
			mgmt_register(mgmt_mesh, MGMT_EV_INDEX_REMOVED,
					MGMT_INDEX_NONE, index_removed,
					NULL, NULL);/*注册关注controller移除事件*/
		}
		mesh_detected = true;/*标明已执行检测*/
	} else
		l_debug("Kernel mesh not supported for hci%u", index);/*KERNEL表明不支持*/

	/*调用回调,指明当前支持情况(重要流程)*/
	if (ctl_info)
		/*触发ctl_info,指明支持情况*/
		ctl_info(index, true/*软件已UP*/, ctl->powered, ctl->mesh_support,
							list_user_data);
}

static void set_exp_mesh_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);

	mesh_mgmt_send(MGMT_OP_MESH_READ_FEATURES, index, 0, NULL,
				features_cb, L_UINT_TO_PTR(index), NULL);/*发送读取mesh features命令*/
}

static void read_info_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);
	const struct mgmt_rp_read_info *rp = param;
	uint32_t current_settings, supported_settings;
	struct mesh_controler *ctl;

	l_debug("hci %u status 0x%02x", index, status);

	ctl = l_queue_find(ctl_list, by_index, L_UINT_TO_PTR(index));
	if (!ctl)
		return;/*此controller已被移除,直接返回*/

	if (status != MGMT_STATUS_SUCCESS) {
		/*读取设备info失败,将此controller移除掉*/
		ctl = l_queue_remove_if(ctl_list, by_index,
						L_UINT_TO_PTR(index));
		l_error("Failed to read info for hci index %u: %s (0x%02x)",
				index, mgmt_errstr(status), status);

		l_warn("Hci dev %d removal detected", index);
		if (ctl && ctl_info)
			/*此controller以前存在,前提供了相应回调,在此处调用*/
			ctl_info(index, false, false, false, list_user_data);

		l_free(ctl);
		return;
	}

	if (length < sizeof(*rp)) {
		/*响应失败*/
		l_error("Read info response too short");
		return;
	}

	current_settings = btohl(rp->current_settings);
	supported_settings = btohl(rp->supported_settings);

	l_debug("settings: supp %8.8x curr %8.8x",
					supported_settings, current_settings);

	if (!(supported_settings & MGMT_SETTING_LE)) {
		/*设备不支持LE,退出*/
		l_info("Controller hci %u does not support LE", index);
		l_queue_remove(ctl_list, ctl);
		l_free(ctl);
		return;
	}

	if (current_settings & MGMT_SETTING_POWERED)
		ctl->powered = true;

	/*向此设备发送开启mesh功能*/
	mesh_mgmt_send(MGMT_OP_SET_EXP_FEATURE, index,
			sizeof(set_exp_feat_param_mesh),
			set_exp_feat_param_mesh,
			set_exp_mesh_cb/*处理MESH开启响应*/, L_UINT_TO_PTR(index), NULL);
}

/*添加mesh controler*/
static void index_added(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	struct mesh_controler *ctl = l_queue_find(ctl_list, by_index,
							L_UINT_TO_PTR(index));

	if (!ctl) {
		/*此CONTROLLER还不存在,创建 */
		ctl = l_new(struct mesh_controler, 1);
		ctl->index = index;
		l_queue_push_head(ctl_list, ctl);
	} else {
		ctl->mesh_support = ctl->powered = false;
	}

	/*读取此controller信息,并尝试开启mesh功能*/
	mgmt_send(mgmt_mesh, MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_cb, L_UINT_TO_PTR(index), NULL);
}

static void index_removed(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	mgmt_send(mgmt_mesh, MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_cb, L_UINT_TO_PTR(index), NULL);/*此函数用于index移除事件处理,处理时读取指定controller,如果读取失败,则移除*/

}

static void read_index_list_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	uint16_t num;
	int i;

	if (status != MGMT_STATUS_SUCCESS) {
		/*读取失败*/
		l_error("Failed to read index list: %s (0x%02x)",
						mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		/*响应内容长度有误*/
		l_error("Read index list response sixe too short");
		return;
	}

	num = btohs(rp->num_controllers);

	l_debug("Number of controllers: %u", num);

	if (num * sizeof(uint16_t) + sizeof(*rp) != length) {
		l_error("Incorrect packet size for index list response");
		return;
	}

	/*遍历响应的每个controller,检测其MESH功能,并开启*/
	for (i = 0; i < num; i++) {
		uint16_t index;

		index = btohs(rp->index[i]);
		index_added(index, 0, NULL, user_data);
	}
}

static bool mesh_mgmt_init(void)
{
	if (!ctl_list)
		ctl_list = l_queue_new();

	if (!mgmt_mesh) {
		mgmt_mesh = mgmt_new_default();/*创建mgmt*/

		if (!mgmt_mesh) {
			l_error("Failed to initialize mesh management");
			return false;
		}

		mgmt_register(mgmt_mesh, MGMT_EV_INDEX_ADDED,
				MGMT_INDEX_NONE, index_added, NULL, NULL);
	}

	return true;
}

bool mesh_mgmt_list(mesh_mgmt_read_info_func_t cb/*执行controller info执行完成后的回调*/, void *user_data)
{
	if (!mesh_mgmt_init())
		return false;

	ctl_info = cb;
	list_user_data = user_data;

	/* Use MGMT to find a candidate controller */
	l_debug("send read index_list");
	/*读取controller index*/
	if (mgmt_send(mgmt_mesh, MGMT_OP_READ_INDEX_LIST,
					MGMT_INDEX_NONE, 0, NULL,
					read_index_list_cb, NULL, NULL) <= 0)
		return false;

	return true;
}

void mesh_mgmt_destroy(void)
{
	mgmt_unref(mgmt_mesh);
	mgmt_mesh = NULL;
	ctl_info = NULL;
	list_user_data = NULL;
	l_queue_destroy(ctl_list, l_free);
	ctl_list = NULL;
}

unsigned int mesh_mgmt_send(uint16_t opcode, uint16_t index,
				uint16_t length/*参数长度*/, const void *param/*参数*/,
				mgmt_request_func_t callback,
				void *user_data, mgmt_destroy_func_t destroy)
{
	return mgmt_send_timeout(mgmt_mesh, opcode, index, length, param,
					callback, user_data, destroy, 0);
}

unsigned int mesh_mgmt_register(uint16_t event/*事件*/, uint16_t index/*关注的设备index*/,
				mgmt_notify_func_t callback/*事件回调*/,
				void *user_data, mgmt_destroy_func_t destroy)
{
	return mgmt_register(mgmt_mesh, event, index, callback,
						user_data, destroy);
}

bool mesh_mgmt_unregister(unsigned int id)
{
	return mgmt_unregister(mgmt_mesh, id);
}

void mesh_mgmt_clear(void)
{
	l_queue_clear(ctl_list, l_free);
}
