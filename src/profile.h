/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 */

#define BTD_PROFILE_PRIORITY_LOW	0
#define BTD_PROFILE_PRIORITY_MEDIUM	1
#define BTD_PROFILE_PRIORITY_HIGH	2

struct btd_service;

struct btd_profile {
	const char *name;/*名称*/
	int priority;/*优先级*/

	const char *local_uuid;/*本端uuid*/
	const char *remote_uuid;

	bool auto_connect;
	/* Some profiles are considered safe to be handled internally and also
	 * be exposed in the GATT API. This flag give such profiles exception
	 * from being claimed internally.
	 */
	bool external;

	/* Indicates the profile is experimental and shall only be registered
	 * when experimental has been enabled (see: main.conf:Experimental).
	 */
	bool experimental;/*是否实验性功能*/

	/* Indicates the profile for testing only and shall only be registered
	 * when testing has been enabled (see: main.conf:Testing).
	 */
	bool testing;/*是否测试性功能*/

	/*检查service是否可应用于此设备（如无此回调则无法创建btd_service），返回0，则应用成功*/
	int (*device_probe) (struct btd_service *service);
	/*设备自此service中移除时，此回调调用*/
	void (*device_remove) (struct btd_service *service);

	/*检查此service是否可连接成功*/
	int (*connect) (struct btd_service *service);
	/*与此服务断开连接*/
	int (*disconnect) (struct btd_service *service);

	int (*accept) (struct btd_service *service);

	/*检查profile是否可应用于此adapter，
	 * 如果可应用会将此profile记录在adapter->profiles上*/
	int (*adapter_probe) (struct btd_profile *p,
						struct btd_adapter *adapter);
	/*profile与adapter解耦合*/
	void (*adapter_remove) (struct btd_profile *p,
						struct btd_adapter *adapter);
};

void btd_profile_foreach(void (*func)(struct btd_profile *p, void *data),
								void *data);

int btd_profile_register(struct btd_profile *profile);
void btd_profile_unregister(struct btd_profile *profile);

typedef bool (*btd_profile_prop_exists)(const char *uuid,
						struct btd_device *dev,
						void *user_data);

typedef bool (*btd_profile_prop_get)(const char *uuid,
						struct btd_device *dev,
						DBusMessageIter *iter,
						void *user_data);

bool btd_profile_add_custom_prop(const char *uuid, const char *type,
					const char *name,
					btd_profile_prop_exists exists,
					btd_profile_prop_get get,
					void *user_data);
bool btd_profile_remove_custom_prop(const char *uuid, const char *name);

void btd_profile_init(void);
void btd_profile_cleanup(void);
