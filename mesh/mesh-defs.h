/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
 *
 *
 */

/*
 * MshPRT_v1.1, section 3.3.1 / Core_v5.3, section 2.3.1.3
 * Maximum length of AdvData without 'Length' field (30)
 */
#define MESH_AD_MAX_LEN		(BT_AD_MAX_DATA_LEN - 1)

/* Max size of a Network PDU, prior prepending AD type (29)*/
#define MESH_NET_MAX_PDU_LEN	(MESH_AD_MAX_LEN - 1)

#define FEATURE_RELAY	1
#define FEATURE_PROXY	2
#define FEATURE_FRIEND	4
#define FEATURE_LPN	8

#define MESH_MODE_DISABLED	0
#define MESH_MODE_ENABLED	1
#define MESH_MODE_UNSUPPORTED	2

#define KEY_REFRESH_PHASE_NONE	0x00
#define KEY_REFRESH_PHASE_ONE	0x01
#define KEY_REFRESH_PHASE_TWO	0x02
#define KEY_REFRESH_PHASE_THREE	0x03

#define KEY_REFRESH_TRANS_TWO	0x02
#define KEY_REFRESH_TRANS_THREE	0x03

#define DEFAULT_TTL		0xff
#define TTL_MASK		0x7f

/* Supported algorithms for provisioning */
#define ALG_FIPS_256_ECC	0x0001

/* Input OOB action bit flags */
#define OOB_IN_PUSH	0x0001
#define OOB_IN_TWIST	0x0002
#define OOB_IN_NUMBER	0x0004
#define OOB_IN_ALPHA	0x0008

/* Output OOB action bit flags */
#define OOB_OUT_BLINK	0x0001
#define OOB_OUT_BEEP	0x0002
#define OOB_OUT_VIBRATE	0x0004
#define OOB_OUT_NUMBER	0x0008
#define OOB_OUT_ALPHA	0x0010

/* Status codes */
#define MESH_STATUS_SUCCESS		0x00
#define MESH_STATUS_INVALID_ADDRESS	0x01
#define MESH_STATUS_INVALID_MODEL	0x02
#define MESH_STATUS_INVALID_APPKEY	0x03
#define MESH_STATUS_INVALID_NETKEY	0x04
#define MESH_STATUS_INSUFF_RESOURCES	0x05
#define MESH_STATUS_IDX_ALREADY_STORED	0x06
#define MESH_STATUS_INVALID_PUB_PARAM	0x07
#define MESH_STATUS_NOT_SUB_MOD		0x08
#define MESH_STATUS_STORAGE_FAIL	0x09
#define MESH_STATUS_FEATURE_NO_SUPPORT	0x0a
#define MESH_STATUS_CANNOT_UPDATE	0x0b
#define MESH_STATUS_CANNOT_REMOVE	0x0c
#define MESH_STATUS_CANNOT_BIND		0x0d
#define MESH_STATUS_UNABLE_CHANGE_STATE	0x0e
#define MESH_STATUS_CANNOT_SET		0x0f
#define MESH_STATUS_UNSPECIFIED_ERROR	0x10
#define MESH_STATUS_INVALID_BINDING	0x11

/*Unassigned Address类型地址*/
#define UNASSIGNED_ADDRESS	0x0000
/*发送给所有proxy节点（节点需开启proxy功能）*/
#define PROXIES_ADDRESS	0xfffc
/*发送给所有friends节点（节点需开启friends功能）*/
#define FRIENDS_ADDRESS	0xfffd
/*发送给所有relay节点（节点需开启relay功能）*/
#define RELAYS_ADDRESS		0xfffe
/*发送给所有节点*/
#define ALL_NODES_ADDRESS	0xffff
#define VIRTUAL_ADDRESS_LOW	0x8000
#define VIRTUAL_ADDRESS_HIGH	0xbfff
/*
 * 一般目的组地址
 * addresses in the range 0xC000
 * through 0xFEFF are generally available for other usage.*/
#define GROUP_ADDRESS_LOW	0xc000
#define GROUP_ADDRESS_HIGH	0xfeff
/*预留的固定组地址：
 * Group addresses in the range 0xFF00
 * through 0xFFFF are reserved for Fixed Group addresses
*/
#define FIXED_GROUP_LOW		0xff00
#define FIXED_GROUP_HIGH	0xffff

#define NODE_IDENTITY_STOPPED		0x00
#define NODE_IDENTITY_RUNNING		0x01
#define NODE_IDENTITY_NOT_SUPPORTED	0x02

#define PRIMARY_ELE_IDX		0x00

#define PRIMARY_NET_IDX		0x0000
#define MAX_KEY_IDX		0x0fff
#define MAX_MODEL_COUNT		0xff
#define MAX_ELE_COUNT		0xff

#define MAX_MSG_LEN		380

#define VENDOR_ID_MASK		0xffff0000

#define NET_IDX_INVALID	0xffff
#define NET_NID_INVALID	0xff

#define NET_IDX_MAX		0x0fff
#define APP_IDX_MAX		0x0fff
#define APP_AID_INVALID	0xff

#define APP_IDX_MASK		0x0fff
#define APP_IDX_DEV_REMOTE	0x6fff
#define APP_IDX_DEV_LOCAL	0x7fff

#define DEFAULT_SEQUENCE_NUMBER 0x000000
#define SEQ_MASK		0xffffff

/*Unassigned Address指的是纯零地址*/
#define IS_UNASSIGNED(x)	((x) == UNASSIGNED_ADDRESS)
/*Unicast Address类型指的是首bit为0的地址，且不能为UNASSIGNED_ADDRESS*/
#define IS_UNICAST(x)		(((x) > UNASSIGNED_ADDRESS) && \
					((x) < VIRTUAL_ADDRESS_LOW))
/*x,c范围内是否均为Unicast Address*/
#define IS_UNICAST_RANGE(x, c)	(IS_UNICAST(x) && IS_UNICAST(x + c - 1))
/*Virtual Address类型指的是首bit为1，次bit为0的地址，即最小地址为0x8000,最大地址为0xBFFF
 * A virtual address represents a set of destination addresses.*/
#define IS_VIRTUAL(x)		(((x) >= VIRTUAL_ADDRESS_LOW) && \
					((x) <= VIRTUAL_ADDRESS_HIGH))
/*Group Address类型指的是首bit为1，次bit为1的地址，即最小地址为0xC000,最大地址0xFFFF*/
#define IS_GROUP(x)		((((x) >= GROUP_ADDRESS_LOW) && \
					((x) < FIXED_GROUP_HIGH)) || \
					((x) == ALL_NODES_ADDRESS))

#define IS_FIXED_GROUP_ADDRESS(x)	((x) >= PROXIES_ADDRESS)
/*指代所有NODES*/
#define IS_ALL_NODES(x)	((x) == ALL_NODES_ADDRESS)
