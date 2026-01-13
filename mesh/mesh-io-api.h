/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
 *
 *
 */

struct mesh_io_private;

typedef bool (*mesh_io_init_t)(struct mesh_io *io, void *opts, void *user_data);
typedef bool (*mesh_io_destroy_t)(struct mesh_io *io);
typedef bool (*mesh_io_caps_t)(struct mesh_io *io, struct mesh_io_caps *caps);
typedef bool (*mesh_io_send_t)(struct mesh_io *io,
					struct mesh_io_send_info *info,
					const uint8_t *data, uint16_t len);
typedef bool (*mesh_io_register_t)(struct mesh_io *io, const uint8_t *filter/*用于匹配报文,匹配上才能调用cb*/,
					uint8_t len/*FILTER长度*/, mesh_io_recv_func_t cb/*收包回调*/,
					void *user_data/*回调参数*/);
typedef bool (*mesh_io_deregister_t)(struct mesh_io *io, const uint8_t *filter,
								uint8_t len);
typedef bool (*mesh_io_tx_cancel_t)(struct mesh_io *io, const uint8_t *pattern,
								uint8_t len);

struct mesh_io_api {
	mesh_io_init_t		init;/*用于实现api初始化,例如挂上mesh钩子*/
	mesh_io_destroy_t	destroy;
	mesh_io_caps_t		caps;
	mesh_io_send_t		send;/*发送*/
	mesh_io_register_t	reg;/*注册收包回调*/
	mesh_io_deregister_t	dereg;
	mesh_io_tx_cancel_t	cancel;
};

struct mesh_io_reg {
	mesh_io_recv_func_t cb;/*收包回调,当FILTER和收到的报文匹配,则触发*/
	void *user_data;/*收包回调参数*/
	uint8_t len;/*filter长度*/
	uint8_t filter[];/*用于匹配*/
};

struct mesh_io {
	int				index;
	int				favored_index;
	mesh_io_ready_func_t		ready;
	struct l_queue			*rx_regs;
	struct mesh_io_private		*pvt;/*私有数据*/
	void				*user_data;
	const struct mesh_io_api	*api;/*默认使用mesh_io_mgmt*/
};

struct mesh_io_table {
	enum mesh_io_type		type;
	const struct mesh_io_api	*api;
};
