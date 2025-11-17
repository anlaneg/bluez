// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2014       Google Inc.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hidp.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"
#include "bluetooth/uuid.h"

#include "gdbus/gdbus.h"

#include "btio/btio.h"
#include "src/log.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/storage.h"
#include "src/dbus-common.h"
#include "src/error.h"
#include "src/sdp-client.h"
#include "src/shared/timeout.h"
#include "src/shared/uhid.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"

#include "device.h"
#include "hidp_defs.h"
#include "server.h"

#define INPUT_INTERFACE "org.bluez.Input1"

enum reconnect_mode_t {
	RECONNECT_NONE = 0,
	RECONNECT_DEVICE,
	RECONNECT_HOST,
	RECONNECT_ANY
};

struct hidp_msg {
	uint8_t hdr;
	struct iovec *iov;
};

struct input_device {
	struct btd_service	*service;
	struct btd_device	*device;/*关联的btd device*/
	char			*path;
	bdaddr_t		src;
	bdaddr_t		dst;
	const sdp_record_t	*rec;
	GIOChannel		*ctrl_io;/*控制用io*/
	GIOChannel		*intr_io;/*中断用io*/
	guint			ctrl_watch;
	guint			intr_watch;
	guint			sec_watch;
	struct hidp_connadd_req *req;
	bool			disable_sdp;
	enum reconnect_mode_t	reconnect_mode;
	unsigned int		reconnect_timer;
	uint32_t		reconnect_attempt;
	/*如果此指针不为空，则kernel uhid功能可用(可通过"/dev/uhid"操作）
	 * 否则采用hidp socket实现*/
	struct bt_uhid		*uhid;
	uint8_t			report_req_pending;
	unsigned int		report_req_timer;
	uint32_t		report_rsp_id;
	bool			virtual_cable_unplug;
	uint8_t			type;/*输入设备类型，例如：BT_UHID_NONE*/
	unsigned int		idle_timer;
};

static int idle_timeout = 0;
static uhid_state_t uhid_state = UHID_ENABLED;
static bool classic_bonded_only = true;

/*设置idle超时时间*/
void input_set_idle_timeout(int timeout)
{
	idle_timeout = timeout;
}

void input_set_userspace_hid(char *state)
{
	if (!strcasecmp(state, "false") || !strcasecmp(state, "no") ||
			!strcasecmp(state, "off"))
		uhid_state = UHID_DISABLED;/*禁止uhid*/
	else if (!strcasecmp(state, "true") || !strcasecmp(state, "yes") ||
			!strcasecmp(state, "on"))
		uhid_state = UHID_ENABLED;
	else if (!strcasecmp(state, "persist"))
		uhid_state = UHID_PERSIST;
	else
		error("Unknown value '%s'", state);
}

void input_set_classic_bonded_only(bool state)
{
	classic_bonded_only = state;
}

bool input_get_classic_bonded_only(void)
{
	return classic_bonded_only;
}

static void input_device_enter_reconnect_mode(struct input_device *idev);
static int connection_disconnect(struct input_device *idev, uint32_t flags);

static bool input_device_bonded(struct input_device *idev)
{
	return device_is_bonded(idev->device,
				btd_device_get_bdaddr_type(idev->device));
}

static void input_device_free(struct input_device *idev)
{
	bt_uhid_unref(idev->uhid);
	btd_service_unref(idev->service);
	btd_device_unref(idev->device);
	g_free(idev->path);

	if (idev->ctrl_watch > 0)
		g_source_remove(idev->ctrl_watch);

	if (idev->intr_watch > 0)
		g_source_remove(idev->intr_watch);

	if (idev->sec_watch > 0)
		g_source_remove(idev->sec_watch);

	if (idev->intr_io)
		g_io_channel_unref(idev->intr_io);

	if (idev->ctrl_io)
		g_io_channel_unref(idev->ctrl_io);

	if (idev->req) {
		g_free(idev->req->rd_data);
		g_free(idev->req);
	}

	if (idev->idle_timer)
		timeout_remove(idev->idle_timer);

	if (idev->reconnect_timer > 0)
		timeout_remove(idev->reconnect_timer);

	if (idev->report_req_timer > 0)
		timeout_remove(idev->report_req_timer);

	g_free(idev);
}

static void virtual_cable_unplug(struct input_device *idev)
{
	device_remove_bonding(idev->device,
				btd_device_get_bdaddr_type(idev->device));

	idev->virtual_cable_unplug = false;
}

static int uhid_disconnect(struct input_device *idev, bool force)
{
	int err;

	if (!bt_uhid_created(idev->uhid))
		return 0;/*未创建uhid,直接返回*/

	/* Force destroy the node if virtual cable unplug flag has been set */
	if (idev->virtual_cable_unplug && !force)
		force = true;

	if (!force && uhid_state != UHID_PERSIST)
		force = true;

	err = bt_uhid_destroy(idev->uhid, force);
	if (err < 0) {
		error("bt_uhid_destroy: %s", strerror(-err));
		return err;
	}

	if (!bt_uhid_created(idev->uhid))
		bt_uhid_unregister_all(idev->uhid);

	return err;
}

static bool input_device_idle_timeout(gpointer user_data)
{
	struct input_device *idev = user_data;

	idev->idle_timer = 0;

	DBG("path=%s", idev->path);

	uhid_disconnect(idev, true);
	connection_disconnect(idev, 0);

	return false;
}

static void input_device_idle_reset(struct input_device *idev)
{
	timeout_remove(idev->idle_timer);

	if (idle_timeout)
		idev->idle_timer = timeout_add_seconds(idle_timeout,
					input_device_idle_timeout, idev,
					NULL);
}

/*实现消息发送*/
static bool hidp_send_message(struct input_device *idev, GIOChannel *chan,
				uint8_t hdr, const uint8_t *data, size_t size)
{
	int fd;
	ssize_t len;
	struct iovec iov[2];

	if (!chan) {
		error("BT socket not connected");
		return false;
	}

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);/*1字节的header*/

	if (data == NULL)
		size = 0;

	iov[1].iov_base = (void *)data;/*size字节的内容*/
	iov[1].iov_len = size;

	fd = g_io_channel_unix_get_fd(chan);

	len = writev(fd, iov, 2);
	if (len < 0) {
		error("BT socket write error: %s (%d)", strerror(errno), errno);
		return false;
	}

	if ((size_t) len < size + 1) {
		error("BT socket write error: partial write (%zd of %zu bytes)",
								len, size + 1);
		return false;
	}

	input_device_idle_reset(idev);

	return true;
}

/*走控制io发送消息*/
static bool hidp_send_ctrl_message(struct input_device *idev, uint8_t hdr/*消息header*/,
					const uint8_t *data/*消息体*/, size_t size)
{
	if (hdr == (HIDP_TRANS_HID_CONTROL | HIDP_CTRL_VIRTUAL_CABLE_UNPLUG))
		idev->virtual_cable_unplug = true;

	return hidp_send_message(idev, idev->ctrl_io, hdr, data, size);
}

/*走中断io发送消息*/
static bool hidp_send_intr_message(struct input_device *idev, uint8_t hdr/*消息header*/,
					const uint8_t *data/*消息体*/, size_t size)
{
	return hidp_send_message(idev, idev->intr_io, hdr, data, size);
}

/*发送get report响应*/
static bool uhid_send_get_report_reply(struct input_device *idev,
					const uint8_t *data/*响应的数据*/, size_t size/*数据长度*/,
					uint32_t id/*响应关联的请求id*/, uint16_t err/*错误码*/)
{
	int ret;

	if (data == NULL)
		size = 0;

	if (!bt_uhid_created(idev->uhid)) {
		/*非uhid,返回false*/
		DBG("HID report (%zu bytes) dropped", size);
		return false;
	}

	//发送get report 响应
	ret = bt_uhid_get_report_reply(idev->uhid, id, 0, err, data, size);
	if (ret < 0) {
		error("bt_uhid_get_report_reply: %s (%d)", strerror(-ret),
			-ret);
		return false;
	}

	DBG("HID report (%zu bytes)", size);

	return true;
}

static bool uhid_send_set_report_reply(struct input_device *idev,
					uint32_t id, uint16_t err)
{
	int ret;

	if (!bt_uhid_created(idev->uhid))
		return false;

	ret = bt_uhid_set_report_reply(idev->uhid, id, err);
	if (ret < 0) {
		error("bt_uhid_set_report_reply: %s (%d)", strerror(-ret),
			-ret);
		return false;
	}

	return true;
}

static bool uhid_send_input_report(struct input_device *idev,
					const uint8_t *data, size_t size)
{
	int err;

	if (data == NULL)
		size = 0;

	if (!bt_uhid_created(idev->uhid)) {
		/*非uhid情况，不处理直接返回*/
		DBG("HID report (%zu bytes) dropped", size);
		return false;
	}

	err = bt_uhid_input(idev->uhid, 0, data, size);
	if (err < 0) {
		error("bt_uhid_input: %s (%d)", strerror(-err), -err);
		return false;
	}

	DBG("HID report (%zu bytes)", size);

	return true;
}

/*收取自中断 socket收到的event消息,这些消息会按input传递给kernel*/
static bool hidp_recv_intr_data(GIOChannel *chan, struct input_device *idev)
{
	int fd;
	ssize_t len;
	uint8_t hdr;
	uint8_t data[UHID_DATA_MAX + 1];

	fd = g_io_channel_unix_get_fd(chan);

	len = read(fd, data, sizeof(data));
	if (len < 0) {
		error("BT socket read error: %s (%d)", strerror(errno), errno);
		return false;
	}

	if (len == 0) {
		DBG("BT socket read returned 0 bytes");
		return true;
	}

	input_device_idle_reset(idev);/*重置idle定时器*/

	hdr = data[0];
	if (hdr != (HIDP_TRANS_DATA | HIDP_DATA_RTYPE_INPUT)) {
		/*中断socket,只考虑input事件*/
		DBG("unsupported HIDP protocol header 0x%02x", hdr);
		return true;
	}

	if (len < 2) {
		DBG("received empty HID report");
		return true;
	}

	uhid_send_input_report(idev, data + 1, len - 1);

	return true;
}

/*处理intr socket的读事件*/
static gboolean intr_watch_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct input_device *idev = data;
	char address[18];

	if (cond & G_IO_IN) {
		/*收取自中断channel收到的event消息,这些消息会传递给kernel*/
		if (hidp_recv_intr_data(chan, idev) && (cond == G_IO_IN))
			return TRUE;
	}

	ba2str(&idev->dst, address);

	DBG("Device %s disconnected", address);

	/* Checking for ctrl_watch avoids a double g_io_channel_shutdown since
	 * it's likely that ctrl_watch_cb has been queued for dispatching in
	 * this mainloop iteration */
	if ((cond & (G_IO_HUP | G_IO_ERR)) && idev->ctrl_watch)
		g_io_channel_shutdown(chan, TRUE, NULL);

	idev->intr_watch = 0;

	if (idev->intr_io) {
		g_io_channel_unref(idev->intr_io);
		idev->intr_io = NULL;
	}

	/* Close control channel if the closing of interrupt channel is not
	 * initiated by the other party
	 */
	if (idev->ctrl_io && !(cond & (G_IO_NVAL | G_IO_ERR)))
		g_io_channel_shutdown(idev->ctrl_io, TRUE, NULL);

	btd_service_disconnecting_complete(idev->service, 0);

	/* Enter the auto-reconnect mode if needed */
	input_device_enter_reconnect_mode(idev);

	if (!idev->ctrl_io && idev->virtual_cable_unplug)
		virtual_cable_unplug(idev);

	/* If connection abruptly ended, uhid might be not yet disconnected */
	uhid_disconnect(idev, false);

	return FALSE;
}

static void hidp_recv_ctrl_handshake(struct input_device *idev, uint8_t param)
{
	bool pending_req_complete = false;
	uint8_t pending_req_type;

	DBG("");

	pending_req_type = idev->report_req_pending & HIDP_HEADER_TRANS_MASK;

	switch (param) {
	case HIDP_HSHK_SUCCESSFUL:
		/*发送的SET_REPORT, SET_IDLE or SET_PROTOCOL已被正确收到*/
		if (pending_req_type == HIDP_TRANS_SET_REPORT) {
			DBG("SET_REPORT successful");
			pending_req_complete = true;
		} else
			DBG("Spurious HIDP_HSHK_SUCCESSFUL");
		break;

	case HIDP_HSHK_NOT_READY:/*设备太忙，没有收取请求，需要重发*/
	case HIDP_HSHK_ERR_INVALID_REPORT_ID:/*传输的report id无效*/
	case HIDP_HSHK_ERR_UNSUPPORTED_REQUEST:/*传输的请求，hid设备不支持*/
	case HIDP_HSHK_ERR_INVALID_PARAMETER:/*请求参数有误*/
	case HIDP_HSHK_ERR_UNKNOWN:/*Device could not identify the error condition.*/
	case HIDP_HSHK_ERR_FATAL:/*这种错误需要重启*/
		if (pending_req_type == HIDP_TRANS_GET_REPORT) {
			DBG("GET_REPORT failed (%u)", param);
			uhid_send_get_report_reply(idev, NULL, 0,
						idev->report_rsp_id, EIO);
			pending_req_complete = true;
		} else if (pending_req_type == HIDP_TRANS_SET_REPORT) {
			DBG("SET_REPORT failed (%u)", param);
			uhid_send_set_report_reply(idev, idev->report_rsp_id,
							EIO);
			pending_req_complete = true;
		} else
			DBG("Spurious HIDP_HSHK_ERR");

		if (param == HIDP_HSHK_ERR_FATAL)
			hidp_send_ctrl_message(idev, HIDP_TRANS_HID_CONTROL |
						HIDP_CTRL_SOFT_RESET, NULL, 0);
		break;

	default:
		/*发送控制消息*/
		hidp_send_ctrl_message(idev, HIDP_TRANS_HANDSHAKE |
				HIDP_HSHK_ERR_INVALID_PARAMETER/*参数无效*/, NULL, 0/*参数长度*/);
		break;
	}

	if (pending_req_complete) {
		idev->report_req_pending = 0;
		if (idev->report_req_timer > 0) {
			timeout_remove(idev->report_req_timer);
			idev->report_req_timer = 0;
		}
		uhid_send_set_report_reply(idev, idev->report_rsp_id, 0);
		idev->report_rsp_id = 0;
	}
}

static void hidp_recv_ctrl_hid_control(struct input_device *idev, uint8_t param)
{
	DBG("");

	/*仅处理VIRTUAL_CABLE_UNPLUG*/
	if (param == HIDP_CTRL_VIRTUAL_CABLE_UNPLUG)
		connection_disconnect(idev, (1 << HIDP_VIRTUAL_CABLE_UNPLUG));
}

/*从hid设备到host收到ctrl data*/
static void hidp_recv_ctrl_data(struct input_device *idev, uint8_t param,
					const uint8_t *data, size_t size)
{
	uint8_t pending_req_type;
	uint8_t pending_req_param;

	DBG("");

	pending_req_type = idev->report_req_pending & HIDP_HEADER_TRANS_MASK;
	if (pending_req_type != HIDP_TRANS_GET_REPORT &&
				pending_req_type != HIDP_TRANS_SET_REPORT) {
		/*只接收get report与set report两种请求类型*/
		DBG("Spurious DATA on control channel");
		return;
	}

	pending_req_param = idev->report_req_pending & HIDP_HEADER_PARAM_MASK;
	if (pending_req_param != param) {
		/*报文内容中的req_param与param指明的不一致*/
		DBG("Received DATA RTYPE doesn't match pending request RTYPE");
		return;
	}

	switch (param) {
	case HIDP_DATA_RTYPE_FEATURE:/*feature*/
	case HIDP_DATA_RTYPE_INPUT:/*input*/
	case HIDP_DATA_RTYPE_OUTPUT:/*output*/
		if (pending_req_type == HIDP_TRANS_GET_REPORT)
			uhid_send_get_report_reply(idev, data + 1/*report来的数据*/, size - 1/*数据长度*/,
							idev->report_rsp_id/*请求id*/, 0/*无错误*/);
		else
			uhid_send_set_report_reply(idev, idev->report_rsp_id,
							0);
		break;

	case HIDP_DATA_RTYPE_OTHER:
		DBG("Received DATA_RTYPE_OTHER");
		break;

	default:
		hidp_send_ctrl_message(idev, HIDP_TRANS_HANDSHAKE |
				HIDP_HSHK_ERR_INVALID_PARAMETER, NULL, 0);
		break;
	}

	idev->report_req_pending = 0;
	if (idev->report_req_timer > 0) {
		timeout_remove(idev->report_req_timer);
		idev->report_req_timer = 0;
	}
	idev->report_rsp_id = 0;
}

/*收取hid发送过来的ctrl消息*/
static bool hidp_recv_ctrl_message(GIOChannel *chan, struct input_device *idev)
{
	int fd;
	ssize_t len;
	uint8_t hdr, type, param;
	uint8_t data[UHID_DATA_MAX + 1];

	fd = g_io_channel_unix_get_fd(chan);

	len = read(fd, data, sizeof(data));
	if (len < 0) {
		error("BT socket read error: %s (%d)", strerror(errno), errno);
		return false;
	}

	if (len == 0) {
		DBG("BT socket read returned 0 bytes");
		return true;
	}

	input_device_idle_reset(idev);

	hdr = data[0];
	type = hdr & HIDP_HEADER_TRANS_MASK;/*取消息类型*/
	param = hdr & HIDP_HEADER_PARAM_MASK;/*消息*/

	switch (type) {
	case HIDP_TRANS_HANDSHAKE:
		/*收到HID设备应答信息*/
		hidp_recv_ctrl_handshake(idev, param/*result code*/);
		break;
	case HIDP_TRANS_HID_CONTROL:
		/*收到状态变更控制*/
		hidp_recv_ctrl_hid_control(idev, param);
		break;
	case HIDP_TRANS_DATA:
		/*This DATA message type identifies a HID payload.*/
		hidp_recv_ctrl_data(idev, param, data, len);
		break;
	default:
		error("unsupported HIDP control message");
		hidp_send_ctrl_message(idev, HIDP_TRANS_HANDSHAKE |
				HIDP_HSHK_ERR_UNSUPPORTED_REQUEST, NULL, 0);
		break;
	}

	return true;
}

/*处理ctrl socket的读事件*/
static gboolean ctrl_watch_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct input_device *idev = data;
	char address[18];

	if (cond & G_IO_IN) {
		/*收取设备经ctrl io发送过来的消息*/
		if (hidp_recv_ctrl_message(chan, idev) && (cond == G_IO_IN))
			return TRUE;
	}

	/*发生了其它非读事件（即错误事件）*/
	ba2str(&idev->dst, address);

	DBG("Device %s disconnected", address);

	/* Checking for intr_watch avoids a double g_io_channel_shutdown since
	 * it's likely that intr_watch_cb has been queued for dispatching in
	 * this mainloop iteration */
	if ((cond & (G_IO_HUP | G_IO_ERR)) && idev->intr_watch)
		g_io_channel_shutdown(chan, TRUE, NULL);

	idev->ctrl_watch = 0;

	if (idev->ctrl_io) {
		g_io_channel_unref(idev->ctrl_io);
		idev->ctrl_io = NULL;
	}

	/* Close interrupt channel */
	if (idev->intr_io && !(cond & G_IO_NVAL))
		g_io_channel_shutdown(idev->intr_io, TRUE, NULL);

	/* It's possible this is triggered while the intr channel is not even
	 * connected yet, therefore we are still in the connecting state.
	 */
	if (btd_service_get_state(idev->service) ==
						BTD_SERVICE_STATE_CONNECTING)
		btd_service_connecting_complete(idev->service, -EIO);

	if (!idev->intr_io && idev->virtual_cable_unplug)
		virtual_cable_unplug(idev);

	return FALSE;
}

#define REPORT_REQ_TIMEOUT  3

/*pending请求对应的超时响应定时器被触发*/
static bool hidp_report_req_timeout(gpointer data)
{
	struct input_device *idev = data;
	uint8_t pending_req_type;
	const char *req_type_str;
	char address[18];

	ba2str(&idev->dst, address);
	pending_req_type = idev->report_req_pending & HIDP_HEADER_TRANS_MASK;/*超时的请求类型*/

	switch (pending_req_type) {
	case HIDP_TRANS_GET_REPORT:/*get report请求超时*/
		req_type_str = "GET_REPORT";
		uhid_send_get_report_reply(idev, NULL, 0, idev->report_rsp_id,
								ETIMEDOUT);
		break;
	case HIDP_TRANS_SET_REPORT:/*set report请求超时*/
		req_type_str = "SET_REPORT";
		uhid_send_set_report_reply(idev, idev->report_rsp_id,
								ETIMEDOUT);
		break;
	default:
		/* Should never happen */
		req_type_str = "OTHER_TRANS";
		break;
	}

	error("Device %s HIDP %s request timed out", address, req_type_str);

	idev->report_req_pending = 0;
	idev->report_req_timer = 0;
	idev->report_rsp_id = 0;

	return FALSE;
}

/*uhid情况下output event对应的回调*/
static void hidp_send_output(struct uhid_event *ev, void *user_data)
{
	struct input_device *idev = user_data;
	uint8_t hdr = HIDP_TRANS_DATA | HIDP_DATA_RTYPE_OUTPUT;
	bool sent;

	DBG("");

	/*将此event,沿中断io对外进行发送*/
	sent = hidp_send_intr_message(idev, hdr, ev->u.output.data,
						ev->u.output.size);
	if (!sent)
		uhid_disconnect(idev, true);
}

/*uhid情况下set report event对应的回调*/
static void hidp_send_set_report(struct uhid_event *ev, void *user_data)
{
	struct input_device *idev = user_data;
	uint8_t hdr;
	bool sent;

	DBG("");

	switch (ev->u.set_report.rtype) {
	case UHID_FEATURE_REPORT:
		hdr = HIDP_TRANS_SET_REPORT | HIDP_DATA_RTYPE_FEATURE;
		break;
	case UHID_INPUT_REPORT:
		hdr = HIDP_TRANS_SET_REPORT | HIDP_DATA_RTYPE_INPUT;
		break;
	case UHID_OUTPUT_REPORT:
		hdr = HIDP_TRANS_SET_REPORT | HIDP_DATA_RTYPE_OUTPUT;
		break;
	default:
		DBG("Unsupported HID report type %u", ev->u.set_report.rtype);
		return;
	}

	if (idev->report_req_pending) {
		/*还有未响应的req,拒绝发消息*/
		DBG("Old GET_REPORT or SET_REPORT still pending");
		uhid_send_set_report_reply(idev, ev->u.set_report.id, EBUSY);
		return;
	}

	/*经ctrl_io发送控制消息*/
	sent = hidp_send_ctrl_message(idev, hdr, ev->u.set_report.data,
						ev->u.set_report.size);
	if (sent) {
		/*发送成功*/
		idev->report_req_pending = hdr;/*记录待响应的请求*/
		idev->report_req_timer =
			timeout_add_seconds(REPORT_REQ_TIMEOUT,
					hidp_report_req_timeout, idev, NULL);/*启动超时定时器*/
		idev->report_rsp_id = ev->u.set_report.id;/*记录响应rsp id*/
	} else {
		/*发送失败,发送set report reply指明eio*/
		uhid_send_set_report_reply(idev, ev->u.set_report.id, EIO);
		/* Force UHID_DESTROY on error */
		uhid_disconnect(idev, true);/*断开连接*/
	}
}

/*uhid情况下，get report event处理回调*/
static void hidp_send_get_report(struct uhid_event *ev, void *user_data)
{
	struct input_device *idev = user_data;
	uint8_t hdr;
	bool sent;

	DBG("");

	if (idev->report_req_pending) {
		DBG("Old GET_REPORT or SET_REPORT still pending");
		uhid_send_get_report_reply(idev, NULL, 0, ev->u.get_report.id,
									EBUSY);
		return;
	}

	/* Send GET_REPORT on control channel */
	switch (ev->u.get_report.rtype) {
	case UHID_FEATURE_REPORT:
		hdr = HIDP_TRANS_GET_REPORT | HIDP_DATA_RTYPE_FEATURE;
		break;
	case UHID_INPUT_REPORT:
		hdr = HIDP_TRANS_GET_REPORT | HIDP_DATA_RTYPE_INPUT;
		break;
	case UHID_OUTPUT_REPORT:
		hdr = HIDP_TRANS_GET_REPORT | HIDP_DATA_RTYPE_OUTPUT;
		break;
	default:
		/*其它类型不支持*/
		DBG("Unsupported HID report type %u", ev->u.get_report.rtype);
		return;
	}

	/*通过ctrl io对外发送event*/
	sent = hidp_send_ctrl_message(idev, hdr, &ev->u.get_report.rnum,
						sizeof(ev->u.get_report.rnum));
	if (sent) {
		/*发送成功*/
		idev->report_req_pending = hdr;
		idev->report_req_timer =
			timeout_add_seconds(REPORT_REQ_TIMEOUT,
						hidp_report_req_timeout, idev,
						NULL);
		idev->report_rsp_id = ev->u.get_report.id;/*记录响应id*/
	} else {
		uhid_send_get_report_reply(idev, NULL, 0, ev->u.get_report.id,
									EIO);
		/* Force UHID_DESTROY on error */
		uhid_disconnect(idev, true);
	}
}

static void epox_endian_quirk(unsigned char *data, int size)
{
	/* USAGE_PAGE (Keyboard)	05 07
	 * USAGE_MINIMUM (0)		19 00
	 * USAGE_MAXIMUM (65280)	2A 00 FF   <= must be FF 00
	 * LOGICAL_MINIMUM (0)		15 00
	 * LOGICAL_MAXIMUM (65280)	26 00 FF   <= must be FF 00
	 */
	unsigned char pattern[] = { 0x05, 0x07, 0x19, 0x00, 0x2a, 0x00, 0xff,
						0x15, 0x00, 0x26, 0x00, 0xff };
	unsigned int i;

	if (!data)
		return;

	for (i = 0; i < size - sizeof(pattern); i++) {
		if (!memcmp(data + i, pattern, sizeof(pattern))) {
			data[i + 5] = 0xff;
			data[i + 6] = 0x00;
			data[i + 10] = 0xff;
			data[i + 11] = 0x00;
		}
	}
}

static int create_hid_dev_name(const sdp_record_t *rec,
					struct hidp_connadd_req *req)
{
	char sdesc[sizeof(req->name) / 2];

	if (sdp_get_service_desc(rec, sdesc, sizeof(sdesc)) == 0) {
		char pname[sizeof(req->name) / 2];

		if (sdp_get_provider_name(rec, pname, sizeof(pname)) == 0 &&
						strncmp(sdesc, pname, 5) != 0)
			snprintf(req->name, sizeof(req->name), "%s %s",
								pname, sdesc);
		else
			snprintf(req->name, sizeof(req->name), "%s", sdesc);
	} else {
		return sdp_get_service_name(rec, req->name, sizeof(req->name));
	}

	return 0;
}

/* See HID profile specification v1.0, "7.11.6 HIDDescriptorList" for details
 * on the attribute format. */
static int extract_hid_desc_data(const sdp_record_t *rec,
						struct hidp_connadd_req *req)
{
	sdp_data_t *d;

	d = sdp_data_get(rec, SDP_ATTR_HID_DESCRIPTOR_LIST);/*取设备描述符list*/
	if (!d)
		goto invalid_desc;

	if (!SDP_IS_SEQ(d->dtd))
		goto invalid_desc;

	/* First HIDDescriptor */
	d = d->val.dataseq;
	if (!SDP_IS_SEQ(d->dtd))
		goto invalid_desc;

	/* ClassDescriptorType */
	d = d->val.dataseq;
	if (d->dtd != SDP_UINT8)
		goto invalid_desc;

	/* ClassDescriptorData */
	d = d->next;
	if (!d || !SDP_IS_TEXT_STR(d->dtd))
		goto invalid_desc;

	req->rd_data = g_try_malloc0(d->unitSize);
	if (req->rd_data) {
		/*填充描述符信息*/
		memcpy(req->rd_data, d->val.str, d->unitSize);
		req->rd_size = d->unitSize;
		epox_endian_quirk(req->rd_data, req->rd_size);
	}

	return 0;

invalid_desc:
	error("Missing or invalid HIDDescriptorList SDP attribute");
	return -EINVAL;
}

static int extract_hid_record(struct input_device *idev,
					struct hidp_connadd_req *req)
{
	sdp_data_t *pdlist;
	uint8_t attr_val;
	int err;

	if (!idev->rec)
		return -ENOENT;

	err = create_hid_dev_name(idev->rec, req);
	if (err < 0)
		DBG("No valid Service Name or Service Description found");

	pdlist = sdp_data_get(idev->rec, SDP_ATTR_HID_PARSER_VERSION);
	req->parser = pdlist ? pdlist->val.uint16 : 0x0100;

	pdlist = sdp_data_get(idev->rec, SDP_ATTR_HID_DEVICE_SUBCLASS);
	req->subclass = pdlist ? pdlist->val.uint8 : 0;

	pdlist = sdp_data_get(idev->rec, SDP_ATTR_HID_COUNTRY_CODE);/*取country code*/
	req->country = pdlist ? pdlist->val.uint8 : 0;

	pdlist = sdp_data_get(idev->rec, SDP_ATTR_HID_VIRTUAL_CABLE);
	attr_val = pdlist ? pdlist->val.uint8 : 0;
	if (attr_val)
		req->flags |= (1 << HIDP_VIRTUAL_CABLE_UNPLUG);

	pdlist = sdp_data_get(idev->rec, SDP_ATTR_HID_BOOT_DEVICE);
	attr_val = pdlist ? pdlist->val.uint8 : 0;
	if (attr_val)
		req->flags |= (1 << HIDP_BOOT_PROTOCOL_MODE);

	err = extract_hid_desc_data(idev->rec, req);
	if (err < 0)
		return err;

	return 0;
}

static int ioctl_connadd(struct hidp_connadd_req *req)
{
	int ctl, err = 0;

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0)
		return -errno;

	/*添加hci设备，启动kernel线程*/
	if (ioctl(ctl, HIDPCONNADD, req) < 0)
		err = -errno;

	close(ctl);

	return err;
}

static bool ioctl_is_connected(struct input_device *idev)
{
	struct hidp_conninfo ci;
	int ctl;

	/* Standard HID */
	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0) {
		error("Can't open HIDP control socket");
		return false;
	}

	memset(&ci, 0, sizeof(ci));
	bacpy(&ci.bdaddr, &idev->dst);/*检查此地址对应的session是否存在*/
	if (ioctl(ctl, HIDPGETCONNINFO, &ci) < 0) {
		error("Can't get HIDP connection info");
		close(ctl);
		return false;
	}

	close(ctl);

	if (ci.state != BT_CONNECTED)
		return false;/*此session状态不为connected*/

	return true;/*状态为connected*/
}

static int ioctl_disconnect(struct input_device *idev, uint32_t flags)
{
	struct hidp_conndel_req req;
	struct hidp_conninfo ci;
	int ctl, err = 0;

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0) {
		error("Can't open HIDP control socket");
		return -errno;
	}

	memset(&ci, 0, sizeof(ci));
	bacpy(&ci.bdaddr, &idev->dst);
	if ((ioctl(ctl, HIDPGETCONNINFO, &ci) < 0) ||
						(ci.state != BT_CONNECTED)) {
		close(ctl);
		return -ENOTCONN;
	}

	memset(&req, 0, sizeof(req));
	bacpy(&req.bdaddr, &idev->dst);
	req.flags = flags;
	if (ioctl(ctl, HIDPCONNDEL, &req) < 0) {
		err = -errno;
		error("Can't delete the HID device: %s (%d)",
							strerror(-err), -err);
	}

	close(ctl);

	return err;
}

static int uhid_connadd(struct input_device *idev, struct hidp_connadd_req *req)
{
	int err;

	if (bt_uhid_created(idev->uhid))
		return bt_uhid_replay(idev->uhid);

	/*发送UHID_CREATE2创建uhid*/
	err = bt_uhid_create(idev->uhid, req->name, &idev->src, &idev->dst,
				req->vendor, req->product, req->version,
				req->country, idev->type,
				req->rd_data, req->rd_size);
	if (err < 0) {
		error("bt_uhid_create: %s", strerror(-err));
		return err;
	}

	/*注册output event对应的回调*/
	bt_uhid_register(idev->uhid, UHID_OUTPUT, hidp_send_output, idev);
	/*注册get report event处理回调*/
	bt_uhid_register(idev->uhid, UHID_GET_REPORT, hidp_send_get_report,
									idev);
	/*注册UHID_SET_REPORT对应的处理回调*/
	bt_uhid_register(idev->uhid, UHID_SET_REPORT, hidp_send_set_report,
									idev);

	return err;
}

static gboolean encrypt_notify(GIOChannel *io, GIOCondition condition,
								gpointer data)
{
	struct input_device *idev = data;
	int err;

	DBG("");

	if (idev->uhid)
		err = uhid_connadd(idev, idev->req);
	else
		err = ioctl_connadd(idev->req);

	if (err < 0) {
		/*添加失败，关闭对应的io*/
		error("ioctl_connadd(): %s (%d)", strerror(-err), -err);

		if (idev->ctrl_io) {
			g_io_channel_shutdown(idev->ctrl_io, FALSE, NULL);
			g_io_channel_unref(idev->ctrl_io);
			idev->ctrl_io = NULL;
		}

		if (idev->intr_io) {
			g_io_channel_shutdown(idev->intr_io, FALSE, NULL);
			g_io_channel_unref(idev->intr_io);
			idev->intr_io = NULL;
		}
	}

	idev->sec_watch = 0;

	g_free(idev->req->rd_data);
	g_free(idev->req);
	idev->req = NULL;

	return FALSE;
}

static int hidp_add_connection(struct input_device *idev)
{
	struct hidp_connadd_req *req;
	bool cable_pairing;
	GError *gerr = NULL;
	int err;

	req = g_new0(struct hidp_connadd_req, 1);
	req->ctrl_sock = g_io_channel_unix_get_fd(idev->ctrl_io);/*取得ctrl socket*/
	req->intr_sock = g_io_channel_unix_get_fd(idev->intr_io);/*取得intr socket*/
	req->flags     = 0;
	req->idle_to   = idle_timeout;/*设置请求idle超时时间*/

	err = extract_hid_record(idev, req);/*填充req其它字段*/
	if (err < 0) {
		error("Could not parse HID SDP record: %s (%d)", strerror(-err),
									-err);
		goto cleanup;
	}

	req->vendor = btd_device_get_vendor(idev->device);/*指明设备vendor*/
	req->product = btd_device_get_product(idev->device);
	req->version = btd_device_get_version(idev->device);

	/*填充设备名称*/
	if (device_name_known(idev->device))
		device_get_name(idev->device, req->name, sizeof(req->name));

	cable_pairing = device_is_cable_pairing(idev->device);

	/* Make sure the device is bonded if required */
	if (!cable_pairing && classic_bonded_only &&
			!input_device_bonded(idev)) {
		error("Rejected connection from !bonded device %s", idev->path);
		goto cleanup;
	}

	/* Encryption is mandatory for keyboards */
	/* Some platforms may choose to require encryption for all devices */
	/* Note that this only matters for pre 2.1 devices as otherwise the */
	/* device is encrypted by default by the lower layers */
	/* Don't enforce encryption for cable paired devices because they */
	/* don't support it */
	if (!cable_pairing && (classic_bonded_only ||
				idev->type == BT_UHID_KEYBOARD)) {
		if (!bt_io_set(idev->intr_io, &gerr,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
					BT_IO_OPT_INVALID)) {
			error("btio: %s", gerr->message);
			g_error_free(gerr);
			err = -EFAULT;
			goto cleanup;
		}

		idev->req = req;
		idev->sec_watch = g_io_add_watch(idev->intr_io, G_IO_OUT,
							encrypt_notify, idev);

		return 0;
	}

	if (idev->uhid)
		/*uhid可用，通过uhid接口实现hid设备添加*/
		err = uhid_connadd(idev, req);
	else
		/*通过ioctl，添加hid设备，kernel启动了数据搬运线程*/
		err = ioctl_connadd(req);

cleanup:
	g_free(req->rd_data);
	g_free(req);

	return err;
}

static bool is_connected(struct input_device *idev)
{
	if (idev->uhid)
		/*uhid情况下，两个io不为NULL，即连接*/
		return (idev->intr_io != NULL && idev->ctrl_io != NULL);
	else
		/*检查session是否已连接*/
		return ioctl_is_connected(idev);
}

static int connection_disconnect(struct input_device *idev, uint32_t flags)
{
	int sock;

	if (!is_connected(idev))
		return -ENOTCONN;

	/* Standard HID disconnect
	 * Intr channel must be disconnected before ctrl channel, so only
	 * disconnect intr here, ctrl is disconnected in intr_watch_cb.
	 */
	if (idev->intr_io) {
		sock = g_io_channel_unix_get_fd(idev->intr_io);
		shutdown(sock, SHUT_WR);
	}

	if (flags & (1 << HIDP_VIRTUAL_CABLE_UNPLUG)) {
		idev->virtual_cable_unplug = true;
		if (idev->uhid)
			hidp_send_ctrl_message(idev, HIDP_TRANS_HID_CONTROL |
						HIDP_CTRL_VIRTUAL_CABLE_UNPLUG,
						NULL, 0);
	}

	/*依据不同情况，执行不同的断开方法*/
	if (idev->uhid)
		return uhid_disconnect(idev, false);
	else
		return ioctl_disconnect(idev, flags);
}

static bool is_device_sdp_disable(const sdp_record_t *rec)
{
	sdp_data_t *data;

	data = sdp_data_get(rec, SDP_ATTR_HID_SDP_DISABLE);

	return data && data->val.uint8;
}

static enum reconnect_mode_t hid_reconnection_mode(bool reconnect_initiate,
						bool normally_connectable)
{
	if (!reconnect_initiate && !normally_connectable)
		return RECONNECT_NONE;
	else if (!reconnect_initiate && normally_connectable)
		return RECONNECT_HOST;
	else if (reconnect_initiate && !normally_connectable)
		return RECONNECT_DEVICE;
	else /* (reconnect_initiate && normally_connectable) */
		return RECONNECT_ANY;
}

static void extract_hid_props(struct input_device *idev,
					const sdp_record_t *rec)
{
	/* Extract HID connectability */
	bool reconnect_initiate, normally_connectable;
	sdp_data_t *pdlist;

	/* HIDNormallyConnectable is optional and assumed FALSE if not
	 * present.
	 */
	pdlist = sdp_data_get(rec, SDP_ATTR_HID_RECONNECT_INITIATE);
	reconnect_initiate = pdlist ? pdlist->val.uint8 : TRUE;

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_NORMALLY_CONNECTABLE);
	normally_connectable = pdlist ? pdlist->val.uint8 : FALSE;

	/* Update local values */
	idev->reconnect_mode =
		hid_reconnection_mode(reconnect_initiate, normally_connectable);
}

static void input_device_update_rec(struct input_device *idev)
{
	struct btd_profile *p = btd_service_get_profile(idev->service);
	const sdp_record_t *rec;

	rec = btd_device_get_record(idev->device, p->remote_uuid);
	if (!rec || idev->rec == rec)
		return;

	idev->rec = rec;
	idev->disable_sdp = is_device_sdp_disable(rec);

	/* Initialize device properties */
	extract_hid_props(idev, rec);

	if (idev->disable_sdp)
		device_set_refresh_discovery(idev->device, false);
}

static int input_device_connected(struct input_device *idev)
{
	int err;

	if (idev->intr_io == NULL || idev->ctrl_io == NULL)
		return -ENOTCONN;/*以上两个必不能为零*/

	/* Attempt to update SDP record if it had changed */
	input_device_update_rec(idev);

	err = hidp_add_connection(idev);/*创建并添加hid设备*/
	if (err < 0)
		return err;

	btd_service_connecting_complete(idev->service, 0);

	return 0;
}

/*中断socket连接成功时调用(通过l2cap收到设备发送过来的消息）*/
static void interrupt_connect_cb(GIOChannel *chan, GError *conn_err,
							gpointer user_data)
{
	struct input_device *idev = user_data;
	GIOCondition cond = G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	int err;

	if (conn_err) {
		/*intr socket连接失败*/
		err = -EIO;
		goto failed;
	}

	err = input_device_connected(idev);
	if (err < 0)
		goto failed;

	if (idev->uhid)
		cond |= G_IO_IN;/*关注intr socket可读*/

	idev->intr_watch = g_io_add_watch(idev->intr_io, cond, intr_watch_cb,
									idev);

	return;

failed:
	btd_service_connecting_complete(idev->service, err);

	/* So we guarantee the interrupt channel is closed before the
	 * control channel (if we only do unref GLib will close it only
	 * after returning control to the mainloop */
	if (!conn_err)
		g_io_channel_shutdown(idev->intr_io, FALSE, NULL);

	g_io_channel_unref(idev->intr_io);
	idev->intr_io = NULL;

	if (idev->ctrl_io) {
		g_io_channel_unref(idev->ctrl_io);
		idev->ctrl_io = NULL;
	}
}

/*创建control socket,再创建intr socket*/
static void control_connect_cb(GIOChannel *chan, GError *conn_err,
							gpointer user_data)
{
	struct input_device *idev = user_data;
	GIOCondition cond = G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	GIOChannel *io;
	GError *err = NULL;

	if (conn_err) {
		/*连接control socket失败*/
		error("%s", conn_err->message);
		goto failed;
	}

	/* Connect to the HID interrupt channel */
	/*采用src到dst建立连接intr socket，目的PSM为HIDP_INTR*/
	io = bt_io_connect(interrupt_connect_cb, idev,
				NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &idev->src,
				BT_IO_OPT_DEST_BDADDR, &idev->dst,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_INTR,/*创建中断socket*/
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
		goto failed;
	}

	idev->intr_io = io;/*设置中断 socket*/

	if (idev->uhid)
		cond |= G_IO_IN;/*关注ctrl读事件*/

	idev->ctrl_watch = g_io_add_watch(idev->ctrl_io, cond, ctrl_watch_cb,
									idev);

	return;

failed:
	btd_service_connecting_complete(idev->service, -EIO);
	g_io_channel_unref(idev->ctrl_io);
	idev->ctrl_io = NULL;
}

static int dev_connect(struct input_device *idev)
{
	GError *err = NULL;
	GIOChannel *io;
	BtIOSecLevel sec_level;

	if (idev->disable_sdp)
		bt_clear_cached_session(&idev->src, &idev->dst);

	/* encrypt connection if device is bonded */
	if (input_device_bonded(idev))
		sec_level = BT_IO_SEC_MEDIUM;
	else
		sec_level = BT_IO_SEC_LOW;

	/*采用src到dst建立control socket连接，目的PSM为HIDP_CTRL*/
	io = bt_io_connect(control_connect_cb, idev,
				NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &idev->src,
				BT_IO_OPT_DEST_BDADDR, &idev->dst,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_CTRL,
				BT_IO_OPT_SEC_LEVEL, sec_level,
				BT_IO_OPT_INVALID);
	idev->ctrl_io = io;/*设置ctrl socket*/

	if (err == NULL)
		return 0;

	error("%s", err->message);
	g_error_free(err);

	return -EIO;
}

static bool input_device_auto_reconnect(gpointer user_data)
{
	struct input_device *idev = user_data;

	DBG("path=%s, attempt=%d", idev->path, idev->reconnect_attempt);

	/* Stop the recurrent reconnection attempts if the device is
	 * reconnected or is marked for removal.
	 */
	if (device_is_temporary(idev->device) ||
					btd_device_is_connected(idev->device))
		goto bail;

	/* Only attempt an auto-reconnect for at most 3 minutes (6 * 30s). */
	if (idev->reconnect_attempt >= 6)
		goto bail;

	/* Check if the profile is already connected. */
	if (idev->ctrl_io)
		goto bail;

	if (is_connected(idev))
		goto bail;

	idev->reconnect_attempt++;
	dev_connect(idev);

	return TRUE;

bail:
	idev->reconnect_timer = 0;
	return FALSE;
}

static const char * const _reconnect_mode_str[] = {
	"none",
	"device",
	"host",
	"any"
};

static const char *reconnect_mode_to_string(const enum reconnect_mode_t mode)
{
	return _reconnect_mode_str[mode];
}

static void input_device_enter_reconnect_mode(struct input_device *idev)
{
	DBG("path=%s reconnect_mode=%s", idev->path,
				reconnect_mode_to_string(idev->reconnect_mode));

	/* Make sure the device is bonded if required */
	if (classic_bonded_only && !input_device_bonded(idev))
		return;

	/* Only attempt an auto-reconnect when the device is required to
	 * accept reconnections from the host.
	 */
	if (idev->reconnect_mode != RECONNECT_ANY &&
				idev->reconnect_mode != RECONNECT_HOST)
		return;

	/* If the device is temporary we are not required to reconnect
	 * with the device. This is likely the case of a removing device.
	 */
	if (device_is_temporary(idev->device) ||
					btd_device_is_connected(idev->device))
		return;

	if (idev->reconnect_timer > 0)
		timeout_remove(idev->reconnect_timer);

	DBG("registering auto-reconnect");
	idev->reconnect_attempt = 0;
	idev->reconnect_timer = timeout_add_seconds(30,
					input_device_auto_reconnect, idev,
					NULL);

}

int input_device_connect(struct btd_service *service)
{
	struct input_device *idev;

	DBG("");

	idev = btd_service_get_user_data(service);

	if (idev->ctrl_io)
		return -EBUSY;

	if (is_connected(idev))
		return -EALREADY;

	return dev_connect(idev);
}

int input_device_disconnect(struct btd_service *service)
{
	struct input_device *idev;
	int err, flags;

	DBG("");

	idev = btd_service_get_user_data(service);

	flags = device_is_temporary(idev->device) ?
					(1 << HIDP_VIRTUAL_CABLE_UNPLUG) : 0;

	err = connection_disconnect(idev, flags);
	if (err < 0)
		return err;

	return 0;
}

static struct input_device *input_device_new(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct input_device *idev;

	/*申请并初始化input设备*/
	idev = g_new0(struct input_device, 1);
	bacpy(&idev->src, btd_adapter_get_address(adapter));
	bacpy(&idev->dst, device_get_address(device));
	idev->service = btd_service_ref(service);
	idev->device = btd_device_ref(device);
	idev->path = g_strdup(path);
	idev->type = bt_uhid_icon_to_type(btd_device_get_icon(device));

	input_device_update_rec(idev);

	return idev;
}

static gboolean property_get_reconnect_mode(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct input_device *idev = data;
	const char *str_mode = reconnect_mode_to_string(idev->reconnect_mode);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str_mode);

	return TRUE;
}

static const GDBusPropertyTable input_properties[] = {
	{ "ReconnectMode", "s", property_get_reconnect_mode },
	{ }
};

int input_device_register(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);
	struct input_device *idev;

	DBG("%s", path);

	idev = input_device_new(service);
	if (!idev)
		return -EINVAL;

	if (uhid_state) {
		idev->uhid = bt_uhid_new_default();
		if (!idev->uhid) {
			/*创建uhid设备失败，uhid不可用，禁用uhid*/
			DBG("bt_uhid_new_default failed, switching to kernel "
			    "mode");
			uhid_state = UHID_DISABLED;
		}
	}

	if (g_dbus_register_interface(btd_get_dbus_connection(),
					idev->path, INPUT_INTERFACE,
					NULL, NULL,
					input_properties, idev,
					NULL) == FALSE) {
		error("Unable to register %s interface", INPUT_INTERFACE);
		input_device_free(idev);
		return -EINVAL;
	}

	btd_service_set_user_data(service, idev);
	device_set_wake_support(device, true);

	if (device_is_cable_pairing(device)) {
		struct btd_adapter *adapter = device_get_adapter(device);
		const bdaddr_t *bdaddr = btd_adapter_get_address(adapter);

		server_set_cable_pairing(bdaddr, true);
	}

	return 0;
}

static struct input_device *find_device(const bdaddr_t *src,
					const bdaddr_t *dst)
{
	struct btd_device *device;
	struct btd_service *service;

	/*通过src确定adapter,然后在adapter下查找dst对应的btd_device*/
	device = btd_adapter_find_device(adapter_find(src), dst, BDADDR_BREDR);
	if (device == NULL)
		return NULL;

	service = btd_device_get_service(device, HID_UUID);
	if (service == NULL)
		return NULL;

	return btd_service_get_user_data(service);
}

void input_device_unregister(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);
	struct input_device *idev = btd_service_get_user_data(service);

	DBG("%s", path);

	g_dbus_unregister_interface(btd_get_dbus_connection(),
						idev->path, INPUT_INTERFACE);

	input_device_free(idev);
}

static int input_device_connadd(struct input_device *idev)
{
	int err;

	err = input_device_connected(idev);/*hid设备连接添加*/
	if (err == 0)
		return 0;

	if (idev->ctrl_io) {
		/*失败，关闭ctrl io*/
		g_io_channel_shutdown(idev->ctrl_io, FALSE, NULL);
		g_io_channel_unref(idev->ctrl_io);
		idev->ctrl_io = NULL;
	}

	if (idev->intr_io) {
		/*失败，关闭intr io*/
		g_io_channel_shutdown(idev->intr_io, FALSE, NULL);
		g_io_channel_unref(idev->intr_io);
		idev->intr_io = NULL;
	}

	return err;
}

bool input_device_exists(const bdaddr_t *src, const bdaddr_t *dst)
{
	if (find_device(src, dst))
		return true;

	return false;
}

int input_device_set_channel(const bdaddr_t *src, const bdaddr_t *dst, int psm,
								GIOChannel *io)
{
	struct input_device *idev = find_device(src, dst);
	GIOCondition cond = G_IO_HUP | G_IO_ERR | G_IO_NVAL;

	DBG("idev %p psm %d", idev, psm);

	if (!idev)
		return -ENOENT;

	if (uhid_state)
		cond |= G_IO_IN;/*可读*/

	switch (psm) {
	case L2CAP_PSM_HIDP_CTRL:/*ctrl socket设置*/
		if (idev->ctrl_io)
			return -EALREADY;
		idev->ctrl_io = g_io_channel_ref(io);
		idev->ctrl_watch = g_io_add_watch(idev->ctrl_io, cond,
							ctrl_watch_cb, idev);
		break;
	case L2CAP_PSM_HIDP_INTR:/*中断socket设置*/
		if (idev->intr_io)
			return -EALREADY;
		idev->intr_io = g_io_channel_ref(io);
		idev->intr_watch = g_io_add_watch(idev->intr_io, cond,
							intr_watch_cb/*设备通过intr发送过来的消息*/, idev);
		break;
	}

	/*控制io及中断io均已包含，添加input设备*/
	if (idev->intr_io && idev->ctrl_io)
		input_device_connadd(idev);

	return 0;
}

int input_device_close_channels(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct input_device *idev = find_device(src, dst);

	if (!idev)
		return -ENOENT;

	if (idev->intr_io)
		g_io_channel_shutdown(idev->intr_io, TRUE, NULL);

	if (idev->ctrl_io)
		g_io_channel_shutdown(idev->ctrl_io, TRUE, NULL);

	return 0;
}
