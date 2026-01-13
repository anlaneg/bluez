// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "monitor/bt.h"
#include "src/shared/mainloop.h"
#include "src/shared/io.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/hci.h"

#define BTPROTO_HCI	1
struct sockaddr_hci {
	sa_family_t	hci_family;
	unsigned short	hci_dev;
	unsigned short  hci_channel;
};
#define HCI_CHANNEL_RAW		0
#define HCI_CHANNEL_USER	1

#define SOL_HCI		0
#define HCI_FILTER	2
struct hci_filter {
	uint32_t type_mask;
	uint32_t event_mask[2];
	uint16_t opcode;
};

struct bt_hci {
	int ref_count;
	struct io *io;
	bool is_stream;
	bool writer_active;/*指明writer是否已激活(是否已设置writer回调) ;当发送处理完成,会置为false*/
	uint8_t num_cmds;/*记录当前可以向hci发送的command数目(由HCI通过event响应提供)*/
	unsigned int next_cmd_id;/*负责分配cmd id*/
	unsigned int next_evt_id;
	struct queue *cmd_queue;/*CMD待发送队列,用于记录等待发送的cmd*/
	struct queue *rsp_queue;/*响应队列,用于记录等待响应的cmd*/
	struct queue *evt_list;/*事件关注队列,用于注册依据KERNEL事件要执行的处理*/
	struct queue *data_queue;/*acl数据报文队列(用于记录等待发送的ACL data)*/
};

struct cmd {
	unsigned int id;/*命令编号*/
	uint16_t opcode;
	void *data;/*cmd参数*/
	uint8_t size;/*cmd参数长度*/
	bt_hci_callback_func_t callback;/*当命令被响应后,此回调触发*/
	bt_hci_destroy_func_t destroy;/*设置此cMd结构体被 释放时需要执行的回调*/
	void *user_data;/*以上两个回调需要的函数参数*/
};

struct evt {
	unsigned int id;
	uint8_t event;
	bt_hci_callback_func_t callback;
	bt_hci_destroy_func_t destroy;
	void *user_data;
};

struct data {
	uint8_t type;/*报文类型*/
	uint16_t handle;
	void *data;
	uint8_t size;
};

static void cmd_free(void *data)
{
	struct cmd *cmd = data;

	if (cmd->destroy)
		cmd->destroy(cmd->user_data);

	free(cmd->data);
	free(cmd);
}

static void evt_free(void *data)
{
	struct evt *evt = data;

	if (evt->destroy)
		evt->destroy(evt->user_data);

	free(evt);
}

static void data_free(void *data)
{
	struct data *d = data;

	free(d->data);
	free(d);
}

/*hci命令发送*/
static void send_command(struct bt_hci *hci, uint16_t opcode,
						void *data, uint8_t size)
{
	uint8_t type = BT_H4_CMD_PKT;
	struct bt_hci_cmd_hdr hdr;
	struct iovec iov[3];
	int iovcnt;

	if (hci->num_cmds < 1)
		return;

	hdr.opcode = cpu_to_le16(opcode);
	hdr.plen = size;

	iov[0].iov_base = &type;/*报文类型*/
	iov[0].iov_len  = 1;
	iov[1].iov_base = &hdr;/*报文header*/
	iov[1].iov_len  = sizeof(hdr);

	if (size > 0) {
		iov[2].iov_base = data;/*命令参数*/
		iov[2].iov_len  = size;
		iovcnt = 3;
	} else
		iovcnt = 2;

	/*命令发送*/
	if (io_send(hci->io, iov, iovcnt) < 0)
		return;

	hci->num_cmds--;/*命令数减少*/
}

/*发送ACL数据报文*/
static void send_data(struct bt_hci *hci, uint8_t type, uint16_t handle,
						void *data, uint16_t size)
{
	struct iovec iov[3];
	struct bt_hci_acl_hdr hdr;

	/*填写acl头部*/
	hdr.handle = cpu_to_le16(handle);
	hdr.dlen = cpu_to_le16(size);

	iov[0].iov_base = &type;/*数据报文类型*/
	iov[0].iov_len  = 1;
	iov[1].iov_base = &hdr;/*ACL数据头*/
	iov[1].iov_len  = sizeof(hdr);
	iov[2].iov_base = data;/*参数*/
	iov[2].iov_len  = size;

	io_send(hci->io, iov, 3);/*发送ACL数据*/
}

/*如果有cmd就向外发送cmd,如果有acl data,就发送acl data;两者都有,则均发送*/
static bool io_write_callback(struct io *io, void *user_data)
{
	struct bt_hci *hci = user_data;
	struct cmd *cmd;
	struct data *data;

	if (hci->num_cmds/*容许向HCI发送命令*/) {
		cmd = queue_pop_head(hci->cmd_queue);/*取一个cmd*/
		if (cmd) {
			/*向kernel发送此cmd*/
			send_command(hci, cmd->opcode, cmd->data, cmd->size);
			/*命令发送完成,将此cmd移动到response队列*/
			queue_push_tail(hci->rsp_queue, cmd);
		}
	}

	/*弹出数据报文,并向外发送*/
	data = queue_pop_head(hci->data_queue);
	if (data)
		send_data(hci, data->type, data->handle,
					data->data, data->size);

	hci->writer_active = false;/*发送结束,writer取消激活*/

	return false;
}

/*使能hci writer,向内核发送命令或数据*/
static void wakeup_writer(struct bt_hci *hci)
{
	if (hci->writer_active)
		return;/*writer已激活,直接返回*/

	if (queue_isempty(hci->cmd_queue) && queue_isempty(hci->data_queue))
		return;/*未激活,但队列是空的*/

	/*设置io的write回调*/
	if (!io_set_write_handler(hci->io, io_write_callback, hci, NULL))
		return;

	hci->writer_active = true;
}

/*按opcode匹配cmd*/
static bool match_cmd_opcode(const void *a, const void *b)
{
	const struct cmd *cmd = a;
	uint16_t opcode = PTR_TO_UINT(b);

	return cmd->opcode == opcode;
}

/*处理BT_HCI_EVT_CMD_COMPLETE响应,BT_HCI_EVT_CMD_STATUS响应*/
static void process_response(struct bt_hci *hci, uint16_t opcode/*完成的opcode*/,
					const void *data/*完成的OPCODE对应的响应参数*/, size_t size/*响应参数长度*/)
{
	struct cmd *cmd;

	if (opcode == BT_HCI_CMD_NOP) {
		/*空响应,用于通知可继续发送,唤醒writer,继续发送*/
		wakeup_writer(hci);
		return;
	}

	/*自等待响应的queue中取出对应的请求*/
	cmd = queue_remove_if(hci->rsp_queue, match_cmd_opcode,
						UINT_TO_PTR(opcode));
	if (!cmd)
		return;/*没有此命令,忽略*/

	/* Take a reference before calling the callback since that can unref
	 * its reference destroying the instance.
	 */
	bt_hci_ref(hci);

	/*触发回调*/
	if (cmd->callback)
		cmd->callback(data, size, cmd->user_data);

	cmd_free(cmd);

	/*唤醒writer*/
	wakeup_writer(hci);

	bt_hci_unref(hci);
}

static void process_notify(void *data, void *user_data)
{
	struct bt_hci_evt_hdr *hdr = user_data;
	struct evt *evt = data;

	if (evt->event == hdr->evt)
		/*此event已被关注，触发event回调*/
		evt->callback(user_data + sizeof(struct bt_hci_evt_hdr),
						hdr->plen, evt->user_data);
}

/*hci处理收到的event*/
static void process_event(struct bt_hci *hci, const void *data/*收到的event*/, size_t size/*event消息长度*/)
{
	const struct bt_hci_evt_hdr *hdr = data;
	const struct bt_hci_evt_cmd_complete *cc;
	const struct bt_hci_evt_cmd_status *cs;

	if (size < sizeof(struct bt_hci_evt_hdr))
		return;

	data += sizeof(struct bt_hci_evt_hdr);/*跳到参数头部*/
	size -= sizeof(struct bt_hci_evt_hdr);

	if (hdr->plen != size)
		return;/*参数长度与实际长度不一致*/

	switch (hdr->evt) {
	case BT_HCI_EVT_CMD_COMPLETE:
		if (size < sizeof(*cc))
			return;
		/*遇到cmd执行完成事件*/
		cc = data;
		hci->num_cmds = cc->ncmd;/*这个参数用于指示控制器可以向hci发送多少个command*/
		process_response(hci, le16_to_cpu(cc->opcode)/*执行完成的cmd opcode*/,
						data + sizeof(*cc)/*COMPLETE响应参数*/,
						size - sizeof(*cc)/*响应参数长度*/);
		break;

	case BT_HCI_EVT_CMD_STATUS:
		if (size < sizeof(*cs))
			return;
		/*遇到cmd执行状态响应事件*/
		cs = data;
		hci->num_cmds = cs->ncmd;
		process_response(hci, le16_to_cpu(cs->opcode), &cs->status/*响应的为状态*/, 1);
		break;

	default:
		/*其它事件,查找关注此event的回调，处理此event*/
		queue_foreach(hci->evt_list, process_notify, (void *) hdr);
		break;
	}
}

/*用于处理hci发送上来的event*/
static bool io_read_callback(struct io *io, void *user_data)
{
	struct bt_hci *hci = user_data;
	uint8_t buf[512];
	ssize_t len;
	int fd;

	fd = io_get_fd(hci->io);
	if (fd < 0)
		return false;

	if (hci->is_stream)
		return false;/*只考虑stream类型*/

	/*读取buffer*/
	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return false;

	if (len < 1)
		return true;

	switch (buf[0]) {
	case BT_H4_EVT_PKT:
		/*必须是event报文类型*/
		process_event(hci, buf + 1/*跳过报文类型,指向event*/, len - 1);
		break;
	}

	return true;
}

/*创建bt_hci*/
static struct bt_hci *create_hci(int fd)
{
	struct bt_hci *hci;

	if (fd < 0)
		return NULL;

	hci = new0(struct bt_hci, 1);
	hci->io = io_new(fd);
	if (!hci->io) {
		free(hci);
		return NULL;
	}

	hci->is_stream = true;/*为stream类型*/
	hci->writer_active = false;
	hci->num_cmds = 1;
	hci->next_cmd_id = 1;
	hci->next_evt_id = 1;

	hci->cmd_queue = queue_new();
	hci->rsp_queue = queue_new();
	hci->evt_list = queue_new();
	hci->data_queue = queue_new();

	/*设置HCI设备的读回调*/
	if (!io_set_read_handler(hci->io, io_read_callback, hci, NULL)) {
		queue_destroy(hci->evt_list, NULL);
		queue_destroy(hci->rsp_queue, NULL);
		queue_destroy(hci->cmd_queue, NULL);
		queue_destroy(hci->data_queue, NULL);
		io_destroy(hci->io);
		free(hci);
		return NULL;
	}

	return bt_hci_ref(hci);
}

struct bt_hci *bt_hci_new(int fd)
{
	struct bt_hci *hci;

	hci = create_hci(fd);
	if (!hci)
		return NULL;

	return hci;
}

/*创建hci socket*/
static int create_socket(uint16_t index, uint16_t channel)
{
	struct sockaddr_hci addr;
	int fd;

	fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
								BTPROTO_HCI);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = index;
	addr.hci_channel = channel;

	/*绑定,关注设备及channel*/
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

struct bt_hci *bt_hci_new_user_channel(uint16_t index)
{
	struct bt_hci *hci;
	int fd;

	fd = create_socket(index, HCI_CHANNEL_USER);
	if (fd < 0) {
		printf("Unable to create user channel socket: %s(%d)\n",
			strerror(errno), -errno);
		return NULL;
	}

	hci = create_hci(fd);
	if (!hci) {
		close(fd);
		return NULL;
	}

	hci->is_stream = false;

	bt_hci_set_close_on_unref(hci, true);

	return hci;
}

struct bt_hci *bt_hci_new_raw_device(uint16_t index)
{
	struct bt_hci *hci;
	struct hci_filter flt;
	int fd;

	fd = create_socket(index, HCI_CHANNEL_RAW);
	if (fd < 0)
		return NULL;

	memset(&flt, 0, sizeof(flt));
	flt.type_mask = 1 << BT_H4_EVT_PKT;
	flt.event_mask[0] = 0xffffffff;
	flt.event_mask[1] = 0xffffffff;

	if (setsockopt(fd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		close(fd);
		return NULL;
	}

	hci = create_hci(fd);
	if (!hci) {
		close(fd);
		return NULL;
	}

	hci->is_stream = false;

	bt_hci_set_close_on_unref(hci, true);

	return hci;
}

struct bt_hci *bt_hci_ref(struct bt_hci *hci)
{
	if (!hci)
		return NULL;

	__sync_fetch_and_add(&hci->ref_count, 1);

	return hci;
}

void bt_hci_unref(struct bt_hci *hci)
{
	if (!hci)
		return;

	if (__sync_sub_and_fetch(&hci->ref_count, 1))
		return;

	queue_destroy(hci->evt_list, evt_free);
	queue_destroy(hci->cmd_queue, cmd_free);
	queue_destroy(hci->rsp_queue, cmd_free);
	queue_destroy(hci->data_queue, data_free);

	io_destroy(hci->io);

	free(hci);
}

bool bt_hci_set_close_on_unref(struct bt_hci *hci, bool do_close)
{
	if (!hci)
		return false;

	return io_set_close_on_destroy(hci->io, do_close);
}

/*向HCI设备发送命令*/
unsigned int bt_hci_send(struct bt_hci *hci, uint16_t opcode/*操作码*/,
				const void *data/*参数*/, uint8_t size/*参数长度*/,
				bt_hci_callback_func_t callback/*命令响应后回调处理*/,
				void *user_data, bt_hci_destroy_func_t destroy)
{
	struct cmd *cmd;

	if (!hci)
		return 0;

	cmd = new0(struct cmd, 1);
	cmd->opcode = opcode;
	cmd->size = size;

	if (cmd->size > 0) {
		cmd->data = malloc(cmd->size);
		if (!cmd->data) {
			free(cmd);
			return 0;
		}

		memcpy(cmd->data, data, cmd->size);/*写命令参数*/
	}

	if (hci->next_cmd_id < 1)
		hci->next_cmd_id = 1;/*初始化cmd_id*/

	cmd->id = hci->next_cmd_id++;/*分配编号*/

	cmd->callback = callback;/*设置此命令响应后需执行的回调*/
	cmd->destroy = destroy;/*设置此cMd结构体被 释放时需要执行的回调*/
	cmd->user_data = user_data;

	/*cmd入队*/
	if (!queue_push_tail(hci->cmd_queue, cmd)) {
		free(cmd->data);
		free(cmd);
		return 0;
	}

	/*唤醒WRITER,发送cmd*/
	wakeup_writer(hci);

	return cmd->id;
}

static bool match_cmd_id(const void *a, const void *b)
{
	const struct cmd *cmd = a;
	unsigned int id = PTR_TO_UINT(b);

	return cmd->id == id;
}

bool bt_hci_cancel(struct bt_hci *hci, unsigned int id)
{
	struct cmd *cmd;

	if (!hci || !id)
		return false;

	cmd = queue_remove_if(hci->cmd_queue, match_cmd_id, UINT_TO_PTR(id));
	if (!cmd) {
		cmd = queue_remove_if(hci->rsp_queue, match_cmd_id,
							UINT_TO_PTR(id));
		if (!cmd)
			return false;
	}

	cmd_free(cmd);

	wakeup_writer(hci);

	return true;
}

bool bt_hci_flush(struct bt_hci *hci)
{
	if (!hci)
		return false;

	if (hci->writer_active) {
		io_set_write_handler(hci->io, NULL, NULL, NULL);
		hci->writer_active = false;
	}

	queue_remove_all(hci->cmd_queue, NULL, NULL, cmd_free);
	queue_remove_all(hci->rsp_queue, NULL, NULL, cmd_free);
	queue_remove_all(hci->data_queue, NULL, NULL, data_free);

	return true;
}

unsigned int bt_hci_register(struct bt_hci *hci, uint8_t event,
				bt_hci_callback_func_t callback,
				void *user_data, bt_hci_destroy_func_t destroy)
{
	struct evt *evt;

	if (!hci)
		return 0;

	evt = new0(struct evt, 1);
	evt->event = event;

	if (hci->next_evt_id < 1)
		hci->next_evt_id = 1;

	evt->id = hci->next_evt_id++;

	evt->callback = callback;
	evt->destroy = destroy;
	evt->user_data = user_data;

	/*注册hci event*/
	if (!queue_push_tail(hci->evt_list, evt)) {
		free(evt);
		return 0;
	}

	return evt->id;
}

bool bt_hci_send_data(struct bt_hci *hci, uint8_t type/*数据报文 类型,例如acl pkt*/, uint16_t handle/*连接handLe*/,
				const void *data/*数据*/, uint8_t size/*数据长度*/)
{
	struct data *d;

	if (!hci)
		return false;

	/* Check if type really reflects to a data packet */
	switch (type) {
	case BT_H4_ACL_PKT:
	case BT_H4_SCO_PKT:
	case BT_H4_ISO_PKT:
		break;
	default:
		return false;/*非以上数据类型*/
	}

	d = new0(struct data, 1);
	d->type = type;
	d->handle = handle;/*连接handle*/
	d->size = size;/*数据长度*/

	if (d->size > 0) {
		/*复制数据*/
		d->data = util_memdup(data, d->size);
		if (!d->data) {
			free(d);
			return false;
		}
	}

	/*向data queue存入*/
	if (!queue_push_tail(hci->data_queue, d)) {
		free(d->data);
		free(d);
		return false;
	}

	wakeup_writer(hci);

	return true;
}

static bool match_evt_id(const void *a, const void *b)
{
	const struct evt *evt = a;
	unsigned int id = PTR_TO_UINT(b);

	return evt->id == id;
}

bool bt_hci_unregister(struct bt_hci *hci, unsigned int id)
{
	struct evt *evt;

	if (!hci || !id)
		return false;

	evt = queue_remove_if(hci->evt_list, match_evt_id, UINT_TO_PTR(id));
	if (!evt)
		return false;

	evt_free(evt);

	return true;
}
