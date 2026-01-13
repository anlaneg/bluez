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

#include "src/shared/util.h"
#include "src/shared/queue.h"

struct queue {
	int ref_count;
	struct queue_entry *head;/*队首*/
	struct queue_entry *tail;/*队尾*/
	unsigned int entries;/*队列长度*/
};

static struct queue *queue_ref(struct queue *queue)
{
	if (!queue)
		return NULL;

	__sync_fetch_and_add(&queue->ref_count, 1);

	return queue;
}

static void queue_unref(struct queue *queue)
{
	if (__sync_sub_and_fetch(&queue->ref_count, 1))
		return;

	free(queue);
}

/*初始化队列*/
struct queue *queue_new(void)
{
	struct queue *queue;

	queue = new0(struct queue, 1);
	queue->head = NULL;
	queue->tail = NULL;
	queue->entries = 0;

	return queue_ref(queue);
}

void queue_destroy(struct queue *queue, queue_destroy_func_t destroy)
{
	if (!queue)
		return;

	/*清空此queue*/
	queue_remove_all(queue, NULL, NULL, destroy);

	queue_unref(queue);
}

/*利用data创建queue_entry*/
static struct queue_entry *queue_entry_new(void *data)
{
	struct queue_entry *entry;

	entry = new0(struct queue_entry, 1);
	entry->data = data;

	return entry;
}

/*利用data创建queue_entry,并将其置于队尾*/
bool queue_push_tail(struct queue *queue, void *data)
{
	struct queue_entry *entry;

	if (!queue)
		return false;

	entry = queue_entry_new(data);

	if (queue->tail)
		queue->tail->next = entry;/*存在队尾*/

	queue->tail = entry;/*更新tail指向队尾*/

	if (!queue->head)
		queue->head = entry;/*之前没有设置head，为首个,更新head*/

	queue->entries++;/*队列长度增加*/

	return true;
}

bool queue_push_head(struct queue *queue, void *data)
{
	struct queue_entry *entry;

	if (!queue)
		return false;

	entry = queue_entry_new(data);

	entry->next = queue->head;

	queue->head = entry;

	if (!queue->tail)
		queue->tail = entry;

	queue->entries++;

	return true;
}

/*创建新的queue_entry并将其加入到queue中，且使其位于entry之后*/
bool queue_push_after(struct queue *queue, void *entry, void *data)
{
	struct queue_entry *qentry, *tmp, *new_entry;

	qentry = NULL;

	if (!queue)
		return false;

	for (tmp = queue->head; tmp; tmp = tmp->next) {
		if (tmp->data == entry) {
			qentry = tmp;
			break;
		}
	}

	if (!qentry)
		return false;/*队列中未找到entry*/

	new_entry = queue_entry_new(data);

	new_entry->next = qentry->next;

	if (!qentry->next)
		/*qentry原来为最后一个，现在不是了，需要更新为new_entry*/
		queue->tail = new_entry;

	qentry->next = new_entry;
	queue->entries++;

	return true;
}

/*自队列中弹出一个entry*/
void *queue_pop_head(struct queue *queue)
{
	struct queue_entry *entry;
	void *data;

	if (!queue || !queue->head)
		return NULL;

	entry = queue->head;/*取首个元素*/

	if (!queue->head->next) {
		/*取完后,队列为空*/
		queue->head = NULL;
		queue->tail = NULL;
	} else
		queue->head = queue->head->next;/*取完后,队列不为空,更新head*/

	/*返回队列内容*/
	data = entry->data;

	free(entry);
	queue->entries--;/*元素数减1*/

	return data;
}

void *queue_peek_head(struct queue *queue)
{
	if (!queue || !queue->head)
		return NULL;

	return queue->head->data;
}

void *queue_peek_tail(struct queue *queue)
{
	if (!queue || !queue->tail)
		return NULL;

	return queue->tail->data;
}

/*遍历queue上所有元素，执行function*/
void queue_foreach(struct queue *queue/*要检查的队列*/, queue_foreach_func_t function/*要触发的回调*/,
							void *user_data/*回调第二个参数*/)
{
	struct queue_entry *entry;

	if (!queue || !function)
		return;/*参数有误*/

	entry = queue->head;
	if (!entry)
		return;/*队列为空*/

	queue_ref(queue);
	/*针对所有元素，执行function*/
	while (entry && queue->head && queue->ref_count > 1) {
		struct queue_entry *next;

		next = entry->next;
		function(entry->data, user_data);
		entry = next;
	}
	queue_unref(queue);
}

/*指针地址比对*/
static bool direct_match(const void *a, const void *b)
{
	return a == b;
}

/*利用function遍历queue中每个元素，一旦命中，返回entry->data*/
void *queue_find(struct queue *queue, queue_match_func_t function,
							const void *match_data)
{
	struct queue_entry *entry;

	if (!queue)
		/*队列为空，直接返回*/
		return NULL;

	if (!function)
		/*未指供函数，使用默认匹配函数*/
		function = direct_match;

	/*遍历queue,并逐个调用function,传入参数*/
	for (entry = queue->head; entry; entry = entry->next)
		if (function(entry->data, match_data))
			return entry->data;

	return NULL;
}

bool queue_remove(struct queue *queue, void *data)
{
	struct queue_entry *entry, *prev;

	if (!queue)
		return false;

	for (entry = queue->head, prev = NULL; entry;
					prev = entry, entry = entry->next) {
		if (entry->data != data)
			continue;

		if (prev)
			prev->next = entry->next;
		else
			queue->head = entry->next;

		if (!entry->next)
			queue->tail = prev;

		free(entry);
		queue->entries--;

		return true;
	}

	return false;
}

/*此队列上有多个queue_entry,通过function比对匹配的entry,并将其移除*/
void *queue_remove_if(struct queue *queue, queue_match_func_t function,
							void *user_data)
{
	struct queue_entry *entry, *prev = NULL;

	if (!queue)
		return NULL;

	if (!function)
		function = direct_match;

	entry = queue->head;

	while (entry) {
		if (function(entry->data, user_data)) {
			/*entry匹配成功,移除此请求*/
			void *data;

			if (prev)
				prev->next = entry->next;
			else
				queue->head = entry->next;

			if (!entry->next)
				queue->tail = prev;

			data = entry->data;

			free(entry);
			queue->entries--;

			return data;/*返回节点数据*/
		} else {
			/*未匹配，尝试下一个entry*/
			prev = entry;
			entry = entry->next;
		}
	}

	return NULL;
}

unsigned int queue_remove_all(struct queue *queue, queue_match_func_t function,
				void *user_data, queue_destroy_func_t destroy/*销毁函数*/)
{
	struct queue_entry *entry;
	unsigned int count = 0;

	if (!queue)
		return 0;

	entry = queue->head;/*遍历queue*/

	if (function) {
		while (entry) {
			void *data;
			unsigned int entries = queue->entries;

			/*按function移除指定元素，返回对应的data并释放*/
			data = queue_remove_if(queue, function, user_data);
			if (entries == queue->entries)
				break;

			if (destroy)
				destroy(data);/*释放节点数据*/

			count++;
		}
	} else {
		/*未提供function,队列初始化为空，释放队列中所有元素*/
		queue->head = NULL;
		queue->tail = NULL;
		queue->entries = 0;

		while (entry) {
			struct queue_entry *tmp = entry;

			entry = entry->next;

			if (destroy)
				destroy(tmp->data);

			free(tmp);
			count++;
		}
	}

	return count;/*返回释放数*/
}

/*返回队首*/
const struct queue_entry *queue_get_entries(struct queue *queue)
{
	if (!queue)
		return NULL;

	return queue->head;
}

unsigned int queue_length(struct queue *queue)
{
	if (!queue)
		return 0;

	return queue->entries;
}

bool queue_isempty(struct queue *queue)
{
	if (!queue)
		return true;

	return queue->entries == 0;/*队列是否为空*/
}
