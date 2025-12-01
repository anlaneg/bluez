// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  D-Bus helper library
 *
 *  Copyright (C) 2004-2011  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "gdbus.h"

/* define MAX_INPUT for musl */
#ifndef MAX_INPUT
#define MAX_INPUT _POSIX_MAX_INPUT
#endif

#include "src/shared/util.h"

#define info(fmt...)
#define error(fmt...)
#define debug(fmt...)

#define DBUS_INTERFACE_OBJECT_MANAGER "org.freedesktop.DBus.ObjectManager"

#ifndef DBUS_ERROR_UNKNOWN_PROPERTY
#define DBUS_ERROR_UNKNOWN_PROPERTY "org.freedesktop.DBus.Error.UnknownProperty"
#endif

#ifndef DBUS_ERROR_PROPERTY_READ_ONLY
#define DBUS_ERROR_PROPERTY_READ_ONLY "org.freedesktop.DBus.Error.PropertyReadOnly"
#endif

struct generic_data {
	unsigned int refcount;
	DBusConnection *conn;
	char *path;
	GSList *interfaces;/*记录注册的所有接口*/
	GSList *objects;
	GSList *added;
	GSList *removed;
	guint process_id;
	gboolean pending_prop;
	char *introspect;
	struct generic_data *parent;
};

/*D-Bus 接口（Interface）的核心作用就是 “定义一组相关的方法（Method）、信号（Signal）和属性（Property）”
 * 接口是 D-Bus 服务端与客户端的 “功能契约”，其中 “方法” 是客户端主动调用的核心功能，
 * 通常会围绕一个业务模块（如蓝牙设备、网络接口）组织一组相关方法，形成完整的功能集合。
 *
 * 简单说：一个 D-Bus 接口 ≈ 一个 “API 集合”，方法是这个集合中最核心的 “可调用功能”，
 * 与信号、属性配合实现完整的交互逻辑。*/
struct interface_data {
	char *name;/*接口名称*/
	/*客户端主动调用，服务端执行并返回结果*/
	const GDBusMethodTable *methods;/*对应的一组方法*/
	/*服务端主动推送，通知客户端状态变化*/
	const GDBusSignalTable *signals;
	/*属性,接口的状态数据.
	 * 客户端通过 Properties.Get 读取、Properties.Set 修改*/
	const GDBusPropertyTable *properties;
	GSList *pending_prop;
	void *user_data;
	GDBusDestroyFunction destroy;
};

struct security_data {
	GDBusPendingReply pending;
	DBusMessage *message;
	const GDBusMethodTable *method;
	void *iface_user_data;
};

struct property_data {
	DBusConnection *conn;
	GDBusPendingPropertySet id;
	DBusMessage *message;
};

struct debug_data {
	g_dbus_debug_func_t func;
	g_dbus_destroy_func_t destroy;
	void *data;
};

static int global_flags = 0;
static struct generic_data *root;
static GSList *pending = NULL;
static struct debug_data debug = { NULL, NULL, NULL };

static gboolean process_changes(gpointer user_data);
static void process_properties_from_interface(struct generic_data *data,
						struct interface_data *iface);
static void process_property_changes(struct generic_data *data);

static void print_arguments(GString *gstr, const GDBusArgInfo *args,
						const char *direction)
{
	for (; args && args->name; args++) {
		g_string_append_printf(gstr,
					"<arg name=\"%s\" type=\"%s\"",
					args->name, args->signature);

		if (direction)
			g_string_append_printf(gstr,
					" direction=\"%s\"/>\n", direction);
		else
			g_string_append_printf(gstr, "/>\n");

	}
}

#define G_DBUS_ANNOTATE(name_, value_)				\
	"<annotation name=\"org.freedesktop.DBus." name_ "\" "	\
	"value=\"" value_ "\"/>"

#define G_DBUS_ANNOTATE_DEPRECATED \
	G_DBUS_ANNOTATE("Deprecated", "true")

#define G_DBUS_ANNOTATE_NOREPLY \
	G_DBUS_ANNOTATE("Method.NoReply", "true")

static gboolean check_experimental(int flags, int flag)
{
	if (!(flags & flag))
		return FALSE;

	/*是否开启实验用功能*/
	return !(global_flags & G_DBUS_FLAG_ENABLE_EXPERIMENTAL);
}

static bool check_testing(int flags, int flag)
{
	if (!(flags & flag))
		return false;

	/*是否开启测试用功能*/
	return !(global_flags & G_DBUS_FLAG_ENABLE_TESTING);
}

static void g_dbus_debug(const char *format, ...)
{
	va_list va;
	char str[MAX_INPUT];

	if (!format || !debug.func)
		return;

	va_start(va, format);
	vsnprintf(str, sizeof(str), format, va);
	debug.func(str, debug.data);
	va_end(va);
}

static void generate_interface_xml(GString *gstr, struct interface_data *iface)
{
	const GDBusMethodTable *method;
	const GDBusSignalTable *signal;
	const GDBusPropertyTable *property;

	for (method = iface->methods; method && method->name; method++) {
		if (check_experimental(method->flags,
					G_DBUS_METHOD_FLAG_EXPERIMENTAL))
			continue;

		if (check_testing(method->flags, G_DBUS_METHOD_FLAG_TESTING))
			continue;

		g_string_append_printf(gstr, "<method name=\"%s\">",
								method->name);
		print_arguments(gstr, method->in_args, "in");
		print_arguments(gstr, method->out_args, "out");

		if (method->flags & G_DBUS_METHOD_FLAG_DEPRECATED)
			g_string_append_printf(gstr,
						G_DBUS_ANNOTATE_DEPRECATED);

		if (method->flags & G_DBUS_METHOD_FLAG_NOREPLY)
			g_string_append_printf(gstr, G_DBUS_ANNOTATE_NOREPLY);

		g_string_append_printf(gstr, "</method>");
	}

	for (signal = iface->signals; signal && signal->name; signal++) {
		if (check_experimental(signal->flags,
					G_DBUS_SIGNAL_FLAG_EXPERIMENTAL))
			continue;

		if (check_testing(signal->flags, G_DBUS_SIGNAL_FLAG_TESTING))
			continue;

		g_string_append_printf(gstr, "<signal name=\"%s\">",
								signal->name);
		print_arguments(gstr, signal->args, NULL);

		if (signal->flags & G_DBUS_SIGNAL_FLAG_DEPRECATED)
			g_string_append_printf(gstr,
						G_DBUS_ANNOTATE_DEPRECATED);

		g_string_append_printf(gstr, "</signal>\n");
	}

	for (property = iface->properties; property && property->name;
								property++) {
		if (check_experimental(property->flags,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL))
			continue;

		if (check_testing(property->flags,
					G_DBUS_PROPERTY_FLAG_TESTING))
			continue;

		g_string_append_printf(gstr, "<property name=\"%s\""
					" type=\"%s\" access=\"%s%s\">",
					property->name,	property->type,
					property->get ? "read" : "",
					property->set ? "write" : "");

		if (property->flags & G_DBUS_PROPERTY_FLAG_DEPRECATED)
			g_string_append_printf(gstr,
						G_DBUS_ANNOTATE_DEPRECATED);

		g_string_append_printf(gstr, "</property>");
	}
}

static void generate_introspection_xml(DBusConnection *conn,
				struct generic_data *data, const char *path)
{
	GSList *list;
	GString *gstr;
	char **children;
	int i;

	g_free(data->introspect);

	gstr = g_string_new(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE);

	g_string_append_printf(gstr, "<node>");

	for (list = data->interfaces; list; list = list->next) {
		struct interface_data *iface = list->data;

		g_string_append_printf(gstr, "<interface name=\"%s\">",
								iface->name);

		generate_interface_xml(gstr, iface);

		g_string_append_printf(gstr, "</interface>");
	}

	if (!dbus_connection_list_registered(conn, path, &children))
		goto done;

	for (i = 0; children[i]; i++)
		g_string_append_printf(gstr, "<node name=\"%s\"/>",
								children[i]);

	dbus_free_string_array(children);

done:
	g_string_append_printf(gstr, "</node>");

	data->introspect = g_string_free(gstr, FALSE);
}

static DBusMessage *introspect(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	DBusMessage *reply;

	if (data->introspect == NULL)
		generate_introspection_xml(connection, data,
						dbus_message_get_path(message));

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &data->introspect,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusHandlerResult process_message(DBusConnection *connection,
			DBusMessage *message, const GDBusMethodTable *method,
							void *iface_user_data)
{
	DBusMessage *reply;

	/*触发方法*/
	reply = method->function(connection, message, iface_user_data);

	if (method->flags & G_DBUS_METHOD_FLAG_NOREPLY ||
					dbus_message_get_no_reply(message)) {
		if (reply != NULL)
			dbus_message_unref(reply);/*不响应消息*/
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (method->flags & G_DBUS_METHOD_FLAG_ASYNC) {
		if (reply == NULL)
			return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (reply == NULL)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/*发送响应*/
	g_dbus_send_message(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static GDBusPendingReply next_pending = 1;
static GSList *pending_security = NULL;

static const GDBusSecurityTable *security_table = NULL;

void g_dbus_pending_success(DBusConnection *connection,
					GDBusPendingReply pending)
{
	GSList *list;

	for (list = pending_security; list; list = list->next) {
		struct security_data *secdata = list->data;

		if (secdata->pending != pending)
			continue;

		pending_security = g_slist_remove(pending_security, secdata);

		process_message(connection, secdata->message,
				secdata->method, secdata->iface_user_data);

		dbus_message_unref(secdata->message);
		g_free(secdata);
		return;
	}
}

void g_dbus_pending_error_valist(DBusConnection *connection,
				GDBusPendingReply pending, const char *name,
					const char *format, va_list args)
{
	GSList *list;

	for (list = pending_security; list; list = list->next) {
		struct security_data *secdata = list->data;

		if (secdata->pending != pending)
			continue;

		pending_security = g_slist_remove(pending_security, secdata);

		g_dbus_send_error_valist(connection, secdata->message,
							name, format, args);

		dbus_message_unref(secdata->message);
		g_free(secdata);
		return;
	}
}

void g_dbus_pending_error(DBusConnection *connection,
				GDBusPendingReply pending,
				const char *name, const char *format, ...)
{
	va_list args;

	va_start(args, format);

	g_dbus_pending_error_valist(connection, pending, name, format, args);

	va_end(args);
}

int polkit_check_authorization(DBusConnection *conn,
				const char *action, gboolean interaction,
				void (*function) (dbus_bool_t authorized,
							void *user_data),
						void *user_data, int timeout);

struct builtin_security_data {
	DBusConnection *conn;
	GDBusPendingReply pending;
};

static void builtin_security_result(dbus_bool_t authorized, void *user_data)
{
	struct builtin_security_data *data = user_data;

	if (authorized == TRUE)
		g_dbus_pending_success(data->conn, data->pending);
	else
		g_dbus_pending_error(data->conn, data->pending,
						DBUS_ERROR_AUTH_FAILED, NULL);

	g_free(data);
}

static void builtin_security_function(DBusConnection *conn,
						const char *action,
						gboolean interaction,
						GDBusPendingReply pending)
{
	struct builtin_security_data *data;

	data = g_new0(struct builtin_security_data, 1);
	data->conn = conn;
	data->pending = pending;

	if (polkit_check_authorization(conn, action, interaction,
				builtin_security_result, data, 30000) < 0)
		g_dbus_pending_error(conn, pending, NULL, NULL);
}

static gboolean check_privilege(DBusConnection *conn, DBusMessage *msg,
			const GDBusMethodTable *method, void *iface_user_data)
{
	const GDBusSecurityTable *security;

	for (security = security_table; security && security->privilege;
								security++) {
		struct security_data *secdata;
		gboolean interaction;

		if (security->privilege != method->privilege)
			continue;

		secdata = g_new(struct security_data, 1);
		secdata->pending = next_pending++;
		secdata->message = dbus_message_ref(msg);
		secdata->method = method;
		secdata->iface_user_data = iface_user_data;

		pending_security = g_slist_prepend(pending_security, secdata);

		if (security->flags & G_DBUS_SECURITY_FLAG_ALLOW_INTERACTION)
			interaction = TRUE;
		else
			interaction = FALSE;

		if (!(security->flags & G_DBUS_SECURITY_FLAG_BUILTIN) &&
							security->function)
			security->function(conn, security->action,
						interaction, secdata->pending);
		else
			builtin_security_function(conn, security->action,
						interaction, secdata->pending);

		return TRUE;
	}

	return FALSE;
}

static GDBusPendingPropertySet next_pending_property = 1;
static GSList *pending_property_set;

static int pending_property_data_compare_id(const void *data,
						const void *user_data)
{
	const struct property_data *propdata = data;
	const GDBusPendingPropertySet *id = user_data;
	return propdata->id - *id;
}

static struct property_data *remove_pending_property_data(
						GDBusPendingPropertySet id)
{
	struct property_data *propdata;
	GSList *l;

	l = g_slist_find_custom(pending_property_set, &id,
				pending_property_data_compare_id);
	if (l == NULL)
		return NULL;

	propdata = l->data;
	pending_property_set = g_slist_delete_link(pending_property_set, l);

	return propdata;
}

const char *g_dbus_pending_property_get_sender(GDBusPendingPropertySet id)
{
	struct property_data *propdata;
	GSList *l;

	l = g_slist_find_custom(pending_property_set, &id,
					pending_property_data_compare_id);
	if (l == NULL)
		return NULL;

	propdata = l->data;
	return dbus_message_get_sender(propdata->message);
}

void g_dbus_pending_property_success(GDBusPendingPropertySet id)
{
	struct property_data *propdata;

	propdata = remove_pending_property_data(id);
	if (propdata == NULL)
		return;

	g_dbus_send_reply(propdata->conn, propdata->message,
							DBUS_TYPE_INVALID);
	dbus_message_unref(propdata->message);
	g_free(propdata);
}

void g_dbus_pending_property_error_valist(GDBusPendingReply id,
					const char *name, const char *format,
					va_list args)
{
	struct property_data *propdata;

	propdata = remove_pending_property_data(id);
	if (propdata == NULL)
		return;

	g_dbus_send_error_valist(propdata->conn, propdata->message, name,
								format, args);

	dbus_message_unref(propdata->message);
	g_free(propdata);
}

void g_dbus_pending_property_error(GDBusPendingReply id, const char *name,
						const char *format, ...)
{
	va_list args;

	va_start(args, format);

	g_dbus_pending_property_error_valist(id, name, format, args);

	va_end(args);
}

static void reset_parent(gpointer data, gpointer user_data)
{
	struct generic_data *child = data;
	struct generic_data *parent = user_data;

	child->parent = parent;
}

static void append_property(struct interface_data *iface,
			const GDBusPropertyTable *p, DBusMessageIter *dict)
{
	DBusMessageIter entry, value;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &p->name);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, p->type,
								&value);

	p->get(p, &value, iface->user_data);

	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(dict, &entry);
}

static void append_properties(struct interface_data *data,
							DBusMessageIter *iter)
{
	DBusMessageIter dict;
	const GDBusPropertyTable *p;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	for (p = data->properties; p && p->name; p++) {
		if (check_experimental(p->flags,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL))
			continue;

		if (check_testing(p->flags, G_DBUS_PROPERTY_FLAG_TESTING))
			continue;

		if (p->get == NULL)
			continue;

		if (p->exists != NULL && !p->exists(p, data->user_data))
			continue;

		append_property(data, p, &dict);
	}

	dbus_message_iter_close_container(iter, &dict);
}

static void append_interface(gpointer data, gpointer user_data)
{
	struct interface_data *iface = data;
	DBusMessageIter *array = user_data;
	DBusMessageIter entry;

	dbus_message_iter_open_container(array, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &iface->name);
	append_properties(data, &entry);
	dbus_message_iter_close_container(array, &entry);
}

static const char *dbus_message_type_string(DBusMessage *msg)
{
	return dbus_message_type_to_string(dbus_message_get_type(msg));
}

static void g_dbus_send_unref(DBusConnection *conn, DBusMessage *msg)
{
	g_dbus_debug("[%s] %s.%s",
			dbus_message_type_string(msg),
			dbus_message_get_interface(msg),
			dbus_message_get_member(msg));

	dbus_connection_send(conn, msg, NULL);
	dbus_message_unref(msg);
}

static void emit_interfaces_added(struct generic_data *data)
{
	DBusMessage *signal;
	DBusMessageIter iter, array;

	if (root == NULL || data == root)
		return;

	/* Emit InterfacesAdded on the parent first so it appears first on the
	 * bus as child objects may point to it.
	 */
	if (data->parent && data->parent->added)
		emit_interfaces_added(data->parent);

	signal = dbus_message_new_signal(root->path,
					DBUS_INTERFACE_OBJECT_MANAGER,
					"InterfacesAdded");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
								&data->path);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_ARRAY_AS_STRING
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &array);

	g_slist_foreach(data->added, append_interface, &array);
	g_slist_free(data->added);
	data->added = NULL;

	dbus_message_iter_close_container(&iter, &array);

	/* Use g_dbus_send_unref to avoid recursive calls to g_dbus_flush */
	g_dbus_send_unref(data->conn, signal);
}

/*遍历interfaces列表,检查名称匹配的interface_data*/
static struct interface_data *find_interface(GSList *interfaces,
						const char *name)
{
	GSList *list;

	if (name == NULL)
		return NULL;

	for (list = interfaces; list; list = list->next) {
		struct interface_data *iface = list->data;
		if (!strcmp(name, iface->name))
			return iface;
	}

	return NULL;
}

static gboolean g_dbus_args_have_signature(const GDBusArgInfo *args,
							DBusMessage *message)
{
	const char *sig = dbus_message_get_signature(message);
	const char *p = NULL;

	for (; args && args->signature && *sig; args++) {
		p = args->signature;

		for (; *sig && *p; sig++, p++) {
			if (*p != *sig)
				return FALSE;
		}
	}

	if (*sig || (p && *p) || (args && args->signature))
		return FALSE;

	return TRUE;
}

static void add_pending(struct generic_data *data)
{
	guint old_id = data->process_id;

	data->process_id = g_idle_add(process_changes, data);

	if (old_id > 0) {
		/*
		 * If the element already had an old idler, remove the old one,
		 * no need to re-add it to the pending list.
		 */
		g_source_remove(old_id);
		return;
	}

	pending = g_slist_append(pending, data);
}

static gboolean remove_interface(struct generic_data *data, const char *name)
{
	struct interface_data *iface;

	iface = find_interface(data->interfaces, name);
	if (iface == NULL)
		return FALSE;

	process_properties_from_interface(data, iface);

	data->interfaces = g_slist_remove(data->interfaces, iface);

	if (iface->destroy) {
		iface->destroy(iface->user_data);
		iface->user_data = NULL;
	}

	/*
	 * Interface being removed was just added, on the same mainloop
	 * iteration? Don't send any signal
	 */
	if (g_slist_find(data->added, iface)) {
		data->added = g_slist_remove(data->added, iface);
		g_free(iface->name);
		g_free(iface);
		return TRUE;
	}

	if (data->parent == NULL) {
		g_free(iface->name);
		g_free(iface);
		return TRUE;
	}

	data->removed = g_slist_prepend(data->removed, iface->name);
	g_free(iface);

	add_pending(data);

	return TRUE;
}

static struct generic_data *invalidate_parent_data(DBusConnection *conn,
						const char *child_path)
{
	struct generic_data *data = NULL, *child = NULL, *parent = NULL;
	char *parent_path, *slash;

	parent_path = g_strdup(child_path);
	slash = strrchr(parent_path, '/');
	if (slash == NULL)
		goto done;

	if (slash == parent_path && parent_path[1] != '\0')
		parent_path[1] = '\0';
	else
		*slash = '\0';

	if (!strlen(parent_path))
		goto done;

	if (dbus_connection_get_object_path_data(conn, parent_path,
							(void *) &data) == FALSE) {
		goto done;
	}

	parent = invalidate_parent_data(conn, parent_path);

	if (data == NULL) {
		data = parent;
		if (data == NULL)
			goto done;
	}

	g_free(data->introspect);
	data->introspect = NULL;

	if (!dbus_connection_get_object_path_data(conn, child_path,
							(void *) &child))
		goto done;

	if (child == NULL || g_slist_find(data->objects, child) != NULL)
		goto done;

	if (g_slist_find(parent->objects, child))
		goto done;

	data->objects = g_slist_prepend(data->objects, child);
	child->parent = data;

done:
	g_free(parent_path);
	return data;
}

static inline const GDBusPropertyTable *find_property(const GDBusPropertyTable *properties,
							const char *name)
{
	const GDBusPropertyTable *p;

	for (p = properties; p && p->name; p++) {
		if (strcmp(name, p->name) != 0)
			continue;

		if (check_experimental(p->flags,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL))
			break;

		if (check_testing(p->flags, G_DBUS_PROPERTY_FLAG_TESTING))
			break;

		return p;
	}

	return NULL;
}

static DBusMessage *properties_get(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	struct interface_data *iface;
	const GDBusPropertyTable *property;
	const char *interface, *name;
	DBusMessageIter iter, value;
	DBusMessage *reply;

	if (!dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &interface,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID))
		return NULL;

	iface = find_interface(data->interfaces, interface);
	if (iface == NULL)
		return g_dbus_create_error(message, DBUS_ERROR_INVALID_ARGS,
				"No such interface '%s'", interface);

	property = find_property(iface->properties, name);
	if (property == NULL)
		return g_dbus_create_error(message, DBUS_ERROR_INVALID_ARGS,
				"No such property '%s'", name);

	if (property->exists != NULL &&
			!property->exists(property, iface->user_data))
		return g_dbus_create_error(message, DBUS_ERROR_INVALID_ARGS,
					"No such property '%s'", name);

	if (property->get == NULL)
		return g_dbus_create_error(message, DBUS_ERROR_INVALID_ARGS,
				"Property '%s' is not readable", name);

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						property->type, &value);

	if (!property->get(property, &value, iface->user_data)) {
		dbus_message_unref(reply);
		return NULL;
	}

	dbus_message_iter_close_container(&iter, &value);

	return reply;
}

static DBusMessage *properties_get_all(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	struct interface_data *iface;
	const char *interface;
	DBusMessageIter iter;
	DBusMessage *reply;

	if (!dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &interface,
					DBUS_TYPE_INVALID))
		return NULL;

	iface = find_interface(data->interfaces, interface);
	if (iface == NULL)
		return g_dbus_create_error(message, DBUS_ERROR_INVALID_ARGS,
					"No such interface '%s'", interface);

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	append_properties(iface, &iter);

	return reply;
}

static DBusMessage *properties_set(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	DBusMessageIter iter, sub;
	struct interface_data *iface;
	const GDBusPropertyTable *property;
	const char *name, *interface;
	struct property_data *propdata;
	gboolean valid_signature;
	char *signature;

	if (!dbus_message_iter_init(message, &iter))
		return g_dbus_create_error(message, DBUS_ERROR_INVALID_ARGS,
							"No arguments given");

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_get_basic(&iter, &interface);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return g_dbus_create_error(message, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_recurse(&iter, &sub);

	iface = find_interface(data->interfaces, interface);
	if (iface == NULL)
		return g_dbus_create_error(message, DBUS_ERROR_INVALID_ARGS,
					"No such interface '%s'", interface);

	property = find_property(iface->properties, name);
	if (property == NULL)
		return g_dbus_create_error(message,
						DBUS_ERROR_UNKNOWN_PROPERTY,
						"No such property '%s'", name);

	if (property->set == NULL)
		return g_dbus_create_error(message,
					DBUS_ERROR_PROPERTY_READ_ONLY,
					"Property '%s' is not writable", name);

	if (property->exists != NULL &&
			!property->exists(property, iface->user_data))
		return g_dbus_create_error(message,
						DBUS_ERROR_UNKNOWN_PROPERTY,
						"No such property '%s'", name);

	signature = dbus_message_iter_get_signature(&sub);
	valid_signature = strcmp(signature, property->type) ? FALSE : TRUE;
	dbus_free(signature);
	if (!valid_signature)
		return g_dbus_create_error(message,
					DBUS_ERROR_INVALID_SIGNATURE,
					"Invalid signature for '%s'", name);

	propdata = g_new(struct property_data, 1);
	propdata->id = next_pending_property++;
	propdata->message = dbus_message_ref(message);
	propdata->conn = connection;
	pending_property_set = g_slist_prepend(pending_property_set, propdata);

	property->set(property, &sub, propdata->id, iface->user_data);

	return NULL;
}

static const GDBusMethodTable properties_methods[] = {
	{ GDBUS_METHOD("Get",
			GDBUS_ARGS({ "interface", "s" }, { "name", "s" }),
			GDBUS_ARGS({ "value", "v" }),
			properties_get) },
	{ GDBUS_ASYNC_METHOD("Set",
			GDBUS_ARGS({ "interface", "s" }, { "name", "s" },
							{ "value", "v" }),
			NULL,
			properties_set) },
	{ GDBUS_METHOD("GetAll",
			GDBUS_ARGS({ "interface", "s" }),
			GDBUS_ARGS({ "properties", "a{sv}" }),
			properties_get_all) },
	{ }
};

static const GDBusSignalTable properties_signals[] = {
	{ GDBUS_SIGNAL("PropertiesChanged",
			GDBUS_ARGS({ "interface", "s" },
					{ "changed_properties", "a{sv}" },
					{ "invalidated_properties", "as"})) },
	{ }
};

static void append_name(gpointer data, gpointer user_data)
{
	char *name = data;
	DBusMessageIter *iter = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &name);
}

static void emit_interfaces_removed(struct generic_data *data)
{
	DBusMessage *signal;
	DBusMessageIter iter, array;

	if (root == NULL || data == root)
		return;

	signal = dbus_message_new_signal(root->path,
					DBUS_INTERFACE_OBJECT_MANAGER,
					"InterfacesRemoved");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
								&data->path);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array);

	g_slist_foreach(data->removed, append_name, &array);
	g_slist_free_full(data->removed, g_free);
	data->removed = NULL;

	dbus_message_iter_close_container(&iter, &array);

	/* Use g_dbus_send_unref to avoid recursive calls to g_dbus_flush */
	g_dbus_send_unref(data->conn, signal);
}

static void remove_pending(struct generic_data *data)
{
	if (data->process_id > 0) {
		g_source_remove(data->process_id);
		data->process_id = 0;
	}

	pending = g_slist_remove(pending, data);
}

static gboolean process_changes(gpointer user_data)
{
	struct generic_data *data = user_data;

	remove_pending(data);

	if (data->added != NULL)
		emit_interfaces_added(data);

	/* Flush pending properties */
	if (data->pending_prop == TRUE)
		process_property_changes(data);

	if (data->removed != NULL)
		emit_interfaces_removed(data);

	data->process_id = 0;

	return FALSE;
}

static void generic_unregister(DBusConnection *connection, void *user_data)
{
	struct generic_data *data = user_data;
	struct generic_data *parent = data->parent;

	if (parent != NULL)
		parent->objects = g_slist_remove(parent->objects, data);

	if (data->process_id > 0) {
		g_source_remove(data->process_id);
		data->process_id = 0;
		process_changes(data);
	}

	g_slist_foreach(data->objects, reset_parent, data->parent);
	g_slist_free(data->objects);

	dbus_connection_unref(data->conn);
	g_free(data->introspect);
	g_free(data->path);
	g_free(data);
}

static DBusHandlerResult generic_message(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	struct interface_data *iface;
	const GDBusMethodTable *method;
	const char *interface;

	g_dbus_debug("[%s:%s] > %s.%s [#%d]",
			dbus_message_get_sender(message),/*获取发送当前 D-Bus 消息的发送方唯一标识（即发送方的 D-Bus 名称）*/
			dbus_message_type_string(message),/*将 D-Bus 消息的类型（枚举值）转换为可读字符串（便于调试 / 日志）*/
			dbus_message_get_interface(message),/*获取当前 D-Bus 消息对应的接口名（即消息关联的功能契约）*/
			dbus_message_get_member(message),/*获取当前 D-Bus 消息对应的成员名（方法名或信号名）*/
			dbus_message_get_serial(message));/*获取当前 D-Bus 消息的唯一序列号（D-Bus 总线分配，用于消息追踪 / 关联）*/

	interface = dbus_message_get_interface(message);

	/*利用接口名称查询interface_data*/
	iface = find_interface(data->interfaces, interface);
	if (iface == NULL)
		/*不能处理此接口*/
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	for (method = iface->methods; method &&
			method->name && method->function; method++) {

		/*检查message调用的是否为此接口下的此方法*/
		if (dbus_message_is_method_call(message, iface->name,
							method->name) == FALSE)
			continue;/*跳过非匹配方法*/

		if (check_experimental(method->flags,
					G_DBUS_METHOD_FLAG_EXPERIMENTAL))
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;/*此方法标记有experimental,且未开启,跳过*/

		if (check_testing(method->flags, G_DBUS_METHOD_FLAG_TESTING))
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;/*此方法标记有TESTING,且未开启,跳过*/

		if (g_dbus_args_have_signature(method->in_args,
							message) == FALSE)
			continue;

		if (check_privilege(connection, message, method,
						iface->user_data) == TRUE)
			return DBUS_HANDLER_RESULT_HANDLED;

		/*处理dbus消息*/
		return process_message(connection, message, method,
							iface->user_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable generic_table = {
	.unregister_function	= generic_unregister,/*对象路径被注销时的回调（如释放资源）*/
	.message_function	= generic_message,/*处理客户端方法调用的回调*/
};

static const GDBusMethodTable introspect_methods[] = {
	{ GDBUS_METHOD("Introspect", NULL,
			GDBUS_ARGS({ "xml", "s" }), introspect) },
	{ }
};

static void append_interfaces(struct generic_data *data, DBusMessageIter *iter)
{
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_ARRAY_AS_STRING
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &array);

	g_slist_foreach(data->interfaces, append_interface, &array);

	dbus_message_iter_close_container(iter, &array);
}

static void append_object(gpointer data, gpointer user_data)
{
	struct generic_data *child = data;
	DBusMessageIter *array = user_data;
	DBusMessageIter entry;

	dbus_message_iter_open_container(array, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
								&child->path);
	append_interfaces(child, &entry);
	dbus_message_iter_close_container(array, &entry);

	g_slist_foreach(child->objects, append_object, user_data);
}

static DBusMessage *get_objects(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_OBJECT_PATH_AS_STRING
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&array);

	g_slist_foreach(data->objects, append_object, &array);

	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

static const GDBusMethodTable manager_methods[] = {
	{ GDBUS_METHOD("GetManagedObjects", NULL,
		GDBUS_ARGS({ "objects", "a{oa{sa{sv}}}" }), get_objects) },
	{ }
};

static const GDBusSignalTable manager_signals[] = {
	{ GDBUS_SIGNAL("InterfacesAdded",
		GDBUS_ARGS({ "object", "o" },
				{ "interfaces", "a{sa{sv}}" })) },
	{ GDBUS_SIGNAL("InterfacesRemoved",
		GDBUS_ARGS({ "object", "o" }, { "interfaces", "as" })) },
	{ }
};

/*注册接口(接口名称及方法名唯一确定一个回调,接口名称可以解决版本问题,例如:org.bluez.Device1)*/
static gboolean add_interface(struct generic_data *data,
				const char *name/*接口名称*/,
				const GDBusMethodTable *methods/*接口下的一组方法*/,
				const GDBusSignalTable *signals,
				const GDBusPropertyTable *properties,
				void *user_data,
				GDBusDestroyFunction destroy)
{
	struct interface_data *iface;
	const GDBusMethodTable *method;
	const GDBusSignalTable *signal;
	const GDBusPropertyTable *property;

	for (method = methods; method && method->name; method++) {
		if (!check_experimental(method->flags,
					G_DBUS_METHOD_FLAG_EXPERIMENTAL))
			goto done;

		if (!check_testing(method->flags, G_DBUS_METHOD_FLAG_TESTING))
			goto done;
	}

	for (signal = signals; signal && signal->name; signal++) {
		if (!check_experimental(signal->flags,
					G_DBUS_SIGNAL_FLAG_EXPERIMENTAL))
			goto done;
		if (!check_testing(signal->flags, G_DBUS_SIGNAL_FLAG_TESTING))
			goto done;
	}

	for (property = properties; property && property->name; property++) {
		if (!check_experimental(property->flags,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL))
			goto done;
		if (!check_testing(property->flags,
					G_DBUS_PROPERTY_FLAG_TESTING))
			goto done;
	}

	/* Nothing to register */
	return FALSE;/*以上均有标记,不能注册*/

done:
	/*初始化interface_data*/
	iface = g_new0(struct interface_data, 1);
	iface->name = g_strdup(name);
	iface->methods = methods;
	iface->signals = signals;
	iface->properties = properties;
	iface->user_data = user_data;
	iface->destroy = destroy;

	data->interfaces = g_slist_append(data->interfaces, iface);/*添加interface_data*/
	if (data->parent == NULL)
		return TRUE;

	data->added = g_slist_append(data->added, iface);

	add_pending(data);

	return TRUE;
}

static struct generic_data *object_path_ref(DBusConnection *connection/*D-Bus 连接（如与系统总线的连接）*/,
							const char *path/*要注册的对象路径*/)
{
	struct generic_data *data;

	if (dbus_connection_get_object_path_data(connection, path,
						(void *) &data) == TRUE) {
		if (data != NULL) {
			data->refcount++;
			return data;
		}
	}

	data = g_new0(struct generic_data, 1);
	data->conn = dbus_connection_ref(connection);
	data->path = g_strdup(path);
	data->refcount = 1;

	data->introspect = g_strdup(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE "<node></node>");

	/*在 D-Bus 连接上注册一个‘对象路径’，并绑定该路径对应的接口方法、信号、属性的处理逻辑*/
	if (!dbus_connection_register_object_path(connection, path,
						&generic_table/*回调函数表（方法/信号/属性的处理逻辑）*/, data/*传递给回调函数的自定义数据*/)) {
		dbus_connection_unref(data->conn);
		g_free(data->path);
		g_free(data->introspect);
		g_free(data);
		return NULL;
	}

	invalidate_parent_data(connection, path);

	add_interface(data, DBUS_INTERFACE_INTROSPECTABLE, introspect_methods,
						NULL, NULL, data, NULL);

	return data;
}

static void object_path_unref(DBusConnection *connection, const char *path)
{
	struct generic_data *data = NULL;

	if (dbus_connection_get_object_path_data(connection, path,
						(void *) &data) == FALSE)
		return;

	if (data == NULL)
		return;

	data->refcount--;

	if (data->refcount > 0)
		return;

	remove_interface(data, DBUS_INTERFACE_INTROSPECTABLE);
	remove_interface(data, DBUS_INTERFACE_PROPERTIES);

	invalidate_parent_data(data->conn, data->path);

	dbus_connection_unregister_object_path(data->conn, data->path);
}

static gboolean check_signal(DBusConnection *conn, const char *path,
				const char *interface, const char *name,
				const GDBusArgInfo **args)
{
	struct generic_data *data = NULL;
	struct interface_data *iface;
	const GDBusSignalTable *signal;

	*args = NULL;
	if (!dbus_connection_get_object_path_data(conn, path,
					(void *) &data) || data == NULL) {
		error("dbus_connection_emit_signal: path %s isn't registered",
				path);
		return FALSE;
	}

	iface = find_interface(data->interfaces, interface);
	if (iface == NULL) {
		error("dbus_connection_emit_signal: %s does not implement %s",
				path, interface);
		return FALSE;
	}

	for (signal = iface->signals; signal && signal->name; signal++) {
		if (strcmp(signal->name, name) != 0)
			continue;

		if (signal->flags & G_DBUS_SIGNAL_FLAG_EXPERIMENTAL) {
			const char *env = g_getenv("GDBUS_EXPERIMENTAL");
			if (g_strcmp0(env, "1") != 0)
				break;
		}

		*args = signal->args;
		return TRUE;
	}

	error("No signal named %s on interface %s", name, interface);
	return FALSE;
}

/*在 D-Bus 连接上注册一个特定的对象路径（Object Path）下的指定接口（Interface），
 * 从而使该接口提供的功能（方法、信号和属性）能够被其他 D-Bus 客户端访问和调用。*/
gboolean g_dbus_register_interface(DBusConnection *connection,
					const char *path/*要注册的对象路径*/, const char *name/*接口名称*/,
					const GDBusMethodTable *methods,
					const GDBusSignalTable *signals,
					const GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy)
{
	struct generic_data *data;

	if (!dbus_validate_path(path, NULL)) {
		error("Invalid object path: %s", path);
		return FALSE;
	}

	if (!dbus_validate_interface(name, NULL)) {
		error("Invalid interface: %s", name);
		return FALSE;
	}

	/*针对此object path创建generic_data,并绑定此object path的处理逻辑*/
	data = object_path_ref(connection, path);
	if (data == NULL)
		return FALSE;

	if (find_interface(data->interfaces, name)) {
		/*此接口已存在*/
		object_path_unref(connection, path);
		return FALSE;
	}

	/*添加接口及其对应的methods,signals,properties*/
	if (!add_interface(data, name, methods, signals, properties, user_data,
								destroy)) {
		object_path_unref(connection, path);
		return FALSE;
	}

	if (properties != NULL && !find_interface(data->interfaces,
						DBUS_INTERFACE_PROPERTIES))
		/*如果DBUS_INTERFACE_PROPERTIES接口也不存在,增加接口*/
		add_interface(data, DBUS_INTERFACE_PROPERTIES,
				properties_methods, properties_signals, NULL,
				data, NULL);

	g_free(data->introspect);
	data->introspect = NULL;

	return TRUE;
}

gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name)
{
	struct generic_data *data = NULL;

	if (path == NULL)
		return FALSE;

	if (dbus_connection_get_object_path_data(connection, path,
						(void *) &data) == FALSE)
		return FALSE;

	if (data == NULL)
		return FALSE;

	if (remove_interface(data, name) == FALSE)
		return FALSE;

	g_free(data->introspect);
	data->introspect = NULL;

	object_path_unref(connection, data->path);

	return TRUE;
}

gboolean g_dbus_register_security(const GDBusSecurityTable *security)
{
	if (security_table != NULL)
		return FALSE;

	security_table = security;

	return TRUE;
}

gboolean g_dbus_unregister_security(const GDBusSecurityTable *security)
{
	security_table = NULL;

	return TRUE;
}

DBusMessage *g_dbus_create_error_valist(DBusMessage *message, const char *name,
					const char *format, va_list args)
{
	char str[1024];

	/* Check if the message can be replied */
	if (dbus_message_get_no_reply(message))
		return NULL;

	if (format)
		vsnprintf(str, sizeof(str), format, args);
	else
		str[0] = '\0';

	return dbus_message_new_error(message, name, str);
}

DBusMessage *g_dbus_create_error(DBusMessage *message, const char *name,
						const char *format, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, format);

	reply = g_dbus_create_error_valist(message, name, format, args);

	va_end(args);

	return reply;
}

DBusMessage *g_dbus_create_reply_valist(DBusMessage *message,
						int type, va_list args)
{
	DBusMessage *reply;

	/* Check if the message can be replied */
	if (dbus_message_get_no_reply(message))
		return NULL;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	if (dbus_message_append_args_valist(reply, type, args) == FALSE) {
		dbus_message_unref(reply);
		return NULL;
	}

	return reply;
}

DBusMessage *g_dbus_create_reply(DBusMessage *message, int type, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, type);

	reply = g_dbus_create_reply_valist(message, type, args);

	va_end(args);

	return reply;
}

static void g_dbus_flush(DBusConnection *connection)
{
	GSList *l;

	for (l = pending; l;) {
		struct generic_data *data = l->data;

		l = l->next;
		if (data->conn != connection)
			continue;

		process_changes(data);
	}
}

gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message)
{
	dbus_bool_t result = FALSE;

	if (!message)
		return FALSE;

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL)
		dbus_message_set_no_reply(message, TRUE);
	else if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_SIGNAL) {
		const char *path = dbus_message_get_path(message);
		const char *interface = dbus_message_get_interface(message);
		const char *name = dbus_message_get_member(message);
		const GDBusArgInfo *args;

		if (!check_signal(connection, path, interface, name, &args))
			goto out;
	}

	/* Flush pending signal to guarantee message order */
	g_dbus_flush(connection);

	switch (dbus_message_get_type(message)) {
	case DBUS_MESSAGE_TYPE_METHOD_RETURN:
		g_dbus_debug("[%s:%s] < [#%d]",
				dbus_message_get_destination(message),
				dbus_message_type_string(message),
				dbus_message_get_reply_serial(message));
		break;
	case DBUS_MESSAGE_TYPE_ERROR:
		g_dbus_debug("[%s:%s] < %s [#%d]",
				dbus_message_get_destination(message),
				dbus_message_type_string(message),
				dbus_message_get_error_name(message),
				dbus_message_get_reply_serial(message));
		break;
	case DBUS_MESSAGE_TYPE_SIGNAL:
		g_dbus_debug("[%s] %s.%s",
				dbus_message_type_string(message),
				dbus_message_get_interface(message),
				dbus_message_get_member(message));
		break;
	default:
		g_dbus_debug("[%s:%s] < %s.%s",
				dbus_message_get_destination(message),
				dbus_message_type_string(message),
				dbus_message_get_interface(message),
				dbus_message_get_member(message));
		break;
	}

	result = dbus_connection_send(connection, message, NULL);

out:
	dbus_message_unref(message);

	return result;
}

/*将一个 D-Bus 消息（GDBusMessage 对象）发送到总线，并异步等待服务器返回一个回复消息。*/
gboolean g_dbus_send_message_with_reply(DBusConnection *connection,
					DBusMessage *message,
					DBusPendingCall **call, int timeout)
{
	dbus_bool_t ret;

	/* Flush pending signal to guarantee message order */
	g_dbus_flush(connection);

	ret = dbus_connection_send_with_reply(connection, message, call,
								timeout);

	if (ret == TRUE && call != NULL && *call == NULL) {
		error("Unable to send message (passing fd blocked?)");
		return FALSE;
	}

	g_dbus_debug("[%s:%s] < %s.%s",
			dbus_message_get_destination(message),
			dbus_message_type_string(message),
			dbus_message_get_interface(message),
			dbus_message_get_member(message));

	return ret;
}

gboolean g_dbus_send_error_valist(DBusConnection *connection,
					DBusMessage *message, const char *name,
					const char *format, va_list args)
{
	DBusMessage *error;

	error = g_dbus_create_error_valist(message, name, format, args);
	if (error == NULL)
		return FALSE;

	return g_dbus_send_message(connection, error);
}

gboolean g_dbus_send_error(DBusConnection *connection, DBusMessage *message,
				const char *name, const char *format, ...)
{
	va_list args;
	gboolean result;

	va_start(args, format);

	result = g_dbus_send_error_valist(connection, message, name,
							format, args);

	va_end(args);

	return result;
}

gboolean g_dbus_send_reply_valist(DBusConnection *connection,
				DBusMessage *message, int type, va_list args)
{
	DBusMessage *reply;

	reply = g_dbus_create_reply_valist(message, type, args);
	if (!reply)
		return FALSE;

	return g_dbus_send_message(connection, reply);
}

gboolean g_dbus_send_reply(DBusConnection *connection,
				DBusMessage *message, int type, ...)
{
	va_list args;
	gboolean result;

	va_start(args, type);

	result = g_dbus_send_reply_valist(connection, message, type, args);

	va_end(args);

	return result;
}

gboolean g_dbus_emit_signal(DBusConnection *connection,
				const char *path, const char *interface,
				const char *name, int type, ...)
{
	va_list args;
	gboolean result;

	va_start(args, type);

	result = g_dbus_emit_signal_valist(connection, path, interface,
							name, type, args);

	va_end(args);

	return result;
}

gboolean g_dbus_emit_signal_valist(DBusConnection *connection,
				const char *path, const char *interface,
				const char *name, int type, va_list args)
{
	DBusMessage *signal;
	dbus_bool_t ret;
	const GDBusArgInfo *args_info;

	if (!check_signal(connection, path, interface, name, &args_info))
		return FALSE;

	signal = dbus_message_new_signal(path, interface, name);
	if (signal == NULL) {
		error("Unable to allocate new %s.%s signal", interface,  name);
		return FALSE;
	}

	ret = dbus_message_append_args_valist(signal, type, args);
	if (!ret)
		goto fail;

	if (g_dbus_args_have_signature(args_info, signal) == FALSE) {
		error("%s.%s: got unexpected signature '%s'", interface, name,
					dbus_message_get_signature(signal));
		ret = FALSE;
		goto fail;
	}

	return g_dbus_send_message(connection, signal);

fail:
	dbus_message_unref(signal);

	return ret;
}

static void process_properties_from_interface(struct generic_data *data,
						struct interface_data *iface)
{
	GSList *l;
	DBusMessage *signal;
	DBusMessageIter iter, dict, array;
	GSList *invalidated;

	if (iface->pending_prop == NULL)
		return;

	signal = dbus_message_new_signal(data->path,
			DBUS_INTERFACE_PROPERTIES, "PropertiesChanged");
	if (signal == NULL) {
		error("Unable to allocate new " DBUS_INTERFACE_PROPERTIES
						".PropertiesChanged signal");
		return;
	}

	iface->pending_prop = g_slist_reverse(iface->pending_prop);

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,	&iface->name);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	invalidated = NULL;

	for (l = iface->pending_prop; l != NULL; l = l->next) {
		GDBusPropertyTable *p = l->data;

		if (p->get == NULL)
			continue;

		if (p->exists != NULL && !p->exists(p, iface->user_data)) {
			invalidated = g_slist_prepend(invalidated, p);
			continue;
		}

		append_property(iface, p, &dict);
	}

	dbus_message_iter_close_container(&iter, &dict);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array);
	for (l = invalidated; l != NULL; l = g_slist_next(l)) {
		GDBusPropertyTable *p = l->data;

		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
								&p->name);
	}
	g_slist_free(invalidated);
	dbus_message_iter_close_container(&iter, &array);

	g_slist_free(iface->pending_prop);
	iface->pending_prop = NULL;

	/* Use g_dbus_send_unref to avoid recursive calls to g_dbus_flush */
	g_dbus_send_unref(data->conn, signal);
}

static void process_property_changes(struct generic_data *data)
{
	GSList *l;

	data->pending_prop = FALSE;

	for (l = data->interfaces; l != NULL; l = l->next) {
		struct interface_data *iface = l->data;

		process_properties_from_interface(data, iface);
	}
}

void g_dbus_emit_property_changed_full(DBusConnection *connection,
				const char *path, const char *interface,
				const char *name,
				GDbusPropertyChangedFlags flags)
{
	const GDBusPropertyTable *property;
	struct generic_data *data;
	struct interface_data *iface;

	if (path == NULL)
		return;

	if (!dbus_connection_get_object_path_data(connection, path,
					(void **) &data) || data == NULL)
		return;

	iface = find_interface(data->interfaces, interface);
	if (iface == NULL)
		return;

	/*
	 * If ObjectManager is attached, don't emit property changed if
	 * interface is not yet published
	 */
	if (root && g_slist_find(data->added, iface))
		return;

	property = find_property(iface->properties, name);
	if (property == NULL) {
		error("Could not find property %s in %p", name,
							iface->properties);
		return;
	}

	if (g_slist_find(iface->pending_prop, (void *) property) != NULL)
		return;

	data->pending_prop = TRUE;
	iface->pending_prop = g_slist_prepend(iface->pending_prop,
						(void *) property);

	if (flags & G_DBUS_PROPERTY_CHANGED_FLAG_FLUSH)
		process_property_changes(data);
	else
		add_pending(data);
}

/*通知客户端 “属性值已变更”*/
void g_dbus_emit_property_changed(DBusConnection *connection, const char *path,
				const char *interface, const char *name)
{
	g_dbus_emit_property_changed_full(connection, path, interface, name, 0);
}

gboolean g_dbus_get_properties(DBusConnection *connection, const char *path,
				const char *interface, DBusMessageIter *iter)
{
	struct generic_data *data;
	struct interface_data *iface;

	if (path == NULL)
		return FALSE;

	if (!dbus_connection_get_object_path_data(connection, path,
					(void **) &data) || data == NULL)
		return FALSE;

	iface = find_interface(data->interfaces, interface);
	if (iface == NULL)
		return FALSE;

	append_properties(iface, iter);

	return TRUE;
}

gboolean g_dbus_attach_object_manager(DBusConnection *connection)
{
	struct generic_data *data;

	/*创建'/'对象*/
	data = object_path_ref(connection, "/");
	if (data == NULL)
		return FALSE;

	add_interface(data, DBUS_INTERFACE_OBJECT_MANAGER,
					manager_methods, manager_signals,
					NULL, data, NULL);
	root = data;

	return TRUE;
}

gboolean g_dbus_detach_object_manager(DBusConnection *connection)
{
	if (!g_dbus_unregister_interface(connection, "/",
					DBUS_INTERFACE_OBJECT_MANAGER))
		return FALSE;

	root = NULL;

	return TRUE;
}

void g_dbus_set_flags(int flags)
{
	global_flags = flags;
}

int g_dbus_get_flags(void)
{
	return global_flags;
}

void g_dbus_set_debug(g_dbus_debug_func_t cb, void *user_data,
				g_dbus_destroy_func_t destroy)
{
	if (debug.destroy)
		debug.destroy(debug.data);

	debug.func = cb;
	debug.destroy = destroy;
	debug.data = user_data;
}
