// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/stat.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"

#include "btio/btio.h"
#include "src/plugin.h"
#include "src/log.h"
#include "src/btd.h"

#define IS_ENABLED(x) (x)

static GSList *plugins = NULL;/*记录系统中所有插件*/

struct bluetooth_plugin {
	void *handle;/*so对应的handle,对内部插件而言此值为NULL*/
	const struct bluetooth_plugin_desc *desc;/*插件描述(元数据)*/
};

/*按优先级从小到大排列*/
static int compare_priority(gconstpointer a, gconstpointer b)
{
	const struct bluetooth_plugin_desc *plugin1 = a;
	const struct bluetooth_plugin_desc *plugin2 = b;

	return plugin2->priority - plugin1->priority;
}

static int init_plugin(const struct bluetooth_plugin_desc *desc)
{
	int err;

	err = desc->init();/*初始化此插件*/
	if (err < 0) {
		/*初始化失败*/
		if (err == -ENOSYS || err == -ENOTSUP)
			DBG("System does not support %s plugin",
						desc->name);
		else
			error("Failed to init %s plugin",
						desc->name);
	}
	return err;
}

/*添加外部插件*/
static gboolean add_external_plugin(void *handle,
				const struct bluetooth_plugin_desc *desc)
{
	struct bluetooth_plugin *plugin;

	if (desc->init == NULL)
		return FALSE;

	if (g_str_equal(desc->version, VERSION) == FALSE) {
		error("Version mismatch for %s", desc->name);
		return FALSE;/*版本号必须与version匹配(这个等于检查使得可用性很差)*/
	}

	plugin = g_try_new0(struct bluetooth_plugin, 1);
	if (plugin == NULL)
		return FALSE;

	plugin->handle = handle;/*对外部插件而言此值不为空*/
	plugin->desc = desc;

	if (init_plugin(desc) < 0) {
		/*初始化此插件失败*/
		g_free(plugin);
		return FALSE;
	}

	__btd_enable_debug(desc->debug_start, desc->debug_stop);

	plugins = g_slist_append(plugins, plugin);
	DBG("Plugin %s loaded", desc->name);

	return TRUE;
}

/*添加内部插件*/
static void add_plugin(void *data, void *user_data)
{
	struct bluetooth_plugin_desc *desc = data;
	struct bluetooth_plugin *plugin;

	DBG("Loading %s plugin", desc->name);

	/*申请plugin变量*/
	plugin = g_try_new0(struct bluetooth_plugin, 1);
	if (plugin == NULL)
		return;

	plugin->desc = desc;/*内部插件仅设置desc即可*/

	if (init_plugin(desc) < 0) {
		/*初始化此插件失败*/
		g_free(plugin);
		return;
	}

	plugins = g_slist_append(plugins, plugin);/*添加此插件*/
	DBG("Plugin %s loaded", desc->name);
}

static gboolean enable_plugin(const char *name, char **cli_enable/*开启的插件列表*/,
							char **cli_disable/*禁用的插件列表*/)
{
	if (cli_disable) {
		/*遍历所有disable插件列表,如果匹配,则禁用*/
		for (; *cli_disable; cli_disable++)
			if (g_pattern_match_simple(*cli_disable, name))
				break;
		if (*cli_disable) {
			info("Excluding (cli) %s", name);
			return FALSE;/*禁用*/
		}
	}

	if (cli_enable) {
		/*遍历所有enable插件列表,如果匹配，则使能*/
		for (; *cli_enable; cli_enable++)
			if (g_pattern_match_simple(*cli_enable, name))
				break;
		if (!*cli_enable) {
			info("Ignoring (cli) %s", name);/*未在enable列表中，失配*/
			return FALSE;
		}
	}

	return TRUE;/*使能*/
}


/*初始化外部插件*/
static void external_plugin_init(char **cli_enabled, char **cli_disabled)
{
	GDir *dir;
	const char *file;

	info("Using external plugins is not officially supported.\n");
	info("Consider upstreaming your plugins into the BlueZ project.");

	if (strlen(PLUGINDIR) == 0)
		return;/*未设置插件目录,则直接返回*/

	DBG("Loading plugins %s", PLUGINDIR);

	/*打开插件目录*/
	dir = g_dir_open(PLUGINDIR, 0, NULL);
	if (!dir)
		return;

	while ((file = g_dir_read_name(dir)) != NULL) {
		const struct bluetooth_plugin_desc *desc;
		void *handle;
		char *filename;

		if (g_str_has_prefix(file, "lib") == TRUE ||
				g_str_has_suffix(file, ".so") == FALSE)
			continue;/*必须是lib开头且.so结尾*/

		filename = g_build_filename(PLUGINDIR, file, NULL);

		/*打开so文件*/
		handle = dlopen(filename, RTLD_NOW);
		if (handle == NULL) {
			error("Can't load plugin %s: %s", filename,
								dlerror());
			g_free(filename);
			continue;
		}

		g_free(filename);

		/*取名称为bluetooth_plugin_desc的符号*/
		desc = dlsym(handle, "bluetooth_plugin_desc");
		if (desc == NULL) {
			error("Can't load plugin description: %s", dlerror());
			dlclose(handle);
			continue;
		}

		/*检查此插件是否开启*/
		if (!enable_plugin(desc->name, cli_enabled, cli_disabled)) {
			dlclose(handle);
			continue;
		}

		/*添加外部插件*/
		if (add_external_plugin(handle, desc) == FALSE)
			dlclose(handle);
	}

	g_dir_close(dir);
}

#include "src/builtin.h"

void plugin_init(const char *enable/*白名单*/, const char *disable/*黑名单*/)
{
	GSList *builtins = NULL;
	char **cli_disabled = NULL;
	char **cli_enabled = NULL;
	unsigned int i;

	/* Make a call to BtIO API so its symbols got resolved before the
	 * plugins are loaded. */
	bt_io_error_quark();

	if (enable)
		/*获取enabled插件名称列表*/
		cli_enabled = g_strsplit_set(enable, ", ", -1);

	if (disable)
		/*获取disable插件名称列表*/
		cli_disabled = g_strsplit_set(disable, ", ", -1);

	DBG("Loading builtin plugins");

	/*遍历内建的插件*/
	for (i = 0; __bluetooth_builtin[i]; i++) {
		if (!enable_plugin(__bluetooth_builtin[i]->name, cli_enabled,
								cli_disabled))
			/*此插件检查黑白名单,不能被使能,跳过*/
			continue;

		/*按优先级构造list,形成可初始化内置插件*/
		builtins = g_slist_insert_sorted(builtins,
			(void *) __bluetooth_builtin[i], compare_priority);
	}

	/*遍历加入内置插件*/
	g_slist_foreach(builtins, add_plugin, NULL);

	if IS_ENABLED(EXTERNAL_PLUGINS)
		/*如果开启了插件,初始化外部插件*/
		external_plugin_init(cli_enabled, cli_disabled);

	g_slist_free(builtins);
	g_strfreev(cli_enabled);
	g_strfreev(cli_disabled);
}

void plugin_cleanup(void)
{
	GSList *list;

	DBG("Cleanup plugins");

	/*遍历并销毁所有plugin*/
	for (list = plugins; list; list = list->next) {
		struct bluetooth_plugin *plugin = list->data;

		if (plugin->desc->exit)
			plugin->desc->exit();

		/*外部插件需要执行dlclose*/
		if (plugin->handle != NULL)
			dlclose(plugin->handle);

		g_free(plugin);
	}

	g_slist_free(plugins);
}
