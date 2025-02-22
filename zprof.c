/*
 *  Copyright (c) 2009 Facebook
 *  Copyright (c) 2014-2016 Qafoo GmbH
 *  Copyright (c) 2016-2017 Tideways GmbH
 *  Copyright (c) 2019 ZPROF Jayki
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

#if __APPLE__
#include <mach/mach_init.h>
#include <mach/mach_time.h>
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/file.h"
#include "php_zprof.h"
#include "zend_extensions.h"
#include "zend_exceptions.h"
#include "zend_builtin_functions.h"
#include "zend_interfaces.h"

#include "ext/standard/url.h"
#if HAVE_PDO
#include "ext/pdo/php_pdo_driver.h"
#endif
#if HAVE_PCRE
#include "ext/pcre/php_pcre.h"
#endif
#include "zend_stream.h"

static inline void **hp_get_execute_arguments(zend_execute_data *data)
{
    void **p;

    p = data->function_state.arguments;

#if PHP_VERSION_ID >= 50500
    /*
     * With PHP 5.5 zend_execute cannot be overwritten by extensions anymore.
     * instead zend_execute_ex has to be used. That however does not have
     * function_state.arguments populated for non-internal functions.
     * As per UPGRADING.INTERNALS we are accessing prev_execute_data which
     * has this information (for whatever reasons).
     */
    if (p == NULL)
    {
        p = (*data).prev_execute_data->function_state.arguments;
    }
#endif

    return p;
}

static inline int hp_num_execute_arguments(zend_execute_data *data)
{
    void **p = hp_get_execute_arguments(data);
    return (int)(zend_uintptr_t)*p;
}

static inline zval *hp_get_execute_argument(zend_execute_data *data, int n)
{
    void **p = hp_get_execute_arguments(data);
    int arg_count = (int)(zend_uintptr_t)*p;
    return *(p - (arg_count - n));
}

static zend_always_inline zend_string *zend_string_alloc(int len, int persistent)
{
    /* single alloc, so free the buf, will also free the struct */
    char *buf = safe_pemalloc(sizeof(zend_string) + len + 1, 1, 0, persistent);
    zend_string *str = (zend_string *)(buf + len + 1);

    str->val = buf;
    str->len = len;
    str->persistent = persistent;

    return str;
}

static zend_always_inline zend_string *zend_string_init(const char *str, size_t len, int persistent)
{
    zend_string *ret = zend_string_alloc(len, persistent);

    memcpy(ret->val, str, len);
    ret->val[len] = '\0';
    return ret;
}

static zend_always_inline void zend_string_release(zend_string *s)
{
    if (s == NULL)
    {
        return;
    }

    pefree(s->val, s->persistent);
}

#define ZEND_CALL_NUM_ARGS(call) hp_num_execute_arguments(call)
#define ZEND_CALL_ARG(call, n) hp_get_execute_argument(call, n - 1)

#define register_trace_callback(function_name, cb)                                                                              \
    do {                                                                                                                        \
        zend_hash_update(ZP_G(trace_callbacks), function_name, sizeof(function_name), &cb, sizeof(zp_trace_callback *), NULL);  \
        hp_init_trace_callbacks_filter(function_name TSRMLS_CC);                                                                \   
    } while(0)

static zend_always_inline zval *zend_compat_hash_find_const(HashTable *ht, const char *key, strsize_t len)
{
    zval **tmp, *result;
    if (zend_hash_find(ht, key, len + 1, (void **)&tmp) == SUCCESS)
    {
        result = *tmp;
        return result;
    }
    return NULL;
}

static zend_always_inline zval *zend_compat_hash_index_find(HashTable *ht, zend_ulong idx)
{
    zval **tmp, *result;

    if (zend_hash_index_find(ht, idx, (void **)&tmp) == FAILURE)
    {
        return NULL;
    }

    result = *tmp;
    return result;
}

static zend_always_inline long zend_compat_hash_find_long(HashTable *ht, char *key, strsize_t len)
{
    long *idx_ptr = NULL;

    if (zend_hash_find(ht, key, len + 1, (void **)&idx_ptr) == SUCCESS)
    {
        return *idx_ptr;
    }

    return -1;
}

static char *strtolower(char *str)
{
    char *origin = str;

    for (; *str != '\0'; str++)
    {
        *str = tolower(*str);
    }
    
    return origin;
}

#define T(offset) (*EX_TMP_VAR(zdata, offset))

zval *zp_zval_ptr(int op_type, const znode_op *node, zend_execute_data *zdata TSRMLS_DC)
{
    if (!zdata->opline) {
        return NULL;
    }

    switch (op_type & 0x0F) {
        case IS_CONST:
            return node->zv;
            break;
        case IS_TMP_VAR:
            return &T(node->var).tmp_var;
            break;
        case IS_VAR:
            if (T(node->var).var.ptr) {
                return T(node->var).var.ptr;
            } else {
                temp_variable *T = &T(node->var);
                zval *str = T->str_offset.str;

                if (T->str_offset.str->type != IS_STRING
                        || ((int)T->str_offset.offset<0)
                        || ((unsigned int) T->str_offset.str->value.str.len <= T->str_offset.offset)) {
                    //zend_error(E_NOTICE, "Uninitialized string offset:  %d", T->str_offset.offset);
                    T->tmp_var.value.str.val = STR_EMPTY_ALLOC();
                    T->tmp_var.value.str.len = 0;
                } else {
                    char c = str->value.str.val[T->str_offset.offset];

                    T->tmp_var.value.str.val = estrndup(&c, 1);
                    T->tmp_var.value.str.len = 1;
                }
                T->tmp_var.refcount__gc=1;
                T->tmp_var.is_ref__gc=1;
                T->tmp_var.type = IS_STRING;
                return &T->tmp_var;
            }
            break;
        case IS_UNUSED:
            return NULL;
            break;
    }
    return NULL;
}

// 获取zv中的值，保存到store数组中
static zend_always_inline zp_add_array_from_ptr(zval *zv, zval *store)
{
    int tlen = 0;
    char *tstr = NULL;
    char value[128] = {0};
    
    switch(Z_TYPE_P(zv)) {
        case IS_BOOL:
            add_next_index_bool(store, Z_BVAL_P(zv));
            break;
        case IS_NULL:
            add_next_index_null(store);
            break;
        case IS_LONG:
            add_next_index_long(store, Z_LVAL_P(zv));
            break;
        case IS_DOUBLE:
            add_next_index_double(store, Z_DVAL_P(zv));
            break;
        case IS_STRING:
            add_next_index_string(store, Z_STRVAL_P(zv), 1);
            break;
        case IS_ARRAY:
            Z_ADDREF_P(zv);
            add_next_index_zval(store, zv);
            break;
        case IS_OBJECT:
            if (Z_OBJ_HANDLER(*zv, get_class_name)) {
                Z_OBJ_HANDLER(*zv, get_class_name)(zv, (const char **) &tstr, (zend_uint *) &tlen, 0 TSRMLS_CC);
                snprintf(value, sizeof(value), "object(%s)#%d",tstr, Z_OBJ_HANDLE_P(zv));
                efree(tstr);
            } else {
                snprintf(value, sizeof(value), "object(unknown)#%d", Z_OBJ_HANDLE_P(zv));
            }
            add_next_index_string(store, value, 1);
            break;
        case IS_RESOURCE:
            tstr = (char *) zend_rsrc_list_get_rsrc_type(Z_LVAL_P(zv) TSRMLS_CC); 
            snprintf(value, sizeof(value), "resource(%s)#%ld", tstr ? tstr : "Unknown", Z_LVAL_P(zv));
            add_next_index_string(store, value, 1);
            break;
        default:
            add_next_index_string(store, "unknown", 1);
            break;
      
    }
}

typedef void (*zp_trace_callback)(char *symbol, zend_execute_data *data TSRMLS_DC);

#if PHP_VERSION_ID < 50500
static void (*_zend_execute)(zend_op_array *ops TSRMLS_DC);
static void (*_zend_execute_internal)(zend_execute_data *data, int ret TSRMLS_DC);
#else
static void (*_zend_execute_ex)(zend_execute_data *execute_data TSRMLS_DC);
static void (*_zend_execute_internal)(zend_execute_data *data, struct _zend_fcall_info *fci, int ret TSRMLS_DC);
#endif

/* Pointer to the original compile function */
static zend_op_array *(*_zend_compile_file)(zend_file_handle *file_handle, int type TSRMLS_DC);

/* Pointer to the original compile string function (used by eval) */
static zend_op_array *(*_zend_compile_string)(zval *source_string, char *filename TSRMLS_DC);

ZEND_DLEXPORT zend_op_array *hp_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC);
ZEND_DLEXPORT zend_op_array *hp_compile_string(zval *source_string, char *filename TSRMLS_DC);

static void (*old_throw_exception_hook)(zval *exception TSRMLS_DC);
void (*old_error_cb)(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args);

void zp_throw_exception_hook(zval *exception TSRMLS_DC);
void zp_error_cb(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args);

#if PHP_VERSION_ID < 50500
ZEND_DLEXPORT void hp_execute(zend_op_array *ops TSRMLS_DC);
#else
ZEND_DLEXPORT void hp_execute_ex(zend_execute_data *execute_data TSRMLS_DC);
#endif

#if PHP_VERSION_ID < 50500
ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, int ret TSRMLS_DC);
#else
ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, struct _zend_fcall_info *fci, int ret TSRMLS_DC);
#endif

/* Bloom filter for function names to be ignored */
#define INDEX_2_BYTE(index) (index >> 3)
#define INDEX_2_BIT(index) (1 << (index & 0x7));

/**
 * ****************************
 * STATIC FUNCTION DECLARATIONS
 * ****************************
 */
static void hp_register_constants(INIT_FUNC_ARGS);

static void hp_begin(long zprof_flags TSRMLS_DC);
static void hp_stop(TSRMLS_D);
static void hp_end(TSRMLS_D);

static uint64 cycle_timer();

static void hp_free_the_free_list(TSRMLS_D);
static hp_entry_t *hp_fast_alloc_hprof_entry(TSRMLS_D);
static void hp_fast_free_hprof_entry(hp_entry_t *p TSRMLS_DC);
static inline uint8 hp_inline_hash(char *str);
static double get_timebase_factor();
static long get_us_interval(struct timeval *start, struct timeval *end);
static inline double get_us_from_tsc(uint64 count TSRMLS_DC);

static void hp_parse_options_from_arg(zval *args TSRMLS_DC);
static void hp_clean_profiler_options_state(TSRMLS_D);

static inline zval *hp_zval_at_key(char *key, size_t size, zval *values);
static inline char **hp_strings_in_zval(zval *values);
static inline void hp_array_del(char **name_array);
static char *hp_get_file_summary(char *filename, int filename_len TSRMLS_DC);
static char *hp_get_base_filename(char *filename);

static inline hp_function_map *hp_function_map_create(char **names);
static inline void hp_function_map_clear(hp_function_map *map);
static inline int hp_function_map_exists(hp_function_map *map, uint8 hash_code, char *curr_func);
static inline int hp_function_map_filter_collision(hp_function_map *map, uint8 hash);
zend_string *zp_pcre_match(char *pattern, strsize_t len, zval *subject TSRMLS_DC);

/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_zprof_enable, 0, 0, 0)
ZEND_ARG_INFO(0, flags)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_zprof_disable, 0)
ZEND_END_ARG_INFO()
/* }}} */

/**
 * *********************
 * PHP EXTENSION GLOBALS
 * *********************
 */
/* List of functions implemented/exposed by Zprof */
zend_function_entry zprof_functions[] = {
    PHP_FE(zprof_enable, arginfo_zprof_enable)
        PHP_FE(zprof_disable, arginfo_zprof_disable){NULL, NULL, NULL}};

ZEND_DECLARE_MODULE_GLOBALS(hp)

/* Callback functions for the Zprof extension */
zend_module_entry zprof_module_entry = {
    STANDARD_MODULE_HEADER,
    "zprof",              /* Name of the extension */
    zprof_functions,      /* List of functions exposed */
    PHP_MINIT(zprof),     /* Module init callback */
    PHP_MSHUTDOWN(zprof), /* Module shutdown callback */
    PHP_RINIT(zprof),     /* Request init callback */
    PHP_RSHUTDOWN(zprof), /* Request shutdown callback */
    PHP_MINFO(zprof),     /* Module info callback */
    ZPROF_VERSION,
    PHP_MODULE_GLOBALS(hp), /* globals descriptor */
    PHP_GINIT(hp),          /* globals ctor */
    PHP_GSHUTDOWN(hp),      /* globals dtor */
    NULL,                   /* post deactivate */
    STANDARD_MODULE_PROPERTIES_EX};

PHP_INI_BEGIN()

/**
 * INI-Settings are always used by the extension, but by the PHP library.
 */
PHP_INI_ENTRY("zprof.stack_threshold", "100", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("zprof.zpkey", "zpkey", PHP_INI_ALL, NULL)

PHP_INI_END()

/* Init module */
ZEND_GET_MODULE(zprof)

PHP_GINIT_FUNCTION(hp) {
    hp_globals->enabled = 0;
    hp_globals->ever_enabled = 0;
    hp_globals->zprof_flags = 0;
    hp_globals->trace_callbacks = NULL;

    hp_globals->stats_count = NULL;
    hp_globals->debug_trace = NULL;
    hp_globals->exceptions = NULL;
    hp_globals->errors = NULL;
    hp_globals->trace = NULL;

    hp_globals->entries = NULL;
    hp_globals->entry_free_list = NULL;
    hp_globals->root = NULL;

    hp_globals->filtered_functions = NULL;
    hp_globals->compile_count = 0;
    hp_globals->compile_wt = 0.0;
    hp_globals->cpu_start = 0;
    hp_globals->start_time = 0;
    hp_globals->stack_threshold = 0;

    hp_globals->function_nums = 0;

    hp_globals->trace_func = NULL;
     hp_globals->trace_on = 0;
}

PHP_GSHUTDOWN_FUNCTION(hp)
{
}

/**
 * Module init callback.
 *
 * @author cjiang
 */
PHP_MINIT_FUNCTION(zprof)
{
    int i;

    REGISTER_INI_ENTRIES();

    hp_register_constants(INIT_FUNC_ARGS_PASSTHRU);

    /* Get the number of available logical CPUs. */
    ZP_G(timebase_factor) = get_timebase_factor();

    ZP_G(stats_count) = NULL;
    ZP_G(debug_trace) = NULL;
    ZP_G(exceptions) = NULL;
    ZP_G(errors) = NULL;
    ZP_G(trace) = NULL;
    ZP_G(etimes) = NULL;

    ZP_G(trace_callbacks) = NULL;

    /* no free hp_entry_t structures to start with */
    ZP_G(entry_free_list) = NULL;

    for (i = 0; i < 256; i++)
    {
        ZP_G(func_hash_counters)[i] = 0;
    }

    _zend_compile_file = zend_compile_file;
    zend_compile_file = hp_compile_file;
    _zend_compile_string = zend_compile_string;
    zend_compile_string = hp_compile_string;

#if PHP_VERSION_ID < 50500
    _zend_execute = zend_execute;
    zend_execute = hp_execute;
#else
    _zend_execute_ex = zend_execute_ex;
    zend_execute_ex = hp_execute_ex;
#endif

    _zend_execute_internal = zend_execute_internal;
    zend_execute_internal = hp_execute_internal;

    // if (zend_throw_exception_hook)
    // {
    //     old_throw_exception_hook = zend_throw_exception_hook;
    // }
    // zend_throw_exception_hook = zp_throw_exception_hook;

    // old_error_cb = zend_error_cb;
    // zend_error_cb = zp_error_cb;

#if defined(DEBUG)
    /* To make it random number generator repeatable to ease testing. */
    srand(0);
#endif
    return SUCCESS;
}

/**
 * Module shutdown callback.
 */
PHP_MSHUTDOWN_FUNCTION(zprof)
{
    /* free any remaining items in the free list */
    hp_free_the_free_list(TSRMLS_C);

    /* Remove proxies, restore the originals */
#if PHP_VERSION_ID < 50500
    zend_execute = _zend_execute;
#else
    zend_execute_ex = _zend_execute_ex;
#endif

    zend_execute_internal = _zend_execute_internal;
    zend_compile_file = _zend_compile_file;
    zend_compile_string = _zend_compile_string;

    if (old_throw_exception_hook)
    {
        zend_throw_exception_hook = old_throw_exception_hook;
    }

    if (old_error_cb)
    {
        zend_error_cb = old_error_cb;
    }

    UNREGISTER_INI_ENTRIES();

    return SUCCESS;
}

void zp_trace_callback_predis_call(char *symbol, zend_execute_data *data TSRMLS_DC)
{
    zval *commandId = ZEND_CALL_ARG(data, 1);

    if (commandId == NULL || Z_TYPE_P(commandId) != IS_STRING)
    {
        return;
    }

    //php_printf("command %s\n", Z_STRVAL_P(commandId));
    return;
}

void zp_trace_callback_mysqli_connect(char *symbol, zend_execute_data *data TSRMLS_DC)
{
    long idx = -1;
    zval *arg;

    if (ZEND_CALL_NUM_ARGS(data) < 1)
    {
        return;
    }

    arg = ZEND_CALL_ARG(data, 1);

    if (Z_TYPE_P(arg) == IS_STRING)
    {
        //php_printf("peer.host %s\n", Z_STRVAL_P(arg));
    }

    if (ZEND_CALL_NUM_ARGS(data) > 3)
    {
        arg = ZEND_CALL_ARG(data, 4);

        if (Z_TYPE_P(arg) == IS_STRING && Z_STRLEN_P(arg) > 0)
        {
            //php_printf("db.name %s\n", Z_STRVAL_P(arg));
        }
    }

    if (ZEND_CALL_NUM_ARGS(data) > 4)
    {
        arg = ZEND_CALL_ARG(data, 5);

        if (Z_TYPE_P(arg) == IS_STRING)
        {
            //php_printf("peer.port %s\n", Z_STRVAL_P(arg));
        }
        else if (Z_TYPE_P(arg) == IS_LONG)
        {
            //php_printf("peer.port %d\n", Z_LAVAL_P(arg));
        }
    }

    return;
}

#if HAVE_PDO
void zp_trace_callback_pdo_connect(char *symbol, zend_execute_data *data TSRMLS_DC)
{
#ifndef HAVE_PCRE
    return;
#endif

    long idx = -1;
    zval *dsn;
    zend_string *match = NULL;
    zval *return_value;
    zval *subpats;
    pcre_cache_entry *pce;

    if (ZEND_CALL_NUM_ARGS(data) < 1)
    {
        return;
    }

    dsn = ZEND_CALL_ARG(data, 1);

    if (dsn == NULL || Z_TYPE_P(dsn) != IS_STRING)
    {
        return;
    }

    if (match = zp_pcre_match("(^(mysql|sqlite|pgsql|odbc|oci):)", sizeof("(^(mysql|sqlite|pgsql|odbc|oci):)") - 1, dsn TSRMLS_CC))
    {
        //php_printf("db.type %s\n", match->val);

        zend_string_release(match);

        if (match = zp_pcre_match("(host=([^;\\s]+))", sizeof("(host=([^;\\s]+))") - 1, dsn TSRMLS_CC))
        {
            //php_printf("peer.host %s\n", match->val);
            zend_string_release(match);
        }

        if (match = zp_pcre_match("(port=([^;\\s]+))", sizeof("(port=([^;\\s]+))") - 1, dsn TSRMLS_CC))
        {
            //php_printf("peer.port %s\n", match->val);
            zend_string_release(match);
        }

        if (match = zp_pcre_match("(dbname=([^;\\s]+))", sizeof("(dbname=([^;\\s]+))") - 1, dsn TSRMLS_CC))
        {
            //php_printf("db.name %s\n", match->val);
            zend_string_release(match);
        }
    }

    return;
}
#endif

#if HAVE_PCRE
zend_string *zp_pcre_match(char *pattern, strsize_t len, zval *subject TSRMLS_DC)
{
    zval *match = NULL;
    zend_string *result = NULL;
    zval *return_value;
    zval *subpats;
    pcre_cache_entry *pce;

    if ((pce = pcre_get_compiled_regex_cache(pattern, len TSRMLS_CC)) == NULL)
    {
        return NULL;
    }

    ALLOC_INIT_ZVAL(return_value);
    ALLOC_INIT_ZVAL(subpats);

    pce->refcount++;
    php_pcre_match_impl(pce, Z_STRVAL_P(subject), Z_STRLEN_P(subject), return_value, subpats, 0, 1, 0, 0 TSRMLS_CC);

    pce->refcount--;

    if (Z_LVAL_P(return_value) > 0 && Z_TYPE_P(subpats) == IS_ARRAY)
    {
        match = zend_compat_hash_index_find(Z_ARRVAL_P(subpats), 1);

        if (match != NULL)
        {
            result = zend_string_init(Z_STRVAL_P(match), Z_STRLEN_P(match), 0);
        }
    }

    zval_ptr_dtor(&return_value);
    zval_ptr_dtor(&subpats);

    return result;
}
#endif

#if HAVE_PDO
void zp_trace_callback_pdo_stmt_execute(char *symbol, zend_execute_data *data TSRMLS_DC)
{
    long idx;

    pdo_stmt_t *stmt = (pdo_stmt_t *)zend_object_store_get_object_by_handle(Z_OBJ_HANDLE_P(data->object) TSRMLS_CC);

    //php_printf("pdo_stmt sql %s\n", stmt->query_string);

    return;
}
#endif

void zp_trace_callback_mysqli_stmt_execute(char *symbol, zend_execute_data *data TSRMLS_DC)
{
    return;
}

void zp_trace_callback_sql_commit(char *symbol, zend_execute_data *data TSRMLS_DC)
{
    return;
}

void zp_trace_callback_sql_functions(char *symbol, zend_execute_data *data TSRMLS_DC)
{
    zval *argument_element, *link, *mysql_result = NULL, *pa, *counts, *row = NULL, *dbname = NULL; 
    zend_class_entry *ce;
    char *sc = "select database() as zp_dbname;";
    char *key = "zp_dbname";
    uint keylen = strlen(key);

    char arKey[] = "sql";
    uint nKeyLength = 4;
    zval **tmpzval;
    HashTable *ht;
    zval *sqlArray;
    zval fname;

    if (strcmp(symbol, "mysqli_query") == 0) {
        // 面向过程模式获取sql语句
        link = ZEND_CALL_ARG(data, 1);
        argument_element = ZEND_CALL_ARG(data, 2);

        if (Z_TYPE_P(argument_element) != IS_STRING) 
        {
            return;
        }

        // 如果执行的SQL语句是select database()，不需要记录回调信息，因为是profiler自己调用的(可能存在误判，用户也可能调用)
        if (strcmp(Z_STRVAL_P(argument_element), sc) == 0) 
        {
            return ;
        }

        // 设置参数，执行的 sql，会导致 profiler 多记录一次数据库函数调用
        MAKE_STD_ZVAL(pa);
        ZVAL_STRING(pa, sc, 1);

        // 执行 mysqli_query 获取当前执行的数据库名
        zval **pa1[2];
        pa1[0] = &link;
        pa1[1] = &pa;

        ZVAL_STRING(&fname, "mysqli_query", 0);

        if (SUCCESS != call_user_function_ex(EG(function_table), NULL, &fname, &mysql_result, 2, pa1, 1, NULL TSRMLS_CC)) 
        {
            zval_ptr_dtor(&pa);
            return ;
        }

        // 如果 mysqli_query 返回结果，执行mysqli_fetch_assoc 获取具体返回数据
        zval **params[1];
        params[0] = &mysql_result;
        ZVAL_STRING(&fname, "mysqli_fetch_assoc", 0);

        if (SUCCESS != call_user_function_ex(EG(function_table), NULL, &fname, &row, 1, params, 1, NULL TSRMLS_CC))
        {
            zval_ptr_dtor(&mysql_result);
            return ;
        }

        // mysqli_fetch_assoc 有返回结果
        if(row) 
        {
            dbname = zend_compat_hash_find_const(Z_ARRVAL_P(row), key, keylen);
        }

        MAKE_STD_ZVAL(counts);
        array_init(counts);
        add_assoc_string(counts, "sql", Z_STRVAL_P(argument_element), 1);
        add_assoc_long(counts, "no", ZP_G(function_nums));

        if(dbname && Z_TYPE_P(dbname) == IS_STRING) 
        {
            add_assoc_string(counts, "dbname", Z_STRVAL_P(dbname), 1);
        }

        // 释放空间
        zval_ptr_dtor(&pa);

        if(mysql_result) 
        {
            zval_ptr_dtor(&mysql_result);
        }

        if(row) 
        {
            zval_ptr_dtor(&row);
        }
    } else {
        // 对象模式执行，获取执行的SQL语句
        argument_element = ZEND_CALL_ARG(data, 1);

        if (Z_TYPE_P(argument_element) != IS_STRING) 
        {
            return;
        }

        // 如果执行的SQL语句是select database()，不需要记录回调信息，因为是profiler自己调用的(可能存在误判，用户也可能调用)
        if (strcmp(Z_STRVAL_P(argument_element), sc) == 0)
        {
            return ;
        }

        // 设置参数，执行的sql,会导致profiler多记录一次数据库函数调用
        MAKE_STD_ZVAL(pa);
        ZVAL_STRING(pa, sc, 1);

        /**
        * 执行 select database() 获取当前数据库名，一个项目如果连接了多个数据库，需要知道当前SQL语句在哪个数据库上执行的
        * 下面语句类似于: $msyqli->query('select database()') or $pdo->query('select database()')
        */
        if(data->object) 
        {
            ce = Z_OBJCE_P(data->object);
            zend_call_method_with_1_params(&data->object, ce, NULL, "query", &mysql_result, pa);
        }

        // $mysql->query 有结果，再调用$mysql_result->fetch_assoc 获取具体返回数据
        if(strcmp(symbol, "mysqli::query") == 0 && mysql_result)
        {
            ce = Z_OBJCE_P(mysql_result);
            zend_call_method_with_0_params(&mysql_result, ce, NULL, "fetch_assoc", &row);

            // $mysql_result->fetch_assoc 有返回结果
            if(row) {
                dbname = zend_compat_hash_find_const(Z_ARRVAL_P(row), key, keylen);
            }

            zval_ptr_dtor(&mysql_result);
        }
        // $pdo->query 有结果，再调用$PDOStatement->fetch 获取具体返回数据
        else if(mysql_result)
        {
            ce = Z_OBJCE_P(mysql_result);
            zend_call_method_with_0_params(&mysql_result, ce, NULL, "fetch", &row);

            // $PDOStatement->fetch 有返回结果
            if(row) {
                dbname = zend_compat_hash_find_const(Z_ARRVAL_P(row), key, keylen);
            }

            zval_ptr_dtor(&mysql_result);
        }

        MAKE_STD_ZVAL(counts);
        array_init(counts);
        add_assoc_string(counts, "sql", Z_STRVAL_P(argument_element), 1);
        add_assoc_long(counts, "no", ZP_G(function_nums));

        if(dbname && Z_TYPE_P(dbname) == IS_STRING) 
        {
            add_assoc_string(counts, "dbname", Z_STRVAL_P(dbname), 1);
        }
        
        // 释放$mysql_result->fetch_assoc 结果空间，
        // 如果在上面释放，会导致dbname获取不到数据库名
        if(row) 
        {
            zval_ptr_dtor(&row);
        }

        // 释放参数的空间
        zval_ptr_dtor(&pa);
    }

    // 记录当前 sql 函数的序号
    add_index_long(ZP_G(etimes), ZP_G(function_nums), 0);  

    // 判断 ZP_G(trace) 数组中是否有 sql，没有则生成一个
    ht = Z_ARRVAL_P(ZP_G(trace));
    if(zend_hash_find(ht, arKey, nKeyLength, (void **) &tmpzval) == FAILURE) {
        // $sql = [];
        MAKE_STD_ZVAL(sqlArray);
        array_init(sqlArray);
        // $trace['sql'] = $sql;
        add_assoc_zval(ZP_G(trace), arKey, sqlArray);   
    } else {
        sqlArray = *tmpzval;
    }

    // 类似于：$trace['sql'][] = $count;
    add_next_index_zval(sqlArray, counts);

    return;
}

void zp_trace_callback_fastcgi_finish_request(char *symbol, zend_execute_data *data TSRMLS_DC)
{
    return;
}

void zp_trace_callback_curl_exec(char *symbol, zend_execute_data *data TSRMLS_DC)
{
    zval *argument = ZEND_CALL_ARG(data, 1);
    zval *option;
    long idx, *idx_ptr;
    zval fname, *opt;
    zval *retval_ptr;
    zval *counts;
    HashTable *ht;
    zval *curlArray;
    zval **tmpzval;

    char arKey[] = "curl";
    uint nKeyLength = 5;

    if (argument == NULL || Z_TYPE_P(argument) != IS_RESOURCE)
    {
        return;
    }

    ZVAL_STRING(&fname, "curl_getinfo", 0);

    zval **pa[1];
    pa[0] = &argument;

    if (SUCCESS == call_user_function_ex(EG(function_table), NULL, &fname, &retval_ptr, 1, pa, 1, NULL TSRMLS_CC))
    {

        option = zend_compat_hash_find_const(Z_ARRVAL_P(retval_ptr), "url", sizeof("url") - 1);

        if (option && Z_TYPE_P(option) == IS_STRING)
        {
            MAKE_STD_ZVAL(counts);
            array_init(counts);
            add_assoc_string(counts, "url", Z_STRVAL_P(option), 1);
            add_assoc_long(counts, "no", ZP_G(function_nums));

            // 记录当前 sql 函数的序号
            add_index_long(ZP_G(etimes), ZP_G(function_nums), 0);  

            // 判断 ZP_G(trace) 数组中是否有 curl，没有则生成一个
            ht = Z_ARRVAL_P(ZP_G(trace));
            if(zend_hash_find(ht, arKey, nKeyLength, (void **) &tmpzval) == FAILURE) {
                // $curl = [];
                MAKE_STD_ZVAL(curlArray);
                array_init(curlArray);
                // $trace['curl'] = $curl;
                add_assoc_zval(ZP_G(trace), arKey, curlArray);   
            } else {
                curlArray = *tmpzval;
            }

            // 类似于：$trace['curl'][] = $count;
            add_next_index_zval(curlArray, counts);
        }

        zval_ptr_dtor(&retval_ptr);
    }

    return;
}

void zp_trace_callback_file_get_contents(char *symbol, zend_execute_data *data TSRMLS_DC)
{
    zval *argument = ZEND_CALL_ARG(data, 1);
    char *summary;
    long idx = -1;

    if (Z_TYPE_P(argument) != IS_STRING)
    {
        return;
    }

    if (strncmp(Z_STRVAL_P(argument), "http", 4) != 0)
    {
        return;
    }

    //php_printf("file_get_content %s\n", Z_STRVAL_P(argument));

    return;
}

/**
 * Request init callback.
 *
 * Check if Zprof.php exists in extension_dir and load it
 * in request init. This makes class \Zprof\Profiler available
 * for usage.
 */
PHP_RINIT_FUNCTION(zprof)
{
    //ZP_G(stats_count) = NULL;
    ZP_G(debug_trace) = NULL;
    ZP_G(exceptions) = NULL;
    ZP_G(errors) = NULL;
    ZP_G(trace) = NULL;
    ZP_G(etimes) = NULL;

    return SUCCESS;
}

/**
 * Request shutdown callback. Stop profiling and return.
 */
PHP_RSHUTDOWN_FUNCTION(zprof)
{
    hp_end(TSRMLS_C);

    return SUCCESS;
}

/**
 * Module info callback. Returns the Zprof version.
 */
PHP_MINFO_FUNCTION(zprof)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "zprof", ZPROF_VERSION);

    php_info_print_table_row(2, "stack_threshold (zprof.stack_threshold)", "执行时间小于该值的函数不进行统计，单位：μs");

    php_info_print_table_end();
}

/**
 * ***************************************************
 * COMMON HELPER FUNCTION DEFINITIONS AND LOCAL MACROS
 * ***************************************************
 */

static void hp_register_constants(INIT_FUNC_ARGS)
{
    REGISTER_LONG_CONSTANT("ZPROF_FLAGS_CPU", ZPROF_FLAGS_CPU, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("ZPROF_FLAGS_MEMORY", ZPROF_FLAGS_MEMORY, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("ZPROF_FLAGS_NO_BUILTINS", ZPROF_FLAGS_NO_BUILTINS, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("ZPROF_FLAGS_NO_USERLAND", ZPROF_FLAGS_NO_USERLAND, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("ZPROF_FLAGS_NO_COMPILE", ZPROF_FLAGS_NO_COMPILE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("ZPROF_FLAGS_NO_HIERACHICAL", ZPROF_FLAGS_NO_HIERACHICAL, CONST_CS | CONST_PERSISTENT);
}

/**
 * A hash function to calculate a 8-bit hash code for a function name.
 * This is based on a small modification to 'zend_inline_hash_func' by summing
 * up all bytes of the ulong returned by 'zend_inline_hash_func'.
 *
 * @param str, char *, string to be calculated hash code for.
 *
 * @author cjiang
 */
static inline uint8 hp_inline_hash(char *arKey)
{
    size_t nKeyLength = strlen(arKey);
    register uint8 hash = 0;

    /* variant with the hash unrolled eight times */
    for (; nKeyLength >= 8; nKeyLength -= 8)
    {
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
    }
    switch (nKeyLength)
    {
    case 7:
        hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
    case 6:
        hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
    case 5:
        hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
    case 4:
        hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
    case 3:
        hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
    case 2:
        hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
    case 1:
        hash = ((hash << 5) + hash) + *arKey++;
        break;
    case 0:
        break;
        EMPTY_SWITCH_DEFAULT_CASE()
    }
    return hash;
}

/**
 * Parse the list of ignored functions from the zval argument.
 *
 * @author mpal
 */
static void hp_parse_options_from_arg(zval *args TSRMLS_DC)
{
    hp_clean_profiler_options_state(TSRMLS_C);

    if (args == NULL)
    {
        return;
    }

    zval *zresult = NULL;

    zresult = hp_zval_at_key("ignored_functions", sizeof("ignored_functions"), args);

    if (zresult == NULL)
    {
        zresult = hp_zval_at_key("functions", sizeof("functions"), args);
        if (zresult != NULL)
        {
            ZP_G(filtered_type) = 2; // whitelist
        }
    }
    else
    {
        ZP_G(filtered_type) = 1; // blacklist
    }

    ZP_G(filtered_functions) = hp_function_map_create(hp_strings_in_zval(zresult));
}

static inline hp_function_map *hp_function_map_create(char **names)
{
    if (names == NULL)
    {
        return NULL;
    }

    hp_function_map *map;

    map = emalloc(sizeof(hp_function_map));
    map->names = names;

    memset(map->filter, 0, ZPROF_FILTERED_FUNCTION_SIZE);

    int i = 0;
    for (; names[i] != NULL; i++)
    {
        char *str = names[i];
        uint8 hash = hp_inline_hash(str);
        int idx = INDEX_2_BYTE(hash);
        map->filter[idx] |= INDEX_2_BIT(hash);
    }

    return map;
}

static inline void hp_function_map_clear(hp_function_map *map)
{
    if (map == NULL)
    {
        return;
    }

    hp_array_del(map->names);
    map->names = NULL;

    memset(map->filter, 0, ZPROF_FILTERED_FUNCTION_SIZE);
    efree(map);
}

static inline int hp_function_map_exists(hp_function_map *map, uint8 hash_code, char *curr_func)
{
    if (hp_function_map_filter_collision(map, hash_code))
    {
        int i = 0;
        for (; map->names[i] != NULL; i++)
        {
            char *name = map->names[i];
            if (strcmp(curr_func, name) == 0)
            {
                return 1;
            }
        }
    }

    return 0;
}

static inline int hp_function_map_filter_collision(hp_function_map *map, uint8 hash)
{
    uint8 mask = INDEX_2_BIT(hash);
    return map->filter[INDEX_2_BYTE(hash)] & mask;
}

static inline void hp_free_trace_cb(void *p) {}

int hp_trace_callbacks_filter_exist(uint8 hash TSRMLS_DC)
{
    uint8 mask = INDEX_2_BIT(hash);
    return ZP_G(trace_callbacks_filter)[INDEX_2_BYTE(hash)] & mask;
}

void hp_init_trace_callbacks_filter(char *str TSRMLS_DC)
{
    if(str) {
        uint8 hash = hp_inline_hash(str);
        int idx = INDEX_2_BYTE(hash);
        ZP_G(trace_callbacks_filter)[idx] |= INDEX_2_BIT(hash);
    }
}

void hp_init_trace_callbacks(TSRMLS_D)
{
    zp_trace_callback cb;

    ZP_G(trace_callbacks) = NULL;

    ALLOC_HASHTABLE(ZP_G(trace_callbacks));
    zend_hash_init(ZP_G(trace_callbacks), 255, NULL, hp_free_trace_cb, 0);

    //cb = zp_trace_callback_file_get_contents;
    //register_trace_callback("file_get_contents", cb);

    cb = zp_trace_callback_curl_exec;
    register_trace_callback("curl_exec", cb);

    cb = zp_trace_callback_sql_functions;
#if HAVE_PDO
    register_trace_callback("PDO::exec", cb);
    register_trace_callback("PDO::query", cb);
#endif
    //register_trace_callback("mysql_query", cb);
    register_trace_callback("mysqli_query", cb);
    register_trace_callback("mysqli::query", cb);
    //register_trace_callback("mysqli::prepare", cb);
    //register_trace_callback("mysqli_prepare", cb);

    //cb = zp_trace_callback_sql_commit;
#if HAVE_PDO
    //register_trace_callback("PDO::commit", cb);
#endif
    //register_trace_callback("mysqli::commit", cb);
    //register_trace_callback("mysqli_commit", cb);

    //cb = zp_trace_callback_mysqli_connect;
    //register_trace_callback("mysql_connect", cb);
    //register_trace_callback("mysqli_connect", cb);
    //register_trace_callback("mysqli::mysqli", cb);

#if HAVE_PDO
    //cb = zp_trace_callback_pdo_connect;
    //register_trace_callback("PDO::__construct", cb);

    //cb = zp_trace_callback_pdo_stmt_execute;
    //register_trace_callback("PDOStatement::execute", cb);
#endif

    //cb = zp_trace_callback_mysqli_stmt_execute;
    //register_trace_callback("mysqli_stmt_execute", cb);
    //register_trace_callback("mysqli_stmt::execute", cb);

    //cb = zp_trace_callback_fastcgi_finish_request;
    //register_trace_callback("fastcgi_finish_request", cb);

    //cb = zp_trace_callback_predis_call;
    //register_trace_callback("Predis\\Client::__call", cb);
}

/**
 * Initialize profiler state
 *
 * @author kannan, veeve
 */
void hp_init_profiler_state(TSRMLS_D)
{
    if (!ZP_G(ever_enabled))
    {
        ZP_G(ever_enabled) = 1;
        ZP_G(entries) = NULL;
    }

    ZP_G(stack_threshold) = INI_INT("zprof.stack_threshold");

    if (ZP_G(stats_count))
    {
        zval_ptr_dtor(&ZP_G(stats_count));
    }

    ALLOC_INIT_ZVAL(ZP_G(stats_count));
    array_init(ZP_G(stats_count));

    if (ZP_G(debug_trace))
    {
        zval_ptr_dtor(&ZP_G(debug_trace));
    }
    ALLOC_INIT_ZVAL(ZP_G(debug_trace));
    array_init(ZP_G(debug_trace));

    if (ZP_G(exceptions))
    {
        zval_ptr_dtor(&ZP_G(exceptions));
    }
    ALLOC_INIT_ZVAL(ZP_G(exceptions));
    array_init(ZP_G(exceptions));

    if (ZP_G(errors))
    {
        zval_ptr_dtor(&ZP_G(errors));
    }
    ALLOC_INIT_ZVAL(ZP_G(errors));
    array_init(ZP_G(errors));

    if (ZP_G(trace))
    {
        zval_ptr_dtor(&ZP_G(trace));
    }
    ALLOC_INIT_ZVAL(ZP_G(trace));
    array_init(ZP_G(trace));

    if (ZP_G(etimes))
    {
        zval_ptr_dtor(&ZP_G(etimes));
    }
    ALLOC_INIT_ZVAL(ZP_G(etimes));
    array_init(ZP_G(etimes));

    // 重置布隆过滤器
    memset(ZP_G(trace_callbacks_filter), 0, ZPROF_FILTERED_FUNCTION_SIZE);

    hp_init_trace_callbacks(TSRMLS_C);

    ZP_G(compile_count) = 0;
    ZP_G(compile_wt) = 0;
}

/**
 * Cleanup profiler state
 *
 * @author kannan, veeve
 */
void hp_clean_profiler_state(TSRMLS_D)
{
    if (ZP_G(stats_count))
    {
        zval_ptr_dtor(&ZP_G(stats_count));
        ZP_G(stats_count) = NULL;
    }

    if (ZP_G(debug_trace))
    {
        zval_ptr_dtor(&ZP_G(debug_trace));
        ZP_G(debug_trace) = NULL;
    }

    if (ZP_G(exceptions))
    {
        zval_ptr_dtor(&ZP_G(exceptions));
        ZP_G(exceptions) = NULL;
    }

    if (ZP_G(errors))
    {
        zval_ptr_dtor(&ZP_G(errors));
        ZP_G(errors) = NULL;
    }

    if (ZP_G(trace))
    {
        zval_ptr_dtor(&ZP_G(trace));
        ZP_G(trace) = NULL;
    }

    if (ZP_G(etimes))
    {
        zval_ptr_dtor(&ZP_G(etimes));
        ZP_G(etimes) = NULL;
    }

    ZP_G(entries) = NULL;
    ZP_G(ever_enabled) = 0;
    ZP_G(function_nums) = 0;

    hp_clean_profiler_options_state(TSRMLS_C);
}

static void hp_clean_profiler_options_state(TSRMLS_D)
{
    hp_function_map_clear(ZP_G(filtered_functions));
    ZP_G(filtered_functions) = NULL;

    if (ZP_G(trace_callbacks))
    {
        zend_hash_destroy(ZP_G(trace_callbacks));
        FREE_HASHTABLE(ZP_G(trace_callbacks));
        ZP_G(trace_callbacks) = NULL;
    }

    memset(ZP_G(trace_callbacks_filter), 0, ZPROF_FILTERED_FUNCTION_SIZE);
}

/*
 * Start profiling - called just before calling the actual function
 * NOTE:  PLEASE MAKE SURE TSRMLS_CC IS AVAILABLE IN THE CONTEXT
 *        OF THE FUNCTION WHERE THIS MACRO IS CALLED.
 *        TSRMLS_CC CAN BE MADE AVAILABLE VIA TSRMLS_DC IN THE
 *        CALLING FUNCTION OR BY CALLING TSRMLS_FETCH()
 *        TSRMLS_FETCH() IS RELATIVELY EXPENSIVE.
 */
#define BEGIN_PROFILING(entries, symbol, profile_curr, execute_data)                 \
    do                                                                               \
    {                                                                                \
        /* Use a hash code to filter most of the string comparisons. */              \
        uint8 hash_code = hp_inline_hash(symbol);                                    \
        profile_curr = !hp_filter_entry(hash_code, symbol TSRMLS_CC);                \
        if (profile_curr)                                                            \
        {                                                                            \
            hp_entry_t *cur_entry = hp_fast_alloc_hprof_entry(TSRMLS_C);             \
            (cur_entry)->hash_code = hash_code;                                      \
            (cur_entry)->name_hprof = symbol;                                        \
            (cur_entry)->debugtrace = NULL;                                          \
            (cur_entry)->seq_no = ZP_G(function_nums);                                \
            (cur_entry)->prev_hprof = (*(entries));                                  \
            hp_mode_hier_beginfn_cb((entries), (cur_entry), execute_data TSRMLS_CC); \
            /* Update entries linked list */                                         \
            (*(entries)) = (cur_entry);                                              \
        }                                                                            \
    } while (0)

/*
 * Stop profiling - called just after calling the actual function
 * NOTE:  PLEASE MAKE SURE TSRMLS_CC IS AVAILABLE IN THE CONTEXT
 *        OF THE FUNCTION WHERE THIS MACRO IS CALLED.
 *        TSRMLS_CC CAN BE MADE AVAILABLE VIA TSRMLS_DC IN THE
 *        CALLING FUNCTION OR BY CALLING TSRMLS_FETCH()
 *        TSRMLS_FETCH() IS RELATIVELY EXPENSIVE.
 */
#define END_PROFILING(entries, profile_curr, data)              \
    do                                                          \
    {                                                           \
        if (profile_curr)                                       \
        {                                                       \
            hp_entry_t *cur_entry;                              \
            hp_mode_hier_endfn_cb((entries), data TSRMLS_CC);   \
            cur_entry = (*(entries));                           \
            /* Free top entry and update entries linked list */ \
            (*(entries)) = (*(entries))->prev_hprof;            \
            hp_fast_free_hprof_entry(cur_entry TSRMLS_CC);      \
        }                                                       \
    } while (0)

/**
 * Returns formatted function name
 *
 * @param  entry        hp_entry
 * @param  result_buf   ptr to result buf
 * @param  result_len   max size of result buf
 * @return total size of the function name returned in result_buf
 * @author veeve
 */
size_t hp_get_entry_name(hp_entry_t *entry, char *result_buf, size_t result_len)
{
    /* Validate result_len */
    if (result_len <= 1)
    {
        /* Insufficient result_bug. Bail! */
        return 0;
    }

    /* Add '@recurse_level' if required */
    /* NOTE:  Dont use snprintf's return val as it is compiler dependent */
    if (entry->rlvl_hprof)
    {
        snprintf(
            result_buf,
            result_len,
            "%s@%d",
            entry->name_hprof,
            entry->rlvl_hprof);
    }
    else
    {
        strncat(
            result_buf,
            entry->name_hprof,
            result_len);
    }

    /* Force null-termination at MAX */
    result_buf[result_len - 1] = '\0';

    return strlen(result_buf);
}

/**
 * Check if this entry should be filtered (positive or negative), first with a
 * conservative Bloomish filter then with an exact check against the function
 * names.
 *
 * @author mpal
 */
static inline int hp_filter_entry(uint8 hash_code, char *curr_func TSRMLS_DC)
{
    int exists;

    /* First check if ignoring functions is enabled */
    if (ZP_G(filtered_functions) == NULL || ZP_G(filtered_type) == 0)
    {
        return 0;
    }

    exists = hp_function_map_exists(ZP_G(filtered_functions), hash_code, curr_func);

    if (ZP_G(filtered_type) == 2)
    {
        // always include main() in profiling result.
        return (strcmp(curr_func, ROOT_SYMBOL) == 0)
                   ? 0
                   : abs(1 - exists);
    }

    return exists;
}

/**
 * Build a caller qualified name for a callee.
 *
 * For example, if A() is caller for B(), then it returns "A==>B".
 * Recursive invokations are denoted with @<n> where n is the recursion
 * depth.
 *
 * For example, "foo==>foo@1", and "foo@2==>foo@3" are examples of direct
 * recursion. And  "bar==>foo@1" is an example of an indirect recursive
 * call to foo (implying the foo() is on the call stack some levels
 * above).
 *
 * @author kannan, veeve
 */
size_t hp_get_function_stack(hp_entry_t *entry, int level, char *result_buf, size_t result_len)
{
    size_t len = 0;

    if (!entry->prev_hprof || (level <= 1))
    {
        return hp_get_entry_name(entry, result_buf, result_len);
    }

    len = hp_get_function_stack(entry->prev_hprof, level - 1, result_buf, result_len);

    /* Append the delimiter */
#define HP_STACK_DELIM "==>"
#define HP_STACK_DELIM_LEN (sizeof(HP_STACK_DELIM) - 1)

    if (result_len < (len + HP_STACK_DELIM_LEN))
    {
        return len;
    }

    if (len)
    {
        strncat(result_buf + len, HP_STACK_DELIM, result_len - len);
        len += HP_STACK_DELIM_LEN;
    }

#undef HP_STACK_DELIM_LEN
#undef HP_STACK_DELIM

    return len + hp_get_entry_name(entry, result_buf + len, result_len - len);
}

/**
 * Takes an input of the form /a/b/c/d/foo.php and returns
 * a pointer to one-level directory and basefile name
 * (d/foo.php) in the same string.
 */
static char *hp_get_base_filename(char *filename)
{
    char *ptr;
    int found = 0;

    if (!filename)
        return "";

    /* reverse search for "/" and return a ptr to the next char */
    for (ptr = filename + strlen(filename) - 1; ptr >= filename; ptr--)
    {
        if (*ptr == '/')
        {
            found++;
        }
        if (found == 2)
        {
            return ptr + 1;
        }
    }

    /* no "/" char found, so return the whole string */
    return filename;
}

static char *hp_get_file_summary(char *filename, int filename_len TSRMLS_DC)
{
    php_url *url;
    char *ret;
    int len;

    len = ZPROF_MAX_ARGUMENT_LEN;
    ret = emalloc(len);
    snprintf(ret, len, "");

    url = php_url_parse_ex(filename, filename_len);

    if (url == NULL)
    {
        return ret;
    }

    if (url->scheme)
    {
        snprintf(ret, len, "%s%s://", ret, url->scheme);
    }
    else
    {
        php_url_free(url);
        return ret;
    }

    if (url->host)
    {
        snprintf(ret, len, "%s%s", ret, url->host);
    }

    if (url->port)
    {
        snprintf(ret, len, "%s:%d", ret, url->port);
    }

    if (url->path)
    {
        snprintf(ret, len, "%s%s", ret, url->path);
    }

    php_url_free(url);

    return ret;
}

static char *hp_concat_char(const char *s1, size_t len1, const char *s2, size_t len2, const char *seperator, size_t sep_len)
{
    char *result = emalloc(len1 + len2 + sep_len + 1);

    strcpy(result, s1);
    strcat(result, seperator);
    strcat(result, s2);
    result[len1 + len2 + sep_len] = '\0';

    return result;
}

/**
 * Get the name of the current function. The name is qualified with
 * the class name if the function is in a class.
 *
 * @author kannan, hzhao
 */
static char *hp_get_function_name(zend_execute_data *data TSRMLS_DC)
{
    const char *cls = NULL;
    char *ret = NULL;
    zend_function *curr_func;

    if (!data)
    {
        return NULL;
    }

    const char *func = NULL;
    curr_func = data->function_state.function;
    func = curr_func->common.function_name;

    if (!func)
    {
        // This branch includes execution of eval and include/require(_once) calls
        // We assume it is not 1999 anymore and not much PHP code runs in the
        // body of a file and if it is, we are ok with adding it to the caller's wt.
        return NULL;
    }

    /* previously, the order of the tests in the "if" below was
     * flipped, leading to incorrect function names in profiler
     * reports. When a method in a super-type is invoked the
     * profiler should qualify the function name with the super-type
     * class name (not the class name based on the run-time type
     * of the object.
     */
    if (curr_func->common.scope)
    {
        cls = curr_func->common.scope->name;
    }
    else if (data->object)
    {
        cls = Z_OBJCE(*data->object)->name;
    }

    if (cls)
    {
        char *sep = "::";
        ret = hp_concat_char(cls, strlen(cls), func, strlen(func), sep, 2);
    }
    else
    {
        ret = estrdup(func);
    }

    return ret;
}

/**
 * Free any items in the free list.
 */
static void hp_free_the_free_list(TSRMLS_D)
{
    hp_entry_t *p = ZP_G(entry_free_list);
    hp_entry_t *cur;

    while (p)
    {
        cur = p;
        p = p->prev_hprof;
        free(cur);
    }
}

/**
 * Fast allocate a hp_entry_t structure. Picks one from the
 * free list if available, else does an actual allocate.
 *
 * Doesn't bother initializing allocated memory.
 *
 * @author kannan
 */
static hp_entry_t *hp_fast_alloc_hprof_entry(TSRMLS_D)
{
    hp_entry_t *p;

    p = ZP_G(entry_free_list);

    if (p)
    {
        ZP_G(entry_free_list) = p->prev_hprof;
        return p;
    }
    else
    {
        return (hp_entry_t *)malloc(sizeof(hp_entry_t));
    }
}

/**
 * Fast free a hp_entry_t structure. Simply returns back
 * the hp_entry_t to a free list and doesn't actually
 * perform the free.
 *
 * @author kannan
 */
static void hp_fast_free_hprof_entry(hp_entry_t *p TSRMLS_DC)
{
    /* we use/overload the prev_hprof field in the structure to link entries in
     * the free list. */
    p->prev_hprof = ZP_G(entry_free_list);
    ZP_G(entry_free_list) = p;
}

/**
 * Increment the count of the given stat with the given count
 * If the stat was not set before, inits the stat to the given count
 *
 * @param  zval *counts   Zend hash table pointer
 * @param  char *name     Name of the stat
 * @param  long  count    Value of the stat to incr by
 * @return void
 * @author kannan
 */
void hp_inc_count(zval *counts, char *name, long count TSRMLS_DC)
{
    HashTable *ht;
    zval *data, val;

    if (!counts)
    {
        return;
    }

    ht = HASH_OF(counts);

    if (!ht)
    {
        return;
    }

    data = zend_compat_hash_find_const(ht, name, strlen(name));

    if (data)
    {
        ZVAL_LONG(data, Z_LVAL_P(data) + count);
    }
    else
    {
        add_assoc_long(counts, name, count);
    }
}

/**
 * ***********************
 * High precision timer related functions.
 * ***********************
 */

/**
 * Get the current wallclock timer
 *
 * @return 64 bit unsigned integer
 * @author cjiang
 */
static uint64 cycle_timer()
{
#ifdef __APPLE__
    return mach_absolute_time();
#else
    struct timespec s;
    clock_gettime(CLOCK_MONOTONIC, &s);

    return s.tv_sec * 1000000 + s.tv_nsec / 1000;
#endif
}

/**
 * Get the current real CPU clock timer
 */
static uint64 cpu_timer()
{
#if defined(CLOCK_PROCESS_CPUTIME_ID)
    struct timespec s;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &s);

    return s.tv_sec * 1000000 + s.tv_nsec / 1000;
#else
    struct rusage ru;

    getrusage(RUSAGE_SELF, &ru);

    return ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec +
           ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec;
#endif
}

/**
 * Get time delta in microseconds.
 */
static long get_us_interval(struct timeval *start, struct timeval *end)
{
    return (((end->tv_sec - start->tv_sec) * 1000000) + (end->tv_usec - start->tv_usec));
}

/**
 * Convert from TSC counter values to equivalent microseconds.
 *
 * @param uint64 count, TSC count value
 * @return 64 bit unsigned integer
 *
 * @author cjiang
 */
static inline double get_us_from_tsc(uint64 count TSRMLS_DC)
{
    return count / ZP_G(timebase_factor);
}

/**
 * Get the timebase factor necessary to divide by in cycle_timer()
 */
static double get_timebase_factor()
{
#ifdef __APPLE__
    mach_timebase_info_data_t sTimebaseInfo;
    (void)mach_timebase_info(&sTimebaseInfo);

    return (sTimebaseInfo.numer / sTimebaseInfo.denom) * 1000;
#else
    return 1.0;
#endif
}

/**
 * ZPROF_MODE_HIERARCHICAL's begin function callback
 *
 * @author kannan
 */
void hp_mode_hier_beginfn_cb(hp_entry_t **entries, hp_entry_t *current, zend_execute_data *data TSRMLS_DC)
{
    hp_entry_t *p;
    zp_trace_callback *callback;
    int recurse_level = 0;

    if (data != NULL)
    {
        if (hp_trace_callbacks_filter_exist(current->hash_code TSRMLS_CC) && zend_hash_find(ZP_G(trace_callbacks), current->name_hprof, strlen(current->name_hprof) + 1, (void **)&callback) == SUCCESS)
        {
            (*callback)(current->name_hprof, data TSRMLS_CC);
        }
    }

    if ((ZP_G(zprof_flags) & ZPROF_FLAGS_NO_HIERACHICAL) == 0)
    {
        if (ZP_G(func_hash_counters)[current->hash_code] > 0)
        {
            /* Find this symbols recurse level */
            for (p = (*entries); p; p = p->prev_hprof)
            {
                if (!strcmp(current->name_hprof, p->name_hprof))
                {
                    recurse_level = (p->rlvl_hprof) + 1;
                    break;
                }
            }
        }
        ZP_G(func_hash_counters)[current->hash_code]++;

        /* Init current function's recurse level */
        current->rlvl_hprof = recurse_level;

        /* Get CPU usage */
        if (ZP_G(zprof_flags) & ZPROF_FLAGS_CPU)
        {
            current->cpu_start = cpu_timer();
        }

        /* Get memory usage */
        if (ZP_G(zprof_flags) & ZPROF_FLAGS_MEMORY)
        {
            current->mu_start_hprof = zend_memory_usage(0 TSRMLS_CC);
            current->pmu_start_hprof = zend_memory_peak_usage(0 TSRMLS_CC);
        }
    }

    /* Get start tsc counter */
    current->tsc_start = cycle_timer();
}

/**
 * **********************************
 * ZPROF END FUNCTION CALLBACKS
 * **********************************
 */

/**
 * ZPROF_MODE_HIERARCHICAL's end function callback
 *
 * @author kannan
 */
void hp_mode_hier_endfn_cb(hp_entry_t **entries, zend_execute_data *data TSRMLS_DC)
{
    hp_entry_t *top = (*entries);
    zval *counts, count_val;
    char symbol[SCRATCH_BUF_LEN] = "";
    long int mu_end;
    long int pmu_end;
    uint64 tsc_end;
    double wt, cpu;
    zp_trace_callback *callback;
    HashTable *ht;

    zval *trace, *tmp;
    int i, len;

    /* Get the stat array */
    hp_get_function_stack(top, 2, symbol, sizeof(symbol));

    // 将函数参数和返回值,写入ZP_G(debug_trace)中
    if(top->debugtrace) {
        add_assoc_string(*top->debugtrace, "function_name", symbol, 1);

        zend_hash_index_update(
                Z_ARRVAL_P(ZP_G(debug_trace)), 
                (long)top->seq_no, 
                top->debugtrace, 
                sizeof(zval *), 
                NULL);
    }

    /* Get end tsc counter */
    tsc_end = cycle_timer();
    wt = get_us_from_tsc(tsc_end - top->tsc_start TSRMLS_CC);

    // 记录 curl、sql 函数的执行时间
    ht = Z_ARRVAL_P(ZP_G(etimes));
    if (zend_hash_index_exists(ht, ZP_G(function_nums)))
    {
        MAKE_STD_ZVAL(tmp);
        ZVAL_LONG(tmp, wt);
        zend_hash_index_update(ht, ZP_G(function_nums), (void *) &tmp, sizeof(zval *), NULL);
    }

    // 可以考虑只记录执行时间大于 stack_threshold 微妙的函数，wt 的单位为 微妙
    if (wt < ZP_G(stack_threshold))
    {
       ZP_G(func_hash_counters)[top->hash_code]--;
       return ;
    }

    if (ZP_G(zprof_flags) & ZPROF_FLAGS_CPU)
    {
        cpu = get_us_from_tsc(cpu_timer() - top->cpu_start TSRMLS_CC);
    }

    if ((ZP_G(zprof_flags) & ZPROF_FLAGS_NO_HIERACHICAL) > 0)
    {
        return;
    }

    counts = zend_compat_hash_find_const(Z_ARRVAL_P(ZP_G(stats_count)), symbol, strlen(symbol));

    if (counts == NULL)
    {
        MAKE_STD_ZVAL(counts);
        array_init(counts);
        zend_hash_update(Z_ARRVAL_P(ZP_G(stats_count)), symbol, strlen(symbol) + 1, &counts, sizeof(zval *), NULL);
    }

    /* Bump stats in the counts hashtable */
    hp_inc_count(counts, "ct", 1 TSRMLS_CC);
    hp_inc_count(counts, "wt", wt TSRMLS_CC);

    if (ZP_G(zprof_flags) & ZPROF_FLAGS_CPU)
    {
        /* Bump CPU stats in the counts hashtable */
        hp_inc_count(counts, "cpu", cpu TSRMLS_CC);
    }

    if (ZP_G(zprof_flags) & ZPROF_FLAGS_MEMORY)
    {
        /* Get Memory usage */
        mu_end = zend_memory_usage(0 TSRMLS_CC);
        pmu_end = zend_memory_peak_usage(0 TSRMLS_CC);

        /* Bump Memory stats in the counts hashtable */
        hp_inc_count(counts, "mu", mu_end - top->mu_start_hprof TSRMLS_CC);
        hp_inc_count(counts, "pmu", pmu_end - top->pmu_start_hprof TSRMLS_CC);
    }

    ZP_G(func_hash_counters)[top->hash_code]--;
    
}

/**
 * ***************************
 * PHP EXECUTE/COMPILE PROXIES
 * ***************************
 */

/**
 * Zprof enable replaced the zend_execute function with this
 * new execute function. We can do whatever profiling we need to
 * before and after calling the actual zend_execute().
 *
 * @author hzhao, kannan
 */
#if PHP_VERSION_ID < 50500
ZEND_DLEXPORT void hp_execute(zend_op_array *ops TSRMLS_DC)
{
    zend_execute_data *execute_data = EG(current_execute_data);
    zend_execute_data *real_execute_data = execute_data;
#else
ZEND_DLEXPORT void hp_execute_ex(zend_execute_data *execute_data TSRMLS_DC)
{
    zend_op_array *ops = execute_data->op_array;
    zend_execute_data *real_execute_data = execute_data->prev_execute_data;
#endif
    char *func = NULL;
    int hp_profile_flag = 1;
    int argNum = 0;
    int i = 0;
    zval *argument;
    zval *result;
    zval *counts;
    hp_entry_t *cur_entry; 
    zval *function_argument = NULL;
    zval *function_result = NULL;

    if (!ZP_G(enabled))
    {
#if PHP_VERSION_ID < 50500
        _zend_execute(ops TSRMLS_CC);
#else
        _zend_execute_ex(execute_data TSRMLS_CC);
#endif
        return;
    }

    // 函数调用总次数加1
    ZP_G(function_nums)++;

    func = hp_get_function_name(real_execute_data TSRMLS_CC);

    if (!func)
    {
#if PHP_VERSION_ID < 50500
        _zend_execute(ops TSRMLS_CC);
#else
        _zend_execute_ex(execute_data TSRMLS_CC);
#endif
        return;
    } 

    if ((ZP_G(zprof_flags) & ZPROF_FLAGS_NO_USERLAND) > 0)
    {
#if PHP_VERSION_ID < 50500
        _zend_execute(ops TSRMLS_CC);
#else
        _zend_execute_ex(execute_data TSRMLS_CC);
#endif
        efree(func);
        return;
    }

    BEGIN_PROFILING(&ZP_G(entries), func, hp_profile_flag, real_execute_data);

    // 如果是指定的追踪函数，获取函数参数
    if(ZP_G(trace_on) && ZP_G(trace_func) && strcmp(strtolower(ZP_G(trace_func)), strtolower(func)) == 0) {
        argNum = ZEND_CALL_NUM_ARGS(real_execute_data);
        if (hp_profile_flag && argNum > 0) { // 该函数不在过滤列表里，并且参数个数大于0
            MAKE_STD_ZVAL(function_argument);
            array_init(function_argument);
            for (i = 0; i < argNum; i++) {
                argument = ZEND_CALL_ARG(real_execute_data, i + 1);
                zp_add_array_from_ptr(argument, function_argument);
            }
        }
    }

#if PHP_VERSION_ID < 50500
    _zend_execute(ops TSRMLS_CC);
#else
    _zend_execute_ex(execute_data TSRMLS_CC);
#endif
    
    // 如果是指定的追踪函数，获取函数返回值
    if(ZP_G(trace_on) && ZP_G(trace_func) && strcmp(strtolower(ZP_G(trace_func)), strtolower(func)) == 0) {
        if(hp_profile_flag && EG(return_value_ptr_ptr)) {
            MAKE_STD_ZVAL(function_result);
            array_init(function_result);
            zval *result = (zval *)(*EG(return_value_ptr_ptr));
            zp_add_array_from_ptr(result, function_result);
        }
    }

    // 如果有函数参数或函数返回值,记录到hp_entry_t
    if(function_result || function_argument) {
        MAKE_STD_ZVAL(counts);
        array_init(counts);

        if(function_argument) {
            add_assoc_zval(counts, "arguments", function_argument);
        }
        if(function_result) {
            add_assoc_zval(counts, "result", function_result);
        }

        // 如果调用栈顶有数据,并且该函数不在过滤列表里
        if(ZP_G(entries) && hp_profile_flag) {
            ZP_G(entries)->debugtrace = &counts;
        } else {
            // 释放arguments、result、counts
            if(function_argument) {
                zval_ptr_dtor(&function_argument);
            }
            if(function_result) {
                zval_ptr_dtor(&function_result);
            }
            zval_ptr_dtor(&counts);
        }
    }

    if (ZP_G(entries))
    {
        END_PROFILING(&ZP_G(entries), hp_profile_flag, real_execute_data);
    }

    efree(func);
}

#undef EX
#define EX(element) ((execute_data)->element)

/**
 * Very similar to hp_execute. Proxy for zend_execute_internal().
 * Applies to zend builtin functions.
 *
 * @author hzhao, kannan
 */

#if PHP_VERSION_ID < 50500
#define EX_T(offset) (*(temp_variable *)((char *)EX(Ts) + offset))

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data,
                                       int ret TSRMLS_DC)
{
#else
#define EX_T(offset) (*EX_TMP_VAR(execute_data, offset))

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data,
                                       struct _zend_fcall_info *fci, int ret TSRMLS_DC)
{
#endif
    char *func = NULL;
    int hp_profile_flag = 1;
    int argNum = 0;
    zval *argument, *result, *counts;
    int i = 0;
    hp_entry_t *cur_entry; 
    zval *function_argument = NULL;
    zval *function_result = NULL;
    const zend_op        *cur_opcode;

    if (!ZP_G(enabled) || (ZP_G(zprof_flags) & ZPROF_FLAGS_NO_BUILTINS) > 0)
    {
#if PHP_VERSION_ID < 50500
        execute_internal(execute_data, ret TSRMLS_CC);
#else
    execute_internal(execute_data, fci, ret TSRMLS_CC);
#endif
        return;
    }

    // 函数调用总次数加1
    ZP_G(function_nums)++;

    func = hp_get_function_name(execute_data TSRMLS_CC);

    if (func)
    {
        BEGIN_PROFILING(&ZP_G(entries), func, hp_profile_flag, execute_data);

        // 如果是指定的追踪函数，获取函数参数
        if(ZP_G(trace_on) && ZP_G(trace_func) && strcmp(strtolower(ZP_G(trace_func)), strtolower(func)) == 0) {
            argNum = ZEND_CALL_NUM_ARGS(execute_data);
            if (hp_profile_flag && argNum > 0) { // 该函数不在过滤列表里，并且参数个数大于0
                MAKE_STD_ZVAL(function_argument);
                array_init(function_argument);
                for (i = 0; i < argNum; i++) {
                    argument = ZEND_CALL_ARG(execute_data, i + 1);
                    zp_add_array_from_ptr(argument, function_argument);
                }
            } 
        }
    }

    if (!_zend_execute_internal)
    {
#if PHP_VERSION_ID < 50500
        execute_internal(execute_data, ret TSRMLS_CC);
#else
        execute_internal(execute_data, fci, ret TSRMLS_CC);
#endif
    }
    else
    {
        /* call the old override */
#if PHP_VERSION_ID < 50500
        _zend_execute_internal(execute_data, ret TSRMLS_CC);
#else
        _zend_execute_internal(execute_data, fci, ret TSRMLS_CC);
#endif
    }

    if (func)
    {
        // 如果是指定的追踪函数，获取函数返回值
        if(ZP_G(trace_on) && ZP_G(trace_func) && strcmp(strtolower(ZP_G(trace_func)), strtolower(func)) == 0) {
            if(hp_profile_flag && EG(opline_ptr) && execute_data->opline) {
                MAKE_STD_ZVAL(function_result);
                array_init(function_result);
                cur_opcode = *EG(opline_ptr);
                if (cur_opcode) {
                    zval *ret = zp_zval_ptr(cur_opcode->result_type, &(cur_opcode->result), execute_data TSRMLS_CC);
                    if (ret) {
                        zp_add_array_from_ptr(ret, function_result);
                    }
                }
            }
        }

        // 如果有函数参数或函数返回值,记录到hp_entry_t
        if(function_result || function_argument) {
            MAKE_STD_ZVAL(counts);
            array_init(counts);

            if(function_argument) {
                add_assoc_zval(counts, "arguments", function_argument);
            }
            if(function_result) {
                add_assoc_zval(counts, "result", function_result);
            }

            // 如果调用栈顶有数据,并且该函数不在过滤列表里
            if(ZP_G(entries) && hp_profile_flag) {
                ZP_G(entries)->debugtrace = &counts;
            } else {
                // 释放arguments、result、counts
                if(function_argument) {
                    zval_ptr_dtor(&function_argument);
                }
                if(function_result) {
                    zval_ptr_dtor(&function_result);
                }
                zval_ptr_dtor(&counts);
            }
        }

        if (ZP_G(entries))
        {
            END_PROFILING(&ZP_G(entries), hp_profile_flag, execute_data);
        }

        efree(func);
    }
}

/**
 * Proxy for zend_compile_file(). Used to profile PHP compilation time.
 *
 * @author kannan, hzhao
 */
ZEND_DLEXPORT zend_op_array *hp_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC)
{
    if (!ZP_G(enabled) || (ZP_G(zprof_flags) & ZPROF_FLAGS_NO_COMPILE) > 0)
    {
        return _zend_compile_file(file_handle, type TSRMLS_CC);
    }

    zend_op_array *ret;
    uint64 start = cycle_timer();

    ZP_G(compile_count)++;

    ret = _zend_compile_file(file_handle, type TSRMLS_CC);

    ZP_G(compile_wt) += get_us_from_tsc(cycle_timer() - start TSRMLS_CC);

    return ret;
}

/**
 * Proxy for zend_compile_string(). Used to profile PHP eval compilation time.
 */
ZEND_DLEXPORT zend_op_array *hp_compile_string(zval *source_string, char *filename TSRMLS_DC)
{
    if (!ZP_G(enabled) || (ZP_G(zprof_flags) & ZPROF_FLAGS_NO_COMPILE) > 0)
    {
        return _zend_compile_string(source_string, filename TSRMLS_CC);
    }

    zend_op_array *ret;
    uint64 start = cycle_timer();

    ZP_G(compile_count)++;

    ret = _zend_compile_string(source_string, filename TSRMLS_CC);

    ZP_G(compile_wt) += get_us_from_tsc(cycle_timer() - start TSRMLS_CC);

    return ret;
}


/**
 * exception hook function.Get info from exception.
 */
void zp_throw_exception_hook(zval *exception TSRMLS_DC)
{
    zval *message, *file, *line, *code;
    zend_class_entry *default_ce;
    zval *counts;

    if (!exception)
    {
        return;
    }

    default_ce = zend_exception_get_default(TSRMLS_C);

    message = zend_read_property(default_ce, exception, "message", sizeof("message") - 1, 0 TSRMLS_CC);
    file = zend_read_property(default_ce, exception, "file", sizeof("file") - 1, 0 TSRMLS_CC);
    line = zend_read_property(default_ce, exception, "line", sizeof("line") - 1, 0 TSRMLS_CC);
    code = zend_read_property(default_ce, exception, "code", sizeof("code") - 1, 0 TSRMLS_CC);

    MAKE_STD_ZVAL(counts);
    array_init(counts);
    add_assoc_long(counts, "type", Z_LVAL_P(code));
    add_assoc_string(counts, "file", Z_STRVAL_P(file), 1);
    add_assoc_long(counts, "line", Z_LVAL_P(line));
    add_assoc_string(counts, "message", Z_STRVAL_P(message), 1);

    add_next_index_zval(ZP_G(exceptions), counts);

    if (old_throw_exception_hook)
    {
        old_throw_exception_hook(exception TSRMLS_CC);
    }
}

/**
 * Proxy for zend_error_cb(). Capture php code error.
 */
void zp_error_cb(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args)
{
    TSRMLS_FETCH();

    char *msg;
    va_list args_copy;
    zval *counts;
    char *level;

    va_copy(args_copy, args);
    vspprintf(&msg, 0, format, args_copy);
    va_end(args_copy);

    if (type == E_ERROR || type == E_PARSE || type == E_CORE_ERROR || type == E_COMPILE_ERROR || type == E_USER_ERROR || type == E_RECOVERABLE_ERROR) {
        level = "Error";
    }
    else if (type == E_WARNING || type == E_CORE_WARNING || type == E_COMPILE_WARNING || type == E_USER_WARNING) {
        level = "Warning";
    }
    else if (type == E_NOTICE || type == E_USER_NOTICE || type == E_STRICT || type == E_DEPRECATED || type == E_USER_DEPRECATED) {
        level = "Notice";
    }

    MAKE_STD_ZVAL(counts);
    array_init(counts);
    add_assoc_string(counts, "level", level, 1);
    add_assoc_long(counts, "type", type);
    add_assoc_string(counts, "file", (char *)error_filename, 1);
    add_assoc_long(counts, "line", error_lineno);
    add_assoc_string(counts, "message", msg, 1);

    add_next_index_zval(ZP_G(errors), counts);

    efree(msg);

    old_error_cb(type, error_filename, error_lineno, format, args);
}

/**
 * **************************
 * MAIN ZPROF CALLBACKS
 * **************************
 */

/**
 * This function gets called once when Zprof gets enabled.
 * It replaces all the functions like zend_execute, zend_execute_internal,
 * etc that needs to be instrumented with their corresponding proxies.
 */
static void hp_begin(long zprof_flags TSRMLS_DC)
{
    if (!ZP_G(enabled))
    {
        int hp_profile_flag = 1;

        ZP_G(enabled) = 1;
        ZP_G(zprof_flags) = (uint32)zprof_flags;

        /* one time initializations */
        hp_init_profiler_state(TSRMLS_C);

        /* start profiling from fictitious main() */
        ZP_G(root) = estrdup(ROOT_SYMBOL);
        ZP_G(start_time) = cycle_timer();

        ZP_G(cpu_start) = cpu_timer();

        BEGIN_PROFILING(&ZP_G(entries), ZP_G(root), hp_profile_flag, NULL);
    }
}

/**
 * Called at request shutdown time. Cleans the profiler's global state.
 */
static void hp_end(TSRMLS_D)
{
    /* Bail if not ever enabled */
    if (!ZP_G(ever_enabled))
    {
        return;
    }

    /* Stop profiler if enabled */
    if (ZP_G(enabled))
    {
        hp_stop(TSRMLS_C);
    }

    /* Clean up state */
    hp_clean_profiler_state(TSRMLS_C);
}

/**
 * Called from zprof_disable(). Removes all the proxies setup by
 * hp_begin() and restores the original values.
 */
static void hp_stop(TSRMLS_D)
{
    int hp_profile_flag = 1;

    /* End any unfinished calls */
    while (ZP_G(entries))
    {
        END_PROFILING(&ZP_G(entries), hp_profile_flag, NULL);
    }

    if (ZP_G(root))
    {
        efree(ZP_G(root));
        ZP_G(root) = NULL;
    }

    if (ZP_G(trace_func))
    {
        efree(ZP_G(trace_func));
        ZP_G(trace_func) = NULL;
    }

    /* Stop profiling */
    ZP_G(enabled) = 0;
}

/**
 * *****************************
 * ZPROF ZVAL UTILITY FUNCTIONS
 * *****************************
 */

/** Look in the PHP assoc array to find a key and return the zval associated
 *  with it.
 *
 *  @author mpal
 **/
static zval *hp_zval_at_key(char *key, size_t size, zval *values)
{
    if (Z_TYPE_P(values) == IS_ARRAY)
    {
        HashTable *ht = Z_ARRVAL_P(values);

        return zend_compat_hash_find_const(ht, key, size - 1);
    }

    return NULL;
}

/**
 *  Convert the PHP array of strings to an emalloced array of strings. Note,
 *  this method duplicates the string data in the PHP array.
 *
 *  @author mpal
 **/
static char **hp_strings_in_zval(zval *values)
{
    char **result;
    size_t count;
    size_t ix = 0;
    char *str;
    uint len;
    ulong idx;
    int type;
    zval **data, *val;

    if (!values)
    {
        return NULL;
    }

    if (Z_TYPE_P(values) == IS_ARRAY)
    {
        HashTable *ht;

        ht = Z_ARRVAL_P(values);
        count = zend_hash_num_elements(ht);

        if ((result =
                 (char **)emalloc(sizeof(char *) * (count + 1))) == NULL)
        {
            return result;
        }

        for (zend_hash_internal_pointer_reset(ht);
             zend_hash_has_more_elements(ht) == SUCCESS;
             zend_hash_move_forward(ht))
        {

            type = zend_hash_get_current_key_ex(ht, &str, &len, &idx, 0, NULL);
            if (type == HASH_KEY_IS_LONG)
            {
                if ((zend_hash_get_current_data(ht, (void **)&data) == SUCCESS) &&
                    Z_TYPE_PP(data) == IS_STRING &&
                    strcmp(Z_STRVAL_PP(data), ROOT_SYMBOL))
                { /* do not ignore "main" */
                    result[ix] = estrdup(Z_STRVAL_PP(data));
                    ix++;
                }
            }
            else if (type == HASH_KEY_IS_STRING)
            {
                result[ix] = estrdup(str);
                ix++;
            }
        }
    }
    else if (Z_TYPE_P(values) == IS_STRING)
    {
        if ((result = (char **)emalloc(sizeof(char *) * 2)) == NULL)
        {
            return result;
        }
        result[0] = estrdup(Z_STRVAL_P(values));
        ix = 1;
    }
    else
    {
        result = NULL;
    }

    /* NULL terminate the array */
    if (result != NULL)
    {
        result[ix] = NULL;
    }

    return result;
}

/* Free this memory at the end of profiling */
static inline void hp_array_del(char **name_array)
{
    if (name_array != NULL)
    {
        int i = 0;
        for (; name_array[i] != NULL && i < ZPROF_MAX_FILTERED_FUNCTIONS; i++)
        {
            efree(name_array[i]);
        }
        efree(name_array);
    }
}

/**
 * **********************************
 * PHP EXTENSION FUNCTION DEFINITIONS
 * **********************************
 */

/**
 * Start Zprof profiling in hierarchical mode.
 *
 * @param  long $flags  flags for hierarchical mode
 * @return void
 * @author kannan
 */
PHP_FUNCTION(zprof_enable)
{
    zend_long zprof_flags = 0;
    zval *optional_array = NULL;
    zval *trace_key = NULL, *trace_class = NULL, *trace_method = NULL;
    char *ini_zpkey;

    if (ZP_G(enabled))
    {
        hp_stop(TSRMLS_C);
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                              "|lz", &zprof_flags, &optional_array) == FAILURE)
    {
        return;
    }

    hp_parse_options_from_arg(optional_array TSRMLS_CC);

    // 获取ini配置的zpkey
    ini_zpkey = INI_STR("zprof.zpkey");

    // 默认不追踪任何函数
    ZP_G(trace_on) = 0;
    ZP_G(trace_func) = NULL;

    // 获取GET参数，追踪指定函数参数及返回值
    if(PG(http_globals)[TRACK_VARS_GET] && zend_hash_num_elements(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_GET]))) 
    {
        // 获取trace key,只有trace key与设置的一样，才会追踪指定函数
        trace_key = zend_compat_hash_find_const(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_GET]), "zp_key", sizeof("zp_key") - 1);

        // 判断GET传递的zpkey与ini配置的zpkey是否一样，如果相等，打开追踪函数开关
        if(trace_key && Z_TYPE_P(trace_key) == IS_STRING && Z_STRLEN_P(trace_key) && strcmp(ini_zpkey, Z_STRVAL_P(trace_key)) == 0) 
        {
            ZP_G(trace_on) = 1;
        }

        if(ZP_G(trace_on)) 
        {
            // 获取需要追踪的类名
            trace_class = zend_compat_hash_find_const(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_GET]), "zp_class", sizeof("zp_class") - 1);

            // 获取需要追踪的函数名
            trace_method = zend_compat_hash_find_const(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_GET]), "zp_method", sizeof("zp_method") - 1);
            
            if(trace_class && Z_TYPE_P(trace_class) == IS_STRING && Z_STRLEN_P(trace_class) && trace_method && Z_TYPE_P(trace_method) == IS_STRING && Z_STRLEN_P(trace_method)) {
                ZP_G(trace_func) = hp_concat_char(Z_STRVAL_P(trace_class), Z_STRLEN_P(trace_class), Z_STRVAL_P(trace_method), Z_STRLEN_P(trace_method), "::", 2);
            } else if(trace_method && Z_TYPE_P(trace_method) == IS_STRING && Z_STRLEN_P(trace_method)) {
                ZP_G(trace_func) = estrdup(Z_STRVAL_P(trace_method));
            }

        }
    }

    hp_begin(zprof_flags TSRMLS_CC);
}

/**
 * Stops Zprof from profiling  and returns the profile info.
 *
 * @param  void
 * @return array  hash-array of Zprof's profile info
 * @author cjiang
 */
PHP_FUNCTION(zprof_disable)
{
    if (!ZP_G(enabled))
    {
        return;
    }

    hp_stop(TSRMLS_C);

    // 把返回值初始化为数组
    array_init(return_value);

    add_assoc_zval(return_value, "profile", ZP_G(stats_count));
    add_assoc_zval(return_value, "debugtrace", ZP_G(debug_trace));
    //add_assoc_zval(return_value, "exception", ZP_G(exceptions));
    //add_assoc_zval(return_value, "error", ZP_G(errors));
    add_assoc_zval(return_value, "trace", ZP_G(trace));
    add_assoc_zval(return_value, "etimes", ZP_G(etimes));

    return;
}
