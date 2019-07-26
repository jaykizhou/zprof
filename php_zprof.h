/*
 *  Copyright (c) 2009 Facebook
 *  Copyright (c) 2014-2016 Qafoo GmbH
 *  Copyright (c) 2016-2017 Tideway GmbH
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

#ifndef PHP_ZPROF_H
#define PHP_ZPROF_H

extern zend_module_entry zprof_module_entry;
#define phpext_zprof_ptr &zprof_module_entry

#ifdef PHP_WIN32
#define PHP_ZPROF_API __declspec(dllexport)
#else
#define PHP_ZPROF_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

/* zprof version                           */
#define ZPROF_VERSION       "19.07.1"

/* Fictitious function name to represent top of the call tree. The paranthesis
 * in the name is to ensure we don't conflict with user function names.  */
#define ROOT_SYMBOL                "main()"

/* Size of a temp scratch buffer            */
#define SCRATCH_BUF_LEN            512

/* Hierarchical profiling flags.
 *
 * Note: Function call counts and wall (elapsed) time are always profiled.
 * The following optional flags can be used to control other aspects of
 * profiling.
 */
#define ZPROF_FLAGS_NO_BUILTINS   0x0001 /* do not profile builtins */
#define ZPROF_FLAGS_CPU           0x0002 /* gather CPU times for funcs */
#define ZPROF_FLAGS_MEMORY        0x0004 /* gather memory usage for funcs */
#define ZPROF_FLAGS_NO_USERLAND   0x0008 /* do not profile userland functions */
#define ZPROF_FLAGS_NO_COMPILE    0x0010 /* do not profile require/include/eval */
#define ZPROF_FLAGS_NO_HIERACHICAL 0x0040

/* Constant for ignoring functions, transparent to hierarchical profile */
#define ZPROF_MAX_FILTERED_FUNCTIONS  256
#define ZPROF_FILTERED_FUNCTION_SIZE                           \
               ((ZPROF_MAX_FILTERED_FUNCTIONS + 7)/8)
#define ZPROF_MAX_ARGUMENT_LEN 256

#if !defined(uint64)
typedef unsigned long long uint64;
#endif
#if !defined(uint32)
typedef unsigned int uint32;
#endif
#if !defined(uint8)
typedef unsigned char uint8;
#endif


struct _zend_string {
  char *val;
  int   len;
  int   persistent;
};
typedef struct _zend_string zend_string;
typedef long zend_long;
typedef int strsize_t;
typedef zend_uint uint32_t;

/**
 * *****************************
 * GLOBAL DATATYPES AND TYPEDEFS
 * *****************************
 */

/* Zprof maintains a stack of entries being profiled. The memory for the entry
 * is passed by the layer that invokes BEGIN_PROFILING(), e.g. the hp_execute()
 * function. Often, this is just C-stack memory.
 *
 * This structure is a convenient place to track start time of a particular
 * profile operation, recursion depth, and the name of the function being
 * profiled. */
typedef struct hp_entry_t {
    char                   *name_hprof;                       /* function name */
    int                     rlvl_hprof;        /* recursion level for function */
    uint64                  tsc_start;         /* start value for wall clock timer */
    uint64                  cpu_start;         /* start value for CPU clock timer */
    long int                mu_start_hprof;                    /* memory usage */
    long int                pmu_start_hprof;              /* peak memory usage */
    struct hp_entry_t      *prev_hprof;    /* ptr to prev entry being profiled */
    uint8                   hash_code;     /* hash_code for the function name  */
} hp_entry_t;

typedef struct hp_function_map {
    char **names;
    uint8 filter[ZPROF_FILTERED_FUNCTION_SIZE];
} hp_function_map;

/* Zprof's global state.
 *
 * This structure is instantiated once.  Initialize defaults for attributes in
 * hp_init_profiler_state() Cleanup/free attributes in
 * hp_clean_profiler_state() */
ZEND_BEGIN_MODULE_GLOBALS(hp)

    /*       ----------   Global attributes:  -----------       */

    /* Indicates if Zprof is currently enabled */
    int              enabled;

    /* Indicates if Zprof was ever enabled during this request */
    int              ever_enabled;

    /* Zprof flags */
    uint32 zprof_flags;

    /* listening functions */ 
    HashTable *trace_callbacks; 
    
    /* Holds all the Zprof statistics */
    zval            *stats_count;
    zval            *debug_trace;
    zval            *exceptions;
    zval            *errors;
    zval            *trace;

    /* Top of the profile stack */
    hp_entry_t      *entries;

    /* freelist of hp_entry_t chunks for reuse... */
    hp_entry_t      *entry_free_list;

    char            *root;

    double timebase_factor;

    /* counter table indexed by hash value of function names. */
    uint8  func_hash_counters[256];

    /* Table of filtered function names and their filter */
    int     filtered_type; // 1 = blacklist, 2 = whitelist, 0 = nothing

    hp_function_map *filtered_functions;

    
    int compile_count;
    double compile_wt;
    uint64 cpu_start;
    uint64 start_time;

    //  microseconds, profiling if function's execution time greater than this 
    double stack_threshold;  
ZEND_END_MODULE_GLOBALS(hp)

#ifdef ZTS
#define ZP_G(v) TSRMG(hp_globals_id, zend_hp_globals *, v)
#else
#define ZP_G(v) (hp_globals.v)
#endif

PHP_MINIT_FUNCTION(zprof);
PHP_MSHUTDOWN_FUNCTION(zprof);
PHP_RINIT_FUNCTION(zprof);
PHP_RSHUTDOWN_FUNCTION(zprof);
PHP_MINFO_FUNCTION(zprof);
PHP_GINIT_FUNCTION(hp);
PHP_GSHUTDOWN_FUNCTION(hp);

PHP_FUNCTION(zprof_enable);
PHP_FUNCTION(zprof_disable);

#endif  /* PHP_ZPROF_H */
