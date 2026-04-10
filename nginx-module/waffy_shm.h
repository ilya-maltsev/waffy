/*
 * waffy — Rule store interface
 * Handles loading compiled rules from mmap'd files and looking up
 * rule sets by location+method at request time.
 */

#ifndef _WAFFY_SHM_H_
#define _WAFFY_SHM_H_

#include "waffy_types.h"

/*
 * Load the compiled rule store from disk via mmap.
 * Called during nginx init_module phase.
 * Validates magic, version, checksum before accepting.
 *
 * Returns NGX_OK on success, NGX_ERROR on failure.
 */
ngx_int_t waffy_store_load(waffy_main_conf_t *conf, ngx_log_t *log);

/*
 * Unmap and close the rule store.
 * Called during nginx exit_module.
 */
void waffy_store_unload(waffy_main_conf_t *conf);

/*
 * Look up the rule set for a given location path and HTTP method.
 * Uses the hash index in the mmap'd store for O(1) lookup.
 *
 * Returns pointer to the rule set, or NULL if no rules defined.
 */
waffy_location_ruleset_t *waffy_store_lookup(waffy_main_conf_t *conf,
                                           ngx_str_t *location,
                                           ngx_uint_t method,
                                           ngx_pool_t *pool);

/*
 * Hot-reload: atomically swap to a new rule store file.
 * 1. mmap the new file
 * 2. validate header
 * 3. swap pointer (atomic)
 * 4. munmap old file
 *
 * Called from signal handler or management socket.
 */
ngx_int_t waffy_store_reload(waffy_main_conf_t *conf, ngx_str_t *new_path,
                            ngx_log_t *log);

/*
 * Compute lookup hash for a location+method pair.
 * Uses FNV-1a for speed and distribution.
 */
uint32_t waffy_location_hash(ngx_str_t *location, ngx_uint_t method);

#endif /* _WAFFY_SHM_H_ */
