/*
 * waffy — Rule store interface
 *
 * Loads compiled rules from an mmap'd binary file.
 * Hot-reload swaps the mmap pointer atomically.
 */

#include "waffy_shm.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* FNV-1a hash for location+method lookup */
uint32_t
waffy_location_hash(ngx_str_t *location, ngx_uint_t method)
{
    uint32_t hash = 2166136261u;  /* FNV offset basis */
    size_t   i;

    for (i = 0; i < location->len; i++) {
        hash ^= location->data[i];
        hash *= 16777619u;  /* FNV prime */
    }

    /* Mix in method */
    hash ^= (uint32_t)method;
    hash *= 16777619u;

    return hash;
}

ngx_int_t
waffy_store_load(waffy_main_conf_t *conf, ngx_log_t *log)
{
    int                   fd;
    struct stat           sb;
    void                 *mapped;
    waffy_store_header_t  *header;
    char                  path_buf[NGX_MAX_PATH];

    if (conf->rules_path.len == 0) {
        return NGX_ERROR;
    }

    /* Null-terminate path for syscalls */
    if (conf->rules_path.len >= NGX_MAX_PATH) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "waffy: rules path too long");
        return NGX_ERROR;
    }
    ngx_memcpy(path_buf, conf->rules_path.data, conf->rules_path.len);
    path_buf[conf->rules_path.len] = '\0';

    fd = open(path_buf, O_RDONLY);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "waffy: open(\"%s\") failed", path_buf);
        return NGX_ERROR;
    }

    if (fstat(fd, &sb) == -1) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "waffy: fstat(\"%s\") failed", path_buf);
        close(fd);
        return NGX_ERROR;
    }

    if ((size_t)sb.st_size < sizeof(waffy_store_header_t)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "waffy: rule store too small (%zd bytes)", sb.st_size);
        close(fd);
        return NGX_ERROR;
    }

    mapped = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (mapped == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "waffy: mmap(\"%s\") failed", path_buf);
        return NGX_ERROR;
    }

    /* Validate header */
    header = (waffy_store_header_t *)mapped;

    if (header->magic != WAFFY_RULE_MAGIC) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "waffy: invalid rule store magic: 0x%08xd "
                      "(expected 0x%08xd)",
                      header->magic, WAFFY_RULE_MAGIC);
        munmap(mapped, sb.st_size);
        return NGX_ERROR;
    }

    if (header->version != WAFFY_RULE_VERSION) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "waffy: unsupported rule store version %ud "
                      "(expected %ud)",
                      header->version, WAFFY_RULE_VERSION);
        munmap(mapped, sb.st_size);
        return NGX_ERROR;
    }

    /* TODO: validate checksum */

    conf->rule_store_mmap = mapped;
    conf->rule_store_size = sb.st_size;
    conf->log = log;

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "waffy: loaded rule store v%ud with %ud locations (%uz bytes)",
                  header->version, header->n_locations, sb.st_size);

    return NGX_OK;
}

void
waffy_store_unload(waffy_main_conf_t *conf)
{
    if (conf->rule_store_mmap != NULL) {
        munmap(conf->rule_store_mmap, conf->rule_store_size);
        conf->rule_store_mmap = NULL;
        conf->rule_store_size = 0;
    }
}

waffy_location_ruleset_t *
waffy_store_lookup(waffy_main_conf_t *conf, ngx_str_t *location,
                  ngx_uint_t method, ngx_pool_t *pool)
{
    /*
     * TODO: Full implementation reads from the mmap'd binary format.
     *
     * Algorithm:
     * 1. Compute hash = waffy_location_hash(location, method)
     * 2. index_slot = hash % header->n_locations
     * 3. Walk the index at (base + header->index_offset + slot * entry_size)
     * 4. Compare location string and method mask
     * 5. If match, deserialize the rule set from data section
     * 6. Compile regex patterns (cached after first lookup per worker)
     *
     * For now, return NULL (no rules = pass-through).
     */

    (void)conf;
    (void)location;
    (void)method;
    (void)pool;

    return NULL;
}

ngx_int_t
waffy_store_reload(waffy_main_conf_t *conf, ngx_str_t *new_path,
                  ngx_log_t *log)
{
    void   *old_mmap;
    size_t  old_size;

    /* Save old pointers */
    old_mmap = conf->rule_store_mmap;
    old_size = conf->rule_store_size;

    /* Update path */
    conf->rules_path = *new_path;

    /* Load new store */
    if (waffy_store_load(conf, log) != NGX_OK) {
        /* Restore old mapping on failure */
        conf->rule_store_mmap = old_mmap;
        conf->rule_store_size = old_size;
        return NGX_ERROR;
    }

    /* Unmap old store */
    if (old_mmap != NULL) {
        munmap(old_mmap, old_size);
    }

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "waffy: hot-reloaded rule store from \"%V\"", new_path);

    return NGX_OK;
}
