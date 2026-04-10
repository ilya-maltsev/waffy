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

/*
 * ───── Helper: read a length-prefixed string from buffer ─────
 *
 * Format: uint16_t len (LE) + len bytes of data.
 * Returns NGX_OK on success, NGX_ERROR if out of bounds.
 * Advances *pos past the string.
 */
static ngx_int_t
waffy_read_lps(u_char **pos, u_char *end, ngx_str_t *out)
{
    u_char  *p = *pos;

    if (p + 2 > end) {
        return NGX_ERROR;
    }

    out->len = (size_t) p[0] | ((size_t) p[1] << 8);  /* LE uint16 */
    p += 2;

    if (p + out->len > end) {
        return NGX_ERROR;
    }

    out->data = p;  /* points directly into mmap (zero-copy) */
    *pos = p + out->len;
    return NGX_OK;
}

/* Read a little-endian uint16 and advance *pos */
static ngx_int_t
waffy_read_u16(u_char **pos, u_char *end, uint16_t *out)
{
    u_char *p = *pos;

    if (p + 2 > end) {
        return NGX_ERROR;
    }

    *out = (uint16_t) p[0] | ((uint16_t) p[1] << 8);
    *pos = p + 2;
    return NGX_OK;
}

/* Read a little-endian uint32 and advance *pos */
static ngx_int_t
waffy_read_u32(u_char **pos, u_char *end, uint32_t *out)
{
    u_char *p = *pos;

    if (p + 4 > end) {
        return NGX_ERROR;
    }

    *out = (uint32_t) p[0]
         | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16)
         | ((uint32_t) p[3] << 24);
    *pos = p + 4;
    return NGX_OK;
}

/* Read a little-endian uint64 and advance *pos */
static ngx_int_t
waffy_read_u64(u_char **pos, u_char *end, uint64_t *out)
{
    u_char *p = *pos;

    if (p + 8 > end) {
        return NGX_ERROR;
    }

    *out = (uint64_t) p[0]
         | ((uint64_t) p[1] << 8)
         | ((uint64_t) p[2] << 16)
         | ((uint64_t) p[3] << 24)
         | ((uint64_t) p[4] << 32)
         | ((uint64_t) p[5] << 40)
         | ((uint64_t) p[6] << 48)
         | ((uint64_t) p[7] << 56);
    *pos = p + 8;
    return NGX_OK;
}

/*
 * ───── Deserialize one parameter rule from TLV data ─────
 */
static ngx_int_t
waffy_deserialize_param(u_char **pos, u_char *end,
                       waffy_param_rule_t *param, ngx_pool_t *pool,
                       ngx_log_t *log)
{
    uint16_t  u16;
    uint32_t  u32;
    uint64_t  u64;
    u_char    u8val;
    ngx_str_t regex_pattern;
    ngx_uint_t i;

    /* name (length-prefixed string) */
    if (waffy_read_lps(pos, end, &param->name) != NGX_OK) {
        return NGX_ERROR;
    }

    /* source (1 byte) */
    if (*pos + 1 > end) return NGX_ERROR;
    u8val = **pos; (*pos)++;
    param->source = (waffy_param_source_e) u8val;

    /* required (1 byte) */
    if (*pos + 1 > end) return NGX_ERROR;
    param->required = **pos ? 1 : 0; (*pos)++;

    /* type (1 byte) */
    if (*pos + 1 > end) return NGX_ERROR;
    u8val = **pos; (*pos)++;
    param->type = (waffy_param_type_e) u8val;

    /* min_length (uint32 LE) */
    if (waffy_read_u32(pos, end, &u32) != NGX_OK) return NGX_ERROR;
    param->min_length = (ngx_uint_t) u32;

    /* max_length (uint32 LE) */
    if (waffy_read_u32(pos, end, &u32) != NGX_OK) return NGX_ERROR;
    param->max_length = (ngx_uint_t) u32;

    /* min_value (int64 as uint64 LE) */
    if (waffy_read_u64(pos, end, &u64) != NGX_OK) return NGX_ERROR;
    param->min_value = (int64_t) u64;

    /* max_value (int64 as uint64 LE) */
    if (waffy_read_u64(pos, end, &u64) != NGX_OK) return NGX_ERROR;
    param->max_value = (int64_t) u64;

    /* regex pattern (length-prefixed string) */
    if (waffy_read_lps(pos, end, &regex_pattern) != NGX_OK) {
        return NGX_ERROR;
    }

    param->regex = NULL;
    if (regex_pattern.len > 0) {
#if (NGX_PCRE || NGX_PCRE2)
        ngx_regex_compile_t  rc;
        u_char               errstr[NGX_MAX_CONF_ERRSTR];

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
        rc.pattern = regex_pattern;
        rc.pool = pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "waffy: failed to compile regex \"%V\" for param \"%V\": %V",
                          &regex_pattern, &param->name, &rc.err);
            /* Continue without regex — don't fail the entire ruleset */
        } else {
            param->regex = rc.regex;
        }
#else
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "waffy: regex support not available, "
                      "ignoring pattern for param \"%V\"",
                      &param->name);
#endif
    }

    /* enum values: count (uint16 LE), then count length-prefixed strings */
    if (waffy_read_u16(pos, end, &u16) != NGX_OK) return NGX_ERROR;
    param->enum_count = (ngx_uint_t) u16;

    if (param->enum_count > 0) {
        if (param->enum_count > WAFFY_MAX_ENUM_VALUES) {
            return NGX_ERROR;
        }
        param->enum_values = ngx_palloc(pool,
                                        param->enum_count * sizeof(ngx_str_t));
        if (param->enum_values == NULL) {
            return NGX_ERROR;
        }
        for (i = 0; i < param->enum_count; i++) {
            if (waffy_read_lps(pos, end, &param->enum_values[i]) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    } else {
        param->enum_values = NULL;
    }

    return NGX_OK;
}

/*
 * ───── Deserialize a full location ruleset from TLV data ─────
 */
static waffy_location_ruleset_t *
waffy_deserialize_location(u_char *data, uint32_t size,
                          ngx_pool_t *pool, ngx_log_t *log)
{
    waffy_location_ruleset_t *rs;
    u_char                   *pos, *end;
    uint16_t                  u16;
    ngx_uint_t                i;

    rs = ngx_pcalloc(pool, sizeof(waffy_location_ruleset_t));
    if (rs == NULL) {
        return NULL;
    }

    pos = data;
    end = data + size;

    /* location_path */
    if (waffy_read_lps(&pos, end, &rs->location_path) != NGX_OK) {
        goto bad_format;
    }

    /* method (1 byte bitmask) */
    if (pos + 1 > end) goto bad_format;
    rs->methods = (ngx_uint_t) *pos; pos++;

    /* strict_mode (1 byte) */
    if (pos + 1 > end) goto bad_format;
    rs->strict_mode = *pos ? 1 : 0; pos++;

    /* content_types: count (uint16), then count length-prefixed strings */
    if (waffy_read_u16(&pos, end, &u16) != NGX_OK) goto bad_format;
    rs->n_content_types = (ngx_uint_t) u16;

    if (rs->n_content_types > 0) {
        rs->content_types = ngx_palloc(pool,
                                       rs->n_content_types * sizeof(ngx_str_t));
        if (rs->content_types == NULL) return NULL;

        for (i = 0; i < rs->n_content_types; i++) {
            if (waffy_read_lps(&pos, end, &rs->content_types[i]) != NGX_OK) {
                goto bad_format;
            }
        }
    }

    /* parameters: count (uint16), then count serialized params */
    if (waffy_read_u16(&pos, end, &u16) != NGX_OK) goto bad_format;
    rs->n_params = (ngx_uint_t) u16;

    if (rs->n_params > WAFFY_MAX_PARAMS) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "waffy: too many params (%ui) for location \"%V\"",
                      rs->n_params, &rs->location_path);
        return NULL;
    }

    if (rs->n_params > 0) {
        rs->params = ngx_pcalloc(pool,
                                 rs->n_params * sizeof(waffy_param_rule_t));
        if (rs->params == NULL) return NULL;

        for (i = 0; i < rs->n_params; i++) {
            if (waffy_deserialize_param(&pos, end, &rs->params[i],
                                       pool, log) != NGX_OK)
            {
                goto bad_format;
            }
        }
    }

    return rs;

bad_format:
    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "waffy: corrupt rule data for location \"%V\"",
                  &rs->location_path);
    return NULL;
}

/*
 * ───── Public: look up ruleset by location + method ─────
 *
 * Linear scan of the index (typically < 100 entries, fits in L1 cache).
 * On match, deserializes TLV data from the data section.
 * Result is allocated from the provided pool and can be cached.
 */
waffy_location_ruleset_t *
waffy_store_lookup(waffy_main_conf_t *conf, ngx_str_t *location,
                  ngx_uint_t method, ngx_pool_t *pool)
{
    waffy_store_header_t     *header;
    u_char                   *base;
    u_char                   *index_base;
    u_char                   *idx_pos, *idx_end;
    uint32_t                  target_hash;
    uint32_t                  entry_hash;
    uint64_t                  entry_offset;
    uint32_t                  entry_size;
    ngx_uint_t                i;
    ngx_log_t                *log;

    if (conf == NULL || conf->rule_store_mmap == NULL) {
        return NULL;
    }

    log = conf->log;
    base = (u_char *) conf->rule_store_mmap;
    header = (waffy_store_header_t *) base;

    if (header->n_locations == 0) {
        return NULL;
    }

    target_hash = waffy_location_hash(location, method);

    /* Walk the index: each entry is hash(4) + offset(8) + size(4) = 16 bytes */
    index_base = base + header->index_offset;
    idx_end = index_base + (size_t) header->n_locations * 16;

    /* Bounds check: index must fit within the mmap'd region */
    if (idx_end > base + conf->rule_store_size) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "waffy: index extends beyond rule store bounds");
        return NULL;
    }

    idx_pos = index_base;

    for (i = 0; i < header->n_locations; i++) {
        /* Read index entry fields (LE) */
        if (waffy_read_u32(&idx_pos, idx_end, &entry_hash) != NGX_OK
            || waffy_read_u64(&idx_pos, idx_end, &entry_offset) != NGX_OK
            || waffy_read_u32(&idx_pos, idx_end, &entry_size) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "waffy: truncated index entry %ui", i);
            return NULL;
        }

        if (entry_hash != target_hash) {
            continue;
        }

        /* Hash match — validate data section bounds */
        if (entry_offset + entry_size > conf->rule_store_size) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "waffy: data section out of bounds for entry %ui "
                          "(offset=%uL, size=%uD, store=%uz)",
                          i, entry_offset, entry_size,
                          conf->rule_store_size);
            return NULL;
        }

        /* Deserialize and return */
        return waffy_deserialize_location(base + entry_offset,
                                         entry_size, pool, log);
    }

    /* No match found */
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
