/*
 * waffy — Request body parsers
 *
 * Parse HTTP request components into flat key-value pairs for rule evaluation.
 * All parsing is pool-allocated (no malloc/free in hot path).
 */

#include "waffy_parser.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define WAFFY_MAX_PARAMS_PER_REQUEST  256
#define WAFFY_MAX_JSON_DEPTH          16
#define WAFFY_MAX_JSON_KEY_LEN        512

/* ───── Helpers ───── */

static ngx_int_t
waffy_add_param(waffy_parsed_request_t *parsed, ngx_str_t *name,
               ngx_str_t *value, waffy_param_source_e source,
               ngx_pool_t *pool)
{
    waffy_parsed_param_t *param;

    if (parsed->n_params >= WAFFY_MAX_PARAMS_PER_REQUEST) {
        return NGX_ERROR;
    }

    /* Lazy-allocate the params array on first use */
    if (parsed->params == NULL) {
        parsed->params = ngx_pcalloc(pool,
            sizeof(waffy_parsed_param_t) * WAFFY_MAX_PARAMS_PER_REQUEST);
        if (parsed->params == NULL) {
            return NGX_ERROR;
        }
    }

    param = &parsed->params[parsed->n_params];
    param->name = *name;
    param->value = *value;
    param->source = source;
    parsed->n_params++;

    return NGX_OK;
}

/* URL-decode in place. Returns decoded length. */
static size_t
waffy_url_decode(u_char *dst, u_char *src, size_t len)
{
    u_char *d = dst;
    u_char *s = src;
    u_char *end = src + len;

    while (s < end) {
        if (*s == '%' && s + 2 < end) {
            u_char hi = s[1];
            u_char lo = s[2];
            int    valid = 1;
            u_char decoded;

            if (hi >= '0' && hi <= '9')      decoded = (hi - '0') << 4;
            else if (hi >= 'a' && hi <= 'f') decoded = (hi - 'a' + 10) << 4;
            else if (hi >= 'A' && hi <= 'F') decoded = (hi - 'A' + 10) << 4;
            else valid = 0;

            if (valid) {
                if (lo >= '0' && lo <= '9')      decoded |= (lo - '0');
                else if (lo >= 'a' && lo <= 'f') decoded |= (lo - 'a' + 10);
                else if (lo >= 'A' && lo <= 'F') decoded |= (lo - 'A' + 10);
                else valid = 0;
            }

            if (valid) {
                *d++ = decoded;
                s += 3;
                continue;
            }
        }

        if (*s == '+') {
            *d++ = ' ';
        } else {
            *d++ = *s;
        }
        s++;
    }

    return (size_t)(d - dst);
}

/* ───── Query string parser ───── */

ngx_int_t
waffy_parse_query_args(ngx_http_request_t *r, waffy_parsed_request_t *parsed,
                      ngx_pool_t *pool)
{
    u_char    *p, *end, *key_start, *val_start;
    ngx_str_t  name, value;

    if (r->args.len == 0) {
        return NGX_OK;
    }

    p = r->args.data;
    end = p + r->args.len;

    while (p < end) {
        key_start = p;

        /* Find = or & */
        while (p < end && *p != '=' && *p != '&') {
            p++;
        }

        name.data = key_start;
        name.len = p - key_start;

        if (p < end && *p == '=') {
            p++;  /* skip '=' */
            val_start = p;

            while (p < end && *p != '&') {
                p++;
            }

            value.data = val_start;
            value.len = p - val_start;
        } else {
            value.data = (u_char *)"";
            value.len = 0;
        }

        if (*p == '&') {
            p++;
        }

        /* URL-decode name and value in-place (safe: decoded is always <= encoded) */
        name.len = waffy_url_decode(name.data, name.data, name.len);
        value.len = waffy_url_decode(value.data, value.data, value.len);

        if (name.len > 0) {
            if (waffy_add_param(parsed, &name, &value, WAFFY_SRC_QUERY, pool)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}

/* ───── Body flattener ───── */

ngx_int_t
waffy_flatten_body(ngx_chain_t *body, ngx_str_t *out, ngx_pool_t *pool,
                  size_t max_size)
{
    ngx_chain_t *cl;
    ngx_buf_t   *buf;
    size_t       total = 0;
    u_char      *p;

    /* Calculate total size */
    for (cl = body; cl; cl = cl->next) {
        buf = cl->buf;
        if (buf->in_file) {
            return NGX_ERROR;  /* We don't handle file-backed buffers */
        }
        total += buf->last - buf->pos;
    }

    if (total > max_size) {
        return NGX_ERROR;
    }

    /* Single buffer optimization: zero-copy */
    if (body->next == NULL) {
        out->data = body->buf->pos;
        out->len = body->buf->last - body->buf->pos;
        return NGX_OK;
    }

    /* Multiple buffers: concatenate */
    out->data = ngx_pnalloc(pool, total);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    p = out->data;
    for (cl = body; cl; cl = cl->next) {
        buf = cl->buf;
        size_t chunk = buf->last - buf->pos;
        ngx_memcpy(p, buf->pos, chunk);
        p += chunk;
    }
    out->len = total;

    return NGX_OK;
}

/* ───── Form-urlencoded body parser ───── */

ngx_int_t
waffy_parse_form_body(ngx_http_request_t *r, ngx_chain_t *body,
                     waffy_parsed_request_t *parsed, ngx_pool_t *pool)
{
    ngx_str_t  flat;
    u_char    *p, *end, *key_start, *val_start;
    ngx_str_t  name, value;

    if (waffy_flatten_body(body, &flat, pool, 64 * 1024) != NGX_OK) {
        return NGX_ERROR;
    }

    if (flat.len == 0) {
        return NGX_OK;
    }

    p = flat.data;
    end = p + flat.len;

    while (p < end) {
        key_start = p;

        while (p < end && *p != '=' && *p != '&') {
            p++;
        }

        name.data = key_start;
        name.len = p - key_start;

        if (p < end && *p == '=') {
            p++;
            val_start = p;
            while (p < end && *p != '&') {
                p++;
            }
            value.data = val_start;
            value.len = p - val_start;
        } else {
            value.data = (u_char *)"";
            value.len = 0;
        }

        if (p < end && *p == '&') {
            p++;
        }

        name.len = waffy_url_decode(name.data, name.data, name.len);
        value.len = waffy_url_decode(value.data, value.data, value.len);

        if (name.len > 0) {
            if (waffy_add_param(parsed, &name, &value, WAFFY_SRC_BODY, pool)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}

/* ───── Minimal JSON parser ───── */

typedef struct {
    u_char *pos;
    u_char *end;
} waffy_json_ctx_t;

static void waffy_json_skip_ws(waffy_json_ctx_t *ctx)
{
    while (ctx->pos < ctx->end &&
           (*ctx->pos == ' ' || *ctx->pos == '\t' ||
            *ctx->pos == '\n' || *ctx->pos == '\r'))
    {
        ctx->pos++;
    }
}

/* Forward declarations for recursive descent */
static ngx_int_t waffy_json_parse_value(waffy_json_ctx_t *ctx,
                                       u_char *key_buf, size_t key_len,
                                       waffy_parsed_request_t *parsed,
                                       ngx_pool_t *pool, int depth);

static ngx_int_t
waffy_json_parse_string(waffy_json_ctx_t *ctx, ngx_str_t *out)
{
    u_char *start;

    if (ctx->pos >= ctx->end || *ctx->pos != '"') {
        return NGX_ERROR;
    }
    ctx->pos++;  /* skip opening quote */
    start = ctx->pos;

    while (ctx->pos < ctx->end && *ctx->pos != '"') {
        if (*ctx->pos == '\\') {
            ctx->pos++;  /* skip escaped char */
            if (ctx->pos >= ctx->end) {
                return NGX_ERROR;
            }
        }
        ctx->pos++;
    }

    if (ctx->pos >= ctx->end) {
        return NGX_ERROR;
    }

    out->data = start;
    out->len = ctx->pos - start;
    ctx->pos++;  /* skip closing quote */

    return NGX_OK;
}

/* Parse a JSON scalar (string, number, bool, null) as a string value */
static ngx_int_t
waffy_json_parse_scalar(waffy_json_ctx_t *ctx, ngx_str_t *out)
{
    u_char *start;

    waffy_json_skip_ws(ctx);

    if (ctx->pos >= ctx->end) {
        return NGX_ERROR;
    }

    if (*ctx->pos == '"') {
        return waffy_json_parse_string(ctx, out);
    }

    /* Number, boolean, null — read until delimiter */
    start = ctx->pos;
    while (ctx->pos < ctx->end &&
           *ctx->pos != ',' && *ctx->pos != '}' && *ctx->pos != ']' &&
           *ctx->pos != ' ' && *ctx->pos != '\t' &&
           *ctx->pos != '\n' && *ctx->pos != '\r')
    {
        ctx->pos++;
    }

    out->data = start;
    out->len = ctx->pos - start;

    return NGX_OK;
}

static ngx_int_t
waffy_json_parse_object(waffy_json_ctx_t *ctx, u_char *key_buf, size_t key_len,
                       waffy_parsed_request_t *parsed, ngx_pool_t *pool,
                       int depth)
{
    ngx_str_t prop_name;
    size_t    new_key_len;

    if (depth > WAFFY_MAX_JSON_DEPTH) {
        return NGX_ERROR;
    }

    ctx->pos++;  /* skip '{' */
    waffy_json_skip_ws(ctx);

    if (ctx->pos < ctx->end && *ctx->pos == '}') {
        ctx->pos++;
        return NGX_OK;
    }

    for (;;) {
        waffy_json_skip_ws(ctx);

        /* Parse property name */
        if (waffy_json_parse_string(ctx, &prop_name) != NGX_OK) {
            return NGX_ERROR;
        }

        waffy_json_skip_ws(ctx);
        if (ctx->pos >= ctx->end || *ctx->pos != ':') {
            return NGX_ERROR;
        }
        ctx->pos++;  /* skip ':' */

        /* Build dotpath key: "parent.child" */
        if (key_len > 0) {
            new_key_len = key_len + 1 + prop_name.len;
        } else {
            new_key_len = prop_name.len;
        }

        if (new_key_len >= WAFFY_MAX_JSON_KEY_LEN) {
            return NGX_ERROR;
        }

        u_char new_key[WAFFY_MAX_JSON_KEY_LEN];
        if (key_len > 0) {
            ngx_memcpy(new_key, key_buf, key_len);
            new_key[key_len] = '.';
            ngx_memcpy(new_key + key_len + 1, prop_name.data, prop_name.len);
        } else {
            ngx_memcpy(new_key, prop_name.data, prop_name.len);
        }

        /* Parse value */
        if (waffy_json_parse_value(ctx, new_key, new_key_len, parsed, pool,
                                  depth + 1) != NGX_OK)
        {
            return NGX_ERROR;
        }

        waffy_json_skip_ws(ctx);

        if (ctx->pos >= ctx->end) {
            return NGX_ERROR;
        }

        if (*ctx->pos == '}') {
            ctx->pos++;
            return NGX_OK;
        }

        if (*ctx->pos != ',') {
            return NGX_ERROR;
        }
        ctx->pos++;  /* skip ',' */
    }
}

static ngx_int_t
waffy_json_parse_array(waffy_json_ctx_t *ctx, u_char *key_buf, size_t key_len,
                      waffy_parsed_request_t *parsed, ngx_pool_t *pool,
                      int depth)
{
    int    index = 0;
    u_char idx_str[16];
    size_t idx_len, new_key_len;

    if (depth > WAFFY_MAX_JSON_DEPTH) {
        return NGX_ERROR;
    }

    ctx->pos++;  /* skip '[' */
    waffy_json_skip_ws(ctx);

    if (ctx->pos < ctx->end && *ctx->pos == ']') {
        ctx->pos++;
        return NGX_OK;
    }

    for (;;) {
        /* Build key with array index: "parent.0", "parent.1" */
        idx_len = ngx_snprintf(idx_str, sizeof(idx_str), "%d", index)
                  - idx_str;

        if (key_len > 0) {
            new_key_len = key_len + 1 + idx_len;
        } else {
            new_key_len = idx_len;
        }

        if (new_key_len >= WAFFY_MAX_JSON_KEY_LEN) {
            return NGX_ERROR;
        }

        u_char new_key[WAFFY_MAX_JSON_KEY_LEN];
        if (key_len > 0) {
            ngx_memcpy(new_key, key_buf, key_len);
            new_key[key_len] = '.';
            ngx_memcpy(new_key + key_len + 1, idx_str, idx_len);
        } else {
            ngx_memcpy(new_key, idx_str, idx_len);
        }

        if (waffy_json_parse_value(ctx, new_key, new_key_len, parsed, pool,
                                  depth + 1) != NGX_OK)
        {
            return NGX_ERROR;
        }

        waffy_json_skip_ws(ctx);
        index++;

        if (ctx->pos >= ctx->end) {
            return NGX_ERROR;
        }

        if (*ctx->pos == ']') {
            ctx->pos++;
            return NGX_OK;
        }

        if (*ctx->pos != ',') {
            return NGX_ERROR;
        }
        ctx->pos++;
    }
}

static ngx_int_t
waffy_json_parse_value(waffy_json_ctx_t *ctx, u_char *key_buf, size_t key_len,
                      waffy_parsed_request_t *parsed, ngx_pool_t *pool,
                      int depth)
{
    ngx_str_t name, value;

    waffy_json_skip_ws(ctx);

    if (ctx->pos >= ctx->end) {
        return NGX_ERROR;
    }

    if (*ctx->pos == '{') {
        return waffy_json_parse_object(ctx, key_buf, key_len, parsed, pool,
                                      depth);
    }

    if (*ctx->pos == '[') {
        return waffy_json_parse_array(ctx, key_buf, key_len, parsed, pool,
                                     depth);
    }

    /* Scalar value — emit as parameter */
    if (waffy_json_parse_scalar(ctx, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Copy key to pool since it's on stack */
    name.data = ngx_pnalloc(pool, key_len);
    if (name.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(name.data, key_buf, key_len);
    name.len = key_len;

    return waffy_add_param(parsed, &name, &value, WAFFY_SRC_BODY, pool);
}

ngx_int_t
waffy_parse_json_body(ngx_http_request_t *r, ngx_chain_t *body,
                     waffy_parsed_request_t *parsed, ngx_pool_t *pool)
{
    ngx_str_t       flat;
    waffy_json_ctx_t ctx;

    if (waffy_flatten_body(body, &flat, pool, 256 * 1024) != NGX_OK) {
        return NGX_ERROR;
    }

    if (flat.len == 0) {
        return NGX_OK;
    }

    ctx.pos = flat.data;
    ctx.end = flat.data + flat.len;

    waffy_json_skip_ws(&ctx);

    if (ctx.pos >= ctx.end) {
        return NGX_OK;
    }

    if (*ctx.pos == '{') {
        return waffy_json_parse_object(&ctx, NULL, 0, parsed, pool, 0);
    }

    /* Top-level array */
    if (*ctx.pos == '[') {
        return waffy_json_parse_array(&ctx, NULL, 0, parsed, pool, 0);
    }

    return NGX_ERROR;  /* Invalid JSON: not object or array at root */
}

/* ───── Multipart parser (field metadata only) ───── */

ngx_int_t
waffy_parse_multipart_body(ngx_http_request_t *r, ngx_chain_t *body,
                          waffy_parsed_request_t *parsed, ngx_pool_t *pool)
{
    ngx_str_t  flat;
    ngx_str_t  content_type;
    u_char    *boundary, *p, *end, *part_start;
    size_t     boundary_len;

    /* Extract boundary from Content-Type */
    content_type = r->headers_in.content_type->value;
    boundary = ngx_strcasestrn(content_type.data,
                               "boundary=", 9 - 1);
    if (boundary == NULL) {
        return NGX_ERROR;
    }
    boundary += 9;

    /* Calculate boundary length */
    boundary_len = content_type.len - (boundary - content_type.data);

    if (waffy_flatten_body(body, &flat, pool, 50 * 1024 * 1024) != NGX_OK) {
        return NGX_ERROR;
    }

    p = flat.data;
    end = flat.data + flat.len;

    /*
     * Simplified multipart parsing: find each Content-Disposition header
     * and extract the field name. For file fields, extract filename.
     * For regular fields, extract the value.
     */
    while (p < end) {
        /* Find boundary */
        part_start = ngx_strnstr(p, (char *)boundary, end - p);
        if (part_start == NULL) {
            break;
        }
        p = part_start + boundary_len;

        /* Find Content-Disposition */
        u_char *disp = ngx_strcasestrn(p, "content-disposition:", 20 - 1);
        if (disp == NULL || disp > end - 20) {
            continue;
        }

        /* Find field name: name="fieldname" */
        u_char *name_start = ngx_strnstr(disp, "name=\"",
                                         end - disp);
        if (name_start == NULL) {
            continue;
        }
        name_start += 6;  /* skip 'name="' */

        u_char *name_end = ngx_strlchr(name_start, end, '"');
        if (name_end == NULL) {
            continue;
        }

        ngx_str_t field_name;
        field_name.data = name_start;
        field_name.len = name_end - name_start;

        /* Check if it's a file field (has filename=) */
        u_char *filename = ngx_strnstr(disp, "filename=\"",
                                       end - disp);
        if (filename != NULL && filename < name_end + 100) {
            /* File field — add filename as the value for rule checking */
            filename += 10;
            u_char *fn_end = ngx_strlchr(filename, end, '"');
            if (fn_end != NULL) {
                ngx_str_t fn_value;
                fn_value.data = filename;
                fn_value.len = fn_end - filename;
                waffy_add_param(parsed, &field_name, &fn_value,
                               WAFFY_SRC_BODY, pool);
            }
            continue;
        }

        /* Regular field — find value after double CRLF */
        u_char *val_start = ngx_strnstr(name_end, "\r\n\r\n",
                                        end - name_end);
        if (val_start == NULL) {
            continue;
        }
        val_start += 4;

        /* Value ends at next boundary */
        u_char *val_end = ngx_strnstr(val_start, (char *) boundary,
                                      end - val_start);
        if (val_end == NULL) {
            val_end = end;
        }
        /* Trim trailing \r\n-- before boundary */
        if (val_end - val_start >= 4) {
            val_end -= 4;  /* \r\n-- */
        }

        ngx_str_t field_value;
        field_value.data = val_start;
        field_value.len = val_end - val_start;

        waffy_add_param(parsed, &field_name, &field_value,
                       WAFFY_SRC_BODY, pool);
    }

    return NGX_OK;
}

/* ───── Header parser ───── */

ngx_int_t
waffy_parse_headers(ngx_http_request_t *r, waffy_location_ruleset_t *ruleset,
                   waffy_parsed_request_t *parsed, ngx_pool_t *pool)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_uint_t       i, j;

    if (ruleset == NULL) {
        return NGX_OK;
    }

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }

        /* Only extract headers that have rules defined */
        for (j = 0; j < ruleset->n_params; j++) {
            if (ruleset->params[j].source != WAFFY_SRC_HEADER) {
                continue;
            }
            if (header[i].key.len == ruleset->params[j].name.len &&
                ngx_strncasecmp(header[i].key.data,
                                ruleset->params[j].name.data,
                                header[i].key.len) == 0)
            {
                waffy_add_param(parsed, &header[i].key, &header[i].value,
                               WAFFY_SRC_HEADER, pool);
                break;
            }
        }
    }

    return NGX_OK;
}

/* ───── Cookie parser ───── */

ngx_int_t
waffy_parse_cookies(ngx_http_request_t *r, waffy_parsed_request_t *parsed,
                   ngx_pool_t *pool)
{
    ngx_table_elt_t  *cookie;
    u_char           *p, *end, *name_start, *val_start;
    ngx_str_t         name, value;

    /* nginx 1.23+: cookie headers form a linked list via ->next */
    cookie = r->headers_in.cookie;
    if (cookie == NULL) {
        return NGX_OK;
    }

    while (cookie) {
        p = cookie->value.data;
        end = p + cookie->value.len;

        while (p < end) {
            /* Skip whitespace */
            while (p < end && *p == ' ') {
                p++;
            }

            name_start = p;
            while (p < end && *p != '=' && *p != ';') {
                p++;
            }

            name.data = name_start;
            name.len = p - name_start;

            if (p < end && *p == '=') {
                p++;
                val_start = p;
                while (p < end && *p != ';') {
                    p++;
                }
                value.data = val_start;
                value.len = p - val_start;
            } else {
                value.data = (u_char *)"";
                value.len = 0;
            }

            if (p < end && *p == ';') {
                p++;
            }

            if (name.len > 0) {
                waffy_add_param(parsed, &name, &value,
                               WAFFY_SRC_COOKIE, pool);
            }
        }

        cookie = cookie->next;
    }

    return NGX_OK;
}

/* ───── Content-Type auto-detection ───── */

waffy_body_parser_e
waffy_detect_body_parser(ngx_http_request_t *r)
{
    ngx_str_t *ct;

    if (r->headers_in.content_type == NULL) {
        return WAFFY_BODY_FORM;  /* Default */
    }

    ct = &r->headers_in.content_type->value;

    if (ngx_strnstr(ct->data, "application/json", ct->len)) {
        return WAFFY_BODY_JSON;
    }

    if (ngx_strnstr(ct->data, "multipart/form-data", ct->len)) {
        return WAFFY_BODY_MULTIPART;
    }

    if (ngx_strnstr(ct->data, "application/x-www-form-urlencoded", ct->len)) {
        return WAFFY_BODY_FORM;
    }

    return WAFFY_BODY_FORM;
}
