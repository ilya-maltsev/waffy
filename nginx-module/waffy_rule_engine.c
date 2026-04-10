/*
 * waffy — Rule matching engine implementation
 *
 * Hot-path code: validate parsed parameters against whitelist rules.
 * Design principles:
 *   - Zero dynamic allocation (all memory from request pool)
 *   - Fail-fast: first violation stops evaluation
 *   - Type checks before regex (cheaper checks first)
 */

#include "waffy_rule_engine.h"

#include <ngx_config.h>
#include <ngx_core.h>

/* ───── Type validators (inline, branchless where possible) ───── */

int
waffy_is_integer(ngx_str_t *value)
{
    u_char *p, *end;

    if (value->len == 0) {
        return 0;
    }

    p = value->data;
    end = p + value->len;

    /* Optional leading minus */
    if (*p == '-') {
        p++;
        if (p == end) {
            return 0;  /* lone minus */
        }
    }

    while (p < end) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        p++;
    }

    return 1;
}

int
waffy_is_float(ngx_str_t *value)
{
    u_char *p, *end;
    int     dot_seen = 0;

    if (value->len == 0) {
        return 0;
    }

    p = value->data;
    end = p + value->len;

    if (*p == '-') {
        p++;
        if (p == end) {
            return 0;
        }
    }

    while (p < end) {
        if (*p == '.') {
            if (dot_seen) {
                return 0;
            }
            dot_seen = 1;
        } else if (*p < '0' || *p > '9') {
            return 0;
        }
        p++;
    }

    return dot_seen;  /* Must have at least one dot to be float */
}

int
waffy_is_boolean(ngx_str_t *value)
{
    if (value->len == 1) {
        return (value->data[0] == '0' || value->data[0] == '1');
    }
    if (value->len == 4) {
        return (ngx_strncasecmp(value->data, (u_char *)"true", 4) == 0);
    }
    if (value->len == 5) {
        return (ngx_strncasecmp(value->data, (u_char *)"false", 5) == 0);
    }
    return 0;
}

int
waffy_is_uuid(ngx_str_t *value)
{
    u_char *p;
    size_t  i;

    /* UUID: 8-4-4-4-12 = 36 chars */
    if (value->len != 36) {
        return 0;
    }

    p = value->data;
    for (i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (p[i] != '-') {
                return 0;
            }
        } else {
            u_char c = p[i];
            if (!((c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'))) {
                return 0;
            }
        }
    }

    return 1;
}

int
waffy_is_email(ngx_str_t *value)
{
    u_char *p, *end, *at;
    int     local_len, domain_len;

    if (value->len < 3 || value->len > 254) {
        return 0;
    }

    p = value->data;
    end = p + value->len;
    at = NULL;

    /* Find @ */
    for (u_char *s = p; s < end; s++) {
        if (*s == '@') {
            if (at != NULL) {
                return 0;  /* Multiple @ */
            }
            at = s;
        }
    }

    if (at == NULL) {
        return 0;
    }

    local_len = (int)(at - p);
    domain_len = (int)(end - at - 1);

    if (local_len < 1 || local_len > 64) {
        return 0;
    }
    if (domain_len < 3) {  /* a.b minimum */
        return 0;
    }

    /* Check domain has at least one dot */
    int has_dot = 0;
    for (u_char *s = at + 1; s < end; s++) {
        if (*s == '.') {
            has_dot = 1;
        }
    }

    return has_dot;
}

int
waffy_is_ipv4(ngx_str_t *value)
{
    u_char   *p, *end;
    int       octet, dots, digits;

    if (value->len < 7 || value->len > 15) {
        return 0;
    }

    p = value->data;
    end = p + value->len;
    octet = 0;
    dots = 0;
    digits = 0;

    while (p < end) {
        if (*p >= '0' && *p <= '9') {
            octet = octet * 10 + (*p - '0');
            digits++;
            if (digits > 3 || octet > 255) {
                return 0;
            }
        } else if (*p == '.') {
            if (digits == 0) {
                return 0;
            }
            dots++;
            octet = 0;
            digits = 0;
        } else {
            return 0;
        }
        p++;
    }

    return (dots == 3 && digits > 0);
}

int
waffy_is_hex(ngx_str_t *value)
{
    u_char *p, *end;

    if (value->len == 0) {
        return 0;
    }

    p = value->data;
    end = p + value->len;

    while (p < end) {
        u_char c = *p;
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return 0;
        }
        p++;
    }

    return 1;
}

/* ───── Integer parsing with range check ───── */

ngx_int_t
waffy_parse_int64(ngx_str_t *value, int64_t *out, int64_t min, int64_t max)
{
    u_char  *p, *end;
    int64_t  result = 0;
    int      negative = 0;

    if (value->len == 0) {
        return NGX_ERROR;
    }

    p = value->data;
    end = p + value->len;

    if (*p == '-') {
        negative = 1;
        p++;
        if (p == end) {
            return NGX_ERROR;
        }
    }

    while (p < end) {
        if (*p < '0' || *p > '9') {
            return NGX_ERROR;
        }
        /* Overflow check */
        if (result > (INT64_MAX - (*p - '0')) / 10) {
            return NGX_ERROR;
        }
        result = result * 10 + (*p - '0');
        p++;
    }

    if (negative) {
        result = -result;
    }

    if (result < min || result > max) {
        return NGX_ERROR;
    }

    *out = result;
    return NGX_OK;
}

/* ───── Enum check ───── */

int
waffy_check_enum(ngx_str_t *value, ngx_str_t *allowed, ngx_uint_t count)
{
    ngx_uint_t i;

    for (i = 0; i < count; i++) {
        if (value->len == allowed[i].len &&
            ngx_memcmp(value->data, allowed[i].data, value->len) == 0) {
            return 1;
        }
    }

    return 0;
}

/* ───── Single parameter validation ───── */

ngx_int_t
waffy_validate_param(waffy_param_rule_t *rule, ngx_str_t *value,
                    waffy_violation_t *violation, ngx_pool_t *pool)
{
    int      rc;
    int64_t  int_val;

    /* Length checks (cheapest, always first) */
    if (value->len < rule->min_length) {
        violation->violation_msg = (ngx_str_t)
            ngx_string("value too short");
        return NGX_ERROR;
    }

    if (rule->max_length > 0 && value->len > rule->max_length) {
        violation->violation_msg = (ngx_str_t)
            ngx_string("value too long");
        return NGX_ERROR;
    }

    /* Type-specific validation */
    switch (rule->type) {

    case WAFFY_TYPE_INTEGER:
        if (waffy_parse_int64(value, &int_val,
                             rule->min_value, rule->max_value) != NGX_OK) {
            violation->violation_msg = (ngx_str_t)
                ngx_string("invalid integer or out of range");
            return NGX_ERROR;
        }
        break;

    case WAFFY_TYPE_FLOAT:
        if (!waffy_is_float(value)) {
            violation->violation_msg = (ngx_str_t)
                ngx_string("invalid float");
            return NGX_ERROR;
        }
        break;

    case WAFFY_TYPE_BOOLEAN:
        if (!waffy_is_boolean(value)) {
            violation->violation_msg = (ngx_str_t)
                ngx_string("invalid boolean");
            return NGX_ERROR;
        }
        break;

    case WAFFY_TYPE_UUID:
        if (!waffy_is_uuid(value)) {
            violation->violation_msg = (ngx_str_t)
                ngx_string("invalid UUID");
            return NGX_ERROR;
        }
        break;

    case WAFFY_TYPE_EMAIL:
        if (!waffy_is_email(value)) {
            violation->violation_msg = (ngx_str_t)
                ngx_string("invalid email");
            return NGX_ERROR;
        }
        break;

    case WAFFY_TYPE_IPV4:
        if (!waffy_is_ipv4(value)) {
            violation->violation_msg = (ngx_str_t)
                ngx_string("invalid IPv4 address");
            return NGX_ERROR;
        }
        break;

    case WAFFY_TYPE_HEX:
        if (!waffy_is_hex(value)) {
            violation->violation_msg = (ngx_str_t)
                ngx_string("invalid hex string");
            return NGX_ERROR;
        }
        break;

    case WAFFY_TYPE_ENUM:
        if (!waffy_check_enum(value, rule->enum_values, rule->enum_count)) {
            violation->violation_msg = (ngx_str_t)
                ngx_string("value not in allowed set");
            return NGX_ERROR;
        }
        break;

    case WAFFY_TYPE_STRING:
        /* String type — regex is the primary constraint */
        break;

    default:
        break;
    }

    /* Regex check (most expensive, always last) */
    if (rule->regex != NULL) {
        rc = ngx_regex_exec(rule->regex, value, NULL, 0);
        if (rc < 0) {
            violation->violation_msg = (ngx_str_t)
                ngx_string("value does not match expected pattern");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* ───── Full request evaluation ───── */

waffy_action_e
waffy_evaluate_request(waffy_location_ruleset_t *ruleset,
                      waffy_parsed_request_t *request,
                      waffy_violation_t *violation,
                      ngx_pool_t *pool)
{
    ngx_uint_t  i, j;
    int         found;

    /*
     * Pass 1: Check for unknown parameters (strict mode).
     * This catches mass-assignment and parameter injection attacks.
     */
    if (ruleset->strict_mode) {
        for (i = 0; i < request->n_params; i++) {
            found = 0;
            for (j = 0; j < ruleset->n_params; j++) {
                if (request->params[i].name.len == ruleset->params[j].name.len
                    && request->params[i].source == ruleset->params[j].source
                    && ngx_memcmp(request->params[i].name.data,
                                  ruleset->params[j].name.data,
                                  request->params[i].name.len) == 0)
                {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                violation->param_name = request->params[i].name;
                violation->source = request->params[i].source;
                violation->violation_msg = (ngx_str_t)
                    ngx_string("unknown parameter (strict mode)");
                violation->observed_value = request->params[i].value;
                return WAFFY_ACTION_BLOCK;
            }
        }
    }

    /*
     * Pass 2: Validate each rule against the parsed request.
     */
    for (i = 0; i < ruleset->n_params; i++) {
        waffy_param_rule_t *rule = &ruleset->params[i];
        ngx_str_t         *value = NULL;

        /* Find the parameter in the parsed request */
        for (j = 0; j < request->n_params; j++) {
            if (request->params[j].name.len == rule->name.len
                && request->params[j].source == rule->source
                && ngx_memcmp(request->params[j].name.data,
                              rule->name.data,
                              rule->name.len) == 0)
            {
                value = &request->params[j].value;
                break;
            }
        }

        /* Required parameter missing? */
        if (value == NULL) {
            if (rule->required) {
                violation->param_name = rule->name;
                violation->source = rule->source;
                violation->violation_msg = (ngx_str_t)
                    ngx_string("required parameter missing");
                ngx_str_set(&violation->observed_value, "(absent)");
                return WAFFY_ACTION_BLOCK;
            }
            continue;  /* Optional and absent — skip */
        }

        /* Validate the value */
        violation->param_name = rule->name;
        violation->source = rule->source;
        violation->observed_value.data = value->data;
        violation->observed_value.len =
            (value->len > 128) ? 128 : value->len;  /* Truncate for log */

        if (waffy_validate_param(rule, value, violation, pool) != NGX_OK) {
            return WAFFY_ACTION_BLOCK;
        }
    }

    return WAFFY_ACTION_PASS;
}
