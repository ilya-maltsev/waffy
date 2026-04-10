/*
 * waffy — Whitelist Application Firewall for nginx
 *
 * Main module file: nginx integration, config directives, request handler.
 *
 * Build:
 *   ./configure --add-module=/path/to/waffy/nginx-module
 *   make && make install
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "waffy_types.h"
#include "waffy_rule_engine.h"
#include "waffy_parser.h"
#include "waffy_shm.h"

/* Forward declarations */
static ngx_int_t waffy_init_module(ngx_cycle_t *cycle);
static void      waffy_exit_module(ngx_cycle_t *cycle);
static ngx_int_t waffy_postconfiguration(ngx_conf_t *cf);
static void     *waffy_create_main_conf(ngx_conf_t *cf);
static char     *waffy_init_main_conf(ngx_conf_t *cf, void *conf);
static void     *waffy_create_loc_conf(ngx_conf_t *cf);
static char     *waffy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t waffy_access_handler(ngx_http_request_t *r);
static void      waffy_body_read_handler(ngx_http_request_t *r);
static ngx_int_t waffy_process_request(ngx_http_request_t *r);
static ngx_int_t waffy_log_violation(ngx_http_request_t *r,
                                    waffy_violation_t *violation,
                                    waffy_loc_conf_t *lcf);
static ngx_uint_t waffy_method_to_bitmask(ngx_uint_t method);

/* ───── Mode mapping ───── */

static ngx_conf_enum_t waffy_mode_values[] = {
    { ngx_string("off"),     WAFFY_MODE_OFF },
    { ngx_string("learn"),   WAFFY_MODE_LEARN },
    { ngx_string("detect"),  WAFFY_MODE_DETECT },
    { ngx_string("enforce"), WAFFY_MODE_ENFORCE },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t waffy_body_parser_values[] = {
    { ngx_string("auto"),      WAFFY_BODY_AUTO },
    { ngx_string("form"),      WAFFY_BODY_FORM },
    { ngx_string("json"),      WAFFY_BODY_JSON },
    { ngx_string("multipart"), WAFFY_BODY_MULTIPART },
    { ngx_null_string, 0 }
};

/* ───── Configuration directives ───── */

static ngx_command_t waffy_commands[] = {

    { ngx_string("waffy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(waffy_loc_conf_t, enable),
      NULL },

    { ngx_string("waffy_rules"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(waffy_main_conf_t, rules_path),
      NULL },

    { ngx_string("waffy_mode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(waffy_loc_conf_t, mode),
      &waffy_mode_values },

    { ngx_string("waffy_body_parser"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(waffy_loc_conf_t, body_parser),
      &waffy_body_parser_values },

    { ngx_string("waffy_max_body_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(waffy_loc_conf_t, max_body_size),
      NULL },

    { ngx_string("waffy_on_violation"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(waffy_loc_conf_t, violation_status),
      NULL },

    ngx_null_command
};

/* ───── Module context ───── */

static ngx_http_module_t waffy_module_ctx = {
    NULL,                          /* preconfiguration */
    waffy_postconfiguration,        /* postconfiguration */

    waffy_create_main_conf,         /* create main configuration */
    waffy_init_main_conf,           /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    waffy_create_loc_conf,          /* create location configuration */
    waffy_merge_loc_conf            /* merge location configuration */
};

/* ───── Module definition ───── */

ngx_module_t ngx_http_waffy_module = {
    NGX_MODULE_V1,
    &waffy_module_ctx,              /* module context */
    waffy_commands,                 /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    waffy_init_module,              /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    waffy_exit_module,              /* exit module */
    NGX_MODULE_V1_PADDING
};

/* ───── Configuration callbacks ───── */

static void *
waffy_create_main_conf(ngx_conf_t *cf)
{
    waffy_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(waffy_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* rules_path is zero-initialized (empty ngx_str_t) */
    conf->rule_store_mmap = NULL;
    conf->rule_store_size = 0;

    return conf;
}

static char *
waffy_init_main_conf(ngx_conf_t *cf, void *conf)
{
    /* Validation of rules_path happens at init_module time */
    return NGX_CONF_OK;
}

static void *
waffy_create_loc_conf(ngx_conf_t *cf)
{
    waffy_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(waffy_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->mode = NGX_CONF_UNSET_UINT;
    conf->body_parser = NGX_CONF_UNSET_UINT;
    conf->max_body_size = NGX_CONF_UNSET_SIZE;
    conf->violation_status = NGX_CONF_UNSET_UINT;
    conf->log_violations = NGX_CONF_UNSET;
    conf->ruleset = NULL;

    return conf;
}

static char *
waffy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    waffy_loc_conf_t *prev = parent;
    waffy_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->mode, prev->mode, WAFFY_MODE_OFF);
    ngx_conf_merge_uint_value(conf->body_parser, prev->body_parser,
                              WAFFY_BODY_AUTO);
    ngx_conf_merge_size_value(conf->max_body_size, prev->max_body_size,
                              16 * 1024);  /* 16k default */
    ngx_conf_merge_uint_value(conf->violation_status, prev->violation_status,
                              NGX_HTTP_FORBIDDEN);
    ngx_conf_merge_value(conf->log_violations, prev->log_violations, 1);

    return NGX_CONF_OK;
}

/* ───── Module lifecycle ───── */

static ngx_int_t
waffy_init_module(ngx_cycle_t *cycle)
{
    waffy_main_conf_t *mcf;

    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waffy_module);
    if (mcf == NULL || mcf->rules_path.len == 0) {
        /* No rules configured — module is effectively disabled */
        return NGX_OK;
    }

    if (waffy_store_load(mcf, cycle->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "waffy: failed to load rule store from \"%V\"",
                      &mcf->rules_path);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "waffy: loaded rule store from \"%V\" (%uz bytes)",
                  &mcf->rules_path, mcf->rule_store_size);

    return NGX_OK;
}

static void
waffy_exit_module(ngx_cycle_t *cycle)
{
    waffy_main_conf_t *mcf;

    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waffy_module);
    if (mcf != NULL) {
        waffy_store_unload(mcf);
    }
}

static ngx_int_t
waffy_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = waffy_access_handler;

    return NGX_OK;
}

/* ───── Request handler (hot path entry point) ───── */

static ngx_int_t
waffy_access_handler(ngx_http_request_t *r)
{
    waffy_loc_conf_t  *lcf;
    waffy_main_conf_t *mcf;
    ngx_int_t         rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waffy_module);

    /* Fast exit: module disabled for this location */
    if (!lcf->enable || lcf->mode == WAFFY_MODE_OFF) {
        return NGX_DECLINED;
    }

    /* Learn mode: pass request through, capture happens via log/mirror */
    if (lcf->mode == WAFFY_MODE_LEARN) {
        return NGX_DECLINED;
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_waffy_module);
    if (mcf == NULL || mcf->rule_store_mmap == NULL) {
        /* No rules loaded — pass through */
        return NGX_DECLINED;
    }

    /* Resolve ruleset for this location if not cached yet */
    if (lcf->ruleset == NULL) {
        ngx_http_core_loc_conf_t *clcf;
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        lcf->ruleset = waffy_store_lookup(mcf, &clcf->name,
                                         waffy_method_to_bitmask(r->method),
                                         r->pool);
        if (lcf->ruleset == NULL) {
            /* No rules for this location+method — pass through */
            return NGX_DECLINED;
        }
    }

    /* If request has a body, read it first then validate */
    if (r->headers_in.content_length_n > 0) {
        if ((size_t)r->headers_in.content_length_n > lcf->max_body_size) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "waffy: request body too large (%O > %uz)",
                          r->headers_in.content_length_n,
                          lcf->max_body_size);
            return lcf->violation_status;
        }

        rc = ngx_http_read_client_request_body(r, waffy_body_read_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;  /* Will continue in body_read_handler */
    }

    /* No body — validate query string, headers, cookies only */
    return waffy_process_request(r);
}

/* Called after request body is fully read */
static void
waffy_body_read_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;

    rc = waffy_process_request(r);

    if (rc == NGX_DECLINED) {
        /* Passed validation — continue to next handler */
        ngx_http_core_run_phases(r);
        return;
    }

    /* Blocked or error — finalize with the returned status */
    ngx_http_finalize_request(r, rc);
}

/* Core validation logic — called for all requests */
static ngx_int_t
waffy_process_request(ngx_http_request_t *r)
{
    waffy_loc_conf_t       *lcf;
    waffy_parsed_request_t  parsed;
    waffy_violation_t       violation;
    waffy_action_e          action;
    waffy_body_parser_e     parser_type;
    ngx_int_t              rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waffy_module);

    ngx_memzero(&parsed, sizeof(waffy_parsed_request_t));
    ngx_memzero(&violation, sizeof(waffy_violation_t));

    /* Step 1: Parse query string args */
    rc = waffy_parse_query_args(r, &parsed, r->pool);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "waffy: failed to parse query args");
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Step 2: Parse request body if present */
    if (r->request_body && r->request_body->bufs) {
        parser_type = lcf->body_parser;
        if (parser_type == WAFFY_BODY_AUTO) {
            parser_type = waffy_detect_body_parser(r);
        }

        switch (parser_type) {
        case WAFFY_BODY_FORM:
            rc = waffy_parse_form_body(r, r->request_body->bufs, &parsed,
                                      r->pool);
            break;
        case WAFFY_BODY_JSON:
            rc = waffy_parse_json_body(r, r->request_body->bufs, &parsed,
                                      r->pool);
            break;
        case WAFFY_BODY_MULTIPART:
            rc = waffy_parse_multipart_body(r, r->request_body->bufs, &parsed,
                                           r->pool);
            break;
        default:
            rc = NGX_OK;  /* Unknown content type — skip body parsing */
            break;
        }

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "waffy: failed to parse request body");
            return lcf->violation_status;
        }
    }

    /* Step 3: Parse relevant headers */
    rc = waffy_parse_headers(r, lcf->ruleset, &parsed, r->pool);
    if (rc != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Step 4: Parse cookies */
    rc = waffy_parse_cookies(r, &parsed, r->pool);
    if (rc != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Step 5: Evaluate all rules */
    action = waffy_evaluate_request(lcf->ruleset, &parsed, &violation, r->pool);

    if (action == WAFFY_ACTION_BLOCK) {
        waffy_log_violation(r, &violation, lcf);

        if (lcf->mode == WAFFY_MODE_DETECT) {
            /* Detection only — log but pass through */
            return NGX_DECLINED;
        }

        /* Enforcement — block the request */
        return lcf->violation_status;
    }

    return NGX_DECLINED;  /* PASS — continue to upstream */
}

/* Log violation details */
static ngx_int_t
waffy_log_violation(ngx_http_request_t *r, waffy_violation_t *violation,
                   waffy_loc_conf_t *lcf)
{
    if (!lcf->log_violations) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "waffy [%s]: param=\"%V\" source=%d violation=\"%V\" "
                  "value=\"%V\" uri=\"%V\" method=%ui client=%V",
                  (lcf->mode == WAFFY_MODE_DETECT) ? "DETECT" : "BLOCK",
                  &violation->param_name,
                  violation->source,
                  &violation->violation_msg,
                  &violation->observed_value,
                  &r->uri,
                  r->method,
                  &r->connection->addr_text);

    return NGX_OK;
}

/* Convert nginx method constant to waffy bitmask */
static ngx_uint_t
waffy_method_to_bitmask(ngx_uint_t method)
{
    switch (method) {
    case NGX_HTTP_GET:     return WAFFY_METHOD_GET;
    case NGX_HTTP_POST:    return WAFFY_METHOD_POST;
    case NGX_HTTP_PUT:     return WAFFY_METHOD_PUT;
    case NGX_HTTP_DELETE:  return WAFFY_METHOD_DELETE;
    case NGX_HTTP_PATCH:   return WAFFY_METHOD_PATCH;
    case NGX_HTTP_HEAD:    return WAFFY_METHOD_HEAD;
    case NGX_HTTP_OPTIONS: return WAFFY_METHOD_OPTIONS;
    default:               return 0;
    }
}
