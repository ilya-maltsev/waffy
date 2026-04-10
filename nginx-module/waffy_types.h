/*
 * waffy — Whitelist Application Firewall for nginx
 * Core type definitions shared across all module components
 */

#ifndef _WAFFY_TYPES_H_
#define _WAFFY_TYPES_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* ───── Constants ───── */

#define WAFFY_RULE_MAGIC         0x57414657  /* "WAFFY" */
#define WAFFY_RULE_VERSION       1
#define WAFFY_MAX_PARAMS         256
#define WAFFY_MAX_ENUM_VALUES    64
#define WAFFY_MAX_PATTERN_LEN    4096
#define WAFFY_HASH_BUCKETS       512

/* ───── Enums ───── */

typedef enum {
    WAFFY_MODE_OFF     = 0,
    WAFFY_MODE_LEARN   = 1,
    WAFFY_MODE_DETECT  = 2,
    WAFFY_MODE_ENFORCE = 3
} waffy_mode_e;

typedef enum {
    WAFFY_ACTION_PASS  = 0,
    WAFFY_ACTION_BLOCK = 1,
    WAFFY_ACTION_LOG   = 2
} waffy_action_e;

typedef enum {
    WAFFY_SRC_QUERY   = 0x01,
    WAFFY_SRC_BODY    = 0x02,
    WAFFY_SRC_HEADER  = 0x04,
    WAFFY_SRC_COOKIE  = 0x08
} waffy_param_source_e;

typedef enum {
    WAFFY_TYPE_STRING  = 0,
    WAFFY_TYPE_INTEGER = 1,
    WAFFY_TYPE_FLOAT   = 2,
    WAFFY_TYPE_BOOLEAN = 3,
    WAFFY_TYPE_ENUM    = 4,
    WAFFY_TYPE_UUID    = 5,
    WAFFY_TYPE_EMAIL   = 6,
    WAFFY_TYPE_IPV4    = 7,
    WAFFY_TYPE_DATE    = 8,
    WAFFY_TYPE_BASE64  = 9,
    WAFFY_TYPE_HEX     = 10,
    WAFFY_TYPE_JWT     = 11
} waffy_param_type_e;

typedef enum {
    WAFFY_BODY_AUTO      = 0,
    WAFFY_BODY_FORM      = 1,
    WAFFY_BODY_JSON      = 2,
    WAFFY_BODY_MULTIPART = 3
} waffy_body_parser_e;

/* Method bitmask */
#define WAFFY_METHOD_GET     0x01
#define WAFFY_METHOD_POST    0x02
#define WAFFY_METHOD_PUT     0x04
#define WAFFY_METHOD_DELETE  0x08
#define WAFFY_METHOD_PATCH   0x10
#define WAFFY_METHOD_HEAD    0x20
#define WAFFY_METHOD_OPTIONS 0x40

/* ───── Violation detail ───── */

typedef struct {
    ngx_str_t       param_name;
    waffy_param_source_e source;
    ngx_str_t       violation_msg;    /* e.g. "integer expected, got 'abc'" */
    ngx_str_t       observed_value;   /* truncated to 128 bytes for logging */
} waffy_violation_t;

/* ───── Rule structures (mirrors binary format in mmap) ───── */

typedef struct {
    ngx_str_t           name;
    waffy_param_source_e source;
    ngx_flag_t          required;
    waffy_param_type_e   type;

    /* String constraints */
    ngx_uint_t          min_length;
    ngx_uint_t          max_length;
    ngx_regex_t        *regex;        /* Pre-compiled PCRE2 pattern */

    /* Numeric constraints */
    int64_t             min_value;
    int64_t             max_value;

    /* Enum constraints */
    ngx_uint_t          enum_count;
    ngx_str_t          *enum_values;  /* Array of allowed values */
} waffy_param_rule_t;

typedef struct {
    ngx_str_t           location_path;
    ngx_uint_t          methods;       /* Bitmask of WAFFY_METHOD_* */
    ngx_flag_t          strict_mode;   /* Reject unknown parameters */

    ngx_uint_t          n_content_types;
    ngx_str_t          *content_types; /* Allowed Content-Type values */

    ngx_uint_t          n_params;
    waffy_param_rule_t  *params;        /* Array of parameter rules */
} waffy_location_ruleset_t;

/* ───── Parsed request parameters ───── */

typedef struct {
    ngx_str_t           name;
    ngx_str_t           value;
    waffy_param_source_e source;
} waffy_parsed_param_t;

typedef struct {
    ngx_uint_t          n_params;
    waffy_parsed_param_t *params;       /* Pool-allocated array */
} waffy_parsed_request_t;

/* ───── Rule store header (mmap'd file) ───── */

typedef struct {
    uint32_t    magic;
    uint32_t    version;
    uint32_t    flags;
    uint32_t    n_locations;
    uint64_t    index_offset;
    uint64_t    data_offset;
    uint64_t    total_size;
    uint64_t    checksum;
} __attribute__((packed)) waffy_store_header_t;

/* ───── Module configuration ───── */

typedef struct {
    ngx_str_t       rules_path;       /* Path to compiled rules.bin */
    void           *rule_store_mmap;  /* mmap'd rule store base pointer */
    size_t          rule_store_size;
    ngx_log_t      *log;
} waffy_main_conf_t;

typedef struct {
    ngx_flag_t          enable;       /* waffy on|off */
    waffy_mode_e         mode;         /* enforce|detect|learn|off */
    waffy_body_parser_e  body_parser;  /* json|form|multipart|auto */
    size_t              max_body_size; /* Maximum request body to inspect */
    ngx_uint_t          violation_status; /* HTTP status on block (default 403) */
    ngx_flag_t          log_violations;

    /* Resolved at init: pointer into mmap'd rule store */
    waffy_location_ruleset_t *ruleset;
} waffy_loc_conf_t;

#endif /* _WAFFY_TYPES_H_ */
