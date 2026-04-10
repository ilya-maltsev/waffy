/*
 * waffy — Request body parsers
 * Parse request bodies (form-urlencoded, JSON, multipart) into
 * flat key-value pairs for rule evaluation.
 */

#ifndef _WAFFY_PARSER_H_
#define _WAFFY_PARSER_H_

#include "waffy_types.h"

/*
 * Parse query string arguments from the request URI.
 * Appends to the existing parsed_request params array.
 */
ngx_int_t waffy_parse_query_args(ngx_http_request_t *r,
                                waffy_parsed_request_t *parsed,
                                ngx_pool_t *pool);

/*
 * Parse form-urlencoded request body.
 * Expects the body to already be read (buffered).
 */
ngx_int_t waffy_parse_form_body(ngx_http_request_t *r,
                               ngx_chain_t *body,
                               waffy_parsed_request_t *parsed,
                               ngx_pool_t *pool);

/*
 * Parse JSON request body into flattened dotpath key-value pairs.
 * e.g., {"user": {"name": "Alice"}} becomes "user.name" = "Alice"
 *
 * Arrays are indexed: {"ids": [1,2]} becomes "ids.0" = "1", "ids.1" = "2"
 *
 * Uses a minimal recursive-descent JSON parser (no malloc, pool-allocated).
 * Max nesting depth: 16 levels.
 */
ngx_int_t waffy_parse_json_body(ngx_http_request_t *r,
                               ngx_chain_t *body,
                               waffy_parsed_request_t *parsed,
                               ngx_pool_t *pool);

/*
 * Parse multipart/form-data body.
 * Extracts field names and values (file contents are NOT inspected,
 * only filename/content-type metadata is extracted as params).
 */
ngx_int_t waffy_parse_multipart_body(ngx_http_request_t *r,
                                    ngx_chain_t *body,
                                    waffy_parsed_request_t *parsed,
                                    ngx_pool_t *pool);

/*
 * Extract selected headers into parsed params.
 * Only extracts headers that have rules defined (avoids parsing all headers).
 */
ngx_int_t waffy_parse_headers(ngx_http_request_t *r,
                             waffy_location_ruleset_t *ruleset,
                             waffy_parsed_request_t *parsed,
                             ngx_pool_t *pool);

/*
 * Parse Cookie header into individual cookie key-value pairs.
 */
ngx_int_t waffy_parse_cookies(ngx_http_request_t *r,
                             waffy_parsed_request_t *parsed,
                             ngx_pool_t *pool);

/*
 * Auto-detect body parser based on Content-Type header.
 */
waffy_body_parser_e waffy_detect_body_parser(ngx_http_request_t *r);

/*
 * Reassemble a chained body buffer into a contiguous ngx_str_t.
 * Returns pointer to the data (may be zero-copy if single buffer).
 */
ngx_int_t waffy_flatten_body(ngx_chain_t *body, ngx_str_t *out,
                            ngx_pool_t *pool, size_t max_size);

#endif /* _WAFFY_PARSER_H_ */
