/*
 * waffy — Rule matching engine
 * Validates parsed request parameters against per-location rule sets.
 * All functions are designed for zero-allocation in the hot path
 * (regex objects are pre-compiled at init time).
 */

#ifndef _WAFFY_RULE_ENGINE_H_
#define _WAFFY_RULE_ENGINE_H_

#include "waffy_types.h"

/*
 * Validate a single parameter value against its rule.
 * Returns NGX_OK if the value passes all constraints,
 * or NGX_ERROR with violation details populated.
 */
ngx_int_t waffy_validate_param(waffy_param_rule_t *rule,
                              ngx_str_t *value,
                              waffy_violation_t *violation,
                              ngx_pool_t *pool);

/*
 * Validate an entire parsed request against a location rule set.
 * Checks: required params present, no unknown params (strict mode),
 * and each param value passes its rule constraints.
 *
 * Returns WAFFY_ACTION_PASS or WAFFY_ACTION_BLOCK.
 * On BLOCK, violation is populated with details of first failure.
 */
waffy_action_e waffy_evaluate_request(waffy_location_ruleset_t *ruleset,
                                    waffy_parsed_request_t *request,
                                    waffy_violation_t *violation,
                                    ngx_pool_t *pool);

/*
 * Quick type-check functions (no allocation, branchless where possible).
 * Return 1 if value matches type, 0 otherwise.
 */
int waffy_is_integer(ngx_str_t *value);
int waffy_is_float(ngx_str_t *value);
int waffy_is_boolean(ngx_str_t *value);
int waffy_is_uuid(ngx_str_t *value);
int waffy_is_email(ngx_str_t *value);
int waffy_is_ipv4(ngx_str_t *value);
int waffy_is_hex(ngx_str_t *value);

/*
 * Parse an integer from an ngx_str_t with range checking.
 * Returns NGX_OK if parsed and within [min, max], NGX_ERROR otherwise.
 */
ngx_int_t waffy_parse_int64(ngx_str_t *value, int64_t *out,
                           int64_t min, int64_t max);

/*
 * Check if value matches one of the enum values.
 * Uses linear scan for small sets (<8), hash for larger.
 */
int waffy_check_enum(ngx_str_t *value, ngx_str_t *allowed,
                    ngx_uint_t count);

#endif /* _WAFFY_RULE_ENGINE_H_ */
