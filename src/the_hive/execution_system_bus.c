#include "execution_system_bus.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <systemd/sd-bus.h>

enum {
    EXECUTION_SYSTEM_BUS_TIMER_TIME_COUNT = 4U,
    EXECUTION_SYSTEM_BUS_CALLS_PER_PROCESS = 7U,
    EXECUTION_SYSTEM_BUS_CALLS_PER_NAMED_SERVICE = 7U,
    EXECUTION_SYSTEM_BUS_CALLS_PER_TIMER = 12U
};

static bool identifier_byte(uint8_t byte, bool first) {
    if (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') return true;
    if (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') return !first;
    return !first && (byte == (uint8_t)'-' || byte == (uint8_t)'_' || byte == (uint8_t)'.');
}

static bool wire_text_valid(const ExecutionWireV1Text *text, const ExecutionWireV1Limits *limits) {
    size_t index;

    if (text == NULL || limits == NULL || text->length == 0U ||
        text->length > limits->max_text_bytes ||
        text->length > EXECUTION_WIRE_V1_TEXT_CAPACITY || text->bytes[text->length] != 0U) {
        return false;
    }
    for (index = 0U; index < text->length; ++index) {
        if (!identifier_byte(text->bytes[index], index == 0U)) return false;
    }
    return true;
}

static bool utf8_valid(const uint8_t *bytes, size_t length) {
    size_t index = 0U;

    while (index < length) {
        uint8_t first = bytes[index];
        size_t continuation;
        uint32_t codepoint;
        size_t offset;

        if (first <= 0x7fU) {
            if (first == 0U) return false;
            ++index;
            continue;
        }
        if (first >= 0xc2U && first <= 0xdfU) {
            continuation = 1U;
            codepoint = (uint32_t)(first & 0x1fU);
        } else if (first >= 0xe0U && first <= 0xefU) {
            continuation = 2U;
            codepoint = (uint32_t)(first & 0x0fU);
        } else if (first >= 0xf0U && first <= 0xf4U) {
            continuation = 3U;
            codepoint = (uint32_t)(first & 0x07U);
        } else {
            return false;
        }
        if (continuation > length - index - 1U) return false;
        for (offset = 1U; offset <= continuation; ++offset) {
            uint8_t next = bytes[index + offset];
            if ((next & 0xc0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (uint32_t)(next & 0x3fU);
        }
        if ((continuation == 2U && codepoint < 0x800U) ||
            (continuation == 3U && codepoint < 0x10000U) ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU) || codepoint > 0x10ffffU) {
            return false;
        }
        index += continuation + 1U;
    }
    return true;
}

static bool d73_text_valid(const ExecutionSystemBusD73Text *text, const ExecutionWireV1Limits *limits) {
    if (text == NULL || limits == NULL || text->length == 0U ||
        text->length > limits->max_text_bytes || text->length > EXECUTION_WIRE_V1_TEXT_CAPACITY ||
        text->bytes[text->length] != 0U) {
        return false;
    }
    return utf8_valid(text->bytes, text->length);
}

static bool wire_text_equal(const ExecutionWireV1Text *left, const ExecutionWireV1Text *right) {
    return left->length == right->length && memcmp(left->bytes, right->bytes, left->length) == 0;
}

static bool d73_text_equal_cstring(const ExecutionSystemBusD73Text *expected, const char *actual) {
    size_t index;

    if (actual == NULL) return false;
    for (index = 0U; index <= expected->length; ++index) {
        if ((uint8_t)actual[index] == 0U) {
            return index == expected->length && memcmp(expected->bytes, actual, index) == 0;
        }
    }
    return false;
}

static bool digest_present(const ExecutionWireV1Digest *digest) {
    size_t index;
    for (index = 0U; index < sizeof(digest->bytes); ++index) {
        if (digest->bytes[index] != 0U) return true;
    }
    return false;
}

static bool checked_add_size(size_t left, size_t right, size_t *result) {
    if (left > SIZE_MAX - right) return false;
    *result = left + right;
    return true;
}

static bool checked_multiply_size(size_t left, size_t right, size_t *result) {
    if (left != 0U && right > SIZE_MAX / left) return false;
    *result = left * right;
    return true;
}

static bool checked_multiply_u64(uint64_t left, uint64_t right, uint64_t *result) {
    if (left != 0U && right > UINT64_MAX / left) return false;
    *result = left * right;
    return true;
}

static bool limits_valid(const ExecutionWireV1Limits *limits) {
    return limits != NULL && limits->max_total_bytes > 0U &&
           limits->max_total_bytes <= EXECUTION_WIRE_V1_HARD_MAX_TOTAL_BYTES &&
           limits->max_snapshot_bytes > 0U && limits->max_snapshot_bytes <= limits->max_total_bytes &&
           limits->max_text_bytes > 0U && limits->max_text_bytes <= EXECUTION_WIRE_V1_TEXT_CAPACITY &&
           limits->max_roles > 0U && limits->max_roles <= EXECUTION_WIRE_V1_MAX_ROLES &&
           limits->max_phases > 0U && limits->max_phases <= EXECUTION_WIRE_V1_MAX_PHASES &&
           limits->max_process_records > 0U && limits->max_process_records <= EXECUTION_WIRE_V1_MAX_PROCESS_RECORDS &&
           limits->max_fd_records > 0U && limits->max_fd_records <= EXECUTION_WIRE_V1_MAX_FD_RECORDS &&
           limits->max_fdinfo_records > 0U && limits->max_fdinfo_records <= EXECUTION_WIRE_V1_MAX_FDINFO_RECORDS &&
           limits->max_lock_records > 0U && limits->max_lock_records <= EXECUTION_WIRE_V1_MAX_LOCK_RECORDS &&
           limits->max_namespace_records > 0U && limits->max_namespace_records <= EXECUTION_WIRE_V1_MAX_NAMESPACE_RECORDS &&
           limits->max_unit_records > 0U && limits->max_unit_records <= EXECUTION_WIRE_V1_MAX_UNIT_RECORDS &&
           limits->max_timer_records > 0U && limits->max_timer_records <= EXECUTION_WIRE_V1_MAX_TIMER_RECORDS;
}

static bool state_rule_valid(const ExecutionSystemBusStateRule *rule, const ExecutionWireV1Limits *limits) {
    return rule != NULL && d73_text_valid(&rule->load_state, limits) &&
           d73_text_valid(&rule->active_state, limits) && d73_text_valid(&rule->sub_state, limits) &&
           wire_text_valid(&rule->output_state_code, limits);
}

static bool time_rule_valid(const ExecutionSystemBusTimeRule *rule, size_t index) {
    return rule != NULL && rule->member == (ExecutionSystemBusTimeMember)(index + 1U) &&
           rule->relation >= EXECUTION_SYSTEM_BUS_TIME_EQ && rule->relation <= EXECUTION_SYSTEM_BUS_TIME_GE;
}

static bool process_rule_valid(const ExecutionSystemBusProcessRule *rule, const ExecutionWireV1Limits *limits) {
    return rule != NULL && wire_text_valid(&rule->selector_id, limits) &&
           wire_text_valid(&rule->unit_class_id, limits) && wire_text_valid(&rule->cgroup_class_id, limits) &&
           d73_text_valid(&rule->unit_id, limits) && d73_text_valid(&rule->cgroup, limits) &&
           state_rule_valid(&rule->state, limits);
}

static bool named_service_rule_valid(const ExecutionSystemBusNamedServiceRule *rule, const ExecutionWireV1Limits *limits) {
    return rule != NULL && wire_text_valid(&rule->selector_id, limits) &&
           wire_text_valid(&rule->unit_class_id, limits) && d73_text_valid(&rule->unit_id, limits) &&
           d73_text_valid(&rule->cgroup, limits) && state_rule_valid(&rule->state, limits);
}

static bool timer_rule_valid(const ExecutionSystemBusTimerRule *rule, const ExecutionWireV1Limits *limits) {
    size_t index;

    if (rule == NULL || !wire_text_valid(&rule->selector_id, limits) ||
        !wire_text_valid(&rule->timer_class_id, limits) ||
        !wire_text_valid(&rule->bound_unit_class_id, limits) ||
        !wire_text_valid(&rule->output_result_code, limits) ||
        !d73_text_valid(&rule->timer_unit_id, limits) ||
        !d73_text_valid(&rule->bound_service_unit_id, limits) ||
        !d73_text_valid(&rule->result, limits) || !state_rule_valid(&rule->state, limits)) {
        return false;
    }
    for (index = 0U; index < EXECUTION_SYSTEM_BUS_TIMER_TIME_COUNT; ++index) {
        if (!time_rule_valid(&rule->time[index], index)) return false;
    }
    return true;
}

static bool selector_is_duplicate(const ExecutionSystemBusPlan *plan, const ExecutionWireV1Text *selector, size_t ordinal) {
    size_t index;
    size_t current = 0U;

    for (index = 0U; index < plan->process_rule_count; ++index, ++current) {
        if (current < ordinal && wire_text_equal(selector, &plan->process_rules[index].selector_id)) return true;
    }
    for (index = 0U; index < plan->named_service_rule_count; ++index, ++current) {
        if (current < ordinal && wire_text_equal(selector, &plan->named_service_rules[index].selector_id)) return true;
    }
    for (index = 0U; index < plan->timer_rule_count; ++index, ++current) {
        if (current < ordinal && wire_text_equal(selector, &plan->timer_rules[index].selector_id)) return true;
    }
    return false;
}

static ExecutionSystemBusStatus validate_call_budget(const ExecutionSystemBusPlan *plan) {
    size_t calls = 0U;
    size_t component_calls;
    uint64_t total_timeout;

    if (!checked_multiply_size(plan->process_rule_count, EXECUTION_SYSTEM_BUS_CALLS_PER_PROCESS, &component_calls) ||
        !checked_add_size(calls, component_calls, &calls) ||
        !checked_multiply_size(plan->named_service_rule_count, EXECUTION_SYSTEM_BUS_CALLS_PER_NAMED_SERVICE, &component_calls) ||
        !checked_add_size(calls, component_calls, &calls) ||
        !checked_multiply_size(plan->timer_rule_count, EXECUTION_SYSTEM_BUS_CALLS_PER_TIMER, &component_calls) ||
        !checked_add_size(calls, component_calls, &calls) ||
        !checked_multiply_u64((uint64_t)calls, plan->method_timeout_usec, &total_timeout)) {
        return EXECUTION_SYSTEM_BUS_OVERFLOW;
    }
    return total_timeout <= plan->snapshot_attempt_timeout_usec ? EXECUTION_SYSTEM_BUS_OK :
        EXECUTION_SYSTEM_BUS_POLICY_MISMATCH;
}

static ExecutionSystemBusStatus validate_plan(const ExecutionSystemBusPlan *plan) {
    size_t index;
    size_t ordinal = 0U;
    size_t total;
    ExecutionSystemBusStatus status;

    if (plan == NULL || plan->abi_version != EXECUTION_SYSTEM_BUS_ABI_VERSION ||
        !digest_present(&plan->tuple_policy_plan_binder) || !limits_valid(&plan->limits) ||
        plan->method_timeout_usec == 0U || plan->snapshot_attempt_timeout_usec == 0U ||
        plan->method_timeout_usec > plan->snapshot_attempt_timeout_usec || plan->max_snapshot_attempts == 0U ||
        plan->process_rule_count > plan->limits.max_process_records ||
        plan->named_service_rule_count > plan->limits.max_unit_records ||
        plan->timer_rule_count > plan->limits.max_timer_records) {
        return EXECUTION_SYSTEM_BUS_POLICY_MISMATCH;
    }
    if (!checked_add_size(plan->process_rule_count, plan->named_service_rule_count, &total) ||
        !checked_add_size(total, plan->timer_rule_count, &total)) {
        return EXECUTION_SYSTEM_BUS_OVERFLOW;
    }
    if (total == 0U) return EXECUTION_SYSTEM_BUS_POLICY_MISMATCH;
    for (index = 0U; index < plan->process_rule_count; ++index, ++ordinal) {
        if (!process_rule_valid(&plan->process_rules[index], &plan->limits) ||
            selector_is_duplicate(plan, &plan->process_rules[index].selector_id, ordinal)) {
            return EXECUTION_SYSTEM_BUS_POLICY_MISMATCH;
        }
    }
    for (index = 0U; index < plan->named_service_rule_count; ++index, ++ordinal) {
        if (!named_service_rule_valid(&plan->named_service_rules[index], &plan->limits) ||
            selector_is_duplicate(plan, &plan->named_service_rules[index].selector_id, ordinal)) {
            return EXECUTION_SYSTEM_BUS_POLICY_MISMATCH;
        }
    }
    for (index = 0U; index < plan->timer_rule_count; ++index, ++ordinal) {
        if (!timer_rule_valid(&plan->timer_rules[index], &plan->limits) ||
            selector_is_duplicate(plan, &plan->timer_rules[index].selector_id, ordinal)) {
            return EXECUTION_SYSTEM_BUS_POLICY_MISMATCH;
        }
    }
    status = validate_call_budget(plan);
    return status;
}

static ExecutionSystemBusStatus validate_processes(
    const ExecutionSystemBusPlan *plan, const ExecutionSystemBusProcessSelector *processes, size_t process_count
) {
    size_t index;

    if (process_count != plan->process_rule_count ||
        (process_count == 0U ? processes != NULL : processes == NULL)) {
        return EXECUTION_SYSTEM_BUS_POLICY_MISMATCH;
    }
    for (index = 0U; index < process_count; ++index) {
        if (!wire_text_valid(&processes[index].selector_id, &plan->limits) ||
            !wire_text_equal(&processes[index].selector_id, &plan->process_rules[index].selector_id) ||
            processes[index].pidfd < 0 || processes[index].expected_start_time == 0U) {
            return EXECUTION_SYSTEM_BUS_POLICY_MISMATCH;
        }
    }
    return EXECUTION_SYSTEM_BUS_OK;
}

static ExecutionSystemBusStatus map_bus_result(int result) {
    if (result == -ENOMEM) return EXECUTION_SYSTEM_BUS_NOMEM;
    if (result == -ETIMEDOUT || result == -ETIME) return EXECUTION_SYSTEM_BUS_TIMEOUT;
    if (result == -EINTR) return EXECUTION_SYSTEM_BUS_INTERRUPTED;
    return EXECUTION_SYSTEM_BUS_MANAGER_ERROR;
}

static ExecutionSystemBusStatus new_method_call(
    sd_bus *bus, const char *path, const char *interface, const char *member, sd_bus_message **request
) {
    int result = sd_bus_message_new_method_call(bus, request, EXECUTION_SYSTEM_BUS_DBUS_NAME, path, interface, member);
    return result < 0 ? map_bus_result(result) : EXECUTION_SYSTEM_BUS_OK;
}

static ExecutionSystemBusStatus send_request(
    sd_bus *bus, sd_bus_message *request, uint64_t timeout_usec, sd_bus_message **reply
) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int result = sd_bus_call(bus, request, timeout_usec, &error, reply);
    ExecutionSystemBusStatus status = result < 0 ? map_bus_result(result) : EXECUTION_SYSTEM_BUS_OK;

    sd_bus_error_free(&error);
    return status;
}

static bool message_at_exact_end(sd_bus_message *message) {
    return sd_bus_message_at_end(message, 1) > 0;
}

static ExecutionSystemBusStatus lookup_pidfd(
    sd_bus *bus, const ExecutionSystemBusProcessSelector *selector, const ExecutionSystemBusProcessRule *rule,
    uint64_t timeout_usec, sd_bus_message **lookup_reply, const char **object_path,
    uint8_t invocation_id[EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES]
) {
    sd_bus_message *request = NULL;
    sd_bus_message *reply = NULL;
    const char *returned_path = NULL;
    const char *returned_unit = NULL;
    const void *returned_invocation = NULL;
    size_t invocation_size = 0U;
    ExecutionSystemBusStatus status;
    int result;

    status = new_method_call(bus, EXECUTION_SYSTEM_BUS_MANAGER_PATH, EXECUTION_SYSTEM_BUS_MANAGER_INTERFACE,
                             EXECUTION_SYSTEM_BUS_METHOD_GET_UNIT_BY_PIDFD, &request);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    result = sd_bus_message_append(request, "h", selector->pidfd);
    if (result < 0) {
        status = map_bus_result(result);
        goto finish;
    }
    status = send_request(bus, request, timeout_usec, &reply);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    result = sd_bus_message_read(reply, "os", &returned_path, &returned_unit);
    if (result < 0 || returned_path == NULL || returned_unit == NULL ||
        sd_bus_message_read_array(reply, 'y', &returned_invocation, &invocation_size) <= 0 ||
        invocation_size != EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES || !message_at_exact_end(reply) ||
        sd_bus_object_path_is_valid(returned_path) <= 0) {
        status = EXECUTION_SYSTEM_BUS_PROTOCOL_ERROR;
        goto finish;
    }
    if (!d73_text_equal_cstring(&rule->unit_id, returned_unit)) {
        status = EXECUTION_SYSTEM_BUS_BINDING_MISMATCH;
        goto finish;
    }
    memcpy(invocation_id, returned_invocation, EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES);
    *object_path = returned_path;
    *lookup_reply = reply;
    reply = NULL;
    status = EXECUTION_SYSTEM_BUS_OK;

finish:
    sd_bus_message_unref(reply);
    sd_bus_message_unref(request);
    return status;
}

static ExecutionSystemBusStatus lookup_named_unit(
    sd_bus *bus, const ExecutionSystemBusD73Text *unit_id, uint64_t timeout_usec,
    sd_bus_message **lookup_reply, const char **object_path
) {
    sd_bus_message *request = NULL;
    sd_bus_message *reply = NULL;
    const char *returned_path = NULL;
    ExecutionSystemBusStatus status;
    int result;

    status = new_method_call(bus, EXECUTION_SYSTEM_BUS_MANAGER_PATH, EXECUTION_SYSTEM_BUS_MANAGER_INTERFACE,
                             EXECUTION_SYSTEM_BUS_METHOD_GET_UNIT, &request);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    result = sd_bus_message_append(request, "s", (const char *)unit_id->bytes);
    if (result < 0) {
        status = map_bus_result(result);
        goto finish;
    }
    status = send_request(bus, request, timeout_usec, &reply);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    if (sd_bus_message_read(reply, "o", &returned_path) != 1 || !message_at_exact_end(reply) ||
        sd_bus_object_path_is_valid(returned_path) <= 0) {
        status = EXECUTION_SYSTEM_BUS_PROTOCOL_ERROR;
        goto finish;
    }
    *object_path = returned_path;
    *lookup_reply = reply;
    reply = NULL;
    status = EXECUTION_SYSTEM_BUS_OK;

finish:
    sd_bus_message_unref(reply);
    sd_bus_message_unref(request);
    return status;
}

static ExecutionSystemBusStatus property_request(
    sd_bus *bus, const char *object_path, const char *interface, const char *property,
    uint64_t timeout_usec, sd_bus_message **reply_out
) {
    sd_bus_message *request = NULL;
    sd_bus_message *reply = NULL;
    ExecutionSystemBusStatus status;
    int result;

    status = new_method_call(bus, object_path, EXECUTION_SYSTEM_BUS_PROPERTIES_INTERFACE,
                             EXECUTION_SYSTEM_BUS_METHOD_GET, &request);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    result = sd_bus_message_append(request, "ss", interface, property);
    if (result < 0) {
        status = map_bus_result(result);
        goto finish;
    }
    status = send_request(bus, request, timeout_usec, &reply);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    *reply_out = reply;
    reply = NULL;
    status = EXECUTION_SYSTEM_BUS_OK;

finish:
    sd_bus_message_unref(reply);
    sd_bus_message_unref(request);
    return status;
}

static ExecutionSystemBusStatus property_string_equals(
    sd_bus *bus, const char *object_path, const char *interface, const char *property,
    const ExecutionSystemBusD73Text *expected, uint64_t timeout_usec
) {
    sd_bus_message *reply = NULL;
    const char *actual = NULL;
    ExecutionSystemBusStatus status = property_request(bus, object_path, interface, property, timeout_usec, &reply);

    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    if (sd_bus_message_enter_container(reply, 'v', "s") <= 0 ||
        sd_bus_message_read(reply, "s", &actual) != 1 || sd_bus_message_exit_container(reply) <= 0 ||
        !message_at_exact_end(reply)) {
        status = EXECUTION_SYSTEM_BUS_PROTOCOL_ERROR;
        goto finish;
    }
    status = d73_text_equal_cstring(expected, actual) ? EXECUTION_SYSTEM_BUS_OK :
        EXECUTION_SYSTEM_BUS_BINDING_MISMATCH;

finish:
    sd_bus_message_unref(reply);
    return status;
}

static ExecutionSystemBusStatus property_invocation_id(
    sd_bus *bus, const char *object_path, uint64_t timeout_usec,
    uint8_t invocation_id[EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES]
) {
    sd_bus_message *reply = NULL;
    const void *actual = NULL;
    size_t size = 0U;
    ExecutionSystemBusStatus status = property_request(bus, object_path, EXECUTION_SYSTEM_BUS_UNIT_INTERFACE,
                                                        EXECUTION_SYSTEM_BUS_PROPERTY_INVOCATION_ID, timeout_usec, &reply);

    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    if (sd_bus_message_enter_container(reply, 'v', "ay") <= 0 ||
        sd_bus_message_read_array(reply, 'y', &actual, &size) <= 0 ||
        size != EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES || sd_bus_message_exit_container(reply) <= 0 ||
        !message_at_exact_end(reply)) {
        status = EXECUTION_SYSTEM_BUS_PROTOCOL_ERROR;
        goto finish;
    }
    memcpy(invocation_id, actual, EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES);
    status = EXECUTION_SYSTEM_BUS_OK;

finish:
    sd_bus_message_unref(reply);
    return status;
}

static ExecutionSystemBusStatus property_u64(
    sd_bus *bus, const char *object_path, const char *property, uint64_t timeout_usec, uint64_t *value
) {
    sd_bus_message *reply = NULL;
    uint64_t observed = 0U;
    ExecutionSystemBusStatus status = property_request(bus, object_path, EXECUTION_SYSTEM_BUS_TIMER_INTERFACE,
                                                        property, timeout_usec, &reply);

    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    if (sd_bus_message_enter_container(reply, 'v', "t") <= 0 ||
        sd_bus_message_read_basic(reply, 't', &observed) <= 0 || sd_bus_message_exit_container(reply) <= 0 ||
        !message_at_exact_end(reply)) {
        status = EXECUTION_SYSTEM_BUS_PROTOCOL_ERROR;
        goto finish;
    }
    *value = observed;
    status = EXECUTION_SYSTEM_BUS_OK;

finish:
    sd_bus_message_unref(reply);
    return status;
}

static ExecutionSystemBusStatus query_unit(
    sd_bus *bus, const char *object_path, const ExecutionSystemBusD73Text *unit_id,
    const ExecutionSystemBusStateRule *state, uint64_t timeout_usec,
    uint8_t invocation_id[EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES]
) {
    ExecutionSystemBusStatus status;

    status = property_string_equals(bus, object_path, EXECUTION_SYSTEM_BUS_UNIT_INTERFACE,
                                    EXECUTION_SYSTEM_BUS_PROPERTY_ID, unit_id, timeout_usec);
    if (status != EXECUTION_SYSTEM_BUS_OK) return status;
    status = property_invocation_id(bus, object_path, timeout_usec, invocation_id);
    if (status != EXECUTION_SYSTEM_BUS_OK) return status;
    status = property_string_equals(bus, object_path, EXECUTION_SYSTEM_BUS_UNIT_INTERFACE,
                                    EXECUTION_SYSTEM_BUS_PROPERTY_LOAD_STATE,
                                    &state->load_state, timeout_usec);
    if (status != EXECUTION_SYSTEM_BUS_OK) return status;
    status = property_string_equals(bus, object_path, EXECUTION_SYSTEM_BUS_UNIT_INTERFACE,
                                    EXECUTION_SYSTEM_BUS_PROPERTY_ACTIVE_STATE,
                                    &state->active_state, timeout_usec);
    if (status != EXECUTION_SYSTEM_BUS_OK) return status;
    return property_string_equals(bus, object_path, EXECUTION_SYSTEM_BUS_UNIT_INTERFACE,
                                  EXECUTION_SYSTEM_BUS_PROPERTY_SUB_STATE,
                                  &state->sub_state, timeout_usec);
}

static bool time_rule_matches(const ExecutionSystemBusTimeRule *rule, uint64_t observed) {
    switch (rule->relation) {
        case EXECUTION_SYSTEM_BUS_TIME_EQ: return observed == rule->operand;
        case EXECUTION_SYSTEM_BUS_TIME_NE: return observed != rule->operand;
        case EXECUTION_SYSTEM_BUS_TIME_LT: return observed < rule->operand;
        case EXECUTION_SYSTEM_BUS_TIME_LE: return observed <= rule->operand;
        case EXECUTION_SYSTEM_BUS_TIME_GT: return observed > rule->operand;
        case EXECUTION_SYSTEM_BUS_TIME_GE: return observed >= rule->operand;
        default: return false;
    }
}

static ExecutionSystemBusStatus query_timer(
    sd_bus *bus, const char *object_path, const ExecutionSystemBusTimerRule *rule,
    uint64_t timeout_usec, ExecutionSystemBusTimerObservation *output
) {
    static const char *const names[EXECUTION_SYSTEM_BUS_TIMER_TIME_COUNT] = {
        EXECUTION_SYSTEM_BUS_PROPERTY_NEXT_ELAPSE_REALTIME,
        EXECUTION_SYSTEM_BUS_PROPERTY_NEXT_ELAPSE_MONOTONIC,
        EXECUTION_SYSTEM_BUS_PROPERTY_LAST_TRIGGER_REALTIME,
        EXECUTION_SYSTEM_BUS_PROPERTY_LAST_TRIGGER_MONOTONIC
    };
    uint64_t *const values[EXECUTION_SYSTEM_BUS_TIMER_TIME_COUNT] = {
        &output->next_elapse_realtime_usec, &output->next_elapse_monotonic_usec,
        &output->last_trigger_realtime_usec, &output->last_trigger_monotonic_usec
    };
    size_t index;
    ExecutionSystemBusStatus status;

    status = property_string_equals(bus, object_path, EXECUTION_SYSTEM_BUS_TIMER_INTERFACE,
                                    EXECUTION_SYSTEM_BUS_PROPERTY_TIMER_UNIT,
                                    &rule->bound_service_unit_id, timeout_usec);
    if (status != EXECUTION_SYSTEM_BUS_OK) return status;
    status = property_string_equals(bus, object_path, EXECUTION_SYSTEM_BUS_TIMER_INTERFACE,
                                    EXECUTION_SYSTEM_BUS_PROPERTY_TIMER_RESULT,
                                    &rule->result, timeout_usec);
    if (status != EXECUTION_SYSTEM_BUS_OK) return status;
    for (index = 0U; index < EXECUTION_SYSTEM_BUS_TIMER_TIME_COUNT; ++index) {
        status = property_u64(bus, object_path, names[index], timeout_usec, values[index]);
        if (status != EXECUTION_SYSTEM_BUS_OK) return status;
        if (!time_rule_matches(&rule->time[index], *values[index])) return EXECUTION_SYSTEM_BUS_BINDING_MISMATCH;
    }
    return EXECUTION_SYSTEM_BUS_OK;
}

static ExecutionSystemBusStatus capture_process(
    sd_bus *bus, const ExecutionSystemBusPlan *plan, const ExecutionSystemBusProcessSelector *selector,
    size_t index, ExecutionSystemBusProcessBinding *output
) {
    const ExecutionSystemBusProcessRule *rule = &plan->process_rules[index];
    sd_bus_message *lookup_reply = NULL;
    const char *object_path = NULL;
    uint8_t manager_invocation[EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES];
    uint8_t property_invocation[EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES];
    ExecutionSystemBusStatus status = lookup_pidfd(bus, selector, rule, plan->method_timeout_usec,
                                                   &lookup_reply, &object_path, manager_invocation);

    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    status = query_unit(bus, object_path, &rule->unit_id, &rule->state, plan->method_timeout_usec, property_invocation);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    if (memcmp(manager_invocation, property_invocation, sizeof(manager_invocation)) != 0) {
        status = EXECUTION_SYSTEM_BUS_BINDING_MISMATCH;
        goto finish;
    }
    status = property_string_equals(bus, object_path, EXECUTION_SYSTEM_BUS_SERVICE_INTERFACE,
                                    EXECUTION_SYSTEM_BUS_PROPERTY_CONTROL_GROUP,
                                    &rule->cgroup, plan->method_timeout_usec);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    output->selector_id = rule->selector_id;
    output->unit_class_id = rule->unit_class_id;
    output->cgroup_class_id = rule->cgroup_class_id;
    output->state_code = rule->state.output_state_code;
    memcpy(output->invocation_id, property_invocation, sizeof(output->invocation_id));

finish:
    sd_bus_message_unref(lookup_reply);
    return status;
}

static ExecutionSystemBusStatus capture_named_service(
    sd_bus *bus, const ExecutionSystemBusPlan *plan, size_t index, ExecutionSystemBusUnitObservation *output
) {
    const ExecutionSystemBusNamedServiceRule *rule = &plan->named_service_rules[index];
    sd_bus_message *lookup_reply = NULL;
    const char *object_path = NULL;
    uint8_t invocation_id[EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES];
    ExecutionSystemBusStatus status = lookup_named_unit(bus, &rule->unit_id, plan->method_timeout_usec,
                                                         &lookup_reply, &object_path);

    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    status = query_unit(bus, object_path, &rule->unit_id, &rule->state, plan->method_timeout_usec, invocation_id);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    status = property_string_equals(bus, object_path, EXECUTION_SYSTEM_BUS_SERVICE_INTERFACE,
                                    EXECUTION_SYSTEM_BUS_PROPERTY_CONTROL_GROUP,
                                    &rule->cgroup, plan->method_timeout_usec);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    output->selector_id = rule->selector_id;
    output->wire_record.class_id = rule->unit_class_id;
    output->wire_record.status = rule->state.output_state_code;
    output->wire_record.time_value = 0U;
    memcpy(output->invocation_id, invocation_id, sizeof(output->invocation_id));

finish:
    sd_bus_message_unref(lookup_reply);
    return status;
}

static ExecutionSystemBusStatus capture_timer(
    sd_bus *bus, const ExecutionSystemBusPlan *plan, size_t index, ExecutionSystemBusTimerObservation *output
) {
    const ExecutionSystemBusTimerRule *rule = &plan->timer_rules[index];
    sd_bus_message *lookup_reply = NULL;
    const char *object_path = NULL;
    uint8_t invocation_id[EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES];
    ExecutionSystemBusStatus status = lookup_named_unit(bus, &rule->timer_unit_id, plan->method_timeout_usec,
                                                         &lookup_reply, &object_path);

    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    status = query_unit(bus, object_path, &rule->timer_unit_id, &rule->state, plan->method_timeout_usec, invocation_id);
    if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    output->selector_id = rule->selector_id;
    output->bound_unit_class_id = rule->bound_unit_class_id;
    output->unit_state_code = rule->state.output_state_code;
    output->timer_result_code = rule->output_result_code;
    memcpy(output->invocation_id, invocation_id, sizeof(output->invocation_id));
    status = query_timer(bus, object_path, rule, plan->method_timeout_usec, output);

finish:
    sd_bus_message_unref(lookup_reply);
    return status;
}

static bool capture_matches_baseline(const ExecutionSystemBusCapture *capture, const ExecutionSystemBusCapture *baseline) {
    size_t index;

    if (baseline->final_target || capture->process_binding_count != baseline->process_binding_count ||
        capture->unit_count != baseline->unit_count || capture->timer_count != baseline->timer_count) {
        return false;
    }
    for (index = 0U; index < capture->process_binding_count; ++index) {
        if (!wire_text_equal(&capture->process_bindings[index].selector_id, &baseline->process_bindings[index].selector_id) ||
            !wire_text_equal(&capture->process_bindings[index].unit_class_id, &baseline->process_bindings[index].unit_class_id) ||
            !wire_text_equal(&capture->process_bindings[index].cgroup_class_id, &baseline->process_bindings[index].cgroup_class_id) ||
            memcmp(capture->process_bindings[index].invocation_id, baseline->process_bindings[index].invocation_id,
                   EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES) != 0) return false;
    }
    for (index = 0U; index < capture->unit_count; ++index) {
        if (!wire_text_equal(&capture->units[index].selector_id, &baseline->units[index].selector_id) ||
            !wire_text_equal(&capture->units[index].wire_record.class_id, &baseline->units[index].wire_record.class_id) ||
            memcmp(capture->units[index].invocation_id, baseline->units[index].invocation_id,
                   EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES) != 0) return false;
    }
    for (index = 0U; index < capture->timer_count; ++index) {
        if (!wire_text_equal(&capture->timers[index].selector_id, &baseline->timers[index].selector_id) ||
            !wire_text_equal(&capture->timers[index].bound_unit_class_id, &baseline->timers[index].bound_unit_class_id) ||
            memcmp(capture->timers[index].invocation_id, baseline->timers[index].invocation_id,
                   EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES) != 0) return false;
    }
    return true;
}

ExecutionSystemBusStatus execution_system_bus_capture(
    const ExecutionSystemBusPlan *plan, const ExecutionSystemBusProcessSelector *processes, size_t process_count,
    ExecutionSystemBusPhase phase, const ExecutionSystemBusCapture *identity_baseline, ExecutionSystemBusCapture *out
) {
    ExecutionSystemBusCapture temporary;
    sd_bus *bus = NULL;
    ExecutionSystemBusStatus status;
    size_t index;
    int result;

    if (out == NULL || out == identity_baseline) return EXECUTION_SYSTEM_BUS_INVALID_INPUT;
    memset(out, 0, sizeof(*out));
    if ((phase != EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT && phase != EXECUTION_SYSTEM_BUS_PHASE_FINAL_TARGET) ||
        (phase == EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT && identity_baseline != NULL) ||
        (phase == EXECUTION_SYSTEM_BUS_PHASE_FINAL_TARGET && identity_baseline == NULL)) {
        return EXECUTION_SYSTEM_BUS_INVALID_INPUT;
    }
    if (plan == NULL) return EXECUTION_SYSTEM_BUS_INVALID_INPUT;
    status = validate_plan(plan);
    if (status != EXECUTION_SYSTEM_BUS_OK) return status;
    status = validate_processes(plan, processes, process_count);
    if (status != EXECUTION_SYSTEM_BUS_OK) return status;
    memset(&temporary, 0, sizeof(temporary));
    result = sd_bus_open_system(&bus);
    if (result < 0) {
        status = result == -ENOMEM ? EXECUTION_SYSTEM_BUS_NOMEM : EXECUTION_SYSTEM_BUS_OPEN_FAILED;
        goto finish;
    }
    result = sd_bus_set_method_call_timeout(bus, plan->method_timeout_usec);
    if (result < 0) {
        status = map_bus_result(result);
        goto finish;
    }
    for (index = 0U; index < plan->process_rule_count; ++index) {
        status = capture_process(bus, plan, &processes[index], index, &temporary.process_bindings[index]);
        if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    }
    temporary.process_binding_count = plan->process_rule_count;
    for (index = 0U; index < plan->named_service_rule_count; ++index) {
        status = capture_named_service(bus, plan, index, &temporary.units[index]);
        if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    }
    temporary.unit_count = plan->named_service_rule_count;
    for (index = 0U; index < plan->timer_rule_count; ++index) {
        status = capture_timer(bus, plan, index, &temporary.timers[index]);
        if (status != EXECUTION_SYSTEM_BUS_OK) goto finish;
    }
    temporary.timer_count = plan->timer_rule_count;
    if (phase == EXECUTION_SYSTEM_BUS_PHASE_FINAL_TARGET && !capture_matches_baseline(&temporary, identity_baseline)) {
        status = EXECUTION_SYSTEM_BUS_BINDING_MISMATCH;
        goto finish;
    }
    temporary.final_target = phase == EXECUTION_SYSTEM_BUS_PHASE_FINAL_TARGET;
    *out = temporary;
    status = EXECUTION_SYSTEM_BUS_OK;

finish:
    sd_bus_unref(bus);
    if (status != EXECUTION_SYSTEM_BUS_OK) memset(out, 0, sizeof(*out));
    return status;
}
