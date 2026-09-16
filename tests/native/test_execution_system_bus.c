/* RED first: compiled directly with the native libsystemd development ABI. */
#ifdef NDEBUG
#error "test_execution_system_bus requires assertions"
#endif

#include "execution_system_bus.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Compile the one product owner into this test translation unit solely to
 * cover private, pure parser/mapping logic.  This creates no product symbol,
 * callback, bus, transport, or injected seam; the harness never compiles a
 * second implementation of the owner.
 */
#include "../../src/the_hive/execution_system_bus.c"

static ExecutionWireV1Text wire_text(const char *value) {
    ExecutionWireV1Text result;
    size_t length = strlen(value);

    assert(length <= EXECUTION_WIRE_V1_TEXT_CAPACITY);
    memset(&result, 0, sizeof(result));
    memcpy(result.bytes, value, length);
    result.length = length;
    return result;
}

static ExecutionSystemBusD73Text d73_text(const char *value) {
    ExecutionSystemBusD73Text result;
    size_t length = strlen(value);

    assert(length <= EXECUTION_WIRE_V1_TEXT_CAPACITY);
    memset(&result, 0, sizeof(result));
    memcpy(result.bytes, value, length);
    result.length = length;
    return result;
}

static ExecutionWireV1Limits limits(void) {
    return (ExecutionWireV1Limits){
        .max_total_bytes = 65536U,
        .max_snapshot_bytes = 32768U,
        .max_text_bytes = EXECUTION_WIRE_V1_TEXT_CAPACITY,
        .max_roles = 1U,
        .max_phases = 1U,
        .max_process_records = 2U,
        .max_fd_records = 1U,
        .max_fdinfo_records = 1U,
        .max_lock_records = 1U,
        .max_namespace_records = 1U,
        .max_unit_records = 2U,
        .max_timer_records = 2U,
    };
}

static ExecutionSystemBusStateRule state_rule(void) {
    return (ExecutionSystemBusStateRule){
        .load_state = d73_text("loaded"),
        .active_state = d73_text("active"),
        .sub_state = d73_text("running"),
        .output_state_code = wire_text("running"),
    };
}

static ExecutionSystemBusPlan valid_plan(void) {
    ExecutionSystemBusPlan result;
    size_t index;

    memset(&result, 0, sizeof(result));
    result.abi_version = EXECUTION_SYSTEM_BUS_ABI_VERSION;
    result.tuple_policy_plan_binder.bytes[0] = 1U;
    result.limits = limits();
    result.method_timeout_usec = 1U;
    result.snapshot_attempt_timeout_usec = 64U;
    result.max_snapshot_attempts = 1U;
    result.named_service_rule_count = 1U;
    result.named_service_rules[0].selector_id = wire_text("service-a");
    result.named_service_rules[0].unit_class_id = wire_text("service");
    result.named_service_rules[0].unit_id = d73_text("dbus.service");
    result.named_service_rules[0].cgroup = d73_text("/system.slice/dbus.service");
    result.named_service_rules[0].state = state_rule();
    result.timer_rule_count = 1U;
    result.timer_rules[0].selector_id = wire_text("timer-a");
    result.timer_rules[0].timer_class_id = wire_text("timer");
    result.timer_rules[0].bound_unit_class_id = wire_text("service");
    result.timer_rules[0].output_result_code = wire_text("success");
    result.timer_rules[0].timer_unit_id = d73_text("systemd-tmpfiles-clean.timer");
    result.timer_rules[0].bound_service_unit_id = d73_text("systemd-tmpfiles-clean.service");
    result.timer_rules[0].result = d73_text("success");
    result.timer_rules[0].state = state_rule();
    for (index = 0U; index < 4U; ++index) {
        result.timer_rules[0].time[index].member = (ExecutionSystemBusTimeMember)(index + 1U);
        result.timer_rules[0].time[index].relation = EXECUTION_SYSTEM_BUS_TIME_GE;
        result.timer_rules[0].time[index].operand = 0U;
    }
    return result;
}

static void assert_zero_capture(const ExecutionSystemBusCapture *capture) {
    static const ExecutionSystemBusCapture zero;
    assert(memcmp(capture, &zero, sizeof(*capture)) == 0);
}

static void fixed_native_literals_are_closed(void) {
    assert(strcmp(EXECUTION_SYSTEM_BUS_DBUS_NAME, "org.freedesktop.systemd1") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_MANAGER_PATH, "/org/freedesktop/systemd1") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_MANAGER_INTERFACE, "org.freedesktop.systemd1.Manager") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTIES_INTERFACE, "org.freedesktop.DBus.Properties") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_UNIT_INTERFACE, "org.freedesktop.systemd1.Unit") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_SERVICE_INTERFACE, "org.freedesktop.systemd1.Service") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_TIMER_INTERFACE, "org.freedesktop.systemd1.Timer") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_METHOD_GET_UNIT_BY_PIDFD, "GetUnitByPIDFD") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_METHOD_GET_UNIT, "GetUnit") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_METHOD_GET, "Get") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_ID, "Id") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_INVOCATION_ID, "InvocationID") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_LOAD_STATE, "LoadState") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_ACTIVE_STATE, "ActiveState") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_SUB_STATE, "SubState") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_CONTROL_GROUP, "ControlGroup") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_TIMER_UNIT, "Unit") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_TIMER_RESULT, "Result") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_NEXT_ELAPSE_REALTIME, "NextElapseUSecRealtime") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_NEXT_ELAPSE_MONOTONIC, "NextElapseUSecMonotonic") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_LAST_TRIGGER_REALTIME, "LastTriggerUSec") == 0);
    assert(strcmp(EXECUTION_SYSTEM_BUS_PROPERTY_LAST_TRIGGER_MONOTONIC, "LastTriggerUSecMonotonic") == 0);
    assert(EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES == 16U);
    assert(EXECUTION_SYSTEM_BUS_MIN_SYSTEMD_VERSION == 253U);
}

static void invalid_input_is_zeroed_and_fail_closed(void) {
    ExecutionSystemBusCapture output;

    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(NULL, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_INVALID_INPUT);
    assert_zero_capture(&output);
    assert(execution_system_bus_capture(NULL, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, NULL) ==
           EXECUTION_SYSTEM_BUS_INVALID_INPUT);
}

static void plan_abi_binder_text_and_count_rejections_are_local(void) {
    ExecutionSystemBusPlan plan = valid_plan();
    ExecutionSystemBusCapture output;

    memset(&output, 0xa5, sizeof(output));
    plan.abi_version = 0U;
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
    assert_zero_capture(&output);

    plan = valid_plan();
    memset(plan.tuple_policy_plan_binder.bytes, 0, sizeof(plan.tuple_policy_plan_binder.bytes));
    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
    assert_zero_capture(&output);

    plan = valid_plan();
    plan.named_service_rules[0].unit_id.bytes[0] = 0xc0U;
    plan.named_service_rules[0].unit_id.bytes[1] = 0x80U;
    plan.named_service_rules[0].unit_id.length = 2U;
    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
    assert_zero_capture(&output);

    plan = valid_plan();
    plan.named_service_rule_count = 2U;
    plan.named_service_rules[1] = plan.named_service_rules[0];
    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
    assert_zero_capture(&output);

    plan = valid_plan();
    plan.named_service_rule_count = plan.limits.max_unit_records + 1U;
    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
    assert_zero_capture(&output);

    plan = valid_plan();
    plan.named_service_rules[0].unit_id.length = EXECUTION_WIRE_V1_TEXT_CAPACITY + 1U;
    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
    assert_zero_capture(&output);
}

static void timer_order_and_timeout_overflow_are_local(void) {
    ExecutionSystemBusPlan plan = valid_plan();
    ExecutionSystemBusCapture output;

    plan.timer_rules[0].time[1].member = EXECUTION_SYSTEM_BUS_NEXT_REALTIME;
    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
    assert_zero_capture(&output);

    plan = valid_plan();
    plan.method_timeout_usec = UINT64_MAX;
    plan.snapshot_attempt_timeout_usec = UINT64_MAX;
    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_OVERFLOW);
    assert_zero_capture(&output);
}

static void phase_and_process_bindings_are_checked_before_bus_access(void) {
    ExecutionSystemBusPlan plan = valid_plan();
    ExecutionSystemBusCapture baseline;
    ExecutionSystemBusCapture output;
    ExecutionSystemBusProcessSelector selector;

    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, &baseline, &output) ==
           EXECUTION_SYSTEM_BUS_INVALID_INPUT);
    assert_zero_capture(&output);

    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_FINAL_TARGET, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_INVALID_INPUT);
    assert_zero_capture(&output);

    plan = valid_plan();
    plan.process_rule_count = 1U;
    plan.process_rules[0].selector_id = wire_text("process-a");
    plan.process_rules[0].unit_class_id = wire_text("service");
    plan.process_rules[0].cgroup_class_id = wire_text("system");
    plan.process_rules[0].unit_id = d73_text("dbus.service");
    plan.process_rules[0].cgroup = d73_text("/system.slice/dbus.service");
    plan.process_rules[0].state = state_rule();
    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
    assert_zero_capture(&output);

    selector.selector_id = wire_text("process-a");
    selector.pidfd = -1;
    selector.expected_start_time = 1U;
    memset(&output, 0xa5, sizeof(output));
    assert(execution_system_bus_capture(&plan, &selector, 1U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
    assert_zero_capture(&output);
}

static void borrowed_baseline_is_never_mutated_when_out_aliases_it(void) {
    ExecutionSystemBusPlan plan = valid_plan();
    ExecutionSystemBusCapture baseline;
    ExecutionSystemBusCapture before;

    memset(&baseline, 0xa5, sizeof(baseline));
    before = baseline;
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT,
                                        &baseline, &baseline) == EXECUTION_SYSTEM_BUS_INVALID_INPUT);
    assert(memcmp(&baseline, &before, sizeof(baseline)) == 0);
}

static void time_relations_and_bus_status_mapping_are_exhaustive(void) {
    ExecutionSystemBusTimeRule rule = {
        .member = EXECUTION_SYSTEM_BUS_NEXT_REALTIME,
        .operand = 7U,
    };

    rule.relation = EXECUTION_SYSTEM_BUS_TIME_EQ;
    assert(time_rule_matches(&rule, 7U));
    assert(!time_rule_matches(&rule, 8U));
    rule.relation = EXECUTION_SYSTEM_BUS_TIME_NE;
    assert(time_rule_matches(&rule, 8U));
    assert(!time_rule_matches(&rule, 7U));
    rule.relation = EXECUTION_SYSTEM_BUS_TIME_LT;
    assert(time_rule_matches(&rule, 6U));
    assert(!time_rule_matches(&rule, 7U));
    rule.relation = EXECUTION_SYSTEM_BUS_TIME_LE;
    assert(time_rule_matches(&rule, 7U));
    assert(!time_rule_matches(&rule, 8U));
    rule.relation = EXECUTION_SYSTEM_BUS_TIME_GT;
    assert(time_rule_matches(&rule, 8U));
    assert(!time_rule_matches(&rule, 7U));
    rule.relation = EXECUTION_SYSTEM_BUS_TIME_GE;
    assert(time_rule_matches(&rule, 7U));
    assert(!time_rule_matches(&rule, 6U));
    rule.relation = (ExecutionSystemBusTimeRelation)0;
    assert(!time_rule_matches(&rule, 7U));

    assert(map_bus_result(-ENOMEM) == EXECUTION_SYSTEM_BUS_NOMEM);
    assert(map_bus_result(-ETIMEDOUT) == EXECUTION_SYSTEM_BUS_TIMEOUT);
    assert(map_bus_result(-ETIME) == EXECUTION_SYSTEM_BUS_TIMEOUT);
    assert(map_bus_result(-EINTR) == EXECUTION_SYSTEM_BUS_INTERRUPTED);
    assert(map_bus_result(-EIO) == EXECUTION_SYSTEM_BUS_MANAGER_ERROR);
}

static void wire_identifier_and_call_budget_contracts_are_exact(void) {
    ExecutionSystemBusPlan plan = valid_plan();

    plan.named_service_rules[0].selector_id = wire_text("1service");
    assert(validate_plan(&plan) == EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
    plan.named_service_rules[0].selector_id = wire_text("a1service");
    assert(validate_plan(&plan) == EXECUTION_SYSTEM_BUS_OK);
    plan.named_service_rules[0].selector_id = wire_text("Aservice");
    assert(validate_plan(&plan) == EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);

    plan = valid_plan();
    assert(validate_call_budget(&plan) == EXECUTION_SYSTEM_BUS_OK);
    plan.method_timeout_usec = 10U;
    plan.snapshot_attempt_timeout_usec = 100U;
    assert(validate_call_budget(&plan) == EXECUTION_SYSTEM_BUS_POLICY_MISMATCH);
}

static void baseline_comparator_accepts_owner_shape_and_rejects_mismatch(void) {
    ExecutionSystemBusCapture capture;
    ExecutionSystemBusCapture baseline;

    memset(&capture, 0, sizeof(capture));
    capture.process_binding_count = 1U;
    capture.unit_count = 1U;
    capture.timer_count = 1U;
    capture.process_bindings[0].selector_id = wire_text("process-a");
    capture.process_bindings[0].unit_class_id = wire_text("service");
    capture.process_bindings[0].cgroup_class_id = wire_text("system");
    capture.process_bindings[0].invocation_id[0] = 1U;
    capture.units[0].selector_id = wire_text("unit-a");
    capture.units[0].wire_record.class_id = wire_text("service");
    capture.units[0].invocation_id[0] = 2U;
    capture.timers[0].selector_id = wire_text("timer-a");
    capture.timers[0].bound_unit_class_id = wire_text("service");
    capture.timers[0].invocation_id[0] = 3U;
    baseline = capture;
    assert(capture_matches_baseline(&capture, &baseline));

    baseline.timers[0].invocation_id[0] ^= 1U;
    assert(!capture_matches_baseline(&capture, &baseline));
}

#ifdef THE_HIVE_EXECUTION_SYSTEM_BUS_HOST_TEST
/*
 * Optional, host-dependent evidence only.  It calls the product owner's
 * sd_bus_open_system path against this Fedora host's manager; its shape-valid
 * plan is not an authenticated D73 generation and proves no Root/Live gate.
 */
static void host_manager_capture_uses_the_native_owner(void) {
    ExecutionSystemBusPlan plan = valid_plan();
    ExecutionSystemBusCapture output;
    ExecutionSystemBusCapture baseline;

    plan.method_timeout_usec = UINT64_C(1000000);
    plan.snapshot_attempt_timeout_usec = UINT64_C(8000000);
    plan.timer_rule_count = 0U;
    plan.named_service_rules[0].unit_id = d73_text("dbus-broker.service");
    plan.named_service_rules[0].cgroup = d73_text("/system.slice/dbus-broker.service");
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT, NULL, &output) ==
           EXECUTION_SYSTEM_BUS_OK);
    assert(output.process_binding_count == 0U);
    assert(output.unit_count == 1U);
    assert(output.timer_count == 0U);
    assert(!output.final_target);
    assert(wire_text_equal(&output.units[0].selector_id, &plan.named_service_rules[0].selector_id));
    assert(wire_text_equal(&output.units[0].wire_record.class_id, &plan.named_service_rules[0].unit_class_id));
    assert(wire_text_equal(&output.units[0].wire_record.status, &plan.named_service_rules[0].state.output_state_code));
    assert(output.units[0].wire_record.time_value == 0U);

    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_FINAL_TARGET,
                                        &output, &baseline) == EXECUTION_SYSTEM_BUS_OK);
    assert(baseline.final_target);
    assert(baseline.unit_count == 1U);

    output.units[0].invocation_id[0] ^= 1U;
    memset(&baseline, 0xa5, sizeof(baseline));
    assert(execution_system_bus_capture(&plan, NULL, 0U, EXECUTION_SYSTEM_BUS_PHASE_FINAL_TARGET,
                                        &output, &baseline) == EXECUTION_SYSTEM_BUS_BINDING_MISMATCH);
    assert_zero_capture(&baseline);
}
#endif

int main(void) {
    fixed_native_literals_are_closed();
    invalid_input_is_zeroed_and_fail_closed();
    plan_abi_binder_text_and_count_rejections_are_local();
    timer_order_and_timeout_overflow_are_local();
    phase_and_process_bindings_are_checked_before_bus_access();
    borrowed_baseline_is_never_mutated_when_out_aliases_it();
    time_relations_and_bus_status_mapping_are_exhaustive();
    wire_identifier_and_call_budget_contracts_are_exact();
    baseline_comparator_accepts_owner_shape_and_rejects_mismatch();
#ifdef THE_HIVE_EXECUTION_SYSTEM_BUS_HOST_TEST
    host_manager_capture_uses_the_native_owner();
    puts("test_execution_system_bus: PASS (optional host manager; no D73/Root/Live claim)");
#else
    puts("test_execution_system_bus: PASS (deterministic schema checks)");
#endif
    return 0;
}
