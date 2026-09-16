#ifndef THE_HIVE_EXECUTION_SYSTEM_BUS_H
#define THE_HIVE_EXECUTION_SYSTEM_BUS_H

/*
 * Fixed ABI-v1 system-manager reader.  This is the only native owner of the
 * system bus path; callers supply only an already bound D73 plan and pidfds.
 */

#include "execution_wire_v1.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EXECUTION_SYSTEM_BUS_ABI_VERSION 1U
#define EXECUTION_SYSTEM_BUS_MIN_SYSTEMD_VERSION 253U
#define EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES 16U

#define EXECUTION_SYSTEM_BUS_DBUS_NAME "org.freedesktop.systemd1"
#define EXECUTION_SYSTEM_BUS_MANAGER_PATH "/org/freedesktop/systemd1"
#define EXECUTION_SYSTEM_BUS_MANAGER_INTERFACE "org.freedesktop.systemd1.Manager"
#define EXECUTION_SYSTEM_BUS_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define EXECUTION_SYSTEM_BUS_UNIT_INTERFACE "org.freedesktop.systemd1.Unit"
#define EXECUTION_SYSTEM_BUS_SERVICE_INTERFACE "org.freedesktop.systemd1.Service"
#define EXECUTION_SYSTEM_BUS_TIMER_INTERFACE "org.freedesktop.systemd1.Timer"
#define EXECUTION_SYSTEM_BUS_METHOD_GET_UNIT_BY_PIDFD "GetUnitByPIDFD"
#define EXECUTION_SYSTEM_BUS_METHOD_GET_UNIT "GetUnit"
#define EXECUTION_SYSTEM_BUS_METHOD_GET "Get"
#define EXECUTION_SYSTEM_BUS_PROPERTY_ID "Id"
#define EXECUTION_SYSTEM_BUS_PROPERTY_INVOCATION_ID "InvocationID"
#define EXECUTION_SYSTEM_BUS_PROPERTY_LOAD_STATE "LoadState"
#define EXECUTION_SYSTEM_BUS_PROPERTY_ACTIVE_STATE "ActiveState"
#define EXECUTION_SYSTEM_BUS_PROPERTY_SUB_STATE "SubState"
#define EXECUTION_SYSTEM_BUS_PROPERTY_CONTROL_GROUP "ControlGroup"
#define EXECUTION_SYSTEM_BUS_PROPERTY_TIMER_UNIT "Unit"
#define EXECUTION_SYSTEM_BUS_PROPERTY_TIMER_RESULT "Result"
#define EXECUTION_SYSTEM_BUS_PROPERTY_NEXT_ELAPSE_REALTIME "NextElapseUSecRealtime"
#define EXECUTION_SYSTEM_BUS_PROPERTY_NEXT_ELAPSE_MONOTONIC "NextElapseUSecMonotonic"
#define EXECUTION_SYSTEM_BUS_PROPERTY_LAST_TRIGGER_REALTIME "LastTriggerUSec"
#define EXECUTION_SYSTEM_BUS_PROPERTY_LAST_TRIGGER_MONOTONIC "LastTriggerUSecMonotonic"

typedef enum ExecutionSystemBusPhase {
    EXECUTION_SYSTEM_BUS_PHASE_SNAPSHOT = 1,
    EXECUTION_SYSTEM_BUS_PHASE_FINAL_TARGET = 2
} ExecutionSystemBusPhase;

typedef enum ExecutionSystemBusStatus {
    EXECUTION_SYSTEM_BUS_OK = 0,
    EXECUTION_SYSTEM_BUS_INVALID_INPUT,
    EXECUTION_SYSTEM_BUS_POLICY_MISMATCH,
    EXECUTION_SYSTEM_BUS_OVERFLOW,
    EXECUTION_SYSTEM_BUS_NOMEM,
    EXECUTION_SYSTEM_BUS_OPEN_FAILED,
    EXECUTION_SYSTEM_BUS_TIMEOUT,
    EXECUTION_SYSTEM_BUS_INTERRUPTED,
    EXECUTION_SYSTEM_BUS_MANAGER_ERROR,
    EXECUTION_SYSTEM_BUS_PROTOCOL_ERROR,
    EXECUTION_SYSTEM_BUS_BINDING_MISMATCH
} ExecutionSystemBusStatus;

typedef struct ExecutionSystemBusD73Text {
    uint8_t bytes[EXECUTION_WIRE_V1_TEXT_CAPACITY + 1U];
    size_t length;
} ExecutionSystemBusD73Text;

typedef struct ExecutionSystemBusProcessSelector {
    ExecutionWireV1Text selector_id;
    int pidfd; /* Borrowed.  This owner never closes it. */
    uint64_t expected_start_time;
} ExecutionSystemBusProcessSelector;

typedef struct ExecutionSystemBusProcessBinding {
    ExecutionWireV1Text selector_id;
    ExecutionWireV1Text unit_class_id;
    ExecutionWireV1Text cgroup_class_id;
    ExecutionWireV1Text state_code;
    uint8_t invocation_id[EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES];
} ExecutionSystemBusProcessBinding;

typedef struct ExecutionSystemBusUnitObservation {
    ExecutionWireV1Text selector_id;
    ExecutionWireV1ServiceRecord wire_record;
    uint8_t invocation_id[EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES];
} ExecutionSystemBusUnitObservation;

typedef struct ExecutionSystemBusTimerObservation {
    ExecutionWireV1Text selector_id;
    ExecutionWireV1Text bound_unit_class_id;
    ExecutionWireV1Text unit_state_code;
    ExecutionWireV1Text timer_result_code;
    uint64_t next_elapse_realtime_usec;
    uint64_t next_elapse_monotonic_usec;
    uint64_t last_trigger_realtime_usec;
    uint64_t last_trigger_monotonic_usec;
    uint8_t invocation_id[EXECUTION_SYSTEM_BUS_INVOCATION_ID_BYTES];
} ExecutionSystemBusTimerObservation;

typedef struct ExecutionSystemBusCapture {
    ExecutionSystemBusProcessBinding process_bindings[EXECUTION_WIRE_V1_MAX_PROCESS_RECORDS];
    size_t process_binding_count;
    ExecutionSystemBusUnitObservation units[EXECUTION_WIRE_V1_MAX_UNIT_RECORDS];
    size_t unit_count;
    ExecutionSystemBusTimerObservation timers[EXECUTION_WIRE_V1_MAX_TIMER_RECORDS];
    size_t timer_count;
    bool final_target;
} ExecutionSystemBusCapture;

typedef struct ExecutionSystemBusStateRule {
    ExecutionSystemBusD73Text load_state;
    ExecutionSystemBusD73Text active_state;
    ExecutionSystemBusD73Text sub_state;
    ExecutionWireV1Text output_state_code;
} ExecutionSystemBusStateRule;

typedef enum ExecutionSystemBusTimeMember {
    EXECUTION_SYSTEM_BUS_NEXT_REALTIME = 1,
    EXECUTION_SYSTEM_BUS_NEXT_MONOTONIC = 2,
    EXECUTION_SYSTEM_BUS_LAST_REALTIME = 3,
    EXECUTION_SYSTEM_BUS_LAST_MONOTONIC = 4
} ExecutionSystemBusTimeMember;

typedef enum ExecutionSystemBusTimeRelation {
    EXECUTION_SYSTEM_BUS_TIME_EQ = 1,
    EXECUTION_SYSTEM_BUS_TIME_NE = 2,
    EXECUTION_SYSTEM_BUS_TIME_LT = 3,
    EXECUTION_SYSTEM_BUS_TIME_LE = 4,
    EXECUTION_SYSTEM_BUS_TIME_GT = 5,
    EXECUTION_SYSTEM_BUS_TIME_GE = 6
} ExecutionSystemBusTimeRelation;

typedef struct ExecutionSystemBusTimeRule {
    ExecutionSystemBusTimeMember member;
    ExecutionSystemBusTimeRelation relation;
    uint64_t operand;
} ExecutionSystemBusTimeRule;

typedef struct ExecutionSystemBusProcessRule {
    ExecutionWireV1Text selector_id;
    ExecutionWireV1Text unit_class_id;
    ExecutionWireV1Text cgroup_class_id;
    ExecutionSystemBusD73Text unit_id;
    ExecutionSystemBusD73Text cgroup;
    ExecutionSystemBusStateRule state;
} ExecutionSystemBusProcessRule;

typedef struct ExecutionSystemBusNamedServiceRule {
    ExecutionWireV1Text selector_id;
    ExecutionWireV1Text unit_class_id;
    ExecutionSystemBusD73Text unit_id;
    ExecutionSystemBusD73Text cgroup;
    ExecutionSystemBusStateRule state;
} ExecutionSystemBusNamedServiceRule;

typedef struct ExecutionSystemBusTimerRule {
    ExecutionWireV1Text selector_id;
    ExecutionWireV1Text timer_class_id;
    ExecutionWireV1Text bound_unit_class_id;
    ExecutionWireV1Text output_result_code;
    ExecutionSystemBusD73Text timer_unit_id;
    ExecutionSystemBusD73Text bound_service_unit_id;
    ExecutionSystemBusD73Text result;
    ExecutionSystemBusStateRule state;
    ExecutionSystemBusTimeRule time[4];
} ExecutionSystemBusTimerRule;

typedef struct ExecutionSystemBusPlan {
    uint32_t abi_version;
    ExecutionWireV1Digest tuple_policy_plan_binder;
    ExecutionWireV1Limits limits;
    uint64_t method_timeout_usec;
    uint64_t snapshot_attempt_timeout_usec;
    uint32_t max_snapshot_attempts;
    ExecutionSystemBusProcessRule process_rules[EXECUTION_WIRE_V1_MAX_PROCESS_RECORDS];
    size_t process_rule_count;
    ExecutionSystemBusNamedServiceRule named_service_rules[EXECUTION_WIRE_V1_MAX_UNIT_RECORDS];
    size_t named_service_rule_count;
    ExecutionSystemBusTimerRule timer_rules[EXECUTION_WIRE_V1_MAX_TIMER_RECORDS];
    size_t timer_rule_count;
} ExecutionSystemBusPlan;

/*
 * All arguments are borrowed except caller-owned out.  out is zeroed on every
 * ordinary error path; it must not alias identity_baseline.  An alias is
 * rejected before any out mutation so the borrowed baseline remains intact.
 */
ExecutionSystemBusStatus execution_system_bus_capture(
    const ExecutionSystemBusPlan *plan,
    const ExecutionSystemBusProcessSelector *processes,
    size_t process_count,
    ExecutionSystemBusPhase phase,
    const ExecutionSystemBusCapture *identity_baseline,
    ExecutionSystemBusCapture *out
);

#ifdef __cplusplus
}
#endif

#endif
