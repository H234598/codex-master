#ifndef THE_HIVE_EXECUTION_WIRE_V1_H
#define THE_HIVE_EXECUTION_WIRE_V1_H

/*
 * Pure, allocation-free RFC 8949 deterministic CBOR for the offline G0B
 * execution wire.  The caller supplies every policy bound; this module does
 * not select releases, paths, identities, or host policy.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EXECUTION_WIRE_V1_SCHEMA_VERSION UINT64_C(1)
#define EXECUTION_WIRE_V1_DIGEST_SIZE 32U
#define EXECUTION_WIRE_V1_TEXT_CAPACITY 63U
#define EXECUTION_WIRE_V1_MAX_ROLES 32U
#define EXECUTION_WIRE_V1_MAX_PHASES 32U
#define EXECUTION_WIRE_V1_MAX_PROCESS_RECORDS 128U
#define EXECUTION_WIRE_V1_MAX_FD_RECORDS 256U
#define EXECUTION_WIRE_V1_MAX_FDINFO_RECORDS 256U
#define EXECUTION_WIRE_V1_MAX_LOCK_RECORDS 256U
#define EXECUTION_WIRE_V1_MAX_NAMESPACE_RECORDS 128U
#define EXECUTION_WIRE_V1_MAX_UNIT_RECORDS 128U
#define EXECUTION_WIRE_V1_MAX_TIMER_RECORDS 128U
#define EXECUTION_WIRE_V1_HARD_MAX_TOTAL_BYTES (16U * 1024U * 1024U)
#define EXECUTION_WIRE_V1_ENVELOPE_FD 3U
#define EXECUTION_WIRE_V1_SEAL_SEAL 0x0001U
#define EXECUTION_WIRE_V1_SEAL_SHRINK 0x0002U
#define EXECUTION_WIRE_V1_SEAL_GROW 0x0004U
#define EXECUTION_WIRE_V1_SEAL_WRITE 0x0008U
#define EXECUTION_WIRE_V1_REQUIRED_SEALS \
    (EXECUTION_WIRE_V1_SEAL_SEAL | EXECUTION_WIRE_V1_SEAL_SHRINK | \
     EXECUTION_WIRE_V1_SEAL_GROW | EXECUTION_WIRE_V1_SEAL_WRITE)
#define EXECUTION_WIRE_V1_APPROVAL_RECORD_KIND "execution-approval.v1"
#define EXECUTION_WIRE_V1_APPROVAL_RECORD_PATH "meta/execution-approval.v1.cbor"

typedef enum ExecutionWireV1Status {
    EXECUTION_WIRE_V1_OK = 0,
    EXECUTION_WIRE_V1_INVALID_ARGUMENT,
    EXECUTION_WIRE_V1_LIMIT,
    EXECUTION_WIRE_V1_BUFFER_TOO_SMALL,
    EXECUTION_WIRE_V1_TRUNCATED,
    EXECUTION_WIRE_V1_NONCANONICAL,
    EXECUTION_WIRE_V1_MALFORMED,
    EXECUTION_WIRE_V1_MISMATCH
} ExecutionWireV1Status;

typedef struct ExecutionWireV1Digest {
    uint8_t bytes[EXECUTION_WIRE_V1_DIGEST_SIZE];
} ExecutionWireV1Digest;

/* Text is ASCII; identifiers and non-empty relative-path segments match [a-z][a-z0-9._-]* exactly. */
typedef struct ExecutionWireV1Text {
    uint8_t bytes[EXECUTION_WIRE_V1_TEXT_CAPACITY + 1U];
    size_t length;
} ExecutionWireV1Text;

/* Every effective collection and parser bound is a validated producer input. */
typedef struct ExecutionWireV1Limits {
    size_t max_total_bytes;
    size_t max_snapshot_bytes;
    size_t max_text_bytes;
    size_t max_roles;
    size_t max_phases;
    size_t max_process_records;
    size_t max_fd_records;
    size_t max_fdinfo_records;
    size_t max_lock_records;
    size_t max_namespace_records;
    size_t max_unit_records;
    size_t max_timer_records;
} ExecutionWireV1Limits;

typedef struct ExecutionWireV1RoleDigest {
    ExecutionWireV1Text role_id;
    ExecutionWireV1Text relative_path;
    ExecutionWireV1Digest normal_digest;
} ExecutionWireV1RoleDigest;

/* Full D73-selected view; authentication of its binder belongs to D73. */
typedef struct D73AuthorizedExecutionTupleV1 {
    uint64_t schema_version;
    uint64_t execution_abi_version;
    ExecutionWireV1Text authority_domain;
    uint64_t generation;
    ExecutionWireV1Digest source_manifest_digest;
    ExecutionWireV1Digest tuple_digest;
    ExecutionWireV1RoleDigest roles[EXECUTION_WIRE_V1_MAX_ROLES];
    size_t role_count;
    ExecutionWireV1Digest policy_leaf_digest;
    ExecutionWireV1Digest launcher_leaf_digest;
    ExecutionWireV1Digest attestor_leaf_digest;
    uint64_t phase;
    ExecutionWireV1Digest d73_authorization_binder;
} D73AuthorizedExecutionTupleV1;

typedef struct ExecutionWireV1RoleMeasurement {
    ExecutionWireV1Text role_id;
    ExecutionWireV1Text relative_path;
    ExecutionWireV1Digest normal_digest;
    ExecutionWireV1Digest verity_digest;
    ExecutionWireV1Text owner_class;
    uint64_t expected_mode;
    uint64_t nlink;
    uint64_t device;
    uint64_t inode;
    bool verity_enabled;
} ExecutionWireV1RoleMeasurement;

/* No self-digest, pointer, retention, desired-generation, or alternate map. */
typedef struct ApprovalRecordV1 {
    uint64_t schema_version;
    uint64_t execution_abi_version;
    ExecutionWireV1Text record_kind;
    ExecutionWireV1Digest tuple_digest;
    ExecutionWireV1Digest source_manifest_digest;
    ExecutionWireV1Digest d73_authorization_binder;
    uint64_t generation;
    ExecutionWireV1RoleMeasurement roles[EXECUTION_WIRE_V1_MAX_ROLES];
    size_t role_count;
    ExecutionWireV1Digest policy_leaf_digest;
    ExecutionWireV1Digest launcher_leaf_digest;
    ExecutionWireV1Digest attestor_leaf_digest;
    uint64_t policy_collector_abi_version;
    uint64_t allowed_phases[EXECUTION_WIRE_V1_MAX_PHASES];
    size_t allowed_phase_count;
    ExecutionWireV1Digest host_binding_digest;
    ExecutionWireV1Digest boot_binding_digest;
    ExecutionWireV1Text record_relative_path;
} ApprovalRecordV1;

typedef struct ExecutionWireV1ProcessRecord {
    uint64_t pid;
    uint64_t uid;
    uint64_t ppid;
    uint64_t start_time;
    ExecutionWireV1Text comm;
    ExecutionWireV1Text exe_basename;
    ExecutionWireV1Text cgroup_class;
    ExecutionWireV1Text unit_class;
} ExecutionWireV1ProcessRecord;

typedef struct ExecutionWireV1FdRecord {
    uint64_t pid;
    uint64_t start_time;
    uint64_t fd;
    uint64_t device;
    uint64_t inode;
    uint64_t flags;
    uint64_t position;
    ExecutionWireV1Text type_id;
} ExecutionWireV1FdRecord;

typedef struct ExecutionWireV1FdInfoRecord {
    uint64_t pid;
    uint64_t start_time;
    uint64_t fd;
    uint64_t flags;
    uint64_t position;
    ExecutionWireV1Text identifier;
} ExecutionWireV1FdInfoRecord;

typedef struct ExecutionWireV1LockRecord {
    uint64_t pid;
    uint64_t start_time;
    uint64_t device;
    uint64_t inode;
    uint64_t range_start;
    uint64_t range_end;
    ExecutionWireV1Text lock_class;
} ExecutionWireV1LockRecord;

typedef struct ExecutionWireV1NamespaceRecord {
    uint64_t pid;
    uint64_t start_time;
    uint64_t inode;
    ExecutionWireV1Text class_id;
} ExecutionWireV1NamespaceRecord;

typedef struct ExecutionWireV1ServiceRecord {
    ExecutionWireV1Text class_id;
    ExecutionWireV1Text status;
    uint64_t time_value;
} ExecutionWireV1ServiceRecord;

typedef struct ExecutionWireV1SnapshotV1 {
    ExecutionWireV1Digest selector_digest;
    uint64_t monotonic_capture_interval;
    bool complete;
    ExecutionWireV1ProcessRecord processes[EXECUTION_WIRE_V1_MAX_PROCESS_RECORDS];
    size_t process_count;
    ExecutionWireV1FdRecord fds[EXECUTION_WIRE_V1_MAX_FD_RECORDS];
    size_t fd_count;
    ExecutionWireV1FdInfoRecord fdinfo[EXECUTION_WIRE_V1_MAX_FDINFO_RECORDS];
    size_t fdinfo_count;
    ExecutionWireV1LockRecord locks[EXECUTION_WIRE_V1_MAX_LOCK_RECORDS];
    size_t lock_count;
    ExecutionWireV1NamespaceRecord namespaces[EXECUTION_WIRE_V1_MAX_NAMESPACE_RECORDS];
    size_t namespace_count;
    ExecutionWireV1ServiceRecord units[EXECUTION_WIRE_V1_MAX_UNIT_RECORDS];
    size_t unit_count;
    ExecutionWireV1ServiceRecord timers[EXECUTION_WIRE_V1_MAX_TIMER_RECORDS];
    size_t timer_count;
} ExecutionWireV1SnapshotV1;

typedef struct ExecutionWireV1TargetFinal {
    ExecutionWireV1Digest selector_digest;
    ExecutionWireV1Digest observed_target_set_digest;
    bool final_predicate;
} ExecutionWireV1TargetFinal;

typedef struct ExecutionEnvelopeV1 {
    uint64_t schema_version;
    uint64_t execution_abi_version;
    uint64_t phase;
    uint64_t collector_abi_version;
    ExecutionWireV1Digest tuple_digest;
    ExecutionWireV1Digest source_manifest_digest;
    /* In-memory measured digest; it is not a field of ApprovalRecordV1. */
    ExecutionWireV1Digest approval_record_digest;
    uint64_t generation;
    ExecutionWireV1Digest policy_leaf_digest;
    ExecutionWireV1Digest launcher_leaf_digest;
    ExecutionWireV1Digest attestor_leaf_digest;
    ExecutionWireV1Digest host_binding_digest;
    ExecutionWireV1Digest boot_binding_digest;
    ExecutionWireV1Digest collector_artifact_binder;
    ExecutionWireV1SnapshotV1 snapshot_a;
    ExecutionWireV1SnapshotV1 snapshot_b;
    ExecutionWireV1Digest snapshot_a_digest;
    ExecutionWireV1Digest snapshot_b_digest;
    ExecutionWireV1TargetFinal target_final;
    uint64_t fd_number;
    uint64_t fd_seal_mask;
    bool fd_cloexec;
} ExecutionEnvelopeV1;

ExecutionWireV1Status execution_wire_v1_encode_tuple(
    const D73AuthorizedExecutionTupleV1 *input,
    const ExecutionWireV1Limits *limits,
    uint8_t *output,
    size_t *inout_length
);
ExecutionWireV1Status execution_wire_v1_decode_tuple(
    const uint8_t *input,
    size_t input_length,
    const ExecutionWireV1Limits *limits,
    D73AuthorizedExecutionTupleV1 *output
);
ExecutionWireV1Status execution_wire_v1_encode_approval(
    const ApprovalRecordV1 *input,
    const ExecutionWireV1Limits *limits,
    uint8_t *output,
    size_t *inout_length
);
ExecutionWireV1Status execution_wire_v1_decode_approval(
    const uint8_t *input,
    size_t input_length,
    const ExecutionWireV1Limits *limits,
    ApprovalRecordV1 *output
);
ExecutionWireV1Status execution_wire_v1_encode_envelope(
    const ExecutionEnvelopeV1 *input,
    const ExecutionWireV1Limits *limits,
    uint8_t *output,
    size_t *inout_length
);
ExecutionWireV1Status execution_wire_v1_decode_envelope(
    const uint8_t *input,
    size_t input_length,
    const ExecutionWireV1Limits *limits,
    ExecutionEnvelopeV1 *output
);

/* SHA-256 of the fixed canonical snapshot-binding CBOR preimage. */
ExecutionWireV1Status execution_wire_v1_snapshot_digest(
    const ExecutionWireV1SnapshotV1 *snapshot,
    const ExecutionWireV1Limits *limits,
    ExecutionWireV1Digest *output
);

ExecutionWireV1Status execution_wire_v1_validate_approval_for_tuple(
    const ApprovalRecordV1 *approval,
    const D73AuthorizedExecutionTupleV1 *tuple,
    const ExecutionWireV1Limits *limits
);
ExecutionWireV1Status execution_wire_v1_validate_envelope_for_tuple_and_approval(
    const ExecutionEnvelopeV1 *envelope,
    const D73AuthorizedExecutionTupleV1 *tuple,
    const ApprovalRecordV1 *approval,
    const ExecutionWireV1Digest *measured_approval_record_digest,
    const ExecutionWireV1Limits *limits
);

#ifdef __cplusplus
}
#endif

#endif
