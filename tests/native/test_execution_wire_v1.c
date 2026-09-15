/* RED first: this focused harness is intentionally compiled directly. */
#ifdef NDEBUG
#error "test_execution_wire_v1 requires assertions"
typedef int execution_wire_v1_ndebug_is_forbidden;
#else

#include "execution_wire_v1.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const ExecutionWireV1Limits *limits(void) {
    static const ExecutionWireV1Limits value = {
        .max_total_bytes = 65536U,
        .max_snapshot_bytes = 32768U,
        .max_text_bytes = 63U,
        .max_roles = 8U,
        .max_phases = 4U,
        .max_process_records = 4U,
        .max_fd_records = 4U,
        .max_fdinfo_records = 4U,
        .max_lock_records = 4U,
        .max_namespace_records = 4U,
        .max_unit_records = 4U,
        .max_timer_records = 4U,
    };
    return &value;
}

static ExecutionWireV1Digest digest(uint8_t seed) {
    ExecutionWireV1Digest value;
    size_t index;
    for (index = 0U; index < EXECUTION_WIRE_V1_DIGEST_SIZE; ++index) {
        value.bytes[index] = (uint8_t)(seed + index);
    }
    return value;
}

static ExecutionWireV1Text text(const char *value) {
    ExecutionWireV1Text result;
    size_t length = strlen(value);
    assert(length < sizeof(result.bytes));
    memset(&result, 0, sizeof(result));
    memcpy(result.bytes, value, length);
    result.length = length;
    return result;
}

static D73AuthorizedExecutionTupleV1 tuple(void) {
    D73AuthorizedExecutionTupleV1 value;
    memset(&value, 0, sizeof(value));
    value.schema_version = EXECUTION_WIRE_V1_SCHEMA_VERSION;
    value.execution_abi_version = 7U;
    value.authority_domain = text("d73-authority");
    value.generation = 42U;
    value.source_manifest_digest = digest(1U);
    value.tuple_digest = digest(2U);
    value.policy_leaf_digest = digest(3U);
    value.launcher_leaf_digest = digest(4U);
    value.attestor_leaf_digest = digest(5U);
    value.phase = 9U;
    value.d73_authorization_binder = digest(6U);
    value.role_count = 2U;
    /* Deliberately unsorted input proves encoder canonicalizes the role map. */
    value.roles[0].role_id = text("z-attestor");
    value.roles[0].relative_path = text("libexec/the-hive-execution-attestor");
    value.roles[0].normal_digest = value.attestor_leaf_digest;
    value.roles[1].role_id = text("a-launcher");
    value.roles[1].relative_path = text("libexec/the-hive-execution-launcher");
    value.roles[1].normal_digest = value.launcher_leaf_digest;
    return value;
}

static ApprovalRecordV1 approval(const D73AuthorizedExecutionTupleV1 *tuple_value) {
    ApprovalRecordV1 value;
    memset(&value, 0, sizeof(value));
    value.schema_version = EXECUTION_WIRE_V1_SCHEMA_VERSION;
    value.execution_abi_version = tuple_value->execution_abi_version;
    value.record_kind = text(EXECUTION_WIRE_V1_APPROVAL_RECORD_KIND);
    value.tuple_digest = tuple_value->tuple_digest;
    value.source_manifest_digest = tuple_value->source_manifest_digest;
    value.d73_authorization_binder = tuple_value->d73_authorization_binder;
    value.generation = tuple_value->generation;
    value.role_count = 2U;
    value.roles[0].role_id = text("a-launcher");
    value.roles[0].relative_path = text("libexec/the-hive-execution-launcher");
    value.roles[0].normal_digest = tuple_value->launcher_leaf_digest;
    value.roles[0].verity_digest = digest(11U);
    value.roles[0].owner_class = text("root-owner");
    value.roles[0].expected_mode = 0400U;
    value.roles[0].nlink = 1U;
    value.roles[0].device = 12U;
    value.roles[0].inode = 13U;
    value.roles[0].verity_enabled = true;
    value.roles[1].role_id = text("z-attestor");
    value.roles[1].relative_path = text("libexec/the-hive-execution-attestor");
    value.roles[1].normal_digest = tuple_value->attestor_leaf_digest;
    value.roles[1].verity_digest = digest(12U);
    value.roles[1].owner_class = text("root-owner");
    value.roles[1].expected_mode = 0400U;
    value.roles[1].nlink = 1U;
    value.roles[1].device = 14U;
    value.roles[1].inode = 15U;
    value.roles[1].verity_enabled = true;
    value.policy_leaf_digest = tuple_value->policy_leaf_digest;
    value.launcher_leaf_digest = tuple_value->launcher_leaf_digest;
    value.attestor_leaf_digest = tuple_value->attestor_leaf_digest;
    value.policy_collector_abi_version = 3U;
    value.allowed_phase_count = 1U;
    value.allowed_phases[0] = tuple_value->phase;
    value.host_binding_digest = digest(20U);
    value.boot_binding_digest = digest(21U);
    value.record_relative_path = text(EXECUTION_WIRE_V1_APPROVAL_RECORD_PATH);
    return value;
}

static ExecutionEnvelopeV1 envelope(
    const D73AuthorizedExecutionTupleV1 *tuple_value,
    const ApprovalRecordV1 *approval_value,
    const ExecutionWireV1Digest *approval_digest
) {
    ExecutionEnvelopeV1 value;
    ExecutionWireV1SnapshotV1 *a;
    ExecutionWireV1SnapshotV1 *b;
    memset(&value, 0, sizeof(value));
    value.schema_version = EXECUTION_WIRE_V1_SCHEMA_VERSION;
    value.execution_abi_version = tuple_value->execution_abi_version;
    value.collector_abi_version = approval_value->policy_collector_abi_version;
    value.phase = tuple_value->phase;
    value.tuple_digest = tuple_value->tuple_digest;
    value.source_manifest_digest = tuple_value->source_manifest_digest;
    value.approval_record_digest = *approval_digest;
    value.generation = tuple_value->generation;
    value.policy_leaf_digest = tuple_value->policy_leaf_digest;
    value.launcher_leaf_digest = tuple_value->launcher_leaf_digest;
    value.attestor_leaf_digest = tuple_value->attestor_leaf_digest;
    value.host_binding_digest = approval_value->host_binding_digest;
    value.boot_binding_digest = approval_value->boot_binding_digest;
    value.collector_artifact_binder = tuple_value->launcher_leaf_digest;
    value.fd_number = EXECUTION_WIRE_V1_ENVELOPE_FD;
    value.fd_seal_mask = EXECUTION_WIRE_V1_REQUIRED_SEALS;
    value.fd_cloexec = false;
    a = &value.snapshot_a;
    b = &value.snapshot_b;
    a->selector_digest = digest(41U);
    a->monotonic_capture_interval = 10U;
    a->complete = true;
    a->process_count = 1U;
    a->processes[0].pid = 100U;
    a->processes[0].uid = 200U;
    a->processes[0].ppid = 1U;
    a->processes[0].start_time = 300U;
    a->processes[0].comm = text("attestor");
    a->processes[0].exe_basename = text("attestor");
    a->processes[0].cgroup_class = text("approved-cgroup");
    a->processes[0].unit_class = text("approved-unit");
    a->fd_count = 1U;
    a->fds[0].pid = 100U;
    a->fds[0].start_time = 300U;
    a->fds[0].fd = 3U;
    a->fds[0].device = 1U;
    a->fds[0].inode = 2U;
    a->fds[0].flags = 0U;
    a->fds[0].position = 0U;
    a->fds[0].type_id = text("memfd");
    a->fdinfo_count = 1U;
    a->fdinfo[0].pid = 100U;
    a->fdinfo[0].start_time = 300U;
    a->fdinfo[0].fd = 3U;
    a->fdinfo[0].flags = 0U;
    a->fdinfo[0].position = 0U;
    a->fdinfo[0].identifier = text("sealed");
    a->lock_count = 1U;
    a->locks[0].pid = 100U;
    a->locks[0].start_time = 300U;
    a->locks[0].device = 1U;
    a->locks[0].inode = 2U;
    a->locks[0].range_start = 0U;
    a->locks[0].range_end = 1U;
    a->locks[0].lock_class = text("read");
    a->namespace_count = 1U;
    a->namespaces[0].pid = 100U;
    a->namespaces[0].start_time = 300U;
    a->namespaces[0].inode = 90U;
    a->namespaces[0].class_id = text("pid");
    a->unit_count = 1U;
    a->units[0].class_id = text("approved-unit");
    a->units[0].status = text("active");
    a->units[0].time_value = 2U;
    a->timer_count = 1U;
    a->timers[0].class_id = text("approved-timer");
    a->timers[0].status = text("waiting");
    a->timers[0].time_value = 3U;
    *b = *a;
    b->monotonic_capture_interval = 11U;
    assert(execution_wire_v1_snapshot_digest(&value.snapshot_a, limits(), &value.snapshot_a_digest) == EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_snapshot_digest(&value.snapshot_b, limits(), &value.snapshot_b_digest) == EXECUTION_WIRE_V1_OK);
    value.target_final.selector_digest = value.snapshot_a.selector_digest;
    value.target_final.observed_target_set_digest = digest(62U);
    value.target_final.final_predicate = true;
    return value;
}

static size_t locate(const uint8_t *bytes, size_t length, const char *needle) {
    size_t index;
    size_t needle_length = strlen(needle);
    assert(needle_length > 0U && needle_length <= length);
    for (index = 0U; index + needle_length <= length; ++index) {
        if (memcmp(bytes + index, needle, needle_length) == 0) return index;
    }
    assert(!"required CBOR key was absent");
    return 0U;
}

static size_t locate_bytes(const uint8_t *bytes, size_t length, const uint8_t *needle, size_t needle_length) {
    size_t index;
    assert(needle_length > 0U && needle_length <= length);
    for (index = 0U; index + needle_length <= length; ++index) {
        if (memcmp(bytes + index, needle, needle_length) == 0) return index;
    }
    assert(!"required CBOR value was absent");
    return 0U;
}

typedef struct CborAuditCursor {
    const uint8_t *bytes;
    size_t length;
    size_t position;
} CborAuditCursor;

static uint64_t cbor_audit_head(CborAuditCursor *cursor, uint8_t *major) {
    uint8_t initial;
    uint8_t additional;
    uint8_t width;
    uint8_t index;
    uint64_t value = 0U;
    assert(cursor->position < cursor->length);
    initial = cursor->bytes[cursor->position++];
    *major = initial >> 5U;
    additional = initial & 0x1fU;
    assert(additional != 31U);
    if (additional < 24U) return additional;
    width = additional == 24U ? 1U : additional == 25U ? 2U : additional == 26U ? 4U : 8U;
    assert(additional <= 27U && (size_t)width <= cursor->length - cursor->position);
    for (index = 0U; index < width; ++index) value = (value << 8U) | cursor->bytes[cursor->position++];
    return value;
}

static int cbor_audit_compare_key(const uint8_t *left, size_t left_length, const uint8_t *right, size_t right_length) {
    size_t shortest = left_length < right_length ? left_length : right_length;
    int comparison = memcmp(left, right, shortest);
    if (comparison != 0) return comparison;
    return left_length < right_length ? -1 : left_length > right_length ? 1 : 0;
}

static void cbor_audit_item(CborAuditCursor *cursor) {
    uint8_t major;
    uint64_t argument = cbor_audit_head(cursor, &major);
    uint64_t index;
    if (major == 0U || major == 1U || major == 7U) return;
    if (major == 2U || major == 3U) {
        assert(argument <= (uint64_t)(cursor->length - cursor->position));
        cursor->position += (size_t)argument;
        return;
    }
    if (major == 4U) {
        for (index = 0U; index < argument; ++index) cbor_audit_item(cursor);
        return;
    }
    if (major == 5U) {
        const uint8_t *previous_key = NULL;
        size_t previous_length = 0U;
        for (index = 0U; index < argument; ++index) {
            size_t key_start = cursor->position;
            cbor_audit_item(cursor);
            assert(previous_key == NULL || cbor_audit_compare_key(previous_key, previous_length, cursor->bytes + key_start, cursor->position - key_start) < 0);
            previous_key = cursor->bytes + key_start;
            previous_length = cursor->position - key_start;
            cbor_audit_item(cursor);
        }
        return;
    }
    if (major == 6U) {
        cbor_audit_item(cursor);
        return;
    }
    assert(!"unsupported CBOR major type");
}

static void encoded_maps_are_rfc8949_ordered(void) {
    uint8_t bytes[65536];
    size_t length;
    CborAuditCursor cursor;
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ExecutionWireV1Digest approval_digest = digest(70U);
    ExecutionEnvelopeV1 envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
#define AUDIT_ENCODED_MAPS(encode_call) do { \
    length = sizeof(bytes); \
    assert((encode_call) == EXECUTION_WIRE_V1_OK); \
    cursor = (CborAuditCursor){.bytes = bytes, .length = length, .position = 0U}; \
    cbor_audit_item(&cursor); \
    assert(cursor.position == length); \
} while (0)
    AUDIT_ENCODED_MAPS(execution_wire_v1_encode_tuple(&tuple_value, limits(), bytes, &length));
    AUDIT_ENCODED_MAPS(execution_wire_v1_encode_approval(&approval_value, limits(), bytes, &length));
    AUDIT_ENCODED_MAPS(execution_wire_v1_encode_envelope(&envelope_value, limits(), bytes, &length));
#undef AUDIT_ENCODED_MAPS
}

static bool same_digest(const ExecutionWireV1Digest *left, const ExecutionWireV1Digest *right) {
    return memcmp(left->bytes, right->bytes, EXECUTION_WIRE_V1_DIGEST_SIZE) == 0;
}

static bool same_text(const ExecutionWireV1Text *left, const ExecutionWireV1Text *right) {
    return left->length == right->length && memcmp(left->bytes, right->bytes, left->length) == 0;
}

static bool tuple_differs(const D73AuthorizedExecutionTupleV1 *left, const D73AuthorizedExecutionTupleV1 *right) {
    size_t index;
    if (left->schema_version != right->schema_version || left->execution_abi_version != right->execution_abi_version || left->generation != right->generation || left->phase != right->phase || left->role_count != right->role_count ||
        !same_text(&left->authority_domain, &right->authority_domain) || !same_digest(&left->source_manifest_digest, &right->source_manifest_digest) || !same_digest(&left->tuple_digest, &right->tuple_digest) ||
        !same_digest(&left->policy_leaf_digest, &right->policy_leaf_digest) || !same_digest(&left->launcher_leaf_digest, &right->launcher_leaf_digest) || !same_digest(&left->attestor_leaf_digest, &right->attestor_leaf_digest) || !same_digest(&left->d73_authorization_binder, &right->d73_authorization_binder)) return true;
    for (index = 0U; index < left->role_count; ++index) {
        if (!same_text(&left->roles[index].role_id, &right->roles[index].role_id) || !same_text(&left->roles[index].relative_path, &right->roles[index].relative_path) || !same_digest(&left->roles[index].normal_digest, &right->roles[index].normal_digest)) return true;
    }
    return false;
}

static void round_trip_tuple(void) {
    uint8_t bytes[65536];
    uint8_t second[65536];
    size_t length = sizeof(bytes);
    size_t second_length = sizeof(second);
    D73AuthorizedExecutionTupleV1 input = tuple();
    D73AuthorizedExecutionTupleV1 decoded;
    size_t required = 0U;
    size_t too_small = 1U;
    uint8_t one_byte[1];
    assert(execution_wire_v1_encode_tuple(&input, limits(), NULL, &required) == EXECUTION_WIRE_V1_OK);
    assert(required > too_small);
    assert(execution_wire_v1_encode_tuple(&input, limits(), one_byte, &too_small) == EXECUTION_WIRE_V1_BUFFER_TOO_SMALL);
    assert(too_small == required);
    assert(execution_wire_v1_encode_tuple(&input, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_decode_tuple(bytes, length, limits(), &decoded) == EXECUTION_WIRE_V1_OK);
    assert(decoded.role_count == 2U);
    assert(memcmp(decoded.roles[0].role_id.bytes, "a-launcher", 10U) == 0);
    assert(execution_wire_v1_encode_tuple(&decoded, limits(), second, &second_length) == EXECUTION_WIRE_V1_OK);
    assert(length == second_length && memcmp(bytes, second, length) == 0);
}

static void round_trip_approval_and_envelope(void) {
    uint8_t bytes[65536];
    uint8_t second[65536];
    size_t length;
    size_t second_length;
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ExecutionWireV1Digest approval_digest = digest(70U);
    ApprovalRecordV1 approval_decoded;
    ExecutionEnvelopeV1 envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    ExecutionEnvelopeV1 envelope_decoded;
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_OK);
    length = sizeof(bytes);
    assert(execution_wire_v1_encode_approval(&approval_value, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_decode_approval(bytes, length, limits(), &approval_decoded) == EXECUTION_WIRE_V1_OK);
    second_length = sizeof(second);
    assert(execution_wire_v1_encode_approval(&approval_decoded, limits(), second, &second_length) == EXECUTION_WIRE_V1_OK);
    assert(length == second_length && memcmp(bytes, second, length) == 0);
    length = sizeof(bytes);
    assert(execution_wire_v1_encode_envelope(&envelope_value, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_decode_envelope(bytes, length, limits(), &envelope_decoded) == EXECUTION_WIRE_V1_OK);
    second_length = sizeof(second);
    assert(execution_wire_v1_encode_envelope(&envelope_decoded, limits(), second, &second_length) == EXECUTION_WIRE_V1_OK);
    assert(length == second_length && memcmp(bytes, second, length) == 0);
}

static void rejects_raw_noncanonical_forms(void) {
    /* The tuple decoder expects its fixed first key, so each vector is fatal. */
    static const uint8_t indefinite[] = {0xbf, 0xff};
    static const uint8_t nonminimal[] = {0xb8, 0x0c};
    static const uint8_t tag[] = {0xc0, 0x80};
    static const uint8_t floating[] = {0xf9, 0x00, 0x00};
    static const uint8_t trailing[] = {0xa0, 0x00};
    static const uint8_t overflow[] = {0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    D73AuthorizedExecutionTupleV1 decoded;
    assert(execution_wire_v1_decode_tuple(indefinite, sizeof(indefinite), limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_decode_tuple(nonminimal, sizeof(nonminimal), limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_decode_tuple(tag, sizeof(tag), limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_decode_tuple(floating, sizeof(floating), limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_decode_tuple(trailing, sizeof(trailing), limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_decode_tuple(overflow, sizeof(overflow), limits(), &decoded) != EXECUTION_WIRE_V1_OK);
}

static void rejects_key_order_digest_lengths_and_bounds(void) {
    uint8_t bytes[65536];
    uint8_t changed[65536];
    size_t length = sizeof(bytes);
    size_t phase;
    size_t roles;
    size_t digest_header;
    size_t position;
    ExecutionWireV1Limits restricted = *limits();
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    D73AuthorizedExecutionTupleV1 decoded;
    assert(execution_wire_v1_encode_tuple(&tuple_value, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    phase = locate(bytes, length, "phase");
    roles = locate(bytes, length, "roles");
    memcpy(changed, bytes, length);
    memcpy(changed + phase, "roles", 5U);
    memcpy(changed + roles, "phase", 5U);
    assert(execution_wire_v1_decode_tuple(changed, length, limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    memcpy(changed, bytes, length);
    memcpy(changed + roles, "phase", 5U);
    assert(execution_wire_v1_decode_tuple(changed, length, limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    memcpy(changed, bytes, length);
    changed[phase] = (uint8_t)'x';
    assert(execution_wire_v1_decode_tuple(changed, length, limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    digest_header = 0U;
    while (digest_header + 1U < length && !(bytes[digest_header] == 0x58U && bytes[digest_header + 1U] == 0x20U)) ++digest_header;
    assert(digest_header + 1U < length);
    memcpy(changed, bytes, length);
    changed[digest_header + 1U] = 31U;
    assert(execution_wire_v1_decode_tuple(changed, length, limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    memcpy(changed, bytes, length);
    changed[0] = 0xabU;
    assert(execution_wire_v1_decode_tuple(changed, length, limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    memcpy(changed, bytes, length);
    changed[0] = 0xadU;
    assert(execution_wire_v1_decode_tuple(changed, length, limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    restricted.max_total_bytes = 1U;
    assert(execution_wire_v1_decode_tuple(bytes, length, &restricted, &decoded) == EXECUTION_WIRE_V1_LIMIT);
    restricted = *limits();
    restricted.max_roles = 1U;
    assert(execution_wire_v1_encode_tuple(&tuple_value, &restricted, bytes, &length) == EXECUTION_WIRE_V1_LIMIT);
    for (position = 0U; position < length; ++position) {
        assert(execution_wire_v1_decode_tuple(bytes, position, limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    }
}

static void rejects_forbidden_approval_fields(void) {
    static const char *const forbidden[] = {
        "self_hash", "pointer", "retention", "desired_generation", "alternative_rolemap"
    };
    uint8_t bytes[65536];
    uint8_t changed[65536];
    size_t length = sizeof(bytes);
    size_t index;
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ApprovalRecordV1 decoded;
    assert(execution_wire_v1_encode_approval(&approval_value, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    for (index = 0U; index < sizeof(forbidden) / sizeof(forbidden[0]); ++index) {
        size_t key_length = strlen(forbidden[index]);
        const char *replaced = index < 3U ? "record_kind" : "record_relative_path";
        size_t replaced_length = strlen(replaced);
        size_t position;
        size_t changed_length;
        assert(key_length <= replaced_length);
        memcpy(changed, bytes, length);
        position = locate(changed, length, replaced);
        assert(position > 0U && changed[position - 1U] == (uint8_t)(0x60U + replaced_length));
        changed[position - 1U] = (uint8_t)(0x60U + key_length);
        memcpy(changed + position, forbidden[index], key_length);
        memmove(changed + position + key_length, changed + position + replaced_length, length - position - replaced_length);
        changed_length = length - replaced_length + key_length;
        /* Map cardinality remains sixteen: decoder reaches the forbidden key. */
        assert(changed[0] == 0xb0U);
        assert(execution_wire_v1_decode_approval(changed, changed_length, limits(), &decoded) != EXECUTION_WIRE_V1_OK);
    }
}

static void rejects_decode_bounds_before_record_parse(void) {
    uint8_t bytes[65536];
    uint8_t changed[65536];
    size_t length = sizeof(bytes);
    size_t position;
    ExecutionWireV1Limits restricted = *limits();
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ExecutionWireV1Digest approval_digest = digest(70U);
    ExecutionEnvelopeV1 envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    ExecutionEnvelopeV1 decoded;
    assert(execution_wire_v1_encode_envelope(&envelope_value, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    memcpy(changed, bytes, length);
    position = locate(changed, length, "unit_records") + strlen("unit_records");
    assert(changed[position] == 0x81U);
    changed[position] = 0x82U;
    restricted.max_unit_records = 1U;
    assert(execution_wire_v1_decode_envelope(changed, length, &restricted, &decoded) == EXECUTION_WIRE_V1_LIMIT);
    memcpy(changed, bytes, length);
    position = locate(changed, length, "timer_records") + strlen("timer_records");
    assert(changed[position] == 0x81U);
    changed[position] = 0x82U;
    restricted = *limits();
    restricted.max_timer_records = 1U;
    assert(execution_wire_v1_decode_envelope(changed, length, &restricted, &decoded) == EXECUTION_WIRE_V1_LIMIT);
}

static void rejects_stale_snapshot_claims_and_selector_mismatches(void) {
    uint8_t bytes[65536];
    uint8_t changed[65536];
    size_t length = sizeof(bytes);
    size_t position;
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ExecutionWireV1Digest approval_digest = digest(70U);
    ExecutionEnvelopeV1 envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    ExecutionEnvelopeV1 decoded;
    envelope_value.snapshot_b.processes[0].uid++;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_a_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.target_final.selector_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    assert(execution_wire_v1_encode_envelope(&envelope_value, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    memcpy(changed, bytes, length);
    position = locate(changed, length, "approved-cgroup");
    changed[position] = (uint8_t)'x';
    assert(execution_wire_v1_decode_envelope(changed, length, limits(), &decoded) == EXECUTION_WIRE_V1_MISMATCH);
}

static void rejects_snapshot_array_order_and_identity_duplicates(void) {
    uint8_t bytes[65536];
    size_t length;
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ExecutionWireV1Digest approval_digest = digest(70U);
    ExecutionEnvelopeV1 envelope_value;
#define EXPECT_ENVELOPE_REJECTED() do { length = sizeof(bytes); assert(execution_wire_v1_encode_envelope(&envelope_value, limits(), bytes, &length) != EXECUTION_WIRE_V1_OK); } while (0)
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_a.process_count = 2U; envelope_value.snapshot_a.processes[1] = envelope_value.snapshot_a.processes[0]; envelope_value.snapshot_b = envelope_value.snapshot_a; EXPECT_ENVELOPE_REJECTED();
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_a.fd_count = 2U; envelope_value.snapshot_a.fds[1] = envelope_value.snapshot_a.fds[0]; envelope_value.snapshot_b = envelope_value.snapshot_a; EXPECT_ENVELOPE_REJECTED();
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_a.fdinfo_count = 2U; envelope_value.snapshot_a.fdinfo[1] = envelope_value.snapshot_a.fdinfo[0]; envelope_value.snapshot_b = envelope_value.snapshot_a; EXPECT_ENVELOPE_REJECTED();
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_a.lock_count = 2U; envelope_value.snapshot_a.locks[1] = envelope_value.snapshot_a.locks[0]; envelope_value.snapshot_b = envelope_value.snapshot_a; EXPECT_ENVELOPE_REJECTED();
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_a.namespace_count = 2U; envelope_value.snapshot_a.namespaces[1] = envelope_value.snapshot_a.namespaces[0]; envelope_value.snapshot_b = envelope_value.snapshot_a; EXPECT_ENVELOPE_REJECTED();
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_a.unit_count = 2U; envelope_value.snapshot_a.units[1] = envelope_value.snapshot_a.units[0]; envelope_value.snapshot_b = envelope_value.snapshot_a; EXPECT_ENVELOPE_REJECTED();
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_a.timer_count = 2U; envelope_value.snapshot_a.timers[1] = envelope_value.snapshot_a.timers[0]; envelope_value.snapshot_b = envelope_value.snapshot_a; EXPECT_ENVELOPE_REJECTED();
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_a.process_count = 2U; envelope_value.snapshot_a.processes[1] = envelope_value.snapshot_a.processes[0]; envelope_value.snapshot_a.processes[1].pid--; envelope_value.snapshot_b = envelope_value.snapshot_a; EXPECT_ENVELOPE_REJECTED();
#undef EXPECT_ENVELOPE_REJECTED
}

static void rejects_decoded_duplicate_snapshot_identity(void) {
    static const uint8_t second_pid[] = {0x18U, 0x65U};
    uint8_t bytes[65536];
    size_t length = sizeof(bytes);
    size_t position;
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ExecutionWireV1Digest approval_digest = digest(70U);
    ExecutionEnvelopeV1 envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    ExecutionEnvelopeV1 decoded;
    envelope_value.snapshot_a.process_count = 2U;
    envelope_value.snapshot_a.processes[1] = envelope_value.snapshot_a.processes[0];
    envelope_value.snapshot_a.processes[1].pid++;
    envelope_value.snapshot_b = envelope_value.snapshot_a;
    envelope_value.snapshot_b.monotonic_capture_interval++;
    assert(execution_wire_v1_snapshot_digest(&envelope_value.snapshot_a, limits(), &envelope_value.snapshot_a_digest) == EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_snapshot_digest(&envelope_value.snapshot_b, limits(), &envelope_value.snapshot_b_digest) == EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_encode_envelope(&envelope_value, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    position = locate_bytes(bytes, length, second_pid, sizeof(second_pid));
    bytes[position + 1U] = 0x64U;
    assert(execution_wire_v1_decode_envelope(bytes, length, limits(), &decoded) == EXECUTION_WIRE_V1_INVALID_ARGUMENT);
}

static void enforces_envelope_fd_key_order(void) {
    uint8_t bytes[65536];
    uint8_t changed[65536];
    uint8_t number_member[11];
    size_t length = sizeof(bytes);
    size_t cloexec;
    size_t number;
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ExecutionWireV1Digest approval_digest = digest(70U);
    ExecutionEnvelopeV1 envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    ExecutionEnvelopeV1 decoded;
    assert(execution_wire_v1_encode_envelope(&envelope_value, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    cloexec = locate(bytes, length, "fd_cloexec");
    number = locate(bytes, length, "fd_number");
    assert(bytes[number - 1U] == 0x69U && bytes[cloexec - 1U] == 0x6aU);
    assert(number < cloexec);
    assert(number > 0U && cloexec == number + sizeof(number_member));
    memcpy(changed, bytes, length);
    memcpy(number_member, changed + number - 1U, sizeof(number_member));
    memmove(changed + number - 1U, changed + cloexec - 1U, 12U);
    memcpy(changed + number - 1U + 12U, number_member, sizeof(number_member));
    assert(execution_wire_v1_decode_envelope(changed, length, limits(), &decoded) != EXECUTION_WIRE_V1_OK);
}

static void rejects_all_cross_object_mismatches(void) {
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ExecutionWireV1Digest approval_digest = digest(70U);
    ExecutionEnvelopeV1 envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_OK);
    approval_value.source_manifest_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    approval_value = approval(&tuple_value);
    approval_value.tuple_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    approval_value = approval(&tuple_value);
    approval_value.d73_authorization_binder.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    approval_value = approval(&tuple_value);
    approval_value.execution_abi_version++;
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    approval_value = approval(&tuple_value);
    approval_value.policy_leaf_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    approval_value = approval(&tuple_value);
    approval_value.launcher_leaf_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    approval_value = approval(&tuple_value);
    approval_value.attestor_leaf_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    approval_value = approval(&tuple_value);
    approval_value.roles[0].relative_path = text("libexec/other");
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    approval_value = approval(&tuple_value);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.schema_version = 2U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) != EXECUTION_WIRE_V1_OK);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.execution_abi_version++;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.collector_abi_version++;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.tuple_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.source_manifest_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.generation++;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.policy_leaf_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.launcher_leaf_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.attestor_leaf_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.approval_record_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.host_binding_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.boot_binding_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.collector_artifact_binder.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.phase++;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.target_final.final_predicate = false;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) != EXECUTION_WIRE_V1_OK);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_a.process_count = 5U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_LIMIT);
}

static void rejects_mutated_wire_and_bindings(void) {
    uint8_t bytes[65536];
    size_t length = sizeof(bytes);
    size_t index;
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ExecutionWireV1Digest approval_digest = digest(70U);
    ExecutionEnvelopeV1 envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    D73AuthorizedExecutionTupleV1 decoded;
    assert(execution_wire_v1_encode_tuple(&tuple_value, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    for (index = 0U; index < length; ++index) {
        uint8_t saved = bytes[index];
        bytes[index] ^= 0x01U;
        assert(execution_wire_v1_decode_tuple(bytes, length, limits(), &decoded) != EXECUTION_WIRE_V1_OK || tuple_differs(&decoded, &tuple_value));
        bytes[index] = saved;
    }
    approval_value.generation++;
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    approval_value = approval(&tuple_value);
    approval_value.roles[0].normal_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
    approval_value = approval(&tuple_value);
    approval_value.record_relative_path = text("meta/other.cbor");
    assert(execution_wire_v1_validate_approval_for_tuple(&approval_value, &tuple_value, limits()) != EXECUTION_WIRE_V1_OK);
    approval_value = approval(&tuple_value);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.fd_number = 4U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) != EXECUTION_WIRE_V1_OK);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.fd_seal_mask = EXECUTION_WIRE_V1_REQUIRED_SEALS - 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) != EXECUTION_WIRE_V1_OK);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.fd_cloexec = true;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) != EXECUTION_WIRE_V1_OK);
    envelope_value = envelope(&tuple_value, &approval_value, &approval_digest);
    envelope_value.snapshot_b_digest.bytes[0] ^= 1U;
    assert(execution_wire_v1_validate_envelope_for_tuple_and_approval(&envelope_value, &tuple_value, &approval_value, &approval_digest, limits()) == EXECUTION_WIRE_V1_MISMATCH);
}

static void rejects_approval_wire_byteflip_against_tuple(void) {
    uint8_t bytes[65536];
    size_t length = sizeof(bytes);
    size_t position;
    D73AuthorizedExecutionTupleV1 tuple_value = tuple();
    ApprovalRecordV1 approval_value = approval(&tuple_value);
    ApprovalRecordV1 decoded;
    assert(execution_wire_v1_encode_approval(&approval_value, limits(), bytes, &length) == EXECUTION_WIRE_V1_OK);
    position = locate_bytes(bytes, length, approval_value.roles[0].normal_digest.bytes, EXECUTION_WIRE_V1_DIGEST_SIZE);
    bytes[position] ^= 1U;
    assert(execution_wire_v1_decode_approval(bytes, length, limits(), &decoded) == EXECUTION_WIRE_V1_OK);
    assert(execution_wire_v1_validate_approval_for_tuple(&decoded, &tuple_value, limits()) == EXECUTION_WIRE_V1_MISMATCH);
}

int main(void) {
    round_trip_tuple();
    round_trip_approval_and_envelope();
    rejects_raw_noncanonical_forms();
    rejects_key_order_digest_lengths_and_bounds();
    rejects_forbidden_approval_fields();
    rejects_decode_bounds_before_record_parse();
    rejects_stale_snapshot_claims_and_selector_mismatches();
    rejects_snapshot_array_order_and_identity_duplicates();
    rejects_decoded_duplicate_snapshot_identity();
    enforces_envelope_fd_key_order();
    encoded_maps_are_rfc8949_ordered();
    rejects_mutated_wire_and_bindings();
    rejects_approval_wire_byteflip_against_tuple();
    rejects_all_cross_object_mismatches();
    puts("test_execution_wire_v1: PASS");
    return 0;
}

#endif
