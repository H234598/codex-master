#include "execution_wire_v1.h"

#include <limits.h>
#include <string.h>

typedef struct WireWriter {
    uint8_t *data;
    size_t capacity;
    size_t length;
    bool sizing;
    void (*emit)(void *context, uint8_t byte);
    void *emit_context;
    ExecutionWireV1Status status;
} WireWriter;

typedef struct WireReader {
    const uint8_t *data;
    size_t length;
    size_t position;
    ExecutionWireV1Status status;
} WireReader;

static bool digest_equal(const ExecutionWireV1Digest *left, const ExecutionWireV1Digest *right) {
    return memcmp(left->bytes, right->bytes, EXECUTION_WIRE_V1_DIGEST_SIZE) == 0;
}

static bool text_equal_literal(const ExecutionWireV1Text *text, const char *literal) {
    size_t length = strlen(literal);
    return text->length == length && memcmp(text->bytes, literal, length) == 0;
}

static int text_compare(const ExecutionWireV1Text *left, const ExecutionWireV1Text *right) {
    size_t shortest = left->length < right->length ? left->length : right->length;
    if (left->length < right->length) {
        return -1;
    }
    if (left->length > right->length) {
        return 1;
    }
    return memcmp(left->bytes, right->bytes, shortest);
}

static bool is_identifier_byte(uint8_t byte, bool first) {
    if (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') {
        return true;
    }
    if (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') {
        return !first;
    }
    return !first && (byte == (uint8_t)'-' || byte == (uint8_t)'_' || byte == (uint8_t)'.');
}

static ExecutionWireV1Status validate_identifier(const ExecutionWireV1Text *text, const ExecutionWireV1Limits *limits) {
    size_t index;
    if (text == NULL || text->length == 0U || text->length > limits->max_text_bytes ||
        text->length > EXECUTION_WIRE_V1_TEXT_CAPACITY || text->bytes[text->length] != 0U) {
        return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    }
    for (index = 0U; index < text->length; ++index) {
        if (!is_identifier_byte(text->bytes[index], index == 0U)) {
            return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
        }
    }
    return EXECUTION_WIRE_V1_OK;
}

static ExecutionWireV1Status validate_relative_path(const ExecutionWireV1Text *text, const ExecutionWireV1Limits *limits) {
    size_t index;
    bool segment_start = true;
    ExecutionWireV1Status status;
    if (text == NULL || text->length == 0U || text->length > limits->max_text_bytes ||
        text->length > EXECUTION_WIRE_V1_TEXT_CAPACITY || text->bytes[text->length] != 0U) {
        return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    }
    for (index = 0U; index < text->length; ++index) {
        uint8_t byte = text->bytes[index];
        if (byte == (uint8_t)'/') {
            if (segment_start) {
                return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
            }
            segment_start = true;
            continue;
        }
        status = is_identifier_byte(byte, segment_start) ? EXECUTION_WIRE_V1_OK : EXECUTION_WIRE_V1_INVALID_ARGUMENT;
        if (status != EXECUTION_WIRE_V1_OK) {
            return status;
        }
        segment_start = false;
    }
    return segment_start ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : EXECUTION_WIRE_V1_OK;
}

static ExecutionWireV1Status validate_limits(const ExecutionWireV1Limits *limits) {
    if (limits == NULL || limits->max_total_bytes == 0U ||
        limits->max_total_bytes > EXECUTION_WIRE_V1_HARD_MAX_TOTAL_BYTES ||
        limits->max_snapshot_bytes == 0U || limits->max_snapshot_bytes > limits->max_total_bytes ||
        limits->max_text_bytes == 0U || limits->max_text_bytes > EXECUTION_WIRE_V1_TEXT_CAPACITY ||
        limits->max_roles == 0U || limits->max_roles > EXECUTION_WIRE_V1_MAX_ROLES ||
        limits->max_phases == 0U || limits->max_phases > EXECUTION_WIRE_V1_MAX_PHASES ||
        limits->max_process_records == 0U || limits->max_process_records > EXECUTION_WIRE_V1_MAX_PROCESS_RECORDS ||
        limits->max_fd_records == 0U || limits->max_fd_records > EXECUTION_WIRE_V1_MAX_FD_RECORDS ||
        limits->max_fdinfo_records == 0U || limits->max_fdinfo_records > EXECUTION_WIRE_V1_MAX_FDINFO_RECORDS ||
        limits->max_lock_records == 0U || limits->max_lock_records > EXECUTION_WIRE_V1_MAX_LOCK_RECORDS ||
        limits->max_namespace_records == 0U || limits->max_namespace_records > EXECUTION_WIRE_V1_MAX_NAMESPACE_RECORDS ||
        limits->max_unit_records == 0U || limits->max_unit_records > EXECUTION_WIRE_V1_MAX_UNIT_RECORDS ||
        limits->max_timer_records == 0U || limits->max_timer_records > EXECUTION_WIRE_V1_MAX_TIMER_RECORDS) {
        return EXECUTION_WIRE_V1_LIMIT;
    }
    return EXECUTION_WIRE_V1_OK;
}

static ExecutionWireV1Status ordered_role_digests(
    const ExecutionWireV1RoleDigest *roles, size_t count, const ExecutionWireV1Limits *limits, size_t order[EXECUTION_WIRE_V1_MAX_ROLES]
) {
    size_t index;
    size_t scan;
    if (count == 0U || count > limits->max_roles) {
        return EXECUTION_WIRE_V1_LIMIT;
    }
    for (index = 0U; index < count; ++index) {
        ExecutionWireV1Status status = validate_identifier(&roles[index].role_id, limits);
        if (status == EXECUTION_WIRE_V1_OK) {
            status = validate_relative_path(&roles[index].relative_path, limits);
        }
        if (status != EXECUTION_WIRE_V1_OK) {
            return status;
        }
        order[index] = index;
    }
    for (index = 1U; index < count; ++index) {
        size_t chosen = order[index];
        scan = index;
        while (scan > 0U && text_compare(&roles[order[scan - 1U]].role_id, &roles[chosen].role_id) > 0) {
            order[scan] = order[scan - 1U];
            --scan;
        }
        order[scan] = chosen;
    }
    for (index = 1U; index < count; ++index) {
        if (text_compare(&roles[order[index - 1U]].role_id, &roles[order[index]].role_id) == 0) {
            return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
        }
    }
    return EXECUTION_WIRE_V1_OK;
}

static ExecutionWireV1Status ordered_measurements(
    const ExecutionWireV1RoleMeasurement *roles, size_t count, const ExecutionWireV1Limits *limits, size_t order[EXECUTION_WIRE_V1_MAX_ROLES]
) {
    size_t index;
    size_t scan;
    if (count == 0U || count > limits->max_roles) {
        return EXECUTION_WIRE_V1_LIMIT;
    }
    for (index = 0U; index < count; ++index) {
        ExecutionWireV1Status status = validate_identifier(&roles[index].role_id, limits);
        if (status == EXECUTION_WIRE_V1_OK) {
            status = validate_relative_path(&roles[index].relative_path, limits);
        }
        if (status == EXECUTION_WIRE_V1_OK) {
            status = validate_identifier(&roles[index].owner_class, limits);
        }
        if (status != EXECUTION_WIRE_V1_OK || !roles[index].verity_enabled || roles[index].nlink != 1U) {
            return status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : status;
        }
        order[index] = index;
    }
    for (index = 1U; index < count; ++index) {
        size_t chosen = order[index];
        scan = index;
        while (scan > 0U && text_compare(&roles[order[scan - 1U]].role_id, &roles[chosen].role_id) > 0) {
            order[scan] = order[scan - 1U];
            --scan;
        }
        order[scan] = chosen;
    }
    for (index = 1U; index < count; ++index) {
        if (text_compare(&roles[order[index - 1U]].role_id, &roles[order[index]].role_id) == 0) {
            return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
        }
    }
    return EXECUTION_WIRE_V1_OK;
}

static ExecutionWireV1Status validate_tuple(const D73AuthorizedExecutionTupleV1 *value, const ExecutionWireV1Limits *limits) {
    size_t order[EXECUTION_WIRE_V1_MAX_ROLES];
    ExecutionWireV1Status status;
    if (value == NULL || value->schema_version != EXECUTION_WIRE_V1_SCHEMA_VERSION || value->execution_abi_version == 0U) {
        return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    }
    status = validate_identifier(&value->authority_domain, limits);
    if (status != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    return ordered_role_digests(value->roles, value->role_count, limits, order);
}

static ExecutionWireV1Status validate_approval(const ApprovalRecordV1 *value, const ExecutionWireV1Limits *limits) {
    size_t order[EXECUTION_WIRE_V1_MAX_ROLES];
    size_t index;
    ExecutionWireV1Status status;
    if (value == NULL || value->schema_version != EXECUTION_WIRE_V1_SCHEMA_VERSION || value->execution_abi_version == 0U ||
        value->policy_collector_abi_version == 0U || !text_equal_literal(&value->record_kind, EXECUTION_WIRE_V1_APPROVAL_RECORD_KIND) ||
        !text_equal_literal(&value->record_relative_path, EXECUTION_WIRE_V1_APPROVAL_RECORD_PATH)) {
        return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    }
    status = ordered_measurements(value->roles, value->role_count, limits, order);
    if (status != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    for (index = 0U; index < value->role_count; ++index) {
        if (text_equal_literal(&value->roles[index].relative_path, EXECUTION_WIRE_V1_APPROVAL_RECORD_PATH)) {
            return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
        }
    }
    if (value->allowed_phase_count == 0U || value->allowed_phase_count > limits->max_phases) {
        return EXECUTION_WIRE_V1_LIMIT;
    }
    for (index = 1U; index < value->allowed_phase_count; ++index) {
        if (value->allowed_phases[index - 1U] >= value->allowed_phases[index]) {
            return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
        }
    }
    return EXECUTION_WIRE_V1_OK;
}

static void writer_put(WireWriter *writer, uint8_t byte) {
    if (writer->status != EXECUTION_WIRE_V1_OK) {
        return;
    }
    if (writer->length == SIZE_MAX) {
        writer->status = EXECUTION_WIRE_V1_LIMIT;
        return;
    }
    if (!writer->sizing) {
        if (writer->length >= writer->capacity) {
            writer->status = EXECUTION_WIRE_V1_BUFFER_TOO_SMALL;
            return;
        }
        if (writer->emit != NULL) {
            writer->emit(writer->emit_context, byte);
        } else {
            writer->data[writer->length] = byte;
        }
    }
    ++writer->length;
}

static void writer_head(WireWriter *writer, uint8_t major, uint64_t value) {
    uint8_t index;
    if (value < 24U) {
        writer_put(writer, (uint8_t)((major << 5U) | (uint8_t)value));
    } else if (value <= UINT8_MAX) {
        writer_put(writer, (uint8_t)((major << 5U) | 24U));
        writer_put(writer, (uint8_t)value);
    } else if (value <= UINT16_MAX) {
        writer_put(writer, (uint8_t)((major << 5U) | 25U));
        for (index = 2U; index > 0U; --index) {
            writer_put(writer, (uint8_t)(value >> ((index - 1U) * 8U)));
        }
    } else if (value <= UINT32_MAX) {
        writer_put(writer, (uint8_t)((major << 5U) | 26U));
        for (index = 4U; index > 0U; --index) {
            writer_put(writer, (uint8_t)(value >> ((index - 1U) * 8U)));
        }
    } else {
        writer_put(writer, (uint8_t)((major << 5U) | 27U));
        for (index = 8U; index > 0U; --index) {
            writer_put(writer, (uint8_t)(value >> ((index - 1U) * 8U)));
        }
    }
}

static void writer_uint(WireWriter *writer, uint64_t value) { writer_head(writer, 0U, value); }
static void writer_map(WireWriter *writer, uint64_t count) { writer_head(writer, 5U, count); }
static void writer_array(WireWriter *writer, uint64_t count) { writer_head(writer, 4U, count); }

static void writer_raw(WireWriter *writer, const uint8_t *bytes, size_t length) {
    size_t index;
    for (index = 0U; index < length; ++index) {
        writer_put(writer, bytes[index]);
    }
}

static void writer_text_literal(WireWriter *writer, const char *literal) {
    size_t length = strlen(literal);
    writer_head(writer, 3U, length);
    writer_raw(writer, (const uint8_t *)literal, length);
}

static void writer_text(WireWriter *writer, const ExecutionWireV1Text *text) {
    writer_head(writer, 3U, text->length);
    writer_raw(writer, text->bytes, text->length);
}

static void writer_digest(WireWriter *writer, const ExecutionWireV1Digest *digest) {
    writer_head(writer, 2U, EXECUTION_WIRE_V1_DIGEST_SIZE);
    writer_raw(writer, digest->bytes, EXECUTION_WIRE_V1_DIGEST_SIZE);
}

static void writer_bool(WireWriter *writer, bool value) { writer_put(writer, value ? 0xf5U : 0xf4U); }

static void writer_key(WireWriter *writer, const char *key) { writer_text_literal(writer, key); }

typedef struct Sha256Context {
    uint32_t state[8];
    uint64_t bits;
    uint8_t block[64];
    size_t block_length;
} Sha256Context;

static uint32_t sha256_rotr(uint32_t value, uint32_t amount) { return (value >> amount) | (value << (32U - amount)); }
static uint32_t sha256_choose(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t sha256_majority(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t sha256_big0(uint32_t x) { return sha256_rotr(x, 2U) ^ sha256_rotr(x, 13U) ^ sha256_rotr(x, 22U); }
static uint32_t sha256_big1(uint32_t x) { return sha256_rotr(x, 6U) ^ sha256_rotr(x, 11U) ^ sha256_rotr(x, 25U); }
static uint32_t sha256_small0(uint32_t x) { return sha256_rotr(x, 7U) ^ sha256_rotr(x, 18U) ^ (x >> 3U); }
static uint32_t sha256_small1(uint32_t x) { return sha256_rotr(x, 17U) ^ sha256_rotr(x, 19U) ^ (x >> 10U); }

static void sha256_transform(Sha256Context *context) {
    static const uint32_t constants[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;
    size_t index;
    for (index = 0U; index < 16U; ++index) words[index] = ((uint32_t)context->block[index * 4U] << 24U) | ((uint32_t)context->block[index * 4U + 1U] << 16U) | ((uint32_t)context->block[index * 4U + 2U] << 8U) | context->block[index * 4U + 3U];
    for (index = 16U; index < 64U; ++index) words[index] = sha256_small1(words[index - 2U]) + words[index - 7U] + sha256_small0(words[index - 15U]) + words[index - 16U];
    a = context->state[0]; b = context->state[1]; c = context->state[2]; d = context->state[3]; e = context->state[4]; f = context->state[5]; g = context->state[6]; h = context->state[7];
    for (index = 0U; index < 64U; ++index) {
        uint32_t temporary1 = h + sha256_big1(e) + sha256_choose(e, f, g) + constants[index] + words[index];
        uint32_t temporary2 = sha256_big0(a) + sha256_majority(a, b, c);
        h = g; g = f; f = e; e = d + temporary1; d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    context->state[0] += a; context->state[1] += b; context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f; context->state[6] += g; context->state[7] += h;
}

static void sha256_init(Sha256Context *context) {
    static const uint32_t initial[8] = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
    memcpy(context->state, initial, sizeof(initial));
    context->bits = 0U;
    context->block_length = 0U;
}

static void sha256_update_byte(Sha256Context *context, uint8_t byte) {
    context->block[context->block_length++] = byte;
    context->bits += 8U;
    if (context->block_length == sizeof(context->block)) {
        sha256_transform(context);
        context->block_length = 0U;
    }
}

static void sha256_emit(void *opaque, uint8_t byte) { sha256_update_byte((Sha256Context *)opaque, byte); }

static void sha256_final(Sha256Context *context, ExecutionWireV1Digest *output) {
    uint64_t bit_length = context->bits;
    size_t index;
    sha256_update_byte(context, 0x80U);
    while (context->block_length != 56U) sha256_update_byte(context, 0U);
    for (index = 8U; index > 0U; --index) sha256_update_byte(context, (uint8_t)(bit_length >> ((index - 1U) * 8U)));
    for (index = 0U; index < 8U; ++index) {
        output->bytes[index * 4U] = (uint8_t)(context->state[index] >> 24U);
        output->bytes[index * 4U + 1U] = (uint8_t)(context->state[index] >> 16U);
        output->bytes[index * 4U + 2U] = (uint8_t)(context->state[index] >> 8U);
        output->bytes[index * 4U + 3U] = (uint8_t)context->state[index];
    }
}

static ExecutionWireV1Status reader_take(WireReader *reader, uint8_t *output) {
    if (reader->status != EXECUTION_WIRE_V1_OK) {
        return reader->status;
    }
    if (reader->position >= reader->length) {
        reader->status = EXECUTION_WIRE_V1_TRUNCATED;
        return reader->status;
    }
    *output = reader->data[reader->position++];
    return EXECUTION_WIRE_V1_OK;
}

static ExecutionWireV1Status reader_head(WireReader *reader, uint8_t *major, uint64_t *value) {
    uint8_t initial;
    uint8_t additional;
    uint8_t count;
    uint8_t byte;
    uint64_t result = 0U;
    ExecutionWireV1Status status = reader_take(reader, &initial);
    if (status != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    *major = (uint8_t)(initial >> 5U);
    additional = (uint8_t)(initial & 0x1fU);
    if (additional < 24U) {
        *value = additional;
        return EXECUTION_WIRE_V1_OK;
    }
    if (additional == 31U || additional > 27U) {
        reader->status = EXECUTION_WIRE_V1_NONCANONICAL;
        return reader->status;
    }
    count = additional == 24U ? 1U : (additional == 25U ? 2U : (additional == 26U ? 4U : 8U));
    while (count-- > 0U) {
        status = reader_take(reader, &byte);
        if (status != EXECUTION_WIRE_V1_OK) {
            return status;
        }
        result = (result << 8U) | byte;
    }
    if ((additional == 24U && result < 24U) || (additional == 25U && result <= UINT8_MAX) ||
        (additional == 26U && result <= UINT16_MAX) || (additional == 27U && result <= UINT32_MAX)) {
        reader->status = EXECUTION_WIRE_V1_NONCANONICAL;
        return reader->status;
    }
    *value = result;
    return EXECUTION_WIRE_V1_OK;
}

static ExecutionWireV1Status reader_typed_head(WireReader *reader, uint8_t expected, uint64_t *value) {
    uint8_t major;
    ExecutionWireV1Status status = reader_head(reader, &major, value);
    if (status != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    if (major != expected) {
        reader->status = EXECUTION_WIRE_V1_MALFORMED;
    }
    return reader->status;
}

static ExecutionWireV1Status reader_uint(WireReader *reader, uint64_t *value) { return reader_typed_head(reader, 0U, value); }

static ExecutionWireV1Status reader_count(WireReader *reader, uint8_t major, size_t maximum, size_t *count) {
    uint64_t value;
    ExecutionWireV1Status status = reader_typed_head(reader, major, &value);
    if (status != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    if (value > (uint64_t)SIZE_MAX || value > maximum) {
        reader->status = EXECUTION_WIRE_V1_LIMIT;
        return reader->status;
    }
    *count = (size_t)value;
    return EXECUTION_WIRE_V1_OK;
}

static ExecutionWireV1Status reader_raw(WireReader *reader, uint8_t *output, size_t length) {
    size_t index;
    for (index = 0U; index < length; ++index) {
        ExecutionWireV1Status status = reader_take(reader, &output[index]);
        if (status != EXECUTION_WIRE_V1_OK) {
            return status;
        }
    }
    return EXECUTION_WIRE_V1_OK;
}

static ExecutionWireV1Status reader_digest(WireReader *reader, ExecutionWireV1Digest *digest) {
    size_t length;
    ExecutionWireV1Status status = reader_count(reader, 2U, EXECUTION_WIRE_V1_DIGEST_SIZE, &length);
    if (status != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    if (length != EXECUTION_WIRE_V1_DIGEST_SIZE) {
        reader->status = EXECUTION_WIRE_V1_MALFORMED;
        return reader->status;
    }
    return reader_raw(reader, digest->bytes, length);
}

static ExecutionWireV1Status reader_text(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1Text *text, bool path) {
    size_t length;
    ExecutionWireV1Status status = reader_count(reader, 3U, limits->max_text_bytes, &length);
    if (status != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    if (length == 0U || length > EXECUTION_WIRE_V1_TEXT_CAPACITY) {
        reader->status = EXECUTION_WIRE_V1_LIMIT;
        return reader->status;
    }
    memset(text, 0, sizeof(*text));
    status = reader_raw(reader, text->bytes, length);
    if (status != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    text->length = length;
    status = path ? validate_relative_path(text, limits) : validate_identifier(text, limits);
    if (status != EXECUTION_WIRE_V1_OK) {
        reader->status = status;
    }
    return reader->status;
}

static ExecutionWireV1Status reader_key(WireReader *reader, const char *literal) {
    ExecutionWireV1Text text;
    ExecutionWireV1Limits key_limits = {
        .max_total_bytes = 1U, .max_snapshot_bytes = 1U, .max_text_bytes = EXECUTION_WIRE_V1_TEXT_CAPACITY,
        .max_roles = 1U, .max_phases = 1U, .max_process_records = 1U, .max_fd_records = 1U,
        .max_fdinfo_records = 1U, .max_lock_records = 1U, .max_namespace_records = 1U,
        .max_unit_records = 1U, .max_timer_records = 1U
    };
    ExecutionWireV1Status status = reader_text(reader, &key_limits, &text, false);
    if (status != EXECUTION_WIRE_V1_OK || !text_equal_literal(&text, literal)) {
        reader->status = status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_NONCANONICAL : status;
    }
    return reader->status;
}

static ExecutionWireV1Status reader_bool(WireReader *reader, bool *value) {
    uint8_t byte;
    ExecutionWireV1Status status = reader_take(reader, &byte);
    if (status != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    if (byte == 0xf4U) {
        *value = false;
    } else if (byte == 0xf5U) {
        *value = true;
    } else {
        reader->status = EXECUTION_WIRE_V1_MALFORMED;
    }
    return reader->status;
}

static ExecutionWireV1Status reader_map_exact(WireReader *reader, size_t expected) {
    size_t count;
    ExecutionWireV1Status status = reader_count(reader, 5U, expected, &count);
    if (status != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    if (count != expected) {
        reader->status = EXECUTION_WIRE_V1_MALFORMED;
    }
    return reader->status;
}

static void writer_role_map(WireWriter *writer, const ExecutionWireV1RoleDigest *roles, size_t count, const size_t *order) {
    size_t index;
    writer_map(writer, count);
    for (index = 0U; index < count; ++index) {
        writer_text(writer, &roles[order[index]].role_id);
        writer_map(writer, 2U);
        writer_key(writer, "normal_digest"); writer_digest(writer, &roles[order[index]].normal_digest);
        writer_key(writer, "relative_path"); writer_text(writer, &roles[order[index]].relative_path);
    }
}

static ExecutionWireV1Status reader_role_map(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1RoleDigest *roles, size_t *count) {
    size_t index;
    ExecutionWireV1Status status = reader_count(reader, 5U, limits->max_roles, count);
    if (status != EXECUTION_WIRE_V1_OK || *count == 0U) {
        return status == EXECUTION_WIRE_V1_OK ? (reader->status = EXECUTION_WIRE_V1_MALFORMED) : status;
    }
    for (index = 0U; index < *count; ++index) {
        status = reader_text(reader, limits, &roles[index].role_id, false);
        if (status == EXECUTION_WIRE_V1_OK && index > 0U && text_compare(&roles[index - 1U].role_id, &roles[index].role_id) >= 0) {
            status = reader->status = EXECUTION_WIRE_V1_NONCANONICAL;
        }
        if (status == EXECUTION_WIRE_V1_OK) status = reader_map_exact(reader, 2U);
        if (status == EXECUTION_WIRE_V1_OK) status = reader_key(reader, "normal_digest");
        if (status == EXECUTION_WIRE_V1_OK) status = reader_digest(reader, &roles[index].normal_digest);
        if (status == EXECUTION_WIRE_V1_OK) status = reader_key(reader, "relative_path");
        if (status == EXECUTION_WIRE_V1_OK) status = reader_text(reader, limits, &roles[index].relative_path, true);
        if (status != EXECUTION_WIRE_V1_OK) {
            return status;
        }
    }
    return EXECUTION_WIRE_V1_OK;
}

static void writer_tuple(WireWriter *writer, const D73AuthorizedExecutionTupleV1 *value) {
    size_t order[EXECUTION_WIRE_V1_MAX_ROLES];
    (void)ordered_role_digests(value->roles, value->role_count, &(ExecutionWireV1Limits){
        .max_total_bytes = EXECUTION_WIRE_V1_HARD_MAX_TOTAL_BYTES, .max_snapshot_bytes = EXECUTION_WIRE_V1_HARD_MAX_TOTAL_BYTES,
        .max_text_bytes = EXECUTION_WIRE_V1_TEXT_CAPACITY, .max_roles = EXECUTION_WIRE_V1_MAX_ROLES,
        .max_phases = EXECUTION_WIRE_V1_MAX_PHASES, .max_process_records = EXECUTION_WIRE_V1_MAX_PROCESS_RECORDS,
        .max_fd_records = EXECUTION_WIRE_V1_MAX_FD_RECORDS, .max_fdinfo_records = EXECUTION_WIRE_V1_MAX_FDINFO_RECORDS,
        .max_lock_records = EXECUTION_WIRE_V1_MAX_LOCK_RECORDS, .max_namespace_records = EXECUTION_WIRE_V1_MAX_NAMESPACE_RECORDS,
        .max_unit_records = EXECUTION_WIRE_V1_MAX_UNIT_RECORDS, .max_timer_records = EXECUTION_WIRE_V1_MAX_TIMER_RECORDS
    }, order);
    writer_map(writer, 12U);
    writer_key(writer, "phase"); writer_uint(writer, value->phase);
    writer_key(writer, "roles"); writer_role_map(writer, value->roles, value->role_count, order);
    writer_key(writer, "generation"); writer_uint(writer, value->generation);
    writer_key(writer, "tuple_digest"); writer_digest(writer, &value->tuple_digest);
    writer_key(writer, "schema_version"); writer_uint(writer, value->schema_version);
    writer_key(writer, "authority_domain"); writer_text(writer, &value->authority_domain);
    writer_key(writer, "policy_leaf_digest"); writer_digest(writer, &value->policy_leaf_digest);
    writer_key(writer, "attestor_leaf_digest"); writer_digest(writer, &value->attestor_leaf_digest);
    writer_key(writer, "launcher_leaf_digest"); writer_digest(writer, &value->launcher_leaf_digest);
    writer_key(writer, "execution_abi_version"); writer_uint(writer, value->execution_abi_version);
    writer_key(writer, "source_manifest_digest"); writer_digest(writer, &value->source_manifest_digest);
    writer_key(writer, "d73_authorization_binder"); writer_digest(writer, &value->d73_authorization_binder);
}

static ExecutionWireV1Status reader_tuple(WireReader *reader, const ExecutionWireV1Limits *limits, D73AuthorizedExecutionTupleV1 *value) {
    ExecutionWireV1Status status;
    memset(value, 0, sizeof(*value));
    status = reader_map_exact(reader, 12U);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    if ((status = reader_key(reader, "phase")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->phase)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "roles")) != EXECUTION_WIRE_V1_OK || (status = reader_role_map(reader, limits, value->roles, &value->role_count)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "generation")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->generation)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "tuple_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->tuple_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "schema_version")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->schema_version)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "authority_domain")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->authority_domain, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "policy_leaf_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->policy_leaf_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "attestor_leaf_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->attestor_leaf_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "launcher_leaf_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->launcher_leaf_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "execution_abi_version")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->execution_abi_version)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "source_manifest_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->source_manifest_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "d73_authorization_binder")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->d73_authorization_binder)) != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    return validate_tuple(value, limits);
}

ExecutionWireV1Status execution_wire_v1_encode_tuple(const D73AuthorizedExecutionTupleV1 *input, const ExecutionWireV1Limits *limits, uint8_t *output, size_t *inout_length) {
    WireWriter writer;
    size_t needed;
    ExecutionWireV1Status status = validate_limits(limits);
    if (status != EXECUTION_WIRE_V1_OK || inout_length == NULL) return status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : status;
    status = validate_tuple(input, limits);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    writer = (WireWriter){.data = NULL, .capacity = 0U, .length = 0U, .sizing = true, .status = EXECUTION_WIRE_V1_OK};
    writer_tuple(&writer, input);
    if (writer.status != EXECUTION_WIRE_V1_OK || writer.length > limits->max_total_bytes) return writer.status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_LIMIT : writer.status;
    needed = writer.length;
    if (output == NULL) { *inout_length = needed; return EXECUTION_WIRE_V1_OK; }
    if (*inout_length < needed) { *inout_length = needed; return EXECUTION_WIRE_V1_BUFFER_TOO_SMALL; }
    writer = (WireWriter){.data = output, .capacity = *inout_length, .length = 0U, .sizing = false, .status = EXECUTION_WIRE_V1_OK};
    writer_tuple(&writer, input);
    *inout_length = writer.length;
    return writer.status;
}

ExecutionWireV1Status execution_wire_v1_decode_tuple(const uint8_t *input, size_t input_length, const ExecutionWireV1Limits *limits, D73AuthorizedExecutionTupleV1 *output) {
    WireReader reader;
    ExecutionWireV1Status status = validate_limits(limits);
    if (status != EXECUTION_WIRE_V1_OK || input == NULL || output == NULL || input_length == 0U) return status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : status;
    if (input_length > limits->max_total_bytes) return EXECUTION_WIRE_V1_LIMIT;
    reader = (WireReader){.data = input, .length = input_length, .position = 0U, .status = EXECUTION_WIRE_V1_OK};
    status = reader_tuple(&reader, limits, output);
    if (status == EXECUTION_WIRE_V1_OK && reader.position != reader.length) return EXECUTION_WIRE_V1_NONCANONICAL;
    return status;
}

static void writer_measurement(WireWriter *writer, const ExecutionWireV1RoleMeasurement *value) {
    writer_map(writer, 9U);
    writer_key(writer, "inode"); writer_uint(writer, value->inode);
    writer_key(writer, "nlink"); writer_uint(writer, value->nlink);
    writer_key(writer, "device"); writer_uint(writer, value->device);
    writer_key(writer, "owner_class"); writer_text(writer, &value->owner_class);
    writer_key(writer, "expected_mode"); writer_uint(writer, value->expected_mode);
    writer_key(writer, "normal_digest"); writer_digest(writer, &value->normal_digest);
    writer_key(writer, "relative_path"); writer_text(writer, &value->relative_path);
    writer_key(writer, "verity_digest"); writer_digest(writer, &value->verity_digest);
    writer_key(writer, "verity_enabled"); writer_bool(writer, value->verity_enabled);
}

static ExecutionWireV1Status reader_measurement(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1RoleMeasurement *value) {
    ExecutionWireV1Status status;
    if ((status = reader_map_exact(reader, 9U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "inode")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->inode)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "nlink")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->nlink)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "device")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->device)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "owner_class")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->owner_class, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "expected_mode")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->expected_mode)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "normal_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->normal_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "relative_path")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->relative_path, true)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "verity_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->verity_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "verity_enabled")) != EXECUTION_WIRE_V1_OK || (status = reader_bool(reader, &value->verity_enabled)) != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    return EXECUTION_WIRE_V1_OK;
}

static void writer_measurement_map(WireWriter *writer, const ExecutionWireV1RoleMeasurement *roles, size_t count, const size_t *order) {
    size_t index;
    writer_map(writer, count);
    for (index = 0U; index < count; ++index) {
        writer_text(writer, &roles[order[index]].role_id);
        writer_measurement(writer, &roles[order[index]]);
    }
}

static ExecutionWireV1Status reader_measurement_map(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1RoleMeasurement *roles, size_t *count) {
    size_t index;
    ExecutionWireV1Status status = reader_count(reader, 5U, limits->max_roles, count);
    if (status != EXECUTION_WIRE_V1_OK || *count == 0U) {
        return status == EXECUTION_WIRE_V1_OK ? (reader->status = EXECUTION_WIRE_V1_MALFORMED) : status;
    }
    for (index = 0U; index < *count; ++index) {
        status = reader_text(reader, limits, &roles[index].role_id, false);
        if (status == EXECUTION_WIRE_V1_OK && index > 0U && text_compare(&roles[index - 1U].role_id, &roles[index].role_id) >= 0) {
            status = reader->status = EXECUTION_WIRE_V1_NONCANONICAL;
        }
        if (status == EXECUTION_WIRE_V1_OK) status = reader_measurement(reader, limits, &roles[index]);
        if (status != EXECUTION_WIRE_V1_OK) return status;
    }
    return EXECUTION_WIRE_V1_OK;
}

static void writer_phases(WireWriter *writer, const ApprovalRecordV1 *value) {
    size_t index;
    writer_array(writer, value->allowed_phase_count);
    for (index = 0U; index < value->allowed_phase_count; ++index) writer_uint(writer, value->allowed_phases[index]);
}

static ExecutionWireV1Status reader_phases(WireReader *reader, const ExecutionWireV1Limits *limits, ApprovalRecordV1 *value) {
    size_t index;
    ExecutionWireV1Status status = reader_count(reader, 4U, limits->max_phases, &value->allowed_phase_count);
    if (status != EXECUTION_WIRE_V1_OK || value->allowed_phase_count == 0U) {
        return status == EXECUTION_WIRE_V1_OK ? (reader->status = EXECUTION_WIRE_V1_MALFORMED) : status;
    }
    for (index = 0U; index < value->allowed_phase_count; ++index) {
        if ((status = reader_uint(reader, &value->allowed_phases[index])) != EXECUTION_WIRE_V1_OK) return status;
        if (index > 0U && value->allowed_phases[index - 1U] >= value->allowed_phases[index]) {
            reader->status = EXECUTION_WIRE_V1_NONCANONICAL;
            return reader->status;
        }
    }
    return EXECUTION_WIRE_V1_OK;
}

static void writer_approval(WireWriter *writer, const ApprovalRecordV1 *value) {
    size_t order[EXECUTION_WIRE_V1_MAX_ROLES];
    (void)ordered_measurements(value->roles, value->role_count, &(ExecutionWireV1Limits){
        .max_total_bytes = EXECUTION_WIRE_V1_HARD_MAX_TOTAL_BYTES, .max_snapshot_bytes = EXECUTION_WIRE_V1_HARD_MAX_TOTAL_BYTES,
        .max_text_bytes = EXECUTION_WIRE_V1_TEXT_CAPACITY, .max_roles = EXECUTION_WIRE_V1_MAX_ROLES,
        .max_phases = EXECUTION_WIRE_V1_MAX_PHASES, .max_process_records = EXECUTION_WIRE_V1_MAX_PROCESS_RECORDS,
        .max_fd_records = EXECUTION_WIRE_V1_MAX_FD_RECORDS, .max_fdinfo_records = EXECUTION_WIRE_V1_MAX_FDINFO_RECORDS,
        .max_lock_records = EXECUTION_WIRE_V1_MAX_LOCK_RECORDS, .max_namespace_records = EXECUTION_WIRE_V1_MAX_NAMESPACE_RECORDS,
        .max_unit_records = EXECUTION_WIRE_V1_MAX_UNIT_RECORDS, .max_timer_records = EXECUTION_WIRE_V1_MAX_TIMER_RECORDS
    }, order);
    writer_map(writer, 16U);
    writer_key(writer, "roles"); writer_measurement_map(writer, value->roles, value->role_count, order);
    writer_key(writer, "generation"); writer_uint(writer, value->generation);
    writer_key(writer, "record_kind"); writer_text(writer, &value->record_kind);
    writer_key(writer, "tuple_digest"); writer_digest(writer, &value->tuple_digest);
    writer_key(writer, "allowed_phases"); writer_phases(writer, value);
    writer_key(writer, "schema_version"); writer_uint(writer, value->schema_version);
    writer_key(writer, "policy_leaf_digest"); writer_digest(writer, &value->policy_leaf_digest);
    writer_key(writer, "boot_binding_digest"); writer_digest(writer, &value->boot_binding_digest);
    writer_key(writer, "host_binding_digest"); writer_digest(writer, &value->host_binding_digest);
    writer_key(writer, "attestor_leaf_digest"); writer_digest(writer, &value->attestor_leaf_digest);
    writer_key(writer, "launcher_leaf_digest"); writer_digest(writer, &value->launcher_leaf_digest);
    writer_key(writer, "record_relative_path"); writer_text(writer, &value->record_relative_path);
    writer_key(writer, "execution_abi_version"); writer_uint(writer, value->execution_abi_version);
    writer_key(writer, "source_manifest_digest"); writer_digest(writer, &value->source_manifest_digest);
    writer_key(writer, "d73_authorization_binder"); writer_digest(writer, &value->d73_authorization_binder);
    writer_key(writer, "policy_collector_abi_version"); writer_uint(writer, value->policy_collector_abi_version);
}

static ExecutionWireV1Status reader_approval(WireReader *reader, const ExecutionWireV1Limits *limits, ApprovalRecordV1 *value) {
    ExecutionWireV1Status status;
    memset(value, 0, sizeof(*value));
    if ((status = reader_map_exact(reader, 16U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "roles")) != EXECUTION_WIRE_V1_OK || (status = reader_measurement_map(reader, limits, value->roles, &value->role_count)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "generation")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->generation)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "record_kind")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->record_kind, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "tuple_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->tuple_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "allowed_phases")) != EXECUTION_WIRE_V1_OK || (status = reader_phases(reader, limits, value)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "schema_version")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->schema_version)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "policy_leaf_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->policy_leaf_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "boot_binding_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->boot_binding_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "host_binding_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->host_binding_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "attestor_leaf_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->attestor_leaf_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "launcher_leaf_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->launcher_leaf_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "record_relative_path")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->record_relative_path, true)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "execution_abi_version")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->execution_abi_version)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "source_manifest_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->source_manifest_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "d73_authorization_binder")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->d73_authorization_binder)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "policy_collector_abi_version")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->policy_collector_abi_version)) != EXECUTION_WIRE_V1_OK) {
        return status;
    }
    return validate_approval(value, limits);
}

ExecutionWireV1Status execution_wire_v1_encode_approval(const ApprovalRecordV1 *input, const ExecutionWireV1Limits *limits, uint8_t *output, size_t *inout_length) {
    WireWriter writer;
    size_t needed;
    ExecutionWireV1Status status = validate_limits(limits);
    if (status != EXECUTION_WIRE_V1_OK || inout_length == NULL) return status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : status;
    status = validate_approval(input, limits);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    writer = (WireWriter){.data = NULL, .capacity = 0U, .length = 0U, .sizing = true, .status = EXECUTION_WIRE_V1_OK};
    writer_approval(&writer, input);
    if (writer.status != EXECUTION_WIRE_V1_OK || writer.length > limits->max_total_bytes) return writer.status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_LIMIT : writer.status;
    needed = writer.length;
    if (output == NULL) { *inout_length = needed; return EXECUTION_WIRE_V1_OK; }
    if (*inout_length < needed) { *inout_length = needed; return EXECUTION_WIRE_V1_BUFFER_TOO_SMALL; }
    writer = (WireWriter){.data = output, .capacity = *inout_length, .length = 0U, .sizing = false, .status = EXECUTION_WIRE_V1_OK};
    writer_approval(&writer, input);
    *inout_length = writer.length;
    return writer.status;
}

ExecutionWireV1Status execution_wire_v1_decode_approval(const uint8_t *input, size_t input_length, const ExecutionWireV1Limits *limits, ApprovalRecordV1 *output) {
    WireReader reader;
    ExecutionWireV1Status status = validate_limits(limits);
    if (status != EXECUTION_WIRE_V1_OK || input == NULL || output == NULL || input_length == 0U) return status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : status;
    if (input_length > limits->max_total_bytes) return EXECUTION_WIRE_V1_LIMIT;
    reader = (WireReader){.data = input, .length = input_length, .position = 0U, .status = EXECUTION_WIRE_V1_OK};
    status = reader_approval(&reader, limits, output);
    if (status == EXECUTION_WIRE_V1_OK && reader.position != reader.length) return EXECUTION_WIRE_V1_NONCANONICAL;
    return status;
}

static void writer_process(WireWriter *writer, const ExecutionWireV1ProcessRecord *value) {
    writer_map(writer, 8U);
    writer_key(writer, "pid"); writer_uint(writer, value->pid);
    writer_key(writer, "uid"); writer_uint(writer, value->uid);
    writer_key(writer, "comm"); writer_text(writer, &value->comm);
    writer_key(writer, "ppid"); writer_uint(writer, value->ppid);
    writer_key(writer, "start_time"); writer_uint(writer, value->start_time);
    writer_key(writer, "unit_class"); writer_text(writer, &value->unit_class);
    writer_key(writer, "cgroup_class"); writer_text(writer, &value->cgroup_class);
    writer_key(writer, "exe_basename"); writer_text(writer, &value->exe_basename);
}

static ExecutionWireV1Status reader_process(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1ProcessRecord *value) {
    ExecutionWireV1Status status;
    memset(value, 0, sizeof(*value));
    if ((status = reader_map_exact(reader, 8U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "pid")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->pid)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "uid")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->uid)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "comm")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->comm, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "ppid")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->ppid)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "start_time")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->start_time)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "unit_class")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->unit_class, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "cgroup_class")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->cgroup_class, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "exe_basename")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->exe_basename, false)) != EXECUTION_WIRE_V1_OK) return status;
    return EXECUTION_WIRE_V1_OK;
}

static void writer_fd(WireWriter *writer, const ExecutionWireV1FdRecord *value) {
    writer_map(writer, 8U);
    writer_key(writer, "fd"); writer_uint(writer, value->fd);
    writer_key(writer, "pid"); writer_uint(writer, value->pid);
    writer_key(writer, "flags"); writer_uint(writer, value->flags);
    writer_key(writer, "inode"); writer_uint(writer, value->inode);
    writer_key(writer, "device"); writer_uint(writer, value->device);
    writer_key(writer, "type_id"); writer_text(writer, &value->type_id);
    writer_key(writer, "position"); writer_uint(writer, value->position);
    writer_key(writer, "start_time"); writer_uint(writer, value->start_time);
}

static ExecutionWireV1Status reader_fd(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1FdRecord *value) {
    ExecutionWireV1Status status;
    memset(value, 0, sizeof(*value));
    if ((status = reader_map_exact(reader, 8U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "fd")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->fd)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "pid")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->pid)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "flags")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->flags)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "inode")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->inode)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "device")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->device)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "type_id")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->type_id, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "position")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->position)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "start_time")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->start_time)) != EXECUTION_WIRE_V1_OK) return status;
    return EXECUTION_WIRE_V1_OK;
}

static void writer_fdinfo(WireWriter *writer, const ExecutionWireV1FdInfoRecord *value) {
    writer_map(writer, 6U);
    writer_key(writer, "fd"); writer_uint(writer, value->fd);
    writer_key(writer, "pid"); writer_uint(writer, value->pid);
    writer_key(writer, "flags"); writer_uint(writer, value->flags);
    writer_key(writer, "position"); writer_uint(writer, value->position);
    writer_key(writer, "identifier"); writer_text(writer, &value->identifier);
    writer_key(writer, "start_time"); writer_uint(writer, value->start_time);
}

static ExecutionWireV1Status reader_fdinfo(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1FdInfoRecord *value) {
    ExecutionWireV1Status status;
    memset(value, 0, sizeof(*value));
    if ((status = reader_map_exact(reader, 6U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "fd")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->fd)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "pid")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->pid)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "flags")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->flags)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "position")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->position)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "identifier")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->identifier, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "start_time")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->start_time)) != EXECUTION_WIRE_V1_OK) return status;
    return EXECUTION_WIRE_V1_OK;
}

static void writer_lock(WireWriter *writer, const ExecutionWireV1LockRecord *value) {
    writer_map(writer, 7U);
    writer_key(writer, "pid"); writer_uint(writer, value->pid);
    writer_key(writer, "inode"); writer_uint(writer, value->inode);
    writer_key(writer, "device"); writer_uint(writer, value->device);
    writer_key(writer, "range_end"); writer_uint(writer, value->range_end);
    writer_key(writer, "lock_class"); writer_text(writer, &value->lock_class);
    writer_key(writer, "start_time"); writer_uint(writer, value->start_time);
    writer_key(writer, "range_start"); writer_uint(writer, value->range_start);
}

static ExecutionWireV1Status reader_lock(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1LockRecord *value) {
    ExecutionWireV1Status status;
    memset(value, 0, sizeof(*value));
    if ((status = reader_map_exact(reader, 7U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "pid")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->pid)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "inode")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->inode)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "device")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->device)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "range_end")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->range_end)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "lock_class")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->lock_class, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "start_time")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->start_time)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "range_start")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->range_start)) != EXECUTION_WIRE_V1_OK) return status;
    return value->range_start > value->range_end ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : EXECUTION_WIRE_V1_OK;
}

static void writer_namespace(WireWriter *writer, const ExecutionWireV1NamespaceRecord *value) {
    writer_map(writer, 4U);
    writer_key(writer, "pid"); writer_uint(writer, value->pid);
    writer_key(writer, "inode"); writer_uint(writer, value->inode);
    writer_key(writer, "class_id"); writer_text(writer, &value->class_id);
    writer_key(writer, "start_time"); writer_uint(writer, value->start_time);
}

static ExecutionWireV1Status reader_namespace(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1NamespaceRecord *value) {
    ExecutionWireV1Status status;
    memset(value, 0, sizeof(*value));
    if ((status = reader_map_exact(reader, 4U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "pid")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->pid)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "inode")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->inode)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "class_id")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->class_id, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "start_time")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->start_time)) != EXECUTION_WIRE_V1_OK) return status;
    return EXECUTION_WIRE_V1_OK;
}

static void writer_service(WireWriter *writer, const ExecutionWireV1ServiceRecord *value) {
    writer_map(writer, 3U);
    writer_key(writer, "status"); writer_text(writer, &value->status);
    writer_key(writer, "class_id"); writer_text(writer, &value->class_id);
    writer_key(writer, "time_value"); writer_uint(writer, value->time_value);
}

static ExecutionWireV1Status reader_service(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1ServiceRecord *value) {
    ExecutionWireV1Status status;
    memset(value, 0, sizeof(*value));
    if ((status = reader_map_exact(reader, 3U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "status")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->status, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "class_id")) != EXECUTION_WIRE_V1_OK || (status = reader_text(reader, limits, &value->class_id, false)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "time_value")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->time_value)) != EXECUTION_WIRE_V1_OK) return status;
    return EXECUTION_WIRE_V1_OK;
}

static void writer_processes(WireWriter *writer, const ExecutionWireV1ProcessRecord *values, size_t count) {
    size_t index;
    writer_array(writer, count);
    for (index = 0U; index < count; ++index) writer_process(writer, &values[index]);
}
static void writer_fds(WireWriter *writer, const ExecutionWireV1FdRecord *values, size_t count) {
    size_t index;
    writer_array(writer, count);
    for (index = 0U; index < count; ++index) writer_fd(writer, &values[index]);
}
static void writer_fdinfos(WireWriter *writer, const ExecutionWireV1FdInfoRecord *values, size_t count) {
    size_t index;
    writer_array(writer, count);
    for (index = 0U; index < count; ++index) writer_fdinfo(writer, &values[index]);
}
static void writer_locks(WireWriter *writer, const ExecutionWireV1LockRecord *values, size_t count) {
    size_t index;
    writer_array(writer, count);
    for (index = 0U; index < count; ++index) writer_lock(writer, &values[index]);
}
static void writer_namespaces(WireWriter *writer, const ExecutionWireV1NamespaceRecord *values, size_t count) {
    size_t index;
    writer_array(writer, count);
    for (index = 0U; index < count; ++index) writer_namespace(writer, &values[index]);
}
static void writer_services(WireWriter *writer, const ExecutionWireV1ServiceRecord *values, size_t count) {
    size_t index;
    writer_array(writer, count);
    for (index = 0U; index < count; ++index) writer_service(writer, &values[index]);
}

static ExecutionWireV1Status reader_processes(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1ProcessRecord *values, size_t *count) {
    size_t index;
    ExecutionWireV1Status status = reader_count(reader, 4U, limits->max_process_records, count);
    for (index = 0U; status == EXECUTION_WIRE_V1_OK && index < *count; ++index) status = reader_process(reader, limits, &values[index]);
    return status;
}
static ExecutionWireV1Status reader_fds(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1FdRecord *values, size_t *count) {
    size_t index;
    ExecutionWireV1Status status = reader_count(reader, 4U, limits->max_fd_records, count);
    for (index = 0U; status == EXECUTION_WIRE_V1_OK && index < *count; ++index) status = reader_fd(reader, limits, &values[index]);
    return status;
}
static ExecutionWireV1Status reader_fdinfos(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1FdInfoRecord *values, size_t *count) {
    size_t index;
    ExecutionWireV1Status status = reader_count(reader, 4U, limits->max_fdinfo_records, count);
    for (index = 0U; status == EXECUTION_WIRE_V1_OK && index < *count; ++index) status = reader_fdinfo(reader, limits, &values[index]);
    return status;
}
static ExecutionWireV1Status reader_locks(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1LockRecord *values, size_t *count) {
    size_t index;
    ExecutionWireV1Status status = reader_count(reader, 4U, limits->max_lock_records, count);
    for (index = 0U; status == EXECUTION_WIRE_V1_OK && index < *count; ++index) status = reader_lock(reader, limits, &values[index]);
    return status;
}
static ExecutionWireV1Status reader_namespaces(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1NamespaceRecord *values, size_t *count) {
    size_t index;
    ExecutionWireV1Status status = reader_count(reader, 4U, limits->max_namespace_records, count);
    for (index = 0U; status == EXECUTION_WIRE_V1_OK && index < *count; ++index) status = reader_namespace(reader, limits, &values[index]);
    return status;
}
static ExecutionWireV1Status reader_services(WireReader *reader, const ExecutionWireV1Limits *limits, size_t maximum, ExecutionWireV1ServiceRecord *values, size_t *count) {
    size_t index;
    ExecutionWireV1Status status;
    status = reader_count(reader, 4U, maximum, count);
    for (index = 0U; status == EXECUTION_WIRE_V1_OK && index < *count; ++index) status = reader_service(reader, limits, &values[index]);
    return status;
}

static ExecutionWireV1Status validate_process(const ExecutionWireV1ProcessRecord *value, const ExecutionWireV1Limits *limits) {
    ExecutionWireV1Status status = validate_identifier(&value->comm, limits);
    if (status == EXECUTION_WIRE_V1_OK) status = validate_identifier(&value->exe_basename, limits);
    if (status == EXECUTION_WIRE_V1_OK) status = validate_identifier(&value->cgroup_class, limits);
    if (status == EXECUTION_WIRE_V1_OK) status = validate_identifier(&value->unit_class, limits);
    return status;
}
static ExecutionWireV1Status validate_fd(const ExecutionWireV1FdRecord *value, const ExecutionWireV1Limits *limits) { return validate_identifier(&value->type_id, limits); }
static ExecutionWireV1Status validate_fdinfo(const ExecutionWireV1FdInfoRecord *value, const ExecutionWireV1Limits *limits) { return validate_identifier(&value->identifier, limits); }
static ExecutionWireV1Status validate_lock(const ExecutionWireV1LockRecord *value, const ExecutionWireV1Limits *limits) {
    if (value->range_start > value->range_end) return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    return validate_identifier(&value->lock_class, limits);
}
static ExecutionWireV1Status validate_namespace(const ExecutionWireV1NamespaceRecord *value, const ExecutionWireV1Limits *limits) { return validate_identifier(&value->class_id, limits); }
static ExecutionWireV1Status validate_service(const ExecutionWireV1ServiceRecord *value, const ExecutionWireV1Limits *limits) {
    ExecutionWireV1Status status = validate_identifier(&value->class_id, limits);
    return status == EXECUTION_WIRE_V1_OK ? validate_identifier(&value->status, limits) : status;
}

static int compare_u64(uint64_t left, uint64_t right) { return left < right ? -1 : (left > right ? 1 : 0); }
static bool text_equal(const ExecutionWireV1Text *left, const ExecutionWireV1Text *right) { return left->length == right->length && memcmp(left->bytes, right->bytes, left->length) == 0; }

static int compare_process_identity(const ExecutionWireV1ProcessRecord *left, const ExecutionWireV1ProcessRecord *right) {
    int compared = compare_u64(left->pid, right->pid);
    return compared != 0 ? compared : compare_u64(left->start_time, right->start_time);
}
static int compare_fd_identity(const ExecutionWireV1FdRecord *left, const ExecutionWireV1FdRecord *right) {
    int compared = compare_u64(left->pid, right->pid);
    if (compared == 0) compared = compare_u64(left->start_time, right->start_time);
    return compared == 0 ? compare_u64(left->fd, right->fd) : compared;
}
static int compare_fdinfo_identity(const ExecutionWireV1FdInfoRecord *left, const ExecutionWireV1FdInfoRecord *right) {
    int compared = compare_u64(left->pid, right->pid);
    if (compared == 0) compared = compare_u64(left->start_time, right->start_time);
    return compared == 0 ? compare_u64(left->fd, right->fd) : compared;
}
static int compare_lock_identity(const ExecutionWireV1LockRecord *left, const ExecutionWireV1LockRecord *right) {
    int compared = compare_u64(left->pid, right->pid);
    if (compared == 0) compared = compare_u64(left->start_time, right->start_time);
    if (compared == 0) compared = compare_u64(left->device, right->device);
    if (compared == 0) compared = compare_u64(left->inode, right->inode);
    if (compared == 0) compared = compare_u64(left->range_start, right->range_start);
    if (compared == 0) compared = compare_u64(left->range_end, right->range_end);
    return compared == 0 ? text_compare(&left->lock_class, &right->lock_class) : compared;
}
static int compare_namespace_identity(const ExecutionWireV1NamespaceRecord *left, const ExecutionWireV1NamespaceRecord *right) {
    int compared = compare_u64(left->pid, right->pid);
    if (compared == 0) compared = compare_u64(left->start_time, right->start_time);
    if (compared == 0) compared = text_compare(&left->class_id, &right->class_id);
    return compared == 0 ? compare_u64(left->inode, right->inode) : compared;
}
static int compare_service_identity(const ExecutionWireV1ServiceRecord *left, const ExecutionWireV1ServiceRecord *right) { return text_compare(&left->class_id, &right->class_id); }

static ExecutionWireV1Status validate_snapshot_order(const ExecutionWireV1SnapshotV1 *value) {
    size_t index;
    for (index = 1U; index < value->process_count; ++index) if (compare_process_identity(&value->processes[index - 1U], &value->processes[index]) >= 0) return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    for (index = 1U; index < value->fd_count; ++index) if (compare_fd_identity(&value->fds[index - 1U], &value->fds[index]) >= 0) return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    for (index = 1U; index < value->fdinfo_count; ++index) if (compare_fdinfo_identity(&value->fdinfo[index - 1U], &value->fdinfo[index]) >= 0) return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    for (index = 1U; index < value->lock_count; ++index) if (compare_lock_identity(&value->locks[index - 1U], &value->locks[index]) >= 0) return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    for (index = 1U; index < value->namespace_count; ++index) if (compare_namespace_identity(&value->namespaces[index - 1U], &value->namespaces[index]) >= 0) return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    for (index = 1U; index < value->unit_count; ++index) if (compare_service_identity(&value->units[index - 1U], &value->units[index]) >= 0) return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    for (index = 1U; index < value->timer_count; ++index) if (compare_service_identity(&value->timers[index - 1U], &value->timers[index]) >= 0) return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    return EXECUTION_WIRE_V1_OK;
}

static bool process_equal(const ExecutionWireV1ProcessRecord *left, const ExecutionWireV1ProcessRecord *right) {
    return left->pid == right->pid && left->uid == right->uid && left->ppid == right->ppid && left->start_time == right->start_time &&
        text_equal(&left->comm, &right->comm) && text_equal(&left->exe_basename, &right->exe_basename) && text_equal(&left->cgroup_class, &right->cgroup_class) && text_equal(&left->unit_class, &right->unit_class);
}
static bool fd_equal(const ExecutionWireV1FdRecord *left, const ExecutionWireV1FdRecord *right) {
    return left->pid == right->pid && left->start_time == right->start_time && left->fd == right->fd && left->device == right->device && left->inode == right->inode && left->flags == right->flags && left->position == right->position && text_equal(&left->type_id, &right->type_id);
}
static bool fdinfo_equal(const ExecutionWireV1FdInfoRecord *left, const ExecutionWireV1FdInfoRecord *right) {
    return left->pid == right->pid && left->start_time == right->start_time && left->fd == right->fd && left->flags == right->flags && left->position == right->position && text_equal(&left->identifier, &right->identifier);
}
static bool lock_equal(const ExecutionWireV1LockRecord *left, const ExecutionWireV1LockRecord *right) {
    return left->pid == right->pid && left->start_time == right->start_time && left->device == right->device && left->inode == right->inode && left->range_start == right->range_start && left->range_end == right->range_end && text_equal(&left->lock_class, &right->lock_class);
}
static bool namespace_equal(const ExecutionWireV1NamespaceRecord *left, const ExecutionWireV1NamespaceRecord *right) {
    return left->pid == right->pid && left->start_time == right->start_time && left->inode == right->inode && text_equal(&left->class_id, &right->class_id);
}
static bool service_equal(const ExecutionWireV1ServiceRecord *left, const ExecutionWireV1ServiceRecord *right) {
    return left->time_value == right->time_value && text_equal(&left->class_id, &right->class_id) && text_equal(&left->status, &right->status);
}

static bool snapshots_equal_except_interval(const ExecutionWireV1SnapshotV1 *left, const ExecutionWireV1SnapshotV1 *right) {
    size_t index;
    if (!digest_equal(&left->selector_digest, &right->selector_digest) || left->complete != right->complete || left->process_count != right->process_count || left->fd_count != right->fd_count || left->fdinfo_count != right->fdinfo_count || left->lock_count != right->lock_count || left->namespace_count != right->namespace_count || left->unit_count != right->unit_count || left->timer_count != right->timer_count) return false;
    for (index = 0U; index < left->process_count; ++index) if (!process_equal(&left->processes[index], &right->processes[index])) return false;
    for (index = 0U; index < left->fd_count; ++index) if (!fd_equal(&left->fds[index], &right->fds[index])) return false;
    for (index = 0U; index < left->fdinfo_count; ++index) if (!fdinfo_equal(&left->fdinfo[index], &right->fdinfo[index])) return false;
    for (index = 0U; index < left->lock_count; ++index) if (!lock_equal(&left->locks[index], &right->locks[index])) return false;
    for (index = 0U; index < left->namespace_count; ++index) if (!namespace_equal(&left->namespaces[index], &right->namespaces[index])) return false;
    for (index = 0U; index < left->unit_count; ++index) if (!service_equal(&left->units[index], &right->units[index])) return false;
    for (index = 0U; index < left->timer_count; ++index) if (!service_equal(&left->timers[index], &right->timers[index])) return false;
    return true;
}

static ExecutionWireV1Status validate_snapshot(const ExecutionWireV1SnapshotV1 *value, const ExecutionWireV1Limits *limits) {
    size_t index;
    ExecutionWireV1Status status;
    if (value == NULL || !value->complete || value->process_count > limits->max_process_records || value->fd_count > limits->max_fd_records ||
        value->fdinfo_count > limits->max_fdinfo_records || value->lock_count > limits->max_lock_records ||
        value->namespace_count > limits->max_namespace_records || value->unit_count > limits->max_unit_records || value->timer_count > limits->max_timer_records) return EXECUTION_WIRE_V1_LIMIT;
    for (index = 0U; index < value->process_count; ++index) { status = validate_process(&value->processes[index], limits); if (status != EXECUTION_WIRE_V1_OK) return status; }
    for (index = 0U; index < value->fd_count; ++index) { status = validate_fd(&value->fds[index], limits); if (status != EXECUTION_WIRE_V1_OK) return status; }
    for (index = 0U; index < value->fdinfo_count; ++index) { status = validate_fdinfo(&value->fdinfo[index], limits); if (status != EXECUTION_WIRE_V1_OK) return status; }
    for (index = 0U; index < value->lock_count; ++index) { status = validate_lock(&value->locks[index], limits); if (status != EXECUTION_WIRE_V1_OK) return status; }
    for (index = 0U; index < value->namespace_count; ++index) { status = validate_namespace(&value->namespaces[index], limits); if (status != EXECUTION_WIRE_V1_OK) return status; }
    for (index = 0U; index < value->unit_count; ++index) { status = validate_service(&value->units[index], limits); if (status != EXECUTION_WIRE_V1_OK) return status; }
    for (index = 0U; index < value->timer_count; ++index) { status = validate_service(&value->timers[index], limits); if (status != EXECUTION_WIRE_V1_OK) return status; }
    return validate_snapshot_order(value);
}

static void writer_snapshot(WireWriter *writer, const ExecutionWireV1SnapshotV1 *value) {
    writer_map(writer, 10U);
    writer_key(writer, "complete"); writer_bool(writer, value->complete);
    writer_key(writer, "fd_records"); writer_fds(writer, value->fds, value->fd_count);
    writer_key(writer, "lock_records"); writer_locks(writer, value->locks, value->lock_count);
    writer_key(writer, "unit_records"); writer_services(writer, value->units, value->unit_count);
    writer_key(writer, "timer_records"); writer_services(writer, value->timers, value->timer_count);
    writer_key(writer, "fdinfo_records"); writer_fdinfos(writer, value->fdinfo, value->fdinfo_count);
    writer_key(writer, "process_records"); writer_processes(writer, value->processes, value->process_count);
    writer_key(writer, "selector_digest"); writer_digest(writer, &value->selector_digest);
    writer_key(writer, "namespace_records"); writer_namespaces(writer, value->namespaces, value->namespace_count);
    writer_key(writer, "monotonic_capture_interval"); writer_uint(writer, value->monotonic_capture_interval);
}

/* The binding preimage deliberately excludes only the capture interval. */
static void writer_snapshot_binding_preimage(WireWriter *writer, const ExecutionWireV1SnapshotV1 *value) {
    writer_map(writer, 9U);
    writer_key(writer, "complete"); writer_bool(writer, value->complete);
    writer_key(writer, "fd_records"); writer_fds(writer, value->fds, value->fd_count);
    writer_key(writer, "lock_records"); writer_locks(writer, value->locks, value->lock_count);
    writer_key(writer, "unit_records"); writer_services(writer, value->units, value->unit_count);
    writer_key(writer, "timer_records"); writer_services(writer, value->timers, value->timer_count);
    writer_key(writer, "fdinfo_records"); writer_fdinfos(writer, value->fdinfo, value->fdinfo_count);
    writer_key(writer, "process_records"); writer_processes(writer, value->processes, value->process_count);
    writer_key(writer, "selector_digest"); writer_digest(writer, &value->selector_digest);
    writer_key(writer, "namespace_records"); writer_namespaces(writer, value->namespaces, value->namespace_count);
}

ExecutionWireV1Status execution_wire_v1_snapshot_digest(const ExecutionWireV1SnapshotV1 *snapshot, const ExecutionWireV1Limits *limits, ExecutionWireV1Digest *output) {
    Sha256Context hash;
    WireWriter writer;
    ExecutionWireV1Status status = validate_limits(limits);
    if (status != EXECUTION_WIRE_V1_OK || output == NULL) return status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : status;
    status = validate_snapshot(snapshot, limits);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    sha256_init(&hash);
    writer = (WireWriter){.data = NULL, .capacity = SIZE_MAX, .length = 0U, .sizing = false, .emit = sha256_emit, .emit_context = &hash, .status = EXECUTION_WIRE_V1_OK};
    writer_snapshot_binding_preimage(&writer, snapshot);
    if (writer.status != EXECUTION_WIRE_V1_OK || writer.length > limits->max_snapshot_bytes) return writer.status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_LIMIT : writer.status;
    sha256_final(&hash, output);
    return EXECUTION_WIRE_V1_OK;
}

static ExecutionWireV1Status reader_snapshot(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionWireV1SnapshotV1 *value) {
    ExecutionWireV1Status status;
    size_t start = reader->position;
    memset(value, 0, sizeof(*value));
    if ((status = reader_map_exact(reader, 10U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "complete")) != EXECUTION_WIRE_V1_OK || (status = reader_bool(reader, &value->complete)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "fd_records")) != EXECUTION_WIRE_V1_OK || (status = reader_fds(reader, limits, value->fds, &value->fd_count)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "lock_records")) != EXECUTION_WIRE_V1_OK || (status = reader_locks(reader, limits, value->locks, &value->lock_count)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "unit_records")) != EXECUTION_WIRE_V1_OK || (status = reader_services(reader, limits, limits->max_unit_records, value->units, &value->unit_count)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "timer_records")) != EXECUTION_WIRE_V1_OK || (status = reader_services(reader, limits, limits->max_timer_records, value->timers, &value->timer_count)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "fdinfo_records")) != EXECUTION_WIRE_V1_OK || (status = reader_fdinfos(reader, limits, value->fdinfo, &value->fdinfo_count)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "process_records")) != EXECUTION_WIRE_V1_OK || (status = reader_processes(reader, limits, value->processes, &value->process_count)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "selector_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->selector_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "namespace_records")) != EXECUTION_WIRE_V1_OK || (status = reader_namespaces(reader, limits, value->namespaces, &value->namespace_count)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "monotonic_capture_interval")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->monotonic_capture_interval)) != EXECUTION_WIRE_V1_OK) return status;
    if (value->timer_count > limits->max_timer_records || value->unit_count > limits->max_unit_records || reader->position - start > limits->max_snapshot_bytes) return EXECUTION_WIRE_V1_LIMIT;
    return validate_snapshot(value, limits);
}

static ExecutionWireV1Status snapshot_size(const ExecutionWireV1SnapshotV1 *value, const ExecutionWireV1Limits *limits, size_t *size) {
    WireWriter writer = {.data = NULL, .capacity = 0U, .length = 0U, .sizing = true, .status = EXECUTION_WIRE_V1_OK};
    ExecutionWireV1Status status = validate_snapshot(value, limits);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    writer_snapshot(&writer, value);
    if (writer.status != EXECUTION_WIRE_V1_OK || writer.length > limits->max_snapshot_bytes) return writer.status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_LIMIT : writer.status;
    *size = writer.length;
    return EXECUTION_WIRE_V1_OK;
}

static void writer_target_final(WireWriter *writer, const ExecutionWireV1TargetFinal *value) {
    writer_map(writer, 3U);
    writer_key(writer, "final_predicate"); writer_bool(writer, value->final_predicate);
    writer_key(writer, "selector_digest"); writer_digest(writer, &value->selector_digest);
    writer_key(writer, "observed_target_set_digest"); writer_digest(writer, &value->observed_target_set_digest);
}

static ExecutionWireV1Status reader_target_final(WireReader *reader, ExecutionWireV1TargetFinal *value) {
    ExecutionWireV1Status status;
    memset(value, 0, sizeof(*value));
    if ((status = reader_map_exact(reader, 3U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "final_predicate")) != EXECUTION_WIRE_V1_OK || (status = reader_bool(reader, &value->final_predicate)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "selector_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->selector_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "observed_target_set_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->observed_target_set_digest)) != EXECUTION_WIRE_V1_OK) return status;
    return value->final_predicate ? EXECUTION_WIRE_V1_OK : EXECUTION_WIRE_V1_INVALID_ARGUMENT;
}

static ExecutionWireV1Status validate_envelope(const ExecutionEnvelopeV1 *value, const ExecutionWireV1Limits *limits) {
    size_t ignored;
    ExecutionWireV1Status status;
    ExecutionWireV1Digest snapshot_a_digest;
    ExecutionWireV1Digest snapshot_b_digest;
    if (value == NULL || value->schema_version != EXECUTION_WIRE_V1_SCHEMA_VERSION || value->execution_abi_version == 0U ||
        value->collector_abi_version == 0U || value->fd_number != EXECUTION_WIRE_V1_ENVELOPE_FD ||
        value->fd_seal_mask != EXECUTION_WIRE_V1_REQUIRED_SEALS || value->fd_cloexec || !value->target_final.final_predicate) return EXECUTION_WIRE_V1_INVALID_ARGUMENT;
    status = snapshot_size(&value->snapshot_a, limits, &ignored);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    status = snapshot_size(&value->snapshot_b, limits, &ignored);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    if (!snapshots_equal_except_interval(&value->snapshot_a, &value->snapshot_b) ||
        !digest_equal(&value->snapshot_a.selector_digest, &value->target_final.selector_digest)) return EXECUTION_WIRE_V1_MISMATCH;
    status = execution_wire_v1_snapshot_digest(&value->snapshot_a, limits, &snapshot_a_digest);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    status = execution_wire_v1_snapshot_digest(&value->snapshot_b, limits, &snapshot_b_digest);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    if (!digest_equal(&snapshot_a_digest, &snapshot_b_digest) || !digest_equal(&value->snapshot_a_digest, &snapshot_a_digest) ||
        !digest_equal(&value->snapshot_b_digest, &snapshot_b_digest)) return EXECUTION_WIRE_V1_MISMATCH;
    return EXECUTION_WIRE_V1_OK;
}

static void writer_envelope(WireWriter *writer, const ExecutionEnvelopeV1 *value) {
    writer_map(writer, 22U);
    writer_key(writer, "phase"); writer_uint(writer, value->phase);
    writer_key(writer, "fd_cloexec"); writer_bool(writer, value->fd_cloexec);
    writer_key(writer, "fd_number"); writer_uint(writer, value->fd_number);
    writer_key(writer, "generation"); writer_uint(writer, value->generation);
    writer_key(writer, "snapshot_a"); writer_snapshot(writer, &value->snapshot_a);
    writer_key(writer, "snapshot_b"); writer_snapshot(writer, &value->snapshot_b);
    writer_key(writer, "fd_seal_mask"); writer_uint(writer, value->fd_seal_mask);
    writer_key(writer, "target_final"); writer_target_final(writer, &value->target_final);
    writer_key(writer, "tuple_digest"); writer_digest(writer, &value->tuple_digest);
    writer_key(writer, "schema_version"); writer_uint(writer, value->schema_version);
    writer_key(writer, "snapshot_a_digest"); writer_digest(writer, &value->snapshot_a_digest);
    writer_key(writer, "snapshot_b_digest"); writer_digest(writer, &value->snapshot_b_digest);
    writer_key(writer, "policy_leaf_digest"); writer_digest(writer, &value->policy_leaf_digest);
    writer_key(writer, "boot_binding_digest"); writer_digest(writer, &value->boot_binding_digest);
    writer_key(writer, "host_binding_digest"); writer_digest(writer, &value->host_binding_digest);
    writer_key(writer, "attestor_leaf_digest"); writer_digest(writer, &value->attestor_leaf_digest);
    writer_key(writer, "launcher_leaf_digest"); writer_digest(writer, &value->launcher_leaf_digest);
    writer_key(writer, "collector_abi_version"); writer_uint(writer, value->collector_abi_version);
    writer_key(writer, "execution_abi_version"); writer_uint(writer, value->execution_abi_version);
    writer_key(writer, "approval_record_digest"); writer_digest(writer, &value->approval_record_digest);
    writer_key(writer, "source_manifest_digest"); writer_digest(writer, &value->source_manifest_digest);
    writer_key(writer, "collector_artifact_binder"); writer_digest(writer, &value->collector_artifact_binder);
}

static ExecutionWireV1Status reader_envelope(WireReader *reader, const ExecutionWireV1Limits *limits, ExecutionEnvelopeV1 *value) {
    ExecutionWireV1Status status;
    memset(value, 0, sizeof(*value));
    if ((status = reader_map_exact(reader, 22U)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "phase")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->phase)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "fd_cloexec")) != EXECUTION_WIRE_V1_OK || (status = reader_bool(reader, &value->fd_cloexec)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "fd_number")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->fd_number)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "generation")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->generation)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "snapshot_a")) != EXECUTION_WIRE_V1_OK || (status = reader_snapshot(reader, limits, &value->snapshot_a)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "snapshot_b")) != EXECUTION_WIRE_V1_OK || (status = reader_snapshot(reader, limits, &value->snapshot_b)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "fd_seal_mask")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->fd_seal_mask)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "target_final")) != EXECUTION_WIRE_V1_OK || (status = reader_target_final(reader, &value->target_final)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "tuple_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->tuple_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "schema_version")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->schema_version)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "snapshot_a_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->snapshot_a_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "snapshot_b_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->snapshot_b_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "policy_leaf_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->policy_leaf_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "boot_binding_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->boot_binding_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "host_binding_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->host_binding_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "attestor_leaf_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->attestor_leaf_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "launcher_leaf_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->launcher_leaf_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "collector_abi_version")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->collector_abi_version)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "execution_abi_version")) != EXECUTION_WIRE_V1_OK || (status = reader_uint(reader, &value->execution_abi_version)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "approval_record_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->approval_record_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "source_manifest_digest")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->source_manifest_digest)) != EXECUTION_WIRE_V1_OK ||
        (status = reader_key(reader, "collector_artifact_binder")) != EXECUTION_WIRE_V1_OK || (status = reader_digest(reader, &value->collector_artifact_binder)) != EXECUTION_WIRE_V1_OK) return status;
    return validate_envelope(value, limits);
}

ExecutionWireV1Status execution_wire_v1_encode_envelope(const ExecutionEnvelopeV1 *input, const ExecutionWireV1Limits *limits, uint8_t *output, size_t *inout_length) {
    WireWriter writer;
    size_t needed;
    ExecutionWireV1Status status = validate_limits(limits);
    if (status != EXECUTION_WIRE_V1_OK || inout_length == NULL) return status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : status;
    status = validate_envelope(input, limits);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    writer = (WireWriter){.data = NULL, .capacity = 0U, .length = 0U, .sizing = true, .status = EXECUTION_WIRE_V1_OK};
    writer_envelope(&writer, input);
    if (writer.status != EXECUTION_WIRE_V1_OK || writer.length > limits->max_total_bytes) return writer.status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_LIMIT : writer.status;
    needed = writer.length;
    if (output == NULL) { *inout_length = needed; return EXECUTION_WIRE_V1_OK; }
    if (*inout_length < needed) { *inout_length = needed; return EXECUTION_WIRE_V1_BUFFER_TOO_SMALL; }
    writer = (WireWriter){.data = output, .capacity = *inout_length, .length = 0U, .sizing = false, .status = EXECUTION_WIRE_V1_OK};
    writer_envelope(&writer, input);
    *inout_length = writer.length;
    return writer.status;
}

ExecutionWireV1Status execution_wire_v1_decode_envelope(const uint8_t *input, size_t input_length, const ExecutionWireV1Limits *limits, ExecutionEnvelopeV1 *output) {
    WireReader reader;
    ExecutionWireV1Status status = validate_limits(limits);
    if (status != EXECUTION_WIRE_V1_OK || input == NULL || output == NULL || input_length == 0U) return status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : status;
    if (input_length > limits->max_total_bytes) return EXECUTION_WIRE_V1_LIMIT;
    reader = (WireReader){.data = input, .length = input_length, .position = 0U, .status = EXECUTION_WIRE_V1_OK};
    status = reader_envelope(&reader, limits, output);
    if (status == EXECUTION_WIRE_V1_OK && reader.position != reader.length) return EXECUTION_WIRE_V1_NONCANONICAL;
    return status;
}

static bool approval_allows_phase(const ApprovalRecordV1 *approval, uint64_t phase) {
    size_t index;
    for (index = 0U; index < approval->allowed_phase_count; ++index) {
        if (approval->allowed_phases[index] == phase) return true;
    }
    return false;
}

ExecutionWireV1Status execution_wire_v1_validate_approval_for_tuple(const ApprovalRecordV1 *approval, const D73AuthorizedExecutionTupleV1 *tuple, const ExecutionWireV1Limits *limits) {
    size_t approval_order[EXECUTION_WIRE_V1_MAX_ROLES];
    size_t tuple_order[EXECUTION_WIRE_V1_MAX_ROLES];
    size_t index;
    ExecutionWireV1Status status = validate_limits(limits);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    status = validate_approval(approval, limits);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    status = validate_tuple(tuple, limits);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    if (approval->execution_abi_version != tuple->execution_abi_version || approval->generation != tuple->generation ||
        !digest_equal(&approval->tuple_digest, &tuple->tuple_digest) || !digest_equal(&approval->source_manifest_digest, &tuple->source_manifest_digest) ||
        !digest_equal(&approval->d73_authorization_binder, &tuple->d73_authorization_binder) ||
        !digest_equal(&approval->policy_leaf_digest, &tuple->policy_leaf_digest) || !digest_equal(&approval->launcher_leaf_digest, &tuple->launcher_leaf_digest) ||
        !digest_equal(&approval->attestor_leaf_digest, &tuple->attestor_leaf_digest) || !approval_allows_phase(approval, tuple->phase) ||
        approval->role_count != tuple->role_count) return EXECUTION_WIRE_V1_MISMATCH;
    status = ordered_measurements(approval->roles, approval->role_count, limits, approval_order);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    status = ordered_role_digests(tuple->roles, tuple->role_count, limits, tuple_order);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    for (index = 0U; index < approval->role_count; ++index) {
        const ExecutionWireV1RoleMeasurement *measurement = &approval->roles[approval_order[index]];
        const ExecutionWireV1RoleDigest *role = &tuple->roles[tuple_order[index]];
        if (text_compare(&measurement->role_id, &role->role_id) != 0 || text_compare(&measurement->relative_path, &role->relative_path) != 0 ||
            !digest_equal(&measurement->normal_digest, &role->normal_digest)) return EXECUTION_WIRE_V1_MISMATCH;
    }
    return EXECUTION_WIRE_V1_OK;
}

ExecutionWireV1Status execution_wire_v1_validate_envelope_for_tuple_and_approval(
    const ExecutionEnvelopeV1 *envelope,
    const D73AuthorizedExecutionTupleV1 *tuple,
    const ApprovalRecordV1 *approval,
    const ExecutionWireV1Digest *measured_approval_record_digest,
    const ExecutionWireV1Limits *limits
) {
    ExecutionWireV1Status status = validate_limits(limits);
    if (status != EXECUTION_WIRE_V1_OK || measured_approval_record_digest == NULL) return status == EXECUTION_WIRE_V1_OK ? EXECUTION_WIRE_V1_INVALID_ARGUMENT : status;
    status = execution_wire_v1_validate_approval_for_tuple(approval, tuple, limits);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    status = validate_envelope(envelope, limits);
    if (status != EXECUTION_WIRE_V1_OK) return status;
    if (envelope->execution_abi_version != tuple->execution_abi_version || envelope->collector_abi_version != approval->policy_collector_abi_version ||
        envelope->generation != tuple->generation || envelope->phase != tuple->phase ||
        !digest_equal(&envelope->tuple_digest, &tuple->tuple_digest) || !digest_equal(&envelope->source_manifest_digest, &tuple->source_manifest_digest) ||
        !digest_equal(&envelope->approval_record_digest, measured_approval_record_digest) || !digest_equal(&envelope->policy_leaf_digest, &tuple->policy_leaf_digest) ||
        !digest_equal(&envelope->launcher_leaf_digest, &tuple->launcher_leaf_digest) || !digest_equal(&envelope->attestor_leaf_digest, &tuple->attestor_leaf_digest) ||
        !digest_equal(&envelope->collector_artifact_binder, &tuple->launcher_leaf_digest) ||
        !digest_equal(&envelope->host_binding_digest, &approval->host_binding_digest) || !digest_equal(&envelope->boot_binding_digest, &approval->boot_binding_digest)) return EXECUTION_WIRE_V1_MISMATCH;
    return EXECUTION_WIRE_V1_OK;
}
