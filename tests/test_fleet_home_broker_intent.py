from __future__ import annotations

import dataclasses
from dataclasses import FrozenInstanceError
import hashlib
import json
import pickle
import types

import pytest

import codex_master.fleet_home_broker_intent as intent_codec
from codex_master.fleet_home_broker_intent import (
    MAX_BROKER_INTENT_BYTES,
    BrokerIntentCode,
    BrokerIntentError,
    BrokerIntentOperation,
    BrokerIntentV1,
    canonical_intent_payload,
    decode_broker_intent,
    encode_broker_intent,
)


SCHEMA_FIELDS = (
    "schema_version",
    "intent_generation",
    "operation",
    "transaction_id",
    "request_id",
    "agent_id",
    "manifest_generation",
    "unit_generation",
    "policy_generation",
    "fencing_epoch",
    "store_uuid",
    "slot_id",
    "mcs_pair",
    "projection_digest",
    "joint_release_id",
    "server_digest",
    "broker_manifest_digest",
    "credential_binding_ref",
    "credential_generation",
    "created_at_unix_ms",
    "expires_at_unix_ms",
    "nonce",
    "digest",
)


BASE_VALUES: dict[str, object] = {
    "schema_version": 1,
    "intent_generation": 7,
    "operation": BrokerIntentOperation.PROVISION,
    "transaction_id": "2" * 32,
    "request_id": "1" * 32,
    "agent_id": "bee_1",
    "manifest_generation": 3,
    "unit_generation": 9,
    "policy_generation": 7,
    "fencing_epoch": 4,
    "store_uuid": "3" * 32,
    "slot_id": "slot-01",
    "mcs_pair": "c0,c1",
    "projection_digest": "a" * 64,
    "joint_release_id": "release-0.11.0",
    "server_digest": "b" * 64,
    "broker_manifest_digest": "c" * 64,
    "credential_binding_ref": "cred-bind-01",
    "credential_generation": 2,
    "created_at_unix_ms": 1_700_000_000_000,
    "expires_at_unix_ms": 1_700_000_030_000,
    "nonce": "d" * 32,
    "digest": "0" * 64,
}


def _unsigned(**changes: object) -> BrokerIntentV1:
    values = {**BASE_VALUES, **changes}
    return BrokerIntentV1(**values)


def _intent(**changes: object) -> BrokerIntentV1:
    unsigned = _unsigned(**changes)
    digest = hashlib.sha256(canonical_intent_payload(unsigned)).hexdigest()
    return dataclasses.replace(unsigned, digest=digest)


INTENT = _intent()
EXPECTED_UNSIGNED = (
    b'{"schema_version":1,"intent_generation":7,"operation":"provision",'
    b'"transaction_id":"22222222222222222222222222222222",'
    b'"request_id":"11111111111111111111111111111111","agent_id":"bee_1",'
    b'"manifest_generation":3,"unit_generation":9,"policy_generation":7,'
    b'"fencing_epoch":4,"store_uuid":"33333333333333333333333333333333",'
    b'"slot_id":"slot-01","mcs_pair":"c0,c1",'
    b'"projection_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    b'"joint_release_id":"release-0.11.0",'
    b'"server_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
    b'"broker_manifest_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",'
    b'"credential_binding_ref":"cred-bind-01","credential_generation":2,'
    b'"created_at_unix_ms":1700000000000,"expires_at_unix_ms":1700000030000,'
    b'"nonce":"dddddddddddddddddddddddddddddddd"}'
)


EXPECTED_DIGEST = "13b3cc7fc550c0f898577529c1242ed725688a6610ae04c330cd44fc179cfde3"
EXPECTED_BYTES = (
    EXPECTED_UNSIGNED[:-1] + b',"digest":"' + EXPECTED_DIGEST.encode() + b'"}' + b"\n"
)


def _document() -> dict[str, object]:
    return json.loads(encode_broker_intent(INTENT).decode("utf-8"))


def _document_bytes(document: object) -> bytes:
    return (
        json.dumps(
            document, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        + b"\n"
    )


def _assert_code(callable_object, code: BrokerIntentCode) -> None:
    with pytest.raises(BrokerIntentError) as caught:
        callable_object()
    assert caught.value.code is code
    assert str(caught.value) == code.value


def test_public_intent_contract_is_exact_frozen_and_slotted() -> None:
    assert dataclasses.is_dataclass(INTENT)
    assert BrokerIntentV1.__dataclass_params__.frozen
    assert hasattr(BrokerIntentV1, "__slots__")
    assert not hasattr(INTENT, "__dict__")
    assert (
        tuple(field.name for field in dataclasses.fields(BrokerIntentV1))
        == SCHEMA_FIELDS
    )
    assert tuple(operation.value for operation in BrokerIntentOperation) == (
        "provision",
        "replace",
        "deprovision",
    )
    with pytest.raises(FrozenInstanceError):
        INTENT.digest = "e" * 64


def test_public_error_surface_has_only_declared_names() -> None:
    assert tuple(BrokerIntentCode.__members__) == (
        "INVALID_TYPE",
        "INVALID_FIELD",
        "UNKNOWN_FIELD",
        "MISSING_FIELD",
        "DUPLICATE_KEY",
        "INVALID_UTF8",
        "INTENT_TOO_LARGE",
        "NON_CANONICAL",
        "DIGEST_MISMATCH",
        "EXPIRED",
        "INVERTED_TIMESTAMPS",
        "FORBIDDEN_VALUE",
    )
    assert not hasattr(intent_codec, "BrokerIntentValidationError")
    assert "BrokerIntentValidationError" not in intent_codec.__all__


def test_canonical_payload_has_declared_key_order_and_digest_preimage() -> None:
    assert canonical_intent_payload(INTENT) == EXPECTED_UNSIGNED
    assert hashlib.sha256(EXPECTED_UNSIGNED).hexdigest() == INTENT.digest
    assert tuple(json.loads(EXPECTED_UNSIGNED).keys()) == SCHEMA_FIELDS[:-1]


def test_encode_has_golden_bytes_and_decode_roundtrip() -> None:
    assert encode_broker_intent(INTENT) == EXPECTED_BYTES
    assert encode_broker_intent(INTENT).endswith(b"\n")
    assert decode_broker_intent(EXPECTED_BYTES, now_unix_ms=1_700_000_001_000) == INTENT
    assert (
        encode_broker_intent(
            decode_broker_intent(EXPECTED_BYTES, now_unix_ms=1_700_000_001_000)
        )
        == EXPECTED_BYTES
    )


@pytest.mark.parametrize(
    "raw",
    [
        EXPECTED_BYTES.replace(b",", b", ", 1),
        json.dumps(
            json.loads(EXPECTED_BYTES.decode("utf-8")),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n",
        EXPECTED_BYTES[:-1],
        EXPECTED_BYTES + b"\n",
    ],
)
def test_decoder_rejects_noncanonical_json_bytes(raw: bytes) -> None:
    _assert_code(
        lambda: decode_broker_intent(raw, now_unix_ms=1_700_000_001_000),
        BrokerIntentCode.NON_CANONICAL,
    )


def test_encoder_rejects_digest_forgery() -> None:
    _assert_code(
        lambda: encode_broker_intent(dataclasses.replace(INTENT, digest="e" * 64)),
        BrokerIntentCode.DIGEST_MISMATCH,
    )


def test_decoder_rejects_unknown_and_missing_fields_with_stable_codes() -> None:
    unknown = {**_document(), "untrusted": "value"}
    missing = {key: value for key, value in _document().items() if key != "nonce"}
    _assert_code(
        lambda: decode_broker_intent(
            _document_bytes(unknown), now_unix_ms=1_700_000_001_000
        ),
        BrokerIntentCode.UNKNOWN_FIELD,
    )
    _assert_code(
        lambda: decode_broker_intent(
            _document_bytes(missing), now_unix_ms=1_700_000_001_000
        ),
        BrokerIntentCode.MISSING_FIELD,
    )


def test_decoder_rejects_duplicate_fields_before_object_construction() -> None:
    duplicate = EXPECTED_BYTES.replace(
        b'"schema_version":1,', b'"schema_version":1,"schema_version":1,', 1
    )
    _assert_code(
        lambda: decode_broker_intent(duplicate, now_unix_ms=1_700_000_001_000),
        BrokerIntentCode.DUPLICATE_KEY,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 1.0),
        ("operation", "provision"),
        ("transaction_id", 2),
        ("agent_id", ["bee_1"]),
        ("manifest_generation", "3"),
        ("mcs_pair", {"value": "c0,c1"}),
        ("projection_digest", b"a" * 64),
        ("credential_binding_ref", None),
        ("created_at_unix_ms", 1_700_000_000_000.0),
        ("nonce", object()),
    ],
)
def test_constructor_rejects_wrong_nominal_types(field: str, value: object) -> None:
    _assert_code(lambda: _unsigned(**{field: value}), BrokerIntentCode.INVALID_TYPE)


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "intent_generation",
        "manifest_generation",
        "unit_generation",
        "policy_generation",
        "fencing_epoch",
        "credential_generation",
        "created_at_unix_ms",
        "expires_at_unix_ms",
    ],
)
def test_bool_is_not_accepted_as_an_integer(field: str) -> None:
    _assert_code(lambda: _unsigned(**{field: True}), BrokerIntentCode.INVALID_TYPE)


@pytest.mark.parametrize(
    "field",
    [
        "transaction_id",
        "request_id",
        "agent_id",
        "slot_id",
        "joint_release_id",
        "credential_binding_ref",
        "nonce",
    ],
)
def test_identifiers_are_ascii_and_not_unicode_coerced(field: str) -> None:
    _assert_code(lambda: _unsigned(**{field: "id-ä"}), BrokerIntentCode.INVALID_FIELD)


def test_decoder_rejects_json_nan_and_infinity() -> None:
    for marker in (b"NaN", b"Infinity", b"-Infinity"):
        raw = EXPECTED_BYTES.replace(
            b'"intent_generation":7', b'"intent_generation":' + marker, 1
        )
        _assert_code(
            lambda raw=raw: decode_broker_intent(raw, now_unix_ms=1_700_000_001_000),
            BrokerIntentCode.INVALID_FIELD,
        )


def test_decoder_rejects_oversize_before_decoding() -> None:
    _assert_code(
        lambda: decode_broker_intent(
            b"\xff" * (MAX_BROKER_INTENT_BYTES + 1), now_unix_ms=0
        ),
        BrokerIntentCode.INTENT_TOO_LARGE,
    )


def test_decoder_rejects_malformed_utf8_under_byte_bound() -> None:
    _assert_code(
        lambda: decode_broker_intent(b"{\xff}", now_unix_ms=0),
        BrokerIntentCode.INVALID_UTF8,
    )


def test_decoder_rejects_digest_forgery() -> None:
    forged = {**_document(), "digest": "e" * 64}
    _assert_code(
        lambda: decode_broker_intent(
            _document_bytes(forged), now_unix_ms=1_700_000_001_000
        ),
        BrokerIntentCode.DIGEST_MISMATCH,
    )


def test_decoder_rejects_expired_intents() -> None:
    _assert_code(
        lambda: decode_broker_intent(EXPECTED_BYTES, now_unix_ms=1_700_000_030_000),
        BrokerIntentCode.EXPIRED,
    )


def test_constructor_rejects_inverted_timestamps() -> None:
    _assert_code(
        lambda: _unsigned(expires_at_unix_ms=1_699_999_999_999),
        BrokerIntentCode.INVERTED_TIMESTAMPS,
    )


@pytest.mark.parametrize(
    "field",
    [
        "transaction_id",
        "request_id",
        "agent_id",
        "slot_id",
        "joint_release_id",
        "credential_binding_ref",
        "nonce",
    ],
)
@pytest.mark.parametrize(
    "forbidden", ["secret-value", "/absolute/path", "../../escape"]
)
def test_forbidden_secret_and_absolute_path_values_are_not_encoded(
    field: str, forbidden: str
) -> None:
    _assert_code(
        lambda: _unsigned(**{field: forbidden}), BrokerIntentCode.FORBIDDEN_VALUE
    )


@pytest.mark.parametrize(
    "forbidden", [3, lambda: None, types.ModuleType("untrusted"), pickle.dumps]
)
def test_fd_callable_module_and_pickle_values_are_not_encoded(
    forbidden: object,
) -> None:
    forged = object.__new__(BrokerIntentV1)
    for field, value in BASE_VALUES.items():
        object.__setattr__(forged, field, value)
    object.__setattr__(forged, "credential_binding_ref", forbidden)
    _assert_code(lambda: encode_broker_intent(forged), BrokerIntentCode.INVALID_TYPE)


def test_decoder_does_not_reconstruct_python_objects_from_json_values() -> None:
    document = {**_document(), "credential_binding_ref": {"__reduce__": "os.system"}}
    _assert_code(
        lambda: decode_broker_intent(
            _document_bytes(document), now_unix_ms=1_700_000_001_000
        ),
        BrokerIntentCode.INVALID_TYPE,
    )


def test_public_errors_redact_values_paths_and_secrets() -> None:
    canary = "secret-value-/absolute/path"
    with pytest.raises(BrokerIntentError) as caught:
        _unsigned(agent_id=canary)
    assert canary not in str(caught.value)
    assert "/absolute/path" not in str(caught.value)
