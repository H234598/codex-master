"""Synthetic D344 S1 contract tests for the private D73 ingress policy parser."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import json

import pytest

from the_hive import _d73_ingress_policy as ingress_policy


_SYNTHETIC_POLICY = {
    "account_name": "synthetic-control",
    "bus_name": "org.example.Control1",
    "expected_uid": 4242,
    "polkit_action": "org.example.d73.publish",
    "schema_version": 1,
    "selinux_context": "synthetic_u:synthetic_r:synthetic_t:s0",
}

# Hand-checked v1 oracle: these are synthetic test values, not host policy values.
_GOLDEN_BYTES = (
    b'{"account_name":"synthetic-control","bus_name":"org.example.Control1",'
    b'"expected_uid":4242,"polkit_action":"org.example.d73.publish",'
    b'"schema_version":1,"selinux_context":"synthetic_u:synthetic_r:synthetic_t:s0"}\n'
)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _with(**changes: object) -> bytes:
    value = dict(_SYNTHETIC_POLICY)
    value.update(changes)
    return _canonical(value)


def _without(field: str) -> bytes:
    value = dict(_SYNTHETIC_POLICY)
    del value[field]
    return _canonical(value)


def _error_code(raw: bytes) -> str:
    with pytest.raises(ingress_policy.D73IngressPolicyError) as caught:
        ingress_policy._decode_d73_ingress_policy_v1(raw)
    return caught.value.code


def test_decode_accepts_the_hand_checked_canonical_golden_bytes() -> None:
    policy = ingress_policy._decode_d73_ingress_policy_v1(_GOLDEN_BYTES)

    assert type(policy) is ingress_policy.D73IngressPolicyV1
    assert policy.account_name == "synthetic-control"
    assert policy.bus_name == "org.example.Control1"
    assert policy.expected_uid == 4242
    assert policy.polkit_action == "org.example.d73.publish"
    assert policy.schema_version == 1
    assert policy.selinux_context == "synthetic_u:synthetic_r:synthetic_t:s0"


def test_decode_returns_an_immutable_value() -> None:
    policy = ingress_policy._decode_d73_ingress_policy_v1(_GOLDEN_BYTES)

    with pytest.raises(FrozenInstanceError):
        policy.expected_uid = 7  # type: ignore[misc]


@pytest.mark.parametrize("expected_uid", (1, 4_294_967_295))
def test_decode_accepts_each_expected_uid_endpoint(expected_uid: int) -> None:
    policy = ingress_policy._decode_d73_ingress_policy_v1(
        _with(expected_uid=expected_uid)
    )

    assert policy.expected_uid == expected_uid


def test_decode_accepts_a_255_byte_account_name() -> None:
    account_name = "a" * 255

    policy = ingress_policy._decode_d73_ingress_policy_v1(
        _with(account_name=account_name)
    )

    assert policy.account_name == account_name


def test_decode_accepts_a_255_byte_bus_name() -> None:
    bus_name = "b" * 255

    policy = ingress_policy._decode_d73_ingress_policy_v1(_with(bus_name=bus_name))

    assert policy.bus_name == bus_name


def test_decode_accepts_a_255_byte_polkit_action() -> None:
    polkit_action = "p" * 255

    policy = ingress_policy._decode_d73_ingress_policy_v1(
        _with(polkit_action=polkit_action)
    )

    assert policy.polkit_action == polkit_action


def test_decode_accepts_a_4096_byte_selinux_context() -> None:
    selinux_context = "s" * 4096

    policy = ingress_policy._decode_d73_ingress_policy_v1(
        _with(selinux_context=selinux_context)
    )

    assert policy.selinux_context == selinux_context


@pytest.mark.parametrize(
    ("name", "raw", "code"),
    (
        ("missing-final-lf", _GOLDEN_BYTES[:-1], "D73_POLICY_E_TERMINATOR"),
        ("second-final-lf", _GOLDEN_BYTES + b"\n", "D73_POLICY_E_TERMINATOR"),
        ("bom", b"\xef\xbb\xbf" + _GOLDEN_BYTES, "D73_POLICY_E_ASCII"),
        (
            "nul",
            _GOLDEN_BYTES.replace(b"control", b"con\x00trol"),
            "D73_POLICY_E_ASCII",
        ),
        ("crlf", _GOLDEN_BYTES[:-1] + b"\r\n", "D73_POLICY_E_ASCII"),
        ("whitespace", b" " + _GOLDEN_BYTES, "D73_POLICY_E_ASCII"),
    ),
)
def test_decode_rejects_non_v1_raw_byte_framing(
    name: str, raw: bytes, code: str
) -> None:
    del name
    assert _error_code(raw) == code


@pytest.mark.parametrize(
    ("name", "raw", "code"),
    (
        ("malformed-json", b'{"account_name":}\n', "D73_POLICY_E_JSON"),
        (
            "duplicate",
            b'{"account_name":"synthetic-control","account_name":"other",'
            b'"bus_name":"org.example.Control1","expected_uid":4242,'
            b'"polkit_action":"org.example.d73.publish","schema_version":1,'
            b'"selinux_context":"synthetic_u:synthetic_r:synthetic_t:s0"}\n',
            "D73_POLICY_E_DUPLICATE",
        ),
        ("second-json-value", _GOLDEN_BYTES[:-1] + b"{}\n", "D73_POLICY_E_TRAILING"),
        ("top-level-array", b"[]\n", "D73_POLICY_E_TOPLEVEL"),
    ),
)
def test_decode_rejects_invalid_json_shapes_before_field_values(
    name: str, raw: bytes, code: str
) -> None:
    del name
    assert _error_code(raw) == code


def test_decode_checks_unknown_fields_before_missing_fields() -> None:
    assert _error_code(_canonical({"unknown": "x"})) == "D73_POLICY_E_UNKNOWN_FIELD"


@pytest.mark.parametrize(
    "field",
    (
        "account_name",
        "bus_name",
        "expected_uid",
        "polkit_action",
        "schema_version",
        "selinux_context",
    ),
)
def test_decode_rejects_each_missing_field(field: str) -> None:
    assert _error_code(_without(field)) == "D73_POLICY_E_MISSING_FIELD"


@pytest.mark.parametrize(
    ("raw", "code"),
    (
        (_with(schema_version=2), "D73_POLICY_E_VERSION"),
        (_with(schema_version=True), "D73_POLICY_E_VERSION"),
        (_with(expected_uid=0), "D73_POLICY_E_UID"),
        (_with(expected_uid=4_294_967_296), "D73_POLICY_E_UID"),
        (_with(expected_uid=True), "D73_POLICY_E_UID"),
    ),
)
def test_decode_enforces_version_and_uid_integer_contracts(
    raw: bytes, code: str
) -> None:
    assert _error_code(raw) == code


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("account_name", 7, "D73_POLICY_E_ACCOUNT"),
        ("account_name", "", "D73_POLICY_E_ACCOUNT"),
        ("account_name", "x" * 256, "D73_POLICY_E_ACCOUNT"),
        ("account_name", "bad\nvalue", "D73_POLICY_E_ACCOUNT"),
        ("bus_name", 7, "D73_POLICY_E_BUS"),
        ("bus_name", "", "D73_POLICY_E_BUS"),
        ("bus_name", "x" * 256, "D73_POLICY_E_BUS"),
        ("bus_name", "bad\nvalue", "D73_POLICY_E_BUS"),
        ("polkit_action", 7, "D73_POLICY_E_POLKIT"),
        ("polkit_action", "", "D73_POLICY_E_POLKIT"),
        ("polkit_action", "x" * 256, "D73_POLICY_E_POLKIT"),
        ("polkit_action", "bad\nvalue", "D73_POLICY_E_POLKIT"),
        ("selinux_context", 7, "D73_POLICY_E_SELINUX"),
        ("selinux_context", "", "D73_POLICY_E_SELINUX"),
        ("selinux_context", "x" * 4097, "D73_POLICY_E_SELINUX"),
        ("selinux_context", "bad\nvalue", "D73_POLICY_E_SELINUX"),
    ),
)
def test_decode_enforces_each_string_field_type_and_bound(
    field: str, value: object, code: str
) -> None:
    assert _error_code(_with(**{field: value})) == code


@pytest.mark.parametrize(
    "raw",
    (
        b'{"account_name":"\\u0073ynthetic-control",'
        b'"bus_name":"org.example.Control1","expected_uid":4242,'
        b'"polkit_action":"org.example.d73.publish","schema_version":1,'
        b'"selinux_context":"synthetic_u:synthetic_r:synthetic_t:s0"}\n',
        b'{"schema_version":1,"account_name":"synthetic-control",'
        b'"bus_name":"org.example.Control1","expected_uid":4242,'
        b'"polkit_action":"org.example.d73.publish",'
        b'"selinux_context":"synthetic_u:synthetic_r:synthetic_t:s0"}\n',
    ),
)
def test_decode_rejects_bytes_that_parse_but_are_not_canonical(raw: bytes) -> None:
    assert _error_code(raw) == "D73_POLICY_E_CANONICAL"
