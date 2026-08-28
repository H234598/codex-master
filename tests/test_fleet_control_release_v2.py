from __future__ import annotations

import ast
import copy
from dataclasses import FrozenInstanceError, fields, is_dataclass
import hashlib
import json
from pathlib import Path
import pickle

import pytest

from codex_master.fleet_control_release_v2 import (
    ControlReleaseSpecV2,
    ReleasePayloadDigestV2,
    decode_control_release_v2,
    encode_control_release_v2,
)


ROLES = (
    "python_runtime",
    "root_helpers",
    "selinux_policy",
    "systemd_units",
)
ABI = {
    "broker_protocol": "CHPB/2",
    "system_bus_interface": "org.codex_master.HomeBrokerControl2",
    "system_bus_method": "StartDynamicTeamlead",
    "agent_unit_template": "codex-master-agent@.service",
    "launcher_path": "/usr/libexec/codex-master-agent-launcher",
}
FIXTURES = {
    role: f"{role}-bundle\n".encode("ascii") for role in ROLES
}


def _payloads(fixtures: dict[str, bytes] = FIXTURES):
    return tuple(
        ReleasePayloadDigestV2(role, hashlib.sha256(fixtures[role]).hexdigest())
        for role in ROLES
    )


def _spec(fixtures: dict[str, bytes] = FIXTURES, **changes):
    values = {
        "schema_version": 2,
        "payload_version": "0.10.5",
        "payloads": _payloads(fixtures),
        **ABI,
    }
    values.update(changes)
    return ControlReleaseSpecV2(**values)


SPEC = _spec()
GOLDEN_BYTES = (
    b'{"schema_version":2,"payload_version":"0.10.5","payloads":'
    b'[{"role":"python_runtime","sha256":"'
    + hashlib.sha256(FIXTURES["python_runtime"]).hexdigest().encode("ascii")
    + b'"},{"role":"root_helpers","sha256":"'
    + hashlib.sha256(FIXTURES["root_helpers"]).hexdigest().encode("ascii")
    + b'"},{"role":"selinux_policy","sha256":"'
    + hashlib.sha256(FIXTURES["selinux_policy"]).hexdigest().encode("ascii")
    + b'"},{"role":"systemd_units","sha256":"'
    + hashlib.sha256(FIXTURES["systemd_units"]).hexdigest().encode("ascii")
    + b'"}],"broker_protocol":"CHPB/2",'
    b'"system_bus_interface":"org.codex_master.HomeBrokerControl2",'
    b'"system_bus_method":"StartDynamicTeamlead",'
    b'"agent_unit_template":"codex-master-agent@.service",'
    b'"launcher_path":"/usr/libexec/codex-master-agent-launcher"}\n'
)


def _document() -> dict[str, object]:
    return json.loads(GOLDEN_BYTES.decode("utf-8"))


def _document_bytes(document: dict[str, object]) -> bytes:
    return json.dumps(
        document, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8") + b"\n"


def test_public_models_are_exact_frozen_slots_and_have_fixed_fields() -> None:
    assert is_dataclass(ReleasePayloadDigestV2)
    assert is_dataclass(ControlReleaseSpecV2)
    assert getattr(ReleasePayloadDigestV2, "__dataclass_params__").frozen
    assert getattr(ControlReleaseSpecV2, "__dataclass_params__").frozen
    assert hasattr(ReleasePayloadDigestV2, "__slots__")
    assert hasattr(ControlReleaseSpecV2, "__slots__")
    assert not hasattr(SPEC, "__dict__")
    assert not hasattr(SPEC.payloads[0], "__dict__")
    assert tuple(field.name for field in fields(ControlReleaseSpecV2)) == (
        "schema_version",
        "payload_version",
        "payloads",
        "broker_protocol",
        "system_bus_interface",
        "system_bus_method",
        "agent_unit_template",
        "launcher_path",
    )
    assert tuple(item.role for item in SPEC.payloads) == ROLES
    assert not hasattr(SPEC, "selinux_policy_sha256")

    with pytest.raises(FrozenInstanceError):
        SPEC.schema_version = 3
    with pytest.raises(FrozenInstanceError):
        SPEC.payloads[0].sha256 = "a" * 64
    with pytest.raises(AttributeError):
        SPEC.payloads.append(SPEC.payloads[0])


@pytest.mark.parametrize(
    ("role", "digest"),
    [
        (None, "a" * 64),
        (1, "a" * 64),
        ("unknown", "a" * 64),
        ("python_runtime", None),
        ("python_runtime", b"a" * 64),
        ("python_runtime", "A" * 64),
        ("python_runtime", "a" * 63),
        ("python_runtime", "a" * 65),
        ("python_runtime", "g" * 64),
    ],
)
def test_payload_digest_rejects_wrong_exact_types_roles_and_sha256(
    role: object, digest: object
) -> None:
    with pytest.raises(ValueError):
        ReleasePayloadDigestV2(role, digest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("schema_version", 2.0),
        ("schema_version", "2"),
        ("payload_version", None),
        ("payload_version", []),
        ("payload_version", ""),
        ("payload_version", " 0.10.5"),
        ("broker_protocol", None),
        ("broker_protocol", []),
        ("system_bus_interface", None),
        ("system_bus_interface", {}),
        ("system_bus_method", None),
        ("system_bus_method", 1),
        ("agent_unit_template", None),
        ("agent_unit_template", ("codex-master-agent@.service",)),
        ("launcher_path", None),
        ("launcher_path", {"path": "/usr/libexec/codex-master-agent-launcher"}),
    ],
)
def test_spec_rejects_wrong_exact_types_and_abi_values(field: str, value: object) -> None:
    values = {
        "schema_version": 2,
        "payload_version": "0.10.5",
        "payloads": _payloads(),
        **ABI,
    }
    values[field] = value
    with pytest.raises(ValueError):
        ControlReleaseSpecV2(**values)


@pytest.mark.parametrize("payloads", [list(_payloads()), {"payloads": _payloads()}, "payloads", iter(_payloads())])
def test_spec_rejects_collection_substitutes(payloads: object) -> None:
    with pytest.raises(ValueError):
        _spec(payloads=payloads)


@pytest.mark.parametrize(
    "payloads",
    [
        (),
        (ReleasePayloadDigestV2("python_runtime", "a" * 64),),
        (
            ReleasePayloadDigestV2("python_runtime", "a" * 64),
            ReleasePayloadDigestV2("python_runtime", "b" * 64),
            ReleasePayloadDigestV2("selinux_policy", "c" * 64),
            ReleasePayloadDigestV2("systemd_units", "d" * 64),
        ),
        tuple(reversed(_payloads())),
        (object(), object(), object(), object()),
    ],
)
def test_spec_rejects_wrong_payload_entries_roles_and_order(payloads: object) -> None:
    with pytest.raises(ValueError):
        _spec(payloads=payloads)


def test_encode_is_canonical_and_decoder_round_trips_only_that_bytes_form() -> None:
    assert encode_control_release_v2(SPEC) == GOLDEN_BYTES
    assert encode_control_release_v2(SPEC).endswith(b"\n")
    assert not encode_control_release_v2(SPEC)[:-1].endswith(b"\n")
    decoded = decode_control_release_v2(GOLDEN_BYTES, "0.10.5")
    assert decoded == SPEC
    assert encode_control_release_v2(decoded) == GOLDEN_BYTES


@pytest.mark.parametrize("raw", [GOLDEN_BYTES[:-1], GOLDEN_BYTES + b"\n"])
def test_decoder_rejects_wrong_trailing_linefeed(raw: bytes) -> None:
    with pytest.raises(ValueError):
        decode_control_release_v2(raw, expected_payload_version="0.10.5")


@pytest.mark.parametrize("raw", ["bytes", bytearray(GOLDEN_BYTES), memoryview(GOLDEN_BYTES), None])
def test_decoder_requires_exact_bytes_input(raw: object) -> None:
    with pytest.raises(ValueError):
        decode_control_release_v2(raw, expected_payload_version="0.10.5")


@pytest.mark.parametrize(
    "raw",
    [
        GOLDEN_BYTES.replace(b",", b", ", 1),
        json.dumps(
            json.loads(GOLDEN_BYTES.decode("utf-8")),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n",
        GOLDEN_BYTES.replace(b'"schema_version":2', b'"schema_version":2.0', 1),
        GOLDEN_BYTES.replace(
            b'"role":"python_runtime"', b'"role": "python_runtime"', 1
        ),
    ],
)
def test_decoder_rejects_noncanonical_json_bytes(raw: bytes) -> None:
    with pytest.raises(ValueError):
        decode_control_release_v2(raw, expected_payload_version="0.10.5")


@pytest.mark.parametrize(
    "raw",
    [
        b"{\xff}\n",
        GOLDEN_BYTES.replace(b'"payload_version":"0.10.5"', b'"payload_version":NaN', 1),
        GOLDEN_BYTES.replace(b'"payload_version":"0.10.5"', b'"payload_version":Infinity', 1),
        GOLDEN_BYTES.replace(
            b'"schema_version":2,', b'"schema_version":2,"schema_version":2,', 1
        ),
        GOLDEN_BYTES.replace(
            b'"role":"python_runtime",',
            b'"role":"python_runtime","role":"python_runtime",',
            1,
        ),
    ],
)
def test_decoder_rejects_invalid_utf8_constants_and_duplicate_keys(raw: bytes) -> None:
    with pytest.raises(ValueError):
        decode_control_release_v2(raw, expected_payload_version="0.10.5")


@pytest.mark.parametrize(
    "document",
    [
        {**_document(), "unknown": 1},
        {key: value for key, value in _document().items() if key != "payloads"},
        {**_document(), "selinux_policy_sha256": "a" * 64},
        {**_document(), "schema_version": True},
        {**_document(), "schema_version": 1},
        {**_document(), "payload_version": "0.10.4"},
        {**_document(), "payload_version": []},
        {**_document(), "broker_protocol": "CHPB/1"},
        {**_document(), "system_bus_interface": "wrong"},
        {**_document(), "system_bus_method": "wrong"},
        {**_document(), "agent_unit_template": "wrong"},
        {**_document(), "launcher_path": "wrong"},
        {**_document(), "payloads": {}},
        {**_document(), "payloads": "payloads"},
        {
            **_document(),
            "payloads": _document()["payloads"][:-1],
        },
        {
            **_document(),
            "payloads": list(reversed(_document()["payloads"])),
        },
        {
            **_document(),
            "payloads": [
                *_document()["payloads"],
                {"role": "extra", "sha256": "a" * 64},
            ],
        },
        {
            **_document(),
            "payloads": [
                {**_document()["payloads"][0], "sha256": "A" * 64},
                *_document()["payloads"][1:],
            ],
        },
        {
            **_document(),
            "payloads": [
                {**_document()["payloads"][0], "extra": 1},
                *_document()["payloads"][1:],
            ],
        },
        {
            **_document(),
            "payloads": [
                {"sha256": _document()["payloads"][0]["sha256"]},
                *_document()["payloads"][1:],
            ],
        },
    ],
)
def test_decoder_rejects_schema_abi_version_role_and_field_drift(
    document: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        decode_control_release_v2(
            _document_bytes(document), expected_payload_version="0.10.5"
        )


def test_decoder_requires_caller_payload_version_and_rejects_v1_bytes() -> None:
    with pytest.raises(ValueError):
        decode_control_release_v2(GOLDEN_BYTES, expected_payload_version=True)
    with pytest.raises(ValueError):
        decode_control_release_v2(GOLDEN_BYTES, expected_payload_version="0.10.4")
    v1 = (
        b'{"format":"codex-master-home-broker-manifest-v1",'
        b'"payload_version":"0.10.5","payload_entries":[]}\n'
    )
    with pytest.raises(ValueError):
        decode_control_release_v2(v1, expected_payload_version="0.10.5")


def test_encoder_rejects_non_spec_values() -> None:
    for value in ({}, [], "spec", iter(()), object()):
        with pytest.raises(ValueError):
            encode_control_release_v2(value)


def test_copy_deepcopy_pickle_and_mutation_cannot_change_immutable_graph() -> None:
    clones = (copy.copy(SPEC), copy.deepcopy(SPEC), pickle.loads(pickle.dumps(SPEC)))
    for clone in clones:
        assert clone == SPEC
        assert type(clone.payloads) is tuple
        assert all(type(item) is ReleasePayloadDigestV2 for item in clone.payloads)
        assert hash(clone) == hash(SPEC)

    with pytest.raises(FrozenInstanceError):
        clones[0].payload_version = "0.10.6"
    with pytest.raises(FrozenInstanceError):
        clones[0].payloads[0].role = "root_helpers"


def test_in_memory_bundle_bytes_drive_deterministic_selected_role_digest_and_spec() -> None:
    same = _spec()
    assert same == _spec()
    assert encode_control_release_v2(same) == encode_control_release_v2(SPEC)

    changed_fixtures = dict(FIXTURES)
    changed_fixtures["selinux_policy"] += b"x"
    changed = _spec(changed_fixtures)
    assert changed.payloads[2].sha256 != SPEC.payloads[2].sha256
    assert tuple(item.sha256 for item in changed.payloads[:2] + changed.payloads[3:]) == tuple(
        item.sha256 for item in SPEC.payloads[:2] + SPEC.payloads[3:]
    )
    assert encode_control_release_v2(changed) != GOLDEN_BYTES


def test_project_version_is_test_only_build_input() -> None:
    import tomllib

    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    assert document["project"]["version"] == "0.10.5"
    assert _spec(payload_version=document["project"]["version"]).payload_version == "0.10.5"


def test_production_module_imports_only_pure_stdlib_and_has_no_io_surface() -> None:
    module_path = Path(__import__("codex_master.fleet_control_release_v2").fleet_control_release_v2.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    } | {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imported <= {"__future__", "dataclasses", "json"}
    forbidden_calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert forbidden_calls.isdisjoint(
        {"open", "read", "write", "read_bytes", "read_text", "Path", "connect"}
    )
