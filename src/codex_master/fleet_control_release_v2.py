"""Pure immutable schema and canonical codec for control release V2."""

from __future__ import annotations

from dataclasses import dataclass
import json


_SCHEMA_VERSION = 2
_BROKER_PROTOCOL = "CHPB/2"
_SYSTEM_BUS_INTERFACE = "org.codex_master.HomeBrokerControl2"
_SYSTEM_BUS_METHOD = "StartDynamicTeamlead"
_AGENT_UNIT_TEMPLATE = "codex-master-agent@.service"
_LAUNCHER_PATH = "/usr/libexec/codex-master-agent-launcher"
_PAYLOAD_ROLES = (
    "python_runtime",
    "root_helpers",
    "selinux_policy",
    "systemd_units",
)
_TOP_LEVEL_KEYS = (
    "schema_version",
    "payload_version",
    "payloads",
    "broker_protocol",
    "system_bus_interface",
    "system_bus_method",
    "agent_unit_template",
    "launcher_path",
)
_PAYLOAD_KEYS = ("role", "sha256")
_SHA256_HEX = frozenset("0123456789abcdef")


class ControlReleaseV2Error(ValueError):
    """Raised when a V2 release value or byte representation is invalid."""

    __slots__ = ()


def _invalid() -> None:
    raise ControlReleaseV2Error("invalid_control_release_v2") from None


def _validate_utf8_text(value: object, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value) or value != value.strip():
        _invalid()
    if any(ord(character) < 32 for character in value):
        _invalid()
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _invalid()
    return value


def _validate_role(value: object) -> str:
    if type(value) is not str or value not in _PAYLOAD_ROLES:
        _invalid()
    return value


def _validate_sha256(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _SHA256_HEX for character in value)
    ):
        _invalid()
    return value


@dataclass(frozen=True, slots=True)
class ReleasePayloadDigestV2:
    role: str
    sha256: str

    def __post_init__(self) -> None:
        _validate_role(self.role)
        _validate_sha256(self.sha256)


def _validate_payloads(value: object) -> tuple[ReleasePayloadDigestV2, ...]:
    if type(value) is not tuple or len(value) != len(_PAYLOAD_ROLES):
        _invalid()
    if any(type(item) is not ReleasePayloadDigestV2 for item in value):
        _invalid()
    roles = tuple(item.role for item in value)
    if roles != _PAYLOAD_ROLES:
        _invalid()
    return value


def _validate_fixed_text(value: object, expected: str) -> str:
    if type(value) is not str or value != expected:
        _invalid()
    return value


@dataclass(frozen=True, slots=True)
class ControlReleaseSpecV2:
    schema_version: int
    payload_version: str
    payloads: tuple[ReleasePayloadDigestV2, ...]
    broker_protocol: str
    system_bus_interface: str
    system_bus_method: str
    agent_unit_template: str
    launcher_path: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != _SCHEMA_VERSION:
            _invalid()
        _validate_utf8_text(self.payload_version)
        _validate_payloads(self.payloads)
        _validate_fixed_text(self.broker_protocol, _BROKER_PROTOCOL)
        _validate_fixed_text(self.system_bus_interface, _SYSTEM_BUS_INTERFACE)
        _validate_fixed_text(self.system_bus_method, _SYSTEM_BUS_METHOD)
        _validate_fixed_text(self.agent_unit_template, _AGENT_UNIT_TEMPLATE)
        _validate_fixed_text(self.launcher_path, _LAUNCHER_PATH)


def _canonical_document(spec: ControlReleaseSpecV2) -> dict[str, object]:
    if type(spec) is not ControlReleaseSpecV2:
        _invalid()
    return {
        "schema_version": spec.schema_version,
        "payload_version": spec.payload_version,
        "payloads": [
            {"role": payload.role, "sha256": payload.sha256}
            for payload in spec.payloads
        ],
        "broker_protocol": spec.broker_protocol,
        "system_bus_interface": spec.system_bus_interface,
        "system_bus_method": spec.system_bus_method,
        "agent_unit_template": spec.agent_unit_template,
        "launcher_path": spec.launcher_path,
    }


def encode_control_release_v2(spec: ControlReleaseSpecV2) -> bytes:
    """Encode one validated release spec into its canonical JSON bytes."""

    document = _canonical_document(spec)
    try:
        encoded = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        return encoded.encode("utf-8") + b"\n"
    except ControlReleaseV2Error:
        raise
    except Exception:
        _invalid()


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            _invalid()
        document[key] = value
    return document


def _reject_constant(_: str) -> None:
    _invalid()


def decode_control_release_v2(
    raw: bytes, expected_payload_version: str
) -> ControlReleaseSpecV2:
    """Decode only canonical V2 JSON bytes for caller-provided version."""

    try:
        if type(raw) is not bytes:
            _invalid()
        _validate_utf8_text(expected_payload_version)
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_constant,
        )
        if type(document) is not dict or set(document) != set(_TOP_LEVEL_KEYS):
            _invalid()
        if document["payload_version"] != expected_payload_version:
            _invalid()
        raw_payloads = document["payloads"]
        if type(raw_payloads) is not list:
            _invalid()
        payloads = []
        for raw_payload in raw_payloads:
            if type(raw_payload) is not dict or set(raw_payload) != set(_PAYLOAD_KEYS):
                _invalid()
            payloads.append(
                ReleasePayloadDigestV2(raw_payload["role"], raw_payload["sha256"])
            )
        spec = ControlReleaseSpecV2(
            document["schema_version"],
            document["payload_version"],
            tuple(payloads),
            document["broker_protocol"],
            document["system_bus_interface"],
            document["system_bus_method"],
            document["agent_unit_template"],
            document["launcher_path"],
        )
        if encode_control_release_v2(spec) != raw:
            _invalid()
        return spec
    except ControlReleaseV2Error:
        raise
    except Exception:
        _invalid()


__all__ = [
    "ControlReleaseSpecV2",
    "ControlReleaseV2Error",
    "ReleasePayloadDigestV2",
    "decode_control_release_v2",
    "encode_control_release_v2",
]
