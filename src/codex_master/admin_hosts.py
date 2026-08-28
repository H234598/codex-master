"""Private, durable registry for Masterjet control and execution hosts."""

from __future__ import annotations

import builtins
from collections.abc import Mapping, Sequence
import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import ipaddress
import json
import math
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType
from typing import Any, Never

from codex_master.admin_contracts import (
    AdminContractError,
    public_admin_ref,
    public_admin_text,
)
from codex_master.hive.state import HiveStateError, HiveStateStore


MAX_HOST_RECORDS = 256
MAX_HOST_STATE_BYTES = 2 * 1024 * 1024

_DOCUMENT = PurePosixPath("hosts.json")
_SCHEMA_VERSION = 2
_MAX_GENERATION = 2**63 - 1
_MAX_COLLECTION_ITEMS = 64
_MAX_PRIVATE_TEXT_BYTES = 4096
_MAX_NESTING = 6
_ROLES = frozenset({"control", "execution"})
_REACHABILITY_STATES = frozenset({"reachable", "unreachable", "unknown"})
_EVIDENCE_FIELDS = frozenset(
    {
        "label",
        "role",
        "transport_binding",
        "capabilities",
        "reachability",
        "resource_evidence",
        "observed_at",
        "source",
        "binding_state",
    }
)
_HOST_FIELDS = frozenset(
    {
        "ref",
        "label",
        "role",
        "transport_binding",
        "capabilities",
        "reachability",
        "resource_evidence",
        "generation",
        "observed_at",
        "source",
        "probe_digest",
    }
)
_BINDING_FIELDS = frozenset({"ref", "binding_state"})
_SENSITIVE_PUBLIC_KEY = re.compile(
    r"(?:^|[_.-])(?:credential|secret|token|password|passphrase|endpoint|"
    r"root|path|socket|address|url|uri|host)(?:$|[_.-])",
    re.IGNORECASE,
)


class HostRegistryError(ValueError):
    """Stable, path-free host-registry error."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class ControlHostV1:
    ref: str
    label: str
    role: str
    transport_binding: Mapping[str, object]
    capabilities: tuple[str, ...]
    reachability: Mapping[str, object]
    resource_evidence: Mapping[str, object]
    generation: int
    observed_at: datetime
    source: str

    def __post_init__(self) -> None:
        error_code = "control.host_invalid"
        object.__setattr__(self, "ref", _public_ref(self.ref, error_code))
        object.__setattr__(self, "label", _public_text(self.label, error_code))
        if type(self.role) is not str or self.role not in _ROLES:
            raise HostRegistryError(error_code)
        transport = _public_mapping(self.transport_binding, error_code)
        if "kind" not in transport:
            raise HostRegistryError(error_code)
        _public_ref(transport["kind"], error_code)
        object.__setattr__(self, "transport_binding", _freeze_mapping(transport))
        object.__setattr__(
            self, "capabilities", _capabilities(self.capabilities, error_code)
        )
        reachability = _public_mapping(self.reachability, error_code)
        if reachability.get("state") not in _REACHABILITY_STATES:
            raise HostRegistryError(error_code)
        latency = reachability.get("latency_ms")
        if latency is not None and (type(latency) is not int or latency < 0):
            raise HostRegistryError(error_code)
        object.__setattr__(self, "reachability", _freeze_mapping(reachability))
        resources = _public_mapping(self.resource_evidence, error_code)
        if not resources:
            raise HostRegistryError(error_code)
        object.__setattr__(self, "resource_evidence", _freeze_mapping(resources))
        object.__setattr__(self, "generation", _generation(self.generation, error_code))
        object.__setattr__(self, "observed_at", _utc_time(self.observed_at, error_code))
        object.__setattr__(self, "source", _public_ref(self.source, error_code))

    def __repr__(self) -> str:
        return (
            f"ControlHostV1(ref={self.ref!r}, role={self.role!r}, "
            f"generation={self.generation!r})"
        )

    def public_projection(self) -> dict[str, object]:
        """Return the complete public host view without private binding state."""

        return {
            "schema_version": 1,
            "ref": self.ref,
            "label": self.label,
            "role": self.role,
            "transport_binding": _thaw(self.transport_binding),
            "capabilities": list(self.capabilities),
            "reachability": _thaw(self.reachability),
            "resource_evidence": _thaw(self.resource_evidence),
            "generation": self.generation,
            "observed_at": _wire_time(self.observed_at),
            "source": self.source,
        }


class HostRegistry:
    """One bounded host document guarded by Hive's durable CAS lock."""

    def __init__(self, state_root: Path) -> None:
        if not isinstance(state_root, Path) or not state_root.is_absolute():
            raise HostRegistryError("control.host_store_unavailable")
        self._root = state_root / "admin-hosts"
        try:
            self._state = HiveStateStore(self._root)
            with self._state.locked():
                hosts, bindings, migrated = self._read_locked()
                if migrated:
                    self._write_locked(hosts, bindings)
        except HostRegistryError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError):
            raise HostRegistryError("control.host_store_unavailable") from None

    @classmethod
    def for_test(cls, state_root: Path) -> HostRegistry:
        return cls(state_root)

    def list(self) -> tuple[ControlHostV1, ...]:
        with self._locked_state() as (hosts, _bindings):
            return tuple(self._host(record) for record in hosts)

    def get(self, ref: str) -> ControlHostV1:
        ref = _public_ref(ref, "control.host_invalid")
        with self._locked_state() as (hosts, _bindings):
            for record in hosts:
                if record["ref"] == ref:
                    return self._host(record)
        raise HostRegistryError("control.host_not_found")

    def record_probe(
        self,
        ref: str,
        *,
        generation: int,
        evidence: Mapping[str, object],
    ) -> ControlHostV1:
        ref = _public_ref(ref, "control.host_invalid")
        generation = _generation(generation, "control.host_invalid")
        record, binding = self._probe_record(
            ref,
            generation,
            evidence,
            error_code="control.host_invalid",
        )
        with self._locked_state() as (hosts, bindings):
            existing = next((item for item in hosts if item["ref"] == ref), None)
            if existing is not None:
                current_generation = int(existing["generation"])
                if generation < current_generation or (
                    generation == current_generation
                    and record["probe_digest"] != existing["probe_digest"]
                ):
                    raise HostRegistryError("credential.generation_conflict")
                if generation == current_generation:
                    return self._host(existing)
                hosts.remove(existing)
            hosts.append(record)
            bindings[ref] = binding
            hosts.sort(key=lambda item: str(item["ref"]))
            self._write_locked(hosts, bindings)
            return self._host(record)

    @contextlib.contextmanager
    def _locked_state(self) -> Any:
        try:
            with self._state.locked():
                hosts, bindings, migrated = self._read_locked()
                if migrated:
                    self._write_locked(hosts, bindings)
                yield hosts, bindings
        except HostRegistryError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError, RecursionError):
            raise HostRegistryError("control.host_store_unavailable") from None

    def _read_locked(
        self,
    ) -> tuple[builtins.list[dict[str, object]], dict[str, dict[str, object]], bool]:
        try:
            raw = self._state.read_private_bytes(
                _DOCUMENT, max_bytes=MAX_HOST_STATE_BYTES
            )
        except HiveStateError as exc:
            if exc.args == ("state_not_found",):
                return [], {}, False
            raise HostRegistryError("control.host_store_unavailable") from None
        try:
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            HostRegistryError,
        ):
            raise HostRegistryError("control.host_store_unavailable") from None
        if not isinstance(document, Mapping):
            raise HostRegistryError("control.host_store_unavailable")
        version = document.get("schema_version")
        if version == 1:
            return self._read_legacy(document)
        if version != _SCHEMA_VERSION or set(document) != {
            "schema_version",
            "hosts",
            "bindings",
        }:
            raise HostRegistryError("control.host_store_unavailable")
        raw_hosts = document.get("hosts")
        raw_bindings = document.get("bindings")
        if (
            type(raw_hosts) is not list
            or type(raw_bindings) is not list
            or len(raw_hosts) > MAX_HOST_RECORDS
            or len(raw_hosts) != len(raw_bindings)
        ):
            raise HostRegistryError("control.host_store_unavailable")
        bindings: dict[str, dict[str, object]] = {}
        for item in raw_bindings:
            if not isinstance(item, Mapping) or set(item) != _BINDING_FIELDS:
                raise HostRegistryError("control.host_store_unavailable")
            ref = _public_ref(item["ref"], "control.host_store_unavailable")
            if ref in bindings:
                raise HostRegistryError("control.host_store_unavailable")
            bindings[ref] = _private_mapping(
                item["binding_state"], "control.host_store_unavailable"
            )
        hosts: list[dict[str, object]] = []
        seen: set[str] = set()
        for item in raw_hosts:
            if not isinstance(item, Mapping) or set(item) != _HOST_FIELDS:
                raise HostRegistryError("control.host_store_unavailable")
            ref = _public_ref(item["ref"], "control.host_store_unavailable")
            if ref in seen or ref not in bindings:
                raise HostRegistryError("control.host_store_unavailable")
            evidence = {
                key: item[key] for key in _EVIDENCE_FIELDS if key != "binding_state"
            }
            evidence["binding_state"] = bindings[ref]
            record, normalized_binding = self._probe_record(
                ref,
                item["generation"],
                evidence,
                error_code="control.host_store_unavailable",
            )
            if item["probe_digest"] != record["probe_digest"]:
                raise HostRegistryError("control.host_store_unavailable")
            hosts.append(record)
            bindings[ref] = normalized_binding
            seen.add(ref)
        if seen != set(bindings):
            raise HostRegistryError("control.host_store_unavailable")
        hosts.sort(key=lambda item: str(item["ref"]))
        return hosts, bindings, False

    def _read_legacy(
        self, document: Mapping[str, object]
    ) -> tuple[builtins.list[dict[str, object]], dict[str, dict[str, object]], bool]:
        if set(document) != {"schema_version", "hosts"}:
            raise HostRegistryError("control.host_store_unavailable")
        raw_hosts = document.get("hosts")
        if type(raw_hosts) is not list or len(raw_hosts) > MAX_HOST_RECORDS:
            raise HostRegistryError("control.host_store_unavailable")
        expected = _EVIDENCE_FIELDS | {"ref", "generation"}
        hosts: list[dict[str, object]] = []
        bindings: dict[str, dict[str, object]] = {}
        for item in raw_hosts:
            if not isinstance(item, Mapping) or set(item) != expected:
                raise HostRegistryError("control.host_store_unavailable")
            ref = _public_ref(item["ref"], "control.host_store_unavailable")
            if ref in bindings:
                raise HostRegistryError("control.host_store_unavailable")
            record, binding = self._probe_record(
                ref,
                item["generation"],
                {key: item[key] for key in _EVIDENCE_FIELDS},
                error_code="control.host_store_unavailable",
            )
            hosts.append(record)
            bindings[ref] = binding
        hosts.sort(key=lambda item: str(item["ref"]))
        return hosts, bindings, True

    @staticmethod
    def _probe_record(
        ref: str,
        generation: object,
        evidence: Mapping[str, object],
        *,
        error_code: str,
    ) -> tuple[dict[str, object], dict[str, object]]:
        generation = _generation(generation, error_code)
        if not isinstance(evidence, Mapping) or set(evidence) != _EVIDENCE_FIELDS:
            raise HostRegistryError(error_code)
        label = _public_text(evidence["label"], error_code)
        role = evidence["role"]
        if type(role) is not str or role not in _ROLES:
            raise HostRegistryError(error_code)
        transport = _public_mapping(evidence["transport_binding"], error_code)
        if "kind" not in transport:
            raise HostRegistryError(error_code)
        _public_ref(transport["kind"], error_code)
        capabilities = _capabilities(evidence["capabilities"], error_code)
        reachability = _public_mapping(evidence["reachability"], error_code)
        if reachability.get("state") not in _REACHABILITY_STATES:
            raise HostRegistryError(error_code)
        latency = reachability.get("latency_ms")
        if latency is not None and (type(latency) is not int or latency < 0):
            raise HostRegistryError(error_code)
        resources = _public_mapping(evidence["resource_evidence"], error_code)
        if not resources:
            raise HostRegistryError(error_code)
        observed = _parse_time(evidence["observed_at"], error_code)
        source = _public_ref(evidence["source"], error_code)
        binding = _private_mapping(evidence["binding_state"], error_code)
        if not binding:
            raise HostRegistryError(error_code)
        record: dict[str, object] = {
            "ref": ref,
            "label": label,
            "role": role,
            "transport_binding": transport,
            "capabilities": list(capabilities),
            "reachability": reachability,
            "resource_evidence": resources,
            "generation": generation,
            "observed_at": _wire_time(observed),
            "source": source,
        }
        digest_payload = {**record, "binding_state": binding}
        record["probe_digest"] = _digest(digest_payload)
        return record, binding

    def _write_locked(
        self,
        hosts: builtins.list[dict[str, object]],
        bindings: Mapping[str, dict[str, object]],
    ) -> None:
        if len(hosts) > MAX_HOST_RECORDS or len(hosts) != len(bindings):
            raise HostRegistryError("control.host_store_unavailable")
        document = {
            "schema_version": _SCHEMA_VERSION,
            "hosts": hosts,
            "bindings": [
                {"ref": ref, "binding_state": bindings[ref]} for ref in sorted(bindings)
            ],
        }
        try:
            raw = _encode(document)
            if len(raw) > MAX_HOST_STATE_BYTES:
                raise HostRegistryError("control.host_store_unavailable")
            self._state.replace_private_bytes(_DOCUMENT, raw)
        except HostRegistryError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError, RecursionError):
            raise HostRegistryError("control.host_store_unavailable") from None

    @staticmethod
    def _host(record: Mapping[str, object]) -> ControlHostV1:
        return ControlHostV1(
            ref=str(record["ref"]),
            label=str(record["label"]),
            role=str(record["role"]),
            transport_binding=_freeze_mapping(record["transport_binding"]),
            capabilities=_capabilities(
                record["capabilities"], "control.host_store_unavailable"
            ),
            reachability=_freeze_mapping(record["reachability"]),
            resource_evidence=_freeze_mapping(record["resource_evidence"]),
            generation=_generation(
                record["generation"], "control.host_store_unavailable"
            ),
            observed_at=_parse_time(
                record["observed_at"], "control.host_store_unavailable"
            ),
            source=str(record["source"]),
        )


def _raise(code: str) -> Never:
    raise HostRegistryError(code)


def _public_text(value: object, error_code: str) -> str:
    try:
        return public_admin_text(value)
    except AdminContractError:
        _raise(error_code)


def _public_ref(value: object, error_code: str) -> str:
    try:
        return public_admin_ref(value)
    except AdminContractError:
        _raise(error_code)


def _generation(value: object, error_code: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_GENERATION:
        _raise(error_code)
    return value


def _parse_time(value: object, error_code: str) -> datetime:
    if type(value) is not str or not value.endswith("Z") or len(value) > 40:
        _raise(error_code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _raise(error_code)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _raise(error_code)
    return parsed.astimezone(UTC)


def _utc_time(value: object, error_code: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        _raise(error_code)
    return value.astimezone(UTC)


def _wire_time(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _capabilities(value: object, error_code: str) -> tuple[str, ...]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
        or not 1 <= len(value) <= _MAX_COLLECTION_ITEMS
    ):
        _raise(error_code)
    capabilities = tuple(_public_ref(item, error_code) for item in value)
    if len(set(capabilities)) != len(capabilities):
        _raise(error_code)
    return capabilities


def _public_mapping(value: object, error_code: str) -> dict[str, object]:
    normalized = _json_value(value, error_code, public=True, depth=0)
    if type(normalized) is not dict:
        _raise(error_code)
    return normalized


def _private_mapping(value: object, error_code: str) -> dict[str, object]:
    normalized = _json_value(value, error_code, public=False, depth=0)
    if type(normalized) is not dict:
        _raise(error_code)
    try:
        if len(_encode(normalized)) > 64 * 1024:
            _raise(error_code)
    except (TypeError, ValueError, RecursionError):
        _raise(error_code)
    return normalized


def _json_value(
    value: object,
    error_code: str,
    *,
    public: bool,
    depth: int,
) -> object:
    if depth > _MAX_NESTING:
        _raise(error_code)
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            _raise(error_code)
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _raise(error_code)
        return value
    if type(value) is str:
        if public:
            text = _public_text(value, error_code)
            try:
                ipaddress.ip_address(text.removeprefix("[").removesuffix("]"))
            except ValueError:
                return text
            _raise(error_code)
        try:
            if not value or len(value.encode("utf-8")) > _MAX_PRIVATE_TEXT_BYTES:
                _raise(error_code)
        except UnicodeError:
            _raise(error_code)
        return value
    if isinstance(value, Mapping):
        if len(value) > _MAX_COLLECTION_ITEMS:
            _raise(error_code)
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str:
                _raise(error_code)
            try:
                if not key or len(key.encode("utf-8")) > 128:
                    _raise(error_code)
            except UnicodeError:
                _raise(error_code)
            if public and _SENSITIVE_PUBLIC_KEY.search(key):
                _raise(error_code)
            result[key] = _json_value(item, error_code, public=public, depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        if len(value) > _MAX_COLLECTION_ITEMS:
            _raise(error_code)
        return [
            _json_value(item, error_code, public=public, depth=depth + 1)
            for item in value
        ]
    _raise(error_code)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HostRegistryError("control.host_store_unavailable")
        result[key] = value
    return result


def _encode(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _digest(value: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(_encode(value).rstrip(b"\n")).hexdigest()


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _freeze_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise HostRegistryError("control.host_store_unavailable")
    return MappingProxyType({key: _freeze(item) for key, item in value.items()})


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


__all__ = ["ControlHostV1", "HostRegistry", "HostRegistryError"]
