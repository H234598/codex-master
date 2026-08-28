"""Private, durable registry for Masterjet control and execution hosts."""

from __future__ import annotations

import builtins
from collections.abc import Mapping
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
from typing import Any, Never, cast
import unicodedata
from urllib.parse import unquote

from codex_master.admin_contracts import (
    AdminContractError,
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
_TRANSPORT_KINDS = frozenset({"ssh"})
_CAPABILITY_CODES = frozenset({"codex.execute", "resource.probe"})
_PROBE_SOURCES = frozenset({"host-agent", "inventory-agent"})
_HOST_REF = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z", re.ASCII)
_HOST_LABEL = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9 _-]{0,126}[A-Za-z0-9])?\Z", re.ASCII
)
_CODE_TOKEN = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\Z", re.ASCII)
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
_TRANSPORT_FIELDS = frozenset({"kind", "binding_ref"})
_REACHABILITY_FIELDS = frozenset({"state", "latency_ms"})
_RESOURCE_FIELDS = frozenset({"cpu_threads", "memory_bytes"})
_SENSITIVE_KEY_PARTS = frozenset(
    {
        "address",
        "auth",
        "cookie",
        "credential",
        "endpoint",
        "host",
        "jwt",
        "password",
        "passphrase",
        "path",
        "private",
        "root",
        "secret",
        "socket",
        "token",
        "uri",
        "url",
    }
)
_SENSITIVE_VALUE_PARTS = _SENSITIVE_KEY_PARTS - {"host"}
_SENSITIVE_VALUE_SUBSTRINGS = _SENSITIVE_VALUE_PARTS - {"jwt", "uri", "url"}
_PRIVATE_VALUE_MARKERS = frozenset({"localhost"})


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
        object.__setattr__(self, "ref", _host_ref(self.ref, error_code))
        object.__setattr__(self, "label", _host_label(self.label, error_code))
        if type(self.role) is not str or self.role not in _ROLES:
            raise HostRegistryError(error_code)
        transport = _transport_binding(self.transport_binding, error_code)
        object.__setattr__(self, "transport_binding", _freeze_mapping(transport))
        object.__setattr__(
            self, "capabilities", _capabilities(self.capabilities, error_code)
        )
        reachability = _reachability(self.reachability, error_code)
        object.__setattr__(self, "reachability", _freeze_mapping(reachability))
        resources = _resources(self.resource_evidence, error_code)
        object.__setattr__(self, "resource_evidence", _freeze_mapping(resources))
        object.__setattr__(self, "generation", _generation(self.generation, error_code))
        object.__setattr__(self, "observed_at", _utc_time(self.observed_at, error_code))
        object.__setattr__(self, "source", _probe_source(self.source, error_code))

    def __repr__(self) -> str:
        return f"ControlHostV1(role={self.role!r}, generation={self.generation!r})"

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
        ref = _host_ref(ref, "control.host_invalid")
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
        ref = _host_ref(ref, "control.host_invalid")
        generation = _generation(generation, "control.host_invalid")
        record, binding = _validated_probe_record(
            ref,
            generation,
            evidence,
            error_code="control.host_invalid",
        )
        with self._locked_state() as (hosts, bindings):
            existing = next((item for item in hosts if item["ref"] == ref), None)
            if existing is not None:
                current_generation = _generation(
                    existing["generation"], "control.host_store_unavailable"
                )
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
        if type(version) is not int:
            raise HostRegistryError("control.host_store_unavailable")
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
            ref = _host_ref(item["ref"], "control.host_store_unavailable")
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
            ref = _host_ref(item["ref"], "control.host_store_unavailable")
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
            ref = _host_ref(item["ref"], "control.host_store_unavailable")
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
        if type(evidence) is not dict or not _exact_keys(
            evidence, _EVIDENCE_FIELDS, error_code
        ):
            raise HostRegistryError(error_code)
        label = _host_label(evidence["label"], error_code)
        role = evidence["role"]
        if type(role) is not str or role not in _ROLES:
            raise HostRegistryError(error_code)
        transport = _transport_binding(evidence["transport_binding"], error_code)
        capabilities = _capabilities(evidence["capabilities"], error_code)
        reachability = _reachability(evidence["reachability"], error_code)
        resources = _resources(evidence["resource_evidence"], error_code)
        observed = _parse_time(evidence["observed_at"], error_code)
        source = _probe_source(evidence["source"], error_code)
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
            transport_binding=cast(Mapping[str, object], record["transport_binding"]),
            capabilities=_capabilities(
                record["capabilities"], "control.host_store_unavailable"
            ),
            reachability=cast(Mapping[str, object], record["reachability"]),
            resource_evidence=cast(Mapping[str, object], record["resource_evidence"]),
            generation=_generation(
                record["generation"], "control.host_store_unavailable"
            ),
            observed_at=_parse_time(
                record["observed_at"], "control.host_store_unavailable"
            ),
            source=str(record["source"]),
        )


def _validated_probe_record(
    ref: str,
    generation: object,
    evidence: object,
    *,
    error_code: str,
) -> tuple[dict[str, object], dict[str, object]]:
    try:
        return HostRegistry._probe_record(
            ref,
            generation,
            evidence,  # type: ignore[arg-type]
            error_code=error_code,
        )
    except HostRegistryError:
        raise
    except BaseException:
        pass
    raise HostRegistryError(error_code)


def _raise(code: str) -> Never:
    raise HostRegistryError(code)


def _public_text(value: object, error_code: str) -> str:
    try:
        return public_admin_text(value)
    except AdminContractError:
        _raise(error_code)


def _field_string(
    value: object,
    *,
    pattern: re.Pattern[str],
    error_code: str,
) -> str:
    if type(value) is not str:
        _raise(error_code)
    normalized = _normalized_key(value, error_code)
    parts = frozenset(part for part in normalized.split("_") if part)
    compact = normalized.replace("_", "")
    if (
        parts & _SENSITIVE_VALUE_PARTS
        or any(marker in compact for marker in _SENSITIVE_VALUE_SUBSTRINGS)
        or any(marker in compact for marker in _PRIVATE_VALUE_MARKERS)
    ):
        _raise(error_code)
    try:
        value.encode("ascii")
    except UnicodeError:
        _raise(error_code)
    if pattern.fullmatch(value) is None:
        _raise(error_code)
    return value


def _host_ref(value: object, error_code: str) -> str:
    return _field_string(value, pattern=_HOST_REF, error_code=error_code)


def _host_label(value: object, error_code: str) -> str:
    return _field_string(value, pattern=_HOST_LABEL, error_code=error_code)


def _registered_code(value: object, allowed: frozenset[str], error_code: str) -> str:
    code = _field_string(value, pattern=_CODE_TOKEN, error_code=error_code)
    if code not in allowed:
        _raise(error_code)
    return code


def _transport_kind(value: object, error_code: str) -> str:
    return _registered_code(value, _TRANSPORT_KINDS, error_code)


def _probe_source(value: object, error_code: str) -> str:
    return _registered_code(value, _PROBE_SOURCES, error_code)


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
    if type(value) not in {list, tuple}:
        _raise(error_code)
    values = cast(list[object] | tuple[object, ...], value)
    if not 1 <= len(values) <= _MAX_COLLECTION_ITEMS:
        _raise(error_code)
    capabilities = tuple(
        _registered_code(item, _CAPABILITY_CODES, error_code) for item in values
    )
    if len(set(capabilities)) != len(capabilities):
        _raise(error_code)
    return capabilities


def _normalized_key(value: object, error_code: str) -> str:
    if type(value) is not str:
        _raise(error_code)
    candidate = value
    try:
        for _ in range(4):
            candidate = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", candidate)
            candidate = unicodedata.normalize("NFKC", candidate).casefold()
            decoded = unquote(candidate, errors="strict")
            if decoded == candidate:
                break
            candidate = decoded
    except (UnicodeError, ValueError):
        _raise(error_code)
    return re.sub(r"[^a-z0-9]+", "_", candidate).strip("_")


def _exact_keys(value: object, expected: frozenset[str], error_code: str) -> bool:
    if type(value) is not dict:
        _raise(error_code)
    keys = tuple(value.keys())
    if len(keys) != len(expected):
        return False
    for key in keys:
        _normalized_key(key, error_code)
        if type(key) is not str or key not in expected:
            return False
    return True


def _public_object(
    value: object,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    error_code: str,
) -> dict[str, object]:
    allowed = required | optional
    if type(value) is not dict:
        _raise(error_code)
    keys = tuple(value.keys())
    for key in keys:
        normalized = _normalized_key(key, error_code)
        parts = frozenset(part for part in normalized.split("_") if part)
        if parts & _SENSITIVE_KEY_PARTS or type(key) is not str or key not in allowed:
            _raise(error_code)
    if not required <= frozenset(keys):
        _raise(error_code)
    return value


def _transport_binding(value: object, error_code: str) -> dict[str, object]:
    transport = _public_object(
        value,
        required=_TRANSPORT_FIELDS,
        error_code=error_code,
    )
    return {
        "kind": _transport_kind(transport["kind"], error_code),
        "binding_ref": _opaque_binding_ref(transport["binding_ref"], error_code),
    }


def _opaque_binding_ref(value: object, error_code: str) -> str:
    return _field_string(value, pattern=_HOST_REF, error_code=error_code)


def _reachability(value: object, error_code: str) -> dict[str, object]:
    reachability = _public_object(
        value,
        required=frozenset({"state"}),
        optional=frozenset({"latency_ms"}),
        error_code=error_code,
    )
    state = reachability["state"]
    if type(state) is not str or state not in _REACHABILITY_STATES:
        _raise(error_code)
    result: dict[str, object] = {"state": state}
    if "latency_ms" in reachability:
        result["latency_ms"] = _nonnegative_int(reachability["latency_ms"], error_code)
    return result


def _resources(value: object, error_code: str) -> dict[str, object]:
    resources = _public_object(
        value,
        required=_RESOURCE_FIELDS,
        error_code=error_code,
    )
    cpu_threads = _nonnegative_int(resources["cpu_threads"], error_code)
    if cpu_threads == 0:
        _raise(error_code)
    return {
        "cpu_threads": cpu_threads,
        "memory_bytes": _nonnegative_int(resources["memory_bytes"], error_code),
    }


def _nonnegative_int(value: object, error_code: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        _raise(error_code)
    return value


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
    if type(value) is dict:
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
            result[key] = _json_value(item, error_code, public=public, depth=depth + 1)
        return result
    if type(value) in {list, tuple}:
        values = cast(list[object] | tuple[object, ...], value)
        if len(values) > _MAX_COLLECTION_ITEMS:
            _raise(error_code)
        return [
            _json_value(item, error_code, public=public, depth=depth + 1)
            for item in values
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
