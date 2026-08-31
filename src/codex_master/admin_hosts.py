"""Private, durable registry for Masterjet control and execution hosts."""

from __future__ import annotations

import builtins
from collections.abc import Mapping
import contextlib
from dataclasses import dataclass, field
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
_SCHEMA_VERSION = 3
_MAX_GENERATION = 2**63 - 1
_MAX_COLLECTION_ITEMS = 64
_MAX_PRIVATE_TEXT_BYTES = 4096
_MAX_NESTING = 6
_ROLES = frozenset({"control", "execution", "worker"})
_REACHABILITY_STATES = frozenset(
    {"reachable", "unreachable", "unknown", "unavailable"}
)
_TRANSPORT_KINDS = frozenset({"ssh"})
_CAPABILITY_CODES = frozenset(
    {"codex.execute", "resource.probe", "ollama.execute"}
)
_PROBE_SOURCES = frozenset({"host-agent", "inventory-agent"})
_HOST_SOURCES = _PROBE_SOURCES | frozenset({"static-agent-binding"})
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
_LEGACY_SCHEMA3_FIELDS = frozenset(
    {"schema_version", "registrations", "bindings", "observations"}
)
_SCHEMA3_FIELDS = _LEGACY_SCHEMA3_FIELDS | {"generation", "agent_epoch_history"}
_REGISTRATION_FIELDS = frozenset(
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
    }
)
_AGENT_BINDING_FIELDS = frozenset(
    {"ref", "client_spki_sha256", "lease_epoch", "enabled"}
)
_AGENT_EPOCH_FIELDS = frozenset({"ref", "lease_epoch"})
_STATIC_REGISTRATION_INPUT_FIELDS = frozenset(
    {"ref", "label", "role", "capabilities"}
)
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
    observed_at: datetime | None
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
        observed = self.observed_at
        if observed is not None:
            observed = _utc_time(observed, error_code)
        object.__setattr__(self, "observed_at", observed)
        object.__setattr__(self, "source", _host_source(self.source, error_code))

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
            "observed_at": (
                None if self.observed_at is None else _wire_time(self.observed_at)
            ),
            "source": self.source,
        }


@dataclass(frozen=True, slots=True, repr=False)
class AgentBindingV1:
    host_ref: str
    client_spki_sha256: str = field(repr=False)
    lease_epoch: int
    enabled: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "host_ref", _host_ref(self.host_ref, "host.identity_invalid")
        )
        object.__setattr__(
            self,
            "client_spki_sha256",
            _spki_digest(self.client_spki_sha256, "host.identity_invalid"),
        )
        object.__setattr__(
            self, "lease_epoch", _generation(self.lease_epoch, "host.identity_invalid")
        )
        if self.lease_epoch == 0 or type(self.enabled) is not bool:
            raise HostRegistryError("host.identity_invalid")

    def __repr__(self) -> str:
        return (
            "AgentBindingV1("
            f"host_ref={self.host_ref!r}, lease_epoch={self.lease_epoch!r}, "
            f"enabled={self.enabled!r})"
        )


@dataclass(frozen=True, slots=True)
class AgentPrincipalV1:
    host_ref: str
    registry_generation: int
    lease_epoch: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "host_ref", _host_ref(self.host_ref, "host.identity_invalid")
        )
        object.__setattr__(
            self,
            "registry_generation",
            _generation(self.registry_generation, "host.identity_invalid"),
        )
        object.__setattr__(
            self, "lease_epoch", _generation(self.lease_epoch, "host.identity_invalid")
        )


class HostRegistry:
    """One bounded host document guarded by Hive's durable CAS lock."""

    def __init__(self, state_root: Path) -> None:
        if not isinstance(state_root, Path) or not state_root.is_absolute():
            raise HostRegistryError("control.host_store_unavailable")
        self._root = state_root / "admin-hosts"
        try:
            self._state = HiveStateStore(self._root)
            with self._state.locked():
                (
                    hosts,
                    ssh_bindings,
                    agent_bindings,
                    observations,
                    generation,
                    epoch_history,
                    migrated,
                ) = self._read_locked()
                if migrated:
                    self._write_locked(
                        hosts,
                        ssh_bindings,
                        agent_bindings,
                        observations,
                        generation,
                        epoch_history,
                    )
        except HostRegistryError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError):
            raise HostRegistryError("control.host_store_unavailable") from None

    @classmethod
    def for_test(cls, state_root: Path) -> HostRegistry:
        return cls(state_root)

    def list(self) -> tuple[ControlHostV1, ...]:
        with self._locked_state() as (
            hosts,
            _ssh_bindings,
            _agent_bindings,
            observations,
            _generation_value,
            _epoch_history,
        ):
            hosts = _merged_hosts(hosts, observations)
            return tuple(self._host(record) for record in hosts)

    def get(self, ref: str) -> ControlHostV1:
        ref = _host_ref(ref, "control.host_invalid")
        with self._locked_state() as (
            hosts,
            _ssh_bindings,
            _agent_bindings,
            observations,
            _generation_value,
            _epoch_history,
        ):
            for record in _merged_hosts(hosts, observations):
                if record["ref"] == ref:
                    return self._host(record)
        raise HostRegistryError("control.host_not_found")

    def document_generation(self) -> int:
        """Return the authoritative generation used by agent principal fences."""

        with self._locked_state() as (
            _hosts,
            _ssh_bindings,
            _agent_bindings,
            _observations,
            generation,
            _epoch_history,
        ):
            return generation

    def provision_agent_binding(
        self,
        registration: Mapping[str, object],
        binding: AgentBindingV1,
        *,
        expected_generation: int,
    ) -> ControlHostV1:
        expected_generation = _generation(
            expected_generation, "credential.generation_conflict"
        )
        registration_record = _agent_registration_record(registration, generation=1)
        if binding.host_ref != registration_record["ref"]:
            raise HostRegistryError("host.identity_mismatch")
        with self._locked_state() as (
            registrations,
            ssh_bindings,
            agent_bindings,
            observations,
            document_generation,
            epoch_history,
        ):
            if document_generation != expected_generation:
                raise HostRegistryError("credential.generation_conflict")
            for item in agent_bindings:
                if (
                    item["enabled"] is True
                    and binding.enabled
                    and item["client_spki_sha256"] == binding.client_spki_sha256
                    and item["ref"] != binding.host_ref
                ):
                    raise HostRegistryError("host.identity_mismatch")
            existing_binding = next(
                (item for item in agent_bindings if item["ref"] == binding.host_ref),
                None,
            )
            prior_epoch = epoch_history.get(binding.host_ref, 0)
            next_epoch = binding.lease_epoch
            if existing_binding is not None:
                next_epoch = _generation(
                    existing_binding["lease_epoch"], "control.host_store_unavailable"
                )
                if (
                    existing_binding["client_spki_sha256"] != binding.client_spki_sha256
                    or existing_binding["enabled"] != binding.enabled
                ):
                    if next_epoch == _MAX_GENERATION:
                        raise HostRegistryError("host.identity_epoch_exhausted")
                    next_epoch += 1
            elif prior_epoch:
                if prior_epoch == _MAX_GENERATION:
                    raise HostRegistryError("host.identity_epoch_exhausted")
                next_epoch = prior_epoch + 1
            if binding.lease_epoch not in {1, next_epoch}:
                raise HostRegistryError("host.identity_invalid")
            stored_binding = {
                "ref": binding.host_ref,
                "client_spki_sha256": binding.client_spki_sha256,
                "lease_epoch": next_epoch,
                "enabled": binding.enabled,
            }
            existing_registration = next(
                (
                    item
                    for item in registrations
                    if item["ref"] == binding.host_ref
                ),
                None,
            )
            if (
                existing_binding == stored_binding
                and existing_registration is not None
                and _registration_without_generation(existing_registration)
                == _registration_without_generation(registration_record)
            ):
                return self._host(existing_registration)
            if document_generation == _MAX_GENERATION:
                raise HostRegistryError("credential.generation_exhausted")
            mutation_generation = document_generation + 1
            registrations[:] = [
                item for item in registrations if item["ref"] != binding.host_ref
            ]
            agent_bindings[:] = [
                item for item in agent_bindings if item["ref"] != binding.host_ref
            ]
            registration_record["generation"] = mutation_generation
            registrations.append(registration_record)
            agent_bindings.append(stored_binding)
            epoch_history[binding.host_ref] = next_epoch
            registrations.sort(key=lambda item: str(item["ref"]))
            agent_bindings.sort(key=lambda item: str(item["ref"]))
            self._write_locked(
                registrations,
                ssh_bindings,
                agent_bindings,
                observations,
                mutation_generation,
                epoch_history,
            )
            return self._host(registration_record)

    def synchronize_agent_bindings(
        self,
        desired: tuple[tuple[Mapping[str, object], AgentBindingV1], ...],
        *,
        expected_generation: int | None = None,
    ) -> None:
        if expected_generation is not None:
            expected_generation = _generation(
                expected_generation, "credential.generation_conflict"
            )
        validated: list[tuple[dict[str, object], AgentBindingV1]] = []
        seen_refs: set[str] = set()
        seen_enabled_spkis: set[str] = set()
        for registration, binding in desired:
            record = _agent_registration_record(registration, generation=1)
            if binding.host_ref != record["ref"] or binding.host_ref in seen_refs:
                raise HostRegistryError("host.identity_mismatch")
            if binding.enabled:
                if binding.client_spki_sha256 in seen_enabled_spkis:
                    raise HostRegistryError("host.identity_mismatch")
                seen_enabled_spkis.add(binding.client_spki_sha256)
            seen_refs.add(binding.host_ref)
            validated.append((record, binding))

        with self._locked_state() as (
            registrations,
            ssh_bindings,
            agent_bindings,
            observations,
            document_generation,
            epoch_history,
        ):
            if (
                expected_generation is not None
                and document_generation != expected_generation
            ):
                raise HostRegistryError("credential.generation_conflict")
            existing_registrations = {
                str(item["ref"]): item for item in registrations
            }
            existing_bindings = {str(item["ref"]): item for item in agent_bindings}
            next_registrations = [
                item
                for item in registrations
                if item["ref"] in seen_refs
                or item["source"] != "static-agent-binding"
            ]
            next_bindings: list[dict[str, object]] = []
            changed = len(next_registrations) != len(registrations) or bool(
                set(existing_bindings) - seen_refs
            )

            prepared: list[tuple[dict[str, object], dict[str, object], bool]] = []
            for registration, binding in validated:
                existing_binding = existing_bindings.get(binding.host_ref)
                prior_epoch = epoch_history.get(binding.host_ref, 0)
                next_epoch = binding.lease_epoch
                if existing_binding is not None:
                    next_epoch = _generation(
                        existing_binding["lease_epoch"],
                        "control.host_store_unavailable",
                    )
                    binding_changed = (
                        existing_binding["client_spki_sha256"]
                        != binding.client_spki_sha256
                        or existing_binding["enabled"] != binding.enabled
                    )
                    if binding_changed:
                        if next_epoch == _MAX_GENERATION:
                            raise HostRegistryError("host.identity_epoch_exhausted")
                        next_epoch += 1
                elif prior_epoch:
                    if prior_epoch == _MAX_GENERATION:
                        raise HostRegistryError("host.identity_epoch_exhausted")
                    next_epoch = prior_epoch + 1
                if binding.lease_epoch not in {1, next_epoch}:
                    raise HostRegistryError("host.identity_invalid")
                stored_binding = {
                    "ref": binding.host_ref,
                    "client_spki_sha256": binding.client_spki_sha256,
                    "lease_epoch": next_epoch,
                    "enabled": binding.enabled,
                }
                existing_registration = existing_registrations.get(binding.host_ref)
                item_changed = (
                    existing_binding != stored_binding
                    or existing_registration is None
                    or _registration_without_generation(existing_registration)
                    != _registration_without_generation(registration)
                )
                changed = changed or item_changed
                prepared.append((registration, stored_binding, item_changed))

            if not changed:
                return
            if document_generation == _MAX_GENERATION:
                raise HostRegistryError("credential.generation_exhausted")
            mutation_generation = document_generation + 1
            desired_refs = {binding.host_ref for _record, binding in validated}
            next_registrations = [
                item for item in next_registrations if item["ref"] not in desired_refs
            ]
            for registration, stored_binding, item_changed in prepared:
                existing_registration = existing_registrations.get(
                    str(stored_binding["ref"])
                )
                registration["generation"] = (
                    mutation_generation
                    if item_changed or existing_registration is None
                    else existing_registration["generation"]
                )
                next_registrations.append(registration)
                next_bindings.append(stored_binding)
                epoch_history[str(stored_binding["ref"])] = _generation(
                    stored_binding["lease_epoch"], "control.host_store_unavailable"
                )
            if len(epoch_history) > MAX_HOST_RECORDS:
                raise HostRegistryError("host.identity_history_full")
            next_registrations.sort(key=lambda item: str(item["ref"]))
            next_bindings.sort(key=lambda item: str(item["ref"]))
            self._write_locked(
                next_registrations,
                ssh_bindings,
                next_bindings,
                observations,
                mutation_generation,
                epoch_history,
            )

    def agent_binding(self, host_ref: str) -> AgentBindingV1:
        host_ref = _host_ref(host_ref, "host.identity_invalid")
        with self._locked_state() as (
            _registrations,
            _ssh_bindings,
            agent_bindings,
            _observations,
            _generation_value,
            _epoch_history,
        ):
            for item in agent_bindings:
                if item["ref"] == host_ref:
                    return _agent_binding(item, "control.host_store_unavailable")
        raise HostRegistryError("host.identity_not_found")

    def resolve_agent_spki(self, client_spki_sha256: str) -> AgentPrincipalV1:
        client_spki_sha256 = _spki_digest(client_spki_sha256, "host.identity_invalid")
        with self._locked_state() as (
            registrations,
            _ssh_bindings,
            agent_bindings,
            _observations,
            document_generation,
            _epoch_history,
        ):
            matches = [
                item
                for item in agent_bindings
                if item["enabled"] is True
                and item["client_spki_sha256"] == client_spki_sha256
            ]
            if len(matches) != 1:
                raise HostRegistryError("host.identity_not_found")
            binding = matches[0]
            refs = {str(item["ref"]) for item in registrations}
            if binding["ref"] not in refs:
                raise HostRegistryError("host.identity_not_found")
            return AgentPrincipalV1(
                str(binding["ref"]),
                document_generation,
                _generation(binding["lease_epoch"], "control.host_store_unavailable"),
            )

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
        with self._locked_state() as (
            registrations,
            ssh_bindings,
            agent_bindings,
            observations,
            document_generation,
            epoch_history,
        ):
            existing = next((item for item in observations if item["ref"] == ref), None)
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
                observations.remove(existing)
            if document_generation == _MAX_GENERATION:
                raise HostRegistryError("credential.generation_exhausted")
            mutation_generation = max(document_generation + 1, generation)
            observations.append(record)
            registrations[:] = [item for item in registrations if item["ref"] != ref]
            registrations.append(_registration_from_probe(record))
            ssh_bindings[ref] = binding
            observations.sort(key=lambda item: str(item["ref"]))
            registrations.sort(key=lambda item: str(item["ref"]))
            self._write_locked(
                registrations,
                ssh_bindings,
                agent_bindings,
                observations,
                mutation_generation,
                epoch_history,
            )
            return self._host(record)

    def record_active_probe(
        self,
        ref: str,
        *,
        generation: int,
        resource_evidence: Mapping[str, object],
        observed_at: str,
    ) -> ControlHostV1:
        """Record fresh active-probe fields without accepting registry metadata."""
        ref = _host_ref(ref, "control.host_invalid")
        generation = _generation(generation, "control.host_invalid")
        resources = _resources(resource_evidence, "control.host_invalid")
        observed = _wire_time(_parse_time(observed_at, "control.host_invalid"))
        with self._locked_state() as (
            registrations,
            ssh_bindings,
            agent_bindings,
            observations,
            document_generation,
            epoch_history,
        ):
            registration = next((item for item in registrations if item["ref"] == ref), None)
            binding = ssh_bindings.get(ref)
            if registration is None or binding is None:
                raise HostRegistryError("host.identity_not_found")
            evidence = {
                "label": registration["label"],
                "role": registration["role"],
                "transport_binding": registration["transport_binding"],
                "capabilities": registration["capabilities"],
                "reachability": {"state": "reachable", "latency_ms": 0},
                "resource_evidence": resources,
                "observed_at": observed,
                "source": "host-agent",
                "binding_state": binding,
            }
            record, preserved_binding = _validated_probe_record(
                ref, generation, evidence, error_code="control.host_invalid"
            )
            record["probe_digest"] = _digest(
                {
                    "ref": ref,
                    "generation": generation,
                    "resource_evidence": resources,
                    "observed_at": observed,
                    "reachability": {"state": "reachable", "latency_ms": 0},
                }
            )
            existing = next((item for item in observations if item["ref"] == ref), None)
            if existing is not None:
                current = _generation(existing["generation"], "control.host_store_unavailable")
                if generation < current or (generation == current and record["probe_digest"] != existing["probe_digest"]):
                    raise HostRegistryError("credential.generation_conflict")
                if generation == current:
                    return self._host(existing)
                observations.remove(existing)
            if document_generation == _MAX_GENERATION:
                raise HostRegistryError("credential.generation_exhausted")
            observations.append(record)
            registrations[:] = [item for item in registrations if item["ref"] != ref]
            registrations.append(_registration_from_probe(record))
            ssh_bindings[ref] = preserved_binding
            observations.sort(key=lambda item: str(item["ref"]))
            registrations.sort(key=lambda item: str(item["ref"]))
            self._write_locked(
                registrations, ssh_bindings, agent_bindings, observations,
                max(document_generation + 1, generation), epoch_history,
            )
            return self._host(record)

    @contextlib.contextmanager
    def _locked_state(self) -> Any:
        try:
            with self._state.locked():
                (
                    hosts,
                    ssh_bindings,
                    agent_bindings,
                    observations,
                    generation,
                    epoch_history,
                    migrated,
                ) = self._read_locked()
                if migrated:
                    self._write_locked(
                        hosts,
                        ssh_bindings,
                        agent_bindings,
                        observations,
                        generation,
                        epoch_history,
                    )
                yield (
                    hosts,
                    ssh_bindings,
                    agent_bindings,
                    observations,
                    generation,
                    epoch_history,
                )
        except HostRegistryError:
            raise
        except (HiveStateError, OSError, TypeError, ValueError, RecursionError):
            raise HostRegistryError("control.host_store_unavailable") from None

    def _read_locked(
        self,
    ) -> tuple[
        builtins.list[dict[str, object]],
        dict[str, dict[str, object]],
        builtins.list[dict[str, object]],
        builtins.list[dict[str, object]],
        int,
        dict[str, int],
        bool,
    ]:
        try:
            raw = self._state.read_private_bytes(
                _DOCUMENT, max_bytes=MAX_HOST_STATE_BYTES
            )
        except HiveStateError as exc:
            if exc.args == ("state_not_found",):
                return [], {}, [], [], 0, {}, False
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
        if version == 2:
            return self._read_v2(document)
        legacy_schema3 = set(document) == _LEGACY_SCHEMA3_FIELDS
        if version != _SCHEMA_VERSION or not (
            legacy_schema3 or set(document) == _SCHEMA3_FIELDS
        ):
            raise HostRegistryError("control.host_store_unavailable")
        raw_hosts = document.get("registrations")
        raw_bindings = document.get("bindings")
        raw_observations = document.get("observations")
        if (
            type(raw_hosts) is not list
            or type(raw_bindings) is not dict
            or set(raw_bindings) != {"ssh", "agent"}
            or type(raw_bindings.get("ssh")) is not list
            or type(raw_bindings.get("agent")) is not list
            or type(raw_observations) is not list
            or len(raw_hosts) > MAX_HOST_RECORDS
            or len(raw_observations) > MAX_HOST_RECORDS
        ):
            raise HostRegistryError("control.host_store_unavailable")
        bindings: dict[str, dict[str, object]] = {}
        for item in raw_bindings["ssh"]:
            if not isinstance(item, Mapping) or set(item) != _BINDING_FIELDS:
                raise HostRegistryError("control.host_store_unavailable")
            ref = _host_ref(item["ref"], "control.host_store_unavailable")
            if ref in bindings:
                raise HostRegistryError("control.host_store_unavailable")
            bindings[ref] = _private_mapping(
                item["binding_state"], "control.host_store_unavailable"
            )
        agent_bindings: list[dict[str, object]] = []
        agent_refs: set[str] = set()
        enabled_spkis: set[str] = set()
        for item in raw_bindings["agent"]:
            if not isinstance(item, Mapping) or set(item) != _AGENT_BINDING_FIELDS:
                raise HostRegistryError("control.host_store_unavailable")
            normalized = _agent_binding_record(item, "control.host_store_unavailable")
            ref = str(normalized["ref"])
            spki = str(normalized["client_spki_sha256"])
            if ref in agent_refs:
                raise HostRegistryError("control.host_store_unavailable")
            if normalized["enabled"] is True:
                if spki in enabled_spkis:
                    raise HostRegistryError("control.host_store_unavailable")
                enabled_spkis.add(spki)
            agent_refs.add(ref)
            agent_bindings.append(normalized)
        if legacy_schema3:
            epoch_history = {
                str(item["ref"]): _generation(
                    item["lease_epoch"], "control.host_store_unavailable"
                )
                for item in agent_bindings
            }
        else:
            raw_history = document.get("agent_epoch_history")
            if type(raw_history) is not list or len(raw_history) > MAX_HOST_RECORDS:
                raise HostRegistryError("control.host_store_unavailable")
            epoch_history: dict[str, int] = {}
            for item in raw_history:
                if not isinstance(item, Mapping) or set(item) != _AGENT_EPOCH_FIELDS:
                    raise HostRegistryError("control.host_store_unavailable")
                ref = _host_ref(item["ref"], "control.host_store_unavailable")
                epoch = _generation(
                    item["lease_epoch"], "control.host_store_unavailable"
                )
                if ref in epoch_history or epoch == 0:
                    raise HostRegistryError("control.host_store_unavailable")
                epoch_history[ref] = epoch
        hosts: list[dict[str, object]] = []
        seen: set[str] = set()
        for item in raw_hosts:
            if not isinstance(item, Mapping) or set(item) != _REGISTRATION_FIELDS:
                raise HostRegistryError("control.host_store_unavailable")
            record = _registration_record(item, "control.host_store_unavailable")
            ref = str(record["ref"])
            if ref in seen:
                raise HostRegistryError("control.host_store_unavailable")
            hosts.append(record)
            seen.add(ref)
        if not set(bindings).issubset(seen) or not agent_refs.issubset(seen):
            raise HostRegistryError("control.host_store_unavailable")
        observations: list[dict[str, object]] = []
        observed_refs: set[str] = set()
        for item in raw_observations:
            if not isinstance(item, Mapping) or set(item) != _HOST_FIELDS:
                raise HostRegistryError("control.host_store_unavailable")
            ref = _host_ref(item["ref"], "control.host_store_unavailable")
            if ref in observed_refs or ref not in bindings or ref not in seen:
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
            active_digest = _digest(
                {
                    "ref": ref,
                    "generation": item["generation"],
                    "resource_evidence": item["resource_evidence"],
                    "observed_at": item["observed_at"],
                    "reachability": item["reachability"],
                }
            )
            if item["probe_digest"] not in {record["probe_digest"], active_digest}:
                raise HostRegistryError("control.host_store_unavailable")
            record["probe_digest"] = item["probe_digest"]
            observations.append(record)
            bindings[ref] = normalized_binding
            observed_refs.add(ref)
        hosts.sort(key=lambda item: str(item["ref"]))
        observations.sort(key=lambda item: str(item["ref"]))
        agent_bindings.sort(key=lambda item: str(item["ref"]))
        record_generation = _document_generation(hosts, observations)
        if legacy_schema3:
            document_generation = record_generation
        else:
            document_generation = _generation(
                document.get("generation"), "control.host_store_unavailable"
            )
            if document_generation < record_generation:
                raise HostRegistryError("control.host_store_unavailable")
        if any(
            epoch_history.get(str(item["ref"]), 0)
            < _generation(item["lease_epoch"], "control.host_store_unavailable")
            for item in agent_bindings
        ):
            raise HostRegistryError("control.host_store_unavailable")
        return (
            hosts,
            bindings,
            agent_bindings,
            observations,
            document_generation,
            epoch_history,
            legacy_schema3,
        )

    def _read_v2(
        self, document: Mapping[str, object]
    ) -> tuple[
        builtins.list[dict[str, object]],
        dict[str, dict[str, object]],
        builtins.list[dict[str, object]],
        builtins.list[dict[str, object]],
        int,
        dict[str, int],
        bool,
    ]:
        if set(document) != {"schema_version", "hosts", "bindings"}:
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
        observations: list[dict[str, object]] = []
        registrations: list[dict[str, object]] = []
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
            observations.append(record)
            registrations.append(_registration_from_probe(record))
            bindings[ref] = normalized_binding
            seen.add(ref)
        if seen != set(bindings):
            raise HostRegistryError("control.host_store_unavailable")
        registrations.sort(key=lambda item: str(item["ref"]))
        observations.sort(key=lambda item: str(item["ref"]))
        return (
            registrations,
            bindings,
            [],
            observations,
            _document_generation(registrations, observations),
            {},
            True,
        )

    def _read_legacy(
        self, document: Mapping[str, object]
    ) -> tuple[
        builtins.list[dict[str, object]],
        dict[str, dict[str, object]],
        builtins.list[dict[str, object]],
        builtins.list[dict[str, object]],
        int,
        dict[str, int],
        bool,
    ]:
        if set(document) != {"schema_version", "hosts"}:
            raise HostRegistryError("control.host_store_unavailable")
        raw_hosts = document.get("hosts")
        if type(raw_hosts) is not list or len(raw_hosts) > MAX_HOST_RECORDS:
            raise HostRegistryError("control.host_store_unavailable")
        expected = _EVIDENCE_FIELDS | {"ref", "generation"}
        hosts: list[dict[str, object]] = []
        registrations: list[dict[str, object]] = []
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
            registrations.append(_registration_from_probe(record))
            bindings[ref] = binding
        registrations.sort(key=lambda item: str(item["ref"]))
        hosts.sort(key=lambda item: str(item["ref"]))
        return (
            registrations,
            bindings,
            [],
            hosts,
            _document_generation(registrations, hosts),
            {},
            True,
        )

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
        registrations: builtins.list[dict[str, object]],
        ssh_bindings: Mapping[str, dict[str, object]],
        agent_bindings: builtins.list[dict[str, object]],
        observations: builtins.list[dict[str, object]],
        generation: int,
        epoch_history: Mapping[str, int],
    ) -> None:
        generation = _generation(generation, "control.host_store_unavailable")
        try:
            validated_agent_bindings = [
                _agent_binding_record(item, "control.host_store_unavailable")
                for item in agent_bindings
            ]
        except (KeyError, TypeError, ValueError):
            raise HostRegistryError("control.host_store_unavailable") from None
        if (
            len(registrations) > MAX_HOST_RECORDS
            or len(observations) > MAX_HOST_RECORDS
            or not set(ssh_bindings).issubset(
                {str(item["ref"]) for item in registrations}
            )
            or not {str(item["ref"]) for item in agent_bindings}.issubset(
                {str(item["ref"]) for item in registrations}
            )
            or len(epoch_history) > MAX_HOST_RECORDS
        ):
            raise HostRegistryError("control.host_store_unavailable")
        validated_history: list[dict[str, object]] = []
        for ref in sorted(epoch_history):
            epoch = _generation(
                epoch_history[ref], "control.host_store_unavailable"
            )
            if _host_ref(ref, "control.host_store_unavailable") != ref or epoch == 0:
                raise HostRegistryError("control.host_store_unavailable")
            validated_history.append({"ref": ref, "lease_epoch": epoch})
        if any(
            epoch_history.get(str(item["ref"]), 0)
            < _generation(item["lease_epoch"], "control.host_store_unavailable")
            for item in validated_agent_bindings
        ):
            raise HostRegistryError("control.host_store_unavailable")
        document = {
            "schema_version": _SCHEMA_VERSION,
            "generation": generation,
            "agent_epoch_history": validated_history,
            "registrations": registrations,
            "bindings": {
                "ssh": [
                    {"ref": ref, "binding_state": ssh_bindings[ref]}
                    for ref in sorted(ssh_bindings)
                ],
                "agent": validated_agent_bindings,
            },
            "observations": observations,
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
            observed_at=_optional_time(
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


def _agent_registration_record(
    value: Mapping[str, object], *, generation: int
) -> dict[str, object]:
    if type(value) is not dict or not _exact_keys(
        value, _STATIC_REGISTRATION_INPUT_FIELDS, "control.host_invalid"
    ):
        raise HostRegistryError("control.host_invalid")
    ref = _host_ref(value["ref"], "control.host_invalid")
    return {
        "ref": ref,
        "label": _host_label(value["label"], "control.host_invalid"),
        "role": _registered_code(value["role"], _ROLES, "control.host_invalid"),
        "transport_binding": {"kind": "ssh", "binding_ref": ref},
        "capabilities": list(_capabilities(value["capabilities"], "control.host_invalid")),
        "reachability": {"state": "unavailable"},
        "resource_evidence": {},
        "generation": _generation(generation, "control.host_invalid"),
        "observed_at": None,
        "source": "static-agent-binding",
    }


def _registration_from_probe(record: Mapping[str, object]) -> dict[str, object]:
    return {
        key: record[key]
        for key in _REGISTRATION_FIELDS
        if key in record
    }


def _registration_record(value: Mapping[str, object], error_code: str) -> dict[str, object]:
    ref = _host_ref(value["ref"], error_code)
    observed_at = value["observed_at"]
    if observed_at is not None:
        observed_at = _wire_time(_parse_time(observed_at, error_code))
    return {
        "ref": ref,
        "label": _host_label(value["label"], error_code),
        "role": _registered_code(value["role"], _ROLES, error_code),
        "transport_binding": _transport_binding(value["transport_binding"], error_code),
        "capabilities": list(_capabilities(value["capabilities"], error_code)),
        "reachability": _reachability(value["reachability"], error_code),
        "resource_evidence": _resources(value["resource_evidence"], error_code),
        "generation": _generation(value["generation"], error_code),
        "observed_at": observed_at,
        "source": _host_source(value["source"], error_code),
    }


def _agent_binding_record(value: Mapping[str, object], error_code: str) -> dict[str, object]:
    ref = _host_ref(value["ref"], error_code)
    lease_epoch = _generation(value["lease_epoch"], error_code)
    if lease_epoch == 0 or type(value["enabled"]) is not bool:
        raise HostRegistryError(error_code)
    return {
        "ref": ref,
        "client_spki_sha256": _spki_digest(value["client_spki_sha256"], error_code),
        "lease_epoch": lease_epoch,
        "enabled": value["enabled"],
    }


def _agent_binding(value: Mapping[str, object], error_code: str) -> AgentBindingV1:
    record = _agent_binding_record(value, error_code)
    return AgentBindingV1(
        str(record["ref"]),
        str(record["client_spki_sha256"]),
        _generation(record["lease_epoch"], error_code),
        bool(record["enabled"]),
    )


def _merged_hosts(
    registrations: builtins.list[dict[str, object]],
    observations: builtins.list[dict[str, object]],
) -> builtins.list[dict[str, object]]:
    by_ref = {str(item["ref"]): item for item in registrations}
    for item in observations:
        by_ref[str(item["ref"])] = item
    return [by_ref[ref] for ref in sorted(by_ref)]


def _registration_without_generation(
    value: Mapping[str, object],
) -> dict[str, object]:
    return {key: item for key, item in value.items() if key != "generation"}


def _document_generation(
    registrations: builtins.list[dict[str, object]],
    observations: builtins.list[dict[str, object]],
) -> int:
    values = [
        _generation(item["generation"], "control.host_store_unavailable")
        for item in registrations + observations
    ]
    return max(values, default=0)


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
    embedded_sensitive: bool = True,
) -> str:
    text = _public_text(value, error_code)
    normalized = _normalized_key(text, error_code)
    parts = frozenset(part for part in normalized.split("_") if part)
    compact = normalized.replace("_", "")
    if (
        parts & _SENSITIVE_VALUE_PARTS
        or embedded_sensitive
        and any(marker in compact for marker in _SENSITIVE_VALUE_SUBSTRINGS)
        or any(marker in compact for marker in _PRIVATE_VALUE_MARKERS)
    ):
        _raise(error_code)
    try:
        text.encode("ascii")
    except UnicodeError:
        _raise(error_code)
    if pattern.fullmatch(text) is None:
        _raise(error_code)
    return text


def _host_ref(value: object, error_code: str) -> str:
    return _field_string(value, pattern=_HOST_REF, error_code=error_code)


def _host_label(value: object, error_code: str) -> str:
    return _field_string(
        value,
        pattern=_HOST_LABEL,
        error_code=error_code,
        embedded_sensitive=False,
    )


def _registered_code(value: object, allowed: frozenset[str], error_code: str) -> str:
    code = _field_string(value, pattern=_CODE_TOKEN, error_code=error_code)
    if code not in allowed:
        _raise(error_code)
    return code


def _transport_kind(value: object, error_code: str) -> str:
    return _registered_code(value, _TRANSPORT_KINDS, error_code)


def _probe_source(value: object, error_code: str) -> str:
    return _registered_code(value, _PROBE_SOURCES, error_code)


def _host_source(value: object, error_code: str) -> str:
    return _registered_code(value, _HOST_SOURCES, error_code)


def _generation(value: object, error_code: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_GENERATION:
        _raise(error_code)
    return value


def _spki_digest(value: object, error_code: str) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
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


def _optional_time(value: object, error_code: str) -> datetime | None:
    if value is None:
        return None
    return _parse_time(value, error_code)


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
    if value == {}:
        return {}
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


__all__ = [
    "AgentBindingV1",
    "AgentPrincipalV1",
    "ControlHostV1",
    "HostRegistry",
    "HostRegistryError",
]
