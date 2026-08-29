from __future__ import annotations

from datetime import UTC, datetime
import json
import multiprocessing
from pathlib import Path
import stat
from typing import Any, cast

import pytest

from codex_master.admin_hosts import ControlHostV1, HostRegistry, HostRegistryError


OBSERVED_AT = "2026-08-28T10:00:00Z"


class PrivateProbeFailure(BaseException):
    def __str__(self) -> str:
        return "/srv/private synthetic-credential-marker"


class ExplodingMapping(dict[object, object]):
    def __iter__(self):  # type: ignore[no-untyped-def]
        raise PrivateProbeFailure

    def __len__(self) -> int:
        raise PrivateProbeFailure

    def __getitem__(self, key: object) -> object:  # type: ignore[override]
        raise PrivateProbeFailure

    @property
    def items(self):  # type: ignore[no-untyped-def,override]
        raise PrivateProbeFailure

    def __repr__(self) -> str:
        return "/srv/private synthetic-credential-marker"


class ExplodingSequence(list[object]):
    def __iter__(self):  # type: ignore[no-untyped-def]
        raise PrivateProbeFailure

    def __len__(self) -> int:
        raise PrivateProbeFailure

    def __getitem__(self, key: object) -> object:  # type: ignore[override]
        raise PrivateProbeFailure

    def __repr__(self) -> str:
        return "/srv/private synthetic-credential-marker"


def valid_evidence(
    *,
    label: str = "Worker One",
    role: str = "execution",
    binding_ref: str = "worker-one-ssh",
    source: str = "host-agent",
) -> dict[str, object]:
    return {
        "label": label,
        "role": role,
        "transport_binding": {"kind": "ssh", "binding_ref": binding_ref},
        "capabilities": ["codex.execute", "resource.probe"],
        "reachability": {"state": "reachable", "latency_ms": 12},
        "resource_evidence": {
            "cpu_threads": 16,
            "memory_bytes": 68_719_476_736,
        },
        "observed_at": OBSERVED_AT,
        "source": source,
        "binding_state": {
            "endpoint": "ssh://10.0.0.8:22",
            "credential": {"token": "top-secret-token"},
            "root": "/srv/codex-worker",
        },
    }


def registry_at(tmp_path: Path) -> HostRegistry:
    return HostRegistry.for_test(tmp_path)


def _record_host(root: str, ref: str, generation: int) -> None:
    registry = HostRegistry.for_test(Path(root))
    registry.record_probe(
        ref,
        generation=generation,
        evidence=valid_evidence(
            label=ref.replace("-", " ").title(), binding_ref=f"{ref}-ssh"
        ),
    )


def _write_registry_document(tmp_path: Path, payload: dict[str, object]) -> Path:
    root = tmp_path / "admin-hosts"
    root.mkdir(mode=0o700)
    document = root / "hosts.json"
    document.write_text(json.dumps(payload), encoding="utf-8")
    document.chmod(0o600)
    return document


def test_empty_registry_has_no_implicit_local_host(tmp_path: Path) -> None:
    registry = registry_at(tmp_path)

    assert registry.list() == ()


@pytest.mark.parametrize("role", ["control", "execution"])
def test_probe_materializes_typed_separate_host_roles(
    tmp_path: Path, role: str
) -> None:
    registry = registry_at(tmp_path)

    host = registry.record_probe(
        f"{role}-one", generation=4, evidence=valid_evidence(role=role)
    )

    assert isinstance(host, ControlHostV1)
    assert host.ref == f"{role}-one"
    assert host.role == role
    assert host.transport_binding == {
        "kind": "ssh",
        "binding_ref": "worker-one-ssh",
    }
    assert host.capabilities == ("codex.execute", "resource.probe")
    assert host.reachability == {"state": "reachable", "latency_ms": 12}
    assert host.resource_evidence["cpu_threads"] == 16
    assert host.generation == 4
    assert host.observed_at == datetime(2026, 8, 28, 10, 0, tzinfo=UTC)
    assert host.source == "host-agent"
    assert registry.get(host.ref) == host


@pytest.mark.parametrize("role", ["both", "local", "", None])
def test_probe_rejects_combined_or_unknown_roles(tmp_path: Path, role: object) -> None:
    evidence = valid_evidence()
    evidence["role"] = role

    with pytest.raises(HostRegistryError, match="control.host_invalid"):
        registry_at(tmp_path).record_probe(
            "worker-one", generation=1, evidence=evidence
        )


def test_host_projection_hides_connection_secrets_and_absolute_roots(
    tmp_path: Path,
) -> None:
    registry = registry_at(tmp_path)
    registry.record_probe("worker-one", generation=4, evidence=valid_evidence())

    public = registry.list()[0].public_projection()
    rendered = json.dumps(public, sort_keys=True)

    assert "credential" not in rendered
    assert "top-secret-token" not in rendered
    assert "endpoint" not in rendered
    assert "10.0.0.8" not in rendered
    assert "root" not in rendered
    assert "/srv/codex-worker" not in rendered
    assert "top-secret-token" not in repr(registry)
    assert "/srv/codex-worker" not in repr(registry.get("worker-one"))


def test_direct_host_contract_rejects_private_public_evidence() -> None:
    with pytest.raises(HostRegistryError, match="control.host_invalid"):
        ControlHostV1(
            ref="worker-one",
            label="Worker One",
            role="execution",
            transport_binding={"kind": "ssh", "binding_ref": "worker-one-ssh"},
            capabilities=("codex.execute",),
            reachability={"state": "reachable"},
            resource_evidence={"credential": "top-secret-token"},
            generation=4,
            observed_at=datetime(2026, 8, 28, 10, 0, tzinfo=UTC),
            source="host-agent",
        )


@pytest.mark.parametrize(
    "transport_binding",
    [
        {"kind": "ssh", "binding_ref": "/srv/private"},
        {"kind": "ssh", "binding_ref": "10.0.0.8"},
        {"kind": "ssh", "endpoint": "ssh://10.0.0.8"},
        {"kind": "ssh", "credential": "secret"},
    ],
)
def test_public_transport_binding_rejects_private_material(
    tmp_path: Path, transport_binding: dict[str, object]
) -> None:
    evidence = valid_evidence()
    evidence["transport_binding"] = transport_binding

    with pytest.raises(HostRegistryError, match="control.host_invalid"):
        registry_at(tmp_path).record_probe(
            "worker-one", generation=1, evidence=evidence
        )


@pytest.mark.parametrize(
    ("field", "key", "value"),
    [
        ("transport_binding", "clientSecret", "opaqueValue123"),
        ("transport_binding", "ＣＬＩＥＮＴ＿ＳＥＣＲＥＴ", "opaqueValue123"),
        ("transport_binding", "private%255Fendpoint", "opaqueValue123"),
        ("reachability", "credentialToken", "opaqueValue123"),
        ("reachability", "socketAddress", "opaqueValue123"),
        ("resource_evidence", "modelsPath", "opaqueValue123"),
        ("resource_evidence", "privateEndpoint", "opaqueValue123"),
    ],
)
def test_public_field_allowlists_reject_normalized_private_key_variants(
    tmp_path: Path, field: str, key: str, value: str
) -> None:
    evidence = valid_evidence()
    public_mapping = evidence[field]
    assert isinstance(public_mapping, dict)
    public_mapping[key] = value

    with pytest.raises(HostRegistryError, match="control.host_invalid"):
        registry_at(tmp_path).record_probe(
            "worker-one", generation=1, evidence=evidence
        )


@pytest.mark.parametrize(
    "binding_ref",
    [
        "10.0.0.8:22",
        "localhost:8022",
        "worker-one.internal:22",
        "ssh://worker-one.internal:22",
        "/run/codex-master/private.sock",
        "[fd00::8]:22",
    ],
)
def test_transport_binding_ref_cannot_encode_private_endpoint(
    tmp_path: Path, binding_ref: str
) -> None:
    evidence = valid_evidence(binding_ref=binding_ref)

    with pytest.raises(HostRegistryError, match="control.host_invalid"):
        registry_at(tmp_path).record_probe(
            "worker-one", generation=1, evidence=evidence
        )


@pytest.mark.parametrize(
    ("field", "private_value"),
    [
        ("ref", "10.0.0.8:22"),
        ("ref", "localhost"),
        ("ref", "clientSecretOpaque"),
        ("ref", "private%255Fendpoint"),
        ("label", "worker.internal:22"),
        ("label", "localhost"),
        ("label", "CredentialToken Worker"),
        ("label", "models%252Froot"),
        ("transport_kind", "localhost:11434"),
        ("transport_kind", "privateEndpoint"),
        ("transport_kind", "ssh%253A%252F%252Flocalhost"),
        ("capability", "10.0.0.8:22"),
        ("capability", "authToken:opaqueValue123"),
        ("capability", "resource%252Eprobe"),
        ("source", "worker.internal:22"),
        ("source", "credentialToken"),
        ("source", "host%252Dagent"),
        ("source", "\ud800"),
        ("binding_ref", "localhost"),
    ],
)
def test_every_public_string_field_rejects_private_or_encoded_values_without_echo(
    tmp_path: Path, field: str, private_value: str
) -> None:
    registry = registry_at(tmp_path)
    evidence = valid_evidence()
    ref = "worker-one"
    if field == "ref":
        ref = private_value
    elif field == "label":
        evidence["label"] = private_value
    elif field == "transport_kind":
        transport = cast(dict[str, object], evidence["transport_binding"])
        transport["kind"] = private_value
    elif field == "capability":
        evidence["capabilities"] = ["codex.execute", private_value]
    elif field == "binding_ref":
        transport = cast(dict[str, object], evidence["transport_binding"])
        transport["binding_ref"] = private_value
    else:
        evidence["source"] = private_value

    with pytest.raises(HostRegistryError) as captured:
        registry.record_probe(ref, generation=1, evidence=evidence)

    assert captured.value.code == "control.host_invalid"
    assert str(captured.value) == "control.host_invalid"
    assert repr(captured.value) == "HostRegistryError('control.host_invalid')"
    assert registry.list() == ()
    assert private_value not in repr(registry)


@pytest.mark.parametrize(
    ("field", "private_value"),
    [
        ("ref", "localhost:11434"),
        ("label", "privateEndpoint Worker"),
        ("transport_kind", "ssh%253A%252F%252Flocalhost"),
        ("capability", "credentialToken"),
        ("source", "worker.internal:22"),
    ],
)
def test_direct_host_contract_rejects_private_public_string_fields(
    field: str, private_value: str
) -> None:
    values: dict[str, object] = {
        "ref": "worker-one",
        "label": "Worker One",
        "role": "execution",
        "transport_binding": {"kind": "ssh", "binding_ref": "worker-one-ssh"},
        "capabilities": ("codex.execute",),
        "reachability": {"state": "reachable"},
        "resource_evidence": {"cpu_threads": 16, "memory_bytes": 1024},
        "generation": 4,
        "observed_at": datetime(2026, 8, 28, 10, 0, tzinfo=UTC),
        "source": "host-agent",
    }
    if field == "transport_kind":
        values["transport_binding"] = {
            "kind": private_value,
            "binding_ref": "worker-one-ssh",
        }
    elif field == "capability":
        values["capabilities"] = (private_value,)
    else:
        values[field] = private_value

    with pytest.raises(HostRegistryError) as captured:
        ControlHostV1(**cast(Any, values))

    assert captured.value.code == "control.host_invalid"
    assert private_value not in repr(captured.value)


def test_host_repr_redacts_ref_label_and_transport_binding_values() -> None:
    host = ControlHostV1(
        ref="worker-one",
        label="Worker One",
        role="execution",
        transport_binding={"kind": "ssh", "binding_ref": "worker-one-ssh"},
        capabilities=("codex.execute",),
        reachability={"state": "reachable"},
        resource_evidence={"cpu_threads": 16, "memory_bytes": 1024},
        generation=4,
        observed_at=datetime(2026, 8, 28, 10, 0, tzinfo=UTC),
        source="host-agent",
    )

    rendered = repr(host)

    assert rendered.startswith("ControlHostV1(")
    assert "worker-one" not in rendered
    assert "Worker One" not in rendered
    assert "ssh" not in rendered


def test_label_allowlist_does_not_reject_benign_embedded_short_fragments(
    tmp_path: Path,
) -> None:
    host = registry_at(tmp_path).record_probe(
        "worker-one",
        generation=1,
        evidence=valid_evidence(label="Curl Worker"),
    )

    assert host.label == "Curl Worker"


@pytest.mark.parametrize(
    ("field", "credential_value"),
    [
        ("ref", "sk-abcdefgh"),
        ("binding_ref", "sk-abcdefgh"),
        ("label", "AIzaABCDEFGHIJKLMNOPQRSTUVWX"),
        ("label", "Bearer opaquevalue"),
        ("label", "Basic opaquevalue"),
        ("label", "apiKey opaquevalue"),
        ("label", "api_key opaquevalue"),
        ("label", "clientSecret opaquevalue"),
        ("label", "accessToken opaquevalue"),
        ("label", "session marker"),
        ("label", "Ｂｅａｒｅｒ opaquevalue"),
        ("label", "Bearer%2520opaquevalue"),
        ("transport_kind", "sk-abcdefgh"),
        ("capability", "sk-abcdefgh"),
        ("source", "sk-abcdefgh"),
    ],
)
def test_every_public_host_string_composes_central_credential_classification(
    tmp_path: Path, field: str, credential_value: str
) -> None:
    registry = registry_at(tmp_path)
    safe = registry.record_probe("worker-one", generation=1, evidence=valid_evidence())
    evidence = valid_evidence()
    ref = "worker-two"
    if field == "ref":
        ref = credential_value
    elif field == "label":
        evidence["label"] = credential_value
    elif field == "binding_ref":
        transport = cast(dict[str, object], evidence["transport_binding"])
        transport["binding_ref"] = credential_value
    elif field == "transport_kind":
        transport = cast(dict[str, object], evidence["transport_binding"])
        transport["kind"] = credential_value
    elif field == "capability":
        evidence["capabilities"] = [credential_value]
    else:
        evidence["source"] = credential_value

    with pytest.raises(HostRegistryError) as captured:
        registry.record_probe(ref, generation=1, evidence=evidence)

    durable = (tmp_path / "admin-hosts" / "hosts.json").read_text(encoding="utf-8")
    rendered = json.dumps(safe.public_projection(), sort_keys=True) + repr(safe)
    assert captured.value.code == "control.host_invalid"
    assert repr(captured.value) == "HostRegistryError('control.host_invalid')"
    assert credential_value not in durable
    assert credential_value not in rendered
    assert registry.list() == (safe,)


@pytest.mark.parametrize(
    "label",
    [
        "Secretariat Worker",
        "Tokenized Worker",
        "Authenticationless Worker",
        "Privateer Worker",
        "Curl Worker",
    ],
)
def test_pretty_labels_do_not_treat_embedded_word_fragments_as_credentials(
    tmp_path: Path, label: str
) -> None:
    host = registry_at(tmp_path).record_probe(
        "worker-one", generation=1, evidence=valid_evidence(label=label)
    )

    assert host.label == label
    assert host.public_projection()["label"] == label


def test_nested_private_binding_values_remain_private_only(tmp_path: Path) -> None:
    evidence = valid_evidence()
    evidence["binding_state"] = {
        "endpoint": "ssh://worker.internal:22",
        "credential": {"clientSecret": "opaque-private-value"},
        "root": "/srv/codex-worker",
        "metadata": {"encodedMarker": "private%255Fendpoint"},
    }

    host = registry_at(tmp_path).record_probe(
        "worker-one", generation=1, evidence=evidence
    )
    document = json.loads(
        (tmp_path / "admin-hosts" / "hosts.json").read_text(encoding="utf-8")
    )
    public_rendered = json.dumps(host.public_projection(), sort_keys=True)
    repr_rendered = repr(host)

    assert document["bindings"][0]["binding_state"] == evidence["binding_state"]
    for private_value in (
        "worker.internal",
        "opaque-private-value",
        "/srv/codex-worker",
        "private%255Fendpoint",
    ):
        assert private_value not in public_rendered
        assert private_value not in repr_rendered


@pytest.mark.parametrize(
    ("field", "key", "value"),
    [
        ("transport_binding", "description", "public"),
        ("reachability", "detail", "public"),
        ("resource_evidence", "note", "public"),
    ],
)
def test_public_host_subobjects_reject_unknown_even_benign_fields(
    tmp_path: Path, field: str, key: str, value: str
) -> None:
    evidence = valid_evidence()
    public_mapping = evidence[field]
    assert isinstance(public_mapping, dict)
    public_mapping[key] = value

    with pytest.raises(HostRegistryError, match="control.host_invalid"):
        registry_at(tmp_path).record_probe(
            "worker-one", generation=1, evidence=evidence
        )


def test_stale_host_probe_does_not_replace_newer_generation(tmp_path: Path) -> None:
    registry = registry_at(tmp_path)
    newer = registry.record_probe("worker-one", generation=4, evidence=valid_evidence())

    with pytest.raises(HostRegistryError, match="credential.generation_conflict"):
        registry.record_probe("worker-one", generation=3, evidence=valid_evidence())

    assert registry.get("worker-one") == newer


def test_equal_generation_is_idempotent_only_for_identical_bound_evidence(
    tmp_path: Path,
) -> None:
    registry = registry_at(tmp_path)
    first = registry.record_probe("worker-one", generation=4, evidence=valid_evidence())

    assert (
        registry.record_probe("worker-one", generation=4, evidence=valid_evidence())
        == first
    )

    for field, replacement in [
        ("role", "control"),
        ("source", "inventory-agent"),
        ("observed_at", "2026-08-28T10:00:01Z"),
        ("capabilities", ["resource.probe"]),
        (
            "transport_binding",
            {"kind": "ssh", "binding_ref": "replacement-ssh"},
        ),
        (
            "binding_state",
            {
                "endpoint": "ssh://10.0.0.9:22",
                "credential": {"token": "replacement-token"},
                "root": "/srv/replacement",
            },
        ),
    ]:
        changed = valid_evidence()
        changed[field] = replacement
        with pytest.raises(HostRegistryError, match="credential.generation_conflict"):
            registry.record_probe("worker-one", generation=4, evidence=changed)

    assert registry.get("worker-one") == first


def test_newer_probe_replaces_prior_evidence_and_survives_restart(
    tmp_path: Path,
) -> None:
    registry = registry_at(tmp_path)
    registry.record_probe("worker-one", generation=4, evidence=valid_evidence())
    changed = valid_evidence(label="Worker One Renamed", source="inventory-agent")
    changed["observed_at"] = "2026-08-28T10:01:00Z"

    current = registry.record_probe("worker-one", generation=5, evidence=changed)

    assert current.label == "Worker One Renamed"
    assert current.generation == 5
    assert current.source == "inventory-agent"
    assert registry_at(tmp_path).get("worker-one") == current


def test_legacy_document_migrates_binding_into_separate_v2_state(
    tmp_path: Path,
) -> None:
    evidence = valid_evidence()
    legacy = {
        "schema_version": 1,
        "hosts": [
            {
                "ref": "worker-one",
                "generation": 4,
                **evidence,
            }
        ],
    }
    document = _write_registry_document(tmp_path, legacy)

    host = registry_at(tmp_path).get("worker-one")
    migrated = json.loads(document.read_text(encoding="utf-8"))

    assert host.generation == 4
    assert migrated["schema_version"] == 2
    assert set(migrated) == {"schema_version", "hosts", "bindings"}
    assert "binding_state" not in migrated["hosts"][0]
    assert migrated["bindings"] == [
        {"ref": "worker-one", "binding_state": evidence["binding_state"]}
    ]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":2,"hosts":',
        b'{"schema_version":9,"hosts":[],"bindings":[]}',
        b'{"schema_version":2,"hosts":[],"bindings":[],"extra":true}',
    ],
)
def test_corrupt_truncated_or_unknown_state_fails_closed(
    tmp_path: Path, raw: bytes
) -> None:
    document = _write_registry_document(tmp_path, {"schema_version": 2})
    document.write_bytes(raw)

    with pytest.raises(HostRegistryError, match="control.host_store_unavailable"):
        registry_at(tmp_path)


def test_probe_digest_detects_persisted_host_or_binding_tampering(
    tmp_path: Path,
) -> None:
    registry = registry_at(tmp_path)
    registry.record_probe("worker-one", generation=4, evidence=valid_evidence())
    document = tmp_path / "admin-hosts" / "hosts.json"
    payload = json.loads(document.read_text(encoding="utf-8"))
    payload["bindings"][0]["binding_state"]["root"] = "/srv/tampered"
    document.write_text(json.dumps(payload), encoding="utf-8")
    document.chmod(0o600)

    with pytest.raises(HostRegistryError, match="control.host_store_unavailable"):
        registry_at(tmp_path)


def test_concurrent_writers_preserve_distinct_hosts(tmp_path: Path) -> None:
    context = multiprocessing.get_context("fork")
    processes = [
        context.Process(target=_record_host, args=(str(tmp_path), f"worker-{i}", i))
        for i in range(1, 9)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)

    assert [process.exitcode for process in processes] == [0] * len(processes)
    assert [host.ref for host in registry_at(tmp_path).list()] == [
        f"worker-{i}" for i in range(1, 9)
    ]


def test_state_files_remain_private(tmp_path: Path) -> None:
    registry = registry_at(tmp_path)
    registry.record_probe("worker-one", generation=1, evidence=valid_evidence())
    root = tmp_path / "admin-hosts"

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "hosts.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((root / ".hive-state.lock").stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "attack", ["document_symlink", "document_hardlink", "lock_symlink"]
)
def test_path_attacks_fail_closed_without_touching_target(
    tmp_path: Path, attack: str
) -> None:
    registry = registry_at(tmp_path)
    registry.record_probe("worker-one", generation=1, evidence=valid_evidence())
    root = tmp_path / "admin-hosts"
    name = ".hive-state.lock" if attack == "lock_symlink" else "hosts.json"
    attacked = root / name
    target = tmp_path / "outside"
    target.write_text("unchanged", encoding="utf-8")
    target.chmod(0o600)
    attacked.unlink()
    if attack == "document_hardlink":
        attacked.hardlink_to(target)
    else:
        attacked.symlink_to(target)

    with pytest.raises(HostRegistryError, match="control.host_store_unavailable"):
        registry.get("worker-one")

    assert target.read_text(encoding="utf-8") == "unchanged"


def test_errors_and_repr_never_echo_private_input(tmp_path: Path) -> None:
    evidence: dict[str, Any] = valid_evidence()
    evidence["unexpected-/srv/private-top-secret"] = True

    with pytest.raises(HostRegistryError) as captured:
        registry_at(tmp_path).record_probe(
            "worker-one", generation=1, evidence=evidence
        )

    assert str(captured.value) == "control.host_invalid"
    assert repr(captured.value) == "HostRegistryError('control.host_invalid')"
    assert "private-top-secret" not in repr(captured.value)


@pytest.mark.parametrize(
    "location",
    [
        "evidence",
        "transport_binding",
        "reachability",
        "resource_evidence",
        "binding_state",
        "capabilities",
    ],
)
def test_foreign_probe_containers_fail_typed_without_private_exception_context(
    tmp_path: Path, location: str
) -> None:
    evidence = valid_evidence()
    supplied: object = evidence
    if location == "evidence":
        supplied = ExplodingMapping(evidence)
    elif location == "capabilities":
        evidence[location] = ExplodingSequence(["codex.execute"])
    else:
        evidence[location] = ExplodingMapping(
            cast(dict[object, object], evidence[location])
        )

    with pytest.raises(HostRegistryError) as captured:
        registry_at(tmp_path).record_probe(
            "worker-one",
            generation=1,
            evidence=cast(Any, supplied),
        )

    assert captured.value.code == "control.host_invalid"
    assert repr(captured.value) == "HostRegistryError('control.host_invalid')"
    assert captured.value.__context__ is None
    assert "private" not in repr(captured.value).casefold()
    assert "credential" not in repr(captured.value).casefold()


def test_direct_contract_rejects_foreign_mapping_without_calling_repr() -> None:
    with pytest.raises(HostRegistryError) as captured:
        ControlHostV1(
            ref="worker-one",
            label="Worker One",
            role="execution",
            transport_binding=cast(Any, ExplodingMapping()),
            capabilities=("codex.execute",),
            reachability={"state": "reachable"},
            resource_evidence={"cpu_threads": 16, "memory_bytes": 1024},
            generation=4,
            observed_at=datetime(2026, 8, 28, 10, 0, tzinfo=UTC),
            source="host-agent",
        )

    assert captured.value.code == "control.host_invalid"
    assert captured.value.__context__ is None


@pytest.mark.parametrize("schema_version", [True, 1.0, 2.0])
def test_state_schema_version_requires_exact_integer(
    tmp_path: Path, schema_version: object
) -> None:
    payload: dict[str, object]
    if schema_version == 2.0:
        payload = {"schema_version": schema_version, "hosts": [], "bindings": []}
    else:
        payload = {"schema_version": schema_version, "hosts": []}
    _write_registry_document(tmp_path, payload)

    with pytest.raises(HostRegistryError, match="control.host_store_unavailable"):
        registry_at(tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("generation", True),
        ("generation", 4.0),
        ("latency_ms", True),
        ("latency_ms", 12.0),
        ("cpu_threads", True),
        ("cpu_threads", 16.0),
        ("memory_bytes", True),
        ("memory_bytes", 1024.0),
    ],
)
def test_probe_numeric_fields_reject_bool_and_float(
    tmp_path: Path, field: str, value: object
) -> None:
    evidence = valid_evidence()
    generation: object = 4
    if field == "generation":
        generation = value
    elif field == "latency_ms":
        reachability = cast(dict[str, object], evidence["reachability"])
        reachability[field] = value
    else:
        resources = cast(dict[str, object], evidence["resource_evidence"])
        resources[field] = value

    with pytest.raises(HostRegistryError, match="control.host_invalid"):
        registry_at(tmp_path).record_probe(
            "worker-one", generation=cast(Any, generation), evidence=evidence
        )
