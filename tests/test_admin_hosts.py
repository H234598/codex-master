from __future__ import annotations

from datetime import UTC, datetime
import json
import multiprocessing
from pathlib import Path
import stat
from typing import Any

import pytest

from codex_master.admin_hosts import ControlHostV1, HostRegistry, HostRegistryError


OBSERVED_AT = "2026-08-28T10:00:00Z"


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
        ("source", "other-agent"),
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
