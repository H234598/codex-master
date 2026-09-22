from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from base64 import urlsafe_b64decode
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import the_hive.usage_snapshot as usage_snapshot


PRODUCER_NOW = datetime(2026, 8, 31, 12, 1, tzinfo=UTC)
PRODUCER_ROOT = Path(
    os.environ.get("THE_HIVE_TEST_CODEX_USAGE_ROOT", "/home/teladi/codex-usage")
)
PRODUCER_COMMIT = "df2c2b3cdd48b0fdd0f020eedbd7055343ad6b6a"
PRODUCER_SOURCE_FILES = (
    "pyproject.toml",
    "src/codex_usage/__init__.py",
    "src/codex_usage/account_lock.py",
    "src/codex_usage/config.py",
    "src/codex_usage/consumption.py",
    "src/codex_usage/extractor.py",
    "src/codex_usage/integration_attestation.py",
    "src/codex_usage/integration_evidence.py",
    "src/codex_usage/integration_entrypoint.py",
    "src/codex_usage/integration_pool_authority.py",
    "src/codex_usage/integration_snapshot.py",
    "src/codex_usage/json_utils.py",
    "src/codex_usage/models.py",
    "src/codex_usage/history.py",
    "src/codex_usage/pool_authority_owner.py",
    "src/codex_usage/private_io.py",
    "src/codex_usage/source_lock.py",
    "src/codex_usage/state_maintenance.py",
    "src/codex_usage/state.py",
    "src/codex_usage/usage_limits.py",
    "src/codex_usage/usage_resets.py",
)
PRODUCER_TEST_HARNESS_FILES = ("src/codex_usage/integration_installer.py",)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def private_file(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def producer_file(relative: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(PRODUCER_ROOT), "show", f"{PRODUCER_COMMIT}:{relative}"],
        check=True,
        capture_output=True,
    ).stdout


def write_producer_source(root: Path) -> Path:
    source_root = root / "producer-source"
    private_dir(source_root)
    for relative in PRODUCER_SOURCE_FILES + PRODUCER_TEST_HARNESS_FILES:
        destination = source_root / relative
        private_dir(destination.parent)
        private_file(destination, producer_file(relative))
    return source_root


def write_producer_golden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, Path]]:
    """Create authentic, pinned D299 bytes only in pytest's temp directory."""
    source_root = write_producer_source(tmp_path)
    state_home = tmp_path / "producer-state"
    data_home = tmp_path / "producer-data"
    temporary_root = tmp_path / "producer-tmp"
    lock_home = tmp_path / "producer-lock-home"
    for path in (state_home, data_home, temporary_root, lock_home):
        private_dir(path)
    private_dir(data_home / "codex-usage")

    monkeypatch.syspath_prepend(str(source_root / "src"))
    from codex_usage import integration_evidence, integration_pool_authority, integration_snapshot, private_io
    from codex_usage.integration_attestation import verify_active_manifest_at
    from codex_usage.integration_installer import install_release

    fake_pwd = SimpleNamespace(
        getpwuid=lambda _uid: SimpleNamespace(pw_dir=str(lock_home))
    )
    monkeypatch.setattr(private_io, "pwd", fake_pwd)
    release = install_release(
        source_root=source_root,
        state_home=state_home,
        data_home=data_home,
        python_executable=Path(sys.executable),
        temporary_root=temporary_root,
    )
    verified = verify_active_manifest_at(
        state_home=state_home,
        data_home=data_home,
        expected_entrypoint_path=release.entrypoint_path,
    )
    authority_source = json.loads(
        producer_file("tests/fixtures/pool_authority_v2/source-v2-positive.json")
    )
    payload_document = json.loads(
        producer_file("tests/fixtures/pool_authority_v2/usage-v2-positive.json")
    )
    private_file(
        state_home / "codex-usage" / "integration" / "pool-authority-source-v2.json",
        integration_pool_authority.serialize_pool_authority_source(authority_source),
    )
    source_input_contract = {
        "current_directory": {
            "device": 0,
            "gid": 0,
            "inode": 0,
            "mode": 0o700,
            "uid": 0,
        },
        "history": {
            "consumed_rows": [],
            "database": None,
            "shm": None,
            "wal": None,
        },
        "records": [],
        "source_input_binding_schema_version": 1,
    }
    integration_evidence.publish_evidence_generation(
        integration_snapshot.serialize_schema2_document(payload_document),
        state_home=state_home,
        data_home=data_home,
        verified_active_manifest=verified,
        source_input_contract=source_input_contract,
        source_input_revalidator=lambda: source_input_contract,
    )
    monkeypatch.setattr(
        usage_snapshot,
        "pwd",
        fake_pwd,
        raising=False,
    )
    integration = state_home / "codex-usage" / "integration"
    pointer = json.loads((integration / "current.json").read_text(encoding="utf-8"))
    generation = integration / "generations" / pointer["current_generation_id"]
    return state_home, {
        "active": integration / "active.json",
        "pointer": integration / "current.json",
        "binding": generation / "account-usage-v2.binding.json",
        "payload": generation / "account-usage-v2.json",
        "authority": generation / "pool-authority-v2.json",
        "source_inputs": generation / "source-inputs-v2.json",
    }


def read_golden(state_home: Path) -> usage_snapshot.UsageEvidenceV2:
    return usage_snapshot.read_usage_evidence_v2(
        state_home=state_home, clock=lambda: PRODUCER_NOW
    )


def refresh_current_binding(paths: dict[str, Path]) -> None:
    binding = json.loads(paths["binding"].read_text(encoding="utf-8"))
    payload = paths["payload"].read_bytes()
    authority = paths["authority"].read_bytes()
    source_inputs = paths["source_inputs"].read_bytes()
    usage = binding["usage_binding"]
    usage["payload_sha256"] = digest(payload)
    usage["payload_size_bytes"] = len(payload)
    binding["pool_authority_sha256"] = digest(authority)
    binding["pool_authority_size_bytes"] = len(authority)
    binding["source_inputs_sha256"] = digest(source_inputs)
    binding["source_inputs_size_bytes"] = len(source_inputs)
    binding_bytes = canonical(binding)
    private_file(paths["binding"], binding_bytes)
    pointer = json.loads(paths["pointer"].read_text(encoding="utf-8"))
    pointer["current_binding_sha256"] = digest(binding_bytes)
    private_file(paths["pointer"], canonical(pointer))


def test_d300_pinned_producer_06542_golden_generation_is_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, _paths = write_producer_golden(tmp_path, monkeypatch)

    result = usage_snapshot.read_usage_evidence_v2(
        state_home=state_home, clock=lambda: PRODUCER_NOW
    )

    assert result.status == "complete"
    assert type(result) is usage_snapshot.UsageEvidenceV2
    assert not hasattr(result, "_reader_attestation")
    assert tuple(account.account_id for account in result.accounts) == ("synthetic-alpha",)
    integration = state_home / "codex-usage" / "integration"
    pointer = json.loads((integration / "current.json").read_text(encoding="utf-8"))
    active = json.loads((integration / "active.json").read_text(encoding="utf-8"))
    binding = json.loads(
        (
            integration
            / "generations"
            / pointer["current_generation_id"]
            / "account-usage-v2.binding.json"
        ).read_text(encoding="utf-8")
    )

    assert result.generation_id == pointer["current_generation_id"]
    assert active["version"] == "0.6.542"
    assert active["release_id"] == "0.6.542-8da41af5293cf481"
    assert (
        active["source_manifest_sha256"]
        == "8da41af5293cf4816a04db5443b14c718d496756c666ea8854f8b053021f14f0"
    )
    assert binding["usage_binding"]["producer_version"] == "0.6.542"
    assert binding["usage_binding"]["release_id"] == "0.6.542-8da41af5293cf481"
    assert (
        binding["usage_binding"]["source_manifest_sha256"]
        == "8da41af5293cf4816a04db5443b14c718d496756c666ea8854f8b053021f14f0"
    )


def _write_json(path: Path, value: object, *, newline: bool = False) -> None:
    private_file(path, canonical(value) + (b"\n" if newline else b""))


def _rewrite_pointer(paths: dict[str, Path], pointer: dict[str, object]) -> None:
    _write_json(paths["pointer"], pointer)


def _rewrite_binding(paths: dict[str, Path], binding: dict[str, object]) -> None:
    _write_json(paths["binding"], binding)
    pointer = json.loads(paths["pointer"].read_text(encoding="utf-8"))
    pointer["current_binding_sha256"] = digest(paths["binding"].read_bytes())
    _rewrite_pointer(paths, pointer)


@pytest.mark.parametrize(
    "target", ("active", "pointer", "binding", "payload", "authority", "source_inputs")
)
def test_06538_missing_required_current_document_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    paths[target].unlink()

    assert read_golden(state_home).status == "unavailable"


@pytest.mark.parametrize(
    ("target", "mutate"),
    (
        ("active", lambda value: value.pop("wheel_sha256")),
        ("pointer", lambda value: value.update({"unexpected": True})),
        ("binding", lambda value: value.pop("pool_authority_sha256")),
        ("binding", lambda value: value["usage_binding"].pop("payload_sha256")),
        ("payload", lambda value: value["accounts"][0].pop("freshness")),
        ("authority", lambda value: value["authorities"][0].pop("provider")),
        ("source_inputs", lambda value: value.pop("owner_source")),
    ),
)
def test_06538_closed_field_sets_are_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    mutate: object,
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    value = json.loads(paths[target].read_text(encoding="utf-8"))
    assert callable(mutate)
    mutate(value)
    _write_json(paths[target], value, newline=target == "active")
    if target == "binding":
        _rewrite_binding(paths, value)
    elif target in {"payload", "authority", "source_inputs"}:
        refresh_current_binding(paths)

    assert read_golden(state_home).status == "invalid"


@pytest.mark.parametrize(
    "retired_version", ("0.6.537", "0.6.538", "0.6.539", "0.6.540")
)
@pytest.mark.parametrize(
    ("target", "field"),
    (
        ("active", "version"),
        ("binding", "producer_version"),
        ("authority", "producer_version"),
    ),
)
def test_retired_producer_versions_have_no_consumer_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    field: str,
    retired_version: str,
) -> None:
    """A defect accepting a prior producer line must make this read complete."""
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    value = json.loads(paths[target].read_text(encoding="utf-8"))
    if target == "binding":
        value["usage_binding"][field] = retired_version
        _rewrite_binding(paths, value)
    else:
        value[field] = retired_version
        _write_json(paths[target], value, newline=target == "active")
        refresh_current_binding(paths)

    assert read_golden(state_home).status == "invalid"


@pytest.mark.parametrize(
    ("target", "mutate"),
    (
        ("active", lambda value: value.update({"version": "0.6.537"})),
        ("pointer", lambda value: value.update({"pointer_schema_version": 2})),
        ("binding", lambda value: value["usage_binding"].update({"producer_version": "0.6.537"})),
        ("binding", lambda value: value.update({"binding_schema_version": 1})),
        ("binding", lambda value: value["usage_binding"].update({"usage_binding_schema_version": 1})),
        ("payload", lambda value: value.update({"schema_version": 1})),
        ("authority", lambda value: value.update({"pool_authority_schema_version": 1})),
        ("authority", lambda value: value.update({"producer_version": "0.6.537"})),
    ),
)
def test_06538_versions_and_legacy_parallel_path_are_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    mutate: object,
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    value = json.loads(paths[target].read_text(encoding="utf-8"))
    assert callable(mutate)
    mutate(value)
    _write_json(paths[target], value, newline=target == "active")
    if target == "binding":
        _rewrite_binding(paths, value)
    elif target in {"payload", "authority"}:
        refresh_current_binding(paths)

    assert read_golden(state_home).status == "invalid"


@pytest.mark.parametrize(
    ("target", "mutate"),
    (
        ("binding", lambda value: value["usage_binding"].update({"payload_sha256": "0" * 64})),
        ("binding", lambda value: value["usage_binding"].update({"payload_size_bytes": 1})),
        ("binding", lambda value: value.update({"pool_authority_sha256": "0" * 64})),
        ("binding", lambda value: value.update({"pool_authority_size_bytes": 1})),
        ("binding", lambda value: value["usage_binding"].update({"generation_id": "0" * 32})),
        ("binding", lambda value: value["usage_binding"].update({"release_id": "0.6.540-0000000000000000"})),
        ("authority", lambda value: value.update({"generation_id": "0" * 32})),
        ("authority", lambda value: value.update({"release_id": "0.6.540-0000000000000000"})),
    ),
)
def test_06538_digest_size_generation_and_release_crossbindings_are_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    mutate: object,
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    value = json.loads(paths[target].read_text(encoding="utf-8"))
    assert callable(mutate)
    mutate(value)
    _write_json(paths[target], value)
    if target == "binding":
        _rewrite_binding(paths, value)
    else:
        refresh_current_binding(paths)

    assert read_golden(state_home).status == "invalid"


def test_06538_source_input_digest_and_exact_manifest_pin_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path / "shape", monkeypatch)
    source_inputs = json.loads(paths["source_inputs"].read_text(encoding="utf-8"))
    source_inputs["owner_source"]["mode"] = 0o644
    _write_json(paths["source_inputs"], source_inputs)
    refresh_current_binding(paths)

    assert read_golden(state_home).status == "invalid"

    state_home, paths = write_producer_golden(tmp_path / "retired-source", monkeypatch)
    source_inputs = json.loads(paths["source_inputs"].read_text(encoding="utf-8"))
    source_inputs["history"]["consumed_rows"] = [
        {
            "account_id": "synthetic-alpha",
            "pool": "gpt-5.3-codex-spark",
            "rows_sha256": "0" * 64,
            "sample_count": 0,
            "window_seconds": 18000,
        }
    ]
    _write_json(paths["source_inputs"], source_inputs)
    refresh_current_binding(paths)

    assert read_golden(state_home).status == "invalid"

    state_home, paths = write_producer_golden(tmp_path / "digest", monkeypatch)
    binding = json.loads(paths["binding"].read_text(encoding="utf-8"))
    binding["source_inputs_sha256"] = "0" * 64
    _rewrite_binding(paths, binding)

    assert read_golden(state_home).status == "invalid"

    state_home, paths = write_producer_golden(tmp_path / "manifest", monkeypatch)
    active = json.loads(paths["active"].read_text(encoding="utf-8"))
    active["source_manifest_sha256"] = "0" * 64
    _write_json(paths["active"], active, newline=True)

    assert read_golden(state_home).status == "invalid"


def test_06538_previous_current_self_link_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    pointer = json.loads(paths["pointer"].read_text(encoding="utf-8"))
    pointer["previous_generation_id"] = pointer["current_generation_id"]
    pointer["previous_binding_sha256"] = pointer["current_binding_sha256"]
    _rewrite_pointer(paths, pointer)

    assert read_golden(state_home).status == "invalid"


def test_06538_authority_usage_account_set_mismatch_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    payload = json.loads(paths["payload"].read_text(encoding="utf-8"))
    payload["accounts"][0]["account_id"] = "other-account"
    _write_json(paths["payload"], payload)
    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    authority["usage_payload_sha256"] = digest(paths["payload"].read_bytes())
    _write_json(paths["authority"], authority)
    refresh_current_binding(paths)

    assert read_golden(state_home).status == "invalid"


@pytest.mark.parametrize("unsafe", ("symlink", "hardlink", "mode"))
def test_06538_authority_filesystem_substitution_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    target = paths["authority"]
    if unsafe == "symlink":
        replacement = tmp_path / "authority-outside.json"
        private_file(replacement, target.read_bytes())
        target.unlink()
        target.symlink_to(replacement)
    elif unsafe == "hardlink":
        os.link(target, target.with_name("authority-linked.json"))
    else:
        target.chmod(0o644)

    assert read_golden(state_home).status == "invalid"


def test_06538_payload_toctou_name_swap_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    original_read = os.read
    target = paths["payload"]
    original_inode = target.stat().st_ino
    swapped = False

    def swap_after_open(descriptor: int, count: int) -> bytes:
        nonlocal swapped
        if not swapped and os.fstat(descriptor).st_ino == original_inode:
            swapped = True
            replacement = target.with_name("payload-replacement.json")
            private_file(replacement, target.read_bytes())
            os.replace(replacement, target)
        return original_read(descriptor, count)

    monkeypatch.setattr(usage_snapshot.os, "read", swap_after_open)

    assert read_golden(state_home).status == "invalid"
    assert swapped is True


def test_06538_hashed_shared_lock_contention_is_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    integration = paths["pointer"].parent
    expected_names = {
        usage_snapshot._evidence_lock_name(integration / "producer-install"),
        usage_snapshot._evidence_lock_name(integration / "current.json"),
    }
    lock_root = next(
        path for path in (tmp_path / "producer-lock-home").rglob("locks") if path.is_dir()
    )
    assert expected_names.issubset({path.name for path in lock_root.iterdir()})

    def blocked_lock(*_args: object) -> None:
        raise BlockingIOError()

    monkeypatch.setattr(
        usage_snapshot,
        "fcntl",
        SimpleNamespace(LOCK_NB=4, LOCK_SH=1, LOCK_UN=8, flock=blocked_lock),
    )

    assert read_golden(state_home).status == "busy"


def _rebind_after_active_record_change(paths: dict[str, Path]) -> None:
    """Rehash a generation after one RECORD row is removed, without other changes."""
    from codex_usage.integration_attestation import _release_tree_sha256

    active = json.loads(paths["active"].read_text(encoding="utf-8"))
    record = Path(active["record_path"])
    rows = record.read_text(encoding="utf-8").splitlines(keepends=True)
    removed = [
        row
        for row in rows
        if row.split(",", 1)[0] == "codex_usage/integration_entrypoint.py"
    ]
    assert len(removed) == 1
    private_file(record, "".join(row for row in rows if row not in removed).encode("utf-8"))
    active["record_sha256"] = digest(record.read_bytes())
    active["release_tree_sha256"] = _release_tree_sha256(
        release_dir=Path(active["release_dir"])
    )
    _write_json(paths["active"], active, newline=True)

    binding = json.loads(paths["binding"].read_text(encoding="utf-8"))
    binding["usage_binding"]["active_manifest_sha256"] = digest(
        paths["active"].read_bytes()
    )
    _write_json(paths["binding"], binding)
    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    authority["usage_binding_sha256"] = digest(canonical(binding["usage_binding"]))
    _write_json(paths["authority"], authority)
    refresh_current_binding(paths)


def _producer_canonical_payload(document: object) -> dict[str, object]:
    from codex_usage import integration_snapshot

    return json.loads(integration_snapshot.serialize_schema2_document(document))


def _payload_with_complete_evidence(paths: dict[str, Path]) -> dict[str, object]:
    """Use only the snapshot serializer's real V2 fields and its canonical bytes."""
    document = json.loads(paths["payload"].read_text(encoding="utf-8"))
    account = document["accounts"][0]
    account["limits"] = [
        {
            "pool": "main",
            "remaining_percent": 50.0,
            "reset_at": "2026-08-31T13:00:00Z",
            "used_percent": 50.0,
            "window_seconds": 18000,
        },
        {
            "pool": "spark",
            "remaining_percent": 75.0,
            "reset_at": "2026-08-31T13:10:00Z",
            "used_percent": 25.0,
            "window_seconds": 604800,
        },
    ]
    account["tracker_evidence"] = [
        {
            "coverage": "complete",
            "ema_time_constant_seconds": 3600,
            "first_sample_at": "2026-08-31T11:50:00Z",
            "last_sample_at": "2026-08-31T12:00:00Z",
            "limit_window_seconds": 18000,
            "pool": "main",
            "projected_used_percent_at_reset": 100.0,
            "rate_percentage_points_per_second": 1.0 / 60.0,
            "reset_generation": "reset-main",
            "sample_count": 2,
        },
        {
            "coverage": "complete",
            "ema_time_constant_seconds": 3600,
            "first_sample_at": "2026-08-31T11:50:00Z",
            "last_sample_at": "2026-08-31T12:00:00Z",
            "limit_window_seconds": 604800,
            "pool": "spark",
            "projected_used_percent_at_reset": 100.0,
            "rate_percentage_points_per_second": 1.0 / 60.0,
            "reset_generation": "reset-spark",
            "sample_count": 2,
        },
    ]
    return _producer_canonical_payload(document)


def _rebind_payload_and_authority(
    paths: dict[str, Path], payload: dict[str, object], authorities: list[object]
) -> None:
    """Rebind altered payload bytes through every real V2 hash connection."""
    from codex_usage import integration_pool_authority

    _write_json(paths["payload"], payload)
    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    authority["authorities"] = authorities
    authority["usage_payload_sha256"] = digest(paths["payload"].read_bytes())
    _write_json(paths["authority"], authority)
    refresh_current_binding(paths)

    binding = json.loads(paths["binding"].read_text(encoding="utf-8"))
    authority["usage_binding_sha256"] = digest(canonical(binding["usage_binding"]))
    private_file(
        paths["authority"],
        integration_pool_authority.serialize_pool_authority_projection(authority),
    )
    refresh_current_binding(paths)


def _model_capability_entry(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "account_id": "synthetic-alpha",
        "catalog_fresh_until": "2026-08-31T12:15:00Z",
        "catalog_observed_at": "2026-08-31T12:00:00Z",
        "catalog_visible": True,
        "meter_visible": True,
        "model_id": "gpt-5.3-codex-spark",
        "runner_id": "codex_cli",
        "runner_invocable": True,
        "supported_in_api": True,
    }
    entry.update(overrides)
    return entry


def _rebind_model_invocability(
    paths: dict[str, Path], projection: object
) -> None:
    """Bind a V3 model-capability projection through the real generation chain."""
    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    authority["pool_authority_schema_version"] = 3
    authority["model_capabilities"] = projection
    _write_json(paths["authority"], authority)
    refresh_current_binding(paths)

    binding = json.loads(paths["binding"].read_text(encoding="utf-8"))
    authority["usage_binding_sha256"] = digest(canonical(binding["usage_binding"]))
    _write_json(paths["authority"], authority)
    refresh_current_binding(paths)


def _rebind_without_model_invocability(paths: dict[str, Path]) -> None:
    """Bind a V3 authority whose valid usage data has no capability projection."""
    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    authority["pool_authority_schema_version"] = 3
    authority.pop("model_capabilities", None)
    _write_json(paths["authority"], authority)
    refresh_current_binding(paths)

    binding = json.loads(paths["binding"].read_text(encoding="utf-8"))
    authority["usage_binding_sha256"] = digest(canonical(binding["usage_binding"]))
    _write_json(paths["authority"], authority)
    refresh_current_binding(paths)


def _model_invocability_projection(*entries: object) -> dict[str, object]:
    return {"capability_schema_version": 1, "entries": list(entries)}


def test_06538_model_invocability_is_unattested_without_bound_v3_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, _paths = write_producer_golden(tmp_path, monkeypatch)

    evidence = read_golden(state_home)

    assert evidence.status == "complete"
    assert evidence.model_invocability.status == "unattested"
    assert evidence.model_invocability.capabilities == ()
    assert (
        usage_snapshot.find_model_invocability(
            evidence,
            account_id="synthetic-alpha",
            model_id="gpt-5.3-codex-spark",
            runner_id="codex_cli",
        )
        is None
    )


def test_d236_missing_v3_model_capabilities_preserve_valid_usage_but_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    payload = _payload_with_complete_evidence(paths)
    authorities = json.loads(paths["authority"].read_text(encoding="utf-8"))["authorities"]
    _rebind_payload_and_authority(paths, payload, authorities)
    _rebind_without_model_invocability(paths)

    evidence = read_golden(state_home)
    display = usage_snapshot.display_snapshot_from_evidence(
        evidence, known_account_ids=frozenset({"synthetic-alpha"})
    )

    assert evidence.status == "complete"
    assert evidence.model_invocability.status == "unattested"
    assert evidence.model_invocability.capabilities == ()
    assert display.source == "live"
    assert tuple(limit.pool for limit in display.accounts[0].limits) == ("main", "spark")


def test_06538_bound_native_model_capability_preserves_usage_display(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    payload = _payload_with_complete_evidence(paths)
    authorities = json.loads(paths["authority"].read_text(encoding="utf-8"))["authorities"]
    _rebind_payload_and_authority(paths, payload, authorities)
    _rebind_model_invocability(
        paths, _model_invocability_projection(_model_capability_entry())
    )

    evidence = read_golden(state_home)
    capability = usage_snapshot.find_model_invocability(
        evidence,
        account_id="synthetic-alpha",
        model_id="gpt-5.3-codex-spark",
        runner_id="codex_cli",
    )
    display = usage_snapshot.display_snapshot_from_evidence(
        evidence, known_account_ids=frozenset({"synthetic-alpha"})
    )

    assert evidence.status == "complete"
    assert evidence.model_invocability.status == "complete"
    assert capability == usage_snapshot.ModelInvocabilityV1(
        "synthetic-alpha",
        "gpt-5.3-codex-spark",
        "codex_cli",
        True,
        True,
        True,
        True,
    )
    assert display.source == "live"
    assert tuple(limit.pool for limit in display.accounts[0].limits) == ("main", "spark")


def test_usage_evidence_subclass_never_attests_model_invocability_or_display(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    _rebind_model_invocability(
        paths, _model_invocability_projection(_model_capability_entry())
    )
    evidence = read_golden(state_home)

    class CallerUsageEvidenceV2(usage_snapshot.UsageEvidenceV2):
        pass

    derived = CallerUsageEvidenceV2(
        evidence.accounts,
        evidence.status,
        evidence.captured_at,
        evidence.generated_at,
        evidence.pool_authorities,
        evidence.model_invocability,
        evidence.generation_id,
    )

    assert (
        usage_snapshot.find_model_invocability(
            derived,
            account_id="synthetic-alpha",
            model_id="gpt-5.3-codex-spark",
            runner_id="codex_cli",
        )
        is None
    )
    display = usage_snapshot.display_snapshot_from_evidence(
        derived, known_account_ids=frozenset({"synthetic-alpha"})
    )
    assert display.source == "unavailable"
    assert display.stale is True
    assert display.warnings == ("usage_unavailable",)


def test_06538_positive_interactive_codex_cli_capability_keeps_api_state_separate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    _rebind_model_invocability(
        paths,
        _model_invocability_projection(
            _model_capability_entry(supported_in_api=False, runner_invocable=True)
        ),
    )

    capability = usage_snapshot.find_model_invocability(
        read_golden(state_home),
        account_id="synthetic-alpha",
        model_id="gpt-5.3-codex-spark",
        runner_id="codex_cli",
    )

    assert capability is not None
    assert capability.runner_id == "codex_cli"
    assert capability.catalog_visible is True
    assert capability.supported_in_api is False
    assert capability.runner_invocable is True


def test_06538_meter_only_model_evidence_never_attests_catalog_or_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    _rebind_model_invocability(
        paths,
        _model_invocability_projection(
            _model_capability_entry(
                catalog_visible=False,
                supported_in_api=False,
                runner_invocable=False,
            )
        ),
    )

    capability = usage_snapshot.find_model_invocability(
        read_golden(state_home),
        account_id="synthetic-alpha",
        model_id="gpt-5.3-codex-spark",
        runner_id="codex_cli",
    )

    assert capability is not None
    assert capability.meter_visible is True
    assert capability.catalog_visible is False
    assert capability.runner_invocable is False


def test_06538_extreme_model_capability_timestamp_is_locally_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    payload = _payload_with_complete_evidence(paths)
    authorities = json.loads(paths["authority"].read_text(encoding="utf-8"))["authorities"]
    _rebind_payload_and_authority(paths, payload, authorities)
    _rebind_model_invocability(
        paths,
        _model_invocability_projection(
            _model_capability_entry(
                catalog_observed_at="9999-12-31T23:50:00Z",
                catalog_fresh_until="9999-12-31T23:59:59Z",
            )
        ),
    )

    evidence = read_golden(state_home)
    display = usage_snapshot.display_snapshot_from_evidence(
        evidence, known_account_ids=frozenset({"synthetic-alpha"})
    )

    assert evidence.status == "complete"
    assert evidence.model_invocability.status == "invalid"
    assert evidence.model_invocability.capabilities == ()
    assert display.source == "live"
    assert tuple(limit.pool for limit in display.accounts[0].limits) == ("main", "spark")


@pytest.mark.parametrize(
    "projection",
    (
        {"capability_schema_version": 1, "entries": [{"account_id": "synthetic-alpha"}]},
        _model_invocability_projection(
            _model_capability_entry(), _model_capability_entry()
        ),
        _model_invocability_projection(
            _model_capability_entry(catalog_visible=False)
        ),
        _model_invocability_projection(
            _model_capability_entry(visibility="list")
        ),
    ),
)
def test_d236_malformed_model_capabilities_are_invalid_but_preserve_usage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection: object,
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    _rebind_model_invocability(paths, projection)

    evidence = read_golden(state_home)

    assert evidence.status == "complete"
    assert evidence.model_invocability.status == "invalid"
    assert evidence.model_invocability.capabilities == ()
    assert (
        usage_snapshot.find_model_invocability(
            evidence,
            account_id="synthetic-alpha",
            model_id="gpt-5.3-codex-spark",
            runner_id="codex_cli",
        )
        is None
    )
    assert usage_snapshot.display_snapshot_from_evidence(
        evidence, known_account_ids=frozenset({"synthetic-alpha"})
    ).source == "live"


def test_d236_stale_model_capabilities_are_distinct_from_invalid_and_preserve_usage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    _rebind_model_invocability(
        paths,
        _model_invocability_projection(
            _model_capability_entry(
                catalog_observed_at="2026-08-31T11:46:00Z",
                catalog_fresh_until="2026-08-31T12:01:00Z",
            )
        ),
    )

    evidence = read_golden(state_home)

    assert evidence.status == "complete"
    assert evidence.model_invocability.status == "stale"
    assert evidence.model_invocability.capabilities == ()
    assert usage_snapshot.display_snapshot_from_evidence(
        evidence, known_account_ids=frozenset({"synthetic-alpha"})
    ).source == "live"


def test_06538_missing_entrypoint_record_row_after_rebinding_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    _rebind_after_active_record_change(paths)

    assert read_golden(state_home).status == "invalid"


def test_06538_rebound_unsorted_account_list_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    canonical_payload = json.loads(paths["payload"].read_text(encoding="utf-8"))
    beta = json.loads(json.dumps(canonical_payload["accounts"][0]))
    beta["account_id"] = "synthetic-beta"
    canonical_payload["accounts"].append(beta)
    canonical_payload = _producer_canonical_payload(canonical_payload)
    assert [item["account_id"] for item in canonical_payload["accounts"]] == [
        "synthetic-alpha",
        "synthetic-beta",
    ]
    canonical_payload["accounts"].reverse()

    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    beta_authority = json.loads(json.dumps(authority["authorities"][0]))
    beta_authority["account_id"] = "synthetic-beta"
    beta_authority["pool_id"] = "synthetic-secondary"
    _rebind_payload_and_authority(
        paths, canonical_payload, [authority["authorities"][0], beta_authority]
    )

    assert canonical(_producer_canonical_payload(canonical_payload)) != canonical(
        canonical_payload
    )
    assert read_golden(state_home).status == "invalid"


def test_06538_rebound_unsorted_limits_and_tracker_evidence_are_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    payload = _payload_with_complete_evidence(paths)
    account = payload["accounts"][0]
    account["limits"].reverse()
    account["tracker_evidence"].reverse()
    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    _rebind_payload_and_authority(paths, payload, authority["authorities"])

    assert canonical(_producer_canonical_payload(payload)) != canonical(payload)
    assert read_golden(state_home).status == "invalid"


def test_06538_rebound_integer_percent_instead_of_serializer_float_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    payload = _payload_with_complete_evidence(paths)
    payload["accounts"][0]["limits"][0]["used_percent"] = 50
    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    _rebind_payload_and_authority(paths, payload, authority["authorities"])

    assert canonical(_producer_canonical_payload(payload)) != canonical(payload)
    assert read_golden(state_home).status == "invalid"


def test_06538_rebound_secret_shaped_reset_generation_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_usage import integration_snapshot

    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    payload = _payload_with_complete_evidence(paths)
    payload["accounts"][0]["tracker_evidence"][0]["reset_generation"] = (
        "abcdefgh.abcdefgh.abcdefghijklmnop"
    )
    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    _rebind_payload_and_authority(paths, payload, authority["authorities"])

    with pytest.raises(integration_snapshot.IntegrationInvalidSource):
        _producer_canonical_payload(payload)
    assert read_golden(state_home).status == "invalid"


def _rebind_after_noncanonical_record_digest(paths: dict[str, Path]) -> None:
    """Keep the decoded RECORD digest while changing only its unused base64 bits."""
    from codex_usage.integration_attestation import _release_tree_sha256

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    active = json.loads(paths["active"].read_text(encoding="utf-8"))
    record = Path(active["record_path"])
    rows = record.read_text(encoding="utf-8").splitlines(keepends=True)
    entrypoint_index = next(
        index
        for index, row in enumerate(rows)
        if row.split(",", 1)[0] == "codex_usage/integration_entrypoint.py"
    )
    fields = rows[entrypoint_index].rstrip("\n").split(",")
    assert len(fields) == 3
    encoded = fields[1].removeprefix("sha256=")
    assert fields[1] == f"sha256={encoded}"
    final_index = alphabet.index(encoded[-1])
    assert final_index % 4 == 0
    noncanonical = encoded[:-1] + alphabet[final_index + 1]
    assert noncanonical != encoded
    assert urlsafe_b64decode(noncanonical + "=") == urlsafe_b64decode(encoded + "=")
    fields[1] = f"sha256={noncanonical}"
    rows[entrypoint_index] = ",".join(fields) + "\n"
    private_file(record, "".join(rows).encode("utf-8"))

    active["record_sha256"] = digest(record.read_bytes())
    active["release_tree_sha256"] = _release_tree_sha256(
        release_dir=Path(active["release_dir"])
    )
    _write_json(paths["active"], active, newline=True)
    binding = json.loads(paths["binding"].read_text(encoding="utf-8"))
    binding["usage_binding"]["active_manifest_sha256"] = digest(
        paths["active"].read_bytes()
    )
    _write_json(paths["binding"], binding)
    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    authority["usage_binding_sha256"] = digest(canonical(binding["usage_binding"]))
    _write_json(paths["authority"], authority)
    refresh_current_binding(paths)


def test_06538_rebound_noncanonical_record_base64url_digest_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    _rebind_after_noncanonical_record_digest(paths)

    assert read_golden(state_home).status == "invalid"


def test_06538_permissive_ancestor_in_hashed_lock_path_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, _paths = write_producer_golden(tmp_path, monkeypatch)
    lock_root = usage_snapshot._lock_root()
    assert lock_root == next(
        path for path in (tmp_path / "producer-lock-home").rglob("locks") if path.is_dir()
    )
    assert lock_root.parent.stat().st_mode & 0o777 == 0o700
    lock_root.parent.chmod(0o755)

    assert read_golden(state_home).status == "invalid"


def test_06538_rebound_secret_shaped_authority_pool_id_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, paths = write_producer_golden(tmp_path, monkeypatch)
    from codex_usage import integration_pool_authority

    authority = json.loads(paths["authority"].read_text(encoding="utf-8"))
    authority["authorities"][0]["pool_id"] = "abcdefgh.abcdefgh.abcdefghijklmnop"
    _write_json(paths["authority"], authority)
    refresh_current_binding(paths)

    with pytest.raises(integration_pool_authority.PoolAuthorityInvalid):
        integration_pool_authority.parse_pool_authority_projection(
            paths["authority"].read_bytes()
        )
    assert read_golden(state_home).status == "invalid"
