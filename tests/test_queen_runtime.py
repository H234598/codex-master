from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_master.queen_runtime import QueenRuntimeError, QueenRuntimeHomeManager


def manager(tmp_path: Path) -> QueenRuntimeHomeManager:
    return QueenRuntimeHomeManager(root=tmp_path / "Queens", state_root=tmp_path / "state")


def materialize(value: QueenRuntimeHomeManager, generation: int = 1):
    return value.materialize(
        principal_id="queen-codex-master", repository_id="codex-master",
        lease_id="lease-1", fence="fence-1", generation=generation,
    )


def test_materialized_home_is_private_bound_and_monotonic(tmp_path: Path) -> None:
    value = manager(tmp_path)
    first = materialize(value)
    assert first.path.name == "Queen1"
    assert (first.path / "codex-home").is_dir()
    assert (first.path / ".queen-runtime.json").stat().st_mode & 0o777 == 0o600
    assert value.release(first)["released"] is True
    # The counter is durable; a restart cannot reuse a retired home name.
    second = materialize(manager(tmp_path), generation=2)
    assert second.path.name == "Queen2"


def test_cleanup_never_removes_a_home_with_changed_binding(tmp_path: Path) -> None:
    value = manager(tmp_path)
    runtime = materialize(value)
    metadata = runtime.path / ".queen-runtime.json"
    changed = json.loads(metadata.read_text(encoding="utf-8"))
    changed["fence"] = "other-fence"
    metadata.write_text(json.dumps(changed), encoding="utf-8")
    result = value.release(runtime)
    assert result == {"released": False, "quarantined": True, "reason": "queen_runtime_metadata_mismatch"}
    assert runtime.path.exists()


def test_invalid_binding_and_corrupt_registry_fail_closed(tmp_path: Path) -> None:
    value = manager(tmp_path)
    with pytest.raises(QueenRuntimeError, match="invalid_queen_runtime_binding"):
        value.materialize(principal_id="../bad", repository_id="repo", lease_id="lease", fence="fence", generation=1)
    value.state_root.mkdir(mode=0o700)
    (value.state_root / "queen-runtime-homes.json").write_text("[]", encoding="utf-8")
    with pytest.raises(QueenRuntimeError, match="queen_runtime_registry_invalid"):
        materialize(value)
