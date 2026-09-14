from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
import runpy
import subprocess

import pytest

from the_hive.hive.pilot_provisioner import apply_pilot_provisioning
from the_hive.hive.hourly_probe import run_probe
from the_hive.hive.runtime import (
    HiveRuntimeError,
    HiveRuntimeEvidence,
    build_hive_runtime,
    read_hive_runtime_evidence,
)
from the_hive.hive.status import hive_doctor, hive_status
from the_hive.hive.config import (
    load_agent_class_catalog_snapshot_bytes,
    load_hive_config_bytes,
)
from the_hive.runtime_layout import RuntimeLayout
from the_hive.usage_snapshot import (
    AccountUsageEvidenceV2,
    TrackerEvidenceV2,
    UsageEvidenceV2,
    UsageLimitV2,
    UsageTrendV2,
)
import the_hive.hive.runtime as hive_runtime


ROOT = Path(__file__).resolve().parents[1]
SHADOW_CONFIG = ROOT / "tests" / "fixtures" / "hive" / "hive-shadow-valid.json"
NOW = datetime(2026, 8, 31, 12, tzinfo=UTC)
# Private structural builder fixture only, never Git provenance. Production
# publication separately verifies the real commit through _verified_release_commit.
TEST_STRUCTURAL_COMMIT = "a" * 40


def _p2_checkout(tmp_path: Path) -> Path:
    """Materialize the P2 provisioner's real Git-only input contract."""

    checkout = tmp_path / "p2-checkout"
    checkout.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    checkout.mkdir(mode=0o755)
    (checkout / "codex-agent-classes.json").write_bytes(
        (ROOT / "codex-agent-classes.json").read_bytes()
    )
    (checkout / "codex-hive.json").write_bytes(SHADOW_CONFIG.read_bytes())
    subprocess.run(["git", "-C", str(checkout), "init", "-q", "-b", "main"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "config",
            "remote.origin.url",
            "https://github.com/H234598/codex-master.git",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "-c",
            "user.name=Runtime Image Test",
            "-c",
            "user.email=runtime-image-test@example.invalid",
            "commit",
            "--allow-empty",
            "--no-gpg-sign",
            "-q",
            "-m",
            "initial main",
        ],
        check=True,
    )
    return checkout


def _attested_pool_evidence(now: datetime) -> UsageEvidenceV2:
    return UsageEvidenceV2(
        accounts=(
            AccountUsageEvidenceV2(
                "runtime-image-test",
                (
                    UsageLimitV2(
                        "main", 18_000, "runtime-image-generation", 0.0, 100.0, now + timedelta(hours=1)
                    ),
                ),
                (
                    UsageTrendV2(
                        "main",
                        18_000,
                        "runtime-image-generation",
                        "complete",
                        now,
                        now + timedelta(hours=1),
                    ),
                ),
                (
                    TrackerEvidenceV2(
                        "main", 18_000, "runtime-image-generation", "complete", now
                    ),
                ),
            ),
        ),
        status="complete",
        captured_at=now,
        generated_at=now,
    )


def _p2_runtime_image(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    checkout = _p2_checkout(tmp_path)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    state_root = home / ".local" / "state" / "codex-master-mcp" / "hive"
    state_root.parent.mkdir(mode=0o700, parents=True)
    apply_pilot_provisioning(repository_root=checkout, state_root=state_root)

    installer = runpy.run_path(str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install"))
    stage = tmp_path / "runtime-image"
    stage.mkdir(mode=0o700)
    installer["_build_runtime_image"](
        repository=ROOT,
        stage=stage,
        generation=TEST_STRUCTURAL_COMMIT,
        commit=TEST_STRUCTURAL_COMMIT,
    )
    (stage / "codex-hive.json").write_bytes((checkout / "codex-hive.json").read_bytes())
    (stage / "codex-hive.json").chmod(0o644)
    (stage / ".codex-master-runtime-manifest.json").unlink()
    installer["_write_runtime_image_manifest"](
        root=stage,
        generation=TEST_STRUCTURAL_COMMIT,
        commit=TEST_STRUCTURAL_COMMIT,
    )
    assert RuntimeLayout.from_runtime_root(stage).root == stage
    return stage, state_root, installer


def _published_launcher_release(
    tmp_path: Path,
) -> tuple[Path, str, str, dict[str, object]]:
    """Build a harmless attested generation for the stable launchers alone."""

    installer = runpy.run_path(str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install"))
    stage = tmp_path / ".codex-master-runtime.stage.launcher-test"
    stage.mkdir(mode=0o700)
    generation = "launcher-test"
    installer["_build_runtime_image"](  # type: ignore[operator]
        repository=ROOT,
        stage=stage,
        generation=generation,
        commit=TEST_STRUCTURAL_COMMIT,
    )
    # A real monitor would deliberately loop.  The launcher test instead uses
    # an attested server module whose two public dispatches immediately return.
    (stage / "src" / "the_hive" / "server.py").write_text(
        "import sys\n"
        "def run_resource_monitor():\n    return None\n"
        "if __name__ == '__main__' and sys.argv[1:] not in ([], ['--runtime-status-mcp']):\n"
        "    raise RuntimeError('MCP arguments were not preserved')\n",
        encoding="utf-8",
    )
    (stage / "src" / "the_hive" / "server.py").chmod(0o644)
    (stage / ".codex-master-runtime-manifest.json").unlink()
    installer["_write_runtime_image_manifest"](  # type: ignore[operator]
        root=stage,
        generation=generation,
        commit=TEST_STRUCTURAL_COMMIT,
    )
    release_root = tmp_path / "codex-master-runtime"
    installer["_publish_runtime_generation"](stage=stage, release_root=release_root)  # type: ignore[operator]
    manifest_digest = "sha256:" + hashlib.sha256(
        (
            release_root
            / "generations"
            / generation
            / ".codex-master-runtime-manifest.json"
        ).read_bytes()
    ).hexdigest()
    assert RuntimeLayout.from_current_release(
        release_root, generation, manifest_digest
    ).root == release_root / "generations" / generation
    return release_root, generation, manifest_digest, installer


def test_stable_launchers_require_one_attested_current_generation_without_checkout_or_cache(
    tmp_path: Path,
) -> None:
    release_root, generation, manifest_digest, _installer = _published_launcher_release(tmp_path)
    dirty_checkout = tmp_path / "dirty-checkout"
    (dirty_checkout / "the_hive").mkdir(parents=True)
    (dirty_checkout / "the_hive" / "server.py").write_text(
        "raise RuntimeError('dirty checkout imported')\n", encoding="utf-8"
    )
    plugin_cache = tmp_path / "plugin-cache"
    plugin_cache.mkdir()
    sentinel = plugin_cache / "untouched"
    sentinel.write_text("native cache", encoding="utf-8")
    env = {
        "HOME": str(tmp_path / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(dirty_checkout),
        "PYTHONHOME": str(dirty_checkout),
        "CODEX_HOME": str(plugin_cache),
        "CODEX_MASTER_DIRTY_ROOT": str(dirty_checkout),
    }
    launchers = (
        ROOT / "bin" / "codex-master-mcp",
        ROOT / "bin" / "codex-master-resource-monitor",
    )

    for launcher in launchers:
        for arguments in ((), (str(release_root), generation)):
            result = subprocess.run(
                [launcher, *arguments], cwd=dirty_checkout, env=env,
                check=False, capture_output=True, text=True, timeout=10,
            )
            assert result.returncode == 64
            assert result.stdout == ""
            assert result.stderr == ""
        successful = subprocess.run(
            [launcher, release_root, generation, manifest_digest], cwd=dirty_checkout, env=env,
            check=False, capture_output=True, text=True, timeout=10,
        )
        assert successful.returncode == 0, successful.stderr
        assert successful.stdout == ""
        assert successful.stderr == ""
        if launcher.name == "codex-master-mcp":
            forwarded = subprocess.run(
                [launcher, release_root, generation, manifest_digest, "--runtime-status-mcp"],
                cwd=dirty_checkout, env=env, check=False, capture_output=True,
                text=True, timeout=10,
            )
            assert forwarded.returncode == 0, forwarded.stderr
            assert forwarded.stdout == ""
            assert forwarded.stderr == ""
        else:
            extra = subprocess.run(
                [launcher, release_root, generation, manifest_digest, "extra"],
                cwd=dirty_checkout, env=env, check=False, capture_output=True,
                text=True, timeout=10,
            )
            assert extra.returncode == 64
            assert extra.stdout == ""
            assert extra.stderr == ""
        for invalid_generation, invalid_digest in (
            ("other-generation", manifest_digest),
            ("../other-generation", manifest_digest),
            (generation, "sha256:" + "0" * 64),
        ):
            result = subprocess.run(
                [launcher, release_root, invalid_generation, invalid_digest],
                cwd=dirty_checkout, env=env, check=False, capture_output=True,
                text=True, timeout=10,
            )
            assert result.returncode == 64
            assert result.stdout == ""
            assert result.stderr == ""

    pointers = release_root / ".codex-master-release-pointers.json"
    drifted = json.loads(pointers.read_text(encoding="utf-8"))
    drifted["current"]["manifest_digest"] = "sha256:" + "f" * 64
    pointers.write_text(json.dumps(drifted), encoding="utf-8")
    pointers.chmod(0o644)
    for launcher in launchers:
        result = subprocess.run(
            [launcher, release_root, generation, manifest_digest], cwd=dirty_checkout,
            env=env, check=False, capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 64
        assert result.stdout == ""
        assert result.stderr == ""
    assert [path.relative_to(plugin_cache) for path in plugin_cache.rglob("*")] == [Path("untouched")]


def test_plugin_mcp_config_uses_only_the_authority_materialized_stable_launcher(
    tmp_path: Path,
) -> None:
    release_root, generation, manifest_digest, _installer = _published_launcher_release(tmp_path)
    config = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
    server = config["mcpServers"]["codex-master-mcp"]
    assert server == {
        "command": "/home/teladi/.local/lib/codex-master-runtime/codex-master-mcp",
        "args": [],
        "startup_timeout_sec": 120,
        "note": "Local data-sparse Codex Masterjet MCP server. Controls the sleeping Agentinnen pool through tmux and does not return raw terminal output by default.",
    }
    stable = release_root / "codex-master-mcp"
    item = stable.lstat()
    assert stat.S_ISREG(item.st_mode)
    assert not stable.is_symlink()
    assert stat.S_IMODE(item.st_mode) == 0o755
    immutable = release_root / "generations" / generation / "bin" / "codex-master-mcp-stable"
    manifest = json.loads(
        (
            release_root
            / "generations"
            / generation
            / ".codex-master-runtime-manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert stable.read_bytes() == immutable.read_bytes()
    assert manifest["files"]["bin/codex-master-mcp-stable"] == {
        "mode": 0o755,
        "nlink": 1,
        "size": len(stable.read_bytes()),
        "sha256": hashlib.sha256(stable.read_bytes()).hexdigest(),
    }
    dirty_checkout = tmp_path / "dirty-checkout"
    (dirty_checkout / "the_hive").mkdir(parents=True)
    (dirty_checkout / "the_hive" / "server.py").write_text(
        "raise RuntimeError('dirty checkout imported')\n", encoding="utf-8"
    )
    plugin_cache = tmp_path / "plugin-cache"
    plugin_cache.mkdir()
    sentinel = plugin_cache / "untouched"
    sentinel.write_text("native cache", encoding="utf-8")
    result = subprocess.run(
        [stable, "--runtime-status-mcp"], cwd=dirty_checkout,
        env={
            "HOME": str(tmp_path / "attacker-home"),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(dirty_checkout),
            "CODEX_HOME": str(plugin_cache),
        },
        check=False, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""
    assert [path.relative_to(plugin_cache) for path in plugin_cache.rglob("*")] == [Path("untouched")]
    stable.write_bytes(stable.read_bytes() + b"\n# external stable drift\n")
    stable.chmod(0o755)
    drifted_stable = subprocess.run(
        [stable], cwd=dirty_checkout,
        env={"HOME": str(tmp_path / "attacker-home"), "PATH": "/usr/bin:/bin"},
        check=False, capture_output=True, text=True, timeout=10,
    )
    assert drifted_stable.returncode == 64
    assert drifted_stable.stdout == ""
    assert drifted_stable.stderr == ""
    stable.write_bytes(immutable.read_bytes())
    stable.chmod(0o755)
    pointers = release_root / ".codex-master-release-pointers.json"
    drifted = json.loads(pointers.read_text(encoding="utf-8"))
    drifted["current"]["manifest_digest"] = "sha256:" + "0" * 64
    pointers.write_text(json.dumps(drifted), encoding="utf-8")
    pointers.chmod(0o644)
    rejected = subprocess.run(
        [stable], cwd=dirty_checkout,
        env={"HOME": str(tmp_path / "attacker-home"), "PATH": "/usr/bin:/bin"},
        check=False, capture_output=True, text=True, timeout=10,
    )
    assert rejected.returncode == 64
    assert rejected.stdout == ""
    assert rejected.stderr == ""


def test_complete_p2_runtime_image_binds_its_attested_root_without_a_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The image is a valid P2 consumer even though it deliberately has no .git."""

    stage, state_root, installer = _p2_runtime_image(tmp_path)
    external_checkout = _p2_checkout(tmp_path / "external")
    (external_checkout / "codex-hive.json").write_text("{", encoding="utf-8")
    assert not (stage / ".git").exists()
    installer["_validate_runtime_image_stage"](stage=stage, home=tmp_path / "home")

    legacy_launcher = subprocess.run(
        [stage / "bin" / "codex-master-mcp", "hive", "status"],
        check=False,
        capture_output=True,
        text=True,
        cwd=external_checkout,
        env={
            "HOME": str(tmp_path / "home"),
            "PATH": "/usr/bin:/bin",
            "CODEX_HOME": str(external_checkout / "attacker-codex-home"),
            "CODEX_MASTER_RUNTIME_ROOT": str(external_checkout),
        },
    )
    assert legacy_launcher.returncode == 64
    assert legacy_launcher.stdout == ""
    assert legacy_launcher.stderr == ""

    monkeypatch.chdir(external_checkout)
    monkeypatch.setenv("CODEX_HOME", str(external_checkout / "attacker-codex-home"))
    monkeypatch.setenv("CODEX_MASTER_RUNTIME_ROOT", str(external_checkout))
    monkeypatch.setattr(hive_runtime, "__file__", str(stage / "src" / "the_hive" / "hive" / "runtime.py"))
    monkeypatch.setattr(hive_runtime, "_default_hive_state_root", lambda: state_root)
    monkeypatch.setattr(
        hive_runtime,
        "read_usage_evidence_v2",
        lambda *, clock: _attested_pool_evidence(clock()),
    )

    def unexpected_runtime_builder(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("image diagnostics must not assemble HiveRuntime")

    monkeypatch.setattr(hive_runtime, "build_hive_runtime", unexpected_runtime_builder)

    evidence = read_hive_runtime_evidence(now=lambda: NOW)

    assert isinstance(evidence, HiveRuntimeEvidence)
    assert evidence.repository == "ready"
    assert evidence.principal == "ready"
    assert evidence.state == "ready"
    assert evidence.authority == "ready", evidence.public()
    assert evidence.pilot == "ready", evidence.public()
    assert evidence.reason_codes == ()
    assert hive_status(runtime_evidence=evidence)["repository"] == "ready"
    assert hive_doctor(runtime_evidence=evidence)["healthy"] is True
    status = hive_status(runtime_evidence=evidence)
    doctor = hive_doctor(runtime_evidence=evidence)

    def runner(_entrypoint: Path, _namespace: str, command: str) -> tuple[dict[str, object], bool]:
        return (dict(status) if command == "status" else dict(doctor), True)

    probe = run_probe(
        layout=RuntimeLayout.from_runtime_root(stage),
        state_directory=tmp_path / "probe-state",
        now=lambda: NOW,
        runner=runner,
    )
    assert probe["checks"] == {
        "runtime_layout": True,
        "hive_runtime": True,
        "hive_doctor": True,
    }
    public = evidence.public()
    rendered = json.dumps(public, sort_keys=True)
    assert str(stage) not in rendered
    assert str(state_root) not in rendered
    assert str(external_checkout) not in rendered


def test_runtime_image_binding_is_rejected_outside_read_only_diagnostics(
    tmp_path: Path,
) -> None:
    stage, state_root, _installer = _p2_runtime_image(tmp_path)
    layout = RuntimeLayout.from_runtime_root(stage)
    snapshot = load_agent_class_catalog_snapshot_bytes(
        layout.read_attested_file("codex-agent-classes.json")
    )
    config = load_hive_config_bytes(
        layout.read_attested_file("codex-hive.json"), snapshot.classes
    )

    with pytest.raises(HiveRuntimeError, match="invalid_repository_binding"):
        build_hive_runtime(
            config,
            snapshot.classes,
            repository_roots={"codex-master": layout},
            state_root=state_root,
            read_only=True,
        )


def test_missing_runtime_image_config_fails_closed_without_external_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stage, state_root, _installer = _p2_runtime_image(tmp_path)
    external_checkout = _p2_checkout(tmp_path / "external")
    (stage / "codex-hive.json").unlink()

    monkeypatch.chdir(external_checkout)
    monkeypatch.setenv("CODEX_HOME", str(external_checkout / "attacker-codex-home"))
    monkeypatch.setenv("CODEX_MASTER_RUNTIME_ROOT", str(external_checkout))
    monkeypatch.setattr(hive_runtime, "__file__", str(stage / "src" / "the_hive" / "hive" / "runtime.py"))
    monkeypatch.setattr(hive_runtime, "_default_hive_state_root", lambda: state_root)

    evidence = read_hive_runtime_evidence(now=lambda: NOW)

    assert evidence.repository == "unavailable"
    assert evidence.reason_codes == ("hive_config_unavailable",)
    rendered = json.dumps(evidence.public(), sort_keys=True)
    assert str(stage) not in rendered
    assert str(state_root) not in rendered
    assert str(external_checkout) not in rendered


def test_implicit_image_evidence_never_falls_back_to_a_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No-argument consumers require a complete attested image generation."""

    external_checkout = _p2_checkout(tmp_path / "external")
    monkeypatch.chdir(external_checkout)
    monkeypatch.setenv("CODEX_HOME", str(external_checkout / "attacker-codex-home"))
    monkeypatch.setenv("CODEX_MASTER_RUNTIME_ROOT", str(external_checkout))
    monkeypatch.setattr(hive_runtime, "_default_hive_state_root", lambda: tmp_path / "state")

    evidence = read_hive_runtime_evidence(now=lambda: NOW)

    assert evidence.mode == "disabled"
    assert evidence.config_digest is None
    assert evidence.catalog_digest is None
    assert evidence.repository == "unavailable"
    assert evidence.reason_codes == ("hive_config_unavailable",)
    rendered = json.dumps(evidence.public(), sort_keys=True)
    assert str(external_checkout) not in rendered


def test_image_diagnostics_reject_conflicting_authority_profile_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The private image path keeps the normal authority conflict contract."""

    stage, state_root, installer = _p2_runtime_image(tmp_path)
    catalog = json.loads((stage / "codex-agent-classes.json").read_text(encoding="utf-8"))
    for item in catalog["classes"]:
        if item["class_id"] == "teamleiterin":
            item["authority_profile"] = "specialist"
    (stage / "codex-agent-classes.json").write_text(json.dumps(catalog), encoding="utf-8")
    (stage / "codex-agent-classes.json").chmod(0o644)
    (stage / ".codex-master-runtime-manifest.json").unlink()
    installer["_write_runtime_image_manifest"](
        root=stage,
        generation=TEST_STRUCTURAL_COMMIT,
        commit=TEST_STRUCTURAL_COMMIT,
    )

    monkeypatch.setattr(hive_runtime, "__file__", str(stage / "src" / "the_hive" / "hive" / "runtime.py"))
    monkeypatch.setattr(hive_runtime, "_default_hive_state_root", lambda: state_root)

    evidence = read_hive_runtime_evidence(now=lambda: NOW)

    assert evidence.repository == "ready"
    assert evidence.principal == "invalid"
    assert evidence.authority == "fail_closed"
    assert "hive_runtime_invalid" in evidence.reason_codes
