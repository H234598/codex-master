from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
import runpy
import subprocess

import pytest

from codex_master.hive.pilot_provisioner import apply_pilot_provisioning
from codex_master.hive.hourly_probe import run_probe
from codex_master.hive.runtime import (
    HiveRuntimeError,
    HiveRuntimeEvidence,
    build_hive_runtime,
    read_hive_runtime_evidence,
)
from codex_master.hive.status import hive_doctor, hive_status
from codex_master.hive.config import (
    load_agent_class_catalog_snapshot_bytes,
    load_hive_config_bytes,
)
from codex_master.runtime_layout import RuntimeLayout
from codex_master.usage_snapshot import (
    AccountUsageEvidenceV2,
    TrackerEvidenceV2,
    UsageEvidenceV2,
    UsageLimitV2,
    UsageTrendV2,
)
import codex_master.hive.runtime as hive_runtime


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 31, 12, tzinfo=UTC)


def _p2_checkout(tmp_path: Path) -> Path:
    """Materialize the P2 provisioner's real Git-only input contract."""

    checkout = tmp_path / "p2-checkout"
    checkout.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    checkout.mkdir(mode=0o755)
    for name in ("codex-agent-classes.json", "codex-hive.json"):
        (checkout / name).write_bytes((ROOT / name).read_bytes())
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
    installer["_build_runtime_image"](repository=ROOT, stage=stage)
    (stage / "codex-hive.json").write_bytes((checkout / "codex-hive.json").read_bytes())
    (stage / "codex-hive.json").chmod(0o644)
    (stage / ".codex-master-runtime-manifest.json").unlink()
    installer["_write_runtime_image_manifest"](root=stage)
    assert RuntimeLayout.from_runtime_root(stage).root == stage
    return stage, state_root, installer


def test_complete_p2_runtime_image_binds_its_attested_root_without_a_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The image is a valid P2 consumer even though it deliberately has no .git."""

    stage, state_root, installer = _p2_runtime_image(tmp_path)
    external_checkout = _p2_checkout(tmp_path / "external")
    (external_checkout / "codex-hive.json").write_text("{", encoding="utf-8")
    assert not (stage / ".git").exists()
    installer["_validate_runtime_image_stage"](stage=stage, home=tmp_path / "home")

    completed = subprocess.run(
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
    assert completed.returncode == 0, completed.stderr
    image_status = json.loads(completed.stdout)
    assert image_status["repository"] == "ready"
    assert image_status["principal"] == "ready"
    assert image_status["state"] == "ready"

    monkeypatch.chdir(external_checkout)
    monkeypatch.setenv("CODEX_HOME", str(external_checkout / "attacker-codex-home"))
    monkeypatch.setenv("CODEX_MASTER_RUNTIME_ROOT", str(external_checkout))
    monkeypatch.setattr(hive_runtime, "__file__", str(stage / "src" / "codex_master" / "hive" / "runtime.py"))
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
    monkeypatch.setattr(hive_runtime, "__file__", str(stage / "src" / "codex_master" / "hive" / "runtime.py"))
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
    installer["_write_runtime_image_manifest"](root=stage)

    monkeypatch.setattr(hive_runtime, "__file__", str(stage / "src" / "codex_master" / "hive" / "runtime.py"))
    monkeypatch.setattr(hive_runtime, "_default_hive_state_root", lambda: state_root)

    evidence = read_hive_runtime_evidence(now=lambda: NOW)

    assert evidence.repository == "ready"
    assert evidence.principal == "invalid"
    assert evidence.authority == "fail_closed"
    assert "hive_runtime_invalid" in evidence.reason_codes
