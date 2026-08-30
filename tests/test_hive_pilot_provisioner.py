from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from codex_master.hive.pilot_provisioner import (
    PilotProvisionerError,
    apply_pilot_provisioning,
    kill_switch_pilot_provisioning,
    plan_pilot_provisioning,
    rollback_pilot_provisioning,
    verify_pilot_provisioning,
)
from codex_master.hive.runtime import read_hive_runtime_evidence
import codex_master.hive.pilot_provisioner as pilot_provisioner


ROOT = Path(__file__).resolve().parents[1]


def make_repository(tmp_path: Path, *, remote: str = "https://github.com/H234598/codex-master.git") -> Path:
    repository = tmp_path / "repository"
    repository.mkdir(mode=0o755)
    (repository / "codex-agent-classes.json").write_bytes(
        (ROOT / "codex-agent-classes.json").read_bytes()
    )
    (repository / "codex-hive.json").write_bytes((ROOT / "codex-hive.json").read_bytes())
    subprocess.run(["git", "-C", str(repository), "init", "-q", "-b", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "remote.origin.url", remote], check=True
    )
    return repository


def test_plan_is_read_only_and_redacted(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"
    before = (repository / "codex-hive.json").read_bytes()

    plan = plan_pilot_provisioning(repository_root=repository, state_root=state_root)

    assert plan == {
        "operation": "plan",
        "allowed": True,
        "mode": "shadow_to_enforced",
        "repository": "codex-master",
        "principal": "queen-codex-master",
        "feature_flags": "all_off",
        "raw_output": "not_returned",
    }
    assert (repository / "codex-hive.json").read_bytes() == before
    assert not state_root.exists()
    assert str(repository) not in str(plan)
    assert str(state_root) not in str(plan)


def test_apply_is_atomic_idempotent_and_runtime_rejects_a_caller_pool_mapping(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"

    applied = apply_pilot_provisioning(repository_root=repository, state_root=state_root)

    assert applied == {
        "operation": "apply",
        "applied": True,
        "repository": "codex-master",
        "principal": "queen-codex-master",
        "feature_flags": "all_off",
        "raw_output": "not_returned",
    }
    config = json.loads((repository / "codex-hive.json").read_text(encoding="utf-8"))
    assert config["mode"] == "enforced"
    assert config["feature_flags"] == {
        "sp0_passive": False,
        "sp1_deadline": False,
        "sp2_secondary_model": False,
        "sp3_fairness": False,
    }
    assert config["repositories"][0]["repo_id"] == "codex-master"
    assert [item["principal_id"] for item in config["principals"]] == [
        "godbee-main",
        "queen-codex-master",
    ]
    assert (state_root / "principals.json").stat().st_mode & 0o777 == 0o600
    assert (state_root / "pilot-provisioner.json").stat().st_mode & 0o777 == 0o600

    verified = verify_pilot_provisioning(repository_root=repository, state_root=state_root)
    assert verified == {
        "operation": "verify",
        "configured": True,
        "mode": "enforced",
        "repository": "ready",
        "principal": "ready",
        "authority": "fail_closed",
        "pilot": "blocked",
        "raw_output": "not_returned",
    }

    repeated = apply_pilot_provisioning(repository_root=repository, state_root=state_root)
    assert repeated["applied"] is False

    evidence = read_hive_runtime_evidence(
        catalog_path=repository / "codex-agent-classes.json",
        config_path=repository / "codex-hive.json",
        state_root=state_root,
        repository_roots={"codex-master": repository},
        dynamic_account_evidence={
            "fresh": True,
            "long_lived": True,
            "model_family": "sol",
            "reasoning": "max",
        },
    )
    assert evidence.authority == "fail_closed"
    assert evidence.pilot == "blocked"


def test_apply_recovers_a_prepared_crash_without_exposing_partial_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"
    original = (repository / "codex-hive.json").read_bytes()

    def crash(*_args: object, **_kwargs: object) -> None:
        raise PilotProvisionerError("config_write_failed")

    monkeypatch.setattr("codex_master.hive.pilot_provisioner._replace_config_atomically", crash)
    with pytest.raises(PilotProvisionerError, match="config_write_failed"):
        apply_pilot_provisioning(repository_root=repository, state_root=state_root)

    assert (repository / "codex-hive.json").read_bytes() == original
    journal = json.loads((state_root / "pilot-provisioner.json").read_text(encoding="utf-8"))
    assert journal["phase"] == "prepared"

    monkeypatch.undo()
    recovered = apply_pilot_provisioning(repository_root=repository, state_root=state_root)
    assert recovered["applied"] is True
    assert json.loads((state_root / "pilot-provisioner.json").read_text(encoding="utf-8"))["phase"] == "committed"


def test_kill_switch_is_an_atomic_safe_config_cutover_before_rollback(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"
    apply_pilot_provisioning(repository_root=repository, state_root=state_root)

    killed = kill_switch_pilot_provisioning(repository_root=repository, state_root=state_root)

    assert killed == {
        "operation": "kill-switch",
        "applied": True,
        "mode": "shadow",
        "raw_output": "not_returned",
    }
    config = json.loads((repository / "codex-hive.json").read_text(encoding="utf-8"))
    assert config["mode"] == "shadow"
    assert config["repositories"] == []
    assert config["principals"] == []
    assert (state_root / "principals.json").exists()

    rolled_back = rollback_pilot_provisioning(repository_root=repository, state_root=state_root)
    assert rolled_back == {
        "operation": "rollback",
        "applied": True,
        "mode": "shadow",
        "raw_output": "not_returned",
    }
    assert not (state_root / "principals.json").exists()


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (
            lambda repository, state_root: subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "remote.origin.url",
                    "https://github.com/example/other.git",
                ],
                check=True,
            ),
            "pilot_repository_invalid",
        ),
        (
            lambda repository, state_root: (
                (repository / "codex-hive.json").unlink(),
                (repository / "codex-hive.json").symlink_to(
                    repository / "codex-agent-classes.json"
                ),
            ),
            "pilot_config_untrusted",
        ),
    ],
)
def test_plan_rejects_wrong_repository_and_unsafe_config_without_path_leaks(
    tmp_path: Path, mutator, reason: str
) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"
    mutator(repository, state_root)

    with pytest.raises(PilotProvisionerError) as raised:
        plan_pilot_provisioning(repository_root=repository, state_root=state_root)

    assert str(raised.value) == reason
    assert str(repository) not in str(raised.value)
    assert str(state_root) not in str(raised.value)


def test_plan_rejects_wrong_host_root_and_wrong_config_mode(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"
    foreign_root = tmp_path / "foreign-root"
    foreign_root.symlink_to(repository, target_is_directory=True)

    with pytest.raises(PilotProvisionerError, match="pilot_repository_untrusted"):
        plan_pilot_provisioning(repository_root=foreign_root, state_root=state_root)

    config = repository / "codex-hive.json"
    config.chmod(0o600)
    with pytest.raises(PilotProvisionerError, match="pilot_config_untrusted"):
        plan_pilot_provisioning(repository_root=repository, state_root=state_root)


def test_atomic_config_cutover_rechecks_the_bound_repository_identity(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    descriptor, root_identity = pilot_provisioner._open_repository_root(repository)
    try:
        payload, config_identity = pilot_provisioner._read_regular(descriptor, "codex-hive.json")
        catalog, _catalog_identity = pilot_provisioner._read_regular(
            descriptor, "codex-agent-classes.json"
        )
        repository.rename(tmp_path / "retired-repository")

        with pytest.raises(PilotProvisionerError, match="pilot_repository_untrusted"):
            pilot_provisioner._replace_config_atomically(
                repository,
                descriptor,
                root_identity,
                config_identity,
                pilot_provisioner._input_digest(payload),
                pilot_provisioner._input_digest(catalog),
                payload,
            )
    finally:
        os.close(descriptor)


def test_atomic_config_cutover_rejects_an_in_place_replay(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    descriptor, root_identity = pilot_provisioner._open_repository_root(repository)
    try:
        payload, config_identity = pilot_provisioner._read_regular(descriptor, "codex-hive.json")
        catalog, _catalog_identity = pilot_provisioner._read_regular(
            descriptor, "codex-agent-classes.json"
        )
        (repository / "codex-hive.json").write_bytes(payload + b" ")

        with pytest.raises(PilotProvisionerError, match="pilot_config_drift"):
            pilot_provisioner._replace_config_atomically(
                repository,
                descriptor,
                root_identity,
                config_identity,
                pilot_provisioner._input_digest(payload),
                pilot_provisioner._input_digest(catalog),
                payload,
            )
    finally:
        os.close(descriptor)


def test_verify_rejects_principal_drift_and_rollback_rejects_replayed_config(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"
    apply_pilot_provisioning(repository_root=repository, state_root=state_root)

    config_path = repository / "codex-hive.json"
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    payload["principals"][1]["principal_id"] = "queen-other"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PilotProvisionerError, match="pilot_config_drift"):
        verify_pilot_provisioning(repository_root=repository, state_root=state_root)
    with pytest.raises(PilotProvisionerError, match="pilot_config_drift"):
        rollback_pilot_provisioning(repository_root=repository, state_root=state_root)


def test_apply_rejects_an_existing_nonprivate_state_root_without_repair(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"
    state_root.mkdir(mode=0o755)
    state_root.chmod(0o755)

    with pytest.raises(PilotProvisionerError, match="pilot_state_unavailable"):
        apply_pilot_provisioning(repository_root=repository, state_root=state_root)

    assert state_root.stat().st_mode & 0o777 == 0o755


def test_tracked_admin_cli_requires_confirmation_and_has_no_hidden_path(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"
    command = ROOT / "scripts" / "codex-master-hive-pilot-provisioner"

    planned = subprocess.run(
        [str(command), "plan", "--repository-root", str(repository), "--state-root", str(state_root)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(planned.stdout)["operation"] == "plan"
    missing_confirmation = subprocess.run(
        [str(command), "apply", "--repository-root", str(repository), "--state-root", str(state_root)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert missing_confirmation.returncode == 2
    assert not state_root.exists()


def _set_nonmain_head(repository: Path, kind: str) -> None:
    if kind == "feature":
        subprocess.run(["git", "-C", str(repository), "checkout", "-q", "-b", "feature"], check=True)
        return
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "-c",
            "user.name=Hive Test",
            "-c",
            "user.email=hive-test@example.invalid",
            "commit",
            "--allow-empty",
            "--no-gpg-sign",
            "-q",
            "-m",
            "test head",
        ],
        check=True,
    )
    subprocess.run(["git", "-C", str(repository), "checkout", "-q", "--detach", "HEAD"], check=True)


@pytest.mark.parametrize("head_kind", ("feature", "detached"))
@pytest.mark.parametrize("operation", ("plan", "apply", "verify"))
def test_plan_apply_and_verify_require_the_canonical_main_head(
    tmp_path: Path, head_kind: str, operation: str
) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"
    if operation == "verify":
        apply_pilot_provisioning(repository_root=repository, state_root=state_root)
    _set_nonmain_head(repository, head_kind)

    command = {
        "plan": plan_pilot_provisioning,
        "apply": apply_pilot_provisioning,
        "verify": verify_pilot_provisioning,
    }[operation]
    with pytest.raises(PilotProvisionerError, match="pilot_repository_invalid"):
        command(repository_root=repository, state_root=state_root)


@pytest.mark.parametrize("operation", (kill_switch_pilot_provisioning, rollback_pilot_provisioning))
@pytest.mark.parametrize("binding_mutation", ("origin", "branch", "config_digest"))
def test_recovery_operations_require_the_same_repository_binding_as_apply_and_verify(
    tmp_path: Path, operation, binding_mutation: str
) -> None:
    repository = make_repository(tmp_path)
    state_root = tmp_path / "private-state"
    apply_pilot_provisioning(repository_root=repository, state_root=state_root)

    if binding_mutation == "origin":
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "config",
                "remote.origin.url",
                "https://github.com/example/other.git",
            ],
            check=True,
        )
    elif binding_mutation == "branch":
        _set_nonmain_head(repository, "feature")
    else:
        config_path = repository / "codex-hive.json"
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        payload["repositories"][0]["config_digest"] = "sha256:" + "b" * 64
        config_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PilotProvisionerError, match="pilot_repository_invalid"):
        operation(repository_root=repository, state_root=state_root)


def test_plan_rejects_an_unsafe_state_parent_without_creating_state(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    state_parent = tmp_path / "unsafe-parent"
    state_parent.mkdir(mode=0o777)
    state_parent.chmod(0o777)
    state_root = state_parent / "private-state"

    with pytest.raises(PilotProvisionerError, match="pilot_state_unavailable"):
        plan_pilot_provisioning(repository_root=repository, state_root=state_root)

    assert not state_root.exists()
