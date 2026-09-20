from __future__ import annotations

import copy
from dataclasses import replace
import inspect
import json
import os
from pathlib import Path
import pickle

import pytest

from the_hive import google_inventory_deployment_quiescence_authority as authority
from the_hive import runtime_layout


_UTC = 1_700_000_000_000_000_000
_BOOT = 10_000_000_000
_BOOT_ID = "a" * 32
_DIGEST = "sha256:" + "1" * 64


def _digest(payload: dict[str, object]) -> str:
    return authority._digest(payload)


class _Clock:
    def __init__(self) -> None:
        self.boot = _BOOT
        self.utc = _UTC
        self.boot_id = _BOOT_ID

    def boot_now(self) -> int:
        return self.boot

    def utc_now(self) -> int:
        return self.utc

    def read_boot_id(self) -> str:
        return self.boot_id


class _Port:
    def __init__(self, value: object) -> None:
        self.value = value
        self.calls: list[object] = []

    def read(self, *args: object) -> object:
        self.calls.append(args)
        return self.value


def _layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> runtime_layout.RuntimeStateLayoutV1:
    state = tmp_path / "private-state" / "the-hive-ga-i2d-quiescence"
    state.mkdir(mode=0o700, parents=True)
    monkeypatch.setenv("STATE_DIRECTORY", str(state))
    return runtime_layout.RuntimeStateLayoutV1.from_systemd_state_directory()


def _ports(
    *,
    action: str = "binding_manifest",
    expires: int = _UTC + 120 * 1_000_000_000,
) -> tuple[_Port, _Port, _Port]:
    target_class = authority._ACTIONS[action]
    plan = authority.PlanBindingRecord(
        plan_reference="plan-reference-1",
        plan_digest=_DIGEST,
        action=action,
        target_class=target_class,
        inventory_authority_generation="inventory-authority-generation-1",
        inventory_authority_fingerprint=_DIGEST,
        manifest_generation="manifest-generation-1",
        manifest_fingerprint=_DIGEST,
        inventory_generation="inventory-generation-1",
        inventory_content_fingerprint=_DIGEST,
        registry_generation="registry-generation-1",
        registry_fingerprint=_DIGEST,
        candidate_inventory_fingerprint=_DIGEST,
        expires_at_utc=authority._utc_text(expires),
    )
    principal_base = authority.PrincipalLeaseScopeRecord(
        principal_id=authority._PRINCIPAL_ID,
        authority_generation="principal-generation-1",
        lease_id="lease-1",
        lease_expires_boottime_ns=_BOOT + 180 * 1_000_000_000,
        scopes=authority._SCOPE_ORDER,
        scope_digest="",
        queen_authorization_digest=_DIGEST,
        repository_scope="the-hive",
    )
    principal = replace(
        principal_base,
        scope_digest=_digest(authority._principal_projection(principal_base)),
    )
    target_base = authority.TargetSetRecord(
        action=action,
        target_class=target_class,
        principal_id=principal.principal_id,
        principal_generation=principal.authority_generation,
        lease_id=principal.lease_id,
        owner="inventory-writer",
        consumers=("inventory-reader", "deployment-reader"),
        target_set_digest="",
    )
    target = replace(
        target_base,
        target_set_digest=_digest(authority._target_projection(target_base)),
    )
    return _Port(plan), _Port(principal), _Port(target)


def _authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    action: str = "binding_manifest",
) -> tuple[authority.GoogleInventoryDeploymentQuiescenceAuthorityV1, _Clock, _Port, _Port, _Port]:
    layout = _layout(tmp_path, monkeypatch)
    plan, principal, target = _ports(action=action)
    clock = _Clock()
    instance = authority.GoogleInventoryDeploymentQuiescenceAuthorityV1(
        layout,
        plan,
        principal,
        target,
    )
    monkeypatch.setattr(authority, "_current_boottime", clock.boot_now)
    monkeypatch.setattr(authority, "_current_utc", clock.utc_now)
    monkeypatch.setattr(authority, "_current_boot_id", clock.read_boot_id)
    return instance, clock, plan, principal, target


@pytest.mark.parametrize(
    "action",
    (
        "binding_manifest",
        "inventory.desktop_client_registry.provision",
        "inventory.schema2_to_schema3",
    ),
)
def test_issue_resolve_claim_consume_is_bound_to_each_canonical_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(
        tmp_path, monkeypatch, action=action
    )

    receipt = instance.issue("plan-reference-1")
    assert receipt.action == action
    assert receipt.target_class == authority._ACTIONS[action]
    assert instance.resolve(receipt.receipt_reference) == receipt
    continuity = instance.claim(receipt.receipt_reference)
    claimed = instance.resolve(receipt.receipt_reference)
    assert claimed is not None
    assert claimed.state == "CLAIMED"
    consumed = instance.consume(receipt.receipt_reference, continuity)
    assert consumed.state == "CONSUMED"
    assert instance.resolve(receipt.receipt_reference) == consumed


def test_parameterless_ports_and_private_authority_have_no_product_factory() -> None:
    signature = inspect.signature(
        authority.GoogleInventoryDeploymentQuiescenceAuthorityV1.__init__
    )
    for name in ("plan_binding", "principal_lease_scope", "targetset"):
        assert signature.parameters[name].default is inspect.Parameter.empty
    assert authority.__all__ == ()
    assert not any(name.endswith("Factory") for name in dir(authority))


def test_resolve_is_observational_and_does_not_materialize_lock_or_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    state = instance._layout.state_directory
    before = sorted(path.name for path in state.iterdir())

    assert instance.resolve("0" * 32) is None

    assert sorted(path.name for path in state.iterdir()) == before == []


def test_receipt_is_canonical_secret_free_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)

    receipt = instance.issue("plan-reference-1")
    raw = receipt.to_json()
    parsed = json.loads(raw)

    assert raw == authority._canonical_json(parsed)
    assert set(parsed) == authority._RECEIPT_FIELDS
    assert len(raw) <= authority._MAX_RECORD_BYTES
    assert "secret" not in raw.decode("utf-8").casefold()
    assert "token" not in raw.decode("utf-8").casefold()
    assert str(instance._layout.state_directory).encode() not in raw


def test_plan_digest_action_target_generation_and_fingerprint_drift_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    plan.value = replace(plan.value, plan_digest="sha256:" + "2" * 64)

    with pytest.raises(authority.AuthorityUnavailable, match="receipt_plan_digest_stale"):
        instance.resolve(receipt.receipt_reference)


def test_receipt_expiry_cannot_outlive_a_shortened_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    plan.value = replace(
        plan.value,
        expires_at_utc=authority._utc_text(_UTC + 30 * 1_000_000_000),
    )

    with pytest.raises(authority.AuthorityUnavailable, match="plan_expiry_stale"):
        instance.resolve(receipt.receipt_reference)


def test_principal_lease_scope_or_targetset_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, principal, target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    principal.value = replace(principal.value, lease_id="different-lease")

    with pytest.raises(authority.AuthorityUnavailable):
        instance.resolve(receipt.receipt_reference)

    principal.value = _ports()[1].value
    target.value = replace(target.value, consumers=("different-consumer",))
    target.value = replace(
        target.value,
        target_set_digest=_digest(authority._target_projection(target.value)),
    )
    with pytest.raises(authority.AuthorityUnavailable):
        instance.resolve(receipt.receipt_reference)


def test_expiry_is_at_most_sixty_seconds_and_rejects_long_or_expired_plans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    assert receipt.expires_boottime_ns - receipt.issued_boottime_ns == 60 * 1_000_000_000

    bad_plan, principal, target = _ports(expires=_UTC + 301 * 1_000_000_000)
    bad = authority.GoogleInventoryDeploymentQuiescenceAuthorityV1(
        instance._layout,
        bad_plan,
        principal,
        target,
    )
    with pytest.raises(authority.AuthorityUnavailable, match="unbounded"):
        bad.issue("plan-reference-1")


def test_claim_is_irreversible_and_consume_requires_the_exact_local_continuity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    continuity = instance.claim(receipt.receipt_reference)

    with pytest.raises(authority.AuthorityIndeterminate, match="already_claimed"):
        instance.claim(receipt.receipt_reference)
    assert instance.consume(receipt.receipt_reference, continuity).state == "CONSUMED"
    with pytest.raises(authority.AuthorityIndeterminate):
        instance.consume(receipt.receipt_reference, continuity)


def test_reconstructed_authority_cannot_consume_persisted_claimed_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, clock, plan, principal, target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    instance.claim(receipt.receipt_reference)
    reconstructed = authority.GoogleInventoryDeploymentQuiescenceAuthorityV1(
        instance._layout,
        plan,
        principal,
        target,
    )

    with pytest.raises(authority.AuthorityIndeterminate, match="continuity"):
        reconstructed.consume(receipt.receipt_reference, object())  # type: ignore[arg-type]
    with pytest.raises(authority.AuthorityIndeterminate, match="indeterminate"):
        reconstructed.issue("plan-reference-1")


def test_reconstructed_authority_resolve_classifies_claimed_as_indeterminate_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, plan, principal, target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    instance.claim(receipt.receipt_reference)
    reconstructed = authority.GoogleInventoryDeploymentQuiescenceAuthorityV1(
        instance._layout,
        plan,
        principal,
        target,
    )
    state = instance._layout.state_directory
    before_names = sorted(path.name for path in state.iterdir())
    claimed_record = state / f"{receipt.receipt_reference}-claimed.json"
    before_bytes = claimed_record.read_bytes()

    with pytest.raises(authority.AuthorityIndeterminate, match="continuity") as raised:
        reconstructed.resolve(receipt.receipt_reference)

    assert raised.value.receipt is not None
    assert raised.value.receipt.state == "INDETERMINATE"
    assert sorted(path.name for path in state.iterdir()) == before_names
    assert claimed_record.read_bytes() == before_bytes
    assert reconstructed._read_store()[receipt.receipt_reference].state == "CLAIMED"


def test_reboot_invalidates_open_receipt_without_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, clock, plan, principal, target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    clock.boot_id = "b" * 32
    restarted = authority.GoogleInventoryDeploymentQuiescenceAuthorityV1(
        instance._layout,
        plan,
        principal,
        target,
    )

    with pytest.raises(authority.AuthorityIndeterminate, match="reboot"):
        restarted.resolve(receipt.receipt_reference)


def test_copy_deepcopy_and_pickle_cannot_duplicate_authority_continuity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)

    with pytest.raises(TypeError):
        copy.copy(instance)
    with pytest.raises(TypeError):
        copy.deepcopy(instance)
    with pytest.raises(TypeError):
        pickle.dumps(instance)


def test_object_new_cannot_share_or_set_authority_continuity_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    reconstructed = object.__new__(
        authority.GoogleInventoryDeploymentQuiescenceAuthorityV1
    )

    with pytest.raises(AttributeError):
        reconstructed._claimed_continuities = instance._claimed_continuities
    with pytest.raises(AttributeError):
        object.__setattr__(reconstructed, "_layout", instance._layout)
    with pytest.raises(authority.AuthorityUnavailable, match="reconstruction"):
        reconstructed.issue("plan-reference-1")


def test_authority_rejects_an_unattested_object_new_state_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "private-state" / "the-hive-ga-i2d-quiescence"
    state.mkdir(mode=0o700, parents=True)
    monkeypatch.delenv("STATE_DIRECTORY", raising=False)
    forged = object.__new__(runtime_layout.RuntimeStateLayoutV1)
    object.__setattr__(forged, "state_root", state)
    object.__setattr__(forged, "state_root_device", state.stat().st_dev)
    object.__setattr__(forged, "state_root_inode", state.stat().st_ino)
    plan, principal, target = _ports()

    with pytest.raises(authority.AuthorityUnavailable, match="state_layout"):
        authority.GoogleInventoryDeploymentQuiescenceAuthorityV1(
            forged,
            plan,
            principal,
            target,
        )


def test_authority_rejects_subclassed_layout_before_it_can_select_a_caller_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    caller_store = tmp_path / "caller-controlled-store"
    caller_store.mkdir(mode=0o700)

    class CallerControlledLayout(runtime_layout.RuntimeStateLayoutV1):
        def validate(self) -> None:
            return None

        def open_dirfd(self) -> int:
            return os.open(caller_store, os.O_RDONLY | os.O_DIRECTORY)

    forged = object.__new__(CallerControlledLayout)
    plan, principal, target = _ports()

    with pytest.raises(authority.AuthorityUnavailable, match="state_layout"):
        authority.GoogleInventoryDeploymentQuiescenceAuthorityV1(
            forged,
            plan,
            principal,
            target,
        )
    assert list(caller_store.iterdir()) == []


def test_issue_rejects_a_principal_without_the_required_repository_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, principal, _target = _authority(tmp_path, monkeypatch)
    principal.value = replace(principal.value, repository_scope="")

    with pytest.raises(authority.AuthorityUnavailable, match="repository"):
        instance.issue("plan-reference-1")


def test_issue_rejects_a_planbinding_result_for_a_different_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, plan, _principal, _target = _authority(tmp_path, monkeypatch)
    plan.value = replace(plan.value, plan_reference="plan-reference-2")

    with pytest.raises(authority.AuthorityUnavailable, match="plan_reference"):
        instance.issue("plan-reference-1")


def test_open_receipt_uses_boottime_not_utc_as_its_expiry_decider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    clock.utc += 600 * 1_000_000_000

    assert instance.resolve(receipt.receipt_reference) == receipt


@pytest.mark.parametrize(
    "unsafe_reference",
    ("person@example.invalid", "binding.json", "client-secret-plan"),
)
def test_issue_never_persists_an_email_filename_or_secret_bearing_plan_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe_reference: str
) -> None:
    instance, _clock, plan, _principal, _target = _authority(tmp_path, monkeypatch)
    plan.value = replace(plan.value, plan_reference=unsafe_reference)

    with pytest.raises(authority.AuthorityUnavailable):
        instance.issue(unsafe_reference)
    assert list(instance._layout.state_directory.iterdir()) == []


@pytest.mark.parametrize(
    ("source", "field"),
    (
        ("plan", "inventory_authority_generation"),
        ("plan", "manifest_generation"),
        ("plan", "inventory_generation"),
        ("plan", "registry_generation"),
        ("plan", "plan_digest"),
        ("plan", "inventory_authority_fingerprint"),
        ("plan", "manifest_fingerprint"),
        ("plan", "inventory_content_fingerprint"),
        ("plan", "registry_fingerprint"),
        ("plan", "candidate_inventory_fingerprint"),
        ("principal", "authority_generation"),
    ),
)
def test_issue_rejects_free_filename_values_for_all_persistable_generations_and_fingerprints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str, field: str
) -> None:
    instance, _clock, plan, principal, target = _authority(tmp_path, monkeypatch)
    if source == "plan":
        plan.value = replace(plan.value, **{field: "manifest.json"})
    else:
        changed_principal = replace(
            principal.value,
            **{field: "manifest.json"},
        )
        principal.value = replace(
            changed_principal,
            scope_digest=_digest(authority._principal_projection(changed_principal)),
        )
        changed_target = replace(
            target.value,
            principal_generation="manifest.json",
        )
        target.value = replace(
            changed_target,
            target_set_digest=_digest(authority._target_projection(changed_target)),
        )

    with pytest.raises(authority.AuthorityUnavailable):
        instance.issue("plan-reference-1")
    assert list(instance._layout.state_directory.iterdir()) == []


def test_unreadable_known_claimed_record_is_indeterminate_and_not_remintable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    instance.claim(receipt.receipt_reference)
    record = (
        instance._layout.state_directory
        / f"{receipt.receipt_reference}-claimed.json"
    )
    record.write_text("{", encoding="utf-8")
    record.chmod(0o600)

    with pytest.raises(authority.AuthorityIndeterminate, match="unreadable"):
        instance.resolve(receipt.receipt_reference)
    with pytest.raises(authority.AuthorityIndeterminate, match="unreadable"):
        instance.issue("plan-reference-1")


def test_authority_has_no_unused_receipt_store_facade() -> None:
    assert not hasattr(authority, "_ReceiptStoreFacade")


def test_issue_rejects_a_false_action_target_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, plan, _principal, _target = _authority(tmp_path, monkeypatch)
    plan.value = replace(
        plan.value, target_class="inventory-desktop-clients-v1"
    )

    with pytest.raises(authority.AuthorityUnavailable, match="action_target"):
        instance.issue("plan-reference-1")


@pytest.mark.parametrize(
    "field",
    (
        "inventory_authority_generation",
        "manifest_generation",
        "inventory_generation",
        "registry_generation",
    ),
)
def test_each_plan_generation_drift_blocks_receipt_reattestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    instance, _clock, plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    plan.value = replace(plan.value, **{field: "different-generation"})

    with pytest.raises(authority.AuthorityUnavailable):
        instance.resolve(receipt.receipt_reference)


@pytest.mark.parametrize(
    "field",
    (
        "plan_digest",
        "inventory_authority_fingerprint",
        "manifest_fingerprint",
        "inventory_content_fingerprint",
        "registry_fingerprint",
        "candidate_inventory_fingerprint",
    ),
)
def test_each_plan_fingerprint_drift_blocks_receipt_reattestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    instance, _clock, plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    plan.value = replace(plan.value, **{field: "sha256:" + "2" * 64})

    with pytest.raises(authority.AuthorityUnavailable):
        instance.resolve(receipt.receipt_reference)


@pytest.mark.parametrize(
    "field,value",
    (
        ("principal_id", "foreign-principal"),
        ("authority_generation", "different-generation"),
        ("lease_id", "different-lease"),
        ("lease_expires_boottime_ns", _BOOT - 1),
        ("repository_scope", "foreign-repository"),
        ("scopes", ("ga_i2d.quiescence.issue",)),
        ("queen_authorization_digest", "sha256:" + "2" * 64),
    ),
)
def test_each_principal_lease_or_scope_drift_blocks_receipt_reattestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    instance, _clock, _plan, principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    principal.value = replace(principal.value, **{field: value})

    with pytest.raises(authority.QuiescenceAuthorityError):
        instance.resolve(receipt.receipt_reference)


@pytest.mark.parametrize(
    "field,value",
    (
        ("action", "inventory.schema2_to_schema3"),
        ("target_class", "inventory-desktop-clients-v1"),
        ("principal_id", "foreign-principal"),
        ("principal_generation", "different-generation"),
        ("lease_id", "different-lease"),
        ("owner", "different-owner"),
        ("consumers", ("different-consumer",)),
    ),
)
def test_each_targetset_binding_drift_blocks_receipt_reattestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    instance, _clock, _plan, _principal, target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    changed = replace(target.value, **{field: value})
    target.value = replace(
        changed,
        target_set_digest=_digest(authority._target_projection(changed)),
    )

    with pytest.raises(authority.QuiescenceAuthorityError):
        instance.resolve(receipt.receipt_reference)


def test_consume_requires_a_claim_and_the_exact_claim_continuity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")

    with pytest.raises(authority.AuthorityIndeterminate, match="claim_required"):
        instance.consume(receipt.receipt_reference, object())  # type: ignore[arg-type]
    continuity = instance.claim(receipt.receipt_reference)
    wrong_continuity = authority._ClaimContinuity(
        instance, receipt.receipt_reference, continuity.binding_digest
    )
    with pytest.raises(authority.AuthorityIndeterminate, match="continuity"):
        instance.consume(receipt.receipt_reference, wrong_continuity)
    recovered = instance.resolve(receipt.receipt_reference)
    assert recovered is not None
    assert recovered.state == "INDETERMINATE"


@pytest.mark.parametrize(
    "boundary",
    (
        "after_temp_write",
        "after_temp_fsync",
        "after_rename",
        "after_parent_fsync",
        "after_readback",
    ),
)
def test_crash_at_each_claim_persistence_boundary_is_indeterminate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    original_unlink = os.unlink

    def crash_at_boundary(state: str, observed_boundary: str) -> None:
        if state == "CLAIMED" and observed_boundary == boundary:
            raise RuntimeError("simulated_process_stop")

    def retain_crashed_temp(path: str, *args: object, **kwargs: object) -> None:
        if path.startswith(".receipt-v1-") and path.endswith(".tmp"):
            return None
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(authority, "_store_checkpoint", crash_at_boundary)
    monkeypatch.setattr(os, "unlink", retain_crashed_temp)
    with pytest.raises(RuntimeError, match="simulated_process_stop"):
        instance.claim(receipt.receipt_reference)
    monkeypatch.setattr(authority, "_store_checkpoint", lambda state, point: None)
    monkeypatch.setattr(os, "unlink", original_unlink)

    with pytest.raises(authority.AuthorityIndeterminate):
        instance.resolve(receipt.receipt_reference)


def test_unknown_temp_or_symlink_artifact_blocks_the_global_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    state = instance._layout.state_directory
    (state / ".leftover.tmp").write_text("x", encoding="utf-8")
    (state / ".leftover.tmp").chmod(0o600)

    with pytest.raises(authority.AuthorityUnavailable, match="unknown_store_artifact"):
        instance.resolve("0" * 32)

    (state / ".leftover.tmp").unlink()
    outside = tmp_path / "outside"
    outside.write_text("x", encoding="utf-8")
    outside.chmod(0o600)
    (state / "foreign.json").symlink_to(outside)
    with pytest.raises(authority.AuthorityUnavailable):
        instance.resolve("0" * 32)


def test_missing_renameat2_is_fail_closed_without_replace_or_rename_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    record = (
        instance._layout.state_directory
        / f"{receipt.receipt_reference}-issued.json"
    )
    original_record = record.read_bytes()

    def forbidden_replace(*args: object, **kwargs: object) -> None:
        raise AssertionError("os.replace fallback was attempted")

    def forbidden_rename(*args: object, **kwargs: object) -> None:
        raise AssertionError("os.rename fallback was attempted")

    monkeypatch.setattr(authority, "_renameat2_noreplace", None)
    monkeypatch.setattr(os, "replace", forbidden_replace)
    monkeypatch.setattr(os, "rename", forbidden_rename)
    dirfd = instance._layout.open_dirfd()
    try:
        with pytest.raises(authority.AuthorityUnavailable, match="renameat2"):
            authority._persist_new_record(dirfd, receipt)
    finally:
        os.close(dirfd)

    assert record.read_bytes() == original_record
    assert not list(
        instance._layout.state_directory.glob(f".{receipt.receipt_reference}.*.tmp")
    )


def test_claim_rechecks_expiry_after_acquiring_the_store_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    original_open_lock = authority._open_lock

    def acquire_lock_then_expire_receipt(dirfd: int) -> int:
        lockfd = original_open_lock(dirfd)
        clock.boot = receipt.expires_boottime_ns
        return lockfd

    monkeypatch.setattr(authority, "_open_lock", acquire_lock_then_expire_receipt)
    with pytest.raises(authority.AuthorityUnavailable, match="receipt_expired"):
        instance.claim(receipt.receipt_reference)

    assert instance._read_store()[receipt.receipt_reference].state == "ISSUED"


def test_consume_rechecks_expiry_after_acquiring_the_store_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    continuity = instance.claim(receipt.receipt_reference)
    original_open_lock = authority._open_lock

    def acquire_lock_then_expire_receipt(dirfd: int) -> int:
        lockfd = original_open_lock(dirfd)
        clock.boot = receipt.expires_boottime_ns
        return lockfd

    monkeypatch.setattr(authority, "_open_lock", acquire_lock_then_expire_receipt)
    with pytest.raises(authority.AuthorityIndeterminate, match="consume_reattest_failed"):
        instance.consume(receipt.receipt_reference, continuity)

    assert instance._read_store()[receipt.receipt_reference].state == "INDETERMINATE"


def test_consume_rechecks_expiry_after_port_reattest_before_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, clock, plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    continuity = instance.claim(receipt.receipt_reference)
    original_read = plan.read
    advance_once = True

    def advance_during_consume(*args: object) -> object:
        nonlocal advance_once
        value = original_read(*args)
        if advance_once:
            clock.boot = receipt.expires_boottime_ns
            advance_once = False
        return value

    monkeypatch.setattr(plan, "read", advance_during_consume)
    with pytest.raises(authority.AuthorityIndeterminate, match="consume_reattest_failed"):
        instance.consume(receipt.receipt_reference, continuity)

    assert instance._read_store()[receipt.receipt_reference].state == "INDETERMINATE"


@pytest.mark.parametrize(
    "boundary",
    (
        "after_temp_write",
        "after_temp_fsync",
        "after_rename",
        "after_parent_fsync",
        "after_readback",
        "after_cleanup",
    ),
)
def test_claim_expiry_during_durable_transition_is_terminal_indeterminate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    instance, clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    original_checkpoint = authority._store_checkpoint
    seen: list[str] = []

    def advance_at_boundary(state: str, observed_boundary: str) -> None:
        original_checkpoint(state, observed_boundary)
        seen.append(observed_boundary)
        if state == "CLAIMED" and observed_boundary == boundary:
            clock.boot = receipt.expires_boottime_ns

    monkeypatch.setattr(authority, "_store_checkpoint", advance_at_boundary)
    with pytest.raises(authority.AuthorityIndeterminate, match="claim_transition"):
        instance.claim(receipt.receipt_reference)

    assert boundary in seen
    stored = instance._read_store()[receipt.receipt_reference]
    assert stored.state == "INDETERMINATE"


@pytest.mark.parametrize(
    "boundary",
    (
        "after_temp_write",
        "after_temp_fsync",
        "after_rename",
        "after_parent_fsync",
        "after_readback",
        "after_cleanup",
    ),
)
def test_consume_expiry_during_durable_transition_is_terminal_indeterminate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    instance, clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    continuity = instance.claim(receipt.receipt_reference)
    original_checkpoint = authority._store_checkpoint
    seen: list[str] = []

    def advance_at_boundary(state: str, observed_boundary: str) -> None:
        original_checkpoint(state, observed_boundary)
        seen.append(observed_boundary)
        if state == "CONSUMED" and observed_boundary == boundary:
            clock.boot = receipt.expires_boottime_ns

    monkeypatch.setattr(authority, "_store_checkpoint", advance_at_boundary)
    with pytest.raises(authority.AuthorityIndeterminate, match="consume_transition"):
        instance.consume(receipt.receipt_reference, continuity)

    assert boundary in seen
    stored = instance._read_store()[receipt.receipt_reference]
    assert stored.state == "INDETERMINATE"


def test_issue_reattests_clock_after_acquiring_the_store_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    original_open_lock = authority._open_lock

    def acquire_lock_then_advance_clock(dirfd: int) -> int:
        lockfd = original_open_lock(dirfd)
        clock.boot = _BOOT + 61 * 1_000_000_000
        return lockfd

    monkeypatch.setattr(authority, "_open_lock", acquire_lock_then_advance_clock)

    receipt = instance.issue("plan-reference-1")

    assert receipt.issued_boottime_ns == clock.boot
    assert receipt.expires_boottime_ns > clock.boot
    assert instance.resolve(receipt.receipt_reference) == receipt


def test_crash_after_noreplace_rename_is_indeterminate_on_next_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")

    def crash_after_rename(state: str, boundary: str) -> None:
        if boundary == "after_rename":
            raise RuntimeError("simulated_process_stop")

    monkeypatch.setattr(authority, "_store_checkpoint", crash_after_rename)
    with pytest.raises(RuntimeError, match="simulated_process_stop"):
        instance.claim(receipt.receipt_reference)

    monkeypatch.setattr(authority, "_store_checkpoint", lambda state, boundary: None)
    with pytest.raises(authority.AuthorityIndeterminate, match="ambiguous"):
        instance.resolve(receipt.receipt_reference)


def test_record_mode_and_linkcount_are_rechecked_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _clock, _plan, _principal, _target = _authority(tmp_path, monkeypatch)
    receipt = instance.issue("plan-reference-1")
    record = instance._layout.state_directory / f"{receipt.receipt_reference}-issued.json"
    record.chmod(0o644)
    with pytest.raises(authority.AuthorityUnavailable, match="store_file_invariant"):
        instance.resolve(receipt.receipt_reference)

    record.chmod(0o600)
    outside = tmp_path / "hardlink"
    outside.hardlink_to(record)
    with pytest.raises(authority.AuthorityUnavailable, match="store_file_invariant"):
        instance.resolve(receipt.receipt_reference)


def test_state_layout_rejects_admin_vault_and_runtime_image_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for parent_name in ("admin", "codex-master-vault", "runtime-image"):
        parent = tmp_path / parent_name
        state = parent / "the-hive-ga-i2d-quiescence"
        state.mkdir(mode=0o700, parents=True)
        monkeypatch.setenv("STATE_DIRECTORY", str(state))
        with pytest.raises(runtime_layout.LayoutError):
            runtime_layout.RuntimeStateLayoutV1.from_systemd_state_directory()


def test_state_directory_requires_exactly_one_private_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "the-hive-ga-i2d-quiescence"
    state.mkdir(mode=0o700)
    monkeypatch.delenv("STATE_DIRECTORY", raising=False)
    with pytest.raises(runtime_layout.LayoutError):
        runtime_layout.RuntimeStateLayoutV1.from_systemd_state_directory()
    monkeypatch.setenv("STATE_DIRECTORY", f"{state}:{state}")
    with pytest.raises(runtime_layout.LayoutError):
        runtime_layout.RuntimeStateLayoutV1.from_systemd_state_directory()
    state.chmod(0o755)
    monkeypatch.setenv("STATE_DIRECTORY", str(state))
    with pytest.raises(runtime_layout.LayoutError):
        runtime_layout.RuntimeStateLayoutV1.from_systemd_state_directory()
