from __future__ import annotations

import ast
import copy
import dataclasses
from dataclasses import replace
import gc
from pathlib import Path
import pickle
from threading import Barrier, Event, Thread

import pytest

import codex_master.fleet_root_runtime_host as host_module
from codex_master.codex_usage_credential_authority import ProfileCredentialBinding
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetRuntimePrincipalV2,
    FleetSeries,
    FleetSnapshot,
    LimitState,
    MAX_GENERATION,
    Provider,
    RunnerKind,
    SecretState,
    fleet_document,
    normalize_fleet_document,
)
from codex_master.fleet_registry_v2_migration import (
    PreparedFleetRegistryV2Migration,
    RegistryV2MigrationError,
    RegistryV2QuiescenceEvidence,
    prepare_fleet_registry_v2_migration,
)
from codex_master.fleet_root_runtime_host import (
    FleetRootRuntimeHost,
    FleetRootRuntimeHostError,
    RootAdmissionStopOwnership,
    RootHostParticipant,
    RootHostParticipantBinding,
    RootQuiescenceWindow,
    RootRuntimeActivityOwnership,
)


GENERATION = 17
ACCOUNT_ID = "openai-primary"
PROFILE_ID = "BW_Nufker"
BINDING_ID = "hmac-sha256:" + "a" * 64
PRINCIPAL_ID = "tl-" + "1" * 32


def source_snapshot() -> FleetSnapshot:
    source = FleetSnapshot(
        schema_version=1,
        generation=GENERATION,
        accounts=(
            FleetAccount(
                account_id=ACCOUNT_ID,
                label="OpenAI primary",
                provider=Provider.OPENAI_CHATGPT,
                auth_kind=AuthKind.CHATGPT_SESSION,
                secret_state=SecretState.CONFIGURED,
                limit_state=LimitState.READY,
                enabled=True,
                reset_at_utc=None,
                last_probe_at_utc="2026-08-27T00:00:00Z",
                limit_reason=None,
            ),
            FleetAccount(
                account_id="gemini-secondary",
                label="Gemini secondary",
                provider=Provider.GEMINI_API,
                auth_kind=AuthKind.API_KEY,
                secret_state=SecretState.CONFIGURED,
                limit_state=LimitState.READY,
                enabled=True,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=None,
            ),
        ),
        series=(
            FleetSeries(
                prefix="o",
                display_name="Old local series",
                count=2,
                runner=RunnerKind.CODEX_CLI,
                provider=Provider.OLLAMA_LOCAL,
                model="local-model",
                account_id=None,
                enabled=True,
            ),
        ),
    )
    normalized = normalize_fleet_document(fleet_document(source))
    assert type(normalized) is FleetSnapshot
    return normalized


def runtime_principal() -> FleetRuntimePrincipalV2:
    return FleetRuntimePrincipalV2(
        principal_id=PRINCIPAL_ID,
        account_id=ACCOUNT_ID,
        profile_id=PROFILE_ID,
        credential_binding_id=BINDING_ID,
        class_id="teamleiterin",
        lifecycle="persistent",
        provider=Provider.OPENAI_CHATGPT,
        runner=RunnerKind.CODEX_CLI,
        model="gpt-5.6-terra",
        reasoning="xhigh",
        enabled=True,
    )


def participant_bindings(
    generation: int = 1,
) -> tuple[RootHostParticipantBinding, ...]:
    return tuple(
        RootHostParticipantBinding(participant, generation)
        for participant in RootHostParticipant
    )


def reconciled_host(generation: int = 1) -> FleetRootRuntimeHost:
    host = FleetRootRuntimeHost()
    assert host.reconcile(participant_bindings(generation)) == 1
    return host


def stopped_window() -> tuple[
    FleetRootRuntimeHost,
    RootAdmissionStopOwnership,
    RootQuiescenceWindow,
    FleetSnapshot,
]:
    host = reconciled_host()
    admission = host.stop_admission()
    source = source_snapshot()
    window = host.open_quiescence_window(admission, source)
    return host, admission, window, source


def assert_code(code: str, operation) -> None:
    with pytest.raises(FleetRootRuntimeHostError) as caught:
        operation()
    assert caught.value.code == code
    assert caught.value.args == (code,)
    assert repr(caught.value) == f"FleetRootRuntimeHostError('{code}')"


def test_fresh_host_requires_exact_closed_reconciliation() -> None:
    host = FleetRootRuntimeHost()
    state = host.snapshot()
    assert state.reconciled is False
    assert state.host_generation == 0
    assert state.runtime_broker_epoch == 0
    assert_code("host_unreconciled", host.stop_admission)
    assert_code("host_unreconciled", lambda: host.probe_quiescence(object()))

    exact = participant_bindings()
    invalid = (
        exact[:-1],
        exact[:-1] + (exact[0],),
        exact[:-1] + (RootHostParticipantBinding(exact[-1].participant, 2),),
        exact[:-1] + (RootHostParticipantBinding("free_participant", 1),),
        tuple(replace(item, generation=True) for item in exact),
    )
    for bindings in invalid:
        assert_code(
            "participant_contract_invalid",
            lambda bindings=bindings: host.reconcile(bindings),
        )
        assert host.snapshot() == state

    assert host.reconcile(exact) == 1
    reconciled = host.snapshot()
    assert reconciled.reconciled is True
    assert reconciled.host_generation == 1
    assert reconciled.participant_generation == 1
    assert reconciled.runtime_broker_epoch == 1

    restarted = FleetRootRuntimeHost()
    assert restarted.snapshot().reconciled is False
    assert_code("host_unreconciled", restarted.stop_admission)


def test_participant_loss_requires_current_binding_and_fresh_generation() -> None:
    host = reconciled_host()
    current = participant_bindings()
    assert_code(
        "participant_contract_invalid",
        lambda: host.mark_participant_lost(
            RootHostParticipantBinding(RootHostParticipant.RECOVERY, True)
        ),
    )
    assert_code(
        "participant_contract_invalid",
        lambda: host.mark_participant_lost(
            RootHostParticipantBinding(RootHostParticipant.RECOVERY, 2)
        ),
    )

    host.mark_participant_lost(current[-1])
    assert host.snapshot().reconciled is False
    assert_code("host_unreconciled", host.stop_admission)
    assert_code(
        "participant_generation_stale",
        lambda: host.reconcile(participant_bindings(1)),
    )
    assert host.reconcile(participant_bindings(2)) == 2
    assert host.snapshot().participant_generation == 2


ACTIVITIES = (
    (
        "begin_principal_or_agent",
        "end_principal_or_agent",
        "active_principals_or_agents",
    ),
    (
        "begin_lease_or_reservation",
        "end_lease_or_reservation",
        "active_leases_or_reservations",
    ),
    (
        "begin_registry_or_broker_transaction",
        "end_registry_or_broker_transaction",
        "pending_registry_or_broker_transactions",
    ),
    ("begin_recovery", "end_recovery", "pending_recoveries"),
)


@pytest.mark.parametrize(("begin_name", "end_name", "counter"), ACTIVITIES)
def test_each_activity_has_one_owned_begin_and_terminal_end(
    begin_name: str, end_name: str, counter: str
) -> None:
    host = reconciled_host()
    before = host.snapshot()
    ownership = getattr(host, begin_name)()
    active = host.snapshot()

    assert type(ownership) is RootRuntimeActivityOwnership
    assert ownership.host_generation == active.host_generation
    assert ownership.begin_epoch == before.runtime_broker_epoch + 1
    assert active.runtime_broker_epoch == ownership.begin_epoch
    assert getattr(active, counter) == 1
    assert sum(getattr(active, item[2]) for item in ACTIVITIES) == 1

    terminal_epoch = getattr(host, end_name)(ownership)
    ended = host.snapshot()
    assert terminal_epoch == active.runtime_broker_epoch + 1
    assert ended.runtime_broker_epoch == terminal_epoch
    assert getattr(ended, counter) == 0


def test_double_end_foreign_host_wrong_category_and_stale_generation_block() -> None:
    host = reconciled_host()
    ownership = host.begin_lease_or_reservation()
    assert_code("ownership_invalid", lambda: host.end_recovery(ownership))

    foreign = reconciled_host()
    assert_code(
        "ownership_invalid",
        lambda: foreign.end_lease_or_reservation(ownership),
    )

    original_generation = ownership.host_generation
    object.__setattr__(ownership, "host_generation", original_generation + 1)
    assert_code(
        "host_generation_stale",
        lambda: host.end_lease_or_reservation(ownership),
    )
    object.__setattr__(ownership, "host_generation", original_generation)

    original_epoch = ownership.begin_epoch
    object.__setattr__(ownership, "begin_epoch", original_epoch + 1)
    assert_code(
        "ownership_invalid",
        lambda: host.end_lease_or_reservation(ownership),
    )
    object.__setattr__(ownership, "begin_epoch", original_epoch)

    host.end_lease_or_reservation(ownership)
    after = host.snapshot()
    assert_code(
        "ownership_invalid",
        lambda: host.end_lease_or_reservation(ownership),
    )
    assert host.snapshot() == after


def test_activity_ownership_cannot_be_cloned_replaced_pickled_or_rebuilt() -> None:
    host = reconciled_host()
    ownership = host.begin_recovery()

    for clone in (
        lambda: copy.copy(ownership),
        lambda: copy.deepcopy(ownership),
        lambda: pickle.dumps(ownership),
        lambda: dataclasses.replace(ownership),
    ):
        with pytest.raises(TypeError):
            clone()
    with pytest.raises(TypeError):
        RootRuntimeActivityOwnership(
            ownership.host_generation,
            ownership.begin_epoch,
        )

    forged = object.__new__(RootRuntimeActivityOwnership)
    object.__setattr__(forged, "host_generation", ownership.host_generation)
    object.__setattr__(forged, "begin_epoch", ownership.begin_epoch)
    assert_code("ownership_invalid", lambda: host.end_recovery(forged))
    host.end_recovery(ownership)


def test_parallel_activity_uses_one_epoch_and_counter_serialization() -> None:
    host = reconciled_host()
    start = Barrier(33)
    all_begun = Barrier(33)
    release_end = Event()
    results: list[tuple[int, int]] = []

    def worker() -> None:
        start.wait()
        ownership = host.begin_lease_or_reservation()
        all_begun.wait()
        release_end.wait()
        terminal = host.end_lease_or_reservation(ownership)
        results.append((ownership.begin_epoch, terminal))

    threads = [Thread(target=worker) for _ in range(32)]
    for thread in threads:
        thread.start()
    start.wait()
    all_begun.wait()
    active = host.snapshot()
    assert active.active_leases_or_reservations == 32
    release_end.set()
    for thread in threads:
        thread.join(2)
    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 32
    epochs = {epoch for pair in results for epoch in pair}
    assert epochs == set(range(2, 66))
    final = host.snapshot()
    assert final.active_leases_or_reservations == 0
    assert final.runtime_broker_epoch == 65


def test_epoch_overflow_blocks_before_state_change() -> None:
    host = reconciled_host()
    host._epoch = MAX_GENERATION
    before = host.snapshot()

    assert_code("epoch_overflow", host.begin_recovery)
    assert host.snapshot() == before


def test_window_requires_stopped_admission_and_zero_activity() -> None:
    host = reconciled_host()
    source = source_snapshot()
    assert_code(
        "admission_open",
        lambda: host.open_quiescence_window(object(), source),
    )
    assert_code("quiescence_window_stale", lambda: host.probe_quiescence(object()))

    ownership = host.begin_lease_or_reservation()
    admission = host.stop_admission()
    assert_code(
        "activity_present",
        lambda: host.open_quiescence_window(admission, source),
    )
    host.end_lease_or_reservation(ownership)
    window = host.open_quiescence_window(admission, source)
    assert type(host.probe_quiescence(window)) is RegistryV2QuiescenceEvidence


def test_between_probe_activity_invalidates_epoch_even_after_terminal_end() -> None:
    host, _admission, window, _source = stopped_window()
    first = host.probe_quiescence(window)
    ownership = host.begin_registry_or_broker_transaction()
    host.end_registry_or_broker_transaction(ownership)

    assert host.snapshot().pending_registry_or_broker_transactions == 0
    assert host.snapshot().runtime_broker_epoch == first.runtime_broker_epoch + 2
    assert_code("quiescence_epoch_drift", lambda: host.probe_quiescence(window))


def test_parallel_start_invalidates_window_before_activity_is_visible() -> None:
    host, _admission, window, _source = stopped_window()
    start = Barrier(2)
    begun = Event()
    release = Event()

    def worker() -> None:
        start.wait()
        ownership = host.begin_recovery()
        begun.set()
        release.wait()
        host.end_recovery(ownership)

    thread = Thread(target=worker)
    thread.start()
    start.wait()
    assert begun.wait(1)
    visible = host.snapshot()
    assert visible.pending_recoveries == 1
    assert_code("quiescence_epoch_drift", lambda: host.probe_quiescence(window))
    release.set()
    thread.join(2)
    assert not thread.is_alive()


def test_window_close_abort_and_reopen_have_exact_ownership() -> None:
    host, admission, window, source = stopped_window()
    foreign = reconciled_host().stop_admission()
    assert_code("ownership_invalid", lambda: host.reopen_admission(foreign))

    host.close_quiescence_window(window)
    assert host.snapshot().admission_stopped is True
    assert_code("quiescence_window_stale", lambda: host.close_quiescence_window(window))
    host.reopen_admission(admission)
    assert host.snapshot().admission_stopped is False
    assert_code("ownership_invalid", lambda: host.reopen_admission(admission))

    admission = host.stop_admission()
    window = host.open_quiescence_window(admission, source)
    activity = host.begin_recovery()
    assert_code("quiescence_epoch_drift", lambda: host.probe_quiescence(window))
    host.abort_quiescence_window(window)
    assert_code("quiescence_window_stale", lambda: host.abort_quiescence_window(window))
    host.end_recovery(activity)
    host.reopen_admission(admission)


def test_lost_window_never_closes_or_reopens_itself() -> None:
    host, admission, window, source = stopped_window()
    del window
    gc.collect()

    assert host.snapshot().admission_stopped is True
    assert_code(
        "quiescence_window_stale",
        lambda: host.open_quiescence_window(admission, source),
    )


def test_admission_window_and_activity_capabilities_are_nontransferable() -> None:
    host, admission, window, _source = stopped_window()
    for capability in (admission, window):
        for clone in (
            lambda capability=capability: copy.copy(capability),
            lambda capability=capability: copy.deepcopy(capability),
            lambda capability=capability: pickle.dumps(capability),
            lambda capability=capability: dataclasses.replace(capability),
        ):
            with pytest.raises(TypeError):
                clone()

    with pytest.raises(TypeError):
        RootAdmissionStopOwnership(admission.host_generation, admission.stop_epoch)
    with pytest.raises(TypeError):
        RootQuiescenceWindow(
            window.host_generation,
            window.window_epoch,
            window.source_generation,
            window.source_digest,
        )

    original_stop_epoch = admission.stop_epoch
    object.__setattr__(admission, "stop_epoch", original_stop_epoch + 1)
    assert_code("ownership_invalid", lambda: host.reopen_admission(admission))
    object.__setattr__(admission, "stop_epoch", original_stop_epoch)

    original_host_generation = window.host_generation
    object.__setattr__(window, "host_generation", original_host_generation + 1)
    assert_code("host_generation_stale", lambda: host.probe_quiescence(window))
    object.__setattr__(window, "host_generation", original_host_generation)
    host.close_quiescence_window(window)
    host.reopen_admission(admission)


def test_stale_or_lost_window_never_attests_or_reopens_admission() -> None:
    host, admission, window, _source = stopped_window()
    host.mark_participant_lost(participant_bindings()[-1])

    assert host.snapshot().reconciled is False
    assert host.snapshot().admission_stopped is False
    assert_code("host_unreconciled", lambda: host.probe_quiescence(window))
    assert_code("ownership_invalid", lambda: host.reopen_admission(admission))


def test_probe_digest_matches_r1_prepared_and_is_stable_for_prepare() -> None:
    host, _admission, window, source = stopped_window()
    document_before = fleet_document(source)
    first = host.probe_quiescence(window)
    second = host.probe_quiescence(window)
    assert first == second

    prepared = prepare_fleet_registry_v2_migration(
        source,
        expected_generation=source.generation,
        profile_bindings={ACCOUNT_ID: ProfileCredentialBinding(PROFILE_ID, BINDING_ID)},
        runtime_principals=(runtime_principal(),),
        quiescence_probe=lambda: host.probe_quiescence(window),
    )

    assert type(prepared) is PreparedFleetRegistryV2Migration
    assert prepared.source_digest == first.source_digest
    assert prepared.quiescence_before == prepared.quiescence_after == first
    assert fleet_document(source) == document_before


def test_real_r1_prepare_blocks_activity_between_its_two_probes() -> None:
    host, _admission, window, source = stopped_window()

    class ActivityBindings(dict[str, ProfileCredentialBinding]):
        def items(self):  # type: ignore[no-untyped-def]
            ownership = host.begin_registry_or_broker_transaction()
            host.end_registry_or_broker_transaction(ownership)
            return super().items()

    with pytest.raises(RegistryV2MigrationError) as caught:
        prepare_fleet_registry_v2_migration(
            source,
            expected_generation=source.generation,
            profile_bindings=ActivityBindings(
                {ACCOUNT_ID: ProfileCredentialBinding(PROFILE_ID, BINDING_ID)}
            ),
            runtime_principals=(runtime_principal(),),
            quiescence_probe=lambda: host.probe_quiescence(window),
        )
    assert caught.value.code == "quiescence_probe_failed"
    assert host.snapshot().pending_registry_or_broker_transactions == 0


@pytest.mark.parametrize(
    "mutation",
    (
        "generation",
        "account",
        "series",
        "schema",
        "noncanonical",
        "digest",
    ),
)
def test_registry_source_drift_is_revalidated_before_evidence(mutation: str) -> None:
    host, _admission, window, source = stopped_window()
    if mutation == "generation":
        object.__setattr__(source, "generation", source.generation + 1)
    elif mutation == "account":
        object.__setattr__(source.accounts[0], "label", "drifted")
    elif mutation == "series":
        object.__setattr__(source, "series", ())
    elif mutation == "schema":
        object.__setattr__(source, "schema_version", 2)
    elif mutation == "noncanonical":
        object.__setattr__(source.accounts[0], "account_id", "../invalid")
    else:
        object.__setattr__(window, "source_digest", "sha256:" + "f" * 64)

    assert_code("registry_source_invalid", lambda: host.probe_quiescence(window))


def test_module_has_no_runtime_effect_or_generic_state_setter() -> None:
    source = Path(host_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        node.names[0].name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
    }
    imports.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    assert imports <= {
        "__future__",
        "dataclasses",
        "enum",
        "hashlib",
        "json",
        "threading",
        "codex_master",
    }
    forbidden = {
        "set_count",
        "set_quiescent",
        "set_stopped",
        "socket",
        "subprocess",
        "open",
        "recvmsg",
        "sendmsg",
        "SCM_RIGHTS",
        "FleetService",
    }
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names.update(
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    )
    assert names.isdisjoint(forbidden)
