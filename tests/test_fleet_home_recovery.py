from __future__ import annotations

import ast
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
import stat

import pytest

import codex_master.fleet_home_recovery as recovery_module
from codex_master.fleet_home_recovery import (
    MAX_FLEET_HOME_RECOVERY_BYTES,
    FleetHomeEntryKind,
    FleetHomeRecoveryAction,
    FleetHomeRecoveryAbsentEntryObservationV2,
    FleetHomeRecoveryAbsentHomeObservationV2,
    FleetHomeRecoveryAbsentHomeV2,
    FleetHomeRecoveryEntryObservationV2,
    FleetHomeRecoveryEntryV2,
    FleetHomeRecoveryHomeObservationV2,
    FleetHomeRecoveryHomeV2,
    FleetHomeRecoveryObjectSnapshot,
    FleetHomeRecoveryParentObservationV2,
    FleetHomeRecoveryParentV2,
    FleetHomeRecoveryPhase,
    FleetHomeRecoverySnapshotIdentity,
    FleetHomeRecoveryStat,
    FleetHomeRecoveryTransactionObservationV2,
    FleetHomeRecoveryTransactionV2,
    FleetHomeRecoveryValidationError,
    FleetHomeRecoveryPopulationEntryV2,
    FleetHomeRecoveryPopulationV2,
    advance_fleet_home_recovery_v2,
    apply_fleet_home_recovery_absent_v2,
    decode_fleet_home_recovery_transaction_v2,
    encode_fleet_home_recovery_transaction_v2,
    load_fleet_home_recovery_transaction_v2,
    make_fleet_home_recovery_transaction_v2,
    make_fleet_identity_journal_plan,
    persist_fleet_home_recovery_transaction_v2,
    plan_fleet_home_recovery_v2,
    validate_fleet_identity_journal_plan,
)


NONCE = "0123456789abcdef0123456789abcdef"
HOME_A_NONCE = "11111111111111111111111111111111"
HOME_B_NONCE = "22222222222222222222222222222222"
OLD_DIGEST = "1" * 64
NEW_DIGEST = "2" * 64
OTHER_DIGEST = "3" * 64
ABSENT_STAGING_NAME = f".fleet-home-staging-v2-{NONCE}-0000"


def stat_fixture(
    inode: int,
    kind: FleetHomeEntryKind,
    *,
    mode: int | None = None,
    size: int = 0,
    mtime_ns: int = 10,
) -> FleetHomeRecoveryStat:
    permissions = (
        mode
        if mode is not None
        else (0o700 if kind is FleetHomeEntryKind.DIRECTORY else 0o600)
    )
    object_type = stat.S_IFDIR if kind is FleetHomeEntryKind.DIRECTORY else stat.S_IFREG
    return FleetHomeRecoveryStat(
        dev=7,
        ino=inode,
        mode=object_type | permissions,
        uid=os.geteuid(),
        gid=os.getegid(),
        nlink=2 if kind is FleetHomeEntryKind.DIRECTORY else 1,
        size=size,
        mtime_ns=mtime_ns,
    )


def object_fixture(
    inode: int,
    kind: FleetHomeEntryKind,
    *,
    digest: str | None = None,
    mode: int | None = None,
    size: int = 4,
    mtime_ns: int = 10,
) -> FleetHomeRecoveryObjectSnapshot:
    return FleetHomeRecoveryObjectSnapshot(
        stat_fixture(inode, kind, mode=mode, size=size, mtime_ns=mtime_ns),
        digest if kind is FleetHomeEntryKind.FILE else None,
    )


def homes_fixture() -> tuple[FleetHomeRecoveryHomeV2, ...]:
    file_before = object_fixture(20, FleetHomeEntryKind.FILE, digest=OLD_DIGEST)
    directory_before = object_fixture(21, FleetHomeEntryKind.DIRECTORY, size=0)
    delete_before = object_fixture(22, FleetHomeEntryKind.FILE, digest=OTHER_DIGEST)
    nested_before = object_fixture(23, FleetHomeEntryKind.FILE, digest=OLD_DIGEST)
    return (
        FleetHomeRecoveryHomeV2(
            membership_index=0,
            member_id="a1",
            home_root_before=stat_fixture(10, FleetHomeEntryKind.DIRECTORY),
            parents=(
                FleetHomeRecoveryParentV2(
                    "nested",
                    stat_fixture(11, FleetHomeEntryKind.DIRECTORY),
                ),
            ),
            journal_plan=make_fleet_identity_journal_plan(
                HOME_A_NONCE,
                (
                    ("alpha", True, True),
                    ("beta", True, True),
                    ("gone", True, False),
                    ("nested/item", True, True),
                ),
            ),
            entries=(
                FleetHomeRecoveryEntryV2(
                    "alpha",
                    FleetHomeEntryKind.FILE,
                    file_before,
                    FleetHomeEntryKind.DIRECTORY,
                    0o700,
                    None,
                ),
                FleetHomeRecoveryEntryV2(
                    "beta",
                    FleetHomeEntryKind.DIRECTORY,
                    directory_before,
                    FleetHomeEntryKind.FILE,
                    0o600,
                    NEW_DIGEST,
                ),
                FleetHomeRecoveryEntryV2(
                    "gone",
                    FleetHomeEntryKind.FILE,
                    delete_before,
                    None,
                    None,
                    None,
                ),
                FleetHomeRecoveryEntryV2(
                    "nested/item",
                    FleetHomeEntryKind.FILE,
                    nested_before,
                    FleetHomeEntryKind.FILE,
                    0o700,
                    NEW_DIGEST,
                ),
            ),
        ),
        FleetHomeRecoveryHomeV2(
            membership_index=1,
            member_id="b1",
            home_root_before=stat_fixture(30, FleetHomeEntryKind.DIRECTORY),
            parents=(),
            journal_plan=make_fleet_identity_journal_plan(
                HOME_B_NONCE,
                (("created", False, True),),
            ),
            entries=(
                FleetHomeRecoveryEntryV2(
                    "created",
                    None,
                    None,
                    FleetHomeEntryKind.FILE,
                    0o600,
                    NEW_DIGEST,
                ),
            ),
        ),
    )


def transaction_fixture() -> FleetHomeRecoveryTransactionV2:
    return make_fleet_home_recovery_transaction_v2(
        nonce=NONCE,
        pool_parent_before=stat_fixture(1, FleetHomeEntryKind.DIRECTORY),
        current_snapshot=FleetHomeRecoverySnapshotIdentity(4, OLD_DIGEST),
        planned_snapshot=FleetHomeRecoverySnapshotIdentity(5, NEW_DIGEST),
        homes=homes_fixture(),
    )


def absent_home_fixture(
    *, membership_index: int = 0, member_id: str = "a1", final_name: str = "a1"
) -> FleetHomeRecoveryAbsentHomeV2:
    return FleetHomeRecoveryAbsentHomeV2(
        membership_index=membership_index,
        member_id=member_id,
        final_name=final_name,
        staging_name=f".fleet-home-staging-v2-{NONCE}-{membership_index:04d}",
        marker_path=".fleet-home-marker-v2.json",
        entries=(
            FleetHomeRecoveryEntryV2(
                "common.md",
                None,
                None,
                FleetHomeEntryKind.FILE,
                0o600,
                NEW_DIGEST,
            ),
            FleetHomeRecoveryEntryV2(
                "profiles",
                None,
                None,
                FleetHomeEntryKind.DIRECTORY,
                0o700,
                None,
            ),
            FleetHomeRecoveryEntryV2(
                "profiles/worker.md",
                None,
                None,
                FleetHomeEntryKind.FILE,
                0o600,
                OTHER_DIGEST,
            ),
            FleetHomeRecoveryEntryV2(
                ".fleet-home-marker-v2.json",
                None,
                None,
                FleetHomeEntryKind.FILE,
                0o600,
                OLD_DIGEST,
            ),
        ),
    )


def absent_transaction_fixture(
    *absent_homes: FleetHomeRecoveryAbsentHomeV2,
) -> FleetHomeRecoveryTransactionV2:
    return make_fleet_home_recovery_transaction_v2(
        nonce=NONCE,
        pool_parent_before=stat_fixture(1, FleetHomeEntryKind.DIRECTORY),
        current_snapshot=FleetHomeRecoverySnapshotIdentity(4, OLD_DIGEST),
        planned_snapshot=FleetHomeRecoverySnapshotIdentity(5, NEW_DIGEST),
        homes=(),
        absent_homes=absent_homes or (absent_home_fixture(),),
    )


def filesystem_stat(current: os.stat_result) -> FleetHomeRecoveryStat:
    return FleetHomeRecoveryStat(
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_uid,
        current.st_gid,
        current.st_nlink,
        current.st_size,
        current.st_mtime_ns,
    )


def absent_population_fixture() -> tuple[FleetHomeRecoveryPopulationV2, ...]:
    common = b"common-policy\n"
    profile = b"worker-profile\n"
    marker = b'{"schema_version":2}\n'
    return (
        FleetHomeRecoveryPopulationV2(
            "a1",
            (
                FleetHomeRecoveryPopulationEntryV2("common.md", common),
                FleetHomeRecoveryPopulationEntryV2("profiles", None),
                FleetHomeRecoveryPopulationEntryV2("profiles/worker.md", profile),
                FleetHomeRecoveryPopulationEntryV2(
                    ".fleet-home-marker-v2.json", marker
                ),
            ),
        ),
    )


def filesystem_absent_transaction(pool_fd: int) -> FleetHomeRecoveryTransactionV2:
    population = absent_population_fixture()[0]
    entries = (
        FleetHomeRecoveryEntryV2(
            "common.md",
            None,
            None,
            FleetHomeEntryKind.FILE,
            0o600,
            hashlib.sha256(population.entries[0].content).hexdigest(),
        ),
        FleetHomeRecoveryEntryV2(
            "profiles",
            None,
            None,
            FleetHomeEntryKind.DIRECTORY,
            0o700,
            None,
        ),
        FleetHomeRecoveryEntryV2(
            "profiles/worker.md",
            None,
            None,
            FleetHomeEntryKind.FILE,
            0o600,
            hashlib.sha256(population.entries[2].content).hexdigest(),
        ),
        FleetHomeRecoveryEntryV2(
            ".fleet-home-marker-v2.json",
            None,
            None,
            FleetHomeEntryKind.FILE,
            0o600,
            hashlib.sha256(population.entries[3].content).hexdigest(),
        ),
    )
    return make_fleet_home_recovery_transaction_v2(
        nonce=NONCE,
        pool_parent_before=filesystem_stat(os.fstat(pool_fd)),
        current_snapshot=FleetHomeRecoverySnapshotIdentity(4, OLD_DIGEST),
        planned_snapshot=FleetHomeRecoverySnapshotIdentity(5, NEW_DIGEST),
        homes=(),
        absent_homes=(
            FleetHomeRecoveryAbsentHomeV2(
                0,
                "a1",
                "a1",
                ABSENT_STAGING_NAME,
                ".fleet-home-marker-v2.json",
                entries,
            ),
        ),
    )


def absent_staged_observation(
    transaction: FleetHomeRecoveryTransactionV2,
    *,
    populated: int = 0,
    published: int = 0,
) -> FleetHomeRecoveryTransactionObservationV2:
    absent_homes = []
    for home_index, home in enumerate(transaction.absent_homes):
        staging = object_fixture(
            200 + home_index,
            FleetHomeEntryKind.DIRECTORY,
            size=96,
            mtime_ns=20 + populated,
        )
        entries = tuple(
            FleetHomeRecoveryAbsentEntryObservationV2(
                entry.name,
                (
                    replacement_fixture(home_index, entry_index, entry)
                    if entry_index < populated
                    else None
                ),
            )
            for entry_index, entry in enumerate(home.entries)
        )
        is_published = home_index < published
        absent_homes.append(
            FleetHomeRecoveryAbsentHomeObservationV2(
                home.membership_index,
                home.member_id,
                staging if is_published else None,
                None if is_published else staging,
                (),
                entries,
            )
        )
    return FleetHomeRecoveryTransactionObservationV2(
        replace(transaction.pool_parent_before, size=96, mtime_ns=20 + published),
        (),
        tuple(absent_homes),
    )


def test_absent_home_basis_roundtrips_strictly_with_exact_initial_absence() -> None:
    transaction = absent_transaction_fixture()
    assert transaction.phase is FleetHomeRecoveryPhase.ABSENT_CREATE_PENDING
    assert transaction.absent_homes[0].staging_name == ABSENT_STAGING_NAME
    assert transaction.records[0].observation.absent_homes == (
        FleetHomeRecoveryAbsentHomeObservationV2(
            membership_index=0,
            member_id="a1",
            final_identity=None,
            staging_identity=None,
            unexpected_entries=(),
            entries=(
                FleetHomeRecoveryAbsentEntryObservationV2("common.md", None),
                FleetHomeRecoveryAbsentEntryObservationV2("profiles", None),
                FleetHomeRecoveryAbsentEntryObservationV2("profiles/worker.md", None),
                FleetHomeRecoveryAbsentEntryObservationV2(
                    ".fleet-home-marker-v2.json", None
                ),
            ),
        ),
    )

    encoded = encode_fleet_home_recovery_transaction_v2(transaction)
    assert decode_fleet_home_recovery_transaction_v2(encoded) == transaction
    document = json.loads(encoded)
    assert document["basis"]["absent_homes"][0].get("marker_path") == (
        ".fleet-home-marker-v2.json"
    )
    assert set(document["basis"]) == {
        "pool_parent_before",
        "current_snapshot",
        "planned_snapshot",
        "homes",
        "absent_homes",
    }

    for mutation in ("missing", "unknown"):
        malformed = json.loads(encoded)
        if mutation == "missing":
            del malformed["basis"]["absent_homes"]
        else:
            malformed["basis"]["absent_homes"][0]["unknown"] = True
        with pytest.raises(FleetHomeRecoveryValidationError):
            decode_fleet_home_recovery_transaction_v2(
                json.dumps(
                    malformed,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                + b"\n"
            )


def test_mixed_existing_and_absent_homes_are_strictly_rejected() -> None:
    absent = replace(
        absent_home_fixture(),
        membership_index=2,
        member_id="c1",
        final_name="c1",
        staging_name=f".fleet-home-staging-v2-{NONCE}-0002",
    )
    with pytest.raises(FleetHomeRecoveryValidationError):
        make_fleet_home_recovery_transaction_v2(
            nonce=NONCE,
            pool_parent_before=stat_fixture(1, FleetHomeEntryKind.DIRECTORY),
            current_snapshot=FleetHomeRecoverySnapshotIdentity(4, OLD_DIGEST),
            planned_snapshot=FleetHomeRecoverySnapshotIdentity(5, NEW_DIGEST),
            homes=homes_fixture(),
            absent_homes=(absent,),
        )


@pytest.mark.parametrize(
    ("marker_path", "marker_mode"),
    (("common.md", 0o600), (".fleet-home-marker-v2.json", 0o700)),
)
def test_absent_home_marker_must_be_exactly_last_private_file(
    marker_path: str,
    marker_mode: int,
) -> None:
    home = absent_home_fixture()
    marker = replace(home.entries[-1], replacement_mode=marker_mode)
    with pytest.raises(FleetHomeRecoveryValidationError):
        absent_transaction_fixture(
            replace(
                home,
                marker_path=marker_path,
                entries=(*home.entries[:-1], marker),
            )
        )


def test_absent_home_planner_requires_persisted_pending_phases_and_blocks_drift() -> (
    None
):
    transaction = absent_transaction_fixture()
    before = transaction.records[-1].observation
    assert plan_fleet_home_recovery_v2(
        transaction,
        before,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    ) == (FleetHomeRecoveryAction.CREATE_STAGING, transaction)

    created = absent_staged_observation(transaction)
    action, blocked = plan_fleet_home_recovery_v2(
        transaction,
        created,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.BLOCK
    assert blocked.phase is FleetHomeRecoveryPhase.BLOCKED

    pinned = advance_fleet_home_recovery_v2(
        transaction,
        FleetHomeRecoveryPhase.ABSENT_PIN_PENDING,
        created,
    )
    assert plan_fleet_home_recovery_v2(
        pinned,
        created,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    ) == (FleetHomeRecoveryAction.PIN_STAGING, pinned)

    populate = advance_fleet_home_recovery_v2(
        pinned,
        FleetHomeRecoveryPhase.ABSENT_POPULATE_PENDING,
        created,
    )
    assert plan_fleet_home_recovery_v2(
        populate,
        created,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    ) == (FleetHomeRecoveryAction.POPULATE_STAGING, populate)

    populated = absent_staged_observation(
        transaction, populated=len(transaction.absent_homes[0].entries)
    )
    action, publish = plan_fleet_home_recovery_v2(
        populate,
        populated,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.PERSIST
    assert publish.phase is FleetHomeRecoveryPhase.ABSENT_PUBLISH_PENDING
    assert plan_fleet_home_recovery_v2(
        publish,
        populated,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    ) == (FleetHomeRecoveryAction.PUBLISH_HOME, publish)

    published_observation = absent_staged_observation(
        transaction,
        populated=len(transaction.absent_homes[0].entries),
        published=1,
    )
    action, published = plan_fleet_home_recovery_v2(
        publish,
        published_observation,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.PERSIST
    assert published.phase is FleetHomeRecoveryPhase.ABSENT_PUBLISHED

    action, cas = plan_fleet_home_recovery_v2(
        published,
        published_observation,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.PERSIST
    assert cas.phase is FleetHomeRecoveryPhase.CAS_PENDING


def test_absent_home_apply_requires_durable_intent_then_publishes_exact_tree(
    tmp_path: Path,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    try:
        transaction = filesystem_absent_transaction(pool_fd)
        population = absent_population_fixture()
        with pytest.raises(FleetHomeRecoveryValidationError):
            apply_fleet_home_recovery_absent_v2(
                recovery_fd, pool_fd, transaction, population
            )
        assert list(pool.iterdir()) == []

        expected_phases = (
            FleetHomeRecoveryPhase.ABSENT_PIN_PENDING,
            FleetHomeRecoveryPhase.ABSENT_POPULATE_PENDING,
            FleetHomeRecoveryPhase.ABSENT_PUBLISH_PENDING,
            FleetHomeRecoveryPhase.ABSENT_PUBLISHED,
            FleetHomeRecoveryPhase.CAS_PENDING,
        )
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
        for expected in expected_phases:
            transaction = apply_fleet_home_recovery_absent_v2(
                recovery_fd,
                pool_fd,
                transaction,
                population,
            )
            assert transaction.phase is expected
            persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)

        home = pool / "a1"
        assert not (pool / ABSENT_STAGING_NAME).exists()
        assert (home / "common.md").read_bytes() == b"common-policy\n"
        assert (home / "profiles" / "worker.md").read_bytes() == b"worker-profile\n"
        assert stat.S_IMODE(home.stat().st_mode) == 0o700
        assert stat.S_IMODE((home / "common.md").stat().st_mode) == 0o600
        assert sorted(
            path.relative_to(home).as_posix() for path in home.rglob("*")
        ) == [
            ".fleet-home-marker-v2.json",
            "common.md",
            "profiles",
            "profiles/worker.md",
        ]
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


def test_absent_home_unknown_prepin_or_final_object_is_preserved_and_blocked(
    tmp_path: Path,
) -> None:
    for foreign_name in (ABSENT_STAGING_NAME, "a1"):
        case = tmp_path / foreign_name.replace("/", "_")
        recovery = case / "recovery"
        pool = case / "pool"
        recovery.mkdir(parents=True, mode=0o700)
        pool.mkdir(mode=0o700)
        foreign = pool / foreign_name
        foreign.mkdir(mode=0o700)
        payload = foreign / "foreign"
        payload.write_bytes(b"keep")
        recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
        pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
        try:
            transaction = filesystem_absent_transaction(pool_fd)
            persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
            blocked = apply_fleet_home_recovery_absent_v2(
                recovery_fd,
                pool_fd,
                transaction,
                absent_population_fixture(),
            )
            assert blocked.phase is FleetHomeRecoveryPhase.BLOCKED
            assert payload.read_bytes() == b"keep"
        finally:
            os.close(pool_fd)
            os.close(recovery_fd)


def advance_absent_filesystem(
    recovery_fd: int,
    pool_fd: int,
    transaction: FleetHomeRecoveryTransactionV2,
    target: FleetHomeRecoveryPhase,
    population: tuple[FleetHomeRecoveryPopulationV2, ...],
) -> FleetHomeRecoveryTransactionV2:
    while transaction.phase is not target:
        transaction = apply_fleet_home_recovery_absent_v2(
            recovery_fd, pool_fd, transaction, population
        )
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
    return transaction


def classify_absent_authoritative_result(
    recovery_fd: int,
    pool_fd: int,
    transaction: FleetHomeRecoveryTransactionV2,
    population: tuple[FleetHomeRecoveryPopulationV2, ...],
    *,
    readable: bool,
    snapshot: FleetHomeRecoverySnapshotIdentity | None,
) -> FleetHomeRecoveryTransactionV2:
    action, observed = plan_fleet_home_recovery_v2(
        transaction,
        transaction.records[-1].observation,
        authoritative_readable=readable,
        authoritative_snapshot=snapshot,
        explicit_conflict=True,
    )
    assert action is FleetHomeRecoveryAction.PERSIST
    persist_fleet_home_recovery_transaction_v2(recovery_fd, observed)
    classified = apply_fleet_home_recovery_absent_v2(
        recovery_fd, pool_fd, observed, population
    )
    persist_fleet_home_recovery_transaction_v2(recovery_fd, classified)
    return classified


@pytest.mark.parametrize(
    ("authoritative", "readable", "decision", "terminal"),
    (
        (
            "new",
            True,
            FleetHomeRecoveryPhase.COMMIT_PENDING,
            FleetHomeRecoveryPhase.COMMITTED,
        ),
        (
            "old",
            True,
            FleetHomeRecoveryPhase.ROLLBACK_PENDING,
            FleetHomeRecoveryPhase.ROLLED_BACK,
        ),
        ("third", True, FleetHomeRecoveryPhase.BLOCKED, FleetHomeRecoveryPhase.BLOCKED),
        (
            "unreadable",
            False,
            FleetHomeRecoveryPhase.BLOCKED,
            FleetHomeRecoveryPhase.BLOCKED,
        ),
    ),
)
def test_absent_home_authoritative_result_commits_rolls_back_or_blocks(
    tmp_path: Path,
    authoritative: str,
    readable: bool,
    decision: FleetHomeRecoveryPhase,
    terminal: FleetHomeRecoveryPhase,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    population = absent_population_fixture()
    try:
        transaction = filesystem_absent_transaction(pool_fd)
        pool_before = transaction.pool_parent_before
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
        transaction = advance_absent_filesystem(
            recovery_fd,
            pool_fd,
            transaction,
            FleetHomeRecoveryPhase.CAS_PENDING,
            population,
        )
        final = pool / "a1"
        final_before = final.stat()
        snapshot = {
            "new": transaction.planned_snapshot,
            "old": transaction.current_snapshot,
            "third": FleetHomeRecoverySnapshotIdentity(9, OTHER_DIGEST),
            "unreadable": None,
        }[authoritative]
        transaction = classify_absent_authoritative_result(
            recovery_fd,
            pool_fd,
            transaction,
            population,
            readable=readable,
            snapshot=snapshot,
        )
        assert transaction.phase is decision

        if decision is not FleetHomeRecoveryPhase.BLOCKED:
            transaction = apply_fleet_home_recovery_absent_v2(
                recovery_fd, pool_fd, transaction, population
            )
        assert transaction.phase is terminal
        assert not (pool / ABSENT_STAGING_NAME).exists()
        if terminal is FleetHomeRecoveryPhase.COMMITTED:
            assert final.stat().st_ino == final_before.st_ino
            assert (final / ".fleet-home-marker-v2.json").read_bytes() == (
                b'{"schema_version":2}\n'
            )
            pool_after = filesystem_stat(os.fstat(pool_fd))
            assert pool_after.mtime_ns == pool_before.mtime_ns
        elif terminal is FleetHomeRecoveryPhase.ROLLED_BACK:
            assert not final.exists()
            assert filesystem_stat(os.fstat(pool_fd)) == pool_before
        else:
            assert final.stat().st_ino == final_before.st_ino
            assert (final / "common.md").read_bytes() == b"common-policy\n"
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


def test_absent_home_rollback_never_removes_drifted_bound_final(
    tmp_path: Path,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    population = absent_population_fixture()
    try:
        transaction = filesystem_absent_transaction(pool_fd)
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
        transaction = advance_absent_filesystem(
            recovery_fd,
            pool_fd,
            transaction,
            FleetHomeRecoveryPhase.CAS_PENDING,
            population,
        )
        transaction = classify_absent_authoritative_result(
            recovery_fd,
            pool_fd,
            transaction,
            population,
            readable=True,
            snapshot=transaction.current_snapshot,
        )
        final = pool / "a1"
        foreign = final / "foreign"
        foreign.write_bytes(b"keep")

        blocked = apply_fleet_home_recovery_absent_v2(
            recovery_fd, pool_fd, transaction, population
        )
        assert blocked.phase is FleetHomeRecoveryPhase.BLOCKED
        assert foreign.read_bytes() == b"keep"
        assert final.is_dir()
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


@pytest.mark.parametrize(
    ("start_phase", "selected_faultpoint", "expected_phase", "unknown_staging"),
    (
        (
            FleetHomeRecoveryPhase.ABSENT_CREATE_PENDING,
            "before_absent_staging_create",
            FleetHomeRecoveryPhase.ABSENT_PIN_PENDING,
            False,
        ),
        (
            FleetHomeRecoveryPhase.ABSENT_CREATE_PENDING,
            "after_absent_staging_create",
            FleetHomeRecoveryPhase.BLOCKED,
            True,
        ),
        (
            FleetHomeRecoveryPhase.ABSENT_CREATE_PENDING,
            "after_absent_staging_pin",
            FleetHomeRecoveryPhase.BLOCKED,
            True,
        ),
        (
            FleetHomeRecoveryPhase.ABSENT_PIN_PENDING,
            "before_absent_staging_pin",
            FleetHomeRecoveryPhase.ABSENT_POPULATE_PENDING,
            False,
        ),
        (
            FleetHomeRecoveryPhase.ABSENT_PIN_PENDING,
            "after_absent_staging_pin",
            FleetHomeRecoveryPhase.ABSENT_POPULATE_PENDING,
            False,
        ),
        (
            FleetHomeRecoveryPhase.ABSENT_POPULATE_PENDING,
            "before_absent_population_entry",
            FleetHomeRecoveryPhase.ABSENT_PUBLISH_PENDING,
            False,
        ),
        (
            FleetHomeRecoveryPhase.ABSENT_POPULATE_PENDING,
            "after_absent_population_entry",
            FleetHomeRecoveryPhase.ABSENT_PUBLISH_PENDING,
            False,
        ),
        (
            FleetHomeRecoveryPhase.ABSENT_PUBLISH_PENDING,
            "before_absent_home_publish",
            FleetHomeRecoveryPhase.ABSENT_PUBLISHED,
            False,
        ),
        (
            FleetHomeRecoveryPhase.ABSENT_PUBLISH_PENDING,
            "after_absent_home_publish",
            FleetHomeRecoveryPhase.ABSENT_PUBLISHED,
            False,
        ),
    ),
)
def test_absent_home_faultpoints_restart_or_preserve_unknown_prepin_orphan(
    tmp_path: Path,
    start_phase: FleetHomeRecoveryPhase,
    selected_faultpoint: str,
    expected_phase: FleetHomeRecoveryPhase,
    unknown_staging: bool,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    try:
        population = absent_population_fixture()
        transaction = filesystem_absent_transaction(pool_fd)
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
        transaction = advance_absent_filesystem(
            recovery_fd, pool_fd, transaction, start_phase, population
        )

        def fail(marker: str) -> None:
            if marker == selected_faultpoint:
                raise RuntimeError(marker)

        with pytest.raises(RuntimeError, match=selected_faultpoint):
            apply_fleet_home_recovery_absent_v2(
                recovery_fd,
                pool_fd,
                transaction,
                population,
                faultpoint=fail,
            )
        assert (
            load_fleet_home_recovery_transaction_v2(recovery_fd, NONCE) == transaction
        )

        restarted = apply_fleet_home_recovery_absent_v2(
            recovery_fd, pool_fd, transaction, population
        )
        if restarted.phase is start_phase and restarted != transaction:
            persist_fleet_home_recovery_transaction_v2(recovery_fd, restarted)
            restarted = apply_fleet_home_recovery_absent_v2(
                recovery_fd, pool_fd, restarted, population
            )
        assert restarted.phase is expected_phase
        if unknown_staging:
            assert (pool / ABSENT_STAGING_NAME).is_dir()
            assert not (pool / "a1").exists()
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


@pytest.mark.parametrize(
    ("selected_faultpoint", "marker_exists"),
    (("before_absent_marker", False), ("after_absent_marker", True)),
)
def test_absent_home_marker_is_last_with_persistent_before_after_faultpoints(
    tmp_path: Path,
    selected_faultpoint: str,
    marker_exists: bool,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    population = absent_population_fixture()
    try:
        transaction = filesystem_absent_transaction(pool_fd)
        home = transaction.absent_homes[0]
        assert home.marker_path == home.entries[-1].name
        assert home.entries[-1].replacement_mode == 0o600
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
        transaction = advance_absent_filesystem(
            recovery_fd,
            pool_fd,
            transaction,
            FleetHomeRecoveryPhase.ABSENT_POPULATE_PENDING,
            population,
        )

        def fail(marker: str) -> None:
            if marker == selected_faultpoint:
                raise RuntimeError(marker)

        with pytest.raises(RuntimeError, match=selected_faultpoint):
            apply_fleet_home_recovery_absent_v2(
                recovery_fd,
                pool_fd,
                transaction,
                population,
                faultpoint=fail,
            )
        staging = pool / ABSENT_STAGING_NAME
        marker = staging / home.marker_path
        assert marker.exists() is marker_exists
        assert all((staging / entry.name).exists() for entry in home.entries[:-1])
        assert (
            load_fleet_home_recovery_transaction_v2(recovery_fd, NONCE) == transaction
        )
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


def test_absent_home_population_revalidates_checkpoint_before_next_mutation(
    tmp_path: Path,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    population = absent_population_fixture()
    try:
        transaction = filesystem_absent_transaction(pool_fd)
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
        transaction = advance_absent_filesystem(
            recovery_fd,
            pool_fd,
            transaction,
            FleetHomeRecoveryPhase.ABSENT_POPULATE_PENDING,
            population,
        )
        staging = pool / ABSENT_STAGING_NAME
        tampered = False

        def tamper(marker: str) -> None:
            nonlocal tampered
            if marker != "after_absent_population_entry" or tampered:
                return
            tampered = True
            common = staging / "common.md"
            before = common.stat()
            common.write_bytes(b"foreign-data!\n")
            os.utime(common, ns=(before.st_atime_ns, before.st_mtime_ns))

        with pytest.raises(FleetHomeRecoveryValidationError):
            apply_fleet_home_recovery_absent_v2(
                recovery_fd,
                pool_fd,
                transaction,
                population,
                faultpoint=tamper,
            )
        assert (staging / "common.md").read_bytes() == b"foreign-data!\n"
        assert not (staging / "profiles").exists()
        assert not (staging / ".fleet-home-marker-v2.json").exists()
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


def test_absent_home_publish_rejects_hardlink_nlink_drift(
    tmp_path: Path,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    population = absent_population_fixture()
    try:
        transaction = filesystem_absent_transaction(pool_fd)
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
        transaction = advance_absent_filesystem(
            recovery_fd,
            pool_fd,
            transaction,
            FleetHomeRecoveryPhase.ABSENT_PUBLISH_PENDING,
            population,
        )
        staging = pool / ABSENT_STAGING_NAME
        linked = pool / "foreign-link"
        os.link(staging / "common.md", linked)

        with pytest.raises(FleetHomeRecoveryValidationError):
            apply_fleet_home_recovery_absent_v2(
                recovery_fd, pool_fd, transaction, population
            )
        assert linked.read_bytes() == b"common-policy\n"
        assert staging.is_dir()
        assert not (pool / "a1").exists()
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


@pytest.mark.parametrize(
    "selected_faultpoint",
    ("after_absent_staging_create", "after_absent_staging_pin"),
)
def test_absent_home_create_rejects_mkdir_to_open_and_after_open_path_swaps(
    tmp_path: Path,
    selected_faultpoint: str,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    original = pool / f"{ABSENT_STAGING_NAME}.original"
    replacement = pool / ABSENT_STAGING_NAME
    try:
        transaction = filesystem_absent_transaction(pool_fd)
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)

        def swap(marker: str) -> None:
            if marker != selected_faultpoint:
                return
            replacement.rename(original)
            replacement.mkdir(mode=0o700)

        with pytest.raises(FleetHomeRecoveryValidationError):
            apply_fleet_home_recovery_absent_v2(
                recovery_fd,
                pool_fd,
                transaction,
                absent_population_fixture(),
                faultpoint=swap,
            )
        assert original.is_dir()
        assert replacement.is_dir()
        assert list(replacement.iterdir()) == []
        assert (
            load_fleet_home_recovery_transaction_v2(recovery_fd, NONCE) == transaction
        )
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


@pytest.mark.parametrize(
    "selected_faultpoint",
    ("before_absent_home_publish", "after_absent_home_publish"),
)
def test_absent_home_publish_keeps_staging_fd_pinned_across_path_swaps(
    tmp_path: Path,
    selected_faultpoint: str,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    population = absent_population_fixture()
    try:
        transaction = filesystem_absent_transaction(pool_fd)
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
        transaction = advance_absent_filesystem(
            recovery_fd,
            pool_fd,
            transaction,
            FleetHomeRecoveryPhase.ABSENT_PUBLISH_PENDING,
            population,
        )
        staging = pool / ABSENT_STAGING_NAME
        final = pool / "a1"
        original = pool / "original"

        def swap(marker: str) -> None:
            if marker != selected_faultpoint:
                return
            current = staging if staging.exists() else final
            current.rename(original)
            replacement = staging if marker.startswith("before") else final
            replacement.mkdir(mode=0o700)
            (replacement / "foreign").write_bytes(b"keep")

        with pytest.raises(FleetHomeRecoveryValidationError):
            apply_fleet_home_recovery_absent_v2(
                recovery_fd,
                pool_fd,
                transaction,
                population,
                faultpoint=swap,
            )
        assert original.is_dir()
        foreign = staging if selected_faultpoint.startswith("before") else final
        assert (foreign / "foreign").read_bytes() == b"keep"
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


@pytest.mark.parametrize("drift_target", ("pool", "home", "nested", "file"))
def test_absent_home_publish_requires_exact_full_stat_checkpoint(
    tmp_path: Path,
    drift_target: str,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    population = absent_population_fixture()
    try:
        transaction = filesystem_absent_transaction(pool_fd)
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
        transaction = advance_absent_filesystem(
            recovery_fd,
            pool_fd,
            transaction,
            FleetHomeRecoveryPhase.ABSENT_PUBLISH_PENDING,
            population,
        )
        staging = pool / ABSENT_STAGING_NAME
        target = {
            "pool": pool,
            "home": staging,
            "nested": staging / "profiles",
            "file": staging / "common.md",
        }[drift_target]
        before = target.stat()
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 1))

        blocked = apply_fleet_home_recovery_absent_v2(
            recovery_fd, pool_fd, transaction, population
        )
        assert blocked.phase is FleetHomeRecoveryPhase.BLOCKED
        assert not (pool / "a1").exists()
        assert staging.exists()
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


def test_absent_home_publish_blocks_same_size_sha_tamper_and_staging_swap(
    tmp_path: Path,
) -> None:
    for case_name in ("sha", "staging-swap"):
        case = tmp_path / case_name
        recovery = case / "recovery"
        pool = case / "pool"
        recovery.mkdir(parents=True, mode=0o700)
        pool.mkdir(mode=0o700)
        recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
        pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
        try:
            population = absent_population_fixture()
            transaction = filesystem_absent_transaction(pool_fd)
            persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
            transaction = advance_absent_filesystem(
                recovery_fd,
                pool_fd,
                transaction,
                FleetHomeRecoveryPhase.ABSENT_PUBLISH_PENDING,
                population,
            )
            staging = pool / ABSENT_STAGING_NAME
            if case_name == "sha":
                common = staging / "common.md"
                before = common.stat()
                common.write_bytes(b"foreign-data!\n")
                os.utime(common, ns=(before.st_atime_ns, before.st_mtime_ns))
            else:
                original = pool / f"{ABSENT_STAGING_NAME}.original"
                staging.rename(original)
                staging.mkdir(mode=0o700)
                (staging / "foreign").write_bytes(b"keep")

            blocked = apply_fleet_home_recovery_absent_v2(
                recovery_fd, pool_fd, transaction, population
            )
            assert blocked.phase is FleetHomeRecoveryPhase.BLOCKED
            assert not (pool / "a1").exists()
            if case_name == "sha":
                assert (staging / "common.md").read_bytes() == b"foreign-data!\n"
            else:
                assert (staging / "foreign").read_bytes() == b"keep"
                assert original.is_dir()
        finally:
            os.close(pool_fd)
            os.close(recovery_fd)


def test_absent_home_multi_home_publish_has_one_pool_and_exact_membership(
    tmp_path: Path,
) -> None:
    recovery = tmp_path / "recovery"
    pool = tmp_path / "pool"
    recovery.mkdir(mode=0o700)
    pool.mkdir(mode=0o700)
    recovery_fd = os.open(recovery, os.O_RDONLY | os.O_DIRECTORY)
    pool_fd = os.open(pool, os.O_RDONLY | os.O_DIRECTORY)
    try:
        first_population = absent_population_fixture()[0]
        first = filesystem_absent_transaction(pool_fd).absent_homes[0]
        second = replace(
            first,
            membership_index=1,
            member_id="b1",
            final_name="b1",
            staging_name=f".fleet-home-staging-v2-{NONCE}-0001",
        )
        transaction = make_fleet_home_recovery_transaction_v2(
            nonce=NONCE,
            pool_parent_before=filesystem_stat(os.fstat(pool_fd)),
            current_snapshot=FleetHomeRecoverySnapshotIdentity(4, OLD_DIGEST),
            planned_snapshot=FleetHomeRecoverySnapshotIdentity(5, NEW_DIGEST),
            homes=(),
            absent_homes=(first, second),
        )
        population = (
            first_population,
            replace(first_population, member_id="b1"),
        )
        persist_fleet_home_recovery_transaction_v2(recovery_fd, transaction)
        transaction = advance_absent_filesystem(
            recovery_fd,
            pool_fd,
            transaction,
            FleetHomeRecoveryPhase.ABSENT_PUBLISHED,
            population,
        )
        assert (
            transaction.records[-1].observation.pool_parent.dev
            == os.fstat(pool_fd).st_dev
        )
        assert sorted(path.name for path in pool.iterdir()) == ["a1", "b1"]
        assert all((pool / member / "common.md").is_file() for member in ("a1", "b1"))
    finally:
        os.close(pool_fd)
        os.close(recovery_fd)


def replacement_fixture(
    home_index: int,
    entry_index: int,
    entry: FleetHomeRecoveryEntryV2,
) -> FleetHomeRecoveryObjectSnapshot | None:
    if entry.replacement_kind is None:
        return None
    return object_fixture(
        100 + home_index * 10 + entry_index,
        entry.replacement_kind,
        digest=entry.replacement_sha256,
        mode=entry.replacement_mode,
        size=0 if entry.replacement_kind is FleetHomeEntryKind.DIRECTORY else 4,
        mtime_ns=20,
    )


def before_observation(
    transaction: FleetHomeRecoveryTransactionV2,
) -> FleetHomeRecoveryTransactionObservationV2:
    return FleetHomeRecoveryTransactionObservationV2(
        pool_parent=transaction.pool_parent_before,
        homes=tuple(
            FleetHomeRecoveryHomeObservationV2(
                membership_index=home.membership_index,
                member_id=home.member_id,
                home_root=home.home_root_before,
                parents=tuple(
                    FleetHomeRecoveryParentObservationV2(parent.path, parent.before)
                    for parent in home.parents
                ),
                staging_identity=None,
                journal_identity=None,
                unexpected_slots=(),
                entries=tuple(
                    FleetHomeRecoveryEntryObservationV2(
                        entry.name, entry.before, None, None
                    )
                    for entry in home.entries
                ),
            )
            for home in transaction.homes
        ),
    )


def prepared_observation(
    transaction: FleetHomeRecoveryTransactionV2,
) -> FleetHomeRecoveryTransactionObservationV2:
    return FleetHomeRecoveryTransactionObservationV2(
        pool_parent=replace(transaction.pool_parent_before, size=96, mtime_ns=20),
        homes=tuple(
            FleetHomeRecoveryHomeObservationV2(
                membership_index=home.membership_index,
                member_id=home.member_id,
                home_root=home.home_root_before,
                parents=tuple(
                    FleetHomeRecoveryParentObservationV2(parent.path, parent.before)
                    for parent in home.parents
                ),
                staging_identity=None,
                journal_identity=object_fixture(
                    80 + home.membership_index,
                    FleetHomeEntryKind.DIRECTORY,
                    size=128,
                    mtime_ns=20,
                ),
                unexpected_slots=(),
                entries=tuple(
                    FleetHomeRecoveryEntryObservationV2(
                        entry.name,
                        entry.before,
                        None,
                        replacement_fixture(home.membership_index, index, entry),
                    )
                    for index, entry in enumerate(home.entries)
                ),
            )
            for home in transaction.homes
        ),
    )


def switched_observation(
    transaction: FleetHomeRecoveryTransactionV2,
) -> FleetHomeRecoveryTransactionObservationV2:
    prepared = prepared_observation(transaction)
    return replace(
        prepared,
        homes=tuple(
            replace(
                home_observation,
                home_root=replace(home.home_root_before, size=96, mtime_ns=30),
                parents=tuple(
                    FleetHomeRecoveryParentObservationV2(
                        parent.path,
                        replace(parent.before, size=96, mtime_ns=31),
                    )
                    for parent in home.parents
                ),
                journal_identity=replace(
                    home_observation.journal_identity,
                    stat=replace(
                        home_observation.journal_identity.stat, size=160, mtime_ns=30
                    ),
                ),
                entries=tuple(
                    replace(
                        observed,
                        live=observed.replacement_slot,
                        old_slot=entry.before,
                        replacement_slot=None,
                    )
                    for entry, observed in zip(
                        home.entries, home_observation.entries, strict=True
                    )
                ),
            )
            for home, home_observation in zip(
                transaction.homes, prepared.homes, strict=True
            )
        ),
    )


def test_switched_entry_requires_replacement_live_and_before_in_old_slot() -> None:
    transaction = transaction_fixture()
    entry = transaction.homes[0].entries[0]
    prepared = prepared_observation(transaction).homes[0].entries[0]
    switched = switched_observation(transaction).homes[0].entries[0]

    assert recovery_module._switched_entry(entry, prepared, switched) is True
    assert recovery_module._switched_entry(entry, prepared, prepared) is False


def partial_switch_observation(
    transaction: FleetHomeRecoveryTransactionV2,
) -> FleetHomeRecoveryTransactionObservationV2:
    prepared = prepared_observation(transaction)
    first_home = prepared.homes[0]
    first_entry = first_home.entries[0]
    return replace(
        prepared,
        homes=(
            replace(
                first_home,
                home_root=replace(first_home.home_root, size=96, mtime_ns=25),
                journal_identity=replace(
                    first_home.journal_identity,
                    stat=replace(
                        first_home.journal_identity.stat, size=144, mtime_ns=25
                    ),
                ),
                entries=(
                    replace(
                        first_entry,
                        live=None,
                        old_slot=transaction.homes[0].entries[0].before,
                    ),
                    *first_home.entries[1:],
                ),
            ),
            prepared.homes[1],
        ),
    )


def commit_partial_observation(
    transaction: FleetHomeRecoveryTransactionV2,
) -> FleetHomeRecoveryTransactionObservationV2:
    switched = switched_observation(transaction)
    home = switched.homes[0]
    return replace(
        switched,
        homes=(
            replace(
                home,
                journal_identity=replace(
                    home.journal_identity,
                    stat=replace(home.journal_identity.stat, size=144, mtime_ns=40),
                ),
                entries=(replace(home.entries[0], old_slot=None), *home.entries[1:]),
            ),
            switched.homes[1],
        ),
    )


def committed_observation(
    transaction: FleetHomeRecoveryTransactionV2,
) -> FleetHomeRecoveryTransactionObservationV2:
    switched = switched_observation(transaction)
    return FleetHomeRecoveryTransactionObservationV2(
        pool_parent=transaction.pool_parent_before,
        homes=tuple(
            replace(
                home,
                journal_identity=None,
                entries=tuple(
                    replace(entry, old_slot=None, replacement_slot=None)
                    for entry in home.entries
                ),
            )
            for home in switched.homes
        ),
    )


def rollback_partial_observation(
    transaction: FleetHomeRecoveryTransactionV2,
) -> FleetHomeRecoveryTransactionObservationV2:
    switched = switched_observation(transaction)
    home = switched.homes[0]
    entry = home.entries[0]
    return replace(
        switched,
        homes=(
            replace(
                home,
                home_root=replace(home.home_root, size=112, mtime_ns=40),
                journal_identity=replace(
                    home.journal_identity,
                    stat=replace(home.journal_identity.stat, size=176, mtime_ns=40),
                ),
                entries=(
                    replace(entry, live=None, replacement_slot=entry.live),
                    *home.entries[1:],
                ),
            ),
            switched.homes[1],
        ),
    )


def rolled_back_observation(
    transaction: FleetHomeRecoveryTransactionV2,
) -> FleetHomeRecoveryTransactionObservationV2:
    return before_observation(transaction)


def transaction_at_phase(
    phase: FleetHomeRecoveryPhase,
) -> FleetHomeRecoveryTransactionV2:
    transaction = transaction_fixture()
    if phase is FleetHomeRecoveryPhase.PREPARE_PENDING:
        return transaction
    prepared = prepared_observation(transaction)
    transaction = advance_fleet_home_recovery_v2(
        transaction, FleetHomeRecoveryPhase.PREPARED, prepared
    )
    if phase is FleetHomeRecoveryPhase.PREPARED:
        return transaction
    transaction = advance_fleet_home_recovery_v2(
        transaction,
        FleetHomeRecoveryPhase.SWITCH_PENDING,
        prepared,
    )
    if phase is FleetHomeRecoveryPhase.SWITCH_PENDING:
        return transaction
    switched = switched_observation(transaction)
    transaction = advance_fleet_home_recovery_v2(
        transaction, FleetHomeRecoveryPhase.SWITCHED, switched
    )
    if phase is FleetHomeRecoveryPhase.SWITCHED:
        return transaction
    transaction = advance_fleet_home_recovery_v2(
        transaction,
        FleetHomeRecoveryPhase.CAS_PENDING,
        switched,
    )
    if phase is FleetHomeRecoveryPhase.CAS_PENDING:
        return transaction
    raise AssertionError(phase)


def with_authoritative_result(
    transaction: FleetHomeRecoveryTransactionV2,
    snapshot: FleetHomeRecoverySnapshotIdentity | None,
    *,
    readable: bool,
    conflict: bool = False,
) -> FleetHomeRecoveryTransactionV2:
    return advance_fleet_home_recovery_v2(
        transaction,
        FleetHomeRecoveryPhase.CAS_PENDING,
        transaction.records[-1].observation,
        authoritative_readable=readable,
        authoritative_snapshot=snapshot,
        explicit_conflict=conflict,
    )


def pending_decision_transaction(
    phase: FleetHomeRecoveryPhase,
) -> FleetHomeRecoveryTransactionV2:
    cas = transaction_at_phase(FleetHomeRecoveryPhase.CAS_PENDING)
    snapshot = (
        cas.planned_snapshot
        if phase is FleetHomeRecoveryPhase.COMMIT_PENDING
        else cas.current_snapshot
    )
    with_result = with_authoritative_result(cas, snapshot, readable=True, conflict=True)
    return advance_fleet_home_recovery_v2(
        with_result,
        phase,
        with_result.records[-1].observation,
        authoritative_readable=True,
        authoritative_snapshot=snapshot,
        explicit_conflict=True,
    )


def open_private_parent(tmp_path: Path) -> tuple[Path, int]:
    parent = tmp_path / "state"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    return parent, os.open(parent, os.O_RDONLY | os.O_DIRECTORY)


def test_journal_plan_is_exact_immutable_and_ordered() -> None:
    entries = (("one", True, True), ("two", False, True), ("gone", True, False))
    plan = make_fleet_identity_journal_plan(HOME_A_NONCE, entries)

    assert plan.nonce == HOME_A_NONCE
    assert plan.staging_name == f".fleet-identity-staging-{HOME_A_NONCE}"
    assert plan.journal_name == f".fleet-identity-journal-{HOME_A_NONCE}"
    assert tuple((slot.old, slot.replacement) for slot in plan.slots) == (
        ("old-0000", "replacement-0000"),
        (None, "replacement-0001"),
        ("old-0002", None),
    )
    assert validate_fleet_identity_journal_plan(plan, entries) is plan


def test_basis_deduplicates_pool_and_home_root_authority() -> None:
    transaction = transaction_fixture()

    assert transaction.pool_parent_before.ino == 1
    assert [home.membership_index for home in transaction.homes] == [0, 1]
    assert transaction.homes[0].home_root_before.ino == 10
    assert [parent.path for parent in transaction.homes[0].parents] == ["nested"]
    assert all(
        parent.path != "" for home in transaction.homes for parent in home.parents
    )
    assert not hasattr(transaction.homes[0], "pool_parent_before")
    assert not hasattr(transaction.homes[0], "home_current")


def test_entry_contract_separates_before_and_replacement_kinds() -> None:
    transaction = transaction_fixture()
    entries = transaction.homes[0].entries
    switched = switched_observation(transaction).homes[0].entries

    assert (entries[0].before_kind, entries[0].replacement_kind) == (
        FleetHomeEntryKind.FILE,
        FleetHomeEntryKind.DIRECTORY,
    )
    assert stat.S_ISDIR(switched[0].live.stat.mode)
    assert (entries[1].before_kind, entries[1].replacement_kind) == (
        FleetHomeEntryKind.DIRECTORY,
        FleetHomeEntryKind.FILE,
    )
    assert stat.S_ISREG(switched[1].live.stat.mode)
    assert entries[2].replacement_kind is None
    assert switched[2].live is None


@pytest.mark.parametrize(
    ("phase", "current", "action", "success_phase"),
    (
        (
            FleetHomeRecoveryPhase.PREPARE_PENDING,
            prepared_observation,
            FleetHomeRecoveryAction.PREPARE,
            FleetHomeRecoveryPhase.PREPARED,
        ),
        (
            FleetHomeRecoveryPhase.SWITCH_PENDING,
            switched_observation,
            FleetHomeRecoveryAction.SWITCH,
            FleetHomeRecoveryPhase.SWITCHED,
        ),
        (
            FleetHomeRecoveryPhase.COMMIT_PENDING,
            committed_observation,
            FleetHomeRecoveryAction.COMMIT,
            FleetHomeRecoveryPhase.COMMITTED,
        ),
        (
            FleetHomeRecoveryPhase.ROLLBACK_PENDING,
            rolled_back_observation,
            FleetHomeRecoveryAction.ROLLBACK,
            FleetHomeRecoveryPhase.ROLLED_BACK,
        ),
    ),
)
def test_each_b1_action_requires_persisted_pending_and_success_revalidation(
    phase: FleetHomeRecoveryPhase,
    current,
    action: FleetHomeRecoveryAction,
    success_phase: FleetHomeRecoveryPhase,
) -> None:
    transaction = (
        transaction_at_phase(phase)
        if phase
        in {
            FleetHomeRecoveryPhase.PREPARE_PENDING,
            FleetHomeRecoveryPhase.SWITCH_PENDING,
        }
        else pending_decision_transaction(phase)
    )
    before_action = transaction.records[-1].observation

    actual_action, unchanged = plan_fleet_home_recovery_v2(
        transaction,
        before_action,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert actual_action is action
    assert unchanged is transaction
    assert unchanged.phase is phase

    actual_action, success = plan_fleet_home_recovery_v2(
        transaction,
        current(transaction),
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert actual_action is FleetHomeRecoveryAction.PERSIST
    assert success.phase is success_phase
    assert success.records[-2].phase is phase


def test_success_phase_must_be_persisted_before_next_pending_action() -> None:
    transaction = transaction_fixture()
    action, prepared = plan_fleet_home_recovery_v2(
        transaction,
        prepared_observation(transaction),
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.PERSIST
    assert prepared.phase is FleetHomeRecoveryPhase.PREPARED

    action, switch_pending = plan_fleet_home_recovery_v2(
        prepared,
        prepared.records[-1].observation,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.PERSIST
    assert switch_pending.phase is FleetHomeRecoveryPhase.SWITCH_PENDING

    action, unchanged = plan_fleet_home_recovery_v2(
        switch_pending,
        switch_pending.records[-1].observation,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.SWITCH
    assert unchanged is switch_pending


def test_partial_switch_is_persisted_then_resumed_idempotently() -> None:
    transaction = transaction_at_phase(FleetHomeRecoveryPhase.SWITCH_PENDING)
    partial = partial_switch_observation(transaction)

    action, checkpoint = plan_fleet_home_recovery_v2(
        transaction,
        partial,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.PERSIST
    assert checkpoint.phase is FleetHomeRecoveryPhase.SWITCH_PENDING
    assert checkpoint.retry_count == 1
    assert checkpoint.records[-1].observation == partial

    action, unchanged = plan_fleet_home_recovery_v2(
        checkpoint,
        partial,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.SWITCH
    assert unchanged is checkpoint


@pytest.mark.parametrize(
    ("phase", "partial_factory", "action"),
    (
        (
            FleetHomeRecoveryPhase.COMMIT_PENDING,
            commit_partial_observation,
            FleetHomeRecoveryAction.COMMIT,
        ),
        (
            FleetHomeRecoveryPhase.ROLLBACK_PENDING,
            rollback_partial_observation,
            FleetHomeRecoveryAction.ROLLBACK,
        ),
    ),
)
def test_partial_finalize_is_checkpointed_before_resume(
    phase: FleetHomeRecoveryPhase,
    partial_factory,
    action: FleetHomeRecoveryAction,
) -> None:
    transaction = pending_decision_transaction(phase)
    partial = partial_factory(transaction)

    planned_action, checkpoint = plan_fleet_home_recovery_v2(
        transaction,
        partial,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert planned_action is FleetHomeRecoveryAction.PERSIST
    assert checkpoint.phase is phase
    assert checkpoint.retry_count == 1

    planned_action, unchanged = plan_fleet_home_recovery_v2(
        checkpoint,
        partial,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert planned_action is action
    assert unchanged is checkpoint


def test_pending_foreign_slot_or_digest_drift_blocks() -> None:
    transaction = transaction_at_phase(FleetHomeRecoveryPhase.SWITCH_PENDING)
    partial = partial_switch_observation(transaction)
    home = partial.homes[0]
    entry = home.entries[1]
    bad_digest = replace(
        partial,
        homes=(
            replace(
                home,
                entries=(
                    home.entries[0],
                    replace(
                        entry,
                        replacement_slot=replace(
                            entry.replacement_slot, sha256=OTHER_DIGEST
                        ),
                    ),
                    *home.entries[2:],
                ),
            ),
            partial.homes[1],
        ),
    )
    extra_slot = replace(
        partial,
        homes=(replace(home, unexpected_slots=("foreign-slot",)), partial.homes[1]),
    )

    for observation in (bad_digest, extra_slot):
        action, blocked = plan_fleet_home_recovery_v2(
            transaction,
            observation,
            authoritative_readable=None,
            authoritative_snapshot=None,
            explicit_conflict=False,
        )
        assert action is FleetHomeRecoveryAction.BLOCK
        assert blocked.phase is FleetHomeRecoveryPhase.BLOCKED


@pytest.mark.parametrize(
    ("classification", "readable", "conflict", "pending_phase"),
    (
        ("new", True, False, FleetHomeRecoveryPhase.COMMIT_PENDING),
        ("new", True, True, FleetHomeRecoveryPhase.COMMIT_PENDING),
        ("old", True, False, FleetHomeRecoveryPhase.ROLLBACK_PENDING),
        ("old", True, True, FleetHomeRecoveryPhase.ROLLBACK_PENDING),
        ("third", True, True, FleetHomeRecoveryPhase.BLOCKED),
        ("unreadable", False, True, FleetHomeRecoveryPhase.BLOCKED),
    ),
)
def test_authoritative_snapshot_alone_selects_commit_or_rollback(
    classification: str,
    readable: bool,
    conflict: bool,
    pending_phase: FleetHomeRecoveryPhase,
) -> None:
    transaction = transaction_at_phase(FleetHomeRecoveryPhase.CAS_PENDING)
    authoritative = {
        "new": transaction.planned_snapshot,
        "old": transaction.current_snapshot,
        "third": FleetHomeRecoverySnapshotIdentity(99, OTHER_DIGEST),
        "unreadable": None,
    }[classification]

    action, result_record = plan_fleet_home_recovery_v2(
        transaction,
        transaction.records[-1].observation,
        authoritative_readable=readable,
        authoritative_snapshot=authoritative,
        explicit_conflict=conflict,
    )
    assert action is FleetHomeRecoveryAction.PERSIST
    assert result_record.phase is FleetHomeRecoveryPhase.CAS_PENDING
    assert result_record.records[-1].explicit_conflict is conflict

    action, decision = plan_fleet_home_recovery_v2(
        result_record,
        result_record.records[-1].observation,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action in {FleetHomeRecoveryAction.PERSIST, FleetHomeRecoveryAction.BLOCK}
    assert decision.phase is pending_phase
    if classification == "old":
        assert decision.phase is FleetHomeRecoveryPhase.ROLLBACK_PENDING


def test_cas_action_requires_persisted_cas_pending_without_result() -> None:
    switched = transaction_at_phase(FleetHomeRecoveryPhase.SWITCHED)
    action, pending = plan_fleet_home_recovery_v2(
        switched,
        switched.records[-1].observation,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.PERSIST
    assert pending.phase is FleetHomeRecoveryPhase.CAS_PENDING

    action, unchanged = plan_fleet_home_recovery_v2(
        pending,
        pending.records[-1].observation,
        authoritative_readable=None,
        authoritative_snapshot=None,
        explicit_conflict=False,
    )
    assert action is FleetHomeRecoveryAction.CAS
    assert unchanged is pending


def test_final_parent_mtimes_are_strict() -> None:
    commit_pending = pending_decision_transaction(FleetHomeRecoveryPhase.COMMIT_PENDING)
    committed = committed_observation(commit_pending)
    drifted_commit = replace(
        committed, pool_parent=replace(committed.pool_parent, mtime_ns=999)
    )
    rollback_pending = pending_decision_transaction(
        FleetHomeRecoveryPhase.ROLLBACK_PENDING
    )
    rolled_back = rolled_back_observation(rollback_pending)
    first_home = rolled_back.homes[0]
    drifted_rollback = replace(
        rolled_back,
        homes=(
            replace(first_home, home_root=replace(first_home.home_root, mtime_ns=999)),
            rolled_back.homes[1],
        ),
    )

    for transaction, observation in (
        (commit_pending, drifted_commit),
        (rollback_pending, drifted_rollback),
    ):
        action, blocked = plan_fleet_home_recovery_v2(
            transaction,
            observation,
            authoritative_readable=None,
            authoritative_snapshot=None,
            explicit_conflict=False,
        )
        assert action is FleetHomeRecoveryAction.BLOCK
        assert blocked.phase is FleetHomeRecoveryPhase.BLOCKED


def test_codec_roundtrip_is_canonical_strict_and_bounded() -> None:
    transaction = transaction_fixture()
    raw = encode_fleet_home_recovery_transaction_v2(transaction)

    assert decode_fleet_home_recovery_transaction_v2(raw) == transaction
    assert raw.endswith(b"\n")
    assert len(raw) <= MAX_FLEET_HOME_RECOVERY_BYTES
    document = json.loads(raw)
    document["unexpected"] = True
    malformed = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    with pytest.raises(FleetHomeRecoveryValidationError):
        decode_fleet_home_recovery_transaction_v2(malformed)
    with pytest.raises(FleetHomeRecoveryValidationError):
        decode_fleet_home_recovery_transaction_v2(
            b"{" + b" " * MAX_FLEET_HOME_RECOVERY_BYTES + b"}"
        )


def test_persisted_chain_has_immutable_basis_once_and_compact_records(
    tmp_path: Path,
) -> None:
    parent, parent_fd = open_private_parent(tmp_path)
    initial = transaction_fixture()
    prepared = advance_fleet_home_recovery_v2(
        initial,
        FleetHomeRecoveryPhase.PREPARED,
        prepared_observation(initial),
    )
    try:
        persist_fleet_home_recovery_transaction_v2(parent_fd, initial)
        persist_fleet_home_recovery_transaction_v2(parent_fd, prepared)
        loaded = load_fleet_home_recovery_transaction_v2(parent_fd, NONCE)
    finally:
        os.close(parent_fd)

    record0 = json.loads(
        (parent / f".fleet-home-recovery-v2-{NONCE}-0000.json").read_bytes()
    )
    record1 = json.loads(
        (parent / f".fleet-home-recovery-v2-{NONCE}-0001.json").read_bytes()
    )
    assert set(record0) == {"basis", "nonce", "record", "schema_version"}
    assert set(record1) == {
        "authoritative_readable",
        "authoritative_snapshot",
        "current_observation",
        "explicit_conflict",
        "index",
        "nonce",
        "phase",
        "previous_digest",
        "retry_count",
        "schema_version",
    }
    assert "basis" not in record1
    assert "records" not in record1
    assert len(json.dumps(record1)) < len(json.dumps(record0))
    assert loaded == prepared


@pytest.mark.parametrize("future_kind", ("record", "temp"))
def test_record0_preflights_every_future_name_before_mutation(
    tmp_path: Path,
    future_kind: str,
) -> None:
    parent, parent_fd = open_private_parent(tmp_path)
    final = f".fleet-home-recovery-v2-{NONCE}-0015.json"
    name = final if future_kind == "record" else f".{final}.tmp"
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"foreign\n")
    (parent / name).symlink_to(foreign)
    try:
        with pytest.raises(FleetHomeRecoveryValidationError, match="collision"):
            persist_fleet_home_recovery_transaction_v2(parent_fd, transaction_fixture())
    finally:
        os.close(parent_fd)

    assert (parent / name).is_symlink()
    assert foreign.read_bytes() == b"foreign\n"
    assert not (parent / f".fleet-home-recovery-v2-{NONCE}-0000.json").exists()
    assert not (parent / f"..fleet-home-recovery-v2-{NONCE}-0000.json.tmp").exists()


def test_loader_revalidates_record_bytes_and_name_against_fd(tmp_path: Path) -> None:
    parent, parent_fd = open_private_parent(tmp_path)
    transaction = transaction_fixture()
    record = parent / f".fleet-home-recovery-v2-{NONCE}-0000.json"

    def tamper(marker: str) -> None:
        if marker != "before_recovery_final_identity_revalidation":
            return
        before = record.stat()
        raw = record.read_bytes()
        record.write_bytes(b"[" + raw[1:])
        record.chmod(0o600)
        os.utime(record, ns=(before.st_atime_ns, before.st_mtime_ns))

    try:
        persist_fleet_home_recovery_transaction_v2(parent_fd, transaction)
        with pytest.raises(FleetHomeRecoveryValidationError):
            load_fleet_home_recovery_transaction_v2(parent_fd, NONCE, faultpoint=tamper)
    finally:
        os.close(parent_fd)

    assert record.read_bytes().startswith(b"[")


def test_temp_cleanup_preserves_same_inode_foreign_modification(tmp_path: Path) -> None:
    parent, parent_fd = open_private_parent(tmp_path)
    temp = parent / f"..fleet-home-recovery-v2-{NONCE}-0000.json.tmp"

    def tamper(marker: str) -> None:
        if marker != "before_recovery_record_publish":
            return
        raw = temp.read_bytes()
        temp.write_bytes(b"[" + raw[1:])
        temp.chmod(0o600)
        raise RuntimeError("injected")

    try:
        with pytest.raises(FleetHomeRecoveryValidationError, match="cleanup_diverged"):
            persist_fleet_home_recovery_transaction_v2(
                parent_fd,
                transaction_fixture(),
                faultpoint=tamper,
            )
    finally:
        os.close(parent_fd)

    assert temp.read_bytes().startswith(b"[")


@pytest.mark.parametrize(
    ("selected_faultpoint", "published"),
    (
        ("after_recovery_temp_open", False),
        ("after_recovery_file_fsync", False),
        ("before_recovery_record_publish", False),
        ("after_recovery_record_publish", True),
        ("after_recovery_parent_fsync", True),
    ),
)
@pytest.mark.parametrize("followup", (False, True), ids=("record0", "followup"))
def test_persist_faultpoints_leave_exact_restartable_state(
    tmp_path: Path,
    selected_faultpoint: str,
    published: bool,
    followup: bool,
) -> None:
    parent, parent_fd = open_private_parent(tmp_path)
    initial = transaction_fixture()
    transaction = initial
    record_index = 0
    if followup:
        persist_fleet_home_recovery_transaction_v2(parent_fd, initial)
        transaction = advance_fleet_home_recovery_v2(
            initial,
            FleetHomeRecoveryPhase.PREPARED,
            prepared_observation(initial),
        )
        record_index = 1
    previous_names = {
        f".fleet-home-recovery-v2-{NONCE}-{index:04d}.json"
        for index in range(record_index)
    }
    final_name = f".fleet-home-recovery-v2-{NONCE}-{record_index:04d}.json"

    def fail(marker: str) -> None:
        if marker == selected_faultpoint:
            raise RuntimeError("injected")

    try:
        with pytest.raises(RuntimeError, match="injected"):
            persist_fleet_home_recovery_transaction_v2(
                parent_fd, transaction, faultpoint=fail
            )
        expected_names = previous_names | ({final_name} if published else set())
        assert {entry.name for entry in parent.iterdir()} == expected_names
        if published:
            assert load_fleet_home_recovery_transaction_v2(parent_fd, NONCE) == (
                transaction
            )
            with pytest.raises(FleetHomeRecoveryValidationError, match="collision"):
                persist_fleet_home_recovery_transaction_v2(parent_fd, transaction)
        else:
            persist_fleet_home_recovery_transaction_v2(parent_fd, transaction)
            assert load_fleet_home_recovery_transaction_v2(parent_fd, NONCE) == (
                transaction
            )
    finally:
        os.close(parent_fd)


@pytest.mark.parametrize(
    "race",
    ("future_record_symlink", "future_temp_object", "parent_drift", "final_object"),
)
def test_last_prepublish_revalidates_every_reserved_name_and_parent(
    tmp_path: Path,
    race: str,
) -> None:
    parent, parent_fd = open_private_parent(tmp_path)
    final = parent / f".fleet-home-recovery-v2-{NONCE}-0000.json"
    temp = parent / f".{final.name}.tmp"
    future_final = parent / f".fleet-home-recovery-v2-{NONCE}-0015.json"
    future_temp = parent / f".{future_final.name}.tmp"
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"foreign\n")
    raced_path = {
        "future_record_symlink": future_final,
        "future_temp_object": future_temp,
        "parent_drift": parent / "unrelated-foreign",
        "final_object": final,
    }[race]

    def race_at_last_check(marker: str) -> None:
        if marker != "before_recovery_record_publish":
            return
        if race == "future_record_symlink":
            raced_path.symlink_to(foreign)
        else:
            raced_path.write_bytes(b"foreign\n")
            raced_path.chmod(0o600)

    try:
        with pytest.raises(FleetHomeRecoveryValidationError):
            persist_fleet_home_recovery_transaction_v2(
                parent_fd,
                transaction_fixture(),
                faultpoint=race_at_last_check,
            )
    finally:
        os.close(parent_fd)

    assert raced_path.is_symlink() or raced_path.read_bytes() == b"foreign\n"
    assert foreign.read_bytes() == b"foreign\n"
    assert not temp.exists()
    assert {entry.name for entry in parent.iterdir()} == {raced_path.name}
    if race != "final_object":
        assert not final.exists()


@pytest.mark.parametrize(
    ("faultpoint", "swap_name"),
    (
        ("after_recovery_temp_open", "temp"),
        ("after_recovery_file_fsync", "temp"),
        ("before_recovery_record_publish", "temp"),
        ("after_recovery_record_publish", "final"),
        ("after_recovery_parent_fsync", "final"),
    ),
)
def test_record_publish_swap_preserves_foreign_objects(
    tmp_path: Path,
    faultpoint: str,
    swap_name: str,
) -> None:
    parent, parent_fd = open_private_parent(tmp_path)
    final = parent / f".fleet-home-recovery-v2-{NONCE}-0000.json"
    temp = parent / f".{final.name}.tmp"
    raced = temp if swap_name == "temp" else final
    moved = parent / f"owned-{swap_name}"
    owned_bytes: bytes | None = None

    def swap(marker: str) -> None:
        nonlocal owned_bytes
        if marker != faultpoint:
            return
        owned_bytes = raced.read_bytes()
        raced.rename(moved)
        raced.write_bytes(b"foreign\n")
        raced.chmod(0o600)

    try:
        with pytest.raises(FleetHomeRecoveryValidationError):
            persist_fleet_home_recovery_transaction_v2(
                parent_fd, transaction_fixture(), faultpoint=swap
            )
    finally:
        os.close(parent_fd)

    assert raced.read_bytes() == b"foreign\n"
    if faultpoint != "after_recovery_temp_open":
        assert moved.read_bytes() == owned_bytes
    else:
        assert moved.read_bytes() != b"foreign\n"
    assert {entry.name for entry in parent.iterdir()} == {raced.name, moved.name}


@pytest.mark.parametrize("tampered_index", (0, 1))
def test_followup_pins_previous_chain_and_blocks_same_size_mtime_tamper(
    tmp_path: Path,
    tampered_index: int,
) -> None:
    parent, parent_fd = open_private_parent(tmp_path)
    initial = transaction_fixture()
    prepared = advance_fleet_home_recovery_v2(
        initial,
        FleetHomeRecoveryPhase.PREPARED,
        prepared_observation(initial),
    )
    switch_pending = advance_fleet_home_recovery_v2(
        prepared,
        FleetHomeRecoveryPhase.SWITCH_PENDING,
        prepared.records[-1].observation,
    )
    previous_records = tuple(
        parent / f".fleet-home-recovery-v2-{NONCE}-{index:04d}.json"
        for index in range(2)
    )
    previous = previous_records[tampered_index]
    next_record = parent / f".fleet-home-recovery-v2-{NONCE}-0002.json"
    next_temp = parent / f".{next_record.name}.tmp"
    persist_fleet_home_recovery_transaction_v2(parent_fd, initial)
    persist_fleet_home_recovery_transaction_v2(parent_fd, prepared)
    raw = previous.read_bytes()
    before = previous.stat()

    def tamper_pinned_previous(marker: str) -> None:
        if marker != "before_recovery_record_publish":
            return
        pinned = tuple(
            candidate
            for candidate in Path("/proc/self/fd").iterdir()
            if candidate.name.isdigit()
            and os.path.realpath(candidate)
            in {os.path.realpath(record) for record in previous_records}
        )
        assert len(pinned) == len(previous_records), "previous chain is not FD-pinned"
        previous.write_bytes(b"[" + raw[1:])
        previous.chmod(0o600)
        os.utime(previous, ns=(before.st_atime_ns, before.st_mtime_ns))

    try:
        with pytest.raises(FleetHomeRecoveryValidationError):
            persist_fleet_home_recovery_transaction_v2(
                parent_fd,
                switch_pending,
                faultpoint=tamper_pinned_previous,
            )
    finally:
        os.close(parent_fd)

    after = previous.stat()
    assert previous.read_bytes() == b"[" + raw[1:]
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns
    assert not next_record.exists()
    assert not next_temp.exists()
    assert {entry.name for entry in parent.iterdir()} == {
        record.name for record in previous_records
    }


def test_restart_extends_partially_persisted_followup_record(tmp_path: Path) -> None:
    parent, parent_fd = open_private_parent(tmp_path)
    initial = transaction_fixture()
    prepared = advance_fleet_home_recovery_v2(
        initial,
        FleetHomeRecoveryPhase.PREPARED,
        prepared_observation(initial),
    )

    def fail_after_publish(marker: str) -> None:
        if marker == "after_recovery_record_publish":
            raise RuntimeError("injected")

    try:
        persist_fleet_home_recovery_transaction_v2(parent_fd, initial)
        with pytest.raises(RuntimeError, match="injected"):
            persist_fleet_home_recovery_transaction_v2(
                parent_fd, prepared, faultpoint=fail_after_publish
            )
        restarted = load_fleet_home_recovery_transaction_v2(parent_fd, NONCE)
        assert restarted == prepared
        switch_pending = advance_fleet_home_recovery_v2(
            restarted,
            FleetHomeRecoveryPhase.SWITCH_PENDING,
            restarted.records[-1].observation,
        )
        persist_fleet_home_recovery_transaction_v2(parent_fd, switch_pending)
        assert load_fleet_home_recovery_transaction_v2(parent_fd, NONCE) == (
            switch_pending
        )
    finally:
        os.close(parent_fd)

    assert {entry.name for entry in parent.iterdir()} == {
        f".fleet-home-recovery-v2-{NONCE}-{index:04d}.json" for index in range(3)
    }


def _static_import_string(node: ast.AST, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_import_string(node.left, constants)
        right = _static_import_string(node.right, constants)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            expression = value.value if isinstance(value, ast.FormattedValue) else value
            part = _static_import_string(expression, constants)
            if part is None:
                return None
            parts.append(part)
        return "".join(parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        separator = _static_import_string(node.func.value, constants)
        parts = [_static_import_string(item, constants) for item in node.args[0].elts]
        if separator is not None and all(part is not None for part in parts):
            return separator.join(part for part in parts if part is not None)
    return None


def _relative_import_module(
    path: Path,
    source_root: Path,
    node: ast.ImportFrom,
) -> str:
    if node.level == 0:
        return node.module or ""
    package = list(path.relative_to(source_root).with_suffix("").parts[:-1])
    keep = len(package) - (node.level - 1)
    if keep < 0:
        return ""
    suffix = tuple(part for part in (node.module or "").split(".") if part)
    return ".".join((*package[:keep], *suffix))


def _b2a_ast_findings(path: Path, source_root: Path, source: str) -> list[str]:
    module_name = "codex_master.fleet_home_recovery"
    recovery_path = source_root / "codex_master" / "fleet_home_recovery.py"
    if path == recovery_path:
        return []
    server_path = source_root / "codex_master" / "server.py"
    allowed = {
        "FleetHomeRecoveryValidationError",
        "FleetIdentityJournalPlan",
        "validate_fleet_identity_journal_plan",
    }
    public_b2a = {
        "FleetHomeEntryKind",
        "FleetHomeRecoveryAction",
        "FleetHomeRecoveryAbsentEntryObservationV2",
        "FleetHomeRecoveryAbsentHomeObservationV2",
        "FleetHomeRecoveryAbsentHomeV2",
        "FleetHomeRecoveryEntryObservationV2",
        "FleetHomeRecoveryEntryV2",
        "FleetHomeRecoveryHomeObservationV2",
        "FleetHomeRecoveryHomeV2",
        "FleetHomeRecoveryObjectSnapshot",
        "FleetHomeRecoveryParentObservationV2",
        "FleetHomeRecoveryParentV2",
        "FleetHomeRecoveryPhase",
        "FleetHomeRecoveryPhaseRecordV2",
        "FleetHomeRecoveryPopulationEntryV2",
        "FleetHomeRecoveryPopulationV2",
        "FleetHomeRecoverySnapshotIdentity",
        "FleetHomeRecoveryStat",
        "FleetHomeRecoveryTransactionObservationV2",
        "FleetHomeRecoveryTransactionV2",
        "FleetHomeRecoveryValidationError",
        "FleetIdentityJournalPlan",
        "FleetIdentityJournalSlot",
        "advance_fleet_home_recovery_v2",
        "apply_fleet_home_recovery_absent_v2",
        "decode_fleet_home_recovery_transaction_v2",
        "encode_fleet_home_recovery_transaction_v2",
        "load_fleet_home_recovery_transaction_v2",
        "make_fleet_home_recovery_transaction_v2",
        "make_fleet_identity_journal_plan",
        "persist_fleet_home_recovery_transaction_v2",
        "plan_fleet_home_recovery_v2",
        "validate_fleet_identity_journal_plan",
    }
    tree = ast.parse(source)
    constants: dict[str, str] = {}
    for _ in tree.body:
        changed = False
        for statement in tree.body:
            target: ast.expr | None = None
            value: ast.expr | None = None
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target, value = statement.targets[0], statement.value
            elif isinstance(statement, ast.AnnAssign):
                target, value = statement.target, statement.value
            if isinstance(target, ast.Name) and value is not None:
                resolved = _static_import_string(value, constants)
                if resolved is not None and constants.get(target.id) != resolved:
                    constants[target.id] = resolved
                    changed = True
        if not changed:
            break

    findings: list[str] = []
    permitted = allowed if path == server_path else set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            findings.extend(
                f"import:{alias.name}"
                for alias in node.names
                if alias.name == module_name
            )
        elif isinstance(node, ast.ImportFrom):
            imported_module = _relative_import_module(path, source_root, node)
            imported = {alias.name for alias in node.names}
            if imported_module == module_name:
                findings.extend(f"from:{name}" for name in imported - permitted)
            else:
                findings.extend(
                    f"from-module:{name}"
                    for name in imported
                    if f"{imported_module}.{name}" == module_name
                )
        elif (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in public_b2a - permitted
        ):
            findings.append(f"name:{node.id}")
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Load)
            and node.attr in public_b2a
        ):
            findings.append(f"attribute:{node.attr}")
        elif isinstance(node, ast.Constant) and node.value == module_name:
            findings.append("module-literal")
        elif isinstance(node, ast.Call) and node.args:
            dynamic_name = None
            if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                dynamic_name = "__import__"
            elif isinstance(node.func, ast.Attribute) and node.func.attr in {
                "import_module",
                "run_module",
                "run_path",
            }:
                dynamic_name = node.func.attr
            argument = _static_import_string(node.args[0], constants)
            matches_target = argument == module_name
            if dynamic_name == "run_path" and argument is not None:
                argument_path = Path(argument)
                normalized_recovery_path = Path(os.path.normpath(recovery_path))
                matches_target = any(
                    Path(os.path.normpath(base / argument_path))
                    == normalized_recovery_path
                    for base in (source_root.parent, source_root, path.parent)
                )
            if dynamic_name is not None and matches_target:
                findings.append(f"dynamic:{dynamic_name}")
    return findings


def test_ast_guard_selftests_relative_and_static_dynamic_imports() -> None:
    source_root = Path("/synthetic/src")
    cases = (
        (
            source_root / "codex_master" / "relative.py",
            "from .fleet_home_recovery import plan_fleet_home_recovery_v2 as hidden",
        ),
        (
            source_root / "codex_master" / "nested" / "relative.py",
            "from ..fleet_home_recovery import plan_fleet_home_recovery_v2 as hidden",
        ),
        (
            source_root / "codex_master" / "package_relative.py",
            "from . import fleet_home_recovery as hidden",
        ),
        (
            source_root / "codex_master" / "package_absolute.py",
            "from codex_master import fleet_home_recovery as hidden",
        ),
        (
            source_root / "codex_master" / "dynamic.py",
            "import runpy\nPREFIX = 'codex_master.'\n"
            "TARGET = PREFIX + 'fleet_home_recovery'\nrunpy.run_module(TARGET)",
        ),
        (
            source_root / "codex_master" / "run_path.py",
            "import runpy\nROOT = '/synthetic/src/codex_master/..'\n"
            "TARGET = ROOT + '/codex_master/fleet_home_recovery.py'\n"
            "runpy.run_path(TARGET)",
        ),
        (
            source_root / "codex_master" / "run_path_repo_relative.py",
            "import runpy\nrunpy.run_path('src/codex_master/fleet_home_recovery.py')",
        ),
        (
            source_root / "codex_master" / "run_path_source_relative.py",
            "import runpy\nrunpy.run_path('codex_master/fleet_home_recovery.py')",
        ),
        (
            source_root / "codex_master" / "run_path_file_relative.py",
            "import runpy\nrunpy.run_path('fleet_home_recovery.py')",
        ),
        (
            source_root / "codex_master" / "nested" / "fleet_home_recovery.py",
            "from ..fleet_home_recovery import plan_fleet_home_recovery_v2 as hidden",
        ),
    )
    assert all(_b2a_ast_findings(path, source_root, source) for path, source in cases)
    assert (
        _b2a_ast_findings(
            source_root / "codex_master" / "fleet_home_recovery.py",
            source_root,
            "import runpy\nrunpy.run_module('codex_master.fleet_home_recovery')",
        )
        == []
    )


def test_recursive_ast_guard_allows_only_three_b1_server_references() -> None:
    package = Path(__file__).parents[1] / "src" / "codex_master"
    source_root = package.parent
    findings: list[tuple[str, str]] = []
    for path in package.rglob("*.py"):
        findings.extend(
            (path.name, finding)
            for finding in _b2a_ast_findings(
                path, source_root, path.read_text(encoding="utf-8")
            )
        )
    assert findings == []

    source = ast.parse((package / "fleet_home_recovery.py").read_text(encoding="utf-8"))
    assert not any(
        isinstance(node, ast.Attribute) and node.attr in {"glob", "rglob"}
        for node in ast.walk(source)
    )
    assert not any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
        and node.attr == "replace"
        for node in ast.walk(source)
    )
