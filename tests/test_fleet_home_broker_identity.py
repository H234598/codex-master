import dataclasses
from dataclasses import FrozenInstanceError
from hashlib import sha256

import pytest

from codex_master.fleet_home_broker_identity import (
    BrokerIdentity,
    IdentityValidationError,
    ImportClosure,
    ImportClosureEntry,
)

MAX_GENERATION = 2**63 - 1
MAX_MCS_CATEGORY = 1023


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _identity() -> BrokerIdentity:
    return BrokerIdentity(
        agent_id="agent-17",
        manifest_generation=4,
        mcs_pair="c17,c42",
        slot_snapshot="slot-snapshot-8f2",
        policy_generation=9,
        projection_digest=_digest("policy-v9"),
        executable_fingerprint=_digest("broker-package-v4"),
        fencing_epoch=2,
    )


def test_public_contract_dataclasses_are_frozen_and_slotted() -> None:
    entry = ImportClosureEntry("codex_master/a.py", _digest("a"))
    values = (
        (_identity(), "agent_id", "agent-18"),
        (entry, "path", "codex_master/b.py"),
        (ImportClosure((entry,)), "entries", ()),
    )

    for value, field, replacement in values:
        klass = type(value)
        assert dataclasses.is_dataclass(value)
        assert klass.__dataclass_params__.frozen
        assert hasattr(klass, "__slots__")
        assert not hasattr(value, "__dict__")
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, replacement)


def test_broker_identity_is_immutable_and_digest_bound() -> None:
    identity = _identity()

    with pytest.raises(FrozenInstanceError):
        identity.agent_id = "agent-18"

    assert identity.canonical_bytes() == _identity().canonical_bytes()
    assert identity.digest() == _identity().digest()

    changed = dataclasses.replace(identity, fencing_epoch=identity.fencing_epoch + 1)
    assert changed.digest() != identity.digest()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", ""),
        ("mcs_pair", ""),
        ("slot_snapshot", ""),
        ("projection_digest", "not-a-sha256"),
        ("executable_fingerprint", "not-a-sha256"),
    ],
)
def test_broker_identity_rejects_unclear_static_identity(
    field: str, value: str
) -> None:
    with pytest.raises(IdentityValidationError):
        dataclasses.replace(_identity(), **{field: value})


def test_broker_identity_accepts_exact_pb_s1_chpb2_boundaries() -> None:
    assert dataclasses.replace(
        _identity(),
        agent_id="a",
        manifest_generation=1,
        mcs_pair="c0,c1",
        policy_generation=1,
        fencing_epoch=0,
    )
    assert dataclasses.replace(
        _identity(),
        agent_id="a" + "b" * 127,
        manifest_generation=MAX_GENERATION,
        mcs_pair=f"c0,c{MAX_MCS_CATEGORY}",
        policy_generation=MAX_GENERATION,
        fencing_epoch=MAX_GENERATION,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("manifest_generation", 0),
        ("manifest_generation", MAX_GENERATION + 1),
        ("manifest_generation", True),
        ("policy_generation", 0),
        ("policy_generation", MAX_GENERATION + 1),
        ("policy_generation", False),
        ("fencing_epoch", -1),
        ("fencing_epoch", MAX_GENERATION + 1),
        ("fencing_epoch", True),
        ("agent_id", "Bee_1"),
        ("agent_id", "1bee"),
        ("agent_id", "bee.1"),
        ("agent_id", "a" * 129),
        ("mcs_pair", "c0,c0"),
        ("mcs_pair", "c2,c1"),
        ("mcs_pair", "c01,c2"),
        ("mcs_pair", "c0,c1024"),
        ("mcs_pair", "c-1,c2"),
        ("mcs_pair", "c0,c2,x"),
    ],
)
def test_broker_identity_rejects_pb_s1_chpb2_boundary_violations(
    field: str, value: object
) -> None:
    with pytest.raises(IdentityValidationError):
        dataclasses.replace(_identity(), **{field: value})


def test_import_closure_direct_constructor_canonicalizes_like_from_entries() -> None:
    entries = (
        ImportClosureEntry("codex_master/b.py", _digest("b")),
        ImportClosureEntry("codex_master/a.py", _digest("a")),
    )

    direct = ImportClosure(entries)
    via_factory = ImportClosure.from_entries(entries)

    assert direct.entries == (
        ImportClosureEntry("codex_master/a.py", _digest("a")),
        ImportClosureEntry("codex_master/b.py", _digest("b")),
    )
    assert direct == via_factory
    assert direct.digest() == via_factory.digest()


def test_import_closure_is_nonempty_canonical_and_digest_bound() -> None:
    entries = [
        ImportClosureEntry("codex_master/b.py", _digest("b")),
        ImportClosureEntry("codex_master/a.py", _digest("a")),
    ]

    closure = ImportClosure.from_entries(entries)

    assert closure.paths == ("codex_master/a.py", "codex_master/b.py")
    assert closure.digest() == ImportClosure.from_entries(list(reversed(entries))).digest()

    changed = ImportClosure.from_entries(
        [ImportClosureEntry("codex_master/a.py", _digest("changed"))]
    )
    assert changed.digest() != closure.digest()


@pytest.mark.parametrize(
    "entry_data",
    [
        [],
        [("", _digest("empty-path"))],
        [("/absolute/module.py", _digest("absolute"))],
        [("codex_master/../secret.py", _digest("traversal"))],
        [
            ("codex_master/module.py", _digest("one")),
            ("codex_master/module.py", _digest("two")),
        ],
        [("codex_master/module.py", "")],
    ],
)
def test_import_closure_blocks_empty_unsafe_duplicate_or_unclear_identity(
    entry_data: list[tuple[str, str]],
) -> None:
    with pytest.raises(IdentityValidationError):
        ImportClosure.from_entries(
            [ImportClosureEntry(path, digest) for path, digest in entry_data]
        )


@pytest.mark.parametrize(
    "entries",
    [
        (),
        [],
        (
            ImportClosureEntry("codex_master/a.py", _digest("a")),
            ImportClosureEntry("codex_master/a.py", _digest("other-a")),
        ),
        (object(),),
        (ImportClosureEntry("codex_master/a.py", _digest("a")), object()),
        None,
    ],
)
def test_import_closure_direct_constructor_blocks_invalid_entries(
    entries: object,
) -> None:
    with pytest.raises(IdentityValidationError):
        ImportClosure(entries)  # type: ignore[arg-type]
