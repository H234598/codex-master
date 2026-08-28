import ast
import dataclasses
from pathlib import Path

import pytest

from codex_master.fleet_home_broker_identity_contract import (
    BrokerCapabilityModel,
    BrokerIdentityCode,
    BrokerIdentityError,
    BrokerManifestV1,
    ImportClosureEntry,
    ImportClosureManifestV1,
    ObjectIdentity,
    PeerCgroupEvidence,
    principal_for_attested_peer,
    validate_broker_manifest,
    validate_empty_capability_model,
    validate_import_closure_manifest,
    validate_peer_cgroup_evidence,
)
from codex_master.fleet_home_broker_protocol import MAX_CHPB_GENERATION


def identity(*, mode=0o40700, dev=7, ino=9, uid=0, gid=0, nlink=2):
    return ObjectIdentity(dev, ino, mode, uid, gid, nlink)


def manifest(**changes):
    values = {
        "agent_id": "bee_1",
        "manifest_generation": 3,
        "policy_generation": 7,
        "projection_digest": "a" * 64,
        "executable_fingerprint": "b" * 64,
        "mcs_pair": "c0,c1",
        "slot": identity(),
        "fencing_epoch": 4,
    }
    values.update(changes)
    return BrokerManifestV1(**values)


def peer(**changes):
    values = {
        "pid": 123,
        "cgroup": identity(),
        "invocation_id": "1" * 32,
        "unit_name": "codex-master-agent@bee_1.service",
        "unit_generation": 9,
        "mcs_pair": "c0,c1",
    }
    values.update(changes)
    return PeerCgroupEvidence(**values)


def closure(*entries):
    if not entries:
        entries = (
            ImportClosureEntry("codex_master/__init__.py", "c" * 64, identity(mode=0o100600, ino=11, nlink=1)),
            ImportClosureEntry("codex_master/fleet_home_broker_identity.py", "d" * 64, identity(mode=0o100600, ino=12, nlink=1)),
        )
    return ImportClosureManifestV1("1.0.0", identity(), tuple(entries))


def test_public_contract_types_are_frozen_and_slotted():
    for klass in (ObjectIdentity, BrokerManifestV1, PeerCgroupEvidence, BrokerCapabilityModel, ImportClosureEntry, ImportClosureManifestV1):
        assert dataclasses.is_dataclass(klass)
        assert klass.__dataclass_params__.frozen
        assert hasattr(klass, "__slots__")


def test_manifest_and_peer_bind_only_the_exact_principal():
    principal = principal_for_attested_peer(manifest(), peer())
    assert principal.agent_id == "bee_1"
    assert principal.manifest_generation == 3
    assert principal.unit_generation == 9
    assert principal.cgroup_dev == 7
    assert principal.cgroup_ino == 9
    assert principal.invocation_id == "1" * 32
    assert principal.mcs_pair == "c0,c1"
    assert principal.fencing_epoch == 4


@pytest.mark.parametrize("altered_manifest,altered_peer", [(manifest(mcs_pair="c0,c2"), peer()), (manifest(), peer(mcs_pair="c0,c2"))])
def test_manifest_and_peer_mcs_mismatch_is_rejected(altered_manifest, altered_peer):
    with pytest.raises(BrokerIdentityError) as error:
        principal_for_attested_peer(altered_manifest, altered_peer)
    assert error.value.code in {BrokerIdentityCode.WRONG_PRINCIPAL, BrokerIdentityCode.STALE_PEER, BrokerIdentityCode.STALE_GENERATION, BrokerIdentityCode.FENCED}


def test_manifest_and_peer_validators_require_exact_types_and_boundaries():
    assert validate_broker_manifest(manifest(manifest_generation=1, policy_generation=1, fencing_epoch=0))
    assert validate_broker_manifest(manifest(manifest_generation=MAX_CHPB_GENERATION, policy_generation=MAX_CHPB_GENERATION, fencing_epoch=MAX_CHPB_GENERATION))
    assert validate_peer_cgroup_evidence(peer(pid=1, unit_generation=1))
    assert validate_peer_cgroup_evidence(peer(pid=MAX_CHPB_GENERATION, unit_generation=MAX_CHPB_GENERATION))
    for value in (object(), dataclasses.replace(manifest(), manifest_generation=True), dataclasses.replace(peer(), unit_generation=False)):
        validator = validate_broker_manifest if isinstance(value, BrokerManifestV1) else validate_peer_cgroup_evidence
        with pytest.raises(BrokerIdentityError) as error:
            validator(value)
        assert error.value.code in {BrokerIdentityCode.INVALID_TYPE, BrokerIdentityCode.INVALID_FIELD}


@pytest.mark.parametrize(
    "altered",
    [
        dataclasses.replace(manifest(), manifest_generation=0),
        dataclasses.replace(manifest(), policy_generation=MAX_CHPB_GENERATION + 1),
        dataclasses.replace(manifest(), projection_digest="A" * 64),
        dataclasses.replace(manifest(), executable_fingerprint="z" * 64),
        dataclasses.replace(manifest(), fencing_epoch=True),
        dataclasses.replace(peer(), pid=0),
        dataclasses.replace(peer(), cgroup=identity(mode=0o40722)),
        dataclasses.replace(peer(), invocation_id="z" * 32),
    ],
)
def test_manifest_and_peer_reject_invalid_fields(altered):
    validator = validate_broker_manifest if isinstance(altered, BrokerManifestV1) else validate_peer_cgroup_evidence
    with pytest.raises(BrokerIdentityError):
        validator(altered)


def test_capability_model_is_exactly_root_with_three_empty_sets():
    root = BrokerCapabilityModel(0, (), (), ())
    assert validate_empty_capability_model(root).euid == 0
    for model in (
        BrokerCapabilityModel(1, (), (), ()),
        BrokerCapabilityModel(True, (), (), ()),
        BrokerCapabilityModel(0, ("CAP_CHOWN",), (), ()),
        BrokerCapabilityModel(0, (), ("CAP_CHOWN",), ()),
        BrokerCapabilityModel(0, (), (), ("CAP_CHOWN",)),
        BrokerCapabilityModel(0, [], (), ()),
    ):
        with pytest.raises(BrokerIdentityError) as error:
            validate_empty_capability_model(model)
        assert error.value.code in {BrokerIdentityCode.INVALID_TYPE, BrokerIdentityCode.INVALID_CAPABILITY_MODEL}


def test_import_closure_requires_sorted_root_owned_regular_single_link_entries():
    value = validate_import_closure_manifest(closure())
    assert value.entries[0].relative_path < value.entries[1].relative_path
@pytest.mark.parametrize(
    "candidate",
    [
        closure(ImportClosureEntry("z.py", "a" * 64, identity(mode=0o100600, ino=11, nlink=1)), ImportClosureEntry("a.py", "b" * 64, identity(mode=0o100600, ino=12, nlink=1))),
        closure(ImportClosureEntry("a.py", "a" * 64, identity(mode=0o100600, ino=11, nlink=2))),
        closure(ImportClosureEntry("a.py", "a" * 64, identity(mode=0o40700, ino=11, nlink=2))),
        closure(ImportClosureEntry("../a.py", "a" * 64, identity(mode=0o100600, ino=11, nlink=1))),
        closure(ImportClosureEntry("./a.py", "a" * 64, identity(mode=0o100600, ino=11, nlink=1))),
        closure(ImportClosureEntry("a//b.py", "a" * 64, identity(mode=0o100600, ino=11, nlink=1))),
        closure(ImportClosureEntry("/a.py", "a" * 64, identity(mode=0o100600, ino=11, nlink=1))),
        closure(ImportClosureEntry("a\\\\b.py", "a" * 64, identity(mode=0o100600, ino=11, nlink=1))),
        closure(ImportClosureEntry("a\x00b.py", "a" * 64, identity(mode=0o100600, ino=11, nlink=1))),
        closure(ImportClosureEntry("a.py", "A" * 64, identity(mode=0o100600, ino=11, nlink=1))),
        closure(ImportClosureEntry("a.py", "a" * 64, identity(mode=0o100600, ino=11, nlink=1)), ImportClosureEntry("a.py", "b" * 64, identity(mode=0o100600, ino=12, nlink=1))),
    ],
)
def test_import_closure_rejects_malformed_entries(candidate):
    with pytest.raises(BrokerIdentityError) as error:
        validate_import_closure_manifest(candidate)
    assert error.value.code in {BrokerIdentityCode.INVALID_FIELD, BrokerIdentityCode.INVALID_IMPORT_CLOSURE}


def test_import_closure_rejects_explicit_empty_relative_path():
    manifest = ImportClosureManifestV1(
        "1.0.0",
        identity(),
        (
            ImportClosureEntry(
                "",
                "a" * 64,
                identity(mode=0o100600, ino=11, nlink=1),
            ),
            ImportClosureEntry(
                "codex_master/fleet_home_broker_identity.py",
                "b" * 64,
                identity(mode=0o100600, ino=12, nlink=1),
            ),
        ),
    )

    with pytest.raises(BrokerIdentityError) as error:
        validate_import_closure_manifest(manifest)

    assert error.value.code is BrokerIdentityCode.INVALID_FIELD


def test_import_closure_rejects_non_root_or_writable_identity():
    for candidate in (
        ImportClosureManifestV1("1.0.0", identity(uid=1), closure().entries),
        ImportClosureManifestV1("1.0.0", identity(mode=0o40720), closure().entries),
        closure(ImportClosureEntry("a.py", "a" * 64, identity(mode=0o100620, ino=11, nlink=1))),
    ):
        with pytest.raises(BrokerIdentityError):
            validate_import_closure_manifest(candidate)


def test_identity_production_imports_are_stdlib_or_pb1_only():
    source = Path("src/codex_master/fleet_home_broker_identity_contract.py").read_text()
    tree = ast.parse(source)
    allowed = {"dataclasses", "enum", "re", "typing", "codex_master.fleet_home_broker_protocol"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name in allowed for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module in allowed or (node.level == 1 and node.module == "fleet_home_broker_protocol")
    assert all(token not in source.lower() for token in ("fleet_home_recovery", "server", "socket", "sqlite", "subprocess", "systemd", "selinux", "os.", "time."))
