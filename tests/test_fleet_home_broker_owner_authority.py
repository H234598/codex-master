from __future__ import annotations

import ast
import copy
from dataclasses import fields
from hashlib import sha256
import inspect
import json
import os
import pickle
import stat

import pytest
import selinux

from the_hive.fleet_home_broker_runtime import BrokerReleaseSpec
from the_hive.fleet_home_broker_owner_authority import (
    FdSelinuxObjectLabelV1,
    OwnerAuthorityError,
    RootBrokerOwnerAuthorityV1,
    RootBrokerOwnerLayoutV1,
    load_root_broker_owner_authority_from_open_fds,
    root_broker_owner_layout_digest,
)


LAYOUT_ABI = "TH-ROOT-OWNER-LAYOUT/1"
ROLES = (
    "Intentparent",
    "WAL",
    "Lease",
    "Config",
    "ResourceEvidence",
    "Registry",
    "Poolroot",
    "Credentialprofilroot",
    "Bindingkey",
)


def _release(layout_digest: str, *, release_id: str = "0.11.0") -> BrokerReleaseSpec:
    return BrokerReleaseSpec(
        joint_release_version=1,
        release_id=release_id,
        server_digest="1" * 64,
        broker_manifest_digest="2" * 64,
        chpb_abi="CHPB/2",
        policy_abi="fixture-policy-v1",
        provider_abi="fixture-provider-v1",
        unit_digest="3" * 64,
        selinux_digest="4" * 64,
        socket_unit="the-hive-home-broker.socket",
        service_unit="the-hive-home-broker.service",
        system_bus_name="org.the_hive.HomeBrokerControl",
        system_bus_path="/org/the_hive/HomeBrokerControl",
        system_bus_interface="org.the_hive.HomeBrokerControl1",
        broker_domain="the_hive_home_broker_t",
        gateway_domain="the_hive_control_t",
        socket_type="the_hive_home_broker_runtime_t",
        agent_domain="the_hive_agent_t",
        owner_layout_abi=LAYOUT_ABI,
        owner_layout_digest=layout_digest,
    )


def _fixture_payload(*, mutate=None) -> bytes:
    roles = []
    for index, role in enumerate(ROLES):
        roles.append(
            {
                "role": role,
                "path": f"/fixture-layout/{role.lower()}",
                "purpose": role,
                "object_type": "directory" if index < 8 else "regular_file",
                "uid": 10_000 + index,
                "gid": 11_000 + index,
                "mode": 0o700 if index < 8 else 0o600,
                "link_count": 1,
                "selinux_type": "fixture_object_t",
                "selinux_mls_range": None,
                "joint_release_version": 1,
                "release_id": "0.11.0",
            }
        )
    document = {"abi": LAYOUT_ABI, "roles": roles}
    if mutate is not None:
        mutate(document)
    return json.dumps(
        document, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _open_fixture_layout(tmp_path, payload: bytes) -> tuple[int, int]:
    fixture = tmp_path / "layout.json"
    fixture.write_bytes(payload)
    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    layout_fd = os.open(fixture, os.O_RDONLY | os.O_NOFOLLOW)
    return root_fd, layout_fd


def _native_label(fd: int) -> tuple[str, str]:
    length, raw_context = selinux.fgetfilecon_raw(fd)
    assert type(length) is int and length >= 0
    assert selinux.security_check_context_raw(raw_context) == 0
    context = selinux.context_new(raw_context)
    try:
        return selinux.context_type_get(context), selinux.context_range_get(context)
    finally:
        selinux.context_free(context)


def test_layout_schema_accepts_only_all_explicit_fixture_roles_and_canonical_bytes() -> None:
    payload = _fixture_payload()

    layout = RootBrokerOwnerLayoutV1.from_canonical_bytes(payload)

    assert layout.abi == LAYOUT_ABI
    assert tuple(entry.role for entry in layout.roles) == ROLES
    assert layout.canonical_bytes() == payload
    assert root_broker_owner_layout_digest(payload) == sha256(payload).hexdigest()
    assert tuple(field.name for field in fields(layout)) == ("abi", "roles")


def test_layout_direct_construction_fails_closed_without_the_factory() -> None:
    with pytest.raises(TypeError, match="root_broker_owner_layout_factory_required"):
        RootBrokerOwnerLayoutV1()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document["roles"].pop(),
        lambda document: document["roles"].append(document["roles"][0].copy()),
        lambda document: document["roles"][0].__setitem__("role", "Unknown"),
        lambda document: document["roles"][0].pop("path"),
        lambda document: document["roles"][0].pop("purpose"),
        lambda document: document["roles"][0].pop("object_type"),
        lambda document: document["roles"][0].pop("uid"),
        lambda document: document["roles"][0].pop("gid"),
        lambda document: document["roles"][0].pop("mode"),
        lambda document: document["roles"][0].pop("link_count"),
        lambda document: document["roles"][0].pop("selinux_type"),
        lambda document: document["roles"][0].pop("selinux_mls_range"),
        lambda document: document["roles"][0].pop("joint_release_version"),
        lambda document: document["roles"][0].pop("release_id"),
        lambda document: document["roles"][0].__setitem__("purpose", "free-purpose"),
        lambda document: document["roles"][0].__setitem__("object_type", "socket"),
        lambda document: document["roles"][0].__setitem__("path", "/fixture-layout/../drift"),
        lambda document: document["roles"][0].__setitem__("uid", -1),
        lambda document: document["roles"][0].__setitem__("gid", "10000"),
        lambda document: document["roles"][0].__setitem__("mode", 0o10000),
        lambda document: document["roles"][0].__setitem__("link_count", 0),
        lambda document: document["roles"][0].__setitem__("selinux_type", "invalid"),
        lambda document: document["roles"][0].__setitem__("selinux_mls_range", 0),
        lambda document: document["roles"][0].__setitem__("joint_release_version", 2),
        lambda document: document["roles"][0].__setitem__("release_id", ""),
        lambda document: document.__setitem__("abi", "TH-ROOT-OWNER-LAYOUT/2"),
        lambda document: document.__setitem__("extra", None),
        lambda document: document["roles"][0].__setitem__("extra", None),
    ],
)
def test_layout_schema_rejects_missing_duplicate_unknown_or_unbound_values(mutate) -> None:
    with pytest.raises(OwnerAuthorityError, match="owner layout is invalid"):
        RootBrokerOwnerLayoutV1.from_canonical_bytes(_fixture_payload(mutate=mutate))


def test_layout_schema_rejects_noncanonical_or_duplicate_json_members() -> None:
    payload = _fixture_payload()
    noncanonical = b" " + payload
    duplicate_abi = payload.replace(
        b'{"abi":"TH-ROOT-OWNER-LAYOUT/1",',
        b'{"abi":"TH-ROOT-OWNER-LAYOUT/1","abi":"TH-ROOT-OWNER-LAYOUT/1",',
    )

    for candidate in (noncanonical, duplicate_abi):
        with pytest.raises(OwnerAuthorityError, match="owner layout is invalid"):
            RootBrokerOwnerLayoutV1.from_canonical_bytes(candidate)


def test_layout_schema_accepts_an_explicit_none_range_binding() -> None:
    layout = RootBrokerOwnerLayoutV1.from_canonical_bytes(_fixture_payload())

    assert layout.roles[0].selinux_mls_range is None


def test_loader_binds_exact_fd_bytes_to_the_existing_joint_release(tmp_path) -> None:
    payload = _fixture_payload()
    digest = root_broker_owner_layout_digest(payload)
    root_fd, layout_fd = _open_fixture_layout(tmp_path, payload)
    try:
        authority = load_root_broker_owner_authority_from_open_fds(
            root_fd,
            layout_fd,
            expected_layout_abi=LAYOUT_ABI,
            expected_layout_digest=digest,
            release=_release(digest),
        )

        assert type(authority) is RootBrokerOwnerAuthorityV1
        assert authority.layout.abi == LAYOUT_ABI
        assert authority.layout_digest == digest
        assert authority.release.owner_layout_abi == LAYOUT_ABI
        assert authority.release.owner_layout_digest == digest
        assert stat.S_ISDIR(os.fstat(root_fd).st_mode)
        assert stat.S_ISREG(os.fstat(layout_fd).st_mode)
    finally:
        os.close(layout_fd)
        os.close(root_fd)


@pytest.mark.parametrize(
    "change",
    [
        lambda digest: {"expected_layout_abi": "TH-ROOT-OWNER-LAYOUT/2"},
        lambda digest: {"expected_layout_digest": "f" * 64},
        lambda digest: {"release": _release("f" * 64)},
        lambda digest: {"release": _release(digest, release_id="0.11.1")},
    ],
)
def test_loader_rejects_layout_or_joint_release_drift_before_authority_issue(
    tmp_path, change
) -> None:
    payload = _fixture_payload()
    digest = root_broker_owner_layout_digest(payload)
    root_fd, layout_fd = _open_fixture_layout(tmp_path, payload)
    arguments = {
        "expected_layout_abi": LAYOUT_ABI,
        "expected_layout_digest": digest,
        "release": _release(digest),
    }
    arguments.update(change(digest))
    try:
        with pytest.raises(OwnerAuthorityError, match="owner layout binding is invalid"):
            load_root_broker_owner_authority_from_open_fds(root_fd, layout_fd, **arguments)
    finally:
        os.close(layout_fd)
        os.close(root_fd)


def test_loader_rejects_wrong_fd_kinds_and_never_closes_caller_fds(tmp_path) -> None:
    payload = _fixture_payload()
    digest = root_broker_owner_layout_digest(payload)
    root_fd, layout_fd = _open_fixture_layout(tmp_path, payload)
    try:
        with pytest.raises(OwnerAuthorityError, match="owner layout file descriptor is invalid"):
            load_root_broker_owner_authority_from_open_fds(
                root_fd,
                root_fd,
                expected_layout_abi=LAYOUT_ABI,
                expected_layout_digest=digest,
                release=_release(digest),
            )
        with pytest.raises(OwnerAuthorityError, match="owner layout file descriptor is invalid"):
            load_root_broker_owner_authority_from_open_fds(
                layout_fd,
                root_fd,
                expected_layout_abi=LAYOUT_ABI,
                expected_layout_digest=digest,
                release=_release(digest),
            )
        os.fstat(root_fd)
        os.fstat(layout_fd)
    finally:
        os.close(layout_fd)
        os.close(root_fd)


def test_issued_authority_is_process_local_nonconstructible_and_nontransferable(
    tmp_path,
) -> None:
    payload = _fixture_payload()
    digest = root_broker_owner_layout_digest(payload)
    root_fd, layout_fd = _open_fixture_layout(tmp_path, payload)
    try:
        authority = load_root_broker_owner_authority_from_open_fds(
            root_fd,
            layout_fd,
            expected_layout_abi=LAYOUT_ABI,
            expected_layout_digest=digest,
            release=_release(digest),
        )
        with pytest.raises(TypeError):
            RootBrokerOwnerAuthorityV1()
        for copier in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                copier(authority)
    finally:
        os.close(layout_fd)
        os.close(root_fd)


def test_issued_authority_repr_and_str_are_fixed_and_redacted(tmp_path) -> None:
    payload = _fixture_payload()
    digest = root_broker_owner_layout_digest(payload)
    root_fd, layout_fd = _open_fixture_layout(tmp_path, payload)
    try:
        authority = load_root_broker_owner_authority_from_open_fds(
            root_fd,
            layout_fd,
            expected_layout_abi=LAYOUT_ABI,
            expected_layout_digest=digest,
            release=_release(digest),
        )

        assert repr(authority) == "<RootBrokerOwnerAuthorityV1 redacted>"
        assert str(authority) == repr(authority)
    finally:
        os.close(layout_fd)
        os.close(root_fd)


def test_fd_selinux_label_uses_native_fd_observation_without_closing_fd(tmp_path) -> None:
    fixture = tmp_path / "label-fixture"
    fixture.write_bytes(b"fixture")
    fd = os.open(fixture, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        expected_type, expected_range = _native_label(fd)

        label = FdSelinuxObjectLabelV1.observe(
            fd,
            expected_type=expected_type,
            expected_mls_range=expected_range,
        )

        assert label.object_type == expected_type
        assert label.mls_range == expected_range
        os.fstat(fd)
    finally:
        os.close(fd)


def test_fd_selinux_label_requires_explicit_type_and_range_arguments() -> None:
    parameters = inspect.signature(FdSelinuxObjectLabelV1.observe).parameters

    assert tuple(parameters) == ("fd", "expected_type", "expected_mls_range")
    assert parameters["expected_type"].default is inspect.Parameter.empty
    assert parameters["expected_mls_range"].default is inspect.Parameter.empty


def test_fd_selinux_label_accepts_explicit_none_range_binding(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "label-fixture"
    fixture.write_bytes(b"fixture")
    fd = os.open(fixture, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        expected_type, _expected_range = _native_label(fd)
        monkeypatch.setattr(selinux, "context_range_get", lambda _context: None)

        label = FdSelinuxObjectLabelV1.observe(
            fd,
            expected_type=expected_type,
            expected_mls_range=None,
        )

        assert label.mls_range is None
        os.fstat(fd)
    finally:
        os.close(fd)


def test_fd_selinux_label_rejects_type_or_range_drift_without_fallback(tmp_path) -> None:
    fixture = tmp_path / "label-fixture"
    fixture.write_bytes(b"fixture")
    fd = os.open(fixture, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        expected_type, expected_range = _native_label(fd)
        for expected_type_value, expected_range_value in (
            ("wrong_type_t", expected_range),
            (expected_type, "s999"),
        ):
            with pytest.raises(OwnerAuthorityError, match="SELinux object label is invalid"):
                FdSelinuxObjectLabelV1.observe(
                    fd,
                    expected_type=expected_type_value,
                    expected_mls_range=expected_range_value,
                )
        os.fstat(fd)
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "patch",
    (
        lambda monkeypatch: monkeypatch.setattr(
            selinux,
            "fgetfilecon_raw",
            lambda _fd: (_ for _ in ()).throw(OSError("read failed")),
        ),
        lambda monkeypatch: monkeypatch.setattr(
            selinux, "security_check_context_raw", lambda _raw: -1
        ),
        lambda monkeypatch: monkeypatch.setattr(selinux, "context_new", lambda _raw: None),
        lambda monkeypatch: monkeypatch.setattr(
            selinux,
            "context_type_get",
            lambda _context: (_ for _ in ()).throw(OSError("type failed")),
        ),
        lambda monkeypatch: monkeypatch.setattr(
            selinux,
            "context_range_get",
            lambda _context: (_ for _ in ()).throw(OSError("range failed")),
        ),
    ),
)
def test_fd_selinux_label_fails_closed_for_native_read_or_context_failures(
    tmp_path, monkeypatch: pytest.MonkeyPatch, patch
) -> None:
    fixture = tmp_path / "label-fixture"
    fixture.write_bytes(b"fixture")
    fd = os.open(fixture, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        expected_type, expected_range = _native_label(fd)
        patch(monkeypatch)

        with pytest.raises(OwnerAuthorityError, match="SELinux object label is invalid"):
            FdSelinuxObjectLabelV1.observe(
                fd,
                expected_type=expected_type,
                expected_mls_range=expected_range,
            )
        os.fstat(fd)
    finally:
        os.close(fd)


def test_owner_authority_module_has_no_path_xattr_ctypes_shell_or_fallback_adapter() -> None:
    module_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "src",
        "the_hive",
        "fleet_home_broker_owner_authority.py",
    )
    source = open(module_path, encoding="utf-8").read()
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_from = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert "selinux" in imports
    assert {"ctypes", "subprocess", "xattr"}.isdisjoint(imports | imported_from)
    assert "/proc/self/fd" not in source
    assert not any(
        isinstance(node, ast.Attribute) and node.attr in {"getxattr", "fgetxattr"}
        for node in ast.walk(tree)
    )
