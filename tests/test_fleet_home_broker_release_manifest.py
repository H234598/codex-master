import hashlib
import importlib.util
import json
import pytest
import re
import stat
import sys
from pathlib import Path, PurePosixPath

from the_hive.fleet_control_release_v2 import (
    ControlReleaseSpecV2,
    ReleasePayloadDigestV2,
    decode_control_release_v2,
    encode_control_release_v2,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src/the_hive/fleet_home_broker_install.py"
MANIFEST_PATH = REPO_ROOT / "systemd/manifest/the-hive-home-broker-manifest-v1.json"
MANIFEST_SOURCE = "systemd/manifest/the-hive-home-broker-manifest-v1.json"
MANIFEST_TARGET = "/usr/lib/the-hive-home-broker/manifest-v1.json"
PAYLOAD_ROOT = "/usr/lib/the-hive-home-broker/0.10.5"

EXPECTED_PAYLOAD = (
    (
        "bin/the-hive-home-broker",
        "bin/the-hive-home-broker",
        "84efd30a9390b8ac9bb4310763337aa035e798ee759dc30c8104146ad2d02569",
        493,
    ),
    (
        "python/the_hive/__init__.py",
        "src/the_hive/__init__.py",
        "34fb60a2addf955f310134f6e4670241e320936298337ebd9894cce85767cc6b",
        420,
    ),
    (
        "python/the_hive/fleet_agent_launcher.py",
        "src/the_hive/fleet_agent_launcher.py",
        "bf02b3d0b39ed56b81f06ed69d951c44ad08f08e427e8324138e40ae47a173b4",
        420,
    ),
    (
        "python/the_hive/fleet_home_broker.py",
        "src/the_hive/fleet_home_broker.py",
        "58db3221acf9c16420c7cf7da7c4c21586536f4f5a6b112d27721e6ea056e316",
        420,
    ),
    (
        "python/the_hive/fleet_home_broker_client.py",
        "src/the_hive/fleet_home_broker_client.py",
        "3868f1b86aedfdc1eb861082260a1e0dc3026a82ec0651ca6b67a957b88853a6",
        420,
    ),
    (
        "python/the_hive/fleet_home_broker_identity.py",
        "src/the_hive/fleet_home_broker_identity.py",
        "e1020cac4275441a9720d2ea9029288cbf2f2289054278e2508e4169d0990c49",
        420,
    ),
    (
        "python/the_hive/fleet_home_broker_linux.py",
        "src/the_hive/fleet_home_broker_linux.py",
        "63067a170efa8dec4f80007d6b4a249cfd1f04d46a1c53191896dc9b0a570f5f",
        420,
    ),
    (
        "python/the_hive/fleet_home_broker_package.py",
        "src/the_hive/fleet_home_broker_package.py",
        "7989c0c92dab6cf1ea7ce3d4b8de6433756525bd5bd9f293e1041a9ccf0c5de6",
        420,
    ),
    (
        "python/the_hive/fleet_home_broker_protocol.py",
        "src/the_hive/fleet_home_broker_protocol.py",
        "f748e44c665883d9842f4259472fdbd651ee7f7fd03cd953230263f42a9d1596",
        420,
    ),
    (
        "python/the_hive/fleet_home_broker_wal.py",
        "src/the_hive/fleet_home_broker_wal.py",
        "f720caf69b6b036315dcfd86691c89be5f5ec8e6c8acd125b68f786f25213920",
        420,
    ),
)

EXPECTED_MANIFEST_BYTES = (
    b'{"format":"the-hive-home-broker-manifest-v1",'
    b'"payload_version":"0.10.5","payload_entries":['
    b'{"path":"bin/the-hive-home-broker","sha256":"'
    b'84efd30a9390b8ac9bb4310763337aa035e798ee759dc30c8104146ad2d02569",'
    b'"mode":493},'
    b'{"path":"python/the_hive/__init__.py","sha256":"'
    b'34fb60a2addf955f310134f6e4670241e320936298337ebd9894cce85767cc6b",'
    b'"mode":420},'
    b'{"path":"python/the_hive/fleet_agent_launcher.py","sha256":"'
    b'bf02b3d0b39ed56b81f06ed69d951c44ad08f08e427e8324138e40ae47a173b4",'
    b'"mode":420},'
    b'{"path":"python/the_hive/fleet_home_broker.py","sha256":"'
    b'58db3221acf9c16420c7cf7da7c4c21586536f4f5a6b112d27721e6ea056e316",'
    b'"mode":420},'
    b'{"path":"python/the_hive/fleet_home_broker_client.py","sha256":"'
    b'3868f1b86aedfdc1eb861082260a1e0dc3026a82ec0651ca6b67a957b88853a6",'
    b'"mode":420},'
    b'{"path":"python/the_hive/fleet_home_broker_identity.py","sha256":"'
    b'e1020cac4275441a9720d2ea9029288cbf2f2289054278e2508e4169d0990c49",'
    b'"mode":420},'
    b'{"path":"python/the_hive/fleet_home_broker_linux.py","sha256":"'
    b'63067a170efa8dec4f80007d6b4a249cfd1f04d46a1c53191896dc9b0a570f5f",'
    b'"mode":420},'
    b'{"path":"python/the_hive/fleet_home_broker_package.py","sha256":"'
    b'7989c0c92dab6cf1ea7ce3d4b8de6433756525bd5bd9f293e1041a9ccf0c5de6",'
    b'"mode":420},'
    b'{"path":"python/the_hive/fleet_home_broker_protocol.py","sha256":"'
    b'f748e44c665883d9842f4259472fdbd651ee7f7fd03cd953230263f42a9d1596",'
    b'"mode":420},'
    b'{"path":"python/the_hive/fleet_home_broker_wal.py","sha256":"'
    b'f720caf69b6b036315dcfd86691c89be5f5ec8e6c8acd125b68f786f25213920",'
    b'"mode":420}'
    b"]}\n"
)


def _install_plan_module():
    spec = importlib.util.spec_from_file_location("test_install_plan", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load pure install-plan interface")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert Path(module.__file__).resolve() == MODULE_PATH.resolve()
    return module


def test_manifest_has_exact_canonical_bytes_and_schema() -> None:
    raw = MANIFEST_PATH.read_bytes()
    assert raw == EXPECTED_MANIFEST_BYTES
    assert raw.endswith(b"\n")
    assert not raw[:-1].endswith(b"\n")

    pairs = json.loads(raw.decode("utf-8"), object_pairs_hook=list)
    assert [key for key, _ in pairs] == [
        "format",
        "payload_version",
        "payload_entries",
    ]
    assert pairs[0][1] == "the-hive-home-broker-manifest-v1"
    assert pairs[1][1] == "0.10.5"

    entries = pairs[2][1]
    assert len(entries) == 10
    assert [key for key, _ in entries[0]] == ["path", "sha256", "mode"]
    assert all(
        [key for key, _ in entry] == ["path", "sha256", "mode"] for entry in entries
    )

    expected_paths = tuple(path for path, _, _, _ in EXPECTED_PAYLOAD)
    assert tuple(dict(entry)["path"] for entry in entries) == expected_paths
    assert expected_paths == tuple(sorted(expected_paths))
    for entry, expected in zip(entries, EXPECTED_PAYLOAD, strict=True):
        actual = dict(entry)
        path, _, digest, mode = expected
        assert actual == {"path": path, "sha256": digest, "mode": mode}
        assert path == PurePosixPath(path).as_posix()
        assert path and not path.startswith("/") and "\\" not in path
        assert "." not in PurePosixPath(path).parts
        assert ".." not in PurePosixPath(path).parts
        assert re.fullmatch(r"[0-9a-f]{64}", actual["sha256"])
        assert type(actual["mode"]) is int
        assert actual["mode"] in (420, 493)


def test_manifest_digests_and_modes_match_ten_repository_payload_sources() -> None:
    for _, source, digest, mode in EXPECTED_PAYLOAD:
        source_path = REPO_ROOT / source
        source_bytes = source_path.read_bytes()
        assert source_bytes
        assert hashlib.sha256(source_bytes).hexdigest() == digest
        assert stat.S_IMODE(source_path.stat().st_mode) == mode


def test_manifest_payload_closure_and_e3_install_mapping_are_exact() -> None:
    install = _install_plan_module()
    plan = install.build_home_broker_install_plan()
    assert plan.payload_version == "0.10.5"

    payload_files = tuple(
        entry
        for entry in plan.files
        if entry.target_path.startswith(PAYLOAD_ROOT + "/")
    )
    actual_payload = tuple(
        (
            entry.target_path.removeprefix(PAYLOAD_ROOT + "/"),
            entry.source_path,
            entry.uid,
            entry.gid,
            entry.mode,
        )
        for entry in payload_files
    )
    expected_payload = tuple(
        (path, source, 0, 0, mode) for path, source, _, mode in EXPECTED_PAYLOAD
    )
    assert actual_payload == expected_payload
    assert len(payload_files) == 10
    assert len({entry.target_path for entry in payload_files}) == 10
    assert all(not hasattr(entry, "sha256") for entry in payload_files)
    assert all(
        not entry.source_path.startswith(("systemd/", "tests/"))
        for entry in payload_files
    )
    assert MANIFEST_SOURCE not in {entry.source_path for entry in payload_files}
    assert MANIFEST_TARGET not in {entry.target_path for entry in payload_files}

    manifest_files = tuple(
        entry for entry in plan.files if entry.target_path == MANIFEST_TARGET
    )
    assert len(manifest_files) == 1
    manifest = manifest_files[0]
    assert (
        manifest.source_path,
        manifest.target_path,
        manifest.uid,
        manifest.gid,
        manifest.mode,
    ) == (MANIFEST_SOURCE, MANIFEST_TARGET, 0, 0, 0o644)


def test_v1_decoder_rejects_v2_bytes_without_compatibility_fallback() -> None:
    bootstrap_path = REPO_ROOT / "systemd/libexec/the_hive_bootstrap.py"
    spec = importlib.util.spec_from_file_location("test_v1_bootstrap", bootstrap_path)
    assert spec is not None and spec.loader is not None
    bootstrap = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = bootstrap
    spec.loader.exec_module(bootstrap)

    control_v2 = ControlReleaseSpecV2(
        schema_version=2,
        payload_version="0.10.5",
        payloads=(
            ReleasePayloadDigestV2("python_runtime", "a" * 64),
            ReleasePayloadDigestV2("root_helpers", "b" * 64),
            ReleasePayloadDigestV2("selinux_policy", "c" * 64),
            ReleasePayloadDigestV2("systemd_units", "d" * 64),
        ),
        broker_protocol="CHPB/2",
        system_bus_interface="org.the_hive.HomeBrokerControl2",
        system_bus_method="StartDynamicTeamlead",
        agent_unit_template="the-hive-agent@.service",
        launcher_path="/usr/libexec/the-hive-agent-launcher",
    )
    v2_bytes = encode_control_release_v2(control_v2)
    assert decode_control_release_v2(v2_bytes, "0.10.5") == control_v2
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.parse_manifest(v2_bytes)


def test_install_plan_origin_is_derived_from_test_file() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden_prefix = "/" + "home/"
    assert forbidden_prefix not in source
    assert "REPO_ROOT = Path(__file__).resolve().parents[1]" in source
    forbidden_name = "WORK" + "TREE"
    assert forbidden_name not in source
    forbidden_assert = "assert " + "REPO_ROOT " + "=" + "="
    assert forbidden_assert not in source
