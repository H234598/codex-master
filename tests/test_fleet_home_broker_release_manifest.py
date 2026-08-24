import hashlib
import importlib.util
import json
import re
import stat
import sys
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src/codex_master/fleet_home_broker_install.py"
MANIFEST_PATH = REPO_ROOT / "systemd/manifest/codex-master-home-broker-manifest-v1.json"
MANIFEST_SOURCE = "systemd/manifest/codex-master-home-broker-manifest-v1.json"
MANIFEST_TARGET = "/usr/lib/codex-master-home-broker/manifest-v1.json"
PAYLOAD_ROOT = "/usr/lib/codex-master-home-broker/0.10.5"

EXPECTED_PAYLOAD = (
    (
        "bin/codex-master-home-broker",
        "bin/codex-master-home-broker",
        "9c58f08b99738543efd07356a0c152b391555a3fc3a448a6f262274084f13982",
        493,
    ),
    (
        "python/codex_master/__init__.py",
        "src/codex_master/__init__.py",
        "8f58d472923fd7b7e729e7a947940c2ccb8521edc0fd5630c7389abc6dd3d678",
        420,
    ),
    (
        "python/codex_master/fleet_agent_launcher.py",
        "src/codex_master/fleet_agent_launcher.py",
        "e9509de8c0a3813f7cb0f918648ea2393f60608ce66d29320022761f17c467a3",
        420,
    ),
    (
        "python/codex_master/fleet_home_broker.py",
        "src/codex_master/fleet_home_broker.py",
        "83b5288383e58d4fb95f21fbe15de3596030d80025813d1d48134a613b5def0b",
        420,
    ),
    (
        "python/codex_master/fleet_home_broker_client.py",
        "src/codex_master/fleet_home_broker_client.py",
        "366b4123b8754070da77ede6bea887b42be5d0aa860e20ffe6bfe4aaa4bb6a8a",
        420,
    ),
    (
        "python/codex_master/fleet_home_broker_identity.py",
        "src/codex_master/fleet_home_broker_identity.py",
        "e1020cac4275441a9720d2ea9029288cbf2f2289054278e2508e4169d0990c49",
        420,
    ),
    (
        "python/codex_master/fleet_home_broker_linux.py",
        "src/codex_master/fleet_home_broker_linux.py",
        "45db0d0fe14c616094fa686415e1211cbc9b42ccaa16a2226bcf83a97b44fcb0",
        420,
    ),
    (
        "python/codex_master/fleet_home_broker_package.py",
        "src/codex_master/fleet_home_broker_package.py",
        "7989c0c92dab6cf1ea7ce3d4b8de6433756525bd5bd9f293e1041a9ccf0c5de6",
        420,
    ),
    (
        "python/codex_master/fleet_home_broker_protocol.py",
        "src/codex_master/fleet_home_broker_protocol.py",
        "a13c533d4a2425bbab72e64494321955155d1fa8fb6c6c2de2a8fea97ae0f55f",
        420,
    ),
    (
        "python/codex_master/fleet_home_broker_wal.py",
        "src/codex_master/fleet_home_broker_wal.py",
        "70398f8ca97a176b665fb2626086dd50671fb073589ffd56fff484b6a45b4da3",
        420,
    ),
)

EXPECTED_MANIFEST_BYTES = (
    b'{"format":"codex-master-home-broker-manifest-v1",'
    b'"payload_version":"0.10.5","payload_entries":['
    b'{"path":"bin/codex-master-home-broker","sha256":"'
    b'9c58f08b99738543efd07356a0c152b391555a3fc3a448a6f262274084f13982",'
    b'"mode":493},'
    b'{"path":"python/codex_master/__init__.py","sha256":"'
    b'8f58d472923fd7b7e729e7a947940c2ccb8521edc0fd5630c7389abc6dd3d678",'
    b'"mode":420},'
    b'{"path":"python/codex_master/fleet_agent_launcher.py","sha256":"'
    b'e9509de8c0a3813f7cb0f918648ea2393f60608ce66d29320022761f17c467a3",'
    b'"mode":420},'
    b'{"path":"python/codex_master/fleet_home_broker.py","sha256":"'
    b'83b5288383e58d4fb95f21fbe15de3596030d80025813d1d48134a613b5def0b",'
    b'"mode":420},'
    b'{"path":"python/codex_master/fleet_home_broker_client.py","sha256":"'
    b'366b4123b8754070da77ede6bea887b42be5d0aa860e20ffe6bfe4aaa4bb6a8a",'
    b'"mode":420},'
    b'{"path":"python/codex_master/fleet_home_broker_identity.py","sha256":"'
    b'e1020cac4275441a9720d2ea9029288cbf2f2289054278e2508e4169d0990c49",'
    b'"mode":420},'
    b'{"path":"python/codex_master/fleet_home_broker_linux.py","sha256":"'
    b'45db0d0fe14c616094fa686415e1211cbc9b42ccaa16a2226bcf83a97b44fcb0",'
    b'"mode":420},'
    b'{"path":"python/codex_master/fleet_home_broker_package.py","sha256":"'
    b'7989c0c92dab6cf1ea7ce3d4b8de6433756525bd5bd9f293e1041a9ccf0c5de6",'
    b'"mode":420},'
    b'{"path":"python/codex_master/fleet_home_broker_protocol.py","sha256":"'
    b'a13c533d4a2425bbab72e64494321955155d1fa8fb6c6c2de2a8fea97ae0f55f",'
    b'"mode":420},'
    b'{"path":"python/codex_master/fleet_home_broker_wal.py","sha256":"'
    b'70398f8ca97a176b665fb2626086dd50671fb073589ffd56fff484b6a45b4da3",'
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
    assert pairs[0][1] == "codex-master-home-broker-manifest-v1"
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


def test_install_plan_origin_is_derived_from_test_file() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden_prefix = "/" + "home/"
    assert forbidden_prefix not in source
    assert "REPO_ROOT = Path(__file__).resolve().parents[1]" in source
    forbidden_name = "WORK" + "TREE"
    assert forbidden_name not in source
    forbidden_assert = "assert " + "REPO_ROOT " + "=" + "="
    assert forbidden_assert not in source
