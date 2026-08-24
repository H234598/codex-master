import ast
from dataclasses import FrozenInstanceError, fields, is_dataclass
import hashlib
import inspect
import json
from pathlib import Path
import runpy

import pytest


REPO_ROOT = Path(__file__).parents[1]
LIBEXEC = REPO_ROOT / "systemd/libexec"
BOOTSTRAP_FILE = LIBEXEC / "codex_master_bootstrap.py"
WRAPPERS = (
    LIBEXEC / "codex-master-broker-verify",
    LIBEXEC / "codex-master-home-broker",
    LIBEXEC / "codex-master-agent-launcher",
)
BOOTSTRAP = runpy.run_path(str(BOOTSTRAP_FILE))
BootstrapError = BOOTSTRAP["BootstrapError"]
FileStat = BOOTSTRAP["FileStat"]
PayloadEntry = BOOTSTRAP["PayloadEntry"]
VersionedManifest = BOOTSTRAP["VersionedManifest"]
VerifiedPayload = BOOTSTRAP["VerifiedPayload"]
dispatch = BOOTSTRAP["dispatch"]
parse_manifest = BOOTSTRAP["parse_manifest"]
run_after_verified = BOOTSTRAP["run_after_verified"]

PAYLOAD_ROOT = BOOTSTRAP["PAYLOAD_ROOT"]
MANIFEST_PATH = BOOTSTRAP["MANIFEST_PATH"]
FAILURE = "codex-master bootstrap verification failed"
PAYLOAD = {
    "bin/codex-master-home-broker": (b"broker", 0o755),
    "python/codex_master/fleet_agent_launcher.py": (b"agent", 0o644),
}


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _payload_entry(path: str, content: bytes, mode: int) -> dict[str, object]:
    return {"path": path, "sha256": _digest(content), "mode": mode}


def _document(
    payload_entries: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "format": "codex-master-home-broker-manifest-v1",
        "payload_version": "0.10.5",
        "payload_entries": payload_entries
        if payload_entries is not None
        else [
            _payload_entry(path, content, mode)
            for path, (content, mode) in PAYLOAD.items()
        ],
    }


def _manifest_bytes(document: dict[str, object] | None = None) -> bytes:
    return json.dumps(
        document or _document(), separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


class FakeOperations:
    def __init__(
        self,
        *,
        manifest_bytes: bytes | None = None,
        paths: tuple[str, ...] | None = None,
        manifest_stat: object | None = None,
        stats: dict[str, object] | None = None,
        contents: dict[str, object] | None = None,
        errors: dict[str, Exception] | None = None,
    ) -> None:
        self.manifest_bytes = manifest_bytes or _manifest_bytes()
        self.paths = paths if paths is not None else tuple(PAYLOAD)
        self.manifest_stat = manifest_stat or FileStat(0, 0, 0o644, True, 1)
        self.stats = stats or {
            PAYLOAD_ROOT + "/" + path: FileStat(0, 0, mode, True, 1)
            for path, (_, mode) in PAYLOAD.items()
        }
        self.contents = contents or {
            PAYLOAD_ROOT + "/" + path: content for path, (content, _) in PAYLOAD.items()
        }
        self.errors = errors or {}
        self.calls: list[tuple[str, str]] = []

    def _raise(self, operation: str) -> None:
        error = self.errors.get(operation)
        if error is not None:
            raise error

    def lstat(self, path: str) -> object:
        self.calls.append(("lstat", path))
        self._raise("lstat")
        if path == MANIFEST_PATH:
            return self.manifest_stat
        self._raise("lstat:" + path)
        return self.stats[path]

    def read_bytes(self, path: str) -> object:
        self.calls.append(("read_bytes", path))
        self._raise("read_bytes")
        if path == MANIFEST_PATH:
            return self.manifest_bytes
        self._raise("read_bytes:" + path)
        return self.contents[path]

    def list_payload_paths(self, payload_root: str) -> tuple[str, ...]:
        self.calls.append(("list_payload_paths", payload_root))
        self._raise("list_payload_paths")
        return self.paths


def _operations(**kwargs: object) -> FakeOperations:
    return FakeOperations(**kwargs)


def _raises_bootstrap(callable_, *args, **kwargs):
    with pytest.raises(BootstrapError) as raised:
        callable_(*args, **kwargs)
    assert str(raised.value) == FAILURE
    return raised


def test_bootstrap_exists_with_non_executable_mode() -> None:
    assert BOOTSTRAP_FILE.is_file()
    assert BOOTSTRAP_FILE.stat().st_mode & 0o777 == 0o644


def test_wrappers_exist_and_are_executable() -> None:
    assert all(wrapper.is_file() for wrapper in WRAPPERS)
    assert all(wrapper.stat().st_mode & 0o777 == 0o755 for wrapper in WRAPPERS)


def test_public_api_is_frozen_slotted_and_v1_minimal() -> None:
    values = (
        FileStat(0, 0, 0o644, True, 1),
        PayloadEntry("a", "a" * 64, 0o644),
        VersionedManifest(
            "0.10.5",
            (PayloadEntry("a", "a" * 64, 0o644),),
        ),
        VerifiedPayload(
            PAYLOAD_ROOT,
            (PayloadEntry("a", "a" * 64, 0o644),),
        ),
    )
    for value in values:
        assert is_dataclass(value)
        assert type(value).__dataclass_params__.frozen
        assert hasattr(type(value), "__slots__")
        assert not hasattr(value, "__dict__")
    with pytest.raises(FrozenInstanceError):
        values[0].uid = 1
    assert issubclass(BootstrapError, ValueError)
    assert tuple(field.name for field in fields(VersionedManifest)) == (
        "payload_version",
        "payload_entries",
    )
    assert "ReleaseEntry" not in BOOTSTRAP
    assert "release_entries" not in BOOTSTRAP
    assert tuple(inspect.signature(dispatch).parameters) == ("mode", "operations")
    assert tuple(inspect.signature(run_after_verified).parameters) == (
        "mode",
        "operations",
        "callback",
    )


def test_parse_manifest_accepts_only_nonempty_sorted_v1_payload() -> None:
    manifest = parse_manifest(_manifest_bytes())

    assert manifest.payload_version == "0.10.5"
    assert tuple(entry.relative_path for entry in manifest.payload_entries) == tuple(
        PAYLOAD
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda document: document.pop("format"),
        lambda document: document.update(unknown=True),
        lambda document: document.update(format="wrong"),
        lambda document: document.update(payload_version="wrong"),
        lambda document: document.update(payload_entries={}),
        lambda document: document.update(release_entries=[]),
    ],
)
def test_parse_manifest_rejects_removed_or_invalid_top_level_schema(change) -> None:
    document = _document()
    change(document)

    _raises_bootstrap(parse_manifest, _manifest_bytes(document))


def test_parse_manifest_rejects_duplicate_nested_entry_keys() -> None:
    raw = (
        b'{"format":"codex-master-home-broker-manifest-v1",'
        b'"payload_version":"0.10.5","payload_entries":['
        b'{"path":"a","path":"b","sha256":"' + b"a" * 64 + b'","mode":420}]}'
    )

    _raises_bootstrap(parse_manifest, raw)


def test_parse_manifest_rejects_empty_duplicate_and_unsorted_payload() -> None:
    _raises_bootstrap(
        parse_manifest,
        _manifest_bytes(_document(payload_entries=[])),
    )
    entries = list(_document()["payload_entries"])
    _raises_bootstrap(
        parse_manifest,
        _manifest_bytes(_document(payload_entries=[entries[0], entries[0]])),
    )
    _raises_bootstrap(
        parse_manifest,
        _manifest_bytes(_document(payload_entries=list(reversed(entries)))),
    )


@pytest.mark.parametrize(
    "path",
    [
        "",
        " /a",
        "/a",
        "a ",
        "a\\b",
        "a\x00b",
        "C:/a",
        "a//b",
        "a/./b",
        "a/../b",
        "a/\udcff",
    ],
)
def test_parse_manifest_rejects_unsafe_payload_paths(path: str) -> None:
    document = _document(
        payload_entries=[_payload_entry(path, b"payload", 0o644)],
    )

    _raises_bootstrap(parse_manifest, _manifest_bytes(document))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sha256", "A" * 64),
        ("sha256", "a" * 63),
        ("sha256", "g" * 64),
        ("mode", 0o600),
        ("mode", True),
    ],
)
def test_parse_manifest_rejects_bad_digest_and_mode(field: str, value: object) -> None:
    document = _document()
    entry = document["payload_entries"][0]
    entry[field] = value

    _raises_bootstrap(parse_manifest, _manifest_bytes(document))


def test_dispatch_acquires_manifest_after_trusted_lstat() -> None:
    operations = _operations()

    dispatch("verify", operations)

    assert operations.calls[:3] == [
        ("lstat", MANIFEST_PATH),
        ("read_bytes", MANIFEST_PATH),
        ("list_payload_paths", PAYLOAD_ROOT),
    ]


def test_failed_manifest_stat_does_not_read_list_or_call_callback() -> None:
    operations = _operations(manifest_stat=FileStat(1, 0, 0o644, True, 1))
    callback_calls: list[VerifiedPayload] = []

    _raises_bootstrap(run_after_verified, "verify", operations, callback_calls.append)

    assert operations.calls == [("lstat", MANIFEST_PATH)]
    assert callback_calls == []


def test_dispatch_verifies_exact_payload_closure_for_all_modes() -> None:
    for mode in ("verify", "broker", "agent"):
        operations = _operations()

        verified = dispatch(mode, operations)

        assert verified == VerifiedPayload(
            PAYLOAD_ROOT,
            tuple(
                PayloadEntry(path, _digest(content), mode_bits)
                for path, (content, mode_bits) in PAYLOAD.items()
            ),
        )


@pytest.mark.parametrize(
    "paths",
    [
        ("bin/codex-master-home-broker",),
        (
            "bin/codex-master-home-broker",
            "python/codex_master/fleet_agent_launcher.py",
            "extra",
        ),
        ("bin/codex-master-home-broker", "bin/codex-master-home-broker"),
        ("../secret", "python/codex_master/fleet_agent_launcher.py"),
    ],
)
def test_dispatch_rejects_missing_extra_duplicate_or_traversal_paths(paths) -> None:
    operations = _operations(paths=paths)

    _raises_bootstrap(dispatch, "verify", operations)
    assert [call[0] for call in operations.calls] == [
        "lstat",
        "read_bytes",
        "list_payload_paths",
    ]


@pytest.mark.parametrize(
    "stat_value",
    [
        FileStat(1, 0, 0o755, True, 1),
        FileStat(0, 1, 0o755, True, 1),
        FileStat(0, 0, 0o755, True, 2),
        FileStat(0, 0, 0o755, False, 1),
        FileStat(0, 0, 0o644, True, 1),
    ],
)
def test_dispatch_rejects_untrusted_payload_stat(stat_value: FileStat) -> None:
    operations = _operations()
    operations.stats[PAYLOAD_ROOT + "/bin/codex-master-home-broker"] = stat_value

    _raises_bootstrap(dispatch, "verify", operations)


@pytest.mark.parametrize(
    "stat_value",
    [
        FileStat(1, 0, 0o644, True, 1),
        FileStat(0, 1, 0o644, True, 1),
        FileStat(0, 0, 0o600, True, 1),
        FileStat(0, 0, 0o644, False, 1),
        FileStat(0, 0, 0o644, True, 2),
    ],
)
def test_dispatch_rejects_untrusted_manifest_stat(stat_value: FileStat) -> None:
    operations = _operations(manifest_stat=stat_value)

    _raises_bootstrap(dispatch, "verify", operations)
    assert operations.calls == [("lstat", MANIFEST_PATH)]


def test_dispatch_rejects_payload_hash_drift() -> None:
    operations = _operations()
    operations.contents[PAYLOAD_ROOT + "/bin/codex-master-home-broker"] = b"changed"

    _raises_bootstrap(dispatch, "verify", operations)


def test_dispatch_rejects_unknown_modes_and_missing_required_paths() -> None:
    operations = _operations()
    _raises_bootstrap(dispatch, "unknown", operations)
    assert operations.calls == []

    other = _document(payload_entries=[_payload_entry("other", b"other", 0o644)])
    missing_operations = _operations(
        manifest_bytes=_manifest_bytes(other), paths=("other",)
    )
    _raises_bootstrap(dispatch, "broker", missing_operations)
    missing_operations = _operations(
        manifest_bytes=_manifest_bytes(other), paths=("other",)
    )
    _raises_bootstrap(dispatch, "agent", missing_operations)


@pytest.mark.parametrize(
    "operation",
    ["lstat", "read_bytes", "list_payload_paths"],
)
def test_dispatch_normalizes_operation_failures(operation: str) -> None:
    operations = _operations(errors={operation: RuntimeError("/secret/local/path")})

    raised = _raises_bootstrap(dispatch, "verify", operations)

    assert "/secret/local/path" not in str(raised.value)


def test_run_after_verified_calls_callback_once_only_after_green() -> None:
    calls: list[VerifiedPayload] = []
    operations = _operations()

    result = run_after_verified("verify", operations, calls.append)

    assert result is None
    assert len(calls) == 1
    assert calls[0].payload_root == PAYLOAD_ROOT

    failed_calls: list[VerifiedPayload] = []
    failed_operations = _operations(paths=("extra",))
    _raises_bootstrap(
        run_after_verified,
        "verify",
        failed_operations,
        failed_calls.append,
    )
    assert failed_calls == []


def test_run_after_verified_normalizes_callback_failure() -> None:
    calls = 0

    def callback(_verified: VerifiedPayload) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("/callback/private")

    raised = _raises_bootstrap(run_after_verified, "verify", _operations(), callback)

    assert calls == 1
    assert "/callback/private" not in str(raised.value)


def test_bootstrap_source_is_stdlib_only_and_has_no_package_import() -> None:
    tree = ast.parse(BOOTSTRAP_FILE.read_text(encoding="utf-8"))
    allowed = {
        "__future__",
        "dataclasses",
        "hashlib",
        "json",
        "os",
        "re",
        "stat",
        "typing",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name in allowed for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module in allowed
        elif isinstance(node, ast.Name):
            assert node.id != "codex_master"


def test_wrappers_have_constants_modes_and_static_security_order() -> None:
    constants = {
        "PAYLOAD_PARENT": '"/usr/lib/codex-master-home-broker"',
        "PAYLOAD_VERSION": '"0.10.5"',
        "PAYLOAD_ROOT": '"/usr/lib/codex-master-home-broker/0.10.5"',
        "MANIFEST_PATH": '"/usr/lib/codex-master-home-broker/manifest-v1.json"',
        "BOOTSTRAP_PATH": '"/usr/libexec/codex_master_bootstrap.py"',
        "BROKER_VERIFY_PATH": '"/usr/libexec/codex-master-broker-verify"',
        "BROKER_PATH": '"/usr/libexec/codex-master-home-broker"',
        "AGENT_PATH": '"/usr/libexec/codex-master-agent-launcher"',
        "PYTHON": '"/usr/bin/python3"',
        "INERT_EXIT_CODE": "INERT_EXIT_CODE = 78",
    }
    forbidden = (
        "subprocess",
        "socket",
        "scm",
        "selinux",
        "network",
        "systemd",
        "server",
        "lifecycle",
        "install",
        "multiprocessing",
        "os.system",
        "manifest_bytes",
        "release_entries",
    )
    for wrapper in WRAPPERS:
        source = wrapper.read_text(encoding="utf-8")
        assert source.startswith("#!/usr/bin/python3\n")
        assert all(value in source for value in constants.values())
        assert "runpy.run_path(BOOTSTRAP_PATH)" in source
        assert not any(word in source.lower() for word in forbidden)

    verify_source = WRAPPERS[0].read_text(encoding="utf-8")
    assert 'dispatch"]("verify"' in verify_source
    assert "read_bytes" not in verify_source

    broker_source = WRAPPERS[1].read_text(encoding="utf-8")
    assert 'dispatch"]("broker"' in broker_source
    assert "read_bytes" not in broker_source
    assert broker_source.index("except SystemExit") < broker_source.index(
        "except Exception"
    )
    assert broker_source.index('dispatch"]("broker"') < broker_source.index(
        'verified.payload_root + "/bin/codex-master-home-broker"'
    )

    agent_source = WRAPPERS[2].read_text(encoding="utf-8")
    assert 'dispatch"]("agent"' in agent_source
    assert "read_bytes" not in agent_source
    assert (
        agent_source.index('dispatch"]("agent"')
        < agent_source.index("sys.modules")
        < agent_source.index("sys.path.insert")
        < agent_source.index('import_module("codex_master.fleet_agent_launcher")')
    )
    assert "realpath" in agent_source
    assert "commonpath" in agent_source
    assert "__file__" in agent_source
    assert "reload" not in agent_source
    assert "del sys.modules" not in agent_source
    assert "return INERT_EXIT_CODE" in agent_source


def test_wrapper_imports_are_stdlib_only() -> None:
    allowed = {"runpy", "sys", "importlib", "os", "__future__"}
    for wrapper in WRAPPERS:
        tree = ast.parse(wrapper.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name in allowed for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.module in allowed
