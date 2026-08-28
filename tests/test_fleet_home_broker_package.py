import ast
import dataclasses
from dataclasses import FrozenInstanceError
from hashlib import sha256
from pathlib import Path

import pytest

from codex_master.fleet_home_broker_identity import ImportClosure, ImportClosureEntry
from codex_master.fleet_home_broker_package import (
    BrokerPackageManifest,
    PackageEntry,
    PackageFileStat,
    PackageVerificationError,
    PackageVerifierOperations,
    VerifiedPackage,
    verify_broker_package,
)


MODULE = Path(__file__).parents[1] / "src/codex_master/fleet_home_broker_package.py"


def _digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def _entry(path: str, data: bytes, mode: int = 0o644) -> PackageEntry:
    return PackageEntry(path, _digest(data), mode)


def _imports(*entries: PackageEntry) -> ImportClosure:
    return ImportClosure.from_entries(
        ImportClosureEntry(entry.relative_path, entry.sha256) for entry in entries
    )


def _manifest(
    entries: tuple[PackageEntry, ...],
    python_imports: ImportClosure | None = None,
) -> BrokerPackageManifest:
    return BrokerPackageManifest(
        version=1,
        entries=entries,
        python_imports=python_imports or _imports(*entries),
    )


class FakeOperations:
    def __init__(
        self,
        entries: tuple[PackageEntry, ...],
        *,
        paths: tuple[str, ...] | None = None,
        stats: dict[str, PackageFileStat] | None = None,
        contents: dict[str, bytes] | None = None,
    ) -> None:
        self.paths = (
            paths
            if paths is not None
            else tuple(entry.relative_path for entry in entries)
        )
        self.stats = stats or {
            entry.relative_path: PackageFileStat(0, 0, entry.mode, True, 1)
            for entry in entries
        }
        self.contents = contents or {
            entry.relative_path: entry.sha256.encode() for entry in entries
        }
        self.calls: list[tuple[str, str]] = []

    def list_paths(self) -> tuple[str, ...]:
        self.calls.append(("list_paths", ""))
        return self.paths

    def lstat(self, relative_path: str) -> PackageFileStat:
        self.calls.append(("lstat", relative_path))
        return self.stats[relative_path]

    def read_bytes(self, relative_path: str) -> bytes:
        self.calls.append(("read_bytes", relative_path))
        return self.contents[relative_path]


def _valid_package() -> tuple[BrokerPackageManifest, FakeOperations]:
    source = _entry("codex_master/a.py", b"a")
    data = _entry("data/config.txt", b"config")
    manifest = _manifest((data, source), _imports(source))
    return manifest, FakeOperations(
        manifest.entries,
        contents={
            source.relative_path: b"a",
            data.relative_path: b"config",
        },
    )


def test_public_api_is_frozen_slotted_and_operations_are_minimal() -> None:
    source = _entry("codex_master/a.py", b"a")
    manifest = _manifest((source,))
    values = (
        source,
        manifest,
        PackageFileStat(0, 0, 0o644, True, 1),
        VerifiedPackage(manifest),
    )

    for value in values:
        klass = type(value)
        assert dataclasses.is_dataclass(value)
        assert klass.__dataclass_params__.frozen
        assert hasattr(klass, "__slots__")
        assert not hasattr(value, "__dict__")

    with pytest.raises(FrozenInstanceError):
        source.relative_path = "other.py"
    assert issubclass(PackageVerificationError, ValueError)
    assert {"list_paths", "lstat", "read_bytes"} <= set(
        PackageVerifierOperations.__dict__
    )


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/absolute.py",
        "C:\\absolute.py",
        "codex_master/../secret.py",
        "a//b.py",
        ".",
    ],
)
def test_package_entry_rejects_empty_absolute_windows_and_traversal_paths(
    path: str,
) -> None:
    with pytest.raises(ValueError):
        _entry(path, b"content")


def test_package_entry_rejects_unpaired_surrogate_as_invalid_utf8() -> None:
    with pytest.raises(PackageVerificationError):
        _entry("codex_master/\udcff.py", b"content")


def test_package_entry_accepts_mode_bits_only_through_0o7777() -> None:
    assert _entry("mode.py", b"content", 0o7777).mode == 0o7777

    with pytest.raises(PackageVerificationError):
        _entry("mode.py", b"content", 0o100644)


def test_manifest_rejects_empty_or_duplicate_entries_and_sorts_entries() -> None:
    first = _entry("codex_master/a.py", b"a")
    second = _entry("codex_master/b.py", b"b")

    manifest = _manifest((second, first), _imports(first))
    assert manifest.entries == (first, second)

    with pytest.raises(PackageVerificationError):
        _manifest((first, first), _imports(first))
    with pytest.raises(PackageVerificationError):
        BrokerPackageManifest(1, (), _imports(first))


def test_verify_accepts_root_owned_regular_single_link_files() -> None:
    manifest, operations = _valid_package()

    verified = verify_broker_package(manifest, operations)

    assert verified == VerifiedPackage(manifest)
    assert verified.manifest.digest() == manifest.digest()
    assert [call[0] for call in operations.calls] == [
        "list_paths",
        "lstat",
        "read_bytes",
        "lstat",
        "read_bytes",
    ]


@pytest.mark.parametrize(
    "paths",
    [
        ("codex_master/a.py",),
        ("codex_master/a.py", "data/config.txt", "extra.txt"),
    ],
)
def test_verify_rejects_missing_or_extra_paths_before_file_reads(
    paths: tuple[str, ...],
) -> None:
    manifest, _ = _valid_package()
    operations = FakeOperations(manifest.entries, paths=paths)

    with pytest.raises(PackageVerificationError):
        verify_broker_package(manifest, operations)
    assert operations.calls == [("list_paths", "")]


def test_verify_rejects_duplicate_or_unsafe_listed_paths() -> None:
    manifest, _ = _valid_package()
    operations = FakeOperations(
        manifest.entries,
        paths=("codex_master/a.py", "codex_master/a.py"),
    )

    with pytest.raises(PackageVerificationError):
        verify_broker_package(manifest, operations)
    assert operations.calls == [("list_paths", "")]


@pytest.mark.parametrize("paths", ["ab", b"ab"])
def test_verify_rejects_text_or_bytes_list_result_before_tuple_normalization(
    paths: str | bytes,
) -> None:
    first = _entry("a", b"a")
    second = _entry("b", b"b")
    manifest = _manifest((first, second), _imports(first))
    operations = FakeOperations(
        manifest.entries,
        paths=paths,  # type: ignore[arg-type]
    )

    with pytest.raises(PackageVerificationError):
        verify_broker_package(manifest, operations)
    assert operations.calls == [("list_paths", "")]


def test_verify_rejects_sha256_drift() -> None:
    manifest, operations = _valid_package()
    operations.contents["codex_master/a.py"] = b"changed"

    with pytest.raises(PackageVerificationError):
        verify_broker_package(manifest, operations)


@pytest.mark.parametrize(
    "stat",
    [
        PackageFileStat(1, 0, 0o644, True, 1),
        PackageFileStat(0, 1, 0o644, True, 1),
        PackageFileStat(0, 0, 0o600, True, 1),
        PackageFileStat(0, 0, 0o644, False, 1),
        PackageFileStat(0, 0, 0o644, True, 2),
    ],
)
def test_verify_rejects_untrusted_file_stat(stat: PackageFileStat) -> None:
    manifest, operations = _valid_package()
    operations.stats["codex_master/a.py"] = stat

    with pytest.raises(PackageVerificationError):
        verify_broker_package(manifest, operations)


def test_verify_requires_python_import_subset_path_and_digest_match() -> None:
    source = _entry("codex_master/a.py", b"a")
    data = _entry("data/config.txt", b"config")
    package = _manifest((source, data), _imports(source))
    operations = FakeOperations(
        package.entries,
        contents={
            source.relative_path: b"a",
            data.relative_path: b"config",
        },
    )

    missing = _manifest(
        (data,),
        ImportClosure.from_entries(
            [ImportClosureEntry(source.relative_path, source.sha256)]
        ),
    )
    with pytest.raises(PackageVerificationError):
        verify_broker_package(missing, FakeOperations(missing.entries))

    drifted = _manifest(
        (source, data),
        ImportClosure.from_entries(
            [ImportClosureEntry(source.relative_path, _digest(b"changed"))]
        ),
    )
    with pytest.raises(PackageVerificationError):
        verify_broker_package(drifted, operations)


def test_manifest_canonical_bytes_and_digest_are_order_independent() -> None:
    first = _entry("codex_master/a.py", b"a")
    second = _entry("codex_master/b.py", b"b")
    left = _manifest((first, second), _imports(second, first))
    right = _manifest((second, first), _imports(first, second))

    assert left.canonical_bytes() == right.canonical_bytes()
    assert left.digest() == right.digest()
    assert left.digest() == sha256(left.canonical_bytes()).hexdigest()
    assert left.digest() != _manifest((first,), _imports(first)).digest()


def test_package_verifier_source_has_exact_import_boundary() -> None:
    tree = ast.parse(MODULE.read_text())
    allowed_imports = {
        "__future__": {"annotations"},
        "dataclasses": {"dataclass"},
        "hashlib": {"sha256"},
        "typing": {"Iterable", "Protocol"},
        "fleet_home_broker_identity": {"ImportClosure"},
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            pytest.fail(f"direct module import is forbidden: {ast.unparse(node)}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert module in allowed_imports
            assert node.level == (1 if module == "fleet_home_broker_identity" else 0)
            assert {alias.name for alias in node.names} <= allowed_imports[module]
        elif isinstance(node, ast.Name):
            assert node.id != "open"
        elif isinstance(node, ast.Attribute):
            assert node.attr != "open"
            assert not (
                isinstance(node.value, ast.Name)
                and node.value.id in {"os", "pathlib"}
                and node.attr in {"path", "Path"}
            )
