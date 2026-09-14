"""Crash-safe in-place updates for the managed files in Q-series homes."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid


__all__ = [
    "InplaceError",
    "QHomeUpdate",
    "apply_series_update",
    "recover_series_update",
]

MAX_Q_HOMES = 3
MAX_JOURNAL_BYTES = 128 * 1024
_TX_RE = re.compile(r"[0-9a-f]{32}\Z")
_HOME_ID_RE = re.compile(r"q(?:[1-9]|[1-9][0-9]|100)\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_TEMP_RE = re.compile(r"\.codex-inplace-[0-9a-f]{32}\Z")
_SPECS = (
    ("codex", "wrapper", 0o700, 512 * 1024),
    ("config.toml", "config", 0o600, 256 * 1024),
    ("AGENTS.md", "instructions", 0o600, 256 * 1024),
    ("AGENTS.class-teamleiterin.md", "class_instructions", 0o600, 256 * 1024),
    (".codex-fleet-agent.json", "marker", 0o600, 64 * 1024),
)
_SPEC_BY_NAME = {item[0]: item for item in _SPECS}
_PHASES = {"prepared", "materializing", "materialized", "committed", "rolling_back", "rolling_forward"}


class InplaceError(RuntimeError):
    """Path- and content-free error at the fleet integration boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class QHomeUpdate:
    home_id: str
    home: Path = field(repr=False)
    wrapper: bytes = field(repr=False)
    config: bytes = field(repr=False)
    instructions: bytes = field(repr=False)
    marker: bytes = field(repr=False)
    class_instructions: bytes = field(default=b"", repr=False)


@dataclass(frozen=True, slots=True)
class _FileState:
    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    mtime_ns: int
    digest: str


RegistryCAS = Callable[[int, int], bool]
FaultHook = Callable[[str], None]


def _fail(code: str) -> None:
    raise InplaceError(code)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dir_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _directory(path: Path, code: str) -> os.stat_result:
    try:
        current = path.lstat()
    except OSError:
        _fail(code)
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_uid != os.geteuid()
        or current.st_mode & 0o077
    ):
        _fail(code)
    return current


def _home_identity(current: os.stat_result) -> tuple[int, int, int, int, int]:
    return current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_gid


def _metadata(current: os.stat_result) -> tuple[int, ...]:
    return (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_uid,
        current.st_gid,
        current.st_nlink,
        current.st_size,
        current.st_mtime_ns,
    )


def _open_home(path: Path, expected: tuple[int, int, int, int, int] | None = None) -> int:
    _directory(path, "unsafe_home")
    try:
        descriptor = os.open(path, _dir_flags())
        current = os.fstat(descriptor)
    except OSError:
        _fail("unsafe_home")
    identity = _home_identity(current)
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_uid != os.geteuid()
        or current.st_mode & 0o077
        or (expected is not None and identity != expected)
    ):
        os.close(descriptor)
        _fail("home_drift" if expected is not None else "unsafe_home")
    return descriptor


def _state(current: os.stat_result, data: bytes) -> _FileState:
    return _FileState(
        current.st_dev,
        current.st_ino,
        stat.S_IMODE(current.st_mode),
        current.st_uid,
        current.st_gid,
        current.st_nlink,
        len(data),
        current.st_mtime_ns,
        _digest(data),
    )


def _bounded_read(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_leaf(
    home_fd: int, name: str, limit: int, *, missing_ok: bool
) -> tuple[_FileState | None, bytes | None]:
    try:
        before = os.stat(name, dir_fd=home_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return None, None
        _fail("unsafe_managed_leaf")
    except OSError:
        _fail("unsafe_managed_leaf")
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or before.st_mode & 0o077
        or before.st_size > limit
    ):
        _fail("unsafe_managed_leaf")
    try:
        descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=home_fd)
        opened = os.fstat(descriptor)
        if _metadata(opened) != _metadata(before):
            _fail("managed_drift")
        data = _bounded_read(descriptor, limit)
        after = os.fstat(descriptor)
    except InplaceError:
        raise
    except OSError:
        _fail("unsafe_managed_leaf")
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
    if len(data) > limit or _metadata(after) != _metadata(opened):
        _fail("managed_drift")
    return _state(after, data), data


def _same(left: _FileState | None, right: _FileState | None) -> bool:
    return left == right


def _same_payload(state: _FileState | None, other: _FileState | None) -> bool:
    if state is None or other is None:
        return state is other
    return state.mode == other.mode and state.digest == other.digest


def _revalidate_leaf(home_fd: int, name: str, limit: int, expected: _FileState | None) -> None:
    current, _ = _read_leaf(home_fd, name, limit, missing_ok=True)
    if not _same(current, expected):
        _fail("managed_drift")


def _replace_leaf(
    home_fd: int,
    name: str,
    expected: _FileState | None,
    data: bytes,
    mode: int,
    limit: int,
) -> None:
    _atomic_at(
        home_fd,
        name,
        data,
        mode,
        before=lambda: _revalidate_leaf(home_fd, name, limit, expected),
    )


def _atomic_at(
    parent_fd: int,
    name: str,
    data: bytes,
    mode: int,
    *,
    before: Callable[[], None] | None = None,
) -> None:
    temporary = f".codex-inplace-{uuid.uuid4().hex}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            offset += os.write(descriptor, view[offset:])
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if before is not None:
            before()
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass


def _unlink_leaf(home_fd: int, name: str, expected: _FileState, limit: int) -> None:
    _revalidate_leaf(home_fd, name, limit, expected)
    os.unlink(name, dir_fd=home_fd)
    os.fsync(home_fd)


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, _dir_flags())
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private(path: Path, data: bytes) -> None:
    parent_fd = os.open(path.parent, _dir_flags())
    try:
        _atomic_at(parent_fd, path.name, data, 0o600)
    finally:
        os.close(parent_fd)


def _read_private(path: Path, limit: int, code: str) -> bytes:
    descriptor: int | None = None
    try:
        current = path.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.geteuid()
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_size > limit
        ):
            _fail(code)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        data = _bounded_read(descriptor, limit)
        after = os.fstat(descriptor)
    except InplaceError:
        raise
    except OSError:
        _fail(code)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(data) > limit or _metadata(opened) != _metadata(current) or _metadata(after) != _metadata(opened):
        _fail(code)
    return data


def _state_doc(value: _FileState | None) -> dict[str, object] | None:
    return None if value is None else asdict(value)


def _parse_state(value: object) -> _FileState | None:
    if value is None:
        return None
    fields = {"dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "digest"}
    if not isinstance(value, dict) or set(value) != fields:
        _fail("invalid_journal")
    numbers = [value[key] for key in ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns")]
    if any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in numbers):
        _fail("invalid_journal")
    digest = value["digest"]
    if (
        not isinstance(digest, str)
        or not _DIGEST_RE.fullmatch(digest)
        or numbers[2] & 0o077
        or numbers[5] != 1
        or numbers[6] > 512 * 1024
    ):
        _fail("invalid_journal")
    return _FileState(*numbers, digest)


def _journal_bytes(journal: dict[str, object]) -> bytes:
    def encode(value: object) -> object:
        if isinstance(value, _FileState):
            return _state_doc(value)
        raise TypeError

    payload = json.dumps(
        journal, sort_keys=True, separators=(",", ":"), default=encode
    ).encode() + b"\n"
    if len(payload) > MAX_JOURNAL_BYTES:
        _fail("invalid_request")
    return payload


def _store_journal(transaction: Path, journal: dict[str, object]) -> None:
    _atomic_private(transaction / "journal.json", _journal_bytes(journal))


def _ordered(updates: tuple[QHomeUpdate, ...]) -> list[tuple[QHomeUpdate, tuple[str, str, int, int]]]:
    return [(update, spec) for spec in _SPECS for update in updates]


def _validate_apply(
    updates: object,
    transaction_root: object,
    transaction_id: object,
    old_generation: object,
    new_generation: object,
    registry_cas: object,
) -> tuple[QHomeUpdate, ...]:
    if (
        not isinstance(updates, tuple)
        or not 1 <= len(updates) <= MAX_Q_HOMES
        or not isinstance(transaction_root, Path)
        or not isinstance(transaction_id, str)
        or not _TX_RE.fullmatch(transaction_id)
        or isinstance(old_generation, bool)
        or not isinstance(old_generation, int)
        or old_generation < 0
        or isinstance(new_generation, bool)
        or not isinstance(new_generation, int)
        or new_generation < 0
        or old_generation == new_generation
        or not callable(registry_cas)
    ):
        _fail("invalid_request")
    result: tuple[QHomeUpdate, ...] = updates
    ids: set[str] = set()
    paths: set[Path] = set()
    for update in result:
        if (
            not isinstance(update, QHomeUpdate)
            or not _HOME_ID_RE.fullmatch(update.home_id)
            or update.home_id in ids
            or not isinstance(update.home, Path)
        ):
            _fail("invalid_request")
        ids.add(update.home_id)
        for _name, attribute, _mode, limit in _SPECS:
            content = getattr(update, attribute)
            if not isinstance(content, bytes) or len(content) > limit:
                _fail("invalid_request")
        try:
            resolved = update.home.resolve(strict=True)
        except OSError:
            _fail("unsafe_home")
        if resolved in paths:
            _fail("invalid_request")
        paths.add(resolved)
    _directory(transaction_root, "unsafe_transaction_root")
    root = transaction_root.resolve(strict=True)
    if any(root == path or path in root.parents for path in paths):
        _fail("unsafe_transaction_root")
    return result


def _prepare(
    updates: tuple[QHomeUpdate, ...],
    transaction_root: Path,
    transaction_id: str,
    old_generation: int,
    new_generation: int,
) -> tuple[Path, dict[str, object], dict[str, Path]]:
    homes: dict[str, Path] = {}
    identities: dict[str, tuple[int, int, int, int, int]] = {}
    snapshots: list[tuple[QHomeUpdate, tuple[str, str, int, int], _FileState | None, bytes | None]] = []
    for update in updates:
        home_fd = _open_home(update.home)
        identity = _home_identity(os.fstat(home_fd))
        homes[update.home_id] = update.home
        identities[update.home_id] = identity
        try:
            for item, spec in ((candidate, spec) for candidate, spec in _ordered((update,))):
                name, _attribute, _mode, limit = spec
                old, data = _read_leaf(home_fd, name, limit, missing_ok=True)
                snapshots.append((item, spec, old, data))
        finally:
            os.close(home_fd)
    transaction = transaction_root / transaction_id
    try:
        transaction.mkdir(mode=0o700)
        transaction.chmod(0o700)
        _fsync_dir(transaction_root)
    except FileExistsError:
        _fail("transaction_exists")
    except OSError:
        _fail("transaction_prepare_failed")
    entries: list[dict[str, object]] = []
    try:
        lookup = {(item.home_id, spec[0]): (item, spec, old, data) for item, spec, old, data in snapshots}
        for index, (update, spec) in enumerate(_ordered(updates)):
            name, attribute, mode, _limit = spec
            _item, _spec, old, old_data = lookup[(update.home_id, name)]
            desired = getattr(update, attribute)
            stage = f"new-{index:02d}"
            _atomic_private(transaction / stage, desired)
            backup: str | None = None
            if old_data is not None:
                backup = f"old-{index:02d}"
                _atomic_private(transaction / backup, old_data)
            entries.append({
                "home_id": update.home_id,
                "name": name,
                "mode": mode,
                "digest": _digest(desired),
                "stage": stage,
                "old": _state_doc(old),
                "backup": backup,
                "applied": False,
                "installed": None,
                "restored": None,
            })
        journal: dict[str, object] = {
            "version": 1,
            "transaction_id": transaction_id,
            "old_generation": old_generation,
            "new_generation": new_generation,
            "phase": "prepared",
            "homes": [
                {"home_id": key, "identity": list(value)} for key, value in identities.items()
            ],
            "entries": entries,
        }
        _store_journal(transaction, journal)
        return transaction, _parse_journal(transaction, transaction_id), homes
    except Exception:
        _cleanup_partial(transaction, entries)
        raise


def _parse_journal(transaction: Path, transaction_id: str) -> dict[str, object]:
    try:
        raw = json.loads(_read_private(transaction / "journal.json", MAX_JOURNAL_BYTES, "invalid_journal"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("invalid_journal")
    root_fields = {"version", "transaction_id", "old_generation", "new_generation", "phase", "homes", "entries"}
    if not isinstance(raw, dict) or set(raw) != root_fields or raw["version"] != 1 or raw["transaction_id"] != transaction_id:
        _fail("invalid_journal")
    if raw["phase"] not in _PHASES:
        _fail("invalid_journal")
    generations = (raw["old_generation"], raw["new_generation"])
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in generations) or generations[0] == generations[1]:
        _fail("invalid_journal")
    homes_raw = raw["homes"]
    if not isinstance(homes_raw, list) or not 1 <= len(homes_raw) <= MAX_Q_HOMES:
        _fail("invalid_journal")
    ids: list[str] = []
    for item in homes_raw:
        if not isinstance(item, dict) or set(item) != {"home_id", "identity"}:
            _fail("invalid_journal")
        home_id, identity = item["home_id"], item["identity"]
        if (
            not isinstance(home_id, str)
            or not _HOME_ID_RE.fullmatch(home_id)
            or home_id in ids
            or not isinstance(identity, list)
            or len(identity) != 5
            or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in identity)
        ):
            _fail("invalid_journal")
        ids.append(home_id)
    entries = raw["entries"]
    fields = {"home_id", "name", "mode", "digest", "stage", "old", "backup", "applied", "installed", "restored"}
    expected = [(home_id, spec[0]) for spec in _SPECS for home_id in ids]
    if not isinstance(entries, list) or len(entries) != len(expected):
        _fail("invalid_journal")
    for index, (entry, coordinate) in enumerate(zip(entries, expected)):
        if not isinstance(entry, dict) or set(entry) != fields or (entry["home_id"], entry["name"]) != coordinate:
            _fail("invalid_journal")
        spec = _SPEC_BY_NAME[coordinate[1]]
        if (
            entry["mode"] != spec[2]
            or not isinstance(entry["digest"], str)
            or not _DIGEST_RE.fullmatch(entry["digest"])
            or entry["stage"] != f"new-{index:02d}"
            or not isinstance(entry["applied"], bool)
        ):
            _fail("invalid_journal")
        old = _parse_state(entry["old"])
        if entry["backup"] != (None if old is None else f"old-{index:02d}"):
            _fail("invalid_journal")
        installed, restored = _parse_state(entry["installed"]), _parse_state(entry["restored"])
        if (entry["applied"] and installed is None) or (not entry["applied"] and installed is not None):
            _fail("invalid_journal")
        if installed is not None and (installed.mode != entry["mode"] or installed.digest != entry["digest"]):
            _fail("invalid_journal")
        if restored is not None and (old is None or not _same_payload(restored, old)):
            _fail("invalid_journal")
        entry["old"], entry["installed"], entry["restored"] = old, installed, restored
    return raw


def _identities(journal: dict[str, object]) -> dict[str, tuple[int, int, int, int, int]]:
    result: dict[str, tuple[int, int, int, int, int]] = {}
    for item in journal["homes"]:  # type: ignore[union-attr]
        result[item["home_id"]] = tuple(item["identity"])
    return result


def _entry_names(journal: dict[str, object]) -> set[str]:
    names = {"journal.json"}
    for entry in journal["entries"]:  # type: ignore[union-attr]
        names.add(entry["stage"])
        if entry["backup"] is not None:
            names.add(entry["backup"])
    return names


def _scan_transaction(transaction: Path, journal: dict[str, object]) -> list[str]:
    expected = _entry_names(journal)
    temps: list[str] = []
    try:
        children = list(transaction.iterdir())
    except OSError:
        _fail("invalid_journal")
    for child in children:
        if child.name in expected:
            continue
        if not _TEMP_RE.fullmatch(child.name):
            _fail("transaction_contains_foreign_entry")
        try:
            current = child.lstat()
        except OSError:
            _fail("transaction_contains_foreign_entry")
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.geteuid()
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            _fail("transaction_contains_foreign_entry")
        temps.append(child.name)
    return temps


def _cleanup_partial(transaction: Path, entries: list[dict[str, object]]) -> None:
    allowed = {value for entry in entries for key in ("stage", "backup") if isinstance((value := entry.get(key)), str)}
    try:
        for child in transaction.iterdir():
            if child.name not in allowed and not _TEMP_RE.fullmatch(child.name):
                _fail("transaction_contains_foreign_entry")
        for child in list(transaction.iterdir()):
            child.unlink()
        transaction.rmdir()
        _fsync_dir(transaction.parent)
    except InplaceError:
        raise
    except OSError:
        _fail("transaction_cleanup_failed")


def _cleanup(transaction: Path, journal: dict[str, object]) -> None:
    temps = _scan_transaction(transaction, journal)
    names = (_entry_names(journal) - {"journal.json"}) | set(temps)
    try:
        for name in names:
            (transaction / name).unlink(missing_ok=True)
        (transaction / "journal.json").unlink()
        _fsync_dir(transaction)
        transaction.rmdir()
        _fsync_dir(transaction.parent)
    except OSError:
        _fail("transaction_cleanup_failed")


def _load_aux(transaction: Path, name: str, limit: int, digest: str) -> bytes:
    data = _read_private(transaction / name, limit, "invalid_journal")
    if _digest(data) != digest:
        _fail("invalid_journal")
    return data


def _paths_for_recovery(
    homes: Mapping[str, Path], transaction_root: Path, identities: dict[str, tuple[int, int, int, int, int]]
) -> dict[str, Path]:
    if not isinstance(homes, Mapping) or set(homes) != set(identities):
        _fail("invalid_request")
    result: dict[str, Path] = {}
    resolved: set[Path] = set()
    root = transaction_root.resolve(strict=True)
    for home_id, identity in identities.items():
        path = homes[home_id]
        if not isinstance(path, Path):
            _fail("invalid_request")
        descriptor = _open_home(path, identity)
        os.close(descriptor)
        location = path.resolve(strict=True)
        if location in resolved:
            _fail("invalid_request")
        if root == location or location in root.parents:
            _fail("unsafe_transaction_root")
        resolved.add(location)
        result[home_id] = path
    _directory(transaction_root, "unsafe_transaction_root")
    return result


def _current(homes: Mapping[str, Path], identities: Mapping[str, tuple[int, int, int, int, int]], entry: dict[str, object]) -> _FileState | None:
    name = entry["name"]
    home_id = entry["home_id"]
    spec = _SPEC_BY_NAME[name]
    descriptor = _open_home(homes[home_id], identities[home_id])
    try:
        state, _ = _read_leaf(descriptor, name, spec[3], missing_ok=True)
        return state
    finally:
        os.close(descriptor)


def _materialize(
    homes: Mapping[str, Path], identities: Mapping[str, tuple[int, int, int, int, int]], transaction: Path, journal: dict[str, object], fault: FaultHook | None
) -> None:
    journal["phase"] = "materializing"
    _store_journal(transaction, journal)
    for entry in journal["entries"]:  # type: ignore[union-attr]
        name, home_id = entry["name"], entry["home_id"]
        spec = _SPEC_BY_NAME[name]
        current = _current(homes, identities, entry)
        if not _same(current, entry["old"]):
            _fail("managed_drift")
        desired = _load_aux(transaction, entry["stage"], spec[3], entry["digest"])
        descriptor = _open_home(homes[home_id], identities[home_id])
        try:
            _replace_leaf(descriptor, name, current, desired, entry["mode"], spec[3])
            installed, _ = _read_leaf(descriptor, name, spec[3], missing_ok=False)
        finally:
            os.close(descriptor)
        entry["applied"], entry["installed"] = True, installed
        _store_journal(transaction, journal)
        if fault is not None:
            fault(f"after:{home_id}:{name}")
    journal["phase"] = "materialized"
    _store_journal(transaction, journal)


def _rollback(
    homes: Mapping[str, Path], identities: Mapping[str, tuple[int, int, int, int, int]], transaction: Path, journal: dict[str, object], *, strict: bool
) -> None:
    journal["phase"] = "rolling_back"
    _store_journal(transaction, journal)
    for entry in reversed(journal["entries"]):  # type: ignore[union-attr]
        name, home_id = entry["name"], entry["home_id"]
        spec, old = _SPEC_BY_NAME[name], entry["old"]
        current = _current(homes, identities, entry)
        if _same(current, old) or _same(current, entry["restored"]):
            continue
        if _same_payload(current, old):
            entry["restored"] = current
            _store_journal(transaction, journal)
            continue
        installed = entry["installed"]
        if strict:
            allowed = entry["applied"] and _same(current, installed)
        else:
            allowed = _same(current, installed) if entry["applied"] else (
                current is not None and current.mode == entry["mode"] and current.digest == entry["digest"]
            )
        if not allowed or current is None:
            _fail("rollback_diverged")
        descriptor = _open_home(homes[home_id], identities[home_id])
        try:
            if old is None:
                _unlink_leaf(descriptor, name, current, spec[3])
                restored = None
            else:
                backup = _load_aux(transaction, entry["backup"], spec[3], old.digest)
                _replace_leaf(descriptor, name, current, backup, old.mode, spec[3])
                restored, _ = _read_leaf(descriptor, name, spec[3], missing_ok=False)
        finally:
            os.close(descriptor)
        entry["restored"] = restored
        _store_journal(transaction, journal)
    for entry in journal["entries"]:  # type: ignore[union-attr]
        if not _same_payload(_current(homes, identities, entry), entry["old"]):
            _fail("rollback_diverged")


def _roll_forward(
    homes: Mapping[str, Path], identities: Mapping[str, tuple[int, int, int, int, int]], transaction: Path, journal: dict[str, object]
) -> None:
    journal["phase"] = "rolling_forward"
    _store_journal(transaction, journal)
    for entry in journal["entries"]:  # type: ignore[union-attr]
        name, home_id = entry["name"], entry["home_id"]
        spec = _SPEC_BY_NAME[name]
        current = _current(homes, identities, entry)
        if current is not None and current.mode == entry["mode"] and current.digest == entry["digest"]:
            entry["applied"], entry["installed"] = True, current
            _store_journal(transaction, journal)
            continue
        if not (_same(current, entry["old"]) or _same(current, entry["restored"])):
            _fail("roll_forward_diverged")
        desired = _load_aux(transaction, entry["stage"], spec[3], entry["digest"])
        descriptor = _open_home(homes[home_id], identities[home_id])
        try:
            _replace_leaf(descriptor, name, current, desired, entry["mode"], spec[3])
            installed, _ = _read_leaf(descriptor, name, spec[3], missing_ok=False)
        finally:
            os.close(descriptor)
        entry["applied"], entry["installed"] = True, installed
        _store_journal(transaction, journal)
    for entry in journal["entries"]:  # type: ignore[union-attr]
        current = _current(homes, identities, entry)
        if current is None or current.mode != entry["mode"] or current.digest != entry["digest"]:
            _fail("roll_forward_diverged")


def apply_series_update(
    updates: tuple[QHomeUpdate, ...],
    *,
    transaction_root: Path,
    transaction_id: str,
    old_generation: int,
    new_generation: int,
    registry_cas: RegistryCAS,
    _fault: FaultHook | None = None,
) -> int:
    """Update Q homes in place and invoke registry CAS exactly once."""

    try:
        updates = _validate_apply(updates, transaction_root, transaction_id, old_generation, new_generation, registry_cas)
        transaction, journal, homes = _prepare(updates, transaction_root, transaction_id, old_generation, new_generation)
        identities = _identities(journal)
        try:
            if _fault is not None:
                _fault("prepared")
            for entry in journal["entries"]:  # type: ignore[union-attr]
                if not _same(_current(homes, identities, entry), entry["old"]):
                    _fail("managed_drift")
            _materialize(homes, identities, transaction, journal, _fault)
            if _fault is not None:
                _fault("before_cas")
        except Exception as error:
            if any(entry["applied"] for entry in journal["entries"]):  # type: ignore[union-attr]
                try:
                    _rollback(homes, identities, transaction, journal, strict=True)
                    _cleanup(transaction, journal)
                except InplaceError:
                    raise InplaceError("rollback_diverged") from None
            else:
                _cleanup(transaction, journal)
            if isinstance(error, InplaceError):
                raise error
            raise InplaceError("materialization_failed") from None
        try:
            committed = registry_cas(old_generation, new_generation)
        except Exception:
            raise InplaceError("registry_cas_uncertain") from None
        if committed is not True:
            try:
                _rollback(homes, identities, transaction, journal, strict=True)
                _cleanup(transaction, journal)
            except InplaceError:
                raise InplaceError("rollback_diverged") from None
            _fail("registry_conflict")
        journal["phase"] = "committed"
        _store_journal(transaction, journal)
        if _fault is not None:
            _fault("after_cas")
        _roll_forward(homes, identities, transaction, journal)
        _cleanup(transaction, journal)
        return new_generation
    except InplaceError:
        raise
    except Exception:
        raise InplaceError("update_failed") from None


def recover_series_update(
    homes: Mapping[str, Path],
    *,
    transaction_root: Path,
    transaction_id: str,
    authoritative_generation: int,
) -> int:
    """Recover one retained Q-series journal from authoritative generation."""

    try:
        if (
            not isinstance(transaction_root, Path)
            or not isinstance(transaction_id, str)
            or not _TX_RE.fullmatch(transaction_id)
            or isinstance(authoritative_generation, bool)
            or not isinstance(authoritative_generation, int)
            or authoritative_generation < 0
        ):
            _fail("invalid_request")
        _directory(transaction_root, "unsafe_transaction_root")
        transaction = transaction_root / transaction_id
        _directory(transaction, "invalid_journal")
        journal = _parse_journal(transaction, transaction_id)
        if authoritative_generation not in {journal["old_generation"], journal["new_generation"]}:
            _fail("generation_ambiguous")
        if journal["phase"] == "committed" and authoritative_generation == journal["old_generation"]:
            _fail("recovery_diverged")
        identities = _identities(journal)
        paths = _paths_for_recovery(homes, transaction_root, identities)
        _scan_transaction(transaction, journal)
        for entry in journal["entries"]:  # type: ignore[union-attr]
            spec = _SPEC_BY_NAME[entry["name"]]
            _load_aux(transaction, entry["stage"], spec[3], entry["digest"])
            if entry["old"] is not None:
                _load_aux(transaction, entry["backup"], spec[3], entry["old"].digest)
        if authoritative_generation == journal["old_generation"]:
            _rollback(paths, identities, transaction, journal, strict=False)
        else:
            _roll_forward(paths, identities, transaction, journal)
        _cleanup(transaction, journal)
        return authoritative_generation
    except InplaceError:
        raise
    except Exception:
        raise InplaceError("recovery_failed") from None
