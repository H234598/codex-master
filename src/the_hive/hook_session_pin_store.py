"""Private, no-follow HookSessionBindingV1 persistence for hook ABI v1.

This module deliberately accepts an explicit state-root only.  The immutable
ABI launcher derives the one canonical per-account location before calling it;
tests provide private temporary roots.  Neither the module nor its callers use
plugin cache or plugin-data paths as a retention authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile


class HookSessionPinStoreError(ValueError):
    """The canonical hook-session pin store is missing or untrusted."""


_STORE_SCHEMA = "HookSessionPinStoreV1"
_BINDING_SCHEMA = "HookSessionBindingV1"
_LOCK_NAME = ".hook-session-pins-v1.lock"
_BINDING_SUFFIX = ".json"
_BINDING_NAME = re.compile(r"^[0-9a-f]{64}\.json$")
_STATE_MODE = 0o700
_FILE_MODE = 0o600
_DAY_NS = 24 * 60 * 60 * 1_000_000_000
_ENDED_GRACE_NS = _DAY_NS
_ORPHAN_IDLE_NS = 30 * _DAY_NS
_ORPHAN_QUARANTINE_NS = 7 * _DAY_NS
_ABI_V1 = "/usr/local/libexec/the-hive/hook-abi/v1/launcher"
_ALLOWED_HOOKS = frozenset({"native_bee_event", "native_spawn_admission"})


def _invalid() -> HookSessionPinStoreError:
    return HookSessionPinStoreError("hook_session_pin_store_invalid")


def _canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise _invalid() from exc


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _safe_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _safe_generation(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "/" not in value
        and value not in {".", ".."}
        and "\x00" not in value
    )


def _safe_session_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= 256
        and "\x00" not in value
        and not any(ord(character) < 0x20 for character in value)
    )


def _safe_time(value: object) -> bool:
    return type(value) is int and value >= 0


def _safe_state_root(path: Path) -> None:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or not path.name
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise _invalid()


def _open_private_directory(path: Path, *, create: bool) -> int:
    """Open one private absolute directory without following any component."""

    _safe_state_root(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = -1
    handed_off = False
    try:
        descriptor = os.open(path.anchor, flags)
        for part in path.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, _STATE_MODE, dir_fd=descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
            before = os.fstat(child)
            if not stat.S_ISDIR(before.st_mode):
                os.close(child)
                raise _invalid()
            os.close(descriptor)
            descriptor = child
        item = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(item.st_mode)
            or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) != _STATE_MODE
        ):
            raise _invalid()
        handed_off = True
        return descriptor
    except HookSessionPinStoreError:
        raise
    except OSError as exc:
        raise _invalid() from exc
    finally:
        if descriptor >= 0 and not handed_off:
            os.close(descriptor)


def _read_regular(directory: int, name: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != _FILE_MODE
            or not 0 < before.st_size <= 64 * 1024
        ):
            raise _invalid()
        raw = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
    except HookSessionPinStoreError:
        raise
    except OSError as exc:
        raise _invalid() from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) != before.st_size or (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_nlink,
        before.st_size,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_nlink,
        after.st_size,
    ):
        raise _invalid()
    return raw


def _binding_name(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest() + _BINDING_SUFFIX


def _binding_projection(value: Mapping[str, object]) -> dict[str, object]:
    result = dict(value)
    result.pop("content_digest", None)
    return result


def _content_digest(value: Mapping[str, object]) -> str:
    return (
        "sha256:"
        + hashlib.sha256(_canonical_json(_binding_projection(value))).hexdigest()
    )


def _validated_hooks(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _ALLOWED_HOOKS:
        raise _invalid()
    hooks: dict[str, str] = {}
    for name in sorted(_ALLOWED_HOOKS):
        digest = value.get(name)
        if not _safe_digest(digest):
            raise _invalid()
        hooks[name] = digest
    return hooks


def _validated_binding(value: object, *, expected_name: str) -> dict[str, object]:
    expected_keys = {
        "schema",
        "session_id",
        "generation",
        "runtime_manifest_digest",
        "launcher_abi",
        "hooks",
        "state",
        "state_transitions",
        "created_at_unix_ns",
        "last_seen_at_unix_ns",
        "ended_at_unix_ns",
        "orphan_candidate_at_unix_ns",
        "revalidations",
        "store_generation",
        "content_digest",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise _invalid()
    session_id = value.get("session_id")
    if not _safe_session_id(session_id) or _binding_name(session_id) != expected_name:
        raise _invalid()
    if (
        value.get("schema") != _BINDING_SCHEMA
        or not _safe_generation(value.get("generation"))
        or not _safe_digest(value.get("runtime_manifest_digest"))
        or value.get("launcher_abi") != _ABI_V1
        or not _safe_time(value.get("created_at_unix_ns"))
        or not _safe_time(value.get("last_seen_at_unix_ns"))
        or type(value.get("store_generation")) is not int
        or value["store_generation"] < 1
        or not _safe_digest(value.get("content_digest"))
    ):
        raise _invalid()
    hooks = _validated_hooks(value.get("hooks"))
    created = value["created_at_unix_ns"]
    last_seen = value["last_seen_at_unix_ns"]
    if last_seen < created:
        raise _invalid()
    ended = value.get("ended_at_unix_ns")
    candidate = value.get("orphan_candidate_at_unix_ns")
    if ended is not None and (not _safe_time(ended) or ended < created):
        raise _invalid()
    if candidate is not None and (not _safe_time(candidate) or candidate < last_seen):
        raise _invalid()
    state = value.get("state")
    if state not in {"active", "ended", "orphan_candidate"}:
        raise _invalid()
    if (state == "ended") != (ended is not None):
        raise _invalid()
    if (state == "orphan_candidate") != (candidate is not None):
        raise _invalid()
    transitions = value.get("state_transitions")
    if not isinstance(transitions, list) or not transitions:
        raise _invalid()
    previous = -1
    for transition in transitions:
        if (
            not isinstance(transition, dict)
            or set(transition) != {"state", "at_unix_ns"}
            or transition.get("state") not in {"active", "ended", "orphan_candidate"}
            or not _safe_time(transition.get("at_unix_ns"))
            or transition["at_unix_ns"] < previous
        ):
            raise _invalid()
        previous = transition["at_unix_ns"]
    if transitions[-1]["state"] != state:
        raise _invalid()
    revalidations = value.get("revalidations")
    if not isinstance(revalidations, list) or any(
        not _safe_time(item) for item in revalidations
    ):
        raise _invalid()
    if any(
        later < earlier for earlier, later in zip(revalidations, revalidations[1:])
    ) or (state != "orphan_candidate" and revalidations):
        raise _invalid()
    binding = dict(value)
    binding["hooks"] = hooks
    if binding["content_digest"] != _content_digest(binding):
        raise _invalid()
    return binding


@dataclass(frozen=True, slots=True)
class ReclamationEvidenceV1:
    """An explicit, independently observed absence assertion for one binding."""

    session_file_present: bool
    process_present: bool
    writer_lock_present: bool
    certain: bool

    @property
    def absent(self) -> bool:
        return self.certain and not (
            self.session_file_present
            or self.process_present
            or self.writer_lock_present
        )


@dataclass(frozen=True, slots=True)
class HookSessionPinStoreV1:
    """The one lock-and-schema authority for canonical hook session pins."""

    state_root: Path

    @classmethod
    def create_at(cls, state_root: Path) -> HookSessionPinStoreV1:
        descriptor = _open_private_directory(state_root, create=True)
        os.close(descriptor)
        store = cls(state_root)
        # Creation is a launcher-owned write: seed the no-follow store lock so
        # a publisher can subsequently read but never repair this authority.
        with store._locked_directory(create_lock=True):
            pass
        return store

    @classmethod
    def open_at(cls, state_root: Path) -> HookSessionPinStoreV1:
        descriptor = _open_private_directory(state_root, create=False)
        os.close(descriptor)
        return cls(state_root)

    @contextmanager
    def _locked_directory(self, *, create_lock: bool):
        directory = _open_private_directory(self.state_root, create=False)
        lock = -1
        try:
            try:
                lock = os.open(
                    _LOCK_NAME,
                    os.O_RDWR
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW
                    | (os.O_CREAT if create_lock else 0),
                    _FILE_MODE,
                    dir_fd=directory,
                )
            except OSError as exc:
                raise _invalid() from exc
            item = os.fstat(lock)
            if (
                not stat.S_ISREG(item.st_mode)
                or item.st_uid != os.geteuid()
                or item.st_nlink != 1
                or stat.S_IMODE(item.st_mode) != _FILE_MODE
            ):
                raise _invalid()
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield directory
        except HookSessionPinStoreError:
            raise
        except OSError as exc:
            raise _invalid() from exc
        finally:
            if lock >= 0:
                try:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                finally:
                    os.close(lock)
            os.close(directory)

    def _read_all_locked(self, directory: int) -> dict[str, dict[str, object]]:
        try:
            names = sorted(os.listdir(directory))
        except OSError as exc:
            raise _invalid() from exc
        bindings: dict[str, dict[str, object]] = {}
        for name in names:
            if name == _LOCK_NAME:
                continue
            if not _BINDING_NAME.fullmatch(name):
                raise _invalid()
            try:
                raw = _read_regular(directory, name)
                value = json.loads(
                    raw.decode("utf-8"), object_pairs_hook=_unique_object
                )
            except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise _invalid() from exc
            binding = _validated_binding(value, expected_name=name)
            session_id = binding["session_id"]
            assert isinstance(session_id, str)
            if session_id in bindings:
                raise _invalid()
            bindings[session_id] = binding
        return bindings

    @staticmethod
    def _write_locked(directory: int, name: str, binding: Mapping[str, object]) -> None:
        encoded = _canonical_json(binding)
        temporary = Path()
        descriptor = -1
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{name}.", suffix=".tmp", dir=f"/proc/self/fd/{directory}"
            )
            temporary = Path(temporary_name)
            os.fchmod(descriptor, _FILE_MODE)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, name, dst_dir_fd=directory)
            temporary = Path()
            os.fsync(directory)
        except OSError as exc:
            raise _invalid() from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary != Path():
                try:
                    temporary.unlink()
                except OSError:
                    pass

    @staticmethod
    def _remove_locked(directory: int, name: str) -> None:
        try:
            raw = _read_regular(directory, name)
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
            _validated_binding(value, expected_name=name)
            os.unlink(name, dir_fd=directory)
            os.fsync(directory)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise _invalid() from exc

    @staticmethod
    def _with_digest(value: dict[str, object]) -> dict[str, object]:
        value = dict(value)
        value["content_digest"] = _content_digest(value)
        return value

    def bind_session(
        self,
        *,
        session_id: str,
        generation: str,
        runtime_manifest_digest: str,
        hooks: Mapping[str, str],
        now_unix_ns: int,
    ) -> dict[str, object]:
        """Create or touch one immutable release binding under the store lock."""

        if not (
            _safe_session_id(session_id)
            and _safe_generation(generation)
            and _safe_digest(runtime_manifest_digest)
            and _safe_time(now_unix_ns)
        ):
            raise _invalid()
        normalized_hooks = _validated_hooks(dict(hooks))
        with self._locked_directory(create_lock=True) as directory:
            bindings = self._read_all_locked(directory)
            existing = bindings.get(session_id)
            if existing is None:
                binding: dict[str, object] = {
                    "schema": _BINDING_SCHEMA,
                    "session_id": session_id,
                    "generation": generation,
                    "runtime_manifest_digest": runtime_manifest_digest,
                    "launcher_abi": _ABI_V1,
                    "hooks": normalized_hooks,
                    "state": "active",
                    "state_transitions": [
                        {"state": "active", "at_unix_ns": now_unix_ns}
                    ],
                    "created_at_unix_ns": now_unix_ns,
                    "last_seen_at_unix_ns": now_unix_ns,
                    "ended_at_unix_ns": None,
                    "orphan_candidate_at_unix_ns": None,
                    "revalidations": [],
                    "store_generation": 1,
                }
            else:
                if (
                    existing["generation"] != generation
                    or existing["runtime_manifest_digest"] != runtime_manifest_digest
                    or existing["launcher_abi"] != _ABI_V1
                    or existing["hooks"] != normalized_hooks
                    or existing["ended_at_unix_ns"] is not None
                    or now_unix_ns < existing["last_seen_at_unix_ns"]
                ):
                    raise _invalid()
                binding = dict(existing)
                binding["last_seen_at_unix_ns"] = now_unix_ns
                if binding["state"] == "orphan_candidate":
                    binding["state"] = "active"
                    binding["state_transitions"] = [
                        *binding["state_transitions"],
                        {"state": "active", "at_unix_ns": now_unix_ns},
                    ]
                    binding["orphan_candidate_at_unix_ns"] = None
                    binding["revalidations"] = []
                binding["store_generation"] = existing["store_generation"] + 1
            binding = self._with_digest(binding)
            name = _binding_name(session_id)
            _validated_binding(binding, expected_name=name)
            self._write_locked(directory, name, binding)
            return binding

    def end_session(self, *, session_id: str, now_unix_ns: int) -> dict[str, object]:
        """Mark only an already pinned session ended; Stop never calls this."""

        if not _safe_session_id(session_id) or not _safe_time(now_unix_ns):
            raise _invalid()
        with self._locked_directory(create_lock=True) as directory:
            bindings = self._read_all_locked(directory)
            try:
                existing = bindings[session_id]
            except KeyError as exc:
                raise _invalid() from exc
            if (
                existing["ended_at_unix_ns"] is not None
                or now_unix_ns < existing["last_seen_at_unix_ns"]
            ):
                raise _invalid()
            binding = dict(existing)
            binding["state"] = "ended"
            binding["state_transitions"] = [
                *binding["state_transitions"],
                {"state": "ended", "at_unix_ns": now_unix_ns},
            ]
            binding["last_seen_at_unix_ns"] = now_unix_ns
            binding["ended_at_unix_ns"] = now_unix_ns
            binding["orphan_candidate_at_unix_ns"] = None
            binding["revalidations"] = []
            binding["store_generation"] = existing["store_generation"] + 1
            binding = self._with_digest(binding)
            name = _binding_name(session_id)
            _validated_binding(binding, expected_name=name)
            self._write_locked(directory, name, binding)
            return binding

    def bindings(self) -> dict[str, dict[str, object]]:
        """Read all complete bindings under exactly the canonical store lock."""

        with self._locked_directory(create_lock=False) as directory:
            return self._read_all_locked(directory)

    def retained_bindings(self, *, now_unix_ns: int) -> dict[str, dict[str, object]]:
        """Read only the bindings whose D320 retention window is still live."""

        if not _safe_time(now_unix_ns):
            raise _invalid()
        retained: dict[str, dict[str, object]] = {}
        for session_id, binding in self.bindings().items():
            ended = binding["ended_at_unix_ns"]
            if (
                ended is None
                or now_unix_ns < ended
                or now_unix_ns - ended < _ENDED_GRACE_NS
            ):
                retained[session_id] = binding
        return retained

    def retained_generations(self, *, now_unix_ns: int) -> set[str]:
        """Return active pins and exact 24-hour SessionEnd grace bindings.

        Unended bindings remain retained unless the ABI launcher has completed
        D320 orphan reclamation.  A publisher only reads this store and never
        creates, repairs, marks, or deletes bindings.
        """

        return {
            binding["generation"]
            for binding in self.retained_bindings(now_unix_ns=now_unix_ns).values()
        }

    def reclaim_orphans(
        self,
        *,
        now_unix_ns: int,
        evidence: Mapping[str, ReclamationEvidenceV1] | None,
    ) -> set[str]:
        """Perform D320's conservative 30d + 7d + two-readback reclamation.

        ``None`` or incomplete/uncertain evidence is deliberately not treated
        as absence.  It clears a pending orphan candidate and keeps the pin.
        The immutable ABI launcher is the only caller permitted to mutate this
        store in production; this method is directly testable with temp roots.
        """

        if not _safe_time(now_unix_ns):
            raise _invalid()
        removed: set[str] = set()
        with self._locked_directory(create_lock=True) as directory:
            bindings = self._read_all_locked(directory)
            for session_id, existing in bindings.items():
                if existing["ended_at_unix_ns"] is not None:
                    continue
                observation = evidence.get(session_id) if evidence is not None else None
                uncertain = observation is None or not observation.absent
                last_seen = existing["last_seen_at_unix_ns"]
                candidate_at = existing["orphan_candidate_at_unix_ns"]
                if now_unix_ns < last_seen or (
                    candidate_at is not None and now_unix_ns < candidate_at
                ):
                    uncertain = True
                if uncertain:
                    if existing["state"] == "orphan_candidate":
                        transition_at = max(
                            now_unix_ns,
                            existing["last_seen_at_unix_ns"],
                            existing["orphan_candidate_at_unix_ns"],
                        )
                        binding = dict(existing)
                        binding["state"] = "active"
                        binding["state_transitions"] = [
                            *binding["state_transitions"],
                            {"state": "active", "at_unix_ns": transition_at},
                        ]
                        binding["orphan_candidate_at_unix_ns"] = None
                        binding["revalidations"] = []
                        binding["store_generation"] = existing["store_generation"] + 1
                        binding = self._with_digest(binding)
                        name = _binding_name(session_id)
                        _validated_binding(binding, expected_name=name)
                        self._write_locked(directory, name, binding)
                    continue
                if candidate_at is None:
                    if now_unix_ns - last_seen < _ORPHAN_IDLE_NS:
                        continue
                    binding = dict(existing)
                    binding["state"] = "orphan_candidate"
                    binding["state_transitions"] = [
                        *binding["state_transitions"],
                        {"state": "orphan_candidate", "at_unix_ns": now_unix_ns},
                    ]
                    binding["orphan_candidate_at_unix_ns"] = now_unix_ns
                    binding["revalidations"] = []
                    binding["store_generation"] = existing["store_generation"] + 1
                    binding = self._with_digest(binding)
                    name = _binding_name(session_id)
                    _validated_binding(binding, expected_name=name)
                    self._write_locked(directory, name, binding)
                    continue
                if now_unix_ns - candidate_at < _ORPHAN_QUARANTINE_NS:
                    continue
                revalidations = list(existing["revalidations"])
                if not revalidations or now_unix_ns - revalidations[-1] >= _DAY_NS:
                    revalidations.append(now_unix_ns)
                    if len(revalidations) < 2:
                        binding = dict(existing)
                        binding["revalidations"] = revalidations
                        binding["store_generation"] = existing["store_generation"] + 1
                        binding = self._with_digest(binding)
                        name = _binding_name(session_id)
                        _validated_binding(binding, expected_name=name)
                        self._write_locked(directory, name, binding)
                        continue
                if (
                    len(revalidations) >= 2
                    and revalidations[-1] - revalidations[-2] >= _DAY_NS
                ):
                    self._remove_locked(directory, _binding_name(session_id))
                    removed.add(session_id)
            return removed


__all__ = [
    "HookSessionPinStoreError",
    "HookSessionPinStoreV1",
    "ReclamationEvidenceV1",
]
