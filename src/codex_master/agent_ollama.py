"""Closed host-local Ollama action adapter and private-path gate."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import os
from pathlib import Path
import stat
from typing import Literal, Protocol, cast


class AgentOllamaError(ValueError):
    """Code-only rejected Ollama operation."""


def _fail(code: str) -> None:
    raise AgentOllamaError(code)


def _arguments(value: object, fields: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("host.arguments_invalid")
    document = dict(cast(Mapping[str, object], value))
    for field, item in document.items():
        if field.endswith("_ref") and (
            type(item) is not str or not item or len(item) > 128
        ):
            _fail("host.arguments_invalid")
        if field == "generation" and (type(item) is not int or item < 0):
            _fail("host.arguments_invalid")
    return document


def validate_private_path(
    value: str,
    *,
    roots: Sequence[Path],
    owner_uid: int,
    kind: Literal["file", "directory"],
) -> Path:
    """Validate one absolute private path without following any component."""
    if (
        type(value) is not str
        or not value.startswith("/")
        or type(owner_uid) is not int
        or kind not in {"file", "directory"}
    ):
        _fail("resource.path_invalid")
    path = Path(value)
    if any(not isinstance(root, Path) or not root.is_absolute() for root in roots):
        _fail("resource.path_invalid")
    allowed = False
    for root in roots:
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in {"", ".", ".."} for part in relative.parts):
            continue
        allowed = True
        break
    if not allowed:
        _fail("resource.path_invalid")
    parts = path.parts[1:]
    if not parts or len(parts) > 64:
        _fail("resource.path_invalid")
    descriptor = -1
    try:
        descriptor = os.open(
            "/", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if index < len(parts) - 1 or kind == "directory":
                flags |= os.O_DIRECTORY
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        opened = os.fstat(descriptor)
    except OSError:
        _fail("resource.path_invalid")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    expected = (
        stat.S_ISREG(opened.st_mode)
        if kind == "file"
        else stat.S_ISDIR(opened.st_mode)
    )
    if not expected or opened.st_uid != owner_uid:
        _fail("resource.path_invalid")
    return path


class AgentOllamaRuntime(Protocol):
    """Fixed typed boundary implemented by the hardened local runtime adapter."""

    def plan(self, arguments: object) -> Mapping[str, object]: ...
    def apply(self, arguments: object) -> Mapping[str, object]: ...
    def probe(self, arguments: object) -> Mapping[str, object]: ...
    def stop(self, arguments: object) -> Mapping[str, object]: ...


class AgentOllamaExecutor:
    """Exact per-action parsers in front of a non-dynamic runtime adapter."""

    def __init__(self, runtime: AgentOllamaRuntime) -> None:
        self._runtime = runtime

    def plan(self, value: object) -> dict[str, object]:
        """Validate and execute a read-only local plan."""
        return dict(
            self._runtime.plan(
                _arguments(value, frozenset({"instance_ref", "generation"}))
            )
        )

    def apply(self, value: object) -> dict[str, object]:
        """Validate and apply one previously bound plan reference."""
        return dict(self._runtime.apply(_arguments(value, frozenset({"plan_ref"}))))

    def probe(self, value: object) -> dict[str, object]:
        """Validate and probe one applied instance generation."""
        return dict(
            self._runtime.probe(
                _arguments(value, frozenset({"instance_ref", "generation"}))
            )
        )

    def stop(self, value: object) -> dict[str, object]:
        """Validate and stop one applied instance generation."""
        return dict(
            self._runtime.stop(
                _arguments(value, frozenset({"instance_ref", "generation"}))
            )
        )


__all__ = [
    "AgentOllamaError",
    "AgentOllamaExecutor",
    "AgentOllamaRuntime",
    "validate_private_path",
]
