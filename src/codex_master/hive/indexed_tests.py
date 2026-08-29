"""Canonical Hive test-index V1 domain model."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPOSITORY_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_LANGUAGES = frozenset({"python", "javascript", "typescript"})
_RUNNERS = frozenset({"pytest", "node_test", "repository_adapter"})
_COOLDOWNS = frozenset({"deterministic", "integration", "environmental", "external", "mandatory"})
_RISKS = frozenset({"read_only", "mutating", "credential_boundary", "lifecycle", "release"})
_KINDS = frozenset({"unit", "boundary", "integration", "regression", "packaging", "external", "gate"})
_HERMETICITY = frozenset({"hermetic", "executor_bound", "external"})
_PHASES = frozenset({"change", "branch", "merge", "release"})
_RESOURCES = frozenset({"network", "database", "browser", "gpu", "system_bus", "external_api"})
_TOP_FIELDS = frozenset(
    {
        "schema_version",
        "generation",
        "repository_id",
        "indexer_version",
        "source_root_digest",
        "test_root_digest",
        "dependency_policy_digest",
        "functions",
        "tests",
        "gates",
    }
)


class TestIndexError(ValueError):
    """Typed, bounded test-index validation failure."""


def _fail(reason: str) -> None:
    raise TestIndexError(reason)


def _exact_fields(value: object, expected: frozenset[str], *, reason: str = "test.index_invalid") -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail(reason)
    return value


def _text(value: object, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(char) < 32 for char in value):
        _fail("test.index_invalid")
    return value


def _enum(value: object, allowed: frozenset[str]) -> str:
    text = _text(value, maximum=64)
    if text not in allowed:
        _fail("test.index_invalid")
    return text


def _positive_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail("test.index_invalid")
    return value


def _digest(value: object, *, assertion: bool = False) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        _fail("test.assertion_missing" if assertion else "test.index_invalid")
    return value


def _path(value: object) -> str:
    text = _text(value, maximum=512)
    path = PurePosixPath(text)
    if path.is_absolute() or text != path.as_posix() or ".." in path.parts or "." in path.parts:
        _fail("test.index_invalid")
    return text


def _sorted_unique_texts(value: object, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or (nonempty and not value):
        _fail("test.index_invalid")
    values = tuple(_text(item) for item in value)
    if list(values) != sorted(set(values)):
        _fail("test.index_invalid")
    return values


@dataclass(frozen=True, slots=True)
class FunctionEntryV1:
    function_id: str
    language: str
    path: str
    qualified_name: str
    source_digest: str
    dependency_digest: str
    test_ids: tuple[str, ...]
    cooldown_class: str
    risk: str
    generated: bool

    @classmethod
    def from_mapping(cls, value: object) -> FunctionEntryV1:
        fields = frozenset(cls.__dataclass_fields__)
        raw = _exact_fields(value, fields)
        language = _enum(raw["language"], _LANGUAGES)
        path = _path(raw["path"])
        qualified_name = _text(raw["qualified_name"])
        function_id = _text(raw["function_id"], maximum=1024)
        if function_id != f"{language}:{path}:{qualified_name}":
            _fail("test.index_invalid")
        if raw["test_ids"] == [] or raw["test_ids"] == ():
            _fail("test.function_unindexed")
        test_ids = _sorted_unique_texts(raw["test_ids"], nonempty=True)
        generated = raw["generated"]
        if not isinstance(generated, bool):
            _fail("test.index_invalid")
        return cls(
            function_id,
            language,
            path,
            qualified_name,
            _digest(raw["source_digest"]),
            _digest(raw["dependency_digest"]),
            test_ids,
            _enum(raw["cooldown_class"], _COOLDOWNS),
            _enum(raw["risk"], _RISKS),
            generated,
        )

    def public(self) -> dict[str, object]:
        value = asdict(self)
        value["test_ids"] = list(self.test_ids)
        return value


@dataclass(frozen=True, slots=True)
class TestEntryV1:
    test_id: str
    runner: str
    path: str
    node_id: str
    test_digest: str
    assertion_digest: str
    covers: tuple[str, ...]
    kind: str
    timeout_seconds: int
    hermeticity: str
    required_resources: tuple[str, ...]
    cooldown_class: str

    @classmethod
    def from_mapping(cls, value: object) -> TestEntryV1:
        fields = frozenset(cls.__dataclass_fields__)
        raw = _exact_fields(value, fields)
        runner = _enum(raw["runner"], _RUNNERS)
        path = _path(raw["path"])
        node_id = _text(raw["node_id"], maximum=1024)
        test_id = _text(raw["test_id"], maximum=2048)
        if test_id != f"{runner}:{path}:{node_id}":
            _fail("test.index_invalid")
        resources = _sorted_unique_texts(raw["required_resources"])
        if any(resource not in _RESOURCES for resource in resources):
            _fail("test.index_invalid")
        return cls(
            test_id,
            runner,
            path,
            node_id,
            _digest(raw["test_digest"]),
            _digest(raw["assertion_digest"], assertion=True),
            _sorted_unique_texts(raw["covers"], nonempty=True),
            _enum(raw["kind"], _KINDS),
            _positive_int(raw["timeout_seconds"]),
            _enum(raw["hermeticity"], _HERMETICITY),
            resources,
            _enum(raw["cooldown_class"], _COOLDOWNS),
        )

    def public(self) -> dict[str, object]:
        value = asdict(self)
        value["covers"] = list(self.covers)
        value["required_resources"] = list(self.required_resources)
        return value


@dataclass(frozen=True, slots=True)
class GateEntryV1:
    gate_id: str
    phase: str
    test_ids: tuple[str, ...]
    cooldown_allowed: bool
    required: bool

    @classmethod
    def from_mapping(cls, value: object) -> GateEntryV1:
        fields = frozenset(cls.__dataclass_fields__)
        raw = _exact_fields(value, fields)
        phase = _enum(raw["phase"], _PHASES)
        cooldown_allowed = raw["cooldown_allowed"]
        required = raw["required"]
        if not isinstance(cooldown_allowed, bool) or not isinstance(required, bool):
            _fail("test.index_invalid")
        if phase in {"branch", "merge", "release"} and cooldown_allowed:
            _fail("test.index_invalid")
        return cls(
            _text(raw["gate_id"], maximum=128),
            phase,
            _sorted_unique_texts(raw["test_ids"], nonempty=True),
            cooldown_allowed,
            required,
        )

    def public(self) -> dict[str, object]:
        value = asdict(self)
        value["test_ids"] = list(self.test_ids)
        return value


@dataclass(frozen=True, slots=True)
class TestIndexV1:
    schema_version: int
    generation: int
    repository_id: str
    indexer_version: str
    source_root_digest: str
    test_root_digest: str
    dependency_policy_digest: str
    functions: tuple[FunctionEntryV1, ...]
    tests: tuple[TestEntryV1, ...]
    gates: tuple[GateEntryV1, ...]

    @classmethod
    def from_mapping(cls, value: object) -> TestIndexV1:
        raw = _exact_fields(value, _TOP_FIELDS)
        if raw["schema_version"] != 1 or isinstance(raw["schema_version"], bool):
            _fail("test.index_invalid")
        repository_id = raw["repository_id"]
        if not isinstance(repository_id, str) or not _REPOSITORY_RE.fullmatch(repository_id):
            _fail("test.index_invalid")
        if not isinstance(raw["functions"], (list, tuple)) or not raw["functions"]:
            _fail("test.index_invalid")
        if not isinstance(raw["tests"], (list, tuple)) or not raw["tests"]:
            _fail("test.index_invalid")
        if not isinstance(raw["gates"], (list, tuple)):
            _fail("test.index_invalid")
        functions = tuple(FunctionEntryV1.from_mapping(item) for item in raw["functions"])
        tests = tuple(TestEntryV1.from_mapping(item) for item in raw["tests"])
        gates = tuple(GateEntryV1.from_mapping(item) for item in raw["gates"])
        cls._validate_relations(functions, tests, gates)
        return cls(
            1,
            _positive_int(raw["generation"]),
            repository_id,
            _text(raw["indexer_version"], maximum=128),
            _digest(raw["source_root_digest"]),
            _digest(raw["test_root_digest"]),
            _digest(raw["dependency_policy_digest"]),
            functions,
            tests,
            gates,
        )

    @staticmethod
    def _validate_relations(
        functions: tuple[FunctionEntryV1, ...],
        tests: tuple[TestEntryV1, ...],
        gates: tuple[GateEntryV1, ...],
    ) -> None:
        function_ids = tuple(item.function_id for item in functions)
        test_ids = tuple(item.test_id for item in tests)
        gate_ids = tuple(item.gate_id for item in gates)
        if list(function_ids) != sorted(set(function_ids)) or list(test_ids) != sorted(set(test_ids)):
            _fail("test.index_invalid")
        if list(gate_ids) != sorted(set(gate_ids)):
            _fail("test.index_invalid")
        function_set = set(function_ids)
        test_set = set(test_ids)
        for function in functions:
            if not function.test_ids:
                _fail("test.function_unindexed")
            if not set(function.test_ids) <= test_set:
                _fail("test.test_uncollectable")
        for test in tests:
            if not set(test.covers) <= function_set:
                _fail("test.index_invalid")
            for function_id in test.covers:
                function = functions[function_ids.index(function_id)]
                if test.test_id not in function.test_ids:
                    _fail("test.index_invalid")
        if any(not set(gate.test_ids) <= test_set for gate in gates):
            _fail("test.test_uncollectable")

    def public(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generation": self.generation,
            "repository_id": self.repository_id,
            "indexer_version": self.indexer_version,
            "source_root_digest": self.source_root_digest,
            "test_root_digest": self.test_root_digest,
            "dependency_policy_digest": self.dependency_policy_digest,
            "functions": [item.public() for item in self.functions],
            "tests": [item.public() for item in self.tests],
            "gates": [item.public() for item in self.gates],
        }

    def canonical_bytes(self) -> bytes:
        return (
            json.dumps(self.public(), ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()


def combine_test_indexes(*indexes: TestIndexV1) -> TestIndexV1:
    """Merge language adapters into one repository authority."""
    if not indexes or any(not isinstance(index, TestIndexV1) for index in indexes):
        raise TestIndexError("test.index_invalid")
    repository_ids = {index.repository_id for index in indexes}
    generations = {index.generation for index in indexes}
    if len(repository_ids) != 1 or len(generations) != 1:
        raise TestIndexError("test.index_invalid")
    functions = sorted(
        (item for index in indexes for item in index.functions),
        key=lambda item: item.function_id,
    )
    tests = sorted(
        (item for index in indexes for item in index.tests),
        key=lambda item: item.test_id,
    )
    gates = sorted(
        (item for index in indexes for item in index.gates),
        key=lambda item: item.gate_id,
    )

    def digest_rows(rows: list[str]) -> str:
        return "sha256:" + hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()

    versions = sorted({index.indexer_version for index in indexes})
    version_digest = hashlib.sha256("\n".join(versions).encode()).hexdigest()[:16]
    return TestIndexV1.from_mapping(
        {
            "schema_version": 1,
            "generation": indexes[0].generation,
            "repository_id": indexes[0].repository_id,
            "indexer_version": f"combined-v1-{version_digest}",
            "source_root_digest": digest_rows(
                [f"{item.function_id}:{item.source_digest}" for item in functions]
            ),
            "test_root_digest": digest_rows(
                [f"{item.test_id}:{item.test_digest}:{item.assertion_digest}" for item in tests]
            ),
            "dependency_policy_digest": digest_rows(
                sorted(index.dependency_policy_digest for index in indexes)
            ),
            "functions": [item.public() for item in functions],
            "tests": [item.public() for item in tests],
            "gates": [item.public() for item in gates],
        }
    )


__all__ = [
    "FunctionEntryV1",
    "GateEntryV1",
    "TestEntryV1",
    "TestIndexError",
    "TestIndexV1",
    "combine_test_indexes",
]
