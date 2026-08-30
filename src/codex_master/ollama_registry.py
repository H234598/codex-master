"""Versioned, local Ollama model catalog and instance-placement registry."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import secrets
from typing import Iterator


_SCHEMA_VERSION = 1
_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_LOCAL_RUNNING_INSTANCES = 4
_DEFAULT_PATH = Path.home() / ".local/state/codex-master-mcp/ollama-registry.json"


class OllamaRegistryError(ValueError):
    """Code-only registry failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise OllamaRegistryError(code) from None


def _required_string(value: object, code: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(code)
    return value


@dataclass(frozen=True, slots=True)
class OllamaModelV1:
    ref: str
    provider_model_id: str
    installed: bool
    hive_enabled: bool
    simple_only: bool
    evidence_at_utc: str | None
    capabilities: tuple[str, ...] = ("chat",)

    def __post_init__(self) -> None:
        _required_string(self.ref, "ollama.model_invalid")
        _required_string(self.provider_model_id, "ollama.model_invalid")
        if (
            type(self.installed) is not bool
            or type(self.hive_enabled) is not bool
            or self.simple_only is not True
            or (
                self.evidence_at_utc is not None
                and not isinstance(self.evidence_at_utc, str)
            )
            or not isinstance(self.capabilities, tuple)
            or not 1 <= len(self.capabilities) <= 16
            or any(
                not isinstance(capability, str)
                or not 1 <= len(capability) <= 64
                or not capability.isascii()
                or any(
                    not (character.isalnum() or character in "._-")
                    for character in capability
                )
                for capability in self.capabilities
            )
            or len(set(self.capabilities)) != len(self.capabilities)
        ):
            _fail("ollama.model_invalid")


@dataclass(frozen=True, slots=True)
class OllamaInstanceV1:
    ref: str
    label: str
    host_ref: str
    ollama_executable: str
    models_directory: str
    selected_model_refs: tuple[str, ...]
    allowed_cpus: str
    cpu_quota_percent: int
    cpu_weight: int
    lifecycle_state: str
    readiness_state: str

    def __post_init__(self) -> None:
        for value in (
            self.ref,
            self.label,
            self.host_ref,
            self.ollama_executable,
            self.models_directory,
            self.allowed_cpus,
            self.lifecycle_state,
            self.readiness_state,
        ):
            _required_string(value, "ollama.instance_invalid")
        if (
            not isinstance(self.selected_model_refs, tuple)
            or not self.selected_model_refs
            or any(not isinstance(ref, str) or not ref for ref in self.selected_model_refs)
            or len(set(self.selected_model_refs)) != len(self.selected_model_refs)
            or type(self.cpu_quota_percent) is not int
            or self.cpu_quota_percent < 1
            or type(self.cpu_weight) is not int
            or self.cpu_weight < 1
        ):
            _fail("ollama.instance_models_invalid")


@dataclass(frozen=True, slots=True)
class OllamaRegistryV1:
    schema_version: int
    generation: int
    models: tuple[OllamaModelV1, ...]
    instances: tuple[OllamaInstanceV1, ...]

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_VERSION:
            _fail("ollama.registry_version_invalid")
        if type(self.generation) is not int or self.generation < 0:
            _fail("ollama.registry_schema_invalid")
        if not isinstance(self.models, tuple) or not isinstance(self.instances, tuple):
            _fail("ollama.registry_schema_invalid")
        if not all(isinstance(model, OllamaModelV1) for model in self.models):
            _fail("ollama.registry_schema_invalid")
        if not all(isinstance(instance, OllamaInstanceV1) for instance in self.instances):
            _fail("ollama.registry_schema_invalid")

        model_refs = tuple(model.ref for model in self.models)
        instance_refs = tuple(instance.ref for instance in self.instances)
        if len(set((*model_refs, *instance_refs))) != len(model_refs) + len(instance_refs):
            _fail("ollama.registry_ref_duplicate")
        known_models = set(model_refs)
        if any(
            ref not in known_models
            for instance in self.instances
            for ref in instance.selected_model_refs
        ):
            _fail("ollama.instance_model_missing")
        if sum(
            instance.host_ref == "local" and instance.lifecycle_state == "running"
            for instance in self.instances
        ) > _MAX_LOCAL_RUNNING_INSTANCES:
            _fail("ollama.instance_count_invalid")


class OllamaRegistryStore:
    """CAS-backed registry file using a lock plus durable atomic replacement."""

    __slots__ = ("_path", "_lock_path")

    def __init__(self, path: Path = _DEFAULT_PATH) -> None:
        self._path = Path(path)
        self._lock_path = self._path.with_name(f".{self._path.name}.lock")

    @classmethod
    def for_test(cls, directory: Path) -> OllamaRegistryStore:
        return cls(Path(directory) / "ollama-registry.json")

    def load(self) -> OllamaRegistryV1:
        with self._locked():
            return self._load_unlocked()

    def replace(
        self,
        *,
        models: tuple[OllamaModelV1, ...],
        instances: tuple[OllamaInstanceV1, ...],
        expected_generation: int,
    ) -> OllamaRegistryV1:
        if type(expected_generation) is not int or expected_generation < 0:
            _fail("ollama.registry_generation_conflict")
        with self._locked():
            current = self._load_unlocked()
            if current.generation != expected_generation:
                _fail("ollama.registry_generation_conflict")
            replacement = OllamaRegistryV1(
                schema_version=_SCHEMA_VERSION,
                generation=current.generation + 1,
                models=models,
                instances=instances,
            )
            self._write_unlocked(replacement)
            return replacement

    @contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                self._lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
        except OSError:
            _fail("ollama.registry_store_unavailable")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        except OllamaRegistryError:
            raise
        except OSError:
            _fail("ollama.registry_store_unavailable")
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _load_unlocked(self) -> OllamaRegistryV1:
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            return OllamaRegistryV1(_SCHEMA_VERSION, 0, (), ())
        except OSError:
            _fail("ollama.registry_store_unavailable")
        if len(raw) > _MAX_DOCUMENT_BYTES:
            _fail("ollama.registry_schema_invalid")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("ollama.registry_schema_invalid")
        return _registry_from_document(document)

    def _write_unlocked(self, registry: OllamaRegistryV1) -> None:
        payload = json.dumps(
            _registry_document(registry), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        temporary = self._path.with_name(
            f".{self._path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        )
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
            )
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, self._path)
            parent_descriptor = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except OSError:
            _fail("ollama.registry_store_write_failed")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                _fail("ollama.registry_store_write_failed")


def _registry_from_document(value: object) -> OllamaRegistryV1:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "generation",
        "models",
        "instances",
    }:
        _fail("ollama.registry_schema_invalid")
    if value["schema_version"] != _SCHEMA_VERSION:
        _fail("ollama.registry_version_invalid")
    models = value["models"]
    instances = value["instances"]
    if type(models) is not list or type(instances) is not list:
        _fail("ollama.registry_schema_invalid")
    try:
        return OllamaRegistryV1(
            schema_version=value["schema_version"],
            generation=value["generation"],
            models=tuple(
                OllamaModelV1(
                    **{
                        **model,
                        **(
                            {"capabilities": tuple(model["capabilities"])}
                            if "capabilities" in model
                            else {}
                        ),
                    }
                )
                for model in models
            ),
            instances=tuple(
                OllamaInstanceV1(
                    **{
                        **instance,
                        "selected_model_refs": tuple(instance["selected_model_refs"]),
                    }
                )
                for instance in instances
            ),
        )
    except (KeyError, TypeError, OllamaRegistryError):
        _fail("ollama.registry_schema_invalid")


def _registry_document(registry: OllamaRegistryV1) -> dict[str, object]:
    return {
        "schema_version": registry.schema_version,
        "generation": registry.generation,
        "models": [
            {
                "ref": model.ref,
                "provider_model_id": model.provider_model_id,
                "installed": model.installed,
                "hive_enabled": model.hive_enabled,
                "simple_only": model.simple_only,
                "evidence_at_utc": model.evidence_at_utc,
                "capabilities": list(model.capabilities),
            }
            for model in registry.models
        ],
        "instances": [
            {
                "ref": instance.ref,
                "label": instance.label,
                "host_ref": instance.host_ref,
                "ollama_executable": instance.ollama_executable,
                "models_directory": instance.models_directory,
                "selected_model_refs": list(instance.selected_model_refs),
                "allowed_cpus": instance.allowed_cpus,
                "cpu_quota_percent": instance.cpu_quota_percent,
                "cpu_weight": instance.cpu_weight,
                "lifecycle_state": instance.lifecycle_state,
                "readiness_state": instance.readiness_state,
            }
            for instance in registry.instances
        ],
    }


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]
