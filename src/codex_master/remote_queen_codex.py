from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Protocol

from codex_master.remote_queen_bootstrap import ManifestGenerationV1
from codex_master.remote_queen_bootstrap import RemoteQueenBootstrapError


OPENAI_CODEX_CLI_DOCUMENTATION_URL = (
    "https://developers.openai.com/codex/cli/"
)
OPENAI_CODEX_STANDALONE_INSTALLER_URL = (
    "https://chatgpt.com/codex/install.sh"
)


class CodexInstallStateKindV1(str, Enum):
    ABSENT = "absent"
    OWNED = "owned"
    FOREIGN = "foreign"


class CodexPlanActionV1(str, Enum):
    INSTALL = "install"
    REPLACE_OWNED = "replace-owned"


_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MUTABLE_GENERATION_VALUES = frozenset(
    "".join(parts)
    for parts in (
        ("l", "a", "t", "e", "s", "t"),
        ("s", "t", "a", "b", "l", "e"),
        ("d", "a", "i", "l", "y"),
        ("m", "a", "i", "n"),
        ("H", "E", "A", "D"),
    )
)


def _inconsistent() -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


def _require_text(value: object, *, max_length: int = 128) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > max_length
        or value != value.strip()
        or not value.isascii()
        or not value.isprintable()
    ):
        raise _inconsistent()
    return value


def _require_generation(value: object) -> str:
    value = _require_text(value)
    if value in _MUTABLE_GENERATION_VALUES:
        raise _inconsistent()
    return value


def _require_digest(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise _inconsistent()
    return value


def _require_version(value: object) -> str:
    value = _require_text(value)
    if any(operator in value for operator in "<>=~^*"):
        raise _inconsistent()
    if value in _MUTABLE_GENERATION_VALUES:
        raise _inconsistent()
    return value


def _require_remote_home(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value == "/"
        or not value.startswith("/")
        or value.startswith("~")
        or "~" in value
        or "//" in value
        or value.endswith("/")
        or value != value.rstrip()
        or not value.isprintable()
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise _inconsistent()
    path = PurePosixPath(value)
    if str(path) != value or not path.is_absolute():
        raise _inconsistent()
    return value


def _require_absolute_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value == "/"
        or not value.startswith("/")
        or "~" in value
        or "//" in value
        or value.endswith("/")
        or value != value.strip()
        or not value.isprintable()
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise _inconsistent()
    path = PurePosixPath(value)
    if str(path) != value or not path.is_absolute():
        raise _inconsistent()
    return value


@dataclass(frozen=True, slots=True)
class CodexStandaloneSourceV1:
    kind: str
    documentation_url: str
    installer_url: str
    installer_generation: str
    installer_sha256: str

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind != "openai-standalone-installer":
            raise _inconsistent()
        if (
            type(self.documentation_url) is not str
            or self.documentation_url != OPENAI_CODEX_CLI_DOCUMENTATION_URL
        ):
            raise _inconsistent()
        if (
            type(self.installer_url) is not str
            or self.installer_url != OPENAI_CODEX_STANDALONE_INSTALLER_URL
        ):
            raise _inconsistent()
        _require_generation(self.installer_generation)
        _require_digest(self.installer_sha256)


@dataclass(frozen=True, slots=True)
class RemoteQueenCodexManifestV1:
    schema_version: str
    desired_generation: ManifestGenerationV1
    catalog_generation: ManifestGenerationV1
    source: CodexStandaloneSourceV1
    platform: str
    architecture: str
    expected_version: str
    expected_binary_sha256: str
    expected_owner_uid: int
    install_path: str
    config_path: str
    manifest_digest: str

    def __post_init__(self) -> None:
        _validate_manifest(self, verify_digest=True)


def _generation_dict(value: ManifestGenerationV1) -> dict[str, object]:
    return {"generation": value.generation, "sha256": value.sha256}


def _source_dict(value: CodexStandaloneSourceV1) -> dict[str, object]:
    return {
        "kind": value.kind,
        "documentation_url": value.documentation_url,
        "installer_url": value.installer_url,
        "installer_generation": value.installer_generation,
        "installer_sha256": value.installer_sha256,
    }


def _manifest_payload(manifest: RemoteQueenCodexManifestV1) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "desired_generation": _generation_dict(manifest.desired_generation),
        "catalog_generation": _generation_dict(manifest.catalog_generation),
        "source": _source_dict(manifest.source),
        "platform": manifest.platform,
        "architecture": manifest.architecture,
        "expected_version": manifest.expected_version,
        "expected_binary_sha256": manifest.expected_binary_sha256,
        "expected_owner_uid": manifest.expected_owner_uid,
        "install_path": manifest.install_path,
        "config_path": manifest.config_path,
    }


def _manifest_dict(manifest: RemoteQueenCodexManifestV1) -> dict[str, object]:
    payload = _manifest_payload(manifest)
    payload["manifest_digest"] = manifest.manifest_digest
    return payload


def _digest(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_manifest(
    manifest: RemoteQueenCodexManifestV1,
    *,
    verify_digest: bool,
) -> None:
    if type(manifest.schema_version) is not str or manifest.schema_version != (
        "RemoteQueenCodexManifestV1"
    ):
        raise _inconsistent()
    if type(manifest.desired_generation) is not ManifestGenerationV1:
        raise _inconsistent()
    if type(manifest.catalog_generation) is not ManifestGenerationV1:
        raise _inconsistent()
    _require_generation(manifest.desired_generation.generation)
    _require_digest(manifest.desired_generation.sha256)
    _require_generation(manifest.catalog_generation.generation)
    _require_digest(manifest.catalog_generation.sha256)
    if type(manifest.source) is not CodexStandaloneSourceV1:
        raise _inconsistent()
    if type(manifest.platform) is not str or manifest.platform != "linux":
        raise _inconsistent()
    if type(manifest.architecture) is not str or manifest.architecture not in {
        "x86_64",
        "aarch64",
    }:
        raise _inconsistent()
    _require_version(manifest.expected_version)
    _require_digest(manifest.expected_binary_sha256)
    if type(manifest.expected_owner_uid) is not int or isinstance(
        manifest.expected_owner_uid, bool
    ) or manifest.expected_owner_uid < 0:
        raise _inconsistent()
    install_path = _require_absolute_path(manifest.install_path)
    config_path = _require_absolute_path(manifest.config_path)
    if not install_path.endswith("/.local/bin/codex") or not config_path.endswith(
        "/.codex/config.toml"
    ):
        raise _inconsistent()
    install_home = install_path.removesuffix("/.local/bin/codex")
    config_home = config_path.removesuffix("/.codex/config.toml")
    if install_home != config_home:
        raise _inconsistent()
    _require_remote_home(install_home)
    if install_path != str(PurePosixPath(install_home) / ".local" / "bin" / "codex"):
        raise _inconsistent()
    if config_path != str(PurePosixPath(config_home) / ".codex" / "config.toml"):
        raise _inconsistent()
    if type(manifest.manifest_digest) is not str or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", manifest.manifest_digest
    ):
        raise _inconsistent()
    if verify_digest and _digest(_manifest_payload(manifest)) != manifest.manifest_digest:
        raise _inconsistent()


def build_remote_queen_codex_manifest(
    *,
    desired_generation: ManifestGenerationV1,
    catalog_generation: ManifestGenerationV1,
    installer_generation: str,
    installer_sha256: str,
    architecture: str,
    expected_version: str,
    expected_binary_sha256: str,
    remote_home: str,
    expected_owner_uid: int,
) -> RemoteQueenCodexManifestV1:
    if type(desired_generation) is not ManifestGenerationV1:
        raise _inconsistent()
    if type(catalog_generation) is not ManifestGenerationV1:
        raise _inconsistent()
    _require_generation(desired_generation.generation)
    _require_digest(desired_generation.sha256)
    _require_generation(catalog_generation.generation)
    _require_digest(catalog_generation.sha256)
    _require_generation(installer_generation)
    _require_digest(installer_sha256)
    if type(architecture) is not str or architecture not in {
        "x86_64",
        "aarch64",
    }:
        raise _inconsistent()
    _require_version(expected_version)
    _require_digest(expected_binary_sha256)
    _require_remote_home(remote_home)
    if type(expected_owner_uid) is not int or isinstance(expected_owner_uid, bool):
        raise _inconsistent()
    if expected_owner_uid < 0:
        raise _inconsistent()
    source = CodexStandaloneSourceV1(
        kind="openai-standalone-installer",
        documentation_url=OPENAI_CODEX_CLI_DOCUMENTATION_URL,
        installer_url=OPENAI_CODEX_STANDALONE_INSTALLER_URL,
        installer_generation=installer_generation,
        installer_sha256=installer_sha256,
    )
    home = PurePosixPath(remote_home)
    install_path = str(home / ".local" / "bin" / "codex")
    config_path = str(home / ".codex" / "config.toml")
    payload = {
        "schema_version": "RemoteQueenCodexManifestV1",
        "desired_generation": _generation_dict(desired_generation),
        "catalog_generation": _generation_dict(catalog_generation),
        "source": _source_dict(source),
        "platform": "linux",
        "architecture": architecture,
        "expected_version": expected_version,
        "expected_binary_sha256": expected_binary_sha256,
        "expected_owner_uid": expected_owner_uid,
        "install_path": install_path,
        "config_path": config_path,
    }
    return RemoteQueenCodexManifestV1(
        schema_version="RemoteQueenCodexManifestV1",
        desired_generation=desired_generation,
        catalog_generation=catalog_generation,
        source=source,
        platform="linux",
        architecture=architecture,
        expected_version=expected_version,
        expected_binary_sha256=expected_binary_sha256,
        expected_owner_uid=expected_owner_uid,
        install_path=install_path,
        config_path=config_path,
        manifest_digest=_digest(payload),
    )


def codex_manifest_as_dict(
    manifest: RemoteQueenCodexManifestV1,
) -> dict[str, object]:
    if type(manifest) is not RemoteQueenCodexManifestV1:
        raise _inconsistent()
    _validate_manifest(manifest, verify_digest=True)
    return _manifest_dict(manifest)


@dataclass(frozen=True, slots=True)
class CodexInstallFactV1:
    state: CodexInstallStateKindV1
    generation: str | None
    install_path: str | None
    owner_uid: int | None
    reported_version: str | None
    binary_sha256: str | None
    installer_generation: str | None
    installer_sha256: str | None
    source_url: str | None
    config_path: str | None
    cli_start_ok: bool
    mcp_list_ok: bool
    resume_supported: bool

    def __post_init__(self) -> None:
        _validate_fact(self)


@dataclass(frozen=True, slots=True)
class RemoteQueenCodexPlanV1:
    schema_version: str
    manifest: RemoteQueenCodexManifestV1
    before: CodexInstallFactV1
    before_digest: str
    action: CodexPlanActionV1 | None
    plan_digest: str

    def __post_init__(self) -> None:
        _validate_plan(self, verify_digest=True)


@dataclass(frozen=True, slots=True)
class CodexApplyRequestV1:
    generation: str
    manifest_digest: str
    plan_digest: str

    def __post_init__(self) -> None:
        _validate_apply_request(self)


@dataclass(frozen=True, slots=True)
class CodexApplyJournalV1:
    schema_version: str
    generation: str
    manifest_digest: str
    plan_digest: str
    prior: CodexInstallFactV1
    resulting_fact_digest: str

    def __post_init__(self) -> None:
        _validate_journal(self)


@dataclass(frozen=True, slots=True)
class CodexApplyResultV1:
    changed: bool
    journal: CodexApplyJournalV1 | None
    fact_digest: str

    def __post_init__(self) -> None:
        if type(self.changed) is not bool:
            raise _inconsistent()
        if self.journal is not None and type(self.journal) is not CodexApplyJournalV1:
            raise _inconsistent()
        _require_prefixed_digest(self.fact_digest)


@dataclass(frozen=True, slots=True)
class CodexVerifyRequestV1:
    generation: str
    manifest_digest: str

    def __post_init__(self) -> None:
        _validate_verify_request(self)


@dataclass(frozen=True, slots=True)
class CodexVerifyResultV1:
    fact_digest: str

    def __post_init__(self) -> None:
        _require_prefixed_digest(self.fact_digest)


@dataclass(frozen=True, slots=True)
class CodexRollbackRequestV1:
    generation: str
    manifest_digest: str
    plan_digest: str

    def __post_init__(self) -> None:
        _validate_rollback_request(self)


@dataclass(frozen=True, slots=True)
class CodexRollbackResultV1:
    restored_fact_digest: str

    def __post_init__(self) -> None:
        _require_prefixed_digest(self.restored_fact_digest)


class RemoteQueenCodexOperations(Protocol):
    def inspect(
        self, manifest: RemoteQueenCodexManifestV1
    ) -> CodexInstallFactV1: ...

    def install_attested(
        self, plan: RemoteQueenCodexPlanV1
    ) -> CodexApplyJournalV1: ...

    def rollback_installation(
        self,
        plan: RemoteQueenCodexPlanV1,
        journal: CodexApplyJournalV1,
    ) -> None: ...


def _require_url(value: object) -> str:
    if type(value) is not str or not value or len(value) > 2048:
        raise _inconsistent()
    if value != value.strip() or not value.isascii() or not value.isprintable():
        raise _inconsistent()
    if not (value.startswith("http://") or value.startswith("https://")):
        raise _inconsistent()
    if value.endswith("://"):
        raise _inconsistent()
    return value


def _validate_fact(fact: CodexInstallFactV1) -> None:
    if type(fact.state) is not CodexInstallStateKindV1:
        raise _inconsistent()
    probes = (fact.cli_start_ok, fact.mcp_list_ok, fact.resume_supported)
    if any(type(value) is not bool for value in probes):
        raise _inconsistent()
    values = (
        fact.generation,
        fact.install_path,
        fact.owner_uid,
        fact.reported_version,
        fact.binary_sha256,
        fact.installer_generation,
        fact.installer_sha256,
        fact.source_url,
        fact.config_path,
    )
    if fact.state is CodexInstallStateKindV1.ABSENT:
        if any(value is not None for value in values) or any(probes):
            raise _inconsistent()
        return
    _require_generation(fact.generation)
    _require_absolute_path(fact.install_path)
    if type(fact.owner_uid) is not int or isinstance(fact.owner_uid, bool):
        raise _inconsistent()
    if fact.owner_uid < 0:
        raise _inconsistent()
    _require_version(fact.reported_version)
    _require_digest(fact.binary_sha256)
    _require_generation(fact.installer_generation)
    _require_digest(fact.installer_sha256)
    _require_url(fact.source_url)
    _require_absolute_path(fact.config_path)


def _fact_dict(fact: CodexInstallFactV1) -> dict[str, object]:
    return {
        "state": fact.state.value,
        "generation": fact.generation,
        "install_path": fact.install_path,
        "owner_uid": fact.owner_uid,
        "reported_version": fact.reported_version,
        "binary_sha256": fact.binary_sha256,
        "installer_generation": fact.installer_generation,
        "installer_sha256": fact.installer_sha256,
        "source_url": fact.source_url,
        "config_path": fact.config_path,
        "cli_start_ok": fact.cli_start_ok,
        "mcp_list_ok": fact.mcp_list_ok,
        "resume_supported": fact.resume_supported,
    }


def _fact_digest(fact: CodexInstallFactV1) -> str:
    return _digest(_fact_dict(fact))


def _plan_payload(plan: RemoteQueenCodexPlanV1) -> dict[str, object]:
    return {
        "schema_version": plan.schema_version,
        "manifest": _manifest_dict(plan.manifest),
        "before": _fact_dict(plan.before),
        "before_digest": plan.before_digest,
        "action": None if plan.action is None else plan.action.value,
    }


def _validate_plan(
    plan: RemoteQueenCodexPlanV1,
    *,
    verify_digest: bool,
) -> None:
    if type(plan.schema_version) is not str or plan.schema_version != (
        "RemoteQueenCodexPlanV1"
    ):
        raise _inconsistent()
    if type(plan.manifest) is not RemoteQueenCodexManifestV1:
        raise _inconsistent()
    _validate_manifest(plan.manifest, verify_digest=True)
    if type(plan.before) is not CodexInstallFactV1:
        raise _inconsistent()
    _validate_fact(plan.before)
    if type(plan.before_digest) is not str or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", plan.before_digest
    ):
        raise _inconsistent()
    if _fact_digest(plan.before) != plan.before_digest:
        raise _inconsistent()
    if plan.action is not None and type(plan.action) is not CodexPlanActionV1:
        raise _inconsistent()
    try:
        expected_action = _expected_plan_action(
            manifest=plan.manifest,
            fact=plan.before,
        )
    except RemoteQueenBootstrapError:
        raise _inconsistent() from None
    if plan.action is not expected_action:
        raise _inconsistent()
    if type(plan.plan_digest) is not str or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", plan.plan_digest
    ):
        raise _inconsistent()
    if verify_digest and _digest(_plan_payload(plan)) != plan.plan_digest:
        raise _inconsistent()


def codex_plan_as_dict(
    plan: RemoteQueenCodexPlanV1,
) -> dict[str, object]:
    if type(plan) is not RemoteQueenCodexPlanV1:
        raise _inconsistent()
    _validate_plan(plan, verify_digest=True)
    payload = _plan_payload(plan)
    payload["plan_digest"] = plan.plan_digest
    return payload


def _attestation() -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError("RQ_E_CODEX_ATTESTATION")


def _foreign() -> RemoteQueenBootstrapError:
    return RemoteQueenBootstrapError("RQ_E_FOREIGN_STATE")


def _fact_matches_manifest(
    fact: CodexInstallFactV1,
    manifest: RemoteQueenCodexManifestV1,
) -> bool:
    return (
        fact.state is CodexInstallStateKindV1.OWNED
        and fact.generation == manifest.desired_generation.generation
        and fact.install_path == manifest.install_path
        and fact.owner_uid == manifest.expected_owner_uid
        and fact.reported_version == manifest.expected_version
        and fact.binary_sha256 == manifest.expected_binary_sha256
        and fact.installer_generation == manifest.source.installer_generation
        and fact.installer_sha256 == manifest.source.installer_sha256
        and fact.source_url == manifest.source.installer_url
        and fact.config_path == manifest.config_path
        and fact.cli_start_ok
        and fact.mcp_list_ok
        and fact.resume_supported
    )


def plan_remote_queen_codex(
    *,
    manifest: RemoteQueenCodexManifestV1,
    operations: RemoteQueenCodexOperations,
) -> RemoteQueenCodexPlanV1:
    if type(manifest) is not RemoteQueenCodexManifestV1:
        raise _inconsistent()
    _validate_manifest(manifest, verify_digest=True)
    try:
        before = operations.inspect(manifest)
    except Exception:
        raise _attestation() from None
    if type(before) is not CodexInstallFactV1:
        raise _inconsistent()
    _validate_fact(before)

    if before.state is CodexInstallStateKindV1.FOREIGN:
        raise _foreign()
    if before.state is CodexInstallStateKindV1.ABSENT:
        action = CodexPlanActionV1.INSTALL
    elif before.owner_uid != manifest.expected_owner_uid:
        raise _foreign()
    elif before.install_path != manifest.install_path or before.config_path != manifest.config_path:
        raise _foreign()
    elif before.source_url != manifest.source.installer_url:
        raise _attestation()
    elif before.generation == manifest.desired_generation.generation:
        if not _fact_matches_manifest(before, manifest):
            raise _attestation()
        action = None
    elif not (before.cli_start_ok and before.mcp_list_ok and before.resume_supported):
        raise _attestation()
    else:
        action = CodexPlanActionV1.REPLACE_OWNED

    before_digest = _fact_digest(before)
    plan_payload = {
        "schema_version": "RemoteQueenCodexPlanV1",
        "manifest": _manifest_dict(manifest),
        "before": _fact_dict(before),
        "before_digest": before_digest,
        "action": None if action is None else action.value,
    }
    plan_digest = _digest(plan_payload)
    return RemoteQueenCodexPlanV1(
        schema_version="RemoteQueenCodexPlanV1",
        manifest=manifest,
        before=before,
        before_digest=before_digest,
        action=action,
        plan_digest=plan_digest,
    )


def _require_prefixed_digest(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise _inconsistent()
    return value


def _validate_apply_request(request: CodexApplyRequestV1) -> None:
    _require_generation(request.generation)
    _require_prefixed_digest(request.manifest_digest)
    _require_prefixed_digest(request.plan_digest)


def _validate_verify_request(request: CodexVerifyRequestV1) -> None:
    _require_generation(request.generation)
    _require_prefixed_digest(request.manifest_digest)


def _validate_rollback_request(request: CodexRollbackRequestV1) -> None:
    _require_generation(request.generation)
    _require_prefixed_digest(request.manifest_digest)
    _require_prefixed_digest(request.plan_digest)


def _validate_journal(journal: CodexApplyJournalV1) -> None:
    if type(journal.schema_version) is not str or journal.schema_version != (
        "CodexApplyJournalV1"
    ):
        raise _inconsistent()
    _require_generation(journal.generation)
    _require_prefixed_digest(journal.manifest_digest)
    _require_prefixed_digest(journal.plan_digest)
    if type(journal.prior) is not CodexInstallFactV1:
        raise _inconsistent()
    _validate_fact(journal.prior)
    _require_prefixed_digest(journal.resulting_fact_digest)


def _inspect_fact(
    *,
    manifest: RemoteQueenCodexManifestV1,
    operations: RemoteQueenCodexOperations,
) -> CodexInstallFactV1:
    try:
        fact = operations.inspect(manifest)
    except Exception:
        raise _attestation() from None
    if type(fact) is not CodexInstallFactV1:
        raise _inconsistent()
    _validate_fact(fact)
    return fact


def _validate_request_binding(
    *,
    manifest: RemoteQueenCodexManifestV1,
    plan: RemoteQueenCodexPlanV1,
    request: CodexApplyRequestV1 | CodexRollbackRequestV1,
) -> None:
    if (
        request.generation != manifest.desired_generation.generation
        or request.manifest_digest != manifest.manifest_digest
        or request.plan_digest != plan.plan_digest
        or plan.manifest != manifest
    ):
        raise _inconsistent()


def _validate_verify_binding(
    *,
    manifest: RemoteQueenCodexManifestV1,
    request: CodexVerifyRequestV1,
) -> None:
    if (
        request.generation != manifest.desired_generation.generation
        or request.manifest_digest != manifest.manifest_digest
    ):
        raise _inconsistent()


def _expected_plan_action(
    *,
    manifest: RemoteQueenCodexManifestV1,
    fact: CodexInstallFactV1,
) -> CodexPlanActionV1 | None:
    if fact.state is CodexInstallStateKindV1.ABSENT:
        return CodexPlanActionV1.INSTALL
    if fact.state is not CodexInstallStateKindV1.OWNED:
        raise _inconsistent()
    if (
        fact.owner_uid != manifest.expected_owner_uid
        or fact.install_path != manifest.install_path
        or fact.config_path != manifest.config_path
        or fact.source_url != manifest.source.installer_url
    ):
        raise _inconsistent()
    if fact.generation == manifest.desired_generation.generation:
        if not _fact_matches_manifest(fact, manifest):
            raise _inconsistent()
        return None
    if not (fact.cli_start_ok and fact.mcp_list_ok and fact.resume_supported):
        raise _inconsistent()
    return CodexPlanActionV1.REPLACE_OWNED


def apply_remote_queen_codex(
    *,
    plan: RemoteQueenCodexPlanV1,
    request: CodexApplyRequestV1,
    operations: RemoteQueenCodexOperations,
) -> CodexApplyResultV1:
    if type(plan) is not RemoteQueenCodexPlanV1 or type(request) is not CodexApplyRequestV1:
        raise _inconsistent()
    _validate_plan(plan, verify_digest=True)
    _validate_apply_request(request)
    _validate_request_binding(manifest=plan.manifest, plan=plan, request=request)
    if _expected_plan_action(manifest=plan.manifest, fact=plan.before) != plan.action:
        raise _inconsistent()

    before = _inspect_fact(manifest=plan.manifest, operations=operations)
    if _fact_digest(before) != plan.before_digest:
        raise _attestation()
    if plan.action is None:
        if not _fact_matches_manifest(before, plan.manifest):
            raise _attestation()
        return CodexApplyResultV1(
            changed=False,
            journal=None,
            fact_digest=_fact_digest(before),
        )

    try:
        journal = operations.install_attested(plan)
    except Exception:
        raise _attestation() from None
    if type(journal) is not CodexApplyJournalV1:
        raise _inconsistent()
    _validate_journal(journal)
    if (
        journal.generation != plan.manifest.desired_generation.generation
        or journal.manifest_digest != plan.manifest.manifest_digest
        or journal.plan_digest != plan.plan_digest
        or journal.prior != plan.before
    ):
        raise _inconsistent()

    after = _inspect_fact(manifest=plan.manifest, operations=operations)
    after_digest = _fact_digest(after)
    if journal.resulting_fact_digest != after_digest:
        raise _inconsistent()
    if not _fact_matches_manifest(after, plan.manifest):
        raise _attestation()
    return CodexApplyResultV1(
        changed=True,
        journal=journal,
        fact_digest=after_digest,
    )


def verify_remote_queen_codex(
    *,
    manifest: RemoteQueenCodexManifestV1,
    request: CodexVerifyRequestV1,
    operations: RemoteQueenCodexOperations,
) -> CodexVerifyResultV1:
    if type(manifest) is not RemoteQueenCodexManifestV1 or type(request) is not CodexVerifyRequestV1:
        raise _inconsistent()
    _validate_manifest(manifest, verify_digest=True)
    _validate_verify_request(request)
    _validate_verify_binding(manifest=manifest, request=request)
    fact = _inspect_fact(manifest=manifest, operations=operations)
    if not _fact_matches_manifest(fact, manifest):
        raise _attestation()
    return CodexVerifyResultV1(fact_digest=_fact_digest(fact))


def rollback_remote_queen_codex(
    *,
    plan: RemoteQueenCodexPlanV1,
    journal: CodexApplyJournalV1,
    request: CodexRollbackRequestV1,
    operations: RemoteQueenCodexOperations,
) -> CodexRollbackResultV1:
    if (
        type(plan) is not RemoteQueenCodexPlanV1
        or type(journal) is not CodexApplyJournalV1
        or type(request) is not CodexRollbackRequestV1
    ):
        raise _inconsistent()
    _validate_plan(plan, verify_digest=True)
    _validate_journal(journal)
    _validate_rollback_request(request)
    _validate_request_binding(manifest=plan.manifest, plan=plan, request=request)
    if plan.action is None:
        raise _inconsistent()
    if (
        journal.generation != plan.manifest.desired_generation.generation
        or journal.manifest_digest != plan.manifest.manifest_digest
        or journal.plan_digest != plan.plan_digest
        or journal.prior != plan.before
    ):
        raise _inconsistent()

    current = _inspect_fact(manifest=plan.manifest, operations=operations)
    if (
        current.state is not CodexInstallStateKindV1.OWNED
        or current.generation != plan.manifest.desired_generation.generation
        or _fact_digest(current) != journal.resulting_fact_digest
        or not _fact_matches_manifest(current, plan.manifest)
    ):
        raise RemoteQueenBootstrapError("RQ_E_ROLLBACK_DRIFT")
    try:
        operations.rollback_installation(plan, journal)
    except Exception:
        raise _attestation() from None
    restored = _inspect_fact(manifest=plan.manifest, operations=operations)
    if restored != plan.before:
        raise RemoteQueenBootstrapError("RQ_E_ROLLBACK_DRIFT")
    return CodexRollbackResultV1(restored_fact_digest=_fact_digest(restored))
