"""Markdown context projection for managed Codex and Gemini homes.

The Hive owns these files.  A managed home receives one common context file
and one class profile; it never receives the host's full ``/home/teladi``
instruction file.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from codex_master.fleet_registry import RunnerKind
from codex_master.hive_policy import load_common_policy

if TYPE_CHECKING:
    from codex_master.fleet_registry import AgentDescriptor


_PROFILE_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_MARKDOWN_ROOT = Path(__file__).with_name("markdown")


@dataclass(frozen=True, slots=True)
class FleetMarkdownProjectionMetadata:
    schema_version: int
    generation: int
    common_digest: str
    common_size: int
    provider_artifact_name: str
    provider_artifact_digest: str
    provider_artifact_size: int
    class_profile: str
    class_artifact_name: str


@dataclass(frozen=True, slots=True)
class FleetMarkdownProjection:
    artifacts: Mapping[str, bytes]
    metadata: FleetMarkdownProjectionMetadata


def _profile_name(profile: str) -> str:
    candidate = profile.strip().lower()
    if not _PROFILE_RE.fullmatch(candidate):
        return "generic"
    return candidate


def _class_body(profile: str) -> bytes:
    path = _MARKDOWN_ROOT / "classes" / f"{profile}.md"
    if path.is_file():
        return path.read_bytes()
    return (
        f"# Hive class profile: `{profile}`\n\n"
        "This profile has no additional class-specific policy yet. Follow the "
        "common Hive context and the assigned task scope.\n"
    ).encode("utf-8")


def fleet_markdown_projection(agent: AgentDescriptor) -> FleetMarkdownProjection:
    """Return one canonical provider projection and bounded marker metadata."""

    profile = _profile_name(agent.skill_profile)
    contract = load_common_policy()
    policy_projections = contract.project(profile)
    class_name = policy_projections.class_file_name
    if agent.runner is RunnerKind.GEMINI_CLI:
        provider_projection = policy_projections.gemini
        provider_artifact_name = ".gemini/GEMINI.md"
        class_artifact_name = f".gemini/{class_name}"
    else:
        provider_projection = policy_projections.codex
        provider_artifact_name = "AGENTS.md"
        class_artifact_name = class_name

    artifacts = MappingProxyType(
        {
            provider_artifact_name: provider_projection.artifact_bytes,
            class_artifact_name: _class_body(profile),
        }
    )
    return FleetMarkdownProjection(
        artifacts=artifacts,
        metadata=FleetMarkdownProjectionMetadata(
            schema_version=contract.schema_version,
            generation=contract.generation,
            common_digest=provider_projection.common_digest,
            common_size=len(provider_projection.common_bytes),
            provider_artifact_name=provider_artifact_name,
            provider_artifact_digest=provider_projection.artifact_digest,
            provider_artifact_size=len(provider_projection.artifact_bytes),
            class_profile=profile,
            class_artifact_name=class_artifact_name,
        ),
    )


def fleet_markdown_artifacts(agent: AgentDescriptor) -> dict[str, bytes]:
    """Return exactly the Markdown context files for one managed home."""

    return dict(fleet_markdown_projection(agent).artifacts)


def fleet_markdown_file_names(agent: AgentDescriptor) -> set[str]:
    return set(fleet_markdown_artifacts(agent))
