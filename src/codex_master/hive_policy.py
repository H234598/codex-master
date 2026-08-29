"""Pure Common Hive policy contract and provider projections."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path


COMMON_POLICY_PATH = Path(__file__).with_name("markdown") / "common.md"
MAX_COMMON_POLICY_BYTES = 64 * 1024

_HEADER_PREFIX = b"<!-- codex-master-common-policy:"
_HEADER_SUFFIX = b" -->"
_HEADER_FIELDS = {"generation", "schema_version"}
_PROFILE_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_ANNOTATION_FIXTURE_TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.md\Z")


class CommonPolicyError(ValueError):
    """The canonical Common Hive policy contract is unusable."""


@dataclass(frozen=True, slots=True)
class ProviderPolicyProjection:
    common_bytes: bytes
    common_digest: str
    artifact_bytes: bytes
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class CommonPolicyProjections:
    class_file_name: str
    codex: ProviderPolicyProjection
    gemini: ProviderPolicyProjection


@dataclass(frozen=True, slots=True)
class CommonPolicyContract:
    schema_version: int
    generation: int
    common_digest: str
    common_bytes: bytes

    def project(self, class_profile: str) -> CommonPolicyProjections:
        """Return complete Codex/Gemini common artifacts for one class reference."""

        if (
            not isinstance(class_profile, str)
            or _PROFILE_RE.fullmatch(class_profile) is None
        ):
            raise CommonPolicyError("common_policy_class_profile_invalid")
        class_file_name = f"AGENTS.class-{class_profile}.md"
        codex_bytes = self.common_bytes + (
            "\n\n## Active class profile\n\n"
            f"Read `./{class_file_name}` before acting. "
            "Only that class profile is active in this home.\n"
        ).encode("utf-8")
        gemini_bytes = self.common_bytes + (
            f"\n\n## Active class profile\n\n@./{class_file_name}\n"
        ).encode("utf-8")
        return CommonPolicyProjections(
            class_file_name=class_file_name,
            codex=_provider_projection(self, codex_bytes),
            gemini=_provider_projection(self, gemini_bytes),
        )


def _provider_projection(
    contract: CommonPolicyContract,
    artifact_bytes: bytes,
) -> ProviderPolicyProjection:
    return ProviderPolicyProjection(
        common_bytes=contract.common_bytes,
        common_digest=contract.common_digest,
        artifact_bytes=artifact_bytes,
        artifact_digest=hashlib.sha256(artifact_bytes).hexdigest(),
    )


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as policy_file:
            content = policy_file.read(MAX_COMMON_POLICY_BYTES + 1)
    except OSError as exc:
        raise CommonPolicyError("common_policy_unavailable") from exc
    if len(content) > MAX_COMMON_POLICY_BYTES:
        raise CommonPolicyError("common_policy_oversized")
    return content


def _parse_header(content: bytes) -> tuple[int, int]:
    first_newline = content.find(b"\n")
    if first_newline < 0:
        raise CommonPolicyError("common_policy_header_missing")
    header = content[:first_newline]
    if not header.startswith(_HEADER_PREFIX) or not header.endswith(_HEADER_SUFFIX):
        raise CommonPolicyError("common_policy_header_invalid")
    if content.count(_HEADER_PREFIX) != 1:
        raise CommonPolicyError("common_policy_header_duplicated")

    encoded_metadata = header[len(_HEADER_PREFIX) : -len(_HEADER_SUFFIX)]
    try:
        metadata = json.loads(encoded_metadata.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CommonPolicyError("common_policy_header_invalid") from None
    if not isinstance(metadata, dict) or set(metadata) != _HEADER_FIELDS:
        raise CommonPolicyError("common_policy_header_invalid")
    canonical_metadata = json.dumps(
        metadata,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if encoded_metadata != canonical_metadata:
        raise CommonPolicyError("common_policy_header_noncanonical")

    schema_version = metadata["schema_version"]
    generation = metadata["generation"]
    if type(schema_version) is not int or schema_version != 1:
        raise CommonPolicyError("common_policy_schema_unsupported")
    if type(generation) is not int or generation <= 0:
        raise CommonPolicyError("common_policy_generation_invalid")
    return schema_version, generation


def apply_annotation_response_fixture(
    document: str,
    *,
    annotation_id: str,
    answer_target: str,
    answer_heading: str,
    source_heading: str,
) -> str:
    """Apply the canonical annotation backlink to one strict Markdown fixture.

    This is deliberately a narrow conformance check, not a general Markdown
    parser. All fixture references are resolved before constructing the
    returned document so an invalid annotation cannot produce a partial update.
    """

    values = (annotation_id, answer_target, answer_heading, source_heading)
    if (
        not isinstance(document, str)
        or not document
        or any(not isinstance(value, str) for value in values)
        or _PROFILE_RE.fullmatch(annotation_id) is None
        or _ANNOTATION_FIXTURE_TARGET_RE.fullmatch(answer_target) is None
        or _PROFILE_RE.fullmatch(answer_heading) is None
        or _PROFILE_RE.fullmatch(source_heading) is None
        or re.search(r"^[ ]{0,3}(?:`{3,}|~{3,})", document, re.MULTILINE) is not None
    ):
        raise CommonPolicyError("annotation_response_fixture_invalid")

    annotation_pattern = re.compile(
        rf'<mark data-annotation-id="{re.escape(annotation_id)}">[^<]+</mark>'
    )
    annotations = list(annotation_pattern.finditer(document))
    if len(annotations) != 1:
        raise CommonPolicyError("annotation_response_annotation_id_unresolved")

    answer_chapter = f"## Antwort auf Freigabe — [{annotation_id}](#{source_heading})"
    chapter_headers = list(re.finditer(r"^## .+$", document, re.MULTILINE))
    source_headers = [
        header
        for header in chapter_headers
        if header.group()[3:].casefold() == source_heading.casefold()
    ]
    answer_headers = [
        header for header in chapter_headers if header.group() == answer_chapter
    ]
    if (
        len(source_headers) != 1
        or len(answer_headers) != 1
        or chapter_headers[-1] != answer_headers[0]
    ):
        raise CommonPolicyError("annotation_response_fixture_invalid")

    answer_section = document[answer_headers[0].start() :]
    answer_annotation_id = f'<!-- data-annotation-id="{annotation_id}" -->'
    if answer_section.count(answer_annotation_id) != 1:
        raise CommonPolicyError("annotation_response_fixture_invalid")

    backlink = f"[(A)]({answer_target}#{answer_heading})"
    annotation = annotations[0]
    direct_backlink = f" {backlink}"
    backlink_count = document.count(backlink)
    if backlink_count:
        if backlink_count != 1 or not document.startswith(
            direct_backlink, annotation.end()
        ):
            raise CommonPolicyError("annotation_response_fixture_invalid")
        updated = document
    else:
        updated = (
            document[: annotation.end()]
            + direct_backlink
            + document[annotation.end() :]
        )

    if updated.count("(A)") != 1 or updated.count(backlink) != 1:
        raise CommonPolicyError("annotation_response_fixture_invalid")
    return updated


def load_common_policy(path: str | Path = COMMON_POLICY_PATH) -> CommonPolicyContract:
    """Load the sole canonical policy with strict, bounded validation."""

    content = _read_bounded(Path(path))
    schema_version, generation = _parse_header(content)
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        raise CommonPolicyError("common_policy_encoding_invalid") from None
    return CommonPolicyContract(
        schema_version=schema_version,
        generation=generation,
        common_digest=hashlib.sha256(content).hexdigest(),
        common_bytes=content,
    )
