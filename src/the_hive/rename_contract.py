"""Deterministic TH-R1 rename contract and tracked-tree release validator."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from importlib.resources import files
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tomllib
from typing import Mapping, Sequence


_CONTRACT_SHA256 = "8bd4894672b3db2a494c4b23ec84cbc48eebcd11fe27ac3dd771f602964c396f"
_CONTRACT_FILE_NAME = "rename_contract.v1.json"
_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "canonical",
        "legacy_forms",
        "protected_terms",
        "cinnamon_surface",
        "bounded_families",
        "retirement_artifacts",
        "proven_product_aliases",
        "legacy_characterization",
        "target_readiness",
    }
)
_CANONICAL_KEYS = frozenset(
    {
        "display",
        "slug",
        "python",
        "environment",
        "desktop",
        "dbus_name",
        "dbus_path",
        "c_abi_prefix",
        "openmetrics_namespace",
        "compact_metrics",
        "repository",
        "principal",
        "mcp_name",
        "runtime_root",
        "runtime_manifest",
        "release_pointers",
        "release_publish_lock",
        "plugin",
        "skill",
        "manpage",
        "state_root",
        "github_repository",
        "checkout",
        "vault_project",
        "cinnamon_uuid",
    }
)
_LEGACY_FORM_IDENTIFIERS = frozenset({"display", "slug", "python", "environment", "compact"})
_CHARACTERIZATION_IDENTIFIERS = frozenset(
    {
        "distribution",
        "python_package",
        "cli_mcp",
        "mcp_manifest",
        "app_bridge",
        "runtime_layout",
        "state_interface",
        "c_abi",
        "metrics",
        "desktop",
        "unit",
        "plugin",
        "skill",
        "hook",
        "manpage",
        "error_surface",
        "dbus_api",
    }
)
_READINESS_IDENTIFIERS = frozenset(
    {
        "display",
        "slug",
        "mcp_name",
        "python",
        "environment",
        "desktop",
        "dbus_name",
        "dbus_path",
        "c_abi_prefix",
        "openmetrics_namespace",
        "compact_metrics",
        "repository",
        "principal",
        "github_repository",
        "plugin",
        "skill",
        "manpage",
        "runtime_root",
        "runtime_manifest",
        "release_pointers",
        "release_publish_lock",
        "state_root",
    }
)
_BOUNDED_FAMILY_IDENTIFIERS = frozenset(
    {"cli_entry_points", "systemd_artifacts", "hook_artifacts"}
)
_RETIREMENT_ARTIFACT_IDENTIFIERS = frozenset({"hive_test_index"})
_PROVEN_PRODUCT_ALIAS_IDENTIFIERS = frozenset(
    {"plugin_description_masterjet_alias", "plugin_long_description_masterjet_alias"}
)
_UNSAFE_GIT_ENVIRONMENT = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_OBJECT_DIRECTORY",
        "GIT_INDEX_FILE",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_COUNT",
    }
)


class RenameContractError(ValueError):
    """Raised when the single rename contract cannot be safely evaluated."""


@dataclass(frozen=True)
class LegacyForm:
    identifier: str
    parts: tuple[str, ...]
    separator: str

    @property
    def value(self) -> str:
        return self.separator.join(self.parts)

    @property
    def expression(self) -> re.Pattern[bytes]:
        value = re.escape(self.value.encode("ascii"))
        return re.compile(rb"(?<![A-Za-z0-9])" + value + rb"(?![A-Za-z0-9])", re.IGNORECASE)


@dataclass(frozen=True)
class SurfaceExpectation:
    identifier: str
    semantic_kind: str
    path_template: str
    form_identifiers: tuple[str, ...]
    legacy_value_templates: tuple[str, ...]
    target_path_template: str
    target_value_templates: tuple[str, ...]
    caller_locators: tuple["CallerLocator", ...]


@dataclass(frozen=True)
class TargetReadiness:
    identifier: str
    path_template: str
    target_identifier: str


@dataclass(frozen=True)
class CallerLocator:
    path_template: str
    symbol: str
    semantic_kind: str


@dataclass(frozen=True)
class BoundedFamily:
    identifier: str
    semantic_kind: str
    legacy_path_templates: tuple[str, ...]
    target_path_templates: tuple[str, ...]
    caller_path_template: str
    caller_symbol: str
    target_content_identifiers: tuple[str, ...]


@dataclass(frozen=True)
class CinnamonSurface:
    identifier: str
    legacy_path_prefix_template: str
    target_path_prefix_template: str
    member_count: int
    metadata_name: str
    metadata_field: tuple[str, ...]
    legacy_metadata_value_template: str
    target_metadata_value_template: str
    applet_name: str
    legacy_applet_value_template: str
    target_applet_value_template: str


@dataclass(frozen=True)
class RetirementArtifact:
    identifier: str
    path_template: str
    caller_path_template: str
    caller_symbol: str
    target_caller_path_template: str
    target_forbidden_symbol: str
    disposition: str
    generator_status: str


@dataclass(frozen=True)
class ProvenProductAlias:
    identifier: str
    path_template: str
    field: tuple[str, ...]
    legacy_phrase: str
    caller_symbol: str


@dataclass(frozen=True)
class RenameMatrix:
    schema_version: int
    canonical: Mapping[str, str]
    legacy_forms: Mapping[str, LegacyForm]
    protected_terms: tuple[str, ...]
    cinnamon_surface: CinnamonSurface
    bounded_families: tuple[BoundedFamily, ...]
    retirement_artifacts: tuple[RetirementArtifact, ...]
    proven_product_aliases: tuple[ProvenProductAlias, ...]
    legacy_characterization: tuple[SurfaceExpectation, ...]
    target_readiness: tuple[TargetReadiness, ...]

    def render_template(self, template: str) -> PurePosixPath:
        rendered = self.render_value(template)
        path = PurePosixPath(rendered)
        if path.is_absolute() or ".." in path.parts:
            raise RenameContractError("rename contract has an unsafe relative path")
        return path

    def render_value(self, template: str) -> str:
        values = {f"legacy_{key}": form.value for key, form in self.legacy_forms.items()}
        values.update({f"target_{key}": value for key, value in self.canonical.items()})
        try:
            return template.format_map(values)
        except (KeyError, ValueError) as error:
            raise RenameContractError("rename contract has an unknown template token") from error


@dataclass(frozen=True)
class GateFinding:
    location: str
    path: str
    form_identifier: str


@dataclass(frozen=True)
class CharacterizationFailure:
    surface_identifier: str
    reason: str


@dataclass(frozen=True)
class RenameGateReport:
    legacy_findings: tuple[GateFinding, ...]
    missing_target_identifiers: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.legacy_findings and not self.missing_target_identifiers


def load_rename_matrix() -> RenameMatrix:
    """Load and validate the sole machine-readable TH-R1 naming matrix."""

    resource = files("the_hive").joinpath(_CONTRACT_FILE_NAME)
    try:
        raw = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RenameContractError("rename contract is unreadable") from error
    return parse_rename_matrix(raw)


def parse_rename_matrix(raw: object) -> RenameMatrix:
    """Fail closed for any structural or value-level contract drift."""

    if not isinstance(raw, dict) or raw.get("schema_version") != 1 or set(raw) != _TOP_LEVEL_KEYS:
        raise RenameContractError("rename contract schema version is unsupported")
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != _CONTRACT_SHA256:
        raise RenameContractError("rename contract digest is not approved")

    canonical = raw.get("canonical")
    forms = raw.get("legacy_forms")
    characterization = raw.get("legacy_characterization")
    bounded_families = raw.get("bounded_families")
    retirement_artifacts = raw.get("retirement_artifacts")
    proven_product_aliases = raw.get("proven_product_aliases")
    readiness = raw.get("target_readiness")
    protected_terms = raw.get("protected_terms")
    if not all(
        isinstance(item, list)
        for item in (
            forms,
            bounded_families,
            retirement_artifacts,
            proven_product_aliases,
            characterization,
            readiness,
            protected_terms,
        )
    ):
        raise RenameContractError("rename contract collections are malformed")
    if not all(isinstance(term, str) and term for term in protected_terms):
        raise RenameContractError("rename contract protected terms are malformed")
    if not isinstance(canonical, dict) or not all(
        isinstance(key, str) and isinstance(value, str) and value for key, value in canonical.items()
    ) or set(canonical) != _CANONICAL_KEYS:
        raise RenameContractError("rename contract canonical values are malformed")

    parsed_forms: dict[str, LegacyForm] = {}
    for item in forms:
        if not isinstance(item, dict):
            raise RenameContractError("rename contract legacy form is malformed")
        identifier = item.get("id")
        parts = item.get("parts")
        separator = item.get("separator")
        if (
            not isinstance(identifier, str)
            or identifier in parsed_forms
            or not isinstance(parts, list)
            or not parts
            or not all(isinstance(part, str) and part for part in parts)
            or not isinstance(separator, str)
        ):
            raise RenameContractError("rename contract legacy form is malformed")
        parsed_forms[identifier] = LegacyForm(identifier, tuple(parts), separator)
    if set(parsed_forms) != _LEGACY_FORM_IDENTIFIERS:
        raise RenameContractError("rename contract legacy forms are incomplete")

    def parse_expectations(items: Sequence[object]) -> tuple[SurfaceExpectation, ...]:
        parsed: list[SurfaceExpectation] = []
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict) or set(item) != {
                "id",
                "kind",
                "path",
                "forms",
                "legacy_values",
                "target_path",
                "target_values",
                "callers",
            }:
                raise RenameContractError("rename contract characterization is malformed")
            identifier = item.get("id")
            kind = item.get("kind")
            path = item.get("path")
            form_identifiers = item.get("forms")
            legacy_values = item.get("legacy_values")
            target_path = item.get("target_path")
            target_values = item.get("target_values")
            callers = item.get("callers")
            if (
                not isinstance(identifier, str)
                or identifier in seen
                or not isinstance(kind, str)
                or not kind
                or not isinstance(path, str)
                or not isinstance(form_identifiers, list)
                or not form_identifiers
                or not all(isinstance(form, str) and form in parsed_forms for form in form_identifiers)
                or not isinstance(legacy_values, list)
                or not legacy_values
                or not all(isinstance(value, str) and value for value in legacy_values)
                or not isinstance(target_path, str)
                or not isinstance(target_values, list)
                or not target_values
                or not all(isinstance(value, str) and value for value in target_values)
                or not isinstance(callers, list)
                or not callers
                or not all(
                    isinstance(caller, dict)
                    and set(caller) == {"path", "symbol", "kind"}
                    and isinstance(caller.get("path"), str)
                    and isinstance(caller.get("symbol"), str)
                    and caller.get("symbol")
                    and isinstance(caller.get("kind"), str)
                    and caller.get("kind")
                    for caller in callers
                )
            ):
                raise RenameContractError("rename contract characterization is malformed")
            seen.add(identifier)
            parsed.append(
                SurfaceExpectation(
                    identifier,
                    kind,
                    path,
                    tuple(form_identifiers),
                    tuple(legacy_values),
                    target_path,
                    tuple(target_values),
                    tuple(
                        CallerLocator(caller["path"], caller["symbol"], caller["kind"])
                        for caller in callers
                    ),
                )
            )
        return tuple(parsed)

    parsed_characterization = parse_expectations(characterization)
    if {entry.identifier for entry in parsed_characterization} != _CHARACTERIZATION_IDENTIFIERS:
        raise RenameContractError("rename contract characterization is incomplete")

    cinnamon = raw.get("cinnamon_surface")
    if (
        not isinstance(cinnamon, dict)
        or set(cinnamon) != {
            "id",
            "legacy_path_prefix",
            "target_path_prefix",
            "member_count",
            "metadata_name",
            "metadata_field",
            "legacy_metadata_value",
            "target_metadata_value",
            "applet_name",
            "legacy_applet_value",
            "target_applet_value",
        }
        or cinnamon.get("id") != "cinnamon_uuid"
        or not isinstance(cinnamon.get("legacy_path_prefix"), str)
        or not isinstance(cinnamon.get("target_path_prefix"), str)
        or not isinstance(cinnamon.get("member_count"), int)
        or cinnamon.get("member_count") != 28
        or not isinstance(cinnamon.get("metadata_name"), str)
        or not isinstance(cinnamon.get("metadata_field"), list)
        or not cinnamon["metadata_field"]
        or not all(isinstance(part, str) and part for part in cinnamon["metadata_field"])
        or not isinstance(cinnamon.get("legacy_metadata_value"), str)
        or not isinstance(cinnamon.get("target_metadata_value"), str)
        or not isinstance(cinnamon.get("applet_name"), str)
        or not isinstance(cinnamon.get("legacy_applet_value"), str)
        or not isinstance(cinnamon.get("target_applet_value"), str)
    ):
        raise RenameContractError("rename contract Cinnamon surface is malformed")
    metadata_name = PurePosixPath(cinnamon["metadata_name"])
    applet_name = PurePosixPath(cinnamon["applet_name"])
    if (
        metadata_name.is_absolute()
        or applet_name.is_absolute()
        or len(metadata_name.parts) != 1
        or len(applet_name.parts) != 1
        or metadata_name.name != cinnamon["metadata_name"]
        or applet_name.name != cinnamon["applet_name"]
    ):
        raise RenameContractError("rename contract Cinnamon member path is malformed")
    parsed_cinnamon = CinnamonSurface(
        cinnamon["id"],
        cinnamon["legacy_path_prefix"],
        cinnamon["target_path_prefix"],
        cinnamon["member_count"],
        cinnamon["metadata_name"],
        tuple(cinnamon["metadata_field"]),
        cinnamon["legacy_metadata_value"],
        cinnamon["target_metadata_value"],
        cinnamon["applet_name"],
        cinnamon["legacy_applet_value"],
        cinnamon["target_applet_value"],
    )

    parsed_families: list[BoundedFamily] = []
    seen_families: set[str] = set()
    for item in bounded_families:
        if not isinstance(item, dict) or set(item) != {
            "id", "kind", "legacy_paths", "target_paths", "caller_path", "caller_symbol", "target_content_forms"
        }:
            raise RenameContractError("rename contract bounded family is malformed")
        identifier = item.get("id")
        kind = item.get("kind")
        legacy_paths = item.get("legacy_paths")
        target_paths = item.get("target_paths")
        caller_path = item.get("caller_path")
        caller_symbol = item.get("caller_symbol")
        target_content_forms = item.get("target_content_forms")
        if (
            not isinstance(identifier, str)
            or identifier in seen_families
            or not isinstance(kind, str)
            or not kind
            or not isinstance(legacy_paths, list)
            or not legacy_paths
            or not all(isinstance(path, str) and path for path in legacy_paths)
            or not isinstance(target_paths, list)
            or len(legacy_paths) != len(target_paths)
            or not all(isinstance(path, str) and path for path in target_paths)
            or not isinstance(caller_path, str)
            or not isinstance(caller_symbol, str)
            or not caller_symbol
            or not isinstance(target_content_forms, list)
            or not all(isinstance(form, str) and form in canonical for form in target_content_forms)
            or (not target_content_forms and identifier != "hook_artifacts")
        ):
            raise RenameContractError("rename contract bounded family is malformed")
        seen_families.add(identifier)
        parsed_families.append(
            BoundedFamily(
                identifier,
                kind,
                tuple(legacy_paths),
                tuple(target_paths),
                caller_path,
                caller_symbol,
                tuple(target_content_forms),
            )
        )
    if {family.identifier for family in parsed_families} != _BOUNDED_FAMILY_IDENTIFIERS:
        raise RenameContractError("rename contract bounded families are incomplete")

    parsed_retirements: list[RetirementArtifact] = []
    seen_retirements: set[str] = set()
    for item in retirement_artifacts:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "path",
            "caller_path",
            "caller_symbol",
            "target_caller_path",
            "target_forbidden_symbol",
            "disposition",
            "generator_status",
        }:
            raise RenameContractError("rename contract retirement artifact is malformed")
        identifier = item.get("id")
        path = item.get("path")
        caller_path = item.get("caller_path")
        caller_symbol = item.get("caller_symbol")
        target_caller_path = item.get("target_caller_path")
        target_forbidden_symbol = item.get("target_forbidden_symbol")
        disposition = item.get("disposition")
        generator_status = item.get("generator_status")
        if (
            not isinstance(identifier, str)
            or identifier in seen_retirements
            or not isinstance(path, str)
            or not isinstance(caller_path, str)
            or not isinstance(caller_symbol, str)
            or not caller_symbol
            or not isinstance(target_caller_path, str)
            or not isinstance(target_forbidden_symbol, str)
            or not target_forbidden_symbol
            or disposition != "remove_from_product_tree_only"
            or generator_status != "no_production_generator_attested"
        ):
            raise RenameContractError("rename contract retirement artifact is malformed")
        seen_retirements.add(identifier)
        parsed_retirements.append(
            RetirementArtifact(
                identifier,
                path,
                caller_path,
                caller_symbol,
                target_caller_path,
                target_forbidden_symbol,
                disposition,
                generator_status,
            )
        )
    if {artifact.identifier for artifact in parsed_retirements} != _RETIREMENT_ARTIFACT_IDENTIFIERS:
        raise RenameContractError("rename contract retirement artifacts are incomplete")

    parsed_aliases: list[ProvenProductAlias] = []
    seen_aliases: set[str] = set()
    for item in proven_product_aliases:
        if not isinstance(item, dict) or set(item) != {"id", "path", "field", "legacy_phrase", "caller_symbol"}:
            raise RenameContractError("rename contract proven alias is malformed")
        identifier = item.get("id")
        path = item.get("path")
        field = item.get("field")
        phrase = item.get("legacy_phrase")
        caller_symbol = item.get("caller_symbol")
        if (
            not isinstance(identifier, str)
            or identifier in seen_aliases
            or not isinstance(path, str)
            or not isinstance(field, list)
            or not field
            or not all(isinstance(part, str) and part for part in field)
            or not isinstance(phrase, str)
            or not phrase
            or not isinstance(caller_symbol, str)
            or not caller_symbol
        ):
            raise RenameContractError("rename contract proven alias is malformed")
        seen_aliases.add(identifier)
        parsed_aliases.append(ProvenProductAlias(identifier, path, tuple(field), phrase, caller_symbol))
    if {alias.identifier for alias in parsed_aliases} != _PROVEN_PRODUCT_ALIAS_IDENTIFIERS:
        raise RenameContractError("rename contract proven aliases are incomplete")

    parsed_readiness: list[TargetReadiness] = []
    seen_readiness: set[str] = set()
    for item in readiness:
        if not isinstance(item, dict):
            raise RenameContractError("rename contract target readiness is malformed")
        identifier = item.get("id")
        path = item.get("path")
        target = item.get("target")
        if (
            not isinstance(identifier, str)
            or identifier in seen_readiness
            or not isinstance(path, str)
            or not isinstance(target, str)
            or target not in canonical
        ):
            raise RenameContractError("rename contract target readiness is malformed")
        seen_readiness.add(identifier)
        parsed_readiness.append(TargetReadiness(identifier, path, target))
    if {entry.identifier for entry in parsed_readiness} != _READINESS_IDENTIFIERS:
        raise RenameContractError("rename contract target readiness is incomplete")

    matrix = RenameMatrix(
        schema_version=1,
        canonical=dict(canonical),
        legacy_forms=parsed_forms,
        protected_terms=tuple(protected_terms),
        cinnamon_surface=parsed_cinnamon,
        bounded_families=tuple(parsed_families),
        retirement_artifacts=tuple(parsed_retirements),
        proven_product_aliases=tuple(parsed_aliases),
        legacy_characterization=parsed_characterization,
        target_readiness=tuple(parsed_readiness),
    )
    for expectation in matrix.legacy_characterization:
        matrix.render_template(expectation.path_template)
        matrix.render_template(expectation.target_path_template)
        for template in expectation.legacy_value_templates + expectation.target_value_templates:
            matrix.render_value(template)
        for caller in expectation.caller_locators:
            if not caller.path_template.startswith("external:"):
                matrix.render_template(caller.path_template)
            matrix.render_value(caller.symbol)
    for family in matrix.bounded_families:
        if not family.caller_path_template.startswith("external:"):
            matrix.render_template(family.caller_path_template)
        for template in family.legacy_path_templates + family.target_path_templates:
            matrix.render_template(template)
    for artifact in matrix.retirement_artifacts:
        matrix.render_template(artifact.path_template)
        matrix.render_template(artifact.caller_path_template)
        matrix.render_template(artifact.target_caller_path_template)
    for alias in matrix.proven_product_aliases:
        matrix.render_template(alias.path_template)
    cinnamon = matrix.cinnamon_surface
    matrix.render_template(cinnamon.legacy_path_prefix_template + "/placeholder")
    matrix.render_template(cinnamon.target_path_prefix_template + "/placeholder")
    for template in (
        cinnamon.legacy_metadata_value_template,
        cinnamon.target_metadata_value_template,
        cinnamon.legacy_applet_value_template,
        cinnamon.target_applet_value_template,
    ):
        matrix.render_value(template)
    for readiness_entry in matrix.target_readiness:
        matrix.render_template(readiness_entry.path_template)
    return matrix


class RenameReleaseValidator:
    """Validate one Git tree against the sole TH-R1 rename matrix."""

    def __init__(self, matrix: RenameMatrix | None = None) -> None:
        self.matrix = matrix or load_rename_matrix()

    def characterize_legacy_surfaces(
        self, repository_root: Path, treeish: str = "HEAD"
    ) -> tuple[CharacterizationFailure, ...]:
        """Pin the current legacy interfaces from one explicit Git tree."""

        blobs = self._tracked_blobs(repository_root, treeish)
        matrix = self._matrix_from_tracked_blobs(blobs)
        paths_to_blobs = {path: content for path, content in blobs}
        failures: list[CharacterizationFailure] = []
        for expectation in matrix.legacy_characterization:
            relative_path = matrix.render_template(expectation.path_template).as_posix()
            content = paths_to_blobs.get(relative_path)
            if content is None:
                failures.append(CharacterizationFailure(expectation.identifier, "missing_path"))
                continue
            if not self._semantic_surface_is_valid(matrix, expectation, relative_path, content, target=False):
                failures.append(CharacterizationFailure(expectation.identifier, "invalid_structured_surface"))
                continue
            path_bytes = relative_path.encode("utf-8")
            for form_identifier in expectation.form_identifiers:
                expression = matrix.legacy_forms[form_identifier].expression
                if not expression.search(path_bytes) and not expression.search(content):
                    failures.append(CharacterizationFailure(expectation.identifier, "missing_legacy_form"))
                    break
            else:
                if any(
                    matrix.render_value(template).casefold().encode("utf-8") not in content.lower()
                    for template in expectation.legacy_value_templates
                ):
                    failures.append(CharacterizationFailure(expectation.identifier, "missing_legacy_value"))
            for caller in expectation.caller_locators:
                if caller.path_template.startswith("external:"):
                    continue
                caller_path = matrix.render_template(caller.path_template).as_posix()
                caller_content = paths_to_blobs.get(caller_path)
                if (
                    caller_content is None
                    or matrix.render_value(caller.symbol).encode("utf-8") not in caller_content
                ):
                    failures.append(CharacterizationFailure(expectation.identifier, "missing_caller_locator"))
                    break
        for family in matrix.bounded_families:
            legacy_paths = tuple(matrix.render_template(path).as_posix() for path in family.legacy_path_templates)
            caller_path = family.caller_path_template
            caller_content = None
            if not caller_path.startswith("external:"):
                caller_content = paths_to_blobs.get(matrix.render_template(caller_path).as_posix())
            caller_is_present = caller_path.startswith("external:") or caller_content is not None
            if (
                not caller_is_present
                or any(path not in paths_to_blobs for path in legacy_paths)
                or any(
                    not self._family_member_is_structurally_valid(family.semantic_kind, path, paths_to_blobs[path])
                    for path in legacy_paths
                )
            ):
                failures.append(CharacterizationFailure(family.identifier, "missing_family_member"))
            elif caller_content is not None and matrix.render_value(family.caller_symbol).encode("utf-8") not in caller_content:
                failures.append(CharacterizationFailure(family.identifier, "missing_family_caller"))
        for artifact in matrix.retirement_artifacts:
            path = matrix.render_template(artifact.path_template).as_posix()
            caller_path = matrix.render_template(artifact.caller_path_template).as_posix()
            caller_content = paths_to_blobs.get(caller_path)
            if (
                path not in paths_to_blobs
                or caller_content is None
                or matrix.render_value(artifact.caller_symbol).encode("utf-8") not in caller_content
            ):
                failures.append(CharacterizationFailure(artifact.identifier, "missing_retirement_artifact_provenance"))
        for alias in matrix.proven_product_aliases:
            path = matrix.render_template(alias.path_template).as_posix()
            value = self._json_field(paths_to_blobs.get(path), alias.field)
            if not self._alias_phrase_is_present(value, alias.legacy_phrase):
                failures.append(CharacterizationFailure(alias.identifier, "missing_alias_provenance"))
        cinnamon = matrix.cinnamon_surface
        legacy_prefix = matrix.render_template(cinnamon.legacy_path_prefix_template + "/placeholder").parent.as_posix()
        legacy_metadata = f"{legacy_prefix}/{cinnamon.metadata_name}"
        legacy_applet = f"{legacy_prefix}/{cinnamon.applet_name}"
        if sum(path.startswith(legacy_prefix + "/") for path in paths_to_blobs) != cinnamon.member_count:
            failures.append(CharacterizationFailure(cinnamon.identifier, "legacy_member_count_drift"))
        elif self._json_field(paths_to_blobs.get(legacy_metadata), cinnamon.metadata_field) != matrix.render_value(
            cinnamon.legacy_metadata_value_template
        ):
            failures.append(CharacterizationFailure(cinnamon.identifier, "legacy_metadata_uuid_drift"))
        elif matrix.render_value(cinnamon.legacy_applet_value_template).encode("utf-8") not in paths_to_blobs.get(
            legacy_applet, b""
        ):
            failures.append(CharacterizationFailure(cinnamon.identifier, "legacy_applet_uuid_drift"))
        return tuple(failures)

    def validate_tree(self, repository_root: Path, treeish: str = "HEAD") -> RenameGateReport:
        """Inspect only tracked paths and raw blobs from a deterministic Git tree."""

        blobs = self._tracked_blobs(repository_root, treeish)
        matrix = self._matrix_from_tracked_blobs(blobs)
        paths_to_blobs = {path: content for path, content in blobs}
        findings: list[GateFinding] = []
        for path, content in paths_to_blobs.items():
            path_bytes = path.encode("utf-8", "surrogateescape")
            for form in matrix.legacy_forms.values():
                if form.expression.search(path_bytes):
                    findings.append(GateFinding("path", path, form.identifier))
                if form.expression.search(content):
                    findings.append(GateFinding("content", path, form.identifier))

        missing_targets: list[str] = []
        for family in matrix.bounded_families:
            target_paths = tuple(matrix.render_template(path).as_posix() for path in family.target_path_templates)
            target_markers = tuple(matrix.canonical[identifier].encode("utf-8") for identifier in family.target_content_identifiers)
            if any(
                path not in paths_to_blobs
                or (target_markers and not any(marker in paths_to_blobs[path] for marker in target_markers))
                or not self._family_member_is_structurally_valid(family.semantic_kind, path, paths_to_blobs[path])
                for path in target_paths
            ):
                missing_targets.append(f"family:{family.identifier}")
        for artifact in matrix.retirement_artifacts:
            target_caller = paths_to_blobs.get(matrix.render_template(artifact.target_caller_path_template).as_posix())
            if (
                matrix.render_template(artifact.path_template).as_posix() in paths_to_blobs
                or target_caller is None
                or matrix.render_value(artifact.target_forbidden_symbol).encode("utf-8") in target_caller
            ):
                missing_targets.append(f"retire:{artifact.identifier}")
        for alias in matrix.proven_product_aliases:
            path = matrix.render_template(alias.path_template).as_posix()
            if self._alias_phrase_is_present(self._json_field(paths_to_blobs.get(path), alias.field), alias.legacy_phrase):
                missing_targets.append(f"alias:{alias.identifier}")
        cinnamon = matrix.cinnamon_surface
        target_prefix = matrix.render_template(cinnamon.target_path_prefix_template + "/placeholder").parent.as_posix()
        target_metadata = f"{target_prefix}/{cinnamon.metadata_name}"
        target_applet = f"{target_prefix}/{cinnamon.applet_name}"
        if (
            sum(path.startswith(target_prefix + "/") for path in paths_to_blobs) != cinnamon.member_count
            or self._json_field(paths_to_blobs.get(target_metadata), cinnamon.metadata_field)
            != matrix.render_value(cinnamon.target_metadata_value_template)
            or matrix.render_value(cinnamon.target_applet_value_template).encode("utf-8")
            not in paths_to_blobs.get(target_applet, b"")
        ):
            missing_targets.append(cinnamon.identifier)
        for expectation in matrix.legacy_characterization:
            target_path = matrix.render_template(expectation.target_path_template).as_posix()
            content = paths_to_blobs.get(target_path)
            if content is None or not self._semantic_surface_is_valid(
                matrix, expectation, target_path, content, target=True
            ) or any(
                matrix.render_value(template).encode("utf-8") not in content
                for template in expectation.target_value_templates
            ):
                missing_targets.append(f"surface:{expectation.identifier}")
        for readiness in matrix.target_readiness:
            target_path = matrix.render_template(readiness.path_template).as_posix()
            content = paths_to_blobs.get(target_path)
            target = matrix.canonical[readiness.target_identifier].encode("utf-8")
            if content is None or (
                target not in target_path.encode("utf-8", "surrogateescape") and target not in content
            ):
                missing_targets.append(readiness.identifier)

        findings.sort(key=lambda finding: (finding.location, finding.path, finding.form_identifier))
        return RenameGateReport(tuple(findings), tuple(sorted(missing_targets)))

    @staticmethod
    def _family_member_is_structurally_valid(kind: str, path: str, content: bytes) -> bool:
        if not content:
            return False
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return False
        if kind == "tracked_cli_path_set":
            return text.startswith("#!")
        if kind == "tracked_plugin_hook_path_set":
            if path.endswith("hooks.json"):
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    return False
                return isinstance(data, dict) and isinstance(data.get("hooks"), dict)
            try:
                ast.parse(text, filename=path)
            except SyntaxError:
                return False
            return True
        if kind == "tracked_systemd_unit_config_path_set":
            if path.endswith(".json"):
                try:
                    return isinstance(json.loads(text), dict)
                except json.JSONDecodeError:
                    return False
            if path.endswith(".service"):
                return "[Unit]" in text and "[Service]" in text
            if path.endswith(".timer"):
                return "[Unit]" in text and "[Timer]" in text
            if path.endswith(".slice"):
                return "[Unit]" in text
            if path.endswith(".te"):
                return "policy_module(" in text
            if path.endswith(".fc"):
                return "gen_context(" in text
            if "/libexec/" in path:
                if path.endswith(".py"):
                    try:
                        ast.parse(text, filename=path)
                    except SyntaxError:
                        return False
                    return True
                return text.startswith("#!")
            if "/sysusers.d/" in path:
                return any(line.startswith(("g ", "u ", "m ")) for line in text.splitlines())
            if "/tmpfiles.d/" in path:
                return any(line.startswith(("d ", "D ", "f ")) for line in text.splitlines())
            return bool(text.strip())
        return False

    @staticmethod
    def _semantic_surface_is_valid(
        matrix: RenameMatrix, expectation: SurfaceExpectation, path: str, content: bytes, *, target: bool
    ) -> bool:
        try:
            data: object
            if path.endswith(".json"):
                data = json.loads(content.decode("utf-8"))
            elif path == "pyproject.toml":
                data = tomllib.loads(content.decode("utf-8"))
            else:
                return True
        except (UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError):
            return False
        if not isinstance(data, dict):
            return False
        legacy = {key: form.value for key, form in matrix.legacy_forms.items()}
        canonical = matrix.canonical
        values = canonical if target else legacy
        if expectation.semantic_kind == "packaging_entry_points":
            project = data.get("project")
            scripts = project.get("scripts") if isinstance(project, dict) else None
            if not isinstance(scripts, dict) or not isinstance(project, dict):
                return False
            prefix = values["slug"]
            python_name = values["python"]
            return project.get("name") == prefix and all(
                scripts.get(name) == value
                for name, value in {
                    f"{prefix}-mcp": f"{python_name}.server:main",
                    f"{prefix}-admin": f"{python_name}.admin_daemon:main",
                    f"{prefix}-agent-api": f"{python_name}.agent_daemon:main",
                    f"{prefix}-host-agent": f"{python_name}.host_agent:main",
                    "google-account-manager": f"{python_name}.google_account_manager_cli:main",
                }.items()
            )
        if expectation.semantic_kind == "mcp_manifest":
            servers = data.get("mcpServers")
            mcp_name = canonical["mcp_name"] if target else f"{legacy['slug']}-mcp"
            runtime_root = canonical["runtime_root"] if target else f"{legacy['slug']}-runtime"
            server = servers.get(mcp_name) if isinstance(servers, dict) else None
            return isinstance(server, dict) and server.get("command") == (
                f"/home/teladi/.local/lib/{runtime_root}/{mcp_name}"
            )
        if expectation.semantic_kind == "app_bridge_manifest":
            apps = data.get("apps")
            app_name = canonical["slug"] if target else legacy["slug"]
            return isinstance(apps, dict) and isinstance(apps.get(app_name), dict)
        if expectation.semantic_kind == "plugin_manifest":
            slug = canonical["slug"] if target else legacy["slug"]
            plugin = canonical["plugin"] if target else legacy["slug"]
            repository = canonical["github_repository"] if target else f"H234598/{slug}"
            interface = data.get("interface")
            return (
                data.get("name") == plugin
                and data.get("homepage") == f"https://github.com/{repository}"
                and data.get("repository") == f"https://github.com/{repository}"
                and data.get("skills") == "./skills/"
                and data.get("mcpServers") == "./.mcp.json"
                and data.get("apps") == "./.app.json"
                and data.get("hooks") == "./hooks/hooks.json"
                and isinstance(interface, dict)
                and interface.get("displayName") == canonical["display"]
            )
        return True

    @staticmethod
    def _json_field(content: bytes | None, field: Sequence[str]) -> object:
        if content is None:
            return None
        try:
            value: object = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        for part in field:
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value

    @staticmethod
    def _alias_phrase_is_present(value: object, phrase: str) -> bool:
        return isinstance(value, str) and phrase.casefold() in value.casefold()

    @staticmethod
    def _matrix_from_tracked_blobs(blobs: Sequence[tuple[str, bytes]]) -> RenameMatrix:
        candidates = [(path, content) for path, content in blobs if PurePosixPath(path).name == _CONTRACT_FILE_NAME]
        if len(candidates) != 1:
            raise RenameContractError("Git tree must contain exactly one rename contract")
        try:
            path, content = candidates[0]
            raw = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RenameContractError("tracked rename contract is unreadable") from error
        matrix = parse_rename_matrix(raw)
        expected_path = f"src/{matrix.canonical['python']}/{_CONTRACT_FILE_NAME}"
        if path != expected_path:
            raise RenameContractError("tracked rename contract is not packaged at the target path")
        return matrix

    @staticmethod
    def _tracked_blobs(repository_root: Path, treeish: str) -> tuple[tuple[str, bytes], ...]:
        root = repository_root.resolve()
        top_level = RenameReleaseValidator._git(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"]
        ).decode("utf-8", "surrogateescape").strip()
        if Path(top_level).resolve() != root:
            raise RenameContractError("repository root must be the Git top level")
        tree = RenameReleaseValidator._git(
            ["git", "-C", str(root), "rev-parse", "--verify", "--end-of-options", f"{treeish}^{{tree}}"]
        ).decode("ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", tree):
            raise RenameContractError("treeish does not resolve to a local Git tree")
        command = ["git", "-C", str(root), "ls-tree", "-rz", "--full-tree", "-r", "--", tree]
        listing = RenameReleaseValidator._git(command)
        blobs: list[tuple[str, bytes]] = []
        for record in listing.split(b"\0"):
            if not record:
                continue
            try:
                header, raw_path = record.split(b"\t", 1)
                _mode, object_type, object_id = header.split(b" ", 2)
            except ValueError as error:
                raise RenameContractError("Git tree entry is malformed") from error
            if object_type != b"blob":
                continue
            path = raw_path.decode("utf-8", "surrogateescape")
            blob = RenameReleaseValidator._git(
                ["git", "-C", str(repository_root), "cat-file", "blob", object_id.decode("ascii")]
            )
            blobs.append((path, blob))
        return tuple(blobs)

    @staticmethod
    def _git(command: Sequence[str]) -> bytes:
        if any(
            key in _UNSAFE_GIT_ENVIRONMENT
            or key.startswith("GIT_CONFIG_")
            for key in os.environ
        ):
            raise RenameContractError("Git environment is not permitted for rename validation")
        completed = subprocess.run(
            command,
            check=False,
            env={
                "PATH": os.defpath,
                "LANG": "C",
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if completed.returncode != 0:
            raise RenameContractError("tracked tree cannot be read")
        return completed.stdout
