"""Pretty Google project names with separate monotone Hive references."""

from __future__ import annotations

from dataclasses import dataclass
import re
import secrets
from typing import Collection, Iterable


_ADJECTIVE_STEMS = (
    "Amber", "Azure", "Bright", "Calm", "Clear", "Cobalt", "Coral", "Cosmic",
    "Crimson", "Dawn", "Emerald", "Gentle", "Golden", "Happy", "Indigo", "Ivory",
    "Jade", "Kind", "Lilac", "Lively", "Lucid", "Lunar", "Mellow", "Misty",
    "Noble", "Quiet", "Radiant", "Silver", "Solar", "Sunny", "Swift", "Tender",
    "Velvet", "Verdant", "Violet", "Warm", "Wild", "Wise", "Witty", "Young",
)
_NOUN_STEMS = (
    "Aurora", "Badger", "Bay", "Birch", "Breeze", "Brook", "Cedar", "Cloud",
    "Comet", "Cove", "Dahlia", "Dawn", "Delta", "Dune", "Echo", "Falcon",
    "Fern", "Forest", "Grove", "Harbor", "Heron", "Hill", "Iris", "Island",
    "Juniper", "Lake", "Lark", "Maple", "Meadow", "Moon", "Nova", "Ocean",
    "Orchid", "Otter", "Pine", "River", "Robin", "Sage", "Sky", "Sparrow",
)
_ADJECTIVE_ENDINGS = (
    "bloom", "bright", "calm", "glow", "light", "mist", "song", "soft", "warm", "wise",
)
_NOUN_ENDINGS = (
    "bay", "brook", "cove", "field", "glen", "grove", "haven", "mead", "ridge", "wood",
)
_ADJECTIVES = tuple(
    stem + ending for stem in _ADJECTIVE_STEMS for ending in _ADJECTIVE_ENDINGS
)
_NOUNS = tuple(stem + ending for stem in _NOUN_STEMS for ending in _NOUN_ENDINGS)
_HIVE_REF = re.compile(r"the-hive-([1-9][0-9]*)\Z")


class GoogleProjectNamingError(ValueError):
    """Code-only naming failure."""


@dataclass(frozen=True, slots=True)
class GoogleProjectIdentity:
    project_name: str
    project_id: str


def generate_pretty_project_identity(
    *, visible_names: Collection[str], reserved_project_ids: Collection[str]
) -> GoogleProjectIdentity:
    """Generate unrelated display and technical identities without internal ordinals."""

    for _ in range(16_384):
        project_name = f"{secrets.choice(_ADJECTIVES)} {secrets.choice(_NOUNS)}"
        if len(project_name) > 30 or project_name in visible_names:
            continue
        slug = project_name.casefold().replace(" ", "-")[:23].rstrip("-")
        for _ in range(128):
            project_id = f"{slug}-{secrets.token_hex(3)}"
            if project_id not in reserved_project_ids:
                return GoogleProjectIdentity(project_name, project_id)
    raise GoogleProjectNamingError("project.naming_capacity_exhausted")


def next_hive_ref(existing_refs: Iterable[str]) -> str:
    maximum = 0
    for ref in existing_refs:
        if type(ref) is not str:
            raise GoogleProjectNamingError("project.naming_ref_invalid")
        match = _HIVE_REF.fullmatch(ref)
        if match is None:
            raise GoogleProjectNamingError("project.naming_ref_invalid")
        maximum = max(maximum, int(match.group(1)))
    return f"the-hive-{maximum + 1}"


def pretty_key_display_name(project_name: str) -> str:
    if type(project_name) is not str or re.fullmatch(
        r"[A-Za-z][A-Za-z' !-]{2,28}[A-Za-z]", project_name
    ) is None:
        raise GoogleProjectNamingError("project.naming_name_invalid")
    return f"{project_name} Key"
