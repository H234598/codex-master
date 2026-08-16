import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from codex_master.hive.decisions import (
    DecisionError,
    DecisionRecord,
    record_decision,
    supersede_decision,
    verify_decision_chain,
)
from codex_master.hive.principals import Principal


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64


def principal(principal_id: str, class_id: str, repo_id: str | None) -> Principal:
    return Principal(principal_id, class_id, None, "profile", "global" if repo_id is None else "repository", repo_id, "active", DIGEST, 1)


def decision(*, scope_kind: str = "global", repo_id: str | None = None, actor: str = "godbee-main") -> DecisionRecord:
    return DecisionRecord(
        "decision-one", scope_kind, repo_id, "scheduling policy", "accepted", ({"option_id": "a", "summary": "separate planes"},),
        "a", "Separate work and resource scheduling.", ("adr:0003",), actor, (actor,), NOW,
    )


ACTOR = principal("godbee-main", "gottbiene", None)
CHAIN_DIGEST = "sha256:" + "c" * 64


def stamped(
    decision_id: str,
    *,
    previous_record_hash: str | None = None,
    supersedes: str | None = None,
    options: tuple[Mapping[str, object], ...] | None = None,
) -> DecisionRecord:
    if options is None:
        options = ({"option_id": "a", "summary": "separate planes"},)
    return record_decision(
        DecisionRecord(
            decision_id,
            "global",
            None,
            "scheduling policy",
            "accepted",
            options,
            "a",
            "Separate work and resource scheduling.",
            ("adr:0003",),
            "godbee-main",
            ("godbee-main",),
            NOW,
            supersedes=supersedes,
            previous_record_hash=previous_record_hash,
        ),
        actor=ACTOR,
    )


def record_bytes(records: tuple[object, ...]) -> tuple[str, ...]:
    return tuple(
        json.dumps(record.public(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        if isinstance(record, DecisionRecord)
        else f"<{type(record).__name__}>"
        for record in records
    )


def registry_snapshot(
    registry: tuple[object, ...],
) -> tuple[tuple[object, ...], tuple[str, ...]]:
    values = tuple(registry)
    return values, record_bytes(values)


def assert_registry_unchanged(
    registry: tuple[object, ...],
    before: tuple[tuple[object, ...], tuple[str, ...]],
) -> None:
    before_values, before_bytes = before
    after_values = tuple(registry)
    assert after_values == before_values
    assert record_bytes(after_values) == before_bytes


def test_decision_is_authorized_hashed_and_chain_verifiable() -> None:
    stored = record_decision(decision(), actor=principal("godbee-main", "gottbiene", None))
    assert stored.record_hash is not None
    assert verify_decision_chain([stored])["valid"] is True
    tampered = DecisionRecord(
        stored.decision_id, stored.scope_kind, stored.repo_id, "tampered", stored.status, stored.options,
        stored.selected_option_id, stored.rationale, stored.evidence_refs, stored.created_by, stored.approved_by,
        stored.created_at_utc, stored.supersedes, stored.previous_record_hash, stored.record_hash,
    )
    assert verify_decision_chain([tampered])["valid"] is False


def test_repository_decision_requires_matching_queen_or_teamlead() -> None:
    stored = record_decision(
        decision(scope_kind="repository", repo_id="repo-one", actor="queen-one"),
        actor=principal("queen-one", "koenigin", "repo-one"),
    )
    assert stored.scope_kind == "repository"
    with pytest.raises(DecisionError, match="decision_scope_unauthorized"):
        record_decision(
            decision(scope_kind="repository", repo_id="repo-one", actor="specialist-one"),
            actor=principal("specialist-one", "spezialistin", "repo-one"),
        )


def test_decision_options_are_copied_and_immutable_before_record_hashing() -> None:
    source_option = {"option_id": "a", "summary": "separate planes"}
    stored = stamped("decision-immutable", options=(source_option,))

    source_option["summary"] = "forged-after-hash"

    assert stored.options[0]["summary"] == "separate planes"
    assert verify_decision_chain((stored,)) == {
        "valid": True,
        "record_count": 1,
        "reason_code": "decision_chain_verified",
    }
    with pytest.raises(TypeError):
        stored.options[0]["summary"] = "forged-directly"  # type: ignore[index]


def test_decision_mapping_key_insertion_does_not_change_equality_or_digest() -> None:
    first = stamped(
        "decision-equal",
        options=({"option_id": "a", "summary": "separate planes"},),
    )
    same_content = stamped(
        "decision-equal",
        options=({"summary": "separate planes", "option_id": "a"},),
    )

    assert first == same_content
    assert first.record_hash == same_content.record_hash


def test_decision_equality_and_record_hash_isolate_supersedes() -> None:
    without_supersedes = stamped(
        "decision-supersedes-isolation",
        previous_record_hash=CHAIN_DIGEST,
    )
    with_supersedes = stamped(
        "decision-supersedes-isolation",
        previous_record_hash=CHAIN_DIGEST,
        supersedes="decision-root",
    )

    assert replace(
        with_supersedes,
        supersedes=None,
        record_hash=without_supersedes.record_hash,
    ) == without_supersedes
    assert without_supersedes != replace(
        with_supersedes,
        record_hash=without_supersedes.record_hash,
    )
    assert without_supersedes != with_supersedes
    assert without_supersedes.record_hash != with_supersedes.record_hash


def test_decision_options_order_alone_changes_equality_and_digest() -> None:
    ordered_options = stamped(
        "decision-options-order",
        options=(
            {"option_id": "a", "summary": "separate planes"},
            {"option_id": "b", "summary": "split planes"},
        ),
    )
    reversed_options = stamped(
        "decision-options-order",
        options=(
            {"option_id": "b", "summary": "split planes"},
            {"option_id": "a", "summary": "separate planes"},
        ),
    )

    assert ordered_options != replace(
        reversed_options,
        record_hash=ordered_options.record_hash,
    )
    assert ordered_options != reversed_options
    assert ordered_options.record_hash != reversed_options.record_hash


def invalid_record() -> tuple[object, ...]:
    return (object(),)


def missing_target() -> tuple[object, ...]:
    return (stamped("decision-missing", supersedes="decision-absent"),)


def self_link() -> tuple[object, ...]:
    return (stamped("decision-self", supersedes="decision-self"),)


def duplicate_id() -> tuple[object, ...]:
    first = stamped("decision-duplicate")
    return (first, stamped("decision-duplicate", previous_record_hash=first.record_hash))


def forward_order() -> tuple[object, ...]:
    first = stamped("decision-forward", supersedes="decision-later")
    return (
        first,
        stamped("decision-later", previous_record_hash=first.record_hash),
    )


def cycle() -> tuple[object, ...]:
    first = stamped("decision-cycle-a", supersedes="decision-cycle-b")
    return (
        first,
        stamped(
            "decision-cycle-b",
            previous_record_hash=first.record_hash,
            supersedes="decision-cycle-a",
        ),
    )


def invalid_link_hash() -> tuple[object, ...]:
    root = stamped("decision-root")
    return (
        root,
        stamped(
            "decision-bad-link",
            previous_record_hash="sha256:" + "d" * 64,
            supersedes=root.decision_id,
        ),
    )


def assert_chain_rejected_without_registry_mutation(
    case: str,
    raw: object,
    reason_code: str,
) -> None:
    registry = () if raw is None else tuple(raw)  # type: ignore[arg-type]
    before = registry_snapshot(registry)

    result = verify_decision_chain(raw)  # type: ignore[arg-type]

    assert result == {
        "valid": False,
        "record_count": len(registry),
        "reason_code": reason_code,
    }, case
    assert_registry_unchanged(registry, before)
    if raw is not None:
        assert_registry_unchanged(tuple(raw), before)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("case", "factory", "reason_code"),
    (
        ("invalid", invalid_record, "duplicate_or_invalid_record"),
        ("duplicate", duplicate_id, "duplicate_or_invalid_record"),
        ("link_hash", invalid_link_hash, "decision_chain_mismatch"),
    ),
)
def test_decision_chain_baseline_rejects_shape_and_link_errors_without_mutation(
    case: str,
    factory: Callable[[], object],
    reason_code: str,
) -> None:
    assert_chain_rejected_without_registry_mutation(case, factory(), reason_code)


@pytest.mark.parametrize(
    ("case", "factory", "reason_code"),
    (
        ("type", lambda: None, "duplicate_or_invalid_record"),
        ("missing", missing_target, "decision_chain_mismatch"),
        ("self", self_link, "decision_chain_mismatch"),
        ("order", forward_order, "decision_chain_mismatch"),
        ("cycle", cycle, "decision_chain_mismatch"),
    ),
)
def test_decision_chain_rejects_new_input_and_supersede_errors_without_mutation(
    case: str,
    factory: Callable[[], object],
    reason_code: str,
) -> None:
    assert_chain_rejected_without_registry_mutation(
        case,
        factory(),
        reason_code,
    )


def replacement_record(
    decision_id: str,
    *,
    supersedes: str,
    previous_record_hash: str | None,
    options: tuple[Mapping[str, object], ...] | None = None,
) -> DecisionRecord:
    if options is None:
        options = ({"option_id": "a", "summary": "separate planes"},)
    return DecisionRecord(
        decision_id,
        "global",
        None,
        "scheduling policy",
        "accepted",
        options,
        "a",
        "Separate work and resource scheduling.",
        ("adr:0003",),
        "godbee-main",
        ("godbee-main",),
        NOW,
        supersedes=supersedes,
        previous_record_hash=previous_record_hash,
    )


def test_invalid_option_reject_leaves_registry_unchanged() -> None:
    root = stamped("decision-root")
    registry = (root,)
    before = registry_snapshot(registry)

    with pytest.raises(DecisionError, match="invalid_decision_option"):
        replacement_record(
            "decision-invalid-option",
            supersedes=root.decision_id,
            previous_record_hash=root.record_hash,
            options=(object(),),  # type: ignore[arg-type]
        )

    assert_registry_unchanged(registry, before)


def test_supersede_rejects_replacement_type_without_registry_mutation() -> None:
    root = stamped("decision-root")
    registry = (root,)
    before_registry = registry_snapshot(registry)
    supplied: object = object()
    before_supplied = registry_snapshot((supplied,))

    with pytest.raises(DecisionError, match="supersede_reference_mismatch"):
        supersede_decision(root.decision_id, supplied, actor=ACTOR)  # type: ignore[arg-type]

    assert_registry_unchanged(registry, before_registry)
    assert_registry_unchanged((supplied,), before_supplied)


@pytest.mark.parametrize(
    ("case", "replacement_factory"),
    (
        (
            "missing_link",
            lambda: replacement_record(
                "decision-replacement",
                supersedes="decision-root",
                previous_record_hash=None,
            ),
        ),
        (
            "duplicate_id",
            lambda: replacement_record(
                "decision-root",
                supersedes="decision-root",
                previous_record_hash=CHAIN_DIGEST,
            ),
        ),
    ),
)
def test_supersede_rejects_missing_link_or_duplicate_id_without_registry_mutation(
    case: str,
    replacement_factory: Callable[[], DecisionRecord],
) -> None:
    root = stamped("decision-root")
    registry = (root,)
    before_registry = registry_snapshot(registry)
    replacement = replacement_factory()
    before_replacement = registry_snapshot((replacement,))

    with pytest.raises(DecisionError, match="supersede_reference_mismatch"):
        supersede_decision(root.decision_id, replacement, actor=ACTOR)

    assert_registry_unchanged(registry, before_registry)
    assert_registry_unchanged((replacement,), before_replacement)


def test_supersede_preflight_is_valid_and_never_mutates_existing_records() -> None:
    root = stamped("decision-root")
    registry = (root,)
    before_registry = registry_snapshot(registry)
    candidate = supersede_decision(
        root.decision_id,
        DecisionRecord(
            "decision-replacement",
            "global",
            None,
            "scheduling policy",
            "accepted",
            ({"option_id": "a", "summary": "separate planes"},),
            "a",
            "Refined rationale.",
            ("adr:0004",),
            "godbee-main",
            ("godbee-main",),
            NOW,
            supersedes=root.decision_id,
            previous_record_hash=root.record_hash,
        ),
        actor=ACTOR,
    )
    prospective = (*registry, candidate)
    before_prospective = registry_snapshot(prospective)

    assert verify_decision_chain(prospective) == {
        "valid": True,
        "record_count": 2,
        "reason_code": "decision_chain_verified",
    }
    assert_registry_unchanged(registry, before_registry)
    assert_registry_unchanged(prospective, before_prospective)
    assert root.supersedes is None
