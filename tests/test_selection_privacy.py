from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from codex_master.selection import (
    AdmissionMode,
    AdmissionPolicy,
    ModelRole,
    SelectionCandidate,
    SelectionError,
    SelectionPolicy,
    TaskKind,
    normalize_usage_observation,
    preview_selection_admission,
)
from codex_master.selection.model_policy import ModelPolicyError, load_model_policy
from codex_master.selection.sources import AccountIdentityResolver, SelectionSourceProvider


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def test_selection_preview_public_shape_does_not_contain_account_or_path_data() -> None:
    private_account_key = "sha256:" + "b" * 64
    candidate = SelectionCandidate(
        "agent-one", private_account_key, "gpt-primary", TaskKind.SIMPLE, ModelRole.PRIMARY,
    )
    result = preview_selection_admission(
        [candidate], selection_policy=SelectionPolicy(sp3=True),
        admission_policy=AdmissionPolicy(mode=AdmissionMode.SHADOW), now=NOW,
    )
    public = asdict(result)
    encoded = json.dumps(public)
    assert private_account_key not in encoded
    assert "path" not in encoded
    assert public["selection"]["selected"]["agent_id"] == "agent-one"


def test_usage_and_source_boundaries_drop_private_provider_fields() -> None:
    with pytest.raises(SelectionError, match="invalid_usage_payload"):
        normalize_usage_observation({
            "semantics": "remaining", "unit": "percent", "value": 100,
            "reset_kind": "rolling_unanchored", "confidence": "verified",
            "observed_at": "2026-08-06T11:59:00Z", "account_id": "private-account",
        })
    provider = SelectionSourceProvider(
        lambda _ids: (),
        lambda _id: {"fresh": True, "secret": "private-token", "prompt": "private prompt", "path": "/private"},
    )
    assert provider.usage_snapshot("agent-one") == {
        "schema_version": 1, "fresh": True, "raw_output": "not_returned",
    }


def test_account_identity_is_pseudonymous_and_invalid_external_data_fails_closed() -> None:
    resolver = AccountIdentityResolver(b"s" * 32)
    identity = resolver.resolve(agent_id="agent-one", routing={"account": "provider-account"})
    assert identity.account_key.startswith("sha256:")
    with pytest.raises(ValueError, match="account_identity_unavailable"):
        resolver.resolve(agent_id="agent-one", routing={"account": "private token"})


def test_model_policy_rejects_secret_and_private_extra_fields(tmp_path: Path) -> None:
    path = tmp_path / "model-policy.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "models": [{
            "model_id": "gpt-primary", "aliases": [], "role": "primary", "provider": "openai",
            "capabilities": [], "budget_key": "standard", "secret": "private-token",
        }],
    }), encoding="utf-8")
    with pytest.raises(ModelPolicyError, match="invalid_model_definition"):
        load_model_policy(path)


@pytest.mark.parametrize("payload", [None, [], {"schema_version": 1}, {"schema_version": 1, "models": []}])
def test_model_policy_invalid_json_shapes_fail_closed(payload: object, tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ModelPolicyError):
        load_model_policy(path)
