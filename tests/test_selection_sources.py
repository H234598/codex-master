from codex_master.selection.sources import AccountIdentityResolver, BeeSnapshot, SelectionSourceProvider


def test_account_identity_is_hmac_pseudonymous_and_usage_output_is_bounded() -> None:
    resolver = AccountIdentityResolver(b"s" * 32)
    first = resolver.resolve(agent_id="a1", routing={"account": "external-account"})
    second = resolver.resolve(agent_id="a2", routing={"account": "external-account"})
    assert first.account_key == second.account_key
    assert first.account_key.startswith("sha256:")
    provider = SelectionSourceProvider(lambda _ids: (BeeSnapshot("a1", first.account_key, "gpt-primary", True),), lambda _id: {"secret": "no", "fresh": True})
    assert provider.fleet_snapshot(("a1",))[0].agent_id == "a1"
    assert provider.usage_snapshot("a1") == {"schema_version": 1, "fresh": True, "raw_output": "not_returned"}
