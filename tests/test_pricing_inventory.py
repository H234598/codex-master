from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from codex_master import pricing_inventory


MODEL = "gpt-5.6-sol"


def _catalog(*, tiers: list[str]) -> dict[str, object]:
    return {
        "fetched_at": datetime.now(UTC).isoformat(),
        "client_version": "test-client",
        "models": [
            {
                "slug": MODEL,
                "service_tiers": [{"id": tier, "name": tier.title()} for tier in tiers],
                "additional_speed_tiers": ["fast"],
                "supported_in_api": True,
            }
        ],
    }


def _write_codex_home(codex: Path, *, tiers: list[str]) -> Path:
    codex.mkdir(parents=True)
    (codex / "models_cache.json").write_text(
        json.dumps(_catalog(tiers=tiers)), encoding="utf-8"
    )
    config = codex / "config.toml"
    config.write_text('model = "gpt-5.6-sol"\nservice_tier = "auto"\n', encoding="utf-8")
    return config


def _write_home(home: Path, *, tiers: list[str]) -> Path:
    return _write_codex_home(home / ".codex", tiers=tiers)


def _stub_external_sources(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pricing: str,
    models: str = MODEL,
    api_models: list[str] | None = None,
) -> None:
    api_models = [MODEL] if api_models is None else api_models

    def fake_fetch(url: str, *, headers: dict[str, str] | None = None) -> tuple[str, str]:
        del headers
        if url == pricing_inventory.PRICING_URL:
            return "utf-8", pricing
        if url == pricing_inventory.MODELS_URL:
            return "utf-8", models
        if url == "https://api.openai.com/v1/models":
            return "utf-8", json.dumps({"data": [{"id": model} for model in api_models]})
        raise AssertionError(f"unexpected external URL: {url}")

    monkeypatch.setattr(pricing_inventory, "_fetch", fake_fetch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")


def _catalog_model(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["models"][0]


def test_documented_flex_evidence_stays_with_its_own_pricing_model_block() -> None:
    pricing = "gpt-5.6-sol / Flex Processing / gpt-5.6-mini / Standard Processing"

    assert pricing_inventory._documented_flex_models(pricing) == {"gpt-5.6-sol"}


def test_inventory_policy_contains_no_model_specific_sol_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    _write_home(home, tiers=["priority"])
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(
        monkeypatch,
        pricing="gpt-5.6-sol: Flex Processing",
    )

    generation = pricing_inventory.update(tmp_path / "inventory")
    inventory = json.loads((generation / "inventory.json").read_text(encoding="utf-8"))

    assert inventory["policy"] == {
        "served_service_tier_is_verified_on_response": True,
        "sources_are_independent": ["codex_catalog", "openai_api", "web_pricing"],
    }


def test_update_promotes_documented_api_flex_sol_when_home_cache_only_has_priority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    config = _write_home(home, tiers=["priority"])
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(
        monkeypatch,
        pricing="<article><h2>gpt-5.6-sol</h2><p>Flex Processing eligible</p></article>",
    )

    root = tmp_path / "inventory"
    generation = pricing_inventory.update(root)

    effective = root / "effective-codex-model-catalog.json"
    service_tiers = _catalog_model(effective)["service_tiers"]
    assert [tier["id"] for tier in service_tiers] == ["priority", "flex"]
    assert config.read_text(encoding="utf-8").splitlines()[:2] == [
        f'model_catalog_json = "{effective}"',
        'service_tier = "flex"',
    ]
    assert generation.is_dir()


def test_update_does_not_promote_model_without_documented_flex_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    config = _write_home(home, tiers=["priority", "flex"])
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(monkeypatch, pricing="<article>gpt-5.6-sol standard pricing</article>")

    root = tmp_path / "inventory"
    pricing_inventory.update(root)

    effective_model = _catalog_model(root / "effective-codex-model-catalog.json")
    assert [tier["id"] for tier in effective_model["service_tiers"]] == ["priority"]
    assert 'service_tier = "auto"' in config.read_text(encoding="utf-8")


def test_effective_catalog_preserves_existing_tiers_and_never_duplicates_flex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    _write_home(home, tiers=["priority"])
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(
        monkeypatch,
        pricing="gpt-5.6-sol: Flex Processing; priority remains available",
    )

    root = tmp_path / "inventory"
    pricing_inventory.update(root)

    model = _catalog_model(root / "effective-codex-model-catalog.json")
    assert [tier["id"] for tier in model["service_tiers"]] == ["priority", "flex"]
    assert model["additional_speed_tiers"] == ["fast"]
    assert [tier["id"] for tier in model["service_tiers"]].count("flex") == 1


def test_all_discovered_home_configs_receive_same_stable_catalog_and_resolved_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    configs = [_write_home(home, tiers=["priority"])]
    for relative in (
        Path(".codex-agents") / "agent-a",
        Path(".local/share/codex-usage/profiles/profile-a/codex-home"),
        Path(".codex-test"),
    ):
        configs.append(_write_codex_home(home / relative, tiers=["priority"]))
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(
        monkeypatch,
        pricing="<model>gpt-5.6-sol <service-tier>Flex</service-tier></model>",
    )

    root = tmp_path / "inventory"
    pricing_inventory.update(root)

    catalog_paths = set()
    for config in configs:
        values = {
            line.split(" = ", 1)[0]: line.split(" = ", 1)[1].strip('"')
            for line in config.read_text(encoding="utf-8").splitlines()
            if " = " in line
        }
        catalog_paths.add(values["model_catalog_json"])
        assert values["service_tier"] == "flex"
    assert catalog_paths == {str(root / "effective-codex-model-catalog.json")}
    assert Path(next(iter(catalog_paths))).is_file()


def test_fetch_builds_fixed_request_and_decodes_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, int]] = []

    class Headers:
        @staticmethod
        def get_content_charset() -> str:
            return "utf-8"

    class Response:
        headers = Headers()

        def __enter__(self):
            return self

        def __exit__(self, *_values: object) -> None:
            return None

        @staticmethod
        def read() -> bytes:
            return "gültig".encode()

    def open_request(request: object, *, timeout: int) -> Response:
        calls.append((request, timeout))
        return Response()

    monkeypatch.setattr(pricing_inventory, "urlopen", open_request)

    assert pricing_inventory._fetch(pricing_inventory.PRICING_URL) == (
        "utf-8",
        "gültig",
    )
    request, timeout = calls[0]
    assert request.full_url == pricing_inventory.PRICING_URL
    assert request.get_header("User-agent") == "codex-master-openai-inventory/1"
    assert timeout == 60


def test_openai_key_reader_uses_only_openai_section(tmp_path: Path) -> None:
    token_file = tmp_path / "api-token.env"
    token_file.write_text(
        "[OTHER]\nwrong\n[OPENAI]\nOPENAI_API_KEY=private-openai-key\n",
        encoding="utf-8",
    )

    assert pricing_inventory._openai_key_from_file(token_file) == "private-openai-key"
    assert pricing_inventory._openai_key_from_file(tmp_path / "missing") is None


def test_main_reports_generation_or_bounded_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    generation = tmp_path / "generation"
    monkeypatch.setattr(pricing_inventory, "update", lambda _root: generation)

    assert pricing_inventory.main(["--root", str(tmp_path)]) == 0
    assert capsys.readouterr().out == f"{generation}\n"

    def fail(_root: Path) -> Path:
        raise RuntimeError("fetch-failed")

    monkeypatch.setattr(pricing_inventory, "update", fail)
    assert pricing_inventory.main(["--root", str(tmp_path)]) == 1
    assert capsys.readouterr().err == "openai-pricing-inventory: fetch-failed\n"
