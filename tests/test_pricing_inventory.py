from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from the_hive import pricing_inventory


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
    assert 'service_tier = "flex"' in config.read_text(encoding="utf-8")


def test_home_service_tier_fallback_returns_flex_when_cache_missing_or_stale(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config.toml"
    config.write_text('model = "gpt-5.6-sol"\nservice_tier = "flex"\n', encoding="utf-8")
    tier, reason = pricing_inventory._home_service_tier(config, [], {"gpt-5.6-sol"})
    assert tier == "flex"
    assert reason == "model_cache_missing_or_stale"


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
    assert request.get_header("User-agent") == "the-hive-openai-inventory/1"
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
    assert capsys.readouterr().err == "openai-pricing-inventory: inventory_failed\n"


def test_run_retries_once_with_an_injectable_short_pause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation = tmp_path / "20260927T220000Z"
    calls: list[Path] = []
    pauses: list[float] = []

    def fail_once(root: Path) -> Path:
        calls.append(root)
        if len(calls) == 1:
            raise RuntimeError("temporary failure")
        return generation

    monkeypatch.setattr(pricing_inventory, "update", fail_once)

    assert pricing_inventory.run(
        tmp_path, pause=pauses.append, retry_delay_seconds=0.01
    ) == generation
    assert calls == [tmp_path, tmp_path]
    assert pauses == [0.01]
    health = json.loads((tmp_path / "health.json").read_text(encoding="utf-8"))
    assert health["status"] == "healthy"
    assert health["attempts"] == 2
    assert health["last_successful_generation"] == generation.name


def test_final_failure_preserves_existing_generation_catalog_and_home_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    config = _write_home(home, tiers=["priority"])
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(monkeypatch, pricing="gpt-5.6-sol: Flex Processing")
    root = tmp_path / "inventory"
    root.mkdir()
    valid_generation = root / "20260926T220000Z"
    valid_generation.mkdir()
    (valid_generation / "inventory.json").write_text("old inventory\n", encoding="utf-8")
    (root / "current").write_text(valid_generation.name + "\n", encoding="utf-8")
    stable_catalog = root / "effective-codex-model-catalog.json"
    stable_catalog.write_text("old catalog\n", encoding="utf-8")
    before = {
        "config": config.read_bytes(),
        "catalog": stable_catalog.read_bytes(),
        "current": (root / "current").read_bytes(),
        "generations": sorted(path.name for path in root.glob("20*")),
    }
    replacements: list[tuple[Path, Path]] = []
    replace = os.replace

    def record_replace(source: os.PathLike[str], target: os.PathLike[str]) -> None:
        replacements.append((Path(source), Path(target)))
        replace(source, target)

    monkeypatch.setattr(pricing_inventory.os, "replace", record_replace)
    update_configs = pricing_inventory._update_codex_configs

    def change_then_fail(*args: object, **kwargs: object) -> tuple[list[str], list[dict[str, str]]]:
        update_configs(*args, **kwargs)
        raise OSError("do not retain the partial catalog or configuration")

    monkeypatch.setattr(pricing_inventory, "_update_codex_configs", change_then_fail)

    with pytest.raises(OSError):
        pricing_inventory.update(root)

    assert config.read_bytes() == before["config"]
    assert stable_catalog.read_bytes() == before["catalog"]
    assert (root / "current").read_bytes() == before["current"]
    assert sorted(path.name for path in root.glob("20*")) == before["generations"]
    assert not list(root.glob(".staging-*"))
    config_replacements = [
        source for source, target in replacements if target == config
    ]
    assert len(config_replacements) == 2
    assert len(set(config_replacements)) == 2
    assert all(source.name.startswith(f".{config.name}.") for source in config_replacements)


def test_recovery_rolls_back_crashed_catalog_and_config_transaction_twice_without_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedPowerLoss(BaseException):
        pass

    home = tmp_path / "home"
    config = _write_home(home, tiers=["priority"])
    config.write_text(
        config.read_text(encoding="utf-8") + 'openai_api_key = "private-openai-key"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(
        monkeypatch,
        pricing="gpt-5.6-sol: Flex Processing raw-pricing-response-sentinel",
    )
    root = tmp_path / "inventory"
    root.mkdir()
    previous_generation = root / "20260926T220000Z"
    previous_generation.mkdir()
    (previous_generation / "inventory.json").write_text("old inventory\n", encoding="utf-8")
    (root / "current").write_text(previous_generation.name + "\n", encoding="utf-8")
    stable_catalog = root / "effective-codex-model-catalog.json"
    stable_catalog.write_text("old catalog\n", encoding="utf-8")
    before = {
        "config": config.read_bytes(),
        "catalog": stable_catalog.read_bytes(),
        "current": (root / "current").read_bytes(),
        "generations": sorted(path.name for path in root.glob("20*")),
    }
    apply_updates = pricing_inventory._update_codex_configs

    def crash_after_config(*args: object, **kwargs: object) -> tuple[list[str], list[dict[str, str]]]:
        apply_updates(*args, **kwargs)
        raise SimulatedPowerLoss()

    monkeypatch.setattr(pricing_inventory, "_update_codex_configs", crash_after_config)

    with pytest.raises(SimulatedPowerLoss):
        pricing_inventory.update(root)

    journal = root / pricing_inventory.TRANSACTION_FILE_NAME
    journal_text = journal.read_text(encoding="utf-8")
    assert stat.S_IMODE(journal.stat().st_mode) == 0o600
    assert "private-openai-key" not in journal_text
    assert "raw-pricing-response-sentinel" not in journal_text
    assert json.loads(journal_text)["phase"] == "backup_ready"
    assert config.read_bytes() != before["config"]
    assert stable_catalog.read_bytes() != before["catalog"]

    backup = root / pricing_inventory.TRANSACTION_BACKUP_FILE_NAME
    durable_unlink = pricing_inventory._durable_unlink

    def fail_recovery_backup_cleanup(path: Path) -> None:
        if path == backup:
            raise OSError("injected recovery backup cleanup failure")
        durable_unlink(path)

    monkeypatch.setattr(pricing_inventory, "_durable_unlink", fail_recovery_backup_cleanup)
    with pytest.raises(OSError, match="injected recovery backup cleanup failure"):
        pricing_inventory._recover_transaction(root)

    assert json.loads(journal.read_text(encoding="utf-8"))["phase"] == "rolled_back"
    assert backup.is_file()
    monkeypatch.setattr(pricing_inventory, "_durable_unlink", durable_unlink)
    pricing_inventory._recover_transaction(root)
    after_first_recovery = {
        "config": config.read_bytes(),
        "catalog": stable_catalog.read_bytes(),
        "current": (root / "current").read_bytes(),
        "generations": sorted(path.name for path in root.glob("20*")),
    }
    pricing_inventory._recover_transaction(root)
    after_second_recovery = {
        "config": config.read_bytes(),
        "catalog": stable_catalog.read_bytes(),
        "current": (root / "current").read_bytes(),
        "generations": sorted(path.name for path in root.glob("20*")),
    }

    assert after_first_recovery == before
    assert after_second_recovery == before
    assert not journal.exists()
    assert not (root / pricing_inventory.TRANSACTION_BACKUP_FILE_NAME).exists()
    assert not list(root.glob(".staging-*"))


def test_recovery_removes_new_current_and_generation_after_crash_then_repeats(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedPowerLoss(BaseException):
        pass

    home = tmp_path / "home"
    config = _write_home(home, tiers=["priority"])
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(monkeypatch, pricing="gpt-5.6-sol: Flex Processing")
    root = tmp_path / "inventory"
    root.mkdir()
    previous_generation = root / "20260926T220000Z"
    previous_generation.mkdir()
    (previous_generation / "inventory.json").write_text("old inventory\n", encoding="utf-8")
    (root / "current").write_text(previous_generation.name + "\n", encoding="utf-8")
    stable_catalog = root / "effective-codex-model-catalog.json"
    stable_catalog.write_text("old catalog\n", encoding="utf-8")
    before = {
        "config": config.read_bytes(),
        "catalog": stable_catalog.read_bytes(),
        "current": (root / "current").read_bytes(),
        "generations": sorted(path.name for path in root.glob("20*")),
    }
    write_current = pricing_inventory._write_current_generation

    def crash_after_current(path: Path, generation: str) -> None:
        write_current(path, generation)
        raise SimulatedPowerLoss()

    monkeypatch.setattr(pricing_inventory, "_write_current_generation", crash_after_current)

    with pytest.raises(SimulatedPowerLoss):
        pricing_inventory.update(root)

    assert (root / "current").read_text(encoding="utf-8") != before["current"].decode("utf-8")
    monkeypatch.setattr(pricing_inventory, "_write_current_generation", write_current)
    pricing_inventory._recover_transaction(root)
    pricing_inventory._recover_transaction(root)

    assert config.read_bytes() == before["config"]
    assert stable_catalog.read_bytes() == before["catalog"]
    assert (root / "current").read_bytes() == before["current"]
    assert sorted(path.name for path in root.glob("20*")) == before["generations"]
    assert not (root / pricing_inventory.TRANSACTION_FILE_NAME).exists()


def test_transaction_journal_uses_only_normalized_semantic_config_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    config = _write_home(home, tiers=["priority"])
    monkeypatch.setenv("HOME", str(home))
    original = (
        'model_catalog_json = "/tmp/original-catalog.json"\n'
        ' service_tier = "auto"\n'
        'openai_api_key = "private-openai-key"\n'
    )
    config.write_text(original, encoding="utf-8")

    rollback = pricing_inventory._config_rollback_state(original)
    assert rollback == {
        "fields": [
            {
                "index": 0,
                "key": "model_catalog_json",
                "value": "/tmp/original-catalog.json",
            },
            {"index": 1, "key": "service_tier", "value": "auto"},
        ],
        "trailing_newline": True,
    }
    assert pricing_inventory._valid_config_rollback_state(rollback)

    config.write_text(
        'model_catalog_json = "/tmp/new-catalog.json"\n'
        'service_tier = "flex"\n'
        'openai_api_key = "private-openai-key"\n',
        encoding="utf-8",
    )
    pricing_inventory._restore_config_rollback_state(config, rollback)

    restored = config.read_text(encoding="utf-8")
    assert restored == (
        'model_catalog_json = "/tmp/original-catalog.json"\n'
        'service_tier = "auto"\n'
        'openai_api_key = "private-openai-key"\n'
    )
    assert "private-openai-key" not in json.dumps(rollback)


def test_catalog_path_validation_requires_normalized_non_sensitive_absolute_paths(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    valid_first_run_path = str(root / "new-state" / "catalog.json")
    traversal = f"{root}/new-state/../private/catalog.json"
    query_with_secret = f"{root}/catalog.json?api_key=secret"
    ordinary_secret_component = f"{root}/secret-catalog.json"
    control_character = f"{root}/catalog\t.json"

    assert pricing_inventory._is_valid_local_catalog_path(valid_first_run_path)
    assert not pricing_inventory._is_valid_local_catalog_path(traversal)
    assert not pricing_inventory._is_valid_local_catalog_path(query_with_secret)
    assert pricing_inventory._is_valid_local_catalog_path(ordinary_secret_component)
    assert not pricing_inventory._is_valid_local_catalog_path(control_character)

    with pytest.raises(ValueError, match="invalid managed configuration field") as failure:
        pricing_inventory._parse_managed_config_field(
            f'model_catalog_json = "{query_with_secret}"'
        )
    assert query_with_secret not in str(failure.value)


def test_catalog_path_validation_allows_ordinary_credential_words(tmp_path: Path) -> None:
    root = tmp_path.resolve()

    for component in ("author", "authentication", "secret-catalog", "credential"):
        assert pricing_inventory._is_valid_local_catalog_path(
            str(root / component / "effective-codex-model-catalog.json")
        )
    assert not pricing_inventory._is_valid_local_catalog_path(
        str(root / "catalog-api_key=secret")
    )
    assert not pricing_inventory._is_valid_local_catalog_path(
        str(root / "catalog-token:secret")
    )


def test_catalog_path_validation_rejects_existing_parent_symlink(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    real_parent = root / "real-parent"
    real_parent.mkdir()
    symlink_parent = root / "linked-parent"
    symlink_parent.symlink_to(real_parent, target_is_directory=True)

    assert not pricing_inventory._is_valid_local_catalog_path(
        str(symlink_parent / "not-created-yet.json")
    )


def test_malicious_managed_config_lines_are_skipped_from_journal_and_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    config = _write_home(home, tiers=["priority"])
    unsafe_catalog = "/tmp/../private/catalog?api_key=secret"
    malicious = (
        f'model_catalog_json = "{unsafe_catalog}"\n'
        'service_tier = "flex" # output-secret-token\n'
    )
    config.write_text(malicious, encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(monkeypatch, pricing="gpt-5.6-sol: Flex Processing")
    root = tmp_path / "inventory"

    for malicious_line in (
        malicious,
        'model_catalog_json = "/tmp/catalog\\nsecret-token"\n',
        'service_tier = "flex" = "secret-token"\n',
    ):
        with pytest.raises(ValueError, match="invalid managed configuration field"):
            pricing_inventory._config_rollback_state(malicious_line)
    assert pricing_inventory._plan_codex_config_updates(
        Path("relative-catalog.json"), [], {MODEL}
    ) == []
    plans = pricing_inventory._plan_codex_config_updates(
        root / "effective-codex-model-catalog.json", [], {MODEL}
    )
    assert plans == []

    class SimulatedPowerLoss(BaseException):
        pass

    update_configs = pricing_inventory._update_codex_configs

    def crash_after_actual_journal(*args: object, **kwargs: object) -> tuple[list[str], list[dict[str, str]]]:
        raise SimulatedPowerLoss()

    monkeypatch.setattr(pricing_inventory, "_update_codex_configs", crash_after_actual_journal)
    with pytest.raises(SimulatedPowerLoss):
        pricing_inventory.update(root)

    journal = (root / pricing_inventory.TRANSACTION_FILE_NAME).read_text(encoding="utf-8")
    assert unsafe_catalog not in journal
    assert "api_key=secret" not in journal
    assert "journal-secret-token" not in journal
    assert "output-secret-token" not in journal
    monkeypatch.setattr(pricing_inventory, "_update_codex_configs", update_configs)
    pricing_inventory._recover_transaction(root)

    published = pricing_inventory.update(root)

    assert config.read_text(encoding="utf-8") == malicious
    inventory = (published / "inventory.json").read_text(encoding="utf-8")
    assert unsafe_catalog not in inventory
    assert "api_key=secret" not in inventory
    assert "journal-secret-token" not in inventory
    assert "output-secret-token" not in inventory


def test_committed_transaction_keeps_backup_journal_for_retry_then_second_update_finishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AdvancingDatetime(datetime):
        calls = 0

        @classmethod
        def now(cls, tz: object | None = None) -> datetime:
            assert tz is UTC
            result = datetime(2026, 9, 27, 22, 0, cls.calls, tzinfo=UTC)
            cls.calls += 1
            return result

    home = tmp_path / "home"
    config = _write_home(home, tiers=["priority"])
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(pricing_inventory, "datetime", AdvancingDatetime)
    _stub_external_sources(monkeypatch, pricing="gpt-5.6-sol: Flex Processing")
    root = tmp_path / "inventory"
    root.mkdir()
    previous = root / "20260926T220000Z"
    previous.mkdir()
    (previous / "inventory.json").write_text("old inventory\n", encoding="utf-8")
    (root / "current").write_text(previous.name + "\n", encoding="utf-8")
    stable_catalog = root / "effective-codex-model-catalog.json"
    stable_catalog.write_text("old catalog\n", encoding="utf-8")
    backup = root / pricing_inventory.TRANSACTION_BACKUP_FILE_NAME
    journal = root / pricing_inventory.TRANSACTION_FILE_NAME
    durable_unlink = pricing_inventory._durable_unlink

    def fail_backup_cleanup(path: Path) -> None:
        if path == backup and backup.exists():
            raise OSError("injected backup cleanup failure")
        durable_unlink(path)

    monkeypatch.setattr(pricing_inventory, "_durable_unlink", fail_backup_cleanup)
    with pytest.raises(OSError, match="injected backup cleanup failure"):
        pricing_inventory.update(root)

    assert json.loads(journal.read_text(encoding="utf-8"))["phase"] == "committed"
    assert backup.is_file()
    assert 'service_tier = "flex"' in config.read_text(encoding="utf-8")
    first_published = pricing_inventory._read_current_generation(root)
    assert first_published is not None and (root / first_published).is_dir()

    monkeypatch.setattr(pricing_inventory, "_durable_unlink", durable_unlink)
    second_published = pricing_inventory.update(root)

    assert second_published.is_dir()
    assert (root / "current").read_text(encoding="utf-8") == second_published.name + "\n"
    assert not backup.exists()
    assert not journal.exists()


def test_generation_rename_fsync_failure_cleans_registered_unpublished_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "inventory"
    home = tmp_path / "home"
    config = _write_home(home, tiers=["priority"])
    before_config = config.read_bytes()
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(monkeypatch, pricing="gpt-5.6-sol: Flex Processing")
    rename = Path.rename
    fsync_directory = pricing_inventory._fsync_directory
    renamed_generation = False
    failed = False

    def record_generation_rename(path: Path, target: os.PathLike[str]) -> Path:
        nonlocal renamed_generation
        result = rename(path, target)
        if Path(target).parent == root and Path(target).name.startswith("20"):
            renamed_generation = True
        return result

    def fail_first_root_sync_after_generation_rename(directory: Path) -> None:
        nonlocal failed
        if renamed_generation and directory == root and not failed:
            failed = True
            raise OSError("injected root fsync failure")
        fsync_directory(directory)

    monkeypatch.setattr(Path, "rename", record_generation_rename)
    monkeypatch.setattr(pricing_inventory, "_fsync_directory", fail_first_root_sync_after_generation_rename)

    with pytest.raises(OSError, match="injected root fsync failure"):
        pricing_inventory.update(root)

    assert renamed_generation and failed
    assert config.read_bytes() == before_config
    assert not list(root.glob("20*"))
    assert not list(root.glob(".staging-*"))
    assert not (root / "current").exists()
    assert not (root / "effective-codex-model-catalog.json").exists()
    assert not (root / pricing_inventory.TRANSACTION_FILE_NAME).exists()
    assert not (root / pricing_inventory.TRANSACTION_BACKUP_FILE_NAME).exists()


def test_current_generation_is_private_crash_atomic_and_directory_synced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "inventory"
    root.mkdir()
    generation = "20260927T220000Z"
    replacements: list[tuple[Path, Path, int]] = []
    fsyncs: list[int] = []
    replace = os.replace
    fsync = os.fsync

    def record_replace(source: os.PathLike[str], target: os.PathLike[str]) -> None:
        source_path = Path(source)
        replacements.append((source_path, Path(target), stat.S_IMODE(source_path.stat().st_mode)))
        replace(source, target)

    def record_fsync(descriptor: int) -> None:
        fsyncs.append(descriptor)
        fsync(descriptor)

    monkeypatch.setattr(pricing_inventory.os, "replace", record_replace)
    monkeypatch.setattr(pricing_inventory.os, "fsync", record_fsync)

    pricing_inventory._write_current_generation(root, generation)

    assert (root / "current").read_text(encoding="utf-8") == f"{generation}\n"
    assert len(replacements) == 1
    temporary, target, temporary_mode = replacements[0]
    assert target == root / "current"
    assert temporary_mode == 0o600
    assert temporary.name.startswith(".current.")
    assert len(fsyncs) == 2
    assert not list(root.glob(".current.*.tmp"))


def test_update_syncs_generation_files_and_directories_before_current_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "inventory"
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(monkeypatch, pricing="gpt-5.6-sol: Flex Processing")

    events: list[tuple[str, Path]] = []
    fsync = os.fsync
    replace = os.replace
    rename = Path.rename

    def record_fsync(descriptor: int) -> None:
        events.append(("fsync", Path(os.readlink(f"/proc/self/fd/{descriptor}"))))
        fsync(descriptor)

    def record_replace(source: os.PathLike[str], target: os.PathLike[str]) -> None:
        events.append(("replace", Path(target)))
        replace(source, target)

    def record_rename(path: Path, target: os.PathLike[str]) -> Path:
        events.append(("rename", Path(target)))
        return rename(path, target)

    monkeypatch.setattr(pricing_inventory.os, "fsync", record_fsync)
    monkeypatch.setattr(pricing_inventory.os, "replace", record_replace)
    monkeypatch.setattr(Path, "rename", record_rename)

    published = pricing_inventory.update(root)

    staging = root / f".staging-{published.name}"
    generation_rename = events.index(("rename", published))
    generation_file_syncs = [
        index
        for index, (event, path) in enumerate(events)
        if event == "fsync"
        and path.parent == staging
        and any(
            path.name.startswith(f".{name}.")
            for name in ("pricing.html", "models.html", "inventory.json")
        )
    ]
    staging_sync = max(
        index
        for index, (event, path) in enumerate(events[:generation_rename])
        if event == "fsync" and path == staging
    )
    root_sync = next(
        index
        for index, (event, path) in enumerate(events[generation_rename + 1:], generation_rename + 1)
        if event == "fsync" and path == root
    )
    current_publication = next(
        index
        for index, (event, path) in enumerate(events[root_sync + 1:], root_sync + 1)
        if event == "replace" and path == root / "current"
    )

    assert len(generation_file_syncs) == 3
    assert max(generation_file_syncs) < staging_sync < generation_rename < root_sync
    assert root_sync < current_publication


def test_update_durably_moves_stable_catalog_before_config_or_current_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "inventory"
    home = tmp_path / "home"
    config = _write_home(home, tiers=["priority"])
    monkeypatch.setenv("HOME", str(home))
    _stub_external_sources(monkeypatch, pricing="gpt-5.6-sol: Flex Processing")

    events: list[tuple[str, Path]] = []
    fsync = os.fsync
    replace = os.replace
    path_replace = Path.replace

    def record_fsync(descriptor: int) -> None:
        events.append(("fsync", Path(os.readlink(f"/proc/self/fd/{descriptor}"))))
        fsync(descriptor)

    def record_replace(source: os.PathLike[str], target: os.PathLike[str]) -> None:
        events.append(("replace", Path(target)))
        replace(source, target)

    def record_path_replace(path: Path, target: os.PathLike[str]) -> Path:
        events.append(("catalog-rename", Path(target)))
        return path_replace(path, target)

    monkeypatch.setattr(pricing_inventory.os, "fsync", record_fsync)
    monkeypatch.setattr(pricing_inventory.os, "replace", record_replace)
    monkeypatch.setattr(Path, "replace", record_path_replace)

    published = pricing_inventory.update(root)

    staging = root / f".staging-{published.name}"
    stable_catalog = root / "effective-codex-model-catalog.json"
    catalog_file_sync = next(
        index
        for index, (event, path) in enumerate(events)
        if event == "fsync"
        and path.parent == staging
        and path.name.startswith(".effective-codex-model-catalog.json.")
    )
    catalog_rename = events.index(("catalog-rename", stable_catalog))
    journal_publication = events.index((
        "replace", root / pricing_inventory.TRANSACTION_FILE_NAME
    ))
    target_directory_sync = next(
        index
        for index, (event, path) in enumerate(events[catalog_rename + 1:], catalog_rename + 1)
        if event == "fsync" and path == root
    )
    source_directory_sync = next(
        index
        for index, (event, path) in enumerate(events[target_directory_sync + 1:], target_directory_sync + 1)
        if event == "fsync" and path == staging
    )
    config_publication = next(
        index
        for index, (event, path) in enumerate(events[source_directory_sync + 1:], source_directory_sync + 1)
        if event == "replace" and path == config
    )
    current_publication = next(
        index
        for index, (event, path) in enumerate(events[config_publication + 1:], config_publication + 1)
        if event == "replace" and path == root / "current"
    )

    assert journal_publication < catalog_rename
    assert catalog_file_sync < catalog_rename < target_directory_sync < source_directory_sync
    assert source_directory_sync < config_publication < current_publication


def test_retention_never_deletes_current_generation_when_clock_moves_backwards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> datetime:
            assert tz is UTC
            return datetime(2026, 1, 1, tzinfo=UTC)

    root = tmp_path / "inventory"
    root.mkdir()
    frozen_now = datetime(2026, 1, 1, tzinfo=UTC)
    for offset in range(1, 51):
        (root / (frozen_now + timedelta(days=offset)).strftime("%Y%m%dT%H%M%SZ")).mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(pricing_inventory, "datetime", FrozenDatetime)
    _stub_external_sources(monkeypatch, pricing="gpt-5.6-sol: Flex Processing")

    published = pricing_inventory.update(root)

    assert published.name == "20260101T000000Z"
    assert published.is_dir()
    assert (root / "current").read_text(encoding="utf-8") == f"{published.name}\n"
    assert len([path for path in root.iterdir() if path.is_dir() and path.name.startswith("20")]) == 50


def test_retention_after_committed_transaction_never_recovers_to_deleted_previous_current(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedPowerLoss(BaseException):
        pass

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> datetime:
            assert tz is UTC
            return datetime(2026, 1, 1, tzinfo=UTC)

    root = tmp_path / "inventory"
    root.mkdir()
    previous = root / "20250101T000000Z"
    previous.mkdir()
    (previous / "inventory.json").write_text("old inventory\n", encoding="utf-8")
    (root / "current").write_text(previous.name + "\n", encoding="utf-8")
    for offset in range(50):
        (root / (datetime(2027, 1, 1, tzinfo=UTC) + timedelta(days=offset)).strftime(
            "%Y%m%dT%H%M%SZ"
        )).mkdir()
    home = tmp_path / "home"
    _write_home(home, tiers=["priority"])
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(pricing_inventory, "datetime", FrozenDatetime)
    _stub_external_sources(monkeypatch, pricing="gpt-5.6-sol: Flex Processing")
    remove_directory = pricing_inventory._durable_remove_generated_directory
    journal = root / pricing_inventory.TRANSACTION_FILE_NAME

    def crash_when_retention_reaches_previous(directory: Path) -> None:
        if directory == previous:
            assert not journal.exists()
            raise SimulatedPowerLoss()
        remove_directory(directory)

    monkeypatch.setattr(
        pricing_inventory, "_durable_remove_generated_directory", crash_when_retention_reaches_previous
    )
    with pytest.raises(SimulatedPowerLoss):
        pricing_inventory.update(root)

    published = "20260101T000000Z"
    assert (root / "current").read_text(encoding="utf-8") == published + "\n"
    assert (root / published).is_dir()
    monkeypatch.setattr(
        pricing_inventory, "_durable_remove_generated_directory", remove_directory
    )
    pricing_inventory._recover_transaction(root)
    pricing_inventory._recover_transaction(root)

    current = pricing_inventory._read_current_generation(root)
    assert current == published
    assert current is not None and (root / current).is_dir()


def test_parallel_run_reports_stable_lock_code_without_changing_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "inventory"
    root.mkdir()
    generation = root / "20260926T220000Z"
    generation.mkdir()
    (generation / "inventory.json").write_text("last valid inventory\n", encoding="utf-8")
    (root / "current").write_text(f"{generation.name}\n", encoding="utf-8")
    calls: list[Path] = []

    def must_not_run(path: Path) -> Path:
        calls.append(path)
        raise AssertionError("a locked run must not call update")

    monkeypatch.setattr(pricing_inventory, "update", must_not_run)

    with pricing_inventory._inventory_lock(root):
        before = {
            path.relative_to(root): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }
        with pytest.raises(pricing_inventory.InventoryRunFailure) as failure:
            pricing_inventory.run(root, pause=lambda _seconds: None)
        after = {
            path.relative_to(root): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    assert failure.value.error_code == "inventory_in_progress"
    assert calls == []
    assert after == before


def test_health_state_is_private_atomic_and_never_serializes_exception_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replacements: list[tuple[Path, Path]] = []
    replace = os.replace

    def record_replace(source: os.PathLike[str], target: os.PathLike[str]) -> None:
        replacements.append((Path(source), Path(target)))
        replace(source, target)

    monkeypatch.setattr(pricing_inventory.os, "replace", record_replace)
    monkeypatch.setattr(pricing_inventory, "update", lambda _root: (_ for _ in ()).throw(
        RuntimeError("response body with secret-token")
    ))

    with pytest.raises(pricing_inventory.InventoryRunFailure) as failure:
        pricing_inventory.run(tmp_path, pause=lambda _seconds: None)

    assert failure.value.error_code == "inventory_failed"
    health_path = tmp_path / "health.json"
    health = json.loads(health_path.read_text(encoding="utf-8"))
    assert health == {
        "schema_version": 1,
        "status": "alert",
        "updated_at": health["updated_at"],
        "attempts": 2,
        "last_error_at": health["last_error_at"],
        "last_error_code": "inventory_failed",
    }
    assert "secret-token" not in health_path.read_text(encoding="utf-8")
    assert stat.S_IMODE(health_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert len(replacements) == 1
    temporary, target = replacements[0]
    assert target == health_path
    assert temporary.name.startswith(".health.json.")
    assert not list(tmp_path.glob(".health.json.*.tmp"))


def test_successful_health_state_preserves_the_previous_error_history(tmp_path: Path) -> None:
    pricing_inventory._write_health_state(
        tmp_path, status="alert", attempts=2, error_code="inventory_failed"
    )
    generation = tmp_path / "20260927T220000Z"
    pricing_inventory._write_health_state(
        tmp_path, status="healthy", attempts=1, generation=generation
    )

    health = json.loads((tmp_path / "health.json").read_text(encoding="utf-8"))
    assert health["status"] == "healthy"
    assert health["attempts"] == 1
    assert health["last_successful_generation"] == generation.name
    assert health["last_error_code"] == "inventory_failed"
    assert isinstance(health["last_error_at"], str)


def test_health_history_accepts_only_canonical_non_sensitive_values(tmp_path: Path) -> None:
    health_path = tmp_path / "health.json"
    health_path.write_text(
        json.dumps({
            "last_successful_generation": "20260927T220000Z",
            "last_successful_at": "2026-09-27T22:00:00+00:00",
            "last_error_at": "2026-09-27T22:01:00+00:00",
            "last_error_code": "io_error",
            "exception": "Bearer secret-token leaked here",
        }),
        encoding="utf-8",
    )

    assert pricing_inventory._read_health_state(tmp_path) == {
        "last_successful_generation": "20260927T220000Z",
        "last_successful_at": "2026-09-27T22:00:00+00:00",
        "last_error_at": "2026-09-27T22:01:00+00:00",
        "last_error_code": "io_error",
    }

    health_path.write_text(
        json.dumps({
            "last_successful_generation": "20261340T250000Z",
            "last_successful_at": "yesterday with secret-token",
            "last_error_at": "RuntimeError: secret-token",
            "last_error_code": "RuntimeError: secret-token",
        }),
        encoding="utf-8",
    )

    assert pricing_inventory._read_health_state(tmp_path) == {}


def test_pricing_units_use_the_canonical_the_hive_state_path() -> None:
    repository = Path(__file__).resolve().parents[1]
    assert pricing_inventory.PRICING_URL == "https://developers.openai.com/api/docs/pricing"
    service = (repository / "systemd/user/the-hive-openai-pricing.service").read_text(
        encoding="utf-8"
    )
    timer = (repository / "systemd/user/the-hive-openai-pricing.timer").read_text(
        encoding="utf-8"
    )

    assert "codex-master-mcp" not in service
    assert "StateDirectory=the-hive/openai-pricing" in service
    assert "StateDirectoryMode=0700" in service
    assert "ReadWritePaths=%h/.local/state/the-hive/openai-pricing" in service
    assert "Restart=" not in service
    assert "ExecStart=%h/.local/bin/the-hive-openai-pricing-inventory" in service
    assert "OnCalendar=daily" in timer
    assert "Persistent=true" in timer
    assert "Unit=the-hive-openai-pricing.service" in timer
