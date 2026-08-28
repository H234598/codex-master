"""Fetch and retain the public OpenAI model/pricing inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
import time
from html import unescape
from pathlib import Path
from urllib.request import Request, urlopen

PRICING_URL = "https://platform.openai.com/pricing?latest-pricing"
MODELS_URL = "https://developers.openai.com/api/docs/models/all"
DEFAULT_ROOT = Path.home() / ".local/state/codex-master-mcp/openai-pricing"
DEFAULT_TOKEN_FILE = Path.home() / ".config/codex-master-mcp/api-token.env"
EFFECTIVE_CATALOG = DEFAULT_ROOT / "effective-codex-model-catalog.json"
MAX_GENERATIONS = 50
MODEL_CACHE_MAX_AGE_SECONDS = 24 * 60 * 60
MODEL_RE = re.compile(r"\b(?:gpt|o[1-9]|codex|chat|computer-use|sora|text-|text-embedding|dall-e|whisper|tts)[A-Za-z0-9._-]*\b", re.I)


def _fetch(url: str, *, headers: dict[str, str] | None = None) -> tuple[str, str]:
    request_headers = {"User-Agent": "codex-master-openai-inventory/1"}
    if headers:
        request_headers.update(headers)
    request = Request(url, headers=request_headers)
    with urlopen(request, timeout=60) as response:  # noqa: S310 - fixed HTTPS URLs
        body = response.read()
        return response.headers.get_content_charset() or "utf-8", body.decode(
            response.headers.get_content_charset() or "utf-8", errors="replace"
        )


def _models_from_text(*texts: str) -> list[str]:
    found: set[str] = set()
    for text in texts:
        for match in MODEL_RE.findall(unescape(re.sub(r"<[^>]+>", " ", text))):
            value = match.lower()
            if len(value) <= 120 and any(ch.isdigit() for ch in value):
                found.add(value)
    return sorted(found)


def _documented_flex_models(pricing: str) -> set[str]:
    text = unescape(re.sub(r"<[^>]+>", " ", pricing))
    matches = list(MODEL_RE.finditer(text))
    flex_models: set[str] = set()
    for index, match in enumerate(matches):
        next_model = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        context = text[match.end() : next_model]
        if re.search(r"\bflex\b", context, re.IGNORECASE):
            flex_models.add(match.group().lower())
    return flex_models


def _openai_key_from_file(path: Path = DEFAULT_TOKEN_FILE) -> str | None:
    """Read only the legacy OPENAI section; never include it in output."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    section = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped.upper() == "[OPENAI]"
            continue
        if section and stripped and not stripped.startswith("#"):
            return stripped.split("=", 1)[-1].strip()
    return None


def _catalog_paths() -> list[Path]:
    configured = os.environ.get("CODEX_MODEL_CATALOG")
    paths = [Path(configured)] if configured else [Path.home() / ".codex/models_cache.json"]
    agents = Path.home() / ".codex-agents"
    if agents.is_dir():
        paths.extend(sorted(agents.glob("*/models_cache.json")))
    # codex-usage owns the canonical homes for provisioned accounts.  They are
    # real Codex homes too and must participate in the three-way reconciliation.
    profiles = Path.home() / ".local/share/codex-usage/profiles"
    if profiles.is_dir():
        paths.extend(sorted(profiles.glob("*/codex-home/models_cache.json")))
    paths.append(Path.home() / ".codex-test/models_cache.json")
    return [path for path in dict.fromkeys(paths) if path.is_file()]


def _read_catalogs() -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for path in _catalog_paths():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            models = payload.get("models", []) if isinstance(payload, dict) else []
            entries = []
            for model in models:
                if not isinstance(model, dict) or not isinstance(model.get("slug"), str):
                    continue
                tiers = model.get("service_tiers", [])
                entries.append({
                    "id": model["slug"],
                    "service_tiers": sorted(
                        tier.get("id") for tier in tiers
                        if isinstance(tier, dict) and isinstance(tier.get("id"), str)
                    ),
                    "additional_speed_tiers": sorted(
                        value for value in model.get("additional_speed_tiers", [])
                        if isinstance(value, str)
                    ),
                    "supported_in_api": model.get("supported_in_api"),
                })
            fetched_at = payload.get("fetched_at") if isinstance(payload, dict) else None
            age_seconds: float | None = None
            if isinstance(fetched_at, str):
                try:
                    age_seconds = max(
                        0.0,
                        time.time() - datetime.fromisoformat(fetched_at.replace("Z", "+00:00")).timestamp(),
                    )
                except ValueError:
                    age_seconds = None
            result.append({
                "path": str(path),
                "models": entries,
                "fetched_at": fetched_at,
                "client_version": payload.get("client_version") if isinstance(payload, dict) else None,
                "age_seconds": age_seconds,
                "fresh": age_seconds is not None and age_seconds <= MODEL_CACHE_MAX_AGE_SECONDS,
            })
        except (OSError, ValueError, TypeError):
            result.append({"path": str(path), "error": "invalid_or_unreadable"})
    return result


def _write_effective_catalog(root: Path, eligible_flex: set[str]) -> Path | None:
    source_paths = _catalog_paths()
    if not source_paths:
        return None
    try:
        payload = json.loads(source_paths[0].read_text(encoding="utf-8"))
        models = payload.get("models", [])
        for model in models:
            if not isinstance(model, dict):
                continue
            tiers = model.setdefault("service_tiers", [])
            if not isinstance(tiers, list):
                continue
            tiers[:] = [
                tier
                for tier in tiers
                if not isinstance(tier, dict) or tier.get("id") != "flex"
            ]
            if model.get("slug") in eligible_flex:
                tiers.append({"id": "flex", "name": "Flex", "description": "Flex Processing"})
        target = root / "effective-codex-model-catalog.json"
        temporary = root / ".effective-codex-model-catalog.json.tmp"
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(target)
        return target
    except (OSError, ValueError, TypeError):
        return None


def _codex_config_paths() -> list[Path]:
    paths = [Path.home() / ".codex/config.toml"]
    agents = Path.home() / ".codex-agents"
    if agents.is_dir():
        paths.extend(sorted(agents.glob("*/config.toml")))
    profiles = Path.home() / ".local/share/codex-usage/profiles"
    if profiles.is_dir():
        paths.extend(sorted(profiles.glob("*/codex-home/config.toml")))
    paths.append(Path.home() / ".codex-test/config.toml")
    return [path for path in dict.fromkeys(paths) if path.is_file()]


def _cache_for_config(config: Path, catalogs: list[dict[str, object]]) -> dict[str, object] | None:
    home = config.parent
    cache = home / "models_cache.json"
    for item in catalogs:
        if item.get("path") == str(cache):
            return item
    return None


def _configured_model(config: Path) -> str | None:
    try:
        for line in config.read_text(encoding="utf-8").splitlines():
            match = re.match(r"\s*model\s*=\s*\"([^\"]+)\"", line)
            if match:
                return match.group(1)
    except OSError:
        return None
    return None


def _home_service_tier(
    config: Path, catalogs: list[dict[str, object]], eligible_flex: set[str]
) -> tuple[str, str]:
    """Return a tier and an audit reason for one concrete Codex home."""
    catalog = _cache_for_config(config, catalogs)
    model_id = _configured_model(config)
    if not catalog or not catalog.get("fresh"):
        return "auto", "model_cache_missing_or_stale"
    entries = catalog.get("models", [])
    model = next(
        (entry for entry in entries if isinstance(entry, dict) and entry.get("id") == model_id),
        None,
    )
    if not model:
        return "auto", "model_missing_from_home_cache"
    tiers = model.get("service_tiers", [])
    if model_id in eligible_flex:
        return "flex", "documented_flex_evidence"
    if isinstance(tiers, list) and "flex" in tiers:
        return "auto", "home_cache_flex_without_documented_evidence"
    if isinstance(tiers, list) and tiers:
        return "auto", "home_cache_denies_flex"
    return "auto", "home_cache_has_no_service_tier"


def _update_codex_configs(
    catalog: Path, catalogs: list[dict[str, object]], eligible_flex: set[str]
) -> tuple[list[str], list[dict[str, str]]]:
    changed: list[str] = []
    decisions: list[dict[str, str]] = []
    for path in _codex_config_paths():
        try:
            text = path.read_text(encoding="utf-8")
            tier, reason = _home_service_tier(path, catalogs, eligible_flex)
            decisions.append({"config": str(path), "service_tier": tier, "reason": reason})
            lines = text.splitlines()
            updated: list[str] = []
            for line in lines:
                if re.match(r"^\s*(?:model_catalog_json|service_tier)\s*=", line):
                    continue
                updated.append(line)
            updated[0:0] = [
                f'model_catalog_json = "{catalog}"',
                f'service_tier = "{tier}"',
            ]
            new_text = "\n".join(updated) + "\n"
            if new_text != text:
                temporary = path.with_name(f".{path.name}.pricing.tmp")
                temporary.write_text(new_text, encoding="utf-8")
                temporary.replace(path)
                changed.append(str(path))
        except OSError:
            continue
    return changed, decisions


def update(root: Path = DEFAULT_ROOT) -> Path:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    generation = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    staging = root / f".staging-{generation}"
    staging.mkdir(mode=0o700)
    try:
        pricing_encoding, pricing = _fetch(PRICING_URL)
        models_encoding, models = _fetch(MODELS_URL)
        api_key = (
            os.environ.get("OPENAI_API_KEY")
            or os.environ.get("CODEX_OPENAI_API_KEY")
            or _openai_key_from_file()
        )
        api_models: list[str] = []
        api_status = "not_configured"
        if api_key:
            _, api_payload = _fetch(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            parsed = json.loads(api_payload)
            api_models = sorted(
                str(item["id"])
                for item in parsed.get("data", [])
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            )
            api_status = "ok"
        documented_models = _models_from_text(pricing, models)
        documented_flex_models = _documented_flex_models(pricing) & set(documented_models)
        catalogs = _read_catalogs()
        catalog_models = sorted({
            entry["id"] for catalog in catalogs
            for entry in catalog.get("models", [])
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        })
        catalog_flex_models = sorted({
            entry["id"] for catalog in catalogs
            for entry in catalog.get("models", [])
            if isinstance(entry, dict)
            and isinstance(entry.get("id"), str)
            and "flex" in entry.get("service_tiers", [])
        })
        api_set = set(api_models)
        eligible_flex = set(documented_flex_models)
        if api_status == "ok":
            eligible_flex &= api_set
        effective_catalog = _write_effective_catalog(staging, eligible_flex)
        # The catalog path must be stable across generations. Move it out of the
        # generation before the generation is published.
        if effective_catalog is not None:
            stable_catalog = root / effective_catalog.name
            effective_catalog.replace(stable_catalog)
            effective_catalog = stable_catalog
            config_changes, config_decisions = _update_codex_configs(
                stable_catalog, catalogs, eligible_flex
            )
        else:
            config_changes = []
            config_decisions = []
        inventory = {
            "schema_version": 1,
            "fetched_at": datetime.now(UTC).isoformat(),
            "sources": {
                "pricing": {"url": PRICING_URL, "encoding": pricing_encoding},
                "models": {"url": MODELS_URL, "encoding": models_encoding},
            },
            "models": documented_models,
            "api": {
                "status": api_status,
                "models": api_models,
                "only_in_documentation": sorted(set(documented_models) - set(api_models))
                if api_status == "ok" else [],
                "only_in_api": sorted(set(api_models) - set(documented_models))
                if api_status == "ok" else [],
            },
            "codex_catalog": {
                "files": catalogs,
                "models": catalog_models,
                "flex_models": catalog_flex_models,
            },
            "reconciliation": {
                "documentation_model_count": len(documented_models),
                "api_model_count": len(api_models),
                "catalog_model_count": len(catalog_models),
                "catalog_flex_model_count": len(catalog_flex_models),
                "flex_gap": sorted(set(documented_models) & set(api_models) - set(catalog_flex_models))
                if api_status == "ok" else [],
                "eligible_flex_models": sorted(eligible_flex),
                "effective_catalog": str(effective_catalog or ""),
                "config_files_updated": config_changes,
                "home_service_tier_decisions": config_decisions,
                "home_cache_max_age_seconds": MODEL_CACHE_MAX_AGE_SECONDS,
            },
            "policy": {
                "served_service_tier_is_verified_on_response": True,
                "sources_are_independent": ["codex_catalog", "openai_api", "web_pricing"],
            },
            "sha256": {
                "pricing": hashlib.sha256(pricing.encode()).hexdigest(),
                "models": hashlib.sha256(models.encode()).hexdigest(),
            },
        }
        (staging / "pricing.html").write_text(pricing, encoding="utf-8")
        (staging / "models.html").write_text(models, encoding="utf-8")
        (staging / "inventory.json").write_text(
            json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        staging.rename(root / generation)
        generations = sorted(
            (path for path in root.iterdir() if path.is_dir() and re.fullmatch(r"\d{8}T\d{6}Z", path.name)),
            reverse=True,
        )
        for old in generations[MAX_GENERATIONS:]:
            for child in old.iterdir():
                child.unlink()
            old.rmdir()
        (root / "current").write_text(generation + "\n", encoding="utf-8")
        return root / generation
    except Exception:
        for child in staging.iterdir():
            child.unlink()
        staging.rmdir()
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args(argv)
    try:
        print(update(args.root))
    except Exception as exc:
        print(f"openai-pricing-inventory: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
