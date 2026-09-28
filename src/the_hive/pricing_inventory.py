"""Fetch and retain the public OpenAI model/pricing inventory."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import UTC, datetime
import time
from html import unescape
from pathlib import Path
from typing import Callable, Iterator
from urllib.request import Request, urlopen

PRICING_URL = "https://developers.openai.com/api/docs/pricing"
MODELS_URL = "https://developers.openai.com/api/docs/models/all"
DEFAULT_ROOT = Path.home() / ".local/state/the-hive/openai-pricing"
DEFAULT_TOKEN_FILE = Path.home() / ".config/the-hive/api-token.env"
EFFECTIVE_CATALOG = DEFAULT_ROOT / "effective-codex-model-catalog.json"
MAX_GENERATIONS = 50
MODEL_CACHE_MAX_AGE_SECONDS = 24 * 60 * 60
HEALTH_SCHEMA_VERSION = 1
HEALTH_FILE_NAME = "health.json"
RETRY_DELAY_SECONDS = 1.0
RUN_LOCK_FILE_NAME = ".inventory.lock"
TRANSACTION_FILE_NAME = ".transaction.json"
TRANSACTION_BACKUP_FILE_NAME = ".transaction-catalog-backup.json"
TRANSACTION_SCHEMA_VERSION = 1
STABLE_ERROR_CODES = frozenset({
    "invalid_response",
    "io_error",
    "inventory_failed",
    "inventory_in_progress",
})
MODEL_RE = re.compile(r"\b(?:gpt|o[1-9]|codex|chat|computer-use|sora|text-|text-embedding|dall-e|whisper|tts)[A-Za-z0-9._-]*\b", re.I)
MANAGED_CONFIG_LINE_RE = re.compile(
    r"^\s*(?P<key>model_catalog_json|service_tier)\s*="
)
MODEL_CATALOG_JSON_LINE_RE = re.compile(
    r'^\s*model_catalog_json\s*=\s*"(?P<value>[^"\r\n]*)"\s*$'
)
SERVICE_TIER_LINE_RE = re.compile(
    r'^\s*service_tier\s*=\s*"(?P<value>[a-z0-9_-]+)"\s*$'
)
SERVICE_TIER_VALUES = frozenset({"auto", "flex", "priority"})
CREDENTIAL_VALUE_PATH_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:api[_-]?key|access[_-]?token|token|secret|credential|password|passwd|authorization|bearer|auth)(?:=|:)[^/?#&;\s]+",
    re.IGNORECASE,
)


class InventoryRunFailure(RuntimeError):
    """A bounded inventory run failed and recorded only its stable error code."""

    def __init__(self, error_code: str) -> None:
        super().__init__(error_code)
        self.error_code = error_code


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _health_path(root: Path) -> Path:
    return root / HEALTH_FILE_NAME


def _ensure_private_root(root: Path) -> None:
    """Create the inventory state directory and keep it private."""
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (root.stat().st_mode & 0o777) != 0o700:
        os.chmod(root, 0o700)


def _is_valid_timestamp(value: str) -> bool:
    """Accept canonical, timezone-aware ISO timestamps emitted by this module."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None and parsed.isoformat() == value


def _is_valid_generation_name(value: str) -> bool:
    """Accept only actual inventory generation directory names."""
    if not re.fullmatch(r"\d{8}T\d{6}Z", value):
        return False
    try:
        datetime.strptime(value, "%Y%m%dT%H%M%SZ")
    except ValueError:
        return False
    return True


def _fsync_directory(directory: Path) -> None:
    """Durably persist a directory entry after an atomic replacement."""
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_bytes(target: Path, contents: bytes, *, mode: int = 0o600) -> None:
    """Replace one private file only after its contents and directory entry are synced."""
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, target)
        _fsync_directory(target.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _durable_unlink(target: Path) -> None:
    """Remove one file and persist the removal from its parent directory."""
    try:
        target.unlink()
    except FileNotFoundError:
        return
    _fsync_directory(target.parent)


def _durable_remove_generated_directory(directory: Path) -> None:
    """Remove a known flat staging or unpublished generation directory durably."""
    if not directory.is_dir():
        return
    for child in directory.iterdir():
        child.unlink()
    directory.rmdir()
    _fsync_directory(directory.parent)


def _transaction_path(root: Path) -> Path:
    return root / TRANSACTION_FILE_NAME


def _transaction_backup_path(root: Path) -> Path:
    return root / TRANSACTION_BACKUP_FILE_NAME


def _read_current_generation(root: Path) -> str | None:
    """Read only a valid current pointer so it can be journalled without raw data."""
    try:
        contents = (root / "current").read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    if not contents.endswith("\n"):
        raise ValueError("invalid current generation")
    generation = contents[:-1]
    if not _is_valid_generation_name(generation):
        raise ValueError("invalid current generation")
    return generation


def _is_valid_local_catalog_path(value: str) -> bool:
    """Accept only a normalized, non-sensitive local path safe for recovery."""
    if (
        not value
        or value.startswith("//")
        or value != os.path.normpath(value)
        or any(marker in value for marker in ("?", "#", "\\"))
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or CREDENTIAL_VALUE_PATH_RE.search(value)
    ):
        return False
    path = Path(value)
    if not path.is_absolute() or len(path.parts) < 2:
        return False
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        except OSError:
            return False
        if stat.S_ISLNK(mode):
            return False
    return True


def _parse_managed_config_field(line: str) -> tuple[str, str] | None:
    """Parse one managed assignment without retaining raw TOML text."""
    match = MANAGED_CONFIG_LINE_RE.match(line)
    if match is None:
        return None
    key = match["key"]
    value_match = (
        MODEL_CATALOG_JSON_LINE_RE.fullmatch(line)
        if key == "model_catalog_json"
        else SERVICE_TIER_LINE_RE.fullmatch(line)
    )
    if value_match is None:
        raise ValueError("invalid managed configuration field")
    value = value_match["value"]
    if (
        key == "model_catalog_json" and not _is_valid_local_catalog_path(value)
    ) or (key == "service_tier" and value not in SERVICE_TIER_VALUES):
        raise ValueError("invalid managed configuration field")
    return key, value


def _config_rollback_state(text: str) -> dict[str, object]:
    """Keep semantic, non-secret managed fields only for transaction recovery."""
    fields: list[dict[str, object]] = []
    keys: set[str] = set()
    for index, line in enumerate(text.splitlines()):
        parsed = _parse_managed_config_field(line)
        if parsed is None:
            continue
        key, value = parsed
        if key in keys:
            raise ValueError("duplicate managed configuration field")
        keys.add(key)
        fields.append({"index": index, "key": key, "value": value})
    return {"fields": fields, "trailing_newline": text.endswith("\n")}


def _valid_config_rollback_state(value: object) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("trailing_newline"), bool):
        return False
    fields = value.get("fields")
    if not isinstance(fields, list):
        return False
    previous_index = -1
    keys: set[str] = set()
    for field in fields:
        if not isinstance(field, dict):
            return False
        index = field.get("index")
        key = field.get("key")
        value = field.get("value")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
            or index <= previous_index
            or not isinstance(key, str)
            or key in keys
            or not isinstance(value, str)
            or (
                key == "model_catalog_json"
                and not _is_valid_local_catalog_path(value)
            )
            or (key == "service_tier" and value not in SERVICE_TIER_VALUES)
            or key not in {"model_catalog_json", "service_tier"}
        ):
            return False
        previous_index = index
        keys.add(key)
    return True


def _write_transaction_journal(
    root: Path,
    *,
    generation: str,
    previous_current: str | None,
    catalog_existed: bool,
    config_plans: list[dict[str, object]],
) -> dict[str, object]:
    """Durably describe rollback state before changing catalog or home configs."""
    if not _is_valid_generation_name(generation):
        raise ValueError("invalid transaction generation")
    if previous_current is not None and not _is_valid_generation_name(previous_current):
        raise ValueError("invalid transaction current generation")
    configs: list[dict[str, object]] = []
    for plan in config_plans:
        if not plan["changed"]:
            continue
        path = plan["path"]
        rollback = plan["rollback"]
        if not isinstance(path, Path) or not _valid_config_rollback_state(rollback):
            raise ValueError("invalid config rollback state")
        configs.append({"path": str(path), "rollback": rollback})
    transaction: dict[str, object] = {
        "schema_version": TRANSACTION_SCHEMA_VERSION,
        "phase": "prepared",
        "generation": generation,
        "previous_current": previous_current,
        "catalog_existed": catalog_existed,
        "configs": configs,
    }
    _atomic_write_bytes(
        _transaction_path(root),
        (json.dumps(transaction, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    return transaction


def _mark_transaction_phase(
    root: Path, transaction: dict[str, object], phase: str
) -> None:
    """Durably advance a transaction only through its finite recovery phases."""
    if phase not in {"backup_ready", "rolled_back", "committed"}:
        raise ValueError("invalid transaction phase")
    transaction["phase"] = phase
    _atomic_write_bytes(
        _transaction_path(root),
        (json.dumps(transaction, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )


def _read_transaction_journal(root: Path) -> dict[str, object] | None:
    """Read one strictly constrained transaction journal, never arbitrary rollback data."""
    try:
        payload = json.loads(_transaction_path(root).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError) as error:
        raise ValueError("invalid transaction journal") from error
    if not isinstance(payload, dict):
        raise ValueError("invalid transaction journal")
    if payload.get("schema_version") != TRANSACTION_SCHEMA_VERSION:
        raise ValueError("invalid transaction journal")
    if payload.get("phase") not in {
        "prepared", "backup_ready", "rolled_back", "committed"
    }:
        raise ValueError("invalid transaction journal")
    generation = payload.get("generation")
    previous_current = payload.get("previous_current")
    if (
        not isinstance(generation, str)
        or not _is_valid_generation_name(generation)
        or (previous_current is not None and (
            not isinstance(previous_current, str)
            or not _is_valid_generation_name(previous_current)
        ))
        or not isinstance(payload.get("catalog_existed"), bool)
    ):
        raise ValueError("invalid transaction journal")
    configs = payload.get("configs")
    if not isinstance(configs, list):
        raise ValueError("invalid transaction journal")
    allowed_configs = {str(path) for path in _codex_config_paths()}
    for config in configs:
        if (
            not isinstance(config, dict)
            or not isinstance(config.get("path"), str)
            or config["path"] not in allowed_configs
            or not _valid_config_rollback_state(config.get("rollback"))
        ):
            raise ValueError("invalid transaction journal")
    return payload


def _restore_config_rollback_state(path: Path, state: dict[str, object]) -> None:
    """Restore only managed fields while retaining all unjournalled config content."""
    if not _valid_config_rollback_state(state):
        raise ValueError("invalid config rollback state")
    text = path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not MANAGED_CONFIG_LINE_RE.match(line)]
    fields = state["fields"]
    assert isinstance(fields, list)
    for field in fields:
        assert isinstance(field, dict)
        index = field["index"]
        key = field["key"]
        value = field["value"]
        assert isinstance(index, int)
        assert isinstance(key, str)
        assert isinstance(value, str)
        lines.insert(
            min(index, len(lines)), f"{key} = {json.dumps(value, ensure_ascii=False)}"
        )
    restored = "\n".join(lines)
    if state["trailing_newline"]:
        restored += "\n"
    _atomic_write_bytes(path, restored.encode("utf-8"))


def _recover_transaction(root: Path) -> None:
    """Idempotently finish rollback or cleanup for an interrupted transaction."""
    transaction = _read_transaction_journal(root)
    if transaction is None:
        # A crash after the durably removed journal can leave only this private
        # rollback copy; it can no longer describe an active transaction.
        _durable_unlink(_transaction_backup_path(root))
        return
    generation = transaction["generation"]
    previous_current = transaction["previous_current"]
    assert isinstance(generation, str)
    assert previous_current is None or isinstance(previous_current, str)
    staging = root / f".staging-{generation}"
    generation_target = root / generation
    backup = _transaction_backup_path(root)
    phase = transaction["phase"]
    assert isinstance(phase, str)
    if phase == "prepared":
        _durable_remove_generated_directory(staging)
        _durable_unlink(backup)
        _durable_unlink(_transaction_path(root))
        return

    if phase in {"rolled_back", "committed"}:
        _durable_unlink(backup)
        _durable_unlink(_transaction_path(root))
        return

    if previous_current is None:
        _durable_unlink(root / "current")
    else:
        _write_current_generation(root, previous_current)

    catalog = root / "effective-codex-model-catalog.json"
    if transaction["catalog_existed"]:
        try:
            previous_catalog = backup.read_bytes()
        except OSError as error:
            raise OSError("transaction catalog backup unavailable") from error
        _atomic_write_bytes(catalog, previous_catalog)

    configs = transaction["configs"]
    assert isinstance(configs, list)
    for config in configs:
        assert isinstance(config, dict)
        path = Path(config["path"])
        rollback = config["rollback"]
        assert isinstance(rollback, dict)
        _restore_config_rollback_state(path, rollback)

    if not transaction["catalog_existed"]:
        _durable_unlink(catalog)
    _durable_remove_generated_directory(generation_target)
    _durable_remove_generated_directory(staging)
    # Once every externally visible value was restored, persist that no future
    # recovery needs the backup before making its removal durable.
    _mark_transaction_phase(root, transaction, "rolled_back")
    _durable_unlink(backup)
    _durable_unlink(_transaction_path(root))


def _finalize_transaction(root: Path) -> None:
    """Durably remove a committed backup before retiring its journal last."""
    _durable_unlink(_transaction_backup_path(root))
    _durable_unlink(_transaction_path(root))


def _write_current_generation(root: Path, generation: str) -> None:
    """Publish the active generation without exposing a partially written pointer."""
    if not _is_valid_generation_name(generation):
        raise ValueError("invalid generation name")
    _atomic_write_bytes(root / "current", f"{generation}\n".encode("utf-8"))


@contextmanager
def _inventory_lock(root: Path) -> Iterator[None]:
    """Hold one non-waiting advisory lock for a complete bounded inventory run."""
    _ensure_private_root(root)
    lock_path = root / RUN_LOCK_FILE_NAME
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    locked = False
    try:
        if (lock_path.stat().st_mode & 0o777) != 0o600:
            os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise InventoryRunFailure("inventory_in_progress") from None
            raise
        locked = True
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _read_health_state(root: Path) -> dict[str, object]:
    """Return only validated, non-sensitive history from the prior health state."""
    try:
        payload = json.loads(_health_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    state: dict[str, object] = {}
    generation = payload.get("last_successful_generation")
    if isinstance(generation, str) and _is_valid_generation_name(generation):
        state["last_successful_generation"] = generation
    for key in ("last_successful_at", "last_error_at"):
        value = payload.get(key)
        if isinstance(value, str) and _is_valid_timestamp(value):
            state[key] = value
    error_code = payload.get("last_error_code")
    if isinstance(error_code, str) and error_code in STABLE_ERROR_CODES:
        state["last_error_code"] = error_code
    return state


def _write_health_state(
    root: Path,
    *,
    status: str,
    attempts: int,
    generation: Path | None = None,
    error_code: str | None = None,
) -> Path:
    """Atomically write the compact, private health state for one bounded run."""
    if status not in {"healthy", "alert"}:
        raise ValueError("invalid health status")
    if attempts not in {1, 2}:
        raise ValueError("attempts must describe the bounded retry policy")
    if status == "healthy" and generation is None:
        raise ValueError("a healthy state needs a generation")
    if status == "alert" and error_code not in STABLE_ERROR_CODES:
        raise ValueError("an alert state needs an error code")

    _ensure_private_root(root)
    timestamp = _timestamp()
    payload: dict[str, object] = {
        "schema_version": HEALTH_SCHEMA_VERSION,
        "status": status,
        "updated_at": timestamp,
        "attempts": attempts,
    }
    payload.update(_read_health_state(root))
    if generation is not None:
        payload["last_successful_generation"] = generation.name
        payload["last_successful_at"] = timestamp
    if error_code is not None:
        payload["last_error_at"] = timestamp
        payload["last_error_code"] = error_code

    target = _health_path(root)
    _atomic_write_bytes(
        target,
        (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    return target


def _stable_error_code(error: Exception) -> str:
    """Map failures to a journal- and state-safe code, never exception text."""
    if isinstance(error, (json.JSONDecodeError, UnicodeError, ValueError)):
        return "invalid_response"
    if isinstance(error, OSError):
        return "io_error"
    return "inventory_failed"


def _fetch(url: str, *, headers: dict[str, str] | None = None) -> tuple[str, str]:
    request_headers = {"User-Agent": "the-hive-openai-inventory/1"}
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


def _agent_home_files(name: str) -> list[Path]:
    agents = Path.home() / ".codex-agents"
    if not agents.is_dir():
        return []
    ignored = {"plugins", ".tmp", ".device-login-staging"}
    return sorted(
        path
        for path in agents.rglob(name)
        if ignored.isdisjoint(path.relative_to(agents).parts[:-1])
    )


def _catalog_paths() -> list[Path]:
    configured = os.environ.get("CODEX_MODEL_CATALOG")
    paths = [Path(configured)] if configured else [Path.home() / ".codex/models_cache.json"]
    paths.extend(_agent_home_files("models_cache.json"))
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
        _atomic_write_bytes(
            target,
            (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        )
        return target
    except (OSError, ValueError, TypeError):
        return None


def _codex_config_paths() -> list[Path]:
    paths = [Path.home() / ".codex/config.toml"]
    paths.extend(_agent_home_files("config.toml"))
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
        return "flex", "model_cache_missing_or_stale"
    entries = catalog.get("models", [])
    model = next(
        (entry for entry in entries if isinstance(entry, dict) and entry.get("id") == model_id),
        None,
    )
    if not model:
        return "flex", "model_missing_from_home_cache"
    tiers = model.get("service_tiers", [])
    if model_id in eligible_flex:
        return "flex", "documented_flex_evidence"
    if isinstance(tiers, list) and "flex" in tiers:
        return "flex", "home_cache_flex_without_documented_evidence"
    if isinstance(tiers, list) and tiers:
        return "flex", "home_cache_denies_flex"
    return "flex", "home_cache_has_no_service_tier"


def _plan_codex_config_updates(
    catalog: Path, catalogs: list[dict[str, object]], eligible_flex: set[str]
) -> list[dict[str, object]]:
    """Read every target before mutation, retaining only rollback-safe fields."""
    if not _is_valid_local_catalog_path(str(catalog)):
        return []
    plans: list[dict[str, object]] = []
    for path in _codex_config_paths():
        try:
            text = path.read_text(encoding="utf-8")
            tier, reason = _home_service_tier(path, catalogs, eligible_flex)
            lines = text.splitlines()
            updated: list[str] = []
            for line in lines:
                if re.match(r"^\s*(?:model_catalog_json|service_tier)\s*=", line):
                    continue
                updated.append(line)
            updated[0:0] = [
                f"model_catalog_json = {json.dumps(str(catalog), ensure_ascii=False)}",
                f'service_tier = "{tier}"',
            ]
            new_text = "\n".join(updated) + "\n"
            plans.append({
                "path": path,
                "new_text": new_text,
                "changed": new_text != text,
                "rollback": _config_rollback_state(text),
                "decision": {"config": str(path), "service_tier": tier, "reason": reason},
            })
        except (OSError, ValueError):
            continue
    return plans


def _update_codex_configs(
    catalog: Path,
    catalogs: list[dict[str, object]],
    eligible_flex: set[str],
    *,
    plans: list[dict[str, object]] | None = None,
) -> tuple[list[str], list[dict[str, str]]]:
    """Apply preplanned private replacements after their rollback journal is durable."""
    if plans is None:
        plans = _plan_codex_config_updates(catalog, catalogs, eligible_flex)
    changed: list[str] = []
    decisions: list[dict[str, str]] = []
    for plan in plans:
        decision = plan["decision"]
        path = plan["path"]
        if not isinstance(decision, dict) or not isinstance(path, Path):
            raise ValueError("invalid config update plan")
        if not all(isinstance(decision.get(key), str) for key in ("config", "service_tier", "reason")):
            raise ValueError("invalid config update plan")
        decisions.append({
            "config": decision["config"],
            "service_tier": decision["service_tier"],
            "reason": decision["reason"],
        })
        if not plan["changed"]:
            continue
        new_text = plan["new_text"]
        if not isinstance(new_text, str):
            raise ValueError("invalid config update plan")
        _atomic_write_bytes(path, new_text.encode("utf-8"))
        changed.append(str(path))
    return changed, decisions


def update(root: Path = DEFAULT_ROOT) -> Path:
    _ensure_private_root(root)
    _recover_transaction(root)
    generation = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    staging = root / f".staging-{generation}"
    staging.mkdir(mode=0o700)
    published_generation: Path | None = None
    stable_catalog: Path | None = None
    previous_current: str | None = None
    current_write_started = False
    transaction: dict[str, object] | None = None
    try:
        previous_current = _read_current_generation(root)
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
            config_plans = _plan_codex_config_updates(
                stable_catalog, catalogs, eligible_flex
            )
            transaction = _write_transaction_journal(
                root,
                generation=generation,
                previous_current=previous_current,
                catalog_existed=stable_catalog.is_file(),
                config_plans=config_plans,
            )
            if stable_catalog.is_file():
                _atomic_write_bytes(
                    _transaction_backup_path(root), stable_catalog.read_bytes()
                )
            _mark_transaction_phase(root, transaction, "backup_ready")
            # _write_effective_catalog() has already synced the catalog file.
            # This rename spans directories, so persist its target entry and
            # its source removal before any home config can reference it.
            effective_catalog.replace(stable_catalog)
            _fsync_directory(root)
            _fsync_directory(staging)
            effective_catalog = stable_catalog
            config_changes, config_decisions = _update_codex_configs(
                stable_catalog, catalogs, eligible_flex, plans=config_plans
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
        _atomic_write_bytes(staging / "pricing.html", pricing.encode("utf-8"))
        _atomic_write_bytes(staging / "models.html", models.encode("utf-8"))
        _atomic_write_bytes(
            staging / "inventory.json",
            (json.dumps(inventory, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        )
        generation_target = root / generation
        if generation_target.exists():
            raise FileExistsError(f"generation already exists: {generation}")
        # The atomic writes synced each file; sync the completed staging
        # directory, then its parent after the directory rename, before
        # publishing a current pointer to this generation.
        _fsync_directory(staging)
        staging.rename(generation_target)
        # Register the cleanup target before the parent directory sync: a
        # failed sync occurs after the rename has made this path observable.
        published_generation = generation_target
        _fsync_directory(root)
        current_write_started = True
        _write_current_generation(root, generation)
        if transaction is not None:
            # A durably committed journal means recovery must retain this new
            # catalog/config/current state even if backup cleanup is interrupted.
            _mark_transaction_phase(root, transaction, "committed")
            _finalize_transaction(root)
        generations = sorted(
            (path for path in root.iterdir() if path.is_dir() and re.fullmatch(r"\d{8}T\d{6}Z", path.name)),
            reverse=True,
        )
        retained_nonactive = 0
        for old in generations:
            if old == published_generation:
                continue
            if retained_nonactive < MAX_GENERATIONS - 1:
                retained_nonactive += 1
                continue
            try:
                _durable_remove_generated_directory(old)
            except OSError:
                continue
        return published_generation
    except Exception:
        if transaction is not None:
            _recover_transaction(root)
        else:
            current = root / "current"
            if current_write_started:
                if previous_current is not None:
                    _write_current_generation(root, previous_current)
                else:
                    _durable_unlink(current)
            if published_generation is not None:
                _durable_remove_generated_directory(published_generation)
            _durable_remove_generated_directory(staging)
        raise


def run(
    root: Path = DEFAULT_ROOT,
    *,
    pause: Callable[[float], None] = time.sleep,
    retry_delay_seconds: float = RETRY_DELAY_SECONDS,
) -> Path:
    """Run one inventory update and, at most once, retry a failed attempt."""
    with _inventory_lock(root):
        for attempts in (1, 2):
            try:
                generation = update(root)
            except Exception as error:
                error_code = _stable_error_code(error)
                if attempts == 1:
                    pause(retry_delay_seconds)
                    continue
                _write_health_state(
                    root,
                    status="alert",
                    attempts=attempts,
                    error_code=error_code,
                )
                raise InventoryRunFailure(error_code) from None
            _write_health_state(
                root,
                status="healthy",
                attempts=attempts,
                generation=generation,
            )
            return generation
    raise AssertionError("the bounded retry loop did not return or fail")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args(argv)
    try:
        print(run(args.root))
    except InventoryRunFailure as error:
        print(f"openai-pricing-inventory: {error.error_code}", file=sys.stderr)
        return 1
    except Exception:
        print("openai-pricing-inventory: health_state_write_failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
