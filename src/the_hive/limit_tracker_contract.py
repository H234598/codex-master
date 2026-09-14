"""Read-only OpenAI limit trend calculations for Masterjet's Fast gate."""

from __future__ import annotations

import json
import math
import os
import shutil
import secrets
import sqlite3
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HISTORY_DB = Path.home() / ".local/share/codex-usage/usage-history.sqlite3"
SNAPSHOTS = Path.home() / ".local/share/codex-usage/snapshots"
STATE_ROOT = Path.home() / ".local/state/codex-master-mcp"
CODEX_USAGE_EMERGENCY_OVERRIDES = STATE_ROOT / "codex-usage-emergency-overrides.json"
SPARK_PRIORITY_STATE = STATE_ROOT / "spark-priority.json"
EMERGENCY_QUEEN_REQUEST = STATE_ROOT / "emergency-queen-work.json"
EMERGENCY_QUEEN_STATE = STATE_ROOT / "emergency-queen-state.json"
EMA_MINUTES = 60
FAST_START_THRESHOLD = 10.0
FAST_STOP_THRESHOLD = -15.0
FAST_START_HORIZON_SECONDS = 18_000
HOT_WEEKLY_USED_PERCENT = 80.0
HOT_WEEKLY_WINDOWS = 5
HOT_PER_WINDOW_PERCENT = 85.0
FIVE_HOUR_SECONDS = 18_000
EMERGENCY_QUEEN_ACTIVE_STATES = frozenset({"requested", "running", "finishing", "next", "draining"})


def emergency_refresh_needed(evaluation: dict[str, Any], *, active_fast: bool = False) -> bool:
    """Return whether the emergency path may spend an API pull.

    The normal tracker is intentionally snapshot-only.  In the hot end-window
    regime, or while Fast is already active, freshness is more valuable than
    the cost of another usage request.
    """
    if active_fast:
        return True
    tracker = evaluation.get("five_hour_tracker", {})
    weekly = next(
        (item for item in evaluation.get("weekly_monthly", []) if item.get("window") == "weekly"),
        {},
    )
    used = weekly.get("used_percent")
    count = tracker.get("five_hour_windows_until_weekly_reset")
    return (
        isinstance(used, (int, float))
        and used >= HOT_WEEKLY_USED_PERCENT
        and isinstance(count, int)
        and count <= HOT_WEEKLY_WINDOWS
    )


def refresh_usage_snapshots() -> dict[str, Any]:
    """Pull fresh account usage through codex-usage for the emergency gate."""
    command = os.environ.get("CODEX_USAGE_COMMAND", str(Path.home() / ".local/bin/codex-usage"))
    if not os.path.isabs(command):
        command = shutil.which(command) or command
    config = os.environ.get(
        "CODEX_USAGE_CONFIG",
        str(Path.home() / ".config/codex-usage/config.toml"),
    )
    argv = [command]
    if config and Path(config).is_file():
        argv.extend(("--config", config))
    argv.extend(("once", "--format", "json"))
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
            start_new_session=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"attempted": True, "ok": False, "error": type(exc).__name__}
    return {
        "attempted": True,
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "error": "usage_pull_failed" if completed.returncode else None,
    }


def _dt(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.astimezone(UTC) if result.tzinfo else None


def _ema_rate(rows: list[tuple[float, int]], now_ms: int) -> float:
    ema: float | None = None
    previous: tuple[float, int] | None = None
    tau = EMA_MINUTES * 60.0
    for used, captured_ms in rows:
        if previous is None:
            previous = (used, captured_ms)
            continue
        gap = (captured_ms - previous[1]) / 1000.0
        if gap <= 0 or gap > 3600:
            previous = (used, captured_ms)
            continue
        delta = used - previous[0]
        if delta < 0:
            delta = max(0.0, used)
        rate = delta / gap
        alpha = 1.0 - math.exp(-gap / tau)
        ema = rate if ema is None else ema + alpha * (rate - ema)
        previous = (used, captured_ms)
    return max(0.0, ema or 0.0)


def _window(
    account: str,
    window: dict[str, Any],
    *,
    active_fast: bool,
    pool: str = "main",
) -> dict[str, Any]:
    now = datetime.now(UTC)
    reset = _dt(window.get("reset_at"))
    used = float(window.get("used", 0.0)) if isinstance(window.get("used"), (int, float)) else None
    if reset is None or used is None:
        return {"available": False, "reason": "missing_window_data", "window": window.get("name")}
    remaining_seconds = max(0.0, (reset - now).total_seconds())
    rows: list[tuple[float, int]] = []
    try:
        with sqlite3.connect(HISTORY_DB) as db:
            rows = [
                (float(row[0]), int(row[1]))
                for row in db.execute(
                    "SELECT used_percent,captured_at_ms FROM samples WHERE account_id=? AND pool_key=? AND window_seconds=? AND captured_at_ms>=? ORDER BY captured_at_ms",
                    (account, pool, int(window.get("duration_seconds") or (604800 if window.get("name") == "weekly" else 2592000)), int((now.timestamp() - 86400) * 1000)),
                )
            ]
    except (OSError, sqlite3.Error, TypeError, ValueError):
        rows = []
    rate = _ema_rate(rows, int(now.timestamp() * 1000))
    projected = min(200.0, used + rate * remaining_seconds)
    deviation = projected - 100.0
    start = (
        deviation > FAST_START_THRESHOLD and remaining_seconds <= FAST_START_HORIZON_SECONDS
        if not active_fast
        else deviation > FAST_STOP_THRESHOLD
    )
    return {
        "available": True,
        "window": window.get("name"),
        "pool": pool,
        "used_percent": round(used, 3),
        "ema_minutes": EMA_MINUTES,
        "ema_rate_pp_per_second": round(rate, 8),
        "remaining_seconds": round(remaining_seconds, 1),
        "projected_percent_at_reset": round(projected, 3),
        "deviation_from_limit_pp": round(deviation, 3),
        "threshold_start_pp": FAST_START_THRESHOLD,
        "start_horizon_seconds": FAST_START_HORIZON_SECONDS,
        "threshold_stop_pp": FAST_STOP_THRESHOLD if active_fast else None,
        "fast_recommendation": "keep_fast" if active_fast and start else ("activate" if start else "flex"),
        "sample_count": len(rows),
    }


def evaluate_account(account: str, *, active_fast: bool = False) -> dict[str, Any]:
    try:
        payload = json.loads((SNAPSHOTS / f"{account}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {"account": account, "available": False, "reason": "snapshot_unavailable"}
    windows = []
    for key in ("weekly", "monthly"):
        value = payload.get(key)
        if isinstance(value, dict):
            windows.append(_window(account, value, active_fast=active_fast))
    main = payload.get("main") if isinstance(payload, dict) else None
    five_hour = None
    if isinstance(main, dict):
        five_hour = next((item for item in main.get("windows", []) if isinstance(item, dict) and item.get("name") == "5h"), None)
    five_tracker = {"available": False, "reason": "missing_5h_window"}
    if isinstance(five_hour, dict):
        reset = _dt(five_hour.get("reset_at"))
        five_tracker = {
            "available": reset is not None,
            "remaining_seconds": max(0, round((reset - datetime.now(UTC)).total_seconds())) if reset else None,
            "five_hour_windows_until_weekly_reset": None,
        }
        weekly_reset = _dt(payload.get("weekly", {}).get("reset_at")) if isinstance(payload.get("weekly"), dict) else None
        if reset and weekly_reset:
            five_tracker["five_hour_windows_until_weekly_reset"] = max(
                0, math.ceil(max(0, (weekly_reset - datetime.now(UTC)).total_seconds()) / FIVE_HOUR_SECONDS)
            )
            weekly_value = payload.get("weekly")
            weekly_used = weekly_value.get("used") if isinstance(weekly_value, dict) else None
            weekly_remaining = 100.0 - float(weekly_used) if isinstance(weekly_used, (int, float)) else None
            five_tracker["weekly_remaining_percent"] = weekly_remaining
            count = five_tracker["five_hour_windows_until_weekly_reset"]
            five_tracker["weekly_budget_per_remaining_5h_window"] = (
                round(weekly_remaining / count, 3)
                if isinstance(weekly_remaining, float) and count
                else None
            )
            five_tracker["current_five_hour_used_percent"] = five_hour.get("used")
            five_tracker["zero_landing_is_realistic"] = (
                isinstance(weekly_remaining, float) and weekly_remaining >= 0
            )
        five_projection = _window(account, five_hour, active_fast=active_fast, pool="main")
    else:
        five_projection = {"available": False, "reason": "missing_5h_window"}
    activate = any(item.get("fast_recommendation") == "activate" for item in windows)
    keep_fast = active_fast and any(item.get("fast_recommendation") in {"keep_fast", "activate"} for item in windows)
    weekly_projection = next((item for item in windows if item.get("window") == "weekly"), None)
    if weekly_projection is not None:
        five_tracker["projected_weekly_deviation_pp"] = weekly_projection.get("deviation_from_limit_pp")
        five_tracker["zero_landing_projection"] = weekly_projection.get("projected_percent_at_reset")
        five_tracker["zero_landing_is_realistic"] = (
            isinstance(weekly_projection.get("deviation_from_limit_pp"), (int, float))
            and weekly_projection["deviation_from_limit_pp"] <= 0
        )
    spark_windows: list[dict[str, Any]] = []
    models = payload.get("models") if isinstance(payload, dict) else None
    spark_payload = models.get("gpt-5.3-codex-spark") if isinstance(models, dict) else None
    if isinstance(spark_payload, dict):
        for item in spark_payload.get("windows", []):
            if isinstance(item, dict) and item.get("name") in {"5h", "weekly", "monthly", "30d"}:
                spark_windows.append(_window(account, item, active_fast=False, pool="spark"))
    spark_recommendation = "flex"
    if spark_windows:
        spark_recommendation = "activate" if any(
            item.get("deviation_from_limit_pp", 0) > FAST_START_THRESHOLD
            and item.get("remaining_seconds", FAST_START_HORIZON_SECONDS + 1) <= FAST_START_HORIZON_SECONDS
            for item in spark_windows
        ) else "flex"
    return {
        "account": account,
        "available": True,
        "ema_minutes": EMA_MINUTES,
        "weekly_monthly": windows,
        "five_hour_projection": five_projection,
        "five_hour_tracker": five_tracker,
        "spark": {
            "available": bool(spark_windows),
            "windows": spark_windows,
            "recommended_action": spark_recommendation,
        },
        "recommended_action": "activate" if activate else ("keep_fast" if keep_fast else "flex"),
        "raw_output": "not_returned",
    }


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _read_state_file(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return dict(default or {})
    return value if isinstance(value, dict) else dict(default or {})


@contextmanager
def _emergency_queen_lock():
    """Serialize Queen state transitions across concurrent MCP processes."""
    lock_path = STATE_ROOT / "emergency-queen.lock"
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+", encoding="utf-8")
    try:
        try:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            # The state transition remains atomic; platforms without flock
            # still get the generation check and atomic replacement.
            pass
        yield
    finally:
        try:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (ImportError, OSError):
            pass
        handle.close()


def emergency_queen_status() -> dict[str, Any]:
    """Return the bounded, durable emergency-Queen state without secrets."""
    value = _read_state_file(EMERGENCY_QUEEN_STATE)
    state = value.get("state")
    if state not in {"idle", "requested", "running", "finishing", "next", "draining", "blocked"}:
        state = "idle"
    generation = value.get("generation")
    if not isinstance(generation, int) or generation < 0:
        generation = 0
    plans = value.get("plans")
    if not isinstance(plans, list):
        plans = []
    plans = [item for item in plans[:64] if isinstance(item, str)][:64]
    return {
        "state": state,
        "generation": generation,
        "queen_agent": value.get("queen_agent") if isinstance(value.get("queen_agent"), str) else None,
        "children": [item for item in value.get("children", [])[:32] if isinstance(item, str)]
            if isinstance(value.get("children"), list) else [],
        "current_plan": value.get("current_plan") if isinstance(value.get("current_plan"), str) else None,
        "plans": plans,
        "emergency_active": value.get("emergency_active") is True,
        "reason": value.get("reason") if isinstance(value.get("reason"), str) else None,
        "blocked_reason": value.get("blocked_reason") if isinstance(value.get("blocked_reason"), str) else None,
        "raw_output": "not_returned",
    }


def _queen_candidates() -> list[str]:
    plans_root = Path.home() / "Dokumente/Obsidian_Vaults/Teladi_Programming/Projekte/codex-master/Baupläne!"
    candidates: list[str] = []
    try:
        for path in sorted(plans_root.glob("*.md"))[:256]:
            text = path.read_text(encoding="utf-8", errors="replace")[:32_000].lower()
            if any(marker in text for marker in ("status: approved", "freigegeben", "in umsetzung")):
                candidates.append(str(path))
    except OSError:
        pass
    return candidates[:64]


def _queen_state_payload(
    *, state: str, generation: int, reason: str, plans: list[str],
    current_plan: str | None, emergency_active: bool, queen_agent: str | None = None,
    blocked_reason: str | None = None, children: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "state": state,
        "generation": generation,
        "reason": reason[:200],
        "plans": plans[:64],
        "current_plan": current_plan,
        "emergency_active": emergency_active,
        "queen_agent": queen_agent,
        "children": [item for item in (children or [])[:32] if isinstance(item, str)],
        "blocked_reason": blocked_reason[:200] if isinstance(blocked_reason, str) else None,
        "updated_at_utc": datetime.now(UTC).isoformat(),
    }


def set_emergency_display_override(
    account: str,
    *,
    enabled: bool,
    limit_window: str | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Publish a bounded, reversible display override for the Cinnamon applet."""
    try:
        current = json.loads(CODEX_USAGE_EMERGENCY_OVERRIDES.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        current = {}
    if not isinstance(current, dict):
        current = {}
    if enabled:
        current[account] = {
            "active": True,
            "delta_enabled": True,
            "limit_window": limit_window if limit_window in {"short", "weekly", "monthly", "spark"} else "short",
            "reason": reason[:200],
        }
    else:
        current.pop(account, None)
    _write_state(CODEX_USAGE_EMERGENCY_OVERRIDES, current)
    return {"account": account, "active": enabled, "limit_window": current.get(account, {}).get("limit_window")}


def set_spark_priority(account: str, *, enabled: bool, reason: str = "") -> dict[str, Any]:
    """Publish Spark worker-selection priority without changing leadership routing."""
    try:
        current = json.loads(SPARK_PRIORITY_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        current = {}
    if not isinstance(current, dict):
        current = {}
    if enabled:
        current[account] = {"active": True, "reason": reason[:200]}
    else:
        current.pop(account, None)
    _write_state(SPARK_PRIORITY_STATE, current)
    return {"account": account, "active": enabled}


def spark_priority_active(account: str) -> bool:
    try:
        payload = json.loads(SPARK_PRIORITY_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return False
    return isinstance(payload, dict) and isinstance(payload.get(account), dict) and payload[account].get("active") is True


def preferred_delta_window(payload: dict[str, Any], *, pool: str = "main") -> str:
    """Choose the most useful available window for the emergency delta display."""
    if not isinstance(payload, dict):
        return "short"
    if pool == "spark":
        models = payload.get("models")
        source = models.get("gpt-5.3-codex-spark") if isinstance(models, dict) else None
        windows = source.get("windows", []) if isinstance(source, dict) else []
    else:
        source = payload.get("main")
        windows = source.get("windows", []) if isinstance(source, dict) else []
        if isinstance(payload.get("weekly"), dict):
            windows = list(windows) + [payload["weekly"]]
        if isinstance(payload.get("monthly"), dict):
            windows = list(windows) + [payload["monthly"]]
    names = {item.get("name") for item in windows if isinstance(item, dict)}
    for candidate in (("5h", "short"), ("weekly", "weekly"), ("monthly", "monthly"), ("30d", "monthly")):
        if candidate[0] in names:
            return candidate[1]
    return "short"


def request_emergency_queen_work(*, reason: str) -> dict[str, Any]:
    """Create one idempotent emergency-Queen request and plan queue."""
    with _emergency_queen_lock():
        current = emergency_queen_status()
        if current["state"] in EMERGENCY_QUEEN_ACTIVE_STATES:
            return {"queued": False, "duplicate": True, "state": current, "raw_output": "not_returned"}
        candidates = _queen_candidates()
        generation = int(current["generation"]) + 1
        selected = secrets.choice(candidates) if candidates else None
        state = _queen_state_payload(
            state="requested", generation=generation, reason=reason,
            plans=candidates, current_plan=selected, emergency_active=True,
        )
        _write_state(EMERGENCY_QUEEN_STATE, state)
        request = {
            "active": True,
            "requested_at_utc": state["updated_at_utc"],
            "reason": reason[:200],
            "candidate_count": len(candidates),
            "candidates": candidates,
            "selected_plan": selected,
            "selection": "random_approved_plan",
            "class": "koenigin",
            "lifecycle": "persistent",
            "spawn_required": True,
            "generation": generation,
        }
        _write_state(EMERGENCY_QUEEN_REQUEST, request)
        return {"queued": True, "duplicate": False, "candidate_count": len(candidates), "state": emergency_queen_status(), "raw_output": "not_returned"}


def set_emergency_queen_running(generation: int, agent: str) -> dict[str, Any]:
    with _emergency_queen_lock():
        current = emergency_queen_status()
        if current["generation"] != generation or current["state"] not in {"requested", "blocked"}:
            return {"updated": False, "state": current, "raw_output": "not_returned"}
        payload = _queen_state_payload(
            state="running", generation=generation, reason=current["reason"] or "Notfallmodus",
            plans=current["plans"], current_plan=current["current_plan"],
            emergency_active=True, queen_agent=agent, children=current["children"],
        )
        _write_state(EMERGENCY_QUEEN_STATE, payload)
        return {"updated": True, "state": emergency_queen_status(), "raw_output": "not_returned"}


def set_emergency_queen_blocked(generation: int, reason: str) -> dict[str, Any]:
    with _emergency_queen_lock():
        current = emergency_queen_status()
        if current["generation"] != generation:
            return {"updated": False, "state": current, "raw_output": "not_returned"}
        payload = _queen_state_payload(
            state="blocked", generation=generation, reason=current["reason"] or "Notfallmodus",
            plans=current["plans"], current_plan=current["current_plan"],
            emergency_active=True, queen_agent=current["queen_agent"], blocked_reason=reason,
            children=current["children"],
        )
        _write_state(EMERGENCY_QUEEN_STATE, payload)
        return {"updated": True, "state": emergency_queen_status(), "raw_output": "not_returned"}


def advance_emergency_queen(generation: int, *, emergency_active: bool, completed_plan: str) -> dict[str, Any]:
    """Advance one completed plan or drain the Queen after emergency mode."""
    with _emergency_queen_lock():
        current = emergency_queen_status()
        if current["generation"] != generation or current["state"] not in {"running", "finishing", "next"}:
            return {"updated": False, "state": current, "raw_output": "not_returned"}
        remaining = [plan for plan in current["plans"] if plan != completed_plan]
        if emergency_active and remaining:
            next_plan = secrets.choice(remaining)
            state = "next"
            active = True
        else:
            next_plan = None
            state = "draining"
            active = False
        payload = _queen_state_payload(
            state=state, generation=generation, reason=current["reason"] or "Notfallmodus",
            plans=remaining, current_plan=next_plan, emergency_active=active,
            queen_agent=current["queen_agent"], children=current["children"],
        )
        _write_state(EMERGENCY_QUEEN_STATE, payload)
        return {"updated": True, "state": emergency_queen_status(), "raw_output": "not_returned"}


def finish_emergency_queen(generation: int) -> dict[str, Any]:
    with _emergency_queen_lock():
        current = emergency_queen_status()
        if current["generation"] != generation:
            return {"updated": False, "state": current, "raw_output": "not_returned"}
        payload = _queen_state_payload(
            state="idle", generation=generation, reason=current["reason"] or "Notfallmodus beendet",
            plans=[], current_plan=None, emergency_active=False,
            children=[],
        )
        _write_state(EMERGENCY_QUEEN_STATE, payload)
        _write_state(EMERGENCY_QUEEN_REQUEST, {"active": False, "generation": generation})
        return {"updated": True, "state": emergency_queen_status(), "raw_output": "not_returned"}


def register_emergency_queen_child(generation: int, agent: str) -> dict[str, Any]:
    """Persist one managed child so draining waits for it as well."""
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        return {"updated": False, "reason": "invalid_generation", "raw_output": "not_returned"}
    if not isinstance(agent, str) or not agent or len(agent) > 128:
        return {"updated": False, "reason": "invalid_agent", "raw_output": "not_returned"}
    with _emergency_queen_lock():
        current = emergency_queen_status()
        if current["generation"] != generation or current["state"] not in EMERGENCY_QUEEN_ACTIVE_STATES:
            return {"updated": False, "state": current, "raw_output": "not_returned"}
        children = list(current["children"])
        if agent not in children:
            children.append(agent)
        payload = _queen_state_payload(
            state=current["state"], generation=generation,
            reason=current["reason"] or "Notfallmodus", plans=current["plans"],
            current_plan=current["current_plan"], emergency_active=current["emergency_active"],
            queen_agent=current["queen_agent"], blocked_reason=current["blocked_reason"],
            children=children,
        )
        _write_state(EMERGENCY_QUEEN_STATE, payload)
        return {"updated": True, "state": emergency_queen_status(), "raw_output": "not_returned"}


def unregister_emergency_queen_child(generation: int, agent: str) -> dict[str, Any]:
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        return {"updated": False, "reason": "invalid_generation", "raw_output": "not_returned"}
    with _emergency_queen_lock():
        current = emergency_queen_status()
        if current["generation"] != generation:
            return {"updated": False, "state": current, "raw_output": "not_returned"}
        children = [item for item in current["children"] if item != agent]
        payload = _queen_state_payload(
            state=current["state"], generation=generation,
            reason=current["reason"] or "Notfallmodus", plans=current["plans"],
            current_plan=current["current_plan"], emergency_active=current["emergency_active"],
            queen_agent=current["queen_agent"], blocked_reason=current["blocked_reason"],
            children=children,
        )
        _write_state(EMERGENCY_QUEEN_STATE, payload)
        return {"updated": True, "state": emergency_queen_status(), "raw_output": "not_returned"}


def emergency_recommendation(evaluation: dict[str, Any], *, active_fast: bool = False) -> str:
    """Cheap 10-minute guard for the final weekly-window regime."""
    tracker = evaluation.get("five_hour_tracker", {})
    weekly = next((item for item in evaluation.get("weekly_monthly", []) if item.get("window") == "weekly"), {})
    five = evaluation.get("five_hour_projection", {})
    used = weekly.get("used_percent")
    count = tracker.get("five_hour_windows_until_weekly_reset")
    hot = isinstance(used, (int, float)) and used >= HOT_WEEKLY_USED_PERCENT and isinstance(count, int) and count <= HOT_WEEKLY_WINDOWS
    weekly_hot = isinstance(weekly.get("deviation_from_limit_pp"), (int, float)) and weekly["deviation_from_limit_pp"] > HOT_PER_WINDOW_PERCENT
    five_hot = isinstance(five.get("deviation_from_limit_pp"), (int, float)) and five["deviation_from_limit_pp"] > FAST_START_THRESHOLD
    if active_fast:
        weekly_stop = isinstance(weekly.get("deviation_from_limit_pp"), (int, float)) and weekly["deviation_from_limit_pp"] <= FAST_STOP_THRESHOLD
        five_stop = isinstance(five.get("deviation_from_limit_pp"), (int, float)) and five["deviation_from_limit_pp"] <= FAST_STOP_THRESHOLD
        return "flex" if weekly_stop and five_stop else "keep_fast"
    return "activate" if hot and (weekly_hot or five_hot) else "flex"
