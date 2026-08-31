"""One explicit non-secret state boundary shared by Admin and Agent API."""

from __future__ import annotations

import grp
import os
from pathlib import Path


AGENT_STATE_ROOT = Path("/var/lib/codex-master-agent")
AGENT_STATE_GROUP = "codex-master-agent-state"
ADMIN_STATE_ROOT = Path("/var/lib/codex-master-admin")


def agent_state_group_id() -> int:
    """Resolve the static group provisioned by the Task-9 sysusers contract."""

    try:
        return grp.getgrnam(AGENT_STATE_GROUP).gr_gid
    except KeyError as exc:
        raise RuntimeError("agent.state_group_unavailable") from exc


def resolve_agent_state_boundary(admin_state_root: Path) -> tuple[Path, int]:
    """Use static production ownership; keep explicit local runs self-contained."""

    if not isinstance(admin_state_root, Path) or not admin_state_root.is_absolute():
        raise RuntimeError("agent.state_root_unavailable")
    if admin_state_root == ADMIN_STATE_ROOT:
        return AGENT_STATE_ROOT, agent_state_group_id()
    return admin_state_root.with_name(f"{admin_state_root.name}-agent"), os.getegid()
