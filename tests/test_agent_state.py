from pathlib import Path

from codex_master.agent_state import resolve_agent_state_boundary


def test_local_admin_state_gets_one_sibling_agent_boundary() -> None:
    root, gid = resolve_agent_state_boundary(Path("/tmp/codex-master-admin-test"))

    assert root == Path("/tmp/codex-master-admin-test-agent")
    assert isinstance(gid, int) and gid >= 0
