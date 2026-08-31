from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_master.agent_ollama import (
    AgentOllamaError,
    AgentOllamaExecutor,
    validate_private_path,
)


class Runtime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def plan(self, arguments: object) -> dict[str, object]:
        self.calls.append(("plan", arguments))
        return {"plan_ref": "plan-one"}

    def apply(self, arguments: object) -> dict[str, object]:
        self.calls.append(("apply", arguments))
        return {"instance_ref": "instance-one"}

    def probe(self, arguments: object) -> dict[str, object]:
        self.calls.append(("probe", arguments))
        return {"ready": True}

    def stop(self, arguments: object) -> dict[str, object]:
        self.calls.append(("stop", arguments))
        return {"stopped": True}


def test_each_closed_action_has_exact_arguments() -> None:
    runtime = Runtime()
    executor = AgentOllamaExecutor(runtime)
    assert (
        executor.plan({"instance_ref": "one", "generation": 2})["plan_ref"]
        == "plan-one"
    )
    assert executor.apply({"plan_ref": "one"})["instance_ref"] == "instance-one"
    assert executor.probe({"instance_ref": "one", "generation": 2})["ready"] is True
    assert executor.stop({"instance_ref": "one", "generation": 2})["stopped"] is True
    with pytest.raises(AgentOllamaError, match="host.arguments_invalid"):
        executor.apply({"plan_ref": "one", "free": "form"})


def test_private_absolute_path_is_allowlisted_owned_regular_and_nofollow(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    target = allowed / "ollama"
    target.write_text("binary")
    assert (
        validate_private_path(
            str(target),
            roots=(tmp_path / "missing", allowed),
            owner_uid=os.geteuid(),
            kind="file",
        )
        == target
    )
    link = allowed / "link"
    link.symlink_to(target)
    linked_directory = allowed / "linked-directory"
    real_directory = allowed / "real-directory"
    real_directory.mkdir()
    linked_directory.symlink_to(real_directory)
    nested = linked_directory / "nested"
    nested.write_text("data")
    for candidate in (link, nested, tmp_path / "outside"):
        with pytest.raises(AgentOllamaError, match="resource.path_invalid"):
            validate_private_path(
                str(candidate), roots=(allowed,), owner_uid=os.geteuid(), kind="file"
            )

    ancestor_link = tmp_path / "ancestor-link"
    ancestor_link.symlink_to(tmp_path, target_is_directory=True)
    linked_root = ancestor_link / "allowed"
    with pytest.raises(AgentOllamaError, match="resource.path_invalid"):
        validate_private_path(
            str(linked_root / "ollama"),
            roots=(linked_root,),
            owner_uid=os.geteuid(),
            kind="file",
        )


def test_private_directory_type_and_owner_are_checked(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    assert (
        validate_private_path(
            str(allowed), roots=(allowed,), owner_uid=os.geteuid(), kind="directory"
        )
        == allowed
    )
    with pytest.raises(AgentOllamaError, match="resource.path_invalid"):
        validate_private_path(
            str(allowed), roots=(allowed,), owner_uid=os.geteuid() + 1, kind="directory"
        )
