from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import time

import pytest


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/python3\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_bounded_runner_uses_an_explicit_minimal_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_master.runtime_process import run_bounded

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    child = _script(
        tmp_path / "environment.py",
        "import json, os\n"
        "print(json.dumps({'codex': any(key.startswith('CODEX_') for key in os.environ), "
        "'pythonpath': 'PYTHONPATH' in os.environ, 'path': os.environ.get('PATH'), 'home': os.environ.get('HOME')}))\n",
    )
    monkeypatch.setenv("PATH", "/attacker/path")
    monkeypatch.setenv("PYTHONPATH", "/attacker/python")
    monkeypatch.setenv("CODEX_HOME", "/attacker/codex")
    monkeypatch.setenv("CODEX_MASTER_MCP_STATE", "/attacker/state")

    result = run_bounded([str(child)], cwd=tmp_path, home=home, timeout_seconds=1)

    assert result.returncode == 0
    assert json.loads(result.stdout) == {
        "codex": False,
        "pythonpath": False,
        "path": "/usr/bin:/bin",
        "home": str(home),
    }


@pytest.mark.parametrize("stream", ("stdout", "stderr"))
def test_bounded_runner_rejects_each_output_overflow(tmp_path: Path, stream: str) -> None:
    from codex_master.runtime_process import BoundedProcessError, run_bounded

    child = _script(
        tmp_path / f"overflow-{stream}.py",
        f"import sys\nsys.{stream}.write('x' * 4096)\nsys.{stream}.flush()\n",
    )

    with pytest.raises(BoundedProcessError, match=f"command_{stream}_limit"):
        run_bounded(
            [str(child)],
            cwd=tmp_path,
            home=tmp_path,
            timeout_seconds=1,
            stdout_limit=128,
            stderr_limit=128,
        )


def test_bounded_runner_times_out_and_terminates_the_whole_process_group(tmp_path: Path) -> None:
    from codex_master.runtime_process import BoundedProcessError, run_bounded

    child_pid = tmp_path / "child.pid"
    child = _script(
        tmp_path / "timeout.py",
        "import subprocess, sys, time\n"
        "child = subprocess.Popen(['/usr/bin/python3', '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(child_pid)!r}, 'w', encoding='utf-8').write(str(child.pid))\n"
        "time.sleep(60)\n",
    )

    with pytest.raises(BoundedProcessError, match="command_timeout"):
        run_bounded([str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=0.1)

    deadline = time.monotonic() + 2
    while not child_pid.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert child_pid.exists()
    process_id = int(child_pid.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(process_id, 0)
        except OSError as exc:
            assert exc.errno == errno.ESRCH
            break
        time.sleep(0.02)
    else:
        pytest.fail("descendant process survived bounded-runner termination")
