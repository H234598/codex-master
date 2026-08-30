from __future__ import annotations

import contextlib
import errno
import json
import os
from pathlib import Path
import signal
import time
from types import SimpleNamespace

import pytest


pytestmark = pytest.mark.usefixtures("runtime_spawn_helper")


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/python3\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_runtime_spawn_helper_has_a_compiled_glibc_header_contract() -> None:
    import codex_master.runtime_process as runtime_process

    helper = Path(runtime_process.__file__).with_name("runtime_spawn_helper.c")
    helper_source = helper.read_text(encoding="utf-8")
    runner_source = Path(runtime_process.__file__).read_text(encoding="utf-8")

    assert "#include <spawn.h>" in helper_source
    assert "__GLIBC_PREREQ(2, 39)" in helper_source
    assert "POSIX_SPAWN_SETSID" in helper_source
    assert "pidfd_spawnp" in helper_source
    assert "create_string_buffer" not in runner_source
    assert "_SPAWN_BUFFER_BYTES" not in runner_source


def test_bounded_runner_uses_an_explicit_minimal_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
def test_bounded_runner_rejects_each_output_overflow(
    tmp_path: Path, stream: str
) -> None:
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


def test_bounded_runner_times_out_and_terminates_the_whole_process_group(
    tmp_path: Path,
) -> None:
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
        run_bounded([str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=1)

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


def test_bounded_runner_times_out_while_a_child_does_not_read_64k_stdin(
    tmp_path: Path,
) -> None:
    from codex_master.runtime_process import BoundedProcessError, run_bounded

    child = _script(
        tmp_path / "does-not-read-stdin.py",
        "import time\ntime.sleep(3)\n",
    )
    started = time.monotonic()

    with pytest.raises(BoundedProcessError, match="command_timeout"):
        run_bounded(
            [str(child)],
            cwd=tmp_path,
            home=tmp_path,
            timeout_seconds=0.1,
            input_data=b"x" * (64 * 1024),
        )

    assert time.monotonic() - started < 1


def test_bounded_runner_rejects_a_nul_cwd_without_starting_a_child(
    tmp_path: Path,
) -> None:
    from codex_master.runtime_process import BoundedProcessError, run_bounded

    marker = tmp_path / "started"
    child = _script(
        tmp_path / "must-not-run-with-nul-cwd.py",
        f"open({str(marker)!r}, 'w', encoding='utf-8').write('started')\n",
    )
    nul_cwd = Path(os.fspath(tmp_path) + "\x00suffix")

    with pytest.raises(BoundedProcessError, match="command_arguments_invalid"):
        run_bounded([str(child)], cwd=nul_cwd, home=tmp_path, timeout_seconds=1)

    assert not marker.exists()


def test_bounded_runner_fails_before_opening_fds_when_native_spawn_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.runtime_process as runtime_process

    marker = tmp_path / "started"
    child = _script(
        tmp_path / "must-not-run-without-native-spawn.py",
        f"open({str(marker)!r}, 'w', encoding='utf-8').write('started')\n",
    )
    descriptors_before = len(list(Path("/proc/self/fd").iterdir()))

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise runtime_process.BoundedProcessError("command_group_unavailable")

    monkeypatch.setattr(
        runtime_process, "_load_runtime_spawn_helper", unavailable, raising=False
    )

    with pytest.raises(
        runtime_process.BoundedProcessError, match="command_group_unavailable"
    ):
        runtime_process.run_bounded(
            [str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=1
        )

    assert not marker.exists()
    assert len(list(Path("/proc/self/fd").iterdir())) == descriptors_before


def test_bounded_runner_handles_partial_stdin_and_epipe(
    tmp_path: Path,
) -> None:
    from codex_master.runtime_process import run_bounded

    child = _script(
        tmp_path / "read-one-byte.py",
        "import os\nos.read(0, 1)\nprint('read-one-byte')\n",
    )

    result = run_bounded(
        [str(child)],
        cwd=tmp_path,
        home=tmp_path,
        timeout_seconds=1,
        input_data=b"x" * (64 * 1024),
    )

    assert result.returncode == 0
    assert result.stdout == "read-one-byte\n"


def test_bounded_runner_delivers_all_64k_stdin_within_the_shared_deadline(
    tmp_path: Path,
) -> None:
    from codex_master.runtime_process import run_bounded

    child = _script(
        tmp_path / "read-all-stdin.py",
        "import sys\ndata = sys.stdin.buffer.read()\nprint(len(data))\n",
    )

    result = run_bounded(
        [str(child)],
        cwd=tmp_path,
        home=tmp_path,
        timeout_seconds=1,
        input_data=b"x" * (64 * 1024),
    )

    assert result.returncode == 0
    assert result.stdout == "65536\n"


def _wait_until_process_is_not_live(process_id: int) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(process_id, 0)
        except OSError as exc:
            assert exc.errno == errno.ESRCH
            return
        try:
            state = (
                (Path("/proc") / str(process_id) / "stat")
                .read_text(encoding="utf-8")
                .split(") ", 1)[1][0]
            )
        except (FileNotFoundError, IndexError):
            return
        if state == "Z":
            pytest.fail(
                "descendant process remained as a zombie after bounded-runner return"
            )
        time.sleep(0.02)
    pytest.fail("descendant process survived bounded-runner termination")


@pytest.mark.parametrize("attempt", range(3))
def test_bounded_runner_repeatedly_reaps_descendants_after_leader_exit(
    tmp_path: Path, attempt: int
) -> None:
    from codex_master.runtime_process import BoundedProcessError, run_bounded

    descendant_pid = tmp_path / f"repeated-descendant-{attempt}.pid"
    parent = _script(
        tmp_path / f"leader-exit-{attempt}.py",
        "import subprocess, sys\n"
        "child = subprocess.Popen(['/usr/bin/python3', '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(descendant_pid)!r}, 'w', encoding='utf-8').write(str(child.pid))\n"
        "sys.exit(0)\n",
    )

    try:
        with pytest.raises(BoundedProcessError, match="command_timeout"):
            run_bounded([str(parent)], cwd=tmp_path, home=tmp_path, timeout_seconds=1)
        deadline = time.monotonic() + 2
        while not descendant_pid.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert descendant_pid.exists()
        _wait_until_process_is_not_live(int(descendant_pid.read_text(encoding="utf-8")))
    finally:
        if descendant_pid.exists():
            with contextlib.suppress(OSError):
                os.kill(int(descendant_pid.read_text(encoding="utf-8")), signal.SIGKILL)


def test_bounded_runner_fails_before_execution_when_atomic_pidfd_spawn_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.runtime_process as runtime_process

    marker = tmp_path / "started"
    child = _script(
        tmp_path / "must-not-run.py",
        f"open({str(marker)!r}, 'w', encoding='utf-8').write('started')\n",
    )
    group_signals: list[tuple[int, signal.Signals]] = []

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise runtime_process.BoundedProcessError("command_group_unavailable")

    def record_group_signal(process_group: int, sig: signal.Signals) -> None:
        group_signals.append((process_group, sig))

    monkeypatch.setattr(
        runtime_process, "_spawn_with_pidfd", unavailable, raising=False
    )
    monkeypatch.setattr(runtime_process.os, "killpg", record_group_signal)

    with pytest.raises(
        runtime_process.BoundedProcessError, match="command_group_unavailable"
    ):
        runtime_process.run_bounded(
            [str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=1
        )

    assert not marker.exists()
    assert group_signals == []


def test_bounded_runner_fails_before_execution_when_pidfd_preflight_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.runtime_process as runtime_process

    marker = tmp_path / "started"
    child = _script(
        tmp_path / "must-not-run-without-pidfd.py",
        f"open({str(marker)!r}, 'w', encoding='utf-8').write('started')\n",
    )

    def unavailable(_process_id: int) -> int:
        raise OSError(errno.EMFILE, "pidfd unavailable")

    monkeypatch.setattr(runtime_process.os, "pidfd_open", unavailable)

    with pytest.raises(
        runtime_process.BoundedProcessError, match="command_group_unavailable"
    ):
        runtime_process.run_bounded(
            [str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=1
        )

    assert not marker.exists()


def test_bounded_runner_reaps_the_group_when_post_spawn_pidfd_identity_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.runtime_process as runtime_process

    descendant_pid = tmp_path / "descendant.pid"
    parent = _script(
        tmp_path / "post-spawn-identity-failure.py",
        "import subprocess, time\n"
        "child = subprocess.Popen(['/usr/bin/python3', '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(descendant_pid)!r}, 'w', encoding='utf-8').write(str(child.pid))\n"
        "time.sleep(60)\n",
    )
    read_identity = runtime_process._pid_from_fdinfo
    reads = 0

    def fail_after_preflight(pidfd: int) -> int:
        nonlocal reads
        reads += 1
        if reads == 1:
            return read_identity(pidfd)
        time.sleep(1)
        raise runtime_process.BoundedProcessError("command_group_unavailable")

    monkeypatch.setattr(runtime_process, "_pid_from_fdinfo", fail_after_preflight)

    try:
        with pytest.raises(
            runtime_process.BoundedProcessError, match="command_group_unavailable"
        ):
            runtime_process.run_bounded(
                [str(parent)], cwd=tmp_path, home=tmp_path, timeout_seconds=1
            )

        assert reads == 2
        deadline = time.monotonic() + 2
        while not descendant_pid.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert descendant_pid.exists()
        _wait_until_process_is_not_live(int(descendant_pid.read_text(encoding="utf-8")))
    finally:
        if descendant_pid.exists():
            with contextlib.suppress(OSError):
                os.kill(int(descendant_pid.read_text(encoding="utf-8")), signal.SIGKILL)


def test_bounded_runner_never_treats_a_lost_child_status_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codex_master.runtime_process as runtime_process

    process = SimpleNamespace(returncode=None, pidfd=17)

    def child_already_reaped(*_args: object, **_kwargs: object) -> None:
        raise ChildProcessError

    monkeypatch.setattr(runtime_process.os, "waitid", child_already_reaped)

    with pytest.raises(
        runtime_process.BoundedProcessError, match="command_unavailable"
    ):
        runtime_process._wait_for_process(process, 0)


def test_reap_process_suppresses_a_lost_child_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codex_master.runtime_process as runtime_process

    process = SimpleNamespace(pidfd=17)
    waits = 0
    signals: list[tuple[int, signal.Signals]] = []

    def child_already_reaped(*_args: object, **_kwargs: object) -> None:
        nonlocal waits
        waits += 1
        raise runtime_process.BoundedProcessError("command_unavailable")

    def record_signal(pidfd: int, sig: signal.Signals) -> None:
        signals.append((pidfd, sig))

    monkeypatch.setattr(runtime_process, "_wait_for_process", child_already_reaped)
    monkeypatch.setattr(runtime_process.signal, "pidfd_send_signal", record_signal)

    runtime_process._reap_process(process)

    assert waits == 2
    assert signals == [(17, signal.SIGKILL)]


@pytest.mark.parametrize(
    ("stream", "failure_code"),
    (
        ("stdout", "command_stdout_limit"),
        ("stderr", "command_stderr_limit"),
        ("stdout", "command_timeout"),
        ("stderr", "command_timeout"),
    ),
)
def test_bounded_runner_terminates_descendants_after_early_parent_exit(
    tmp_path: Path, stream: str, failure_code: str
) -> None:
    from codex_master.runtime_process import BoundedProcessError, run_bounded

    descendant_pid = tmp_path / f"{stream}-{failure_code}.pid"
    descendant_body = (
        "import sys, time\n"
        + (
            f"sys.{stream}.write('x' * 4096)\nsys.{stream}.flush()\n"
            if "limit" in failure_code
            else ""
        )
        + "time.sleep(60)\n"
    )
    parent = _script(
        tmp_path / f"early-exit-{stream}-{failure_code}.py",
        "import subprocess, sys\n"
        + f"child = subprocess.Popen(['/usr/bin/python3', '-c', {descendant_body!r}])\n"
        + f"open({str(descendant_pid)!r}, 'w', encoding='utf-8').write(str(child.pid))\n"
        + "sys.exit(0)\n",
    )

    try:
        with pytest.raises(BoundedProcessError, match=failure_code):
            run_bounded(
                [str(parent)],
                cwd=tmp_path,
                home=tmp_path,
                timeout_seconds=1,
                stdout_limit=128,
                stderr_limit=128,
            )

        deadline = time.monotonic() + 2
        while not descendant_pid.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert descendant_pid.exists()
        _wait_until_process_is_not_live(int(descendant_pid.read_text(encoding="utf-8")))
    finally:
        if descendant_pid.exists():
            with contextlib.suppress(OSError):
                os.kill(int(descendant_pid.read_text(encoding="utf-8")), signal.SIGKILL)
