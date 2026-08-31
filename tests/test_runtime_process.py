from __future__ import annotations

import contextlib
import errno
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import subprocess
import time
from types import SimpleNamespace

import pytest


pytestmark = pytest.mark.usefixtures("runtime_spawn_helper")


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/python3\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _test_unit_cgroup(
    runtime_process: object,
    unit: str,
    *,
    environment: dict[str, str],
    deadline: float,
) -> Path | None:
    try:
        output = runtime_process._systemctl(
            ("show", "--value", "--property=ControlGroup", unit),
            environment=environment,
            deadline=deadline,
        )
    except runtime_process.BoundedProcessError:
        return None
    return runtime_process._cgroup_path(output) if output.strip() else None


def _cleanup_exact_test_unit(
    runtime_process: object,
    unit: str,
    *,
    environment: dict[str, str],
    systemctl: object,
) -> None:
    """Bounded test-only cleanup for the one random unit this test created."""

    deadline = time.monotonic() + 1
    cgroup = _test_unit_cgroup(
        runtime_process, unit, environment=environment, deadline=deadline
    )
    with contextlib.suppress(runtime_process.BoundedProcessError):
        systemctl(("stop", unit), environment=environment, deadline=deadline)
    if cgroup is not None:
        descriptor = -1
        try:
            descriptor = os.open(
                cgroup / "cgroup.kill", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            assert os.write(descriptor, b"1") == 1
        except FileNotFoundError:
            pass
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    with contextlib.suppress(runtime_process.BoundedProcessError):
        systemctl(("reset-failed", unit), environment=environment, deadline=deadline)


def _read_fifo_event(path: Path, *, deadline: float) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                ready = selector.select(deadline - time.monotonic())
                if not ready:
                    break
                event = os.read(descriptor, 5)
                if event:
                    return event
    finally:
        os.close(descriptor)
    pytest.fail("runtime test child did not emit its readiness event")


def _read_fifo_message(
    descriptor: int, selector: selectors.BaseSelector, *, deadline: float
) -> bytes:
    while time.monotonic() < deadline:
        ready = selector.select(deadline - time.monotonic())
        if not ready:
            break
        message = os.read(descriptor, 16)
        if message:
            return message
    pytest.fail("runtime test child did not emit its liveness event")


def _wait_for_fifo_eof(
    descriptor: int, selector: selectors.BaseSelector, *, deadline: float
) -> None:
    while time.monotonic() < deadline:
        ready = selector.select(deadline - time.monotonic())
        if not ready:
            break
        if not os.read(descriptor, 16):
            return
    pytest.fail("manager lifetime did not close the live child event")


def _test_unit_properties(
    runtime_process: object,
    unit: str,
    *,
    environment: dict[str, str],
    deadline: float,
) -> dict[str, str]:
    output = runtime_process._systemctl(
        (
            "show",
            "--property=RuntimeMaxUSec",
            "--property=TimeoutStopUSec",
            "--property=KillMode",
            "--property=SendSIGKILL",
            "--property=CollectMode",
            "--property=ExitType",
            unit,
        ),
        environment=environment,
        deadline=deadline,
    )
    properties: dict[str, str] = {}
    for line in output.decode("utf-8").splitlines():
        name, separator, value = line.partition("=")
        assert separator and name not in properties
        properties[name] = value
    return properties


def _assert_process_gone(process_id: int) -> None:
    with pytest.raises(OSError) as error:
        os.kill(process_id, 0)
    assert error.value.errno == errno.ESRCH


def _wait_for_test_unit_resolved(
    runtime_process: object,
    unit: str,
    *,
    environment: dict[str, str],
    deadline: float,
) -> None:
    while time.monotonic() < deadline:
        if (
            runtime_process._systemctl(
                ("show", "--value", "--property=LoadState", unit),
                environment=environment,
                deadline=deadline,
            ).strip()
            == b"not-found"
        ):
            return
    pytest.fail("manager lifetime did not resolve the exact test unit")


def _close_test_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=1)


def test_bounded_runner_never_kills_a_reused_cgroup_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale bound cgroup must not affect a new unit with the same path."""

    import codex_master.runtime_process as runtime_process

    from codex_master.runtime_process import BoundedProcessError, run_bounded

    unit = f"codex-master-runtime-inode-swap-{secrets.token_hex(16)}.service"
    foreign_ready = tmp_path / "foreign.ready"
    foreign_hold = tmp_path / "foreign.hold"
    foreign_pid = tmp_path / "foreign.pid"
    foreign_cgroup = tmp_path / "foreign.cgroup"
    os.mkfifo(foreign_ready, 0o600)
    os.mkfifo(foreign_hold, 0o600)
    foreign = (
        "import os\n"
        "from pathlib import Path\n"
        f"Path({str(foreign_pid)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        "cgroup = next(\n"
        "    line.split('::', 1)[1].strip()\n"
        "    for line in open('/proc/self/cgroup', encoding='utf-8')\n"
        "    if line.startswith('0::')\n"
        ")\n"
        f"Path({str(foreign_cgroup)!r}).write_text(cgroup, encoding='utf-8')\n"
        f"ready = os.open({str(foreign_ready)!r}, os.O_WRONLY)\n"
        "os.write(ready, b'ready')\n"
        "os.close(ready)\n"
        f"os.read(os.open({str(foreign_hold)!r}, os.O_RDONLY), 1)\n"
    )
    child = _script(tmp_path / "old-generation.py", "import time\ntime.sleep(60)\n")
    environment = runtime_process.minimal_environment(home=tmp_path)
    real_bind = runtime_process._bind_cgroup
    real_systemctl = runtime_process._systemctl
    observed: dict[str, object] = {}
    descriptors_before = len(list(Path("/proc/self/fd").iterdir()))

    def bind_then_replace(
        process: object, *, environment: dict[str, str], deadline: float
    ) -> None:
        real_bind(process, environment=environment, deadline=deadline)
        assert process.cgroup is not None
        observed["old_cgroup"] = process.cgroup
        observed["old_inode"] = os.stat(process.cgroup).st_ino
        observed["old_fd_inode"] = os.fstat(process.cgroup_fd).st_ino
        real_systemctl(
            ("stop", process.unit), environment=environment, deadline=deadline
        )
        assert (
            real_systemctl(
                ("show", "--value", "--property=LoadState", process.unit),
                environment=environment,
                deadline=deadline,
            ).strip()
            == b"not-found"
        )
        started = subprocess.run(
            [
                "/usr/bin/systemd-run",
                "--user",
                "--no-block",
                "--collect",
                f"--unit={process.unit}",
                "/usr/bin/python3",
                "-c",
                foreign,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=deadline - time.monotonic(),
        )
        assert started.returncode == 0
        assert _read_fifo_event(foreign_ready, deadline=deadline) == b"ready"
        observed["foreign_cgroup"] = Path("/sys/fs/cgroup") / foreign_cgroup.read_text(
            encoding="utf-8"
        ).strip().lstrip("/")
        observed["foreign_inode"] = os.stat(observed["foreign_cgroup"]).st_ino
        raise BoundedProcessError("command_group_unavailable")

    monkeypatch.setattr(runtime_process, "_bind_cgroup", bind_then_replace)
    monkeypatch.setattr(runtime_process, "_unit_name", lambda: unit)

    try:
        with pytest.raises(BoundedProcessError):
            run_bounded([str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=2)

        assert observed["old_cgroup"] == observed["foreign_cgroup"]
        assert observed["old_fd_inode"] == observed["old_inode"]
        assert observed["old_inode"] != observed["foreign_inode"]
        assert foreign_pid.exists()
        os.kill(int(foreign_pid.read_text(encoding="utf-8")), 0)
        assert Path(observed["foreign_cgroup"]).exists()
        assert (
            real_systemctl(
                ("show", "--value", "--property=LoadState", unit),
                environment=environment,
                deadline=time.monotonic() + 1,
            ).strip()
            != b"not-found"
        )
    finally:
        _cleanup_exact_test_unit(
            runtime_process,
            unit,
            environment=environment,
            systemctl=real_systemctl,
        )

    assert len(list(Path("/proc/self/fd").iterdir())) == descriptors_before


def test_bounded_runner_never_stops_a_reused_unit_after_a_valid_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A late same-name replacement must survive the old cgroup cleanup."""

    import codex_master.runtime_process as runtime_process

    from codex_master.runtime_process import BoundedProcessError, run_bounded

    unit = f"codex-master-runtime-late-swap-{secrets.token_hex(16)}.service"
    foreign_ready = tmp_path / "foreign.ready"
    foreign_hold = tmp_path / "foreign.hold"
    foreign_pid = tmp_path / "foreign.pid"
    foreign_cgroup = tmp_path / "foreign.cgroup"
    os.mkfifo(foreign_ready, 0o600)
    os.mkfifo(foreign_hold, 0o600)
    foreign = (
        "import os\n"
        "from pathlib import Path\n"
        f"Path({str(foreign_pid)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        "cgroup = next(\n"
        "    line.split('::', 1)[1].strip()\n"
        "    for line in open('/proc/self/cgroup', encoding='utf-8')\n"
        "    if line.startswith('0::')\n"
        ")\n"
        f"Path({str(foreign_cgroup)!r}).write_text(cgroup, encoding='utf-8')\n"
        f"ready = os.open({str(foreign_ready)!r}, os.O_WRONLY)\n"
        "os.write(ready, b'ready')\n"
        "os.close(ready)\n"
        f"os.read(os.open({str(foreign_hold)!r}, os.O_RDONLY), 1)\n"
    )
    child = _script(tmp_path / "old-generation.py", "import time\ntime.sleep(60)\n")
    environment = runtime_process.minimal_environment(home=tmp_path)
    real_bind = runtime_process._bind_cgroup
    real_snapshot = runtime_process._unit_snapshot
    real_systemctl = runtime_process._systemctl
    bound: dict[str, object] = {}
    armed = False
    descriptors_before = len(list(Path("/proc/self/fd").iterdir()))

    def bind_then_arm(
        process: object, *, environment: dict[str, str], deadline: float
    ) -> None:
        nonlocal armed
        real_bind(process, environment=environment, deadline=deadline)
        assert process.cgroup is not None
        assert process.invocation_id is not None
        bound["snapshot"] = runtime_process._UnitSnapshot(
            process.cgroup, process.invocation_id
        )
        bound["old_inode"] = os.fstat(process.cgroup_fd).st_ino
        armed = True
        raise BoundedProcessError("command_group_unavailable")

    def snapshot_then_replace(
        observed_unit: str, *, environment: dict[str, str], deadline: float
    ) -> object:
        nonlocal armed
        snapshot = real_snapshot(
            observed_unit, environment=environment, deadline=deadline
        )
        if observed_unit != unit or not armed:
            return snapshot
        assert snapshot in {
            bound["snapshot"],
            runtime_process._UnitSnapshot(None, None),
        }
        armed = False
        with contextlib.suppress(BoundedProcessError):
            real_systemctl(("stop", unit), environment=environment, deadline=deadline)
        _wait_for_test_unit_resolved(
            runtime_process,
            unit,
            environment=environment,
            deadline=deadline,
        )
        started = subprocess.run(
            [
                "/usr/bin/systemd-run",
                "--user",
                "--no-block",
                "--collect",
                f"--unit={unit}",
                "/usr/bin/python3",
                "-c",
                foreign,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=deadline - time.monotonic(),
        )
        assert started.returncode == 0
        assert _read_fifo_event(foreign_ready, deadline=deadline) == b"ready"
        foreign_path = Path("/sys/fs/cgroup") / foreign_cgroup.read_text(
            encoding="utf-8"
        ).strip().lstrip("/")
        bound["foreign_cgroup"] = foreign_path
        bound["foreign_inode"] = foreign_path.stat().st_ino
        return bound["snapshot"]

    monkeypatch.setattr(runtime_process, "_bind_cgroup", bind_then_arm)
    monkeypatch.setattr(runtime_process, "_unit_snapshot", snapshot_then_replace)
    monkeypatch.setattr(runtime_process, "_unit_name", lambda: unit)

    try:
        with pytest.raises(BoundedProcessError):
            run_bounded([str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=2)

        assert foreign_pid.exists()
        foreign_process = int(foreign_pid.read_text(encoding="utf-8"))
        os.kill(foreign_process, 0)
        assert bound["foreign_cgroup"] == bound["snapshot"].control_group
        assert bound["old_inode"] != bound["foreign_inode"]
        assert Path(bound["foreign_cgroup"]).exists()
        assert (
            real_systemctl(
                ("show", "--value", "--property=LoadState", unit),
                environment=environment,
                deadline=time.monotonic() + 1,
            ).strip()
            != b"not-found"
        )
    finally:
        _cleanup_exact_test_unit(
            runtime_process,
            unit,
            environment=environment,
            systemctl=real_systemctl,
        )

    assert len(list(Path("/proc/self/fd").iterdir())) == descriptors_before


def test_bounded_runner_manager_lifetime_ends_a_unit_after_runner_sigkill(
    tmp_path: Path, runtime_image
) -> None:
    """The manager, not the runner, bounds a child after runner death."""

    import codex_master.runtime_process as runtime_process

    unit = f"codex-master-runtime-runner-death-{secrets.token_hex(16)}.service"
    ready = tmp_path / "runner-death.ready"
    hold = tmp_path / "runner-death.hold"
    child_pid = tmp_path / "runner-death.pid"
    child_cgroup = tmp_path / "runner-death.cgroup"
    os.mkfifo(ready, 0o600)
    os.mkfifo(hold, 0o600)
    child = _script(
        tmp_path / "runner-death-child.py",
        "import os\n"
        "from pathlib import Path\n"
        f"Path({str(child_pid)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        "cgroup = next(\n"
        "    line.split('::', 1)[1].strip()\n"
        "    for line in open('/proc/self/cgroup', encoding='utf-8')\n"
        "    if line.startswith('0::')\n"
        ")\n"
        f"Path({str(child_cgroup)!r}).write_text(cgroup, encoding='utf-8')\n"
        f"ready = os.open({str(ready)!r}, os.O_WRONLY)\n"
        "os.write(ready, b'ready')\n"
        f"os.read(os.open({str(hold)!r}, os.O_RDONLY), 1)\n",
    )
    supervisor = _script(
        tmp_path / "runner-death-supervisor.py",
        "import os\n"
        "from pathlib import Path\n"
        "import codex_master.runtime_process as runtime_process\n"
        "runtime_process._unit_name = lambda: os.environ['RUNTIME_TEST_UNIT']\n"
        "try:\n"
        "    runtime_process.run_bounded(\n"
        "        [os.environ['RUNTIME_TEST_CHILD']],\n"
        "        cwd=Path(os.environ['RUNTIME_TEST_CWD']),\n"
        "        home=Path(os.environ['RUNTIME_TEST_HOME']),\n"
        "        timeout_seconds=float(os.environ['RUNTIME_TEST_TIMEOUT']),\n"
        "    )\n"
        "except runtime_process.BoundedProcessError:\n"
        "    pass\n",
    )
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    environment = runtime_process.minimal_environment(home=home)
    supervisor_environment = {
        **os.environ,
        "PYTHONPATH": os.fspath(runtime_image.root / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "RUNTIME_TEST_UNIT": unit,
        "RUNTIME_TEST_CHILD": os.fspath(child),
        "RUNTIME_TEST_CWD": os.fspath(tmp_path),
        "RUNTIME_TEST_HOME": os.fspath(home),
        "RUNTIME_TEST_TIMEOUT": "0.75",
    }
    descriptor = os.open(ready, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    process = subprocess.Popen(
        ["/usr/bin/python3", os.fspath(supervisor)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=supervisor_environment,
    )
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            assert (
                _read_fifo_message(descriptor, selector, deadline=time.monotonic() + 2)
                == b"ready"
            )
            properties = _test_unit_properties(
                runtime_process,
                unit,
                environment=environment,
                deadline=time.monotonic() + 1,
            )
            os.kill(process.pid, signal.SIGKILL)
            process.wait(timeout=1)
            _wait_for_fifo_eof(descriptor, selector, deadline=time.monotonic() + 1.5)

        assert properties["RuntimeMaxUSec"] != "infinity"
        assert properties["TimeoutStopUSec"] == "0"
        assert properties["KillMode"] == "control-group"
        assert properties["SendSIGKILL"] == "yes"
        assert properties["CollectMode"] == "inactive-or-failed"
        assert properties["ExitType"] == "main"
        cgroup = Path("/sys/fs/cgroup") / child_cgroup.read_text(
            encoding="utf-8"
        ).strip().lstrip("/")
        _wait_for_test_unit_resolved(
            runtime_process,
            unit,
            environment=environment,
            deadline=time.monotonic() + 1,
        )
        assert not cgroup.exists()
        _assert_process_gone(int(child_pid.read_text(encoding="utf-8")))
    finally:
        _close_test_process(process)
        os.close(descriptor)
        _cleanup_exact_test_unit(
            runtime_process,
            unit,
            environment=environment,
            systemctl=runtime_process._systemctl,
        )


def test_bounded_runner_reports_a_bounded_manager_lifetime_when_cleanup_loses_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dual immediate-cleanup failure reports a manager-bounded lifetime."""

    import codex_master.runtime_process as runtime_process

    from codex_master.runtime_process import BoundedProcessError, run_bounded

    unit = f"codex-master-runtime-cleanup-loss-{secrets.token_hex(16)}.service"
    ready = tmp_path / "cleanup-loss.ready"
    live = tmp_path / "cleanup-loss.live"
    hold = tmp_path / "cleanup-loss.hold"
    child_pid = tmp_path / "cleanup-loss.pid"
    child_cgroup = tmp_path / "cleanup-loss.cgroup"
    os.mkfifo(ready, 0o600)
    os.mkfifo(live, 0o600)
    os.mkfifo(hold, 0o600)
    child = _script(
        tmp_path / "cleanup-loss-child.py",
        "import os\n"
        "from pathlib import Path\n"
        f"Path({str(child_pid)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        "cgroup = next(\n"
        "    line.split('::', 1)[1].strip()\n"
        "    for line in open('/proc/self/cgroup', encoding='utf-8')\n"
        "    if line.startswith('0::')\n"
        ")\n"
        f"Path({str(child_cgroup)!r}).write_text(cgroup, encoding='utf-8')\n"
        f"live = os.open({str(live)!r}, os.O_WRONLY)\n"
        "os.write(live, b'live')\n"
        f"ready = os.open({str(ready)!r}, os.O_WRONLY)\n"
        "os.write(ready, b'ready')\n"
        "os.close(ready)\n"
        f"os.read(os.open({str(hold)!r}, os.O_RDONLY), 1)\n",
    )
    environment = runtime_process.minimal_environment(home=tmp_path)
    real_bind = runtime_process._bind_cgroup
    real_systemctl = runtime_process._systemctl
    bound: dict[str, object] = {}
    descriptor = os.open(live, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)

    def bind_then_fail(
        process: object, *, environment: dict[str, str], deadline: float
    ) -> None:
        real_bind(process, environment=environment, deadline=deadline)
        bound["cgroup"] = process.cgroup
        assert _read_fifo_event(ready, deadline=deadline) == b"ready"
        raise BoundedProcessError("command_group_unavailable")

    def fail_bound_cgroup_kill(*_args: object, **_kwargs: object) -> None:
        raise BoundedProcessError("command_group_unavailable")

    monkeypatch.setattr(runtime_process, "_bind_cgroup", bind_then_fail)
    monkeypatch.setattr(runtime_process, "_kill_bound_cgroup", fail_bound_cgroup_kill)
    monkeypatch.setattr(runtime_process, "_unit_name", lambda: unit)

    try:
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            with pytest.raises(BoundedProcessError) as error:
                run_bounded(
                    [str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=0.75
                )
            assert error.value.code == "command_cleanup_bounded"
            assert (
                _read_fifo_message(descriptor, selector, deadline=time.monotonic() + 1)
                == b"live"
            )
            os.kill(int(child_pid.read_text(encoding="utf-8")), 0)
            assert bound["cgroup"] is not None
            assert Path(bound["cgroup"]).exists()
            _wait_for_fifo_eof(descriptor, selector, deadline=time.monotonic() + 1.5)

        cgroup = Path("/sys/fs/cgroup") / child_cgroup.read_text(
            encoding="utf-8"
        ).strip().lstrip("/")
        _wait_for_test_unit_resolved(
            runtime_process,
            unit,
            environment=environment,
            deadline=time.monotonic() + 1,
        )
        assert not cgroup.exists()
        _assert_process_gone(int(child_pid.read_text(encoding="utf-8")))
    finally:
        os.close(descriptor)
        _cleanup_exact_test_unit(
            runtime_process,
            unit,
            environment=environment,
            systemctl=real_systemctl,
        )


def test_bounded_runner_denies_a_user_manager_escape_from_the_runtime_unit(
    tmp_path: Path,
) -> None:
    """A target cannot create a second same-UID user unit outside its cgroup."""

    import codex_master.runtime_process as runtime_process

    from codex_master.runtime_process import run_bounded

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    unit = f"codex-master-runtime-escape-{secrets.token_hex(16)}.service"
    ready = tmp_path / "escape.ready"
    hold = tmp_path / "escape.hold"
    escaped_pid = tmp_path / "escape.pid"
    os.mkfifo(ready, 0o600)
    os.mkfifo(hold, 0o600)
    inner = (
        "import os\n"
        "from pathlib import Path\n"
        f"Path({str(escaped_pid)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        f"ready = os.open({str(ready)!r}, os.O_WRONLY)\n"
        "os.write(ready, b'ready')\n"
        "os.close(ready)\n"
        f"os.read(os.open({str(hold)!r}, os.O_RDONLY), 1)\n"
    )
    parent = _script(
        tmp_path / "user-manager-escape.py",
        "import os, selectors, subprocess, sys, time\n"
        f"ready = {str(ready)!r}\n"
        "manager = f'/run/user/{os.geteuid()}'\n"
        "environment = {**os.environ, 'XDG_RUNTIME_DIR': manager, "
        "'DBUS_SESSION_BUS_ADDRESS': f'unix:path={manager}/bus'}\n"
        "completed = subprocess.run(\n"
        "    ['/usr/bin/systemd-run', '--user', '--no-block', '--collect', "
        f"'--unit={unit}', '/usr/bin/python3', '-c', {inner!r}],\n"
        "    check=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, env=environment,\n"
        ")\n"
        "if completed.returncode:\n"
        "    print('blocked')\n"
        "else:\n"
        "    descriptor = os.open(ready, os.O_RDONLY | os.O_NONBLOCK)\n"
        "    try:\n"
        "        with selectors.DefaultSelector() as selector:\n"
        "            selector.register(descriptor, selectors.EVENT_READ)\n"
        "            deadline = time.monotonic() + 0.5\n"
        "            escaped = False\n"
        "            while time.monotonic() < deadline:\n"
        "                if not selector.select(deadline - time.monotonic()):\n"
        "                    break\n"
        "                if os.read(descriptor, 5) == b'ready':\n"
        "                    escaped = True\n"
        "                    break\n"
        "    finally:\n"
        "        os.close(descriptor)\n"
        "    print('escaped' if escaped else 'blocked')\n",
    )
    environment = runtime_process.minimal_environment(home=home)
    real_systemctl = runtime_process._systemctl

    try:
        result = run_bounded([str(parent)], cwd=tmp_path, home=home, timeout_seconds=2)

        assert result.returncode == 0
        assert result.stdout == "blocked\n"
        assert not escaped_pid.exists()
        assert (
            real_systemctl(
                ("show", "--value", "--property=LoadState", unit),
                environment=environment,
                deadline=time.monotonic() + 1,
            ).strip()
            == b"not-found"
        )
    finally:
        _cleanup_exact_test_unit(
            runtime_process,
            unit,
            environment=environment,
            systemctl=real_systemctl,
        )


def test_bounded_runner_terminates_its_bound_cgroup_without_a_manager_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The FD-bound kill terminates a known child without a named manager stop."""

    import codex_master.runtime_process as runtime_process

    from codex_master.runtime_process import BoundedProcessError, run_bounded

    ready = tmp_path / "stop-failure.ready"
    hold = tmp_path / "stop-failure.hold"
    child_pid = tmp_path / "stop-failure.pid"
    child_cgroup = tmp_path / "stop-failure.cgroup"
    os.mkfifo(ready, 0o600)
    os.mkfifo(hold, 0o600)
    child = _script(
        tmp_path / "stop-failure-child.py",
        "import os\n"
        "from pathlib import Path\n"
        f"Path({str(child_pid)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        "cgroup = next(\n"
        "    line.split('::', 1)[1].strip()\n"
        "    for line in open('/proc/self/cgroup', encoding='utf-8')\n"
        "    if line.startswith('0::')\n"
        ")\n"
        f"Path({str(child_cgroup)!r}).write_text(cgroup, encoding='utf-8')\n"
        f"ready = os.open({str(ready)!r}, os.O_WRONLY)\n"
        "os.write(ready, b'ready')\n"
        "os.close(ready)\n"
        f"os.read(os.open({str(hold)!r}, os.O_RDONLY), 1)\n",
    )
    environment = runtime_process.minimal_environment(home=tmp_path)
    real_bind = runtime_process._bind_cgroup
    real_systemctl = runtime_process._systemctl
    unit = f"codex-master-runtime-stop-failure-{secrets.token_hex(16)}.service"
    bound: dict[str, object] = {}
    calls: list[tuple[str, ...]] = []

    def bind_then_wait(
        process: object, *, environment: dict[str, str], deadline: float
    ) -> None:
        real_bind(process, environment=environment, deadline=deadline)
        bound["unit"] = process.unit
        bound["cgroup"] = process.cgroup
        assert _read_fifo_event(ready, deadline=deadline) == b"ready"

    def record_manager_call(
        arguments: tuple[str, ...],
        *,
        environment: dict[str, str],
        deadline: float,
    ) -> bytes:
        calls.append(arguments)
        return real_systemctl(arguments, environment=environment, deadline=deadline)

    monkeypatch.setattr(runtime_process, "_bind_cgroup", bind_then_wait)
    monkeypatch.setattr(runtime_process, "_systemctl", record_manager_call)
    monkeypatch.setattr(runtime_process, "_unit_name", lambda: unit)

    try:
        with pytest.raises(BoundedProcessError, match="command_timeout"):
            run_bounded([str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=0.5)

        assert ("stop", unit) not in calls
        assert bound["cgroup"] is not None
        cgroup = Path(bound["cgroup"])
        assert cgroup == Path("/sys/fs/cgroup") / child_cgroup.read_text(
            encoding="utf-8"
        ).strip().lstrip("/")
        assert not cgroup.exists()
        assert (
            real_systemctl(
                ("show", "--value", "--property=LoadState", unit),
                environment=environment,
                deadline=time.monotonic() + 1,
            ).strip()
            == b"not-found"
        )
        process_id = int(child_pid.read_text(encoding="utf-8"))
        with pytest.raises(OSError) as error:
            os.kill(process_id, 0)
        assert error.value.errno == errno.ESRCH
    finally:
        _cleanup_exact_test_unit(
            runtime_process,
            unit,
            environment=environment,
            systemctl=real_systemctl,
        )


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


def test_default_runtime_image_loads_its_manifest_bound_native_helper(
    runtime_image,
) -> None:
    import codex_master.runtime_process as runtime_process

    helper = runtime_process._load_runtime_spawn_helper(runtime_image)

    assert callable(helper.spawn)
    assert runtime_image.spawn_helper.name == "_runtime_spawn_helper.so"
    assert len(runtime_image.spawn_helper_digest) == 64


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
            timeout_seconds=2,
            stdout_limit=128,
            stderr_limit=128,
        )


def test_bounded_runner_times_out_and_terminates_the_whole_cgroup(
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


def test_bounded_runner_terminates_a_setsid_descendant_after_leader_exit(
    tmp_path: Path,
) -> None:
    from codex_master.runtime_process import run_bounded

    descendant_pid = tmp_path / "setsid-descendant.pid"
    ready = tmp_path / "setsid-descendant.ready"
    cgroup_marker = tmp_path / "setsid-descendant.cgroup"
    descendant = (
        "import os, time\n"
        "os.setsid()\n"
        f"open({str(descendant_pid)!r}, 'w', encoding='utf-8').write(str(os.getpid()))\n"
        "cgroup = next(line.split('::', 1)[1].strip() for line in open('/proc/self/cgroup', encoding='utf-8') if line.startswith('0::'))\n"
        f"open({str(cgroup_marker)!r}, 'w', encoding='utf-8').write(cgroup)\n"
        f"open({str(ready)!r}, 'wb').write(b'ready')\n"
        "os.write(int(os.environ['READY_FD']), b'ready')\n"
        "time.sleep(60)\n"
    )
    parent = _script(
        tmp_path / "setsid-leader-exit.py",
        "import os, subprocess, sys\n"
        + "reader, writer = os.pipe()\n"
        + f"subprocess.Popen(['/usr/bin/python3', '-c', {descendant!r}], pass_fds=(writer,), env={{**os.environ, 'READY_FD': str(writer)}})\n"
        + "os.close(writer)\n"
        + "assert os.read(reader, 5) == b'ready'\n"
        + "sys.exit(0)\n",
    )

    try:
        result = run_bounded(
            [str(parent)], cwd=tmp_path, home=tmp_path, timeout_seconds=0.5
        )
        assert result.returncode in {0, 1}
        assert ready.read_bytes() == b"ready"
        _wait_until_process_is_not_live(int(descendant_pid.read_text(encoding="utf-8")))
        relative = cgroup_marker.read_text(encoding="utf-8").strip().lstrip("/")
        assert not (Path("/sys/fs/cgroup") / relative).exists()
    finally:
        if descendant_pid.exists():
            with contextlib.suppress(OSError):
                os.kill(int(descendant_pid.read_text(encoding="utf-8")), signal.SIGKILL)


@pytest.mark.parametrize(
    ("mode", "failure_code"),
    (
        ("success", None),
        ("timeout", "command_timeout"),
        ("stdout", "command_stdout_limit"),
        ("stderr", "command_stderr_limit"),
    ),
)
def test_bounded_runner_removes_the_actual_cgroup_after_every_outcome(
    tmp_path: Path, mode: str, failure_code: str | None
) -> None:
    import codex_master.runtime_process as runtime_process
    from codex_master.runtime_process import BoundedProcessError, run_bounded

    cgroup_marker = tmp_path / f"{mode}.cgroup"
    body = (
        "from pathlib import Path\n"
        "import sys, time\n"
        "cgroup = next(line.split('::', 1)[1].strip() for line in open('/proc/self/cgroup', encoding='utf-8') if line.startswith('0::'))\n"
        f"Path({str(cgroup_marker)!r}).write_text(cgroup, encoding='utf-8')\n"
    )
    if mode == "success":
        body += "print('ok')\n"
    elif mode == "timeout":
        body += "time.sleep(60)\n"
    else:
        body += f"sys.{mode}.write('x' * 4096)\nsys.{mode}.flush()\ntime.sleep(60)\n"
    child = _script(tmp_path / f"cgroup-{mode}.py", body)

    if failure_code is None:
        result = run_bounded(
            [str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=1
        )
        assert result.returncode == 0
    else:
        with pytest.raises(BoundedProcessError, match=failure_code):
            run_bounded(
                [str(child)],
                cwd=tmp_path,
                home=tmp_path,
                timeout_seconds=0.5,
                stdout_limit=128,
                stderr_limit=128,
            )

    relative = cgroup_marker.read_text(encoding="utf-8").strip().lstrip("/")
    assert not (Path("/sys/fs/cgroup") / relative).exists()
    unit = Path(relative).name
    assert (
        runtime_process._systemctl(
            ("show", "--value", "--property=LoadState", unit),
            environment=runtime_process.minimal_environment(home=tmp_path),
            deadline=time.monotonic() + 1,
        ).strip()
        == b"not-found"
    )


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
    from codex_master.runtime_process import run_bounded

    descendant_pid = tmp_path / f"repeated-descendant-{attempt}.pid"
    descendant = (
        "import os, time\n"
        f"open({str(descendant_pid)!r}, 'w', encoding='utf-8').write(str(os.getpid()))\n"
        "os.write(int(os.environ['READY_FD']), b'ready')\n"
        "time.sleep(60)\n"
    )
    parent = _script(
        tmp_path / f"leader-exit-{attempt}.py",
        "import os, subprocess, sys\n"
        "reader, writer = os.pipe()\n"
        + f"subprocess.Popen(['/usr/bin/python3', '-c', {descendant!r}], pass_fds=(writer,), env={{**os.environ, 'READY_FD': str(writer)}})\n"
        + "os.close(writer)\n"
        + "assert os.read(reader, 5) == b'ready'\n"
        "sys.exit(0)\n",
    )

    try:
        result = run_bounded(
            [str(parent)], cwd=tmp_path, home=tmp_path, timeout_seconds=1
        )
        assert result.returncode in {0, 1}
        _wait_until_process_is_not_live(int(descendant_pid.read_text(encoding="utf-8")))
    finally:
        if descendant_pid.exists():
            with contextlib.suppress(OSError):
                os.kill(int(descendant_pid.read_text(encoding="utf-8")), signal.SIGKILL)


def test_bounded_runner_fails_before_execution_when_cgroup_capability_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.runtime_process as runtime_process

    marker = tmp_path / "started"
    child = _script(
        tmp_path / "must-not-run.py",
        f"open({str(marker)!r}, 'w', encoding='utf-8').write('started')\n",
    )
    descriptors_before = len(list(Path("/proc/self/fd").iterdir()))

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise runtime_process.BoundedProcessError("command_group_unavailable")

    monkeypatch.setattr(
        runtime_process, "_verify_runner_capability", unavailable, raising=False
    )

    with pytest.raises(
        runtime_process.BoundedProcessError, match="command_group_unavailable"
    ):
        runtime_process.run_bounded(
            [str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=1
        )

    assert not marker.exists()
    assert len(list(Path("/proc/self/fd").iterdir())) == descriptors_before


def test_bounded_runner_fails_before_execution_when_pidfd_primitive_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.runtime_process as runtime_process

    marker = tmp_path / "started"
    child = _script(
        tmp_path / "must-not-run-without-pidfd.py",
        f"open({str(marker)!r}, 'w', encoding='utf-8').write('started')\n",
    )

    monkeypatch.delattr(runtime_process.os, "P_PIDFD", raising=False)

    with pytest.raises(
        runtime_process.BoundedProcessError, match="command_group_unavailable"
    ):
        runtime_process.run_bounded(
            [str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=1
        )

    assert not marker.exists()


def test_bound_helper_path_swap_never_loads_the_replacement_constructor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime_image
) -> None:
    import shutil
    import subprocess

    import codex_master.runtime_process as runtime_process
    from codex_master.runtime_layout import RuntimeLayout

    image = tmp_path / "swappable-image"
    shutil.copytree(runtime_image.root, image)
    layout = RuntimeLayout.from_runtime_root(image)
    sentinel = tmp_path / "helper-constructor-ran"
    replacement_source = tmp_path / "replacement.c"
    replacement = tmp_path / "replacement.so"
    replacement_source.write_text(
        "#include <fcntl.h>\n"
        "#include <unistd.h>\n"
        "__attribute__((constructor)) static void mark(void) {\n"
        f"  int fd = open({json.dumps(str(sentinel))}, O_WRONLY | O_CREAT, 0600);\n"
        "  if (fd >= 0) close(fd);\n"
        "}\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            "/usr/bin/cc",
            "-shared",
            "-fPIC",
            "-o",
            str(replacement),
            str(replacement_source),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    validate = runtime_process.validate_runtime_metadata

    def validate_then_swap(value: RuntimeLayout) -> None:
        validate(value)
        os.replace(replacement, value.spawn_helper)

    monkeypatch.setattr(
        runtime_process, "validate_runtime_metadata", validate_then_swap
    )

    with pytest.raises(
        runtime_process.BoundedProcessError, match="command_group_unavailable"
    ):
        runtime_process._load_runtime_spawn_helper(layout)

    assert not sentinel.exists()


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

    runtime_process._reap_process(process, time.monotonic() + 0.1)

    assert waits == 2
    assert signals == [(17, signal.SIGKILL)]
