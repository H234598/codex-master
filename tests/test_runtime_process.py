from __future__ import annotations

import contextlib
import errno
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
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


def test_bounded_runner_terminates_its_bound_cgroup_when_systemctl_stop_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stop error cannot let a known live target child survive runner return."""

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

    def bind_then_wait(
        process: object, *, environment: dict[str, str], deadline: float
    ) -> None:
        real_bind(process, environment=environment, deadline=deadline)
        bound["unit"] = process.unit
        bound["cgroup"] = process.cgroup
        assert _read_fifo_event(ready, deadline=deadline) == b"ready"

    def fail_only_the_bound_unit_stop(
        arguments: tuple[str, ...],
        *,
        environment: dict[str, str],
        deadline: float,
    ) -> bytes:
        if arguments == ("stop", bound.get("unit")):
            assert child_pid.exists()
            os.kill(int(child_pid.read_text(encoding="utf-8")), 0)
            raise BoundedProcessError("command_group_unavailable")
        return real_systemctl(arguments, environment=environment, deadline=deadline)

    monkeypatch.setattr(runtime_process, "_bind_cgroup", bind_then_wait)
    monkeypatch.setattr(runtime_process, "_systemctl", fail_only_the_bound_unit_stop)
    monkeypatch.setattr(runtime_process, "_unit_name", lambda: unit)

    try:
        with pytest.raises(BoundedProcessError, match="command_group_unavailable"):
            run_bounded([str(child)], cwd=tmp_path, home=tmp_path, timeout_seconds=0.5)

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
            timeout_seconds=1,
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
        assert result.returncode == 0
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
        assert result.returncode == 0
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
