"""Opt-in local Codex 0.161 start/resume and trusted hook regression."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from the_hive import server


CODEX = Path("/usr/local/bin/codex")  # Avoid the desktop launcher, which moves into its own scope.


def _run(argv: list[str], *, env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv, env=env, cwd=cwd, input="", capture_output=True, text=True,
        timeout=30, check=False,
    )


def _wait_own_scope_empty(unit: str, home: Path, env: dict[str, str], root: Path) -> None:
    identity = b"CODEX_HOME=" + os.fsencode(home) + b"\0"
    for _ in range(50):
        state = _run(["systemctl", "--user", "show", unit,
                      "-p", "ActiveState", "-p", "ControlGroup"], env=env, cwd=root)
        pids = []
        for proc in Path("/proc").glob("[0-9]*"):
            try:
                if identity in (proc / "environ").read_bytes():
                    pids.append(proc.name)
            except OSError:
                pass
        if (state.returncode == 0 and "ActiveState=inactive" in state.stdout
                and "ControlGroup=\n" in state.stdout and not pids):
            return
        time.sleep(0.1)
    pytest.fail(f"own scope/home processes did not drain: {unit}; pids={pids}")


def _fixture_plugin(root: Path, home: Path) -> None:
    plugin = root / "plugins" / "fixture-plugin"
    (plugin / ".codex-plugin").mkdir(parents=True)
    (plugin / "hooks").mkdir()
    (plugin / ".codex-plugin" / "plugin.json").write_text(
        json.dumps({"name": "fixture-plugin", "version": "0.1.0"})
    )
    (plugin / "hooks" / "record.py").write_text(
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "payload = json.load(sys.stdin)\n"
        "payload['cgroup'] = Path('/proc/self/cgroup').read_text().strip()\n"
        "with (Path(os.environ['CODEX_HOME']).parent / 'hook-events.jsonl').open('a') as f:\n"
        "    f.write(json.dumps(payload) + '\\n')\n"
    )
    command = 'python3 -I "${PLUGIN_ROOT}/hooks/record.py"'
    groups = {
        "SessionStart": [{
            "matcher": "startup|resume",
            "hooks": [{"type": "command", "command": command, "commandWindows": command,
                       "timeout": 5, "statusMessage": "fixture recording"}],
        }],
        "Stop": [{
            "hooks": [{"type": "command", "command": command, "commandWindows": command,
                       "timeout": 5}],
        }],
    }
    (plugin / "hooks" / "hooks.json").write_text(json.dumps({"hooks": groups}))
    marketplace = root / ".agents" / "plugins"
    marketplace.mkdir(parents=True)
    (marketplace / "marketplace.json").write_text(json.dumps({
        "name": "local-fixture",
        "plugins": [{
            "name": "fixture-plugin",
            "source": {"source": "local", "path": "./plugins/fixture-plugin"},
            "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
            "category": "Productivity",
        }],
    }))
    with (home / "config.toml").open("a") as config:
        for event, key in (("session_start", "SessionStart"), ("stop", "Stop")):
            hook_id = f"fixture-plugin@local-fixture:hooks/hooks.json:{event}:0:0"
            trusted_hash = server._home_refresh_plugin_hook_hash(
                event, groups[key][0], groups[key][0]["hooks"][0]
            )
            config.write(f'[hooks.state."{hook_id}"]\ntrusted_hash="{trusted_hash}"\n')
    (home / "config.toml").chmod(0o600)


def _event_stream(index: int) -> bytes:
    message = {"id": f"msg_{index}", "type": "message", "status": "completed",
               "role": "assistant", "content": [{"type": "output_text",
               "text": "fixture answer", "annotations": []}]}
    response = {"id": f"resp_{index}", "object": "response", "created_at": 0,
                "status": "completed", "model": "fixture-model", "output": [message],
                "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}}
    events = [
        ("response.created", {"type": "response.created",
                              "response": {**response, "status": "in_progress", "output": []}}),
        ("response.output_item.added", {"type": "response.output_item.added",
                                        "output_index": 0, "item": {**message,
                                        "status": "in_progress", "content": []}}),
        ("response.content_part.added", {"type": "response.content_part.added",
                                         "output_index": 0, "item_id": message["id"],
                                         "content_index": 0, "part": {"type": "output_text",
                                         "text": "", "annotations": []}}),
        ("response.output_text.delta", {"type": "response.output_text.delta",
                                        "output_index": 0, "item_id": message["id"],
                                        "content_index": 0, "delta": "fixture answer"}),
        ("response.content_part.done", {"type": "response.content_part.done",
                                        "output_index": 0, "item_id": message["id"],
                                        "content_index": 0, "part": message["content"][0]}),
        ("response.output_item.done", {"type": "response.output_item.done",
                                       "output_index": 0, "item": message}),
        ("response.completed", {"type": "response.completed", "response": response}),
    ]
    return "".join(
        f"event: {name}\ndata: {json.dumps(payload)}\n\n" for name, payload in events
    ).encode()


def test_real_cli_start_resume_stop_hooks_and_empty_scopes(tmp_path: Path) -> None:
    if os.environ.get("HIVE_LIVE_CODEX_TEST") != "1":
        pytest.skip("set HIVE_LIVE_CODEX_TEST=1 for the local live CLI regression")
    if not (CODEX.is_file() and shutil.which("systemd-run") and shutil.which("systemctl")):
        pytest.skip("Codex binary or systemd user tools unavailable")
    root = tmp_path
    home = root / "home"
    home.mkdir(mode=0o700)
    env = {key: os.environ[key] for key in (
        "PATH", "LANG", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "USER", "LOGNAME",
    ) if key in os.environ}
    env.update(HOME=str(root), CODEX_HOME=str(home),
               LOCAL_RESPONSES_DUMMY_TOKEN="dummy-local-only")
    version = _run([str(CODEX), "--no-daemon", "--version"], env=env, cwd=root)
    if version.stdout.strip() != "codex-cli 0.161.0":
        pytest.skip("Codex CLI 0.161.0 unavailable")
    if _run(["systemctl", "--user", "show-environment"], env=env, cwd=root).returncode:
        pytest.skip("systemd user manager unavailable")

    requests: list[dict] = []
    active_cgroups: list[str] = []
    unit = ""
    scope_safe_to_remove = True

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            assert self.path == "/v1/responses"
            assert self.headers["Authorization"] == "Bearer dummy-local-only"
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(payload)
            observed = _run(
                ["systemctl", "--user", "show", unit, "-p", "ControlGroup", "--value"],
                env=env, cwd=root,
            )
            active_cgroups.append(observed.stdout.strip())
            data = _event_stream(len(requests))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args: object) -> None:
            pass

    transport = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=transport.serve_forever, daemon=True).start()
    try:
        (home / "config.toml").write_text(
            f'model="fixture-model"\nmodel_provider="local"\n'
            f'approval_policy="never"\nsandbox_mode="read-only"\n'
            f'[model_providers.local]\nname="local"\n'
            f'base_url="http://127.0.0.1:{transport.server_port}/v1"\n'
            f'wire_api="responses"\nenv_key="LOCAL_RESPONSES_DUMMY_TOKEN"\n'
            f'[features]\ndaemon_auto_start=false\n'
        )
        _fixture_plugin(root, home)
        for command in (
            [str(CODEX), "--no-daemon", "plugin", "marketplace", "add", str(root)],
            [str(CODEX), "--no-daemon", "plugin", "add", "fixture-plugin@local-fixture"],
        ):
            result = _run(command, env=env, cwd=root)
            assert result.returncode == 0, result.stderr[-500:]
        wrapper = home / "codex"
        wrapper.write_text(server.pool_wrapper_text("fixture", home, str(CODEX)))
        wrapper.chmod(0o700)
        thread_id = ""
        for turn in range(2):
            server._require_managed_codex_daemon_free(home)
            args = [str(wrapper), "exec"]
            if turn:
                args += ["resume", "--skip-git-repo-check", "--json", thread_id, "say again"]
            else:
                args += ["--skip-git-repo-check", "--json", "say fixture"]
            unit = f"hive-cli-fixture-{uuid.uuid4().hex[:12]}.scope"
            scope_safe_to_remove = False
            try:
                result = _run(
                    ["systemd-run", "--user", "--scope", "--quiet", "--unit", unit, *args],
                    env=env, cwd=root,
                )
                assert result.returncode == 0, result.stderr[-500:]
                events = [json.loads(line) for line in result.stdout.splitlines()]
                started = [event["thread_id"] for event in events
                           if event.get("type") == "thread.started"]
                assert len(started) == 1
                thread_id = thread_id or started[0]
                assert started[0] == thread_id
                assert any(event.get("type") == "turn.completed" for event in events)
                _wait_own_scope_empty(unit, home, env, root)
                assert active_cgroups[turn].endswith("/" + unit)
                scope = Path("/sys/fs/cgroup" + active_cgroups[turn])
                assert not scope.exists() or not (scope / "cgroup.procs").read_text().strip()
            finally:
                try:
                    _run(["systemctl", "--user", "stop", unit], env=env, cwd=root)
                finally:
                    _wait_own_scope_empty(unit, home, env, root)
                    scope_safe_to_remove = True
            server._require_managed_codex_daemon_free(home)
        rollouts = list((home / "sessions").rglob("*.jsonl"))
        assert len(rollouts) == 1 and thread_id in rollouts[0].name
        assert len(requests) == 2
        assert any("say fixture" in str(item) for item in requests[1]["input"])
        assert any("fixture answer" in str(item) for item in requests[1]["input"])
        hooks = [json.loads(line) for line in (root / "hook-events.jsonl").read_text().splitlines()]
        assert [(event["hook_event_name"], event.get("source")) for event in hooks] == [
            ("SessionStart", "startup"), ("Stop", None),
            ("SessionStart", "resume"), ("Stop", None),
        ]
        assert all(event["session_id"] == thread_id for event in hooks)
        assert [event["cgroup"].removeprefix("0::") for event in hooks] == [
            active_cgroups[0], active_cgroups[0], active_cgroups[1], active_cgroups[1],
        ]
    finally:
        transport.shutdown()
        transport.server_close()
        if scope_safe_to_remove:
            shutil.rmtree(root)
