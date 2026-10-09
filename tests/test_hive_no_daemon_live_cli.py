"""Opt-in local Codex 0.161 start/resume and trusted hook regression."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from the_hive import server


CODEX = Path("/home/teladi/.codex/packages/app-server-daemon/releases/0.161.0-x86_64-unknown-linux-musl/bin/codex")
HIVE_BUNDLE_FILES = (
    "release-binding.json", ".codex-plugin/plugin.json", ".mcp.json", ".app.json",
    "hooks/hooks.json", "hooks/native_bee_event.py", "hooks/native_spawn_admission.py",
    "skills/the-hive-fleet/SKILL.md",
    "skills/the-hive-fleet/references/common-invariants.md",
    "skills/the-hive-fleet/references/diagnostics-retry-reporting.md",
    "skills/the-hive-fleet/references/queen-operations.md",
    "skills/the-hive-fleet/references/tl-worker-operations.md",
)


def _run(argv: list[str], *, env: dict[str, str], cwd: Path,
         input_text: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv, env=env, cwd=cwd, input=input_text, capture_output=True, text=True,
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


def _attest_hive_bundle(source: Path, release: Path, cache: Path) -> None:
    for name in HIVE_BUNDLE_FILES:
        expected = (release / name).read_bytes()
        assert (source / name).read_bytes() == expected
        assert (cache / name).read_bytes() == expected


def _trust_installed_hive(home: Path, plugin: Path, release: Path,
                          personal_home: Path) -> None:
    """Reuse only the nine previously approved hashes for identical hook bytes."""
    personal_cache = personal_home / "plugins/cache/personal/the-hive/0.10.5+codex.20260808003125"
    _attest_hive_bundle(plugin, release, personal_cache)
    groups = json.loads((plugin / "hooks/hooks.json").read_text())["hooks"]
    expected = set()
    for event, rules in groups.items():
        key = re.sub(r"(?<!^)(?=[A-Z])", "_", event).lower()
        for rule_index, rule in enumerate(rules):
            for hook_index, _hook in enumerate(rule["hooks"]):
                expected.add(f"the-hive@personal:hooks/hooks.json:{key}:{rule_index}:{hook_index}")
    approved = tomllib.loads((personal_home / "config.toml").read_text())["hooks"]["state"]
    approved = {key: value for key, value in approved.items()
                if key.startswith("the-hive@personal:hooks/hooks.json:")}
    assert len(expected) == 9 and set(approved) == expected
    approved_hashes = {}
    for hook_id in expected:
        value = approved[hook_id]
        trusted_hash = value.get("trusted_hash")
        assert set(value) == {"enabled", "trusted_hash"} and value["enabled"] is True
        assert isinstance(trusted_hash, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", trusted_hash)
        approved_hashes[hook_id] = trusted_hash
    with (home / "config.toml").open("a") as config:
        for hook_id in sorted(expected):
            config.write(f'[hooks.state."{hook_id}"]\n'
                         f'trusted_hash="{approved_hashes[hook_id]}"\nenabled=true\n')
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


def _installed_pin_active(pin_root: Path, session_id: str) -> bool:
    pin = pin_root / (hashlib.sha256(session_id.encode()).hexdigest() + ".json")
    try:
        before = pin.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1):
            return False
        binding = json.loads(pin.read_text())
        after = pin.lstat()
    except (OSError, ValueError):
        return False
    def stable(item: os.stat_result) -> tuple[int, ...]:
        return (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                item.st_gid, item.st_nlink, item.st_size, item.st_mtime_ns)
    return (stable(before) == stable(after)
            and binding.get("session_id") == session_id
            and binding.get("state") == "active"
            and binding.get("ended_at_unix_ns") is None)


def test_installed_probe_requires_active_pin(tmp_path: Path) -> None:
    session_id = "own-session"
    pin = tmp_path / (hashlib.sha256(session_id.encode()).hexdigest() + ".json")
    pin.write_text(json.dumps({"session_id": session_id, "state": "active",
                               "ended_at_unix_ns": None}))
    pin.chmod(0o600)
    assert _installed_pin_active(tmp_path, session_id)
    pin.write_text(json.dumps({"session_id": session_id, "state": "ended",
                               "ended_at_unix_ns": 2}))
    assert not _installed_pin_active(tmp_path, session_id)


def test_installed_admission_fixture_denies_before_reservation(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    event = {"session_id": "own-session", "hook_event_name": "PreToolUse",
             "tool_name": "spawn_agent", "tool_input": [], "cwd": str(tmp_path)}
    result = _run([sys.executable, "-I", str(root / "hooks/native_spawn_admission.py")],
                  env={"PATH": os.environ["PATH"], "PLUGIN_ROOT": str(root),
                       "CODEX_MASTER_MCP_STATE": str(tmp_path / "state")},
                  cwd=tmp_path, input_text=json.dumps(event) + "\n")
    specific = json.loads(result.stdout)["hookSpecificOutput"]
    assert result.returncode == 0 and specific == {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason":
        "error_code=invalid_pretooluse_input reason_codes=invalid_input",
    }
    assert not (tmp_path / "state/native-agents.json").exists()


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


def test_installed_hive_admission_during_active_cli_session(tmp_path: Path) -> None:
    if os.environ.get("HIVE_INSTALLED_HOOK_LIVE_TEST") != "1":
        pytest.skip("set HIVE_INSTALLED_HOOK_LIVE_TEST=1 for the installed hook probe")
    home = Path("/home/teladi")
    personal_codex_home = home / ".codex"
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    source_plugin = home / "plugins/the-hive"
    source_descriptor = json.loads((source_plugin / "release-binding.json").read_text())
    generation = source_descriptor["generation"]
    assert generation == "ab5973849639df261d82c1cec84c4619af89f889"
    release = home / ".local/lib/the-hive-runtime/generations" / generation
    plugin = codex_home / "plugins/cache/personal/the-hive/0.10.5+codex.20260808003125"
    pins = home / ".local/state/the-hive/hook-session-pins-v1"
    registry_path = home / ".local/state/codex-master-mcp/native-agents.json"
    launcher = "/usr/local/libexec/the-hive/hook-abi/v1/launcher"
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if (not CODEX.is_file() or not shutil.which("systemd-run")
            or digest(source_plugin / "release-binding.json")
            != digest(release / "TheHivePluginBundleV1/release-binding.json")):
        pytest.skip("installed Hive source and runtime descriptor unavailable")
    assert digest(CODEX) == "9a820c17865fa825d04db416818679a9d63bd72e50835c396f496e5684626c9c"
    verify = _run([str(Path(__file__).resolve().parents[1] / "scripts/the-hive-runtime-service"),
                   "verify", "--home", str(home)], env=os.environ.copy(), cwd=tmp_path)
    assert verify.returncode == 0
    identity = json.loads(verify.stdout)["runtime_identity"]
    assert identity["generation"] == generation
    assert identity["manifest_digest"] == source_descriptor["runtime_manifest_digest"]
    config_digest = digest(personal_codex_home / "config.toml")
    updater_pid = 886704
    assert b"pid-update-loop" in Path(f"/proc/{updater_pid}/cmdline").read_bytes()
    children = Path(f"/proc/{updater_pid}/task/{updater_pid}/children").read_text().split()
    daemons = [int(pid) for pid in children if b"app-server\x00--listen\x00" in
               Path(f"/proc/{pid}/cmdline").read_bytes()]
    assert len(daemons) == 1
    process_ticks = {
        pid: Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        for pid in (updater_pid, daemons[0])
    }
    before = json.loads(registry_path.read_text())
    probe_before = server.read_probe_gate()
    assert len(before["sessions"]) < 1024 and len(before["agents"]) < 1024
    env = {key: os.environ[key] for key in (
        "PATH", "LANG", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "USER", "LOGNAME",
    ) if key in os.environ}
    env.update(HOME=str(tmp_path), CODEX_HOME=str(codex_home),
               LOCAL_RESPONSES_DUMMY_TOKEN="dummy-local-only")
    assert _run([str(CODEX), "--no-daemon", "--version"], env=env,
                cwd=tmp_path).stdout.strip() == "codex-cli 0.161.0"
    (codex_home / "config.toml").write_text("[features]\ndaemon_auto_start=false\n")
    _fixture_plugin(tmp_path, codex_home)
    _trust_installed_hive(codex_home, source_plugin,
                          release / "TheHivePluginBundleV1", personal_codex_home)
    trusted_before = tomllib.loads((codex_home / "config.toml").read_text())["hooks"]["state"]
    for command in (
        [str(CODEX), "--no-daemon", "plugin", "marketplace", "add", str(home)],
        [str(CODEX), "--no-daemon", "plugin", "marketplace", "add", str(tmp_path)],
        [str(CODEX), "--no-daemon", "plugin", "add", "the-hive@personal"],
        [str(CODEX), "--no-daemon", "plugin", "add", "fixture-plugin@local-fixture"],
    ):
        result = _run(command, env=env, cwd=tmp_path)
        assert result.returncode == 0, f"native plugin materialization rc={result.returncode}"
    server._require_managed_codex_daemon_free(codex_home)
    _attest_hive_bundle(source_plugin, release / "TheHivePluginBundleV1", plugin)
    hook_state = tomllib.loads((codex_home / "config.toml").read_text())["hooks"]["state"]
    hive_hooks = [value for key, value in hook_state.items()
                  if key.startswith("the-hive@personal:hooks/hooks.json:")]
    assert len(hive_hooks) == 9 and all(value.get("enabled") is True
                                        and value.get("trusted_hash", "").startswith("sha256:")
                                        for value in hive_hooks)
    assert all(hook_state[key] == value for key, value in trusted_before.items())
    requests: list[dict[str, bool]] = []
    probes: list[dict[str, object]] = []
    units: list[str] = []
    current_unit = [""]
    current_phase = [""]
    started_id = [""]
    started = threading.Event()

    def scope_empty(unit: str) -> bool:
        for _ in range(50):
            state = _run(["systemctl", "--user", "show", unit,
                          "-p", "ActiveState", "-p", "ControlGroup"],
                         env=env, cwd=tmp_path)
            if (state.returncode == 0 and "ActiveState=inactive" in state.stdout
                    and "ControlGroup=\n" in state.stdout):
                return True
            time.sleep(0.1)
        return False

    def direct_hook(name: str, event: dict[str, object]) -> subprocess.CompletedProcess[str]:
        unit = f"hive-resume-{name}-{uuid.uuid4().hex[:10]}.scope"
        units.append(unit)
        result = _run(["systemd-run", "--user", "--scope", "--quiet", "--unit", unit,
                       launcher, "native_spawn_admission" if name == "admission"
                       else "native_bee_event"],
                      env={**env, "PLUGIN_ROOT": str(plugin)}, cwd=tmp_path,
                      input_text=json.dumps(event) + "\n")
        return result

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append({"local": self.path == "/v1/responses",
                             "dummy": self.headers.get("Authorization") ==
                             "Bearer dummy-local-only",
                             "prior": "fixture answer" in str(payload.get("input", []))})
            observation: dict[str, object] = {"phase": current_phase[0]}
            observation["cgroup"] = _run(
                ["systemctl", "--user", "show", current_unit[0],
                 "-p", "ControlGroup", "--value"], env=env,
                cwd=tmp_path).stdout.strip()
            observation["active_cgroup"] = observation["cgroup"].endswith("/" + current_unit[0])
            if started.wait(5):
                sid = started_id[0]
                observation["pin_active"] = _installed_pin_active(pins, sid)
                pin_path = pins / (hashlib.sha256(sid.encode()).hexdigest() + ".json")
                try:
                    observation["pin_transitions"] = [
                        item["state"] for item in json.loads(pin_path.read_text())["state_transitions"]
                    ]
                except (OSError, ValueError, KeyError):
                    observation["pin_transitions"] = []
                if current_phase[0] == "start" and observation["pin_active"]:
                    reservations_before = json.loads(registry_path.read_text())["reservations"]
                    try:
                        admission = direct_hook("admission", {
                            "session_id": sid, "hook_event_name": "PreToolUse",
                            "tool_name": "spawn_agent",
                            "tool_input": {"task_name": "fixture-admission", "message": "local no-op"},
                            "cwd": str(tmp_path),
                        })
                    finally:
                        reservations_after = json.loads(registry_path.read_text())["reservations"]
                        own_before = {row["reservation_id"] for row in reservations_before
                                      if row.get("parent_session_id") == sid}
                        own_new = [row for row in reservations_after
                                   if row.get("parent_session_id") == sid
                                   and row["reservation_id"] not in own_before]
                        observation["reservation_delta"] = len(own_new)
                        if own_new:
                            agent_id = f"fixture-{uuid.uuid4().hex[:12]}"
                            agent = {"session_id": sid, "agent_id": agent_id,
                                     "agent_type": "fixture"}
                            started_agent = direct_hook("agent-start", {
                                **agent, "hook_event_name": "SubagentStart"})
                            stopped_agent = direct_hook("agent-stop", {
                                **agent, "hook_event_name": "SubagentStop"})
                            observation["reservation_cleanup"] = (
                                started_agent.returncode == stopped_agent.returncode == 0
                                and not any(row.get("reservation_id") == own_new[0]["reservation_id"]
                                            for row in json.loads(registry_path.read_text())["reservations"])
                            )
                    try:
                        decision = json.loads(admission.stdout)["hookSpecificOutput"] if admission.stdout else {}
                    except (KeyError, TypeError, ValueError):
                        decision = {}
                    observation["admission_rc"] = admission.returncode
                    observation["admission_decision"] = decision.get("permissionDecision", "allow" if not admission.stdout else None)
                    observation["admission_reason"] = decision.get("permissionDecisionReason")
                    stop = direct_hook("stop", {"session_id": sid,
                                                "hook_event_name": "Stop"})
                    observation["direct_stop_rc"] = stop.returncode
                    observation["direct_stop_json"] = stop.stdout.strip() == "{}"
            probes.append(observation)
            data = _event_stream(len(requests))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args: object) -> None:
            pass

    transport = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=transport.serve_forever, daemon=True)
    thread.start()
    cli = [str(CODEX), "--no-daemon", "-c", "features.daemon_auto_start=false",
           "-c", 'model_provider="local"', "-c", 'model="fixture-model"',
           "-c", 'approval_policy="never"', "-c", 'sandbox_mode="read-only"',
           "-c", 'model_providers.local.name="local"',
           "-c", f'model_providers.local.base_url="http://127.0.0.1:{transport.server_port}/v1"',
           "-c", 'model_providers.local.wire_api="responses"',
           "-c", 'model_providers.local.env_key="LOCAL_RESPONSES_DUMMY_TOKEN"']
    sid = ""
    turns: list[dict[str, object]] = []
    try:
        for phase in ("start", "resume"):
            server._require_managed_codex_daemon_free(codex_home)
            current_phase[0] = phase
            current_unit[0] = f"hive-resume-cli-{uuid.uuid4().hex[:12]}.scope"
            units.append(current_unit[0])
            started.clear()
            tail = (["resume", "--skip-git-repo-check", "--json", sid, "say again"]
                    if sid else ["--skip-git-repo-check", "--json", "say fixture"])
            events: list[dict[str, object]] = []
            with tempfile.TemporaryFile() as stderr_file:
                process = subprocess.Popen(
                    ["systemd-run", "--user", "--scope", "--quiet", "--unit",
                     current_unit[0], *cli, "exec", *tail], env=env, cwd=tmp_path,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=stderr_file, text=True,
                )
                assert process.stdout is not None

                def read_events() -> None:
                    for line in process.stdout:
                        try:
                            event = json.loads(line)
                        except ValueError:
                            continue
                        events.append(event)
                        if event.get("type") == "thread.started":
                            started_id[0] = str(event["thread_id"])
                            started.set()

                reader = threading.Thread(target=read_events, daemon=True)
                reader.start()
                try:
                    rc = process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)
                    raise
                reader.join(timeout=5)
            _wait_own_scope_empty(current_unit[0], codex_home, env, tmp_path)
            server._require_managed_codex_daemon_free(codex_home)
            ids = [event["thread_id"] for event in events
                   if event.get("type") == "thread.started"]
            sid = sid or (str(ids[0]) if ids else "")
            turns.append({"phase": phase, "rc": rc, "same_thread": ids == [sid],
                          "completed": any(event.get("type") == "turn.completed"
                                           for event in events)})
            assert rc == 0 and turns[-1]["same_thread"] and turns[-1]["completed"]
        assert len(requests) == 2 and all(item["local"] and item["dummy"]
                                          for item in requests)
        assert requests[1]["prior"]
        assert probes[0]["pin_active"] and probes[0]["active_cgroup"]
        assert probes[1]["pin_active"] and probes[1]["active_cgroup"]
        assert probes[1]["pin_transitions"][-3:] == ["active", "ended", "active"]
        assert probes[0]["direct_stop_rc"] == 0 and probes[0]["direct_stop_json"]
        recorded = [json.loads(line) for line in (tmp_path / "hook-events.jsonl").read_text().splitlines()]
        assert [(event["hook_event_name"], event.get("source")) for event in recorded] == [
            ("SessionStart", "startup"), ("Stop", None),
            ("SessionStart", "resume"), ("Stop", None),
        ]
        assert all(event["session_id"] == sid for event in recorded)
        assert [event["cgroup"].removeprefix("0::") for event in recorded] == [
            probes[0]["cgroup"], probes[0]["cgroup"],
            probes[1]["cgroup"], probes[1]["cgroup"],
        ]
        for item in probes:
            scope = Path("/sys/fs/cgroup" + item["cgroup"])
            assert not scope.exists() or not (scope / "cgroup.procs").read_text().strip()
        after = json.loads(registry_path.read_text())
        assert [item for item in after["sessions"] if item.get("session_id") != sid] == before["sessions"]
        assert [item for item in after["agents"] if item.get("session_id") != sid] == before["agents"]
        assert [item for item in after["reservations"] if item.get("parent_session_id") != sid] == before["reservations"]
        assert not any(item.get("parent_session_id") == sid for item in after["reservations"])
        assert not any(item.get("session_id") == sid and item.get("activity_state") == "active"
                       for item in after["agents"])
        assert any(item.get("session_id") == sid and item.get("activity_state") == "ended"
                   for item in after["sessions"])
        assert not _installed_pin_active(pins, sid)
        server._require_managed_codex_daemon_free(codex_home)
        assert digest(personal_codex_home / "config.toml") == config_digest
        assert all(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
                   == tick for pid, tick in process_ticks.items())
        gate_after = server.read_probe_gate()
        print(json.dumps({"cli_turns": turns, "admission":
                          {"decision": probes[0]["admission_decision"],
                           "reason": probes[0]["admission_reason"],
                           "reservation_delta": probes[0]["reservation_delta"]},
                          "probe_before": probe_before.get("reason_code"),
                          "probe_after": gate_after.get("reason_code"),
                          "fixture_direct_stop": True, "codex_auto_stop": True,
                          "resume_pin_active": probes[1]["pin_active"],
                          "foreign_registry_preserved": True,
                          "own_scopes_empty": True}, sort_keys=True))
        assert probes[0]["admission_rc"] == 0
        assert probes[0]["admission_decision"] in {"allow", "deny"}
        assert probes[0]["admission_reason"] is None or "invalid_pretooluse_input" not in probes[0]["admission_reason"]
        if probes[0]["admission_decision"] == "allow":
            assert probes[0]["reservation_delta"] == 1
            assert probes[0]["reservation_cleanup"]
        else:
            assert probes[0]["reservation_delta"] == 0
            assert isinstance(probes[0]["admission_reason"], str)
            assert "hook_error" not in probes[0]["admission_reason"], "valid admission blocked; inspect probe gate"
    finally:
        cleanup_errors = []
        try:
            transport.shutdown()
            transport.server_close()
            thread.join(timeout=5)
            if thread.is_alive():
                cleanup_errors.append("transport_thread_not_stopped")
        except Exception:
            cleanup_errors.append("transport_shutdown_failed")
        try:
            if started_id[0] and _installed_pin_active(pins, started_id[0]):
                ended = direct_hook("end", {"session_id": started_id[0],
                                            "hook_event_name": "SessionEnd"})
                if ended.returncode != 0:
                    cleanup_errors.append("own_pin_end_failed")
        except Exception:
            cleanup_errors.append("own_pin_end_failed")
        for unit in units:
            try:
                if not scope_empty(unit):
                    _run(["systemctl", "--user", "stop", unit], env=env, cwd=tmp_path)
            except Exception:
                cleanup_errors.append(f"own_scope_stop_failed:{unit}")
        for unit in units:
            try:
                if not scope_empty(unit):
                    cleanup_errors.append(f"own_scope_not_empty:{unit}")
            except Exception:
                cleanup_errors.append(f"own_scope_check_failed:{unit}")
        own_processes = []
        for proc in Path("/proc").glob("[0-9]*"):
            try:
                if (proc / "cwd").resolve() == tmp_path:
                    own_processes.append(proc.name)
            except OSError:
                pass
        if own_processes:
            cleanup_errors.append(f"own_processes_remain:{own_processes}")
        if not cleanup_errors:
            shutil.rmtree(tmp_path)
        assert not cleanup_errors, f"cleanup incomplete: {cleanup_errors}"
