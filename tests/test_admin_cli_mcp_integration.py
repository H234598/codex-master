from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Iterator

from codex_master import server
from codex_master.admin_contracts import AdminPrincipalV1, OperationV1
from codex_master.admin_socket import AdminSocketServer
from test_admin_service import service_at


PROBE_CREATED = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


class _HostProbeOwner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int, str]] = []

    def probe(
        self,
        host_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> OperationV1:
        self.calls.append((host_ref, expected_generation, idempotency_key))
        return OperationV1(
            "op-host-probe",
            "hosts.probe",
            "planned",
            expected_generation,
            None,
            "sha256:" + "a" * 64,
            PROBE_CREATED,
            PROBE_CREATED + timedelta(minutes=15),
            0,
            0,
            1,
            ("control.plan_ready",),
        )


def _probe_projection() -> dict[str, object]:
    return {
        "schema_version": 1,
        "id": "op-host-probe",
        "kind": "hosts.probe",
        "state": "planned",
        "expected_generation": 4,
        "resulting_generation": None,
        "plan_digest": "sha256:" + "a" * 64,
        "created_at": "2026-08-30T12:00:00Z",
        "expires_at": "2026-08-30T12:15:00Z",
        "completed_count": 0,
        "failed_count": 0,
        "not_attempted_count": 1,
        "reason_codes": ["control.plan_ready"],
    }


@contextmanager
def _admin_socket(tmp_path: Path) -> Iterator[tuple[Path, Path, object]]:
    credential_directory = tmp_path / "credentials"
    credential_directory.mkdir(mode=0o700)
    key_path = credential_directory / "masterjet-local-attestation-key"
    key_path.write_bytes(b"k" * 32)
    key_path.chmod(0o400)
    key_fd = os.open(key_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    service, owners = service_at()
    owners.host_probe = _HostProbeOwner()
    service._host_probe = owners.host_probe
    principal = AdminPrincipalV1(
        "operator-one",
        (
            "fleet.read",
            "fleet.host.read",
            "fleet.openai.write",
            "fleet.google.oauth",
            "fleet.google.provision",
            "fleet.google.billing.bind",
            "fleet.host.probe",
        ),
        "unix_peer",
        True,
    )
    adapter = AdminSocketServer(
        tmp_path / "socket" / "admin.sock",
        service,
        lambda _peer: principal,
        attestation_key_fd=key_fd,
    )
    adapter.start()
    try:
        yield adapter.path, credential_directory, owners
    finally:
        adapter.close()
        os.close(key_fd)


def _subprocess_env(
    tmp_path: Path, socket_path: Path, credential_directory: Path
) -> dict[str, str]:
    home = tmp_path / "home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    state = tmp_path / "state"
    state.mkdir()
    registry = state / "teamleaders.json"
    registry.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "principals": [
                    {
                        "digest": server.teamleader_principal_digest(codex_home),
                        "class": "koenigin",
                        "agent_id": None,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    registry.chmod(0o600)
    source = Path(__file__).resolve().parents[1] / "src"
    return {
        "HOME": str(home),
        "CODEX_HOME": str(codex_home),
        "CODEX_MASTER_MCP_STATE": str(state),
        "CODEX_MASTER_ADMIN_SOCKET": str(socket_path),
        "CREDENTIALS_DIRECTORY": str(credential_directory),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ["PATH"],
        "PYTHONPATH": str(source),
    }


def _run_child(
    arguments: list[str],
    *,
    env: dict[str, str],
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        arguments,
        env=env,
        stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    pid = process.pid
    try:
        stdout, stderr = process.communicate(input_text, timeout=20)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)
    assert not Path(f"/proc/{pid}").exists()
    return subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)


def test_real_host_probe_cli_uses_exact_parser_contract_and_internal_key(
    tmp_path: Path,
) -> None:
    with _admin_socket(tmp_path) as (socket_path, credential_directory, owners):
        environment = _subprocess_env(tmp_path, socket_path, credential_directory)
        completed = _run_child(
            [
                sys.executable,
                "-m",
                "codex_master.server",
                "fleet",
                "host",
                "probe",
                "worker-one",
                "--expected-generation",
                "4",
                "--json",
            ],
            env=environment,
        )
        rejected = _run_child(
            [
                sys.executable,
                "-m",
                "codex_master.server",
                "fleet",
                "host",
                "probe",
                "worker-one",
                "--expected-generation",
                "4",
                "--json",
                "--idempotency-key",
                "operator-key",
            ],
            env=environment,
        )
        missing_json = _run_child(
            [
                sys.executable,
                "-m",
                "codex_master.server",
                "fleet",
                "host",
                "probe",
                "worker-one",
                "--expected-generation",
                "4",
            ],
            env=environment,
        )
        help_result = _run_child(
            [
                sys.executable,
                "-m",
                "codex_master.server",
                "fleet",
                "host",
                "probe",
                "--help",
            ],
            env=environment,
        )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == _probe_projection()
    expected_key = "cli-probe-" + hashlib.sha256(b"worker-one\x004").hexdigest()
    assert owners.host_probe.calls == [("worker-one", 4, expected_key)]
    assert len(expected_key) <= 128
    assert rejected.returncode == 2
    assert "--idempotency-key" in rejected.stderr
    assert "unrecognized arguments" in rejected.stderr
    assert missing_json.returncode == 2
    assert "--json" in missing_json.stderr
    assert help_result.returncode == 0
    assert "--idempotency-key" not in help_result.stdout


def test_real_registered_host_probe_mcp_call_forwards_caller_key(
    tmp_path: Path,
) -> None:
    list_request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    call_request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "fleet_host_probe",
            "arguments": {
                "host_ref": "worker-one",
                "expected_generation": 4,
                "idempotency_key": "caller-probe-key",
            },
        },
    }
    hosts_request = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "fleet_hosts", "arguments": {}},
    }
    with _admin_socket(tmp_path) as (socket_path, credential_directory, owners):
        completed = _run_child(
            [sys.executable, "-m", "codex_master.server"],
            input_text="\n".join(
                (
                    json.dumps(list_request),
                    json.dumps(call_request),
                    json.dumps(hosts_request),
                    "",
                )
            ),
            env=_subprocess_env(tmp_path, socket_path, credential_directory),
        )

    assert completed.returncode == 0, completed.stderr
    listed, response, hosts_response = [
        json.loads(line) for line in completed.stdout.splitlines()
    ]
    visible_names = {tool["name"] for tool in listed["result"]["tools"]}
    assert "fleet_host_probe" in visible_names
    assert "fleet_hosts" in visible_names
    assert response["result"]["isError"] is False
    assert json.loads(response["result"]["content"][0]["text"]) == _probe_projection()
    assert hosts_response["result"]["isError"] is False
    assert "hosts" in json.loads(hosts_response["result"]["content"][0]["text"])
    assert owners.host_probe.calls == [("worker-one", 4, "caller-probe-key")]


def test_real_cli_process_calls_attested_admin_socket(tmp_path: Path) -> None:
    with _admin_socket(tmp_path) as (socket_path, credential_directory, _owners):
        completed = _run_child(
            [
                sys.executable,
                "-m",
                "codex_master.server",
                "fleet",
                "google",
                "inventory",
            ],
            env=_subprocess_env(tmp_path, socket_path, credential_directory),
        )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "registry_generation": 4,
        "accounts": [
            {
                "billing_count": 1,
                "billing_refs": ["billing-one"],
                "default_oauth_client_ref": "oauth-client-opaque",
                "enabled": True,
                "inventory_generation": 4,
                "label": "Google One",
                "oauth_client_availability": "available",
                "oauth_state": "ready",
                "project_count": 1,
                "quota_state": "fresh",
                "ref": "google-one",
                "reload_state": "ready",
                "subject_bound": True,
            }
        ],
    }


def test_real_mcp_stdio_process_calls_same_attested_admin_socket(
    tmp_path: Path,
) -> None:
    list_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
    }
    call_request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "fleet_google_inventory", "arguments": {}},
    }
    quota_request = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "fleet_google_quota_evidence_sync",
            "arguments": {
                "account_ref": "google-one",
                "remaining": "9",
                "observed_at": "2026-08-30T00:01:00Z",
                "source": "cloudresourcemanager",
                "inventory_fingerprint": "sha256:" + "a" * 64,
                "expected_generation": 4,
                "idempotency_key": "quota-sync-mcp",
            },
        },
    }
    with _admin_socket(tmp_path) as (socket_path, credential_directory, owners):
        completed = _run_child(
            [sys.executable, "-m", "codex_master.server"],
            input_text="\n".join(
                (
                    json.dumps(list_request),
                    json.dumps(call_request),
                    json.dumps(quota_request),
                    "",
                )
            ),
            env=_subprocess_env(tmp_path, socket_path, credential_directory),
        )

    assert completed.returncode == 0, completed.stderr
    listed, response, quota_response = [
        json.loads(line) for line in completed.stdout.splitlines()
    ]
    visible_names = {tool["name"] for tool in listed["result"]["tools"]}
    assert "fleet_google_inventory" in visible_names
    assert "fleet_openai_auth_plan" in visible_names
    assert "fleet_google_quota_evidence_sync" in visible_names
    assert response["result"]["isError"] is False
    assert (
        json.loads(response["result"]["content"][0]["text"])["accounts"][0]["ref"]
        == "google-one"
    )
    assert quota_response["result"]["isError"] is False
    assert owners.quota_collector is not None
    assert owners.quota_collector.sync_calls[-1][0] == "google-one"


def test_real_cli_process_syncs_quota_evidence_without_restart(tmp_path: Path) -> None:
    with _admin_socket(tmp_path) as (socket_path, credential_directory, owners):
        completed = _run_child(
            [
                sys.executable,
                "-m",
                "codex_master.server",
                "fleet",
                "google",
                "quota-sync",
                "--account-ref",
                "google-one",
                "--remaining",
                "9",
                "--observed-at",
                "2026-08-30T00:01:00Z",
                "--source",
                "cloudresourcemanager",
                "--inventory-fingerprint",
                "sha256:" + "a" * 64,
                "--expected-generation",
                "4",
                "--idempotency-key",
                "quota-sync-cli",
            ],
            env=_subprocess_env(tmp_path, socket_path, credential_directory),
        )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "account_ref": "google-one",
        "remaining": 9,
        "inventory_generation": 4,
    }
    assert owners.quota_collector is not None
    assert owners.quota_collector.sync_calls[-1][0] == "google-one"
