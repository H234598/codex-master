from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Iterator

from codex_master import server
from codex_master.admin_contracts import AdminPrincipalV1
from codex_master.admin_socket import AdminSocketServer
from test_admin_service import service_at


@contextmanager
def _admin_socket(tmp_path: Path) -> Iterator[tuple[Path, Path, object]]:
    credential_directory = tmp_path / "credentials"
    credential_directory.mkdir(mode=0o700)
    key_path = credential_directory / "masterjet-local-attestation-key"
    key_path.write_bytes(b"k" * 32)
    key_path.chmod(0o400)
    key_fd = os.open(key_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    service, owners = service_at()
    principal = AdminPrincipalV1(
        "operator-one",
        (
            "fleet.read",
            "fleet.openai.write",
            "fleet.google.oauth",
            "fleet.google.provision",
            "fleet.google.billing.bind",
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
