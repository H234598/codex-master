from __future__ import annotations

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "systemd" / "codex-master-admin.service"
AGENT_API_UNIT = ROOT / "systemd" / "codex-master-agent-api.service"
HOST_AGENT_UNIT = ROOT / "systemd" / "codex-master-host-agent.service"
SYSUSERS = ROOT / "systemd" / "sysusers.d" / "codex-master-host-agent.conf"
TMPFILES = ROOT / "systemd" / "tmpfiles.d" / "codex-master-host-agent.conf"


def _directives(
    section: str, unit: Path = UNIT
) -> dict[str, list[str]]:
    current = ""
    result: dict[str, list[str]] = {}
    for raw_line in unit.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
        elif current == section and line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result.setdefault(key, []).append(value)
    return result


def test_unit_exposes_the_admin_cli_entrypoint() -> None:
    """Production break: systemd cannot supervise a module-only daemon."""

    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert document["project"]["scripts"]["codex-master-admin"] == (
        "codex_master.admin_daemon:main"
    )
    assert _directives("Service")["ExecStart"] == ["/usr/bin/codex-master-admin"]


def test_unit_passes_every_secret_only_as_a_systemd_credential() -> None:
    """Production break: env and argv leak secrets through procfs and diagnostics."""

    service = _directives("Service")
    credentials = service["LoadCredential"]

    assert credentials == [
        "admin-config:/etc/codex-master-admin/admin-config.json",
        "admin-bearer:/etc/codex-master-admin/admin-bearer",
        "admin-totp:/etc/codex-master-admin/admin-totp",
        "admin-attestation:/etc/codex-master-admin/admin-attestation",
        "admin-vault-key:/etc/codex-master-admin/admin-vault-key",
        "admin-quota-evidence:/etc/codex-master-admin/admin-quota-evidence.json",
        "agent-bindings:/etc/codex-master-admin/agent-bindings.json",
    ]
    assert "Environment" not in service
    assert "EnvironmentFile" not in service
    exec_start = " ".join(service["ExecStart"]).lower()
    assert all(
        marker not in exec_start
        for marker in ("bearer", "totp", "attestation", "vault-key", "secret")
    )


def test_unit_owns_private_runtime_and_state_write_boundaries() -> None:
    """Production break: GUI users or broad paths can own durable admin state."""

    service = _directives("Service")

    assert service["User"] == ["codex-master-admin"]
    assert service["Group"] == ["codex-master-admin"]
    assert service["RuntimeDirectory"] == ["codex-master-admin"]
    assert service["RuntimeDirectoryMode"] == ["0700"]
    assert service["StateDirectory"] == ["codex-master-admin"]
    assert service["StateDirectoryMode"] == ["0700"]
    assert service["UMask"] == ["0007"]
    assert service["SupplementaryGroups"] == ["codex-master-agent-state"]
    assert service["ReadWritePaths"] == [
        "/run/codex-master-admin /var/lib/codex-master-admin /var/lib/codex-master-agent"
    ]
    assert "DynamicUser" not in service


def test_unit_hardening_is_fail_closed_and_has_no_http_health_probe() -> None:
    """Production break: weak sandboxing or health curls can bypass daemon readiness."""

    service = _directives("Service")

    expected = {
        "Type": ["notify"],
        "Restart": ["on-failure"],
        "RestartSec": ["5s"],
        "NoNewPrivileges": ["yes"],
        "ProtectSystem": ["strict"],
        "ProtectHome": ["yes"],
        "PrivateTmp": ["yes"],
        "PrivateDevices": ["yes"],
        "PrivateMounts": ["yes"],
        "ProtectKernelTunables": ["yes"],
        "ProtectKernelModules": ["yes"],
        "ProtectKernelLogs": ["yes"],
        "ProtectControlGroups": ["yes"],
        "LockPersonality": ["yes"],
        "RestrictRealtime": ["yes"],
        "RestrictSUIDSGID": ["yes"],
        "CapabilityBoundingSet": [""],
        "AmbientCapabilities": [""],
        "RestrictAddressFamilies": ["AF_UNIX AF_INET AF_INET6"],
    }
    assert {key: service.get(key) for key in expected} == expected
    unit_text = UNIT.read_text(encoding="utf-8").lower()
    assert "health" not in unit_text
    assert "curl" not in unit_text
    assert "wget" not in unit_text


def _assert_hardening(service: dict[str, list[str]]) -> None:
    expected = {
        "Restart": ["on-failure"],
        "RestartSec": ["5s"],
        "NoNewPrivileges": ["yes"],
        "ProtectSystem": ["strict"],
        "ProtectHome": ["yes"],
        "PrivateTmp": ["yes"],
        "PrivateDevices": ["yes"],
        "PrivateMounts": ["yes"],
        "ProtectKernelTunables": ["yes"],
        "ProtectKernelModules": ["yes"],
        "ProtectKernelLogs": ["yes"],
        "ProtectControlGroups": ["yes"],
        "LockPersonality": ["yes"],
        "RestrictRealtime": ["yes"],
        "RestrictSUIDSGID": ["yes"],
        "CapabilityBoundingSet": [""],
        "AmbientCapabilities": [""],
        "RestrictAddressFamilies": ["AF_INET AF_INET6 AF_UNIX"],
    }
    assert {key: service.get(key) for key in expected} == expected


def test_agent_api_unit_uses_private_tls_entrypoint_and_credentials() -> None:
    """Production break: the API can accidentally expose Admin or plaintext HTTP."""

    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    service = _directives("Service", AGENT_API_UNIT)

    assert document["project"]["scripts"]["codex-master-agent-api"] == (
        "codex_master.agent_daemon:main"
    )
    assert service["Type"] == ["exec"]
    assert service["User"] == ["codex-master-agent-api"]
    assert service["Group"] == ["codex-master-agent-api"]
    assert service["WorkingDirectory"] == ["/var/empty"]
    assert service["UMask"] == ["0007"]
    assert service["SupplementaryGroups"] == ["codex-master-agent-state"]
    assert service["ReadWritePaths"] == ["/var/lib/codex-master-agent"]
    assert service["ExecStart"] == [
        "/usr/bin/codex-master-agent-api --listen-address=127.0.0.1 --port=9443"
    ]
    assert service["TimeoutStopSec"] == ["10s"]
    assert service["LoadCredential"] == [
        "agent-server-key:/etc/codex-master/agent-server.key",
        "agent-server-cert:/etc/codex-master/agent-server.crt",
        "agent-client-ca:/etc/codex-master/agent-client-ca.crt",
    ]
    assert "BindPaths" not in service
    assert "BindReadOnlyPaths" not in service
    assert "Environment" not in service
    assert "EnvironmentFile" not in service
    assert "DynamicUser" not in service
    _assert_hardening(service)
    assert "admin" not in " ".join(service["ExecStart"]).lower()
    assert "agent-bindings" not in service["LoadCredential"]


def test_host_agent_unit_has_exact_hardening_credentials_and_write_scope() -> None:
    """Production break: a host agent can otherwise leak keys or write broadly."""

    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    service = _directives("Service", HOST_AGENT_UNIT)

    assert document["project"]["scripts"]["codex-master-host-agent"] == (
        "codex_master.host_agent:main"
    )
    assert service["Type"] == ["exec"]
    assert service["User"] == ["codex-master-host-agent"]
    assert service["Group"] == ["codex-master-host-agent"]
    assert service["WorkingDirectory"] == ["/var/empty"]
    assert service["RuntimeDirectory"] == ["codex-master-host-agent"]
    assert service["RuntimeDirectoryMode"] == ["0700"]
    assert service["StateDirectory"] == ["codex-master-host-agent"]
    assert service["StateDirectoryMode"] == ["0700"]
    assert service["UMask"] == ["0077"]
    assert service["ReadWritePaths"] == [
        "/var/lib/codex-master-host-agent",
    ]
    assert service["ExecStart"] == ["/usr/bin/codex-master-host-agent"]
    assert service["TimeoutStopSec"] == ["10s"]
    assert set(service["LoadCredential"]) == {
        "agent-client-key:/etc/codex-master/agent-client.key",
        "agent-client-cert:/etc/codex-master/agent-client.crt",
        "agent-master-ca:/etc/codex-master/agent-master-ca.crt",
        "agent-config:/etc/codex-master/agent-config.json",
    }
    assert "Environment" not in service
    assert "EnvironmentFile" not in service
    assert "DynamicUser" not in service
    _assert_hardening(service)
    exec_start = " ".join(service["ExecStart"]).lower()
    assert not any(marker in exec_start for marker in ("key", "cert", "config", "secret"))


def test_static_accounts_and_shared_agent_state_are_deployable() -> None:
    """Production break: distinct service UIDs need one deliberate non-secret bridge."""

    assert SYSUSERS.read_text(encoding="utf-8").splitlines() == [
        "g codex-master-admin -",
        "g codex-master-agent-api -",
        "g codex-master-host-agent -",
        "g codex-master-agent-state -",
        'u codex-master-admin - "Codex Master administration daemon" /var/empty',
        'u codex-master-agent-api - "Codex Master agent API" /var/empty',
        'u codex-master-host-agent - "Codex Master outbound host agent" /var/empty',
        "m codex-master-admin codex-master-agent-state",
        "m codex-master-agent-api codex-master-agent-state",
    ]
    assert TMPFILES.read_text(encoding="utf-8").splitlines() == [
        "d /var/lib/codex-master-agent 2770 codex-master-agent-api codex-master-agent-state -",
        "d /var/lib/codex-master-host-agent 0700 codex-master-host-agent codex-master-host-agent -",
        "d /var/lib/codex-master-host-agent/ollama 0700 codex-master-host-agent codex-master-host-agent -",
    ]


def test_wheel_contract_contains_installer_units_and_static_account_layout() -> None:
    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert document["tool"]["setuptools"]["data-files"] == {
        "lib/codex-master/systemd": [
            "systemd/codex-master-admin.service",
            "systemd/codex-master-agent-api.service",
            "systemd/codex-master-host-agent.service",
        ],
        "lib/codex-master/systemd/sysusers.d": [
            "systemd/sysusers.d/codex-master-host-agent.conf"
        ],
        "lib/codex-master/systemd/tmpfiles.d": [
            "systemd/tmpfiles.d/codex-master-host-agent.conf"
        ],
        "libexec/codex-master": ["scripts/install-host-agent"],
    }
