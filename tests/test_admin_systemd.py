from __future__ import annotations

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "systemd" / "the-hive-admin.service"
AGENT_API_UNIT = ROOT / "systemd" / "the-hive-agent-api.service"
HOST_AGENT_UNIT = ROOT / "systemd" / "the-hive-host-agent.service"
SYSUSERS = ROOT / "systemd" / "sysusers.d" / "the-hive-host-agent.conf"
TMPFILES = ROOT / "systemd" / "tmpfiles.d" / "the-hive-host-agent.conf"
MASTER_SYSUSERS = ROOT / "systemd" / "sysusers.d" / "the-hive-agent-api.conf"
MASTER_TMPFILES = ROOT / "systemd" / "tmpfiles.d" / "the-hive-agent-api.conf"


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

    assert document["project"]["scripts"]["the-hive-admin"] == (
        "the_hive.admin_daemon:main"
    )
    assert _directives("Service")["ExecStart"] == [
        "@THE_HIVE_BINDIR@/the-hive-admin"
    ]


def test_unit_passes_every_secret_only_as_a_systemd_credential() -> None:
    """Production break: env and argv leak secrets through procfs and diagnostics."""

    service = _directives("Service")
    credentials = service["LoadCredential"]

    assert credentials == [
        "admin-config:/etc/the-hive-admin/admin-config.json",
        "admin-bearer:/etc/the-hive-admin/admin-bearer",
        "admin-totp:/etc/the-hive-admin/admin-totp",
        "admin-attestation:/etc/the-hive-admin/admin-attestation",
        "admin-vault-key:/etc/the-hive-admin/admin-vault-key",
        "admin-quota-evidence:/etc/the-hive-admin/admin-quota-evidence.json",
        "agent-bindings:/etc/the-hive-admin/agent-bindings.json",
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

    assert service["User"] == ["the-hive-admin"]
    assert service["Group"] == ["the-hive-admin"]
    assert service["RuntimeDirectory"] == ["the-hive-admin"]
    assert service["RuntimeDirectoryMode"] == ["0700"]
    assert service["StateDirectory"] == ["codex-master-admin"]
    assert service["StateDirectoryMode"] == ["0700"]
    assert service["UMask"] == ["0007"]
    assert service["SupplementaryGroups"] == ["the-hive-agent-state"]
    assert service["ReadWritePaths"] == [
        "/run/the-hive-admin /var/lib/codex-master-admin /var/lib/codex-master-agent"
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

    assert document["project"]["scripts"]["the-hive-agent-api"] == (
        "the_hive.agent_daemon:main"
    )
    assert service["Type"] == ["exec"]
    assert service["User"] == ["the-hive-agent-api"]
    assert service["Group"] == ["the-hive-agent-api"]
    assert service["WorkingDirectory"] == ["/var/empty"]
    assert service["UMask"] == ["0007"]
    assert service["SupplementaryGroups"] == ["the-hive-agent-state"]
    assert service["ReadWritePaths"] == ["/var/lib/codex-master-agent"]
    assert service["ExecStart"] == [
        "@THE_HIVE_BINDIR@/the-hive-agent-api "
        "--listen-address-credential --port=9443"
    ]
    assert service["TimeoutStopSec"] == ["10s"]
    assert service["LoadCredential"] == [
        "agent-server-key:/etc/the-hive/agent-server.key",
        "agent-server-cert:/etc/the-hive/agent-server.crt",
        "agent-client-ca:/etc/the-hive/agent-client-ca.crt",
        "agent-listen-address:/etc/the-hive/agent-listen-address",
    ]
    assert "BindPaths" not in service
    assert "BindReadOnlyPaths" not in service
    assert "Environment" not in service
    assert "EnvironmentFile" not in service
    assert "DynamicUser" not in service
    _assert_hardening(service)
    assert "admin" not in " ".join(service["ExecStart"]).lower()
    assert "agent-bindings" not in service["LoadCredential"]


def test_agent_api_waits_for_admin_binding_provisioning() -> None:
    unit = _directives("Unit", AGENT_API_UNIT)

    assert unit["Requires"] == ["the-hive-admin.service"]
    assert unit["After"] == [
        "network-online.target the-hive-admin.service"
    ]


def test_host_agent_unit_has_exact_hardening_credentials_and_write_scope() -> None:
    """Production break: a host agent can otherwise leak keys or write broadly."""

    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    service = _directives("Service", HOST_AGENT_UNIT)

    assert document["project"]["scripts"]["the-hive-host-agent"] == (
        "the_hive.host_agent:main"
    )
    assert service["Type"] == ["exec"]
    assert service["User"] == ["the-hive-host-agent"]
    assert service["Group"] == ["the-hive-host-agent"]
    assert service["WorkingDirectory"] == ["/var/empty"]
    assert service["RuntimeDirectory"] == ["the-hive-host-agent"]
    assert service["RuntimeDirectoryMode"] == ["0700"]
    assert service["StateDirectory"] == ["codex-master-host-agent"]
    assert service["StateDirectoryMode"] == ["0700"]
    assert service["UMask"] == ["0077"]
    assert service["ReadWritePaths"] == [
        "/var/lib/codex-master-host-agent",
    ]
    assert service["ExecStart"] == [
        "@THE_HIVE_BINDIR@/the-hive-host-agent"
    ]
    assert service["PAMName"] == ["login"]
    assert service["TimeoutStopSec"] == ["10s"]
    assert set(service["LoadCredential"]) == {
        "agent-client-key:/etc/the-hive/agent-client.key",
        "agent-client-cert:/etc/the-hive/agent-client.crt",
        "agent-master-ca:/etc/the-hive/agent-master-ca.crt",
        "agent-config:/etc/the-hive/agent-config.json",
    }
    assert "Environment" not in service
    assert "EnvironmentFile" not in service
    assert "DynamicUser" not in service
    _assert_hardening(service)
    exec_start = " ".join(service["ExecStart"]).lower()
    assert not any(marker in exec_start for marker in ("key", "cert", "config", "secret"))


def test_static_accounts_and_shared_agent_state_are_deployable() -> None:
    """Production break: distinct service UIDs need one deliberate non-secret bridge."""

    assert MASTER_SYSUSERS.read_text(encoding="utf-8").splitlines() == [
        "g the-hive-admin -",
        "g the-hive-agent-api -",
        "g the-hive-agent-state -",
        'u the-hive-admin - "The Hive administration daemon" /var/empty',
        'u the-hive-agent-api - "The Hive agent API" /var/empty',
        "m the-hive-admin the-hive-agent-state",
        "m the-hive-agent-api the-hive-agent-state",
    ]
    assert MASTER_TMPFILES.read_text(encoding="utf-8").splitlines() == [
        "d /var/lib/codex-master-agent 2770 the-hive-agent-api the-hive-agent-state -",
    ]
    assert SYSUSERS.read_text(encoding="utf-8").splitlines() == [
        "g the-hive-host-agent -",
        'u the-hive-host-agent - "The Hive outbound host agent" /var/empty',
    ]
    assert TMPFILES.read_text(encoding="utf-8").splitlines() == [
        "d /var/lib/codex-master-host-agent 0700 the-hive-host-agent the-hive-host-agent -",
        "d /var/lib/codex-master-host-agent/ollama 0700 the-hive-host-agent the-hive-host-agent -",
    ]


def test_wheel_contract_contains_installer_units_and_static_account_layout() -> None:
    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert document["tool"]["setuptools"]["data-files"] == {
        "lib/the-hive/systemd": [
            "systemd/the-hive-admin.service",
            "systemd/the-hive-agent-api.service",
            "systemd/the-hive-host-agent.service",
        ],
        "lib/the-hive/systemd/sysusers.d": [
            "systemd/sysusers.d/the-hive-agent-api.conf",
            "systemd/sysusers.d/the-hive-host-agent.conf"
        ],
        "lib/the-hive/systemd/tmpfiles.d": [
            "systemd/tmpfiles.d/the-hive-agent-api.conf",
            "systemd/tmpfiles.d/the-hive-host-agent.conf"
        ],
        "libexec/the-hive": ["scripts/install-host-agent"],
    }


def test_systemd_tree_has_no_legacy_product_identifier() -> None:
    """Rename break: R3 bytes must not retain old product identifiers.

    The explicitly deferred D83/R4 state roots remain index-bound in this
    slice, so remove only those exact state-root components before checking
    the delivered R3 files.
    """

    systemd_root = ROOT / "systemd"
    legacy_tokens = ("codex-master", "codex_master", "CODEX_MASTER")
    deferred_r4_state_components = (
        "%h/.local/state/codex-master-mcp",
        "/var/lib/codex-master-home-broker",
        "/var/lib/codex-master-host-agent",
        "/var/lib/codex-master-admin",
        "/var/lib/codex-master-agent",
        "codex-master-home-broker",
        "codex-master-host-agent",
        "codex-master-admin",
    )
    deferred_r4_instance_id_lines = {
        "the-hive-watchdog.service": "Environment=CODEX_MASTER_MCP_INSTANCE_ID=the-hive-watchdog",
        "the-hive-goddess-report.service": "Environment=CODEX_MASTER_MCP_INSTANCE_ID=the-hive-goddess-report",
    }

    def r3_text(path: Path) -> str:
        text = path.read_text(encoding="utf-8")
        for component in deferred_r4_state_components:
            text = text.replace(component, "<deferred-r4-state>")
        instance_id_line = deferred_r4_instance_id_lines.get(path.name)
        if instance_id_line is not None:
            text = text.replace(instance_id_line, "<deferred-r4-instance-id>")
        return text

    assert all(
        token not in path.as_posix()
        and token not in r3_text(path)
        for path in systemd_root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
        for token in legacy_tokens
    )
