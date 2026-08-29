from __future__ import annotations

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "systemd" / "codex-master-admin.service"


def _directives(section: str) -> dict[str, list[str]]:
    current = ""
    result: dict[str, list[str]] = {}
    for raw_line in UNIT.read_text(encoding="utf-8").splitlines():
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
    assert service["UMask"] == ["0077"]
    assert service["ReadWritePaths"] == [
        "/run/codex-master-admin /var/lib/codex-master-admin"
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
