"""Immutable offline installation data for the home-broker payload."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class InstallDirectory:
    path: str
    uid: int
    gid: int
    mode: int


@dataclass(frozen=True, slots=True)
class InstallFile:
    source_path: str
    target_path: str
    uid: int
    gid: int
    mode: int


@dataclass(frozen=True, slots=True)
class InstallPlan:
    payload_version: str
    directories: tuple[InstallDirectory, ...]
    files: tuple[InstallFile, ...]


def build_home_broker_install_plan() -> InstallPlan:
    files = tuple(
        sorted(
            (
                InstallFile(
                    "systemd/config/codex-master-home-broker.conf",
                    "/etc/codex-master/home-broker.conf",
                    0,
                    0,
                    0o400,
                ),
                InstallFile(
                    "systemd/manifest/codex-master-home-broker-manifest-v1.json",
                    "/usr/lib/codex-master-home-broker/manifest-v1.json",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "bin/codex-master-home-broker",
                    "/usr/lib/codex-master-home-broker/0.10.5/bin/codex-master-home-broker",
                    0,
                    0,
                    0o755,
                ),
                InstallFile(
                    "src/codex_master/__init__.py",
                    "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master/__init__.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/codex_master/fleet_agent_launcher.py",
                    "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master/fleet_agent_launcher.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/codex_master/fleet_home_broker.py",
                    "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master/fleet_home_broker.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/codex_master/fleet_home_broker_client.py",
                    "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master/fleet_home_broker_client.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/codex_master/fleet_home_broker_identity.py",
                    "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master/fleet_home_broker_identity.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/codex_master/fleet_home_broker_linux.py",
                    "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master/fleet_home_broker_linux.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/codex_master/fleet_home_broker_package.py",
                    "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master/fleet_home_broker_package.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/codex_master/fleet_home_broker_protocol.py",
                    "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master/fleet_home_broker_protocol.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/codex_master/fleet_home_broker_wal.py",
                    "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master/fleet_home_broker_wal.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "systemd/libexec/codex-master-agent-launcher",
                    "/usr/libexec/codex-master-agent-launcher",
                    0,
                    0,
                    0o555,
                ),
                InstallFile(
                    "systemd/libexec/codex-master-broker-verify",
                    "/usr/libexec/codex-master-broker-verify",
                    0,
                    0,
                    0o555,
                ),
                InstallFile(
                    "systemd/libexec/codex-master-home-broker",
                    "/usr/libexec/codex-master-home-broker",
                    0,
                    0,
                    0o555,
                ),
                InstallFile(
                    "systemd/libexec/codex_master_bootstrap.py",
                    "/usr/libexec/codex_master_bootstrap.py",
                    0,
                    0,
                    0o555,
                ),
                InstallFile(
                    "systemd/system/codex-master-agent@.service",
                    "/usr/lib/systemd/system/codex-master-agent@.service",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "systemd/system/codex-master-home-broker.service",
                    "/usr/lib/systemd/system/codex-master-home-broker.service",
                    0,
                    0,
                    0o644,
                ),
            ),
            key=lambda entry: entry.target_path,
        )
    )
    return InstallPlan(
        "0.10.5",
        (
            InstallDirectory("/etc/codex-master", 0, 0, 0o755),
            InstallDirectory("/usr/lib/codex-master-home-broker", 0, 0, 0o555),
            InstallDirectory("/usr/lib/codex-master-home-broker/0.10.5", 0, 0, 0o555),
            InstallDirectory(
                "/usr/lib/codex-master-home-broker/0.10.5/bin", 0, 0, 0o555
            ),
            InstallDirectory(
                "/usr/lib/codex-master-home-broker/0.10.5/python", 0, 0, 0o555
            ),
            InstallDirectory(
                "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master",
                0,
                0,
                0o555,
            ),
        ),
        files,
    )


__all__ = (
    "InstallDirectory",
    "InstallFile",
    "InstallPlan",
    "build_home_broker_install_plan",
)
