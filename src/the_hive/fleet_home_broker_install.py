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
                    "systemd/config/the-hive-home-broker.conf",
                    "/etc/the-hive/home-broker.conf",
                    0,
                    0,
                    0o400,
                ),
                InstallFile(
                    "systemd/manifest/the-hive-home-broker-manifest-v1.json",
                    "/usr/lib/the-hive-home-broker/manifest-v1.json",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "bin/the-hive-home-broker",
                    "/usr/lib/the-hive-home-broker/0.10.5/bin/the-hive-home-broker",
                    0,
                    0,
                    0o755,
                ),
                InstallFile(
                    "src/the_hive/__init__.py",
                    "/usr/lib/the-hive-home-broker/0.10.5/python/the_hive/__init__.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/the_hive/fleet_agent_launcher.py",
                    "/usr/lib/the-hive-home-broker/0.10.5/python/the_hive/fleet_agent_launcher.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/the_hive/fleet_home_broker.py",
                    "/usr/lib/the-hive-home-broker/0.10.5/python/the_hive/fleet_home_broker.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/the_hive/fleet_home_broker_client.py",
                    "/usr/lib/the-hive-home-broker/0.10.5/python/the_hive/fleet_home_broker_client.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/the_hive/fleet_home_broker_identity.py",
                    "/usr/lib/the-hive-home-broker/0.10.5/python/the_hive/fleet_home_broker_identity.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/the_hive/fleet_home_broker_linux.py",
                    "/usr/lib/the-hive-home-broker/0.10.5/python/the_hive/fleet_home_broker_linux.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/the_hive/fleet_home_broker_package.py",
                    "/usr/lib/the-hive-home-broker/0.10.5/python/the_hive/fleet_home_broker_package.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/the_hive/fleet_home_broker_protocol.py",
                    "/usr/lib/the-hive-home-broker/0.10.5/python/the_hive/fleet_home_broker_protocol.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "src/the_hive/fleet_home_broker_wal.py",
                    "/usr/lib/the-hive-home-broker/0.10.5/python/the_hive/fleet_home_broker_wal.py",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "systemd/libexec/the-hive-agent-launcher",
                    "/usr/libexec/the-hive-agent-launcher",
                    0,
                    0,
                    0o555,
                ),
                InstallFile(
                    "systemd/libexec/the-hive-broker-verify",
                    "/usr/libexec/the-hive-broker-verify",
                    0,
                    0,
                    0o555,
                ),
                InstallFile(
                    "systemd/libexec/the-hive-home-broker",
                    "/usr/libexec/the-hive-home-broker",
                    0,
                    0,
                    0o555,
                ),
                InstallFile(
                    "systemd/libexec/the_hive_bootstrap.py",
                    "/usr/libexec/the_hive_bootstrap.py",
                    0,
                    0,
                    0o555,
                ),
                InstallFile(
                    "systemd/system/the-hive-agent@.service",
                    "/usr/lib/systemd/system/the-hive-agent@.service",
                    0,
                    0,
                    0o644,
                ),
                InstallFile(
                    "systemd/system/the-hive-home-broker.service",
                    "/usr/lib/systemd/system/the-hive-home-broker.service",
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
            InstallDirectory("/etc/the-hive", 0, 0, 0o755),
            InstallDirectory("/usr/lib/the-hive-home-broker", 0, 0, 0o555),
            InstallDirectory("/usr/lib/the-hive-home-broker/0.10.5", 0, 0, 0o555),
            InstallDirectory(
                "/usr/lib/the-hive-home-broker/0.10.5/bin", 0, 0, 0o555
            ),
            InstallDirectory(
                "/usr/lib/the-hive-home-broker/0.10.5/python", 0, 0, 0o555
            ),
            InstallDirectory(
                "/usr/lib/the-hive-home-broker/0.10.5/python/the_hive",
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
