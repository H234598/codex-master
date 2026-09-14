from pathlib import Path
import re

import the_hive.fleet_home_broker_runtime as runtime


REPO_ROOT = Path(__file__).parents[1]
SOCKET_UNIT = REPO_ROOT / "systemd/system/the-hive-home-broker.socket"
SERVICE_UNIT = REPO_ROOT / "systemd/system/the-hive-home-broker.service"
FILECONTEXTS = REPO_ROOT / "systemd/selinux/the_hive_home_broker.fc"
POLICY = REPO_ROOT / "systemd/selinux/the_hive_home_broker.te"


def _release() -> runtime.BrokerReleaseSpec:
    return runtime.BrokerReleaseSpec(
        joint_release_version=1,
        release_id="0.11.0",
        server_digest="1" * 64,
        broker_manifest_digest="2" * 64,
        chpb_abi="CHPB/2",
        policy_abi="policy-v1",
        provider_abi="provider-v1",
        unit_digest="3" * 64,
        selinux_digest="4" * 64,
        socket_unit="the-hive-home-broker.socket",
        service_unit="the-hive-home-broker.service",
        system_bus_name="org.the_hive.HomeBrokerControl",
        system_bus_path="/org/the_hive/HomeBrokerControl",
        system_bus_interface="org.the_hive.HomeBrokerControl1",
        broker_domain="the_hive_home_broker_t",
        gateway_domain="the_hive_control_t",
        socket_type="the_hive_home_broker_runtime_t",
        agent_domain="the_hive_agent_t",
    )


def _unit(path: Path) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    section: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            sections.setdefault(section, {})
            continue
        key, separator, value = line.partition("=")
        assert section is not None and separator
        sections[section].setdefault(key, []).append(value)
    return sections


def test_broker_release_spec_binds_socket_policy_and_exec_artifacts() -> None:
    release = _release()
    assert runtime._validate_release_spec(release) is release

    socket = _unit(SOCKET_UNIT)
    service = _unit(SERVICE_UNIT)
    assert SOCKET_UNIT.name == release.socket_unit
    assert SERVICE_UNIT.name == release.service_unit
    assert socket["Socket"]["Service"] == [release.service_unit]
    assert socket["Socket"]["ListenSequentialPacket"] == [
        "/run/the-hive-home-broker.sock"
    ]
    assert socket["Socket"]["SocketMode"] == ["0600"]
    assert socket["Socket"]["RemoveOnStop"] == ["yes"]

    socket_path = re.escape(
        socket["Socket"]["ListenSequentialPacket"][0].replace(".", r"\.")
    )
    filecontexts = FILECONTEXTS.read_text(encoding="utf-8")
    assert re.search(
        rf"^{socket_path} -s gen_context\(system_u:object_r:{release.socket_type},s0\)$",
        filecontexts,
        re.MULTILINE,
    )
    policy = POLICY.read_text(encoding="utf-8")
    assert re.search(rf"^type {release.gateway_domain};$", policy, re.MULTILINE)
    assert re.search(rf"^type {release.socket_type};$", policy, re.MULTILINE)
    assert re.search(
        rf"^allow {release.gateway_domain} {release.socket_type}:sock_file write;$",
        policy,
        re.MULTILINE,
    )

    entrypoint = service["Service"]["ExecStart"]
    assert entrypoint == ["/usr/libexec/the-hive-home-broker"]
    broker_exec_type = release.broker_domain.removesuffix("_t") + "_exec_t"
    assert re.search(
        rf"^{re.escape(entrypoint[0])} -- gen_context\(system_u:object_r:"
        rf"{broker_exec_type},s0\)$",
        filecontexts,
        re.MULTILINE,
    )
    assert (REPO_ROOT / "systemd/libexec/the-hive-home-broker").read_text(
        encoding="utf-8"
    ).startswith("#!/usr/bin/python3\n")
