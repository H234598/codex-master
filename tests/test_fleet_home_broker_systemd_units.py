from pathlib import Path


REPO_ROOT = Path(__file__).parents[1]
BROKER_UNIT = REPO_ROOT / "systemd/system/codex-master-home-broker.service"
AGENT_UNIT = REPO_ROOT / "systemd/system/codex-master-agent@.service"


def _parse_unit(path: Path) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    section = None
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            sections.setdefault(section, {})
            continue
        key, separator, value = line.partition("=")
        assert section is not None, f"directive outside section at line {line_number}"
        assert separator, f"invalid directive at line {line_number}"
        sections[section].setdefault(key, []).append(value)
    return sections


def test_broker_unit_has_static_root_verifier_contract():
    unit = _parse_unit(BROKER_UNIT)

    assert set(unit) == {"Unit", "Service"}
    assert set(unit["Unit"]) == {"Description"}
    service = unit["Service"]
    assert set(service) == {
        "Type",
        "User",
        "Group",
        "WorkingDirectory",
        "Environment",
        "StateDirectory",
        "StateDirectoryMode",
        "ExecStart",
        "NoNewPrivileges",
        "ProtectSystem",
        "ProtectHome",
        "PrivateTmp",
        "PrivateDevices",
        "RestrictAddressFamilies",
        "CapabilityBoundingSet",
        "AmbientCapabilities",
        "SystemCallFilter",
    }
    assert service["Type"] == ["exec"]
    assert service["User"] == ["root"]
    assert service["Group"] == ["root"]
    assert service["WorkingDirectory"] == ["/var/empty"]
    assert service["Environment"] == ["PATH=/usr/sbin:/usr/bin"]
    assert service["StateDirectory"] == ["codex-master-home-broker"]
    assert service["StateDirectoryMode"] == ["0700"]
    assert service["ExecStart"] == ["/usr/libexec/codex-master-broker-verify"]
    assert service["NoNewPrivileges"] == ["yes"]
    assert service["ProtectSystem"] == ["strict"]
    assert service["ProtectHome"] == ["yes"]
    assert service["PrivateTmp"] == ["yes"]
    assert service["PrivateDevices"] == ["yes"]
    assert service["RestrictAddressFamilies"] == ["AF_UNIX"]
    assert service["CapabilityBoundingSet"] == [""]
    assert service["AmbientCapabilities"] == [""]
    assert service["SystemCallFilter"] == ["~@mount @module @keyring bpf"]
    assert "@bpf" not in service["SystemCallFilter"][0]

    forbidden = {
        "ReadWritePaths",
        "DynamicUser",
        "BindPaths",
        "SELinuxContext",
        "RuntimeDirectory",
        "WantedBy",
        "IPAddressAllow",
        "IPAddressDeny",
        "DeviceAllow",
        "RestrictNamespaces",
    }
    assert not forbidden.intersection(service)
    assert "Install" not in unit
    assert not forbidden.intersection(
        {key for section in unit.values() for key in section}
    )
    broker_unit_text = "\n".join(
        f"{key}={value}"
        for section in unit.values()
        for key, values in section.items()
        for value in values
    ).lower()
    assert not any(
        token in broker_unit_text
        for token in ("@bpf", "bindpaths", "uid", "mcs", "policy", "slot", "fallback")
    )


def test_agent_template_has_dynamic_user_launcher_contract_without_activation_edge():
    unit = _parse_unit(AGENT_UNIT)

    assert set(unit) == {"Unit", "Service"}
    assert set(unit["Unit"]) == {"Description"}
    service = unit["Service"]
    assert set(service) == {
        "Type",
        "DynamicUser",
        "PrivateUsers",
        "PrivateMounts",
        "ExecStart",
        "NoNewPrivileges",
        "ProtectSystem",
        "ProtectHome",
        "PrivateTmp",
        "PrivateDevices",
        "RestrictAddressFamilies",
        "CapabilityBoundingSet",
        "AmbientCapabilities",
        "SystemCallFilter",
    }
    assert service["Type"] == ["exec"]
    assert service["DynamicUser"] == ["yes"]
    assert service["PrivateUsers"] == ["yes"]
    assert service["PrivateMounts"] == ["yes"]
    assert "User" not in service
    assert "Group" not in service
    assert service["ExecStart"] == ["/usr/libexec/codex-master-agent-launcher"]
    assert service["NoNewPrivileges"] == ["yes"]
    assert service["ProtectSystem"] == ["strict"]
    assert service["ProtectHome"] == ["yes"]
    assert service["PrivateTmp"] == ["yes"]
    assert service["PrivateDevices"] == ["yes"]
    assert service["RestrictAddressFamilies"] == ["AF_UNIX"]
    assert service["CapabilityBoundingSet"] == [""]
    assert service["AmbientCapabilities"] == [""]
    assert service["SystemCallFilter"] == ["~@mount @module @keyring bpf"]
    assert "@bpf" not in service["SystemCallFilter"][0]

    forbidden = {
        "StateDirectory",
        "RuntimeDirectory",
        "ReadWritePaths",
        "SELinuxContext",
        "BindPaths",
        "WantedBy",
        "Requires",
        "Wants",
        "Requisite",
        "BindsTo",
        "PartOf",
        "After",
        "Before",
        "Sockets",
        "IPAddressAllow",
        "IPAddressDeny",
        "DeviceAllow",
        "RestrictNamespaces",
    }
    assert not forbidden.intersection(service)
    assert "Install" not in unit
    assert not forbidden.intersection(
        {key for section in unit.values() for key in section}
    )
    unit_text = "\n".join(
        f"{key}={value}"
        for section in unit.values()
        for key, values in section.items()
        for value in values
    ).lower()
    assert not any(
        token in unit_text for token in ("slot", "mcs", "uid", "policy", "fallback")
    )
