import re
from pathlib import Path


RUNBOOK = Path(__file__).parents[1] / "docs/operations/codex-master-home-broker.md"


def _read_runbook() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def test_runbook_separates_scope_evidence_audits_and_release_handoff() -> None:
    text = _read_runbook()

    assert all(
        heading in text
        for heading in (
            "## Scope and hard boundary",
            "## Artifact inventory",
            "## Offline evidence checklist",
            "## Systemd unit audit",
            "## SELinux static audit",
            "## Release gate and handoff",
        )
    )
    assert all(
        artifact in text
        for artifact in (
            "src/codex_master/fleet_home_broker_package.py",
            "systemd/system/codex-master-home-broker.service",
            "systemd/system/codex-master-agent@.service",
            "systemd/selinux/codex_master_home_broker.te",
            "systemd/selinux/codex_master_home_broker.fc",
        )
    )


def test_runbook_records_offline_contract_and_separate_fedora_gate() -> None:
    text = _read_runbook()
    contract = (
        "The root-owned manifest/verifier is a release-artifact boundary; "
        "the verifier checks declared entries for uid/gid zero."
    )

    assert all(
        requirement in text
        for requirement in (
            "Packageclosure: exact closure",
            "canonical bytes",
            "SHA-256",
            "mode",
            "uid=0",
            "gid=0",
            "regular file",
            "link count=1",
            "Python import closure",
            "StateDirectory=codex-master-home-broker",
            "StateDirectoryMode=0700",
            "ProtectSystem=strict",
            "kein ReadWritePaths/[Install]",
            "DynamicUser=yes",
            "PrivateUsers=yes",
            "PrivateMounts=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "SystemCallFilter=~@mount @module @keyring bpf",
            "statische Source/Filecontexts-Audit",
            "s0 ohne Kategorie",
            "minimale Broker-/Agent-Typen",
            "unconnected",
            "kein Socket/SCM/Netzpfad",
            "Broker-write nur StateDirectory",
            "Agent ohne State/RuntimeDirectory",
            "No installation, policy load, unit activation, or runtime invocation occurs in this runbook.",
            "Fedora Enforcing semantic validation is a separately authorized release gate.",
            "No static UID, GID, SELinux user, MCS category, or policy fallback is permitted.",
        )
    )
    assert contract in text
    assert "Root-owned Manifest/Verifier" not in text
    assert "root-owned manifest/verifier" in text
    assert "```" not in text
    assert "~~~" not in text
    assert not any(re.match(r"^ {4}", line) for line in text.splitlines())
    forbidden_line_start = re.compile(
        r"^\s*(?:[-*+]\s*)?(?:\$\s*)?"
        r"(?:systemctl|dnf|rpm|semodule|checkmodule|restorecon|setenforce|"
        r"sudo|curl|wget)(?:\s|$)"
    )
    assert not any(forbidden_line_start.match(line) for line in text.splitlines())
