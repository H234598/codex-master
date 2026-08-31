from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from codex_master.host_probe import HostProbeError, LocalHostProbeCollector


class Kernel:
    def __init__(self, *, cpu_count: object = 8, memory_bytes: object = 16 * 1024**3) -> None:
        self.cpu_count = cpu_count
        self.memory_bytes = memory_bytes

    def uname(self) -> tuple[str, str]:
        return ("Linux", "x86_64")

    def cgroup_v2(self) -> bool:
        return True

    def systemd(self) -> bool:
        return True

    def load(self) -> float:
        return 0.5

    def pressure(self) -> float:
        return 0.0

    def ollama_available(self) -> bool:
        return False


def test_local_probe_collects_only_bounded_normalized_evidence() -> None:
    evidence = LocalHostProbeCollector(lambda: datetime(2026, 8, 30, tzinfo=UTC)).collect(Kernel())

    assert set(evidence.public()) == {
        "kernel_class", "architecture_class", "cpu_count", "memory_class",
        "cgroup_v2", "systemd", "load_class", "pressure_class",
        "ollama_capability", "observed_at", "agent_generation", "evidence_digest",
    }
    assert "/" not in json.dumps(evidence.public())
    assert evidence.public()["cpu_count"] == 8
    assert evidence.public()["memory_class"] == "8-31-gib"


@pytest.mark.parametrize("field", ("cpu_count", "memory_bytes"))
def test_local_probe_rejects_boolean_resource_values(field: str) -> None:
    values = {field: True}

    with pytest.raises(HostProbeError, match="host.probe_failed"):
        LocalHostProbeCollector().collect(Kernel(**values))


def test_local_probe_maps_collector_failure_to_stable_code() -> None:
    class Broken(Kernel):
        def uname(self) -> tuple[str, str]:
            raise OSError

    with pytest.raises(HostProbeError, match="host.probe_failed"):
        LocalHostProbeCollector().collect(Broken())
