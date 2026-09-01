import ast
import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_master import remote_queen_preflight
from codex_master.remote_queen_bootstrap import (
    HostFactsV1,
    ManifestGenerationV1,
    RemoteQueenBootstrapError,
    SshTargetV1,
)
from codex_master.remote_queen_preflight import (
    ManagedStateFactV1,
    ManagedStateIdV1,
    ManagedStateKindV1,
    NetworkPathFactV1,
    NetworkPathIdV1,
    RemoteQueenHostFactsV1,
    RemoteQueenSshPreflightV1,
    collect_remote_queen_ssh_preflight,
    preflight_as_dict,
)
from codex_master.remote_queen_ssh import (
    ApprovedHostKeyV1,
    KnownHostKeyV1,
    PresentedHostKeyV1,
    SshOperationLimitsV1,
    SshOperationResultV1,
    SshReadOnlyOperationV1,
)


TARGET = SshTargetV1(user="queen", host="example.test")
FINGERPRINT = "SHA256:" + "A" * 43
OTHER_FINGERPRINT = "SHA256:" + "B" * 43
LIMITS = SshOperationLimitsV1(
    connect_timeout_seconds=7,
    operation_timeout_seconds=21,
    max_stdout_bytes=4096,
    max_stderr_bytes=1024,
)
DESIRED_GENERATION = ManifestGenerationV1(
    generation="rq-bootstrap-2026-08-29",
    sha256="a" * 64,
)


def test_json_constant_rejection_is_fail_closed() -> None:
    with pytest.raises(RemoteQueenBootstrapError) as caught:
        remote_queen_preflight._reject_json_constant("NaN")
    assert caught.value.code == "RQ_E_PLAN_INCONSISTENT"

HOST_FACTS_PAYLOAD = {
    "schema_version": "RemoteQueenHostFactsV1",
    "distribution_id": "fedora",
    "distribution_version": "41",
    "architecture": "x86_64",
    "package_manager": "dnf",
    "remote_user": "queen",
    "remote_home": "/home/queen",
    "uid": 1000,
    "gid": 1000,
    "shell": "/bin/bash",
    "python_version": "3.12.8",
    "git_version": "2.47.1",
    "curl_version": "8.11.1",
    "systemd_user_available": True,
    "dbus_session_available": True,
    "selinux_mode": "enforcing",
    "apparmor_mode": "unavailable",
    "syncthing_version": None,
    "codex_version": None,
    "free_bytes": 10737418240,
    "clock_synchronized": True,
    "noninteractive_sudo_available": False,
    "network_paths": [
        {"path_id": "dns", "reachable": True},
        {"path_id": "package-repositories", "reachable": True},
        {"path_id": "codex-download", "reachable": True},
        {"path_id": "canonical-masterjet", "reachable": False},
        {"path_id": "canonical-hive-bus", "reachable": False},
        {"path_id": "syncthing-discovery", "reachable": True},
    ],
    "managed_states": [
        {"object_id": "codex", "state": "absent", "generation": None},
        {"object_id": "mcp", "state": "absent", "generation": None},
        {"object_id": "queen", "state": "absent", "generation": None},
        {"object_id": "syncthing", "state": "absent", "generation": None},
    ],
}


def _json_bytes(payload):
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _result(**overrides):
    values = {
        "operation": SshReadOnlyOperationV1.HOST_FACTS,
        "returncode": 0,
        "stdout": _json_bytes(HOST_FACTS_PAYLOAD),
        "stderr": b"",
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "host_key_fingerprint": FINGERPRINT,
    }
    values.update(overrides)
    return SshOperationResultV1(**values)


class FakeSshOperations:
    def __init__(
        self,
        *,
        known_host_keys=(
            KnownHostKeyV1(
                host=TARGET.host,
                key_type="ssh-ed25519",
                sha256_fingerprint=FINGERPRINT,
            ),
        ),
        presented_host_key=PresentedHostKeyV1(
            host=TARGET.host,
            key_type="ssh-ed25519",
            sha256_fingerprint=FINGERPRINT,
        ),
        result=None,
        exception_method=None,
    ):
        self.known = known_host_keys
        self.presented = presented_host_key
        self.result = result if result is not None else _result()
        self.exception_method = exception_method
        self.calls = []

    def _raise_if_configured(self, method):
        if self.exception_method == method:
            raise RuntimeError("remote operation secret")

    def known_host_keys(self, target):
        self.calls.append(("known_host_keys", target))
        self._raise_if_configured("known_host_keys")
        return self.known

    def presented_host_key(self, target, limits):
        self.calls.append(("presented_host_key", target, limits))
        self._raise_if_configured("presented_host_key")
        return self.presented

    def run_read_only(
        self,
        target,
        operation,
        *,
        expected_host_key_sha256,
        limits,
    ):
        self.calls.append(
            (
                "run_read_only",
                target,
                operation,
                expected_host_key_sha256,
                limits,
            )
        )
        self._raise_if_configured("run_read_only")
        return self.result


def assert_domain_error(call, code):
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        call()
    assert exc_info.value.code == code
    assert str(exc_info.value) == code
    return exc_info.value


def collect(fake=None, *, limits=LIMITS):
    fake = fake if fake is not None else FakeSshOperations()
    return collect_remote_queen_ssh_preflight(
        ssh_target=TARGET,
        desired_generation=DESIRED_GENERATION,
        operations=fake,
        limits=limits,
    )


def test_success_collects_facts_with_exact_call_order_and_fixed_digest():
    fake = FakeSshOperations()

    preflight = collect(fake)

    assert fake.calls == [
        ("known_host_keys", TARGET),
        ("presented_host_key", TARGET, LIMITS),
        (
            "run_read_only",
            TARGET,
            SshReadOnlyOperationV1.HOST_FACTS,
            FINGERPRINT,
            LIMITS,
        ),
    ]
    assert isinstance(preflight, RemoteQueenSshPreflightV1)
    assert preflight.ssh_target == TARGET
    assert preflight.host_key == ApprovedHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )
    assert preflight.desired_generation == DESIRED_GENERATION
    assert preflight.host_facts == RemoteQueenHostFactsV1(
        schema_version="RemoteQueenHostFactsV1",
        host_facts=HostFactsV1(
            distribution_id="fedora",
            distribution_version="41",
            architecture="x86_64",
            package_manager="dnf",
        ),
        remote_user="queen",
        remote_home="/home/queen",
        uid=1000,
        gid=1000,
        shell="/bin/bash",
        python_version="3.12.8",
        git_version="2.47.1",
        curl_version="8.11.1",
        systemd_user_available=True,
        dbus_session_available=True,
        selinux_mode="enforcing",
        apparmor_mode="unavailable",
        syncthing_version=None,
        codex_version=None,
        free_bytes=10737418240,
        clock_synchronized=True,
        noninteractive_sudo_available=False,
        network_paths=tuple(
            NetworkPathFactV1(
                path_id=NetworkPathIdV1(path["path_id"]),
                reachable=path["reachable"],
            )
            for path in HOST_FACTS_PAYLOAD["network_paths"]
        ),
        managed_states=tuple(
            ManagedStateFactV1(
                object_id=ManagedStateIdV1(state["object_id"]),
                state=ManagedStateKindV1(state["state"]),
                generation=state["generation"],
            )
            for state in HOST_FACTS_PAYLOAD["managed_states"]
        ),
    )
    assert preflight.package_plan.manager == "dnf"
    assert preflight.package_plan.packages == (
        "ca-certificates",
        "curl",
        "gcc",
        "git",
        "glib2-devel",
        "pkgconf-pkg-config",
        "python3",
        "python3-dbus",
        "python3-devel",
        "python3-gobject",
        "syncthing",
        "systemd",
    )
    assert tuple(item.path_id for item in preflight.host_facts.network_paths) == tuple(
        NetworkPathIdV1
    )
    assert tuple(item.object_id for item in preflight.host_facts.managed_states) == tuple(
        ManagedStateIdV1
    )
    assert (
        preflight.preflight_digest
        == "sha256:72f51bfaa17a54c8a3672a536525317d540dc4de2b4a503ba2cb48c1cf4c3e52"
    )


def test_preflight_as_dict_is_flat_json_primitive_contract():
    payload = preflight_as_dict(collect())

    assert set(payload) == {
        "schema_version",
        "ssh_target",
        "host_key",
        "desired_generation",
        "host_facts",
        "package_plan",
        "preflight_digest",
    }
    assert payload["schema_version"] == "RemoteQueenSshPreflightV1"
    assert payload["ssh_target"] == {"user": "queen", "host": "example.test"}
    assert payload["host_key"] == {
        "key_type": "ssh-ed25519",
        "sha256_fingerprint": FINGERPRINT,
    }
    assert payload["desired_generation"] == {
        "generation": "rq-bootstrap-2026-08-29",
        "sha256": "a" * 64,
    }
    assert payload["host_facts"] == HOST_FACTS_PAYLOAD
    assert payload["package_plan"] == {
        "manager": "dnf",
        "packages": [
            "ca-certificates",
            "curl",
            "gcc",
            "git",
            "glib2-devel",
            "pkgconf-pkg-config",
            "python3",
            "python3-dbus",
            "python3-devel",
            "python3-gobject",
            "syncthing",
            "systemd",
        ],
    }

    def assert_primitives(value):
        assert isinstance(value, (str, int, bool, type(None), list, dict))
        if isinstance(value, dict):
            for item in value.values():
                assert_primitives(item)
        elif isinstance(value, list):
            for item in value:
                assert_primitives(item)

    assert_primitives(payload)
    assert "stdout" not in repr(payload)
    assert "stderr" not in repr(payload)
    assert "remote operation secret" not in repr(payload)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda preflight: replace(
            preflight,
            host_facts=replace(
                preflight.host_facts,
                free_bytes=preflight.host_facts.free_bytes + 1,
            ),
        ),
        lambda preflight: replace(
            preflight,
            preflight_digest="sha256:" + "0" * 64,
        ),
    ],
)
def test_preflight_as_dict_rejects_stale_or_false_digest(mutate):
    assert_domain_error(
        lambda: preflight_as_dict(mutate(collect())),
        "RQ_E_PLAN_INCONSISTENT",
    )


def test_preflight_as_dict_rejects_malformed_nested_contract():
    preflight = collect()
    malformed = replace(
        preflight,
        host_facts=replace(
            preflight.host_facts,
            network_paths=("remote-secret",),
        ),
    )

    error = assert_domain_error(
        lambda: preflight_as_dict(malformed),
        "RQ_E_PLAN_INCONSISTENT",
    )
    assert "remote-secret" not in str(error)


@pytest.mark.parametrize(
    "known_host_keys",
    [
        (),
        (
            KnownHostKeyV1(
                host=TARGET.host,
                key_type="ssh-ed25519",
                sha256_fingerprint=OTHER_FINGERPRINT,
            ),
        ),
        (
            KnownHostKeyV1(
                host=TARGET.host,
                key_type="ssh-ed25519",
                sha256_fingerprint=FINGERPRINT,
                revoked=True,
            ),
        ),
    ],
)
def test_hostkey_failures_happen_before_read_only_operation(known_host_keys):
    fake = FakeSshOperations(known_host_keys=known_host_keys)

    error = assert_domain_error(lambda: collect(fake), "RQ_E_SSH_HOSTKEY")

    assert [call[0] for call in fake.calls] == [
        "known_host_keys",
        "presented_host_key",
    ]
    assert "example.test" not in str(error)
    assert "SHA256:" not in str(error)


@pytest.mark.parametrize("method", ["known_host_keys", "presented_host_key", "run_read_only"])
def test_operation_exception_is_redacted_as_transport_blocker(method):
    fake = FakeSshOperations(exception_method=method)

    error = assert_domain_error(lambda: collect(fake), "RQ_E_SSH_PREFLIGHT")

    assert "remote operation secret" not in str(error)
    assert "example.test" not in str(error)


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (_result(timed_out=True), "RQ_E_SSH_PREFLIGHT"),
        (_result(stdout_truncated=True), "RQ_E_SSH_PREFLIGHT"),
        (_result(stderr_truncated=True), "RQ_E_SSH_PREFLIGHT"),
        (_result(stdout=b"x" * (4096 + 1)), "RQ_E_SSH_PREFLIGHT"),
        (_result(stderr=b"x" * (1024 + 1)), "RQ_E_SSH_PREFLIGHT"),
        (_result(returncode=1), "RQ_E_SSH_PREFLIGHT"),
        (_result(host_key_fingerprint=OTHER_FINGERPRINT), "RQ_E_SSH_HOSTKEY"),
    ],
)
def test_operation_result_failures_are_domain_errors_without_payload(result, code):
    fake = FakeSshOperations(result=result)

    error = assert_domain_error(lambda: collect(fake), code)

    assert "remote operation secret" not in str(error)
    assert "example.test" not in str(error)


@pytest.mark.parametrize(
    ("description", "stdout"),
    [
        ("invalid utf8", b"\xff"),
        ("invalid json", b"not-json"),
        ("non-dict", _json_bytes([])),
    ],
)
def test_payload_encoding_and_top_level_shape_are_strict(description, stdout):
    fake = FakeSshOperations(result=_result(stdout=stdout))

    error = assert_domain_error(lambda: collect(fake), "RQ_E_PLAN_INCONSISTENT")

    assert description
    assert "not-json" not in str(error)
    assert "example.test" not in str(error)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update(extra="forbidden"),
        lambda payload: payload.pop("shell"),
        lambda payload: payload.update(schema_version="WrongSchema"),
    ],
)
def test_payload_requires_exact_top_level_schema(mutate):
    payload = copy.deepcopy(HOST_FACTS_PAYLOAD)
    mutate(payload)

    error = assert_domain_error(
        lambda: collect(FakeSshOperations(result=_result(stdout=_json_bytes(payload)))),
        "RQ_E_PLAN_INCONSISTENT",
    )
    assert "forbidden" not in str(error)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("uid", True),
        ("gid", -1),
        ("free_bytes", 2**63),
        ("systemd_user_available", 1),
        ("python_version", 1),
        ("remote_home", "relative/home"),
        ("shell", "/bin/../bash"),
        ("remote_user", "queen\nsecret"),
        ("selinux_mode", "unknown"),
        ("apparmor_mode", "unknown"),
    ],
)
def test_payload_rejects_malformed_scalar_fields(field, value):
    payload = copy.deepcopy(HOST_FACTS_PAYLOAD)
    payload[field] = value

    error = assert_domain_error(
        lambda: collect(FakeSshOperations(result=_result(stdout=_json_bytes(payload)))),
        "RQ_E_PLAN_INCONSISTENT",
    )
    assert "secret" not in str(error)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("remote_home", "/home/queen\u0085suffix"),
        ("shell", "/bin/bash\u202e"),
    ],
)
def test_host_fact_paths_reject_unicode_control_characters(field, value):
    payload = copy.deepcopy(HOST_FACTS_PAYLOAD)
    payload[field] = value

    assert_domain_error(
        lambda: collect(
            FakeSshOperations(result=_result(stdout=_json_bytes(payload)))
        ),
        "RQ_E_PLAN_INCONSISTENT",
    )


def test_payload_rejects_user_mismatch():
    payload = copy.deepcopy(HOST_FACTS_PAYLOAD)
    payload["remote_user"] = "other"

    assert_domain_error(
        lambda: collect(FakeSshOperations(result=_result(stdout=_json_bytes(payload)))),
        "RQ_E_PLAN_INCONSISTENT",
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda paths: paths[1].update(path_id="dns"),
        lambda paths: paths.pop(),
        lambda paths: paths[0].update(path_id="unknown-path"),
        lambda paths: paths[0].update(reachable=1),
        lambda paths: paths[0].update(extra=True),
    ],
)
def test_payload_network_paths_require_unique_known_ids_and_strict_entries(mutate):
    payload = copy.deepcopy(HOST_FACTS_PAYLOAD)
    mutate(payload["network_paths"])

    assert_domain_error(
        lambda: collect(FakeSshOperations(result=_result(stdout=_json_bytes(payload)))),
        "RQ_E_PLAN_INCONSISTENT",
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda states: states[1].update(object_id="codex"),
        lambda states: states.pop(),
        lambda states: states[0].update(object_id="unknown-object"),
        lambda states: states[0].update(state="unknown-state"),
        lambda states: states[0].update(extra=True),
    ],
)
def test_payload_managed_states_require_unique_known_ids_and_strict_entries(mutate):
    payload = copy.deepcopy(HOST_FACTS_PAYLOAD)
    mutate(payload["managed_states"])

    assert_domain_error(
        lambda: collect(FakeSshOperations(result=_result(stdout=_json_bytes(payload)))),
        "RQ_E_PLAN_INCONSISTENT",
    )


def test_unknown_distribution_manager_is_well_formed_but_unsupported():
    payload = copy.deepcopy(HOST_FACTS_PAYLOAD)
    payload["distribution_id"] = "arch"
    payload["package_manager"] = "pacman"

    assert_domain_error(
        lambda: collect(FakeSshOperations(result=_result(stdout=_json_bytes(payload)))),
        "RQ_E_HOST_UNSUPPORTED",
    )


@pytest.mark.parametrize("object_id", ["codex", "mcp", "queen", "syncthing"])
def test_every_foreign_managed_state_blocks_without_leaking_generation(object_id):
    payload = copy.deepcopy(HOST_FACTS_PAYLOAD)
    state = next(item for item in payload["managed_states"] if item["object_id"] == object_id)
    state.update(state="foreign", generation="foreign-generation-secret")

    error = assert_domain_error(
        lambda: collect(FakeSshOperations(result=_result(stdout=_json_bytes(payload)))),
        "RQ_E_FOREIGN_STATE",
    )
    assert "foreign-generation-secret" not in str(error)
    assert object_id not in str(error)


def test_owned_state_requires_nonempty_generation():
    payload = copy.deepcopy(HOST_FACTS_PAYLOAD)
    payload["managed_states"][0].update(state="owned", generation="")

    assert_domain_error(
        lambda: collect(FakeSshOperations(result=_result(stdout=_json_bytes(payload)))),
        "RQ_E_PLAN_INCONSISTENT",
    )


def test_absent_state_requires_null_generation():
    payload = copy.deepcopy(HOST_FACTS_PAYLOAD)
    payload["managed_states"][0]["generation"] = "generation-secret"

    error = assert_domain_error(
        lambda: collect(FakeSshOperations(result=_result(stdout=_json_bytes(payload)))),
        "RQ_E_PLAN_INCONSISTENT",
    )
    assert "generation-secret" not in str(error)


def test_network_and_state_input_order_is_canonicalized_before_digest():
    reordered = copy.deepcopy(HOST_FACTS_PAYLOAD)
    reordered["network_paths"].reverse()
    reordered["managed_states"].reverse()

    expected = preflight_as_dict(collect())
    actual = preflight_as_dict(
        collect(
            FakeSshOperations(
                result=_result(stdout=_json_bytes(reordered)),
            )
        )
    )

    assert actual == expected


def _dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _is_forbidden_import(module: str, forbidden_imports: set[str]) -> bool:
    return any(
        module == forbidden or module.startswith(forbidden + ".")
        for forbidden in forbidden_imports
    )


def _assert_no_runtime_effects_source(source: str) -> None:
    forbidden_imports = {
        "subprocess",
        "socket",
        "asyncio.subprocess",
        "requests",
        "urllib",
        "paramiko",
        "asyncssh",
        "os",
    }
    forbidden_calls = {
        "os.system",
        "systemctl",
        "dnf",
        "apt",
        "firewall",
        "git",
        "codex",
        "mcp",
        "syncthing",
        "dbus",
        "open",
        "write_text",
        "write_bytes",
        "unlink",
        "rename",
        "replace",
    }

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not _is_forbidden_import(alias.name, forbidden_imports)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imported_names = (module,) + tuple(
                f"{module}.{alias.name}" if module else alias.name
                for alias in node.names
            )
            for imported_name in imported_names:
                assert not _is_forbidden_import(
                    imported_name,
                    forbidden_imports,
                )
        elif isinstance(node, ast.Call):
            dotted = _dotted_name(node.func)
            assert dotted not in forbidden_calls
            assert dotted and dotted.rsplit(".", 1)[-1] not in {
                "systemctl",
                "dnf",
                "apt",
                "firewall",
                "git",
                "codex",
                "mcp",
                "syncthing",
                "dbus",
                "open",
                "write_text",
                "write_bytes",
                "unlink",
                "rename",
                "replace",
            }


def test_no_runtime_effects():
    production_paths = [
        Path(__file__).parents[1] / "src/codex_master/remote_queen_ssh.py",
        Path(__file__).parents[1] / "src/codex_master/remote_queen_preflight.py",
    ]

    for path in production_paths:
        _assert_no_runtime_effects_source(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "source",
    [
        "import urllib.request\nurllib.request.urlopen('https://example.test')",
        "import socket.socket\nsocket.socket.socket()",
        "from os.path import exists\nexists('/tmp/example')",
        (
            "from asyncio import subprocess\n"
            "subprocess.create_subprocess_exec('/bin/false')"
        ),
    ],
)
def test_runtime_effect_gate_rejects_forbidden_import_submodules(source):
    with pytest.raises(AssertionError):
        _assert_no_runtime_effects_source(source)
