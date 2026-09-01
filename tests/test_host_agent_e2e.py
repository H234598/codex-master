"""Offline E2E evidence for the outbound host-agent trust boundary."""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
import hashlib
import http.client
import ipaddress
import json
import multiprocessing
import os
from pathlib import Path
import signal
import ssl
import threading
from typing import Iterator

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from codex_master import agent_daemon, host_agent as host_agent_module
from codex_master.admin_hosts import AgentBindingV1, AgentPrincipalV1, HostRegistry
from codex_master.admin_auth import MasterjetBearerVerifier, TotpStepUpVerifier
from codex_master.admin_http import AdminHttpServer
from codex_master.admin_operations import AdminOperationStore
from codex_master.agent_contracts import AgentReceiptV1
from codex_master.agent_daemon import AgentApiServer
from codex_master.agent_http import AgentHttpApplication
from codex_master.agent_identity import AgentIdentityResolver
from codex_master.agent_operations import AgentOperationRequestV1, AgentOperationStore
from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    remote_envelope_digest,
)
from codex_master.agent_ollama import ProductionAgentOllamaAdapter
from codex_master.fleet_service import FleetPaths, FleetService
from codex_master.host_agent import (
    HostAgent,
    HostAgentClient,
    HostAgentExecutor,
    HostProbeExecutor,
)
from codex_master.host_agent_state import HostAgentState
from codex_master.host_probe import (
    LocalHostProbeCollector,
    RemoteHostProbeAdapter,
    RemoteHostProbeCompletionOwner,
)
from codex_master.ollama_host_transport import (
    AgentQueueRemoteOllamaOperationPort,
    HostRegistryOllamaLeaseSource,
    OllamaHostTransport,
)
from codex_master.ollama_registry import (
    OllamaInstanceV1,
    OllamaModelV1,
    OllamaRegistryStore,
)
from codex_master.server import build_fleet_private_io


_CAPABILITIES_DIGEST = "sha256:" + "c" * 64


def _pem_private_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _certificate(
    name: str,
    *,
    key: rsa.RSAPrivateKey,
    issuer: x509.Certificate | None,
    issuer_key: rsa.RSAPrivateKey,
    client: bool,
    expired: bool = False,
) -> x509.Certificate:
    now = datetime.now(UTC)
    not_before = now - timedelta(hours=2) if expired else now - timedelta(minutes=1)
    not_after = now - timedelta(hours=1) if expired else now + timedelta(days=1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(issuer.subject if issuer is not None else x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name)
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=issuer is None, path_length=0 if issuer is None else None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=issuer is not None,
                content_commitment=False,
                key_encipherment=issuer is not None,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=issuer is None,
                crl_sign=issuer is None,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
    )
    if issuer is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=True,
        )
    if not client:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
            ]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _spki_digest(certificate: x509.Certificate) -> str:
    public_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(public_key).hexdigest()


@dataclass(frozen=True, slots=True)
class _Pki:
    root: Path
    worker_one_spki: str

    def context(self, client: str | None) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(self.root / "ca.crt"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if client is not None:
            context.load_cert_chain(
                self.root / f"{client}.crt", self.root / f"{client}.key"
            )
        return context


def _create_pki(tmp_path: Path) -> _Pki:
    root = tmp_path / "pki"
    root.mkdir(mode=0o700)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = _certificate("agent-test-ca", key=ca_key, issuer=None, issuer_key=ca_key, client=False)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    worker_one_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    worker_two_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    worker_one = _certificate(
        "worker-one", key=worker_one_key, issuer=ca, issuer_key=ca_key, client=True
    )
    files = {
        "ca.crt": ca.public_bytes(serialization.Encoding.PEM),
        "ca.key": _pem_private_key(ca_key),
        "server.crt": _certificate(
            "agent-api", key=server_key, issuer=ca, issuer_key=ca_key, client=False
        ).public_bytes(serialization.Encoding.PEM),
        "server.key": _pem_private_key(server_key),
        "worker-one.crt": worker_one.public_bytes(serialization.Encoding.PEM),
        "worker-one.key": _pem_private_key(worker_one_key),
        "worker-two.crt": _certificate(
            "worker-two", key=worker_two_key, issuer=ca, issuer_key=ca_key, client=True
        ).public_bytes(serialization.Encoding.PEM),
        "worker-two.key": _pem_private_key(worker_two_key),
        "expired.crt": _certificate(
            "expired-worker", key=expired_key, issuer=ca, issuer_key=ca_key,
            client=True, expired=True,
        ).public_bytes(serialization.Encoding.PEM),
        "expired.key": _pem_private_key(expired_key),
    }
    for name, contents in files.items():
        path = root / name
        path.write_bytes(contents)
        path.chmod(0o400 if name.endswith(".key") else 0o444)
    return _Pki(root, _spki_digest(worker_one))


@dataclass(frozen=True, slots=True)
class _Response:
    status: int | None
    tls_failed: bool = False


class _NoopCompletionOwner:
    def complete(self, principal: object, receipt: object) -> object:
        del principal, receipt
        raise AssertionError("no receipt is expected in the identity E2E")

    def reconcile_attempt_exhaustion(self, value: object) -> bool:
        del value
        return False

    def reconcile_operation_deadline(self, value: object) -> bool:
        del value
        return False

    def acknowledge_agent_lifecycle(self, value: object) -> None:
        del value


class _UnreachableAdminService:
    def handle(self, *args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        raise AssertionError("agent credentials must not reach the admin owner")

    def put_secret(self, *args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        raise AssertionError("agent credentials must not reach the admin owner")

    def reserve_secret_upload(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("agent credentials must not reach the admin owner")

    def rollback_secret_upload(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("agent credentials must not reach the admin owner")

    def continue_secret_upload(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("agent credentials must not reach the admin owner")


@dataclass(slots=True)
class _E2E:
    root: Path
    pki: _Pki
    registry: HostRegistry
    operations: AgentOperationStore
    server: AgentApiServer
    thread: threading.Thread

    def agent_poll(self, *, client: str | None) -> _Response:
        return self.agent_request(
            client=client,
            target="/agent/v1/polls",
            body=json.dumps({
                "schema_version": 1,
                "registry_generation": self.registry.document_generation(),
                "lease_epoch": 3,
                "capabilities_digest": _CAPABILITIES_DIGEST,
                "max_wait_seconds": 0,
            }).encode(),
        )

    def agent_request(self, *, client: str | None, target: str, body: bytes) -> _Response:
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.server.server_address[1],
            context=self.pki.context(client), timeout=2,
        )
        try:
            connection.request(
                "POST", target, body=body,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            response.read()
            return _Response(response.status)
        except (ConnectionError, OSError, ssl.SSLError, http.client.HTTPException):
            return _Response(None, tls_failed=True)
        finally:
            connection.close()

    def agent_client(self) -> HostAgentClient:
        return HostAgentClient(
            f"https://127.0.0.1:{self.server.server_address[1]}",
            context=self.pki.context("worker-one"),
            sleep=lambda _seconds: None,
        )

    def install_completion_owner(self, owner: object) -> None:
        self.server.application = AgentHttpApplication(self.operations, owner)

    def admin_request(self, *, client: str) -> _Response:
        """An accepted agent certificate conveys no bearer/admin authority."""
        if client not in {"worker-one", "worker-two", "expired"}:
            raise ValueError("test client is unknown")
        bearer_path = self.root / "admin-bearer"
        totp_path = self.root / "admin-totp"
        bearer_path.write_bytes(b"admin-bearer")
        totp_path.write_bytes(base64.b32encode(b"T" * 20))
        bearer_path.chmod(0o600)
        totp_path.chmod(0o600)
        bearer_fd = os.open(bearer_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        totp_fd = os.open(totp_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            bearer = MasterjetBearerVerifier.from_fd(
                bearer_fd, subject="admin", scopes=("fleet.read",)
            )
            totp = TotpStepUpVerifier.from_fd(
                totp_fd,
                replay_state_path=self.root / "admin-totp-state",
            )
        finally:
            os.close(bearer_fd)
            os.close(totp_fd)
        server = AdminHttpServer(
            ("127.0.0.1", 0),
            _UnreachableAdminService(),
            authority_mode="bearer",
            bearer_verifier=bearer,
            access_verifier=None,
            step_up_verifier=totp,
            origin_host="admin.test",
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(self.pki.root / "ca.crt"))
        context.load_cert_chain(
            self.pki.root / "server.crt", self.pki.root / "server.key"
        )
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPSConnection(
                *server.server_address,
                context=self.pki.context(client),
                timeout=2,
            )
            connection.request(
                "POST", "/admin/v1", body=b"{}", headers={
                    "Host": "admin.test",
                    "X-Forwarded-Host": "admin.test",
                    "X-Forwarded-Proto": "https",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            response.read()
            return _Response(response.status)
        finally:
            connection.close()
            server.shutdown()
            server.drain(2)
            server.server_close()
            thread.join(2)
            assert not thread.is_alive()
            bearer.close()
            totp.close()


@pytest.fixture
def e2e(tmp_path: Path) -> Iterator[_E2E]:
    pki = _create_pki(tmp_path)
    registry = HostRegistry.for_test(tmp_path / "master")
    registry.provision_agent_binding(
        {
            "ref": "worker-one",
            "label": "Worker One",
            "role": "execution",
            "capabilities": ["resource.probe", "ollama.execute"],
        },
        AgentBindingV1("worker-one", pki.worker_one_spki, 3, True),
        expected_generation=0,
    )
    operations = AgentOperationStore.for_test(tmp_path / "master")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(pki.root / "ca.crt"))
    context.load_cert_chain(pki.root / "server.crt", pki.root / "server.key")
    server = AgentApiServer(
        ("127.0.0.1", 0),
        AgentHttpApplication(operations, _NoopCompletionOwner()),
        AgentIdentityResolver(registry),
        context,
    )
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    value = _E2E(tmp_path, pki, registry, operations, server, thread)
    try:
        yield value
    finally:
        server.shutdown()
        assert server.drain(2)
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


def test_agent_and_admin_credentials_are_not_interchangeable(e2e: _E2E) -> None:
    """A changed SPKI binding or missing mTLS certificate must deny agent polling."""
    assert e2e.agent_poll(client="worker-one").status == 200
    assert e2e.agent_poll(client="worker-two").status == 403
    assert e2e.agent_poll(client="expired").tls_failed
    assert e2e.agent_poll(client=None).tls_failed
    assert e2e.admin_request(client="worker-one").status in {401, 403}


class _Kernel:
    cpu_count = 8
    memory_bytes = 16 * 1024**3

    def uname(self) -> tuple[str, str]:
        return "Linux", "x86_64"

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


class _CapturingClient:
    def __init__(self, client: HostAgentClient) -> None:
        self._client = client
        self.polls: list[object] = []
        self.receipts: list[AgentReceiptV1] = []

    def poll(self, poll: object) -> object:
        self.polls.append(poll)
        return self._client.poll(poll)  # type: ignore[arg-type]

    def put_receipt(self, receipt: AgentReceiptV1) -> None:
        self.receipts.append(receipt)
        self._client.put_receipt(receipt)


def _host_evidence() -> dict[str, object]:
    return {
        "label": "Worker One",
        "role": "execution",
        "transport_binding": {"kind": "ssh", "binding_ref": "worker-one-ssh"},
        "capabilities": ["resource.probe", "ollama.execute"],
        "reachability": {"state": "reachable", "latency_ms": 1},
        "resource_evidence": {"cpu_threads": 4, "memory_bytes": 8 * 1024**3},
        "observed_at": "2026-09-01T12:00:00Z",
        "source": "host-agent",
        "binding_state": {"ref": "worker-one"},
    }


def test_remote_host_probe_updates_once_and_rejects_stale_or_cross_host_receipts(
    e2e: _E2E,
) -> None:
    """A missing receipt-owner fence would let old or foreign evidence overwrite a host."""
    e2e.registry.record_probe("worker-one", generation=4, evidence=_host_evidence())
    admin_operations = AdminOperationStore.for_test(e2e.root / "admin")
    remote = RemoteHostProbeAdapter(
        operation_store=admin_operations,
        agent_operations=e2e.operations,
        host_registry=e2e.registry,
    )
    planned = remote.probe(
        "worker-one", expected_generation=4, idempotency_key="probe-e2e-one"
    )
    owner = RemoteHostProbeCompletionOwner(
        operation_store=admin_operations,
        agent_operations=e2e.operations,
        host_registry=e2e.registry,
    )
    e2e.install_completion_owner(owner)
    client = _CapturingClient(e2e.agent_client())
    agent = HostAgent(
        client=client,
        executor=HostAgentExecutor(
            state=HostAgentState.for_test(e2e.root / "agent-state", host_ref="worker-one"),
            ollama=object(),
            host_probe=HostProbeExecutor(
                collector=LocalHostProbeCollector(
                    lambda: datetime(2026, 9, 1, 12, 1, tzinfo=UTC)
                ),
                kernel=_Kernel(),
            ),
        ),
        registry_generation=e2e.registry.document_generation(),
        lease_epoch=3,
        capabilities_digest=_CAPABILITIES_DIGEST,
    )

    assert agent.run_once() == 0
    assert admin_operations.get(planned.id).state == "succeeded"
    refreshed = e2e.registry.get("worker-one")
    assert refreshed.generation == 5
    assert refreshed.resource_evidence == {
        "cpu_threads": 8,
        "memory_bytes": 8 * 1024**3,
    }
    assert len(client.receipts) == 1
    delivered = client.receipts[0]
    document = e2e.root / "master" / "admin-hosts" / "hosts.json"
    before = document.read_bytes()

    replay = e2e.server.application.handle(
        AgentPrincipalV1("worker-one", e2e.registry.document_generation(), 3),
        "POST",
        f"/agent/v1/operations/{delivered.operation_id}/receipts",
        _receipt_wire(delivered),
    )
    assert replay.status == 409
    assert document.read_bytes() == before
    foreign = e2e.server.application.handle(
        AgentPrincipalV1("worker-two", e2e.registry.document_generation(), 3),
        "POST",
        f"/agent/v1/operations/{delivered.operation_id}/receipts",
        _receipt_wire(delivered),
    )
    assert foreign.status == 409
    assert document.read_bytes() == before


def _receipt_wire(receipt: AgentReceiptV1) -> bytes:
    from codex_master.agent_contracts import serialize_agent_result

    return json.dumps(
        {
            "schema_version": 2 if receipt.result.kind == "ollama.instance" else 1,
            "operation_id": receipt.operation_id,
            "lease_id": receipt.lease_id,
            "lease_epoch": receipt.lease_epoch,
            "attempt": receipt.attempt,
            "plan_digest": receipt.plan_digest,
            "arguments_digest": receipt.arguments_digest,
            "state": receipt.state,
            "reason_codes": list(receipt.reason_codes),
            "result_digest": receipt.result_digest,
            "result": serialize_agent_result(receipt.result),
            **(
                {"envelope_digest": receipt.envelope_digest}
                if receipt.result.kind == "ollama.instance"
                else {}
            ),
        },
        separators=(",", ":"),
    ).encode()


class _FakeProcess:
    pid = 4242

    def poll(self) -> None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0


class _OllamaRuntime:
    """Offline runtime boundary; every asserted transition still uses production code."""

    def __init__(self) -> None:
        self.actions: list[str] = []
        self.process_up = True
        self.started = False
        self.cgroup_member = True

    def available_cpus(self) -> tuple[int, ...]:
        if not self.actions:
            self.actions.append("plan")
        return (0,)

    def allocate_loopback_port(self) -> int:
        return 11435

    def start_scope(self, request: object) -> _FakeProcess:
        del request
        self.actions.append("apply")
        self.started = True
        return _FakeProcess()

    def resolve_scope(self, request: object, process: object) -> tuple[int, str, int]:
        del request, process
        return 4242, "/user.slice/ollama.scope", 901

    def process_running(self, process: object, pid: int, start_ticks: int) -> bool:
        del process, pid, start_ticks
        return self.process_up

    def scope_process_matches(
        self, unit_name: str, pid: int, control_group: str, start_ticks: int
    ) -> bool:
        del unit_name, pid, control_group, start_ticks
        return self.cgroup_member

    def listener_owned_by(self, pid: int, port: int) -> bool:
        del pid, port
        return True

    def classify_running_identity(
        self,
        unit_name: str,
        pid: int,
        control_group: str,
        start_ticks: int,
        port: int,
        executable: object,
    ) -> str:
        del unit_name, pid, control_group, start_ticks, port, executable
        return "exact" if self.process_up else "absent"

    def recover_start_intent(
        self, unit_name: str, port: int, executable: object
    ) -> tuple[str, int | None, str | None, int | None]:
        del unit_name, port, executable
        if not self.started or not self.process_up:
            return "absent", None, None, None
        return "exact", 4242, "/user.slice/ollama.scope", 901

    def fetch_tags(
        self,
        pid: int,
        port: int,
        *,
        unit_name: str,
        control_group: str,
        start_ticks: int,
        timeout_seconds: float,
        max_bytes: int,
    ) -> set[str]:
        del pid, port, unit_name, control_group, start_ticks, timeout_seconds, max_bytes
        self.actions.append("probe")
        return {"provider-model"}

    def cleanup_scope(self, request: object, process: object) -> bool:
        del request, process
        return True

    def stop_scope(self, request: object) -> None:
        del request
        self.actions.append("stop")
        self.process_up = False


def _remote_instance(tmp_path: Path, *, host_ref: str) -> OllamaInstanceV1:
    executable = tmp_path / "ollama"
    if not executable.exists():
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o700)
    models = tmp_path / "models"
    if not models.exists():
        models.mkdir(mode=0o700)
    return OllamaInstanceV1(
        "remote-one",
        "Remote One",
        host_ref,
        str(executable),
        str(models),
        ("model-one",),
        "0",
        100,
        100,
        "planned",
        "unknown",
    )


def _fleet(
    e2e: _E2E, registry: OllamaRegistryStore
) -> FleetService:
    paths = FleetPaths.from_state_root(e2e.root / "fleet-owner")
    return FleetService(
        paths,
        build_fleet_private_io(paths),
        pool_root=e2e.root / "fleet-pool",
        ollama_registry=registry,
        ollama_transport=OllamaHostTransport(
            registry=registry,
            leases=HostRegistryOllamaLeaseSource(e2e.registry),
            remote=AgentQueueRemoteOllamaOperationPort(
                agent_operations=e2e.operations, host_registry=e2e.registry
            ),
        ),
        agent_operations=e2e.operations,
    )


def _install_remote_owner(e2e: _E2E, fleet: FleetService) -> None:
    e2e.install_completion_owner(
        agent_daemon._AgentCompletionRouter(
            e2e.operations, _NoopCompletionOwner(), fleet
        )
    )


def _poll(client: HostAgentClient, e2e: _E2E) -> AgentLeaseV1:
    lease = client.poll(
        AgentPollV1(
            e2e.registry.document_generation(), 3, _CAPABILITIES_DIGEST, 0
        )
    )
    assert type(lease) is AgentLeaseV1
    return lease


def test_remote_ollama_survives_master_restart_and_only_opens_ready_lanes(
    e2e: _E2E,
) -> None:
    """A lost remote owner or early lane publication would expose an unfenced runtime."""
    instance = _remote_instance(e2e.root, host_ref="worker-one")
    registry = OllamaRegistryStore.for_test(e2e.root / "master-ollama-registry")
    registry.replace(
        models=(OllamaModelV1("model-one", "provider-model", True, True, True, None),),
        instances=(instance,),
        expected_generation=0,
    )
    agent_registry = OllamaRegistryStore.for_test(e2e.root / "agent-ollama-registry")
    agent_registry.replace(
        models=(OllamaModelV1("model-one", "provider-model", True, True, True, None),),
        instances=(_remote_instance(e2e.root, host_ref="local"),),
        expected_generation=0,
    )
    runtime = _OllamaRuntime()
    state_root = e2e.root / "host-agent-state"
    executor = HostAgentExecutor(
        state=HostAgentState.for_test(state_root, host_ref="worker-one"),
        ollama=ProductionAgentOllamaAdapter(
            agent_registry, state_root=state_root, runtime=runtime
        ),
    )
    client = e2e.agent_client()
    fleet = _fleet(e2e, registry)
    _install_remote_owner(e2e, fleet)

    planned = fleet.plan_ollama_instance(instance, expected_generation=1)
    lanes_after_plan = fleet.ollama_hive_lanes()
    assert lanes_after_plan == ()
    plan_lease = _poll(client, e2e)
    plan_receipt = executor.execute(plan_lease)
    assert plan_receipt.state == "succeeded", plan_receipt.reason_codes
    drifted = replace(plan_receipt, plan_digest="sha256:" + "d" * 64)
    assert e2e.agent_request(
        client="worker-one",
        target=f"/agent/v1/operations/{planned.id}/receipts",
        body=_receipt_wire(drifted),
    ).status in {400, 409}
    assert e2e.agent_request(
        client="worker-two",
        target=f"/agent/v1/operations/{planned.id}/receipts",
        body=_receipt_wire(plan_receipt),
    ).status == 403
    assert e2e.operations.get(planned.id).state == "leased"

    # A fresh owner reconstructs the persisted remote plan before it receives
    # the first receipt; redelivery is then semantic rather than a new effect.
    fleet = _fleet(e2e, registry)
    _install_remote_owner(e2e, fleet)
    client.put_receipt(plan_receipt)
    client.put_receipt(plan_receipt)
    assert e2e.operations.get(planned.id).state == "succeeded"

    applied = fleet.apply_ollama_instance(planned.id, expected_generation=1)
    assert applied is not None
    client.put_receipt(executor.execute(_poll(client, e2e)))
    lanes_after_apply = fleet.ollama_hive_lanes()
    assert lanes_after_apply == ()

    probed = fleet.probe_ollama_instance("remote-one", expected_generation=2)
    assert probed is not None
    client.put_receipt(executor.execute(_poll(client, e2e)))
    lanes_after_ready_probe = fleet.ollama_hive_lanes()
    assert len(lanes_after_ready_probe) == 1

    # A lost cgroup identity must fence the endpoint before it reaches Ollama.
    runtime.cgroup_member = False
    fenced_probe = fleet.probe_ollama_instance(
        "remote-one", expected_generation=registry.load().generation
    )
    assert fenced_probe is not None
    fenced_receipt = executor.execute(_poll(client, e2e))
    assert fenced_receipt.state == "succeeded"
    assert fenced_receipt.result.payload["cgroup_member"] is False
    client.put_receipt(fenced_receipt)
    assert runtime.actions == ["plan", "apply", "probe"]

    runtime.cgroup_member = True
    stopped = fleet.stop_ollama_instance(
        "remote-one", expected_generation=registry.load().generation
    )
    assert stopped is not None
    client.put_receipt(executor.execute(_poll(client, e2e)))
    lanes_after_stop = fleet.ollama_hive_lanes()
    assert lanes_after_stop == ()
    assert runtime.actions == ["plan", "apply", "probe", "stop"]

    # Keep the agent's private registry in the same snapshot for a real mTLS
    # plan attempt whose executable was replaced by a symlink after planning.
    local_instance = _remote_instance(e2e.root, host_ref="local")
    while agent_registry.load().generation < registry.load().generation:
        current = agent_registry.load()
        agent_registry.replace(
            models=current.models,
            instances=(local_instance,),
            expected_generation=current.generation,
        )
    assert agent_registry.load().generation == registry.load().generation
    executable = e2e.root / "ollama"
    original = e2e.root / "ollama-original"
    executable.rename(original)
    executable.symlink_to(original)
    symlinked = fleet.plan_ollama_instance(
        instance, expected_generation=registry.load().generation
    )
    assert symlinked is not None
    symlink_receipt = executor.execute(_poll(client, e2e))
    assert symlink_receipt.state == "failed"
    assert runtime.actions == ["plan", "apply", "probe", "stop"]


class _BlockingProbeCollector:
    def __init__(self, entered: object = None, release: object = None) -> None:
        self.entered = threading.Event() if entered is None else entered
        self.release = threading.Event() if release is None else release

    def collect(self, kernel: object) -> object:
        assert self.entered.set() is None
        assert self.release.wait(2)
        return LocalHostProbeCollector(
            lambda: datetime(2026, 9, 1, 12, 2, tzinfo=UTC)
        ).collect(kernel)  # type: ignore[arg-type]


class _NoCredentials:
    def __enter__(self) -> object:
        return self

    def __exit__(self, *args: object) -> None:
        del args


class _HostAgentMainConfig:
    max_wait_seconds = 0


def _run_host_agent_until_sigterm(
    master_url: str,
    pki_root: Path,
    registry_generation: int,
    state_root: Path,
    entered: object,
    release: object,
) -> None:
    agent = HostAgent(
        client=HostAgentClient(
            master_url,
            context=_Pki(pki_root, "").context("worker-one"),
            sleep=lambda _seconds: None,
        ),
        executor=HostAgentExecutor(
            state=HostAgentState.for_test(state_root, host_ref="worker-one"),
            ollama=object(),
            host_probe=HostProbeExecutor(
                collector=_BlockingProbeCollector(entered, release),
                kernel=_Kernel(),
            ),
        ),
        registry_generation=registry_generation,
        lease_epoch=3,
        capabilities_digest=_CAPABILITIES_DIGEST,
    )
    original_open = host_agent_module.open_host_agent_credentials
    original_assemble = host_agent_module.assemble_host_agent
    host_agent_module.open_host_agent_credentials = lambda _environment: _NoCredentials()
    host_agent_module.assemble_host_agent = lambda _credentials: (
        agent,
        _HostAgentMainConfig(),
    )
    try:
        raise SystemExit(host_agent_module.main([]))
    finally:
        host_agent_module.open_host_agent_credentials = original_open
        host_agent_module.assemble_host_agent = original_assemble


def _run_agent_api_until_sigterm(
    state_root: Path,
    pki_root: Path,
    ready: object,
) -> None:
    registry = HostRegistry.for_test(state_root)
    operations = AgentOperationStore.for_test(state_root)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(pki_root / "ca.crt"))
    context.load_cert_chain(pki_root / "server.crt", pki_root / "server.key")
    server = AgentApiServer(
        ("127.0.0.1", 0),
        AgentHttpApplication(operations),
        AgentIdentityResolver(registry),
        context,
    )
    ready.send(server.server_address[1])  # type: ignore[attr-defined]
    ready.close()  # type: ignore[attr-defined]
    agent_daemon.run_server(server)


def test_real_sigterm_stops_agent_api_listener(e2e: _E2E) -> None:
    """The installed SIGTERM handler must close the real TLS listener."""
    state_root = e2e.root / "signal-agent-api"
    registry = HostRegistry.for_test(state_root)
    registry.provision_agent_binding(
        {
            "ref": "worker-one",
            "label": "Worker One",
            "role": "execution",
            "capabilities": ["resource.probe", "ollama.execute"],
        },
        AgentBindingV1("worker-one", e2e.pki.worker_one_spki, 3, True),
        expected_generation=0,
    )
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_run_agent_api_until_sigterm,
        args=(state_root, e2e.pki.root, sender),
    )
    process.start()
    sender.close()
    assert receiver.poll(5)
    port = receiver.recv()
    receiver.close()
    client = HostAgentClient(
        f"https://127.0.0.1:{port}",
        context=e2e.pki.context("worker-one"),
        sleep=lambda _seconds: None,
    )
    assert type(client.poll(AgentPollV1(1, 3, _CAPABILITIES_DIGEST, 0))) is AgentNoWorkV1

    os.kill(process.pid, signal.SIGTERM)
    process.join(7)
    assert process.exitcode == 0
    connection = http.client.HTTPSConnection(
        "127.0.0.1",
        port,
        context=e2e.pki.context("worker-one"),
        timeout=1,
    )
    try:
        with pytest.raises(
            (ConnectionError, OSError, ssl.SSLError, http.client.HTTPException)
        ):
            connection.request("POST", "/agent/v1/polls", body=b"{}")
    finally:
        connection.close()


def test_real_sigterm_finishes_current_host_agent_receipt_without_repoll(
    e2e: _E2E,
) -> None:
    """The packaged agent must finish one leased receipt and then stop polling."""
    e2e.server.application = AgentHttpApplication(e2e.operations)
    deadline = (datetime.now(UTC) + timedelta(minutes=5)).replace(microsecond=0)
    first = e2e.operations.enqueue(
        AgentOperationRequestV1(
            "drain-e2e-first",
            "host.probe",
            "collect",
            e2e.registry.document_generation(),
            "sha256:" + "a" * 64,
            {"admin_operation_id": "drain-e2e-first", "probe_schema": 1},
            deadline,
            target_host_ref="worker-one",
        )
    )
    second = e2e.operations.enqueue(
        AgentOperationRequestV1(
            "drain-e2e-second",
            "host.probe",
            "collect",
            e2e.registry.document_generation(),
            "sha256:" + "b" * 64,
            {"admin_operation_id": "drain-e2e-second", "probe_schema": 1},
            deadline,
            target_host_ref="worker-one",
        )
    )
    state_root = e2e.root / "drain-agent-state"
    context = multiprocessing.get_context("spawn")
    entered = context.Event()
    release = context.Event()
    process = context.Process(
        target=_run_host_agent_until_sigterm,
        args=(
            f"https://127.0.0.1:{e2e.server.server_address[1]}",
            e2e.pki.root,
            e2e.registry.document_generation(),
            state_root,
            entered,
            release,
        ),
    )
    process.start()
    assert entered.wait(5)
    os.kill(process.pid, signal.SIGTERM)
    release.set()
    process.join(7)

    assert process.exitcode == 0
    assert e2e.operations.get(first.operation_id).state == "succeeded"
    queued = e2e.operations.get(second.operation_id)
    assert (queued.state, queued.attempt) == ("queued", 0)
    assert HostAgentState.for_test(state_root, host_ref="worker-one").receipt_count() == 1
    assert all(
        ".tmp" not in path.name
        for path in (state_root / "host-agent").iterdir()
    )


def _poll_then_crash(
    master_url: str,
    pki_root: Path,
    registry_generation: int,
) -> None:
    client = HostAgentClient(
        master_url,
        context=_Pki(pki_root, "").context("worker-one"),
        sleep=lambda _seconds: None,
    )
    lease = client.poll(
        AgentPollV1(registry_generation, 3, _CAPABILITIES_DIGEST, 0)
    )
    if type(lease) is not AgentLeaseV1:
        os._exit(2)
    os._exit(23)


def test_agent_crash_before_effect_redelivers_over_the_real_mtls_queue(
    e2e: _E2E,
) -> None:
    """A process death after polling but before acceptance must redeliver once."""
    now = datetime.now(UTC).replace(microsecond=0)
    clock = [now]
    operations = AgentOperationStore.for_test(
        e2e.root / "crash-before-effect", clock=lambda: clock[0]
    )
    e2e.server.application = AgentHttpApplication(operations)
    enqueued = operations.enqueue(
        AgentOperationRequestV1(
            "crash-before-effect",
            "host.probe",
            "collect",
            e2e.registry.document_generation(),
            "sha256:" + "b" * 64,
            {"admin_operation_id": "crash-before-effect", "probe_schema": 1},
            now + timedelta(minutes=5),
            target_host_ref="worker-one",
        )
    )
    process = multiprocessing.get_context("spawn").Process(
        target=_poll_then_crash,
        args=(
            f"https://127.0.0.1:{e2e.server.server_address[1]}",
            e2e.pki.root,
            e2e.registry.document_generation(),
        ),
    )
    process.start()
    process.join(5)
    assert process.exitcode == 23
    leased = operations.get(enqueued.operation_id)
    assert (leased.state, leased.attempt) == ("leased", 1)

    clock[0] += timedelta(minutes=2)
    client = e2e.agent_client()
    redelivered = client.poll(
        AgentPollV1(e2e.registry.document_generation(), 3, _CAPABILITIES_DIGEST, 0)
    )
    assert type(redelivered) is AgentLeaseV1
    assert (redelivered.operation_id, redelivered.attempt) == (
        enqueued.operation_id,
        2,
    )

    receipt = HostAgentExecutor(
        state=HostAgentState.for_test(e2e.root / "redelivery-state", host_ref="worker-one"),
        ollama=object(),
        host_probe=HostProbeExecutor(
            collector=LocalHostProbeCollector(
                lambda: datetime(2026, 9, 1, 12, 3, tzinfo=UTC)
            ),
            kernel=_Kernel(),
        ),
    ).execute(redelivered)
    client.put_receipt(receipt)
    assert operations.get(redelivered.operation_id).state == "succeeded"


class _NoEffectRuntime:
    def apply(self, arguments: object, **fences: object) -> dict[str, object]:
        del arguments, fences
        raise AssertionError("a recovered unknown receipt must never re-run apply")

    def validate_plan_precondition(
        self, plan_ref: object, plan_digest: object, resource_generation: object
    ) -> None:
        del plan_ref, plan_digest, resource_generation
        raise AssertionError("a recovered unknown receipt must never validate a new effect")


def _crash_after_begin_effect(state_root: Path, lease: AgentLeaseV1) -> None:
    state = HostAgentState.for_test(state_root, host_ref="worker-one")
    assert state.accept(lease) is None
    assert state.begin_effect(lease) is not None


def test_agent_crash_after_begin_effect_recovers_unknown_without_runtime_call(
    tmp_path: Path,
) -> None:
    """A process death after the durable mutation boundary is intentionally unknown."""
    arguments = {"plan_ref": "plan-one"}
    arguments_digest = "sha256:" + hashlib.sha256(
        json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    plan_digest = "sha256:" + "a" * 64
    lease = AgentLeaseV1(
        operation_id="crash-after-effect",
        lease_id="lease-after-effect",
        host_ref="worker-one",
        kind="ollama.instance",
        action="apply",
        registry_generation=1,
        lease_epoch=3,
        attempt=1,
        plan_digest=plan_digest,
        arguments_digest=arguments_digest,
        deadline=datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5),
        arguments=arguments,
        plan_precondition_digest=plan_digest,
        resource_generation=1,
        envelope_digest=remote_envelope_digest(
            registry_generation=1,
            lease_epoch=3,
            resource_generation=1,
            plan_precondition_digest=plan_digest,
        ),
    )
    state_root = tmp_path / "crash-after-effect"
    process = multiprocessing.get_context("fork").Process(
        target=_crash_after_begin_effect, args=(state_root, lease)
    )
    process.start()
    process.join(2)
    assert process.exitcode == 0

    receipt = HostAgentExecutor(
        state=HostAgentState.for_test(state_root, host_ref="worker-one"),
        ollama=_NoEffectRuntime(),
    ).execute(lease)
    assert receipt.state == "unknown"
    assert receipt.reason_codes == ("host.operation_unknown",)
