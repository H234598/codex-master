"""Private, inert D355 S5a authority state and Q1 ownership core."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256

from . import _d73_q1_record
from ._d73_ingress_policy import D73IngressPolicyV1
from .runtime_layout import _RuntimeLayoutAttestation


D73_AUTHORITY_BUS_NAME = "org.the_hive.D73Authority1"
D73_AUTHORITY_OBJECT_PATH = "/org/the_hive/D73Authority1"
D73_AUTHORITY_INTERFACE = "org.the_hive.D73Authority1"
D73_AUTHORITY_MEMBER = "PublishAndMaterialize"
D73_AUTHORITY_INPUT_SIGNATURE = ""
D73_AUTHORITY_OUTPUT_SIGNATURE = ""
D73_AUTHORITY_REJECTED_ERROR_NAME = "org.the_hive.D73Authority1.Error.Rejected"
D73_AUTHORITY_REJECTED_ERROR_TEXT = "request rejected"

D73_PEER_PID = 1 << 0
D73_PEER_UID = 1 << 1
D73_PEER_SELINUX_CONTEXT = 1 << 2
D73_PEER_UNIQUE_NAME = 1 << 3
D73_PEER_AUGMENT = 1 << 4
D73_REQUIRED_PEER_MASK = (
    D73_PEER_PID | D73_PEER_UID | D73_PEER_SELINUX_CONTEXT | D73_PEER_UNIQUE_NAME
)

_D73_PEER_KNOWN_MASK = D73_REQUIRED_PEER_MASK | D73_PEER_AUGMENT
_UINT32_MAX = (1 << 32) - 1
_AUTHORIZATION_TOKEN = object()


class D73AuthorityRejected(ValueError):
    """The sole, stable S5a rejection outcome."""

    __slots__ = ()

    error_name = D73_AUTHORITY_REJECTED_ERROR_NAME

    def __init__(self) -> None:
        super().__init__(D73_AUTHORITY_REJECTED_ERROR_TEXT)


def _reject() -> None:
    raise D73AuthorityRejected() from None


def _text(value: object, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        _reject()
    return value


def _u32(value: object, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value <= _UINT32_MAX:
        _reject()
    return value


def _selinux_bytes(value: object) -> bytes:
    if (
        type(value) is not bytes
        or not 1 <= len(value) <= 4096
        or any(not 0x21 <= byte <= 0x7E for byte in value)
    ):
        _reject()
    return value


def _peer_mask(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _D73_PEER_KNOWN_MASK:
        _reject()
    return value


@dataclass(frozen=True, slots=True)
class D73AuthorityAbiV1:
    """The fixed, not-yet-exported D73 authority D-Bus ABI."""

    bus_name: str
    object_path: str
    interface: str
    member: str
    input_signature: str
    output_signature: str
    rejected_error_name: str
    rejected_error_text: str

    def __post_init__(self) -> None:
        if (
            type(self.bus_name) is not str
            or type(self.object_path) is not str
            or type(self.interface) is not str
            or type(self.member) is not str
            or type(self.input_signature) is not str
            or type(self.output_signature) is not str
            or type(self.rejected_error_name) is not str
            or type(self.rejected_error_text) is not str
            or self.bus_name != D73_AUTHORITY_BUS_NAME
            or self.object_path != D73_AUTHORITY_OBJECT_PATH
            or self.interface != D73_AUTHORITY_INTERFACE
            or self.member != D73_AUTHORITY_MEMBER
            or self.input_signature != D73_AUTHORITY_INPUT_SIGNATURE
            or self.output_signature != D73_AUTHORITY_OUTPUT_SIGNATURE
            or self.rejected_error_name != D73_AUTHORITY_REJECTED_ERROR_NAME
            or self.rejected_error_text != D73_AUTHORITY_REJECTED_ERROR_TEXT
        ):
            _reject()


D73_AUTHORITY_ABI_V1 = D73AuthorityAbiV1(
    bus_name=D73_AUTHORITY_BUS_NAME,
    object_path=D73_AUTHORITY_OBJECT_PATH,
    interface=D73_AUTHORITY_INTERFACE,
    member=D73_AUTHORITY_MEMBER,
    input_signature=D73_AUTHORITY_INPUT_SIGNATURE,
    output_signature=D73_AUTHORITY_OUTPUT_SIGNATURE,
    rejected_error_name=D73_AUTHORITY_REJECTED_ERROR_NAME,
    rejected_error_text=D73_AUTHORITY_REJECTED_ERROR_TEXT,
)


@dataclass(frozen=True, slots=True)
class D73DirectPeerV1:
    """Adapter/test input only; it does not assert transport provenance."""

    unique_sender: str
    pid: int
    uid: int
    selinux_context: bytes
    available_mask: int
    requested_mask: int
    augmented_mask: int
    has_direct_pidfd: bool

    def __post_init__(self) -> None:
        _text(self.unique_sender, 255)
        _u32(self.pid, minimum=1)
        _u32(self.uid, minimum=0)
        _selinux_bytes(self.selinux_context)
        _peer_mask(self.available_mask)
        _peer_mask(self.requested_mask)
        _peer_mask(self.augmented_mask)
        if type(self.has_direct_pidfd) is not bool or not _required_mask_status(self):
            _reject()


@dataclass(frozen=True, slots=True)
class D73PolicyBusOwnerV1:
    """Adapter/test observation of one fresh owner of one named policy bus."""

    bus_name: str
    unique_sender: str

    def __post_init__(self) -> None:
        _text(self.bus_name, 255)
        _text(self.unique_sender, 255)


@dataclass(frozen=True, slots=True, init=False)
class _D73AuthorizationV1:
    """A future positive, noninteractive Polkit result fixed by policy only."""

    polkit_action: str
    noninteractive: bool

    def __init__(
        self,
        polkit_action: object,
        noninteractive: object,
        *,
        _token: object | None = None,
    ) -> None:
        if _token is not _AUTHORIZATION_TOKEN:
            _reject()
        object.__setattr__(self, "polkit_action", _text(polkit_action, 255))
        if type(noninteractive) is not bool or noninteractive is not True:
            _reject()
        object.__setattr__(self, "noninteractive", noninteractive)


class D73IngressTransactionStateV1(str, Enum):
    """The complete non-resumable S5a lifecycle."""

    NEW = "NEW"
    A_VERIFIED = "A_VERIFIED"
    AUTHORIZED = "AUTHORIZED"
    CAPABILITY_MOVED = "CAPABILITY_MOVED"
    DECODED_BOUND = "DECODED_BOUND"
    B_VERIFIED = "B_VERIFIED"
    C_VERIFIED = "C_VERIFIED"
    CLOSED = "CLOSED"
    ABORTED = "ABORTED"


def _required_mask_status(peer: object) -> bool:
    """Return whether exactly the non-augmented mandatory credential set exists."""

    if type(peer) is not D73DirectPeerV1:
        return False
    try:
        return (
            type(peer.available_mask) is int
            and type(peer.requested_mask) is int
            and type(peer.augmented_mask) is int
            and peer.available_mask == D73_REQUIRED_PEER_MASK
            and peer.requested_mask == D73_REQUIRED_PEER_MASK
            and peer.augmented_mask == 0
        )
    except AttributeError:
        return False


def _policy_values(policy: object) -> tuple[int, str, str, str]:
    if type(policy) is not D73IngressPolicyV1:
        _reject()
    try:
        expected_uid = _u32(policy.expected_uid, minimum=1)
        bus_name = _text(policy.bus_name, 255)
        selinux_context = _text(policy.selinux_context, 4096)
        polkit_action = _text(policy.polkit_action, 255)
    except AttributeError:
        _reject()
    return expected_uid, bus_name, selinux_context, polkit_action


def _attestation_values(
    attestation: object,
) -> tuple[bytes, str, str, str]:
    if type(attestation) is not _RuntimeLayoutAttestation:
        _reject()
    try:
        manifest_bytes = attestation.manifest_bytes
        manifest_digest = attestation.manifest_digest
        commit = attestation.commit
        generation = attestation.generation
    except AttributeError:
        _reject()
    if (
        type(manifest_bytes) is not bytes
        or type(manifest_digest) is not str
        or type(commit) is not str
        or type(generation) is not str
    ):
        _reject()
    return manifest_bytes, manifest_digest, commit, generation


def _verify_peer_continuity_v1(
    reference: object,
    observed: object,
    owner: object,
    policy: object,
) -> None:
    """Purely bind a new adapter observation to the original peer and policy name."""

    _policy_values(policy)
    if (
        type(reference) is not D73DirectPeerV1
        or type(observed) is not D73DirectPeerV1
        or type(owner) is not D73PolicyBusOwnerV1
    ):
        _reject()
    try:
        if (
            not _required_mask_status(reference)
            or not _required_mask_status(observed)
            or owner.bus_name != policy.bus_name
            or owner.unique_sender != observed.unique_sender
            or reference.unique_sender != observed.unique_sender
            or reference.pid != observed.pid
            or reference.uid != observed.uid
            or reference.selinux_context != observed.selinux_context
        ):
            _reject()
    except AttributeError:
        _reject()


class D73IngressTransactionV1:
    """One callback-free, non-resumable ownership path for one Q1 capability."""

    __slots__ = (
        "_active",
        "_attestation",
        "_authorization",
        "_capability",
        "_decoded_record",
        "_peer",
        "_policy",
        "_state",
    )

    def __init__(self, policy: object, attestation: object) -> None:
        _policy_values(policy)
        _attestation_values(attestation)
        self._active = False
        self._attestation = attestation
        self._authorization: _D73AuthorizationV1 | None = None
        self._capability: _d73_q1_record.D73Q1Capability | None = None
        self._decoded_record: _d73_q1_record._DecodedRecord | None = None
        self._peer: D73DirectPeerV1 | None = None
        self._policy = policy
        self._state = D73IngressTransactionStateV1.NEW

    def __copy__(self) -> None:
        self._abort()
        _reject()

    def __deepcopy__(self, memo: object) -> None:
        del memo
        self._abort()
        _reject()

    def __reduce_ex__(self, protocol: int) -> None:
        del protocol
        self._abort()
        _reject()

    @property
    def authorization(self) -> _D73AuthorizationV1 | None:
        return self._authorization

    @property
    def state(self) -> D73IngressTransactionStateV1:
        return self._state

    def _abort(self) -> None:
        capability = self._capability
        self._capability = None
        self._decoded_record = None
        self._peer = None
        self._state = D73IngressTransactionStateV1.ABORTED
        if capability is not None:
            try:
                _d73_q1_record._discard_capability(capability)
            except Exception:
                pass

    def _begin(self, expected: D73IngressTransactionStateV1) -> None:
        if self._active or self._state is not expected:
            self._abort()
            _reject()
        self._active = True

    def _failure(self) -> None:
        self._abort()
        _reject()

    def verify_a(self, peer: object, owner: object) -> None:
        self._begin(D73IngressTransactionStateV1.NEW)
        try:
            _verify_peer_continuity_v1(peer, peer, owner, self._policy)
            if peer.selinux_context != _policy_values(self._policy)[2].encode("ascii"):
                self._failure()
            if peer.uid != _policy_values(self._policy)[0]:
                self._failure()
            if self._state is not D73IngressTransactionStateV1.NEW:
                self._failure()
            self._peer = peer
            self._state = D73IngressTransactionStateV1.A_VERIFIED
        except Exception:
            self._failure()
        finally:
            self._active = False

    def authorize(self) -> None:
        self._begin(D73IngressTransactionStateV1.A_VERIFIED)
        try:
            _expected_uid, _bus_name, _selinux_context, polkit_action = _policy_values(
                self._policy
            )
            self._authorization = _D73AuthorizationV1(
                polkit_action=polkit_action,
                noninteractive=True,
                _token=_AUTHORIZATION_TOKEN,
            )
            if self._state is not D73IngressTransactionStateV1.A_VERIFIED:
                self._failure()
            self._state = D73IngressTransactionStateV1.AUTHORIZED
        except Exception:
            self._failure()
        finally:
            self._active = False

    def move_capability(self, capability: object) -> None:
        self._begin(D73IngressTransactionStateV1.AUTHORIZED)
        try:
            if type(capability) is not _d73_q1_record.D73Q1Capability:
                self._failure()
            self._capability = capability
            if self._state is not D73IngressTransactionStateV1.AUTHORIZED:
                self._failure()
            self._state = D73IngressTransactionStateV1.CAPABILITY_MOVED
        except Exception:
            self._failure()
        finally:
            self._active = False

    def decode(self) -> None:
        self._begin(D73IngressTransactionStateV1.CAPABILITY_MOVED)
        try:
            capability = self._capability
            if type(capability) is not _d73_q1_record.D73Q1Capability:
                self._failure()
            self._capability = None
            decoded = _d73_q1_record._decode_capability(capability)
            if self._state is not D73IngressTransactionStateV1.CAPABILITY_MOVED:
                self._failure()
            self._bind_decoded_record(decoded)
            if self._state is not D73IngressTransactionStateV1.CAPABILITY_MOVED:
                self._failure()
            self._decoded_record = decoded
            self._state = D73IngressTransactionStateV1.DECODED_BOUND
        except Exception:
            self._failure()
        finally:
            self._active = False

    def _bind_decoded_record(self, decoded: object) -> None:
        if type(decoded) is not _d73_q1_record._DecodedRecord:
            _reject()
        expected_uid, bus_name, selinux_context, polkit_action = _policy_values(
            self._policy
        )
        manifest_bytes, manifest_digest, commit, generation = _attestation_values(
            self._attestation
        )
        try:
            if (
                decoded.expected_uid != expected_uid
                or decoded.bus_name != bus_name.encode("ascii")
                or decoded.selinux_context != selinux_context.encode("ascii")
                or decoded.polkit_action != polkit_action.encode("ascii")
                or decoded.manifest != manifest_bytes
                or sha256(decoded.manifest).hexdigest() != manifest_digest
                or decoded.commit != commit.encode("ascii")
                or decoded.generation != generation.encode("ascii")
            ):
                _reject()
        except (AttributeError, UnicodeEncodeError):
            _reject()

    def _verify_later(
        self,
        expected: D73IngressTransactionStateV1,
        successor: D73IngressTransactionStateV1,
        peer: object,
        owner: object,
        attestation: object,
    ) -> None:
        self._begin(expected)
        try:
            if attestation is not self._attestation:
                self._failure()
            _attestation_values(attestation)
            if self._peer is None:
                self._failure()
            _verify_peer_continuity_v1(self._peer, peer, owner, self._policy)
            if self._state is not expected:
                self._failure()
            self._state = successor
        except Exception:
            self._failure()
        finally:
            self._active = False

    def verify_b(self, peer: object, owner: object, attestation: object) -> None:
        self._verify_later(
            D73IngressTransactionStateV1.DECODED_BOUND,
            D73IngressTransactionStateV1.B_VERIFIED,
            peer,
            owner,
            attestation,
        )

    def verify_c(self, peer: object, owner: object, attestation: object) -> None:
        self._verify_later(
            D73IngressTransactionStateV1.B_VERIFIED,
            D73IngressTransactionStateV1.C_VERIFIED,
            peer,
            owner,
            attestation,
        )

    def close(self) -> None:
        self._begin(D73IngressTransactionStateV1.C_VERIFIED)
        try:
            self._decoded_record = None
            self._peer = None
            self._state = D73IngressTransactionStateV1.CLOSED
        except Exception:
            self._failure()
        finally:
            self._active = False

    def abort(self) -> None:
        if self._active:
            self._abort()
            _reject()
        if self._state is D73IngressTransactionStateV1.ABORTED:
            return
        if self._state is D73IngressTransactionStateV1.CLOSED:
            self._abort()
            _reject()
        self._active = True
        try:
            self._abort()
        finally:
            self._active = False
