"""Fail-closed remote identity and step-up verification for Masterjet admin."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import base64
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time
from types import MappingProxyType
from typing import Final, cast

import jwt

from .admin_contracts import AdminPrincipalV1


MAX_ASSERTION_BYTES: Final[int] = 16_384
MAX_CREDENTIAL_BYTES: Final[int] = 64 * 1024
_MAX_BEARER_BYTES: Final[int] = 4096
_MAX_JWKS_KEYS: Final[int] = 32
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_SCOPE = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z", re.ASCII)
_KID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z", re.ASCII)
_TOTP = re.compile(r"[0-9]{6}\Z", re.ASCII)
_ALGORITHMS = frozenset({"RS256"})


class AdminAuthError(ValueError):
    """Code-only failure at the remote authentication boundary."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"AdminAuthError({self.code!r})"


class CloudflareAccessVerifier:
    """Verify one Cloudflare Access application assertion from pinned JWKS."""

    __slots__ = (
        "_algorithms",
        "_audience",
        "_clock",
        "_issuer",
        "_keys",
        "_max_token_age",
        "_principal_resolver",
    )

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks: Mapping[str, object],
        principal_resolver: Callable[[str, Mapping[str, object]], Sequence[str]],
        algorithms: Sequence[str] = ("RS256",),
        clock: Callable[[], float] = time.time,
        max_token_age_seconds: int = 600,
    ) -> None:
        self._issuer = _https_issuer(issuer)
        self._audience = _token(audience, "authority.identity_invalid")
        self._algorithms = _allowed_algorithms(algorithms)
        if not callable(principal_resolver) or not callable(clock):
            raise AdminAuthError("authority.configuration_invalid")
        if (
            type(max_token_age_seconds) is not int
            or not 30 <= max_token_age_seconds <= 86_400
        ):
            raise AdminAuthError("authority.configuration_invalid")
        self._principal_resolver = principal_resolver
        self._clock = clock
        self._max_token_age = max_token_age_seconds
        self._keys = _parse_jwks(jwks, self._algorithms)

    def verify(self, assertion: str) -> AdminPrincipalV1:
        token = _ascii_secret(assertion, maximum=MAX_ASSERTION_BYTES)
        try:
            header = jwt.get_unverified_header(token)
            if type(header) is not dict or set(header) & {"jku", "x5u", "x5c", "crit"}:
                raise ValueError
            algorithm = header.get("alg")
            kid = header.get("kid")
            if (
                type(algorithm) is not str
                or algorithm not in self._algorithms
                or type(kid) is not str
                or _KID.fullmatch(kid) is None
            ):
                raise ValueError
            key = self._keys.get(kid)
            if key is None or key.algorithm_name != algorithm:
                raise ValueError
            decoded = jwt.decode(
                token,
                key=key.key,
                algorithms=(algorithm,),
                options={
                    "require": ["iss", "aud", "sub", "iat", "nbf", "exp"],
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
            claims = _claims(decoded)
            subject = _verify_cloudflare_claims(
                claims,
                issuer=self._issuer,
                audience=self._audience,
                now=_now(self._clock),
                max_token_age=self._max_token_age,
            )
        except AdminAuthError:
            raise
        except Exception:
            raise AdminAuthError("authority.identity_invalid") from None
        try:
            scopes = _scopes(self._principal_resolver(subject, claims))
        except AdminAuthError:
            raise
        except Exception:
            raise AdminAuthError("authority.scope_invalid") from None
        return AdminPrincipalV1(subject, scopes, "cloudflare-access", False)

    @classmethod
    def from_fd(
        cls,
        *,
        issuer: str,
        audience: str,
        jwks_fd: int,
        principal_resolver: Callable[[str, Mapping[str, object]], Sequence[str]],
        algorithms: Sequence[str] = ("RS256",),
        clock: Callable[[], float] = time.time,
        max_token_age_seconds: int = 600,
    ) -> CloudflareAccessVerifier:
        return cls(
            issuer=issuer,
            audience=audience,
            jwks=_jwks_from_fd(jwks_fd),
            principal_resolver=principal_resolver,
            algorithms=algorithms,
            clock=clock,
            max_token_age_seconds=max_token_age_seconds,
        )

    def replace_jwks(self, jwks: Mapping[str, object]) -> None:
        """Atomically replace the pinned cache after an external trusted refresh."""

        self._keys = _parse_jwks(jwks, self._algorithms)

    def replace_jwks_from_fd(self, jwks_fd: int) -> None:
        self.replace_jwks(_jwks_from_fd(jwks_fd))

    @property
    def jwks_kids(self) -> tuple[str, ...]:
        """Expose redacted cache state for daemon refresh observability."""

        return tuple(self._keys)

    def refresh_jwks(self, loader: Callable[[], Mapping[str, object]]) -> bool:
        """Refresh atomically; preserve last-known-good keys on failure."""

        try:
            replacement = _parse_jwks(loader(), self._algorithms)
        except Exception:
            return False
        self._keys = replacement
        return True


class MasterjetBearerVerifier:
    """Verify an app-owned bearer loaded only through already-private FDs."""

    __slots__ = ("_credentials", "_scopes", "_subject")

    def __init__(
        self,
        credentials: tuple[bytearray, ...],
        *,
        subject: str,
        scopes: tuple[str, ...],
    ) -> None:
        if not credentials:
            raise AdminAuthError("authority.configuration_invalid")
        self._credentials = credentials
        self._subject = _token(subject, "authority.configuration_invalid")
        self._scopes = _scopes(scopes)

    @classmethod
    def from_fd(
        cls,
        fd: int,
        *,
        subject: str,
        scopes: Sequence[str],
    ) -> MasterjetBearerVerifier:
        return cls.from_fds((fd,), subject=subject, scopes=scopes)

    @classmethod
    def from_fds(
        cls,
        fds: Sequence[int],
        *,
        subject: str,
        scopes: Sequence[str],
    ) -> MasterjetBearerVerifier:
        if type(fds) not in {tuple, list} or not 1 <= len(fds) <= 4:
            raise AdminAuthError("authority.configuration_invalid")
        credentials: list[bytearray] = []
        try:
            for fd in fds:
                raw = _read_private_fd(fd, maximum=_MAX_BEARER_BYTES)
                while raw.endswith(b"\n"):
                    raw.pop()
                _ascii_secret_bytes(raw, maximum=_MAX_BEARER_BYTES)
                credentials.append(raw)
            return cls(tuple(credentials), subject=subject, scopes=_scopes(scopes))
        except AdminAuthError:
            _wipe_all(credentials)
            raise
        except Exception:
            _wipe_all(credentials)
            raise AdminAuthError("authority.credential_invalid") from None

    def verify(self, bearer: str) -> AdminPrincipalV1:
        try:
            candidate = bytearray(bearer, "ascii")
            _ascii_secret_bytes(candidate, maximum=_MAX_BEARER_BYTES)
        except AdminAuthError:
            raise AdminAuthError("authority.identity_invalid") from None
        try:
            accepted = False
            for credential in self._credentials:
                accepted = hmac.compare_digest(candidate, credential) or accepted
            if not accepted:
                raise AdminAuthError("authority.identity_invalid")
            return AdminPrincipalV1(
                self._subject,
                self._scopes,
                "masterjet-bearer",
                False,
            )
        finally:
            _wipe(candidate)

    def close(self) -> None:
        _wipe_all(self._credentials)

    def __repr__(self) -> str:
        return "MasterjetBearerVerifier(<redacted>)"


class TotpStepUpVerifier:
    """RFC 6238 SHA-1 verifier with process-wide atomic counter replay defense."""

    __slots__ = ("_clock", "_db", "_lock", "_secret", "_skew_steps", "_used")

    def __init__(
        self,
        secret: bytearray,
        *,
        clock: Callable[[], float],
        skew_steps: int,
        replay_state_path: Path | None = None,
    ) -> None:
        if not 16 <= len(secret) <= 128 or not callable(clock):
            raise AdminAuthError("authority.configuration_invalid")
        if type(skew_steps) is not int or not 0 <= skew_steps <= 2:
            raise AdminAuthError("authority.configuration_invalid")
        self._secret = secret
        self._clock = clock
        self._skew_steps = skew_steps
        self._lock = threading.Lock()
        self._used: set[int] = set()
        self._db: sqlite3.Connection | None = None
        if replay_state_path is not None:
            try:
                path = Path(replay_state_path)
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                self._db = sqlite3.connect(path, check_same_thread=False)
                self._db.execute("PRAGMA journal_mode=WAL")
                self._db.execute("PRAGMA synchronous=FULL")
                self._db.execute(
                    "CREATE TABLE IF NOT EXISTS consumed (counter INTEGER PRIMARY KEY)"
                )
                self._db.commit()
                os.chmod(path, 0o600)
            except Exception:
                if self._db is not None:
                    self._db.close()
                raise AdminAuthError("authority.configuration_invalid") from None

    @classmethod
    def from_fd(
        cls,
        fd: int,
        *,
        clock: Callable[[], float] = time.time,
        skew_steps: int = 1,
        replay_state_path: Path | None = None,
    ) -> TotpStepUpVerifier:
        encoded = _read_private_fd(fd, maximum=256)
        try:
            while encoded.endswith(b"\n"):
                encoded.pop()
            secret = bytearray(base64.b32decode(encoded, casefold=False))
        except Exception:
            raise AdminAuthError("authority.credential_invalid") from None
        finally:
            _wipe(encoded)
        try:
            return cls(
                secret,
                clock=clock,
                skew_steps=skew_steps,
                replay_state_path=replay_state_path,
            )
        except Exception:
            _wipe(secret)
            raise

    def verify(self, subject: str, code: str) -> int:
        _token(subject, "authority.identity_invalid")
        if type(code) is not str or _TOTP.fullmatch(code) is None:
            raise AdminAuthError("authority.step_up_invalid")
        counter = int(_now(self._clock)) // 30
        candidates = (counter,) + tuple(
            item
            for distance in range(1, self._skew_steps + 1)
            for item in (counter - distance, counter + distance)
            if item >= 0
        )
        with self._lock:
            matched = next(
                (
                    candidate
                    for candidate in candidates
                    if hmac.compare_digest(_totp(self._secret, candidate), code)
                ),
                None,
            )
            if matched is None:
                raise AdminAuthError("authority.step_up_invalid")
            floor = counter - self._skew_steps - 2
            if self._db is None:
                if matched in self._used:
                    raise AdminAuthError("authority.step_up_replayed")
                self._used.add(matched)
                self._used.intersection_update(
                    item for item in self._used if item >= floor
                )
            else:
                try:
                    self._db.execute("BEGIN IMMEDIATE")
                    self._db.execute("DELETE FROM consumed WHERE counter < ?", (floor,))
                    self._db.execute(
                        "INSERT INTO consumed(counter) VALUES (?)", (matched,)
                    )
                    self._db.commit()
                except sqlite3.IntegrityError:
                    self._db.rollback()
                    raise AdminAuthError("authority.step_up_replayed") from None
                except Exception:
                    self._db.rollback()
                    raise AdminAuthError("authority.configuration_invalid") from None
            return matched

    def close(self) -> None:
        with self._lock:
            _wipe(self._secret)
            self._used.clear()
            if self._db is not None:
                self._db.close()
                self._db = None

    def __repr__(self) -> str:
        return "TotpStepUpVerifier(<redacted>)"


def _parse_jwks(
    value: Mapping[str, object], algorithms: frozenset[str]
) -> Mapping[str, jwt.PyJWK]:
    try:
        if (
            not isinstance(value, Mapping)
            or not set(value)
            <= {
                "keys",
                "public_cert",
                "public_certs",
            }
            or "keys" not in value
        ):
            raise ValueError
        if "public_cert" in value and (
            type(value["public_cert"]) is not str
            or len(value["public_cert"].encode("utf-8")) > MAX_CREDENTIAL_BYTES
        ):
            raise ValueError
        if "public_certs" in value:
            public_certs = value["public_certs"]
            if type(public_certs) is not dict or len(public_certs) > _MAX_JWKS_KEYS:
                raise ValueError
            if any(
                type(kid) is not str
                or _KID.fullmatch(kid) is None
                or type(cert) is not str
                or len(cert.encode("utf-8")) > MAX_CREDENTIAL_BYTES
                for kid, cert in public_certs.items()
            ):
                raise ValueError
        raw_keys = value["keys"]
        if type(raw_keys) is not list or not 1 <= len(raw_keys) <= _MAX_JWKS_KEYS:
            raise ValueError
        keys: dict[str, jwt.PyJWK] = {}
        for raw in raw_keys:
            if type(raw) is not dict:
                raise ValueError
            kid = raw.get("kid")
            algorithm = raw.get("alg")
            if (
                type(kid) is not str
                or _KID.fullmatch(kid) is None
                or kid in keys
                or algorithm not in algorithms
                or raw.get("kty") != "RSA"
                or raw.get("use") not in {None, "sig"}
            ):
                raise ValueError
            key = jwt.PyJWK.from_dict(raw, algorithm=cast(str, algorithm))
            if key.key_type != "RSA" or key.algorithm_name != algorithm:
                raise ValueError
            keys[kid] = key
        return MappingProxyType(keys)
    except Exception:
        raise AdminAuthError("authority.configuration_invalid") from None


def _claims(value: object) -> Mapping[str, object]:
    if type(value) is not dict or not 1 <= len(value) <= 64:
        raise AdminAuthError("authority.identity_invalid")
    return MappingProxyType(dict(cast(dict[str, object], value)))


def _verify_cloudflare_claims(
    claims: Mapping[str, object],
    *,
    issuer: str,
    audience: str,
    now: float,
    max_token_age: int,
) -> str:
    if claims.get("iss") != issuer:
        raise AdminAuthError("authority.identity_invalid")
    aud = claims.get("aud")
    if not (aud == audience or (type(aud) is list and aud == [audience])):
        raise AdminAuthError("authority.identity_invalid")
    subject = _token(claims.get("sub"), "authority.identity_invalid")
    times: dict[str, int] = {}
    for name in ("iat", "nbf", "exp"):
        value = claims.get(name)
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise AdminAuthError("authority.identity_invalid")
        times[name] = value
    if not (
        times["iat"] <= now
        and times["nbf"] <= now
        and now < times["exp"]
        and now - times["iat"] <= max_token_age
        and times["iat"] <= times["exp"] <= times["iat"] + 86_400
    ):
        raise AdminAuthError("authority.identity_invalid")
    return subject


def _allowed_algorithms(value: Sequence[str]) -> frozenset[str]:
    if type(value) not in {tuple, list}:
        raise AdminAuthError("authority.configuration_invalid")
    result = frozenset(value)
    if not result or not result <= _ALGORITHMS or len(result) != len(value):
        raise AdminAuthError("authority.configuration_invalid")
    return result


def _scopes(value: Sequence[str]) -> tuple[str, ...]:
    if type(value) not in {tuple, list} or len(value) > 64:
        raise AdminAuthError("authority.scope_invalid")
    result = tuple(value)
    if len(set(result)) != len(result) or any(
        type(item) is not str or _SCOPE.fullmatch(item) is None for item in result
    ):
        raise AdminAuthError("authority.scope_invalid")
    return result


def _https_issuer(value: object) -> str:
    if (
        type(value) is not str
        or not value.startswith("https://")
        or value.endswith("/")
        or "/" in value[8:]
        or len(value) > 512
    ):
        raise AdminAuthError("authority.configuration_invalid")
    return value


def _token(value: object, code: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AdminAuthError(code)
    return value


def _ascii_secret(value: object, *, maximum: int) -> str:
    if type(value) is not str:
        raise AdminAuthError("authority.credential_invalid")
    try:
        raw = value.encode("ascii")
    except UnicodeError:
        raise AdminAuthError("authority.credential_invalid") from None
    if (
        not raw
        or len(raw) > maximum
        or any(byte <= 0x20 or byte >= 0x7F for byte in raw)
    ):
        raise AdminAuthError("authority.credential_invalid")
    return value


def _ascii_secret_bytes(value: bytearray, *, maximum: int) -> None:
    if (
        not value
        or len(value) > maximum
        or any(byte <= 0x20 or byte >= 0x7F for byte in value)
    ):
        raise AdminAuthError("authority.credential_invalid")


def _now(clock: Callable[[], float]) -> float:
    value = clock()
    if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
        raise AdminAuthError("authority.configuration_invalid")
    return float(value)


def _read_private_fd(fd: int, *, maximum: int) -> bytearray:
    try:
        if type(fd) is not int or fd < 0 or not hasattr(os, "pread"):
            raise ValueError
        before = os.fstat(fd)
        access_mode = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
        if (
            not stat.S_ISREG(before.st_mode)
            or access_mode != os.O_RDONLY
            or before.st_nlink not in {0, 1}
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & 0o077
            or not 1 <= before.st_size <= maximum
        ):
            raise ValueError
        payload = bytearray(before.st_size)
        view = memoryview(payload)
        read = os.preadv(fd, (view,), 0)
        after = os.fstat(fd)
        stable = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
        )
        if not stable or read != before.st_size:
            _wipe(payload)
            raise ValueError
        return payload
    except Exception:
        raise AdminAuthError("authority.credential_invalid") from None


def _jwks_from_fd(fd: int) -> Mapping[str, object]:
    raw: bytearray | None = None
    try:
        raw = _read_private_fd(fd, maximum=MAX_CREDENTIAL_BYTES)
        value = json.loads(raw)
        if type(value) is not dict:
            raise ValueError
        return cast(dict[str, object], value)
    except AdminAuthError:
        raise
    except Exception:
        raise AdminAuthError("authority.credential_invalid") from None
    finally:
        if raw is not None:
            _wipe(raw)


def _totp(secret: bytearray, counter: int) -> str:
    digest = hmac.new(secret, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def _wipe(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)
    value.clear()


def _wipe_all(values: Sequence[bytearray]) -> None:
    for value in values:
        _wipe(value)
