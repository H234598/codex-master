# Codex-Usage handoff: `cache_invalidated` Last-Good contract

**Owner:** Codex-Usage.  **Consumer:** Masterjet routing only.  **Status:**
technical handoff; no Masterjet workaround exists or is requested.

## Problem

A fresh app-server query can fail transiently while a previously valid,
identity-equivalent usage observation exists.  Current Masterjet routing treats
the resulting `cache_invalidated` as terminal, even when the failure has not
shown a changed account identity or a changed limit.  This blocks selection
before any resolver or V2-home work can begin.

## Narrow Last-Good rule

Codex-Usage may publish a Last-Good decision only when *all* conditions hold:

1. Current fetch failed with an explicitly classified transient transport
   failure.  The public enum must name the failure; no string matching.
2. Current attempt and Last-Good record share the exact account ID, configured
   profile ID, backend account ID, credential-binding HMAC, launcher identity,
   and schema version.
3. Last-Good record was a fully validated success, is younger than a
   documented bounded max age, and belongs to the immediately preceding or a
   later monotonic observation generation for that same identity tuple.
4. No auth, identity, protocol, parsing, schema, policy, credential, or
   account-state error occurred in current attempt or Last-Good record.
5. Returned payload is marked `state: "last_good_transient"`, includes
   `last_good_age_seconds`, source and observation generations, and retains
   the classified current error without secrets or raw responses.

Masterjet consumes this as a normal *explicit* routing state; it does not read
or infer Last-Good data itself.

## Never eligible for Last-Good

Do not publish a routing candidate after: `401`, `403`, `token_revoked`, any
credential/profile/account identity mismatch, malformed or schema-invalid
payload, unsupported backend protocol, unknown error class, explicit account
disable, exhausted/limited state, or an ambiguous clock/generation ordering.
Do not use a generic stale-cache fallback, an auth copy, or a series-derived
identity.

## Required observable contract

Codex-Usage must expose these bounded public fields on every routing decision:

- `state`: `fresh`, `last_good_transient`, or terminal state;
- `identity_binding`: opaque HMAC/digest only;
- `profile_id`, `backend_account_id`, `launcher_identity`;
- `observation_generation`, `last_good_generation`, and bounded age;
- `current_error_class` and `fallback_reason` when applicable.

It must emit one audit event when entering or leaving `last_good_transient`.
Masterjet must preserve the state verbatim in selection/start reports, without
turning it into a second cache, account selector, or resolver.

## Acceptance cases for Codex-Usage owner

1. Temporary app-server transport failure + same bound successful observation
   within max age yields `last_good_transient`.
2. Same failure with a changed credential-binding HMAC remains terminal.
3. `401`, `token_revoked`, malformed response, stale/expired Last-Good, and
   unknown failure class remain terminal.
4. A later fresh success clears the transient marker and increments the
   observation generation.
