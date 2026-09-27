# D378-B – canonical pricing runtime materialization handoff

Status: `REVIEW_READY`
Date: 2026-09-28 (Europe/Berlin)
Branch: `d378b-flex-watchdog`

## Review scope

This handoff covers the unreviewed source range beginning at the reviewed Flex
watchdog parent `8c620cd96a76d20d9d8d9b23fc62feae02853d11`, including the
follow-up that closes the two independent runtime-authority review findings.

The range contains the earlier unreviewed package-entrypoint commit
`4c64686298b43ed94e2f4f609b77bbf490a99c64`. Its console-script declaration
and isolated-wheel test are deliberately removed by this follow-up change: the
console script would own the canonical name but cannot materialize the required
user units or attest a generation. The commit remains in ancestry; no history
was rewritten and no foreign work was discarded.

## Product result awaiting review

The existing single-owner attested runtime lifecycle now includes these
manifested artifacts in every generation:

- `bin/the-hive-openai-pricing-inventory` (generation entrypoint, `0755`)
- `bin/the-hive-openai-pricing-inventory-stable` (stable launcher source, `0755`)
- `systemd/user/the-hive-openai-pricing.service` and
  `systemd/user/the-hive-openai-pricing.timer` (`0644`)
- `src/the_hive/pricing_inventory.py`

The installer writes only manifest-attested bytes to the canonical
`~/.local/bin/the-hive-openai-pricing-inventory` launcher and the two
`~/.config/systemd/user/the-hive-openai-pricing.*` units.

The public launcher uses existing release-pointer/manifest ownership checks,
validates its own digest and bytes plus the generation entrypoint through
no-follow descriptors, then executes the pinned descriptor. It acquires the
existing `.the-hive-release-publish.lock` with `LOCK_SH`; the publisher uses
the compatible `LOCK_EX`. The descriptor remains inherited across the pinned
`execve` until the generation entrypoint has completed
`RuntimeLayout.from_current_release(...)`, which attests both `current` and
`previous` plus the complete required image. The entrypoint verifies that the
inherited descriptor is the canonical owned lock and only then releases it
before invoking the inventory with `python3 -I`, not checkout-relative
`PYTHONPATH`.

The existing publish transaction snapshots the launcher and both units,
publishes them before moving the release pointer, and restores all three on a
failure. Existing owner, regular-file, link-count, mode, and no-follow
conventions reject symlink, non-owned, and unsafe targets. Existing
`current`/`previous` semantics remain intact.

Staging accepts the pricing stable launcher, service, and timer only when each
is byte-for-byte equal to its owned canonical source artifact. This is
structurally fail-closed: repeated or overriding `ExecStart`,
`ReadWritePaths`, `Unit`, or any other directives cannot be smuggled through
a substring allowlist. The canonical service invokes only
`%h/.local/bin/the-hive-openai-pricing-inventory`; its canonical state root
and the timer target remain part of that exact contract.

## Changed source files

- `bin/the-hive-openai-pricing-inventory`
- `bin/the-hive-openai-pricing-inventory-stable` (new)
- `scripts/the-hive-hive-hourly-probe-install`
- `src/the_hive/runtime_layout.py`
- `src/the_hive/runtime_lifecycle.py` (canonical user-manager environment
  follow-up)
- `tests/test_hive_hourly_probe.py`
- `tests/test_runtime_lifecycle_service.py`
- `tests/test_runtime_layout.py`
- `pyproject.toml` and `tests/test_pricing_inventory.py` (remove the
  conflicting package console-script change)

The pre-existing untracked prompt files
`.local/d378b-flex-watchdog-openai-fix5.prompt.md` and
`.local/d378b-flex-watchdog-openai-review-fix4.prompt.md` are not part of
this change and must remain unstaged.

## Focused evidence

Passed:

```
PYTHONPATH=src pytest -q tests/test_runtime_layout.py tests/test_pricing_inventory.py
# 131 passed in 7.36s

PYTHONPATH=src pytest -q -x \
  tests/test_hive_hourly_probe.py::test_pricing_inventory_runtime_materialization_is_attested_and_upgrade_safe
# 1 passed in 16.81s

PYTHONPATH=src pytest -q -x \
  tests/test_hive_hourly_probe.py::test_pricing_runtime_rejects_noncanonical_launcher_and_unit_directives \
  tests/test_hive_hourly_probe.py::test_pricing_stable_launcher_waits_for_the_runtime_publish_lock
# 2 passed in 8.58s

PYTHONPATH=src pytest -q \
  tests/test_hive_hourly_probe.py::test_pricing_stable_launcher_waits_for_the_runtime_publish_lock
# 1 passed in 8.74s (after replacing the `/proc` observation with the
# deterministic absent-pointer lock proof)

PYTHONPATH=src pytest -q \
  tests/test_hive_hourly_probe.py::test_pricing_runtime_rolls_back_the_complete_pair_on_timer_failure
# 1 passed in 15.57s

python3 -m py_compile scripts/the-hive-hive-hourly-probe-install
# passed

bash -n bin/the-hive-openai-pricing-inventory \
  bin/the-hive-openai-pricing-inventory-stable
# passed

git diff --check
# passed
```

## User-manager preflight follow-up

`runtime_lifecycle._systemctl_default` now invokes the bounded user-manager
protocol with only `LANG=C`, `PATH=/usr/bin:/bin`, and canonical,
effective-UID-derived `XDG_RUNTIME_DIR=/run/user/<euid>` plus
`DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<euid>/bus`. It does not inherit
caller-supplied bus, runtime directory, or path values. This repairs the
otherwise fail-closed preflight path under a sanitized environment without
changing the existing nonzero-systemctl failure code.

```
PYTHONPATH=src pytest -q \
  tests/test_runtime_lifecycle_service.py::test_systemctl_default_uses_only_the_canonical_uid_user_manager_environment \
  tests/test_runtime_lifecycle_service.py::test_systemctl_default_keeps_a_nonzero_systemctl_result_fail_closed
# 2 passed in 0.42s

python3 -m py_compile src/the_hive/runtime_lifecycle.py \
  tests/test_runtime_lifecycle_service.py
# passed
```

The tests mock `subprocess.run`; no live `systemctl` retry, user-runtime
installation, daemon reload, unit action, or inventory execution occurred.

The materialization node proves manifest inclusion, modes/content,
neutral-working-directory launch despite hostile `PYTHONPATH` and Codex
environment, pointer-digest rejection, upgrade materialization, and
`current`/`previous` preservation. It now additionally proves that an invalid
`previous` binding fails the public launcher. The new negative-contract node
rejects a manipulated stable launcher and appended/overriding service
`ExecStart`, service `ReadWritePaths`, service `[Unit]`, and timer `Unit`
directives. The lock node holds the real publish lock with `LOCK_EX`, removes
the release pointer, and proves that the launcher cannot complete while the
exclusive lock remains held. Only after unlock does it reach the deliberately
absent pointer and fail closed with exit status `64`; this does not depend on
`/proc` observation. The existing unsafe replacement cases and rollback node
were exercised during this follow-up; only the rollback command's complete
result is reproduced above. The parameterized unsafe-replacement command
returned incremental progress before the tool yielded; after it exited, its
exit status was not independently recoverable, so its final aggregate result
is unknown despite no corresponding pytest `lastfailed` entry.

The existing installer stage validator did create temporary
`systemd-run --user` child processes against test-only `/tmp/pytest-.../home`
images. No `systemctl` command ran, no canonical real-home user unit was
installed or activated, and no live inventory ran. Lasting transient-manager
state was not independently queried, so it remains unknown.

## Residual unknowns / blockers

- This source range is ready for independent review. It is not self-reviewed;
  no integration, push, installation, or activation is authorized by this
  status.
- The pre-existing
  `test_internal_attested_runtime_api_materializes_one_complete_regular_runtime_image`
  was observed failing during inspection with
  `hive_hourly_probe_error code=legacy_probe_attestation_failed`. Its
  baseline status and causality are unverified.
- No fetch was performed during this materialization-only task. The supplied
  earlier `origin/main` was
  `5de430caa4a8b95d272d3dfb1223cd3b26a9954a`; current remote state is unknown.
- No canonical real-home runtime was installed and no daemon reload, unit
  enable/start, old-unit removal, or inventory run occurred. Live health,
  catalog, unit state, redaction, and ordinary-restart Flex capability are
  unverified.
- The repaired user-manager environment has not been exercised against the
  live user bus in this task; the live cutover preflight remains unverified.
- The subscription-path 400 versus direct `openai-flex` 200 boundary was not
  re-executed. No secret was persisted or placed in source, command arguments,
  output, or this handoff.
