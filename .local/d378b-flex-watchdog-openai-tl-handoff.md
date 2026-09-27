# D378-B – canonical pricing runtime materialization handoff

Status: `REVIEW_REQUIRED`
Date: 2026-09-28 (Europe/Berlin)
Branch: `d378b-flex-watchdog`

## Review scope

This handoff covers the unreviewed source range beginning at the reviewed Flex
watchdog parent `8c620cd96a76d20d9d8d9b23fc62feae02853d11`.

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
no-follow descriptors, then executes the pinned descriptor. The generation
entrypoint validates `RuntimeLayout.from_current_release(...)` and invokes
the inventory with `python3 -I`, not checkout-relative `PYTHONPATH`.

The existing publish transaction snapshots the launcher and both units,
publishes them before moving the release pointer, and restores all three on a
failure. Existing owner, regular-file, link-count, mode, and no-follow
conventions reject symlink, non-owned, and unsafe targets. Existing
`current`/`previous` semantics remain intact.

Staging checks that the service has exactly
`ExecStart=%h/.local/bin/the-hive-openai-pricing-inventory`, uses the
canonical pricing state root, and contains no legacy `codex-master` name.
The timer must target `the-hive-openai-pricing.service`.

## Changed source files

- `bin/the-hive-openai-pricing-inventory`
- `bin/the-hive-openai-pricing-inventory-stable` (new)
- `scripts/the-hive-hive-hourly-probe-install`
- `src/the_hive/runtime_layout.py`
- `tests/test_hive_hourly_probe.py`
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
PYTHONPATH=src python3 -m pytest -q tests/test_runtime_layout.py tests/test_pricing_inventory.py
# 131 passed in 7.53s

python3 -m py_compile src/the_hive/pricing_inventory.py \
  src/the_hive/runtime_layout.py scripts/the-hive-hive-hourly-probe-install
# passed

bash -n bin/the-hive-openai-pricing-inventory \
  bin/the-hive-openai-pricing-inventory-stable
# passed

git diff --check
# passed
```

The dedicated pricing materialization node passed earlier in this session. It
proves manifest inclusion, modes/content, neutral-working-directory launch
despite hostile `PYTHONPATH` and Codex environment, pointer-digest rejection,
upgrade materialization, and `current`/`previous` preservation. The three
unsafe replacement cases (launcher symlink, service symlink, timer unsafe mode)
passed individually. The pricing-unit-pair rollback-on-timer-write-failure
case also passed.

A later combined re-run of those four installer nodes was intentionally
terminated without a result after the pre-existing test path started temporary
`systemd-run --user` subprocesses for its test-only `/tmp/pytest-.../home`
image. No `systemctl` command ran, no canonical user unit was installed or
activated, and no live inventory ran. Lasting transient-manager state was not
independently queried, so it remains unknown.

## Residual unknowns / blockers

- Independent review is required before integration, push, installation, or
  activation.
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
- The subscription-path 400 versus direct `openai-flex` 200 boundary was not
  re-executed. No secret was persisted or placed in source, command arguments,
  output, or this handoff.
