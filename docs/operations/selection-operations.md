# Selection Operations

Selection is a preview/ordering layer. It does not start, stop, interrupt,
reserve, or preempt an Agentin.

Run a bounded preview from the server:

```sh
python3 -m codex_master.server selection-preview \
  --series d --task-kind simple --admission-mode shadow --limit 8
```

Selection evaluates eligibility first, then assigns a band and deterministic
tie-break key. A candidate that is ineligible never receives a selection band.
The fairness ledger is immutable during preview. Final execution must create a
fresh admission and revalidate every server/Hive gate immediately before the
existing low-level assignment operation.

Safe rollout order is SP3, SP2, SP1, then passive SP0. Feature policy is a
fail-closed upper bound: a caller cannot enable a flag that the loaded policy
does not allow. A disabled feature produces a reason code and no state write.

For current usage, prefer the typed Usage-v2 source. A missing, stale,
unverified, or semantically ambiguous source is reported as unavailable; the
system never infers a reset or quota from free-form provider text.

## Class, lifecycle, model, and reasoning resolution

Before the first start or assignment for a target series, call
`agent_selection_options` with one concrete Agentin. Cache its `generation`,
not an independently reconstructed model list. On later work, pass the digest
as `known_generation`; refresh local choices whenever `options_changed` is
true.

For the first offer to a Teamleiterin, the visible options must include the
single legal tuple `class=teamleiterin`, `lifecycle=persistent`,
`model=gpt-5.6-terra`, `reasoning=xhigh`. Policy fixes `xhigh` as both minimum
and maximum effort. No other Teamleiterin tuple is offerable.

Send only a tuple returned in `options` when possible. `agent_start`,
`agent_assign`, and assignment shortcuts accept `class`, `lifecycle`, `model`,
`reasoning_effort`, and `complexity`, then use one shared resolver. The public
lifecycle names are `ephemeral`, `binding`, and `persistent`; legacy input
`invocation` normalizes to `ephemeral`.

Omitted fields follow these operational defaults:

- auto-select a compatible non-leadership class;
- use the selected class's default lifecycle;
- simple ephemeral write: Spark/low when capability and account availability
  allow it, otherwise Luna/medium;
- read-only or medium/complex ephemeral work: Luna/medium;
- binding: Luna/high;
- persistent worker: Luna/xhigh.

Leadership inventory bindings override caller requests: Gottbiene is always
persistent Sol/max and Koenigin is always persistent Sol/xhigh. Teamleiterin
is always persistent `gpt-5.6-terra`/`xhigh`, with `xhigh` as both minimum and
maximum effort. Teamleiterin cannot become Spark, Luna, or Sol and cannot use
`ultra`.
If `gpt-5.6-terra` is unavailable, return the hard error
`required_model_unavailable:gpt-5.6-terra`; if its `xhigh` effort is
unavailable, return `required_model_effort_unavailable:gpt-5.6-terra:xhigh`.
Workers may move Spark -> Luna -> Terra -> Sol only when the selected class,
lifecycle, model-specific effort levels, and class effort bounds permit it.
Persistent workers require at least `xhigh`; non-Gottbiene selections never
exceed `xhigh`.

Treat `selection.fallback: true` as a visible policy correction. Inspect
`selection.reason_codes` and the effective tuple before continuing. Typical
causes are unavailable or unknown models, class/lifecycle incompatibility,
task-minimum violations, and unsupported or out-of-range reasoning. Do not
retry the rejected tuple unchanged; choose a current offered tuple or stop.

Spark is only the simple-write default when no model was requested. For a
worker with an explicitly unknown or unavailable model, use Luna as the safe
fallback, never Spark. Preserve a compatible explicitly requested reasoning
level or clamp it to the replacement model and class/lifecycle bounds. Return
the requested and effective tuples plus the concrete reason code. Leadership
bindings still override this worker fallback. A required model or effort that
is unavailable is a hard error with no fallback; this applies in particular to
the exact Teamleiterin tuple above, which must never be substituted.

The checked-in `codex-agent-classes.json` and `codex-model-policy.json` files
are authoritative. Documentation and callers must not maintain a second model
matrix. Medium or complex work cannot retain Spark merely because it was
requested; task capability raises the effective model to at least Luna, then
class and lifecycle minima still apply.

Masterjet lifecycle administration is outside selection resolution. Only the
Koenigin may restart or reload Masterjet, install it, or synchronize the plugin
cache. Teamleiterinnen and other roles may inspect status, retain verification
evidence, and recommend the Queen action, but must not execute it.
