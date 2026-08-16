# CI operations

Last verified: 2026-08-14.

`.github/workflows/ci.yml` is the authoritative remote workflow. It runs with
`contents: read`, does not consume repository secrets, and pins every external
action to a full 40-character commit SHA.

## Gate matrix

| Area | GitHub Actions gate | Local reproduction |
|---|---|---|
| Python syntax | `python -m compileall -q src tests` | `PYTHONPATH=src python -m compileall -q src tests` |
| Python lint | `ruff check --select E4,E7,E9,F --output-format=github .` with `ruff==0.16.3` | same command without GitHub output format |
| Python tests | `PYTHONPATH=src python -m pytest -q` | same command |
| Node | `node --check` plus `node --test` for the Cinnamon applet | commands from the workflow |
| Public schemas and examples | full pytest suite, including `tests/test_plan_fixtures.py` | `PYTHONPATH=src python -m pytest -q tests/test_plan_fixtures.py` |
| Plugin/App/MCP manifests | dedicated inline JSON and contract validation | workflow validator plus full pytest suite |
| Manpage | deterministic repository builder plus GNU groff render | commands below |
| Workflow supply chain | read-only permissions and full-SHA action pins | `actionlint .github/workflows/ci.yml` and `tests/test_ci_workflow.py` |
| Whitespace | commit-range-aware `git diff --check` | `git diff --check` |
| CLI and pool | wrapper and disposable pool smoke tests | commands from the workflow |

The Manpage gate installs Ubuntu's `groff-base` package without recommended
packages, then runs:

```sh
./scripts/codex-master-manpage build --output-dir /tmp/codex-master-man
groff -man -Tutf8 man/man1/codex-master-mcp.1 >/dev/null
```

## Local-only and deferred checks

`telint scan . --format json` remains a local additional gate. Telint currently
has no published, pinned package, Git remote, or vendored source in this
repository. CI must not download it from an unverified location or silently
skip it. A CI step remains blocked until a reproducible source and provenance
are approved.

No coverage threshold is enforced. Baseline measurement and a justified
threshold remain a separate package; adding `pytest-cov` without that contract
would create a dependency without a stable gate.

Ruff 0.16 expanded its defaults beyond the repository's previous baseline.
The explicit `E4,E7,E9,F` selection preserves the established syntax/import
error gate while making the pinned Ruff upgrade deterministic. Expanding this
set requires a measured cleanup package; CI does not use `--fix`.

`actionlint` is used locally when installed. `yamllint` is optional and was not
installed by this change. Remote GitHub Actions execution is the final check of
runner behavior; local success does not claim a green remote run.

## Primary sources and licenses

- GitHub's [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
  recommends immutable full-SHA action references. GitHub Docs content is
  CC-BY-4.0.
- [actions/checkout](https://github.com/actions/checkout) and
  [actions/setup-python](https://github.com/actions/setup-python) are MIT
  licensed. This workflow keeps the existing audited SHAs
  `df4cb1c069e1874edd31b4311f1884172cec0e10` (`v6.0.3`) and
  `a309ff8b426b58ec0e2a45f0f869d46889d02405` (`v6.2.0`).
- Ruff's official [GitHub Actions integration](https://docs.astral.sh/ruff/integrations/)
  supports direct CLI installation. The immutable
  [0.16.3 release](https://github.com/astral-sh/ruff/releases/tag/0.16.3) is MIT
  licensed; direct CLI use avoids another workflow action.
- GitHub's [runner-images](https://github.com/actions/runner-images) repository
  and its [Ubuntu 24.04 inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
  are MIT licensed. `ubuntu-latest` currently maps to a GA Ubuntu image but can
  migrate; the remote job log is authoritative for the image used.
- [GNU groff](https://www.gnu.org/software/groff/) is distributed under the GNU
  General Public License. CI installs the Canonical-provided `groff-base`
  package instead of adding a third-party action.
