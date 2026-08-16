# Wiki publication manifest

This manifest is documentation only. The repository files remain canonical;
this file performs and authorizes no publication. Only Ihre Hoheit (the Queen)
may select the Wiki remote, approve `SOURCE_COMMIT`, clone, commit, push,
verify, revert, or clear the release gate. There is no automatic or scheduled
sync, history-rewriting push, or `gh` write command.

## Source-to-page mapping

| Order | Source | Wiki file | Page/slug |
|---:|---|---|---|
| 1 | `docs/wiki/Architecture.md` | `Architecture.md` | `Architecture` |
| 2 | `docs/wiki/Recovery.md` | `Recovery.md` | `Recovery` |
| 3 | `docs/wiki/Resolver.md` | `Resolver.md` | `Resolver` |
| 4 | `docs/wiki/Control-Plane.md` | `Control-Plane.md` | `Control-Plane` |
| 5 | `docs/wiki/Runbook.md` | `Runbook.md` | `Runbook` |
| 6 | `docs/wiki/Home.md` | `Home.md` | `Home` |

`Home` is staged and published last, so first publication cannot expose
navigation to a page that was not staged.

## Link transformation

The Queen supplies an immutable `SOURCE_COMMIT`. The following is one
dedicated Bash/GNU/Linux session: Bash 5.x, GNU `mktemp`, `install`, `cmp`,
`awk`, Git, Python 3, and `curl` are required; POSIX-shell portability is not
claimed. Staging, preflight, publish, and post-push verification use the same
temporary directories and cleanup happens only after verification. It reads
source bytes only with `git show` from one canonical full commit OID; it never
reads a source from the worktree. The Python 3 standard library is the only
extra runtime.

## Publish

```bash
set -euo pipefail
umask 077
STAGE_DIR=''
WIKI_DIR=''
cleanup() {
    rc=${1:-$?}
    trap - EXIT HUP INT TERM
    cleanup_rc=0
    if [ -n "${STAGE_DIR:-}" ]; then rm -rf -- "$STAGE_DIR" || cleanup_rc=$?; fi
    if [ -n "${WIKI_DIR:-}" ]; then rm -rf -- "$WIKI_DIR" || cleanup_rc=$?; fi
    if [ "$rc" -eq 0 ] && [ "$cleanup_rc" -ne 0 ]; then rc=$cleanup_rc; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

test -n "${SOURCE_COMMIT:-}" || { echo 'SOURCE_COMMIT is required' >&2; exit 1; }
SOURCE_COMMIT=$(git rev-parse --verify --quiet "${SOURCE_COMMIT}^{commit}") || {
    echo 'SOURCE_COMMIT is not an immutable commit' >&2; exit 1;
}
export SOURCE_COMMIT
test "$(git config --get remote.origin.url)" = 'https://github.com/H234598/codex-master.git'
STAGE_DIR=$(mktemp -d)
export SOURCE_COMMIT STAGE_DIR
python3 - <<'PY'
import os
import posixpath
import re
import subprocess
import sys
from pathlib import PurePosixPath
from urllib.parse import urlsplit

mapping = [
    ('docs/wiki/Architecture.md', 'Architecture.md', 'Architecture'),
    ('docs/wiki/Recovery.md', 'Recovery.md', 'Recovery'),
    ('docs/wiki/Resolver.md', 'Resolver.md', 'Resolver'),
    ('docs/wiki/Control-Plane.md', 'Control-Plane.md', 'Control-Plane'),
    ('docs/wiki/Runbook.md', 'Runbook.md', 'Runbook'),
    ('docs/wiki/Home.md', 'Home.md', 'Home'),
]
commit = os.environ['SOURCE_COMMIT']
stage = os.environ['STAGE_DIR']
pages = {source: slug for source, _, slug in mapping}
destinations = {destination for _, destination, _ in mapping}
link = re.compile(r'(!?\[[^\]]*\])\(([^)]+)\)')
secret = re.compile(r'(?i)(-----begin [^-]*private key-----|(?:https?|ssh)://[^/\s:@]+(?::[^@/\s]+)?@|(?:token|password|secret)\s*[=:])')
home_path = re.compile(r'(?i)(?:^|[^a-z0-9_])/(?:home)/[^/\s]+(?:/|$)')

def git_blob(path):
    check = subprocess.run(
        ['git', 'cat-file', '-e', f'{commit}:{path}'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if check.returncode:
        raise SystemExit(f'missing SOURCE_COMMIT target: {path}')
    kind = subprocess.check_output(['git', 'cat-file', '-t', f'{commit}:{path}'], text=True).strip()
    if kind != 'blob':
        raise SystemExit(f'SOURCE_COMMIT target is not a file: {path}')

def read_source(source):
    git_blob(source)
    raw = subprocess.check_output(['git', 'show', f'{commit}:{source}'])
    text = raw.decode('utf-8', errors='strict')
    if not text.endswith('\n'):
        raise SystemExit(f'source lacks final newline: {source}')
    return text

def source_target_exists(path):
    check = subprocess.run(
        ['git', 'cat-file', '-e', f'{commit}:{path}'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if check.returncode:
        return False
    return subprocess.check_output(['git', 'cat-file', '-t', f'{commit}:{path}'], text=True).strip() == 'blob'

def transform(text, source):
    source_dir = posixpath.dirname(source)
    def replace(match):
        label, raw = match.groups()
        target, *fragment = raw.split('#', 1)
        frag = ('#' + fragment[0]) if fragment else ''
        parts = urlsplit(target)
        if parts.scheme or parts.netloc:
            if parts.scheme.lower() == 'file' or parts.username or parts.password:
                raise SystemExit(f'unsafe URL in {source}: {target}')
            return match.group(0)
        if target.startswith('/'):
            raise SystemExit(f'absolute link in {source}: {target}')
        normalized = posixpath.normpath(posixpath.join(source_dir, target))
        if normalized == '..' or normalized.startswith('../'):
            raise SystemExit(f'escaping link in {source}: {target}')
        if normalized in pages:
            return f'{label}({pages[normalized]}{frag})'
        if not source_target_exists(normalized):
            raise SystemExit(f'unknown SOURCE_COMMIT target in {source}: {target}')
        repo_path = PurePosixPath(normalized).as_posix()
        return f'{label}(https://github.com/H234598/codex-master/blob/{commit}/{repo_path}{frag})'
    result = link.sub(replace, text)
    if secret.search(result) or home_path.search(result) or re.search(r'(?i)file\s*:', result):
        raise SystemExit(f'sensitive content in {source}')
    return result

for source, destination, _ in mapping:
    output = transform(read_source(source), source).encode('utf-8', errors='strict')
    with open(os.path.join(stage, destination), 'wb') as handle:
        handle.write(output)
if {name for name in os.listdir(stage)} != destinations:
    raise SystemExit('staging output is not exactly the six mapped files')
PY

# Preflight is fail-closed and does not mutate the source worktree.
test "$(git config --get remote.origin.url)" = 'https://github.com/H234598/codex-master.git'
for p in docs/wiki/Architecture.md docs/wiki/Recovery.md docs/wiki/Resolver.md docs/wiki/Control-Plane.md docs/wiki/Runbook.md docs/wiki/Home.md; do
    git cat-file -e "$SOURCE_COMMIT:$p"
done
test "$(python3 -c 'import os; print(sorted(os.listdir(os.environ["STAGE_DIR"])))')" = "['Architecture.md', 'Control-Plane.md', 'Home.md', 'Recovery.md', 'Resolver.md', 'Runbook.md']"
python3 - "$STAGE_DIR" <<'PY'
import os
import pathlib
import re
import sys

home_path = re.compile(rb'(?i)(?:^|[^a-z0-9_])/(?:home)/[^/\s]+(?:/|$)')
credential_url = re.compile(rb'(?i)(?:https?|ssh)://[^/\s:@]+(?::[^@/\s]+)?@')
private_key = re.compile(rb'-----BEGIN .*PRIVATE KEY-----')
for path in pathlib.Path(sys.argv[1]).iterdir():
    data = path.read_bytes()
    if home_path.search(data) or re.search(rb'(?i)file\s*:', data) or credential_url.search(data) or private_key.search(data):
        raise SystemExit(f'sensitive staged content: {path.name}')
PY
git diff --check

# WIKI_REMOTE is private Queen input. Credential-bearing HTTP(S) and SSH URLs
# are rejected before clone, case-insensitively and by structured parsing.
test -n "${WIKI_REMOTE:-}" || { echo 'Queen must supply WIKI_REMOTE' >&2; exit 1; }
python3 - "$WIKI_REMOTE" <<'PY'
import sys
import re
from urllib.parse import urlsplit
value = sys.argv[1]
if not value or any(ord(c) < 32 for c in value) or value.startswith('-'):
    raise SystemExit('invalid remote')
p = urlsplit(value)
scheme = p.scheme.lower()
if scheme == 'file' or scheme in {'http', 'https', 'ssh'} and (p.password is not None or (scheme in {'http', 'https'} and p.username is not None)):
    raise SystemExit('credential-bearing or local remote rejected')
if scheme not in {'http', 'https', 'ssh', 'git'}:
    scp = re.fullmatch(r'[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:(?P<path>\S+)', value)
    if not scp or scp.group('path').startswith(('/', '\\')) or re.search(r'(^|[/\\])\.\.?([/\\]|$)', scp.group('path')):
        raise SystemExit('unsupported remote form')
PY
WIKI_DIR=$(mktemp -d)
git clone --quiet "$WIKI_REMOTE" "$WIKI_DIR"

for f in Architecture.md Recovery.md Resolver.md Control-Plane.md Runbook.md Home.md; do
    install -m 0644 "$STAGE_DIR/$f" "$WIKI_DIR/$f"
done
git -C "$WIKI_DIR" diff --check
python3 - "$WIKI_DIR" <<'PY'
import subprocess
import sys

allowed = {'Architecture.md', 'Recovery.md', 'Resolver.md', 'Control-Plane.md', 'Runbook.md', 'Home.md'}
raw = subprocess.check_output(
    ['git', '-C', sys.argv[1], 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--', '.']
)
records = raw.decode('utf-8', errors='strict').split('\0')
for record in records:
    if not record:
        continue
    status, path = record[:2], record[3:]
    if 'R' in status or 'C' in status or path not in allowed:
        raise SystemExit(f'changed path outside exact six-file allowlist: {record!r}')
PY
git -C "$WIKI_DIR" add -- Architecture.md Recovery.md Resolver.md Control-Plane.md Runbook.md Home.md
git -C "$WIKI_DIR" diff --cached --check
if git -C "$WIKI_DIR" diff --cached --quiet; then
    echo 'Wiki already matches staged publication; no commit and no push.'
    exit 0
fi
WIKI_SHORT=$(git rev-parse --short=12 "$SOURCE_COMMIT")
git -C "$WIKI_DIR" commit -m "Publish wiki from $WIKI_SHORT"
git -C "$WIKI_DIR" push

# Complete post-push verification occurs before the cleanup trap removes clones.
WIKI_BRANCH=$(git -C "$WIKI_DIR" symbolic-ref --short HEAD)
LOCAL_HEAD=$(git -C "$WIKI_DIR" rev-parse HEAD)
REMOTE_HEAD=$(git ls-remote "$WIKI_REMOTE" "refs/heads/$WIKI_BRANCH" | awk 'NR == 1 { print $1 }')
test -n "$REMOTE_HEAD" && test "$REMOTE_HEAD" = "$LOCAL_HEAD"
for f in Architecture.md Recovery.md Resolver.md Control-Plane.md Runbook.md Home.md; do cmp -- "$STAGE_DIR/$f" "$WIKI_DIR/$f"; done
for slug in Architecture Recovery Resolver Control-Plane Runbook Home; do
    curl --fail --silent --show-error "https://github.com/H234598/codex-master/wiki/$slug" >/dev/null
done
```

The `status --porcelain` allowlist deliberately sees tracked modifications,
untracked files, and deletions. Any path outside the six mapped names fails
closed. An identical stand exits successfully before commit or push; deletion
cannot be silently ignored because the staged six files are copied first.
The session never enables shell tracing and never echoes a secret.

## Preflight

The session above is the complete preflight gate. It requires a resolvable
immutable commit containing all six sources, the reviewed source origin, exact
six-file staging output, strict UTF-8 and final newlines, commit-only target
checks, transformed-link validation, and `git diff --check`. It never cleans,
resets, stages, or otherwise mutates the source worktree. A failed check stops
before clone or any remote mutation.

## Verify

The publish session performs complete post-push verification before cleanup.
For a later check, the Queen must use a fresh clone so verification does not
depend on removed temporary directories.

```bash
set -euo pipefail
umask 077
VERIFY_DIR=$(mktemp -d); trap 'rm -rf -- "$VERIFY_DIR"' EXIT
python3 - "$WIKI_REMOTE" <<'PY'
import sys
import re
from urllib.parse import urlsplit
p = urlsplit(sys.argv[1]); s = p.scheme.lower()
value = sys.argv[1]
if not value or any(ord(c) < 32 for c in value) or value.startswith('-'): raise SystemExit('unsafe remote')
if s == 'file' or s in {'http','https','ssh'} and (p.password is not None or (s in {'http','https'} and p.username is not None)): raise SystemExit('unsafe remote')
if s not in {'http','https','ssh','git'}:
    scp = re.fullmatch(r'[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:(?P<path>\S+)', value)
    if not scp or scp.group('path').startswith(('/', '\\')) or re.search(r'(^|[/\\])\.\.?([/\\]|$)', scp.group('path')): raise SystemExit('unsupported remote')
PY
git clone --quiet "$WIKI_REMOTE" "$VERIFY_DIR"
branch=$(git -C "$VERIFY_DIR" symbolic-ref --short HEAD)
remote_head=$(git ls-remote "$WIKI_REMOTE" "refs/heads/$branch" | awk 'NR == 1 {print $1}')
test "$remote_head" = "$WIKI_PUBLISH_COMMIT"
test "$(git -C "$VERIFY_DIR" rev-parse HEAD)" = "$remote_head"
for f in Architecture.md Recovery.md Resolver.md Control-Plane.md Runbook.md Home.md; do
    test -f "$VERIFY_DIR/$f"
done
test "$(git -C "$VERIFY_DIR" ls-files -- '*.md' | wc -l)" = 6
for slug in Architecture Recovery Resolver Control-Plane Runbook Home; do
    curl --fail --silent --show-error "https://github.com/H234598/codex-master/wiki/$slug" >/dev/null
done
```

Record `SOURCE_COMMIT`, the Wiki commit, branch, remote head, and verification
timestamp in a future Vault publication record. Public-page verification is
performed only after the remote write and head comparison succeed.

## Rollback

Rollback is Queen-only and uses a fresh clone, shared-history-safe normal push,
and an expected-head check before mutation. It never resets or force-pushes.

```bash
set -euo pipefail
umask 077
ROLLBACK_DIR=$(mktemp -d); trap 'rm -rf -- "$ROLLBACK_DIR"' EXIT
test -n "${WIKI_REMOTE:-}" && test -n "${WIKI_PUBLISH_COMMIT:-}" && test -n "${WIKI_EXPECTED_HEAD:-}"
python3 - "$WIKI_REMOTE" <<'PY'
import sys
import re
from urllib.parse import urlsplit
p = urlsplit(sys.argv[1]); s = p.scheme.lower()
value = sys.argv[1]
if not value or any(ord(c) < 32 for c in value) or value.startswith('-'): raise SystemExit('unsafe remote')
if s == 'file' or s in {'http','https','ssh'} and (p.password is not None or (s in {'http','https'} and p.username is not None)): raise SystemExit('unsafe remote')
if s not in {'http','https','ssh','git'}:
    scp = re.fullmatch(r'[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:(?P<path>\S+)', value)
    if not scp or scp.group('path').startswith(('/', '\\')) or re.search(r'(^|[/\\])\.\.?([/\\]|$)', scp.group('path')): raise SystemExit('unsupported remote')
PY
git clone --quiet "$WIKI_REMOTE" "$ROLLBACK_DIR"
branch=$(git -C "$ROLLBACK_DIR" symbolic-ref --short HEAD)
test "$(git ls-remote "$WIKI_REMOTE" "refs/heads/$branch" | awk 'NR == 1 {print $1}')" = "$WIKI_EXPECTED_HEAD"
test "$(git -C "$ROLLBACK_DIR" rev-parse HEAD)" = "$WIKI_EXPECTED_HEAD"
git -C "$ROLLBACK_DIR" cat-file -e "$WIKI_PUBLISH_COMMIT^{commit}"
git -C "$ROLLBACK_DIR" merge-base --is-ancestor "$WIKI_PUBLISH_COMMIT" "$WIKI_EXPECTED_HEAD"
git -C "$ROLLBACK_DIR" revert --no-edit "$WIKI_PUBLISH_COMMIT"
git -C "$ROLLBACK_DIR" push "$WIKI_REMOTE" "$branch"
new_head=$(git -C "$ROLLBACK_DIR" rev-parse HEAD)
test "$(git ls-remote "$WIKI_REMOTE" "refs/heads/$branch" | awk 'NR == 1 { print $1 }')" = "$new_head"
for f in Architecture.md Recovery.md Resolver.md Control-Plane.md Runbook.md Home.md; do test -f "$ROLLBACK_DIR/$f"; done
test "$(git -C "$ROLLBACK_DIR" ls-files -- '*.md' | wc -l)" = 6
```

The fresh-clone head and exact six-file presence are verified after the normal
rollback push. Never rewrite shared Wiki history or use a force push.

## Security, dirty-worktree isolation, and idempotence

All temporary directories use `umask 077`, `mktemp -d`, and one exit/signal
trap that removes both `STAGE_DIR` and `WIKI_DIR` only after the dedicated
session finishes. Secrets and credential-bearing HTTP(S) URLs are excluded;
SSH-agent and credential-helper authentication are permitted. No secret is
echoed and shell tracing is not enabled. Local repository link targets are
validated exclusively with `git cat-file` against `SOURCE_COMMIT`, never with
filesystem existence checks or another worktree check. UTF-8 decoding and encoding are
explicitly strict.

Publication consumes only a Queen-approved immutable commit, so unrelated
dirty-worktree changes cannot enter staging. The same `SOURCE_COMMIT` and Wiki
head produce identical staged bytes and no new commit or push. A changed
approved commit can produce only the exact six-file allowlisted diff. If any
source or local link target is absent from that commit, all work stops before
remote mutation.
