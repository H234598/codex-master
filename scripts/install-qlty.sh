#!/usr/bin/env bash
set -eu

TARGET=x86_64-unknown-linux-gnu

for tool in curl gh tar install mktemp sort; do
	command -v "$tool" >/dev/null || {
		printf 'Required command is unavailable: %s\n' "$tool" >&2
		exit 1
	}
done

# Resolve the current stable release only through the official repository API.
RELEASE_TAG="$(gh api repos/qltysh/qlty/releases/latest \
	--jq 'select(.draft == false and .prerelease == false) | .tag_name')"
if [[ ! $RELEASE_TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	printf 'Cannot determine the stable Qlty release. Not installing.\n' >&2
	exit 1
fi
VERSION="${RELEASE_TAG#v}"

# A stale release response must never replace a newer local release.
CURRENT_BIN="$(command -v qlty || true)"
if [ -n "$CURRENT_BIN" ]; then
	CURRENT_VERSION="$("$CURRENT_BIN" --version | awk '{print $2}')"
	if [[ ! $CURRENT_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		printf 'Cannot determine the installed Qlty version. Not installing.\n' >&2
		exit 1
	fi
	NEWEST="$(printf '%s\n%s\n' "$VERSION" "$CURRENT_VERSION" | sort -V | tail -n 1)"
	if [ "$NEWEST" = "$CURRENT_VERSION" ]; then
		"$CURRENT_BIN" --version
		exit 0
	fi
fi

# Work in a new empty directory, so a failed step can't leave
# files from an earlier run behind
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
ARCHIVE="$WORK/qlty-$TARGET.tar.xz"

# Install only if the download, the attestation check and the extraction
# all succeed. This replaces the qlty on your PATH, or installs to
# ~/.qlty/bin if you have none.
if curl -fL "https://github.com/qltysh/qlty/releases/download/v$VERSION/qlty-$TARGET.tar.xz" -o "$ARCHIVE" &&
	gh attestation verify "$ARCHIVE" --repo qltysh/qlty &&
	tar -xJf "$ARCHIVE" -C "$WORK"; then
	DEST="$(dirname "${CURRENT_BIN:-$HOME/.qlty/bin/qlty}")"
	mkdir -p "$DEST"
	install -m 755 "$WORK/qlty-$TARGET/qlty" "$DEST/qlty"
else
	echo "Download, attestation check or extraction failed. Not installing." >&2
	exit 1
fi

# Confirm which qlty runs, and its version
printf '%s\n' "$DEST/qlty"
"$DEST/qlty" --version
