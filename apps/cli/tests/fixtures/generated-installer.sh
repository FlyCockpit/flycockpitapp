#!/bin/sh
set -eu

: "${COCKPIT_FIXTURE_ARCHIVE:?}"
: "${COCKPIT_FIXTURE_SHA256:?}"
: "${COCKPIT_FIXTURE_DEST:?}"
: "${COCKPIT_FIXTURE_STAGE_ROOT:?}"

arch=${COCKPIT_FIXTURE_ARCH:-$(uname -m)}
case "$arch" in x86_64|amd64|aarch64|arm64) ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac

stage="$COCKPIT_FIXTURE_STAGE_ROOT/cockpit-installer-$$"
cleanup() { rm -rf "$stage"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$stage/unpack"

actual=$(sha256sum "$COCKPIT_FIXTURE_ARCHIVE" | awk '{print $1}')
[ "$actual" = "$COCKPIT_FIXTURE_SHA256" ] || { echo 'checksum verification failed' >&2; exit 1; }
tar -xzf "$COCKPIT_FIXTURE_ARCHIVE" -C "$stage/unpack" || { echo 'archive extraction failed' >&2; exit 1; }

count=$(find "$stage/unpack" -type f -name cockpit -perm -u+x | wc -l | tr -d ' ')
[ "$count" = 1 ] || { echo 'archive must contain exactly one executable cockpit' >&2; exit 1; }
bin=$(find "$stage/unpack" -type f -name cockpit -perm -u+x)
mkdir -p "$COCKPIT_FIXTURE_DEST"
[ ! -e "$COCKPIT_FIXTURE_DEST/cockpit" ] || { echo 'destination already exists' >&2; exit 1; }
cp "$bin" "$stage/cockpit"
chmod +x "$stage/cockpit"
mv "$stage/cockpit" "$COCKPIT_FIXTURE_DEST/cockpit"

notice=$(find "$stage/unpack" -type f -name runtime-prerequisite-notice.sh | head -n 1)
[ -z "$notice" ] || sh "$notice" || true

