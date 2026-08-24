#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: assemble-linux-containment-bundle.sh TARGET RELEASE_TAG OUTPUT_DIR" >&2
  exit 2
fi

target=$1
release_tag=$2
output_dir=$3
case "$target" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *) echo "unsupported containment bundle target: $target" >&2; exit 2 ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd -P)
binary_root=${FLYCOCKPIT_BUNDLE_BINARY_ROOT:-$repo_root/target}
case "$output_dir" in /*) ;; *) output_dir="$repo_root/$output_dir" ;; esac
stage=$(mktemp -d "${TMPDIR:-/tmp}/flycockpit-containment-bundle.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
payload="$stage/flycockpit-containment-$release_tag-$target"
mkdir -p "$payload/infra/systemd" "$payload/infra/tmpfiles.d" "$output_dir"

install -m 0755 "$binary_root/$target/release/cockpit" "$payload/cockpit"
install -m 0755 "$binary_root/$target/release/cockpit-containment-broker" "$payload/cockpit-containment-broker"
cmp -s "$binary_root/$target/release/cockpit" "$payload/cockpit" \
  || { echo "staged cockpit differs from explicit Cargo output" >&2; exit 1; }
cmp -s "$binary_root/$target/release/cockpit-containment-broker" "$payload/cockpit-containment-broker" \
  || { echo "staged broker differs from explicit Cargo output" >&2; exit 1; }
install -m 0755 "$repo_root/apps/cli/scripts/install-linux-containment-broker.sh" "$payload/install-linux-containment-broker.sh"
install -m 0644 "$repo_root/infra/systemd/cockpit-containment-broker@.service" "$payload/infra/systemd/cockpit-containment-broker@.service"
install -m 0644 "$repo_root/infra/systemd/cockpit-daemon@.service" "$payload/infra/systemd/cockpit-daemon@.service"
install -m 0644 "$repo_root/infra/tmpfiles.d/flycockpit-containment.conf" "$payload/infra/tmpfiles.d/flycockpit-containment.conf"
printf '%s\n' "$target" > "$payload/TARGET"
printf '%s\n' "$release_tag" > "$payload/RELEASE"
chmod 0644 "$payload/TARGET" "$payload/RELEASE"

# Bind every archive member to the exact output of the explicit, same-profile
# Cargo build (or to its reviewed source payload). The outer checksum detects a
# damaged download; this manifest also lets consumers verify the extracted
# bundle before any privileged mutation.
(
  cd "$payload"
  LC_ALL=C find . -type f ! -name MANIFEST.sha256 -print | sed 's#^./##' | sort |
    while IFS= read -r member; do sha256sum "$member"; done > MANIFEST.sha256
)
chmod 0644 "$payload/MANIFEST.sha256"

archive="$output_dir/flycockpit-containment-$release_tag-$target.tar.gz"
tar -C "$stage" -czf "$archive" "$(basename "$payload")"
(cd "$output_dir" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
