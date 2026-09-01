#!/usr/bin/env bash
# Reject source inputs that could enable banned official-release features.
#
# Cargo unifies a dependency's features, so a feature can enter the CLI graph
# through a normal dependency declaration even when the CLI's defaults and
# cargo-dist's arguments are empty. `cargo metadata --no-deps` reads every
# workspace manifest without compiling the workspace.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# A repository Cargo config can set either rustflags or a Cargo environment
# variable that Rust later interprets as `#[cfg(feature = ...)]`. The official
# profile has no legitimate use for this feature in Cargo config, so fail on
# every occurrence rather than trying to parse a flag spelling.
for config in .cargo/config .cargo/config.toml; do
  if [[ -f "$config" ]] && grep -Fn 'grok-subscription' "$config"; then
    echo "::error file=$config::Cargo config enables forbidden official feature grok-subscription" >&2
    exit 1
  fi
done

metadata="$(cargo metadata --locked --no-deps --format-version=1)"
violations="$(jq -r '
    def activates_grok_subscription:
      sub("^dep:"; "") | sub("\\?$"; "") |
      (. == "grok-subscription" or endswith("/grok-subscription"));
    .packages[] |
    .name as $package |
    ((.features["default"] // [])[]? |
      select(type == "string" and activates_grok_subscription) |
      "\($package): default feature declaration enables grok-subscription"),
    (.dependencies[] |
      .name as $dependency |
      (.features[]? |
        select(type == "string" and activates_grok_subscription) |
        "\($package): dependency feature declaration for \($dependency) enables grok-subscription"))
  ' <<<"$metadata")"

if [[ -n "$violations" ]]; then
  printf '%s\n' "$violations" >&2
  echo "::error::official release cannot activate grok-subscription through defaults or dependencies" >&2
  exit 1
fi
