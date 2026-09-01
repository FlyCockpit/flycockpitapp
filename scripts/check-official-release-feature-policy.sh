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
    # Cargo features form a graph, not a flat list. In particular, a feature
    # such as `release-grok = ["grok-subscription"]` can be enabled by a
    # dependency declaration without ever spelling the forbidden feature at
    # the declaration site. Walk that graph for every workspace package.
    #
    # `dep:name` only activates an optional dependency; it cannot select an
    # optional dependency feature, so it has no feature edge of its own.
    # That dependency default feature is checked independently below. `name?/x`
    # is deliberately treated as an edge: although it needs `name` to be
    # enabled elsewhere, it is still a manifest path by which that feature can
    # enter Cargo feature unification.
    def workspace_dependency($packages; $package; $handle):
      $package.dependencies[]
      | select((.rename // .name) == $handle and .path != null)
      | .path as $path
      | $packages[]
      | select(.manifest_path == ($path + "/Cargo.toml"));

    def feature_reference_targets($packages; $package; $reference):
      if ($reference | startswith("dep:")) then
        empty
      elif ($reference | contains("/")) then
        ($reference
          | capture("^(?<dependency>[^/]+?)(?<conditional>\\?)?/(?<feature>.+)$"))
          as $parsed
        | workspace_dependency($packages; $package; $parsed.dependency)
        | { package: ., feature: $parsed.feature }
      else
        { package: $package, feature: ($reference | sub("\\?$"; "")) }
      end;

    def feature_targets($packages; $node):
      ($node.package.features[$node.feature] // [])[]?
      | select(type == "string")
      | feature_reference_targets($packages; $node.package; .);

    def reaches_grok_subscription($packages; $node; $seen):
      ($node.package.manifest_path + "#" + $node.feature) as $key
      | if ($seen | index($key)) then
          false
        elif $node.feature == "grok-subscription" then
          true
        else
          any(
            feature_targets($packages; $node);
            reaches_grok_subscription($packages; .; ($seen + [$key]))
          )
        end;

    def dependency_feature_reaches_grok_subscription(
      $packages; $package; $dependency; $feature
    ):
      if $feature == "grok-subscription" then
        true
      else
        any(
          workspace_dependency($packages; $package; ($dependency.rename // $dependency.name));
          reaches_grok_subscription($packages; { package: ., feature: $feature }; [])
        )
      end;

    .packages as $packages
    | $packages[] as $package
    | (
        if reaches_grok_subscription(
          $packages; { package: $package, feature: "default" }; []
        ) then
          "\($package.name): default feature declaration enables grok-subscription"
        else
          empty
        end
      ),
      (
        $package.dependencies[] as $dependency
        | $dependency.features[]?
        | select(type == "string")
        | select(dependency_feature_reaches_grok_subscription(
            $packages; $package; $dependency; .
          ))
        | "\($package.name): dependency feature declaration for \($dependency.rename // $dependency.name) enables grok-subscription"
      )
  ' <<<"$metadata")"

if [[ -n "$violations" ]]; then
  printf '%s\n' "$violations" >&2
  echo "::error::official release cannot activate grok-subscription through defaults or dependencies" >&2
  exit 1
fi
