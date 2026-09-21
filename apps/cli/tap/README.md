# Homebrew tap

This folder documents how the `cockpit` Homebrew formula is published. The
actual tap is the separate GitHub repository:

```text
https://github.com/FlyCockpit/homebrew-tap
```

Users install from that tap with:

```sh
brew install flycockpit/tap/cockpit
```

## One-time setup

1. Keep `FlyCockpit/homebrew-tap` public so Homebrew can clone it without auth.
2. In `FlyCockpit/flycockpitapp`, create a protected `release` environment
   and add an environment secret named `HOMEBREW_TAP_TOKEN`. Use a
   fine-grained GitHub token with `contents:read` access to
   `FlyCockpit/homebrew-tap` so the release workflow can validate the formula.

## Release behavior

The owner publishes the formula in the separate tap. The root `Release CLI`
workflow then uses the protected `release` environment to fail closed unless:

1. `Formula/cockpit.rb` points at the exact release tag.
2. The formula builds from source with `"--features", "no-self-update"`.
3. Validation leaves the tap checkout byte-for-byte unchanged.

Cargo-dist's generated prebuilt-binary formula is not the tap authority because
Homebrew requires self-update to be compiled out. Formula changes are an
owner-only operation in `FlyCockpit/homebrew-tap`; this repository only checks
the release contract. If the tap name changes, update
`tap = "FlyCockpit/homebrew-tap"` in `dist-workspace.toml` and review the root
release workflow.

## How users install

```sh
brew install flycockpit/tap/cockpit
brew upgrade cockpit
```

Private repositories do not work with the one-line `brew install` flow unless
the user has GitHub/Homebrew auth configured. Keep both the source repo and the
tap public for the smooth install path.
