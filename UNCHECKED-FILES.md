# UNCHECKED-FILES — Windows compile-unchecked worklist

Linux-development sessions cannot compile `cfg(windows)` code. Changes below
were validated only by Linux-side reasoning (and `cargo fmt` parsing); they
are compile-unchecked until the Windows runner builds and tests them.
The owner must run the full Rust gates (`cargo fmt --check`,
`cargo nextest run --locked --workspace`,
`cargo clippy --locked --tests -- -D warnings`) on Windows and fix fallout
before merging.

When this worklist is empty again, delete the file.

## issue #283 — Windows `skill_manage` (`issue-283-windows-skill-manage`)

- `crates/cockpit-host/src/private_fs/held_nt.rs` — NEW, `#[cfg(windows)]`
  module behind `private_fs::held_nt`. Raw NT FFI (NtCreateFile /
  NtSetInformationFile / NtQueryDirectoryFile / CreateFileW /
  GetFileInformationByHandle / FlushFileBuffers), relative no-reparse child
  opens, no-follow entry probes, no-replace/replace renames, verified
  disposition deletes, and single-entry enumeration. Includes Windows-only
  unit tests (reparse refusal, rename/delete round-trips, enumeration).
- `crates/cockpit-host/src/private_fs.rs` — module wiring only
  (`#[cfg(windows)] pub mod held_nt;`).
- `crates/cockpit-core/src/skills/manage.rs` — platform seam refactor:
  `SkillComponentBuf` / `PreparedRootCapability` / `DirectoryBinding`
  aliases, shared `PreparedSkillRoot` / `ManagedTarget` bodies over
  cfg-split primitives, new `WindowsPreparedSkillRoot` capability, Windows
  `remove_tree_nofollow`, and `cfg(windows)` reparse-swap tests (these
  build their reparse fixture with `symlink_dir` and fail loudly on hosts
  without the symlink privilege — enable Developer Mode or run as
  administrator). Windows handle-lifecycle discipline: a disposition
  delete completes only when the last handle closes, so
  `ManagedTarget::delete_package` drops every handle to the staged
  package — including the retained prepared pin, released only after all
  identity checks — immediately before the final entry removal, and
  Windows `remove_tree_nofollow` drops each child handle before removing
  the entry. The prepared package is retained as a *live* handle
  (`RetainedPackageIdentity`) on both platforms so the object (and its
  NTFS file index) cannot be deleted and recycled into a lookalike across
  the approval window; `apply_prepared` takes the plan by mutable
  reference so the delete path can consume that pin exactly once. Linux
  behavior is unchanged except: `atomic_write_at`'s destination probe now
  goes through the shared `entry_kind_nofollow` (same fail-closed
  branches), and absent support files/renames report explicit bail
  messages instead of raw `ENOENT`.
- `crates/cockpit-core/src/skills/mod.rs` — `!`-command shell selection:
  `bang_command_invocation` replaces `bang_command_shell`; Windows runs
  the *absolute* `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`
  (an unqualified `powershell` would be resolved through the session cwd /
  PATH before System32 and could be hijacked by workspace content) with
  `-NoProfile -NonInteractive -Command <script>`, an explicit UTF-8
  preamble, and an exit-status ladder (`if ($null -eq $LASTEXITCODE)
  { if ($?) { exit 0 } else { exit 1 } }; exit $LASTEXITCODE`) so a failed
  cmdlet — which never sets `$LASTEXITCODE` — still exits nonzero like
  `sh -c` (owner-adopted design; shell choice is not a config knob).
  C5 scrub seam (`scrub_bang_output`) is platform-shared and unchanged;
  Windows-only scrub and cmdlet-failure tests added.

Windows-runner acceptance for this issue:
`skill_manage` create/delete/remove_file round-trips, the reparse-swap
refusals, `held_nt` unit tests, the PowerShell invocation-shape test, and
the Windows `!`-command scrub tests must all pass. The reparse-swap
refusals and the `held_nt` reparse unit test create real directory
symlinks, so the runner needs the symlink privilege (administrator or
Developer Mode) — they fail loudly, never skip green, without it.
