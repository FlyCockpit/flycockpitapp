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
  `remove_tree_nofollow`, and `cfg(windows)` reparse-swap tests. Windows
  handle-lifecycle discipline: a disposition delete completes only when the
  last handle closes, so the prepared package is retained as
  `RetainedPackageIdentity` (volume serial + file index, no live handle)
  and `delete_package` / Windows `remove_tree_nofollow` drop their local
  handles before removing a directory entry. Linux behavior is unchanged
  except: `atomic_write_at`'s destination probe now goes through the shared
  `entry_kind_nofollow` (same fail-closed branches), and absent support
  files/renames report explicit bail messages instead of raw `ENOENT`.
- `crates/cockpit-core/src/skills/mod.rs` — `!`-command shell selection:
  `bang_command_invocation` replaces `bang_command_shell`; Windows now runs
  `powershell -NoProfile -NonInteractive -Command <script>` with an
  explicit UTF-8 preamble and `exit $LASTEXITCODE` (owner-adopted design;
  shell choice is not a config knob). C5 scrub seam (`scrub_bang_output`)
  is platform-shared and unchanged; Windows-only scrub tests added.

Windows-runner acceptance for this issue:
`skill_manage` create/delete/remove_file round-trips, the reparse-swap
refusals, `held_nt` unit tests, the PowerShell invocation-shape test, and
the Windows `!`-command scrub tests must all pass.
