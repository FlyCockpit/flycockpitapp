//! Project-instructions-file bootstrap shared by every front end.
//!
//! `cockpit init` (the headless subcommand) and the TUI `/init` slash
//! command drive the identical work: resolve the target guidance file for a
//! `cwd`, decide create-vs-update-vs-overwrite, and build the user message
//! that sends the agent exploring before it writes through the normal
//! file-write tool path. None of that is terminal-specific, so it lives
//! here and both surfaces call it — the front ends own only the interaction
//! (argument parsing, confirmation, transcript rendering).
//!
//! Deliberately does **not** touch `config.json` or set up providers:
//! cockpit config is created lazily by the cockpit-specific commands that
//! need it (`cockpit harness add`, `cockpit redact disable`, …).

use std::path::{Path, PathBuf};

/// What the agent should do with the target file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitMode {
    /// The file does not exist yet — write it fresh.
    Create,
    /// The file exists — revise/extend it, preserving useful content.
    Update,
    /// The file exists — replace it from scratch.
    Overwrite,
}

/// Resolve the target instructions file for `/init [path]` at `cwd`.
///
/// - An explicit arg is taken verbatim: absolute paths as-is, relative
///   paths joined under `cwd`.
/// - No arg → the **first configured** guidance filename
///   (`agent_guidance_files[0]`, default `AGENTS.md`) joined under `cwd`
///   — the first *configured* name, not the first that happens to exist.
pub fn resolve_target(cwd: &Path, explicit: Option<&str>) -> PathBuf {
    match explicit.map(str::trim).filter(|s| !s.is_empty()) {
        Some(arg) => {
            let p = Path::new(arg);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                cwd.join(p)
            }
        }
        None => {
            let cfg = crate::config::extended::load_for_cwd(cwd);
            let name = cfg
                .agent_guidance_files
                .first()
                .cloned()
                .unwrap_or_else(|| "AGENTS.md".to_string());
            cwd.join(name)
        }
    }
}

/// The path to show the user / hand the agent: relative to `cwd` when the
/// target lives under it, else the absolute path.
pub fn display_target(cwd: &Path, target: &Path) -> String {
    target
        .strip_prefix(cwd)
        .unwrap_or(target)
        .display()
        .to_string()
}

/// Build the user message that drives the init agent. `target` is the
/// path the file must be written to (as shown to the user); `mode`
/// selects fresh-write vs. revise-in-place vs. overwrite wording. The
/// message instructs the agent to explore first and write through the
/// normal tool path — no canned template — and to leave `config.json`
/// alone.
pub fn build_init_prompt(target: &str, mode: InitMode) -> String {
    let action = match mode {
        InitMode::Create => format!("Write a new project instructions file at `{target}`."),
        InitMode::Update => format!(
            "Update the existing project instructions file at `{target}` in place: \
             revise and extend it, preserving the content that is still accurate."
        ),
        InitMode::Overwrite => format!(
            "Overwrite the project instructions file at `{target}` from scratch, \
             replacing its current content entirely."
        ),
    };
    format!(
        "{action}\n\n\
         First explore this project — its structure, the build/test/lint commands, \
         the languages and frameworks in use, and any conventions a contributor must \
         follow. Then write the file via the normal file-write tool path (delegate to \
         `builder`, the single writer). Keep it concise and genuinely useful: terse, \
         high-signal guidance an agent or new contributor needs, not padding. \
         Do not create or modify `config.json` or any other config file — \
         only the instructions file at `{target}`."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_relative_arg_joins_under_cwd() {
        let cwd = Path::new("/proj");
        let t = resolve_target(cwd, Some("docs/GUIDE.md"));
        assert_eq!(t, Path::new("/proj/docs/GUIDE.md"));
    }

    #[test]
    fn explicit_absolute_arg_taken_verbatim() {
        let cwd = Path::new("/proj");
        let t = resolve_target(cwd, Some("/etc/elsewhere.md"));
        assert_eq!(t, Path::new("/etc/elsewhere.md"));
    }

    #[test]
    fn no_arg_targets_first_configured_name_under_cwd() {
        // No/blank arg → `cwd.join(agent_guidance_files[0])`: the first
        // *configured* name (resolved from layered config for `cwd`), not
        // "first that happens to exist". Pin against the same config the
        // resolver reads so the test is independent of ambient config.
        let cwd = Path::new("/nonexistent-cockpit-init-test-dir");
        let first = crate::config::extended::load_for_cwd(cwd)
            .agent_guidance_files
            .first()
            .cloned()
            .unwrap_or_else(|| "AGENTS.md".to_string());
        assert_eq!(resolve_target(cwd, None), cwd.join(&first));
        assert_eq!(resolve_target(cwd, Some("   ")), cwd.join(&first));
    }

    #[test]
    fn display_target_is_relative_under_cwd() {
        let cwd = Path::new("/proj");
        assert_eq!(display_target(cwd, &cwd.join("AGENTS.md")), "AGENTS.md");
        assert_eq!(display_target(cwd, Path::new("/other/x.md")), "/other/x.md");
    }

    #[test]
    fn prompt_carries_target_mode_and_config_guard() {
        let create = build_init_prompt("AGENTS.md", InitMode::Create);
        assert!(create.contains("AGENTS.md"));
        assert!(create.contains("new project instructions file"));
        // Always forbids touching config + names the single writer.
        assert!(create.contains("config.json"));
        assert!(create.contains("builder"));

        let update = build_init_prompt("AGENTS.md", InitMode::Update);
        assert!(update.contains("in place"));
        let overwrite = build_init_prompt("AGENTS.md", InitMode::Overwrite);
        assert!(overwrite.contains("from scratch"));
    }
}
