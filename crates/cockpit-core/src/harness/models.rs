//! Live model-list probe for a harness (implementation note
//! §4 — hybrid static + probe).
//!
//! When a harness config carries `model_list_args`, the list tool's
//! `refresh` path runs `command model_list_args`, parses stdout as one
//! model identifier per line, and the caller caches the result back into
//! the harness's static `models` list. When `model_list_args` is empty
//! (the harness can't list models), the caller falls back to the static
//! list silently.

use std::path::Path;
use std::time::Duration;

use crate::config::extended::HarnessConfig;
use crate::harness::env::harness_child_env;

/// Timeout for a model-list probe. Listing models is a quick metadata
/// call; bound it so a hung CLI can't wedge the refresh.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Probe `cfg`'s live model list by running `command model_list_args` in
/// `cwd`. Returns the parsed model identifiers (one per non-empty stdout
/// line, deduped, order-preserving). `None` when the harness has no
/// `model_list_args`, the command fails to spawn, exits non-zero, or times
/// out — the caller then keeps the static list.
pub async fn probe_models(
    cfg: &HarnessConfig,
    cwd: &Path,
    session_overlay: Option<&std::collections::HashMap<String, String>>,
) -> Option<Vec<String>> {
    if cfg.model_list_args.is_empty() {
        return None;
    }
    let mut cmd = tokio::process::Command::new(&cfg.command);
    cmd.args(&cfg.model_list_args)
        .current_dir(cwd)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    for (key, value) in harness_child_env(cfg, session_overlay) {
        cmd.env(key, value);
    }
    let out = tokio::time::timeout(PROBE_TIMEOUT, cmd.output())
        .await
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let models = parse_model_lines(&stdout);
    if models.is_empty() {
        None
    } else {
        Some(models)
    }
}

/// Parse a model-list command's stdout into model identifiers: trim each
/// line, drop empties and obvious header/blank noise, dedupe preserving
/// order. Kept lenient — different harnesses format slightly differently,
/// but all the verified ones (opencode, codex `debug models`) emit one id
/// per line.
fn parse_model_lines(stdout: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in stdout.lines() {
        let m = line.trim();
        if m.is_empty() {
            continue;
        }
        // Skip lines that are plainly not a model id (whitespace-broken
        // prose). A model id is a single token possibly containing
        // `/`, `:`, `.`, `-`.
        if m.split_whitespace().count() != 1 {
            continue;
        }
        if seen.insert(m.to_string()) {
            out.push(m.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extended::{ArgvOverflowBehavior, PromptInputMode};

    fn cfg_with_list_args(args: &[&str]) -> HarnessConfig {
        HarnessConfig {
            command: "sh".to_string(),
            args: vec![],
            prompt_input: PromptInputMode::Stdin,
            argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
            model_args: vec![],
            default_model: None,
            models: vec![],
            model_list_args: args.iter().map(|s| s.to_string()).collect(),
            supports_json_output: false,
            json_output_args: vec![],
            supports_agent_file: false,
            agent_file_args: vec![],
            agent_file_env: None,
            auth_env_vars: vec![],
            auth_probe_args: vec![],
            timeout_secs: 60,
        }
    }

    #[test]
    fn parse_lines_dedupes_and_drops_prose() {
        let out =
            "provider/a\nprovider/b\n\nprovider/a\nsome header line with spaces\nprovider/c\n";
        let got = parse_model_lines(out);
        assert_eq!(got, vec!["provider/a", "provider/b", "provider/c"]);
    }

    #[tokio::test]
    async fn probe_none_when_no_list_args() {
        let mut cfg = cfg_with_list_args(&[]);
        cfg.model_list_args.clear();
        assert!(
            probe_models(&cfg, std::env::temp_dir().as_path(), None)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn probe_parses_stdout_lines() {
        let cfg = cfg_with_list_args(&["-c", "printf 'm/one\\nm/two\\n'"]);
        let got = probe_models(&cfg, std::env::temp_dir().as_path(), None)
            .await
            .unwrap();
        assert_eq!(got, vec!["m/one", "m/two"]);
    }

    #[tokio::test]
    async fn probe_none_on_nonzero_exit() {
        let cfg = cfg_with_list_args(&["-c", "exit 1"]);
        assert!(
            probe_models(&cfg, std::env::temp_dir().as_path(), None)
                .await
                .is_none()
        );
    }
}
