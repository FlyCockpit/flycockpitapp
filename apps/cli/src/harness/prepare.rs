//! Arg-template expansion + prompt-delivery resolution.
//!
//! Turns a [`HarnessConfig`] + a prompt + optional model/agent-file into
//! the concrete argv the spawn path runs, plus a [`PromptDelivery`]
//! describing the side-channel (stdin pipe / temp file / nothing) the
//! spawn path must set up. Honors [`PromptInputMode`] and, for the argv
//! case, [`ArgvOverflowBehavior`].
//!
//! **Redaction note.** This module is pure template mechanics; it never
//! sees an un-scrubbed prompt. The caller ([`crate::harness::run`])
//! scrubs the prompt through [`crate::redact::scrub`] *before* handing it
//! here, so whatever lands in argv / stdin / the temp file is already
//! redacted (GOALS §7 — non-bypassable).

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use tempfile::NamedTempFile;

use crate::config::extended::{ArgvOverflowBehavior, HarnessConfig, PromptInputMode};

const PROMPT_PLACEHOLDER: &str = "{prompt}";
const MODEL_PLACEHOLDER: &str = "{model}";
const AGENT_FILE_PLACEHOLDER: &str = "{agent_file}";

/// Size at which [`PromptInputMode::Argv`] consults
/// [`ArgvOverflowBehavior`]. Linux caps a single argv string at
/// `MAX_ARG_STRLEN` (128 KB) and `execve` returns `E2BIG` past that. Half
/// the limit leaves headroom for the other argv elements and a few KB of
/// env counted against the same ceiling.
pub const ARGV_SPILL_THRESHOLD_BYTES: usize = 64 * 1024;

/// How the prompt will actually reach the child for a specific
/// invocation. Returned by [`prepare_invocation`] so the spawn path knows
/// what side-channel to wire up.
#[derive(Debug)]
pub enum PromptDelivery {
    /// Prompt already lives in `args` — nothing extra at spawn time.
    Argv,
    /// Prompt bytes are piped to the child's stdin, then stdin is closed.
    Stdin(Vec<u8>),
    /// Prompt was written to a temp file whose path is in `args`. The
    /// handle must be held alive until the child exits (drop = cleanup).
    TempFile(NamedTempFile),
}

/// Build the argv + prompt-delivery for one harness invocation.
///
/// `prompt` must already be redacted (see the module note). `model` is
/// the resolved model (the explicit one or the harness default), or
/// `None` to omit the model flag. `agent_file` is an optional
/// system-prompt / agent file path.
pub fn prepare_invocation(
    harness_name: &str,
    cfg: &HarnessConfig,
    prompt: &str,
    model: Option<&str>,
    agent_file: Option<&Path>,
) -> Result<(Vec<String>, PromptDelivery)> {
    reject_leading_dash("prompt", prompt)?;
    if let Some(model) = model {
        reject_leading_dash("model", model)?;
    }

    // Start from the raw args template; resolve `{agent_file}` first so a
    // prompt whose text happens to contain the literal `{agent_file}`
    // token isn't mangled by the removal pass (ralph-rs regression).
    let mut args = cfg.args.clone();
    match agent_file {
        Some(p) if cfg.supports_agent_file => {
            let path_str = p.to_string_lossy().to_string();
            inject_agent_file(cfg, &mut args, &path_str);
        }
        _ => remove_agent_file_args(&mut args),
    }

    // Resolve the effective delivery mode, consulting argv_overflow past
    // the threshold so a bloated prompt doesn't trip E2BIG and a harness
    // with no file/stdin fallback fails loudly instead of being fed a
    // path-as-prompt.
    let mode = match cfg.prompt_input {
        PromptInputMode::Argv if prompt.len() > ARGV_SPILL_THRESHOLD_BYTES => {
            match cfg.argv_overflow {
                ArgvOverflowBehavior::SpillToTempfile => PromptInputMode::Tempfile,
                ArgvOverflowBehavior::SpillToStdin => PromptInputMode::Stdin,
                ArgvOverflowBehavior::Error => {
                    anyhow::bail!(
                        "harness `{harness_name}` accepts prompts only as inline argv text and the \
                         prompt is {bytes} bytes ({kb} KB), past the {limit_kb} KB safety threshold \
                         for the 128 KB argv ceiling; the harness has no file/stdin fallback \
                         (`argv_overflow: error`). Shorten the prompt or use a harness that supports \
                         stdin/file delivery.",
                        bytes = prompt.len(),
                        kb = prompt.len() / 1024,
                        limit_kb = ARGV_SPILL_THRESHOLD_BYTES / 1024,
                    );
                }
            }
        }
        other => other,
    };

    let delivery = match mode {
        PromptInputMode::Stdin => {
            // The prompt rides stdin; strip the placeholder from argv.
            args.retain(|a| !a.contains(PROMPT_PLACEHOLDER));
            PromptDelivery::Stdin(prompt.as_bytes().to_vec())
        }
        PromptInputMode::Tempfile => {
            let mut tmp = NamedTempFile::new().context("creating prompt temp file")?;
            tmp.write_all(prompt.as_bytes())
                .context("writing prompt to temp file")?;
            tmp.flush().context("flushing prompt temp file")?;
            let path_str = tmp.path().to_string_lossy().to_string();
            substitute_or_append(&mut args, PROMPT_PLACEHOLDER, &path_str);
            PromptDelivery::TempFile(tmp)
        }
        PromptInputMode::Argv => {
            substitute_prompt(&mut args, prompt);
            PromptDelivery::Argv
        }
    };

    append_model_and_json_args(&mut args, cfg, model);
    Ok((args, delivery))
}

/// Replace every `placeholder` occurrence in `args` with `value`; if no
/// arg carries the placeholder, append `value` as the trailing positional.
fn substitute_or_append(args: &mut Vec<String>, placeholder: &str, value: &str) {
    let has = args.iter().any(|a| a.contains(placeholder));
    if has {
        for a in args.iter_mut() {
            if a.contains(placeholder) {
                *a = a.replace(placeholder, value);
            }
        }
    } else {
        args.push(value.to_string());
    }
}

fn substitute_prompt(args: &mut Vec<String>, prompt: &str) {
    let has = args.iter().any(|a| a.contains(PROMPT_PLACEHOLDER));
    if has {
        substitute_or_append(args, PROMPT_PLACEHOLDER, prompt);
    } else {
        args.push("--".to_string());
        args.push(prompt.to_string());
    }
}

fn reject_leading_dash(label: &str, value: &str) -> Result<()> {
    if value.starts_with('-') {
        anyhow::bail!("refusing {label} that starts with `-`");
    }
    Ok(())
}

/// Append the optional model flag and JSON-output flags to `args`.
fn append_model_and_json_args(args: &mut Vec<String>, cfg: &HarnessConfig, model: Option<&str>) {
    if let Some(model) = model
        && !cfg.model_args.is_empty()
    {
        for arg in &cfg.model_args {
            args.push(arg.replace(MODEL_PLACEHOLDER, model));
        }
    }
    if cfg.supports_json_output {
        args.extend(cfg.json_output_args.clone());
    }
}

/// Inject the agent-file path via `{agent_file}` placeholders already in
/// `args`, else via the `agent_file_args` template.
fn inject_agent_file(cfg: &HarnessConfig, args: &mut Vec<String>, agent_path: &str) {
    let has_inline = args.iter().any(|a| a.contains(AGENT_FILE_PLACEHOLDER));
    if has_inline {
        *args = args
            .iter()
            .map(|a| a.replace(AGENT_FILE_PLACEHOLDER, agent_path))
            .collect();
        return;
    }
    for arg in &cfg.agent_file_args {
        args.push(arg.replace(AGENT_FILE_PLACEHOLDER, agent_path));
    }
}

/// Remove `{agent_file}` placeholder tokens and their preceding flag from
/// `args` (the no-agent-file path).
fn remove_agent_file_args(args: &mut Vec<String>) {
    let mut remove = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if arg.contains(AGENT_FILE_PLACEHOLDER) {
            remove.push(i);
            if i > 0 && args[i - 1].starts_with('-') {
                remove.push(i - 1);
            }
        }
    }
    remove.sort_unstable();
    remove.dedup();
    for &idx in remove.iter().rev() {
        args.remove(idx);
    }
}

/// The agent-file env var an invocation must set, when the harness conveys
/// the agent file via env rather than a flag (e.g. goose). `None` when the
/// harness uses a native flag or no agent file is supplied.
pub fn agent_file_env(cfg: &HarnessConfig, agent_file: Option<&Path>) -> Option<(String, String)> {
    match (&cfg.agent_file_env, agent_file) {
        (Some(var), Some(path)) if !cfg.supports_agent_file => {
            Some((var.clone(), path.to_string_lossy().to_string()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hc(mode: PromptInputMode, args: &[&str]) -> HarnessConfig {
        HarnessConfig {
            command: "test".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            prompt_input: mode,
            argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
            model_args: vec![],
            default_model: None,
            models: vec![],
            model_list_args: vec![],
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
    fn stdin_mode_strips_placeholder_and_returns_bytes() {
        let c = hc(PromptInputMode::Stdin, &["-p", "{prompt}"]);
        let (args, delivery) = prepare_invocation("t", &c, "hello", None, None).unwrap();
        assert_eq!(args, vec!["-p".to_string()]);
        match delivery {
            PromptDelivery::Stdin(b) => assert_eq!(b, b"hello"),
            other => panic!("expected stdin, got {other:?}"),
        }
    }

    #[test]
    fn argv_mode_under_threshold_inlines() {
        let c = hc(PromptInputMode::Argv, &["-p", "{prompt}"]);
        let (args, delivery) = prepare_invocation("t", &c, "short", None, None).unwrap();
        assert_eq!(args, vec!["-p".to_string(), "short".to_string()]);
        assert!(matches!(delivery, PromptDelivery::Argv));
    }

    #[test]
    fn argv_mode_appends_when_no_placeholder() {
        let c = hc(PromptInputMode::Argv, &["run"]);
        let (args, _) = prepare_invocation("t", &c, "do it", None, None).unwrap();
        assert_eq!(
            args,
            vec!["run".to_string(), "--".to_string(), "do it".to_string()]
        );
    }

    #[test]
    fn argv_mode_rejects_leading_dash_prompt() {
        let c = hc(PromptInputMode::Argv, &["run"]);
        let err = prepare_invocation("t", &c, "--foo", None, None).unwrap_err();
        assert!(format!("{err}").contains("prompt"));
    }

    #[test]
    fn model_value_rejects_leading_dash() {
        let mut c = hc(PromptInputMode::Stdin, &[]);
        c.model_args = vec!["--model".to_string(), "{model}".to_string()];
        let err = prepare_invocation("t", &c, "p", Some("--model"), None).unwrap_err();
        assert!(format!("{err}").contains("model"));
    }

    #[test]
    fn argv_overflow_spill_to_tempfile() {
        let c = hc(PromptInputMode::Argv, &["-p", "{prompt}"]);
        let big = "x".repeat(100 * 1024);
        let (args, delivery) = prepare_invocation("t", &c, &big, None, None).unwrap();
        assert!(!args.iter().any(|a| a.len() > ARGV_SPILL_THRESHOLD_BYTES));
        let tmp = match delivery {
            PromptDelivery::TempFile(t) => t,
            other => panic!("expected tempfile, got {other:?}"),
        };
        assert_eq!(
            args,
            vec!["-p".to_string(), tmp.path().to_string_lossy().to_string()]
        );
        assert_eq!(std::fs::read_to_string(tmp.path()).unwrap(), big);
    }

    #[test]
    fn argv_overflow_error_aborts() {
        let mut c = hc(PromptInputMode::Argv, &["-p", "{prompt}"]);
        c.argv_overflow = ArgvOverflowBehavior::Error;
        let big = "x".repeat(100 * 1024);
        let err = prepare_invocation("copilot", &c, &big, None, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("copilot"), "{msg}");
        assert!(msg.contains("inline argv"), "{msg}");
    }

    #[test]
    fn argv_overflow_spill_to_stdin() {
        let mut c = hc(PromptInputMode::Argv, &["-p", "{prompt}"]);
        c.argv_overflow = ArgvOverflowBehavior::SpillToStdin;
        let big = "y".repeat(100 * 1024);
        let (args, delivery) = prepare_invocation("t", &c, &big, None, None).unwrap();
        assert!(!args.iter().any(|a| a.contains("{prompt}")));
        match delivery {
            PromptDelivery::Stdin(b) => assert_eq!(b.len(), big.len()),
            other => panic!("expected stdin, got {other:?}"),
        }
    }

    #[test]
    fn tempfile_mode_writes_and_substitutes_path() {
        let c = hc(
            PromptInputMode::Tempfile,
            &["--prompt-file", "{prompt}", "--silent"],
        );
        let (args, delivery) = prepare_invocation("t", &c, "body", None, None).unwrap();
        let tmp = match delivery {
            PromptDelivery::TempFile(t) => t,
            other => panic!("expected tempfile, got {other:?}"),
        };
        assert_eq!(args[0], "--prompt-file");
        assert_eq!(args[1], tmp.path().to_string_lossy());
        assert_eq!(args[2], "--silent");
        assert_eq!(std::fs::read_to_string(tmp.path()).unwrap(), "body");
    }

    #[test]
    fn model_flag_appended_when_model_args_present() {
        let mut c = hc(PromptInputMode::Stdin, &[]);
        c.model_args = vec!["--model".to_string(), "{model}".to_string()];
        let (args, _) = prepare_invocation("t", &c, "p", Some("opus"), None).unwrap();
        assert!(args.windows(2).any(|w| w[0] == "--model" && w[1] == "opus"));
    }

    #[test]
    fn model_flag_omitted_when_no_model_or_no_template() {
        // No model resolved → no flag.
        let mut c = hc(PromptInputMode::Stdin, &[]);
        c.model_args = vec!["--model".to_string(), "{model}".to_string()];
        let (args, _) = prepare_invocation("t", &c, "p", None, None).unwrap();
        assert!(!args.iter().any(|a| a == "--model"));
        // Model resolved but no template → no flag.
        let c2 = hc(PromptInputMode::Stdin, &[]);
        let (args2, _) = prepare_invocation("t", &c2, "p", Some("opus"), None).unwrap();
        assert!(!args2.iter().any(|a| a == "opus"));
    }

    #[test]
    fn json_output_args_appended_when_supported() {
        let mut c = hc(PromptInputMode::Stdin, &["run"]);
        c.supports_json_output = true;
        c.json_output_args = vec!["--format".to_string(), "json".to_string()];
        let (args, _) = prepare_invocation("t", &c, "p", None, None).unwrap();
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--format" && w[1] == "json")
        );
    }

    #[test]
    fn agent_file_injected_via_template() {
        let mut c = hc(PromptInputMode::Stdin, &["-p"]);
        c.supports_agent_file = true;
        c.agent_file_args = vec![
            "--append-system-prompt-file".to_string(),
            "{agent_file}".to_string(),
        ];
        let (args, _) =
            prepare_invocation("claude", &c, "p", None, Some(Path::new("/tmp/a.md"))).unwrap();
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--append-system-prompt-file" && w[1] == "/tmp/a.md")
        );
    }

    #[test]
    fn agent_file_env_for_env_based_harness() {
        let mut c = hc(PromptInputMode::Stdin, &["run"]);
        c.agent_file_env = Some("GOOSE_SYSTEM_PROMPT_FILE_PATH".to_string());
        let env = agent_file_env(&c, Some(Path::new("/tmp/a.md")));
        assert_eq!(
            env,
            Some((
                "GOOSE_SYSTEM_PROMPT_FILE_PATH".to_string(),
                "/tmp/a.md".to_string()
            ))
        );
        // No agent file → no env.
        assert!(agent_file_env(&c, None).is_none());
    }

    #[test]
    fn prompt_containing_agent_file_token_survives() {
        // A prompt mentioning the literal `{agent_file}` token must not be
        // mangled by the no-agent-file removal pass.
        let c = hc(PromptInputMode::Argv, &["-p", "{prompt}"]);
        let prompt = "discuss {agent_file} placeholder";
        let (args, _) = prepare_invocation("t", &c, prompt, None, None).unwrap();
        assert!(args.iter().any(|a| a == prompt));
        assert!(args.iter().any(|a| a == "-p"));
    }

    #[test]
    fn builtin_grok_uses_prompt_file_and_headless_flags() {
        let (_, c) = crate::config::extended::builtin_harness_presets()
            .into_iter()
            .find(|(name, _)| name == "grok")
            .expect("grok preset");
        let (args, delivery) = prepare_invocation(
            "grok",
            &c,
            "short prompt",
            Some("grok-build"),
            Some(Path::new("/tmp/grok-agent.md")),
        )
        .unwrap();
        let tmp = match delivery {
            PromptDelivery::TempFile(t) => t,
            other => panic!("expected tempfile, got {other:?}"),
        };
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--prompt-file" && w[1] == tmp.path().to_string_lossy().as_ref())
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--permission-mode" && w[1] == "bypassPermissions")
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-m" && w[1] == "grok-build")
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--output-format" && w[1] == "json")
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--agent" && w[1] == "/tmp/grok-agent.md")
        );
        assert_eq!(std::fs::read_to_string(tmp.path()).unwrap(), "short prompt");
    }
}
