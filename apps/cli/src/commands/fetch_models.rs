//! `cockpit fetch-models` is a daemon request.  The CLI never resolves a
//! credential, probes a provider, or writes a provider config layer.

use anyhow::{Context, Result, bail};
use std::io::{BufRead, IsTerminal, Write};

use crate::cli::FetchModelsArgs;
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{ProviderModelFetchOutcome, Request, Response};

pub async fn run(args: FetchModelsArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("getting cwd")?;
    let provider_id = match (args.provider_arg, args.provider) {
        (Some(_), Some(_)) => {
            bail!("pass provider id once, either positionally or with --provider")
        }
        (Some(provider), None) | (None, Some(provider)) => Some(provider),
        (None, None) => None,
    };
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    // An omitted flag is meaningful: let the daemon preserve the configured
    // policy instead of replacing it with a client-side Keep default.
    let on_unlisted = on_unlisted_policy(args.on_unlisted.as_deref(), interactive)?;
    if args.model.is_some() && !args.deep {
        bail!("--model is only valid with --deep");
    }
    if args.deep && !args.yes {
        if !interactive {
            bail!("deep fetch sends billable probes; rerun with --yes in non-interactive mode");
        }
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut input = stdin.lock();
        let mut output = stdout.lock();
        if !confirm_deep_fetch(&mut input, &mut output)? {
            println!("deep fetch cancelled before sending any probe requests");
            return Ok(());
        }
    }
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for model fetch")?;
    let response = daemon
        .client
        .request(Request::FetchProviderModels {
            project_root: cwd.display().to_string(),
            provider_id,
            model_id: args.model.clone(),
            deep: args.deep,
            on_unlisted,
            allow_fallback: args.allow_fallback,
        })
        .await
        .context("requesting model fetch from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected model fetch request: {error}"))?;
    let Response::ProviderModelsFetched { results, .. } = response else {
        bail!("daemon returned unexpected response to model fetch request: {response:?}");
    };
    if results.is_empty() {
        println!("no providers configured");
        return Ok(());
    }
    let mut failed = 0usize;
    for mut result in results {
        let mut kept_fallback = false;
        if matches!(
            result.outcome,
            ProviderModelFetchOutcome::FallbackAvailable { .. }
        ) && !args.allow_fallback
        {
            let decision = fallback_choice(&result.provider_id)?;
            match decision {
                FallbackChoice::Use => {
                    let retry = daemon
                        .client
                        .request(Request::FetchProviderModels {
                            project_root: cwd.display().to_string(),
                            provider_id: Some(result.provider_id.clone()),
                            model_id: args.model.clone(),
                            deep: args.deep,
                            on_unlisted,
                            allow_fallback: true,
                        })
                        .await
                        .context("retrying model fetch with fallback catalog")?
                        .map_err(|error| {
                            anyhow::anyhow!("daemon rejected fallback model fetch retry: {error}")
                        })?;
                    let Response::ProviderModelsFetched { mut results, .. } = retry else {
                        bail!("daemon returned unexpected response to fallback retry");
                    };
                    if let Some(retry_result) = results.pop() {
                        result = retry_result;
                    }
                }
                FallbackChoice::Cancel => bail!("fetch-models cancelled"),
                FallbackChoice::Keep => kept_fallback = true,
            }
        }
        if is_unlisted_models_prompt(&result.outcome) {
            let decision = unlisted_models_choice(&result.provider_id)?;
            let Some(decision) = decision else {
                bail!("fetch-models cancelled");
            };
            let retry = daemon
                .client
                .request(Request::FetchProviderModels {
                    project_root: cwd.display().to_string(),
                    provider_id: Some(result.provider_id.clone()),
                    model_id: args.model.clone(),
                    deep: args.deep,
                    on_unlisted: Some(decision),
                    allow_fallback: args.allow_fallback,
                })
                .await
                .context("retrying model fetch with selected unlisted-model policy")?
                .map_err(|error| {
                    anyhow::anyhow!("daemon rejected unlisted-model fetch retry: {error}")
                })?;
            let Response::ProviderModelsFetched { mut results, .. } = retry else {
                bail!("daemon returned unexpected response to unlisted-model retry");
            };
            if let Some(retry_result) = results.pop() {
                result = retry_result;
            }
        }
        let line = match result.outcome {
            ProviderModelFetchOutcome::Models { models, .. } => {
                format!(
                    "{}: refreshed {} model(s)",
                    result.provider_id,
                    models.len()
                )
            }
            ProviderModelFetchOutcome::FallbackAvailable { reason, .. } if kept_fallback => {
                format!(
                    "{}: kept existing catalog (fallback available: {reason})",
                    result.provider_id
                )
            }
            ProviderModelFetchOutcome::FallbackAvailable { reason, .. } => {
                failed += 1;
                format!(
                    "{}: fallback catalog available ({reason})",
                    result.provider_id
                )
            }
            ProviderModelFetchOutcome::Unsupported => {
                format!("{}: no published /models endpoint", result.provider_id)
            }
            ProviderModelFetchOutcome::UnlistedModelsPreview { unlisted_count } => {
                failed += 1;
                format!(
                    "{}: {} configured model(s) are absent from the fetched catalog; retry with --on-unlisted=keep or --on-unlisted=remove",
                    result.provider_id, unlisted_count
                )
            }
            ProviderModelFetchOutcome::Error { message } => {
                failed += 1;
                format!("{}: failed: {message}", result.provider_id)
            }
        };
        println!("{line}");
    }
    if failed > 0 {
        bail!("model fetch failed for {failed} provider(s)");
    }
    Ok(())
}

/// Select the policy on the client because `Ask` needs an actual terminal
/// decision after the daemon has discovered the stale models.  Non-interactive
/// invocations are deliberately deterministic: they preserve local models.
fn on_unlisted_policy(
    requested: Option<&str>,
    interactive: bool,
) -> Result<Option<crate::config::providers::OnUnlistedModelsFetch>> {
    use crate::config::providers::OnUnlistedModelsFetch::{Ask, Keep, Remove};

    let policy = match requested {
        Some("keep") => Keep,
        Some("remove") => Remove,
        Some("ask") if interactive => Ask,
        Some("ask") => bail!(
            "--on-unlisted=ask requires an interactive terminal; use --on-unlisted=keep or --on-unlisted=remove"
        ),
        Some(other) => bail!("--on-unlisted must be keep|remove|ask, got `{other}`"),
        None => return Ok(None),
    };
    Ok(Some(policy))
}

fn is_unlisted_models_prompt(outcome: &ProviderModelFetchOutcome) -> bool {
    matches!(
        outcome,
        ProviderModelFetchOutcome::UnlistedModelsPreview { .. }
    )
}

fn unlisted_models_choice(
    provider_id: &str,
) -> Result<Option<crate::config::providers::OnUnlistedModelsFetch>> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if !stdin.is_terminal() || !stdout.is_terminal() {
        // `on_unlisted_policy` prevents this branch for ordinary CLI calls;
        // keep the guard fail-closed if this helper is reused.
        bail!(
            "unlisted models require --on-unlisted=keep or --on-unlisted=remove without a terminal"
        );
    }
    unlisted_models_choice_with_io(provider_id, &mut stdin.lock(), &mut stdout.lock())
}

fn unlisted_models_choice_with_io(
    provider_id: &str,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<Option<crate::config::providers::OnUnlistedModelsFetch>> {
    use crate::config::providers::OnUnlistedModelsFetch::{Keep, Remove};

    writeln!(
        output,
        "`{provider_id}` has configured models absent from its live catalog."
    )?;
    writeln!(output, "  [1] Keep configured models (default)")?;
    writeln!(output, "  [2] Remove unlisted configured models")?;
    writeln!(output, "  [3] Cancel")?;
    write!(output, "Choose 1/2/3: ")?;
    output.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    Ok(match line.trim().to_ascii_lowercase().as_str() {
        "2" | "r" | "remove" => Some(Remove),
        "3" | "c" | "cancel" | "q" | "quit" => None,
        _ => Some(Keep),
    })
}

fn confirm_deep_fetch(input: &mut dyn BufRead, output: &mut dyn Write) -> Result<bool> {
    writeln!(
        output,
        "Deep fetch sends billable probes to each eligible model. Continue? [y/N]"
    )?;
    output.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FallbackChoice {
    Keep,
    Use,
    Cancel,
}

fn fallback_choice(provider_id: &str) -> Result<FallbackChoice> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if !stdin.is_terminal() || !stdout.is_terminal() {
        return Ok(FallbackChoice::Keep);
    }
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    writeln!(output, "`{provider_id}` live model fetch failed.")?;
    writeln!(output, "  [1] Keep existing catalog (default)")?;
    writeln!(output, "  [2] Use fallback catalog")?;
    writeln!(output, "  [3] Cancel")?;
    write!(output, "Choose 1/2/3: ")?;
    output.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    Ok(match line.trim().to_ascii_lowercase().as_str() {
        "2" | "f" | "fallback" | "use" => FallbackChoice::Use,
        "3" | "c" | "cancel" | "q" | "quit" => FallbackChoice::Cancel,
        _ => FallbackChoice::Keep,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::OnUnlistedModelsFetch::{Ask, Keep, Remove};

    #[test]
    fn omitted_unlisted_policy_is_delegated_to_the_daemon() {
        assert_eq!(on_unlisted_policy(None, true).unwrap(), None);
        assert_eq!(on_unlisted_policy(None, false).unwrap(), None);
    }

    #[test]
    fn ask_unlisted_policy_requires_a_terminal() {
        assert_eq!(on_unlisted_policy(Some("ask"), true).unwrap(), Some(Ask));
        let error = on_unlisted_policy(Some("ask"), false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires an interactive terminal")
        );
    }

    #[test]
    fn unlisted_models_prompt_choices_preserve_remove_or_cancel() {
        let mut input = std::io::Cursor::new(b"\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            unlisted_models_choice_with_io("example", &mut input, &mut output).unwrap(),
            Some(Keep)
        );
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("Remove unlisted")
        );

        let mut input = std::io::Cursor::new(b"remove\n".to_vec());
        assert_eq!(
            unlisted_models_choice_with_io("example", &mut input, &mut Vec::new()).unwrap(),
            Some(Remove)
        );
        let mut input = std::io::Cursor::new(b"cancel\n".to_vec());
        assert_eq!(
            unlisted_models_choice_with_io("example", &mut input, &mut Vec::new()).unwrap(),
            None
        );
    }
}
