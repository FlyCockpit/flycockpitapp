use anyhow::{Result, anyhow, bail};

use crate::cli::{ProviderAddArgs, ProviderLogoutArgs, ProvidersCommand, ProvidersUsageArgs};
#[cfg(test)]
use crate::config::providers::{AuthKind, ProviderEntry, ProvidersConfig};
#[cfg(test)]
use crate::credentials::CredentialStore;
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{ProviderUsageAvailabilityView, Request, Response};
#[cfg(test)]
use std::path::Path;

pub async fn run(cmd: ProvidersCommand) -> Result<()> {
    match cmd {
        ProvidersCommand::List => {
            println!("Built-in provider templates (configure with `cockpit provider add`):");
            for t in crate::providers::TEMPLATES {
                println!("  {} — {}", t.id, t.display);
            }
            Ok(())
        }
        ProvidersCommand::Add(args) => add(args).await,
        ProvidersCommand::Logout(args) => logout(args).await,
        ProvidersCommand::Usage(args) => usage(args).await,
    }
}

async fn add(args: ProviderAddArgs) -> Result<()> {
    crate::commands::setup::run_provider_add(args.template).await
}

async fn logout(args: ProviderLogoutArgs) -> Result<()> {
    let project_root = std::env::current_dir()
        .map_err(|error| anyhow!("resolving provider logout workspace: {error}"))?
        .display()
        .to_string();
    let daemon = ensure_persistent_daemon()
        .await
        .map_err(|error| anyhow!("starting persistent daemon for provider logout: {error}"))?;
    let client_operation_id = uuid::Uuid::new_v4().to_string();
    let response = daemon
        .client
        .request(Request::DeleteProviderCredential {
            client_operation_id: client_operation_id.clone(),
            provider_id: args.provider.clone(),
            project_root: Some(project_root.clone()),
        })
        .await
        .map_err(|error| anyhow!("provider logout RPC failed: {error}"))?
        .map_err(|error| anyhow!("daemon rejected provider logout request: {error}"))?;
    match response {
        Response::ProviderCredentialCommitted {
            client_operation_id: returned_operation_id,
            provider_id,
            project_root: Some(returned_root),
            owner_root: Some(owner_root),
            owner_scope,
            consumed_vault_generation,
            result_vault_generation,
            changed: true,
            stored: false,
            ..
        } if returned_operation_id == client_operation_id
            && provider_id == args.provider
            && returned_root == project_root
            && owner_scope == format!("project:{owner_root}")
            && result_vault_generation > consumed_vault_generation
            && result_vault_generation > 0 =>
        {
            println!("signed out `{}`", args.provider)
        }
        Response::ProviderCredentialCommitted {
            client_operation_id: returned_operation_id,
            provider_id,
            project_root: Some(returned_root),
            owner_root: Some(owner_root),
            owner_scope,
            consumed_vault_generation,
            result_vault_generation,
            changed: false,
            stored: false,
            ..
        } if returned_operation_id == client_operation_id
            && provider_id == args.provider
            && returned_root == project_root
            && owner_scope == format!("project:{owner_root}")
            && result_vault_generation == consumed_vault_generation
            && result_vault_generation > 0 =>
        {
            println!("`{}` was already signed out", args.provider)
        }
        other => {
            bail!("daemon returned unexpected response to provider logout request: {other:?}")
        }
    }
    Ok(())
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderLogout {
    SignedOut,
    AlreadySignedOut,
}

#[cfg(test)]
pub(crate) fn logout_configured_provider(
    cfg: &ProvidersConfig,
    provider_id: &str,
    store_path: Option<&Path>,
) -> Result<ProviderLogout> {
    let entry = cfg
        .providers
        .get(provider_id)
        .ok_or_else(|| anyhow!("provider `{provider_id}` is not configured"))?;
    let credential_ref = oauth_credential_ref(provider_id, entry)?;
    let was_present = credential_record_exists(credential_ref, store_path)?;
    match credential_ref {
        crate::auth::xai_oauth::CREDENTIAL_KEY => match store_path {
            Some(path) => crate::auth::xai_oauth::logout_at(Some(path))?,
            None => {
                let mut store = open_store(None)?;
                crate::auth::xai_oauth::logout_in(&mut store)?;
            }
        },
        crate::auth::codex_oauth::CREDENTIAL_KEY => match store_path {
            Some(path) => crate::auth::codex_oauth::logout_at(Some(path))?,
            None => {
                let mut store = open_store(None)?;
                crate::auth::codex_oauth::logout_in(&mut store)?;
            }
        },
        other => {
            let mut store = open_store(store_path)?;
            store.remove(other);
            store.save()?;
        }
    }
    Ok(if was_present {
        ProviderLogout::SignedOut
    } else {
        ProviderLogout::AlreadySignedOut
    })
}

#[cfg(test)]
fn oauth_credential_ref<'a>(provider_id: &str, entry: &'a ProviderEntry) -> Result<&'a str> {
    if entry.auth != Some(AuthKind::OAuth) {
        bail!("provider `{provider_id}` is not an OAuth provider");
    }
    entry
        .credential_ref
        .as_deref()
        .ok_or_else(|| anyhow!("OAuth provider `{provider_id}` has no credential_ref"))
}

#[cfg(test)]
fn credential_record_exists(credential_ref: &str, store_path: Option<&Path>) -> Result<bool> {
    Ok(open_store(store_path)?.get(credential_ref).is_some())
}

#[cfg(test)]
fn open_store(store_path: Option<&Path>) -> Result<CredentialStore> {
    if let Some(path) = store_path {
        #[cfg(test)]
        {
            return CredentialStore::open(path.to_path_buf());
        }
        #[cfg(not(test))]
        {
            let _ = path;
            anyhow::bail!("explicit credential store path is test-only")
        }
    }
    unreachable!("test callers always provide a credential-store path")
}

async fn usage(args: ProvidersUsageArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let daemon = ensure_persistent_daemon()
        .await
        .map_err(|error| anyhow!("starting persistent daemon for provider usage: {error}"))?;
    let response = daemon
        .client
        .request(Request::GetProviderUsageSnapshot {
            project_root: cwd.display().to_string(),
            provider_id: args.provider,
        })
        .await
        .map_err(|error| anyhow!("provider usage RPC failed: {error}"))?
        .map_err(|error| anyhow!("daemon rejected provider usage request: {error}"))?;
    let Response::ProviderUsageSnapshot { snapshots } = response else {
        bail!("daemon returned unexpected response to provider usage request: {response:?}");
    };
    for (idx, row) in snapshots.iter().enumerate() {
        if idx > 0 {
            println!();
        }
        for line in render_provider_usage_wire(row) {
            println!("{line}");
        }
    }
    Ok(())
}

fn render_provider_usage_wire(
    row: &crate::daemon::proto::ProviderUsageSnapshotView,
) -> Vec<String> {
    match &row.availability {
        ProviderUsageAvailabilityView::Fetched {
            plan,
            windows,
            details,
            ..
        } => {
            let mut lines = vec![
                match plan.as_deref().filter(|plan| !plan.trim().is_empty()) {
                    Some(plan) => {
                        format!("{} ({}) — plan: {plan}", row.display_name, row.provider_id)
                    }
                    None => format!("{} ({})", row.display_name, row.provider_id),
                },
            ];
            if windows.is_empty() && details.is_empty() {
                lines.push("  No usage windows returned.".into());
            }
            for window in windows {
                let mut line = format!("  {}: ", window.label);
                match window.used_percent {
                    Some(used) => line.push_str(&format!(
                        "{:.0}% remaining ({:.0}% used)",
                        (100.0 - used.clamp(0.0, 100.0)).max(0.0).round(),
                        used.clamp(0.0, 100.0).round()
                    )),
                    None => line.push_str("usage not reported"),
                }
                if let Some(reset_at) = window.reset_at {
                    line.push_str(&format!("; resets {}", reset_at.to_rfc3339()));
                }
                if let Some(detail) = window
                    .detail
                    .as_deref()
                    .filter(|detail| !detail.trim().is_empty())
                {
                    line.push_str(&format!(" — {detail}"));
                }
                lines.push(line);
            }
            lines.extend(details.iter().map(|detail| format!("  {detail}")));
            lines
        }
        ProviderUsageAvailabilityView::Unsupported { reason } => vec![format!(
            "{} ({}) — unsupported: {reason}",
            row.display_name, row.provider_id
        )],
        ProviderUsageAvailabilityView::Unavailable { reason, hint_url } => vec![format!(
            "{} ({}) — unavailable: {reason}{}",
            row.display_name,
            row.provider_id,
            hint_url
                .as_ref()
                .map(|url| format!(" {url}"))
                .unwrap_or_default()
        )],
        ProviderUsageAvailabilityView::Error { message } => vec![format!(
            "{} ({}) — error: {message}",
            row.display_name, row.provider_id
        )],
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    fn oauth_provider(credential_ref: &str) -> ProviderEntry {
        ProviderEntry {
            url: "https://api.example.test/v1".into(),
            auth: Some(AuthKind::OAuth),
            credential_ref: Some(credential_ref.into()),
            ..Default::default()
        }
    }

    fn api_key_provider() -> ProviderEntry {
        ProviderEntry {
            url: "https://api.example.test/v1".into(),
            auth: Some(AuthKind::ApiKey),
            ..Default::default()
        }
    }

    fn config(entries: impl IntoIterator<Item = (&'static str, ProviderEntry)>) -> ProvidersConfig {
        ProvidersConfig {
            providers: entries
                .into_iter()
                .map(|(id, entry)| (id.to_string(), entry))
                .collect::<BTreeMap<_, _>>(),
            ..Default::default()
        }
    }

    #[test]
    fn provider_logout_preserves_unrelated_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("credentials.json");
        let mut store = CredentialStore::open(store_path.clone()).unwrap();
        store.set(
            crate::auth::xai_oauth::CREDENTIAL_KEY,
            json!({"access_token":"grok","refresh_token":"refresh","expires_at":9_999_999_999i64}),
        );
        store.set(
            crate::auth::codex_oauth::CREDENTIAL_KEY,
            json!({"access_token":"codex","refresh_token":"refresh","expires_at":9_999_999_999i64}),
        );
        #[cfg(feature = "remote")]
        store.set(
            crate::auth::flycockpit::CREDENTIAL_KEY,
            json!({"keep":true}),
        );
        store.save().unwrap();
        let cfg = config([(
            crate::auth::xai_oauth::CREDENTIAL_KEY,
            oauth_provider(crate::auth::xai_oauth::CREDENTIAL_KEY),
        )]);

        assert_eq!(
            logout_configured_provider(
                &cfg,
                crate::auth::xai_oauth::CREDENTIAL_KEY,
                Some(&store_path),
            )
            .unwrap(),
            ProviderLogout::SignedOut
        );

        let store = CredentialStore::open(store_path).unwrap();
        assert!(store.get(crate::auth::xai_oauth::CREDENTIAL_KEY).is_none());
        assert!(
            store
                .get(crate::auth::codex_oauth::CREDENTIAL_KEY)
                .is_some()
        );
        #[cfg(feature = "remote")]
        assert!(store.get(crate::auth::flycockpit::CREDENTIAL_KEY).is_some());
    }

    #[test]
    fn provider_logout_is_idempotent_when_credential_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("credentials.json");
        let cfg = config([(
            crate::auth::codex_oauth::CREDENTIAL_KEY,
            oauth_provider(crate::auth::codex_oauth::CREDENTIAL_KEY),
        )]);

        assert_eq!(
            logout_configured_provider(
                &cfg,
                crate::auth::codex_oauth::CREDENTIAL_KEY,
                Some(&store_path),
            )
            .unwrap(),
            ProviderLogout::AlreadySignedOut
        );
    }

    #[test]
    fn provider_logout_errors_for_non_oauth_provider() {
        let cfg = config([("openai", api_key_provider())]);

        let error = logout_configured_provider(&cfg, "openai", None).unwrap_err();

        assert!(
            error.to_string().contains("is not an OAuth provider"),
            "{error}"
        );
    }
}
