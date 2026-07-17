use std::path::Path;

use anyhow::{Result, anyhow, bail};

use crate::cli::{ProviderAddArgs, ProviderLogoutArgs, ProvidersCommand, ProvidersUsageArgs};
use crate::config::providers::{AuthKind, ProviderEntry, ProvidersConfig};
use crate::credentials::CredentialStore;

pub async fn run(cmd: ProvidersCommand) -> Result<()> {
    match cmd {
        ProvidersCommand::List => {
            println!("API-key provider templates (configure with `cockpit provider add`):");
            for t in crate::providers::TEMPLATES {
                if matches!(t.auth, crate::config::providers::AuthKind::ApiKey) {
                    println!("  {} — {}", t.id, t.display);
                }
            }
            Ok(())
        }
        ProvidersCommand::Add(args) => add(args).await,
        ProvidersCommand::Logout(args) => logout(args),
        ProvidersCommand::Usage(args) => usage(args).await,
    }
}

async fn add(args: ProviderAddArgs) -> Result<()> {
    crate::commands::setup::run_provider_add(args.template).await
}

fn logout(args: ProviderLogoutArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let cfg = crate::secret_ref::load_effective(&cwd);
    match logout_configured_provider(&cfg, &args.provider, None)? {
        ProviderLogout::SignedOut => println!("signed out `{}`", args.provider),
        ProviderLogout::AlreadySignedOut => println!("`{}` was already signed out", args.provider),
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderLogout {
    SignedOut,
    AlreadySignedOut,
}

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
            None => crate::auth::xai_oauth::logout()?,
        },
        crate::auth::codex_oauth::CREDENTIAL_KEY => match store_path {
            Some(path) => crate::auth::codex_oauth::logout_at(Some(path))?,
            None => crate::auth::codex_oauth::logout()?,
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

fn oauth_credential_ref<'a>(provider_id: &str, entry: &'a ProviderEntry) -> Result<&'a str> {
    if entry.auth != Some(AuthKind::OAuth) {
        bail!("provider `{provider_id}` is not an OAuth provider");
    }
    entry
        .credential_ref
        .as_deref()
        .ok_or_else(|| anyhow!("OAuth provider `{provider_id}` has no credential_ref"))
}

fn credential_record_exists(credential_ref: &str, store_path: Option<&Path>) -> Result<bool> {
    Ok(open_store(store_path)?.get(credential_ref).is_some())
}

fn open_store(store_path: Option<&Path>) -> Result<CredentialStore> {
    match store_path {
        Some(path) => CredentialStore::open(path.to_path_buf()),
        None => CredentialStore::open_default(),
    }
}

async fn usage(args: ProvidersUsageArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let cfg = crate::secret_ref::load_effective(&cwd);
    let rows =
        crate::providers::usage::probes::fetch_all_provider_usage(&cfg, args.provider.as_deref())
            .await?;
    for (idx, row) in rows.iter().enumerate() {
        if idx > 0 {
            println!();
        }
        for line in crate::providers::usage::render_usage_lines(row) {
            println!("{line}");
        }
    }
    Ok(())
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
