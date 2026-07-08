use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::credentials::{CredentialStore, default_path};

type RefreshLock = Arc<tokio::sync::Mutex<()>>;
type RefreshLockMap = Mutex<HashMap<&'static str, RefreshLock>>;

static REFRESH_LOCKS: OnceLock<RefreshLockMap> = OnceLock::new();

fn lock_for(key: &'static str) -> Arc<tokio::sync::Mutex<()>> {
    let locks = REFRESH_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = locks.lock().expect("OAuth refresh lock map poisoned");
    locks
        .entry(key)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

#[allow(clippy::too_many_arguments)]
pub async fn credential_with_refresh<
    T,
    Refresh,
    RefreshFuture,
    Missing,
    Terminal,
    TerminalMessage,
>(
    key: &'static str,
    parse_context: &'static str,
    missing_auth_error: Missing,
    needs_refresh: fn(&T, i64) -> bool,
    refresh_token: fn(&T) -> &str,
    merge_refresh: fn(&T, T) -> T,
    refresh: Refresh,
    is_terminal_refresh_error: Terminal,
    terminal_message: TerminalMessage,
) -> Result<T>
where
    T: Clone + DeserializeOwned + Serialize,
    Refresh: Fn(T) -> RefreshFuture,
    RefreshFuture: Future<Output = Result<T>>,
    Missing: Fn() -> anyhow::Error + Copy,
    Terminal: Fn(&anyhow::Error) -> bool,
    TerminalMessage: Fn(anyhow::Error) -> anyhow::Error,
{
    credential_with_refresh_from_path(
        default_path().context("could not locate $HOME for credentials path")?,
        key,
        parse_context,
        missing_auth_error,
        needs_refresh,
        refresh_token,
        merge_refresh,
        refresh,
        is_terminal_refresh_error,
        terminal_message,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn credential_with_refresh_from_path<
    T,
    Refresh,
    RefreshFuture,
    Missing,
    Terminal,
    TerminalMessage,
>(
    path: std::path::PathBuf,
    key: &'static str,
    parse_context: &'static str,
    missing_auth_error: Missing,
    needs_refresh: fn(&T, i64) -> bool,
    refresh_token: fn(&T) -> &str,
    merge_refresh: fn(&T, T) -> T,
    refresh: Refresh,
    is_terminal_refresh_error: Terminal,
    terminal_message: TerminalMessage,
) -> Result<T>
where
    T: Clone + DeserializeOwned + Serialize,
    Refresh: Fn(T) -> RefreshFuture,
    RefreshFuture: Future<Output = Result<T>>,
    Missing: Fn() -> anyhow::Error + Copy,
    Terminal: Fn(&anyhow::Error) -> bool,
    TerminalMessage: Fn(anyhow::Error) -> anyhow::Error,
{
    let tokens = load_tokens(&path, key, parse_context, missing_auth_error)?;
    let now = unix_now();
    if !needs_refresh(&tokens, now) {
        return Ok(tokens);
    }

    let lock = lock_for(key);
    let _guard = lock.lock().await;

    let tokens = load_tokens(&path, key, parse_context, missing_auth_error)?;
    let now = unix_now();
    if !needs_refresh(&tokens, now) {
        return Ok(tokens);
    }

    let attempted_refresh_token = refresh_token(&tokens).to_string();
    match refresh(tokens.clone()).await {
        Ok(fresh) => {
            let latest = load_tokens(&path, key, parse_context, missing_auth_error).ok();
            let previous = latest.as_ref().unwrap_or(&tokens);
            let merged = merge_refresh(previous, fresh);
            let store = CredentialStore::open(path)?;
            store.save_record_merged(key, serde_json::to_value(&merged)?)?;
            Ok(merged)
        }
        Err(e) if is_terminal_refresh_error(&e) => {
            let store = CredentialStore::open(path)?;
            let latest = store
                .get(key)
                .and_then(|raw| serde_json::from_value::<T>(raw.clone()).ok());
            if let Some(latest) = latest
                && refresh_token(&latest) != attempted_refresh_token
            {
                let now = unix_now();
                if !needs_refresh(&latest, now) {
                    return Ok(latest);
                }
                return Err(terminal_message(e));
            }
            store.remove_record_merged(key)?;
            Err(terminal_message(e))
        }
        Err(e) => Err(e),
    }
}

fn load_tokens<T, Missing>(
    path: &std::path::Path,
    key: &str,
    parse_context: &'static str,
    missing_auth_error: Missing,
) -> Result<T>
where
    T: DeserializeOwned,
    Missing: Fn() -> anyhow::Error,
{
    let store = CredentialStore::open(path.to_path_buf())?;
    let raw = store.get(key).ok_or_else(missing_auth_error)?;
    serde_json::from_value(raw.clone()).context(parse_context)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anyhow::anyhow;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestTokens {
        access_token: String,
        refresh_token: String,
        expires_at: i64,
    }

    fn missing() -> anyhow::Error {
        anyhow!("missing")
    }

    fn needs_refresh(tokens: &TestTokens, now: i64) -> bool {
        tokens.expires_at.saturating_sub(now) <= 120
    }

    fn refresh_token(tokens: &TestTokens) -> &str {
        &tokens.refresh_token
    }

    fn merge_refresh(_previous: &TestTokens, fresh: TestTokens) -> TestTokens {
        fresh
    }

    fn is_terminal(error: &anyhow::Error) -> bool {
        error.to_string().contains("invalid_grant")
    }

    fn terminal_message(error: anyhow::Error) -> anyhow::Error {
        anyhow!("{error}; terminal")
    }

    fn write_tokens(path: &std::path::Path, tokens: &TestTokens) {
        let mut store = CredentialStore::open(path.to_path_buf()).unwrap();
        store.set("test-oauth", serde_json::to_value(tokens).unwrap());
        store.save().unwrap();
    }

    #[tokio::test]
    async fn concurrent_refresh_uses_one_post_and_second_task_reads_fresh_disk_state() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        write_tokens(
            &path,
            &TestTokens {
                access_token: "old".into(),
                refresh_token: "refresh-1".into(),
                expires_at: 1,
            },
        );
        let calls = Arc::new(AtomicUsize::new(0));

        let run_one = || {
            let path = path.clone();
            let calls = Arc::clone(&calls);
            async move {
                credential_with_refresh_from_path(
                    path,
                    "test-oauth",
                    "parse test tokens",
                    missing,
                    needs_refresh,
                    refresh_token,
                    merge_refresh,
                    move |_| {
                        let calls = Arc::clone(&calls);
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(TestTokens {
                                access_token: "fresh".into(),
                                refresh_token: "refresh-2".into(),
                                expires_at: unix_now() + 3600,
                            })
                        }
                    },
                    is_terminal,
                    terminal_message,
                )
                .await
            }
        };

        let (first, second) = tokio::join!(run_one(), run_one());

        assert_eq!(first.unwrap().access_token, "fresh");
        assert_eq!(second.unwrap().access_token, "fresh");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fast_path_returns_without_refresh_call() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        write_tokens(
            &path,
            &TestTokens {
                access_token: "current".into(),
                refresh_token: "refresh-1".into(),
                expires_at: unix_now() + 3600,
            },
        );

        let tokens = credential_with_refresh_from_path(
            path,
            "test-oauth",
            "parse test tokens",
            missing,
            needs_refresh,
            refresh_token,
            merge_refresh,
            |_| async { Err(anyhow!("refresh should not run")) },
            is_terminal,
            terminal_message,
        )
        .await
        .unwrap();

        assert_eq!(tokens.access_token, "current");
    }

    #[tokio::test]
    async fn terminal_error_does_not_purge_when_disk_refresh_token_changed() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        write_tokens(
            &path,
            &TestTokens {
                access_token: "old".into(),
                refresh_token: "refresh-1".into(),
                expires_at: 1,
            },
        );
        let path_for_refresh = path.clone();

        let tokens = credential_with_refresh_from_path(
            path.clone(),
            "test-oauth",
            "parse test tokens",
            missing,
            needs_refresh,
            refresh_token,
            merge_refresh,
            move |_| {
                let path_for_refresh = path_for_refresh.clone();
                async move {
                    write_tokens(
                        &path_for_refresh,
                        &TestTokens {
                            access_token: "other-fresh".into(),
                            refresh_token: "refresh-2".into(),
                            expires_at: unix_now() + 3600,
                        },
                    );
                    Err(anyhow!("invalid_grant"))
                }
            },
            is_terminal,
            terminal_message,
        )
        .await
        .unwrap();

        assert_eq!(tokens.access_token, "other-fresh");
        let saved: TestTokens =
            load_tokens(&path, "test-oauth", "parse test tokens", missing).unwrap();
        assert_eq!(saved.refresh_token, "refresh-2");
    }

    #[tokio::test]
    async fn terminal_error_purges_when_disk_refresh_token_still_matches() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        write_tokens(
            &path,
            &TestTokens {
                access_token: "old".into(),
                refresh_token: "refresh-1".into(),
                expires_at: 1,
            },
        );

        let err = credential_with_refresh_from_path(
            path.clone(),
            "test-oauth",
            "parse test tokens",
            missing,
            needs_refresh,
            refresh_token,
            merge_refresh,
            |_| async { Err(anyhow!("invalid_grant")) },
            is_terminal,
            terminal_message,
        )
        .await
        .unwrap_err();

        assert_eq!(err.to_string(), "invalid_grant; terminal");
        let store = CredentialStore::open(path).unwrap();
        assert!(store.get("test-oauth").is_none());
    }
}
