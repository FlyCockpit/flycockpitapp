//! Remote-principal audit upload.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use reqwest::header::RETRY_AFTER;
use reqwest::{Method, StatusCode};
use serde_json::{Map, Value, json};

use crate::auth::flycockpit::StoredFlycockpitCredential;
use crate::daemon::egress::{FirstPartyEgressClient, connector_enabled};
use crate::daemon::server::DaemonContext;
use crate::db::Db;
use crate::db::principals::RemoteAuditRow;

const INGEST_PATH: &str = "/api/relay/audit-ingest";
const MAX_BATCH_EVENTS: usize = 100;
const MAX_BATCH_BYTES: usize = 1024 * 1024;
const MAX_INGEST_ATTEMPTS: usize = 3;
const BACKGROUND_INTERVAL: Duration = Duration::from_secs(60);

pub fn spawn_background(ctx: Arc<DaemonContext>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut wake_rx = ctx.connector_wake_rx();
        loop {
            if ctx.shutdown_signal().is_draining() {
                break;
            }
            let mut wait_for_relogin = false;
            match sync_current_credential_once(&ctx).await {
                Ok(RemoteAuditUploadOnceOutcome::Revoked) => {
                    wait_for_relogin = true;
                    tracing::warn!("remote audit upload stopped until Flycockpit re-login");
                }
                Ok(_) => {}
                Err(error) => {
                    let message = error.to_string();
                    if message.contains("(404)") {
                        tracing::debug!(error = %error, "remote audit upload endpoint unavailable");
                    } else {
                        tracing::warn!(error = %error, "remote audit upload failed");
                    }
                }
            }
            if wait_for_relogin {
                tokio::select! {
                    changed = wake_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                    _ = wait_for_shutdown(ctx.clone()) => break,
                }
            } else {
                tokio::select! {
                    _ = tokio::time::sleep(BACKGROUND_INTERVAL) => {}
                    changed = wake_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                    _ = wait_for_shutdown(ctx.clone()) => break,
                }
            }
        }
    })
}

async fn wait_for_shutdown(ctx: Arc<DaemonContext>) {
    while !ctx.shutdown_signal().is_draining() {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn sync_current_credential_once(
    ctx: &DaemonContext,
) -> Result<RemoteAuditUploadOnceOutcome> {
    let Some(credential) = ctx.load_flycockpit_credential()? else {
        return Ok(RemoteAuditUploadOnceOutcome::NoCredential);
    };
    let db = &ctx.db;
    let Some(client) = FirstPartyEgressClient::connect(db.clone(), credential.clone()).await?
    else {
        return Ok(RemoteAuditUploadOnceOutcome::Disabled);
    };
    let mut sleeper = |duration| -> SleepFuture { Box::pin(tokio::time::sleep(duration)) };
    sync_once_with_client_and_vault(
        db,
        &credential,
        &client,
        &mut sleeper,
        Some(&ctx.secret_vault),
    )
    .await
}

pub type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type SleepFn<'a> = &'a mut (dyn FnMut(Duration) -> SleepFuture + Send);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteAuditUploadOnceOutcome {
    NoCredential,
    Disabled,
    Idle,
    Skipped { cursor_audit_id: i64 },
    Uploaded { events: usize, cursor_audit_id: i64 },
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IngestOutcome {
    Accepted,
    Revoked,
}

async fn post_batch_with_retries(
    client: &FirstPartyEgressClient,
    payload: &Value,
    sleep: SleepFn<'_>,
) -> Result<IngestOutcome> {
    for attempt in 0..MAX_INGEST_ATTEMPTS {
        let resp = client
            .send_json(Method::POST, INGEST_PATH, &[], Some(payload))
            .await?
            .ok_or_else(|| anyhow!("connector disabled before remote audit upload"))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(IngestOutcome::Accepted);
        }
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Ok(IngestOutcome::Revoked);
        }
        let retry_after = resp
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after);
        let body = resp.text().await.unwrap_or_default();
        if is_retryable(status) && attempt + 1 < MAX_INGEST_ATTEMPTS {
            sleep(retry_after.unwrap_or_else(|| backoff_delay(attempt))).await;
            continue;
        }
        return Err(anyhow!(
            "Flycockpit remote audit ingest failed ({status}): {}",
            response_hint(&body)
        ));
    }
    Err(anyhow!("Flycockpit remote audit ingest exhausted retries"))
}

async fn audit_upload_enabled(db: &Db, credential: &StoredFlycockpitCredential) -> Result<bool> {
    connector_enabled(db, credential).await
}

#[allow(dead_code)]
async fn sync_once_with_client(
    db: &Db,
    credential: &StoredFlycockpitCredential,
    client: &FirstPartyEgressClient,
    sleep: SleepFn<'_>,
) -> Result<RemoteAuditUploadOnceOutcome> {
    sync_once_with_client_and_vault(db, credential, client, sleep, None).await
}

async fn sync_once_with_client_and_vault(
    db: &Db,
    credential: &StoredFlycockpitCredential,
    client: &FirstPartyEgressClient,
    sleep: SleepFn<'_>,
    vault: Option<&crate::secure_key::SecretVault>,
) -> Result<RemoteAuditUploadOnceOutcome> {
    if !audit_upload_enabled(db, credential).await? {
        return Ok(RemoteAuditUploadOnceOutcome::Disabled);
    }
    db.upsert_remote_audit_upload_state(&credential.server_url, &credential.instance_id)
        .await?;
    let state = db
        .remote_audit_upload_state(&credential.server_url, &credential.instance_id)
        .await?
        .ok_or_else(|| anyhow!("remote audit upload state missing after upsert"))?;
    let built = match build_batch(db, credential, state.cursor_audit_id, vault).await {
        Ok(built) => built,
        Err(error) => {
            db.update_remote_audit_upload_error(
                &credential.server_url,
                &credential.instance_id,
                &error.to_string(),
            )
            .await?;
            return Err(error);
        }
    };
    match built {
        BatchBuild::Idle => Ok(RemoteAuditUploadOnceOutcome::Idle),
        BatchBuild::Skipped { cursor_audit_id } => {
            db.update_remote_audit_upload_cursor(
                &credential.server_url,
                &credential.instance_id,
                cursor_audit_id,
            )
            .await?;
            Ok(RemoteAuditUploadOnceOutcome::Skipped { cursor_audit_id })
        }
        BatchBuild::Ready {
            payload,
            cursor_audit_id,
            event_count,
        } => {
            let ingest = match post_batch_with_retries(client, &payload, sleep).await {
                Ok(ingest) => ingest,
                Err(error) => {
                    db.update_remote_audit_upload_error(
                        &credential.server_url,
                        &credential.instance_id,
                        &error.to_string(),
                    )
                    .await?;
                    return Err(error);
                }
            };
            match ingest {
                IngestOutcome::Accepted => {
                    db.update_remote_audit_upload_cursor(
                        &credential.server_url,
                        &credential.instance_id,
                        cursor_audit_id,
                    )
                    .await?;
                    Ok(RemoteAuditUploadOnceOutcome::Uploaded {
                        events: event_count,
                        cursor_audit_id,
                    })
                }
                IngestOutcome::Revoked => {
                    db.update_remote_audit_upload_error(
                        &credential.server_url,
                        &credential.instance_id,
                        "Flycockpit instance credential rejected",
                    )
                    .await?;
                    Ok(RemoteAuditUploadOnceOutcome::Revoked)
                }
            }
        }
    }
}

enum BatchBuild {
    Idle,
    Skipped {
        cursor_audit_id: i64,
    },
    Ready {
        payload: Value,
        cursor_audit_id: i64,
        event_count: usize,
    },
}

async fn build_batch(
    db: &Db,
    credential: &StoredFlycockpitCredential,
    cursor_audit_id: i64,
    vault: Option<&crate::secure_key::SecretVault>,
) -> Result<BatchBuild> {
    let rows = db
        .list_remote_audit_after(cursor_audit_id, MAX_BATCH_EVENTS)
        .await?;
    if rows.is_empty() {
        return Ok(BatchBuild::Idle);
    }
    let mut batch_cursor = cursor_audit_id;
    let mut events = Vec::new();
    for row in &rows {
        if row.session_id.is_some() && vault.is_none() {
            tracing::warn!(
                audit_id = row.audit_id,
                "deferring remote audit row until a vault-backed redaction load is available"
            );
            break;
        }
        let event = match audit_event_json(db, credential, row, vault).await {
            Ok(Some(event)) => event,
            Ok(None) => {
                batch_cursor = row.audit_id;
                continue;
            }
            Err(error) if crate::redact::RedactionTableUnavailable::in_chain(&error) => {
                if events.is_empty() {
                    return Err(error);
                }
                tracing::warn!(
                    error = %error,
                    audit_id = row.audit_id,
                    "stopping remote audit batch before a record whose redaction custody cannot be loaded"
                );
                break;
            }
            Err(error) => {
                batch_cursor = row.audit_id;
                tracing::warn!(
                    error = %error,
                    audit_id = row.audit_id,
                    "skipping malformed remote audit row"
                );
                continue;
            }
        };
        let mut candidate_events = events.clone();
        candidate_events.push(event.clone());
        let candidate_payload = audit_payload(credential, candidate_events);
        let candidate_size = serde_json::to_vec(&candidate_payload)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX);
        if candidate_size > MAX_BATCH_BYTES {
            if events.is_empty() {
                batch_cursor = row.audit_id;
                tracing::warn!(
                    audit_id = row.audit_id,
                    "skipping oversized remote audit row"
                );
                continue;
            }
            break;
        }
        events.push(event);
        batch_cursor = row.audit_id;
    }
    if events.is_empty() {
        return Ok(BatchBuild::Skipped {
            cursor_audit_id: batch_cursor,
        });
    }
    let event_count = events.len();
    Ok(BatchBuild::Ready {
        payload: audit_payload(credential, events),
        cursor_audit_id: batch_cursor,
        event_count,
    })
}

fn audit_payload(credential: &StoredFlycockpitCredential, events: Vec<Value>) -> Value {
    json!({
        "instanceId": credential.instance_id,
        "instanceToken": credential.instance_token,
        "events": events,
    })
}

async fn audit_event_json(
    db: &Db,
    credential: &StoredFlycockpitCredential,
    row: &RemoteAuditRow,
    vault: Option<&crate::secure_key::SecretVault>,
) -> Result<Option<Value>> {
    let Some(session_id) = row.session_id else {
        return Ok(None);
    };
    let vault = vault.ok_or_else(|| {
        crate::redact::RedactionTableUnavailable::new(
            "loading session redaction table for first-party egress",
            "vault handle is required",
        )
    })?;
    let redaction = crate::daemon::egress::redaction_for_session(db, vault, session_id).await?;
    let kind = row.request_kind.trim();
    if kind.is_empty() {
        return Err(anyhow!("remote audit kind is empty"));
    }
    if kind.len() > 120 {
        return Err(anyhow!("remote audit kind exceeds endpoint limit"));
    }
    if row.principal.len() > 256 {
        return Err(anyhow!("remote audit principal exceeds endpoint limit"));
    }
    let client_event_id = format!("{}:{}", credential.instance_id, row.audit_id);
    if client_event_id.len() > 160 {
        return Err(anyhow!("remote audit clientEventId exceeds endpoint limit"));
    }

    let mut event = Map::new();
    event.insert("clientEventId".to_string(), Value::String(client_event_id));
    event.insert("kind".to_string(), Value::String(kind.to_string()));
    event.insert(
        "principalTag".to_string(),
        Value::String(row.principal.clone()),
    );
    if let Some(actor_user_id) = actor_user_id(&row.principal)
        && actor_user_id.len() <= 128
    {
        event.insert("actorUserId".to_string(), Value::String(actor_user_id));
    }
    if let Some(session_id) = row.session_id {
        event.insert(
            "sessionId".to_string(),
            Value::String(session_id.to_string()),
        );
    }

    let mut metadata = Map::new();
    metadata.insert("auditId".to_string(), json!(row.audit_id));
    metadata.insert("verdict".to_string(), Value::String(row.verdict.clone()));
    if let Some(path) = row.path.as_deref() {
        metadata.insert("path".to_string(), Value::String(redaction.scrub(path)));
    }
    event.insert("metadata".to_string(), Value::Object(metadata));
    Ok(Some(Value::Object(event)))
}

fn actor_user_id(principal: &str) -> Option<String> {
    principal
        .strip_prefix("flycockpit:")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn is_retryable(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn parse_retry_after(raw: &str) -> Option<Duration> {
    raw.trim().parse::<u64>().ok().map(Duration::from_secs)
}

fn backoff_delay(attempt: usize) -> Duration {
    Duration::from_millis(250 * 2_u64.saturating_pow(attempt as u32))
}

fn response_hint(body: &str) -> String {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return "response was not valid JSON".to_string();
    };
    let Some(obj) = value.as_object() else {
        return "response root was not an object".to_string();
    };
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    format!("JSON object with keys: {}", keys.join(", "))
}

#[cfg(all(test, feature = "remote"))]
mod tests {
    #![allow(deprecated)]

    use super::*;
    use crate::auth::flycockpit::AccountInfo;
    use crate::config::extended::RedactConfig;
    use std::collections::VecDeque;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    fn credential(server_url: String) -> StoredFlycockpitCredential {
        StoredFlycockpitCredential {
            server_url,
            instance_id: "inst-1".to_string(),
            instance_token: "fci_secret_token".to_string(),
            account: AccountInfo {
                user_id: "user-1".to_string(),
                email: "user@example.test".to_string(),
            },
            display_name: Some("Devbox".to_string()),
            relay_choice: None,
        }
    }

    async fn sync_with_responses(
        db: &Db,
        responses: Vec<TestResponse>,
    ) -> (
        RemoteAuditUploadOnceOutcome,
        Vec<String>,
        Vec<Duration>,
        String,
    ) {
        let (server, requests) = start_test_server(responses).await;
        let credential = credential(server.clone());
        db.set_connector_enabled(&server, &credential.instance_id, true)
            .await
            .unwrap();
        let client = FirstPartyEgressClient::connect(db.clone(), credential.clone())
            .await
            .unwrap()
            .unwrap();
        let sleeps = std::sync::Arc::new(Mutex::new(Vec::new()));
        let sleep_log = sleeps.clone();
        let mut sleeper = move |duration| -> SleepFuture {
            let sleep_log = sleep_log.clone();
            Box::pin(async move {
                sleep_log.lock().await.push(duration);
            })
        };
        let vault = crate::secure_key::vault_for_db(db).unwrap();
        let outcome =
            sync_once_with_client_and_vault(db, &credential, &client, &mut sleeper, Some(&vault))
                .await
                .unwrap();
        let requests = requests.lock().await.clone();
        let sleeps = sleeps.lock().await.clone();
        (outcome, requests, sleeps, server)
    }

    async fn insert_remote(db: &Db, kind: &str, path: Option<&str>) -> i64 {
        let session = db
            .write(|conn| {
                crate::db::Db::insert_session_row_conn(
                    conn,
                    &crate::db::Db::build_new_session_row_conn(
                        conn,
                        "project",
                        "/tmp/project",
                        "Build",
                    )?,
                )
            })
            .await
            .unwrap();
        crate::session::lifecycle::write_redaction_table_json_to_vault(
            db,
            session.session_id,
            &crate::redact::RedactionTable::empty()
                .to_persisted_json()
                .unwrap(),
        )
        .unwrap();
        db.insert_remote_audit_with_path(
            "flycockpit:user-1",
            kind,
            Some(session.session_id),
            "allowed",
            path,
        )
        .await
        .unwrap();
        db.list_remote_audit_after(0, 10_000)
            .await
            .unwrap()
            .last()
            .unwrap()
            .audit_id
    }

    #[tokio::test]
    async fn upload_success_advances_cursor_and_uses_bare_rest_body() {
        let db = Db::open_in_memory().unwrap();
        let audit_id = insert_remote(&db, "send_user_message", None).await;
        let (outcome, requests, _, server) = sync_with_responses(
            &db,
            vec![response(
                200,
                r#"{"ok":true,"result":{"received":1,"ingested":1}}"#,
            )],
        )
        .await;
        assert_eq!(
            outcome,
            RemoteAuditUploadOnceOutcome::Uploaded {
                events: 1,
                cursor_audit_id: audit_id
            }
        );
        let state = db
            .remote_audit_upload_state(&server, "inst-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.cursor_audit_id, audit_id);
        let request = requests.iter().find(|r| r.starts_with("POST ")).unwrap();
        assert!(request.starts_with("POST /api/relay/audit-ingest HTTP/1.1"));
        assert!(request.contains(r#""instanceId":"inst-1""#));
        assert!(request.contains(r#""instanceToken":"fci_secret_token""#));
        assert!(request.contains(&format!(r#""clientEventId":"inst-1:{audit_id}""#)));
        assert!(request.contains(r#""kind":"send_user_message""#));
        assert!(!request.contains(r#""json""#));
        assert!(!request.contains(r#""occurredAt""#));
    }

    #[tokio::test]
    async fn server_error_does_not_advance_cursor() {
        let db = Db::open_in_memory().unwrap();
        insert_remote(&db, "send_user_message", None).await;
        let (server, _requests) = start_test_server(vec![
            response(500, r#"{"error":"retry"}"#),
            response(500, r#"{"error":"retry"}"#),
            response(500, r#"{"error":"retry"}"#),
        ])
        .await;
        let credential = credential(server.clone());
        db.set_connector_enabled(&server, &credential.instance_id, true)
            .await
            .unwrap();
        let client = FirstPartyEgressClient::connect(db.clone(), credential.clone())
            .await
            .unwrap()
            .unwrap();
        let mut sleeper = |_duration| -> SleepFuture { Box::pin(async {}) };
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let error =
            sync_once_with_client_and_vault(&db, &credential, &client, &mut sleeper, Some(&vault))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("remote audit ingest failed"));
        let state = db
            .remote_audit_upload_state(&server, "inst-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.cursor_audit_id, 0);
        assert!(state.last_error.is_some());
    }

    #[tokio::test]
    async fn revocation_does_not_advance_cursor() {
        let db = Db::open_in_memory().unwrap();
        insert_remote(&db, "send_user_message", None).await;
        let (outcome, _, _, server) =
            sync_with_responses(&db, vec![response(403, r#"{"error":"revoked"}"#)]).await;
        assert_eq!(outcome, RemoteAuditUploadOnceOutcome::Revoked);
        let state = db
            .remote_audit_upload_state(&server, "inst-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.cursor_audit_id, 0);
    }

    #[tokio::test]
    async fn batch_event_cap_is_one_hundred() {
        let db = Db::open_in_memory().unwrap();
        for _ in 0..101 {
            insert_remote(&db, "fs_write", None).await;
        }
        let credential = credential("http://127.0.0.1:1".to_string());
        let rows = db.list_remote_audit_after(0, 101).await.unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let built = build_batch(&db, &credential, 0, Some(&vault))
            .await
            .unwrap();
        match built {
            BatchBuild::Ready {
                payload,
                cursor_audit_id,
                event_count,
            } => {
                assert_eq!(event_count, 100);
                assert_eq!(cursor_audit_id, rows[99].audit_id);
                assert_eq!(payload["events"].as_array().unwrap().len(), 100);
            }
            BatchBuild::Idle | BatchBuild::Skipped { .. } => panic!("expected ready batch"),
        }
    }

    #[tokio::test]
    async fn redaction_is_applied_to_paths() {
        let db = Db::open_in_memory().unwrap();
        insert_remote(&db, "fs_write", Some("src/project-secret-token.txt")).await;
        let credential = credential("http://127.0.0.1:1".to_string());
        let tmp = tempfile::TempDir::new().unwrap();
        let config = RedactConfig {
            scan_environment: false,
            scan_dotenv: false,
            scan_ssh_keys: false,
            denylist: vec!["project-secret-token".to_string()],
            ..RedactConfig::default()
        };
        let redaction = crate::redact::RedactionTable::build(&config, tmp.path()).unwrap();
        let session_id = db.list_remote_audit_after(0, 1).await.unwrap()[0]
            .session_id
            .unwrap();
        crate::session::lifecycle::write_redaction_table_json_to_vault(
            &db,
            session_id,
            &redaction.to_persisted_json().unwrap(),
        )
        .unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let built = build_batch(&db, &credential, 0, Some(&vault))
            .await
            .unwrap();
        match built {
            BatchBuild::Ready { payload, .. } => {
                let body = payload.to_string();
                assert!(!body.contains("project-secret-token"));
                assert!(body.contains("REDACTED BY COCKPIT"));
            }
            BatchBuild::Idle | BatchBuild::Skipped { .. } => panic!("expected ready batch"),
        }
    }

    #[tokio::test]
    async fn poison_row_is_skipped_and_cursor_advances() {
        let db = Db::open_in_memory().unwrap();
        let audit_id = insert_remote(&db, "", None).await;
        let credential = credential("http://127.0.0.1:1".to_string());
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let built = build_batch(&db, &credential, 0, Some(&vault))
            .await
            .unwrap();
        match built {
            BatchBuild::Skipped { cursor_audit_id } => assert_eq!(cursor_audit_id, audit_id),
            BatchBuild::Idle | BatchBuild::Ready { .. } => panic!("expected skipped row"),
        }
    }

    #[tokio::test]
    async fn vault_less_load_defers_without_advancing_cursor() {
        let db = Db::open_in_memory().unwrap();
        insert_remote(&db, "send_user_message", None).await;
        let credential = credential("http://127.0.0.1:1".to_string());
        let built = build_batch(&db, &credential, 0, None).await.unwrap();
        match built {
            BatchBuild::Idle => {}
            BatchBuild::Skipped { cursor_audit_id } => assert_eq!(
                cursor_audit_id, 0,
                "vault-less load must not advance past unread vault-backed rows"
            ),
            BatchBuild::Ready { event_count, .. } => {
                panic!("vault-less load must defer vault-backed rows, got {event_count} events")
            }
        }
    }

    #[tokio::test]
    async fn missing_redaction_table_fails_closed_without_advancing_cursor() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/tmp/project", "Build")
            .await
            .unwrap();
        db.insert_remote_audit_with_path(
            "flycockpit:user-1",
            "send_user_message",
            Some(session.session_id),
            "allowed",
            None,
        )
        .await
        .unwrap();
        let (server, requests) = start_test_server(vec![response(
            200,
            r#"{"ok":true,"result":{"received":1,"ingested":1}}"#,
        )])
        .await;
        let credential = credential(server.clone());
        db.set_connector_enabled(&server, &credential.instance_id, true)
            .await
            .unwrap();
        let client = FirstPartyEgressClient::connect(db.clone(), credential.clone())
            .await
            .unwrap()
            .unwrap();
        let mut sleeper = |_duration| -> SleepFuture { Box::pin(async {}) };
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let error =
            sync_once_with_client_and_vault(&db, &credential, &client, &mut sleeper, Some(&vault))
                .await
                .expect_err("missing custody must fail the batch");
        let message = format!("{error:#}");
        assert!(
            crate::redact::RedactionTableUnavailable::in_chain(&error),
            "missing table must be a typed redaction failure: {message}"
        );
        assert!(
            message.contains("refusing to proceed unredacted"),
            "visible fail-closed signal missing: {message}"
        );
        let state = db
            .remote_audit_upload_state(&server, "inst-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            state.cursor_audit_id, 0,
            "cursor must not skip a custody failure"
        );
        assert!(
            state
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("refusing to proceed unredacted")),
            "custody failure must be acknowledged: {:?}",
            state.last_error
        );
        assert!(
            !requests
                .lock()
                .await
                .iter()
                .any(|request| request.starts_with("POST ")),
            "plaintext must not be transmitted"
        );
    }

    #[tokio::test]
    async fn unreadable_redaction_table_fails_closed_instead_of_skipping() {
        let db = Db::open_in_memory().unwrap();
        insert_remote(&db, "send_user_message", None).await;
        let session_id = db.list_remote_audit_after(0, 1).await.unwrap()[0]
            .session_id
            .unwrap();
        crate::secure_key::tamper_item_ciphertext(
            &db,
            cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
            &crate::secure_key::redaction_table_item_id(&session_id.to_string()),
            |ciphertext| ciphertext[0] ^= 0xff,
        )
        .unwrap();
        let credential = credential("http://127.0.0.1:1".to_string());
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let error = build_batch(&db, &credential, 0, Some(&vault))
            .await
            .expect_err("unreadable table must fail the batch");
        assert!(
            crate::redact::RedactionTableUnavailable::in_chain(&error),
            "unreadable table must be a typed redaction failure: {error:#}"
        );
    }

    #[tokio::test]
    async fn upload_gate_requires_connect_enabled() {
        let db = Db::open_in_memory().unwrap();
        let credential = credential("https://app.example.test".to_string());
        assert!(!audit_upload_enabled(&db, &credential).await.unwrap());
        db.set_connector_enabled(&credential.server_url, &credential.instance_id, false)
            .await
            .unwrap();
        assert!(!audit_upload_enabled(&db, &credential).await.unwrap());
        db.set_connector_enabled(&credential.server_url, &credential.instance_id, true)
            .await
            .unwrap();
        assert!(audit_upload_enabled(&db, &credential).await.unwrap());
    }

    #[derive(Clone)]
    struct TestResponse {
        status: u16,
        body: String,
        headers: Vec<(String, String)>,
    }

    fn response(status: u16, body: impl Into<String>) -> TestResponse {
        TestResponse {
            status,
            body: body.into(),
            headers: Vec::new(),
        }
    }

    #[allow(dead_code)]
    fn response_with_headers(
        status: u16,
        body: impl Into<String>,
        headers: Vec<(&str, &str)>,
    ) -> TestResponse {
        TestResponse {
            status,
            body: body.into(),
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        }
    }

    async fn start_test_server(
        responses: Vec<TestResponse>,
    ) -> (String, std::sync::Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let request_log = requests.clone();
        let responses = std::sync::Arc::new(Mutex::new(VecDeque::from(responses)));
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let request_log = request_log.clone();
                let responses = responses.clone();
                tokio::spawn(async move {
                    let request = read_request(&mut stream).await;
                    request_log.lock().await.push(request);
                    let response = responses
                        .lock()
                        .await
                        .pop_front()
                        .unwrap_or_else(|| response(500, r#"{"error":"unexpected"}"#));
                    let status_text = if response.status == 200 {
                        "OK"
                    } else {
                        "ERROR"
                    };
                    let mut raw = format!(
                        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                        response.status,
                        status_text,
                        response.body.len()
                    );
                    for (name, value) in response.headers {
                        raw.push_str(&format!("{name}: {value}\r\n"));
                    }
                    raw.push_str("\r\n");
                    raw.push_str(&response.body);
                    let _ = stream.write_all(raw.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        (format!("http://{addr}"), requests)
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut tmp = [0_u8; 1024];
        loop {
            let n = stream.read(&mut tmp).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(header_end) = find_subsequence(&buf, b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buf[..header_end + 4]).to_string();
                let content_len = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .or_else(|| line.strip_prefix("Content-Length:"))
                            .and_then(|s| s.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + 4 + content_len {
                    let n = stream.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                break;
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }
}
