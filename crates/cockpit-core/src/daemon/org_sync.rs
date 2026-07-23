//! Enterprise org-policy session-log sync.
//!
//! This module is daemon-owned by design: it reads already-captured,
//! post-redaction rows from SQLite and never participates in the engine driver
//! hot path.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::header::RETRY_AFTER;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::flycockpit::{StoredFlycockpitCredential, maybe_load_credential};
use crate::config::extended::RedactConfig;
use crate::daemon::server::DaemonContext;
use crate::db::Db;
use crate::db::session_log::SessionEventRow;
use crate::redact::RedactionTable;

const POLICY_PATH: &str = "/api/enterprise/org-policy";
const INGEST_PATH: &str = "/api/enterprise/session-log-sync/ingest";
const MAX_BATCH_EVENTS: usize = 500;
const MAX_BATCH_BYTES: usize = 1024 * 1024;
const MAX_INGEST_ATTEMPTS: usize = 3;
const BACKGROUND_INTERVAL: Duration = Duration::from_secs(60);

pub fn spawn_background(ctx: Arc<DaemonContext>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if ctx.shutdown_signal().is_draining() {
                break;
            }
            if let Err(error) = sync_current_credential_once(&ctx.db).await {
                tracing::warn!(error = %error, "enterprise session-log sync failed");
            }
            tokio::select! {
                _ = tokio::time::sleep(BACKGROUND_INTERVAL) => {}
                _ = wait_for_shutdown(ctx.clone()) => break,
            }
        }
    })
}

async fn wait_for_shutdown(ctx: Arc<DaemonContext>) {
    while !ctx.shutdown_signal().is_draining() {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn sync_current_credential_once(db: &Db) -> Result<OrgSyncOnceOutcome> {
    let Some(credential) = maybe_load_credential() else {
        return Ok(OrgSyncOnceOutcome::NoCredential);
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let redaction = RedactionTable::build(&RedactConfig::default(), &cwd)
        .unwrap_or_else(|_| RedactionTable::empty());
    let client = OrgSyncHttpClient::new(&credential.server_url)?;
    let mut sleeper = |duration| -> SleepFuture { Box::pin(tokio::time::sleep(duration)) };
    sync_once_with_client(db, &credential, &client, &redaction, &mut sleeper).await
}

pub type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type SleepFn<'a> = &'a mut (dyn FnMut(Duration) -> SleepFuture + Send);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgSyncOnceOutcome {
    NoCredential,
    Disabled,
    Idle,
    Filtered { cursor_seq: i64 },
    Uploaded { events: usize, cursor_seq: i64 },
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgLogSyncPolicy {
    pub org_id: String,
    pub policy_version: Option<String>,
    #[serde(default)]
    pub include_event_kinds: Vec<String>,
    #[serde(default)]
    pub exclude_event_kinds: Vec<String>,
    #[serde(default = "default_true")]
    pub include_local_model_transcripts: bool,
    #[serde(default)]
    pub raw: Value,
}

impl OrgLogSyncPolicy {
    fn allows_kind(&self, kind: &str) -> bool {
        if !self.include_event_kinds.is_empty()
            && !self
                .include_event_kinds
                .iter()
                .any(|allowed| allowed == kind)
        {
            return false;
        }
        !self
            .exclude_event_kinds
            .iter()
            .any(|excluded| excluded == kind)
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicyFetchOutcome {
    Active(OrgLogSyncPolicy),
    Disabled,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IngestOutcome {
    Accepted,
    Revoked,
}

#[derive(Clone)]
struct OrgSyncHttpClient {
    http: reqwest::Client,
    server_url: String,
}

impl OrgSyncHttpClient {
    fn new(server_url: &str) -> Result<Self> {
        let server_url = crate::auth::flycockpit::normalize_server_url(server_url)?;
        Ok(Self {
            http: reqwest::Client::new(),
            server_url,
        })
    }

    async fn fetch_policy(
        &self,
        credential: &StoredFlycockpitCredential,
    ) -> Result<PolicyFetchOutcome> {
        let resp = self
            .http
            .get(endpoint(&self.server_url, POLICY_PATH)?)
            .bearer_auth(&credential.instance_token)
            .header("x-flycockpit-instance-id", &credential.instance_id)
            .header("x-csrf-token", crate::auth::flycockpit::CLIENT_ID)
            .send()
            .await
            .context("fetching Flycockpit org policy")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        match status {
            StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => Ok(PolicyFetchOutcome::Disabled),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Ok(PolicyFetchOutcome::Revoked),
            status if status.is_success() => parse_policy(&body),
            _ => Err(anyhow!(
                "Flycockpit org policy request failed ({status}): {}",
                response_hint(&body)
            )),
        }
    }

    async fn post_batch_with_retries(
        &self,
        credential: &StoredFlycockpitCredential,
        policy: &OrgLogSyncPolicy,
        payload: &Value,
        sleep: SleepFn<'_>,
    ) -> Result<IngestOutcome> {
        for attempt in 0..MAX_INGEST_ATTEMPTS {
            let resp = self
                .http
                .post(endpoint(&self.server_url, INGEST_PATH)?)
                .bearer_auth(&credential.instance_token)
                .header("x-flycockpit-instance-id", &credential.instance_id)
                .header("x-flycockpit-org-id", &policy.org_id)
                .header("x-csrf-token", crate::auth::flycockpit::CLIENT_ID)
                .json(payload)
                .send()
                .await
                .context("posting Flycockpit session-log sync batch")?;
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
                "Flycockpit session-log ingest failed ({status}): {}",
                response_hint(&body)
            ));
        }
        Err(anyhow!("Flycockpit session-log ingest exhausted retries"))
    }
}

async fn sync_once_with_client(
    db: &Db,
    credential: &StoredFlycockpitCredential,
    client: &OrgSyncHttpClient,
    redaction: &RedactionTable,
    sleep: SleepFn<'_>,
) -> Result<OrgSyncOnceOutcome> {
    let policy = match client.fetch_policy(credential).await? {
        PolicyFetchOutcome::Active(policy) => policy,
        PolicyFetchOutcome::Disabled => {
            db.mark_org_sync_disabled(&credential.server_url)?;
            return Ok(OrgSyncOnceOutcome::Disabled);
        }
        PolicyFetchOutcome::Revoked => {
            db.mark_org_sync_disabled(&credential.server_url)?;
            return Ok(OrgSyncOnceOutcome::Revoked);
        }
    };

    db.upsert_org_sync_policy(
        &credential.server_url,
        &policy.org_id,
        policy.policy_version.as_deref(),
        &policy.raw,
        true,
    )?;
    let state = db
        .org_sync_state(&credential.server_url, &policy.org_id)?
        .ok_or_else(|| anyhow!("org sync state missing after policy upsert"))?;
    let built = build_batch(db, credential, &policy, state.cursor_seq, redaction)?;
    match built {
        BatchBuild::Idle => Ok(OrgSyncOnceOutcome::Idle),
        BatchBuild::Filtered { cursor_seq } => {
            db.update_org_sync_cursor(&credential.server_url, &policy.org_id, cursor_seq)?;
            Ok(OrgSyncOnceOutcome::Filtered { cursor_seq })
        }
        BatchBuild::Ready {
            payload,
            cursor_seq,
            event_count,
        } => {
            let ingest = match client
                .post_batch_with_retries(credential, &policy, &payload, sleep)
                .await
            {
                Ok(ingest) => ingest,
                Err(error) => {
                    db.update_org_sync_error(
                        &credential.server_url,
                        &policy.org_id,
                        &error.to_string(),
                    )?;
                    return Err(error);
                }
            };
            match ingest {
                IngestOutcome::Accepted => {
                    db.update_org_sync_cursor(&credential.server_url, &policy.org_id, cursor_seq)?;
                    Ok(OrgSyncOnceOutcome::Uploaded {
                        events: event_count,
                        cursor_seq,
                    })
                }
                IngestOutcome::Revoked => {
                    db.mark_org_sync_disabled(&credential.server_url)?;
                    Ok(OrgSyncOnceOutcome::Revoked)
                }
            }
        }
    }
}

enum BatchBuild {
    Idle,
    Filtered {
        cursor_seq: i64,
    },
    Ready {
        payload: Value,
        cursor_seq: i64,
        event_count: usize,
    },
}

fn build_batch(
    db: &Db,
    credential: &StoredFlycockpitCredential,
    policy: &OrgLogSyncPolicy,
    cursor_seq: i64,
    redaction: &RedactionTable,
) -> Result<BatchBuild> {
    let rows = db.list_org_sync_events_after(cursor_seq, MAX_BATCH_EVENTS)?;
    if rows.is_empty() {
        return Ok(BatchBuild::Idle);
    }
    let input_cursor_seq = cursor_seq;
    let mut batch_cursor_seq = cursor_seq;
    let mut events = Vec::new();
    let mut bytes = 0usize;
    for row in &rows {
        if !policy.allows_kind(&row.kind) {
            batch_cursor_seq = row.seq;
            continue;
        }
        let event = sync_event_json(db, row, redaction)?;
        let size = serde_json::to_vec(&event)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        if !events.is_empty() && bytes.saturating_add(size) > MAX_BATCH_BYTES {
            break;
        }
        bytes = bytes.saturating_add(size);
        batch_cursor_seq = row.seq;
        events.push(event);
    }
    if events.is_empty() {
        return Ok(BatchBuild::Filtered {
            cursor_seq: batch_cursor_seq,
        });
    }
    let event_count = events.len();
    Ok(BatchBuild::Ready {
        payload: json!({
            "schemaVersion": 1,
            "serverUrl": credential.server_url,
            "orgId": policy.org_id,
            "policyVersion": policy.policy_version.as_deref(),
            "instanceId": credential.instance_id,
            "accountUserId": credential.account.user_id,
            "cursorStart": input_cursor_seq,
            "cursorEnd": batch_cursor_seq,
            "events": events,
        }),
        cursor_seq: batch_cursor_seq,
        event_count,
    })
}

fn sync_event_json(db: &Db, row: &SessionEventRow, redaction: &RedactionTable) -> Result<Value> {
    let mut event = json!({
        "idempotencyKey": format!("session_event:{}", row.seq),
        "sourceTable": "session_events",
        "seq": row.seq,
        "sessionId": row.session_id,
        "tsMs": row.ts_ms,
        "kind": row.kind,
        "agent": row.agent,
        "callId": row.call_id,
        "data": row.data,
    });
    if row.kind == "inference_request"
        && let Some(call_id) = row.call_id.as_deref()
        && let Some((payload, status)) = db.get_inference_request(call_id)?
    {
        event["inferenceRequest"] = json!({
            "status": status,
            "payload": payload,
        });
    }
    Ok(scrub_json_value(event, redaction))
}

fn scrub_json_value(value: Value, redaction: &RedactionTable) -> Value {
    match value {
        Value::String(s) => Value::String(redaction.scrub(&s)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| scrub_json_value(item, redaction))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, scrub_json_value(value, redaction)))
                .collect(),
        ),
        other => other,
    }
}

fn parse_policy(body: &str) -> Result<PolicyFetchOutcome> {
    let value: Value = serde_json::from_str(body).context("parsing Flycockpit org policy")?;
    let root = value.get("json").unwrap_or(&value);
    let sync = root
        .get("sessionLogSync")
        .or_else(|| root.get("session_log_sync"))
        .or_else(|| root.get("logSync"))
        .or_else(|| root.get("log_sync"));
    let enabled = sync
        .and_then(|v| v.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mandatory = sync
        .and_then(|v| v.get("mandatory"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !enabled || !mandatory {
        return Ok(PolicyFetchOutcome::Disabled);
    }
    let org_id = string_field(root, &["orgId", "org_id"])
        .or_else(|| sync.and_then(|v| string_field(v, &["orgId", "org_id"])))
        .ok_or_else(|| anyhow!("Flycockpit org policy omitted orgId"))?;
    let policy_version = string_field(root, &["policyVersion", "policy_version"])
        .or_else(|| sync.and_then(|v| string_field(v, &["policyVersion", "policy_version"])));
    Ok(PolicyFetchOutcome::Active(OrgLogSyncPolicy {
        org_id,
        policy_version,
        include_event_kinds: string_vec(sync, &["includeEventKinds", "include_event_kinds"]),
        exclude_event_kinds: string_vec(sync, &["excludeEventKinds", "exclude_event_kinds"]),
        include_local_model_transcripts: sync
            .and_then(|v| {
                v.get("includeLocalModelTranscripts")
                    .or_else(|| v.get("include_local_model_transcripts"))
            })
            .and_then(Value::as_bool)
            .unwrap_or(true),
        raw: root.clone(),
    }))
}

fn string_field(value: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn string_vec(container: Option<&Value>, names: &[&str]) -> Vec<String> {
    let Some(container) = container else {
        return Vec::new();
    };
    names
        .iter()
        .find_map(|name| container.get(*name).and_then(Value::as_array))
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default()
}

fn endpoint(server_url: &str, path: &str) -> Result<Url> {
    let base = Url::parse(server_url).context("parsing Flycockpit server URL")?;
    base.join(path.trim_start_matches('/'))
        .with_context(|| format!("building Flycockpit endpoint {path}"))
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

#[cfg(test)]
mod tests {
    #![allow(deprecated)]

    use super::*;
    use crate::auth::flycockpit::{AccountInfo, with_redaction_token_override};
    use crate::db::session_log::SessionEventKind;
    use serde_json::json;
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

    fn active_policy() -> String {
        json!({
            "orgId": "org-1",
            "policyVersion": "v1",
            "sessionLogSync": {"enabled": true, "mandatory": true}
        })
        .to_string()
    }

    async fn sync_with_responses(
        db: &Db,
        responses: Vec<TestResponse>,
    ) -> (OrgSyncOnceOutcome, Vec<String>, Vec<Duration>) {
        let (server, requests) = start_test_server(responses).await;
        let credential = credential(server.clone());
        let client = OrgSyncHttpClient::new(&server).unwrap();
        let redaction = RedactionTable::empty();
        let sleeps = std::sync::Arc::new(Mutex::new(Vec::new()));
        let sleep_log = sleeps.clone();
        let mut sleeper = move |duration| -> SleepFuture {
            let sleep_log = sleep_log.clone();
            Box::pin(async move {
                sleep_log.lock().await.push(duration);
            })
        };
        let outcome = sync_once_with_client(db, &credential, &client, &redaction, &mut sleeper)
            .await
            .unwrap();
        let requests = requests.lock().await.clone();
        let sleeps = sleeps.lock().await.clone();
        (outcome, requests, sleeps)
    }

    fn insert_event(db: &Db, kind: SessionEventKind, text: &str) -> i64 {
        let session = db
            .write_blocking(|conn| {
                crate::db::Db::insert_session_row_conn(
                    conn,
                    &crate::db::Db::build_new_session_row_conn(
                        conn,
                        "p",
                        "/tmp/project",
                        "builder",
                    )?,
                )
            })
            .unwrap();
        db.insert_session_event(
            session.session_id,
            kind,
            Some("builder"),
            None,
            &json!({"text": text}),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn incremental_cursor_sync_uploads_new_rows() {
        let db = Db::open_in_memory().unwrap();
        let first = insert_event(&db, SessionEventKind::UserMessage, "one");
        let second = insert_event(&db, SessionEventKind::AssistantMessage, "two");
        let (outcome, requests, _) = sync_with_responses(
            &db,
            vec![response(200, active_policy()), response(200, "{}")],
        )
        .await;
        assert_eq!(
            outcome,
            OrgSyncOnceOutcome::Uploaded {
                events: 2,
                cursor_seq: second
            }
        );
        let ingest = requests.iter().find(|r| r.starts_with("POST ")).unwrap();
        assert!(ingest.contains(&format!("\"seq\":{first}")));
        assert!(ingest.contains(&format!("\"seq\":{second}")));
        assert_eq!(db.list_org_sync_states().unwrap()[0].cursor_seq, second);
    }

    #[tokio::test]
    async fn restart_resume_uses_persisted_cursor() {
        let db = Db::open_in_memory().unwrap();
        let first = insert_event(&db, SessionEventKind::UserMessage, "old");
        let second = insert_event(&db, SessionEventKind::UserMessage, "new");
        let (server, requests) =
            start_test_server(vec![response(200, active_policy()), response(200, "{}")]).await;
        db.upsert_org_sync_policy(&server, "org-1", Some("v1"), &json!({}), true)
            .unwrap();
        db.update_org_sync_cursor(&server, "org-1", first).unwrap();
        let credential = credential(server.clone());
        let client = OrgSyncHttpClient::new(&server).unwrap();
        let redaction = RedactionTable::empty();
        let mut sleeper = |_duration| -> SleepFuture { Box::pin(async {}) };
        let outcome = sync_once_with_client(&db, &credential, &client, &redaction, &mut sleeper)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            OrgSyncOnceOutcome::Uploaded {
                events: 1,
                cursor_seq: second
            }
        );
        let seen = requests.lock().await;
        let ingest = seen.iter().find(|r| r.starts_with("POST ")).unwrap();
        assert!(!ingest.contains(&format!("\"seq\":{first}")));
        assert!(ingest.contains(&format!("\"seq\":{second}")));
    }

    #[tokio::test]
    async fn ingest_retries_5xx_with_backoff() {
        let db = Db::open_in_memory().unwrap();
        let seq = insert_event(&db, SessionEventKind::UserMessage, "retry");
        let (outcome, requests, sleeps) = sync_with_responses(
            &db,
            vec![
                response(200, active_policy()),
                response(500, r#"{"error":"try again"}"#),
                response(200, "{}"),
            ],
        )
        .await;
        assert_eq!(
            outcome,
            OrgSyncOnceOutcome::Uploaded {
                events: 1,
                cursor_seq: seq
            }
        );
        assert_eq!(
            requests.iter().filter(|r| r.starts_with("POST ")).count(),
            2
        );
        assert_eq!(sleeps, vec![Duration::from_millis(250)]);
    }

    #[tokio::test]
    async fn retry_after_header_is_honored() {
        let db = Db::open_in_memory().unwrap();
        let seq = insert_event(&db, SessionEventKind::UserMessage, "retry-after");
        let (outcome, _, sleeps) = sync_with_responses(
            &db,
            vec![
                response(200, active_policy()),
                response_with_headers(503, r#"{"error":"busy"}"#, vec![("Retry-After", "7")]),
                response(200, "{}"),
            ],
        )
        .await;
        assert_eq!(
            outcome,
            OrgSyncOnceOutcome::Uploaded {
                events: 1,
                cursor_seq: seq
            }
        );
        assert_eq!(sleeps, vec![Duration::from_secs(7)]);
    }

    #[tokio::test]
    async fn revocation_stops_sync_and_disables_state() {
        let db = Db::open_in_memory().unwrap();
        insert_event(&db, SessionEventKind::UserMessage, "secret");
        let (server, _) = start_test_server(vec![response(401, r#"{"error":"revoked"}"#)]).await;
        db.upsert_org_sync_policy(&server, "org-1", Some("v1"), &json!({}), true)
            .unwrap();
        let credential = credential(server.clone());
        let client = OrgSyncHttpClient::new(&server).unwrap();
        let redaction = RedactionTable::empty();
        let mut sleeper = |_duration| -> SleepFuture { Box::pin(async {}) };
        let outcome = sync_once_with_client(&db, &credential, &client, &redaction, &mut sleeper)
            .await
            .unwrap();
        assert_eq!(outcome, OrgSyncOnceOutcome::Revoked);
        assert!(
            db.active_org_sync_state_for_server(&server)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn byte_cap_does_not_advance_past_unuploaded_included_events() {
        let db = Db::open_in_memory().unwrap();
        let first = insert_event(
            &db,
            SessionEventKind::UserMessage,
            &"a".repeat(MAX_BATCH_BYTES / 2),
        );
        let second = insert_event(
            &db,
            SessionEventKind::AssistantMessage,
            &"b".repeat(MAX_BATCH_BYTES / 2),
        );
        let policy = OrgLogSyncPolicy {
            org_id: "org-1".to_string(),
            policy_version: Some("v1".to_string()),
            include_event_kinds: Vec::new(),
            exclude_event_kinds: Vec::new(),
            include_local_model_transcripts: true,
            raw: json!({}),
        };
        let credential = credential("http://localhost:1".to_string());
        let built = build_batch(&db, &credential, &policy, 0, &RedactionTable::empty()).unwrap();
        match built {
            BatchBuild::Ready {
                cursor_seq,
                event_count,
                payload,
            } => {
                assert_eq!(cursor_seq, first);
                assert_eq!(event_count, 1);
                let payload = payload.to_string();
                assert!(payload.contains(&format!("\"seq\":{first}")));
                assert!(!payload.contains(&format!("\"seq\":{second}")));
            }
            BatchBuild::Idle | BatchBuild::Filtered { .. } => panic!("expected ready batch"),
        }
    }

    #[tokio::test]
    async fn event_kind_filters_are_applied_and_cursor_advances() {
        let db = Db::open_in_memory().unwrap();
        let user = insert_event(&db, SessionEventKind::UserMessage, "include me");
        let assistant = insert_event(&db, SessionEventKind::AssistantMessage, "exclude me");
        let policy = json!({
            "orgId": "org-1",
            "policyVersion": "v1",
            "sessionLogSync": {
                "enabled": true,
                "mandatory": true,
                "includeEventKinds": ["user_message"]
            }
        })
        .to_string();
        let (outcome, requests, _) =
            sync_with_responses(&db, vec![response(200, policy), response(200, "{}")]).await;
        assert_eq!(
            outcome,
            OrgSyncOnceOutcome::Uploaded {
                events: 1,
                cursor_seq: assistant
            }
        );
        let ingest = requests.iter().find(|r| r.starts_with("POST ")).unwrap();
        assert!(ingest.contains(&format!("\"seq\":{user}")));
        assert!(!ingest.contains(&format!("\"seq\":{assistant}")));
    }

    #[tokio::test]
    async fn redacted_values_never_appear_in_payloads() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("p", "/tmp/project", "builder")
            .await
            .unwrap();
        db.insert_session_event(
            session.session_id,
            SessionEventKind::UserMessage,
            Some("builder"),
            None,
            &json!({"text": "token fci_instance_secret should not leave"}),
        )
        .unwrap();
        let (server, requests) =
            start_test_server(vec![response(200, active_policy()), response(200, "{}")]).await;
        let credential = credential(server.clone());
        let client = OrgSyncHttpClient::new(&server).unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let redaction = with_redaction_token_override("fci_instance_secret", || {
            RedactionTable::build(&RedactConfig::default(), tmp.path()).unwrap()
        });
        let mut sleeper = |_duration| -> SleepFuture { Box::pin(async {}) };
        sync_once_with_client(&db, &credential, &client, &redaction, &mut sleeper)
            .await
            .unwrap();
        let seen = requests.lock().await;
        let ingest = seen.iter().find(|r| r.starts_with("POST ")).unwrap();
        assert!(!ingest.contains("fci_instance_secret"));
        assert!(ingest.contains("REDACT"));
    }

    #[test]
    fn sync_code_is_not_on_driver_hot_path() {
        let driver = include_str!("../engine/driver/mod.rs");
        assert!(!driver.contains("org_sync"));
        assert!(!driver.contains("session-log sync"));
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
