//! Connector-gated HTTP client for FlyCockpit-owned egress.
//!
//! This is the sole daemon transport that can construct first-party URLs.
//! Every request rechecks the connector state so `--no-remote` remains an
//! absolute boundary even while a background uploader is running.

use anyhow::{Context, Result};
use reqwest::{Method, Response, Url};
use serde_json::Value;
use uuid::Uuid;

use crate::auth::flycockpit::{StoredFlycockpitCredential, normalize_server_url};
use crate::db::Db;

#[derive(Clone)]
pub(crate) struct FirstPartyEgressClient {
    db: Db,
    credential: StoredFlycockpitCredential,
    http: reqwest::Client,
    server_url: String,
}

impl FirstPartyEgressClient {
    /// Returns `None` unless both the stored credential and its connector are
    /// enabled. Callers must treat that as a normal no-egress outcome.
    pub(crate) async fn connect(
        db: Db,
        credential: StoredFlycockpitCredential,
    ) -> Result<Option<Self>> {
        if !connector_enabled(&db, &credential).await? {
            return Ok(None);
        }
        let server_url = normalize_server_url(&credential.server_url)?;
        Ok(Some(Self {
            db,
            credential,
            http: reqwest::Client::new(),
            server_url,
        }))
    }

    /// Sends a first-party request only while the connector remains enabled.
    /// A `None` response means the user disabled remote access between batches
    /// (or before the policy poll), so no request was emitted.
    pub(crate) async fn send_json(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        payload: Option<&Value>,
    ) -> Result<Option<Response>> {
        if !connector_enabled(&self.db, &self.credential).await? {
            return Ok(None);
        }
        let endpoint = first_party_endpoint(&self.server_url, path)?;
        let mut request = self
            .http
            .request(method, endpoint)
            .bearer_auth(&self.credential.instance_token)
            .header("x-flycockpit-instance-id", &self.credential.instance_id)
            .header("x-csrf-token", crate::auth::flycockpit::CLIENT_ID);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(payload) = payload {
            request = request.json(payload);
        }
        request
            .send()
            .await
            .map(Some)
            .context("sending connector-gated Flycockpit request")
    }
}

pub(crate) async fn redaction_for_session(
    db: &Db,
    session_id: Uuid,
) -> Result<Option<crate::redact::RedactionTable>> {
    let Some(session) = db.get_session(session_id).await? else {
        return Ok(None);
    };
    let Some(json) = session.redaction_table_json else {
        return Ok(None);
    };
    crate::redact::RedactionTable::from_persisted_json(&json)
        .map(Some)
        .context("loading session redaction table for first-party egress")
}

pub(crate) async fn connector_enabled(
    db: &Db,
    credential: &StoredFlycockpitCredential,
) -> Result<bool> {
    Ok(db
        .connector_state(&credential.server_url, &credential.instance_id)
        .await?
        .is_some_and(|state| state.enabled))
}

fn first_party_endpoint(server_url: &str, path: &str) -> Result<Url> {
    let base = Url::parse(server_url).context("parsing Flycockpit server URL")?;
    base.join(path.trim_start_matches('/'))
        .with_context(|| format!("building Flycockpit endpoint {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_connector_suppresses_all_first_party_egress() {
        let db = Db::open_in_memory().unwrap();
        let credential = StoredFlycockpitCredential {
            server_url: "http://127.0.0.1:9".to_string(),
            instance_id: "instance".to_string(),
            instance_token: "token".to_string(),
            account: crate::auth::flycockpit::AccountInfo {
                user_id: "user".to_string(),
                email: "user@example.test".to_string(),
            },
            display_name: None,
            relay_choice: None,
        };
        assert!(
            FirstPartyEgressClient::connect(db, credential)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn upload_uses_session_redaction_table() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("p", "/tmp/project", "builder")
            .await
            .unwrap();
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal("custom-upload-secret".to_string(), "test".to_string())
            .unwrap();
        db.set_session_redaction_table_json(
            session.session_id,
            Some(table.to_persisted_json().unwrap()),
        )
        .await
        .unwrap();
        let loaded = redaction_for_session(&db, session.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(loaded.scrub("custom-upload-secret"), "custom-upload-secret");
    }

    #[tokio::test]
    async fn unloadable_redaction_table_blocks_upload() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("p", "/tmp/project", "builder")
            .await
            .unwrap();
        db.set_session_redaction_table_json(session.session_id, Some("not json".to_string()))
            .await
            .unwrap();
        assert!(
            redaction_for_session(&db, session.session_id)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn connector_disabled_midrun_stops_upload() {
        let db = Db::open_in_memory().unwrap();
        let credential = StoredFlycockpitCredential {
            server_url: "http://127.0.0.1:9".to_string(),
            instance_id: "instance".to_string(),
            instance_token: "token".to_string(),
            account: crate::auth::flycockpit::AccountInfo {
                user_id: "user".to_string(),
                email: "user@example.test".to_string(),
            },
            display_name: None,
            relay_choice: None,
        };
        db.set_connector_enabled(&credential.server_url, &credential.instance_id, true)
            .await
            .unwrap();
        let client = FirstPartyEgressClient::connect(db.clone(), credential.clone())
            .await
            .unwrap()
            .unwrap();
        db.set_connector_enabled(&credential.server_url, &credential.instance_id, false)
            .await
            .unwrap();
        assert!(
            client
                .send_json(Method::POST, "/api/test", &[], Some(&serde_json::json!({})))
                .await
                .unwrap()
                .is_none()
        );
    }
}
