//! Daemon-owned ACP Code-root authority.
//!
//! Capabilities, discovery snapshots, and idempotency receipts are deliberately
//! boot-local. Only the redacted delivery projection and logical-client ACK
//! cursor are durable (in `cockpit-db`).

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{daemon::proto, db::Db};

const MAX_ATTACHMENTS: usize = 4_096;
const MAX_IDEMPOTENCY_RECEIPTS: usize = 8_192;
const MAX_DISCOVERY_SNAPSHOTS: usize = 256;

#[derive(Debug, Clone)]
pub(crate) struct CodeRootAttachmentRecord {
    pub root_id: proto::CodeRootIdV1,
    pub logical_client_id: proto::OpaqueAsciiId128V1,
    pub capture_generation: u64,
    pub replay_cursor: proto::CodeRootReplayCursorV1,
    pub open: bool,
}

#[derive(Debug, Clone)]
enum IdempotencyResult {
    Create(proto::CreateCodeRootV1Result),
    Attach(proto::AttachExistingCodeRootV1Result),
    Close(proto::CloseCodeRootAttachmentV1Result),
    Ack(proto::AckCodeRootDeliveriesV1Result),
}

#[derive(Debug, Clone)]
struct IdempotencyReceipt {
    fingerprint: [u8; 32],
    result: IdempotencyResult,
}

#[derive(Debug, Clone)]
struct DiscoverySnapshot {
    workspace_path: String,
    logical_client_id: proto::OpaqueAsciiId128V1,
    roots: Vec<proto::CodeRootSummaryV1>,
    offset: usize,
}

#[derive(Debug, Default)]
pub(crate) struct CodeRootAuthorityV1 {
    attachments: HashMap<String, CodeRootAttachmentRecord>,
    idempotency: HashMap<(String, String, &'static str), IdempotencyReceipt>,
    discovery: HashMap<String, DiscoverySnapshot>,
    next_capture_generation: u64,
}

impl CodeRootAuthorityV1 {
    pub fn preflight_new_attachment(&self) -> Result<()> {
        if self.attachments.len() >= MAX_ATTACHMENTS {
            bail!("Code-root attachment capacity exhausted");
        }
        if self.idempotency.len() >= MAX_IDEMPOTENCY_RECEIPTS {
            bail!("Code-root idempotency capacity exhausted");
        }
        Ok(())
    }

    pub fn preflight_idempotency(&self) -> Result<()> {
        if self.idempotency.len() >= MAX_IDEMPOTENCY_RECEIPTS {
            bail!("Code-root idempotency capacity exhausted");
        }
        Ok(())
    }

    pub fn next_capture_generation(&mut self) -> u64 {
        self.next_capture_generation = self.next_capture_generation.saturating_add(1).max(1);
        self.next_capture_generation
    }

    pub fn mint_attachment(
        &mut self,
        root_id: proto::CodeRootIdV1,
        logical_client_id: proto::OpaqueAsciiId128V1,
        capture_generation: u64,
        replay_cursor: proto::CodeRootReplayCursorV1,
    ) -> Result<proto::CodeRootAttachmentV1> {
        if self.attachments.len() >= MAX_ATTACHMENTS {
            bail!("Code-root attachment capacity exhausted");
        }
        let capability = proto::CodeRootAttachmentCapabilityV1::from_daemon_random(Uuid::new_v4());
        self.attachments.insert(
            capability.expose_opaque().to_owned(),
            CodeRootAttachmentRecord {
                root_id,
                logical_client_id,
                capture_generation,
                replay_cursor: replay_cursor.clone(),
                open: true,
            },
        );
        Ok(proto::CodeRootAttachmentV1 {
            root_id,
            attachment_capability: capability,
            capture_generation,
            replay_cursor,
        })
    }

    pub fn authenticate(
        &self,
        capability: &proto::CodeRootAttachmentCapabilityV1,
    ) -> Result<&CodeRootAttachmentRecord> {
        let record = self
            .attachments
            .get(capability.expose_opaque())
            .context("unknown Code-root attachment capability")?;
        if !record.open {
            bail!("Code-root attachment is closed");
        }
        debug_assert!(record.capture_generation > 0);
        Ok(record)
    }

    pub fn close(
        &mut self,
        capability: &proto::CodeRootAttachmentCapabilityV1,
    ) -> Result<proto::CloseCodeRootAttachmentV1Result> {
        let record = self
            .attachments
            .get_mut(capability.expose_opaque())
            .context("unknown Code-root attachment capability")?;
        if record.open {
            record.open = false;
            Ok(proto::CloseCodeRootAttachmentV1Result::Closed)
        } else {
            Ok(proto::CloseCodeRootAttachmentV1Result::AlreadyClosed)
        }
    }

    pub fn record_for_capability(
        &self,
        capability: &proto::CodeRootAttachmentCapabilityV1,
    ) -> Result<CodeRootAttachmentRecord> {
        self.attachments
            .get(capability.expose_opaque())
            .cloned()
            .context("unknown Code-root attachment capability")
    }

    pub fn begin_discovery(
        &mut self,
        workspace_path: String,
        logical_client_id: proto::OpaqueAsciiId128V1,
        roots: Vec<proto::CodeRootSummaryV1>,
        limit: u16,
    ) -> Result<proto::DiscoverCodeRootsV1Result> {
        if roots.len() <= usize::from(limit) {
            return Ok(proto::DiscoverCodeRootsV1Result {
                roots,
                next_cursor: None,
            });
        }
        if self.discovery.len() >= MAX_DISCOVERY_SNAPSHOTS {
            bail!("Code-root discovery snapshot capacity exhausted");
        }
        let cursor = proto::CodeRootDiscoveryCursorV1::from_daemon_random(Uuid::new_v4());
        let first = roots[..usize::from(limit)].to_vec();
        self.discovery.insert(
            cursor.expose_opaque().to_owned(),
            DiscoverySnapshot {
                workspace_path,
                logical_client_id,
                roots,
                offset: usize::from(limit),
            },
        );
        Ok(proto::DiscoverCodeRootsV1Result {
            roots: first,
            next_cursor: Some(cursor),
        })
    }

    pub fn continue_discovery(
        &mut self,
        cursor: &proto::CodeRootDiscoveryCursorV1,
        workspace_path: &str,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        limit: u16,
    ) -> Result<proto::DiscoverCodeRootsV1Result> {
        let key = cursor.expose_opaque().to_owned();
        let snapshot = self
            .discovery
            .get_mut(&key)
            .context("unknown or expired Code-root discovery cursor")?;
        if snapshot.workspace_path != workspace_path
            || snapshot.logical_client_id != *logical_client_id
        {
            bail!("Code-root discovery cursor does not match this request");
        }
        let end = snapshot
            .offset
            .saturating_add(usize::from(limit))
            .min(snapshot.roots.len());
        let roots = snapshot.roots[snapshot.offset..end].to_vec();
        snapshot.offset = end;
        let next_cursor = (end < snapshot.roots.len()).then_some(cursor.clone());
        if next_cursor.is_none() {
            self.discovery.remove(&key);
        }
        Ok(proto::DiscoverCodeRootsV1Result { roots, next_cursor })
    }

    fn replay(
        &self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        client_request_id: &proto::OpaqueAsciiId128V1,
        route: &'static str,
        fingerprint: [u8; 32],
    ) -> Result<Option<IdempotencyResult>> {
        let key = (
            logical_client_id.as_str().to_owned(),
            client_request_id.as_str().to_owned(),
            route,
        );
        let Some(receipt) = self.idempotency.get(&key) else {
            return Ok(None);
        };
        if receipt.fingerprint != fingerprint {
            bail!("Code-root idempotency conflict");
        }
        Ok(Some(receipt.result.clone()))
    }

    fn record(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        client_request_id: &proto::OpaqueAsciiId128V1,
        route: &'static str,
        fingerprint: [u8; 32],
        result: IdempotencyResult,
    ) -> Result<()> {
        if self.idempotency.len() >= MAX_IDEMPOTENCY_RECEIPTS {
            bail!("Code-root idempotency capacity exhausted");
        }
        self.idempotency.insert(
            (
                logical_client_id.as_str().to_owned(),
                client_request_id.as_str().to_owned(),
                route,
            ),
            IdempotencyReceipt { fingerprint, result },
        );
        Ok(())
    }

    pub fn replay_create(
        &self,
        request: &proto::CreateCodeRootV1Request,
    ) -> Result<Option<proto::CreateCodeRootV1Result>> {
        match self.replay(
            &request.logical_client_id,
            &request.client_request_id,
            "create",
            fingerprint(request)?,
        )? {
            Some(IdempotencyResult::Create(result)) => {
                self.authenticate(&result.attachment.attachment_capability)?;
                Ok(Some(result))
            }
            Some(_) => bail!("invalid Code-root idempotency receipt"),
            None => Ok(None),
        }
    }

    pub fn record_create(
        &mut self,
        request: &proto::CreateCodeRootV1Request,
        result: proto::CreateCodeRootV1Result,
    ) -> Result<()> {
        self.record(
            &request.logical_client_id,
            &request.client_request_id,
            "create",
            fingerprint(request)?,
            IdempotencyResult::Create(result),
        )
    }

    pub fn replay_attach(
        &self,
        request: &proto::AttachExistingCodeRootV1Request,
    ) -> Result<Option<proto::AttachExistingCodeRootV1Result>> {
        match self.replay(
            &request.logical_client_id,
            &request.client_request_id,
            "attach",
            fingerprint(request)?,
        )? {
            Some(IdempotencyResult::Attach(result)) => {
                self.authenticate(&result.attachment.attachment_capability)?;
                Ok(Some(result))
            }
            Some(_) => bail!("invalid Code-root idempotency receipt"),
            None => Ok(None),
        }
    }

    pub fn record_attach(
        &mut self,
        request: &proto::AttachExistingCodeRootV1Request,
        result: proto::AttachExistingCodeRootV1Result,
    ) -> Result<()> {
        self.record(
            &request.logical_client_id,
            &request.client_request_id,
            "attach",
            fingerprint(request)?,
            IdempotencyResult::Attach(result),
        )
    }

    pub fn replay_close(
        &self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        request: &proto::CloseCodeRootAttachmentV1Request,
    ) -> Result<Option<proto::CloseCodeRootAttachmentV1Result>> {
        match self.replay(
            logical_client_id,
            &request.client_request_id,
            "close",
            fingerprint(request)?,
        )? {
            Some(IdempotencyResult::Close(result)) => Ok(Some(result)),
            Some(_) => bail!("invalid Code-root idempotency receipt"),
            None => Ok(None),
        }
    }

    pub fn record_close(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        request: &proto::CloseCodeRootAttachmentV1Request,
        result: proto::CloseCodeRootAttachmentV1Result,
    ) -> Result<()> {
        self.record(
            logical_client_id,
            &request.client_request_id,
            "close",
            fingerprint(request)?,
            IdempotencyResult::Close(result),
        )
    }

    pub fn replay_ack(
        &self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        request: &proto::AckCodeRootDeliveriesV1Request,
    ) -> Result<Option<proto::AckCodeRootDeliveriesV1Result>> {
        match self.replay(
            logical_client_id,
            &request.client_request_id,
            "ack",
            fingerprint(request)?,
        )? {
            Some(IdempotencyResult::Ack(result)) => Ok(Some(result)),
            Some(_) => bail!("invalid Code-root idempotency receipt"),
            None => Ok(None),
        }
    }

    pub fn record_ack(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        request: &proto::AckCodeRootDeliveriesV1Request,
        result: proto::AckCodeRootDeliveriesV1Result,
    ) -> Result<()> {
        self.record(
            logical_client_id,
            &request.client_request_id,
            "ack",
            fingerprint(request)?,
            IdempotencyResult::Ack(result),
        )
    }
}

fn fingerprint<T: serde::Serialize>(value: &T) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(value).context("serializing Code-root idempotency input")?;
    Ok(Sha256::digest(bytes).into())
}

/// The only service allowed to create durable ACP projection deliveries.
/// Implementations receive typed, already-redacted Cockpit records rather
/// than arbitrary JSON from an adapter.
#[async_trait]
pub trait CodeRootProjectionWriterV1: Send + Sync {
    async fn write_history(
        &self,
        root_id: proto::CodeRootIdV1,
        entry: proto::HistoryEntry,
    ) -> Result<proto::CodeRootDeliveryV1>;

    async fn write_attention(
        &self,
        root_id: proto::CodeRootIdV1,
        entry: proto::AgentDecisionAttention,
    ) -> Result<proto::CodeRootDeliveryV1>;

    async fn write_root_state_changed(
        &self,
        root_id: proto::CodeRootIdV1,
    ) -> Result<proto::CodeRootDeliveryV1>;
}

#[derive(Clone)]
pub(crate) struct DurableCodeRootProjectionWriterV1 {
    db: Db,
}

impl DurableCodeRootProjectionWriterV1 {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    async fn write(
        &self,
        root_id: proto::CodeRootIdV1,
        mut payload: proto::CodeRootDeliveryPayloadV1,
    ) -> Result<proto::CodeRootDeliveryV1> {
        let (mut kind, mut source_key) = match &payload {
            proto::CodeRootDeliveryPayloadV1::History { entry } => {
                let value = serde_json::to_value(entry)?;
                let sequence = value
                    .get("seq")
                    .and_then(serde_json::Value::as_i64)
                    .context("history projection is missing its durable sequence")?;
                ("history", Some(format!("history:{sequence}")))
            }
            proto::CodeRootDeliveryPayloadV1::Attention { entry } => (
                "attention",
                Some(format!(
                    "attention:{}:{}",
                    entry.decision_request_id, entry.revision
                )),
            ),
            proto::CodeRootDeliveryPayloadV1::RootStateChanged => ("root_state_changed", None),
            proto::CodeRootDeliveryPayloadV1::ClientIncompatible => ("client_incompatible", None),
        };
        let mut payload_json = serde_json::to_string(&payload)?;
        if payload_json.len()
            > crate::db::code_root_projection::MAX_CODE_ROOT_PROJECTION_PAYLOAD_BYTES
        {
            source_key = source_key.map(|key| format!("incompatible:{key}"));
            kind = "client_incompatible";
            payload = proto::CodeRootDeliveryPayloadV1::ClientIncompatible;
            payload_json = serde_json::to_string(&payload)?;
        }
        let row = self
            .db
            .append_code_root_projection_delivery(
                root_id.0,
                kind,
                source_key.as_deref(),
                &payload_json,
                chrono::Utc::now().timestamp_millis(),
            )
            .await?;
        Ok(proto::CodeRootDeliveryV1 {
            delivery_id: row.delivery_id,
            cursor: proto::CodeRootReplayCursorV1::from_daemon_opaque(row.replay_cursor)
                .map_err(anyhow::Error::msg)?,
            payload,
            created_at_unix_ms: row.created_at_unix_ms,
        })
    }
}

#[async_trait]
impl CodeRootProjectionWriterV1 for DurableCodeRootProjectionWriterV1 {
    async fn write_history(
        &self,
        root_id: proto::CodeRootIdV1,
        entry: proto::HistoryEntry,
    ) -> Result<proto::CodeRootDeliveryV1> {
        self.write(
            root_id,
            proto::CodeRootDeliveryPayloadV1::History { entry },
        )
        .await
    }

    async fn write_attention(
        &self,
        root_id: proto::CodeRootIdV1,
        entry: proto::AgentDecisionAttention,
    ) -> Result<proto::CodeRootDeliveryV1> {
        self.write(
            root_id,
            proto::CodeRootDeliveryPayloadV1::Attention { entry },
        )
        .await
    }

    async fn write_root_state_changed(
        &self,
        root_id: proto::CodeRootIdV1,
    ) -> Result<proto::CodeRootDeliveryV1> {
        self.write(
            root_id,
            proto::CodeRootDeliveryPayloadV1::RootStateChanged,
        )
        .await
    }
}
