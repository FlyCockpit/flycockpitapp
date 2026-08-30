//! Daemon-owned ACP Code-root authority.
//!
//! Capabilities, discovery snapshots, and idempotency receipts are deliberately
//! boot-local. Only the redacted delivery projection and logical-client ACK
//! cursor are durable (in `cockpit-db`).

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{daemon::proto, db::Db};

const MAX_ATTACHMENTS: usize = 4_096;
const MAX_IDEMPOTENCY_RECEIPTS: usize = 8_192;
const MAX_DISCOVERY_SNAPSHOTS: usize = 256;
const ATTACHMENT_TOMBSTONE_TTL: Duration = Duration::from_secs(10 * 60);
const IDEMPOTENCY_RECEIPT_TTL: Duration = Duration::from_secs(10 * 60);
const DISCOVERY_SNAPSHOT_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub(crate) struct CodeRootAttachmentRecord {
    pub root_id: proto::CodeRootIdV1,
    pub logical_client_id: proto::OpaqueAsciiId128V1,
    pub capture_generation: u64,
    pub replay_cursor: proto::CodeRootReplayCursorV1,
    pub open: bool,
    closed_at: Option<Instant>,
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
    recorded_at: Instant,
}

/// Outcome of atomically claiming a mutating Code-root request identity.
///
/// The authority lock is intentionally released before the route performs
/// asynchronous session or projection work.  While that work is pending, a
/// matching retry must not manufacture a second result; once the receipt is
/// recorded it can instead replay the first result.
#[derive(Debug)]
pub(crate) enum CodeRootRequestStart<T> {
    Started,
    Replayed(T),
    /// A create request installed its session worker before the response
    /// receipt was completed.  Retrying this exact request must finish that
    /// root, never manufacture another one.
    Recovering(proto::CodeRootIdV1),
    InFlight,
}

#[derive(Debug, Clone)]
struct CodeRootRequestInFlight {
    fingerprint: [u8; 32],
    created_root_id: Option<proto::CodeRootIdV1>,
    started_at: Instant,
}

#[derive(Debug, Clone)]
struct DiscoverySnapshot {
    workspace_path: String,
    logical_client_id: proto::OpaqueAsciiId128V1,
    roots: Vec<proto::CodeRootSummaryV1>,
    offset: usize,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub(crate) struct CodeRootAuthorityV1 {
    attachments: HashMap<String, CodeRootAttachmentRecord>,
    idempotency: HashMap<(String, String, &'static str), IdempotencyReceipt>,
    discovery: HashMap<String, DiscoverySnapshot>,
    attachment_reservations: HashSet<String>,
    code_root_requests_in_flight: HashMap<(String, String, &'static str), CodeRootRequestInFlight>,
    interrupt_resolutions_in_flight: HashSet<(String, String)>,
}

impl CodeRootAuthorityV1 {
    fn reap_expired(&mut self, now: Instant) {
        self.attachments.retain(|_, record| {
            record.open
                || record.closed_at.is_some_and(|closed_at| {
                    now.duration_since(closed_at) < ATTACHMENT_TOMBSTONE_TTL
                })
        });
        self.idempotency
            .retain(|_, receipt| now.duration_since(receipt.recorded_at) < IDEMPOTENCY_RECEIPT_TTL);
        self.code_root_requests_in_flight
            .retain(|_, request| now.duration_since(request.started_at) < IDEMPOTENCY_RECEIPT_TTL);
        self.discovery
            .retain(|_, snapshot| now < snapshot.expires_at);
    }

    pub fn reserve_new_attachment(&mut self) -> Result<String> {
        self.reap_expired(Instant::now());
        let open_attachments = self
            .attachments
            .values()
            .filter(|record| record.open)
            .count();
        if open_attachments + self.attachment_reservations.len() >= MAX_ATTACHMENTS {
            bail!("Code-root attachment capacity exhausted");
        }
        if self.idempotency.len() + self.attachment_reservations.len() >= MAX_IDEMPOTENCY_RECEIPTS {
            bail!("Code-root idempotency capacity exhausted");
        }
        let reservation = Uuid::new_v4().simple().to_string();
        self.attachment_reservations.insert(reservation.clone());
        Ok(reservation)
    }

    pub fn release_attachment_reservation(&mut self, reservation: &str) {
        self.attachment_reservations.remove(reservation);
    }

    fn start_request(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        client_request_id: &proto::OpaqueAsciiId128V1,
        route: &'static str,
        fingerprint: [u8; 32],
    ) -> Result<CodeRootRequestStart<IdempotencyResult>> {
        self.reap_expired(Instant::now());
        if let Some(result) =
            self.replay(logical_client_id, client_request_id, route, fingerprint)?
        {
            return Ok(CodeRootRequestStart::Replayed(result));
        }

        let key = (
            logical_client_id.as_str().to_owned(),
            client_request_id.as_str().to_owned(),
            route,
        );
        if let Some(in_flight) = self.code_root_requests_in_flight.get(&key) {
            if in_flight.fingerprint != fingerprint {
                bail!("Code-root idempotency conflict");
            }
            if let Some(root_id) = in_flight.created_root_id {
                return Ok(CodeRootRequestStart::Recovering(root_id));
            }
            return Ok(CodeRootRequestStart::InFlight);
        }
        self.code_root_requests_in_flight.insert(
            key,
            CodeRootRequestInFlight {
                fingerprint,
                created_root_id: None,
                started_at: Instant::now(),
            },
        );
        Ok(CodeRootRequestStart::Started)
    }

    pub fn start_create(
        &mut self,
        request: &proto::CreateCodeRootV1Request,
    ) -> Result<CodeRootRequestStart<proto::CreateCodeRootV1Result>> {
        match self.start_request(
            &request.logical_client_id,
            &request.client_request_id,
            "create",
            request_fingerprint(request)?,
        )? {
            CodeRootRequestStart::Started => Ok(CodeRootRequestStart::Started),
            CodeRootRequestStart::InFlight => Ok(CodeRootRequestStart::InFlight),
            CodeRootRequestStart::Replayed(IdempotencyResult::Create(result)) => Ok(
                CodeRootRequestStart::Replayed(self.refresh_replayed_create(request, result)?),
            ),
            CodeRootRequestStart::Recovering(root_id) => {
                Ok(CodeRootRequestStart::Recovering(root_id))
            }
            CodeRootRequestStart::Replayed(_) => bail!("invalid Code-root idempotency receipt"),
        }
    }

    pub fn start_attach(
        &mut self,
        request: &proto::AttachExistingCodeRootV1Request,
    ) -> Result<CodeRootRequestStart<proto::AttachExistingCodeRootV1Result>> {
        match self.start_request(
            &request.logical_client_id,
            &request.client_request_id,
            "attach",
            request_fingerprint(request)?,
        )? {
            CodeRootRequestStart::Started => Ok(CodeRootRequestStart::Started),
            CodeRootRequestStart::InFlight => Ok(CodeRootRequestStart::InFlight),
            CodeRootRequestStart::Replayed(IdempotencyResult::Attach(result)) => Ok(
                CodeRootRequestStart::Replayed(self.refresh_replayed_attach(request, result)?),
            ),
            CodeRootRequestStart::Recovering(_) => {
                bail!("invalid recovered Code-root attach request")
            }
            CodeRootRequestStart::Replayed(_) => bail!("invalid Code-root idempotency receipt"),
        }
    }

    pub fn finish_code_root_request(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        client_request_id: &proto::OpaqueAsciiId128V1,
        route: &'static str,
    ) {
        self.code_root_requests_in_flight.remove(&(
            logical_client_id.as_str().to_owned(),
            client_request_id.as_str().to_owned(),
            route,
        ));
    }

    /// An unbound request has not created a root, so it is safe to let an
    /// error/cancellation relinquish its identity.  Once `created_root_id` is
    /// bound, keep the fence until its receipt is completed (or expires): an
    /// exact retry will recover that root rather than create a second one.
    pub fn abandon_unbound_code_root_request(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        client_request_id: &proto::OpaqueAsciiId128V1,
        route: &'static str,
    ) {
        let key = (
            logical_client_id.as_str().to_owned(),
            client_request_id.as_str().to_owned(),
            route,
        );
        if self
            .code_root_requests_in_flight
            .get(&key)
            .is_some_and(|request| request.created_root_id.is_none())
        {
            self.code_root_requests_in_flight.remove(&key);
        }
    }

    pub fn bind_created_root(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        client_request_id: &proto::OpaqueAsciiId128V1,
        root_id: proto::CodeRootIdV1,
    ) -> Result<()> {
        let key = (
            logical_client_id.as_str().to_owned(),
            client_request_id.as_str().to_owned(),
            "create",
        );
        let request = self
            .code_root_requests_in_flight
            .get_mut(&key)
            .context("Code-root create request is no longer in flight")?;
        if let Some(existing) = request.created_root_id {
            anyhow::ensure!(
                existing == root_id,
                "Code-root create request recovered a different root"
            );
        } else {
            request.created_root_id = Some(root_id);
        }
        Ok(())
    }

    /// Serializes one logical interrupt resolution until its durable receipt
    /// is written. A concurrent retry never gets to manufacture a competing
    /// terminal result while the original worker call is still in flight.
    pub fn begin_interrupt_resolution(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        client_request_id: &proto::OpaqueAsciiId128V1,
    ) -> bool {
        self.interrupt_resolutions_in_flight.insert((
            logical_client_id.as_str().to_owned(),
            client_request_id.as_str().to_owned(),
        ))
    }

    pub fn finish_interrupt_resolution(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        client_request_id: &proto::OpaqueAsciiId128V1,
    ) {
        self.interrupt_resolutions_in_flight.remove(&(
            logical_client_id.as_str().to_owned(),
            client_request_id.as_str().to_owned(),
        ));
    }

    pub fn preflight_idempotency(&mut self) -> Result<()> {
        self.reap_expired(Instant::now());
        if self.idempotency.len() >= MAX_IDEMPOTENCY_RECEIPTS {
            bail!("Code-root idempotency capacity exhausted");
        }
        Ok(())
    }

    pub fn capture_generation_for(&self, root_id: proto::CodeRootIdV1) -> u64 {
        root_id.capture_generation()
    }

    pub fn validate_capture_generation(
        &mut self,
        root_id: proto::CodeRootIdV1,
        capture_generation: u64,
    ) -> Result<()> {
        let current = self.capture_generation_for(root_id);
        if current != capture_generation {
            bail!("stale Code-root capture generation");
        }
        Ok(())
    }

    pub fn mint_attachment(
        &mut self,
        root_id: proto::CodeRootIdV1,
        logical_client_id: proto::OpaqueAsciiId128V1,
        capture_generation: u64,
        replay_cursor: proto::CodeRootReplayCursorV1,
        reservation: &str,
    ) -> Result<proto::CodeRootAttachmentV1> {
        if !self.attachment_reservations.remove(reservation) {
            bail!("unknown Code-root attachment reservation");
        }
        debug_assert_eq!(capture_generation, self.capture_generation_for(root_id));
        let capability = proto::CodeRootAttachmentCapabilityV1::from_daemon_random(Uuid::new_v4());
        self.attachments.insert(
            capability.expose_opaque().to_owned(),
            CodeRootAttachmentRecord {
                root_id,
                logical_client_id,
                capture_generation,
                replay_cursor: replay_cursor.clone(),
                open: true,
                closed_at: None,
            },
        );
        Ok(proto::CodeRootAttachmentV1 {
            root_id,
            attachment_capability: capability,
            capture_generation,
            replay_cursor,
        })
    }

    fn refresh_replayed_create(
        &mut self,
        request: &proto::CreateCodeRootV1Request,
        mut result: proto::CreateCodeRootV1Result,
    ) -> Result<proto::CreateCodeRootV1Result> {
        self.reissue_receipt_attachment(&request.logical_client_id, &mut result.attachment)?;
        self.replace_replay_result(
            &request.logical_client_id,
            &request.client_request_id,
            "create",
            IdempotencyResult::Create(result.clone()),
        )?;
        Ok(result)
    }

    fn refresh_replayed_attach(
        &mut self,
        request: &proto::AttachExistingCodeRootV1Request,
        mut result: proto::AttachExistingCodeRootV1Result,
    ) -> Result<proto::AttachExistingCodeRootV1Result> {
        self.reissue_receipt_attachment(&request.logical_client_id, &mut result.attachment)?;
        self.replace_replay_result(
            &request.logical_client_id,
            &request.client_request_id,
            "attach",
            IdempotencyResult::Attach(result.clone()),
        )?;
        Ok(result)
    }

    /// Replays must never share an attachment capability with an uncertain
    /// original transport. Reissue one for the authenticated logical client,
    /// preserving the root and frozen response; this makes an ambiguous
    /// disconnect exactly replayable even before its teardown has drained.
    fn reissue_receipt_attachment(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        attachment: &mut proto::CodeRootAttachmentV1,
    ) -> Result<()> {
        let old = self
            .attachments
            .get(attachment.attachment_capability.expose_opaque())
            .cloned()
            .context("Code-root idempotency receipt has an unknown attachment capability")?;
        anyhow::ensure!(
            old.logical_client_id == *logical_client_id,
            "Code-root idempotency receipt belongs to a different logical client"
        );
        if old.open {
            let record = self
                .attachments
                .get_mut(attachment.attachment_capability.expose_opaque())
                .expect("cloned Code-root attachment record must still exist");
            record.open = false;
            record.closed_at = Some(Instant::now());
        }
        let open_attachments = self
            .attachments
            .values()
            .filter(|record| record.open)
            .count();
        if open_attachments >= MAX_ATTACHMENTS {
            bail!("Code-root attachment capacity exhausted");
        }
        let capability = proto::CodeRootAttachmentCapabilityV1::from_daemon_random(Uuid::new_v4());
        self.attachments.insert(
            capability.expose_opaque().to_owned(),
            CodeRootAttachmentRecord {
                root_id: old.root_id,
                logical_client_id: old.logical_client_id,
                capture_generation: old.capture_generation,
                replay_cursor: old.replay_cursor,
                open: true,
                closed_at: None,
            },
        );
        attachment.attachment_capability = capability;
        Ok(())
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
            record.closed_at = Some(Instant::now());
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
        self.reap_expired(Instant::now());
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
                expires_at: Instant::now() + DISCOVERY_SNAPSHOT_TTL,
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
        self.reap_expired(Instant::now());
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
        let key = (
            logical_client_id.as_str().to_owned(),
            client_request_id.as_str().to_owned(),
            route,
        );
        if self.idempotency.contains_key(&key) {
            bail!("Code-root idempotency conflict");
        }
        if self.idempotency.len() >= MAX_IDEMPOTENCY_RECEIPTS {
            bail!("Code-root idempotency capacity exhausted");
        }
        self.idempotency.insert(
            key,
            IdempotencyReceipt {
                fingerprint,
                result,
                recorded_at: Instant::now(),
            },
        );
        Ok(())
    }

    fn replace_replay_result(
        &mut self,
        logical_client_id: &proto::OpaqueAsciiId128V1,
        client_request_id: &proto::OpaqueAsciiId128V1,
        route: &'static str,
        result: IdempotencyResult,
    ) -> Result<()> {
        let key = (
            logical_client_id.as_str().to_owned(),
            client_request_id.as_str().to_owned(),
            route,
        );
        self.idempotency
            .get_mut(&key)
            .context("Code-root idempotency receipt disappeared during replay")?
            .result = result;
        Ok(())
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
            request_fingerprint(request)?,
            IdempotencyResult::Create(result),
        )
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
            request_fingerprint(request)?,
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
            request_fingerprint(request)?,
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
            request_fingerprint(request)?,
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
            request_fingerprint(request)?,
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
            request_fingerprint(request)?,
            IdempotencyResult::Ack(result),
        )
    }
}

pub(crate) fn request_fingerprint<T: serde::Serialize>(value: &T) -> Result<[u8; 32]> {
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
        self.write(root_id, proto::CodeRootDeliveryPayloadV1::History { entry })
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
        self.write(root_id, proto::CodeRootDeliveryPayloadV1::RootStateChanged)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_request() -> proto::CreateCodeRootV1Request {
        proto::CreateCodeRootV1Request {
            workspace_selector: proto::CodeRootWorkspaceSelectorV1 {
                path: "/workspace".to_string(),
            },
            logical_client_id: proto::OpaqueAsciiId128V1::new("client").unwrap(),
            client_request_id: proto::OpaqueAsciiId128V1::new("request").unwrap(),
            options: proto::CodeRootAttachOptionsV1 {
                initial_model: None,
                model_override: None,
                no_sandbox: false,
                interactive: false,
                client_protocol_version: proto::PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: proto::EnvDriftPolicy::Daemon,
            },
        }
    }

    fn create_result(attachment: proto::CodeRootAttachmentV1) -> proto::CreateCodeRootV1Result {
        let root_id = attachment.root_id.0;
        serde_json::from_value(serde_json::json!({
            "attachment": attachment,
            "root": {
                "root_id": root_id,
                "workspace_path": "/workspace",
                "title": null,
                "short_id": "root",
                "project_id": "project",
                "active_agent": "agent",
                "active_agent_path": ["agent"],
                "history": [],
                "daemon_version": "test",
                "compatible": true,
                "attention": []
            }
        }))
        .unwrap()
    }

    #[test]
    fn bound_create_request_recovers_the_original_root_after_cancellation() {
        let request = create_request();
        let root_id = proto::CodeRootIdV1(Uuid::new_v4());
        let mut authority = CodeRootAuthorityV1::default();

        assert!(matches!(
            authority.start_create(&request).unwrap(),
            CodeRootRequestStart::Started
        ));
        authority
            .bind_created_root(
                &request.logical_client_id,
                &request.client_request_id,
                root_id,
            )
            .unwrap();
        authority.abandon_unbound_code_root_request(
            &request.logical_client_id,
            &request.client_request_id,
            "create",
        );

        assert!(matches!(
            authority.start_create(&request).unwrap(),
            CodeRootRequestStart::Recovering(recovered) if recovered == root_id
        ));
    }

    #[test]
    fn receipt_replay_reissues_its_attachment_before_transport_teardown() {
        let request = create_request();
        let root_id = proto::CodeRootIdV1(Uuid::new_v4());
        let mut authority = CodeRootAuthorityV1::default();
        let reservation = authority.reserve_new_attachment().unwrap();
        let original = authority
            .mint_attachment(
                root_id,
                request.logical_client_id.clone(),
                root_id.capture_generation(),
                proto::CodeRootReplayCursorV1::from_daemon_random(Uuid::new_v4()),
                &reservation,
            )
            .unwrap();
        authority
            .record_create(&request, create_result(original.clone()))
            .unwrap();
        let CodeRootRequestStart::Replayed(replayed) = authority.start_create(&request).unwrap()
        else {
            panic!("receipt did not replay");
        };
        assert_ne!(
            replayed.attachment.attachment_capability,
            original.attachment_capability
        );
        authority
            .authenticate(&replayed.attachment.attachment_capability)
            .unwrap();
        assert!(
            authority
                .authenticate(&original.attachment_capability)
                .is_err()
        );
    }
}
