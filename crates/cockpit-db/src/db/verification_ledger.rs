//! Durable, daemon-owned verification ledger.
//!
//! This module is intentionally not a verifier or dispatcher. It persists the
//! redacted control plane around those volatile host activities: candidates,
//! adjudication, a prepared model-visible envelope, a host-idempotent dispatch
//! reservation, and one terminal projection. Every externally meaningful
//! mutation is one immediate SQLite transaction; raw verifier/provider data is
//! made unrepresentable by the public input types.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use crate::db::Db;

const MAX_REDACTED_JSON_BYTES: usize = 16 * 1024;
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_PROJECTED_EVENTS: usize = 16;
const MAX_CANDIDATES: i64 = 64;

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
static TEST_SETTLEMENT_FAULT: std::sync::Mutex<Option<Uuid>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn inject_settlement_fault_once(operation_id: Uuid) {
    *TEST_SETTLEMENT_FAULT
        .lock()
        .expect("verification test fault lock") = Some(operation_id);
}

#[cfg(test)]
fn fail_after_attempt_settlement_for_test(operation_id: Uuid) -> Result<()> {
    let mut fault = TEST_SETTLEMENT_FAULT
        .lock()
        .expect("verification test fault lock");
    if *fault == Some(operation_id) {
        *fault = None;
        bail!("injected verification settlement crash")
    }
    Ok(())
}

#[cfg(not(test))]
fn fail_after_attempt_settlement_for_test(_operation_id: Uuid) -> Result<()> {
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VerificationDigest(String);

impl VerificationDigest {
    pub fn of(bytes: &[u8]) -> Self {
        Self(sha256_hex(bytes))
    }

    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            value.len() == 64
                && value.bytes().all(
                    |byte| byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte <= b'f')
                ),
            "verification digest must be 64 lowercase hexadecimal characters"
        );
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for VerificationDigest {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<VerificationDigest> for String {
    fn from(value: VerificationDigest) -> Self {
        value.0
    }
}

/// Closed classifications for every durable ledger summary, receipt, and
/// proof. The database never accepts a caller-defined semantic label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationRedactionClass {
    CandidateSummary,
    SynthesisPending,
    SynthesisSelected,
    SynthesisWriteUnion,
    SynthesisRefused,
    SynthesisNoValidCandidate,
    SynthesisFailed,
    RestartAborted,
    PreDispatchCancelled,
    BudgetRefused,
    InvalidOriginal,
    DispatchSuccess,
    DispatchFinalError,
    DispatchUnknown,
    NoSubmission,
    RecoverySuccess,
    RecoveryFinalError,
}

impl VerificationRedactionClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::CandidateSummary => "candidate_summary",
            Self::SynthesisPending => "synthesis_pending",
            Self::SynthesisSelected => "synthesis_selected",
            Self::SynthesisWriteUnion => "synthesis_write_union",
            Self::SynthesisRefused => "synthesis_refused",
            Self::SynthesisNoValidCandidate => "synthesis_no_valid_candidate",
            Self::SynthesisFailed => "synthesis_failed",
            Self::RestartAborted => "restart_aborted",
            Self::PreDispatchCancelled => "pre_dispatch_cancelled",
            Self::BudgetRefused => "budget_refused",
            Self::InvalidOriginal => "invalid_original",
            Self::DispatchSuccess => "dispatch_success",
            Self::DispatchFinalError => "dispatch_final_error",
            Self::DispatchUnknown => "dispatch_unknown",
            Self::NoSubmission => "no_submission",
            Self::RecoverySuccess => "recovery_success",
            Self::RecoveryFinalError => "recovery_final_error",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "candidate_summary" => Ok(Self::CandidateSummary),
            "synthesis_pending" => Ok(Self::SynthesisPending),
            "synthesis_selected" => Ok(Self::SynthesisSelected),
            "synthesis_write_union" => Ok(Self::SynthesisWriteUnion),
            "synthesis_refused" => Ok(Self::SynthesisRefused),
            "synthesis_no_valid_candidate" => Ok(Self::SynthesisNoValidCandidate),
            "synthesis_failed" => Ok(Self::SynthesisFailed),
            "restart_aborted" => Ok(Self::RestartAborted),
            "pre_dispatch_cancelled" => Ok(Self::PreDispatchCancelled),
            "budget_refused" => Ok(Self::BudgetRefused),
            "invalid_original" => Ok(Self::InvalidOriginal),
            "dispatch_success" => Ok(Self::DispatchSuccess),
            "dispatch_final_error" => Ok(Self::DispatchFinalError),
            "dispatch_unknown" => Ok(Self::DispatchUnknown),
            "no_submission" => Ok(Self::NoSubmission),
            "recovery_success" => Ok(Self::RecoverySuccess),
            "recovery_final_error" => Ok(Self::RecoveryFinalError),
            _ => bail!("verification redaction classification is not allowed"),
        }
    }
}

/// A bounded, closed-classification digest-only ledger value. Raw
/// verifier/provider/host text remains outside SQLite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedVerificationJson {
    classification: VerificationRedactionClass,
    digest: VerificationDigest,
    encoded: String,
}

impl RedactedVerificationJson {
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            value.len() <= MAX_REDACTED_JSON_BYTES,
            "verification redacted JSON exceeds its bound"
        );
        let json: Value = serde_json::from_str(value).context("verification JSON must be valid")?;
        let object = json
            .as_object()
            .context("verification ledger value must be an object")?;
        ensure!(
            object.len() == 2
                && object.contains_key("classification")
                && object.contains_key("digest"),
            "verification ledger value must be exactly classification and digest"
        );
        let classification = object
            .get("classification")
            .and_then(Value::as_str)
            .context("verification classification must be a string")?;
        let digest = object
            .get("digest")
            .and_then(Value::as_str)
            .context("verification digest must be a string")?;
        Ok(Self::closed(
            VerificationRedactionClass::parse(classification)?,
            VerificationDigest::parse(digest)?,
        ))
    }

    /// The only host-supplied candidate summary shape.
    pub fn candidate_summary(digest: VerificationDigest) -> Self {
        Self::closed(VerificationRedactionClass::CandidateSummary, digest)
    }

    /// A terminal reason for an original descriptor which could not be used.
    pub fn invalid_original(digest: VerificationDigest) -> Self {
        Self::closed(VerificationRedactionClass::InvalidOriginal, digest)
    }

    /// A host-proven dispatch success receipt.
    pub fn dispatch_success(digest: VerificationDigest) -> Self {
        Self::closed(VerificationRedactionClass::DispatchSuccess, digest)
    }

    /// A host-proven final dispatch error receipt.
    pub fn dispatch_final_error(digest: VerificationDigest) -> Self {
        Self::closed(VerificationRedactionClass::DispatchFinalError, digest)
    }

    /// A host receipt for a dispatch whose eventual effect cannot be proven.
    pub fn dispatch_unknown(digest: VerificationDigest) -> Self {
        Self::closed(VerificationRedactionClass::DispatchUnknown, digest)
    }

    /// Evidence that no host effect was submitted.
    pub fn no_submission(digest: VerificationDigest) -> Self {
        Self::closed(VerificationRedactionClass::NoSubmission, digest)
    }

    /// Internal-only constructors are deliberately role-labelled at every
    /// callsite. Public callers cannot manufacture a generic classification.
    fn closed(classification: VerificationRedactionClass, digest: VerificationDigest) -> Self {
        let encoded = serde_json::to_string(&json!({
            "classification": classification.as_str(),
            "digest": digest.as_str(),
        }))
        .expect("closed verification redaction JSON serializes");
        Self {
            classification,
            digest,
            encoded,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    pub fn classification(&self) -> VerificationRedactionClass {
        self.classification
    }

    pub fn digest(&self) -> &VerificationDigest {
        &self.digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationOperationState {
    Created,
    Collecting,
    Synthesizing,
    Dispatching,
    Succeeded,
    Failed,
    Cancelled,
    Aborted,
    SkippedBudgetRefused,
    Unknown,
}

impl VerificationOperationState {
    pub const ALL: [Self; 10] = [
        Self::Created,
        Self::Collecting,
        Self::Synthesizing,
        Self::Dispatching,
        Self::Succeeded,
        Self::Failed,
        Self::Cancelled,
        Self::Aborted,
        Self::SkippedBudgetRefused,
        Self::Unknown,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Collecting => "collecting",
            Self::Synthesizing => "synthesizing",
            Self::Dispatching => "dispatching",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Aborted => "aborted",
            Self::SkippedBudgetRefused => "skipped_budget_refused",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "created" => Ok(Self::Created),
            "collecting" => Ok(Self::Collecting),
            "synthesizing" => Ok(Self::Synthesizing),
            "dispatching" => Ok(Self::Dispatching),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "aborted" => Ok(Self::Aborted),
            "skipped_budget_refused" => Ok(Self::SkippedBudgetRefused),
            "unknown" => Ok(Self::Unknown),
            _ => Err(invalid_value("verification operation state")),
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::Aborted
                | Self::SkippedBudgetRefused
                | Self::Unknown
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationCandidateState {
    Queued,
    Running,
    Valid,
    Invalid,
    Cancelled,
    TimedOut,
    Malformed,
}

impl VerificationCandidateState {
    pub const ALL: [Self; 7] = [
        Self::Queued,
        Self::Running,
        Self::Valid,
        Self::Invalid,
        Self::Cancelled,
        Self::TimedOut,
        Self::Malformed,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::Malformed => "malformed",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "cancelled" => Ok(Self::Cancelled),
            "timed_out" => Ok(Self::TimedOut),
            "malformed" => Ok(Self::Malformed),
            _ => Err(invalid_value("verification candidate state")),
        }
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Valid | Self::Invalid | Self::Cancelled | Self::TimedOut | Self::Malformed
        )
    }

    fn legal_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Queued,
                Self::Running | Self::Cancelled | Self::TimedOut
            ) | (
                Self::Running,
                Self::Valid | Self::Invalid | Self::Cancelled | Self::TimedOut | Self::Malformed
            )
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationArtifactKind {
    ProposedCall,
    WriteChangeSet,
}

impl VerificationArtifactKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProposedCall => "proposed_call",
            Self::WriteChangeSet => "write_change_set",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "proposed_call" => Ok(Self::ProposedCall),
            "write_change_set" => Ok(Self::WriteChangeSet),
            _ => Err(invalid_value("verification artifact kind")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationBudgetAction {
    Refuse,
    DispatchOriginal,
}

impl VerificationBudgetAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::DispatchOriginal => "dispatch_original",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationDispatchState {
    Reserved,
    Executing,
    Succeeded,
    Failed,
    Unknown,
    CancelledNoSubmission,
}

impl VerificationDispatchState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Executing => "executing",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::CancelledNoSubmission => "cancelled_no_submission",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "reserved" => Ok(Self::Reserved),
            "executing" => Ok(Self::Executing),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "unknown" => Ok(Self::Unknown),
            "cancelled_no_submission" => Ok(Self::CancelledNoSubmission),
            _ => Err(invalid_value("verification dispatch state")),
        }
    }

    fn is_terminal(self) -> bool {
        !matches!(self, Self::Reserved | Self::Executing)
    }
}

#[derive(Debug, Clone)]
pub struct NewVerificationOperation {
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub requested_candidate_count: i64,
    pub effective_candidate_count: i64,
    pub total_token_ceiling: i64,
    pub estimated_cost_ceiling_microunits: i64,
    pub collection_deadline_unix_ms: i64,
    pub collection_duration_ms: i64,
    pub conservative_token_reservation: i64,
    pub conservative_cost_reservation_microunits: i64,
    pub original_operation_digest: VerificationDigest,
    /// Digest-only anchor for the immutable pre-tool context/cache capability.
    pub pretool_context_capability_digest: VerificationDigest,
    /// `None` is a normal estimable request; `Some` makes the pre-candidate
    /// branch explicit and therefore impossible to silently fall back later.
    pub estimate_unavailable_action: Option<VerificationBudgetAction>,
}

#[derive(Debug, Clone)]
pub struct NewVerificationCandidate {
    pub artifact_kind: VerificationArtifactKind,
    pub canonical_call_digest: VerificationDigest,
    pub artifact_union_digest: VerificationDigest,
    pub redacted_summary: RedactedVerificationJson,
    pub reserved_tokens: i64,
    pub reserved_cost_microunits: i64,
    pub artifact_members: Vec<VerificationArtifactMember>,
}

/// SQL row shape for one persisted, digest-only write artifact member.  A
/// named alias keeps the storage tuple local without promoting raw columns to
/// the host-facing ledger API.
type PersistedVerificationArtifact = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Digest-only write metadata. A member represents one add/delete/modify/
/// rename/mode operation and never a raw path, diff, binary payload, or mode.
#[derive(Debug, Clone)]
pub struct VerificationArtifactMember {
    pub operation_kind: VerificationArtifactOperation,
    pub affected_path_digest: VerificationDigest,
    pub prior_path_digest: Option<VerificationDigest>,
    pub content_digest: Option<VerificationDigest>,
    pub binary_metadata_digest: Option<VerificationDigest>,
    pub mode_digest: Option<VerificationDigest>,
}

/// A single output member of a synthesized write, represented only by a
/// stable reference to the digest-only metadata of a valid source candidate.
/// The host must provide one entry for every output operation; this API does
/// not accept raw paths, patches, or generated content.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerificationSynthesisArtifactSource {
    pub candidate_id: Uuid,
    pub artifact_ordinal: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationArtifactOperation {
    Add,
    Delete,
    Modify,
    Rename,
    Mode,
}

impl VerificationArtifactOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Delete => "delete",
            Self::Modify => "modify",
            Self::Rename => "rename",
            Self::Mode => "mode",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerificationOperationRow {
    pub operation_id: Uuid,
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub state: VerificationOperationState,
    pub revision: i64,
    pub collection_closed_at_unix_ms: Option<i64>,
    pub collection_revision: i64,
    pub original_operation_digest: VerificationDigest,
    pub pretool_context_capability_digest: VerificationDigest,
    pub budget_action: Option<VerificationBudgetAction>,
}

#[derive(Debug, Clone)]
pub struct VerificationCandidateRow {
    pub candidate_id: Uuid,
    pub operation_id: Uuid,
    pub session_id: Uuid,
    pub artifact_kind: VerificationArtifactKind,
    pub canonical_call_digest: VerificationDigest,
    pub artifact_union_digest: VerificationDigest,
    pub state: VerificationCandidateState,
    pub revision: i64,
}

#[derive(Debug, Clone)]
pub struct VerificationDispatchAttemptRow {
    pub attempt_id: Uuid,
    pub operation_id: Uuid,
    pub session_id: Uuid,
    pub host_idempotency_key: String,
    pub dispatch_digest: VerificationDigest,
    pub state: VerificationDispatchState,
    /// Present only after a terminal host settlement. This remains a closed,
    /// digest-only receipt and lets a same-key host retry replay the durable
    /// terminal result without re-dispatching.
    pub terminal_receipt: Option<RedactedVerificationJson>,
    pub revision: i64,
}

/// Host-only result of write adjudication. The batch digest is derived from
/// the durable ordered artifact union and is the only value a later dispatch
/// reservation may use for a synthesized write.
#[derive(Debug, Clone)]
pub struct VerificationWriteSynthesisResult {
    pub operation: VerificationOperationRow,
    pub canonical_output_batch_digest: VerificationDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateTransitionOutcome {
    Transitioned,
    LateResult,
    AlreadyTerminal,
    RevisionConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchSettlement {
    Succeeded,
    Failed,
    Unknown,
    CancelledNoSubmission,
}

/// Typed evidence that a reservation was never handed to an effect executor.
/// Keeping it distinct from an ordinary terminal receipt prevents an unknown
/// effect from being silently reclassified as a safe cancellation.
#[derive(Debug, Clone)]
pub struct NoSubmissionProof(RedactedVerificationJson);

impl NoSubmissionProof {
    pub fn from_digest(digest: VerificationDigest) -> Self {
        Self(RedactedVerificationJson::no_submission(digest))
    }

    pub fn parse(value: RedactedVerificationJson) -> Result<Self> {
        ensure!(
            value.classification() == VerificationRedactionClass::NoSubmission,
            "verification no-submission proof requires its typed classification"
        );
        Ok(Self(value))
    }

    fn receipt(&self) -> &RedactedVerificationJson {
        &self.0
    }
}

#[derive(Debug, Clone)]
struct VerificationProjectionEvent {
    /// A normal session event discriminant. Only safe ordinary projection
    /// kinds are allowed here; provider/verifier event classes never reach the
    /// model-visible history.
    event_kind: &'static str,
    /// Correlates a normal surrogate call with its terminal result. Recovery
    /// derives this from the durable prepared-projection identity.
    call_id: Option<String>,
    data: VerificationProjectionPayload,
}

/// A projection payload is either a classified result or a model-safe
/// surrogate call reconstructed by this module. The call representation has
/// no public constructor: callers cannot smuggle arbitrary event JSON into a
/// committed session event.
#[derive(Debug, Clone)]
enum VerificationProjectionPayload {
    Redacted(RedactedVerificationJson),
    SurrogateCall(VerificationSurrogateCall),
}

impl VerificationProjectionPayload {
    fn as_json(&self) -> Result<Value> {
        match self {
            Self::Redacted(value) => serde_json::from_str(value.as_str())
                .context("stored verification projection result is invalid"),
            Self::SurrogateCall(call) => call.as_json(),
        }
    }
}

/// Strict, bounded normal-call payload retained in a prepared envelope. The
/// encoded value contains only operation/arguments/patch and is built only
/// after envelope validation.
#[derive(Debug, Clone)]
struct VerificationSurrogateCall {
    encoded: String,
}

impl VerificationSurrogateCall {
    fn from_model_visible(value: &Value) -> Result<Self> {
        let object = value
            .as_object()
            .context("verification model-visible envelope must be an object")?;
        ensure!(
            object
                .keys()
                .all(|key| matches!(key.as_str(), "operation" | "arguments" | "patch")),
            "verification model-visible envelope has a non-surrogate field"
        );
        let operation = object
            .get("operation")
            .and_then(Value::as_str)
            .context("verification model-visible envelope requires an operation")?;
        ensure!(
            !operation.is_empty()
                && operation.len() <= 128
                && operation.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/')
                }),
            "verification surrogate operation is not a safe identifier"
        );
        if let Some(arguments) = object.get("arguments") {
            ensure!(
                arguments.is_object() || arguments.is_array() || arguments.is_null(),
                "verification surrogate arguments must be object, array, or null"
            );
        }
        if let Some(patch) = object.get("patch") {
            ensure!(
                patch.is_string(),
                "verification surrogate patch must be a string"
            );
        }
        validate_redacted_value(value, true)?;
        let mut call = serde_json::Map::new();
        call.insert("verification_surrogate".to_owned(), Value::Bool(true));
        call.insert("operation".to_owned(), Value::String(operation.to_owned()));
        if let Some(arguments) = object.get("arguments") {
            call.insert("arguments".to_owned(), arguments.clone());
        }
        if let Some(patch) = object.get("patch") {
            call.insert("patch".to_owned(), patch.clone());
        }
        Ok(Self {
            encoded: canonical_model_visible_json(&Value::Object(call))?,
        })
    }

    fn as_json(&self) -> Result<Value> {
        serde_json::from_str(&self.encoded).context("stored verification surrogate call is invalid")
    }
}

#[derive(Debug, Clone)]
pub struct NewVerificationEnvelope {
    pub batch_digest: VerificationDigest,
    pub surrogate_kind: VerificationArtifactKind,
    /// This is the one intentionally bounded model-visible payload. It may
    /// carry selected call arguments or a patch body, but cannot carry receipt,
    /// provider, verifier, or evidence fields.
    pub model_visible_projection: Value,
}

impl Db {
    /// Host-only creation boundary. No agent/root/subagent-facing read or
    /// write API is exposed from this module.
    pub async fn create_verification_operation(
        &self,
        input: NewVerificationOperation,
        now_unix_ms: i64,
    ) -> Result<VerificationOperationRow> {
        validate_operation_input(&input)?;
        let operation_id = Uuid::new_v4();
        self.transaction(move |conn| {
            ensure_agent_in_session(conn, input.session_id, input.agent_instance_id)?;
            let (state, estimate_state, budget_action) = match input.estimate_unavailable_action {
                None => (VerificationOperationState::Created, "available", None),
                Some(VerificationBudgetAction::Refuse) => (
                    VerificationOperationState::SkippedBudgetRefused,
                    "estimate_unavailable",
                    Some(VerificationBudgetAction::Refuse),
                ),
                Some(VerificationBudgetAction::DispatchOriginal) => (
                    VerificationOperationState::Created,
                    "estimate_unavailable",
                    Some(VerificationBudgetAction::DispatchOriginal),
                ),
            };
            conn.execute(
                "INSERT INTO verification_operations (
                    operation_id, session_id, agent_instance_id, requested_candidate_count,
                    effective_candidate_count, total_token_ceiling,
                    estimated_cost_ceiling_microunits, cost_unit,
                    collection_deadline_unix_ms, collection_duration_ms,
                    conservative_token_reservation, conservative_cost_reservation_microunits,
                    estimate_state, budget_action, original_operation_digest, pretool_context_capability_digest, state, revision,
                    created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'microusd', ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, 0, ?17, ?17)",
                params![
                    operation_id.to_string(), input.session_id.to_string(), input.agent_instance_id.to_string(),
                    input.requested_candidate_count, input.effective_candidate_count,
                    input.total_token_ceiling, input.estimated_cost_ceiling_microunits,
                    input.collection_deadline_unix_ms, input.collection_duration_ms,
                    input.conservative_token_reservation, input.conservative_cost_reservation_microunits,
                    estimate_state, budget_action.map(VerificationBudgetAction::as_str),
                    input.original_operation_digest.as_str(), input.pretool_context_capability_digest.as_str(), state.as_str(), now_unix_ms,
                ],
            )?;
            if state == VerificationOperationState::SkippedBudgetRefused {
                insert_suppressed_projection_conn(
                    conn, input.session_id, operation_id,
                    VerificationDigest::of(b"verification-budget-refused"), now_unix_ms,
                )?;
            }
            load_operation(conn, input.session_id, operation_id)?.context("created verification operation missing")
        }).await
    }

    pub async fn start_verification_collection(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_revision: i64,
        now_unix_ms: i64,
    ) -> Result<VerificationOperationRow> {
        self.transaction(move |conn| {
            let operation = required_operation(conn, session_id, operation_id)?;
            if operation.state.is_terminal()
                || matches!(
                    operation.state,
                    VerificationOperationState::Collecting
                        | VerificationOperationState::Synthesizing
                        | VerificationOperationState::Dispatching
                )
            {
                return Ok(operation);
            }
            ensure!(
                operation.state == VerificationOperationState::Created,
                "verification operation is not ready to collect"
            );
            ensure!(
                operation.revision == expected_revision,
                "verification operation revision conflict"
            );
            if operation.budget_action == Some(VerificationBudgetAction::DispatchOriginal) {
                set_operation_state(
                    conn,
                    session_id,
                    operation_id,
                    expected_revision,
                    VerificationOperationState::Dispatching,
                    now_unix_ms,
                )?;
            } else if now_unix_ms >= operation_deadline(conn, operation_id)? {
                // Starting at the exact deadline cannot leave a transient
                // collecting state behind. Advance through Collecting inside
                // this one transaction so the normal close path owns the
                // collection timestamp/revision, candidate timeout sweep, and
                // one pending synthesis row.
                set_operation_state(
                    conn,
                    session_id,
                    operation_id,
                    expected_revision,
                    VerificationOperationState::Collecting,
                    now_unix_ms,
                )?;
                let collecting = required_operation(conn, session_id, operation_id)?;
                close_collection_conn(
                    conn,
                    session_id,
                    operation_id,
                    collecting.revision,
                    now_unix_ms,
                )?;
            } else {
                set_operation_state(
                    conn,
                    session_id,
                    operation_id,
                    expected_revision,
                    VerificationOperationState::Collecting,
                    now_unix_ms,
                )?;
            }
            required_operation(conn, session_id, operation_id)
        })
        .await
    }

    /// Terminalizes a pre-candidate operation whose original descriptor could
    /// not be used. This is deliberately separate from candidate adjudication:
    /// no candidate, synthesis, envelope, or projected event may be created on
    /// this branch.
    pub async fn fail_verification_pre_collection(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_revision: i64,
        failure: RedactedVerificationJson,
        now_unix_ms: i64,
    ) -> Result<VerificationOperationRow> {
        self.transaction(move |conn| {
            ensure!(
                failure.classification() == VerificationRedactionClass::InvalidOriginal,
                "pre-collection verification failure needs an invalid-original receipt"
            );
            let operation = required_operation(conn, session_id, operation_id)?;
            if operation.state.is_terminal() {
                return Ok(operation);
            }
            ensure!(
                operation.state == VerificationOperationState::Created,
                "verification operation is not pre-collection"
            );
            ensure!(
                operation.revision == expected_revision,
                "verification operation revision conflict"
            );
            set_operation_state(
                conn,
                session_id,
                operation_id,
                expected_revision,
                VerificationOperationState::Failed,
                now_unix_ms,
            )?;
            insert_suppressed_projection_with_receipt_conn(
                conn,
                session_id,
                operation_id,
                VerificationDigest::of(b"verification-invalid-original"),
                Some(&failure),
                now_unix_ms,
            )?;
            required_operation(conn, session_id, operation_id)
        })
        .await
    }

    /// Atomically cancels work before any external dispatch exists. The
    /// operation, active candidates, and pending adjudication (when present)
    /// are terminalized with the one zero-effect projection in one CAS.
    pub async fn cancel_verification_pre_dispatch(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_revision: i64,
        now_unix_ms: i64,
    ) -> Result<VerificationOperationRow> {
        self.transaction(move |conn| {
            let operation = required_operation(conn, session_id, operation_id)?;
            if operation.state.is_terminal() {
                return Ok(operation);
            }
            ensure!(
                matches!(
                    operation.state,
                    VerificationOperationState::Collecting | VerificationOperationState::Synthesizing
                ),
                "verification operation is not eligible for pre-dispatch cancellation"
            );
            ensure!(operation.revision == expected_revision, "verification operation revision conflict");
            conn.execute(
                "UPDATE verification_candidates SET state = 'cancelled', revision = revision + 1, updated_at_unix_ms = ?1
                 WHERE operation_id = ?2 AND session_id = ?3 AND state IN ('queued', 'running')",
                params![now_unix_ms, operation_id.to_string(), session_id.to_string()],
            )?;
            if operation.state == VerificationOperationState::Synthesizing {
                transition_synthesis_conn(
                    conn,
                    session_id,
                    operation_id,
                    "refused",
                    None,
                    None,
                    None,
                    None,
                    RedactedVerificationJson::closed(
                        VerificationRedactionClass::PreDispatchCancelled,
                        VerificationDigest::of(b"verification-cancelled"),
                    ),
                    now_unix_ms,
                )?;
            }
            set_operation_state(
                conn,
                session_id,
                operation_id,
                expected_revision,
                VerificationOperationState::Cancelled,
                now_unix_ms,
            )?;
            insert_suppressed_projection_conn(
                conn,
                session_id,
                operation_id,
                VerificationDigest::of(b"verification-pre-dispatch-cancelled"),
                now_unix_ms,
            )?;
            required_operation(conn, session_id, operation_id)
        })
        .await
    }

    pub async fn reserve_verification_candidate(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        candidate: NewVerificationCandidate,
        now_unix_ms: i64,
    ) -> Result<VerificationCandidateRow> {
        validate_candidate_input(&candidate)?;
        let candidate_id = Uuid::new_v4();
        let row = self.transaction(move |conn| {
            let operation = required_operation(conn, session_id, operation_id)?;
            ensure!(operation.state == VerificationOperationState::Collecting, "verification operation is not collecting");
            if now_unix_ms >= operation_deadline(conn, operation_id)? {
                close_collection_conn(conn, session_id, operation_id, operation.revision, now_unix_ms)?;
                return Ok(None);
            }
            ensure!(operation.collection_closed_at_unix_ms.is_none(), "verification collection is closed");
            let (count, tokens, cost): (i64, i64, i64) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(reserved_tokens), 0), COALESCE(SUM(reserved_cost_microunits), 0)
                 FROM verification_candidates WHERE operation_id = ?1",
                [operation_id.to_string()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            ensure!(count < MAX_CANDIDATES && count < operation_effective_candidates(conn, operation_id)?, "verification candidate ceiling reached");
            let (token_ceiling, cost_ceiling) = operation_budget_ceilings(conn, operation_id)?;
            ensure!(tokens.checked_add(candidate.reserved_tokens).is_some_and(|value| value <= token_ceiling), "verification token reservation exceeds ceiling");
            ensure!(cost.checked_add(candidate.reserved_cost_microunits).is_some_and(|value| value <= cost_ceiling), "verification cost reservation exceeds ceiling");
            conn.execute(
                "INSERT INTO verification_candidates (
                    candidate_id, operation_id, session_id, artifact_kind, canonical_call_digest,
                    artifact_union_digest, redacted_summary_json, reserved_tokens,
                    reserved_cost_microunits, state, revision, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'queued', 0, ?10, ?10)",
                params![candidate_id.to_string(), operation_id.to_string(), session_id.to_string(),
                    candidate.artifact_kind.as_str(), candidate.canonical_call_digest.as_str(),
                    candidate.artifact_union_digest.as_str(), candidate.redacted_summary.as_str(),
                    candidate.reserved_tokens, candidate.reserved_cost_microunits, now_unix_ms],
            )?;
            for (ordinal, member) in candidate.artifact_members.iter().enumerate() {
                conn.execute(
                    "INSERT INTO verification_candidate_artifacts (
                        candidate_id, operation_id, session_id, ordinal, operation_kind,
                        affected_path_digest, prior_path_digest, content_digest,
                        binary_metadata_digest, mode_digest
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        candidate_id.to_string(), operation_id.to_string(), session_id.to_string(), ordinal as i64,
                        member.operation_kind.as_str(), member.affected_path_digest.as_str(),
                        member.prior_path_digest.as_ref().map(VerificationDigest::as_str),
                        member.content_digest.as_ref().map(VerificationDigest::as_str),
                        member.binary_metadata_digest.as_ref().map(VerificationDigest::as_str),
                        member.mode_digest.as_ref().map(VerificationDigest::as_str),
                    ],
                )?;
            }
            Ok(Some(required_candidate(conn, session_id, operation_id, candidate_id)?))
        }).await?;
        row.context("verification collection deadline closed before candidate reservation")
    }

    // Candidate transition is the public CAS boundary: operation/candidate
    // identity, revision, proposed terminal state, immutable late evidence,
    // and clock must remain independently visible to callers.
    #[allow(clippy::too_many_arguments)]
    pub async fn transition_verification_candidate(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        candidate_id: Uuid,
        expected_revision: i64,
        next: VerificationCandidateState,
        late_result_digest: VerificationDigest,
        now_unix_ms: i64,
    ) -> Result<CandidateTransitionOutcome> {
        self.transaction(move |conn| {
            let operation = required_operation(conn, session_id, operation_id)?;
            let candidate = required_candidate(conn, session_id, operation_id, candidate_id)?;
            // The deadline winner closes before *every* attempted candidate
            // transition. This prevents a queued worker from claiming
            // `queued -> running` at the exact deadline; terminal reports are
            // retained only as immutable late evidence.
            if operation.collection_closed_at_unix_ms.is_some()
                || now_unix_ms >= operation_deadline(conn, operation_id)?
            {
                if operation.collection_closed_at_unix_ms.is_none() {
                    close_collection_conn(
                        conn,
                        session_id,
                        operation_id,
                        operation.revision,
                        now_unix_ms,
                    )?;
                }
                if next.is_terminal() {
                    insert_late_result_conn(
                        conn,
                        session_id,
                        operation_id,
                        candidate_id,
                        next,
                        late_result_digest,
                        now_unix_ms,
                    )?;
                    return Ok(CandidateTransitionOutcome::LateResult);
                }
                return Ok(CandidateTransitionOutcome::AlreadyTerminal);
            }
            if candidate.state.is_terminal() {
                if next.is_terminal() {
                    insert_late_result_conn(
                        conn,
                        session_id,
                        operation_id,
                        candidate_id,
                        next,
                        late_result_digest,
                        now_unix_ms,
                    )?;
                    return Ok(CandidateTransitionOutcome::LateResult);
                }
                return Ok(CandidateTransitionOutcome::AlreadyTerminal);
            }
            if candidate.revision != expected_revision {
                return Ok(CandidateTransitionOutcome::RevisionConflict);
            }
            ensure!(candidate.state.legal_transition(next), "illegal verification candidate transition");
            let changed = conn.execute(
                "UPDATE verification_candidates SET state = ?1, revision = revision + 1, updated_at_unix_ms = ?2
                 WHERE candidate_id = ?3 AND operation_id = ?4 AND session_id = ?5 AND revision = ?6",
                params![next.as_str(), now_unix_ms, candidate_id.to_string(), operation_id.to_string(), session_id.to_string(), expected_revision],
            )?;
            ensure!(changed == 1, "verification candidate revision conflict");
            Ok(CandidateTransitionOutcome::Transitioned)
        }).await
    }

    pub async fn close_verification_collection(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_revision: i64,
        now_unix_ms: i64,
    ) -> Result<VerificationOperationRow> {
        self.transaction(move |conn| {
            close_collection_conn(
                conn,
                session_id,
                operation_id,
                expected_revision,
                now_unix_ms,
            )?;
            required_operation(conn, session_id, operation_id)
        })
        .await
    }

    pub async fn select_verification_candidate(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_revision: i64,
        candidate_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<VerificationOperationRow> {
        self.transaction(move |conn| {
            let operation = required_operation(conn, session_id, operation_id)?;
            ensure!(
                operation.state == VerificationOperationState::Synthesizing,
                "verification operation is not synthesizing"
            );
            ensure!(
                operation.revision == expected_revision,
                "verification operation revision conflict"
            );
            ensure!(
                operation.collection_closed_at_unix_ms.is_some(),
                "verification collection must close before adjudication"
            );
            let candidate = required_candidate(conn, session_id, operation_id, candidate_id)?;
            ensure!(
                candidate.state == VerificationCandidateState::Valid,
                "selected verification candidate is not valid"
            );
            ensure!(
                candidate.artifact_kind == VerificationArtifactKind::ProposedCall,
                "write candidates require synthesized-write adjudication"
            );
            ensure!(
                candidate.canonical_call_digest == operation.original_operation_digest,
                "selected non-write candidate changes canonical call bytes"
            );
            transition_synthesis_conn(
                conn,
                session_id,
                operation_id,
                "selected",
                Some(candidate_id),
                Some(VerificationArtifactKind::ProposedCall),
                Some(candidate.canonical_call_digest),
                None,
                RedactedVerificationJson::closed(
                    VerificationRedactionClass::SynthesisSelected,
                    VerificationDigest::of(b"verification-selected"),
                ),
                now_unix_ms,
            )?;
            set_operation_state(
                conn,
                session_id,
                operation_id,
                expected_revision,
                VerificationOperationState::Dispatching,
                now_unix_ms,
            )?;
            required_operation(conn, session_id, operation_id)
        })
        .await
    }

    pub async fn synthesize_verification_write(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_revision: i64,
        source_artifacts: Vec<VerificationSynthesisArtifactSource>,
        now_unix_ms: i64,
    ) -> Result<VerificationWriteSynthesisResult> {
        self.transaction(move |conn| {
            let operation = required_operation(conn, session_id, operation_id)?;
            ensure!(
                operation.state == VerificationOperationState::Synthesizing,
                "verification operation is not synthesizing"
            );
            ensure!(
                operation.revision == expected_revision,
                "verification operation revision conflict"
            );
            ensure!(
                operation.collection_closed_at_unix_ms.is_some(),
                "verification collection must close before adjudication"
            );
            ensure!(
                !source_artifacts.is_empty()
                    && source_artifacts.len() <= MAX_CANDIDATES as usize,
                "write synthesis requires bounded artifact sources"
            );
            let mut unique_sources = BTreeSet::new();
            let mut canonical_union = Vec::with_capacity(source_artifacts.len());
            for source in &source_artifacts {
                ensure!(source.artifact_ordinal >= 0, "write synthesis artifact ordinal is invalid");
                ensure!(unique_sources.insert(source.clone()), "write synthesis repeats an artifact source");
                let candidate = required_candidate(conn, session_id, operation_id, source.candidate_id)?;
                ensure!(
                    candidate.state == VerificationCandidateState::Valid,
                    "write synthesis source candidate is not valid"
                );
                ensure!(
                    candidate.artifact_kind == VerificationArtifactKind::WriteChangeSet,
                    "write synthesis source is not a write change set"
                );
                let artifact: Option<PersistedVerificationArtifact> = conn.query_row(
                    "SELECT operation_kind, affected_path_digest, prior_path_digest, content_digest,
                            binary_metadata_digest, mode_digest
                     FROM verification_candidate_artifacts
                     WHERE candidate_id = ?1 AND ordinal = ?2 AND operation_id = ?3 AND session_id = ?4",
                    params![source.candidate_id.to_string(), source.artifact_ordinal, operation_id.to_string(), session_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
                ).optional()?;
                let artifact = artifact.context("write synthesis output is outside its candidate artifact union")?;
                canonical_union.push(json!({
                    "source_candidate_id": source.candidate_id.to_string(),
                    "source_artifact_ordinal": source.artifact_ordinal,
                    "operation_kind": artifact.0,
                    "affected_path_digest": artifact.1,
                    "prior_path_digest": artifact.2,
                    "content_digest": artifact.3,
                    "binary_metadata_digest": artifact.4,
                    "mode_digest": artifact.5,
                }));
            }
            let union_receipt_digest = VerificationDigest::of(
                canonical_model_visible_json(&Value::Array(canonical_union))?.as_bytes(),
            );
            let synthesis_id = transition_synthesis_conn(
                conn,
                session_id,
                operation_id,
                "synthesized_write",
                None,
                Some(VerificationArtifactKind::WriteChangeSet),
                None,
                Some(union_receipt_digest.clone()),
                RedactedVerificationJson::closed(
                    VerificationRedactionClass::SynthesisWriteUnion,
                    VerificationDigest::of(b"verification-write-union"),
                ),
                now_unix_ms,
            )?;
            for (ordinal, source) in source_artifacts.iter().enumerate() {
                conn.execute(
                    "INSERT INTO verification_synthesis_artifacts (
                         synthesis_id, ordinal, source_candidate_id, source_artifact_ordinal
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![synthesis_id.to_string(), ordinal as i64, source.candidate_id.to_string(), source.artifact_ordinal],
                )?;
            }
            set_operation_state(
                conn,
                session_id,
                operation_id,
                expected_revision,
                VerificationOperationState::Dispatching,
                now_unix_ms,
            )?;
            Ok(VerificationWriteSynthesisResult {
                operation: required_operation(conn, session_id, operation_id)?,
                canonical_output_batch_digest: union_receipt_digest,
            })
        })
        .await
    }

    /// Resolves a pre-dispatch synthesis branch. It always creates the one
    /// suppressed projection and never creates selected metadata or events.
    pub async fn suppress_verification_synthesis(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_revision: i64,
        state: VerificationSynthesisTerminal,
        now_unix_ms: i64,
    ) -> Result<VerificationOperationRow> {
        self.transaction(move |conn| {
            let operation = required_operation(conn, session_id, operation_id)?;
            ensure!(
                operation.state == VerificationOperationState::Synthesizing,
                "verification operation is not synthesizing"
            );
            ensure!(
                operation.revision == expected_revision,
                "verification operation revision conflict"
            );
            ensure!(
                operation.collection_closed_at_unix_ms.is_some(),
                "verification collection must close before adjudication"
            );
            let synthesis_state = state.as_str();
            transition_synthesis_conn(
                conn,
                session_id,
                operation_id,
                synthesis_state,
                None,
                None,
                None,
                None,
                RedactedVerificationJson::closed(
                    match state {
                        VerificationSynthesisTerminal::Refused => {
                            VerificationRedactionClass::SynthesisRefused
                        }
                        VerificationSynthesisTerminal::NoValidCandidate => {
                            VerificationRedactionClass::SynthesisNoValidCandidate
                        }
                        VerificationSynthesisTerminal::Failed => {
                            VerificationRedactionClass::SynthesisFailed
                        }
                    },
                    VerificationDigest::of(synthesis_state.as_bytes()),
                ),
                now_unix_ms,
            )?;
            let terminal = match state {
                VerificationSynthesisTerminal::Refused => VerificationOperationState::Cancelled,
                VerificationSynthesisTerminal::NoValidCandidate
                | VerificationSynthesisTerminal::Failed => VerificationOperationState::Failed,
            };
            set_operation_state(
                conn,
                session_id,
                operation_id,
                expected_revision,
                terminal,
                now_unix_ms,
            )?;
            insert_suppressed_projection_conn(
                conn,
                session_id,
                operation_id,
                VerificationDigest::of(synthesis_state.as_bytes()),
                now_unix_ms,
            )?;
            required_operation(conn, session_id, operation_id)
        })
        .await
    }

    /// Atomically writes the model-safe envelope and the host idempotency
    /// reservation before an effect may be attempted. A retry returns the
    /// existing matching reservation; it never reconstructs a dispatch from a
    /// digest or volatile candidate payload.
    pub async fn reserve_verification_dispatch(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_revision: i64,
        host_idempotency_key: &str,
        envelope: NewVerificationEnvelope,
        now_unix_ms: i64,
    ) -> Result<VerificationDispatchAttemptRow> {
        validate_host_key(host_idempotency_key)?;
        validate_envelope(&envelope)?;
        let host_idempotency_key = host_idempotency_key.to_owned();
        self.transaction(move |conn| {
            let operation = required_operation(conn, session_id, operation_id)?;
            let envelope_json = canonical_model_visible_json(&envelope.model_visible_projection)?;
            let prepared_projection_digest = VerificationDigest::of(envelope_json.as_bytes());
            let surrogate_kind = if operation.budget_action
                == Some(VerificationBudgetAction::DispatchOriginal)
            {
                "normalized_original"
            } else if envelope.surrogate_kind == VerificationArtifactKind::ProposedCall {
                "selected_call"
            } else {
                "synthesized_write"
            };
            if let Some(existing) = load_attempt(conn, session_id, operation_id)? {
                ensure!(
                    existing.host_idempotency_key == host_idempotency_key,
                    "verification dispatch idempotency key conflict"
                );
                ensure!(
                    existing.dispatch_digest == envelope.batch_digest,
                    "verification dispatch batch digest conflict"
                );
                let persisted = load_envelope_identity(conn, session_id, operation_id)?
                    .context("verification dispatch reservation has no envelope")?;
                ensure!(
                    persisted.prepared_projection_digest == prepared_projection_digest
                        && persisted.batch_digest == envelope.batch_digest
                        && persisted.surrogate_kind == surrogate_kind
                        && persisted.model_visible_projection_json == envelope_json,
                    "verification dispatch envelope conflict"
                );
                return Ok(existing);
            }
            ensure!(
                operation.state == VerificationOperationState::Dispatching,
                "verification operation is not dispatching"
            );
            ensure!(
                operation.revision == expected_revision,
                "verification operation revision conflict"
            );
            validate_dispatch_precondition(
                conn,
                session_id,
                operation_id,
                &operation,
                envelope.surrogate_kind,
                &envelope.batch_digest,
            )?;
            let envelope_id = Uuid::new_v4();
            let attempt_id = Uuid::new_v4();
            let prepared_projection_id = Uuid::new_v4();
            conn.execute(
                "INSERT INTO verification_projection_envelopes (
                    envelope_id, operation_id, session_id, prepared_projection_id, prepared_projection_digest, batch_digest,
                    surrogate_kind, model_visible_projection_json, retention_state, revision,
                    created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'retained', 0, ?9, ?9)",
                params![
                    envelope_id.to_string(),
                    operation_id.to_string(),
                    session_id.to_string(),
                    prepared_projection_id.to_string(),
                    prepared_projection_digest.as_str(),
                    envelope.batch_digest.as_str(),
                    surrogate_kind,
                    envelope_json,
                    now_unix_ms
                ],
            )?;
            conn.execute(
                "INSERT INTO verification_dispatch_attempts (
                    attempt_id, operation_id, session_id, host_idempotency_key, dispatch_digest,
                    state, revision, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'reserved', 0, ?6, ?6)",
                params![
                    attempt_id.to_string(),
                    operation_id.to_string(),
                    session_id.to_string(),
                    host_idempotency_key,
                    envelope.batch_digest.as_str(),
                    now_unix_ms
                ],
            )?;
            load_attempt(conn, session_id, operation_id)?
                .context("reserved verification dispatch missing")
        })
        .await
    }

    pub async fn mark_verification_dispatch_executing(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_revision: i64,
        now_unix_ms: i64,
    ) -> Result<VerificationDispatchAttemptRow> {
        self.transaction(move |conn| {
            let attempt = load_attempt(conn, session_id, operation_id)?.context("verification dispatch attempt is missing")?;
            if attempt.state.is_terminal() { return Ok(attempt); }
            ensure!(attempt.revision == expected_revision && attempt.state == VerificationDispatchState::Reserved, "verification dispatch attempt revision conflict");
            let changed = conn.execute(
                "UPDATE verification_dispatch_attempts SET state = 'executing', revision = revision + 1, updated_at_unix_ms = ?1
                 WHERE attempt_id = ?2 AND revision = ?3 AND state = 'reserved'",
                params![now_unix_ms, attempt.attempt_id.to_string(), expected_revision],
            )?;
            ensure!(changed == 1, "verification dispatch attempt revision conflict");
            load_attempt(conn, session_id, operation_id)?.context("executing verification dispatch missing")
        }).await
    }

    /// Settles a proven host receipt. Success and final-error insert the one
    /// committed projection and its ordered ordinary session events in the
    /// same transaction. Uncertain and no-submission outcomes are suppressed.
    pub async fn settle_verification_dispatch(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_attempt_revision: i64,
        settlement: DispatchSettlement,
        receipt: RedactedVerificationJson,
        now_unix_ms: i64,
    ) -> Result<VerificationOperationRow> {
        ensure!(
            settlement != DispatchSettlement::CancelledNoSubmission,
            "use the no-submission proof settlement API for cancellation"
        );
        ensure!(
            matches!(
                (settlement, receipt.classification()),
                (
                    DispatchSettlement::Succeeded,
                    VerificationRedactionClass::DispatchSuccess
                ) | (
                    DispatchSettlement::Failed,
                    VerificationRedactionClass::DispatchFinalError
                ) | (
                    DispatchSettlement::Unknown,
                    VerificationRedactionClass::DispatchUnknown
                )
            ),
            "verification dispatch receipt class does not match settlement"
        );
        self.transaction(move |conn| {
            let attempt = load_attempt(conn, session_id, operation_id)?
                .context("verification dispatch attempt is missing")?;
            // A same-key terminal replay is independent of mutable envelope
            // storage: its receipt/projection was atomically committed by the
            // winner and must not be re-derived or re-ranked.
            if attempt.state.is_terminal() {
                return required_operation(conn, session_id, operation_id);
            }
            let projected_events = envelope_projection_events_conn(
                conn,
                session_id,
                operation_id,
                &attempt,
                settlement,
                &receipt,
                VerificationRedactionClass::DispatchSuccess,
                VerificationRedactionClass::DispatchFinalError,
            )?;
            validate_projected_events(&projected_events, settlement)?;
            settle_dispatch_conn(
                conn,
                session_id,
                operation_id,
                expected_attempt_revision,
                settlement,
                &receipt,
                &projected_events,
                false,
                now_unix_ms,
            )?;
            required_operation(conn, session_id, operation_id)
        })
        .await
    }

    pub async fn cancel_verification_dispatch_no_submission(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        expected_attempt_revision: i64,
        proof: NoSubmissionProof,
        now_unix_ms: i64,
    ) -> Result<VerificationOperationRow> {
        self.transaction(move |conn| {
            settle_dispatch_conn(
                conn,
                session_id,
                operation_id,
                expected_attempt_revision,
                DispatchSettlement::CancelledNoSubmission,
                proof.receipt(),
                &[],
                true,
                now_unix_ms,
            )?;
            required_operation(conn, session_id, operation_id)
        })
        .await
    }

    /// Restart reconciliation never re-dispatches. Collection/synthesis is
    /// terminalized to aborted; a selected or original attempt is settled from
    /// a proven host lookup result, otherwise unknown exactly once.
    pub async fn recover_verification_operation(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
        host_outcome: Option<DispatchSettlement>,
        receipt: RedactedVerificationJson,
        now_unix_ms: i64,
    ) -> Result<VerificationOperationRow> {
        self.transaction(move |conn| {
            let operation = required_operation(conn, session_id, operation_id)?;
            if operation.state.is_terminal() { return Ok(operation); }
            if matches!(operation.state, VerificationOperationState::Created | VerificationOperationState::Collecting | VerificationOperationState::Synthesizing) {
                ensure!(
                    host_outcome.is_none(),
                    "pre-dispatch verification recovery cannot settle an effect"
                );
                conn.execute(
                    "UPDATE verification_candidates SET state = 'cancelled', revision = revision + 1, updated_at_unix_ms = ?1
                     WHERE operation_id = ?2 AND session_id = ?3 AND state IN ('queued', 'running')",
                    params![now_unix_ms, operation_id.to_string(), session_id.to_string()],
                )?;
                if operation.state == VerificationOperationState::Synthesizing {
                    transition_synthesis_conn(
                        conn,
                        session_id,
                        operation_id,
                        "failed",
                        None,
                        None,
                        None,
                        None,
                        RedactedVerificationJson::closed(
                            VerificationRedactionClass::RestartAborted,
                            VerificationDigest::of(b"verification-restart-aborted"),
                        ),
                        now_unix_ms,
                    )?;
                }
                set_operation_state(conn, session_id, operation_id, operation.revision, VerificationOperationState::Aborted, now_unix_ms)?;
                insert_suppressed_projection_conn(conn, session_id, operation_id, VerificationDigest::of(b"verification-restart-aborted"), now_unix_ms)?;
                return required_operation(conn, session_id, operation_id);
            }
            let attempt = load_attempt(conn, session_id, operation_id)?.context("dispatching verification operation is missing reservation")?;
            if attempt.state.is_terminal() { return required_operation(conn, session_id, operation_id); }
            let outcome = host_outcome.unwrap_or(DispatchSettlement::Unknown);
            ensure!(
                outcome != DispatchSettlement::CancelledNoSubmission,
                "restart cancellation requires a durable no-submission proof"
            );
            ensure!(
                matches!(
                    (outcome, receipt.classification()),
                    (
                        DispatchSettlement::Succeeded,
                        VerificationRedactionClass::DispatchSuccess
                    ) | (
                        DispatchSettlement::Failed,
                        VerificationRedactionClass::DispatchFinalError
                    ) | (
                        DispatchSettlement::Unknown,
                        VerificationRedactionClass::DispatchUnknown
                    )
                ),
                "verification recovery receipt class does not match host outcome"
            );
            let projected_events = envelope_projection_events_conn(
                conn,
                session_id,
                operation_id,
                &attempt,
                outcome,
                &receipt,
                VerificationRedactionClass::RecoverySuccess,
                VerificationRedactionClass::RecoveryFinalError,
            )?;
            settle_dispatch_conn(conn, session_id, operation_id, attempt.revision, outcome, &receipt, &projected_events, false, now_unix_ms)?;
            required_operation(conn, session_id, operation_id)
        }).await
    }

    /// Host-only redacted operation read. It is intentionally session-scoped;
    /// the module exposes no candidate body, raw evidence, or agent-facing
    /// projection query.
    pub async fn host_verification_operation(
        &self,
        session_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<VerificationOperationRow>> {
        self.read(move |conn| load_operation(conn, session_id, operation_id))
            .await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationSynthesisTerminal {
    Refused,
    NoValidCandidate,
    Failed,
}

impl VerificationSynthesisTerminal {
    pub const ALL: [Self; 3] = [Self::Refused, Self::NoValidCandidate, Self::Failed];

    fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::NoValidCandidate => "no_valid_candidate",
            Self::Failed => "failed",
        }
    }
}

fn validate_operation_input(input: &NewVerificationOperation) -> Result<()> {
    ensure!(
        (0..=MAX_CANDIDATES).contains(&input.requested_candidate_count)
            && (0..=input.requested_candidate_count).contains(&input.effective_candidate_count),
        "verification candidate counts are invalid"
    );
    for (value, field) in [
        (input.total_token_ceiling, "token ceiling"),
        (input.estimated_cost_ceiling_microunits, "cost ceiling"),
        (input.collection_duration_ms, "collection duration"),
        (input.conservative_token_reservation, "token reservation"),
        (
            input.conservative_cost_reservation_microunits,
            "cost reservation",
        ),
    ] {
        ensure!(value >= 0, "verification {field} must be non-negative");
    }
    if input.estimate_unavailable_action.is_some() {
        ensure!(
            input.effective_candidate_count == 0,
            "estimate-unavailable verification cannot reserve candidates"
        );
    }
    ensure!(
        input.conservative_token_reservation <= input.total_token_ceiling
            && input.conservative_cost_reservation_microunits
                <= input.estimated_cost_ceiling_microunits,
        "verification conservative reservation exceeds its budget ceiling"
    );
    Ok(())
}

fn validate_candidate_input(candidate: &NewVerificationCandidate) -> Result<()> {
    ensure!(
        candidate.redacted_summary.classification() == VerificationRedactionClass::CandidateSummary,
        "verification candidate needs a candidate-summary receipt"
    );
    ensure!(
        candidate.reserved_tokens >= 0 && candidate.reserved_cost_microunits >= 0,
        "verification candidate reservation must be non-negative"
    );
    ensure!(
        candidate.artifact_members.len() <= MAX_CANDIDATES as usize,
        "verification artifact union exceeds its bound"
    );
    match candidate.artifact_kind {
        VerificationArtifactKind::ProposedCall => ensure!(
            candidate.artifact_members.is_empty(),
            "non-write verification candidate cannot carry artifact members"
        ),
        VerificationArtifactKind::WriteChangeSet => ensure!(
            !candidate.artifact_members.is_empty(),
            "write verification candidate requires artifact members"
        ),
    }
    for member in &candidate.artifact_members {
        ensure!(
            (member.operation_kind == VerificationArtifactOperation::Rename)
                == member.prior_path_digest.is_some(),
            "verification rename metadata requires exactly one prior path digest"
        );
        ensure!(
            (member.operation_kind == VerificationArtifactOperation::Mode)
                == member.mode_digest.is_some(),
            "verification mode metadata requires exactly one mode digest"
        );
    }
    Ok(())
}

fn validate_host_key(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "verification host idempotency key is not a safe opaque identifier"
    );
    Ok(())
}

fn validate_envelope(envelope: &NewVerificationEnvelope) -> Result<()> {
    let bytes = serde_json::to_vec(&envelope.model_visible_projection)?;
    ensure!(
        bytes.len() <= MAX_ENVELOPE_BYTES,
        "verification model-visible envelope exceeds its bound"
    );
    VerificationSurrogateCall::from_model_visible(&envelope.model_visible_projection).map(|_| ())
}

fn canonical_model_visible_json(value: &Value) -> Result<String> {
    fn canonicalize(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
            Value::Object(values) => {
                let mut sorted = BTreeMap::new();
                for (key, value) in values {
                    sorted.insert(key.clone(), canonicalize(value));
                }
                Value::Object(sorted.into_iter().collect())
            }
            value => value.clone(),
        }
    }
    Ok(serde_json::to_string(&canonicalize(value))?)
}

fn validate_redacted_value(value: &Value, model_visible: bool) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(value) => {
            ensure!(
                value.len() <= MAX_ENVELOPE_BYTES,
                "verification JSON string exceeds its bound"
            );
            Ok(())
        }
        Value::Array(values) => {
            ensure!(
                values.len() <= MAX_CANDIDATES as usize,
                "verification JSON array exceeds its bound"
            );
            for value in values {
                validate_redacted_value(value, model_visible)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            ensure!(
                values.len() <= 64,
                "verification JSON object exceeds its bound"
            );
            for (key, value) in values {
                let normalized = key.to_ascii_lowercase();
                let forbidden = [
                    "credential",
                    "secret",
                    "password",
                    "provider",
                    "evidence",
                    "receipt",
                    "header",
                    "token",
                    "handle",
                    "response",
                    "prompt",
                    "output",
                    "result",
                    "trace",
                ];
                ensure!(
                    !forbidden
                        .iter()
                        .any(|forbidden| normalized.contains(forbidden))
                        || (model_visible
                            && matches!(
                                normalized.as_str(),
                                "operation" | "arguments" | "patch" | "path" | "paths" | "kind"
                            )),
                    "verification JSON contains a forbidden raw field"
                );
                ensure!(key.len() <= 64 && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')), "verification JSON key is unsafe");
                validate_redacted_value(value, model_visible)?;
            }
            Ok(())
        }
    }
}

fn validate_projected_events(
    events: &[VerificationProjectionEvent],
    settlement: DispatchSettlement,
) -> Result<()> {
    match settlement {
        DispatchSettlement::Succeeded | DispatchSettlement::Failed => ensure!(
            !events.is_empty() && events.len() <= MAX_PROJECTED_EVENTS,
            "proved verification dispatch settlement requires bounded projected events"
        ),
        DispatchSettlement::Unknown | DispatchSettlement::CancelledNoSubmission => ensure!(
            events.is_empty(),
            "uncertain or no-submission verification settlement cannot project events"
        ),
    }
    let mut surrogate_call_id: Option<String> = None;
    for (ordinal, event) in events.iter().enumerate() {
        if let Some(call_id) = &event.call_id {
            ensure!(
                !call_id.is_empty()
                    && call_id.len() <= 128
                    && call_id.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                    }),
                "verification projected event call id is unsafe"
            );
        }
        match (event.event_kind, &event.data) {
            ("tool_call", VerificationProjectionPayload::SurrogateCall(_)) => {
                ensure!(
                    ordinal == 0,
                    "verification surrogate call must be the first event"
                );
                surrogate_call_id = event.call_id.clone();
                ensure!(
                    surrogate_call_id.is_some(),
                    "verification surrogate call needs a correlation id"
                );
            }
            ("tool_call_completed", VerificationProjectionPayload::Redacted(_)) => {
                if let Some(call_id) = surrogate_call_id.as_deref() {
                    ensure!(
                        event.call_id.as_deref() == Some(call_id),
                        "verification surrogate result call id does not match"
                    );
                    ensure!(
                        ordinal == 1 && events.len() == 2,
                        "verification surrogate recovery must emit one call and one result"
                    );
                }
            }
            _ => bail!("verification projected event does not match the strict safe schema"),
        }
    }
    if surrogate_call_id.is_some() {
        ensure!(
            events.len() == 2
                && events
                    .get(1)
                    .is_some_and(|event| event.event_kind == "tool_call_completed"),
            "verification surrogate call requires exactly one terminal result"
        );
    }
    Ok(())
}

fn ensure_agent_in_session(
    conn: &Connection,
    session_id: Uuid,
    agent_instance_id: Uuid,
) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_instances WHERE agent_instance_id = ?1 AND session_id = ?2)",
        params![agent_instance_id.to_string(), session_id.to_string()], |row| row.get(0),
    )?;
    ensure!(
        exists,
        "verification agent instance is not authorized for this session"
    );
    Ok(())
}

fn parse_budget_action(
    value: Option<String>,
) -> rusqlite::Result<Option<VerificationBudgetAction>> {
    value
        .map(|value| match value.as_str() {
            "refuse" => Ok(VerificationBudgetAction::Refuse),
            "dispatch_original" => Ok(VerificationBudgetAction::DispatchOriginal),
            _ => Err(invalid_value("verification budget action")),
        })
        .transpose()
}

fn load_operation(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
) -> Result<Option<VerificationOperationRow>> {
    conn.query_row(
        "SELECT operation_id, session_id, agent_instance_id, state, revision, collection_closed_at_unix_ms,
                collection_revision, original_operation_digest, pretool_context_capability_digest, budget_action
         FROM verification_operations WHERE operation_id = ?1 AND session_id = ?2",
        params![operation_id.to_string(), session_id.to_string()],
        |row| Ok(VerificationOperationRow {
            operation_id: parse_uuid(row.get(0)?)?, session_id: parse_uuid(row.get(1)?)?,
            agent_instance_id: parse_uuid(row.get(2)?)?, state: VerificationOperationState::parse(&row.get::<_, String>(3)?)?,
            revision: row.get(4)?, collection_closed_at_unix_ms: row.get(5)?, collection_revision: row.get(6)?,
            original_operation_digest: VerificationDigest::parse(&row.get::<_, String>(7)?).map_err(anyhow_to_sql_error)?,
            pretool_context_capability_digest: VerificationDigest::parse(&row.get::<_, String>(8)?).map_err(anyhow_to_sql_error)?,
            budget_action: parse_budget_action(row.get(9)?)?,
        }),
    ).optional().context("loading authorized verification operation")
}

fn required_operation(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
) -> Result<VerificationOperationRow> {
    load_operation(conn, session_id, operation_id)?
        .context("verification operation is not authorized for this session")
}

fn required_candidate(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    candidate_id: Uuid,
) -> Result<VerificationCandidateRow> {
    conn.query_row(
        "SELECT candidate_id, operation_id, session_id, artifact_kind, canonical_call_digest,
                artifact_union_digest, state, revision
         FROM verification_candidates WHERE candidate_id = ?1 AND operation_id = ?2 AND session_id = ?3",
        params![candidate_id.to_string(), operation_id.to_string(), session_id.to_string()],
        |row| Ok(VerificationCandidateRow {
            candidate_id: parse_uuid(row.get(0)?)?, operation_id: parse_uuid(row.get(1)?)?, session_id: parse_uuid(row.get(2)?)?,
            artifact_kind: VerificationArtifactKind::parse(&row.get::<_, String>(3)?)?,
            canonical_call_digest: VerificationDigest::parse(&row.get::<_, String>(4)?).map_err(anyhow_to_sql_error)?,
            artifact_union_digest: VerificationDigest::parse(&row.get::<_, String>(5)?).map_err(anyhow_to_sql_error)?,
            state: VerificationCandidateState::parse(&row.get::<_, String>(6)?)?, revision: row.get(7)?,
        }),
    ).optional().context("loading authorized verification candidate")?.context("verification candidate is not authorized for this operation")
}

fn load_attempt(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
) -> Result<Option<VerificationDispatchAttemptRow>> {
    conn.query_row(
        "SELECT attempt_id, operation_id, session_id, host_idempotency_key, dispatch_digest, state,
                redacted_receipt_json, revision
         FROM verification_dispatch_attempts WHERE operation_id = ?1 AND session_id = ?2",
        params![operation_id.to_string(), session_id.to_string()],
        |row| {
            let terminal_receipt: Option<String> = row.get(6)?;
            Ok(VerificationDispatchAttemptRow {
                attempt_id: parse_uuid(row.get(0)?)?,
                operation_id: parse_uuid(row.get(1)?)?,
                session_id: parse_uuid(row.get(2)?)?,
                host_idempotency_key: row.get(3)?,
                dispatch_digest: VerificationDigest::parse(&row.get::<_, String>(4)?)
                    .map_err(anyhow_to_sql_error)?,
                state: VerificationDispatchState::parse(&row.get::<_, String>(5)?)?,
                terminal_receipt: terminal_receipt
                    .map(|receipt| {
                        RedactedVerificationJson::parse(&receipt).map_err(anyhow_to_sql_error)
                    })
                    .transpose()?,
                revision: row.get(7)?,
            })
        },
    )
    .optional()
    .context("loading authorized verification dispatch attempt")
}

struct VerificationEnvelopeIdentity {
    prepared_projection_id: Uuid,
    prepared_projection_digest: VerificationDigest,
    batch_digest: VerificationDigest,
    surrogate_kind: String,
    model_visible_projection_json: String,
}

fn load_envelope_identity(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
) -> Result<Option<VerificationEnvelopeIdentity>> {
    conn.query_row(
        "SELECT prepared_projection_id, prepared_projection_digest, batch_digest, surrogate_kind, model_visible_projection_json
         FROM verification_projection_envelopes WHERE operation_id = ?1 AND session_id = ?2",
        params![operation_id.to_string(), session_id.to_string()],
        |row| {
            Ok(VerificationEnvelopeIdentity {
                prepared_projection_id: parse_uuid(row.get(0)?)?,
                prepared_projection_digest: VerificationDigest::parse(&row.get::<_, String>(1)?)
                    .map_err(anyhow_to_sql_error)?,
                batch_digest: VerificationDigest::parse(&row.get::<_, String>(2)?)
                    .map_err(anyhow_to_sql_error)?,
                surrogate_kind: row.get(3)?,
                model_visible_projection_json: row.get(4)?,
            })
        },
    )
    .optional()
    .context("loading verification dispatch envelope")
}

fn operation_deadline(conn: &Connection, operation_id: Uuid) -> Result<i64> {
    conn.query_row(
        "SELECT collection_deadline_unix_ms FROM verification_operations WHERE operation_id = ?1",
        [operation_id.to_string()],
        |row| row.get(0),
    )
    .context("loading verification deadline")
}

fn operation_effective_candidates(conn: &Connection, operation_id: Uuid) -> Result<i64> {
    conn.query_row(
        "SELECT effective_candidate_count FROM verification_operations WHERE operation_id = ?1",
        [operation_id.to_string()],
        |row| row.get(0),
    )
    .context("loading verification candidate ceiling")
}

fn operation_budget_ceilings(conn: &Connection, operation_id: Uuid) -> Result<(i64, i64)> {
    conn.query_row("SELECT total_token_ceiling, estimated_cost_ceiling_microunits FROM verification_operations WHERE operation_id = ?1", [operation_id.to_string()], |row| Ok((row.get(0)?, row.get(1)?))).context("loading verification budget ceilings")
}

fn set_operation_state(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    expected_revision: i64,
    next: VerificationOperationState,
    now_unix_ms: i64,
) -> Result<()> {
    let current = required_operation(conn, session_id, operation_id)?;
    ensure!(
        current.revision == expected_revision,
        "verification operation revision conflict"
    );
    ensure!(
        legal_operation_transition(current.state, next),
        "illegal verification operation transition"
    );
    let changed = conn.execute(
        "UPDATE verification_operations SET state = ?1, revision = revision + 1, updated_at_unix_ms = ?2
         WHERE operation_id = ?3 AND session_id = ?4 AND revision = ?5",
        params![next.as_str(), now_unix_ms, operation_id.to_string(), session_id.to_string(), expected_revision],
    )?;
    ensure!(changed == 1, "verification operation revision conflict");
    Ok(())
}

fn legal_operation_transition(
    current: VerificationOperationState,
    next: VerificationOperationState,
) -> bool {
    matches!(
        (current, next),
        (
            VerificationOperationState::Created,
            VerificationOperationState::Collecting
                | VerificationOperationState::Dispatching
                | VerificationOperationState::SkippedBudgetRefused
                | VerificationOperationState::Failed
                | VerificationOperationState::Aborted
        ) | (
            VerificationOperationState::Collecting,
            VerificationOperationState::Synthesizing
                | VerificationOperationState::Aborted
                | VerificationOperationState::Cancelled
        ) | (
            VerificationOperationState::Synthesizing,
            VerificationOperationState::Dispatching
                | VerificationOperationState::Failed
                | VerificationOperationState::Cancelled
                | VerificationOperationState::Aborted
        ) | (
            VerificationOperationState::Dispatching,
            VerificationOperationState::Succeeded
                | VerificationOperationState::Failed
                | VerificationOperationState::Cancelled
                | VerificationOperationState::Unknown
        )
    )
}

fn close_collection_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    expected_revision: i64,
    now_unix_ms: i64,
) -> Result<()> {
    let operation = required_operation(conn, session_id, operation_id)?;
    if operation.collection_closed_at_unix_ms.is_some() {
        ensure!(
            matches!(
                operation.state,
                VerificationOperationState::Synthesizing | VerificationOperationState::Dispatching
            ) || operation.state.is_terminal(),
            "verification collection closed in an unexpected state"
        );
        return Ok(());
    }
    ensure!(
        operation.state == VerificationOperationState::Collecting,
        "verification operation is not collecting"
    );
    ensure!(
        operation.revision == expected_revision,
        "verification operation revision conflict"
    );
    let changed = conn.execute(
        "UPDATE verification_operations
         SET state = 'synthesizing', revision = revision + 1,
             collection_closed_at_unix_ms = ?1, collection_revision = collection_revision + 1,
             updated_at_unix_ms = ?1
         WHERE operation_id = ?2 AND session_id = ?3 AND revision = ?4
           AND collection_closed_at_unix_ms IS NULL AND state = 'collecting'",
        params![
            now_unix_ms,
            operation_id.to_string(),
            session_id.to_string(),
            expected_revision
        ],
    )?;
    ensure!(changed == 1, "verification collection close lost its CAS");
    conn.execute(
        "UPDATE verification_candidates SET state = 'timed_out', revision = revision + 1, updated_at_unix_ms = ?1
         WHERE operation_id = ?2 AND session_id = ?3 AND state IN ('queued', 'running')",
        params![now_unix_ms, operation_id.to_string(), session_id.to_string()],
    )?;
    insert_pending_synthesis_conn(conn, session_id, operation_id, now_unix_ms)?;
    Ok(())
}

fn insert_late_result_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    candidate_id: Uuid,
    outcome: VerificationCandidateState,
    digest: VerificationDigest,
    now_unix_ms: i64,
) -> Result<()> {
    let kind = match outcome {
        VerificationCandidateState::Valid => "valid",
        VerificationCandidateState::Invalid => "invalid",
        VerificationCandidateState::Malformed => "malformed",
        VerificationCandidateState::Cancelled | VerificationCandidateState::TimedOut => "failed",
        VerificationCandidateState::Queued | VerificationCandidateState::Running => {
            bail!("nonterminal verification candidate cannot be a late result")
        }
    };
    conn.execute(
        "INSERT INTO verification_late_results (
             late_result_id, candidate_id, operation_id, session_id, result_kind, result_digest, received_at_unix_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(candidate_id, result_digest) DO NOTHING",
        params![Uuid::new_v4().to_string(), candidate_id.to_string(), operation_id.to_string(), session_id.to_string(), kind, digest.as_str(), now_unix_ms],
    )?;
    Ok(())
}

fn insert_pending_synthesis_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    now_unix_ms: i64,
) -> Result<Uuid> {
    let synthesis_id = Uuid::new_v4();
    conn.execute(
        "INSERT INTO verification_syntheses (
             synthesis_id, operation_id, session_id, state, redacted_summary_json,
             revision, created_at_unix_ms, updated_at_unix_ms
         ) VALUES (?1, ?2, ?3, 'pending', ?4, 0, ?5, ?5)",
        params![
            synthesis_id.to_string(),
            operation_id.to_string(),
            session_id.to_string(),
            RedactedVerificationJson::closed(
                VerificationRedactionClass::SynthesisPending,
                VerificationDigest::of(b"verification-synthesis-pending"),
            )
            .as_str(),
            now_unix_ms,
        ],
    )
    .context("creating pending verification synthesis")?;
    Ok(synthesis_id)
}

// Synthesis fields map one-for-one to immutable selected/write audit columns;
// a wrapper would only conceal which nullable column each terminal state owns.
#[allow(clippy::too_many_arguments)]
fn transition_synthesis_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    state: &str,
    selected_candidate_id: Option<Uuid>,
    artifact_kind: Option<VerificationArtifactKind>,
    canonical_call_digest: Option<VerificationDigest>,
    write_union_receipt_digest: Option<VerificationDigest>,
    summary: RedactedVerificationJson,
    now_unix_ms: i64,
) -> Result<Uuid> {
    let synthesis_id: String = conn
        .query_row(
            "SELECT synthesis_id FROM verification_syntheses
         WHERE operation_id = ?1 AND session_id = ?2 AND state = 'pending' AND revision = 0",
            params![operation_id.to_string(), session_id.to_string()],
            |row| row.get(0),
        )
        .context("verification synthesis is not pending")?;
    let changed = conn.execute(
        "UPDATE verification_syntheses
         SET state = ?1, selected_candidate_id = ?2, artifact_kind = ?3,
             canonical_call_digest = ?4, write_union_receipt_digest = ?5,
             redacted_summary_json = ?6, revision = revision + 1, updated_at_unix_ms = ?7
         WHERE synthesis_id = ?8 AND operation_id = ?9 AND session_id = ?10
           AND state = 'pending' AND revision = 0",
        params![
            state,
            selected_candidate_id.map(|value| value.to_string()),
            artifact_kind.map(VerificationArtifactKind::as_str),
            canonical_call_digest
                .as_ref()
                .map(VerificationDigest::as_str),
            write_union_receipt_digest
                .as_ref()
                .map(VerificationDigest::as_str),
            summary.as_str(),
            now_unix_ms,
            synthesis_id,
            operation_id.to_string(),
            session_id.to_string()
        ],
    )?;
    ensure!(
        changed == 1,
        "verification synthesis transition lost its CAS"
    );
    parse_uuid(synthesis_id).map_err(Into::into)
}

fn validate_dispatch_precondition(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    operation: &VerificationOperationRow,
    surrogate_kind: VerificationArtifactKind,
    batch_digest: &VerificationDigest,
) -> Result<()> {
    if operation.budget_action == Some(VerificationBudgetAction::DispatchOriginal) {
        ensure!(
            surrogate_kind == VerificationArtifactKind::ProposedCall,
            "original dispatch must use a call surrogate"
        );
        ensure!(
            batch_digest == &operation.original_operation_digest,
            "budget-original dispatch batch digest must equal the original digest"
        );
        let synthesis: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM verification_syntheses WHERE operation_id = ?1",
                [operation_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            synthesis.is_none(),
            "budget-original dispatch cannot have candidates or synthesis"
        );
        return Ok(());
    }
    let synthesis: (String, Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT state, artifact_kind, canonical_call_digest, write_union_receipt_digest FROM verification_syntheses
         WHERE operation_id = ?1 AND session_id = ?2",
            params![operation_id.to_string(), session_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .context("verification dispatch requires selected or synthesized adjudication")?;
    match synthesis.0.as_str() {
        "selected" => {
            ensure!(
                surrogate_kind == VerificationArtifactKind::ProposedCall
                    && synthesis.1.as_deref() == Some("proposed_call"),
                "selected verification dispatch kind mismatch"
            );
            let selected_digest = synthesis
                .2
                .as_deref()
                .context("selected verification has no canonical call digest")?;
            ensure!(
                selected_digest == operation.original_operation_digest.as_str(),
                "selected verification call digest changed"
            );
            ensure!(
                batch_digest.as_str() == selected_digest,
                "selected dispatch batch digest must equal the canonical call digest"
            );
        }
        "synthesized_write" => {
            ensure!(
                surrogate_kind == VerificationArtifactKind::WriteChangeSet
                    && synthesis.1.as_deref() == Some("write_change_set"),
                "synthesized write dispatch kind mismatch"
            );
            ensure!(
                batch_digest.as_str()
                    == synthesis
                        .3
                        .as_deref()
                        .context("synthesized write has no union digest")?,
                "synthesized write dispatch batch digest must equal the canonical union digest"
            );
        }
        _ => bail!("verification synthesis does not permit dispatch"),
    }
    Ok(())
}

fn insert_suppressed_projection_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    batch_digest: VerificationDigest,
    now_unix_ms: i64,
) -> Result<()> {
    insert_suppressed_projection_with_receipt_conn(
        conn,
        session_id,
        operation_id,
        batch_digest,
        None,
        now_unix_ms,
    )
}

fn insert_suppressed_projection_with_receipt_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    batch_digest: VerificationDigest,
    receipt: Option<&RedactedVerificationJson>,
    now_unix_ms: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO verification_projections (
             projection_id, operation_id, session_id, state, batch_digest, redacted_result_json, created_at_unix_ms
         ) VALUES (?1, ?2, ?3, 'suppressed', ?4, ?5, ?6)
         ON CONFLICT(operation_id) DO NOTHING",
        params![
            Uuid::new_v4().to_string(),
            operation_id.to_string(),
            session_id.to_string(),
            batch_digest.as_str(),
            receipt.map(RedactedVerificationJson::as_str),
            now_unix_ms
        ],
    )?;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1",
        [operation_id.to_string()],
        |row| row.get(0),
    )?;
    ensure!(
        count == 1,
        "verification operation has conflicting projections"
    );
    Ok(())
}

/// Derives the sole model-visible call/result pair from a durable validated
/// envelope plus a typed host receipt. Neither normal settlement nor restart
/// recovery accepts caller-supplied projected events.
// Recovery and live settlement share this exact envelope/receipt derivation
// boundary. The independently typed classes prevent a recovery receipt from
// being rendered as a live one.
#[allow(clippy::too_many_arguments)]
fn envelope_projection_events_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    attempt: &VerificationDispatchAttemptRow,
    outcome: DispatchSettlement,
    receipt: &RedactedVerificationJson,
    success_class: VerificationRedactionClass,
    final_error_class: VerificationRedactionClass,
) -> Result<Vec<VerificationProjectionEvent>> {
    match outcome {
        DispatchSettlement::Unknown => return Ok(Vec::new()),
        DispatchSettlement::CancelledNoSubmission => {
            bail!("restart cancellation requires a persisted no-submission terminal receipt")
        }
        DispatchSettlement::Succeeded | DispatchSettlement::Failed => {}
    }
    let envelope = load_envelope_identity(conn, session_id, operation_id)?
        .context("proven verification recovery is missing its durable envelope")?;
    ensure!(
        envelope.batch_digest == attempt.dispatch_digest,
        "verification recovery envelope batch does not match its attempt"
    );
    let model_visible: Value = serde_json::from_str(&envelope.model_visible_projection_json)
        .context("persisted verification envelope is not valid JSON")?;
    let surrogate_kind = match envelope.surrogate_kind.as_str() {
        "selected_call" | "normalized_original" => VerificationArtifactKind::ProposedCall,
        "synthesized_write" => VerificationArtifactKind::WriteChangeSet,
        _ => bail!("persisted verification envelope has an invalid surrogate kind"),
    };
    validate_envelope(&NewVerificationEnvelope {
        batch_digest: envelope.batch_digest.clone(),
        surrogate_kind,
        model_visible_projection: model_visible.clone(),
    })?;
    let recovered_call = VerificationSurrogateCall::from_model_visible(&model_visible)?;
    let canonical = canonical_model_visible_json(&model_visible)?;
    ensure!(
        VerificationDigest::of(canonical.as_bytes()) == envelope.prepared_projection_digest,
        "persisted verification envelope digest does not match its model-visible projection"
    );
    let operation = required_operation(conn, session_id, operation_id)?;
    validate_dispatch_precondition(
        conn,
        session_id,
        operation_id,
        &operation,
        surrogate_kind,
        &envelope.batch_digest,
    )?;
    let outcome_classification = match outcome {
        DispatchSettlement::Succeeded => success_class,
        DispatchSettlement::Failed => final_error_class,
        DispatchSettlement::Unknown | DispatchSettlement::CancelledNoSubmission => unreachable!(),
    };
    let event_digest = VerificationDigest::of(
        canonical_model_visible_json(&json!({
            "prepared_projection_id": envelope.prepared_projection_id.to_string(),
            "prepared_projection_digest": envelope.prepared_projection_digest.as_str(),
            "batch_digest": envelope.batch_digest.as_str(),
            "outcome": outcome_classification.as_str(),
            "receipt_digest": receipt.digest().as_str(),
        }))?
        .as_bytes(),
    );
    Ok(vec![
        VerificationProjectionEvent {
            event_kind: "tool_call",
            call_id: Some(format!("verification:{}", envelope.prepared_projection_id)),
            data: VerificationProjectionPayload::SurrogateCall(recovered_call),
        },
        VerificationProjectionEvent {
            event_kind: "tool_call_completed",
            call_id: Some(format!("verification:{}", envelope.prepared_projection_id)),
            data: VerificationProjectionPayload::Redacted(RedactedVerificationJson::closed(
                outcome_classification,
                event_digest,
            )),
        },
    ])
}

// All parameters are independent CAS/effect predicates required to atomically
// settle the attempt, operation, receipt and projection; do not hide them in
// a loosely validated helper payload.
#[allow(clippy::too_many_arguments)]
fn settle_dispatch_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    expected_attempt_revision: i64,
    settlement: DispatchSettlement,
    receipt: &RedactedVerificationJson,
    events: &[VerificationProjectionEvent],
    no_submission_proven: bool,
    now_unix_ms: i64,
) -> Result<()> {
    let operation = required_operation(conn, session_id, operation_id)?;
    let attempt = load_attempt(conn, session_id, operation_id)?
        .context("verification dispatch attempt is missing")?;
    if attempt.state.is_terminal() {
        ensure!(
            operation.state.is_terminal(),
            "terminal verification attempt has nonterminal operation"
        );
        return Ok(());
    }
    ensure!(
        operation.state == VerificationOperationState::Dispatching,
        "verification operation is not dispatching"
    );
    ensure!(
        attempt.revision == expected_attempt_revision,
        "verification dispatch attempt revision conflict"
    );
    ensure!(
        settlement != DispatchSettlement::CancelledNoSubmission || no_submission_proven,
        "verification cancellation requires no-submission proof"
    );
    let next_attempt = match settlement {
        DispatchSettlement::Succeeded => VerificationDispatchState::Succeeded,
        DispatchSettlement::Failed => VerificationDispatchState::Failed,
        DispatchSettlement::Unknown => VerificationDispatchState::Unknown,
        DispatchSettlement::CancelledNoSubmission => {
            VerificationDispatchState::CancelledNoSubmission
        }
    };
    let next_operation = match settlement {
        DispatchSettlement::Succeeded => VerificationOperationState::Succeeded,
        DispatchSettlement::Failed => VerificationOperationState::Failed,
        DispatchSettlement::Unknown => VerificationOperationState::Unknown,
        DispatchSettlement::CancelledNoSubmission => VerificationOperationState::Cancelled,
    };
    let receipt_digest = VerificationDigest::of(receipt.as_str().as_bytes());
    let changed = conn.execute(
        "UPDATE verification_dispatch_attempts
         SET state = ?1, redacted_receipt_json = ?2, receipt_digest = ?3,
             revision = revision + 1, updated_at_unix_ms = ?4
         WHERE attempt_id = ?5 AND revision = ?6 AND state IN ('reserved', 'executing')",
        params![
            next_attempt.as_str(),
            receipt.as_str(),
            receipt_digest.as_str(),
            now_unix_ms,
            attempt.attempt_id.to_string(),
            expected_attempt_revision
        ],
    )?;
    ensure!(
        changed == 1,
        "verification dispatch attempt revision conflict"
    );
    // A deterministic test-only cut point models a process loss after an
    // external effect is known but before the atomic receipt/projection commit.
    // Returning an error here rolls the attempt update back with the rest of
    // this transaction; recovery must use the host idempotency key instead.
    fail_after_attempt_settlement_for_test(operation_id)?;
    set_operation_state(
        conn,
        session_id,
        operation_id,
        operation.revision,
        next_operation,
        now_unix_ms,
    )?;
    match settlement {
        DispatchSettlement::Succeeded | DispatchSettlement::Failed => {
            insert_committed_projection_conn(
                conn,
                session_id,
                operation_id,
                attempt.dispatch_digest,
                receipt,
                events,
                now_unix_ms,
            )
        }
        DispatchSettlement::Unknown | DispatchSettlement::CancelledNoSubmission => {
            insert_suppressed_projection_conn(
                conn,
                session_id,
                operation_id,
                attempt.dispatch_digest,
                now_unix_ms,
            )
        }
    }
}

fn insert_committed_projection_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    batch_digest: VerificationDigest,
    receipt: &RedactedVerificationJson,
    events: &[VerificationProjectionEvent],
    now_unix_ms: i64,
) -> Result<()> {
    let projection_id = Uuid::new_v4();
    conn.execute(
        "INSERT INTO verification_projections (
             projection_id, operation_id, session_id, state, batch_digest, redacted_result_json, created_at_unix_ms
         ) VALUES (?1, ?2, ?3, 'committed', ?4, ?5, ?6)",
        params![projection_id.to_string(), operation_id.to_string(), session_id.to_string(), batch_digest.as_str(), receipt.as_str(), now_unix_ms],
    )?;
    for (ordinal, event) in events.iter().enumerate() {
        let data_json = serde_json::to_string(&json!({
            "verification_projection": true,
            "ordinal": ordinal,
            "data": event.data.as_json()?,
        }))?;
        conn.execute(
            "INSERT INTO session_events (session_id, ts_ms, type, call_id, data_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![session_id.to_string(), now_unix_ms, event.event_kind, event.call_id.as_deref(), data_json],
        )?;
        let seq = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO verification_projection_events (projection_id, ordinal, session_id, session_event_seq)
             VALUES (?1, ?2, ?3, ?4)",
            params![projection_id.to_string(), ordinal as i64, session_id.to_string(), seq],
        )?;
    }
    Ok(())
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn anyhow_to_sql_error(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

fn invalid_value(field: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid persisted {field}"),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::agent_tree_decisions::{AgentInstanceState, NewAgentInstance};

    async fn owner(db: &Db, project: &str) -> (Uuid, Uuid) {
        let session = db
            .create_session(project, "/workspace", "root")
            .await
            .unwrap();
        let created = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let running = db
            .transition_agent_instance(
                session.session_id,
                created.agent_instance_id,
                created.revision,
                AgentInstanceState::Running,
                "{}",
                2,
            )
            .await
            .unwrap();
        let agent = match running {
            crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(row) => row,
            outcome => panic!("unexpected agent transition: {outcome:?}"),
        };
        (session.session_id, agent.agent_instance_id)
    }

    fn digest(label: &str) -> VerificationDigest {
        VerificationDigest::of(label.as_bytes())
    }

    fn redacted(class: VerificationRedactionClass, label: &str) -> RedactedVerificationJson {
        RedactedVerificationJson::closed(class, digest(label))
    }

    fn operation(session_id: Uuid, agent_instance_id: Uuid) -> NewVerificationOperation {
        NewVerificationOperation {
            session_id,
            agent_instance_id,
            requested_candidate_count: 2,
            effective_candidate_count: 2,
            total_token_ceiling: 100,
            estimated_cost_ceiling_microunits: 100,
            collection_deadline_unix_ms: 100,
            collection_duration_ms: 50,
            conservative_token_reservation: 10,
            conservative_cost_reservation_microunits: 10,
            original_operation_digest: digest("original"),
            pretool_context_capability_digest: digest("pretool-context-anchor"),
            estimate_unavailable_action: None,
        }
    }

    fn candidate() -> NewVerificationCandidate {
        NewVerificationCandidate {
            artifact_kind: VerificationArtifactKind::ProposedCall,
            canonical_call_digest: digest("original"),
            artifact_union_digest: digest("call-union"),
            redacted_summary: redacted(VerificationRedactionClass::CandidateSummary, "candidate"),
            reserved_tokens: 10,
            reserved_cost_microunits: 10,
            artifact_members: Vec::new(),
        }
    }

    fn write_candidate() -> NewVerificationCandidate {
        NewVerificationCandidate {
            artifact_kind: VerificationArtifactKind::WriteChangeSet,
            canonical_call_digest: digest("write-canonical"),
            artifact_union_digest: digest("write-union"),
            redacted_summary: redacted(
                VerificationRedactionClass::CandidateSummary,
                "write-candidate",
            ),
            reserved_tokens: 10,
            reserved_cost_microunits: 10,
            artifact_members: vec![VerificationArtifactMember {
                operation_kind: VerificationArtifactOperation::Add,
                affected_path_digest: digest("added-path"),
                prior_path_digest: None,
                content_digest: Some(digest("added-content")),
                binary_metadata_digest: None,
                mode_digest: None,
            }],
        }
    }

    fn envelope() -> NewVerificationEnvelope {
        NewVerificationEnvelope {
            batch_digest: digest("original"),
            surrogate_kind: VerificationArtifactKind::ProposedCall,
            model_visible_projection: json!({
                "operation":"call",
                "arguments":{"path":"src/lib.rs"},
                "patch":"safe patch body"
            }),
        }
    }

    async fn prepared_selected_dispatch(
        db: &Db,
        session_id: Uuid,
        agent_id: Uuid,
        base: i64,
    ) -> (Uuid, VerificationDispatchAttemptRow) {
        let created = db
            .create_verification_operation(operation(session_id, agent_id), base)
            .await
            .unwrap();
        let collecting = db
            .start_verification_collection(
                session_id,
                created.operation_id,
                created.revision,
                base + 1,
            )
            .await
            .unwrap();
        let candidate = db
            .reserve_verification_candidate(session_id, created.operation_id, candidate(), base + 2)
            .await
            .unwrap();
        db.transition_verification_candidate(
            session_id,
            created.operation_id,
            candidate.candidate_id,
            candidate.revision,
            VerificationCandidateState::Running,
            digest("prepared-running"),
            base + 3,
        )
        .await
        .unwrap();
        db.transition_verification_candidate(
            session_id,
            created.operation_id,
            candidate.candidate_id,
            candidate.revision + 1,
            VerificationCandidateState::Valid,
            digest("prepared-valid"),
            base + 4,
        )
        .await
        .unwrap();
        let synthesizing = db
            .close_verification_collection(
                session_id,
                created.operation_id,
                collecting.revision,
                base + 5,
            )
            .await
            .unwrap();
        let dispatching = db
            .select_verification_candidate(
                session_id,
                created.operation_id,
                synthesizing.revision,
                candidate.candidate_id,
                base + 6,
            )
            .await
            .unwrap();
        let host_key = format!("prepared-{base}");
        let reserved = db
            .reserve_verification_dispatch(
                session_id,
                created.operation_id,
                dispatching.revision,
                &host_key,
                envelope(),
                base + 7,
            )
            .await
            .unwrap();
        let replay_reserved = db
            .reserve_verification_dispatch(
                session_id,
                created.operation_id,
                dispatching.revision,
                &host_key,
                envelope(),
                base + 7,
            )
            .await
            .unwrap();
        assert_eq!(replay_reserved.attempt_id, reserved.attempt_id);
        assert!(
            db.reserve_verification_dispatch(
                session_id,
                collecting.operation_id,
                dispatching.revision,
                &host_key,
                NewVerificationEnvelope {
                    batch_digest: digest("original"),
                    surrogate_kind: VerificationArtifactKind::ProposedCall,
                    model_visible_projection: json!({"operation":"different", "arguments": {}}),
                },
                10,
            )
            .await
            .is_err()
        );
        let executing = db
            .mark_verification_dispatch_executing(
                session_id,
                created.operation_id,
                reserved.revision,
                base + 8,
            )
            .await
            .unwrap();
        (created.operation_id, executing)
    }

    #[test]
    fn verification_ledger_db_operation_and_candidate_legal_transition_matrices_are_exhaustive() {
        for current in VerificationOperationState::ALL {
            for next in VerificationOperationState::ALL {
                let expected = matches!(
                    (current, next),
                    (
                        VerificationOperationState::Created,
                        VerificationOperationState::Collecting
                            | VerificationOperationState::Dispatching
                            | VerificationOperationState::SkippedBudgetRefused
                            | VerificationOperationState::Failed
                            | VerificationOperationState::Aborted
                    ) | (
                        VerificationOperationState::Collecting,
                        VerificationOperationState::Synthesizing
                            | VerificationOperationState::Aborted
                            | VerificationOperationState::Cancelled
                    ) | (
                        VerificationOperationState::Synthesizing,
                        VerificationOperationState::Dispatching
                            | VerificationOperationState::Failed
                            | VerificationOperationState::Cancelled
                            | VerificationOperationState::Aborted
                    ) | (
                        VerificationOperationState::Dispatching,
                        VerificationOperationState::Succeeded
                            | VerificationOperationState::Failed
                            | VerificationOperationState::Cancelled
                            | VerificationOperationState::Unknown
                    )
                );
                assert_eq!(
                    legal_operation_transition(current, next),
                    expected,
                    "unexpected operation transition {current:?} -> {next:?}"
                );
            }
        }

        for current in VerificationCandidateState::ALL {
            for next in VerificationCandidateState::ALL {
                let expected = matches!(
                    (current, next),
                    (
                        VerificationCandidateState::Queued,
                        VerificationCandidateState::Running
                            | VerificationCandidateState::Cancelled
                            | VerificationCandidateState::TimedOut
                    ) | (
                        VerificationCandidateState::Running,
                        VerificationCandidateState::Valid
                            | VerificationCandidateState::Invalid
                            | VerificationCandidateState::Cancelled
                            | VerificationCandidateState::TimedOut
                            | VerificationCandidateState::Malformed
                    )
                );
                assert_eq!(
                    current.legal_transition(next),
                    expected,
                    "unexpected candidate transition {current:?} -> {next:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn verification_ledger_db_candidate_terminal_states_record_late_completions() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "candidate-terminal-matrix").await;
        for (index, terminal) in [
            VerificationCandidateState::Valid,
            VerificationCandidateState::Invalid,
            VerificationCandidateState::Cancelled,
            VerificationCandidateState::TimedOut,
            VerificationCandidateState::Malformed,
        ]
        .into_iter()
        .enumerate()
        {
            let base = 10 + index as i64 * 10;
            let created = db
                .create_verification_operation(operation(session_id, agent_id), base)
                .await
                .unwrap();
            let collecting = db
                .start_verification_collection(
                    session_id,
                    created.operation_id,
                    created.revision,
                    base + 1,
                )
                .await
                .unwrap();
            let candidate = db
                .reserve_verification_candidate(
                    session_id,
                    collecting.operation_id,
                    candidate(),
                    base + 2,
                )
                .await
                .unwrap();
            let terminal_revision = if matches!(
                terminal,
                VerificationCandidateState::Valid
                    | VerificationCandidateState::Invalid
                    | VerificationCandidateState::Malformed
            ) {
                assert_eq!(
                    db.transition_verification_candidate(
                        session_id,
                        created.operation_id,
                        candidate.candidate_id,
                        candidate.revision,
                        VerificationCandidateState::Running,
                        digest("terminal-matrix-running"),
                        base + 3,
                    )
                    .await
                    .unwrap(),
                    CandidateTransitionOutcome::Transitioned
                );
                candidate.revision + 1
            } else {
                candidate.revision
            };
            assert_eq!(
                db.transition_verification_candidate(
                    session_id,
                    created.operation_id,
                    candidate.candidate_id,
                    terminal_revision,
                    terminal,
                    digest("terminal-matrix-terminal"),
                    base + 4,
                )
                .await
                .unwrap(),
                CandidateTransitionOutcome::Transitioned
            );
            assert_eq!(
                db.transition_verification_candidate(
                    session_id,
                    created.operation_id,
                    candidate.candidate_id,
                    0,
                    VerificationCandidateState::Valid,
                    digest(&format!("terminal-matrix-late-{index}")),
                    base + 5,
                )
                .await
                .unwrap(),
                CandidateTransitionOutcome::LateResult
            );
            let (state, late): (String, i64) = db
                .read(move |conn| {
                    Ok((
                        conn.query_row(
                            "SELECT state FROM verification_candidates WHERE candidate_id = ?1",
                            [candidate.candidate_id.to_string()],
                            |row| row.get(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM verification_late_results WHERE candidate_id = ?1",
                            [candidate.candidate_id.to_string()],
                            |row| row.get(0),
                        )?,
                    ))
                })
                .await
                .unwrap();
            assert_eq!((state.as_str(), late), (terminal.as_str(), 1));
        }
    }

    #[tokio::test]
    async fn verification_ledger_db_synthesis_terminal_matrix_is_exactly_one_suppressed_projection()
    {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "synthesis-terminal-matrix").await;
        for (index, synthesis_terminal) in
            VerificationSynthesisTerminal::ALL.into_iter().enumerate()
        {
            let base = 10 + index as i64 * 10;
            let created = db
                .create_verification_operation(operation(session_id, agent_id), base)
                .await
                .unwrap();
            let collecting = db
                .start_verification_collection(
                    session_id,
                    created.operation_id,
                    created.revision,
                    base + 1,
                )
                .await
                .unwrap();
            let synthesizing = db
                .close_verification_collection(
                    session_id,
                    created.operation_id,
                    collecting.revision,
                    base + 2,
                )
                .await
                .unwrap();
            let terminal = db
                .suppress_verification_synthesis(
                    session_id,
                    created.operation_id,
                    synthesizing.revision,
                    synthesis_terminal,
                    base + 3,
                )
                .await
                .unwrap();
            let expected_operation = match synthesis_terminal {
                VerificationSynthesisTerminal::Refused => VerificationOperationState::Cancelled,
                VerificationSynthesisTerminal::NoValidCandidate
                | VerificationSynthesisTerminal::Failed => VerificationOperationState::Failed,
            };
            assert_eq!(terminal.state, expected_operation);
            let (state, projections, events): (String, i64, i64) = db
                .read(move |conn| {
                    Ok((
                        conn.query_row(
                            "SELECT state FROM verification_syntheses WHERE operation_id = ?1",
                            [created.operation_id.to_string()],
                            |row| row.get(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1 AND state = 'suppressed'",
                            [created.operation_id.to_string()],
                            |row| row.get(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM verification_projection_events p
                             JOIN verification_projections v ON v.projection_id = p.projection_id
                             WHERE v.operation_id = ?1",
                            [created.operation_id.to_string()],
                            |row| row.get(0),
                        )?,
                    ))
                })
                .await
                .unwrap();
            assert_eq!(
                (state.as_str(), projections, events),
                (synthesis_terminal.as_str(), 1, 0)
            );
        }
    }

    #[tokio::test]
    async fn verification_ledger_db_transition_matrix_and_exactly_one_projection() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "ledger").await;
        let created = db
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let collecting = db
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let candidate = db
            .reserve_verification_candidate(session_id, collecting.operation_id, candidate(), 5)
            .await
            .unwrap();
        assert_eq!(
            db.transition_verification_candidate(
                session_id,
                collecting.operation_id,
                candidate.candidate_id,
                candidate.revision,
                VerificationCandidateState::Running,
                digest("running"),
                6
            )
            .await
            .unwrap(),
            CandidateTransitionOutcome::Transitioned
        );
        assert_eq!(
            db.transition_verification_candidate(
                session_id,
                collecting.operation_id,
                candidate.candidate_id,
                candidate.revision + 1,
                VerificationCandidateState::Valid,
                digest("valid"),
                7
            )
            .await
            .unwrap(),
            CandidateTransitionOutcome::Transitioned
        );
        let synthesizing = db
            .close_verification_collection(
                session_id,
                collecting.operation_id,
                collecting.revision,
                8,
            )
            .await
            .unwrap();
        let dispatching = db
            .select_verification_candidate(
                session_id,
                collecting.operation_id,
                synthesizing.revision,
                candidate.candidate_id,
                9,
            )
            .await
            .unwrap();
        let reserved = db
            .reserve_verification_dispatch(
                session_id,
                collecting.operation_id,
                dispatching.revision,
                "host-key",
                envelope(),
                10,
            )
            .await
            .unwrap();
        let executing = db
            .mark_verification_dispatch_executing(
                session_id,
                collecting.operation_id,
                reserved.revision,
                11,
            )
            .await
            .unwrap();
        let settled = db
            .settle_verification_dispatch(
                session_id,
                collecting.operation_id,
                executing.revision,
                DispatchSettlement::Succeeded,
                redacted(VerificationRedactionClass::DispatchSuccess, "host-success"),
                12,
            )
            .await
            .unwrap();
        assert_eq!(settled.state, VerificationOperationState::Succeeded);
        let (projections, committed, events): (i64, i64, i64) = db.read(move |conn| Ok((
            conn.query_row("SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
            conn.query_row("SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1 AND state = 'committed'", [created.operation_id.to_string()], |row| row.get(0))?,
            conn.query_row("SELECT COUNT(*) FROM verification_projection_events p JOIN verification_projections v ON v.projection_id = p.projection_id WHERE v.operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
        ))).await.unwrap();
        assert_eq!((projections, committed, events), (1, 1, 2));
        let ordered: Vec<(i64, i64)> = db
            .read(move |conn| {
                let mut statement = conn.prepare(
                    "SELECT p.ordinal, p.session_event_seq
                     FROM verification_projection_events p
                     JOIN verification_projections v ON v.projection_id = p.projection_id
                     WHERE v.operation_id = ?1 ORDER BY p.ordinal",
                )?;
                let rows = statement.query_map([created.operation_id.to_string()], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            ordered
                .iter()
                .map(|(ordinal, _)| *ordinal)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(ordered[0].1 < ordered[1].1);
        let replay = db
            .settle_verification_dispatch(
                session_id,
                created.operation_id,
                executing.revision,
                DispatchSettlement::Succeeded,
                redacted(VerificationRedactionClass::DispatchSuccess, "different"),
                13,
            )
            .await
            .unwrap();
        assert_eq!(replay.state, VerificationOperationState::Succeeded);
    }

    #[tokio::test]
    async fn verification_ledger_db_budget_branches_are_terminal_and_candidate_free() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "budget").await;
        let mut refuse = operation(session_id, agent_id);
        refuse.effective_candidate_count = 0;
        refuse.estimate_unavailable_action = Some(VerificationBudgetAction::Refuse);
        let refused = db.create_verification_operation(refuse, 3).await.unwrap();
        assert_eq!(
            refused.state,
            VerificationOperationState::SkippedBudgetRefused
        );
        let mut original = operation(session_id, agent_id);
        original.effective_candidate_count = 0;
        original.estimate_unavailable_action = Some(VerificationBudgetAction::DispatchOriginal);
        let created = db.create_verification_operation(original, 4).await.unwrap();
        let dispatching = db
            .start_verification_collection(session_id, created.operation_id, created.revision, 5)
            .await
            .unwrap();
        assert_eq!(dispatching.state, VerificationOperationState::Dispatching);
        let reserved = db
            .reserve_verification_dispatch(
                session_id,
                created.operation_id,
                dispatching.revision,
                "original-key",
                envelope(),
                6,
            )
            .await
            .unwrap();
        let unknown = db
            .settle_verification_dispatch(
                session_id,
                created.operation_id,
                reserved.revision,
                DispatchSettlement::Unknown,
                redacted(VerificationRedactionClass::DispatchUnknown, "unknown"),
                7,
            )
            .await
            .unwrap();
        assert_eq!(unknown.state, VerificationOperationState::Unknown);
        let (candidates, syntheses, projections, event_count): (i64, i64, i64, i64) = db.read(move |conn| Ok((
            conn.query_row("SELECT COUNT(*) FROM verification_candidates WHERE operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
            conn.query_row("SELECT COUNT(*) FROM verification_syntheses WHERE operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
            conn.query_row("SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1 AND state = 'suppressed'", [created.operation_id.to_string()], |row| row.get(0))?,
            conn.query_row("SELECT COUNT(*) FROM verification_projection_events p JOIN verification_projections v ON v.projection_id = p.projection_id WHERE v.operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
        ))).await.unwrap();
        assert_eq!(
            (candidates, syntheses, projections, event_count),
            (0, 0, 1, 0)
        );
    }

    #[tokio::test]
    async fn verification_ledger_db_terminal_dispatch_reservation_replays_exact_identity_only() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "terminal-reservation-replay").await;

        for (base, settlement, receipt) in [
            (
                10_i64,
                DispatchSettlement::Succeeded,
                RedactedVerificationJson::dispatch_success(digest("terminal-success")),
            ),
            (
                30_i64,
                DispatchSettlement::Failed,
                RedactedVerificationJson::dispatch_final_error(digest("terminal-failure")),
            ),
            (
                50_i64,
                DispatchSettlement::Unknown,
                RedactedVerificationJson::dispatch_unknown(digest("terminal-unknown")),
            ),
        ] {
            let (operation_id, executing) =
                prepared_selected_dispatch(&db, session_id, agent_id, base).await;
            db.settle_verification_dispatch(
                session_id,
                operation_id,
                executing.revision,
                settlement,
                receipt.clone(),
                base + 20,
            )
            .await
            .unwrap();

            let replay = db
                .reserve_verification_dispatch(
                    session_id,
                    operation_id,
                    -1,
                    &format!("prepared-{base}"),
                    envelope(),
                    base + 21,
                )
                .await
                .unwrap();
            assert!(replay.state.is_terminal());
            assert_eq!(replay.terminal_receipt.as_ref(), Some(&receipt));

            assert!(
                db.reserve_verification_dispatch(
                    session_id,
                    operation_id,
                    -1,
                    &format!("mismatched-{base}"),
                    envelope(),
                    base + 22,
                )
                .await
                .is_err()
            );
            assert!(db
                .reserve_verification_dispatch(
                    session_id,
                    operation_id,
                    -1,
                    &format!("prepared-{base}"),
                    NewVerificationEnvelope {
                        batch_digest: digest("original"),
                        surrogate_kind: VerificationArtifactKind::ProposedCall,
                        model_visible_projection: json!({"operation": "different", "arguments": {}}),
                    },
                    base + 23,
                )
                .await
                .is_err());
            let (attempt_count, projection_count, attempt_revision): (i64, i64, i64) = db
                .read(move |conn| {
                    Ok((
                        conn.query_row(
                            "SELECT COUNT(*) FROM verification_dispatch_attempts WHERE operation_id = ?1",
                            [operation_id.to_string()],
                            |row| row.get(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1",
                            [operation_id.to_string()],
                            |row| row.get(0),
                        )?,
                        conn.query_row(
                            "SELECT revision FROM verification_dispatch_attempts WHERE attempt_id = ?1",
                            [executing.attempt_id.to_string()],
                            |row| row.get(0),
                        )?,
                    ))
                })
                .await
                .unwrap();
            assert_eq!(
                (attempt_count, projection_count, attempt_revision),
                (1, 1, 2)
            );
        }
    }

    #[tokio::test]
    async fn verification_ledger_db_collection_close_replays_after_dispatch_and_terminal_settlement()
     {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "collection-close-replay").await;
        let (operation_id, executing) =
            prepared_selected_dispatch(&db, session_id, agent_id, 10).await;

        let dispatching = db
            .close_verification_collection(session_id, operation_id, -1, 30)
            .await
            .unwrap();
        assert_eq!(dispatching.state, VerificationOperationState::Dispatching);
        let terminal = db
            .settle_verification_dispatch(
                session_id,
                operation_id,
                executing.revision,
                DispatchSettlement::Succeeded,
                RedactedVerificationJson::dispatch_success(digest("close-replay-success")),
                31,
            )
            .await
            .unwrap();
        assert_eq!(terminal.state, VerificationOperationState::Succeeded);
        let replay = db
            .close_verification_collection(session_id, operation_id, -1, 32)
            .await
            .unwrap();
        assert_eq!(replay.state, VerificationOperationState::Succeeded);
        let ((closed_at, collection_revision), synthesis_count, projection_count): (
            (Option<i64>, i64),
            i64,
            i64,
        ) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT collection_closed_at_unix_ms, collection_revision
                         FROM verification_operations WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_syntheses WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (
                closed_at,
                collection_revision,
                synthesis_count,
                projection_count
            ),
            (Some(15), 1, 1, 1)
        );
    }

    #[tokio::test]
    async fn verification_ledger_db_separate_handle_close_replays_after_selection_without_mutation()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("verification-close-select-replay.sqlite");
        let closer = Db::open(&path).unwrap();
        let (session_id, agent_id) = owner(&closer, "close-select-replay").await;
        let created = closer
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let collecting = closer
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let candidate = closer
            .reserve_verification_candidate(session_id, created.operation_id, candidate(), 5)
            .await
            .unwrap();
        closer
            .transition_verification_candidate(
                session_id,
                created.operation_id,
                candidate.candidate_id,
                candidate.revision,
                VerificationCandidateState::Running,
                digest("close-select-running"),
                6,
            )
            .await
            .unwrap();
        closer
            .transition_verification_candidate(
                session_id,
                created.operation_id,
                candidate.candidate_id,
                candidate.revision + 1,
                VerificationCandidateState::Valid,
                digest("close-select-valid"),
                7,
            )
            .await
            .unwrap();
        let closed = closer
            .close_verification_collection(session_id, created.operation_id, collecting.revision, 8)
            .await
            .unwrap();
        assert_eq!(closed.state, VerificationOperationState::Synthesizing);

        let selector = Db::open(&path).unwrap();
        let selected = selector
            .select_verification_candidate(
                session_id,
                created.operation_id,
                closed.revision,
                candidate.candidate_id,
                9,
            )
            .await
            .unwrap();
        assert_eq!(selected.state, VerificationOperationState::Dispatching);
        let replay = closer
            .close_verification_collection(
                session_id,
                created.operation_id,
                collecting.revision,
                10,
            )
            .await
            .unwrap();
        assert_eq!(replay.state, VerificationOperationState::Dispatching);
        let ((closed_at, collection_revision), syntheses, projections): (
            (Option<i64>, i64),
            i64,
            i64,
        ) = closer
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT collection_closed_at_unix_ms, collection_revision
                         FROM verification_operations WHERE operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_syntheses WHERE operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (closed_at, collection_revision, syntheses, projections),
            (Some(8), 1, 1, 0)
        );
    }

    #[tokio::test]
    async fn verification_ledger_db_input_capacity_deadline_and_session_validation_are_fail_closed()
    {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "operation-validation").await;
        let (_other_session_id, other_agent_id) = owner(&db, "operation-validation-other").await;

        for (label, input) in [
            ("negative-requested", {
                let mut input = operation(session_id, agent_id);
                input.requested_candidate_count = -1;
                input
            }),
            ("requested-over-bound", {
                let mut input = operation(session_id, agent_id);
                input.requested_candidate_count = MAX_CANDIDATES + 1;
                input
            }),
            ("effective-over-requested", {
                let mut input = operation(session_id, agent_id);
                input.effective_candidate_count = input.requested_candidate_count + 1;
                input
            }),
            ("negative-effective", {
                let mut input = operation(session_id, agent_id);
                input.effective_candidate_count = -1;
                input
            }),
            ("negative-token-ceiling", {
                let mut input = operation(session_id, agent_id);
                input.total_token_ceiling = -1;
                input
            }),
            ("negative-cost-ceiling", {
                let mut input = operation(session_id, agent_id);
                input.estimated_cost_ceiling_microunits = -1;
                input
            }),
            ("token-reservation-over-ceiling", {
                let mut input = operation(session_id, agent_id);
                input.conservative_token_reservation = input.total_token_ceiling + 1;
                input
            }),
            ("cost-reservation-over-ceiling", {
                let mut input = operation(session_id, agent_id);
                input.conservative_cost_reservation_microunits =
                    input.estimated_cost_ceiling_microunits + 1;
                input
            }),
            ("unknown-estimate-has-effective-candidates", {
                let mut input = operation(session_id, agent_id);
                input.estimate_unavailable_action = Some(VerificationBudgetAction::Refuse);
                input
            }),
        ] {
            assert!(
                db.create_verification_operation(input, 3).await.is_err(),
                "{label} must be rejected"
            );
        }
        assert!(
            db.create_verification_operation(operation(session_id, other_agent_id), 4)
                .await
                .is_err()
        );
        let cross_session_rows: i64 = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM verification_operations
                     WHERE session_id = ?1 AND agent_instance_id = ?2",
                    params![session_id.to_string(), other_agent_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(cross_session_rows, 0);

        for (action, expected_state) in [
            (
                VerificationBudgetAction::Refuse,
                VerificationOperationState::SkippedBudgetRefused,
            ),
            (
                VerificationBudgetAction::DispatchOriginal,
                VerificationOperationState::Created,
            ),
        ] {
            let mut unknown = operation(session_id, agent_id);
            unknown.effective_candidate_count = 0;
            unknown.estimate_unavailable_action = Some(action);
            let created = db.create_verification_operation(unknown, 5).await.unwrap();
            assert_eq!(created.state, expected_state);
            assert_eq!(created.budget_action, Some(action));
        }

        let mut limited = operation(session_id, agent_id);
        limited.requested_candidate_count = 2;
        limited.effective_candidate_count = 1;
        let limited = db.create_verification_operation(limited, 10).await.unwrap();
        let collecting = db
            .start_verification_collection(session_id, limited.operation_id, limited.revision, 11)
            .await
            .unwrap();
        assert_eq!(collecting.state, VerificationOperationState::Collecting);
        db.reserve_verification_candidate(session_id, limited.operation_id, candidate(), 12)
            .await
            .unwrap();
        assert!(
            db.reserve_verification_candidate(session_id, limited.operation_id, candidate(), 13)
                .await
                .is_err()
        );
        let mut negative_candidate = candidate();
        negative_candidate.reserved_cost_microunits = -1;
        assert!(
            db.reserve_verification_candidate(
                session_id,
                limited.operation_id,
                negative_candidate,
                14,
            )
            .await
            .is_err()
        );

        for now in [100_i64, 101_i64] {
            let deadline_operation = db
                .create_verification_operation(operation(session_id, agent_id), now - 10)
                .await
                .unwrap();
            let collecting = db
                .start_verification_collection(
                    session_id,
                    deadline_operation.operation_id,
                    deadline_operation.revision,
                    now - 9,
                )
                .await
                .unwrap();
            assert!(
                db.reserve_verification_candidate(
                    session_id,
                    deadline_operation.operation_id,
                    candidate(),
                    now,
                )
                .await
                .is_err()
            );
            let ((state, closed_at), candidates): ((String, Option<i64>), i64) = db
                .read(move |conn| {
                    Ok((
                        conn.query_row(
                            "SELECT state, collection_closed_at_unix_ms
                             FROM verification_operations WHERE operation_id = ?1",
                            [deadline_operation.operation_id.to_string()],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM verification_candidates WHERE operation_id = ?1",
                            [deadline_operation.operation_id.to_string()],
                            |row| row.get(0),
                        )?,
                    ))
                })
                .await
                .unwrap();
            assert_eq!(
                (state.as_str(), closed_at, candidates),
                ("synthesizing", Some(now), 0),
                "deadline {now} must win before reservation"
            );
            assert_eq!(collecting.state, VerificationOperationState::Collecting);
        }
    }

    #[tokio::test]
    async fn verification_ledger_db_start_at_or_after_deadline_closes_once_and_replays() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "start-deadline-close").await;
        for now in [100_i64, 101_i64] {
            let created = db
                .create_verification_operation(operation(session_id, agent_id), now - 10)
                .await
                .unwrap();
            let closed = db
                .start_verification_collection(
                    session_id,
                    created.operation_id,
                    created.revision,
                    now,
                )
                .await
                .unwrap();
            assert_eq!(closed.state, VerificationOperationState::Synthesizing);
            let replay = db
                .start_verification_collection(session_id, created.operation_id, -1, now + 1)
                .await
                .unwrap();
            assert_eq!(replay.state, VerificationOperationState::Synthesizing);
            let ((closed_at, collection_revision), candidates, syntheses): (
                (Option<i64>, i64),
                i64,
                i64,
            ) = db
                .read(move |conn| {
                    Ok((
                        conn.query_row(
                            "SELECT collection_closed_at_unix_ms, collection_revision
                             FROM verification_operations WHERE operation_id = ?1",
                            [created.operation_id.to_string()],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM verification_candidates WHERE operation_id = ?1",
                            [created.operation_id.to_string()],
                            |row| row.get(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM verification_syntheses WHERE operation_id = ?1",
                            [created.operation_id.to_string()],
                            |row| row.get(0),
                        )?,
                    ))
                })
                .await
                .unwrap();
            assert_eq!(
                (closed_at, collection_revision, candidates, syntheses),
                (Some(now), 1, 0, 1)
            );
        }

        let mut original = operation(session_id, agent_id);
        original.effective_candidate_count = 0;
        original.estimate_unavailable_action = Some(VerificationBudgetAction::DispatchOriginal);
        let original = db
            .create_verification_operation(original, 90)
            .await
            .unwrap();
        let dispatching = db
            .start_verification_collection(
                session_id,
                original.operation_id,
                original.revision,
                101,
            )
            .await
            .unwrap();
        assert_eq!(dispatching.state, VerificationOperationState::Dispatching);
        let replay = db
            .start_verification_collection(session_id, original.operation_id, -1, 102)
            .await
            .unwrap();
        assert_eq!(replay.state, VerificationOperationState::Dispatching);
        let (closed_at, candidates, syntheses): (Option<i64>, i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT collection_closed_at_unix_ms FROM verification_operations WHERE operation_id = ?1",
                        [original.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_candidates WHERE operation_id = ?1",
                        [original.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_syntheses WHERE operation_id = ?1",
                        [original.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((closed_at, candidates, syntheses), (None, 0, 0));
    }

    #[tokio::test]
    async fn verification_ledger_db_deadline_wins_and_late_results_are_audit_only() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "deadline").await;
        let created = db
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let collecting = db
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let mut wrong_summary = candidate();
        wrong_summary.redacted_summary =
            RedactedVerificationJson::dispatch_success(digest("wrong-role"));
        assert!(
            db.reserve_verification_candidate(session_id, created.operation_id, wrong_summary, 5,)
                .await
                .is_err()
        );
        let candidate = db
            .reserve_verification_candidate(session_id, created.operation_id, candidate(), 6)
            .await
            .unwrap();
        let closed = db
            .close_verification_collection(
                session_id,
                created.operation_id,
                collecting.revision,
                100,
            )
            .await
            .unwrap();
        assert_eq!(closed.state, VerificationOperationState::Synthesizing);
        assert_eq!(
            db.transition_verification_candidate(
                session_id,
                created.operation_id,
                candidate.candidate_id,
                candidate.revision,
                VerificationCandidateState::Valid,
                digest("late-valid"),
                101
            )
            .await
            .unwrap(),
            CandidateTransitionOutcome::LateResult
        );
        let (state, late): (String, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_candidates WHERE candidate_id = ?1",
                        [candidate.candidate_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_late_results WHERE candidate_id = ?1",
                        [candidate.candidate_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((state.as_str(), late), ("timed_out", 1));
    }

    #[tokio::test]
    async fn verification_ledger_db_deadline_closes_before_queued_candidate_can_start() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "deadline-before-running").await;
        let created = db
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let collecting = db
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let queued = db
            .reserve_verification_candidate(session_id, created.operation_id, candidate(), 5)
            .await
            .unwrap();

        assert_eq!(
            db.transition_verification_candidate(
                session_id,
                created.operation_id,
                queued.candidate_id,
                queued.revision,
                VerificationCandidateState::Running,
                digest("must-not-start-at-deadline"),
                100,
            )
            .await
            .unwrap(),
            CandidateTransitionOutcome::AlreadyTerminal
        );
        let ((operation_state, closed_at), (candidate_state, candidate_revision), syntheses):
            ((String, Option<i64>), (String, i64), i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state, collection_closed_at_unix_ms
                         FROM verification_operations WHERE operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?,
                    conn.query_row(
                        "SELECT state, revision FROM verification_candidates WHERE candidate_id = ?1",
                        [queued.candidate_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_syntheses WHERE operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (
                operation_state.as_str(),
                closed_at,
                candidate_state.as_str(),
                candidate_revision,
                syntheses,
            ),
            ("synthesizing", Some(100), "timed_out", 1, 1)
        );
        assert_eq!(collecting.state, VerificationOperationState::Collecting);
    }

    #[tokio::test]
    async fn verification_ledger_db_session_isolation_restart_and_redaction_are_fail_closed() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "owner").await;
        let (other_session, _) = owner(&db, "other").await;
        let created = db
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        assert!(
            db.host_verification_operation(other_session, created.operation_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.start_verification_collection(
                other_session,
                created.operation_id,
                created.revision,
                4
            )
            .await
            .is_err()
        );
        let collecting = db
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let candidate = db
            .reserve_verification_candidate(session_id, created.operation_id, candidate(), 5)
            .await
            .unwrap();
        let recovered = db
            .recover_verification_operation(
                session_id,
                created.operation_id,
                None,
                redacted(VerificationRedactionClass::RestartAborted, "restart"),
                7,
            )
            .await
            .unwrap();
        assert_eq!(recovered.state, VerificationOperationState::Aborted);
        assert_eq!(
            recovered.pretool_context_capability_digest,
            digest("pretool-context-anchor")
        );
        let (candidate_state, projection_state): (String, String) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_candidates WHERE candidate_id = ?1",
                        [candidate.candidate_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM verification_projections WHERE operation_id = ?1",
                        [collecting.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (candidate_state.as_str(), projection_state.as_str()),
            ("cancelled", "suppressed")
        );
        assert!(RedactedVerificationJson::parse(r#"{"credential":"secret"}"#).is_err());
        assert!(RedactedVerificationJson::parse(r#"{"label":"safe"}"#).is_err());
        assert!(
            RedactedVerificationJson::parse(&format!(
                r#"{{"classification":"not_an_allowed_class","digest":"{}"}}"#,
                digest("safe").as_str()
            ))
            .is_err()
        );
        assert_eq!(
            redacted(VerificationRedactionClass::CandidateSummary, "safe").classification(),
            VerificationRedactionClass::CandidateSummary
        );
        assert!(
            validate_envelope(&NewVerificationEnvelope {
                batch_digest: digest("x"),
                surrogate_kind: VerificationArtifactKind::ProposedCall,
                model_visible_projection: json!({"provider_receipt":"raw"})
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn verification_ledger_db_restart_of_synthesizing_is_audited_and_terminalized() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "synthesizing-restart").await;
        let created = db
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let collecting = db
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let synthesizing = db
            .close_verification_collection(session_id, created.operation_id, collecting.revision, 5)
            .await
            .unwrap();
        assert_eq!(synthesizing.state, VerificationOperationState::Synthesizing);

        let recovered = db
            .recover_verification_operation(
                session_id,
                created.operation_id,
                None,
                redacted(
                    VerificationRedactionClass::RestartAborted,
                    "ignored-pre-dispatch-receipt",
                ),
                6,
            )
            .await
            .unwrap();
        assert_eq!(recovered.state, VerificationOperationState::Aborted);
        let (synthesis_state, nonterminal_syntheses, suppressed): (String, i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_syntheses WHERE operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_syntheses WHERE operation_id = ?1 AND state = 'pending'",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1 AND state = 'suppressed'",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (synthesis_state.as_str(), nonterminal_syntheses, suppressed),
            ("failed", 0, 1)
        );
    }

    #[tokio::test]
    async fn verification_ledger_db_preflight_budgets_and_write_unions_are_atomic() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "write-union").await;
        let created = db
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let collecting = db
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let mut over_budget = candidate();
        over_budget.reserved_tokens = 101;
        assert!(
            db.reserve_verification_candidate(session_id, created.operation_id, over_budget, 5)
                .await
                .is_err()
        );
        let mut over_cost = candidate();
        over_cost.reserved_cost_microunits = 101;
        assert!(
            db.reserve_verification_candidate(session_id, created.operation_id, over_cost, 5)
                .await
                .is_err()
        );
        let write = db
            .reserve_verification_candidate(session_id, created.operation_id, write_candidate(), 6)
            .await
            .unwrap();
        assert_eq!(
            db.transition_verification_candidate(
                session_id,
                created.operation_id,
                write.candidate_id,
                write.revision,
                VerificationCandidateState::Running,
                digest("write-running"),
                7,
            )
            .await
            .unwrap(),
            CandidateTransitionOutcome::Transitioned
        );
        assert_eq!(
            db.transition_verification_candidate(
                session_id,
                created.operation_id,
                write.candidate_id,
                write.revision + 1,
                VerificationCandidateState::Valid,
                digest("write-valid"),
                8,
            )
            .await
            .unwrap(),
            CandidateTransitionOutcome::Transitioned
        );
        let synthesizing = db
            .close_verification_collection(session_id, created.operation_id, collecting.revision, 9)
            .await
            .unwrap();
        assert!(
            db.select_verification_candidate(
                session_id,
                created.operation_id,
                synthesizing.revision,
                write.candidate_id,
                10,
            )
            .await
            .is_err()
        );
        assert!(
            db.synthesize_verification_write(
                session_id,
                created.operation_id,
                synthesizing.revision,
                vec![VerificationSynthesisArtifactSource {
                    candidate_id: write.candidate_id,
                    artifact_ordinal: 1,
                }],
                11,
            )
            .await
            .is_err()
        );
        let dispatching = db
            .synthesize_verification_write(
                session_id,
                created.operation_id,
                synthesizing.revision,
                vec![VerificationSynthesisArtifactSource {
                    candidate_id: write.candidate_id,
                    artifact_ordinal: 0,
                }],
                12,
            )
            .await
            .unwrap();
        assert_eq!(
            dispatching.operation.state,
            VerificationOperationState::Dispatching
        );
        assert!(
            db.reserve_verification_dispatch(
                session_id,
                created.operation_id,
                dispatching.operation.revision,
                "write-batch",
                NewVerificationEnvelope {
                    batch_digest: digest("wrong-write-batch"),
                    surrogate_kind: VerificationArtifactKind::WriteChangeSet,
                    model_visible_projection: json!({"operation":"write", "patch":"safe patch"}),
                },
                13,
            )
            .await
            .is_err()
        );
        let write_attempt = db
            .reserve_verification_dispatch(
                session_id,
                created.operation_id,
                dispatching.operation.revision,
                "write-batch",
                NewVerificationEnvelope {
                    batch_digest: dispatching.canonical_output_batch_digest,
                    surrogate_kind: VerificationArtifactKind::WriteChangeSet,
                    model_visible_projection: json!({"operation":"write", "patch":"safe patch"}),
                },
                14,
            )
            .await
            .unwrap();
        assert_eq!(write_attempt.state, VerificationDispatchState::Reserved);
        let members: i64 = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM verification_synthesis_artifacts s
                     JOIN verification_syntheses y ON y.synthesis_id = s.synthesis_id
                     WHERE y.operation_id = ?1",
                    [created.operation_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(members, 1);
    }

    #[tokio::test]
    async fn verification_ledger_db_precollection_failure_is_suppressed() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "precollection").await;
        let invalid = db
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let failed = db
            .fail_verification_pre_collection(
                session_id,
                invalid.operation_id,
                invalid.revision,
                redacted(
                    VerificationRedactionClass::InvalidOriginal,
                    "invalid-original",
                ),
                4,
            )
            .await
            .unwrap();
        assert_eq!(failed.state, VerificationOperationState::Failed);
        let (candidates, synthesis, projection): (i64, i64, String) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_candidates WHERE operation_id = ?1",
                        [invalid.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_syntheses WHERE operation_id = ?1",
                        [invalid.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM verification_projections WHERE operation_id = ?1",
                        [invalid.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (candidates, synthesis, projection.as_str()),
            (0, 0, "suppressed")
        );
    }

    #[tokio::test]
    async fn verification_ledger_db_failed_synthesis_has_one_suppressed_audit_and_no_selection() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "failed-synthesis").await;
        let created = db
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let collecting = db
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let synthesizing = db
            .close_verification_collection(session_id, created.operation_id, collecting.revision, 5)
            .await
            .unwrap();
        let terminal = db
            .suppress_verification_synthesis(
                session_id,
                created.operation_id,
                synthesizing.revision,
                VerificationSynthesisTerminal::Failed,
                6,
            )
            .await
            .unwrap();
        assert_eq!(terminal.state, VerificationOperationState::Failed);
        let ((synthesis_state, selected), envelopes, projections, events): ((String, Option<String>), i64, i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state, selected_candidate_id FROM verification_syntheses WHERE operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?,
                    conn.query_row("SELECT COUNT(*) FROM verification_projection_envelopes WHERE operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
                    conn.query_row("SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1 AND state = 'suppressed'", [created.operation_id.to_string()], |row| row.get(0))?,
                    conn.query_row("SELECT COUNT(*) FROM verification_projection_events p JOIN verification_projections v ON v.projection_id = p.projection_id WHERE v.operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(synthesis_state, "failed");
        assert!(selected.is_none());
        assert_eq!((envelopes, projections, events), (0, 1, 0));
    }

    #[tokio::test]
    async fn verification_ledger_db_pre_dispatch_cancel_is_cas_terminal_and_event_free() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "pre-dispatch-cancel").await;
        let created = db
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        assert_eq!(
            db.host_verification_operation(session_id, created.operation_id)
                .await
                .unwrap()
                .unwrap()
                .pretool_context_capability_digest,
            digest("pretool-context-anchor")
        );
        let collecting = db
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let candidate = db
            .reserve_verification_candidate(session_id, created.operation_id, candidate(), 5)
            .await
            .unwrap();
        let cancelled = db
            .cancel_verification_pre_dispatch(
                session_id,
                created.operation_id,
                collecting.revision,
                6,
            )
            .await
            .unwrap();
        assert_eq!(cancelled.state, VerificationOperationState::Cancelled);
        let replay = db
            .cancel_verification_pre_dispatch(
                session_id,
                created.operation_id,
                collecting.revision,
                7,
            )
            .await
            .unwrap();
        assert_eq!(replay.state, VerificationOperationState::Cancelled);
        let (candidate_state, projections, events): (String, i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_candidates WHERE candidate_id = ?1",
                        [candidate.candidate_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1 AND state = 'suppressed'",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projection_events p JOIN verification_projections v ON v.projection_id = p.projection_id WHERE v.operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (candidate_state.as_str(), projections, events),
            ("cancelled", 1, 0)
        );
        let created_only = db
            .create_verification_operation(operation(session_id, agent_id), 8)
            .await
            .unwrap();
        assert!(
            db.cancel_verification_pre_dispatch(
                session_id,
                created_only.operation_id,
                created_only.revision,
                9,
            )
            .await
            .is_err()
        );
        let (created_state, created_projections): (String, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_operations WHERE operation_id = ?1",
                        [created_only.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1",
                        [created_only.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (created_state.as_str(), created_projections),
            ("created", 0)
        );
        let synth_only = db
            .create_verification_operation(operation(session_id, agent_id), 10)
            .await
            .unwrap();
        let synth_collecting = db
            .start_verification_collection(
                session_id,
                synth_only.operation_id,
                synth_only.revision,
                11,
            )
            .await
            .unwrap();
        let synthesizing = db
            .close_verification_collection(
                session_id,
                synth_only.operation_id,
                synth_collecting.revision,
                12,
            )
            .await
            .unwrap();
        assert_eq!(
            db.cancel_verification_pre_dispatch(
                session_id,
                synth_only.operation_id,
                synthesizing.revision,
                13,
            )
            .await
            .unwrap()
            .state,
            VerificationOperationState::Cancelled
        );
    }

    #[tokio::test]
    async fn verification_ledger_db_original_no_submission_and_crash_recovery_are_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "original-recovery").await;
        let mut original = operation(session_id, agent_id);
        original.effective_candidate_count = 0;
        original.estimate_unavailable_action = Some(VerificationBudgetAction::DispatchOriginal);
        let created = db.create_verification_operation(original, 3).await.unwrap();
        let dispatching = db
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let attempt = db
            .reserve_verification_dispatch(
                session_id,
                created.operation_id,
                dispatching.revision,
                "original-not-submitted",
                envelope(),
                5,
            )
            .await
            .unwrap();
        let cancelled = db
            .cancel_verification_dispatch_no_submission(
                session_id,
                created.operation_id,
                attempt.revision,
                NoSubmissionProof::parse(redacted(
                    VerificationRedactionClass::NoSubmission,
                    "not-submitted",
                ))
                .unwrap(),
                6,
            )
            .await
            .unwrap();
        assert_eq!(cancelled.state, VerificationOperationState::Cancelled);
        let replay = db
            .recover_verification_operation(
                session_id,
                created.operation_id,
                Some(DispatchSettlement::Succeeded),
                redacted(
                    VerificationRedactionClass::DispatchSuccess,
                    "must-not-replace-cancel",
                ),
                7,
            )
            .await
            .unwrap();
        assert_eq!(replay.state, VerificationOperationState::Cancelled);
        let (attempt_state, projections, events): (String, i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_dispatch_attempts WHERE operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1 AND state = 'suppressed'",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projection_events p JOIN verification_projections v ON v.projection_id = p.projection_id WHERE v.operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (attempt_state.as_str(), projections, events),
            ("cancelled_no_submission", 1, 0)
        );
    }

    #[tokio::test]
    async fn verification_ledger_db_budget_original_success_and_failure_commit_normalized_surrogates()
     {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "original-terminal").await;
        for (label, settlement, now) in [
            ("original-success", DispatchSettlement::Succeeded, 10_i64),
            ("original-failure", DispatchSettlement::Failed, 30_i64),
        ] {
            let mut original = operation(session_id, agent_id);
            original.effective_candidate_count = 0;
            original.estimate_unavailable_action = Some(VerificationBudgetAction::DispatchOriginal);
            let created = db
                .create_verification_operation(original, now)
                .await
                .unwrap();
            let dispatching = db
                .start_verification_collection(
                    session_id,
                    created.operation_id,
                    created.revision,
                    now + 1,
                )
                .await
                .unwrap();
            let attempt = db
                .reserve_verification_dispatch(
                    session_id,
                    created.operation_id,
                    dispatching.revision,
                    label,
                    envelope(),
                    now + 2,
                )
                .await
                .unwrap();
            let replay_attempt = db
                .reserve_verification_dispatch(
                    session_id,
                    created.operation_id,
                    dispatching.revision,
                    label,
                    envelope(),
                    now + 2,
                )
                .await
                .unwrap();
            assert_eq!(replay_attempt.attempt_id, attempt.attempt_id);
            let terminal = db
                .settle_verification_dispatch(
                    session_id,
                    created.operation_id,
                    attempt.revision,
                    settlement,
                    redacted(
                        match settlement {
                            DispatchSettlement::Succeeded => {
                                VerificationRedactionClass::DispatchSuccess
                            }
                            DispatchSettlement::Failed => {
                                VerificationRedactionClass::DispatchFinalError
                            }
                            _ => unreachable!("budget original test only settles proved outcomes"),
                        },
                        label,
                    ),
                    now + 3,
                )
                .await
                .unwrap();
            assert_eq!(
                terminal.state,
                if settlement == DispatchSettlement::Succeeded {
                    VerificationOperationState::Succeeded
                } else {
                    VerificationOperationState::Failed
                }
            );
            let (kind, candidates, syntheses, committed, events): (String, i64, i64, i64, i64) = db
                .read(move |conn| {
                    Ok((
                        conn.query_row("SELECT surrogate_kind FROM verification_projection_envelopes WHERE operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
                        conn.query_row("SELECT COUNT(*) FROM verification_candidates WHERE operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
                        conn.query_row("SELECT COUNT(*) FROM verification_syntheses WHERE operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
                        conn.query_row("SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1 AND state = 'committed'", [created.operation_id.to_string()], |row| row.get(0))?,
                        conn.query_row("SELECT COUNT(*) FROM verification_projection_events p JOIN verification_projections v ON v.projection_id = p.projection_id WHERE v.operation_id = ?1", [created.operation_id.to_string()], |row| row.get(0))?,
                    ))
                })
                .await
                .unwrap();
            assert_eq!(kind, "normalized_original");
            assert_eq!((candidates, syntheses, committed, events), (0, 0, 1, 2));
        }
    }

    #[tokio::test]
    async fn verification_ledger_db_projection_event_composite_session_fk_rejects_cross_session() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "projection-owner").await;
        let (operation_id, executing) =
            prepared_selected_dispatch(&db, session_id, agent_id, 3).await;
        db.settle_verification_dispatch(
            session_id,
            operation_id,
            executing.revision,
            DispatchSettlement::Succeeded,
            redacted(
                VerificationRedactionClass::DispatchSuccess,
                "projection-success",
            ),
            20,
        )
        .await
        .unwrap();
        let projection_id: String = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT projection_id FROM verification_projections WHERE operation_id = ?1",
                    [operation_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        let (other_session, _) = owner(&db, "projection-other").await;
        let rejected = db
            .transaction(move |conn| {
                conn.execute(
                    "INSERT INTO session_events (session_id, ts_ms, type, data_json) VALUES (?1, 21, 'notice', '{}')",
                    [other_session.to_string()],
                )?;
                let other_seq = conn.last_insert_rowid();
                conn.execute(
                    "INSERT INTO verification_projection_events (projection_id, ordinal, session_id, session_event_seq)
                     VALUES (?1, 99, ?2, ?3)",
                    params![projection_id, other_session.to_string(), other_seq],
                )?;
                Ok(())
            })
            .await;
        assert!(rejected.is_err());
    }

    #[tokio::test]
    async fn verification_ledger_db_effect_before_settlement_recovers_once_without_raw_receipts() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "crash-recovery").await;
        let (operation_id, executing) =
            prepared_selected_dispatch(&db, session_id, agent_id, 3).await;
        inject_settlement_fault_once(operation_id);
        assert!(
            db.settle_verification_dispatch(
                session_id,
                operation_id,
                executing.revision,
                DispatchSettlement::Failed,
                redacted(
                    VerificationRedactionClass::DispatchFinalError,
                    "effect-before-crash"
                ),
                19,
            )
            .await
            .is_err()
        );
        let uncommitted: (String, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_operations WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((uncommitted.0.as_str(), uncommitted.1), ("dispatching", 0));
        let recovered = db
            .recover_verification_operation(
                session_id,
                operation_id,
                Some(DispatchSettlement::Failed),
                redacted(VerificationRedactionClass::DispatchFinalError, "safe"),
                20,
            )
            .await
            .unwrap();
        assert_eq!(recovered.state, VerificationOperationState::Failed);
        let terminal = db
            .recover_verification_operation(
                session_id,
                operation_id,
                Some(DispatchSettlement::Succeeded),
                redacted(
                    VerificationRedactionClass::DispatchSuccess,
                    "ignored-replay",
                ),
                21,
            )
            .await
            .unwrap();
        assert_eq!(terminal.state, VerificationOperationState::Failed);
        let (
            attempt_revision,
            committed,
            event_count,
            secret_count,
            recovery_call,
            recovery_result,
            recovery_call_id,
            recovery_result_call_id,
        ): (i64, i64, i64, i64, String, String, String, String) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT revision FROM verification_dispatch_attempts WHERE attempt_id = ?1",
                        [executing.attempt_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1 AND state = 'committed'",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projection_events p JOIN verification_projections v ON v.projection_id = p.projection_id WHERE v.operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_dispatch_attempts WHERE redacted_receipt_json LIKE '%provider%' OR redacted_receipt_json LIKE '%secret%'",
                        [],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT e.data_json
                         FROM session_events e
                         JOIN verification_projection_events p
                           ON p.session_id = e.session_id AND p.session_event_seq = e.seq
                         JOIN verification_projections v ON v.projection_id = p.projection_id
                         WHERE v.operation_id = ?1 AND p.ordinal = 0",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT e.data_json
                         FROM session_events e
                         JOIN verification_projection_events p
                           ON p.session_id = e.session_id AND p.session_event_seq = e.seq
                         JOIN verification_projections v ON v.projection_id = p.projection_id
                         WHERE v.operation_id = ?1 AND p.ordinal = 1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT e.call_id
                         FROM session_events e
                         JOIN verification_projection_events p
                           ON p.session_id = e.session_id AND p.session_event_seq = e.seq
                         JOIN verification_projections v ON v.projection_id = p.projection_id
                         WHERE v.operation_id = ?1 AND p.ordinal = 0",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT e.call_id
                         FROM session_events e
                         JOIN verification_projection_events p
                           ON p.session_id = e.session_id AND p.session_event_seq = e.seq
                         JOIN verification_projections v ON v.projection_id = p.projection_id
                         WHERE v.operation_id = ?1 AND p.ordinal = 1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (attempt_revision, committed, event_count, secret_count),
            (2, 1, 2, 0)
        );
        let recovery_call: Value = serde_json::from_str(&recovery_call).unwrap();
        assert_eq!(recovery_call["data"]["operation"], "call");
        assert_eq!(recovery_call["data"]["arguments"]["path"], "src/lib.rs");
        assert_eq!(recovery_call["data"]["patch"], "safe patch body");
        assert!(recovery_call_id.starts_with("verification:"));
        assert_eq!(recovery_call_id, recovery_result_call_id);
        assert!(!recovery_call.to_string().contains("effect-before-crash"));
        let recovery_result: Value = serde_json::from_str(&recovery_result).unwrap();
        assert_eq!(
            recovery_result["data"]["classification"],
            "recovery_final_error"
        );
        assert!(!recovery_result.to_string().contains("effect-before-crash"));
        let (success_operation, success_attempt) =
            prepared_selected_dispatch(&db, session_id, agent_id, 30).await;
        inject_settlement_fault_once(success_operation);
        assert!(
            db.settle_verification_dispatch(
                session_id,
                success_operation,
                success_attempt.revision,
                DispatchSettlement::Succeeded,
                redacted(
                    VerificationRedactionClass::DispatchSuccess,
                    "success-before-crash"
                ),
                40,
            )
            .await
            .is_err()
        );
        let recovered_success = db
            .recover_verification_operation(
                session_id,
                success_operation,
                Some(DispatchSettlement::Succeeded),
                redacted(VerificationRedactionClass::DispatchSuccess, "success"),
                41,
            )
            .await
            .unwrap();
        assert_eq!(
            recovered_success.state,
            VerificationOperationState::Succeeded
        );
        let (success_projections, success_events, success_calls, success_completions):
            (i64, i64, i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1 AND state = 'committed'",
                        [success_operation.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projection_events p JOIN verification_projections v ON v.projection_id = p.projection_id WHERE v.operation_id = ?1",
                        [success_operation.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM session_events e
                         JOIN verification_projection_events p
                           ON p.session_id = e.session_id AND p.session_event_seq = e.seq
                         JOIN verification_projections v ON v.projection_id = p.projection_id
                         WHERE v.operation_id = ?1 AND e.type = 'tool_call'",
                        [success_operation.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM session_events e
                         JOIN verification_projection_events p
                           ON p.session_id = e.session_id AND p.session_event_seq = e.seq
                         JOIN verification_projections v ON v.projection_id = p.projection_id
                         WHERE v.operation_id = ?1 AND e.type = 'tool_call_completed'",
                        [success_operation.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (
                success_projections,
                success_events,
                success_calls,
                success_completions
            ),
            (1, 2, 1, 1)
        );
    }

    #[tokio::test]
    async fn verification_ledger_db_recovery_rejects_tampered_durable_envelope_without_projection()
    {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "tampered-recovery-envelope").await;
        let (operation_id, executing) =
            prepared_selected_dispatch(&db, session_id, agent_id, 3).await;
        db.write(move |conn| {
            conn.execute(
                "UPDATE verification_projection_envelopes
                 SET model_visible_projection_json = ?1
                 WHERE operation_id = ?2 AND session_id = ?3",
                params![
                    r#"{"operation":"call","arguments":{"path":"tampered"}}"#,
                    operation_id.to_string(),
                    session_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        assert!(
            db.recover_verification_operation(
                session_id,
                operation_id,
                Some(DispatchSettlement::Succeeded),
                redacted(
                    VerificationRedactionClass::DispatchSuccess,
                    "safe-host-proof"
                ),
                20,
            )
            .await
            .is_err()
        );
        let (state, attempt_revision, projections): (String, i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_operations WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT revision FROM verification_dispatch_attempts WHERE attempt_id = ?1",
                        [executing.attempt_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (state.as_str(), attempt_revision, projections),
            ("dispatching", 1, 0)
        );
    }

    #[tokio::test]
    async fn verification_ledger_db_normal_settlement_derives_only_envelope_events_and_rejects_tampering()
     {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "normal-envelope-projection").await;
        let (operation_id, executing) =
            prepared_selected_dispatch(&db, session_id, agent_id, 3).await;

        db.write(move |conn| {
            conn.execute(
                "UPDATE verification_projection_envelopes
                 SET model_visible_projection_json = ?1
                 WHERE operation_id = ?2 AND session_id = ?3",
                params![
                    r#"{"operation":"call","arguments":{"path":"tampered"}}"#,
                    operation_id.to_string(),
                    session_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.settle_verification_dispatch(
                session_id,
                operation_id,
                executing.revision,
                DispatchSettlement::Succeeded,
                RedactedVerificationJson::dispatch_success(digest("normal-safe-host-receipt")),
                20,
            )
            .await
            .is_err()
        );
        let (state, attempt_revision, projections, events): (String, i64, i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_operations WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT revision FROM verification_dispatch_attempts WHERE attempt_id = ?1",
                        [executing.attempt_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projection_events p
                         JOIN verification_projections v ON v.projection_id = p.projection_id
                         WHERE v.operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (state.as_str(), attempt_revision, projections, events),
            ("dispatching", 1, 0, 0)
        );

        let (clean_operation, clean_executing) =
            prepared_selected_dispatch(&db, session_id, agent_id, 30).await;
        db.settle_verification_dispatch(
            session_id,
            clean_operation,
            clean_executing.revision,
            DispatchSettlement::Succeeded,
            RedactedVerificationJson::dispatch_success(digest("normal-clean-host-receipt")),
            40,
        )
        .await
        .unwrap();
        let events: Vec<(String, Option<String>, String)> = db
            .read(move |conn| {
                let mut statement = conn.prepare(
                    "SELECT e.type, e.call_id, e.data_json
                     FROM session_events e
                     JOIN verification_projection_events p
                       ON p.session_id = e.session_id AND p.session_event_seq = e.seq
                     JOIN verification_projections v ON v.projection_id = p.projection_id
                     WHERE v.operation_id = ?1 ORDER BY p.ordinal",
                )?;
                statement
                    .query_map([clean_operation.to_string()], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, "tool_call");
        assert_eq!(events[1].0, "tool_call_completed");
        assert_eq!(events[0].1, events[1].1);
        let call: Value = serde_json::from_str(&events[0].2).unwrap();
        let result: Value = serde_json::from_str(&events[1].2).unwrap();
        assert_eq!(call["data"]["operation"], "call");
        assert_eq!(call["data"]["arguments"]["path"], "src/lib.rs");
        assert_eq!(call["data"]["patch"], "safe patch body");
        assert_eq!(result["data"]["classification"], "dispatch_success");
        assert!(!result.to_string().contains("normal-clean-host-receipt"));
    }

    #[tokio::test]
    async fn verification_ledger_db_dispatch_recovery_requires_the_unknown_receipt_role() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, agent_id) = owner(&db, "recovery-unknown-role").await;
        let (operation_id, executing) =
            prepared_selected_dispatch(&db, session_id, agent_id, 3).await;

        assert!(
            db.recover_verification_operation(
                session_id,
                operation_id,
                None,
                RedactedVerificationJson::invalid_original(digest("wrong-recovery-role")),
                20,
            )
            .await
            .is_err()
        );
        let after_rejection: (String, i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_operations WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT revision FROM verification_dispatch_attempts WHERE attempt_id = ?1",
                        [executing.attempt_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_projections WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (
                after_rejection.0.as_str(),
                after_rejection.1,
                after_rejection.2
            ),
            ("dispatching", 1, 0)
        );
        let terminal = db
            .recover_verification_operation(
                session_id,
                operation_id,
                None,
                RedactedVerificationJson::dispatch_unknown(digest("unknown-host-proof")),
                21,
            )
            .await
            .unwrap();
        assert_eq!(terminal.state, VerificationOperationState::Unknown);
    }

    #[tokio::test]
    async fn verification_ledger_db_separate_connections_have_one_candidate_cas_winner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("verification-ledger.sqlite");
        let first = Db::open(&path).unwrap();
        let (session_id, agent_id) = owner(&first, "concurrent-ledger").await;
        let created = first
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let collecting = first
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let candidate = first
            .reserve_verification_candidate(session_id, collecting.operation_id, candidate(), 5)
            .await
            .unwrap();
        let second = Db::open(&path).unwrap();
        let first_task = first.transition_verification_candidate(
            session_id,
            created.operation_id,
            candidate.candidate_id,
            candidate.revision,
            VerificationCandidateState::Running,
            digest("first-winner"),
            6,
        );
        let second_task = second.transition_verification_candidate(
            session_id,
            created.operation_id,
            candidate.candidate_id,
            candidate.revision,
            VerificationCandidateState::Running,
            digest("second-winner"),
            6,
        );
        let (first_outcome, second_outcome) = tokio::join!(first_task, second_task);
        let first_outcome = first_outcome.unwrap();
        let second_outcome = second_outcome.unwrap();
        assert!(
            matches!(first_outcome, CandidateTransitionOutcome::Transitioned)
                ^ matches!(second_outcome, CandidateTransitionOutcome::Transitioned)
        );
        assert!(
            matches!(first_outcome, CandidateTransitionOutcome::RevisionConflict)
                ^ matches!(second_outcome, CandidateTransitionOutcome::RevisionConflict)
        );
        let (state, revision): (String, i64) = first
            .read(move |conn| {
                conn.query_row(
                    "SELECT state, revision FROM verification_candidates WHERE candidate_id = ?1",
                    [candidate.candidate_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!((state.as_str(), revision), ("running", 1));
    }

    #[tokio::test]
    async fn verification_ledger_db_separate_file_deadline_close_race_has_valid_or_late_winner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("verification-deadline-race.sqlite");
        let closer = Db::open(&path).unwrap();
        let (session_id, agent_id) = owner(&closer, "deadline-race").await;
        let created = closer
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let collecting = closer
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let candidate = closer
            .reserve_verification_candidate(session_id, created.operation_id, candidate(), 5)
            .await
            .unwrap();
        assert_eq!(
            closer
                .transition_verification_candidate(
                    session_id,
                    created.operation_id,
                    candidate.candidate_id,
                    candidate.revision,
                    VerificationCandidateState::Running,
                    digest("race-running"),
                    6,
                )
                .await
                .unwrap(),
            CandidateTransitionOutcome::Transitioned
        );
        let committer = Db::open(&path).unwrap();
        let close = closer.close_verification_collection(
            session_id,
            created.operation_id,
            collecting.revision,
            100,
        );
        let valid = committer.transition_verification_candidate(
            session_id,
            created.operation_id,
            candidate.candidate_id,
            candidate.revision + 1,
            VerificationCandidateState::Valid,
            digest("race-valid"),
            99,
        );
        let (closed, valid_outcome) = tokio::join!(close, valid);
        assert_eq!(
            closed.unwrap().state,
            VerificationOperationState::Synthesizing
        );
        assert!(matches!(
            valid_outcome.unwrap(),
            CandidateTransitionOutcome::Transitioned | CandidateTransitionOutcome::LateResult
        ));
        let (state, late): (String, i64) = closer
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_candidates WHERE candidate_id = ?1",
                        [candidate.candidate_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_late_results WHERE candidate_id = ?1",
                        [candidate.candidate_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        match state.as_str() {
            "valid" => assert_eq!(late, 0),
            "timed_out" => assert_eq!(late, 1),
            other => panic!("unexpected deadline race candidate state: {other}"),
        }
    }

    #[tokio::test]
    async fn verification_ledger_db_separate_file_deadline_race_never_starts_queued_work() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("verification-deadline-running-race.sqlite");
        let closer = Db::open(&path).unwrap();
        let (session_id, agent_id) = owner(&closer, "deadline-running-race").await;
        let created = closer
            .create_verification_operation(operation(session_id, agent_id), 3)
            .await
            .unwrap();
        let collecting = closer
            .start_verification_collection(session_id, created.operation_id, created.revision, 4)
            .await
            .unwrap();
        let queued = closer
            .reserve_verification_candidate(session_id, created.operation_id, candidate(), 5)
            .await
            .unwrap();
        let runner = Db::open(&path).unwrap();
        let close = closer.close_verification_collection(
            session_id,
            created.operation_id,
            collecting.revision,
            100,
        );
        let start = runner.transition_verification_candidate(
            session_id,
            created.operation_id,
            queued.candidate_id,
            queued.revision,
            VerificationCandidateState::Running,
            digest("late-running-race"),
            100,
        );
        let (closed, start_outcome) = tokio::join!(close, start);
        assert_eq!(
            closed.unwrap().state,
            VerificationOperationState::Synthesizing
        );
        assert_eq!(
            start_outcome.unwrap(),
            CandidateTransitionOutcome::AlreadyTerminal
        );
        let (operation_state, candidate_state, starts): (String, String, i64) = closer
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM verification_operations WHERE operation_id = ?1",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM verification_candidates WHERE candidate_id = ?1",
                        [queued.candidate_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM verification_candidates
                         WHERE operation_id = ?1 AND state = 'running'",
                        [created.operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (operation_state.as_str(), candidate_state.as_str(), starts),
            ("synthesizing", "timed_out", 0)
        );
    }
}
