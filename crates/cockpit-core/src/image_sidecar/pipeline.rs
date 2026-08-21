//! The single authorized image-sidecar invocation pipeline.
//!
//! This module is the production integration that joins the two previously
//! unwired islands — the selection/policy island ([`super`]) and the
//! dossier/ask-image island ([`super::dossier`]) — into one authorized egress
//! path shared by both purposes (`dossier` and `ask_image`).
//!
//! # The security invariant
//!
//! There is exactly one orchestrator, [`SidecarPipeline::invoke`], and it is
//! the ONLY path that reaches a provider. Every invocation runs, in order:
//!
//! 1. resolve the session-authorized image attachment
//!    ([`SidecarAttachmentResolver`]);
//! 2. bind the destination tuple from the resolved sidecar selection;
//! 3. check destination grants and run [`evaluate_egress_authority`] — a
//!    denial or a missing sidecar returns a stable typed error and makes
//!    **zero** provider calls (fail closed);
//! 4. acquire a media reservation through the injected
//!    [`ReservationAcquirer`] (the production impl is
//!    [`LedgerReservationAcquirer`], backed by the real media-reservation
//!    ledger — never the test-only fake);
//! 5. build and [`CapturedProviderRequest::verify`] the provider request
//!    (exactly one image plus one fixed dossier instruction OR the caller's
//!    validated question — no transcript/system/memory/other content);
//! 6. dispatch through the injected [`SidecarProviderTransport`] (the one
//!    egress chokepoint) — reached only after steps 3 and 4 both pass;
//! 7. validate the dossier JSON or ask-image answer, with at most one repair
//!    inference that independently re-authorizes and re-reserves;
//! 8. cache dossier bodies only in the memory-only [`DossierCache`]; persist
//!    only safe metadata (the reservation row) to SQLite.
//!
//! Both purposes enter through the same [`SidecarPipeline::invoke`] seam,
//! parameterized by [`Purpose`]/[`PurposeBody`]; there is no second dispatch
//! stack.
//!
//! # What is deferred (see the follow-up notes in this file)
//!
//! The production [`SidecarProviderTransport`] adapter over the engine's
//! inference chokepoint (`engine::model::Model::complete_captured`) and the
//! production [`SidecarAttachmentResolver`] over the typed-media attachment
//! authority are environment-blocked in this tree exactly as `read_image` is
//! (the typed session attachment authority is not yet reachable from
//! `ToolCtx`). They are provided here as explicit fail-closed stubs so no
//! unauthorized or plausibly-wrong egress path exists; the injected seams keep
//! the whole pipeline exercised end to end under test.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use super::dossier::{
    AskImageAnswer, AskImageAttachmentKind, AskImageError, AskImageService, DOSSIER_SCHEMA_VERSION,
    DossierCache, DossierCacheKey, DossierClock, DossierValidator, DurableImageRef,
    ImageSidecarDossier, RepairController,
};
use super::{
    ApprovalMode, CAPABILITY_CONTRACT_REVISION, CapturedProviderRequest, CapturedRequestViolation,
    DestinationGrantStore, DestinationPolicy, DestinationPolicyDigest, DestinationTuple,
    EgressDecision, EgressFields, GrantAuthorizationOutcome, GrantScope, HardGateFailureReason,
    MediaClass, PermittedContext, ProjectIdentity, Purpose, PurposeBody, ReservationAcquirer,
    ReservationAcquisition, ReservationFailureReason, ReservationRequest, ReservationSettleError,
    SelectedSidecar, SidecarInvocationCap, evaluate_egress_authority,
};

/// Process-global monotonic sequence for generating fresh, unique reservation
/// ids so no invocation can ride a prior/terminalized reservation.
static NEXT_RESERVATION_SEQ: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Injected seams
// ---------------------------------------------------------------------------

/// A resolved, session-authorized image attachment. Produced by the
/// [`SidecarAttachmentResolver`] before any policy decision. Carries only the
/// safe identity the pipeline needs — never raw pixels beyond the opaque
/// artifact id used to build the single-image provider request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImageAttachment {
    /// The durable-image reference used by the existing typed-media rules.
    pub durable: DurableImageRef,
    /// Whether the attachment is a durable image or a one-use transient
    /// computer frame (which is never addressable by `ask_image`).
    pub kind: AskImageAttachmentKind,
    /// The opaque artifact id placed into the single permitted image slot of
    /// the provider request.
    pub image_artifact_id: String,
    /// Host-authoritative source pixel dimensions (from the durable attachment
    /// metadata). Used to overwrite provider-claimed dossier provenance so the
    /// exported "safe metadata" cannot carry provider-controlled values.
    pub source_width_px: u32,
    pub source_height_px: u32,
}

/// Resolves an opaque session-authorized image attachment id into the safe
/// identity the pipeline needs. The production impl is environment-blocked in
/// this tree (see [`UnavailableAttachmentResolver`]); tests inject a fake.
#[async_trait]
pub trait SidecarAttachmentResolver: Send + Sync {
    async fn resolve(
        &self,
        attachment_id: &str,
        session_id: &str,
    ) -> Result<ResolvedImageAttachment, SidecarInvokeError>;
}

/// A provider request built by the pipeline. It carries exactly one image plus
/// one fixed dossier instruction or one validated question — never transcript,
/// system/developer messages, memories, other attachments, computer history,
/// or credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarProviderRequest {
    pub provider: String,
    pub model: String,
    pub purpose: Purpose,
    pub instruction_version: u8,
    /// The fixed dossier instruction or the caller's validated question.
    pub body: String,
    /// The single authorized image artifact id.
    pub image_artifact_id: String,
    pub destination_policy_digest_hex: String,
}

/// The raw provider response. The pipeline validates it before exposing it and
/// never persists it to SQLite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarProviderResponse {
    /// The raw model output text (dossier JSON or ask-image answer JSON).
    pub output_text: String,
}

/// The single provider/model egress chokepoint used by the pipeline. The
/// production impl reuses the engine's existing inference path
/// (`Model::complete_captured`); it is provided here as a fail-closed stub
/// (see [`UnavailableProviderTransport`]) because that path is
/// environment-blocked in this tree. Tests inject a scripted/spy transport.
///
/// The pipeline calls `dispatch` ONLY after egress authority and the media
/// reservation have both been granted — a denial makes zero calls.
#[async_trait]
pub trait SidecarProviderTransport: Send + Sync {
    async fn dispatch(
        &self,
        request: &SidecarProviderRequest,
    ) -> Result<SidecarProviderResponse, SidecarInvokeError>;
}

// ---------------------------------------------------------------------------
// Typed pipeline errors (stable, closed set)
// ---------------------------------------------------------------------------

/// The stable typed outcome errors for an authorized invocation. Each variant
/// is a distinct, closed reason; none is stringly-typed at a decision point.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SidecarInvokeError {
    /// A hard egress gate failed (destination denied, cap exhausted, missing
    /// credential, stale capability, session authorization). Zero provider
    /// contact.
    #[error("egress hard gate failed: {0:?}")]
    EgressDenied(HardGateFailureReason),
    /// No grant exists and the approval mode declined authority. Zero provider
    /// contact.
    #[error("egress not authorized")]
    EgressNotAuthorized,
    /// The media reservation was refused or rolled back. Zero provider
    /// contact.
    #[error("media reservation failed: {0:?}")]
    ReservationFailed(ReservationFailureReason),
    /// The attachment failed the existing typed-media rules (missing, wrong
    /// session, expired, quarantined, over limit).
    #[error("attachment rejected: {0}")]
    AttachmentRejected(AskImageError),
    /// `ask_image` was asked to address a one-use transient computer frame.
    /// Rejected before any provider contact.
    #[error("transient frames cannot be used by ask_image")]
    TransientNotAllowed,
    /// The selection's carried destination-policy digest does not match a
    /// digest recomputed from its actual `(provider, model, destination)`. A
    /// forged/mismatched selection can never authorize egress. Zero provider
    /// contact.
    #[error("destination binding mismatch: selection digest is not authentic")]
    DestinationBindingMismatch,
    /// The resolver returned an attachment whose id differs from the requested
    /// id. Fail closed — a resolver may not substitute another image.
    #[error("resolved attachment id does not match the requested attachment id")]
    ResolvedAttachmentMismatch,
    /// The built provider request violated the one-image/one-instruction
    /// boundary. Fail closed before dispatch.
    #[error("provider request boundary violated: {0}")]
    RequestBoundary(CapturedRequestViolation),
    /// The provider output failed validation after the single permitted
    /// repair.
    #[error("invalid provider output")]
    InvalidOutput,
    /// The provider transport failed. The `ambiguous_handoff` signal is carried
    /// for the future real-transport follow-up (which can distinguish
    /// definitely-not-sent from a lost-response ambiguous handoff and keep the
    /// `AtHandoff` charge). In THIS tree the transport performs no real external
    /// egress, so every transport error is treated identically: the reservation
    /// is released (no leaked row). The signal is not acted on here.
    #[error("provider transport error (ambiguous_handoff={ambiguous_handoff}): {message}")]
    Transport {
        message: String,
        ambiguous_handoff: bool,
    },
    /// The reservation could not be terminally settled after a dispatch. Fail
    /// closed rather than report a clean success over a possibly-leaked row.
    #[error("reservation could not be settled: {0}")]
    ReservationNotSettled(String),
    /// The production attachment authority is not wired in this environment.
    /// Fail closed (never a plausible-but-wrong resolution).
    #[error("image attachment authority unavailable")]
    AttachmentAuthorityUnavailable,
    /// The production provider transport is not wired in this environment.
    /// Fail closed (never an ad-hoc client).
    #[error("provider transport unavailable")]
    TransportUnavailable,
}

/// The successful result of an authorized invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarInvokeOutcome {
    /// A validated dossier (cached memory-only in [`DossierCache`]).
    Dossier(Box<ImageSidecarDossier>),
    /// A validated, sanitized ask-image answer (returned as an ordinary tool
    /// result; never cached as a dossier).
    AskImage(Box<AskImageAnswer>),
}

// ---------------------------------------------------------------------------
// Per-invocation context
// ---------------------------------------------------------------------------

/// The per-invocation context. Immutable identity for one authorized
/// invocation, pinned once at the operation's start.
#[derive(Debug, Clone)]
pub struct SidecarInvokeContext {
    /// The resolved sidecar selection (from [`super::SidecarResolver`]). Its
    /// destination policy digest binds grant equality.
    pub selected: SelectedSidecar,
    pub attachment_id: String,
    pub session_id: String,
    pub project: Option<ProjectIdentity>,
    pub approval_mode: ApprovalMode,
    pub scope: GrantScope,
    /// Whether the invoking principal currently holds session authorization
    /// for a project-scoped grant.
    pub session_authorized: bool,
    pub invocation_id: String,
    pub parent_operation: String,
    /// Host-known ordinal of this image within the originating request (0 for a
    /// single-image invocation). Used as host-authoritative dossier provenance.
    pub source_order: u32,
    /// The effective sidecar-invocation cap from the central media policy.
    pub reservation_cap: SidecarInvocationCap,
    pub provider_concurrency_max: u64,
    pub current_provider_concurrency: u64,
    pub current_session_usage: u64,
}

// ---------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------

/// The single authorized invocation pipeline shared by `dossier` and
/// `ask_image`. Holds the injected policy/reservation/transport seams; each
/// call to [`SidecarPipeline::invoke`] is parameterized by the [`PurposeBody`].
pub struct SidecarPipeline {
    grants: Arc<DestinationGrantStore>,
    cache: Arc<DossierCache>,
    clock: Arc<dyn DossierClock>,
    resolver: Arc<dyn SidecarAttachmentResolver>,
    acquirer: Arc<dyn ReservationAcquirer>,
    transport: Arc<dyn SidecarProviderTransport>,
}

impl SidecarPipeline {
    pub fn new(
        grants: Arc<DestinationGrantStore>,
        cache: Arc<DossierCache>,
        clock: Arc<dyn DossierClock>,
        resolver: Arc<dyn SidecarAttachmentResolver>,
        acquirer: Arc<dyn ReservationAcquirer>,
        transport: Arc<dyn SidecarProviderTransport>,
    ) -> Self {
        Self {
            grants,
            cache,
            clock,
            resolver,
            acquirer,
            transport,
        }
    }

    /// The one authorized invocation seam. Both `dossier` and `ask_image`
    /// enter here; the flow is identical except for the request body and the
    /// output validator, selected by `body.purpose`.
    pub async fn invoke(
        &self,
        body: &PurposeBody,
        ctx: &SidecarInvokeContext,
    ) -> Result<SidecarInvokeOutcome, SidecarInvokeError> {
        // 1. Resolve the session-authorized attachment (before any provider
        //    contact), assert the resolver returned the REQUESTED attachment,
        //    and enforce the existing typed-media rules.
        let resolved = self
            .resolver
            .resolve(&ctx.attachment_id, &ctx.session_id)
            .await?;
        Self::enforce_attachment_rules(&resolved, &ctx.session_id, &ctx.attachment_id)?;

        // 2. Recompute the destination-policy digest from the selection's ACTUAL
        //    identity (anti-forgery) and bind the current project into the
        //    authorization digest, so a `Session`-scope grant approved in one
        //    project cannot authorize another. Build the grant tuple from that
        //    authentic, project-bound digest — never the caller-carried one.
        let digest = Self::authorized_destination_digest(&ctx.selected, ctx.project.as_ref())?;
        let tuple =
            Self::destination_tuple(&ctx.selected, &digest, ctx.project.as_ref(), body.purpose);

        // 3. Egress authority — fail closed with ZERO provider contact.
        let (grant_id, grant_scope) = self.authorize_egress(ctx, &tuple)?;

        // 4. Acquire a FRESH, unique reservation id generated internally — never
        //    a caller-reusable id — so no invocation can ride a prior or
        //    already-terminalized reservation.
        let reservation_id = Self::fresh_reservation_id(&ctx.invocation_id, self.clock.now_ms());
        let _acquisition = self.acquire_reservation(ctx, &reservation_id).await?;

        // 5. Build the provider request and run the mandatory request-boundary
        //    check (`CapturedProviderRequest::verify`) BEFORE consuming any
        //    grant, so a malformed request cannot burn a `Once` grant with no
        //    handoff. A failure here is definitely-not-sent → settle (release).
        let request = match self.build_provider_request(
            body,
            ctx,
            &resolved,
            &digest,
            &body.body,
            body.instruction_version,
        ) {
            Ok(req) => req,
            Err(err) => return Err(self.settle_after_error(&reservation_id, err).await),
        };

        // 6. Consume a `Once` grant now that the request is legitimate and about
        //    to dispatch (still before dispatch). A second invocation — and the
        //    repair, which independently re-authorizes — cannot ride it.
        if let Err(err) = self.consume_once_if_needed(grant_scope, &grant_id) {
            return Err(self.settle_after_error(&reservation_id, err).await);
        }

        // 7. Dispatch. Any transport error settles (releases) the reservation so
        //    no queued row leaks. (The ambiguous-handoff keep-charge accounting
        //    is deferred to the real transport — see the `settle` contract.)
        let response = match self.transport.dispatch(&request).await {
            Ok(resp) => resp,
            Err(err) => return Err(self.settle_after_error(&reservation_id, err).await),
        };

        // 8. Validate; on invalid, at most one repair inference with independent
        //    re-authorization and re-reservation. Settle the reservation
        //    terminally on every path (no leaked row); fail closed if settlement
        //    itself fails rather than report a clean success over a leaked row.
        let outcome = match self.validate_output(body, ctx, &resolved, &response) {
            Ok(outcome) => Ok(outcome),
            Err(_first_invalid) => self.try_repair(body, ctx, &resolved, &digest).await,
        };
        self.settle_on_success(&reservation_id).await?;
        outcome
    }

    /// Enforce the existing typed-media rules on the resolved attachment. A
    /// transient computer frame is never addressable here; a wrong-session or
    /// otherwise-invalid attachment is rejected before any provider contact.
    /// The resolver must return the REQUESTED attachment — it may not substitute
    /// another current-session image.
    fn enforce_attachment_rules(
        resolved: &ResolvedImageAttachment,
        session_id: &str,
        requested_attachment_id: &str,
    ) -> Result<(), SidecarInvokeError> {
        if resolved.durable.attachment_id != requested_attachment_id {
            return Err(SidecarInvokeError::ResolvedAttachmentMismatch);
        }
        match AskImageService::validate_attachment(&resolved.durable, session_id, resolved.kind) {
            Ok(()) => Ok(()),
            Err(AskImageError::TransientNotAllowed) => Err(SidecarInvokeError::TransientNotAllowed),
            Err(other) => Err(SidecarInvokeError::AttachmentRejected(other)),
        }
    }

    /// Generate a fresh, process-unique reservation id from the caller's logical
    /// id plus a monotonic sequence (+ a wall-clock tag). Never returns a
    /// caller-reusable id, so a reused `invocation_id` still yields a distinct
    /// reservation each acquisition.
    fn fresh_reservation_id(base: &str, now_ms: u64) -> String {
        let seq = NEXT_RESERVATION_SEQ.fetch_add(1, Ordering::Relaxed);
        format!("{base}#sidecar-res-{now_ms}-{seq}")
    }

    /// Rebuild the exact `DestinationPolicy` a legitimate selection was hashed
    /// from, substituting `project_identity`. With `ProjectIdentity::default()`
    /// this reproduces `SidecarResolver::build_selected_sidecar`'s carried
    /// digest (anti-forgery baseline); with the real project it produces the
    /// project-bound authorization digest.
    fn destination_policy_for(
        selected: &SelectedSidecar,
        project_identity: ProjectIdentity,
    ) -> DestinationPolicy {
        DestinationPolicy {
            provider: selected.provider.clone(),
            model: selected.model.clone(),
            endpoint_origin: selected.endpoint_origin.clone(),
            connected_location: selected.location,
            credential_fingerprint: selected.credential_fingerprint.clone(),
            project_identity,
            image_capability_value: selected.capability_evidence.status,
            capability_contract_revision: CAPABILITY_CONTRACT_REVISION,
            egress_fields: EgressFields::default(),
        }
    }

    /// Return the authentic, project-bound destination digest used for grant
    /// equality, or reject a forged selection.
    ///
    /// 1. Anti-forgery: recompute the digest with the machine-local DEFAULT
    ///    project (exactly what `build_selected_sidecar` hashes) and reject a
    ///    selection whose carried digest is not authentic — a mismatched
    ///    provider/model can never authorize egress.
    /// 2. Project binding: return the digest recomputed with the ACTUAL project,
    ///    so a `Session`-scope grant approved in project A does not authorize
    ///    project B (the landed grant `check` only compares session id for
    ///    `Session` scope, so the project must be folded into the digest).
    fn authorized_destination_digest(
        selected: &SelectedSidecar,
        project: Option<&ProjectIdentity>,
    ) -> Result<DestinationPolicyDigest, SidecarInvokeError> {
        let base = Self::destination_policy_for(selected, ProjectIdentity::default()).digest();
        if base != selected.destination_policy_digest {
            return Err(SidecarInvokeError::DestinationBindingMismatch);
        }
        let auth =
            Self::destination_policy_for(selected, project.cloned().unwrap_or_default()).digest();
        Ok(auth)
    }

    fn destination_tuple(
        selected: &SelectedSidecar,
        digest: &DestinationPolicyDigest,
        project: Option<&ProjectIdentity>,
        purpose: Purpose,
    ) -> DestinationTuple {
        DestinationTuple {
            provider: selected.provider.clone(),
            model: selected.model.clone(),
            endpoint_origin: selected.endpoint_origin.clone(),
            connected_location: selected.location,
            credential_fingerprint: selected.credential_fingerprint.clone(),
            project_identity: project.cloned().unwrap_or_default(),
            // The AUTHENTIC recomputed digest, not the carried one.
            destination_policy_digest: digest.clone(),
            media_class: MediaClass::Image,
            purpose,
        }
    }

    /// Run the mandatory egress chokepoint. Returns the authorized
    /// `(grant_id, scope)` only when the invocation may proceed to reservation +
    /// dispatch; every other outcome is a typed error and guarantees zero
    /// provider contact.
    fn authorize_egress(
        &self,
        ctx: &SidecarInvokeContext,
        tuple: &DestinationTuple,
    ) -> Result<(String, GrantScope), SidecarInvokeError> {
        let outcome = self.grants.check(
            tuple,
            ctx.scope,
            Some(ctx.session_id.as_str()),
            ctx.project.as_ref(),
        );
        let decision = evaluate_egress_authority(
            ctx.approval_mode,
            &outcome,
            ctx.session_authorized,
            &ctx.invocation_id,
        );
        match decision {
            // Proceeding under either mode required a concrete `Authorized`
            // grant (Yolo's discretion still checked the grant); surface its id
            // and scope so a `Once` grant can be consumed at handoff.
            EgressDecision::AskGranted { grant_id, scope } => Ok((grant_id, scope)),
            EgressDecision::YoloAgentDiscretion { .. } => match outcome {
                GrantAuthorizationOutcome::Authorized { grant_id, scope } => Ok((grant_id, scope)),
                // Defensive: evaluate_egress_authority only yields discretion
                // from an Authorized outcome. Any other pairing fails closed.
                _ => Err(SidecarInvokeError::EgressDenied(
                    HardGateFailureReason::DestinationDenied,
                )),
            },
            EgressDecision::AskDenied => Err(SidecarInvokeError::EgressNotAuthorized),
            EgressDecision::HardGateFailed { reason } => {
                Err(SidecarInvokeError::EgressDenied(reason))
            }
        }
    }

    /// Atomically consume a `Once`-scoped grant at handoff. Session/project
    /// grants are not consumed (each use re-checks). A consumed/revoked grant
    /// fails closed so the next invocation must re-authorize.
    fn consume_once_if_needed(
        &self,
        scope: GrantScope,
        grant_id: &str,
    ) -> Result<(), SidecarInvokeError> {
        if scope == GrantScope::Once {
            self.grants.consume_once(grant_id).map_err(|_| {
                SidecarInvokeError::EgressDenied(HardGateFailureReason::DestinationDenied)
            })?;
        }
        Ok(())
    }

    /// Terminally settle (release) the reservation after a dispatch-path error
    /// and return the error to propagate. Returns `original` when settlement
    /// succeeds; if settlement itself fails, returns `ReservationNotSettled`
    /// (fail closed) rather than silently leaving a leaked row.
    async fn settle_after_error(
        &self,
        reservation_id: &str,
        original: SidecarInvokeError,
    ) -> SidecarInvokeError {
        match self.acquirer.settle(reservation_id).await {
            Ok(()) => original,
            Err(e) => SidecarInvokeError::ReservationNotSettled(e.message),
        }
    }

    /// Terminally settle the reservation on success. Fail closed if settlement
    /// fails — never report a clean success over a possibly-leaked row.
    async fn settle_on_success(&self, reservation_id: &str) -> Result<(), SidecarInvokeError> {
        self.acquirer
            .settle(reservation_id)
            .await
            .map_err(|e| SidecarInvokeError::ReservationNotSettled(e.message))
    }

    async fn acquire_reservation(
        &self,
        ctx: &SidecarInvokeContext,
        reservation_id: &str,
    ) -> Result<ReservationAcquisition, SidecarInvokeError> {
        let request = ReservationRequest {
            invocation_id: reservation_id.to_string(),
            session_id: ctx.session_id.clone(),
            sidecar_invocation_cap: ctx.reservation_cap,
            current_session_usage: ctx.current_session_usage,
            provider_concurrency_max: ctx.provider_concurrency_max,
            current_provider_concurrency: ctx.current_provider_concurrency,
        };
        match self.acquirer.acquire(request).await {
            acq @ ReservationAcquisition::Committed { .. } => Ok(acq),
            ReservationAcquisition::RolledBack { reason } => {
                Err(SidecarInvokeError::ReservationFailed(reason))
            }
        }
    }

    /// Build the captured provider request and run the mandatory
    /// one-image/one-body boundary check ([`CapturedProviderRequest::verify`]),
    /// returning the request only if it is legitimate. An empty resolved
    /// artifact id is treated as a missing image so `verify` fails closed.
    /// Dispatch is performed by the caller AFTER a `Once` grant is consumed.
    fn build_provider_request(
        &self,
        body: &PurposeBody,
        ctx: &SidecarInvokeContext,
        resolved: &ResolvedImageAttachment,
        digest: &DestinationPolicyDigest,
        instruction_body: &str,
        instruction_version: u8,
    ) -> Result<SidecarProviderRequest, SidecarInvokeError> {
        let image_artifact_id = if resolved.image_artifact_id.is_empty() {
            None
        } else {
            Some(resolved.image_artifact_id.clone())
        };
        let captured = CapturedProviderRequest {
            purpose: body.purpose,
            instruction_version,
            body: instruction_body.to_string(),
            image_count: 1,
            permitted_context: PermittedContext {
                image_artifact_id: image_artifact_id.clone(),
            },
        };
        captured
            .verify()
            .map_err(SidecarInvokeError::RequestBoundary)?;

        Ok(SidecarProviderRequest {
            provider: ctx.selected.provider.clone(),
            model: ctx.selected.model.clone(),
            purpose: body.purpose,
            instruction_version,
            body: instruction_body.to_string(),
            // `verify` guaranteed this is present.
            image_artifact_id: image_artifact_id.unwrap_or_default(),
            // The authentic (recomputed + verified) digest.
            destination_policy_digest_hex: digest.hex(),
        })
    }

    /// Validate the provider output for the purpose. Dossier bodies are cached
    /// memory-only; ask-image answers are returned without dossier caching.
    fn validate_output(
        &self,
        body: &PurposeBody,
        ctx: &SidecarInvokeContext,
        resolved: &ResolvedImageAttachment,
        response: &SidecarProviderResponse,
    ) -> Result<SidecarInvokeOutcome, SidecarInvokeError> {
        match body.purpose {
            Purpose::Dossier => {
                let value: serde_json::Value = serde_json::from_str(&response.output_text)
                    .map_err(|_| SidecarInvokeError::InvalidOutput)?;
                let mut dossier = DossierValidator::validate_value(&value)
                    .map_err(|_| SidecarInvokeError::InvalidOutput)?;
                // Overwrite EVERY provider-supplied provenance/metadata field
                // with host-authoritative values. Provenance is exported as
                // "safe metadata" (`DossierCache::export_metadata`), so nothing
                // provider-controlled may escape through it. The dossier BODY
                // (summary/OCR/facts/…) stays as untrusted provider evidence.
                let p = &mut dossier.provenance;
                p.sidecar_provider = ctx.selected.provider.clone();
                p.sidecar_model = ctx.selected.model.clone();
                p.attachment_checksum_hex = resolved.durable.checksum_hex.clone();
                p.config_generation = ctx.selected.config_generation;
                p.created_at_ms = self.clock.now_ms();
                p.source_width_px = resolved.source_width_px;
                p.source_height_px = resolved.source_height_px;
                p.source_order = ctx.source_order;
                p.schema_version = DOSSIER_SCHEMA_VERSION;
                self.cache_dossier(ctx, resolved, &dossier);
                Ok(SidecarInvokeOutcome::Dossier(Box::new(dossier)))
            }
            Purpose::AskImage => {
                let mut answer: AskImageAnswer = serde_json::from_str(&response.output_text)
                    .map_err(|_| SidecarInvokeError::InvalidOutput)?;
                answer
                    .validate()
                    .map_err(|_| SidecarInvokeError::InvalidOutput)?;
                // Overwrite provider-claimed provenance IDENTITY with
                // host-authoritative values (the provider must not be able to
                // misattribute which model/checksum served the answer). The
                // answer / uncertainty / status_note remain provider evidence
                // and are already bound by `AskImageAnswer::validate`'s bounds.
                answer.provenance.sidecar_provider = ctx.selected.provider.clone();
                answer.provenance.sidecar_model = ctx.selected.model.clone();
                answer.provenance.attachment_checksum_hex = resolved.durable.checksum_hex.clone();
                answer.provenance.created_at_ms = self.clock.now_ms();
                // The sanitized answer is an ordinary tool result and is NOT
                // added to the dossier cache.
                Ok(SidecarInvokeOutcome::AskImage(Box::new(answer)))
            }
        }
    }

    /// The single permitted repair inference. It independently re-authorizes
    /// egress and re-acquires a reservation, then re-dispatches the SAME one
    /// image plus the SAME versioned purpose body and validates. A second
    /// invalid response is `invalid_output`. If any gate now fails, the repair
    /// does not run.
    ///
    /// The repair re-sends the original purpose body (the fixed dossier
    /// instruction or the caller's validated question) rather than a distinct
    /// repair instruction: the request boundary
    /// ([`CapturedProviderRequest::verify`]) admits only the canonical
    /// instruction for the purpose's `instruction_version`, so re-sending the
    /// original body is the only body a legitimate repair can carry without
    /// weakening that security check. [`RepairController`] enforces the
    /// at-most-one-repair cap.
    async fn try_repair(
        &self,
        body: &PurposeBody,
        ctx: &SidecarInvokeContext,
        resolved: &ResolvedImageAttachment,
        digest: &DestinationPolicyDigest,
    ) -> Result<SidecarInvokeOutcome, SidecarInvokeError> {
        let controller = RepairController::new();

        // Independent re-authorization against the authentic, project-bound
        // digest (fail closed if egress now denies — e.g. a `Once` grant the
        // first invocation already consumed).
        let tuple =
            Self::destination_tuple(&ctx.selected, digest, ctx.project.as_ref(), body.purpose);
        let (grant_id, grant_scope) = self.authorize_egress(ctx, &tuple)?;

        // Independent re-reservation under a FRESH, unique reservation id.
        let reservation_id = Self::fresh_reservation_id(&ctx.invocation_id, self.clock.now_ms());
        let _acq = self.acquire_reservation(ctx, &reservation_id).await?;

        // Build + verify the repair request BEFORE consuming a grant (a
        // malformed request cannot burn a `Once` grant with no handoff).
        let request = match self.build_provider_request(
            body,
            ctx,
            resolved,
            digest,
            &body.body,
            body.instruction_version,
        ) {
            Ok(req) => req,
            Err(err) => return Err(self.settle_after_error(&reservation_id, err).await),
        };

        // The repair is its own authorization: consume a `Once` grant here too.
        if let Err(err) = self.consume_once_if_needed(grant_scope, &grant_id) {
            return Err(self.settle_after_error(&reservation_id, err).await);
        }

        // Consume the one repair attempt now that gates passed. The repair
        // re-sends the original purpose body (the request boundary only admits
        // the canonical instruction for the purpose).
        let _repair = controller
            .try_repair(true)
            .map_err(|_| SidecarInvokeError::InvalidOutput)?;

        let outcome = match self.transport.dispatch(&request).await {
            Ok(response) => self.validate_output(body, ctx, resolved, &response),
            Err(err) => return Err(self.settle_after_error(&reservation_id, err).await),
        };
        // Settle the repair reservation terminally (no leaked row); fail closed
        // if settlement fails.
        self.settle_on_success(&reservation_id).await?;
        outcome
    }

    fn cache_dossier(
        &self,
        ctx: &SidecarInvokeContext,
        resolved: &ResolvedImageAttachment,
        dossier: &ImageSidecarDossier,
    ) {
        let key = DossierCacheKey {
            session_id: ctx.session_id.clone(),
            attachment_id: ctx.attachment_id.clone(),
            attachment_checksum_hex: resolved.durable.checksum_hex.clone(),
            schema_version: dossier.schema_version,
            sidecar_provider: ctx.selected.provider.clone(),
            sidecar_model: ctx.selected.model.clone(),
            config_generation: ctx.selected.config_generation,
            crop_identity: None,
            purpose: Purpose::Dossier,
        };
        // Memory-only. The pipeline does NOT start the session: session
        // lifecycle is host-owned (started at session begin, ended at session
        // end). `insert` is a no-op for an inactive session, so a session that
        // ended during inference is not resurrected or re-cached here.
        let _ = self.cache.insert(key, dossier.clone(), self.clock.as_ref());
    }
}

// ---------------------------------------------------------------------------
// Production reservation acquirer (real media-reservation ledger)
// ---------------------------------------------------------------------------

/// The production [`ReservationAcquirer`], backed by the real
/// [`MediaReservationLedger`] — the same tables/APIs image-generation jobs and
/// attachment uploads use. It creates a durable `media_reservations` row for
/// the `sidecar_invocations_per_session` dimension; the fake acquirer is never
/// used in production composition.
///
/// The sidecar-invocation dimension is charged at external handoff and never
/// released, so `acquire` records the durable reservation (a real ledger row +
/// deferred estimate); the charge-at-handoff/settle lifecycle beyond this
/// reservation is owned by the external-journal handoff path.
pub struct LedgerReservationAcquirer {
    ledger: crate::media_reservation::MediaReservationLedger,
    policy: crate::config::config::media_budget::MediaResourcePolicy,
    project_id: String,
}

impl LedgerReservationAcquirer {
    pub fn new(
        ledger: crate::media_reservation::MediaReservationLedger,
        policy: crate::config::config::media_budget::MediaResourcePolicy,
        project_id: String,
    ) -> Self {
        Self {
            ledger,
            policy,
            project_id,
        }
    }

    fn build_plans(
        &self,
    ) -> Result<Vec<crate::config::config::media_budget::MediaReservationPlan>, ()> {
        use crate::config::config::media_budget::{MediaDimension, MediaEvaluationRequest};
        let deadline = self
            .policy
            .limits()
            .get(MediaDimension::OperationDeadlineSeconds);
        [
            (MediaDimension::SidecarInvocationsPerSession, 1u64),
            (MediaDimension::OperationDeadlineSeconds, deadline),
        ]
        .into_iter()
        .map(|(dimension, requested)| {
            self.policy
                .evaluate(MediaEvaluationRequest {
                    dimension,
                    requested: Some(requested),
                    current_scope: 0,
                    profile: None,
                    adapter_limit: None,
                    request_limit: None,
                })
                .map_err(|_| ())
        })
        .collect()
    }
}

#[async_trait]
impl ReservationAcquirer for LedgerReservationAcquirer {
    async fn acquire(&self, request: ReservationRequest) -> ReservationAcquisition {
        use crate::media_reservation::{LedgerError, MediaOwner, ReserveRequest};

        let plans = match self.build_plans() {
            Ok(plans) => plans,
            Err(()) => {
                return ReservationAcquisition::RolledBack {
                    reason: ReservationFailureReason::MediaReservationDenied,
                };
            }
        };
        let reserve = ReserveRequest {
            reservation_id: request.invocation_id.clone(),
            recovery_id: request.invocation_id.clone(),
            owner: MediaOwner {
                project_id: self.project_id.clone(),
                session_id: request.session_id.clone(),
            },
            operation: "image_sidecar".to_string(),
            purpose: "image_sidecar".to_string(),
            plans,
            wall_ms: self.ledger.clock_now_ms(),
        };
        match self.ledger.reserve(reserve).await {
            Ok(receipt) => ReservationAcquisition::Committed {
                invocation_id: request.invocation_id,
                // The sidecar dimension is charged at external handoff, not at
                // reserve; this durable row is the accounting artifact.
                sidecar_invocation_charged: false,
                media_reservation_id: receipt.reservation_id,
                provider_concurrency_slot: format!("queue-{}", receipt.queue_sequence),
            },
            Err(LedgerError::Denied(_)) => ReservationAcquisition::RolledBack {
                reason: ReservationFailureReason::MediaReservationDenied,
            },
            Err(_other) => ReservationAcquisition::RolledBack {
                reason: ReservationFailureReason::MediaReservationDenied,
            },
        }
    }

    /// Terminally settle the reservation on ANY terminal outcome (success or
    /// failure): the queued reservation is released via the ledger's
    /// cancellation path so no `reserved_queued` row leaks. Returns `Err` if the
    /// ledger could not terminalize the row, so the caller fails closed instead
    /// of reporting success over a leaked row. The freshly-reserved row is at
    /// version 1.
    ///
    /// TODO(image-sidecar-integration): the real `SidecarProviderTransport`
    /// (`Model::complete_captured`) follow-up must replace this with the true
    /// `AtHandoff` lifecycle: on a SUCCESSFUL handoff, settle WITH the
    /// `sidecar_invocations_per_session` charge retained (drive
    /// `handoff_external` + `settle_verified`) so the per-session cap AND
    /// provider-concurrency are enforced, and keep the charge on an ambiguous
    /// handoff (provider may have received the image). The stubbed transport
    /// performs no real external egress today, so there is no charge to retain
    /// and every terminal outcome simply releases the queued reservation.
    async fn settle(&self, reservation_id: &str) -> Result<(), ReservationSettleError> {
        match self
            .ledger
            .request_cancellation(reservation_id, 1, self.ledger.clock_now_ms())
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => {
                // Surface, do not swallow: a failed terminalization could
                // otherwise silently leak a queued row.
                tracing::warn!(
                    reservation_id = %reservation_id,
                    error = %error,
                    "sidecar reservation settlement failed"
                );
                Err(ReservationSettleError::new(error.to_string()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fail-closed production stubs for the environment-blocked live edges
// ---------------------------------------------------------------------------

/// Fail-closed production attachment resolver. The typed-media session
/// attachment authority is not yet reachable from `ToolCtx` in this tree
/// (exactly as `read_image` is blocked). This resolver refuses every request
/// rather than returning a plausible-but-wrong resolution.
//
// TODO(image-sidecar-integration): replace with a resolver over the typed
// session attachment authority once it is reachable from the tool/engine
// context (same dependency that unblocks `read_image`'s live path).
pub struct UnavailableAttachmentResolver;

#[async_trait]
impl SidecarAttachmentResolver for UnavailableAttachmentResolver {
    async fn resolve(
        &self,
        _attachment_id: &str,
        _session_id: &str,
    ) -> Result<ResolvedImageAttachment, SidecarInvokeError> {
        Err(SidecarInvokeError::AttachmentAuthorityUnavailable)
    }
}

/// Fail-closed production transport. The engine inference chokepoint
/// (`engine::model::Model::complete_captured`) is the intended production
/// transport, but wiring a one-image sidecar request through it requires the
/// resolved image bytes + credentials that the (blocked) attachment authority
/// supplies. This stub refuses to dispatch rather than inventing an ad-hoc
/// client.
//
// TODO(image-sidecar-integration): implement over `Model::for_provider(..)` +
// `Model::complete_captured(..)`, building a `Message::User` with exactly one
// `UserContent::image_base64` part plus one text part, once image bytes are
// resolvable. Must remain the ONLY provider path (never an ad-hoc HTTP client).
pub struct UnavailableProviderTransport;

#[async_trait]
impl SidecarProviderTransport for UnavailableProviderTransport {
    async fn dispatch(
        &self,
        _request: &SidecarProviderRequest,
    ) -> Result<SidecarProviderResponse, SidecarInvokeError> {
        Err(SidecarInvokeError::TransportUnavailable)
    }
}

#[cfg(test)]
mod tests;
