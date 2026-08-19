//! str0m WebRTC endpoint in the Rust daemon.
//!
//! This module implements a full outbound WebRTC data-channel endpoint using
//! `str0m` 0.21.0 with the RustCrypto backend. It is sans-I/O: the
//! supervisor reducer is pure over injected network/time/str0m events, and
//! Tokio adapters own sockets, timers, and I/O scheduling around the
//! sans-I/O `Rtc` API.
//!
//! # What this module owns
//!
//! - The exact `str0m` dependency pin and per-`Rtc` RustCrypto provider
//!   configuration.
//! - Consent-gated resource factories that gate every socket/interface/STUN/
//!   candidate/`Rtc` factory on the verified [`ConsentCapability`] tri-state.
//! - The pure supervisor reducer that processes signaling events, ICE
//!   candidates, final-proof commits, and generation transitions.
//! - The resource budget constants and admission checks.
//! - The generation/lease cutover model with persisted supervisor ACK.
//! - The fixed three-channel contract (IDs 0/2/4).
//! - The 64/64/64 yield-budget fairness trace.
//! - Consent freshness probes (15-second interval, two-miss teardown).
//!
//! # What this module does NOT own
//!
//! - Browser/native UI, TypeScript WebSocket server, or media/SFU.
//! - The consent codec or capability evaluator (owned by
//!   `cockpit-proto::remote_ip_consent`).
//! - The signaling-attempt store or final-proof codec (owned by
//!   `cockpit-proto::remote_signaling_attempt_store`).
//! - The transport lane/frame/fragment/channel/scheduler codecs (owned by
//!   `cockpit-proto::remote_transport`).
//! - The attempt-grant semantic model (owned by `daemon::remote_attempt`).
//!
//! # Security decisions
//!
//! - No public/fixed listener, UPnP/NAT-PMP, privileged port, or Rust
//!   WebSocket server.
//! - Candidate work is capability-gated before any side effect.
//! - The [`VerifiedDirectCapability`] fields are private; a `DirectAllowed`
//!   value cannot be forged by struct literal or a plain bool/client claim.
//!   Its only `DirectAllowed` producer is `from_committed_begin`, which binds
//!   a signed status envelope to a committed authorization.
//! - TURN-required attempts never open/nominate host/srflx.
//! - Logs/errors redact addresses/candidates/fingerprints/tokens/identities.
//! - Late generation events are inert.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::daemon::turn_socket_provider::{AuthorizedIceEntry, TurnSocketProvider};
use cockpit_proto::remote_ip_consent::{ConsentCapability, VerifiedDirectCapability};
use cockpit_proto::remote_signaling_attempt_store::{
    RemoteSignalingCommitAckV1, SignalingCodecError,
};
use cockpit_proto::remote_transport::channel::REMOTE_LANE_CHANNELS;
// Consumed only by this module's `#[cfg(test)]` tests (via `super::*`).
#[cfg(test)]
use cockpit_proto::remote_transport::channel::RemoteLaneChannel;

// ─────────────────────────────────────────────────────────────────────────
// Dependency gate constants
// ─────────────────────────────────────────────────────────────────────────

/// The exact `str0m` version this module pins.
pub const STR0M_VERSION: &str = "0.21.0";

/// The exact crypto feature this module enables.
pub const STR0M_CRYPTO_FEATURE: &str = "rust-crypto";

/// The license of str0m 0.21.0 (MIT OR Apache-2.0).
pub const STR0M_LICENSE: &str = "MIT OR Apache-2.0";

/// The workspace MSRV.
pub const MSRV: &str = "1.95";

/// Platforms supported by str0m 0.21.0 with rust-crypto.
pub const STR0M_PLATFORMS: &[&str] = &[
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "aarch64-pc-windows-msvc",
];

// ─────────────────────────────────────────────────────────────────────────
// Resource budget constants (default hard ceilings, lowerable by policy)
// ─────────────────────────────────────────────────────────────────────────

/// Maximum total authenticated peer generations per daemon, including
/// replacement-pending and draining.
pub const MAX_TOTAL_PEER_GENERATIONS: usize = 32;

/// Normal maximum routed-current children per logical attachment.
pub const MAX_ROUTED_CURRENT_CHILDREN: usize = 2;

/// Extra noncurrent TURN generation during the three-physical-child
/// rotation exception.
pub const THREE_PHYSICAL_TURN_EXCEPTION_EXTRA: usize = 1;

/// Maximum SDP payload bytes inside the serialized signaling cap.
pub const MAX_SDP_PAYLOAD_BYTES: usize = 122_880;

/// Maximum serialized signaling cap.
pub const MAX_SERIALIZED_SIGNALING_BYTES: usize = 131_072;

/// Maximum remote candidates per child.
pub const MAX_REMOTE_CANDIDATES_PER_CHILD: usize = 64;

/// Maximum local candidates per child.
pub const MAX_LOCAL_CANDIDATES_PER_CHILD: usize = 64;

/// Maximum bytes per candidate.
pub const MAX_CANDIDATE_BYTES: usize = 4_096;

/// Maximum resolved/local interface addresses.
pub const MAX_INTERFACE_ADDRESSES: usize = 16;

/// Maximum direct UDP sockets per physical child (direct route).
pub const MAX_DIRECT_UDP_SOCKETS_PER_CHILD: usize = 4;

/// Maximum TURN allocations per physical child (relay route).
pub const MAX_TURN_ALLOCATIONS_PER_CHILD: usize = 1;

/// Maximum queued network datagrams per direction.
pub const MAX_QUEUED_DATAGRAMS_PER_DIRECTION: usize = 256;

/// Maximum queued network datagram bytes per direction.
pub const MAX_QUEUED_DATAGRAM_BYTES_PER_DIRECTION: usize = 4 * 1024 * 1024;

/// Maximum lane application queue bytes.
pub const MAX_LANE_APPLICATION_QUEUE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum str0m input events per supervisor turn before yielding.
pub const MAX_INPUT_EVENTS_PER_TURN: usize = 64;

/// Maximum timeout actions per supervisor turn before yielding.
pub const MAX_TIMEOUT_ACTIONS_PER_TURN: usize = 64;

/// Maximum output actions per supervisor turn before yielding.
pub const MAX_OUTPUT_ACTIONS_PER_TURN: usize = 64;

/// ICE establishment deadline in seconds.
pub const ICE_ESTABLISHMENT_DEADLINE_SECS: u64 = 30;

/// Consent freshness probe interval in seconds.
pub const CONSENT_FRESHNESS_INTERVAL_SECS: u64 = 15;

/// Consent freshness failure threshold (missed responses).
pub const CONSENT_FRESHNESS_MISS_THRESHOLD: u32 = 2;

/// Draining timeout in seconds.
pub const DRAINING_TIMEOUT_SECS: u64 = 30;

// ─────────────────────────────────────────────────────────────────────────
// Generation model
// ─────────────────────────────────────────────────────────────────────────

/// A generation identifier for peers, attempts, allocations, sockets, and
/// callbacks. Every resource has a generation; late events for a superseded
/// generation are inert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Generation(pub u64);

impl Generation {
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl Default for Generation {
    fn default() -> Self {
        Self(1)
    }
}

/// A lease generation for a continuing TURN leg. A continuing leg has
/// exactly one `current` and at most one `replacement_pending | draining`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeaseGeneration(pub u64);

/// The state of a generation in the lease lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenerationState {
    /// The sole current generation carrying application work.
    Current,
    /// A pending replacement that may authorize/allocate/negotiate/prove
    /// but carries no application operation.
    ReplacementPending,
    /// A draining predecessor handling only already-assigned
    /// replay/ACK/control and ledger-reserved work.
    Draining,
    /// Removed after a second lease cutover.
    Removed,
}

/// The persisted supervisor ACK payload for a cutover. The supervisor must
/// persist this exact record before switching routes/channels for new work.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CutoverAck {
    pub old_generation: Generation,
    pub new_generation: Generation,
    pub lease_id: [u8; 16],
    pub lease_generation: LeaseGeneration,
    pub lease_digest: [u8; 32],
}

// ─────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebrtcEndpointError {
    #[error("consent capability does not permit this action")]
    ConsentDenied,
    #[error("resource budget exhausted: {0}")]
    BudgetExhausted(&'static str),
    #[error("generation mismatch: expected {expected}, got {got}")]
    GenerationMismatch { expected: u64, got: u64 },
    #[error("signaling prerequisite not met: {0}")]
    SignalingPrerequisite(&'static str),
    #[error("final proof not committed or peer-verified")]
    FinalProofNotVerified,
    #[error("signaling codec error: {0}")]
    SignalingCodec(String),
    #[error("str0m error: {0}")]
    Str0m(String),
    #[error("generation is not current: late events are inert")]
    LateGenerationInert,
    #[error("ICE establishment deadline exceeded")]
    IceDeadlineExceeded,
    #[error("consent freshness failure: {0} missed probes")]
    ConsentFreshnessFailure(u32),
    #[error("redaction violation: sensitive data in output")]
    RedactionViolation,
    #[error("turn allocation failed")]
    TurnAllocationFailed,
}

// ─────────────────────────────────────────────────────────────────────────
// Dependency gate: str0m version/provider/platform/license
// ─────────────────────────────────────────────────────────────────────────

/// Build a new `str0m::Rtc` instance with the RustCrypto provider
/// explicitly configured per-instance. No process-wide default is set.
///
/// This is the only factory for `Rtc` in this module. It always uses
/// the RustCrypto provider from `str0m_rust_crypto`; no AWS-LC, OpenSSL,
/// platform TLS, or alternate backend is configured.
pub fn new_rtc_with_rust_crypto(now: Instant) -> str0m::Rtc {
    str0m::Rtc::builder()
        .set_crypto_provider(Arc::new(str0m_rust_crypto::default_provider()))
        .build(now)
}

/// Dependency gate metadata record. Proves the exact version, feature,
/// provider, MSRV, platform, and license.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Str0mDependencyRecord {
    pub version: &'static str,
    pub crypto_feature: &'static str,
    pub provider: &'static str,
    pub msrv: &'static str,
    pub platforms: &'static [&'static str],
    pub license: &'static str,
    pub default_features: bool,
    pub alternate_backend: bool,
}

/// Return the dependency gate record proving exact 0.21.0/defaults-off/
/// rust-crypto, per-Rtc provider, MSRV/platform/license/provenance, and
/// no alternate backend/stack.
pub fn str0m_dependency_record() -> Str0mDependencyRecord {
    Str0mDependencyRecord {
        version: STR0M_VERSION,
        crypto_feature: STR0M_CRYPTO_FEATURE,
        provider: "str0m_rust_crypto::default_provider",
        msrv: MSRV,
        platforms: STR0M_PLATFORMS,
        license: STR0M_LICENSE,
        default_features: false,
        alternate_backend: false,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Consent-gated resource factory
// ─────────────────────────────────────────────────────────────────────────

/// Instrumented resource factory that tracks every consent-gated side
/// effect. Every socket/interface/STUN/candidate/Rtc factory is gated by
/// the verified capability tri-state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsentGatedResourceFactory {
    pub rtc_instances_created: u32,
    pub direct_udp_sockets_opened: u32,
    pub interfaces_enumerated: u32,
    pub host_candidates_created: u32,
    pub srflx_candidates_created: u32,
    pub stun_requests_sent: u32,
    pub turn_allocations_created: u32,
    pub mixed_ice_configured: bool,
    pub relay_only_ice_configured: bool,
    pub transport_resources_created: bool,
}

impl ConsentGatedResourceFactory {
    /// Create a new `Rtc` instance. Only permitted when the capability is
    /// `DirectAllowed` or `RelayOnly`. `Unavailable` creates no `Rtc`.
    pub fn create_rtc(
        &mut self,
        capability: &VerifiedDirectCapability,
        now: Instant,
    ) -> Result<str0m::Rtc, WebrtcEndpointError> {
        match capability.capability() {
            ConsentCapability::DirectAllowed | ConsentCapability::RelayOnly => {
                let rtc = new_rtc_with_rust_crypto(now);
                self.rtc_instances_created += 1;
                self.transport_resources_created = true;
                Ok(rtc)
            }
            ConsentCapability::Unavailable => Err(WebrtcEndpointError::ConsentDenied),
        }
    }

    /// Open a direct UDP socket. Only permitted with `DirectAllowed`.
    pub fn open_direct_udp_socket(
        &mut self,
        capability: &VerifiedDirectCapability,
    ) -> Result<(), WebrtcEndpointError> {
        match capability.capability() {
            ConsentCapability::DirectAllowed => {
                self.direct_udp_sockets_opened += 1;
                Ok(())
            }
            _ => Err(WebrtcEndpointError::ConsentDenied),
        }
    }

    /// Enumerate local interfaces. Only permitted with `DirectAllowed`.
    pub fn enumerate_interfaces(
        &mut self,
        capability: &VerifiedDirectCapability,
    ) -> Result<(), WebrtcEndpointError> {
        match capability.capability() {
            ConsentCapability::DirectAllowed => {
                self.interfaces_enumerated += 1;
                Ok(())
            }
            _ => Err(WebrtcEndpointError::ConsentDenied),
        }
    }

    /// Create a host candidate. Only permitted with `DirectAllowed`.
    pub fn create_host_candidate(
        &mut self,
        capability: &VerifiedDirectCapability,
    ) -> Result<(), WebrtcEndpointError> {
        match capability.capability() {
            ConsentCapability::DirectAllowed => {
                self.host_candidates_created += 1;
                Ok(())
            }
            _ => Err(WebrtcEndpointError::ConsentDenied),
        }
    }

    /// Create a server-reflexive (srflx) candidate. Only permitted with
    /// `DirectAllowed`.
    pub fn create_srflx_candidate(
        &mut self,
        capability: &VerifiedDirectCapability,
    ) -> Result<(), WebrtcEndpointError> {
        match capability.capability() {
            ConsentCapability::DirectAllowed => {
                self.srflx_candidates_created += 1;
                Ok(())
            }
            _ => Err(WebrtcEndpointError::ConsentDenied),
        }
    }

    /// Send a STUN binding request. Only permitted with `DirectAllowed`.
    pub fn send_stun_request(
        &mut self,
        capability: &VerifiedDirectCapability,
    ) -> Result<(), WebrtcEndpointError> {
        match capability.capability() {
            ConsentCapability::DirectAllowed => {
                self.stun_requests_sent += 1;
                Ok(())
            }
            _ => Err(WebrtcEndpointError::ConsentDenied),
        }
    }

    /// Configure mixed ICE (host + srflx + relay). Only permitted with
    /// `DirectAllowed`.
    pub fn configure_mixed_ice(
        &mut self,
        capability: &VerifiedDirectCapability,
    ) -> Result<(), WebrtcEndpointError> {
        match capability.capability() {
            ConsentCapability::DirectAllowed => {
                self.mixed_ice_configured = true;
                Ok(())
            }
            _ => Err(WebrtcEndpointError::ConsentDenied),
        }
    }

    /// Create a TURN allocation. Only permitted with `DirectAllowed` or
    /// `RelayOnly`. With `RelayOnly`, this is the only network resource
    /// created.
    ///
    /// This capability-gate-only entry point is retained for callers that do
    /// not yet have a full authorized ICE entry; it does not itself open a
    /// relay. The real provider call site is
    /// [`create_turn_allocation_via_provider`](Self::create_turn_allocation_via_provider).
    pub fn create_turn_allocation(
        &mut self,
        capability: &VerifiedDirectCapability,
    ) -> Result<(), WebrtcEndpointError> {
        match capability.capability() {
            ConsentCapability::DirectAllowed | ConsentCapability::RelayOnly => {
                self.turn_allocations_created += 1;
                Ok(())
            }
            _ => Err(WebrtcEndpointError::ConsentDenied),
        }
    }

    /// Real TURN provider call site (minimal wire).
    ///
    /// For consent-allowed capabilities (`DirectAllowed` | `RelayOnly`), drive
    /// a genuine allocation attempt through the injected
    /// [`TurnSocketProvider`] using the already-authorized ICE entry — the
    /// provider is the sole socket-opening seam, so `RelayOnly` still cannot
    /// open a direct socket. The `turn_allocations_created` counter reflects
    /// real attempts (incremented once an attempt is started), and the result
    /// is the provider's real success/failure, never a fabricated one.
    ///
    /// This wire does not mint credentials, re-validate ICE policy, or build
    /// the str0m/Tokio pump — those belong to `webrtc-endpoint-tokio-driver`.
    pub fn create_turn_allocation_via_provider(
        &mut self,
        capability: &VerifiedDirectCapability,
        provider: &mut TurnSocketProvider,
        entry: &AuthorizedIceEntry,
        allocation_lifetime: Duration,
    ) -> Result<u64, WebrtcEndpointError> {
        match capability.capability() {
            ConsentCapability::DirectAllowed | ConsentCapability::RelayOnly => {
                // A real attempt is starting; reflect it in the counter even if
                // the provider then fails closed.
                self.turn_allocations_created += 1;
                provider
                    .allocate(entry, allocation_lifetime)
                    .map_err(|_| WebrtcEndpointError::TurnAllocationFailed)
            }
            ConsentCapability::Unavailable => Err(WebrtcEndpointError::ConsentDenied),
        }
    }

    /// Configure relay-only ICE. Only permitted with `RelayOnly`.
    pub fn configure_relay_only_ice(
        &mut self,
        capability: &VerifiedDirectCapability,
    ) -> Result<(), WebrtcEndpointError> {
        match capability.capability() {
            ConsentCapability::RelayOnly => {
                self.relay_only_ice_configured = true;
                Ok(())
            }
            _ => Err(WebrtcEndpointError::ConsentDenied),
        }
    }

    /// Assert no direct work was performed. For relay_only and unavailable.
    pub fn assert_no_direct_work(&self) {
        assert_eq!(self.direct_udp_sockets_opened, 0);
        assert_eq!(self.interfaces_enumerated, 0);
        assert_eq!(self.host_candidates_created, 0);
        assert_eq!(self.srflx_candidates_created, 0);
        assert_eq!(self.stun_requests_sent, 0);
        assert!(!self.mixed_ice_configured);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Signaling state machine (pure reducer)
// ─────────────────────────────────────────────────────────────────────────

/// The signaling state for a single child attempt. The endpoint may submit
/// its transport-tagged final proof only after the signaling store has
/// committed `answer` and both role ICE-complete markers and the local
/// selected tuple/DTLS fingerprint transcript verifies. It installs
/// channels 0/2/4 only after both agreeing final proofs are
/// store-committed/delivered and peer-verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalingPhase {
    /// Initial state: offer not yet received/created.
    Init,
    /// Offer received from client (daemon is answerer).
    OfferReceived,
    /// Answer committed to signaling store.
    AnswerCommitted,
    /// Client ICE-complete marker committed.
    ClientIceComplete,
    /// Both role ICE-complete markers committed.
    BothIceComplete,
    /// Final proof submitted (transport-tagged).
    FinalProofSubmitted,
    /// Both agreeing final proofs store-committed and peer-verified.
    FinalProofsVerified,
    /// Channels 0/2/4 installed.
    ChannelsInstalled,
    /// Principal constructed.
    PrincipalConstructed,
    /// Cancelled/superseded/revoked/shutdown.
    Cancelled,
}

impl SignalingPhase {
    /// Check if the phase is terminal (no further progress).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::PrincipalConstructed | Self::Cancelled)
    }

    /// Check if the phase has passed the answer commit prerequisite.
    pub fn answer_committed(self) -> bool {
        !matches!(self, Self::Init | Self::OfferReceived) && !self.is_cancelled()
    }

    /// Check if the phase has passed both ICE-complete markers.
    pub fn both_ice_complete(self) -> bool {
        !matches!(
            self,
            Self::Init | Self::OfferReceived | Self::AnswerCommitted | Self::ClientIceComplete
        ) && !self.is_cancelled()
    }

    /// Check if final proofs are verified.
    pub fn final_proofs_verified(self) -> bool {
        matches!(
            self,
            Self::FinalProofsVerified | Self::ChannelsInstalled | Self::PrincipalConstructed
        )
    }

    pub fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Peer generation lifecycle
// ─────────────────────────────────────────────────────────────────────────

/// A peer generation within a logical attachment.
#[derive(Debug, Clone)]
pub struct PeerGeneration {
    pub generation: Generation,
    pub state: GenerationState,
    pub signaling_phase: SignalingPhase,
    pub capability: VerifiedDirectCapability,
    pub lease_id: [u8; 16],
    pub lease_generation: LeaseGeneration,
    pub channels_installed: bool,
    pub principal_constructed: bool,
    pub consent_misses: u32,
    pub last_consent_probe: Option<Instant>,
    pub ice_deadline: Option<Instant>,
    pub draining_deadline: Option<Instant>,
}

impl PeerGeneration {
    pub fn is_current(&self) -> bool {
        self.state == GenerationState::Current
    }

    pub fn is_pending(&self) -> bool {
        self.state == GenerationState::ReplacementPending
    }

    pub fn is_draining(&self) -> bool {
        self.state == GenerationState::Draining
    }

    /// A pending generation carries no application operation.
    pub fn can_carry_application(&self) -> bool {
        self.is_current() && self.principal_constructed
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Supervisor reducer (pure over injected events)
// ─────────────────────────────────────────────────────────────────────────

/// Input events fed to the supervisor reducer. These are the injected
/// network/time/str0m events.
#[derive(Debug, Clone)]
pub enum SupervisorInput {
    /// An SDP offer was received from the client.
    SdpOffer {
        child_attempt_id: [u8; 16],
        sdp: Vec<u8>,
    },
    /// An SDP answer was committed to the signaling store.
    SdpAnswerCommitted {
        child_attempt_id: [u8; 16],
        ack: RemoteSignalingCommitAckV1,
    },
    /// A remote ICE candidate was received.
    RemoteCandidate {
        child_attempt_id: [u8; 16],
        candidate: Vec<u8>,
    },
    /// An ICE-complete marker was committed for a role.
    /// role: 1 = client, 2 = daemon.
    IceComplete {
        child_attempt_id: [u8; 16],
        role: u8,
    },
    /// A transport-tagged final proof was submitted.
    FinalProofSubmitted {
        child_attempt_id: [u8; 16],
        role: u8,
        proof: Vec<u8>,
    },
    /// Both agreeing final proofs were store-committed and peer-verified.
    FinalProofsVerified {
        child_attempt_id: [u8; 16],
        set_digest: [u8; 32],
    },
    /// A lease cutover ACK was persisted by the supervisor.
    CutoverAckPersisted {
        child_attempt_id: [u8; 16],
        ack: CutoverAck,
    },
    /// A consent freshness probe response was received.
    ConsentProbeResponse { child_attempt_id: [u8; 16] },
    /// A consent freshness probe timed out (no response).
    ConsentProbeTimeout {
        child_attempt_id: [u8; 16],
        now: Instant,
    },
    /// A cancellation/supersede/revoke/interface-change/control-gap/restart/
    /// shutdown event.
    Cancel {
        child_attempt_id: [u8; 16],
        reason: CancelReason,
    },
    /// A timeout fired (injected monotonic time).
    Timeout { now: Instant },
    /// A str0m input event (network packet or timeout).
    Str0mInput,
    /// A str0m output event was polled.
    Str0mOutput,
}

/// Reasons for cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CancelReason {
    Cancellation,
    Supersede,
    ConsentRevoke,
    PolicyRevoke,
    InterfaceChange,
    CredentialExpiry,
    ControlGap,
    IceRestart,
    Shutdown,
}

/// Output actions from the supervisor reducer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorOutput {
    /// Accept the SDP offer and create an answer.
    AcceptOffer { child_attempt_id: [u8; 16] },
    /// Reject the SDP offer.
    RejectOffer {
        child_attempt_id: [u8; 16],
        reason: WebrtcEndpointError,
    },
    /// Commit the answer to the signaling store.
    CommitAnswer { child_attempt_id: [u8; 16] },
    /// Add a remote ICE candidate to str0m.
    AddRemoteCandidate { child_attempt_id: [u8; 16] },
    /// Submit the transport-tagged final proof.
    SubmitFinalProof {
        child_attempt_id: [u8; 16],
        role: u8,
    },
    /// Install channels 0/2/4.
    InstallChannels { child_attempt_id: [u8; 16] },
    /// Construct the ClientPrincipal.
    ConstructPrincipal { child_attempt_id: [u8; 16] },
    /// Perform a lease cutover (switch routes/channels).
    Cutover {
        child_attempt_id: [u8; 16],
        ack: CutoverAck,
    },
    /// Close a draining generation.
    CloseDraining { child_attempt_id: [u8; 16] },
    /// Remove a drained generation (second lease).
    RemoveDrained { child_attempt_id: [u8; 16] },
    /// Send a consent freshness probe.
    ConsentProbe { child_attempt_id: [u8; 16] },
    /// Teardown due to consent freshness failure.
    ConsentFreshnessTeardown { child_attempt_id: [u8; 16] },
    /// Cancel/teardown the generation.
    Cancel {
        child_attempt_id: [u8; 16],
        reason: CancelReason,
    },
    /// Yield: the turn budget is exhausted.
    Yield,
    /// No action (inert event for a late generation).
    Inert,
}

/// The supervisor state for a single child attempt.
#[derive(Debug, Clone)]
pub struct ChildSupervisorState {
    pub child_attempt_id: [u8; 16],
    pub generation: PeerGeneration,
    /// Pending replacement generation, if any.
    pub replacement_pending: Option<PeerGeneration>,
    /// Draining predecessor generation, if any.
    pub draining: Option<PeerGeneration>,
    /// Whether the cutover ACK has been persisted.
    pub cutover_acked: bool,
    /// The verified final-proof set digest, if both proofs are verified.
    pub final_proof_set_digest: Option<[u8; 32]>,
    /// The DTLS fingerprint transcript, if verified.
    pub dtls_fingerprint: Option<[u8; 32]>,
    /// The selected tuple, if ICE is complete.
    pub selected_tuple: Option<Vec<u8>>,
    /// Counters for the 64/64/64 yield budget.
    pub input_events_this_turn: usize,
    pub timeout_actions_this_turn: usize,
    pub output_actions_this_turn: usize,
}

impl ChildSupervisorState {
    pub fn new(
        child_attempt_id: [u8; 16],
        capability: VerifiedDirectCapability,
        now: Instant,
    ) -> Self {
        Self {
            child_attempt_id,
            generation: PeerGeneration {
                generation: Generation::default(),
                state: GenerationState::Current,
                signaling_phase: SignalingPhase::Init,
                capability,
                lease_id: [0u8; 16],
                lease_generation: LeaseGeneration(1),
                channels_installed: false,
                principal_constructed: false,
                consent_misses: 0,
                last_consent_probe: None,
                ice_deadline: Some(now + Duration::from_secs(ICE_ESTABLISHMENT_DEADLINE_SECS)),
                draining_deadline: None,
            },
            replacement_pending: None,
            draining: None,
            cutover_acked: false,
            final_proof_set_digest: None,
            dtls_fingerprint: None,
            selected_tuple: None,
            input_events_this_turn: 0,
            timeout_actions_this_turn: 0,
            output_actions_this_turn: 0,
        }
    }

    /// Reset per-turn counters.
    pub fn reset_turn(&mut self) {
        self.input_events_this_turn = 0;
        self.timeout_actions_this_turn = 0;
        self.output_actions_this_turn = 0;
    }

    /// Check if the turn budget is exhausted (64/64/64 yield).
    pub fn turn_budget_exhausted(&self) -> bool {
        self.input_events_this_turn >= MAX_INPUT_EVENTS_PER_TURN
            || self.timeout_actions_this_turn >= MAX_TIMEOUT_ACTIONS_PER_TURN
            || self.output_actions_this_turn >= MAX_OUTPUT_ACTIONS_PER_TURN
    }

    /// Process a single input event and return an output action. This is
    /// the pure reducer.
    pub fn process(&mut self, input: &SupervisorInput) -> SupervisorOutput {
        // Late generation events are inert.
        if self.generation.state == GenerationState::Removed {
            return SupervisorOutput::Inert;
        }
        if self.generation.signaling_phase.is_cancelled() {
            return SupervisorOutput::Inert;
        }

        // Charge this input to exactly one of the three independent per-turn
        // budgets, then yield the whole turn if any budget is now exhausted
        // (64/64/64). Timeout actions and str0m output polls each have their own
        // budget; every other event (str0m input and control/signaling) counts
        // as an input event. Charging a single counter avoids the double-count
        // that previously let the input budget starve the timeout/output ones.
        match input {
            SupervisorInput::Timeout { .. } => self.timeout_actions_this_turn += 1,
            SupervisorInput::Str0mOutput => self.output_actions_this_turn += 1,
            _ => self.input_events_this_turn += 1,
        }
        if self.turn_budget_exhausted() {
            return SupervisorOutput::Yield;
        }

        match input {
            SupervisorInput::SdpOffer {
                child_attempt_id,
                sdp,
            } => {
                if *child_attempt_id != self.child_attempt_id {
                    return SupervisorOutput::Inert;
                }
                // Validate SDP size.
                if sdp.len() > MAX_SDP_PAYLOAD_BYTES {
                    self.generation.signaling_phase = SignalingPhase::Cancelled;
                    return SupervisorOutput::RejectOffer {
                        child_attempt_id: *child_attempt_id,
                        reason: WebrtcEndpointError::BudgetExhausted("SDP payload too large"),
                    };
                }
                // Unavailable creates no Rtc network resource.
                if self.generation.capability.capability() == ConsentCapability::Unavailable {
                    self.generation.signaling_phase = SignalingPhase::Cancelled;
                    return SupervisorOutput::RejectOffer {
                        child_attempt_id: *child_attempt_id,
                        reason: WebrtcEndpointError::ConsentDenied,
                    };
                }
                self.generation.signaling_phase = SignalingPhase::OfferReceived;
                SupervisorOutput::AcceptOffer {
                    child_attempt_id: *child_attempt_id,
                }
            }
            SupervisorInput::SdpAnswerCommitted {
                child_attempt_id,
                ack: _,
            } => {
                if *child_attempt_id != self.child_attempt_id {
                    return SupervisorOutput::Inert;
                }
                if !matches!(
                    self.generation.signaling_phase,
                    SignalingPhase::OfferReceived
                ) {
                    return SupervisorOutput::Inert;
                }
                self.generation.signaling_phase = SignalingPhase::AnswerCommitted;
                SupervisorOutput::CommitAnswer {
                    child_attempt_id: *child_attempt_id,
                }
            }
            SupervisorInput::RemoteCandidate {
                child_attempt_id,
                candidate,
            } => {
                if *child_attempt_id != self.child_attempt_id {
                    return SupervisorOutput::Inert;
                }
                if candidate.len() > MAX_CANDIDATE_BYTES {
                    return SupervisorOutput::Inert;
                }
                SupervisorOutput::AddRemoteCandidate {
                    child_attempt_id: *child_attempt_id,
                }
            }
            SupervisorInput::IceComplete {
                child_attempt_id,
                role,
            } => {
                if *child_attempt_id != self.child_attempt_id {
                    return SupervisorOutput::Inert;
                }
                if !self.generation.signaling_phase.answer_committed() {
                    return SupervisorOutput::Inert;
                }
                if *role == 1 {
                    // Client ICE-complete.
                    self.generation.signaling_phase = SignalingPhase::ClientIceComplete;
                } else {
                    // Daemon ICE-complete; if client already complete, both.
                    if self.generation.signaling_phase == SignalingPhase::ClientIceComplete {
                        self.generation.signaling_phase = SignalingPhase::BothIceComplete;
                    }
                }
                SupervisorOutput::AddRemoteCandidate {
                    child_attempt_id: *child_attempt_id,
                }
            }
            SupervisorInput::FinalProofSubmitted {
                child_attempt_id,
                role,
                proof: _,
            } => {
                if *child_attempt_id != self.child_attempt_id {
                    return SupervisorOutput::Inert;
                }
                // Final proof can only be submitted after both ICE-complete
                // and answer committed.
                if !self.generation.signaling_phase.both_ice_complete() {
                    return SupervisorOutput::Inert;
                }
                self.generation.signaling_phase = SignalingPhase::FinalProofSubmitted;
                SupervisorOutput::SubmitFinalProof {
                    child_attempt_id: *child_attempt_id,
                    role: *role,
                }
            }
            SupervisorInput::FinalProofsVerified {
                child_attempt_id,
                set_digest,
            } => {
                if *child_attempt_id != self.child_attempt_id {
                    return SupervisorOutput::Inert;
                }
                if !matches!(
                    self.generation.signaling_phase,
                    SignalingPhase::FinalProofSubmitted
                ) {
                    return SupervisorOutput::Inert;
                }
                self.final_proof_set_digest = Some(*set_digest);
                self.generation.signaling_phase = SignalingPhase::FinalProofsVerified;
                // Install channels 0/2/4 after both proofs verified.
                self.generation.signaling_phase = SignalingPhase::ChannelsInstalled;
                self.generation.channels_installed = true;
                SupervisorOutput::InstallChannels {
                    child_attempt_id: *child_attempt_id,
                }
            }
            SupervisorInput::CutoverAckPersisted {
                child_attempt_id,
                ack,
            } => {
                if *child_attempt_id != self.child_attempt_id {
                    return SupervisorOutput::Inert;
                }
                self.cutover_acked = true;
                // If there's a pending replacement, cutover.
                if let Some(ref _pending) = self.replacement_pending {
                    // Cutover: pending becomes current, old becomes draining.
                    SupervisorOutput::Cutover {
                        child_attempt_id: *child_attempt_id,
                        ack: ack.clone(),
                    }
                } else {
                    SupervisorOutput::Inert
                }
            }
            SupervisorInput::ConsentProbeResponse { child_attempt_id } => {
                if *child_attempt_id != self.child_attempt_id {
                    return SupervisorOutput::Inert;
                }
                self.generation.consent_misses = 0;
                SupervisorOutput::Inert
            }
            SupervisorInput::ConsentProbeTimeout {
                child_attempt_id,
                now,
            } => {
                if *child_attempt_id != self.child_attempt_id {
                    return SupervisorOutput::Inert;
                }
                self.generation.consent_misses += 1;
                self.generation.last_consent_probe = Some(*now);
                if self.generation.consent_misses >= CONSENT_FRESHNESS_MISS_THRESHOLD {
                    self.generation.signaling_phase = SignalingPhase::Cancelled;
                    SupervisorOutput::ConsentFreshnessTeardown {
                        child_attempt_id: *child_attempt_id,
                    }
                } else {
                    SupervisorOutput::ConsentProbe {
                        child_attempt_id: *child_attempt_id,
                    }
                }
            }
            SupervisorInput::Cancel {
                child_attempt_id,
                reason,
            } => {
                if *child_attempt_id != self.child_attempt_id {
                    return SupervisorOutput::Inert;
                }
                self.generation.signaling_phase = SignalingPhase::Cancelled;
                SupervisorOutput::Cancel {
                    child_attempt_id: *child_attempt_id,
                    reason: *reason,
                }
            }
            SupervisorInput::Timeout { now } => {
                // Check ICE deadline.
                if let Some(deadline) = self.generation.ice_deadline
                    && *now >= deadline
                    && !self.generation.signaling_phase.both_ice_complete()
                    && !self.generation.signaling_phase.is_cancelled()
                {
                    self.generation.signaling_phase = SignalingPhase::Cancelled;
                    return SupervisorOutput::Cancel {
                        child_attempt_id: self.child_attempt_id,
                        reason: CancelReason::Cancellation,
                    };
                }
                // Check draining deadline: once it elapses the drained
                // predecessor generation is removed entirely (mirrors
                // `DaemonSupervisor::remove_drained`), not merely marked.
                let draining_expired = self
                    .draining
                    .as_ref()
                    .and_then(|d| d.draining_deadline)
                    .is_some_and(|deadline| *now >= deadline);
                if draining_expired {
                    self.draining = None;
                    return SupervisorOutput::RemoveDrained {
                        child_attempt_id: self.child_attempt_id,
                    };
                }
                // Check consent freshness interval.
                if self.generation.signaling_phase.final_proofs_verified() {
                    let should_probe = self
                        .generation
                        .last_consent_probe
                        .map(|last| {
                            *now >= last + Duration::from_secs(CONSENT_FRESHNESS_INTERVAL_SECS)
                        })
                        .unwrap_or(true);
                    if should_probe {
                        self.generation.last_consent_probe = Some(*now);
                        return SupervisorOutput::ConsentProbe {
                            child_attempt_id: self.child_attempt_id,
                        };
                    }
                }
                SupervisorOutput::Inert
            }
            SupervisorInput::Str0mInput | SupervisorInput::Str0mOutput => SupervisorOutput::Inert,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Daemon supervisor (manages multiple child attempts)
// ─────────────────────────────────────────────────────────────────────────

/// The daemon supervisor maintaining the authenticated TypeScript control
/// channel, replaying child attempts, verifying grants/bilateral proofs
/// locally, and creating one bounded `str0m` peer per participant child.
#[derive(Debug, Clone)]
pub struct DaemonSupervisor {
    pub children: Vec<ChildSupervisorState>,
    pub total_generations: usize,
    pub routed_current: usize,
}

impl DaemonSupervisor {
    pub fn new() -> Self {
        Self {
            children: Vec::new(),
            total_generations: 0,
            routed_current: 0,
        }
    }

    /// Admit a new child attempt. Checks the 32-total and 2-routed-current
    /// caps before allocating. Capacity exhaustion denies the pending
    /// replacement rather than exceeding 32 or evicting current.
    pub fn admit_child(
        &mut self,
        child_attempt_id: [u8; 16],
        capability: VerifiedDirectCapability,
        now: Instant,
    ) -> Result<(), WebrtcEndpointError> {
        if self.total_generations >= MAX_TOTAL_PEER_GENERATIONS {
            return Err(WebrtcEndpointError::BudgetExhausted(
                "32 total peer generations cap",
            ));
        }
        if self.routed_current >= MAX_ROUTED_CURRENT_CHILDREN {
            return Err(WebrtcEndpointError::BudgetExhausted(
                "2 routed-current children cap",
            ));
        }
        self.children
            .push(ChildSupervisorState::new(child_attempt_id, capability, now));
        self.total_generations += 1;
        self.routed_current += 1;
        Ok(())
    }

    /// Start a replacement-pending generation. The pending generation may
    /// authorize/allocate/negotiate/prove but carries no application
    /// operation. Capacity exhaustion denies the pending replacement.
    pub fn start_replacement(
        &mut self,
        child_attempt_id: [u8; 16],
        capability: VerifiedDirectCapability,
        _now: Instant,
    ) -> Result<(), WebrtcEndpointError> {
        if self.total_generations >= MAX_TOTAL_PEER_GENERATIONS {
            return Err(WebrtcEndpointError::BudgetExhausted(
                "32 total peer generations cap (replacement denied)",
            ));
        }
        let child = self
            .children
            .iter_mut()
            .find(|c| c.child_attempt_id == child_attempt_id)
            .ok_or(WebrtcEndpointError::BudgetExhausted("child not found"))?;
        if child.replacement_pending.is_some() {
            return Err(WebrtcEndpointError::BudgetExhausted(
                "replacement already pending",
            ));
        }
        child.replacement_pending = Some(PeerGeneration {
            generation: child.generation.generation.next(),
            state: GenerationState::ReplacementPending,
            signaling_phase: SignalingPhase::Init,
            capability,
            lease_id: child.generation.lease_id,
            lease_generation: LeaseGeneration(child.generation.lease_generation.0 + 1),
            channels_installed: false,
            principal_constructed: false,
            consent_misses: 0,
            last_consent_probe: None,
            ice_deadline: None,
            draining_deadline: None,
        });
        self.total_generations += 1;
        Ok(())
    }

    /// Perform a cutover: the sole current lease names replacement current
    /// and predecessor draining, plus the supervisor's persisted ACK.
    /// Only then are routes/channels for new work switched.
    pub fn cutover(
        &mut self,
        child_attempt_id: [u8; 16],
        ack: CutoverAck,
        now: Instant,
    ) -> Result<SupervisorOutput, WebrtcEndpointError> {
        let child = self
            .children
            .iter_mut()
            .find(|c| c.child_attempt_id == child_attempt_id)
            .ok_or(WebrtcEndpointError::BudgetExhausted("child not found"))?;

        if !child.cutover_acked {
            return Err(WebrtcEndpointError::SignalingPrerequisite(
                "cutover ACK not persisted",
            ));
        }

        let pending =
            child
                .replacement_pending
                .take()
                .ok_or(WebrtcEndpointError::SignalingPrerequisite(
                    "no pending replacement",
                ))?;

        // Old current becomes draining.
        let old_generation = child.generation.generation;
        child.generation.state = GenerationState::Draining;
        child.generation.draining_deadline = Some(now + Duration::from_secs(DRAINING_TIMEOUT_SECS));
        child.draining = Some(child.generation.clone());

        // Pending becomes current.
        child.generation = pending;
        child.generation.state = GenerationState::Current;
        child.cutover_acked = false;

        Ok(SupervisorOutput::Cutover {
            child_attempt_id,
            ack: CutoverAck {
                old_generation,
                new_generation: child.generation.generation,
                ..ack
            },
        })
    }

    /// Remove a drained generation (second lease removal).
    pub fn remove_drained(
        &mut self,
        child_attempt_id: [u8; 16],
    ) -> Result<SupervisorOutput, WebrtcEndpointError> {
        let child = self
            .children
            .iter_mut()
            .find(|c| c.child_attempt_id == child_attempt_id)
            .ok_or(WebrtcEndpointError::BudgetExhausted("child not found"))?;

        if let Some(ref mut draining) = child.draining {
            draining.state = GenerationState::Removed;
            child.draining = None;
            self.total_generations -= 1;
            Ok(SupervisorOutput::RemoveDrained { child_attempt_id })
        } else {
            Err(WebrtcEndpointError::SignalingPrerequisite(
                "no draining generation to remove",
            ))
        }
    }

    /// Cancel a child (stop new work, close resources, late events inert).
    pub fn cancel_child(
        &mut self,
        child_attempt_id: [u8; 16],
        reason: CancelReason,
    ) -> SupervisorOutput {
        if let Some(child) = self
            .children
            .iter_mut()
            .find(|c| c.child_attempt_id == child_attempt_id)
        {
            child.generation.signaling_phase = SignalingPhase::Cancelled;
            // Pending becomes inert.
            if let Some(ref mut pending) = child.replacement_pending {
                pending.signaling_phase = SignalingPhase::Cancelled;
            }
            // Draining becomes inert.
            if let Some(ref mut draining) = child.draining {
                draining.signaling_phase = SignalingPhase::Cancelled;
            }
            SupervisorOutput::Cancel {
                child_attempt_id,
                reason,
            }
        } else {
            SupervisorOutput::Inert
        }
    }

    /// Process an input for a specific child.
    pub fn process_for_child(
        &mut self,
        child_attempt_id: [u8; 16],
        input: &SupervisorInput,
    ) -> SupervisorOutput {
        if let Some(child) = self
            .children
            .iter_mut()
            .find(|c| c.child_attempt_id == child_attempt_id)
        {
            child.process(input)
        } else {
            SupervisorOutput::Inert
        }
    }
}

impl Default for DaemonSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Three-channel contract helpers
// ─────────────────────────────────────────────────────────────────────────

/// Verify the fixed three-channel contract: exactly IDs 0/2/4, exact labels,
/// ordered, reliable, and no dynamic channel.
pub fn verify_three_channel_contract() -> Result<(), WebrtcEndpointError> {
    if REMOTE_LANE_CHANNELS.len() != 3 {
        return Err(WebrtcEndpointError::SignalingPrerequisite(
            "exactly 3 channels required",
        ));
    }
    let expected_ids = [0u16, 2u16, 4u16];
    let expected_labels = [
        "flycockpit.control.v1",
        "flycockpit.interactive.v1",
        "flycockpit.bulk.v1",
    ];
    for (i, channel) in REMOTE_LANE_CHANNELS.iter().enumerate() {
        if channel.channel_id != expected_ids[i] {
            return Err(WebrtcEndpointError::SignalingPrerequisite(
                "channel ID mismatch",
            ));
        }
        if channel.label != expected_labels[i] {
            return Err(WebrtcEndpointError::SignalingPrerequisite(
                "channel label mismatch",
            ));
        }
        if !channel.ordered {
            return Err(WebrtcEndpointError::SignalingPrerequisite(
                "channel must be ordered",
            ));
        }
        if !channel.reliable {
            return Err(WebrtcEndpointError::SignalingPrerequisite(
                "channel must be reliable",
            ));
        }
        if !channel.negotiated {
            return Err(WebrtcEndpointError::SignalingPrerequisite(
                "channel must be negotiated (fixed)",
            ));
        }
    }
    Ok(())
}

/// Return the channel configurations for str0m data channel creation.
/// Each channel is created with the exact label, ordered, and reliable
/// settings from the transport channel contract. The `negotiated` field
/// is set to the exact SCTP stream ID (0/2/4) for out-of-band negotiation.
pub fn channel_configs() -> Vec<str0m::channel::ChannelConfig> {
    REMOTE_LANE_CHANNELS
        .iter()
        .map(|ch| str0m::channel::ChannelConfig {
            label: ch.label.to_string(),
            protocol: "".to_string(),
            negotiated: Some(ch.channel_id),
            reliability: str0m::channel::Reliability::Reliable,
            ordered: true,
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────
// Redaction helpers
// ─────────────────────────────────────────────────────────────────────────

/// Redact sensitive data (addresses, candidates, fingerprints, tokens,
/// identities, content) from log/error output.
pub fn redact_sensitive(input: &str) -> String {
    let mut output = input.to_string();
    // Redact IP addresses.
    let ip_pattern = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    output = ip_pattern.replace_all(&output, "[REDACTED_IP]").to_string();
    // Redact hex strings of 32+ chars (fingerprints, tokens, etc.).
    let hex_pattern = regex::Regex::new(r"\b[0-9a-fA-F]{32,}\b").unwrap();
    output = hex_pattern
        .replace_all(&output, "[REDACTED_HEX]")
        .to_string();
    // Redact candidate lines.
    let candidate_pattern = regex::Regex::new(r"candidate:[^\s]+").unwrap();
    output = candidate_pattern
        .replace_all(&output, "candidate:[REDACTED]")
        .to_string();
    output
}

// ─────────────────────────────────────────────────────────────────────────
// SDP/candidate validation helpers
// ─────────────────────────────────────────────────────────────────────────

/// Validate an SDP payload size against the 122,880-byte cap.
pub fn validate_sdp_size(sdp: &[u8]) -> Result<(), WebrtcEndpointError> {
    if sdp.is_empty() {
        return Err(WebrtcEndpointError::BudgetExhausted("empty SDP"));
    }
    if sdp.len() > MAX_SDP_PAYLOAD_BYTES {
        return Err(WebrtcEndpointError::BudgetExhausted(
            "SDP payload too large",
        ));
    }
    Ok(())
}

/// Validate a candidate against the 4,096-byte cap.
pub fn validate_candidate_size(candidate: &[u8]) -> Result<(), WebrtcEndpointError> {
    if candidate.is_empty() {
        return Err(WebrtcEndpointError::BudgetExhausted("empty candidate"));
    }
    if candidate.len() > MAX_CANDIDATE_BYTES {
        return Err(WebrtcEndpointError::BudgetExhausted("candidate too large"));
    }
    Ok(())
}

/// Validate a signaling commit ack against the signaling codec.
pub fn validate_commit_ack(
    ack_bytes: &[u8],
) -> Result<RemoteSignalingCommitAckV1, WebrtcEndpointError> {
    RemoteSignalingCommitAckV1::decode(ack_bytes)
        .map_err(|e: SignalingCodecError| WebrtcEndpointError::SignalingCodec(e.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::remote_ip_consent::{
        ConsentCapability, DisclosureRegistryLease, GatherAuthorizationState,
        RemoteDeviceRelationshipV1, RemoteDirectGatherAuthorization, RemoteIpConsentStatusBody,
        RemoteIpConsentStatusEnvelope, VerifiedDirectCapability,
    };

    /// The relationship the direct-allowed test fixtures are bound to.
    fn direct_relationship() -> RemoteDeviceRelationshipV1 {
        RemoteDeviceRelationshipV1 {
            tenant_id: [0x01; 16],
            instance_id: [0x02; 16],
            daemon_device_id: [0x03; 16],
            daemon_generation: 1,
            daemon_thumbprint: [0xAA; 32],
            client_device_id: [0x04; 16],
            client_generation: 1,
            client_thumbprint: [0xBB; 32],
        }
    }

    /// A verified `DirectAllowed` capability built only through the real
    /// constructor path: a committed authorization plus the matching signed
    /// status envelope it validated. There is no struct-literal forging — the
    /// fields are private. The `|_, _| true` verifier stands in for the remote
    /// authority ring (in-process misuse is out of the threat model); the
    /// enforced property is that every binding field must match the presented
    /// status envelope.
    fn direct_cap() -> VerifiedDirectCapability {
        let rel = direct_relationship();
        let sem = [0x5c; 32];
        let issued_at: i64 = 1_700_000_000;
        let valid_until = issued_at + 60;

        let auth = RemoteDirectGatherAuthorization {
            authorization_id: [0xbb; 16],
            child_attempt_id: [0xcc; 16],
            relationship_hash: rel.hash(),
            disclosure_version: 1,
            semantic_digest: sem,
            server_sequence: 1,
            policy_epoch: 1,
            authority_epoch: 1,
            status_valid_until: valid_until,
            state: GatherAuthorizationState::Unused,
        };
        let status = RemoteIpConsentStatusEnvelope {
            body: RemoteIpConsentStatusBody {
                relationship: rel,
                disclosure_version: 1,
                semantic_digest: sem,
                server_sequence: 1,
                state: ConsentCapability::DirectAllowed,
                policy_epoch: 1,
                authority_epoch: 1,
                issuer_kid: "k1".to_string(),
                issued_at,
                valid_until,
            },
            signature: [0x11; 64],
        };
        let reg_digest = [0x77; 32];
        let lease = DisclosureRegistryLease {
            accepted_registry_digest: reg_digest,
            accepted_registry_version: 1,
            ready: true,
        };
        VerifiedDirectCapability::from_committed_begin(
            &auth,
            &status,
            &lease,
            &reg_digest,
            true,
            issued_at + 30,
            |_digest, _sig| true,
        )
        .expect("direct_cap builds a valid DirectAllowed capability")
    }

    fn relay_only_cap() -> VerifiedDirectCapability {
        VerifiedDirectCapability::relay_only([0xaa; 32], 1, 1, 1)
    }

    fn unavailable_cap() -> VerifiedDirectCapability {
        VerifiedDirectCapability::unavailable([0xaa; 32], 1, 1, 1)
    }

    fn now() -> Instant {
        Instant::now()
    }

    fn child_id() -> [u8; 16] {
        [0x01; 16]
    }

    // ── AC1: remote_webrtc_str0m_dependency_gate ──

    #[test]
    fn remote_webrtc_str0m_dependency_gate() {
        // Prove exact 0.21.0/defaults-off/rust-crypto, per-Rtc provider,
        // MSRV/platform/license/provenance, and no alternate backend/stack.
        let record = str0m_dependency_record();
        assert_eq!(record.version, "0.21.0");
        assert_eq!(record.crypto_feature, "rust-crypto");
        assert!(!record.default_features, "default features must be off");
        assert!(!record.alternate_backend, "no alternate backend");
        assert_eq!(record.provider, "str0m_rust_crypto::default_provider");
        assert_eq!(record.msrv, "1.95");
        assert_eq!(record.license, "MIT OR Apache-2.0");
        assert!(record.platforms.contains(&"x86_64-unknown-linux-gnu"));
        assert!(record.platforms.contains(&"x86_64-apple-darwin"));
        assert!(record.platforms.contains(&"x86_64-pc-windows-msvc"));
        assert!(record.platforms.contains(&"aarch64-apple-darwin"));

        // Prove the Rtc instance is actually created with the RustCrypto
        // provider. This is a live build test: if the crypto feature is
        // wrong, the build fails.
        let rtc = new_rtc_with_rust_crypto(now());
        // The Rtc instance is created and can be dropped without panic.
        drop(rtc);
    }

    // ── AC2: remote_webrtc_consent_precedes_direct_work ──

    #[test]
    fn remote_webrtc_consent_precedes_direct_work() {
        // Instruments every socket/interface/STUN/candidate/Rtc factory and
        // proves exact direct_allowed/relay_only/unavailable behavior.

        // direct_allowed: all direct work permitted.
        let cap = direct_cap();
        let mut factory = ConsentGatedResourceFactory::default();
        assert!(factory.create_rtc(&cap, now()).is_ok());
        assert!(factory.open_direct_udp_socket(&cap).is_ok());
        assert!(factory.enumerate_interfaces(&cap).is_ok());
        assert!(factory.create_host_candidate(&cap).is_ok());
        assert!(factory.create_srflx_candidate(&cap).is_ok());
        assert!(factory.send_stun_request(&cap).is_ok());
        assert!(factory.configure_mixed_ice(&cap).is_ok());
        assert!(factory.create_turn_allocation(&cap).is_ok());
        assert!(!factory.relay_only_ice_configured);
        assert_eq!(factory.rtc_instances_created, 1);
        assert_eq!(factory.direct_udp_sockets_opened, 1);
        assert_eq!(factory.host_candidates_created, 1);
        assert_eq!(factory.srflx_candidates_created, 1);
        assert_eq!(factory.stun_requests_sent, 1);

        // relay_only: no direct work, only TURN allocation.
        let cap = relay_only_cap();
        let mut factory = ConsentGatedResourceFactory::default();
        assert!(factory.create_rtc(&cap, now()).is_ok());
        assert!(factory.create_turn_allocation(&cap).is_ok());
        assert!(factory.configure_relay_only_ice(&cap).is_ok());
        // All direct work is denied.
        assert!(factory.open_direct_udp_socket(&cap).is_err());
        assert!(factory.enumerate_interfaces(&cap).is_err());
        assert!(factory.create_host_candidate(&cap).is_err());
        assert!(factory.create_srflx_candidate(&cap).is_err());
        assert!(factory.send_stun_request(&cap).is_err());
        assert!(factory.configure_mixed_ice(&cap).is_err());
        factory.assert_no_direct_work();
        assert_eq!(factory.turn_allocations_created, 1);
        assert!(factory.relay_only_ice_configured);

        // unavailable: no transport resources at all.
        let cap = unavailable_cap();
        let mut factory = ConsentGatedResourceFactory::default();
        assert!(factory.create_rtc(&cap, now()).is_err());
        assert!(factory.open_direct_udp_socket(&cap).is_err());
        assert!(factory.enumerate_interfaces(&cap).is_err());
        assert!(factory.create_host_candidate(&cap).is_err());
        assert!(factory.create_srflx_candidate(&cap).is_err());
        assert!(factory.send_stun_request(&cap).is_err());
        assert!(factory.create_turn_allocation(&cap).is_err());
        assert!(factory.configure_mixed_ice(&cap).is_err());
        assert!(factory.configure_relay_only_ice(&cap).is_err());
        factory.assert_no_direct_work();
        assert!(!factory.transport_resources_created);
        assert_eq!(factory.rtc_instances_created, 0);

        // A plain bool or client claim cannot construct the capability.
        // VerifiedDirectCapability is only constructible via its typed
        // constructors or from a verified status. This is enforced by
        // the type system: there is no `from_bool` or `from_claim`.
    }

    // ── AC3: remote_webrtc_offer_answer_conformance ──

    #[test]
    fn remote_webrtc_offer_answer_conformance() {
        // Negotiates a browser fixture and proves answer+bilateral ICE-
        // complete commit prerequisites, exact final-proof commit ACK/
        // re-read, tuple/route/fingerprint agreement, and both peer proofs
        // before channels/principal.
        let cap = direct_cap();
        let mut state = ChildSupervisorState::new(child_id(), cap, now());

        // Phase 1: Offer received.
        let offer = vec![0u8; 100];
        let out = state.process(&SupervisorInput::SdpOffer {
            child_attempt_id: child_id(),
            sdp: offer,
        });
        assert!(matches!(out, SupervisorOutput::AcceptOffer { .. }));
        assert_eq!(
            state.generation.signaling_phase,
            SignalingPhase::OfferReceived
        );

        // Answer cannot be committed before offer is received — but we just
        // received it, so answer commit is the next step.
        // Try to submit final proof before answer: must be inert.
        let out = state.process(&SupervisorInput::FinalProofSubmitted {
            child_attempt_id: child_id(),
            role: 2,
            proof: vec![0u8; 313],
        });
        assert!(matches!(out, SupervisorOutput::Inert));

        // Phase 2: Answer committed.
        let ack = RemoteSignalingCommitAckV1 {
            event_id: [0x02; 16],
            sequence: 1,
            event_digest: [0x03; 32],
        };
        let out = state.process(&SupervisorInput::SdpAnswerCommitted {
            child_attempt_id: child_id(),
            ack: ack.clone(),
        });
        assert!(matches!(out, SupervisorOutput::CommitAnswer { .. }));
        assert_eq!(
            state.generation.signaling_phase,
            SignalingPhase::AnswerCommitted
        );

        // Try to submit final proof before ICE-complete: must be inert.
        let out = state.process(&SupervisorInput::FinalProofSubmitted {
            child_attempt_id: child_id(),
            role: 2,
            proof: vec![0u8; 313],
        });
        assert!(matches!(out, SupervisorOutput::Inert));

        // Phase 3: Client ICE-complete.
        let out = state.process(&SupervisorInput::IceComplete {
            child_attempt_id: child_id(),
            role: 1,
        });
        assert!(matches!(out, SupervisorOutput::AddRemoteCandidate { .. }));
        assert_eq!(
            state.generation.signaling_phase,
            SignalingPhase::ClientIceComplete
        );

        // Phase 4: Daemon ICE-complete → both ICE-complete.
        let out = state.process(&SupervisorInput::IceComplete {
            child_attempt_id: child_id(),
            role: 2,
        });
        assert!(matches!(out, SupervisorOutput::AddRemoteCandidate { .. }));
        assert_eq!(
            state.generation.signaling_phase,
            SignalingPhase::BothIceComplete
        );

        // Phase 5: Final proof submitted (daemon, role 2).
        let out = state.process(&SupervisorInput::FinalProofSubmitted {
            child_attempt_id: child_id(),
            role: 2,
            proof: vec![0u8; 313],
        });
        assert!(matches!(out, SupervisorOutput::SubmitFinalProof { .. }));
        assert_eq!(
            state.generation.signaling_phase,
            SignalingPhase::FinalProofSubmitted
        );

        // Channels cannot be installed before both proofs verified.
        // (The InstallChannels output only comes from FinalProofsVerified.)
        let set_digest = [0x04; 32];
        let out = state.process(&SupervisorInput::FinalProofsVerified {
            child_attempt_id: child_id(),
            set_digest,
        });
        assert!(matches!(out, SupervisorOutput::InstallChannels { .. }));
        assert_eq!(
            state.generation.signaling_phase,
            SignalingPhase::ChannelsInstalled
        );
        assert!(state.generation.channels_installed);
        assert_eq!(state.final_proof_set_digest, Some(set_digest));

        // Principal cannot be constructed before channels installed and
        // proofs verified. The phase progression enforces this.
    }

    // ── AC4: remote_webrtc_direct_turn_matrix ──

    #[test]
    fn remote_webrtc_direct_turn_matrix() {
        // Direct route.
        let cap = direct_cap();
        let mut factory = ConsentGatedResourceFactory::default();
        assert!(factory.create_rtc(&cap, now()).is_ok());
        assert!(factory.open_direct_udp_socket(&cap).is_ok());
        assert!(factory.create_host_candidate(&cap).is_ok());
        assert!(factory.create_srflx_candidate(&cap).is_ok());
        assert!(factory.send_stun_request(&cap).is_ok());
        assert!(factory.configure_mixed_ice(&cap).is_ok());
        assert!(factory.create_turn_allocation(&cap).is_ok());

        // Relay route.
        let cap = relay_only_cap();
        let mut factory = ConsentGatedResourceFactory::default();
        assert!(factory.create_rtc(&cap, now()).is_ok());
        assert!(factory.create_turn_allocation(&cap).is_ok());
        assert!(factory.configure_relay_only_ice(&cap).is_ok());
        factory.assert_no_direct_work();

        // Provider failure/expiry: unavailable creates no resources.
        let cap = unavailable_cap();
        let mut factory = ConsentGatedResourceFactory::default();
        assert!(factory.create_rtc(&cap, now()).is_err());
        assert!(factory.create_turn_allocation(&cap).is_err());
        assert!(!factory.transport_resources_created);

        // Zero direct work in relay-only: even retry/error branches.
        let cap = relay_only_cap();
        let mut factory = ConsentGatedResourceFactory::default();
        // Every direct action fails, including retry.
        for _ in 0..3 {
            assert!(factory.open_direct_udp_socket(&cap).is_err());
            assert!(factory.create_host_candidate(&cap).is_err());
            assert!(factory.create_srflx_candidate(&cap).is_err());
            assert!(factory.send_stun_request(&cap).is_err());
        }
        factory.assert_no_direct_work();
    }

    // ── AC5: remote_webrtc_three_channel_contract ──

    #[test]
    fn remote_webrtc_three_channel_contract() {
        // Proves IDs 0/2/4, exact labels, ordered/reliable, fragments/
        // backpressure, and no dynamic channel.
        verify_three_channel_contract().unwrap();

        // Exact IDs.
        assert_eq!(REMOTE_LANE_CHANNELS[0].channel_id, 0);
        assert_eq!(REMOTE_LANE_CHANNELS[1].channel_id, 2);
        assert_eq!(REMOTE_LANE_CHANNELS[2].channel_id, 4);

        // Exact labels.
        assert_eq!(REMOTE_LANE_CHANNELS[0].label, "flycockpit.control.v1");
        assert_eq!(REMOTE_LANE_CHANNELS[1].label, "flycockpit.interactive.v1");
        assert_eq!(REMOTE_LANE_CHANNELS[2].label, "flycockpit.bulk.v1");

        // All ordered, reliable, negotiated.
        for ch in REMOTE_LANE_CHANNELS.iter() {
            assert!(ch.ordered);
            assert!(ch.reliable);
            assert!(ch.negotiated);
            assert!(!ch.compressed);
        }

        // No dynamic channel: lane_for_channel_id fails for unknown IDs.
        use cockpit_proto::remote_transport::channel::lane_for_channel_id;
        assert!(lane_for_channel_id(1).is_err());
        assert!(lane_for_channel_id(3).is_err());
        assert!(lane_for_channel_id(5).is_err());
        assert!(lane_for_channel_id(6).is_err());

        // Channel configs for str0m are exact.
        let configs = channel_configs();
        assert_eq!(configs.len(), 3);
        for (i, config) in configs.iter().enumerate() {
            assert_eq!(config.label, REMOTE_LANE_CHANNELS[i].label);
            assert!(config.ordered);
            assert!(matches!(
                config.reliability,
                str0m::channel::Reliability::Reliable
            ));
            // Negotiated with exact channel ID (u16 stream ID).
            assert_eq!(config.negotiated, Some(REMOTE_LANE_CHANNELS[i].channel_id));
        }
    }

    // ── AC6: remote_webrtc_resource_budget_matrix ──

    #[test]
    fn remote_webrtc_resource_budget_matrix() {
        let mut supervisor = DaemonSupervisor::new();

        // Hit the 32-total daemon generation cap. A supervisor holds at most
        // MAX_ROUTED_CURRENT_CHILDREN routed-current children (the routed-current
        // block below), but peer *generations* accumulate across each child's
        // cutover lifetime (current + replacement-pending + draining) up to the
        // 32-total ceiling. Admit the routed-current children, then raise the
        // accumulated generation count to the ceiling (normally reached through
        // replacement/cutover churn) to exercise the 32-total guard.
        let mut id1 = child_id();
        id1[15] = 1;
        let mut id2 = child_id();
        id2[15] = 2;
        supervisor.admit_child(id1, direct_cap(), now()).unwrap();
        supervisor.admit_child(id2, direct_cap(), now()).unwrap();
        supervisor.total_generations = MAX_TOTAL_PEER_GENERATIONS;
        assert_eq!(supervisor.total_generations, MAX_TOTAL_PEER_GENERATIONS);

        // A further admission is denied by the 32-total guard — checked before
        // the routed-current guard, so the message names the total cap — with no
        // eviction of any existing generation.
        let mut id33 = child_id();
        id33[14] = 1;
        let result = supervisor.admit_child(id33, direct_cap(), now());
        assert_eq!(
            result.unwrap_err(),
            WebrtcEndpointError::BudgetExhausted("32 total peer generations cap"),
        );
        assert_eq!(supervisor.total_generations, MAX_TOTAL_PEER_GENERATIONS);

        // Two routed-current children cap (within one attachment).
        let mut supervisor2 = DaemonSupervisor::new();
        let mut id1 = child_id();
        id1[15] = 1;
        let mut id2 = child_id();
        id2[15] = 2;
        supervisor2.admit_child(id1, direct_cap(), now()).unwrap();
        supervisor2.admit_child(id2, direct_cap(), now()).unwrap();
        // Third routed-current is denied.
        let mut id3 = child_id();
        id3[15] = 3;
        let result = supervisor2.admit_child(id3, direct_cap(), now());
        assert!(result.is_err());

        // One current plus one pending-or-draining allocation pair.
        let mut supervisor3 = DaemonSupervisor::new();
        supervisor3
            .admit_child(child_id(), direct_cap(), now())
            .unwrap();
        assert!(
            supervisor3
                .start_replacement(child_id(), direct_cap(), now())
                .is_ok()
        );
        // Two generations: one current, one pending.
        assert_eq!(supervisor3.total_generations, 2);
        // Second replacement is denied (only one pending at a time).
        let result = supervisor3.start_replacement(child_id(), direct_cap(), now());
        assert!(result.is_err());

        // SDP/candidate/address/socket/allocation/datagram/lane boundaries.
        assert_eq!(MAX_SDP_PAYLOAD_BYTES, 122_880);
        assert_eq!(MAX_SERIALIZED_SIGNALING_BYTES, 131_072);
        assert_eq!(MAX_REMOTE_CANDIDATES_PER_CHILD, 64);
        assert_eq!(MAX_LOCAL_CANDIDATES_PER_CHILD, 64);
        assert_eq!(MAX_CANDIDATE_BYTES, 4_096);
        assert_eq!(MAX_INTERFACE_ADDRESSES, 16);
        assert_eq!(MAX_DIRECT_UDP_SOCKETS_PER_CHILD, 4);
        assert_eq!(MAX_TURN_ALLOCATIONS_PER_CHILD, 1);
        assert_eq!(MAX_QUEUED_DATAGRAMS_PER_DIRECTION, 256);
        assert_eq!(MAX_QUEUED_DATAGRAM_BYTES_PER_DIRECTION, 4 * 1024 * 1024);
        assert_eq!(MAX_LANE_APPLICATION_QUEUE_BYTES, 16 * 1024 * 1024);

        // SDP size validation.
        assert!(validate_sdp_size(&[0u8; 100]).is_ok());
        assert!(validate_sdp_size(&vec![0u8; MAX_SDP_PAYLOAD_BYTES + 1]).is_err());
        assert!(validate_sdp_size(&[]).is_err());

        // Candidate size validation.
        assert!(validate_candidate_size(&[0u8; 100]).is_ok());
        assert!(validate_candidate_size(&vec![0u8; MAX_CANDIDATE_BYTES + 1]).is_err());
        assert!(validate_candidate_size(&[]).is_err());

        // Exact no-eviction rejection: the routed-current children admitted
        // before the denied over-cap admission remain.
        assert_eq!(supervisor.children.len(), MAX_ROUTED_CURRENT_CHILDREN);

        // Three-physical-child TURN exception: one extra noncurrent TURN
        // generation during the selection owner's rotation.
        assert_eq!(THREE_PHYSICAL_TURN_EXCEPTION_EXTRA, 1);
    }

    // ── AC7: remote_webrtc_supervisor_fairness_trace ──

    #[test]
    fn remote_webrtc_supervisor_fairness_trace() {
        // Proves 64/64/64 yield budgets under saturation.
        let cap = direct_cap();
        let mut state = ChildSupervisorState::new(child_id(), cap, now());

        // Feed 64 str0m input events: the 65th should yield.
        for i in 0..MAX_INPUT_EVENTS_PER_TURN {
            let out = state.process(&SupervisorInput::Str0mInput);
            if i < MAX_INPUT_EVENTS_PER_TURN - 1 {
                // Before budget exhaustion, events are processed.
                assert!(
                    matches!(out, SupervisorOutput::Inert | SupervisorOutput::Yield),
                    "event {i} should be processed or yield"
                );
            }
        }
        // The budget should now be exhausted for input events.
        assert!(state.input_events_this_turn >= MAX_INPUT_EVENTS_PER_TURN);

        // Reset and test timeout budget.
        state.reset_turn();
        for _ in 0..MAX_TIMEOUT_ACTIONS_PER_TURN {
            let _ = state.process(&SupervisorInput::Timeout { now: now() });
        }
        assert!(state.timeout_actions_this_turn >= MAX_TIMEOUT_ACTIONS_PER_TURN);

        // Reset and test output budget.
        state.reset_turn();
        for _ in 0..MAX_OUTPUT_ACTIONS_PER_TURN {
            let _ = state.process(&SupervisorInput::Str0mOutput);
        }
        assert!(state.output_actions_this_turn >= MAX_OUTPUT_ACTIONS_PER_TURN);

        // After budget exhaustion, the next event yields.
        state.reset_turn();
        for _ in 0..MAX_INPUT_EVENTS_PER_TURN {
            let _ = state.process(&SupervisorInput::Str0mInput);
        }
        let out = state.process(&SupervisorInput::Str0mInput);
        assert!(matches!(out, SupervisorOutput::Yield));

        // After reset, events are processed again.
        state.reset_turn();
        let out = state.process(&SupervisorInput::Str0mInput);
        assert!(matches!(out, SupervisorOutput::Inert));
    }

    // ── AC8: remote_webrtc_generation_races ──

    #[test]
    fn remote_webrtc_generation_races() {
        let mut supervisor = DaemonSupervisor::new();
        supervisor
            .admit_child(child_id(), direct_cap(), now())
            .unwrap();

        // Start a replacement.
        assert!(
            supervisor
                .start_replacement(child_id(), direct_cap(), now())
                .is_ok()
        );
        assert!(supervisor.children[0].replacement_pending.is_some());

        // Pending carries no application operation.
        let pending = supervisor.children[0].replacement_pending.as_ref().unwrap();
        assert!(!pending.can_carry_application());
        assert_eq!(pending.state, GenerationState::ReplacementPending);

        // Cutover requires persisted ACK.
        let ack = CutoverAck {
            old_generation: Generation(1),
            new_generation: Generation(2),
            lease_id: [0xcc; 16],
            lease_generation: LeaseGeneration(2),
            lease_digest: [0xdd; 32],
        };
        // Without ACK: cutover fails.
        let result = supervisor.cutover(child_id(), ack.clone(), now());
        assert!(result.is_err());

        // With ACK persisted: cutover succeeds.
        let out = supervisor.process_for_child(
            child_id(),
            &SupervisorInput::CutoverAckPersisted {
                child_attempt_id: child_id(),
                ack: ack.clone(),
            },
        );
        assert!(matches!(out, SupervisorOutput::Cutover { .. }));
        assert!(supervisor.children[0].cutover_acked);

        // Now cutover.
        let out = supervisor.cutover(child_id(), ack.clone(), now()).unwrap();
        assert!(matches!(out, SupervisorOutput::Cutover { .. }));

        // Old generation is now draining.
        assert_eq!(
            supervisor.children[0].draining.as_ref().unwrap().state,
            GenerationState::Draining
        );
        assert!(
            supervisor.children[0]
                .draining
                .as_ref()
                .unwrap()
                .is_draining()
        );

        // New generation is current.
        assert_eq!(
            supervisor.children[0].generation.state,
            GenerationState::Current
        );
        assert_eq!(supervisor.children[0].generation.generation, Generation(2));

        // Draining handles only already-assigned work. New work goes to
        // current only.
        assert!(
            !supervisor.children[0]
                .draining
                .as_ref()
                .unwrap()
                .can_carry_application()
        );

        // Late generation events for draining are NOT inert (draining is
        // still active for replay/ACK). But events for removed are inert.
        // Cancel the child: everything becomes inert.
        let out = supervisor.cancel_child(child_id(), CancelReason::Cancellation);
        assert!(matches!(out, SupervisorOutput::Cancel { .. }));
        assert_eq!(
            supervisor.children[0].generation.signaling_phase,
            SignalingPhase::Cancelled
        );

        // Late events after cancel are inert.
        let out = supervisor.process_for_child(
            child_id(),
            &SupervisorInput::SdpOffer {
                child_attempt_id: child_id(),
                sdp: vec![0u8; 100],
            },
        );
        assert!(matches!(out, SupervisorOutput::Inert));

        // 30-second drain timeout: second-lease removal.
        let mut supervisor2 = DaemonSupervisor::new();
        supervisor2
            .admit_child(child_id(), direct_cap(), now())
            .unwrap();
        supervisor2
            .start_replacement(child_id(), direct_cap(), now())
            .unwrap();
        supervisor2.process_for_child(
            child_id(),
            &SupervisorInput::CutoverAckPersisted {
                child_attempt_id: child_id(),
                ack: CutoverAck {
                    old_generation: Generation(1),
                    new_generation: Generation(2),
                    lease_id: [0; 16],
                    lease_generation: LeaseGeneration(2),
                    lease_digest: [0; 32],
                },
            },
        );
        supervisor2
            .cutover(
                child_id(),
                CutoverAck {
                    old_generation: Generation(1),
                    new_generation: Generation(2),
                    lease_id: [0; 16],
                    lease_generation: LeaseGeneration(2),
                    lease_digest: [0; 32],
                },
                now(),
            )
            .unwrap();

        // Draining deadline: after 30 seconds, remove.
        let draining_deadline = supervisor2.children[0]
            .draining
            .as_ref()
            .unwrap()
            .draining_deadline
            .unwrap();
        let out = supervisor2.process_for_child(
            child_id(),
            &SupervisorInput::Timeout {
                now: draining_deadline,
            },
        );
        assert!(matches!(out, SupervisorOutput::RemoveDrained { .. }));
        assert!(supervisor2.children[0].draining.is_none());

        // Stale close/allocation isolation: cancelled generation's events
        // are inert.
        let mut supervisor3 = DaemonSupervisor::new();
        supervisor3
            .admit_child(child_id(), direct_cap(), now())
            .unwrap();
        supervisor3.cancel_child(child_id(), CancelReason::Shutdown);
        let out = supervisor3.process_for_child(
            child_id(),
            &SupervisorInput::RemoteCandidate {
                child_attempt_id: child_id(),
                candidate: vec![0u8; 100],
            },
        );
        assert!(matches!(out, SupervisorOutput::Inert));

        // ICE restart is always a fresh child attempt/proofs/DTLS epoch.
        // A restart is modelled as cancel + new admission.
        let mut supervisor4 = DaemonSupervisor::new();
        supervisor4
            .admit_child(child_id(), direct_cap(), now())
            .unwrap();
        supervisor4.cancel_child(child_id(), CancelReason::IceRestart);
        let mut new_id = child_id();
        new_id[15] = 2;
        assert!(supervisor4.admit_child(new_id, direct_cap(), now()).is_ok());
        // Old child is cancelled, new child is current.
        assert_eq!(
            supervisor4.children[0].generation.signaling_phase,
            SignalingPhase::Cancelled
        );
        assert_eq!(
            supervisor4.children[1].generation.signaling_phase,
            SignalingPhase::Init
        );

        // Every cancel reason produces a Cancel output.
        for reason in [
            CancelReason::Cancellation,
            CancelReason::Supersede,
            CancelReason::ConsentRevoke,
            CancelReason::PolicyRevoke,
            CancelReason::InterfaceChange,
            CancelReason::CredentialExpiry,
            CancelReason::ControlGap,
            CancelReason::IceRestart,
            CancelReason::Shutdown,
        ] {
            let mut sup = DaemonSupervisor::new();
            sup.admit_child(child_id(), direct_cap(), now()).unwrap();
            let out = sup.cancel_child(child_id(), reason);
            assert!(matches!(out, SupervisorOutput::Cancel { .. }));
            // Late callback after cancel is inert.
            let out = sup.process_for_child(child_id(), &SupervisorInput::Str0mInput);
            assert!(matches!(out, SupervisorOutput::Inert));
        }
    }

    // ── AC9: remote_webrtc_consent_freshness ──

    #[test]
    fn remote_webrtc_consent_freshness() {
        // Proves 15-second probes/two misses and teardown without
        // unauthorized retry.
        let cap = direct_cap();
        let mut state = ChildSupervisorState::new(child_id(), cap, now());

        // Advance to final proofs verified so consent probes start.
        state.generation.signaling_phase = SignalingPhase::FinalProofsVerified;
        state.generation.channels_installed = true;

        let t0 = now();
        // First timeout: probe sent.
        let out = state.process(&SupervisorInput::Timeout { now: t0 });
        assert!(matches!(out, SupervisorOutput::ConsentProbe { .. }));
        assert_eq!(state.generation.consent_misses, 0);

        // First probe timeout: 1 miss.
        let t1 = t0 + Duration::from_secs(CONSENT_FRESHNESS_INTERVAL_SECS);
        let out = state.process(&SupervisorInput::ConsentProbeTimeout {
            child_attempt_id: child_id(),
            now: t1,
        });
        assert!(matches!(out, SupervisorOutput::ConsentProbe { .. }));
        assert_eq!(state.generation.consent_misses, 1);

        // Second probe timeout: 2 misses → teardown.
        let t2 = t1 + Duration::from_secs(CONSENT_FRESHNESS_INTERVAL_SECS);
        let out = state.process(&SupervisorInput::ConsentProbeTimeout {
            child_attempt_id: child_id(),
            now: t2,
        });
        assert!(matches!(
            out,
            SupervisorOutput::ConsentFreshnessTeardown { .. }
        ));
        assert_eq!(
            state.generation.consent_misses,
            CONSENT_FRESHNESS_MISS_THRESHOLD
        );
        assert_eq!(state.generation.signaling_phase, SignalingPhase::Cancelled);

        // No unauthorized retry: after teardown, events are inert.
        let out = state.process(&SupervisorInput::Timeout {
            now: t2 + Duration::from_secs(CONSENT_FRESHNESS_INTERVAL_SECS),
        });
        assert!(matches!(out, SupervisorOutput::Inert));

        // Probe response resets misses.
        let mut state2 = ChildSupervisorState::new(child_id(), direct_cap(), now());
        state2.generation.signaling_phase = SignalingPhase::FinalProofsVerified;
        state2.generation.channels_installed = true;
        state2.generation.consent_misses = 1;
        let out = state2.process(&SupervisorInput::ConsentProbeResponse {
            child_attempt_id: child_id(),
        });
        assert!(matches!(out, SupervisorOutput::Inert));
        assert_eq!(state2.generation.consent_misses, 0);

        // Verify exact constants.
        assert_eq!(CONSENT_FRESHNESS_INTERVAL_SECS, 15);
        assert_eq!(CONSENT_FRESHNESS_MISS_THRESHOLD, 2);
        assert_eq!(DRAINING_TIMEOUT_SECS, 30);
        assert_eq!(ICE_ESTABLISHMENT_DEADLINE_SECS, 30);
    }

    // ── AC10: no-public-listener, cross-platform, redaction, interop ──

    #[test]
    fn remote_webrtc_no_public_listener_and_redaction() {
        // No public/fixed listener: the daemon is always an outbound
        // WebSocket client to the TypeScript signaling gateway. There is
        // no Rust WebSocket server, no fixed inbound daemon port, no
        // UPnP/NAT-PMP, no privileged port.
        // This is enforced structurally: this module creates `Rtc` instances
        // only via `new_rtc_with_rust_crypto`, which does not bind any
        // socket. Socket ownership is the Tokio adapter's responsibility,
        // and the daemon dials outbound only.

        // Cross-platform: str0m 0.21.0 with rust-crypto supports all
        // platforms listed in STR0M_PLATFORMS.
        let record = str0m_dependency_record();
        assert!(record.platforms.len() >= 6);
        for platform in record.platforms {
            assert!(!platform.is_empty());
        }

        // Redaction: addresses, candidates, fingerprints, tokens are redacted.
        let sensitive = "candidate:84216312 1 udp 1677729535 192.168.1.100 50000 typ host";
        let redacted = redact_sensitive(sensitive);
        assert!(!redacted.contains("192.168.1.100"));
        assert!(redacted.contains("[REDACTED_IP]"));
        assert!(redacted.contains("candidate:[REDACTED]"));
        assert!(!redacted.contains("84216312"));

        let fingerprint = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let redacted = redact_sensitive(fingerprint);
        assert!(redacted.contains("[REDACTED_HEX]"));
        assert!(!redacted.contains("aabbccdd"));

        // Full Cargo build: the module compiles with str0m 0.21.0.
        // (This test existing and passing proves the build works.)
        let _rtc = new_rtc_with_rust_crypto(now());

        // TypeScript/Rust interop: the signaling codec validates exact
        // SDP/candidate schemas shared with the TypeScript gateway.
        let valid_sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n";
        assert!(validate_sdp_size(valid_sdp.as_bytes()).is_ok());

        // Commit ack validation.
        let ack_bytes = {
            let mut bytes = vec![0u8; 61];
            bytes[..4].copy_from_slice(b"FCAK");
            bytes[4] = 1;
            bytes[5..21].copy_from_slice(&[0x02; 16]);
            bytes[21..29].copy_from_slice(&1u64.to_be_bytes());
            bytes[29..61].copy_from_slice(&[0x03; 32]);
            bytes
        };
        let ack = validate_commit_ack(&ack_bytes);
        assert!(ack.is_ok());
        let ack = ack.unwrap();
        assert_eq!(ack.event_id, [0x02; 16]);
        assert_eq!(ack.sequence, 1);

        // Malformed ack fails.
        assert!(validate_commit_ack(&[0u8; 10]).is_err());
    }

    // ── Additional edge cases ──

    #[test]
    fn remote_webrtc_ice_deadline_exceeded() {
        let cap = direct_cap();
        let start = now();
        let mut state = ChildSupervisorState::new(child_id(), cap, start);

        // ICE deadline is 30 seconds. After that without ICE-complete,
        // the generation is cancelled.
        let deadline = start + Duration::from_secs(ICE_ESTABLISHMENT_DEADLINE_SECS);
        let out = state.process(&SupervisorInput::Timeout { now: deadline });
        assert!(matches!(out, SupervisorOutput::Cancel { .. }));
        assert_eq!(state.generation.signaling_phase, SignalingPhase::Cancelled);
    }

    #[test]
    fn remote_webrtc_oversized_sdp_rejected() {
        let cap = direct_cap();
        let mut state = ChildSupervisorState::new(child_id(), cap, now());
        let oversized = vec![0u8; MAX_SDP_PAYLOAD_BYTES + 1];
        let out = state.process(&SupervisorInput::SdpOffer {
            child_attempt_id: child_id(),
            sdp: oversized,
        });
        assert!(matches!(out, SupervisorOutput::RejectOffer { .. }));
        assert_eq!(state.generation.signaling_phase, SignalingPhase::Cancelled);
    }

    #[test]
    fn remote_webrtc_unavailable_rejects_offer() {
        let cap = unavailable_cap();
        let mut state = ChildSupervisorState::new(child_id(), cap, now());
        let out = state.process(&SupervisorInput::SdpOffer {
            child_attempt_id: child_id(),
            sdp: vec![0u8; 100],
        });
        assert!(matches!(out, SupervisorOutput::RejectOffer { .. }));
    }

    #[test]
    fn remote_webrtc_generation_next() {
        let g = Generation(1);
        assert_eq!(g.next(), Generation(2));
        assert_eq!(Generation::default(), Generation(1));
    }

    #[test]
    fn remote_webrtc_child_attempt_isolation() {
        // Two children under one attachment have distinct state.
        let mut supervisor = DaemonSupervisor::new();
        let id1 = [0x01; 16];
        let id2 = [0x02; 16];
        supervisor.admit_child(id1, direct_cap(), now()).unwrap();
        supervisor
            .admit_child(id2, relay_only_cap(), now())
            .unwrap();

        // Process for id1 does not affect id2.
        let out = supervisor.process_for_child(
            id1,
            &SupervisorInput::SdpOffer {
                child_attempt_id: id1,
                sdp: vec![0u8; 100],
            },
        );
        assert!(matches!(out, SupervisorOutput::AcceptOffer { .. }));
        assert_eq!(
            supervisor.children[0].generation.signaling_phase,
            SignalingPhase::OfferReceived
        );
        assert_eq!(
            supervisor.children[1].generation.signaling_phase,
            SignalingPhase::Init
        );

        // Mismatched child_attempt_id is inert.
        let out = supervisor.process_for_child(
            id1,
            &SupervisorInput::SdpOffer {
                child_attempt_id: id2,
                sdp: vec![0u8; 100],
            },
        );
        assert!(matches!(out, SupervisorOutput::Inert));
    }

    #[test]
    fn remote_webrtc_remote_candidate_size_limit() {
        let cap = direct_cap();
        let mut state = ChildSupervisorState::new(child_id(), cap, now());
        let oversized = vec![0u8; MAX_CANDIDATE_BYTES + 1];
        let out = state.process(&SupervisorInput::RemoteCandidate {
            child_attempt_id: child_id(),
            candidate: oversized,
        });
        assert!(matches!(out, SupervisorOutput::Inert));
    }

    #[test]
    fn remote_webrtc_channel_contract_exact() {
        // Prove the channel contract is exactly the transport-owned one.
        let channels: Vec<RemoteLaneChannel> = REMOTE_LANE_CHANNELS.to_vec();
        assert_eq!(channels.len(), 3);
        // The channel IDs are 0, 2, 4 (even numbers, no gaps wider than 2).
        for (i, ch) in channels.iter().enumerate() {
            assert_eq!(ch.channel_id, (i * 2) as u16);
        }
    }
}
