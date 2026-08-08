//! The containment barrier the write-scope coordinator depends on.
//!
//! This is a narrow injectable seam over the `cross-platform-descendant-process-containment`
//! prerequisite. Platform mechanics (cgroups, job objects, Docker, Podman) stay
//! owned by that prompt; here we only need the four operations the authority
//! barrier orders itself around, so tests can drive every interleaving without
//! timing sleeps.

use async_trait::async_trait;
use uuid::Uuid;

use super::backend::ExecutionMode;
use super::coordinator::{OwnershipRecorded, OwnershipReserved};
use super::types::WriteScopeError;

/// Per-execution launch parameters.
///
/// These are properties of *one child*, not of the daemon, so they belong on
/// the `create` call rather than on the barrier's constructor. Putting them on
/// the constructor would make a daemon-lifetime barrier impossible, and the
/// barrier must be daemon-lifetime because `recover` and the shutdown drain are
/// daemon-global.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionLaunch {
    /// Native host process.
    Native {
        program: std::path::PathBuf,
        args: Vec<String>,
        cwd: std::path::PathBuf,
    },
    /// Fresh container per generation (zerobox / Docker / Podman).
    Container {
        image: String,
        command: Vec<String>,
        installation_id: String,
        nonce: String,
    },
}

/// A created containment generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainmentTicket {
    pub containment_id: Uuid,
    pub generation: u64,
}

/// Outcome of awaiting the descendant set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenEmptyOutcome {
    /// Same-generation oracle proved the group empty. Only this permits
    /// releasing the execution-wide permit and restoring parent authority.
    ProvenEmpty { generation: u64 },
    /// Ambiguous. Authority stays with the child and the row is retained.
    Uncertain { generation: u64, reason: String },
    /// The platform cannot prove containment at all.
    Unsupported { reason: String },
}

impl ProvenEmptyOutcome {
    pub fn is_proven_empty(&self) -> bool {
        matches!(self, Self::ProvenEmpty { .. })
    }
}

/// The barrier operations the authority coordinator orders around.
#[async_trait]
pub trait ContainmentBarrier: Send + Sync {
    /// Create containment for a delegated execution. Must happen before any
    /// user code exists.
    ///
    /// Takes ONLY an [`OwnershipReserved`] for its identity, which is
    /// unforgeable outside `coordinator` and is minted solely from the durable
    /// `prepared` transfer row. This is the first link of the witness chain,
    /// and it exists because `create` is the moment a *writing process* comes
    /// into being: gating it on [`OwnershipRecorded`] is impossible, since that
    /// witness carries the containment id this call has not yet returned.
    ///
    /// The session and the containment `operation_id` both come from the
    /// witness rather than from free-form parameters, so neither can disagree
    /// with the durable record — and because the operation id is *derived* from
    /// the transfer id, recovery can find a containment this call created even
    /// if the crash landed before its ticket was attached.
    async fn create(
        &self,
        reserved: &OwnershipReserved,
        mode: ExecutionMode,
        launch: &ExecutionLaunch,
    ) -> Result<ContainmentTicket, WriteScopeError>;

    /// Prove membership / runtime ownership, then release user code. Separated
    /// from `create` so a test can fail exactly here and assert the unwind
    /// ordering.
    ///
    /// Takes ONLY an [`OwnershipRecorded`], which is unforgeable outside
    /// `coordinator` and is minted solely from the row returned by the persist.
    /// It also carries the containment it attests, so a witness for one
    /// transfer cannot be used to release another — there is no separate ticket
    /// argument that could disagree with it.
    async fn prove_membership_and_release_user_code(
        &self,
        recorded: &OwnershipRecorded,
    ) -> Result<(), WriteScopeError>;

    /// Await the same-generation empty oracle.
    async fn await_proven_empty(&self, ticket: &ContainmentTicket) -> ProvenEmptyOutcome;

    /// Idempotent terminate, used by cancellation and the deletion/shutdown
    /// barriers.
    async fn terminate(&self, ticket: &ContainmentTicket) -> Result<(), WriteScopeError>;
}

/// Production adapter over the daemon's `ProcessContainmentActor`.
///
/// Kept thin on purpose: it maps the prerequisite's typed results onto the
/// authority barrier's vocabulary and adds no policy.
pub struct ProcessContainmentBarrier {
    handle: crate::process_containment::ProcessContainmentHandle,
    leases: std::sync::Mutex<
        std::collections::HashMap<Uuid, crate::process_containment::ContainmentLease>,
    >,
}

impl ProcessContainmentBarrier {
    /// Daemon-lifetime: it holds only the actor handle. Per-child launch
    /// parameters arrive with each `create` call.
    pub fn new(handle: crate::process_containment::ProcessContainmentHandle) -> Self {
        Self {
            handle,
            leases: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn take_lease(
        &self,
        containment_id: Uuid,
    ) -> Option<crate::process_containment::ContainmentLease> {
        self.leases.lock().ok()?.get(&containment_id).cloned()
    }
}

fn map_containment_error(err: crate::process_containment::ContainmentError) -> WriteScopeError {
    use crate::process_containment::ContainmentError as CE;
    match err {
        CE::SessionDeleting => WriteScopeError::SessionDeleting,
        CE::ShutdownIntakeClosed => WriteScopeError::ShutdownIntakeClosed,
        CE::DescendantContainmentUnavailable { reason } => WriteScopeError::unsupported(format!(
            "descendant process containment unavailable: {reason}"
        )),
        other => WriteScopeError::Internal(other.to_string()),
    }
}

#[async_trait]
impl ContainmentBarrier for ProcessContainmentBarrier {
    async fn create(
        &self,
        reserved: &OwnershipReserved,
        _mode: ExecutionMode,
        launch: &ExecutionLaunch,
    ) -> Result<ContainmentTicket, WriteScopeError> {
        // Both derived from the witness, so neither can disagree with the
        // durable transfer row this containment belongs to.
        let session_id = reserved.session_id();
        let operation_id = reserved.containment_operation_id();
        // `require_proven` is always true: strict writable delegation may never
        // run user code under unproven containment.
        let lease = match launch {
            ExecutionLaunch::Native { program, args, cwd } => self
                .handle
                .create_and_spawn(
                    session_id,
                    operation_id.clone(),
                    program.clone(),
                    args.clone(),
                    cwd.clone(),
                    true,
                )
                .await
                .map_err(map_containment_error)?,
            ExecutionLaunch::Container {
                image,
                command,
                installation_id,
                nonce,
            } => self
                .handle
                .create_container_and_exec(
                    session_id,
                    operation_id.clone(),
                    image.clone(),
                    command.clone(),
                    installation_id.clone(),
                    nonce.clone(),
                    true,
                )
                .await
                .map_err(map_containment_error)?,
        };
        let ticket = ContainmentTicket {
            containment_id: lease.containment_id(),
            generation: lease.generation(),
        };
        if let Ok(mut leases) = self.leases.lock() {
            leases.insert(ticket.containment_id, lease);
        }
        Ok(ticket)
    }

    async fn prove_membership_and_release_user_code(
        &self,
        recorded: &OwnershipRecorded,
    ) -> Result<(), WriteScopeError> {
        // The containment comes from the witness itself, so it is by
        // construction the one whose ownership was just persisted.
        let containment_id = recorded.containment_id();
        let lease = self.take_lease(containment_id).ok_or_else(|| {
            WriteScopeError::Internal(format!("containment lease {containment_id} missing"))
        })?;
        if !lease.is_alive() {
            return Err(WriteScopeError::unsupported(
                "containment lease was invalidated before user code could be released",
            ));
        }
        if lease.guarantee() != crate::process_containment::ContainmentGuarantee::Proven {
            return Err(WriteScopeError::unsupported(
                "containment guarantee is not Proven; refusing to release user code",
            ));
        }
        Ok(())
    }

    async fn await_proven_empty(&self, ticket: &ContainmentTicket) -> ProvenEmptyOutcome {
        let Some(lease) = self.take_lease(ticket.containment_id) else {
            return ProvenEmptyOutcome::Uncertain {
                generation: ticket.generation,
                reason: "containment lease missing".into(),
            };
        };
        match self.handle.await_empty(lease).await {
            Ok(crate::process_containment::EmptyOutcome::ProvenEmpty { generation }) => {
                ProvenEmptyOutcome::ProvenEmpty { generation }
            }
            Ok(crate::process_containment::EmptyOutcome::Uncertain { generation, reason }) => {
                ProvenEmptyOutcome::Uncertain { generation, reason }
            }
            Ok(crate::process_containment::EmptyOutcome::Unsupported { reason }) => {
                ProvenEmptyOutcome::Unsupported { reason }
            }
            Err(err) => ProvenEmptyOutcome::Uncertain {
                generation: ticket.generation,
                reason: err.to_string(),
            },
        }
    }

    async fn terminate(&self, ticket: &ContainmentTicket) -> Result<(), WriteScopeError> {
        let Some(lease) = self.take_lease(ticket.containment_id) else {
            return Ok(());
        };
        self.handle
            .terminate(lease)
            .await
            .map_err(map_containment_error)
    }
}
