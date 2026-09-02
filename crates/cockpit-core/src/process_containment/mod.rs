//! Generation-bound descendant process containment.
//!
//! Provides a daemon-owned [`ProcessContainmentActor`] with durable
//! `execution_containments` rows. Callers receive a non-serializable
//! [`ContainmentLease`] and must spawn user code only into that lease's
//! process-tree guard when the adapter provides one. The adapter must not
//! run `req.program`. Durable `MembershipProven` is written only after
//! [`ProcessContainmentHandle::prove_membership`] observes kernel membership;
//! allocation is persisted as `PlatformAllocated`.
//!
//! ContainmentGuarantee is Proven or Unsupported only — no BestEffort.

mod actor;
mod adapter;
mod container;
mod fake;
mod linux;
mod macos;
mod observability;
mod state_machine;
mod types;
mod unix;
mod windows;

#[cfg(test)]
mod tests;

pub use actor::{
    CONTAINMENT_QUEUE_CAPACITY, ProcessContainmentActor, ProcessContainmentHandle,
    default_host_adapter,
};
pub use adapter::{
    AdapterHandle, AllocatedContainment, ContainerExecRequest, ContainmentAdapter,
    NativeSpawnRequest, SharedAdapter,
};
pub use container::{ContainerRuntimeAdapter, RuntimeKind};
pub use fake::{FakeEmptyMode, FakeProvenAdapter, FakeUnsupportedAdapter};
pub use linux::{
    LINUX_PROCESS_TREE_UNAVAILABLE_ON_HOST, LinuxCgroupAdapter, MANAGEMENT_BOUNDARY_UNAVAILABLE,
    PROCESS_GROUP_EMPTY_MEMBERSHIP_UNPROVEN,
};
pub use macos::{
    MACOS_PROCESS_TREE_UNAVAILABLE_ON_HOST, MACOS_UNSUPPORTED_REASON, MacosNativeAdapter,
};
pub use observability::{doctor_lines, error_audit_fields, sanitize_reason};
pub use types::{
    ContainmentError, ContainmentGuarantee, ContainmentLease, ContainmentState, EmptyOutcome,
    LateCallbackKind, PlatformKind, SafeContainmentMetadata, SafeLocator,
};
pub use windows::{
    WINDOWS_JOB_EMPTY_MEMBERSHIP_UNPROVEN, WINDOWS_JOB_UNAVAILABLE_ON_HOST, WindowsJobAdapter,
};
