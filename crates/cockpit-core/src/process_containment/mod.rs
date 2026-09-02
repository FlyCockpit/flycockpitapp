//! Generation-bound descendant process containment.
//!
//! Provides a daemon-owned [`ProcessContainmentActor`] with durable
//! `execution_containments` rows. Callers receive a non-serializable
//! [`ContainmentLease`] and must not spawn user code outside this actor.
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
    CgroupNamespaceGuard, LinuxCgroupAdapter, MANAGEMENT_BOUNDARY_UNAVAILABLE, TestBroker,
};
pub use macos::{MACOS_UNSUPPORTED_REASON, MacosNativeAdapter};
pub use observability::{doctor_lines, error_audit_fields, sanitize_reason};
pub use types::{
    ContainmentError, ContainmentGuarantee, ContainmentLease, ContainmentState, EmptyOutcome,
    LateCallbackKind, PlatformKind, SafeContainmentMetadata, SafeLocator,
};
pub use windows::{WINDOWS_JOB_UNAVAILABLE_ON_HOST, WindowsJobAdapter};
