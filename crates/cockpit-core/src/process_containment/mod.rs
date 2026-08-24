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
#[cfg(target_os = "linux")]
mod linux_broker;
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
    AdapterHandle, AllocatedContainment, AllocatedNativeIo, ContainerExecRequest,
    ContainmentAdapter, NativeChildIo, NativeIoSpawnRequest, NativeSpawnRequest, SharedAdapter,
};
pub(crate) use adapter::AllocationCancellation;
pub use container::{ContainerRuntimeAdapter, RuntimeKind};
pub use fake::{FakeEmptyMode, FakeProvenAdapter, FakeUnsupportedAdapter};
pub use linux::{
    CgroupNamespaceGuard, LinuxCgroupAdapter, MANAGEMENT_BOUNDARY_UNAVAILABLE, TestBroker,
};
#[cfg(target_os = "linux")]
pub use linux_broker::{
    LinuxBrokerConfig, LinuxBrokerServerConfig, doctor_linux_containment_broker,
    run_linux_containment_broker,
};
#[cfg(target_os = "linux")]
pub fn inherited_linux_broker_capability_fd() -> Option<std::os::fd::RawFd> {
    linux_broker::inherited_named_fd("flycockpit-containment-capability")
}
pub use macos::{MACOS_UNSUPPORTED_REASON, MacosNativeAdapter};
pub use observability::{doctor_lines, error_audit_fields, sanitize_reason};
pub use types::{
    ContainmentError, ContainmentGuarantee, ContainmentLease, ContainmentState, EmptyOutcome,
    LateCallbackKind, PlatformKind, SafeContainmentMetadata, SafeLocator,
};
pub use windows::WindowsJobAdapter;
