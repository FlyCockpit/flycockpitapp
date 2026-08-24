//! Remote-only session queue operation identities and durable receipts.

use crate::daemon::proto;

#[derive(Debug, Clone)]
pub struct RemoteQueueOperation {
    pub logical_attachment_id: String,
    pub operation_id: String,
    pub authenticated_device_id: String,
    pub authenticated_device_generation: u64,
    pub request_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteQueueMutationReceiptV1 {
    pub schema_version: u8,
    pub applied: bool,
    pub reason: proto::RemoveQueuedUserMessageReason,
    pub removed_count: u32,
}

impl RemoteQueueMutationReceiptV1 {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.schema_version == 1, "unsupported queue receipt schema");
        anyhow::ensure!(self.removed_count <= 10_000, "queue receipt removed_count exceeds bound");
        let removed = matches!(self.reason, proto::RemoveQueuedUserMessageReason::Removed);
        anyhow::ensure!(self.applied == removed, "queue receipt applied/reason mismatch");
        anyhow::ensure!(removed == (self.removed_count > 0), "queue receipt count mismatch");
        Ok(())
    }
}

#[derive(Debug)]
pub enum RemoteSendDecision {
    Accepted,
    Replayed,
    Rejected(proto::ErrorPayload),
}

pub(crate) async fn reserve_remote_send_operation(
    db: &crate::db::Db,
    remote: &RemoteQueueOperation,
) -> RemoteSendDecision {
    super::run::reserve_remote_send_operation_impl(db, remote).await
}
