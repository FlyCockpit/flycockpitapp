//! Transport-neutral staged bulk-transfer contract.
//!
//! Local import/export and oversized-message RPCs use this module directly.
//! The remote logical-lane codec consumes the same contract through its
//! compatibility exports; bulk staging is not itself a remote capability.

pub use crate::remote_protocol_id::RemoteTransferId as BulkTransferId;
pub use crate::remote_transport::bulk::{
    MAX_BULK_CHUNK_PAYLOAD_BYTES, MAX_TRANSFER_BYTES,
    RemoteBulkMimeClass as BulkMimeClass, RemoteBulkTransferRef as BulkTransferRef,
};

/// Construct a nonzero opaque transfer identity without exposing the remote
/// protocol-id namespace to local import/export clients.
pub fn transfer_id_from_bytes(bytes: [u8; 16]) -> Result<BulkTransferId, String> {
    crate::remote_protocol_id::tag_protocol_id_bytes::<crate::remote_protocol_id::kind::Transfer>(
        bytes,
    )
    .map_err(|error| error.to_string())
}
