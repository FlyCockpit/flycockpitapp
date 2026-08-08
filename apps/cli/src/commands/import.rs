use anyhow::{Context, Result};
use base64::Engine;

use crate::daemon::client::DaemonClient;
use crate::daemon::proto::{Request, Response};
use crate::daemon::{DaemonStatus, discover};

use crate::cli::ImportArgs;
use crate::db::Db;

/// Push an archive into daemon-side bulk staging and return its reference.
///
/// Chunks are contiguous and each body stays inside the advertised chunk bound,
/// so no single frame can starve the control lane. The daemon verifies the
/// declared length and SHA-256 before the import runs.
async fn push_bulk_transfer(
    client: &DaemonClient,
    bytes: &[u8],
) -> Result<cockpit_core::daemon::proto::remote_transport::bulk::RemoteBulkTransferRef> {
    use cockpit_core::daemon::proto::remote_protocol_id::{kind, tag_protocol_id_bytes};
    use cockpit_core::daemon::proto::remote_transport::bulk::{
        RemoteBulkMimeClass, RemoteBulkTransferRef,
    };
    use rand::RngExt as _;
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&hasher.finalize());

    let mut transfer_id_bytes = [0u8; 16];
    rand::rng().fill(&mut transfer_id_bytes[..]);
    if transfer_id_bytes.iter().all(|b| *b == 0) {
        transfer_id_bytes[0] = 1;
    }
    let transfer_id = tag_protocol_id_bytes::<kind::Transfer>(transfer_id_bytes)
        .map_err(|error| anyhow::anyhow!("building transfer id: {error}"))?;
    let transfer = RemoteBulkTransferRef::new(
        transfer_id,
        bytes.len() as u64,
        sha256,
        RemoteBulkMimeClass::Archive,
    )
    .map_err(|error| anyhow::anyhow!("import archive rejected: {error}"))?;

    let chunk_size = cockpit_core::daemon::bulk_staging::STAGED_CHUNK_BYTES;
    // A zero-length archive still sends one chunk so the transfer completes.
    for (chunk_index, chunk) in (0_u32..).zip(bytes.chunks(chunk_size).chain(if bytes.is_empty() {
        Some(&bytes[..0])
    } else {
        None
    })) {
        match client
            .request_ok(Request::WriteBulkTransferChunk {
                transfer: transfer.clone(),
                chunk_index,
                data_base64: base64::engine::general_purpose::STANDARD.encode(chunk),
            })
            .await?
        {
            Response::BulkTransferChunkAccepted { .. } => {}
            other => anyhow::bail!(
                "daemon returned unexpected response to bulk transfer chunk: {other:?}"
            ),
        }
    }
    Ok(transfer)
}

pub async fn run(args: ImportArgs) -> Result<()> {
    let daemon = discover().await;
    let imported = if matches!(daemon.status, DaemonStatus::Running) {
        let paths = daemon.paths;
        let client = DaemonClient::connect(&paths.socket)
            .await
            .context("connecting to running daemon for session import")?;
        let bytes = std::fs::read(&args.file)
            .with_context(|| format!("reading import archive {}", args.file.display()))?;
        // The archive never rides one frame: push it as bounded bulk chunks,
        // then hand the daemon a reference it can verify.
        let transfer = push_bulk_transfer(&client, &bytes).await?;
        match client
            .request_ok(Request::ImportSessionArchive {
                transfer,
                as_new: args.as_new,
            })
            .await?
        {
            Response::ImportSessionArchive { imported, redacted } => {
                cockpit_core::session::import::ImportResult { imported, redacted }
            }
            other => {
                anyhow::bail!("daemon returned unexpected response to session import: {other:?}")
            }
        }
    } else {
        let archive = cockpit_core::session::import::read_archive(&args.file)?;
        let db = Db::open_default()?;
        cockpit_core::session::import::import_archive(&db, archive, args.as_new).await?
    };
    println!(
        "Imported {} session{}{}.",
        imported.imported.len(),
        if imported.imported.len() == 1 {
            ""
        } else {
            "s"
        },
        if imported.redacted {
            "; archive content was redacted"
        } else {
            ""
        },
    );
    Ok(())
}
