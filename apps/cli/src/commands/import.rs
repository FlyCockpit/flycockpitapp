use anyhow::{Context, Result};
use base64::Engine;

use cockpit_client::DaemonClient;

use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response};

use crate::cli::ImportArgs;

/// Push an archive into daemon-side bulk staging and return its reference.
///
/// Chunks are contiguous and each body stays inside the advertised chunk bound,
/// so no single frame can starve the control lane. The daemon verifies the
/// declared length and SHA-256 before the import runs.
async fn push_bulk_transfer(
    client: &DaemonClient,
    bytes: &[u8],
) -> Result<cockpit_core::daemon::proto::bulk_transfer::BulkTransferRef> {
    use cockpit_core::daemon::proto::bulk_transfer::{
        BulkMimeClass, BulkTransferRef, transfer_id_from_bytes,
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
    let transfer_id = transfer_id_from_bytes(transfer_id_bytes)
        .map_err(|error| anyhow::anyhow!("building transfer id: {error}"))?;
    let transfer = BulkTransferRef::new(
        transfer_id,
        bytes.len() as u64,
        sha256,
        BulkMimeClass::Archive,
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
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for session import")?;
    let client = daemon.client.clone();
    // Bound the read with the same compressed cap the daemon enforces
    // (`archive_compressed_bytes` == the bulk-lane transfer limit), and refuse
    // non-regular files before any content is accumulated: an oversized or
    // FIFO/device path fails here instead of allocating or blocking the CLI.
    let limits = cockpit_core::resource_limits::ResourceLimits::defaults();
    let bytes = cockpit_host::bounded::read_at_most(&args.file, limits.archive_compressed_bytes)
        .map_err(|error| match error {
            cockpit_host::bounded::BoundedIoError::Limit { actual, limit, .. } => {
                anyhow!("import archive exceeds the {limit} byte compressed limit ({actual} bytes)")
            }
            other => {
                anyhow!(other).context(format!("reading import archive {}", args.file.display()))
            }
        })?;
    // The archive never rides one frame: push it as bounded bulk chunks,
    // then hand the daemon a reference it can verify.
    let transfer = push_bulk_transfer(&client, &bytes).await?;
    let imported = match client
        .request_ok(Request::ImportSessionArchive {
            transfer,
            include_sensitive: args.include_sensitive,
        })
        .await?
    {
        Response::ImportSessionArchive { imported, redacted } => {
            cockpit_core::session::import::ImportResult { imported, redacted }
        }
        other => {
            anyhow::bail!("daemon returned unexpected response to session import: {other:?}")
        }
    };
    if !imported.redacted {
        // Mandatory warning on every raw import, mirroring the export side:
        // the restored events carry raw secrets whose redaction custody this
        // machine cannot reconstruct. Emitted to stderr so it is visible even
        // when stdout is captured by a script.
        eprintln!("{}", raw_import_stderr_warning());
    }
    // The imported ids are the usable handles for the restored sessions:
    // import always mints fresh destination ids, so the source id is the wrong
    // handle afterwards. Print one id per line so scripts can consume them.
    println!(
        "Imported {} session{}{}:",
        imported.imported.len(),
        if imported.imported.len() == 1 {
            ""
        } else {
            "s"
        },
        if imported.redacted {
            "; archive content was redacted"
        } else {
            "; archive content was unredacted"
        },
    );
    for id in &imported.imported {
        println!("  {id}");
    }
    Ok(())
}

/// The mandatory stderr warning printed on every acknowledged unredacted
/// import. It mirrors the export side's raw warning: the restored sessions
/// contain raw secret material whose custody cannot be reconstructed here,
/// and the copy must state that plainly so a user cannot mistake the result
/// for a normally-redacted restore.
fn raw_import_stderr_warning() -> String {
    "warning: `--include-sensitive` imported an UNREDACTED session archive — the restored \
     sessions contain raw secrets from the exporting machine, and redaction custody for them \
     cannot be reconstructed on this machine; outbound egress scrubs only secrets still \
     present in this environment. Handle the restored sessions as sensitive material."
        .to_owned()
}
