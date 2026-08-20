//! `cockpit export <session>` — the CLI command surface for session-log
//! export (session-log-export Part D).
//!
//! The CLI never opens the database. It asks the persistent daemon to assemble
//! the archive (permanently redacted by default; raw only through the explicit
//! local `--include-sensitive` opt-in), streams the bytes back over the reader
//! that matches the archive's kind, and writes the user-path file itself with
//! the private-export writer:
//!
//! - The redacted archive is staged as the `RedactedExport` bulk kind and read
//!   over the owner-remoted type-bound [`Request::ReadRedactedExportChunk`].
//! - The raw `--include-sensitive` archive is staged as the raw `Export` kind
//!   and read only over the owner-local generic [`Request::ReadBulkTransferChunk`];
//!   the daemon rejects a raw assemble for any remoted caller.

use anyhow::{Context, Result, bail};
use base64::Engine;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use cockpit_core::daemon::proto::remote_transport::bulk::RemoteBulkTransferRef;
use cockpit_core::daemon::proto::{ExportSessionKind, Request, Response, SessionSummary};

use crate::cli::ExportArgs;
use crate::commands::CommandUsageError;
use crate::daemon::client::{DaemonClient, ensure_persistent_daemon};

pub async fn run(args: ExportArgs) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for session export")?;
    let client = daemon.client.clone();

    let (session_id, short_id) = resolve_target_session(&client, &args).await?;

    let out_path = args
        .output
        .clone()
        .unwrap_or_else(|| default_output_path(short_id.as_deref(), session_id));

    // No-clobber unless `--force`. Checked before the (potentially large)
    // assemble so a mistaken overwrite fails fast.
    if out_path.exists() && !args.force {
        bail!(
            "output path `{}` already exists — pass `--force` to overwrite",
            out_path.display()
        );
    }

    // The daemon owns the DB read and the redaction policy. Its response is a
    // bulk transfer reference, never inline ZIP bytes. `include_sensitive` is
    // the local-only raw opt-in; the daemon rejects it for any remoted caller.
    let response = client
        .request_ok(Request::ExportSessionData {
            session_id,
            kind: ExportSessionKind::DebugBundle,
            include_generated_artifacts: args.include_generated,
            include_sensitive: args.include_sensitive,
        })
        .await
        .context("requesting session export assembly from daemon")?;
    let data = match response {
        Response::ExportSessionData { data } => data,
        other => bail!("daemon returned unexpected response to session export: {other:?}"),
    };

    // Stream the archive back over the reader that matches its kind.
    let bytes = download_export(&client, &data.transfer, args.include_sensitive).await?;

    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        cockpit_core::private_fs::ensure_output_parent_private(parent)
            .with_context(|| format!("securing export directory `{}`", parent.display()))?;
    }
    // `write_private_export_file` fails closed on any build that cannot enforce
    // the private-file discipline (0600 / ownership / no-follow), so a secret
    // export never lands world-readable.
    cockpit_core::private_fs::write_private_export_file(&out_path, &bytes)
        .with_context(|| format!("writing private export to `{}`", out_path.display()))?;

    if args.include_sensitive {
        // Mandatory warning on every raw export: the archive contains raw
        // secrets. Emitted to stderr so it is visible even when stdout is
        // captured by a script.
        eprintln!("{}", raw_export_stderr_warning(&out_path));
    }

    let session_count = data.session_count.unwrap_or(0);
    println!(
        "Exported session `{}` ({} session{}, {} bytes) → {}",
        short_id.as_deref().unwrap_or("?"),
        session_count,
        if session_count == 1 { "" } else { "s" },
        bytes.len(),
        out_path.display()
    );
    Ok(())
}

/// The mandatory stderr warning printed on every successful
/// `cockpit export --include-sensitive` run. The archive it describes is
/// unredacted; the copy must state that plainly so a user cannot mistake a raw
/// export for a safe one. The exact wording is CLI-owned; it always mentions
/// that the archive is unredacted and contains raw secrets.
pub(crate) fn raw_export_stderr_warning(out_path: &std::path::Path) -> String {
    format!(
        "warning: `--include-sensitive` wrote an UNREDACTED export to `{}` — it contains \
         raw secrets (API keys, tokens, credentials, SSH material). The archive is NOT \
         redacted; handle and share it as sensitive material.",
        out_path.display()
    )
}

/// Default output path, mirroring `cockpit_core::session::export::default_output_path`
/// without opening the database: `./cockpit-session-<short_id|uuid>.zip`.
fn default_output_path(short_id: Option<&str>, session_id: Uuid) -> std::path::PathBuf {
    let id = short_id
        .map(str::to_owned)
        .unwrap_or_else(|| session_id.to_string());
    std::path::PathBuf::from(format!("cockpit-session-{id}.zip"))
}

/// Resolve the CLI's session identifier to `(session_id, short_id)` using the
/// daemon's `ListSessions` read — the CLI does not open the database.
async fn resolve_target_session(
    client: &DaemonClient,
    args: &ExportArgs,
) -> Result<(Uuid, Option<String>)> {
    let ident = args
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CommandUsageError::new("a session identifier (`short_id` or UUID) is required")
        })?;

    let response = client
        .request_ok(Request::ListSessions {
            project_id: None,
            parent_session_id: None,
            assistant_id: None,
        })
        .await
        .context("requesting session list from daemon")?;
    let sessions = match response {
        Response::Sessions { sessions } => sessions,
        other => bail!("daemon returned unexpected response to session list: {other:?}"),
    };

    resolve_from_summaries(&sessions, ident)
        .map_err(|message| CommandUsageError::new(message).into())
}

/// Pure resolution over a session summary list, mirroring
/// `cockpit_core::session::export::resolve_session`: a full UUID resolves
/// directly (the short id, if listed, only decorates the default output name);
/// otherwise the identifier is matched against `short_id`, rejecting an unknown
/// or ambiguous short id with the same messages the daemon-local resolver used.
fn resolve_from_summaries(
    sessions: &[SessionSummary],
    ident: &str,
) -> std::result::Result<(Uuid, Option<String>), String> {
    if let Ok(uuid) = Uuid::parse_str(ident) {
        let short_id = sessions
            .iter()
            .find(|s| s.session_id == uuid)
            .and_then(|s| s.short_id.clone());
        return Ok((uuid, short_id));
    }

    let matches: Vec<&SessionSummary> = sessions
        .iter()
        .filter(|s| s.short_id.as_deref() == Some(ident))
        .collect();
    match matches.as_slice() {
        [] => Err(format!("no session with short id `{ident}`")),
        [only] => Ok((only.session_id, only.short_id.clone())),
        many => Err(format!(
            "short id `{ident}` is ambiguous — it matches {} sessions across projects; \
             pass the full UUID instead",
            many.len()
        )),
    }
}

/// Stream a staged export transfer back from the daemon over the reader that
/// matches its kind. Redacted exports ride the owner-remoted type-bound
/// [`Request::ReadRedactedExportChunk`]; the raw `--include-sensitive` archive
/// rides the owner-local generic [`Request::ReadBulkTransferChunk`]. The
/// assembled bytes are checked against the transfer's declared length and
/// SHA-256 so a truncated or corrupted download never lands on disk.
async fn download_export(
    client: &DaemonClient,
    transfer: &RemoteBulkTransferRef,
    raw: bool,
) -> Result<Vec<u8>> {
    let expected_len = transfer.total_length_value();
    let transfer_id = transfer.transfer_id;
    // Deliberately not `with_capacity(expected_len)`: the length arrives on the
    // wire; the buffer only grows with bytes that actually arrived and the loop
    // refuses to exceed the declared length.
    let mut bytes: Vec<u8> = Vec::new();
    let mut chunk_index: u32 = 0;
    loop {
        let request = if raw {
            Request::ReadBulkTransferChunk {
                transfer_id,
                chunk_index,
            }
        } else {
            Request::ReadRedactedExportChunk {
                transfer_id,
                chunk_index,
            }
        };
        let response = client
            .request_ok(request)
            .await
            .context("reading export data from daemon")?;
        let Response::BulkTransferChunk {
            chunk_index: got,
            data_base64,
            last,
        } = response
        else {
            bail!("daemon returned unexpected response to export chunk read: {response:?}");
        };
        if got != chunk_index {
            bail!("daemon returned an out-of-order export chunk");
        }
        let chunk = base64::engine::general_purpose::STANDARD
            .decode(data_base64)
            .context("decoding export data")?;
        if bytes.len() as u64 + chunk.len() as u64 > expected_len {
            bail!("export transfer overran its declared length");
        }
        bytes.extend_from_slice(&chunk);
        if last {
            break;
        }
        chunk_index += 1;
    }
    if bytes.len() as u64 != expected_len {
        bail!("export transfer length mismatch");
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    if hasher.finalize().as_slice() != transfer.sha256 {
        bail!("export transfer digest mismatch");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(short_id: Option<&str>, session_id: Uuid) -> SessionSummary {
        // Build through serde so the many `#[serde(default)]` fields fill in;
        // only the resolution-relevant fields are set.
        serde_json::from_value(serde_json::json!({
            "session_id": session_id,
            "short_id": short_id,
            "project_root": "/x",
            "project_id": "p",
            "started_at": 0,
            "last_active_at": 0,
            "turns": 0,
            "active_agent": "builder",
        }))
        .expect("minimal session summary deserializes")
    }

    #[test]
    fn raw_export_stderr_warning_names_the_unredacted_archive() {
        // The production warning string used by the `--include-sensitive` branch
        // of `run` must be non-empty, name the raw archive as unredacted /
        // containing raw secrets, and reference the output path. The default
        // (redacted) export never emits this text.
        let path = std::path::Path::new("/tmp/example-export.zip");
        let warning = raw_export_stderr_warning(path);
        assert!(!warning.trim().is_empty(), "warning must be non-empty");
        assert!(
            warning.contains("UNREDACTED"),
            "warning must state the archive is unredacted",
        );
        assert!(
            warning.contains("raw secrets"),
            "warning must state the archive contains raw secrets",
        );
        assert!(
            warning.contains("example-export.zip"),
            "warning must name the destination path",
        );
    }

    #[test]
    fn cli_export_uses_write_private_export_file() {
        // AC10: the production export write goes through the fail-closed
        // private-export writer, never the plain `write_private_file`.
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/export.rs"),
        )
        .unwrap();
        // Assertion is about production code, not this test module.
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(
            production.contains("write_private_export_file"),
            "the CLI export write must use the private-export writer"
        );
        assert!(
            !production.contains("write_private_file("),
            "the CLI export must not use the plain write_private_file"
        );
        // AC3/AC12 belt-and-braces: the CLI export never opens the DB or a vault.
        assert!(!production.contains("Db::open_default"));
        assert!(!production.contains("vault_for_db"));
    }

    #[test]
    fn resolve_from_summaries_resolves_a_unique_short_id() {
        let id = Uuid::new_v4();
        let sessions = vec![
            summary(Some("aaaaaa"), Uuid::new_v4()),
            summary(Some("same42"), id),
        ];
        let (session_id, short_id) = resolve_from_summaries(&sessions, "same42").unwrap();
        assert_eq!(session_id, id);
        assert_eq!(short_id.as_deref(), Some("same42"));
    }

    #[test]
    fn resolve_from_summaries_resolves_a_full_uuid_without_short_id_lookup() {
        let id = Uuid::new_v4();
        // The daemon does not list this session, yet a full UUID still resolves.
        let (session_id, short_id) = resolve_from_summaries(&[], &id.to_string()).unwrap();
        assert_eq!(session_id, id);
        assert_eq!(short_id, None);
    }

    #[test]
    fn resolve_from_summaries_rejects_unknown_short_id() {
        let sessions = vec![summary(Some("aaaaaa"), Uuid::new_v4())];
        let err = resolve_from_summaries(&sessions, "zzzzzz").unwrap_err();
        assert_eq!(err, "no session with short id `zzzzzz`");
    }

    #[test]
    fn resolve_from_summaries_rejects_ambiguous_short_id() {
        let sessions = vec![
            summary(Some("same42"), Uuid::new_v4()),
            summary(Some("same42"), Uuid::new_v4()),
        ];
        let err = resolve_from_summaries(&sessions, "same42").unwrap_err();
        assert_eq!(
            err,
            "short id `same42` is ambiguous — it matches 2 sessions across projects; \
             pass the full UUID instead"
        );
    }
}
