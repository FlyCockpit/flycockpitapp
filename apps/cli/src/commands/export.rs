//! `cockpit export <session>` — the CLI command surface for session-log
//! export (session-log-export Part D).
//!
//! This module owns only the command surface: identifier resolution from
//! parsed args and the stdout summary. The archive itself is assembled by
//! [`cockpit_core::session::export::write_bundle_zip`], the single
//! zip-assembly implementation shared with the TUI `/export debug`
//! command.

use anyhow::{Result, anyhow};

use cockpit_core::session::export::{
    default_output_path, resolve_session, write_bundle_zip, write_bundle_zip_raw_local,
};

use crate::cli::ExportArgs;
use crate::commands::CommandUsageError;
use crate::db::Db;
use crate::db::sessions::SessionRow;

pub async fn run(args: ExportArgs) -> Result<()> {
    let db = Db::open_default()?;
    let target = resolve_target_session(&db, &args).await?;

    // Collect the target plus all descendant forks and `/compact`
    // successor sessions, then assemble the archive. The walk is cheap
    // point-lookups per session; the read is bounded by the session's
    // history, which is acceptable to do on the current task for a
    // one-shot CLI export.
    //
    // The default export is a permanently redacted, portable artifact whose
    // redaction cannot be disabled by config, provider trust, or mode. The
    // single unredacted path is the explicit local `--include-sensitive`
    // opt-in, which prints a stderr warning and marks the manifest raw.
    let out_path = args
        .output
        .clone()
        .unwrap_or_else(|| default_output_path(&target));

    let summary = if args.include_sensitive {
        let summary =
            write_bundle_zip_raw_local(&db, &target, &out_path, args.force, args.include_generated)
                .await?;
        // Mandatory warning on every raw export: the archive contains raw
        // secrets. Emitted to stderr so it is visible even when stdout is
        // captured by a script.
        eprintln!("{}", raw_export_stderr_warning(&out_path));
        summary
    } else {
        {
            let vault = cockpit_core::secure_key::vault_for_db(&db)
                .map_err(|e| anyhow!("opening export vault: {e}"))?;
            write_bundle_zip(
                &db,
                &target,
                &out_path,
                args.force,
                args.include_generated,
                &vault,
            )
            .await?
        }
    };

    println!(
        "Exported session `{}` ({} session{}, {} bytes) → {}",
        target.short_id.as_deref().unwrap_or("?"),
        summary.session_count,
        if summary.session_count == 1 { "" } else { "s" },
        summary.byte_len,
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

async fn resolve_target_session(db: &Db, args: &ExportArgs) -> Result<SessionRow> {
    let ident = args
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CommandUsageError::new("a session identifier (`short_id` or UUID) is required")
        })?;

    match resolve_session(db, ident).await? {
        Ok(row) => Ok(row),
        Err(message) => Err(CommandUsageError::new(message).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_sensitive_export_prints_stderr_warning() {
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

    #[tokio::test]
    async fn export_missing_identifier_returns_typed_usage_error() {
        let db = Db::open_in_memory().unwrap();
        let err = resolve_target_session(
            &db,
            &ExportArgs {
                session_id: None,
                output: None,
                force: false,
                include_generated: false,
                include_sensitive: false,
            },
        )
        .await
        .unwrap_err();
        let usage = err
            .downcast_ref::<CommandUsageError>()
            .expect("missing identifier is a usage error");
        assert_eq!(
            usage.message(),
            "a session identifier (`short_id` or UUID) is required"
        );
    }

    #[tokio::test]
    async fn export_unknown_identifier_returns_typed_usage_error() {
        let db = Db::open_in_memory().unwrap();
        let err = resolve_target_session(
            &db,
            &ExportArgs {
                session_id: Some("zzzzzz".to_string()),
                output: None,
                force: false,
                include_generated: false,
                include_sensitive: false,
            },
        )
        .await
        .unwrap_err();
        let usage = err
            .downcast_ref::<CommandUsageError>()
            .expect("unknown short id is a usage error");
        assert_eq!(usage.message(), "no session with short id `zzzzzz`");
    }

    #[tokio::test]
    async fn export_ambiguous_identifier_returns_typed_usage_error() {
        let db = Db::open_in_memory().unwrap();
        db.write(move |conn| {
            let a = crate::db::Db::insert_session_row_conn(
                conn,
                &crate::db::Db::build_new_session_row_conn(conn, "p1", "/x", "builder")?,
            )?;
            let b = crate::db::Db::insert_session_row_conn(
                conn,
                &crate::db::Db::build_new_session_row_conn(conn, "p2", "/y", "builder")?,
            )?;
            conn.execute(
                "UPDATE sessions SET short_id = 'same42' WHERE session_id IN (?1, ?2)",
                rusqlite::params![a.session_id.to_string(), b.session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let err = resolve_target_session(
            &db,
            &ExportArgs {
                session_id: Some("same42".to_string()),
                output: None,
                force: false,
                include_generated: false,
                include_sensitive: false,
            },
        )
        .await
        .unwrap_err();
        let usage = err
            .downcast_ref::<CommandUsageError>()
            .expect("ambiguous short id is a usage error");
        assert_eq!(
            usage.message(),
            "short id `same42` is ambiguous — it matches 2 sessions across projects; pass the full UUID instead"
        );
    }
}
