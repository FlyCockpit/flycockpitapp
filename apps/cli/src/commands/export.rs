//! `cockpit export <session>` — the CLI command surface for session-log
//! export (session-log-export Part D).
//!
//! This module owns only the command surface: identifier resolution from
//! parsed args and the stdout summary. The archive itself is assembled by
//! [`cockpit_core::session::export::write_bundle_zip`], the single
//! zip-assembly implementation shared with the TUI `/export debug`
//! command.

use anyhow::Result;

use cockpit_core::session::export::{default_output_path, resolve_session, write_bundle_zip};

use crate::cli::ExportArgs;
use crate::commands::CommandUsageError;
use crate::db::Db;
use crate::db::sessions::SessionRow;

pub async fn run(args: ExportArgs) -> Result<()> {
    let db = Db::open_default()?;
    let target = resolve_target_session(&db, &args)?;

    // Collect the target plus all descendant forks and `/compact`
    // successor sessions, then assemble the archive. The walk is cheap
    // point-lookups per session; the read is bounded by the session's
    // history, which is acceptable to do on the current task for a
    // one-shot CLI export.
    let out_path = args
        .output
        .clone()
        .unwrap_or_else(|| default_output_path(&target));

    if args.include_sensitive {
        eprintln!(
            "warning: --include-sensitive exports exact captured payloads and may include secrets sent to trusted models"
        );
    }

    let summary = write_bundle_zip(
        &db,
        &target,
        &out_path,
        args.force,
        args.include_generated,
        args.include_sensitive,
    )?;

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

fn resolve_target_session(db: &Db, args: &ExportArgs) -> Result<SessionRow> {
    let ident = args
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CommandUsageError::new("a session identifier (`short_id` or UUID) is required")
        })?;

    match resolve_session(db, ident)? {
        Ok(row) => Ok(row),
        Err(message) => Err(CommandUsageError::new(message).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_missing_identifier_returns_typed_usage_error() {
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
        .unwrap_err();
        let usage = err
            .downcast_ref::<CommandUsageError>()
            .expect("missing identifier is a usage error");
        assert_eq!(
            usage.message(),
            "a session identifier (`short_id` or UUID) is required"
        );
    }

    #[test]
    fn export_unknown_identifier_returns_typed_usage_error() {
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
        .unwrap_err();
        let usage = err
            .downcast_ref::<CommandUsageError>()
            .expect("unknown short id is a usage error");
        assert_eq!(usage.message(), "no session with short id `zzzzzz`");
    }

    #[test]
    fn export_ambiguous_identifier_returns_typed_usage_error() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("p1", "/x", "builder").unwrap();
        let b = db.create_session("p2", "/y", "builder").unwrap();
        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET short_id = 'same42' WHERE session_id IN (?1, ?2)",
                rusqlite::params![a.session_id.to_string(), b.session_id.to_string()],
            )?;
            Ok(())
        })
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
