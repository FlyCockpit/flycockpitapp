use super::*;

impl App {
    /// `/export` (default) — write the persisted transcript as
    /// `<stem>.json`, overwriting any prior file.
    pub(super) fn export_transcript_json(&mut self, file_stem: &str, exports_dir: &Path) {
        self.export_transcript_json_with_db(file_stem, exports_dir, cockpit_db::Db::open_default);
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; TUI export action remains sync until db-async-session-log"
    )]
    fn export_transcript_json_with_db(
        &mut self,
        file_stem: &str,
        exports_dir: &Path,
        open_db: impl FnOnce() -> anyhow::Result<cockpit_db::Db>,
    ) {
        let Some(session_id) = self.current_session_id() else {
            self.push_plain("/export: no active session to export".to_string());
            return;
        };
        let out_path = exports_dir.join(format!("{file_stem}.json"));
        let result = (|| -> anyhow::Result<()> {
            let db = open_db()?;
            let target = db
                .write_blocking(move |conn| cockpit_db::Db::get_session_conn(conn, session_id))?
                .ok_or_else(|| anyhow::anyhow!("session `{session_id}` not found in the DB"))?;
            std::fs::create_dir_all(exports_dir).with_context(|| {
                format!("creating export directory `{}`", exports_dir.display())
            })?;
            let value = cockpit_core::session::export::transcript_json(
                &db,
                session_id,
                &target.active_agent,
            )?;
            let json = serde_json::to_string_pretty(&value)?;
            std::fs::write(&out_path, json)
                .with_context(|| format!("writing export to `{}`", out_path.display()))?;
            Ok(())
        })();
        let line = match result {
            Ok(_) => format!("Exported conversation → {}", out_path.display()),
            Err(e) => format!("/export: {e}"),
        };
        self.push_plain(line);
    }

    /// `/export debug` (hidden) — write the full CLI bundle `.zip` for
    /// the current session, overwriting any prior file. Reads the DB
    /// directly (like the CLI) so it works regardless of daemon state,
    /// reusing [`cockpit_core::session::export::write_bundle_zip`] —
    /// the single shared zip-assembly implementation, called in-process
    /// with this handle.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; TUI export action remains sync until db-async-session-log"
    )]
    pub(super) fn export_debug_bundle(
        &mut self,
        session_id: uuid::Uuid,
        file_stem: &str,
        exports_dir: &Path,
    ) {
        let out_path = exports_dir.join(format!("{file_stem}.zip"));
        let result = (|| -> anyhow::Result<cockpit_core::session::export::BundleSummary> {
            let db = cockpit_db::Db::open_default()?;
            let target = db
                .write_blocking(move |conn| cockpit_db::Db::get_session_conn(conn, session_id))?
                .ok_or_else(|| anyhow::anyhow!("session `{session_id}` not found in the DB"))?;
            // Unconditional overwrite (the TUI has no `--force`); this
            // does not weaken the CLI's no-clobber-without-`--force`
            // guarantee, which lives in the CLI's `export::run`.
            cockpit_core::session::export::write_bundle_zip(
                &db, &target, &out_path, true, false, false,
            )
        })();
        let line = match result {
            Ok(summary) => format!(
                "Exported debug bundle ({} session{}, {} bytes) → {}",
                summary.session_count,
                if summary.session_count == 1 { "" } else { "s" },
                summary.byte_len,
                out_path.display()
            ),
            Err(e) => format!("/export debug: {e}"),
        };
        self.push_plain(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last_plain(app: &App) -> &str {
        match app.history.last().expect("history line") {
            HistoryEntry::Plain { line } => line,
            other => panic!("expected plain line, got {other:?}"),
        }
    }

    #[test]
    fn export_transcript_json_without_current_session_writes_no_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let exports_dir = tmp.path().join("exports");
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.session_id = None;

        app.export_transcript_json_with_db("conversation", &exports_dir, || {
            Ok(cockpit_db::Db::open_in_memory().unwrap())
        });

        assert_eq!(last_plain(&app), "/export: no active session to export");
        assert!(!exports_dir.join("conversation.json").exists());
    }

    #[test]
    fn export_transcript_json_absent_session_writes_no_file_and_names_session() {
        let tmp = tempfile::TempDir::new().unwrap();
        let exports_dir = tmp.path().join("exports");
        let missing = uuid::Uuid::new_v4();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.session_id = Some(missing);

        app.export_transcript_json_with_db("conversation", &exports_dir, || {
            Ok(cockpit_db::Db::open_in_memory().unwrap())
        });

        let line = last_plain(&app);
        assert!(line.starts_with("/export: "), "{line}");
        assert!(line.contains(&missing.to_string()), "{line}");
        assert!(!exports_dir.join("conversation.json").exists());
    }
}
