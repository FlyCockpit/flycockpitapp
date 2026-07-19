use super::*;

impl App {
    /// `/export` (default) — write the live transcript as
    /// `<stem>.json`, overwriting any prior file.
    pub(super) fn export_transcript_json(&mut self, file_stem: &str, exports_dir: &Path) {
        let out_path = exports_dir.join(format!("{file_stem}.json"));
        let result = (|| -> anyhow::Result<()> {
            std::fs::create_dir_all(exports_dir).with_context(|| {
                format!("creating export directory `{}`", exports_dir.display())
            })?;
            let value = crate::tui::history::export_transcript(&self.history);
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
    /// reusing the single shared zip-assembly implementation.
    pub(super) fn export_debug_bundle(
        &mut self,
        session_id: uuid::Uuid,
        file_stem: &str,
        exports_dir: &Path,
    ) {
        let out_path = exports_dir.join(format!("{file_stem}.zip"));
        let result = (|| -> anyhow::Result<crate::commands::export::BundleSummary> {
            let db = crate::db::Db::open_default()?;
            let target = db
                .get_session(session_id)?
                .ok_or_else(|| anyhow::anyhow!("session `{session_id}` not found in the DB"))?;
            // Unconditional overwrite (the TUI has no `--force`); this
            // does not weaken the CLI's no-clobber-without-`--force`
            // guarantee, which lives in `commands::export::run`.
            crate::commands::export::write_bundle_zip(&db, &target, &out_path, true, false, false)
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
