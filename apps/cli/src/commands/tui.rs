use std::io::{IsTerminal, stdin, stdout};
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::db::workspace_trust::WorkspaceTrustMode;
use crate::welcome;
use cockpit_core::startup::PhaseTimer;
use cockpit_tui::tui::app::{App, StartupWorkspaceTrust};

pub async fn run(
    project: Option<&Path>,
    no_sandbox: bool,
    launch_start: Option<Instant>,
) -> Result<()> {
    if !stdin().is_terminal() || !stdout().is_terminal() {
        welcome::print(project);
        return Ok(());
    }

    let (db, trust) = prepare_tui_workspace_trust(project)?;

    let mut app = App::new_with_db_and_workspace_trust_and_launch_start(
        project,
        no_sandbox,
        db,
        trust,
        launch_start,
    );
    app.run().await
}

pub async fn run_with_session(
    project: Option<&Path>,
    no_sandbox: bool,
    session_id: Uuid,
    launch_start: Option<Instant>,
) -> Result<()> {
    if !stdin().is_terminal() || !stdout().is_terminal() {
        println!("session {session_id}");
        return Ok(());
    }

    let (db, trust) = prepare_tui_workspace_trust(project)?;

    let mut app = App::new_with_db_and_session_and_launch_start(
        project,
        no_sandbox,
        db,
        session_id,
        launch_start,
    );
    app.set_startup_workspace_trust(trust);
    app.run().await
}

#[expect(
    deprecated,
    reason = "db-async-foundation bridge; TUI command boot remains sync until db-async-workspace-trust"
)]
fn prepare_tui_workspace_trust(
    project: Option<&Path>,
) -> Result<(crate::db::Db, StartupWorkspaceTrust)> {
    let opened = match project {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().context("resolving cwd")?,
    };
    let mut timer = PhaseTimer::start("prepare_tui_workspace_trust");
    let root = crate::config::trust::resolve_trust_root(&opened)?;
    timer.phase("trust_root_resolve");
    let db = crate::db::Db::open_default().context("opening cockpit DB")?;
    timer.phase("db_open");
    let root_for_db = root.root.clone();
    if let Some(decision) = db.write_blocking(move |conn| {
        crate::db::Db::workspace_trust_by_root_conn(conn, &root_for_db)
    })? {
        timer.phase("trust_lookup");
        crate::config::trust::apply_trusted_workspace(root, decision.mode)?;
        return Ok((db, StartupWorkspaceTrust::Decided));
    }
    timer.phase("trust_lookup");

    crate::config::trust::set_runtime_policy(root.clone(), WorkspaceTrustMode::IgnoreConfig);
    Ok((db, StartupWorkspaceTrust::Pending(root)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{ConfigDoc, ModelEntry, ProviderEntry, ProvidersConfig};
    use cockpit_test_support::TestEnvGuard;

    fn write_provider_config(cwd: &Path) {
        let cockpit = cwd.join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        let mut cfg = ProvidersConfig::default();
        let mut provider = ProviderEntry {
            url: "http://localhost:1/v1".to_string(),
            ..Default::default()
        };
        provider.models.push(ModelEntry {
            id: "m".to_string(),
            ..Default::default()
        });
        cfg.providers.insert("p".to_string(), provider);
        let mut doc = ConfigDoc::load(&cockpit.join("config.json")).unwrap();
        doc.write(&cfg).unwrap();
    }

    #[test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db-async-workspace-trust"
    )]
    fn trust_gate_excludes_project_config_until_decided() {
        let tmp = tempfile::tempdir().unwrap();
        let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        write_provider_config(tmp.path());

        let (db, trust) = prepare_tui_workspace_trust(Some(tmp.path())).unwrap();
        assert!(matches!(trust, StartupWorkspaceTrust::Pending(_)));
        let ignored = ConfigDoc::load_effective(tmp.path());
        assert!(!ignored.providers.contains_key("p"));

        let root = crate::config::trust::resolve_trust_root(tmp.path()).unwrap();
        let normalized_root = root.root.to_string_lossy().into_owned();
        db.write_blocking(move |conn| {
            crate::db::Db::set_workspace_trust_conn(
                conn,
                &normalized_root,
                WorkspaceTrustMode::Trust,
                chrono::Utc::now().timestamp(),
            )
            .map(|_| ())
        })
        .unwrap();
        crate::config::trust::apply_trusted_workspace(root, WorkspaceTrustMode::Trust).unwrap();
        let trusted = ConfigDoc::load_effective(tmp.path());
        assert!(trusted.providers.contains_key("p"));

        crate::config::trust::clear_runtime_policy_for_tests();
    }
}
