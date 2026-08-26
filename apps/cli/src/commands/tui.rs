use std::io::{IsTerminal, stdin, stdout};
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::welcome;
use cockpit_tui::tui::app::{App, StartupWorkspaceTrust};

fn lifecycle_composition() -> (
    cockpit_client::LifecycleClient,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (client, requests) = cockpit_client::LifecycleClient::channel(16);
    let task = tokio::spawn(cockpit_core::daemon::client::serve_lifecycle_requests(
        requests,
    ));
    (client, task)
}

async fn finish_lifecycle(mut task: tokio::task::JoinHandle<anyhow::Result<()>>) -> Result<()> {
    finish_lifecycle_with_deadline(&mut task, std::time::Duration::from_secs(35)).await
}

async fn finish_lifecycle_with_deadline(
    task: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    deadline: std::time::Duration,
) -> Result<()> {
    match tokio::time::timeout(deadline, &mut *task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error).context("daemon lifecycle task failed"),
        Err(_) => {
            // Aborting only retires the async request actor. Every accepted or
            // provisional daemon owner is RAII-bound to a process-lifetime OS
            // reaper/supervisor, so dropping the actor transfers cleanup
            // rather than cancelling it. Bound the abort acknowledgement too:
            // top-level CLI exit must never turn 35 seconds into infinity.
            task.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), &mut *task).await;
            anyhow::bail!(
                "daemon lifecycle cleanup exceeded {deadline:?}; ownership transferred to the runtime-independent reaper"
            )
        }
    }
}

fn combine_app_and_lifecycle(app: Result<()>, lifecycle: Result<()>) -> Result<()> {
    match (app, lifecycle) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(app), Ok(())) => Err(app),
        (Ok(()), Err(lifecycle)) => Err(lifecycle),
        (Err(app), Err(lifecycle)) => {
            anyhow::bail!("application failed: {app:#}; daemon lifecycle failed: {lifecycle:#}")
        }
    }
}

pub async fn run(
    project: Option<&Path>,
    no_sandbox: bool,
    launch_start: Option<Instant>,
) -> Result<()> {
    if !stdin().is_terminal() || !stdout().is_terminal() {
        welcome::print(project, !no_sandbox);
        return Ok(());
    }

    let trust = prepare_tui_workspace_trust(project)?;

    let (lifecycle, lifecycle_task) = lifecycle_composition();
    let mut app = App::new_composed(project, no_sandbox, trust, launch_start, lifecycle);
    let result = app.run().await;
    drop(app);
    let lifecycle_result = finish_lifecycle(lifecycle_task).await;
    combine_app_and_lifecycle(result, lifecycle_result)
}

pub async fn run_with_session(
    project: Option<&Path>,
    no_sandbox: bool,
    session_id: Uuid,
    launch_start: Option<Instant>,
) -> Result<()> {
    if !stdin().is_terminal() || !stdout().is_terminal() {
        println!("session {session_id}");
        let _ = std::io::Write::flush(&mut stdout());
        let cwd = project.map_or_else(
            || std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
            std::path::Path::to_path_buf,
        );
        welcome::print_dependency_warning(&cwd, !no_sandbox);
        return Ok(());
    }

    let trust = prepare_tui_workspace_trust(project)?;

    let (lifecycle, lifecycle_task) = lifecycle_composition();
    let mut app = App::new_composed_with_session(
        project,
        no_sandbox,
        trust,
        session_id,
        launch_start,
        lifecycle,
    );
    let result = app.run().await;
    drop(app);
    let lifecycle_result = finish_lifecycle(lifecycle_task).await;
    combine_app_and_lifecycle(result, lifecycle_result)
}

fn prepare_tui_workspace_trust(project: Option<&Path>) -> Result<StartupWorkspaceTrust> {
    let opened = match project {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().context("resolving cwd")?,
    };
    let root = crate::config::trust::resolve_trust_root(&opened)?;
    crate::config::trust::set_runtime_policy(
        root.clone(),
        cockpit_config::WorkspaceTrustMode::IgnoreConfig,
    );
    Ok(StartupWorkspaceTrust::Pending(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{ConfigDoc, ModelEntry, ProviderEntry, ProvidersConfig};
    use cockpit_test_support::TestEnvGuard;

    #[tokio::test]
    async fn wedged_lifecycle_actor_is_bounded_and_drops_its_owner() {
        struct DropNotice(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for DropNotice {
            fn drop(&mut self) {
                if let Some(notice) = self.0.take() {
                    let _ = notice.send(());
                }
            }
        }

        let (dropped, drop_notice) = tokio::sync::oneshot::channel();
        let mut task = tokio::spawn(async move {
            let _owner = DropNotice(Some(dropped));
            std::future::pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        });
        let result =
            finish_lifecycle_with_deadline(&mut task, std::time::Duration::from_millis(10)).await;
        assert!(result.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(1), drop_notice)
            .await
            .expect("wedged lifecycle owner was not transferred/dropped")
            .expect("drop notice sender disappeared");
    }

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
    fn untrusted_first_run_reaches_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();

        let trust = prepare_tui_workspace_trust(Some(tmp.path())).unwrap();
        assert!(matches!(trust, StartupWorkspaceTrust::Pending(_)));
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn trust_gate_excludes_project_config_until_decided() {
        let tmp = tempfile::tempdir().unwrap();
        let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        write_provider_config(tmp.path());

        let trust = prepare_tui_workspace_trust(Some(tmp.path())).unwrap();
        assert!(matches!(trust, StartupWorkspaceTrust::Pending(_)));
        let ignored = ConfigDoc::load_effective(tmp.path());
        assert!(!ignored.providers.contains_key("p"));

        let root = crate::config::trust::resolve_trust_root(tmp.path()).unwrap();
        crate::config::trust::apply_trusted_workspace(
            root,
            cockpit_config::WorkspaceTrustMode::Trust,
        )
        .unwrap();
        let trusted = ConfigDoc::load_effective(tmp.path());
        assert!(trusted.providers.contains_key("p"));

        crate::config::trust::clear_runtime_policy_for_tests();
    }
}
