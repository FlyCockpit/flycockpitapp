use std::path::{Path, PathBuf};

const RAW_AUTHORITY: &[&str] = &[
    "probe_or_spawn",
    "ConnectedDaemon",
    "take_owned_daemon_guard",
    "spawn_signal_shutdown",
    "EphemeralDaemonGuard::new",
];

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}

#[test]
fn cli_production_has_no_raw_daemon_lifecycle_authority() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = rust_sources(&root)
        .into_iter()
        .flat_map(|path| {
            let source = std::fs::read_to_string(&path).unwrap();
            RAW_AUTHORITY.iter().filter_map(move |symbol| {
                source
                    .contains(symbol)
                    .then(|| format!("{}: {symbol}", path.display()))
            })
        })
        .collect::<Vec<_>>();
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn owned_session_is_the_single_cli_lifecycle_facade() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let facade =
        std::fs::read_to_string(workspace.join("crates/cockpit-core/src/daemon/client.rs"))
            .unwrap();
    for contract in [
        "pub struct OwnedDaemonSession",
        "pub async fn connect(mode: LifecycleMode)",
        "let mut connected = probe_or_spawn(mode).await?",
        "let guard = connected.take_owned_daemon_guard()",
        "spawn_signal_shutdown(",
        "pub fn client(&self) -> &DaemonClient",
        "pub async fn finish<T>",
        "aggregate_shutdown_result(result, shutdown)",
    ] {
        assert!(
            facade.contains(contract),
            "missing facade contract: {contract}"
        );
    }
    for forbidden_public_field in [
        "pub client: DaemonClient",
        "pub guard: Option<",
        "pub signal_task: Option<",
    ] {
        assert!(!facade.contains(forbidden_public_field));
    }
}

#[test]
fn every_ephemeral_command_uses_and_finishes_the_owned_session() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands");
    for command in [
        "doctor.rs",
        "init.rs",
        "invocation.rs",
        "learn.rs",
        "run.rs",
        "schedule.rs",
        "session.rs",
    ] {
        let source = std::fs::read_to_string(root.join(command)).unwrap();
        assert!(
            source.contains("OwnedDaemonSession"),
            "{command} does not acquire the owned-session facade"
        );
        assert!(
            source.contains(".finish("),
            "{command} does not explicitly finish its owned session"
        );
    }
}
