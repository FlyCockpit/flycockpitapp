use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;

use crate::support::{
    COMPOSER_PLACEHOLDER, EXCLUDED_POISON_KEYS, HERMETIC_ENV_KEYS, HERMETIC_LOCALE,
    HERMETIC_PTY_SHELL, HERMETIC_TERM, HermeticCockpit, HermeticLaunchKind, HermeticProfile,
    INITIAL_PTY_COLS, InheritedEnvironmentModel, REMOTE_OSC52_SSH_CONNECTION,
    UNWANTED_STARTUP_MARKERS,
};

#[test]
fn tui_pty_fixture_launches_and_reaps() {
    let mut session = HermeticCockpit::launch_ready(HermeticProfile::Default);
    let screen = session.snapshot();
    assert!(
        screen.contains(COMPOSER_PLACEHOLDER),
        "ready composer missing:\n{}",
        screen.contents()
    );
    for marker in UNWANTED_STARTUP_MARKERS {
        assert!(
            !screen.contains(marker),
            "unwanted startup marker {marker:?} present:\n{}",
            screen.contents()
        );
    }

    assert!(
        session.snapshot().has_unwrapped_text(COMPOSER_PLACEHOLDER)
            && session.snapshot().has_box_top_width(INITIAL_PTY_COLS),
        "ready TUI must paint a {INITIAL_PTY_COLS}-column box with an unwrapped composer:\n{}",
        session.snapshot().contents()
    );
    session.resize(40, 16);
    session
        .wait_until_screen(
            "child reflowed composer placeholder across rows",
            Duration::from_secs(5),
            |screen| {
                !screen.has_unwrapped_text(COMPOSER_PLACEHOLDER)
                    && screen.contains("Message FlyCockpit")
                    && screen.has_box_top_width(40)
            },
        )
        .expect("resize current-screen assertion");

    session.type_line("/exit");
    assert!(
        session.wait_for_child_exit(Duration::from_secs(10)),
        "PTY child did not exit after /exit"
    );
    session.reap();
    session.assert_reaped();
}

#[test]
fn tui_pty_hermetic_command_environment_is_exact() {
    let inherited = InheritedEnvironmentModel::poison_sentinels();
    for key in EXCLUDED_POISON_KEYS {
        assert!(
            inherited.contains(key),
            "poison model missing excluded key {key}"
        );
        assert_eq!(
            inherited.get(key),
            Some(format!("POISON_{key}").as_str()),
            "poison sentinel for {key}"
        );
    }

    let default =
        HermeticCockpit::prepare_with_inherited(HermeticProfile::Default, inherited.clone());
    assert_eq!(default.inherited_environment(), &inherited);
    assert_launch_graph(&default, HermeticProfile::Default);

    let remote =
        HermeticCockpit::prepare_with_inherited(HermeticProfile::RemoteOsc52, inherited.clone());
    assert_eq!(remote.inherited_environment(), &inherited);
    assert_launch_graph(&remote, HermeticProfile::RemoteOsc52);
    assert_eq!(
        default.spec().executable(),
        remote.spec().executable(),
        "cargo_bin must be resolved once for every launcher"
    );
}

fn assert_launch_graph(launcher: &HermeticCockpit, profile: HermeticProfile) {
    let spec = launcher.spec();
    assert!(
        spec.executable().is_absolute(),
        "cargo_bin executable must be absolute: {}",
        spec.executable().display()
    );
    assert_eq!(
        spec.config_dir(),
        spec.home().join(".config").join("cockpit"),
        "config is discovered at HOME/.config/cockpit/"
    );
    assert!(
        spec.config_dir().join("config.json").is_file(),
        "isolated config.json must exist at HOME/.config/cockpit/"
    );
    assert_eq!(spec.profile(), profile);

    for path in spec.all_launch_paths() {
        assert_eq!(path.executable, spec.executable());
        assert_eq!(path.cwd, spec.project());
        match (profile, path.kind) {
            (HermeticProfile::RemoteOsc52, HermeticLaunchKind::PtyChild) => {
                assert_eq!(path.env.len(), 10, "{path:?}");
                assert_eq!(
                    path.env_value("SSH_CONNECTION"),
                    Some(REMOTE_OSC52_SSH_CONNECTION)
                );
            }
            (_, HermeticLaunchKind::DaemonStart) => {
                // The detached daemon has an explicit startup-log policy;
                // this is fixture-owned input, not inherited environment.
                assert_eq!(path.env.len(), 10, "{path:?}");
                assert_eq!(
                    path.env_value("COCKPIT_LOG"),
                    Some("warn,cockpit::startup=info"),
                    "{path:?}"
                );
            }
            _ => {
                assert_eq!(path.env.len(), 9, "{path:?}");
                assert!(
                    path.env_value("SSH_CONNECTION").is_none(),
                    "SSH_CONNECTION must stay off non-PTY and default-PTY paths: {path:?}"
                );
            }
        }
        assert_allowlisted_env(&path.env, path.kind, profile);
        for (key, poison) in launcher.inherited_environment().iter() {
            let leaked = path.env_value(key) == Some(poison);
            assert!(
                !leaked,
                "launch path {:?} inherited poison {key}={poison}",
                path.kind
            );
        }

        if path.kind == HermeticLaunchKind::PtyChild {
            let pty_env = path.pty_env_pairs();
            let mut expected = path.env.clone();
            expected.push(("SHELL".into(), HERMETIC_PTY_SHELL.into()));
            assert_eq!(
                sorted_pairs(&pty_env),
                sorted_pairs(&expected),
                "PTY CommandBuilder env must be the spec plus pinned SHELL=/bin/sh"
            );
            assert_eq!(
                pty_env
                    .iter()
                    .find(|(k, _)| k == "SHELL")
                    .map(|(_, v)| v.as_str()),
                Some(HERMETIC_PTY_SHELL),
                "portable-pty SHELL injection must be pinned, not host-derived"
            );
        }
    }
}

fn assert_allowlisted_env(
    env: &[(String, String)],
    kind: HermeticLaunchKind,
    profile: HermeticProfile,
) {
    let mut keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
    keys.sort_unstable();
    let mut expected: Vec<&str> = HERMETIC_ENV_KEYS.to_vec();
    if kind == HermeticLaunchKind::DaemonStart {
        expected.push("COCKPIT_LOG");
    }
    if kind == HermeticLaunchKind::PtyChild && profile == HermeticProfile::RemoteOsc52 {
        expected.push("SSH_CONNECTION");
    }
    expected.sort_unstable();
    assert_eq!(keys, expected, "unexpected env keys for {kind:?}");

    let map: std::collections::BTreeMap<&str, &str> =
        env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    assert_eq!(map.get("TERM").copied(), Some(HERMETIC_TERM));
    assert_eq!(map.get("LANG").copied(), Some(HERMETIC_LOCALE));
    assert_eq!(map.get("LC_ALL").copied(), Some(HERMETIC_LOCALE));
}

fn sorted_pairs(env: &[(String, String)]) -> Vec<(String, String)> {
    let mut pairs = env.to_vec();
    pairs.sort();
    pairs
}

#[test]
fn tui_pty_fixture_failure_paths_reap() {
    let mut timeout_session = HermeticCockpit::prepare(HermeticProfile::Default);
    timeout_session.start_trusted_daemon();
    timeout_session
        .spawn_pty(100, 30)
        .expect("spawn PTY for timeout path");
    let timeout_pty = timeout_session.pty_pid();
    let timeout_daemon = timeout_session.daemon_pid();
    let timeout_socket = timeout_session.socket_path();
    let timed_out = timeout_session.wait_until_ready(Duration::ZERO);
    assert!(timed_out.is_err(), "readiness predicate must time out");
    timeout_session.reap();
    timeout_session.assert_reaped();
    if let Some(pid) = timeout_pty {
        assert!(
            !crate::support::pid_is_live(pid),
            "timeout-path PTY still live"
        );
    }
    if let Some(pid) = timeout_daemon {
        assert!(
            !crate::support::pid_is_live(pid),
            "timeout-path daemon still live"
        );
    }
    assert!(!timeout_socket.exists(), "timeout-path socket still exists");
    timeout_session.reap();
    timeout_session.assert_reaped();

    let mut panic_ids = None;
    let panicked = catch_unwind(AssertUnwindSafe(|| {
        let panic_session = HermeticCockpit::launch_ready(HermeticProfile::Default);
        panic_ids = Some((
            panic_session.pty_pid(),
            panic_session.daemon_pid(),
            panic_session.socket_path(),
        ));
        assert!(
            panic_session
                .snapshot()
                .contains("this assertion must fail"),
            "forced scenario assertion"
        );
    }));
    assert!(panicked.is_err(), "scenario assertion must panic");
    let (panic_pty, panic_daemon, panic_socket) = panic_ids.expect("panic-path pids recorded");
    if let Some(pid) = panic_pty {
        assert!(
            !crate::support::pid_is_live(pid),
            "panic-path PTY still live"
        );
    }
    if let Some(pid) = panic_daemon {
        assert!(
            !crate::support::pid_is_live(pid),
            "panic-path daemon still live"
        );
    }
    assert!(!panic_socket.exists(), "panic-path socket still exists");
}
