use super::*;
use tempfile::TempDir;

#[cfg(unix)]
const PRIVATE_ATOMIC_WRITE_UMASK_CHILD: &str = "COCKPIT_TEST_PRIVATE_ATOMIC_WRITE_UMASK_CHILD";

#[cfg(unix)]
#[test]
fn provider_atomic_writes_are_private_under_a_permissive_umask() {
    if let Some(root) = std::env::var_os(PRIVATE_ATOMIC_WRITE_UMASK_CHILD) {
        run_private_atomic_write_umask_case(Path::new(&root));
        return;
    }

    let tmp = TempDir::new().unwrap();
    let child_root = tmp.path().join("child");
    let test_name = std::thread::current()
        .name()
        .expect("test thread has a name")
        .to_string();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env(PRIVATE_ATOMIC_WRITE_UMASK_CHILD, &child_root)
        .output()
        .expect("spawn isolated umask regression test");
    assert!(
        output.status.success(),
        "isolated umask regression test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        child_root.join("home/.cockpit/config.json").is_file(),
        "the isolated child test must have executed"
    );
}

#[cfg(unix)]
fn run_private_atomic_write_umask_case(root: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    struct UmaskRestore(libc::mode_t);

    impl Drop for UmaskRestore {
        fn drop(&mut self) {
            // SAFETY: This test runs as the only selected test in a child
            // process, and restores the original process-global umask.
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    std::fs::create_dir_all(root).unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(root);
    // SAFETY: The parent invokes this exact test in a dedicated child process,
    // so no sibling test can observe this deliberately permissive umask.
    let _umask = UmaskRestore(unsafe { libc::umask(0o000) });

    let config_path = root.join("home/.cockpit/config.json");
    let provider_path = provider_file_path_for_config(&config_path, "private-provider").unwrap();
    let mut doc = ConfigDoc::load(&config_path).unwrap();
    let mut cfg = ProvidersConfig {
        active_model: Some(ActiveModelRef {
            provider: "private-provider".into(),
            model: "first-model".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        }),
        ..Default::default()
    };
    cfg.providers.insert(
        "private-provider".into(),
        ProviderEntry {
            url: "https://private.example.test/v1".into(),
            ..Default::default()
        },
    );

    doc.write(&cfg).unwrap();
    assert_private_mode(&config_path, 0o600);
    assert_private_mode(&provider_path, 0o600);
    assert_private_mode(config_path.parent().unwrap(), 0o700);
    assert_private_mode(provider_path.parent().unwrap(), 0o700);

    // Existing product-owned config directories and files must be repaired,
    // not merely protected when they are first created.
    for path in [&config_path, &provider_path] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    for path in [
        config_path.parent().unwrap(),
        provider_path.parent().unwrap(),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    cfg.active_model.as_mut().unwrap().model = "second-model".into();
    cfg.providers.get_mut("private-provider").unwrap().favorite = Some(true);

    doc.write(&cfg).unwrap();
    assert_private_mode(&config_path, 0o600);
    assert_private_mode(&provider_path, 0o600);
    assert_private_mode(config_path.parent().unwrap(), 0o700);
    assert_private_mode(provider_path.parent().unwrap(), 0o700);

    let shared_parent = root.join("shared");
    std::fs::create_dir(&shared_parent).unwrap();
    std::fs::set_permissions(&shared_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let explicit_config = shared_parent.join("explicit-config.json");
    env.set_cockpit_config(&explicit_config);
    let mut explicit_doc = ConfigDoc::load(&explicit_config).unwrap();
    explicit_doc.write(&cfg).unwrap();
    assert_private_mode(&explicit_config, 0o600);
    assert_private_mode(&shared_parent, 0o777);

    // Basename resemblance does not grant ownership to an explicit override.
    let explicit_dot_cockpit = root.join("shared-project/.cockpit");
    std::fs::create_dir_all(&explicit_dot_cockpit).unwrap();
    std::fs::set_permissions(
        &explicit_dot_cockpit,
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let explicit_named_like_default = explicit_dot_cockpit.join("custom.json");
    env.set_cockpit_config(&explicit_named_like_default);
    let mut explicit_named_doc = ConfigDoc::load(&explicit_named_like_default).unwrap();
    explicit_named_doc.write(&cfg).unwrap();
    assert_private_mode(&explicit_named_like_default, 0o600);
    assert_private_mode(&explicit_dot_cockpit, 0o755);

    cfg.active_model.as_mut().unwrap().model = "third-model".into();
    explicit_doc.write(&cfg).unwrap();
    assert_private_mode(&explicit_config, 0o600);
    assert_private_mode(&shared_parent, 0o777);

    // The production helpers use per-create modes and must not alter the
    // process-global umask as part of their normal path.
    // SAFETY: this entire case runs alone in the dedicated child process.
    let observed_umask = unsafe { libc::umask(0o000) };
    unsafe {
        libc::umask(observed_umask);
    }
    assert_eq!(
        observed_umask, 0o000,
        "config writes changed the process umask"
    );
}

#[cfg(unix)]
fn assert_private_mode(path: &Path, expected: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    let actual = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(actual, expected, "unexpected mode for {}", path.display());
}

#[test]
fn active_model_ref_rejects_empty_wire_identity_and_reasoning_effort() {
    for (field, value) in [
        (
            "provider",
            serde_json::json!({ "provider": "", "model": "gpt-5" }),
        ),
        (
            "model",
            serde_json::json!({ "provider": "openai", "model": "" }),
        ),
        (
            "reasoning_effort",
            serde_json::json!({
                "provider": "openai",
                "model": "gpt-5",
                "reasoning_effort": { "value": "" }
            }),
        ),
    ] {
        let error = serde_json::from_value::<ActiveModelRef>(value)
            .expect_err("empty active-model fields must fail deserialization");
        assert!(
            error.to_string().contains("must not be empty"),
            "{field}: {error}"
        );
    }

    let selection: ActiveModelRef = serde_json::from_value(serde_json::json!({
        "provider": "openai",
        "model": "gpt-5",
        "reasoning_effort": { "value": "high" },
        "thinking_mode": "high",
        "prompt_cache_retention": "extended"
    }))
    .expect("complete nonempty selection should deserialize");
    assert_eq!(selection.provider, "openai");
    assert_eq!(selection.model, "gpt-5");
    assert_eq!(
        selection
            .reasoning_effort
            .as_ref()
            .map(|effort| effort.value.as_str()),
        Some("high")
    );
}

#[test]
fn typed_active_model_ref_validation_matches_wire_validation() {
    for selection in [
        ActiveModelRef {
            provider: String::new(),
            model: "gpt-5".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        ActiveModelRef {
            provider: "openai".to_string(),
            model: String::new(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        ActiveModelRef {
            provider: "openai".to_string(),
            model: "gpt-5".to_string(),
            reasoning_effort: Some(ActiveReasoningEffort {
                value: String::new(),
            }),
            thinking_mode: None,
            prompt_cache_retention: None,
        },
    ] {
        assert!(selection.validate().is_err());
    }
}

#[test]
fn capability_value_rejects_empty_advertised_value() {
    let error = serde_json::from_value::<CapabilityValue>(serde_json::json!({ "value": "" }))
        .expect_err("empty advertised capability values must fail deserialization");
    assert!(error.to_string().contains("must not be empty"), "{error}");
}

#[test]
fn atomic_first_default_initialization_has_one_winner_across_file_handles() {
    let tmp = TempDir::new().unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let config_path = tmp.path().join("atomic-config.json");
    std::fs::write(
        &config_path,
        r#"{"active_model":null,"unknown":{"preserve":"yes"}}"#,
    )
    .unwrap();
    env.set_cockpit_config(&config_path);

    let selections = [
        ActiveModelRef {
            provider: "provider-a".into(),
            model: "model-a".into(),
            reasoning_effort: Some(ActiveReasoningEffort {
                value: "high".into(),
            }),
            thinking_mode: Some(ThinkingMode::High),
            prompt_cache_retention: Some(PromptCacheRetention::Extended),
        },
        ActiveModelRef {
            provider: "provider-b".into(),
            model: "model-b".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
    ];
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let handles = selections
        .iter()
        .cloned()
        .map(|selection| {
            let barrier = std::sync::Arc::clone(&barrier);
            let config_path = config_path.clone();
            let cwd = tmp.path().to_path_buf();
            std::thread::spawn(move || {
                barrier.wait();
                ConfigDoc::write_effective_active_model_atomically(
                    &cwd,
                    &config_path,
                    &selection,
                    ActiveModelWriteMode::InitializeIfMissing,
                )
                .unwrap()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        results.iter().filter(|result| result.wrote).count(),
        1,
        "exactly one independently opened lock handle may initialize"
    );
    let raw: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    assert_eq!(raw["unknown"]["preserve"], "yes");
    let final_selection: ActiveModelRef =
        serde_json::from_value(raw["active_model"].clone()).unwrap();
    assert!(selections.contains(&final_selection));
    assert!(
        results
            .iter()
            .all(|result| { result.authoritative_selection.as_ref() == Some(&final_selection) })
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let lock_dir = tmp.path().join("state/cockpit/config-locks");
        assert_eq!(
            std::fs::metadata(&lock_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let lock_files = std::fs::read_dir(&lock_dir)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(lock_files.len(), 1);
        assert_eq!(
            lock_files[0].metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn config_namespace_lock_intersects_home_and_project_targets() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let home_config = tmp.path().join("home/.config/cockpit/config.json");
    let project_root = tmp.path().join("workspace");
    let project_config = project_root.join(".cockpit/config.json");
    std::fs::create_dir_all(home_config.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
    std::fs::write(&home_config, "{}").unwrap();
    std::fs::write(&project_config, "{}").unwrap();

    let trust_policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(&project_root).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    let held_home_lock = crate::config::files::ConfigMutationLock::acquire(&home_config).unwrap();
    let ready = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker_ready = std::sync::Arc::clone(&ready);
    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    let project = project_config.clone();
    let cwd = project_root.clone();
    let handle = std::thread::spawn(move || {
        worker_ready.wait();
        let result = crate::config::trust::with_workspace_trust_policy(trust_policy, || {
            ConfigDoc::write_effective_active_model_atomically(
                &cwd,
                &project,
                &ActiveModelRef {
                    provider: "project-provider".into(),
                    model: "project-model".into(),
                    reasoning_effort: None,
                    thinking_mode: None,
                    prompt_cache_retention: None,
                },
                ActiveModelWriteMode::InitializeIfMissing,
            )
        });
        completed_tx.send(result).unwrap();
    });

    ready.wait();
    assert!(
        matches!(
            completed_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "a project writer must remain blocked while a distinct home-layer lock is held"
    );
    drop(held_home_lock);
    let result = completed_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("project writer completed after the namespace lock was released")
        .unwrap();
    assert!(result.wrote);
    handle.join().unwrap();
}

#[test]
fn cancelled_active_model_lock_waiter_exits_before_owner_releases_lock() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let root = tmp.path().join("workspace");
    let config = root.join(".cockpit/config.json");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "{}").unwrap();

    let held = crate::config::files::ConfigMutationLock::acquire(&config).unwrap();
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_cancelled = std::sync::Arc::clone(&cancelled);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    let worker_root = root.clone();
    let worker_config = config.clone();
    let handle = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = ConfigDoc::prepare_effective_active_model_write_cancellable(
            &worker_root,
            &worker_config,
            &ActiveModelRef {
                provider: "provider-b".into(),
                model: "model-b".into(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            ActiveModelWriteMode::Replace,
            &worker_cancelled,
        )
        .map(drop);
        completed_tx.send(result).unwrap();
    });

    started_rx.recv().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(25));
    cancelled.store(true, std::sync::atomic::Ordering::Release);
    let error = completed_rx
        .recv_timeout(std::time::Duration::from_millis(250))
        .expect("cancelled waiter exits while the original lock remains held")
        .expect_err("cancelled waiter must not acquire the lock");
    assert!(error.to_string().contains("cancelled"));
    handle.join().unwrap();
    drop(held);
}

#[cfg(unix)]
#[test]
fn failed_prepared_active_model_commit_preserves_precommit_authority() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = TempDir::new().unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let workspace = tmp.path().to_path_buf();
    let config = workspace.join("config.json");
    let old = ActiveModelRef {
        provider: "provider-a".into(),
        model: "model-a".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    };
    let target = ActiveModelRef {
        provider: "provider-b".into(),
        model: "model-b".into(),
        reasoning_effort: Some(ActiveReasoningEffort {
            value: "high".into(),
        }),
        thinking_mode: Some(ThinkingMode::High),
        prompt_cache_retention: Some(PromptCacheRetention::Extended),
    };
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({ "active_model": old })).unwrap(),
    )
    .unwrap();
    env.set_cockpit_config(&config);

    let prepared = ConfigDoc::prepare_effective_active_model_write(
        &workspace,
        &config,
        &target,
        ActiveModelWriteMode::Replace,
    )
    .unwrap();
    assert_eq!(prepared.authoritative_selection_before_commit(), Some(&old));
    assert_eq!(prepared.authoritative_selection(), Some(&target));

    let parent = config.parent().unwrap();
    let original_permissions = std::fs::metadata(parent).unwrap().permissions();
    let mut read_only = original_permissions.clone();
    read_only.set_mode(original_permissions.mode() & !0o222);
    std::fs::set_permissions(parent, read_only).unwrap();
    let commit = prepared.commit();
    std::fs::set_permissions(parent, original_permissions).unwrap();

    assert!(
        commit.is_err(),
        "atomic replacement must fail without directory write access"
    );
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_value::<ActiveModelRef>(raw["active_model"].clone()).unwrap(),
        old
    );
}

#[test]
fn stale_project_initialization_keeps_concurrently_established_home_default() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let home_config = tmp.path().join("home/.config/cockpit/config.json");
    let project_root = tmp.path().join("workspace");
    let project_config = project_root.join(".cockpit/config.json");
    std::fs::create_dir_all(home_config.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
    std::fs::write(&home_config, r#"{"home_opaque":true}"#).unwrap();
    std::fs::write(&project_config, r#"{"project_opaque":true}"#).unwrap();

    let trust_policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(&project_root).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    let stale_observed = std::sync::Arc::new(std::sync::Barrier::new(2));
    let home_committed = std::sync::Arc::new(std::sync::Barrier::new(2));
    let project_handle = {
        let cwd = project_root.clone();
        let target = project_config.clone();
        let trust_policy = trust_policy.clone();
        let stale_observed = std::sync::Arc::clone(&stale_observed);
        let home_committed = std::sync::Arc::clone(&home_committed);
        std::thread::spawn(move || {
            crate::config::trust::with_workspace_trust_policy(trust_policy, || {
                assert_eq!(ConfigDoc::load_effective(&cwd).active_model, None);
                stale_observed.wait();
                home_committed.wait();
                ConfigDoc::write_effective_active_model_atomically(
                    &cwd,
                    &target,
                    &ActiveModelRef {
                        provider: "stale-project-provider".into(),
                        model: "stale-project-model".into(),
                        reasoning_effort: None,
                        thinking_mode: Some(ThinkingMode::Low),
                        prompt_cache_retention: None,
                    },
                    ActiveModelWriteMode::InitializeIfMissing,
                )
                .unwrap()
            })
        })
    };

    stale_observed.wait();
    let home_selection = ActiveModelRef {
        provider: "home-provider".into(),
        model: "home-model".into(),
        reasoning_effort: Some(ActiveReasoningEffort {
            value: "high".into(),
        }),
        thinking_mode: Some(ThinkingMode::High),
        prompt_cache_retention: Some(PromptCacheRetention::Extended),
    };
    let home_result =
        crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
            ConfigDoc::write_effective_active_model_atomically(
                &project_root,
                &home_config,
                &home_selection,
                ActiveModelWriteMode::InitializeIfMissing,
            )
            .unwrap()
        });
    assert!(home_result.wrote);
    home_committed.wait();

    let project_result = project_handle.join().unwrap();
    assert!(!project_result.wrote);
    assert_eq!(
        project_result.authoritative_selection,
        Some(home_selection.clone())
    );
    let project_raw: Value =
        serde_json::from_slice(&std::fs::read(&project_config).unwrap()).unwrap();
    assert_eq!(project_raw["project_opaque"], true);
    assert!(project_raw.get("active_model").is_none());
    let _trust = crate::config::trust::enter_workspace_trust_policy(trust_policy);
    assert_eq!(
        ConfigDoc::load_effective(&project_root).active_model,
        Some(home_selection)
    );
}

#[test]
fn atomic_first_default_serializes_home_and_project_layers() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let home_config = tmp.path().join("home/.config/cockpit/config.json");
    let project_root = tmp.path().join("workspace");
    let project_config = project_root.join(".cockpit/config.json");
    std::fs::create_dir_all(home_config.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
    std::fs::write(&home_config, r#"{"home_opaque":"preserved"}"#).unwrap();
    std::fs::write(&project_config, r#"{"project_opaque":"preserved"}"#).unwrap();

    let trust_policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(&project_root).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    let selections = [
        ActiveModelRef {
            provider: "home-provider".into(),
            model: "home-model".into(),
            reasoning_effort: Some(ActiveReasoningEffort {
                value: "high".into(),
            }),
            thinking_mode: Some(ThinkingMode::High),
            prompt_cache_retention: Some(PromptCacheRetention::Extended),
        },
        ActiveModelRef {
            provider: "project-provider".into(),
            model: "project-model".into(),
            reasoning_effort: None,
            thinking_mode: Some(ThinkingMode::Low),
            prompt_cache_retention: Some(PromptCacheRetention::Default),
        },
    ];
    let targets = [home_config.clone(), project_config.clone()];
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let handles = selections
        .iter()
        .cloned()
        .zip(targets.iter().cloned())
        .map(|(selection, target)| {
            let barrier = std::sync::Arc::clone(&barrier);
            let cwd = project_root.clone();
            let trust_policy = trust_policy.clone();
            std::thread::spawn(move || {
                barrier.wait();
                crate::config::trust::with_workspace_trust_policy(trust_policy, || {
                    ConfigDoc::write_effective_active_model_atomically(
                        &cwd,
                        &target,
                        &selection,
                        ActiveModelWriteMode::InitializeIfMissing,
                    )
                    .unwrap()
                })
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        results.iter().filter(|result| result.wrote).count(),
        1,
        "different effective layers must participate in one initialization transaction"
    );
    let _trust = crate::config::trust::enter_workspace_trust_policy(trust_policy);
    let effective = ConfigDoc::load_effective(&project_root)
        .active_model
        .expect("one caller established the effective default");
    assert!(selections.contains(&effective));
    assert!(
        results
            .iter()
            .all(|result| result.authoritative_selection.as_ref() == Some(&effective)),
        "the loser must observe the winner from the other effective layer"
    );

    let home_raw: Value = serde_json::from_slice(&std::fs::read(&home_config).unwrap()).unwrap();
    let project_raw: Value =
        serde_json::from_slice(&std::fs::read(&project_config).unwrap()).unwrap();
    assert_eq!(home_raw["home_opaque"], "preserved");
    assert_eq!(project_raw["project_opaque"], "preserved");
    assert_eq!(
        [
            home_raw.get("active_model"),
            project_raw.get("active_model"),
        ]
        .into_iter()
        .filter(Option::is_some)
        .count(),
        1,
        "the losing layer must not shadow the inherited winner"
    );

    let lock_files = std::fs::read_dir(tmp.path().join("state/cockpit/config-locks"))
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        lock_files.len(),
        1,
        "home and project mutations must resolve to one stable namespace lock"
    );
    assert_eq!(
        lock_files[0].file_name(),
        std::ffi::OsStr::new("effective-config.lock")
    );
}

#[test]
fn stale_ordinary_provider_writes_preserve_atomic_default_unless_explicitly_changed() {
    let tmp = TempDir::new().unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let config_path = tmp.path().join("config.json");
    std::fs::write(
        &config_path,
        r#"{"active_model":null,"unknown":{"before":true}}"#,
    )
    .unwrap();
    write_provider_file(
        &config_path,
        "provider-a",
        r#"{
            "url": "https://example.test/v1",
            "opaque": { "preserve": true },
            "models": [{ "id": "model-a", "name": "Model A" }]
        }"#,
    );
    env.set_cockpit_config(&config_path);

    let mut stale_full_doc = ConfigDoc::load(&config_path).unwrap();
    let mut stale_full_cfg = stale_full_doc.providers();
    stale_full_cfg.on_unlisted_models_fetch = Some(OnUnlistedModelsFetch::Keep);
    stale_full_cfg.providers.get_mut("provider-a").unwrap().name = Some("Renamed Provider".into());
    let mut stale_policy_doc = ConfigDoc::load(&config_path).unwrap();

    let initialized = ActiveModelRef {
        provider: "provider-a".into(),
        model: "model-a".into(),
        reasoning_effort: Some(ActiveReasoningEffort {
            value: "high".into(),
        }),
        thinking_mode: Some(ThinkingMode::High),
        prompt_cache_retention: Some(PromptCacheRetention::Extended),
    };
    let result = ConfigDoc::write_effective_active_model_atomically(
        tmp.path(),
        &config_path,
        &initialized,
        ActiveModelWriteMode::InitializeIfMissing,
    )
    .unwrap();
    assert!(result.wrote);

    let mut current: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    current["unknown_after_load"] = serde_json::json!({ "preserve": true });
    std::fs::write(
        &config_path,
        format!("{}\n", serde_json::to_string_pretty(&current).unwrap()),
    )
    .unwrap();

    stale_policy_doc
        .write_unlisted_models_policy(Some(OnUnlistedModelsFetch::Ask))
        .unwrap();
    let after_policy = ConfigDoc::load(&config_path).unwrap();
    assert_eq!(
        after_policy.providers().active_model,
        Some(initialized.clone())
    );
    assert_eq!(after_policy.raw["unknown_after_load"]["preserve"], true);

    let mut favorite_doc = ConfigDoc::load(&config_path).unwrap();
    favorite_doc
        .write_model_favorite("provider-a", "model-a", true)
        .unwrap();

    stale_full_doc.write(&stale_full_cfg).unwrap();
    let after_stale_full = ConfigDoc::load(&config_path).unwrap();
    assert_eq!(
        after_stale_full.providers().active_model,
        Some(initialized.clone())
    );
    assert_eq!(
        after_stale_full.providers().on_unlisted_models_fetch,
        Some(OnUnlistedModelsFetch::Keep)
    );
    assert_eq!(after_stale_full.raw["unknown_after_load"]["preserve"], true);
    let provider_after_stale_full = read_provider_file(&config_path, "provider-a");
    assert_eq!(
        provider_after_stale_full["models"][0]["favorite"], true,
        "an unchanged favorite from a stale full save must preserve the newer value"
    );
    assert_eq!(provider_after_stale_full["name"], "Renamed Provider");
    assert_eq!(provider_after_stale_full["opaque"]["preserve"], true);

    let mut explicit_favorite_doc = ConfigDoc::load(&config_path).unwrap();
    let mut explicit_favorite_cfg = explicit_favorite_doc.providers();
    explicit_favorite_cfg
        .providers
        .get_mut("provider-a")
        .unwrap()
        .models
        .iter_mut()
        .find(|model| model.id == "model-a")
        .unwrap()
        .favorite = false;
    explicit_favorite_doc.write(&explicit_favorite_cfg).unwrap();
    let provider_after_explicit_favorite = read_provider_file(&config_path, "provider-a");
    assert_eq!(
        provider_after_explicit_favorite["models"][0].get("favorite"),
        None,
        "an explicit favorite edit must win when its locked write runs last"
    );
    assert_eq!(provider_after_explicit_favorite["opaque"]["preserve"], true);

    let mut explicit_doc = ConfigDoc::load(&config_path).unwrap();
    let mut explicit_cfg = explicit_doc.providers();
    let explicitly_selected = ActiveModelRef {
        provider: "provider-b".into(),
        model: "model-b".into(),
        reasoning_effort: None,
        thinking_mode: Some(ThinkingMode::Low),
        prompt_cache_retention: None,
    };
    explicit_cfg.active_model = Some(explicitly_selected.clone());

    let intervening = ActiveModelRef {
        provider: "provider-c".into(),
        model: "model-c".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: Some(PromptCacheRetention::Default),
    };
    ConfigDoc::write_effective_active_model_atomically(
        tmp.path(),
        &config_path,
        &intervening,
        ActiveModelWriteMode::Replace,
    )
    .unwrap();

    explicit_doc.write(&explicit_cfg).unwrap();
    let final_doc = ConfigDoc::load(&config_path).unwrap();
    assert_eq!(
        final_doc.providers().active_model,
        Some(explicitly_selected),
        "an explicit ordinary active-model edit wins after acquiring the shared lock"
    );
    assert_eq!(final_doc.raw["unknown_after_load"]["preserve"], true);
}

fn write_provider_file(config_path: &Path, provider_id: &str, json: &str) {
    let path = provider_file_path_for_config(config_path, provider_id).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, json).unwrap();
}

fn read_provider_file(config_path: &Path, provider_id: &str) -> Value {
    let path = provider_file_path_for_config(config_path, provider_id).unwrap();
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn enter_trusted_workspace(root: &Path) -> crate::config::trust::ThreadWorkspaceTrustGuard {
    crate::config::trust::enter_workspace_trust_policy(crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(root).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    })
}

#[derive(Clone)]
struct SharedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

struct LogWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLog {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter(std::sync::Arc::clone(&self.0))
    }
}

fn capture_warn_logs(f: impl FnOnce()) -> String {
    let sink = SharedLog(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .with_ansi(false)
        .with_writer(sink.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8(sink.0.lock().unwrap().clone()).unwrap()
}

#[test]
fn provider_default_resolvers_match_model_resolvers_without_overrides() {
    let mut cfg = ProvidersConfig::default();
    let mut provider = ProviderEntry {
        url: "https://example.test/v1".to_string(),
        trust: Some(ModelTrust::Trusted),
        subagent_invokable: Some(true),
        can_delegate: Some(false),
        default_thinking_mode: Some(ThinkingMode::High),
        mode: Some(LlmMode::Frontier),
        ..Default::default()
    };
    provider.models.push(ModelEntry {
        id: "m".to_string(),
        ..Default::default()
    });
    cfg.providers.insert("p".to_string(), provider);
    let global = LlmMode::Normal;

    assert_eq!(cfg.resolve_trust("p", "m"), cfg.provider_trust_default("p"));
    assert_eq!(
        cfg.resolve_subagent_invokable("p", "m"),
        cfg.provider_subagent_invokable_default("p")
    );
    assert_eq!(
        cfg.resolve_can_delegate("p", "m"),
        cfg.provider_can_delegate_default("p")
    );
    assert_eq!(
        cfg.resolve_default_thinking_mode("p", "m"),
        cfg.provider_default_thinking_mode_default("p")
    );
    assert_eq!(
        cfg.resolve_mode("p", "m", global),
        cfg.provider_mode_default("p", global)
    );

    assert_eq!(cfg.provider_trust_default("missing"), ModelTrust::Untrusted);
    assert!(!cfg.provider_subagent_invokable_default("missing"));
    assert!(cfg.provider_can_delegate_default("missing"));
    assert_eq!(cfg.provider_mode_default("missing", global), global);
}

#[test]
fn round_trips_a_provider_entry() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ConfigDoc::load(&path).unwrap();
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "opencode-zen".to_string(),
        ProviderEntry {
            name: Some("OpenCode Zen".into()),
            template: Some("opencode-zen".into()),
            url: "https://opencode.ai/zen/v1".into(),
            headers: vec![HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $OPENCODE_ZEN_TOKEN".into(),
            }],
            models_fetched_at: None,
            model_catalog: ProviderModelCatalog::Live,
            favorite: Some(true),
            allow_insecure_http: false,
            credential_ref: None,
            auth: Some(AuthKind::ApiKey),
            trust: None,
            location: None,
            quality_rank: None,
            cost_rank: None,
            subagent_invokable: None,
            can_delegate: Some(false),
            computer_use: Some(crate::config::extended::ComputerUseMode::Ask),
            default_thinking_mode: Some(ThinkingMode::High),
            embeddings: None,
            availability: Default::default(),
            cache: CacheConfig::default(),
            shrink: ShrinkConfig::default(),
            context: ContextConfig::default(),
            auto_prune: None,
            timeout: TimeoutConfig::default(),
            wire_api: WireApi::default(),
            backup: None,
            mode: None,
            inline_think: None,
            hint_tool_call_corrections: None,
            text_embedded_recovery: None,
            thinking_params: Default::default(),
            models: vec![ModelEntry {
                id: "claude-opus-4-7".into(),
                name: Some("Claude Opus 4.7".into()),
                thinking_modes: vec![ThinkingMode::Off, ThinkingMode::High],
                context_length: None,
                favorite: false,
                manual: false,
                trust: None,
                location: None,
                quality_rank: None,
                cost_rank: None,
                subagent_invokable: None,
                can_delegate: Some(true),
                computer_use: Some(crate::config::extended::ComputerUseMode::Yolo),
                default_thinking_mode: Some(ThinkingMode::Low),
                embeddings: None,
                embedding_dimensions: None,
                availability: Default::default(),
                cache: None,
                shrink: None,
                context: None,
                auto_prune: None,
                timeout: None,
                backup: None,
                mode: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                system_prompt: None,
                wire_api: WireApi::default(),
                inputs: Some(Inputs {
                    images: Some(true),
                    video: None,
                    audio: None,
                }),
                extra: Default::default(),
                capabilities: Default::default(),
                capability_overrides: Default::default(),
                provider_metadata: Default::default(),
            }],
            capabilities: Default::default(),
            provider_metadata: Default::default(),
            last_model_fetch: None,
        },
    );
    cfg.on_unlisted_models_fetch = Some(OnUnlistedModelsFetch::Ask);
    doc.write(&cfg).unwrap();

    let doc2 = ConfigDoc::load(&path).unwrap();
    let cfg2 = doc2.providers();
    let entry = cfg2.providers.get("opencode-zen").unwrap();
    assert_eq!(entry.url, "https://opencode.ai/zen/v1");
    assert_eq!(entry.headers.len(), 1);
    assert_eq!(entry.favorite, Some(true));
    assert_eq!(entry.can_delegate, Some(false));
    assert_eq!(entry.models[0].id, "claude-opus-4-7");
    assert_eq!(entry.models[0].can_delegate, Some(true));
    assert_eq!(
        cfg2.on_unlisted_models_fetch,
        Some(OnUnlistedModelsFetch::Ask)
    );
}

#[test]
fn provider_write_removes_stale_skipped_optional_fields_but_keeps_empty_models() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    write_provider_file(
        &path,
        "p",
        r#"{
                "url": "https://example.test/v1",
                "name": "Pretty",
                "allow_insecure_http": true,
                "favorite": true,
                "trust": "trusted",
                "location": "local",
                "quality_rank": 9,
                "cost_rank": 1,
                "subagent_invokable": true,
                "can_delegate": true,
                "mode": "frontier",
                "inline_think": false,
                "hint_tool_call_corrections": true,
                "text_embedded_recovery": "off",
                "thinking_params": { "high": { "reasoning_effort": "high" } },
                "provider_metadata": { "vendor": "x" },
                "models": [{ "id": "m", "name": "Model Name", "favorite": true }]
            }"#,
    );

    let mut doc = ConfigDoc::load(&path).unwrap();
    let mut cfg = doc.providers();
    let provider = cfg.providers.get_mut("p").unwrap();
    provider.name = None;
    provider.allow_insecure_http = false;
    provider.favorite = None;
    provider.trust = None;
    provider.location = None;
    provider.quality_rank = None;
    provider.cost_rank = None;
    provider.subagent_invokable = None;
    provider.can_delegate = None;
    provider.mode = None;
    provider.inline_think = None;
    provider.hint_tool_call_corrections = None;
    provider.text_embedded_recovery = None;
    provider.thinking_params = ThinkingParams::default();
    provider.provider_metadata.clear();
    let model = provider.models.get_mut(0).unwrap();
    model.name = None;
    model.favorite = false;
    provider.models.clear();
    doc.write(&cfg).unwrap();

    let provider_path = provider_file_path_for_config(&path, "p").unwrap();
    let raw: Value =
        serde_json::from_str(&std::fs::read_to_string(provider_path).unwrap()).unwrap();
    let obj = raw.as_object().unwrap();
    for key in [
        "name",
        "allow_insecure_http",
        "favorite",
        "trust",
        "location",
        "quality_rank",
        "cost_rank",
        "subagent_invokable",
        "can_delegate",
        "mode",
        "inline_think",
        "hint_tool_call_corrections",
        "text_embedded_recovery",
        "thinking_params",
        "provider_metadata",
    ] {
        assert!(
            !obj.contains_key(key),
            "stale provider key `{key}` remained: {raw}"
        );
    }
    assert_eq!(obj.get("models"), Some(&Value::Array(vec![])));
}

#[test]
fn preserves_unknown_fields() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{"providers":{},"agents":{"foo":"bar"},"misc":[1,2,3]}"#,
    )
    .unwrap();
    let mut doc = ConfigDoc::load(&path).unwrap();
    doc.write(&ProvidersConfig::default()).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"agents\""));
    assert!(on_disk.contains("\"misc\""));
}

#[test]
fn skips_malformed_provider_entry_warning_only() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    write_provider_file(&path, "good", r#"{"url":"https://x"}"#);
    write_provider_file(&path, "bad", "42");
    let doc = ConfigDoc::load(&path).unwrap();
    let cfg = doc.providers();
    assert!(cfg.providers.contains_key("good"));
    assert!(!cfg.providers.contains_key("bad"));
}

#[test]
fn malformed_provider_metadata_and_inline_provider_entries_warn_on_drop() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    let top_level_doc = ConfigDoc {
        path: path.clone(),
        raw: serde_json::json!({
            "on_unlisted_models_fetch": "explode",
            "active_model": { "model": "missing-provider" },
            "category_defaults": { "cheap_code": { "provider": "p" } }
        }),
        originally_loaded_providers: BTreeMap::new(),
    };
    let inline_doc = ConfigDoc {
        path: PathBuf::new(),
        raw: serde_json::json!({ "providers": { "bad": 42 } }),
        originally_loaded_providers: BTreeMap::new(),
    };

    let logs = capture_warn_logs(|| {
        let _ = top_level_doc.providers();
        let _ = inline_doc.providers();
    });

    assert!(logs.contains(path.to_string_lossy().as_ref()), "{logs}");
    assert!(logs.contains("on_unlisted_models_fetch"), "{logs}");
    assert!(logs.contains("active_model"), "{logs}");
    assert!(logs.contains("category_defaults"), "{logs}");
    assert!(logs.contains("bad"), "{logs}");
    assert!(
        logs.contains("skipping malformed inline provider entry"),
        "{logs}"
    );
}

#[test]
fn label_falls_back_to_id() {
    let entry = ProviderEntry::default();
    assert_eq!(entry.label("my-id"), "my-id");
    let entry = ProviderEntry {
        name: Some("Pretty".into()),
        ..Default::default()
    };
    assert_eq!(entry.label("ignored"), "Pretty");
}

#[test]
fn cache_defaults_to_none() {
    let entry = ProviderEntry::default();
    assert_eq!(entry.cache.mode, CacheMode::None);
    assert_eq!(entry.cache.ttl_secs, 300);
}

#[test]
fn resolve_cache_prefers_model_override() {
    let mut cfg = ProvidersConfig::default();
    let mut entry = ProviderEntry {
        url: "https://x".into(),
        cache: CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 600,
        },
        ..ProviderEntry::default()
    };
    entry.models.push(ModelEntry {
        id: "fast".into(),
        name: None,
        thinking_modes: vec![],
        context_length: None,
        favorite: false,
        manual: false,
        trust: None,
        location: None,
        quality_rank: None,
        cost_rank: None,
        subagent_invokable: None,
        can_delegate: None,
        computer_use: None,
        default_thinking_mode: None,
        embeddings: None,
        embedding_dimensions: None,
        availability: Default::default(),
        cache: Some(CacheConfig {
            mode: CacheMode::None,
            ttl_secs: 300,
        }),
        shrink: None,
        context: None,
        auto_prune: None,
        timeout: None,
        backup: None,
        mode: None,
        inline_think: None,
        hint_tool_call_corrections: None,
        text_embedded_recovery: None,
        thinking_params: Default::default(),
        system_prompt: None,
        wire_api: WireApi::default(),
        inputs: None,
        extra: Default::default(),
        capabilities: Default::default(),
        capability_overrides: Default::default(),
        provider_metadata: Default::default(),
    });
    cfg.providers.insert("p".into(), entry);

    // Model with an override wins.
    let m = cfg.resolve_cache("p", "fast");
    assert_eq!(m.mode, CacheMode::None);
    // Model without an override inherits the provider config.
    let p = cfg.resolve_cache("p", "other");
    assert_eq!(p.mode, CacheMode::Ephemeral);
    assert_eq!(p.ttl_secs, 600);
    // Unknown provider → default (none).
    assert_eq!(cfg.resolve_cache("nope", "x").mode, CacheMode::None);
}

/// The `ttl_secs` lever maps to the Anthropic TTL mode (prompt
/// `prompt-caching-strategy.md`, decision 4): `>= 3600` selects the
/// 1-hour extended cache; the default and anything below stay 5-minute.
#[test]
fn cache_ttl_selects_one_hour_mode_at_or_above_3600() {
    // Default is 300s → 5-minute.
    assert!(!CacheConfig::default().wants_one_hour_ttl());
    // Just below the threshold → still 5-minute.
    assert!(
        !CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 3599,
        }
        .wants_one_hour_ttl()
    );
    // Exactly the threshold → 1-hour.
    assert!(
        CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 3600,
        }
        .wants_one_hour_ttl()
    );
    // Well above → 1-hour.
    assert!(
        CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 86_400,
        }
        .wants_one_hour_ttl()
    );
}

#[test]
fn context_config_defaults_nudge_60_auto_compact_unset() {
    let c = ContextConfig::default();
    assert_eq!(c.auto_compact_pct, None);
    assert_eq!(c.compact_nudge_pct, 60);
    assert_eq!(c.compact_keep_recent_turns, 4);
    assert!(c.compact_shadow);
    assert_eq!(c.compact_shadow_margin_pct, 10);
    assert_eq!(c.auto_prune_pct, 50);
    assert_eq!(c.auto_prune_prunable_pct, 30);
    // Older configs (no `context` key) load with the defaults.
    let entry = ProviderEntry::default();
    assert_eq!(entry.context, ContextConfig::default());
    assert!(entry.mode.is_none());
    let missing_json: ContextConfig = serde_json::from_value(serde_json::json!({})).unwrap();
    assert_eq!(missing_json.auto_compact_pct, None);
    assert_eq!(missing_json.compact_nudge_pct, 60);

    let legacy: ContextConfig = serde_json::from_value(serde_json::json!({
        "auto_compact_pct": 77,
        "compact_nudge_pct": 58,
        "auto_prune_pct": 44,
        "auto_prune_prunable_pct": 22
    }))
    .unwrap();
    assert_eq!(legacy.auto_compact_pct, Some(77));
    assert_eq!(legacy.compact_nudge_pct, 58);
    assert_eq!(legacy.compact_keep_recent_turns, 4);
    assert!(legacy.compact_shadow);
    assert_eq!(legacy.compact_shadow_margin_pct, 10);
    let encoded = serde_json::to_value(&legacy).unwrap();
    assert_eq!(encoded["auto_compact_pct"], 77);
}

#[test]
fn resolve_context_prefers_model_then_provider_then_default() {
    let mut cfg = ProvidersConfig::default();
    let mut entry = ProviderEntry {
        url: "https://x".into(),
        context: ContextConfig {
            auto_compact_pct: Some(90),
            compact_nudge_pct: 60,
            compact_keep_recent_turns: 2,
            compact_shadow: true,
            compact_shadow_margin_pct: 10,
            auto_prune_pct: 60,
            auto_prune_prunable_pct: 40,
        },
        ..ProviderEntry::default()
    };
    let mut pinned = model("pinned", false);
    pinned.context = Some(ContextConfig {
        auto_compact_pct: Some(70),
        compact_nudge_pct: 55,
        compact_keep_recent_turns: 1,
        compact_shadow: false,
        compact_shadow_margin_pct: 12,
        auto_prune_pct: 55,
        auto_prune_prunable_pct: 25,
    });
    entry.models.push(pinned);
    entry.models.push(model("bare", false));
    cfg.providers.insert("p".into(), entry);

    // Model override wins.
    assert_eq!(
        cfg.resolve_context("p", "pinned").auto_compact_pct,
        Some(70)
    );
    assert_eq!(cfg.resolve_context("p", "pinned").compact_nudge_pct, 55);
    // No model override → provider value.
    assert_eq!(cfg.resolve_context("p", "bare").auto_compact_pct, Some(90));
    assert_eq!(cfg.resolve_context("p", "bare").compact_nudge_pct, 60);
    assert_eq!(cfg.resolve_context("p", "bare").auto_prune_pct, 60);
    // Unknown provider → built-in default.
    assert_eq!(cfg.resolve_context("nope", "x"), ContextConfig::default());
}

#[test]
fn resolve_timeout_prefers_model_then_provider_then_default() {
    // Stream-timeout resolution: model override → provider value → built-in
    // default (implementation note).
    let mut cfg = ProvidersConfig::default();
    let mut entry = ProviderEntry {
        url: "https://x".into(),
        timeout: TimeoutConfig {
            ttft_secs: 200,
            idle_secs: 100,
        },
        ..ProviderEntry::default()
    };
    let mut pinned = model("pinned", false);
    pinned.timeout = Some(TimeoutConfig {
        ttft_secs: 45,
        idle_secs: 30,
    });
    entry.models.push(pinned);
    entry.models.push(model("bare", false));
    cfg.providers.insert("p".into(), entry);

    // Model override wins.
    let m = cfg.resolve_timeout("p", "pinned");
    assert_eq!(m.ttft_secs, 45);
    assert_eq!(m.idle_secs, 30);
    // No model override → provider value.
    let p = cfg.resolve_timeout("p", "bare");
    assert_eq!(p.ttft_secs, 200);
    assert_eq!(p.idle_secs, 100);
    // Unknown provider → built-in default (120s TTFT, 90s idle).
    assert_eq!(cfg.resolve_timeout("nope", "x"), TimeoutConfig::default());
    assert_eq!(TimeoutConfig::default().ttft_secs, 120);
    assert_eq!(TimeoutConfig::default().idle_secs, 90);
}

#[test]
fn providers_from_paths_replaces_active_model_atomically() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home").join("config.json");
    let project = tmp.path().join("project").join("config.json");
    std::fs::create_dir_all(home.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project.parent().unwrap()).unwrap();
    std::fs::write(
            &home,
            r#"{"active_model":{"provider":"home","model":"old","reasoning_effort":{"value":"high"},"thinking_mode":"high"}}"#,
        )
        .unwrap();
    std::fs::write(
        &project,
        r#"{"active_model":{"provider":"project","model":"new"}}"#,
    )
    .unwrap();

    let cfg = ConfigDoc::providers_from_paths(&[home, project]);
    let active = cfg.active_model.expect("project active model survives");

    assert_eq!(active.provider, "project");
    assert_eq!(active.model, "new");
    assert_eq!(active.reasoning_effort, None);
    assert_eq!(active.thinking_mode, None);
}

#[test]
fn providers_from_paths_merges_layers_with_project_model_setting_winning() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home").join("config.json");
    let project = tmp.path().join("project").join("config.json");
    std::fs::create_dir_all(home.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project.parent().unwrap()).unwrap();
    std::fs::write(&home, "{}").unwrap();
    std::fs::write(&project, "{}").unwrap();
    write_provider_file(
        &home,
        "p",
        r#"{
                "url": "https://home.example/v1",
                "timeout": { "ttft_secs": 200, "idle_secs": 100 },
                "models": [
                    { "id": "m", "timeout": { "ttft_secs": 80, "idle_secs": 40 } }
                ]
            }"#,
    );
    write_provider_file(
        &project,
        "p",
        r#"{
                "models": [
                    { "id": "m", "timeout": { "ttft_secs": 20, "idle_secs": 10 } }
                ]
            }"#,
    );

    let cfg = ConfigDoc::providers_from_paths(&[home, project]);

    let provider = cfg.providers.get("p").expect("provider survives merge");
    assert_eq!(provider.url, "https://home.example/v1");
    let timeout = cfg.resolve_timeout("p", "m");
    assert_eq!(timeout.ttft_secs, 20);
    assert_eq!(timeout.idle_secs, 10);
}

#[test]
fn project_url_override_does_not_inherit_home_credential() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home/config.json");
    let project = tmp.path().join("project/config.json");
    std::fs::create_dir_all(home.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project.parent().unwrap()).unwrap();
    std::fs::write(&home, "{}").unwrap();
    std::fs::write(&project, "{}").unwrap();
    write_provider_file(
        &home,
        "p",
        r#"{ "url": "https://home.example/v1", "credential_ref": "home-token", "headers": [{"name":"Authorization","value":"Bearer :home-token"}] }"#,
    );
    write_provider_file(&project, "p", r#"{ "url": "https://project.example/v1" }"#);

    let cfg = ConfigDoc::providers_from_paths(&[home, project]);
    let provider = cfg.providers.get("p").unwrap();
    assert_eq!(provider.url, "https://project.example/v1");
    assert!(provider.credential_ref.is_none());
    assert!(provider.headers.is_empty());
}

#[test]
fn providers_from_paths_merges_model_arrays_by_id_without_dropping_home_models() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home").join("config.json");
    let project = tmp.path().join("project").join("config.json");
    std::fs::create_dir_all(home.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project.parent().unwrap()).unwrap();
    std::fs::write(&home, "{}").unwrap();
    std::fs::write(&project, "{}").unwrap();
    write_provider_file(
        &home,
        "p",
        r#"{
                "url": "https://home.example/v1",
                "models": [
                    { "id": "m1", "name": "Model One", "favorite": true },
                    {
                        "id": "m2",
                        "name": "Model Two",
                        "wire_api": "responses",
                        "timeout": { "ttft_secs": 80, "idle_secs": 40 }
                    },
                    { "id": "m3", "name": "Model Three" }
                ]
            }"#,
    );
    write_provider_file(
        &project,
        "p",
        r#"{
                "models": [
                    { "id": "m2", "timeout": { "ttft_secs": 20, "idle_secs": 10 } }
                ]
            }"#,
    );

    let cfg = ConfigDoc::providers_from_paths(&[home, project]);

    let models = &cfg.providers.get("p").expect("provider survives").models;
    assert_eq!(
        models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        vec!["m1", "m2", "m3"]
    );
    let m2 = models.iter().find(|m| m.id == "m2").unwrap();
    assert_eq!(m2.name.as_deref(), Some("Model Two"));
    assert_eq!(m2.wire_api, WireApi::Responses);
    let timeout = m2.timeout.as_ref().unwrap();
    assert_eq!(timeout.ttft_secs, 20);
    assert_eq!(timeout.idle_secs, 10);
}

#[test]
fn raw_provider_model_write_preserves_layered_provider_fields() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let home = tmp.path().join("home").join("config.json");
    let project = tmp.path().join("project").join("config.json");
    std::fs::create_dir_all(home.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project.parent().unwrap()).unwrap();
    std::fs::write(&home, r#"{"on_unlisted_models_fetch": "keep"}"#).unwrap();
    std::fs::write(&project, "{}").unwrap();
    write_provider_file(
        &home,
        "p",
        r#"{
                "url": "https://home.example/v1",
                "headers": [
                    { "name": "Authorization", "value": "Bearer $TOKEN" }
                ],
                "models": [
                    { "id": "old", "name": "Old Model" }
                ]
            }"#,
    );

    let _trust = enter_trusted_workspace(tmp.path());
    let mut fetched = model("new", false);
    fetched.name = Some("New Model".to_string());
    let fetched_at = Utc::now();
    let mut doc = ConfigDoc::load(&project).unwrap();
    doc.write_provider_models(
        "p",
        &[fetched],
        Some(fetched_at),
        ProviderModelCatalog::Live,
        Some(ModelFetchStatus {
            status: ModelFetchStatusKind::Live,
            at: fetched_at,
            source: ModelFetchSource::Live,
            reason: None,
        }),
    )
    .unwrap();

    let raw: Value = serde_json::from_slice(&std::fs::read(&project).unwrap()).unwrap();
    let provider_raw = read_provider_file(&project, "p");
    let provider = provider_raw.as_object().unwrap();
    assert!(!provider.contains_key("url"));
    assert!(!provider.contains_key("headers"));
    assert!(provider.contains_key("models"));
    assert!(provider.contains_key("models_fetched_at"));
    assert!(
        !raw.as_object()
            .unwrap()
            .contains_key("on_unlisted_models_fetch")
    );

    let cfg = ConfigDoc::providers_from_paths(&[home, project]);
    let provider = cfg.providers.get("p").unwrap();
    assert_eq!(provider.url, "https://home.example/v1");
    assert_eq!(provider.headers.len(), 1);
    assert_eq!(
        provider
            .models
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        vec!["old", "new"]
    );
    assert_eq!(
        cfg.on_unlisted_models_fetch,
        Some(OnUnlistedModelsFetch::Keep)
    );
}

#[test]
fn raw_model_favorite_write_is_partial_model_override() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let home = tmp.path().join("home").join("config.json");
    let project = tmp.path().join("project").join("config.json");
    std::fs::create_dir_all(home.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project.parent().unwrap()).unwrap();
    std::fs::write(&home, "{}").unwrap();
    std::fs::write(&project, "{}").unwrap();
    write_provider_file(
        &home,
        "p",
        r#"{
                "url": "https://home.example/v1",
                "models": [
                    { "id": "m", "name": "Model M" }
                ]
            }"#,
    );

    let mut doc = ConfigDoc::load(&project).unwrap();
    doc.write_model_favorite("p", "m", true).unwrap();

    let provider_raw = read_provider_file(&project, "p");
    let provider = provider_raw.as_object().unwrap();
    assert!(!provider.contains_key("url"));
    let model = provider
        .get("models")
        .and_then(Value::as_array)
        .and_then(|models| models.first())
        .and_then(Value::as_object)
        .unwrap();
    assert_eq!(model.get("id").and_then(Value::as_str), Some("m"));
    assert_eq!(model.get("favorite").and_then(Value::as_bool), Some(true));
    assert!(!model.contains_key("name"));

    let cfg = ConfigDoc::providers_from_paths(&[home, project]);
    let model = cfg
        .providers
        .get("p")
        .unwrap()
        .models
        .iter()
        .find(|m| m.id == "m")
        .unwrap();
    assert_eq!(model.name.as_deref(), Some("Model M"));
    assert!(model.favorite);
}

#[test]
fn providers_from_paths_appends_new_models_and_empty_overlay_is_noop() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home").join("config.json");
    let project = tmp.path().join("project").join("config.json");
    let empty_project = tmp.path().join("empty-project").join("config.json");
    std::fs::create_dir_all(home.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project.parent().unwrap()).unwrap();
    std::fs::create_dir_all(empty_project.parent().unwrap()).unwrap();
    std::fs::write(&home, "{}").unwrap();
    std::fs::write(&project, "{}").unwrap();
    std::fs::write(&empty_project, "{}").unwrap();
    write_provider_file(
        &home,
        "p",
        r#"{
                "url": "https://home.example/v1",
                "models": [
                    { "id": "m1", "name": "Model One" },
                    { "id": "m2", "name": "Model Two" }
                ]
            }"#,
    );
    write_provider_file(
        &project,
        "p",
        r#"{"models":[{"id":"m3","name":"Model Three"}]}"#,
    );
    write_provider_file(&empty_project, "p", r#"{"models":[]}"#);

    let cfg = ConfigDoc::providers_from_paths(&[home.clone(), project]);
    let models = &cfg.providers.get("p").expect("provider survives").models;
    assert_eq!(
        models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        vec!["m1", "m2", "m3"]
    );

    let cfg = ConfigDoc::providers_from_paths(&[home, empty_project]);
    let models = &cfg.providers.get("p").expect("provider survives").models;
    assert_eq!(
        models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        vec!["m1", "m2"]
    );
}

#[test]
fn resolve_backup_prefers_model_then_provider_then_none() {
    // Backup-model resolution: model override → provider value → None
    // (implementation note). The backup may name a
    // DIFFERENT provider than the primary.
    let mut cfg = ProvidersConfig::default();
    let mut entry = ProviderEntry {
        url: "https://x".into(),
        // Provider-level backup points at a different provider.
        backup: Some(BackupConfig {
            provider: "reliable".into(),
            model: "claude-sonnet-4-6".into(),
        }),
        ..ProviderEntry::default()
    };
    let mut pinned = model("pinned", false);
    pinned.backup = Some(BackupConfig {
        provider: "other-reliable".into(),
        model: "gpt-mini".into(),
    });
    entry.models.push(pinned);
    entry.models.push(model("bare", false));
    cfg.providers.insert("flaky".into(), entry);

    // Model override wins (and can name yet another provider).
    let m = cfg.resolve_backup("flaky", "pinned").unwrap();
    assert_eq!(m.provider, "other-reliable");
    assert_eq!(m.model, "gpt-mini");
    // No model override → the provider-level backup (different provider).
    let p = cfg.resolve_backup("flaky", "bare").unwrap();
    assert_eq!(p.provider, "reliable");
    assert_eq!(p.model, "claude-sonnet-4-6");
    // Unknown provider → no backup (hard-fail).
    assert!(cfg.resolve_backup("nope", "x").is_none());
    // A provider with neither tier set → no backup.
    let mut cfg2 = ProvidersConfig::default();
    cfg2.providers.insert(
        "none".into(),
        ProviderEntry {
            url: "https://y".into(),
            models: vec![model("m", false)],
            ..ProviderEntry::default()
        },
    );
    assert!(cfg2.resolve_backup("none", "m").is_none());
}

/// An unset `backup` is skipped on serialize at both scopes (configs that
/// never pin one stay clean), and a configured one round-trips.
#[test]
fn backup_skipped_on_serialize_when_unset_and_round_trips() {
    let unset = ProviderEntry::default();
    let json = serde_json::to_string(&unset).unwrap();
    assert!(!json.contains("backup"));
    let unset_model = model("m", false);
    let json = serde_json::to_string(&unset_model).unwrap();
    assert!(!json.contains("backup"));

    let set = ProviderEntry {
        backup: Some(BackupConfig {
            provider: "reliable".into(),
            model: "claude-sonnet-4-6".into(),
        }),
        ..ProviderEntry::default()
    };
    let json = serde_json::to_string(&set).unwrap();
    assert!(json.contains("\"backup\""));
    let back: ProviderEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.backup, set.backup);
}

#[test]
fn resolve_mode_falls_through_model_provider_global() {
    let mut cfg = ProvidersConfig::default();
    let mut entry = ProviderEntry {
        url: "https://x".into(),
        mode: Some(LlmMode::Defensive),
        ..ProviderEntry::default()
    };
    let mut pinned = model("pinned", false);
    pinned.mode = Some(LlmMode::Frontier);
    entry.models.push(pinned);
    entry.models.push(model("bare", false));
    cfg.providers.insert("p".into(), entry);

    // Model override beats provider + global.
    assert_eq!(
        cfg.resolve_mode("p", "pinned", LlmMode::Defensive),
        LlmMode::Frontier
    );
    // No model override → provider override beats the global.
    assert_eq!(
        cfg.resolve_mode("p", "bare", LlmMode::Normal),
        LlmMode::Defensive
    );
    // Provider with no mode override → global wins.
    let mut cfg2 = ProvidersConfig::default();
    cfg2.providers.insert(
        "q".into(),
        ProviderEntry {
            url: "https://y".into(),
            inline_think: None,
            hint_tool_call_corrections: None,
            text_embedded_recovery: None,
            models: vec![model("m", false)],
            ..ProviderEntry::default()
        },
    );
    assert_eq!(
        cfg2.resolve_mode("q", "m", LlmMode::Normal),
        LlmMode::Normal
    );
    // Unknown provider → global.
    assert_eq!(
        cfg.resolve_mode("nope", "x", LlmMode::Normal),
        LlmMode::Normal
    );
}

#[test]
fn mode_undefined_serializes_as_absent() {
    // A model with no `mode`/`context` override omits both keys entirely
    // (parse to a map so the `cache.mode` inner key can't false-match).
    let v: Value = serde_json::to_value(model("x", false)).unwrap();
    let obj = v.as_object().unwrap();
    assert!(!obj.contains_key("mode"), "undefined mode is absent");
    assert!(!obj.contains_key("context"), "absent context override");
    // A provider with no `mode` override omits the top-level key.
    let entry = ProviderEntry {
        url: "https://x".into(),
        ..ProviderEntry::default()
    };
    let pv: Value = serde_json::to_value(&entry).unwrap();
    assert!(!pv.as_object().unwrap().contains_key("mode"));
    // A pinned model mode serializes its lowercase spelling.
    let mut m = model("x", false);
    m.mode = Some(LlmMode::Frontier);
    let mv: Value = serde_json::to_value(&m).unwrap();
    assert_eq!(mv.get("mode").and_then(Value::as_str), Some("frontier"));
}

/// Minimal `ModelEntry` for the merge tests.
fn model(id: &str, manual: bool) -> ModelEntry {
    ModelEntry {
        id: id.to_string(),
        name: None,
        thinking_modes: vec![],
        inputs: None,
        context_length: None,
        favorite: false,
        manual,
        trust: None,
        location: None,
        quality_rank: None,
        cost_rank: None,
        subagent_invokable: None,
        can_delegate: None,
        computer_use: None,
        default_thinking_mode: None,
        embeddings: None,
        embedding_dimensions: None,
        availability: Default::default(),
        cache: None,
        shrink: None,
        context: None,
        auto_prune: None,
        timeout: None,
        backup: None,
        mode: None,
        inline_think: None,
        hint_tool_call_corrections: None,
        text_embedded_recovery: None,
        thinking_params: Default::default(),
        system_prompt: None,
        wire_api: WireApi::default(),
        extra: Default::default(),
        capabilities: Default::default(),
        capability_overrides: Default::default(),
        provider_metadata: Default::default(),
    }
}

#[test]
fn model_system_prompt_serializes_only_when_set_and_resolves_nonblank() {
    let unset = model("m", false);
    let unset_json = serde_json::to_string(&unset).unwrap();
    assert!(!unset_json.contains("system_prompt"), "{unset_json}");

    let mut set = model("m", false);
    set.system_prompt = Some("line one\nUnicode: café".to_string());
    let set_json = serde_json::to_string(&set).unwrap();
    assert!(set_json.contains("system_prompt"), "{set_json}");
    let parsed: ModelEntry = serde_json::from_str(&set_json).unwrap();
    assert_eq!(parsed.system_prompt, set.system_prompt);

    let mut cfg = ProvidersConfig::default();
    let mut provider = ProviderEntry::default();
    provider.models.push(set);
    let mut blank = model("blank", false);
    blank.system_prompt = Some("   \n\t".to_string());
    provider.models.push(blank);
    cfg.providers.insert("p".into(), provider);

    assert_eq!(
        cfg.resolve_model_system_prompt("p", "m"),
        Some("line one\nUnicode: café")
    );
    assert_eq!(cfg.resolve_model_system_prompt("p", "blank"), None);
}

#[test]
fn layered_model_system_prompt_project_overrides_and_removal_reveals_home() {
    let home_dir = TempDir::new().unwrap();
    let project_dir = TempDir::new().unwrap();
    let home = home_dir.path().join("config.json");
    let project = project_dir.path().join("config.json");
    std::fs::write(&home, "{}").unwrap();
    std::fs::write(&project, "{}").unwrap();
    write_provider_file(
        &home,
        "p",
        r#"{"url":"https://home.example.test/v1","models":[{"id":"m","system_prompt":"home prompt"}]}"#,
    );
    write_provider_file(
        &project,
        "p",
        r#"{"models":[{"id":"m","system_prompt":"project prompt"}]}"#,
    );

    let cfg = ConfigDoc::providers_from_paths(&[home.clone(), project.clone()]);
    assert_eq!(
        cfg.resolve_model_system_prompt("p", "m"),
        Some("project prompt")
    );

    write_provider_file(&project, "p", r#"{"models":[{"id":"m"}]}"#);
    let cfg = ConfigDoc::providers_from_paths(&[home, project]);
    assert_eq!(
        cfg.resolve_model_system_prompt("p", "m"),
        Some("home prompt")
    );
}

#[test]
fn model_system_prompt_is_typed_not_passthrough_and_survives_refetch() {
    let parsed: ProviderEntry = serde_json::from_str(
        r#"{"url":"https://x","models":[{"id":"m","system_prompt":"stay","vendor":"kept"}]}"#,
    )
    .unwrap();
    let parsed_model = &parsed.models[0];
    assert_eq!(parsed_model.system_prompt.as_deref(), Some("stay"));
    assert!(!parsed_model.extra.contains_key("system_prompt"));

    let fetched = vec![model("m", false)];
    let merged = merge_fetched_models_with_policy(
        None,
        &parsed.models,
        fetched,
        ModelMergePolicy::KeepUnlisted,
    );
    assert_eq!(merged[0].system_prompt.as_deref(), Some("stay"));

    let removed = merge_fetched_models_with_policy(
        None,
        &parsed.models,
        Vec::new(),
        ModelMergePolicy::RemoveUnlisted,
    );
    assert!(removed.is_empty());
}

#[test]
fn manual_field_defaults_false_when_absent() {
    // A model row written before the `manual` field existed must
    // load as non-manual.
    let m: ModelEntry = serde_json::from_str(r#"{"id":"legacy"}"#).unwrap();
    assert!(!m.manual);
    // And the field is skipped when serializing a non-manual entry.
    let json = serde_json::to_string(&model("x", false)).unwrap();
    assert!(!json.contains("manual"));
    let json = serde_json::to_string(&model("x", true)).unwrap();
    assert!(json.contains("\"manual\":true"));
}

#[test]
fn resolve_inline_think_defaults_on_and_honors_opt_out() {
    let mut cfg = ProvidersConfig::default();
    let mut entry = ProviderEntry::default();
    // Default-on: an unset override.
    let default_model = model("default-on", false);
    assert_eq!(default_model.inline_think, None);
    entry.models.push(default_model);
    // Explicit opt-out: raw passthrough.
    let mut off = model("legacy-off", true);
    off.inline_think = Some(false);
    entry.models.push(off);
    // Explicit opt-in (redundant with the default, but resolvable).
    let mut on = model("explicit-on", true);
    on.inline_think = Some(true);
    entry.models.push(on);
    cfg.providers.insert("p".into(), entry);

    // Unset override → falls through to the global default (on here).
    assert!(cfg.resolve_inline_think("p", "default-on", true));
    // Explicit model `false` → disabled (raw passthrough).
    assert!(!cfg.resolve_inline_think("p", "legacy-off", true));
    // Explicit model `true` → enabled.
    assert!(cfg.resolve_inline_think("p", "explicit-on", true));
    // Unknown provider / model → the global default.
    assert!(cfg.resolve_inline_think("nope", "x", true));
    assert!(cfg.resolve_inline_think("p", "ghost", true));
    // With a global default of `false`, unset tiers inherit it.
    assert!(!cfg.resolve_inline_think("p", "default-on", false));
    assert!(!cfg.resolve_inline_think("nope", "x", false));
    // A model `true`/`false` still wins over the global.
    assert!(cfg.resolve_inline_think("p", "explicit-on", false));
    assert!(!cfg.resolve_inline_think("p", "legacy-off", false));

    // `None` is skipped on serialize; `Some(false)` is written.
    let json_on = serde_json::to_string(&model("k", false)).unwrap();
    assert!(!json_on.contains("inline_think"));
    let mut k = model("k", false);
    k.inline_think = Some(false);
    let json_off = serde_json::to_string(&k).unwrap();
    assert!(json_off.contains("\"inline_think\":false"));
}

#[test]
fn trust_defaults_untrusted_and_honors_provider_model_overrides() {
    let mut cfg = ProvidersConfig::default();
    let mut entry = ProviderEntry {
        trust: Some(ModelTrust::Trusted),
        ..ProviderEntry::default()
    };
    let default_model = model("default-on", false);
    assert_eq!(default_model.trust, None);
    entry.models.push(default_model.clone());
    let mut untrusted_override = model("untrusted-override", false);
    untrusted_override.trust = Some(ModelTrust::Untrusted);
    entry.models.push(untrusted_override.clone());
    cfg.providers.insert("p".into(), entry);

    assert_eq!(cfg.resolve_trust("p", "default-on"), ModelTrust::Trusted);
    assert_eq!(
        cfg.resolve_trust("p", "untrusted-override"),
        ModelTrust::Untrusted
    );
    assert_eq!(
        cfg.resolve_trust("missing", "default-on"),
        ModelTrust::Untrusted
    );
    assert_eq!(cfg.resolve_trust("p", "missing"), ModelTrust::Trusted);

    let json_default = serde_json::to_string(&default_model).unwrap();
    assert!(!json_default.contains("trust"));
    let json_override = serde_json::to_string(&untrusted_override).unwrap();
    assert!(json_override.contains("\"trust\":\"untrusted\""));
}

#[test]
fn subagent_invokable_defaults_false_and_honors_overrides() {
    let mut cfg = ProvidersConfig::default();
    let mut provider_default = ProviderEntry {
        subagent_invokable: Some(true),
        ..ProviderEntry::default()
    };
    provider_default.models.push(model("inherits", false));
    let mut disabled = model("disabled", false);
    disabled.subagent_invokable = Some(false);
    provider_default.models.push(disabled);
    cfg.providers
        .insert("provider-default".into(), provider_default);
    cfg.providers.insert(
        "unset".into(),
        ProviderEntry {
            models: vec![model("missing", false)],
            ..ProviderEntry::default()
        },
    );

    assert!(cfg.resolve_subagent_invokable("provider-default", "inherits"));
    assert!(!cfg.resolve_subagent_invokable("provider-default", "disabled"));
    assert!(!cfg.resolve_subagent_invokable("unset", "missing"));
    assert!(!cfg.resolve_subagent_invokable("missing", "missing"));
}

#[test]
fn can_delegate_model_overrides_provider() {
    let mut cfg = ProvidersConfig::default();
    let mut provider = ProviderEntry {
        can_delegate: Some(false),
        ..ProviderEntry::default()
    };
    provider.models.push(model("inherits-provider", false));
    let mut override_on = model("override-on", false);
    override_on.can_delegate = Some(true);
    provider.models.push(override_on);
    cfg.providers.insert("p".into(), provider);

    assert!(!cfg.resolve_can_delegate("p", "inherits-provider"));
    assert!(cfg.resolve_can_delegate("p", "override-on"));
}

#[test]
fn can_delegate_missing_defaults_true() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "p".into(),
        ProviderEntry {
            models: vec![model("m", false)],
            ..ProviderEntry::default()
        },
    );

    assert!(cfg.resolve_can_delegate("p", "m"));
    assert!(cfg.resolve_can_delegate("p", "unknown-model"));
    assert!(cfg.resolve_can_delegate("unknown-provider", "m"));
}

#[test]
fn fetch_merge_preserves_can_delegate() {
    let mut existing = model("m", false);
    existing.can_delegate = Some(false);
    let fetched = vec![model("m", false)];

    let merged = merge_fetched_models_with_policy(
        None,
        &[existing],
        fetched,
        ModelMergePolicy::KeepUnlisted,
    );

    assert_eq!(merged[0].can_delegate, Some(false));
}

#[test]
fn computer_use_resolve_matrix() {
    use crate::config::extended::ComputerUseMode;

    let mut cfg = ProvidersConfig::default();
    let mut provider = ProviderEntry {
        computer_use: Some(ComputerUseMode::Ask),
        ..ProviderEntry::default()
    };
    provider.models.push(model("inherits-provider", false));
    let mut override_yolo = model("override-yolo", false);
    override_yolo.computer_use = Some(ComputerUseMode::Yolo);
    provider.models.push(override_yolo);
    let mut override_disabled = model("override-disabled", false);
    override_disabled.computer_use = Some(ComputerUseMode::Disabled);
    provider.models.push(override_disabled);
    cfg.providers.insert("p".into(), provider);

    assert_eq!(
        cfg.resolve_computer_use_effective("p", "inherits-provider", None, None),
        ComputerUseMode::Ask
    );
    assert_eq!(
        cfg.resolve_computer_use_effective("p", "override-yolo", None, None),
        ComputerUseMode::Yolo
    );
    assert_eq!(
        cfg.resolve_computer_use_effective("p", "override-disabled", None, None),
        ComputerUseMode::Disabled
    );
    assert_eq!(
        cfg.resolve_computer_use_effective("p", "override-yolo", Some(ComputerUseMode::Ask), None),
        ComputerUseMode::Ask
    );
    assert_eq!(
        cfg.resolve_computer_use_effective("p", "override-yolo", None, Some(ComputerUseMode::Ask)),
        ComputerUseMode::Ask
    );
    assert_eq!(
        cfg.resolve_computer_use_effective("missing", "missing", None, None),
        ComputerUseMode::Disabled
    );

    let tmp = tempfile::tempdir().unwrap();
    let global = tmp.path().join("global.json");
    let project = tmp.path().join("project.json");
    std::fs::write(&global, r#"{"computer_use":"yolo"}"#).unwrap();
    std::fs::write(&project, "{}").unwrap();
    assert_eq!(
        crate::config::extended::resolve_computer_use_policy_from_paths(&[
            global.clone(),
            project.clone()
        ]),
        Some(ComputerUseMode::Yolo)
    );
    std::fs::write(&project, r#"{"computer_use":"ask"}"#).unwrap();
    assert_eq!(
        crate::config::extended::resolve_computer_use_policy_from_paths(&[global, project]),
        Some(ComputerUseMode::Ask)
    );
}

#[test]
fn policy_resolver_applies_defaults_filters_and_tie_breaks() {
    let mut cfg = ProvidersConfig::default();
    let mut cheap = model("cheap", false);
    cheap.subagent_invokable = Some(true);
    cheap.quality_rank = Some(5);
    cheap.cost_rank = Some(1);
    cheap.capabilities.tool_calling = CapabilityStatus::Supported;
    cheap.capabilities.context_tokens = Some(32_000);

    let mut reasoning = model("reasoning", false);
    reasoning.subagent_invokable = Some(true);
    reasoning.trust = Some(ModelTrust::Trusted);
    reasoning.quality_rank = Some(10);
    reasoning.cost_rank = Some(5);
    reasoning.thinking_modes = vec![ThinkingMode::High];
    reasoning.capabilities.images = Some(true);
    reasoning.context_length = Some(128_000);

    cfg.providers.insert(
        "a".into(),
        ProviderEntry {
            models: vec![cheap],
            ..ProviderEntry::default()
        },
    );
    cfg.providers.insert(
        "b".into(),
        ProviderEntry {
            models: vec![reasoning],
            ..ProviderEntry::default()
        },
    );

    cfg.category_defaults.insert(
        "cheap_code".into(),
        ProviderModelRef {
            provider: "b".into(),
            model: "reasoning".into(),
        },
    );

    let chosen = cfg
        .resolve_model_policy(&ModelPolicyRequest {
            selector: ModelPolicySelector::Category("cheap_code"),
            trust: None,
            required_capabilities: vec![],
            min_context_tokens: None,
            require_subagent_invokable: true,
            optimize: ModelOptimization::Cost,
            role: Some("cheap_code"),
            agent: Some("explore"),
        })
        .unwrap();
    assert_eq!(chosen.selector(), "b:reasoning");

    let chosen = cfg
        .resolve_model_policy(&ModelPolicyRequest {
            selector: ModelPolicySelector::Trust(ModelTrust::Untrusted),
            trust: None,
            required_capabilities: vec![RequiredModelCapability::ToolCalling],
            min_context_tokens: Some(16_000),
            require_subagent_invokable: true,
            optimize: ModelOptimization::Quality,
            role: None,
            agent: None,
        })
        .unwrap();
    assert_eq!(chosen.selector(), "a:cheap");

    let chosen = cfg
        .resolve_model_policy(&ModelPolicyRequest {
            selector: ModelPolicySelector::Category("reasoning"),
            trust: None,
            required_capabilities: vec![
                RequiredModelCapability::Reasoning,
                RequiredModelCapability::Images,
            ],
            min_context_tokens: Some(64_000),
            require_subagent_invokable: true,
            optimize: ModelOptimization::Balanced,
            role: Some("reasoning"),
            agent: Some("deepthink"),
        })
        .unwrap();
    assert_eq!(chosen.selector(), "b:reasoning");

    let err = cfg
        .resolve_model_policy(&ModelPolicyRequest {
            selector: ModelPolicySelector::Category("strict"),
            trust: None,
            required_capabilities: vec![RequiredModelCapability::StructuredOutputs],
            min_context_tokens: None,
            require_subagent_invokable: true,
            optimize: ModelOptimization::Balanced,
            role: Some("strict"),
            agent: None,
        })
        .unwrap_err();
    assert!(matches!(err, ModelPolicyError::NoEligibleModel(_)));
}

#[test]
fn mixed_harness_policy_loaded_from_files_covers_trust_and_hidden_models() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.json");
    std::fs::write(&config_path, "{}").unwrap();
    write_provider_file(
        &config_path,
        "mixed",
        r#"{
                "url": "https://mixed.example/v1",
                "trust": "untrusted",
                "models": [
                    { "id": "parent-untrusted", "subagent_invokable": true, "quality_rank": 4, "cost_rank": 1 },
                    { "id": "top-trusted", "trust": "trusted", "quality_rank": 6, "cost_rank": 4 },
                    { "id": "child-trusted", "trust": "trusted", "subagent_invokable": true, "quality_rank": 9, "cost_rank": 3 },
                    { "id": "hidden-trusted", "trust": "trusted", "subagent_invokable": false, "quality_rank": 20, "cost_rank": 1 }
                ]
            }"#,
    );
    let cfg = ConfigDoc::providers_from_paths(&[config_path]);

    let top = cfg
        .resolve_model_policy(&ModelPolicyRequest {
            selector: ModelPolicySelector::Exact("mixed:top-trusted"),
            trust: Some(ModelTrust::Trusted),
            required_capabilities: vec![],
            min_context_tokens: None,
            require_subagent_invokable: false,
            optimize: ModelOptimization::Balanced,
            role: Some("top_level"),
            agent: Some("Build"),
        })
        .unwrap();
    assert_eq!(top.selector(), "mixed:top-trusted");

    let child = cfg
        .resolve_model_policy(&ModelPolicyRequest {
            selector: ModelPolicySelector::Trust(ModelTrust::Trusted),
            trust: Some(ModelTrust::Trusted),
            required_capabilities: vec![],
            min_context_tokens: None,
            require_subagent_invokable: true,
            optimize: ModelOptimization::Quality,
            role: Some("sensitive_child"),
            agent: Some("builder"),
        })
        .unwrap();
    assert_eq!(child.selector(), "mixed:child-trusted");

    let untrusted = cfg
        .resolve_model_policy(&ModelPolicyRequest {
            selector: ModelPolicySelector::Exact("mixed:parent-untrusted"),
            trust: None,
            required_capabilities: vec![],
            min_context_tokens: None,
            require_subagent_invokable: true,
            optimize: ModelOptimization::Balanced,
            role: Some("utility"),
            agent: Some("explore"),
        })
        .unwrap();
    assert_eq!(untrusted.selector(), "mixed:parent-untrusted");

    let hidden_refusal = cfg
        .resolve_model_policy(&ModelPolicyRequest {
            selector: ModelPolicySelector::Exact("mixed:hidden-trusted"),
            trust: Some(ModelTrust::Trusted),
            required_capabilities: vec![],
            min_context_tokens: None,
            require_subagent_invokable: true,
            optimize: ModelOptimization::Quality,
            role: Some("sensitive_child"),
            agent: Some("builder"),
        })
        .unwrap_err();
    assert!(matches!(
        hidden_refusal,
        ModelPolicyError::NotSubagentInvokable { provider, model }
            if provider == "mixed" && model == "hidden-trusted"
    ));
}

#[test]
fn legacy_redact_fields_are_rejected_with_migration_hint() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.json");
    std::fs::write(&config_path, "{}").unwrap();
    write_provider_file(
        &config_path,
        "p",
        r#"{"url":"https://x","models":[{"id":"m","redact":false}]}"#,
    );
    let path = provider_file_path_for_config(&config_path, "p").unwrap();
    let err = load_provider_raw_file(&path).unwrap_err().to_string();
    assert!(err.contains("legacy `redact`"));
    assert!(err.contains("trust"));
}

#[test]
fn resolve_inline_think_three_tier_precedence() {
    let mut cfg = ProvidersConfig::default();

    // Provider with `inline_think = true`, holding three models:
    // one unset, one forcing false, one forcing true.
    let mut prov_on = ProviderEntry {
        inline_think: Some(true),
        ..Default::default()
    };
    prov_on.models.push(model("inherit", false));
    let mut m_off = model("model-off", true);
    m_off.inline_think = Some(false);
    prov_on.models.push(m_off);
    let mut m_on = model("model-on", true);
    m_on.inline_think = Some(true);
    prov_on.models.push(m_on);
    cfg.providers.insert("prov_on".into(), prov_on);

    // Provider with `inline_think = false`, one unset model.
    let mut prov_off = ProviderEntry {
        inline_think: Some(false),
        ..Default::default()
    };
    prov_off.models.push(model("inherit", false));
    cfg.providers.insert("prov_off".into(), prov_off);

    // Provider with NO override (inherits global), one unset model.
    let mut prov_inherit = ProviderEntry::default();
    assert_eq!(prov_inherit.inline_think, None);
    prov_inherit.models.push(model("inherit", false));
    cfg.providers.insert("prov_inherit".into(), prov_inherit);

    // Model wins over provider: model `false` disables despite provider `true`.
    assert!(!cfg.resolve_inline_think("prov_on", "model-off", true));
    // Model `true` enables despite a (hypothetical) lower tier off.
    assert!(cfg.resolve_inline_think("prov_on", "model-on", false));
    // Unset model inherits the provider override (true), ignoring global false.
    assert!(cfg.resolve_inline_think("prov_on", "inherit", false));

    // Provider `false` wins over global `true` when the model is unset.
    assert!(!cfg.resolve_inline_think("prov_off", "inherit", true));

    // Both tiers unset → the global default decides.
    assert!(cfg.resolve_inline_think("prov_inherit", "inherit", true));
    assert!(!cfg.resolve_inline_think("prov_inherit", "inherit", false));
}

/// Three-tier precedence for `hint_tool_call_corrections`
/// (implementation note): model `Some(false)` beats
/// provider `Some(true)` beats global `true`; `None` falls through.
#[test]
fn resolve_hint_tool_call_corrections_three_tier_precedence() {
    let mut cfg = ProvidersConfig::default();

    // Provider `true`, with a model forcing `false`, a model forcing `true`,
    // and an unset model.
    let mut prov_on = ProviderEntry {
        hint_tool_call_corrections: Some(true),
        ..Default::default()
    };
    prov_on.models.push(model("inherit", false));
    let mut m_off = model("model-off", true);
    m_off.hint_tool_call_corrections = Some(false);
    prov_on.models.push(m_off);
    let mut m_on = model("model-on", true);
    m_on.hint_tool_call_corrections = Some(true);
    prov_on.models.push(m_on);
    cfg.providers.insert("prov_on".into(), prov_on);

    // Provider `false`, one unset model.
    let mut prov_off = ProviderEntry {
        hint_tool_call_corrections: Some(false),
        ..Default::default()
    };
    prov_off.models.push(model("inherit", false));
    cfg.providers.insert("prov_off".into(), prov_off);

    // Provider with NO override (inherits global), one unset model.
    let mut prov_inherit = ProviderEntry::default();
    assert_eq!(prov_inherit.hint_tool_call_corrections, None);
    prov_inherit.models.push(model("inherit", false));
    cfg.providers.insert("prov_inherit".into(), prov_inherit);

    // Model `Some(false)` beats provider `Some(true)` beats global `true`.
    assert!(!cfg.resolve_hint_tool_call_corrections("prov_on", "model-off", true));
    // Model `true` enables despite a global `false`.
    assert!(cfg.resolve_hint_tool_call_corrections("prov_on", "model-on", false));
    // Unset model inherits the provider override (true), ignoring global false.
    assert!(cfg.resolve_hint_tool_call_corrections("prov_on", "inherit", false));
    // Provider `false` wins over global `true` when the model is unset.
    assert!(!cfg.resolve_hint_tool_call_corrections("prov_off", "inherit", true));
    // Both tiers unset (`None`) → the global default decides.
    assert!(cfg.resolve_hint_tool_call_corrections("prov_inherit", "inherit", true));
    assert!(!cfg.resolve_hint_tool_call_corrections("prov_inherit", "inherit", false));
    // Unknown provider/model → the global default.
    assert!(cfg.resolve_hint_tool_call_corrections("nope", "x", true));
    assert!(!cfg.resolve_hint_tool_call_corrections("nope", "x", false));

    // `None` is skipped on serialize; `Some(false)` is written.
    let json_unset = serde_json::to_string(&model("k", false)).unwrap();
    assert!(!json_unset.contains("hint_tool_call_corrections"));
    let mut k = model("k", false);
    k.hint_tool_call_corrections = Some(false);
    let json_off = serde_json::to_string(&k).unwrap();
    assert!(json_off.contains("\"hint_tool_call_corrections\":false"));
    // Provider tier too: unset omits the key, `Some` serializes it.
    let entry_unset: Value = serde_json::to_value(ProviderEntry {
        url: "https://x".into(),
        ..ProviderEntry::default()
    })
    .unwrap();
    assert!(
        !entry_unset
            .as_object()
            .unwrap()
            .contains_key("hint_tool_call_corrections")
    );
}

/// Three-tier precedence for `text_embedded_recovery`
/// (implementation note): model override beats provider
/// override beats the global default; `None` falls through. Mirrors the
/// `inline_think` / `hint_tool_call_corrections` resolvers.
#[test]
fn resolve_text_embedded_recovery_three_tier_precedence() {
    use crate::config::extended::TextEmbeddedRecovery as M;
    let mut cfg = ProvidersConfig::default();

    // Provider pinned `strict`, with a model forcing `off`, a model forcing
    // `available`, and an unset model.
    let mut prov_strict = ProviderEntry {
        text_embedded_recovery: Some(M::Strict),
        ..Default::default()
    };
    prov_strict.models.push(model("inherit", false));
    let mut m_off = model("model-off", true);
    m_off.text_embedded_recovery = Some(M::Off);
    prov_strict.models.push(m_off);
    let mut m_avail = model("model-avail", true);
    m_avail.text_embedded_recovery = Some(M::Available);
    prov_strict.models.push(m_avail);
    cfg.providers.insert("prov_strict".into(), prov_strict);

    // Provider with NO override (inherits global), one unset model.
    let mut prov_inherit = ProviderEntry::default();
    assert_eq!(prov_inherit.text_embedded_recovery, None);
    prov_inherit.models.push(model("inherit", false));
    cfg.providers.insert("prov_inherit".into(), prov_inherit);

    // Model wins over provider: model `off` beats provider `strict`.
    assert_eq!(
        cfg.resolve_text_embedded_recovery("prov_strict", "model-off", M::Available),
        M::Off
    );
    // Model `available` beats provider `strict`.
    assert_eq!(
        cfg.resolve_text_embedded_recovery("prov_strict", "model-avail", M::Off),
        M::Available
    );
    // Unset model inherits the provider override (`strict`), ignoring global.
    assert_eq!(
        cfg.resolve_text_embedded_recovery("prov_strict", "inherit", M::Available),
        M::Strict
    );
    // Both tiers unset (`None`) → the global default decides.
    assert_eq!(
        cfg.resolve_text_embedded_recovery("prov_inherit", "inherit", M::Available),
        M::Available
    );
    assert_eq!(
        cfg.resolve_text_embedded_recovery("prov_inherit", "inherit", M::Off),
        M::Off
    );
    // Unknown provider/model → the global default.
    assert_eq!(
        cfg.resolve_text_embedded_recovery("nope", "x", M::Strict),
        M::Strict
    );

    // `None` is skipped on serialize; `Some(...)` round-trips.
    let json_unset = serde_json::to_string(&model("k", false)).unwrap();
    assert!(!json_unset.contains("text_embedded_recovery"));
    let mut k = model("k", false);
    k.text_embedded_recovery = Some(M::Strict);
    let json_set = serde_json::to_string(&k).unwrap();
    assert!(json_set.contains("\"text_embedded_recovery\":\"strict\""));
    // Round-trips back to the same value.
    let parsed: ModelEntry = serde_json::from_str(&json_set).unwrap();
    assert_eq!(parsed.text_embedded_recovery, Some(M::Strict));
}

/// The DeepSeek built-in default mapping (bottom tier) for ALL FOUR
/// thinking modes (implementation note). `Off`
/// explicitly emits the disabled form (not omission); every level
/// enables and sets `reasoning_effort`. The mapping lives in the
/// built-in provider defaults, surfaced through
/// `resolve_thinking_params` with no model/provider override configured.
mod model_defaults_and_capabilities;
