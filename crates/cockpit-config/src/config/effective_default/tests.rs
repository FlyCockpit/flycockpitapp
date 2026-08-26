//! Effective-default mutation, journal, and recovery tests.
//!
//! Every test is tempdir-rooted, uses the shared `TestEnvGuard` seam instead of
//! mutating process environment directly, injects its own session authority,
//! and contains no sleeps, no network, and no real credentials.

use super::*;

use std::sync::{Arc, Barrier};

use tempfile::TempDir;

use crate::config::providers::{ActiveReasoningEffort, ThinkingMode};
use crate::config::trust::WorkspaceTrustPolicy;
use crate::db::workspace_trust::WorkspaceTrustMode;

// ---- helpers ---------------------------------------------------------------

fn selection(provider: &str, model: &str) -> ActiveModelRef {
    ActiveModelRef {
        provider: provider.to_string(),
        model: model.to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    }
}

fn test_default_update_authority(generation: u64) -> DefaultUpdateAuthorityBinding {
    DefaultUpdateAuthorityBinding::new(
        "4d8d4cd5bbf18d6ae07e52adf7f0b6a9e5e8f91a9e72d8cb69c6a129e84e400c"
            .to_string(),
        generation,
    )
    .unwrap()
}

fn test_retained_receipt_proof(
    default_update_id: Uuid,
    session_id: Uuid,
    generation: u64,
) -> RetainedDefaultReceiptProof {
    RetainedDefaultReceiptProof::new(
        default_update_id,
        session_id,
        test_default_update_authority(generation),
        r#"{"type":"applied"}"#,
    )
    .unwrap()
}

/// A fully specified reference: the verified default must match every field,
/// including reasoning effort and thinking mode.
fn rich_selection(provider: &str, model: &str) -> ActiveModelRef {
    ActiveModelRef {
        provider: provider.to_string(),
        model: model.to_string(),
        reasoning_effort: Some(ActiveReasoningEffort {
            value: "high".to_string(),
        }),
        thinking_mode: Some(ThinkingMode::High),
        prompt_cache_retention: None,
    }
}

/// Write a config layer, optionally declaring `active_model`, and always
/// declaring the providers referenced by these tests so a cleared default can
/// be validated against a resolvable provider/model.
fn write_layer(dir: &Path, active: Option<&ActiveModelRef>, providers: &[(&str, &str)]) {
    std::fs::create_dir_all(dir).unwrap();
    let mut raw = serde_json::json!({ "layer_opaque": true });
    if let Some(active) = active {
        raw["active_model"] = serde_json::to_value(active).unwrap();
    }
    std::fs::write(
        dir.join("config.json"),
        format!("{}\n", serde_json::to_string_pretty(&raw).unwrap()),
    )
    .unwrap();
    if providers.is_empty() {
        return;
    }
    let providers_dir = dir.join("providers");
    std::fs::create_dir_all(&providers_dir).unwrap();
    for (provider, model) in providers {
        std::fs::write(
            providers_dir.join(format!("{provider}.json")),
            serde_json::to_string(&serde_json::json!({
                "url": "https://example.test/v1",
                "models": [{ "id": model }],
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

fn user_dir(root: &Path) -> PathBuf {
    root.join("home/.config/cockpit")
}

fn trust_policy(project: &Path, mode: WorkspaceTrustMode) -> WorkspaceTrustPolicy {
    WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(project).unwrap(),
        mode,
    }
}

/// Deterministic in-memory stand-in for the durable session row.
#[derive(Default)]
struct FakeSessions {
    revision: i64,
    selection: Option<ActiveModelRef>,
    missing: bool,
    fail_cas: bool,
    /// Commit the CAS and *then* report an error — the ambiguous case, where
    /// the caller cannot tell whether the row was written.
    commit_then_error: bool,
    cas_calls: usize,
    /// When set, this authority may only act on that session — the driver's
    /// binding, which stops a stale journal reaching another session's row.
    bound: Option<Uuid>,
}

impl SessionRevisionAuthority for FakeSessions {
    fn bound_session_id(&self) -> Option<Uuid> {
        self.bound
    }

    fn current_revision(&mut self, session_id: Uuid) -> Result<Option<i64>> {
        if let Some(bound) = self.bound
            && bound != session_id
        {
            anyhow::bail!("authority is bound to a different session");
        }
        if self.missing {
            return Ok(None);
        }
        Ok(Some(self.revision))
    }

    fn cas_set_active_model(
        &mut self,
        session_id: Uuid,
        expected_revision: i64,
        selection: &ActiveModelRef,
    ) -> Result<bool> {
        if let Some(bound) = self.bound
            && bound != session_id
        {
            anyhow::bail!("authority is bound to a different session");
        }
        self.cas_calls += 1;
        if self.fail_cas {
            anyhow::bail!("injected session persistence failure");
        }
        if self.revision != expected_revision {
            return Ok(false);
        }
        self.revision += 1;
        self.selection = Some(selection.clone());
        if self.commit_then_error {
            // One-shot: the compensating CAS that follows must be able to
            // succeed, exactly as a real transient failure would allow.
            self.commit_then_error = false;
            anyhow::bail!("injected failure after the row was written");
        }
        Ok(true)
    }
}

fn participant<'a>(
    sessions: &'a mut FakeSessions,
    prior: ActiveModelRef,
) -> SessionDefaultParticipant<'a> {
    let expected_revision = sessions.revision;
    SessionDefaultParticipant {
        session_id: Uuid::from_u128(7),
        prior,
        expected_revision,
        authority: sessions,
    }
}

/// The exact reference a freshly created, model-less session would resolve.
fn fresh_session_resolution(cwd: &Path) -> Option<ActiveModelRef> {
    ConfigDoc::load_effective(cwd).active_model
}

fn journal_and_backup_are_gone(config_path: &Path) -> bool {
    !journal_path_for_config(config_path).exists() && !backup_path_for_config(config_path).exists()
}

/// A deliberately small filesystem spy for recovery-boundary tests. The
/// retained path is allowed to have created its own journal/backup/lock before
/// ambient recovery starts; the ambient classifier must not add or remove any
/// sibling artifact after seeing the retained correlation.
fn sidecar_entries(dir: &Path) -> Vec<std::ffi::OsString> {
    let mut entries = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

/// Build one capability-bound config-only target with a concrete old and new
/// default. Tests that mutate journal metadata use this rather than a
/// pathname-based recovery helper so they exercise the same retained backend
/// as the daemon.
fn retained_config_only_target(
    tmp: &TempDir,
) -> (
    RetainedEffectiveDefaultTarget,
    PathBuf,
    ActiveModelRef,
    ActiveModelRef,
) {
    let config_dir = tmp.path().join("retained-config");
    let project_root = tmp.path().join("project");
    std::fs::create_dir_all(&project_root).unwrap();
    let prior = selection("old", "a");
    let requested = selection("new", "b");
    write_layer(
        &config_dir,
        Some(&prior),
        &[("old", "a"), ("new", "b")],
    );
    let config_path = config_dir.join("config.json");
    let target = RetainedEffectiveDefaultTarget::new(
        std::fs::File::open(&config_dir).unwrap(),
        std::ffi::OsString::from("config.json"),
        journal_path_for_config(&config_path)
            .file_name()
            .unwrap()
            .to_os_string(),
        backup_path_for_config(&config_path)
            .file_name()
            .unwrap()
            .to_os_string(),
        config_path.canonicalize().unwrap(),
        project_root.canonicalize().unwrap(),
        EffectiveDefaultScope::Project,
    )
    .unwrap();
    (target, config_path, prior, requested)
}

// ---- AC2: layer matrix + fresh-session resolution --------------------------

#[test]
fn user_layer_mutation_is_verified_and_resolves_for_a_fresh_session() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("old", "a")), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();

    let target = rich_selection("new", "b");
    let result = mutate_effective_default(
        &cwd,
        Some(&target),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect("user-layer mutation");

    assert!(result.wrote && !result.unchanged);
    assert_eq!(result.scope_label, "user");
    assert_eq!(result.selection.as_ref(), Some(&target));
    assert!(result.generation >= 1, "generation must be stamped");
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&target));
    assert!(journal_and_backup_are_gone(&user.join("config.json")));
    // Unrelated keys survive the replacement.
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(user.join("config.json")).unwrap()).unwrap();
    assert_eq!(raw["layer_opaque"], true);
}

#[test]
fn machine_local_layer_outranks_user_and_owns_the_default() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("user", "u")), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let machine = crate::config::dirs::local_config_dir_for(&cwd).unwrap();
    write_layer(&machine, None, &[]);

    let target = selection("new", "b");
    let result = mutate_effective_default(
        &cwd,
        Some(&target),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect("machine-local mutation");

    assert_eq!(result.scope_label, "machine/local");
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&target));
    let user_raw = std::fs::read_to_string(user.join("config.json")).unwrap();
    assert!(
        user_raw.contains("\"user\""),
        "the lower-precedence user layer must not be rewritten: {user_raw}"
    );
}

#[test]
fn trusted_project_layer_is_the_sole_target_and_user_layer_is_untouched() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("user", "u")), &[("new", "b")]);
    let project = tmp.path().join("proj");
    write_layer(&project.join(".cockpit"), None, &[]);

    let target = selection("new", "b");
    let policy = trust_policy(&project, WorkspaceTrustMode::Trust);
    let result = crate::config::trust::with_workspace_trust_policy(policy.clone(), || {
        mutate_effective_default(
            &project,
            Some(&target),
            ActiveModelWriteMode::Replace,
            None,
            None,
            None,
        )
    })
    .expect("project-layer mutation");

    assert_eq!(result.scope_label, "project");
    let resolved = crate::config::trust::with_workspace_trust_policy(policy, || {
        fresh_session_resolution(&project)
    });
    assert_eq!(resolved.as_ref(), Some(&target));
    let user_raw = std::fs::read_to_string(user.join("config.json")).unwrap();
    assert!(user_raw.contains("\"user\""));
    let project_raw = std::fs::read_to_string(project.join(".cockpit/config.json")).unwrap();
    assert!(project_raw.contains("\"new\""));
}

#[test]
fn untrusted_project_layer_is_never_written_and_the_user_layer_governs() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("user", "u")), &[("new", "b")]);
    let project = tmp.path().join("proj");
    write_layer(
        &project.join(".cockpit"),
        Some(&selection("proj", "p")),
        &[],
    );
    let project_before = std::fs::read_to_string(project.join(".cockpit/config.json")).unwrap();

    let target = selection("new", "b");
    let policy = trust_policy(&project, WorkspaceTrustMode::IgnoreConfig);
    let result = crate::config::trust::with_workspace_trust_policy(policy.clone(), || {
        mutate_effective_default(
            &project,
            Some(&target),
            ActiveModelWriteMode::Replace,
            None,
            None,
            None,
        )
    })
    .expect("an ignored project layer falls to the highest layer attach reads");

    assert_eq!(
        result.scope_label, "user",
        "a layer attach would not read must never be the write target"
    );
    assert_eq!(
        std::fs::read_to_string(project.join(".cockpit/config.json")).unwrap(),
        project_before,
        "the ignored project layer must be byte-identical"
    );
    let resolved = crate::config::trust::with_workspace_trust_policy(policy, || {
        fresh_session_resolution(&project)
    });
    assert_eq!(resolved.as_ref(), Some(&target));
}

#[test]
fn explicit_cockpit_config_is_the_sole_layer_and_the_only_target() {
    let tmp = TempDir::new().unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("user", "u")), &[]);
    let explicit_dir = tmp.path().join("explicit");
    write_layer(&explicit_dir, None, &[("new", "b")]);
    let explicit = explicit_dir.join("config.json");
    env.set_cockpit_config(&explicit);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();

    let target = selection("new", "b");
    let result = mutate_effective_default(
        &cwd,
        Some(&target),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect("explicit override mutation");

    assert_eq!(result.scope_label, "explicit override");
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&target));
    let user_raw = std::fs::read_to_string(user.join("config.json")).unwrap();
    assert!(
        user_raw.contains("\"user\""),
        "an explicit override is a sole-layer context"
    );
}

#[cfg(unix)]
#[test]
fn unwritable_project_layer_rejects_without_writing_the_user_layer() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("user", "u")), &[("new", "b")]);
    let project = tmp.path().join("proj");
    let project_cockpit = project.join(".cockpit");
    write_layer(&project_cockpit, Some(&selection("project", "p")), &[]);
    let project_cfg = project_cockpit.join("config.json");
    let mut perms = std::fs::metadata(&project_cfg).unwrap().permissions();
    perms.set_mode(0o400);
    std::fs::set_permissions(&project_cfg, perms).unwrap();
    let user_before = std::fs::read_to_string(user.join("config.json")).unwrap();

    let policy = trust_policy(&project, WorkspaceTrustMode::Trust);
    let error = crate::config::trust::with_workspace_trust_policy(policy.clone(), || {
        mutate_effective_default(
            &project,
            Some(&selection("new", "b")),
            ActiveModelWriteMode::Replace,
            None,
            None,
            None,
        )
    })
    .expect_err("an unwritable highest-precedence layer must reject");

    assert_eq!(error.diagnostic_code, "effective_default_target_unwritable");
    assert_eq!(error.scope_label.as_deref(), Some("project"));
    assert_eq!(
        std::fs::read_to_string(user.join("config.json")).unwrap(),
        user_before,
        "no fallback write to a lower-precedence layer"
    );
    let resolved = crate::config::trust::with_workspace_trust_policy(policy, || {
        fresh_session_resolution(&project)
    });
    assert_eq!(
        resolved.as_ref().map(|active| active.provider.as_str()),
        Some("project"),
        "a fresh session still resolves the unchanged project default"
    );
}

#[test]
fn missing_explicit_cockpit_config_directory_fails_closed() {
    let tmp = TempDir::new().unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    write_layer(&user_dir(tmp.path()), Some(&selection("user", "u")), &[]);
    let explicit = tmp.path().join("nowhere/config.json");
    env.set_cockpit_config(&explicit);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();

    let error = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect_err("an invalid explicit config must fail closed");
    assert_eq!(error.diagnostic_code, "effective_default_target_missing");
    assert!(!explicit.exists());
}

#[test]
fn no_op_replacement_reports_unchanged_after_reload_verification() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    let target = rich_selection("p", "m");
    write_layer(&user, Some(&target), &[("p", "m")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let before = std::fs::read_to_string(user.join("config.json")).unwrap();

    let result = mutate_effective_default(
        &cwd,
        Some(&target),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect("no-op replacement");

    assert!(result.unchanged && !result.wrote);
    assert_eq!(result.selection.as_ref(), Some(&target));
    assert_eq!(
        std::fs::read_to_string(user.join("config.json")).unwrap(),
        before,
        "an already-effective request must not claim a write occurred"
    );
}

// ---- AC9: clearing -----------------------------------------------------------

#[test]
fn clearing_a_layer_succeeds_when_a_deterministic_inherited_default_exists() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let inherited = selection("user", "u");
    write_layer(&user_dir(tmp.path()), Some(&inherited), &[("user", "u")]);
    let project = tmp.path().join("proj");
    write_layer(
        &project.join(".cockpit"),
        Some(&selection("project", "p")),
        &[],
    );

    let policy = trust_policy(&project, WorkspaceTrustMode::Trust);
    let result = crate::config::trust::with_workspace_trust_policy(policy.clone(), || {
        mutate_effective_default(
            &project,
            None,
            ActiveModelWriteMode::Replace,
            None,
            None,
            None,
        )
    })
    .expect("clearing succeeds with a deterministic inherited default");

    assert!(result.wrote);
    assert_eq!(
        result.selection.as_ref(),
        Some(&inherited),
        "the confirmation must name the resulting effective state"
    );
    let resolved = crate::config::trust::with_workspace_trust_policy(policy, || {
        fresh_session_resolution(&project)
    });
    assert_eq!(resolved.as_ref(), Some(&inherited));
    let project_raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.join(".cockpit/config.json")).unwrap())
            .unwrap();
    assert!(project_raw.get("active_model").is_none());
    assert_eq!(project_raw["layer_opaque"], true);
}

#[test]
fn clearing_the_sole_layer_yields_an_explicit_no_default_state() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("p", "m")), &[("p", "m")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();

    let result =
        mutate_effective_default(&cwd, None, ActiveModelWriteMode::Replace, None, None, None)
            .expect("clearing the sole layer is an explicit no-default state");
    assert!(result.wrote);
    assert_eq!(result.selection, None);
    assert_eq!(fresh_session_resolution(&cwd), None);
}

#[test]
fn clearing_is_rejected_when_it_would_expose_an_unconfigured_provider() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    // The user layer names a provider that is not configured anywhere.
    write_layer(&user_dir(tmp.path()), Some(&selection("ghost", "g")), &[]);
    let project = tmp.path().join("proj");
    write_layer(
        &project.join(".cockpit"),
        Some(&selection("project", "p")),
        &[("project", "p")],
    );
    let before = std::fs::read_to_string(project.join(".cockpit/config.json")).unwrap();

    let policy = trust_policy(&project, WorkspaceTrustMode::Trust);
    let error = crate::config::trust::with_workspace_trust_policy(policy, || {
        mutate_effective_default(
            &project,
            None,
            ActiveModelWriteMode::Replace,
            None,
            None,
            None,
        )
    })
    .expect_err("a clear that would expose an invalid default must reject");

    assert_eq!(
        error.diagnostic_code,
        "effective_default_clear_exposes_invalid"
    );
    assert_eq!(
        std::fs::read_to_string(project.join(".cockpit/config.json")).unwrap(),
        before,
        "a rejected clear must not mutate"
    );
}

// ---- AC3/AC4: session+default transaction ----------------------------------

#[test]
fn session_and_default_commit_together_and_advance_the_guarded_revision() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("old", "a")), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();

    let target = rich_selection("new", "b");
    let mut sessions = FakeSessions {
        revision: 3,
        selection: Some(selection("old", "a")),
        ..Default::default()
    };
    let result = mutate_effective_default(
        &cwd,
        Some(&target),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, selection("old", "a"))),
        None,
        None,
    )
    .expect("session+default transaction");

    assert_eq!(result.selection.as_ref(), Some(&target));
    assert_eq!(
        sessions.revision, 4,
        "the CAS token must advance exactly once"
    );
    assert_eq!(sessions.selection.as_ref(), Some(&target));
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&target));
    assert!(journal_and_backup_are_gone(&user.join("config.json")));
}

#[test]
fn session_cas_conflict_rejects_and_leaves_both_authorities_unchanged() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let before = std::fs::read_to_string(user.join("config.json")).unwrap();

    let mut sessions = FakeSessions {
        revision: 2,
        selection: Some(prior.clone()),
        ..Default::default()
    };
    // A concurrent writer advanced the row between the read and the CAS, so
    // the guard revision this transaction carries is already stale.
    let spoiled = SessionDefaultParticipant {
        session_id: Uuid::from_u128(7),
        prior: prior.clone(),
        expected_revision: 1,
        authority: &mut sessions,
    };
    let error = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(spoiled),
        None,
        None,
    )
    .expect_err("a zero-row CAS is a conflict, never permission to overwrite");

    assert!(
        error.restored_after_boundary,
        "a post-boundary conflict converges by verified restoration: {error:?}"
    );
    assert_eq!(
        sessions.cas_calls, 1,
        "a zero-row CAS proves nothing was written, so no compensating CAS may run"
    );
    assert_eq!(sessions.revision, 2, "the other writer's row is untouched");
    assert_eq!(sessions.selection.as_ref(), Some(&prior));
    assert_eq!(
        std::fs::read_to_string(user.join("config.json")).unwrap(),
        before
    );
    assert!(journal_and_backup_are_gone(&user.join("config.json")));
}

#[test]
fn cancellation_before_the_boundary_leaves_both_authorities_unchanged() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let before = std::fs::read_to_string(user.join("config.json")).unwrap();

    let cancelled = AtomicBool::new(true);
    let mut sessions = FakeSessions {
        revision: 1,
        selection: Some(prior.clone()),
        ..Default::default()
    };
    let error = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, prior.clone())),
        Some(&cancelled),
        None,
    )
    .expect_err("cancellation before the boundary rejects");

    assert_eq!(error.diagnostic_code, "effective_default_cancelled");
    assert!(!error.restored_after_boundary && !error.recovery_pending);
    assert_eq!(sessions.cas_calls, 0, "zero mutation before the boundary");
    assert_eq!(sessions.revision, 1);
    assert_eq!(
        std::fs::read_to_string(user.join("config.json")).unwrap(),
        before
    );
    assert!(journal_and_backup_are_gone(&user.join("config.json")));
}

// ---- AC5: crash injection at every phase -----------------------------------

/// Every phase boundary, swept by both matrices below.
///
/// `AfterCompensatingMarker` is included for completeness but is structurally
/// unreachable from a *successful* mutation: the compensating marker is only
/// written from `compensate`, which a clean run never enters, and never at all
/// for a config-only transaction (which has no session half to revert). The
/// matrices assert that arming it changes nothing; the dedicated
/// `interrupted_compensation_resumes_instead_of_refusing_forever` test is its
/// real coverage. `FailJournalCleanup` is likewise exercised by the
/// `recovery_pending` test rather than swept here, because it deliberately
/// leaves the journal in place.
const ALL_CRASH_POINTS: &[EffectiveDefaultCrashPoint] = &[
    EffectiveDefaultCrashPoint::AfterJournalPrepared,
    EffectiveDefaultCrashPoint::AfterPrivateReplacementPrepared,
    EffectiveDefaultCrashPoint::AfterSessionCas,
    EffectiveDefaultCrashPoint::AfterSessionCommittedMarker,
    EffectiveDefaultCrashPoint::AfterConfigReplaced,
    EffectiveDefaultCrashPoint::AfterCommittedMarker,
    EffectiveDefaultCrashPoint::AfterReloadVerified,
    EffectiveDefaultCrashPoint::AfterJournalCleanup,
    EffectiveDefaultCrashPoint::AfterCompensatingMarker,
];

/// The retained-directory backend has the same durable recovery contract as
/// the ambient writer, but must recover through its held directory instead of
/// finding a newly selected `COCKPIT_CONFIG` path. Exercise both sides of the
/// commit boundary with a correlated receipt: prepared restores the old
/// value, while committed completes the new one, and neither journal can be
/// deleted before the sink accepts that receipt.
#[test]
fn retained_config_only_recovery_matches_prepared_and_committed_journal_contract() {
    for (point, expect_target) in [
        (EffectiveDefaultCrashPoint::AfterJournalPrepared, false),
        (EffectiveDefaultCrashPoint::AfterCommittedMarker, true),
        (
            EffectiveDefaultCrashPoint::AfterRetainedCommitBeforeRefresh,
            true,
        ),
        (
            EffectiveDefaultCrashPoint::AfterRetainedRefreshBeforeReceipt,
            true,
        ),
    ] {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path().join("retained-config");
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let prior = selection("old", "a");
        let target_selection = selection("new", "b");
        write_layer(
            &config_dir,
            Some(&prior),
            &[("old", "a"), ("new", "b")],
        );
        let config_path = config_dir.join("config.json");
        let target = RetainedEffectiveDefaultTarget::new(
            std::fs::File::open(&config_dir).unwrap(),
            std::ffi::OsString::from("config.json"),
            journal_path_for_config(&config_path)
                .file_name()
                .unwrap()
                .to_os_string(),
            backup_path_for_config(&config_path)
                .file_name()
                .unwrap()
                .to_os_string(),
            config_path.canonicalize().unwrap(),
            project_root.canonicalize().unwrap(),
            EffectiveDefaultScope::Project,
        )
        .unwrap();
        let update_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        set_crash_inject(Some(point));
        let result = mutate_effective_default_retained(
            &target,
            Some(&target_selection),
            Some(target_selection.clone()),
            TransactionCorrelation::RetainedDefaultUpdate {
                default_update_id: update_id,
                session_id,
                authority: None,
            },
        );
        if point == EffectiveDefaultCrashPoint::AfterRetainedRefreshBeforeReceipt {
            result.expect("the config commit reaches the refresh handoff");
            assert!(
                retained_default_after_refresh_before_terminal_receipt("project").is_err(),
                "{point:?} simulates an abrupt stop after refresh but before the durable receipt"
            );
        } else {
            assert!(result.is_err(), "{point:?} simulates an abrupt stop");
        }
        set_crash_inject(None);

        let recovery = recover_retained_effective_default_journal(&target)
            .expect("retained recovery converges the journal");
        let (recovered, mut finalization, receipt_validation) = recovery.into_parts();
        assert!(receipt_validation.is_none());
        assert_eq!(recovered.len(), 1);
        match (&recovered[0].outcome, expect_target) {
            (RecoveredOutcome::Applied { selection, .. }, true) => {
                assert_eq!(selection.as_ref(), Some(&target_selection));
            }
            (RecoveredOutcome::Restored { restored, .. }, false) => {
                assert_eq!(restored.as_ref(), Some(&prior));
            }
            (outcome, _) => panic!("unexpected retained recovery outcome: {outcome:?}"),
        }
        assert_eq!(
            ConfigDoc::providers_from_paths(&[config_path.clone()]).active_model,
            if expect_target {
                Some(target_selection)
            } else {
                Some(prior)
            },
        );
        let mut finalization = finalization
            .expect("correlated recovery retains a terminal finalizer");
        finalization
            .bind_default_update_authority(test_default_update_authority(1))
            .expect("recovery seals its authority before terminal receipt");
        finalization
            .finalize_after_terminal_receipt(&test_retained_receipt_proof(
                update_id, session_id, 1,
            ))
            .expect("receipt finalization removes retained artifacts");
        assert!(journal_and_backup_are_gone(&config_path));
        assert!(
            recover_retained_effective_default_journal(&target)
                .expect("retained recovery is idempotent")
                .into_parts()
                .0
                .is_empty()
        );
    }
}

/// A retained correlation is an explicit capability boundary, not merely a
/// conventional config journal. Startup/path recovery may see the same leaf
/// through a replacement `COCKPIT_CONFIG` spelling; it must leave the journal
/// and its terminal delivery untouched until an attached worker presents the
/// exact retained target.
#[test]
fn ambient_recovery_never_converges_or_delivers_a_retained_default_journal() {
    let tmp = TempDir::new().unwrap();
    let (target, config_path, _prior, requested) = retained_config_only_target(&tmp);
    let update_id = Uuid::new_v4();
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterCommittedMarker));
    assert!(
        mutate_effective_default_retained(
            &target,
            Some(&requested),
            Some(requested),
            TransactionCorrelation::RetainedDefaultUpdate {
                default_update_id: update_id,
                session_id: Uuid::new_v4(),
                authority: None,
            },
        )
        .is_err(),
        "crash leaves the durable retained handoff pending"
    );
    set_crash_inject(None);

    let sidecars_before = sidecar_entries(config_path.parent().unwrap());

    reset_ambient_recovery_operation_counts_for_tests();
    let mut delivered = Vec::new();
    let mut sink = |transaction: &RecoveredTransaction| {
        delivered.push(transaction.clone());
        Ok(())
    };
    let ambient = recover_effective_default_journal(
        &config_path,
        JournalRecovery::with_sink(&mut sink),
    )
    .expect("ambient recovery declines retained work rather than failing startup");
    assert!(ambient.is_empty());
    assert!(delivered.is_empty(), "ambient recovery must not emit a receipt");
    assert!(
        journal_path_for_config(&config_path).exists(),
        "only retained worker recovery may retire the private journal"
    );
    assert_eq!(
        sidecar_entries(config_path.parent().unwrap()),
        sidecars_before,
        "ambient retained classification must not create a lock/temporary sidecar or touch the retained backup"
    );
    assert_eq!(
        ambient_recovery_operation_counts_for_tests(),
        AmbientRecoveryOperationCounts::default(),
        "a preexisting retained journal must return before target canonicalization or ambient lock acquisition"
    );

    // Both public entry points and the orphan-sweep helper share the same
    // fence. Exercise all three even though the deterministic retained write
    // already created the lock leaf before this probe begins.
    reset_ambient_recovery_operation_counts_for_tests();
    recover_layer_journals(
        std::slice::from_ref(&config_path),
        JournalRecovery::read_only(),
    )
    .expect("public layer recovery also declines retained work");
    assert_eq!(
        ambient_recovery_operation_counts_for_tests(),
        AmbientRecoveryOperationCounts::default(),
        "public layer recovery must not derive the retained target lock"
    );
    reset_ambient_recovery_operation_counts_for_tests();
    sweep_orphans(&config_path);
    assert_eq!(
        ambient_recovery_operation_counts_for_tests(),
        AmbientRecoveryOperationCounts::default(),
        "orphan sweeping must not acquire a path lock beside a retained journal"
    );

    let recovered = recover_retained_effective_default_journal(&target)
        .expect("the held target can recover the same journal");
    assert_eq!(recovered.into_parts().0.len(), 1);
}

/// Ambient recovery first observes an ordinary journal, then the containing
/// directory is replaced with a retained one before it can derive/open the
/// ambient lock. The captured-handle bounded reread recognizes the new
/// correlation *before* lock acquisition and leaves its private artifacts
/// intact; it must never recover or lock B using facts read from A.
#[test]
fn ambient_recovery_reclassifies_a_replaced_journal_before_touching_retained_sidecars() {
    let tmp = TempDir::new().unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();

    let live_dir = tmp.path().join("live");
    let live_config = live_dir.join("config.json");
    let prior = selection("old", "a");
    let replacement = selection("new", "b");
    write_layer(&live_dir, Some(&prior), &[("old", "a"), ("new", "b")]);
    env.set_cockpit_config(&live_config);
    let cwd = tmp.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();

    // A is a normal path-owned transaction, deliberately stopped after its
    // config replacement so the first classifier has a non-retained record.
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterConfigReplaced));
    assert!(
        mutate_effective_default(
            &cwd,
            Some(&replacement),
            ActiveModelWriteMode::Replace,
            None,
            None,
            None,
        )
        .is_err()
    );
    set_crash_inject(None);
    assert!(journal_path_for_config(&live_config).exists());

    // Construct B through a retained handle, while naming its transaction
    // artifacts for the final `live/config.json` spelling. Its handle remains
    // B's capability even after the pathname swap below.
    let replacement_dir = tmp.path().join("replacement");
    let replacement_root = tmp.path().join("replacement-project");
    std::fs::create_dir_all(&replacement_root).unwrap();
    write_layer(
        &replacement_dir,
        Some(&prior),
        &[("old", "a"), ("new", "b")],
    );
    let retained_target = RetainedEffectiveDefaultTarget::new(
        std::fs::File::open(&replacement_dir).unwrap(),
        std::ffi::OsString::from("config.json"),
        journal_path_for_config(&live_config)
            .file_name()
            .unwrap()
            .to_os_string(),
        backup_path_for_config(&live_config)
            .file_name()
            .unwrap()
            .to_os_string(),
        live_config.clone(),
        replacement_root.canonicalize().unwrap(),
        EffectiveDefaultScope::ExplicitOverride,
    )
    .unwrap();
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterCommittedMarker));
    assert!(
        mutate_effective_default_retained(
            &retained_target,
            Some(&replacement),
            Some(replacement.clone()),
            TransactionCorrelation::RetainedDefaultUpdate {
                default_update_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                authority: None,
            },
        )
        .is_err()
    );
    set_crash_inject(None);
    let retained_journal = journal_path_for_config(&live_config);
    let retained_backup = backup_path_for_config(&live_config);
    assert!(replacement_dir.join(retained_journal.file_name().unwrap()).exists());

    let moved_a = tmp.path().join("moved-a");
    let replacement_for_hook = replacement_dir.clone();
    let live_for_hook = live_dir.clone();
    let moved_a_for_hook = moved_a.clone();
    set_ambient_recovery_classification_hook_for_tests(Some(Arc::new(move || {
        std::fs::rename(&live_for_hook, &moved_a_for_hook).unwrap();
        std::fs::rename(&replacement_for_hook, &live_for_hook).unwrap();
    })));

    // The journal is not at `live` until the hook runs; save B's bytes by its
    // current retained directory before invoking ambient recovery.
    let journal_before = std::fs::read(replacement_dir.join(retained_journal.file_name().unwrap()))
        .unwrap();
    let backup_before = std::fs::read(replacement_dir.join(retained_backup.file_name().unwrap()))
        .unwrap();
    let config_before = std::fs::read(replacement_dir.join("config.json")).unwrap();

    reset_ambient_recovery_operation_counts_for_tests();
    let recovered = recover_effective_default_journal(&live_config, JournalRecovery::read_only())
        .expect("the retained replacement is declined, not path-recovered");
    set_ambient_recovery_classification_hook_for_tests(None);
    assert!(recovered.is_empty());
    assert_eq!(
        std::fs::read(live_dir.join(retained_journal.file_name().unwrap())).unwrap(),
        journal_before,
        "ambient recovery must not rewrite or remove B's retained journal"
    );
    assert_eq!(
        std::fs::read(live_dir.join(retained_backup.file_name().unwrap())).unwrap(),
        backup_before,
        "ambient recovery must not reopen, compensate, or remove B's backup"
    );
    assert_eq!(
        std::fs::read(live_dir.join("config.json")).unwrap(),
        config_before,
        "the captured retained reclassification must not mutate B's config"
    );
    let operations = ambient_recovery_operation_counts_for_tests();
    assert_eq!(operations.target_canonicalizations, 1);
    assert_eq!(
        operations.lock_acquisitions, 0,
        "a newly captured retained B is rejected before ambient recovery opens its lock leaf"
    );
}

/// Once a default mutation has captured A, a pathname replacement with a
/// retained B may not redirect its probe, lock, recovery, or commit. The
/// operation continues through its held A directory; B remains byte-for-byte
/// untouched for the retained worker that owns it.
#[test]
fn ambient_mutation_keeps_probe_and_lock_on_captured_a_after_path_becomes_b() {
    let tmp = TempDir::new().unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();

    let live_dir = tmp.path().join("live");
    let live_config = live_dir.join("config.json");
    let prior = selection("old", "a");
    let replacement = selection("new", "b");
    write_layer(&live_dir, Some(&prior), &[("old", "a"), ("new", "b")]);
    env.set_cockpit_config(&live_config);
    let cwd = tmp.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();

    // Build B's correlated retained transaction while it is not reachable
    // through the ambient spelling. Its artifact names intentionally match
    // the final live target spelling.
    let replacement_dir = tmp.path().join("replacement");
    let replacement_root = tmp.path().join("replacement-project");
    std::fs::create_dir_all(&replacement_root).unwrap();
    write_layer(
        &replacement_dir,
        Some(&prior),
        &[("old", "a"), ("new", "b")],
    );
    let retained_target = RetainedEffectiveDefaultTarget::new(
        std::fs::File::open(&replacement_dir).unwrap(),
        std::ffi::OsString::from("config.json"),
        journal_path_for_config(&live_config)
            .file_name()
            .unwrap()
            .to_os_string(),
        backup_path_for_config(&live_config)
            .file_name()
            .unwrap()
            .to_os_string(),
        live_config.clone(),
        replacement_root.canonicalize().unwrap(),
        EffectiveDefaultScope::ExplicitOverride,
    )
    .unwrap();
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterCommittedMarker));
    assert!(
        mutate_effective_default_retained(
            &retained_target,
            Some(&replacement),
            Some(replacement.clone()),
            TransactionCorrelation::RetainedDefaultUpdate {
                default_update_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                authority: None,
            },
        )
        .is_err()
    );
    set_crash_inject(None);

    fn directory_snapshot(dir: &Path) -> Vec<(std::ffi::OsString, Vec<u8>)> {
        let mut entries = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    let before = directory_snapshot(&replacement_dir);
    let moved_a = tmp.path().join("moved-a");
    let replacement_for_hook = replacement_dir.clone();
    let live_for_hook = live_dir.clone();
    let moved_a_for_hook = moved_a.clone();
    set_ambient_mutation_classification_hook_for_tests(Some(Arc::new(move || {
        std::fs::rename(&live_for_hook, &moved_a_for_hook).unwrap();
        std::fs::rename(&replacement_for_hook, &live_for_hook).unwrap();
    })));

    reset_ambient_recovery_operation_counts_for_tests();
    let result = mutate_effective_default(
        &cwd,
        Some(&replacement),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect("captured A remains the mutation authority after the replacement");
    set_ambient_mutation_classification_hook_for_tests(None);
    assert_eq!(result.selection.as_ref(), Some(&replacement));
    assert_eq!(directory_snapshot(&live_dir), before);
    let operations = ambient_recovery_operation_counts_for_tests();
    assert_eq!(operations.mutation_writable_probes, 1);
    assert_eq!(operations.mutation_lock_acquisitions, 1);
    assert!(
        std::fs::read_dir(&moved_a)
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("effective-default-lock")),
        "the capability-local lock belongs to held A, not the replacement path",
    );
    assert!(
        std::fs::read_dir(&live_dir)
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("effective-default-lock")),
        "B must not receive an ambient lock sidecar",
    );
    assert_eq!(
        active_model_from_config_bytes(&std::fs::read(moved_a.join("config.json")).unwrap()),
        Some(replacement),
        "the held A target, not B's replacement spelling, receives the update",
    );
}

/// The probe is not merely a retained no-op assertion: a normal path-owned
/// journal must still derive its target identity and acquire the ambient lock
/// before recovery converges it.
#[test]
fn ambient_recovery_nonretained_control_uses_the_canonical_lock_path() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    let replacement = selection("new", "b");
    write_layer(&user, Some(&prior), &[("old", "a"), ("new", "b")]);
    let cwd = tmp.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterConfigReplaced));
    assert!(
        mutate_effective_default(
            &cwd,
            Some(&replacement),
            ActiveModelWriteMode::Replace,
            None,
            None,
            None,
        )
        .is_err()
    );
    set_crash_inject(None);

    reset_ambient_recovery_operation_counts_for_tests();
    recover_effective_default_journal(&config_path, JournalRecovery::read_only())
        .expect("ordinary config-only recovery converges under its path lock");
    let operations = ambient_recovery_operation_counts_for_tests();
    assert!(operations.target_canonicalizations >= 1);
    assert!(operations.lock_acquisitions >= 1);
}

/// A retained write cannot retire the correlation merely because its config
/// bytes reached disk. The worker refresh/terminal handoff owns cleanup.
#[test]
fn retained_commit_keeps_journal_until_terminal_finalization() {
    let tmp = TempDir::new().unwrap();
    let config_dir = tmp.path().join("retained-config");
    let project_root = tmp.path().join("project");
    std::fs::create_dir_all(&project_root).unwrap();
    let prior = selection("old", "a");
    let target_selection = selection("new", "b");
    write_layer(
        &config_dir,
        Some(&prior),
        &[("old", "a"), ("new", "b")],
    );
    let config_path = config_dir.join("config.json");
    let target = RetainedEffectiveDefaultTarget::new(
        std::fs::File::open(&config_dir).unwrap(),
        std::ffi::OsString::from("config.json"),
        journal_path_for_config(&config_path)
            .file_name()
            .unwrap()
            .to_os_string(),
        backup_path_for_config(&config_path)
            .file_name()
            .unwrap()
            .to_os_string(),
        config_path.canonicalize().unwrap(),
        project_root.canonicalize().unwrap(),
        EffectiveDefaultScope::Project,
    )
    .unwrap();
    let update_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();

    let mut pending = mutate_effective_default_retained(
        &target,
        Some(&target_selection),
        Some(target_selection.clone()),
        TransactionCorrelation::RetainedDefaultUpdate {
            default_update_id: update_id,
            session_id,
            authority: None,
        },
    )
    .expect("retained commit succeeds before receipt handoff");
    assert!(pending.result().wrote);
    assert!(
        !journal_and_backup_are_gone(&config_path),
        "a committed correlation must survive until its terminal handoff"
    );
    assert_eq!(
        ConfigDoc::providers_from_paths(&[config_path.clone()]).active_model,
        Some(target_selection),
    );

    pending
        .bind_default_update_authority(test_default_update_authority(1))
        .expect("terminal handoff seals its authority first");
    // A retry with the same fence is harmless, but a later worker must never
    // reinterpret this committed A transaction as its own B receipt.
    pending
        .bind_default_update_authority(test_default_update_authority(1))
        .expect("same authority binding is idempotent");
    assert!(
        pending
            .bind_default_update_authority(test_default_update_authority(2))
            .is_err(),
        "a sealed retained authority is write-once"
    );
    pending
        .finalize_after_terminal_receipt(&test_retained_receipt_proof(
            update_id, session_id, 1,
        ))
        .expect("terminal handoff finalizes retained artifacts");
    assert!(journal_and_backup_are_gone(&config_path));
}

/// A process death after receipt emission leaves a durable marker. Recovery is
/// cleanup-only, so the same correlation is never re-emitted after that point.
#[test]
fn retained_receipt_marker_makes_post_receipt_recovery_cleanup_only() {
    let tmp = TempDir::new().unwrap();
    let config_dir = tmp.path().join("retained-config");
    let project_root = tmp.path().join("project");
    std::fs::create_dir_all(&project_root).unwrap();
    let prior = selection("old", "a");
    let target_selection = selection("new", "b");
    write_layer(
        &config_dir,
        Some(&prior),
        &[("old", "a"), ("new", "b")],
    );
    let config_path = config_dir.join("config.json");
    let target = RetainedEffectiveDefaultTarget::new(
        std::fs::File::open(&config_dir).unwrap(),
        std::ffi::OsString::from("config.json"),
        journal_path_for_config(&config_path)
            .file_name()
            .unwrap()
            .to_os_string(),
        backup_path_for_config(&config_path)
            .file_name()
            .unwrap()
            .to_os_string(),
        config_path.canonicalize().unwrap(),
        project_root.canonicalize().unwrap(),
        EffectiveDefaultScope::Project,
    )
    .unwrap();
    let default_update_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let mut pending = mutate_effective_default_retained(
        &target,
        Some(&target_selection),
        Some(target_selection),
        TransactionCorrelation::RetainedDefaultUpdate {
            default_update_id,
            session_id,
            authority: None,
        },
    )
    .unwrap();

    pending
        .bind_default_update_authority(test_default_update_authority(1))
        .expect("terminal handoff seals its authority first");
    set_crash_inject(Some(
        EffectiveDefaultCrashPoint::AfterRetainedReceiptBeforeCleanup,
    ));
    let proof = test_retained_receipt_proof(default_update_id, session_id, 1);
    assert!(pending.finalize_after_terminal_receipt(&proof).is_err());
    set_crash_inject(None);
    assert!(!journal_and_backup_are_gone(&config_path));

    let recovery = recover_retained_effective_default_journal(&target).unwrap();
    let (recovered, finalization, receipt_validation) = recovery.into_parts();
    assert!(
        recovered.is_empty(),
        "receipt-marked recovery never re-emits a terminal correlation"
    );
    assert!(finalization.is_none());
    let receipt_validation = receipt_validation.expect("receipt marker needs daemon-ledger validation");
    assert_eq!(receipt_validation.proof(), &proof);
    assert!(
        !journal_and_backup_are_gone(&config_path),
        "the low-level recovery must retain unvalidated artifacts"
    );
    receipt_validation
        .into_finalization()
        .finalize_after_terminal_receipt(&proof)
        .expect("a daemon-validated receipt may clean retained artifacts");
    assert!(journal_and_backup_are_gone(&config_path));
}

/// A workspace-controlled journal cannot manufacture the ReceiptEmitted
/// cleanup state. Both a missing proof and a syntactically valid proof for a
/// different operation remain pending for attached-daemon ledger validation.
#[test]
fn retained_receipt_marker_missing_or_mismatched_proof_fails_closed() {
    let tmp = TempDir::new().unwrap();
    let (target, config_path, _prior, requested) = retained_config_only_target(&tmp);
    let default_update_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let mut pending = mutate_effective_default_retained(
        &target,
        Some(&requested),
        Some(requested),
        TransactionCorrelation::RetainedDefaultUpdate {
            default_update_id,
            session_id,
            authority: None,
        },
    )
    .unwrap();
    pending
        .bind_default_update_authority(test_default_update_authority(3))
        .unwrap();

    let mut record = target.load_journal().unwrap().unwrap();
    record.phase = JournalPhase::ReceiptEmitted;
    record.receipt_proof = None;
    target.write_journal(&record).unwrap();
    assert!(
        recover_retained_effective_default_journal(&target).is_err(),
        "a receipt-emitted retained journal without a proof remains pending"
    );
    assert!(!journal_and_backup_are_gone(&config_path));

    let mut record = target.load_journal().unwrap().unwrap();
    record.receipt_proof = Some(test_retained_receipt_proof(
        Uuid::new_v4(),
        session_id,
        3,
    ));
    target.write_journal(&record).unwrap();
    assert!(
        recover_retained_effective_default_journal(&target).is_err(),
        "a valid-shaped proof for another update remains pending"
    );
    assert!(!journal_and_backup_are_gone(&config_path));
}

/// A syntactically parseable but invalid authority proof is not equivalent to
/// an unsealed journal. Recovery must leave its exact retained artifacts in
/// place for repair; otherwise a damaged proof could silently become a new
/// receipt authority.
#[test]
fn retained_corrupt_authority_seal_fails_closed_without_rewriting_journal() {
    let tmp = TempDir::new().unwrap();
    let (target, config_path, _prior, requested) = retained_config_only_target(&tmp);
    let mut pending = mutate_effective_default_retained(
        &target,
        Some(&requested),
        Some(requested.clone()),
        TransactionCorrelation::RetainedDefaultUpdate {
            default_update_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            authority: None,
        },
    )
    .expect("retained commit succeeds before the terminal handoff");
    pending
        .bind_default_update_authority(test_default_update_authority(1))
        .expect("write a normally sealed journal first");

    let mut record = target
        .load_journal()
        .unwrap()
        .expect("committed retained journal");
    let Some(TransactionCorrelation::RetainedDefaultUpdate { authority, .. }) = record.correlation.as_mut()
    else {
        panic!("expected config-only default-update correlation");
    };
    *authority = Some(DefaultUpdateAuthorityBinding {
        authority_revision: "not-a-valid-authority-digest".to_string(),
        config_generation: 1,
    });
    target.write_journal(&record).unwrap();
    let journal_path = journal_path_for_config(&config_path);
    let before = std::fs::read(&journal_path).unwrap();

    let error = recover_retained_effective_default_journal(&target)
        .expect_err("a corrupt authority seal must not be interpreted as unbound");
    assert!(
        format!("{error:#}").contains("authority revision"),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read(&journal_path).unwrap(),
        before,
        "failed recovery never rewrites the corrupt journal"
    );
    assert!(
        !journal_and_backup_are_gone(&config_path),
        "failed recovery never cleans correlated artifacts"
    );
    assert_eq!(
        ConfigDoc::providers_from_paths(&[config_path]).active_model,
        Some(requested),
        "failed recovery preserves the already committed A bytes"
    );
}

/// A committed journal is intentionally allowed to be unbound until the
/// worker refresh completes, but no terminal cleanup phase may run before
/// that one-way seal exists.
#[test]
fn retained_terminal_phases_require_a_sealed_authority_and_stay_pending_without_one() {
    let tmp = TempDir::new().unwrap();
    let (target, config_path, _prior, requested) = retained_config_only_target(&tmp);
    let pending = mutate_effective_default_retained(
        &target,
        Some(&requested),
        Some(requested.clone()),
        TransactionCorrelation::RetainedDefaultUpdate {
            default_update_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            authority: None,
        },
    )
    .expect("retained commit succeeds before authority sealing");
    let journal_path = journal_path_for_config(&config_path);
    let before_finalize = std::fs::read(&journal_path).unwrap();
    let error = pending
        .finalize_after_terminal_receipt(&test_retained_receipt_proof(
            Uuid::new_v4(),
            Uuid::new_v4(),
            1,
        ))
        .expect_err("unsealed journal cannot be terminally finalized");
    assert!(
        format!("{error:#}").contains("no sealed authority"),
        "{error:#}"
    );
    assert_eq!(std::fs::read(&journal_path).unwrap(), before_finalize);
    assert!(!journal_and_backup_are_gone(&config_path));

    let mut record = target
        .load_journal()
        .unwrap()
        .expect("the unsealed journal remains pending");
    record.phase = JournalPhase::ReceiptEmitted;
    target.write_journal(&record).unwrap();
    let before_recovery = std::fs::read(&journal_path).unwrap();
    let error = recover_retained_effective_default_journal(&target)
        .expect_err("receipt-emitted cleanup cannot proceed without the seal");
    assert!(
        format!("{error:#}").contains("no sealed authority"),
        "{error:#}"
    );
    assert_eq!(std::fs::read(&journal_path).unwrap(), before_recovery);
    assert!(!journal_and_backup_are_gone(&config_path));
    assert_eq!(
        ConfigDoc::providers_from_paths(&[config_path]).active_model,
        Some(requested),
        "the malformed terminal phase never compensates or rewrites committed bytes"
    );
}

/// Config-only (`SetDefaultModel`) crash coverage: no session phase runs, and
/// a "restarted" process converges the config to prior or target.
#[test]
fn config_only_crash_at_every_phase_converges_to_prior_or_target() {
    for point in ALL_CRASH_POINTS {
        let tmp = TempDir::new().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        reset_recovery_backoff_for_tests();
        let user = user_dir(tmp.path());
        let prior = selection("old", "a");
        let target = selection("new", "b");
        write_layer(&user, Some(&prior), &[("new", "b"), ("old", "a")]);
        let cwd = tmp.path().join("proj");
        std::fs::create_dir_all(&cwd).unwrap();
        let config_path = user.join("config.json");

        set_crash_inject(Some(*point));
        let outcome = mutate_effective_default(
            &cwd,
            Some(&target),
            ActiveModelWriteMode::Replace,
            None,
            None,
            None,
        );
        set_crash_inject(None);
        if *point == EffectiveDefaultCrashPoint::AfterJournalCleanup {
            assert!(outcome.is_err(), "{point:?}");
        }

        // Simulated restart: recovery must complete before a snapshot is served.
        recover_effective_default_journal(&config_path, JournalRecovery::read_only())
            .expect("idempotent recovery");
        // Idempotent second pass.
        recover_effective_default_journal(&config_path, JournalRecovery::read_only())
            .expect("second recovery pass");

        let resolved = fresh_session_resolution(&cwd);
        assert!(
            resolved.as_ref() == Some(&prior) || resolved.as_ref() == Some(&target),
            "{point:?} must converge to prior or target, got {resolved:?}"
        );
        assert!(
            journal_and_backup_are_gone(&config_path),
            "{point:?} must remove the journal and private backup after convergence"
        );
    }
}

/// Session+default crash coverage: after recovery both durable authorities
/// expose the same reference — never one target and one prior.
#[test]
fn session_and_default_crash_at_every_phase_converges_both_authorities() {
    for point in ALL_CRASH_POINTS {
        let tmp = TempDir::new().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        reset_recovery_backoff_for_tests();
        let user = user_dir(tmp.path());
        let prior = selection("old", "a");
        let target = selection("new", "b");
        write_layer(&user, Some(&prior), &[("new", "b"), ("old", "a")]);
        let cwd = tmp.path().join("proj");
        std::fs::create_dir_all(&cwd).unwrap();
        let config_path = user.join("config.json");

        let mut sessions = FakeSessions {
            revision: 5,
            selection: Some(prior.clone()),
            ..Default::default()
        };
        set_crash_inject(Some(*point));
        let _ = mutate_effective_default(
            &cwd,
            Some(&target),
            ActiveModelWriteMode::Replace,
            Some(participant(&mut sessions, prior.clone())),
            None,
            None,
        );
        set_crash_inject(None);

        recover_effective_default_journal(
            &config_path,
            JournalRecovery::with_sessions(&mut sessions),
        )
        .expect("idempotent recovery");
        recover_effective_default_journal(
            &config_path,
            JournalRecovery::with_sessions(&mut sessions),
        )
        .expect("second recovery pass");

        let config_default = fresh_session_resolution(&cwd);
        assert_eq!(
            config_default, sessions.selection,
            "{point:?} left the config default and session model divergent"
        );
        assert!(
            config_default.as_ref() == Some(&prior) || config_default.as_ref() == Some(&target),
            "{point:?} converged to neither recorded value: {config_default:?}"
        );
        assert!(journal_and_backup_are_gone(&config_path), "{point:?}");
    }
}

#[test]
fn journal_metadata_carries_only_identifiers_digests_and_model_references() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    std::fs::create_dir_all(&user).unwrap();
    std::fs::write(
        user.join("config.json"),
        r#"{"active_model":{"provider":"old","model":"a"},"api_key":"sk-do-not-journal-me"}"#,
    )
    .unwrap();
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterJournalPrepared));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    );
    set_crash_inject(None);

    let journal_path = journal_path_for_config(&config_path);
    let raw = std::fs::read_to_string(&journal_path).expect("journal survives the crash");
    assert!(
        !raw.contains("sk-do-not-journal-me"),
        "journal metadata must never contain raw configuration bytes"
    );
    assert!(!raw.contains("layer_opaque"));
    assert!(raw.contains("old_config_digest") && raw.contains("new_config_digest"));
    assert!(raw.contains("target_path_digest"));
    assert!(
        !raw.contains(&config_path.display().to_string()),
        "the target path is recorded as a digest, not a raw path"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let backup = backup_path_for_config(&config_path);
        assert!(backup.exists(), "the private rollback snapshot is retained");
        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600,
            "the rollback snapshot must be owner-only"
        );
        let backup_bytes = std::fs::read_to_string(&backup).unwrap();
        assert!(
            backup_bytes.contains("sk-do-not-journal-me"),
            "the byte-for-byte snapshot lives only in the private sibling"
        );
    }

    recover_effective_default_journal(&config_path, JournalRecovery::read_only()).unwrap();
    assert!(journal_and_backup_are_gone(&config_path));
}

#[test]
fn recovery_refuses_a_config_digest_mismatch_without_clobbering_data() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("old", "a")), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterJournalPrepared));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    );
    set_crash_inject(None);

    // A third party rewrites the layer out of band while the journal is open.
    let interloper = r#"{"active_model":{"provider":"third","model":"party"}}"#;
    std::fs::write(&config_path, interloper).unwrap();

    let error = recover_effective_default_journal(&config_path, JournalRecovery::read_only())
        .expect_err("recovery must fail closed on a digest mismatch");
    assert!(
        format!("{error:#}").contains("refusing to overwrite")
            || format!("{error:#}").contains("does not match"),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        interloper,
        "a conflicting concurrent mutation is never overwritten by compensation"
    );
    assert!(
        journal_path_for_config(&config_path).exists(),
        "an unconverged journal stays recoverable"
    );
}

#[test]
fn recovery_refuses_a_session_revision_mismatch_without_overwriting() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    let mut sessions = FakeSessions {
        revision: 9,
        selection: Some(prior.clone()),
        ..Default::default()
    };
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterSessionCas));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, prior.clone())),
        None,
        None,
    );
    set_crash_inject(None);
    assert_eq!(sessions.revision, 10, "the CAS committed before the crash");

    // Someone else moved the session on before recovery ran.
    let later = selection("later", "l");
    sessions.revision = 11;
    sessions.selection = Some(later.clone());

    let error = recover_effective_default_journal(
        &config_path,
        JournalRecovery::with_sessions(&mut sessions),
    )
    .expect_err("recovery must not clobber a later selection");
    assert!(format!("{error:#}").contains("unexpected active-model revision"));
    assert_eq!(sessions.selection.as_ref(), Some(&later));
    assert!(
        journal_path_for_config(&config_path).exists(),
        "the conflicting transaction remains recoverable"
    );
}

#[test]
fn out_of_context_journal_is_refused_and_left_for_repair() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("old", "a")), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");
    let before = std::fs::read_to_string(&config_path).unwrap();

    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterJournalPrepared));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    );
    set_crash_inject(None);

    // Repoint the journal at a different config layer.
    let journal_path = journal_path_for_config(&config_path);
    let mut record: JournalRecord =
        serde_json::from_str(&std::fs::read_to_string(&journal_path).unwrap()).unwrap();
    record.target_path_digest = "0".repeat(64);
    std::fs::write(
        &journal_path,
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();

    recover_effective_default_journal(&config_path, JournalRecovery::read_only())
        .expect("out-of-context is not an error");
    assert!(
        journal_path.exists(),
        "an out-of-context journal is left for manual repair, never applied"
    );
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), before);
}

// ---- AC11: concurrency, staleness, and secret hygiene ----------------------

#[test]
fn two_explicit_replacements_serialize_and_each_result_is_its_own() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(
        &user,
        Some(&selection("old", "a")),
        &[("first", "one"), ("second", "two")],
    );
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();

    let selections = [selection("first", "one"), selection("second", "two")];
    let barrier = Arc::new(Barrier::new(selections.len()));
    let handles = selections
        .iter()
        .cloned()
        .map(|requested| {
            let barrier = Arc::clone(&barrier);
            let cwd = cwd.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let result = mutate_effective_default(
                    &cwd,
                    Some(&requested),
                    ActiveModelWriteMode::Replace,
                    None,
                    None,
                    None,
                )
                .expect("both explicit replacements must serialize and succeed");
                (requested, result)
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();

    for (requested, result) in &results {
        assert_eq!(
            result.selection.as_ref(),
            Some(requested),
            "every outcome is tied to its own request, never the other writer's model"
        );
    }
    let final_default = fresh_session_resolution(&cwd).expect("one writer won");
    assert!(selections.contains(&final_default));
    assert!(journal_and_backup_are_gone(&user.join("config.json")));
}

#[test]
fn an_initializer_cannot_overwrite_a_successful_explicit_default() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, None, &[("explicit", "x"), ("initial", "i")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();

    let explicit = selection("explicit", "x");
    mutate_effective_default(
        &cwd,
        Some(&explicit),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect("explicit replacement");

    let initializer = mutate_effective_default(
        &cwd,
        Some(&selection("initial", "i")),
        ActiveModelWriteMode::InitializeIfMissing,
        None,
        None,
        None,
    )
    .expect("an initializer observes the winner instead of writing");

    assert!(!initializer.wrote && initializer.unchanged);
    assert_eq!(initializer.selection.as_ref(), Some(&explicit));
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&explicit));
}

#[test]
fn rejections_and_journal_records_disclose_no_paths_or_secrets() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();

    // No layer exists at all: the rejection may only name a scope.
    let error = mutate_effective_default(
        &cwd,
        Some(&selection("p", "m")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect_err("no writable layer");
    let rendered = format!("{} {:?}", error.user_message, error.scope_label);
    assert!(
        !rendered.contains(&tmp.path().display().to_string()),
        "a rejection must not disclose a filesystem path: {rendered}"
    );
    assert!(!rendered.contains("config.json"));
}

#[test]
fn a_stale_reader_cannot_claim_a_concurrent_writers_model() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    let mine = selection("mine", "m");
    write_layer(&user, Some(&mine), &[("mine", "m"), ("theirs", "t")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();

    // A no-op request for the already-effective model reports `unchanged` and
    // names only its own reference.
    let result = mutate_effective_default(
        &cwd,
        Some(&mine),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect("no-op");
    assert!(result.unchanged);
    assert_eq!(result.selection.as_ref(), Some(&mine));

    // A different writer then wins; the earlier result is unaffected.
    let theirs = selection("theirs", "t");
    mutate_effective_default(
        &cwd,
        Some(&theirs),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect("second writer");
    assert_eq!(result.selection.as_ref(), Some(&mine));
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&theirs));
}

#[test]
fn recovery_runs_under_an_already_held_mutation_lock_without_deadlocking() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    // Leave a journal behind, then run a fresh mutation: it acquires the lock
    // and recovers under it. A second `acquire` on this thread would block on
    // the guard it already holds.
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterJournalPrepared));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("mid", "m")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    );
    set_crash_inject(None);
    assert!(journal_path_for_config(&config_path).exists());

    let target = selection("new", "b");
    let result = mutate_effective_default(
        &cwd,
        Some(&target),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect("pre-mutation recovery must not self-deadlock");

    assert_eq!(result.selection.as_ref(), Some(&target));
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&target));
    assert!(journal_and_backup_are_gone(&config_path));
}

#[test]
fn a_session_persistence_failure_converges_by_restoring_both_authorities() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let before = std::fs::read_to_string(user.join("config.json")).unwrap();

    let mut sessions = FakeSessions {
        revision: 1,
        selection: Some(prior.clone()),
        fail_cas: true,
        ..Default::default()
    };
    let error = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, prior.clone())),
        None,
        None,
    )
    .expect_err("a failed session CAS cannot leave the default applied");

    assert!(error.restored_after_boundary, "{error:?}");
    // The CAS errored *before* writing, so the revision guard classifies the
    // session as untouched and no compensating CAS runs — but the authority
    // was retained, because an error alone does not prove that.
    assert_eq!(sessions.cas_calls, 1);
    assert_eq!(sessions.revision, 1, "the guard found nothing to revert");
    assert_eq!(sessions.selection.as_ref(), Some(&prior));
    assert_eq!(
        std::fs::read_to_string(user.join("config.json")).unwrap(),
        before
    );
    assert!(journal_and_backup_are_gone(&user.join("config.json")));
}

#[test]
fn recovery_skips_session_compensation_when_the_session_row_is_gone() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    let mut sessions = FakeSessions {
        revision: 4,
        selection: Some(prior.clone()),
        ..Default::default()
    };
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterSessionCas));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, prior.clone())),
        None,
        None,
    );
    set_crash_inject(None);

    // The session was deleted before the daemon restarted.
    sessions.missing = true;
    recover_effective_default_journal(&config_path, JournalRecovery::with_sessions(&mut sessions))
        .expect("a deleted session leaves nothing to compensate");
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&prior));
    assert!(journal_and_backup_are_gone(&config_path));
}

// ---- Who may finish a transaction (session-authority ownership) ------------

/// The blocker case: a recovery pass with **no** session authority must not
/// touch a session-bearing journal. It may not compensate, and it may not
/// delete the journal or its rollback snapshot — doing so would strand the
/// session half of the transaction forever.
#[test]
fn recovery_without_session_authority_leaves_a_session_bearing_journal_intact() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b"), ("old", "a")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    let mut sessions = FakeSessions {
        revision: 5,
        selection: Some(prior.clone()),
        ..Default::default()
    };
    // Crash with the session already advanced and the config already replaced.
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterConfigReplaced));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, prior.clone())),
        None,
        None,
    );
    set_crash_inject(None);
    let journal_path = journal_path_for_config(&config_path);
    let backup_path = backup_path_for_config(&config_path);
    assert!(journal_path.exists() && backup_path.exists());
    let journal_before = std::fs::read_to_string(&journal_path).unwrap();
    let session_before = sessions.selection.clone();
    let revision_before = sessions.revision;

    // A reader with no session authority.
    let recovered = recover_effective_default_journal(&config_path, JournalRecovery::read_only())
        .expect("a session-bearing journal is not an error for a plain reader");
    assert!(recovered.is_empty());
    assert!(
        journal_path.exists() && backup_path.exists(),
        "a plain reader must never delete a session-bearing journal or its snapshot"
    );
    assert_eq!(
        std::fs::read_to_string(&journal_path).unwrap(),
        journal_before
    );
    assert_eq!(sessions.selection, session_before);
    assert_eq!(sessions.revision, revision_before);
    assert_eq!(sessions.cas_calls, 1, "no compensating CAS was attempted");

    // And the layer is masked, so a fresh client sees the agreed prior value
    // rather than the half-committed one that is already on disk.
    assert_eq!(
        fresh_session_resolution(&cwd).as_ref(),
        Some(&prior),
        "a pending session transaction must be masked on read"
    );

    // The daemon pass, with authority, converges it.
    reset_recovery_backoff_for_tests();
    recover_effective_default_journal(&config_path, JournalRecovery::with_sessions(&mut sessions))
        .expect("the authoritative pass converges");
    assert!(journal_and_backup_are_gone(&config_path));
    assert_eq!(fresh_session_resolution(&cwd), sessions.selection);
}

/// A journal naming another session must never be compensated through an
/// authority bound to a different one.
#[test]
fn a_bound_authority_refuses_another_sessions_journal() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    let mut sessions = FakeSessions {
        revision: 2,
        selection: Some(prior.clone()),
        ..Default::default()
    };
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterSessionCas));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, prior.clone())),
        None,
        None,
    );
    set_crash_inject(None);

    // A different session's authority must decline entirely.
    let mut foreign = FakeSessions {
        revision: 99,
        selection: Some(selection("foreign", "f")),
        bound: Some(Uuid::from_u128(4242)),
        ..Default::default()
    };
    let recovered = recover_effective_default_journal(
        &config_path,
        JournalRecovery::with_sessions(&mut foreign),
    )
    .expect("declining is not an error");
    assert!(recovered.is_empty());
    assert_eq!(foreign.cas_calls, 0, "no CAS may touch a foreign session");
    assert_eq!(foreign.revision, 99);
    assert!(
        journal_path_for_config(&config_path).exists(),
        "the journal stays for the authority that owns it"
    );
}

/// Compensation must be resumable: the `compensating` marker is durable
/// *before* the session revert, so a re-run recognizes the already-reverted
/// revision instead of refusing forever and bricking attach.
#[test]
fn interrupted_compensation_resumes_instead_of_refusing_forever() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b"), ("old", "a")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    let mut sessions = FakeSessions {
        revision: 7,
        selection: Some(prior.clone()),
        ..Default::default()
    };
    // Crash with the session committed and the config still prior.
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterSessionCas));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, prior.clone())),
        None,
        None,
    );
    set_crash_inject(None);
    assert_eq!(sessions.revision, 8, "the CAS committed before the crash");

    // Recovery writes the `compensating` marker, reverts the session to 9,
    // and is killed before it can restore the config half.
    reset_recovery_backoff_for_tests();
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterCompensatingMarker));
    let interrupted = recover_effective_default_journal(
        &config_path,
        JournalRecovery::with_sessions(&mut sessions),
    );
    set_crash_inject(None);
    assert!(interrupted.is_err(), "the interrupted pass reports failure");
    assert!(
        journal_path_for_config(&config_path).exists(),
        "an unconverged journal stays recoverable"
    );

    // Simulate the revert having landed just before the kill.
    sessions.revision = 9;
    sessions.selection = Some(prior.clone());

    // The next pass must resume, not refuse: revision 9 is expected+2, which
    // only the durable `compensating` marker makes recognizable.
    reset_recovery_backoff_for_tests();
    recover_effective_default_journal(&config_path, JournalRecovery::with_sessions(&mut sessions))
        .expect("compensation resumes from the recorded phase");
    assert!(journal_and_backup_are_gone(&config_path));
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&prior));
    assert_eq!(sessions.selection.as_ref(), Some(&prior));
}

// ---- Journal/backup keying and crash-window debris -------------------------

/// Two config files can share one directory (an explicit `COCKPIT_CONFIG`
/// beside a conventional `config.json`). Their journals and rollback snapshots
/// must not collide, and a mutation must never overwrite a foreign pending
/// journal.
#[test]
fn journals_are_keyed_per_config_file_and_never_overwrite_a_foreign_one() {
    let tmp = TempDir::new().unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let shared_dir = tmp.path().join("shared");
    write_layer(&shared_dir, Some(&selection("old", "a")), &[("new", "b")]);
    let conventional = shared_dir.join("config.json");
    let explicit = shared_dir.join("explicit.json");
    std::fs::copy(&conventional, &explicit).unwrap();
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();

    assert_ne!(
        journal_path_for_config(&conventional),
        journal_path_for_config(&explicit),
        "two config files in one directory must not share a journal"
    );
    assert_ne!(
        backup_path_for_config(&conventional),
        backup_path_for_config(&explicit),
        "two config files in one directory must not share a rollback snapshot"
    );

    // Leave a pending journal for the explicit file, then mutate through it.
    env.set_cockpit_config(&explicit);
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterJournalPrepared));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    );
    set_crash_inject(None);
    let explicit_journal = journal_path_for_config(&explicit);
    assert!(explicit_journal.exists());
    let foreign_before = std::fs::read_to_string(&explicit_journal).unwrap();

    // Corrupt it into a foreign record so recovery must refuse it, then prove
    // a fresh mutation fails closed rather than overwriting it.
    let mut record: JournalRecord = serde_json::from_str(&foreign_before).unwrap();
    record.target_path_digest = "0".repeat(64);
    let rewritten = serde_json::to_string_pretty(&record).unwrap();
    std::fs::write(&explicit_journal, &rewritten).unwrap();

    reset_recovery_backoff_for_tests();
    let error = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect_err("a foreign pending journal must fail the mutation closed");
    assert_eq!(error.diagnostic_code, "effective_default_journal_conflict");
    assert_eq!(
        std::fs::read_to_string(&explicit_journal).unwrap(),
        rewritten,
        "a foreign journal is never overwritten"
    );
}

/// Crash-window debris: a rollback snapshot whose journal never landed, and a
/// private temporary replacement whose process was killed. Neither has an
/// owning transaction, so a later pass sweeps them.
#[cfg(unix)]
#[test]
fn recovery_sweeps_orphan_snapshots_and_stale_temporary_replacements() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("old", "a")), &[("old", "a")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    // An orphan rollback snapshot with no journal.
    let orphan_backup = backup_path_for_config(&config_path);
    std::fs::write(&orphan_backup, b"{}").unwrap();
    std::fs::set_permissions(&orphan_backup, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Only a *stale* snapshot is debris: a fresh one may belong to a live
    // transaction that has not written its journal yet.
    filetime_set(&orphan_backup, old_time_for_sweep());
    // A stale private temporary replacement.
    let stale_temp = user.join(".config.json.999.1.tmp");
    std::fs::write(&stale_temp, b"{}").unwrap();
    std::fs::set_permissions(&stale_temp, std::fs::Permissions::from_mode(0o600)).unwrap();
    filetime_set(&stale_temp, old_time_for_sweep());
    // A fresh temporary replacement that may still belong to a live writer.
    let fresh_temp = user.join(".config.json.999.2.tmp");
    std::fs::write(&fresh_temp, b"{}").unwrap();
    std::fs::set_permissions(&fresh_temp, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Reset immediately before the sweep so this directory counts as unseen.
    reset_recovery_backoff_for_tests();
    recover_effective_default_journal(&config_path, JournalRecovery::read_only()).unwrap();

    assert!(!orphan_backup.exists(), "an orphan snapshot must be swept");
    assert!(!stale_temp.exists(), "a stale temporary must be swept");
    assert!(
        fresh_temp.exists(),
        "a recent temporary may still belong to a live writer"
    );
}

#[cfg(unix)]
fn old_time_for_sweep() -> std::time::SystemTime {
    std::time::SystemTime::now() - std::time::Duration::from_secs(STALE_TEMP_AGE.as_secs() * 2)
}

/// Set an mtime far enough in the past to qualify as stale, without adding a
/// dependency: rewrite the file through a handle and then adjust via `utimes`.
#[cfg(unix)]
fn filetime_set(path: &Path, when: std::time::SystemTime) {
    use std::os::unix::ffi::OsStrExt as _;

    let seconds = when
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as libc::time_t;
    let times = [
        libc::timeval {
            tv_sec: seconds,
            tv_usec: 0,
        },
        libc::timeval {
            tv_sec: seconds,
            tv_usec: 0,
        },
    ];
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a live NUL-terminated string and `times` is a live
    // two-element array, exactly what `utimes(2)` requires.
    let result = unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()) };
    assert_eq!(result, 0, "utimes failed for {}", path.display());
}

// ---- Real I/O faults (not simulated crash points) --------------------------

/// A genuine OS failure — not an injected crash — on the **pre-boundary**
/// writability probe. Named for what it actually exercises: the probe runs
/// before any journal exists, so this is the zero-mutation rejection path, not
/// convergence. The post-boundary real-fault case is
/// `a_real_compensation_failure_after_the_boundary_fails_closed`.
///
/// The layer must be a *caller-owned* one (an explicit `COCKPIT_CONFIG`):
/// cockpit-owned config directories are deliberately repaired to `0700` by the
/// private-write path, so chmodding one read-only would not stay read-only.
#[cfg(unix)]
#[test]
fn a_real_readonly_directory_failure_rejects_before_the_boundary() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = TempDir::new().unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let explicit_dir = tmp.path().join("explicit");
    let prior = selection("old", "a");
    write_layer(&explicit_dir, Some(&prior), &[("new", "b"), ("old", "a")]);
    let explicit = explicit_dir.join("config.json");
    env.set_cockpit_config(&explicit);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let before = std::fs::read_to_string(&explicit).unwrap();

    let original = std::fs::metadata(&explicit_dir).unwrap().permissions();
    let mut readonly = original.clone();
    readonly.set_mode(original.mode() & !0o222);
    std::fs::set_permissions(&explicit_dir, readonly).unwrap();
    let error = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    )
    .expect_err("a read-only layer directory is a real failure");
    std::fs::set_permissions(&explicit_dir, original).unwrap();

    assert_eq!(error.diagnostic_code, "effective_default_target_unwritable");
    assert!(!error.restored_after_boundary && !error.recovery_pending);
    assert_eq!(
        std::fs::read_to_string(&explicit).unwrap(),
        before,
        "a pre-boundary failure mutates nothing"
    );
    assert!(journal_and_backup_are_gone(&explicit));
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&prior));
}

/// `cockpit doctor` must be able to describe a journal recovery refuses to
/// touch, without leaking configuration content.
#[test]
fn journal_diagnostics_describe_a_pending_journal_without_configuration_content() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    std::fs::create_dir_all(&user).unwrap();
    std::fs::write(
        user.join("config.json"),
        r#"{"active_model":{"provider":"old","model":"a"},"api_key":"sk-not-in-diagnostics"}"#,
    )
    .unwrap();
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    assert!(
        journal_diagnostics(&cwd).is_empty(),
        "no journal, no report"
    );

    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterJournalPrepared));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    );
    set_crash_inject(None);

    let reported = journal_diagnostics(&cwd);
    assert_eq!(reported.len(), 1);
    let entry = &reported[0];
    assert_eq!(entry.journal_path, journal_path_for_config(&config_path));
    assert_eq!(entry.scope_label, "user");
    assert_eq!(entry.phase, "prepared");
    assert!(!entry.needs_session_authority);
    assert!(!entry.out_of_context);
    let rendered = format!("{entry:?}");
    assert!(
        !rendered.contains("sk-not-in-diagnostics"),
        "diagnostics must never carry configuration content: {rendered}"
    );
}

// ---- Correlated terminal delivery ------------------------------------------

/// A correlated transaction is a promise of exactly one terminal event. A pass
/// that has nowhere to deliver it must not converge the journal — otherwise
/// cleanup destroys the correlation and the client waits forever.
#[test]
fn a_plain_reader_never_converges_a_correlated_journal_and_the_daemon_pass_delivers_it() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    let target = selection("new", "b");
    write_layer(&user, Some(&prior), &[("new", "b"), ("old", "a")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    let default_update_id = Uuid::from_u128(11);
    let session_id = Uuid::from_u128(12);
    let correlation = TransactionCorrelation::DefaultUpdate {
        default_update_id,
        session_id,
        authority: None,
    };
    // A config-only (no session) but correlated transaction that crashed after
    // its `committed` marker was fsynced — the phase recovery converges
    // *forward* from. (`AfterConfigReplaced` leaves a config-only journal at
    // `prepared`, which correctly converges backwards instead.)
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterReloadVerified));
    let _ = mutate_effective_default(
        &cwd,
        Some(&target),
        ActiveModelWriteMode::Replace,
        None,
        None,
        Some(correlation),
    );
    set_crash_inject(None);
    assert!(journal_path_for_config(&config_path).exists());

    // A plain configuration read must leave it entirely alone and mask it.
    let recovered = recover_effective_default_journal(&config_path, JournalRecovery::read_only())
        .expect("declining is not an error");
    assert!(recovered.is_empty());
    assert!(
        journal_path_for_config(&config_path).exists(),
        "a correlated journal survives a pass that cannot deliver its event"
    );
    assert_eq!(
        fresh_session_resolution(&cwd).as_ref(),
        Some(&prior),
        "the layer is masked until the correlated transaction is finished"
    );

    // The daemon pass supplies a sink, converges, and receives the terminal
    // result *before* the journal is removed.
    let mut delivered: Vec<RecoveredTransaction> = Vec::new();
    {
        let mut journal_present_at_delivery = false;
        let journal = journal_path_for_config(&config_path);
        let mut sink = |transaction: &RecoveredTransaction| -> Result<()> {
            journal_present_at_delivery = journal.exists();
            delivered.push(transaction.clone());
            Ok(())
        };
        let mut sessions = FakeSessions::default();
        let recovery = JournalRecovery::with_sessions(&mut sessions).with_sink(&mut sink);
        recover_effective_default_journal(&config_path, recovery).expect("daemon pass converges");
        assert!(
            journal_present_at_delivery,
            "the terminal result must be handed off before cleanup"
        );
    }
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].correlation, correlation);
    match &delivered[0].outcome {
        RecoveredOutcome::Applied {
            selection,
            generation,
        } => {
            assert_eq!(selection.as_ref(), Some(&target));
            assert!(
                *generation >= 1,
                "a recovered Applied must carry a real resolution generation, not a placeholder"
            );
        }
        other => panic!("expected Applied, got {other:?}"),
    }
    assert!(journal_and_backup_are_gone(&config_path));
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&target));
}

/// Forward convergence proves the transaction's **own** layer holds the
/// recorded bytes, then reports what the merged configuration actually
/// resolves to. A higher-precedence layer that changed between the crash and
/// recovery is *divergence to report*, not a failure: treating it as an error
/// would wedge recovery — and therefore attach — for the whole project root
/// with no repair path, even though both authorities already hold the target.
#[test]
fn forward_recovery_reports_divergence_instead_of_wedging_on_a_higher_layer_change() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    write_layer(
        &user,
        Some(&selection("old", "a")),
        &[("new", "b"), ("old", "a"), ("machine", "m")],
    );
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");
    let requested = selection("new", "b");

    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterReloadVerified));
    let _ = mutate_effective_default(
        &cwd,
        Some(&requested),
        ActiveModelWriteMode::Replace,
        None,
        None,
        Some(TransactionCorrelation::DefaultUpdate {
            default_update_id: Uuid::from_u128(21),
            session_id: Uuid::from_u128(22),
            authority: None,
        }),
    );
    set_crash_inject(None);

    // A higher-precedence machine-local layer appears while the journal is open.
    let machine = crate::config::dirs::local_config_dir_for(&cwd).unwrap();
    let overriding = selection("machine", "m");
    write_layer(&machine, Some(&overriding), &[]);

    let mut delivered: Vec<RecoveredTransaction> = Vec::new();
    {
        let mut sink = |transaction: &RecoveredTransaction| -> Result<()> {
            delivered.push(transaction.clone());
            Ok(())
        };
        let mut sessions = FakeSessions::default();
        let recovery = JournalRecovery::with_sessions(&mut sessions).with_sink(&mut sink);
        recover_effective_default_journal(&config_path, recovery)
            .expect("a higher-layer change must not wedge recovery");
    }

    assert!(
        journal_and_backup_are_gone(&config_path),
        "the transaction converged; nothing is left to repair by hand"
    );
    // The transaction's own layer holds exactly what it committed.
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_value::<ActiveModelRef>(raw["active_model"].clone()).unwrap(),
        requested
    );
    assert_eq!(delivered.len(), 1);
    match &delivered[0].outcome {
        RecoveredOutcome::Applied {
            selection,
            generation,
        } => {
            assert_eq!(
                selection.as_ref(),
                Some(&overriding),
                "the terminal event reports the *effective* value, so the client sees divergence"
            );
            assert_ne!(selection.as_ref(), delivered[0].requested.as_ref());
            assert!(*generation >= 1);
        }
        other => panic!("expected Applied-with-divergence, got {other:?}"),
    }
}

/// The negative cache may suppress duplicate *work*, never change the
/// *result*: a passive read behind an unconverged journal must keep failing,
/// and an explicit (forced) pass must still do the work.
#[test]
fn the_recovery_cache_replays_failure_and_never_downgrades_to_success() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    write_layer(&user, Some(&selection("old", "a")), &[("new", "b")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");
    let journal_path = journal_path_for_config(&config_path);

    // An unparseable journal: every pass fails, forever.
    std::fs::write(&journal_path, b"{ not a journal record").unwrap();

    let first = recover_effective_default_journal(&config_path, JournalRecovery::read_only())
        .expect_err("an unreadable journal fails closed");
    let second = recover_effective_default_journal(&config_path, JournalRecovery::read_only())
        .expect_err("a cached negative must replay the failure, not report success");
    assert!(format!("{first:#}").contains("parsing journal"));
    assert!(format!("{second:#}").contains("parsing journal"));

    // A forced pass bypasses the cache and does the work again (still failing).
    let mut sessions = FakeSessions::default();
    let forced = recover_effective_default_journal(
        &config_path,
        JournalRecovery::with_sessions(&mut sessions),
    )
    .expect_err("an explicit recovery attempt still fails closed");
    assert!(format!("{forced:#}").contains("parsing journal"));
    assert!(journal_path.exists());
}

/// The `recovery_pending` branch: compensation succeeds but the journal cannot
/// be removed. No terminal outcome may be claimed — the transaction stays open
/// for a later pass.
#[test]
fn a_failed_journal_cleanup_leaves_the_transaction_pending_not_terminal() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b"), ("old", "a")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    // A session CAS conflict drives `converge(forward_allowed = false)`;
    // compensation succeeds, then journal cleanup is made to fail.
    let mut sessions = FakeSessions {
        revision: 4,
        selection: Some(prior.clone()),
        ..Default::default()
    };
    let spoiled = SessionDefaultParticipant {
        session_id: Uuid::from_u128(7),
        prior: prior.clone(),
        expected_revision: 3,
        authority: &mut sessions,
    };
    set_crash_inject(Some(EffectiveDefaultCrashPoint::FailJournalCleanup));
    let error = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(spoiled),
        None,
        Some(TransactionCorrelation::ModelSelection {
            selection_id: Uuid::from_u128(31),
            session_id: Uuid::from_u128(7),
        }),
    )
    .expect_err("cleanup failure is not a terminal outcome");
    set_crash_inject(None);

    assert!(
        error.recovery_pending,
        "an unprovable outcome must be pending, not a rejection: {error:?}"
    );
    assert!(
        !error.restored_after_boundary,
        "pending must never masquerade as a verified restoration"
    );
    assert_eq!(error.diagnostic_code, "effective_default_recovery_pending");
    assert!(
        journal_path_for_config(&config_path).exists(),
        "a pending transaction keeps its journal so a later pass can finish it"
    );

    // A later pass with delivery capability finishes it exactly once.
    reset_recovery_backoff_for_tests();
    let mut delivered: Vec<RecoveredTransaction> = Vec::new();
    {
        let mut sink = |transaction: &RecoveredTransaction| -> Result<()> {
            delivered.push(transaction.clone());
            Ok(())
        };
        let recovery = JournalRecovery::with_sessions(&mut sessions).with_sink(&mut sink);
        recover_effective_default_journal(&config_path, recovery).expect("the later pass finishes");
    }
    assert_eq!(delivered.len(), 1, "exactly one terminal result");
    assert!(matches!(
        delivered[0].outcome,
        RecoveredOutcome::Restored { .. }
    ));
    assert!(journal_and_backup_are_gone(&config_path));
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&prior));
}

/// A genuine OS failure *after* the durable commit boundary: compensation
/// cannot write, so nothing may be claimed and the journal survives.
#[cfg(unix)]
#[test]
fn a_real_compensation_failure_after_the_boundary_fails_closed() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b"), ("old", "a")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    // Cross the boundary and leave the config already replaced.
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterConfigReplaced));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        None,
    );
    set_crash_inject(None);
    // Break the *lower* layer's digest so forward convergence is refused and
    // compensation must write — then make the directory read-only so that
    // write is a real `EACCES`.
    std::fs::write(
        &config_path,
        br#"{"active_model":{"provider":"third","model":"party"}}"#,
    )
    .unwrap();
    let original = std::fs::metadata(&user).unwrap().permissions();
    let mut readonly = original.clone();
    readonly.set_mode(original.mode() & !0o222);
    std::fs::set_permissions(&user, readonly).unwrap();

    let error = recover_effective_default_journal(&config_path, JournalRecovery::read_only())
        .expect_err("a real OS failure during compensation must fail closed");
    std::fs::set_permissions(&user, original).unwrap();

    assert!(
        format!("{error:#}").contains("refusing to overwrite")
            || format!("{error:#}").contains("does not match"),
        "{error:#}"
    );
    assert!(
        journal_path_for_config(&config_path).exists(),
        "an unconverged transaction keeps its journal"
    );
}

/// Two spellings of one config file must resolve to one journal *key* — and
/// the record's `target_path_digest` must use the same canonical form, or the
/// journal is found under both spellings yet judged out of context under both.
#[test]
fn one_config_file_has_one_journal_key_across_path_spellings() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    let target = selection("new", "b");
    write_layer(&user, Some(&prior), &[("new", "b"), ("old", "a")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(user.join("nested")).unwrap();

    let direct = user.join("config.json");
    let round_about = user.join("nested").join("..").join("config.json");
    // Compare file *names*: the paths differ component-wise by construction,
    // and the whole point is that they hash to one key.
    let key = |path: &Path| {
        journal_path_for_config(path)
            .file_name()
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        key(&direct),
        key(&round_about),
        "a `..` segment must not mint a second journal key"
    );
    let backup_key = |path: &Path| backup_path_for_config(path).file_name().unwrap().to_owned();
    assert_eq!(backup_key(&direct), backup_key(&round_about));

    #[cfg(unix)]
    let linked = {
        let link = tmp.path().join("linked-layer");
        std::os::unix::fs::symlink(&user, &link).unwrap();
        assert_eq!(
            key(&direct),
            key(&link.join("config.json")),
            "a symlinked ancestor must not mint a second journal key"
        );
        link.join("config.json")
    };

    // Write the journal under one spelling, at the phase recovery converges
    // forward from…
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterReloadVerified));
    let _ = mutate_effective_default(
        &cwd,
        Some(&target),
        ActiveModelWriteMode::Replace,
        None,
        None,
        Some(TransactionCorrelation::DefaultUpdate {
            default_update_id: Uuid::from_u128(41),
            session_id: Uuid::from_u128(42),
            authority: None,
        }),
    );
    set_crash_inject(None);
    assert!(journal_path_for_config(&direct).exists());

    // …and it must be in context — hence maskable — under the others.
    let masked_round_about = masked_layer_bytes(std::slice::from_ref(&round_about));
    assert_eq!(
        masked_round_about.len(),
        1,
        "the journal must be recognised as in-context under a `..` spelling"
    );
    #[cfg(unix)]
    {
        // The key matches (asserted above), but the layer sits behind a
        // symlinked ancestor, which the nofollow policy refuses to read. That
        // is the correct outcome: unreadable, therefore unmaskable, therefore
        // fail-closed — never a live merge.
        let (masked_link, unmaskable_link) = masked_layers(std::slice::from_ref(&linked));
        assert!(masked_link.is_empty());
        assert_eq!(
            unmaskable_link.len(),
            1,
            "a symlinked ancestor must fail closed rather than be read through"
        );
    }

    // And a recovery pass addressed by the other spelling converges it.
    reset_recovery_backoff_for_tests();
    let mut delivered: Vec<RecoveredTransaction> = Vec::new();
    {
        let mut sink = |transaction: &RecoveredTransaction| -> Result<()> {
            delivered.push(transaction.clone());
            Ok(())
        };
        let mut sessions = FakeSessions::default();
        let recovery = JournalRecovery::with_sessions(&mut sessions).with_sink(&mut sink);
        recover_effective_default_journal(&round_about, recovery)
            .expect("a journal is recoverable under any spelling of its config file");
    }
    assert_eq!(delivered.len(), 1);
    assert!(journal_and_backup_are_gone(&direct));
    assert_eq!(fresh_session_resolution(&cwd).as_ref(), Some(&target));
}

/// A mutation must never converge a *correlated* journal it did not originate:
/// finishing it would delete another operation's terminal event and leave that
/// client's pending state open forever. The mutation fails closed instead, and
/// the journal survives for the daemon pass that can deliver the event.
#[test]
fn a_second_mutation_never_swallows_a_pending_correlated_transaction() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(
        &user,
        Some(&prior),
        &[("first", "one"), ("second", "two"), ("old", "a")],
    );
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");

    let waiting = TransactionCorrelation::DefaultUpdate {
        default_update_id: Uuid::from_u128(51),
        session_id: Uuid::from_u128(52),
        authority: None,
    };
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterConfigReplaced));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("first", "one")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        Some(waiting),
    );
    set_crash_inject(None);
    let journal_before = std::fs::read_to_string(journal_path_for_config(&config_path)).unwrap();

    // A completely unrelated second mutation.
    let error = mutate_effective_default(
        &cwd,
        Some(&selection("second", "two")),
        ActiveModelWriteMode::Replace,
        None,
        None,
        Some(TransactionCorrelation::DefaultUpdate {
            default_update_id: Uuid::from_u128(53),
            session_id: Uuid::from_u128(52),
            authority: None,
        }),
    )
    .expect_err("a pending correlated transaction blocks a new mutation");

    assert_eq!(error.diagnostic_code, "effective_default_journal_conflict");
    assert_eq!(
        std::fs::read_to_string(journal_path_for_config(&config_path)).unwrap(),
        journal_before,
        "the waiting operation's journal must be byte-identical"
    );
    assert!(
        backup_path_for_config(&config_path).exists(),
        "its rollback snapshot must survive too"
    );
    assert_eq!(
        fresh_session_resolution(&cwd).as_ref(),
        Some(&prior),
        "the layer stays masked while the correlated transaction is pending"
    );

    // The daemon pass still delivers the original terminal event, exactly once.
    reset_recovery_backoff_for_tests();
    let mut delivered: Vec<RecoveredTransaction> = Vec::new();
    {
        let mut sink = |transaction: &RecoveredTransaction| -> Result<()> {
            delivered.push(transaction.clone());
            Ok(())
        };
        let mut sessions = FakeSessions::default();
        let recovery = JournalRecovery::with_sessions(&mut sessions).with_sink(&mut sink);
        recover_effective_default_journal(&config_path, recovery).expect("daemon pass converges");
    }
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].correlation, waiting);
}

/// A layer whose journal cannot be masked (unreadable record, or a missing
/// rollback snapshot) must never be merged live: its bytes may already hold
/// the target of an unfinished transaction.
#[test]
fn an_unmaskable_pending_layer_fails_the_load_closed() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    write_layer(
        &user,
        Some(&selection("old", "a")),
        &[("new", "b"), ("old", "a")],
    );
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");
    let paths = config_file_paths_for_load(&cwd);

    // Case 1: an unreadable journal.
    std::fs::write(journal_path_for_config(&config_path), b"{ not a record").unwrap();
    let (_, unmaskable) = masked_layers(&paths);
    assert_eq!(unmaskable.len(), 1, "an unreadable journal is unmaskable");
    let error = ConfigDoc::try_load_effective_from_paths(&paths)
        .expect_err("an unmaskable pending layer must fail the load closed");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("cannot be masked") || rendered.contains("parsing journal"),
        "{rendered}"
    );
    // The infallible entry point degrades rather than exposing live bytes.
    assert_eq!(
        ConfigDoc::load_effective_from_paths(&paths).active_model,
        None,
        "a degraded load must not surface the pending layer's default"
    );

    // Case 2: a well-formed session-bearing journal whose snapshot is gone.
    reset_recovery_backoff_for_tests();
    let _ = std::fs::remove_file(journal_path_for_config(&config_path));
    let mut sessions = FakeSessions {
        revision: 1,
        selection: Some(selection("old", "a")),
        ..Default::default()
    };
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterConfigReplaced));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, selection("old", "a"))),
        None,
        None,
    );
    set_crash_inject(None);
    std::fs::remove_file(backup_path_for_config(&config_path)).unwrap();

    let (_, unmaskable) = masked_layers(&paths);
    assert_eq!(unmaskable.len(), 1, "a missing snapshot is unmaskable");
    assert!(ConfigDoc::try_load_effective_from_paths(&paths).is_err());
    assert_eq!(
        ConfigDoc::load_effective_from_paths(&paths).active_model,
        None,
        "the half-committed target must not be exposed by the degraded path"
    );
}

/// A CAS that **committed and then reported an error** is the ambiguous case.
/// Skipping compensation there would strand the session on the target while
/// the config was rolled back. The recorded-revision guard resolves it: it
/// sees `expected + 1`, knows this transaction wrote it, and reverts.
#[test]
fn an_errored_cas_that_actually_committed_is_still_compensated() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    let prior = selection("old", "a");
    write_layer(&user, Some(&prior), &[("new", "b"), ("old", "a")]);
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");
    let before = std::fs::read_to_string(&config_path).unwrap();

    let mut sessions = FakeSessions {
        revision: 5,
        selection: Some(prior.clone()),
        commit_then_error: true,
        ..Default::default()
    };
    let error = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, prior.clone())),
        None,
        None,
    )
    .expect_err("an ambiguous CAS failure cannot leave the default applied");

    assert!(
        error.restored_after_boundary,
        "compensation must converge to the recorded prior values: {error:?}"
    );
    assert_eq!(
        sessions.revision, 7,
        "the committed CAS (6) was reverted by a guarded compensating CAS (7)"
    );
    assert_eq!(
        sessions.selection.as_ref(),
        Some(&prior),
        "the session must not be stranded on the target after a rollback"
    );
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), before);
    assert!(journal_and_backup_are_gone(&config_path));
}

#[test]
fn modes_session_setup_retained_selected_leaf_projects_exact_effective_default_journal_states() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.json");
    let canonical = canonical_config_path(&config_path);
    let project_root = tmp.path().to_string_lossy().to_string();
    let prior = b"{\"active_model\":{\"provider\":\"old\",\"model\":\"a\"}}\n".to_vec();
    let requested = selection("new", "b");
    let committed = replacement_bytes(&prior, Some(&requested)).unwrap();

    let record_for = |phase: JournalPhase, session: JournalSession| JournalRecord {
        transaction_id: Uuid::new_v4(),
        project_root: project_root.clone(),
        trust_mode: Some(WorkspaceTrustMode::Trust.as_str().to_string()),
        scope: EffectiveDefaultScope::Project,
        target_path_digest: path_digest(&canonical),
        old_config_digest: bytes_digest(&prior),
        new_config_digest: bytes_digest(&committed),
        requested: Some(requested.clone()),
        expected_effective: Some(requested.clone()),
        session,
        correlation: None,
        receipt_proof: None,
        phase,
    };

    let serialize = |record: &JournalRecord| serde_json::to_vec(record).unwrap();

    // A config-only prepared transaction exposes the recoverable prior view,
    // even if the replacement had reached the config file before a crash.
    let prepared = serialize(&record_for(JournalPhase::Prepared, JournalSession::None));
    assert_eq!(
        project_retained_effective_default_bytes(
            &canonical,
            Some(committed.clone()),
            Some(&prepared),
            Some(&prior),
        )
        .unwrap(),
        Some(prior.clone())
    );

    // The capability projection preserves every config-only recovery branch:
    // an already-prior layer needs no backup, whereas a replacement in flight
    // needs the validated backup to project the compensating view.
    for phase in [JournalPhase::Prepared, JournalPhase::Compensating] {
        let record = serialize(&record_for(phase, JournalSession::None));
        assert_eq!(
            project_retained_effective_default_bytes(
                &canonical,
                Some(prior.clone()),
                Some(&record),
                None,
            )
            .unwrap(),
            Some(prior.clone()),
            "{phase:?} with prior bytes is already safely recovered"
        );
        assert!(
            project_retained_effective_default_bytes(
                &canonical,
                Some(committed.clone()),
                Some(&record),
                None,
            )
            .is_err(),
            "{phase:?} with replacement bytes requires its rollback snapshot"
        );
    }

    // A committed config-only record deterministically exposes the forward
    // bytes even before the normal recovery pass writes/removes artifacts.
    let committed_record = serialize(&record_for(JournalPhase::Committed, JournalSession::None));
    assert_eq!(
        project_retained_effective_default_bytes(
            &canonical,
            Some(prior.clone()),
            Some(&committed_record),
            Some(&prior),
        )
        .unwrap(),
        Some(committed.clone())
    );
    assert_eq!(
        project_retained_effective_default_bytes(
            &canonical,
            Some(committed.clone()),
            Some(&committed_record),
            None,
        )
        .unwrap(),
        Some(committed.clone()),
        "a durably committed layer needs no backup to project forward"
    );

    // A session-bound transaction is always masked back to the validated
    // prior snapshot until a daemon session-authority recovery owns it.
    let session_record = serialize(&record_for(
        JournalPhase::SessionCommitted,
        JournalSession::Session {
            session_id: Uuid::new_v4(),
            prior: selection("old", "a"),
            target: requested.clone(),
            expected_revision: 7,
        },
    ));
    assert_eq!(
        project_retained_effective_default_bytes(
            &canonical,
            Some(committed.clone()),
            Some(&session_record),
            Some(&prior),
        )
        .unwrap(),
        Some(prior.clone())
    );

    // A stale record for a different selected leaf is not this layer's
    // transaction and cannot block it merely by sharing a directory.
    let foreign_path = tmp.path().join("other.json");
    let foreign_canonical = canonical_config_path(&foreign_path);
    let mut foreign: JournalRecord = serde_json::from_slice(&prepared).unwrap();
    foreign.target_path_digest = path_digest(&foreign_canonical);
    let foreign = serialize(&foreign);
    assert_eq!(
        project_retained_effective_default_bytes(
            &canonical,
            Some(committed.clone()),
            Some(&foreign),
            Some(&prior),
        )
        .unwrap(),
        Some(committed)
    );
}

/// The uncounted masked read used by pre-attach bootstrap and export obeys the
/// same fail-closed rule as the counted one: an unmaskable pending layer is
/// served as empty, never as its live (possibly half-committed) bytes.
#[test]
fn the_uncounted_masked_read_degrades_an_unmaskable_pending_layer() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    crate::config::trust::clear_runtime_policy_for_tests();
    reset_recovery_backoff_for_tests();
    let user = user_dir(tmp.path());
    write_layer(
        &user,
        Some(&selection("old", "a")),
        &[("new", "b"), ("old", "a")],
    );
    let cwd = tmp.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_path = user.join("config.json");
    let paths = config_file_paths_for_load(&cwd);

    // Every masked read must leave the resolution-generation counter alone.
    let masked_read = |paths: &[PathBuf]| {
        let before = crate::config::providers::load_effective_call_count();
        let resolved = ConfigDoc::providers_from_paths_masked(paths).active_model;
        assert_eq!(
            crate::config::providers::load_effective_call_count(),
            before,
            "the bootstrap/export read must stay an uncounted, non-recovering resolution"
        );
        resolved
    };

    // Baseline: no journal, so this is an ordinary merge.
    assert_eq!(masked_read(&paths), Some(selection("old", "a")));

    // Case 1: an unreadable journal beside a layer whose live bytes already
    // hold the half-committed target.
    std::fs::write(
        &config_path,
        br#"{"active_model":{"provider":"new","model":"b"}}"#,
    )
    .unwrap();
    std::fs::write(journal_path_for_config(&config_path), b"{ not a record").unwrap();
    assert_eq!(
        masked_read(&paths),
        None,
        "an unmaskable pending layer must be degraded, not merged live"
    );

    // Case 2: a well-formed session-bearing journal whose snapshot is gone.
    reset_recovery_backoff_for_tests();
    std::fs::remove_file(journal_path_for_config(&config_path)).unwrap();
    write_layer(
        &user,
        Some(&selection("old", "a")),
        &[("new", "b"), ("old", "a")],
    );
    let mut sessions = FakeSessions {
        revision: 1,
        selection: Some(selection("old", "a")),
        ..Default::default()
    };
    set_crash_inject(Some(EffectiveDefaultCrashPoint::AfterConfigReplaced));
    let _ = mutate_effective_default(
        &cwd,
        Some(&selection("new", "b")),
        ActiveModelWriteMode::Replace,
        Some(participant(&mut sessions, selection("old", "a"))),
        None,
        None,
    );
    set_crash_inject(None);
    std::fs::remove_file(backup_path_for_config(&config_path)).unwrap();
    assert_eq!(
        masked_read(&paths),
        None,
        "a missing rollback snapshot is unmaskable and must be degraded too"
    );
}
