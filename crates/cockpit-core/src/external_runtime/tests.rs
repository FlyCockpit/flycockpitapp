//! Acceptance tests for the external-runtime dependency health foundation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::*;
use crate::capabilities::{
    BinaryRequirement, BinaryRequirementKind, CapabilityProbeCache, ExecutionTarget,
    evaluate_tool_requirements,
};

fn ctx(platform: HostPlatform) -> EvaluationContext {
    EvaluationContext::new(platform)
}

#[test]
fn dependency_headless_schema_and_shared_reason_are_stable() {
    let descriptor = ExternalRuntimeDescriptor::builder("runtime.test")
        .owner("test", "selected")
        .probe_policy(ProbePolicy::configured_command("test-runtime", None))
        .importance(DependencyImportance::RequiredWhenFeatureSelected)
        .remedy(RemedyKind::config_guidance(
            "configure an absolute executable path",
        ))
        .build()
        .unwrap();
    let unknown = project_dependencies(None, std::slice::from_ref(&descriptor));
    assert_eq!(unknown.schema_version, DEPENDENCY_HEADLESS_SCHEMA_VERSION);
    assert_eq!(unknown.rows[0].state, DependencyViewState::Unknown);
    let json = serde_json::to_string(&unknown).unwrap();
    assert!(!json.contains("PATH="));
    assert!(!json.contains("environment"));
    assert_eq!(
        unknown.render_lines()[0],
        format!("runtime.test: {}", unknown.rows[0].reason)
    );
    assert_eq!(
        unknown.contextual_line("runtime.test").as_deref(),
        Some(unknown.render_lines()[0].as_str()),
        "Settings/doctor/context/headless must use byte-identical row text"
    );
}

#[test]
fn dependency_headless_fixture_matches_rust_schema() {
    let fixture: DependencyProjection = serde_json::from_str(include_str!(
        "../../../../packages/cockpit-protocol/fixtures/dependency-health-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture.schema_version, DEPENDENCY_HEADLESS_SCHEMA_VERSION);
    assert_eq!(fixture.rows[0].id, "git");
    assert_eq!(fixture.rows[0].state, DependencyViewState::Available);
}

#[test]
fn dependency_settings_first_paint_and_refresh_generation() {
    let descriptor = ExternalRuntimeDescriptor::builder("runtime.test")
        .owner("test", "optional")
        .probe_policy(ProbePolicy::configured_command("runtime", None))
        .build()
        .unwrap();
    let mut page = DependenciesPageState::first_paint(None, std::slice::from_ref(&descriptor));
    assert_eq!(page.displayed.rows[0].state, DependencyViewState::Unknown);
    let older = page.begin_refresh();
    let newer = page.begin_refresh();
    let mut completed = ExternalRuntimeSnapshot::empty(newer, HostPlatform::GenericLinux);
    completed.entries.insert(
        "runtime.test".into(),
        HealthEntry {
            id: "runtime.test".into(),
            state: HealthState::Available {
                resolved_path: None,
                version_evidence: Some("1.2.3".into()),
            },
            importance: DependencyImportance::OptionalIntegration,
            target: ExecutionTarget::Host,
            remedy: None,
            platform: HostPlatform::GenericLinux,
        },
    );
    let projected = project_dependencies(Some(&completed), std::slice::from_ref(&descriptor));
    assert!(!page.apply_success(older, projected.clone()));
    assert!(page.apply_success(newer, projected));
    let generation = page.begin_refresh();
    assert!(page.apply_failure(generation, "probe construction failed"));
    assert_eq!(page.displayed.rows[0].state, DependencyViewState::Available);
    page.close();
    assert!(!page.apply_success(generation, page.displayed.clone()));
}

#[test]
fn dependency_deadline_and_startup_policy_are_deterministic() {
    let mut snapshot = ExternalRuntimeSnapshot::empty(1, HostPlatform::GenericLinux);
    snapshot.entries.insert(
        "required.pending".into(),
        HealthEntry {
            id: "required.pending".into(),
            state: HealthState::Pending,
            importance: DependencyImportance::RequiredForDefaultSafety,
            target: ExecutionTarget::Host,
            remedy: None,
            platform: HostPlatform::GenericLinux,
        },
    );
    snapshot.entries.insert(
        "optional.missing".into(),
        HealthEntry {
            id: "optional.missing".into(),
            state: HealthState::Missing,
            importance: DependencyImportance::OptionalAccelerator,
            target: ExecutionTarget::Host,
            remedy: None,
            platform: HostPlatform::GenericLinux,
        },
    );
    let frozen = freeze_pending_as_timed_out(&snapshot);
    let projection = project_dependencies(Some(&frozen), &[]);
    assert_eq!(projection.rows[0].state, DependencyViewState::TimedOut);
    assert_eq!(projection.rows[1].state, DependencyViewState::Missing);
    let policy = startup_dependency_policy(&projection);
    assert!(!policy.allowed);
    assert_eq!(
        policy.summary.as_deref(),
        Some("required dependencies unavailable: required.pending: timed out")
    );
}

fn ctx_features(platform: HostPlatform, features: &[&str]) -> EvaluationContext {
    EvaluationContext::new(platform).with_features(features.iter().copied())
}

fn trusted_rg() -> ExternalRuntimeDescriptor {
    ExternalRuntimeDescriptor::builder("tool.rg")
        .owner("cockpit-core", "search")
        .candidates(["rg", "ripgrep"])
        .importance(DependencyImportance::OptionalAccelerator)
        .probe_policy(ProbePolicy::trusted_catalog(
            ["--version"],
            VersionParser::FirstSemverToken,
            None,
        ))
        .remedy(common_platform_remedy("rg"))
        .build()
        .unwrap()
}

fn configured(cmd: &str, path: Option<&str>) -> ExternalRuntimeDescriptor {
    ExternalRuntimeDescriptor::builder(format!("configured.{cmd}"))
        .owner("user", "harness")
        .importance(DependencyImportance::RequiredWhenFeatureSelected)
        .probe_policy(ProbePolicy::configured_command(
            cmd,
            path.map(PathBuf::from),
        ))
        .remedy(configured_command_remedy(cmd, path))
        .build()
        .unwrap()
}

#[test]
fn external_dependency_descriptor_schema() {
    // Complete closed schema document round-trips through serde JSON.
    let mut doc = ExternalRuntimeSchemaDocument::empty();
    assert_eq!(
        doc.schema_version,
        ExternalRuntimeSchemaDocument::CURRENT_VERSION
    );

    let group = RequirementGroup::all_of([
        RequirementGroup::leaf("a"),
        RequirementGroup::any_of([RequirementGroup::leaf("b"), RequirementGroup::leaf("c")]),
    ]);

    let mut recipes = BTreeMap::new();
    recipes.insert(HostPlatform::MacOs, "brew install demo".into());
    recipes.insert(
        HostPlatform::DebianUbuntu,
        "sudo apt-get install demo".into(),
    );
    recipes.insert(HostPlatform::Windows, "winget install demo".into());
    recipes.insert(HostPlatform::FedoraRhel, "sudo dnf install demo".into());
    recipes.insert(HostPlatform::Arch, "sudo pacman -S demo".into());
    recipes.insert(HostPlatform::GenericLinux, "install demo".into());
    recipes.insert(HostPlatform::OtherUnix, "install demo".into());
    recipes.insert(HostPlatform::Unsupported, "install demo".into());

    let trusted = ExternalRuntimeDescriptor::builder("catalog.demo")
        .owner("cockpit-core", "demo")
        .candidates(["demo"])
        .applicability(Applicability::Platforms(vec![
            HostPlatform::MacOs,
            HostPlatform::DebianUbuntu,
        ]))
        .importance(DependencyImportance::RequiredForDefaultSafety)
        .target(ExecutionTarget::Host)
        .probe_policy(ProbePolicy::trusted_catalog(
            ["--version"],
            VersionParser::RegexCapture {
                pattern: r"(\d+\.\d+\.\d+)".into(),
                group: 1,
            },
            Some(vec!["--help".into()]),
        ))
        .compatibility(CompatibilityRule::MinVersion {
            version: "1.0.0".into(),
        })
        .remedy(RemedyKind::platform_recipes("Install demo.", recipes))
        .group(group.clone())
        .build()
        .unwrap();

    let cfg = configured("my-agent", Some("/opt/my-agent"));
    doc.descriptors.push(trusted);
    doc.descriptors.push(cfg);
    doc.groups.push(group);

    // Enumerate every closed schema surface in the document.
    let json = serde_json::to_string_pretty(&doc).expect("serialize schema");
    let back: ExternalRuntimeSchemaDocument =
        serde_json::from_str(&json).expect("deserialize schema");
    assert_eq!(back.schema_version, doc.schema_version);
    assert_eq!(back.descriptors.len(), doc.descriptors.len());
    assert_eq!(back.groups, doc.groups);
    assert_eq!(back.descriptors[0].id, doc.descriptors[0].id);
    // Trusted catalog rehydrated from JSON is intentionally non-executable.
    assert!(
        !back.descriptors[0]
            .probe_policy
            .as_trusted_catalog()
            .unwrap()
            .is_executable()
    );
    assert!(
        doc.descriptors[0]
            .probe_policy
            .as_trusted_catalog()
            .unwrap()
            .is_executable()
    );

    // Importance closed set
    for imp in [
        DependencyImportance::RequiredForDefaultSafety,
        DependencyImportance::RequiredWhenFeatureSelected,
        DependencyImportance::OptionalIntegration,
        DependencyImportance::OptionalAccelerator,
    ] {
        let s = serde_json::to_string(&imp).unwrap();
        let r: DependencyImportance = serde_json::from_str(&s).unwrap();
        assert_eq!(r, imp);
    }

    // Health states closed set
    for state in [
        HealthState::Pending,
        HealthState::Available {
            resolved_path: Some(PathBuf::from("/bin/x")),
            version_evidence: Some("1.0".into()),
        },
        HealthState::Missing,
        HealthState::Incompatible {
            detail: "old".into(),
        },
        HealthState::TimedOut,
        HealthState::Failed {
            cause: HealthCause::NotSpawnable,
        },
        HealthState::Unknown {
            cause: HealthCause::Cancellation,
        },
        HealthState::NotApplicable,
    ] {
        let s = serde_json::to_string(&state).unwrap();
        let r: HealthState = serde_json::from_str(&s).unwrap();
        assert_eq!(r, state);
        if !matches!(r, HealthState::Available { .. }) {
            assert!(!r.is_healthy(), "Unknown never means healthy: {r:?}");
        }
    }

    // Targets
    for t in [ExecutionTarget::Host, ExecutionTarget::Container] {
        let s = serde_json::to_string(&t).unwrap();
        let r: ExecutionTarget = serde_json::from_str(&s).unwrap();
        assert_eq!(r, t);
    }
}

#[test]
fn external_dependency_registration_is_extensible() {
    let registry = ExternalRuntimeRegistry::new();
    // Later feature registrations use stable string IDs — no closed enum edit.
    let ids = [
        "git.repository",
        "harness.claude",
        "lsp.rust-analyzer",
        "mcp.stdio.custom",
        "media.ffmpeg",
        "container.docker",
    ];
    for id in ids {
        let desc = ExternalRuntimeDescriptor::builder(id)
            .owner("feature", id)
            .candidates([id.rsplit('.').next().unwrap_or(id)])
            .probe_policy(ProbePolicy::trusted_catalog(
                ["--version"],
                VersionParser::FirstLine,
                None,
            ))
            .remedy(RemedyKind::prose(format!("Install {id}")))
            .build()
            .unwrap();
        registry.register(desc).unwrap();
    }
    assert_eq!(registry.len(), ids.len());
    for id in ids {
        assert!(registry.get(id).is_some(), "missing {id}");
    }
    // Duplicate rejected
    let err = registry
        .register(
            ExternalRuntimeDescriptor::builder("git.repository")
                .candidates(["git"])
                .probe_policy(ProbePolicy::trusted_catalog(
                    ["--version"],
                    VersionParser::FirstLine,
                    None,
                ))
                .build()
                .unwrap(),
        )
        .unwrap_err();
    assert!(matches!(err, RegistryError::DuplicateId(_)));

    // Configured command registration without touching a closed ID enum
    registry
        .register(configured("user-binary-xyz", None))
        .unwrap();
    assert_eq!(registry.len(), ids.len() + 1);
}

#[test]
fn external_dependency_model_all_any_health() {
    let executor = RecordingProbeExecutor::new()
        .with_resolve("a", "/usr/bin/a")
        .with_resolve("b", "/usr/bin/b");
    // c missing

    let a = ExternalRuntimeDescriptor::builder("a")
        .candidates(["a"])
        .importance(DependencyImportance::RequiredForDefaultSafety)
        .target(ExecutionTarget::Host)
        .applicability(Applicability::Always)
        .probe_policy(ProbePolicy::trusted_catalog(
            ["--version"],
            VersionParser::FirstLine,
            None,
        ))
        .build()
        .unwrap();
    // Container-target: candidate `jq` is in the image guarantee list; host
    // resolve for bare name `b` must not drive container Available.
    let b = ExternalRuntimeDescriptor::builder("b")
        .owner("cockpit-core", "feature-b")
        .candidates(["jq"])
        .importance(DependencyImportance::RequiredWhenFeatureSelected)
        .target(ExecutionTarget::Container)
        .applicability(Applicability::WhenFeatureSelected)
        .probe_policy(ProbePolicy::trusted_catalog(
            ["--version"],
            VersionParser::FirstLine,
            None,
        ))
        .build()
        .unwrap();
    let b_host_only = ExternalRuntimeDescriptor::builder("b-host-bleed")
        .candidates(["a"]) // present on host via executor, NOT in container image
        .target(ExecutionTarget::Container)
        .probe_policy(ProbePolicy::trusted_catalog(
            ["--version"],
            VersionParser::FirstLine,
            None,
        ))
        .build()
        .unwrap();
    let c = ExternalRuntimeDescriptor::builder("c")
        .candidates(["c"])
        .importance(DependencyImportance::OptionalIntegration)
        .target(ExecutionTarget::Host)
        .applicability(Applicability::Platforms(vec![HostPlatform::MacOs]))
        .probe_policy(ProbePolicy::trusted_catalog(
            ["--version"],
            VersionParser::FirstLine,
            None,
        ))
        .build()
        .unwrap();
    let d = ExternalRuntimeDescriptor::builder("d")
        .candidates(["d"])
        .importance(DependencyImportance::OptionalAccelerator)
        .probe_policy(ProbePolicy::trusted_catalog(
            ["--version"],
            VersionParser::FirstLine,
            None,
        ))
        .build()
        .unwrap();

    // Force timeout / fail / incompatible via handler on specific programs.
    executor.set_handler(|program, _args| {
        let name = program.file_name().and_then(|n| n.to_str()).unwrap_or("");
        match name {
            "a" | "b" => ProbeCommandResult {
                exit_code: Some(0),
                stdout: b"2.0.0\n".to_vec(),
                stderr: Vec::new(),
                timed_out: false,
                cancelled: false,
                spawn_error: None,
            },
            _ => ProbeCommandResult {
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                timed_out: false,
                cancelled: false,
                spawn_error: Some(SpawnFailureKind::Other),
            },
        }
    });

    let cancel = CancelToken::new();
    let snap = refresh_snapshot(
        1,
        &[
            a.clone(),
            b.clone(),
            b_host_only.clone(),
            c.clone(),
            d.clone(),
        ],
        &executor,
        None,
        Path::new("/"),
        &ctx_features(HostPlatform::DebianUbuntu, &["feature-b"]),
        ProbeDeadlines::default(),
        &cancel,
    );

    assert!(matches!(
        snap.get("a").unwrap().state,
        HealthState::Available { .. }
    ));
    assert_eq!(
        snap.get("a").unwrap().importance,
        DependencyImportance::RequiredForDefaultSafety
    );
    assert_eq!(snap.get("b").unwrap().target, ExecutionTarget::Container);
    // Container image provides jq — Available without host spawn.
    assert!(matches!(
        snap.get("b").unwrap().state,
        HealthState::Available { .. }
    ));
    // Host-present binary that is not container-provided must be Missing.
    assert!(matches!(
        snap.get("b-host-bleed").unwrap().state,
        HealthState::Missing
    ));
    // No host spawn for pure container-target rows.
    let runs_for_container = executor
        .run_log
        .lock()
        .unwrap()
        .iter()
        .filter(|r| {
            r.program
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "a" || n == "jq")
        })
        .count();
    // `a` is host-target and may run; jq container must not.
    assert!(
        executor.run_log.lock().unwrap().iter().all(|r| r
            .program
            .file_name()
            .and_then(|n| n.to_str())
            != Some("jq"))
    );
    let _ = runs_for_container;
    // Feature not selected → NotApplicable (not Missing).
    let snap_no_feature = refresh_snapshot(
        2,
        std::slice::from_ref(&b),
        &executor,
        None,
        Path::new("/"),
        &ctx(HostPlatform::DebianUbuntu),
        ProbeDeadlines::default(),
        &cancel,
    );
    assert!(matches!(
        snap_no_feature.get("b").unwrap().state,
        HealthState::NotApplicable
    ));

    // WhenFeatureSelectedOnPlatforms requires both feature and platform.
    let fplat = ExternalRuntimeDescriptor::builder("fplat")
        .owner("cockpit-core", "feat-plat")
        .candidates(["a"])
        .applicability(Applicability::WhenFeatureSelectedOnPlatforms {
            platforms: vec![HostPlatform::MacOs],
        })
        .probe_policy(ProbePolicy::trusted_catalog(
            ["--version"],
            VersionParser::FirstLine,
            None,
        ))
        .build()
        .unwrap();
    let snap_wrong_plat = refresh_snapshot(
        3,
        std::slice::from_ref(&fplat),
        &executor,
        None,
        Path::new("/"),
        &ctx_features(HostPlatform::DebianUbuntu, &["feat-plat"]),
        ProbeDeadlines::default(),
        &cancel,
    );
    assert!(matches!(
        snap_wrong_plat.get("fplat").unwrap().state,
        HealthState::NotApplicable
    ));
    let snap_right = refresh_snapshot(
        4,
        &[fplat],
        &executor,
        None,
        Path::new("/"),
        &ctx_features(HostPlatform::MacOs, &["feat-plat"]),
        ProbeDeadlines::default(),
        &cancel,
    );
    assert!(matches!(
        snap_right.get("fplat").unwrap().state,
        HealthState::Available { .. }
    ));
    // c not applicable on Debian
    assert!(matches!(
        snap.get("c").unwrap().state,
        HealthState::NotApplicable
    ));
    assert!(matches!(snap.get("d").unwrap().state, HealthState::Missing));

    // Nested all_of / any_of
    let group = RequirementGroup::all_of([
        RequirementGroup::leaf("a"),
        RequirementGroup::any_of([RequirementGroup::leaf("b"), RequirementGroup::leaf("d")]),
    ]);
    assert_eq!(
        evaluate_requirement_group(&group, &snap),
        GroupHealth::Available
    );

    let missing_group =
        RequirementGroup::all_of([RequirementGroup::leaf("a"), RequirementGroup::leaf("d")]);
    assert_eq!(
        evaluate_requirement_group(&missing_group, &snap),
        GroupHealth::Missing
    );

    // Pending leaf (no entry) → Unknown
    let unknown_group = RequirementGroup::leaf("never-registered");
    assert_eq!(
        evaluate_requirement_group(&unknown_group, &snap),
        GroupHealth::Unknown
    );

    // TimedOut / Failed / Incompatible unit paths via evaluate_descriptor
    let mut slow = trusted_rg();
    slow.id = ExternalRuntimeId::new("slow");
    let exec2 = RecordingProbeExecutor::new().with_resolve("rg", "/usr/bin/rg");
    exec2.set_handler(|_, _| ProbeCommandResult {
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        timed_out: true,
        cancelled: false,
        spawn_error: None,
    });
    let timed = evaluate_descriptor(
        &slow,
        &exec2,
        None,
        Path::new("/"),
        &ctx(HostPlatform::GenericLinux),
        ProbeDeadlines::default(),
        &CancelToken::new(),
    );
    assert!(matches!(timed.state, HealthState::TimedOut));

    let mut bad_ver = trusted_rg();
    bad_ver.id = ExternalRuntimeId::new("old");
    bad_ver.compatibility = Some(CompatibilityRule::MinVersion {
        version: "99.0.0".into(),
    });
    let exec3 = RecordingProbeExecutor::new().with_resolve("rg", "/usr/bin/rg");
    exec3.set_handler(|_, _| ProbeCommandResult {
        exit_code: Some(0),
        stdout: b"rg 1.0.0\n".to_vec(),
        stderr: Vec::new(),
        timed_out: false,
        cancelled: false,
        spawn_error: None,
    });
    let incompat = evaluate_descriptor(
        &bad_ver,
        &exec3,
        None,
        Path::new("/"),
        &ctx(HostPlatform::GenericLinux),
        ProbeDeadlines::default(),
        &CancelToken::new(),
    );
    assert!(matches!(incompat.state, HealthState::Incompatible { .. }));

    // Failed spawn
    let exec4 = RecordingProbeExecutor::new().with_resolve("rg", "/usr/bin/rg");
    exec4.set_handler(|_, _| ProbeCommandResult {
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        timed_out: false,
        cancelled: false,
        spawn_error: Some(SpawnFailureKind::PermissionDenied),
    });
    let failed = evaluate_descriptor(
        &trusted_rg(),
        &exec4,
        None,
        Path::new("/"),
        &ctx(HostPlatform::GenericLinux),
        ProbeDeadlines::default(),
        &CancelToken::new(),
    );
    assert!(matches!(
        failed.state,
        HealthState::Failed {
            cause: HealthCause::SpawnFailed {
                failure: SpawnFailureKind::PermissionDenied
            }
        }
    ));
}

#[test]
fn external_dependency_probe_bounds() {
    // Deadlines are exactly 2s version / 5s functional in defaults.
    let deadlines = ProbeDeadlines::default();
    assert_eq!(deadlines.version, Duration::from_secs(2));
    assert_eq!(deadlines.functional, Duration::from_secs(5));
    assert_eq!(VERSION_PROBE_DEADLINE, Duration::from_secs(2));
    assert_eq!(FUNCTIONAL_PROBE_DEADLINE, Duration::from_secs(5));
    assert_eq!(PROBE_CAPTURE_BUDGET, 8 * 1024);
    assert_eq!(VERSION_EVIDENCE_BUDGET, 512);

    let executor = RecordingProbeExecutor::new().with_resolve("demo", "/usr/bin/demo");
    let mut seen_deadlines = Vec::new();
    executor.set_handler(|_program, args| {
        if args.first().map(String::as_str) == Some("--version") {
            // Secrets/paths first so they survive 512-byte evidence truncation;
            // then pad to exceed the 8 KiB combined capture budget.
            let mut big = b"version 3.1.4 Bearer short-token sk-abcdefghijklmnopqrstuvwxyz012345 token=supersecrettokenvalue path=/home/u/.ssh/id_rsa config=/home/alice/.cfg\x01\x02 /usr/local/lib/secret\n".to_vec();
            big.extend(std::iter::repeat_n(b'x', 10_000));
            ProbeCommandResult {
                exit_code: Some(0),
                stdout: big,
                stderr: b"warn".to_vec(),
                timed_out: false,
                cancelled: false,
                spawn_error: None,
            }
        } else {
            ProbeCommandResult {
                exit_code: Some(0),
                stdout: b"ok".to_vec(),
                stderr: Vec::new(),
                timed_out: false,
                cancelled: false,
                spawn_error: None,
            }
        }
    });

    let desc = ExternalRuntimeDescriptor::builder("demo")
        .candidates(["demo"])
        .probe_policy(ProbePolicy::trusted_catalog(
            ["--version"],
            VersionParser::FirstSemverToken,
            Some(vec!["--functional".into()]),
        ))
        .build()
        .unwrap();

    let entry = evaluate_descriptor(
        &desc,
        &executor,
        None,
        Path::new("/"),
        &ctx(HostPlatform::GenericLinux),
        deadlines,
        &CancelToken::new(),
    );
    let runs = executor.run_log.lock().unwrap().clone();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].deadline, Duration::from_secs(2));
    assert_eq!(runs[1].deadline, Duration::from_secs(5));
    assert_eq!(runs[0].args, vec!["--version".to_string()]);
    assert_eq!(runs[1].args, vec!["--functional".to_string()]);
    seen_deadlines.push(runs[0].deadline);
    seen_deadlines.push(runs[1].deadline);
    assert_eq!(
        seen_deadlines,
        vec![Duration::from_secs(2), Duration::from_secs(5)]
    );

    match &entry.state {
        HealthState::Available {
            version_evidence: Some(ev),
            ..
        } => {
            assert!(ev.len() <= VERSION_EVIDENCE_BUDGET);
            assert!(!ev.contains('\n'));
            assert!(!ev.contains('\x01'));
            assert!(!ev.contains("sk-"));
            assert!(!ev.contains("short-token"));
            assert!(!ev.contains("/home/u"));
            assert!(!ev.contains("supersecrettokenvalue"));
            assert!(!ev.contains("/home/alice"));
            assert!(ev.contains("3.1.4") || ev.contains("demo") || !ev.is_empty());
        }
        other => panic!("expected Available with evidence, got {other:?}"),
    }

    // Combined capture budget on ProbeCommandResult
    let huge = ProbeCommandResult {
        exit_code: Some(0),
        stdout: vec![b'a'; 10_000],
        stderr: vec![b'b'; 10_000],
        timed_out: false,
        cancelled: false,
        spawn_error: None,
    };
    assert!(huge.combined_capped().len() <= PROBE_CAPTURE_BUDGET);

    // Zero deadline → TimedOut without sleep
    let zero = ProbeDeadlines {
        version: Duration::ZERO,
        functional: Duration::ZERO,
    };
    let timed = evaluate_descriptor(
        &desc,
        &executor,
        None,
        Path::new("/"),
        &ctx(HostPlatform::GenericLinux),
        zero,
        &CancelToken::new(),
    );
    assert!(matches!(timed.state, HealthState::TimedOut));

    // Cancellation
    let cancel = CancelToken::new();
    cancel.cancel();
    let cancelled = evaluate_descriptor(
        &desc,
        &executor,
        None,
        Path::new("/"),
        &ctx(HostPlatform::GenericLinux),
        deadlines,
        &cancel,
    );
    assert!(matches!(
        cancelled.state,
        HealthState::Unknown {
            cause: HealthCause::Cancellation
        }
    ));

    // Late generation discard is covered in snapshot_atomicity.
    // Real SystemProbeExecutor kill/reap on a short deadline without sleep(2):
    // the child blocks on an unread FIFO (not a timed sleep), records its PID,
    // and must be gone after TimedOut.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("hang.sh");
        let pidfile = dir.path().join("child.pid");
        let fifo = dir.path().join("block.fifo");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$$\" > '{}'\nmkfifo '{}'\nexec cat '{}'\n",
                pidfile.display(),
                fifo.display(),
                fifo.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();

        let hang = ExternalRuntimeDescriptor::builder("hang")
            .candidates([script.to_str().unwrap()])
            .probe_policy(ProbePolicy::trusted_catalog(
                std::iter::empty::<String>(),
                VersionParser::FirstLine,
                None,
            ))
            .build()
            .unwrap();
        // Allow enough time for the child to write its pid and block on the
        // FIFO; still far below any multi-second sleep.
        let short = ProbeDeadlines {
            version: Duration::from_millis(500),
            functional: Duration::from_millis(500),
        };
        let started = std::time::Instant::now();
        let entry = evaluate_descriptor(
            &hang,
            &SystemProbeExecutor,
            None,
            Path::new("/"),
            &ctx(HostPlatform::GenericLinux),
            short,
            &CancelToken::new(),
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "probe hung instead of kill/reap: {:?}",
            started.elapsed()
        );
        assert!(
            matches!(entry.state, HealthState::TimedOut),
            "expected TimedOut after kill/reap, got {:?}",
            entry.state
        );
        // Require pidfile: proves a child started. Then prove it was reaped via
        // kill(pid, 0) (portable across Linux and macOS).
        let pid_txt = std::fs::read_to_string(&pidfile)
            .expect("child never wrote pidfile — cannot prove kill/reap");
        let pid: i32 = pid_txt.trim().parse().expect("pid");
        // Spin without timed sleeps until the child is gone or a wall budget
        // elapses (Instant-based; no sleep(2) in the child or the assertion).
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        let mut alive = true;
        while std::time::Instant::now() < deadline {
            // SAFETY: kill(pid, 0) is a liveness probe; ESRCH means gone.
            let rc = unsafe { libc::kill(pid, 0) };
            if rc != 0 {
                alive = false;
                break;
            }
            std::thread::yield_now();
        }
        assert!(
            !alive,
            "child pid {pid} still alive after TimedOut — kill/reap failed"
        );
    }
}

#[test]
fn external_dependency_platform_recipes() {
    // Table-test every HostPlatform classification and recipe rendering.
    let cases = [
        ("macos", None, HostPlatform::MacOs),
        ("darwin", None, HostPlatform::MacOs),
        ("windows", None, HostPlatform::Windows),
        (
            "linux",
            Some("ID=ubuntu\nID_LIKE=debian\n"),
            HostPlatform::DebianUbuntu,
        ),
        ("linux", Some("ID=debian\n"), HostPlatform::DebianUbuntu),
        ("linux", Some("ID=fedora\n"), HostPlatform::FedoraRhel),
        (
            "linux",
            Some("ID=rhel\nID_LIKE=\"fedora\"\n"),
            HostPlatform::FedoraRhel,
        ),
        ("linux", Some("ID=arch\n"), HostPlatform::Arch),
        (
            "linux",
            Some("ID=manjaro\nID_LIKE=arch\n"),
            HostPlatform::Arch,
        ),
        // Malformed os-release → generic Linux (never panics)
        (
            "linux",
            Some("THIS IS NOT VALID"),
            HostPlatform::GenericLinux,
        ),
        ("linux", Some("ID=\""), HostPlatform::GenericLinux),
        ("linux", Some("ID='"), HostPlatform::GenericLinux),
        ("linux", Some(""), HostPlatform::GenericLinux),
        ("linux", None, HostPlatform::GenericLinux),
        ("freebsd", None, HostPlatform::OtherUnix),
        ("openbsd", None, HostPlatform::OtherUnix),
        ("haiku", None, HostPlatform::Unsupported),
        ("unknown-os", None, HostPlatform::Unsupported),
    ];
    for (os, release, expected) in cases {
        assert_eq!(
            detect_host_platform_from(os, release),
            expected,
            "os={os} release={release:?}"
        );
    }

    let remedy = common_platform_remedy("rg");
    for platform in [
        HostPlatform::MacOs,
        HostPlatform::Windows,
        HostPlatform::DebianUbuntu,
        HostPlatform::FedoraRhel,
        HostPlatform::Arch,
        HostPlatform::GenericLinux,
        HostPlatform::OtherUnix,
        HostPlatform::Unsupported,
    ] {
        let rendered = remedy.render_for(platform);
        assert!(!rendered.is_empty(), "empty remedy for {platform:?}");
        // Remedies are strings only — never invoke package managers.
        assert!(!rendered.contains("\0"));
    }

    // macOS prefers brew for rg
    assert!(remedy.render_for(HostPlatform::MacOs).contains("brew"));
    assert!(
        remedy
            .render_for(HostPlatform::DebianUbuntu)
            .contains("apt-get")
    );
    assert!(remedy.render_for(HostPlatform::FedoraRhel).contains("dnf"));
    assert!(remedy.render_for(HostPlatform::Arch).contains("pacman"));
}

#[test]
fn external_dependency_snapshot_atomicity() {
    let store = HealthSnapshotStore::new();
    assert!(store.current().is_none());

    let g1 = store.begin_refresh();
    let g2 = store.begin_refresh();
    assert!(g2 > g1);

    let mut snap1 = ExternalRuntimeSnapshot::empty(g1, HostPlatform::GenericLinux);
    snap1.entries.insert(
        "a".into(),
        HealthEntry {
            id: ExternalRuntimeId::new("a"),
            state: HealthState::Available {
                resolved_path: None,
                version_evidence: Some("old".into()),
            },
            importance: DependencyImportance::OptionalIntegration,
            target: ExecutionTarget::Host,
            remedy: None,
            platform: HostPlatform::GenericLinux,
        },
    );

    let mut snap2 = ExternalRuntimeSnapshot::empty(g2, HostPlatform::GenericLinux);
    snap2.entries.insert(
        "a".into(),
        HealthEntry {
            id: ExternalRuntimeId::new("a"),
            state: HealthState::Missing,
            importance: DependencyImportance::OptionalIntegration,
            target: ExecutionTarget::Host,
            remedy: None,
            platform: HostPlatform::GenericLinux,
        },
    );

    // Older in-flight refresh completing after a newer generation was reserved
    // must not publish even when nothing is current yet.
    assert!(!store.publish(snap1.clone()));
    assert!(store.current().is_none());

    // Latest reserved generation publishes.
    assert!(store.publish(snap2.clone()));
    let current = store.current().unwrap();
    assert_eq!(current.generation, g2);
    assert!(matches!(
        current.get("a").unwrap().state,
        HealthState::Missing
    ));

    // Late older generation discarded — readers still see complete g2 only
    assert!(!store.publish(snap1));
    let current = store.current().unwrap();
    assert_eq!(current.generation, g2);

    // Equal/stale generation rejected
    assert!(!store.publish(snap2));

    // Readers never observe a partial generation: only complete Arc snapshots.
    let g3 = store.begin_refresh();
    let complete = ExternalRuntimeSnapshot::empty(g3, HostPlatform::MacOs);
    assert!(store.publish(complete));
    let seen = store.current().unwrap();
    assert_eq!(seen.generation, g3);
    assert!(seen.entries.is_empty());
}

#[test]
fn external_dependency_configured_command_remedy() {
    // Arbitrary commands receive no guessed package/vendor mapping.
    let remedy = configured_command_remedy("totally-unknown-vendor-cli", None);
    let rendered = remedy.render_for(HostPlatform::DebianUbuntu);
    assert!(!rendered.to_ascii_lowercase().contains("apt-get"));
    assert!(!rendered.to_ascii_lowercase().contains("brew"));
    assert!(!rendered.to_ascii_lowercase().contains("winget"));
    assert!(!rendered.to_ascii_lowercase().contains("dnf"));
    assert!(!rendered.to_ascii_lowercase().contains("pacman"));
    assert!(rendered.contains("totally-unknown-vendor-cli"));
    assert!(matches!(remedy, RemedyKind::ConfigGuidance { .. }));

    let with_path = configured_command_remedy("x", Some("/opt/custom/x"));
    let r = with_path.render_for(HostPlatform::MacOs);
    assert!(r.contains("/opt/custom/x"));
    assert!(!r.contains("brew"));

    // Name resemblance to known packages must not map to recipes.
    let dockerish = configured_command_remedy("docker", None);
    let d = dockerish.render_for(HostPlatform::DebianUbuntu);
    assert!(!d.contains("apt-get install docker"));
    assert!(matches!(dockerish, RemedyKind::ConfigGuidance { .. }));
}

#[test]
fn external_dependency_configured_commands_never_execute() {
    let executor = RecordingProbeExecutor::new().with_resolve("my-harness", "/opt/my-harness");
    // Also mark absolute path spawnable for exact_path case.
    executor
        .spawnable
        .lock()
        .unwrap()
        .insert(PathBuf::from("/opt/custom/lsp"));

    let harness = configured("my-harness", None);
    let lsp = configured("lsp-server", Some("/opt/custom/lsp"));
    let mcp = configured("mcp-stdio-tool", None);

    let cancel = CancelToken::new();
    let snap = refresh_snapshot(
        1,
        &[harness, lsp, mcp],
        &executor,
        None,
        Path::new("/"),
        &ctx_features(
            HostPlatform::GenericLinux,
            &["unknown", "harness", "search"],
        ),
        ProbeDeadlines::default(),
        &cancel,
    );

    assert_eq!(executor.run_count.load(Ordering::SeqCst), 0);
    assert!(executor.run_log.lock().unwrap().is_empty());

    assert!(matches!(
        snap.get("configured.my-harness").unwrap().state,
        HealthState::Available { .. }
    ));
    assert!(matches!(
        snap.get("configured.lsp-server").unwrap().state,
        HealthState::Available { .. }
    ));
    assert!(matches!(
        snap.get("configured.mcp-stdio-tool").unwrap().state,
        HealthState::Missing
    ));

    // ProbePolicy rejects embedding version argv on configured commands by type:
    // only ConfiguredCommand { command, exact_path } exists — no version fields.
    match &configured("x", None).probe_policy {
        ProbePolicy::ConfiguredCommand {
            command,
            exact_path,
        } => {
            assert_eq!(command, "x");
            assert!(exact_path.is_none());
        }
        ProbePolicy::TrustedCatalog(_) => panic!("must not be trusted catalog"),
    }
}

#[test]
fn external_dependency_trusted_catalog_probe_policy() {
    let executor = RecordingProbeExecutor::new().with_resolve("rg", "/usr/bin/rg");
    let desc = trusted_rg();
    assert!(desc.probe_policy.is_trusted_catalog());

    let entry = evaluate_descriptor(
        &desc,
        &executor,
        None,
        Path::new("/"),
        &ctx(HostPlatform::GenericLinux),
        ProbeDeadlines::default(),
        &CancelToken::new(),
    );
    assert!(matches!(entry.state, HealthState::Available { .. }));
    assert_eq!(executor.run_count.load(Ordering::SeqCst), 1);
    let run = &executor.run_log.lock().unwrap()[0];
    assert_eq!(run.args, vec!["--version".to_string()]);
    assert_eq!(run.deadline, VERSION_PROBE_DEADLINE);

    // Only trusted catalog reaches the run seam. Configured does not.
    let before = executor.run_count.load(Ordering::SeqCst);
    let _ = evaluate_descriptor(
        &configured("nope", None),
        &executor,
        None,
        Path::new("/"),
        &ctx(HostPlatform::GenericLinux),
        ProbeDeadlines::default(),
        &CancelToken::new(),
    );
    assert_eq!(executor.run_count.load(Ordering::SeqCst), before);

    // Catalog construction requires the sealed constructor.
    let policy = ProbePolicy::trusted_catalog(["-V"], VersionParser::FirstLine, None);
    assert!(policy.is_trusted_catalog());
    assert!(policy.as_trusted_catalog().unwrap().is_executable());

    // Serde-rehydrated trusted policies are not executable and never reach run(),
    // even if JSON claims `"executable": true` (field is serde-skipped).
    let forged_json = serde_json::json!({
        "kind": "trusted_catalog",
        "version_argv": ["--evil"],
        "version_parser": {"kind": "first_line"},
        "functional_argv": null,
        "executable": true
    });
    let forged: ProbePolicy = serde_json::from_value(forged_json).unwrap();
    assert!(!forged.as_trusted_catalog().unwrap().is_executable());
    let forged_desc = ExternalRuntimeDescriptor::builder("forged")
        .candidates(["rg"])
        .probe_policy(forged)
        .build()
        .unwrap();
    let reg = ExternalRuntimeRegistry::new();
    let reg_err = reg.register(forged_desc.clone()).unwrap_err();
    assert!(matches!(
        reg_err,
        RegistryError::NonExecutableTrustedCatalog(_)
    ));
    let before_forged = executor.run_count.load(Ordering::SeqCst);
    let forged_entry = evaluate_descriptor(
        &forged_desc,
        &executor,
        None,
        Path::new("/"),
        &ctx(HostPlatform::GenericLinux),
        ProbeDeadlines::default(),
        &CancelToken::new(),
    );
    assert_eq!(executor.run_count.load(Ordering::SeqCst), before_forged);
    assert!(matches!(
        forged_entry.state,
        HealthState::Failed {
            cause: HealthCause::Internal { .. }
        }
    ));
}

#[test]
fn external_dependency_binary_requirements_remain_fail_closed() {
    // Existing Tool::binary_requirements safety semantics remain fail-closed.
    let probe = Arc::new(crate::capabilities::SystemBinaryProbe);
    // Use a counting-style manual cache via evaluate with empty PATH so
    // required missing binaries stay unavailable.
    let cache = CapabilityProbeCache::new(Arc::new(MissingAllProbe), Duration::from_millis(5));
    let requirements = vec![
        BinaryRequirement::required("must-have", crate::capabilities::common_remedy("must-have")),
        BinaryRequirement::optional("nice", crate::capabilities::common_remedy("nice")),
    ];
    let result = evaluate_tool_requirements(
        "demo-tool",
        &requirements,
        &std::collections::HashMap::new(),
        Path::new("/"),
        ExecutionTarget::Host,
        &cache,
    );
    assert!(!result.is_callable());
    assert_eq!(result.unavailable.len(), 1);
    assert_eq!(result.unavailable[0].requirement.name, "must-have");
    assert_eq!(
        result.unavailable[0].requirement.kind,
        BinaryRequirementKind::Required
    );
    assert!(!result.unavailable[0].availability.is_available());
    assert_eq!(result.optional_missing.len(), 1);
    let _ = probe; // keep import meaningful if SystemBinaryProbe used later
}

struct MissingAllProbe;

impl crate::capabilities::BinaryProbe for MissingAllProbe {
    fn resolve(
        &self,
        _name: &str,
        _path: Option<&str>,
        _cwd: &Path,
        _budget: Duration,
    ) -> crate::capabilities::BinaryProbeStatus {
        crate::capabilities::BinaryProbeStatus::Missing
    }
}

#[test]
fn common_remedy_uses_platform_recipes_when_adapted() {
    // capabilities::common_remedy remains available and fail-closed prose/command.
    let remedy = crate::capabilities::common_remedy("rg");
    assert!(
        remedy
            .render_for_platform(crate::capabilities::RemedyPlatform::Unix)
            .contains("ripgrep")
    );
}

#[cfg(windows)]
#[test]
fn external_dependency_windows_ps1_not_spawnable() {
    let dir = tempfile::tempdir().unwrap();
    let ps1 = dir.path().join("tool.ps1");
    std::fs::write(&ps1, "Write-Host hi\n").unwrap();
    let exe = dir.path().join("tool.exe");
    std::fs::write(&exe, b"MZ").unwrap();
    let executor = SystemProbeExecutor;
    assert!(!executor.is_spawnable(&ps1));
    assert!(executor.is_spawnable(&exe));
}
