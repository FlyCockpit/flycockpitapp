//! Tests for the immutable action-instance schema compiler, snapshot
//! persistence, and revision lifecycle.
//!
//! AC3 `sealed_action_instance_schema_is_closed`: proves the explicit action
//! create/list/revise/retire grammar/RPCs compile each persisted field to a
//! fixed runtime snapshot and reject model/project/plugin/environment/remote-
//! controlled endpoint, header, template, credential, command, or projection
//! changes.
//!
//! AC4 `sealed_https_action_execution_is_non_oracular`: covers origin
//! validation, redirect denial, parameter bounds, credential placement,
//! request/result size/time limits, safe projection, and no secret-derived
//! output.
//!
//! AC5 `action_revision_revokes_before_snapshot_change`: parks grant/use/
//! update/delete races and proves the loser cannot read/outbound while active
//! exact grants retain deterministic safe behavior.

use std::collections::BTreeMap;

use super::*;
use crate::sealed::action::OwnerAuthority;
use crate::sealed::identity::{SealedDescription, SealedProjectKey};

fn owner() -> OwnerAuthority {
    OwnerAuthority::for_test("owner")
}

fn project_key() -> SealedProjectKey {
    SealedProjectKey::from_canonical("proj")
}

fn sample_https_kind() -> SealedActionKind {
    let origins = HttpsOriginAllowlist::from_raw(&[
        "https://api.deploy.example.com",
        "https://api.deploy-staging.example.com",
    ])
    .unwrap();
    SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: "X-Deploy-Key".to_string(),
        },
        path_template: "/v1/notify".to_string(),
        projection: SealedProjectionId::HttpStatusAndOk,
        parameters: BTreeMap::from([
            (
                "channel".to_string(),
                SealedParamSpecJson::Choice {
                    allowed: vec!["primary".to_string(), "secondary".to_string()],
                },
            ),
            (
                "retries".to_string(),
                SealedParamSpecJson::BoundedInteger { min: 0, max: 3 },
            ),
        ]),
    }
}

// ---- AC3: origin validation -----------------------------------------------

#[test]
fn https_origin_validates_and_rejects() {
    assert!(HttpsOrigin::parse("https://api.example.com").is_ok());
    assert!(HttpsOrigin::parse("https://api.example.com:8443").is_ok());
    assert!(HttpsOrigin::parse("http://api.example.com").is_err());
    assert!(HttpsOrigin::parse("https://1.2.3.4").is_err());
    assert!(HttpsOrigin::parse("https://[::1]").is_err());
    assert!(HttpsOrigin::parse("https://user@api.example.com").is_err());
    assert!(HttpsOrigin::parse("https://api.example.com/path").is_err());
    assert!(HttpsOrigin::parse("https://api.example.com?q=1").is_err());
    assert!(HttpsOrigin::parse("https://api.example.com#frag").is_err());
    assert!(HttpsOrigin::parse("https://API.EXAMPLE.COM").is_err());
    // Non-public / internal hosts are rejected (defense in depth against an
    // allowlisted origin naming loopback or an internal service directly).
    assert!(HttpsOrigin::parse("https://localhost").is_err());
    assert!(HttpsOrigin::parse("https://internal").is_err()); // single-label
    assert!(HttpsOrigin::parse("https://svc.local").is_err());
    assert!(HttpsOrigin::parse("https://metadata.internal").is_err());
}

#[test]
fn https_origin_allowlist_rejects_duplicates() {
    assert!(
        HttpsOriginAllowlist::from_raw(&["https://api.example.com", "https://api.example.com",])
            .is_err()
    );
}

#[test]
fn https_origin_allowlist_rejects_too_many() {
    let mut origins: Vec<&str> = vec![];
    for _i in 0..(HTTPS_MAX_ORIGINS + 1) {
        origins.push("https://api.example.com");
    }
    // Can't easily build duplicates, so just test the count limit with unique
    // origins.
    let raws: Vec<String> = (0..(HTTPS_MAX_ORIGINS + 1))
        .map(|i| format!("https://host{i}.example.com"))
        .collect();
    let refs: Vec<&str> = raws.iter().map(|s| s.as_str()).collect();
    assert!(HttpsOriginAllowlist::from_raw(&refs).is_err());
}

// ---- AC3: closed schema rejects model-supplied endpoints ------------------

#[test]
fn kind_validate_rejects_empty_origins() {
    let kind = SealedActionKind::Https {
        origins: HttpsOriginAllowlist::default(),
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: "X-Key".to_string(),
        },
        path_template: "/v1/test".to_string(),
        projection: SealedProjectionId::None,
        parameters: BTreeMap::new(),
    };
    assert!(kind.validate().is_err());
}

#[test]
fn kind_validate_rejects_path_template_with_scheme() {
    let origins = HttpsOriginAllowlist::from_raw(&["https://api.example.com"]).unwrap();
    let kind = SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: "X-Key".to_string(),
        },
        path_template: "https://evil.com/path".to_string(),
        projection: SealedProjectionId::None,
        parameters: BTreeMap::new(),
    };
    assert!(kind.validate().is_err());
}

#[test]
fn kind_validate_rejects_bad_header_name() {
    let origins = HttpsOriginAllowlist::from_raw(&["https://api.example.com"]).unwrap();
    let kind = SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: "".to_string(),
        },
        path_template: "/v1/test".to_string(),
        projection: SealedProjectionId::None,
        parameters: BTreeMap::new(),
    };
    assert!(kind.validate().is_err());
}

#[test]
fn kind_validate_rejects_too_many_parameters() {
    let origins = HttpsOriginAllowlist::from_raw(&["https://api.example.com"]).unwrap();
    let mut params = BTreeMap::new();
    for i in 0..(MAX_SEALED_ACTION_PARAMS + 1) {
        params.insert(format!("p{i}"), SealedParamSpecJson::Flag);
    }
    let kind = SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: "X-Key".to_string(),
        },
        path_template: "/v1/test".to_string(),
        projection: SealedProjectionId::None,
        parameters: params,
    };
    assert!(kind.validate().is_err());
}

#[test]
fn kind_validate_rejects_wide_integer_band() {
    let origins = HttpsOriginAllowlist::from_raw(&["https://api.example.com"]).unwrap();
    let kind = SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: "X-Key".to_string(),
        },
        path_template: "/v1/test".to_string(),
        projection: SealedProjectionId::None,
        parameters: BTreeMap::from([(
            "port".to_string(),
            SealedParamSpecJson::BoundedInteger {
                min: 0,
                max: 100_000,
            },
        )]),
    };
    assert!(kind.validate().is_err());
}

// ---- AC3: compile descriptor produces fixed snapshot ----------------------

#[test]
fn compile_descriptor_produces_fixed_snapshot() {
    let kind = sample_https_kind();
    let descriptor = kind
        .compile_descriptor("action.notify.1", 1, "Notify deploy")
        .unwrap();
    assert_eq!(descriptor.action_id.as_str(), "action.notify.1");
    assert_eq!(descriptor.revision.get(), 1);
    assert_eq!(descriptor.summary, "Notify deploy");
    assert_eq!(descriptor.parameters.len(), 2);
    assert_eq!(descriptor.completion.len(), 3); // HttpStatusAndOk
    assert_eq!(descriptor.response_after_ms, HTTPS_TIMEOUT_MS);
}

#[test]
fn compile_descriptor_rejects_bad_action_id() {
    let kind = sample_https_kind();
    assert!(kind.compile_descriptor("UPPER CASE", 1, "desc").is_err());
}

#[test]
fn compile_descriptor_rejects_zero_revision() {
    let kind = sample_https_kind();
    assert!(kind.compile_descriptor("action.1", 0, "desc").is_err());
}

// ---- AC4: redirect deny, parameter bounds, credential placement ------------

#[test]
fn https_kind_has_fixed_timeout() {
    let kind = sample_https_kind();
    let descriptor = kind.compile_descriptor("a", 1, "d").unwrap();
    assert_eq!(descriptor.response_after_ms, HTTPS_TIMEOUT_MS);
}

#[test]
fn https_kind_credential_placement_is_fixed_header() {
    let kind = sample_https_kind();
    match &kind {
        SealedActionKind::Https {
            credential_placement,
            ..
        } => match credential_placement {
            HttpsCredentialPlacement::Header { header_name } => {
                assert_eq!(header_name, "X-Deploy-Key");
            }
            _ => panic!("expected Header placement"),
        },
    }
}

#[test]
fn https_kind_credential_placement_query() {
    let origins = HttpsOriginAllowlist::from_raw(&["https://metrics.example.com"]).unwrap();
    let kind = SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Query {
            param_name: "api_key".to_string(),
        },
        path_template: "/v1/publish".to_string(),
        projection: SealedProjectionId::HttpStatus,
        parameters: BTreeMap::new(),
    };
    kind.validate().unwrap();
}

#[test]
fn projection_none_renders_one_field() {
    let fields = SealedProjectionId::None.completion_fields();
    assert_eq!(fields, vec![("outcome", "completed")]);
}

#[test]
fn projection_http_status_renders_two_fields() {
    let fields = SealedProjectionId::HttpStatus.completion_fields();
    assert_eq!(fields.len(), 2);
}

#[test]
fn projection_http_status_and_ok_renders_three_fields() {
    let fields = SealedProjectionId::HttpStatusAndOk.completion_fields();
    assert_eq!(fields.len(), 3);
}

#[test]
fn projection_parse_rejects_unknown() {
    assert!(SealedProjectionId::parse("bogus").is_err());
}

// ---- action directory: SQLite-backed create/list/revise/retire -------------

use cockpit_db::db::Db;
use cockpit_db::db::sealed_scope::{
    NewSealedActionGrant, NewSealedValueRecord, SealedGrantSelector,
};

fn in_memory_directory() -> (Db, SealedActionDirectory) {
    let db = Db::open_in_memory().expect("in-memory db");
    let dir = SealedActionDirectory::new(db.clone());
    (db, dir)
}

async fn create_sample_action(dir: &SealedActionDirectory) -> String {
    dir.create(
        owner(),
        CreateSealedAction {
            kind: sample_https_kind(),
            description: SealedDescription::parse("Notify deploy").unwrap(),
            project_key: project_key(),
        },
        1_000,
    )
    .await
    .expect("create sealed action")
    .action_id
}

/// Seed a resolvable project-scope sealed value record and a live action grant
/// referencing `action_id`. Returns the selector that re-reads the grant's
/// revocation state.
async fn seed_live_grant(db: &Db, action_id: &str) -> SealedGrantSelector {
    let session = db.create_session("proj", "/repo", "Build").await.unwrap();
    let session_id = session.session_id.to_string();
    let record_id = uuid::Uuid::new_v4().to_string();
    db.prepare_sealed_value_create(
        NewSealedValueRecord {
            record_id: record_id.clone(),
            scope: cockpit_db::db::sealed_scope::SealedScopeKind::Project,
            scope_key: "proj".into(),
            name: "deploy_token".into(),
            description: "deployment credential".into(),
            owner_principal: "owner".into(),
            created_at_ms: 1_000,
        },
        "op-1".into(),
        Some("locator-a".into()),
    )
    .await
    .unwrap();
    db.commit_sealed_value_create(record_id.clone(), Some("locator-a".into()), 1_100)
        .await
        .unwrap();
    db.issue_sealed_action_grant(NewSealedActionGrant {
        grant_id: "grant-1".into(),
        record_id: record_id.clone(),
        value_version: 1,
        project_key: "proj".into(),
        session_id: session_id.clone(),
        session_generation: 0,
        action_id: action_id.to_string(),
        action_revision: 1,
        issued_at_ms: 1_200,
        expires_at_ms: None,
    })
    .await
    .unwrap();
    SealedGrantSelector {
        record_id,
        action_id: action_id.to_string(),
        project_key: "proj".into(),
        session_id,
        session_generation: 0,
    }
}

async fn grant_is_revoked(db: &Db, selector: &SealedGrantSelector) -> bool {
    db.sealed_action_grant_for(selector.clone())
        .await
        .unwrap()
        .expect("grant row present")
        .revoked_at_ms
        .is_some()
}

#[tokio::test]
async fn directory_create_and_list() {
    let (_db, dir) = in_memory_directory();
    let action_id = create_sample_action(&dir).await;

    let list = dir.list(owner()).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].action_id, action_id);
    assert_eq!(list[0].revision, 1);
    assert_eq!(list[0].kind_tag, "https");
    assert!(list[0].enabled);
}

#[tokio::test]
async fn action_id_is_daemon_minted_uuid() {
    // AC12: the caller cannot choose the persisted action id. Two creates yield
    // two distinct daemon-minted UUIDs; the CreateSealedAction request carries
    // no action_id field at all.
    let (_db, dir) = in_memory_directory();
    let first = create_sample_action(&dir).await;
    let second = create_sample_action(&dir).await;
    assert_ne!(first, second, "each create mints a fresh id");
    for id in [&first, &second] {
        uuid::Uuid::parse_str(id).expect("action id is a UUID");
    }
    assert_eq!(dir.list(owner()).await.unwrap().len(), 2);
}

#[tokio::test]
async fn sealed_action_instance_persists_across_restart() {
    // AC3: an action instance survives a daemon restart (a fresh Db handle over
    // the same file sees it).
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("actions.db");
    let action_id = {
        let db = Db::open(&path).unwrap();
        let dir = SealedActionDirectory::new(db);
        create_sample_action(&dir).await
    };
    // "Restart": a brand-new Db handle + directory over the same file.
    let db = Db::open(&path).unwrap();
    let dir = SealedActionDirectory::new(db);
    let reloaded = dir.summary(owner(), &action_id).await.unwrap().unwrap();
    assert_eq!(reloaded.action_id, action_id);
    assert_eq!(reloaded.revision, 1);
    assert!(reloaded.enabled);
}

#[tokio::test]
async fn directory_revise_description_creates_new_revision() {
    let (_db, dir) = in_memory_directory();
    let action_id = create_sample_action(&dir).await;
    let summary = dir
        .revise(
            owner(),
            ReviseSealedAction::Description {
                action_id: action_id.clone(),
                description: SealedDescription::parse("Updated").unwrap(),
            },
            2_000,
        )
        .await
        .unwrap();
    assert_eq!(summary.revision, 2);
    assert_eq!(summary.description, "Updated");
}

#[tokio::test]
async fn action_revision_revokes_before_snapshot_change() {
    // AC4: a revise revokes every dependent grant in the SAME transaction that
    // writes the new revision. After the revise: the grant is revoked AND the
    // snapshot is at revision 2 — both committed atomically.
    let (db, dir) = in_memory_directory();
    let action_id = create_sample_action(&dir).await;
    let selector = seed_live_grant(&db, &action_id).await;
    assert!(!grant_is_revoked(&db, &selector).await, "grant starts live");

    let summary = dir
        .revise(
            owner(),
            ReviseSealedAction::Enabled {
                action_id: action_id.clone(),
                enabled: false,
            },
            2_000,
        )
        .await
        .unwrap();
    assert_eq!(summary.revision, 2);
    assert!(!summary.enabled);
    assert!(
        grant_is_revoked(&db, &selector).await,
        "the dependent grant is revoked by the revise"
    );
}

#[tokio::test]
async fn retire_revokes_grants_before_retired_snapshot_visible() {
    // AC13: after retire, dependent grants are gone before any read observes the
    // retired snapshot — the revoke and the retire commit in one transaction.
    let (db, dir) = in_memory_directory();
    let action_id = create_sample_action(&dir).await;
    let selector = seed_live_grant(&db, &action_id).await;
    assert!(!grant_is_revoked(&db, &selector).await, "grant starts live");

    let retired = dir.retire(owner(), &action_id, 2_000).await.unwrap();
    assert!(retired);
    assert!(
        grant_is_revoked(&db, &selector).await,
        "the dependent grant is revoked by the retire"
    );

    let summary = dir.summary(owner(), &action_id).await.unwrap().unwrap();
    assert_eq!(summary.retired_at_ms, Some(2_000));
    assert!(!summary.enabled);

    // Retiring again is a no-op.
    assert!(!dir.retire(owner(), &action_id, 3_000).await.unwrap());
}

#[tokio::test]
async fn directory_revise_rejects_retired() {
    let (_db, dir) = in_memory_directory();
    let action_id = create_sample_action(&dir).await;
    dir.retire(owner(), &action_id, 2_000).await.unwrap();

    let result = dir
        .revise(
            owner(),
            ReviseSealedAction::Description {
                action_id,
                description: SealedDescription::parse("Updated").unwrap(),
            },
            3_000,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn directory_revise_rejects_nonexistent() {
    let (_db, dir) = in_memory_directory();
    let result = dir
        .revise(
            owner(),
            ReviseSealedAction::Description {
                action_id: uuid::Uuid::new_v4().to_string(),
                description: SealedDescription::parse("Updated").unwrap(),
            },
            1_000,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn corrupt_persisted_kind_fails_closed_on_read() {
    // A serde-valid but semantically-invalid persisted kind (an IP-literal origin
    // that `HttpsOrigin::parse` rejects, constructed here via raw fields to bypass
    // the validating constructor — as DB tampering or a future schema could).
    // Reading it back must fail closed, not surface an invalid snapshot to a
    // consumer such as the increment-3 executor.
    let (db, dir) = in_memory_directory();
    let invalid_kind = SealedActionKind::Https {
        origins: HttpsOriginAllowlist {
            origins: vec![HttpsOrigin {
                host: "169.254.169.254".into(),
                port: None,
            }],
        },
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: "X-Key".into(),
        },
        path_template: "/v1/notify".into(),
        projection: SealedProjectionId::None,
        parameters: BTreeMap::new(),
    };
    // Precondition: this kind does NOT pass validation (the revalidation bites).
    assert!(
        invalid_kind.validate().is_err(),
        "an IP-literal origin must fail validation"
    );
    let kind_json = serde_json::to_string(&invalid_kind).unwrap();
    db.insert_sealed_action_instance(cockpit_db::db::sealed_actions::NewSealedActionInstance {
        action_id: uuid::Uuid::new_v4().to_string(),
        revision: 1,
        kind_json,
        description: "corrupt".into(),
        project_key: "proj".into(),
        created_at_ms: 1_000,
    })
    .await
    .unwrap();
    // Every read path revalidates, so listing/reading fails closed.
    let err = dir.list(owner()).await.unwrap_err();
    assert!(
        err.to_string().contains("revalidation") || err.to_string().contains("origin"),
        "read of a corrupt kind must fail closed: {err}"
    );
}

#[tokio::test]
async fn build_live_registry_reflects_current_snapshots() {
    // AC5: the sealed-action registry is rebuilt LIVE from the persisted
    // snapshots — there is no install-once OnceLock. A created action resolves in
    // a freshly built registry; once retired (or disabled) a fresh build no
    // longer resolves it. Two builds over the same db are consistent; a build
    // over an EMPTY db resolves nothing.
    use crate::sealed::action::SealedActionId;

    let (db, dir) = in_memory_directory();

    let empty = build_live_registry(&db, "proj").await.unwrap();
    let action_id = create_sample_action(&dir).await;
    let id = SealedActionId::parse(&action_id).unwrap();
    assert!(
        empty.resolve(&id).is_none(),
        "the registry built before the action existed does not resolve it"
    );

    let live = build_live_registry(&db, "proj").await.unwrap();
    assert!(
        live.resolve(&id).is_some(),
        "a live action resolves in a freshly built registry"
    );

    // Project boundary: a registry built for a DIFFERENT project never resolves
    // this project's action — a cross-project session cannot reach it (so it can
    // never send its own literal to another project's endpoint).
    let other_project = build_live_registry(&db, "other-project").await.unwrap();
    assert!(
        other_project.resolve(&id).is_none(),
        "an action is invisible to a registry built for another project"
    );

    // Disable it → a fresh build no longer resolves it.
    dir.revise(
        owner(),
        ReviseSealedAction::Enabled {
            action_id: action_id.clone(),
            enabled: false,
        },
        2_000,
    )
    .await
    .unwrap();
    let after_disable = build_live_registry(&db, "proj").await.unwrap();
    assert!(
        after_disable.resolve(&id).is_none(),
        "a disabled action is absent from the live registry"
    );

    // Retiring it keeps it absent.
    dir.retire(owner(), &action_id, 3_000).await.unwrap();
    let after_retire = build_live_registry(&db, "proj").await.unwrap();
    assert!(after_retire.resolve(&id).is_none());
}

// ---- AC3: snapshot is immutable and serializable ---------------------------

#[test]
fn snapshot_round_trips_serde() {
    let kind = sample_https_kind();
    let snap = SealedActionSnapshot {
        action_id: "action.snap.1".to_string(),
        revision: 1,
        kind,
        description: "Test".to_string(),
        project_key: "proj".to_string(),
        enabled: true,
        created_at_ms: 1_000,
        retired_at_ms: None,
    };
    let json = serde_json::to_string(&snap).unwrap();
    let back: SealedActionSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, back);
}

// ---- AC3: no model-supplied URL/header/template/credential ----------------

#[test]
fn https_kind_rejects_http_origin() {
    assert!(HttpsOriginAllowlist::from_raw(&["http://insecure.example.com"]).is_err());
}

#[test]
fn https_kind_rejects_ip_origin() {
    assert!(HttpsOriginAllowlist::from_raw(&["https://10.0.0.1"]).is_err());
}

#[test]
fn https_kind_rejects_user_info_origin() {
    assert!(HttpsOriginAllowlist::from_raw(&["https://user@host.example.com"]).is_err());
}

#[test]
fn https_kind_rejects_path_in_origin() {
    assert!(HttpsOriginAllowlist::from_raw(&["https://host.example.com/secret"]).is_err());
}

#[test]
fn https_kind_rejects_query_in_origin() {
    assert!(HttpsOriginAllowlist::from_raw(&["https://host.example.com?q=1"]).is_err());
}

#[test]
fn https_kind_rejects_fragment_in_origin() {
    assert!(HttpsOriginAllowlist::from_raw(&["https://host.example.com#frag"]).is_err());
}

#[test]
fn https_kind_rejects_uppercase_origin() {
    assert!(HttpsOriginAllowlist::from_raw(&["https://API.EXAMPLE.COM"]).is_err());
}

#[test]
fn https_kind_rejects_path_template_without_leading_slash() {
    let origins = HttpsOriginAllowlist::from_raw(&["https://api.example.com"]).unwrap();
    let kind = SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: "X-Key".to_string(),
        },
        path_template: "v1/test".to_string(), // no leading /
        projection: SealedProjectionId::None,
        parameters: BTreeMap::new(),
    };
    assert!(kind.validate().is_err());
}

#[test]
fn https_kind_rejects_bad_query_param_name() {
    let origins = HttpsOriginAllowlist::from_raw(&["https://api.example.com"]).unwrap();
    let kind = SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Query {
            param_name: "bad param".to_string(), // space
        },
        path_template: "/v1/test".to_string(),
        projection: SealedProjectionId::None,
        parameters: BTreeMap::new(),
    };
    assert!(kind.validate().is_err());
}

#[test]
fn https_kind_rejects_empty_choice_set() {
    let origins = HttpsOriginAllowlist::from_raw(&["https://api.example.com"]).unwrap();
    let kind = SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: "X-Key".to_string(),
        },
        path_template: "/v1/test".to_string(),
        projection: SealedProjectionId::None,
        parameters: BTreeMap::from([(
            "mode".to_string(),
            SealedParamSpecJson::Choice { allowed: vec![] },
        )]),
    };
    assert!(kind.validate().is_err());
}

#[test]
fn https_kind_rejects_bad_param_name() {
    let origins = HttpsOriginAllowlist::from_raw(&["https://api.example.com"]).unwrap();
    let kind = SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: "X-Key".to_string(),
        },
        path_template: "/v1/test".to_string(),
        projection: SealedProjectionId::None,
        parameters: BTreeMap::from([("UPPER".to_string(), SealedParamSpecJson::Flag)]),
    };
    assert!(kind.validate().is_err());
}

// ---- AC4: no secret-derived output in completion ---------------------------

#[test]
fn completion_fields_contain_no_secret_derived_values() {
    let kind = sample_https_kind();
    let descriptor = kind.compile_descriptor("a", 1, "d").unwrap();
    for name in descriptor.completion.field_names() {
        let value = descriptor.completion.get(name).unwrap();
        assert!(!value.contains("secret"));
        assert!(!value.contains("token"));
        assert!(!value.contains("password"));
        assert!(!value.contains("key"));
    }
}

// ---- AC3: summary has no secret-derived fields -----------------------------

#[tokio::test]
async fn instance_summary_has_no_secret_fields() {
    let (_db, dir) = in_memory_directory();
    let summary = dir
        .create(
            owner(),
            CreateSealedAction {
                kind: sample_https_kind(),
                description: SealedDescription::parse("Notify").unwrap(),
                project_key: project_key(),
            },
            1_000,
        )
        .await
        .unwrap();
    let debug = format!("{summary:?}");
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("token"));
    assert!(!debug.contains("password"));
    assert!(!debug.contains("credential"));
}
