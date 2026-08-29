//! AC8 `sealed_marker_capability_predicate`
//!
//! The predicate exposes typed canonical identity, active exact
//! value/version/action capability, and the historical-redaction inventory —
//! and nothing else. It does not render provider copy, select subagents,
//! compile actions, validate adapter attributes, or implement export behavior.

use std::sync::Arc;

use super::*;
use crate::sealed::marker::{
    SealedCapabilityState, SealedMarkerPredicate, historical_redaction_inventory,
};
use crate::sealed::{SealedActionId, SealedActionRevision, SealedScopeKind};

#[tokio::test]
async fn sealed_marker_capability_predicate() {
    let fixture = SealedFixture::new().await;
    let directory = fixture.directory();
    let owner = SealedFixture::owner();
    let seeded = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;

    let probe = Arc::new(ProbeAction::new(1));
    let registry = registry_with(vec![probe as Arc<dyn SealedHostAction>]);
    let predicate = SealedMarkerPredicate::new(fixture.db.clone());
    let action_id = SealedActionId::parse(PROBE_ACTION).expect("action id");
    let revision_one = SealedActionRevision::new(1).expect("revision");

    // ---- typed canonical identity ------------------------------------------
    let identity = predicate
        .identity(seeded.record_id)
        .await
        .expect("identity read")
        .expect("record is live");
    assert_eq!(identity.record_id, seeded.record_id);
    assert_eq!(identity.scope, SealedScopeKind::Project);
    assert_eq!(identity.name.as_str(), "deploy_token");
    assert_eq!(identity.version, 1);
    assert!(
        !format!("{identity:?}").contains(TEST_LITERAL),
        "typed identity carries no literal"
    );

    // ---- active exact value/version/action capability -----------------------
    assert_eq!(
        predicate
            .active_capability(seeded.record_id, 1, &action_id, revision_one, &registry)
            .await
            .expect("capability read"),
        SealedCapabilityState::Active
    );

    // Wrong version, wrong revision, and an uncompiled action are all inactive.
    assert_eq!(
        predicate
            .active_capability(seeded.record_id, 2, &action_id, revision_one, &registry)
            .await
            .expect("capability read"),
        SealedCapabilityState::Inactive
    );
    assert_eq!(
        predicate
            .active_capability(
                seeded.record_id,
                1,
                &action_id,
                SealedActionRevision::new(2).expect("revision"),
                &registry
            )
            .await
            .expect("capability read"),
        SealedCapabilityState::Inactive
    );
    assert_eq!(
        predicate
            .active_capability(
                seeded.record_id,
                1,
                &action_id,
                revision_one,
                &crate::sealed::SealedActionRegistry::empty()
            )
            .await
            .expect("capability read"),
        SealedCapabilityState::Inactive
    );

    // Rotation moves the live version, so the old tuple goes inactive and the
    // new one becomes active.
    directory
        .rotate(
            owner,
            seeded.record_id,
            SealedLiteral::new("rotated-literal-value-0002"),
            5_000,
        )
        .await
        .expect("rotated");
    assert_eq!(
        predicate
            .active_capability(seeded.record_id, 1, &action_id, revision_one, &registry)
            .await
            .expect("capability read"),
        SealedCapabilityState::Inactive
    );
    assert_eq!(
        predicate
            .active_capability(seeded.record_id, 2, &action_id, revision_one, &registry)
            .await
            .expect("capability read"),
        SealedCapabilityState::Active
    );

    // ---- historical redaction inventory --------------------------------------
    // Redaction is monotonic: an entry survives deletion of the value it names.
    use crate::sealed::identity::SealedRedactionIdentity;
    let table = crate::redact::RedactionTable::empty();
    let table = table
        .with_forced_sealed_literal(
            TEST_LITERAL.to_string(),
            SealedRedactionIdentity {
                scope: SealedScopeKind::Project,
                record_id: Some(seeded.record_id),
                name: SealedName::canonical("deploy_token").expect("name"),
                version: 1,
            },
        )
        .expect("registered v1");
    let table = table
        .with_forced_sealed_literal(
            "rotated-literal-value-0002".to_string(),
            SealedRedactionIdentity {
                scope: SealedScopeKind::Project,
                record_id: Some(seeded.record_id),
                name: SealedName::canonical("deploy_token").expect("name"),
                version: 2,
            },
        )
        .expect("registered v2");
    // A pre-scope session entry is still inventoried.
    let table = table
        .with_forced_sealed_literal(
            "legacy-session-literal-x".to_string(),
            SealedRedactionIdentity {
                scope: SealedScopeKind::Session,
                record_id: None,
                name: SealedName::canonical("prod_token").expect("name"),
                version: 0,
            },
        )
        .expect("registered legacy");

    let inventory = historical_redaction_inventory(&table);
    assert_eq!(inventory.len(), 3, "{inventory:?}");
    let versions: Vec<u32> = inventory
        .iter()
        .filter(|entry| entry.name.as_str() == "deploy_token")
        .map(|entry| entry.version)
        .collect();
    assert_eq!(versions, vec![1, 2], "both versions stay inventoried");
    assert!(
        inventory
            .iter()
            .any(|entry| entry.name.as_str() == "prod_token"
                && entry.record_id.is_none()
                && entry.scope == SealedScopeKind::Session),
        "a pre-scope session entry is inventoried by name"
    );

    // The inventory carries identity only — never a literal, never a grant.
    let rendered = format!("{inventory:?}");
    assert!(!rendered.contains(TEST_LITERAL));
    assert!(!rendered.contains("rotated-literal-value-0002"));
    assert!(!rendered.contains("grant"));

    // Deleting the value does not shrink the historical inventory: a
    // transcript written while it was live must stay scrubbed forever.
    directory
        .delete(owner, seeded.record_id, 6_000)
        .await
        .expect("deleted");
    assert!(
        predicate
            .identity(seeded.record_id)
            .await
            .expect("identity read")
            .is_none(),
        "a deleted value has no live identity"
    );
    assert_eq!(
        historical_redaction_inventory(&table).len(),
        3,
        "redaction history is monotonic across deletion"
    );

    // Round-trips through the persisted form the export consumer reads.
    let json = table.to_persisted_json().expect("persisted");
    let from_persisted =
        crate::sealed::marker::historical_redaction_inventory_from_persisted(&json)
            .expect("persisted inventory");
    assert_eq!(from_persisted, historical_redaction_inventory(&table));

    // ---- structural: the predicate does only its three jobs -------------------
    // Scan code only: the module docs *name* the neighbouring owners on
    // purpose, so a doc mention must not read as a dependency.
    let source: String = include_str!("../marker.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        // no provider-wire copy
        "format!(\"You are",
        "provider_copy",
        // no subagent or mode selection
        "AgentDef",
        "subagent",
        // no action compilation or adapter validation
        "with_action",
        "SealedActionRegistryBuilder",
        "OwnerAuthority",
        "adapter",
        // no export behavior
        "std::fs",
        "write_all",
        "serde_json::to_writer",
        // no literal access, and no grant/authorization result
        "expose",
        "SealedUseDenied",
        "authorize",
        "sealed_action_grant_for",
    ] {
        assert!(
            !source.contains(forbidden),
            "the marker predicate must not reference `{forbidden}`"
        );
    }
}
