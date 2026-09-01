//! AC8 `sealed_marker_reaches_untrusted_wire_only_with_active_grant`.
//!
//! Drives the two real production entry points that wire the sealed marker to
//! real grants: [`crate::sealed::active_sealed_value_ids`] (the grant-liveness
//! derivation, over real grant + record rows in a tempdir DB) and
//! [`crate::engine::model::Model::prepare_completion_request`] (the interactive
//! completion chokepoint's egress), with the derived active set applied to the
//! model's effective table via `with_sealed_replacements`. It proves the
//! actionable marker reaches every model wire iff an exact grant is live, is
//! generic otherwise, and that derivation is fresh per attempt (a grant revoked
//! between two attempts renders marker then generic).

use std::sync::Arc;

use super::*;
use crate::config::providers::{ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig};
use crate::engine::message::{Message, ToolDefinition};
use crate::engine::model::{Model, ModelParams};
use crate::redact::{RedactionTable, sealed_untrusted_inference_marker};
use crate::sealed::active_sealed_value_ids;
use crate::sealed::compartment::SealedLiteral;
use crate::sealed::identity::{
    SealedName, SealedRedactionIdentity, sealed_legacy_active_key, sealed_scoped_active_key,
};
use crate::sealed::{IssueSealedGrant, SealedActionId, SealedActionRevision, SealedScopeKind};

const GENERATION: u64 = 4;
const NOW: i64 = 50_000;

fn untrusted_model(session_table: Arc<RedactionTable>) -> Model {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "cloud".into(),
        ProviderEntry {
            url: "http://127.0.0.1:1/v1".into(),
            models: vec![ModelEntry {
                id: "cloud-model".into(),
                trust: Some(ModelTrust::Untrusted),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    Model::for_provider(&cfg, "cloud", "cloud-model", session_table).expect("untrusted model")
}

fn trusted_model(session_table: Arc<RedactionTable>) -> Model {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "local".into(),
        ProviderEntry {
            url: "http://127.0.0.1:1/v1".into(),
            models: vec![ModelEntry {
                id: "local-model".into(),
                trust: Some(ModelTrust::Trusted),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    Model::for_provider(&cfg, "local", "local-model", session_table).expect("trusted model")
}

/// The sealed literal, registered under a scoped typed identity keyed by the
/// seeded record id.
fn sealed_table(record_id: crate::sealed::identity::SealedRecordId) -> Arc<RedactionTable> {
    let identity = SealedRedactionIdentity {
        scope: SealedScopeKind::Project,
        record_id: Some(record_id),
        name: SealedName::canonical("deploy_token").expect("name"),
        version: 1,
    };
    Arc::new(
        RedactionTable::empty()
            .with_forced_sealed_literal(TEST_LITERAL.to_string(), identity)
            .expect("sealed table"),
    )
}

/// Prepare a request body with the derived active set applied and
/// return the serialized captured wire body.
fn prepared_body(model: &Model, active: &std::collections::HashSet<String>) -> String {
    let egress = model.redact_table().with_sealed_replacements(active);
    let history = [Message::user(format!("the deploy token is {TEST_LITERAL}"))];
    let prepared = model
        .prepare_completion_request(
            crate::engine::model::AgentPromptParts::new("system", &history),
            &Message::user("proceed"),
            &[],
            &ModelParams::default(),
            false,
            Some(&egress),
        )
        .expect("prepared untrusted request");
    serde_json::to_string(&prepared.captured).expect("serialize captured")
}

#[tokio::test]
async fn sealed_marker_reaches_untrusted_wire_only_with_active_grant() {
    let fixture = SealedFixture::new().await;
    let seeded = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;
    let probe = Arc::new(ProbeAction::new(1));
    let registry = registry_with(vec![probe as Arc<dyn crate::sealed::SealedHostAction>]);
    let action_id = SealedActionId::parse(PROBE_ACTION).expect("action id");
    let marker = sealed_untrusted_inference_marker(&seeded.record_id.to_string());

    // (a) A live exact grant → the record id is in the active set, and the
    // untrusted wire body renders the exact actionable marker with zero literal
    // bytes.
    let live_grant = fixture
        .directory()
        .issue_action_grant(
            SealedFixture::owner(),
            IssueSealedGrant {
                record_id: seeded.record_id,
                value_version: 1,
                project_key: fixture.project_key.clone(),
                session_id: fixture.session_id,
                session_generation: GENERATION,
                action_id: action_id.clone(),
                action_revision: SealedActionRevision::new(1).expect("revision"),
                issued_at_ms: 1_000,
                expires_at_ms: None,
            },
        )
        .await
        .expect("live grant");

    let active =
        active_sealed_value_ids(&fixture.db, &registry, fixture.session_id, GENERATION, NOW)
            .await
            .expect("derive active");
    assert!(
        active.contains(&sealed_scoped_active_key(&seeded.record_id.to_string(), 1)),
        "a live exact grant activates its record id at the granted version"
    );

    let table = sealed_table(seeded.record_id);
    let untrusted = untrusted_model(table.clone());
    let body = prepared_body(&untrusted, &active);
    assert!(
        body.contains(&marker),
        "the exact actionable marker reaches the wire: {body}"
    );
    assert!(
        !body.contains(TEST_LITERAL),
        "zero literal bytes on the wire: {body}"
    );

    // (d) The identical message on a TRUSTED target is reference-only too.
    let trusted = trusted_model(table.clone());
    let trusted_history = [Message::user(format!("the deploy token is {TEST_LITERAL}"))];
    let trusted_prepared = trusted
        .prepare_completion_request(
            crate::engine::model::AgentPromptParts::new("system", &trusted_history),
            &Message::user("proceed"),
            &[],
            &ModelParams::default(),
            false,
            Some(&trusted.redact_table().with_sealed_replacements(&active)),
        )
        .expect("prepared trusted request");
    let trusted_body = serde_json::to_string(&trusted_prepared.captured).expect("serialize");
    assert!(
        !trusted_body.contains(TEST_LITERAL),
        "trusted completion receives no literal: {trusted_body}"
    );
    assert!(
        trusted_body.contains(&marker),
        "a trusted completion gets the actionable reference marker"
    );

    // Per attempt: revoke the grant, then re-derive. The set no longer contains
    // the record, and the untrusted wire renders the generic placeholder — not a
    // stale marker, not the literal.
    assert!(
        fixture
            .directory()
            .revoke_action_grant(SealedFixture::owner(), live_grant, NOW - 1)
            .await
            .expect("revoke")
    );
    let after_revoke =
        active_sealed_value_ids(&fixture.db, &registry, fixture.session_id, GENERATION, NOW)
            .await
            .expect("re-derive");
    assert!(
        !after_revoke.contains(&sealed_scoped_active_key(&seeded.record_id.to_string(), 1)),
        "a revoked grant is not active on the later attempt"
    );
    let generic_body = prepared_body(&untrusted, &after_revoke);
    assert!(
        !generic_body.contains(&marker) && !generic_body.contains("reference sealed value"),
        "no stale marker after revocation: {generic_body}"
    );
    assert!(
        !generic_body.contains(TEST_LITERAL),
        "still no literal after revocation: {generic_body}"
    );
    assert!(
        generic_body.contains(untrusted.redact_table().placeholder()),
        "revoked sealed value renders the generic placeholder: {generic_body}"
    );
}

fn use_sealed_value_tool() -> ToolDefinition {
    ToolDefinition {
        name: crate::sealed::USE_SEALED_VALUE_TOOL.to_string(),
        description: "use a sealed value through an owner-compiled action".to_string(),
        parameters: serde_json::json!({ "type": "object", "properties": {} }),
    }
}

fn unrelated_tool() -> ToolDefinition {
    ToolDefinition {
        name: "search".to_string(),
        description: "search".to_string(),
        parameters: serde_json::json!({ "type": "object", "properties": {} }),
    }
}

/// AC8: drive the ACTUAL production chokepoint derivation
/// (`derive_interactive_sealed_egress`, the single seam
/// `turn_phases` calls) end-to-end over real grant rows, so deleting the marker
/// derivation from production fails this test. Proves every gate: (a) live grant
/// → exact marker + zero literal; (b) revoked → generic; (c) no
/// `use_sealed_value` in the roster → generic; (d) trusted target → marker; (e)
/// per-attempt refresh (revoke between attempts → marker then generic).
#[tokio::test]
async fn sealed_marker_reaches_every_model_wire_only_through_production_chokepoint() {
    use crate::sealed::egress::derive_interactive_sealed_egress;

    let fixture = SealedFixture::new().await;
    let seeded = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;
    let probe = Arc::new(ProbeAction::new(1));
    let registry = registry_with(vec![probe as Arc<dyn crate::sealed::SealedHostAction>]);
    let action_id = SealedActionId::parse(PROBE_ACTION).expect("action id");
    let marker = sealed_untrusted_inference_marker(&seeded.record_id.to_string());
    let roster = [use_sealed_value_tool()];

    let live_grant = fixture
        .directory()
        .issue_action_grant(
            SealedFixture::owner(),
            IssueSealedGrant {
                record_id: seeded.record_id,
                value_version: 1,
                project_key: fixture.project_key.clone(),
                session_id: fixture.session_id,
                session_generation: GENERATION,
                action_id: action_id.clone(),
                action_revision: SealedActionRevision::new(1).expect("revision"),
                issued_at_ms: 1_000,
                expires_at_ms: None,
            },
        )
        .await
        .expect("live grant");

    let table = sealed_table(seeded.record_id);
    let untrusted = untrusted_model(table.clone());

    // (a) Every gate holds → the production seam returns the marker table.
    let egress = derive_interactive_sealed_egress(
        &untrusted,
        true,
        &roster,
        &fixture.db,
        &registry,
        fixture.session_id,
        GENERATION,
        NOW,
    )
    .await
    .expect("live grant + all gates → a derived marker table");
    let scrubbed = egress.scrub(TEST_LITERAL);
    assert!(
        scrubbed.contains(&marker),
        "the exact actionable marker is derived: {scrubbed}"
    );
    assert!(
        !scrubbed.contains(TEST_LITERAL),
        "zero literal bytes: {scrubbed}"
    );

    // (c) The SAME live grant but no `use_sealed_value` in the roster → the seam
    // returns None (generic), so removing the tool-roster gate would leak a
    // marker to a request that cannot act on it.
    assert!(
        derive_interactive_sealed_egress(
            &untrusted,
            true,
            &[unrelated_tool()],
            &fixture.db,
            &registry,
            fixture.session_id,
            GENERATION,
            NOW,
        )
        .await
        .is_none(),
        "a roster without use_sealed_value renders generic"
    );

    // Non-interactive with a live grant and the tool present → None.
    assert!(
        derive_interactive_sealed_egress(
            &untrusted,
            false,
            &roster,
            &fixture.db,
            &registry,
            fixture.session_id,
            GENERATION,
            NOW,
        )
        .await
        .is_none(),
        "a non-interactive request renders generic"
    );

    // (d) A trusted target gets the same reference-only marker table.
    let trusted = trusted_model(table.clone());
    assert!(
        derive_interactive_sealed_egress(
            &trusted,
            true,
            &roster,
            &fixture.db,
            &registry,
            fixture.session_id,
            GENERATION,
            NOW,
        )
        .await
        .is_some(),
        "a trusted target derives the same marker table"
    );

    // (b)/(e) Per-attempt refresh: revoke the grant, then re-derive — the seam
    // now returns None (generic), proving the derivation is fresh per attempt.
    assert!(
        fixture
            .directory()
            .revoke_action_grant(SealedFixture::owner(), live_grant, NOW - 1)
            .await
            .expect("revoke")
    );
    assert!(
        derive_interactive_sealed_egress(
            &untrusted,
            true,
            &roster,
            &fixture.db,
            &registry,
            fixture.session_id,
            GENERATION,
            NOW,
        )
        .await
        .is_none(),
        "a revoked grant renders generic on the later attempt"
    );
}

#[tokio::test]
async fn sealed_marker_derivation_rejects_expired_and_wrong_version_grants() {
    let fixture = SealedFixture::new().await;
    let seeded = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;
    let probe = Arc::new(ProbeAction::new(1));
    let registry = registry_with(vec![probe as Arc<dyn crate::sealed::SealedHostAction>]);
    let action_id = SealedActionId::parse(PROBE_ACTION).expect("action id");

    // An expired grant: `expires_at_ms <= now` is inactive.
    fixture
        .directory()
        .issue_action_grant(
            SealedFixture::owner(),
            IssueSealedGrant {
                record_id: seeded.record_id,
                value_version: 1,
                project_key: fixture.project_key.clone(),
                session_id: fixture.session_id,
                session_generation: GENERATION,
                action_id: action_id.clone(),
                action_revision: SealedActionRevision::new(1).expect("revision"),
                issued_at_ms: 1_000,
                expires_at_ms: Some(NOW - 1),
            },
        )
        .await
        .expect("expired grant");
    let active =
        active_sealed_value_ids(&fixture.db, &registry, fixture.session_id, GENERATION, NOW)
            .await
            .expect("derive active");
    assert!(
        !active.contains(&sealed_scoped_active_key(&seeded.record_id.to_string(), 1)),
        "an expired grant does not activate its record"
    );

    // A wrong-version grant (pinned to a version the record does not have as its
    // active version) is inactive.
    let other = SealedFixture::new().await;
    let seeded2 = other
        .seed_value(
            SealedScopeRef::Project(other.project_key.clone()),
            "deploy_token",
        )
        .await;
    other
        .directory()
        .issue_action_grant(
            SealedFixture::owner(),
            IssueSealedGrant {
                record_id: seeded2.record_id,
                value_version: 2, // record's active version is 1
                project_key: other.project_key.clone(),
                session_id: other.session_id,
                session_generation: GENERATION,
                action_id,
                action_revision: SealedActionRevision::new(1).expect("revision"),
                issued_at_ms: 1_000,
                expires_at_ms: None,
            },
        )
        .await
        .expect("wrong-version grant");
    let active2 = active_sealed_value_ids(&other.db, &registry, other.session_id, GENERATION, NOW)
        .await
        .expect("derive active");
    assert!(
        !active2.contains(&sealed_scoped_active_key(&seeded2.record_id.to_string(), 1))
            && !active2.contains(&sealed_scoped_active_key(&seeded2.record_id.to_string(), 2)),
        "a version-mismatched grant does not activate its record"
    );

    // No grant at all → empty active set.
    let none = SealedFixture::new().await;
    let seeded3 = none
        .seed_value(
            SealedScopeRef::Project(none.project_key.clone()),
            "deploy_token",
        )
        .await;
    let active3 = active_sealed_value_ids(&none.db, &registry, none.session_id, GENERATION, NOW)
        .await
        .expect("derive active");
    assert!(
        !active3.contains(&sealed_scoped_active_key(&seeded3.record_id.to_string(), 1)),
        "an ungranted record is never active"
    );
}

/// A scoped sealed redaction table over `record_id` at a specific `version`,
/// holding [`TEST_LITERAL`]. Used to prove the active-set key is version-bound.
fn sealed_table_at_version(
    record_id: crate::sealed::identity::SealedRecordId,
    version: u32,
) -> Arc<RedactionTable> {
    let identity = SealedRedactionIdentity {
        scope: SealedScopeKind::Project,
        record_id: Some(record_id),
        name: SealedName::canonical("deploy_token").expect("name"),
        version,
    };
    Arc::new(
        RedactionTable::empty()
            .with_forced_sealed_literal(TEST_LITERAL.to_string(), identity)
            .expect("sealed table"),
    )
}

/// FINDING 1(a): a live grant for version N must NOT activate a persisted entry
/// sealed at a DIFFERENT version of the same record. The record is rotated to
/// version 2, a live exact grant is pinned to version 2, and the active set is
/// derived through the real production path. A table entry sealed at the stale
/// version 1 renders GENERIC (no marker); the positive control — an entry at the
/// current version 2 — renders the marker. Under the pre-fix keying (bare record
/// id, version discarded) the version-1 entry would match the version-2 grant and
/// leak the actionable marker, so this fails against the broken behavior.
#[tokio::test]
async fn sealed_marker_ignores_entry_whose_version_differs_from_the_live_grant() {
    let fixture = SealedFixture::new().await;
    let seeded = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;
    // Publish version 2 as the record's active version.
    let rotated = fixture
        .directory()
        .rotate(
            SealedFixture::owner(),
            seeded.record_id,
            SealedLiteral::new("sk-live-rotated-to-version-two-abc123"),
            2_000,
        )
        .await
        .expect("rotate to version 2");
    assert_eq!(rotated.version, 2, "rotation publishes version 2");

    let probe = Arc::new(ProbeAction::new(1));
    let registry = registry_with(vec![probe as Arc<dyn crate::sealed::SealedHostAction>]);
    let action_id = SealedActionId::parse(PROBE_ACTION).expect("action id");
    let marker = sealed_untrusted_inference_marker(&seeded.record_id.to_string());

    // A live exact grant pinned to the CURRENT version 2.
    fixture
        .directory()
        .issue_action_grant(
            SealedFixture::owner(),
            IssueSealedGrant {
                record_id: seeded.record_id,
                value_version: 2,
                project_key: fixture.project_key.clone(),
                session_id: fixture.session_id,
                session_generation: GENERATION,
                action_id,
                action_revision: SealedActionRevision::new(1).expect("revision"),
                issued_at_ms: 1_000,
                expires_at_ms: None,
            },
        )
        .await
        .expect("live version-2 grant");

    let active =
        active_sealed_value_ids(&fixture.db, &registry, fixture.session_id, GENERATION, NOW)
            .await
            .expect("derive active");
    assert!(
        active.contains(&sealed_scoped_active_key(&seeded.record_id.to_string(), 2)),
        "the live grant activates its record at version 2"
    );
    assert!(
        !active.contains(&sealed_scoped_active_key(&seeded.record_id.to_string(), 1)),
        "the version-2 grant does not activate the version-1 key"
    );

    // A STALE version-1 entry of the same record → GENERIC, never the marker.
    let stale = untrusted_model(sealed_table_at_version(seeded.record_id, 1));
    let stale_body = prepared_untrusted_body(&stale, &active);
    assert!(
        !stale_body.contains(&marker) && !stale_body.contains("reference sealed value"),
        "a stale prior-version entry never activates a later-version grant: {stale_body}"
    );
    assert!(
        stale_body.contains(stale.redact_table().placeholder()),
        "the stale-version entry renders the generic placeholder: {stale_body}"
    );
    assert!(
        !stale_body.contains(TEST_LITERAL),
        "no literal on the untrusted wire: {stale_body}"
    );

    // Positive control: an entry at the CURRENT version 2 DOES render the marker,
    // proving the grant itself is live and the negative above is not vacuous.
    let current = untrusted_model(sealed_table_at_version(seeded.record_id, 2));
    let current_body = prepared_untrusted_body(&current, &active);
    assert!(
        current_body.contains(&marker),
        "the current-version entry renders the actionable marker: {current_body}"
    );
    assert!(
        !current_body.contains(TEST_LITERAL),
        "no literal on the untrusted wire: {current_body}"
    );
}

/// FINDING 1(b): a live grant for record R must NOT activate a LEGACY (pre-
/// scoping) session entry that merely shares R's canonical name but belongs to a
/// DIFFERENT record. The grant is derived through the real production path; a
/// legacy entry (no record id, version 0) named `deploy_token` renders GENERIC.
/// Under the pre-fix keying the grant inserted the bare canonical name into the
/// active set and the legacy entry matched it, leaking a marker for an unrelated
/// value — so this fails against the broken behavior.
#[tokio::test]
async fn sealed_marker_ignores_legacy_same_name_entry_of_a_different_record() {
    let fixture = SealedFixture::new().await;
    let seeded = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;
    let probe = Arc::new(ProbeAction::new(1));
    let registry = registry_with(vec![probe as Arc<dyn crate::sealed::SealedHostAction>]);
    let action_id = SealedActionId::parse(PROBE_ACTION).expect("action id");

    fixture
        .directory()
        .issue_action_grant(
            SealedFixture::owner(),
            IssueSealedGrant {
                record_id: seeded.record_id,
                value_version: 1,
                project_key: fixture.project_key.clone(),
                session_id: fixture.session_id,
                session_generation: GENERATION,
                action_id,
                action_revision: SealedActionRevision::new(1).expect("revision"),
                issued_at_ms: 1_000,
                expires_at_ms: None,
            },
        )
        .await
        .expect("live grant for record R");

    let active =
        active_sealed_value_ids(&fixture.db, &registry, fixture.session_id, GENERATION, NOW)
            .await
            .expect("derive active");
    assert!(
        active.contains(&sealed_scoped_active_key(&seeded.record_id.to_string(), 1)),
        "the grant activates record R at version 1"
    );
    // The legacy version-scoped key the grant contributes is at the grant's
    // version (1) — a legacy entry is version 0, so it can never match.
    assert!(
        !active.contains(&sealed_legacy_active_key("deploy_token", 0)),
        "the grant contributes no version-0 legacy key a legacy entry could match"
    );

    // A LEGACY entry (no record id, version 0) that merely shares the name
    // `deploy_token` but is a DIFFERENT, pre-scoping registration → GENERIC.
    let legacy_identity = SealedRedactionIdentity {
        scope: SealedScopeKind::Session,
        record_id: None,
        name: SealedName::canonical("deploy_token").expect("name"),
        version: 0,
    };
    let table = Arc::new(
        RedactionTable::empty()
            .with_forced_sealed_literal(TEST_LITERAL.to_string(), legacy_identity)
            .expect("legacy sealed table"),
    );
    let model = untrusted_model(table);
    let body = prepared_untrusted_body(&model, &active);
    assert!(
        !body.contains("reference sealed value"),
        "a legacy same-name entry of a different record never activates a scoped grant: {body}"
    );
    assert!(
        body.contains(model.redact_table().placeholder()),
        "the legacy same-name entry renders the generic placeholder: {body}"
    );
    assert!(
        !body.contains(TEST_LITERAL),
        "no literal on the untrusted wire: {body}"
    );
}
