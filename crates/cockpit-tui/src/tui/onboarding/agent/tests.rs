//! Reducer and render tests for the nested agent authoring editor.

use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;

use cockpit_proto::{
    AGENT_AUTHORING_DTO_VERSION, AgentAuthoringCatalogOrigin, AgentAuthoringCompatibleRoute,
    AgentAuthoringProjection, AgentAuthoringSource, AgentAuthoringSourceKind, AgentPolicyRoute,
    AgentPolicySnapshot, AgentPolicyTrustClassification, ApplyAuthoredAgentPackageOutcome,
    AuthoredAgentReview, AuthoredAgentReviewGrant,
};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn sample_projection(revision: &str) -> AgentAuthoringProjection {
    AgentAuthoringProjection {
        dto_version: AGENT_AUTHORING_DTO_VERSION,
        policy: AgentPolicySnapshot {
            policy_revision: revision.into(),
            routes: vec![
                AgentPolicyRoute {
                    provider_id: "vendor".into(),
                    model_id: "exact-a".into(),
                    trust: AgentPolicyTrustClassification::Unset,
                    confirmation_required: true,
                    trust_is_shared: true,
                    capabilities: vec!["text_generation".into()],
                    location: Some("remote".into()),
                    auto_prune: false,
                    sidecar_eligible: false,
                    remote_sidecar_egress_required: false,
                },
                AgentPolicyRoute {
                    provider_id: "vendor".into(),
                    model_id: "exact-b".into(),
                    trust: AgentPolicyTrustClassification::Trusted,
                    confirmation_required: false,
                    trust_is_shared: true,
                    capabilities: vec!["text_generation".into()],
                    location: Some("remote".into()),
                    auto_prune: false,
                    sidecar_eligible: false,
                    remote_sidecar_egress_required: false,
                },
            ],
            catalog_origin: AgentAuthoringCatalogOrigin::Cached,
            catalog_revision: "catalog-rev".into(),
            bundled_frontier_slug: "frontier".into(),
        },
        sources: vec![AgentAuthoringSource {
            kind: AgentAuthoringSourceKind::BundledFrontier,
            slug: Some("navigator".into()),
            display_name: "Navigator".into(),
            source_locator: Some("catalog/frontier@rev".into()),
            compatible_routes: vec![AgentAuthoringCompatibleRoute {
                provider_id: "vendor".into(),
                model_id: "exact-a".into(),
            }],
            definition_frontmatter_yaml: None,
        }],
        review_trust_disclosure: "Trust classification is shared global provider/model policy."
            .into(),
    }
}

fn sample_review() -> AuthoredAgentReview {
    AuthoredAgentReview {
        agent_name: "navigator".into(),
        grants: vec![AuthoredAgentReviewGrant {
            provider_id: "vendor".into(),
            model_id: "exact-a".into(),
            is_default: true,
            trust: AgentPolicyTrustClassification::Untrusted,
            trust_is_shared: true,
        }],
        tool_tier_preferences: vec![("read".into(), "enabled".into())],
        verification_label: Some("Self-verification (1 rules)".into()),
        interactive_subagents: true,
        goal_skeptics_label: "2 goal skeptics".into(),
        children: vec![],
        sidecars: vec![],
        source: "catalog/frontier@rev".into(),
        trust_is_shared: true,
        trust_disclosure: "Trust classification is shared global provider/model policy.".into(),
    }
}

fn render_string(screen: &mut AgentAuthoringScreen, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| screen.render(frame, frame.area()))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

fn advance_to_subagents(screen: &mut AgentAuthoringScreen) {
    screen.handle_key(key(KeyCode::Enter));
    screen.draft.trust_confirmations[0] = true;
    screen.handle_key(key(KeyCode::Enter));
    while !matches!(screen.phase, Phase::SubagentsList) {
        screen.handle_key(key(KeyCode::Enter));
    }
}

fn advance_to_create(screen: &mut AgentAuthoringScreen) {
    advance_to_subagents(screen);
    screen.apply_outcome(ApplyAuthoredAgentPackageOutcome::Review(sample_review()));
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(screen.phase, Phase::Create));
}

#[test]
fn default_replacement_toggle_on_create_screen() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-1".into());
    advance_to_create(&mut screen);
    assert!(screen.draft.make_default);
    screen.cursor = 0;
    screen.handle_key(key(KeyCode::Char(' ')));
    assert!(!screen.draft.make_default);
}

#[test]
fn back_restores_parent_after_canceling_nested_subagent() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-1".into());
    advance_to_subagents(&mut screen);
    let before = screen.draft.children.len();
    screen.cursor = 0;
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(screen.phase, Phase::SubagentEdit(_)));
    screen.handle_key(key(KeyCode::Esc));
    assert!(matches!(screen.phase, Phase::SubagentsList));
    assert_eq!(screen.draft.children.len(), before);
}

#[test]
fn stale_review_refresh_after_projection_revision_change() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-1".into());
    advance_to_subagents(&mut screen);
    screen.apply_outcome(ApplyAuthoredAgentPackageOutcome::Review(sample_review()));
    assert!(screen.review.is_some());
    screen.replace_projection(sample_projection("rev-b"));
    assert!(screen.review.is_none());
    assert!(matches!(screen.phase, Phase::Review));
    assert!(
        screen
            .status
            .as_deref()
            .is_some_and(|status| status.contains("stale"))
    );
}

#[test]
fn trust_gate_blocks_advance_until_confirmed() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-1".into());
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(screen.phase, Phase::ModelGrants));
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(screen.phase, Phase::ModelTrust));
    screen.handle_key(key(KeyCode::Enter));
    assert!(
        screen
            .status
            .as_deref()
            .is_some_and(|status| status.contains("Confirm trust"))
    );
    screen.cursor = 0;
    screen.handle_key(key(KeyCode::Char(' ')));
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(screen.phase, Phase::Optimizations));
}

#[test]
fn review_render_matches_canonical_projection_without_secrets() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-1".into());
    let review = sample_review();
    screen.apply_outcome(ApplyAuthoredAgentPackageOutcome::Review(review.clone()));
    let rendered = render_string(&mut screen, 100, 30);
    assert!(rendered.contains("navigator"));
    assert!(rendered.contains("vendor/exact-a"));
    assert!(rendered.contains("2 goal skeptics"));
    assert!(rendered.contains("shared global provider/model policy"));
    for secret in [
        "api_key",
        "apiKey",
        "password",
        "passphrase",
        "credential",
        "profile_handle",
        "profileHandle",
    ] {
        assert!(!rendered.contains(secret), "render leaked `{secret}`");
    }
}

#[test]
fn preview_action_is_emitted_from_review() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-1".into());
    advance_to_subagents(&mut screen);
    screen.draft.trust_confirmations[0] = true;
    screen.apply_outcome(ApplyAuthoredAgentPackageOutcome::Review(sample_review()));
    let action = screen.handle_key(key(KeyCode::Char('r')));
    assert!(matches!(
        action,
        Some(AgentAuthoringAction::PreviewPackage(_))
    ));
}

#[test]
fn apply_uses_stable_client_operation_id() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "stable-op".into());
    advance_to_create(&mut screen);
    let action = screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        action,
        Some(AgentAuthoringAction::ApplyPackage {
            client_operation_id,
            ..
        }) if client_operation_id == "stable-op"
    ));
}

#[test]
fn invalid_nested_depth_surfaces_canonical_failure() {
    let mut projection = sample_projection("rev-a");
    projection.policy.routes = vec![AgentPolicyRoute {
        provider_id: "vendor".into(),
        model_id: "exact-a".into(),
        trust: AgentPolicyTrustClassification::Trusted,
        confirmation_required: false,
        trust_is_shared: true,
        capabilities: vec!["text_generation".into()],
        location: Some("remote".into()),
        auto_prune: false,
        sidecar_eligible: false,
        remote_sidecar_egress_required: false,
    }];
    let mut screen = AgentAuthoringScreen::new(projection, "op-depth".into());
    advance_to_subagents(&mut screen);
    screen.draft.children = vec![
        cockpit_core::authoring_draft::ChildAuthoringDraft {
            name: "child-a".into(),
            route_grants: vec![cockpit_core::authoring_draft::RouteGrantDraft { enabled: true }],
            default_route_index: 0,
            tool_tiers: Default::default(),
        },
        cockpit_core::authoring_draft::ChildAuthoringDraft {
            name: "child-a".into(),
            route_grants: vec![cockpit_core::authoring_draft::RouteGrantDraft { enabled: true }],
            default_route_index: 0,
            tool_tiers: Default::default(),
        },
    ];
    screen.cursor = screen.draft.children.len() + 1;
    screen.handle_key(key(KeyCode::Enter));
    assert!(
        screen
            .status
            .as_deref()
            .is_some_and(|status| !status.is_empty()),
        "duplicate child names must surface a canonical validation failure"
    );
}
