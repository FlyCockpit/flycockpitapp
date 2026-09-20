//! Reducer and render tests for the nested agent authoring editor.

use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Position;

use cockpit_core::authoring_draft::build_package_draft;
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
        make_default: true,
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

fn render_buffer(screen: &mut AgentAuthoringScreen, width: u16, height: u16) -> Buffer {
    crate::tui::golden::render_frame(width, height, |frame| {
        screen.render(frame, frame.area());
    })
}

fn click_at(position: Position) -> crossterm::event::MouseEvent {
    crossterm::event::MouseEvent {
        kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
        column: position.x,
        row: position.y,
        modifiers: KeyModifiers::NONE,
    }
}

fn click_action(screen: &mut AgentAuthoringScreen, index: usize) {
    let rect = screen.actions.rects()[index];
    assert!(rect.width > 0, "action {index} must have a hit target");
    assert!(screen.handle_mouse(click_at(Position::new(rect.x, rect.y))));
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
fn model_grant_toggle_replaces_disabled_default() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-1".into());
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(screen.phase, Phase::ModelGrants));
    screen.cursor = 1;
    screen.handle_key(key(KeyCode::Char(' ')));
    assert!(screen.draft.route_grants[0].enabled);
    assert!(screen.draft.route_grants[1].enabled);
    screen.cursor = 0;
    screen.handle_key(key(KeyCode::Char(' ')));
    assert!(!screen.draft.route_grants[0].enabled);
    assert!(screen.draft.route_grants[1].enabled);
    assert_eq!(screen.draft.default_route_index, 1);
}

#[test]
fn model_grant_toggle_refuses_disabling_sole_enabled_default() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-1".into());
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(screen.phase, Phase::ModelGrants));
    screen.cursor = 0;
    screen.handle_key(key(KeyCode::Char(' ')));
    assert!(screen.draft.route_grants[0].enabled);
    assert_eq!(screen.draft.default_route_index, 0);
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
            trust_confirmations: vec![false],
            tool_tiers: Default::default(),
            children: vec![],
        },
        cockpit_core::authoring_draft::ChildAuthoringDraft {
            name: "child-a".into(),
            route_grants: vec![cockpit_core::authoring_draft::RouteGrantDraft { enabled: true }],
            default_route_index: 0,
            trust_confirmations: vec![false],
            tool_tiers: Default::default(),
            children: vec![],
        },
    ];
    let error = build_package_draft(&screen.projection, &screen.draft)
        .expect_err("duplicate child names must fail canonical package construction");
    assert!(
        error.to_string().contains("duplicate child name"),
        "expected duplicate child validation, got: {error}"
    );
}

#[test]
fn model_gated_tool_stays_off_until_its_inline_model_is_chosen() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-tools".into());
    screen.phase = Phase::ToolTiers;
    let catalog = tool_surface_catalog();
    let tool_index = catalog
        .iter()
        .position(|item| item.name == "transcribe_audio")
        .expect("model-gated transcription tool must be in the catalog");
    screen.cursor = tool_presentation_order()
        .iter()
        .position(|index| *index == tool_index)
        .expect("model-gated tool must be presented");
    assert_eq!(
        screen.draft.tool_tiers["transcribe_audio"],
        cockpit_core::agents::ToolTier::Disabled,
        "model-gated tools must start disabled"
    );

    screen.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(
        screen.draft.tool_tiers["transcribe_audio"],
        cockpit_core::agents::ToolTier::Disabled,
        "opening the picker must not grant the tool"
    );
    let picker = render_string(&mut screen, 120, 40);
    assert!(picker.contains("Choose a model for this tool"), "{picker}");
    assert!(picker.contains(" Models "), "{picker}");

    screen.handle_key(key(KeyCode::Enter));
    assert_eq!(
        screen.draft.tool_tiers["transcribe_audio"],
        cockpit_core::agents::ToolTier::Enabled
    );
    let inline = render_string(&mut screen, 120, 40);
    assert!(
        inline.contains("transcribe_audio") && inline.contains("vendor/exact-a"),
        "the selected model must render on the tool row: {inline}"
    );
}

#[test]
fn tools_are_grouped_and_required_tools_cannot_be_disabled() {
    let catalog = tool_surface_catalog();
    let order = tool_presentation_order();
    let sections = order
        .iter()
        .map(|index| tool_section(&catalog[*index]))
        .collect::<Vec<_>>();
    assert!(
        sections.windows(2).all(|pair| pair[0] <= pair[1]),
        "tool sections must be required, suggested, then not suggested: {sections:?}"
    );

    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-tools".into());
    screen.phase = Phase::ToolTiers;
    let read_index = catalog
        .iter()
        .position(|item| item.name == "read")
        .expect("read must remain in the tool catalog");
    screen.cursor = order
        .iter()
        .position(|index| *index == read_index)
        .expect("read must remain in the presentation order");
    assert_eq!(screen.draft.tool_tiers["read"], ToolTier::Enabled);
    screen.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(
        screen.draft.tool_tiers["read"],
        ToolTier::Enabled,
        "the required read tool must remain enabled after activation"
    );
}

#[test]
fn model_tool_optimization_and_subagent_rows_activate_on_first_click() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "click-op".into());

    screen.phase = Phase::ModelGrants;
    render_buffer(&mut screen, 120, 40);
    let second_model = screen.list_row_rects[1];
    assert!(screen.handle_mouse(click_at(Position::new(second_model.x, second_model.y))));
    assert!(screen.draft.route_grants[1].enabled);

    screen.phase = Phase::Optimizations;
    let interactive_before = screen.draft.interactive_subagents;
    render_buffer(&mut screen, 120, 40);
    let optimization = screen.list_row_rects[0];
    assert!(screen.handle_mouse(click_at(Position::new(optimization.x, optimization.y))));
    assert_ne!(screen.draft.interactive_subagents, interactive_before);

    screen.phase = Phase::ToolTiers;
    render_buffer(&mut screen, 120, 40);
    let tool_row = screen
        .list_row_indices
        .iter()
        .position(|logical| {
            let index = tool_presentation_order()[*logical];
            tool_surface_catalog()[index].name == "context_pack"
        })
        .expect("context_pack must have a visible hit target at 120x40");
    let tool_rect = screen.list_row_rects[tool_row];
    assert!(screen.handle_mouse(click_at(Position::new(tool_rect.x, tool_rect.y))));
    assert_ne!(screen.draft.tool_tiers["context_pack"], ToolTier::Disabled);

    screen.phase = Phase::SubagentsList;
    render_buffer(&mut screen, 120, 40);
    let runner = screen.list_row_rects[0];
    assert!(screen.handle_mouse(click_at(Position::new(runner.x, runner.y))));
    assert!(matches!(
        screen.phase,
        Phase::SubagentEdit(SubagentPhase::Identity)
    ));
}

#[test]
fn mouse_only_authoring_keeps_runner_and_submits_it() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "mouse-op".into());
    assert_eq!(screen.draft.children.len(), 1);
    assert_eq!(screen.draft.children[0].name, "runner");

    for expected in [Phase::ModelGrants, Phase::ModelTrust] {
        render_buffer(&mut screen, 120, 40);
        click_action(&mut screen, 0);
        assert_eq!(screen.phase, expected);
    }

    render_buffer(&mut screen, 120, 40);
    let trust = screen.list_row_rects[0];
    assert!(screen.handle_mouse(click_at(Position::new(trust.x, trust.y))));
    assert!(!screen.draft.trust_confirmations[0]);
    assert!(screen.handle_mouse(click_at(Position::new(trust.x, trust.y))));
    assert!(screen.draft.trust_confirmations[0]);
    click_action(&mut screen, 0);
    assert_eq!(screen.phase, Phase::Optimizations);

    for expected in [Phase::ToolTiers, Phase::SubagentsList] {
        render_buffer(&mut screen, 120, 40);
        click_action(&mut screen, 0);
        assert_eq!(screen.phase, expected);
    }
    let subagents = render_string(&mut screen, 120, 40);
    assert!(subagents.contains("runner"), "{subagents}");
    render_buffer(&mut screen, 120, 40);
    click_action(&mut screen, 1);
    let Some(AgentAuthoringAction::PreviewPackage(package)) = screen.take_pending_action() else {
        panic!("mouse Continue must request the canonical preview");
    };
    assert_eq!(package.children.len(), 1);
    assert!(
        package.children[0].relative_path.contains("runner"),
        "runner must survive into the child package path: {:?}",
        package.children[0].relative_path
    );
    assert!(
        package.children[0].markdown.contains("`runner` subagent"),
        "runner must survive into canonical child markdown"
    );
}

fn golden_screen(phase: Phase) -> AgentAuthoringScreen {
    let mut screen = AgentAuthoringScreen::new(sample_projection("golden-rev"), "golden-op".into());
    if let Phase::SubagentEdit(subphase) = phase {
        screen.begin_edit_subagent(0);
        screen.phase = Phase::SubagentEdit(subphase);
    } else {
        screen.phase = phase;
    }
    if phase == Phase::Review {
        screen.review = Some(sample_review());
    }
    if matches!(phase, Phase::Conflict | Phase::Unknown) {
        screen.status = Some(
            match phase {
                Phase::Conflict => "Policy revision conflict — review the refreshed projection.",
                Phase::Unknown => "Create outcome unknown — query the receipt before retrying.",
                _ => unreachable!(),
            }
            .into(),
        );
    }
    screen
}

#[test]
fn golden_agent_authoring_all_twenty_states() {
    let _pins = crate::tui::golden::GoldenPins::install();
    let states = [
        ("name", Phase::SourceIdentity),
        ("third-party-locator", Phase::ThirdPartyLocator),
        ("third-party-trust", Phase::ThirdPartyTrust),
        ("models", Phase::ModelGrants),
        ("trust", Phase::ModelTrust),
        ("sidecar-egress", Phase::SidecarEgress),
        ("optimizations", Phase::Optimizations),
        ("tools", Phase::ToolTiers),
        ("subagents", Phase::SubagentsList),
        (
            "subagent-identity",
            Phase::SubagentEdit(SubagentPhase::Identity),
        ),
        (
            "subagent-models",
            Phase::SubagentEdit(SubagentPhase::ModelGrants),
        ),
        (
            "subagent-trust",
            Phase::SubagentEdit(SubagentPhase::ModelTrust),
        ),
        (
            "subagent-tools",
            Phase::SubagentEdit(SubagentPhase::ToolTiers),
        ),
        (
            "subagent-children",
            Phase::SubagentEdit(SubagentPhase::SubagentsList),
        ),
        ("review", Phase::Review),
        ("create", Phase::Create),
        ("pending", Phase::Pending),
        ("conflict", Phase::Conflict),
        ("unknown", Phase::Unknown),
        ("success", Phase::Success),
    ];
    assert_eq!(states.len(), 20);
    for (name, phase) in states {
        let mut screen = golden_screen(phase);
        crate::tui::golden::assert_golden_sizes("onboarding-agent", name, |width, height| {
            render_buffer(&mut screen, width, height)
        });
    }
}
