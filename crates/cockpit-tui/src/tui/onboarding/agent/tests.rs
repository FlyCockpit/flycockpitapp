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
    AuthoredAgentReview, AuthoredAgentReviewAdjudicator, AuthoredAgentReviewGrant,
    AuthoredAgentReviewVerificationSurface,
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
        auto_prune: false,
        max_subagent_recursion: 2,
        tool_steering: "terse".into(),
        goal_skeptics_label: "2 goal skeptics".into(),
        verification_surfaces: vec![AuthoredAgentReviewVerificationSurface {
            surface: "Writes & edits".into(),
            adjudicators: vec![AuthoredAgentReviewAdjudicator {
                provider_id: "vendor".into(),
                model_id: "exact-a".into(),
                copies: 1,
                is_default_model: true,
            }],
            enforcement_note: None,
        }],
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
    let _ = screen.action_bar_click(index);
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
    assert!(
        screen.review.is_none(),
        "changing Create invalidates its preview"
    );
    let rendered = render_string(&mut screen, 120, 40);
    assert!(
        rendered.contains("Make default agent  off"),
        "Create must render the value that Apply will send: {rendered}"
    );
}

#[test]
fn hyphen_is_preserved_in_identity_and_locator_text_fields() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "hyphen-root".into());
    screen.name_field.set("my");
    screen.handle_key(key(KeyCode::Char('-')));
    screen.handle_key(key(KeyCode::Char('p')));
    assert_eq!(screen.name_field.text(), "my-p");

    screen.phase = Phase::ThirdPartyLocator;
    screen.third_party_field.set("registry");
    screen.handle_key(key(KeyCode::Char('-')));
    screen.handle_key(key(KeyCode::Char('p')));
    assert_eq!(screen.third_party_field.text(), "registry-p");

    screen.begin_edit_subagent(0);
    screen.name_field.set("child");
    screen.handle_key(key(KeyCode::Char('-')));
    assert_eq!(screen.name_field.text(), "child-");
}

#[test]
fn child_optimization_back_restores_pending_model_trust() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "child-trust".into());
    screen.begin_edit_subagent(0);
    screen
        .editing_child
        .as_mut()
        .expect("child editor")
        .trust_confirmations[0] = false;
    screen.phase = Phase::SubagentEdit(SubagentPhase::Optimizations);

    screen.handle_key(key(KeyCode::Esc));

    assert_eq!(screen.phase, Phase::SubagentEdit(SubagentPhase::ModelTrust));
}

#[test]
fn self_verify_and_panel_done_restore_the_opening_rows() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "restore-focus".into());
    screen.phase = Phase::SelfVerify;
    screen.cursor = 2;
    screen.handle_key(key(KeyCode::Esc));
    assert_eq!(screen.phase, Phase::Optimizations);
    assert_eq!(screen.cursor, 5);

    screen.phase = Phase::SelfVerify;
    screen.cursor = 1;
    screen.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(screen.phase, Phase::VerifierPanel(1));
    screen.handle_key(key(KeyCode::Enter));
    assert_eq!(screen.phase, Phase::SelfVerify);
    assert_eq!(screen.cursor, 1);
}

#[test]
fn child_self_verify_edits_the_child_draft_only() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "child-verify".into());
    let root = screen.draft.self_verification[1].copies.clone();
    screen.begin_edit_subagent(0);
    screen.phase = Phase::SubagentEdit(SubagentPhase::Optimizations);
    screen.cursor = 5;
    screen.handle_key(key(KeyCode::Char(' ')));
    screen.cursor = 1;
    screen.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(screen.phase, Phase::VerifierPanel(1));
    screen.cursor = 0;
    screen.handle_key(key(KeyCode::Char('+')));

    assert_eq!(screen.draft.self_verification[1].copies, root);
    assert_eq!(
        screen
            .current_child()
            .expect("child editor")
            .self_verification[1]
            .copies[0],
        1
    );
}

#[test]
fn back_restores_parent_after_canceling_nested_subagent() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-1".into());
    advance_to_subagents(&mut screen);
    let before = screen.draft.children.len();
    screen.cursor = 0;
    screen.handle_key(key(KeyCode::Char('e')));
    assert!(matches!(screen.phase, Phase::SubagentEdit(_)));
    screen.handle_key(key(KeyCode::Esc));
    assert!(matches!(screen.phase, Phase::SubagentsList));
    assert_eq!(screen.draft.children.len(), before);
}

#[test]
fn canceling_nested_subagent_restores_its_parent_editor_without_the_new_child() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "nested-cancel".into());
    advance_to_subagents(&mut screen);
    screen.begin_edit_subagent(0);
    screen.phase = Phase::SubagentEdit(SubagentPhase::SubagentsList);
    screen.cursor = 0;
    screen.handle_key(key(KeyCode::Char(' ')));
    assert!(matches!(
        screen.phase,
        Phase::SubagentEdit(SubagentPhase::Identity)
    ));
    assert_eq!(screen.subagent_stack.len(), 2);

    screen.handle_key(key(KeyCode::Esc));

    assert!(matches!(
        screen.phase,
        Phase::SubagentEdit(SubagentPhase::SubagentsList)
    ));
    assert_eq!(screen.subagent_stack.len(), 1, "runner edit stays active");
    assert_eq!(
        screen
            .editing_child
            .as_ref()
            .expect("parent editor must be restored")
            .name,
        "runner"
    );
    assert!(
        screen.draft.children[0].children.is_empty(),
        "cancel must discard the uncommitted nested helper"
    );
}

fn advance_subagent_to_helpers(screen: &mut AgentAuthoringScreen) {
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        screen.phase,
        Phase::SubagentEdit(SubagentPhase::ModelGrants)
    ));
    screen.handle_key(key(KeyCode::Enter));
    if matches!(screen.phase, Phase::SubagentEdit(SubagentPhase::ModelTrust)) {
        screen.handle_key(key(KeyCode::Char(' ')));
        screen.handle_key(key(KeyCode::Enter));
    }
    assert!(matches!(
        screen.phase,
        Phase::SubagentEdit(SubagentPhase::Optimizations)
    ));
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        screen.phase,
        Phase::SubagentEdit(SubagentPhase::ToolTiers)
    ));
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        screen.phase,
        Phase::SubagentEdit(SubagentPhase::SubagentsList)
    ));
}

#[test]
fn saving_added_subagent_appends_it_to_the_root_draft() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "root-add".into());
    advance_to_subagents(&mut screen);
    let initial_children = screen.draft.children.len();

    screen.handle_key(key(KeyCode::Char('a')));
    for _ in "runner".chars() {
        screen.handle_key(key(KeyCode::Backspace));
    }
    screen.paste("reviewer");
    advance_subagent_to_helpers(&mut screen);
    screen.handle_key(key(KeyCode::Enter));

    assert!(matches!(screen.phase, Phase::SubagentsList));
    assert_eq!(screen.draft.children.len(), initial_children + 1);
    assert_eq!(
        screen
            .draft
            .children
            .last()
            .map(|child| child.name.as_str()),
        Some("reviewer")
    );
}

#[test]
fn saving_added_nested_subagent_preserves_the_parent_editor() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "nested-add".into());
    advance_to_subagents(&mut screen);
    screen.begin_edit_subagent(0);
    for _ in "runner".chars() {
        screen.handle_key(key(KeyCode::Backspace));
    }
    screen.paste("coordinator");
    advance_subagent_to_helpers(&mut screen);
    assert!(matches!(
        screen.phase,
        Phase::SubagentEdit(SubagentPhase::SubagentsList)
    ));

    screen.cursor = 0;
    screen.handle_key(key(KeyCode::Char(' ')));
    for _ in "helper".chars() {
        screen.handle_key(key(KeyCode::Backspace));
    }
    screen.paste("reviewer");
    advance_subagent_to_helpers(&mut screen);
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        screen.phase,
        Phase::SubagentEdit(SubagentPhase::SubagentsList)
    ));
    screen.handle_key(key(KeyCode::Enter));

    assert!(matches!(screen.phase, Phase::SubagentsList));
    assert_eq!(screen.draft.children[0].name, "coordinator");
    assert_eq!(screen.draft.children[0].children.len(), 1);
    assert_eq!(screen.draft.children[0].children[0].name, "reviewer");
}

#[test]
fn tool_model_selection_is_scoped_to_the_draft_being_edited() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "tool-scope".into());
    let tool_index = screen
        .tool_catalog
        .iter()
        .position(|item| item.name == "transcribe_audio")
        .expect("model-gated tool");
    let cursor = tool_presentation_order(&screen.tool_catalog)
        .iter()
        .position(|index| *index == tool_index)
        .expect("model-gated tool must be visible");

    screen.phase = Phase::ToolTiers;
    screen.cursor = cursor;
    screen.handle_key(key(KeyCode::Char(' ')));
    screen.handle_key(key(KeyCode::Enter));
    assert_eq!(screen.draft.tool_models["transcribe_audio"], 0);

    screen.begin_edit_subagent(0);
    screen.phase = Phase::SubagentEdit(SubagentPhase::ToolTiers);
    screen.cursor = cursor;
    let child_before = render_string(&mut screen, 120, 40);
    assert!(
        child_before.contains("transcribe_audio") && child_before.contains("choose model"),
        "the child must not render its parent's model choice: {child_before}"
    );
    screen.handle_key(key(KeyCode::Char(' ')));
    assert!(
        screen.tool_model_picker.is_some(),
        "a child must open its own picker rather than inheriting the parent choice"
    );
    screen.handle_key(key(KeyCode::Down));
    screen.handle_key(key(KeyCode::Enter));
    assert_eq!(
        screen.current_child().expect("child editor").tool_models["transcribe_audio"],
        1
    );
    assert_eq!(screen.draft.tool_models["transcribe_audio"], 0);
}

#[test]
fn stale_review_refresh_after_projection_revision_change() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "op-1".into());
    advance_to_subagents(&mut screen);
    screen.apply_outcome(ApplyAuthoredAgentPackageOutcome::Review(sample_review()));
    assert!(screen.review.is_some());
    assert_eq!(screen.draft.children[0].name, "runner");
    assert_eq!(
        screen.draft.tool_tiers["transcribe_audio"],
        cockpit_core::agents::ToolTier::Disabled,
        "model-gated tool pins must survive until explicitly chosen"
    );
    screen.replace_projection(sample_projection("rev-b"));
    assert!(screen.review.is_none());
    assert!(matches!(screen.phase, Phase::Review));
    assert_eq!(screen.draft.children[0].name, "runner");
    assert_eq!(
        screen.draft.tool_tiers["transcribe_audio"],
        cockpit_core::agents::ToolTier::Disabled
    );
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
    assert!(rendered.contains("Auto-prune  off"));
    assert!(
        !rendered.contains("Auto-prune  off (not yet enforced)"),
        "the enabled runtime setting must not be labeled unsupported"
    );
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
    let mut duplicate = cockpit_core::authoring_draft::default_child_draft(&screen.projection);
    duplicate.name = "child-a".into();
    screen.draft.children = vec![duplicate.clone(), duplicate];
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
    let catalog = &screen.tool_catalog;
    let tool_index = catalog
        .iter()
        .position(|item| item.name == "transcribe_audio")
        .expect("model-gated transcription tool must be in the catalog");
    screen.cursor = tool_presentation_order(catalog)
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
    let order = tool_presentation_order(&catalog);
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
    let auto_prune_before = screen.draft.auto_prune;
    render_buffer(&mut screen, 120, 40);
    let optimization = screen.list_row_rects[0];
    assert!(screen.handle_mouse(click_at(Position::new(optimization.x, optimization.y))));
    assert_ne!(screen.draft.auto_prune, auto_prune_before);

    screen.phase = Phase::ToolTiers;
    render_buffer(&mut screen, 120, 40);
    let tool_row = screen
        .list_row_indices
        .iter()
        .position(|logical| {
            let index = tool_presentation_order(&screen.tool_catalog)[*logical];
            screen.tool_catalog[index].name == "context_pack"
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
fn verifier_panel_keeps_default_model_first_and_labels_cache_reuse() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "panel-order".into());
    screen.draft.default_route_index = 1;
    screen.phase = Phase::VerifierPanel(0);
    assert_eq!(screen.verifier_route_index(0), Some(1));
    assert_eq!(screen.verifier_route_index(1), Some(0));
    screen.draft.self_verification[0].copies[1] = 1;
    let rows = screen.phase_rows();
    let first = &rows[0].1;
    assert_eq!(first.spans[6].content, "Same model");
    assert_eq!(first.spans[7].content, "  reuses cache");
}

#[test]
fn changing_the_default_model_moves_same_model_verification_copies() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "panel-default".into());
    screen.phase = Phase::ModelGrants;
    screen.cursor = 1;
    screen.handle_key(key(KeyCode::Char(' ')));
    screen.handle_key(key(KeyCode::Char('d')));

    assert_eq!(screen.draft.default_route_index, 1);
    assert_eq!(screen.draft.self_verification[0].copies, vec![0, 1]);
    screen.phase = Phase::VerifierPanel(0);
    let rows = screen.phase_rows();
    assert_eq!(screen.verifier_route_index(0), Some(1));
    assert_eq!(rows[0].1.spans[3].content, "×1 ");
    assert_eq!(rows[0].1.spans[6].content, "Same model");
    assert_eq!(rows[0].1.spans[7].content, "  reuses cache");
}

#[test]
fn verifier_minus_at_zero_is_a_no_op_and_surface_off_requires_all_zero() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "panel-zero".into());
    screen.draft.self_verification[1].copies.fill(0);
    assert!(screen.draft.self_verification[1].is_off());
    screen.phase = Phase::VerifierPanel(1);
    render_buffer(&mut screen, 120, 40);
    let first = screen.list_row_rects[0];
    assert!(screen.handle_mouse(click_at(Position::new(first.x + 2, first.y))));
    assert_eq!(screen.draft.self_verification[1].copies, vec![0, 0]);
    screen.adjust_verifier(1, 1, 1);
    assert!(!screen.draft.self_verification[1].is_off());
    screen.adjust_verifier(1, 1, -1);
    assert!(screen.draft.self_verification[1].is_off());
}

#[test]
fn verifier_space_wraps_from_the_copy_cap_to_zero() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "panel-wrap".into());
    screen.phase = Phase::VerifierPanel(0);
    screen.draft.self_verification[0].copies[0] = 9;
    screen.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(screen.draft.self_verification[0].copies[0], 0);
}

#[test]
fn review_row_click_stashes_preview_package() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "preview-click".into());
    advance_to_subagents(&mut screen);
    screen.cursor = screen.draft.children.len();
    render_buffer(&mut screen, 120, 40);
    let review_row = screen.list_row_rects[screen.draft.children.len()];
    assert!(screen.handle_mouse(click_at(Position::new(review_row.x, review_row.y))));
    let action = screen
        .take_pending_action()
        .expect("clicking Review agent package must stash preview intent");
    assert!(matches!(action, AgentAuthoringAction::PreviewPackage(_)));
}

#[test]
fn space_on_review_row_returns_preview_package_immediately() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "preview-space".into());
    advance_to_subagents(&mut screen);
    screen.cursor = screen.draft.children.len();
    let action = screen
        .handle_key(key(KeyCode::Char(' ')))
        .expect("space on Review agent package must emit preview immediately");
    assert!(matches!(action, AgentAuthoringAction::PreviewPackage(_)));
    assert!(screen.take_pending_action().is_none());
}

#[test]
fn nested_subagent_required_tool_lock_does_not_cycle_tier() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "nested-tools".into());
    advance_to_subagents(&mut screen);
    screen.cursor = 0;
    screen.handle_key(key(KeyCode::Char('e')));
    assert!(matches!(
        screen.phase,
        Phase::SubagentEdit(SubagentPhase::Identity)
    ));
    screen.handle_key(key(KeyCode::Enter));
    screen.handle_key(key(KeyCode::Enter));
    while !matches!(screen.phase, Phase::SubagentEdit(SubagentPhase::ToolTiers)) {
        if matches!(screen.phase, Phase::SubagentEdit(SubagentPhase::ModelTrust)) {
            screen.handle_key(key(KeyCode::Char(' ')));
        }
        screen.handle_key(key(KeyCode::Enter));
    }
    let catalog = &screen.tool_catalog;
    let read_index = catalog
        .iter()
        .position(|item| item.name == "read")
        .expect("read tool");
    screen.cursor = tool_presentation_order(catalog)
        .iter()
        .position(|index| *index == read_index)
        .expect("read row");
    let bash_before = screen
        .current_child()
        .expect("nested editor")
        .tool_tiers
        .get("bash")
        .copied()
        .unwrap_or(ToolTier::Disabled);
    screen.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(
        screen.current_child().expect("nested editor").tool_tiers["read"],
        ToolTier::Enabled
    );
    assert_eq!(
        screen
            .current_child()
            .expect("nested editor")
            .tool_tiers
            .get("bash")
            .copied()
            .unwrap_or(ToolTier::Disabled),
        bash_before,
        "required-tool activation must not fall through into tier cycling"
    );
}

#[test]
fn tool_model_picker_click_uses_picker_row_index_after_tools_scroll() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "picker-scroll".into());
    screen.phase = Phase::ToolTiers;
    let catalog = &screen.tool_catalog;
    let tool_index = catalog
        .iter()
        .position(|item| item.name == "transcribe_audio")
        .expect("model-gated tool");
    screen.cursor = tool_presentation_order(catalog)
        .iter()
        .position(|index| *index == tool_index)
        .expect("tool row");
    for _ in 0..4 {
        assert!(screen.handle_mouse(crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        }));
    }
    screen.handle_key(key(KeyCode::Char(' ')));
    render_buffer(&mut screen, 80, 24);
    assert_eq!(screen.model_picker_row_rects.len(), 2);
    let second_route = screen.model_picker_row_rects[1];
    assert!(screen.handle_mouse(click_at(Position::new(second_route.x, second_route.y))));
    assert_eq!(screen.draft.tool_models["transcribe_audio"], 1);
    assert_eq!(
        screen.draft.tool_tiers["transcribe_audio"],
        cockpit_core::agents::ToolTier::Enabled
    );
}

#[test]
fn trust_first_mouse_click_renders_selected_radio() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "trust-radio".into());
    screen.handle_key(key(KeyCode::Enter));
    screen.handle_key(key(KeyCode::Enter));
    assert!(matches!(screen.phase, Phase::ModelTrust));
    render_buffer(&mut screen, 120, 40);
    let trust_row = screen.list_row_rects[0];
    assert!(screen.handle_mouse(click_at(Position::new(trust_row.x, trust_row.y))));
    let rendered = render_string(&mut screen, 120, 40);
    assert!(
        rendered.contains('◉'),
        "first trust click must paint the selected radio before confirmation: {rendered}"
    );
    assert!(!screen.draft.trust_confirmations[0]);
}

#[test]
fn settlement_trust_first_mouse_click_renders_selected_radio() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("settlement-radio"), "op".into());

    screen.phase = Phase::ThirdPartyTrust;
    render_buffer(&mut screen, 120, 40);
    let publisher_trust = screen.list_row_rects[0];
    assert!(screen.handle_mouse(click_at(Position::new(
        publisher_trust.x,
        publisher_trust.y,
    ))));
    assert!(!screen.draft.third_party_trust_confirmed);
    assert!(render_string(&mut screen, 120, 40).contains('◉'));
    assert!(screen.handle_mouse(click_at(Position::new(
        publisher_trust.x,
        publisher_trust.y,
    ))));
    assert!(screen.draft.third_party_trust_confirmed);

    screen.phase = Phase::SidecarEgress;
    screen.draft.sidecar_route_index = Some(0);
    screen.mouse_selected = None;
    render_buffer(&mut screen, 120, 40);
    let sidecar_egress = screen.list_row_rects[0];
    assert!(screen.handle_mouse(click_at(Position::new(sidecar_egress.x, sidecar_egress.y,))));
    assert!(!screen.draft.sidecar_egress_confirmed);
    assert!(render_string(&mut screen, 120, 40).contains('◉'));
    assert!(screen.handle_mouse(click_at(Position::new(sidecar_egress.x, sidecar_egress.y,))));
    assert!(screen.draft.sidecar_egress_confirmed);
}

#[test]
fn runner_keeps_the_safe_default_route_and_lists_its_actual_trust() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("runner-route"), "op".into());
    let runner = &screen.draft.children[0];
    assert!(runner.route_grants[0].enabled);
    assert!(!runner.route_grants[1].enabled);
    assert_eq!(runner.default_route_index, 0);

    screen.phase = Phase::SubagentsList;
    let rendered = render_string(&mut screen, 120, 40);
    assert!(rendered.contains("runner  ·  unset"), "{rendered}");
}

#[test]
fn enter_on_subagents_list_requests_preview_even_with_runner_focused() {
    let mut screen = AgentAuthoringScreen::new(sample_projection("rev-a"), "enter-op".into());
    advance_to_subagents(&mut screen);
    assert_eq!(screen.cursor, 0);
    let action = screen
        .handle_key(key(KeyCode::Enter))
        .expect("Enter must request preview instead of opening the runner editor");
    assert!(matches!(action, AgentAuthoringAction::PreviewPackage(_)));
    assert!(matches!(screen.phase, Phase::SubagentsList));
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
    let action = screen
        .action_bar_click(1)
        .expect("Continue must request the canonical preview");
    let AgentAuthoringAction::PreviewPackage(package) = action else {
        panic!("expected preview package action, got {action:?}");
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

    screen.apply_outcome(ApplyAuthoredAgentPackageOutcome::Review(sample_review()));
    assert_eq!(screen.phase, Phase::Review);
    render_buffer(&mut screen, 120, 40);
    click_action(&mut screen, 0);
    assert_eq!(screen.phase, Phase::Create);
    render_buffer(&mut screen, 120, 40);
    let action = screen
        .action_bar_click(0)
        .expect("Create must emit apply intent");
    let AgentAuthoringAction::ApplyPackage { package, .. } = action else {
        panic!("expected apply package action, got {action:?}");
    };
    assert_eq!(package.children.len(), 1);
    assert!(
        package.children[0].relative_path.contains("runner"),
        "runner must survive through review and create: {:?}",
        package.children[0].relative_path
    );
}

fn golden_screen(phase: Phase) -> AgentAuthoringScreen {
    let mut screen = AgentAuthoringScreen::new(sample_projection("golden-rev"), "golden-op".into());
    screen.tool_catalog = golden_tool_catalog();
    if let Phase::SubagentEdit(subphase) = phase {
        screen.begin_edit_subagent(0);
        let child = screen
            .editing_child
            .as_mut()
            .expect("golden subagent phase must edit the seeded runner");
        child.trust_confirmations[0] = false;
        let child = screen
            .editing_child
            .as_ref()
            .expect("golden subagent phase must edit the seeded runner");
        assert!(child.route_grants[0].enabled);
        assert!(!child.trust_confirmations[0]);
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

/// The onboarding goldens exercise a fixed authoring catalog, not the
/// feature-selected runtime inventory. Keep this list explicit so a new tool
/// (including one behind a feature) cannot change their scroll geometry.
fn golden_tool_catalog() -> Vec<ToolSurfaceItem> {
    const NAMES: &[&str] = &[
        "read",
        "bash",
        "escalate",
        "context_pack",
        "code",
        "graph",
        "search",
        "change_impact",
        "task",
        "skill",
        "skill_manage",
        "question",
        "raise",
        "schedule",
        "spawn",
        "worktree_orchestrate",
        "mcp",
        "webfetch",
        "websearch",
        "lsp",
        "start_build",
        "defer_to_orchestrator",
        "return",
        "harness_list",
        "harness_invoke",
        "history_search",
        "thread_start",
        "semantic_search",
        "structured_search",
        "todo",
        "set_conversation_rule",
        "list_conversation_rules",
        "remove_conversation_rule",
        "write",
        "edit",
        "delete",
        "unlock",
        "grep",
        "glob",
        "list_sealed_value_descriptions",
        "use_sealed_value",
        "acquire_sealed_value",
        "run_acquisition_command",
        "capture_sealed_value",
        "acquisition_requires_user",
        "acquisition_fail",
        "inspect_audio",
        "inspect_video",
        "extract_video_clip",
        "extract_audio",
        "transcribe_audio",
        "read_image",
        "ask_image",
    ];
    let live = tool_surface_catalog();
    NAMES
        .iter()
        .map(|name| {
            live.iter()
                .find(|item| item.name == *name)
                .cloned()
                .expect("every pinned golden tool must remain in the live catalog")
        })
        .collect()
}

fn golden_states() -> [(&'static str, Phase); 22] {
    [
        ("name", Phase::SourceIdentity),
        ("third-party-locator", Phase::ThirdPartyLocator),
        ("third-party-trust", Phase::ThirdPartyTrust),
        ("models", Phase::ModelGrants),
        ("trust", Phase::ModelTrust),
        ("sidecar-egress", Phase::SidecarEgress),
        ("optimizations", Phase::Optimizations),
        ("self-verify", Phase::SelfVerify),
        ("verifier-panel", Phase::VerifierPanel(0)),
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
    ]
}

#[test]
fn golden_agent_authoring_screens() {
    let _pins = crate::tui::golden::GoldenPins::install();
    assert_eq!(golden_tool_catalog().len(), 53);
    let states = golden_states();
    assert_eq!(states.len(), 22);
    for (name, phase) in states {
        let mut screen = golden_screen(phase);
        if phase == Phase::SubagentEdit(SubagentPhase::ModelTrust) {
            let rendered = render_string(&mut screen, 120, 40);
            assert!(
                rendered.contains("Confirm vendor/exact-a as unset") && rendered.contains('○'),
                "nested trust golden must include a confirmable runner route: {rendered}"
            );
        }
        crate::tui::golden::assert_golden_sizes("onboarding-agent", name, |width, height| {
            render_buffer(&mut screen, width, height)
        });
    }
}

#[test]
fn golden_agent_authoring_live_shell_screens() {
    let _pins = crate::tui::golden::GoldenPins::install();
    for (name, phase) in golden_states() {
        crate::tui::golden::assert_golden_sizes(
            "onboarding",
            &format!("agent-authoring-{name}"),
            |width, height| {
                let snapshot = cockpit_proto::OnboardingBootstrapSnapshot {
                    run_id: uuid::Uuid::from_u128(1),
                    attempt_id: uuid::Uuid::from_u128(2),
                    revision: 3,
                    stage: cockpit_proto::OnboardingStage::Agent,
                    bootstrap_state: cockpit_proto::OnboardingBootstrapState::Ready,
                    limited_mode: false,
                    lifetime_selection: None,
                    host_capabilities: cockpit_proto::HostCapabilitySnapshot::unpublished(),
                    last_receipt: None,
                };
                let mut shell = super::super::OnboardingShell::new(&snapshot, false);
                // #432 composition seam: inject a deterministic inner phase
                // so the live shell owns title, help, actions, and content
                // layout. These goldens cover composition, not navigation;
                // the cold first-run PTYs cover the production present path.
                shell.screen =
                    super::super::OnboardingScreen::AgentAuthoring(Box::new(golden_screen(phase)));
                let engine = crate::tui::settings::Dialog::None;
                let mut links = crate::tui::links::LinkRegistry::default();
                crate::tui::golden::render_frame(width, height, |frame| {
                    shell.render(frame, frame.area(), &engine, &mut links);
                })
            },
        );
    }
}

fn optimizations_shell() -> super::super::OnboardingShell {
    let snapshot = cockpit_proto::OnboardingBootstrapSnapshot {
        run_id: uuid::Uuid::from_u128(1),
        attempt_id: uuid::Uuid::from_u128(2),
        revision: 3,
        stage: cockpit_proto::OnboardingStage::Agent,
        bootstrap_state: cockpit_proto::OnboardingBootstrapState::Ready,
        limited_mode: false,
        lifetime_selection: None,
        host_capabilities: cockpit_proto::HostCapabilitySnapshot::unpublished(),
        last_receipt: None,
    };
    let mut shell = super::super::OnboardingShell::new(&snapshot, false);
    shell.screen = super::super::OnboardingScreen::AgentAuthoring(Box::new(golden_screen(
        Phase::Optimizations,
    )));
    shell
}

fn render_shell(shell: &mut super::super::OnboardingShell, width: u16, height: u16) {
    let engine = crate::tui::settings::Dialog::None;
    let mut links = crate::tui::links::LinkRegistry::default();
    crate::tui::golden::render_frame(width, height, |frame| {
        shell.render(frame, frame.area(), &engine, &mut links);
    });
}

fn shell_auto_prune(shell: &super::super::OnboardingShell) -> bool {
    match &shell.screen {
        super::super::OnboardingScreen::AgentAuthoring(screen) => screen.draft.auto_prune,
        _ => unreachable!("optimizations shell holds the authoring screen"),
    }
}

fn shell_auto_prune_row(shell: &super::super::OnboardingShell) -> Rect {
    match &shell.screen {
        super::super::OnboardingScreen::AgentAuthoring(screen) => screen.list_row_rects[0],
        _ => unreachable!("optimizations shell holds the authoring screen"),
    }
}

#[test]
fn shrinking_to_an_empty_content_area_leaves_no_stale_clickable_rows() {
    let mut engine = crate::tui::settings::Dialog::None;

    // Control: at 80x9 the Auto-prune row is on screen and one click there
    // toggles it.
    let mut shell = optimizations_shell();
    render_shell(&mut shell, 80, 9);
    let row = shell_auto_prune_row(&shell);
    let before = shell_auto_prune(&shell);
    shell.handle_mouse(click_at(Position::new(row.x + 2, row.y)), &mut engine);
    assert_ne!(
        shell_auto_prune(&shell),
        before,
        "control click must toggle"
    );

    // Resize to 80x3: the column is one row, which the footer owns, so the
    // content area is empty and the screen takes its early-return path. The
    // old row must not stay clickable.
    let mut shell = optimizations_shell();
    render_shell(&mut shell, 80, 9);
    let row = shell_auto_prune_row(&shell);
    render_shell(&mut shell, 80, 3);
    match &shell.screen {
        super::super::OnboardingScreen::AgentAuthoring(screen) => {
            assert!(screen.list_row_rects.is_empty(), "stale rows survived");
        }
        _ => unreachable!("optimizations shell holds the authoring screen"),
    }
    shell.handle_mouse(click_at(Position::new(row.x + 2, row.y)), &mut engine);
    assert_eq!(
        shell_auto_prune(&shell),
        before,
        "stale row toggled Auto-prune"
    );
}

#[test]
fn rendering_into_an_empty_area_clears_the_previous_rows() {
    // The screen's own early return for an empty area must not keep the
    // previous frame's rows clickable (the shell funnel clears them too, but
    // the screen renders standalone in other hosts).
    let mut screen = golden_screen(Phase::Optimizations);
    render_buffer(&mut screen, 80, 24);
    let row = screen.list_row_rects[0];
    let before = screen.draft.auto_prune;
    crate::tui::golden::render_frame(80, 24, |frame| {
        let area = frame.area();
        screen.render(frame, Rect { height: 0, ..area });
    });
    screen.handle_mouse(click_at(Position::new(row.x + 2, row.y)));
    assert_eq!(
        screen.draft.auto_prune, before,
        "stale row toggled Auto-prune"
    );
    assert!(screen.list_row_rects.is_empty());
}
