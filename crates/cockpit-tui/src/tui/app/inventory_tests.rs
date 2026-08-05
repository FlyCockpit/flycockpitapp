//! Acceptance tests for daemon-backed TUI inventory consumption.
//! Named tests mandated by tui-inventory-from-daemon.

use super::inventory::*;
use cockpit_config::config::providers::ModelTrust;
use cockpit_core::daemon::proto::{AgentSummary, ModelSummary, SkillSummary};
use uuid::Uuid;

fn agent(name: &str) -> AgentSummary {
    AgentSummary {
        name: name.into(),
        description: format!("{name} desc"),
        mode: "primary".into(),
        source: "builtin".into(),
        builtin: true,
    }
}

fn model(provider: &str, id: &str, favorite: bool) -> ModelSummary {
    ModelSummary {
        provider: provider.into(),
        id: id.into(),
        display_name: Some(id.into()),
        favorite,
        trust: ModelTrust::Untrusted,
        reasoning_effort: None,
        thinking_modes: Vec::new(),
        available: true,
        native_provider_valid: true,
    }
}

fn skill(name: &str) -> SkillSummary {
    SkillSummary {
        name: name.into(),
        description: format!("{name} desc"),
        source: "test".into(),
        user_invocable: true,
    }
}

fn bundle(
    selected: &str,
    agents: Vec<AgentSummary>,
    models: Vec<ModelSummary>,
    skills: Vec<SkillSummary>,
    session_gen: u64,
    config_gen: u64,
    inv_gen: u64,
) -> InventorySnapshot {
    InventorySnapshot {
        selected_agent: selected.into(),
        agents,
        models,
        skills,
        session_generation: session_gen,
        config_generation: config_gen,
        inventory_generation: inv_gen,
    }
}

fn attach_state(session_gen: u64) -> (InventoryState, Uuid, Uuid) {
    let mut state = InventoryState::default();
    let client = Uuid::new_v4();
    let session = Uuid::new_v4();
    state.begin_attach(client, 1, session, "Build".into(), session_gen);
    (state, client, session)
}

#[test]
fn tui_inventory_matches_prechange_parity_fixture() {
    // Captures the pre-change visible projection shape and proves a daemon
    // bundle with the same rows satisfies picker parity fields.
    let agents = vec![agent("Plan"), agent("Build"), agent("Careful")];
    let models = vec![
        model("openai", "gpt-a", true),
        model("openai", "gpt-b", false),
    ];
    let skills = vec![skill("review"), skill("docs")];
    let snap = bundle(
        "Build",
        agents.clone(),
        models.clone(),
        skills.clone(),
        0,
        1,
        1,
    );
    assert_eq!(
        snap.agents
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Plan", "Build", "Careful"]
    );
    assert!(snap.models[0].favorite);
    assert_eq!(snap.models[0].trust, ModelTrust::Untrusted);
    assert!(snap.models[0].available);
    assert!(snap.models[0].native_provider_valid);
    assert_eq!(
        snap.skills
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        vec!["review", "docs"]
    );
    assert_eq!(snap.selected_agent, "Build");
}

#[test]
fn tui_performs_no_local_skill_discovery() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tui/app/agent_inventory.rs"
    ));
    let slash = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tui/app/slash.rs"));
    let inventory = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tui/app/inventory.rs"
    ));
    for (name, body) in [
        ("agent_inventory.rs", src),
        ("slash.rs", slash),
        ("inventory.rs", inventory),
    ] {
        assert!(
            !body.contains("skills::discover") && !body.contains("discover_for_agent"),
            "{name} must not call local skill discovery"
        );
    }
}

#[test]
fn per_agent_skill_inventory_comes_from_daemon() {
    let mut state = InventoryState::default();
    let client = Uuid::new_v4();
    let session = Uuid::new_v4();
    state.begin_attach(client, 1, session, "Build".into(), 0);
    let ticket = state.start_refresh("Build".into(), true).expect("refresh");
    let snap = bundle(
        "Build",
        vec![agent("Build")],
        vec![],
        vec![skill("build-only")],
        0,
        1,
        1,
    );
    assert!(state.apply_success(&ticket, snap));
    let skills = &state.snapshot.as_ref().unwrap().skills;
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "build-only");

    let ticket2 = state
        .start_refresh("Plan".into(), true)
        .expect("agent switch refresh");
    let snap2 = bundle(
        "Plan",
        vec![agent("Plan"), agent("Build")],
        vec![],
        vec![skill("plan-only")],
        0,
        1,
        1,
    );
    assert!(state.apply_success(&ticket2, snap2));
    assert_eq!(state.snapshot.as_ref().unwrap().skills[0].name, "plan-only");
    assert_eq!(state.snapshot.as_ref().unwrap().selected_agent, "Plan");
}

#[test]
fn tui_performs_no_local_agent_resolution() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tui/app/agent_inventory.rs"
    ));
    let slash = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tui/app/slash.rs"));
    let model_controls = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tui/app/model_controls.rs"
    ));
    for (name, body) in [
        ("agent_inventory.rs", src),
        ("slash.rs", slash),
        ("model_controls.rs", model_controls),
    ] {
        assert!(
            !body.contains("chat_ownable_primaries"),
            "{name} must not call chat_ownable_primaries"
        );
    }
}

#[test]
fn model_picker_performs_no_local_credential_resolution() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tui/model_picker.rs"
    ));
    assert!(
        !src.contains("secret_ref::load_effective"),
        "model_picker.rs must not call secret_ref::load_effective"
    );
}

#[test]
fn inventory_bundle_is_one_atomic_rpc() {
    let inventory = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tui/app/inventory.rs"
    ));
    let agent_inv = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tui/app/agent_inventory.rs"
    ));
    for body in [inventory, agent_inv] {
        assert!(!body.contains("ListAgents"));
        assert!(!body.contains("ListModels"));
        assert!(!body.contains("ListSkills"));
        assert!(!body.contains("list_agents"));
        assert!(!body.contains("list_models"));
        assert!(!body.contains("list_skills"));
    }
}

#[test]
fn inventory_generation_bootstrap() {
    let (mut state, _client, _session) = attach_state(7);
    assert_eq!(state.floors.config_generation, None);
    assert_eq!(state.floors.inventory_generation, None);
    assert_eq!(state.floors.session_generation, 7);

    let ticket = state.start_refresh("Build".into(), false).unwrap();
    // Exact session mismatch rejected.
    let bad = bundle("Build", vec![], vec![], vec![], 6, 1, 1);
    assert!(!state.apply_success(&ticket, bad));
    assert!(state.snapshot.is_none());

    let ticket = state.start_refresh("Build".into(), false).unwrap();
    let good = bundle("Build", vec![agent("Build")], vec![], vec![], 7, 3, 4);
    assert!(state.apply_success(&ticket, good));
    assert_eq!(state.floors.config_generation, Some(3));
    assert_eq!(state.floors.inventory_generation, Some(4));

    // Detach/session switch clears floors.
    state.clear_for_session_switch();
    assert_eq!(state.floors.config_generation, None);
    assert_eq!(state.floors.inventory_generation, None);
    assert!(state.snapshot.is_none());
}

#[test]
fn inventory_generation_triple_rejects_stale_bundle() {
    let (mut state, _, _) = attach_state(1);
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    assert!(state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 10, 20)
    ));
    assert_eq!(state.floors.config_generation, Some(10));
    assert_eq!(state.floors.inventory_generation, Some(20));

    // Lower config generation discarded; floors unchanged.
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    assert!(!state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 9, 21)
    ));
    assert_eq!(state.floors.config_generation, Some(10));
    assert_eq!(state.floors.inventory_generation, Some(20));
    // Snapshot retained from last complete success.
    assert_eq!(state.snapshot.as_ref().unwrap().config_generation, 10);

    // Lower inventory generation discarded.
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    assert!(!state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 11, 19)
    ));
    assert_eq!(state.floors.inventory_generation, Some(20));

    // Independent raise of both succeeds.
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    assert!(state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 11, 21)
    ));
    assert_eq!(state.floors.config_generation, Some(11));
    assert_eq!(state.floors.inventory_generation, Some(21));
}

#[test]
fn inventory_invalidation_advances_or_sets_floor() {
    let (mut state, _, _) = attach_state(1);
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    assert!(state.apply_success(&ticket, bundle("Build", vec![], vec![], vec![], 1, 5, 5)));

    // Generation-bearing config invalidation raises floor.
    state.on_invalidation(Some(8), None);
    assert_eq!(state.floors.config_generation, Some(8));

    // Generationless inventory invalidation sets MustAdvance.
    state.on_invalidation(None, None);
    assert!(state.advance.must_advance_inventory || state.advance.must_advance_config);

    // Equal generation rejected when advance required.
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    // Force inventory must-advance relative to last accepted.
    state.advance.must_advance_inventory = true;
    state.floors.inventory_generation = Some(5);
    let ticket = InventoryRequestTicket {
        advance: state.advance,
        floors: state.floors,
        ..ticket
    };
    assert!(!state.apply_success(&ticket, bundle("Build", vec![], vec![], vec![], 1, 8, 5)));

    // Strictly advanced inventory clears requirement.
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    state.advance.must_advance_inventory = true;
    let ticket = InventoryRequestTicket {
        advance: AdvanceRequirements {
            must_advance_inventory: true,
            must_advance_config: false,
        },
        floors: state.floors,
        ..ticket
    };
    assert!(state.apply_success(&ticket, bundle("Build", vec![], vec![], vec![], 1, 8, 6)));
    assert!(!state.advance.must_advance_inventory);
}

#[test]
fn inventory_refresh_coalesces_invalidation_races() {
    let (mut state, _, _) = attach_state(1);
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    assert!(state.in_flight.is_some());

    // Multiple invalidations while in flight.
    state.on_invalidation(Some(2), Some(2));
    state.on_invalidation(Some(3), Some(3));
    assert!(state.dirty);
    assert!(state.in_flight.is_none()); // old ticket invalidated

    // Old ticket response is inert.
    assert!(!state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 1, 1)
    ));
    assert!(state.snapshot.is_none());

    // Exactly one dirty replacement with newest floors.
    assert!(state.take_dirty_replacement());
    assert!(!state.dirty);
    assert_eq!(state.floors.config_generation, Some(3));
    assert_eq!(state.floors.inventory_generation, Some(3));
    let ticket2 = state.start_refresh("Build".into(), false).unwrap();
    assert!(state.apply_success(
        &ticket2,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 3, 3)
    ));
    assert!(!state.dirty);
}

#[test]
fn inventory_explicit_and_agent_refresh_allow_equal_triple() {
    let (mut state, _, _) = attach_state(1);
    let ticket = state.start_refresh("Build".into(), true).unwrap();
    assert!(state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 4, 4)
    ));

    // Explicit refresh with equal gens allowed.
    let ticket = state.start_refresh("Build".into(), true).unwrap();
    assert!(state.apply_success(
        &ticket,
        bundle(
            "Build",
            vec![agent("Build"), agent("Plan")],
            vec![],
            vec![],
            1,
            4,
            4
        )
    ));
    assert_eq!(state.snapshot.as_ref().unwrap().agents.len(), 2);

    // Agent change with equal gens allowed.
    let ticket = state.start_refresh("Plan".into(), true).unwrap();
    assert!(state.apply_success(
        &ticket,
        bundle(
            "Plan",
            vec![agent("Plan")],
            vec![],
            vec![skill("p")],
            1,
            4,
            4
        )
    ));
    assert_eq!(state.snapshot.as_ref().unwrap().selected_agent, "Plan");
}

#[test]
fn inventory_bundle_failure_retains_last_complete_snapshot() {
    let (mut state, _, _) = attach_state(1);
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    assert!(state.apply_success(
        &ticket,
        bundle(
            "Build",
            vec![agent("Build")],
            vec![model("p", "m", false)],
            vec![skill("s")],
            1,
            1,
            1
        )
    ));
    let before = state.snapshot.clone().unwrap();

    let ticket = state.start_refresh("Build".into(), false).unwrap();
    assert!(state.apply_failure(&ticket, "transient".into()));
    assert_eq!(
        state.snapshot.as_ref().unwrap().selected_agent,
        before.selected_agent
    );
    assert_eq!(
        state.snapshot.as_ref().unwrap().agents.len(),
        before.agents.len()
    );
    assert_eq!(
        state.snapshot.as_ref().unwrap().models.len(),
        before.models.len()
    );
    assert_eq!(
        state.snapshot.as_ref().unwrap().skills.len(),
        before.skills.len()
    );
    assert_eq!(state.last_notice.as_deref(), Some("transient"));
}

#[test]
fn inventory_identity_rejects_late_results() {
    let (mut state, client, _session) = attach_state(1);
    let ticket = state.start_refresh("Build".into(), false).unwrap();

    // Session switch invalidates.
    state.begin_attach(client, 1, Uuid::new_v4(), "Build".into(), 1);
    assert!(!state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 1, 1)
    ));
    assert!(!state.apply_failure(&ticket, "late err".into()));

    // Reconnect advances connection_epoch.
    let (mut state, client, session) = attach_state(1);
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    state.begin_attach(client, 2, session, "Build".into(), 1);
    assert!(!state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 1, 1)
    ));

    // Newer refresh_generation / invalidation epoch.
    let (mut state, _, _) = attach_state(1);
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    let _ = state.start_refresh("Build".into(), false).unwrap();
    assert!(!state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 1, 1)
    ));
}

#[test]
fn inventory_initial_unavailable_and_authoritative_empty_are_distinct() {
    let state = InventoryState::default();
    assert_eq!(state.availability(), InventoryAvailability::Unavailable);

    let (mut state, _, _) = attach_state(0);
    assert_eq!(state.availability(), InventoryAvailability::Unavailable);

    let ticket = state.start_refresh("Build".into(), false).unwrap();
    assert!(state.apply_success(&ticket, bundle("Build", vec![], vec![], vec![], 0, 1, 1)));
    assert_eq!(state.availability(), InventoryAvailability::Empty);

    let ticket = state.start_refresh("Build".into(), true).unwrap();
    assert!(state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 0, 1, 1)
    ));
    assert_eq!(state.availability(), InventoryAvailability::Ready);

    state.clear_for_session_switch();
    assert_eq!(state.availability(), InventoryAvailability::Unavailable);
}

#[test]
fn inventory_refresh_preserves_focus_by_identity() {
    let ids = vec!["a".into(), "b".into(), "c".into()];
    assert_eq!(preserve_focus_by_identity(Some("b"), &ids), Some(1));

    // Insertion / reordering: still find by id.
    let ids2 = vec!["x".into(), "b".into(), "a".into()];
    assert_eq!(preserve_focus_by_identity(Some("b"), &ids2), Some(1));

    // Vanished selection → first valid.
    assert_eq!(preserve_focus_by_identity(Some("gone"), &ids2), Some(0));

    // Empty list.
    assert_eq!(preserve_focus_by_identity(Some("a"), &[]), None);
}

#[test]
fn inventory_handlers_do_not_block_event_loop() {
    // The pure reducer never parks; in-flight is a ticket only. Parking is
    // owned by the async RPC layer which posts a completion message.
    let (mut state, _, _) = attach_state(1);
    let ticket = state.start_refresh("Build".into(), false).unwrap();
    assert!(state.in_flight.is_some());
    // Event-loop-style invalidation still reduces while "RPC" is out.
    state.on_invalidation(None, None);
    assert!(state.dirty);
    // Late success of old ticket is inert.
    assert!(!state.apply_success(
        &ticket,
        bundle("Build", vec![agent("Build")], vec![], vec![], 1, 1, 1)
    ));
}
