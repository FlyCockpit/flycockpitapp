//! App- and onboarding-screen helpers for the golden harness.

use std::path::Path;
use std::time::{Duration, Instant};

use ratatui::buffer::Buffer;

use super::{App, Overlay};
use crate::tui::composer_controls::ComposerControlKind;
use crate::tui::golden::{
    GoldenPins, assert_golden_sizes, buffer_text, hover_allowed, pinned_frame, render_frame,
};
use crate::tui::onboarding::OnboardingShell;
use crate::tui::settings::Dialog;
use cockpit_config::extended::VimModeSetting;
use cockpit_config::providers::{
    ActiveModelRef, ActiveReasoningEffort, CapabilityValue, ModelCapabilities, ModelEntry,
    ProviderEntry, ReasoningEffortCapability, ThinkingMode,
};
use cockpit_proto::{OnboardingBootstrapSnapshot, OnboardingStage};
use crossterm::event::{KeyCode, KeyEvent};

fn golden_model_config() -> cockpit_config::config::providers::ProvidersConfig {
    let mut config = cockpit_config::config::providers::ProvidersConfig::default();
    config.providers.insert(
        "openai".to_string(),
        cockpit_config::config::providers::ProviderEntry {
            models: vec![
                cockpit_config::config::providers::ModelEntry {
                    id: "gpt-5.2-codex".to_string(),
                    ..Default::default()
                },
                cockpit_config::config::providers::ModelEntry {
                    id: "gpt-5.2".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    );
    config
}

use crate::tui::history::{
    DiffVerb, HistoryEntry, PendingMsg, SubagentOutcome, SubagentRoutingChips, ToolCallState,
};

/// Clear mouse-hover unless the test opted in via [`GoldenPins::allow_hover`].
pub fn pin_app(app: &mut App) {
    if hover_allowed() {
        return;
    }
    app.hovered_affordance = None;
    app.hovered_suggestion = None;
    app.hovered_control_chip = None;
    app.queue_hover = None;
    app.button_registry.clear_hover_and_pressed();
    app.link_registry.clear_hover();
}

/// Render the whole `App` frame through [`ratatui::backend::TestBackend`].
pub fn render_app(app: &mut App, width: u16, height: u16) -> Buffer {
    pin_app(app);
    if app.launch.banner_enabled {
        crate::tui::banner_box::with_test_banner_visible(|| {
            render_frame(width, height, |frame| app.render(frame))
        })
    } else {
        render_frame(width, height, |frame| app.render(frame))
    }
}

/// Empty chat with the in-TUI launch banner — seed dump (a).
pub fn empty_chat_banner_app() -> App {
    let mut app = App::new(Some(Path::new("/tmp/project")), false);
    app.dialog = Dialog::None;
    app.overlay = Overlay::None;
    app.launch.banner_enabled = true;
    app.launch.cwd = Path::new("/tmp/project").to_path_buf();
    app.launch.cwd_display = "~/project".to_string();
    app.launch.repo_status = None;
    app.launch.user_name = None;
    app.launch.session_id = None;
    app.launch.session_short_id = None;
    app.vim_setting = VimModeSetting::Disabled;
    app.composer.set_vim_enabled(false);
    app
}

/// Spawn-failure surface: blocking toast + session-setup error in place of
/// the loading placeholder.
pub fn spawn_error_app() -> App {
    let mut app = empty_chat_banner_app();
    let error = "daemon socket address already in use: /tmp/cockpit.sock\n\
--- daemon.log (last 20 lines) ---\n\
bind-line\n";
    app.apply_daemon_spawn_failure(error);
    app
}

fn transcript_fixture_app() -> App {
    let mut app = App::new(Some(Path::new("/tmp/project")), false);
    app.dialog = Dialog::None;
    app.overlay = Overlay::None;
    app.launch.banner_enabled = false;
    app.mouse_capture = false;
    // Pin the fixture to the Inline 6-column diff chrome — the shared-element
    // spec shape — so the wide dump exercises it (the default SideBySide mode
    // stays covered by `diff::tests::side_by_side_uses_separator_when_wide`
    // and its narrow-degradation sibling).
    app.diff_style = cockpit_config::extended::DiffStyle::Inline;
    let now = chrono::Local::now();
    let user = |text: &str, seq| HistoryEntry::User {
        text: text.to_string(),
        cleaned: None,
        expanded: false,
        timestamp: now,
        seq: Some(seq),
        optimistic_submission_id: None,
        preflight_pending: false,
        persist_failed: false,
    };
    let agent = |text: &str, reasoning: &str, expanded: bool, seq, interrupted| {
        HistoryEntry::Agent {
            name: "Agent".to_string(),
            text: text.to_string(),
            reasoning: reasoning.to_string(),
            timestamp: now,
            expanded,
            reasoning_offset: 0,
            think_duration: Some(Duration::from_secs(2)),
            seq: Some(seq),
            performance: Some(cockpit_client::presentation::ResponsePerformance {
                ttft_ms: 850,
                generation_ms: 2_000,
                displayed_tokens: 80,
                encoding: "o200k_base".to_string(),
            }),
            performance_expanded: expanded,
            // The interrupted turn uses the production shape the
            // `AgentIdle(Interrupted)` finalize path freezes (see
            // `App::finalize_pending_interrupted`): the marker row is
            // rendered by the entry, not staged as a synthetic `Plain` row.
            interrupted,
        }
    };
    app.history = vec![
        user("Restyle the complete transcript surface.", 1),
        agent(
            "The first response is interrupted.",
            "Inspect the current transcript hierarchy.",
            false,
            2,
            true,
        ),
        user("Continue with every transcript element.", 3),
        HistoryEntry::Plain {
            line: "steer from You: Prioritize the transcript chrome.".to_string(),
        },
        HistoryEntry::UserNote {
            text: "Keep product-only transcript variants.".to_string(),
            timestamp: now,
        },
        agent(
            "The open thought is followed by tool work.",
            "Map each requested row to its owning renderer.",
            true,
            4,
            false,
        ),
        HistoryEntry::ToolLine {
            call_id: "read-1".to_string(),
            tool: "read".to_string(),
            summary: "crates/cockpit-tui/src/tui/history/mod.rs".to_string(),
            icon_path: None,
            state: ToolCallState::Success,
        },
        HistoryEntry::Subagent {
            parent: "Agent".to_string(),
            child: "explore".to_string(),
            task_call_id: "task-interactive".to_string(),
            label: "interactive".to_string(),
            model_trusted: false,
            routing: SubagentRoutingChips::default(),
            spawned_at: Instant::now(),
            outcome: Some(SubagentOutcome {
                report: "Interactive child inspected the rendering seam.".to_string(),
                failed: false,
                duration: Duration::from_secs(3),
                status: None,
            }),
            expanded: true,
        },
        HistoryEntry::Subagent {
            parent: "Agent".to_string(),
            child: "runner".to_string(),
            task_call_id: "task-background".to_string(),
            label: "background".to_string(),
            model_trusted: false,
            routing: SubagentRoutingChips::default(),
            spawned_at: Instant::now(),
            outcome: Some(SubagentOutcome {
                report: "Background child returned a compact report.".to_string(),
                failed: false,
                duration: Duration::from_secs(4),
                status: None,
            }),
            expanded: false,
        },
        HistoryEntry::Diff {
            tool: "edit".to_string(),
            path: "src/transcript.rs".to_string(),
            old: "old line\nshared line\n".to_string(),
            new: "new line\nshared line\n".to_string(),
            verb: DiffVerb::Edited,
        },
        HistoryEntry::CompactBoundary {
            predecessor_short_id: "abc123".to_string(),
            seed_tool_count: 2,
            seed_tool_tokens: 42,
            source: "auto".to_string(),
            trigger_ctx_pct: Some(82.0),
            tokens_before: 9_000,
            tokens_after: 2_400,
            turns_summarized: 6,
            tail_kept: 2,
            tail_trimmed: 1,
            handoff: Some("Summary of the compacted conversation.".to_string()),
            expanded: false,
            result_offset: 0,
        },
    ]
    .into();
    app.pending = Some(PendingMsg {
        name: "Agent".to_string(),
        text:
            "Streaming the final response with a stable caret while the viewport remains scrolled."
                .to_string(),
        reasoning: "Check the final visual hierarchy.".to_string(),
        timestamp: now,
        started_at: Instant::now(),
        text_started_at: Some(Instant::now()),
        inside_think: false,
        body_started: true,
        tag_partial: String::new(),
        attempt_id: None,
        seq: Some(5),
        strip_think: true,
        response_performance: None,
    });
    app
}

pub fn render_transcript_fixture(width: u16, height: u16) -> Buffer {
    let mut app = transcript_fixture_app();
    let _ = render_frame(width, height, |frame| {
        app.render_chat_history_pane(frame, frame.area());
    });
    app.set_chat_scroll_offset_from_interaction(1);
    let buffer = render_frame(width, height, |frame| {
        app.render_chat_history_pane(frame, frame.area());
    });
    assert!(
        app.sticky_header_area.is_some(),
        "transcript golden must exercise the sticky header at {width}x{height}"
    );
    buffer
}

pub fn assert_transcript_fixture() {
    let _pins = GoldenPins::install();
    assert_golden_sizes("chat", "transcript-elements", render_transcript_fixture);
    // Per-size marker checks that distinguish the states the byte dumps
    // carry: both Thought collapse states plus the live `Thinking` header,
    // the interrupted marker row from the finalized entry, the Inline
    // 6-column diff chrome, the sticky accent, and the `↓ Latest` chip.
    let wide = buffer_text(&render_transcript_fixture(120, 40));
    for marker in [
        "↓ Latest",
        "  ⎯ Stopped — you sent a message",
        "▸ Thought",
        "▾ Thought",
        "  Thinking",
        "Check the final visual hierarchy.",
        "▸ You",
        "note to self",
        "interactive ✓",
        "background ✓",
        "◇ Edited",
        "  │ - old line",
        "  │ + new line",
        "[show summary]",
        "[Pin]",
        "[Fork]",
        "  TTFT",
    ] {
        assert!(wide.contains(marker), "120x40 dump must contain {marker:?}");
    }
    assert_sticky_bare_bar(&wide);
    let narrow = buffer_text(&render_transcript_fixture(80, 24));
    for marker in [
        "↓ Latest",
        "  Thinking",
        "Check the final visual hierarchy.",
        "  │ + new line",
    ] {
        assert!(
            narrow.contains(marker),
            "80x24 dump must contain {marker:?}"
        );
    }
    assert_sticky_bare_bar(&narrow);
}

/// The sticky accent is the bare `▌` bar with the condensed INK-bold preview
/// directly after it — not the `▌ ` user-message body bar.
fn assert_sticky_bare_bar(dump: &str) {
    let sticky = dump.lines().next().expect("sticky header row");
    assert!(
        sticky.starts_with('▌') && !sticky.starts_with("▌ "),
        "sticky row must use the bare bar accent: {sticky:?}"
    );
}

/// Settled onboarding Welcome shell — seed dump (b).
pub fn onboarding_welcome_shell_at(frame: usize, reduced_motion: bool) -> OnboardingShell {
    let snapshot = OnboardingBootstrapSnapshot {
        run_id: uuid::Uuid::from_u128(1),
        attempt_id: uuid::Uuid::from_u128(2),
        revision: 3,
        stage: OnboardingStage::Welcome,
        bootstrap_state: cockpit_proto::OnboardingBootstrapState::AwaitingChoice,
        limited_mode: false,
        lifetime_selection: None,
        host_capabilities: cockpit_proto::HostCapabilitySnapshot::unpublished(),
        last_receipt: None,
    };
    let mut shell = OnboardingShell::new(&snapshot, reduced_motion);
    shell.set_frame_for_golden(frame);
    shell.set_welcome_cloud_seed_for_golden(crate::tui::golden::cloud_seed());
    shell
}

pub fn onboarding_welcome_shell() -> OnboardingShell {
    onboarding_welcome_shell_at(pinned_frame(), false)
}

/// Render the settled Welcome screen.
pub fn render_onboarding_welcome(width: u16, height: u16) -> Buffer {
    let mut shell = onboarding_welcome_shell();
    let engine = Dialog::None;
    let mut links = crate::tui::links::LinkRegistry::default();
    render_frame(width, height, |frame| {
        shell.render(frame, frame.area(), &engine, &mut links);
    })
}

pub fn render_onboarding_welcome_at(
    width: u16,
    height: u16,
    frame_count: usize,
    reduced_motion: bool,
) -> Buffer {
    let mut shell = onboarding_welcome_shell_at(frame_count, reduced_motion);
    let engine = Dialog::None;
    let mut links = crate::tui::links::LinkRegistry::default();
    render_frame(width, height, |frame| {
        shell.render(frame, frame.area(), &engine, &mut links);
    })
}

/// Compare empty-chat-with-banner dumps at both review sizes.
pub fn assert_empty_chat_banner() {
    let _pins = GoldenPins::install();
    let mut app = empty_chat_banner_app();
    assert_golden_sizes("chat", "empty-banner", |width, height| {
        render_app(&mut app, width, height)
    });
    let preview = buffer_text(&render_app(&mut app, 80, 24));
    assert!(
        preview.contains("FlyCockpit"),
        "empty chat dump must include the launch banner"
    );
}

pub fn assert_spawn_error() {
    let _pins = GoldenPins::install();
    let mut app = spawn_error_app();
    assert_golden_sizes("chat", "spawn-error", |width, height| {
        render_app(&mut app, width, height)
    });
    let preview = buffer_text(&render_app(&mut app, 80, 24));
    assert!(
        preview.contains("already in use"),
        "spawn-error dump must include the spawn failure summary"
    );
    assert!(
        !preview.contains("Loading session setup"),
        "spawn-error dump must not stay on the loading placeholder"
    );
}

fn composer_picker_app(kind: ComposerControlKind, model_level: u8) -> App {
    let mut app = empty_chat_banner_app();
    app.launch.banner_enabled = false;
    app.launch.active_model = Some(("openai".to_string(), "gpt-5".to_string()));
    app.active_model_selection = Some(ActiveModelRef {
        provider: "openai".to_string(),
        model: "gpt-5".to_string(),
        reasoning_effort: Some(ActiveReasoningEffort {
            value: "medium".to_string(),
        }),
        thinking_mode: None,
        prompt_cache_retention: None,
    });
    let reasoning = ReasoningEffortCapability {
        values: vec![
            CapabilityValue {
                value: "low".to_string(),
                label: Some("Fast".to_string()),
                description: Some("short reasoning pass".to_string()),
            },
            CapabilityValue {
                value: "medium".to_string(),
                label: Some("Balanced".to_string()),
                description: Some("balanced speed and depth".to_string()),
            },
            CapabilityValue {
                value: "high".to_string(),
                label: Some("Thorough".to_string()),
                description: Some("deep reasoning pass".to_string()),
            },
        ],
        default: Some("medium".to_string()),
        ..Default::default()
    };
    app.config_snapshot.providers.providers.clear();
    app.config_snapshot.providers.providers.insert(
        "anthropic".to_string(),
        ProviderEntry {
            models: vec![
                ModelEntry {
                    id: "claude-sonnet".to_string(),
                    favorite: true,
                    thinking_modes: vec![ThinkingMode::Low, ThinkingMode::High],
                    ..Default::default()
                },
                ModelEntry {
                    id: "claude-opus".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    );
    app.config_snapshot.providers.providers.insert(
        "openai".to_string(),
        ProviderEntry {
            models: vec![
                ModelEntry {
                    id: "gpt-5".to_string(),
                    favorite: true,
                    capabilities: ModelCapabilities {
                        reasoning_effort: Some(reasoning.clone()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ModelEntry {
                    id: "gpt-5-mini".to_string(),
                    capabilities: ModelCapabilities {
                        reasoning_effort: Some(reasoning),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    );
    app.usage_models.insert("openai/gpt-5".to_string(), 12);
    app.usage_models
        .insert("anthropic/claude-sonnet".to_string(), 7);
    app.composer_controls.selection = Some(kind);
    app.open_composer_picker(kind);
    if kind == ComposerControlKind::Model && model_level == 1 {
        app.handle_key(KeyEvent::from(KeyCode::Enter));
    }
    app
}

pub fn assert_composer_pickers() {
    let _pins = GoldenPins::install();
    for (name, kind, level) in [
        ("model-providers", ComposerControlKind::Model, 0),
        ("model-models", ComposerControlKind::Model, 1),
        ("effort", ComposerControlKind::Effort, 1),
    ] {
        assert_golden_sizes("composer-picker", name, |width, height| {
            let mut app = composer_picker_app(kind, level);
            render_app(&mut app, width, height)
        });
    }
}

/// Compare onboarding Welcome dumps at both review sizes.
pub fn assert_onboarding_welcome() {
    let _pins = GoldenPins::install();
    let scenes = [
        ("welcome-t0", 0, false),
        (
            "welcome-mid-flight",
            crate::tui::onboarding::welcome::FLIGHT_FRAMES / 2,
            false,
        ),
        (
            "welcome-landed-wordmarks",
            crate::tui::onboarding::welcome::COCKPIT_FRAME,
            false,
        ),
        (
            "welcome-prompt",
            crate::tui::onboarding::welcome::PROMPT_FRAME,
            false,
        ),
        ("welcome-reduced-motion", 0, true),
    ];
    for (name, frame_count, reduced_motion) in scenes {
        assert_golden_sizes("onboarding", name, |width, height| {
            render_onboarding_welcome_at(width, height, frame_count, reduced_motion)
        });
    }
    let preview = buffer_text(&render_onboarding_welcome(80, 24));
    assert!(
        preview.contains("[press any button to continue]"),
        "welcome dump must be the settled screen"
    );
}

/// Settled Secure store screen — issue #427 chrome dump.
pub fn onboarding_secure_store_shell() -> OnboardingShell {
    let snapshot = OnboardingBootstrapSnapshot {
        run_id: uuid::Uuid::from_u128(1),
        attempt_id: uuid::Uuid::from_u128(2),
        revision: 3,
        stage: OnboardingStage::SecureStore,
        bootstrap_state: cockpit_proto::OnboardingBootstrapState::AwaitingChoice,
        limited_mode: false,
        lifetime_selection: None,
        host_capabilities: {
            let mut capabilities = cockpit_proto::HostCapabilitySnapshot::unpublished();
            capabilities.features = vec![
                cockpit_proto::FeatureCapabilityRow {
                    id: "secret_store.keyring".into(),
                    state: cockpit_proto::FeatureCapabilityState::Available,
                    reason: "keyring is available".into(),
                    fix_command: None,
                    remedy_text: None,
                    dependency_ids: Vec::new(),
                },
                cockpit_proto::FeatureCapabilityRow {
                    id: "secret_store.file".into(),
                    state: cockpit_proto::FeatureCapabilityState::Available,
                    reason: "encrypted file vault is available".into(),
                    fix_command: None,
                    remedy_text: None,
                    dependency_ids: Vec::new(),
                },
            ];
            capabilities
        },
        last_receipt: None,
    };
    OnboardingShell::new(&snapshot, false)
}

pub fn render_onboarding_secure_store(width: u16, height: u16) -> Buffer {
    let mut shell = onboarding_secure_store_shell();
    let engine = Dialog::None;
    let mut links = crate::tui::links::LinkRegistry::default();
    render_frame(width, height, |frame| {
        shell.render(frame, frame.area(), &engine, &mut links);
    })
}

pub fn assert_onboarding_secure_store() {
    let _pins = GoldenPins::install();
    assert_golden_sizes("onboarding", "secure-store", render_onboarding_secure_store);
    let preview = buffer_text(&render_onboarding_secure_store(80, 24));
    assert!(
        preview.contains("[ Continue ]") && preview.contains("Secure your secrets"),
        "secure-store dump must include chrome"
    );
}

fn onboarding_shell_at(stage: OnboardingStage) -> OnboardingShell {
    let snapshot = OnboardingBootstrapSnapshot {
        run_id: uuid::Uuid::from_u128(1),
        attempt_id: uuid::Uuid::from_u128(2),
        revision: 3,
        stage,
        bootstrap_state: cockpit_proto::OnboardingBootstrapState::Ready,
        limited_mode: false,
        lifetime_selection: None,
        host_capabilities: cockpit_proto::HostCapabilitySnapshot::unpublished(),
        last_receipt: None,
    };
    OnboardingShell::new(&snapshot, false)
}

fn render_onboarding_stage(stage: OnboardingStage, width: u16, height: u16) -> Buffer {
    let mut shell = onboarding_shell_at(stage);
    if stage == OnboardingStage::Complete {
        shell.present_completion("Name: Amelia · Provider: OpenAI · Agent: cockpit".to_string());
    }
    let engine = Dialog::None;
    let mut links = crate::tui::links::LinkRegistry::default();
    render_frame(width, height, |frame| {
        shell.render(frame, frame.area(), &engine, &mut links)
    })
}

pub fn assert_onboarding_native_screens() {
    for (name, stage) in [
        ("profile", OnboardingStage::Profile),
        ("lifetime", OnboardingStage::Lifetime),
        ("provider", OnboardingStage::Provider),
        ("completion", OnboardingStage::Complete),
    ] {
        assert_golden_sizes("onboarding", name, |width, height| {
            render_onboarding_stage(stage, width, height)
        });
    }
    for (name, phase) in [
        (
            "model-default",
            crate::tui::onboarding::ModelPhase::DefaultModel,
        ),
        ("model-trust", crate::tui::onboarding::ModelPhase::Trust),
        (
            "model-capabilities",
            crate::tui::onboarding::ModelPhase::Capabilities,
        ),
        ("model-limits", crate::tui::onboarding::ModelPhase::Limits),
        (
            "model-thinking",
            crate::tui::onboarding::ModelPhase::Thinking,
        ),
        (
            "model-delegation",
            crate::tui::onboarding::ModelPhase::Delegation,
        ),
    ] {
        assert_golden_sizes("onboarding", name, |width, height| {
            let mut shell = onboarding_shell_at(OnboardingStage::Model);
            let config = golden_model_config();
            shell.present_model(&config, Some(("openai", "gpt-5.2-codex")));
            shell.set_model_phase_for_golden(phase);
            let engine = Dialog::None;
            let mut links = crate::tui::links::LinkRegistry::default();
            render_frame(width, height, |frame| {
                shell.render(frame, frame.area(), &engine, &mut links)
            })
        });
    }
}

#[cfg(test)]
mod seed_tests {
    use super::*;
    use cockpit_test_support::TestEnvGuard;

    fn isolate_render_env() -> TestEnvGuard {
        let env = TestEnvGuard::isolated_cockpit_home();
        env.remove_var("NO_COLOR");
        env.remove_var("COCKPIT_ROOSTER");
        env.remove_var("COCKPIT_REDUCE_MOTION");
        env.remove_var("REDUCE_MOTION");
        env.set_var("TERM", "xterm-256color");
        env.set_var("USER", "amelia");
        env
    }

    #[test]
    fn golden_empty_chat_with_banner() {
        let _env = isolate_render_env();
        assert_empty_chat_banner();
    }

    #[test]
    fn golden_spawn_error() {
        let _env = isolate_render_env();
        assert_spawn_error();
    }

    #[test]
    fn golden_transcript_elements() {
        let _env = isolate_render_env();
        assert_transcript_fixture();
    }

    #[test]
    fn golden_onboarding_welcome() {
        let _env = isolate_render_env();
        assert_onboarding_welcome();
    }

    #[test]
    fn golden_onboarding_secure_store() {
        let _env = isolate_render_env();
        assert_onboarding_secure_store();
    }

    #[test]
    fn golden_onboarding_native_screens() {
        let _env = isolate_render_env();
        assert_onboarding_native_screens();
    }

    #[test]
    fn golden_composer_pickers() {
        let _env = isolate_render_env();
        assert_composer_pickers();
    }
}
