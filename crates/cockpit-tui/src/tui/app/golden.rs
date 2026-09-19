//! App- and onboarding-screen helpers for the golden harness.

use std::path::Path;
use std::time::{Duration, Instant};

use ratatui::buffer::Buffer;

use super::{App, Overlay};
use crate::tui::golden::{
    GoldenPins, assert_golden_sizes, buffer_text, hover_allowed, pinned_frame, render_frame,
};
use crate::tui::onboarding::OnboardingShell;
use crate::tui::settings::Dialog;
use cockpit_config::extended::VimModeSetting;
use cockpit_proto::{OnboardingBootstrapSnapshot, OnboardingStage};

use crate::tui::history::{
    HistoryEntry, PendingMsg, SubagentOutcome, SubagentRoutingChips, ToolCallState,
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

fn transcript_fixture_app() -> App {
    let mut app = App::new(Some(Path::new("/tmp/project")), false);
    app.dialog = Dialog::None;
    app.overlay = Overlay::None;
    app.launch.banner_enabled = false;
    app.mouse_capture = false;
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
    let agent = |text: &str, reasoning: &str, expanded: bool, seq| HistoryEntry::Agent {
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
    };
    app.history = vec![
        user("Restyle the complete transcript surface.", 1),
        agent(
            "The first response is interrupted.",
            "Inspect the current transcript hierarchy.",
            false,
            2,
        ),
        HistoryEntry::Plain {
            line: "Stopped — you sent a message".to_string(),
        },
        user("Continue with every transcript element.", 3),
        HistoryEntry::Plain {
            line: "steer from You: Prioritize the transcript chrome.".to_string(),
        },
        agent(
            "The open thought is followed by tool work.",
            "Map each requested row to its owning renderer.",
            true,
            4,
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
        text: "Streaming the final response".to_string(),
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
    app.set_chat_scroll_offset_from_interaction(6);
    render_frame(width, height, |frame| {
        app.render_chat_history_pane(frame, frame.area());
    })
}

pub fn assert_transcript_fixture() {
    let _pins = GoldenPins::install();
    assert_golden_sizes("chat", "transcript-elements", render_transcript_fixture);
    let preview = format!(
        "{}\n{}",
        buffer_text(&render_transcript_fixture(80, 24)),
        buffer_text(&render_transcript_fixture(120, 40))
    );
    for marker in [
        "↓ Latest",
        "▌",
        "Thought",
        "Stopped — you sent a message",
        "▸ You",
        "interactive ✓",
        "background ✓",
        "◇ Edited",
        "[show summary]",
        "[Agent stats]",
    ] {
        assert!(preview.contains(marker), "fixture must contain {marker:?}");
    }
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
        preview.contains("‹ Back") && preview.contains("[ Continue ]"),
        "secure-store dump must include chrome"
    );
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
        env
    }

    #[test]
    fn golden_empty_chat_with_banner() {
        let _env = isolate_render_env();
        assert_empty_chat_banner();
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
}
