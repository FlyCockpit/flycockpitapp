//! App- and onboarding-screen helpers for the golden harness.

use std::path::Path;

use ratatui::buffer::Buffer;

use super::{App, Overlay};
use crate::tui::golden::{
    GoldenPins, assert_golden_sizes, buffer_text, hover_allowed, pinned_frame, render_frame,
};
use crate::tui::onboarding::OnboardingShell;
use crate::tui::settings::Dialog;
use cockpit_config::extended::VimModeSetting;
use cockpit_proto::{OnboardingBootstrapSnapshot, OnboardingStage};

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
    let error = "daemon spawn failed: socket path too long; set COCKPIT_SOCKET_DIR".to_string();
    app.apply_daemon_spawn_failure(&error);
    app
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
        preview.contains("COCKPIT_SOCKET_DIR"),
        "spawn-error dump must include the spawn failure"
    );
    assert!(
        !preview.contains("Loading session setup"),
        "spawn-error dump must not stay on the loading placeholder"
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
}
