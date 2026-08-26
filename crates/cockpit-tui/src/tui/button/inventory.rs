use crate::tui::chrome::FooterControl;
use crate::tui::settings::pointer_actions::SettingsPointerAction;
use crate::tui::settings::shell::SettingsHeaderAction;

use super::id::{ButtonId, ControlKind, DialogSurface, OverlaySurface, RowControlId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InventoryMember {
    Button(ButtonId),
    RowControl(RowControlId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InventoryAssignment {
    pub surface: &'static str,
    pub member: InventoryMember,
    pub kind: ControlKind,
}

pub(crate) fn settings_pointer_control_kind(action: &SettingsPointerAction) -> ControlKind {
    if action.is_button() {
        ControlKind::Button
    } else {
        ControlKind::RowControl
    }
}

pub(crate) fn inventory_member_for_settings(action: SettingsPointerAction) -> InventoryMember {
    if action.is_button() {
        InventoryMember::Button(ButtonId::Settings(action))
    } else {
        InventoryMember::RowControl(RowControlId::Settings(action))
    }
}

/// Sealed Button/RowControl table. Adding a surface or `ButtonId` family
/// requires an entry here; the inventory test derives expected coverage
/// from this list plus the `ButtonId` / `SettingsPointerAction` enums.
pub(crate) fn button_inventory() -> Vec<InventoryAssignment> {
    let mut out = Vec::new();
    push_button(
        &mut out,
        "settings",
        ButtonId::SettingsHeader(SettingsHeaderAction::Close),
    );
    push_button(
        &mut out,
        "settings",
        ButtonId::SettingsHeader(SettingsHeaderAction::Back),
    );
    push_button(
        &mut out,
        "settings",
        ButtonId::SettingsHeader(SettingsHeaderAction::BackToConfigPicker),
    );
    push_button(&mut out, "footer", ButtonId::Footer(FooterControl::Agent));
    push_button(&mut out, "footer", ButtonId::Footer(FooterControl::Model));
    push_button(&mut out, "footer", ButtonId::Footer(FooterControl::Mode));
    push_button(&mut out, "transcript", ButtonId::TranscriptPin { seq: 0 });
    push_button(&mut out, "transcript", ButtonId::TranscriptUnpin { seq: 0 });
    push_button(&mut out, "transcript", ButtonId::TranscriptFork { seq: 0 });
    push_button(&mut out, "notice", ButtonId::PersistentNoticeCopy);
    push_button(&mut out, "notice", ButtonId::PersistentNoticeSwitchModel);
    push_button(&mut out, "notice", ButtonId::PersistentNoticeFixProvider);
    push_button(&mut out, "sessions", ButtonId::SessionsConfirmArchive);
    push_button(&mut out, "sessions", ButtonId::SessionsConfirmDelete);
    push_button(&mut out, "sessions", ButtonId::SessionsConfirmCancel);
    push_button(
        &mut out,
        "resources",
        ButtonId::ResourcePromote {
            request_id: uuid::Uuid::nil(),
        },
    );
    push_button(&mut out, "notes", ButtonId::NoteNew);

    for surface in overlay_surfaces() {
        match surface {
            OverlaySurface::Help | OverlaySurface::Usage | OverlaySurface::Context => {}
            OverlaySurface::ModelPicker => {
                push_row(
                    &mut out,
                    "model_picker",
                    RowControlId::ModelPicker { cursor: 0 },
                );
            }
            OverlaySurface::Multireview => {
                push_row(
                    &mut out,
                    "multireview",
                    RowControlId::Multireview { index: 0 },
                );
            }
            OverlaySurface::Stats => {
                push_row(&mut out, "stats", RowControlId::StatsToggle { index: 0 });
                push_row(&mut out, "stats", RowControlId::StatsRecovery { index: 0 });
            }
            OverlaySurface::Sessions => {
                push_row(
                    &mut out,
                    "sessions",
                    RowControlId::SessionBrowse { index: 0 },
                );
            }
            OverlaySurface::Skills => {
                push_row(&mut out, "skills", RowControlId::SkillsBrowse { index: 0 });
            }
            OverlaySurface::Resources => {
                push_row(
                    &mut out,
                    "resources",
                    RowControlId::ResourceBrowse { index: 0 },
                );
            }
            OverlaySurface::Quick => {
                push_row(&mut out, "quick", RowControlId::QuickTab { index: 0 });
                push_row(&mut out, "quick", RowControlId::QuickOption { index: 0 });
            }
            OverlaySurface::Notes => {
                push_row(
                    &mut out,
                    "notes",
                    RowControlId::OverlayRow { surface, index: 0 },
                );
            }
            OverlaySurface::Tools
            | OverlaySurface::GoalSettings
            | OverlaySurface::Permissions
            | OverlaySurface::Diff => {
                push_button(
                    &mut out,
                    overlay_name(surface),
                    ButtonId::overlay(surface, 0),
                );
                push_row(
                    &mut out,
                    overlay_name(surface),
                    RowControlId::OverlayRow { surface, index: 0 },
                );
            }
        }
    }

    for surface in dialog_surfaces() {
        match surface {
            DialogSurface::Settings => {}
            _ => push_row(
                &mut out,
                dialog_name(surface),
                RowControlId::DialogRow { surface, index: 0 },
            ),
        }
    }
    push_row(
        &mut out,
        "context_menu",
        RowControlId::ContextMenu { index: 0 },
    );
    push_row(
        &mut out,
        "question",
        RowControlId::QuestionOption { index: 0 },
    );
    push_row(
        &mut out,
        "daemon_prompt",
        RowControlId::DaemonPrompt { index: 0 },
    );
    out
}

fn push_button(out: &mut Vec<InventoryAssignment>, surface: &'static str, id: ButtonId) {
    out.push(InventoryAssignment {
        surface,
        member: InventoryMember::Button(id),
        kind: ControlKind::Button,
    });
}

fn push_row(out: &mut Vec<InventoryAssignment>, surface: &'static str, id: RowControlId) {
    out.push(InventoryAssignment {
        surface,
        member: InventoryMember::RowControl(id),
        kind: ControlKind::RowControl,
    });
}

fn overlay_surfaces() -> [OverlaySurface; 15] {
    [
        OverlaySurface::ModelPicker,
        OverlaySurface::Multireview,
        OverlaySurface::Stats,
        OverlaySurface::Usage,
        OverlaySurface::Sessions,
        OverlaySurface::Skills,
        OverlaySurface::Tools,
        OverlaySurface::GoalSettings,
        OverlaySurface::Permissions,
        OverlaySurface::Resources,
        OverlaySurface::Quick,
        OverlaySurface::Context,
        OverlaySurface::Notes,
        OverlaySurface::Diff,
        OverlaySurface::Help,
    ]
}

fn dialog_surfaces() -> [DialogSurface; 9] {
    [
        DialogSurface::WorkspaceTrust,
        DialogSurface::PickConfig,
        DialogSurface::CreateConfig,
        DialogSurface::CreateScopedConfig,
        DialogSurface::WizardMenu,
        DialogSurface::ModelSetupChoice,
        DialogSurface::SetupWizard,
        DialogSurface::FirstRunComplete,
        DialogSurface::Settings,
    ]
}

fn overlay_name(surface: OverlaySurface) -> &'static str {
    match surface {
        OverlaySurface::ModelPicker => "model_picker",
        OverlaySurface::Multireview => "multireview",
        OverlaySurface::Stats => "stats",
        OverlaySurface::Usage => "usage",
        OverlaySurface::Sessions => "sessions",
        OverlaySurface::Skills => "skills",
        OverlaySurface::Tools => "tools",
        OverlaySurface::GoalSettings => "goal_settings",
        OverlaySurface::Permissions => "permissions",
        OverlaySurface::Resources => "resources",
        OverlaySurface::Quick => "quick",
        OverlaySurface::Context => "context",
        OverlaySurface::Notes => "notes",
        OverlaySurface::Diff => "diff",
        OverlaySurface::Help => "help",
    }
}

fn dialog_name(surface: DialogSurface) -> &'static str {
    match surface {
        DialogSurface::WorkspaceTrust => "workspace_trust",
        DialogSurface::PickConfig => "pick_config",
        DialogSurface::CreateConfig => "create_config",
        DialogSurface::CreateScopedConfig => "create_scoped_config",
        DialogSurface::WizardMenu => "wizard_menu",
        DialogSurface::ModelSetupChoice => "model_setup_choice",
        DialogSurface::SetupWizard => "setup_wizard",
        DialogSurface::FirstRunComplete => "first_run_complete",
        DialogSurface::Settings => "settings",
    }
}

pub(crate) fn button_id_family(id: &ButtonId) -> &'static str {
    match id {
        ButtonId::SettingsHeader(_) => "settings_header",
        ButtonId::Settings(_) => "settings",
        ButtonId::Footer(_) => "footer",
        ButtonId::TranscriptPin { .. }
        | ButtonId::TranscriptUnpin { .. }
        | ButtonId::TranscriptFork { .. } => "transcript",
        ButtonId::PersistentNoticeCopy
        | ButtonId::PersistentNoticeSwitchModel
        | ButtonId::PersistentNoticeFixProvider => "notice",
        ButtonId::SessionsConfirmArchive
        | ButtonId::SessionsConfirmDelete
        | ButtonId::SessionsConfirmCancel => "sessions",
        ButtonId::ResourcePromote { .. } => "resources",
        ButtonId::NoteNew => "notes",
        ButtonId::OverlayAction { .. } => "overlay",
        ButtonId::DialogAction { .. } => "dialog",
        ButtonId::QuestionAction { .. } => "question",
        ButtonId::DaemonPrompt { .. } => "daemon_prompt",
    }
}
