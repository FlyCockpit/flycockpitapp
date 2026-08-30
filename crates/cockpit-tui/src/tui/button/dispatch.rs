use crate::tui::chrome::FooterControl;
use crate::tui::settings::pointer_actions::SettingsPointerAction;
use crate::tui::settings::shell::SettingsHeaderAction;

use super::id::{DialogSurface, OverlaySurface};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ButtonDispatch {
    SettingsHeader(SettingsHeaderAction),
    Settings(SettingsPointerAction),
    Footer(FooterControl),
    TranscriptPin {
        seq: i64,
    },
    TranscriptUnpin {
        seq: i64,
    },
    TranscriptFork {
        seq: i64,
    },
    QueueSendNow {
        item_id: Option<uuid::Uuid>,
    },
    QueueToggleClass {
        item_id: Option<uuid::Uuid>,
    },
    QueueEdit {
        item_id: Option<uuid::Uuid>,
    },
    QueueCancel {
        item_id: Option<uuid::Uuid>,
    },
    PersistentNoticeCopy,
    PersistentNoticeSwitchModel,
    PersistentNoticeFixProvider,
    SessionsConfirmArchive,
    SessionsConfirmDelete,
    SessionsConfirmCancel,
    ResourcePromote {
        request_id: uuid::Uuid,
    },
    NoteNew,
    OverlayAction {
        surface: OverlaySurface,
        index: usize,
    },
    DialogAction {
        surface: DialogSurface,
        index: usize,
    },
    QuestionAction {
        index: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RowDispatch {
    Settings(SettingsPointerAction),
    ContextMenu {
        index: usize,
    },
    ModelPicker {
        cursor: usize,
    },
    QuickTab {
        index: usize,
    },
    QuickOption {
        index: usize,
    },
    QuestionOption {
        index: usize,
    },
    Multireview {
        index: usize,
    },
    StatsToggle {
        index: usize,
    },
    StatsRecovery {
        index: usize,
    },
    SkillsBrowse {
        index: usize,
    },
    ResourceBrowse {
        index: usize,
    },
    SessionBrowse {
        index: usize,
    },
    OverlayRow {
        surface: OverlaySurface,
        index: usize,
    },
    DialogRow {
        surface: DialogSurface,
        index: usize,
    },
    FooterPicker {
        index: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ButtonPointerOutcome {
    HoverChanged,
    Pressed(super::ButtonId),
    Activated(ButtonDispatch),
    Cancelled,
    Consumed,
}
