use crate::tui::chrome::FooterControl;
use crate::tui::settings::pointer_actions::SettingsPointerAction;
use crate::tui::settings::shell::SettingsHeaderAction;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ButtonKind {
    Default,
    Destructive,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ButtonId {
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
    PersistentNoticeCopy,
    PersistentNoticeSwitchModel,
    PersistentNoticeFixProvider,
    SessionsConfirmArchive,
    SessionsConfirmDelete,
    SessionsConfirmCancel,
    ResourcePromote {
        index: usize,
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
    DaemonPrompt {
        index: usize,
    },
}

impl ButtonId {
    pub(crate) fn overlay(surface: OverlaySurface, index: usize) -> Self {
        Self::OverlayAction { surface, index }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OverlaySurface {
    ModelPicker,
    Multireview,
    Stats,
    Usage,
    Sessions,
    Skills,
    Tools,
    GoalSettings,
    Permissions,
    Resources,
    Quick,
    Context,
    Notes,
    Diff,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DialogSurface {
    WorkspaceTrust,
    PickConfig,
    CreateConfig,
    CreateScopedConfig,
    WizardMenu,
    ModelSetupChoice,
    SetupWizard,
    FirstRunComplete,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ControlKind {
    Button,
    RowControl,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum RowControlId {
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
    DaemonPrompt {
        index: usize,
    },
    FooterPicker {
        index: usize,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct ButtonSpec {
    pub id: ButtonId,
    pub label: String,
    pub enabled: bool,
    pub focused: bool,
    pub kind: ButtonKind,
    pub dispatch: super::ButtonDispatch,
}

impl ButtonSpec {
    pub fn new(id: ButtonId, label: impl Into<String>, dispatch: super::ButtonDispatch) -> Self {
        Self {
            id,
            label: label.into(),
            enabled: true,
            focused: false,
            kind: ButtonKind::Default,
            dispatch,
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn kind(mut self, kind: ButtonKind) -> Self {
        self.kind = kind;
        self
    }
}
