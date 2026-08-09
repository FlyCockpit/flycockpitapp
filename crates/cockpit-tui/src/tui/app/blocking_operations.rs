use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum BlockingOperationKind {
    CuratorMaintenance,
    DoctorSnapshot,
    ExportWrite,
    QueueMutation,
    BtwTeardown,
    FileAutocomplete,
}

pub(super) const BLOCKING_OPERATION_MANIFEST: &[(&str, BlockingOperationKind)] = &[
    ("slash:/curator", BlockingOperationKind::CuratorMaintenance),
    ("slash:/doctor", BlockingOperationKind::DoctorSnapshot),
    ("slash:/export", BlockingOperationKind::ExportWrite),
    ("key:queue-edit", BlockingOperationKind::QueueMutation),
    ("composer:/btw-end", BlockingOperationKind::BtwTeardown),
    (
        "composer:@suggestions",
        BlockingOperationKind::FileAutocomplete,
    ),
];

impl BlockingOperationKind {
    pub(super) const fn action_name(self) -> &'static str {
        match self {
            Self::CuratorMaintenance => "curator.command",
            Self::DoctorSnapshot => "doctor.snapshot",
            Self::ExportWrite => "export.write",
            Self::QueueMutation => "queue.edit",
            Self::BtwTeardown => "btw.teardown",
            Self::FileAutocomplete => "autocomplete.files",
        }
    }

    pub(super) const fn action_kind(self) -> AsyncActionKind {
        AsyncActionKind::Blocking(self.action_name())
    }
}

impl App {
    pub(super) fn start_owned_blocking_action<F>(
        &mut self,
        operation: BlockingOperationKind,
        policy: AsyncActionPolicy,
        work: F,
    ) -> crate::tui::async_action::AsyncActionStart
    where
        F: FnOnce() -> Result<AsyncActionPayload, String> + Send + 'static,
    {
        self.async_actions
            .start_blocking(operation.action_kind(), policy, work)
    }
}
