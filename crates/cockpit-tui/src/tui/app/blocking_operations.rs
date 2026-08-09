use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(super) enum BlockingOperationKind {
    CuratorMaintenance,
    DoctorSnapshot,
    ExportWrite,
    QueueMutation,
    BtwTeardown,
    FileAutocomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BlockingOperationRegistration {
    pub(super) site: &'static str,
    pub(super) kind: BlockingOperationKind,
    pub(super) actions: &'static [&'static str],
}

pub(super) const BLOCKING_OPERATION_MANIFEST: &[BlockingOperationRegistration] = &[
    BlockingOperationRegistration {
        site: "slash:/curator",
        kind: BlockingOperationKind::CuratorMaintenance,
        actions: &["curator.command"],
    },
    BlockingOperationRegistration {
        site: "slash:/doctor",
        kind: BlockingOperationKind::DoctorSnapshot,
        actions: &["doctor.snapshot"],
    },
    BlockingOperationRegistration {
        site: "slash:/export",
        kind: BlockingOperationKind::ExportWrite,
        actions: &["export.transcript", "export.debug"],
    },
    BlockingOperationRegistration {
        site: "key:queue-edit",
        kind: BlockingOperationKind::QueueMutation,
        actions: &["queue.edit"],
    },
    BlockingOperationRegistration {
        site: "slash:/btw",
        kind: BlockingOperationKind::BtwTeardown,
        actions: &["btw.teardown"],
    },
    BlockingOperationRegistration {
        site: "composer:@suggestions",
        kind: BlockingOperationKind::FileAutocomplete,
        actions: &["autocomplete.files"],
    },
];

impl BlockingOperationKind {
    const fn registration(self) -> BlockingOperationRegistration {
        let mut index = 0;
        while index < BLOCKING_OPERATION_MANIFEST.len() {
            let registration = BLOCKING_OPERATION_MANIFEST[index];
            if registration.kind as u8 == self as u8 {
                return registration;
            }
            index += 1;
        }
        panic!("blocking operation is absent from manifest")
    }

    pub(super) const fn action_name_at(self, index: usize) -> &'static str {
        self.registration().actions[index]
    }

    pub(super) const fn action_name(self) -> &'static str {
        self.action_name_at(0)
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
