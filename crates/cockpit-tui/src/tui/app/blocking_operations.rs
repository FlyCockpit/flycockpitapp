use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BlockingOperationRegistration {
    pub(super) site: &'static str,
    pub(super) handler: &'static str,
    pub(super) dispatch: &'static str,
    pub(super) kind: BlockingOperationKind,
    pub(super) actions: &'static [&'static str],
}

macro_rules! blocking_operation_manifest {
    ($( $kind:ident => $site:literal => $handler:literal => $dispatch:literal => [$($action:literal),+ $(,)?] ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub(super) enum BlockingOperationKind { $( $kind ),+ }

        pub(super) const BLOCKING_OPERATION_KINDS: &[BlockingOperationKind] =
            &[$(BlockingOperationKind::$kind),+];

        pub(super) const BLOCKING_OPERATION_MANIFEST: &[BlockingOperationRegistration] = &[
            $(BlockingOperationRegistration {
                site: $site,
                handler: $handler,
                dispatch: $dispatch,
                kind: BlockingOperationKind::$kind,
                actions: &[$($action),+],
            }),+
        ];
    };
}

blocking_operation_manifest! {
    CuratorMaintenance => "slash:/curator" => "handle_curator_command" => "start_owned_blocking_action" => ["curator.command"],
    DoctorSnapshot => "slash:/doctor" => "handle_doctor_command" => "start_owned_blocking_action" => ["doctor.snapshot"],
    ExportWrite => "slash:/export" => "handle_export_command" => "export_transcript_json" => ["export.transcript", "export.debug"],
    QueueMutation => "key:queue-edit" => "edit_queued_messages" => "start_serialized" => ["queue.edit"],
    BtwTeardown => "slash:/btw" => "handle_btw_command" => "async_actions.start" => ["btw.teardown"],
    FileAutocomplete => "composer:@suggestions" => "reset_at_window" => "start_owned_blocking_action" => ["autocomplete.files"],
}

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
    #[cfg(test)]
    pub(super) fn dispatch_owned_test_barrier(&mut self, operation: BlockingOperationKind) -> bool {
        let Some(barrier) =
            TEST_OWNED_BARRIERS.with(|barriers| barriers.borrow_mut().remove(&operation))
        else {
            return false;
        };
        self.async_actions.start_blocking(
            operation.action_kind(),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                barrier.wait();
                Ok(AsyncActionPayload::Unit)
            },
        );
        true
    }

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

#[cfg(test)]
thread_local! {
    static TEST_OWNED_BARRIERS: std::cell::RefCell<
        std::collections::HashMap<BlockingOperationKind, std::sync::Arc<std::sync::Barrier>>
    > = Default::default();
}

#[cfg(test)]
pub(super) fn install_owned_test_barrier(
    operation: BlockingOperationKind,
    barrier: std::sync::Arc<std::sync::Barrier>,
) {
    TEST_OWNED_BARRIERS.with(|barriers| barriers.borrow_mut().insert(operation, barrier));
}
