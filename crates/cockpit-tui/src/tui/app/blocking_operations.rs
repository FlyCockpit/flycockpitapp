use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) struct BlockingOperationRegistration {
    #[cfg(test)]
    pub(super) site: &'static str,
    #[cfg(test)]
    pub(super) binding: fn(&App) -> BlockingOperationKind,
    #[cfg(test)]
    pub(super) wrapper: &'static str,
    pub(super) kind: BlockingOperationKind,
    pub(super) actions: &'static [&'static str],
}

macro_rules! blocking_operation_manifest {
    ($( $kind:ident => $site:literal => $binding:ident => [$($action_binding:ident => $action:literal),+ $(,)?] ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub(super) enum BlockingOperationKind { $( $kind ),+ }

        pub(super) const BLOCKING_OPERATION_MANIFEST: &[BlockingOperationRegistration] = &[
            $(BlockingOperationRegistration {
                #[cfg(test)]
                site: $site,
                #[cfg(test)]
                binding: App::$binding,
                #[cfg(test)]
                wrapper: stringify!($binding),
                kind: BlockingOperationKind::$kind,
                actions: &[$($action),+],
            }),+
        ];

        impl App {
            $(pub(super) const fn $binding(&self) -> BlockingOperationKind {
                BlockingOperationKind::$kind
            }
            $(#[allow(dead_code)]
            pub(super) const fn $action_binding(&self) -> &'static str { $action })+)+
        }
    };
}

blocking_operation_manifest! {
    CuratorMaintenance => "slash:curator" => curator_blocking_operation => [curator_action_name => "curator.command"],
    DoctorSnapshot => "slash:doctor" => doctor_blocking_operation => [doctor_action_name => "doctor.snapshot"],
    ExportWrite => "slash:export" => export_blocking_operation => [export_transcript_action_name => "export.transcript", export_debug_action_name => "export.debug"],
    QueueMutation => "key:up-queue-edit" => queue_blocking_operation => [queue_action_name => "queue.edit"],
    BtwTeardown => "slash:btw" => btw_blocking_operation => [btw_action_name => "btw.teardown"],
    FileAutocomplete => "composer:char-reset-at" => autocomplete_blocking_operation => [autocomplete_action_name => "autocomplete.files"],
}

impl BlockingOperationKind {
    pub(super) const fn registration(self) -> BlockingOperationRegistration {
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
    pub(super) fn take_owned_test_barrier(
        &self,
        operation: BlockingOperationKind,
    ) -> Option<std::sync::Arc<OwnedTestGate>> {
        TEST_OWNED_BARRIERS.with(|barriers| barriers.borrow_mut().remove(&operation))
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
        #[cfg(test)]
        let barrier = self.take_owned_test_barrier(operation);
        self.async_actions
            .start_blocking(operation.action_kind(), policy, move || {
                #[cfg(test)]
                if let Some(barrier) = barrier {
                    barrier.arrive_and_wait();
                    return Ok(AsyncActionPayload::Unit);
                }
                work()
            })
    }
}

#[cfg(test)]
thread_local! {
    static TEST_OWNED_BARRIERS: std::cell::RefCell<
        std::collections::HashMap<BlockingOperationKind, std::sync::Arc<OwnedTestGate>>
    > = Default::default();
}

#[cfg(test)]
pub(super) struct OwnedTestGate {
    arrived: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    released: std::sync::Mutex<bool>,
    release: std::sync::Condvar,
}

#[cfg(test)]
impl OwnedTestGate {
    pub(super) fn new() -> (std::sync::Arc<Self>, tokio::sync::oneshot::Receiver<()>) {
        let (arrived, receiver) = tokio::sync::oneshot::channel();
        (
            std::sync::Arc::new(Self {
                arrived: std::sync::Mutex::new(Some(arrived)),
                released: std::sync::Mutex::new(false),
                release: std::sync::Condvar::new(),
            }),
            receiver,
        )
    }

    pub(super) fn arrive_and_wait(&self) {
        if let Some(arrived) = self.arrived.lock().unwrap().take() {
            let _ = arrived.send(());
        }
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.release.wait(released).unwrap();
        }
    }

    pub(super) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_all();
    }
}

#[cfg(test)]
pub(super) fn install_owned_test_barrier(
    operation: BlockingOperationKind,
    barrier: std::sync::Arc<OwnedTestGate>,
) {
    TEST_OWNED_BARRIERS.with(|barriers| barriers.borrow_mut().insert(operation, barrier));
}

#[cfg(test)]
pub(super) fn unclaimed_owned_test_operations() -> Vec<BlockingOperationKind> {
    TEST_OWNED_BARRIERS.with(|barriers| barriers.borrow().keys().copied().collect())
}
