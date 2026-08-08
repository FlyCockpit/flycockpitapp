//! Injected event sink for write-scope authority changes.
//!
//! Exists so tests can assert the *absence* of events: a CAS loser and an
//! Unsupported refusal must produce zero child records, tokens, and events.

use std::sync::Mutex;

use uuid::Uuid;

/// Authority-changing events. Deliberately content-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteScopeEvent {
    LeaseOpened {
        lease_id: Uuid,
        generation: u64,
    },
    TransferPrepared {
        transfer_id: Uuid,
        parent_lease_id: Uuid,
    },
    ParentExcluded {
        transfer_id: Uuid,
        parent_generation: u64,
    },
    ChildActivated {
        transfer_id: Uuid,
        child_lease_id: Uuid,
        child_generation: u64,
    },
    ChildTerminal {
        transfer_id: Uuid,
    },
    ParentRestored {
        transfer_id: Uuid,
        parent_generation: u64,
    },
    TransferCommitted {
        transfer_id: Uuid,
    },
    TransferUnwound {
        parent_lease_id: Uuid,
        reason: String,
    },
}

impl WriteScopeEvent {
    /// True for events that only exist once a child actually owns authority.
    /// A refusal must emit none of these.
    pub fn implies_child_exists(&self) -> bool {
        matches!(
            self,
            Self::ChildActivated { .. } | Self::ChildTerminal { .. }
        )
    }
}

pub trait WriteScopeEventSink: Send + Sync {
    fn emit(&self, event: WriteScopeEvent);
}

/// Drops everything. Production default until a consumer needs the stream.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullEventSink;

impl WriteScopeEventSink for NullEventSink {
    fn emit(&self, _event: WriteScopeEvent) {}
}

/// Records every event for assertions.
#[derive(Debug, Default)]
pub struct RecordingEventSink {
    events: Mutex<Vec<WriteScopeEvent>>,
}

impl RecordingEventSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<WriteScopeEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.events().is_empty()
    }

    pub fn count(&self) -> usize {
        self.events().len()
    }
}

impl WriteScopeEventSink for RecordingEventSink {
    fn emit(&self, event: WriteScopeEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}
