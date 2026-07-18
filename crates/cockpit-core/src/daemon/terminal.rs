use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

use uuid::Uuid;

use crate::daemon::proto::{ErrorPayload, Response};
use crate::daemon::{EventSender, SharedRedactionTable};

pub type TerminalResult = std::result::Result<Response, ErrorPayload>;
pub type TerminalHostHandle = Arc<dyn TerminalHost>;

pub trait TerminalHost: std::fmt::Debug + Send + Sync {
    fn open(&self, cwd: Option<String>, cols: u16, rows: u16) -> TerminalResult;
    fn attach(&self, terminal_id: Uuid, cols: u16, rows: u16) -> TerminalResult;
    fn release_viewer(&self, terminal_id: Uuid);
    fn input(&self, terminal_id: Uuid, bytes: Vec<u8>) -> TerminalResult;
    fn resize(&self, terminal_id: Uuid, cols: u16, rows: u16) -> TerminalResult;
    fn close(&self, terminal_id: Uuid) -> TerminalResult;
    fn paste_image(&self, terminal_id: Uuid, bytes: &[u8]) -> TerminalResult;
    fn contains(&self, terminal_id: Uuid) -> bool;
    fn sweep_idle(&self, now: Instant) -> Vec<Uuid>;
}

#[derive(Clone)]
pub struct TerminalHostFactory {
    build:
        Arc<dyn Fn(EventSender, SharedRedactionTable, PathBuf) -> TerminalHostHandle + Send + Sync>,
}

impl TerminalHostFactory {
    pub fn new(
        build: impl Fn(EventSender, SharedRedactionTable, PathBuf) -> TerminalHostHandle
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            build: Arc::new(build),
        }
    }

    pub fn build(
        &self,
        events: EventSender,
        redaction: SharedRedactionTable,
        temp_root: PathBuf,
    ) -> TerminalHostHandle {
        (self.build)(events, redaction, temp_root)
    }
}

static DEFAULT_FACTORY: OnceLock<TerminalHostFactory> = OnceLock::new();

pub fn install_default_host_factory(factory: TerminalHostFactory) {
    let _ = DEFAULT_FACTORY.set(factory);
}

pub fn default_host_factory() -> TerminalHostFactory {
    DEFAULT_FACTORY
        .get()
        .cloned()
        .unwrap_or_else(unsupported_host_factory)
}

fn unsupported_host_factory() -> TerminalHostFactory {
    TerminalHostFactory::new(|_events, _redaction, _temp_root| Arc::new(UnsupportedTerminalHost))
}

#[derive(Debug)]
struct UnsupportedTerminalHost;

impl TerminalHost for UnsupportedTerminalHost {
    fn open(&self, _cwd: Option<String>, _cols: u16, _rows: u16) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn attach(&self, _terminal_id: Uuid, _cols: u16, _rows: u16) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn release_viewer(&self, _terminal_id: Uuid) {}

    fn input(&self, _terminal_id: Uuid, _bytes: Vec<u8>) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn resize(&self, _terminal_id: Uuid, _cols: u16, _rows: u16) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn close(&self, _terminal_id: Uuid) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn paste_image(&self, _terminal_id: Uuid, _bytes: &[u8]) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn contains(&self, _terminal_id: Uuid) -> bool {
        false
    }

    fn sweep_idle(&self, _now: Instant) -> Vec<Uuid> {
        Vec::new()
    }
}

fn unsupported_terminal_host() -> ErrorPayload {
    ErrorPayload {
        code: crate::daemon::proto::ErrorCode::Internal,
        message: "terminal host is not installed".to_string(),
    }
}

#[cfg(test)]
pub(crate) fn test_host_factory() -> TerminalHostFactory {
    TerminalHostFactory::new(|_events, _redaction, _temp_root| Arc::new(TestTerminalHost))
}

#[cfg(test)]
#[derive(Debug)]
struct TestTerminalHost;

#[cfg(test)]
impl TerminalHost for TestTerminalHost {
    fn open(&self, _cwd: Option<String>, _cols: u16, _rows: u16) -> TerminalResult {
        Ok(Response::TerminalOpened {
            terminal_id: Uuid::new_v4(),
            viewer_count: 1,
            recording: false,
        })
    }

    fn attach(&self, terminal_id: Uuid, _cols: u16, _rows: u16) -> TerminalResult {
        Ok(Response::TerminalOpened {
            terminal_id,
            viewer_count: 1,
            recording: false,
        })
    }

    fn release_viewer(&self, _terminal_id: Uuid) {}

    fn input(&self, _terminal_id: Uuid, _bytes: Vec<u8>) -> TerminalResult {
        Ok(Response::Ack)
    }

    fn resize(&self, _terminal_id: Uuid, _cols: u16, _rows: u16) -> TerminalResult {
        Ok(Response::Ack)
    }

    fn close(&self, _terminal_id: Uuid) -> TerminalResult {
        Ok(Response::Ack)
    }

    fn paste_image(&self, terminal_id: Uuid, _bytes: &[u8]) -> TerminalResult {
        Ok(Response::TerminalPasteImage {
            terminal_id,
            path: String::new(),
        })
    }

    fn contains(&self, _terminal_id: Uuid) -> bool {
        true
    }

    fn sweep_idle(&self, _now: Instant) -> Vec<Uuid> {
        Vec::new()
    }
}
