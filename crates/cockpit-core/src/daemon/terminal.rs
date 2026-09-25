use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

use uuid::Uuid;

use crate::daemon::proto::{ErrorPayload, Response};
use crate::daemon::{EventSender, SharedRedactionTable};

pub type TerminalResult = std::result::Result<Response, ErrorPayload>;
pub type TerminalHostHandle = Arc<dyn TerminalHost>;

/// Server-derived identity for terminal authority decisions. This type is
/// deliberately not part of `cockpit-proto`: clients can present only the
/// opaque binding capability issued after daemon authorization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticatedTerminalContext {
    pub principal_id: String,
    pub client_instance_id: Uuid,
    pub connection_epoch: u64,
}

/// Exact, host-retained bytes released by consuming one opaque terminal
/// ingress capability. Paths never cross the client protocol boundary.
#[derive(Debug)]
pub struct PrivateImageIngress {
    pub bytes: Vec<u8>,
    pub declared_sha256: String,
    pub media_type: crate::daemon::proto::terminal::TerminalImageType,
}

pub trait TerminalHost: std::fmt::Debug + Send + Sync {
    fn open(
        &self,
        context: AuthenticatedTerminalContext,
        session_id: Uuid,
        cwd: Option<String>,
        cols: u16,
        rows: u16,
    ) -> TerminalResult;
    fn attach(
        &self,
        context: AuthenticatedTerminalContext,
        session_id: Uuid,
        terminal_id: Uuid,
        cols: u16,
        rows: u16,
    ) -> TerminalResult;
    fn release_viewer(
        &self,
        terminal_id: Uuid,
        binding: crate::daemon::proto::terminal::TerminalBinding,
    );
    fn input(
        &self,
        terminal_id: Uuid,
        binding: crate::daemon::proto::terminal::TerminalBinding,
        bytes: Vec<u8>,
    ) -> TerminalResult;
    fn resize(
        &self,
        terminal_id: Uuid,
        binding: crate::daemon::proto::terminal::TerminalBinding,
        cols: u16,
        rows: u16,
    ) -> TerminalResult;
    fn close(
        &self,
        terminal_id: Uuid,
        binding: crate::daemon::proto::terminal::TerminalBinding,
    ) -> TerminalResult;
    fn ingress_begin(
        &self,
        terminal_id: Uuid,
        binding: crate::daemon::proto::terminal::TerminalBinding,
        metadata: crate::daemon::proto::terminal::TerminalIngressMetadata,
    ) -> TerminalResult;
    fn ingress_chunk(
        &self,
        terminal_id: Uuid,
        binding: crate::daemon::proto::terminal::TerminalBinding,
        operation_id: Uuid,
        offset: u64,
        bytes: Vec<u8>,
    ) -> TerminalResult;
    fn ingress_finish(
        &self,
        terminal_id: Uuid,
        binding: crate::daemon::proto::terminal::TerminalBinding,
        operation_id: Uuid,
    ) -> TerminalResult;
    fn ingress_status(
        &self,
        terminal_id: Uuid,
        binding: crate::daemon::proto::terminal::TerminalBinding,
        operation_id: Uuid,
    ) -> TerminalResult;
    /// Consume a capability minted by this host for the exact authenticated
    /// terminal owner and session. Implementations must make this one-shot,
    /// expiry-bound, root-bound, and reject pathname/object mutation.
    fn consume_private_image_ingress(
        &self,
        context: &AuthenticatedTerminalContext,
        session_id: Uuid,
        capability: &str,
    ) -> std::result::Result<PrivateImageIngress, ErrorPayload>;
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
    fn open(
        &self,
        _context: AuthenticatedTerminalContext,
        _session_id: Uuid,
        _cwd: Option<String>,
        _cols: u16,
        _rows: u16,
    ) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn attach(
        &self,
        _context: AuthenticatedTerminalContext,
        _session_id: Uuid,
        _terminal_id: Uuid,
        _cols: u16,
        _rows: u16,
    ) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn release_viewer(
        &self,
        _terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
    ) {
    }

    fn input(
        &self,
        _terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        _bytes: Vec<u8>,
    ) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn resize(
        &self,
        _terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        _cols: u16,
        _rows: u16,
    ) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn close(
        &self,
        _terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
    ) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn ingress_begin(
        &self,
        _terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        _metadata: crate::daemon::proto::terminal::TerminalIngressMetadata,
    ) -> TerminalResult {
        Err(unsupported_terminal_host())
    }
    fn ingress_chunk(
        &self,
        _terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        _operation_id: Uuid,
        _offset: u64,
        _bytes: Vec<u8>,
    ) -> TerminalResult {
        Err(unsupported_terminal_host())
    }
    fn ingress_finish(
        &self,
        _terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        _operation_id: Uuid,
    ) -> TerminalResult {
        Err(unsupported_terminal_host())
    }
    fn ingress_status(
        &self,
        _terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        _operation_id: Uuid,
    ) -> TerminalResult {
        Err(unsupported_terminal_host())
    }

    fn consume_private_image_ingress(
        &self,
        _context: &AuthenticatedTerminalContext,
        _session_id: Uuid,
        _capability: &str,
    ) -> std::result::Result<PrivateImageIngress, ErrorPayload> {
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
    TerminalHostFactory::new(
        |_events, _redaction, _temp_root| Arc::new(TestTerminalHost::default()),
    )
}

/// Contract-faithful in-memory fake of the CLI's PTY terminal host: no
/// process is spawned, but the observable protocol semantics match the real
/// host (`apps/cli/src/terminal_host.rs`) — `open` rejects a missing/non-dir
/// cwd with `RootMissing`, and every id-addressed operation rejects unknown
/// or closed terminals with `BadRequest` `unknown terminal {id}` — so daemon
/// server tests exercise the same error surface as production.
#[cfg(test)]
#[derive(Debug, Default)]
struct TestTerminalHost {
    open_terminals: std::sync::Mutex<std::collections::HashSet<Uuid>>,
}

#[cfg(test)]
fn test_unknown_terminal(terminal_id: Uuid) -> ErrorPayload {
    ErrorPayload {
        code: crate::daemon::proto::ErrorCode::BadRequest,
        message: format!("unknown terminal {terminal_id}"),
    }
}

#[cfg(test)]
impl TestTerminalHost {
    fn require_open(&self, terminal_id: Uuid) -> Result<(), ErrorPayload> {
        if self.open_terminals.lock().unwrap().contains(&terminal_id) {
            Ok(())
        } else {
            Err(test_unknown_terminal(terminal_id))
        }
    }
}

#[cfg(test)]
impl TerminalHost for TestTerminalHost {
    fn open(
        &self,
        _context: AuthenticatedTerminalContext,
        _session_id: Uuid,
        cwd: Option<String>,
        _cols: u16,
        _rows: u16,
    ) -> TerminalResult {
        // Same cwd validation as the real host's `resolve_cwd`, without
        // consulting the home directory for the `None` default.
        if let Some(cwd) = cwd
            && !std::path::Path::new(&cwd).is_dir()
        {
            return Err(ErrorPayload {
                code: crate::daemon::proto::ErrorCode::RootMissing,
                message: format!("terminal cwd `{cwd}` is unavailable"),
            });
        }
        let terminal_id = Uuid::new_v4();
        self.open_terminals.lock().unwrap().insert(terminal_id);
        Ok(Response::TerminalOpened {
            terminal_id,
            viewer_count: 1,
            recording: false,
            binding: crate::daemon::proto::terminal::TerminalBinding {
                binding_id: Uuid::nil(),
                binding_epoch: 1,
            },
            terminal_generation: 1,
        })
    }

    fn attach(
        &self,
        _context: AuthenticatedTerminalContext,
        _session_id: Uuid,
        terminal_id: Uuid,
        _cols: u16,
        _rows: u16,
    ) -> TerminalResult {
        self.require_open(terminal_id)?;
        Ok(Response::TerminalOpened {
            terminal_id,
            viewer_count: 1,
            recording: false,
            binding: crate::daemon::proto::terminal::TerminalBinding {
                binding_id: Uuid::nil(),
                binding_epoch: 1,
            },
            terminal_generation: 1,
        })
    }

    fn release_viewer(
        &self,
        _terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
    ) {
    }

    fn input(
        &self,
        terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        _bytes: Vec<u8>,
    ) -> TerminalResult {
        self.require_open(terminal_id)?;
        Ok(Response::Ack)
    }

    fn resize(
        &self,
        terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        _cols: u16,
        _rows: u16,
    ) -> TerminalResult {
        self.require_open(terminal_id)?;
        Ok(Response::Ack)
    }

    fn close(
        &self,
        terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
    ) -> TerminalResult {
        if self.open_terminals.lock().unwrap().remove(&terminal_id) {
            Ok(Response::Ack)
        } else {
            Err(test_unknown_terminal(terminal_id))
        }
    }

    fn ingress_begin(
        &self,
        terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        metadata: crate::daemon::proto::terminal::TerminalIngressMetadata,
    ) -> TerminalResult {
        self.require_open(terminal_id)?;
        Ok(Response::TerminalIngress {
            receipt: crate::daemon::proto::terminal::TerminalIngressReceipt {
                operation_id: metadata.operation_id,
                state: crate::daemon::proto::terminal::TerminalIngressState::Prepared,
                next_offset: 0,
                input_sequence: None,
                expires_at_unix_ms: None,
            },
        })
    }
    fn ingress_chunk(
        &self,
        terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        operation_id: Uuid,
        offset: u64,
        bytes: Vec<u8>,
    ) -> TerminalResult {
        self.require_open(terminal_id)?;
        Ok(Response::TerminalIngress {
            receipt: crate::daemon::proto::terminal::TerminalIngressReceipt {
                operation_id,
                state: crate::daemon::proto::terminal::TerminalIngressState::Prepared,
                next_offset: offset + bytes.len() as u64,
                input_sequence: None,
                expires_at_unix_ms: None,
            },
        })
    }
    fn ingress_finish(
        &self,
        terminal_id: Uuid,
        _binding: crate::daemon::proto::terminal::TerminalBinding,
        operation_id: Uuid,
    ) -> TerminalResult {
        self.require_open(terminal_id)?;
        Ok(Response::TerminalIngress {
            receipt: crate::daemon::proto::terminal::TerminalIngressReceipt {
                operation_id,
                state: crate::daemon::proto::terminal::TerminalIngressState::Committed,
                next_offset: 0,
                input_sequence: Some(1),
                expires_at_unix_ms: None,
            },
        })
    }
    fn ingress_status(
        &self,
        terminal_id: Uuid,
        binding: crate::daemon::proto::terminal::TerminalBinding,
        operation_id: Uuid,
    ) -> TerminalResult {
        self.ingress_finish(terminal_id, binding, operation_id)
    }

    fn consume_private_image_ingress(
        &self,
        _context: &AuthenticatedTerminalContext,
        _session_id: Uuid,
        _capability: &str,
    ) -> std::result::Result<PrivateImageIngress, ErrorPayload> {
        Err(ErrorPayload {
            code: crate::daemon::proto::ErrorCode::BadRequest,
            message: "private image ingress capability is unavailable".into(),
        })
    }

    fn contains(&self, terminal_id: Uuid) -> bool {
        self.open_terminals.lock().unwrap().contains(&terminal_id)
    }

    fn sweep_idle(&self, _now: Instant) -> Vec<Uuid> {
        Vec::new()
    }
}
