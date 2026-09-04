//! Service readiness and the platform-gated listener.
//!
//! **Reference-only:** the submit-only mTLS listener is not wired. On Unix the
//! `serve` subcommand fails with [`ServiceListenError::NotImplemented`]; on
//! non-Unix targets it fails with [`ServiceListenError::UnsupportedPlatform`].
//! Non-Unix workspace builds retain every codec, validator, pure state-machine
//! test and bootstrap parser so the contract surface stays compilable on the
//! workspace MSRV and Windows CI target.

use thiserror::Error;

/// Typed unsupported-platform error. The non-Unix service binary exits with
/// this before opening a listener.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "unsupported platform: tenant-authority service requires a Unix peer-credential/admin-socket adapter"
)]
pub struct UnsupportedPlatform;

/// Why `serve` cannot open the submit-only mTLS listener.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceListenError {
    #[error(transparent)]
    UnsupportedPlatform(UnsupportedPlatform),
    #[error(
        "not implemented: tenant-authority serve does not bind a submit-only mTLS listener yet"
    )]
    NotImplemented,
}

/// Service readiness state. Replicas fail readiness on epoch, registry,
/// policy or key divergence/rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceReadiness {
    /// All configured authorities are anchored and the replica is ready to
    /// serve operational signing.
    Ready,
    /// One or more authorities are pending watermark anchoring.
    Pending,
    /// The replica is not ready: epoch/registry/policy/key divergence or
    /// rollback, or bootstrap-pending.
    NotReady,
}

/// The tenant-authority service. Owns the closed handler table, key provider,
/// mTLS selection, and durable stores. The listener is not implemented yet;
/// [`Self::listen`] fails closed on every target.
#[derive(Debug)]
pub struct Service {
    readiness: ServiceReadiness,
}

impl Service {
    /// Construct a service that is not yet ready. Production startup performs
    /// PKCS#11 conformance, config/replica/credential validation, and
    /// watermark anchoring before transitioning to [`ServiceReadiness::Ready`].
    pub fn new() -> Self {
        Self {
            readiness: ServiceReadiness::NotReady,
        }
    }

    pub fn readiness(&self) -> ServiceReadiness {
        self.readiness
    }

    /// Mark the service ready. In production this follows successful
    /// conformance, config validation, and watermark anchoring.
    pub fn mark_ready(&mut self) {
        self.readiness = ServiceReadiness::Ready;
    }

    /// Open the submit-only mTLS listener. Not implemented on Unix; on non-Unix
    /// targets returns [`ServiceListenError::UnsupportedPlatform`].
    #[cfg(unix)]
    pub fn listen(&self, _addr: &str) -> Result<(), ServiceListenError> {
        // TODO(#378): bind HTTP/2 over TLS 1.3 with mandatory client
        // certificates via the audited rustls/hyper adapter.
        Err(ServiceListenError::NotImplemented)
    }

    #[cfg(not(unix))]
    pub fn listen(&self, _addr: &str) -> Result<(), ServiceListenError> {
        Err(ServiceListenError::UnsupportedPlatform(UnsupportedPlatform))
    }
}

impl Default for Service {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_starts_not_ready() {
        let s = Service::new();
        assert_eq!(s.readiness(), ServiceReadiness::NotReady);
    }

    #[test]
    fn service_can_become_ready() {
        let mut s = Service::new();
        s.mark_ready();
        assert_eq!(s.readiness(), ServiceReadiness::Ready);
    }

    #[test]
    fn listen_fails_closed() {
        let s = Service::new();
        let res = s.listen("127.0.0.1:8443");
        #[cfg(unix)]
        assert_eq!(res, Err(ServiceListenError::NotImplemented));
        #[cfg(not(unix))]
        assert_eq!(
            res,
            Err(ServiceListenError::UnsupportedPlatform(UnsupportedPlatform))
        );
    }
}
