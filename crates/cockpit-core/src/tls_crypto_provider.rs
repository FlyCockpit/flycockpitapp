//! Process-global rustls crypto provider — `aws_lc_rs` only.
//!
//! Every rustls user in the daemon/CLI process (TURN TLS via
//! `turn-client-rustls`, media HTTPS test servers, and any future direct
//! rustls client) shares **one** process-global [`rustls::crypto::CryptoProvider`],
//! and that provider is `aws_lc_rs` (USER-SETTLED, 2026-08-11).
//!
//! `ring` is never installed as the process default; it may remain only as a
//! transitive dependency of non-rustls crates (e.g. the Noise stack). OpenSSL
//! and native-TLS remain forbidden.
//!
//! # Contract
//!
//! - [`install_process_default`] installs `aws_lc_rs` exactly once via a
//!   [`std::sync::Once`] and is safe to call from production startup and from
//!   any test that needs rustls.
//! - It **fails closed** on a conflict: if a different `CryptoProvider` was
//!   already installed as the process default before the first call here, the
//!   helper returns [`CryptoProviderError::Conflict`] rather than silently
//!   accepting a foreign provider. Because every sanctioned install site routes
//!   through this one helper (which only ever installs `aws_lc_rs`), a conflict
//!   can only originate from unsanctioned code.
//! - The `aws_lc_rs` provider is installed **before** any rustls client config
//!   is built (TURN TLS or otherwise), so `turn-client-rustls` never relies on
//!   an implicit default.

use std::sync::{Once, OnceLock};

/// Error installing the process-global rustls crypto provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoProviderError {
    /// A different `CryptoProvider` was already installed as the process
    /// default before this helper ran. Fail closed rather than accept a
    /// provider this workspace did not sanction.
    #[error("a conflicting rustls CryptoProvider is already installed as the process default")]
    Conflict,
}

static INSTALL: Once = Once::new();
static RESULT: OnceLock<Result<(), CryptoProviderError>> = OnceLock::new();

/// Install `aws_lc_rs` as the process-global rustls crypto provider.
///
/// Idempotent: the first call performs the install; every later call returns
/// the same recorded result. Fails closed if a foreign provider was already
/// the process default when the first call ran.
pub fn install_process_default() -> Result<(), CryptoProviderError> {
    INSTALL.call_once(|| {
        // If a default is already present before we ever installed, it was set
        // by unsanctioned code — fail closed.
        let outcome = if rustls::crypto::CryptoProvider::get_default().is_some() {
            Err(CryptoProviderError::Conflict)
        } else {
            match rustls::crypto::aws_lc_rs::default_provider().install_default() {
                Ok(()) => Ok(()),
                // A concurrent installer won the race between our check and our
                // install. Since our helper only installs `aws_lc_rs`, treat a
                // provider we did not set as a conflict.
                Err(_) => Err(CryptoProviderError::Conflict),
            }
        };
        let _ = RESULT.set(outcome);
    });
    *RESULT.get().expect("install_process_default set RESULT")
}

/// Test-only alias with a panicking contract: the shared `aws_lc_rs` provider
/// must install cleanly in a test process (this helper is the only sanctioned
/// installer, so there is nothing to conflict with).
#[cfg(test)]
pub(crate) fn install_for_tests() {
    install_process_default().expect("aws_lc_rs crypto provider must install for tests");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_crypto_provider_installs_aws_lc_rs_once_and_is_idempotent() {
        // First install succeeds and sets a process default.
        assert_eq!(install_process_default(), Ok(()));
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "a process-global crypto provider must be installed"
        );
        // Idempotent: repeat calls return the same Ok without a second install.
        assert_eq!(install_process_default(), Ok(()));

        // The installed provider must be usable to build a rustls client config
        // (a config build fails outright with no provider), proving the
        // aws_lc_rs default is live for turn-client-rustls / media HTTPS.
        let roots = rustls::RootCertStore::empty();
        let _config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
    }
}
