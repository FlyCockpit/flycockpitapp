//! Process-wide TLS server-trust policy for every Cockpit-owned TLS client.
//!
//! Every outbound TLS connection Cockpit makes itself (all `reqwest` clients,
//! the daemon websocket connector, TURN-over-TLS) builds its
//! [`rustls::ClientConfig`] here, so the trust decision lives in one place:
//!
//! 1. **OS trust store** via `rustls-platform-verifier`. On macOS and Windows
//!    the platform verifier delegates to Security.framework / CryptoAPI, so OS
//!    revocation (Apple valid, Microsoft disallowed-cert CTL) applies. On Linux
//!    it verifies with `rustls-webpki` against the system CA bundle.
//! 2. **Explicit key distrust** ([`DISTRUSTED_SPKI_SHA256`]): any presented
//!    certificate whose SubjectPublicKeyInfo hashes to a distrusted key is
//!    rejected as revoked *before* the platform verifier runs. This is the same
//!    key-based block Go, Chrome's CRLSet and `rustls-webpki` 0.103.16 apply, and
//!    it covers cross-signs of the same key under roots that stay trusted
//!    (e.g. Sectigo "AAA Certificate Services"), which no root-store update can
//!    block. It does not depend on the host OS or CA bundle being patched.
//!
//! Limitation: the distrust check sees the chain the server presents. A
//! platform verifier that fetches a missing intermediate itself (AIA on
//! macOS/Windows) can complete a path our check never sees; those platforms
//! block the compromised intermediates through their own revocation data.
//! On Linux path building is done by `rustls-webpki` (>= 0.103.16), which
//! applies the same distrust list to every candidate path.

use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

mod der;

/// SHA-256 of the DER SubjectPublicKeyInfo of every explicitly distrusted CA key.
///
/// CVE-2026-111943 (disclosed 2026-10-20): the private keys of eight eMudhra
/// intermediate CAs were generated with weak entropy and are recoverable from
/// the certificates. Each key exists as a certificate issued by its eMudhra
/// root and as a Sectigo "AAA Certificate Services" cross-sign; blocking by key
/// covers both. Values from
/// <https://emudhra.we-have-a-problem.com/impacted-intermediates.json>,
/// re-derived from the published certificates and identical to
/// `rustls-webpki` 0.103.16's `DISTRUSTED_SPKIS`.
pub const DISTRUSTED_SPKI_SHA256: [[u8; 32]; 8] = [
    // EM DV TLS CA - G3B
    hex32("EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105"),
    // EM OV TLS CA - G3B
    hex32("43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B"),
    // EM EV TLS CA - G3B
    hex32("E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41"),
    // EM DV TLS CA - G3C
    hex32("49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F"),
    // EM OV TLS CA - G3C
    hex32("63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8"),
    // EM EV TLS CA - G3C
    hex32("5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0"),
    // EM OV CS CA - G3B
    hex32("EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6"),
    // EM OV CS CA - G3C
    hex32("92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30"),
];

const fn hex32(hex: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("DISTRUSTED_SPKI_SHA256 entries are upper-case hex"),
        }
    }
    let bytes = hex.as_bytes();
    assert!(
        bytes.len() == 64,
        "DISTRUSTED_SPKI_SHA256 entries are 32 bytes"
    );
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

/// Error building Cockpit's TLS client configuration.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TlsTrustError {
    #[error("installing the process rustls crypto provider failed")]
    CryptoProvider,
    #[error("no process rustls crypto provider is installed")]
    MissingCryptoProvider,
    #[error("an additional trust anchor is not a valid certificate")]
    InvalidExtraRoot,
    #[error("building the platform certificate verifier failed: {0}")]
    PlatformVerifier(String),
    #[error("building the rustls client configuration failed: {0}")]
    ClientConfig(String),
}

/// True when `cert_der`'s SubjectPublicKeyInfo is explicitly distrusted.
/// Certificates that cannot be parsed are left to the inner verifier.
pub fn is_distrusted_certificate(cert_der: &[u8]) -> bool {
    der::subject_public_key_info(cert_der)
        .map(|spki| {
            let digest = Sha256::digest(spki);
            DISTRUSTED_SPKI_SHA256
                .iter()
                .any(|distrusted| distrusted.as_slice() == digest.as_slice())
        })
        .unwrap_or(false)
}

/// Wraps a [`ServerCertVerifier`] and rejects any presented chain containing
/// an explicitly distrusted key, before delegating.
#[derive(Debug)]
pub struct DistrustingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
}

impl DistrustingVerifier {
    pub fn new(inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self { inner }
    }
}

impl ServerCertVerifier for DistrustingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if std::iter::once(end_entity)
            .chain(intermediates)
            .any(|cert| is_distrusted_certificate(cert.as_ref()))
        {
            return Err(rustls::Error::InvalidCertificate(CertificateError::Revoked));
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// Build a rustls client config trusting the OS store (plus `extra_roots`,
/// which augment and never replace it) behind the explicit key distrust list.
/// ALPN is left empty; callers set it for their protocol.
pub fn client_config(
    extra_roots: Vec<CertificateDer<'static>>,
) -> Result<rustls::ClientConfig, TlsTrustError> {
    crate::tls_crypto_provider::install_process_default()
        .map_err(|_| TlsTrustError::CryptoProvider)?;
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .ok_or(TlsTrustError::MissingCryptoProvider)?;
    // An extra anchor that does not parse is a hard failure, never skipped.
    for root in &extra_roots {
        rustls::RootCertStore::empty()
            .add(root.clone())
            .map_err(|_| TlsTrustError::InvalidExtraRoot)?;
    }
    let platform = if extra_roots.is_empty() {
        rustls_platform_verifier::Verifier::new(provider.clone())
    } else {
        rustls_platform_verifier::Verifier::new_with_extra_roots(extra_roots, provider.clone())
    }
    .map_err(|error| TlsTrustError::PlatformVerifier(error.to_string()))?;
    let verifier = DistrustingVerifier::new(Arc::new(platform));
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| TlsTrustError::ClientConfig(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

/// The shared OS-store config (no extra roots), built once per process so the
/// platform verifier does not reload the system store for every client.
pub fn default_client_config() -> Result<Arc<rustls::ClientConfig>, TlsTrustError> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, TlsTrustError>> = OnceLock::new();
    CONFIG
        .get_or_init(|| client_config(Vec::new()).map(Arc::new))
        .clone()
}

/// Marker handed to reqwest when the trust config cannot be built. reqwest
/// does not recognise it, so `ClientBuilder::build()` fails: no client ever
/// falls back to reqwest's own verifier, which lacks the distrust list.
struct FailClosedTls;

fn reqwest_builder_from(
    config: Result<rustls::ClientConfig, TlsTrustError>,
) -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder();
    match config {
        Ok(mut config) => {
            // reqwest leaves ALPN to a preconfigured config; offer what
            // reqwest itself would (`http2` is enabled on the workspace reqwest).
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            builder.tls_backend_preconfigured(config)
        }
        Err(error) => {
            tracing::error!(%error, "TLS trust configuration unavailable; refusing to build HTTP client");
            builder.tls_backend_preconfigured(FailClosedTls)
        }
    }
}

/// The only sanctioned way to start a `reqwest::ClientBuilder` in Cockpit.
///
/// Do not call reqwest's own TLS options (`add_root_certificate`,
/// `tls_*`, `danger_*`) on the result: reqwest ignores them for a
/// preconfigured backend. Use [`reqwest_client_builder_with_extra_roots`].
pub fn reqwest_client_builder() -> reqwest::ClientBuilder {
    reqwest_builder_from(default_client_config().map(|config| (*config).clone()))
}

/// [`reqwest_client_builder`] with additional trust anchors that augment the
/// OS store (enterprise roots, test CAs).
pub fn reqwest_client_builder_with_extra_roots(
    extra_roots: Vec<CertificateDer<'static>>,
) -> reqwest::ClientBuilder {
    reqwest_builder_from(client_config(extra_roots))
}

#[cfg(test)]
mod tests;
