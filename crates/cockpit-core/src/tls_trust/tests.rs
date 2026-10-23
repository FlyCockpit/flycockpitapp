use std::sync::atomic::{AtomicUsize, Ordering};

use rcgen::{CertifiedKey, PublicKeyData, generate_simple_self_signed};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};

use super::*;

const COMPROMISED_PEM: &[u8] = include_bytes!("testdata/emudhra-compromised-intermediates.pem");

fn compromised_certificates() -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(COMPROMISED_PEM)
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture PEM parses")
}

fn spki_sha256(cert: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(der::subject_public_key_info(cert).expect("SPKI located"));
    <[u8; 32]>::try_from(digest.as_slice()).expect("SHA-256 is 32 bytes")
}

#[test]
fn every_published_compromised_emudhra_certificate_is_distrusted() {
    let certs = compromised_certificates();
    // 8 keys, each issued by its eMudhra root and cross-signed by Sectigo AAA.
    assert_eq!(certs.len(), 16);
    let mut keys = std::collections::BTreeSet::new();
    for cert in &certs {
        assert!(is_distrusted_certificate(cert.as_ref()));
        keys.insert(spki_sha256(cert.as_ref()));
    }
    // Every list entry is backed by a published certificate, and vice versa.
    let listed: std::collections::BTreeSet<_> = DISTRUSTED_SPKI_SHA256.into_iter().collect();
    assert_eq!(keys, listed);
}

#[test]
fn spki_extraction_matches_the_key_pair_encoding() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["spki.example.test".into()]).unwrap();
    assert_eq!(
        der::subject_public_key_info(cert.der().as_ref()),
        Some(signing_key.subject_public_key_info().as_slice())
    );
    assert!(!is_distrusted_certificate(cert.der().as_ref()));
}

#[test]
fn malformed_der_is_not_distrusted_and_does_not_panic() {
    let cert = compromised_certificates().remove(0);
    let bytes = cert.as_ref();
    for len in 0..bytes.len() {
        assert!(!is_distrusted_certificate(&bytes[..len]));
    }
    assert!(!is_distrusted_certificate(&[
        0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF
    ]));
    assert!(!is_distrusted_certificate(&[0x30, 0x80, 0x00, 0x00]));
}

/// Inner verifier that accepts everything and counts how often it was asked.
#[derive(Debug, Default)]
struct AcceptAll {
    calls: AtomicUsize,
}

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

#[test]
fn distrusting_verifier_rejects_compromised_keys_before_the_inner_verifier() {
    let inner = Arc::new(AcceptAll::default());
    let verifier = DistrustingVerifier::new(inner.clone());
    let leaf = generate_simple_self_signed(vec!["leaf.example.test".into()])
        .unwrap()
        .cert
        .der()
        .clone();
    let name = ServerName::try_from("leaf.example.test").unwrap();
    let now = UnixTime::now();

    for compromised in compromised_certificates() {
        // As a presented intermediate (either the eMudhra or the AAA cross-sign).
        assert_eq!(
            verifier
                .verify_server_cert(&leaf, &[compromised.clone()], &name, &[], now)
                .unwrap_err(),
            rustls::Error::InvalidCertificate(CertificateError::Revoked)
        );
        // As the end-entity position.
        assert_eq!(
            verifier
                .verify_server_cert(&compromised, &[], &name, &[], now)
                .unwrap_err(),
            rustls::Error::InvalidCertificate(CertificateError::Revoked)
        );
    }
    assert_eq!(inner.calls.load(Ordering::SeqCst), 0);

    // A clean chain is delegated unchanged.
    assert!(
        verifier
            .verify_server_cert(&leaf, &[], &name, &[], now)
            .is_ok()
    );
    assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
}

/// Drive a full in-memory TLS handshake with Cockpit's production client
/// config (platform verifier + distrust list) against a server presenting
/// `chain`; the leaf is trusted as an extra root.
fn handshake(
    chain: Vec<CertificateDer<'static>>,
    key: PrivatePkcs8KeyDer<'static>,
) -> Result<(), rustls::Error> {
    crate::tls_crypto_provider::install_for_tests();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain.clone(), key.into())
        .unwrap();
    let client_config = client_config(vec![chain[0].clone()]).expect("client config");
    let mut client = rustls::ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("trust.example.test").unwrap(),
    )
    .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
    for _ in 0..16 {
        let mut buf = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        server.read_tls(&mut buf.as_slice()).unwrap();
        server.process_new_packets()?;
        let mut buf = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        client.read_tls(&mut buf.as_slice()).unwrap();
        client.process_new_packets()?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("handshake did not complete");
}

#[test]
fn production_client_config_rejects_a_chain_carrying_a_compromised_intermediate() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["trust.example.test".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());

    // Control: the same server without the compromised certificate verifies.
    handshake(vec![cert.der().clone()], key.clone_key()).expect("clean chain verifies");

    for compromised in compromised_certificates() {
        assert_eq!(
            handshake(vec![cert.der().clone(), compromised], key.clone_key()),
            Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
        );
    }
}

#[test]
fn invalid_extra_root_is_a_hard_failure() {
    assert!(matches!(
        client_config(vec![CertificateDer::from(vec![0x30, 0x82, 0x01])]),
        Err(TlsTrustError::InvalidExtraRoot)
    ));
}

#[test]
fn reqwest_builder_fails_closed_without_a_trust_config() {
    assert!(
        reqwest_builder_from(Err(TlsTrustError::MissingCryptoProvider))
            .build()
            .is_err()
    );
    assert!(reqwest_client_builder().build().is_ok());
}
