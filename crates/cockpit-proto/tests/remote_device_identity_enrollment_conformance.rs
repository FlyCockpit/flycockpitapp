//! Cross-language conformance for the remote device identity enrollment
//! protocol surface: SAS-V1 committed vectors, enrollment discovery-link
//! exact bytes/order/length/origin, foundation consumption guard, and the
//! closed enrollment/certificate-lifecycle/revocation state/reason matrix.
//!
//! The SAS vectors are checked into
//! packages/cockpit-protocol/fixtures/remote-device-enrollment-sas-v1.json and
//! consumed identically by the TypeScript mirror. This test name is exactly
//! `remote_device_identity_enrollment_sas_v1_vectors`.

use cockpit_proto::remote_device_identity_enrollment::*;
use sha2::{Digest, Sha256};

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn unhex32(value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&unhex(value));
    out
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SasFixture {
    schema_version: u64,
    salt_preimage_hex: String,
    salt_digest_hex: String,
    info_preimage_hex: String,
    forbidden_escape_hex: String,
    okm_len: usize,
    block_count: usize,
    reject_threshold: u64,
    modulus: u64,
    vectors: Vec<SasVector>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SasVector {
    name: String,
    transcript_digest_hex: String,
    accepted_index: usize,
    accepted_block_hex: String,
    accepted_block_integer: u64,
    sas: String,
    digits: String,
    #[serde(default)]
    rejected_blocks: Vec<RejectedBlock>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RejectedBlock {
    index: usize,
    block_hex: String,
    block_integer: u64,
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    let mut s = String::with_capacity(bytes.as_ref().len() * 2);
    for b in bytes.as_ref() {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

fn b64url(bytes: impl AsRef<[u8]>) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(bytes.as_ref())
}

#[test]
fn remote_device_identity_enrollment_sas_v1_vectors() {
    let fixture: SasFixture = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote-device-enrollment-sas-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture.schema_version, 1);

    // Committed salt/info preimages match the canonical builders byte-for-byte.
    assert_eq!(sas_v1_salt_preimage(), unhex(&fixture.salt_preimage_hex));
    assert_eq!(sas_v1_info_preimage(), unhex(&fixture.info_preimage_hex));

    // Committed salt digest matches SHA-256(salt preimage).
    let salt_digest = Sha256::digest(sas_v1_salt_preimage());
    assert_eq!(hex_encode(salt_digest), fixture.salt_digest_hex);
    assert_eq!(salt_digest.as_slice(), SAS_V1_SALT_DIGEST);

    // Replacing either 0x00 separator with the forbidden 5c30 escape must fail.
    let forbidden = unhex(&fixture.forbidden_escape_hex);
    assert_eq!(forbidden, SAS_V1_FORBIDDEN_ESCAPE);
    let mut bad_salt = sas_v1_salt_preimage();
    let nul_pos = bad_salt
        .iter()
        .position(|&b| b == SAS_V1_NUL)
        .expect("salt preimage has a NUL separator");
    bad_salt.splice(nul_pos..nul_pos + 1, forbidden.clone());
    assert!(validate_sas_preimage(&bad_salt).is_err());

    let mut bad_info = sas_v1_info_preimage();
    let nul_pos_info = bad_info
        .iter()
        .position(|&b| b == SAS_V1_NUL)
        .expect("info preimage has a NUL separator");
    bad_info.splice(nul_pos_info..nul_pos_info + 1, forbidden);
    assert!(validate_sas_preimage(&bad_info).is_err());

    // Canonical preimages contain no backslash or ASCII '0' and validate.
    assert!(validate_sas_preimage(&sas_v1_salt_preimage()).is_ok());
    assert!(validate_sas_preimage(&sas_v1_info_preimage()).is_ok());

    // OKM length and block count.
    assert_eq!(SAS_V1_OKM_LEN, fixture.okm_len);
    assert_eq!(SAS_V1_BLOCK_COUNT, fixture.block_count);
    assert_eq!(SAS_V1_REJECT_THRESHOLD, fixture.reject_threshold);
    assert_eq!(SAS_V1_MODULUS, fixture.modulus);

    for vector in &fixture.vectors {
        let digest = unhex32(&vector.transcript_digest_hex);
        let okm = sas_v1_okm(&digest);
        assert_eq!(okm.len(), fixture.okm_len);

        // Verify each explicitly rejected block matches and is >= threshold.
        for rejected in &vector.rejected_blocks {
            let block = &okm[rejected.index * 5..rejected.index * 5 + 5];
            assert_eq!(hex_encode(block), rejected.block_hex);
            let mut buf = [0u8; 8];
            buf[3..8].copy_from_slice(block);
            let value = u64::from_be_bytes(buf);
            assert_eq!(value, rejected.block_integer);
            assert!(value >= fixture.reject_threshold);
        }

        let sas = derive_sas_v1(&digest)
            .unwrap_or_else(|e| panic!("SAS derivation for {} failed: {e}", vector.name));
        assert_eq!(
            sas.accepted_index, vector.accepted_index,
            "accepted index for {}",
            vector.name
        );
        assert_eq!(
            sas.accepted_block, vector.accepted_block_integer,
            "accepted block for {}",
            vector.name
        );
        // The accepted block's hex must match the committed five-byte block.
        let mut block_buf = [0u8; 8];
        block_buf[3..8]
            .copy_from_slice(&okm[vector.accepted_index * 5..vector.accepted_index * 5 + 5]);
        assert_eq!(
            hex_encode(&block_buf[3..8]),
            vector.accepted_block_hex,
            "accepted block hex for {}",
            vector.name
        );
        assert_eq!(sas.digits, vector.digits, "digits for {}", vector.name);
        assert_eq!(sas.display(), vector.sas, "display for {}", vector.name);
    }

    // Derivation is deterministic.
    let zero = [0u8; 32];
    let first = derive_sas_v1(&zero).unwrap();
    let second = derive_sas_v1(&zero).unwrap();
    assert_eq!(first, second);
}

/// Static detector: returns a reason when `source` *defines* (not merely uses
/// or imports) a second local copy of a foundation-owned identity schema/enum,
/// an alternate FCIP/FCEN/FCCE/FCPC/FCPP/FCCF magic, or a foundation
/// challenge/signature-input function. Only top-level items are inspected, so
/// example patterns inside function bodies are not matched.
fn scan_for_second_identity_definition(source: &str) -> Option<String> {
    const FORBIDDEN_TYPES: &[&str] = &[
        "EnrollmentTranscript",
        "Proposal",
        "CustodyEvidence",
        "PossessionContext",
        "PossessionProof",
        "EnrollmentConfirmation",
        "PossessionPurpose",
        "SubjectKind",
        "CustodyClass",
        "PresenceMode",
        "EnrollmentRole",
    ];
    const FORBIDDEN_MAGICS: &[&str] = &["FCIP", "FCEN", "FCCE", "FCPC", "FCPP", "FCCF"];
    const FORBIDDEN_FNS: &[&str] = &[
        "parse_remote_identity_certificate_jws",
        "derive_possession_challenge",
        "possession_proof_signing_digest",
        "enrollment_confirmation_signing_digest",
    ];
    // Match a magic by literal VALUE (`b"FCEN"`/`"FCEN"`) as well as by name, so a
    // rename like `const ALT: &[u8] = b"FCEN";` cannot bypass the guard.
    fn lit_matches_magic(expr: &syn::Expr, magics: &[&str]) -> bool {
        let bytes: Vec<u8> = match expr {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::ByteStr(bs),
                ..
            }) => bs.value(),
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) => s.value().into_bytes(),
            syn::Expr::Reference(r) => return lit_matches_magic(&r.expr, magics),
            _ => return false,
        };
        magics.iter().any(|m| m.as_bytes() == bytes.as_slice())
    }
    let file = syn::parse_file(source).expect("scanned source parses");
    for item in &file.items {
        let flagged = match item {
            syn::Item::Struct(item)
                if FORBIDDEN_TYPES.contains(&item.ident.to_string().as_str()) =>
            {
                Some(format!("second local identity struct `{}`", item.ident))
            }
            syn::Item::Enum(item) if FORBIDDEN_TYPES.contains(&item.ident.to_string().as_str()) => {
                Some(format!("second local identity enum `{}`", item.ident))
            }
            syn::Item::Const(item)
                if FORBIDDEN_MAGICS.contains(&item.ident.to_string().as_str())
                    || lit_matches_magic(&item.expr, FORBIDDEN_MAGICS) =>
            {
                Some(format!("second local identity magic `{}`", item.ident))
            }
            syn::Item::Static(item)
                if FORBIDDEN_MAGICS.contains(&item.ident.to_string().as_str())
                    || lit_matches_magic(&item.expr, FORBIDDEN_MAGICS) =>
            {
                Some(format!("second local identity magic `{}`", item.ident))
            }
            syn::Item::Fn(item) if FORBIDDEN_FNS.contains(&item.sig.ident.to_string().as_str()) => {
                Some(format!(
                    "second local identity signature-input fn `{}`",
                    item.sig.ident
                ))
            }
            _ => None,
        };
        if flagged.is_some() {
            return flagged;
        }
    }
    None
}

#[test]
fn remote_identity_protocol_consumption_guard() {
    // Closed-surface cardinality still holds.
    closed_surface_guard();

    // Static source scan: the enrollment module must not redefine any
    // foundation identity schema/enum/challenge/signature-input.
    let source = include_str!("../src/remote_device_identity_enrollment.rs");
    assert_eq!(
        scan_for_second_identity_definition(source),
        None,
        "enrollment module must not redefine a foundation identity schema"
    );

    // Non-vacuity: planted second definitions are caught; a usage/import is not.
    assert!(
        scan_for_second_identity_definition("pub struct EnrollmentTranscript { pub id: [u8; 16] }")
            .is_some()
    );
    assert!(scan_for_second_identity_definition("const FCEN: &[u8] = b\"FCEN\";").is_some());
    assert!(
        scan_for_second_identity_definition("pub enum PossessionPurpose { EnrollProposed }")
            .is_some()
    );
    assert!(
        scan_for_second_identity_definition(
            "use crate::remote_identity_protocol::EnrollmentTranscript;"
        )
        .is_none()
    );
}

#[test]
fn remote_device_identity_enrollment_link_contract() {
    let origin = "https://enroll.flycockpit.example";
    let enrollment_id = [0x11; 16];
    let capability = [0x22; 32];
    let link = build_discovery_link(origin, enrollment_id, capability).unwrap();

    // Exact HTTPS link bytes/order/length/origin.
    let url = link.https_url();
    assert_eq!(
        url,
        format!(
            "https://enroll.flycockpit.example/remote/enroll?v=1&id={}&cap={}",
            b64url(enrollment_id),
            b64url(capability),
        )
    );
    let parsed = parse_https_enrollment_link(&url).unwrap();
    assert_eq!(parsed, link);

    // Exact typed deep link.
    let deep = link.deep_link();
    assert_eq!(
        deep,
        format!(
            "flycockpit://remote/enroll?v=1&id={}&cap={}",
            b64url(enrollment_id),
            b64url(capability),
        )
    );
    let parsed_deep = parse_deep_enrollment_link(&deep).unwrap();
    assert_eq!(parsed_deep.enrollment_id, enrollment_id);
    assert_eq!(parsed_deep.discovery_capability, capability);

    // Malformed/extra/padded variants reject.
    assert!(parse_https_enrollment_link(&format!("{url}&extra=1")).is_err());
    assert!(parse_https_enrollment_link(&url.replace("v=1", "v=2")).is_err());
    assert!(parse_https_enrollment_link(&url.replace("/remote/enroll", "/Remote/Enroll")).is_err());
    assert!(parse_https_enrollment_link(&url.replacen("https://", "http://", 1)).is_err());
    assert!(parse_https_enrollment_link(&format!("{url}#frag")).is_err());
    assert!(parse_deep_enrollment_link(&format!("{deep}#frag")).is_err());

    // Noncanonical origins reject.
    assert!(
        build_discovery_link(
            "https://Enroll.flycockpit.example",
            enrollment_id,
            capability
        )
        .is_err()
    );
    assert!(
        build_discovery_link(
            "https://enroll.flycockpit.example:443",
            enrollment_id,
            capability
        )
        .is_err()
    );
    assert!(
        build_discovery_link(
            "http://enroll.flycockpit.example",
            enrollment_id,
            capability
        )
        .is_err()
    );
    assert!(
        build_discovery_link(
            "https://enroll.flycockpit.example/",
            enrollment_id,
            capability
        )
        .is_err()
    );

    // Zero IDs reject (high-entropy nonzero required).
    assert!(build_discovery_link(origin, [0; 16], capability).is_err());
    assert!(build_discovery_link(origin, enrollment_id, [0; 32]).is_err());
}

#[test]
fn remote_device_identity_enrollment_state_reason_matrix() {
    // Every non-terminal enrollment state has a null terminal reason.
    for state in EnrollmentState::ALL {
        assert_eq!(
            state.null_terminal_reason(),
            !state.requires_terminal_reason()
        );
        if state.requires_terminal_reason() {
            assert!(matches!(
                state,
                EnrollmentState::Rejected
                    | EnrollmentState::Expired
                    | EnrollmentState::Cancelled
                    | EnrollmentState::Superseded
            ));
        }
    }
    // Legal pairs.
    assert!(
        EnrollmentTerminalReason::ExplicitReject
            .validate_pair(EnrollmentState::Rejected)
            .is_ok()
    );
    assert!(
        EnrollmentTerminalReason::MismatchLimit
            .validate_pair(EnrollmentState::Rejected)
            .is_ok()
    );
    assert!(
        EnrollmentTerminalReason::PolicyDenied
            .validate_pair(EnrollmentState::Rejected)
            .is_ok()
    );
    assert!(
        EnrollmentTerminalReason::IssuanceFailed
            .validate_pair(EnrollmentState::Rejected)
            .is_ok()
    );
    assert!(
        EnrollmentTerminalReason::Expired
            .validate_pair(EnrollmentState::Expired)
            .is_ok()
    );
    assert!(
        EnrollmentTerminalReason::Cancelled
            .validate_pair(EnrollmentState::Cancelled)
            .is_ok()
    );
    assert!(
        EnrollmentTerminalReason::Superseded
            .validate_pair(EnrollmentState::Superseded)
            .is_ok()
    );
    // Illegal pairs: mismatched reason/state.
    assert!(
        EnrollmentTerminalReason::Expired
            .validate_pair(EnrollmentState::Rejected)
            .is_err()
    );
    assert!(
        EnrollmentTerminalReason::ExplicitReject
            .validate_pair(EnrollmentState::Issued)
            .is_err()
    );
    assert!(
        EnrollmentTerminalReason::MismatchLimit
            .validate_pair(EnrollmentState::Expired)
            .is_err()
    );
    assert!(
        EnrollmentTerminalReason::Superseded
            .validate_pair(EnrollmentState::Cancelled)
            .is_err()
    );

    // Certificate operation matrix.
    for state in CertificateOperationState::ALL {
        assert_eq!(
            state.null_terminal_reason(),
            !state.requires_terminal_reason()
        );
    }
    assert!(
        CertificateOperationTerminalReason::InvalidCurrent
            .validate_pair(CertificateOperationState::Denied)
            .is_ok()
    );
    assert!(
        CertificateOperationTerminalReason::InvalidProof
            .validate_pair(CertificateOperationState::Denied)
            .is_ok()
    );
    assert!(
        CertificateOperationTerminalReason::Revoked
            .validate_pair(CertificateOperationState::Denied)
            .is_ok()
    );
    assert!(
        CertificateOperationTerminalReason::PolicyDenied
            .validate_pair(CertificateOperationState::Denied)
            .is_ok()
    );
    assert!(
        CertificateOperationTerminalReason::SignerUnavailable
            .validate_pair(CertificateOperationState::Denied)
            .is_ok()
    );
    assert!(
        CertificateOperationTerminalReason::Expired
            .validate_pair(CertificateOperationState::Expired)
            .is_ok()
    );
    assert!(
        CertificateOperationTerminalReason::Cancelled
            .validate_pair(CertificateOperationState::Cancelled)
            .is_ok()
    );
    assert!(
        CertificateOperationTerminalReason::InvalidCurrent
            .validate_pair(CertificateOperationState::Issued)
            .is_err()
    );
    assert!(
        CertificateOperationTerminalReason::Expired
            .validate_pair(CertificateOperationState::Cancelled)
            .is_err()
    );

    // Revocation matrix.
    for state in RevocationState::ALL {
        assert_eq!(
            state.requires_terminal_reason(),
            matches!(
                state,
                RevocationState::Denied | RevocationState::Expired | RevocationState::Cancelled
            )
        );
    }
    assert!(
        RevocationTerminalReason::InvalidCurrent
            .validate_pair(RevocationState::Denied)
            .is_ok()
    );
    assert!(
        RevocationTerminalReason::InvalidProof
            .validate_pair(RevocationState::Denied)
            .is_ok()
    );
    assert!(
        RevocationTerminalReason::InvalidApproval
            .validate_pair(RevocationState::Denied)
            .is_ok()
    );
    assert!(
        RevocationTerminalReason::PolicyDenied
            .validate_pair(RevocationState::Denied)
            .is_ok()
    );
    assert!(
        RevocationTerminalReason::SignerUnavailable
            .validate_pair(RevocationState::Denied)
            .is_ok()
    );
    assert!(
        RevocationTerminalReason::Expired
            .validate_pair(RevocationState::Expired)
            .is_ok()
    );
    assert!(
        RevocationTerminalReason::Cancelled
            .validate_pair(RevocationState::Cancelled)
            .is_ok()
    );
    assert!(
        RevocationTerminalReason::InvalidCurrent
            .validate_pair(RevocationState::Revoked)
            .is_err()
    );
    assert!(
        RevocationTerminalReason::Expired
            .validate_pair(RevocationState::Denied)
            .is_err()
    );

    // Closed action reducer: enroll | renew | rotate.
    assert_eq!(
        CertificateLifecycleAction::ALL
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>(),
        vec!["enroll", "renew", "rotate"]
    );

    // Closed revocation actor modes.
    assert_eq!(
        RevocationActorMode::ALL
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>(),
        vec![
            "public_self_account",
            "public_instance_owner",
            "self_client",
            "security_admin"
        ]
    );

    // Closed device lifecycle.
    assert_eq!(
        RemoteDeviceLifecycle::ALL
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>(),
        vec![
            "reserved",
            "pending",
            "active",
            "rotation_pending",
            "revoked",
            "deleted",
            "abandoned"
        ]
    );
}
