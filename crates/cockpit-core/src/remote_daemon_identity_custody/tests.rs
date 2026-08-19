use super::*;
use cockpit_db::Db;
use cockpit_proto::remote_device_identity_enrollment::{
    RemoteIdentityCustodyClassV1 as CustodyClass, RemoteIdentityCustodyError,
    RemoteIdentityCustodyProvider, RemoteIdentityPresenceModeV1 as PresenceMode,
    RemoteSubjectKindV1 as SubjectKind,
};
use cockpit_proto::remote_identity_protocol::{
    CustodyEvidence, PossessionProof, PossessionPurpose, possession_proof_signing_digest,
};
use cockpit_proto::remote_public_service_policy::DaemonCustodyPolicy;

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn provider_over(
    db: Db,
    profile: DaemonCustodyProfile,
    clock: i64,
) -> DaemonIdentityCustodyProvider<FakeDaemonCustodyAdapter> {
    DaemonIdentityCustodyProvider::new(
        FakeDaemonCustodyAdapter::new(),
        profile,
        SqliteCustodyStore::new(db),
        Box::new(FixedClock(clock)),
    )
}

fn provider_in_memory(
    profile: DaemonCustodyProfile,
    clock: i64,
) -> DaemonIdentityCustodyProvider<FakeDaemonCustodyAdapter> {
    provider_over(Db::open_in_memory().unwrap(), profile, clock)
}

/// A valid 175-byte unsigned attempt-daemon possession proof, built via the
/// production encoder (with a placeholder low-S signature) and sliced.
fn unsigned_attempt_daemon_proof() -> Vec<u8> {
    let mut placeholder = [0u8; 64];
    placeholder[31] = 1;
    placeholder[63] = 1;
    let proof = PossessionProof {
        purpose: PossessionPurpose::AttemptDaemon,
        subject_kind: SubjectKind::Daemon,
        subject_id: [0x11; 16],
        certificate_id: [0x22; 16],
        generation: 7,
        request_id: [0x33; 16],
        issuer_status_digest: [0x44; 32],
        challenge: [0x55; 32],
        transcript_digest: [0x66; 32],
        issued_at: 1000,
        expires_at: 1060,
        signature_p1363: placeholder,
    };
    proof.encode().unwrap()[..175].to_vec()
}

// ─────────────────────────────────────────────────────────────────────────
// Profile matrix + policy gate (ported, provider-independent)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn remote_daemon_identity_provider_matrix() {
    let expected = [
        (
            DaemonCustodyProfile::MacosSecureEnclave,
            CustodyClass::HardwareOrExternal,
        ),
        (
            DaemonCustodyProfile::MacosKeychain,
            CustodyClass::OsProtected,
        ),
        (
            DaemonCustodyProfile::WindowsCngTpm,
            CustodyClass::HardwareOrExternal,
        ),
        (
            DaemonCustodyProfile::WindowsSoftwareKsp,
            CustodyClass::OsProtected,
        ),
        (
            DaemonCustodyProfile::LinuxTpmPkcs11,
            CustodyClass::HardwareOrExternal,
        ),
        (
            DaemonCustodyProfile::WslExternalPkcs11,
            CustodyClass::HardwareOrExternal,
        ),
    ];
    assert_eq!(DaemonCustodyProfile::ALL.len(), expected.len());
    for (profile, class) in expected {
        assert_eq!(profile.custody_class(), class);
        assert_eq!(profile.presence_mode(), PresenceMode::Unattended);
        assert_eq!(
            DaemonCustodyProfile::from_label(profile.platform_label()),
            Some(profile)
        );
    }
}

#[test]
fn remote_daemon_identity_custody_policy_rejects_non_unattended_and_ineligible() {
    let gate = DaemonCustodyPolicyGate;
    for presence in [
        PresenceMode::UnattendedAfterFirstUnlock,
        PresenceMode::UnattendedUnlockedDevice,
        PresenceMode::UserPresenceRequired,
    ] {
        for profile in DaemonCustodyProfile::ALL {
            assert!(gate.authorize(profile, presence).is_err());
        }
    }
    for path in IneligibleCustodyPath::ALL {
        assert!(gate.reject_ineligible(path).is_err());
    }
    assert_eq!(
        gate.meet(
            DaemonCustodyPolicy::OsProtected,
            DaemonCustodyPolicy::HardwareOrExternal
        ),
        DaemonCustodyPolicy::HardwareOrExternal
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Criterion 15 — construction-time profile; forged evidence cannot classify
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn remote_daemon_identity_custody_forged_evidence_cannot_select_profile() {
    // Provider is configured LinuxTpmPkcs11; the caller forges a macOS evidence
    // buffer. Classification must come ONLY from the configured profile, and the
    // forged bytes must appear nowhere in the recorded evidence. (Against the old
    // select_profile_from_evidence code this would classify as macOS.)
    let mut provider = provider_in_memory(DaemonCustodyProfile::LinuxTpmPkcs11, 1000);
    let forged = b"macos-secure-enclave forged attestation payload".to_vec();
    let (handle, _pk, evidence) = provider
        .generate(
            SubjectKind::Daemon,
            CustodyClass::HardwareOrExternal,
            PresenceMode::Unattended,
            &forged,
        )
        .unwrap();

    assert_eq!(evidence.custody_class, CustodyClass::HardwareOrExternal);
    assert_eq!(evidence.presence_mode, PresenceMode::Unattended);
    // Recorded evidence is adapter attestation for the configured Linux profile.
    assert!(evidence.provider_evidence.starts_with(b"linux-tpm-pkcs11"));
    assert!(!contains_subslice(
        &evidence.provider_evidence,
        b"macos-secure-enclave"
    ));
    // Reopen reports the configured class, not a forged upgrade.
    let (_pk, class, presence) = provider.reopen(handle).unwrap();
    assert_eq!(class, CustodyClass::HardwareOrExternal);
    assert_eq!(presence, PresenceMode::Unattended);
}

#[test]
fn remote_daemon_identity_custody_generate_rejects_mismatched_class() {
    // A LinuxTpmPkcs11 provider reports hardware_or_external; requesting the
    // weaker os_protected must be refused before any allocation.
    let mut provider = provider_in_memory(DaemonCustodyProfile::LinuxTpmPkcs11, 1000);
    let result = provider.generate(
        SubjectKind::Daemon,
        CustodyClass::OsProtected,
        PresenceMode::Unattended,
        b"",
    );
    assert!(matches!(
        result,
        Err(RemoteIdentityCustodyError::PolicyDenied(_))
    ));
    assert_eq!(provider.generation_high_water().unwrap(), 0);
    assert_eq!(provider.adapter().len(), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Criterion 16 — durable records, monotonic generation, injected clock
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn remote_daemon_identity_custody_generation_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cockpit.db");

    let first_generation = {
        let mut provider = provider_over(
            Db::open(&path).unwrap(),
            DaemonCustodyProfile::MacosKeychain,
            10,
        );
        let (handle, _pk, evidence) = provider
            .generate(
                SubjectKind::Daemon,
                CustodyClass::OsProtected,
                PresenceMode::Unattended,
                b"",
            )
            .unwrap();
        // Destroy must NOT reset the monotonic sequence.
        provider.destroy(handle).unwrap();
        evidence.generation
    };

    let second_generation = {
        let mut provider = provider_over(
            Db::open(&path).unwrap(),
            DaemonCustodyProfile::MacosKeychain,
            20,
        );
        let (_handle, _pk, evidence) = provider
            .generate(
                SubjectKind::Daemon,
                CustodyClass::OsProtected,
                PresenceMode::Unattended,
                b"",
            )
            .unwrap();
        evidence.generation
    };

    assert!(
        second_generation > first_generation,
        "generation must strictly increase across restart + destroy ({second_generation} > {first_generation})"
    );
}

#[test]
fn remote_daemon_identity_custody_rotate_consumes_next_generation() {
    let mut provider = provider_in_memory(DaemonCustodyProfile::MacosSecureEnclave, 5);
    let (handle, pk_old, ev0) = provider
        .generate(
            SubjectKind::Daemon,
            CustodyClass::HardwareOrExternal,
            PresenceMode::Unattended,
            b"",
        )
        .unwrap();
    let (pk_new, ev1) = provider.rotate(handle, b"").unwrap();
    assert_ne!(pk_old, pk_new);
    assert!(ev1.generation > ev0.generation);
    // Reopen reflects the rotated key and preserved custody class.
    let (pk_reopen, class, _presence) = provider.reopen(handle).unwrap();
    assert_eq!(pk_reopen, pk_new);
    assert_eq!(class, CustodyClass::HardwareOrExternal);
}

#[test]
fn remote_daemon_identity_custody_rotation_failure_preserves_old_key_and_record() {
    // Publish-before-retire: if the durable rotation publish fails, the OLD
    // generation's key must still exist and the record must still point at it —
    // never a destroyed/replaced key with a stale record. (This test fails
    // against a rotate that retires/overwrites the old key before persisting.)
    let mut provider = provider_in_memory(DaemonCustodyProfile::MacosKeychain, 100);
    let (handle, pk_old, ev0) = provider
        .generate(
            SubjectKind::Daemon,
            CustodyClass::OsProtected,
            PresenceMode::Unattended,
            b"",
        )
        .unwrap();
    assert_eq!(ev0.generation, 1);

    // Arm the rotation-publish failpoint so `update_rotation` fails AFTER the new
    // key is staged but BEFORE the record is flipped.
    provider.store().set_rotation_update_failpoint(true);
    assert!(provider.rotate(handle, b"").is_err());
    provider.store().set_rotation_update_failpoint(false);

    // Fail closed: the record still points at generation 1 and its old public key.
    let (pk_reopen, class, _presence) = provider.reopen(handle).unwrap();
    assert_eq!(pk_reopen, pk_old);
    assert_eq!(class, CustodyClass::OsProtected);

    // The old generation's key was never retired and still signs; the staged new
    // key (generation 2) was retired on failure, leaving no orphan.
    assert!(provider.adapter().has_key(handle, 1));
    assert!(!provider.adapter().has_key(handle, 2));
    let unsigned = unsigned_attempt_daemon_proof();
    let digest =
        possession_proof_signing_digest(&unsigned, PossessionPurpose::AttemptDaemon).unwrap();
    let signature = provider.sign_possession_proof(handle, &digest).unwrap();
    let mut full = [0u8; 239];
    full[..175].copy_from_slice(&unsigned);
    full[175..].copy_from_slice(&signature);
    assert!(PossessionProof::decode(&full).is_ok());
}

#[test]
fn remote_daemon_identity_custody_observed_at_from_injected_clock() {
    let mut provider = provider_in_memory(DaemonCustodyProfile::MacosSecureEnclave, 987_654);
    let (_handle, _pk, evidence) = provider
        .generate(
            SubjectKind::Daemon,
            CustodyClass::HardwareOrExternal,
            PresenceMode::Unattended,
            b"",
        )
        .unwrap();
    assert_eq!(evidence.observed_at, 987_654);
    // Round-trips through the foundation codec.
    let encoded = evidence.encode().unwrap();
    let decoded = CustodyEvidence::decode(&encoded).unwrap();
    assert_eq!(decoded.observed_at, 987_654);
    assert_ne!(decoded.observed_at, 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Criterion 17 — codec round-trip with a real-key fake; no low_s_valid helper
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn remote_daemon_identity_custody_codec_round_trip() {
    let mut provider = provider_in_memory(DaemonCustodyProfile::MacosKeychain, 1);
    let (handle, _pk, _ev) = provider
        .generate(
            SubjectKind::Daemon,
            CustodyClass::OsProtected,
            PresenceMode::Unattended,
            b"",
        )
        .unwrap();
    let unsigned = unsigned_attempt_daemon_proof();
    let digest =
        possession_proof_signing_digest(&unsigned, PossessionPurpose::AttemptDaemon).unwrap();

    // The real p256 fake signs; the resulting low-S signature is accepted by the
    // PRODUCTION codec (which enforces low-S). No hand-rolled predicate is used.
    let signature = provider.sign_possession_proof(handle, &digest).unwrap();
    let mut full = [0u8; 239];
    full[..175].copy_from_slice(&unsigned);
    full[175..].copy_from_slice(&signature);
    let decoded = PossessionProof::decode(&full).expect("production codec accepts the signature");
    assert_eq!(decoded.encode().unwrap(), full.to_vec());

    // Enrollment-confirmation signing path also produces a codec-acceptable sig.
    let sig2 = provider
        .sign_enrollment_confirmation(handle, &digest)
        .unwrap();
    let mut full2 = [0u8; 239];
    full2[..175].copy_from_slice(&unsigned);
    full2[175..].copy_from_slice(&sig2);
    assert!(PossessionProof::decode(&full2).is_ok());

    // After destroy, signing fails closed.
    provider.destroy(handle).unwrap();
    assert!(provider.sign_possession_proof(handle, &digest).is_err());
    assert!(provider.reopen(handle).is_err());
}

// ─────────────────────────────────────────────────────────────────────────
// Criterion 18 — DER→P1363 low-S normalization against a pinned vector
// ─────────────────────────────────────────────────────────────────────────

// Independently generated with the `cryptography` library (see prompt report):
// r = 0x1122...ff00, s_high = n - 0x2222..22 (> n/2). Normalized low-S = (r, 0x2222..22).
const DER_HIGH_S: &str = "30450220112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00022100dddddddcdddddddedddddddddddddddd9ac4d88b84f57c62d197a8a0da41032f";
const DER_LOW_S: &str = "30440220112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0002202222222222222222222222222222222222222222222222222222222222222222";
const EXPECTED_LOW_S_P1363: &str = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff002222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn remote_daemon_identity_custody_der_high_s_normalizes_to_low_s_p1363() {
    let expected = unhex(EXPECTED_LOW_S_P1363);
    // A high-S DER signature is normalized to the canonical low-S P1363 form.
    let normalized = der_signature_to_low_s_p1363(&unhex(DER_HIGH_S)).unwrap();
    assert_eq!(normalized.to_vec(), expected);
    // An already-low-S DER signature yields the same P1363 form unchanged.
    let unchanged = der_signature_to_low_s_p1363(&unhex(DER_LOW_S)).unwrap();
    assert_eq!(unchanged.to_vec(), expected);
    // Malformed DER is a typed error, never a mangled signature.
    assert!(der_signature_to_low_s_p1363(b"not-a-der-signature").is_err());
    // The P1363 normalizer agrees on the low-S form.
    let mut high_p1363 = [0u8; 64];
    high_p1363[..32].copy_from_slice(&unhex(EXPECTED_LOW_S_P1363)[..32]);
    let n = [
        0xff_u8, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc,
        0x63, 0x25, 0x51,
    ];
    // s_high = n - 0x2222..22
    let low = unhex(EXPECTED_LOW_S_P1363);
    let mut borrow = 0i16;
    let mut s_high = [0u8; 32];
    for i in (0..32).rev() {
        let diff = n[i] as i16 - low[32 + i] as i16 - borrow;
        if diff < 0 {
            s_high[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            s_high[i] = diff as u8;
            borrow = 0;
        }
    }
    high_p1363[32..].copy_from_slice(&s_high);
    assert_eq!(
        normalize_p1363_low_s(&high_p1363).unwrap().to_vec(),
        expected
    );
}

#[test]
fn remote_daemon_identity_custody_pkcs11_ec_point_validates_length_byte() {
    // Valid: 0x04 (OCTET STRING) 0x41 (len 65) 0x04 (uncompressed) X(32) Y(32).
    let mut valid = vec![0x04u8, 0x41, 0x04];
    valid.extend_from_slice(&[0x11u8; 32]);
    valid.extend_from_slice(&[0x22u8; 32]);
    let pk = parse_pkcs11_ec_point(&valid).unwrap();
    assert_eq!(pk.x, [0x11u8; 32]);
    assert_eq!(pk.y, [0x22u8; 32]);

    // Malformed length byte: declares 0x00 while 65 value bytes follow. The old
    // parser (which ignored the length byte) accepted this; it must be rejected.
    let mut bad_length = vec![0x04u8, 0x00, 0x04];
    bad_length.extend_from_slice(&[0x11u8; 32]);
    bad_length.extend_from_slice(&[0x22u8; 32]);
    assert!(parse_pkcs11_ec_point(&bad_length).is_err());

    // Wrong outer tag, wrong total length, and missing uncompressed marker.
    assert!(parse_pkcs11_ec_point(&[0x03, 0x41, 0x04]).is_err());
    assert!(parse_pkcs11_ec_point(&valid[..66]).is_err());
    let mut wrong_marker = valid.clone();
    wrong_marker[2] = 0x02;
    assert!(parse_pkcs11_ec_point(&wrong_marker).is_err());
}

// ─────────────────────────────────────────────────────────────────────────
// Criterion 18 — syn source-scan guards (replace the old `let _ =` guards)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn remote_daemon_identity_custody_source_scan_guards() {
    use syn::visit::Visit;

    struct IdentCollector {
        idents: Vec<String>,
    }
    impl<'ast> Visit<'ast> for IdentCollector {
        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            self.idents.push(ident.to_string());
        }
    }

    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/remote_daemon_identity_custody");
    let mut collector = IdentCollector { idents: Vec::new() };
    let mut enum_names: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        // The test file itself is excluded — it references forbidden tokens as
        // string literals; the guard proves the PRODUCTION source is clean.
        if path.file_name().and_then(|n| n.to_str()) == Some("tests.rs") {
            continue;
        }
        scanned += 1;
        let text = std::fs::read_to_string(&path).unwrap();
        let file = syn::parse_file(&text).unwrap();
        for item in &file.items {
            if let syn::Item::Enum(item_enum) = item {
                enum_names.push(item_enum.ident.to_string());
            }
        }
        collector.visit_file(&file);
    }
    assert!(scanned >= 2, "expected mod.rs + store.rs at minimum");

    let lowered: Vec<String> = collector
        .idents
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    // No X25519/DH/ECDH API surface anywhere in the module's real code.
    for forbidden in [
        "x25519",
        "montgomery",
        "diffie_hellman",
        "ecdh",
        "derive_bits",
        "derivebits",
    ] {
        assert!(
            !lowered
                .iter()
                .any(|s| s == forbidden || s.contains(forbidden)),
            "forbidden DH/X25519 identifier present: {forbidden}"
        );
    }
    // No private-key export API.
    for name in &lowered {
        assert!(
            !(name.contains("export") && (name.contains("private") || name.contains("secret"))),
            "private-key export identifier present: {name}"
        );
        assert!(
            !matches!(
                name.as_str(),
                "to_pkcs8" | "to_sec1_der" | "to_sec1_pem" | "secret_bytes" | "private_key_bytes"
            ),
            "private-material accessor present: {name}"
        );
    }
    // No second custody/presence/subject enum definition — the foundation ones
    // are consumed, never redefined here.
    for name in &enum_names {
        assert!(
            !matches!(
                name.as_str(),
                "CustodyClass"
                    | "PresenceMode"
                    | "SubjectKind"
                    | "RemoteIdentityCustodyClassV1"
                    | "RemoteIdentityPresenceModeV1"
            ),
            "foundation enum redefined in module: {name}"
        );
    }
    // Positive control: the module DOES define its profile enum.
    assert!(enum_names.iter().any(|n| n == "DaemonCustodyProfile"));
}

// ─────────────────────────────────────────────────────────────────────────
// Criterion 14 — provenance record cross-checked against the manifest + lock
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn remote_daemon_identity_custody_provenance_matches_manifest() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let provenance: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(crate_dir.join("PROVENANCE-remote-identity-custody.json"))
            .unwrap(),
    )
    .unwrap();
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(crate_dir.join("Cargo.toml")).unwrap()).unwrap();
    // Cargo.lock lives at the workspace root (two levels up from the crate).
    let lock: toml::Value =
        toml::from_str(&std::fs::read_to_string(crate_dir.join("../../Cargo.lock")).unwrap())
            .unwrap();

    let deps = provenance["dependencies"].as_array().unwrap();
    assert!(!deps.is_empty());
    for dep in deps {
        let name = dep["name"].as_str().unwrap();
        let want_version = dep["version"].as_str().unwrap();

        // Locate the dependency table (normal or target-gated).
        let table = match dep["target"].as_str() {
            Some(target) => &manifest["target"][target]["dependencies"],
            None => &manifest["dependencies"],
        };
        let spec = table
            .get(name)
            .unwrap_or_else(|| panic!("missing manifest entry for {name}"));
        let version_req = match spec {
            toml::Value::String(s) => s.clone(),
            toml::Value::Table(t) => t["version"].as_str().unwrap().to_string(),
            _ => panic!("unexpected dependency spec for {name}"),
        };
        assert_eq!(
            version_req.trim_start_matches('='),
            want_version,
            "manifest version for {name} disagrees with provenance"
        );

        // Recorded features must EXACTLY equal the manifest's enabled features
        // (set equality, sorted) — an added or removed manifest feature fails.
        let mut recorded_features: Vec<String> = dep["features"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let mut manifest_features: Vec<String> = match spec {
            toml::Value::Table(t) => t
                .get("features")
                .and_then(|f| f.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        recorded_features.sort();
        manifest_features.sort();
        assert_eq!(
            recorded_features, manifest_features,
            "provenance features for {name} must EXACTLY equal the manifest features"
        );

        // Cross-check the checksum against Cargo.lock (the second artifact). This
        // only passes once the lock has been refreshed to include the pinned
        // dependency — see the PROVENANCE note for cryptoki.
        let want_checksum = dep["checksum"].as_str().unwrap();
        let packages = lock["package"].as_array().unwrap();
        let locked = packages.iter().find(|p| {
            p["name"].as_str() == Some(name) && p["version"].as_str() == Some(want_version)
        });
        let locked = locked.unwrap_or_else(|| {
            panic!("{name} {want_version} not found in Cargo.lock (refresh lock)")
        });
        assert_eq!(
            locked["checksum"].as_str().unwrap(),
            want_checksum,
            "Cargo.lock checksum for {name} disagrees with provenance"
        );
    }
}
