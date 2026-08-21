//! Linux/WSL PKCS#11 daemon custody adapter (feature `daemon-custody-pkcs11`).
//!
//! Loads only an explicitly configured **absolute** PKCS#11 module path — never
//! a `dlopen` search path — via the pinned `cryptoki` wrapper. Private keys are
//! generated `CKA_SENSITIVE = true`, `CKA_EXTRACTABLE = false`, `CKA_TOKEN =
//! true`; they never leave the token. `CKM_ECDSA` signs a precomputed 32-byte
//! digest and returns a raw P1363 (`r || s`) signature, which is normalized to
//! low-S via [`super::normalize_p1363_low_s`].
//!
//! The `Pkcs11` context finalizes on drop and each `Session` closes on drop
//! (owned-handle RAII); every `cryptoki` status is translated to a typed
//! [`RemoteIdentityCustodyError`].
//!
//! TODO(native-platform): this module is compiled and exercised ONLY by the
//! SoftHSM CI job (feature `daemon-custody-pkcs11`; its conformance tests are
//! `#[ignore]`d by default and run against a real token only in CI). It is not
//! built in the default Linux gate and has not been executed here — treat every
//! cryptoki call surface below as verified only on that CI job. See
//! apps/native/modules/remote-identity-custody/NATIVE-PLATFORM-TODO.md.

use std::path::PathBuf;

use cockpit_proto::remote_device_identity_enrollment::{
    RemoteIdentityCustodyError, RemoteIdentityCustodyHandleId, RemoteIdentityP256PublicKey,
    RemoteSubjectKindV1 as SubjectKind,
};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use super::{AdapterKeyMaterial, DaemonCustodyAdapter, DaemonCustodyProfile};

/// DER-encoded OID for `prime256v1` / `secp256r1` (`1.2.840.10045.3.1.7`).
const SECP256R1_OID_DER: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// PKCS#11 adapter configuration, threaded from the constructor (never read from
/// the environment inside library code — the SoftHSM CI job passes it
/// explicitly).
#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    /// Absolute path to the PKCS#11 module (`.so`). Relative paths are rejected.
    pub module_path: PathBuf,
    /// Token label to select the slot.
    pub token_label: String,
    /// User PIN.
    pub user_pin: String,
}

fn unavailable(context: &str, error: impl std::fmt::Display) -> RemoteIdentityCustodyError {
    RemoteIdentityCustodyError::Unavailable(format!("pkcs11 {context}: {error}"))
}

/// A logged-in PKCS#11 session. Closes (and logs out) on drop.
struct LoggedSession {
    session: Session,
}

impl LoggedSession {
    fn session(&self) -> &Session {
        &self.session
    }
}

impl Drop for LoggedSession {
    fn drop(&mut self) {
        // `Session::logout` is best-effort on teardown; the session close in the
        // cryptoki `Drop` impl releases the underlying handle regardless.
        let _ = self.session.logout();
    }
}

/// The Linux/WSL PKCS#11 custody adapter.
pub struct Pkcs11CustodyAdapter {
    context: Pkcs11,
    slot: Slot,
    config: Pkcs11Config,
}

impl Pkcs11CustodyAdapter {
    /// Open the configured PKCS#11 module and select the token slot. Rejects a
    /// non-absolute module path.
    pub fn open(config: Pkcs11Config) -> Result<Self, RemoteIdentityCustodyError> {
        if !config.module_path.is_absolute() {
            return Err(RemoteIdentityCustodyError::InvalidEvidence(
                "PKCS#11 module path must be absolute".into(),
            ));
        }
        let context =
            Pkcs11::new(&config.module_path).map_err(|e| unavailable("module load", e))?;
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| unavailable("initialize", e))?;
        let slots = context
            .get_slots_with_token()
            .map_err(|e| unavailable("get_slots_with_token", e))?;
        let mut selected = None;
        for slot in slots {
            let info = context
                .get_token_info(slot)
                .map_err(|e| unavailable("get_token_info", e))?;
            if info.label().trim_end() == config.token_label {
                selected = Some(slot);
                break;
            }
        }
        let slot = selected.ok_or_else(|| {
            RemoteIdentityCustodyError::Unavailable(format!(
                "no PKCS#11 token labeled {}",
                config.token_label
            ))
        })?;
        Ok(Self {
            context,
            slot,
            config,
        })
    }

    fn login(&self) -> Result<LoggedSession, RemoteIdentityCustodyError> {
        let session = self
            .context
            .open_rw_session(self.slot)
            .map_err(|e| unavailable("open_rw_session", e))?;
        session
            .login(
                UserType::User,
                Some(&AuthPin::new(self.config.user_pin.clone())),
            )
            .map_err(|e| unavailable("login", e))?;
        Ok(LoggedSession { session })
    }

    /// CKA_ID for `(handle, generation)`: `handle(16) || generation(8)` — a
    /// distinct, immutable object per generation.
    fn object_id(handle: RemoteIdentityCustodyHandleId, generation: u64) -> Vec<u8> {
        let mut id = handle.0.to_vec();
        id.extend_from_slice(&generation.to_be_bytes());
        id
    }

    /// CKA_LABEL shared by every generation of a handle, so `destroy_all` can
    /// enumerate them.
    fn handle_label(handle: RemoteIdentityCustodyHandleId) -> Vec<u8> {
        format!("flycockpit-remote-daemon-custody-{}", hex16(&handle.0)).into_bytes()
    }

    fn find_one(
        session: &Session,
        class: cryptoki::object::ObjectClass,
        id: Vec<u8>,
    ) -> Result<ObjectHandle, RemoteIdentityCustodyError> {
        let template = vec![Attribute::Class(class), Attribute::Id(id)];
        session
            .find_objects(&template)
            .map_err(|e| unavailable("find_objects", e))?
            .into_iter()
            .next()
            .ok_or(RemoteIdentityCustodyError::NotFound)
    }

    fn find_by_label(
        session: &Session,
        class: cryptoki::object::ObjectClass,
        label: Vec<u8>,
    ) -> Result<Vec<ObjectHandle>, RemoteIdentityCustodyError> {
        let template = vec![Attribute::Class(class), Attribute::Label(label)];
        session
            .find_objects(&template)
            .map_err(|e| unavailable("find_objects(label)", e))
    }

    fn public_key_of(
        session: &Session,
        public: ObjectHandle,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
        let attributes = session
            .get_attributes(public, &[AttributeType::EcPoint])
            .map_err(|e| unavailable("get_attributes(EcPoint)", e))?;
        let point = attributes
            .into_iter()
            .find_map(|attr| match attr {
                Attribute::EcPoint(bytes) => Some(bytes),
                _ => None,
            })
            .ok_or_else(|| unavailable("get_attributes", "EcPoint absent"))?;
        super::parse_pkcs11_ec_point(&point)
    }

    fn create_pair(
        &self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
        let session = self.login()?;
        let id = Self::object_id(handle, generation);
        let label = Self::handle_label(handle);
        let pub_template = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::KeyType(KeyType::EC),
            Attribute::Verify(true),
            Attribute::EcParams(SECP256R1_OID_DER.to_vec()),
            Attribute::Id(id.clone()),
            Attribute::Label(label.clone()),
        ];
        let priv_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Id(id),
            Attribute::Label(label),
        ];
        let (public, _private) = session
            .session()
            .generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)
            .map_err(|e| unavailable("generate_key_pair", e))?;
        Self::public_key_of(session.session(), public)
    }

    fn attestation(public_key: &RemoteIdentityP256PublicKey) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut fingerprint = Sha256::new();
        fingerprint.update(public_key.x);
        fingerprint.update(public_key.y);
        let mut evidence = Vec::new();
        evidence.extend_from_slice(
            DaemonCustodyProfile::LinuxTpmPkcs11
                .platform_label()
                .as_bytes(),
        );
        evidence.push(0x00);
        evidence.extend_from_slice(&fingerprint.finalize());
        evidence
    }
}

impl DaemonCustodyAdapter for Pkcs11CustodyAdapter {
    fn create(
        &mut self,
        _profile: DaemonCustodyProfile,
        _subject_kind: SubjectKind,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<AdapterKeyMaterial, RemoteIdentityCustodyError> {
        let public_key = self.create_pair(handle, generation)?;
        Ok(AdapterKeyMaterial {
            provider_evidence: Self::attestation(&public_key),
            public_key,
        })
    }

    fn reopen(
        &self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
        let session = self.login()?;
        let public = Self::find_one(
            session.session(),
            cryptoki::object::ObjectClass::PUBLIC_KEY,
            Self::object_id(handle, generation),
        )?;
        Self::public_key_of(session.session(), public)
    }

    fn sign(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError> {
        let session = self.login()?;
        let private = Self::find_one(
            session.session(),
            cryptoki::object::ObjectClass::PRIVATE_KEY,
            Self::object_id(handle, generation),
        )?;
        // CKM_ECDSA signs the precomputed digest and returns raw P1363 (r || s).
        let raw = session
            .session()
            .sign(&Mechanism::Ecdsa, private, digest)
            .map_err(|e| unavailable("sign", e))?;
        let signature: [u8; 64] = raw.as_slice().try_into().map_err(|_| {
            RemoteIdentityCustodyError::InvalidEvidence("PKCS#11 signature length".into())
        })?;
        super::normalize_p1363_low_s(&signature)
    }

    fn retire(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<(), RemoteIdentityCustodyError> {
        let session = self.login()?;
        let id = Self::object_id(handle, generation);
        let mut destroyed = false;
        for class in [
            cryptoki::object::ObjectClass::PUBLIC_KEY,
            cryptoki::object::ObjectClass::PRIVATE_KEY,
        ] {
            if let Ok(object) = Self::find_one(session.session(), class, id.clone()) {
                session
                    .session()
                    .destroy_object(object)
                    .map_err(|e| unavailable("destroy_object(retire)", e))?;
                destroyed = true;
            }
        }
        if destroyed {
            Ok(())
        } else {
            Err(RemoteIdentityCustodyError::NotFound)
        }
    }

    fn destroy_all(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError> {
        let session = self.login()?;
        let label = Self::handle_label(handle);
        let mut destroyed = false;
        for class in [
            cryptoki::object::ObjectClass::PUBLIC_KEY,
            cryptoki::object::ObjectClass::PRIVATE_KEY,
        ] {
            for object in Self::find_by_label(session.session(), class, label.clone())? {
                session
                    .session()
                    .destroy_object(object)
                    .map_err(|e| unavailable("destroy_object", e))?;
                destroyed = true;
            }
        }
        if destroyed {
            Ok(())
        } else {
            Err(RemoteIdentityCustodyError::NotFound)
        }
    }
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod softhsm_tests {
    use super::*;
    use cockpit_proto::remote_device_identity_enrollment::RemoteIdentityP256PublicKey;

    /// Reads SoftHSM2 configuration from CI-provided environment (the CI job sets
    /// them explicitly; library code never reads env). Ignored by default so the
    /// serialized local gate passes without SoftHSM installed.
    fn softhsm_config() -> Option<Pkcs11Config> {
        Some(Pkcs11Config {
            module_path: std::env::var_os("COCKPIT_SOFTHSM_MODULE")?.into(),
            token_label: std::env::var("COCKPIT_SOFTHSM_TOKEN_LABEL").ok()?,
            user_pin: std::env::var("COCKPIT_SOFTHSM_USER_PIN").ok()?,
        })
    }

    /// A valid 175-byte unsigned attempt-daemon possession proof (built via the
    /// production encoder with a placeholder low-S signature, then sliced), used
    /// to route SoftHSM signatures through `PossessionProof::decode`.
    fn softhsm_unsigned_attempt_daemon_proof() -> Vec<u8> {
        use cockpit_proto::remote_identity_protocol::{PossessionProof, PossessionPurpose};
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

    #[test]
    #[ignore = "requires SoftHSM2; run only in the cli-ci SoftHSM job"]
    fn remote_daemon_custody_pkcs11_softhsm_generates_and_signs_low_s() {
        let config = softhsm_config().expect("SoftHSM env configured in CI");
        let mut adapter = Pkcs11CustodyAdapter::open(config).unwrap();
        let handle = RemoteIdentityCustodyHandleId([0x7a; 16]);
        let material = adapter
            .create(
                DaemonCustodyProfile::LinuxTpmPkcs11,
                SubjectKind::Daemon,
                handle,
                1,
            )
            .unwrap();
        // Public key parses to two 32-byte coordinates; no private bytes returned.
        let RemoteIdentityP256PublicKey { x, y } = material.public_key;
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        // Route REPEATED (randomized) signatures through the PRODUCTION codec:
        // `PossessionProof::decode` runs `validate_low_s` (s <= n/2), so a missing
        // low-S normalization would fail here ~half the time — unlike a bit-7
        // check. Assemble a valid unsigned proof and append the signature.
        let unsigned = softhsm_unsigned_attempt_daemon_proof();
        for _ in 0..8 {
            let signature = adapter.sign(handle, 1, &[0x42; 32]).unwrap();
            let mut full = [0u8; 239];
            full[..175].copy_from_slice(&unsigned);
            full[175..].copy_from_slice(&signature);
            cockpit_proto::remote_identity_protocol::PossessionProof::decode(&full)
                .expect("production codec accepts canonical low-S signature");
        }
        // Rotation: a second generation coexists until the first is retired.
        let _ = adapter
            .create(
                DaemonCustodyProfile::LinuxTpmPkcs11,
                SubjectKind::Daemon,
                handle,
                2,
            )
            .unwrap();
        adapter.retire(handle, 1).unwrap();
        assert!(adapter.reopen(handle, 1).is_err());
        assert!(adapter.reopen(handle, 2).is_ok());
        adapter.destroy_all(handle).unwrap();
    }

    #[test]
    #[ignore = "requires SoftHSM2; run only in the cli-ci SoftHSM job"]
    fn remote_daemon_custody_pkcs11_softhsm_rejects_relative_module_path() {
        let config = Pkcs11Config {
            module_path: "relative/libsofthsm2.so".into(),
            token_label: "flycockpit".into(),
            user_pin: "1234".into(),
        };
        assert!(Pkcs11CustodyAdapter::open(config).is_err());
    }
}
