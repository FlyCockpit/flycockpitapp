//! Sealed-state load/CAS/create operations on the secure-key actor thread.
#![allow(clippy::needless_return, clippy::collapsible_if)]

use uuid::Uuid;

use crate::db::secure_key::{
    ReserveResult, SEALED_STATE_CONSUMER_KIND, SealedStateSagaPhase, SealedStateSagaRow,
    activate_consumer_ref_conn, delete_sealed_state_saga_conn,
    get_sealed_state_saga_for_namespace_conn, insert_sealed_state_saga_conn,
    list_open_sealed_state_sagas_conn, reserve_consumer_ref_conn, sealed_state_ref_id,
    set_sealed_state_saga_phase_conn,
};

use super::error::SecureKeyError;
use super::key_material::SecureKeyBytes;
use super::namespace::{Namespace, SECURE_KEY_SERVICE};
use super::sealed_state::{
    MAX_PAYLOAD_LEN, SealedHealth, SealedPayload, SealedSlot, SealedStateMeta, SealedStateView,
    decode_and_verify, encode_item_base64url, payload_digest, sealed_state_account,
};
use super::worker::Worker;

const CONSUMER_KIND: &str = SEALED_STATE_CONSUMER_KIND;

fn install_raw(hex: &str) -> Result<[u8; 16], SecureKeyError> {
    if hex.len() != 32 {
        return Err(SecureKeyError::Internal(
            "installation identity hex length".into(),
        ));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| SecureKeyError::Internal("installation identity hex".into()))?;
        out[i] = byte;
    }
    Ok(out)
}

fn digest_hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_digest_hex(s: &str) -> Result<[u8; 32], SecureKeyError> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(SecureKeyError::Corrupt(
            "payload digest hex must be 64 ASCII hex digits".into(),
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        // Safe: length and ASCII hex checked above.
        let pair = std::str::from_utf8(&bytes[i * 2..i * 2 + 2]).unwrap();
        out[i] = u8::from_str_radix(pair, 16)
            .map_err(|_| SecureKeyError::Corrupt("payload digest hex".into()))?;
    }
    Ok(out)
}

/// Coordination-row load failures for sealed sagas are always Corrupt (not Internal).
fn map_saga_db_err(e: impl std::fmt::Display) -> SecureKeyError {
    SecureKeyError::Corrupt(format!("sealed saga coordination corrupt: {e}"))
}

enum SlotProbe {
    Absent,
    Valid {
        generation: u64,
        key_version: u32,
        payload: SealedPayload,
        payload_digest: [u8; 32],
    },
    /// Present but not authenticable without a saga explanation.
    Invalid,
}

impl Worker<'_> {
    fn sealed_probe_slot(
        &self,
        namespace: &Namespace,
        slot: SealedSlot,
        key_loader: &dyn Fn(u32) -> Result<SecureKeyBytes, SecureKeyError>,
    ) -> Result<SlotProbe, SecureKeyError> {
        let account = sealed_state_account(self.installation.as_hex(), namespace, slot)?;
        let secret = match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
            Ok(s) => s,
            Err(SecureKeyError::NotFound(_)) => return Ok(SlotProbe::Absent),
            Err(e) => return Err(e),
        };
        let raw = secret.as_slice();
        let Ok(text) = std::str::from_utf8(raw) else {
            return Ok(SlotProbe::Invalid);
        };
        let install = install_raw(self.installation.as_hex())?;
        // Prefer key_version embedded in the item (offset 130..134 of decoded body).
        // Missing named key version is Corrupt (no fallback key guessing).
        let Ok(decoded) = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            text.as_bytes(),
        ) else {
            return Ok(SlotProbe::Invalid);
        };
        if decoded.len() < 134 {
            return Ok(SlotProbe::Invalid);
        }
        let kv = u32::from_be_bytes(decoded[130..134].try_into().unwrap());
        if kv == 0 {
            return Ok(SlotProbe::Invalid);
        }
        let key = match key_loader(kv) {
            Ok(k) => k,
            Err(SecureKeyError::NotFound(_)) => {
                return Err(SecureKeyError::Corrupt(format!(
                    "sealed state names missing key version {kv}"
                )));
            }
            Err(e) => return Err(e),
        };
        match decode_and_verify(text, &install, namespace, slot, &key) {
            Ok((generation, key_version, payload, payload_digest)) => Ok(SlotProbe::Valid {
                generation,
                key_version,
                payload,
                payload_digest,
            }),
            Err(SecureKeyError::Corrupt(_)) => Ok(SlotProbe::Invalid),
            Err(e) => Err(e),
        }
    }

    fn load_key_version(
        &self,
        namespace: &Namespace,
        version: u32,
    ) -> Result<SecureKeyBytes, SecureKeyError> {
        // Do not resume retire/provision sagas here: sealed reconcile must re-pin
        // consumer refs from native slots before any retirement can delete a key.
        let version_i64 = i64::from(version);
        let (_v, key) = self.load_version_after_consistent(namespace, version_i64)?;
        Ok(key)
    }

    fn key_version_u32(version_i64: i64) -> Result<u32, SecureKeyError> {
        u32::try_from(version_i64).map_err(|_| {
            SecureKeyError::Corrupt(format!(
                "secure-key version {version_i64} exceeds sealed-state u32 range"
            ))
        })
    }

    /// Load sealed state; applies in-flight saga cleanup when present.
    pub fn sealed_load(&self, namespace: &Namespace) -> Result<SealedStateView, SecureKeyError> {
        // ensure_namespace_ready resumes sealed sagas before reconciling slots.
        self.ensure_namespace_ready(namespace)?;
        self.sealed_select(namespace)
    }

    fn sealed_select(&self, namespace: &Namespace) -> Result<SealedStateView, SecureKeyError> {
        let key_loader = |ver: u32| self.load_key_version(namespace, ver);
        let a = self.sealed_probe_slot(namespace, SealedSlot::A, &key_loader)?;
        let b = self.sealed_probe_slot(namespace, SealedSlot::B, &key_loader)?;

        // Diagnostic enumeration: unexpected third sealed-state account is Corrupt.
        let expected_a =
            sealed_state_account(self.installation.as_hex(), namespace, SealedSlot::A)?;
        let expected_b =
            sealed_state_account(self.installation.as_hex(), namespace, SealedSlot::B)?;
        let listed = self.store.list_accounts(SECURE_KEY_SERVICE)?;
        let prefix = {
            let inst = super::namespace::encode_account_component(self.installation.as_hex())?;
            let ns = super::namespace::encode_account_component(namespace.as_str())?;
            format!("{inst}/{ns}/")
        };
        for acct in listed {
            if !acct.starts_with(&prefix) {
                continue;
            }
            // Only sealed dual slots are state-*; ignore key versions (/v…) and manifest.
            if !acct
                .rsplit('/')
                .next()
                .is_some_and(|s| s.starts_with("state-"))
            {
                continue;
            }
            if acct != expected_a && acct != expected_b {
                return Err(SecureKeyError::Corrupt(
                    "unexpected sealed-state account under namespace".into(),
                ));
            }
        }

        // Unexplained invalid is always Corrupt.
        match (&a, &b) {
            (SlotProbe::Invalid, _) | (_, SlotProbe::Invalid) => {
                return Err(SecureKeyError::Corrupt(
                    "sealed state slot present but unauthenticated".into(),
                ));
            }
            (SlotProbe::Absent, SlotProbe::Absent) => {
                return Err(SecureKeyError::NotFound(format!(
                    "sealed state {} empty",
                    namespace.as_str()
                )));
            }
            (SlotProbe::Valid { .. }, SlotProbe::Absent) => {
                return self.view_from_probe(namespace, SealedSlot::A, a, SealedHealth::Degraded);
            }
            (SlotProbe::Absent, SlotProbe::Valid { .. }) => {
                return self.view_from_probe(namespace, SealedSlot::B, b, SealedHealth::Degraded);
            }
            (SlotProbe::Valid { .. }, SlotProbe::Valid { .. }) => {
                let SlotProbe::Valid {
                    generation: ga,
                    key_version: ka,
                    payload: pa,
                    payload_digest: da,
                } = a
                else {
                    unreachable!()
                };
                let SlotProbe::Valid {
                    generation: gb,
                    key_version: kb,
                    payload: pb,
                    payload_digest: db,
                } = b
                else {
                    unreachable!()
                };
                if ga != gb {
                    let (slot, probe) = if ga > gb {
                        (
                            SealedSlot::A,
                            SlotProbe::Valid {
                                generation: ga,
                                key_version: ka,
                                payload: pa,
                                payload_digest: da,
                            },
                        )
                    } else {
                        (
                            SealedSlot::B,
                            SlotProbe::Valid {
                                generation: gb,
                                key_version: kb,
                                payload: pb,
                                payload_digest: db,
                            },
                        )
                    };
                    return self.view_from_probe(namespace, slot, probe, SealedHealth::Healthy);
                }
                // Equal generation: must be identical logical state.
                if ka != kb || da != db || pa.as_slice() != pb.as_slice() {
                    return Err(SecureKeyError::Corrupt(
                        "equal-generation sealed slots disagree".into(),
                    ));
                }
                // Deterministic: state-a is current.
                return self.view_from_probe(
                    namespace,
                    SealedSlot::A,
                    SlotProbe::Valid {
                        generation: ga,
                        key_version: ka,
                        payload: pa,
                        payload_digest: da,
                    },
                    SealedHealth::Healthy,
                );
            }
        }
    }

    fn view_from_probe(
        &self,
        namespace: &Namespace,
        slot: SealedSlot,
        probe: SlotProbe,
        health: SealedHealth,
    ) -> Result<SealedStateView, SecureKeyError> {
        let SlotProbe::Valid {
            generation,
            key_version,
            payload,
            payload_digest,
        } = probe
        else {
            return Err(SecureKeyError::Internal("view_from_probe".into()));
        };
        Ok(SealedStateView {
            meta: SealedStateMeta {
                namespace: namespace.as_str().to_owned(),
                generation,
                payload_digest,
                key_version,
                health,
                current_slot: slot,
            },
            payload,
        })
    }

    pub fn sealed_create_or_load(
        &self,
        namespace: &Namespace,
        initial_payload: SealedPayload,
    ) -> Result<SealedStateView, SecureKeyError> {
        match self.sealed_load(namespace) {
            Ok(v) => Ok(v),
            Err(SecureKeyError::NotFound(_)) => {
                self.sealed_write_initial(namespace, initial_payload)
            }
            Err(e) => Err(e),
        }
    }

    fn sealed_write_initial(
        &self,
        namespace: &Namespace,
        payload: SealedPayload,
    ) -> Result<SealedStateView, SecureKeyError> {
        // Ensure secure-key namespace has an active key.
        let (key_version_i64, key) = self.create_or_load(namespace)?;
        let key_version = Self::key_version_u32(key_version_i64)?;
        if key_version == 0 {
            return Err(SecureKeyError::Corrupt("active key version zero".into()));
        }
        self.sealed_cas_write(
            namespace,
            /*expected_generation*/ 0,
            /*expected_digest*/ None,
            payload,
            SealedSlot::A,
            1,
            key_version,
            &key,
            /*lost_ack_prev*/ None,
        )
    }

    pub fn sealed_compare_and_swap(
        &self,
        namespace: &Namespace,
        expected_generation: u64,
        expected_payload_digest: [u8; 32],
        new_payload: SealedPayload,
    ) -> Result<SealedStateView, SecureKeyError> {
        if new_payload.len() > MAX_PAYLOAD_LEN {
            return Err(SecureKeyError::Invalid("payload too large".into()));
        }
        let current = self.sealed_load(namespace)?;
        let expected_plus_one = expected_generation.checked_add(1);
        // Lost-ack replay first (including when current is u64::MAX from a completed write).
        if let Some(e1) = expected_plus_one {
            if current.meta.generation == e1
                && current.meta.payload_digest == payload_digest(new_payload.as_slice())
                && current.payload.as_slice() == new_payload.as_slice()
            {
                let other = current.meta.current_slot.other();
                let key_loader = |ver: u32| self.load_key_version(namespace, ver);
                match self.sealed_probe_slot(namespace, other, &key_loader)? {
                    SlotProbe::Valid {
                        generation,
                        payload_digest: d,
                        ..
                    } if generation == expected_generation && d == expected_payload_digest => {
                        return Ok(current);
                    }
                    _ => {}
                }
            }
        }
        // Overflow is Corrupt only when the authoritative current cannot advance.
        if current.meta.generation == u64::MAX {
            return Err(SecureKeyError::Corrupt(
                "sealed state generation overflow".into(),
            ));
        }
        let Some(new_gen) = expected_plus_one else {
            // Caller expected u64::MAX which cannot match a writable current → Conflict.
            return Err(SecureKeyError::Conflict {
                namespace: current.meta.namespace,
                generation: current.meta.generation,
                payload_digest: current.meta.payload_digest,
                key_version: current.meta.key_version,
                degraded: current.meta.health == SealedHealth::Degraded,
            });
        };
        if current.meta.generation != expected_generation
            || current.meta.payload_digest != expected_payload_digest
        {
            return Err(SecureKeyError::Conflict {
                namespace: current.meta.namespace,
                generation: current.meta.generation,
                payload_digest: current.meta.payload_digest,
                key_version: current.meta.key_version,
                degraded: current.meta.health == SealedHealth::Degraded,
            });
        }
        let target = current.meta.current_slot.other();
        let (key_version_i64, key) = self.create_or_load(namespace)?;
        let key_version = Self::key_version_u32(key_version_i64)?;
        self.sealed_cas_write(
            namespace,
            expected_generation,
            Some(expected_payload_digest),
            new_payload,
            target,
            new_gen,
            key_version,
            &key,
            Some((
                current.meta.current_slot,
                expected_generation,
                expected_payload_digest,
            )),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sealed_cas_write(
        &self,
        namespace: &Namespace,
        expected_generation: u64,
        expected_digest: Option<[u8; 32]>,
        payload: SealedPayload,
        target_slot: SealedSlot,
        new_generation: u64,
        key_version: u32,
        key: &SecureKeyBytes,
        prev: Option<(SealedSlot, u64, [u8; 32])>,
    ) -> Result<SealedStateView, SecureKeyError> {
        let install = install_raw(self.installation.as_hex())?;
        let account = sealed_state_account(self.installation.as_hex(), namespace, target_slot)?;
        let pd = payload_digest(payload.as_slice());
        let pd_hex = digest_hex(&pd);
        let expected_pd_hex = expected_digest.map(|d| digest_hex(&d)).unwrap_or_default();
        let prior_slot = prev
            .map(|(s, _, _)| s.suffix().to_owned())
            .unwrap_or_default();
        let op_id = Uuid::new_v4().to_string();
        let ns = namespace.as_str().to_owned();
        let key_version_i64 = i64::from(key_version);
        let ref_id = sealed_state_ref_id(&ns, key_version_i64);

        // 1) Persist saga Prepared (full u64 generations as decimal text).
        self.tx({
            let op_id = op_id.clone();
            let ns = ns.clone();
            let account = account.clone();
            let pd_hex = pd_hex.clone();
            let expected_pd_hex = expected_pd_hex.clone();
            let prior_slot = prior_slot.clone();
            let slot = target_slot.suffix().to_owned();
            move |conn| {
                insert_sealed_state_saga_conn(
                    conn,
                    &op_id,
                    &ns,
                    &slot,
                    &account,
                    expected_generation,
                    new_generation,
                    &pd_hex,
                    &expected_pd_hex,
                    &prior_slot,
                    key_version_i64,
                )
                .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;

        // 2) Reserve consumer ref for this key version
        self.tx({
            let ref_id = ref_id.clone();
            let ns = ns.clone();
            let op_id = op_id.clone();
            move |conn| {
                match reserve_consumer_ref_conn(
                    conn,
                    &ref_id,
                    &ns,
                    key_version_i64,
                    CONSUMER_KIND,
                    &ns,
                )
                .map_err(|e| SecureKeyError::Internal(e.to_string()))?
                {
                    ReserveResult::Reserved(_) | ReserveResult::Idempotent(_) => {}
                    ReserveResult::Retiring => {
                        return Err(SecureKeyError::Retiring {
                            namespace: ns,
                            version: key_version_i64,
                        });
                    }
                    other => {
                        return Err(SecureKeyError::Internal(format!(
                            "sealed state ref reserve: {other:?}"
                        )));
                    }
                }
                set_sealed_state_saga_phase_conn(conn, &op_id, SealedStateSagaPhase::RefReserved)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;

        // 3) Encode + native write
        let encoded = encode_item_base64url(
            &install,
            namespace,
            target_slot,
            new_generation,
            key_version,
            &payload,
            key,
        )?;
        self.store
            .set_secret(SECURE_KEY_SERVICE, &account, encoded.as_bytes())?;
        self.tx({
            let op_id = op_id.clone();
            move |conn| {
                set_sealed_state_saga_phase_conn(conn, &op_id, SealedStateSagaPhase::NativeWritten)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;

        // 4) Reread + verify
        let reread = self.store.get_secret(SECURE_KEY_SERVICE, &account)?;
        let text = std::str::from_utf8(reread.as_slice())
            .map_err(|_| SecureKeyError::Corrupt("sealed write reread utf8".into()))?;
        let (got_gen, got_kv, got_payload, got_pd) =
            decode_and_verify(text, &install, namespace, target_slot, key)?;
        if got_gen != new_generation
            || got_kv != key_version
            || got_pd != pd
            || got_payload.as_slice() != payload.as_slice()
        {
            return Err(SecureKeyError::Corrupt(
                "sealed write reread verification failed".into(),
            ));
        }
        self.tx({
            let op_id = op_id.clone();
            move |conn| {
                set_sealed_state_saga_phase_conn(conn, &op_id, SealedStateSagaPhase::NativeVerified)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;

        // 5) Activate ref
        self.tx({
            let ref_id = ref_id.clone();
            let op_id = op_id.clone();
            move |conn| {
                activate_consumer_ref_conn(conn, &ref_id)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                set_sealed_state_saga_phase_conn(conn, &op_id, SealedStateSagaPhase::RefActivated)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;

        // 6) Complete saga
        self.tx({
            let op_id = op_id.clone();
            move |conn| {
                delete_sealed_state_saga_conn(conn, &op_id)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;

        // Reconcile consumer refs from authoritative slots.
        self.sealed_reconcile_key_refs(namespace)?;

        // Re-select so health matches one-vs-two slot reality (create is Degraded).
        self.sealed_select(namespace)
    }

    /// Resume open sealed-state sagas for one namespace (or all on startup).
    pub fn sealed_resume_open_sagas_for(
        &self,
        namespace: &Namespace,
    ) -> Result<(), SecureKeyError> {
        let ns = namespace.as_str().to_owned();
        let saga = self.read({
            let ns = ns.clone();
            move |conn| get_sealed_state_saga_for_namespace_conn(conn, &ns).map_err(map_saga_db_err)
        })?;
        if let Some(saga) = saga {
            self.sealed_resume_saga(&saga)?;
        }
        Ok(())
    }

    pub fn sealed_startup_resume_all(&self) -> Result<(), SecureKeyError> {
        let sagas =
            self.read(|conn| list_open_sealed_state_sagas_conn(conn).map_err(map_saga_db_err))?;
        for saga in sagas {
            self.sealed_resume_saga(&saga)?;
        }
        Ok(())
    }

    /// Fail-closed saga row shape before any native mutation or success path.
    /// Create: target state-a, empty prior, empty expected digest, 0→1.
    /// CAS: prior is opposite of target, expected digest present, e→e+1.
    fn sealed_validate_saga_shape(saga: &SealedStateSagaRow) -> Result<(), SecureKeyError> {
        if saga.key_version <= 0 {
            return Err(SecureKeyError::Corrupt(
                "saga key_version non-positive".into(),
            ));
        }
        let step_ok = saga.expected_generation.checked_add(1) == Some(saga.new_generation)
            || (saga.expected_generation == 0 && saga.new_generation == 1);
        if !step_ok || saga.new_generation == 0 {
            return Err(SecureKeyError::Corrupt(
                "saga generation pair is not a single-step write".into(),
            ));
        }
        let target = match saga.target_slot.as_str() {
            "state-a" => SealedSlot::A,
            "state-b" => SealedSlot::B,
            _ => {
                return Err(SecureKeyError::Corrupt("saga target_slot".into()));
            }
        };
        let is_create = saga.expected_generation == 0 && saga.new_generation == 1;
        if is_create {
            if target != SealedSlot::A {
                return Err(SecureKeyError::Corrupt(
                    "create saga must target state-a".into(),
                ));
            }
            if !saga.prior_slot.is_empty() || !saga.expected_payload_digest_hex.is_empty() {
                return Err(SecureKeyError::Corrupt(
                    "create saga must have empty prior_slot and expected digest".into(),
                ));
            }
            return Ok(());
        }
        // Non-create CAS saga.
        if saga.expected_payload_digest_hex.is_empty() {
            return Err(SecureKeyError::Corrupt(
                "cas saga missing expected_payload_digest".into(),
            ));
        }
        // Validate hex shape early (fail closed as Corrupt).
        let _ = parse_digest_hex(&saga.expected_payload_digest_hex)?;
        let prior = match saga.prior_slot.as_str() {
            "state-a" => SealedSlot::A,
            "state-b" => SealedSlot::B,
            "" => {
                return Err(SecureKeyError::Corrupt(
                    "cas saga missing prior_slot".into(),
                ));
            }
            _ => {
                return Err(SecureKeyError::Corrupt("saga prior_slot invalid".into()));
            }
        };
        if prior != target.other() {
            return Err(SecureKeyError::Corrupt(
                "cas saga prior_slot must be opposite target_slot".into(),
            ));
        }
        Ok(())
    }

    /// Prove retained prior slot still matches the saga expected generation/digest
    /// (or create: other slot absent) before stripping interrupted target residue.
    fn sealed_prove_prior_intact(
        &self,
        namespace: &Namespace,
        saga: &SealedStateSagaRow,
    ) -> Result<(), SecureKeyError> {
        // Shape already validated by sealed_validate_saga_shape.
        if saga.expected_generation == 0 && saga.prior_slot.is_empty() {
            // Create: only an absent state-b authorizes stripping interrupted state-a.
            let key_loader = |ver: u32| self.load_key_version(namespace, ver);
            match self.sealed_probe_slot(namespace, SealedSlot::B, &key_loader)? {
                SlotProbe::Absent => return Ok(()),
                _ => {
                    return Err(SecureKeyError::Corrupt(
                        "create saga cannot strip target while state-b is present".into(),
                    ));
                }
            }
        }
        let prior = match saga.prior_slot.as_str() {
            "state-a" => SealedSlot::A,
            "state-b" => SealedSlot::B,
            _ => {
                return Err(SecureKeyError::Corrupt("saga prior_slot invalid".into()));
            }
        };
        let expected_pd = parse_digest_hex(&saga.expected_payload_digest_hex)?;
        let key_loader = |ver: u32| self.load_key_version(namespace, ver);
        match self.sealed_probe_slot(namespace, prior, &key_loader)? {
            SlotProbe::Valid {
                generation,
                payload_digest: d,
                ..
            } if generation == saga.expected_generation && d == expected_pd => Ok(()),
            _ => Err(SecureKeyError::Corrupt(
                "retained prior sealed slot does not match saga expected state".into(),
            )),
        }
    }

    fn sealed_resume_saga(&self, saga: &SealedStateSagaRow) -> Result<(), SecureKeyError> {
        let namespace = Namespace::parse(&saga.namespace)
            .map_err(|_| SecureKeyError::Corrupt("saga namespace syntax invalid".into()))?;
        // Unconditional shape validation before any target inspection or success path.
        Self::sealed_validate_saga_shape(saga)?;
        let slot = match saga.target_slot.as_str() {
            "state-a" => SealedSlot::A,
            "state-b" => SealedSlot::B,
            _ => {
                return Err(SecureKeyError::Corrupt("saga target_slot".into()));
            }
        };
        let account = sealed_state_account(self.installation.as_hex(), &namespace, slot)?;
        if account != saga.target_account {
            return Err(SecureKeyError::Corrupt(
                "saga account does not match canonical target".into(),
            ));
        }
        // Operation verification before any native mutation.
        let expected_pd = parse_digest_hex(&saga.payload_digest_hex)?;
        let saga_kv = Self::key_version_u32(saga.key_version)?;
        let install = install_raw(self.installation.as_hex())?;
        let saga_new_gen = saga.new_generation;

        // Authenticate target with the *embedded* key version so a newer rotated-key
        // generation is never deleted when the saga still names an older key.
        match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
            Ok(secret) => {
                let verified_phase = matches!(
                    saga.phase,
                    SealedStateSagaPhase::NativeVerified | SealedStateSagaPhase::RefActivated
                );
                let text = match std::str::from_utf8(secret.as_slice()) {
                    Ok(t) => t,
                    Err(_) => {
                        if verified_phase {
                            return Err(SecureKeyError::Corrupt(
                                "verified sealed write target is unreadable".into(),
                            ));
                        }
                        self.sealed_prove_prior_intact(&namespace, saga)?;
                        self.store.delete_secret(SECURE_KEY_SERVICE, &account)?;
                        let op = saga.op_id.clone();
                        self.tx(move |conn| {
                            delete_sealed_state_saga_conn(conn, &op)
                                .map_err(|e| SecureKeyError::Internal(e.to_string()))
                        })?;
                        return self.sealed_reconcile_key_refs(&namespace);
                    }
                };
                let decoded = match base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    text.as_bytes(),
                ) {
                    Ok(d) if d.len() >= 134 => d,
                    _ => {
                        if verified_phase {
                            return Err(SecureKeyError::Corrupt(
                                "verified sealed write target is noncanonical".into(),
                            ));
                        }
                        self.sealed_prove_prior_intact(&namespace, saga)?;
                        self.store.delete_secret(SECURE_KEY_SERVICE, &account)?;
                        let op = saga.op_id.clone();
                        self.tx(move |conn| {
                            delete_sealed_state_saga_conn(conn, &op)
                                .map_err(|e| SecureKeyError::Internal(e.to_string()))
                        })?;
                        return self.sealed_reconcile_key_refs(&namespace);
                    }
                };
                let embedded_kv = u32::from_be_bytes(decoded[130..134].try_into().unwrap());
                if embedded_kv == 0 {
                    if verified_phase {
                        return Err(SecureKeyError::Corrupt(
                            "verified sealed write has zero key version".into(),
                        ));
                    }
                    self.sealed_prove_prior_intact(&namespace, saga)?;
                    self.store.delete_secret(SECURE_KEY_SERVICE, &account)?;
                    let op = saga.op_id.clone();
                    self.tx(move |conn| {
                        delete_sealed_state_saga_conn(conn, &op)
                            .map_err(|e| SecureKeyError::Internal(e.to_string()))
                    })?;
                    return self.sealed_reconcile_key_refs(&namespace);
                }
                let item_key = match self.load_key_version(&namespace, embedded_kv) {
                    Ok(k) => k,
                    Err(SecureKeyError::NotFound(_)) => {
                        // Well-formed item naming a missing key is Corrupt — never delete
                        // a structured slot as residue (including after key-metadata rollback).
                        return Err(SecureKeyError::Corrupt(format!(
                            "sealed item names missing key version {embedded_kv}"
                        )));
                    }
                    Err(e) => return Err(e),
                };
                match decode_and_verify(text, &install, &namespace, slot, &item_key) {
                    Ok((got_gen, kv, payload, pd)) => {
                        if got_gen == saga_new_gen
                            && kv == saga_kv
                            && pd == expected_pd
                            && payload_digest(payload.as_slice()) == expected_pd
                        {
                            let ref_id = sealed_state_ref_id(&saga.namespace, saga.key_version);
                            let op = saga.op_id.clone();
                            self.tx(move |conn| {
                                let _ = activate_consumer_ref_conn(conn, &ref_id);
                                delete_sealed_state_saga_conn(conn, &op)
                                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
                            })?;
                            return self.sealed_reconcile_key_refs(&namespace);
                        }
                        // Exact gen with field disagreement is an unexplained fork → Corrupt
                        // in every phase. Only strictly newer proves a stale SQLite saga.
                        // Older residue may be stripped after prior proof (pre-verify only).
                        if got_gen == saga_new_gen {
                            return Err(SecureKeyError::Corrupt(
                                "sealed target at new_generation disagrees with saga".into(),
                            ));
                        }
                        let verified_phase = matches!(
                            saga.phase,
                            SealedStateSagaPhase::NativeVerified
                                | SealedStateSagaPhase::RefActivated
                        );
                        if verified_phase && got_gen < saga_new_gen {
                            return Err(SecureKeyError::Corrupt(
                                "verified sealed write target rolled back".into(),
                            ));
                        }
                        if got_gen > saga_new_gen {
                            // Strictly newer authentic target: stale SQLite saga.
                        } else {
                            // Pre-verify older authentic residue: prior must still match.
                            self.sealed_prove_prior_intact(&namespace, saga)?;
                        }
                        let op = saga.op_id.clone();
                        self.tx(move |conn| {
                            delete_sealed_state_saga_conn(conn, &op)
                                .map_err(|e| SecureKeyError::Internal(e.to_string()))
                        })?;
                        return self.sealed_reconcile_key_refs(&namespace);
                    }
                    Err(SecureKeyError::Corrupt(_)) => {
                        // Once native verify was recorded, disappearance/corruption is Corrupt.
                        if matches!(
                            saga.phase,
                            SealedStateSagaPhase::NativeVerified
                                | SealedStateSagaPhase::RefActivated
                        ) {
                            return Err(SecureKeyError::Corrupt(
                                "verified sealed write target is no longer authentic".into(),
                            ));
                        }
                        self.sealed_prove_prior_intact(&namespace, saga)?;
                        self.store.delete_secret(SECURE_KEY_SERVICE, &account)?;
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(SecureKeyError::NotFound(_)) => {
                if matches!(
                    saga.phase,
                    SealedStateSagaPhase::NativeVerified | SealedStateSagaPhase::RefActivated
                ) {
                    return Err(SecureKeyError::Corrupt(
                        "verified sealed write target is missing".into(),
                    ));
                }
                // Interrupted write never landed: prior must still match expected.
                self.sealed_prove_prior_intact(&namespace, saga)?;
            }
            Err(e) => return Err(e),
        }
        let op = saga.op_id.clone();
        self.tx(move |conn| {
            delete_sealed_state_saga_conn(conn, &op)
                .map_err(|e| SecureKeyError::Internal(e.to_string()))
        })?;
        self.sealed_reconcile_key_refs(&namespace)
    }

    /// Ensure every key version named by a valid slot has an Active sealed_state ref;
    /// release refs for versions no longer named by any valid slot.
    pub(crate) fn sealed_reconcile_key_refs(
        &self,
        namespace: &Namespace,
    ) -> Result<(), SecureKeyError> {
        let key_loader = |ver: u32| self.load_key_version(namespace, ver);
        let mut named: Vec<i64> = Vec::new();
        for slot in [SealedSlot::A, SealedSlot::B] {
            match self.sealed_probe_slot(namespace, slot, &key_loader)? {
                SlotProbe::Valid { key_version, .. } => {
                    let v = i64::from(key_version);
                    if !named.contains(&v) {
                        named.push(v);
                    }
                }
                SlotProbe::Absent => {}
                SlotProbe::Invalid => {
                    return Err(SecureKeyError::Corrupt(
                        "sealed reconcile saw unauthenticated slot".into(),
                    ));
                }
            }
        }
        let ns = namespace.as_str().to_owned();
        for ver in &named {
            let ref_id = sealed_state_ref_id(&ns, *ver);
            self.tx({
                let ref_id = ref_id.clone();
                let ns = ns.clone();
                let ver = *ver;
                move |conn| {
                    match reserve_consumer_ref_conn(conn, &ref_id, &ns, ver, CONSUMER_KIND, &ns)
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?
                    {
                        ReserveResult::Reserved(_) | ReserveResult::Idempotent(_) => {
                            if !activate_consumer_ref_conn(conn, &ref_id)
                                .map_err(|e| SecureKeyError::Internal(e.to_string()))?
                            {
                                return Err(SecureKeyError::Internal(
                                    "sealed ref activate failed".into(),
                                ));
                            }
                        }
                        other => {
                            return Err(SecureKeyError::Internal(format!(
                                "sealed ref reserve: {other:?}"
                            )));
                        }
                    }
                    Ok(())
                }
            })?;
        }
        let all_refs = self.read({
            let ns = ns.clone();
            move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT reference_id, version, state
                         FROM secure_key_consumer_refs
                         WHERE namespace = ?1 AND consumer_kind = ?2
                           AND state IN ('Reserved', 'Active', 'Releasing')",
                    )
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                let rows = stmt
                    .query_map(rusqlite::params![ns, CONSUMER_KIND], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;
        for (ref_id, ver, _state) in all_refs {
            if named.contains(&ver) {
                continue;
            }
            // Version no longer named by any valid slot: prove Active→Releasing→Released.
            let id = ref_id;
            self.tx(move |conn| {
                let began = crate::db::secure_key::begin_release_consumer_ref_conn(conn, &id)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                if !began {
                    // Already Releasing/Released or missing — still try mark Released.
                }
                let marked = crate::db::secure_key::mark_consumer_ref_released_conn(conn, &id)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                if !marked && began {
                    return Err(SecureKeyError::Internal(
                        "sealed ref release: began Releasing but mark Released failed".into(),
                    ));
                }
                Ok(())
            })?;
        }
        Ok(())
    }
}
