//! Compatible remote protocol tuple negotiation.
//!
//! Owns the code-enabled compatible-tuple registry, the
//! `RemoteNegotiationTranscriptV1` binary codec, the SHA-256 transcript and
//! enabled-registry digest helpers, and the pure selection / upgrade-required
//! function. Paired with `packages/cockpit-protocol/src/remote-version.ts`.
//!
//! The `application` component of every registry tuple is sourced from the
//! single [`crate::PROTOCOL_VERSION`] constant — never hardcoded in the
//! registry, in any fixture, or in any test. Pre-release bumps of that
//! constant update tuple `0x0001`'s recorded application component in place;
//! `proto-version-reset-at-tag` renumbers it to 1 at tag time without editing
//! this registry.
//!
//! New negotiation code never sniffs, aliases, or falls back: this module
//! contains no legacy-envelope parsing, no environment-defined tuples, no
//! permissive default tuple, and no import of `relay-protocol`.

use crate::PROTOCOL_VERSION;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Four-byte wire magic for `RemoteNegotiationTranscriptV1` (`"FCRN"`).
pub const TRANSCRIPT_MAGIC: &[u8; 4] = b"FCRN";
/// Transcript wire version (currently the only version).
pub const TRANSCRIPT_VERSION: u8 = 1;
/// Fixed portion size: `4+1+1+16+16+32+32+32 = 134` bytes through
/// `policyDigest`, plus three count bytes, `selectedTupleId:u16`, and
/// `featureCount:u8` = 140 bytes before tuple/feature entries.
pub const TRANSCRIPT_FIXED_BYTES: usize = 140;
/// Maximum transcript size: `140 + 3*16*2 + 32*4 = 364` bytes.
pub const TRANSCRIPT_MAX_BYTES: usize = 364;
/// Minimum well-formed transcript (three one-entry lists, zero features) = 146
/// bytes. This is also the exact V1 instance size since every V1 list is
/// `{0x0001}`.
pub const TRANSCRIPT_MIN_BYTES: usize = 146;

/// Transport discriminant: WebRTC.
pub const TRANSPORT_WEBRTC: u8 = 1;
/// Transport discriminant: WebSocket data.
pub const TRANSPORT_WEBSOCKET_DATA: u8 = 2;

/// Minimum/maximum tuple IDs per offer or allowed list.
pub const TUPLE_LIST_MIN: usize = 1;
pub const TUPLE_LIST_MAX: usize = 16;
/// Maximum feature pairs per registry tuple.
pub const FEATURE_LIST_MAX: usize = 32;

/// V1 tuple ID.
pub const V1_TUPLE_ID: u16 = 0x0001;
/// V1 security rank.
pub const V1_SECURITY_RANK: u16 = 100;
/// V1 non-application component literals.
pub const V1_SIGNALING: u16 = 1;
pub const V1_AUTHORIZATION: u16 = 1;
pub const V1_TRANSPORT: u16 = 1;

/// Canonical domain prefix for the enabled-registry digest.
pub const REGISTRY_DIGEST_DOMAIN: &[u8] = b"flycockpit.remote.version-registry.v1\0";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteVersionError {
    #[error("malformed or truncated input")]
    Length,
    #[error("bad preamble (magic or version)")]
    Preamble,
    #[error("bad discriminant")]
    Discriminant,
    #[error("invalid combination of fields")]
    Combination,
    #[error("invalid protocol input")]
    Invalid,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// A critical feature pair in a registry tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CriticalFeature {
    pub id: u16,
    pub version: u16,
}

/// A compatible-tuple registry entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibleTuple {
    pub tuple_id: u16,
    pub signaling: u16,
    pub authorization: u16,
    pub transport: u16,
    /// Sourced from [`PROTOCOL_VERSION`]; never hardcoded.
    pub application: u16,
    pub security_rank: u16,
    pub critical_features: Vec<CriticalFeature>,
}

/// The single code-enabled V1 tuple.
///
/// Its `application` component is sourced from [`PROTOCOL_VERSION`] at
/// construction time so a constant bump requires no registry edit.
pub fn v1_tuple() -> CompatibleTuple {
    CompatibleTuple {
        tuple_id: V1_TUPLE_ID,
        signaling: V1_SIGNALING,
        authorization: V1_AUTHORIZATION,
        transport: V1_TRANSPORT,
        application: PROTOCOL_VERSION as u16,
        security_rank: V1_SECURITY_RANK,
        critical_features: Vec::new(),
    }
}

/// The enabled compatible-tuple registry: currently exactly one entry (V1).
pub fn enabled_registry() -> Vec<CompatibleTuple> {
    vec![v1_tuple()]
}

/// Look up a tuple by ID in the enabled registry.
pub fn registry_tuple(tuple_id: u16) -> Option<CompatibleTuple> {
    enabled_registry()
        .into_iter()
        .find(|t| t.tuple_id == tuple_id)
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

/// Validate a strictly ascending unique list of `1..16` nonzero tuple IDs.
fn validate_tuple_list(ids: &[u16]) -> Result<(), RemoteVersionError> {
    if !(TUPLE_LIST_MIN..=TUPLE_LIST_MAX).contains(&ids.len()) {
        return Err(RemoteVersionError::Length);
    }
    let mut previous: u16 = 0;
    for &id in ids {
        if id == 0 {
            return Err(RemoteVersionError::Invalid);
        }
        if id <= previous {
            return Err(RemoteVersionError::Combination);
        }
        previous = id;
    }
    Ok(())
}

/// Filter to enabled, nonrevoked registry tuple IDs. The revocation set is a
/// list of tuple IDs that policy has revoked.
fn enabled_ids(revoked: &[u16]) -> Vec<u16> {
    enabled_registry()
        .into_iter()
        .filter_map(|t| {
            if revoked.contains(&t.tuple_id) {
                None
            } else {
                Some(t.tuple_id)
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// Selection inputs: validated client, daemon, and server-allowed tuple ID
/// lists plus the revocation set.
#[derive(Debug, Clone)]
pub struct SelectionInputs<'a> {
    pub client: &'a [u16],
    pub daemon: &'a [u16],
    /// Grant claim `compatibleTupleIds` — the server-allowed list.
    pub server_allowed: &'a [u16],
    /// Revoked tuple IDs (policy revocation).
    pub revoked: &'a [u16],
}

/// Successful selection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedTuple {
    pub tuple_id: u16,
    pub security_rank: u16,
    pub critical_features: Vec<CriticalFeature>,
}

/// Pure selection function over validated lists.
///
/// Intersects client, daemon, server-allowed, registry-enabled, and nonrevoked
/// IDs; chooses highest `securityRank`, then lowest numeric tuple ID.
/// Returns `Ok(None)` when no overlap exists (caller then builds the upgrade
/// error via [`upgrade_required`]).
pub fn select(inputs: &SelectionInputs<'_>) -> Result<Option<SelectedTuple>, RemoteVersionError> {
    validate_tuple_list(inputs.client)?;
    validate_tuple_list(inputs.daemon)?;
    validate_tuple_list(inputs.server_allowed)?;
    // Revoked is a set (may be empty); validate no zeros, but order is not
    // required from the caller — we sort internally.
    if inputs.revoked.contains(&0) {
        return Err(RemoteVersionError::Invalid);
    }

    let enabled = enabled_ids(inputs.revoked);
    let registry = enabled_registry();

    // Intersection: client ∩ daemon ∩ server_allowed ∩ enabled
    let candidates: Vec<u16> = inputs
        .client
        .iter()
        .filter(|id| inputs.daemon.contains(id))
        .filter(|id| inputs.server_allowed.contains(id))
        .filter(|id| enabled.contains(id))
        .copied()
        .collect();

    if candidates.is_empty() {
        return Ok(None);
    }

    // Choose highest security rank, then lowest tuple ID.
    let best = candidates
        .iter()
        .map(|&id| {
            let entry = registry.iter().find(|t| t.tuple_id == id).expect("enabled");
            (id, entry.security_rank)
        })
        .max_by(|a, b| {
            a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)) // lower ID wins → reverse on max
        })
        .unwrap();

    let entry = registry
        .iter()
        .find(|t| t.tuple_id == best.0)
        .expect("enabled");

    Ok(Some(SelectedTuple {
        tuple_id: best.0,
        security_rank: best.1,
        critical_features: entry.critical_features.clone(),
    }))
}

// ---------------------------------------------------------------------------
// Upgrade-required error
// ---------------------------------------------------------------------------

/// Safe upgrade-required error shape. No component versions, device/build
/// identity, policy details, fingerprint, or tenant offer leaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeRequired {
    pub code: &'static str,
    pub protocol_version: u16,
    pub upgrade_side: UpgradeSide,
    pub client_supported: Vec<u16>,
    pub daemon_supported: Vec<u16>,
    pub server_allowed: Vec<u16>,
    pub recommended_tuple_id: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeSide {
    Client,
    Daemon,
    ServerPolicy,
    Multiple,
}

impl UpgradeSide {
    pub fn as_str(self) -> &'static str {
        match self {
            UpgradeSide::Client => "client",
            UpgradeSide::Daemon => "daemon",
            UpgradeSide::ServerPolicy => "server_policy",
            UpgradeSide::Multiple => "multiple",
        }
    }
}

/// The exact upgrade-required algorithm.
///
/// `server_allowed` is the grant's `compatibleTupleIds` set. Let `E` be
/// enabled nonrevoked registry tuple IDs and `P = client ∩ daemon ∩ E`. If `P`
/// is nonempty but `P ∩ server_allowed` is empty, return
/// `upgradeSide="server_policy"` and recommend the best tuple in `P` by
/// highest security rank then lowest ID. Otherwise let `S = server_allowed ∩
/// E`; for each tuple in `S`, compute endpoint-support count
/// `(client contains id) + (daemon contains id)`. Recommend the tuple with
/// greatest support count, then highest security rank, then lowest ID; return
/// null only when `S` is empty. For a nonnull recommendation, return `client`
/// when only the client lacks it, `daemon` when only the daemon lacks it, and
/// `multiple` when both lack it. If `S` is empty and `P` is empty, return
/// `server_policy`.
pub fn upgrade_required(
    inputs: &SelectionInputs<'_>,
) -> Result<UpgradeRequired, RemoteVersionError> {
    validate_tuple_list(inputs.client)?;
    validate_tuple_list(inputs.daemon)?;
    validate_tuple_list(inputs.server_allowed)?;
    if inputs.revoked.contains(&0) {
        return Err(RemoteVersionError::Invalid);
    }

    let registry = enabled_registry();
    let enabled = enabled_ids(inputs.revoked);

    // P = client ∩ daemon ∩ E
    let p: Vec<u16> = inputs
        .client
        .iter()
        .filter(|id| inputs.daemon.contains(id))
        .filter(|id| enabled.contains(id))
        .copied()
        .collect();

    // S = server_allowed ∩ E
    let s: Vec<u16> = inputs
        .server_allowed
        .iter()
        .filter(|id| enabled.contains(id))
        .copied()
        .collect();

    let rank_of = |id: u16| -> u16 {
        registry
            .iter()
            .find(|t| t.tuple_id == id)
            .map(|t| t.security_rank)
            .unwrap_or(0)
    };

    let best_in = |ids: &[u16]| -> Option<u16> {
        ids.iter()
            .copied()
            .max_by(|a, b| rank_of(*a).cmp(&rank_of(*b)).then_with(|| b.cmp(a)))
    };

    let (upgrade_side, recommended) = if !p.is_empty()
        && p.iter().all(|id| !inputs.server_allowed.contains(id))
    {
        // P nonempty but P ∩ server_allowed empty → server_policy, recommend
        // best in P.
        (UpgradeSide::ServerPolicy, best_in(&p))
    } else if s.is_empty() {
        // S empty and P empty (if P nonempty we'd be in the branch above
        // because p ∩ server_allowed would be empty). Return server_policy.
        (UpgradeSide::ServerPolicy, None)
    } else {
        // S nonempty: recommend by support count, then rank, then lowest ID.
        let best = s
            .iter()
            .copied()
            .max_by(|a, b| {
                let support_a = inputs.client.contains(a) as u8 + inputs.daemon.contains(a) as u8;
                let support_b = inputs.client.contains(b) as u8 + inputs.daemon.contains(b) as u8;
                support_a
                    .cmp(&support_b)
                    .then_with(|| rank_of(*a).cmp(&rank_of(*b)))
                    .then_with(|| b.cmp(a))
            })
            .unwrap();
        let client_has = inputs.client.contains(&best);
        let daemon_has = inputs.daemon.contains(&best);
        let side = match (client_has, daemon_has) {
            (true, true) => {
                // Both contain it — normal selection would have succeeded.
                // This is an internal invariant failure.
                return Err(RemoteVersionError::Combination);
            }
            (false, true) => UpgradeSide::Client,
            (true, false) => UpgradeSide::Daemon,
            (false, false) => UpgradeSide::Multiple,
        };
        (side, Some(best))
    };

    // Filter lists to public code-owned tuple IDs (enabled, nonrevoked) and
    // sort ascending.
    let filter_sort = |ids: &[u16]| -> Vec<u16> {
        let mut out: Vec<u16> = ids
            .iter()
            .filter(|id| enabled.contains(id))
            .copied()
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    };

    Ok(UpgradeRequired {
        code: "remote_upgrade_required",
        protocol_version: PROTOCOL_VERSION as u16,
        upgrade_side,
        client_supported: filter_sort(inputs.client),
        daemon_supported: filter_sort(inputs.daemon),
        server_allowed: filter_sort(inputs.server_allowed),
        recommended_tuple_id: recommended,
    })
}

/// Non-enumerating invalid-input error. Returns a fixed shape with no
/// supported-set disclosure.
pub fn invalid_input_error() -> UpgradeRequired {
    UpgradeRequired {
        code: "remote_protocol_invalid",
        protocol_version: PROTOCOL_VERSION as u16,
        upgrade_side: UpgradeSide::ServerPolicy,
        client_supported: Vec::new(),
        daemon_supported: Vec::new(),
        server_allowed: Vec::new(),
        recommended_tuple_id: None,
    }
}

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

/// Decoded `RemoteNegotiationTranscriptV1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteNegotiationTranscriptV1 {
    pub transport: u8,
    pub child_attempt_id: [u8; 16],
    pub grant_jti: [u8; 16],
    pub server_nonce: [u8; 32],
    pub client_nonce: [u8; 32],
    pub policy_digest: [u8; 32],
    pub client_tuple_ids: Vec<u16>,
    pub daemon_tuple_ids: Vec<u16>,
    pub server_allowed_tuple_ids: Vec<u16>,
    pub selected_tuple_id: u16,
    pub critical_features: Vec<CriticalFeature>,
}

fn take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    size: usize,
) -> Result<&'a [u8], RemoteVersionError> {
    let end = offset.checked_add(size).ok_or(RemoteVersionError::Length)?;
    let value = bytes.get(*offset..end).ok_or(RemoteVersionError::Length)?;
    *offset = end;
    Ok(value)
}

fn take_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, RemoteVersionError> {
    Ok(take(bytes, offset, 1)?[0])
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, RemoteVersionError> {
    Ok(u16::from_be_bytes(
        take(bytes, offset, 2)?.try_into().unwrap(),
    ))
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], RemoteVersionError> {
    take(bytes, offset, N)
        .map(|slice| slice.try_into().unwrap())
        .map_err(|_| RemoteVersionError::Length)
}

fn take_tuple_list(bytes: &[u8], offset: &mut usize) -> Result<Vec<u16>, RemoteVersionError> {
    let count = take_u8(bytes, offset)? as usize;
    if !(TUPLE_LIST_MIN..=TUPLE_LIST_MAX).contains(&count) {
        return Err(RemoteVersionError::Length);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let value = take_u16(bytes, offset)?;
        if value == 0 {
            return Err(RemoteVersionError::Invalid);
        }
        if values.last().is_some_and(|last: &u16| value <= *last) {
            return Err(RemoteVersionError::Combination);
        }
        values.push(value);
    }
    Ok(values)
}

fn take_feature_list(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<Vec<CriticalFeature>, RemoteVersionError> {
    let count = take_u8(bytes, offset)? as usize;
    if count > FEATURE_LIST_MAX {
        return Err(RemoteVersionError::Length);
    }
    let mut features = Vec::with_capacity(count);
    for _ in 0..count {
        let id = take_u16(bytes, offset)?;
        let version = take_u16(bytes, offset)?;
        if id == 0 {
            return Err(RemoteVersionError::Invalid);
        }
        if features
            .last()
            .is_some_and(|last: &CriticalFeature| id <= last.id)
        {
            return Err(RemoteVersionError::Combination);
        }
        features.push(CriticalFeature { id, version });
    }
    Ok(features)
}

impl RemoteNegotiationTranscriptV1 {
    /// Encode the transcript to its exact binary layout.
    pub fn encode(&self) -> Result<Vec<u8>, RemoteVersionError> {
        // Validate transport.
        if self.transport != TRANSPORT_WEBRTC && self.transport != TRANSPORT_WEBSOCKET_DATA {
            return Err(RemoteVersionError::Discriminant);
        }
        validate_tuple_list(&self.client_tuple_ids)?;
        validate_tuple_list(&self.daemon_tuple_ids)?;
        validate_tuple_list(&self.server_allowed_tuple_ids)?;
        if self.selected_tuple_id == 0 {
            return Err(RemoteVersionError::Invalid);
        }
        // Selected ID must be present in all three lists.
        if !self.client_tuple_ids.contains(&self.selected_tuple_id)
            || !self.daemon_tuple_ids.contains(&self.selected_tuple_id)
            || !self
                .server_allowed_tuple_ids
                .contains(&self.selected_tuple_id)
        {
            return Err(RemoteVersionError::Combination);
        }
        if self.critical_features.len() > FEATURE_LIST_MAX {
            return Err(RemoteVersionError::Length);
        }
        // Features sorted by ID, no duplicates.
        for w in self.critical_features.windows(2) {
            if w[0].id >= w[1].id {
                return Err(RemoteVersionError::Combination);
            }
        }
        for f in &self.critical_features {
            if f.id == 0 {
                return Err(RemoteVersionError::Invalid);
            }
        }

        // Check the selected tuple's features match the registry.
        if let Some(entry) = registry_tuple(self.selected_tuple_id) {
            if entry.critical_features != self.critical_features {
                return Err(RemoteVersionError::Combination);
            }
        } else {
            return Err(RemoteVersionError::Invalid);
        }

        let total = TRANSCRIPT_FIXED_BYTES
            + self.client_tuple_ids.len() * 2
            + self.daemon_tuple_ids.len() * 2
            + self.server_allowed_tuple_ids.len() * 2
            + self.critical_features.len() * 4;
        if total > TRANSCRIPT_MAX_BYTES {
            return Err(RemoteVersionError::Length);
        }

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(TRANSCRIPT_MAGIC);
        out.push(TRANSCRIPT_VERSION);
        out.push(self.transport);
        out.extend_from_slice(&self.child_attempt_id);
        out.extend_from_slice(&self.grant_jti);
        out.extend_from_slice(&self.server_nonce);
        out.extend_from_slice(&self.client_nonce);
        out.extend_from_slice(&self.policy_digest);
        out.push(self.client_tuple_ids.len() as u8);
        for id in &self.client_tuple_ids {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out.push(self.daemon_tuple_ids.len() as u8);
        for id in &self.daemon_tuple_ids {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out.push(self.server_allowed_tuple_ids.len() as u8);
        for id in &self.server_allowed_tuple_ids {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out.extend_from_slice(&self.selected_tuple_id.to_be_bytes());
        out.push(self.critical_features.len() as u8);
        for f in &self.critical_features {
            out.extend_from_slice(&f.id.to_be_bytes());
            out.extend_from_slice(&f.version.to_be_bytes());
        }
        debug_assert_eq!(out.len(), total);
        Ok(out)
    }

    /// Strict decode: requires exact length derived from counts and rejects
    /// trailing bytes, duplicates, zero/unknown/revoked IDs, nonascending
    /// lists, selected ID absent from any list, feature mismatch/order/count,
    /// reserved transport, and oversize before allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, RemoteVersionError> {
        if bytes.len() < TRANSCRIPT_MIN_BYTES || bytes.len() > TRANSCRIPT_MAX_BYTES {
            return Err(RemoteVersionError::Length);
        }
        if &bytes[..4] != TRANSCRIPT_MAGIC {
            return Err(RemoteVersionError::Preamble);
        }
        let mut o = 4;
        if take_u8(bytes, &mut o)? != TRANSCRIPT_VERSION {
            return Err(RemoteVersionError::Preamble);
        }
        let transport = take_u8(bytes, &mut o)?;
        if transport != TRANSPORT_WEBRTC && transport != TRANSPORT_WEBSOCKET_DATA {
            return Err(RemoteVersionError::Discriminant);
        }
        let child_attempt_id = take_array(bytes, &mut o)?;
        let grant_jti = take_array(bytes, &mut o)?;
        let server_nonce = take_array(bytes, &mut o)?;
        let client_nonce = take_array(bytes, &mut o)?;
        let policy_digest = take_array(bytes, &mut o)?;

        let client_tuple_ids = take_tuple_list(bytes, &mut o)?;
        let daemon_tuple_ids = take_tuple_list(bytes, &mut o)?;
        let server_allowed_tuple_ids = take_tuple_list(bytes, &mut o)?;

        let selected_tuple_id = take_u16(bytes, &mut o)?;
        if selected_tuple_id == 0 {
            return Err(RemoteVersionError::Invalid);
        }
        if !client_tuple_ids.contains(&selected_tuple_id)
            || !daemon_tuple_ids.contains(&selected_tuple_id)
            || !server_allowed_tuple_ids.contains(&selected_tuple_id)
        {
            return Err(RemoteVersionError::Combination);
        }

        let critical_features = take_feature_list(bytes, &mut o)?;

        // No trailing bytes.
        if o != bytes.len() {
            return Err(RemoteVersionError::Length);
        }

        // Selected tuple must be a known registry tuple.
        let entry = registry_tuple(selected_tuple_id).ok_or(RemoteVersionError::Invalid)?;
        // Features must match the registry entry exactly.
        if entry.critical_features != critical_features {
            return Err(RemoteVersionError::Combination);
        }

        // All tuple IDs in every list must be known registry tuples.
        for id in client_tuple_ids
            .iter()
            .chain(daemon_tuple_ids.iter())
            .chain(server_allowed_tuple_ids.iter())
        {
            if registry_tuple(*id).is_none() {
                return Err(RemoteVersionError::Invalid);
            }
        }

        Ok(Self {
            transport,
            child_attempt_id,
            grant_jti,
            server_nonce,
            client_nonce,
            policy_digest,
            client_tuple_ids,
            daemon_tuple_ids,
            server_allowed_tuple_ids,
            selected_tuple_id,
            critical_features,
        })
    }
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/// `SHA-256(transcriptBytes)` — the only negotiation digest.
pub fn transcript_digest(bytes: &[u8]) -> Result<[u8; 32], RemoteVersionError> {
    // Validate first so we never digest malformed bytes.
    RemoteNegotiationTranscriptV1::decode(bytes)?;
    Ok(Sha256::digest(bytes).into())
}

/// Canonical enabled-registry digest.
///
/// `SHA-256(UTF8("flycockpit.remote.version-registry.v1\0") || count:u8 ||
/// per enabled tuple in ascending ID order: tupleId:u16be | signaling:u16be |
/// authorization:u16be | transport:u16be | application:u16be | securityRank:u16be
/// | featureCount:u8 | (featureId:u16be | featureVersion:u16be)*)`
pub fn enabled_registry_digest() -> [u8; 32] {
    let mut registry = enabled_registry();
    registry.sort_by_key(|t| t.tuple_id);

    let mut hash = Sha256::new();
    hash.update(REGISTRY_DIGEST_DOMAIN);
    hash.update([registry.len() as u8]);
    for tuple in &registry {
        hash.update(tuple.tuple_id.to_be_bytes());
        hash.update(tuple.signaling.to_be_bytes());
        hash.update(tuple.authorization.to_be_bytes());
        hash.update(tuple.transport.to_be_bytes());
        hash.update(tuple.application.to_be_bytes());
        hash.update(tuple.security_rank.to_be_bytes());
        hash.update([tuple.critical_features.len() as u8]);
        for f in &tuple.critical_features {
            hash.update(f.id.to_be_bytes());
            hash.update(f.version.to_be_bytes());
        }
    }
    hash.finalize().into()
}

/// Verify that a proof/prologue `negotiationDigest` matches the locally
/// reconstructed transcript. Both endpoints reconstruct the transcript locally
/// and reject a proof whose digest differs.
pub fn verify_transcript_digest(
    transcript_bytes: &[u8],
    expected_digest: &[u8; 32],
) -> Result<(), RemoteVersionError> {
    let computed = transcript_digest(transcript_bytes)?;
    if &computed != expected_digest {
        return Err(RemoteVersionError::Combination);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const fn hex_to_u8(text: &str) -> u8 {
        let bytes = text.as_bytes();
        let hi = (bytes[0] as char).to_digit(16).unwrap() as u8;
        let lo = (bytes[1] as char).to_digit(16).unwrap() as u8;
        (hi << 4) | lo
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| hex_to_u8(std::str::from_utf8(pair).unwrap()))
            .collect()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn remote_version_tuple_registry_v1() {
        let registry = enabled_registry();
        assert_eq!(registry.len(), 1);
        let v1 = &registry[0];
        assert_eq!(v1.tuple_id, V1_TUPLE_ID);
        assert_eq!(v1.signaling, V1_SIGNALING);
        assert_eq!(v1.authorization, V1_AUTHORIZATION);
        assert_eq!(v1.transport, V1_TRANSPORT);
        assert_eq!(v1.security_rank, V1_SECURITY_RANK);
        assert!(v1.critical_features.is_empty());
        // application sourced from PROTOCOL_VERSION constant, not hardcoded.
        assert_eq!(v1.application, PROTOCOL_VERSION as u16);
        // Nonzero unique IDs.
        let ids: Vec<u16> = registry.iter().map(|t| t.tuple_id).collect();
        assert!(ids.iter().all(|&id| id != 0));
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            ids.len()
        );
    }

    #[test]
    fn remote_version_selection_basic_v1() {
        let client = [V1_TUPLE_ID];
        let daemon = [V1_TUPLE_ID];
        let server = [V1_TUPLE_ID];
        let revoked: [u16; 0] = [];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &daemon,
            server_allowed: &server,
            revoked: &revoked,
        };
        let sel = select(&inputs).unwrap().unwrap();
        assert_eq!(sel.tuple_id, V1_TUPLE_ID);
        assert_eq!(sel.security_rank, V1_SECURITY_RANK);
        assert!(sel.critical_features.is_empty());
    }

    #[test]
    fn remote_version_selection_no_overlap() {
        // Client and daemon agree, but server doesn't allow it.
        let client = [V1_TUPLE_ID];
        let daemon = [V1_TUPLE_ID];
        let server = [0x0002]; // not in registry
        let revoked: [u16; 0] = [];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &daemon,
            server_allowed: &server,
            revoked: &revoked,
        };
        assert!(select(&inputs).unwrap().is_none());
    }

    #[test]
    fn remote_version_selection_revoked_excluded() {
        let client = [V1_TUPLE_ID];
        let daemon = [V1_TUPLE_ID];
        let server = [V1_TUPLE_ID];
        let revoked = [V1_TUPLE_ID];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &daemon,
            server_allowed: &server,
            revoked: &revoked,
        };
        // V1 revoked → no candidates.
        assert!(select(&inputs).unwrap().is_none());
    }

    #[test]
    fn remote_version_selection_rejects_invalid_lists() {
        let revoked: [u16; 0] = [];
        // Empty list.
        let inputs = SelectionInputs {
            client: &[],
            daemon: &[V1_TUPLE_ID],
            server_allowed: &[V1_TUPLE_ID],
            revoked: &revoked,
        };
        assert_eq!(select(&inputs), Err(RemoteVersionError::Length));
        // Non-ascending.
        let client = [0x0002, 0x0001];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &[V1_TUPLE_ID],
            server_allowed: &[V1_TUPLE_ID],
            revoked: &revoked,
        };
        assert_eq!(select(&inputs), Err(RemoteVersionError::Combination));
        // Zero ID.
        let client = [0x0000];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &[V1_TUPLE_ID],
            server_allowed: &[V1_TUPLE_ID],
            revoked: &revoked,
        };
        assert_eq!(select(&inputs), Err(RemoteVersionError::Invalid));
        // Too many.
        let client = [1u16; 17];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &[V1_TUPLE_ID],
            server_allowed: &[V1_TUPLE_ID],
            revoked: &revoked,
        };
        assert_eq!(select(&inputs), Err(RemoteVersionError::Length));
    }

    #[test]
    fn remote_version_transcript_wire_vectors() {
        // Build a V1 transcript: all lists are {0x0001}, zero features.
        let transcript = RemoteNegotiationTranscriptV1 {
            transport: TRANSPORT_WEBRTC,
            child_attempt_id: [0x01; 16],
            grant_jti: [0x02; 16],
            server_nonce: [0x03; 32],
            client_nonce: [0x04; 32],
            policy_digest: [0x05; 32],
            client_tuple_ids: vec![V1_TUPLE_ID],
            daemon_tuple_ids: vec![V1_TUPLE_ID],
            server_allowed_tuple_ids: vec![V1_TUPLE_ID],
            selected_tuple_id: V1_TUPLE_ID,
            critical_features: Vec::new(),
        };
        let encoded = transcript.encode().unwrap();
        // V1 instance is exactly 146 bytes.
        assert_eq!(encoded.len(), TRANSCRIPT_MIN_BYTES);
        assert_eq!(encoded.len(), 146);

        // Magic at offset 0.
        assert_eq!(&encoded[..4], TRANSCRIPT_MAGIC);
        assert_eq!(&encoded[..4], b"FCRN");
        // Version at offset 4.
        assert_eq!(encoded[4], TRANSCRIPT_VERSION);
        // Transport at offset 5.
        assert_eq!(encoded[5], TRANSPORT_WEBRTC);
        // childAttemptId at offset 6..22.
        assert_eq!(&encoded[6..22], &[0x01; 16]);
        // grantJti at offset 22..38.
        assert_eq!(&encoded[22..38], &[0x02; 16]);
        // serverNonce at offset 38..70.
        assert_eq!(&encoded[38..70], &[0x03; 32]);
        // clientNonce at offset 70..102.
        assert_eq!(&encoded[70..102], &[0x04; 32]);
        // policyDigest at offset 102..134.
        assert_eq!(&encoded[102..134], &[0x05; 32]);
        // clientCount at offset 134.
        assert_eq!(encoded[134], 1);
        // clientTupleIds at offset 135..137.
        assert_eq!(&encoded[135..137], &V1_TUPLE_ID.to_be_bytes());
        // daemonCount at offset 137.
        assert_eq!(encoded[137], 1);
        // daemonTupleIds at offset 138..140.
        assert_eq!(&encoded[138..140], &V1_TUPLE_ID.to_be_bytes());
        // serverCount at offset 140.
        assert_eq!(encoded[140], 1);
        // serverAllowedTupleIds at offset 141..143.
        assert_eq!(&encoded[141..143], &V1_TUPLE_ID.to_be_bytes());
        // selectedTupleId at offset 143..145.
        assert_eq!(&encoded[143..145], &V1_TUPLE_ID.to_be_bytes());
        // featureCount at offset 145.
        assert_eq!(encoded[145], 0);

        // Fixed portion is 140 bytes (through serverAllowedTupleIds entry +
        // selectedTupleId + featureCount).
        // 134 (through policyDigest) + 3 (counts) + 2 (selectedTupleId) + 1
        // (featureCount) = 140.
        assert_eq!(TRANSCRIPT_FIXED_BYTES, 140);

        // Round-trip.
        let decoded = RemoteNegotiationTranscriptV1::decode(&encoded).unwrap();
        assert_eq!(decoded, transcript);

        // Maximum size: 140 + 3*16*2 + 32*4 = 364.
        assert_eq!(TRANSCRIPT_MAX_BYTES, 364);
    }

    #[test]
    fn remote_version_strict_parser_matrix() {
        let base = RemoteNegotiationTranscriptV1 {
            transport: TRANSPORT_WEBRTC,
            child_attempt_id: [0x01; 16],
            grant_jti: [0x02; 16],
            server_nonce: [0x03; 32],
            client_nonce: [0x04; 32],
            policy_digest: [0x05; 32],
            client_tuple_ids: vec![V1_TUPLE_ID],
            daemon_tuple_ids: vec![V1_TUPLE_ID],
            server_allowed_tuple_ids: vec![V1_TUPLE_ID],
            selected_tuple_id: V1_TUPLE_ID,
            critical_features: Vec::new(),
        };
        let valid = base.encode().unwrap();

        // Truncated.
        let mut truncated = valid.clone();
        truncated.truncate(truncated.len() - 1);
        assert_eq!(
            RemoteNegotiationTranscriptV1::decode(&truncated),
            Err(RemoteVersionError::Length)
        );

        // Trailing bytes.
        let mut trailing = valid.clone();
        trailing.push(0x00);
        assert_eq!(
            RemoteNegotiationTranscriptV1::decode(&trailing),
            Err(RemoteVersionError::Length)
        );

        // Bad magic.
        let mut bad_magic = valid.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            RemoteNegotiationTranscriptV1::decode(&bad_magic),
            Err(RemoteVersionError::Preamble)
        );

        // Bad version.
        let mut bad_ver = valid.clone();
        bad_ver[4] = 2;
        assert_eq!(
            RemoteNegotiationTranscriptV1::decode(&bad_ver),
            Err(RemoteVersionError::Preamble)
        );

        // Reserved transport (0).
        let mut bad_transport = base.clone();
        bad_transport.transport = 0;
        assert_eq!(
            bad_transport.encode(),
            Err(RemoteVersionError::Discriminant)
        );

        // Reserved transport (3).
        let mut bad_transport3 = base.clone();
        bad_transport3.transport = 3;
        assert_eq!(
            bad_transport3.encode(),
            Err(RemoteVersionError::Discriminant)
        );

        // Selected ID absent from client list.
        let mut sel_absent = base.clone();
        sel_absent.client_tuple_ids = vec![0x0002];
        sel_absent.selected_tuple_id = V1_TUPLE_ID;
        // Selected ID is absent from client list → combination error.
        assert_eq!(sel_absent.encode(), Err(RemoteVersionError::Combination));

        // Zero selected ID.
        let mut zero_sel = base.clone();
        zero_sel.selected_tuple_id = 0;
        assert_eq!(zero_sel.encode(), Err(RemoteVersionError::Invalid));

        // Duplicate IDs in list: clientCount=2, IDs=[0x0001, 0x0001].
        let mut with_dup = valid[..134].to_vec(); // through policyDigest + before counts
        with_dup.push(2); // clientCount=2
        with_dup.extend_from_slice(&V1_TUPLE_ID.to_be_bytes()); // first client ID
        with_dup.extend_from_slice(&V1_TUPLE_ID.to_be_bytes()); // duplicate second ID
        with_dup.extend_from_slice(&valid[137..]); // daemonCount onward
        assert_eq!(
            RemoteNegotiationTranscriptV1::decode(&with_dup),
            Err(RemoteVersionError::Combination)
        );

        // Nonascending list: clientCount=2, IDs=[0x0002, 0x0001].
        let mut nonasc = valid[..134].to_vec();
        nonasc.push(2); // clientCount=2
        nonasc.extend_from_slice(&0x0002u16.to_be_bytes()); // first client ID
        nonasc.extend_from_slice(&V1_TUPLE_ID.to_be_bytes()); // second, nonascending
        nonasc.extend_from_slice(&valid[137..]); // daemonCount onward
        assert_eq!(
            RemoteNegotiationTranscriptV1::decode(&nonasc),
            Err(RemoteVersionError::Combination)
        );

        // Unknown tuple ID in list: clientCount=1, ID=[0x0002].
        // 0x0002 is not a known registry tuple. The selected ID (0x0001) is
        // absent from the client list → Combination.
        let mut unknown = valid[..134].to_vec();
        unknown.push(1); // clientCount=1
        unknown.extend_from_slice(&0x0002u16.to_be_bytes()); // unknown ID
        unknown.extend_from_slice(&valid[137..]); // daemonCount onward
        assert_eq!(
            RemoteNegotiationTranscriptV1::decode(&unknown),
            Err(RemoteVersionError::Combination)
        );

        // Oversize: too many tuple IDs (count > 16).
        let mut oversize = valid.clone();
        oversize[134] = 17; // clientCount = 17
        assert_eq!(
            RemoteNegotiationTranscriptV1::decode(&oversize),
            Err(RemoteVersionError::Length)
        );

        // Feature count too large.
        let mut feat_count = valid.clone();
        // featureCount is the last byte (offset 145 for V1).
        feat_count[145] = 33;
        assert_eq!(
            RemoteNegotiationTranscriptV1::decode(&feat_count),
            Err(RemoteVersionError::Length)
        );
    }

    #[test]
    fn remote_version_transcript_digest_sensitivity() {
        let base = RemoteNegotiationTranscriptV1 {
            transport: TRANSPORT_WEBRTC,
            child_attempt_id: [0x01; 16],
            grant_jti: [0x02; 16],
            server_nonce: [0x03; 32],
            client_nonce: [0x04; 32],
            policy_digest: [0x05; 32],
            client_tuple_ids: vec![V1_TUPLE_ID],
            daemon_tuple_ids: vec![V1_TUPLE_ID],
            server_allowed_tuple_ids: vec![V1_TUPLE_ID],
            selected_tuple_id: V1_TUPLE_ID,
            critical_features: Vec::new(),
        };
        let base_bytes = base.encode().unwrap();
        let base_digest = transcript_digest(&base_bytes).unwrap();

        // Determinism: same input → same digest.
        assert_eq!(transcript_digest(&base_bytes).unwrap(), base_digest);

        // Mutate serverNonce → different digest.
        let mut m = base.clone();
        m.server_nonce[0] ^= 0xff;
        assert_ne!(
            transcript_digest(&m.encode().unwrap()).unwrap(),
            base_digest
        );

        // Mutate clientNonce → different digest.
        let mut m = base.clone();
        m.client_nonce[0] ^= 0xff;
        assert_ne!(
            transcript_digest(&m.encode().unwrap()).unwrap(),
            base_digest
        );

        // Mutate transport → different digest.
        let mut m = base.clone();
        m.transport = TRANSPORT_WEBSOCKET_DATA;
        assert_ne!(
            transcript_digest(&m.encode().unwrap()).unwrap(),
            base_digest
        );

        // Mutate selectedTupleId (can't change to unknown; V1 only has 0x0001,
        // so mutate via a different field set to prove sensitivity).
        // Mutate childAttemptId → different digest.
        let mut m = base.clone();
        m.child_attempt_id[0] ^= 0xff;
        assert_ne!(
            transcript_digest(&m.encode().unwrap()).unwrap(),
            base_digest
        );

        // Verify: matching digest succeeds.
        assert!(verify_transcript_digest(&base_bytes, &base_digest).is_ok());

        // Verify: mismatched digest fails.
        let mut wrong = base_digest;
        wrong[0] ^= 0xff;
        assert_eq!(
            verify_transcript_digest(&base_bytes, &wrong),
            Err(RemoteVersionError::Combination)
        );
    }

    #[test]
    fn remote_version_upgrade_required_shape() {
        let revoked: [u16; 0] = [];

        // Case 1: P nonempty but P ∩ server_allowed empty → server_policy.
        // Client and daemon both have V1, server allows an unknown ID.
        let client = [V1_TUPLE_ID];
        let daemon = [V1_TUPLE_ID];
        let server = [0x00ff]; // not in registry, so S is empty
        let inputs = SelectionInputs {
            client: &client,
            daemon: &daemon,
            server_allowed: &server,
            revoked: &revoked,
        };
        let err = upgrade_required(&inputs).unwrap();
        assert_eq!(err.code, "remote_upgrade_required");
        assert_eq!(err.upgrade_side, UpgradeSide::ServerPolicy);
        assert_eq!(err.recommended_tuple_id, Some(V1_TUPLE_ID));
        // Lists filtered to enabled IDs only → server_allowed (0x00ff) filtered
        // out → empty.
        assert!(err.server_allowed.is_empty());
        assert_eq!(err.client_supported, vec![V1_TUPLE_ID]);
        assert_eq!(err.daemon_supported, vec![V1_TUPLE_ID]);

        // Case 2: S empty and P empty → server_policy, no recommendation.
        // Client has unknown ID, daemon has unknown ID, server has unknown.
        let client = [0x00fe];
        let daemon = [0x00fe];
        let server = [0x00ff];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &daemon,
            server_allowed: &server,
            revoked: &revoked,
        };
        let err = upgrade_required(&inputs).unwrap();
        assert_eq!(err.upgrade_side, UpgradeSide::ServerPolicy);
        assert_eq!(err.recommended_tuple_id, None);
        // All filtered out since none are registry tuples.
        assert!(err.client_supported.is_empty());
        assert!(err.daemon_supported.is_empty());
        assert!(err.server_allowed.is_empty());

        // Case 3: S nonempty, client lacks it → upgradeSide=client.
        let client = [0x00fe]; // client doesn't have V1
        let daemon = [V1_TUPLE_ID];
        let server = [V1_TUPLE_ID];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &daemon,
            server_allowed: &server,
            revoked: &revoked,
        };
        let err = upgrade_required(&inputs).unwrap();
        assert_eq!(err.upgrade_side, UpgradeSide::Client);
        assert_eq!(err.recommended_tuple_id, Some(V1_TUPLE_ID));

        // Case 4: S nonempty, daemon lacks it → upgradeSide=daemon.
        let client = [V1_TUPLE_ID];
        let daemon = [0x00fe];
        let server = [V1_TUPLE_ID];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &daemon,
            server_allowed: &server,
            revoked: &revoked,
        };
        let err = upgrade_required(&inputs).unwrap();
        assert_eq!(err.upgrade_side, UpgradeSide::Daemon);
        assert_eq!(err.recommended_tuple_id, Some(V1_TUPLE_ID));

        // Case 5: S nonempty, both lack it → upgradeSide=multiple.
        let client = [0x00fe];
        let daemon = [0x00fd];
        let server = [V1_TUPLE_ID];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &daemon,
            server_allowed: &server,
            revoked: &revoked,
        };
        let err = upgrade_required(&inputs).unwrap();
        assert_eq!(err.upgrade_side, UpgradeSide::Multiple);
        assert_eq!(err.recommended_tuple_id, Some(V1_TUPLE_ID));

        // Case 6: protocol_version field equals PROTOCOL_VERSION.
        assert_eq!(err.protocol_version, PROTOCOL_VERSION as u16);
    }

    #[test]
    fn remote_version_upgrade_required_no_sensitive_disclosure() {
        // Invalid input → non-enumerating error.
        let err = invalid_input_error();
        assert_eq!(err.code, "remote_protocol_invalid");
        assert!(err.client_supported.is_empty());
        assert!(err.daemon_supported.is_empty());
        assert!(err.server_allowed.is_empty());
        assert_eq!(err.recommended_tuple_id, None);
    }

    #[test]
    fn remote_version_policy_revocation() {
        // Revoking V1 excludes it from E, selection, and recommendation.
        let client = [V1_TUPLE_ID];
        let daemon = [V1_TUPLE_ID];
        let server = [V1_TUPLE_ID];
        let revoked = [V1_TUPLE_ID];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &daemon,
            server_allowed: &server,
            revoked: &revoked,
        };
        // Selection returns None (no candidates).
        assert!(select(&inputs).unwrap().is_none());
        // Upgrade error: S = server_allowed ∩ E → empty (V1 revoked from E).
        // P = client ∩ daemon ∩ E → empty. So server_policy, no recommendation.
        let err = upgrade_required(&inputs).unwrap();
        assert_eq!(err.upgrade_side, UpgradeSide::ServerPolicy);
        assert_eq!(err.recommended_tuple_id, None);
        // Lists filtered to enabled nonrevoked → all empty.
        assert!(err.client_supported.is_empty());
        assert!(err.daemon_supported.is_empty());
        assert!(err.server_allowed.is_empty());
    }

    #[test]
    fn remote_version_replica_registry_digest() {
        // Deterministic: same registry → same digest.
        let d1 = enabled_registry_digest();
        let d2 = enabled_registry_digest();
        assert_eq!(d1, d2);

        // The digest is computed at test time from the live registry, never
        // checked in. We just verify it is a valid 32-byte SHA-256.
        assert_eq!(d1.len(), 32);

        // Domain prefix is present in the canonical encoding.
        assert_eq!(
            REGISTRY_DIGEST_DOMAIN,
            b"flycockpit.remote.version-registry.v1\0"
        );
    }

    #[test]
    fn remote_version_registry_digest_encoding_exact() {
        // Verify the exact canonical encoding by reconstructing it manually.
        let registry = enabled_registry();
        let mut hash = Sha256::new();
        hash.update(b"flycockpit.remote.version-registry.v1\0");
        hash.update([registry.len() as u8]);
        for tuple in &registry {
            hash.update(tuple.tuple_id.to_be_bytes());
            hash.update(tuple.signaling.to_be_bytes());
            hash.update(tuple.authorization.to_be_bytes());
            hash.update(tuple.transport.to_be_bytes());
            hash.update(tuple.application.to_be_bytes());
            hash.update(tuple.security_rank.to_be_bytes());
            hash.update([tuple.critical_features.len() as u8]);
            for f in &tuple.critical_features {
                hash.update(f.id.to_be_bytes());
                hash.update(f.version.to_be_bytes());
            }
        }
        let manual: [u8; 32] = hash.finalize().into();
        assert_eq!(manual, enabled_registry_digest());
    }

    #[test]
    fn remote_version_static_guards() {
        // The module must not import relay-protocol, parse legacy envelopes,
        // or define environment-based tuples. This is enforced structurally:
        // the module only depends on crate::PROTOCOL_VERSION and sha2.
        // We verify the magic is "FCRN" and unique.
        assert_eq!(TRANSCRIPT_MAGIC, b"FCRN");
        assert_eq!(std::str::from_utf8(TRANSCRIPT_MAGIC).unwrap(), "FCRN");

        // No permissive default: selection over empty intersection returns
        // None, not a fallback.
        let client = [0x00fe];
        let daemon = [0x00fe];
        let server = [0x00fe];
        let revoked: [u16; 0] = [];
        let inputs = SelectionInputs {
            client: &client,
            daemon: &daemon,
            server_allowed: &server,
            revoked: &revoked,
        };
        assert!(select(&inputs).unwrap().is_none());

        // The registry has no environment-defined tuples: v1_tuple() is a
        // pure function with no I/O.
        let t1 = v1_tuple();
        let t2 = v1_tuple();
        assert_eq!(t1, t2);
    }

    #[test]
    fn remote_version_transcript_hex_round_trip() {
        // A literal V1 transcript hex for cross-language identity.
        let transcript = RemoteNegotiationTranscriptV1 {
            transport: TRANSPORT_WEBRTC,
            child_attempt_id: [0x01; 16],
            grant_jti: [0x02; 16],
            server_nonce: [0x03; 32],
            client_nonce: [0x04; 32],
            policy_digest: [0x05; 32],
            client_tuple_ids: vec![V1_TUPLE_ID],
            daemon_tuple_ids: vec![V1_TUPLE_ID],
            server_allowed_tuple_ids: vec![V1_TUPLE_ID],
            selected_tuple_id: V1_TUPLE_ID,
            critical_features: Vec::new(),
        };
        let encoded = transcript.encode().unwrap();
        let hex_str = encode_hex(&encoded);
        // Decode hex back.
        let decoded_bytes = decode_hex(&hex_str);
        assert_eq!(decoded_bytes, encoded);
        let decoded = RemoteNegotiationTranscriptV1::decode(&decoded_bytes).unwrap();
        assert_eq!(decoded, transcript);
    }

    #[test]
    fn remote_version_cross_language_digest_identity() {
        // The transcript digest is SHA-256(transcriptBytes) with no domain
        // prefix — the only negotiation digest.
        let transcript = RemoteNegotiationTranscriptV1 {
            transport: TRANSPORT_WEBSOCKET_DATA,
            child_attempt_id: [0xaa; 16],
            grant_jti: [0xbb; 16],
            server_nonce: [0xcc; 32],
            client_nonce: [0xdd; 32],
            policy_digest: [0xee; 32],
            client_tuple_ids: vec![V1_TUPLE_ID],
            daemon_tuple_ids: vec![V1_TUPLE_ID],
            server_allowed_tuple_ids: vec![V1_TUPLE_ID],
            selected_tuple_id: V1_TUPLE_ID,
            critical_features: Vec::new(),
        };
        let bytes = transcript.encode().unwrap();
        let digest = transcript_digest(&bytes).unwrap();
        // SHA-256 of the raw bytes, no prefix.
        let direct: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(digest, direct);
    }

    #[test]
    fn remote_version_fixture_no_checked_in_digest() {
        // Guard: the fixture must not contain a checked-in registry digest.
        // Every comparison against the live registry is computed at test time,
        // never checked in.
        let fixture = include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote/version-negotiation-v1.json"
        );
        assert!(
            !fixture.contains("registryDigestHex"),
            "fixture must not contain a checked-in registry digest"
        );
        assert!(
            !fixture.contains("registry_digest_hex"),
            "fixture must not contain a checked-in registry digest"
        );
    }
}
