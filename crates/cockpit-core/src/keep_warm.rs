//! Observed-hit-gated prompt-cache keep-warm policy.
//!
//! This module intentionally contains no inference or scheduler ownership.
//! It only decides whether one bounded idle-window refresh is worthwhile;
//! callers retain the normal request, redaction, and cancellation boundaries.

use base64::Engine as _;
use uuid::Uuid;

use crate::{
    config::providers::{CacheRetentionProfile, KeepWarmMode},
    session::InferenceSendIdentity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepWarmSkipReason {
    Disabled,
    IdleWindowDisabled,
    ProviderDoesNotCache,
    NoObservedCacheHit,
    WithinKnownRetentionFloor,
}

impl KeepWarmSkipReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::IdleWindowDisabled => "idle_window_disabled",
            Self::ProviderDoesNotCache => "provider_does_not_cache",
            Self::NoObservedCacheHit => "no_observed_cache_hit",
            Self::WithinKnownRetentionFloor => "within_known_retention_floor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepWarmSchedule {
    /// Seconds after the user activity that armed this one-shot refresh.
    pub after_secs: u64,
    /// The same idle window is an absolute deadline for the refresh.
    pub idle_window_secs: u64,
    /// Informational only: aggregators need pinned upstream routing for
    /// locality, even after a cache hit has been observed.
    pub aggregator_route: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepWarmDecision {
    Schedule(KeepWarmSchedule),
    Skip(KeepWarmSkipReason),
}

/// Plan at most one refresh in an idle window.
///
/// A known retention floor avoids a needless refresh when the complete idle
/// window fits inside it. Unknown routes remain observed-only and refresh at
/// the midpoint, which makes no claim about their upstream TTL.
pub fn decide(
    mode: KeepWarmMode,
    idle_window_secs: u64,
    profile: CacheRetentionProfile,
    observed_cache_hit: bool,
) -> KeepWarmDecision {
    if mode == KeepWarmMode::Off {
        return KeepWarmDecision::Skip(KeepWarmSkipReason::Disabled);
    }
    if idle_window_secs == 0 {
        return KeepWarmDecision::Skip(KeepWarmSkipReason::IdleWindowDisabled);
    }
    if profile == CacheRetentionProfile::None {
        return KeepWarmDecision::Skip(KeepWarmSkipReason::ProviderDoesNotCache);
    }
    if !observed_cache_hit {
        return KeepWarmDecision::Skip(KeepWarmSkipReason::NoObservedCacheHit);
    }
    if let Some(floor_secs) = profile.known_floor_secs()
        && idle_window_secs <= floor_secs
    {
        return KeepWarmDecision::Skip(KeepWarmSkipReason::WithinKnownRetentionFloor);
    }

    let after_secs = profile
        .known_floor_secs()
        .map(|floor_secs| floor_secs.saturating_mul(2) / 3)
        .unwrap_or(idle_window_secs / 2)
        .clamp(1, idle_window_secs.saturating_sub(1).max(1));
    KeepWarmDecision::Schedule(KeepWarmSchedule {
        after_secs,
        idle_window_secs,
        aggregator_route: profile.is_aggregator(),
    })
}

/// The durable callback arguments encoded in a keep-warm one-shot job id.
///
/// The job id is the durable handoff boundary: scheduler callback payloads
/// deliberately name only their subsystem. Keep the encoding compact enough
/// for the scheduler's 96-byte generic id contract without relaxing that
/// contract for all job types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeepWarmJobId {
    pub session_id: Uuid,
    pub cache_send_identity: InferenceSendIdentity,
    pub after_secs: u64,
    pub idle_window_secs: u64,
}

/// Mint the deterministic, idempotent id for one cache-producing send.
/// `send_id` is unique per inference send, so the session/send/schedule tuple
/// provides scheduling uniqueness without spending 22 more bytes on a nonce.
pub(crate) fn format_job_id(
    session_id: Uuid,
    cache_send_identity: InferenceSendIdentity,
    after_secs: u64,
    idle_window_secs: u64,
) -> String {
    format!(
        "kw.{}.{}.{}.{}.{}",
        encode_uuid(session_id),
        encode_i64_base36(cache_send_identity.unix_millis),
        encode_uuid(cache_send_identity.send_id),
        encode_u64_base36(after_secs),
        encode_u64_base36(idle_window_secs),
    )
}

/// Parse a locally minted keep-warm id strictly. Reject non-canonical forms so
/// a malformed durable row cannot alias a different callback identity.
pub(crate) fn parse_job_id(id: &str) -> anyhow::Result<KeepWarmJobId> {
    let mut parts = id.split('.');
    anyhow::ensure!(
        parts.next() == Some("kw"),
        "keep-warm callback has an invalid job id"
    );
    let session_id = decode_uuid(next_job_id_part(&mut parts, "session id")?)?;
    let cache_send_at_unix_millis =
        decode_i64_base36(next_job_id_part(&mut parts, "cache-send time")?)?;
    let cache_send_id = decode_uuid(next_job_id_part(&mut parts, "cache-send identity")?)?;
    let after_secs = decode_u64_base36(next_job_id_part(&mut parts, "delay")?)?;
    let idle_window_secs = decode_u64_base36(next_job_id_part(&mut parts, "idle window")?)?;
    anyhow::ensure!(
        parts.next().is_none(),
        "keep-warm callback job id has extra fields"
    );
    Ok(KeepWarmJobId {
        session_id,
        cache_send_identity: InferenceSendIdentity {
            unix_millis: cache_send_at_unix_millis,
            send_id: cache_send_id,
        },
        after_secs,
        idle_window_secs,
    })
}

fn next_job_id_part<'a>(
    parts: &mut impl Iterator<Item = &'a str>,
    label: &str,
) -> anyhow::Result<&'a str> {
    parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| anyhow::anyhow!("keep-warm callback is missing a {label}"))
}

fn encode_uuid(id: Uuid) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes())
}

fn decode_uuid(raw: &str) -> anyhow::Result<Uuid> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| anyhow::anyhow!("keep-warm callback has an invalid UUID field"))?;
    anyhow::ensure!(
        bytes.len() == 16,
        "keep-warm callback has an invalid UUID field"
    );
    anyhow::ensure!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) == raw,
        "keep-warm callback has a non-canonical UUID field"
    );
    Uuid::from_slice(&bytes).map_err(Into::into)
}

fn encode_i64_base36(value: i64) -> String {
    if value < 0 {
        format!("n{}", encode_u64_base36(value.unsigned_abs()))
    } else {
        encode_u64_base36(value as u64)
    }
}

fn decode_i64_base36(raw: &str) -> anyhow::Result<i64> {
    let (negative, magnitude) = raw
        .strip_prefix('n')
        .map_or((false, raw), |value| (true, value));
    let magnitude = decode_u64_base36(magnitude)?;
    if negative {
        anyhow::ensure!(
            magnitude != 0,
            "keep-warm callback has a non-canonical cache-send time"
        );
        let value = i128::from(magnitude);
        anyhow::ensure!(
            value <= i128::from(i64::MAX) + 1,
            "keep-warm callback has an invalid cache-send time"
        );
        Ok((-value) as i64)
    } else {
        i64::try_from(magnitude)
            .map_err(|_| anyhow::anyhow!("keep-warm callback has an invalid cache-send time"))
    }
}

fn encode_u64_base36(mut value: u64) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if value == 0 {
        return "0".to_string();
    }
    let mut encoded = [0u8; 13];
    let mut index = encoded.len();
    while value != 0 {
        index -= 1;
        encoded[index] = DIGITS[(value % 36) as usize];
        value /= 36;
    }
    std::str::from_utf8(&encoded[index..])
        .expect("base36 digits are UTF-8")
        .to_string()
}

fn decode_u64_base36(raw: &str) -> anyhow::Result<u64> {
    anyhow::ensure!(
        !raw.is_empty() && (raw == "0" || !raw.starts_with('0')),
        "keep-warm callback has a non-canonical integer field"
    );
    raw.bytes().try_fold(0u64, |value, digit| {
        let digit = match digit {
            b'0'..=b'9' => u64::from(digit - b'0'),
            b'a'..=b'z' => u64::from(digit - b'a') + 10,
            _ => anyhow::bail!("keep-warm callback has an invalid integer field"),
        };
        value
            .checked_mul(36)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| anyhow::anyhow!("keep-warm callback integer overflows"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_hit_is_required_even_for_known_caches() {
        assert_eq!(
            decide(
                KeepWarmMode::Auto,
                3_600,
                CacheRetentionProfile::KnownFloor { secs: 300 },
                false,
            ),
            KeepWarmDecision::Skip(KeepWarmSkipReason::NoObservedCacheHit)
        );
    }

    #[test]
    fn known_floor_skips_a_short_idle_window() {
        assert_eq!(
            decide(
                KeepWarmMode::Auto,
                300,
                CacheRetentionProfile::KnownFloor { secs: 300 },
                true,
            ),
            KeepWarmDecision::Skip(KeepWarmSkipReason::WithinKnownRetentionFloor)
        );
    }

    #[test]
    fn unknown_cache_is_observed_only_and_stays_in_window() {
        let KeepWarmDecision::Schedule(schedule) = decide(
            KeepWarmMode::Auto,
            901,
            CacheRetentionProfile::Observed,
            true,
        ) else {
            panic!("observed unknown cache should schedule");
        };
        assert_eq!(schedule.after_secs, 450);
        assert!(schedule.after_secs < schedule.idle_window_secs);
    }

    #[test]
    fn no_cache_never_schedules() {
        assert_eq!(
            decide(KeepWarmMode::Auto, 900, CacheRetentionProfile::None, true),
            KeepWarmDecision::Skip(KeepWarmSkipReason::ProviderDoesNotCache)
        );
    }

    #[test]
    fn compact_job_id_round_trips_all_durable_callback_arguments() {
        let session_id = Uuid::from_u128(1);
        let identity = InferenceSendIdentity {
            unix_millis: -1_725_000_000_123,
            send_id: Uuid::from_u128(2),
        };
        let id = format_job_id(session_id, identity, u64::MAX, u64::MAX);
        assert!(id.len() <= 96, "keep-warm id must fit scheduler validation");
        assert!(
            id.bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') })
        );
        assert_eq!(
            parse_job_id(&id).unwrap(),
            KeepWarmJobId {
                session_id,
                cache_send_identity: identity,
                after_secs: u64::MAX,
                idle_window_secs: u64::MAX,
            }
        );
    }

    #[test]
    fn compact_job_id_rejects_negative_zero_timestamp() {
        let mut id = format_job_id(
            Uuid::from_u128(1),
            InferenceSendIdentity {
                unix_millis: 0,
                send_id: Uuid::from_u128(2),
            },
            1,
            2,
        );
        let mut parts = id.split('.').map(str::to_owned).collect::<Vec<_>>();
        parts[2] = "n0".to_string();
        id = parts.join(".");

        assert!(parse_job_id(&id).is_err());
    }
}
