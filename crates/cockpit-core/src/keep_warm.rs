//! Observed-hit-gated prompt-cache keep-warm policy.
//!
//! This module intentionally contains no inference or scheduler ownership.
//! It only decides whether one bounded idle-window refresh is worthwhile;
//! callers retain the normal request, redaction, and cancellation boundaries.

use crate::config::providers::{CacheRetentionProfile, KeepWarmMode};

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
}
