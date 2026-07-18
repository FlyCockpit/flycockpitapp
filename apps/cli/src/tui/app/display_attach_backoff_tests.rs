use super::{DISPLAY_ATTACH_INITIAL_BACKOFF, DISPLAY_ATTACH_MAX_BACKOFF, DisplayAttachBackoff};
use std::time::{Duration, Instant};

#[test]
fn suppresses_repeated_attach_ticks_until_backoff_expires() {
    let mut backoff = DisplayAttachBackoff::default();
    let t0 = Instant::now();

    assert!(backoff.can_attempt(t0));
    backoff.record_failure(t0);
    assert!(!backoff.can_attempt(t0 + Duration::from_millis(249)));
    assert!(backoff.can_attempt(t0 + DISPLAY_ATTACH_INITIAL_BACKOFF));
}

#[test]
fn exponential_delay_is_capped() {
    let mut backoff = DisplayAttachBackoff::default();
    let t0 = Instant::now();

    for _ in 0..8 {
        backoff.record_failure(t0);
    }

    assert_eq!(
        backoff.next_attempt_at,
        Some(t0 + DISPLAY_ATTACH_MAX_BACKOFF)
    );
    assert_eq!(backoff.delay, DISPLAY_ATTACH_MAX_BACKOFF);
}

#[test]
fn reset_allows_immediate_attach_after_explicit_action_or_success() {
    let mut backoff = DisplayAttachBackoff::default();
    let t0 = Instant::now();

    backoff.record_failure(t0);
    assert!(!backoff.can_attempt(t0));

    backoff.reset();
    assert!(backoff.can_attempt(t0));
    assert_eq!(backoff.delay, DISPLAY_ATTACH_INITIAL_BACKOFF);
}
