use std::time::Duration;

/// Injectable source of uniform retry jitter.
pub trait JitterSource: Send + Sync {
    fn duration_up_to(&self, cap: Duration) -> Duration;
}

#[derive(Debug, Default)]
pub struct SystemJitter;

impl JitterSource for SystemJitter {
    fn duration_up_to(&self, cap: Duration) -> Duration {
        let max_millis = cap.as_millis().min(u128::from(u64::MAX)) as u64;
        if max_millis == 0 {
            return Duration::ZERO;
        }
        Duration::from_millis(rand::random_range(0..=max_millis))
    }
}
