use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::{StatusCode, header};

pub(crate) const MAX_RETRIES: usize = 2;
const MAX_RETRY_DELAY: Duration = Duration::from_secs(2);

pub(crate) fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::BAD_GATEWAY
        || status == StatusCode::SERVICE_UNAVAILABLE
        || status == StatusCode::GATEWAY_TIMEOUT
}

pub(crate) fn is_retryable_error(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout() || error.is_request() || error.is_body()
}

pub(crate) fn delay_for(headers: &HeaderMap, attempt: usize) -> Duration {
    headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::engine::retry::parse_retry_after)
        .unwrap_or_else(|| jittered_backoff(attempt))
        .min(MAX_RETRY_DELAY)
}

pub(crate) fn fallback_delay_for(attempt: usize) -> Duration {
    jittered_backoff(attempt).min(MAX_RETRY_DELAY)
}

fn jittered_backoff(attempt: usize) -> Duration {
    let jitter = rand::random_range(0.5..=1.0);
    crate::engine::retry::backoff_for(attempt as u32, jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_statuses_are_bounded_to_rate_limit_and_transient_gateway_errors() {
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(is_retryable_status(StatusCode::GATEWAY_TIMEOUT));
        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED));
        assert!(!is_retryable_status(StatusCode::FORBIDDEN));
    }

    #[test]
    fn retry_after_is_honored_but_capped() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, header::HeaderValue::from_static("60"));
        assert_eq!(delay_for(&headers, 0), MAX_RETRY_DELAY);

        headers.insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
        assert_eq!(delay_for(&headers, 0), Duration::from_secs(1));
    }
}
