use super::attach_to_session_retry_once;
use std::cell::Cell;

#[test]
fn retries_once_and_returns_success_when_second_attach_succeeds() {
    let attempts = Cell::new(0);
    let result = attach_to_session_retry_once(|| {
        let attempt = attempts.get() + 1;
        attempts.set(attempt);
        match attempt {
            1 => Err("first attach failed"),
            2 => Ok("attached"),
            _ => panic!("must not attach more than twice"),
        }
    });

    assert_eq!(result, Ok("attached"));
    assert_eq!(attempts.get(), 2);
}

#[test]
fn returns_second_error_after_retry_also_fails() {
    let attempts = Cell::new(0);
    let result: Result<&str, &str> = attach_to_session_retry_once(|| {
        let attempt = attempts.get() + 1;
        attempts.set(attempt);
        match attempt {
            1 => Err("first attach failed"),
            2 => Err("second attach failed"),
            _ => panic!("must not attach more than twice"),
        }
    });

    assert_eq!(result, Err("second attach failed"));
    assert_eq!(attempts.get(), 2);
}

#[test]
fn does_not_retry_successful_first_attach() {
    let attempts = Cell::new(0);
    let result = attach_to_session_retry_once(|| {
        attempts.set(attempts.get() + 1);
        Ok::<_, &str>("attached")
    });

    assert_eq!(result, Ok("attached"));
    assert_eq!(attempts.get(), 1);
}
