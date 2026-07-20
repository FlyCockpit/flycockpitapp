use super::{WORKING_MESSAGES, pick_working_msg};

#[test]
fn picks_in_range_and_avoids_previous() {
    // Re-roll many times from each previous index; the result must
    // always be valid and never equal to the previous pick.
    for prev in 0..WORKING_MESSAGES.len() {
        for _ in 0..200 {
            let next = pick_working_msg(prev);
            assert!(next < WORKING_MESSAGES.len());
            assert_ne!(next, prev);
        }
    }
}

#[test]
fn out_of_range_sentinel_allows_any_index() {
    // The one-past-end init lets the first roll land anywhere; just
    // assert it always returns an in-range index.
    for _ in 0..200 {
        let idx = pick_working_msg(WORKING_MESSAGES.len());
        assert!(idx < WORKING_MESSAGES.len());
    }
}
