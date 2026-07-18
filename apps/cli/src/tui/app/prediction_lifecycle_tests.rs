use super::PredictionState;

/// Eager generate: a turn ends, a result for that turn lands, and the
/// empty box shows the ghost. Then typing hides it; clearing back to
/// empty restores it from the cache — WITHOUT a new result/utility call.
#[test]
fn show_hide_on_type_then_restore_from_cache_without_recall() {
    let mut st = PredictionState::default();
    st.begin_turn(); // turn 1
    let turn = st.turn();
    // Result for the current turn, box empty → ghost shows.
    st.on_result(turn, Some("run the tests".into()), false, true);
    assert_eq!(
        st.ghost().map(|g| g.display_text().to_string()),
        Some("run the tests".to_string())
    );
    // User types → box non-empty → ghost hidden (cache retained).
    st.reconcile(false);
    assert!(st.ghost().is_none());
    // User clears back to empty → ghost restored from CACHE. No new
    // `on_result` call was made (no new utility call this turn).
    st.reconcile(true);
    assert_eq!(
        st.ghost().map(|g| g.display_text().to_string()),
        Some("run the tests".to_string())
    );
}

/// Stale replacement: a result tagged with an older turn (a newer turn
/// already began) is discarded — never shown.
#[test]
fn stale_turn_result_is_discarded() {
    let mut st = PredictionState::default();
    st.begin_turn(); // turn 1
    let stale_turn = st.turn();
    st.begin_turn(); // turn 2 — the stale result now belongs to turn 1
    st.on_result(stale_turn, Some("old prediction".into()), false, true);
    assert!(
        st.ghost().is_none(),
        "a prior turn's prediction must not show"
    );
    // A result for the CURRENT turn does land.
    st.on_result(st.turn(), Some("fresh prediction".into()), false, true);
    assert_eq!(
        st.ghost().map(|g| g.display_text().to_string()),
        Some("fresh prediction".to_string())
    );
}

/// Appear-once-ready: a result that arrives while the user is already
/// typing (box non-empty) does NOT pop in over active input, but the
/// cache is kept so a later clear-to-empty restores it.
#[test]
fn result_arriving_during_typing_does_not_pop_in_but_caches() {
    let mut st = PredictionState::default();
    st.begin_turn();
    let turn = st.turn();
    // Box non-empty when the async result lands → no ghost now.
    st.on_result(turn, Some("later".into()), false, false);
    assert!(st.ghost().is_none());
    // Clearing to empty restores it from the cache (no new call).
    st.reconcile(true);
    assert_eq!(
        st.ghost().map(|g| g.display_text().to_string()),
        Some("later".to_string())
    );
}

/// A new turn invalidates the previous turn's cache + ghost so a prior
/// prediction never lingers into the next turn.
#[test]
fn begin_turn_drops_previous_prediction() {
    let mut st = PredictionState::default();
    st.begin_turn();
    st.on_result(st.turn(), Some("first".into()), false, true);
    assert!(st.ghost().is_some());
    st.begin_turn();
    assert!(st.ghost().is_none(), "new turn drops the old ghost");
    // The old cache is gone too: an empty-box reconcile restores
    // nothing until a fresh result lands.
    st.reconcile(true);
    assert!(st.ghost().is_none());
}

/// Consume (Tab → real text) drops both ghost and cache so a later
/// clear-to-empty does not re-offer the accepted prediction.
#[test]
fn consume_clears_cache_so_clear_to_empty_does_not_restore() {
    let mut st = PredictionState::default();
    st.begin_turn();
    st.on_result(st.turn(), Some("accepted text".into()), false, true);
    st.consume();
    assert!(st.ghost().is_none());
    st.reconcile(true);
    assert!(
        st.ghost().is_none(),
        "an accepted prediction must not reappear as a ghost"
    );
}

/// A `None` result (degrade path — model unset/timeout/empty) leaves no
/// ghost and no cache.
#[test]
fn none_result_leaves_no_ghost() {
    let mut st = PredictionState::default();
    st.begin_turn();
    st.on_result(st.turn(), None, false, true);
    assert!(st.ghost().is_none());
    st.reconcile(true);
    assert!(st.ghost().is_none());
}
