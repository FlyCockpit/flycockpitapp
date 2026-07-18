use super::{ActiveSchedule, format_schedule_line, session_schedule_ids};
use std::collections::BTreeMap;
use std::time::Instant;

fn sched(session_id: uuid::Uuid, kind: &str, iteration: u64) -> ActiveSchedule {
    ActiveSchedule {
        session_id,
        label: format!("{kind} task"),
        kind: kind.to_string(),
        iteration,
        last_activity: Instant::now(),
    }
}

fn fixture() -> (uuid::Uuid, uuid::Uuid, BTreeMap<String, ActiveSchedule>) {
    let a = uuid::Uuid::from_u128(1);
    let b = uuid::Uuid::from_u128(2);
    let mut scheduled = BTreeMap::new();
    scheduled.insert("sched-a1".to_string(), sched(a, "loop", 3));
    scheduled.insert("sched-a2".to_string(), sched(a, "background", 0));
    scheduled.insert("sched-b1".to_string(), sched(b, "timer", 1));
    (a, b, scheduled)
}

#[test]
fn filters_to_only_the_current_session() {
    // `/ps` scope: session `a` sees its two tasks, in stable id
    // order, and never session `b`'s.
    let (a, b, scheduled) = fixture();
    assert_eq!(
        session_schedule_ids(&scheduled, a),
        vec!["sched-a1", "sched-a2"]
    );
    assert_eq!(session_schedule_ids(&scheduled, b), vec!["sched-b1"]);
}

#[test]
fn empty_when_session_has_no_scheduled_tasks() {
    // `/ps` empty-state basis: a session with nothing scheduled yields nothing.
    let (_, _, scheduled) = fixture();
    let other = uuid::Uuid::from_u128(99);
    assert!(session_schedule_ids(&scheduled, other).is_empty());
}

#[test]
fn cross_session_id_is_not_in_current_set() {
    // `/stop <id>` refusal basis: an id owned by another session is
    // not a member of the current session's id set.
    let (a, _, scheduled) = fixture();
    let current = session_schedule_ids(&scheduled, a);
    assert!(!current.iter().any(|id| id == "sched-b1"));
    assert!(current.iter().any(|id| id == "sched-a1"));
}

#[test]
fn bare_stop_count_matches_current_session_scheduled_tasks() {
    // Bare `/stop` confirm count `N` = number of current-session tasks.
    let (a, b, scheduled) = fixture();
    assert_eq!(session_schedule_ids(&scheduled, a).len(), 2);
    assert_eq!(session_schedule_ids(&scheduled, b).len(), 1);
}

#[test]
fn schedule_line_shows_iteration_for_loops_but_not_background() {
    let a = uuid::Uuid::from_u128(1);
    assert_eq!(
        format_schedule_line("sched-a1", &sched(a, "loop", 3)),
        "sched-a1 [loop] 3 iter  loop task"
    );
    assert_eq!(
        format_schedule_line("sched-a2", &sched(a, "background", 0)),
        "sched-a2 [background]  background task"
    );
}
