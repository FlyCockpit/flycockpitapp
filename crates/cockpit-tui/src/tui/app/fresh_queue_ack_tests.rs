use super::{App, FreshQueueAck};
use crate::tui::history::HistoryEntry;
use cockpit_core::engine::TurnEvent;
use cockpit_core::engine::message::{QueueItemStatus, QueuedUserMessage};

fn item(id: u128, text: &str) -> QueuedUserMessage {
    QueuedUserMessage {
        id: uuid::Uuid::from_u128(id),
        status: QueueItemStatus::Queued,
        text: text.to_string(),
        display_text: None,
        target: cockpit_proto::QueueTarget::root("Build"),
    }
}

#[test]
fn foreground_input_target_event_updates_tracked_target() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.foreground_input_target = Some(cockpit_proto::QueueTarget::root("Build"));

    app.apply_event(TurnEvent::ForegroundInputTarget {
        target: cockpit_proto::QueueTarget::child("explore", 1, "call-1", "default"),
    });
    assert_eq!(
        app.foreground_input_target
            .as_ref()
            .map(|target| target.id.as_str()),
        Some("task:call-1:default")
    );
    assert_eq!(
        app.foreground_input_target
            .as_ref()
            .map(|target| target.agent.as_str()),
        Some("explore")
    );

    app.apply_event(TurnEvent::ForegroundInputTarget {
        target: cockpit_proto::QueueTarget::root("Build"),
    });
    assert_eq!(
        app.foreground_input_target
            .as_ref()
            .map(|target| target.id.as_str()),
        Some("root")
    );
}

fn push_fresh_optimistic(app: &mut App, id: uuid::Uuid, text: &str) {
    app.history.push(HistoryEntry::User {
        text: text.to_string(),
        cleaned: None,
        expanded: false,
        timestamp: chrono::Local::now(),
        seq: None,
        optimistic_submission_id: Some(id),
        preflight_pending: false,
        persist_failed: false,
    });
    app.fresh_queue_ack = FreshQueueAck::AwaitingAck(id);
}

fn user_rows(app: &App) -> Vec<(&str, Option<i64>)> {
    app.history
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::User { text, seq, .. } => Some((text.as_str(), *seq)),
            _ => None,
        })
        .collect()
}

#[test]
fn fresh_queue_ack_does_not_duplicate_optimistic_user_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let id = uuid::Uuid::from_u128(1);
    push_fresh_optimistic(&mut app, id, "fresh hello");
    app.history.push(HistoryEntry::Plain {
        line: "  → read(src/lib.rs) ✓ 1 line".to_string(),
    });

    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(1, "fresh hello")],
    });
    assert!(
        app.queue.is_empty(),
        "the originating client suppresses its fresh-send daemon ack"
    );

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "fresh hello".to_string(),
        display_text: None,
        tag_expansions: vec![cockpit_proto::TagExpansionMeta {
            tool: "read".to_string(),
            path: "src/lib.rs".to_string(),
            detail: "1 line".to_string(),
            ok: true,
        }],
        queue_item_ids: vec![id],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(42),
        preflight_cleaned: None,
    });
    assert_eq!(
        user_rows(&app),
        vec![("fresh hello", Some(42))],
        "queued fold must stamp the fresh optimistic row, not duplicate it"
    );

    app.apply_event(TurnEvent::UserMessageRecorded {
        seq: 42,
        client_submission_ids: vec![id],
        preflight_cleaned: None,
    });
    assert_eq!(
        user_rows(&app),
        vec![("fresh hello", Some(42))],
        "the original optimistic row receives the persisted seq"
    );
    assert_eq!(app.fresh_queue_ack, FreshQueueAck::None);
    assert_eq!(
        app.history
            .iter()
            .filter(|entry| matches!(entry, HistoryEntry::Plain { line } if line.contains("read(src/lib.rs)")))
            .count(),
        1,
        "the originating optimistic tag row is not duplicated by the fold event"
    );
}

#[test]
fn queued_fold_record_pair_never_stamps_an_earlier_failed_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.history.push(HistoryEntry::User {
        text: "failed earlier".to_string(),
        cleaned: None,
        expanded: false,
        timestamp: chrono::Local::now(),
        seq: None,
        optimistic_submission_id: Some(uuid::Uuid::new_v4()),
        preflight_pending: false,
        persist_failed: true,
    });
    let queue_id = uuid::Uuid::new_v4();

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "successful queued message".to_string(),
        display_text: None,
        tag_expansions: Vec::new(),
        queue_item_ids: vec![queue_id],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(73),
        preflight_cleaned: None,
    });
    app.apply_event(TurnEvent::UserMessageRecorded {
        seq: 73,
        client_submission_ids: vec![queue_id],
        preflight_cleaned: None,
    });

    assert_eq!(
        app.history
            .iter()
            .filter_map(|entry| match entry {
                HistoryEntry::User {
                    text,
                    seq,
                    persist_failed,
                    ..
                } => Some((text.as_str(), *seq, *persist_failed)),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![
            ("failed earlier", None, true),
            ("successful queued message", Some(73), false),
        ]
    );
}

#[test]
fn fresh_fold_before_queue_ack_still_suppresses_optimistic_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let id = uuid::Uuid::from_u128(9);
    push_fresh_optimistic(&mut app, id, "fresh race");

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "wire race".to_string(),
        display_text: Some("fresh race".to_string()),
        tag_expansions: Vec::new(),
        queue_item_ids: vec![id],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(49),
        preflight_cleaned: None,
    });
    assert_eq!(user_rows(&app), vec![("fresh race", Some(49))]);
    assert_eq!(app.fresh_queue_ack, FreshQueueAck::FoldedBeforeAck(id));

    app.apply_event(TurnEvent::UserMessageRecorded {
        seq: 49,
        client_submission_ids: vec![id],
        preflight_cleaned: None,
    });
    assert_eq!(
        app.fresh_queue_ack,
        FreshQueueAck::FoldedBeforeAck(id),
        "the durable record must not release a still-delayed queue response"
    );

    app.apply_event(TurnEvent::QueueUpdated { queue: vec![] });
    assert_eq!(
        app.fresh_queue_ack,
        FreshQueueAck::FoldedBeforeAck(id),
        "an overtaking empty broadcast is not the delayed ACK"
    );

    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(8, "other in flight"), item(9, "wire race")],
    });
    assert_eq!(
        app.queue
            .iter()
            .map(|queued| (queued.id, queued.text.as_str()))
            .collect::<Vec<_>>(),
        vec![(uuid::Uuid::from_u128(8), "other in flight")],
        "late ACK suppresses only the exactly correlated folded row"
    );
    assert_eq!(app.fresh_queue_ack, FreshQueueAck::None);
    assert_eq!(user_rows(&app), vec![("fresh race", Some(49))]);
}

#[test]
fn retained_retry_eventually_folds_into_the_same_optimistic_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let id = uuid::Uuid::from_u128(19);
    push_fresh_optimistic(&mut app, id, "retained exact");
    app.begin_working_span();

    app.apply_event(TurnEvent::UserMessageDispatchRetained {
        error: "repair required".to_string(),
        optimistic_submission_id: id,
    });
    assert!(!app.busy);
    assert_eq!(app.fresh_queue_ack, FreshQueueAck::None);
    assert!(matches!(
        app.history.iter().find(|entry| matches!(entry, HistoryEntry::User { .. })),
        Some(HistoryEntry::User {
            optimistic_submission_id: Some(got),
            persist_failed: false,
            ..
        }) if *got == id
    ));

    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(19, "retained exact")],
    });
    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "retained exact".to_string(),
        display_text: None,
        tag_expansions: Vec::new(),
        queue_item_ids: vec![id],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(59),
        preflight_cleaned: None,
    });

    assert!(app.queue.is_empty());
    assert_eq!(
        user_rows(&app),
        vec![("retained exact", Some(59))],
        "successful same-UUID retry stamps the retained row exactly once"
    );
}

#[test]
fn retained_dispatch_wins_over_driver_failure_in_either_event_order() {
    for retained_first in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let id = uuid::Uuid::from_u128(if retained_first { 20 } else { 21 });
        push_fresh_optimistic(&mut app, id, "retained across driver failure");
        app.begin_working_span();

        let retained = TurnEvent::UserMessageDispatchRetained {
            error: "session repair required".to_string(),
            optimistic_submission_id: id,
        };
        let driver_failed = TurnEvent::SessionDriverFailed {
            error: "session repair required".to_string(),
        };
        if retained_first {
            app.apply_event(retained);
            app.apply_event(driver_failed);
        } else {
            app.apply_event(driver_failed);
            app.apply_event(retained);
        }

        assert!(matches!(
            app.history.iter().find(|entry| matches!(
                entry,
                HistoryEntry::User {
                    optimistic_submission_id: Some(got),
                    ..
                } if *got == id
            )),
            Some(HistoryEntry::User {
                persist_failed: false,
                ..
            })
        ));
        assert!(app.retained_user_submission_ids.contains(&id));

        app.apply_event(TurnEvent::QueuedUserMessagesFolded {
            text: "retained across driver failure".to_string(),
            display_text: None,
            tag_expansions: Vec::new(),
            queue_item_ids: vec![id],
            target: cockpit_proto::QueueTarget::root("Build"),
            seq: Some(60),
            preflight_cleaned: None,
        });
        assert_eq!(
            user_rows(&app),
            vec![("retained across driver failure", Some(60))]
        );
        assert!(!app.retained_user_submission_ids.contains(&id));
    }
}

#[test]
fn unrelated_fold_preserves_fresh_uuid_correlation() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let fresh_id = uuid::Uuid::from_u128(40);
    let other_id = uuid::Uuid::from_u128(41);
    push_fresh_optimistic(&mut app, fresh_id, "fresh exact");

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "remote queued work".to_string(),
        display_text: None,
        tag_expansions: Vec::new(),
        queue_item_ids: vec![other_id],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(50),
        preflight_cleaned: None,
    });

    assert_eq!(
        app.fresh_queue_ack,
        FreshQueueAck::AwaitingAck(fresh_id),
        "an unrelated in-flight fold cannot claim the fresh optimistic row"
    );
    assert_eq!(
        app.history
            .iter()
            .filter_map(|entry| match entry {
                HistoryEntry::User {
                    text,
                    seq,
                    optimistic_submission_id,
                    ..
                } => Some((text.as_str(), *seq, *optimistic_submission_id)),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![
            ("fresh exact", None, Some(fresh_id)),
            ("remote queued work", Some(50), None),
        ]
    );

    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(40, "fresh exact"), item(41, "remote queued work")],
    });
    assert_eq!(app.fresh_queue_ack, FreshQueueAck::SuppressId(fresh_id));
    assert!(
        app.queue.is_empty(),
        "the ACK suppresses the exact fresh UUID and the fold tombstone prevents the already-folded unrelated item from being resurrected"
    );
}

#[test]
fn queued_fold_off_tail_preserves_scroll_position() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.chat_scroll_offset = 4;

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "queued while reading".to_string(),
        display_text: None,
        tag_expansions: Vec::new(),
        queue_item_ids: vec![uuid::Uuid::from_u128(10)],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(70),
        preflight_cleaned: None,
    });

    assert_eq!(user_rows(&app), vec![("queued while reading", Some(70))]);
    assert_eq!(app.chat_scroll_offset, 4);
}

#[test]
fn queued_fold_at_tail_stays_live_tail() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.chat_scroll_offset = 0;

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "queued at tail".to_string(),
        display_text: None,
        tag_expansions: Vec::new(),
        queue_item_ids: vec![uuid::Uuid::from_u128(12)],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(72),
        preflight_cleaned: None,
    });

    assert_eq!(user_rows(&app), vec![("queued at tail", Some(72))]);
    assert_eq!(app.chat_scroll_offset, 0);
}

#[test]
fn busy_queue_update_still_renders_and_folds_once() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(11, "queued while busy")],
    });
    assert_eq!(
        app.queue
            .iter()
            .map(|item| item.text.as_str())
            .collect::<Vec<_>>(),
        vec!["queued while busy"],
        "busy queued messages remain visible in the queue strip"
    );

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "queued while busy".to_string(),
        display_text: None,
        tag_expansions: Vec::new(),
        queue_item_ids: vec![uuid::Uuid::from_u128(11)],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(77),
        preflight_cleaned: None,
    });
    assert!(app.queue.is_empty());
    assert_eq!(user_rows(&app), vec![("queued while busy", Some(77))]);

    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(11, "queued while busy")],
    });
    assert!(
        app.queue.is_empty(),
        "a delayed response snapshot cannot resurrect a busy item after its fold"
    );
    assert_eq!(user_rows(&app), vec![("queued while busy", Some(77))]);
}

#[test]
fn replacement_session_may_reuse_an_old_folded_uuid() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let id = uuid::Uuid::from_u128(111);

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "outgoing session".to_string(),
        display_text: None,
        tag_expansions: Vec::new(),
        queue_item_ids: vec![id],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(99),
        preflight_cleaned: None,
    });
    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(111, "late outgoing snapshot")],
    });
    assert!(
        app.queue.is_empty(),
        "the outgoing tombstone suppresses stale state"
    );

    app.reset_session_live_state();
    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(111, "replacement session")],
    });
    assert_eq!(
        app.queue
            .iter()
            .map(|item| item.text.as_str())
            .collect::<Vec<_>>(),
        vec!["replacement session"],
        "tombstones must not cross session epochs"
    );
}

#[test]
fn two_busy_queue_items_fold_once_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(21, "first queued"), item(22, "second queued")],
    });
    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "first queued\n\nsecond queued".to_string(),
        display_text: None,
        tag_expansions: Vec::new(),
        queue_item_ids: vec![uuid::Uuid::from_u128(21), uuid::Uuid::from_u128(22)],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(81),
        preflight_cleaned: None,
    });

    assert_eq!(
        user_rows(&app),
        vec![("first queued\n\nsecond queued", Some(81))],
        "busy queued items fold into one transcript row in daemon order"
    );
    assert_eq!(app.fresh_queue_ack, FreshQueueAck::None);
}

#[test]
fn one_multi_id_fold_replaces_every_optimistic_row_with_authoritative_display_text() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let first_id = uuid::Uuid::from_u128(121);
    let second_id = uuid::Uuid::from_u128(122);
    push_fresh_optimistic(&mut app, first_id, "optimistic first");
    push_fresh_optimistic(&mut app, second_id, "optimistic second");

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "expanded first\n\nexpanded second".to_string(),
        display_text: Some("canonical first\n\ncanonical second".to_string()),
        tag_expansions: Vec::new(),
        queue_item_ids: vec![first_id, second_id],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(82),
        preflight_cleaned: Some("cleaned fold".to_string()),
    });

    assert_eq!(
        user_rows(&app),
        vec![("canonical first\n\ncanonical second", Some(82))],
        "one durable fold must remove all represented optimistic rows and insert one canonical row"
    );
    assert!(app.history.iter().all(|entry| {
        !matches!(
            entry,
            HistoryEntry::User {
                optimistic_submission_id: Some(id),
                ..
            } if *id == first_id || *id == second_id
        )
    }));
}

#[test]
fn queued_fold_event_renders_daemon_display_and_tag_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(31, "queued @src/lib.rs")],
    });
    app.apply_event(TurnEvent::QueueUpdated { queue: vec![] });
    assert!(
        app.queue.is_empty(),
        "pending queue mirror follows the daemon drain"
    );

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "<file path=\"src/lib.rs\">expanded</file>".to_string(),
        display_text: Some("queued @src/lib.rs".to_string()),
        tag_expansions: vec![cockpit_proto::TagExpansionMeta {
            tool: "read".to_string(),
            path: "src/lib.rs".to_string(),
            ok: true,
            detail: "1 line".to_string(),
        }],
        queue_item_ids: vec![uuid::Uuid::from_u128(31)],
        target: cockpit_proto::QueueTarget::root("Build"),
        seq: Some(91),
        preflight_cleaned: None,
    });

    assert_eq!(user_rows(&app), vec![("queued @src/lib.rs", Some(91))]);
    assert!(
        app.history
            .iter()
            .any(|entry| matches!(entry, HistoryEntry::Plain { line } if line == "  → read(src/lib.rs) ✓ 1 line")),
        "the queued tag expansion renders under the folded user row"
    );
}
