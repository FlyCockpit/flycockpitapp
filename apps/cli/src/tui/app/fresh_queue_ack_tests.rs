use super::{App, FreshQueueAck};
use crate::engine::TurnEvent;
use crate::engine::message::{QueueItemStatus, QueuedUserMessage};
use crate::tui::history::HistoryEntry;

fn item(id: u128, text: &str) -> QueuedUserMessage {
    QueuedUserMessage {
        id: uuid::Uuid::from_u128(id),
        status: QueueItemStatus::Queued,
        text: text.to_string(),
        display_text: None,
        target: crate::engine::message::QueueTarget::root("Build"),
    }
}

#[test]
fn foreground_input_target_event_updates_tracked_target() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.foreground_input_target = Some(crate::engine::message::QueueTarget::root("Build"));

    app.apply_event(TurnEvent::ForegroundInputTarget {
        target: crate::engine::message::QueueTarget::child("explore", 1, "call-1", "default"),
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
        target: crate::engine::message::QueueTarget::root("Build"),
    });
    assert_eq!(
        app.foreground_input_target
            .as_ref()
            .map(|target| target.id.as_str()),
        Some("root")
    );
}

fn push_fresh_optimistic(app: &mut App, text: &str) {
    app.history.push(HistoryEntry::User {
        text: text.to_string(),
        cleaned: None,
        expanded: false,
        timestamp: chrono::Local::now(),
        seq: None,
        preflight_pending: false,
        persist_failed: false,
    });
    app.fresh_queue_ack = FreshQueueAck::AwaitingAck;
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
    push_fresh_optimistic(&mut app, "fresh hello");
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
        tag_expansions: vec![crate::daemon::proto::TagExpansionMeta {
            tool: "read".to_string(),
            path: "src/lib.rs".to_string(),
            detail: "1 line".to_string(),
            ok: true,
        }],
        queue_item_ids: vec![uuid::Uuid::from_u128(1)],
        target: crate::engine::message::QueueTarget::root("Build"),
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
fn fresh_fold_before_queue_ack_still_suppresses_optimistic_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    push_fresh_optimistic(&mut app, "fresh race");
    let id = uuid::Uuid::from_u128(9);

    app.apply_event(TurnEvent::QueuedUserMessagesFolded {
        text: "wire race".to_string(),
        display_text: Some("fresh race".to_string()),
        tag_expansions: Vec::new(),
        queue_item_ids: vec![id],
        target: crate::engine::message::QueueTarget::root("Build"),
        seq: Some(49),
        preflight_cleaned: None,
    });
    assert_eq!(user_rows(&app), vec![("fresh race", Some(49))]);
    assert_eq!(app.fresh_queue_ack, FreshQueueAck::FoldedBeforeAck(id));

    app.apply_event(TurnEvent::QueueUpdated {
        queue: vec![item(9, "wire race")],
    });
    assert!(
        app.queue.is_empty(),
        "late ack must not resurrect folded row"
    );
    assert_eq!(app.fresh_queue_ack, FreshQueueAck::None);
    assert_eq!(user_rows(&app), vec![("fresh race", Some(49))]);
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
        target: crate::engine::message::QueueTarget::root("Build"),
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
        target: crate::engine::message::QueueTarget::root("Build"),
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
        target: crate::engine::message::QueueTarget::root("Build"),
        seq: Some(77),
        preflight_cleaned: None,
    });
    assert!(app.queue.is_empty());
    assert_eq!(user_rows(&app), vec![("queued while busy", Some(77))]);
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
        target: crate::engine::message::QueueTarget::root("Build"),
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
        tag_expansions: vec![crate::daemon::proto::TagExpansionMeta {
            tool: "read".to_string(),
            path: "src/lib.rs".to_string(),
            ok: true,
            detail: "1 line".to_string(),
        }],
        queue_item_ids: vec![uuid::Uuid::from_u128(31)],
        target: crate::engine::message::QueueTarget::root("Build"),
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
