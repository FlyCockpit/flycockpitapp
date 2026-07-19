use super::*;

#[test]
fn user_message_event_data_includes_display_fields() {
    let expansions = vec![crate::daemon::proto::TagExpansionMeta {
        tool: "read".into(),
        path: "src/lib.rs".into(),
        detail: "142 lines".into(),
        ok: true,
    }];
    let data = user_message_event_data(
        "<file path=\"src/lib.rs\">expanded</file>",
        Some("review @src/lib.rs"),
        &expansions,
        None,
        &[],
        None,
        None,
    );

    assert!(data["text"].as_str().unwrap().starts_with("<file"));
    assert_eq!(data["display_text"], "review @src/lib.rs");
    assert_eq!(data["tag_expansions"][0]["tool"], "read");
    assert_eq!(data["tag_expansions"][0]["path"], "src/lib.rs");
    assert_eq!(data["tag_expansions"][0]["ok"], true);
}

/// Regression (implementation note, candidate
/// "queued-message state"): on a ctrl+c cancel-unwind the driver must
/// discard *every* user message that was queued during the cancelled
/// span, so `run_main_loop` doesn't immediately pick the next one up and
/// start a fresh turn — which would make the cancel *appear* to leave the
/// primary running. `discard_pending_input` drains the whole buffered
/// queue (no `MAX_FOLD` cap) and reports the count; afterwards the channel
/// yields nothing until a new send.
#[tokio::test]
async fn discard_pending_input_drops_all_queued_messages() {
    let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let target = crate::engine::message::QueueTarget::root("Build");
    // Queue more than MAX_FOLD so we prove the discard has no fold cap —
    // a partial drain would let the leftovers auto-start the next turn.
    let queued = MAX_FOLD + 5;
    for i in 0..queued {
        queue
            .push(
                UserSubmission {
                    text: format!("queued message {i}"),
                    ..Default::default()
                },
                target.clone(),
            )
            .await;
    }

    let dropped = discard_pending_input(&queue).await;
    assert_eq!(
        dropped, queued,
        "every buffered queued message is discarded on cancel (no MAX_FOLD cap)"
    );
    // Nothing is left to auto-start a fresh turn after the cancel.
    let mut drained = Vec::new();
    queue
        .drain_into_for(&mut drained, MAX_FOLD, Some(&target.id))
        .await;
    assert!(
        drained.is_empty(),
        "the queue is empty after a cancel discard"
    );

    // A message sent *after* the cancel is a fresh turn and survives — the
    // discard only drops what was buffered at cancel time, it doesn't close
    // the channel.
    queue
        .push(
            UserSubmission {
                text: "post-cancel message".into(),
                ..Default::default()
            },
            target,
        )
        .await;
    assert_eq!(
        queue.recv().await.map(|s| s.text).as_deref(),
        Some("post-cancel message"),
        "a message sent after the cancel still drives the next turn"
    );

    // Idle discard (nothing queued) is a no-op reporting zero.
    assert_eq!(discard_pending_input(&queue).await, 0);
}

#[test]
fn fold_submission_commands_preserves_compact_order() {
    let folded = fold_submission_commands(vec![
        UserSubmission::text("before"),
        UserSubmission::compact_notice(),
        UserSubmission::text("after one"),
        UserSubmission::text("after two"),
    ]);
    assert_eq!(folded.len(), 4);
    match &folded[0] {
        FoldedSubmission::User(submission) => assert_eq!(submission.text, "before"),
        FoldedSubmission::Compact(_) => panic!("expected leading user turn"),
    }
    assert!(matches!(folded[1], FoldedSubmission::Compact(_)));
    match &folded[2] {
        FoldedSubmission::User(submission) => assert_eq!(submission.text, "after one"),
        FoldedSubmission::Compact(_) => panic!("expected first trailing user turn"),
    }
    match &folded[3] {
        FoldedSubmission::User(submission) => assert_eq!(submission.text, "after two"),
        FoldedSubmission::Compact(_) => panic!("expected second trailing user turn"),
    }
}

#[test]
fn fold_submission_commands_runs_lone_compact_without_dummy_user_turn() {
    let folded = fold_submission_commands(vec![UserSubmission::compact_notice()]);
    assert_eq!(folded.len(), 1);
    assert!(matches!(folded[0], FoldedSubmission::Compact(_)));
}
