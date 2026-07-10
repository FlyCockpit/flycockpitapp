use super::*;

/// Stable lead-in for the synthesized loop-collapse tool-result
/// (implementation note). It doubles as the marker
/// [`collapse_loop_run`] keys on to recognize a previous fire's collapse
/// message in the wire history, so the contiguous run dedups to exactly one
/// message. Kept terse (token economy §10) — it is also human-readable lead
/// text, not a hidden control sequence.
const LOOP_COLLAPSE_TAG: &str = "Loop blocked:";

/// Compact one-line rendering of a tool's wire args for the synthesized
/// loop-collapse message. Truncates long args (token economy §10) — the model
/// already issued this call N times, so the summary only needs to identify it.
fn compact_args(args: &Value) -> String {
    const MAX: usize = 160;
    let s = match args {
        Value::Object(map) if map.is_empty() => String::new(),
        _ => args.to_string(),
    };
    if s.chars().count() > MAX {
        let head: String = s.chars().take(MAX).collect();
        format!("{head}…")
    } else {
        s
    }
}

/// The guidance error returned as a *tool result* when the loop guard
/// blocks a back-to-back identical call (GOALS §1/§12). It reads as a
/// normal tool-result error so the model changes course rather than
/// treating it as a hard abort. Built with [`invalid_input`] so it
/// classifies as an [`crate::engine::tool::ToolFailKind::Invocation`]
/// failure (the model's repeat is the cause). The dispatcher prefixes
/// `Error:` per the wire-vs-user transcript conventions, the same as any
/// other invocation failure.
///
/// This is also the single synthesized message the contiguous identical-
/// rejected run collapses to (implementation note):
/// it states the repeated call (name + compact/truncated args), the attempt
/// `count`, that it is blocked, and the NAMES of the currently-available tools
/// (names only — never schemas; that would bust token economy §10 and the
/// prompt-cache prefix). The tool-name list is the structural escape cue a
/// bare rejection lacks. Leads with [`LOOP_COLLAPSE_TAG`] so a later fire can
/// recognize and update this same message instead of appending a second.
pub(super) fn loop_guard_message(
    tool: &str,
    args: &Value,
    count: u32,
    available: &[&str],
) -> String {
    // `available` names join compactly; `count` is the live consecutive-repeat
    // count for this `(tool, args)` run; the args are rendered compact/truncated.
    let names = available.join(", ");
    let args_summary = compact_args(args);
    let call = if args_summary.is_empty() {
        format!("`{tool}`")
    } else {
        format!("`{tool}` {args_summary}")
    };
    format!(
        "{LOOP_COLLAPSE_TAG} {call} was called {count} times with the same arguments and \
         blocked each time. Do not re-issue it — choose a different action. \
         Available tools: {names}."
    )
}

/// Strip the immediately-preceding contiguous run of identical rejected
/// loop-collapse pairs from the WIRE history so the run collapses to exactly
/// one synthesized message (implementation note).
///
/// History at this point ends with the CURRENT assistant tool-call message
/// (its tool_result has not been pushed yet). Walking backward past it, each
/// earlier fire of this same loop left a `(Assistant{tool_call sig==current},
/// User{tool_result starting with `LOOP_COLLAPSE_TAG`})` pair. Those pairs —
/// and only those — are removed, in whole pairs so tool_use↔tool_result
/// pairing stays valid on replay. The boundary is strict-contiguous: the first
/// non-matching pair (a different call, or a non-collapse tool_result —
/// e.g. the first, below-threshold *dispatched* call whose result is real)
/// breaks the run and stops the walk. Earlier unrelated history is untouched.
pub(super) fn collapse_loop_run(history: &mut Vec<Message>, args: &Value, tool: &str) {
    use crate::engine::message::AssistantContent;
    use rig::message::{ToolResultContent, UserContent};

    let signature = crate::approval::store::GrantStore::loop_signature(tool, args);

    // The trailing message is the current assistant tool-call turn; the prior
    // collapse pairs sit before it. Remove pairs while the tail (just under the
    // current turn) is a `(Assistant matching-sig, User collapse-tool_result)`.
    loop {
        let n = history.len();
        // Need at least the current Assistant turn + a full prior pair beneath.
        if n < 3 {
            return;
        }
        // history[n-1] = current Assistant turn (kept). The candidate prior pair
        // is history[n-3] (Assistant) + history[n-2] (User tool_result).
        let assistant_idx = n - 3;
        let result_idx = n - 2;

        let result_is_collapse = match &history[result_idx] {
            Message::User { content } => content.iter().any(|c| match c {
                UserContent::ToolResult(tr) => tr.content.iter().any(|rc| match rc {
                    ToolResultContent::Text(t) => {
                        // The dispatcher prefixes `Error: ` onto the wire body.
                        t.text.contains(LOOP_COLLAPSE_TAG)
                    }
                    _ => false,
                }),
                _ => false,
            }),
            _ => false,
        };
        let assistant_matches = match &history[assistant_idx] {
            Message::Assistant { content, .. } => content.iter().any(|c| match c {
                AssistantContent::ToolCall(tc) => {
                    crate::approval::store::GrantStore::loop_signature(
                        &tc.function.name,
                        &tc.function.arguments,
                    ) == signature
                }
                _ => false,
            }),
            _ => false,
        };

        if result_is_collapse && assistant_matches {
            // Remove the whole prior pair (result then assistant, high index
            // first so the lower index stays valid). The current Assistant turn
            // shifts down but is preserved.
            history.remove(result_idx);
            history.remove(assistant_idx);
        } else {
            return;
        }
    }
}

#[cfg(test)]
mod loop_collapse_tests {
    //! Structural loop-collapse (implementation note):
    //! the contiguous run of identical rejected `(tool, args)` calls collapses
    //! to exactly ONE synthesized message on the WIRE history (idempotent), the
    //! USER timeline / session-DB rows keep one entry per attempt.

    use super::*;
    use crate::engine::message::{AssistantContent, OneOrMany, ToolCall};
    use rig::message::{ToolFunction, ToolResultContent, UserContent};

    fn call(name: &str, args: Value) -> ToolCall {
        ToolCall {
            id: format!("call-{}", Uuid::new_v4()),
            call_id: None,
            function: ToolFunction {
                name: name.to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        }
    }

    /// Simulate the dispatch loop's WIRE-shaping for ONE loop-guard-rejected
    /// attempt: push the assistant tool-call turn (as `turn` does before
    /// dispatch), collapse the prior identical run, then push the synthesized
    /// rejection tool_result. Returns the synthesized wire body (with the
    /// dispatcher's `Error: ` prefix, matching the real path).
    fn drive_rejected_attempt(
        history: &mut Vec<Message>,
        tc: &ToolCall,
        count: u32,
        available: &[&str],
    ) -> String {
        history.push(Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(tc.clone())),
        });
        // The dispatcher prefixes `Error: ` onto the invalid-input body.
        let body = format!(
            "Error: {}",
            loop_guard_message(&tc.function.name, &tc.function.arguments, count, available)
        );
        collapse_loop_run(history, &tc.function.arguments, &tc.function.name);
        history.push(tool_result_message(tc, body.clone()));
        body
    }

    fn collapse_messages(history: &[Message]) -> Vec<String> {
        history
            .iter()
            .filter_map(|m| match m {
                Message::User { content } => content.iter().find_map(|c| match c {
                    UserContent::ToolResult(tr) => tr.content.iter().find_map(|rc| match rc {
                        ToolResultContent::Text(t) if t.text.contains(LOOP_COLLAPSE_TAG) => {
                            Some(t.text.clone())
                        }
                        _ => None,
                    }),
                    _ => None,
                }),
                _ => None,
            })
            .collect()
    }

    /// N identical rejected calls collapse to exactly ONE synthesized message;
    /// it carries the tool name, the attempt count, and the tool-name list.
    #[test]
    fn n_identical_rejects_collapse_to_one_message() {
        let args = serde_json::json!({"command": "cargo build"});
        let available = ["read", "bash", "edit"];
        let mut history: Vec<Message> = Vec::new();

        // Threshold default 2: attempt #2 is the first rejected call, #3, #4 …
        // each fire again. Drive three consecutive rejected attempts.
        for count in 2u32..=4 {
            let tc = call("bash", args.clone());
            drive_rejected_attempt(&mut history, &tc, count, &available);
        }

        let collapses = collapse_messages(&history);
        assert_eq!(
            collapses.len(),
            1,
            "the run must collapse to exactly one synthesized message, got: {history:?}"
        );
        let msg = &collapses[0];
        assert!(msg.contains("`bash`"), "names the repeated tool: {msg}");
        assert!(
            msg.contains("called 4 times"),
            "states attempt count: {msg}"
        );
        assert!(
            msg.contains("read, bash, edit"),
            "lists available tool names: {msg}"
        );
        // Tool-NAME list only — never a schema fragment.
        assert!(
            !msg.contains("properties") && !msg.contains("\"type\""),
            "no schema leaks into the message: {msg}"
        );
    }

    /// Idempotence: a further identical attempt UPDATES the single message's
    /// count rather than appending a second.
    #[test]
    fn further_attempt_updates_count_in_place() {
        let args = serde_json::json!({"path": "src/x.rs"});
        let available = ["read", "write"];
        let mut history: Vec<Message> = Vec::new();

        let tc2 = call("read", args.clone());
        drive_rejected_attempt(&mut history, &tc2, 2, &available);
        assert_eq!(collapse_messages(&history).len(), 1);
        assert!(collapse_messages(&history)[0].contains("called 2 times"));

        let tc3 = call("read", args.clone());
        drive_rejected_attempt(&mut history, &tc3, 3, &available);
        let collapses = collapse_messages(&history);
        assert_eq!(collapses.len(), 1, "still exactly one message");
        assert!(
            collapses[0].contains("called 3 times"),
            "count updated in place: {}",
            collapses[0]
        );
    }

    /// A differing call between repeats breaks the run: the earlier collapse
    /// message is NOT removed (no collapse across the break).
    #[test]
    fn differing_call_between_repeats_breaks_run() {
        let args = serde_json::json!({"command": "ls"});
        let available = ["bash"];
        let mut history: Vec<Message> = Vec::new();

        // First rejected run (bash ls).
        let tc_a = call("bash", args.clone());
        drive_rejected_attempt(&mut history, &tc_a, 2, &available);

        // A DIFFERENT call lands between — a normal dispatched call + real
        // result (not a collapse tool_result). This breaks the run.
        history.push(Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(call(
                "bash",
                serde_json::json!({"command": "pwd"}),
            ))),
        });
        history.push(Message::from(ToolResultContent::text("/repo")));

        // A new identical-to-the-first call rejects again. Because the
        // immediately-preceding pair is the `pwd` call (not a matching
        // collapse), the walk stops — the first collapse survives.
        let tc_b = call("bash", args.clone());
        drive_rejected_attempt(&mut history, &tc_b, 2, &available);

        assert_eq!(
            collapse_messages(&history).len(),
            2,
            "the break leaves two separate collapse messages, got: {history:?}"
        );
    }

    /// The collapse is WIRE-only: the session-DB tool_call rows (and thus the
    /// user-facing timeline) keep one entry per attempt.
    #[test]
    fn db_rows_kept_one_per_attempt() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db, tmp.path().to_path_buf(), "Build").unwrap();
        let args = serde_json::json!({"command": "cargo build"});

        // Each rejected attempt persists its own audit row (wire-vs-user split,
        // GOALS §14) — the collapse never touches this path.
        for count in 2u32..=4 {
            let body = format!(
                "Error: {}",
                loop_guard_message("bash", &args, count, &["bash"])
            );
            session
                .record_tool_call(ToolCallRow {
                    event_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    agent: "Build".to_string(),
                    call_id: format!("call-{count}"),
                    identity: crate::session::ToolCallProviderIdentity::default(),
                    tool: "bash".to_string(),
                    path: None,
                    original_input_json: args.clone(),
                    wire_input_json: args.clone(),
                    recovery: Recovery::Clean,
                    hard_fail: true,
                    output: body,
                    truncated: false,
                    duration_ms: 1,
                    llm_mode: crate::config::extended::LlmMode::Normal,
                    shape_fingerprint: None,
                    hint: None,
                })
                .unwrap();
        }

        let rows = session.db.list_tool_calls_for_session(session.id).unwrap();
        let bash_rows = rows.iter().filter(|r| r.tool == "bash").count();
        assert_eq!(
            bash_rows, 3,
            "one DB row per attempt is preserved (collapse is wire-only)"
        );
    }

    #[tokio::test]
    async fn repeated_recoverable_tree_call_is_short_circuited_before_dispatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db, tmp.path().to_path_buf(), "Build").unwrap();
        let args = serde_json::json!({"path": "src/nope"});
        let signature = crate::approval::store::GrantStore::loop_signature("tree", &args);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let first_result = if let Some(msg) =
            session.repeated_recoverable_tool_call_message(&signature)
        {
            Err(invalid_input(msg))
        } else {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(ToolOutput::text("No files match filter `src/nope`.\nempty_reason: `path` filter excluded all discovered files\nhint: run `tree` without `path` or use a different subtree.").with_repeat_guard("Previous `tree` call with the same `path` already returned no matches. Do not repeat it. Run `tree` without `path` to list the repo root, or choose a different subtree."))
        };
        let first_guard = match &first_result {
            Ok(out) => out.repeat_guard.clone(),
            Err(_) => None,
        };
        if let Some(RepeatGuard { message }) = first_guard {
            session.remember_recoverable_tool_call(signature.clone(), message);
        }

        let second_result =
            if let Some(msg) = session.repeated_recoverable_tool_call_message(&signature) {
                Err(invalid_input(msg))
            } else {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(ToolOutput::text("should not run"))
            };

        assert!(first_result.is_ok(), "first call should execute the tool");
        let err = second_result.expect_err("second identical call should short-circuit");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            err.to_string().contains("Run `tree` without `path`"),
            "{err}"
        );
    }
}
