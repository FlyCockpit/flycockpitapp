//! `question` — ask the user one or more structured questions and block
//! on the answers (GOALS §3b).
//!
//! A single call carries an **array** of questions. This is deliberate:
//! tool dispatch is sequential and a structural tool early-returns,
//! dropping the rest of the turn's calls (`engine::agent::turn`), so an
//! agent that splits its questions across calls would only ever get the
//! first answered. The description tells the model to ask everything it
//! needs in one call.
//!
//! Each question is `select` (choose one), `multiselect` (choose any),
//! or `text` (free-text). The tool raises one interrupt carrying the
//! whole batch, then blocks on the [`InterruptHub`] until a client
//! answers — indefinitely, with no timeout, so a headless run parks the
//! interrupt until a client (the TUI today, the remote dashboard later)
//! resolves it. On dismissal every question reads back as `Cancel`.
//!
//! [`InterruptHub`]: crate::engine::interrupt::InterruptHub

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::daemon::proto::{
    InterruptOption, InterruptQuestion, InterruptQuestionSet, ResolveResponse,
};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input, typed_args};

pub struct QuestionTool;

#[derive(Debug, Deserialize)]
struct QuestionArgs {
    questions: Vec<QuestionArg>,
}

#[derive(Debug, Deserialize)]
struct QuestionArg {
    #[serde(rename = "type")]
    kind: String,
    prompt: String,
    options: Option<Vec<QuestionOptionArg>>,
}

#[derive(Debug, Deserialize)]
struct QuestionOptionArg {
    id: String,
    label: Option<String>,
    description: Option<String>,
}

#[async_trait]
impl Tool for QuestionTool {
    fn name(&self) -> &str {
        "question"
    }

    fn description(&self) -> &str {
        "Ask the user questions and wait for answers; batch every question you need into this one call."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Stop and ask the human one or more questions, then block until they answer. Use this \
             whenever you are genuinely uncertain about scope, intent, or a decision you cannot \
             safely make alone — it is better to ask than to guess wrong. Put EVERY question you \
             currently have into this single call (the `questions` array); do not fire off \
             several separate `question` calls in a row, which makes the user answer one popup \
             after another. For each question choose `select` (pick one of your proposed \
             options), `multiselect` (pick any number), or `text` (free-form). Offer concrete \
             options when you can so the user just clicks. Don't ask about things you can find \
             out yourself by reading code or running a command."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "questions": {
                    "type": "array",
                    "description": "Questions to ask in this call",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type":   { "type": "string", "enum": ["select", "multiselect", "text"], "description": "Answer mode" },
                            "prompt": { "type": "string", "description": "Question text" },
                            "options": {
                                "type": "array",
                                "description": "Proposed options for select/multiselect",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "id":    { "type": "string", "description": "Stable option id" },
                                        "label": { "type": "string", "description": "Option label" },
                                        "description": { "type": "string", "description": "Optional one-line option description" }
                                    },
                                    "required": ["id", "label"]
                                }
                            }
                        },
                        "required": ["type", "prompt"]
                    }
                }
            },
            "required": ["questions"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "questions": {
                    "type": "array",
                    "description": "Every question to ask the user in this one call. Batch them all here rather than calling the tool repeatedly",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type":   { "type": "string", "enum": ["select", "multiselect", "text"], "description": "How the user answers: `select` = pick exactly one of `options`; `multiselect` = pick any number of `options`; `text` = type a free-form answer (no options needed)" },
                            "prompt": { "type": "string", "description": "The question text shown to the user; phrase it so it is answerable on its own" },
                            "options": {
                                "type": "array",
                                "description": "The choices to offer for a `select`/`multiselect` question; omit for a `text` question",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "id":    { "type": "string", "description": "A short stable identifier for this option, returned to you as the answer" },
                                        "label": { "type": "string", "description": "The human-readable label shown for this option" },
                                        "description": { "type": "string", "description": "Optional one-line elaboration shown under the label" }
                                    },
                                    "required": ["id", "label"]
                                }
                            }
                        },
                        "required": ["type", "prompt"]
                    }
                }
            },
            "required": ["questions"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: QuestionArgs = typed_args(args)?;
        if args.questions.is_empty() {
            return Err(invalid_input("`questions` must be a non-empty array"));
        }

        let mut questions = Vec::with_capacity(args.questions.len());
        for (i, q) in args.questions.iter().enumerate() {
            questions.push(parse_question_arg(q, i)?);
        }
        let set = InterruptQuestionSet { questions };
        let n = set.questions.len();

        // A short description doubles as the needs-attention queue label
        // and the dialog title hint. Single-question batches read more
        // naturally with the prompt verbatim.
        let description = if n == 1 {
            String::new()
        } else {
            format!("{n} questions need your answer")
        };

        // Persist first (so a headless run / late-attaching client can
        // still find and answer the parked interrupt), then register the
        // wakeup, then emit the event. Registering before emitting
        // guarantees a fast client can't resolve before we're listening.
        let response = crate::engine::interrupt::raise_and_wait(
            &ctx.session.db,
            &ctx.interrupts,
            ctx.session.id,
            &ctx.agent_id,
            &description,
            set.clone(),
            "question tool",
        )
        .await
        .into_response_or_cancel();
        let answers = response.into_batch(n);

        Ok(ToolOutput::text(render_answers(&set, &answers)))
    }
}

/// Parse one question entry from the tool args. Returns `invalid_input`
/// (a model-fault, repairable failure) on a malformed entry.
#[cfg(test)]
fn parse_question(q: &Value, index: usize) -> Result<InterruptQuestion> {
    let q: QuestionArg = typed_args(q.clone())?;
    parse_question_arg(&q, index)
}

fn parse_question_arg(q: &QuestionArg, index: usize) -> Result<InterruptQuestion> {
    let kind = q.kind.as_str();
    let prompt = q.prompt.clone();

    match kind {
        "text" => Ok(InterruptQuestion::Freetext {
            prompt,
            masked: false,
        }),
        "select" | "multiselect" => {
            let options = parse_options_arg(q);
            if options.is_empty() {
                return Err(invalid_input(format!(
                    "question {index}: `{kind}` needs at least one option"
                )));
            }
            if kind == "select" {
                Ok(InterruptQuestion::Single {
                    prompt,
                    options,
                    allow_freetext: true,
                    command_detail: None,
                    // The `question` tool always raises a genuine agent
                    // question — never a tool-permission approval.
                    permission: false,
                    sandbox_escalation: None,
                })
            } else {
                Ok(InterruptQuestion::Multi {
                    prompt,
                    options,
                    allow_freetext: true,
                })
            }
        }
        other => Err(invalid_input(format!(
            "question {index}: unknown type `{other}` (use select/multiselect/text)"
        ))),
    }
}

fn parse_options_arg(q: &QuestionArg) -> Vec<InterruptOption> {
    q.options
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|opt| {
            let label = opt.label.clone().unwrap_or_else(|| opt.id.clone());
            InterruptOption {
                id: opt.id.clone(),
                label,
                description: opt.description.clone(),
                secondary: false,
            }
        })
        .collect()
}

fn question_prompt(q: &InterruptQuestion) -> &str {
    match q {
        InterruptQuestion::Single { prompt, .. }
        | InterruptQuestion::Multi { prompt, .. }
        | InterruptQuestion::Freetext { prompt, .. } => prompt,
    }
}

/// Render the resolved answers as the tool result the model sees next
/// turn. One line per question; the option label is preferred over the
/// raw id when it can be resolved, and a free-text answer is shown
/// verbatim. A dismissed batch reads as `[cancelled]` per question.
fn render_answers(set: &InterruptQuestionSet, answers: &[ResolveResponse]) -> String {
    let mut out = String::new();
    for (i, q) in set.questions.iter().enumerate() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(question_prompt(q));
        out.push_str(" → ");
        match answers.get(i) {
            Some(ResolveResponse::Single { selected_id }) => {
                out.push_str(&label_for(q, selected_id));
            }
            Some(ResolveResponse::Multi { selected_ids }) => {
                if selected_ids.is_empty() {
                    out.push_str("[none]");
                } else {
                    let labels: Vec<String> =
                        selected_ids.iter().map(|id| label_for(q, id)).collect();
                    out.push_str(&labels.join(", "));
                }
            }
            Some(ResolveResponse::Freetext { text }) => out.push_str(text),
            Some(ResolveResponse::Batch { .. }) | None => out.push_str("[no answer]"),
            Some(ResolveResponse::Cancel) => out.push_str("[cancelled]"),
        }
    }
    out
}

/// Map a selected option id back to its label, preferring the label but
/// falling back to the raw id (a free-text answer in a `select`/`multi`
/// shows up here as an id with no matching option).
fn label_for(q: &InterruptQuestion, id: &str) -> String {
    let options = match q {
        InterruptQuestion::Single { options, .. } | InterruptQuestion::Multi { options, .. } => {
            options.as_slice()
        }
        InterruptQuestion::Freetext { .. } => &[],
    };
    options
        .iter()
        .find(|o| o.id == id)
        .map(|o| o.label.clone())
        .unwrap_or_else(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_select_question() {
        let q = json!({
            "type": "select",
            "prompt": "Which DB?",
            "options": [{ "id": "pg", "label": "Postgres" }, { "id": "sqlite", "label": "SQLite" }]
        });
        let parsed = parse_question(&q, 0).unwrap();
        match parsed {
            InterruptQuestion::Single {
                prompt, options, ..
            } => {
                assert_eq!(prompt, "Which DB?");
                assert_eq!(options.len(), 2);
            }
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[test]
    fn parse_multiselect_and_text() {
        let multi = parse_question(
            &json!({ "type": "multiselect", "prompt": "Tags?", "options": [{ "id": "a", "label": "A" }] }),
            0,
        )
        .unwrap();
        assert!(matches!(multi, InterruptQuestion::Multi { .. }));
        let text = parse_question(&json!({ "type": "text", "prompt": "Name?" }), 1).unwrap();
        assert!(matches!(text, InterruptQuestion::Freetext { .. }));
    }

    #[test]
    fn select_without_options_is_invalid() {
        let err = parse_question(&json!({ "type": "select", "prompt": "X?" }), 0).unwrap_err();
        assert!(err.to_string().contains("at least one option"));
    }

    #[test]
    fn unknown_type_is_invalid() {
        let err = parse_question(&json!({ "type": "slider", "prompt": "X?" }), 0).unwrap_err();
        assert!(err.to_string().contains("unknown type"));
    }

    #[test]
    fn render_resolves_labels_and_freetext() {
        let set = InterruptQuestionSet {
            questions: vec![
                InterruptQuestion::Single {
                    prompt: "DB?".into(),
                    options: vec![InterruptOption {
                        id: "pg".into(),
                        label: "Postgres".into(),
                        description: None,
                        secondary: false,
                    }],
                    allow_freetext: true,
                    command_detail: None,
                    permission: false,
                    sandbox_escalation: None,
                },
                InterruptQuestion::Freetext {
                    prompt: "Name?".into(),
                    masked: false,
                },
            ],
        };
        let answers = vec![
            ResolveResponse::Single {
                selected_id: "pg".into(),
            },
            ResolveResponse::Freetext { text: "Ada".into() },
        ];
        let rendered = render_answers(&set, &answers);
        assert!(rendered.contains("DB? → Postgres"));
        assert!(rendered.contains("Name? → Ada"));
    }

    #[test]
    fn render_cancel_marks_every_question() {
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Freetext {
                prompt: "Name?".into(),
                masked: false,
            }],
        };
        let answers = ResolveResponse::Cancel.into_batch(1);
        assert!(render_answers(&set, &answers).contains("[cancelled]"));
    }

    #[tokio::test]
    async fn call_blocks_then_returns_resolved_answers() {
        use crate::engine::interrupt::InterruptHub;
        use std::sync::Arc;
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        let hub = Arc::new(InterruptHub::detached());
        ctx.interrupts = hub.clone();
        let session_id = ctx.session.id;
        let db = ctx.session.db.clone();

        let args = json!({
            "questions": [
                { "type": "select", "prompt": "DB?", "options": [{ "id": "pg", "label": "Postgres" }] }
            ]
        });

        // Spawn the blocking call; resolve it from another task once the
        // interrupt is persisted (proves the tool actually parks).
        let call = tokio::spawn(async move { QuestionTool.call(args, &ctx).await });

        // Wait for the interrupt to appear in the DB, then resolve it.
        let iid = loop {
            let open = db.list_open_interrupts(session_id).unwrap();
            if let Some(row) = open.first() {
                break row.interrupt_id;
            }
            tokio::task::yield_now().await;
        };
        assert!(hub.resolve(
            iid,
            ResolveResponse::Single {
                selected_id: "pg".into()
            }
        ));

        let out = call.await.unwrap().unwrap();
        assert!(out.content.contains("DB? → Postgres"));
    }
}
