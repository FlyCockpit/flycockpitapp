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

const MAX_QUESTIONS: usize = 20;
const MIN_OPTIONS: usize = 2;
const MAX_OPTIONS: usize = 8;

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
    label: String,
    description: Option<String>,
}

#[async_trait]
impl Tool for QuestionTool {
    fn name(&self) -> &str {
        "question"
    }

    fn description(&self) -> &str {
        "Ask the user questions and wait for answers; batch every question you need into this one call; ask only when the choice is costly to reverse or changes what gets built."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Stop and ask the human one or more questions, then block until they answer. Use this \
             when the choice is costly to reverse, changes what gets built, spends the user's \
             money or credentials, or is genuinely underdetermined by everything available to \
             you. Do not ask when the choice is cheap and reversible, when a reasonable default \
             exists, or when you are the one better positioned to judge; make the call and say \
             what you chose. Put EVERY question you currently have into this single call (the \
             `questions` array); do not fire off several separate `question` calls in a row, \
             which makes the user answer one popup after another. For each question choose \
             `select` (pick one of your proposed options), `multiselect` (pick any number), or \
             `text` (free-form). Offer concrete options when you can so the user just clicks. \
             Don't ask about things you can find out yourself by reading code or running a \
             command."
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
                    "minItems": 1,
                    "maxItems": MAX_QUESTIONS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "type":   { "type": "string", "enum": ["select", "multiselect", "text"], "description": "Answer mode" },
                            "prompt": { "type": "string", "description": "Question text" },
                            "options": {
                                "type": "array",
                                "description": "Proposed options for select/multiselect",
                                "minItems": MIN_OPTIONS,
                                "maxItems": MAX_OPTIONS,
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
                    "minItems": 1,
                    "maxItems": MAX_QUESTIONS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "type":   { "type": "string", "enum": ["select", "multiselect", "text"], "description": "How the user answers: `select` = pick exactly one of `options`; `multiselect` = pick any number of `options`; `text` = type a free-form answer (no options needed)" },
                            "prompt": { "type": "string", "description": "The question text shown to the user; phrase it so it is answerable on its own" },
                            "options": {
                                "type": "array",
                                "description": "The choices to offer for a `select`/`multiselect` question; omit for a `text` question",
                                "minItems": MIN_OPTIONS,
                                "maxItems": MAX_OPTIONS,
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
        if args.questions.len() > MAX_QUESTIONS {
            return Err(invalid_input(format!(
                "`questions` has {} entries; maximum is {MAX_QUESTIONS}",
                args.questions.len()
            )));
        }

        let mut questions = Vec::with_capacity(args.questions.len());
        for (i, q) in args.questions.iter().enumerate() {
            questions.push(parse_question_arg(q, i)?);
        }
        let set = InterruptQuestionSet { questions };
        let n = set.questions.len();

        if !ctx.interrupts.is_interactive_attached() {
            return Ok(ToolOutput::text(render_headless_guidance(&set)));
        }

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
        .into_response()?;
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
            if options.len() < MIN_OPTIONS {
                return Err(invalid_input(format!(
                    "question {index}: `{kind}` has {} option(s); provide at least {MIN_OPTIONS} options or use `text` for an open-ended question",
                    options.len()
                )));
            }
            if options.len() > MAX_OPTIONS {
                return Err(invalid_input(format!(
                    "question {index}: `{kind}` has {} option(s); maximum is {MAX_OPTIONS}",
                    options.len()
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
                    approval_class: None,
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
        .map(|opt| InterruptOption {
            id: opt.id.clone(),
            label: opt.label.clone(),
            description: opt.description.clone(),
            secondary: false,
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

fn render_headless_guidance(set: &InterruptQuestionSet) -> String {
    let mut out = "No interactive client is attached, so these questions cannot be answered. Proceed on your best judgment and state the assumption you made for each.".to_string();
    for (i, question) in set.questions.iter().enumerate() {
        out.push('\n');
        out.push_str(&(i + 1).to_string());
        out.push_str(". ");
        out.push_str(question_prompt(question));
        out.push_str(
            " → unanswered; choose the most reasonable option and say which you chose and why.",
        );
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
            &json!({ "type": "multiselect", "prompt": "Tags?", "options": [{ "id": "a", "label": "A" }, { "id": "b", "label": "B" }] }),
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
        assert!(err.to_string().contains("0 option(s)"));
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
                    approval_class: None,
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

    fn two_option_question(prompt: &str) -> Value {
        json!({
            "type": "select",
            "prompt": prompt,
            "options": [
                { "id": "a", "label": "A" },
                { "id": "b", "label": "B" }
            ]
        })
    }

    fn sample_call_args() -> Value {
        json!({
            "questions": [
                two_option_question("Pick a database?"),
                { "type": "text", "prompt": "What name should I use?" }
            ]
        })
    }

    fn strip_descriptions(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut stripped = serde_json::Map::new();
                for (key, value) in object {
                    if key != "description" {
                        stripped.insert(key.clone(), strip_descriptions(value));
                    }
                }
                Value::Object(stripped)
            }
            Value::Array(values) => Value::Array(values.iter().map(strip_descriptions).collect()),
            other => other.clone(),
        }
    }

    fn options_schema(schema: &Value) -> &Value {
        &schema["properties"]["questions"]["items"]["properties"]["options"]
    }

    #[tokio::test]
    async fn question_headless_returns_proceed_guidance() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());

        let out = QuestionTool.call(sample_call_args(), &ctx).await.unwrap();

        assert!(out.content.contains("No interactive client is attached"));
        assert!(out.content.contains("Proceed on your best judgment"));
        assert!(out.content.contains("state the assumption"));
        assert!(!out.content.contains("retry"));
    }

    #[tokio::test]
    async fn question_headless_result_echoes_every_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());

        let out = QuestionTool.call(sample_call_args(), &ctx).await.unwrap();

        assert!(out.content.contains("1. Pick a database?"));
        assert!(out.content.contains("2. What name should I use?"));
        assert!(out.content.contains("unanswered"));
    }

    #[tokio::test]
    async fn question_headless_persists_no_interrupt() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());

        QuestionTool.call(sample_call_args(), &ctx).await.unwrap();

        assert!(db.list_open_interrupts(ctx.session.id).unwrap().is_empty());
    }

    #[test]
    fn question_terse_description_carries_one_ask_rule() {
        let description = QuestionTool.description();
        assert!(description.contains("batch every question"));
        assert!(description.contains("costly to reverse"));
        assert!(description.contains("changes what gets built"));
        assert_eq!(description.matches("costly to reverse").count(), 1);
    }

    #[test]
    fn question_defensive_description_states_ask_and_proceed() {
        let description = QuestionTool.defensive_description().unwrap();
        assert!(description.contains("costly to reverse"));
        assert!(description.contains("changes what gets built"));
        assert!(description.contains("cheap and reversible"));
        assert!(description.contains("make the call"));
        assert!(description.contains("Put EVERY question"));
        assert!(description.contains("reading code or running a command"));
    }

    #[test]
    fn question_schema_caps_questions_and_options() {
        for schema in [
            QuestionTool.parameters(),
            QuestionTool.defensive_parameters().unwrap(),
        ] {
            assert_eq!(schema["properties"]["questions"]["minItems"], 1);
            assert_eq!(schema["properties"]["questions"]["maxItems"], MAX_QUESTIONS);
            assert_eq!(options_schema(&schema)["minItems"], MIN_OPTIONS);
            assert_eq!(options_schema(&schema)["maxItems"], MAX_OPTIONS);
        }
    }

    #[test]
    fn question_schema_tiers_agree_on_shape() {
        assert_eq!(
            strip_descriptions(&QuestionTool.parameters()),
            strip_descriptions(&QuestionTool.defensive_parameters().unwrap())
        );
    }

    #[test]
    fn question_rejects_single_option_select() {
        let err = parse_question(
            &json!({
                "type": "select",
                "prompt": "Only?",
                "options": [{ "id": "only", "label": "Only" }]
            }),
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("1 option(s)"));
    }

    #[test]
    fn question_rejects_too_many_options() {
        let options: Vec<Value> = (0..=MAX_OPTIONS)
            .map(|i| json!({ "id": format!("opt-{i}"), "label": format!("Option {i}") }))
            .collect();
        let err = parse_question(
            &json!({ "type": "select", "prompt": "Many?", "options": options }),
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("9 option(s)"));
    }

    #[tokio::test]
    async fn question_rejects_too_many_questions() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let questions: Vec<Value> = (0..=MAX_QUESTIONS)
            .map(|i| json!({ "type": "text", "prompt": format!("Question {i}?") }))
            .collect();

        let err = QuestionTool
            .call(json!({ "questions": questions }), &ctx)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("21 entries"));
    }

    #[test]
    fn question_missing_option_label_is_invalid_input() {
        let err = parse_question(
            &json!({
                "type": "select",
                "prompt": "Missing?",
                "options": [{ "id": "a", "label": "A" }, { "id": "b" }]
            }),
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("label"));
    }

    #[test]
    fn question_freetext_answer_in_select_still_renders_raw_text() {
        let q = parse_question(&two_option_question("DB?"), 0).unwrap();
        let rendered = render_answers(
            &InterruptQuestionSet { questions: vec![q] },
            &[ResolveResponse::Single {
                selected_id: "custom".into(),
            }],
        );
        assert!(rendered.contains("DB? → custom"));
    }

    #[tokio::test]
    async fn question_attached_still_raises_and_renders_answers() {
        use crate::engine::interrupt::InterruptHub;
        use std::sync::Arc;
        let tmp = tempfile::tempdir().unwrap();
        let (mut ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        let (events, _receiver) = tokio::sync::broadcast::channel(8);
        let redaction = Arc::new(std::sync::RwLock::new(Arc::new(
            crate::redact::RedactionTable::empty(),
        )));
        let hub = Arc::new(InterruptHub::new(
            events,
            redaction,
            Arc::new(std::sync::atomic::AtomicUsize::new(1)),
            db.clone(),
            ctx.session.id,
        ));
        ctx.interrupts = hub.clone();
        let session_id = ctx.session.id;

        let args = json!({
            "questions": [
                { "type": "select", "prompt": "DB?", "options": [{ "id": "pg", "label": "Postgres" }, { "id": "sqlite", "label": "SQLite" }] }
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
