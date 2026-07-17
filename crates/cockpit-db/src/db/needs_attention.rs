//! `needs_attention` queue.
//!
//! Background builders push items here via `raise_interrupt` (GOALS §3b);
//! the TUI surfaces them through `interrupt_raised` events, the user
//! resolves with a payload, and the daemon writes the resolution back
//! before un-pausing the agent.
//!
//! v1 stores the wire shapes verbatim — the TUI client and the future
//! web/mobile client both render the same JSON.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;
use crate::db::wire::{
    InterruptDecision, InterruptDecisionLine, InterruptQuestion, InterruptQuestionSet,
    ResolveResponse,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterruptState {
    Open,
    Parked,
    Executing,
    Interrupted,
    Resolved,
}

impl InterruptState {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Parked => "parked",
            Self::Executing => "executing",
            Self::Interrupted => "interrupted",
            Self::Resolved => "resolved",
        }
    }

    fn parse(s: &str) -> rusqlite::Result<Self> {
        match s {
            "open" => Ok(Self::Open),
            "parked" => Ok(Self::Parked),
            "executing" => Ok(Self::Executing),
            "interrupted" => Ok(Self::Interrupted),
            "resolved" => Ok(Self::Resolved),
            other => Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                format!("unknown interrupt state `{other}`").into(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterruptResumeAnchor {
    pub agent_id: String,
    pub call_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assistant_seq: Option<i64>,
    /// Trusted frame provenance that must survive parked-call replay. It is
    /// explicit in every persisted anchor so the replay authority is auditable.
    pub call_origin: InterruptCallOrigin,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterruptCallOrigin {
    #[default]
    Foreground,
    BackgroundReview,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterruptParkPayload {
    pub tool: String,
    pub args: Value,
    pub call_id: String,
    pub resume: InterruptResumeAnchor,
}

// Full hydrated mirror of the `needs_attention` row; its fields back the
// not-yet-wired interrupt-resolution UI, so the struct is retained whole.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct NeedsAttentionRow {
    pub interrupt_id: Uuid,
    pub session_id: Uuid,
    pub agent_id: String,
    pub description: String,
    pub question: Option<InterruptQuestion>,
    /// Multi-question batch (GOALS §3b). Stored in the same
    /// `question_json` column as a single question — the column holds
    /// whichever wire shape the interrupt carried. A row never has both.
    pub questions: Option<InterruptQuestionSet>,
    pub raised_at: i64,
    pub resolved_at: Option<i64>,
    pub response: Option<ResolveResponse>,
    pub state: InterruptState,
    pub parked: Option<InterruptParkPayload>,
}

impl Db {
    pub fn raise_interrupt(
        &self,
        session_id: Uuid,
        agent_id: &str,
        description: &str,
        question: Option<&InterruptQuestion>,
    ) -> Result<Uuid> {
        let interrupt_id = Uuid::new_v4();
        let raised_at = Utc::now().timestamp();
        let question_json = match question {
            Some(q) => Some(serde_json::to_string(q).context("serializing question")?),
            None => None,
        };
        let agent_id = agent_id.to_owned();
        let description = description.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO needs_attention
                 (interrupt_id, session_id, agent_id, description, question_json, raised_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    interrupt_id.to_string(),
                    session_id.to_string(),
                    agent_id,
                    description,
                    question_json,
                    raised_at,
                ],
            )
            .context("inserting needs_attention")?;
            Ok(())
        })?;
        Ok(interrupt_id)
    }

    /// Persist a multi-question interrupt (GOALS §3b). Sibling of
    /// [`Self::raise_interrupt`]: identical except the payload is a
    /// [`InterruptQuestionSet`] stored in `questions_json` (the legacy
    /// `question_json` column stays NULL). Used by the `question` tool.
    #[allow(dead_code)]
    pub fn raise_interrupt_questions(
        &self,
        session_id: Uuid,
        agent_id: &str,
        description: &str,
        questions: &InterruptQuestionSet,
    ) -> Result<Uuid> {
        self.raise_interrupt_questions_with_payload(
            session_id,
            agent_id,
            description,
            questions,
            None,
        )
    }

    pub fn raise_interrupt_questions_with_payload(
        &self,
        session_id: Uuid,
        agent_id: &str,
        description: &str,
        questions: &InterruptQuestionSet,
        parked: Option<&InterruptParkPayload>,
    ) -> Result<Uuid> {
        let interrupt_id = Uuid::new_v4();
        let raised_at = Utc::now().timestamp();
        let questions_json = serde_json::to_string(questions).context("serializing questions")?;
        let parked_tool = parked.map(|payload| payload.tool.clone());
        // Stored verbatim because parked replay must re-run the exact tool
        // wire input. This has the same exposure boundary as
        // session_events.wire_input_json and must not be presented as
        // user-authored text.
        let parked_args_json = parked
            .map(|payload| serde_json::to_string(&payload.args))
            .transpose()
            .context("serializing parked args")?;
        let parked_call_id = parked.map(|payload| payload.call_id.clone());
        let parked_resume_json = parked
            .map(|payload| serde_json::to_string(&payload.resume))
            .transpose()
            .context("serializing parked resume anchor")?;
        let agent_id = agent_id.to_owned();
        let description = description.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO needs_attention
                 (interrupt_id, session_id, agent_id, description, questions_json, raised_at,
                  state, parked_tool, parked_args_json, parked_call_id, parked_resume_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7, ?8, ?9, ?10)",
                params![
                    interrupt_id.to_string(),
                    session_id.to_string(),
                    agent_id,
                    description,
                    questions_json,
                    raised_at,
                    parked_tool,
                    parked_args_json,
                    parked_call_id,
                    parked_resume_json,
                ],
            )
            .context("inserting needs_attention (questions)")?;
            Ok(())
        })?;
        Ok(interrupt_id)
    }

    pub fn resolve_interrupt(&self, interrupt_id: Uuid, response: &ResolveResponse) -> Result<()> {
        let now = Utc::now().timestamp();
        let response_json =
            serde_json::to_string(response).context("serializing resolve response")?;
        self.write_blocking(move |conn| {
            let affected = conn
                .execute(
                    "UPDATE needs_attention
                        SET resolved_at = ?1, response_json = ?2, state = 'resolved'
                      WHERE interrupt_id = ?3 AND state = 'open'",
                    params![now, response_json, interrupt_id.to_string()],
                )
                .context("resolving needs_attention")?;
            if affected == 0 {
                anyhow::bail!("interrupt {interrupt_id} not found or not open");
            }
            Ok(())
        })
    }

    pub fn list_open_interrupts(&self, session_id: Uuid) -> Result<Vec<NeedsAttentionRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT interrupt_id, session_id, agent_id, description,
                            question_json, questions_json, raised_at, resolved_at, response_json,
                            state, parked_tool, parked_args_json, parked_call_id, parked_resume_json
                       FROM needs_attention
                      WHERE session_id = ?1 AND state IN ('open', 'parked')
                      ORDER BY raised_at ASC, rowid ASC",
                )
                .context("preparing list_open_interrupts")?;
            let rows = stmt
                .query_map([session_id.to_string()], decode_row)
                .context("querying needs_attention")?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.context("decoding needs_attention row")?);
            }
            Ok(out)
        })
    }

    pub fn list_reconcilable_interrupts(&self, session_id: Uuid) -> Result<Vec<NeedsAttentionRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT interrupt_id, session_id, agent_id, description,
                            question_json, questions_json, raised_at, resolved_at, response_json,
                            state, parked_tool, parked_args_json, parked_call_id, parked_resume_json
                       FROM needs_attention
                      WHERE session_id = ?1 AND state IN ('open', 'parked', 'executing')
                      ORDER BY raised_at ASC, rowid ASC",
                )
                .context("preparing list_reconcilable_interrupts")?;
            let rows = stmt
                .query_map([session_id.to_string()], decode_row)
                .context("querying reconcilable needs_attention")?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.context("decoding reconcilable needs_attention row")?);
            }
            Ok(out)
        })
    }

    pub fn get_interrupt(&self, interrupt_id: Uuid) -> Result<Option<NeedsAttentionRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT interrupt_id, session_id, agent_id, description,
                            question_json, questions_json, raised_at, resolved_at, response_json,
                            state, parked_tool, parked_args_json, parked_call_id, parked_resume_json
                       FROM needs_attention
                      WHERE interrupt_id = ?1",
                )
                .context("preparing get_interrupt")?;
            let mut rows = stmt
                .query_map([interrupt_id.to_string()], decode_row)
                .context("querying needs_attention by interrupt")?;
            match rows.next() {
                Some(row) => Ok(Some(row.context("decoding needs_attention row")?)),
                None => Ok(None),
            }
        })
    }

    pub fn park_interrupt(&self, interrupt_id: Uuid) -> Result<bool> {
        self.write_blocking(move |conn| {
            let affected = conn
                .execute(
                    "UPDATE needs_attention
                        SET state = 'parked'
                      WHERE interrupt_id = ?1 AND state = 'open'",
                    params![interrupt_id.to_string()],
                )
                .context("parking needs_attention")?;
            Ok(affected > 0)
        })
    }

    pub fn mark_interrupt_interrupted(&self, interrupt_id: Uuid) -> Result<bool> {
        self.write_blocking(move |conn| {
            let affected = conn
                .execute(
                    "UPDATE needs_attention
                        SET state = 'interrupted'
                      WHERE interrupt_id = ?1 AND state IN ('open', 'parked', 'executing')",
                    params![interrupt_id.to_string()],
                )
                .context("marking needs_attention interrupted")?;
            Ok(affected > 0)
        })
    }

    pub fn acknowledge_interrupted_turns(&self, session_id: Uuid) -> Result<usize> {
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            let affected = conn
                .execute(
                    "UPDATE needs_attention
                        SET state = 'resolved', resolved_at = ?1
                      WHERE session_id = ?2 AND state = 'interrupted'",
                    params![now, session_id.to_string()],
                )
                .context("acknowledging interrupted needs_attention markers")?;
            Ok(affected)
        })
    }

    pub fn raise_interrupted_turn(
        &self,
        session_id: Uuid,
        agent_id: &str,
        description: &str,
    ) -> Result<Uuid> {
        let interrupt_id = Uuid::new_v4();
        let raised_at = Utc::now().timestamp();
        let agent_id = agent_id.to_owned();
        let description = description.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO needs_attention
                 (interrupt_id, session_id, agent_id, description, state, raised_at)
                 VALUES (?1, ?2, ?3, ?4, 'interrupted', ?5)",
                params![
                    interrupt_id.to_string(),
                    session_id.to_string(),
                    agent_id,
                    description,
                    raised_at,
                ],
            )
            .context("inserting interrupted needs_attention")?;
            Ok(())
        })?;
        Ok(interrupt_id)
    }

    pub fn begin_parked_interrupt_execution(
        &self,
        interrupt_id: Uuid,
        response: &ResolveResponse,
    ) -> Result<bool> {
        let response_json =
            serde_json::to_string(response).context("serializing parked interrupt response")?;
        self.write_blocking(move |conn| {
            let affected = conn
                .execute(
                    "UPDATE needs_attention
                        SET state = 'executing', response_json = ?1
                      WHERE interrupt_id = ?2 AND state = 'parked'",
                    params![response_json, interrupt_id.to_string()],
                )
                .context("marking parked interrupt executing")?;
            Ok(affected > 0)
        })
    }

    pub fn complete_executing_interrupt(&self, interrupt_id: Uuid) -> Result<bool> {
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            let affected = conn
                .execute(
                    "UPDATE needs_attention
                        SET state = 'resolved', resolved_at = ?1
                      WHERE interrupt_id = ?2 AND state = 'executing'",
                    params![now, interrupt_id.to_string()],
                )
                .context("completing executing interrupt")?;
            Ok(affected > 0)
        })
    }
}

pub fn summarize_interrupt_decision(
    row: &NeedsAttentionRow,
    response: &ResolveResponse,
) -> InterruptDecision {
    let questions: Vec<&InterruptQuestion> = row
        .questions
        .as_ref()
        .map(|set| set.questions.iter().collect())
        .or_else(|| row.question.as_ref().map(|question| vec![question]))
        .unwrap_or_default();
    let responses: Vec<&ResolveResponse> = match response {
        ResolveResponse::Batch { responses } => responses.iter().collect(),
        other => vec![other],
    };
    let cancelled = matches!(response, ResolveResponse::Cancel);
    let permission = questions.iter().any(|question| {
        matches!(
            question,
            InterruptQuestion::Single {
                permission: true,
                approval_class: None,
                ..
            }
        )
    });
    let lines = questions
        .iter()
        .enumerate()
        .map(|(index, question)| InterruptDecisionLine {
            prompt: interrupt_prompt(question).to_string(),
            answer: if cancelled {
                "dismissed".to_string()
            } else {
                responses
                    .get(index)
                    .map(|response| answer_label(question, response))
                    .unwrap_or_else(|| "dismissed".to_string())
            },
        })
        .collect();
    InterruptDecision {
        permission,
        cancelled,
        lines,
    }
}

fn interrupt_prompt(question: &InterruptQuestion) -> &str {
    match question {
        InterruptQuestion::Single { prompt, .. }
        | InterruptQuestion::Multi { prompt, .. }
        | InterruptQuestion::Freetext { prompt, .. } => prompt,
    }
}

fn answer_label(question: &InterruptQuestion, response: &ResolveResponse) -> String {
    match (question, response) {
        (InterruptQuestion::Single { options, .. }, ResolveResponse::Single { selected_id }) => {
            options
                .iter()
                .find(|option| option.id == *selected_id)
                .map(|option| option.label.clone())
                .unwrap_or_else(|| selected_id.clone())
        }
        (InterruptQuestion::Multi { options, .. }, ResolveResponse::Multi { selected_ids }) => {
            selected_ids
                .iter()
                .map(|id| {
                    options
                        .iter()
                        .find(|option| option.id == *id)
                        .map(|option| option.label.clone())
                        .unwrap_or_else(|| id.clone())
                })
                .collect::<Vec<_>>()
                .join(", ")
        }
        (InterruptQuestion::Freetext { masked: true, .. }, ResolveResponse::Freetext { .. }) => {
            "••••••••".to_string()
        }
        (InterruptQuestion::Freetext { masked: false, .. }, ResolveResponse::Freetext { text }) => {
            text.clone()
        }
        (_, ResolveResponse::Cancel) => "dismissed".to_string(),
        _ => "dismissed".to_string(),
    }
}

fn decode_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NeedsAttentionRow> {
    let interrupt_id: String = row.get("interrupt_id")?;
    let interrupt_id = Uuid::parse_str(&interrupt_id).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let session_id: String = row.get("session_id")?;
    let session_id = Uuid::parse_str(&session_id).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let question_json: Option<String> = row.get("question_json")?;
    let question = match question_json {
        Some(s) => Some(serde_json::from_str(&s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?),
        None => None,
    };
    let questions_json: Option<String> = row.get("questions_json")?;
    let questions = match questions_json {
        Some(s) => Some(serde_json::from_str(&s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?),
        None => None,
    };
    let response_json: Option<String> = row.get("response_json")?;
    let response = match response_json {
        Some(s) => Some(serde_json::from_str(&s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?),
        None => None,
    };
    let state_raw: String = row.get("state")?;
    let state = InterruptState::parse(&state_raw)?;
    let parked_tool: Option<String> = row.get("parked_tool")?;
    let parked_args_json: Option<String> = row.get("parked_args_json")?;
    let parked_call_id: Option<String> = row.get("parked_call_id")?;
    let parked_resume_json: Option<String> = row.get("parked_resume_json")?;
    let parked = match (
        parked_tool,
        parked_args_json,
        parked_call_id,
        parked_resume_json,
    ) {
        (Some(tool), Some(args_json), Some(call_id), Some(resume_json)) => {
            let args = serde_json::from_str(&args_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            let resume = serde_json::from_str(&resume_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Some(InterruptParkPayload {
                tool,
                args,
                call_id,
                resume,
            })
        }
        _ => None,
    };
    Ok(NeedsAttentionRow {
        interrupt_id,
        session_id,
        agent_id: row.get("agent_id")?,
        description: row.get("description")?,
        question,
        questions,
        raised_at: row.get("raised_at")?,
        resolved_at: row.get("resolved_at")?,
        response,
        state,
        parked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::wire::{
        InterruptOption, InterruptQuestion, InterruptQuestionSet, ResolveResponse,
    };

    #[test]
    fn raise_and_resolve_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let q = InterruptQuestion::Single {
            prompt: "yes or no".into(),
            options: vec![
                InterruptOption {
                    id: "y".into(),
                    label: "yes".into(),
                    description: None,
                    secondary: false,
                },
                InterruptOption {
                    id: "n".into(),
                    label: "no".into(),
                    description: None,
                    secondary: false,
                },
            ],
            allow_freetext: true,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let iid = db
            .raise_interrupt(s.session_id, "builder", "paused on something", Some(&q))
            .unwrap();

        let open = db.list_open_interrupts(s.session_id).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].interrupt_id, iid);

        db.resolve_interrupt(
            iid,
            &ResolveResponse::Single {
                selected_id: "y".into(),
            },
        )
        .unwrap();
        let open = db.list_open_interrupts(s.session_id).unwrap();
        assert_eq!(open.len(), 0);
    }

    #[test]
    fn decision_summary_uses_labels_and_never_exposes_masked_text() {
        let row = NeedsAttentionRow {
            interrupt_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            agent_id: "builder".into(),
            description: String::new(),
            question: None,
            questions: Some(InterruptQuestionSet {
                questions: vec![
                    InterruptQuestion::Single {
                        prompt: "Continue?".into(),
                        options: vec![InterruptOption {
                            id: "yes".into(),
                            label: "Approve for this project".into(),
                            description: None,
                            secondary: false,
                        }],
                        allow_freetext: false,
                        command_detail: None,
                        permission: true,
                        approval_class: None,
                        sandbox_escalation: None,
                    },
                    InterruptQuestion::Freetext {
                        prompt: "Token".into(),
                        masked: true,
                    },
                ],
            }),
            raised_at: 0,
            resolved_at: None,
            response: None,
            state: InterruptState::Open,
            parked: None,
        };
        let decision = summarize_interrupt_decision(
            &row,
            &ResolveResponse::Batch {
                responses: vec![
                    ResolveResponse::Single {
                        selected_id: "yes".into(),
                    },
                    ResolveResponse::Freetext {
                        text: "super-secret".into(),
                    },
                ],
            },
        );
        assert!(decision.permission);
        assert_eq!(decision.lines[0].answer, "Approve for this project");
        let json = serde_json::to_string(&decision).unwrap();
        assert!(!json.contains("super-secret"));
        assert!(json.contains("••••••••"));
    }

    #[test]
    fn raise_questions_batch_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let set = InterruptQuestionSet {
            questions: vec![
                InterruptQuestion::Single {
                    prompt: "which?".into(),
                    options: vec![InterruptOption {
                        id: "a".into(),
                        label: "A".into(),
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
                    prompt: "name?".into(),
                    masked: false,
                },
            ],
        };
        let iid = db
            .raise_interrupt_questions(s.session_id, "builder", "needs input", &set)
            .unwrap();

        let open = db.list_open_interrupts(s.session_id).unwrap();
        assert_eq!(open.len(), 1);
        // The batch round-trips in `questions`, not the legacy `question`.
        assert!(open[0].question.is_none());
        assert_eq!(open[0].questions.as_ref().unwrap().questions.len(), 2);

        db.resolve_interrupt(
            iid,
            &ResolveResponse::Batch {
                responses: vec![
                    ResolveResponse::Single {
                        selected_id: "a".into(),
                    },
                    ResolveResponse::Freetext { text: "Ada".into() },
                ],
            },
        )
        .unwrap();
        assert_eq!(db.list_open_interrupts(s.session_id).unwrap().len(), 0);
    }

    #[test]
    fn parked_payload_round_trips_and_executes_once() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Freetext {
                prompt: "why?".into(),
                masked: false,
            }],
        };
        let payload = InterruptParkPayload {
            tool: "bash".into(),
            args: serde_json::json!({ "command": "echo yes" }),
            call_id: "call-1".into(),
            resume: InterruptResumeAnchor {
                agent_id: "builder".into(),
                call_id: "call-1".into(),
                provider_call_id: Some("provider-call-1".into()),
                assistant_seq: Some(42),
                call_origin: InterruptCallOrigin::BackgroundReview,
            },
        };
        let iid = db
            .raise_interrupt_questions_with_payload(
                s.session_id,
                "builder",
                "approval",
                &set,
                Some(&payload),
            )
            .unwrap();

        let row = db.get_interrupt(iid).unwrap().unwrap();
        assert_eq!(row.state, InterruptState::Open);
        assert_eq!(row.parked.as_ref(), Some(&payload));

        assert!(db.park_interrupt(iid).unwrap());
        assert!(!db.park_interrupt(iid).unwrap());
        assert!(
            db.resolve_interrupt(iid, &ResolveResponse::Freetext { text: "no".into() })
                .is_err()
        );

        assert!(
            db.begin_parked_interrupt_execution(
                iid,
                &ResolveResponse::Freetext { text: "yes".into() },
            )
            .unwrap()
        );
        assert!(
            !db.begin_parked_interrupt_execution(
                iid,
                &ResolveResponse::Freetext {
                    text: "again".into()
                },
            )
            .unwrap()
        );
        let executing = db.get_interrupt(iid).unwrap().unwrap();
        assert_eq!(executing.state, InterruptState::Executing);
        assert!(matches!(
            executing.response,
            Some(ResolveResponse::Freetext { ref text }) if text == "yes"
        ));

        assert!(db.complete_executing_interrupt(iid).unwrap());
        assert!(!db.complete_executing_interrupt(iid).unwrap());
        let resolved = db.get_interrupt(iid).unwrap().unwrap();
        assert_eq!(resolved.state, InterruptState::Resolved);
        assert!(resolved.resolved_at.is_some());
    }

    #[test]
    fn executing_interrupt_can_be_marked_interrupted_and_reconciled() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Freetext {
                prompt: "why?".into(),
                masked: false,
            }],
        };
        let payload = InterruptParkPayload {
            tool: "bash".into(),
            args: serde_json::json!({ "command": "echo yes" }),
            call_id: "call-1".into(),
            resume: InterruptResumeAnchor {
                agent_id: "builder".into(),
                call_id: "call-1".into(),
                provider_call_id: None,
                assistant_seq: Some(42),
                call_origin: InterruptCallOrigin::Foreground,
            },
        };
        let iid = db
            .raise_interrupt_questions_with_payload(
                s.session_id,
                "builder",
                "approval",
                &set,
                Some(&payload),
            )
            .unwrap();

        assert!(db.park_interrupt(iid).unwrap());
        assert!(
            db.begin_parked_interrupt_execution(
                iid,
                &ResolveResponse::Freetext { text: "yes".into() },
            )
            .unwrap()
        );
        let reconcilable = db.list_reconcilable_interrupts(s.session_id).unwrap();
        assert_eq!(reconcilable.len(), 1);
        assert_eq!(reconcilable[0].state, InterruptState::Executing);

        assert!(db.mark_interrupt_interrupted(iid).unwrap());
        let row = db.get_interrupt(iid).unwrap().unwrap();
        assert_eq!(row.state, InterruptState::Interrupted);
        assert!(!db.complete_executing_interrupt(iid).unwrap());
    }

    #[test]
    fn interrupted_markers_are_acknowledged_after_forward_progress() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let iid = db
            .raise_interrupted_turn(s.session_id, "builder", "forced drain")
            .unwrap();

        assert_eq!(db.acknowledge_interrupted_turns(s.session_id).unwrap(), 1);
        let row = db.get_interrupt(iid).unwrap().unwrap();
        assert_eq!(row.state, InterruptState::Resolved);
        assert!(row.resolved_at.is_some());
        assert_eq!(db.acknowledge_interrupted_turns(s.session_id).unwrap(), 0);
    }

    #[test]
    fn double_resolve_errors() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let iid = db
            .raise_interrupt(s.session_id, "builder", "x", None)
            .unwrap();
        db.resolve_interrupt(iid, &ResolveResponse::Freetext { text: "ok".into() })
            .unwrap();
        assert!(
            db.resolve_interrupt(iid, &ResolveResponse::Freetext { text: "ok".into() },)
                .is_err()
        );
    }
}
