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
use uuid::Uuid;

use crate::daemon::proto::{InterruptQuestion, InterruptQuestionSet, ResolveResponse};
use crate::db::Db;

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
    pub fn raise_interrupt_questions(
        &self,
        session_id: Uuid,
        agent_id: &str,
        description: &str,
        questions: &InterruptQuestionSet,
    ) -> Result<Uuid> {
        let interrupt_id = Uuid::new_v4();
        let raised_at = Utc::now().timestamp();
        let questions_json = serde_json::to_string(questions).context("serializing questions")?;
        let agent_id = agent_id.to_owned();
        let description = description.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO needs_attention
                 (interrupt_id, session_id, agent_id, description, questions_json, raised_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    interrupt_id.to_string(),
                    session_id.to_string(),
                    agent_id,
                    description,
                    questions_json,
                    raised_at,
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
                        SET resolved_at = ?1, response_json = ?2
                      WHERE interrupt_id = ?3 AND resolved_at IS NULL",
                    params![now, response_json, interrupt_id.to_string()],
                )
                .context("resolving needs_attention")?;
            if affected == 0 {
                anyhow::bail!("interrupt {interrupt_id} not found or already resolved");
            }
            Ok(())
        })
    }

    #[allow(dead_code)]
    pub fn list_open_interrupts(&self, session_id: Uuid) -> Result<Vec<NeedsAttentionRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT interrupt_id, session_id, agent_id, description,
                            question_json, questions_json, raised_at, resolved_at, response_json
                       FROM needs_attention
                      WHERE session_id = ?1 AND resolved_at IS NULL
                      ORDER BY raised_at ASC",
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

    pub fn get_interrupt(&self, interrupt_id: Uuid) -> Result<Option<NeedsAttentionRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT interrupt_id, session_id, agent_id, description,
                            question_json, questions_json, raised_at, resolved_at, response_json
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::proto::{
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
                },
                InterruptOption {
                    id: "n".into(),
                    label: "no".into(),
                    description: None,
                },
            ],
            allow_freetext: true,
            command_detail: None,
            permission: false,
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
                    }],
                    allow_freetext: true,
                    command_detail: None,
                    permission: false,
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
