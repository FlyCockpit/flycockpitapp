//! Durable write-ahead intents for crash-interrupted tool execution.

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{Db, WriterGenerationFenced};
use crate::db::wire::{InterruptOption, InterruptQuestion};

pub(crate) fn advance_writer_generation(conn: &Connection, generation: u64) -> Result<()> {
    ensure!(
        generation > 0,
        "supervised writer generation must be nonzero"
    );
    let generation_i64 = i64::try_from(generation).context("writer generation overflow")?;
    let affected = conn
        .execute(
            "INSERT INTO worker_generation_fence(singleton, generation) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation
             WHERE worker_generation_fence.generation < excluded.generation",
            [generation_i64],
        )
        .context("advancing durable worker generation fence")?;
    if affected == 1 {
        return Ok(());
    }
    let current: i64 = conn.query_row(
        "SELECT generation FROM worker_generation_fence WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    Err(WriterGenerationFenced {
        attempted: generation,
        current: u64::try_from(current).context("negative durable writer generation")?,
    }
    .into())
}

pub(crate) fn verify_writer_generation(conn: &Connection, attempted: u64) -> Result<()> {
    let current: i64 = conn
        .query_row(
            "SELECT generation FROM worker_generation_fence WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .context("reading durable worker generation fence")?;
    let current = u64::try_from(current).context("negative durable writer generation")?;
    if current == attempted {
        Ok(())
    } else {
        Err(WriterGenerationFenced { attempted, current }.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolIdempotency {
    Idempotent,
    IdempotentWithKey,
    NotIdempotent,
}

impl ToolIdempotency {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idempotent => "idempotent",
            Self::IdempotentWithKey => "idempotent_with_key",
            Self::NotIdempotent => "not_idempotent",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "idempotent" => Ok(Self::Idempotent),
            "idempotent_with_key" => Ok(Self::IdempotentWithKey),
            "not_idempotent" => Ok(Self::NotIdempotent),
            other => anyhow::bail!("unknown tool idempotency `{other}`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolExecutionIntent {
    pub intent_id: Uuid,
    pub session_id: Uuid,
    pub marker: i64,
    pub call_id: String,
    pub tool: String,
    pub args_hash: String,
    pub args: Value,
    pub generation: u64,
    pub idempotency: ToolIdempotency,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BeginToolExecutionIntent {
    pub session_id: Uuid,
    pub call_id: String,
    pub tool: String,
    pub args: Value,
    pub generation: u64,
    pub idempotency: ToolIdempotency,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ToolRecoveryResolution {
    Inspect,
    Skip,
    Rerun(Box<ToolExecutionIntent>),
}

impl Db {
    /// Fence the actual host/external effect, not only its later SQLite result.
    /// Unsupervised and in-memory handles have no overlapping generation and
    /// therefore need no guard.
    pub async fn enter_tool_effect_generation(
        &self,
    ) -> Result<Option<super::ToolEffectGenerationGuard<'_>>> {
        let Some(fence) = self.supervised_fence.as_ref() else {
            return Ok(None);
        };
        let guard = fence.lock.lock()?;
        let generation = fence.generation;
        self.read(move |conn| verify_writer_generation(conn, generation))
            .await?;
        Ok(Some(super::ToolEffectGenerationGuard { _guard: guard }))
    }

    /// Commit the intent before the caller crosses the tool's effect boundary.
    pub async fn begin_tool_execution_intent(
        &self,
        input: BeginToolExecutionIntent,
    ) -> Result<ToolExecutionIntent> {
        let args_json =
            serde_json::to_string(&input.args).context("serializing tool intent args")?;
        let args_hash = Sha256::digest(args_json.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let intent_id = Uuid::new_v4();
        let opened_at = Utc::now().timestamp_millis();
        self.transaction(move |conn| {
            let marker: i64 = conn
                .query_row(
                    "SELECT handover_boundary FROM sessions WHERE session_id=?1",
                    [input.session_id.to_string()],
                    |row| row.get(0),
                )
                .context("reading tool intent boundary marker")?;
            ensure!(
                input.idempotency_key.is_some()
                    == (input.idempotency == ToolIdempotency::IdempotentWithKey),
                "tool intent key does not match its idempotency class"
            );
            conn.execute(
                "INSERT INTO tool_execution_intents
                 (intent_id, session_id, marker, call_id, tool, args_hash, args_json,
                  generation, idempotency, idempotency_key, opened_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(session_id, call_id) DO NOTHING",
                params![
                    intent_id.to_string(),
                    input.session_id.to_string(),
                    marker,
                    &input.call_id,
                    &input.tool,
                    &args_hash,
                    &args_json,
                    i64::try_from(input.generation).context("tool intent generation overflow")?,
                    input.idempotency.as_str(),
                    input.idempotency_key.as_deref(),
                    opened_at,
                ],
            )
            .context("inserting tool execution intent")?;
            let mut intent = load_for_call_conn(conn, input.session_id, &input.call_id)?
                .context("tool execution intent disappeared after insert")?;
            ensure!(
                intent.tool == input.tool
                    && intent.args_hash == args_hash
                    && intent.idempotency == input.idempotency
                    && intent.idempotency_key == input.idempotency_key,
                "tool call id was reused with different recovery proof"
            );
            if intent.generation < input.generation
                && intent.idempotency != ToolIdempotency::NotIdempotent
            {
                let changed = conn.execute(
                    "UPDATE tool_execution_intents SET generation=?3
                      WHERE session_id=?1 AND call_id=?2 AND generation=?4",
                    params![
                        input.session_id.to_string(),
                        &input.call_id,
                        i64::try_from(input.generation)?,
                        i64::try_from(intent.generation)?,
                    ],
                )?;
                ensure!(changed == 1, "tool recovery intent generation claim raced");
                intent.generation = input.generation;
            }
            ensure!(
                intent.generation == input.generation,
                "tool recovery intent belongs to a different worker generation"
            );
            Ok(intent)
        })
        .await
    }

    pub async fn list_open_tool_execution_intents(&self) -> Result<Vec<ToolExecutionIntent>> {
        self.read(|conn| {
            let mut statement = conn.prepare(
                "SELECT intent_id, session_id, marker, call_id, tool, args_hash, args_json,
                        generation, idempotency, idempotency_key
                   FROM tool_execution_intents
                  ORDER BY session_id, marker, intent_id",
            )?;
            let rows = statement.query_map([], decode_intent)?;
            rows.map(|row| row?.try_into()).collect()
        })
        .await
    }

    /// Calls whose pairing is still owned by replay or a recovery decision.
    pub fn open_tool_execution_call_ids_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<std::collections::HashSet<String>> {
        let mut statement =
            conn.prepare("SELECT call_id FROM tool_execution_intents WHERE session_id=?1")?;
        let rows = statement.query_map([session_id.to_string()], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<_>>().map_err(Into::into)
    }

    pub async fn tool_execution_intent_for_call(
        &self,
        session_id: Uuid,
        call_id: String,
    ) -> Result<Option<ToolExecutionIntent>> {
        self.read(move |conn| load_for_call_conn(conn, session_id, &call_id))
            .await
    }

    /// Queue the one durable user decision for an ambiguous host effect. The
    /// intent id is also the interrupt id, making retries naturally idempotent.
    pub async fn queue_tool_recovery_decision(&self, intent: &ToolExecutionIntent) -> Result<Uuid> {
        ensure!(
            intent.idempotency == ToolIdempotency::NotIdempotent,
            "only non-idempotent tool intents require a user decision"
        );
        let interrupt_id = intent.intent_id;
        let question = InterruptQuestion::Single {
            prompt: "This command may have partially run: rerun / skip / inspect".to_string(),
            options: vec![
                InterruptOption {
                    id: "rerun".to_string(),
                    label: "Rerun".to_string(),
                    description: Some(
                        "Run the command again despite the ambiguous prior effect.".to_string(),
                    ),
                    secondary: false,
                },
                InterruptOption {
                    id: "skip".to_string(),
                    label: "Skip".to_string(),
                    description: Some(
                        "Treat the interrupted command as complete without rerunning it."
                            .to_string(),
                    ),
                    secondary: false,
                },
                InterruptOption {
                    id: "inspect".to_string(),
                    label: "Inspect".to_string(),
                    description: Some(
                        "Inspect the session before choosing whether to rerun.".to_string(),
                    ),
                    secondary: true,
                },
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let question_json = serde_json::to_string(&question)?;
        let session_id = intent.session_id;
        let tool = intent.tool.clone();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO needs_attention
                 (interrupt_id, session_id, recovery_intent_id, agent_id, description,
                  state, question_json, raised_at)
                VALUES (?1, ?2, ?3, 'recovery', ?4, 'open', ?5, ?6)
                 ON CONFLICT(recovery_intent_id) DO UPDATE SET
                    state='open', resolved_at=NULL, response_json=NULL
                  WHERE needs_attention.state IN ('executing', 'interrupted', 'resolved')",
                params![
                    interrupt_id.to_string(),
                    session_id.to_string(),
                    interrupt_id.to_string(),
                    format!("Recovery decision for `{tool}`"),
                    question_json,
                    Utc::now().timestamp(),
                ],
            )?;
            Ok(())
        })
        .await?;
        Ok(interrupt_id)
    }

    /// Apply a recovery answer at the durable intent/interrupt authority.
    /// `inspect` deliberately leaves both records open. `skip` resolves and
    /// closes them atomically. `rerun` claims the intent for this generation
    /// and marks the prompt executing until the driver reports completion.
    pub async fn begin_tool_recovery_resolution(
        &self,
        interrupt_id: Uuid,
        response: &crate::db::wire::ResolveResponse,
        generation: u64,
    ) -> Result<Option<ToolRecoveryResolution>> {
        let selected_id = match response {
            crate::db::wire::ResolveResponse::Single { selected_id } => selected_id.clone(),
            _ => return Ok(None),
        };
        if !matches!(selected_id.as_str(), "rerun" | "skip" | "inspect") {
            return Ok(None);
        }
        let response_json = serde_json::to_string(response)?;
        self.transaction(move |conn| {
            let recovery_intent_id: Option<String> = conn
                .query_row(
                    "SELECT recovery_intent_id FROM needs_attention
                      WHERE interrupt_id=?1 AND state='open'",
                    [interrupt_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            let Some(recovery_intent_id) = recovery_intent_id else {
                return Ok(None);
            };
            ensure!(
                recovery_intent_id == interrupt_id.to_string(),
                "recovery interrupt is not bound to its intent id"
            );
            let mut intent = load_for_intent_conn(conn, interrupt_id)?
                .context("recovery interrupt has no open tool intent")?;
            ensure!(
                intent.idempotency == ToolIdempotency::NotIdempotent,
                "recovery answer targets a replay-safe intent"
            );
            match selected_id.as_str() {
                "inspect" => Ok(Some(ToolRecoveryResolution::Inspect)),
                "skip" => {
                    let now = Utc::now().timestamp();
                    conn.execute(
                        "UPDATE needs_attention SET state='resolved', resolved_at=?2,
                                recovery_intent_id=NULL, response_json=?3
                          WHERE interrupt_id=?1 AND state='open'",
                        params![interrupt_id.to_string(), now, response_json],
                    )?;
                    conn.execute(
                        "DELETE FROM tool_execution_intents WHERE intent_id=?1",
                        [interrupt_id.to_string()],
                    )?;
                    Ok(Some(ToolRecoveryResolution::Skip))
                }
                "rerun" => {
                    let changed = conn.execute(
                        "UPDATE tool_execution_intents SET generation=?2
                          WHERE intent_id=?1 AND generation<=?2",
                        params![interrupt_id.to_string(), i64::try_from(generation)?],
                    )?;
                    ensure!(changed == 1, "recovery rerun generation claim raced");
                    conn.execute(
                        "UPDATE needs_attention SET state='executing', response_json=?2
                          WHERE interrupt_id=?1 AND state='open'",
                        params![interrupt_id.to_string(), response_json],
                    )?;
                    intent.generation = generation;
                    Ok(Some(ToolRecoveryResolution::Rerun(Box::new(intent))))
                }
                _ => unreachable!(),
            }
        })
        .await
    }

    pub async fn finish_tool_recovery_rerun(
        &self,
        interrupt_id: Uuid,
        succeeded: bool,
    ) -> Result<()> {
        self.transaction(move |conn| {
            if succeeded {
                let remains: Option<i64> = conn
                    .query_row(
                        "SELECT 1 FROM tool_execution_intents WHERE intent_id=?1",
                        [interrupt_id.to_string()],
                        |row| row.get(0),
                    )
                    .optional()?;
                ensure!(
                    remains.is_none(),
                    "recovery rerun did not commit its tool result"
                );
                conn.execute(
                    "UPDATE needs_attention SET state='resolved', resolved_at=?2
                      WHERE interrupt_id=?1 AND state='executing'",
                    params![interrupt_id.to_string(), Utc::now().timestamp()],
                )?;
            } else {
                conn.execute(
                    "UPDATE needs_attention SET state='open', response_json=NULL
                      WHERE interrupt_id=?1 AND state='executing'",
                    [interrupt_id.to_string()],
                )?;
            }
            Ok(())
        })
        .await
    }

    pub async fn sessions_with_pending_tool_recovery(&self) -> Result<Vec<Uuid>> {
        self.read(|conn| {
            let mut statement = conn.prepare(
                "SELECT DISTINCT session_id FROM needs_attention
                  WHERE recovery_intent_id IS NOT NULL AND state IN ('open', 'parked')
                  ORDER BY session_id",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.map(|row| Uuid::parse_str(&row?).context("parsing pending recovery session id"))
                .collect()
        })
        .await
    }

    pub(crate) fn close_tool_execution_intent_for_result_conn(
        conn: &Connection,
        session_id: Uuid,
        call_id: &str,
    ) -> Result<()> {
        // Preserve the answer receipt and settle it in the result transaction.
        // Detach before deleting the intent: a crash between result commit and
        // worker notification must neither erase the receipt nor reopen it.
        conn.execute(
            "UPDATE needs_attention SET state='resolved', resolved_at=?3,
                    recovery_intent_id=NULL
              WHERE recovery_intent_id IN (
                  SELECT intent_id FROM tool_execution_intents
                   WHERE session_id=?1 AND call_id=?2)",
            params![session_id.to_string(), call_id, Utc::now().timestamp()],
        )?;
        conn.execute(
            "DELETE FROM tool_execution_intents WHERE session_id=?1 AND call_id=?2",
            params![session_id.to_string(), call_id],
        )
        .context("closing tool execution intent with result")?;
        Ok(())
    }
}

fn load_for_call_conn(
    conn: &Connection,
    session_id: Uuid,
    call_id: &str,
) -> Result<Option<ToolExecutionIntent>> {
    conn.query_row(
        "SELECT intent_id, session_id, marker, call_id, tool, args_hash, args_json,
                generation, idempotency, idempotency_key
           FROM tool_execution_intents WHERE session_id=?1 AND call_id=?2",
        params![session_id.to_string(), call_id],
        decode_intent,
    )
    .optional()?
    .map(TryInto::try_into)
    .transpose()
}

fn load_for_intent_conn(conn: &Connection, intent_id: Uuid) -> Result<Option<ToolExecutionIntent>> {
    conn.query_row(
        "SELECT intent_id, session_id, marker, call_id, tool, args_hash, args_json,
                generation, idempotency, idempotency_key
           FROM tool_execution_intents WHERE intent_id=?1",
        [intent_id.to_string()],
        decode_intent,
    )
    .optional()?
    .map(TryInto::try_into)
    .transpose()
}

struct RawIntent {
    intent_id: String,
    session_id: String,
    marker: i64,
    call_id: String,
    tool: String,
    args_hash: String,
    args_json: String,
    generation: i64,
    idempotency: String,
    idempotency_key: Option<String>,
}

fn decode_intent(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawIntent> {
    Ok(RawIntent {
        intent_id: row.get(0)?,
        session_id: row.get(1)?,
        marker: row.get(2)?,
        call_id: row.get(3)?,
        tool: row.get(4)?,
        args_hash: row.get(5)?,
        args_json: row.get(6)?,
        generation: row.get(7)?,
        idempotency: row.get(8)?,
        idempotency_key: row.get(9)?,
    })
}

impl TryFrom<RawIntent> for ToolExecutionIntent {
    type Error = anyhow::Error;

    fn try_from(raw: RawIntent) -> Result<Self> {
        Ok(Self {
            intent_id: Uuid::parse_str(&raw.intent_id).context("parsing tool intent id")?,
            session_id: Uuid::parse_str(&raw.session_id).context("parsing tool intent session")?,
            marker: raw.marker,
            call_id: raw.call_id,
            tool: raw.tool,
            args_hash: raw.args_hash,
            args: serde_json::from_str(&raw.args_json).context("parsing tool intent args")?,
            generation: u64::try_from(raw.generation).context("negative tool intent generation")?,
            idempotency: ToolIdempotency::parse(&raw.idempotency)?,
            idempotency_key: raw.idempotency_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[cfg(unix)]
    const CRASH_MATRIX_PROCESS_TEST: &str =
        "db::tool_recovery::tests::crash_matrix_kills_worker_process_at_each_boundary";

    async fn session(db: &Db) -> Uuid {
        db.create_session("project", "/workspace", "pilot")
            .await
            .unwrap()
            .session_id
    }

    fn begin(session_id: Uuid, call_id: &str, class: ToolIdempotency) -> BeginToolExecutionIntent {
        BeginToolExecutionIntent {
            session_id,
            call_id: call_id.to_string(),
            tool: "fake_side_effect".to_string(),
            args: serde_json::json!({"value": 1}),
            generation: 1,
            idempotency: class,
            idempotency_key: (class == ToolIdempotency::IdempotentWithKey)
                .then(|| format!("key-{call_id}")),
        }
    }

    #[tokio::test]
    async fn write_ahead_intent_is_durable_and_result_close_is_atomic() {
        let db = Db::open_in_memory().unwrap();
        let session_id = session(&db).await;
        let intent = db
            .begin_tool_execution_intent(begin(session_id, "call-1", ToolIdempotency::Idempotent))
            .await
            .unwrap();

        let open = db.list_open_tool_execution_intents().await.unwrap();
        assert_eq!(open, vec![intent.clone()]);
        assert_eq!(intent.marker, 0);
        assert_eq!(intent.args_hash.len(), 64);

        let rollback = db
            .transaction(move |conn| -> Result<()> {
                Db::close_tool_execution_intent_for_result_conn(conn, session_id, "call-1")?;
                anyhow::bail!("simulated result commit crash")
            })
            .await;
        assert!(rollback.is_err());
        assert_eq!(
            db.list_open_tool_execution_intents().await.unwrap().len(),
            1
        );

        db.transaction(move |conn| {
            conn.execute(
                "INSERT INTO app_flags(key, seen_at) VALUES ('result-call-1', 1)",
                [],
            )?;
            Db::close_tool_execution_intent_for_result_conn(conn, session_id, "call-1")
        })
        .await
        .unwrap();
        assert!(
            db.list_open_tool_execution_intents()
                .await
                .unwrap()
                .is_empty()
        );
        let committed: i64 = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT seen_at FROM app_flags WHERE key='result-call-1'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(committed, 1);
    }

    #[tokio::test]
    async fn recovery_answers_inspect_skip_and_rerun_change_the_durable_intent() {
        use crate::db::wire::ResolveResponse;

        let db = Db::open_in_memory().unwrap();
        let session_id = session(&db).await;

        let inspect = db
            .begin_tool_execution_intent(begin(
                session_id,
                "inspect-call",
                ToolIdempotency::NotIdempotent,
            ))
            .await
            .unwrap();
        db.queue_tool_recovery_decision(&inspect).await.unwrap();
        assert_eq!(
            db.begin_tool_recovery_resolution(
                inspect.intent_id,
                &ResolveResponse::Single {
                    selected_id: "inspect".into(),
                },
                2,
            )
            .await
            .unwrap(),
            Some(ToolRecoveryResolution::Inspect)
        );
        assert!(
            db.tool_execution_intent_for_call(session_id, "inspect-call".into())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            db.sessions_with_pending_tool_recovery().await.unwrap(),
            vec![session_id]
        );

        let skipped = db
            .begin_tool_execution_intent(begin(
                session_id,
                "skip-call",
                ToolIdempotency::NotIdempotent,
            ))
            .await
            .unwrap();
        db.queue_tool_recovery_decision(&skipped).await.unwrap();
        assert_eq!(
            db.begin_tool_recovery_resolution(
                skipped.intent_id,
                &ResolveResponse::Single {
                    selected_id: "skip".into(),
                },
                2,
            )
            .await
            .unwrap(),
            Some(ToolRecoveryResolution::Skip)
        );
        assert!(
            db.tool_execution_intent_for_call(session_id, "skip-call".into())
                .await
                .unwrap()
                .is_none()
        );

        let skip_receipt = db.get_interrupt(skipped.intent_id).await.unwrap().unwrap();
        assert_eq!(
            skip_receipt.state,
            crate::db::needs_attention::InterruptState::Resolved
        );
        assert_eq!(
            skip_receipt.response,
            Some(ResolveResponse::Single {
                selected_id: "skip".into()
            })
        );

        let rerun = db
            .begin_tool_execution_intent(begin(
                session_id,
                "rerun-call",
                ToolIdempotency::NotIdempotent,
            ))
            .await
            .unwrap();
        db.queue_tool_recovery_decision(&rerun).await.unwrap();
        let resolution = db
            .begin_tool_recovery_resolution(
                rerun.intent_id,
                &ResolveResponse::Single {
                    selected_id: "rerun".into(),
                },
                2,
            )
            .await
            .unwrap();
        let Some(ToolRecoveryResolution::Rerun(claimed)) = resolution else {
            panic!("rerun was not claimed");
        };
        assert_eq!(claimed.generation, 2);
        assert_eq!(
            db.get_interrupt(rerun.intent_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            crate::db::needs_attention::InterruptState::Executing
        );
        db.finish_tool_recovery_rerun(rerun.intent_id, false)
            .await
            .unwrap();
        assert_eq!(
            db.sessions_with_pending_tool_recovery().await.unwrap(),
            vec![session_id]
        );
        let response = ResolveResponse::Single {
            selected_id: "rerun".into(),
        };
        assert!(matches!(
            db.begin_tool_recovery_resolution(rerun.intent_id, &response, 2)
                .await
                .unwrap(),
            Some(ToolRecoveryResolution::Rerun(_))
        ));
        let rolled_back = db
            .transaction(move |conn| -> Result<()> {
                Db::close_tool_execution_intent_for_result_conn(conn, session_id, "rerun-call")?;
                anyhow::bail!("result transaction rollback");
            })
            .await;
        assert!(rolled_back.is_err());
        assert_eq!(
            db.get_interrupt(rerun.intent_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            crate::db::needs_attention::InterruptState::Executing
        );
        assert!(
            db.tool_execution_intent_for_call(session_id, "rerun-call".into())
                .await
                .unwrap()
                .is_some()
        );
        db.transaction(move |conn| {
            Db::close_tool_execution_intent_for_result_conn(conn, session_id, "rerun-call")
        })
        .await
        .unwrap();
        // Simulate a crash before the worker calls finish: the committed result
        // has already settled the decision and preserved its answer.
        let receipt = db.get_interrupt(rerun.intent_id).await.unwrap().unwrap();
        assert_eq!(
            receipt.state,
            crate::db::needs_attention::InterruptState::Resolved
        );
        assert_eq!(receipt.response, Some(response));
        assert!(receipt.resolved_at.is_some());
        assert!(
            db.tool_execution_intent_for_call(session_id, "rerun-call".into())
                .await
                .unwrap()
                .is_none()
        );
        db.finish_tool_recovery_rerun(rerun.intent_id, false)
            .await
            .unwrap();
        db.finish_tool_recovery_rerun(rerun.intent_id, true)
            .await
            .unwrap();
        assert_eq!(
            db.get_interrupt(rerun.intent_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            crate::db::needs_attention::InterruptState::Resolved
        );
    }

    #[tokio::test]
    async fn stale_writer_generation_is_rejected_and_successor_row_wins() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fenced.db");
        let predecessor = Db::open_supervised_worker_for_test(&path, 1).unwrap();
        predecessor
            .write(|conn| {
                conn.execute(
                    "INSERT INTO app_flags(key, seen_at) VALUES ('owner', 1)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let predecessor_job_db = predecessor.clone();
        let predecessor_job = tokio::spawn(async move {
            predecessor_job_db
                .write(move |conn| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    conn.execute("UPDATE app_flags SET seen_at=11 WHERE key='owner'", [])?;
                    Ok(())
                })
                .await
        });
        tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
            .await
            .unwrap();

        let successor_path = path.clone();
        let (successor_tx, successor_rx) = std::sync::mpsc::sync_channel(0);
        let successor_open = std::thread::spawn(move || {
            successor_tx
                .send(Db::open_supervised_worker_for_test(&successor_path, 2))
                .unwrap();
        });
        assert!(matches!(
            successor_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        release_tx.send(()).unwrap();
        predecessor_job.await.unwrap().unwrap();
        let successor = successor_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .unwrap();
        successor_open.join().unwrap();
        let predecessor_commit: i64 = successor
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT seen_at FROM app_flags WHERE key='owner'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(predecessor_commit, 11);

        let stale = predecessor
            .write(|conn| {
                conn.execute("UPDATE app_flags SET seen_at=33 WHERE key='owner'", [])?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(
            stale
                .downcast_ref::<super::super::WriterGenerationFenced>()
                .is_some()
        );

        successor
            .write(|conn| {
                conn.execute("UPDATE app_flags SET seen_at=22 WHERE key='owner'", [])?;
                Ok(())
            })
            .await
            .unwrap();
        let winner: i64 = successor
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT seen_at FROM app_flags WHERE key='owner'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(winner, 22);
    }

    #[tokio::test]
    async fn tool_effect_generation_blocks_successor_and_allows_nested_db_writes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cockpit.db");
        let predecessor = Db::open_supervised_worker_for_test(&path, 1).unwrap();
        let session_id = session(&predecessor).await;
        let guard = predecessor
            .enter_tool_effect_generation()
            .await
            .unwrap()
            .unwrap();

        predecessor
            .begin_tool_execution_intent(begin(
                session_id,
                "nested-write",
                ToolIdempotency::NotIdempotent,
            ))
            .await
            .unwrap();

        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let successor_path = path.clone();
        let successor = std::thread::spawn(move || {
            let opened = Db::open_supervised_worker_for_test(&successor_path, 2);
            tx.send(opened).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "successor advanced while predecessor effect guard was live"
        );
        drop(guard);
        let successor_db = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .unwrap();
        successor.join().unwrap();
        drop(successor_db);

        let error = predecessor
            .begin_tool_execution_intent(begin(
                session_id,
                "stale-write",
                ToolIdempotency::NotIdempotent,
            ))
            .await
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<super::super::WriterGenerationFenced>()
                .is_some()
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum CrashPoint {
        BeforeIntent,
        AfterIntent,
        AfterResultBeforeCommit,
    }

    #[derive(Default)]
    struct FakeSideEffectingTool {
        counter: usize,
        receipts: HashSet<String>,
    }

    impl FakeSideEffectingTool {
        fn call(&mut self, class: ToolIdempotency, key: Option<&str>) {
            let receipt = match class {
                ToolIdempotency::Idempotent => "semantic-value-1",
                ToolIdempotency::IdempotentWithKey => key.expect("keyed call has key"),
                ToolIdempotency::NotIdempotent => {
                    self.counter += 1;
                    return;
                }
            };
            if self.receipts.insert(receipt.to_string()) {
                self.counter += 1;
            }
        }
    }

    #[cfg(unix)]
    async fn record_persistent_fake_effect(db: &Db, class: ToolIdempotency, key: Option<&str>) {
        let receipt = match class {
            ToolIdempotency::Idempotent => "semantic-value-1".to_string(),
            ToolIdempotency::IdempotentWithKey => key.expect("keyed call has key").to_string(),
            ToolIdempotency::NotIdempotent => "not-idempotent-counter".to_string(),
        };
        db.write(move |conn| {
            match class {
                ToolIdempotency::Idempotent | ToolIdempotency::IdempotentWithKey => {
                    conn.execute(
                        "INSERT INTO app_flags(key, seen_at) VALUES (?1, 1)
                         ON CONFLICT(key) DO NOTHING",
                        [receipt],
                    )?;
                }
                ToolIdempotency::NotIdempotent => {
                    conn.execute(
                        "INSERT INTO app_flags(key, seen_at) VALUES (?1, 1)
                         ON CONFLICT(key) DO UPDATE SET seen_at=seen_at+1",
                        [receipt],
                    )?;
                }
            }
            Ok(())
        })
        .await
        .unwrap();
    }

    #[cfg(unix)]
    async fn persistent_fake_effect_count(
        db: &Db,
        class: ToolIdempotency,
        key: Option<&str>,
    ) -> i64 {
        let receipt = match class {
            ToolIdempotency::Idempotent => "semantic-value-1".to_string(),
            ToolIdempotency::IdempotentWithKey => key.expect("keyed call has key").to_string(),
            ToolIdempotency::NotIdempotent => "not-idempotent-counter".to_string(),
        };
        db.read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT seen_at FROM app_flags WHERE key=?1",
                    [receipt],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0))
        })
        .await
        .unwrap()
    }

    #[cfg(unix)]
    async fn run_crash_matrix_child() -> bool {
        let Ok(crash) = std::env::var("COCKPIT_441_CHILD_CRASH") else {
            return false;
        };
        let path = std::path::PathBuf::from(
            std::env::var("COCKPIT_441_CHILD_DB").expect("child database path"),
        );
        let session_id =
            Uuid::parse_str(&std::env::var("COCKPIT_441_CHILD_SESSION").expect("child session id"))
                .unwrap();
        let call_id = std::env::var("COCKPIT_441_CHILD_CALL").expect("child call id");
        let class =
            ToolIdempotency::parse(&std::env::var("COCKPIT_441_CHILD_CLASS").expect("child class"))
                .unwrap();
        let db = Db::open_supervised_worker_for_test(&path, 1).unwrap();
        if crash == "before_intent" {
            println!("RECOVERY_READY");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            std::future::pending::<()>().await;
        }
        let input = begin(session_id, &call_id, class);
        db.begin_tool_execution_intent(input.clone()).await.unwrap();
        if crash == "after_intent" {
            println!("RECOVERY_READY");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            std::future::pending::<()>().await;
        }
        record_persistent_fake_effect(&db, class, input.idempotency_key.as_deref()).await;
        println!("RECOVERY_READY");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        std::future::pending::<()>().await;
        true
    }

    #[cfg(unix)]
    async fn kill_worker_at_boundary(
        path: &std::path::Path,
        session_id: Uuid,
        call_id: &str,
        class: ToolIdempotency,
        crash: &str,
    ) {
        use std::io::BufRead;

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CRASH_MATRIX_PROCESS_TEST, "--nocapture"])
            .env("COCKPIT_441_CHILD_DB", path)
            .env("COCKPIT_441_CHILD_SESSION", session_id.to_string())
            .env("COCKPIT_441_CHILD_CALL", call_id)
            .env("COCKPIT_441_CHILD_CLASS", class.as_str())
            .env("COCKPIT_441_CHILD_CRASH", crash)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let ready = std::io::BufReader::new(stdout)
            .lines()
            .map(|line| line.unwrap())
            .find(|line| line == "RECOVERY_READY");
        assert_eq!(ready.as_deref(), Some("RECOVERY_READY"));
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success(), "worker must be terminated at {crash}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn crash_matrix_kills_worker_process_at_each_boundary() {
        if run_crash_matrix_child().await {
            return;
        }
        for class in [
            ToolIdempotency::Idempotent,
            ToolIdempotency::IdempotentWithKey,
            ToolIdempotency::NotIdempotent,
        ] {
            for crash in [
                "before_intent",
                "after_intent",
                "after_result_before_commit",
            ] {
                let temp = tempfile::tempdir().unwrap();
                let path = temp.path().join("crash-matrix.db");
                let setup = Db::open(&path).unwrap();
                let session_id = session(&setup).await;
                drop(setup);
                let call_id = format!("process-{class:?}-{crash}");
                kill_worker_at_boundary(&path, session_id, &call_id, class, crash).await;

                let successor = Db::open_supervised_worker_for_test(&path, 2).unwrap();
                let mut input = begin(session_id, &call_id, class);
                input.generation = 2;
                let intent = match successor
                    .list_open_tool_execution_intents()
                    .await
                    .unwrap()
                    .pop()
                {
                    Some(intent) => intent,
                    None => successor
                        .begin_tool_execution_intent(input.clone())
                        .await
                        .unwrap(),
                };
                match class {
                    ToolIdempotency::Idempotent | ToolIdempotency::IdempotentWithKey => {
                        successor
                            .begin_tool_execution_intent(input.clone())
                            .await
                            .unwrap();
                        record_persistent_fake_effect(
                            &successor,
                            class,
                            intent.idempotency_key.as_deref(),
                        )
                        .await;
                        successor
                            .transaction(move |conn| {
                                Db::close_tool_execution_intent_for_result_conn(
                                    conn, session_id, &call_id,
                                )
                            })
                            .await
                            .unwrap();
                        assert_eq!(
                            persistent_fake_effect_count(
                                &successor,
                                class,
                                input.idempotency_key.as_deref(),
                            )
                            .await,
                            1,
                            "{class:?} at {crash}"
                        );
                    }
                    ToolIdempotency::NotIdempotent => {
                        successor
                            .queue_tool_recovery_decision(&intent)
                            .await
                            .unwrap();
                        successor
                            .queue_tool_recovery_decision(&intent)
                            .await
                            .unwrap();
                        assert_eq!(
                            persistent_fake_effect_count(&successor, class, None).await,
                            i64::from(crash == "after_result_before_commit"),
                            "non-idempotent tool reran at {crash}"
                        );
                        assert_eq!(
                            successor
                                .list_open_interrupts(session_id)
                                .await
                                .unwrap()
                                .len(),
                            1
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn crash_matrix_replays_safe_classes_and_queues_one_ambiguous_decision() {
        for class in [
            ToolIdempotency::Idempotent,
            ToolIdempotency::IdempotentWithKey,
            ToolIdempotency::NotIdempotent,
        ] {
            for crash in [
                CrashPoint::BeforeIntent,
                CrashPoint::AfterIntent,
                CrashPoint::AfterResultBeforeCommit,
            ] {
                let db = Db::open_in_memory().unwrap();
                let session_id = session(&db).await;
                let call_id = format!("{class:?}-{crash:?}");
                let input = begin(session_id, &call_id, class);
                let mut tool = FakeSideEffectingTool::default();

                if !matches!(crash, CrashPoint::BeforeIntent) {
                    db.begin_tool_execution_intent(input.clone()).await.unwrap();
                }
                if matches!(crash, CrashPoint::AfterResultBeforeCommit) {
                    tool.call(class, input.idempotency_key.as_deref());
                }

                let intent = match db.list_open_tool_execution_intents().await.unwrap().pop() {
                    Some(intent) => intent,
                    None => db.begin_tool_execution_intent(input.clone()).await.unwrap(),
                };
                match class {
                    ToolIdempotency::Idempotent | ToolIdempotency::IdempotentWithKey => {
                        tool.call(class, intent.idempotency_key.as_deref());
                        db.transaction(move |conn| {
                            Db::close_tool_execution_intent_for_result_conn(
                                conn, session_id, &call_id,
                            )
                        })
                        .await
                        .unwrap();
                        assert_eq!(tool.counter, 1, "{class:?} at {crash:?}");
                        assert!(
                            db.list_open_tool_execution_intents()
                                .await
                                .unwrap()
                                .is_empty()
                        );
                    }
                    ToolIdempotency::NotIdempotent => {
                        db.queue_tool_recovery_decision(&intent).await.unwrap();
                        db.queue_tool_recovery_decision(&intent).await.unwrap();
                        assert_eq!(
                            tool.counter,
                            usize::from(matches!(crash, CrashPoint::AfterResultBeforeCommit))
                        );
                        assert_eq!(db.list_open_interrupts(session_id).await.unwrap().len(), 1);
                        assert_eq!(
                            db.sessions_with_pending_tool_recovery().await.unwrap(),
                            vec![session_id]
                        );
                    }
                }
            }
        }
    }
}
