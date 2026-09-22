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

impl Db {
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
                 ON CONFLICT(recovery_intent_id) DO NOTHING",
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

        let successor = Db::open_supervised_worker_for_test(&path, 2).unwrap();
        let stale = predecessor
            .write(|conn| {
                conn.execute("UPDATE app_flags SET seen_at=11 WHERE key='owner'", [])?;
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
