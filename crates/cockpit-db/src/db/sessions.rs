//! Session CRUD.
//!
//! A session is the long-lived conversation between a user and a
//! cockpit driver. Per GOALS §8b sessions outlive their TUI client —
//! TUI quit detaches, the daemon keeps the session warm, a later
//! `cockpit -c` or `cockpit --session ID` re-attaches.

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use rusqlite::{
    Connection, ErrorCode, OptionalExtension, params, params_from_iter, types::Value as SqlValue,
};
use uuid::Uuid;

use crate::db::Db;

/// Crockford base32 alphabet, lowercased. Excludes I/L/O/U for visual
/// disambiguation. Used for 6-char session display ids (GOALS §17b).
const CROCKFORD_BASE32: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Length of a session's human-display short id, in characters.
pub const SHORT_ID_LEN: usize = 6;

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub session_id: Uuid,
    pub project_id: String,
    pub project_root: String,
    pub started_at: i64,
    pub last_active_at: i64,
    pub ended_at: Option<i64>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub active_agent: String,
    /// Owning assistant for assistant-backed sessions. NULL for ordinary
    /// sessions and for historical rows.
    pub assistant_name: Option<String>,
    /// 6-char display id, unique within `project_id`. NULL for pre-§17
    /// rows until lazy backfill populates them (see [`Db::resume_session`]).
    pub short_id: Option<String>,
    /// Parent session in the fork tree. NULL = root session (GOALS §17e).
    pub parent_session_id: Option<Uuid>,
    /// Turn id in the parent at which this fork branched off. NULL for
    /// root sessions; also NULL for tail-forks until the daemon resolves
    /// the parent's last turn.
    pub fork_point_turn_id: Option<String>,
    /// Auto-generated or user-set title (GOALS §17d).
    pub title: Option<String>,
    /// `true` when the user has manually set [`title`]. Locks out the
    /// utility-model auto-titling pass.
    pub user_renamed: bool,
    /// Epoch seconds the user last opened/resumed this session in a
    /// client (migration 0010). `None` = never viewed. The browser
    /// reads a session as unread when its latest agent-produced event is
    /// newer than this marker (or it has activity and was never viewed).
    pub last_viewed_at: Option<i64>,
    /// Epoch seconds the session was archived (recoverable soft-delete,
    /// migration 0010). `None` = live. Archived sessions are hidden from
    /// the browser by default.
    pub archived_at: Option<i64>,
    /// `true` for a throwaway `/side` side-conversation fork (migration
    /// 0017) and for persistent `/btw` forks. Ephemeral sessions are
    /// excluded from every list query and never auto-titled. Legacy `/side`
    /// rows are swept on boot; `/btw` rows carry [`Self::btw_parent_session_id`]
    /// and are not swept.
    pub ephemeral: bool,
    /// Parent session for a persistent `/btw` fork. `None` for ordinary
    /// sessions, normal forks, and legacy ephemeral `/side` forks.
    pub btw_parent_session_id: Option<Uuid>,
    /// `true` when a `/btw` fork was created in tangent mode, meaning it
    /// starts with an empty transcript instead of a parent-seeded transcript.
    pub btw_tangent: bool,
    /// Running cl100k_base estimate of RAW typed user content
    /// (pre-skill-injection) this session. Migration 0037.
    pub user_content_tokens: i64,
    /// Auto-title progress (migration 0037): last consumed scheduled title
    /// slot (`0`, `1`, `2`, `4`, `8`, or `16`). Persisted so a resumed session
    /// does not repeat the same automatic utility call.
    pub title_stage: i64,
    /// Frozen guidance baseline path/hash copied into forks so live guidance
    /// diffs continue from the same system-instruction baseline.
    pub guidance_baseline_path: Option<String>,
    pub guidance_baseline_hash: Option<String>,
    pub redaction_table_json: Option<String>,
    pub model_system_prompt_snapshot_json: String,
    pub created_by_principal: Option<String>,
    pub shared_with_collaborators: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtwForkInfo {
    pub session_id: Uuid,
    pub parent_session_id: Uuid,
    pub short_id: Option<String>,
    pub tangent: bool,
    pub created_at: i64,
    pub message_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtwForkCreateResult {
    pub info: BtwForkInfo,
    pub created: bool,
}

impl SessionRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let id: String = row.get("session_id")?;
        let session_id = parse_uuid(&id)?;
        let parent_str: Option<String> = row.get("parent_session_id")?;
        let parent_session_id = match parent_str {
            Some(s) => Some(parse_uuid(&s)?),
            None => None,
        };
        let btw_parent_str: Option<String> = row.get("btw_parent_session_id").unwrap_or(None);
        let btw_parent_session_id = match btw_parent_str {
            Some(s) => Some(parse_uuid(&s)?),
            None => None,
        };
        let user_renamed: i64 = row.get("user_renamed")?;
        Ok(Self {
            session_id,
            project_id: row.get("project_id")?,
            project_root: row.get("project_root")?,
            started_at: row.get("started_at")?,
            last_active_at: row.get("last_active_at")?,
            ended_at: row.get("ended_at")?,
            provider: row.get("provider")?,
            model: row.get("model")?,
            active_agent: row.get("active_agent")?,
            assistant_name: row.get("assistant_name").unwrap_or(None),
            short_id: row.get("short_id")?,
            parent_session_id,
            fork_point_turn_id: row.get("fork_point_turn_id")?,
            title: row.get("title")?,
            user_renamed: user_renamed != 0,
            last_viewed_at: row.get("last_viewed_at")?,
            archived_at: row.get("archived_at")?,
            ephemeral: row.get::<_, i64>("ephemeral")? != 0,
            btw_parent_session_id,
            btw_tangent: row.get::<_, i64>("btw_tangent").unwrap_or(0) != 0,
            user_content_tokens: row.get("user_content_tokens")?,
            title_stage: row.get("title_stage")?,
            guidance_baseline_path: row.get("guidance_baseline_path")?,
            guidance_baseline_hash: row.get("guidance_baseline_hash")?,
            redaction_table_json: row.get("redaction_table_json")?,
            model_system_prompt_snapshot_json: row
                .get("model_system_prompt_snapshot_json")
                .unwrap_or_else(|_| "{}".to_string()),
            created_by_principal: row.get("created_by_principal")?,
            shared_with_collaborators: row.get::<_, i64>("shared_with_collaborators")? != 0,
        })
    }
}

fn parse_uuid(s: &str) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// Generate a random 6-char Crockford base32 string. Not collision-safe
/// on its own — use [`generate_unique_short_id`] for DB inserts.
fn random_short_id() -> String {
    #[cfg(test)]
    if let Some(id) = pop_test_short_id() {
        return id;
    }

    use rand::RngExt;
    let mut rng = rand::rng();
    (0..SHORT_ID_LEN)
        .map(|_| {
            let idx = rng.random_range(0..CROCKFORD_BASE32.len());
            CROCKFORD_BASE32[idx] as char
        })
        .collect()
}

#[cfg(test)]
thread_local! {
    static TEST_SHORT_IDS: std::cell::RefCell<std::collections::VecDeque<String>> =
        std::cell::RefCell::new(std::collections::VecDeque::new());
}

#[cfg(test)]
fn set_test_short_ids(ids: &[&str]) {
    TEST_SHORT_IDS.with(|queue| {
        let mut queue = queue.borrow_mut();
        queue.clear();
        queue.extend(ids.iter().map(|id| (*id).to_string()));
    });
}

#[cfg(test)]
fn pop_test_short_id() -> Option<String> {
    TEST_SHORT_IDS.with(|queue| queue.borrow_mut().pop_front())
}

/// Generate a 6-char short id that doesn't collide within `project_id`.
/// 32^6 ≈ 1.07e9 namespace; collisions are astronomically rare even at
/// hundreds of thousands of sessions per project. The retry loop is a
/// belt-and-braces guard.
fn generate_unique_short_id(conn: &Connection, project_id: &str) -> rusqlite::Result<String> {
    for _ in 0..16 {
        let candidate = random_short_id();
        let exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE project_id = ?1 AND short_id = ?2",
            params![project_id, candidate],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Ok(candidate);
        }
    }
    Err(short_id_exhausted())
}

fn short_id_exhausted() -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(
        "session short-id generation exhausted after 16 attempts".to_string(),
    )
}

fn is_constraint_violation(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(sqlite_err, _)
            if sqlite_err.code == ErrorCode::ConstraintViolation
    )
}

fn short_id_exists(conn: &Connection, project_id: &str, short_id: &str) -> rusqlite::Result<bool> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sessions WHERE project_id = ?1 AND short_id = ?2",
        params![project_id, short_id],
        |row| row.get(0),
    )?;
    Ok(exists > 0)
}

fn is_short_id_collision(conn: &Connection, err: &rusqlite::Error, row: &SessionRow) -> bool {
    if !is_constraint_violation(err) {
        return false;
    }
    row.short_id
        .as_deref()
        .and_then(|short_id| short_id_exists(conn, &row.project_id, short_id).ok())
        .unwrap_or(false)
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for name in rows {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn execute_session_insert(conn: &Connection, row: &SessionRow) -> rusqlite::Result<()> {
    let has_created_by_principal = table_has_column(conn, "sessions", "created_by_principal")?;
    let has_redaction_table = table_has_column(conn, "sessions", "redaction_table_json")?;
    let has_model_prompt_snapshot =
        table_has_column(conn, "sessions", "model_system_prompt_snapshot_json")?;
    let has_assistant_name = table_has_column(conn, "sessions", "assistant_name")?;
    match (has_created_by_principal, has_redaction_table) {
        (true, true) => {
            conn.execute(
                "INSERT INTO sessions
                 (session_id, project_id, project_root, started_at,
                  last_active_at, active_agent, short_id, provider, model,
                  guidance_baseline_path, guidance_baseline_hash, redaction_table_json,
                  created_by_principal, shared_with_collaborators)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    row.session_id.to_string(),
                    row.project_id,
                    row.project_root,
                    row.started_at,
                    row.last_active_at,
                    row.active_agent,
                    row.short_id,
                    row.provider,
                    row.model,
                    row.guidance_baseline_path,
                    row.guidance_baseline_hash,
                    row.redaction_table_json,
                    row.created_by_principal,
                    row.shared_with_collaborators as i64,
                ],
            )?;
        }
        (true, false) => {
            conn.execute(
                "INSERT INTO sessions
                 (session_id, project_id, project_root, started_at,
                  last_active_at, active_agent, short_id, provider, model,
                  guidance_baseline_path, guidance_baseline_hash, created_by_principal,
                  shared_with_collaborators)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    row.session_id.to_string(),
                    row.project_id,
                    row.project_root,
                    row.started_at,
                    row.last_active_at,
                    row.active_agent,
                    row.short_id,
                    row.provider,
                    row.model,
                    row.guidance_baseline_path,
                    row.guidance_baseline_hash,
                    row.created_by_principal,
                    row.shared_with_collaborators as i64,
                ],
            )?;
        }
        (_, true) => {
            conn.execute(
                "INSERT INTO sessions
                 (session_id, project_id, project_root, started_at,
                  last_active_at, active_agent, short_id, provider, model,
                  guidance_baseline_path, guidance_baseline_hash, redaction_table_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    row.session_id.to_string(),
                    row.project_id,
                    row.project_root,
                    row.started_at,
                    row.last_active_at,
                    row.active_agent,
                    row.short_id,
                    row.provider,
                    row.model,
                    row.guidance_baseline_path,
                    row.guidance_baseline_hash,
                    row.redaction_table_json,
                ],
            )?;
        }
        (false, false) => {
            conn.execute(
                "INSERT INTO sessions
                 (session_id, project_id, project_root, started_at,
                  last_active_at, active_agent, short_id, provider, model,
                  guidance_baseline_path, guidance_baseline_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    row.session_id.to_string(),
                    row.project_id,
                    row.project_root,
                    row.started_at,
                    row.last_active_at,
                    row.active_agent,
                    row.short_id,
                    row.provider,
                    row.model,
                    row.guidance_baseline_path,
                    row.guidance_baseline_hash,
                ],
            )?;
        }
    }
    match (has_model_prompt_snapshot, has_assistant_name) {
        (true, true) => {
            conn.execute(
                "UPDATE sessions
                    SET model_system_prompt_snapshot_json = ?1,
                        assistant_name = ?2
                  WHERE session_id = ?3",
                params![
                    row.model_system_prompt_snapshot_json,
                    row.assistant_name,
                    row.session_id.to_string(),
                ],
            )?;
        }
        (true, false) => {
            conn.execute(
                "UPDATE sessions
                    SET model_system_prompt_snapshot_json = ?1
                  WHERE session_id = ?2",
                params![
                    row.model_system_prompt_snapshot_json,
                    row.session_id.to_string(),
                ],
            )?;
        }
        (false, true) => {
            conn.execute(
                "UPDATE sessions
                    SET assistant_name = ?1
                  WHERE session_id = ?2",
                params![row.assistant_name, row.session_id.to_string()],
            )?;
        }
        (false, false) => {}
    }
    Ok(())
}

fn execute_fork_post_insert_update(conn: &Connection, row: &SessionRow) -> rusqlite::Result<()> {
    let has_model_prompt_snapshot =
        table_has_column(conn, "sessions", "model_system_prompt_snapshot_json")?;
    let has_assistant_name = table_has_column(conn, "sessions", "assistant_name")?;
    match (has_model_prompt_snapshot, has_assistant_name) {
        (true, true) => {
            conn.execute(
                "UPDATE sessions
                    SET model_system_prompt_snapshot_json = ?1,
                        assistant_name = ?2
                  WHERE session_id = ?3",
                params![
                    row.model_system_prompt_snapshot_json,
                    row.assistant_name,
                    row.session_id.to_string(),
                ],
            )?;
        }
        (true, false) => {
            conn.execute(
                "UPDATE sessions
                    SET model_system_prompt_snapshot_json = ?1
                  WHERE session_id = ?2",
                params![
                    row.model_system_prompt_snapshot_json,
                    row.session_id.to_string(),
                ],
            )?;
        }
        (false, true) => {
            conn.execute(
                "UPDATE sessions
                    SET assistant_name = ?1
                  WHERE session_id = ?2",
                params![row.assistant_name, row.session_id.to_string()],
            )?;
        }
        (false, false) => {}
    }
    Ok(())
}

fn insert_session_row_with_short_id_retry(
    conn: &Connection,
    mut row: SessionRow,
) -> rusqlite::Result<SessionRow> {
    for attempt in 0..16 {
        match execute_session_insert(conn, &row) {
            Ok(()) => return Ok(row),
            Err(err) if is_short_id_collision(conn, &err, &row) => {
                if attempt == 15 {
                    return Err(short_id_exhausted());
                }
                row.short_id = Some(generate_unique_short_id(conn, &row.project_id)?);
            }
            Err(err) => return Err(err),
        }
    }
    Err(short_id_exhausted())
}

fn execute_fork_insert(
    conn: &Connection,
    row: &SessionRow,
    fork_point_turn_id: &Option<String>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO sessions
         (session_id, project_id, project_root, started_at,
          last_active_at, active_agent, short_id,
          parent_session_id, fork_point_turn_id,
          provider, model, ephemeral, user_content_tokens, title_stage,
          guidance_baseline_path, guidance_baseline_hash, redaction_table_json, created_by_principal,
          shared_with_collaborators, btw_parent_session_id, btw_tangent)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            row.session_id.to_string(),
            row.project_id,
            row.project_root,
            row.started_at,
            row.last_active_at,
            row.active_agent,
            row.short_id,
            row.parent_session_id.map(|id| id.to_string()),
            fork_point_turn_id,
            row.provider,
            row.model,
            row.ephemeral as i64,
            row.user_content_tokens,
            row.title_stage,
            row.guidance_baseline_path,
            row.guidance_baseline_hash,
            row.redaction_table_json,
            row.created_by_principal,
            row.shared_with_collaborators as i64,
            row.btw_parent_session_id.map(|id| id.to_string()),
            row.btw_tangent as i64,
        ],
    )?;
    execute_fork_post_insert_update(conn, row)?;
    Ok(())
}

fn insert_fork_row_with_short_id_retry(
    conn: &Connection,
    mut row: SessionRow,
    fork_point_turn_id: &Option<String>,
) -> rusqlite::Result<SessionRow> {
    for attempt in 0..16 {
        match execute_fork_insert(conn, &row, fork_point_turn_id) {
            Ok(()) => return Ok(row),
            Err(err) if is_short_id_collision(conn, &err, &row) => {
                if attempt == 15 {
                    return Err(short_id_exhausted());
                }
                row.short_id = Some(generate_unique_short_id(conn, &row.project_id)?);
            }
            Err(err) => return Err(err),
        }
    }
    Err(short_id_exhausted())
}

fn backfill_short_id_with_retry(
    conn: &Connection,
    session_id: Uuid,
    project_id: &str,
) -> rusqlite::Result<String> {
    for attempt in 0..16 {
        let short_id = if attempt == 0 {
            random_short_id()
        } else {
            generate_unique_short_id(conn, project_id)?
        };
        match conn.execute(
            "UPDATE sessions SET short_id = ?1 WHERE session_id = ?2",
            params![short_id, session_id.to_string()],
        ) {
            Ok(_) => return Ok(short_id),
            Err(err)
                if is_constraint_violation(&err)
                    && short_id_exists(conn, project_id, &short_id)? =>
            {
                if attempt == 15 {
                    return Err(short_id_exhausted());
                }
            }
            Err(err) => return Err(err),
        }
    }
    Err(short_id_exhausted())
}

fn build_session_row(
    project_id: &str,
    project_root: &str,
    active_agent: &str,
    short_id: Option<String>,
    assistant_name: Option<String>,
) -> SessionRow {
    let session_id = Uuid::new_v4();
    let now = Utc::now().timestamp();
    SessionRow {
        session_id,
        project_id: project_id.to_string(),
        project_root: project_root.to_string(),
        started_at: now,
        last_active_at: now,
        ended_at: None,
        provider: None,
        model: None,
        active_agent: active_agent.to_string(),
        assistant_name,
        short_id,
        parent_session_id: None,
        fork_point_turn_id: None,
        title: None,
        user_renamed: false,
        last_viewed_at: None,
        archived_at: None,
        ephemeral: false,
        btw_parent_session_id: None,
        btw_tangent: false,
        user_content_tokens: 0,
        title_stage: 0,
        guidance_baseline_path: None,
        guidance_baseline_hash: None,
        redaction_table_json: None,
        model_system_prompt_snapshot_json: "{}".to_string(),
        created_by_principal: None,
        shared_with_collaborators: false,
    }
}

fn copy_fork_transcript(
    conn: &Connection,
    parent_session_id: Uuid,
    child_session_id: Uuid,
    fork_point_turn_id: Option<&str>,
) -> Result<()> {
    let parent = parent_session_id.to_string();
    let child = child_session_id.to_string();
    let fork_ceiling = parse_fork_point(conn, parent.as_str(), fork_point_turn_id)?;
    let mut seq_pairs = Vec::new();
    let mut surviving_call_ids = std::collections::BTreeSet::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT seq, ts_ms, type, agent, call_id, data_json
                   FROM session_events
                  WHERE session_id = ?1
                    AND (?2 IS NULL OR seq <= ?2)
                  ORDER BY seq ASC",
            )
            .context("preparing fork event copy")?;
        let rows = stmt
            .query_map(params![parent.as_str(), fork_ceiling], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .context("querying fork event copy")?;
        for row in rows {
            let (old_seq, ts_ms, kind, agent, call_id, data_json) =
                row.context("decoding fork event copy")?;
            if let Some(call_id) = call_id.as_ref() {
                surviving_call_ids.insert(call_id.clone());
            }
            conn.execute(
                "INSERT INTO session_events
                 (session_id, ts_ms, type, agent, call_id, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![child, ts_ms, kind, agent, call_id, data_json],
            )
            .context("copying fork event")?;
            seq_pairs.push((old_seq, conn.last_insert_rowid()));
        }
    }

    copy_fork_tool_calls(
        conn,
        parent.as_str(),
        child.as_str(),
        fork_ceiling,
        &surviving_call_ids,
    )?;

    for (old_seq, new_seq) in seq_pairs {
        conn.execute(
            "INSERT OR IGNORE INTO pins (session_id, seq, pinned_ms)
             SELECT ?3, ?4, pinned_ms
               FROM pins
              WHERE session_id = ?1 AND seq = ?2",
            params![parent, old_seq, child, new_seq],
        )
        .context("copying fork pins")?;
    }

    Ok(())
}

fn parse_fork_point(
    conn: &Connection,
    parent_session_id: &str,
    fork_point_turn_id: Option<&str>,
) -> Result<Option<i64>> {
    let Some(raw) = fork_point_turn_id else {
        return Ok(None);
    };
    let seq = raw
        .parse::<i64>()
        .with_context(|| format!("invalid fork point turn id {raw:?}"))?;
    let kind = conn
        .query_row(
            "SELECT type
               FROM session_events
              WHERE session_id = ?1 AND seq = ?2",
            params![parent_session_id, seq],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .context("validating fork point turn id")?;
    match kind.as_deref() {
        Some("user_message" | "assistant_message") => Ok(Some(seq)),
        Some(other) => Err(anyhow!(
            "fork point turn id {seq} is a {other} event, not a message"
        )),
        None => Err(anyhow!(
            "fork point turn id {seq} was not found in parent session"
        )),
    }
}

fn copy_fork_tool_calls(
    conn: &Connection,
    parent: &str,
    child: &str,
    fork_ceiling: Option<i64>,
    surviving_call_ids: &std::collections::BTreeSet<String>,
) -> Result<()> {
    if fork_ceiling.is_some() && surviving_call_ids.is_empty() {
        return Ok(());
    }
    let mut sql = String::from(
        "INSERT INTO tool_call_events (
             event_id, session_id, call_id, timestamp,
             provider_item_id, provider_call_id, provider_call_id_source,
             wire_api, provider_family,
             model, provider, project_id, project_root,
             agent, tool, path, language,
             recovery_kind, recovery_stage, hard_fail,
             exit_code, sandbox_enabled, sandboxed, sandbox_unavailable_reason,
             original_input_json, wire_input_json,
             output, truncated, duration_ms,
             cockpit_version, llm_mode, shape_fingerprint, hint
         )
         SELECT lower(hex(randomblob(16))), ?2, call_id, timestamp,
                provider_item_id, provider_call_id, provider_call_id_source,
                wire_api, provider_family,
                model, provider, project_id, project_root,
                agent, tool, path, language,
                recovery_kind, recovery_stage, hard_fail,
                exit_code, sandbox_enabled, sandboxed, sandbox_unavailable_reason,
                original_input_json, wire_input_json,
                output, truncated, duration_ms,
                cockpit_version, llm_mode, shape_fingerprint, hint
           FROM tool_call_events
          WHERE session_id = ?1",
    );
    let mut values = vec![
        SqlValue::Text(parent.to_string()),
        SqlValue::Text(child.to_string()),
    ];
    if fork_ceiling.is_some() {
        sql.push_str(" AND call_id IN (");
        for (i, call_id) in surviving_call_ids.iter().enumerate() {
            if i > 0 {
                sql.push_str(", ");
            }
            sql.push('?');
            sql.push_str(&(i + 3).to_string());
            values.push(SqlValue::Text(call_id.clone()));
        }
        sql.push(')');
    }
    sql.push_str(" ORDER BY timestamp ASC, rowid ASC");
    conn.execute(&sql, params_from_iter(values))
        .context("copying fork tool calls")?;
    Ok(())
}

fn live_btw_fork_info_conn(
    conn: &Connection,
    parent_session_id: Uuid,
) -> Result<Option<BtwForkInfo>> {
    let row = conn
        .query_row(
            "SELECT * FROM sessions WHERE btw_parent_session_id = ?1 LIMIT 1",
            [parent_session_id.to_string()],
            SessionRow::from_row,
        )
        .optional()
        .context("querying live btw fork")?;
    row.as_ref()
        .map(|row| btw_info_for_row_conn(conn, row))
        .transpose()
}

fn btw_info_for_row_conn(conn: &Connection, row: &SessionRow) -> Result<BtwForkInfo> {
    let parent_session_id = row
        .btw_parent_session_id
        .ok_or_else(|| anyhow!("session {} is not a btw fork", row.session_id))?;
    let message_count: i64 = conn
        .query_row(
            "SELECT COUNT(*)
               FROM session_events
              WHERE session_id = ?1
                AND type IN ('user_message', 'assistant_message')",
            [row.session_id.to_string()],
            |row| row.get(0),
        )
        .context("counting btw fork messages")?;
    Ok(BtwForkInfo {
        session_id: row.session_id,
        parent_session_id,
        short_id: row.short_id.clone(),
        tangent: row.btw_tangent,
        created_at: row.started_at,
        message_count: message_count.max(0) as u32,
    })
}

impl Db {
    pub fn create_session(
        &self,
        project_id: &str,
        project_root: &str,
        active_agent: &str,
    ) -> Result<SessionRow> {
        let row = build_session_row(
            project_id,
            project_root,
            active_agent,
            Some(random_short_id()),
            None,
        );
        self.insert_session_row(&row)
    }

    /// Build a brand-new session row — fresh UUID + project-unique
    /// provisional short_id — **without** writing it to the DB. Used by the
    /// lazy-persistence path (session-id-display-and-lazy-persist): the
    /// daemon holds the row in memory and only [`Self::insert_session_row`]s
    /// it on the first user message, so an opened-but-unused session leaves
    /// no DB trace. The short_id is checked against the live table at build
    /// time for a useful display value; the eventual INSERT is the reservation
    /// point and may retry with a different final short_id.
    pub fn new_session_row(
        &self,
        project_id: &str,
        project_root: &str,
        active_agent: &str,
    ) -> Result<SessionRow> {
        let short_id = self.read_blocking(|conn| {
            generate_unique_short_id(conn, project_id).context("generating session short_id")
        })?;
        Ok(build_session_row(
            project_id,
            project_root,
            active_agent,
            Some(short_id),
            None,
        ))
    }

    pub fn create_assistant_session(
        &self,
        project_id: &str,
        project_root: &str,
        active_agent: &str,
        assistant_name: &str,
    ) -> Result<SessionRow> {
        let row = build_session_row(
            project_id,
            project_root,
            active_agent,
            Some(random_short_id()),
            Some(assistant_name.to_string()),
        );
        self.insert_session_row(&row)
    }

    pub fn new_assistant_session_row(
        &self,
        project_id: &str,
        project_root: &str,
        active_agent: &str,
        assistant_name: &str,
    ) -> Result<SessionRow> {
        let short_id = self.read_blocking(|conn| {
            generate_unique_short_id(conn, project_id).context("generating session short_id")
        })?;
        Ok(build_session_row(
            project_id,
            project_root,
            active_agent,
            Some(short_id),
            Some(assistant_name.to_string()),
        ))
    }

    /// Insert a pre-built root session row. Pairs with
    /// [`Self::new_session_row`] for the deferred-persistence path; also the
    /// second half of [`Self::create_session`]. Idempotent at the
    /// application layer is **not** assumed — callers persist exactly once.
    pub fn insert_session_row(&self, row: &SessionRow) -> Result<SessionRow> {
        let row = row.clone();
        self.write_blocking(move |conn| {
            insert_session_row_with_short_id_retry(conn, row.clone()).context("inserting session")
        })
    }

    pub fn set_session_created_by_principal(
        &self,
        session_id: Uuid,
        principal: Option<&str>,
    ) -> Result<()> {
        let principal = principal.map(str::to_owned);
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET created_by_principal = ?1 WHERE session_id = ?2",
                params![principal, session_id.to_string()],
            )
            .context("setting session created_by_principal")?;
            Ok(())
        })
    }

    /// Create a fork session branching from `parent_session_id` at
    /// `fork_point_turn_id` (None = tail). Inherits the parent's
    /// project_id, project_root, active_agent, provider, model.
    /// Returns the new session row (with a fresh UUID + short_id).
    pub fn create_fork(
        &self,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
    ) -> Result<SessionRow> {
        self.create_fork_inner(parent_session_id, fork_point_turn_id, false)
    }

    /// Create an **ephemeral** side-conversation fork (`/side`). Identical
    /// to [`Self::create_fork`] but marks the row `ephemeral = 1`, so it is
    /// excluded from every list query, never auto-titled, never resumable,
    /// and discarded when the side conversation ends / its process exits.
    pub fn create_ephemeral_fork(
        &self,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
    ) -> Result<SessionRow> {
        self.create_fork_inner(parent_session_id, fork_point_turn_id, true)
    }

    /// Create or return the one live persistent `/btw` fork for
    /// `parent_session_id`. The fork is hidden from session lists like an
    /// ephemeral `/side` fork, but it is not swept on boot because it carries
    /// typed BTW linkage.
    pub fn create_btw_fork(
        &self,
        parent_session_id: Uuid,
        tangent: bool,
    ) -> Result<BtwForkCreateResult> {
        let session_id = Uuid::new_v4();
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin create_btw_fork tx")?;
            if let Some(info) = live_btw_fork_info_conn(&tx, parent_session_id)? {
                tx.commit().context("commit existing create_btw_fork tx")?;
                return Ok(BtwForkCreateResult {
                    info,
                    created: false,
                });
            }
            let parent = get_session_inner(&tx, parent_session_id)?
                .ok_or_else(|| anyhow::anyhow!("parent session {parent_session_id} not found"))?;
            let row = SessionRow {
                session_id,
                project_id: parent.project_id,
                project_root: parent.project_root,
                started_at: now,
                last_active_at: now,
                ended_at: None,
                provider: parent.provider,
                model: parent.model,
                active_agent: parent.active_agent,
                assistant_name: parent.assistant_name,
                short_id: Some(random_short_id()),
                parent_session_id: Some(parent_session_id),
                fork_point_turn_id: None,
                title: None,
                user_renamed: false,
                last_viewed_at: None,
                archived_at: None,
                ephemeral: true,
                btw_parent_session_id: Some(parent_session_id),
                btw_tangent: tangent,
                user_content_tokens: if tangent {
                    0
                } else {
                    parent.user_content_tokens
                },
                title_stage: if tangent { 0 } else { parent.title_stage },
                guidance_baseline_path: parent.guidance_baseline_path,
                guidance_baseline_hash: parent.guidance_baseline_hash,
                redaction_table_json: parent.redaction_table_json,
                model_system_prompt_snapshot_json: parent.model_system_prompt_snapshot_json,
                created_by_principal: parent.created_by_principal,
                shared_with_collaborators: false,
            };
            let row = insert_fork_row_with_short_id_retry(&tx, row, &None)
                .context("inserting btw fork session")?;
            if !tangent {
                copy_fork_transcript(&tx, parent_session_id, session_id, None)
                    .context("copying btw fork transcript")?;
            }
            let info = btw_info_for_row_conn(&tx, &row)?;
            tx.commit().context("commit create_btw_fork tx")?;
            Ok(BtwForkCreateResult {
                info,
                created: true,
            })
        })
    }

    pub fn live_btw_fork_info(&self, parent_session_id: Uuid) -> Result<Option<BtwForkInfo>> {
        self.read_blocking(|conn| live_btw_fork_info_conn(conn, parent_session_id))
    }

    pub fn end_btw_fork(&self, parent_session_id: Uuid) -> Result<bool> {
        let fork = self.live_btw_fork_info(parent_session_id)?;
        let Some(info) = fork else {
            return Ok(false);
        };
        self.delete_session(info.session_id, true)?;
        Ok(true)
    }

    fn create_fork_inner(
        &self,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
        ephemeral: bool,
    ) -> Result<SessionRow> {
        let session_id = Uuid::new_v4();
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin create_fork tx")?;
            let parent = get_session_inner(&tx, parent_session_id)?
                .ok_or_else(|| anyhow::anyhow!("parent session {parent_session_id} not found"))?;
            let short_id = random_short_id();
            let row = SessionRow {
                session_id,
                project_id: parent.project_id,
                project_root: parent.project_root,
                started_at: now,
                last_active_at: now,
                ended_at: None,
                provider: parent.provider,
                model: parent.model,
                active_agent: parent.active_agent,
                assistant_name: parent.assistant_name,
                short_id: Some(short_id),
                parent_session_id: Some(parent_session_id),
                fork_point_turn_id: fork_point_turn_id.clone(),
                title: None,
                user_renamed: false,
                last_viewed_at: None,
                archived_at: None,
                ephemeral,
                btw_parent_session_id: None,
                btw_tangent: false,
                user_content_tokens: parent.user_content_tokens,
                title_stage: parent.title_stage,
                guidance_baseline_path: parent.guidance_baseline_path,
                guidance_baseline_hash: parent.guidance_baseline_hash,
                redaction_table_json: parent.redaction_table_json,
                model_system_prompt_snapshot_json: parent.model_system_prompt_snapshot_json,
                created_by_principal: parent.created_by_principal,
                shared_with_collaborators: false,
            };
            let row = insert_fork_row_with_short_id_retry(&tx, row, &fork_point_turn_id)
                .context("inserting fork session")?;
            copy_fork_transcript(
                &tx,
                parent_session_id,
                session_id,
                fork_point_turn_id.as_deref(),
            )
            .context("copying fork transcript")?;
            tx.commit().context("commit create_fork tx")?;
            Ok(row)
        })
    }

    pub fn get_session(&self, session_id: Uuid) -> Result<Option<SessionRow>> {
        self.read_blocking(|conn| Self::get_session_conn(conn, session_id))
    }

    pub fn get_session_conn(conn: &Connection, session_id: Uuid) -> Result<Option<SessionRow>> {
        Ok(get_session_inner(conn, session_id)?)
    }

    /// Lookup by short id within a project. Used by CLI/RPC paths where
    /// the user types the 6-char display id rather than the full UUID.
    pub fn get_session_by_short_id(
        &self,
        project_id: &str,
        short_id: &str,
    ) -> Result<Option<SessionRow>> {
        self.read_blocking(|conn| {
            let result = conn.query_row(
                "SELECT * FROM sessions
                 WHERE project_id = ?1 AND short_id = ?2",
                params![project_id, short_id],
                SessionRow::from_row,
            );
            match result {
                Ok(row) => Ok(Some(row)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e).context("query get_session_by_short_id"),
            }
        })
    }

    /// Look up sessions by `short_id` across **every** project. Used by
    /// `cockpit export <session>`, which accepts a bare short_id without a
    /// project context. Returns all matches so the caller can report an
    /// ambiguous identifier (a short_id is unique only within a project).
    pub fn find_sessions_by_short_id_global(&self, short_id: &str) -> Result<Vec<SessionRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM sessions WHERE short_id = ?1")
                .context("preparing find_sessions_by_short_id_global")?;
            let rows = stmt
                .query_map([short_id], SessionRow::from_row)
                .context("querying sessions by short_id")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding session row")?);
            }
            Ok(out)
        })
    }

    /// Ensure the session has a short_id (lazy backfill for rows
    /// migrated from pre-§17 schemas). Returns the resolved short_id.
    pub fn ensure_short_id(&self, session_id: Uuid) -> Result<String> {
        self.write_blocking(move |conn| {
            let row = get_session_inner(conn, session_id)?
                .ok_or_else(|| anyhow::anyhow!("session {session_id} not found"))?;
            if let Some(existing) = row.short_id {
                return Ok(existing);
            }
            let short_id = backfill_short_id_with_retry(conn, session_id, &row.project_id)
                .context("backfilling short_id")?;
            Ok(short_id)
        })
    }

    /// Set or replace the session's title. `user_renamed` flips to true
    /// to lock out the auto-titling pass (GOALS §17d).
    pub fn rename_session(&self, session_id: Uuid, title: &str) -> Result<()> {
        let title = title.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET title = ?1, user_renamed = 1 WHERE session_id = ?2",
                params![title, session_id.to_string()],
            )
            .context("renaming session")?;
            Ok(())
        })
    }

    /// Set the title from the auto-titling pass. Refuses to overwrite a
    /// user-set title — auto-titling never clobbers manual labels.
    pub fn set_auto_title(&self, session_id: Uuid, title: &str) -> Result<bool> {
        let title = title.to_owned();
        self.write_blocking(move |conn| {
            let affected = conn
                .execute(
                    "UPDATE sessions SET title = ?1
                 WHERE session_id = ?2 AND user_renamed = 0 AND ephemeral = 0",
                    params![title, session_id.to_string()],
                )
                .context("setting auto title")?;
            Ok(affected > 0)
        })
    }

    /// Set a title generated by an explicit user request (`/rename` with no
    /// title). This is still an auto-generated title, so it clears
    /// `user_renamed`; future scheduled auto-refreshes may replace it until the
    /// user manually names the session again.
    pub fn set_explicit_auto_title(&self, session_id: Uuid, title: &str) -> Result<bool> {
        let title = title.to_owned();
        self.write_blocking(move |conn| {
            let affected = conn
                .execute(
                    "UPDATE sessions SET title = ?1, user_renamed = 0
                 WHERE session_id = ?2 AND ephemeral = 0",
                    params![title, session_id.to_string()],
                )
                .context("setting explicit auto title")?;
            Ok(affected > 0)
        })
    }

    /// Set a generated title only if the session is still unnamed. This is
    /// used by daemon RPCs where competing callers may generate concurrently;
    /// the storage layer decides the single winner.
    pub fn set_explicit_auto_title_if_untitled(
        &self,
        session_id: Uuid,
        title: &str,
    ) -> Result<bool> {
        let title = title.to_owned();
        self.write_blocking(move |conn| {
            let affected = conn
                .execute(
                    "UPDATE sessions SET title = ?1, user_renamed = 0
                 WHERE session_id = ?2 AND ephemeral = 0 AND title IS NULL",
                    params![title, session_id.to_string()],
                )
                .context("setting explicit auto title if untitled")?;
            Ok(affected > 0)
        })
    }

    /// Persist auto-title progress (migration 0037): the running raw-user
    /// token estimate and last consumed schedule slot. Called from
    /// [`crate::session::Session::note_user_content`] so automatic refresh
    /// progress survives resume / daemon restart. Best-effort at the call
    /// site; an erroring write never blocks a turn.
    pub fn set_title_progress(
        &self,
        session_id: Uuid,
        user_content_tokens: i64,
        title_stage: i64,
    ) -> Result<()> {
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions
                 SET user_content_tokens = ?1, title_stage = ?2
                 WHERE session_id = ?3",
                params![user_content_tokens, title_stage, session_id.to_string()],
            )
            .context("persisting title progress")?;
            Ok(())
        })
    }

    /// Direct children of a session in the fork tree. Most-recent-first.
    pub fn list_forks(&self, parent_session_id: Uuid) -> Result<Vec<SessionRow>> {
        self.read_blocking(|conn| Self::list_forks_conn(conn, parent_session_id))
    }

    pub fn list_forks_conn(conn: &Connection, parent_session_id: Uuid) -> Result<Vec<SessionRow>> {
        let mut stmt = conn
            .prepare(
                "SELECT * FROM sessions WHERE parent_session_id = ?1 AND ephemeral = 0
             ORDER BY last_active_at DESC",
            )
            .context("preparing list_forks")?;
        let rows = stmt
            .query_map([parent_session_id.to_string()], SessionRow::from_row)
            .context("querying list_forks")?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.context("decoding fork row")?);
        }
        Ok(out)
    }

    /// Cheap fork count for the `[N forks]` chip in the `/sessions`
    /// browser. Counts immediate children only (depth-1).
    #[allow(dead_code)]
    pub fn count_forks_for(&self, parent_session_id: Uuid) -> Result<u32> {
        self.read_blocking(|conn| Self::count_forks_for_conn(conn, parent_session_id))
    }

    fn count_forks_for_conn(conn: &Connection, parent_session_id: Uuid) -> Result<u32> {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE parent_session_id = ?1 AND ephemeral = 0",
                [parent_session_id.to_string()],
                |row| row.get(0),
            )
            .context("counting forks")?;
        Ok(count as u32)
    }

    /// Root sessions (no parent) for a project, most-recent-first.
    /// This is what the top-level `/sessions` view shows; forks descend
    /// via [`Self::list_forks`].
    #[allow(dead_code)]
    pub fn list_root_sessions(&self, project_id: &str, limit: u32) -> Result<Vec<SessionRow>> {
        self.read_blocking(|conn| Self::list_root_sessions_conn(conn, project_id, limit))
    }

    pub fn list_root_sessions_conn(
        conn: &Connection,
        project_id: &str,
        limit: u32,
    ) -> Result<Vec<SessionRow>> {
        let mut stmt = conn
            .prepare(
                "SELECT * FROM sessions
             WHERE project_id = ?1 AND parent_session_id IS NULL AND ephemeral = 0
             ORDER BY last_active_at DESC LIMIT ?2",
            )
            .context("preparing list_root_sessions")?;
        let rows = stmt
            .query_map(params![project_id, limit], SessionRow::from_row)
            .context("querying list_root_sessions")?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.context("decoding root session row")?);
        }
        Ok(out)
    }

    /// Delete a session. With `cascade = true`, also deletes every
    /// descendant fork (depth-unbounded). FK CASCADE on tool_call_events
    /// / inference_calls / lock state takes care of dependent rows.
    pub fn delete_session(&self, session_id: Uuid, cascade: bool) -> Result<()> {
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin delete_session tx")?;
            if cascade {
                let mut to_delete = collect_subtree(&tx, session_id)?;
                // Descendants first, so a successful cascade never depends on
                // deleting a parent before its app-level child pointers.
                to_delete.reverse();
                for id in to_delete {
                    tx.execute(
                        "DELETE FROM sessions WHERE session_id = ?1",
                        [id.to_string()],
                    )
                    .context("deleting session in cascade")?;
                }
            } else {
                tx.execute(
                    "DELETE FROM sessions WHERE session_id = ?1",
                    [session_id.to_string()],
                )
                .context("deleting session")?;
            }
            tx.commit().context("commit delete_session tx")?;
            Ok(())
        })
    }

    /// Discard a single ephemeral side-conversation session (`/side`),
    /// cascading to its descendant forks. No-op (returns `Ok(false)`) when
    /// the id is unknown or the row is **not** ephemeral — a guard so a
    /// stray discard can never delete a persisted session. Returns `true`
    /// when an ephemeral row was deleted.
    pub fn discard_ephemeral_session(&self, session_id: Uuid) -> Result<bool> {
        // Guard on the typed row flag — only an ephemeral session is ever
        // discarded this way, so a stray call can't drop a persisted one.
        match self.get_session(session_id)? {
            Some(row) if row.ephemeral => {}
            _ => return Ok(false),
        }
        self.delete_session(session_id, true)?;
        Ok(true)
    }

    /// Sweep every ephemeral session row (and descendant forks) from the DB.
    /// Run once on daemon boot as the SIGKILL backstop: a side conversation
    /// whose owning process died uncatchably can leave an orphaned ephemeral
    /// row behind, and this clears it so ephemeral sessions never accumulate.
    /// Returns the number of root ephemeral sessions removed.
    pub fn sweep_ephemeral_sessions(&self) -> Result<usize> {
        let roots = self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT session_id
                       FROM sessions
                      WHERE ephemeral = 1
                        AND btw_parent_session_id IS NULL",
                )
                .context("preparing ephemeral sweep")?;
            let rows = stmt
                .query_map([], |row| {
                    let s: String = row.get(0)?;
                    parse_uuid(&s)
                })
                .context("querying ephemeral sweep")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding ephemeral row")?);
            }
            Ok(out)
        })?;
        let mut removed = 0;
        for id in roots {
            // Cascade in case a side conversation itself spawned forks.
            match self.delete_session(id, true) {
                Ok(()) => removed += 1,
                Err(error) => {
                    tracing::warn!(
                        session_id = %id,
                        error = %error,
                        "ephemeral session sweep delete failed; continuing"
                    );
                }
            }
        }
        Ok(removed)
    }

    /// Set the read/unread marker to now (migration 0010). Called when a
    /// client opens/resumes the session — everything the agent produced
    /// up to this instant counts as seen; later agent output reads as
    /// unread.
    pub fn mark_session_viewed(&self, session_id: Uuid) -> Result<()> {
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET last_viewed_at = ?1 WHERE session_id = ?2",
                params![now, session_id.to_string()],
            )
            .context("marking session viewed")?;
            Ok(())
        })
    }

    /// Timestamp (epoch seconds) of the most recent agent-produced event
    /// for a session, or `None` when the session has no agent activity
    /// yet. The max across `tool_call_events` and `inference_calls` — the
    /// two tables that record agent output. Drives the unread tier: a
    /// session is unread when this is newer than `last_viewed_at` (or it
    /// has activity and was never viewed).
    #[allow(dead_code)]
    pub fn latest_agent_activity_at(&self, session_id: Uuid) -> Result<Option<i64>> {
        self.read_blocking(|conn| Self::latest_agent_activity_at_conn(conn, session_id))
    }

    fn latest_agent_activity_at_conn(conn: &Connection, session_id: Uuid) -> Result<Option<i64>> {
        let ts: Option<i64> = conn
            .query_row(
                "SELECT MAX(t) FROM (
                     SELECT MAX(timestamp) AS t FROM tool_call_events WHERE session_id = ?1
                     UNION ALL
                     SELECT MAX(timestamp) AS t FROM inference_calls WHERE session_id = ?1
                 )",
                [session_id.to_string()],
                |row| row.get(0),
            )
            .context("querying latest_agent_activity_at")?;
        Ok(ts)
    }

    /// Archive a session (recoverable soft-delete, migration 0010). With
    /// `cascade = true`, archives every descendant fork (depth-unbounded)
    /// via the same recursive walk `delete_session` uses, so the whole
    /// fork subtree disappears from the browser together. Idempotent —
    /// re-archiving an already-archived row just re-stamps `archived_at`.
    pub fn archive_session(&self, session_id: Uuid, cascade: bool) -> Result<()> {
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin archive_session tx")?;
            let targets = if cascade {
                collect_subtree(&tx, session_id)?
            } else {
                vec![session_id]
            };
            for id in targets {
                tx.execute(
                    "UPDATE sessions SET archived_at = ?1 WHERE session_id = ?2",
                    params![now, id.to_string()],
                )
                .context("archiving session")?;
            }
            tx.commit().context("commit archive_session tx")?;
            Ok(())
        })
    }

    /// Clear a session's archive flag (recover). Single row only — the
    /// browser unarchives one session at a time from the archived view.
    pub fn unarchive_session(&self, session_id: Uuid) -> Result<()> {
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET archived_at = NULL WHERE session_id = ?1",
                [session_id.to_string()],
            )
            .context("unarchiving session")?;
            Ok(())
        })
    }

    /// Count the descendant forks of a session (depth-unbounded, not
    /// counting the session itself). Used by the archive/delete confirm
    /// dialog to state how many sessions the cascade will affect.
    #[allow(dead_code)]
    pub fn count_descendants(&self, session_id: Uuid) -> Result<u32> {
        self.read_blocking(|conn| Self::count_descendants_conn(conn, session_id))
    }

    fn count_descendants_conn(conn: &Connection, session_id: Uuid) -> Result<u32> {
        let n = collect_subtree(conn, session_id)?.len();
        // `collect_subtree` includes the root; descendants are the rest.
        Ok((n.saturating_sub(1)) as u32)
    }

    /// `true` when `node` is `root` itself or a (transitive) descendant
    /// of `root` in the fork tree. Walks `node`'s ancestor chain upward —
    /// cheap for the shallow trees forks produce, and bounded by a guard
    /// against cyclic/dangling parents. Used by the daemon to decide
    /// which live workers to interrupt before a cascading archive/delete.
    pub fn is_in_subtree(&self, root: Uuid, node: Uuid) -> Result<bool> {
        if root == node {
            return Ok(true);
        }
        self.read_blocking(|conn| {
            let mut cur = node;
            // Bound the walk so a corrupted parent cycle can't spin.
            for _ in 0..10_000 {
                let parent: Option<String> = match conn.query_row(
                    "SELECT parent_session_id FROM sessions WHERE session_id = ?1",
                    [cur.to_string()],
                    |row| row.get(0),
                ) {
                    Ok(p) => p,
                    Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
                    Err(e) => return Err(anyhow::Error::from(e)).context("is_in_subtree walk"),
                };
                let Some(parent) = parent else {
                    return Ok(false);
                };
                let parent =
                    parse_uuid(&parent).map_err(|e| anyhow::anyhow!("decoding parent id: {e}"))?;
                if parent == root {
                    return Ok(true);
                }
                cur = parent;
            }
            Ok(false)
        })
    }

    /// Move `last_active_at` to now. Called by the daemon on every
    /// interaction so `cockpit -c` resumes the actually-recent one.
    pub fn touch_session(&self, session_id: Uuid) -> Result<()> {
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET last_active_at = ?1 WHERE session_id = ?2",
                params![now, session_id.to_string()],
            )
            .context("touching session")?;
            Ok(())
        })
    }

    pub fn set_session_redaction_table_json(
        &self,
        session_id: Uuid,
        redaction_table_json: Option<String>,
    ) -> Result<()> {
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET redaction_table_json = ?1 WHERE session_id = ?2",
                params![redaction_table_json, session_id.to_string()],
            )
            .context("setting session redaction table")?;
            Ok(())
        })
    }

    pub fn set_session_model(&self, session_id: Uuid, provider: &str, model: &str) -> Result<()> {
        let provider = provider.to_owned();
        let model = model.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET provider = ?1, model = ?2 WHERE session_id = ?3",
                params![provider, model, session_id.to_string()],
            )
            .context("setting session model")?;
            Ok(())
        })
    }

    pub fn set_session_agent(&self, session_id: Uuid, active_agent: &str) -> Result<()> {
        let active_agent = active_agent.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET active_agent = ?1 WHERE session_id = ?2",
                params![active_agent, session_id.to_string()],
            )
            .context("setting session agent")?;
            Ok(())
        })
    }

    pub fn end_session(&self, session_id: Uuid) -> Result<()> {
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET ended_at = ?1 WHERE session_id = ?2",
                params![now, session_id.to_string()],
            )
            .context("ending session")?;
            Ok(())
        })
    }

    /// Sessions newest-first. `only_open = true` filters out ended ones.
    #[allow(dead_code)]
    pub fn list_sessions(&self, only_open: bool, limit: u32) -> Result<Vec<SessionRow>> {
        self.read_blocking(|conn| Self::list_sessions_conn(conn, only_open, limit))
    }

    pub fn list_sessions_conn(
        conn: &Connection,
        only_open: bool,
        limit: u32,
    ) -> Result<Vec<SessionRow>> {
        let sql = if only_open {
            "SELECT * FROM sessions WHERE ended_at IS NULL AND ephemeral = 0
             ORDER BY last_active_at DESC LIMIT ?1"
        } else {
            "SELECT * FROM sessions WHERE ephemeral = 0
             ORDER BY last_active_at DESC LIMIT ?1"
        };
        let mut stmt = conn.prepare(sql).context("preparing list_sessions")?;
        let rows = stmt
            .query_map([limit], SessionRow::from_row)
            .context("querying sessions")?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.context("decoding session row")?);
        }
        Ok(out)
    }

    pub fn list_sessions_for_assistant(
        &self,
        assistant_name: &str,
        only_open: bool,
        limit: u32,
    ) -> Result<Vec<SessionRow>> {
        let assistant_name = assistant_name.to_string();
        self.read_blocking(move |conn| {
            let sql = if only_open {
                "SELECT * FROM sessions
                  WHERE assistant_name = ?1 AND ended_at IS NULL AND ephemeral = 0
                  ORDER BY last_active_at DESC LIMIT ?2"
            } else {
                "SELECT * FROM sessions
                  WHERE assistant_name = ?1 AND ephemeral = 0
                  ORDER BY last_active_at DESC LIMIT ?2"
            };
            let mut stmt = conn
                .prepare(sql)
                .context("preparing list_sessions_for_assistant")?;
            let rows = stmt
                .query_map(params![assistant_name, limit], SessionRow::from_row)
                .context("querying assistant sessions")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding assistant session row")?);
            }
            Ok(out)
        })
    }

    pub fn most_recent_session_for_assistant(
        &self,
        assistant_name: &str,
    ) -> Result<Option<SessionRow>> {
        let assistant_name = assistant_name.to_string();
        self.read_blocking(move |conn| {
            conn.query_row(
                "SELECT * FROM sessions
                  WHERE assistant_name = ?1 AND ephemeral = 0
                  ORDER BY last_active_at DESC, started_at DESC
                  LIMIT 1",
                params![assistant_name],
                SessionRow::from_row,
            )
            .optional()
            .context("loading most recent assistant session")
        })
    }

    /// The most recent durable session for a canonical workspace root,
    /// ordered by its latest user/assistant message rather than incidental
    /// metadata activity. Used by noninteractive `run --continue`.
    pub fn most_recent_session_for_root_by_message(
        &self,
        project_root: &str,
    ) -> Result<Option<SessionRow>> {
        self.read_blocking(|conn| {
            let result = conn.query_row(
                "SELECT s.*
                   FROM sessions AS s
                  WHERE s.project_root = ?1 AND s.ephemeral = 0
                  ORDER BY COALESCE(
                               (SELECT MAX(e.ts_ms)
                                  FROM session_events AS e
                                 WHERE e.session_id = s.session_id
                                   AND e.type IN ('user_message', 'assistant_message')),
                               s.last_active_at * 1000
                           ) DESC,
                           s.last_active_at DESC,
                           s.session_id DESC
                  LIMIT 1",
                [project_root],
                SessionRow::from_row,
            );
            match result {
                Ok(row) => Ok(Some(row)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(error).context("querying latest session by message time"),
            }
        })
    }

    /// Assemble the `/sessions` browser rows for one level, the single
    /// source of truth shared by the daemon's `ListSessions` handler and
    /// the TUI's daemonless direct-DB fallback. The level selection
    /// mirrors the RPC contract:
    ///
    /// - `parent_session_id = Some(p)` → the direct forks of `p`
    ///   (project scope is implied by the parent and ignored).
    /// - `project_id = Some(pid)`, no parent → root sessions in `pid`.
    /// - both `None` → every open session across projects.
    ///
    /// Each row carries the DB-derived fork counts, read/unread inputs
    /// (`latest_activity_at`), and open-interrupt count. Live-only fields
    /// (running/processing) are *not* part of this method — callers
    /// attach them separately (the daemon from its registry, the TUI
    /// daemonless path not at all). A per-row auxiliary-query miss
    /// degrades that field to its empty default rather than failing the
    /// whole list, matching the daemon handler's best-effort behavior.
    pub fn list_session_summaries(
        &self,
        project_id: Option<&str>,
        parent_session_id: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<crate::db::wire::SessionSummary>> {
        self.read_blocking(|conn| {
            Self::list_session_summaries_conn(conn, project_id, parent_session_id, limit)
        })
    }

    pub fn list_session_summaries_conn(
        conn: &Connection,
        project_id: Option<&str>,
        parent_session_id: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<crate::db::wire::SessionSummary>> {
        let rows = match (project_id, parent_session_id) {
            (_, Some(parent)) => Self::list_forks_conn(conn, parent)?,
            (Some(pid), None) => Self::list_root_sessions_conn(conn, pid, limit)?,
            (None, None) => Self::list_sessions_conn(conn, true, limit)?,
        };
        let mut summaries = Vec::with_capacity(rows.len());
        for row in rows {
            let fork_count = summary_count_or_zero(
                row.session_id,
                "fork_count",
                Self::count_forks_for_conn(conn, row.session_id),
            );
            // Full subtree descendant count for the archive/delete cascade
            // statement (GOALS §17h) — direct forks plus their descendants.
            let descendant_count = summary_count_or_zero(
                row.session_id,
                "descendant_count",
                Self::count_descendants_conn(conn, row.session_id),
            );
            // Read/unread + pending-question inputs for the browser's tiers
            // 3-4 (GOALS §17f). Best-effort: a query miss degrades to "no
            // activity / no open question" rather than failing the list.
            let latest_activity_at = summary_latest_activity_or_none(
                row.session_id,
                Self::latest_agent_activity_at_conn(conn, row.session_id),
            );
            let open_interrupts = summary_open_interrupt_count_or_zero(
                row.session_id,
                Self::open_interrupt_count_conn(conn, row.session_id),
            );
            let activity_state = summary_activity_state_or_none(
                row.session_id,
                Self::interrupt_activity_state_conn(conn, row.session_id),
            );
            // Pinned-message count (`pinned-messages`) for the browser's
            // per-session pin chrome. Best-effort: a query miss reads as 0.
            let pin_count = summary_pin_count_or_zero(
                row.session_id,
                Self::pin_count_conn(conn, row.session_id),
            );
            summaries.push(crate::db::wire::SessionSummary {
                session_id: row.session_id,
                short_id: row.short_id,
                project_root: row.project_root,
                project_id: row.project_id,
                started_at: row.started_at,
                last_active_at: row.last_active_at,
                turns: 0, // wire up when we track turn count
                active_agent: row.active_agent,
                title: row.title,
                parent_session_id: row.parent_session_id,
                fork_count,
                descendant_count,
                last_viewed_at: row.last_viewed_at,
                latest_activity_at,
                open_interrupts,
                activity_state,
                archived_at: row.archived_at,
                created_by_principal: row.created_by_principal,
                shared_with_collaborators: row.shared_with_collaborators,
                pin_count,
            });
        }
        Ok(summaries)
    }

    fn open_interrupt_count_conn(conn: &Connection, session_id: Uuid) -> Result<Vec<()>> {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM needs_attention
                  WHERE session_id = ?1 AND resolved_at IS NULL",
                [session_id.to_string()],
                |row| row.get(0),
            )
            .context("counting open interrupts")?;
        Ok(vec![(); count.max(0) as usize])
    }

    fn interrupt_activity_state_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Option<crate::db::wire::SessionActivityState>> {
        let mut stmt = conn
            .prepare(
                "SELECT state, question_json, questions_json
                   FROM needs_attention
                  WHERE session_id = ?1
                    AND state IN ('open', 'parked', 'interrupted')
                  ORDER BY CASE state WHEN 'open' THEN 0 WHEN 'parked' THEN 0 ELSE 1 END,
                           raised_at ASC, rowid ASC
                  LIMIT 1",
            )
            .context("preparing interrupt activity state")?;
        let mut rows = stmt
            .query([session_id.to_string()])
            .context("querying interrupt activity state")?;
        let Some(row) = rows.next().context("reading interrupt activity state")? else {
            return Ok(None);
        };
        let state: String = row.get(0).context("reading interrupt state")?;
        if state == "interrupted" {
            return Ok(Some(crate::db::wire::SessionActivityState::Interrupted));
        }
        let question_json: Option<String> = row.get(1).context("reading question_json")?;
        let questions_json: Option<String> = row.get(2).context("reading questions_json")?;
        let permission = interrupt_payload_has_permission(question_json, questions_json);
        Ok(Some(if permission || state == "parked" {
            crate::db::wire::SessionActivityState::Parked
        } else {
            crate::db::wire::SessionActivityState::PendingQuestion
        }))
    }

    fn pin_count_conn(conn: &Connection, session_id: Uuid) -> Result<i64> {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pins WHERE session_id = ?1",
                [session_id.to_string()],
                |row| row.get(0),
            )
            .context("counting pins")?;
        Ok(n)
    }

    /// Most recently active session for a given project. Used by
    /// `cockpit -c` ("continue") when the user is back in the same
    /// project.
    // Retained for the not-yet-wired `cockpit -c` continue flow.
    #[allow(dead_code)]
    pub fn most_recent_open_session_for(&self, project_id: &str) -> Result<Option<SessionRow>> {
        self.read_blocking(|conn| {
            let result = conn.query_row(
                "SELECT * FROM sessions
                 WHERE project_id = ?1 AND ended_at IS NULL AND ephemeral = 0
                 ORDER BY last_active_at DESC LIMIT 1",
                [project_id],
                SessionRow::from_row,
            );
            match result {
                Ok(row) => Ok(Some(row)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e).context("query most_recent_open_session_for"),
            }
        })
    }
}

fn summary_count_or_zero(session_id: Uuid, field: &'static str, result: Result<u32>) -> u32 {
    match result {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(
                session_id = %session_id,
                field,
                error = %error,
                "session summary count query failed; using zero"
            );
            0
        }
    }
}

fn summary_latest_activity_or_none(session_id: Uuid, result: Result<Option<i64>>) -> Option<i64> {
    match result {
        Ok(ts) => ts,
        Err(error) => {
            tracing::warn!(
                session_id = %session_id,
                field = "latest_activity_at",
                error = %error,
                "session summary latest activity query failed; using none"
            );
            None
        }
    }
}

fn summary_open_interrupt_count_or_zero<T>(session_id: Uuid, result: Result<Vec<T>>) -> u32 {
    match result {
        Ok(open) => open.len() as u32,
        Err(error) => {
            tracing::warn!(
                session_id = %session_id,
                field = "open_interrupts",
                error = %error,
                "session summary open interrupt query failed; using zero"
            );
            0
        }
    }
}

fn summary_activity_state_or_none(
    session_id: Uuid,
    result: Result<Option<crate::db::wire::SessionActivityState>>,
) -> Option<crate::db::wire::SessionActivityState> {
    match result {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(
                session_id = %session_id,
                field = "activity_state",
                error = %error,
                "session summary activity-state query failed; using none"
            );
            None
        }
    }
}

fn interrupt_payload_has_permission(
    question_json: Option<String>,
    questions_json: Option<String>,
) -> bool {
    use crate::db::wire::{InterruptQuestion, InterruptQuestionSet};

    fn question_permission(question: &InterruptQuestion) -> bool {
        matches!(
            question,
            InterruptQuestion::Single {
                permission: true,
                approval_class: None,
                ..
            }
        )
    }

    if let Some(json) = questions_json
        && let Ok(set) = serde_json::from_str::<InterruptQuestionSet>(&json)
    {
        return set.questions.iter().any(question_permission);
    }
    if let Some(json) = question_json
        && let Ok(question) = serde_json::from_str::<InterruptQuestion>(&json)
    {
        return question_permission(&question);
    }
    false
}

fn summary_pin_count_or_zero(session_id: Uuid, result: Result<i64>) -> u32 {
    match result {
        Ok(count) => count.max(0) as u32,
        Err(error) => {
            tracing::warn!(
                session_id = %session_id,
                field = "pin_count",
                error = %error,
                "session summary pin count query failed; using zero"
            );
            0
        }
    }
}

/// Collect a session and every descendant fork (depth-unbounded),
/// root-first. Shared by `delete_session`, `archive_session`, and
/// `count_descendants` so the subtree walk lives in exactly one place.
fn collect_subtree(conn: &Connection, root: Uuid) -> Result<Vec<Uuid>> {
    let mut all = vec![root];
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        let mut stmt = conn
            .prepare("SELECT session_id FROM sessions WHERE parent_session_id = ?1")
            .context("preparing fork-walk")?;
        let children = stmt
            .query_map([parent.to_string()], |row| {
                let s: String = row.get(0)?;
                parse_uuid(&s)
            })
            .context("querying fork-walk")?;
        for child in children {
            let id = child.context("decoding fork child")?;
            all.push(id);
            frontier.push(id);
        }
    }
    Ok(all)
}

fn get_session_inner(conn: &Connection, session_id: Uuid) -> rusqlite::Result<Option<SessionRow>> {
    let mut stmt = conn.prepare("SELECT * FROM sessions WHERE session_id = ?1")?;
    let mut rows = stmt.query([session_id.to_string()])?;
    match rows.next()? {
        Some(row) => Ok(Some(SessionRow::from_row(row)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Mutex as StdMutex;
    use tracing::Level;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CaptureWriter(std::sync::Arc<StdMutex<Vec<u8>>>);

    struct CaptureGuard(std::sync::Arc<StdMutex<Vec<u8>>>);

    impl io::Write for CaptureGuard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureGuard;

        fn make_writer(&'a self) -> Self::Writer {
            CaptureGuard(self.0.clone())
        }
    }

    fn capture_warn_log(f: impl FnOnce()) -> String {
        let bytes = std::sync::Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::WARN)
            .with_ansi(false)
            .with_writer(CaptureWriter(bytes.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
    }

    fn record_message(db: &Db, session_id: Uuid, text: &str, assistant: bool) -> i64 {
        db.insert_session_event(
            session_id,
            if assistant {
                crate::db::session_log::SessionEventKind::AssistantMessage
            } else {
                crate::db::session_log::SessionEventKind::UserMessage
            },
            Some("Build"),
            None,
            &serde_json::json!({"text": text}),
        )
        .unwrap()
    }

    fn record_tool_timeline(db: &Db, session_id: Uuid, call_id: &str) -> i64 {
        db.insert_session_event(
            session_id,
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some(call_id),
            &serde_json::json!({"tool": "read"}),
        )
        .unwrap()
    }

    fn record_tool_call_event(db: &Db, session_id: Uuid, call_id: &str, timestamp: i64) {
        db.insert_tool_call(&crate::db::tool_calls::ToolCallEvent {
            event_id: Uuid::new_v4(),
            session_id,
            call_id: call_id.to_string(),
            parent_call_id: None,
            parent_child_index: None,
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp,
            model: "m".to_string(),
            provider: "p".to_string(),
            project_id: "p".to_string(),
            project_root: "/proj".to_string(),
            agent: "Build".to_string(),
            tool: "read".to_string(),
            mcp_server: None,
            path: Some("src/lib.rs".to_string()),
            recovery: crate::db::tool_calls::Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            original_input_json: serde_json::json!({"path": "src/lib.rs"}),
            wire_input_json: serde_json::json!({"path": "src/lib.rs"}),
            output: "ok".to_string(),
            truncated: false,
            duration_ms: 1,
            cockpit_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            llm_mode: Some("defensive".to_string()),
            shape_fingerprint: None,
            hint: None,
        })
        .unwrap();
    }

    fn fork_tool_call_ids(db: &Db, session_id: Uuid) -> Vec<String> {
        db.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT call_id FROM tool_call_events WHERE session_id = ?1 ORDER BY call_id",
                )
                .unwrap();
            let rows = stmt
                .query_map([session_id.to_string()], |row| row.get::<_, String>(0))
                .unwrap();
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>().unwrap())
        })
        .unwrap()
    }

    fn session_exists(db: &Db, session_id: Uuid) -> bool {
        db.get_session(session_id).unwrap().is_some()
    }

    fn fork_rows_for_parent(db: &Db, parent_session_id: Uuid) -> Vec<Uuid> {
        db.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT session_id FROM sessions WHERE parent_session_id = ?1 ORDER BY started_at",
                )
                .unwrap();
            let rows = stmt
                .query_map([parent_session_id.to_string()], |row| {
                    let raw: String = row.get(0)?;
                    parse_uuid(&raw)
                })
                .unwrap();
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>().unwrap())
        })
        .unwrap()
    }

    fn install_trigger(db: &Db, sql: &str) {
        let db = db.clone();
        let sql = sql.to_owned();
        db.write_blocking(move |conn| {
            conn.execute_batch(&sql)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn create_and_get() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p1", "/x/y", "Build").unwrap();
        let g = db.get_session(s.session_id).unwrap().unwrap();
        assert_eq!(g.project_id, "p1");
        assert_eq!(g.project_root, "/x/y");
        assert_eq!(g.active_agent, "Build");
        assert!(g.ended_at.is_none());
    }

    #[test]
    fn latest_session_for_root_orders_by_last_message() {
        let db = Db::open_in_memory().unwrap();
        let first = db.create_session("p", "/proj", "Build").unwrap();
        let second = db.create_session("p", "/proj", "Build").unwrap();
        let other = db.create_session("q", "/other", "Build").unwrap();
        let first_seq = record_message(&db, first.session_id, "newest message", false);
        let second_seq = record_message(&db, second.session_id, "older message", true);
        let other_seq = record_message(&db, other.session_id, "newest elsewhere", false);

        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE session_events SET ts_ms = 3000 WHERE seq = ?1",
                [first_seq],
            )?;
            conn.execute(
                "UPDATE session_events SET ts_ms = 1000 WHERE seq = ?1",
                [second_seq],
            )?;
            conn.execute(
                "UPDATE session_events SET ts_ms = 4000 WHERE seq = ?1",
                [other_seq],
            )?;
            conn.execute(
                "UPDATE sessions SET last_active_at = 9999 WHERE session_id = ?1",
                [second.session_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();

        let selected = db
            .most_recent_session_for_root_by_message("/proj")
            .unwrap()
            .unwrap();
        assert_eq!(selected.session_id, first.session_id);
        assert!(
            db.most_recent_session_for_root_by_message("/missing")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn new_session_row_defers_the_write() {
        // session-id-display-and-lazy-persist: building a row reserves an id
        // + short_id but writes nothing; inserting it makes it queryable.
        let db = Db::open_in_memory().unwrap();
        let row = db.new_session_row("p", "/x", "builder").unwrap();
        assert!(row.short_id.is_some());
        assert!(db.get_session(row.session_id).unwrap().is_none());
        assert!(db.list_sessions(false, 100).unwrap().is_empty());
        db.insert_session_row(&row).unwrap();
        let got = db.get_session(row.session_id).unwrap().unwrap();
        assert_eq!(got.project_id, "p");
        assert_eq!(got.short_id, row.short_id);
        assert_eq!(db.list_sessions(false, 100).unwrap().len(), 1);
    }

    #[test]
    fn insert_session_row_round_trips_provider_model() {
        let db = Db::open_in_memory().unwrap();
        let mut row = db.new_session_row("p", "/x", "builder").unwrap();
        row.provider = Some("anthropic".into());
        row.model = Some("opus".into());
        db.insert_session_row(&row).unwrap();
        let got = db.get_session(row.session_id).unwrap().unwrap();
        assert_eq!(got.provider.as_deref(), Some("anthropic"));
        assert_eq!(got.model.as_deref(), Some("opus"));
    }

    #[test]
    fn insert_session_row_round_trips_model_system_prompt_snapshot_json() {
        let db = Db::open_in_memory().unwrap();
        let mut row = db.new_session_row("p", "/x", "builder").unwrap();
        row.model_system_prompt_snapshot_json =
            r#"{"prompts":{"p":{"m":"model instructions"}}}"#.to_string();

        db.insert_session_row(&row).unwrap();

        let got = db.get_session(row.session_id).unwrap().unwrap();
        assert_eq!(
            got.model_system_prompt_snapshot_json,
            r#"{"prompts":{"p":{"m":"model instructions"}}}"#
        );
    }

    #[test]
    fn insert_session_row_round_trips_redaction_table_json() {
        let db = Db::open_in_memory().unwrap();
        let mut row = db.new_session_row("p", "/x", "builder").unwrap();
        row.redaction_table_json =
            Some(r#"{"rules":[{"kind":"literal","value":"persisted-secret-value"}]}"#.to_string());
        db.insert_session_row(&row).unwrap();

        let got = db.get_session(row.session_id).unwrap().unwrap();
        assert_eq!(
            got.redaction_table_json.as_deref(),
            Some(r#"{"rules":[{"kind":"literal","value":"persisted-secret-value"}]}"#)
        );
    }

    /// Push a session's `last_active_at` into the past so recency ordering is
    /// deterministic without sleeping across a whole-second timestamp boundary.
    fn backdate_session(db: &Db, session_id: Uuid, seconds: i64) {
        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET last_active_at = last_active_at - ?1 WHERE session_id = ?2",
                params![seconds, session_id.to_string()],
            )
            .context("backdating session")?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn touch_updates_last_active() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        db.touch_session(s.session_id).unwrap();
        let g = db.get_session(s.session_id).unwrap().unwrap();
        assert!(g.last_active_at >= s.last_active_at);
    }

    #[test]
    fn most_recent_open() {
        let db = Db::open_in_memory().unwrap();
        let _ = db.create_session("p", "/x", "a").unwrap();
        let s2 = db.create_session("p", "/x", "a").unwrap();
        db.end_session(s2.session_id).unwrap();
        let recent = db.most_recent_open_session_for("p").unwrap().unwrap();
        assert_ne!(recent.session_id, s2.session_id);
    }

    #[test]
    fn create_session_populates_short_id() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let sid = s.short_id.expect("short_id missing");
        assert_eq!(sid.len(), SHORT_ID_LEN);
        assert!(sid.chars().all(|c| CROCKFORD_BASE32.contains(&(c as u8))));
        let by_short = db.get_session_by_short_id("p", &sid).unwrap().unwrap();
        assert_eq!(by_short.session_id, s.session_id);
    }

    #[test]
    fn short_ids_unique_within_project() {
        let db = Db::open_in_memory().unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let s = db.create_session("p", "/x", "a").unwrap();
            assert!(seen.insert(s.short_id.unwrap()));
        }
    }

    #[test]
    fn create_session_retries_short_id_collision_at_insert() {
        let db = Db::open_in_memory().unwrap();
        set_test_short_ids(&["aaaaaa"]);
        let first = db.create_session("p", "/x", "a").unwrap();
        assert_eq!(first.short_id.as_deref(), Some("aaaaaa"));

        set_test_short_ids(&["aaaaaa", "bbbbbb"]);
        let second = db.create_session("p", "/x", "a").unwrap();
        assert_eq!(second.short_id.as_deref(), Some("bbbbbb"));
        assert_eq!(
            db.get_session(second.session_id)
                .unwrap()
                .unwrap()
                .short_id
                .as_deref(),
            Some("bbbbbb")
        );
    }

    #[test]
    fn deferred_insert_retries_and_returns_final_short_id() {
        let db = Db::open_in_memory().unwrap();
        set_test_short_ids(&["aaaaaa"]);
        let row = db.new_session_row("p", "/x", "a").unwrap();
        assert_eq!(row.short_id.as_deref(), Some("aaaaaa"));

        set_test_short_ids(&["aaaaaa"]);
        let competing = db.create_session("p", "/x", "a").unwrap();
        assert_eq!(competing.short_id.as_deref(), Some("aaaaaa"));

        set_test_short_ids(&["bbbbbb"]);
        let inserted = db.insert_session_row(&row).unwrap();
        assert_eq!(inserted.short_id.as_deref(), Some("bbbbbb"));
        let got = db.get_session(row.session_id).unwrap().unwrap();
        assert_eq!(got.short_id.as_deref(), Some("bbbbbb"));
    }

    #[test]
    fn create_fork_retries_short_id_collision_at_insert() {
        let db = Db::open_in_memory().unwrap();
        set_test_short_ids(&["aaaaaa"]);
        let parent = db.create_session("p", "/x", "a").unwrap();

        set_test_short_ids(&["aaaaaa", "bbbbbb"]);
        let fork = db.create_fork(parent.session_id, None).unwrap();
        assert_eq!(fork.short_id.as_deref(), Some("bbbbbb"));
        assert_eq!(
            db.get_session(fork.session_id)
                .unwrap()
                .unwrap()
                .short_id
                .as_deref(),
            Some("bbbbbb")
        );
    }

    #[test]
    fn ensure_short_id_retries_backfill_collision() {
        let db = Db::open_in_memory().unwrap();
        set_test_short_ids(&["aaaaaa"]);
        let existing = db.create_session("p", "/x", "a").unwrap();
        assert_eq!(existing.short_id.as_deref(), Some("aaaaaa"));

        set_test_short_ids(&["bbbbbb"]);
        let target = db.create_session("p", "/x", "a").unwrap();
        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET short_id = NULL WHERE session_id = ?1",
                [target.session_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();

        set_test_short_ids(&["aaaaaa", "cccccc"]);
        let backfilled = db.ensure_short_id(target.session_id).unwrap();
        assert_eq!(backfilled, "cccccc");
    }

    #[test]
    fn short_id_retry_exhaustion_names_the_condition() {
        let db = Db::open_in_memory().unwrap();
        set_test_short_ids(&["aaaaaa"]);
        db.create_session("p", "/x", "a").unwrap();

        set_test_short_ids(&[
            "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa",
            "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa",
            "aaaaaa", "aaaaaa",
        ]);
        let err = db.create_session("p", "/x", "a").unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("session short-id generation exhausted"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn create_fork_inherits_parent_metadata() {
        let db = Db::open_in_memory().unwrap();
        let mut parent = db.new_session_row("p", "/proj", "Build").unwrap();
        parent.provider = Some("anthropic".to_string());
        parent.model = Some("opus-4-7".to_string());
        parent.redaction_table_json = Some(
            r#"{"entries":[["fork-secret","$TEST"]],"placeholder":"[redacted]","disabled":false,"unsupported_files":[]}"#
                .to_string(),
        );
        parent.model_system_prompt_snapshot_json =
            r#"{"prompts":{"anthropic":{"opus-4-7":"fork prompt"}}}"#.to_string();
        let parent = db.insert_session_row(&parent).unwrap();
        let fork_point = record_message(&db, parent.session_id, "fork here", false).to_string();
        let parent = db.get_session(parent.session_id).unwrap().unwrap();
        let fork = db
            .create_fork(parent.session_id, Some(fork_point.clone()))
            .unwrap();

        assert_eq!(fork.project_id, "p");
        assert_eq!(fork.project_root, "/proj");
        assert_eq!(fork.active_agent, "Build");
        assert_eq!(fork.parent_session_id, Some(parent.session_id));
        assert_eq!(
            fork.fork_point_turn_id.as_deref(),
            Some(fork_point.as_str())
        );
        assert_eq!(fork.provider.as_deref(), Some("anthropic"));
        assert_eq!(fork.model.as_deref(), Some("opus-4-7"));
        assert_eq!(fork.redaction_table_json, parent.redaction_table_json);
        assert_eq!(
            fork.model_system_prompt_snapshot_json,
            parent.model_system_prompt_snapshot_json
        );
        assert_ne!(fork.session_id, parent.session_id);
        assert_ne!(fork.short_id, parent.short_id);
    }

    #[test]
    fn create_fork_copies_transcript_and_then_diverges() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        let first = db
            .insert_session_event(
                parent.session_id,
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({"text": "parent before fork"}),
            )
            .unwrap();
        db.pin_message(parent.session_id, first).unwrap();

        let fork = db.create_fork(parent.session_id, None).unwrap();
        let fork_events = db.list_session_events(fork.session_id).unwrap();
        assert_eq!(fork_events.len(), 1);
        assert_eq!(fork_events[0].data["text"], "parent before fork");
        let fork_pins = db.list_pin_seqs(fork.session_id).unwrap();
        assert_eq!(fork_pins, vec![fork_events[0].seq]);

        db.insert_session_event(
            parent.session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "parent after fork"}),
        )
        .unwrap();
        db.insert_session_event(
            fork.session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "child after fork"}),
        )
        .unwrap();

        let parent_events = db.list_session_events(parent.session_id).unwrap();
        let fork_events = db.list_session_events(fork.session_id).unwrap();
        assert_eq!(parent_events.len(), 2);
        assert_eq!(fork_events.len(), 2);
        assert_eq!(parent_events[1].data["text"], "parent after fork");
        assert_eq!(fork_events[1].data["text"], "child after fork");
    }

    #[test]
    fn copy_fork_transcript_truncates_at_seq() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        record_message(&db, parent.session_id, "s1", false);
        let fork_point = record_message(&db, parent.session_id, "s2", true);
        record_message(&db, parent.session_id, "s3", false);
        record_message(&db, parent.session_id, "s4", true);

        let fork = db
            .create_fork(parent.session_id, Some(fork_point.to_string()))
            .unwrap();
        let fork_events = db.list_session_events(fork.session_id).unwrap();
        let texts: Vec<_> = fork_events
            .iter()
            .filter_map(|row| row.data["text"].as_str())
            .collect();

        assert_eq!(texts, vec!["s1", "s2"]);
    }

    #[test]
    fn fork_event_copy_failure_rolls_back_child_session() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        record_message(&db, parent.session_id, "fail-event-copy", false);
        install_trigger(
            &db,
            "CREATE TEMP TRIGGER fail_fork_event_copy
             BEFORE INSERT ON session_events
             WHEN NEW.data_json LIKE '%fail-event-copy%'
              AND (SELECT parent_session_id FROM sessions WHERE session_id = NEW.session_id) IS NOT NULL
             BEGIN
                 SELECT RAISE(FAIL, 'injected fork event copy failure');
             END;",
        );

        let err = db.create_fork(parent.session_id, None).unwrap_err();

        assert!(
            format!("{err:#}").contains("injected fork event copy failure"),
            "unexpected error: {err:#}"
        );
        assert!(fork_rows_for_parent(&db, parent.session_id).is_empty());
    }

    #[test]
    fn fork_tool_call_copy_failure_rolls_back_child_session() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        record_tool_timeline(&db, parent.session_id, "fail-tool-copy");
        record_tool_call_event(&db, parent.session_id, "fail-tool-copy", 100);
        install_trigger(
            &db,
            "CREATE TEMP TRIGGER fail_fork_tool_copy
             BEFORE INSERT ON tool_call_events
             WHEN NEW.call_id = 'fail-tool-copy'
              AND (SELECT parent_session_id FROM sessions WHERE session_id = NEW.session_id) IS NOT NULL
             BEGIN
                 SELECT RAISE(FAIL, 'injected fork tool copy failure');
             END;",
        );

        let err = db.create_fork(parent.session_id, None).unwrap_err();

        assert!(
            format!("{err:#}").contains("injected fork tool copy failure"),
            "unexpected error: {err:#}"
        );
        assert!(fork_rows_for_parent(&db, parent.session_id).is_empty());
    }

    #[test]
    fn fork_pin_copy_failure_rolls_back_child_session() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        let seq = record_message(&db, parent.session_id, "pinned", false);
        db.pin_message(parent.session_id, seq).unwrap();
        install_trigger(
            &db,
            "CREATE TEMP TRIGGER fail_fork_pin_copy
             BEFORE INSERT ON pins
             WHEN (SELECT parent_session_id FROM sessions WHERE session_id = NEW.session_id) IS NOT NULL
             BEGIN
                 SELECT RAISE(FAIL, 'injected fork pin copy failure');
             END;",
        );

        let err = db.create_fork(parent.session_id, None).unwrap_err();

        assert!(
            format!("{err:#}").contains("injected fork pin copy failure"),
            "unexpected error: {err:#}"
        );
        assert!(fork_rows_for_parent(&db, parent.session_id).is_empty());
    }

    #[test]
    fn fork_at_tail_seq_equals_fork_none() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        record_message(&db, parent.session_id, "s1", false);
        let tail = record_message(&db, parent.session_id, "s2", true);

        let fork_at_tail = db
            .create_fork(parent.session_id, Some(tail.to_string()))
            .unwrap();
        let fork_at_none = db.create_fork(parent.session_id, None).unwrap();
        let tail_payloads: Vec<_> = db
            .list_session_events(fork_at_tail.session_id)
            .unwrap()
            .into_iter()
            .map(|row| row.data)
            .collect();
        let none_payloads: Vec<_> = db
            .list_session_events(fork_at_none.session_id)
            .unwrap()
            .into_iter()
            .map(|row| row.data)
            .collect();

        assert_eq!(tail_payloads, none_payloads);
    }

    #[test]
    fn fork_truncates_pins() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        let s1 = record_message(&db, parent.session_id, "s1", false);
        let fork_point = record_message(&db, parent.session_id, "s2", true);
        let s3 = record_message(&db, parent.session_id, "s3", false);
        db.pin_message(parent.session_id, s1).unwrap();
        db.pin_message(parent.session_id, s3).unwrap();

        let fork = db
            .create_fork(parent.session_id, Some(fork_point.to_string()))
            .unwrap();
        let fork_events = db.list_session_events(fork.session_id).unwrap();
        let fork_pins = db.list_pin_seqs(fork.session_id).unwrap();

        assert_eq!(fork_pins, vec![fork_events[0].seq]);
    }

    #[test]
    fn fork_truncates_tool_calls() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        record_message(&db, parent.session_id, "s1", false);
        record_tool_timeline(&db, parent.session_id, "keep");
        let fork_point = record_message(&db, parent.session_id, "s2", true);
        record_tool_timeline(&db, parent.session_id, "drop");
        record_tool_call_event(&db, parent.session_id, "keep", 100);
        record_tool_call_event(&db, parent.session_id, "drop", 200);

        let fork = db
            .create_fork(parent.session_id, Some(fork_point.to_string()))
            .unwrap();

        assert_eq!(fork_tool_call_ids(&db, fork.session_id), vec!["keep"]);
    }

    #[test]
    fn fork_unparsable_turn_id_errors() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        record_message(&db, parent.session_id, "s1", false);

        let err = db
            .create_fork(parent.session_id, Some("turn-x".to_string()))
            .unwrap_err();

        assert!(format!("{err:#}").contains("invalid fork point turn id"));
    }

    #[test]
    fn fork_missing_seq_errors() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        let only = record_message(&db, parent.session_id, "s1", false);

        let err = db
            .create_fork(parent.session_id, Some((only + 100).to_string()))
            .unwrap_err();

        assert!(format!("{err:#}").contains("was not found in parent session"));
    }

    #[test]
    fn list_forks_returns_children_most_recent_first() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").unwrap();
        let f1 = db.create_fork(parent.session_id, None).unwrap();
        let f2 = db.create_fork(parent.session_id, None).unwrap();
        backdate_session(&db, f1.session_id, 10);
        let forks = db.list_forks(parent.session_id).unwrap();
        assert_eq!(forks.len(), 2);
        assert_eq!(forks[0].session_id, f2.session_id);
        assert_eq!(db.count_forks_for(parent.session_id).unwrap(), 2);
    }

    #[test]
    fn rename_sets_user_renamed_and_blocks_auto_title() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        db.rename_session(s.session_id, "my-custom-title").unwrap();
        let row = db.get_session(s.session_id).unwrap().unwrap();
        assert!(row.user_renamed);
        assert_eq!(row.title.as_deref(), Some("my-custom-title"));
        let updated = db.set_auto_title(s.session_id, "robot-name").unwrap();
        assert!(!updated, "auto-title should refuse a user-renamed row");
        let row2 = db.get_session(s.session_id).unwrap().unwrap();
        assert_eq!(row2.title.as_deref(), Some("my-custom-title"));
    }

    #[test]
    fn set_auto_title_populates_unset_title() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let updated = db.set_auto_title(s.session_id, "auto-name").unwrap();
        assert!(updated);
        let row = db.get_session(s.session_id).unwrap().unwrap();
        assert!(!row.user_renamed);
        assert_eq!(row.title.as_deref(), Some("auto-name"));
    }

    #[test]
    fn explicit_auto_title_clears_user_renamed() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        db.rename_session(s.session_id, "manual-name").unwrap();
        let updated = db
            .set_explicit_auto_title(s.session_id, "generated-name")
            .unwrap();
        assert!(updated);
        let row = db.get_session(s.session_id).unwrap().unwrap();
        assert!(!row.user_renamed);
        assert_eq!(row.title.as_deref(), Some("generated-name"));
    }

    #[test]
    fn explicit_auto_title_if_untitled_has_single_winner() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let first = db
            .set_explicit_auto_title_if_untitled(s.session_id, "first-name")
            .unwrap();
        let second = db
            .set_explicit_auto_title_if_untitled(s.session_id, "second-name")
            .unwrap();
        assert!(first);
        assert!(!second);
        let row = db.get_session(s.session_id).unwrap().unwrap();
        assert!(!row.user_renamed);
        assert_eq!(row.title.as_deref(), Some("first-name"));
    }

    #[test]
    fn list_root_sessions_excludes_forks() {
        let db = Db::open_in_memory().unwrap();
        let root_a = db.create_session("p", "/x", "a").unwrap();
        let _fork_a = db.create_fork(root_a.session_id, None).unwrap();
        let _root_b = db.create_session("p", "/x", "a").unwrap();
        let roots = db.list_root_sessions("p", 100).unwrap();
        assert_eq!(roots.len(), 2);
        assert!(roots.iter().all(|r| r.parent_session_id.is_none()));
    }

    #[test]
    fn delete_session_cascade_drops_forks() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").unwrap();
        let child = db.create_fork(parent.session_id, None).unwrap();
        let grandchild = db.create_fork(child.session_id, None).unwrap();
        db.delete_session(parent.session_id, true).unwrap();
        assert!(db.get_session(parent.session_id).unwrap().is_none());
        assert!(db.get_session(child.session_id).unwrap().is_none());
        assert!(db.get_session(grandchild.session_id).unwrap().is_none());
    }

    #[test]
    fn delete_session_cascade_failure_rolls_back_deleted_descendants() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").unwrap();
        let child = db.create_fork(parent.session_id, None).unwrap();
        let grandchild = db.create_fork(child.session_id, None).unwrap();
        install_trigger(
            &db,
            &format!(
                "CREATE TEMP TRIGGER fail_cascade_delete
                 BEFORE DELETE ON sessions
                 WHEN OLD.session_id = '{}'
                 BEGIN
                     SELECT RAISE(FAIL, 'injected cascade delete failure');
                 END;",
                child.session_id
            ),
        );

        let err = db.delete_session(parent.session_id, true).unwrap_err();

        assert!(
            format!("{err:#}").contains("injected cascade delete failure"),
            "unexpected error: {err:#}"
        );
        for id in [parent.session_id, child.session_id, grandchild.session_id] {
            assert!(session_exists(&db, id), "{id} should have rolled back");
        }
    }

    #[test]
    fn delete_session_no_cascade_leaves_forks() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").unwrap();
        let child = db.create_fork(parent.session_id, None).unwrap();
        db.delete_session(parent.session_id, false).unwrap();
        assert!(db.get_session(parent.session_id).unwrap().is_none());
        // The child is still there — its parent_session_id now points at a
        // dangling id, which the application layer is expected to handle.
        assert!(db.get_session(child.session_id).unwrap().is_some());
    }

    #[test]
    fn mark_viewed_sets_marker() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        assert!(
            db.get_session(s.session_id)
                .unwrap()
                .unwrap()
                .last_viewed_at
                .is_none()
        );
        db.mark_session_viewed(s.session_id).unwrap();
        assert!(
            db.get_session(s.session_id)
                .unwrap()
                .unwrap()
                .last_viewed_at
                .is_some()
        );
    }

    #[test]
    fn archive_cascades_subtree_and_unarchive_recovers() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").unwrap();
        let child = db.create_fork(parent.session_id, None).unwrap();
        let grandchild = db.create_fork(child.session_id, None).unwrap();
        // Descendant count excludes the root itself.
        assert_eq!(db.count_descendants(parent.session_id).unwrap(), 2);

        db.archive_session(parent.session_id, true).unwrap();
        for id in [parent.session_id, child.session_id, grandchild.session_id] {
            assert!(
                db.get_session(id).unwrap().unwrap().archived_at.is_some(),
                "archive should cascade the whole subtree"
            );
        }

        // Unarchive recovers a single row (the rest stay archived).
        db.unarchive_session(parent.session_id).unwrap();
        assert!(
            db.get_session(parent.session_id)
                .unwrap()
                .unwrap()
                .archived_at
                .is_none()
        );
        assert!(
            db.get_session(child.session_id)
                .unwrap()
                .unwrap()
                .archived_at
                .is_some()
        );
    }

    #[test]
    fn archive_session_cascade_failure_rolls_back_updated_ancestors() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").unwrap();
        let child = db.create_fork(parent.session_id, None).unwrap();
        let grandchild = db.create_fork(child.session_id, None).unwrap();
        install_trigger(
            &db,
            &format!(
                "CREATE TEMP TRIGGER fail_cascade_archive
                 BEFORE UPDATE OF archived_at ON sessions
                 WHEN OLD.session_id = '{}'
                  AND NEW.archived_at IS NOT NULL
                 BEGIN
                     SELECT RAISE(FAIL, 'injected cascade archive failure');
                 END;",
                child.session_id
            ),
        );

        let err = db.archive_session(parent.session_id, true).unwrap_err();

        assert!(
            format!("{err:#}").contains("injected cascade archive failure"),
            "unexpected error: {err:#}"
        );
        for id in [parent.session_id, child.session_id, grandchild.session_id] {
            assert!(
                db.get_session(id).unwrap().unwrap().archived_at.is_none(),
                "{id} should not be archived after rollback"
            );
        }
    }

    #[test]
    fn is_in_subtree_walks_ancestors() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "a").unwrap();
        let child = db.create_fork(root.session_id, None).unwrap();
        let grandchild = db.create_fork(child.session_id, None).unwrap();
        let other = db.create_session("p", "/x", "a").unwrap();
        assert!(db.is_in_subtree(root.session_id, root.session_id).unwrap());
        assert!(db.is_in_subtree(root.session_id, child.session_id).unwrap());
        assert!(
            db.is_in_subtree(root.session_id, grandchild.session_id)
                .unwrap()
        );
        assert!(!db.is_in_subtree(root.session_id, other.session_id).unwrap());
        assert!(
            !db.is_in_subtree(child.session_id, root.session_id).unwrap(),
            "the parent is not in the child's subtree"
        );
    }

    #[test]
    fn archive_no_cascade_leaves_forks_live() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").unwrap();
        let child = db.create_fork(parent.session_id, None).unwrap();
        db.archive_session(parent.session_id, false).unwrap();
        assert!(
            db.get_session(parent.session_id)
                .unwrap()
                .unwrap()
                .archived_at
                .is_some()
        );
        assert!(
            db.get_session(child.session_id)
                .unwrap()
                .unwrap()
                .archived_at
                .is_none()
        );
    }

    #[test]
    fn list_session_summaries_scopes_orders_and_groups_forks() {
        // The factored query is the single source of truth for the
        // `/sessions` browser (daemon RPC + TUI daemonless). Assert the
        // three level selections produce the same shape the daemon handler
        // used: project-scoped roots newest-first, forks grouped under a
        // parent, fork/descendant counts, and the all-projects fallback.
        let db = Db::open_in_memory().unwrap();
        let root_a = db.create_session("pid", "/proj", "builder").unwrap();
        let root_b = db.create_session("pid", "/proj", "builder").unwrap();
        backdate_session(&db, root_a.session_id, 10);
        // A session in a different project must not leak into `pid` scope.
        let _other = db.create_session("pid2", "/other", "builder").unwrap();
        // Two forks under root_a (one of them with its own descendant).
        let fork_1 = db.create_fork(root_a.session_id, None).unwrap();
        let _grandchild = db.create_fork(fork_1.session_id, None).unwrap();

        // Project-scoped roots: only `pid` roots, newest (`root_b`) first.
        let roots = db.list_session_summaries(Some("pid"), None, 100).unwrap();
        let root_ids: Vec<_> = roots.iter().map(|s| s.session_id).collect();
        assert_eq!(root_ids, vec![root_b.session_id, root_a.session_id]);
        // root_a has 2 direct forks and 3 descendants (2 forks + 1 grand).
        let a = roots
            .iter()
            .find(|s| s.session_id == root_a.session_id)
            .unwrap();
        assert_eq!(a.fork_count, 1, "one direct fork under root_a");
        assert_eq!(a.descendant_count, 2, "fork + grandchild are descendants");
        assert_eq!(a.project_id, "pid");

        // Fork grouping: parent = root_a → its direct forks only.
        let forks = db
            .list_session_summaries(None, Some(root_a.session_id), 100)
            .unwrap();
        assert_eq!(forks.len(), 1);
        assert_eq!(forks[0].session_id, fork_1.session_id);
        assert_eq!(forks[0].parent_session_id, Some(root_a.session_id));

        // All-projects fallback (both args None) spans every project.
        let all = db.list_session_summaries(None, None, 100).unwrap();
        let project_ids: std::collections::HashSet<_> =
            all.iter().map(|s| s.project_id.as_str()).collect();
        assert!(project_ids.contains("pid"));
        assert!(project_ids.contains("pid2"));
    }

    #[test]
    fn list_session_summaries_conn_matches_db_wrapper() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("pid", "/proj", "builder").unwrap();
        let _fork = db.create_fork(root.session_id, None).unwrap();

        let wrapped = db.list_session_summaries(Some("pid"), None, 100).unwrap();
        let direct = db
            .read_blocking(|conn| Db::list_session_summaries_conn(conn, Some("pid"), None, 100))
            .unwrap();

        assert_eq!(
            serde_json::to_value(&direct).unwrap(),
            serde_json::to_value(&wrapped).unwrap()
        );
    }

    #[test]
    fn list_session_summaries_populates_interrupt_activity_state() {
        use crate::db::wire::{InterruptQuestion, InterruptQuestionSet, SessionActivityState};

        let db = Db::open_in_memory().unwrap();
        let pending = db.create_session("pid", "/proj", "builder").unwrap();
        let parked = db.create_session("pid", "/proj", "builder").unwrap();
        let interrupted = db.create_session("pid", "/proj", "builder").unwrap();
        db.raise_interrupt_questions(
            pending.session_id,
            "builder",
            "question",
            &InterruptQuestionSet {
                questions: vec![InterruptQuestion::Freetext {
                    prompt: "Name?".into(),
                    masked: false,
                }],
            },
        )
        .unwrap();
        db.raise_interrupt_questions(
            parked.session_id,
            "builder",
            "approval",
            &InterruptQuestionSet {
                questions: vec![InterruptQuestion::Single {
                    prompt: "Run?".into(),
                    options: Vec::new(),
                    allow_freetext: false,
                    command_detail: None,
                    permission: true,
                    approval_class: None,
                    sandbox_escalation: None,
                }],
            },
        )
        .unwrap();
        let interrupted_id = db
            .raise_interrupt_questions(
                interrupted.session_id,
                "builder",
                "approval",
                &InterruptQuestionSet {
                    questions: vec![InterruptQuestion::Freetext {
                        prompt: "Name?".into(),
                        masked: false,
                    }],
                },
            )
            .unwrap();
        db.mark_interrupt_interrupted(interrupted_id).unwrap();

        let summaries = db.list_session_summaries(Some("pid"), None, 100).unwrap();
        let pending_summary = summaries
            .iter()
            .find(|summary| summary.session_id == pending.session_id)
            .unwrap();
        assert_eq!(
            pending_summary.activity_state,
            Some(SessionActivityState::PendingQuestion)
        );
        let parked_summary = summaries
            .iter()
            .find(|summary| summary.session_id == parked.session_id)
            .unwrap();
        assert_eq!(
            parked_summary.activity_state,
            Some(SessionActivityState::Parked)
        );
        let interrupted_summary = summaries
            .iter()
            .find(|summary| summary.session_id == interrupted.session_id)
            .unwrap();
        assert_eq!(
            interrupted_summary.activity_state,
            Some(SessionActivityState::Interrupted)
        );
    }

    #[test]
    fn list_session_summaries_prefers_actionable_interrupt_over_stale_interrupted_marker() {
        use crate::db::wire::{InterruptQuestion, InterruptQuestionSet, SessionActivityState};

        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("pid", "/proj", "builder").unwrap();
        db.raise_interrupted_turn(session.session_id, "builder", "forced drain")
            .unwrap();
        db.raise_interrupt_questions(
            session.session_id,
            "builder",
            "question",
            &InterruptQuestionSet {
                questions: vec![InterruptQuestion::Freetext {
                    prompt: "Name?".into(),
                    masked: false,
                }],
            },
        )
        .unwrap();

        let summaries = db.list_session_summaries(Some("pid"), None, 100).unwrap();
        let summary = summaries
            .iter()
            .find(|summary| summary.session_id == session.session_id)
            .unwrap();
        assert_eq!(
            summary.activity_state,
            Some(SessionActivityState::PendingQuestion)
        );
    }

    #[test]
    fn session_summary_fallbacks_warn_and_keep_defaults() {
        let session_id = Uuid::new_v4();
        let log = capture_warn_log(|| {
            assert_eq!(
                summary_count_or_zero(session_id, "fork_count", Err(anyhow::anyhow!("forks"))),
                0
            );
            assert_eq!(
                summary_latest_activity_or_none(session_id, Err(anyhow::anyhow!("activity"))),
                None
            );
            assert_eq!(
                summary_open_interrupt_count_or_zero::<()>(
                    session_id,
                    Err(anyhow::anyhow!("interrupts"))
                ),
                0
            );
            assert_eq!(
                summary_pin_count_or_zero(session_id, Err(anyhow::anyhow!("pins"))),
                0
            );
        });

        assert!(log.contains(&session_id.to_string()));
        assert!(log.contains("fork_count"));
        assert!(log.contains("latest_activity_at"));
        assert!(log.contains("open_interrupts"));
        assert!(log.contains("pin_count"));
    }

    #[test]
    fn ensure_short_id_backfills_null() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        // Simulate a pre-0002 row by clearing the short_id.
        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET short_id = NULL WHERE session_id = ?1",
                [s.session_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();
        let backfilled = db.ensure_short_id(s.session_id).unwrap();
        assert_eq!(backfilled.len(), SHORT_ID_LEN);
        // Idempotent: a second call returns the same id, doesn't churn.
        let again = db.ensure_short_id(s.session_id).unwrap();
        assert_eq!(again, backfilled);
    }

    // ---- `/side` ephemeral side-conversation forks (migration 0017) -------

    #[test]
    fn create_ephemeral_fork_marks_row_ephemeral() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").unwrap();
        let fork_point = record_message(&db, parent.session_id, "fork here", false);
        let side = db
            .create_ephemeral_fork(parent.session_id, Some(fork_point.to_string()))
            .unwrap();
        assert!(side.ephemeral, "side fork row should be ephemeral");
        assert_eq!(side.parent_session_id, Some(parent.session_id));
        let stored = db.get_session(side.session_id).unwrap().unwrap();
        assert!(stored.ephemeral);
        // A plain fork is NOT ephemeral.
        let plain = db.create_fork(parent.session_id, None).unwrap();
        assert!(!plain.ephemeral);
    }

    #[test]
    fn ephemeral_sessions_excluded_from_all_list_queries() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "a").unwrap();
        let _side = db.create_ephemeral_fork(root.session_id, None).unwrap();

        // Root listing: only the persisted root, no ephemeral fork.
        let roots = db.list_root_sessions("p", 100).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].session_id, root.session_id);

        // Direct-forks listing of the parent: the ephemeral fork is hidden.
        let forks = db.list_forks(root.session_id).unwrap();
        assert!(
            forks.is_empty(),
            "ephemeral fork must not appear in list_forks"
        );
        assert_eq!(db.count_forks_for(root.session_id).unwrap(), 0);

        // Flat open-session list (`cockpit session list`).
        let open = db.list_sessions(true, 100).unwrap();
        assert!(open.iter().all(|s| !s.ephemeral));
        assert_eq!(open.len(), 1);

        // `cockpit -c` continue: never resumes the ephemeral fork.
        let recent = db.most_recent_open_session_for("p").unwrap().unwrap();
        assert_eq!(recent.session_id, root.session_id);

        // Browser summaries (the daemon + daemonless shared path).
        let summaries = db.list_session_summaries(Some("p"), None, 100).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].fork_count, 0);
    }

    #[test]
    fn ephemeral_sessions_are_never_auto_titled() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").unwrap();
        let side = db.create_ephemeral_fork(parent.session_id, None).unwrap();
        let updated = db.set_auto_title(side.session_id, "auto-name").unwrap();
        assert!(!updated, "auto-title must refuse an ephemeral row");
        let row = db.get_session(side.session_id).unwrap().unwrap();
        assert!(row.title.is_none());
    }

    #[test]
    fn discard_ephemeral_session_removes_row_and_guards_persisted() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").unwrap();
        let side = db.create_ephemeral_fork(parent.session_id, None).unwrap();

        // Discarding the ephemeral fork drops its row.
        assert!(db.discard_ephemeral_session(side.session_id).unwrap());
        assert!(db.get_session(side.session_id).unwrap().is_none());

        // Guard: discarding a *persisted* session is a no-op, leaves it intact.
        assert!(!db.discard_ephemeral_session(parent.session_id).unwrap());
        assert!(db.get_session(parent.session_id).unwrap().is_some());

        // Unknown id is a no-op, not an error.
        assert!(!db.discard_ephemeral_session(Uuid::new_v4()).unwrap());
    }

    #[test]
    fn sweep_ephemeral_sessions_clears_orphans_only() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "a").unwrap();
        let _plain_fork = db.create_fork(root.session_id, None).unwrap();
        let side_a = db.create_ephemeral_fork(root.session_id, None).unwrap();
        let side_b = db.create_ephemeral_fork(root.session_id, None).unwrap();

        let removed = db.sweep_ephemeral_sessions().unwrap();
        assert_eq!(removed, 2);
        assert!(db.get_session(side_a.session_id).unwrap().is_none());
        assert!(db.get_session(side_b.session_id).unwrap().is_none());
        // The persisted root + its plain fork survive the sweep.
        assert!(db.get_session(root.session_id).unwrap().is_some());
        assert_eq!(db.count_forks_for(root.session_id).unwrap(), 1);
    }

    #[test]
    fn btw_fork_seeded_to_ceiling() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        record_message(&db, parent.session_id, "first", false);
        record_message(&db, parent.session_id, "second", true);

        let result = db.create_btw_fork(parent.session_id, false).unwrap();

        assert!(result.created);
        assert_eq!(result.info.parent_session_id, parent.session_id);
        assert!(!result.info.tangent);
        assert_eq!(result.info.message_count, 2);
        let events = db.list_session_events(result.info.session_id).unwrap();
        let texts: Vec<_> = events
            .iter()
            .map(|event| event.data["text"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(texts, vec!["first", "second"]);
    }

    #[test]
    fn btw_tangent_fork_empty() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        record_message(&db, parent.session_id, "parent context", false);

        let result = db.create_btw_fork(parent.session_id, true).unwrap();

        assert!(result.created);
        assert!(result.info.tangent);
        assert_eq!(result.info.message_count, 0);
        assert!(
            db.list_session_events(result.info.session_id)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn btw_schema_enforces_one_live_fork() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();

        let first = db.create_btw_fork(parent.session_id, false).unwrap();
        let second = db.create_btw_fork(parent.session_id, true).unwrap();

        assert!(first.created);
        assert!(!second.created);
        assert_eq!(first.info.session_id, second.info.session_id);
        assert!(!second.info.tangent, "existing fork identity wins");
        assert!(
            db.list_sessions(false, 100)
                .unwrap()
                .iter()
                .all(|row| row.session_id != first.info.session_id)
        );
        let direct_count: i64 = db
            .read_blocking(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM sessions WHERE btw_parent_session_id = ?1",
                    [parent.session_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(anyhow::Error::from)
            })
            .unwrap();
        assert_eq!(direct_count, 1);
    }

    #[test]
    fn btw_create_is_atomic_and_unique() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let mut joins = Vec::new();
        for tangent in [false, true] {
            let db = db.clone();
            let barrier = barrier.clone();
            let parent_id = parent.session_id;
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                db.create_btw_fork(parent_id, tangent).unwrap()
            }));
        }

        let first = joins.remove(0).join().unwrap();
        let second = joins.remove(0).join().unwrap();
        assert_eq!(first.info.session_id, second.info.session_id);
        assert_ne!(first.created, second.created);
        let direct_count: i64 = db
            .read_blocking(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM sessions WHERE btw_parent_session_id = ?1",
                    [parent.session_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(anyhow::Error::from)
            })
            .unwrap();
        assert_eq!(direct_count, 1);
    }

    #[test]
    fn btw_orphan_sweep_spares_live_fork() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        let side = db.create_ephemeral_fork(parent.session_id, None).unwrap();
        let btw = db.create_btw_fork(parent.session_id, false).unwrap();

        let removed = db.sweep_ephemeral_sessions().unwrap();

        assert_eq!(removed, 1);
        assert!(db.get_session(side.session_id).unwrap().is_none());
        assert!(db.get_session(btw.info.session_id).unwrap().is_some());
    }

    #[test]
    fn btw_end_discards_fork() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        let btw = db.create_btw_fork(parent.session_id, false).unwrap();

        assert!(db.end_btw_fork(parent.session_id).unwrap());
        assert!(db.get_session(btw.info.session_id).unwrap().is_none());
        assert!(!db.end_btw_fork(parent.session_id).unwrap());
    }

    #[test]
    fn btw_parent_delete_cascades() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").unwrap();
        let btw = db.create_btw_fork(parent.session_id, false).unwrap();

        db.delete_session(parent.session_id, true).unwrap();

        assert!(db.get_session(parent.session_id).unwrap().is_none());
        assert!(db.get_session(btw.info.session_id).unwrap().is_none());
    }

    #[test]
    fn sweep_ephemeral_sessions_warns_on_delete_failure_and_continues() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "a").unwrap();
        let blocked = db.create_ephemeral_fork(root.session_id, None).unwrap();
        let removed = db.create_ephemeral_fork(root.session_id, None).unwrap();
        db.write_blocking(move |conn| {
            conn.execute_batch(&format!(
                "CREATE TRIGGER block_ephemeral_delete
                 BEFORE DELETE ON sessions
                 WHEN OLD.session_id = '{}'
                 BEGIN
                   SELECT RAISE(FAIL, 'blocked delete');
                 END",
                blocked.session_id
            ))?;
            Ok(())
        })
        .unwrap();

        let log = capture_warn_log(|| {
            assert_eq!(db.sweep_ephemeral_sessions().unwrap(), 1);
        });

        assert!(log.contains("ephemeral session sweep delete failed"));
        assert!(log.contains(&blocked.session_id.to_string()));
        assert!(db.get_session(blocked.session_id).unwrap().is_some());
        assert!(db.get_session(removed.session_id).unwrap().is_none());
    }
}
