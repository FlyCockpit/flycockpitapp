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

/// A fork was refused because the parent session owns scoped sealed values.
///
/// Typed and downcastable so a caller can render this specific reason rather
/// than a generic failure: `error.downcast_ref::<SessionForkRefusedSealed>()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionForkRefusedSealed {
    pub parent_session_id: Uuid,
    pub scoped_value_count: i64,
}

impl std::fmt::Display for SessionForkRefusedSealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "session {} cannot be forked: it owns {} scoped sealed value(s), \
             and forking them has no defined semantics yet",
            self.parent_session_id, self.scoped_value_count
        )
    }
}

impl std::error::Error for SessionForkRefusedSealed {}

/// Count the scoped sealed value records a session owns.
///
/// Session scope keys its records by the session id. Project- and
/// global-scope values are not owned by any session and so never block a
/// fork. Soft-deleted rows are deliberately **not** excluded: a record mid
/// delete is precisely the ambiguous state a fork must not have to reason
/// about, so it fails closed too.
fn scoped_sealed_value_count(conn: &Connection, session_id: Uuid) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM sealed_value_records
          WHERE scope = 'session' AND scope_key = ?1",
        params![session_id.to_string()],
        |row| row.get(0),
    )
    .context("checking parent session for scoped sealed values")
}

/// Refuse to copy sealed values into a fork when the parent owns scoped ones.
///
/// The invariant being protected is about **inheritance, not coexistence**: a
/// child session must never come to hold sealed state it cannot correctly
/// represent. A parent may perfectly well own scoped values while some
/// earlier fork of it exists — that fork inherited nothing scoped, so nothing
/// is undefined about it. What must never happen is a *copy* handing a child
/// a scoped value's literal without its record, grants, or tombstone.
///
/// So this is called immediately before the copy, not at the fork entry
/// points. Any future path reaching that copy is guarded by construction.
///
/// Copying the legacy `sealed_values` rows is fine and unchanged: they predate
/// the scoped subsystem and are self-contained, so a session holding only
/// legacy rows still forks normally. A *scoped* value has no defined fork
/// semantics — whether the child inherits the parent's action grants, what to
/// do with an in-flight lifecycle saga, and whether a rotated value yields
/// pre- or post-rotation state are all open questions. Guessing at exactly
/// this kind of saga interaction is what produced the delete-versus-rotation
/// defect in this subsystem, so this fails closed with a typed error until a
/// fork semantics is designed deliberately.
fn refuse_fork_with_scoped_sealed_values(conn: &Connection, parent_session_id: Uuid) -> Result<()> {
    let scoped_value_count = scoped_sealed_value_count(conn, parent_session_id)?;
    if scoped_value_count > 0 {
        return Err(anyhow::Error::new(SessionForkRefusedSealed {
            parent_session_id,
            scoped_value_count,
        }));
    }
    Ok(())
}

/// Crockford base32 alphabet, lowercased. Excludes I/L/O/U for visual
/// disambiguation. Used for 6-char session display ids (GOALS §17b).
const CROCKFORD_BASE32: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Length of a session's human-display short id, in characters.
pub const SHORT_ID_LEN: usize = 6;

/// Durable one-shot recovery-nudge latch for a session whose automatic
/// title attempt failed (issue #23). The closed domain mirrors the
/// `title_recovery_nudge_state` CHECK constraint in `0001_initial.sql`. It
/// carries NO title text, prompt, or provider body — only the latch position,
/// so a post-failure Monty nudge can survive a daemon restart and be consumed
/// exactly once before main-model dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TitleRecoveryNudgeState {
    /// No pending recovery nudge — the default at creation and the state a
    /// stored title returns the latch to.
    None,
    /// A title failure armed a nudge that has not yet been consumed.
    Pending,
    /// The nudge was atomically claimed before main-model dispatch.
    Consumed,
}

impl TitleRecoveryNudgeState {
    pub const ALL: [Self; 3] = [Self::None, Self::Pending, Self::Consumed];

    /// The integer encoding stored in `sessions.title_recovery_nudge_state`.
    pub fn as_i64(self) -> i64 {
        match self {
            Self::None => 0,
            Self::Pending => 1,
            Self::Consumed => 2,
        }
    }

    /// Decode the stored integer. `None` for any value outside the closed
    /// domain so a corrupt row fails loudly rather than defaulting silently.
    pub fn from_i64(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Pending),
            2 => Some(Self::Consumed),
            _ => None,
        }
    }
}

fn nudge_state_from_sql(value: i64) -> rusqlite::Result<TitleRecoveryNudgeState> {
    TitleRecoveryNudgeState::from_i64(value).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid title_recovery_nudge_state {value}"),
            )),
        )
    })
}

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
    /// Full daemon-owned session model selection. Kept alongside the indexed
    /// provider/model projection so reasoning, thinking, and cache choices
    /// survive resume without making cockpit-db depend on cockpit-config.
    pub model_selection_json: Option<String>,
    /// Monotonic CAS token advanced on every durable active-model mutation.
    pub active_model_revision: i64,
    pub session_llm_mode: Option<String>,
    pub tool_surface_override_json: Option<String>,
    pub goal_settings_override_json: Option<String>,
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
    /// Durable one-shot post-auto-title-failure recovery nudge latch (issue
    /// #23). Defaults [`TitleRecoveryNudgeState::None`]; never inherited by a
    /// fork/tangent/copy, and cleared whenever a title is successfully stored.
    pub title_recovery_nudge_state: TitleRecoveryNudgeState,
    /// Frozen guidance baseline path/hash copied into forks so live guidance
    /// diffs continue from the same system-instruction baseline.
    pub guidance_baseline_path: Option<String>,
    pub guidance_baseline_hash: Option<String>,
    pub redaction_table_json: Option<String>,
    pub model_system_prompt_snapshot_json: String,
    pub created_by_principal: Option<String>,
    pub shared_with_collaborators: bool,
    /// Session lifecycle barrier. `active` accepts work; `deleting` rejects new
    /// work until every bound execution containment is ProvenEmpty.
    pub lifecycle: String,
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
            model_selection_json: row.get("model_selection_json")?,
            active_model_revision: row.get::<_, i64>("active_model_revision").unwrap_or(0),
            session_llm_mode: row.get("session_llm_mode").unwrap_or(None),
            tool_surface_override_json: row.get("tool_surface_override_json").unwrap_or(None),
            goal_settings_override_json: row.get("goal_settings_override_json").unwrap_or(None),
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
            title_recovery_nudge_state: nudge_state_from_sql(
                row.get("title_recovery_nudge_state")?,
            )?,
            guidance_baseline_path: row.get("guidance_baseline_path")?,
            guidance_baseline_hash: row.get("guidance_baseline_hash")?,
            redaction_table_json: row.get("redaction_table_json")?,
            model_system_prompt_snapshot_json: row
                .get("model_system_prompt_snapshot_json")
                .unwrap_or_else(|_| "{}".to_string()),
            created_by_principal: row.get("created_by_principal")?,
            shared_with_collaborators: row.get::<_, i64>("shared_with_collaborators")? != 0,
            lifecycle: row
                .get::<_, String>("lifecycle")
                .unwrap_or_else(|_| "active".to_string()),
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
fn test_short_ids()
-> &'static std::sync::Mutex<std::collections::HashMap<usize, std::collections::VecDeque<String>>> {
    static TEST_SHORT_IDS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, std::collections::VecDeque<String>>>,
    > = std::sync::OnceLock::new();
    TEST_SHORT_IDS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
fn set_test_short_ids_conn(conn: &Connection, ids: Vec<String>) {
    let mut queues = test_short_ids().lock().unwrap();
    queues.insert(
        conn as *const Connection as usize,
        ids.into_iter().collect(),
    );
}

#[cfg(test)]
fn pop_test_short_id(conn: &Connection) -> Option<String> {
    let mut queues = test_short_ids().lock().unwrap();
    let key = conn as *const Connection as usize;
    let queue = queues.get_mut(&key)?;
    let id = queue.pop_front();
    if queue.is_empty() {
        queues.remove(&key);
    }
    id
}

#[cfg(test)]
async fn set_test_short_ids(db: &Db, ids: &[&str]) {
    let ids = ids.iter().map(|id| (*id).to_string()).collect::<Vec<_>>();
    db.write(move |conn| {
        set_test_short_ids_conn(conn, ids);
        Ok(())
    })
    .await
    .unwrap();
}

/// Generate a 6-char short id that doesn't collide within `project_id`.
/// 32^6 ≈ 1.07e9 namespace; collisions are astronomically rare even at
/// hundreds of thousands of sessions per project. The retry loop is a
/// belt-and-braces guard.
fn generate_unique_short_id(conn: &Connection, project_id: &str) -> rusqlite::Result<String> {
    for _ in 0..16 {
        let candidate = short_id_candidate(conn);
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

fn short_id_candidate(conn: &Connection) -> String {
    #[cfg(test)]
    {
        pop_test_short_id(conn).unwrap_or_else(random_short_id)
    }
    #[cfg(not(test))]
    {
        let _ = conn;
        random_short_id()
    }
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

fn execute_session_insert(conn: &Connection, row: &SessionRow) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO sessions
         (session_id, project_id, project_root, started_at, last_active_at, active_agent,
          short_id, provider, model, model_selection_json, active_model_revision,
          session_llm_mode,
          tool_surface_override_json, goal_settings_override_json, guidance_baseline_path,
          guidance_baseline_hash, redaction_table_json, model_system_prompt_snapshot_json,
          assistant_name, created_by_principal, shared_with_collaborators)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
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
            row.model_selection_json,
            row.active_model_revision,
            row.session_llm_mode,
            row.tool_surface_override_json,
            row.goal_settings_override_json,
            row.guidance_baseline_path,
            row.guidance_baseline_hash,
            row.redaction_table_json,
            row.model_system_prompt_snapshot_json,
            row.assistant_name,
            row.created_by_principal,
            row.shared_with_collaborators as i64,
        ],
    )?;
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
          provider, model, session_llm_mode, tool_surface_override_json,
          goal_settings_override_json, ephemeral, user_content_tokens, title_stage,
          title_recovery_nudge_state,
          guidance_baseline_path, guidance_baseline_hash, redaction_table_json, created_by_principal,
          shared_with_collaborators, btw_parent_session_id, btw_tangent, model_selection_json,
          model_system_prompt_snapshot_json, assistant_name, active_model_revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29)",
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
            row.session_llm_mode,
            row.tool_surface_override_json,
            row.goal_settings_override_json,
            row.ephemeral as i64,
            row.user_content_tokens,
            row.title_stage,
            row.title_recovery_nudge_state.as_i64(),
            row.guidance_baseline_path,
            row.guidance_baseline_hash,
            row.redaction_table_json,
            row.created_by_principal,
            row.shared_with_collaborators as i64,
            row.btw_parent_session_id.map(|id| id.to_string()),
            row.btw_tangent as i64,
            row.model_selection_json,
            row.model_system_prompt_snapshot_json,
            row.assistant_name,
            row.active_model_revision,
        ],
    )?;
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
            short_id_candidate(conn)
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
        model_selection_json: None,
        active_model_revision: 0,
        session_llm_mode: None,
        tool_surface_override_json: None,
        goal_settings_override_json: None,
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
        // A brand-new session never carries a recovery nudge.
        title_recovery_nudge_state: TitleRecoveryNudgeState::None,
        guidance_baseline_path: None,
        guidance_baseline_hash: None,
        redaction_table_json: None,
        model_system_prompt_snapshot_json: "{}".to_string(),
        created_by_principal: None,
        shared_with_collaborators: false,
        lifecycle: "active".to_string(),
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

    crate::db::text_artifacts::fork_session_artifacts_conn(
        conn,
        parent_session_id,
        child_session_id,
        &seq_pairs,
    )
    .context("copying fork text artifacts")?;

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

/// Delete a session, first recording an external side-effect tombstone.
///
/// Session deletion cannot delete unresolved external operations: a provider
/// may already have accepted work on this session's behalf, and the record has
/// to survive so late evidence still resolves it exactly once. The tombstone
/// is what lets resolution after deletion emit owner-visible recovery status
/// without recreating session content. It is written in the caller's
/// transaction, so a session can never be removed without one.
pub fn delete_session_conn(conn: &Connection, session_id: Uuid) -> Result<()> {
    #[cfg(windows)]
    for member in collect_subtree(conn, session_id)? {
        let sidecars: i64 = conn.query_row(
            "SELECT COUNT(*) FROM task_delegation_payloads
              WHERE parent_session_id=?1 AND sidecar_path IS NOT NULL",
            [member.to_string()],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            sidecars == 0,
            "session deletion with delegation sidecars is unavailable on Windows until durable reparse-safe cleanup is supported"
        );
    }
    // Media metadata may cascade only after owned bytes have independently
    // reached a deletion-evidenced terminal. Starting cleanup is owned by the
    // media storage orchestrator; this DB boundary is the final fail-closed
    // guard for every current and future session-deletion caller.
    let mut unsafe_media = 0_i64;
    for member in collect_subtree(conn, session_id)? {
        unsafe_media += conn
            .query_row(
                "SELECT COUNT(*) FROM media_attachments a
                  WHERE a.session_id=?1 AND (
                    a.availability NOT IN ('retained_copy_deleted','borrowed_derivatives_deleted','metadata_deleted')
                    OR EXISTS(SELECT 1 FROM media_attachment_components c
                               WHERE c.attachment_id=a.attachment_id AND c.lifecycle_state<>'deleted'))",
                [member.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .context("checking session media deletion barrier")?;
    }
    anyhow::ensure!(
        unsafe_media == 0,
        "session media cleanup must complete before session deletion"
    );
    // The delete cascades to descendant forks and `/btw` rows, so every member
    // of the cascade set needs a tombstone — not just the requested root. A
    // descendant deleted without one loses the owner-visible marker for its
    // unresolved external operations, which survive the deletion.
    let now_ms = crate::db::session_log::now_ms();
    for member in collect_subtree(conn, session_id)? {
        crate::db::external_journal::tombstone_external_journal_session_id_conn(
            conn, member, now_ms,
        )
        .context("recording external journal session tombstone")?;
    }
    conn.execute(
        "DELETE FROM sessions WHERE session_id = ?1",
        [session_id.to_string()],
    )
    .context("deleting session")?;
    Ok(())
}

impl Db {
    pub async fn create_session(
        &self,
        project_id: &str,
        project_root: &str,
        active_agent: &str,
    ) -> Result<SessionRow> {
        let project_id = project_id.to_string();
        let project_root = project_root.to_string();
        let active_agent = active_agent.to_string();
        self.write(move |conn| {
            let row =
                Self::build_new_session_row_conn(conn, &project_id, &project_root, &active_agent)?;
            Self::insert_session_row_conn(conn, &row)
        })
        .await
    }

    /// Build a brand-new session row — fresh UUID + project-unique
    /// provisional short_id — **without** writing it to the DB. Used by the
    /// lazy-persistence path (session-id-display-and-lazy-persist): the
    /// daemon holds the row in memory and only [`Self::insert_session_row`]s
    /// it on the first user message, so an opened-but-unused session leaves
    /// no DB trace. The short_id is checked against the live table at build
    /// time for a useful display value; the eventual INSERT is the reservation
    /// point and may retry with a different final short_id.
    pub async fn new_session_row(
        &self,
        project_id: &str,
        project_root: &str,
        active_agent: &str,
    ) -> Result<SessionRow> {
        let project_id = project_id.to_string();
        let project_root = project_root.to_string();
        let active_agent = active_agent.to_string();
        self.read(move |conn| {
            Self::build_new_session_row_conn(conn, &project_id, &project_root, &active_agent)
        })
        .await
    }

    pub fn build_new_session_row_conn(
        conn: &Connection,
        project_id: &str,
        project_root: &str,
        active_agent: &str,
    ) -> Result<SessionRow> {
        let short_id =
            generate_unique_short_id(conn, project_id).context("generating session short_id")?;
        Ok(Self::new_session_row_conn(
            project_id,
            project_root,
            active_agent,
            short_id,
        ))
    }

    fn new_session_row_conn(
        project_id: &str,
        project_root: &str,
        active_agent: &str,
        short_id: String,
    ) -> SessionRow {
        build_session_row(project_id, project_root, active_agent, Some(short_id), None)
    }

    pub async fn create_assistant_session(
        &self,
        project_id: &str,
        project_root: &str,
        active_agent: &str,
        assistant_name: &str,
    ) -> Result<SessionRow> {
        let project_id = project_id.to_string();
        let project_root = project_root.to_string();
        let active_agent = active_agent.to_string();
        let assistant_name = assistant_name.to_string();
        self.write(move |conn| {
            let row = Self::build_new_assistant_session_row_conn(
                conn,
                &project_id,
                &project_root,
                &active_agent,
                &assistant_name,
            )?;
            Self::insert_session_row_conn(conn, &row)
        })
        .await
    }

    pub async fn new_assistant_session_row(
        &self,
        project_id: &str,
        project_root: &str,
        active_agent: &str,
        assistant_name: &str,
    ) -> Result<SessionRow> {
        let project_id = project_id.to_string();
        let project_root = project_root.to_string();
        let active_agent = active_agent.to_string();
        let assistant_name = assistant_name.to_string();
        self.read(move |conn| {
            Self::build_new_assistant_session_row_conn(
                conn,
                &project_id,
                &project_root,
                &active_agent,
                &assistant_name,
            )
        })
        .await
    }

    pub fn build_new_assistant_session_row_conn(
        conn: &Connection,
        project_id: &str,
        project_root: &str,
        active_agent: &str,
        assistant_name: &str,
    ) -> Result<SessionRow> {
        let short_id =
            generate_unique_short_id(conn, project_id).context("generating session short_id")?;
        Ok(Self::new_assistant_session_row_conn(
            project_id,
            project_root,
            active_agent,
            assistant_name,
            short_id,
        ))
    }

    fn new_assistant_session_row_conn(
        project_id: &str,
        project_root: &str,
        active_agent: &str,
        assistant_name: &str,
        short_id: String,
    ) -> SessionRow {
        build_session_row(
            project_id,
            project_root,
            active_agent,
            Some(short_id),
            Some(assistant_name.to_string()),
        )
    }

    /// Insert a pre-built root session row. Pairs with
    /// [`Self::new_session_row`] for the deferred-persistence path; also the
    /// second half of [`Self::create_session`]. Idempotent at the
    /// application layer is **not** assumed — callers persist exactly once.
    pub async fn insert_session_row(&self, row: &SessionRow) -> Result<SessionRow> {
        let row = row.clone();
        self.write(move |conn| Self::insert_session_row_conn(conn, &row))
            .await
    }

    pub fn insert_session_row_conn(conn: &Connection, row: &SessionRow) -> Result<SessionRow> {
        insert_session_row_with_short_id_retry(conn, row.clone()).context("inserting session")
    }

    pub async fn set_session_created_by_principal(
        &self,
        session_id: Uuid,
        principal: Option<&str>,
    ) -> Result<()> {
        let principal = principal.map(str::to_owned);
        self.write(move |conn| {
            Self::set_session_created_by_principal_conn(conn, session_id, principal.as_deref())
        })
        .await
    }

    /// Connection-direct `created_by_principal` write for callers already
    /// inside a transaction (e.g. the transactional remote-operation ledger
    /// writer creating a fork in the same commit as its replay record).
    pub fn set_session_created_by_principal_conn(
        conn: &Connection,
        session_id: Uuid,
        principal: Option<&str>,
    ) -> Result<()> {
        conn.execute(
            "UPDATE sessions SET created_by_principal = ?1 WHERE session_id = ?2",
            params![principal, session_id.to_string()],
        )
        .context("setting session created_by_principal")?;
        Ok(())
    }

    /// Create a fork session branching from `parent_session_id` at
    /// `fork_point_turn_id` (None = tail). Inherits the parent's
    /// project_id, project_root, active_agent, provider, model.
    /// Returns the new session row (with a fresh UUID + short_id).
    pub async fn create_fork(
        &self,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
    ) -> Result<SessionRow> {
        self.create_fork_inner(parent_session_id, fork_point_turn_id, false)
            .await
    }

    /// Create an **ephemeral** side-conversation fork (`/side`). Identical
    /// to [`Self::create_fork`] but marks the row `ephemeral = 1`, so it is
    /// excluded from every list query, never auto-titled, never resumable,
    /// and discarded when the side conversation ends / its process exits.
    pub async fn create_ephemeral_fork(
        &self,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
    ) -> Result<SessionRow> {
        self.create_fork_inner(parent_session_id, fork_point_turn_id, true)
            .await
    }

    /// Create or return the one live persistent `/btw` fork for
    /// `parent_session_id`. The fork is hidden from session lists like an
    /// ephemeral `/side` fork, but it is not swept on boot because it carries
    /// typed BTW linkage.
    pub async fn create_btw_fork(
        &self,
        parent_session_id: Uuid,
        tangent: bool,
    ) -> Result<BtwForkCreateResult> {
        let session_id = Uuid::new_v4();
        let now = Utc::now().timestamp();
        self.write(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin create_btw_fork tx")?;
            let result =
                Self::create_btw_fork_conn(&tx, parent_session_id, tangent, session_id, now)?;
            tx.commit().context("commit create_btw_fork tx")?;
            Ok(result)
        })
        .await
    }

    /// `/btw` fork body without an owning transaction. The caller supplies a
    /// connection ALREADY inside a transaction (e.g. the transactional
    /// remote-operation ledger writer). Statements run directly on `conn`;
    /// the caller commits. Idempotent: returns the existing live `/btw` fork
    /// (`created: false`) when one is already present for the parent.
    pub fn create_btw_fork_conn(
        conn: &Connection,
        parent_session_id: Uuid,
        tangent: bool,
        session_id: Uuid,
        now: i64,
    ) -> Result<BtwForkCreateResult> {
        if let Some(info) = live_btw_fork_info_conn(conn, parent_session_id)? {
            return Ok(BtwForkCreateResult {
                info,
                created: false,
            });
        }
        // No sealed-value guard here, deliberately: `/btw` forks copy the
        // transcript and nothing else. There is no `INSERT INTO
        // sealed_values` on this path, so a `/btw` fork never inherits a
        // sealed value by any ordering, and refusing one would restrict a
        // fork that cannot reach the bad state. The property this relies
        // on is pinned by
        // `btw_fork_never_inherits_sealed_values_of_either_kind`.
        let parent = get_session_inner(conn, parent_session_id)?
            .ok_or_else(|| anyhow::anyhow!("parent session {parent_session_id} not found"))?;
        let short_id = generate_unique_short_id(conn, &parent.project_id)
            .context("generating btw fork short_id")?;
        let row = SessionRow {
            session_id,
            project_id: parent.project_id,
            project_root: parent.project_root,
            started_at: now,
            last_active_at: now,
            ended_at: None,
            provider: parent.provider,
            model: parent.model,
            model_selection_json: parent.model_selection_json,
            active_model_revision: 0,
            session_llm_mode: parent.session_llm_mode,
            tool_surface_override_json: parent.tool_surface_override_json,
            goal_settings_override_json: parent.goal_settings_override_json,
            active_agent: parent.active_agent,
            assistant_name: parent.assistant_name,
            short_id: Some(short_id),
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
            // A `/btw` fork is a distinct session: never inherit the
            // parent's unconsumed recovery nudge (tangent or seeded).
            title_recovery_nudge_state: TitleRecoveryNudgeState::None,
            guidance_baseline_path: parent.guidance_baseline_path,
            guidance_baseline_hash: parent.guidance_baseline_hash,
            redaction_table_json: None,
            model_system_prompt_snapshot_json: parent.model_system_prompt_snapshot_json,
            created_by_principal: parent.created_by_principal,
            shared_with_collaborators: false,
            lifecycle: "active".to_string(),
        };
        let row = insert_fork_row_with_short_id_retry(conn, row, &None)
            .context("inserting btw fork session")?;
        if !tangent {
            copy_fork_transcript(conn, parent_session_id, session_id, None)
                .context("copying btw fork transcript")?;
        }
        let info = btw_info_for_row_conn(conn, &row)?;
        Ok(BtwForkCreateResult {
            info,
            created: true,
        })
    }

    pub async fn live_btw_fork_info(&self, parent_session_id: Uuid) -> Result<Option<BtwForkInfo>> {
        self.read(move |conn| live_btw_fork_info_conn(conn, parent_session_id))
            .await
    }

    pub async fn end_btw_fork(&self, parent_session_id: Uuid) -> Result<bool> {
        // `transaction`, not `write`: `delete_session_conn` writes an external
        // side-effect tombstone and then deletes the row, and under `write`
        // each statement autocommits separately — a failure between them would
        // leave a tombstone for a session that still exists, or a deleted
        // session with no owner-visible marker for its unresolved operations.
        self.transaction(move |conn| Self::end_btw_fork_conn(conn, parent_session_id))
            .await
    }

    /// End-`/btw` body without an owning transaction. The caller supplies a
    /// connection ALREADY inside a transaction (e.g. the transactional
    /// remote-operation ledger writer). Deletes the one live `/btw` fork for
    /// the parent and returns whether a row was removed.
    pub fn end_btw_fork_conn(conn: &Connection, parent_session_id: Uuid) -> Result<bool> {
        let Some(info) = live_btw_fork_info_conn(conn, parent_session_id)? else {
            return Ok(false);
        };
        delete_session_conn(conn, info.session_id)?;
        Ok(true)
    }

    async fn create_fork_inner(
        &self,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
        ephemeral: bool,
    ) -> Result<SessionRow> {
        let session_id = Uuid::new_v4();
        let now = Utc::now().timestamp();
        self.write(move |conn| {
            Self::create_fork_conn(
                conn,
                parent_session_id,
                fork_point_turn_id,
                ephemeral,
                session_id,
                now,
            )
        })
        .await
    }

    pub fn create_fork_conn(
        conn: &Connection,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
        ephemeral: bool,
        session_id: Uuid,
        now: i64,
    ) -> Result<SessionRow> {
        let tx = conn
            .unchecked_transaction()
            .context("begin create_fork tx")?;
        let row = Self::create_fork_row_conn(
            &tx,
            parent_session_id,
            fork_point_turn_id,
            ephemeral,
            session_id,
            now,
        )?;
        tx.commit().context("commit create_fork tx")?;
        Ok(row)
    }

    /// Fork body without an owning transaction. The caller supplies a
    /// connection ALREADY inside a transaction (e.g. the transactional
    /// remote-operation ledger writer, which cannot nest a second
    /// `BEGIN`). Statements run directly on `conn`; the caller commits.
    pub fn create_fork_row_conn(
        conn: &Connection,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
        ephemeral: bool,
        session_id: Uuid,
        now: i64,
    ) -> Result<SessionRow> {
        let parent = get_session_inner(conn, parent_session_id)?
            .ok_or_else(|| anyhow::anyhow!("parent session {parent_session_id} not found"))?;
        let short_id = generate_unique_short_id(conn, &parent.project_id)
            .context("generating fork short_id")?;
        let row = SessionRow {
            session_id,
            project_id: parent.project_id,
            project_root: parent.project_root,
            started_at: now,
            last_active_at: now,
            ended_at: None,
            provider: parent.provider,
            model: parent.model,
            model_selection_json: parent.model_selection_json,
            active_model_revision: 0,
            session_llm_mode: parent.session_llm_mode,
            tool_surface_override_json: parent.tool_surface_override_json,
            goal_settings_override_json: parent.goal_settings_override_json,
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
            // A fork (plain or ephemeral `/side`) is a distinct session:
            // never inherit the parent's unconsumed recovery nudge.
            title_recovery_nudge_state: TitleRecoveryNudgeState::None,
            guidance_baseline_path: parent.guidance_baseline_path,
            guidance_baseline_hash: parent.guidance_baseline_hash,
            redaction_table_json: None,
            model_system_prompt_snapshot_json: parent.model_system_prompt_snapshot_json,
            created_by_principal: parent.created_by_principal,
            shared_with_collaborators: false,
            lifecycle: "active".to_string(),
        };
        let row = insert_fork_row_with_short_id_retry(conn, row, &fork_point_turn_id)
            .context("inserting fork session")?;
        copy_fork_transcript(
            conn,
            parent_session_id,
            session_id,
            fork_point_turn_id.as_deref(),
        )
        .context("copying fork transcript")?;
        // Sealed values are fork-point state, not a live parent lookup: a
        // value created in the parent after this fork must stay parent-only.
        //
        // The refusal is welded to the copy rather than to the fork entry
        // points. Copying is the dangerous operation — it is what would give
        // a child session a scoped value's literal without its record — so
        // guarding here means any future path that reaches this copy is
        // guarded by construction, instead of relying on having enumerated
        // the callers correctly.
        refuse_fork_with_scoped_sealed_values(conn, parent_session_id)?;
        conn.execute(
            "INSERT INTO sealed_values (session_id, value_id, value, reason, origin, created_at)
             SELECT ?1, value_id, NULL, reason, origin, created_at
             FROM sealed_values WHERE session_id = ?2",
            params![session_id.to_string(), parent_session_id.to_string()],
        )
        .context("copying sealed values into fork")?;
        Ok(row)
    }

    pub async fn get_session(&self, session_id: Uuid) -> Result<Option<SessionRow>> {
        self.read(move |conn| Self::get_session_conn(conn, session_id))
            .await
    }

    /// Does this session own any scoped sealed value records?
    ///
    /// Exposed so callers can explain the refusal before attempting a fork,
    /// rather than surfacing it only as an error.
    pub async fn session_owns_scoped_sealed_values(&self, session_id: Uuid) -> Result<bool> {
        self.read(move |conn| Ok(scoped_sealed_value_count(conn, session_id)? > 0))
            .await
    }

    pub fn get_session_conn(conn: &Connection, session_id: Uuid) -> Result<Option<SessionRow>> {
        Ok(get_session_inner(conn, session_id)?)
    }

    /// Compare-and-swap the durable session active model. Succeeds only when
    /// `active_model_revision` still equals `expected_revision`, then advances
    /// the revision by one. Returns `Ok(true)` on success, `Ok(false)` on a
    /// concurrent conflict (zero rows), and `Err` for SQL failures.
    pub fn cas_set_active_model_conn(
        conn: &Connection,
        session_id: Uuid,
        expected_revision: i64,
        provider: &str,
        model: &str,
        model_selection_json: &str,
    ) -> Result<bool> {
        let changed = conn
            .execute(
                "UPDATE sessions
                    SET provider = ?1,
                        model = ?2,
                        model_selection_json = ?3,
                        active_model_revision = active_model_revision + 1
                  WHERE session_id = ?4
                    AND active_model_revision = ?5",
                params![
                    provider,
                    model,
                    model_selection_json,
                    session_id.to_string(),
                    expected_revision,
                ],
            )
            .context("CAS updating session active model")?;
        Ok(changed == 1)
    }

    /// Read the current active-model revision for a session, or `None` when
    /// the row is missing.
    pub fn active_model_revision_conn(conn: &Connection, session_id: Uuid) -> Result<Option<i64>> {
        let result = conn.query_row(
            "SELECT active_model_revision FROM sessions WHERE session_id = ?1",
            params![session_id.to_string()],
            |row| row.get::<_, i64>(0),
        );
        match result {
            Ok(revision) => Ok(Some(revision)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error).context("reading active_model_revision"),
        }
    }

    /// Lookup by short id within a project. Used by CLI/RPC paths where
    /// the user types the 6-char display id rather than the full UUID.
    pub async fn get_session_by_short_id(
        &self,
        project_id: &str,
        short_id: &str,
    ) -> Result<Option<SessionRow>> {
        let project_id = project_id.to_string();
        let short_id = short_id.to_string();
        self.read(move |conn| {
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
        .await
    }

    /// Look up sessions by `short_id` across **every** project. Used by
    /// `cockpit export <session>`, which accepts a bare short_id without a
    /// project context. Returns all matches so the caller can report an
    /// ambiguous identifier (a short_id is unique only within a project).
    pub async fn find_sessions_by_short_id_global(
        &self,
        short_id: &str,
    ) -> Result<Vec<SessionRow>> {
        let short_id = short_id.to_string();
        self.read(move |conn| Self::find_sessions_by_short_id_global_conn(conn, &short_id))
            .await
    }

    pub fn find_sessions_by_short_id_global_conn(
        conn: &Connection,
        short_id: &str,
    ) -> Result<Vec<SessionRow>> {
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
    }

    /// Ensure the session has a short_id (lazy backfill for rows
    /// migrated from pre-§17 schemas). Returns the resolved short_id.
    pub async fn ensure_short_id(&self, session_id: Uuid) -> Result<String> {
        self.write(move |conn| Self::ensure_short_id_conn(conn, session_id))
            .await
    }

    pub fn ensure_short_id_conn(conn: &Connection, session_id: Uuid) -> Result<String> {
        let row = get_session_inner(conn, session_id)?
            .ok_or_else(|| anyhow::anyhow!("session {session_id} not found"))?;
        if let Some(existing) = row.short_id {
            return Ok(existing);
        }
        let short_id = backfill_short_id_with_retry(conn, session_id, &row.project_id)
            .context("backfilling short_id")?;
        Ok(short_id)
    }

    /// Set or replace the session's title. `user_renamed` flips to true
    /// to lock out the auto-titling pass (GOALS §17d).
    pub fn rename_session_conn(conn: &Connection, session_id: Uuid, title: &str) -> Result<()> {
        conn.execute(
            "UPDATE sessions SET title = ?1, user_renamed = 1, title_recovery_nudge_state = 0
             WHERE session_id = ?2",
            params![title, session_id.to_string()],
        )
        .context("renaming session")?;
        Ok(())
    }

    /// Transaction-composable rename which reports whether the authoritative
    /// root row still existed at the instant of mutation.
    pub fn rename_existing_session_conn(
        conn: &Connection,
        session_id: Uuid,
        title: &str,
    ) -> Result<bool> {
        let affected = conn
            .execute(
                "UPDATE sessions SET title = ?1, user_renamed = 1, title_recovery_nudge_state = 0
                 WHERE session_id = ?2",
                params![title, session_id.to_string()],
            )
            .context("renaming existing session")?;
        Ok(affected == 1)
    }

    pub async fn rename_session(&self, session_id: Uuid, title: &str) -> Result<()> {
        let title = title.to_owned();
        self.write(move |conn| Self::rename_session_conn(conn, session_id, &title))
            .await
    }

    /// Set the title from the auto-titling pass. Refuses to overwrite a
    /// user-set title — auto-titling never clobbers manual labels. Clears any
    /// pending title-recovery nudge (issue #23): a stored title makes the
    /// recovery moot.
    pub fn set_auto_title_conn(conn: &Connection, session_id: Uuid, title: &str) -> Result<bool> {
        let affected = conn
            .execute(
                "UPDATE sessions SET title = ?1, title_recovery_nudge_state = 0
                 WHERE session_id = ?2 AND user_renamed = 0 AND ephemeral = 0",
                params![title, session_id.to_string()],
            )
            .context("setting auto title")?;
        Ok(affected > 0)
    }

    pub async fn set_auto_title(&self, session_id: Uuid, title: &str) -> Result<bool> {
        let title = title.to_owned();
        self.write(move |conn| Self::set_auto_title_conn(conn, session_id, &title))
            .await
    }

    /// Set a title generated by an explicit user request (`/rename` with no
    /// title). This is still an auto-generated title, so it clears
    /// `user_renamed`; future scheduled auto-refreshes may replace it until the
    /// user manually names the session again.
    pub fn set_explicit_auto_title_conn(
        conn: &Connection,
        session_id: Uuid,
        title: &str,
    ) -> Result<bool> {
        let affected = conn
            .execute(
                "UPDATE sessions SET title = ?1, user_renamed = 0, title_recovery_nudge_state = 0
                 WHERE session_id = ?2 AND ephemeral = 0",
                params![title, session_id.to_string()],
            )
            .context("setting explicit auto title")?;
        Ok(affected > 0)
    }

    pub async fn set_explicit_auto_title(&self, session_id: Uuid, title: &str) -> Result<bool> {
        let title = title.to_owned();
        self.write(move |conn| Self::set_explicit_auto_title_conn(conn, session_id, &title))
            .await
    }

    /// Set a generated title only if the session is still unnamed. This is
    /// used by daemon RPCs where competing callers may generate concurrently;
    /// the storage layer decides the single winner.
    pub fn set_explicit_auto_title_if_untitled_conn(
        conn: &Connection,
        session_id: Uuid,
        title: &str,
    ) -> Result<bool> {
        let affected = conn
            .execute(
                "UPDATE sessions SET title = ?1, user_renamed = 0, title_recovery_nudge_state = 0
                 WHERE session_id = ?2 AND ephemeral = 0 AND title IS NULL",
                params![title, session_id.to_string()],
            )
            .context("setting explicit auto title if untitled")?;
        Ok(affected > 0)
    }

    pub async fn set_explicit_auto_title_if_untitled(
        &self,
        session_id: Uuid,
        title: &str,
    ) -> Result<bool> {
        let title = title.to_owned();
        self.write(move |conn| {
            Self::set_explicit_auto_title_if_untitled_conn(conn, session_id, &title)
        })
        .await
    }

    /// Persist auto-title progress (migration 0037): the running raw-user
    /// token estimate and last consumed schedule slot. Called from
    /// [`crate::session::Session::note_user_content`] so automatic refresh
    /// progress survives resume / daemon restart. Best-effort at the call
    /// site; an erroring write never blocks a turn.
    pub async fn set_title_progress(
        &self,
        session_id: Uuid,
        user_content_tokens: i64,
        title_stage: i64,
    ) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "UPDATE sessions
                 SET user_content_tokens = ?1, title_stage = ?2
                 WHERE session_id = ?3",
                params![user_content_tokens, title_stage, session_id.to_string()],
            )
            .context("persisting title progress")?;
            Ok(())
        })
        .await
    }

    /// Arm the durable one-shot title-recovery nudge (issue #23) for a session
    /// whose automatic title attempt failed. Transitions the latch to
    /// `pending` from either `none` or `consumed`, but ONLY while the session
    /// is still eligible: untitled, not user-renamed, and not ephemeral.
    ///
    /// A session already `pending` is left unchanged — repeated utility
    /// failures coalesce into a single nudge. A `consumed` nudge may be
    /// re-armed by a later distinct failure while eligibility still holds.
    /// Returns `true` iff this call moved the latch to `pending`. Fails closed:
    /// a DB error propagates and arms nothing.
    pub async fn arm_title_recovery_nudge(&self, session_id: Uuid) -> Result<bool> {
        self.write(move |conn| Self::arm_title_recovery_nudge_conn(conn, session_id))
            .await
    }

    pub fn arm_title_recovery_nudge_conn(conn: &Connection, session_id: Uuid) -> Result<bool> {
        // Transition-specific predicate rather than read-then-write: `pending`
        // is excluded from the source set so a duplicate arm cannot re-arm, and
        // the eligibility columns are checked atomically inside the same
        // statement so a concurrent title/rename that lands first wins.
        let affected = conn
            .execute(
                "UPDATE sessions
                    SET title_recovery_nudge_state = 1
                  WHERE session_id = ?1
                    AND title_recovery_nudge_state IN (0, 2)
                    AND title IS NULL
                    AND user_renamed = 0
                    AND ephemeral = 0",
                params![session_id.to_string()],
            )
            .context("arming title recovery nudge")?;
        Ok(affected > 0)
    }

    /// Atomically claim a pending title-recovery nudge exactly once,
    /// transitioning `pending → consumed`. Returns `true` for the single caller
    /// that observed `pending`; every other state — including a second claim of
    /// the same nudge, or a nudge cleared by a stored title — returns `false`.
    /// Fails closed: a DB error propagates and claims nothing.
    pub async fn claim_title_recovery_nudge(&self, session_id: Uuid) -> Result<bool> {
        self.write(move |conn| Self::claim_title_recovery_nudge_conn(conn, session_id))
            .await
    }

    pub fn claim_title_recovery_nudge_conn(conn: &Connection, session_id: Uuid) -> Result<bool> {
        // Belt-and-suspenders: independently re-gate eligibility inside the claim
        // (untitled, not user-renamed, not ephemeral) so that even if some path
        // forgot to clear the latch, an ineligible session FAILS CLOSED and is
        // never nudged. Eligibility is checked atomically with the state
        // transition so a concurrent title/rename that lands first wins.
        let affected = conn
            .execute(
                "UPDATE sessions
                    SET title_recovery_nudge_state = 2
                  WHERE session_id = ?1
                    AND title_recovery_nudge_state = 1
                    AND title IS NULL
                    AND user_renamed = 0
                    AND ephemeral = 0",
                params![session_id.to_string()],
            )
            .context("claiming title recovery nudge")?;
        Ok(affected > 0)
    }

    /// Direct children of a session in the fork tree. Most-recent-first.
    pub async fn list_forks(&self, parent_session_id: Uuid) -> Result<Vec<SessionRow>> {
        self.read(move |conn| Self::list_forks_conn(conn, parent_session_id))
            .await
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
    pub async fn count_forks_for(&self, parent_session_id: Uuid) -> Result<u32> {
        self.read(move |conn| Self::count_forks_for_conn(conn, parent_session_id))
            .await
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
    pub async fn list_root_sessions(
        &self,
        project_id: &str,
        limit: u32,
    ) -> Result<Vec<SessionRow>> {
        let project_id = project_id.to_string();
        self.read(move |conn| Self::list_root_sessions_conn(conn, &project_id, limit))
            .await
    }

    pub(crate) fn list_root_sessions_conn(
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

    /// Delete a session and its complete fork subtree. SQLite owns the
    /// cascading relationship; the pre-delete walk only discovers sidecar
    /// files that must be removed after the transaction commits.
    pub async fn delete_session(&self, session_id: Uuid) -> Result<()> {
        let now_ms = Utc::now().timestamp_millis();
        self.transaction(move |conn| {
            Self::enqueue_delegation_sidecar_cleanup_conn(conn, session_id, now_ms)?;
            delete_session_conn(conn, session_id)
        })
        .await?;
        self.reconcile_delegation_sidecar_cleanup_intents().await?;
        Ok(())
    }

    /// Persist sidecar cleanup identities in the same transaction which will
    /// cascade their source payload rows.
    pub fn enqueue_delegation_sidecar_cleanup_conn(
        conn: &Connection,
        session_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<()> {
        ensure!(now_unix_ms >= 0, "cleanup intent timestamp must be nonnegative");
        for member in collect_subtree(conn, session_id)? {
            conn.execute(
                "INSERT OR IGNORE INTO task_delegation_sidecar_cleanup_intents(sidecar_path,session_id,created_at_unix_ms)
                 SELECT sidecar_path,parent_session_id,?2 FROM task_delegation_payloads
                  WHERE parent_session_id=?1 AND sidecar_path IS NOT NULL",
                params![member.to_string(), now_unix_ms],
            )?;
        }
        Ok(())
    }

    /// Replay durable filesystem cleanup. The intent is removed only after a
    /// successful unlink (or proof the file is already absent).
    pub async fn reconcile_delegation_sidecar_cleanup_intents(&self) -> Result<usize> {
        let rows = self
            .read(|conn| {
                let mut statement = conn.prepare(
                    "SELECT sidecar_path FROM task_delegation_sidecar_cleanup_intents ORDER BY created_at_unix_ms,sidecar_path",
                )?;
                Ok(statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?)
            })
            .await?;
        let base = self.delegation_payload_base_dir()?;
        let mut completed = 0;
        for relative in rows {
            let cleanup_base = base.clone();
            let cleanup_relative = relative.clone();
            let removed = self
                .transaction(move |conn| {
                    // This read and the intent deletion share the writer
                    // transaction. A payload insertion cannot race between
                    // the reference proof and unlink. Non-reusable sidecar
                    // generations also cover the prepare-before-insert gap.
                    let referenced: bool = conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM task_delegation_payloads WHERE sidecar_path=?1)",
                        [&cleanup_relative],
                        |row| row.get(0),
                    )?;
                    if referenced {
                        return Ok(false);
                    }
                    crate::db::files::delete_relative_file_durable_nofollow(
                        &cleanup_base,
                        std::path::Path::new(&cleanup_relative),
                    )?;
                    Ok(conn.execute(
                        "DELETE FROM task_delegation_sidecar_cleanup_intents WHERE sidecar_path=?1",
                        [cleanup_relative],
                    )? == 1)
                })
                .await;
            let removed = match removed {
                Ok(removed) => removed,
                Err(error) => {
                    tracing::warn!(%error, sidecar_path=%relative, "delegation sidecar cleanup remains pending");
                    continue;
                }
            };
            completed += usize::from(removed);
        }
        Ok(completed)
    }

    /// Absolute sidecar payload paths owned by `session_id` and its fork
    /// subtree. Collected BEFORE deletion (the rows are gone afterward) so the
    /// caller can remove the files once the deletion transaction commits.
    pub async fn session_delegation_sidecar_paths(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<std::path::PathBuf>> {
        let session_ids = self
            .read(move |conn| collect_subtree(conn, session_id))
            .await?;
        let mut sidecars = Vec::new();
        for id in session_ids {
            for payload in self.list_task_delegation_payloads(id).await? {
                if let Some(path) = self.task_delegation_payload_sidecar_abs_path(&payload)? {
                    sidecars.push(path);
                }
            }
        }
        Ok(sidecars)
    }

    /// Best-effort removal of collected delegation payload sidecars after a
    /// session deletion commits. A missing file is not an error.
    pub fn remove_delegation_sidecars(sidecars: Vec<std::path::PathBuf>) -> Result<()> {
        for path in sidecars {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("removing delegation payload sidecar {}", path.display())
                    });
                }
            }
        }
        Ok(())
    }

    /// Connection-direct session deletion for the transactional
    /// remote-operation ledger writer (already inside a transaction). Writes
    /// the external tombstone and deletes the row + fork subtree. Sidecar file
    /// removal is the caller's post-commit responsibility.
    pub fn delete_session_row_conn(conn: &Connection, session_id: Uuid) -> Result<()> {
        delete_session_conn(conn, session_id)
    }

    /// Transaction-composable deletion which refuses to treat a concurrently
    /// removed root as a successful remote mutation.
    pub fn delete_existing_session_row_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<bool> {
        if get_session_inner(conn, session_id)?.is_none() {
            return Ok(false);
        }
        delete_session_conn(conn, session_id)?;
        Ok(true)
    }

    /// Discard a single ephemeral side-conversation session (`/side`),
    /// cascading to its descendant forks. No-op (returns `Ok(false)`) when
    /// the id is unknown or the row is **not** ephemeral — a guard so a
    /// stray discard can never delete a persisted session. Returns `true`
    /// when an ephemeral row was deleted.
    pub async fn discard_ephemeral_session(&self, session_id: Uuid) -> Result<bool> {
        // `transaction` so the guard read, the tombstone, and the deletion are
        // one atomic step.
        self.transaction(move |conn| Self::discard_ephemeral_session_conn(conn, session_id))
            .await
    }

    /// Discard-ephemeral body without an owning transaction. The caller
    /// supplies a connection ALREADY inside a transaction (e.g. the
    /// transactional remote-operation ledger writer). Guards on the typed
    /// `ephemeral` flag so a stray call can never drop a persisted session.
    pub fn discard_ephemeral_session_conn(conn: &Connection, session_id: Uuid) -> Result<bool> {
        match get_session_inner(conn, session_id)? {
            Some(row) if row.ephemeral => {}
            _ => return Ok(false),
        }
        delete_session_conn(conn, session_id)?;
        Ok(true)
    }

    /// Sweep every ephemeral session row (and descendant forks) from the DB.
    /// Run once on daemon boot as the SIGKILL backstop: a side conversation
    /// whose owning process died uncatchably can leave an orphaned ephemeral
    /// row behind, and this clears it so ephemeral sessions never accumulate.
    /// Returns the number of root ephemeral sessions removed.
    pub async fn sweep_ephemeral_sessions(&self) -> Result<usize> {
        let roots = self
            .read(|conn| {
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
            })
            .await?;
        let mut removed = 0;
        for id in roots {
            // Cascade in case a side conversation itself spawned forks.
            match self.delete_session(id).await {
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
    pub async fn mark_session_viewed(&self, session_id: Uuid) -> Result<()> {
        let now = Utc::now().timestamp();
        self.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET last_viewed_at = ?1 WHERE session_id = ?2",
                params![now, session_id.to_string()],
            )
            .context("marking session viewed")?;
            Ok(())
        })
        .await
    }

    /// Timestamp (epoch seconds) of the most recent agent-produced event
    /// for a session, or `None` when the session has no agent activity
    /// yet. The max across `tool_call_events` and `inference_calls` — the
    /// two tables that record agent output. Drives the unread tier: a
    /// session is unread when this is newer than `last_viewed_at` (or it
    /// has activity and was never viewed).
    #[allow(dead_code)]
    pub async fn latest_agent_activity_at(&self, session_id: Uuid) -> Result<Option<i64>> {
        self.read(move |conn| Self::latest_agent_activity_at_conn(conn, session_id))
            .await
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
    pub async fn archive_session(&self, session_id: Uuid, cascade: bool) -> Result<()> {
        let now = Utc::now().timestamp();
        self.write(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin archive_session tx")?;
            Self::archive_session_conn(&tx, session_id, cascade, now)?;
            tx.commit().context("commit archive_session tx")
        })
        .await
    }

    pub fn archive_session_conn(
        conn: &Connection,
        session_id: Uuid,
        cascade: bool,
        now: i64,
    ) -> Result<()> {
        let targets = if cascade {
            collect_subtree(conn, session_id)?
        } else {
            vec![session_id]
        };
        for id in targets {
            conn.execute(
                "UPDATE sessions SET archived_at = ?1 WHERE session_id = ?2",
                params![now, id.to_string()],
            )
            .context("archiving session")?;
        }
        Ok(())
    }


    /// Transaction-composable archive which validates the root in the same
    /// transaction as the subtree update.
    pub fn archive_existing_session_conn(
        conn: &Connection,
        session_id: Uuid,
        cascade: bool,
        now: i64,
    ) -> Result<bool> {
        let targets = if cascade {
            collect_subtree(conn, session_id)?
        } else if get_session_inner(conn, session_id)?.is_some() {
            vec![session_id]
        } else {
            Vec::new()
        };
        if targets.is_empty() {
            return Ok(false);
        }
        for id in targets {
            conn.execute(
                "UPDATE sessions SET archived_at = ?1 WHERE session_id = ?2",
                params![now, id.to_string()],
            )
            .context("archiving existing session")?;
        }
        Ok(true)
    }

    /// Clear a session's archive flag (recover). Single row only — the
    /// browser unarchives one session at a time from the archived view.
    pub async fn unarchive_session(&self, session_id: Uuid) -> Result<()> {
        self.write(move |conn| Self::unarchive_session_conn(conn, session_id))
            .await
    }

    pub fn unarchive_session_conn(conn: &Connection, session_id: Uuid) -> Result<()> {
        conn.execute(
            "UPDATE sessions SET archived_at = NULL WHERE session_id = ?1",
            [session_id.to_string()],
        )
        .context("unarchiving session")?;
        Ok(())
    }


    /// Transaction-composable unarchive which reports concurrent removal.
    pub fn unarchive_existing_session_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<bool> {
        let affected = conn
            .execute(
                "UPDATE sessions SET archived_at = NULL WHERE session_id = ?1",
                [session_id.to_string()],
            )
            .context("unarchiving existing session")?;
        Ok(affected == 1)
    }

    /// Count the descendant forks of a session (depth-unbounded, not
    /// counting the session itself). Used by the archive/delete confirm
    /// dialog to state how many sessions the cascade will affect.
    #[allow(dead_code)]
    pub async fn count_descendants(&self, session_id: Uuid) -> Result<u32> {
        self.read(move |conn| Self::count_descendants_conn(conn, session_id))
            .await
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
    pub async fn is_in_subtree(&self, root: Uuid, node: Uuid) -> Result<bool> {
        self.read(move |conn| Ok(collect_subtree(conn, root)?.contains(&node)))
        .await
    }

    /// Move `last_active_at` to now. Called by the daemon on every
    /// interaction so `cockpit -c` resumes the actually-recent one.
    pub async fn touch_session(&self, session_id: Uuid) -> Result<()> {
        let now = Utc::now().timestamp();
        self.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET last_active_at = ?1 WHERE session_id = ?2",
                params![now, session_id.to_string()],
            )
            .context("touching session")?;
            Ok(())
        })
        .await
    }

    pub async fn set_session_redaction_table_json(
        &self,
        session_id: Uuid,
        redaction_table_json: Option<String>,
    ) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET redaction_table_json = ?1 WHERE session_id = ?2",
                params![redaction_table_json, session_id.to_string()],
            )
            .context("setting session redaction table")?;
            Ok(())
        })
        .await
    }

    pub async fn set_session_agent(&self, session_id: Uuid, active_agent: &str) -> Result<()> {
        let active_agent = active_agent.to_owned();
        self.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET active_agent = ?1 WHERE session_id = ?2",
                params![active_agent, session_id.to_string()],
            )
            .context("setting session agent")?;
            Ok(())
        })
        .await
    }

    pub fn set_session_agent_conn(
        conn: &rusqlite::Connection,
        session_id: Uuid,
        active_agent: &str,
    ) -> Result<()> {
        conn.execute(
            "UPDATE sessions SET active_agent = ?1 WHERE session_id = ?2",
            params![active_agent, session_id.to_string()],
        )?;
        Ok(())
    }

    pub fn set_session_llm_mode_conn(
        conn: &rusqlite::Connection,
        session_id: Uuid,
        mode: &str,
    ) -> Result<()> {
        conn.execute(
            "UPDATE sessions SET session_llm_mode = ?1 WHERE session_id = ?2",
            params![mode, session_id.to_string()],
        )?;
        Ok(())
    }

    pub async fn set_session_llm_mode(&self, session_id: Uuid, mode: Option<&str>) -> Result<()> {
        let mode = mode.map(str::to_owned);
        self.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET session_llm_mode = ?1 WHERE session_id = ?2",
                params![mode, session_id.to_string()],
            )
            .context("setting session llm mode")?;
            Ok(())
        })
        .await
    }

    pub async fn set_tool_surface_override(
        &self,
        session_id: Uuid,
        override_json: Option<&str>,
    ) -> Result<()> {
        let override_json = override_json.map(str::to_owned);
        self.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET tool_surface_override_json = ?1 WHERE session_id = ?2",
                params![override_json, session_id.to_string()],
            )
            .context("setting session tool surface override")?;
            Ok(())
        })
        .await
    }

    pub async fn set_goal_settings_override(
        &self,
        session_id: Uuid,
        override_json: Option<&str>,
    ) -> Result<()> {
        let override_json = override_json.map(str::to_owned);
        self.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET goal_settings_override_json = ?1 WHERE session_id = ?2",
                params![override_json, session_id.to_string()],
            )
            .context("setting session goal settings override")?;
            Ok(())
        })
        .await
    }

    pub async fn end_session(&self, session_id: Uuid) -> Result<()> {
        let now = Utc::now().timestamp();
        self.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET ended_at = ?1 WHERE session_id = ?2",
                params![now, session_id.to_string()],
            )
            .context("ending session")?;
            Ok(())
        })
        .await
    }

    /// Sessions newest-first. `only_open = true` filters out ended ones.
    #[allow(dead_code)]
    pub async fn list_sessions(&self, only_open: bool, limit: u32) -> Result<Vec<SessionRow>> {
        self.read(move |conn| Self::list_sessions_conn(conn, only_open, limit))
            .await
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

    pub async fn list_sessions_for_assistant(
        &self,
        assistant_name: &str,
        only_open: bool,
        limit: u32,
    ) -> Result<Vec<SessionRow>> {
        let assistant_name = assistant_name.to_string();
        self.read(move |conn| {
            Self::list_sessions_for_assistant_conn(conn, &assistant_name, only_open, limit)
        })
        .await
    }

    pub fn list_sessions_for_assistant_conn(
        conn: &Connection,
        assistant_name: &str,
        only_open: bool,
        limit: u32,
    ) -> Result<Vec<SessionRow>> {
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
    }

    pub async fn most_recent_session_for_assistant(
        &self,
        assistant_name: &str,
    ) -> Result<Option<SessionRow>> {
        let assistant_name = assistant_name.to_string();
        self.read(move |conn| Self::most_recent_session_for_assistant_conn(conn, &assistant_name))
            .await
    }

    pub fn most_recent_session_for_assistant_conn(
        conn: &Connection,
        assistant_name: &str,
    ) -> Result<Option<SessionRow>> {
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
    }

    /// The most recent durable session for a canonical workspace root,
    /// ordered by its latest user/assistant message rather than incidental
    /// metadata activity. Used by noninteractive `run --continue`.
    pub async fn most_recent_session_for_root_by_message(
        &self,
        project_root: &str,
    ) -> Result<Option<SessionRow>> {
        let project_root = project_root.to_string();
        self.read(move |conn| {
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
                [&project_root],
                SessionRow::from_row,
            );
            match result {
                Ok(row) => Ok(Some(row)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(error).context("querying latest session by message time"),
            }
        })
        .await
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
    pub async fn list_session_summaries(
        &self,
        project_id: Option<&str>,
        parent_session_id: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<crate::db::wire::SessionSummary>> {
        let project_id = project_id.map(str::to_string);
        self.read(move |conn| {
            Self::list_session_summaries_conn(conn, project_id.as_deref(), parent_session_id, limit)
        })
        .await
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
                  WHERE session_id = ?1
                    AND decision_request_id IS NULL
                    AND resolved_at IS NULL",
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
                    AND decision_request_id IS NULL
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
    pub async fn most_recent_open_session_for(
        &self,
        project_id: &str,
    ) -> Result<Option<SessionRow>> {
        let project_id = project_id.to_string();
        self.read(move |conn| {
            let result = conn.query_row(
                "SELECT * FROM sessions
                 WHERE project_id = ?1 AND ended_at IS NULL AND ephemeral = 0
                 ORDER BY last_active_at DESC LIMIT 1",
                [&project_id],
                SessionRow::from_row,
            );
            match result {
                Ok(row) => Ok(Some(row)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e).context("query most_recent_open_session_for"),
            }
        })
        .await
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
/// Every session id that `DELETE FROM sessions WHERE session_id = root`
/// removes, including the root.
///
/// This mirrors the database's own cascade rule rather than a subset of it:
/// `sessions` cascades on **both** `parent_session_id` and
/// `btw_parent_session_id`, so the walk follows both. A `/btw` row currently
/// sets both columns, which made a parent-only walk accidentally correct — but
/// the delete does not depend on that invariant and neither should this. The
/// walk that misses a descendant is the walk that deletes it without a
/// tombstone.
///
/// The anchor selects *from* `sessions` rather than echoing the argument, so
/// an unknown id yields an empty set. Echoing it would report a delete set for
/// a session that does not exist, and `delete_session_conn` would write a
/// tombstone for a row whose deletion cascades nothing.
pub fn collect_subtree(conn: &Connection, root: Uuid) -> Result<Vec<Uuid>> {
    let mut stmt = conn
        .prepare(
            "WITH RECURSIVE cascade(session_id) AS (
                 SELECT session_id FROM sessions WHERE session_id = ?1
                 UNION
                 SELECT s.session_id
                   FROM sessions AS s
                   JOIN cascade AS c
                     ON s.parent_session_id = c.session_id
                     OR s.btw_parent_session_id = c.session_id
             )
             SELECT session_id FROM cascade",
        )
        .context("preparing cascade walk")?;
    let rows = stmt
        .query_map([root.to_string()], |row| {
            let raw: String = row.get(0)?;
            parse_uuid(&raw)
        })
        .context("querying cascade walk")?;
    let mut all = Vec::new();
    for row in rows {
        all.push(row.context("decoding cascade member")?);
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

    /// Load a session's persisted recovery-nudge latch through the real
    /// get+decode path.
    async fn nudge_of(db: &Db, session_id: Uuid) -> TitleRecoveryNudgeState {
        db.get_session(session_id)
            .await
            .unwrap()
            .unwrap()
            .title_recovery_nudge_state
    }

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

    async fn capture_warn_log_async<Fut>(f: impl FnOnce() -> Fut) -> String
    where
        Fut: std::future::Future<Output = ()>,
    {
        let bytes = std::sync::Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::WARN)
            .with_ansi(false)
            .with_writer(CaptureWriter(bytes.clone()))
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        f().await;
        drop(guard);
        String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
    }

    async fn record_message(db: &Db, session_id: Uuid, text: &str, assistant: bool) -> i64 {
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
        .await
        .unwrap()
    }

    async fn record_tool_timeline(db: &Db, session_id: Uuid, call_id: &str) -> i64 {
        db.insert_session_event(
            session_id,
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some(call_id),
            &serde_json::json!({"tool": "read"}),
        )
        .await
        .unwrap()
    }

    async fn record_tool_call_event(db: &Db, session_id: Uuid, call_id: &str, timestamp: i64) {
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
        .await
        .unwrap();
    }

    async fn fork_tool_call_ids(db: &Db, session_id: Uuid) -> Vec<String> {
        db.read(move |conn| {
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
        .await
        .unwrap()
    }

    async fn session_exists(db: &Db, session_id: Uuid) -> bool {
        db.get_session(session_id).await.unwrap().is_some()
    }

    async fn fork_rows_for_parent(db: &Db, parent_session_id: Uuid) -> Vec<Uuid> {
        db.read(move |conn| {
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
        .await
        .unwrap()
    }

    async fn install_trigger(db: &Db, sql: &str) {
        let db = db.clone();
        let sql = sql.to_owned();
        db.write(move |conn| {
            conn.execute_batch(&sql)?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn create_and_get() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p1", "/x/y", "Build").await.unwrap();
        let g = db.get_session(s.session_id).await.unwrap().unwrap();
        assert_eq!(g.project_id, "p1");
        assert_eq!(g.project_root, "/x/y");
        assert_eq!(g.active_agent, "Build");
        assert!(g.ended_at.is_none());
    }

    #[tokio::test]
    async fn db_async_sessions_roundtrip_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project-a", "/workspace/a", "Build")
            .await
            .unwrap();

        db.set_session_agent(session.session_id, "Review")
            .await
            .unwrap();
        db.rename_session(session.session_id, "Reviewed title")
            .await
            .unwrap();

        let stored = db.get_session(session.session_id).await.unwrap().unwrap();
        assert_eq!(stored.active_agent, "Review");
        assert_eq!(stored.title.as_deref(), Some("Reviewed title"));
        assert!(stored.user_renamed);
    }

    #[tokio::test]
    async fn db_async_session_llm_mode_roundtrips_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();

        db.set_session_llm_mode(session.session_id, Some("frontier"))
            .await
            .unwrap();
        let stored = db.get_session(session.session_id).await.unwrap().unwrap();
        assert_eq!(stored.session_llm_mode.as_deref(), Some("frontier"));

        db.set_session_llm_mode(session.session_id, None)
            .await
            .unwrap();
        let stored = db.get_session(session.session_id).await.unwrap().unwrap();
        assert_eq!(stored.session_llm_mode, None);
    }

    #[tokio::test]
    async fn db_async_tool_surface_override_roundtrips_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let override_json = r#"{"tools":["read","bash"],"toolTiers":{"bash":"disabled"}}"#;

        db.set_tool_surface_override(session.session_id, Some(override_json))
            .await
            .unwrap();
        let stored = db.get_session(session.session_id).await.unwrap().unwrap();
        assert_eq!(
            stored.tool_surface_override_json.as_deref(),
            Some(override_json)
        );

        db.set_tool_surface_override(session.session_id, None)
            .await
            .unwrap();
        let stored = db.get_session(session.session_id).await.unwrap().unwrap();
        assert_eq!(stored.tool_surface_override_json, None);
    }

    #[tokio::test]
    async fn db_async_goal_settings_override_roundtrips_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let override_json = r#"{"enabled":false,"coldSkepticCount":2}"#;

        db.set_goal_settings_override(session.session_id, Some(override_json))
            .await
            .unwrap();
        let stored = db.get_session(session.session_id).await.unwrap().unwrap();
        assert_eq!(
            stored.goal_settings_override_json.as_deref(),
            Some(override_json)
        );

        db.set_goal_settings_override(session.session_id, None)
            .await
            .unwrap();
        let stored = db.get_session(session.session_id).await.unwrap().unwrap();
        assert_eq!(stored.goal_settings_override_json, None);
    }

    #[tokio::test]
    async fn db_async_sessions_write_then_read_sees_committed_value() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();

        db.end_session(session.session_id).await.unwrap();

        let stored = db.get_session(session.session_id).await.unwrap().unwrap();
        assert!(stored.ended_at.is_some());
        assert!(
            db.list_sessions(true, 100)
                .await
                .unwrap()
                .iter()
                .all(|row| row.session_id != session.session_id)
        );
    }

    #[tokio::test]
    async fn db_async_sessions_concurrent_read_finishes_during_queued_slow_write() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("db.sqlite3")).unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let (write_started_tx, write_started_rx) = tokio::sync::oneshot::channel();
        let (release_write_tx, release_write_rx) = std::sync::mpsc::channel();
        let db_for_write = db.clone();

        let writer = tokio::spawn(async move {
            db_for_write
                .write(move |_conn| {
                    write_started_tx.send(()).ok();
                    release_write_rx.recv().unwrap();
                    Ok(())
                })
                .await
                .unwrap();
        });

        write_started_rx.await.unwrap();
        let read = db.get_session(session.session_id).await.unwrap().unwrap();
        assert_eq!(read.session_id, session.session_id);

        release_write_tx.send(()).unwrap();
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn db_async_sessions_atomic_delete_rolls_back_on_cascade_failure() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "Build").await.unwrap();
        let child = db.create_fork(parent.session_id, None).await.unwrap();
        let grandchild = db.create_fork(child.session_id, None).await.unwrap();

        install_trigger(
            &db,
            &format!(
                "CREATE TEMP TRIGGER db_async_sessions_fail_child_delete
                 BEFORE DELETE ON sessions
                 WHEN OLD.session_id = '{}'
                 BEGIN
                     SELECT RAISE(ABORT, 'db async sessions injected delete failure');
                 END;",
                child.session_id
            ),
        )
        .await;

        let error = db.delete_session(parent.session_id).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("db async sessions injected delete failure"),
            "unexpected error: {error:#}"
        );
        for id in [parent.session_id, child.session_id, grandchild.session_id] {
            assert!(db.get_session(id).await.unwrap().is_some());
        }
    }

    #[tokio::test]
    async fn db_async_sessions_search_returns_expected_rows_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let target = db
            .create_session("project-a", "/workspace/a", "Build")
            .await
            .unwrap();
        let other = db
            .create_session("project-b", "/workspace/b", "Build")
            .await
            .unwrap();
        record_message(
            &db,
            target.session_id,
            "needle phrase belongs to project a",
            false,
        )
        .await;
        record_message(
            &db,
            other.session_id,
            "needle phrase belongs to project b",
            false,
        )
        .await;

        let hits = db
            .search_candidates("needle", Some("project-a"), None, None, 10)
            .await
            .unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].session_id, target.session_id);
    }

    #[tokio::test]
    async fn db_async_sessions_workspace_trust_roundtrip_through_async_api() {
        use crate::db::workspace_trust::WorkspaceTrustMode;

        let db = Db::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();

        assert!(
            db.workspace_trust_by_root(tmp.path())
                .await
                .unwrap()
                .is_none()
        );
        let decision = db
            .set_workspace_trust(tmp.path(), WorkspaceTrustMode::Trust)
            .await
            .unwrap();

        let stored = db
            .workspace_trust_by_root(tmp.path())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.mode, WorkspaceTrustMode::Trust);
        assert_eq!(stored.root_path, decision.root_path);
    }

    #[tokio::test]
    async fn latest_session_for_root_orders_by_last_message() {
        let db = Db::open_in_memory().unwrap();
        let first = db.create_session("p", "/proj", "Build").await.unwrap();
        let second = db.create_session("p", "/proj", "Build").await.unwrap();
        let other = db.create_session("q", "/other", "Build").await.unwrap();
        let first_seq = record_message(&db, first.session_id, "newest message", false).await;
        let second_seq = record_message(&db, second.session_id, "older message", true).await;
        let other_seq = record_message(&db, other.session_id, "newest elsewhere", false).await;

        db.write(move |conn| {
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
        .await
        .unwrap();

        let selected = db
            .most_recent_session_for_root_by_message("/proj")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.session_id, first.session_id);
        assert!(
            db.most_recent_session_for_root_by_message("/missing")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn new_session_row_defers_the_write() {
        // session-id-display-and-lazy-persist: building a row reserves an id
        // + short_id but writes nothing; inserting it makes it queryable.
        let db = Db::open_in_memory().unwrap();
        let row = db.new_session_row("p", "/x", "builder").await.unwrap();
        assert!(row.short_id.is_some());
        assert!(db.get_session(row.session_id).await.unwrap().is_none());
        assert!(db.list_sessions(false, 100).await.unwrap().is_empty());
        db.insert_session_row(&row).await.unwrap();
        let got = db.get_session(row.session_id).await.unwrap().unwrap();
        assert_eq!(got.project_id, "p");
        assert_eq!(got.short_id, row.short_id);
        assert_eq!(db.list_sessions(false, 100).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn insert_session_row_round_trips_provider_model() {
        let db = Db::open_in_memory().unwrap();
        let mut row = db.new_session_row("p", "/x", "builder").await.unwrap();
        row.provider = Some("anthropic".into());
        row.model = Some("opus".into());
        db.insert_session_row(&row).await.unwrap();
        let got = db.get_session(row.session_id).await.unwrap().unwrap();
        assert_eq!(got.provider.as_deref(), Some("anthropic"));
        assert_eq!(got.model.as_deref(), Some("opus"));
    }

    #[tokio::test]
    async fn insert_session_row_round_trips_the_active_model_cas_revision() {
        // A pending session stages active-model mutations in memory before its
        // first INSERT. If the insert dropped `active_model_revision`, a later
        // CAS would guard against 0 while the caller held the staged token, so
        // recovery could silently overwrite a newer selection.
        let db = Db::open_in_memory().unwrap();
        let mut row = db.new_session_row("p", "/x", "builder").await.unwrap();
        row.provider = Some("anthropic".into());
        row.model = Some("opus".into());
        row.active_model_revision = 3;
        db.insert_session_row(&row).await.unwrap();

        let got = db.get_session(row.session_id).await.unwrap().unwrap();
        assert_eq!(got.active_model_revision, 3);

        // The staged token is the only one that may commit.
        let stale = db
            .write({
                let id = row.session_id;
                move |conn| {
                    crate::db::Db::cas_set_active_model_conn(
                        conn,
                        id,
                        0,
                        "p2",
                        "m2",
                        r#"{"provider":"p2","model":"m2"}"#,
                    )
                }
            })
            .await
            .unwrap();
        assert!(!stale, "a pre-insert revision must not be able to commit");
        let fresh = db
            .write({
                let id = row.session_id;
                move |conn| {
                    crate::db::Db::cas_set_active_model_conn(
                        conn,
                        id,
                        3,
                        "p3",
                        "m3",
                        r#"{"provider":"p3","model":"m3"}"#,
                    )
                }
            })
            .await
            .unwrap();
        assert!(fresh);
        let got = db.get_session(row.session_id).await.unwrap().unwrap();
        assert_eq!(got.active_model_revision, 4);
        assert_eq!(got.provider.as_deref(), Some("p3"));
    }

    #[tokio::test]
    async fn insert_session_row_round_trips_model_system_prompt_snapshot_json() {
        let db = Db::open_in_memory().unwrap();
        let mut row = db.new_session_row("p", "/x", "builder").await.unwrap();
        row.model_system_prompt_snapshot_json =
            r#"{"prompts":{"p":{"m":"model instructions"}}}"#.to_string();

        db.insert_session_row(&row).await.unwrap();

        let got = db.get_session(row.session_id).await.unwrap().unwrap();
        assert_eq!(
            got.model_system_prompt_snapshot_json,
            r#"{"prompts":{"p":{"m":"model instructions"}}}"#
        );
    }

    #[tokio::test]
    async fn insert_session_row_round_trips_redaction_table_json() {
        let db = Db::open_in_memory().unwrap();
        let mut row = db.new_session_row("p", "/x", "builder").await.unwrap();
        row.redaction_table_json =
            Some(r#"{"rules":[{"kind":"literal","value":"persisted-secret-value"}]}"#.to_string());
        db.insert_session_row(&row).await.unwrap();

        let got = db.get_session(row.session_id).await.unwrap().unwrap();
        assert_eq!(
            got.redaction_table_json.as_deref(),
            Some(r#"{"rules":[{"kind":"literal","value":"persisted-secret-value"}]}"#)
        );
    }

    /// Push a session's `last_active_at` into the past so recency ordering is
    /// deterministic without sleeping across a whole-second timestamp boundary.
    async fn backdate_session(db: &Db, session_id: Uuid, seconds: i64) {
        db.write(move |conn| {
            conn.execute(
                "UPDATE sessions
                    SET started_at = started_at - ?1,
                        last_active_at = last_active_at - ?1
                  WHERE session_id = ?2",
                params![seconds, session_id.to_string()],
            )
            .context("backdating session")?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn touch_updates_last_active() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
        db.touch_session(s.session_id).await.unwrap();
        let g = db.get_session(s.session_id).await.unwrap().unwrap();
        assert!(g.last_active_at >= s.last_active_at);
    }

    #[tokio::test]
    async fn most_recent_open() {
        let db = Db::open_in_memory().unwrap();
        let _ = db.create_session("p", "/x", "a").await.unwrap();
        let s2 = db.create_session("p", "/x", "a").await.unwrap();
        db.end_session(s2.session_id).await.unwrap();
        let recent = db.most_recent_open_session_for("p").await.unwrap().unwrap();
        assert_ne!(recent.session_id, s2.session_id);
    }

    #[tokio::test]
    async fn create_session_populates_short_id() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
        let sid = s.short_id.expect("short_id missing");
        assert_eq!(sid.len(), SHORT_ID_LEN);
        assert!(sid.chars().all(|c| CROCKFORD_BASE32.contains(&(c as u8))));
        let by_short = db
            .get_session_by_short_id("p", &sid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_short.session_id, s.session_id);
    }

    #[tokio::test]
    async fn short_ids_unique_within_project() {
        let db = Db::open_in_memory().unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let s = db.create_session("p", "/x", "a").await.unwrap();
            assert!(seen.insert(s.short_id.unwrap()));
        }
    }

    #[tokio::test]
    async fn create_session_retries_short_id_collision_at_insert() {
        let db = Db::open_in_memory().unwrap();
        set_test_short_ids(&db, &["aaaaaa"]).await;
        let first = db.create_session("p", "/x", "a").await.unwrap();
        assert_eq!(first.short_id.as_deref(), Some("aaaaaa"));

        set_test_short_ids(&db, &["aaaaaa", "bbbbbb"]).await;
        let second = db.create_session("p", "/x", "a").await.unwrap();
        assert_eq!(second.short_id.as_deref(), Some("bbbbbb"));
        assert_eq!(
            db.get_session(second.session_id)
                .await
                .unwrap()
                .unwrap()
                .short_id
                .as_deref(),
            Some("bbbbbb")
        );
    }

    #[tokio::test]
    async fn deferred_insert_retries_and_returns_final_short_id() {
        let db = Db::open_in_memory().unwrap();
        set_test_short_ids(&db, &["aaaaaa"]).await;
        let row = db.new_session_row("p", "/x", "a").await.unwrap();
        assert_eq!(row.short_id.as_deref(), Some("aaaaaa"));

        set_test_short_ids(&db, &["aaaaaa"]).await;
        let competing = db.create_session("p", "/x", "a").await.unwrap();
        assert_eq!(competing.short_id.as_deref(), Some("aaaaaa"));

        set_test_short_ids(&db, &["bbbbbb"]).await;
        let inserted = db.insert_session_row(&row).await.unwrap();
        assert_eq!(inserted.short_id.as_deref(), Some("bbbbbb"));
        let got = db.get_session(row.session_id).await.unwrap().unwrap();
        assert_eq!(got.short_id.as_deref(), Some("bbbbbb"));
    }

    #[tokio::test]
    async fn create_fork_retries_short_id_collision_at_insert() {
        let db = Db::open_in_memory().unwrap();
        set_test_short_ids(&db, &["aaaaaa"]).await;
        let parent = db.create_session("p", "/x", "a").await.unwrap();

        set_test_short_ids(&db, &["aaaaaa", "bbbbbb"]).await;
        let fork = db.create_fork(parent.session_id, None).await.unwrap();
        assert_eq!(fork.short_id.as_deref(), Some("bbbbbb"));
        assert_eq!(
            db.get_session(fork.session_id)
                .await
                .unwrap()
                .unwrap()
                .short_id
                .as_deref(),
            Some("bbbbbb")
        );
    }

    #[tokio::test]
    async fn ensure_short_id_retries_backfill_collision() {
        let db = Db::open_in_memory().unwrap();
        set_test_short_ids(&db, &["aaaaaa"]).await;
        let existing = db.create_session("p", "/x", "a").await.unwrap();
        assert_eq!(existing.short_id.as_deref(), Some("aaaaaa"));

        set_test_short_ids(&db, &["bbbbbb"]).await;
        let target = db.create_session("p", "/x", "a").await.unwrap();
        db.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET short_id = NULL WHERE session_id = ?1",
                [target.session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        set_test_short_ids(&db, &["aaaaaa", "cccccc"]).await;
        let backfilled = db.ensure_short_id(target.session_id).await.unwrap();
        assert_eq!(backfilled, "cccccc");
    }

    #[tokio::test]
    async fn short_id_retry_exhaustion_names_the_condition() {
        let db = Db::open_in_memory().unwrap();
        set_test_short_ids(&db, &["aaaaaa"]).await;
        db.create_session("p", "/x", "a").await.unwrap();

        set_test_short_ids(
            &db,
            &[
                "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa",
                "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa", "aaaaaa",
                "aaaaaa", "aaaaaa",
            ],
        )
        .await;
        let err = db.create_session("p", "/x", "a").await.unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("session short-id generation exhausted"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test]
    async fn create_fork_inherits_parent_metadata() {
        let db = Db::open_in_memory().unwrap();
        let mut parent = db.new_session_row("p", "/proj", "Build").await.unwrap();
        parent.provider = Some("anthropic".to_string());
        parent.model = Some("opus-4-7".to_string());
        let model_selection = serde_json::json!({
            "provider": "anthropic",
            "model": "opus-4-7",
            "reasoning_effort": { "value": "high" },
            "thinking_mode": "high",
            "prompt_cache_retention": "extended"
        });
        parent.model_selection_json = Some(model_selection.to_string());
        parent.redaction_table_json = Some(
            r#"{"entries":[{"value":"fork-secret","class":"ordinary","origin":"$TEST"}],"placeholder":"[redacted]","disabled":false,"unsupported_files":[]}"#
                .to_string(),
        );
        parent.model_system_prompt_snapshot_json =
            r#"{"prompts":{"anthropic":{"opus-4-7":"fork prompt"}}}"#.to_string();
        let parent = db.insert_session_row(&parent).await.unwrap();
        let fork_point = record_message(&db, parent.session_id, "fork here", false)
            .await
            .to_string();
        let parent = db.get_session(parent.session_id).await.unwrap().unwrap();
        let fork = db
            .create_fork(parent.session_id, Some(fork_point.clone()))
            .await
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
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                fork.model_selection_json
                    .as_deref()
                    .expect("fork inherits complete model selection")
            )
            .unwrap(),
            model_selection
        );
        assert!(
            fork.redaction_table_json
                .as_deref()
                .is_none_or(|json| !json.contains("fork-secret")),
            "fork must not copy plaintext redaction literals"
        );
    }

    #[tokio::test]
    async fn session_fork_copies_vault_sealed_and_redaction_without_plaintext() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/repo", "Build").await.unwrap();
        db.upsert_sealed_value(
            parent.session_id,
            "prod_token",
            "long-high-entropy-token",
            "reason",
            "user",
        )
        .await
        .unwrap();
        db.set_session_redaction_table_json(
            parent.session_id,
            Some(r#"{"entries":[{"value":"fork-secret"}]}"#.to_string()),
        )
        .await
        .unwrap();
        let fork = db.create_fork(parent.session_id, None).await.unwrap();
        let child_value: Option<String> = db
            .blocking_write_for_sync_maintenance({
                let sid = fork.session_id.to_string();
                move |conn| {
                    Ok(conn.query_row(
                        "SELECT value FROM sealed_values WHERE session_id = ?1 AND value_id = 'prod_token'",
                        rusqlite::params![sid],
                        |row| row.get(0),
                    )?)
                }
            })
            .unwrap();
        assert!(
            child_value
                .as_deref()
                .is_none_or(|raw| raw != "long-high-entropy-token")
        );
        assert!(
            fork.redaction_table_json
                .as_deref()
                .is_none_or(|json| !json.contains("fork-secret"))
        );
    }

    #[tokio::test]
    async fn create_fork_copies_transcript_and_then_diverges() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        let first = db
            .insert_session_event(
                parent.session_id,
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({"text": "parent before fork"}),
            )
            .await
            .unwrap();
        db.pin_message(parent.session_id, first).await.unwrap();

        let fork = db.create_fork(parent.session_id, None).await.unwrap();
        let fork_events = db.list_session_events(fork.session_id).await.unwrap();
        assert_eq!(fork_events.len(), 1);
        assert_eq!(fork_events[0].data["text"], "parent before fork");
        let fork_pins = db.list_pin_seqs(fork.session_id).await.unwrap();
        assert_eq!(fork_pins, vec![fork_events[0].seq]);

        db.insert_session_event(
            parent.session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "parent after fork"}),
        )
        .await
        .unwrap();
        db.insert_session_event(
            fork.session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "child after fork"}),
        )
        .await
        .unwrap();

        let parent_events = db.list_session_events(parent.session_id).await.unwrap();
        let fork_events = db.list_session_events(fork.session_id).await.unwrap();
        assert_eq!(parent_events.len(), 2);
        assert_eq!(fork_events.len(), 2);
        assert_eq!(parent_events[1].data["text"], "parent after fork");
        assert_eq!(fork_events[1].data["text"], "child after fork");
    }

    #[tokio::test]
    async fn copy_fork_transcript_truncates_at_seq() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        record_message(&db, parent.session_id, "s1", false).await;
        let fork_point = record_message(&db, parent.session_id, "s2", true).await;
        record_message(&db, parent.session_id, "s3", false).await;
        record_message(&db, parent.session_id, "s4", true).await;

        let fork = db
            .create_fork(parent.session_id, Some(fork_point.to_string()))
            .await
            .unwrap();
        let fork_events = db.list_session_events(fork.session_id).await.unwrap();
        let texts: Vec<_> = fork_events
            .iter()
            .filter_map(|row| row.data["text"].as_str())
            .collect();

        assert_eq!(texts, vec!["s1", "s2"]);
    }

    #[tokio::test]
    async fn fork_event_copy_failure_rolls_back_child_session() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        record_message(&db, parent.session_id, "fail-event-copy", false).await;
        install_trigger(
            &db,
            "CREATE TEMP TRIGGER fail_fork_event_copy
             BEFORE INSERT ON session_events
             WHEN NEW.data_json LIKE '%fail-event-copy%'
              AND (SELECT parent_session_id FROM sessions WHERE session_id = NEW.session_id) IS NOT NULL
             BEGIN
                 SELECT RAISE(FAIL, 'injected fork event copy failure');
             END;",
        )
        .await;

        let err = db.create_fork(parent.session_id, None).await.unwrap_err();

        assert!(
            format!("{err:#}").contains("injected fork event copy failure"),
            "unexpected error: {err:#}"
        );
        assert!(
            fork_rows_for_parent(&db, parent.session_id)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn fork_tool_call_copy_failure_rolls_back_child_session() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        record_tool_timeline(&db, parent.session_id, "fail-tool-copy").await;
        record_tool_call_event(&db, parent.session_id, "fail-tool-copy", 100).await;
        install_trigger(
            &db,
            "CREATE TEMP TRIGGER fail_fork_tool_copy
             BEFORE INSERT ON tool_call_events
             WHEN NEW.call_id = 'fail-tool-copy'
              AND (SELECT parent_session_id FROM sessions WHERE session_id = NEW.session_id) IS NOT NULL
             BEGIN
                 SELECT RAISE(FAIL, 'injected fork tool copy failure');
             END;",
        )
        .await;

        let err = db.create_fork(parent.session_id, None).await.unwrap_err();

        assert!(
            format!("{err:#}").contains("injected fork tool copy failure"),
            "unexpected error: {err:#}"
        );
        assert!(
            fork_rows_for_parent(&db, parent.session_id)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn fork_pin_copy_failure_rolls_back_child_session() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        let seq = record_message(&db, parent.session_id, "pinned", false).await;
        db.pin_message(parent.session_id, seq).await.unwrap();
        install_trigger(
            &db,
            "CREATE TEMP TRIGGER fail_fork_pin_copy
             BEFORE INSERT ON pins
             WHEN (SELECT parent_session_id FROM sessions WHERE session_id = NEW.session_id) IS NOT NULL
             BEGIN
                 SELECT RAISE(FAIL, 'injected fork pin copy failure');
             END;",
        )
        .await;

        let err = db.create_fork(parent.session_id, None).await.unwrap_err();

        assert!(
            format!("{err:#}").contains("injected fork pin copy failure"),
            "unexpected error: {err:#}"
        );
        assert!(
            fork_rows_for_parent(&db, parent.session_id)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn fork_at_tail_seq_equals_fork_none() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        record_message(&db, parent.session_id, "s1", false).await;
        let tail = record_message(&db, parent.session_id, "s2", true).await;

        let fork_at_tail = db
            .create_fork(parent.session_id, Some(tail.to_string()))
            .await
            .unwrap();
        let fork_at_none = db.create_fork(parent.session_id, None).await.unwrap();
        let tail_payloads: Vec<_> = db
            .list_session_events(fork_at_tail.session_id)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.data)
            .collect();
        let none_payloads: Vec<_> = db
            .list_session_events(fork_at_none.session_id)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.data)
            .collect();

        assert_eq!(tail_payloads, none_payloads);
    }

    #[tokio::test]
    async fn fork_truncates_pins() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        let s1 = record_message(&db, parent.session_id, "s1", false).await;
        let fork_point = record_message(&db, parent.session_id, "s2", true).await;
        let s3 = record_message(&db, parent.session_id, "s3", false).await;
        db.pin_message(parent.session_id, s1).await.unwrap();
        db.pin_message(parent.session_id, s3).await.unwrap();

        let fork = db
            .create_fork(parent.session_id, Some(fork_point.to_string()))
            .await
            .unwrap();
        let fork_events = db.list_session_events(fork.session_id).await.unwrap();
        let fork_pins = db.list_pin_seqs(fork.session_id).await.unwrap();

        assert_eq!(fork_pins, vec![fork_events[0].seq]);
    }

    #[tokio::test]
    async fn fork_truncates_tool_calls() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        record_message(&db, parent.session_id, "s1", false).await;
        record_tool_timeline(&db, parent.session_id, "keep").await;
        let fork_point = record_message(&db, parent.session_id, "s2", true).await;
        record_tool_timeline(&db, parent.session_id, "drop").await;
        record_tool_call_event(&db, parent.session_id, "keep", 100).await;
        record_tool_call_event(&db, parent.session_id, "drop", 200).await;

        let fork = db
            .create_fork(parent.session_id, Some(fork_point.to_string()))
            .await
            .unwrap();

        assert_eq!(fork_tool_call_ids(&db, fork.session_id).await, vec!["keep"]);
    }

    #[tokio::test]
    async fn fork_unparsable_turn_id_errors() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        record_message(&db, parent.session_id, "s1", false).await;

        let err = db
            .create_fork(parent.session_id, Some("turn-x".to_string()))
            .await
            .unwrap_err();

        assert!(format!("{err:#}").contains("invalid fork point turn id"));
    }

    #[tokio::test]
    async fn fork_missing_seq_errors() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        let only = record_message(&db, parent.session_id, "s1", false).await;

        let err = db
            .create_fork(parent.session_id, Some((only + 100).to_string()))
            .await
            .unwrap_err();

        assert!(format!("{err:#}").contains("was not found in parent session"));
    }

    #[tokio::test]
    async fn list_forks_returns_children_most_recent_first() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let f1 = db.create_fork(parent.session_id, None).await.unwrap();
        let f2 = db.create_fork(parent.session_id, None).await.unwrap();
        backdate_session(&db, f1.session_id, 10).await;
        let forks = db.list_forks(parent.session_id).await.unwrap();
        assert_eq!(forks.len(), 2);
        assert_eq!(forks[0].session_id, f2.session_id);
        assert_eq!(db.count_forks_for(parent.session_id).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn rename_sets_user_renamed_and_blocks_auto_title() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
        db.rename_session(s.session_id, "my-custom-title")
            .await
            .unwrap();
        let row = db.get_session(s.session_id).await.unwrap().unwrap();
        assert!(row.user_renamed);
        assert_eq!(row.title.as_deref(), Some("my-custom-title"));
        let updated = db.set_auto_title(s.session_id, "robot-name").await.unwrap();
        assert!(!updated, "auto-title should refuse a user-renamed row");
        let row2 = db.get_session(s.session_id).await.unwrap().unwrap();
        assert_eq!(row2.title.as_deref(), Some("my-custom-title"));
    }

    #[tokio::test]
    async fn set_auto_title_populates_unset_title() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
        let updated = db.set_auto_title(s.session_id, "auto-name").await.unwrap();
        assert!(updated);
        let row = db.get_session(s.session_id).await.unwrap().unwrap();
        assert!(!row.user_renamed);
        assert_eq!(row.title.as_deref(), Some("auto-name"));
    }

    #[tokio::test]
    async fn explicit_auto_title_clears_user_renamed() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
        db.rename_session(s.session_id, "manual-name")
            .await
            .unwrap();
        let updated = db
            .set_explicit_auto_title(s.session_id, "generated-name")
            .await
            .unwrap();
        assert!(updated);
        let row = db.get_session(s.session_id).await.unwrap().unwrap();
        assert!(!row.user_renamed);
        assert_eq!(row.title.as_deref(), Some("generated-name"));
    }

    #[tokio::test]
    async fn explicit_auto_title_if_untitled_has_single_winner() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
        let first = db
            .set_explicit_auto_title_if_untitled(s.session_id, "first-name")
            .await
            .unwrap();
        let second = db
            .set_explicit_auto_title_if_untitled(s.session_id, "second-name")
            .await
            .unwrap();
        assert!(first);
        assert!(!second);
        let row = db.get_session(s.session_id).await.unwrap().unwrap();
        assert!(!row.user_renamed);
        assert_eq!(row.title.as_deref(), Some("first-name"));
    }

    #[tokio::test]
    async fn title_recovery_nudge_state_transitions_are_atomic() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();

        // Precondition: a brand-new session loads with no nudge, read back
        // through the real create+load path (not the in-memory struct).
        let created = db.get_session(s.session_id).await.unwrap().unwrap();
        assert_eq!(
            created.title_recovery_nudge_state,
            TitleRecoveryNudgeState::None,
            "a new session must default to none"
        );

        // Arm an eligible, untitled session: none -> pending, reports the move.
        assert!(db.arm_title_recovery_nudge(s.session_id).await.unwrap());
        assert_eq!(
            nudge_of(&db, s.session_id).await,
            TitleRecoveryNudgeState::Pending
        );

        // Duplicate arm while pending is a no-op: reports false and leaves a
        // single pending state (repeated failures coalesce into one nudge).
        assert!(!db.arm_title_recovery_nudge(s.session_id).await.unwrap());
        assert_eq!(
            nudge_of(&db, s.session_id).await,
            TitleRecoveryNudgeState::Pending
        );

        // Claim is exactly once: the first claim wins pending -> consumed.
        assert!(db.claim_title_recovery_nudge(s.session_id).await.unwrap());
        assert_eq!(
            nudge_of(&db, s.session_id).await,
            TitleRecoveryNudgeState::Consumed
        );
        // A second claim finds no pending state and reports false.
        assert!(!db.claim_title_recovery_nudge(s.session_id).await.unwrap());
        assert_eq!(
            nudge_of(&db, s.session_id).await,
            TitleRecoveryNudgeState::Consumed
        );

        // A later distinct failure re-arms a consumed, still-eligible session.
        assert!(db.arm_title_recovery_nudge(s.session_id).await.unwrap());
        assert_eq!(
            nudge_of(&db, s.session_id).await,
            TitleRecoveryNudgeState::Pending
        );

        // Storing an automatic title clears the latch back to none.
        assert!(db.set_auto_title(s.session_id, "auto-name").await.unwrap());
        let titled = db.get_session(s.session_id).await.unwrap().unwrap();
        assert_eq!(titled.title.as_deref(), Some("auto-name"));
        assert_eq!(
            titled.title_recovery_nudge_state,
            TitleRecoveryNudgeState::None,
            "a stored title must clear a pending nudge"
        );

        // A titled session is ineligible: arm refuses and the latch stays none.
        assert!(!db.arm_title_recovery_nudge(s.session_id).await.unwrap());
        assert_eq!(
            nudge_of(&db, s.session_id).await,
            TitleRecoveryNudgeState::None
        );
        // Claiming a session with no pending nudge reports false.
        assert!(!db.claim_title_recovery_nudge(s.session_id).await.unwrap());
    }

    #[tokio::test]
    async fn title_recovery_nudge_arm_refuses_ineligible_sessions() {
        let db = Db::open_in_memory().unwrap();

        // User-renamed session: user intent wins, arm refuses.
        let renamed = db.create_session("p", "/x", "a").await.unwrap();
        db.rename_session(renamed.session_id, "mine").await.unwrap();
        assert!(
            !db.arm_title_recovery_nudge(renamed.session_id)
                .await
                .unwrap()
        );
        assert_eq!(
            nudge_of(&db, renamed.session_id).await,
            TitleRecoveryNudgeState::None
        );

        // Ephemeral `/side` fork: never nudged.
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let side = db
            .create_ephemeral_fork(parent.session_id, None)
            .await
            .unwrap();
        assert!(side.ephemeral);
        assert!(!db.arm_title_recovery_nudge(side.session_id).await.unwrap());
        assert_eq!(
            nudge_of(&db, side.session_id).await,
            TitleRecoveryNudgeState::None
        );

        // Already-titled (auto) session: ineligible because title is set.
        let autotitled = db.create_session("p", "/x", "a").await.unwrap();
        assert!(
            db.set_auto_title(autotitled.session_id, "auto")
                .await
                .unwrap()
        );
        assert!(
            !db.arm_title_recovery_nudge(autotitled.session_id)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn title_recovery_claim_fails_closed_for_ineligible_session() {
        // Belt-and-suspenders (B8-b): even if a latch is left `pending` while the
        // session became ineligible (a path forgot to clear it), the claim must
        // fail closed. Force the inconsistent state by setting `user_renamed`
        // directly, bypassing the latch-clearing title helpers.
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
        assert!(db.arm_title_recovery_nudge(s.session_id).await.unwrap());
        assert_eq!(
            nudge_of(&db, s.session_id).await,
            TitleRecoveryNudgeState::Pending
        );

        // Precondition: the session is now user-renamed but the latch is STILL
        // pending (the exact state the independent claim gate must reject).
        let sid = s.session_id;
        db.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET user_renamed = 1 WHERE session_id = ?1",
                params![sid.to_string()],
            )
            .context("test: set user_renamed")?;
            Ok(())
        })
        .await
        .unwrap();
        let row = db.get_session(s.session_id).await.unwrap().unwrap();
        assert!(row.user_renamed);
        assert_eq!(
            row.title_recovery_nudge_state,
            TitleRecoveryNudgeState::Pending,
            "precondition: latch still pending despite user_renamed"
        );

        // The claim must fail closed and NOT consume the latch.
        assert!(
            !db.claim_title_recovery_nudge(s.session_id).await.unwrap(),
            "an ineligible (user-renamed) session must not be claimable"
        );
        assert_eq!(
            nudge_of(&db, s.session_id).await,
            TitleRecoveryNudgeState::Pending,
            "a failed-closed claim leaves the latch untouched"
        );
    }

    #[tokio::test]
    async fn forks_and_tangents_start_with_no_title_recovery_nudge() {
        let db = Db::open_in_memory().unwrap();

        // Plain fork: arm the parent to pending, then fork. The child must NOT
        // inherit the pending nudge (unlike user_content_tokens/title_stage,
        // which forks copy).
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        assert!(
            db.arm_title_recovery_nudge(parent.session_id)
                .await
                .unwrap()
        );
        assert_eq!(
            nudge_of(&db, parent.session_id).await,
            TitleRecoveryNudgeState::Pending,
            "parent must be pending so the test is non-vacuous"
        );

        let fork = db.create_fork(parent.session_id, None).await.unwrap();
        assert_eq!(
            fork.title_recovery_nudge_state,
            TitleRecoveryNudgeState::None
        );
        assert_eq!(
            nudge_of(&db, fork.session_id).await,
            TitleRecoveryNudgeState::None
        );

        // Ephemeral `/side` fork from the pending parent: also none.
        let side = db
            .create_ephemeral_fork(parent.session_id, None)
            .await
            .unwrap();
        assert_eq!(
            side.title_recovery_nudge_state,
            TitleRecoveryNudgeState::None
        );
        assert_eq!(
            nudge_of(&db, side.session_id).await,
            TitleRecoveryNudgeState::None
        );

        // Non-tangent `/btw` fork from the pending parent: also none.
        let btw = db.create_btw_fork(parent.session_id, false).await.unwrap();
        assert!(btw.created);
        assert_eq!(
            nudge_of(&db, btw.info.session_id).await,
            TitleRecoveryNudgeState::None
        );

        // Tangent `/btw` fork from a second pending parent: also none.
        let parent2 = db.create_session("p", "/proj", "Build").await.unwrap();
        assert!(
            db.arm_title_recovery_nudge(parent2.session_id)
                .await
                .unwrap()
        );
        let tangent = db.create_btw_fork(parent2.session_id, true).await.unwrap();
        assert!(tangent.created);
        assert_eq!(
            nudge_of(&db, tangent.info.session_id).await,
            TitleRecoveryNudgeState::None
        );
    }

    #[tokio::test]
    async fn list_root_sessions_excludes_forks() {
        let db = Db::open_in_memory().unwrap();
        let root_a = db.create_session("p", "/x", "a").await.unwrap();
        let _fork_a = db.create_fork(root_a.session_id, None).await.unwrap();
        let _root_b = db.create_session("p", "/x", "a").await.unwrap();
        let roots = db.list_root_sessions("p", 100).await.unwrap();
        assert_eq!(roots.len(), 2);
        assert!(roots.iter().all(|r| r.parent_session_id.is_none()));
    }

    #[tokio::test]
    async fn delete_session_cascade_drops_forks() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let child = db.create_fork(parent.session_id, None).await.unwrap();
        let grandchild = db.create_fork(child.session_id, None).await.unwrap();
        db.delete_session(parent.session_id).await.unwrap();
        assert!(db.get_session(parent.session_id).await.unwrap().is_none());
        assert!(db.get_session(child.session_id).await.unwrap().is_none());
        assert!(
            db.get_session(grandchild.session_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_session_cascade_failure_rolls_back_deleted_descendants() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let child = db.create_fork(parent.session_id, None).await.unwrap();
        let grandchild = db.create_fork(child.session_id, None).await.unwrap();
        install_trigger(
            &db,
            &format!(
                "CREATE TEMP TRIGGER fail_cascade_delete
                 BEFORE DELETE ON sessions
                 WHEN OLD.session_id = '{}'
                 BEGIN
                     SELECT RAISE(ABORT, 'injected cascade delete failure');
                 END;",
                child.session_id
            ),
        )
        .await;

        let err = db.delete_session(parent.session_id).await.unwrap_err();

        assert!(
            format!("{err:#}").contains("injected cascade delete failure"),
            "unexpected error: {err:#}"
        );
        for id in [parent.session_id, child.session_id, grandchild.session_id] {
            assert!(
                session_exists(&db, id).await,
                "{id} should have rolled back"
            );
        }
    }

    #[tokio::test]
    async fn raw_sql_delete_cascades_through_the_fork_tree() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let child = db.create_fork(parent.session_id, None).await.unwrap();
        db.write(move |conn| {
            conn.execute(
                "DELETE FROM sessions WHERE session_id = ?1",
                [parent.session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(db.get_session(parent.session_id).await.unwrap().is_none());
        assert!(db.get_session(child.session_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mark_viewed_sets_marker() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
        assert!(
            db.get_session(s.session_id)
                .await
                .unwrap()
                .unwrap()
                .last_viewed_at
                .is_none()
        );
        db.mark_session_viewed(s.session_id).await.unwrap();
        assert!(
            db.get_session(s.session_id)
                .await
                .unwrap()
                .unwrap()
                .last_viewed_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn archive_cascades_subtree_and_unarchive_recovers() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let child = db.create_fork(parent.session_id, None).await.unwrap();
        let grandchild = db.create_fork(child.session_id, None).await.unwrap();
        // Descendant count excludes the root itself.
        assert_eq!(db.count_descendants(parent.session_id).await.unwrap(), 2);

        db.archive_session(parent.session_id, true).await.unwrap();
        for id in [parent.session_id, child.session_id, grandchild.session_id] {
            assert!(
                db.get_session(id)
                    .await
                    .unwrap()
                    .unwrap()
                    .archived_at
                    .is_some(),
                "archive should cascade the whole subtree"
            );
        }

        // Unarchive recovers a single row (the rest stay archived).
        db.unarchive_session(parent.session_id).await.unwrap();
        assert!(
            db.get_session(parent.session_id)
                .await
                .unwrap()
                .unwrap()
                .archived_at
                .is_none()
        );
        assert!(
            db.get_session(child.session_id)
                .await
                .unwrap()
                .unwrap()
                .archived_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn archive_session_cascade_failure_rolls_back_updated_ancestors() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let child = db.create_fork(parent.session_id, None).await.unwrap();
        let grandchild = db.create_fork(child.session_id, None).await.unwrap();
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
        )
        .await;

        let err = db
            .archive_session(parent.session_id, true)
            .await
            .unwrap_err();

        assert!(
            format!("{err:#}").contains("injected cascade archive failure"),
            "unexpected error: {err:#}"
        );
        for id in [parent.session_id, child.session_id, grandchild.session_id] {
            assert!(
                db.get_session(id)
                    .await
                    .unwrap()
                    .unwrap()
                    .archived_at
                    .is_none(),
                "{id} should not be archived after rollback"
            );
        }
    }

    #[tokio::test]
    async fn is_in_subtree_walks_ancestors() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "a").await.unwrap();
        let child = db.create_fork(root.session_id, None).await.unwrap();
        let grandchild = db.create_fork(child.session_id, None).await.unwrap();
        let btw_only = db.create_session("p", "/x", "a").await.unwrap();
        db.write({
            let root = root.session_id;
            let btw_only = btw_only.session_id;
            move |conn| {
                conn.execute(
                    "UPDATE sessions SET parent_session_id=NULL,btw_parent_session_id=?2 WHERE session_id=?1",
                    params![btw_only.to_string(), root.to_string()],
                )?;
                Ok(())
            }
        })
        .await
        .unwrap();
        let other = db.create_session("p", "/x", "a").await.unwrap();
        assert!(
            db.is_in_subtree(root.session_id, root.session_id)
                .await
                .unwrap()
        );
        assert!(
            db.is_in_subtree(root.session_id, child.session_id)
                .await
                .unwrap()
        );
        assert!(
            db.is_in_subtree(root.session_id, grandchild.session_id)
                .await
                .unwrap()
        );
        assert!(
            db.is_in_subtree(root.session_id, btw_only.session_id)
                .await
                .unwrap(),
            "the shared subtree walker follows the BTW cascade edge"
        );
        assert!(
            !db.is_in_subtree(root.session_id, other.session_id)
                .await
                .unwrap()
        );
        assert!(
            !db.is_in_subtree(child.session_id, root.session_id)
                .await
                .unwrap(),
            "the parent is not in the child's subtree"
        );
    }

    #[tokio::test]
    async fn archive_no_cascade_leaves_forks_live() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let child = db.create_fork(parent.session_id, None).await.unwrap();
        db.archive_session(parent.session_id, false).await.unwrap();
        assert!(
            db.get_session(parent.session_id)
                .await
                .unwrap()
                .unwrap()
                .archived_at
                .is_some()
        );
        assert!(
            db.get_session(child.session_id)
                .await
                .unwrap()
                .unwrap()
                .archived_at
                .is_none()
        );
    }

    #[tokio::test]
    async fn list_session_summaries_scopes_orders_and_groups_forks() {
        // The factored query is the single source of truth for the
        // `/sessions` browser (daemon RPC + TUI daemonless). Assert the
        // three level selections produce the same shape the daemon handler
        // used: project-scoped roots newest-first, forks grouped under a
        // parent, fork/descendant counts, and the all-projects fallback.
        let db = Db::open_in_memory().unwrap();
        let root_a = db.create_session("pid", "/proj", "builder").await.unwrap();
        let root_b = db.create_session("pid", "/proj", "builder").await.unwrap();
        backdate_session(&db, root_a.session_id, 10).await;
        // A session in a different project must not leak into `pid` scope.
        let _other = db
            .create_session("pid2", "/other", "builder")
            .await
            .unwrap();
        // Two forks under root_a (one of them with its own descendant).
        let fork_1 = db.create_fork(root_a.session_id, None).await.unwrap();
        let _grandchild = db.create_fork(fork_1.session_id, None).await.unwrap();

        // Project-scoped roots: only `pid` roots, newest (`root_b`) first.
        let roots = db
            .list_session_summaries(Some("pid"), None, 100)
            .await
            .unwrap();
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
            .await
            .unwrap();
        assert_eq!(forks.len(), 1);
        assert_eq!(forks[0].session_id, fork_1.session_id);
        assert_eq!(forks[0].parent_session_id, Some(root_a.session_id));

        // All-projects fallback (both args None) spans every project.
        let all = db.list_session_summaries(None, None, 100).await.unwrap();
        let project_ids: std::collections::HashSet<_> =
            all.iter().map(|s| s.project_id.as_str()).collect();
        assert!(project_ids.contains("pid"));
        assert!(project_ids.contains("pid2"));
    }

    #[tokio::test]
    async fn list_session_summaries_conn_matches_db_wrapper() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("pid", "/proj", "builder").await.unwrap();
        let _fork = db.create_fork(root.session_id, None).await.unwrap();

        let wrapped = db
            .list_session_summaries(Some("pid"), None, 100)
            .await
            .unwrap();
        let direct = db
            .read(|conn| Db::list_session_summaries_conn(conn, Some("pid"), None, 100))
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(&direct).unwrap(),
            serde_json::to_value(&wrapped).unwrap()
        );
    }

    #[tokio::test]
    async fn list_session_summaries_populates_interrupt_activity_state() {
        use crate::db::wire::{InterruptQuestion, InterruptQuestionSet, SessionActivityState};

        let db = Db::open_in_memory().unwrap();
        let pending = db.create_session("pid", "/proj", "builder").await.unwrap();
        let parked = db.create_session("pid", "/proj", "builder").await.unwrap();
        let interrupted = db.create_session("pid", "/proj", "builder").await.unwrap();
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
        .await
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
        .await
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
            .await
            .unwrap();
        db.mark_interrupt_interrupted(interrupted_id).await.unwrap();

        let summaries = db
            .list_session_summaries(Some("pid"), None, 100)
            .await
            .unwrap();
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

    #[tokio::test]
    async fn list_session_summaries_prefers_actionable_interrupt_over_stale_interrupted_marker() {
        use crate::db::wire::{InterruptQuestion, InterruptQuestionSet, SessionActivityState};

        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("pid", "/proj", "builder").await.unwrap();
        db.raise_interrupted_turn(session.session_id, "builder", "forced drain")
            .await
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
        .await
        .unwrap();

        let summaries = db
            .list_session_summaries(Some("pid"), None, 100)
            .await
            .unwrap();
        let summary = summaries
            .iter()
            .find(|summary| summary.session_id == session.session_id)
            .unwrap();
        assert_eq!(
            summary.activity_state,
            Some(SessionActivityState::PendingQuestion)
        );
    }

    #[tokio::test]
    async fn session_summary_fallbacks_warn_and_keep_defaults() {
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

    #[tokio::test]
    async fn ensure_short_id_backfills_null() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
        // Simulate a pre-0002 row by clearing the short_id.
        db.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET short_id = NULL WHERE session_id = ?1",
                [s.session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let backfilled = db.ensure_short_id(s.session_id).await.unwrap();
        assert_eq!(backfilled.len(), SHORT_ID_LEN);
        // Idempotent: a second call returns the same id, doesn't churn.
        let again = db.ensure_short_id(s.session_id).await.unwrap();
        assert_eq!(again, backfilled);
    }

    // ---- `/side` ephemeral side-conversation forks (migration 0017) -------

    #[tokio::test]
    async fn create_ephemeral_fork_marks_row_ephemeral() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let fork_point = record_message(&db, parent.session_id, "fork here", false).await;
        let side = db
            .create_ephemeral_fork(parent.session_id, Some(fork_point.to_string()))
            .await
            .unwrap();
        assert!(side.ephemeral, "side fork row should be ephemeral");
        assert_eq!(side.parent_session_id, Some(parent.session_id));
        let stored = db.get_session(side.session_id).await.unwrap().unwrap();
        assert!(stored.ephemeral);
        // A plain fork is NOT ephemeral.
        let plain = db.create_fork(parent.session_id, None).await.unwrap();
        assert!(!plain.ephemeral);
    }

    #[tokio::test]
    async fn ephemeral_sessions_excluded_from_all_list_queries() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "a").await.unwrap();
        let _side = db
            .create_ephemeral_fork(root.session_id, None)
            .await
            .unwrap();

        // Root listing: only the persisted root, no ephemeral fork.
        let roots = db.list_root_sessions("p", 100).await.unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].session_id, root.session_id);

        // Direct-forks listing of the parent: the ephemeral fork is hidden.
        let forks = db.list_forks(root.session_id).await.unwrap();
        assert!(
            forks.is_empty(),
            "ephemeral fork must not appear in list_forks"
        );
        assert_eq!(db.count_forks_for(root.session_id).await.unwrap(), 0);

        // Flat open-session list (`cockpit session list`).
        let open = db.list_sessions(true, 100).await.unwrap();
        assert!(open.iter().all(|s| !s.ephemeral));
        assert_eq!(open.len(), 1);

        // `cockpit -c` continue: never resumes the ephemeral fork.
        let recent = db.most_recent_open_session_for("p").await.unwrap().unwrap();
        assert_eq!(recent.session_id, root.session_id);

        // Browser summaries (the daemon + daemonless shared path).
        let summaries = db
            .list_session_summaries(Some("p"), None, 100)
            .await
            .unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].fork_count, 0);
    }

    #[tokio::test]
    async fn ephemeral_sessions_are_never_auto_titled() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let side = db
            .create_ephemeral_fork(parent.session_id, None)
            .await
            .unwrap();
        let updated = db
            .set_auto_title(side.session_id, "auto-name")
            .await
            .unwrap();
        assert!(!updated, "auto-title must refuse an ephemeral row");
        let row = db.get_session(side.session_id).await.unwrap().unwrap();
        assert!(row.title.is_none());
    }

    #[tokio::test]
    async fn discard_ephemeral_session_removes_row_and_guards_persisted() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "a").await.unwrap();
        let side = db
            .create_ephemeral_fork(parent.session_id, None)
            .await
            .unwrap();

        // Discarding the ephemeral fork drops its row.
        assert!(db.discard_ephemeral_session(side.session_id).await.unwrap());
        assert!(db.get_session(side.session_id).await.unwrap().is_none());

        // Guard: discarding a *persisted* session is a no-op, leaves it intact.
        assert!(
            !db.discard_ephemeral_session(parent.session_id)
                .await
                .unwrap()
        );
        assert!(db.get_session(parent.session_id).await.unwrap().is_some());

        // Unknown id is a no-op, not an error.
        assert!(!db.discard_ephemeral_session(Uuid::new_v4()).await.unwrap());
    }

    #[tokio::test]
    async fn sweep_ephemeral_sessions_clears_orphans_only() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "a").await.unwrap();
        let _plain_fork = db.create_fork(root.session_id, None).await.unwrap();
        let side_a = db
            .create_ephemeral_fork(root.session_id, None)
            .await
            .unwrap();
        let side_b = db
            .create_ephemeral_fork(root.session_id, None)
            .await
            .unwrap();

        let removed = db.sweep_ephemeral_sessions().await.unwrap();
        assert_eq!(removed, 2);
        assert!(db.get_session(side_a.session_id).await.unwrap().is_none());
        assert!(db.get_session(side_b.session_id).await.unwrap().is_none());
        // The persisted root + its plain fork survive the sweep.
        assert!(db.get_session(root.session_id).await.unwrap().is_some());
        assert_eq!(db.count_forks_for(root.session_id).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn btw_fork_seeded_to_ceiling() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        record_message(&db, parent.session_id, "first", false).await;
        record_message(&db, parent.session_id, "second", true).await;

        let result = db.create_btw_fork(parent.session_id, false).await.unwrap();

        assert!(result.created);
        assert_eq!(result.info.parent_session_id, parent.session_id);
        assert!(!result.info.tangent);
        assert_eq!(result.info.message_count, 2);
        let events = db
            .list_session_events(result.info.session_id)
            .await
            .unwrap();
        let texts: Vec<_> = events
            .iter()
            .map(|event| event.data["text"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(texts, vec!["first", "second"]);
    }

    #[tokio::test]
    async fn btw_tangent_fork_empty() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        record_message(&db, parent.session_id, "parent context", false).await;

        let result = db.create_btw_fork(parent.session_id, true).await.unwrap();

        assert!(result.created);
        assert!(result.info.tangent);
        assert_eq!(result.info.message_count, 0);
        assert!(
            db.list_session_events(result.info.session_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn btw_schema_enforces_one_live_fork() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();

        let first = db.create_btw_fork(parent.session_id, false).await.unwrap();
        let second = db.create_btw_fork(parent.session_id, true).await.unwrap();

        assert!(first.created);
        assert!(!second.created);
        assert_eq!(first.info.session_id, second.info.session_id);
        assert!(!second.info.tangent, "existing fork identity wins");
        assert!(
            db.list_sessions(false, 100)
                .await
                .unwrap()
                .iter()
                .all(|row| row.session_id != first.info.session_id)
        );
        let direct_count: i64 = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM sessions WHERE btw_parent_session_id = ?1",
                    [parent.session_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .unwrap();
        assert_eq!(direct_count, 1);
    }

    #[tokio::test]
    async fn btw_create_is_atomic_and_unique() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));

        let mut joins = Vec::new();
        for tangent in [false, true] {
            let db = db.clone();
            let barrier = barrier.clone();
            let parent_id = parent.session_id;
            joins.push(tokio::spawn(async move {
                barrier.wait().await;
                db.create_btw_fork(parent_id, tangent).await.unwrap()
            }));
        }

        let first = joins.remove(0).await.unwrap();
        let second = joins.remove(0).await.unwrap();
        assert_eq!(first.info.session_id, second.info.session_id);
        assert_ne!(first.created, second.created);
        let direct_count: i64 = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM sessions WHERE btw_parent_session_id = ?1",
                    [parent.session_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .unwrap();
        assert_eq!(direct_count, 1);
    }

    #[tokio::test]
    async fn btw_orphan_sweep_spares_live_fork() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        let side = db
            .create_ephemeral_fork(parent.session_id, None)
            .await
            .unwrap();
        let btw = db.create_btw_fork(parent.session_id, false).await.unwrap();

        let removed = db.sweep_ephemeral_sessions().await.unwrap();

        assert_eq!(removed, 1);
        assert!(db.get_session(side.session_id).await.unwrap().is_none());
        assert!(db.get_session(btw.info.session_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn btw_end_discards_fork() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        let btw = db.create_btw_fork(parent.session_id, false).await.unwrap();

        assert!(db.end_btw_fork(parent.session_id).await.unwrap());
        assert!(db.get_session(btw.info.session_id).await.unwrap().is_none());
        assert!(!db.end_btw_fork(parent.session_id).await.unwrap());
    }

    #[tokio::test]
    async fn btw_parent_delete_cascades() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        let btw = db.create_btw_fork(parent.session_id, false).await.unwrap();

        db.delete_session(parent.session_id).await.unwrap();

        assert!(db.get_session(parent.session_id).await.unwrap().is_none());
        assert!(db.get_session(btw.info.session_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sweep_ephemeral_sessions_warns_on_delete_failure_and_continues() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "a").await.unwrap();
        let blocked = db
            .create_ephemeral_fork(root.session_id, None)
            .await
            .unwrap();
        let removed = db
            .create_ephemeral_fork(root.session_id, None)
            .await
            .unwrap();
        db.write(move |conn| {
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
        .await
        .unwrap();

        let log = capture_warn_log_async(|| async {
            assert_eq!(db.sweep_ephemeral_sessions().await.unwrap(), 1);
        })
        .await;

        assert!(log.contains("ephemeral session sweep delete failed"));
        assert!(log.contains(&blocked.session_id.to_string()));
        assert!(db.get_session(blocked.session_id).await.unwrap().is_some());
        assert!(db.get_session(removed.session_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cas_set_active_model_conn_advances_revision_and_rejects_stale() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let row = db
            .create_session("proj", "/tmp/proj", "orchestrator-build")
            .await
            .unwrap();
        let ok = db
            .write({
                let id = row.session_id;
                move |conn| {
                    crate::db::Db::cas_set_active_model_conn(
                        conn,
                        id,
                        0,
                        "p",
                        "m",
                        r#"{"provider":"p","model":"m"}"#,
                    )
                }
            })
            .await
            .unwrap();
        assert!(ok);
        let loaded = db.get_session(row.session_id).await.unwrap().unwrap();
        assert_eq!(loaded.active_model_revision, 1);
        assert_eq!(loaded.provider.as_deref(), Some("p"));
        let stale = db
            .write({
                let id = row.session_id;
                move |conn| {
                    crate::db::Db::cas_set_active_model_conn(
                        conn,
                        id,
                        0,
                        "p2",
                        "m2",
                        r#"{"provider":"p2","model":"m2"}"#,
                    )
                }
            })
            .await
            .unwrap();
        assert!(!stale);
        let loaded = db.get_session(row.session_id).await.unwrap().unwrap();
        assert_eq!(loaded.active_model_revision, 1);
        assert_eq!(loaded.provider.as_deref(), Some("p"));
    }

    /// A session holding a *scoped* sealed value cannot be forked at all.
    ///
    /// Fail closed by decision: forking a scoped value has no defined
    /// semantics (grants, in-flight sagas, pre- versus post-rotation state),
    /// and the refusal is typed so a caller can say why.
    #[tokio::test]
    async fn fork_is_refused_when_the_session_owns_scoped_sealed_values() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        db.create_session_sealed_value(
            crate::db::sealed_scope::NewSealedValueRecord {
                record_id: Uuid::new_v4().to_string(),
                scope: crate::db::sealed_scope::SealedScopeKind::Session,
                scope_key: parent.session_id.to_string(),
                name: "prod_token".to_string(),
                description: "deployment credential".to_string(),
                owner_principal: "owner".to_string(),
                created_at_ms: 1_000,
            },
            "very-high-entropy-token".to_string(),
            "deploy".to_string(),
            "user".to_string(),
        )
        .await
        .unwrap();
        assert!(
            db.session_owns_scoped_sealed_values(parent.session_id)
                .await
                .unwrap()
        );

        let error = db.create_fork(parent.session_id, None).await.unwrap_err();
        let typed = error
            .downcast_ref::<SessionForkRefusedSealed>()
            .expect("the refusal is typed and downcastable");
        assert_eq!(typed.parent_session_id, parent.session_id);
        assert_eq!(typed.scoped_value_count, 1);
        assert!(
            format!("{error:#}").contains("no defined semantics"),
            "the error names the reason: {error:#}"
        );

        // The ephemeral fork shares the copy path, so it refuses identically.
        assert!(
            db.create_ephemeral_fork(parent.session_id, None)
                .await
                .unwrap_err()
                .downcast_ref::<SessionForkRefusedSealed>()
                .is_some()
        );
        // A `/btw` fork is *allowed*: it copies no sealed values at all, so it
        // cannot inherit the scoped one and is not the state being prevented.
        db.create_btw_fork(parent.session_id, false)
            .await
            .expect("a /btw fork inherits no sealed values and so is permitted");

        // Nothing is written: the refusal returns before `tx.commit()`, so
        // the fork transaction is dropped and rolled back.
        assert!(
            db.get_session(parent.session_id).await.unwrap().is_some(),
            "the parent session is untouched by a refused fork"
        );
    }

    /// A session holding only *legacy* pre-scoped rows still forks normally:
    /// that copy path is self-contained and unchanged.
    #[tokio::test]
    async fn fork_still_works_with_only_legacy_sealed_rows() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        db.upsert_sealed_value(
            parent.session_id,
            "legacy_token",
            "old-secret",
            "deploy",
            "user",
        )
        .await
        .unwrap();
        assert!(
            !db.session_owns_scoped_sealed_values(parent.session_id)
                .await
                .unwrap(),
            "a legacy row is not a scoped record"
        );

        let fork = db.create_fork(parent.session_id, None).await.unwrap();
        assert_ne!(fork.session_id, parent.session_id);
        assert!(
            db.sealed_value_exists(fork.session_id, "legacy_token")
                .await
                .unwrap(),
            "the unchanged legacy copy path still populates the fork"
        );
    }

    /// Pins the property the `/btw` guard decision rests on: a `/btw` fork
    /// copies the transcript and nothing else, so it inherits neither legacy
    /// nor scoped sealed values, in either creation order.
    ///
    /// If someone later adds sealed-value copying to `create_btw_fork`, this
    /// fails — which is the point, because the reasoning for leaving that path
    /// unguarded depends entirely on it copying nothing.
    #[tokio::test]
    async fn btw_fork_never_inherits_sealed_values_of_either_kind() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/proj", "Build").await.unwrap();
        db.upsert_sealed_value(
            parent.session_id,
            "legacy_token",
            "old-secret",
            "deploy",
            "user",
        )
        .await
        .unwrap();

        // Ordering the review raised: fork first, then create a scoped value.
        let first = db.create_btw_fork(parent.session_id, false).await.unwrap();
        assert!(first.created);
        db.create_session_sealed_value(
            crate::db::sealed_scope::NewSealedValueRecord {
                record_id: Uuid::new_v4().to_string(),
                scope: crate::db::sealed_scope::SealedScopeKind::Session,
                scope_key: parent.session_id.to_string(),
                name: "prod_token".to_string(),
                description: "deployment credential".to_string(),
                owner_principal: "owner".to_string(),
                created_at_ms: 1_000,
            },
            "very-high-entropy-token".to_string(),
            "deploy".to_string(),
            "user".to_string(),
        )
        .await
        .unwrap();

        // The live fork is still returned, and still holds nothing sealed.
        let again = db.create_btw_fork(parent.session_id, false).await.unwrap();
        assert!(!again.created, "the existing /btw fork is returned");
        let fork_id = again.info.session_id;
        for name in ["legacy_token", "prod_token"] {
            assert!(
                !db.sealed_value_exists(fork_id, name).await.unwrap(),
                "a /btw fork must not inherit `{name}`"
            );
        }
        assert!(
            !db.session_owns_scoped_sealed_values(fork_id).await.unwrap(),
            "a /btw fork owns no scoped records of its own"
        );
        // The parent is untouched.
        assert!(
            db.sealed_value_exists(parent.session_id, "prod_token")
                .await
                .unwrap()
        );
    }
}
