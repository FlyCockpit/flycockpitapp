//! Persisted session goals.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{Db, sql::placeholders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalStatus {
    Draft,
    Active,
    Paused,
    Blocked,
    Complete,
    BudgetLimited,
    UsageLimited,
}

impl GoalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Blocked => "blocked",
            Self::Complete => "complete",
            Self::BudgetLimited => "budget_limited",
            Self::UsageLimited => "usage_limited",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "draft" => Ok(Self::Draft),
            "active" => Ok(Self::Active),
            "paused" => Ok(Self::Paused),
            "blocked" => Ok(Self::Blocked),
            "complete" => Ok(Self::Complete),
            "budget_limited" => Ok(Self::BudgetLimited),
            "usage_limited" => Ok(Self::UsageLimited),
            _ => anyhow::bail!("invalid goal status `{s}`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionGoal {
    pub id: Uuid,
    pub session_id: Uuid,
    pub project_id: String,
    pub objective: String,
    pub context: Option<String>,
    pub status: GoalStatus,
    pub token_budget: Option<i64>,
    pub tokens_used: i64,
    pub blocked_attempts: i64,
    pub last_read_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalUpdateOutcome {
    Updated(SessionGoal),
    BlockAttempt { attempts: i64, required: i64 },
}

pub const BLOCK_ATTEMPTS_REQUIRED: i64 = 3;
const OPEN_STATUS_VALUES: [&str; 6] = [
    "draft",
    "active",
    "paused",
    "blocked",
    "budget_limited",
    "usage_limited",
];

impl Db {
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn create_session_goal(
        &self,
        session_id: Uuid,
        project_id: &str,
        objective: &str,
        context: Option<&str>,
        token_budget: Option<i64>,
    ) -> Result<SessionGoal> {
        let objective = objective.trim();
        if objective.is_empty() {
            anyhow::bail!("goal objective must not be empty");
        }
        if let Some(b) = token_budget
            && b <= 0
        {
            anyhow::bail!("token_budget must be positive");
        }
        let id = Uuid::new_v4();
        let now = Utc::now().timestamp();
        let project_id = project_id.to_owned();
        let objective = objective.to_owned();
        let context = context.map(str::to_owned);
        self.write_blocking(move |conn| {
            let open_statuses = open_status_placeholders(2);
            let existing_params = bind_session_and_open_statuses(session_id.to_string());
            let existing_param_refs = param_refs(&existing_params);
            let existing: Option<String> = conn
                .query_row(
                    &format!(
                        "SELECT id FROM session_goals
                     WHERE session_id = ?1
                       AND status IN ({open_statuses})
                     LIMIT 1"
                    ),
                    existing_param_refs.as_slice(),
                    |row| row.get(0),
                )
                .optional()
                .context("checking existing session goal")?;
            if existing.is_some() {
                anyhow::bail!("session already has an open goal");
            }
            conn.execute(
                "INSERT INTO session_goals
                    (id, session_id, project_id, objective, context, status, token_budget, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7, ?7)",
                params![
                    id.to_string(),
                    session_id.to_string(),
                    project_id,
                    objective,
                    clean_opt(context.as_deref()),
                    token_budget,
                    now
                ],
            )
            .context("inserting session_goal")?;
            load_goal(conn, session_id, id)
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn current_session_goal(
        &self,
        session_id: Uuid,
        mark_read: bool,
    ) -> Result<Option<SessionGoal>> {
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            let open_statuses = open_status_placeholders(2);
            let goal_params = bind_session_and_open_statuses(session_id.to_string());
            let goal_param_refs = param_refs(&goal_params);
            let goal = conn
                .query_row(
                    &format!(
                        "SELECT id, session_id, project_id, objective, context, status, token_budget,
                            tokens_used, blocked_attempts, last_read_at, created_at, updated_at
                     FROM session_goals
                     WHERE session_id = ?1
                       AND status IN ({open_statuses})
                     ORDER BY CASE status
                         WHEN 'active' THEN 0
                         WHEN 'draft' THEN 1
                         WHEN 'paused' THEN 2
                         WHEN 'blocked' THEN 3
                         WHEN 'budget_limited' THEN 4
                         WHEN 'usage_limited' THEN 5
                     END, updated_at DESC
                     LIMIT 1"
                    ),
                    goal_param_refs.as_slice(),
                    decode_goal,
                )
                .optional()
                .context("loading current session goal")?;
            if mark_read && let Some(goal) = &goal {
                conn.execute(
                    "UPDATE session_goals SET last_read_at = ?1 WHERE id = ?2",
                    params![now, goal.id.to_string()],
                )
                .context("marking goal read")?;
                let mut goal = goal.clone();
                goal.last_read_at = Some(now);
                return Ok(Some(goal));
            }
            Ok(goal)
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn update_session_goal(
        &self,
        session_id: Uuid,
        status: GoalStatus,
        evidence: Option<&str>,
        blocker: Option<&str>,
        context_delta: Option<&str>,
    ) -> Result<GoalUpdateOutcome> {
        let now = Utc::now().timestamp();
        let evidence = evidence.map(str::to_owned);
        let blocker = blocker.map(str::to_owned);
        let context_delta = context_delta.map(str::to_owned);
        self.write_blocking(move |conn| {
            let mut goal = current_goal_required(conn, session_id)?;
            match status {
                GoalStatus::Complete => {
                    if clean_opt(evidence.as_deref()).is_none() {
                        anyhow::bail!("complete requires evidence");
                    }
                    let read_at = goal
                        .last_read_at
                        .ok_or_else(|| anyhow::anyhow!("complete requires get_goal first"))?;
                    if read_at < goal.updated_at {
                        anyhow::bail!("goal changed since last get_goal; reread before complete");
                    }
                }
                GoalStatus::Blocked => {
                    if clean_opt(blocker.as_deref()).is_none() {
                        anyhow::bail!("blocked requires blocker");
                    }
                    let attempts = goal.blocked_attempts + 1;
                    if attempts < BLOCK_ATTEMPTS_REQUIRED {
                        conn.execute(
                            "UPDATE session_goals
                                SET blocked_attempts = ?1, updated_at = ?2
                              WHERE id = ?3",
                            params![attempts, now, goal.id.to_string()],
                        )
                        .context("recording blocked attempt")?;
                        return Ok(GoalUpdateOutcome::BlockAttempt {
                            attempts,
                            required: BLOCK_ATTEMPTS_REQUIRED,
                        });
                    }
                    goal.blocked_attempts = attempts;
                }
                GoalStatus::Active
                | GoalStatus::Paused
                | GoalStatus::BudgetLimited
                | GoalStatus::UsageLimited => {}
                GoalStatus::Draft => anyhow::bail!("update_goal cannot set draft"),
            }

            let context = append_context(goal.context.as_deref(), context_delta.as_deref());
            conn.execute(
                "UPDATE session_goals
                    SET status = ?1,
                        context = COALESCE(?2, context),
                        blocked_attempts = CASE WHEN ?1 = 'blocked' THEN ?3 ELSE 0 END,
                        updated_at = ?4
                  WHERE id = ?5 AND session_id = ?6",
                params![
                    status.as_str(),
                    context,
                    goal.blocked_attempts,
                    now,
                    goal.id.to_string(),
                    session_id.to_string()
                ],
            )
            .context("updating session_goal")?;
            Ok(GoalUpdateOutcome::Updated(load_goal(
                conn, session_id, goal.id,
            )?))
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn clear_session_goal(&self, session_id: Uuid) -> Result<bool> {
        self.write_blocking(move |conn| {
            let now = Utc::now().timestamp();
            let open_statuses = open_status_placeholders(3);
            let mut bind: Vec<Box<dyn rusqlite::ToSql>> =
                vec![Box::new(now), Box::new(session_id.to_string())];
            for status in OPEN_STATUS_VALUES.iter() {
                bind.push(Box::new(*status));
            }
            let bind_refs = param_refs(&bind);
            let changed = conn
                .execute(
                    &format!(
                        "UPDATE session_goals
                        SET status = 'complete', updated_at = ?1
                      WHERE session_id = ?2
                        AND status IN ({open_statuses})"
                    ),
                    bind_refs.as_slice(),
                )
                .context("clearing session goal")?;
            Ok(changed > 0)
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn set_session_goal_status(
        &self,
        session_id: Uuid,
        status: GoalStatus,
    ) -> Result<SessionGoal> {
        if !matches!(status, GoalStatus::Active | GoalStatus::Paused) {
            anyhow::bail!("set_session_goal_status supports active or paused");
        }
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            let goal = current_goal_required(conn, session_id)?;
            conn.execute(
                "UPDATE session_goals SET status = ?1, updated_at = ?2 WHERE id = ?3",
                params![status.as_str(), now, goal.id.to_string()],
            )
            .context("setting session goal status")?;
            load_goal(conn, session_id, goal.id)
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn refresh_session_goal_usage(&self, session_id: Uuid) -> Result<()> {
        self.write_blocking(move |conn| {
            let open_statuses = open_status_placeholders(2);
            let bind = bind_session_and_open_statuses(session_id.to_string());
            let bind_refs = param_refs(&bind);
            conn.execute(
                &format!(
                    "UPDATE session_goals
                    SET tokens_used = COALESCE((
                        SELECT SUM(input_tokens + output_tokens)
                        FROM inference_calls
                        WHERE session_id = session_goals.session_id
                    ), 0)
                  WHERE session_id = ?1
                    AND status IN ({open_statuses})"
                ),
                bind_refs.as_slice(),
            )
            .context("refreshing goal token usage")?;
            Ok(())
        })
    }
}

fn clean_opt(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn append_context(existing: Option<&str>, delta: Option<&str>) -> Option<String> {
    let delta = clean_opt(delta)?;
    match existing.map(str::trim).filter(|s| !s.is_empty()) {
        Some(existing) => Some(format!("{existing}\n\nUpdate:\n{delta}")),
        None => Some(delta),
    }
}

fn current_goal_required(conn: &rusqlite::Connection, session_id: Uuid) -> Result<SessionGoal> {
    let open_statuses = open_status_placeholders(2);
    let goal_params = bind_session_and_open_statuses(session_id.to_string());
    let goal_param_refs = param_refs(&goal_params);
    conn.query_row(
        &format!(
            "SELECT id, session_id, project_id, objective, context, status, token_budget,
                tokens_used, blocked_attempts, last_read_at, created_at, updated_at
         FROM session_goals
         WHERE session_id = ?1
           AND status IN ({open_statuses})
         ORDER BY updated_at DESC
         LIMIT 1"
        ),
        goal_param_refs.as_slice(),
        decode_goal,
    )
    .optional()
    .context("loading open session goal")?
    .ok_or_else(|| anyhow::anyhow!("no open goal for this session"))
}

fn open_status_placeholders(start: usize) -> String {
    placeholders(start, OPEN_STATUS_VALUES.len())
}

fn bind_session_and_open_statuses(session_id: String) -> Vec<Box<dyn rusqlite::ToSql>> {
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(session_id)];
    for status in OPEN_STATUS_VALUES.iter() {
        params.push(Box::new(*status));
    }
    params
}

fn param_refs(params: &[Box<dyn rusqlite::ToSql>]) -> Vec<&dyn rusqlite::ToSql> {
    params.iter().map(|param| param.as_ref()).collect()
}

fn load_goal(conn: &rusqlite::Connection, session_id: Uuid, id: Uuid) -> Result<SessionGoal> {
    conn.query_row(
        "SELECT id, session_id, project_id, objective, context, status, token_budget,
                tokens_used, blocked_attempts, last_read_at, created_at, updated_at
         FROM session_goals
         WHERE session_id = ?1 AND id = ?2",
        params![session_id.to_string(), id.to_string()],
        decode_goal,
    )
    .context("loading session goal")
}

fn decode_goal(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionGoal> {
    let id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let status: String = row.get(5)?;
    Ok(SessionGoal {
        id: Uuid::parse_str(&id).map_err(decode_err)?,
        session_id: Uuid::parse_str(&session_id).map_err(decode_err)?,
        project_id: row.get(2)?,
        objective: row.get(3)?,
        context: row.get(4)?,
        status: GoalStatus::parse(&status).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, e.into())
        })?,
        token_budget: row.get(6)?,
        tokens_used: row.get(7)?,
        blocked_attempts: row.get(8)?,
        last_read_at: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn decode_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_requires_get_goal_after_latest_update() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/goal-test", "Build").unwrap();
        db.create_session_goal(
            session.session_id,
            &session.project_id,
            "ship feature",
            None,
            None,
        )
        .unwrap();
        let err = db
            .update_session_goal(
                session.session_id,
                GoalStatus::Complete,
                Some("done"),
                None,
                None,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("get_goal"));
        db.current_session_goal(session.session_id, true).unwrap();
        let out = db
            .update_session_goal(
                session.session_id,
                GoalStatus::Complete,
                Some("done"),
                None,
                None,
            )
            .unwrap();
        assert!(matches!(out, GoalUpdateOutcome::Updated(g) if g.status == GoalStatus::Complete));
    }

    #[test]
    fn blocked_requires_three_attempts() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/goal-test", "Build").unwrap();
        db.create_session_goal(
            session.session_id,
            &session.project_id,
            "ship feature",
            None,
            None,
        )
        .unwrap();
        for expected in 1..BLOCK_ATTEMPTS_REQUIRED {
            let out = db
                .update_session_goal(
                    session.session_id,
                    GoalStatus::Blocked,
                    None,
                    Some("waiting"),
                    None,
                )
                .unwrap();
            assert!(
                matches!(out, GoalUpdateOutcome::BlockAttempt { attempts, .. } if attempts == expected)
            );
        }
        let out = db
            .update_session_goal(
                session.session_id,
                GoalStatus::Blocked,
                None,
                Some("waiting"),
                None,
            )
            .unwrap();
        assert!(matches!(out, GoalUpdateOutcome::Updated(g) if g.status == GoalStatus::Blocked));
    }

    #[test]
    fn current_session_goal_ignores_terminal_goals() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/goal-test", "Build").unwrap();
        db.create_session_goal(
            session.session_id,
            &session.project_id,
            "ship feature",
            None,
            None,
        )
        .unwrap();
        db.current_session_goal(session.session_id, true).unwrap();
        db.update_session_goal(
            session.session_id,
            GoalStatus::Complete,
            Some("done"),
            None,
            None,
        )
        .unwrap();

        assert!(
            db.current_session_goal(session.session_id, false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn new_goal_can_be_created_after_completion() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/goal-test", "Build").unwrap();
        db.create_session_goal(
            session.session_id,
            &session.project_id,
            "first goal",
            None,
            None,
        )
        .unwrap();
        db.current_session_goal(session.session_id, true).unwrap();
        db.update_session_goal(
            session.session_id,
            GoalStatus::Complete,
            Some("done"),
            None,
            None,
        )
        .unwrap();

        let next = db
            .create_session_goal(
                session.session_id,
                &session.project_id,
                "second goal",
                None,
                None,
            )
            .unwrap();
        assert_eq!(next.objective, "second goal");
        assert_eq!(next.status, GoalStatus::Active);
    }

    #[test]
    fn second_open_goal_is_rejected() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/goal-test", "Build").unwrap();
        db.create_session_goal(
            session.session_id,
            &session.project_id,
            "first goal",
            None,
            None,
        )
        .unwrap();

        let err = db
            .create_session_goal(
                session.session_id,
                &session.project_id,
                "second goal",
                None,
                None,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("open goal"));
    }
}
