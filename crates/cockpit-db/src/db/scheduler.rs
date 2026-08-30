use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, Row, params};
use uuid::Uuid;

use super::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledJobRow {
    pub id: String,
    pub row_identity: String,
    pub owner: String,
    pub schedule_json: String,
    pub payload_json: String,
    pub enabled: bool,
    pub missed_run_policy: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_run_at: Option<i64>,
    pub next_run_at: Option<i64>,
    pub last_result_json: Option<String>,
    pub failure_count: u32,
    pub backoff_until: Option<i64>,
    pub disabled_notice: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewScheduledJobRow {
    pub id: String,
    pub owner: String,
    pub schedule_json: String,
    pub payload_json: String,
    pub enabled: bool,
    pub missed_run_policy: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub next_run_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledJobRunUpdate {
    pub id: String,
    pub row_identity: String,
    pub last_run_at: i64,
    pub next_run_at: Option<i64>,
    pub last_result_json: String,
    pub failure_count: u32,
    pub backoff_until: Option<i64>,
    pub enabled: bool,
    pub disabled_notice: Option<String>,
}

/// Result of a scheduler mutation guarded by the exact durable row observed by
/// the caller. A changed row is returned rather than silently retried so the
/// caller can re-validate its authority before attempting the mutation again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionalScheduledJob<T> {
    Missing,
    Current(ScheduledJobRow),
    Applied(T),
}

impl Db {
    pub async fn insert_scheduled_job(&self, job: NewScheduledJobRow) -> Result<ScheduledJobRow> {
        self.write(move |conn| insert_scheduled_job_conn(conn, &job))
            .await
    }

    pub async fn list_scheduled_jobs(&self, owner: Option<&str>) -> Result<Vec<ScheduledJobRow>> {
        let owner = owner.map(ToOwned::to_owned);
        self.read(move |conn| list_scheduled_jobs_conn(conn, owner.as_deref()))
            .await
    }

    pub async fn get_scheduled_job(&self, id: &str) -> Result<Option<ScheduledJobRow>> {
        let id = id.to_string();
        self.read(move |conn| get_scheduled_job_conn(conn, &id))
            .await
    }

    pub async fn delete_scheduled_job(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.write(move |conn| {
            let changed = conn
                .execute("DELETE FROM scheduled_jobs WHERE id = ?1", [id])
                .context("deleting scheduled job")?;
            Ok(changed > 0)
        })
        .await
    }

    /// Delete only when the observed insertion identity still belongs to `id`.
    /// This fences delete/reinsert ABA without relying on mutable row values.
    pub async fn delete_scheduled_job_if_matches(
        &self,
        expected: ScheduledJobRow,
    ) -> Result<ConditionalScheduledJob<()>> {
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM scheduled_jobs
                      WHERE id = ?1 AND row_identity = ?2",
                    params![&expected.id, &expected.row_identity],
                )
                .context("conditionally deleting scheduled job")?;
            conditional_scheduled_job_result(conn, &expected.id, changed, ())
        })
        .await
    }

    pub async fn set_scheduled_job_enabled(
        &self,
        id: &str,
        enabled: bool,
        next_run_at: Option<i64>,
        updated_at: i64,
    ) -> Result<Option<ScheduledJobRow>> {
        let id = id.to_string();
        self.write(move |conn| {
            conn.execute(
                "UPDATE scheduled_jobs
                    SET enabled = ?2,
                        next_run_at = ?3,
                        updated_at = ?4,
                        failure_count = CASE WHEN ?2 = 1 THEN 0 ELSE failure_count END,
                        backoff_until = CASE WHEN ?2 = 1 THEN NULL ELSE backoff_until END,
                        disabled_notice = CASE WHEN ?2 = 1 THEN NULL ELSE disabled_notice END
                  WHERE id = ?1",
                params![id, enabled, next_run_at, updated_at],
            )
            .context("updating scheduled job enabled state")?;
            get_scheduled_job_conn(conn, &id)
        })
        .await
    }

    /// Update a job's enabled state only when the observed insertion identity
    /// still belongs to `id`, so an id reuse cannot inherit public authority.
    pub async fn set_scheduled_job_enabled_if_matches(
        &self,
        expected: ScheduledJobRow,
        enabled: bool,
        next_run_at: Option<i64>,
        updated_at: i64,
    ) -> Result<ConditionalScheduledJob<ScheduledJobRow>> {
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE scheduled_jobs
                        SET enabled = ?3,
                            next_run_at = ?4,
                            updated_at = ?5,
                            failure_count = CASE WHEN ?3 = 1 THEN 0 ELSE failure_count END,
                            backoff_until = CASE WHEN ?3 = 1 THEN NULL ELSE backoff_until END,
                            disabled_notice = CASE WHEN ?3 = 1 THEN NULL ELSE disabled_notice END
                      WHERE id = ?1 AND row_identity = ?2",
                    params![
                        &expected.id,
                        &expected.row_identity,
                        enabled,
                        next_run_at,
                        updated_at,
                    ],
                )
                .context("conditionally updating scheduled job enabled state")?;
            if changed == 0 {
                return conditional_scheduled_job_result(conn, &expected.id, changed, ()).map(
                    |result| match result {
                        ConditionalScheduledJob::Missing => ConditionalScheduledJob::Missing,
                        ConditionalScheduledJob::Current(row) => {
                            ConditionalScheduledJob::Current(row)
                        }
                        ConditionalScheduledJob::Applied(()) => {
                            unreachable!("zero changed rows cannot apply a conditional update")
                        }
                    },
                );
            }
            let row = get_scheduled_job_conn(conn, &expected.id)?
                .ok_or_else(|| anyhow::anyhow!("scheduled job missing after conditional update"))?;
            Ok(ConditionalScheduledJob::Applied(row))
        })
        .await
    }

    /// Atomically validate the observed insertion identity before a manual run
    /// is enqueued. The no-op assignment makes this writer-serialized without
    /// changing scheduling metadata.
    pub async fn claim_scheduled_job_for_manual_run_if_matches(
        &self,
        expected: ScheduledJobRow,
    ) -> Result<ConditionalScheduledJob<ScheduledJobRow>> {
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE scheduled_jobs
                        SET updated_at = updated_at
                      WHERE id = ?1 AND row_identity = ?2",
                    params![&expected.id, &expected.row_identity],
                )
                .context("conditionally claiming scheduled job manual run")?;
            if changed == 0 {
                return conditional_scheduled_job_result(conn, &expected.id, changed, ()).map(
                    |result| match result {
                        ConditionalScheduledJob::Missing => ConditionalScheduledJob::Missing,
                        ConditionalScheduledJob::Current(row) => {
                            ConditionalScheduledJob::Current(row)
                        }
                        ConditionalScheduledJob::Applied(()) => {
                            unreachable!("zero changed rows cannot apply a conditional claim")
                        }
                    },
                );
            }
            let row = get_scheduled_job_conn(conn, &expected.id)?
                .ok_or_else(|| anyhow::anyhow!("scheduled job missing after conditional claim"))?;
            Ok(ConditionalScheduledJob::Applied(row))
        })
        .await
    }

    pub async fn update_scheduled_job_after_run(
        &self,
        update: ScheduledJobRunUpdate,
    ) -> Result<Option<ScheduledJobRow>> {
        self.write(move |conn| {
            let id = update.id;
            let changed = conn
                .execute(
                    "UPDATE scheduled_jobs
                    SET last_run_at = ?3,
                        next_run_at = ?4,
                        last_result_json = ?5,
                        failure_count = ?6,
                        backoff_until = ?7,
                        enabled = ?8,
                        disabled_notice = ?9,
                        updated_at = ?3
                  WHERE id = ?1 AND row_identity = ?2",
                    params![
                        &id,
                        &update.row_identity,
                        update.last_run_at,
                        update.next_run_at,
                        update.last_result_json,
                        i64::from(update.failure_count),
                        update.backoff_until,
                        update.enabled,
                        update.disabled_notice
                    ],
                )
                .context("updating scheduled job after run")?;
            if changed == 0 {
                return Ok(None);
            }
            get_scheduled_job_conn(conn, &id)
        })
        .await
    }

    pub async fn update_scheduled_job_manual_run_result(
        &self,
        id: &str,
        last_run_at: i64,
        last_result_json: String,
    ) -> Result<Option<ScheduledJobRow>> {
        let id = id.to_string();
        self.write(move |conn| {
            conn.execute(
                "UPDATE scheduled_jobs
                    SET last_run_at = ?2,
                        last_result_json = ?3,
                        updated_at = ?2
                  WHERE id = ?1",
                params![id, last_run_at, last_result_json],
            )
            .context("updating scheduled job manual run result")?;
            get_scheduled_job_conn(conn, &id)
        })
        .await
    }

    pub async fn update_scheduled_job_next_run(
        &self,
        id: &str,
        next_run_at: Option<i64>,
        updated_at: i64,
    ) -> Result<Option<ScheduledJobRow>> {
        let id = id.to_string();
        self.write(move |conn| {
            conn.execute(
                "UPDATE scheduled_jobs
                    SET next_run_at = ?2,
                        updated_at = ?3
                  WHERE id = ?1",
                params![id, next_run_at, updated_at],
            )
            .context("updating scheduled job next_run")?;
            get_scheduled_job_conn(conn, &id)
        })
        .await
    }

    pub async fn claim_scheduled_job_due(
        &self,
        id: &str,
        expected_next_run_at: Option<i64>,
        claim_next_run_at: Option<i64>,
        updated_at: i64,
    ) -> Result<Option<ScheduledJobRow>> {
        let id = id.to_string();
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE scheduled_jobs
                        SET next_run_at = ?3,
                            updated_at = ?4
                      WHERE id = ?1
                        AND enabled = 1
                        AND next_run_at IS ?2",
                    params![id, expected_next_run_at, claim_next_run_at, updated_at],
                )
                .context("claiming due scheduled job")?;
            if changed == 0 {
                return Ok(None);
            }
            get_scheduled_job_conn(conn, &id)
        })
        .await
    }
}

fn conditional_scheduled_job_result<T>(
    conn: &rusqlite::Connection,
    id: &str,
    changed: usize,
    applied: T,
) -> Result<ConditionalScheduledJob<T>> {
    if changed > 0 {
        return Ok(ConditionalScheduledJob::Applied(applied));
    }
    Ok(match get_scheduled_job_conn(conn, id)? {
        Some(row) => ConditionalScheduledJob::Current(row),
        None => ConditionalScheduledJob::Missing,
    })
}

fn insert_scheduled_job_conn(
    conn: &rusqlite::Connection,
    job: &NewScheduledJobRow,
) -> Result<ScheduledJobRow> {
    conn.execute(
        "INSERT INTO scheduled_jobs (
            id, row_identity, owner, schedule_json, payload_json, enabled, missed_run_policy,
            created_at, updated_at, next_run_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            job.id,
            Uuid::new_v4().to_string(),
            job.owner,
            job.schedule_json,
            job.payload_json,
            job.enabled,
            job.missed_run_policy,
            job.created_at,
            job.updated_at,
            job.next_run_at
        ],
    )
    .context("inserting scheduled job")?;
    get_scheduled_job_conn(conn, &job.id)?
        .ok_or_else(|| anyhow::anyhow!("scheduled job missing after insert"))
}

pub fn list_scheduled_jobs_conn(
    conn: &rusqlite::Connection,
    owner: Option<&str>,
) -> Result<Vec<ScheduledJobRow>> {
    let exists: i64 = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type='table' AND name='scheduled_jobs'
            )",
            [],
            |row| row.get(0),
        )
        .context("checking scheduled_jobs table")?;
    if exists == 0 {
        return Ok(Vec::new());
    }
    let rows = match owner {
        Some(owner) => list_scheduled_jobs_for_owner_conn(conn, owner)?,
        None => conn
            .prepare(
                "SELECT *
                   FROM scheduled_jobs
                  ORDER BY enabled DESC, next_run_at IS NULL, next_run_at ASC, id ASC",
            )
            .context("preparing scheduled job list")?
            .query_map([], scheduled_job_from_row)
            .context("querying scheduled jobs")?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("reading scheduled jobs")?,
    };
    Ok(rows)
}

fn list_scheduled_jobs_for_owner_conn(
    conn: &rusqlite::Connection,
    owner: &str,
) -> Result<Vec<ScheduledJobRow>> {
    conn.prepare(
        // schema-hot-query: extended.scheduler.by-owner
        "SELECT *
                   FROM scheduled_jobs
                  WHERE owner = ?1
                  ORDER BY enabled DESC, next_run_at IS NULL, next_run_at ASC, id ASC",
    )
    .context("preparing owner scheduled job list")?
    .query_map([owner], scheduled_job_from_row)
    .context("querying scheduled jobs")?
    .collect::<rusqlite::Result<Vec<_>>>()
    .context("reading scheduled jobs")
}

pub fn get_scheduled_job_conn(
    conn: &rusqlite::Connection,
    id: &str,
) -> Result<Option<ScheduledJobRow>> {
    conn.query_row(
        "SELECT * FROM scheduled_jobs WHERE id = ?1",
        [id],
        scheduled_job_from_row,
    )
    .optional()
    .context("querying scheduled job")
}

fn scheduled_job_from_row(row: &Row<'_>) -> rusqlite::Result<ScheduledJobRow> {
    let failure_count: i64 = row.get("failure_count")?;
    Ok(ScheduledJobRow {
        id: row.get("id")?,
        row_identity: row.get("row_identity")?,
        owner: row.get("owner")?,
        schedule_json: row.get("schedule_json")?,
        payload_json: row.get("payload_json")?,
        enabled: row.get("enabled")?,
        missed_run_policy: row.get("missed_run_policy")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        last_run_at: row.get("last_run_at")?,
        next_run_at: row.get("next_run_at")?,
        last_result_json: row.get("last_result_json")?,
        failure_count: failure_count.max(0) as u32,
        backoff_until: row.get("backoff_until")?,
        disabled_notice: row.get("disabled_notice")?,
    })
}

#[cfg(all(test, feature = "extended"))]
mod tests {
    use super::*;

    fn job(id: &str, next_run_at: Option<i64>) -> NewScheduledJobRow {
        NewScheduledJobRow {
            id: id.to_string(),
            owner: "test".to_string(),
            schedule_json: r#"{"type":"cron","expr":"0 0 * * *"}"#.to_string(),
            payload_json: r#"{"prompt":"run"}"#.to_string(),
            enabled: true,
            missed_run_policy: "skip".to_string(),
            created_at: 10,
            updated_at: 10,
            next_run_at,
        }
    }

    #[tokio::test]
    async fn db_async_delegation_scheduler_roundtrip_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let inserted = db
            .insert_scheduled_job(job("job-1", Some(20)))
            .await
            .unwrap();
        assert_eq!(inserted.id, "job-1");

        let rows = db.list_scheduled_jobs(Some("test")).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].next_run_at, Some(20));

        let updated = db
            .update_scheduled_job_next_run("job-1", Some(30), 25)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.next_run_at, Some(30));
    }

    #[tokio::test]
    async fn db_async_delegation_scheduler_claim_is_exclusive() {
        let db = Db::open_in_memory().unwrap();
        db.insert_scheduled_job(job("job-claim", Some(20)))
            .await
            .unwrap();

        let first = db.claim_scheduled_job_due("job-claim", Some(20), None, 21);
        let second = db.claim_scheduled_job_due("job-claim", Some(20), None, 22);
        let (first, second) = tokio::join!(first, second);
        let wins = [first.unwrap(), second.unwrap()]
            .into_iter()
            .filter(Option::is_some)
            .count();
        assert_eq!(wins, 1);
        assert_eq!(
            db.get_scheduled_job("job-claim")
                .await
                .unwrap()
                .unwrap()
                .next_run_at,
            None
        );
    }

    #[tokio::test]
    async fn conditional_scheduler_mutations_do_not_apply_after_row_replacement() {
        let db = Db::open_in_memory().unwrap();
        for id in ["job-delete-match", "job-enable-match", "job-run-match"] {
            db.insert_scheduled_job(job(id, Some(20))).await.unwrap();
        }
        let delete_expected = db
            .get_scheduled_job("job-delete-match")
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            db.delete_scheduled_job_if_matches(delete_expected)
                .await
                .unwrap(),
            ConditionalScheduledJob::Applied(())
        ));
        let enable_expected = db
            .get_scheduled_job("job-enable-match")
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            db.set_scheduled_job_enabled_if_matches(enable_expected, false, None, 21)
                .await
                .unwrap(),
            ConditionalScheduledJob::Applied(row) if !row.enabled
        ));
        let run_expected = db
            .get_scheduled_job("job-run-match")
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            db.claim_scheduled_job_for_manual_run_if_matches(run_expected)
                .await
                .unwrap(),
            ConditionalScheduledJob::Applied(row) if row.id == "job-run-match"
        ));

        db.insert_scheduled_job(job("job-conditional", Some(20)))
            .await
            .unwrap();
        let expected = db
            .get_scheduled_job("job-conditional")
            .await
            .unwrap()
            .unwrap();

        // Simulate a replacement between a public caller's authorization
        // snapshot and its eventual writer operation. The new row has a
        // daemon-owned owner, so a stale public mutation must not touch it.
        db.write(|conn| {
            conn.execute(
                "UPDATE scheduled_jobs SET owner = 'system:test' WHERE id = 'job-conditional'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        assert!(matches!(
            db.delete_scheduled_job_if_matches(expected.clone())
                .await
                .unwrap(),
            ConditionalScheduledJob::Current(row) if row.owner == "system:test"
        ));
        assert!(matches!(
            db.set_scheduled_job_enabled_if_matches(expected.clone(), false, None, 21)
                .await
                .unwrap(),
            ConditionalScheduledJob::Current(row) if row.owner == "system:test"
        ));
        assert!(matches!(
            db.claim_scheduled_job_for_manual_run_if_matches(expected)
                .await
                .unwrap(),
            ConditionalScheduledJob::Current(row) if row.owner == "system:test"
        ));

        let current = db
            .get_scheduled_job("job-conditional")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.owner, "system:test");
        assert!(current.enabled, "stale enable mutation must not be applied");
    }

    #[tokio::test]
    async fn scheduler_row_identity_fences_identical_value_aba_and_stale_completion() {
        let db = Db::open_in_memory().unwrap();
        let original = db
            .insert_scheduled_job(job("job-aba", Some(20)))
            .await
            .unwrap();
        assert!(db.delete_scheduled_job("job-aba").await.unwrap());
        let replacement = db
            .insert_scheduled_job(job("job-aba", Some(20)))
            .await
            .unwrap();
        assert_ne!(original.row_identity, replacement.row_identity);
        assert!(
            db.write(|conn| {
                conn.execute(
                    "UPDATE scheduled_jobs SET row_identity = 'forbidden' WHERE id = 'job-aba'",
                    [],
                )?;
                Ok(())
            })
            .await
            .is_err()
        );

        assert!(matches!(
            db.delete_scheduled_job_if_matches(original.clone()).await.unwrap(),
            ConditionalScheduledJob::Current(row) if row.row_identity == replacement.row_identity
        ));
        assert!(matches!(
            db.set_scheduled_job_enabled_if_matches(original.clone(), false, None, 21)
                .await
                .unwrap(),
            ConditionalScheduledJob::Current(row) if row.row_identity == replacement.row_identity
        ));
        assert!(matches!(
            db.claim_scheduled_job_for_manual_run_if_matches(original.clone())
                .await
                .unwrap(),
            ConditionalScheduledJob::Current(row) if row.row_identity == replacement.row_identity
        ));

        assert!(
            db.update_scheduled_job_after_run(ScheduledJobRunUpdate {
                id: original.id,
                row_identity: original.row_identity,
                last_run_at: 30,
                next_run_at: None,
                last_result_json: r#"{"ok":true,"summary":"stale","finished_at":30}"#.into(),
                failure_count: 4,
                backoff_until: Some(60),
                enabled: false,
                disabled_notice: Some("stale".into()),
            })
            .await
            .unwrap()
            .is_none()
        );
        let current = db.get_scheduled_job("job-aba").await.unwrap().unwrap();
        assert_eq!(current.row_identity, replacement.row_identity);
        assert_eq!(current.last_run_at, None);
        assert!(current.enabled);
    }
}
