use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, Row, params};

use super::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledJobRow {
    pub id: String,
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
    pub last_run_at: i64,
    pub next_run_at: Option<i64>,
    pub last_result_json: String,
    pub failure_count: u32,
    pub backoff_until: Option<i64>,
    pub enabled: bool,
    pub disabled_notice: Option<String>,
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

    pub async fn update_scheduled_job_after_run(
        &self,
        update: ScheduledJobRunUpdate,
    ) -> Result<Option<ScheduledJobRow>> {
        self.write(move |conn| {
            let id = update.id;
            conn.execute(
                "UPDATE scheduled_jobs
                    SET last_run_at = ?2,
                        next_run_at = ?3,
                        last_result_json = ?4,
                        failure_count = ?5,
                        backoff_until = ?6,
                        enabled = ?7,
                        disabled_notice = ?8,
                        updated_at = ?2
                  WHERE id = ?1",
                params![
                    &id,
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

fn insert_scheduled_job_conn(
    conn: &rusqlite::Connection,
    job: &NewScheduledJobRow,
) -> Result<ScheduledJobRow> {
    conn.execute(
        "INSERT INTO scheduled_jobs (
            id, owner, schedule_json, payload_json, enabled, missed_run_policy,
            created_at, updated_at, next_run_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            job.id,
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
    let rows = match owner {
        Some(owner) => conn
            .prepare(
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
            .context("reading scheduled jobs")?,
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
}
