//! Daemon-owned durable authority and safe audit projections for image sidecars.
//!
//! The database is the sole local authority for standing destination grants.
//! The provider handoff is intentionally not represented here until the
//! production sidecar transport is available; callers then receive an empty
//! invocation history rather than a fabricated local audit record.

use anyhow::{Context as _, Result, ensure};
use rusqlite::{OptionalExtension, params};

use super::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSidecarGrantCreate {
    pub grant_id: String,
    pub project_id: String,
    pub session_id: Option<String>,
    pub invocation_id: Option<String>,
    pub destination: String,
    pub purpose: String,
    pub scope: String,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSidecarGrantRow {
    pub grant_id: String,
    pub version: u64,
    pub project_id: String,
    pub session_id: Option<String>,
    pub invocation_id: Option<String>,
    pub destination: String,
    pub purpose: String,
    pub scope: String,
    pub created_at_unix_ms: i64,
    pub last_used_at_unix_ms: Option<i64>,
    pub revoked_at_unix_ms: Option<i64>,
    pub consumed_at_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSidecarSnapshot {
    pub entity_version: u64,
    pub grants: Vec<ImageSidecarGrantRow>,
}

impl Db {
    /// Atomically persist a grant and advance the project-local snapshot
    /// sequence. `once` is bound to one invocation, `session` to one session,
    /// and `project` has neither wildcard binding.
    pub async fn create_image_sidecar_grant(
        &self,
        create: ImageSidecarGrantCreate,
    ) -> Result<(ImageSidecarGrantRow, u64)> {
        self.transaction(move |conn| {
            let mut create = create;
            create.destination = canonical_grant_destination(&create.destination)?;
            validate_create(&create)?;
            conn.execute(
                "INSERT OR IGNORE INTO image_sidecar_entities(project_id,entity_version) VALUES(?1,0)",
                [&create.project_id],
            )
            .context("initializing image-sidecar entity")?;
            let changed = conn.execute(
                "INSERT INTO image_sidecar_grants(\
                    grant_id,project_id,session_id,invocation_id,destination,purpose,scope,\
                    created_at_unix_ms,version\
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1)",
                params![
                    &create.grant_id,
                    &create.project_id,
                    &create.session_id,
                    &create.invocation_id,
                    &create.destination,
                    &create.purpose,
                    &create.scope,
                    create.created_at_unix_ms,
                ],
            )
            .context("creating image-sidecar grant")?;
            ensure!(changed == 1, "image-sidecar grant was not created");
            let entity_version = bump_entity_version_conn(conn, &create.project_id)?;
            let row = image_sidecar_grant_conn(conn, &create.project_id, &create.grant_id)?
                .context("created image-sidecar grant is missing")?;
            Ok((row, entity_version))
        })
        .await
    }

    /// Revoke the exact version currently shown to the caller. The predicate
    /// makes a stale confirmation harmless and keeps revocation authoritative.
    pub async fn revoke_image_sidecar_grant(
        &self,
        project_id: String,
        grant_id: String,
        expected_version: u64,
        revoked_at_unix_ms: i64,
    ) -> Result<Option<(ImageSidecarGrantRow, u64)>> {
        self.transaction(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE image_sidecar_grants\
                 SET revoked_at_unix_ms=?4,version=version+1\
                 WHERE project_id=?1 AND grant_id=?2 AND version=?3\
                   AND revoked_at_unix_ms IS NULL",
                    params![
                        project_id,
                        grant_id,
                        i64::try_from(expected_version)
                            .context("image-sidecar grant version is too large")?,
                        revoked_at_unix_ms
                    ],
                )
                .context("revoking image-sidecar grant")?;
            if changed == 0 {
                return Ok(None);
            }
            let entity_version = bump_entity_version_conn(conn, &project_id)?;
            let row = image_sidecar_grant_conn(conn, &project_id, &grant_id)?
                .context("revoked image-sidecar grant is missing")?;
            Ok(Some((row, entity_version)))
        })
        .await
    }

    /// Read safe metadata only. Invocation records remain empty until a real
    /// provider handoff can atomically write them; no unavailable dispatch is
    /// ever presented as an audit entry.
    pub async fn image_sidecar_snapshot(&self, project_id: String) -> Result<ImageSidecarSnapshot> {
        self.read(move |conn| {
            let entity_version = conn
                .query_row(
                    "SELECT entity_version FROM image_sidecar_entities WHERE project_id=?1",
                    [&project_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .context("reading image-sidecar entity version")?
                .unwrap_or(0);
            let mut statement = conn.prepare(
                "SELECT grant_id,version,project_id,session_id,invocation_id,destination,purpose,scope,\
                        created_at_unix_ms,last_used_at_unix_ms,revoked_at_unix_ms,consumed_at_unix_ms \
                 FROM image_sidecar_grants WHERE project_id=?1\
                 ORDER BY created_at_unix_ms,grant_id",
            )?;
            let grants = statement
                .query_map([project_id], image_sidecar_grant_from_row)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("reading image-sidecar grants")?;
            Ok(ImageSidecarSnapshot {
                entity_version: u64::try_from(entity_version)
                    .context("image-sidecar entity version is negative")?,
                grants,
            })
        })
        .await
    }
}

/// Persist only scheme/host/port. Userinfo, path, query, and fragment are
/// request-scoped bearer material and must never enter the ledger.
fn canonical_grant_destination(raw: &str) -> Result<String> {
    let raw = raw.trim();
    ensure!(!raw.is_empty() && raw.len() <= 2048, "invalid destination");
    let Some((scheme, rest)) = raw.split_once("://") else {
        anyhow::bail!("invalid destination");
    };
    let scheme = scheme.to_ascii_lowercase();
    ensure!(scheme == "http" || scheme == "https", "invalid destination");
    let hostport = rest.rsplit_once('@').map(|(_, host)| host).unwrap_or(rest);
    let hostport = hostport
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(hostport)
        .trim();
    ensure!(
        !hostport.is_empty() && !hostport.contains('@'),
        "invalid destination"
    );
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let Some((host, rest)) = rest.split_once(']') else {
            anyhow::bail!("invalid destination");
        };
        ensure!(!host.is_empty(), "invalid destination");
        match rest {
            "" => (host.to_ascii_lowercase(), None),
            rest => {
                let port = rest
                    .strip_prefix(':')
                    .ok_or_else(|| anyhow::anyhow!("invalid destination"))?;
                let port: u16 = port.parse().context("invalid destination")?;
                (host.to_ascii_lowercase(), Some(port))
            }
        }
    } else if let Some((host, port)) = hostport.rsplit_once(':')
        && !host.is_empty()
        && port.chars().all(|ch| ch.is_ascii_digit())
    {
        let port: u16 = port.parse().context("invalid destination")?;
        (host.to_ascii_lowercase(), Some(port))
    } else {
        (hostport.to_ascii_lowercase(), None)
    };
    ensure!(
        !host.is_empty() && !host.contains('/'),
        "invalid destination"
    );
    let default_port = if scheme == "http" { 80 } else { 443 };
    let host_disp = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Ok(match port {
        Some(port) if port != default_port => format!("{scheme}://{host_disp}:{port}"),
        _ => format!("{scheme}://{host_disp}"),
    })
}

fn validate_create(create: &ImageSidecarGrantCreate) -> Result<()> {
    ensure!(
        !create.grant_id.is_empty() && create.grant_id.len() <= 128,
        "invalid grant id"
    );
    ensure!(
        !create.project_id.is_empty() && create.project_id.len() <= 4096,
        "invalid project id"
    );
    ensure!(
        !create.destination.is_empty() && create.destination.len() <= 2048,
        "invalid destination"
    );
    ensure!(
        matches!(create.purpose.as_str(), "dossier" | "ask_image"),
        "invalid purpose"
    );
    match create.scope.as_str() {
        "once" => ensure!(
            create
                .invocation_id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
                && create
                    .session_id
                    .as_deref()
                    .is_some_and(|id| !id.is_empty()),
            "once grant requires invocation and session binding"
        ),
        "session" => ensure!(
            create.invocation_id.is_none()
                && create
                    .session_id
                    .as_deref()
                    .is_some_and(|id| !id.is_empty()),
            "session grant requires only session binding"
        ),
        "project" => ensure!(
            create.invocation_id.is_none() && create.session_id.is_none(),
            "project grant must not carry session or invocation binding"
        ),
        _ => anyhow::bail!("invalid image-sidecar grant scope"),
    }
    Ok(())
}

fn bump_entity_version_conn(conn: &rusqlite::Connection, project_id: &str) -> Result<u64> {
    conn.execute(
        "INSERT INTO image_sidecar_entities(project_id,entity_version) VALUES(?1,1)\
         ON CONFLICT(project_id) DO UPDATE SET entity_version=entity_version+1",
        [project_id],
    )?;
    let version: i64 = conn.query_row(
        "SELECT entity_version FROM image_sidecar_entities WHERE project_id=?1",
        [project_id],
        |row| row.get(0),
    )?;
    u64::try_from(version).context("image-sidecar entity version is negative")
}

fn image_sidecar_grant_conn(
    conn: &rusqlite::Connection,
    project_id: &str,
    grant_id: &str,
) -> Result<Option<ImageSidecarGrantRow>> {
    conn.query_row(
        "SELECT grant_id,version,project_id,session_id,invocation_id,destination,purpose,scope,\
                created_at_unix_ms,last_used_at_unix_ms,revoked_at_unix_ms,consumed_at_unix_ms \
         FROM image_sidecar_grants WHERE project_id=?1 AND grant_id=?2",
        params![project_id, grant_id],
        image_sidecar_grant_from_row,
    )
    .optional()
    .context("reading image-sidecar grant")
}

fn image_sidecar_grant_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ImageSidecarGrantRow> {
    Ok(ImageSidecarGrantRow {
        grant_id: row.get(0)?,
        version: u64::try_from(row.get::<_, i64>(1)?)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, 0))?,
        project_id: row.get(2)?,
        session_id: row.get(3)?,
        invocation_id: row.get(4)?,
        destination: row.get(5)?,
        purpose: row.get(6)?,
        scope: row.get(7)?,
        created_at_unix_ms: row.get(8)?,
        last_used_at_unix_ms: row.get(9)?,
        revoked_at_unix_ms: row.get(10)?,
        consumed_at_unix_ms: row.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn canonical_grant_destination_strips_bearer_components() {
        assert_eq!(
            canonical_grant_destination(
                "https://user:token@example.test/private?sig=secret#fragment"
            )
            .unwrap(),
            "https://example.test"
        );
        assert_eq!(
            canonical_grant_destination("http://localhost:8080/v1").unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            canonical_grant_destination("https://example.test:443/path").unwrap(),
            "https://example.test"
        );
        assert!(canonical_grant_destination("not a URL").is_err());
        assert!(canonical_grant_destination("ftp://example.test").is_err());
    }

    #[tokio::test]
    async fn create_image_sidecar_grant_persists_only_canonical_origin() {
        let db = Db::open_in_memory().unwrap();
        let (row, version) = db
            .create_image_sidecar_grant(ImageSidecarGrantCreate {
                grant_id: "grant-1".into(),
                project_id: "/project".into(),
                session_id: None,
                invocation_id: None,
                destination: "https://user:token@example.test/private?sig=secret#fragment".into(),
                purpose: "ask_image".into(),
                scope: "project".into(),
                created_at_unix_ms: 1,
            })
            .await
            .expect("grant insert");
        assert_eq!(row.destination, "https://example.test");
        assert_eq!(version, 1);
        let snapshot = db
            .image_sidecar_snapshot("/project".into())
            .await
            .expect("snapshot");
        assert_eq!(snapshot.grants[0].destination, "https://example.test");
    }
}
