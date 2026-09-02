//! Durable owner-granted Monty network policy.
//!
//! Agent definitions are deliberately absent from this module. They may carry
//! requested hosts for prompt prefill, but only these explicit user-action
//! mutations create durable authority.

use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use super::Db;

/// Canonical host authority shared by authored requests, session grants,
/// durable grants, and URL-derived destinations. Ports, URL syntax, userinfo,
/// and mixed-case spellings are never host authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalNetworkHost(String);

impl CanonicalNetworkHost {
    pub fn parse(host: &str) -> Result<Self> {
        if host.is_empty()
            || host.len() > 253
            || host != host.to_ascii_lowercase()
            || host
                .chars()
                .any(|ch| ch.is_whitespace() || matches!(ch, '/' | '?' | '#' | '@' | ':'))
        {
            bail!("network host is not canonical");
        }
        Ok(Self(host.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CanonicalNetworkHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for CanonicalNetworkHost {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CanonicalNetworkHost {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let host = String::deserialize(deserializer)?;
        Self::parse(&host).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MontyNetworkInstallationPolicy {
    /// Immutable installed-agent identity. Execution instances are resolved
    /// against this identity at every production entry point.
    pub installation_id: Uuid,
    pub requests_enabled: bool,
    pub approval_required: bool,
    pub generation: u64,
    pub hosts: std::collections::BTreeSet<CanonicalNetworkHost>,
}

impl MontyNetworkInstallationPolicy {
    pub fn deny_all(installation_id: Uuid) -> Self {
        Self {
            installation_id,
            requests_enabled: false,
            approval_required: false,
            generation: 0,
            hosts: std::collections::BTreeSet::new(),
        }
    }

    pub fn permits(&self, host: &CanonicalNetworkHost) -> bool {
        self.requests_enabled && self.hosts.contains(host)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MontyNetworkAgentMutation {
    SetRequestsEnabled(bool),
    SetApprovalRequired(bool),
    GrantHost(CanonicalNetworkHost),
    RevokeHost(CanonicalNetworkHost),
    RevokeAllHosts,
}

fn read_policy(
    conn: &rusqlite::Connection,
    installation_id: Uuid,
) -> Result<MontyNetworkInstallationPolicy> {
    let installation_id = installation_id.to_string();
    let header = conn
        .query_row(
            "SELECT requests_enabled, approval_required, generation FROM monty_network_agent_policies WHERE installation_id=?1",
            [&installation_id],
            |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?, row.get::<_, i64>(2)?)),
        )
        .optional()?;
    let Some((requests_enabled, approval_required, generation)) = header else {
        return Ok(MontyNetworkInstallationPolicy::deny_all(Uuid::parse_str(
            &installation_id,
        )?));
    };
    let generation = u64::try_from(generation)?;
    let mut statement = conn.prepare(
        "SELECT host FROM monty_network_agent_grants WHERE installation_id=?1 ORDER BY host",
    )?;
    let hosts = statement
        .query_map([&installation_id], |row| row.get::<_, String>(0))?
        .map(|host| CanonicalNetworkHost::parse(&host?))
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    Ok(MontyNetworkInstallationPolicy {
        installation_id: Uuid::parse_str(&installation_id)?,
        requests_enabled,
        approval_required,
        generation,
        hosts,
    })
}

impl Db {
    /// Resolve a live, session-bound executor to its immutable installation.
    /// A missing binding is deny-by-error: ephemeral/headless executors cannot
    /// read or mutate durable installed-agent authority.
    pub async fn monty_network_installation_id_for_agent_instance(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
    ) -> Result<Uuid> {
        self.read(move |conn| {
            let installation_id: Option<String> = conn
                .query_row(
                    "SELECT resolved_installation_id FROM agent_instances WHERE session_id=?1 AND agent_instance_id=?2",
                    params![session_id.to_string(), agent_instance_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?
                .context("governed network executor is not a live session agent")?;
            let installation_id = installation_id.context(
                "governed network executor has no immutable installed-agent identity",
            )?;
            Uuid::parse_str(&installation_id)
                .context("governed network executor has an invalid installed-agent identity")
        })
        .await
    }

    pub async fn monty_network_installation_policy(
        &self,
        installation_id: Uuid,
    ) -> Result<MontyNetworkInstallationPolicy> {
        self.read(move |conn| read_policy(conn, installation_id))
            .await
    }

    /// Apply one explicit owner action and advance the revocation generation.
    pub async fn mutate_monty_network_installation_policy(
        &self,
        installation_id: Uuid,
        mutation: MontyNetworkAgentMutation,
        now_unix_ms: i64,
    ) -> Result<MontyNetworkInstallationPolicy> {
        // A completed policy mutation must be ordered after an egress that
        // already crossed its final durable-policy check, and before every
        // later egress. The request holds the shared permit through
        // `RequestBuilder::send`; do not move this exclusive acquisition
        // below the SQLite transaction.
        let _revocation_fence = self.monty_network_egress_gate.write().await;
        let installation_id = installation_id.to_string();
        self.transaction(move |conn| {
            conn.execute(
                "INSERT INTO monty_network_agent_policies(installation_id,requests_enabled,approval_required,generation,updated_at_unix_ms) VALUES(?1,0,0,1,?2) ON CONFLICT(installation_id) DO UPDATE SET generation=generation+1,updated_at_unix_ms=excluded.updated_at_unix_ms",
                params![installation_id, now_unix_ms],
            )?;
            match mutation {
                MontyNetworkAgentMutation::SetRequestsEnabled(enabled) => {
                    conn.execute(
                        "UPDATE monty_network_agent_policies SET requests_enabled=?2 WHERE installation_id=?1",
                        params![installation_id, enabled],
                    )?;
                }
                MontyNetworkAgentMutation::SetApprovalRequired(required) => {
                    conn.execute(
                        "UPDATE monty_network_agent_policies SET approval_required=?2 WHERE installation_id=?1",
                        params![installation_id, required],
                    )?;
                }
                MontyNetworkAgentMutation::GrantHost(host) => {
                    conn.execute(
                        "INSERT INTO monty_network_agent_grants(installation_id,host,granted_at_unix_ms) VALUES(?1,?2,?3) ON CONFLICT(installation_id,host) DO UPDATE SET granted_at_unix_ms=excluded.granted_at_unix_ms",
                        params![installation_id, host.as_str(), now_unix_ms],
                    )?;
                }
                MontyNetworkAgentMutation::RevokeHost(host) => {
                    conn.execute(
                        "DELETE FROM monty_network_agent_grants WHERE installation_id=?1 AND host=?2",
                        params![installation_id, host.as_str()],
                    )?;
                }
                MontyNetworkAgentMutation::RevokeAllHosts => {
                    conn.execute(
                        "DELETE FROM monty_network_agent_grants WHERE installation_id=?1",
                        [&installation_id],
                    )?;
                }
            }
            read_policy(conn, Uuid::parse_str(&installation_id)?)
        })
        .await
    }

    /// Read-only generation predicate for diagnostics and focused tests.
    ///
    /// Transport dispatch uses [`Db::monty_network_egress_permit`] plus an
    /// exact policy read instead, so the revocation fence remains held through
    /// the actual `RequestBuilder::send` boundary.
    pub async fn monty_network_installation_fence_is_current(
        &self,
        installation_id: Uuid,
        expected_generation: u64,
    ) -> Result<bool> {
        let installation_id = installation_id.to_string();
        self.read(move |conn| {
            let generation = i64::try_from(expected_generation)?;
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM monty_network_agent_policies WHERE installation_id=?1 AND requests_enabled=1 AND generation=?2)",
                params![installation_id, generation],
                |row| row.get::<_, bool>(0),
            )?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn installed_agent(db: &Db) -> Uuid {
        let installation_id = Uuid::now_v7();
        let outcome = db
            .install_agent(crate::db::agent_installations::AgentInstallationInput {
                installation_id,
                scope: crate::db::agent_installations::AgentInstallationScope::Global,
                canonical_workspace_id: None,
                source_agent_id: format!("network-test-{installation_id}"),
                source_identity: format!("network-test:{installation_id}"),
                source_revision: Some("test".into()),
                source_digest: "a".repeat(64),
                fetched_at_unix_ms: 1,
            })
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            crate::db::agent_installations::InstallAgentOutcome::Installed(_)
        ));
        installation_id
    }

    #[tokio::test]
    async fn installation_policy_is_deny_by_default_and_revocation_advances_fence() {
        let db = Db::open_in_memory().unwrap();
        let installation_id = installed_agent(&db).await;
        let absent = db
            .monty_network_installation_policy(installation_id)
            .await
            .unwrap();
        assert!(!absent.requests_enabled);
        assert!(absent.hosts.is_empty());

        let enabled = db
            .mutate_monty_network_installation_policy(
                installation_id,
                MontyNetworkAgentMutation::SetRequestsEnabled(true),
                10,
            )
            .await
            .unwrap();
        let granted = db
            .mutate_monty_network_installation_policy(
                installation_id,
                MontyNetworkAgentMutation::GrantHost(
                    CanonicalNetworkHost::parse("api.example.test").unwrap(),
                ),
                11,
            )
            .await
            .unwrap();
        assert!(granted.generation > enabled.generation);
        assert!(granted.permits(&CanonicalNetworkHost::parse("api.example.test").unwrap()));
        assert!(
            db.monty_network_installation_fence_is_current(installation_id, granted.generation)
                .await
                .unwrap()
        );

        let revoked = db
            .mutate_monty_network_installation_policy(
                installation_id,
                MontyNetworkAgentMutation::RevokeHost(
                    CanonicalNetworkHost::parse("api.example.test").unwrap(),
                ),
                12,
            )
            .await
            .unwrap();
        assert!(revoked.generation > granted.generation);
        assert!(!revoked.permits(&CanonicalNetworkHost::parse("api.example.test").unwrap()));
        assert!(
            !db.monty_network_installation_fence_is_current(installation_id, granted.generation)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn durable_policy_mutation_waits_for_an_in_flight_egress_permit() {
        let db = Db::open_in_memory().unwrap();
        let installation_id = installed_agent(&db).await;
        let permit = db.monty_network_egress_permit().await;
        let revoking_db = db.clone();
        let revocation = tokio::spawn(async move {
            revoking_db
                .mutate_monty_network_installation_policy(
                    installation_id,
                    MontyNetworkAgentMutation::SetRequestsEnabled(false),
                    10,
                )
                .await
        });
        // Tokio's RwLock is fair/write-preferring: once the mutation has
        // attempted the exclusive fence, later read attempts are blocked even
        // while this first read permit remains held. Waiting for that state
        // makes the assertion below fail if the mutation ever stops taking its
        // write-side revocation fence, instead of merely racing one yield.
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if db.monty_network_egress_gate.try_read().is_err() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("durable policy mutation must attempt the write-side egress fence");
        assert!(
            !revocation.is_finished(),
            "durable policy mutation committed while egress retained its permit"
        );
        drop(permit);
        revocation.await.unwrap().unwrap();
    }
}
