//! Durable owner-granted Monty network policy.
//!
//! Agent definitions are deliberately absent from this module. They may carry
//! requested hosts for prompt prefill, but only these explicit user-action
//! mutations create durable authority.

use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use super::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MontyNetworkAgentPolicy {
    pub agent_instance_id: Uuid,
    pub requests_enabled: bool,
    pub approval_required: bool,
    pub generation: u64,
    pub hosts: std::collections::BTreeSet<String>,
}

impl MontyNetworkAgentPolicy {
    pub fn deny_all(agent_instance_id: Uuid) -> Self {
        Self {
            agent_instance_id,
            requests_enabled: false,
            approval_required: false,
            generation: 0,
            hosts: std::collections::BTreeSet::new(),
        }
    }

    pub fn permits(&self, host: &str) -> bool {
        self.requests_enabled && self.hosts.contains(host)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MontyNetworkAgentMutation {
    SetRequestsEnabled(bool),
    SetApprovalRequired(bool),
    GrantHost(String),
    RevokeHost(String),
    RevokeAllHosts,
}

fn read_policy(
    conn: &rusqlite::Connection,
    agent_instance_id: Uuid,
) -> Result<MontyNetworkAgentPolicy> {
    let agent_instance_id = agent_instance_id.to_string();
    let header = conn
        .query_row(
            "SELECT requests_enabled, approval_required, generation FROM monty_network_agent_policies WHERE agent_instance_id=?1",
            [&agent_instance_id],
            |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?, row.get::<_, i64>(2)?)),
        )
        .optional()?;
    let Some((requests_enabled, approval_required, generation)) = header else {
        return Ok(MontyNetworkAgentPolicy::deny_all(Uuid::parse_str(
            &agent_instance_id,
        )?));
    };
    let generation = u64::try_from(generation)?;
    let mut statement = conn.prepare(
        "SELECT host FROM monty_network_agent_grants WHERE agent_instance_id=?1 ORDER BY host",
    )?;
    let hosts = statement
        .query_map([&agent_instance_id], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()?;
    Ok(MontyNetworkAgentPolicy {
        agent_instance_id: Uuid::parse_str(&agent_instance_id)?,
        requests_enabled,
        approval_required,
        generation,
        hosts,
    })
}

impl Db {
    pub async fn monty_network_agent_policy(
        &self,
        agent_instance_id: Uuid,
    ) -> Result<MontyNetworkAgentPolicy> {
        self.read(move |conn| read_policy(conn, agent_instance_id))
            .await
    }

    /// Apply one explicit owner action and advance the revocation generation.
    pub async fn mutate_monty_network_agent_policy(
        &self,
        agent_instance_id: Uuid,
        mutation: MontyNetworkAgentMutation,
        now_unix_ms: i64,
    ) -> Result<MontyNetworkAgentPolicy> {
        // A completed policy mutation must be ordered after an egress that
        // already crossed its final durable-policy check, and before every
        // later egress. The request holds the shared permit through
        // `RequestBuilder::send`; do not move this exclusive acquisition
        // below the SQLite transaction.
        let _revocation_fence = self.monty_network_egress_gate.write().await;
        let agent_instance_id = agent_instance_id.to_string();
        self.transaction(move |conn| {
            conn.execute(
                "INSERT INTO monty_network_agent_policies(agent_instance_id,requests_enabled,approval_required,generation,updated_at_unix_ms) VALUES(?1,0,0,1,?2) ON CONFLICT(agent_instance_id) DO UPDATE SET generation=generation+1,updated_at_unix_ms=excluded.updated_at_unix_ms",
                params![agent_instance_id, now_unix_ms],
            )?;
            match mutation {
                MontyNetworkAgentMutation::SetRequestsEnabled(enabled) => {
                    conn.execute(
                        "UPDATE monty_network_agent_policies SET requests_enabled=?2 WHERE agent_instance_id=?1",
                        params![agent_instance_id, enabled],
                    )?;
                }
                MontyNetworkAgentMutation::SetApprovalRequired(required) => {
                    conn.execute(
                        "UPDATE monty_network_agent_policies SET approval_required=?2 WHERE agent_instance_id=?1",
                        params![agent_instance_id, required],
                    )?;
                }
                MontyNetworkAgentMutation::GrantHost(host) => {
                    validate_canonical_host(&host)?;
                    conn.execute(
                        "INSERT INTO monty_network_agent_grants(agent_instance_id,host,granted_at_unix_ms) VALUES(?1,?2,?3) ON CONFLICT(agent_instance_id,host) DO UPDATE SET granted_at_unix_ms=excluded.granted_at_unix_ms",
                        params![agent_instance_id, host, now_unix_ms],
                    )?;
                }
                MontyNetworkAgentMutation::RevokeHost(host) => {
                    validate_canonical_host(&host)?;
                    conn.execute(
                        "DELETE FROM monty_network_agent_grants WHERE agent_instance_id=?1 AND host=?2",
                        params![agent_instance_id, host],
                    )?;
                }
                MontyNetworkAgentMutation::RevokeAllHosts => {
                    conn.execute(
                        "DELETE FROM monty_network_agent_grants WHERE agent_instance_id=?1",
                        [&agent_instance_id],
                    )?;
                }
            }
            read_policy(conn, Uuid::parse_str(&agent_instance_id)?)
        })
        .await
    }

    /// Read-only generation predicate for diagnostics and focused tests.
    ///
    /// Transport dispatch uses [`Db::monty_network_egress_permit`] plus an
    /// exact policy read instead, so the revocation fence remains held through
    /// the actual `RequestBuilder::send` boundary.
    pub async fn monty_network_agent_fence_is_current(
        &self,
        agent_instance_id: Uuid,
        expected_generation: u64,
    ) -> Result<bool> {
        let agent_instance_id = agent_instance_id.to_string();
        self.read(move |conn| {
            let generation = i64::try_from(expected_generation)?;
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM monty_network_agent_policies WHERE agent_instance_id=?1 AND requests_enabled=1 AND generation=?2)",
                params![agent_instance_id, generation],
                |row| row.get::<_, bool>(0),
            )?)
        })
        .await
    }
}

fn validate_canonical_host(host: &str) -> Result<()> {
    if host.is_empty()
        || host.len() > 253
        || host != host.to_ascii_lowercase()
        || host
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '/' | '?' | '#' | '@' | ':'))
    {
        bail!("network grant host is not canonical");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn agent_policy_is_deny_by_default_and_revocation_advances_fence() {
        let db = Db::open_in_memory().unwrap();
        let agent_instance_id = Uuid::new_v4();
        let absent = db
            .monty_network_agent_policy(agent_instance_id)
            .await
            .unwrap();
        assert!(!absent.requests_enabled);
        assert!(absent.hosts.is_empty());

        let enabled = db
            .mutate_monty_network_agent_policy(
                agent_instance_id,
                MontyNetworkAgentMutation::SetRequestsEnabled(true),
                10,
            )
            .await
            .unwrap();
        let granted = db
            .mutate_monty_network_agent_policy(
                agent_instance_id,
                MontyNetworkAgentMutation::GrantHost("api.example.test".to_string()),
                11,
            )
            .await
            .unwrap();
        assert!(granted.generation > enabled.generation);
        assert!(granted.permits("api.example.test"));
        assert!(
            db.monty_network_agent_fence_is_current(agent_instance_id, granted.generation)
                .await
                .unwrap()
        );

        let revoked = db
            .mutate_monty_network_agent_policy(
                agent_instance_id,
                MontyNetworkAgentMutation::RevokeHost("api.example.test".to_string()),
                12,
            )
            .await
            .unwrap();
        assert!(revoked.generation > granted.generation);
        assert!(!revoked.permits("api.example.test"));
        assert!(
            !db.monty_network_agent_fence_is_current(agent_instance_id, granted.generation)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn durable_policy_mutation_waits_for_an_in_flight_egress_permit() {
        let db = Db::open_in_memory().unwrap();
        let agent_instance_id = Uuid::new_v4();
        let permit = db.monty_network_egress_permit().await;
        let revoking_db = db.clone();
        let revocation = tokio::spawn(async move {
            revoking_db
                .mutate_monty_network_agent_policy(
                    agent_instance_id,
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
