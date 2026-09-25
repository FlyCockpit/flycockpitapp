//! Daemon-derived coverage key material and capture-boundary revision snapshots.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::extended::RedactConfig;
use crate::daemon::principal::ClientPrincipal;
use crate::env_snapshot::EnvSnapshot;

use super::coverage_authority::{CoverageBinding, RedactionCoverageKey};
use super::{RedactionSourceScope, RedactionTable, matched_dotenv_sources};

/// Inputs needed to derive a session coverage key and to snapshot capture
/// boundary revisions at publication time.
pub(crate) struct SessionCoverageInputs<'a> {
    pub principal: &'a ClientPrincipal,
    pub owner_authorization_revision: i64,
    pub session_id: Uuid,
    pub workspace_root: &'a Path,
    pub environment: &'a EnvSnapshot,
    pub vault_revision: u64,
    pub command_cache: &'a crate::secret_command::CommandSecretCache,
    pub policy_digest: &'a str,
    pub sealed: CoverageBinding,
    pub override_revision: u64,
    pub redact_config: &'a RedactConfig,
}

/// Inputs of daemon-wide coverage. There is deliberately no root: daemon-global
/// coverage is built from daemon-global sources only (the environment
/// snapshot, vault/keyring and command secrets, and the global config layer's
/// redact settings) and never walks a workspace or the daemon's working
/// directory. Workspace env files are covered per session.
pub(crate) struct DaemonGlobalCoverageInputs<'a> {
    pub environment: &'a EnvSnapshot,
    pub vault_revision: u64,
    pub command_cache: &'a crate::secret_command::CommandSecretCache,
    pub policy_digest: &'a str,
    pub sealed: CoverageBinding,
    pub override_revision: u64,
    pub redact_config: &'a RedactConfig,
}

/// Daemon-global coverage could not resolve one of its owned sources. Callers
/// fail closed (no table is published) instead of panicking.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DaemonGlobalCoverageError {
    #[error("coverage_unavailable: loading the global redaction config layer: {0:#}")]
    GlobalRedactConfig(anyhow::Error),
}

/// The single read of daemon-global redaction policy: the global config layer
/// through the injected [`ConfigSource`](crate::daemon::config_source::ConfigSource),
/// with no project root.
pub(crate) fn load_daemon_global_redact_config(
    config_source: &crate::daemon::config_source::ConfigSource,
) -> Result<RedactConfig, DaemonGlobalCoverageError> {
    config_source
        .load_global()
        .map(|extended| extended.redact)
        .map_err(DaemonGlobalCoverageError::GlobalRedactConfig)
}

/// Owned-input revisions recorded at the completed-scan boundary and re-checked
/// at publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedSourceRevisions {
    pub environment: CoverageBinding,
    pub credential_vault: CoverageBinding,
    pub policy: CoverageBinding,
    pub sealed: CoverageBinding,
    pub override_revision: CoverageBinding,
    pub machine_sources: CoverageBinding,
}

/// Digest of every table-affecting redact setting.
///
/// The config is destructured exhaustively, so adding a `RedactConfig` field
/// is a compile error here until it is encoded. Each field is written with a
/// tag and every string, path, and list with an explicit length, so no two
/// distinct configs (for example `["ab"]` and `["a", "b"]`) share an encoding.
pub(crate) fn redact_config_digest(config: &RedactConfig) -> String {
    let RedactConfig {
        enabled,
        scan_environment,
        scan_dotenv,
        scan_ssh_keys,
        ssh_key_dir,
        dotenv_patterns,
        extra_dotenv_paths,
        secret_path_patterns,
        min_secret_length,
        placeholder,
        denylist,
        allowlist,
    } = config;
    let mut hasher = Sha256::new();
    hasher.update(b"flycockpit-redact-policy-v1\0");
    let mut field = |tag: &[u8], bytes: &[u8]| {
        hasher.update((tag.len() as u64).to_le_bytes());
        hasher.update(tag);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    field(b"enabled", &[u8::from(*enabled)]);
    field(b"scan_environment", &[u8::from(*scan_environment)]);
    field(b"scan_dotenv", &[u8::from(*scan_dotenv)]);
    field(b"scan_ssh_keys", &[u8::from(*scan_ssh_keys)]);
    match ssh_key_dir {
        Some(dir) => field(b"ssh_key_dir", dir.as_os_str().as_encoded_bytes()),
        None => field(b"ssh_key_dir:none", &[]),
    }
    field(
        b"min_secret_length",
        &(*min_secret_length as u64).to_le_bytes(),
    );
    field(b"placeholder", placeholder.as_bytes());
    let mut list = |tag: &[u8], items: Vec<&[u8]>| {
        field(tag, &(items.len() as u64).to_le_bytes());
        for item in items {
            field(tag, item);
        }
    };
    list(
        b"dotenv_patterns",
        dotenv_patterns.iter().map(|item| item.as_bytes()).collect(),
    );
    list(
        b"extra_dotenv_paths",
        extra_dotenv_paths
            .iter()
            .map(|item| item.as_os_str().as_encoded_bytes())
            .collect(),
    );
    list(
        b"secret_path_patterns",
        secret_path_patterns
            .iter()
            .map(|item| item.as_bytes())
            .collect(),
    );
    list(
        b"denylist",
        denylist.iter().map(|item| item.as_bytes()).collect(),
    );
    list(
        b"allowlist",
        allowlist.iter().map(|item| item.as_bytes()).collect(),
    );
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn principal_binding(principal: &ClientPrincipal) -> CoverageBinding {
    CoverageBinding::derive(b"principal", &principal.coverage_identity_material())
}

pub(crate) fn owner_authorization_binding(revision: i64) -> CoverageBinding {
    CoverageBinding::derive(b"owner-authorization", &revision.to_le_bytes())
}

pub(crate) fn credential_vault_binding(
    vault_revision: u64,
    command_cache: &crate::secret_command::CommandSecretCache,
) -> CoverageBinding {
    let mut material = vault_revision.to_le_bytes().to_vec();
    material.extend_from_slice(&command_cache.coverage_fingerprint());
    CoverageBinding::derive(b"credential-vault", &material)
}

pub(crate) fn machine_sources_probe_binding(
    config: &RedactConfig,
    scope: RedactionSourceScope<'_>,
) -> anyhow::Result<CoverageBinding> {
    machine_sources_binding(config, scope, None)
}

/// Binding of the file-backed sources a build in `scope` reads.
///
/// Every source failure is an error, never a sentinel: an unavailable source
/// must not hash equal to an empty or earlier successful one, so key
/// derivation, boundary capture, and the publication fence all fail closed.
pub(crate) fn machine_sources_binding(
    config: &RedactConfig,
    scope: RedactionSourceScope<'_>,
    table: Option<&RedactionTable>,
) -> anyhow::Result<CoverageBinding> {
    let mut hasher = Sha256::new();
    hasher.update(b"flycockpit-redaction-machine-sources-v1\0");
    let mut field = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    if config.scan_dotenv {
        let paths =
            matched_dotenv_sources(scope, &config.dotenv_patterns, &config.extra_dotenv_paths)?;
        field(&(paths.len() as u64).to_le_bytes());
        for path in paths {
            // Same typed failures as the capture itself, so an over-cap or
            // unreadable source is reported identically wherever it is hit.
            let bytes =
                crate::resource_limits::read_for_tool(&path).map_err(|error| match error {
                    crate::resource_limits::ResourceLimitError::ByteLimit { .. } => {
                        anyhow::Error::from(super::EnvFileOverLimitError { path: path.clone() })
                    }
                    _ => anyhow::Error::from(super::RedactionSourceUnreadableError {
                        path: path.clone(),
                    }),
                })?;
            field(path.as_os_str().as_encoded_bytes());
            field(&bytes);
        }
    }
    if config.scan_ssh_keys {
        let directory = super::ssh::resolve_ssh_key_dir(scope, config.ssh_key_dir.as_deref())?;
        let candidates = super::ssh::collect_ssh_key_candidates(directory.as_deref())?;
        field(&(candidates.len() as u64).to_le_bytes());
        for (value, origin) in candidates {
            field(origin.as_bytes());
            field(value.as_bytes());
        }
    }
    if let Some(table) = table {
        for path in table.unsupported_files() {
            field(path.as_os_str().as_encoded_bytes());
        }
    }
    let digest = hasher.finalize();
    Ok(CoverageBinding::derive(
        b"machine-sources",
        digest.as_slice(),
    ))
}

pub(crate) fn sealed_records_binding(
    records: &[cockpit_db::db::sealed_scope::SealedValueRecordRow],
) -> CoverageBinding {
    let mut hasher = Sha256::new();
    hasher.update(b"flycockpit-redaction-sealed-v1\0");
    for record in records {
        hasher.update(record.record_id.as_bytes());
        hasher.update(record.active_version.to_le_bytes());
        hasher.update(record.name.as_bytes());
    }
    let digest = hasher.finalize();
    CoverageBinding::derive(b"sealed", digest.as_slice())
}

impl SessionCoverageInputs<'_> {
    pub(crate) fn coverage_key(&self) -> anyhow::Result<RedactionCoverageKey> {
        Ok(RedactionCoverageKey::session(
            principal_binding(self.principal),
            owner_authorization_binding(self.owner_authorization_revision),
            CoverageBinding::derive(b"session", self.session_id.as_bytes()),
            CoverageBinding::derive(
                b"workspace",
                self.workspace_root.as_os_str().as_encoded_bytes(),
            ),
            CoverageBinding::derive(b"environment", self.environment.digest().as_bytes()),
            credential_vault_binding(self.vault_revision, self.command_cache),
            CoverageBinding::derive(b"policy", self.policy_digest.as_bytes()),
            self.sealed,
            CoverageBinding::derive(b"override", &self.override_revision.to_le_bytes()),
            machine_sources_probe_binding(
                self.redact_config,
                RedactionSourceScope::Workspace(self.workspace_root),
            )?,
        ))
    }

    pub(crate) fn boundary_revisions(
        &self,
        table: &RedactionTable,
    ) -> anyhow::Result<OwnedSourceRevisions> {
        Ok(OwnedSourceRevisions {
            environment: CoverageBinding::derive(
                b"environment",
                self.environment.digest().as_bytes(),
            ),
            credential_vault: credential_vault_binding(self.vault_revision, self.command_cache),
            policy: CoverageBinding::derive(b"policy", self.policy_digest.as_bytes()),
            sealed: self.sealed,
            override_revision: CoverageBinding::derive(
                b"override",
                &self.override_revision.to_le_bytes(),
            ),
            machine_sources: machine_sources_binding(
                self.redact_config,
                RedactionSourceScope::Workspace(self.workspace_root),
                Some(table),
            )?,
        })
    }
}

pub(crate) async fn snapshot_session_capture_inputs<'a>(
    session: &'a crate::session::Session,
    principal: &'a ClientPrincipal,
    owner_authorization_revision: i64,
    workspace_root: &'a Path,
    environment: &'a EnvSnapshot,
    command_cache: &'a crate::secret_command::CommandSecretCache,
    policy_digest: &'a str,
    override_revision: u64,
    redact_config: &'a RedactConfig,
) -> anyhow::Result<SessionCoverageInputs<'a>> {
    let vault_revision = session
        .secret_vault()
        .current_inventory_generation()
        .map_err(|error| anyhow::anyhow!("reading redaction vault revision: {error}"))?;
    let sealed_records = session.db.machine_scoped_sealed_redaction_records().await?;
    let sealed = sealed_records_binding(&sealed_records);
    Ok(SessionCoverageInputs {
        principal,
        owner_authorization_revision,
        session_id: session.id,
        workspace_root,
        environment,
        vault_revision,
        command_cache: &command_cache,
        policy_digest,
        sealed,
        override_revision,
        redact_config,
    })
}

impl DaemonGlobalCoverageInputs<'_> {
    pub(crate) fn coverage_key(&self) -> anyhow::Result<RedactionCoverageKey> {
        Ok(RedactionCoverageKey::daemon_global(
            CoverageBinding::derive(b"principal", b"daemon"),
            CoverageBinding::derive(b"owner-authorization", b"daemon-owner"),
            CoverageBinding::derive(b"environment", self.environment.digest().as_bytes()),
            credential_vault_binding(self.vault_revision, self.command_cache),
            CoverageBinding::derive(b"policy", self.policy_digest.as_bytes()),
            self.sealed,
            CoverageBinding::derive(b"override", &self.override_revision.to_le_bytes()),
            machine_sources_probe_binding(self.redact_config, RedactionSourceScope::DaemonGlobal)?,
        ))
    }

    pub(crate) fn boundary_revisions(
        &self,
        table: &RedactionTable,
    ) -> anyhow::Result<OwnedSourceRevisions> {
        Ok(OwnedSourceRevisions {
            environment: CoverageBinding::derive(
                b"environment",
                self.environment.digest().as_bytes(),
            ),
            credential_vault: credential_vault_binding(self.vault_revision, self.command_cache),
            policy: CoverageBinding::derive(b"policy", self.policy_digest.as_bytes()),
            sealed: self.sealed,
            override_revision: CoverageBinding::derive(
                b"override",
                &self.override_revision.to_le_bytes(),
            ),
            machine_sources: machine_sources_binding(
                self.redact_config,
                RedactionSourceScope::DaemonGlobal,
                Some(table),
            )?,
        })
    }
}

/// Live owner reads consulted independently at publication time.
pub(crate) struct SessionCoveragePublishLive {
    pub environment: std::sync::Arc<dyn Fn() -> anyhow::Result<EnvSnapshot> + Send + Sync>,
    pub policy_digest: std::sync::Arc<dyn Fn() -> String + Send + Sync>,
    pub override_revision: std::sync::Arc<dyn Fn() -> u64 + Send + Sync>,
    pub redact_config: std::sync::Arc<dyn Fn() -> RedactConfig + Send + Sync>,
    pub workspace_root: std::sync::Arc<dyn Fn() -> PathBuf + Send + Sync>,
}

/// Live owners consulted independently at publication time.
pub(crate) struct SessionCoveragePublishOwners {
    vault: std::sync::Arc<crate::secure_key::SecretVault>,
    db: cockpit_db::Db,
    command_cache: std::sync::Arc<crate::secret_command::CommandSecretCache>,
    live: SessionCoveragePublishLive,
}

impl SessionCoveragePublishOwners {
    pub(crate) fn owned_revisions(
        &self,
        table: &RedactionTable,
    ) -> anyhow::Result<OwnedSourceRevisions> {
        let vault_revision = self
            .vault
            .current_inventory_generation()
            .map_err(|error| anyhow::anyhow!("reading redaction vault revision: {error}"))?;
        let sealed_records = tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow::anyhow!("coverage publication requires async runtime"))?
            .block_on(self.db.machine_scoped_sealed_redaction_records())
            .map_err(|error| anyhow::anyhow!("reading sealed redaction records: {error}"))?;
        let sealed = sealed_records_binding(&sealed_records);
        let environment = (self.live.environment)()?;
        let policy_digest = (self.live.policy_digest)();
        let override_revision = (self.live.override_revision)();
        let redact_config = (self.live.redact_config)();
        let workspace_root = (self.live.workspace_root)();
        Ok(OwnedSourceRevisions {
            environment: CoverageBinding::derive(b"environment", environment.digest().as_bytes()),
            credential_vault: credential_vault_binding(vault_revision, &self.command_cache),
            policy: CoverageBinding::derive(b"policy", policy_digest.as_bytes()),
            sealed,
            override_revision: CoverageBinding::derive(
                b"override",
                &override_revision.to_le_bytes(),
            ),
            machine_sources: machine_sources_binding(
                &redact_config,
                RedactionSourceScope::Workspace(&workspace_root),
                Some(table),
            )?,
        })
    }

    pub(crate) fn publish_fence(self) -> super::coverage_authority::CoveragePublishFence {
        Box::new(move |table| self.owned_revisions(table))
    }
}

/// Live owner reads consulted independently at daemon-global publication time.
///
/// `redact_config` is read once per fence and both the policy digest and the
/// machine-source binding derive from that one read, so the two cannot come
/// from different config instants. A failed read fails the fence closed.
pub(crate) struct DaemonGlobalCoveragePublishLive {
    pub environment: std::sync::Arc<dyn Fn() -> anyhow::Result<EnvSnapshot> + Send + Sync>,
    pub override_revision: std::sync::Arc<dyn Fn() -> u64 + Send + Sync>,
    pub redact_config: std::sync::Arc<dyn Fn() -> anyhow::Result<RedactConfig> + Send + Sync>,
    pub sealed: std::sync::Arc<dyn Fn() -> CoverageBinding + Send + Sync>,
}

/// Daemon-global publication fence that rereads sync-accessible owned sources.
pub(crate) struct DaemonGlobalCoveragePublishOwners {
    vault: std::sync::Arc<crate::secure_key::SecretVault>,
    command_cache: std::sync::Arc<crate::secret_command::CommandSecretCache>,
    live: DaemonGlobalCoveragePublishLive,
}

impl DaemonGlobalCoveragePublishOwners {
    pub(crate) fn owned_revisions(
        &self,
        table: &RedactionTable,
    ) -> anyhow::Result<OwnedSourceRevisions> {
        let vault_revision = self
            .vault
            .current_inventory_generation()
            .map_err(|error| anyhow::anyhow!("reading redaction vault revision: {error}"))?;
        let environment = (self.live.environment)()?;
        let override_revision = (self.live.override_revision)();
        let redact_config = (self.live.redact_config)()?;
        let policy_digest = redact_config_digest(&redact_config);
        Ok(OwnedSourceRevisions {
            environment: CoverageBinding::derive(b"environment", environment.digest().as_bytes()),
            credential_vault: credential_vault_binding(vault_revision, &self.command_cache),
            policy: CoverageBinding::derive(b"policy", policy_digest.as_bytes()),
            sealed: (self.live.sealed)(),
            override_revision: CoverageBinding::derive(
                b"override",
                &override_revision.to_le_bytes(),
            ),
            machine_sources: machine_sources_binding(
                &redact_config,
                RedactionSourceScope::DaemonGlobal,
                Some(table),
            )?,
        })
    }

    pub(crate) fn publish_fence(self) -> super::coverage_authority::CoveragePublishFence {
        Box::new(move |table| self.owned_revisions(table))
    }
}

pub(crate) fn session_publish_owners(
    vault: std::sync::Arc<crate::secure_key::SecretVault>,
    db: cockpit_db::Db,
    command_cache: std::sync::Arc<crate::secret_command::CommandSecretCache>,
    live: SessionCoveragePublishLive,
) -> SessionCoveragePublishOwners {
    SessionCoveragePublishOwners {
        vault,
        db,
        command_cache,
        live,
    }
}

pub(crate) fn session_publish_owners_for_session(
    session: std::sync::Arc<crate::session::Session>,
    vault: std::sync::Arc<crate::secure_key::SecretVault>,
    db: cockpit_db::Db,
    command_cache: std::sync::Arc<crate::secret_command::CommandSecretCache>,
    environment: std::sync::Arc<dyn Fn() -> anyhow::Result<EnvSnapshot> + Send + Sync>,
    redact_config: std::sync::Arc<dyn Fn() -> RedactConfig + Send + Sync>,
    override_revision: std::sync::Arc<dyn Fn() -> u64 + Send + Sync>,
) -> SessionCoveragePublishOwners {
    session_publish_owners(
        vault,
        db,
        command_cache,
        SessionCoveragePublishLive {
            environment,
            policy_digest: std::sync::Arc::new({
                let redact_config = redact_config.clone();
                move || redact_config_digest(&redact_config())
            }),
            override_revision,
            redact_config,
            workspace_root: std::sync::Arc::new({
                let session = session.clone();
                move || session.project_root.clone()
            }),
        },
    )
}

pub(crate) fn daemon_global_publish_owners(
    vault: std::sync::Arc<crate::secure_key::SecretVault>,
    command_cache: std::sync::Arc<crate::secret_command::CommandSecretCache>,
    live: DaemonGlobalCoveragePublishLive,
) -> DaemonGlobalCoveragePublishOwners {
    DaemonGlobalCoveragePublishOwners {
        vault,
        command_cache,
        live,
    }
}

pub(crate) fn daemon_global_publish_owners_for_config(
    config_source: crate::daemon::config_source::ConfigSource,
    vault: std::sync::Arc<crate::secure_key::SecretVault>,
    command_cache: std::sync::Arc<crate::secret_command::CommandSecretCache>,
    environment: std::sync::Arc<dyn Fn() -> anyhow::Result<EnvSnapshot> + Send + Sync>,
) -> DaemonGlobalCoveragePublishOwners {
    daemon_global_publish_owners(
        vault,
        command_cache,
        DaemonGlobalCoveragePublishLive {
            environment,
            override_revision: std::sync::Arc::new(|| 0),
            redact_config: std::sync::Arc::new(move || {
                load_daemon_global_redact_config(&config_source).map_err(anyhow::Error::from)
            }),
            sealed: std::sync::Arc::new(|| CoverageBinding::derive(b"sealed", b"daemon-global")),
        },
    )
}
