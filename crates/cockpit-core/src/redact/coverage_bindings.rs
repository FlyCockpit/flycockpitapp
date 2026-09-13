//! Daemon-derived coverage key material and capture-boundary revision snapshots.

use std::path::Path;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::extended::RedactConfig;
use crate::daemon::principal::ClientPrincipal;
use crate::env_snapshot::EnvSnapshot;

use super::coverage_authority::{CoverageBinding, RedactionCoverageKey};
use super::{RedactionTable, matched_dotenv_paths};

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

pub(crate) struct DaemonGlobalCoverageInputs<'a> {
    pub environment: &'a EnvSnapshot,
    pub vault_revision: u64,
    pub command_cache: &'a crate::secret_command::CommandSecretCache,
    pub policy_digest: &'a str,
    pub sealed: CoverageBinding,
    pub override_revision: u64,
    pub source_root: &'a Path,
    pub redact_config: &'a RedactConfig,
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

pub(crate) fn redact_config_digest(config: &RedactConfig) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"flycockpit-redact-policy-v1\0");
    hasher.update([u8::from(config.enabled)]);
    hasher.update([u8::from(config.scan_environment)]);
    hasher.update([u8::from(config.scan_dotenv)]);
    hasher.update([u8::from(config.scan_ssh_keys)]);
    if let Some(dir) = &config.ssh_key_dir {
        hasher.update(dir.as_os_str().as_encoded_bytes());
    }
    for pattern in &config.dotenv_patterns {
        hasher.update(pattern.as_bytes());
    }
    for path in &config.extra_dotenv_paths {
        hasher.update(path.as_os_str().as_encoded_bytes());
    }
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

pub(crate) fn machine_sources_probe_binding(config: &RedactConfig, root: &Path) -> CoverageBinding {
    machine_sources_binding(config, root, None)
}

pub(crate) fn machine_sources_binding(
    config: &RedactConfig,
    root: &Path,
    table: Option<&RedactionTable>,
) -> CoverageBinding {
    let mut hasher = Sha256::new();
    hasher.update(b"flycockpit-redaction-machine-sources-v1\0");
    if config.scan_dotenv {
        for path in matched_dotenv_paths(root, &config.dotenv_patterns, &config.extra_dotenv_paths)
        {
            hasher.update(path.as_os_str().as_encoded_bytes());
            if let Ok(bytes) = crate::resource_limits::read_for_tool(&path) {
                hasher.update(&bytes);
            } else {
                hasher.update([0xFF]);
            }
        }
    }
    if config.scan_ssh_keys {
        if let Ok(candidates) =
            super::ssh::collect_ssh_key_candidates(config.ssh_key_dir.as_deref())
        {
            for (value, origin) in candidates {
                hasher.update(origin.as_bytes());
                hasher.update(value.as_bytes());
            }
        }
    }
    if let Some(table) = table {
        for path in table.unsupported_files() {
            hasher.update(path.as_os_str().as_encoded_bytes());
        }
    }
    let digest = hasher.finalize();
    CoverageBinding::derive(b"machine-sources", digest.as_slice())
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
    pub(crate) fn coverage_key(&self) -> RedactionCoverageKey {
        RedactionCoverageKey::session(
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
            machine_sources_probe_binding(self.redact_config, self.workspace_root),
        )
    }

    pub(crate) fn boundary_revisions(&self, table: &RedactionTable) -> OwnedSourceRevisions {
        OwnedSourceRevisions {
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
                self.workspace_root,
                Some(table),
            ),
        }
    }
}

pub(crate) async fn snapshot_session_capture_inputs(
    session: &crate::session::Session,
    principal: &ClientPrincipal,
    owner_authorization_revision: i64,
    workspace_root: &Path,
    environment: &EnvSnapshot,
    policy_digest: &str,
    override_revision: u64,
    redact_config: &RedactConfig,
) -> anyhow::Result<SessionCoverageInputs<'_>> {
    let vault_revision = session
        .secret_vault()
        .current_inventory_generation()
        .map_err(|error| anyhow::anyhow!("reading redaction vault revision: {error}"))?;
    let command_cache = session
        .command_secret_cache()
        .ok_or_else(|| anyhow::anyhow!("coverage_unavailable: command secret cache missing"))?;
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
    pub(crate) fn coverage_key(&self) -> RedactionCoverageKey {
        RedactionCoverageKey::daemon_global(
            CoverageBinding::derive(b"principal", b"daemon"),
            CoverageBinding::derive(b"owner-authorization", b"daemon-owner"),
            CoverageBinding::derive(b"environment", self.environment.digest().as_bytes()),
            credential_vault_binding(self.vault_revision, self.command_cache),
            CoverageBinding::derive(b"policy", self.policy_digest.as_bytes()),
            self.sealed,
            CoverageBinding::derive(b"override", &self.override_revision.to_le_bytes()),
            machine_sources_probe_binding(self.redact_config, self.source_root),
        )
    }

    pub(crate) fn boundary_revisions(&self, table: &RedactionTable) -> OwnedSourceRevisions {
        OwnedSourceRevisions {
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
                self.source_root,
                Some(table),
            ),
        }
    }
}
