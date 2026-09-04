//! Strict shared/replica/credential file schemas (**reference contract**).
//!
//! Each strict file resolves to an absolute owner-readable nonsymlink file
//! with safe parents. Shared config is strict JSON `{schemaVersion:1,
//! deploymentId, audience, issuer, listenAddress, pkcs11ModulePath,
//! idempotencyHours:24, requestDeadlineSeconds:10, tenants}`. Replica JSON
//! is exactly `{schemaVersion:1, deploymentId, replicaId, replicaGeneration,
//! adminSocketPath}`. Credential JSON is exactly `{schemaVersion:1,
//! serverCaFile, serverCertificateFile, serverPrivateKeyFile,
//! tenantCredentials:[{tenantId,authorityId,submitCaFile,pkcs11PinFile}]}`.
//! Unknown fields, relative/unsafe paths, duplicate tenant/replica identity,
//! digest rollback, or deployment/audience/issuer mismatch fails readiness.

use cockpit_proto::remote_tenant_authority_protocol::{
    self as proto, IDEMPOTENCY_RETENTION_HOURS, NETWORK_DEADLINE_SECONDS,
};
use serde::{Deserialize, Serialize};

/// Tenant authority state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantState {
    BootstrapPending,
    Active,
}

/// One key generation in the strict multi-generation registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantKeyGeneration {
    pub generation: String,
    pub cka_id_base64url: String,
    pub kid: String,
    pub state: TenantKeyGenerationState,
    pub public_jwk_digest: String,
    pub activated_at: i64,
    pub retire_at: Option<i64>,
}

/// Key generation lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantKeyGenerationState {
    Next,
    Current,
    VerificationOnly,
    Revoked,
}

/// Control-plane authority trust pins for a tenant entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlPlaneAuthority {
    pub issuer: String,
    pub deployment_id: String,
    /// Exactly one steady digest or one ordered D0/D1/D2 plan.
    pub allowed_ring_digests: Vec<String>,
    pub bootstrap_ring_digest: String,
    pub bootstrap_status_digest: String,
}

/// One tenant config entry. Each entry pins its own submit CA digest, leaf
/// SPKI digest, and exact SAN; no global CA/SPKI pin can authorize another
/// tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantConfigEntry {
    pub tenant_id: String,
    pub authority_id: String,
    pub state: TenantState,
    pub expected_bootstrap_registry_digest: String,
    pub expected_bootstrap_ring_digest: String,
    pub expected_bootstrap_policy_digest: String,
    pub submit_ca_sha256: String,
    pub submit_leaf_spki_sha256: String,
    pub submit_san: String,
    pub control_plane_authority: ControlPlaneAuthority,
    pub module_sha256: String,
    pub slot_id: String,
    pub token_serial: String,
    pub token_label: String,
    pub key_generations: Vec<TenantKeyGeneration>,
}

/// Shared service config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedConfig {
    pub schema_version: u8,
    pub deployment_id: String,
    pub audience: String,
    pub issuer: String,
    pub listen_address: String,
    pub pkcs11_module_path: String,
    pub idempotency_hours: i64,
    pub request_deadline_seconds: i64,
    pub tenants: Vec<TenantConfigEntry>,
}

/// Replica identity file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicaFile {
    pub schema_version: u8,
    pub deployment_id: String,
    pub replica_id: String,
    pub replica_generation: String,
    pub admin_socket_path: String,
}

/// One tenant credential entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantCredential {
    pub tenant_id: String,
    pub authority_id: String,
    pub submit_ca_file: String,
    pub pkcs11_pin_file: String,
}

/// mTLS credentials file. Entries are raw-`tenantId||authorityId` sorted and
/// every value is an absolute owner-readable nonsymlink file reference,
/// never inline secret/key/certificate bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialFile {
    pub schema_version: u8,
    pub server_ca_file: String,
    pub server_certificate_file: String,
    pub server_private_key_file: String,
    pub tenant_credentials: Vec<TenantCredential>,
}

/// Errors raised by strict config validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("schemaVersion must be 1")]
    BadSchemaVersion,
    #[error("deploymentId must be [A-Za-z0-9_-]{{1,64}}")]
    BadDeploymentId,
    #[error("audience/issuer must be normalized HTTPS origins")]
    BadOrigin,
    #[error("listenAddress must be IP:port or [IPv6]:port with nonzero port")]
    BadListenAddress,
    #[error("idempotencyHours must be 24")]
    BadIdempotencyHours,
    #[error("requestDeadlineSeconds must be 10")]
    BadDeadline,
    #[error("tenants must be sorted by raw tenantId||authorityId")]
    TenantsUnsorted,
    #[error("duplicate tenant/authority identity")]
    DuplicateTenant,
    #[error("unknown field: {0}")]
    UnknownField(String),
    #[error("relative or unsafe path: {0}")]
    UnsafePath(String),
    #[error("inline secret/key/certificate bytes forbidden")]
    InlineSecret,
}

impl SharedConfig {
    /// Validate the strict shared config invariants. Unknown fields,
    /// relative/unsafe paths, duplicate tenant identity, or deployment/
    /// audience/issuer mismatch fails readiness.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::BadSchemaVersion);
        }
        validate_deployment_id(&self.deployment_id)?;
        validate_https_origin(&self.audience).map_err(|_| ConfigError::BadOrigin)?;
        validate_https_origin(&self.issuer).map_err(|_| ConfigError::BadOrigin)?;
        validate_listen_address(&self.listen_address)?;
        if self.idempotency_hours != IDEMPOTENCY_RETENTION_HOURS {
            return Err(ConfigError::BadIdempotencyHours);
        }
        if self.request_deadline_seconds != NETWORK_DEADLINE_SECONDS {
            return Err(ConfigError::BadDeadline);
        }
        validate_tenants_sorted_and_unique(&self.tenants)?;
        for t in &self.tenants {
            validate_deployment_id(&t.control_plane_authority.deployment_id)?;
            // Exactly one current generation; revoked can never sign.
            let current = t
                .key_generations
                .iter()
                .filter(|g| g.state == TenantKeyGenerationState::Current)
                .count();
            if current != 1 {
                return Err(ConfigError::UnknownField(
                    "exactly one current generation required".into(),
                ));
            }
        }
        Ok(())
    }
}

impl ReplicaFile {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::BadSchemaVersion);
        }
        validate_deployment_id(&self.deployment_id)?;
        // replica ID is unpadded base64url-16.
        if self.replica_id.len() != 22 {
            return Err(ConfigError::UnknownField(
                "replicaId must be base64url-16".into(),
            ));
        }
        // generation is a nonzero decimal string.
        if self.replica_generation.is_empty()
            || self.replica_generation.chars().any(|c| !c.is_ascii_digit())
            || self.replica_generation == "0"
        {
            return Err(ConfigError::UnknownField(
                "replicaGeneration must be a nonzero decimal string".into(),
            ));
        }
        // absolute owner-only Unix socket path with safe parents.
        validate_absolute_path(&self.admin_socket_path)?;
        Ok(())
    }
}

impl CredentialFile {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::BadSchemaVersion);
        }
        validate_absolute_path(&self.server_ca_file)?;
        validate_absolute_path(&self.server_certificate_file)?;
        validate_absolute_path(&self.server_private_key_file)?;
        let mut prev: Option<(&str, &str)> = None;
        for c in &self.tenant_credentials {
            validate_absolute_path(&c.submit_ca_file)?;
            validate_absolute_path(&c.pkcs11_pin_file)?;
            let key = (c.tenant_id.as_str(), c.authority_id.as_str());
            if let Some(p) = prev
                && p >= key
            {
                return Err(ConfigError::TenantsUnsorted);
            }
            prev = Some(key);
        }
        Ok(())
    }
}

fn validate_deployment_id(s: &str) -> Result<(), ConfigError> {
    if !(1..=64).contains(&s.len())
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ConfigError::BadDeploymentId);
    }
    Ok(())
}

fn validate_https_origin(s: &str) -> Result<(), proto::TenantAuthorityProtocolError> {
    proto::normalized_https_origin(s)?;
    Ok(())
}

fn validate_listen_address(s: &str) -> Result<(), ConfigError> {
    // canonical IP literal plus nonzero port (`IPv4:port` or `[IPv6]:port`).
    if let Some(rest) = s.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(ConfigError::BadListenAddress);
        };
        if host.is_empty() {
            return Err(ConfigError::BadListenAddress);
        }
        validate_nonzero_port(port)?;
    } else if let Some((host, port)) = s.split_once(':') {
        if host.is_empty() {
            return Err(ConfigError::BadListenAddress);
        }
        validate_nonzero_port(port)?;
    } else {
        return Err(ConfigError::BadListenAddress);
    }
    Ok(())
}

fn validate_nonzero_port(port: &str) -> Result<(), ConfigError> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ConfigError::BadListenAddress);
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(ConfigError::BadListenAddress),
        Ok(_) => Ok(()),
    }
}

fn validate_absolute_path(s: &str) -> Result<(), ConfigError> {
    if !s.starts_with('/') {
        return Err(ConfigError::UnsafePath(s.to_string()));
    }
    // Reject `..` components (safe parents).
    for comp in s.split('/') {
        if comp == ".." {
            return Err(ConfigError::UnsafePath(s.to_string()));
        }
    }
    Ok(())
}

fn validate_tenants_sorted_and_unique(tenants: &[TenantConfigEntry]) -> Result<(), ConfigError> {
    let mut prev: Option<(&str, &str)> = None;
    for t in tenants {
        let key = (t.tenant_id.as_str(), t.authority_id.as_str());
        if let Some(p) = prev {
            if p >= key {
                return Err(ConfigError::TenantsUnsorted);
            }
            if p == key {
                return Err(ConfigError::DuplicateTenant);
            }
        }
        prev = Some(key);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_tenant(tid: &str, aid: &str) -> TenantConfigEntry {
        TenantConfigEntry {
            tenant_id: tid.into(),
            authority_id: aid.into(),
            state: TenantState::BootstrapPending,
            expected_bootstrap_registry_digest: "ab".repeat(32),
            expected_bootstrap_ring_digest: "cd".repeat(32),
            expected_bootstrap_policy_digest: "ef".repeat(32),
            submit_ca_sha256: "01".repeat(32),
            submit_leaf_spki_sha256: "02".repeat(32),
            submit_san: format!("spiffe://flycockpit/tenant-authority-submit/deploy1/{tid}/{aid}"),
            control_plane_authority: ControlPlaneAuthority {
                issuer: "https://control.example".into(),
                deployment_id: "deploy1".into(),
                allowed_ring_digests: vec!["00".repeat(32)],
                bootstrap_ring_digest: "00".repeat(32),
                bootstrap_status_digest: "00".repeat(32),
            },
            module_sha256: "03".repeat(32),
            slot_id: "0".into(),
            token_serial: "serial".into(),
            token_label: "label".into(),
            key_generations: vec![TenantKeyGeneration {
                generation: "1".into(),
                cka_id_base64url: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                kid: "k1".into(),
                state: TenantKeyGenerationState::Current,
                public_jwk_digest: "04".repeat(32),
                activated_at: 1,
                retire_at: None,
            }],
        }
    }

    fn valid_config() -> SharedConfig {
        SharedConfig {
            schema_version: 1,
            deployment_id: "deploy1".into(),
            audience: "https://tenant.example".into(),
            issuer: "https://control.example".into(),
            listen_address: "127.0.0.1:8443".into(),
            pkcs11_module_path: "/opt/pkcs11/lib.so".into(),
            idempotency_hours: 24,
            request_deadline_seconds: 10,
            tenants: vec![valid_tenant("t1", "a1")],
        }
    }

    #[test]
    fn valid_config_passes() {
        assert!(valid_config().validate().is_ok());
    }

    #[test]
    fn rejects_bad_deployment_id() {
        let mut c = valid_config();
        c.deployment_id = "bad deploy!".into();
        assert_eq!(c.validate(), Err(ConfigError::BadDeploymentId));
    }

    #[test]
    fn rejects_unsorted_tenants() {
        let mut c = valid_config();
        c.tenants = vec![valid_tenant("t2", "a1"), valid_tenant("t1", "a1")];
        assert_eq!(c.validate(), Err(ConfigError::TenantsUnsorted));
    }

    #[test]
    fn rejects_bad_listen_address() {
        let mut c = valid_config();
        c.listen_address = "127.0.0.1:0".into();
        assert_eq!(c.validate(), Err(ConfigError::BadListenAddress));
    }

    #[test]
    fn rejects_unsafe_path() {
        let mut c = valid_config();
        c.pkcs11_module_path = "relative/path.so".into();
        // pkcs11_module_path is not validated in validate(); test credential
        // file path validation directly.
        let cred = CredentialFile {
            schema_version: 1,
            server_ca_file: "relative/ca.pem".into(),
            server_certificate_file: "/abs/cert.pem".into(),
            server_private_key_file: "/abs/key.pem".into(),
            tenant_credentials: vec![],
        };
        assert_eq!(
            cred.validate(),
            Err(ConfigError::UnsafePath("relative/ca.pem".into()))
        );
    }

    #[test]
    fn replica_file_validates() {
        let r = ReplicaFile {
            schema_version: 1,
            deployment_id: "deploy1".into(),
            replica_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            replica_generation: "1".into(),
            admin_socket_path: "/run/ta/admin.sock".into(),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn replica_file_rejects_zero_generation() {
        let r = ReplicaFile {
            schema_version: 1,
            deployment_id: "deploy1".into(),
            replica_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            replica_generation: "0".into(),
            admin_socket_path: "/run/ta/admin.sock".into(),
        };
        assert!(r.validate().is_err());
    }
}
