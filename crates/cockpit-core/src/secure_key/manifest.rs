//! Namespace manifest stored as a native item (nonsecret metadata only).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::error::SecureKeyError;
use super::namespace::{Namespace, digest_hex};

/// Manifest payload: active/version/retired metadata + installation binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceManifest {
    pub installation_id: String,
    pub namespace: String,
    pub namespace_digest: String,
    pub active_version: Option<i64>,
    /// version -> key_digest
    pub versions: BTreeMap<String, String>,
    pub retired: Vec<i64>,
}

impl NamespaceManifest {
    pub fn new(installation_id: &str, namespace: &Namespace) -> Self {
        Self {
            installation_id: installation_id.to_owned(),
            namespace: namespace.as_str().to_owned(),
            namespace_digest: namespace.digest_hex(),
            active_version: None,
            versions: BTreeMap::new(),
            retired: Vec::new(),
        }
    }

    pub fn verify_binding(
        &self,
        installation_id: &str,
        namespace: &Namespace,
    ) -> Result<(), SecureKeyError> {
        if self.installation_id != installation_id {
            return Err(SecureKeyError::Corrupt(
                "manifest installation_id mismatch".into(),
            ));
        }
        if self.namespace != namespace.as_str() {
            return Err(SecureKeyError::Corrupt(
                "manifest namespace mismatch".into(),
            ));
        }
        if self.namespace_digest != namespace.digest_hex() {
            return Err(SecureKeyError::Corrupt(
                "manifest namespace_digest mismatch".into(),
            ));
        }
        Ok(())
    }

    pub fn set_version_digest(&mut self, version: i64, key_digest: &str) {
        self.versions
            .insert(version.to_string(), key_digest.to_owned());
    }

    pub fn advance_active(&mut self, version: i64, key_digest: &str) {
        self.set_version_digest(version, key_digest);
        self.active_version = Some(version);
    }

    pub fn mark_retired(&mut self, version: i64) {
        if !self.retired.contains(&version) {
            self.retired.push(version);
            self.retired.sort_unstable();
        }
        if self.active_version == Some(version) {
            self.active_version = None;
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, SecureKeyError> {
        serde_json::to_vec(self)
            .map_err(|e| SecureKeyError::Internal(format!("manifest serialize failed: {e}")))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecureKeyError> {
        serde_json::from_slice(bytes)
            .map_err(|e| SecureKeyError::Corrupt(format!("manifest parse failed: {e}")))
    }

    #[allow(dead_code)]
    pub fn content_digest(&self) -> Result<String, SecureKeyError> {
        Ok(digest_hex(&self.to_bytes()?))
    }
}
