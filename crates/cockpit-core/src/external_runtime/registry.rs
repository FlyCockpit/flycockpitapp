//! Feature-owned registration of external runtime descriptors.
//!
//! The registry is extensible by stable string IDs. Later adapter prompts
//! call [`ExternalRuntimeRegistry::register`] without editing a closed enum.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::schema::{ExternalRuntimeDescriptor, ExternalRuntimeId, ProbePolicy, SchemaError};

fn validate_descriptor_for_registry(
    descriptor: &ExternalRuntimeDescriptor,
) -> Result<(), RegistryError> {
    if let ProbePolicy::TrustedCatalog(policy) = &descriptor.probe_policy
        && !policy.is_executable()
    {
        return Err(RegistryError::NonExecutableTrustedCatalog(
            descriptor.id.clone(),
        ));
    }
    Ok(())
}

/// In-process catalog of descriptors. Not persisted.
#[derive(Debug, Default)]
pub struct ExternalRuntimeRegistry {
    inner: Mutex<BTreeMap<String, ExternalRuntimeDescriptor>>,
}

impl ExternalRuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a descriptor. Returns an error on duplicate ID.
    ///
    /// Trusted-catalog policies must be catalog-minted ([`ProbePolicy::trusted_catalog`]);
    /// deserialized non-executable trusted policies are rejected so user config
    /// cannot smuggle probe argv through registration.
    pub fn register(&self, descriptor: ExternalRuntimeDescriptor) -> Result<(), RegistryError> {
        validate_descriptor_for_registry(&descriptor)?;
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let id = descriptor.id.as_str().to_string();
        if inner.contains_key(&id) {
            return Err(RegistryError::DuplicateId(descriptor.id));
        }
        inner.insert(id, descriptor);
        Ok(())
    }

    /// Register or replace (used by tests and hot re-registration of configured commands).
    pub fn upsert(&self, descriptor: ExternalRuntimeDescriptor) -> Result<(), RegistryError> {
        validate_descriptor_for_registry(&descriptor)?;
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.insert(descriptor.id.as_str().to_string(), descriptor);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<ExternalRuntimeDescriptor> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .cloned()
    }

    pub fn descriptors(&self) -> Vec<ExternalRuntimeDescriptor> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect()
    }

    pub fn ids(&self) -> Vec<ExternalRuntimeId> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .map(|k| ExternalRuntimeId::new(k.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("duplicate external runtime id: {0}")]
    DuplicateId(ExternalRuntimeId),
    #[error(
        "trusted catalog policy for {0} is not catalog-minted (refusing deserialized/user-supplied probe argv)"
    )]
    NonExecutableTrustedCatalog(ExternalRuntimeId),
    #[error(transparent)]
    Schema(#[from] SchemaError),
}

/// Process-global registry used by later adapter prompts.
pub fn global_registry() -> Arc<ExternalRuntimeRegistry> {
    static REGISTRY: std::sync::OnceLock<Arc<ExternalRuntimeRegistry>> = std::sync::OnceLock::new();
    REGISTRY
        .get_or_init(|| Arc::new(ExternalRuntimeRegistry::new()))
        .clone()
}
