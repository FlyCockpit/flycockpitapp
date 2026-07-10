use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::providers::{
    MODEL_SYSTEM_PROMPT_MAX_BYTES, ProvidersConfig, model_system_prompt_too_large,
    normalize_model_system_prompt,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelSystemPromptSnapshot {
    prompts: BTreeMap<String, BTreeMap<String, String>>,
}

impl ModelSystemPromptSnapshot {
    pub fn empty() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.prompts.is_empty()
    }

    pub fn get(&self, provider: &str, model: &str) -> Option<&str> {
        self.prompts
            .get(provider)
            .and_then(|models| models.get(model))
            .map(String::as_str)
    }

    pub fn insert(
        &mut self,
        provider: impl Into<String>,
        model: impl Into<String>,
        prompt: String,
    ) {
        self.prompts
            .entry(provider.into())
            .or_default()
            .insert(model.into(), prompt);
    }

    pub fn capture(config: &ProvidersConfig) -> Self {
        let mut snapshot = Self::empty();
        for (provider_id, provider) in &config.providers {
            for model in &provider.models {
                let Some(prompt) = model
                    .system_prompt
                    .as_deref()
                    .and_then(normalize_model_system_prompt)
                else {
                    continue;
                };
                if model_system_prompt_too_large(prompt) {
                    tracing::warn!(
                        provider = provider_id.as_str(),
                        model = model.id.as_str(),
                        limit_bytes = MODEL_SYSTEM_PROMPT_MAX_BYTES,
                        "ignoring oversized model system prompt"
                    );
                    continue;
                }
                snapshot.insert(provider_id.clone(), model.id.clone(), prompt.to_string());
            }
        }
        snapshot
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn from_json_str(raw: &str) -> Self {
        if raw.trim().is_empty() {
            return Self::empty();
        }
        match serde_json::from_str::<Self>(raw) {
            Ok(mut snapshot) => {
                snapshot.prune_invalid();
                snapshot
            }
            Err(error) => {
                tracing::warn!(error = %error, "failed to decode model system prompt snapshot");
                Self::empty()
            }
        }
    }

    fn prune_invalid(&mut self) {
        self.prompts.retain(|_, models| {
            models.retain(|_, prompt| {
                normalize_model_system_prompt(prompt).is_some()
                    && !model_system_prompt_too_large(prompt)
            });
            !models.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{ModelEntry, ProviderEntry};

    #[test]
    fn snapshot_captures_nonempty_prompts_by_provider_and_model() {
        let mut config = ProvidersConfig::default();
        config.providers.insert(
            "p".to_string(),
            ProviderEntry {
                models: vec![
                    ModelEntry {
                        id: "m1".to_string(),
                        system_prompt: Some("alpha".to_string()),
                        ..ModelEntry::default()
                    },
                    ModelEntry {
                        id: "m2".to_string(),
                        system_prompt: Some("   ".to_string()),
                        ..ModelEntry::default()
                    },
                ],
                ..ProviderEntry::default()
            },
        );

        let snapshot = ModelSystemPromptSnapshot::capture(&config);

        assert_eq!(snapshot.get("p", "m1"), Some("alpha"));
        assert_eq!(snapshot.get("p", "m2"), None);
        assert_eq!(snapshot.get("other", "m1"), None);
    }

    #[test]
    fn malformed_snapshot_recovers_to_empty() {
        let snapshot = ModelSystemPromptSnapshot::from_json_str("{not json");
        assert!(snapshot.is_empty());
    }
}
