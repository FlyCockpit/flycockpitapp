//! Shared terse correction hints for validation failures.
//!
//! These are model-facing one-liners. They carry field names and corrected
//! shapes, not argument values. They remain raw until the model dispatch
//! boundary applies the dispatching model's effective redaction table.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationCorrection {
    message: String,
}

impl ValidationCorrection {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn write_requires_readlock(path: &std::path::Path, tool_name: &str) -> Self {
        Self::new(format!(
            "cannot write existing file `{}`: readlock it first, then retry {tool_name}",
            path.display()
        ))
    }

    pub fn harness_model_is_provider_ref(
        model: &str,
        harness_name: &str,
        provider_id: &str,
    ) -> Self {
        Self::new(format!(
            "model `{model}` looks like provider `{provider_id}`, but \
             harness_invoke expects a `{harness_name}` harness model; use provider settings \
             or `cockpit fetch-models {provider_id}` for provider catalogs"
        ))
    }

    pub fn model_message(&self) -> String {
        self.message.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_message_remains_raw_until_dispatch() {
        const SECRET: &str = "sk-validation-secret-1234567890";
        let correction =
            ValidationCorrection::harness_model_is_provider_ref(SECRET, "claude", "openai");

        let msg = correction.model_message();
        assert!(msg.contains(SECRET), "{msg}");
    }
}
