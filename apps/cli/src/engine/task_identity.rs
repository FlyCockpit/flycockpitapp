use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskProviderIdentity {
    pub provider_call_id: String,
    pub provider_call_id_source: &'static str,
}

impl TaskProviderIdentity {
    pub fn for_task_call(cockpit_task_call_id: &str, provider_call_id: Option<&str>) -> Self {
        match provider_call_id.filter(|value| !value.is_empty()) {
            Some(call_id) => Self {
                provider_call_id: call_id.to_string(),
                provider_call_id_source: "provider",
            },
            None => Self {
                provider_call_id: cockpit_task_call_id.to_string(),
                provider_call_id_source: "synthetic_from_cockpit_call_id",
            },
        }
    }

    pub fn event_identity_json(&self, cockpit_task_call_id: &str) -> Value {
        serde_json::json!({
            "cockpit_call_id": cockpit_task_call_id,
            "provider_call_id": self.provider_call_id,
            "provider_call_id_source": self.provider_call_id_source,
            "wire_api": "responses",
        })
    }
}
