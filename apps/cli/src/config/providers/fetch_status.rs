use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProviderModelFetchDisplayState {
    Live,
    Fallback,
    Preserved,
    Failed,
    AuthFailed,
    Unsupported,
}

impl ProviderModelFetchDisplayState {
    pub const ALL: [Self; 6] = [
        Self::Live,
        Self::Fallback,
        Self::Preserved,
        Self::Failed,
        Self::AuthFailed,
        Self::Unsupported,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Live => "Live",
            Self::Fallback => "Fallback",
            Self::Preserved => "Preserved",
            Self::Failed => "Failed",
            Self::AuthFailed => "AuthFailed",
            Self::Unsupported => "Unsupported",
        }
    }
}

pub fn provider_model_fetch_display_state(entry: &ProviderEntry) -> ProviderModelFetchDisplayState {
    match entry.last_model_fetch.as_ref().map(|status| status.status) {
        Some(ModelFetchStatusKind::Live) => ProviderModelFetchDisplayState::Live,
        Some(ModelFetchStatusKind::Fallback) => ProviderModelFetchDisplayState::Fallback,
        Some(ModelFetchStatusKind::FailedKeptExisting) if entry.models.is_empty() => {
            ProviderModelFetchDisplayState::Failed
        }
        Some(ModelFetchStatusKind::FailedKeptExisting) => ProviderModelFetchDisplayState::Preserved,
        Some(ModelFetchStatusKind::AuthFailed) => ProviderModelFetchDisplayState::AuthFailed,
        Some(ModelFetchStatusKind::Unsupported) => ProviderModelFetchDisplayState::Unsupported,
        None if matches!(entry.model_catalog, ProviderModelCatalog::CodexFallback) => {
            ProviderModelFetchDisplayState::Fallback
        }
        None => ProviderModelFetchDisplayState::Live,
    }
}

pub fn model_fetch_reason_display(reason: Option<&str>) -> String {
    let Some(reason) = reason else {
        return "—".to_string();
    };
    let reason = redact_model_fetch_reason(reason);
    if reason.trim().is_empty() {
        "—".to_string()
    } else {
        reason
    }
}

pub fn provider_model_fetch_reason_display(entry: &ProviderEntry) -> String {
    model_fetch_reason_display(
        entry
            .last_model_fetch
            .as_ref()
            .and_then(|status| status.reason.as_deref()),
    )
}

pub fn format_model_fetch_age(fetched_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    let Some(fetched_at) = fetched_at else {
        return "never".to_string();
    };
    let delta = now.signed_duration_since(fetched_at);
    if delta.num_seconds() < 60 {
        return "just now".to_string();
    }
    if delta.num_minutes() < 60 {
        let n = delta.num_minutes();
        return format!("{n} minute{} ago", if n == 1 { "" } else { "s" });
    }
    if delta.num_hours() < 24 {
        let n = delta.num_hours();
        return format!("{n} hour{} ago", if n == 1 { "" } else { "s" });
    }
    if delta.num_hours() < 48 {
        return "yesterday".to_string();
    }
    let n = delta.num_days();
    format!("{n} days ago")
}
