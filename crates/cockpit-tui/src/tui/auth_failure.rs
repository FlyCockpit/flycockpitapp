use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::Path;

use cockpit_core::daemon::proto::AuthFailureKind;

pub type AuthFailureAnnotations = HashMap<(String, String), AuthFailureRecord>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFailureRecord {
    pub kind: AuthFailureKind,
    pub failed_at_epoch_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFailureNotice {
    pub provider: String,
    pub model: String,
    pub kind: AuthFailureKind,
}

pub fn failure_label(kind: &AuthFailureKind) -> String {
    match kind {
        AuthFailureKind::CredentialsRejected { status } => status.to_string(),
        AuthFailureKind::MissingEntitlement { feature } => format!("missing {feature}"),
        AuthFailureKind::OAuthExpired { .. } => "OAuth expired".to_string(),
        AuthFailureKind::ProviderNotConfigured => "provider not configured".to_string(),
    }
}

pub fn relative_age(failed_at_epoch_secs: i64, now_epoch_secs: i64) -> String {
    let elapsed = now_epoch_secs.saturating_sub(failed_at_epoch_secs).max(0);
    match elapsed {
        0..=59 => "just now".to_string(),
        60..=3_599 => format!("{}m ago", elapsed / 60),
        3_600..=86_399 => format!("{}h ago", elapsed / 3_600),
        _ => format!("{}d ago", elapsed / 86_400),
    }
}

pub fn annotation_suffix(record: &AuthFailureRecord, now_epoch_secs: i64) -> String {
    format!(
        "failed {} · {}",
        failure_label(&record.kind),
        relative_age(record.failed_at_epoch_secs, now_epoch_secs)
    )
}

pub fn notice_text(notice: &AuthFailureNotice, mouse: bool) -> String {
    let failure = format!(
        "⚠ {}/{} failed {}.",
        notice.provider,
        notice.model,
        failure_label(&notice.kind)
    );
    if mouse {
        format!("[switch model] [fix provider] {failure}")
    } else {
        format!("{failure} switch model (alt+m) · fix provider (alt+p)")
    }
}

/// Secret-safe, process-local fingerprint of the auth inputs for one provider.
/// Only the hash is retained; credential contents never enter TUI state.
pub fn provider_auth_fingerprint(cwd: &Path, provider_id: &str) -> u64 {
    let config = cockpit_core::secret_ref::load_effective(cwd);
    let entry = config.providers.get(provider_id);
    let credential_ref = entry
        .and_then(|entry| entry.credential_ref.as_deref())
        .unwrap_or(provider_id);
    let credential = cockpit_core::credentials::default_path()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.get(credential_ref).cloned());
    let auth_inputs = entry.map(|entry| {
        serde_json::json!({
            "url": entry.url,
            "headers": entry.headers,
            "credential_ref": entry.credential_ref,
            "auth": entry.auth,
            "credential": credential,
        })
    });
    let encoded = serde_json::to_vec(&auth_inputs).unwrap_or_default();
    let mut hasher = DefaultHasher::new();
    encoded.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_clock_formats_relative_failure_age() {
        let record = AuthFailureRecord {
            kind: AuthFailureKind::CredentialsRejected { status: 403 },
            failed_at_epoch_secs: 10_000,
        };
        assert_eq!(annotation_suffix(&record, 17_200), "failed 403 · 2h ago");
    }
}
