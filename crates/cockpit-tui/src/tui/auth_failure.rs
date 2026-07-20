use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

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

/// Secret-safe, process-local fingerprint of one provider's auth *shape*,
/// computed from the daemon's redacted provider view (`tui-config-single-source`).
///
/// Credential material never reaches the TUI, so this hashes only the
/// non-secret projection the daemon resolves: url, header names, the
/// `credential_configured` flag, and the declared auth scheme. It shifts when
/// the provider's auth *structure* changes (url/header set/scheme/whether a
/// credential is configured); it deliberately cannot observe a pure
/// secret-value edit, since the daemon redacts values before they cross the
/// wire.
pub fn provider_auth_fingerprint(
    view: &cockpit_core::daemon::proto::ProviderConfigView,
    provider_id: &str,
) -> u64 {
    let entry = view.providers.get(provider_id);
    let auth_inputs = entry.map(|entry| {
        let header_names: Vec<&str> = entry
            .headers
            .iter()
            .map(|header| header.name.as_str())
            .collect();
        serde_json::json!({
            "url": entry.entry.url,
            "header_names": header_names,
            "credential_configured": entry.credential_configured,
            "auth": entry.entry.auth,
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
