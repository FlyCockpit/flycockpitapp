//! Safe doctor/audit/error metadata for containment.
//!
//! Must never contain command, environment, path payload, output, PID oracle,
//! container output, endpoint credential, or secret.

use super::types::{ContainmentError, SafeContainmentMetadata};

/// Redact any accidental sensitive material from free-form reasons.
pub fn sanitize_reason(reason: &str) -> String {
    let lowered = reason.to_ascii_lowercase();
    for needle in [
        "password",
        "secret",
        "token",
        "authorization",
        "api_key",
        "apikey",
        "bearer ",
        "sk-",
        "-----begin",
    ] {
        if lowered.contains(needle) {
            return "redacted_reason".into();
        }
    }
    // Truncate long reasons.
    if reason.len() > 128 {
        format!("{}…", &reason[..128])
    } else {
        reason.to_string()
    }
}

/// Doctor-facing view.
pub fn doctor_lines(meta: &SafeContainmentMetadata) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "descendant containment: {} ({})",
        meta.guarantee.as_str(),
        meta.adapter_name
    ));
    lines.push(format!("platform: {}", meta.platform_kind.as_str()));
    if let Some(reason) = &meta.capability_reason {
        lines.push(format!("reason: {}", sanitize_reason(reason)));
    }
    if let Some(boundary) = &meta.management_boundary {
        lines.push(format!("management boundary: {boundary}"));
    }
    lines
}

/// Error payload safe for audit logs.
pub fn error_audit_fields(err: &ContainmentError) -> serde_json::Value {
    match err {
        ContainmentError::DescendantContainmentUnavailable { reason } => serde_json::json!({
            "code": "descendant_containment_unavailable",
            "reason": sanitize_reason(reason),
        }),
        ContainmentError::SessionDeleting => serde_json::json!({
            "code": "session_deleting",
        }),
        ContainmentError::ShutdownIntakeClosed => serde_json::json!({
            "code": "shutdown_intake_closed",
        }),
        ContainmentError::DeletionBlocked { blockers } => serde_json::json!({
            "code": "deletion_blocked",
            "blocker_count": blockers.len(),
        }),
        ContainmentError::ShutdownNotClean { blockers } => serde_json::json!({
            "code": "shutdown_not_clean",
            "blocker_count": blockers.len(),
        }),
        ContainmentError::QueueSaturated => serde_json::json!({
            "code": "queue_saturated",
        }),
        ContainmentError::GenerationMismatch { expected, got } => serde_json::json!({
            "code": "generation_mismatch",
            "expected": expected,
            "got": got,
        }),
        ContainmentError::NotFound(id) => serde_json::json!({
            "code": "not_found",
            "containment_id": id.to_string(),
        }),
        other => serde_json::json!({
            "code": "internal",
            "reason": sanitize_reason(&other.to_string()),
        }),
    }
}

/// Assert metadata JSON does not contain forbidden keys/values.
#[allow(dead_code)]
pub fn metadata_is_safe(value: &serde_json::Value) -> bool {
    let s = value.to_string().to_ascii_lowercase();
    let forbidden = [
        "command",
        "argv",
        "environment",
        "environ",
        "password",
        "secret",
        "\"pid\"",
        "stdout",
        "stderr",
        "endpoint_token",
        "api_key",
    ];
    !forbidden.iter().any(|f| s.contains(f))
}

#[cfg(test)]
mod containment_safe_observability {
    use super::*;
    use crate::process_containment::types::{ContainmentGuarantee, PlatformKind};

    #[test]
    fn doctor_and_error_metadata_have_no_secrets_or_pid_oracle() {
        let meta = SafeContainmentMetadata {
            platform_kind: PlatformKind::LinuxCgroup,
            guarantee: ContainmentGuarantee::Unsupported,
            capability_reason: Some("management_boundary_unavailable".into()),
            adapter_name: "linux_cgroup_namespace_guard".into(),
            management_boundary: None,
        };
        let lines = doctor_lines(&meta);
        let joined = lines.join("\n").to_ascii_lowercase();
        assert!(!joined.contains("password"));
        assert!(!joined.contains("pid="));
        assert!(!joined.contains("argv"));

        let err = ContainmentError::DescendantContainmentUnavailable {
            reason: "password=supersecret".into(),
        };
        let fields = error_audit_fields(&err);
        assert_eq!(fields["reason"], "redacted_reason");
        assert!(metadata_is_safe(&fields));

        let meta_json = serde_json::to_value(&meta).unwrap();
        assert!(metadata_is_safe(&meta_json));
    }
}
