//! Provider subscription usage probes for `/usage` and
//! `cockpit provider usage`.
//!
//! This reports vendor plan/quota data when a provider exposes it. It is
//! distinct from local token/cost stats and from inference response
//! rate-limit headers, which can become a separate probe family later.

pub mod probes;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq)]
pub struct UsageWindow {
    pub label: String,
    pub used_percent: Option<f64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UsageAvailability {
    Fetched {
        source: &'static str,
        plan: Option<String>,
        windows: Vec<UsageWindow>,
        details: Vec<String>,
    },
    Unsupported {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
        hint_url: Option<String>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderUsageSnapshot {
    pub provider_id: String,
    pub display_name: String,
    pub fetched_at: DateTime<Utc>,
    pub availability: UsageAvailability,
}

pub fn render_usage_lines(snapshot: &ProviderUsageSnapshot) -> Vec<String> {
    let mut lines = Vec::new();
    match &snapshot.availability {
        UsageAvailability::Fetched {
            plan,
            windows,
            details,
            ..
        } => {
            let mut header = format!("{} ({})", snapshot.display_name, snapshot.provider_id);
            if let Some(plan) = plan.as_deref().filter(|s| !s.trim().is_empty()) {
                header.push_str(&format!(" — plan: {plan}"));
            }
            lines.push(header);
            if windows.is_empty() && details.is_empty() {
                lines.push("  No usage windows returned.".to_string());
            }
            for window in windows {
                lines.push(render_window_line(window));
            }
            for detail in details {
                lines.push(format!("  {detail}"));
            }
        }
        UsageAvailability::Unsupported { reason } => {
            lines.push(format!(
                "{} ({}) — unsupported: {reason}",
                snapshot.display_name, snapshot.provider_id
            ));
        }
        UsageAvailability::Unavailable { reason, hint_url } => {
            let mut line = format!(
                "{} ({}) — unavailable: {reason}",
                snapshot.display_name, snapshot.provider_id
            );
            if let Some(url) = hint_url.as_deref() {
                line.push_str(&format!(" {url}"));
            }
            lines.push(line);
        }
        UsageAvailability::Error { message } => {
            lines.push(format!(
                "{} ({}) — error: {message}",
                snapshot.display_name, snapshot.provider_id
            ));
        }
    }
    lines
}

fn render_window_line(window: &UsageWindow) -> String {
    let mut line = format!("  {}: ", window.label);
    if let Some(used) = window.used_percent {
        let used = used.clamp(0.0, 100.0);
        let remaining = (100.0 - used).max(0.0);
        line.push_str(&format!(
            "{:.0}% remaining ({:.0}% used)",
            remaining.round(),
            used.round()
        ));
    } else {
        line.push_str("usage not reported");
    }
    if let Some(reset) = window.reset_at {
        line.push_str(&format!("; resets {}", reset.to_rfc3339()));
    }
    if let Some(detail) = window.detail.as_deref().filter(|s| !s.trim().is_empty()) {
        line.push_str(&format!(" — {detail}"));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_fetched_snapshot_lines() {
        let reset = "2026-06-12T00:00:00Z".parse().unwrap();
        let snap = ProviderUsageSnapshot {
            provider_id: "codex-oauth".to_string(),
            display_name: "Codex".to_string(),
            fetched_at: Utc::now(),
            availability: UsageAvailability::Fetched {
                source: "oauth_usage_api",
                plan: Some("plus".to_string()),
                windows: vec![UsageWindow {
                    label: "Weekly".to_string(),
                    used_percent: Some(25.2),
                    reset_at: Some(reset),
                    detail: Some("80 messages".to_string()),
                }],
                details: vec!["credits: 10".to_string()],
            },
        };
        let lines = render_usage_lines(&snap);
        assert_eq!(lines[0], "Codex (codex-oauth) — plan: plus");
        assert!(lines[1].contains("75% remaining (25% used)"));
        assert!(lines[1].contains("2026-06-12T00:00:00+00:00"));
        assert_eq!(lines[2], "  credits: 10");
    }
}
