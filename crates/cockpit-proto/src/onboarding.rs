//! Redacted daemon onboarding bootstrap contracts.
//!
//! These DTOs intentionally contain only opaque correlation identifiers and
//! non-secret display state.  In particular they never carry provider
//! configuration, OAuth material, credentials, paths, or a passphrase.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::HostCapabilitySnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingStage {
    Welcome,
    Profile,
    SecureStore,
    Provider,
    Model,
    Agent,
    Lifetime,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingBootstrapState {
    AwaitingChoice,
    AwaitingPassphrase,
    Materializing,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingSecurePlacement {
    Automatic,
    Keyring,
    PassphraseFile,
    MachineBoundFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingReceiptStatus {
    Pending,
    Committed,
    Rejected,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingTransitionReceipt {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub consumed_revision: u64,
    pub receipt_id: Uuid,
    pub status: OnboardingReceiptStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingBootstrapSnapshot {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub revision: u64,
    pub stage: OnboardingStage,
    pub bootstrap_state: OnboardingBootstrapState,
    pub limited_mode: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_selection: Option<String>,
    pub host_capabilities: HostCapabilitySnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_receipt: Option<OnboardingTransitionReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginOrReopenOnboarding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
    pub client_operation_id: String,
    pub reentry: bool,
}

/// A redacted ordinary onboarding transition.  Provider/OAuth/validation and
/// installation effects are settled by their own daemon authorities; this
/// command records only the stage decision after the exact external receipt
/// has been correlated by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingTransitionKind {
    Advance,
    DeferProvider,
    Back,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyOnboardingTransition {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub expected_revision: u64,
    pub client_operation_id: String,
    pub transition: OnboardingTransitionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingBootstrapEvent {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub revision: u64,
    pub state: OnboardingBootstrapState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingTransitionResult {
    pub snapshot: OnboardingBootstrapSnapshot,
    pub receipt: OnboardingTransitionReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingReceiptQuery {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub client_operation_id: String,
}

/// Redacted metadata sent after local peer authentication while normal daemon
/// services remain locked behind first-run vault materialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedBootstrapHello {
    pub protocol_version: u32,
    pub bootstrap_available: bool,
    pub host_capabilities: HostCapabilitySnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<OnboardingBootstrapSnapshot>,
}

/// One-shot local ingress.  This is deliberately not serializable, cloneable,
/// or printable: any socket implementation must use the existing sensitive
/// local boundary rather than accidentally adding a JSON representation.
pub struct SensitiveOnboardingPassphrase(Zeroizing<String>);

impl SensitiveOnboardingPassphrase {
    /// Construct the one-shot ingress only after the caller has collected a
    /// matching confirmation.  Neither input is retained on mismatch.
    pub fn confirmed(value: String, confirmation: String) -> Result<Self, &'static str> {
        if value != confirmation {
            return Err("onboarding passphrase confirmation does not match");
        }
        if value.is_empty() {
            return Err("onboarding passphrase must not be empty");
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl std::fmt::Debug for SensitiveOnboardingPassphrase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SensitiveOnboardingPassphrase([REDACTED])")
    }
}

/// Local secure-intent command.  It binds sensitive ingress to the current
/// durable attempt and revision without giving that secret a wire shape.
pub struct ApplyOnboardingSecureIntent {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub expected_revision: u64,
    pub client_operation_id: String,
    pub placement: OnboardingSecurePlacement,
    pub passphrase: Option<SensitiveOnboardingPassphrase>,
}

impl std::fmt::Debug for ApplyOnboardingSecureIntent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApplyOnboardingSecureIntent")
            .field("run_id", &self.run_id)
            .field("attempt_id", &self.attempt_id)
            .field("expected_revision", &self.expected_revision)
            .field("client_operation_id", &self.client_operation_id)
            .field("placement", &self.placement)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_passphrase_never_has_a_json_or_debug_representation() {
        let value = SensitiveOnboardingPassphrase::confirmed(
            "onboarding-canary".into(),
            "onboarding-canary".into(),
        )
        .unwrap();
        assert!(!format!("{value:?}").contains("onboarding-canary"));
    }

    #[test]
    fn passphrase_confirmation_is_required_before_sensitive_ingress_exists() {
        let error = SensitiveOnboardingPassphrase::confirmed("first".into(), "second".into())
            .expect_err("mismatched confirmation must not create sensitive ingress");
        assert_eq!(error, "onboarding passphrase confirmation does not match");
    }

    #[test]
    fn bootstrap_projection_has_no_secret_bearing_field_names() {
        let encoded = serde_json::to_string(&ApplyOnboardingTransition {
            run_id: Uuid::nil(),
            attempt_id: Uuid::nil(),
            expected_revision: 0,
            client_operation_id: "operation".into(),
            transition: OnboardingTransitionKind::DeferProvider,
        })
        .unwrap();
        for forbidden in [
            "passphrase",
            "credential",
            "oauth",
            "provider_config",
            "path",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "projection leaked {forbidden}"
            );
        }
    }
}
