//! Redacted daemon onboarding bootstrap contracts.
//!
//! These DTOs intentionally contain only opaque correlation identifiers and
//! non-secret display state.  In particular they never carry provider
//! configuration, OAuth material, credentials, paths, or a passphrase.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{HostCapabilitySnapshot, OwnerCapabilityToken};

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

/// Opaque correlation to a terminal daemon settlement that authorizes leaving
/// provider, model, or agent.  The dispatcher validates this against the
/// owning authority before the onboarding reducer may advance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingStageSettlement {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub stage_revision: u64,
    pub settlement_operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Sanitized digest of the exact provider mutation batch that must match
    /// the terminal `ProviderMutationCommitted` receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_intent_hash: Option<String>,
    /// Setup-wizard identity for model or agent settlement correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wizard_id: Option<String>,
    pub config_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyOnboardingTransition {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub expected_revision: u64,
    pub client_operation_id: String,
    pub transition: OnboardingTransitionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement: Option<OnboardingStageSettlement>,
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
        let value = Zeroizing::new(value);
        let confirmation = Zeroizing::new(confirmation);
        if value != confirmation {
            return Err("onboarding passphrase confirmation does not match");
        }
        if value.is_empty() {
            return Err("onboarding passphrase must not be empty");
        }
        Ok(Self(value))
    }

    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }

    fn from_confirmed_local_frame(value: Zeroizing<String>) -> Result<Self, &'static str> {
        if value.is_empty() {
            return Err("onboarding passphrase must not be empty");
        }
        Ok(Self(value))
    }
}

impl std::fmt::Debug for SensitiveOnboardingPassphrase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SensitiveOnboardingPassphrase([REDACTED])")
    }
}

/// Local secure-intent command.  It binds sensitive ingress to the current
/// durable attempt and revision without giving that secret a serde/JSON shape.
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

const SENSITIVE_ONBOARDING_INTENT_MAGIC: &[u8; 8] = b"COBSI001";
const SENSITIVE_ONBOARDING_RESPONSE_MAGIC: &[u8; 8] = b"COBSR001";
const MAX_SENSITIVE_ONBOARDING_OPERATION_ID_BYTES: usize = 128;
const MAX_SENSITIVE_ONBOARDING_CAPABILITY_BYTES: usize = 512;
const MAX_SENSITIVE_ONBOARDING_PASSPHRASE_BYTES: usize = 64 * 1024;

/// Decoded local-only secure-intent frame. The owner capability remains bound
/// to the authenticated same-owner OS peer that obtained it; possession of the
/// sibling socket alone never authorizes vault materialization.
pub struct SensitiveOnboardingIntentFrame {
    pub connection_id: Uuid,
    pub owner_capability: Option<OwnerCapabilityToken>,
    pub request: ApplyOnboardingSecureIntent,
}

impl std::fmt::Debug for SensitiveOnboardingIntentFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SensitiveOnboardingIntentFrame")
            .field("connection_id", &self.connection_id)
            .field(
                "owner_capability",
                &self.owner_capability.as_ref().map(|_| "[REDACTED]"),
            )
            .field("request", &self.request)
            .finish()
    }
}

/// Fixed, schema-bounded failures permitted while the ready redactor does not
/// yet exist. No dynamic error, path, environment value, or secret crosses
/// this preparation-time boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveOnboardingIntentError {
    Unauthorized,
    InvalidRequest,
    RevisionConflict,
    PlacementUnavailable,
    MaterializationFailed,
    ReadyConstructionFailed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SensitiveOnboardingIntentResponse {
    Applied(OnboardingTransitionResult),
    Rejected(SensitiveOnboardingIntentError),
}

/// Encode the Rust-only ingress without giving it a serde/JSON shape. The
/// returned allocation is zeroized, including the passphrase bytes, on drop.
pub fn encode_sensitive_onboarding_intent(
    frame: SensitiveOnboardingIntentFrame,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let SensitiveOnboardingIntentFrame {
        connection_id,
        owner_capability,
        request,
    } = frame;
    let ApplyOnboardingSecureIntent {
        run_id,
        attempt_id,
        expected_revision,
        client_operation_id,
        placement,
        passphrase,
    } = request;
    let capability = owner_capability
        .as_ref()
        .map(OwnerCapabilityToken::as_str)
        .unwrap_or_default()
        .as_bytes();
    let operation = client_operation_id.as_bytes();
    let passphrase = passphrase.map(SensitiveOnboardingPassphrase::into_zeroizing);
    let passphrase_bytes = passphrase
        .as_deref()
        .map_or(&[][..], |value| value.as_bytes());
    if operation.is_empty() || operation.len() > MAX_SENSITIVE_ONBOARDING_OPERATION_ID_BYTES {
        return Err("invalid onboarding client operation id");
    }
    if capability.len() > MAX_SENSITIVE_ONBOARDING_CAPABILITY_BYTES
        || passphrase_bytes.len() > MAX_SENSITIVE_ONBOARDING_PASSPHRASE_BYTES
    {
        return Err("sensitive onboarding frame exceeds its field limit");
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(
        8 + 16 * 3
            + 8
            + 1
            + 2
            + capability.len()
            + 2
            + operation.len()
            + 4
            + passphrase_bytes.len(),
    ));
    encoded.extend_from_slice(SENSITIVE_ONBOARDING_INTENT_MAGIC);
    encoded.extend_from_slice(connection_id.as_bytes());
    encoded.extend_from_slice(run_id.as_bytes());
    encoded.extend_from_slice(attempt_id.as_bytes());
    encoded.extend_from_slice(&expected_revision.to_be_bytes());
    encoded.push(match placement {
        OnboardingSecurePlacement::Automatic => 0,
        OnboardingSecurePlacement::Keyring => 1,
        OnboardingSecurePlacement::PassphraseFile => 2,
        OnboardingSecurePlacement::MachineBoundFile => 3,
    });
    push_u16_bytes(&mut encoded, capability)?;
    push_u16_bytes(&mut encoded, operation)?;
    encoded.extend_from_slice(
        &u32::try_from(passphrase_bytes.len())
            .map_err(|_| "sensitive onboarding passphrase is too long")?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(passphrase_bytes);
    Ok(encoded)
}

pub fn decode_sensitive_onboarding_intent(
    encoded: &[u8],
) -> Result<SensitiveOnboardingIntentFrame, &'static str> {
    let mut cursor = FrameCursor::new(encoded);
    if cursor.take(8)? != SENSITIVE_ONBOARDING_INTENT_MAGIC {
        return Err("invalid sensitive onboarding frame magic");
    }
    let connection_id = uuid_from_frame(cursor.take(16)?)?;
    let run_id = uuid_from_frame(cursor.take(16)?)?;
    let attempt_id = uuid_from_frame(cursor.take(16)?)?;
    let expected_revision = u64::from_be_bytes(
        cursor
            .take(8)?
            .try_into()
            .map_err(|_| "invalid onboarding revision")?,
    );
    let placement = match cursor.take(1)?[0] {
        0 => OnboardingSecurePlacement::Automatic,
        1 => OnboardingSecurePlacement::Keyring,
        2 => OnboardingSecurePlacement::PassphraseFile,
        3 => OnboardingSecurePlacement::MachineBoundFile,
        _ => return Err("invalid onboarding secure placement"),
    };
    let capability = cursor.take_u16_bytes(MAX_SENSITIVE_ONBOARDING_CAPABILITY_BYTES)?;
    let operation = cursor.take_u16_bytes(MAX_SENSITIVE_ONBOARDING_OPERATION_ID_BYTES)?;
    if operation.is_empty() {
        return Err("invalid onboarding client operation id");
    }
    let passphrase_len = usize::try_from(u32::from_be_bytes(
        cursor
            .take(4)?
            .try_into()
            .map_err(|_| "invalid onboarding passphrase length")?,
    ))
    .map_err(|_| "invalid onboarding passphrase length")?;
    if passphrase_len > MAX_SENSITIVE_ONBOARDING_PASSPHRASE_BYTES {
        return Err("sensitive onboarding passphrase is too long");
    }
    let passphrase = cursor.take(passphrase_len)?;
    if !cursor.is_empty() {
        return Err("sensitive onboarding frame has trailing bytes");
    }
    let passphrase = if passphrase.is_empty() {
        None
    } else {
        Some(SensitiveOnboardingPassphrase::from_confirmed_local_frame(
            zeroizing_utf8(passphrase, "onboarding passphrase is not UTF-8")?,
        )?)
    };
    Ok(SensitiveOnboardingIntentFrame {
        connection_id,
        owner_capability: if capability.is_empty() {
            None
        } else {
            Some(OwnerCapabilityToken::new(
                String::from_utf8(capability.to_vec())
                    .map_err(|_| "invalid onboarding owner capability")?,
            ))
        },
        request: ApplyOnboardingSecureIntent {
            run_id,
            attempt_id,
            expected_revision,
            client_operation_id: String::from_utf8(operation.to_vec())
                .map_err(|_| "onboarding operation id is not UTF-8")?,
            placement,
            passphrase,
        },
    })
}

fn zeroizing_utf8(value: &[u8], error: &'static str) -> Result<Zeroizing<String>, &'static str> {
    let mut bytes = Zeroizing::new(value.to_vec());
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(invalid) => {
            let mut bytes = invalid.into_bytes();
            bytes.zeroize();
            Err(error)
        }
    }
}

pub fn encode_sensitive_onboarding_response(
    response: &SensitiveOnboardingIntentResponse,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut encoded = Zeroizing::new(Vec::new());
    encoded.extend_from_slice(SENSITIVE_ONBOARDING_RESPONSE_MAGIC);
    match response {
        SensitiveOnboardingIntentResponse::Applied(result) => {
            encoded.push(0);
            let json =
                serde_json::to_vec(result).map_err(|_| "could not encode onboarding response")?;
            encoded.extend_from_slice(
                &u32::try_from(json.len())
                    .map_err(|_| "onboarding response is too large")?
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(&json);
        }
        SensitiveOnboardingIntentResponse::Rejected(error) => {
            encoded.push(match error {
                SensitiveOnboardingIntentError::Unauthorized => 1,
                SensitiveOnboardingIntentError::InvalidRequest => 2,
                SensitiveOnboardingIntentError::RevisionConflict => 3,
                SensitiveOnboardingIntentError::PlacementUnavailable => 4,
                SensitiveOnboardingIntentError::MaterializationFailed => 5,
                SensitiveOnboardingIntentError::ReadyConstructionFailed => 6,
            });
        }
    }
    Ok(encoded)
}

pub fn decode_sensitive_onboarding_response(
    encoded: &[u8],
) -> Result<SensitiveOnboardingIntentResponse, &'static str> {
    let mut cursor = FrameCursor::new(encoded);
    if cursor.take(8)? != SENSITIVE_ONBOARDING_RESPONSE_MAGIC {
        return Err("invalid sensitive onboarding response magic");
    }
    let status = cursor.take(1)?[0];
    let response = match status {
        0 => {
            let len = usize::try_from(u32::from_be_bytes(
                cursor
                    .take(4)?
                    .try_into()
                    .map_err(|_| "invalid onboarding response length")?,
            ))
            .map_err(|_| "invalid onboarding response length")?;
            let result = serde_json::from_slice(cursor.take(len)?)
                .map_err(|_| "invalid onboarding response payload")?;
            SensitiveOnboardingIntentResponse::Applied(result)
        }
        1 => SensitiveOnboardingIntentResponse::Rejected(
            SensitiveOnboardingIntentError::Unauthorized,
        ),
        2 => SensitiveOnboardingIntentResponse::Rejected(
            SensitiveOnboardingIntentError::InvalidRequest,
        ),
        3 => SensitiveOnboardingIntentResponse::Rejected(
            SensitiveOnboardingIntentError::RevisionConflict,
        ),
        4 => SensitiveOnboardingIntentResponse::Rejected(
            SensitiveOnboardingIntentError::PlacementUnavailable,
        ),
        5 => SensitiveOnboardingIntentResponse::Rejected(
            SensitiveOnboardingIntentError::MaterializationFailed,
        ),
        6 => SensitiveOnboardingIntentResponse::Rejected(
            SensitiveOnboardingIntentError::ReadyConstructionFailed,
        ),
        _ => return Err("invalid sensitive onboarding response status"),
    };
    if !cursor.is_empty() {
        return Err("sensitive onboarding response has trailing bytes");
    }
    Ok(response)
}

fn push_u16_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), &'static str> {
    target.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(|_| "sensitive onboarding field is too long")?
            .to_be_bytes(),
    );
    target.extend_from_slice(value);
    Ok(())
}

fn uuid_from_frame(value: &[u8]) -> Result<Uuid, &'static str> {
    Uuid::from_slice(value).map_err(|_| "invalid onboarding UUID")
}

struct FrameCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> FrameCursor<'a> {
    fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        if self.remaining.len() < len {
            return Err("truncated sensitive onboarding frame");
        }
        let (value, remaining) = self.remaining.split_at(len);
        self.remaining = remaining;
        Ok(value)
    }

    fn take_u16_bytes(&mut self, max: usize) -> Result<&'a [u8], &'static str> {
        let len = usize::from(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| "invalid sensitive onboarding field length")?,
        ));
        if len > max {
            return Err("sensitive onboarding field exceeds its limit");
        }
        self.take(len)
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
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
            settlement: None,
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

    #[test]
    fn sensitive_intent_binary_frame_round_trips_and_debug_redacts() {
        let canary = "frame-passphrase-canary";
        let frame = SensitiveOnboardingIntentFrame {
            connection_id: Uuid::from_u128(7),
            owner_capability: Some(OwnerCapabilityToken::new("owner-token")),
            request: ApplyOnboardingSecureIntent {
                run_id: Uuid::from_u128(8),
                attempt_id: Uuid::from_u128(9),
                expected_revision: 4,
                client_operation_id: "secure-intent".into(),
                placement: OnboardingSecurePlacement::PassphraseFile,
                passphrase: Some(
                    SensitiveOnboardingPassphrase::confirmed(canary.into(), canary.into()).unwrap(),
                ),
            },
        };
        let encoded = encode_sensitive_onboarding_intent(frame).unwrap();
        assert!(
            encoded
                .windows(canary.len())
                .any(|window| window == canary.as_bytes())
        );
        let decoded = decode_sensitive_onboarding_intent(&encoded).unwrap();
        let debug = format!("{decoded:?}");
        assert!(!debug.contains(canary));
        assert_eq!(decoded.connection_id, Uuid::from_u128(7));
        assert_eq!(decoded.request.expected_revision, 4);
        assert_eq!(
            decoded.request.placement,
            OnboardingSecurePlacement::PassphraseFile
        );
    }
}
