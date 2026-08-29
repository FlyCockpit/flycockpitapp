//! Canonical outer request framing for durable remote-operation identity.

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::send_user_message_v2::MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES;

pub const FCOR_MAGIC: [u8; 4] = *b"FCOR";
pub const FCOR_SCHEMA_VERSION: u8 = 1;
pub const MAX_FCOR_V1_BYTES: u64 = u32::MAX as u64;
pub const FCM2_MAGIC: [u8; 4] = *b"FCM2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalParamErrorCode {
    NonNfc,
    Nul,
    InvalidUnicodeScalar,
    DuplicateNfcKey,
}

impl CanonicalParamErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NonNfc => "non_nfc",
            Self::Nul => "nul",
            Self::InvalidUnicodeScalar => "invalid_unicode_scalar",
            Self::DuplicateNfcKey => "duplicate_nfc_key",
        }
    }
}

pub fn canonical_param_error_code(error: &anyhow::Error) -> Option<CanonicalParamErrorCode> {
    match error.to_string().as_str() {
        "canonical string is not NFC" => Some(CanonicalParamErrorCode::NonNfc),
        "canonical string contains NUL" | "canonical map key contains NUL" => {
            Some(CanonicalParamErrorCode::Nul)
        }
        "duplicate NFC map key" => Some(CanonicalParamErrorCode::DuplicateNfcKey),
        "invalid Unicode scalar input" => Some(CanonicalParamErrorCode::InvalidUnicodeScalar),
        _ => None,
    }
}

pub fn validate_utf16_canonical_boundary(units: &[u16]) -> Result<String> {
    String::from_utf16(units).map_err(|_| anyhow::anyhow!("invalid Unicode scalar input"))
}

/// Foundation-owned semantic validation seam for an opaque canonical codec.
/// The ledger never parses or re-encodes the returned bytes.
pub trait OpaqueCanonicalParamsDecoder {
    fn owner(&self) -> &'static str;
    fn validate(&self, bytes: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpaqueCanonicalParamsRegistrationV1 {
    pub request_kind: &'static str,
    pub magic: [u8; 4],
    pub maximum_bytes: usize,
    pub owner: &'static str,
}

pub const SEND_USER_MESSAGE_V2_REGISTRATION: OpaqueCanonicalParamsRegistrationV1 =
    OpaqueCanonicalParamsRegistrationV1 {
        request_kind: "send_user_message",
        magic: FCM2_MAGIC,
        maximum_bytes: MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES,
        owner: "message-attachment-protocol-foundation",
    };

pub fn validate_registered_opaque_params(
    registration: OpaqueCanonicalParamsRegistrationV1,
    bytes: &[u8],
    decoder: &dyn OpaqueCanonicalParamsDecoder,
) -> Result<()> {
    ensure!(
        registration == SEND_USER_MESSAGE_V2_REGISTRATION,
        "unknown opaque canonical parameter registration"
    );
    ensure!(
        bytes.len() <= registration.maximum_bytes,
        "opaque params exceed registered maximum"
    );
    ensure!(
        bytes.starts_with(&registration.magic),
        "opaque params have wrong magic"
    );
    ensure!(
        decoder.owner() == registration.owner,
        "opaque decoder owner mismatch"
    );
    decoder.validate(bytes)
}

pub fn checked_fcor_v1_size(
    request_kind_len: u64,
    resource_value_lengths: impl IntoIterator<Item = u64>,
    params_len: u64,
) -> Result<u64> {
    ensure!(
        (1..=u8::MAX as u64).contains(&request_kind_len),
        "invalid request kind length"
    );
    ensure!(params_len <= u32::MAX as u64, "params exceed u32 length");
    let mut total = 4_u64
        .checked_add(1)
        .and_then(|v| v.checked_add(1))
        .and_then(|v| v.checked_add(request_kind_len))
        .and_then(|v| v.checked_add(2))
        .and_then(|v| v.checked_add(4))
        .and_then(|v| v.checked_add(params_len))
        .ok_or_else(|| anyhow::anyhow!("FCOR size overflow"))?;
    let mut count = 0_u64;
    for length in resource_value_lengths {
        ensure!(length <= u32::MAX as u64, "resource exceeds u32 length");
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("resource count overflow"))?;
        ensure!(count <= u16::MAX as u64, "too many resources");
        total = total
            .checked_add(5)
            .and_then(|v| v.checked_add(length))
            .ok_or_else(|| anyhow::anyhow!("FCOR size overflow"))?;
    }
    ensure!(total <= MAX_FCOR_V1_BYTES, "FCOR exceeds maximum size");
    Ok(total)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CanonicalParamsV1(Vec<u8>);

/// Closed canonical-value contract used by the exhaustive Request encoder.
/// Implementations must append exactly one value or leave `out` unchanged on
/// error (container implementations stage nested bytes before appending).
pub trait CanonicalFcorValueV1 {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()>;
}

macro_rules! fixed_value {
    ($ty:ty, $method:ident) => {
        impl CanonicalFcorValueV1 for $ty {
            fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
                out.$method(*self);
                Ok(())
            }
        }
    };
}

fixed_value!(u8, push_u8);
fixed_value!(u16, push_u16);
fixed_value!(u32, push_u32);
fixed_value!(u64, push_u64);
fixed_value!(i64, push_i64);
fixed_value!(bool, push_bool);
fixed_value!(Uuid, push_uuid);

impl CanonicalFcorValueV1 for String {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        out.push_string(self)
    }
}

impl<T: CanonicalFcorValueV1> CanonicalFcorValueV1 for Option<T> {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        out.push_optional(self.as_ref(), |nested, value| {
            value.encode_fcor_value_v1(nested)
        })
    }
}

impl<T: CanonicalFcorValueV1> CanonicalFcorValueV1 for Vec<T> {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        out.push_list(self, |nested, value| value.encode_fcor_value_v1(nested))
    }
}

impl<A: CanonicalFcorValueV1, B: CanonicalFcorValueV1> CanonicalFcorValueV1 for (A, B) {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        self.0.encode_fcor_value_v1(&mut nested)?;
        self.1.encode_fcor_value_v1(&mut nested)?;
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for std::collections::HashMap<String, String> {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        out.push_string_map(
            self.iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )
    }
}

impl CanonicalFcorValueV1 for crate::remote_protocol_id::RemoteTransferId {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        out.0.extend_from_slice(self.as_bytes());
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::remote_transport::bulk::RemoteBulkTransferRef {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        self.validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let mut nested = CanonicalParamsV1::new();
        self.transfer_id.encode_fcor_value_v1(&mut nested)?;
        nested.push_u64(self.total_length.value());
        nested.0.extend_from_slice(&self.sha256);
        nested.push_u8(self.mime_class.code());
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::bulk_transfer::BulkTransferId {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        out.0.extend_from_slice(self.as_bytes());
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::bulk_transfer::BulkTransferRef {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        // The command table maps this transport-neutral successor onto the same
        // `struct:RemoteBulkTransferRef:v1` canonical codec, so these bytes must
        // stay identical to the implementation above. The class-ceiling check
        // mirrors `BulkTransferRef::new` so an in-process struct literal cannot
        // bypass it at this boundary.
        ensure!(
            self.total_length.value() <= self.mime_class.max_total_length(),
            "bulk transfer exceeds its MIME-class limit"
        );
        let mut nested = CanonicalParamsV1::new();
        self.transfer_id.encode_fcor_value_v1(&mut nested)?;
        nested.push_u64(self.total_length.value());
        nested.0.extend_from_slice(&self.sha256);
        nested.push_u8(match self.mime_class {
            crate::bulk_transfer::BulkMimeClass::Image => 1,
            crate::bulk_transfer::BulkMimeClass::ImageSet => 2,
            crate::bulk_transfer::BulkMimeClass::Archive => 3,
            crate::bulk_transfer::BulkMimeClass::Export => 4,
            crate::bulk_transfer::BulkMimeClass::Opaque => 5,
            crate::bulk_transfer::BulkMimeClass::RedactedExport => 6,
        });
        out.0.extend(nested.0);
        Ok(())
    }
}

macro_rules! canonical_unit_enum16 {
    ($ty:ty, { $($variant:ident = $code:literal),+ $(,)? }) => {
        impl CanonicalFcorValueV1 for $ty {
            fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
                let code: u16 = match self { $(Self::$variant => $code),+ };
                out.push_u16(code);
                Ok(())
            }
        }
    };
}

canonical_unit_enum16!(crate::EnvDriftPolicy, {
    Daemon = 1,
    Client = 2,
    UpdateDaemon = 3,
    ErrorOnDrift = 4,
});
canonical_unit_enum16!(crate::UserMessageOrigin, {
    ExternalRoot = 1,
    GoalContinuation = 2,
    ScheduledJob = 3,
    AutoContinue = 4,
    RetryRecovery = 5,
    ToolResult = 6,
    CompactNotice = 7,
    Internal = 8,
});
canonical_unit_enum16!(crate::SessionEntryMode, {
    Code = 1,
    Assistant = 2,
    Computer = 3,
});
canonical_unit_enum16!(crate::CaffeinateMode, {
    Toggle = 1,
    On = 2,
    Off = 3,
    UntilIdle = 4,
});
canonical_unit_enum16!(crate::WorkspaceTrustMode, {
    Trust = 1,
    IgnoreConfig = 2,
    Untrusted = 3,
});
canonical_unit_enum16!(crate::AppFlagKey, { DaemonAutostartNotice = 1 });
canonical_unit_enum16!(crate::AssistantSessionResolutionMode, {
    MostRecentOrCreate = 1
});
canonical_unit_enum16!(crate::ExportSessionKind, {
    TranscriptJson = 1,
    DebugBundle = 2,
});
canonical_unit_enum16!(crate::StatsRange, {
    Last7Days = 1,
    AllTime = 2,
});
canonical_unit_enum16!(crate::UsageKind, {
    Model = 1,
    Slash = 2,
    Tag = 3,
});
canonical_unit_enum16!(crate::LspControlAction, {
    Check = 1,
    Install = 2,
    Uninstall = 3,
    Restart = 4,
});
canonical_unit_enum16!(crate::ActiveModelSwitchTrigger, {
    Picker = 1,
    Quick = 2,
    Cycle = 3,
    Daemon = 4,
});
canonical_unit_enum16!(cockpit_config::config::providers::PromptCacheRetention, {
    Default = 1,
    Extended = 2,
});
canonical_unit_enum16!(cockpit_config::config::providers::ThinkingMode, {
    Off = 1,
    Low = 2,
    Medium = 3,
    High = 4,
});
canonical_unit_enum16!(crate::EnvSnapshotSource, {
    DaemonStart = 1,
    TuiShell = 2,
    TuiProcessFallback = 3,
    ExplicitCli = 4,
});
canonical_unit_enum16!(cockpit_config::config::extended::ApprovalMode, {
    Manual = 1,
    Auto = 2,
    Yolo = 3,
});
canonical_unit_enum16!(cockpit_config::config::sandbox_mode::SandboxMode, {
    Off = 1,
    Sandbox = 2,
    Container = 3,
    ContainerReadonly = 4,
});
canonical_unit_enum16!(cockpit_db::db::session_goals::GoalDisposition, {
    Running = 1,
    UserPaused = 2,
    InfraPaused = 3,
    Blocked = 4,
    NoProgressPaused = 5,
    BudgetLimited = 6,
    Complete = 7,
    Cleared = 8,
});
canonical_unit_enum16!(crate::LeakRotationDisposition, {
    Accept = 1,
    Dismiss = 2,
    Rotated = 3,
});
canonical_unit_enum16!(crate::LeakRotationState, {
    None = 1,
    PendingUser = 2,
    Rotated = 3,
    NotApplicable = 4,
});
canonical_unit_enum16!(crate::SecretStorePlacement, {
    Unavailable = 1,
    Database = 2,
    Keyring = 3,
});

macro_rules! canonical_struct {
    ($ty:ty, $value:ident, $out:ident, [$($field:ident),+ $(,)?]) => {
        impl CanonicalFcorValueV1 for $ty {
            fn encode_fcor_value_v1(&$value, $out: &mut CanonicalParamsV1) -> Result<()> {
                let mut nested = CanonicalParamsV1::new();
                $($value.$field.encode_fcor_value_v1(&mut nested)?;)+
                $out.0.extend(nested.0);
                Ok(())
            }
        }
    };
}

canonical_struct!(crate::EnvSnapshotWire, self, out, [source, digest, vars]);
canonical_struct!(crate::ImageAttachmentRef, self, out, [id]);
canonical_struct!(crate::TagExpansionMeta, self, out, [tool, path, detail, ok]);
// Image-spend policy is a versioned, serde-deny-unknown-fields value owned by
// cockpit-config. Encode its canonical JSON as one scalar rather than relying
// on a map iteration order at this protocol boundary.
impl CanonicalFcorValueV1 for cockpit_config::config::image_spend::ImageSpendSettings {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        serde_json::to_string(self)
            .context("serializing image-spend settings for FCOR")?
            .encode_fcor_value_v1(out)
    }
}
impl CanonicalFcorValueV1 for cockpit_config::config::providers::ActiveReasoningEffort {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        self.validate().map_err(anyhow::Error::msg)?;
        let mut nested = CanonicalParamsV1::new();
        self.value.encode_fcor_value_v1(&mut nested)?;
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for cockpit_config::config::providers::OnUnlistedModelsFetch {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let code = match self {
            Self::Keep => 1,
            Self::Remove => 2,
            Self::Ask => 3,
        };
        out.push_u8(code);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for cockpit_config::config::providers::ProviderEntry {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        // Provider configs are serde structs/maps whose canonical wire form is
        // their compact JSON representation.  This is used only after request
        // semantic validation rejects literal header values, so F-COR never
        // serializes a provider secret into an operation record.
        let encoded = serde_json::to_string(self).context("encoding provider entry for F-COR")?;
        out.push_string(&encoded)
    }
}
impl CanonicalFcorValueV1 for crate::RunInvocationOptions {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        ensure!(self.max_turns != Some(0), "run_options_zero_max_turns");
        ensure!(self.timeout_ms != Some(0), "run_options_zero_timeout_ms");
        let mut nested = CanonicalParamsV1::new();
        self.max_turns.encode_fcor_value_v1(&mut nested)?;
        self.timeout_ms.encode_fcor_value_v1(&mut nested)?;
        self.approval_mode.encode_fcor_value_v1(&mut nested)?;
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for cockpit_config::config::providers::ActiveModelRef {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        self.validate().map_err(anyhow::Error::msg)?;
        let mut nested = CanonicalParamsV1::new();
        self.provider.encode_fcor_value_v1(&mut nested)?;
        self.model.encode_fcor_value_v1(&mut nested)?;
        self.reasoning_effort.encode_fcor_value_v1(&mut nested)?;
        self.thinking_mode.encode_fcor_value_v1(&mut nested)?;
        self.prompt_cache_retention
            .encode_fcor_value_v1(&mut nested)?;
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::AttachmentPurpose {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        match self {
            Self::UserMessageImage => nested.push_u16(1),
        }
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::terminal::TerminalBinding {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        nested.push_uuid(self.binding_id);
        nested.push_u64(self.binding_epoch);
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::terminal::TerminalImageType {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        nested.push_u16(match self {
            Self::Png => 1,
            Self::Jpeg => 2,
            Self::Gif => 3,
            Self::Webp => 4,
        });
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::terminal::TerminalIngressMetadata {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        nested.push_uuid(self.operation_id);
        nested.push_u64(self.size);
        self.media_type.encode_fcor_value_v1(&mut nested)?;
        nested.push_string(&self.sha256)?;
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for cockpit_db::wire::ResolveResponse {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        fn count(value: &cockpit_db::wire::ResolveResponse, depth: u16) -> Result<u32> {
            ensure!(depth <= 32, "resolve_response_depth_exceeded");
            let mut nodes = 1_u32;
            if let cockpit_db::wire::ResolveResponse::Batch { responses } = value {
                for child in responses {
                    nodes = nodes
                        .checked_add(count(child, depth + 1)?)
                        .ok_or_else(|| anyhow::anyhow!("resolve_response_nodes_exceeded"))?;
                    ensure!(nodes <= 4096, "resolve_response_nodes_exceeded");
                }
            }
            Ok(nodes)
        }
        count(self, 1)?;
        let mut nested = CanonicalParamsV1::new();
        match self {
            Self::Single { selected_id } => {
                nested.push_u16(1);
                selected_id.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Multi { selected_ids } => {
                nested.push_u16(2);
                selected_ids.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Freetext { text } => {
                nested.push_u16(3);
                text.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Batch { responses } => {
                nested.push_u16(4);
                responses.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Cancel => nested.push_u16(5),
        }
        out.0.extend(nested.0);
        Ok(())
    }
}

canonical_unit_enum16!(crate::MissedRunPolicy, {
    Skip = 1,
    RunOnceOnStart = 2,
});

impl CanonicalFcorValueV1 for crate::ScheduledJobSchedule {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        match self {
            Self::Cron { expr } => {
                nested.push_u16(1);
                expr.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Every { seconds } => {
                nested.push_u16(2);
                seconds.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Once { at } => {
                nested.push_u16(3);
                at.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Idle {
                min_idle_seconds,
                max_age_seconds,
            } => {
                nested.push_u16(4);
                min_idle_seconds.encode_fcor_value_v1(&mut nested)?;
                max_age_seconds.encode_fcor_value_v1(&mut nested)?;
            }
        }
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::ScheduledJobPayload {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        match self {
            Self::RunPrompt {
                assistant,
                prompt,
                project_root: _,
            } => {
                nested.push_u16(1);
                assistant.encode_fcor_value_v1(&mut nested)?;
                prompt.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Callback { subsystem } => {
                nested.push_u16(2);
                subsystem.encode_fcor_value_v1(&mut nested)?;
            }
        }
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::ScheduledJobCreate {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        // `id` is the ordered SchedulerId resource.
        self.owner.encode_fcor_value_v1(&mut nested)?;
        self.schedule.encode_fcor_value_v1(&mut nested)?;
        self.payload.encode_fcor_value_v1(&mut nested)?;
        self.enabled.encode_fcor_value_v1(&mut nested)?;
        self.missed_run_policy.encode_fcor_value_v1(&mut nested)?;
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::CuratorAction {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        match self {
            Self::Status => nested.push_u16(1),
            Self::Run {
                dry_run,
                consolidate,
            } => {
                nested.push_u16(2);
                dry_run.encode_fcor_value_v1(&mut nested)?;
                consolidate.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Pin { name } => {
                nested.push_u16(3);
                name.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Unpin { name } => {
                nested.push_u16(4);
                name.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Restore { name } => {
                nested.push_u16(5);
                name.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Rollback { list, id } => {
                nested.push_u16(6);
                list.encode_fcor_value_v1(&mut nested)?;
                id.encode_fcor_value_v1(&mut nested)?;
            }
        }
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::AccountInfo {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        self.validate()?;
        let mut nested = CanonicalParamsV1::new();
        self.user_id.encode_fcor_value_v1(&mut nested)?;
        self.email.encode_fcor_value_v1(&mut nested)?;
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::RelayChoice {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        self.validate()?;
        let mut nested = CanonicalParamsV1::new();
        self.relay_id.encode_fcor_value_v1(&mut nested)?;
        self.region.encode_fcor_value_v1(&mut nested)?;
        self.ws_url.encode_fcor_value_v1(&mut nested)?;
        self.rtt_ms.encode_fcor_value_v1(&mut nested)?;
        self.chosen_at.encode_fcor_value_v1(&mut nested)?;
        out.0.extend(nested.0);
        Ok(())
    }
}
impl CanonicalFcorValueV1 for crate::StoredFlycockpitCredential {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        self.validate()?;
        let mut nested = CanonicalParamsV1::new();
        self.server_url.encode_fcor_value_v1(&mut nested)?;
        self.instance_id.encode_fcor_value_v1(&mut nested)?;
        self.instance_token.encode_fcor_value_v1(&mut nested)?;
        self.account.encode_fcor_value_v1(&mut nested)?;
        self.display_name.encode_fcor_value_v1(&mut nested)?;
        self.relay_choice.encode_fcor_value_v1(&mut nested)?;
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::GoalSupervisionPatch {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        // `cold_skeptic_count` is platform-width in the settings type; canonical
        // bytes always carry the 64-bit widening (FCOR has no `usize` codec).
        let cold_skeptic_count = match self.cold_skeptic_count {
            Some(Some(value)) => Some(Some(u64::try_from(value)?)),
            Some(None) => Some(None),
            None => None,
        };
        let mut nested = CanonicalParamsV1::new();
        cold_skeptic_count.encode_fcor_value_v1(&mut nested)?;
        self.cold_skeptic_model.encode_fcor_value_v1(&mut nested)?;
        self.max_verification_attempts
            .encode_fcor_value_v1(&mut nested)?;
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::AgentMutation {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        match self {
            Self::EjectBuiltin { name } => {
                nested.push_u16(1);
                name.encode_fcor_value_v1(&mut nested)?;
            }
            Self::SaveDefinition { name, markdown } => {
                nested.push_u16(2);
                name.encode_fcor_value_v1(&mut nested)?;
                markdown.encode_fcor_value_v1(&mut nested)?;
            }
            Self::CreateDefinition { name, markdown } => {
                nested.push_u16(3);
                name.encode_fcor_value_v1(&mut nested)?;
                markdown.encode_fcor_value_v1(&mut nested)?;
            }
            Self::DeleteCustom { name } => {
                nested.push_u16(4);
                name.encode_fcor_value_v1(&mut nested)?;
            }
            Self::ResetBuiltin { name } => {
                nested.push_u16(5);
                name.encode_fcor_value_v1(&mut nested)?;
            }
            Self::ResetAllBuiltins => nested.push_u16(6),
            Self::SaveGoalSupervision { name, patch } => {
                nested.push_u16(7);
                name.encode_fcor_value_v1(&mut nested)?;
                patch.encode_fcor_value_v1(&mut nested)?;
            }
        }
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::ExtendedConfigPathMutation {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        match self {
            Self::Set { path, value } => {
                nested.push_u16(1);
                path.encode_fcor_value_v1(&mut nested)?;
                // A free-form settings value has no field-wise canonical form.
                // Encode the audited RFC 8785 canonicalization as one scalar so
                // object key order cannot change these bytes.
                crate::remote_identity_protocol::canonical_json(value)?
                    .encode_fcor_value_v1(&mut nested)?;
            }
            Self::Unset { path } => {
                nested.push_u16(2);
                path.encode_fcor_value_v1(&mut nested)?;
            }
        }
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::DesiredDenylistEntry {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        match self {
            Self::Existing { entry_id } => {
                nested.push_u16(1);
                entry_id.encode_fcor_value_v1(&mut nested)?;
            }
            Self::New {
                client_nonce,
                literal,
            } => {
                nested.push_u16(2);
                client_nonce.encode_fcor_value_v1(&mut nested)?;
                literal.encode_fcor_value_v1(&mut nested)?;
            }
        }
        out.0.extend(nested.0);
        Ok(())
    }
}

impl CanonicalFcorValueV1 for crate::RedactedOccurrenceMutation {
    fn encode_fcor_value_v1(&self, out: &mut CanonicalParamsV1) -> Result<()> {
        let mut nested = CanonicalParamsV1::new();
        match self {
            Self::Set { pointer, value } => {
                nested.push_u16(1);
                pointer.encode_fcor_value_v1(&mut nested)?;
                value.encode_fcor_value_v1(&mut nested)?;
            }
            Self::Unset { pointer } => {
                nested.push_u16(2);
                pointer.encode_fcor_value_v1(&mut nested)?;
            }
        }
        out.0.extend(nested.0);
        Ok(())
    }
}

// The denylist literal and the redacted-occurrence replacement are
// `SensitiveWireLiteral`, so the nested encodings above resolve to the
// sealed-literal placeholder and no plaintext reaches this canonical buffer.
canonical_struct!(
    crate::ExtendedConfigPatch,
    self,
    out,
    [operations, materialize, denylist, redacted_mutations]
);

impl CanonicalParamsV1 {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
    pub fn push_u8(&mut self, value: u8) {
        self.0.push(value);
    }
    pub fn push_bool(&mut self, value: bool) {
        self.push_u8(u8::from(value));
    }
    pub fn push_u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn push_u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn push_u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn push_i64(&mut self, value: i64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn push_uuid(&mut self, value: Uuid) {
        self.0.extend_from_slice(value.as_bytes());
    }

    pub fn push_bytes(&mut self, value: &[u8]) -> Result<()> {
        self.push_u32(u32::try_from(value.len())?);
        self.0.extend_from_slice(value);
        Ok(())
    }

    pub fn push_string(&mut self, value: &str) -> Result<()> {
        ensure!(!value.contains('\0'), "canonical string contains NUL");
        ensure!(value.nfc().eq(value.chars()), "canonical string is not NFC");
        self.push_bytes(value.as_bytes())
    }

    pub fn push_optional<T>(
        &mut self,
        value: Option<&T>,
        encode: impl FnOnce(&mut Self, &T) -> Result<()>,
    ) -> Result<()> {
        match value {
            Some(value) => {
                let mut nested = Self::new();
                encode(&mut nested, value)?;
                self.push_u8(1);
                self.0.extend(nested.0);
                Ok(())
            }
            None => {
                self.push_u8(0);
                Ok(())
            }
        }
    }

    pub fn push_list<'a, T: 'a>(
        &mut self,
        values: impl IntoIterator<Item = &'a T>,
        mut encode: impl FnMut(&mut Self, &T) -> Result<()>,
    ) -> Result<()> {
        let mut items = Vec::new();
        for value in values {
            let mut item = Self::new();
            encode(&mut item, value)?;
            items.push(item.0);
        }
        self.push_u32(u32::try_from(items.len())?);
        for item in items {
            self.0.extend(item);
        }
        Ok(())
    }

    pub fn push_string_map<'a>(
        &mut self,
        entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<()> {
        let mut encoded = Vec::new();
        for (key, value) in entries {
            ensure!(!key.contains('\0'), "canonical map key contains NUL");
            let normalized_key = key.nfc().collect::<String>();
            let mut key_bytes = Self::new();
            key_bytes.push_string(&normalized_key)?;
            let mut value_bytes = Self::new();
            value_bytes.push_string(value)?;
            encoded.push((normalized_key, key_bytes.0, value_bytes.0));
        }
        encoded.sort_by(|left, right| left.1.cmp(&right.1));
        ensure!(
            encoded.windows(2).all(|pair| pair[0].0 != pair[1].0),
            "duplicate NFC map key"
        );
        self.push_u32(u32::try_from(encoded.len())?);
        for (_, key, value) in encoded {
            self.0.extend(key);
            self.0.extend(value);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RemoteOperationResourceKind {
    SessionUuid = 1,
    ProjectId = 2,
    ProjectRoot = 3,
    FilePath = 4,
    TerminalUuid = 5,
    UploadUuid = 6,
    InterruptUuid = 7,
    SchedulerId = 8,
    QueueUuid = 9,
    ProviderModel = 10,
    DaemonGlobal = 11,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOperationResource<'a> {
    pub kind: RemoteOperationResourceKind,
    pub value: &'a [u8],
}

fn validate_stable_resource_shape(kind: u8, value: &[u8]) -> Result<()> {
    match kind {
        1 | 5 | 6 | 7 | 9 => ensure!(value.len() == 16, "UUID resource must be 16 bytes"),
        11 => ensure!(value.is_empty(), "daemon_global resource must be empty"),
        // Text/path canonicalization is descriptor-specific because paths must
        // first pass through the daemon authorization resolver.
        10 => validate_provider_model_resource_v1(value)?,
        2 | 3 | 4 | 8 => {}
        _ => bail!("unknown resource kind"),
    }
    Ok(())
}

pub fn encode_provider_model_resource_v1(provider: &str, model: &str) -> Result<Vec<u8>> {
    let mut out = CanonicalParamsV1::new();
    out.push_string(provider)?;
    out.push_string(model)?;
    Ok(out.into_bytes())
}

pub fn validate_provider_model_resource_v1(bytes: &[u8]) -> Result<()> {
    let mut offset = 0usize;
    for _ in 0..2 {
        ensure!(offset + 4 <= bytes.len(), "truncated provider_model length");
        let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) as usize;
        offset += 4;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("provider_model length overflow"))?;
        ensure!(end <= bytes.len(), "truncated provider_model value");
        let value = std::str::from_utf8(&bytes[offset..end])?;
        ensure!(!value.contains('\0'), "provider_model contains NUL");
        ensure!(value.nfc().eq(value.chars()), "provider_model is not NFC");
        offset = end;
    }
    ensure!(offset == bytes.len(), "trailing provider_model bytes");
    Ok(())
}

pub fn encode_fcor_v1(
    request_kind: &str,
    resources: &[RemoteOperationResource<'_>],
    canonical_params: &[u8],
) -> Result<Vec<u8>> {
    let kind = request_kind.as_bytes();
    ensure!(
        !kind.is_empty() && kind.len() <= u8::MAX as usize,
        "invalid request kind length"
    );
    ensure!(
        kind.iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'),
        "request kind must be lowercase ASCII"
    );
    let resource_count = u16::try_from(resources.len())?;
    let params_len = u32::try_from(canonical_params.len())?;
    let total = checked_fcor_v1_size(
        kind.len() as u64,
        resources.iter().map(|resource| resource.value.len() as u64),
        canonical_params.len() as u64,
    )?;
    let mut out = Vec::with_capacity(usize::try_from(total)?);
    out.extend_from_slice(&FCOR_MAGIC);
    out.push(FCOR_SCHEMA_VERSION);
    out.push(kind.len() as u8);
    out.extend_from_slice(kind);
    out.extend_from_slice(&resource_count.to_be_bytes());
    for resource in resources {
        validate_stable_resource_shape(resource.kind as u8, resource.value)?;
        let value_len = u32::try_from(resource.value.len())?;
        out.push(resource.kind as u8);
        out.extend_from_slice(&value_len.to_be_bytes());
        out.extend_from_slice(resource.value);
    }
    out.extend_from_slice(&params_len.to_be_bytes());
    out.extend_from_slice(canonical_params);
    Ok(out)
}

pub fn hash_fcor_v1(bytes: &[u8]) -> Result<[u8; 32]> {
    validate_fcor_v1(bytes)?;
    Ok(Sha256::digest(bytes).into())
}

pub fn validate_fcor_v1(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 12 && bytes[..4] == FCOR_MAGIC,
        "invalid FCOR magic"
    );
    ensure!(bytes[4] == FCOR_SCHEMA_VERSION, "unsupported FCOR schema");
    let mut offset = 5;
    let kind_len = bytes[offset] as usize;
    offset += 1;
    ensure!(
        kind_len > 0 && offset + kind_len + 2 <= bytes.len(),
        "invalid request kind length"
    );
    let kind = &bytes[offset..offset + kind_len];
    ensure!(
        kind.iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'),
        "invalid request kind"
    );
    offset += kind_len;
    let resource_count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    for _ in 0..resource_count {
        ensure!(offset + 5 <= bytes.len(), "truncated resource");
        ensure!((1..=11).contains(&bytes[offset]), "unknown resource kind");
        let resource_kind = bytes[offset];
        offset += 1;
        let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) as usize;
        offset += 4;
        offset = offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("resource length overflow"))?;
        ensure!(offset <= bytes.len(), "truncated resource value");
        validate_stable_resource_shape(resource_kind, &bytes[offset - len..offset])?;
    }
    ensure!(offset + 4 <= bytes.len(), "missing params length");
    let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) as usize;
    offset += 4;
    ensure!(
        offset.checked_add(len) == Some(bytes.len()),
        "truncated or trailing FCOR bytes"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_model_resource_shared_vector_is_exact() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/cockpit-protocol/fixtures/provider-model-resource-v1.json"
        ))
        .unwrap();
        let bytes = encode_provider_model_resource_v1(
            fixture["provider"].as_str().unwrap(),
            fixture["model"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(hex(&bytes), fixture["canonicalHex"].as_str().unwrap());
        validate_provider_model_resource_v1(&bytes).unwrap();
        for malformed in fixture["malformedHex"].as_array().unwrap() {
            assert!(
                validate_provider_model_resource_v1(&decode_hex(malformed.as_str().unwrap()))
                    .is_err()
            );
        }
    }

    #[test]
    fn named_codec_validation_is_rollback_safe_and_resolve_is_bounded() {
        let mut out = CanonicalParamsV1::new();
        out.push_u8(9);
        let invalid = crate::RunInvocationOptions {
            max_turns: Some(0),
            timeout_ms: None,
            approval_mode: None,
        };
        assert_eq!(
            invalid
                .encode_fcor_value_v1(&mut out)
                .unwrap_err()
                .to_string(),
            "run_options_zero_max_turns"
        );
        assert_eq!(out.into_bytes(), vec![9]);

        let mut response = cockpit_db::wire::ResolveResponse::Cancel;
        for _ in 0..32 {
            response = cockpit_db::wire::ResolveResponse::Batch {
                responses: vec![response],
            };
        }
        let mut out = CanonicalParamsV1::new();
        out.push_u8(7);
        assert_eq!(
            response
                .encode_fcor_value_v1(&mut out)
                .unwrap_err()
                .to_string(),
            "resolve_response_depth_exceeded"
        );
        assert_eq!(out.into_bytes(), vec![7]);

        let mut depth_32 = cockpit_db::wire::ResolveResponse::Cancel;
        for _ in 0..31 {
            depth_32 = cockpit_db::wire::ResolveResponse::Batch {
                responses: vec![depth_32],
            };
        }
        assert!(
            depth_32
                .encode_fcor_value_v1(&mut CanonicalParamsV1::new())
                .is_ok()
        );

        let nodes_4096 = cockpit_db::wire::ResolveResponse::Batch {
            responses: std::iter::repeat_n(cockpit_db::wire::ResolveResponse::Cancel, 4095)
                .collect(),
        };
        assert!(
            nodes_4096
                .encode_fcor_value_v1(&mut CanonicalParamsV1::new())
                .is_ok()
        );
        let nodes_4097 = cockpit_db::wire::ResolveResponse::Batch {
            responses: std::iter::repeat_n(cockpit_db::wire::ResolveResponse::Cancel, 4096)
                .collect(),
        };
        let mut out = CanonicalParamsV1::new();
        out.push_u8(6);
        assert_eq!(
            nodes_4097
                .encode_fcor_value_v1(&mut out)
                .unwrap_err()
                .to_string(),
            "resolve_response_nodes_exceeded"
        );
        assert_eq!(out.into_bytes(), vec![6]);

        let invalid_effort = cockpit_config::config::providers::ActiveReasoningEffort {
            value: String::new(),
        };
        let mut out = CanonicalParamsV1::new();
        out.push_u8(5);
        assert_eq!(
            invalid_effort
                .encode_fcor_value_v1(&mut out)
                .unwrap_err()
                .to_string(),
            "active reasoning effort must not be empty"
        );
        assert_eq!(out.into_bytes(), vec![5]);

        let invalid_account = crate::AccountInfo {
            user_id: String::new(),
            email: "e".into(),
        };
        let invalid_relay = crate::RelayChoice {
            relay_id: String::new(),
            region: None,
            ws_url: "w".into(),
            rtt_ms: None,
            chosen_at: 0,
        };
        let invalid_credential = crate::StoredFlycockpitCredential {
            server_url: "http://example.test".into(),
            instance_id: "i".into(),
            instance_token: "secret".into(),
            account: crate::AccountInfo {
                user_id: "u".into(),
                email: "e".into(),
            },
            display_name: None,
            relay_choice: None,
        };
        let invalid_schedule = crate::ScheduledJobSchedule::Cron {
            expr: "e\u{301}".into(),
        };
        let invalid_curator = crate::CuratorAction::Pin {
            name: "e\u{301}".into(),
        };
        for invalid in [
            (&invalid_account as &dyn CanonicalFcorValueV1),
            (&invalid_relay as &dyn CanonicalFcorValueV1),
            (&invalid_credential as &dyn CanonicalFcorValueV1),
            (&invalid_schedule as &dyn CanonicalFcorValueV1),
            (&invalid_curator as &dyn CanonicalFcorValueV1),
        ] {
            let mut out = CanonicalParamsV1::new();
            out.push_u8(4);
            assert!(invalid.encode_fcor_value_v1(&mut out).is_err());
            assert_eq!(out.into_bytes(), vec![4]);
        }
    }

    #[test]
    fn named_codec_field_order_and_data_enum_bytes_are_exact() {
        fn exact(value: &impl CanonicalFcorValueV1, expected: &str) {
            let mut out = CanonicalParamsV1::new();
            value.encode_fcor_value_v1(&mut out).unwrap();
            assert_eq!(hex(&out.into_bytes()), expected);
        }
        exact(
            &crate::EnvSnapshotWire {
                source: crate::EnvSnapshotSource::DaemonStart,
                digest: "d".into(),
                vars: std::collections::HashMap::new(),
            },
            "0001000000016400000000",
        );
        exact(
            &crate::ImageAttachmentRef {
                id: Uuid::from_bytes([1; 16]),
            },
            "01010101010101010101010101010101",
        );
        exact(
            &crate::TagExpansionMeta {
                tool: "t".into(),
                path: "p".into(),
                detail: "d".into(),
                ok: true,
            },
            "00000001740000000170000000016401",
        );
        exact(&crate::RunInvocationOptions::default(), "000000");
        exact(
            &cockpit_config::config::providers::ActiveReasoningEffort { value: "r".into() },
            "0000000172",
        );
        exact(
            &cockpit_config::config::providers::ActiveModelRef {
                provider: "p".into(),
                model: "m".into(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            "0000000170000000016d000000",
        );
        exact(
            &cockpit_db::wire::ResolveResponse::Single {
                selected_id: "a".into(),
            },
            "00010000000161",
        );
        exact(
            &cockpit_db::wire::ResolveResponse::Multi {
                selected_ids: vec!["a".into(), "b".into()],
            },
            "00020000000200000001610000000162",
        );
        exact(
            &cockpit_db::wire::ResolveResponse::Freetext { text: "x".into() },
            "00030000000178",
        );
        exact(
            &cockpit_db::wire::ResolveResponse::Batch {
                responses: vec![cockpit_db::wire::ResolveResponse::Cancel],
            },
            "0004000000010005",
        );
        exact(&cockpit_db::wire::ResolveResponse::Cancel, "0005");

        exact(
            &crate::ScheduledJobSchedule::Cron { expr: "x".into() },
            "00010000000178",
        );
        exact(
            &crate::ScheduledJobSchedule::Every { seconds: 1 },
            "00020000000000000001",
        );
        exact(
            &crate::ScheduledJobSchedule::Once { at: -1 },
            "0003ffffffffffffffff",
        );
        exact(
            &crate::ScheduledJobSchedule::Idle {
                min_idle_seconds: 1,
                max_age_seconds: 2,
            },
            "000400000000000000010000000000000002",
        );
        exact(
            &crate::ScheduledJobPayload::RunPrompt {
                assistant: "a".into(),
                prompt: "p".into(),
                project_root: "/not-in-params".into(),
            },
            "000100000001610000000170",
        );
        exact(
            &crate::ScheduledJobPayload::Callback {
                subsystem: "s".into(),
            },
            "00020000000173",
        );
        exact(&crate::CuratorAction::Status, "0001");
        exact(
            &crate::CuratorAction::Run {
                dry_run: false,
                consolidate: true,
            },
            "00020001",
        );
        exact(
            &crate::CuratorAction::Pin { name: "n".into() },
            "0003000000016e",
        );
        exact(
            &crate::CuratorAction::Unpin { name: "n".into() },
            "0004000000016e",
        );
        exact(
            &crate::CuratorAction::Restore { name: "n".into() },
            "0005000000016e",
        );
        exact(
            &crate::CuratorAction::Rollback {
                list: true,
                id: None,
            },
            "00060100",
        );
        exact(
            &crate::AccountInfo {
                user_id: "u".into(),
                email: "e".into(),
            },
            "00000001750000000165",
        );
        exact(
            &crate::RelayChoice {
                relay_id: "r".into(),
                region: None,
                ws_url: "w".into(),
                rtt_ms: None,
                chosen_at: 1,
            },
            "0000000172000000000177000000000000000001",
        );
        exact(
            &crate::StoredFlycockpitCredential {
                server_url: "https://x.test".into(),
                instance_id: "i".into(),
                instance_token: "t".into(),
                account: crate::AccountInfo {
                    user_id: "u".into(),
                    email: "e".into(),
                },
                display_name: None,
                relay_choice: None,
            },
            "0000000e68747470733a2f2f782e7465737400000001690000000174000000017500000001650000",
        );
        exact(
            &crate::ScheduledJobCreate {
                id: "resource-id".into(),
                owner: "o".into(),
                schedule: crate::ScheduledJobSchedule::Every { seconds: 1 },
                payload: crate::ScheduledJobPayload::RunPrompt {
                    assistant: "a".into(),
                    prompt: "p".into(),
                    project_root: "/resource-root".into(),
                },
                enabled: true,
                missed_run_policy: crate::MissedRunPolicy::Skip,
            },
            "000000016f00020000000000000001000100000001610000000170010001",
        );
        exact(
            &crate::StoredFlycockpitCredential {
                server_url: "https://x.test".into(),
                instance_id: "i".into(),
                instance_token: "t".into(),
                account: crate::AccountInfo {
                    user_id: "u".into(),
                    email: "e".into(),
                },
                display_name: Some("d".into()),
                relay_choice: Some(crate::RelayChoice {
                    relay_id: "R".into(),
                    region: Some("z".into()),
                    ws_url: "w".into(),
                    rtt_ms: Some(2),
                    chosen_at: 1,
                }),
            },
            "0000000e68747470733a2f2f782e74657374000000016900000001740000000175000000016501000000016401000000015201000000017a00000001770100000000000000020000000000000001",
        );
        assert_eq!(
            crate::normalize_server_url("http://[::1]/").unwrap(),
            "http://[::1]"
        );
    }

    #[test]
    fn bulk_reference_value_bytes_are_exact_and_revalidate_class_limit() {
        use crate::remote_protocol_id::{kind, tag_protocol_id_bytes};
        use crate::remote_transport::bulk::{RemoteBulkMimeClass, RemoteBulkTransferRef};
        let reference = RemoteBulkTransferRef::new(
            tag_protocol_id_bytes::<kind::Transfer>([1; 16]).unwrap(),
            5,
            [2; 32],
            RemoteBulkMimeClass::Opaque,
        )
        .unwrap();
        let mut encoded = CanonicalParamsV1::new();
        reference.encode_fcor_value_v1(&mut encoded).unwrap();
        assert_eq!(
            hex(&encoded.into_bytes()),
            "010101010101010101010101010101010000000000000005020202020202020202020202020202020202020202020202020202020202020205"
        );

        let invalid = RemoteBulkTransferRef {
            transfer_id: reference.transfer_id,
            total_length: crate::remote_protocol_id::CanonicalU64DecimalStringV1::from_u64(
                RemoteBulkMimeClass::Image.max_total_length() + 1,
            ),
            sha256: [2; 32],
            mime_class: RemoteBulkMimeClass::Image,
        };
        assert!(
            invalid
                .encode_fcor_value_v1(&mut CanonicalParamsV1::new())
                .is_err()
        );
    }

    #[test]
    fn frozen_enum16_ordinals_match_shared_fixture() {
        fn ordinal(value: &impl CanonicalFcorValueV1) -> u16 {
            let mut bytes = CanonicalParamsV1::new();
            value.encode_fcor_value_v1(&mut bytes).unwrap();
            u16::from_be_bytes(bytes.into_bytes().try_into().unwrap())
        }
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote-operation-enum16-v1.json"
        ))
        .unwrap();
        let expected = &fixture["ordinals"];
        macro_rules! check {
            ($key:literal, $value:expr) => {
                assert_eq!(ordinal(&$value), expected[$key].as_u64().unwrap() as u16)
            };
        }
        macro_rules! check_prefix {
            ($key:literal, $value:expr) => {{
                let mut bytes = CanonicalParamsV1::new();
                $value.encode_fcor_value_v1(&mut bytes).unwrap();
                assert_eq!(
                    u16::from_be_bytes(bytes.into_bytes()[..2].try_into().unwrap()),
                    expected[$key].as_u64().unwrap() as u16
                );
            }};
        }
        check!("env_drift_policy.daemon", crate::EnvDriftPolicy::Daemon);
        check!("env_drift_policy.client", crate::EnvDriftPolicy::Client);
        check!(
            "env_drift_policy.update_daemon",
            crate::EnvDriftPolicy::UpdateDaemon
        );
        check!(
            "env_drift_policy.error_on_drift",
            crate::EnvDriftPolicy::ErrorOnDrift
        );
        check!("caffeinate_mode.toggle", crate::CaffeinateMode::Toggle);
        check!("caffeinate_mode.on", crate::CaffeinateMode::On);
        check!("caffeinate_mode.off", crate::CaffeinateMode::Off);
        check!(
            "caffeinate_mode.until_idle",
            crate::CaffeinateMode::UntilIdle
        );
        check!(
            "workspace_trust_mode.trust",
            crate::WorkspaceTrustMode::Trust
        );
        check!(
            "workspace_trust_mode.ignore_config",
            crate::WorkspaceTrustMode::IgnoreConfig
        );
        check!(
            "workspace_trust_mode.untrusted",
            crate::WorkspaceTrustMode::Untrusted
        );
        check!(
            "app_flag_key.daemon_autostart_notice",
            crate::AppFlagKey::DaemonAutostartNotice
        );
        check!(
            "assistant_session_resolution_mode.most_recent_or_create",
            crate::AssistantSessionResolutionMode::MostRecentOrCreate
        );
        check!(
            "export_session_kind.transcript_json",
            crate::ExportSessionKind::TranscriptJson
        );
        check!(
            "export_session_kind.debug_bundle",
            crate::ExportSessionKind::DebugBundle
        );
        check!("stats_range.last_7_days", crate::StatsRange::Last7Days);
        check!("stats_range.all_time", crate::StatsRange::AllTime);
        check!("usage_kind.model", crate::UsageKind::Model);
        check!("usage_kind.slash", crate::UsageKind::Slash);
        check!("usage_kind.tag", crate::UsageKind::Tag);
        check!("lsp_control_action.check", crate::LspControlAction::Check);
        check!(
            "lsp_control_action.install",
            crate::LspControlAction::Install
        );
        check!(
            "lsp_control_action.uninstall",
            crate::LspControlAction::Uninstall
        );
        check!(
            "lsp_control_action.restart",
            crate::LspControlAction::Restart
        );
        check!(
            "active_model_switch_trigger.picker",
            crate::ActiveModelSwitchTrigger::Picker
        );
        check!(
            "active_model_switch_trigger.quick",
            crate::ActiveModelSwitchTrigger::Quick
        );
        check!(
            "active_model_switch_trigger.cycle",
            crate::ActiveModelSwitchTrigger::Cycle
        );
        check!(
            "active_model_switch_trigger.daemon",
            crate::ActiveModelSwitchTrigger::Daemon
        );
        check!(
            "prompt_cache_retention.default",
            cockpit_config::config::providers::PromptCacheRetention::Default
        );
        check!(
            "prompt_cache_retention.extended",
            cockpit_config::config::providers::PromptCacheRetention::Extended
        );
        check!(
            "thinking_mode.off",
            cockpit_config::config::providers::ThinkingMode::Off
        );
        check!(
            "thinking_mode.low",
            cockpit_config::config::providers::ThinkingMode::Low
        );
        check!(
            "thinking_mode.medium",
            cockpit_config::config::providers::ThinkingMode::Medium
        );
        check!(
            "thinking_mode.high",
            cockpit_config::config::providers::ThinkingMode::High
        );
        check!(
            "env_snapshot_source.daemon_start",
            crate::EnvSnapshotSource::DaemonStart
        );
        check!(
            "env_snapshot_source.tui_shell",
            crate::EnvSnapshotSource::TuiShell
        );
        check!(
            "env_snapshot_source.tui_process_fallback",
            crate::EnvSnapshotSource::TuiProcessFallback
        );
        check!(
            "env_snapshot_source.explicit_cli",
            crate::EnvSnapshotSource::ExplicitCli
        );
        check!(
            "approval_mode.manual",
            cockpit_config::config::extended::ApprovalMode::Manual
        );
        check!(
            "approval_mode.auto",
            cockpit_config::config::extended::ApprovalMode::Auto
        );
        check!(
            "approval_mode.yolo",
            cockpit_config::config::extended::ApprovalMode::Yolo
        );
        check!(
            "sandbox_mode.off",
            cockpit_config::config::sandbox_mode::SandboxMode::Off
        );
        check!(
            "sandbox_mode.sandbox",
            cockpit_config::config::sandbox_mode::SandboxMode::Sandbox
        );
        check!(
            "sandbox_mode.container",
            cockpit_config::config::sandbox_mode::SandboxMode::Container
        );
        check!(
            "sandbox_mode.container_readonly",
            cockpit_config::config::sandbox_mode::SandboxMode::ContainerReadonly
        );
        check!(
            "goal_disposition.running",
            cockpit_db::db::session_goals::GoalDisposition::Running
        );
        check!(
            "goal_disposition.user_paused",
            cockpit_db::db::session_goals::GoalDisposition::UserPaused
        );
        check!(
            "goal_disposition.infra_paused",
            cockpit_db::db::session_goals::GoalDisposition::InfraPaused
        );
        check!(
            "goal_disposition.blocked",
            cockpit_db::db::session_goals::GoalDisposition::Blocked
        );
        check!(
            "goal_disposition.no_progress_paused",
            cockpit_db::db::session_goals::GoalDisposition::NoProgressPaused
        );
        check!(
            "goal_disposition.budget_limited",
            cockpit_db::db::session_goals::GoalDisposition::BudgetLimited
        );
        check!(
            "goal_disposition.complete",
            cockpit_db::db::session_goals::GoalDisposition::Complete
        );
        check!(
            "goal_disposition.cleared",
            cockpit_db::db::session_goals::GoalDisposition::Cleared
        );
        check!(
            "attachment_purpose.user_message_image",
            crate::AttachmentPurpose::UserMessageImage
        );
        check!("missed_run_policy.skip", crate::MissedRunPolicy::Skip);
        check!(
            "missed_run_policy.run_once_on_start",
            crate::MissedRunPolicy::RunOnceOnStart
        );
        check_prefix!(
            "scheduled_job_schedule.cron",
            crate::ScheduledJobSchedule::Cron { expr: "x".into() }
        );
        check_prefix!(
            "scheduled_job_schedule.every",
            crate::ScheduledJobSchedule::Every { seconds: 1 }
        );
        check_prefix!(
            "scheduled_job_schedule.once",
            crate::ScheduledJobSchedule::Once { at: 1 }
        );
        check_prefix!(
            "scheduled_job_schedule.idle",
            crate::ScheduledJobSchedule::Idle {
                min_idle_seconds: 1,
                max_age_seconds: 2
            }
        );
        check_prefix!(
            "scheduled_job_payload.run_prompt",
            crate::ScheduledJobPayload::RunPrompt {
                assistant: "a".into(),
                prompt: "p".into(),
                project_root: "/ignored".into()
            }
        );
        check_prefix!(
            "scheduled_job_payload.callback",
            crate::ScheduledJobPayload::Callback {
                subsystem: "s".into()
            }
        );
        check_prefix!("curator_action.status", crate::CuratorAction::Status);
        check_prefix!(
            "curator_action.run",
            crate::CuratorAction::Run {
                dry_run: false,
                consolidate: true
            }
        );
        check_prefix!(
            "curator_action.pin",
            crate::CuratorAction::Pin { name: "n".into() }
        );
        check_prefix!(
            "curator_action.unpin",
            crate::CuratorAction::Unpin { name: "n".into() }
        );
        check_prefix!(
            "curator_action.restore",
            crate::CuratorAction::Restore { name: "n".into() }
        );
        check_prefix!(
            "curator_action.rollback",
            crate::CuratorAction::Rollback {
                list: true,
                id: None
            }
        );
    }

    #[test]
    fn fcor_cross_language_vector_is_exact() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote-operation-fcor-v1.json"
        ))
        .unwrap();
        let bytes = encode_fcor_v1(
            fixture["requestKind"].as_str().unwrap(),
            &[RemoteOperationResource {
                kind: RemoteOperationResourceKind::DaemonGlobal,
                value: &[],
            }],
            &[],
        )
        .unwrap();
        assert_eq!(hex(&bytes), fixture["canonicalHex"].as_str().unwrap());
        assert_eq!(
            hex(&hash_fcor_v1(&bytes).unwrap()),
            fixture["sha256Hex"].as_str().unwrap()
        );
        assert!(encode_fcor_v1("DaemonStatus", &[], &[]).is_err());
        for malformed in fixture["malformed"].as_array().unwrap() {
            let mut candidate = bytes.clone();
            if let Some(replacement) = malformed["replaceByte"].as_array() {
                candidate[replacement[0].as_u64().unwrap() as usize] =
                    replacement[1].as_u64().unwrap() as u8;
            }
            if let Some(truncate_by) = malformed["truncateBy"].as_u64() {
                candidate.truncate(candidate.len() - truncate_by as usize);
            }
            if let Some(append_hex) = malformed["appendHex"].as_str() {
                candidate.extend_from_slice(&decode_hex(append_hex));
            }
            assert!(
                validate_fcor_v1(&candidate).is_err(),
                "malformed vector unexpectedly valid: {}",
                malformed["name"]
            );
        }
        let rich = &fixture["richPositive"];
        let rich_values: Vec<Vec<u8>> = rich["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|resource| decode_hex(resource["valueHex"].as_str().unwrap()))
            .collect();
        let rich_resources: Vec<_> = rich["resources"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&rich_values)
            .map(|(resource, value)| RemoteOperationResource {
                kind: match resource["kind"].as_str().unwrap() {
                    "project_root" => RemoteOperationResourceKind::ProjectRoot,
                    "file_path" => RemoteOperationResourceKind::FilePath,
                    other => panic!("unexpected fixture kind {other}"),
                },
                value,
            })
            .collect();
        let rich_bytes = encode_fcor_v1(
            rich["requestKind"].as_str().unwrap(),
            &rich_resources,
            &decode_hex(rich["paramsHex"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(hex(&rich_bytes), rich["canonicalHex"].as_str().unwrap());
        assert_eq!(
            hex(&hash_fcor_v1(&rich_bytes).unwrap()),
            rich["sha256Hex"].as_str().unwrap()
        );
        for boundary in fixture["sizeCases"].as_array().unwrap() {
            let result = checked_fcor_v1_size(
                boundary["kindLength"].as_u64().unwrap(),
                boundary["resourceLengths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_u64().unwrap()),
                boundary["paramsLength"].as_u64().unwrap(),
            );
            assert_eq!(result.is_ok(), boundary["valid"].as_bool().unwrap());
        }
        for shape in fixture["shapeCases"].as_array().unwrap() {
            let value = vec![0; shape["valueLength"].as_u64().unwrap() as usize];
            let kind = match shape["kind"].as_str().unwrap() {
                "daemon_global" => RemoteOperationResourceKind::DaemonGlobal,
                "session_uuid" => RemoteOperationResourceKind::SessionUuid,
                other => panic!("unexpected fixture kind {other}"),
            };
            let result = encode_fcor_v1(
                "status",
                &[RemoteOperationResource {
                    kind,
                    value: &value,
                }],
                &[],
            );
            assert_eq!(result.is_ok(), shape["valid"].as_bool().unwrap());
        }
        let mut primitive = CanonicalParamsV1::new();
        primitive.push_u8(0xff);
        primitive.push_bool(true);
        primitive.push_u16(0x1234);
        primitive.push_u32(0x01020304);
        primitive.push_u64(0x0102030405060708);
        primitive.push_i64(-2);
        primitive.push_uuid(Uuid::from_bytes(core::array::from_fn(|index| index as u8)));
        assert_eq!(
            hex(&primitive.into_bytes()),
            fixture["canonicalParams"]["primitiveHex"].as_str().unwrap()
        );
        let mut map = CanonicalParamsV1::new();
        map.push_string_map([("b", "y"), ("a", "x")]).unwrap();
        assert_eq!(
            hex(&map.into_bytes()),
            fixture["canonicalParams"]["sortedStringMapHex"]
                .as_str()
                .unwrap()
        );
        for invalid in fixture["invalidCanonicalCases"].as_array().unwrap() {
            let error = match invalid["kind"].as_str().unwrap() {
                "string" => CanonicalParamsV1::new()
                    .push_string(invalid["value"].as_str().unwrap())
                    .unwrap_err(),
                "utf16_string" => {
                    let units: Vec<u16> = invalid["codeUnits"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|unit| unit.as_u64().unwrap() as u16)
                        .collect();
                    validate_utf16_canonical_boundary(&units).unwrap_err()
                }
                "string_map" => {
                    let entries: Vec<(&str, &str)> = invalid["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|entry| {
                            let pair = entry.as_array().unwrap();
                            (pair[0].as_str().unwrap(), pair[1].as_str().unwrap())
                        })
                        .collect();
                    CanonicalParamsV1::new()
                        .push_string_map(entries)
                        .unwrap_err()
                }
                other => panic!("unknown invalid canonical case {other}"),
            };
            assert_eq!(
                canonical_param_error_code(&error).unwrap().as_str(),
                invalid["errorClass"].as_str().unwrap(),
                "{}",
                invalid["name"]
            );
        }
        let boundary = |encode: fn(&mut CanonicalParamsV1) -> Result<()>| {
            let mut params = CanonicalParamsV1::new();
            encode(&mut params).unwrap();
            hex(&params.into_bytes())
        };
        assert_eq!(
            boundary(|p| {
                p.push_u64(u64::MAX);
                Ok(())
            }),
            fixture["canonicalParams"]["u64MaxHex"]
        );
        assert_eq!(
            boundary(|p| {
                p.push_i64(i64::MIN);
                Ok(())
            }),
            fixture["canonicalParams"]["i64MinHex"]
        );
        assert_eq!(
            boundary(|p| {
                p.push_i64(i64::MAX);
                Ok(())
            }),
            fixture["canonicalParams"]["i64MaxHex"]
        );
        assert_eq!(
            boundary(|p| p.push_optional::<u8>(None, |_, _| Ok(()))),
            fixture["canonicalParams"]["optionNoneHex"]
        );
        assert_eq!(
            boundary(|p| p.push_optional(Some(&0x1234_u16), |nested, value| {
                nested.push_u16(*value);
                Ok(())
            })),
            fixture["canonicalParams"]["optionSomeU16Hex"]
        );
        assert_eq!(
            boundary(|p| p.push_bytes(&[])),
            fixture["canonicalParams"]["emptyBytesHex"]
        );
        assert_eq!(
            boundary(|p| p.push_string("é")),
            fixture["canonicalParams"]["composedStringHex"]
        );
        assert_eq!(
            boundary(|p| p.push_string_map([("aa", "y"), ("b", "x")])),
            fixture["canonicalParams"]["encodedLengthSortedMapHex"]
        );
        let mut rollback = CanonicalParamsV1::new();
        assert!(
            rollback
                .push_optional(Some(&1_u8), |nested, _| {
                    nested.push_u8(7);
                    bail!("fail")
                })
                .is_err()
        );
        assert!(rollback.into_bytes().is_empty());
        for item in fixture["primitiveBoundaryCases"].as_array().unwrap() {
            let value = item["value"].as_str().unwrap();
            let mut params = CanonicalParamsV1::new();
            let result = match item["codec"].as_str().unwrap() {
                "u8" => value.parse::<u8>().map(|value| params.push_u8(value)),
                "u16" => value.parse::<u16>().map(|value| params.push_u16(value)),
                "u32" => value.parse::<u32>().map(|value| params.push_u32(value)),
                "u64" => value.parse::<u64>().map(|value| params.push_u64(value)),
                other => panic!("unknown primitive codec {other}"),
            };
            assert_eq!(result.is_ok(), item["valid"].as_bool().unwrap());
            if result.is_ok() {
                assert_eq!(hex(&params.into_bytes()), item["hex"].as_str().unwrap());
            }
        }
        assert_eq!(
            boundary(|p| {
                p.push_bool(false);
                Ok(())
            }),
            fixture["collectionCases"]["boolFalseHex"]
        );
        assert_eq!(
            boundary(|p| {
                p.push_bool(true);
                Ok(())
            }),
            fixture["collectionCases"]["boolTrueHex"]
        );
        assert_eq!(
            boundary(|p| p.push_bytes(&[0, 255])),
            fixture["collectionCases"]["nonemptyBytesHex"]
        );
        assert_eq!(
            boundary(|p| p.push_string("a")),
            fixture["collectionCases"]["nonemptyStringHex"]
        );
        assert_eq!(
            boundary(|p| p.push_string_map([])),
            fixture["collectionCases"]["emptyMapHex"]
        );
        assert_eq!(
            boundary(|p| p.push_string_map([("a", "x")])),
            fixture["collectionCases"]["singleMapHex"]
        );
        assert_eq!(
            boundary(|p| p.push_list(std::iter::empty::<&u8>(), |_, _| Ok(()))),
            fixture["collectionCases"]["emptyListHex"]
        );
        assert_eq!(
            boundary(|p| p.push_list([1_u16, 258].iter(), |item, value| {
                item.push_u16(*value);
                Ok(())
            })),
            fixture["collectionCases"]["u16ListHex"]
        );
        let mut list_rollback = CanonicalParamsV1::new();
        assert!(
            list_rollback
                .push_list([1_u8].iter(), |item, _| {
                    item.push_u8(7);
                    bail!("fail")
                })
                .is_err()
        );
        assert!(list_rollback.into_bytes().is_empty());

        struct FoundationDecoder;
        impl OpaqueCanonicalParamsDecoder for FoundationDecoder {
            fn owner(&self) -> &'static str {
                "message-attachment-protocol-foundation"
            }
            fn validate(&self, bytes: &[u8]) -> Result<()> {
                ensure!(bytes == b"FCM2foundation-owned", "semantic rejection");
                Ok(())
            }
        }
        let opaque = b"FCM2foundation-owned";
        validate_registered_opaque_params(
            SEND_USER_MESSAGE_V2_REGISTRATION,
            opaque,
            &FoundationDecoder,
        )
        .unwrap();
        let fcor = encode_fcor_v1("send_user_message", &[], opaque).unwrap();
        assert!(
            fcor.ends_with(opaque),
            "ledger must embed FCM2 byte-identically"
        );
        assert!(
            validate_registered_opaque_params(
                OpaqueCanonicalParamsRegistrationV1 {
                    request_kind: "other",
                    ..SEND_USER_MESSAGE_V2_REGISTRATION
                },
                opaque,
                &FoundationDecoder,
            )
            .is_err()
        );
        struct RejectingFoundationDecoder;
        impl OpaqueCanonicalParamsDecoder for RejectingFoundationDecoder {
            fn owner(&self) -> &'static str {
                "message-attachment-protocol-foundation"
            }
            fn validate(&self, _bytes: &[u8]) -> Result<()> {
                bail!("semantic rejection")
            }
        }
        assert!(
            validate_registered_opaque_params(
                SEND_USER_MESSAGE_V2_REGISTRATION,
                opaque,
                &RejectingFoundationDecoder,
            )
            .is_err()
        );
        assert!(
            validate_registered_opaque_params(
                SEND_USER_MESSAGE_V2_REGISTRATION,
                b"BAD!foundation-owned",
                &FoundationDecoder,
            )
            .is_err()
        );
    }

    #[test]
    fn remote_operation_fcm2_limit_rejects_oversized_opaque_bytes_before_decoder() {
        struct RecordingFoundationDecoder(std::sync::atomic::AtomicBool);

        impl OpaqueCanonicalParamsDecoder for RecordingFoundationDecoder {
            fn owner(&self) -> &'static str {
                "message-attachment-protocol-foundation"
            }

            fn validate(&self, bytes: &[u8]) -> Result<()> {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                ensure!(bytes.starts_with(&FCM2_MAGIC), "decoder saw invalid FCM2");
                Ok(())
            }
        }

        let decoder = RecordingFoundationDecoder(std::sync::atomic::AtomicBool::new(false));
        let mut exact = vec![0_u8; MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES];
        exact[..FCM2_MAGIC.len()].copy_from_slice(&FCM2_MAGIC);
        validate_registered_opaque_params(SEND_USER_MESSAGE_V2_REGISTRATION, &exact, &decoder)
            .expect("the exact registered FCM2 allocation boundary reaches its owner decoder");
        assert!(decoder.0.load(std::sync::atomic::Ordering::SeqCst));
        let fcor = encode_fcor_v1("send_user_message", &[], &exact).unwrap();
        assert!(fcor.ends_with(&exact), "FCOR preserves FCM2 bytes exactly");

        decoder.0.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut oversized = vec![0_u8; MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES + 1];
        oversized[..FCM2_MAGIC.len()].copy_from_slice(&FCM2_MAGIC);
        assert!(
            validate_registered_opaque_params(
                SEND_USER_MESSAGE_V2_REGISTRATION,
                &oversized,
                &decoder,
            )
            .is_err(),
            "the remote-operation boundary rejects FCM2 before owner decoding"
        );
        assert!(
            !decoder.0.load(std::sync::atomic::Ordering::SeqCst),
            "over-limit opaque bytes cannot reach a decoder/ledger side effect"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
