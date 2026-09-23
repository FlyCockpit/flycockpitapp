//! Typed secure-key failures. No plaintext secret bytes and no unwrapped KEK
//! in SQLite; database backend is a `private_fs` file KEK plus wrap-key vault.

use std::fmt;

use crate::db::secure_key::SecureKeyInUseInfo;

/// Typed secure-key store errors. Distinct locked/denied/unavailable/corrupt/not-found.
#[derive(Clone)]
pub enum SecureKeyError {
    /// Namespace syntax or account component rejected.
    Invalid(String),
    /// OS store is locked.
    Locked(String),
    /// OS store denied access.
    Denied(String),
    /// OS store unavailable (missing service / unsupported platform).
    Unavailable(String),
    /// Manifest/version/saga disagreement that is not explained by an in-flight saga.
    Corrupt(String),
    /// Requested version/item not found.
    NotFound(String),
    /// Actor queue full (capacity 32).
    Busy,
    /// Retirement blocked by consumer references.
    InUse(SecureKeyInUseInfo),
    /// Version is Retiring; new reservations rejected.
    Retiring { namespace: String, version: i64 },
    /// Active version cannot be retired.
    ActiveVersion { namespace: String, version: i64 },
    /// Sealed-state CAS mismatch; safe current metadata only (no payload).
    /// `degraded` is true when only one slot is present (SealedHealth::Degraded).
    Conflict {
        namespace: String,
        generation: u64,
        payload_digest: [u8; 32],
        key_version: u32,
        degraded: bool,
    },
    /// Internal coordination failure (safe message only).
    Internal(String),
    /// KEK placement cannot be established. No file-KEK fallback when
    /// `active_placement` is keyring. Messages are nonsecret. `cause` is the
    /// typed class callers branch on; never classify by `reason` text.
    KekUnavailable {
        cause: KekFailureCause,
        reason: String,
        fix_command: Option<String>,
    },
}

/// Typed, nonsecret class of a KEK-placement failure. It is carried beside
/// the human-readable reason so boundaries (onboarding, doctor, the wire)
/// classify failures by type rather than by substring matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KekFailureCause {
    /// The platform keyring is missing, unsupported, or could not be reached.
    KeyringUnavailable,
    /// The platform keyring is present but locked.
    KeyringLocked,
    /// The platform keyring refused access.
    KeyringDenied,
    /// File-backed vaults are not supported by this build or platform.
    FileVaultUnsupported,
    /// The private vault directory or key file could not be created, secured,
    /// read, or written.
    VaultStorage,
    /// The passphrase could not derive or unlock the vault key, or a
    /// passphrase vault was opened without one.
    Passphrase,
    /// The requested options contradict each other or the durable vault.
    InvalidRequest,
    /// Local database or installation identity state could not be read or
    /// written.
    LocalState,
    /// Durable vault state is corrupt or inconsistent.
    Corrupt,
    /// Unclassified internal failure.
    Internal,
}

impl KekFailureCause {
    /// Typed classification of any secure-key failure. Only the platform
    /// keyring adapter produces `Locked`/`Denied`/`Unavailable`.
    pub fn of(error: &SecureKeyError) -> Self {
        match error {
            SecureKeyError::KekUnavailable { cause, .. } => *cause,
            SecureKeyError::Locked(_) => Self::KeyringLocked,
            SecureKeyError::Denied(_) => Self::KeyringDenied,
            SecureKeyError::Unavailable(_) => Self::KeyringUnavailable,
            SecureKeyError::Corrupt(_) | SecureKeyError::Conflict { .. } => Self::Corrupt,
            SecureKeyError::Invalid(_) => Self::InvalidRequest,
            SecureKeyError::NotFound(_)
            | SecureKeyError::Busy
            | SecureKeyError::InUse(_)
            | SecureKeyError::Retiring { .. }
            | SecureKeyError::ActiveVersion { .. }
            | SecureKeyError::Internal(_) => Self::Internal,
        }
    }
}

impl SecureKeyError {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "Invalid",
            Self::Locked(_) => "Locked",
            Self::Denied(_) => "Denied",
            Self::Unavailable(_) => "Unavailable",
            Self::Corrupt(_) => "Corrupt",
            Self::NotFound(_) => "NotFound",
            Self::Busy => "Busy",
            Self::InUse(_) => "InUse",
            Self::Retiring { .. } => "Retiring",
            Self::ActiveVersion { .. } => "ActiveVersion",
            Self::Conflict { .. } => "Conflict",
            Self::Internal(_) => "Internal",
            Self::KekUnavailable { .. } => "KekUnavailable",
        }
    }
}

impl fmt::Debug for SecureKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never include key bytes; messages are nonsecret.
        match self {
            Self::Invalid(m) => f.debug_tuple("Invalid").field(m).finish(),
            Self::Locked(m) => f.debug_tuple("Locked").field(m).finish(),
            Self::Denied(m) => f.debug_tuple("Denied").field(m).finish(),
            Self::Unavailable(m) => f.debug_tuple("Unavailable").field(m).finish(),
            Self::Corrupt(m) => f.debug_tuple("Corrupt").field(m).finish(),
            Self::NotFound(m) => f.debug_tuple("NotFound").field(m).finish(),
            Self::Busy => f.write_str("Busy"),
            Self::InUse(info) => f
                .debug_struct("InUse")
                .field("namespace", &info.namespace)
                .field("version", &info.version)
                .field("blocking_count", &info.blocking_refs.len())
                .finish(),
            Self::Retiring { namespace, version } => f
                .debug_struct("Retiring")
                .field("namespace", namespace)
                .field("version", version)
                .finish(),
            Self::ActiveVersion { namespace, version } => f
                .debug_struct("ActiveVersion")
                .field("namespace", namespace)
                .field("version", version)
                .finish(),
            Self::Conflict {
                namespace,
                generation,
                payload_digest,
                key_version,
                degraded,
            } => f
                .debug_struct("Conflict")
                .field("namespace", namespace)
                .field("generation", generation)
                .field(
                    "payload_digest",
                    &payload_digest
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                )
                .field("key_version", key_version)
                .field("degraded", degraded)
                .finish(),
            Self::Internal(m) => f.debug_tuple("Internal").field(m).finish(),
            Self::KekUnavailable {
                cause,
                reason,
                fix_command,
            } => f
                .debug_struct("KekUnavailable")
                .field("cause", cause)
                .field("reason", reason)
                .field("fix_command", fix_command)
                .finish(),
        }
    }
}

impl fmt::Display for SecureKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "secure key invalid: {m}"),
            Self::Locked(m) => write!(f, "secure key store locked: {m}"),
            Self::Denied(m) => write!(f, "secure key store denied: {m}"),
            Self::Unavailable(m) => write!(f, "secure key store unavailable: {m}"),
            Self::Corrupt(m) => write!(f, "secure key store corrupt: {m}"),
            Self::NotFound(m) => write!(f, "secure key not found: {m}"),
            Self::Busy => write!(f, "secure key actor busy"),
            Self::InUse(info) => write!(
                f,
                "secure key version {}/{} in use ({} refs)",
                info.namespace,
                info.version,
                info.blocking_refs.len()
            ),
            Self::Retiring { namespace, version } => {
                write!(f, "secure key version {namespace}/{version} is retiring")
            }
            Self::ActiveVersion { namespace, version } => write!(
                f,
                "secure key version {namespace}/{version} is active and cannot be retired"
            ),
            Self::Conflict {
                namespace,
                generation,
                key_version,
                ..
            } => write!(
                f,
                "sealed state conflict for {namespace} (generation {generation}, key v{key_version})"
            ),
            Self::Internal(m) => write!(f, "secure key internal error: {m}"),
            Self::KekUnavailable {
                reason,
                fix_command,
                ..
            } => match fix_command {
                Some(fix) => write!(f, "KEK unavailable: {reason} ({fix})"),
                None => write!(f, "KEK unavailable: {reason}"),
            },
        }
    }
}

impl std::error::Error for SecureKeyError {}

impl From<anyhow::Error> for SecureKeyError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

/// Map keyring-core errors into typed secure-key failures without secret material.
pub fn map_keyring_error(err: keyring_core::Error) -> SecureKeyError {
    use keyring_core::Error as Ke;
    match err {
        Ke::NoEntry => SecureKeyError::NotFound("native item missing".into()),
        Ke::NoStorageAccess(e) => {
            let msg = e.to_string();
            let lower = msg.to_ascii_lowercase();
            if lower.contains("lock") {
                SecureKeyError::Locked(msg)
            } else if lower.contains("denied") || lower.contains("permission") {
                SecureKeyError::Denied(msg)
            } else {
                SecureKeyError::Unavailable(msg)
            }
        }
        Ke::PlatformFailure(e) => {
            let msg = e.to_string();
            let lower = msg.to_ascii_lowercase();
            if lower.contains("lock") {
                SecureKeyError::Locked(msg)
            } else if lower.contains("denied") || lower.contains("permission") {
                SecureKeyError::Denied(msg)
            } else {
                SecureKeyError::Unavailable(msg)
            }
        }
        Ke::BadEncoding(_) | Ke::BadDataFormat(_, _) | Ke::BadStoreFormat(_) => {
            SecureKeyError::Corrupt("native item encoding/format invalid".into())
        }
        Ke::Ambiguous(_) => SecureKeyError::Corrupt("ambiguous native item match".into()),
        Ke::NoDefaultStore => SecureKeyError::Unavailable("no default keyring store".into()),
        Ke::NotSupportedByStore(m) => SecureKeyError::Unavailable(m),
        Ke::TooLong(name, limit) => {
            SecureKeyError::Invalid(format!("attribute {name} exceeds limit {limit}"))
        }
        Ke::Invalid(name, reason) => SecureKeyError::Invalid(format!("invalid {name}: {reason}")),
        other => SecureKeyError::Unavailable(other.to_string()),
    }
}
