//! Recheck-then-apply-or-instruct for Settings, `/sandbox`, and `/quick`.
//!
//! Missing host capabilities are never persisted. Selecting a disabled option
//! refreshes the snapshot first; if the capability is still missing the
//! previous value stays and the snapshot remedy is shown.

use cockpit_core::daemon::session_worker::{sandbox_mode_available, sandbox_mode_selectable};
use cockpit_core::host_capabilities::{
    FEATURE_MEDIA_DECODE, FEATURE_SANDBOX_CONTAINER, FEATURE_SANDBOX_HOST,
    FEATURE_SECRET_STORE_KEYRING,
};
use cockpit_core::tools::sandbox_mode::SandboxMode;
#[cfg(test)]
use cockpit_proto::SecretStoreSnapshot;
use cockpit_proto::{
    FeatureCapabilityRow, FeatureCapabilityState, HostCapabilitySnapshot, SecretStoreIntent,
    SecretStorePlacement,
};

use crate::tui::dialog::{DialogOption, DialogState, Page};

pub const SECRET_STORE_KEYRING_LABEL: &str = "OS keyring";
pub const SECRET_STORE_DATABASE_LABEL: &str = "Database (encrypted, local KEK file)";
pub const SECRET_STORE_HELP: &str = "Where the wrapping key for encrypted secret storage lives. \
     OS keyring keeps the wrapping key in the platform store. Database mode \
     is weaker than the OS keyring: it uses a local private_fs KEK file plus \
     encrypted SQLite (wrapped DEK + AEAD ciphertext). First-run persists \
     the OS keyring when the probe is available, otherwise database.";
pub const SECRET_STORE_DATABASE_REJECTED: &str =
    "cannot place the wrapping key in the database while the OS keyring is available";
pub const SECRET_STORE_DOWNGRADE_PROMPT: &str = "Move secret storage off the OS keyring?\n\n\
     This is weaker than the OS keyring.\n\
     The wrapping key will leave the OS keyring.\n\
     The new at-rest story is a local private_fs KEK file plus encrypted \
     SQLite (wrapped DEK + AEAD ciphertext).";

pub const SECRET_STORE_CONFIRM_ID: &str = "confirm";
pub const SECRET_STORE_CANCEL_ID: &str = "cancel";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityInstruct {
    pub message: String,
    pub fix_command: Option<String>,
}

impl CapabilityInstruct {
    pub fn display(&self) -> String {
        match &self.fix_command {
            Some(fix) if !self.message.contains(fix) => {
                format!("{} Fix: {fix}", self.message)
            }
            _ => self.message.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecheckApply<T> {
    Applied(T),
    Instruct(CapabilityInstruct),
}

pub fn feature_row<'a>(
    caps: &'a HostCapabilitySnapshot,
    id: &str,
) -> Option<&'a FeatureCapabilityRow> {
    caps.feature(id)
}

pub fn format_feature_remedy(row: &FeatureCapabilityRow) -> CapabilityInstruct {
    let mut message = row.reason.clone();
    if let Some(remedy) = &row.remedy_text
        && !message.contains(remedy)
    {
        message.push(' ');
        message.push_str(remedy);
    }
    CapabilityInstruct {
        message,
        fix_command: row.fix_command.clone(),
    }
}

pub fn sandbox_instruct(mode: SandboxMode, caps: &HostCapabilitySnapshot) -> CapabilityInstruct {
    let id = match mode {
        SandboxMode::Off => {
            return CapabilityInstruct {
                message: "sandbox off is always available".into(),
                fix_command: None,
            };
        }
        SandboxMode::Sandbox => FEATURE_SANDBOX_HOST,
        SandboxMode::Container | SandboxMode::ContainerReadonly => FEATURE_SANDBOX_CONTAINER,
    };
    match feature_row(caps, id) {
        Some(row) => format_feature_remedy(row),
        None => CapabilityInstruct {
            message: format!("{id} is unavailable"),
            fix_command: None,
        },
    }
}

pub fn keyring_instruct(caps: &HostCapabilitySnapshot) -> CapabilityInstruct {
    match feature_row(caps, FEATURE_SECRET_STORE_KEYRING) {
        Some(row) => format_feature_remedy(row),
        None => CapabilityInstruct {
            message: "OS keyring is unavailable".into(),
            fix_command: caps
                .secret_store
                .fix_command
                .clone()
                .or_else(|| Some(cockpit_core::secure_key::DEFAULT_FIX_COMMAND.to_string())),
        },
    }
}

pub fn media_decode_instruct(caps: &HostCapabilitySnapshot) -> CapabilityInstruct {
    match feature_row(caps, FEATURE_MEDIA_DECODE) {
        Some(row) => {
            let mut instruct = format_feature_remedy(row);
            if let Some(ffmpeg) = caps.dependency("media.ffmpeg") {
                if !instruct.message.contains(&ffmpeg.reason) {
                    instruct.message.push(' ');
                    instruct.message.push_str(&ffmpeg.reason);
                }
                if instruct.fix_command.is_none() {
                    instruct.fix_command = ffmpeg
                        .remedy
                        .as_ref()
                        .and_then(|remedy| remedy.get("command"))
                        .and_then(|value| value.as_str())
                        .map(str::to_string);
                }
            }
            if let Some(ffprobe) = caps.dependency("media.ffprobe")
                && !instruct.message.contains(&ffprobe.reason)
            {
                instruct.message.push(' ');
                instruct.message.push_str(&ffprobe.reason);
            }
            instruct
        }
        None => CapabilityInstruct {
            message: "media.ffmpeg / media.ffprobe are not available".into(),
            fix_command: None,
        },
    }
}

pub fn recheck_then_apply<T>(
    desired: T,
    available: impl Fn(&HostCapabilitySnapshot) -> bool,
    instruct: impl Fn(&HostCapabilitySnapshot) -> CapabilityInstruct,
    refresh: impl FnOnce() -> HostCapabilitySnapshot,
) -> RecheckApply<T> {
    let refreshed = refresh();
    if available(&refreshed) {
        RecheckApply::Applied(desired)
    } else {
        RecheckApply::Instruct(instruct(&refreshed))
    }
}

pub fn apply_sandbox_choice(
    requested: SandboxMode,
    caps: &HostCapabilitySnapshot,
    refresh: impl FnOnce() -> HostCapabilitySnapshot,
) -> RecheckApply<SandboxMode> {
    if sandbox_mode_available(requested, caps) {
        return RecheckApply::Applied(requested);
    }
    recheck_then_apply(
        requested,
        |next| sandbox_mode_available(requested, next),
        |next| sandbox_instruct(requested, next),
        refresh,
    )
}

pub fn apply_keyring_choice(
    caps: &HostCapabilitySnapshot,
    refresh: impl FnOnce() -> HostCapabilitySnapshot,
) -> RecheckApply<SecretStorePlacement> {
    let available = |snapshot: &HostCapabilitySnapshot| {
        snapshot
            .feature(FEATURE_SECRET_STORE_KEYRING)
            .is_some_and(|row| row.state == FeatureCapabilityState::Available)
    };
    if available(caps) {
        return RecheckApply::Applied(SecretStorePlacement::Keyring);
    }
    recheck_then_apply(
        SecretStorePlacement::Keyring,
        available,
        keyring_instruct,
        refresh,
    )
}

/// Settings cycle: host Sandbox stays in the roster (visible, apply-gated).
/// Container modes stay skipped when unavailable.
pub fn settings_sandbox_cycle_modes(caps: &HostCapabilitySnapshot) -> Vec<SandboxMode> {
    let mut modes = vec![SandboxMode::Off, SandboxMode::Sandbox];
    if sandbox_mode_selectable(SandboxMode::Container, caps) {
        modes.push(SandboxMode::Container);
        modes.push(SandboxMode::ContainerReadonly);
    }
    modes
}

pub fn next_settings_sandbox_mode(
    current: SandboxMode,
    caps: &HostCapabilitySnapshot,
) -> SandboxMode {
    let modes = settings_sandbox_cycle_modes(caps);
    let idx = modes.iter().position(|mode| *mode == current).unwrap_or(0);
    modes[(idx + 1) % modes.len()]
}

/// Slash `/sandbox` cycle: skip every unavailable mode, including host Sandbox.
pub fn next_available_sandbox_mode(
    current: SandboxMode,
    caps: &HostCapabilitySnapshot,
) -> SandboxMode {
    let modes: Vec<SandboxMode> = [
        SandboxMode::Off,
        SandboxMode::Sandbox,
        SandboxMode::Container,
        SandboxMode::ContainerReadonly,
    ]
    .into_iter()
    .filter(|mode| sandbox_mode_available(*mode, caps))
    .collect();
    if modes.is_empty() {
        return SandboxMode::Off;
    }
    let idx = modes.iter().position(|mode| *mode == current).unwrap_or(0);
    modes[(idx + 1) % modes.len()]
}

pub fn sandbox_mode_display(mode: SandboxMode, caps: &HostCapabilitySnapshot) -> String {
    let label = match mode {
        SandboxMode::Off => "off".to_string(),
        SandboxMode::Sandbox => {
            let mut label = "on (default host filesystem sandbox)".to_string();
            if !sandbox_mode_available(mode, caps) {
                let instruct = sandbox_instruct(mode, caps);
                label.push_str(" (unavailable");
                if let Some(fix) = &instruct.fix_command {
                    label.push_str(": ");
                    label.push_str(fix);
                } else if !instruct.message.is_empty() {
                    label.push_str(": ");
                    label.push_str(&instruct.message);
                }
                label.push(')');
            }
            label
        }
        SandboxMode::Container => "container".to_string(),
        SandboxMode::ContainerReadonly => "container-readonly".to_string(),
    };
    if mode.is_container() && !sandbox_mode_available(mode, caps) {
        format!("{label} (unavailable here)")
    } else {
        label
    }
}

pub fn secret_store_switcher_enabled(caps: &HostCapabilitySnapshot) -> bool {
    !matches!(caps.secret_store.intent, SecretStoreIntent::Unconfigured)
}

pub fn secret_store_row_value(caps: &HostCapabilitySnapshot) -> String {
    match (
        caps.secret_store.intent,
        caps.secret_store.effective_placement,
    ) {
        (SecretStoreIntent::Keyring, SecretStorePlacement::Keyring) => {
            SECRET_STORE_KEYRING_LABEL.to_string()
        }
        (SecretStoreIntent::Keyring, SecretStorePlacement::Unavailable) => {
            let mut label = format!("{SECRET_STORE_KEYRING_LABEL} (unavailable)");
            if let Some(fix) = &caps.secret_store.fix_command {
                label.push_str(": ");
                label.push_str(fix);
            } else if let Some(reason) = &caps.secret_store.fail_closed_reason {
                label.push_str(": ");
                label.push_str(reason);
            }
            label
        }
        _ => SECRET_STORE_DATABASE_LABEL.to_string(),
    }
}

pub fn secret_store_row_help(_caps: &HostCapabilitySnapshot) -> &'static str {
    SECRET_STORE_HELP
}

pub fn displayed_secret_store_placement(caps: &HostCapabilitySnapshot) -> SecretStorePlacement {
    match caps.secret_store.effective_placement {
        SecretStorePlacement::Keyring => SecretStorePlacement::Keyring,
        SecretStorePlacement::Database | SecretStorePlacement::Unavailable => {
            match caps.secret_store.intent {
                SecretStoreIntent::Keyring => SecretStorePlacement::Keyring,
                _ => SecretStorePlacement::Database,
            }
        }
    }
}

pub fn next_secret_store_placement(current: SecretStorePlacement) -> SecretStorePlacement {
    match current {
        SecretStorePlacement::Keyring => SecretStorePlacement::Database,
        SecretStorePlacement::Database | SecretStorePlacement::Unavailable => {
            SecretStorePlacement::Keyring
        }
    }
}

pub fn secret_store_downgrade_dialog() -> DialogState {
    DialogState::new_preselected(
        vec![
            Page::select(
                SECRET_STORE_DOWNGRADE_PROMPT,
                vec![
                    DialogOption::new(SECRET_STORE_CONFIRM_ID, "Confirm"),
                    DialogOption::new(SECRET_STORE_CANCEL_ID, "Cancel"),
                ],
            )
            .permission(),
        ],
        DialogState::NO_LOCKOUT,
        &[vec![SECRET_STORE_CONFIRM_ID.to_string()]],
    )
}

pub fn sandbox_intent_effective_banner(
    intent: SandboxMode,
    effective: SandboxMode,
    caps: &HostCapabilitySnapshot,
) -> Option<String> {
    if intent == SandboxMode::Off || effective != SandboxMode::Off || intent == effective {
        return None;
    }
    let instruct = sandbox_instruct(intent, caps);
    let label = match intent {
        SandboxMode::Sandbox => "Sandbox",
        SandboxMode::Container => "Container",
        SandboxMode::ContainerReadonly => "Container-readonly",
        SandboxMode::Off => "Off",
    };
    let mut text = format!(
        "{label} is selected but effective Off because {}.",
        instruct.message
    );
    if let Some(fix) = &instruct.fix_command
        && !text.contains(fix)
    {
        text.push_str(" Install/fix: ");
        text.push_str(fix);
        text.push('.');
    }
    text.push_str(" Run /sandbox off to keep Off.");
    Some(text)
}

/// Daemon-less / pre-attach recheck: compose host + container availability
/// from in-process probes. Secret-store stays at the current unconfigured
/// placeholder until a daemon snapshot arrives.
pub fn empty_capability_snapshot() -> HostCapabilitySnapshot {
    HostCapabilitySnapshot::unpublished()
}

#[cfg(test)]
pub fn snapshot_with_sandbox(
    host: FeatureCapabilityState,
    container: FeatureCapabilityState,
) -> HostCapabilitySnapshot {
    cockpit_core::daemon::session_worker::sandbox_capability_snapshot(host, container)
}

#[cfg(test)]
pub fn snapshot_with_sandbox_reasons(
    host: FeatureCapabilityState,
    container: FeatureCapabilityState,
    host_reason: &str,
    host_fix: Option<&str>,
) -> HostCapabilitySnapshot {
    cockpit_core::daemon::session_worker::sandbox_capability_snapshot_with_reasons(
        host,
        container,
        host_reason,
        "container capability",
        host_fix.map(str::to_string),
        None,
    )
}

#[cfg(test)]
pub fn with_secret_store(
    mut caps: HostCapabilitySnapshot,
    secret_store: SecretStoreSnapshot,
    keyring: FeatureCapabilityState,
    keyring_reason: &str,
    keyring_fix: Option<&str>,
) -> HostCapabilitySnapshot {
    if let Some(row) = caps
        .features
        .iter_mut()
        .find(|row| row.id == FEATURE_SECRET_STORE_KEYRING)
    {
        row.state = keyring;
        row.reason = keyring_reason.to_string();
        row.fix_command = keyring_fix.map(str::to_string);
    } else {
        caps.features.push(FeatureCapabilityRow {
            id: FEATURE_SECRET_STORE_KEYRING.to_string(),
            state: keyring,
            reason: keyring_reason.to_string(),
            fix_command: keyring_fix.map(str::to_string),
            remedy_text: None,
            dependency_ids: vec!["security.keyring".to_string()],
        });
    }
    caps.secret_store = secret_store;
    caps
}

#[cfg(test)]
pub fn unified_secret_store(
    intent: SecretStoreIntent,
    placement: SecretStorePlacement,
) -> SecretStoreSnapshot {
    SecretStoreSnapshot {
        intent,
        effective_placement: placement,
        fail_closed_reason: None,
        fix_command: None,
    }
}
