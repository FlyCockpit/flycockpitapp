//! Independent image/audio/video capability override editor.
//!
//! One editor reducer plus an orthogonal refresh reducer. Save and refresh
//! cannot start concurrently. Async completions are generation- and
//! operation-id keyed so a late result for a superseded selection cannot
//! mutate draft, effective, preview, error, or busy state.

use cockpit_config::providers::{
    CapabilityStatus, EffectiveCapabilitySource, ResolvedInputCapability,
};

/// Which input modality row is being edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaModality {
    Image,
    Audio,
    Video,
}

impl MediaModality {
    pub const ALL: [Self; 3] = [Self::Image, Self::Audio, Self::Video];

    pub fn label(self) -> &'static str {
        match self {
            Self::Image => "Image",
            Self::Audio => "Audio",
            Self::Video => "Video",
        }
    }
}

/// Draft override: Auto (absent), Supported, or Unsupported only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DraftOverride {
    #[default]
    Auto,
    Supported,
    Unsupported,
}

impl DraftOverride {
    pub fn cycle(self) -> Self {
        match self {
            Self::Auto => Self::Supported,
            Self::Supported => Self::Unsupported,
            Self::Unsupported => Self::Auto,
        }
    }

    pub fn as_capability_status(self) -> Option<CapabilityStatus> {
        match self {
            Self::Auto => None,
            Self::Supported => Some(CapabilityStatus::Supported),
            Self::Unsupported => Some(CapabilityStatus::Unsupported),
        }
    }

    pub fn from_capability_status(status: Option<CapabilityStatus>) -> Self {
        match status {
            Some(CapabilityStatus::Supported) => Self::Supported,
            Some(CapabilityStatus::Unsupported) => Self::Unsupported,
            Some(CapabilityStatus::RequiresEntitlement | CapabilityStatus::Unknown) | None => {
                Self::Auto
            }
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto",
            Self::Supported => "Supported",
            Self::Unsupported => "Unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionIdentity {
    pub provider_id: String,
    pub model_id: String,
    pub selection_generation: u64,
    pub config_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModalitySnapshot {
    pub draft: DraftOverride,
    pub effective: ResolvedInputCapability,
    pub detected: ResolvedInputCapability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultimodalSnapshot {
    pub image: ModalitySnapshot,
    pub audio: ModalitySnapshot,
    pub video: ModalitySnapshot,
}

impl MultimodalSnapshot {
    pub fn row(&self, modality: MediaModality) -> &ModalitySnapshot {
        match modality {
            MediaModality::Image => &self.image,
            MediaModality::Audio => &self.audio,
            MediaModality::Video => &self.video,
        }
    }

    pub fn row_mut(&mut self, modality: MediaModality) -> &mut ModalitySnapshot {
        match modality {
            MediaModality::Image => &mut self.image,
            MediaModality::Audio => &mut self.audio,
            MediaModality::Video => &mut self.video,
        }
    }

    pub fn drafts_equal(&self, other: &Self) -> bool {
        self.image.draft == other.image.draft
            && self.audio.draft == other.audio.draft
            && self.video.draft == other.video.draft
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditorPhase {
    Clean {
        saved_generation: u64,
    },
    Dirty,
    Saving {
        save_id: OperationId,
        selection_generation: u64,
        base_config_generation: u64,
    },
    SaveFailed {
        reason: String,
    },
    Conflict {
        current_safe_generation: u64,
    },
    UnavailableClean,
    UnavailableDirty {
        draft: MultimodalSnapshot,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshPhase {
    Idle,
    Refreshing {
        refresh_id: OperationId,
        selection_generation: u64,
        config_generation: u64,
    },
    RefreshFailed {
        safe_reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessibilityAnnouncement {
    Refreshing {
        provider: String,
        model: String,
    },
    OverrideSet {
        modality: MediaModality,
        draft: DraftOverride,
    },
    Saved,
    SaveFailed {
        reason: String,
    },
    SettingsChangedElsewhere,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditorAction {
    Edit {
        modality: MediaModality,
        draft: DraftOverride,
    },
    Cycle {
        modality: MediaModality,
    },
    Save,
    SaveSuccess {
        save_id: OperationId,
        provider_id: String,
        model_id: String,
        selection_generation: u64,
        base_config_generation: u64,
        saved_generation: u64,
        authoritative: MultimodalSnapshot,
    },
    SaveSafeFailure {
        save_id: OperationId,
        provider_id: String,
        model_id: String,
        selection_generation: u64,
        base_config_generation: u64,
        reason: String,
    },
    SaveVersionConflict {
        save_id: OperationId,
        provider_id: String,
        model_id: String,
        selection_generation: u64,
        base_config_generation: u64,
        current_safe_generation: u64,
        authoritative: MultimodalSnapshot,
    },
    Retry,
    Reload {
        authoritative: MultimodalSnapshot,
    },
    Discard {
        authoritative: MultimodalSnapshot,
    },
    Reapply {
        authoritative: MultimodalSnapshot,
    },
    ModelRemoved,
    ModelReappeared {
        identity: SelectionIdentity,
        authoritative: MultimodalSnapshot,
    },
    Rebind {
        identity: SelectionIdentity,
        authoritative: MultimodalSnapshot,
    },
    SelectionChanged {
        identity: SelectionIdentity,
        authoritative: MultimodalSnapshot,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshAction {
    Refresh,
    RefreshSuccess {
        refresh_id: OperationId,
        selection_generation: u64,
        config_generation: u64,
        detected: MultimodalSnapshot,
    },
    RefreshFailure {
        refresh_id: OperationId,
        selection_generation: u64,
        config_generation: u64,
        safe_reason: String,
    },
    Retry,
    Dismiss,
}

/// Bound free-form error text so accessibility/status never carry secrets.
///
/// Strips bearer/authorization material, long high-entropy tokens, and caps
/// length so save/refresh failures never project raw credentials.
pub fn sanitize_user_facing_error(raw: impl Into<String>) -> String {
    const CAP: usize = 160;
    let raw = raw.into();
    let mut out = String::with_capacity(raw.len().min(CAP));
    let mut redact_next = false;
    for token in raw.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        let is_auth_keyword = lower == "bearer"
            || lower.starts_with("bearer:")
            || lower == "authorization"
            || lower.starts_with("authorization:")
            || lower == "basic"
            || lower.starts_with("basic:");
        let is_secret_key_prefix = {
            let key = lower.trim_end_matches(':');
            [
                "token",
                "password",
                "secret",
                "api_key",
                "apikey",
                "access_token",
                "refresh_token",
                "authorization",
            ]
            .iter()
            .any(|n| key == *n || key.ends_with(&format!("_{n}")) || key.contains(n))
                && (lower.ends_with(':') || token.contains('=') || token.contains(':'))
        };
        // After Authorization:/Bearer/secret-key:, redact the following value.
        let redacted = if redact_next {
            // Keep redacting if this token is still an auth scheme keyword.
            redact_next = is_auth_keyword || is_secret_key_prefix;
            "[redacted]".into()
        } else {
            let mut t = redact_error_token(token);
            if is_auth_keyword || is_secret_key_prefix {
                redact_next = true;
                t = "[redacted]".into();
            }
            t
        };
        if !out.is_empty() {
            out.push(' ');
        }
        if out.len() + redacted.len() > CAP {
            out.push('…');
            break;
        }
        out.push_str(&redacted);
    }
    if out.is_empty() { "error".into() } else { out }
}

fn redact_error_token(token: &str) -> String {
    let lower = token.to_ascii_lowercase();
    // Authorization: Bearer <token> and key=value secret forms.
    if lower.starts_with("bearer")
        || lower.contains("bearer=")
        || lower.contains("authorization:")
        || lower.contains("authorization=")
        || lower.starts_with("basic")
    {
        return "[redacted]".into();
    }
    // key=value and key:value secret forms (including JSON-ish "key":"value").
    for sep in ['=', ':'] {
        if let Some((key, value)) = token.split_once(sep) {
            let key_l = key
                .trim_matches(|c: char| c == '"' || c == '\'' || c == '{' || c == '}')
                .to_ascii_lowercase();
            let value = value.trim_matches(|c: char| c == '"' || c == '\'' || c == ',' || c == '}');
            if [
                "token",
                "password",
                "secret",
                "api_key",
                "apikey",
                "access_token",
                "refresh_token",
                "authorization",
            ]
            .iter()
            .any(|n| key_l.contains(n))
                || value.len() >= 16
            {
                return format!("{key}{sep}[redacted]");
            }
        }
    }
    // Standalone secrets (JWT-ish / hex / base64-ish), including short
    // credentials that often follow Authorization headers.
    if token.len() >= 16
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '/' | '='))
        && !token.chars().all(|c| c.is_ascii_alphabetic())
    {
        return "[redacted]".into();
    }
    if lower.contains("sk-") || lower.contains("eyj") {
        return "[redacted]".into();
    }
    token.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultimodalCapabilityEditor {
    pub identity: SelectionIdentity,
    pub phase: EditorPhase,
    pub refresh: RefreshPhase,
    pub working: MultimodalSnapshot,
    pub base: MultimodalSnapshot,
    next_save_id: u64,
    next_refresh_id: u64,
    last_announcement: AccessibilityAnnouncement,
    /// Bounded linearized accessibility projection for assistive consumers.
    accessibility_lines: Vec<String>,
    focused_row: usize,
}

impl MultimodalCapabilityEditor {
    pub fn new(identity: SelectionIdentity, authoritative: MultimodalSnapshot) -> Self {
        let mut editor = Self {
            identity,
            phase: EditorPhase::Clean {
                saved_generation: authoritative.image.effective.source_generation,
            },
            refresh: RefreshPhase::Idle,
            working: authoritative.clone(),
            base: authoritative,
            next_save_id: 1,
            next_refresh_id: 1,
            last_announcement: AccessibilityAnnouncement::None,
            accessibility_lines: Vec::new(),
            focused_row: 0,
        };
        editor.rebuild_accessibility();
        editor
    }

    pub fn last_announcement(&self) -> &AccessibilityAnnouncement {
        &self.last_announcement
    }

    pub fn accessibility_projection(&self) -> &[String] {
        &self.accessibility_lines
    }

    pub fn focused_row(&self) -> usize {
        self.focused_row
    }

    pub fn set_focused_row(&mut self, row: usize) {
        self.focused_row = row.min(2);
        self.rebuild_accessibility();
    }

    pub fn is_save_allowed(&self) -> bool {
        !matches!(
            self.phase,
            EditorPhase::Saving { .. }
                | EditorPhase::UnavailableClean
                | EditorPhase::UnavailableDirty { .. }
        ) && !matches!(self.refresh, RefreshPhase::Refreshing { .. })
            && matches!(
                self.phase,
                EditorPhase::Dirty | EditorPhase::SaveFailed { .. } | EditorPhase::Conflict { .. }
            )
    }

    pub fn is_refresh_allowed(&self) -> bool {
        !matches!(self.phase, EditorPhase::Saving { .. })
            && !matches!(
                self.phase,
                EditorPhase::UnavailableClean | EditorPhase::UnavailableDirty { .. }
            )
            && !matches!(self.refresh, RefreshPhase::Refreshing { .. })
    }

    pub fn visible_busy_label(&self) -> Option<&'static str> {
        if matches!(self.phase, EditorPhase::Saving { .. }) {
            Some("Saving…")
        } else if matches!(self.refresh, RefreshPhase::Refreshing { .. }) {
            Some("Refreshing…")
        } else {
            None
        }
    }

    pub fn available_actions(&self) -> Vec<&'static str> {
        let mut actions = Vec::new();
        match &self.phase {
            EditorPhase::SaveFailed { .. } => {
                actions.extend(["Retry", "Reload", "Discard"]);
            }
            EditorPhase::Conflict { .. } => {
                actions.extend(["Reload", "Reapply", "Discard"]);
            }
            EditorPhase::UnavailableDirty { .. } => {
                // After model reappearance the identity may already be the new
                // model; expose Rebind so the user can attach the preserved draft.
                actions.extend(["Discard", "Rebind"]);
            }
            _ => {}
        }
        if matches!(self.refresh, RefreshPhase::RefreshFailed { .. }) {
            // Same Retry label as save-failed; phase determines which reducer runs.
            actions.extend(["Retry", "Dismiss"]);
        }
        actions
    }

    pub fn apply_editor(&mut self, action: EditorAction) {
        self.last_announcement = AccessibilityAnnouncement::None;
        match action {
            EditorAction::Edit { modality, draft } => self.on_edit(modality, draft),
            EditorAction::Cycle { modality } => {
                let next = self.working.row(modality).draft.cycle();
                self.on_edit(modality, next);
            }
            EditorAction::Save => self.on_save(),
            EditorAction::SaveSuccess {
                save_id,
                provider_id,
                model_id,
                selection_generation,
                base_config_generation,
                saved_generation,
                authoritative,
            } => self.on_save_success(
                save_id,
                &provider_id,
                &model_id,
                selection_generation,
                base_config_generation,
                saved_generation,
                authoritative,
            ),
            EditorAction::SaveSafeFailure {
                save_id,
                provider_id,
                model_id,
                selection_generation,
                base_config_generation,
                reason,
            } => self.on_save_safe_failure(
                save_id,
                &provider_id,
                &model_id,
                selection_generation,
                base_config_generation,
                reason,
            ),
            EditorAction::SaveVersionConflict {
                save_id,
                provider_id,
                model_id,
                selection_generation,
                base_config_generation,
                current_safe_generation,
                authoritative,
            } => self.on_save_version_conflict(
                save_id,
                &provider_id,
                &model_id,
                selection_generation,
                base_config_generation,
                current_safe_generation,
                authoritative,
            ),
            EditorAction::Retry => self.on_retry(),
            EditorAction::Reload { authoritative } => self.on_reload(authoritative),
            EditorAction::Discard { authoritative } => self.on_discard(authoritative),
            EditorAction::Reapply { authoritative } => self.on_reapply(authoritative),
            EditorAction::ModelRemoved => self.on_model_removed(),
            EditorAction::ModelReappeared {
                identity,
                authoritative,
            } => self.on_model_reappeared(identity, authoritative),
            EditorAction::Rebind {
                identity,
                authoritative,
            } => self.on_rebind(identity, authoritative),
            EditorAction::SelectionChanged {
                identity,
                authoritative,
            } => self.on_selection_changed(identity, authoritative),
        }
        self.rebuild_accessibility();
    }

    pub fn apply_refresh(&mut self, action: RefreshAction) {
        self.last_announcement = AccessibilityAnnouncement::None;
        match action {
            RefreshAction::Refresh => self.on_refresh_start(),
            RefreshAction::RefreshSuccess {
                refresh_id,
                selection_generation,
                config_generation,
                detected,
            } => self.on_refresh_success(
                refresh_id,
                selection_generation,
                config_generation,
                detected,
            ),
            RefreshAction::RefreshFailure {
                refresh_id,
                selection_generation,
                config_generation,
                safe_reason,
            } => self.on_refresh_failure(
                refresh_id,
                selection_generation,
                config_generation,
                safe_reason,
            ),
            RefreshAction::Retry => self.on_refresh_retry(),
            RefreshAction::Dismiss => {
                if matches!(self.refresh, RefreshPhase::RefreshFailed { .. }) {
                    self.refresh = RefreshPhase::Idle;
                }
            }
        }
        self.rebuild_accessibility();
    }

    fn on_edit(&mut self, modality: MediaModality, draft: DraftOverride) {
        if matches!(
            self.phase,
            EditorPhase::UnavailableClean | EditorPhase::UnavailableDirty { .. }
        ) {
            return;
        }
        // Editing one row never mutates the other two.
        let detected = self.base.row(modality).detected;
        let config_generation = self.identity.config_generation;
        let row = self.working.row_mut(modality);
        row.draft = draft;
        // Keep effective status/provenance aligned with the draft so the shared
        // row view model shows override vs Auto detection correctly before the
        // next authoritative reload.
        match draft {
            DraftOverride::Auto => {
                row.effective = detected;
                row.detected = detected;
            }
            DraftOverride::Supported | DraftOverride::Unsupported => {
                row.effective = ResolvedInputCapability {
                    status: draft
                        .as_capability_status()
                        .expect("explicit override has a status"),
                    source: EffectiveCapabilitySource::Override,
                    source_generation: config_generation,
                };
            }
        }
        self.last_announcement = AccessibilityAnnouncement::OverrideSet { modality, draft };
        match &self.phase {
            EditorPhase::Clean { .. }
            | EditorPhase::Dirty
            | EditorPhase::SaveFailed { .. }
            | EditorPhase::Conflict { .. } => {
                self.phase = EditorPhase::Dirty;
            }
            EditorPhase::Saving { .. }
            | EditorPhase::UnavailableClean
            | EditorPhase::UnavailableDirty { .. } => {}
        }
        // Edit while refresh_failed changes the editor normally and leaves
        // refresh_failed until dismiss/retry.
        let _ = &self.refresh;
    }

    fn on_save(&mut self) {
        if !self.is_save_allowed() {
            return;
        }
        let save_id = OperationId(self.next_save_id);
        self.next_save_id = self.next_save_id.saturating_add(1);
        self.phase = EditorPhase::Saving {
            save_id,
            selection_generation: self.identity.selection_generation,
            base_config_generation: self.identity.config_generation,
        };
    }

    fn save_matches(
        &self,
        save_id: OperationId,
        provider_id: &str,
        model_id: &str,
        selection_generation: u64,
        base_config_generation: u64,
    ) -> bool {
        if self.identity.provider_id != provider_id || self.identity.model_id != model_id {
            return false;
        }
        matches!(
            self.phase,
            EditorPhase::Saving {
                save_id: sid,
                selection_generation: sgen,
                base_config_generation: bgen,
            } if sid == save_id
                && sgen == selection_generation
                && bgen == base_config_generation
                && bgen == self.identity.config_generation
                && sgen == self.identity.selection_generation
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn on_save_success(
        &mut self,
        save_id: OperationId,
        provider_id: &str,
        model_id: &str,
        selection_generation: u64,
        base_config_generation: u64,
        saved_generation: u64,
        authoritative: MultimodalSnapshot,
    ) {
        if !self.save_matches(
            save_id,
            provider_id,
            model_id,
            selection_generation,
            base_config_generation,
        ) {
            // Superseded: ignore completely.
            return;
        }
        self.working = authoritative.clone();
        self.base = authoritative;
        self.identity.config_generation = saved_generation;
        self.phase = EditorPhase::Clean { saved_generation };
        self.last_announcement = AccessibilityAnnouncement::Saved;
    }

    fn on_save_safe_failure(
        &mut self,
        save_id: OperationId,
        provider_id: &str,
        model_id: &str,
        selection_generation: u64,
        base_config_generation: u64,
        reason: String,
    ) {
        if !self.save_matches(
            save_id,
            provider_id,
            model_id,
            selection_generation,
            base_config_generation,
        ) {
            return;
        }
        // Preserve draft/base; daemon effective unchanged. Always sanitize.
        let safe = sanitize_user_facing_error(reason);
        self.phase = EditorPhase::SaveFailed {
            reason: safe.clone(),
        };
        self.last_announcement = AccessibilityAnnouncement::SaveFailed { reason: safe };
    }

    #[allow(clippy::too_many_arguments)]
    fn on_save_version_conflict(
        &mut self,
        save_id: OperationId,
        provider_id: &str,
        model_id: &str,
        selection_generation: u64,
        base_config_generation: u64,
        current_safe_generation: u64,
        authoritative: MultimodalSnapshot,
    ) {
        if !self.save_matches(
            save_id,
            provider_id,
            model_id,
            selection_generation,
            base_config_generation,
        ) {
            return;
        }
        // Preserve draft; expose Reload/Reapply/Discard.
        self.base = authoritative;
        self.phase = EditorPhase::Conflict {
            current_safe_generation,
        };
        self.last_announcement = AccessibilityAnnouncement::SettingsChangedElsewhere;
    }

    fn on_retry(&mut self) {
        if let EditorPhase::SaveFailed { .. } = &self.phase {
            // New save ID with the still-current base.
            self.on_save();
        }
    }

    fn on_reload(&mut self, authoritative: MultimodalSnapshot) {
        match &self.phase {
            EditorPhase::SaveFailed { .. } | EditorPhase::Conflict { .. } => {
                // Advance identity to the authoritative generation so a later
                // edit/save cannot re-conflict against a stale base.
                self.identity.config_generation = authoritative.image.effective.source_generation;
                self.working = authoritative.clone();
                self.base = authoritative;
                self.phase = EditorPhase::Clean {
                    saved_generation: self.identity.config_generation,
                };
            }
            _ => {}
        }
    }

    fn on_discard(&mut self, authoritative: MultimodalSnapshot) {
        match &self.phase {
            EditorPhase::SaveFailed { .. } | EditorPhase::Conflict { .. } | EditorPhase::Dirty => {
                self.identity.config_generation = authoritative.image.effective.source_generation;
                self.working = authoritative.clone();
                self.base = authoritative;
                self.phase = EditorPhase::Clean {
                    saved_generation: self.identity.config_generation,
                };
            }
            EditorPhase::UnavailableDirty { .. } => {
                self.identity.config_generation = authoritative.image.effective.source_generation;
                self.phase = EditorPhase::UnavailableClean;
                self.working = authoritative.clone();
                self.base = authoritative;
            }
            _ => {}
        }
    }

    fn on_reapply(&mut self, authoritative: MultimodalSnapshot) {
        if let EditorPhase::Conflict { .. } = &self.phase {
            // Preserve draft, rebase onto returned current generation; do not save.
            let preserved = self.working.clone();
            self.base = authoritative.clone();
            self.working = MultimodalSnapshot {
                image: ModalitySnapshot {
                    draft: preserved.image.draft,
                    effective: authoritative.image.effective,
                    detected: authoritative.image.detected,
                },
                audio: ModalitySnapshot {
                    draft: preserved.audio.draft,
                    effective: authoritative.audio.effective,
                    detected: authoritative.audio.detected,
                },
                video: ModalitySnapshot {
                    draft: preserved.video.draft,
                    effective: authoritative.video.effective,
                    detected: authoritative.video.detected,
                },
            };
            self.identity.config_generation = authoritative.image.effective.source_generation;
            self.phase = EditorPhase::Dirty;
        }
    }

    fn on_model_removed(&mut self) {
        // Supersede pending IDs by advancing selection generation.
        self.identity.selection_generation = self.identity.selection_generation.saturating_add(1);
        self.refresh = RefreshPhase::Idle;
        match &self.phase {
            EditorPhase::Clean { .. } => {
                self.phase = EditorPhase::UnavailableClean;
            }
            EditorPhase::Dirty
            | EditorPhase::Saving { .. }
            | EditorPhase::SaveFailed { .. }
            | EditorPhase::Conflict { .. } => {
                self.phase = EditorPhase::UnavailableDirty {
                    draft: self.working.clone(),
                };
            }
            EditorPhase::UnavailableClean | EditorPhase::UnavailableDirty { .. } => {}
        }
    }

    fn on_model_reappeared(
        &mut self,
        identity: SelectionIdentity,
        authoritative: MultimodalSnapshot,
    ) {
        match &self.phase {
            EditorPhase::UnavailableClean => {
                self.identity = identity.clone();
                self.working = authoritative.clone();
                self.base = authoritative;
                self.phase = EditorPhase::Clean {
                    saved_generation: identity.config_generation,
                };
                self.refresh = RefreshPhase::Idle;
            }
            EditorPhase::UnavailableDirty { draft } => {
                // Remain unavailable until explicit rebind; keep draft copy.
                let draft = draft.clone();
                self.identity = identity.clone();
                self.base = authoritative.clone();
                // Show new effective values under the preserved draft.
                self.working = MultimodalSnapshot {
                    image: ModalitySnapshot {
                        draft: draft.image.draft,
                        effective: authoritative.image.effective,
                        detected: authoritative.image.detected,
                    },
                    audio: ModalitySnapshot {
                        draft: draft.audio.draft,
                        effective: authoritative.audio.effective,
                        detected: authoritative.audio.detected,
                    },
                    video: ModalitySnapshot {
                        draft: draft.video.draft,
                        effective: authoritative.video.effective,
                        detected: authoritative.video.detected,
                    },
                };
                self.phase = EditorPhase::UnavailableDirty { draft };
            }
            _ => {}
        }
    }

    fn on_rebind(&mut self, identity: SelectionIdentity, authoritative: MultimodalSnapshot) {
        if let EditorPhase::UnavailableDirty { draft } = &self.phase {
            let draft = draft.clone();
            self.identity = identity;
            self.base = authoritative.clone();
            self.working = MultimodalSnapshot {
                image: ModalitySnapshot {
                    draft: draft.image.draft,
                    effective: authoritative.image.effective,
                    detected: authoritative.image.detected,
                },
                audio: ModalitySnapshot {
                    draft: draft.audio.draft,
                    effective: authoritative.audio.effective,
                    detected: authoritative.audio.detected,
                },
                video: ModalitySnapshot {
                    draft: draft.video.draft,
                    effective: authoritative.video.effective,
                    detected: authoritative.video.detected,
                },
            };
            self.phase = EditorPhase::Dirty;
            self.refresh = RefreshPhase::Idle;
        }
    }

    fn on_selection_changed(
        &mut self,
        identity: SelectionIdentity,
        authoritative: MultimodalSnapshot,
    ) {
        // Synchronous: increment is carried in identity; clear old overlay/busy.
        self.identity = identity;
        self.refresh = RefreshPhase::Idle;
        self.working = authoritative.clone();
        self.base = authoritative;
        self.phase = EditorPhase::Clean {
            saved_generation: self.identity.config_generation,
        };
        // Superseded completions are ignored by generation match; no success
        // announcement here.
        self.last_announcement = AccessibilityAnnouncement::None;
    }

    fn on_refresh_start(&mut self) {
        if !self.is_refresh_allowed() {
            return;
        }
        let refresh_id = OperationId(self.next_refresh_id);
        self.next_refresh_id = self.next_refresh_id.saturating_add(1);
        self.refresh = RefreshPhase::Refreshing {
            refresh_id,
            selection_generation: self.identity.selection_generation,
            config_generation: self.identity.config_generation,
        };
        self.last_announcement = AccessibilityAnnouncement::Refreshing {
            provider: self.identity.provider_id.clone(),
            model: self.identity.model_id.clone(),
        };
    }

    fn refresh_matches(
        &self,
        refresh_id: OperationId,
        selection_generation: u64,
        config_generation: u64,
    ) -> bool {
        matches!(
            self.refresh,
            RefreshPhase::Refreshing {
                refresh_id: rid,
                selection_generation: sgen,
                config_generation: cgen,
            } if rid == refresh_id && sgen == selection_generation && cgen == config_generation
        )
    }

    fn on_refresh_success(
        &mut self,
        refresh_id: OperationId,
        selection_generation: u64,
        config_generation: u64,
        detected: MultimodalSnapshot,
    ) {
        if !self.refresh_matches(refresh_id, selection_generation, config_generation) {
            // Superseded: no state mutation, no success announcement.
            return;
        }
        // Refresh updates only detected previews; never overwrites draft override.
        // Also update base.detected so Auto discard/restore uses the new detection.
        for modality in MediaModality::ALL {
            let det = detected.row(modality).detected;
            let eff = detected.row(modality).effective;
            {
                let row = self.working.row_mut(modality);
                row.detected = det;
                if row.draft == DraftOverride::Auto {
                    row.effective = eff;
                }
            }
            {
                let base_row = self.base.row_mut(modality);
                base_row.detected = det;
                // Base draft stays authoritative; update base effective for Auto.
                if base_row.draft == DraftOverride::Auto {
                    base_row.effective = eff;
                }
            }
        }
        self.refresh = RefreshPhase::Idle;
    }

    fn on_refresh_failure(
        &mut self,
        refresh_id: OperationId,
        selection_generation: u64,
        config_generation: u64,
        safe_reason: String,
    ) {
        if !self.refresh_matches(refresh_id, selection_generation, config_generation) {
            return;
        }
        self.refresh = RefreshPhase::RefreshFailed {
            safe_reason: sanitize_user_facing_error(safe_reason),
        };
    }

    fn on_refresh_retry(&mut self) {
        if matches!(self.refresh, RefreshPhase::RefreshFailed { .. }) {
            self.refresh = RefreshPhase::Idle;
            self.on_refresh_start();
        }
    }

    fn rebuild_accessibility(&mut self) {
        let mut lines = Vec::new();
        if let Some(busy) = self.visible_busy_label() {
            lines.push(busy.to_string());
        }
        match &self.last_announcement {
            AccessibilityAnnouncement::Refreshing { provider, model } => {
                lines.push(format!(
                    "Refreshing media capabilities for {provider}/{model}"
                ));
            }
            AccessibilityAnnouncement::OverrideSet { modality, draft } => {
                lines.push(format!(
                    "{} input set to {}",
                    modality.label(),
                    draft.label()
                ));
            }
            AccessibilityAnnouncement::Saved => {
                lines.push("Media capability settings saved".to_string());
            }
            AccessibilityAnnouncement::SaveFailed { reason } => {
                lines.push(format!("Save failed: {reason}"));
            }
            AccessibilityAnnouncement::SettingsChangedElsewhere => {
                lines.push("Settings changed elsewhere; review your draft".to_string());
            }
            AccessibilityAnnouncement::None => {}
        }
        if let RefreshPhase::RefreshFailed { safe_reason } = &self.refresh {
            lines.push(format!("Refresh failed: {safe_reason}"));
        }
        for (idx, modality) in MediaModality::ALL.iter().enumerate() {
            let row = self.working.row(*modality);
            let focus = if idx == self.focused_row {
                "focused"
            } else {
                "unfocused"
            };
            lines.push(format!(
                "{} input | draft {} | effective {} | provenance {} | generation {} | {focus}",
                modality.label(),
                row.draft.label(),
                status_word(row.effective.status),
                provenance_word(row.effective.source),
                row.effective.source_generation,
            ));
        }
        for action in self.available_actions() {
            lines.push(format!("action: {action}"));
        }
        if matches!(
            self.phase,
            EditorPhase::UnavailableClean | EditorPhase::UnavailableDirty { .. }
        ) {
            lines.push("model unavailable".to_string());
        }
        self.accessibility_lines = lines;
    }

    /// Visible row view model shared with the accessibility projection.
    pub fn row_view(&self, modality: MediaModality) -> RowViewModel {
        let row = self.working.row(modality);
        let effective_label = match (row.draft, row.effective.status, row.effective.source) {
            (DraftOverride::Auto, CapabilityStatus::Unknown, EffectiveCapabilitySource::None) => {
                "Auto — Unknown (no source)".to_string()
            }
            (DraftOverride::Auto, status, source) => {
                format!(
                    "Auto — {} ({})",
                    status_word(status),
                    provenance_word(source)
                )
            }
            (draft, status, source) => {
                format!(
                    "{} — {} ({})",
                    draft.label(),
                    status_word(status),
                    provenance_word(source)
                )
            }
        };
        RowViewModel {
            modality,
            draft: row.draft,
            effective_status: row.effective.status,
            provenance: row.effective.source,
            detected_generation: row.detected.source_generation,
            effective_label,
            busy: self.visible_busy_label().map(str::to_string),
        }
    }

    pub fn narrow_layout_lines(&self, width: usize) -> Vec<String> {
        // Vertically scrollable row/detail layout without truncating state vs
        // provenance when the terminal is narrow.
        let mut lines = Vec::new();
        if let Some(busy) = self.visible_busy_label() {
            lines.push(busy.to_string());
        }
        for modality in MediaModality::ALL {
            let view = self.row_view(modality);
            lines.push(format!("{} input", modality.label()));
            lines.push(format!("  draft: {}", view.draft.label()));
            lines.push(format!("  {}", view.effective_label));
            lines.push(format!(
                "  detected generation: {}",
                view.detected_generation
            ));
            if width < 40 {
                // Force wrap: each facet is already on its own line.
            }
        }
        for action in self.available_actions() {
            lines.push(format!("[{action}]"));
        }
        lines
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowViewModel {
    pub modality: MediaModality,
    pub draft: DraftOverride,
    pub effective_status: CapabilityStatus,
    pub provenance: EffectiveCapabilitySource,
    pub detected_generation: u64,
    pub effective_label: String,
    pub busy: Option<String>,
}

fn status_word(status: CapabilityStatus) -> &'static str {
    match status {
        CapabilityStatus::Supported => "Supported",
        CapabilityStatus::Unsupported => "Unsupported",
        CapabilityStatus::RequiresEntitlement => "RequiresEntitlement",
        CapabilityStatus::Unknown => "Unknown",
    }
}

fn provenance_word(source: EffectiveCapabilitySource) -> &'static str {
    match source {
        EffectiveCapabilitySource::Override => "override",
        EffectiveCapabilitySource::Model => "model",
        EffectiveCapabilitySource::Provider => "provider",
        EffectiveCapabilitySource::Legacy => "legacy",
        EffectiveCapabilitySource::None => "none",
    }
}

pub fn snapshot_from_resolved(
    image: ResolvedInputCapability,
    audio: ResolvedInputCapability,
    video: ResolvedInputCapability,
    image_draft: DraftOverride,
    audio_draft: DraftOverride,
    video_draft: DraftOverride,
) -> MultimodalSnapshot {
    MultimodalSnapshot {
        image: ModalitySnapshot {
            draft: image_draft,
            effective: image,
            detected: image,
        },
        audio: ModalitySnapshot {
            draft: audio_draft,
            effective: audio,
            detected: audio,
        },
        video: ModalitySnapshot {
            draft: video_draft,
            effective: video,
            detected: video,
        },
    }
}

#[cfg(test)]
mod multimodal_capability_ui_tests {
    use super::*;

    fn identity(config_gen: u64) -> SelectionIdentity {
        SelectionIdentity {
            provider_id: "p".into(),
            model_id: "m".into(),
            selection_generation: 1,
            config_generation: config_gen,
        }
    }

    fn resolved(
        status: CapabilityStatus,
        source: EffectiveCapabilitySource,
        config_gen: u64,
    ) -> ResolvedInputCapability {
        ResolvedInputCapability {
            status,
            source,
            source_generation: config_gen,
        }
    }

    fn auto_unknown(config_gen: u64) -> MultimodalSnapshot {
        snapshot_from_resolved(
            resolved(
                CapabilityStatus::Unknown,
                EffectiveCapabilitySource::None,
                config_gen,
            ),
            resolved(
                CapabilityStatus::Unknown,
                EffectiveCapabilitySource::None,
                config_gen,
            ),
            resolved(
                CapabilityStatus::Unknown,
                EffectiveCapabilitySource::None,
                config_gen,
            ),
            DraftOverride::Auto,
            DraftOverride::Auto,
            DraftOverride::Auto,
        )
    }

    fn supported_model(config_gen: u64) -> MultimodalSnapshot {
        snapshot_from_resolved(
            resolved(
                CapabilityStatus::Supported,
                EffectiveCapabilitySource::Model,
                config_gen,
            ),
            resolved(
                CapabilityStatus::Unsupported,
                EffectiveCapabilitySource::Provider,
                config_gen,
            ),
            resolved(
                CapabilityStatus::RequiresEntitlement,
                EffectiveCapabilitySource::Legacy,
                config_gen,
            ),
            DraftOverride::Auto,
            DraftOverride::Auto,
            DraftOverride::Auto,
        )
    }

    #[test]
    fn multimodal_capability_ui_error_redacts_short_bearer_tokens() {
        let s = sanitize_user_facing_error("Authorization: Bearer abc123 save failed");
        assert!(!s.contains("abc123"), "short bearer must be redacted: {s}");
        assert!(s.contains("[redacted]"), "expected redaction marker: {s}");
        let s2 = sanitize_user_facing_error("token=shortsecretvalue save failed");
        assert!(
            !s2.contains("shortsecretvalue"),
            "token= value must be redacted: {s2}"
        );
        let s3 = sanitize_user_facing_error("api_key: abc123xyz");
        assert!(!s3.contains("abc123xyz"), "colon secrets redacted: {s3}");
        let s4 = sanitize_user_facing_error(r#"{"access_token":"abc123xyz"}"#);
        assert!(!s4.contains("abc123xyz"), "json secrets redacted: {s4}");
    }

    #[test]
    fn multimodal_capability_ui_cycle() {
        // Every Auto → Supported → Unsupported → Auto transition, independently,
        // for all three rows (AC1).
        for modality in MediaModality::ALL {
            let mut editor = MultimodalCapabilityEditor::new(identity(1), auto_unknown(1));
            assert_eq!(editor.working.row(modality).draft, DraftOverride::Auto);

            editor.apply_editor(EditorAction::Cycle { modality });
            assert_eq!(editor.working.row(modality).draft, DraftOverride::Supported);
            assert!(matches!(editor.phase, EditorPhase::Dirty));
            assert!(matches!(
                editor.last_announcement(),
                AccessibilityAnnouncement::OverrideSet {
                    modality: m,
                    draft: DraftOverride::Supported,
                } if *m == modality
            ));
            // Sibling rows remain Auto.
            for other in MediaModality::ALL {
                if other != modality {
                    assert_eq!(editor.working.row(other).draft, DraftOverride::Auto);
                }
            }

            editor.apply_editor(EditorAction::Cycle { modality });
            assert_eq!(
                editor.working.row(modality).draft,
                DraftOverride::Unsupported
            );

            editor.apply_editor(EditorAction::Cycle { modality });
            assert_eq!(editor.working.row(modality).draft, DraftOverride::Auto);
            for other in MediaModality::ALL {
                if other != modality {
                    assert_eq!(editor.working.row(other).draft, DraftOverride::Auto);
                }
            }
        }

        // Cross-row independence under concurrent dirty drafts.
        let mut editor = MultimodalCapabilityEditor::new(identity(1), auto_unknown(1));
        editor.apply_editor(EditorAction::Cycle {
            modality: MediaModality::Image,
        });
        editor.apply_editor(EditorAction::Cycle {
            modality: MediaModality::Audio,
        });
        editor.apply_editor(EditorAction::Cycle {
            modality: MediaModality::Audio,
        });
        editor.apply_editor(EditorAction::Cycle {
            modality: MediaModality::Video,
        });
        assert_eq!(editor.working.image.draft, DraftOverride::Supported);
        assert_eq!(editor.working.audio.draft, DraftOverride::Unsupported);
        assert_eq!(editor.working.video.draft, DraftOverride::Supported);
        editor.apply_editor(EditorAction::Cycle {
            modality: MediaModality::Video,
        });
        editor.apply_editor(EditorAction::Cycle {
            modality: MediaModality::Video,
        });
        assert_eq!(editor.working.video.draft, DraftOverride::Auto);
        assert_eq!(editor.working.image.draft, DraftOverride::Supported);
        assert_eq!(editor.working.audio.draft, DraftOverride::Unsupported);
    }

    #[test]
    fn multimodal_capability_ui_async_state_machine() {
        let mut editor = MultimodalCapabilityEditor::new(identity(10), auto_unknown(10));
        // clean + edit → dirty
        editor.apply_editor(EditorAction::Edit {
            modality: MediaModality::Image,
            draft: DraftOverride::Unsupported,
        });
        assert!(matches!(editor.phase, EditorPhase::Dirty));

        // dirty + save → saving
        editor.apply_editor(EditorAction::Save);
        let save_id = match &editor.phase {
            EditorPhase::Saving { save_id, .. } => *save_id,
            other => panic!("expected saving, got {other:?}"),
        };
        assert!(!editor.is_refresh_allowed());

        // Stale/superseded success is inert (wrong save_id + wrong config gen).
        editor.apply_editor(EditorAction::SaveSuccess {
            save_id: OperationId(999),
            provider_id: "p".into(),
            model_id: "m".into(),
            selection_generation: 1,
            base_config_generation: 10,
            saved_generation: 11,
            authoritative: auto_unknown(11),
        });
        assert!(matches!(editor.phase, EditorPhase::Saving { .. }));
        // Wrong provider/model must not complete the save either.
        editor.apply_editor(EditorAction::SaveSuccess {
            save_id,
            provider_id: "other".into(),
            model_id: "m".into(),
            selection_generation: 1,
            base_config_generation: 10,
            saved_generation: 11,
            authoritative: auto_unknown(11),
        });
        assert!(matches!(editor.phase, EditorPhase::Saving { .. }));

        // Matching success → clean
        let mut saved = auto_unknown(11);
        saved.image.draft = DraftOverride::Unsupported;
        saved.image.effective = resolved(
            CapabilityStatus::Unsupported,
            EffectiveCapabilitySource::Override,
            11,
        );
        editor.apply_editor(EditorAction::SaveSuccess {
            save_id,
            provider_id: "p".into(),
            model_id: "m".into(),
            selection_generation: 1,
            base_config_generation: 10,
            saved_generation: 11,
            authoritative: saved.clone(),
        });
        assert!(matches!(
            editor.phase,
            EditorPhase::Clean {
                saved_generation: 11
            }
        ));
        assert!(matches!(
            editor.last_announcement(),
            AccessibilityAnnouncement::Saved
        ));

        // Save failure path
        editor.apply_editor(EditorAction::Edit {
            modality: MediaModality::Audio,
            draft: DraftOverride::Supported,
        });
        editor.apply_editor(EditorAction::Save);
        let save_id = match &editor.phase {
            EditorPhase::Saving { save_id, .. } => *save_id,
            other => panic!("expected saving, got {other:?}"),
        };
        editor.apply_editor(EditorAction::SaveSafeFailure {
            save_id,
            provider_id: "p".into(),
            model_id: "m".into(),
            selection_generation: 1,
            base_config_generation: 11,
            reason: "disk full".into(),
        });
        assert!(matches!(editor.phase, EditorPhase::SaveFailed { .. }));
        assert_eq!(editor.working.audio.draft, DraftOverride::Supported);
        assert!(editor.available_actions().contains(&"Retry"));
        assert!(editor.available_actions().contains(&"Reload"));
        assert!(editor.available_actions().contains(&"Discard"));

        // save_failed + edit → dirty, clears error only
        editor.apply_editor(EditorAction::Edit {
            modality: MediaModality::Video,
            draft: DraftOverride::Supported,
        });
        assert!(matches!(editor.phase, EditorPhase::Dirty));
        assert_eq!(editor.working.audio.draft, DraftOverride::Supported);

        // Version conflict
        editor.apply_editor(EditorAction::Save);
        let save_id = match &editor.phase {
            EditorPhase::Saving { save_id, .. } => *save_id,
            other => panic!("expected saving, got {other:?}"),
        };
        let remote = supported_model(20);
        editor.apply_editor(EditorAction::SaveVersionConflict {
            save_id,
            provider_id: "p".into(),
            model_id: "m".into(),
            selection_generation: 1,
            base_config_generation: 11,
            current_safe_generation: 20,
            authoritative: remote.clone(),
        });
        assert!(matches!(
            editor.phase,
            EditorPhase::Conflict {
                current_safe_generation: 20
            }
        ));
        assert_eq!(editor.working.audio.draft, DraftOverride::Supported);
        assert!(editor.available_actions().contains(&"Reapply"));

        // reapply → dirty rebased, no auto-save
        editor.apply_editor(EditorAction::Reapply {
            authoritative: remote.clone(),
        });
        assert!(matches!(editor.phase, EditorPhase::Dirty));
        assert_eq!(editor.working.audio.draft, DraftOverride::Supported);
        assert_eq!(
            editor.working.image.effective.status,
            CapabilityStatus::Supported
        );

        // Refresh exclusion while saving
        editor.apply_editor(EditorAction::Save);
        assert!(!editor.is_refresh_allowed());
        // Abort save via selection change (supersedes)
        editor.apply_editor(EditorAction::SelectionChanged {
            identity: SelectionIdentity {
                provider_id: "p".into(),
                model_id: "m".into(),
                selection_generation: 2,
                config_generation: 21,
            },
            authoritative: auto_unknown(21),
        });
        assert!(matches!(editor.phase, EditorPhase::Clean { .. }));
        assert!(matches!(editor.refresh, RefreshPhase::Idle));
        // Late save completion for old selection is silent.
        editor.apply_editor(EditorAction::SaveSuccess {
            save_id: OperationId(1),
            provider_id: "p".into(),
            model_id: "m".into(),
            selection_generation: 1,
            base_config_generation: 10,
            saved_generation: 99,
            authoritative: supported_model(99),
        });
        assert!(matches!(editor.phase, EditorPhase::Clean { .. }));
        assert_eq!(editor.working.image.effective.source_generation, 21);
        assert!(matches!(
            editor.last_announcement(),
            AccessibilityAnnouncement::None
        ));

        // Refresh path
        editor.apply_refresh(RefreshAction::Refresh);
        let refresh_id = match &editor.refresh {
            RefreshPhase::Refreshing { refresh_id, .. } => *refresh_id,
            other => panic!("expected refreshing, got {other:?}"),
        };
        assert!(!editor.is_save_allowed());
        // Edit drafts while we prepare a refresh success that must not overwrite.
        editor.apply_editor(EditorAction::Edit {
            modality: MediaModality::Image,
            draft: DraftOverride::Unsupported,
        });
        let mut detected = supported_model(22);
        detected.image.detected = resolved(
            CapabilityStatus::Supported,
            EffectiveCapabilitySource::Model,
            22,
        );
        editor.apply_refresh(RefreshAction::RefreshSuccess {
            refresh_id,
            selection_generation: 2,
            config_generation: 21,
            detected: detected.clone(),
        });
        assert!(matches!(editor.refresh, RefreshPhase::Idle));
        assert_eq!(editor.working.image.draft, DraftOverride::Unsupported);
        assert_eq!(
            editor.working.image.detected.status,
            CapabilityStatus::Supported
        );

        // Refresh failure / retry / dismiss
        editor.apply_refresh(RefreshAction::Refresh);
        let refresh_id = match &editor.refresh {
            RefreshPhase::Refreshing { refresh_id, .. } => *refresh_id,
            other => panic!("expected refreshing, got {other:?}"),
        };
        editor.apply_refresh(RefreshAction::RefreshFailure {
            refresh_id,
            selection_generation: 2,
            config_generation: 21,
            safe_reason: "timeout".into(),
        });
        assert!(matches!(editor.refresh, RefreshPhase::RefreshFailed { .. }));
        editor.apply_refresh(RefreshAction::Retry);
        assert!(matches!(editor.refresh, RefreshPhase::Refreshing { .. }));
        let refresh_id = match &editor.refresh {
            RefreshPhase::Refreshing { refresh_id, .. } => *refresh_id,
            other => panic!("expected refreshing, got {other:?}"),
        };
        editor.apply_refresh(RefreshAction::RefreshFailure {
            refresh_id,
            selection_generation: 2,
            config_generation: 21,
            safe_reason: "timeout".into(),
        });
        editor.apply_refresh(RefreshAction::Dismiss);
        assert!(matches!(editor.refresh, RefreshPhase::Idle));

        // Model removal while dirty
        editor.apply_editor(EditorAction::Edit {
            modality: MediaModality::Audio,
            draft: DraftOverride::Supported,
        });
        editor.apply_editor(EditorAction::ModelRemoved);
        assert!(matches!(editor.phase, EditorPhase::UnavailableDirty { .. }));
        assert!(!editor.is_save_allowed());
        // Reappear remains unavailable until rebind
        editor.apply_editor(EditorAction::ModelReappeared {
            identity: SelectionIdentity {
                provider_id: "p".into(),
                model_id: "m".into(),
                selection_generation: 3,
                config_generation: 30,
            },
            authoritative: supported_model(30),
        });
        assert!(matches!(editor.phase, EditorPhase::UnavailableDirty { .. }));
        editor.apply_editor(EditorAction::Rebind {
            identity: SelectionIdentity {
                provider_id: "p".into(),
                model_id: "m".into(),
                selection_generation: 3,
                config_generation: 30,
            },
            authoritative: supported_model(30),
        });
        assert!(matches!(editor.phase, EditorPhase::Dirty));
        assert_eq!(editor.working.audio.draft, DraftOverride::Supported);

        // unavailable_dirty + discard → unavailable_clean, then reappear → clean
        editor.apply_editor(EditorAction::ModelRemoved);
        editor.apply_editor(EditorAction::Discard {
            authoritative: auto_unknown(31),
        });
        assert!(matches!(editor.phase, EditorPhase::UnavailableClean));
        editor.apply_editor(EditorAction::ModelReappeared {
            identity: SelectionIdentity {
                provider_id: "p".into(),
                model_id: "m".into(),
                selection_generation: 4,
                config_generation: 32,
            },
            authoritative: auto_unknown(32),
        });
        assert!(matches!(editor.phase, EditorPhase::Clean { .. }));
    }

    #[test]
    fn multimodal_capability_ui_provenance_distinct() {
        let snap = supported_model(5);
        let editor = MultimodalCapabilityEditor::new(identity(5), snap);
        let image = editor.row_view(MediaModality::Image);
        assert!(image.effective_label.contains("Supported"));
        assert!(image.effective_label.contains("model"));
        let audio = editor.row_view(MediaModality::Audio);
        assert!(audio.effective_label.contains("Unsupported"));
        assert!(audio.effective_label.contains("provider"));
        let video = editor.row_view(MediaModality::Video);
        assert!(video.effective_label.contains("RequiresEntitlement"));
        assert!(video.effective_label.contains("legacy"));

        let unknown = MultimodalCapabilityEditor::new(identity(1), auto_unknown(1));
        let label = unknown.row_view(MediaModality::Image).effective_label;
        assert_eq!(label, "Auto — Unknown (no source)");
        assert_ne!(label, "Auto — Unsupported (none)");
    }

    #[test]
    fn multimodal_capability_ui_accessibility_projection() {
        let mut editor = MultimodalCapabilityEditor::new(identity(1), auto_unknown(1));
        editor.apply_refresh(RefreshAction::Refresh);
        let proj = editor.accessibility_projection().join("\n");
        assert!(proj.contains("Refreshing…"));
        assert!(proj.contains("Refreshing media capabilities for p/m"));

        let refresh_id = match &editor.refresh {
            RefreshPhase::Refreshing { refresh_id, .. } => *refresh_id,
            other => panic!("{other:?}"),
        };
        editor.apply_refresh(RefreshAction::RefreshSuccess {
            refresh_id,
            selection_generation: 1,
            config_generation: 1,
            detected: supported_model(2),
        });

        editor.apply_editor(EditorAction::Cycle {
            modality: MediaModality::Image,
        });
        let proj = editor.accessibility_projection().join("\n");
        assert!(proj.contains("Image input set to Supported"));
        assert!(proj.contains("Image input | draft Supported"));
        assert!(proj.contains("provenance"));

        editor.apply_editor(EditorAction::Save);
        let save_id = match &editor.phase {
            EditorPhase::Saving { save_id, .. } => *save_id,
            other => panic!("{other:?}"),
        };
        let proj = editor.accessibility_projection().join("\n");
        assert!(proj.contains("Saving…"));

        editor.apply_editor(EditorAction::SaveSafeFailure {
            save_id,
            provider_id: "p".into(),
            model_id: "m".into(),
            selection_generation: 1,
            base_config_generation: 1,
            reason: "io error".into(),
        });
        let proj = editor.accessibility_projection().join("\n");
        assert!(proj.contains("Save failed: io error"));
        assert!(proj.contains("action: Retry"));
        assert!(proj.contains("action: Reload"));
        assert!(proj.contains("action: Discard"));

        // Conflict path exposes Reload / Reapply / Discard with exact announcement.
        editor.apply_editor(EditorAction::Edit {
            modality: MediaModality::Audio,
            draft: DraftOverride::Supported,
        });
        editor.apply_editor(EditorAction::Save);
        let save_id = match &editor.phase {
            EditorPhase::Saving { save_id, .. } => *save_id,
            other => panic!("{other:?}"),
        };
        editor.apply_editor(EditorAction::SaveVersionConflict {
            save_id,
            provider_id: "p".into(),
            model_id: "m".into(),
            selection_generation: 1,
            base_config_generation: 1,
            current_safe_generation: 4,
            authoritative: auto_unknown(4),
        });
        let proj = editor.accessibility_projection().join("\n");
        assert!(proj.contains("Settings changed elsewhere"));
        assert!(proj.contains("action: Reload"));
        assert!(proj.contains("action: Reapply"));
        assert!(proj.contains("action: Discard"));
        assert!(editor.available_actions().contains(&"Reload"));
        assert!(editor.available_actions().contains(&"Reapply"));

        // Model removal while dirty → unavailable_dirty with Discard only.
        editor.apply_editor(EditorAction::ModelRemoved);
        let unavailable_proj = editor.accessibility_projection().join("\n");
        assert!(matches!(editor.phase, EditorPhase::UnavailableDirty { .. }));
        assert!(
            unavailable_proj.contains("action: Discard")
                || editor.available_actions().contains(&"Discard")
        );
        assert!(editor.available_actions().contains(&"Discard"));
        assert!(!editor.is_save_allowed());

        // Superseded completion is silent and cannot clear a newer busy state.
        let mut editor = MultimodalCapabilityEditor::new(identity(1), auto_unknown(1));
        editor.apply_editor(EditorAction::Edit {
            modality: MediaModality::Image,
            draft: DraftOverride::Supported,
        });
        editor.apply_editor(EditorAction::Save);
        editor.apply_editor(EditorAction::SelectionChanged {
            identity: SelectionIdentity {
                provider_id: "p".into(),
                model_id: "m".into(),
                selection_generation: 9,
                config_generation: 9,
            },
            authoritative: auto_unknown(9),
        });
        assert!(editor.visible_busy_label().is_none());
        editor.apply_editor(EditorAction::SaveSuccess {
            save_id: OperationId(1),
            provider_id: "p".into(),
            model_id: "m".into(),
            selection_generation: 1,
            base_config_generation: 1,
            saved_generation: 100,
            authoritative: supported_model(100),
        });
        assert!(matches!(
            editor.last_announcement(),
            AccessibilityAnnouncement::None
        ));
        assert!(
            !editor
                .accessibility_projection()
                .iter()
                .any(|l| l.contains("Media capability settings saved"))
        );
    }

    #[test]
    fn multimodal_capability_ui_save_reset_round_trip() {
        let mut base = supported_model(1);
        base.image.draft = DraftOverride::Unsupported;
        base.image.effective = resolved(
            CapabilityStatus::Unsupported,
            EffectiveCapabilitySource::Override,
            1,
        );
        let mut editor = MultimodalCapabilityEditor::new(identity(1), base);
        // Explicit Unsupported survives refresh.
        editor.apply_refresh(RefreshAction::Refresh);
        let refresh_id = match &editor.refresh {
            RefreshPhase::Refreshing { refresh_id, .. } => *refresh_id,
            other => panic!("{other:?}"),
        };
        let mut detected = supported_model(2);
        detected.image.detected = resolved(
            CapabilityStatus::Supported,
            EffectiveCapabilitySource::Model,
            2,
        );
        editor.apply_refresh(RefreshAction::RefreshSuccess {
            refresh_id,
            selection_generation: 1,
            config_generation: 1,
            detected,
        });
        assert_eq!(editor.working.image.draft, DraftOverride::Unsupported);

        // Auto removes only one override.
        editor.apply_editor(EditorAction::Edit {
            modality: MediaModality::Image,
            draft: DraftOverride::Auto,
        });
        editor.apply_editor(EditorAction::Edit {
            modality: MediaModality::Audio,
            draft: DraftOverride::Supported,
        });
        assert_eq!(editor.working.image.draft, DraftOverride::Auto);
        assert_eq!(editor.working.audio.draft, DraftOverride::Supported);
        assert_eq!(editor.working.video.draft, DraftOverride::Auto);
    }

    #[test]
    fn multimodal_capability_ui_keyboard_focus_and_narrow_terminal() {
        let mut editor = MultimodalCapabilityEditor::new(identity(1), supported_model(1));
        editor.set_focused_row(0);
        assert_eq!(editor.focused_row(), 0);
        editor.set_focused_row(2);
        assert_eq!(editor.focused_row(), 2);
        editor.apply_editor(EditorAction::Cycle {
            modality: MediaModality::ALL[editor.focused_row()],
        });
        assert_eq!(editor.working.video.draft, DraftOverride::Supported);
        assert_eq!(editor.working.image.draft, DraftOverride::Auto);

        editor.apply_editor(EditorAction::Save);
        let save_id = match &editor.phase {
            EditorPhase::Saving { save_id, .. } => *save_id,
            other => panic!("{other:?}"),
        };
        editor.apply_editor(EditorAction::SaveSafeFailure {
            save_id,
            provider_id: "p".into(),
            model_id: "m".into(),
            selection_generation: 1,
            base_config_generation: 1,
            reason: "conflict".into(),
        });
        let narrow = editor.narrow_layout_lines(20);
        assert!(narrow.iter().any(|l| l.contains("draft:")));
        assert!(narrow.iter().any(|l| l.contains("Retry")));
        // Draft vs effective remain distinct in narrow layout.
        assert!(narrow.iter().any(|l| l.contains("Video input")));
        assert!(narrow.iter().any(|l| l.contains("draft: Supported")));
        assert!(narrow.iter().any(|l| l.contains("Auto —")
            || l.contains("Supported —")
            || l.contains("RequiresEntitlement")));
    }
}
