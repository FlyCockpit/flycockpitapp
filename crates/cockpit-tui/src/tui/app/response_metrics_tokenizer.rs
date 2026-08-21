//! Response-metrics tokenizer Behavior setting confirmation.
//!
//! Settings close sends one RefreshConfig for the final candidate. Pending
//! state is `{request_id,session_id,attachment_epoch,candidate,response?,
//! snapshot?,deadline}`. Confirmation requires correlated generation/
//! candidate; unrelated snapshots update held config but never confirm.
//! Terminal error or a 10s injected-time timeout appends one durable
//! post-dialog CommandError with the finite safe-reason mapping.

use cockpit_tokenizer::TiktokenEncoding;
use std::time::Duration;
use uuid::Uuid;

/// How long confirmation may wait before timing out (injected clock).
pub(crate) const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Finite safe-reason mapping for the post-dialog error copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenizerConfirmFailure {
    InvalidConfiguration,
    RefreshFailed,
    TimedOut,
}

impl TokenizerConfirmFailure {
    pub(crate) fn safe_reason(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "configuration value is invalid",
            Self::RefreshFailed => "configuration refresh failed",
            Self::TimedOut => "confirmation timed out",
        }
    }

    pub(crate) fn error_line(self) -> String {
        format!(
            "Response metrics tokenizer was not applied: {}. Open /settings to retry.",
            self.safe_reason()
        )
    }

    pub(crate) fn from_daemon_code(code: &str) -> Self {
        if code == "invalid_response_metrics_tokenizer" {
            Self::InvalidConfiguration
        } else {
            Self::RefreshFailed
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenizerRefreshResponse {
    pub generation: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenizerConfirmPending {
    pub request_id: Uuid,
    pub session_id: Uuid,
    pub attachment_epoch: u64,
    pub candidate: TiktokenEncoding,
    pub response: Option<TokenizerRefreshResponse>,
    pub snapshot: Option<(u64, TiktokenEncoding)>,
    pub deadline: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokenizerConfirmOutcome {
    /// Still waiting for correlation.
    Pending(TokenizerConfirmPending),
    /// Confirmed; clear pending.
    Confirmed,
    /// Terminal failure; append the error line exactly once.
    Failed(TokenizerConfirmFailure),
    /// Silent cancellation (supersede / detach / reattach).
    Cancelled,
}

impl TokenizerConfirmPending {
    pub(crate) fn new(
        request_id: Uuid,
        session_id: Uuid,
        attachment_epoch: u64,
        candidate: TiktokenEncoding,
        now: Duration,
    ) -> Self {
        Self {
            request_id,
            session_id,
            attachment_epoch,
            candidate,
            response: None,
            snapshot: None,
            deadline: now + CONFIRMATION_TIMEOUT,
        }
    }

    /// Apply a RefreshConfig response correlated by request_id.
    pub(crate) fn on_response(
        mut self,
        request_id: Uuid,
        generation: u64,
        changed: bool,
        error_code: Option<&str>,
    ) -> TokenizerConfirmOutcome {
        if request_id != self.request_id {
            return TokenizerConfirmOutcome::Pending(self);
        }
        if let Some(code) = error_code {
            return TokenizerConfirmOutcome::Failed(TokenizerConfirmFailure::from_daemon_code(
                code,
            ));
        }
        self.response = Some(TokenizerRefreshResponse {
            generation,
            changed,
        });
        self.try_confirm()
    }

    /// Apply a config snapshot. Unrelated snapshots update held encoding
    /// tracking but never confirm a mismatched candidate.
    pub(crate) fn on_snapshot(
        mut self,
        generation: u64,
        encoding: TiktokenEncoding,
        related: bool,
    ) -> TokenizerConfirmOutcome {
        if related {
            self.snapshot = Some((generation, encoding));
            return self.try_confirm();
        }
        // Unrelated: keep waiting; do not confirm.
        TokenizerConfirmOutcome::Pending(self)
    }

    pub(crate) fn on_timeout(self, now: Duration) -> TokenizerConfirmOutcome {
        if now >= self.deadline {
            TokenizerConfirmOutcome::Failed(TokenizerConfirmFailure::TimedOut)
        } else {
            TokenizerConfirmOutcome::Pending(self)
        }
    }

    /// A newer write supersedes this pending confirmation silently.
    pub(crate) fn supersede(self) -> TokenizerConfirmOutcome {
        TokenizerConfirmOutcome::Cancelled
    }

    pub(crate) fn on_attachment_change(
        self,
        session_id: Uuid,
        attachment_epoch: u64,
    ) -> TokenizerConfirmOutcome {
        if self.session_id != session_id || self.attachment_epoch != attachment_epoch {
            TokenizerConfirmOutcome::Cancelled
        } else {
            TokenizerConfirmOutcome::Pending(self)
        }
    }

    fn try_confirm(self) -> TokenizerConfirmOutcome {
        let Some(response) = self.response.as_ref() else {
            return TokenizerConfirmOutcome::Pending(self);
        };
        if response.changed {
            // Changed confirms only when response and current matching
            // snapshot have exact generation/candidate.
            match self.snapshot {
                Some((snapshot_gen, enc))
                    if snapshot_gen == response.generation && enc == self.candidate =>
                {
                    TokenizerConfirmOutcome::Confirmed
                }
                _ => TokenizerConfirmOutcome::Pending(self),
            }
        } else {
            // No-op confirms only from response plus exact held daemon snapshot.
            match self.snapshot {
                Some((snapshot_gen, enc))
                    if snapshot_gen == response.generation && enc == self.candidate =>
                {
                    TokenizerConfirmOutcome::Confirmed
                }
                _ => TokenizerConfirmOutcome::Pending(self),
            }
        }
    }
}

/// The five shared encodings shown in Behavior settings (default cl100k_base).
pub(crate) fn response_metrics_tokenizer_choices() -> &'static [TiktokenEncoding] {
    &TiktokenEncoding::ALL
}

pub(crate) fn response_metrics_tokenizer_help() -> &'static str {
    "Normalizes user-experienced TPS across models. Neither provider-native nor calibration."
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(candidate: TiktokenEncoding) -> TokenizerConfirmPending {
        TokenizerConfirmPending::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            3,
            candidate,
            Duration::from_secs(0),
        )
    }

    #[test]
    fn response_metrics_tokenizer_waits_for_correlated_snapshot_confirmation() {
        let p = pending(TiktokenEncoding::Cl100k);
        // Response-first then matching snapshot.
        let mid = match p.on_response(Uuid::from_u128(1), 10, true, None) {
            TokenizerConfirmOutcome::Pending(p) => p,
            other => panic!("expected pending after response-only: {other:?}"),
        };
        match mid.on_snapshot(10, TiktokenEncoding::Cl100k, true) {
            TokenizerConfirmOutcome::Confirmed => {}
            other => panic!("expected confirm: {other:?}"),
        }

        // Snapshot-first then matching response.
        let p = pending(TiktokenEncoding::O200k);
        let mid = match p.on_snapshot(5, TiktokenEncoding::O200k, true) {
            TokenizerConfirmOutcome::Pending(p) => p,
            other => panic!("expected pending after snapshot-only: {other:?}"),
        };
        match mid.on_response(Uuid::from_u128(1), 5, false, None) {
            TokenizerConfirmOutcome::Confirmed => {}
            other => panic!("expected confirm: {other:?}"),
        }
    }

    #[test]
    fn response_metrics_tokenizer_latest_write_wins_and_ignores_stale_events() {
        let first = pending(TiktokenEncoding::Cl100k);
        // Newer write supersedes silently.
        match first.supersede() {
            TokenizerConfirmOutcome::Cancelled => {}
            other => panic!("expected cancel: {other:?}"),
        }
        let second = TokenizerConfirmPending::new(
            Uuid::from_u128(99),
            Uuid::from_u128(2),
            3,
            TiktokenEncoding::O200k,
            Duration::from_secs(0),
        );
        // Stale response for the first request_id is ignored by the new pending.
        match second.on_response(Uuid::from_u128(1), 1, true, None) {
            TokenizerConfirmOutcome::Pending(p) => {
                assert!(p.response.is_none());
                assert_eq!(p.candidate, TiktokenEncoding::O200k);
            }
            other => panic!("stale response must not bind: {other:?}"),
        }
    }

    #[test]
    fn response_metrics_tokenizer_unrelated_snapshot_never_confirms_write() {
        let p = pending(TiktokenEncoding::Cl100k);
        let mid = match p.on_response(Uuid::from_u128(1), 10, true, None) {
            TokenizerConfirmOutcome::Pending(p) => p,
            other => panic!("{other:?}"),
        };
        match mid.on_snapshot(10, TiktokenEncoding::O200k, false) {
            TokenizerConfirmOutcome::Pending(p) => {
                assert!(p.snapshot.is_none(), "unrelated must not set snapshot");
            }
            other => panic!("unrelated snapshot must not confirm: {other:?}"),
        }
    }

    #[test]
    fn response_metrics_tokenizer_attachment_replacement_cancels_confirmation() {
        let p = pending(TiktokenEncoding::Cl100k);
        match p.on_attachment_change(Uuid::from_u128(2), 99) {
            TokenizerConfirmOutcome::Cancelled => {}
            other => panic!("epoch change must cancel: {other:?}"),
        }
        let p = pending(TiktokenEncoding::Cl100k);
        match p.on_attachment_change(Uuid::from_u128(99), 3) {
            TokenizerConfirmOutcome::Cancelled => {}
            other => panic!("session change must cancel: {other:?}"),
        }
        // Same attachment stays pending.
        let p = pending(TiktokenEncoding::Cl100k);
        match p.on_attachment_change(Uuid::from_u128(2), 3) {
            TokenizerConfirmOutcome::Pending(_) => {}
            other => panic!("same attachment must stay pending: {other:?}"),
        }
    }

    #[test]
    fn response_metrics_tokenizer_confirmation_timeout_is_bounded() {
        let p = pending(TiktokenEncoding::Cl100k);
        assert_eq!(p.deadline, CONFIRMATION_TIMEOUT);
        match p.clone().on_timeout(Duration::from_secs(9)) {
            TokenizerConfirmOutcome::Pending(_) => {}
            other => panic!("before deadline: {other:?}"),
        }
        match p.on_timeout(CONFIRMATION_TIMEOUT) {
            TokenizerConfirmOutcome::Failed(TokenizerConfirmFailure::TimedOut) => {}
            other => panic!("at deadline must fail: {other:?}"),
        }
    }

    #[test]
    fn response_metrics_tokenizer_post_dialog_error_is_exactly_once_and_durable() {
        assert_eq!(
            TokenizerConfirmFailure::InvalidConfiguration.error_line(),
            "Response metrics tokenizer was not applied: configuration value is invalid. Open /settings to retry."
        );
        assert_eq!(
            TokenizerConfirmFailure::RefreshFailed.error_line(),
            "Response metrics tokenizer was not applied: configuration refresh failed. Open /settings to retry."
        );
        assert_eq!(
            TokenizerConfirmFailure::TimedOut.error_line(),
            "Response metrics tokenizer was not applied: confirmation timed out. Open /settings to retry."
        );
        assert_eq!(
            TokenizerConfirmFailure::from_daemon_code("invalid_response_metrics_tokenizer"),
            TokenizerConfirmFailure::InvalidConfiguration
        );
        assert_eq!(
            TokenizerConfirmFailure::from_daemon_code("other"),
            TokenizerConfirmFailure::RefreshFailed
        );

        // Supersede / detach / reattach append none.
        let p = pending(TiktokenEncoding::Cl100k);
        assert!(matches!(p.supersede(), TokenizerConfirmOutcome::Cancelled));
        let p = pending(TiktokenEncoding::Cl100k);
        assert!(matches!(
            p.on_attachment_change(Uuid::from_u128(9), 1),
            TokenizerConfirmOutcome::Cancelled
        ));
    }

    #[test]
    fn response_metrics_tokenizer_choices_and_help_are_documented() {
        assert_eq!(response_metrics_tokenizer_choices().len(), 5);
        assert_eq!(TiktokenEncoding::default(), TiktokenEncoding::Cl100k);
        assert!(response_metrics_tokenizer_help().contains("user-experienced TPS"));
        assert!(response_metrics_tokenizer_help().contains("Neither provider-native"));
        for enc in response_metrics_tokenizer_choices() {
            let name = enc.as_str();
            assert_eq!(TiktokenEncoding::from_str_name(name), Some(*enc));
        }
    }
}
