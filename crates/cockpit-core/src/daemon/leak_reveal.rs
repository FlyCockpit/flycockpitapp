//! Channel-agnostic leak-reveal consumption core.
//!
//! This is the single funnel through which a revealed leak secret is produced.
//! It knows nothing about transports: the in-process caller and the Unix
//! peer-authenticated reveal socket both hex-decode the presented capability
//! and call [`consume_leak_reveal`]. Ordinary daemon codecs cannot represent a
//! reveal at all (the request/response variants were removed), so this core is
//! the only place plaintext leaves the protected store.
//!
//! Fail-closed rules enforced here (never leak on an error/log channel):
//! * the pending capability is `take()`n under the state lock **before any DB
//!   read**, so a consumed capability is gone even when the reveal later fails;
//! * the presented token is compared **constant-time** against the stored raw
//!   token, only **after** hex-decode;
//! * every authorization-class failure (no slot, bad/short hex, token mismatch,
//!   expired, record missing/deleted, rehydrate failure) collapses to one
//!   content-free [`LeakRevealDenied::Unauthorized`];
//! * the rolling rate limit (3 successful reveals / 60s) is checked before
//!   consuming and surfaces **only** as [`LeakRevealDenied::RateLimited`].

use std::path::Path;

use zeroize::Zeroizing;

use crate::daemon::server::DaemonContext;
use crate::leaks::{LEAK_REVEAL_MAX_PLAINTEXT_BYTES, RevealStart, ct_eq_32, decode_hex_32};
use crate::redact::protected_redaction_history::ProtectedRedactionHistory;

/// A revealed leak secret handed by value to the caller. Holds the plaintext in
/// a [`Zeroizing<String>`] and derives neither `Clone` nor `Serialize`; its
/// manual `Debug` never prints the plaintext.
pub struct RevealedLeakSecret {
    pub report_id: String,
    pub plaintext: Zeroizing<String>,
    pub generation: u64,
}

impl std::fmt::Debug for RevealedLeakSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevealedLeakSecret")
            .field("report_id", &self.report_id)
            .field("generation", &self.generation)
            .field(
                "plaintext",
                &format_args!("[REDACTED; {} bytes]", self.plaintext.len()),
            )
            .finish()
    }
}

/// Content-free reveal denial vocabulary. Every discriminant is report- and
/// input-independent; `Unauthorized` is byte-identical for every
/// authorization-class failure. Rate-limit is exclusively `RateLimited`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakRevealDenied {
    Unauthorized,
    RateLimited,
    UnavailablePlatform,
    Internal,
}

/// Consume a presented capability against `ctx`'s single reveal slot and return
/// the rehydrated plaintext, or a content-free denial. `now_ms` is injected so
/// tests drive expiry and the rate window deterministically.
pub async fn consume_leak_reveal(
    ctx: &DaemonContext,
    capability_hex: &str,
    now_ms: i64,
) -> Result<RevealedLeakSecret, LeakRevealDenied> {
    // Rate-limit + take the slot + RESERVE an in-flight rate slot atomically
    // under the state lock, before any DB read. The reservation counts toward
    // the limit so concurrent reveals cannot all pass a `< 3` check while their
    // successes are still pending across the `.await`s below. The lock is
    // dropped before the first await.
    let cap = {
        let mut state = ctx
            .leak_reveal_state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match state.begin_reveal(now_ms) {
            RevealStart::RateLimited => return Err(LeakRevealDenied::RateLimited),
            RevealStart::NoCapability => return Err(LeakRevealDenied::Unauthorized),
            RevealStart::Consumed(cap) => cap,
        }
    };

    // A reservation is now held (reserve key == `now_ms`). Every exit below MUST
    // either confirm it (success) or release it (any failure) — do the fallible
    // work in a helper so a single site finalizes the reservation.
    let result = reveal_after_reservation(ctx, &cap, capability_hex, now_ms).await;
    {
        let mut state = ctx
            .leak_reveal_state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match &result {
            Ok(_) => state.confirm_success(now_ms, now_ms),
            Err(_) => state.release_reservation(now_ms),
        }
    }
    result
}

/// The fallible reveal work, run while an in-flight rate reservation is held.
/// The capability is already consumed (fail-closed): every failure here is a
/// content-free denial and the caller releases the reservation.
async fn reveal_after_reservation(
    ctx: &DaemonContext,
    cap: &crate::leaks::PendingCapability,
    capability_hex: &str,
    now_ms: i64,
) -> Result<RevealedLeakSecret, LeakRevealDenied> {
    let decoded = decode_hex_32(capability_hex).ok_or(LeakRevealDenied::Unauthorized)?;
    if !ct_eq_32(&decoded, cap.token()) {
        return Err(LeakRevealDenied::Unauthorized);
    }
    if now_ms >= cap.expires_at_ms() {
        return Err(LeakRevealDenied::Unauthorized);
    }

    let record = match ctx.db.protected_leak_record_get(cap.report_id()).await {
        Ok(Some(record)) => record,
        Ok(None) => return Err(LeakRevealDenied::Unauthorized),
        Err(_) => return Err(LeakRevealDenied::Internal),
    };
    if record.status == crate::db::protected_leak_records::LeakRecordStatus::Deleted {
        return Err(LeakRevealDenied::Unauthorized);
    }

    let resolver = ctx
        .redaction_key_resolver()
        .map_err(|_| LeakRevealDenied::Internal)?;
    let history = ProtectedRedactionHistory::new(&ctx.db, resolver.as_ref());
    // A retired/zeroed row (delete race) or integrity failure fails closed as
    // Unauthorized — no oracle distinguishing "deleted" from "never authorized".
    let rehydrated = match history.rehydrate_by_history_id(&record.history_id).await {
        Ok(literal) => literal,
        Err(_) => return Err(LeakRevealDenied::Unauthorized),
    };
    let plaintext = match rehydrated.as_str() {
        Ok(s) => s,
        Err(_) => return Err(LeakRevealDenied::Internal),
    };
    if plaintext.len() > LEAK_REVEAL_MAX_PLAINTEXT_BYTES {
        return Err(LeakRevealDenied::Internal);
    }

    Ok(RevealedLeakSecret {
        report_id: cap.report_id().to_owned(),
        plaintext,
        generation: now_ms as u64,
    })
}

/// The unified production reveal client the TUI calls with the **control**
/// socket path. Chooses the attach-appropriate path off the single derivation:
/// an in-process context (TUI hosts the daemon; only path on Windows) is used
/// directly; otherwise on Unix it derives the dedicated reveal socket path via
/// [`crate::daemon::DaemonPaths::leak_reveal_socket_path`] (never a divergent
/// basename) and connects to the peer-authenticated reveal socket. A non-Unix
/// build with no in-process context truly cannot provide a reveal path →
/// [`LeakRevealDenied::UnavailablePlatform`].
pub async fn reveal_leak_secret(
    control_socket: &Path,
    capability: &crate::daemon::proto::LeakRevealToken,
) -> Result<RevealedLeakSecret, LeakRevealDenied> {
    if crate::daemon::server::in_process_context(control_socket).is_some() {
        return reveal_leak_secret_in_process(control_socket, capability).await;
    }
    #[cfg(unix)]
    {
        let reveal_socket = crate::daemon::DaemonPaths::leak_reveal_socket_path(control_socket);
        crate::daemon::leak_reveal_socket::reveal_leak_secret_over_socket(
            &reveal_socket,
            capability,
        )
        .await
    }
    #[cfg(not(unix))]
    {
        let _ = capability;
        Err(LeakRevealDenied::UnavailablePlatform)
    }
}

/// In-process reveal caller: resolve the registered in-process [`DaemonContext`]
/// for `socket` and invoke the consumption core. This is the production path
/// when the TUI hosts the daemon, and the **only** production path on Windows
/// (no external Unix-socket transport exists there). Returns
/// [`LeakRevealDenied::UnavailablePlatform`] when no in-process context is
/// registered for `socket`.
pub async fn reveal_leak_secret_in_process(
    socket: &Path,
    capability: &crate::daemon::proto::LeakRevealToken,
) -> Result<RevealedLeakSecret, LeakRevealDenied> {
    let ctx = match crate::daemon::server::in_process_context(socket) {
        Some(ctx) => ctx,
        None => return Err(LeakRevealDenied::UnavailablePlatform),
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    consume_leak_reveal(&ctx, capability.as_str(), now_ms).await
}
