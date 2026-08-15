//! Dispatch-level + reveal-consumption tests for `/leaks`.
//!
//! These drive the real production entry points: the dispatch handlers
//! (`begin_leak_reveal`, `list_leak_reports`, `delete_leak_report`) with an
//! owner principal, the channel-agnostic consumption core
//! (`crate::daemon::leak_reveal::consume_leak_reveal`, the funnel both the
//! in-process and Unix-socket callers reach), the in-process caller, and — on
//! Unix — the peer-authenticated reveal socket end-to-end.

use super::*;
use crate::daemon::leak_reveal::{
    LeakRevealDenied, RevealedLeakSecret, consume_leak_reveal, reveal_leak_secret_in_process,
};
use crate::db::protected_leak_records::{LeakCategory, LeakProvenance, LeakSource};
use crate::leak_report::{LeakReportHandler, LeakReportOutcome, ReportLeakAuthority};
use zeroize::Zeroizing;

async fn seed_session(db: &Db, sid: &str) {
    let sid = sid.to_owned();
    db.write(move |conn| {
        conn.execute(
            "INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) \
             VALUES(?1,'p','/redacted',1,1)",
            [sid],
        )?;
        Ok(())
    })
    .await
    .unwrap();
}

fn provenance() -> LeakProvenance {
    LeakProvenance {
        provider_id: Some("openai".to_owned()),
        model_id: Some("gpt-4".to_owned()),
        generation: Some(1),
        connector_id: None,
    }
}

/// Seed a contained leak into the context's db via the real containment handler.
async fn seed_contained_leak(ctx: &DaemonContext, session_id: &str, secret: &str) -> String {
    seed_session(&ctx.db, session_id).await;
    let resolver = ctx.redaction_key_resolver().expect("test resolver");
    let handler = LeakReportHandler::new(&ctx.db, resolver.as_ref(), 1_000_000);
    let authority =
        ReportLeakAuthority::new(LeakSource::ModelOutput, provenance(), session_id.to_owned());
    let outcome = handler
        .report(
            &authority,
            Zeroizing::new(secret.to_owned()),
            LeakCategory::Token,
        )
        .await
        .unwrap();
    match outcome {
        LeakReportOutcome::Contained { report_id } => report_id,
        LeakReportOutcome::Deduplicated { report_id, .. } => report_id,
        other => panic!("expected contained, got {other:?}"),
    }
}

/// Drive the real `begin_leak_reveal` dispatch handler as owner and return the
/// minted proto capability.
async fn begin_capability(
    ctx: &std::sync::Arc<DaemonContext>,
    report_id: &str,
) -> proto::LeakRevealCapability {
    match super::dispatch::begin_leak_reveal(
        ctx,
        &crate::daemon::principal::ClientPrincipal::owner(),
        report_id.to_owned(),
    )
    .await
    .expect("begin should succeed for a contained record")
    {
        Response::LeakRevealCapability { capability } => capability,
        other => panic!("expected LeakRevealCapability, got {other:?}"),
    }
}

const SESSION_A: &str = "aaaaaaaa-aaaa-aaaa-aaaa-333333333333";

// ---------------------------------------------------------------------------
// AC2: single-use, expiry, replace, restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_reveal_capability_single_use_and_expiry() {
    let ctx = test_context_for_daemon_modules();
    let secret = "revealed-secret-value";
    let report_id = seed_contained_leak(&ctx, SESSION_A, secret).await;

    let cap = begin_capability(&ctx, &report_id).await;
    // Returned as 64 lowercase hex chars (32 raw token bytes at rest).
    assert_eq!(cap.capability.len(), 64);
    assert!(cap.capability.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(cap.report_id, report_id);

    let now = cap.expires_at_ms - 1_000;
    let revealed = consume_leak_reveal(&ctx, &cap.capability, now)
        .await
        .expect("first reveal succeeds");
    assert_eq!(revealed.plaintext.as_str(), secret);
    assert_eq!(revealed.report_id, report_id);

    // Second reveal with the same capability -> consumed -> Unauthorized.
    assert_eq!(
        consume_leak_reveal(&ctx, &cap.capability, now)
            .await
            .unwrap_err(),
        LeakRevealDenied::Unauthorized
    );

    // Expiry: a fresh capability revealed after its expiry -> Unauthorized.
    let cap2 = begin_capability(&ctx, &report_id).await;
    assert_eq!(
        consume_leak_reveal(&ctx, &cap2.capability, cap2.expires_at_ms)
            .await
            .unwrap_err(),
        LeakRevealDenied::Unauthorized
    );

    // Replace: a second BeginLeakReveal overwrites the slot's raw token, so the
    // FIRST (stale) token no longer matches and is rejected indistinguishably.
    // The reveal core takes the single slot BEFORE comparing (fail-closed: a
    // consumed capability is gone even when the reveal then fails), so the stale
    // attempt also empties the slot — a fresh begin is required for the next
    // reveal. This is the strongest single-use guarantee: any attempt burns the
    // one-in-flight capability.
    let cap_a = begin_capability(&ctx, &report_id).await;
    let cap_b = begin_capability(&ctx, &report_id).await;
    assert_ne!(
        cap_a.capability, cap_b.capability,
        "the replacement must mint a fresh token"
    );
    assert_eq!(
        consume_leak_reveal(&ctx, &cap_a.capability, cap_b.expires_at_ms - 1_000)
            .await
            .unwrap_err(),
        LeakRevealDenied::Unauthorized,
        "the replaced (stale) token must be rejected"
    );
    // A freshly minted token reveals — the slot mechanism recovers.
    let cap_c = begin_capability(&ctx, &report_id).await;
    let revealed = consume_leak_reveal(&ctx, &cap_c.capability, cap_c.expires_at_ms - 1_000)
        .await
        .expect("a freshly minted token reveals");
    assert_eq!(revealed.plaintext.as_str(), secret);

    // Restart: a fresh context (empty slot) rejects a previously minted token.
    let fresh = test_context_for_daemon_modules();
    assert_eq!(
        consume_leak_reveal(&fresh, &cap_c.capability, cap_c.expires_at_ms - 1_000)
            .await
            .unwrap_err(),
        LeakRevealDenied::Unauthorized
    );
}

// ---------------------------------------------------------------------------
// AC3: split unauthorized surfaces
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_reveal_begin_indistinguishable_unauthorized() {
    let ctx = test_context_for_daemon_modules();
    let secret = "to-be-deleted";
    let report_id = seed_contained_leak(&ctx, SESSION_A, secret).await;

    let owner = crate::daemon::principal::ClientPrincipal::owner();

    // Unknown report id.
    let err_unknown = super::dispatch::begin_leak_reveal(&ctx, &owner, "does-not-exist".into())
        .await
        .unwrap_err();
    // Delete-missing on the ordinary owner RPC.
    let err_delete_missing = super::dispatch::delete_leak_report(&ctx, "does-not-exist".into())
        .await
        .unwrap_err();

    // Deleted record.
    super::dispatch::delete_leak_report(&ctx, report_id.clone())
        .await
        .unwrap();
    let err_deleted = super::dispatch::begin_leak_reveal(&ctx, &owner, report_id.clone())
        .await
        .unwrap_err();

    // Byte-identical serialized payloads across all three (compared to each
    // other, not to a re-stated literal).
    let a = serde_json::to_vec(&err_unknown).unwrap();
    let b = serde_json::to_vec(&err_deleted).unwrap();
    let c = serde_json::to_vec(&err_delete_missing).unwrap();
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[tokio::test]
async fn leak_reveal_denied_indistinguishable_unauthorized() {
    let ctx = test_context_for_daemon_modules();
    let report_id = seed_contained_leak(&ctx, SESSION_A, "secret").await;

    // Empty capability (no slot minted yet).
    let empty = consume_leak_reveal(&ctx, "", 1000).await.unwrap_err();

    // Non-hex / wrong-length hex (slot minted so we exercise decode failure).
    let cap = begin_capability(&ctx, &report_id).await;
    let non_hex = consume_leak_reveal(&ctx, &"z".repeat(64), cap.expires_at_ms - 1)
        .await
        .unwrap_err();
    let cap = begin_capability(&ctx, &report_id).await;
    let wrong_len = consume_leak_reveal(&ctx, "abcd", cap.expires_at_ms - 1)
        .await
        .unwrap_err();

    // Tampered token: flip one hex nibble of a valid capability.
    let cap = begin_capability(&ctx, &report_id).await;
    let mut tampered = cap.capability.clone();
    let first = tampered.remove(0);
    tampered.insert(0, if first == '0' { '1' } else { '0' });
    let tampered_err = consume_leak_reveal(&ctx, &tampered, cap.expires_at_ms - 1)
        .await
        .unwrap_err();

    // Expired token.
    let cap = begin_capability(&ctx, &report_id).await;
    let expired = consume_leak_reveal(&ctx, &cap.capability, cap.expires_at_ms)
        .await
        .unwrap_err();

    // Consumed token (second use).
    let cap = begin_capability(&ctx, &report_id).await;
    consume_leak_reveal(&ctx, &cap.capability, cap.expires_at_ms - 1)
        .await
        .unwrap();
    let consumed = consume_leak_reveal(&ctx, &cap.capability, cap.expires_at_ms - 1)
        .await
        .unwrap_err();

    // Reveal-after-delete race: mint, delete the record, then reveal.
    let cap = begin_capability(&ctx, &report_id).await;
    super::dispatch::delete_leak_report(&ctx, report_id.clone())
        .await
        .unwrap();
    let after_delete = consume_leak_reveal(&ctx, &cap.capability, cap.expires_at_ms - 1)
        .await
        .unwrap_err();

    for denial in [
        empty,
        non_hex,
        wrong_len,
        tampered_err,
        expired,
        consumed,
        after_delete,
    ] {
        assert_eq!(denial, LeakRevealDenied::Unauthorized);
    }
}

// ---------------------------------------------------------------------------
// AC4: rate limit — three successful reveals per minute
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_reveal_rate_limit_three_per_minute() {
    let ctx = test_context_for_daemon_modules();
    let secret = "rate-limited-secret";
    let report_id = seed_contained_leak(&ctx, SESSION_A, secret).await;

    // Mint capabilities directly into the production slot with a controlled
    // far-future expiry so time is fully injected (dispatch `begin` stamps a
    // real-clock expiry that would race the injected window). The consumption
    // core is the real production reveal path.
    let far = 10_000_000i64;
    let mint = |report: &str| {
        let (token, hex) = crate::leaks::mint_reveal_token();
        ctx.leak_reveal_state
            .lock()
            .unwrap()
            .mint(token, report.to_owned(), far);
        hex
    };

    let t = 1_000_000i64;
    // Three successful reveals inside the window.
    for _ in 0..3 {
        let hex = mint(&report_id);
        let revealed = consume_leak_reveal(&ctx, &hex, t).await.expect("reveal ok");
        assert_eq!(revealed.plaintext.as_str(), secret);
    }

    // A failed reveal does NOT count toward the limit (bad token at t).
    let _ = consume_leak_reveal(&ctx, &"0".repeat(64), t)
        .await
        .unwrap_err();

    // The 4th successful-path reveal inside 60s -> RateLimited only, and the
    // pending capability is NOT consumed.
    let hex = mint(&report_id);
    assert_eq!(
        consume_leak_reveal(&ctx, &hex, t + 1_000)
            .await
            .unwrap_err(),
        LeakRevealDenied::RateLimited
    );
    assert!(ctx.leak_reveal_state.lock().unwrap().pending_is_some());

    // After the window slides, the surviving capability succeeds.
    let revealed = consume_leak_reveal(&ctx, &hex, t + 61_000)
        .await
        .expect("reveal after window slide");
    assert_eq!(revealed.plaintext.as_str(), secret);
}

// ---------------------------------------------------------------------------
// AC5: channel + in-process path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_reveal_channel_and_proto_surface() {
    let ctx = test_context_for_daemon_modules();
    let secret = "in-process-secret";
    let report_id = seed_contained_leak(&ctx, SESSION_A, secret).await;
    let cap = begin_capability(&ctx, &report_id).await;

    // No usable in-process context and no socket for an unknown path ->
    // content-free UnavailablePlatform (never a successful ordinary reveal).
    let unknown = std::path::Path::new("/tmp/definitely-not-registered-cockpit.sock");
    assert_eq!(
        reveal_leak_secret_in_process(unknown, &cap.capability)
            .await
            .unwrap_err(),
        LeakRevealDenied::UnavailablePlatform
    );

    // Register the in-process context; the in-process caller reveals via the
    // consumption core.
    super::register_in_process_context(ctx.clone());
    let revealed = reveal_leak_secret_in_process(&ctx.paths.socket, &cap.capability)
        .await
        .expect("in-process reveal succeeds");
    assert_eq!(revealed.plaintext.as_str(), secret);

    // The revealed value never appears in its own Debug output.
    let dbg = format!("{revealed:?}");
    assert!(
        !dbg.contains(secret),
        "RevealedLeakSecret Debug leaks plaintext"
    );
}

// ---------------------------------------------------------------------------
// AC5: Unix peer-authenticated reveal socket end-to-end
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn leak_reveal_unix_peercred_end_to_end() {
    let ctx = test_context_for_daemon_modules();
    let secret = "peer-auth-secret";
    let report_id = seed_contained_leak(&ctx, SESSION_A, secret).await;
    let cap = begin_capability(&ctx, &report_id).await;

    // Bind the derived 0600 reveal socket under a private temp dir.
    let dir = tempfile::tempdir().unwrap();
    let reveal_path = dir.path().join("cockpit-leak-reveal.sock");
    let listener = crate::daemon::bind_private_socket(&reveal_path).expect("bind reveal socket");
    let server_ctx = ctx.clone();
    let accept = tokio::spawn(async move {
        let _ =
            crate::daemon::leak_reveal_socket::run_reveal_accept_loop(server_ctx, listener).await;
    });

    // A same-uid peer (this process) presenting the 64-char hex capability over
    // the shared frame codecs receives a status-tagged Ok whose plaintext matches.
    let revealed = crate::daemon::leak_reveal_socket::reveal_leak_secret_over_socket(
        &reveal_path,
        &cap.capability,
    )
    .await
    .expect("peer-auth reveal succeeds");
    assert_eq!(revealed.plaintext.as_str(), secret);
    assert_eq!(revealed.report_id, report_id);

    // A wrong-length / non-hex capability fails closed (the client rejects a
    // non-64 capability before contacting the daemon).
    assert_eq!(
        crate::daemon::leak_reveal_socket::reveal_leak_secret_over_socket(&reveal_path, "abcd")
            .await
            .unwrap_err(),
        LeakRevealDenied::Unauthorized
    );
    // A structurally valid but non-hex 64-char capability -> Unauthorized after
    // the consumption core's constant-time compare fails.
    let cap2 = begin_capability(&ctx, &report_id).await;
    let _ = cap2;
    assert_eq!(
        crate::daemon::leak_reveal_socket::reveal_leak_secret_over_socket(
            &reveal_path,
            &"z".repeat(64),
        )
        .await
        .unwrap_err(),
        LeakRevealDenied::Unauthorized
    );

    accept.abort();
}

/// S1: a request that is a valid 67-byte frame FOLLOWED BY a trailing byte must
/// be rejected (closed with no content) — the closed frame admits no trailing
/// data, so the plaintext is never revealed.
#[cfg(unix)]
#[tokio::test]
async fn leak_reveal_socket_rejects_trailing_bytes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let ctx = test_context_for_daemon_modules();
    let secret = "trailing-secret-value";
    let report_id = seed_contained_leak(&ctx, SESSION_A, secret).await;
    let cap = begin_capability(&ctx, &report_id).await;

    let dir = tempfile::tempdir().unwrap();
    let reveal_path = dir.path().join("cockpit-leak-reveal.sock");
    let listener = crate::daemon::bind_private_socket(&reveal_path).expect("bind reveal socket");
    let server_ctx = ctx.clone();
    let accept = tokio::spawn(async move {
        let _ =
            crate::daemon::leak_reveal_socket::run_reveal_accept_loop(server_ctx, listener).await;
    });

    // A valid 67-byte request frame plus one trailing byte.
    let mut frame = crate::daemon::leak_reveal_frame::encode_request(
        &crate::daemon::leak_reveal_frame::LeakRevealSocketRequest {
            capability_hex: cap.capability.clone(),
        },
    )
    .unwrap();
    frame.push(0xFF);

    let mut stream = tokio::net::UnixStream::connect(&reveal_path).await.unwrap();
    stream.write_all(&frame).await.unwrap();
    let _ = stream.flush().await;

    // The server must close (clean EOF) BEFORE the deadline — this asserts S1's
    // no-pin contract (a hang regression fails here instead of passing on an
    // ignored timeout) — and it returns no content at all.
    let mut resp = Vec::new();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut resp),
    )
    .await
    .expect("server must close (EOF) before the deadline — no pinned handler")
    .expect("read should observe a clean EOF, not an error");
    assert_eq!(bytes, 0, "trailing-byte request must receive no content");
    assert!(
        resp.is_empty(),
        "trailing-byte request must receive no content"
    );

    accept.abort();
}

// ---------------------------------------------------------------------------
// AC9 (reveal side): delete makes future recovery fail closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_delete_prevents_future_reveal_and_is_idempotent() {
    let ctx = test_context_for_daemon_modules();
    let report_id = seed_contained_leak(&ctx, SESSION_A, "deletable").await;

    // Delete succeeds and returns LeakReportDeleted.
    match super::dispatch::delete_leak_report(&ctx, report_id.clone())
        .await
        .unwrap()
    {
        Response::LeakReportDeleted { report_id: rid } => assert_eq!(rid, report_id),
        other => panic!("expected LeakReportDeleted, got {other:?}"),
    }

    // Deleting again is idempotent success.
    super::dispatch::delete_leak_report(&ctx, report_id.clone())
        .await
        .unwrap();

    // A reveal against the deleted record fails closed as Unauthorized.
    let (token, hex) = crate::leaks::mint_reveal_token();
    ctx.leak_reveal_state
        .lock()
        .unwrap()
        .mint(token, report_id.clone(), 10_000_000);
    assert_eq!(
        consume_leak_reveal(&ctx, &hex, 1_000_000)
            .await
            .unwrap_err(),
        LeakRevealDenied::Unauthorized
    );

    // Delete of a genuinely missing report returns the AC3 unauthorized payload.
    let err = super::dispatch::delete_leak_report(&ctx, "never-existed".into())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Authorization);
    assert_eq!(err.message, "unauthorized");
}

// Keep the RevealedLeakSecret type referenced so an accidental removal of its
// fields breaks this module.
#[allow(dead_code)]
fn _assert_revealed_shape(r: &RevealedLeakSecret) -> (&str, u64) {
    (&r.report_id, r.generation)
}
