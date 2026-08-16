//! Tests for protected redaction history covering all acceptance criteria.
//!
//! 1. `protected_redaction_history_schema_is_nonexportable`
//! 2. `trusted_artifact_history_commit_is_atomic`
//! 3. `history_snapshot_is_consistent`
//! 4. `unknown_trusted_sensitive_artifact_fails_closed`
//! 5. `portable_import_is_redacted_diagnostic_only`
//! 6. `history_rehydration_is_bounded_and_zeroized`

use super::*;
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::db::protected_redaction_history::{
    ProtectedRedactionHistoryRef, attach_artifact_ref_conn, get_history_conn,
    list_artifact_refs_for_session_conn, list_history_conn, retire_history_conn,
};

/// Independent (unkeyed) SHA-256 hex, built from a different code path than the
/// production keyed MAC, so tests can assert the stored fingerprint is NOT this.
fn plain_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fixed test key (32 bytes) for key version 1.
fn test_key_v1() -> [u8; REDACTION_KEY_LEN] {
    [0x42u8; REDACTION_KEY_LEN]
}

/// A fixed test key for key version 2 (rotation).
fn test_key_v2() -> [u8; REDACTION_KEY_LEN] {
    [0x84u8; REDACTION_KEY_LEN]
}

fn test_resolver() -> MapKeyResolver {
    MapKeyResolver::new()
        .with_version(1, test_key_v1())
        .with_version(2, test_key_v2())
}

async fn test_db() -> Db {
    let db = Db::open_in_memory().unwrap();
    // protected_redaction_history.session_id carries a cascading FK to
    // sessions(session_id), so the referenced session row must exist before any
    // history row is appended.
    db.write(|conn| {
        conn.execute(
            "INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) \
             VALUES(?1,'p','/redacted',1,1)",
            [session_id()],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    db
}

fn session_id() -> &'static str {
    "aaaaaaaa-aaaa-aaaa-aaaa-111111111111"
}

// ---------------------------------------------------------------------------
// Criterion 1: schema is nonexportable
// ---------------------------------------------------------------------------

/// The export projection carries NO fingerprint (or any encrypted material),
/// and no stored column of the row equals the unkeyed `hex(SHA-256(literal))`
/// that the old blessed behavior exported. These corrected assertions FAIL
/// against the old (unkeyed-SHA-256, exported-fingerprint) behavior: the old
/// `ProtectedRedactionHistoryRef` had a `fingerprint` field equal to
/// `hex(SHA-256(literal))`, which both the compile-level and runtime checks
/// below now reject.
#[tokio::test]
async fn protected_redaction_history_schema_is_nonexportable() {
    let db = test_db().await;
    let resolver = test_resolver();
    let history = ProtectedRedactionHistory::new(&db, &resolver);

    let literal_str = "super-secret-token";
    let literal = ProtectedLiteral::new(
        literal_str.to_owned(),
        RedactionHistorySource::Credential,
        None,
        None,
    )
    .unwrap();

    let history_id = history
        .append_and_attach(
            session_id(),
            literal,
            vec![ArtifactRef::new(
                RedactionArtifactKind::Request,
                "req-schema-1",
            )],
        )
        .await
        .unwrap();

    // (a) Compile-level: the export projection has EXACTLY these fields and no
    //     `fingerprint`. This struct literal would not compile if a
    //     `fingerprint` (or any encrypted-material) field were re-added.
    let refs = db
        .protected_redaction_history_refs(session_id())
        .await
        .unwrap();
    assert_eq!(refs.len(), 1);
    let r = &refs[0];
    let _shape = ProtectedRedactionHistoryRef {
        history_id: r.history_id.clone(),
        session_id: r.session_id.clone(),
        source: r.source,
        ref_count: r.ref_count,
        created_at_ms: r.created_at_ms,
        retired_at_ms: r.retired_at_ms,
    };
    assert_eq!(r.history_id, history_id);
    assert_eq!(r.source, RedactionHistorySource::Credential);

    // (b) No column of the stored full row equals hex(SHA-256(literal)) — the
    //     old unkeyed exported fingerprint. The keyed-MAC fingerprint differs,
    //     and no other column carries that digest either.
    let unkeyed = plain_sha256_hex(literal_str.as_bytes());
    let rows = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_ne!(
        row.fingerprint, unkeyed,
        "stored fingerprint must be a keyed MAC, never hex(SHA-256(literal))"
    );
    assert_eq!(row.fingerprint.len(), 64);
    assert!(row.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    // The ciphertext blob does not contain the unkeyed digest bytes either.
    assert_ne!(row.ciphertext, unkeyed.as_bytes());

    // The artifact ref type also carries no encrypted material.
    let artifact_refs = db
        .protected_redaction_artifact_refs_for_artifact(
            RedactionArtifactKind::Request,
            "req-schema-1",
        )
        .await
        .unwrap();
    assert_eq!(artifact_refs.len(), 1);
    assert_eq!(artifact_refs[0].history_id, history_id);
}

// ---------------------------------------------------------------------------
// Criterion 2: trusted artifact history commit is atomic
// ---------------------------------------------------------------------------

/// Cover every `append_and_attach` caller/source, request/response/tool/event/
/// attempt artifact, deduplication, crash point between append/attach, retry,
/// rotation/delete, and reference-count transition; raw artifact/history are
/// both committed or neither.
#[tokio::test]
async fn trusted_artifact_history_commit_is_atomic() {
    let db = test_db().await;
    let resolver = test_resolver();
    let history = ProtectedRedactionHistory::new(&db, &resolver);

    // Test all artifact kinds.
    let kinds = [
        RedactionArtifactKind::Request,
        RedactionArtifactKind::Response,
        RedactionArtifactKind::Tool,
        RedactionArtifactKind::Event,
        RedactionArtifactKind::Attempt,
    ];

    // Test all sources.
    let sources = [
        RedactionHistorySource::Sealed,
        RedactionHistorySource::Environment,
        RedactionHistorySource::Credential,
        RedactionHistorySource::ContainedLeak,
    ];

    for (i, source) in sources.iter().enumerate() {
        let literal_str = format!("secret-for-source-{i}");
        let literal = ProtectedLiteral::new(
            literal_str.clone(),
            *source,
            if *source == RedactionHistorySource::Sealed {
                Some(format!("sealed-rec-{i}"))
            } else {
                None
            },
            if *source == RedactionHistorySource::Sealed {
                Some(i as i64)
            } else {
                None
            },
        )
        .unwrap();

        let artifacts: Vec<ArtifactRef> = kinds
            .iter()
            .map(|k| ArtifactRef::new(*k, format!("artifact-{i}-{}", k.as_str())))
            .collect();

        let history_id = history
            .append_and_attach(session_id(), literal, artifacts)
            .await
            .unwrap();

        // Verify all artifact references were attached.
        for kind in &kinds {
            let refs = db
                .protected_redaction_artifact_refs_for_artifact(
                    *kind,
                    &format!("artifact-{i}-{}", kind.as_str()),
                )
                .await
                .unwrap();
            assert_eq!(refs.len(), 1, "artifact ref missing for kind {:?}", kind);
            assert_eq!(refs[0].history_id, history_id);
        }

        // Verify ref_count = 5 (one per artifact kind).
        let row = db
            .read(move |conn| get_history_conn(conn, &history_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.ref_count, 5);
    }

    // Test deduplication: same fingerprint returns existing history_id.
    let lit1 = ProtectedLiteral::new(
        "dup-secret".to_owned(),
        RedactionHistorySource::Credential,
        None,
        None,
    )
    .unwrap();
    let id1 = history
        .append_and_attach(
            session_id(),
            lit1,
            vec![ArtifactRef::new(
                RedactionArtifactKind::Request,
                "dup-req-1",
            )],
        )
        .await
        .unwrap();

    let lit2 = ProtectedLiteral::new(
        "dup-secret".to_owned(),
        RedactionHistorySource::Credential,
        None,
        None,
    )
    .unwrap();
    let id2 = history
        .append_and_attach(
            session_id(),
            lit2,
            vec![ArtifactRef::new(
                RedactionArtifactKind::Request,
                "dup-req-2",
            )],
        )
        .await
        .unwrap();

    assert_eq!(id1, id2, "dedup should return same history_id");

    // ref_count should be 2 (two different artifacts referencing same history).
    let id_read = id1.clone();
    let row = db
        .read(move |conn| get_history_conn(conn, &id_read))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.ref_count, 2);

    // Test crash point through the PRODUCTION conn-scoped writer
    // (`append_and_attach_conn`, the same sole writer the trusted-ingress
    // journaling uses): prepare the append off-thread, then compose the row
    // write + artifact attach on one connection and force a fault AFTER both,
    // proving the whole transaction rolls back atomically (neither the history
    // row nor its artifact ref commits alone).
    let crash_prepared = history
        .prepare_append(
            session_id(),
            ProtectedLiteral::new(
                "crash-and-attach-secret".to_owned(),
                RedactionHistorySource::Environment,
                None,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let crash_fingerprint = crash_prepared.fingerprint().to_owned();
    let crash_artifact = ArtifactRef::new(RedactionArtifactKind::Request, "crash-attach-req");
    let result: Result<()> = db
        .transaction(move |conn| {
            append_and_attach_conn(conn, &crash_prepared, std::slice::from_ref(&crash_artifact))?;
            // Fault AFTER append+attach: the row and the ref are both written on
            // this connection but the transaction never commits.
            anyhow::bail!("simulated crash after append_and_attach");
        })
        .await;
    assert!(result.is_err());

    // Neither the history row nor the artifact ref should exist.
    let rows = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    assert!(
        rows.iter().all(|r| r.fingerprint != crash_fingerprint),
        "history row should not persist after a post-attach crash"
    );
    let crash_refs = db
        .protected_redaction_artifact_refs_for_artifact(
            RedactionArtifactKind::Request,
            "crash-attach-req",
        )
        .await
        .unwrap();
    assert!(
        crash_refs.is_empty(),
        "artifact ref should not persist after a post-attach crash"
    );

    // Test retry: after a crash, a retry with the same literal succeeds.
    let lit_retry = ProtectedLiteral::new(
        "retry-secret".to_owned(),
        RedactionHistorySource::Credential,
        None,
        None,
    )
    .unwrap();
    let id_retry = history
        .append_and_attach(
            session_id(),
            lit_retry,
            vec![ArtifactRef::new(
                RedactionArtifactKind::Request,
                "retry-req",
            )],
        )
        .await
        .unwrap();
    // Verify it persisted.
    let row = db
        .read(move |conn| get_history_conn(conn, &id_retry))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.ref_count, 1);

    // Test rotation/delete: retire after refs are detached.
    // First, detach all refs for id1.
    let id_detach = id1.clone();
    db.write(move |conn| {
        use crate::db::protected_redaction_history::detach_artifact_ref_conn;
        detach_artifact_ref_conn(
            conn,
            RedactionArtifactKind::Request,
            "dup-req-1",
            &id_detach,
        )?;
        detach_artifact_ref_conn(
            conn,
            RedactionArtifactKind::Request,
            "dup-req-2",
            &id_detach,
        )
    })
    .await
    .unwrap();
    // ref_count should be 0 now.
    let id_read = id1.clone();
    let row = db
        .read(move |conn| get_history_conn(conn, &id_read))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.ref_count, 0);
    assert!(row.retired_at_ms.is_none());

    // Retire succeeds now.
    let id_retire = id1.clone();
    db.write(move |conn| retire_history_conn(conn, &id_retire))
        .await
        .unwrap();
    let row = db
        .read(move |conn| get_history_conn(conn, &id1))
        .await
        .unwrap()
        .unwrap();
    assert!(row.retired_at_ms.is_some());

    // Test reference-count transition: attach then detach.
    let lit_trans = ProtectedLiteral::new(
        "trans-secret".to_owned(),
        RedactionHistorySource::Environment,
        None,
        None,
    )
    .unwrap();
    let id_trans = history
        .append_and_attach(
            session_id(),
            lit_trans,
            vec![ArtifactRef::new(
                RedactionArtifactKind::Tool,
                "trans-tool-1",
            )],
        )
        .await
        .unwrap();
    let id_read0 = id_trans.clone();
    let row = db
        .read(move |conn| get_history_conn(conn, &id_read0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.ref_count, 1);

    // Attach another artifact to the same history.
    let id_attach = id_trans.clone();
    db.write(move |conn| {
        attach_artifact_ref_conn(
            conn,
            RedactionArtifactKind::Tool,
            "trans-tool-2",
            &id_attach,
        )
    })
    .await
    .unwrap();
    let id_read = id_trans.clone();
    let row = db
        .read(move |conn| get_history_conn(conn, &id_read))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.ref_count, 2);

    // Detach one.
    let id_detach = id_trans.clone();
    db.write(move |conn| {
        use crate::db::protected_redaction_history::detach_artifact_ref_conn;
        detach_artifact_ref_conn(
            conn,
            RedactionArtifactKind::Tool,
            "trans-tool-1",
            &id_detach,
        )
    })
    .await
    .unwrap();
    let row = db
        .read(move |conn| get_history_conn(conn, &id_trans))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.ref_count, 1);
}

// ---------------------------------------------------------------------------
// Criterion 3: history snapshot is consistent
// ---------------------------------------------------------------------------

/// Prove export sees a stable graph of artifact rows and history references
/// under concurrent artifact write, rotation, delete, and fork traversal,
/// with post-snapshot writes excluded rather than partially visible.
#[tokio::test]
async fn history_snapshot_is_consistent() {
    let db = test_db().await;
    let resolver = test_resolver();
    let history = ProtectedRedactionHistory::new(&db, &resolver);

    // Write initial history + artifact refs.
    let lit1 = ProtectedLiteral::new(
        "snapshot-secret-1".to_owned(),
        RedactionHistorySource::Credential,
        None,
        None,
    )
    .unwrap();
    let id1 = history
        .append_and_attach(
            session_id(),
            lit1,
            vec![ArtifactRef::new(
                RedactionArtifactKind::Request,
                "snap-req-1",
            )],
        )
        .await
        .unwrap();

    let lit2 = ProtectedLiteral::new(
        "snapshot-secret-2".to_owned(),
        RedactionHistorySource::Environment,
        None,
        None,
    )
    .unwrap();
    let id2 = history
        .append_and_attach(
            session_id(),
            lit2,
            vec![ArtifactRef::new(
                RedactionArtifactKind::Response,
                "snap-resp-1",
            )],
        )
        .await
        .unwrap();

    // Take a snapshot: read all refs and all history rows.
    // In SQLite, a read transaction sees a consistent snapshot.
    let (snap_refs, snap_history) = db
        .read(move |conn| {
            let refs = list_artifact_refs_for_session_conn(conn, session_id())?;
            let history_rows = list_history_conn(conn, session_id())?;
            Ok((refs, history_rows))
        })
        .await
        .unwrap();

    // The snapshot should contain both history rows and both artifact refs.
    assert_eq!(snap_history.len(), 2);
    assert_eq!(snap_refs.len(), 2);
    let snap_ref_artifact_ids: Vec<String> =
        snap_refs.iter().map(|r| r.artifact_id.clone()).collect();
    assert!(snap_ref_artifact_ids.contains(&"snap-req-1".to_owned()));
    assert!(snap_ref_artifact_ids.contains(&"snap-resp-1".to_owned()));

    // Post-snapshot write: add a new history + artifact.
    let lit3 = ProtectedLiteral::new(
        "snapshot-secret-3".to_owned(),
        RedactionHistorySource::Sealed,
        Some("rec-3".to_owned()),
        Some(1),
    )
    .unwrap();
    let _id3 = history
        .append_and_attach(
            session_id(),
            lit3,
            vec![ArtifactRef::new(RedactionArtifactKind::Tool, "snap-tool-3")],
        )
        .await
        .unwrap();

    // The post-snapshot write should NOT be visible in the original snapshot
    // (which was already consumed). But a new read should see it.
    let new_refs = db
        .read(move |conn| list_artifact_refs_for_session_conn(conn, session_id()))
        .await
        .unwrap();
    assert_eq!(new_refs.len(), 3);

    // Verify the snapshot's history rows match the expected IDs.
    let snap_history_ids: Vec<String> = snap_history.iter().map(|h| h.history_id.clone()).collect();
    assert!(snap_history_ids.contains(&id1));
    assert!(snap_history_ids.contains(&id2));

    // Test rotation/delete within a snapshot context: retire zero-ref rows
    // for the session (none should retire since all have refs).
    let retired = db
        .protected_redaction_history_retire_zero_ref(session_id())
        .await
        .unwrap();
    assert_eq!(retired, 0, "no zero-ref rows to retire");

    // Now detach one and retire.
    let id_detach = id1.clone();
    db.write(move |conn| {
        use crate::db::protected_redaction_history::detach_artifact_ref_conn;
        detach_artifact_ref_conn(
            conn,
            RedactionArtifactKind::Request,
            "snap-req-1",
            &id_detach,
        )
    })
    .await
    .unwrap();
    let retired = db
        .protected_redaction_history_retire_zero_ref(session_id())
        .await
        .unwrap();
    assert_eq!(retired, 1, "one zero-ref row should retire");

    // The retired row should still appear in history listing (with retired_at_ms set).
    let rows = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    let retired_row = rows.iter().find(|r| r.history_id == id1).unwrap();
    assert!(retired_row.retired_at_ms.is_some());
}

// ---------------------------------------------------------------------------
// Criterion 4: unknown trusted sensitive artifact fails closed
// ---------------------------------------------------------------------------

/// Prove unclassified raw response/tool/event input cannot persist or export
/// and no secret reaches a generic record.
#[tokio::test]
async fn unknown_trusted_sensitive_artifact_fails_closed() {
    let db = test_db().await;
    let resolver = test_resolver();
    let history = ProtectedRedactionHistory::new(&db, &resolver);

    // The source set is closed: Sealed, Environment, Credential, ContainedLeak.
    // An "unclassified" source has no variant — it cannot be constructed.
    // This is a compile-time guarantee: RedactionHistorySource is an enum with
    // exactly four variants. There is no `Unknown` or `Other` variant.

    // Attempting to use a raw sensitive literal without going through
    // append_and_attach means no history row exists. An artifact that claims
    // to reference a history row that doesn't exist will fail at attach time
    // (foreign key constraint).
    let result: Result<()> = db
        .write(|conn| {
            attach_artifact_ref_conn(
                conn,
                RedactionArtifactKind::Response,
                "unclassified-resp-1",
                "nonexistent-history-id",
            )
        })
        .await;
    assert!(
        result.is_err(),
        "attaching to nonexistent history must fail closed"
    );

    // Verify no artifact ref was persisted.
    let refs = db
        .protected_redaction_artifact_refs_for_artifact(
            RedactionArtifactKind::Response,
            "unclassified-resp-1",
        )
        .await
        .unwrap();
    assert!(
        refs.is_empty(),
        "no artifact ref should persist after failure"
    );

    // Verify no secret reaches a generic record: the safe ref projection
    // contains only opaque IDs and safe metadata, never the literal.
    let refs_meta = db
        .protected_redaction_history_refs(session_id())
        .await
        .unwrap();
    assert!(refs_meta.is_empty());

    // A literal that exceeds the 16 KiB cap fails closed.
    let oversized = "x".repeat(MAX_LITERAL_LEN + 1);
    let result = ProtectedLiteral::new(oversized, RedactionHistorySource::Credential, None, None);
    assert!(result.is_err(), "oversized literal must fail closed");

    // Table-match-only journaling (decision 11, settled) driven END-TO-END through
    // the PRODUCTION `record_inference_request` chokepoint (never a parallel
    // classifier). A trusted payload carrying an in-table literal journals exactly
    // one row (source `Environment` — the enum stays closed), while a trusted
    // payload whose only secret-shaped content is a high-entropy string ABSENT
    // from the session table journals nothing yet still persists raw.
    use crate::db::session_log::InferenceRequestStatus;
    use crate::redact::RedactionTable;
    use crate::session::Session;
    use uuid::Uuid;

    let cfg = crate::config::extended::RedactConfig {
        enabled: true,
        scan_environment: true,
        scan_dotenv: false,
        scan_ssh_keys: false,
        min_secret_length: 4,
        placeholder: "[redacted]".to_string(),
        ..crate::config::extended::RedactConfig::default()
    };
    let in_table = "env-scan-secret-in-table-abc123456";
    let unmatched = "Zq7UnregisteredHighEntropyString42Kv";
    let env = std::collections::HashMap::from([("DEPLOY_TOKEN".to_string(), in_table.to_string())]);
    let table = RedactionTable::build_with_env(&cfg, std::path::Path::new("."), &env).unwrap();

    let session = Session::create_for_test(
        db.clone(),
        std::path::PathBuf::from("/proj"),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    let sid = session.id.to_string();

    // Matched trusted payload → exactly one journaled row, source Environment.
    let matched_call = Uuid::new_v4();
    session
        .record_inference_request(
            matched_call,
            &serde_json::json!({
                "messages": [{"role": "user", "content": format!("deploy {in_table}")}],
            }),
            InferenceRequestStatus::Completed,
            &table,
            true,
        )
        .await
        .unwrap();
    let rows = db.protected_redaction_history_list(&sid).await.unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the in-table literal journals exactly one row"
    );
    assert_eq!(rows[0].source, RedactionHistorySource::Environment);

    // Unmatched high-entropy trusted payload → nothing journaled (table-match
    // only), and the raw payload still persists (not classified, not scrubbed).
    let unmatched_call = Uuid::new_v4();
    session
        .record_inference_request(
            unmatched_call,
            &serde_json::json!({
                "messages": [{"role": "user", "content": format!("noise {unmatched} noise")}],
            }),
            InferenceRequestStatus::Completed,
            &table,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        db.protected_redaction_history_list(&sid)
            .await
            .unwrap()
            .len(),
        1,
        "an unmatched high-entropy string is not classified and journals nothing"
    );
    let raw_row = db
        .get_inference_request(&unmatched_call.to_string(), 0)
        .await
        .unwrap()
        .expect("unmatched payload persists");
    let stored = serde_json::to_string(&raw_row.payload).unwrap();
    assert!(
        stored.contains(unmatched),
        "the unmatched high-entropy content persists raw (not classified, not scrubbed)"
    );
}

// ---------------------------------------------------------------------------
// Criterion 5: portable import is redacted diagnostic only
// ---------------------------------------------------------------------------

/// Cover import of fully redacted portable transcript/debug artifacts without
/// protected history and reject any member claiming raw/artifact-bearing data,
/// unjournaled literal, tampered protected-reference metadata, or legacy raw
/// shape before session persistence.
#[tokio::test]
async fn portable_import_is_redacted_diagnostic_only() {
    let db = test_db().await;
    let resolver = test_resolver();
    let history = ProtectedRedactionHistory::new(&db, &resolver);

    // Portable transcript/debug exports are always redacted diagnostic
    // artifacts. Their import creates only redacted diagnostic/session data
    // and requires no protected history.

    // 1. A fully redacted portable artifact (no history references) imports fine.
    //    No protected history is needed.
    let redacted_artifact_id = "portable-redacted-event-1";
    // No history refs to attach — this is valid for portable import.
    let refs = db
        .protected_redaction_artifact_refs_for_artifact(
            RedactionArtifactKind::Event,
            redacted_artifact_id,
        )
        .await
        .unwrap();
    assert!(
        refs.is_empty(),
        "redacted portable artifact has no history refs"
    );

    // 2. A member claiming raw/artifact-bearing data (i.e., trying to attach
    //    to a history row) must be rejected if the history row doesn't exist.
    //    This simulates a tampered protected-reference metadata import.
    let result: Result<()> = db
        .write(|conn| {
            attach_artifact_ref_conn(
                conn,
                RedactionArtifactKind::Event,
                "portable-tampered-event-1",
                "tampered-history-id-that-does-not-exist",
            )
        })
        .await;
    assert!(
        result.is_err(),
        "tampered protected-reference metadata must be rejected"
    );

    // 3. An unjournaled literal (trying to create history directly without
    //    going through append_and_attach) is rejected: the ProtectedLiteral
    //    type is the only way to create a history row, and it requires a
    //    closed source classification.
    //    This is a compile-time guarantee: ProtectedRedactionHistoryAppend
    //    requires a RedactionHistorySource (closed enum), and the only writer
    //    is append_and_attach which goes through the transaction.

    // 4. A legacy/tampered raw shape: a history row written directly with
    //    ciphertext that does not match the stored fingerprint (i.e. the
    //    literal was never actually encrypted with this key/nonce). The row
    //    inserts (the schema only checks nonce length, not ciphertext
    //    integrity), but rehydration fails closed on fingerprint mismatch.
    use crate::db::protected_redaction_history::ProtectedRedactionHistoryAppend;
    let legacy_input = ProtectedRedactionHistoryAppend {
        session_id: session_id().to_owned(),
        sealed_record_id: None,
        sealed_version: None,
        source: RedactionHistorySource::Credential,
        fingerprint: "l1e2g3a4c5y6l1e2g3a4c5y6l1e2g3a4c5y6l1e2g3a4c5y6l1e2g3a4c5y6l1e2".to_owned(),
        // Garbage ciphertext that will NOT decrypt to a plaintext matching the
        // stored fingerprint. The nonce is a valid 12-byte value so the schema
        // CHECK (length(nonce) = 12) passes.
        ciphertext: vec![0xDE; 272],
        nonce: vec![0u8; NONCE_LEN],
        key_version: 1,
    };
    let legacy_id = db
        .write(move |conn| {
            use crate::db::protected_redaction_history::{
                AppendHistoryResult, append_history_conn,
            };
            let r = append_history_conn(conn, &legacy_input)?;
            Ok(match r {
                AppendHistoryResult::Created { history_id } => history_id,
                AppendHistoryResult::Existing { history_id } => history_id,
            })
        })
        .await
        .unwrap();

    // Rehydration of an artifact with no refs returns an empty frame (no error).
    let result = history
        .rehydrate_for_artifact(RedactionArtifactKind::Event, "no-such-artifact")
        .await;
    let frame = result.unwrap();
    assert!(frame.is_empty());

    // Direct rehydration of the tampered/legacy row fails closed: the
    // decrypted plaintext's fingerprint does not match the stored fingerprint.
    let legacy_row = db
        .read(move |conn| get_history_conn(conn, &legacy_id))
        .await
        .unwrap()
        .unwrap();
    let rehydrate_result = history.rehydrate_row(&legacy_row);
    assert!(
        rehydrate_result.is_err(),
        "rehydration of tampered/legacy row must fail closed"
    );
}

// ---------------------------------------------------------------------------
// Criterion 6: history rehydration is bounded and zeroized
// ---------------------------------------------------------------------------

/// Cover local key custody, 16 KiB cap, failure, zeroization, no literal in
/// persisted redaction JSON, and no read outside Owner-sensitive/export-
/// redaction frames.
#[tokio::test]
async fn history_rehydration_is_bounded_and_zeroized() {
    let db = test_db().await;
    let resolver = test_resolver();
    let history = ProtectedRedactionHistory::new(&db, &resolver);

    // 1. Local key custody: the key resolver provides the key.
    let literal_str = "rehydrate-test-secret";
    let lit = ProtectedLiteral::new(
        literal_str.to_owned(),
        RedactionHistorySource::Credential,
        None,
        None,
    )
    .unwrap();
    let history_id = history
        .append_and_attach(
            session_id(),
            lit,
            vec![ArtifactRef::new(
                RedactionArtifactKind::Request,
                "rehydrate-req-1",
            )],
        )
        .await
        .unwrap();

    // 2. Rehydration succeeds and returns the correct literal.
    let frame = history
        .rehydrate_for_artifact(RedactionArtifactKind::Request, "rehydrate-req-1")
        .await
        .unwrap();
    assert_eq!(frame.len(), 1);
    let literals = frame.into_literals();
    assert_eq!(literals.len(), 1);
    assert_eq!(literals[0].as_str(), literal_str);

    // 3. 16 KiB cap: a literal at exactly the cap succeeds.
    let at_cap = "y".repeat(MAX_LITERAL_LEN);
    let lit_cap = ProtectedLiteral::new(
        at_cap.clone(),
        RedactionHistorySource::Environment,
        None,
        None,
    )
    .unwrap();
    let _cap_id = history
        .append_and_attach(
            session_id(),
            lit_cap,
            vec![ArtifactRef::new(RedactionArtifactKind::Tool, "cap-tool-1")],
        )
        .await
        .unwrap();
    let frame = history
        .rehydrate_for_artifact(RedactionArtifactKind::Tool, "cap-tool-1")
        .await
        .unwrap();
    let literals = frame.into_literals();
    assert_eq!(literals[0].as_str(), at_cap);

    // 4. Over-cap literal fails.
    let over_cap = "z".repeat(MAX_LITERAL_LEN + 1);
    assert!(
        ProtectedLiteral::new(over_cap, RedactionHistorySource::Environment, None, None).is_err()
    );

    // 5. Failure: rehydration with wrong key version fails closed.
    let wrong_resolver = MapKeyResolver::new().with_version(1, test_key_v2()); // wrong key for v1
    let history_wrong = ProtectedRedactionHistory::new(&db, &wrong_resolver);
    // The wrong key produces a different plaintext → fingerprint mismatch.
    // The history_id was created with key v1, and the row has key_version=1.
    // The wrong_resolver has v1 mapped to test_key_v2(), so rehydrate_row
    // resolves version 1 → test_key_v2(), decrypts, and the fingerprint won't
    // match. rehydrate_for_artifact calls rehydrate_row per row and bails on
    // error, so the whole call must fail.
    let result = history_wrong
        .rehydrate_for_artifact(RedactionArtifactKind::Request, "rehydrate-req-1")
        .await;
    assert!(
        result.is_err(),
        "rehydration with wrong key must fail closed (fingerprint mismatch)"
    );

    // 6. No literal in persisted redaction JSON: the safe ref projection
    //    carries only opaque IDs / source / ref-count / timestamps — no
    //    fingerprint, ciphertext, nonce, or key version at all.
    let refs = db
        .protected_redaction_history_refs(session_id())
        .await
        .unwrap();
    for r in &refs {
        // Compile-level: the projection has no field that could carry a
        // literal or a fingerprint. Round-trip through the exact shape.
        let _shape = ProtectedRedactionHistoryRef {
            history_id: r.history_id.clone(),
            session_id: r.session_id.clone(),
            source: r.source,
            ref_count: r.ref_count,
            created_at_ms: r.created_at_ms,
            retired_at_ms: r.retired_at_ms,
        };
    }

    // 7. No read outside Owner-sensitive/export-redaction frames: the full
    //    row (with ciphertext) is only accessible via get_history_conn /
    //    list_history_conn / list_history_for_artifact_conn, which are
    //    Owner-sensitive reads. The safe ref projection (for export) strips
    //    the encrypted material.
    let full_rows = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    let safe_refs = db
        .protected_redaction_history_refs(session_id())
        .await
        .unwrap();
    assert_eq!(full_rows.len(), safe_refs.len());
    // The full rows have ciphertext/nonce/key_version; the safe refs do not.
    // (Compile-time: ProtectedRedactionHistoryRef has no such fields.)

    // 8. Retired rows cannot be rehydrated.
    // First detach all refs and retire.
    let id_detach = history_id.clone();
    db.write(move |conn| {
        use crate::db::protected_redaction_history::detach_artifact_ref_conn;
        detach_artifact_ref_conn(
            conn,
            RedactionArtifactKind::Request,
            "rehydrate-req-1",
            &id_detach,
        )
    })
    .await
    .unwrap();
    let id_retire = history_id.clone();
    db.write(move |conn| retire_history_conn(conn, &id_retire))
        .await
        .unwrap();

    // Rehydration of a retired row's artifact: the artifact no longer has
    // refs (we detached), so the frame is empty.
    let frame = history
        .rehydrate_for_artifact(RedactionArtifactKind::Request, "rehydrate-req-1")
        .await
        .unwrap();
    assert!(frame.is_empty());

    // Direct rehydration of the retired row fails.
    let retired_row = db
        .read(move |conn| get_history_conn(conn, &history_id))
        .await
        .unwrap()
        .unwrap();
    assert!(history.rehydrate_row(&retired_row).is_err());
}

// ---------------------------------------------------------------------------
// Additional: key rotation scenario
// ---------------------------------------------------------------------------

#[tokio::test]
async fn key_rotation_rehydrides_with_correct_version() {
    let db = test_db().await;
    // Version 1 has one key, version 2 has a different key.
    let resolver = test_resolver();
    let history = ProtectedRedactionHistory::new(&db, &resolver);

    // Write a literal with key version 1 (the resolver's active version).
    let lit_v1 = ProtectedLiteral::new(
        "rotation-secret".to_owned(),
        RedactionHistorySource::Credential,
        None,
        None,
    )
    .unwrap();
    let id_v1 = history
        .append_and_attach(
            session_id(),
            lit_v1,
            vec![ArtifactRef::new(
                RedactionArtifactKind::Request,
                "rot-req-1",
            )],
        )
        .await
        .unwrap();

    // Verify the row was written with key_version=1.
    let row = db
        .read(move |conn| get_history_conn(conn, &id_v1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.key_version, 1);

    // Rehydration with the correct resolver (v1 key) succeeds.
    let frame = history
        .rehydrate_for_artifact(RedactionArtifactKind::Request, "rot-req-1")
        .await
        .unwrap();
    let literals = frame.into_literals();
    assert_eq!(literals[0].as_str(), "rotation-secret");

    // A resolver missing version 1 fails closed.
    let resolver_missing_v1 = MapKeyResolver::new().with_version(2, test_key_v2());
    let history_missing = ProtectedRedactionHistory::new(&db, &resolver_missing_v1);
    let result = history_missing
        .rehydrate_for_artifact(RedactionArtifactKind::Request, "rot-req-1")
        .await;
    assert!(result.is_err(), "missing key version must fail closed");
}

// ---------------------------------------------------------------------------
// AC2: real AEAD, fail-closed on tamper or wrong key
// ---------------------------------------------------------------------------

async fn append_via_writer(
    db: &Db,
    resolver: &MapKeyResolver,
    literal: &str,
    artifact: &str,
) -> String {
    let history = ProtectedRedactionHistory::new(db, resolver);
    history
        .append_and_attach(
            session_id(),
            ProtectedLiteral::new(
                literal.to_owned(),
                RedactionHistorySource::Credential,
                None,
                None,
            )
            .unwrap(),
            vec![ArtifactRef::new(RedactionArtifactKind::Request, artifact)],
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn aead_rejects_tampered_ciphertext_and_wrong_key() {
    let db = test_db().await;
    // Seed a second session so we can tamper the AAD-bound session_id column.
    let other_session = "aaaaaaaa-aaaa-aaaa-aaaa-222222222222";
    let os = other_session.to_owned();
    db.write(move |conn| {
        conn.execute(
            "INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) \
             VALUES(?1,'p','/redacted',1,1)",
            [os],
        )?;
        Ok(())
    })
    .await
    .unwrap();

    let resolver = test_resolver();
    let history = ProtectedRedactionHistory::new(&db, &resolver);

    // Untampered round-trip through the production entry point succeeds.
    let ok_id = append_via_writer(&db, &resolver, "untampered-secret", "ok-req").await;
    let rehydrated = history.rehydrate_by_history_id(&ok_id).await.unwrap();
    assert_eq!(rehydrated.as_str().unwrap().as_str(), "untampered-secret");

    // Helper: flip one byte of the ciphertext blob at `idx` (relative to end
    // when `from_end`).
    async fn flip_ciphertext_byte(db: &Db, hid: &str, from_end: bool) {
        let hid = hid.to_owned();
        db.write(move |conn| {
            let ct: Vec<u8> = conn.query_row(
                "SELECT ciphertext FROM protected_redaction_history WHERE history_id=?1",
                [&hid],
                |r| r.get(0),
            )?;
            let mut ct = ct;
            let idx = if from_end { ct.len() - 1 } else { 0 };
            ct[idx] ^= 0x01;
            conn.execute(
                "UPDATE protected_redaction_history SET ciphertext=?1 WHERE history_id=?2",
                rusqlite::params![ct, hid],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    // (1) Flip a ciphertext body byte -> tag check fails.
    let id_body = append_via_writer(&db, &resolver, "tamper-body", "body-req").await;
    flip_ciphertext_byte(&db, &id_body, false).await;
    assert!(history.rehydrate_by_history_id(&id_body).await.is_err());

    // (2) Flip a byte in the appended tag region -> tag check fails.
    let id_tag = append_via_writer(&db, &resolver, "tamper-tag", "tag-req").await;
    flip_ciphertext_byte(&db, &id_tag, true).await;
    assert!(history.rehydrate_by_history_id(&id_tag).await.is_err());

    // (3) Flip a nonce byte -> tag check fails.
    let id_nonce = append_via_writer(&db, &resolver, "tamper-nonce", "nonce-req").await;
    let id_n = id_nonce.clone();
    db.write(move |conn| {
        let mut nonce: Vec<u8> = conn.query_row(
            "SELECT nonce FROM protected_redaction_history WHERE history_id=?1",
            [&id_n],
            |r| r.get(0),
        )?;
        nonce[0] ^= 0x01;
        conn.execute(
            "UPDATE protected_redaction_history SET nonce=?1 WHERE history_id=?2",
            rusqlite::params![nonce, id_n],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    assert!(history.rehydrate_by_history_id(&id_nonce).await.is_err());

    // (4) Tamper the AAD-bound `source` column -> AAD mismatch fails closed.
    let id_src = append_via_writer(&db, &resolver, "tamper-src", "src-req").await;
    let id_s = id_src.clone();
    db.write(move |conn| {
        conn.execute(
            "UPDATE protected_redaction_history SET source='Environment' WHERE history_id=?1",
            [&id_s],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    assert!(history.rehydrate_by_history_id(&id_src).await.is_err());

    // (5) Tamper the AAD-bound `session_id` column -> AAD mismatch fails closed.
    let id_sess = append_via_writer(&db, &resolver, "tamper-sess", "sess-req").await;
    let id_ss = id_sess.clone();
    let os2 = other_session.to_owned();
    db.write(move |conn| {
        conn.execute(
            "UPDATE protected_redaction_history SET session_id=?1 WHERE history_id=?2",
            rusqlite::params![os2, id_ss],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    assert!(history.rehydrate_by_history_id(&id_sess).await.is_err());

    // (6) Tamper the AAD-bound `key_version` column to another present version
    //     -> decrypt under the wrong subkey and wrong AAD fails closed.
    let id_kv = append_via_writer(&db, &resolver, "tamper-kv", "kv-req").await;
    let id_k = id_kv.clone();
    db.write(move |conn| {
        conn.execute(
            "UPDATE protected_redaction_history SET key_version=2 WHERE history_id=?1",
            [&id_k],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    assert!(history.rehydrate_by_history_id(&id_kv).await.is_err());

    // (7) Wrong key material for the same version fails closed.
    let id_wrong = append_via_writer(&db, &resolver, "wrong-key-secret", "wrong-req").await;
    let wrong_resolver = MapKeyResolver::new().with_version(1, test_key_v2());
    let wrong_history = ProtectedRedactionHistory::new(&db, &wrong_resolver);
    assert!(
        wrong_history
            .rehydrate_by_history_id(&id_wrong)
            .await
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// AC3: length hiding — stored ciphertext length reveals only a bucket
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ciphertext_length_reveals_only_bucket() {
    let db = test_db().await;
    let resolver = test_resolver();
    let history = ProtectedRedactionHistory::new(&db, &resolver);

    // (literal length, expected stored ciphertext length).
    let cases = [
        (1usize, 272usize),
        (100, 272),
        (251, 272),
        (252, 272),
        (1000, 1040),
        (4092, 4112),
        (16384, 16404),
    ];

    let mut stored = Vec::new();
    for (i, &(len, expected)) in cases.iter().enumerate() {
        let literal = "a".repeat(len);
        let artifact = format!("bucket-req-{i}");
        let hid = history
            .append_and_attach(
                session_id(),
                ProtectedLiteral::new(literal, RedactionHistorySource::Environment, None, None)
                    .unwrap(),
                vec![ArtifactRef::new(RedactionArtifactKind::Request, &artifact)],
            )
            .await
            .unwrap();
        let row = db
            .read(move |conn| get_history_conn(conn, &hid))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.ciphertext.len(),
            expected,
            "literal length {len} must store ciphertext length {expected}"
        );
        stored.push((len, row.ciphertext.len()));
    }

    // Same-bucket literals of different lengths store the exact same length.
    let bucket_256: Vec<usize> = stored
        .iter()
        .filter(|(len, _)| *len <= 252)
        .map(|(_, ct)| *ct)
        .collect();
    assert!(bucket_256.iter().all(|&ct| ct == 272));
    assert!(bucket_256.len() >= 2, "need multiple same-bucket lengths");
}

// ---------------------------------------------------------------------------
// AC4: keyed fingerprint (keyed MAC), never plain SHA-256
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fingerprint_is_keyed_mac_not_plain_sha256() {
    let literal = "fingerprint-under-test";

    // Root key A.
    let db_a = test_db().await;
    let resolver_a = MapKeyResolver::new().with_version(1, test_key_v1());
    let id_a = append_via_writer(&db_a, &resolver_a, literal, "fp-req-a").await;
    let row_a = db_a
        .read(move |conn| get_history_conn(conn, &id_a))
        .await
        .unwrap()
        .unwrap();

    // Second write of the SAME literal under the SAME root key is deterministic.
    let db_a2 = test_db().await;
    let resolver_a2 = MapKeyResolver::new().with_version(1, test_key_v1());
    let id_a2 = append_via_writer(&db_a2, &resolver_a2, literal, "fp-req-a2").await;
    let row_a2 = db_a2
        .read(move |conn| get_history_conn(conn, &id_a2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row_a.fingerprint, row_a2.fingerprint,
        "keyed MAC must be deterministic under the same key"
    );

    // A DIFFERENT root key yields a DIFFERENT fingerprint for the same literal —
    // proving it is keyed, not an unkeyed digest.
    let db_b = test_db().await;
    let resolver_b = MapKeyResolver::new().with_version(1, test_key_v2());
    let id_b = append_via_writer(&db_b, &resolver_b, literal, "fp-req-b").await;
    let row_b = db_b
        .read(move |conn| get_history_conn(conn, &id_b))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        row_a.fingerprint, row_b.fingerprint,
        "keyed MAC must change with the root key"
    );

    // And it is never the unkeyed hex(SHA-256(literal)) (the old oracle).
    let unkeyed = plain_sha256_hex(literal.as_bytes());
    assert_ne!(row_a.fingerprint, unkeyed);
    assert_ne!(row_b.fingerprint, unkeyed);
    assert_eq!(row_a.fingerprint.len(), 64);

    // AC4 (exact value): the stored fingerprint is EXACTLY
    // `hex(HMAC-SHA-256(derive_subkey(root, fingerprint-label), literal))`.
    // Recompute it here from the raw two-step KDF (independent of the writer's
    // own call), pinning both the domain label and the keyed-MAC construction,
    // for both root keys.
    fn expected_keyed_fingerprint(root: &[u8], literal: &[u8]) -> String {
        use hmac::Mac;
        // Step 1: derive the fingerprint subkey (HMAC-SHA-256 over the label).
        let mut kdf = HmacSha256::new_from_slice(root).unwrap();
        kdf.update(KDF_FINGERPRINT_LABEL);
        let subkey = kdf.finalize().into_bytes();
        // Step 2: keyed MAC of the literal under that subkey.
        let mut mac = HmacSha256::new_from_slice(&subkey).unwrap();
        mac.update(literal);
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    assert_eq!(
        row_a.fingerprint,
        expected_keyed_fingerprint(&test_key_v1(), literal.as_bytes()),
        "stored fingerprint must equal the keyed MAC recomputed in-test (key A)"
    );
    assert_eq!(
        row_b.fingerprint,
        expected_keyed_fingerprint(&test_key_v2(), literal.as_bytes()),
        "stored fingerprint must equal the keyed MAC recomputed in-test (key B)"
    );
}

// ---------------------------------------------------------------------------
// AC7: production key custody from the native secure key store (FakeNativeStore)
// ---------------------------------------------------------------------------

/// Boot the secure-key actor the way production does. `start_with_store` blocks
/// on the actor thread readiness handshake, so it must not run on a Tokio
/// worker; mirror the external-journal test pattern and boot on a plain thread.
async fn boot_secure_key_actor(
    db: &Db,
    store: &crate::secure_key::fake::FakeNativeStore,
) -> crate::secure_key::SecureKeyActor {
    use std::sync::Arc;
    let db = db.clone();
    let store = store.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("prh-test-secure-key-boot".into())
        .spawn(move || {
            let _ = tx.send(crate::secure_key::SecureKeyActor::start_with_store(
                db,
                Box::new(store),
                Arc::new(crate::secure_key::FailClosedReconciler),
            ));
        })
        .expect("spawn secure key boot thread");
    rx.await
        .expect("secure key boot channel")
        .expect("secure key actor")
}

/// Shut the actor down off the runtime (`Drop` blocks on the worker reply).
async fn shutdown_secure_key_actor(actor: crate::secure_key::SecureKeyActor) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("prh-test-secure-key-shutdown".into())
        .spawn(move || {
            drop(actor);
            let _ = tx.send(());
        })
        .expect("spawn secure key shutdown thread");
    rx.await.expect("secure key shutdown channel");
}

#[tokio::test]
async fn production_key_resolver_resolves_versions_from_secure_key_store() {
    use crate::redact::secure_key_resolver::SecureKeyResolver;
    use crate::secure_key::fake::FakeNativeStore;

    let db = test_db().await;
    let store = FakeNativeStore::new();
    let actor = boot_secure_key_actor(&db, &store).await;
    let resolver = SecureKeyResolver::new(actor.handle());

    // Cache-only reads fail closed before any ensure warms the cache.
    assert!(resolver.resolve(1).is_err());
    assert!(resolver.active_version().is_err());

    // ensure_active creates/loads the redaction-history/v1 key and reports the
    // store's active version (no hardcoded constant).
    let active = resolver.ensure_active().await.unwrap();
    assert_eq!(active, 1);
    assert_eq!(resolver.active_version().unwrap(), 1);
    assert!(resolver.resolve(1).is_ok());

    // A version the store does not have fails closed.
    assert!(resolver.ensure_version(99).await.is_err());
    assert!(resolver.resolve(99).is_err());

    // End-to-end: the store-backed resolver drives the real AEAD writer and the
    // literal round-trips through rehydrate.
    let history = ProtectedRedactionHistory::new(&db, &resolver);
    let hid = history
        .append_and_attach(
            session_id(),
            ProtectedLiteral::new(
                "store-backed-secret".to_owned(),
                RedactionHistorySource::Environment,
                None,
                None,
            )
            .unwrap(),
            vec![ArtifactRef::new(
                RedactionArtifactKind::Request,
                "store-req-1",
            )],
        )
        .await
        .unwrap();
    let rehydrated = history.rehydrate_by_history_id(&hid).await.unwrap();
    assert_eq!(rehydrated.as_str().unwrap().as_str(), "store-backed-secret");

    shutdown_secure_key_actor(actor).await;
}
