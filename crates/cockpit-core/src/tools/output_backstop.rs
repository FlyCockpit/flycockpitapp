//! Narrow novel-secret backstop for shell-shaped tool output (secrets
//! increment I2).
//!
//! The session redaction table only replaces literals it already holds. A
//! command that prints a secret the table has never seen — `cat
//! ~/other-project/.env` from an unconfined shell, `aws configure get …`, a
//! JSON config with an `"api_key"` member — would otherwise reach the model
//! verbatim. Bash, custom-tool and background-job output therefore passes
//! [`RedactionTable::scrub_novel_command_output_secrets_with_mode`] in
//! [`NovelScrubMode::KeyedNarrow`] before it reaches the model: keyed values
//! under secret-shaped keys, well-known credential formats, JWTs, PEM
//! private-key blocks and URL-userinfo passwords are replaced, while git
//! SHAs, UUIDs and digests (the keyless opaque-token rule skill `!`-commands
//! use) survive.
//!
//! Every replaced value is also registered in the session's live redaction
//! table (persist-then-swap under the interrupt hub's write lock), so a
//! later echo of the same value — elsewhere, or base64 / hex encoded — is
//! scrubbed by the ordinary table pass even where the key that identified
//! it is gone. This is best-effort defense in depth, not a boundary: the
//! background secret-source index (increments I6+) is the primary control.

use crate::config::extended::RedactConfig;
use crate::engine::interrupt::InterruptHub;
use crate::redact::{NovelScrubMode, NovelScrubOutput, RedactionTable};
use crate::session::Session;

/// Scrub novel secret-shaped values out of freshly captured command output
/// and register them in the session redaction table.
///
/// `redact` is the table the tool call holds; it supplies the placeholder,
/// the config opt-out and the protected paths. The returned text has every
/// observed value (and its registered variants) replaced; the rest of the
/// session table is NOT applied here, so trusted-model custody and the
/// downstream egress chokepoint keep their existing behaviour.
///
/// Registration goes ONLY to the live table `interrupts` owns — the owning
/// session worker's table, which a scheduled fork reaches through
/// [`InterruptHub::leaf_sharing_redaction`] — never to the daemon-global
/// table or another session's. It is fail-closed like the read tool's
/// approved-secret registration: a persist failure is an error, never a
/// silently unregistered value. A hub that owns no live table (tests, a
/// standalone shim) registers nothing: persisting a union of the tool's
/// table snapshot outside the owner's write lock could overwrite
/// concurrently committed entries in the durable table (H1), so there the
/// values are scrubbed from this output only.
pub(crate) async fn scrub_command_output(
    interrupts: &InterruptHub,
    session: &Session,
    redact: &RedactionTable,
    cfg: &RedactConfig,
    text: &str,
) -> anyhow::Result<String> {
    let NovelScrubOutput { text, found } =
        redact.scrub_novel_command_output_secrets_with_mode(text, NovelScrubMode::KeyedNarrow);
    if found.is_empty() {
        return Ok(text);
    }
    if interrupts
        .register_observed_output_secrets(session, cfg, &found)
        .await?
        .is_none()
    {
        tracing::debug!(
            observed = found.len(),
            "no live session redaction table to register observed output secrets into"
        );
    }
    // Encoded / case variants of an observed value that appear elsewhere in
    // this same output are caught now, not only from the next turn on.
    let addition = redact.observed_output_addition(cfg, &found)?;
    Ok(addition.scrub(&text))
}

/// Byte-stream form of [`scrub_command_output`] for raw captured stdout /
/// stderr. Invalid UTF-8 is only rewritten (lossily) when the stream
/// actually carried a secret; clean output keeps its exact bytes.
pub(crate) async fn scrub_command_output_bytes(
    interrupts: &InterruptHub,
    session: &Session,
    redact: &RedactionTable,
    cfg: &RedactConfig,
    bytes: &mut Vec<u8>,
) -> anyhow::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(bytes);
    let scrubbed = scrub_command_output(interrupts, session, redact, cfg, &text).await?;
    if scrubbed != text {
        *bytes = scrubbed.into_bytes();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::sync::Arc;

    fn stripe_key() -> String {
        // Assembled from fragments so the source never carries a contiguous
        // detector-shaped token.
        ["zq8Hc2Lm", "N4pR7tV1wX3y"].concat()
    }

    fn git_sha() -> String {
        ["0d1a4b2c8e3f60718293", "a4b5c6d7e8f9a0b1c2d3"].concat()
    }

    fn test_session(db: &crate::db::Db, tmp: &tempfile::TempDir) -> Arc<Session> {
        Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        )
    }

    /// A session worker's hub: owns a live shared table for `session`.
    fn live_hub(
        db: &crate::db::Db,
        session: &Session,
        interactive_clients: usize,
    ) -> (InterruptHub, crate::daemon::SharedRedactionTable) {
        let table: crate::daemon::SharedRedactionTable =
            Arc::new(std::sync::RwLock::new(Arc::new(RedactionTable::empty())));
        let (events, _rx) = tokio::sync::broadcast::channel(16);
        let hub = InterruptHub::new(
            events,
            table.clone(),
            Arc::new(std::sync::atomic::AtomicUsize::new(interactive_clients)),
            db.clone(),
            session.id,
        );
        (hub, table)
    }

    /// A scheduled fork (loop iteration / swarm child) runs its tools on a
    /// leaf of the owning session's hub. What its shell output backstop
    /// observes lands in THAT session's live and durable table, never in
    /// another session's; the leaf itself can never prompt a human.
    #[tokio::test]
    async fn fork_leaf_registers_secrets_into_the_owning_session_table_only() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let owner = test_session(&db, &tmp);
        let other = test_session(&db, &tmp);
        let (owner_hub, owner_table) = live_hub(&db, &owner, 1);
        let (_other_hub, other_table) = live_hub(&db, &other, 1);
        let leaf = owner_hub.leaf_sharing_redaction();
        assert!(
            !leaf.is_interactive_attached(),
            "a fork leaf never counts as an interactive client"
        );

        let stripe = stripe_key();
        let scrubbed = scrub_command_output(
            &leaf,
            &owner,
            &RedactionTable::empty(),
            &RedactConfig::default(),
            &format!("STRIPE_SECRET_KEY={stripe}\n"),
        )
        .await
        .unwrap();
        assert!(!scrubbed.contains(&stripe), "{scrubbed}");

        let echo = format!("echo {stripe}");
        let owner_live = owner_table.read().unwrap().clone();
        assert!(!owner_live.scrub(&echo).contains(&stripe));
        let owner_durable = owner.persisted_redaction_table().unwrap().unwrap();
        assert!(!owner_durable.scrub(&echo).contains(&stripe));

        let other_live = other_table.read().unwrap().clone();
        assert!(other_live.scrub(&echo).contains(&stripe));
        if let Some(other_durable) = other.persisted_redaction_table().unwrap() {
            assert!(other_durable.scrub(&echo).contains(&stripe));
        }
    }

    /// A hub that owns no live table has no serialized writer to register
    /// through. The backstop still scrubs the output, but it must not write
    /// the durable table from the tool's (possibly stale) snapshot: that
    /// would drop an entry another writer committed after the snapshot.
    #[tokio::test]
    async fn detached_hub_scrubs_without_rewriting_the_durable_secret_table() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = test_session(&db, &tmp);
        let committed = ["committed", "LiteralQ7w2e9"].concat();
        let durable = RedactionTable::empty()
            .with_forced_literal(committed.clone(), "$leak:contained".to_string())
            .unwrap();
        session.persist_redaction_table(&durable).unwrap();

        let stripe = stripe_key();
        let stale_snapshot = RedactionTable::empty();
        let scrubbed = scrub_command_output(
            &InterruptHub::detached(),
            &session,
            &stale_snapshot,
            &RedactConfig::default(),
            &format!("STRIPE_SECRET_KEY={stripe}\n"),
        )
        .await
        .unwrap();
        assert!(!scrubbed.contains(&stripe), "{scrubbed}");

        let after = session.persisted_redaction_table().unwrap().unwrap();
        assert!(
            !after.scrub(&committed).contains(&committed),
            "the committed durable entry survives"
        );
    }

    /// `cat other/.env`-style output reaching a live session: secret-keyed
    /// values are replaced before the text is returned, registered into the
    /// LIVE shared table (so a later echo elsewhere — plain or base64 — is
    /// scrubbed by the ordinary table pass) and persisted, while SHAs, UUIDs
    /// and non-secret assignments survive.
    #[tokio::test]
    async fn dotenv_dump_is_scrubbed_and_registered_in_the_live_table() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let redaction: crate::daemon::SharedRedactionTable =
            Arc::new(std::sync::RwLock::new(Arc::new(RedactionTable::empty())));
        let (events, _rx) = tokio::sync::broadcast::channel(16);
        let hub = InterruptHub::new(
            events,
            redaction.clone(),
            Arc::new(std::sync::atomic::AtomicUsize::new(1)),
            db.clone(),
            session.id,
        );
        let cfg = RedactConfig::default();
        let stripe = stripe_key();
        let uuid = "123e4567-e89b-42d3-a456-426614174000";
        let output = format!(
            "NODE_ENV=production\nSTRIPE_SECRET_KEY={stripe}\nexport DB_PASSWORD='hunter2hunter2'\nBUILD_SHA={sha}\nREQUEST_ID={uuid}\n",
            sha = git_sha(),
        );

        let tool_table = RedactionTable::empty();
        let scrubbed = scrub_command_output(&hub, &session, &tool_table, &cfg, &output)
            .await
            .unwrap();

        assert!(!scrubbed.contains(&stripe), "{scrubbed}");
        assert!(!scrubbed.contains("hunter2hunter2"), "{scrubbed}");
        assert!(scrubbed.contains("NODE_ENV=production"), "{scrubbed}");
        assert!(scrubbed.contains(&git_sha()), "{scrubbed}");
        assert!(scrubbed.contains(uuid), "{scrubbed}");

        let encoded = base64::engine::general_purpose::STANDARD.encode(stripe.as_bytes());
        let later = format!("config says {stripe}; encoded {encoded}; pw hunter2hunter2");
        let live = redaction.read().unwrap().clone();
        let live_scrubbed = live.scrub(&later);
        assert!(!live_scrubbed.contains(&stripe), "{live_scrubbed}");
        assert!(!live_scrubbed.contains(&encoded), "{live_scrubbed}");
        assert!(!live_scrubbed.contains("hunter2hunter2"), "{live_scrubbed}");
        // Only the observed values were registered, not every SHA/UUID.
        assert!(live.scrub(&git_sha()).contains(&git_sha()));

        let persisted = session.persisted_redaction_table().unwrap().unwrap();
        assert!(!persisted.scrub(&later).contains(&stripe));
    }

    #[tokio::test]
    async fn clean_output_is_returned_unchanged_without_registration() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create_for_test(
            db,
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let hub = InterruptHub::detached();
        let output = format!("commit {}\nRUST_LOG=debug\n", git_sha());
        let scrubbed = scrub_command_output(
            &hub,
            &session,
            &RedactionTable::empty(),
            &RedactConfig::default(),
            &output,
        )
        .await
        .unwrap();
        assert_eq!(scrubbed, output);
        let mut bytes = vec![0xff, b'\n'];
        scrub_command_output_bytes(
            &hub,
            &session,
            &RedactionTable::empty(),
            &RedactConfig::default(),
            &mut bytes,
        )
        .await
        .unwrap();
        assert_eq!(
            bytes,
            vec![0xff, b'\n'],
            "clean invalid UTF-8 keeps its bytes"
        );
    }
}
