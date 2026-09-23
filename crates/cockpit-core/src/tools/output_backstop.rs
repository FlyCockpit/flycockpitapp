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
/// Fail-closed like the read tool's approved-secret registration: a
/// persist failure is an error, never a silently unregistered value.
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
        // Detached hub (tests / standalone shim): no shared live table to
        // union onto, so persist a local union exactly like the read tool's
        // approved-secret fallback.
        let table = redact.with_observed_output_secrets(cfg, &found)?;
        session.persist_redaction_table(&table)?;
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
