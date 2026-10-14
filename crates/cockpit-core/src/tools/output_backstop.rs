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

use std::sync::Arc;

use crate::config::extended::RedactConfig;
use crate::engine::interrupt::InterruptHub;
use crate::redact::{NovelScrubMode, NovelScrubOutput, RedactionTable};
use crate::session::Session;

/// Scrub novel secret-shaped values out of the freshly captured streams of
/// ONE command (stdout and stderr together) and register them in the
/// session redaction table.
///
/// - `redact` is the table the tool call holds. It supplies the
///   placeholder, the config opt-out and the protected paths.
/// - The observations of every stream are registered together. Their union,
///   together with every value this session's owner has observed before
///   (the owner's accumulated observed additions), is then applied to EVERY
///   stream. So a keyed `DB_SECRET=v` on stdout also hides a keyless `v` on
///   stderr, and a later same-turn command that prints only `v`, or its
///   base64, is scrubbed even though its tool table snapshot predates the
///   registration.
/// - The rest of the session table is NOT applied here, so trusted-model
///   custody and the downstream egress chokepoint keep their existing
///   behaviour.
///
/// Registration goes ONLY to the table `interrupts`' redaction owner holds:
/// the owning session worker's table, which a scheduled fork reaches through
/// [`InterruptHub::leaf_sharing_redaction`]. It never goes to the
/// daemon-global table or another session's. Persistence targets the owner's
/// durable session, not a fork's execution session.
///
/// Registration fails closed, like the read tool's approved-secret
/// registration: a persist failure is an error, never a silently
/// unregistered value.
///
/// A hub with no owner (tests, a standalone shim) registers nothing.
/// Persisting a union of the tool's table snapshot outside the owner's write
/// lock could overwrite concurrently committed durable entries (H1), so
/// there the values are scrubbed from this output only.
pub(crate) async fn scrub_command_streams(
    interrupts: &InterruptHub,
    session: &Session,
    redact: &RedactionTable,
    cfg: &RedactConfig,
    streams: &mut [&mut String],
) -> anyhow::Result<()> {
    if redact.disabled() {
        return Ok(());
    }
    let mut found = Vec::new();
    for stream in streams.iter_mut() {
        if stream.is_empty() {
            continue;
        }
        let NovelScrubOutput {
            text,
            found: stream_found,
        } = redact
            .scrub_novel_command_output_secrets_with_mode(stream, NovelScrubMode::KeyedNarrow);
        **stream = text;
        found.extend(stream_found);
    }
    let observed = if found.is_empty() {
        interrupts
            .redaction_owner()
            .and_then(|owner| owner.observed_additions())
    } else {
        match interrupts
            .register_observed_output_secrets(session, cfg, &found)
            .await?
        {
            Some(observed) => Some(observed),
            None => {
                tracing::debug!(
                    observed = found.len(),
                    "no session redaction owner to register observed output secrets into"
                );
                Some(Arc::new(redact.observed_output_addition(cfg, &found)?))
            }
        }
    };
    if let Some(observed) = observed.filter(|observed| !observed.is_empty()) {
        for stream in streams.iter_mut() {
            if let std::borrow::Cow::Owned(scrubbed) = observed.scrub_cow(stream) {
                **stream = scrubbed;
            }
        }
    }
    Ok(())
}

/// Single-stream form of [`scrub_command_streams`].
pub(crate) async fn scrub_command_output(
    interrupts: &InterruptHub,
    session: &Session,
    redact: &RedactionTable,
    cfg: &RedactConfig,
    text: &str,
) -> anyhow::Result<String> {
    let mut text = text.to_string();
    scrub_command_streams(interrupts, session, redact, cfg, &mut [&mut text]).await?;
    Ok(text)
}

/// Byte-stream form of [`scrub_command_streams`] for raw captured stdout /
/// stderr. Invalid UTF-8 is only rewritten (lossily) when a stream actually
/// changed; clean output keeps its exact bytes.
pub(crate) async fn scrub_command_byte_streams(
    interrupts: &InterruptHub,
    session: &Session,
    redact: &RedactionTable,
    cfg: &RedactConfig,
    streams: &mut [&mut Vec<u8>],
) -> anyhow::Result<()> {
    let originals: Vec<String> = streams
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .collect();
    let mut texts = originals.clone();
    {
        let mut refs: Vec<&mut String> = texts.iter_mut().collect();
        scrub_command_streams(interrupts, session, redact, cfg, &mut refs).await?;
    }
    for ((bytes, original), text) in streams.iter_mut().zip(&originals).zip(texts) {
        if &text != original {
            **bytes = text.into_bytes();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

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
        scrub_command_byte_streams(
            &hub,
            &session,
            &RedactionTable::empty(),
            &RedactConfig::default(),
            &mut [&mut bytes],
        )
        .await
        .unwrap();
        assert_eq!(
            bytes,
            vec![0xff, b'\n'],
            "clean invalid UTF-8 keeps its bytes"
        );
    }

    /// Secrets r2 C4/C5/C6: what the backstop registers is the plaintext it
    /// replaced — the URL password itself (not only the user:password pair),
    /// the DECODED JSON value, a short password under a bare `password` key,
    /// and the literal default of a `${X:-default}` reference — in both the
    /// live and the durable table.
    #[tokio::test]
    async fn registered_values_are_the_replaced_plaintext() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = test_session(&db, &tmp);
        let (hub, live) = live_hub(&db, &session, 0);
        let cfg = RedactConfig::default();
        let url_password = ["NovelPw78529", "UrlSecret"].concat();
        let decoded = ["novelPw78529", "JsonSecret"].concat();
        let default_literal = ["actualNovel78529", "DefaultSecret"].concat();
        let cases = [
            (
                "url",
                format!("DATABASE_URL=postgres://app:{url_password}@db/x"),
                url_password.clone(),
            ),
            (
                "json_escape",
                r#"{"DB_PASSWORD":"novel\u0050w78529JsonSecret"}"#.to_string(),
                decoded.clone(),
            ),
            (
                "short_password",
                "password: hunter2".to_string(),
                "hunter2".to_string(),
            ),
            (
                "reference_default",
                format!("DB_PASSWORD=${{X:-{default_literal}}}"),
                default_literal.clone(),
            ),
        ];
        let mut leaks = Vec::new();
        for (name, input, value) in cases {
            let out = scrub_command_output(&hub, &session, &RedactionTable::empty(), &cfg, &input)
                .await
                .unwrap();
            assert!(!out.contains(&value), "{name}: immediate output {out}");
            let echo = format!("later echo {value} end");
            let live_echo = live.read().unwrap().scrub(&echo);
            let durable_echo = session
                .persisted_redaction_table()
                .unwrap()
                .unwrap()
                .scrub(&echo);
            if live_echo.contains(&value) || durable_echo.contains(&value) {
                leaks.push(name);
            }
        }
        assert!(
            leaks.is_empty(),
            "replaced plaintext remains unregistered: {leaks:?}"
        );
        // The URL password is registered with its encoded variants too.
        let encoded = base64::engine::general_purpose::STANDARD.encode(url_password.as_bytes());
        assert!(!live.read().unwrap().scrub(&encoded).contains(&encoded));
    }

    /// Secrets r2 C6: a password that equals its user name or a well-known
    /// default is replaced, but only the user:password pair is installed —
    /// the stated policy exception, so `postgres` is not rewritten everywhere.
    #[tokio::test]
    async fn well_known_url_passwords_register_only_the_pair() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = test_session(&db, &tmp);
        let (hub, live) = live_hub(&db, &session, 0);
        let out = scrub_command_output(
            &hub,
            &session,
            &RedactionTable::empty(),
            &RedactConfig::default(),
            "DATABASE_URL=postgres://postgres:postgres@localhost:5432/app\n",
        )
        .await
        .unwrap();
        assert!(out.contains("postgres://postgres:"), "{out}");
        assert!(!out.contains("postgres@localhost"), "{out}");
        let live = live.read().unwrap().clone();
        assert!(live.scrub("image postgres:16").contains("postgres:16"));
        assert!(
            !live
                .scrub("postgres:postgres")
                .contains("postgres:postgres")
        );
    }

    /// Two registrations racing through leaves of one owner both survive in
    /// the live and durable table; a registration cancelled while waiting for
    /// the owner's lock writes nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn leaf_registrations_serialize_and_cancellation_writes_nothing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = test_session(&db, &tmp);
        let (hub, table) = live_hub(&db, &session, 0);
        let hub = Arc::new(hub);
        let guard = hub.redaction_owner().unwrap().lock().await;
        let cancelled_hub = Arc::new(hub.leaf_sharing_redaction());
        let cancelled_session = session.clone();
        let pending = tokio::spawn(async move {
            scrub_command_output(
                &cancelled_hub,
                &cancelled_session,
                &RedactionTable::empty(),
                &RedactConfig::default(),
                "DB_SECRET=Cancelled515Novel4567",
            )
            .await
        });
        tokio::task::yield_now().await;
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        assert!(
            table
                .read()
                .unwrap()
                .scrub("Cancelled515Novel4567")
                .contains("Cancelled515Novel4567")
        );
        drop(guard);
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for secret in ["Concurrent515NovelA78529", "Concurrent515NovelB78529"] {
            let session = session.clone();
            let leaf = Arc::new(hub.leaf_sharing_redaction());
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                scrub_command_output(
                    &leaf,
                    &session,
                    &RedactionTable::empty(),
                    &RedactConfig::default(),
                    &format!("DB_SECRET={secret}"),
                )
                .await
                .unwrap()
            }));
        }
        barrier.wait().await;
        for task in tasks {
            tokio::time::timeout(std::time::Duration::from_secs(10), task)
                .await
                .unwrap()
                .unwrap();
        }
        let durable = session.persisted_redaction_table().unwrap().unwrap();
        for secret in ["Concurrent515NovelA78529", "Concurrent515NovelB78529"] {
            assert!(!table.read().unwrap().scrub(secret).contains(secret));
            assert!(!durable.scrub(secret).contains(secret));
        }
    }

    /// A persist failure withholds the output (an error), leaves both tables
    /// unchanged, and a retry installs the value.
    #[tokio::test]
    async fn registration_persist_failure_withholds_and_keeps_tables() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = test_session(&db, &tmp);
        let (hub, live) = live_hub(&db, &session, 0);
        session
            .persist_redaction_table(&RedactionTable::empty())
            .unwrap();
        crate::session::lifecycle::fail_next_redaction_vault_write_for_test();
        let secret = ["NovelPersist515", "Secret78529"].concat();
        let input = format!("DB_SECRET={secret}");
        let result = scrub_command_output(
            &hub,
            &session,
            &RedactionTable::empty(),
            &RedactConfig::default(),
            &input,
        )
        .await;
        assert!(
            result.is_err(),
            "output must be withheld on persist failure"
        );
        assert!(live.read().unwrap().scrub(&secret).contains(&secret));
        assert!(
            session
                .persisted_redaction_table()
                .unwrap()
                .unwrap()
                .scrub(&secret)
                .contains(&secret)
        );
        let out = scrub_command_output(
            &hub,
            &session,
            &RedactionTable::empty(),
            &RedactConfig::default(),
            &input,
        )
        .await
        .unwrap();
        assert!(!out.contains(&secret));
        assert!(!live.read().unwrap().scrub(&secret).contains(&secret));
    }

    /// Secrets r2: source-code type annotations under secret-shaped keys are
    /// not secrets — they stay visible and are never registered, so reading a
    /// Rust/TypeScript file through the shell is not rewritten afterwards.
    #[tokio::test]
    async fn code_type_annotations_under_secret_keys_stay_visible() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = test_session(&db, &tmp);
        let (hub, live) = live_hub(&db, &session, 0);
        let source = "pub struct Creds {\n    password: String,\n    api_key: Option<SecretString>,\n}\ninterface X { token: string; }\n";
        let out = scrub_command_output(
            &hub,
            &session,
            &RedactionTable::empty(),
            &RedactConfig::default(),
            source,
        )
        .await
        .unwrap();
        assert_eq!(out, source);
        assert!(live.read().unwrap().is_empty());
    }
}
