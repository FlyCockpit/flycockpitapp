//! Session auto-titling via the utility model (GOALS §17d).
//!
//! Detached, best-effort scheduled passes drive automatic titles:
//!
//! - **Eager** — fires on the first user message, *regardless of token count*,
//!   from that message's raw typed text.
//! - **Refined** — fires at bounded follow-up user-turn slots (`2`, `4`, `8`,
//!   and `16`). It feeds a richer slice — the conversation's accumulated
//!   user-authored content — so a generic first title can converge once the
//!   user's concrete topic appears.
//!
//! The result is slugified (after `<think>`-stripping, so a reasoning
//! utility model can't poison the slug) and stored via
//! [`crate::session::Session::set_auto_title`], which refuses to
//! overwrite a user-set title.
//!
//! Forks get an independent pass keyed to post-divergence content; the
//! session-level counter is per-`Session`, not per-tree.
//!
//! A genuine failure is surfaced as a one-per-session [`TurnEvent::Notice`].
//! Missing `utility_model` logs once per process at info; provider/runtime
//! errors still warn. Auto-title never blocks the driver loop.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;

use std::path::Path;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::ProvidersConfig;
use crate::engine::agent::TurnEvent;
use crate::session::{Session, TitleAction};

static UTILITY_MODEL_UNSET_LOGGED: OnceLock<()> = OnceLock::new();

/// Token budget for the accumulated user-content slice fed to the
/// refined pass. Caps the prompt cost while still giving the refined
/// title more than the single eager message to summarise.
pub const REFINE_CONTEXT_TOKEN_BUDGET: usize = 1500;

/// cl100k_base token count for `text`. Re-exported here for callers
/// that already imported this module — new code should call
/// [`crate::tokens::count`] directly.
pub fn estimate_tokens(text: &str) -> usize {
    crate::tokens::count(text)
}

/// Legacy threshold retained for older tests/config-adjacent code. Automatic
/// title refresh is now turn-slot based rather than token-threshold based.
#[cfg(test)]
pub const TITLE_TOKEN_THRESHOLD: usize = 500;

/// Maximum title length, post-slugification.
pub const TITLE_MAX_CHARS: usize = 60;

/// Timeout for the utility-model call. Titles are best-effort; if
/// the provider takes longer than this, we'd rather drop the title
/// than tie up a daemon task indefinitely.
pub const TITLE_CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Slugify a raw model response into a `[a-z0-9-]+` title. Returns
/// `None` if nothing survives — the caller treats that as "no title
/// this pass; leave the next scheduled slot to try again."
pub fn slugify_title(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut last_was_hyphen = false;
    for c in raw.trim().chars() {
        let lower = c.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            out.push(lower);
            last_was_hyphen = false;
        } else if !last_was_hyphen && !out.is_empty() {
            out.push('-');
            last_was_hyphen = true;
        }
    }
    let trimmed = out.trim_end_matches('-');
    let capped: String = trimmed.chars().take(TITLE_MAX_CHARS).collect();
    let capped = capped.trim_end_matches('-').to_string();
    if capped.is_empty() {
        None
    } else {
        Some(capped)
    }
}

/// Fire the auto-titling pass against `session` for `action`
/// (eager / refine). Best-effort; never returns an error to the caller.
/// Intended to be spawned in a detached tokio task — the driver loop
/// doesn't wait on it. `content_prefix` is the eager pass's raw typed
/// text; refresh passes ignore it and rebuild richer context from the
/// recorded user turns. A genuine failure emits a one-per-session
/// `Notice` on `tx` and logs at `warn` (no `None`-slug deferral on the
/// eager path: a model that returned nothing usable simply leaves the next
/// scheduled slot to try again, which is not surfaced as a failure).
pub async fn generate_session_title(
    session: Arc<Session>,
    extended: ExtendedConfig,
    providers: ProvidersConfig,
    redact: Arc<crate::redact::RedactionTable>,
    content_prefix: String,
    action: TitleAction,
    tx: mpsc::Sender<TurnEvent>,
) {
    match generate_inner(
        &session,
        extended,
        providers,
        redact,
        content_prefix,
        action,
    )
    .await
    {
        Ok(TitleOutcome::Titled(_)) => {}
        Ok(TitleOutcome::Deferred) => {
            // The eager pass got no usable slug from a working model
            // (e.g. a trivial/slash-only first message). Not a failure.
            tracing::debug!("auto_title: no usable title this scheduled pass");
        }
        Err(e) => {
            // A genuine failure (model unset/erroring, empty response).
            // Surface it once per session. Missing `utility_model` is a normal
            // setup state, so keep its process log one-shot and non-warning.
            if is_utility_model_unset_error(&e) {
                UTILITY_MODEL_UNSET_LOGGED.get_or_init(|| {
                    tracing::info!(
                        "auto_title: utility_model is not configured; skipping auto-title"
                    );
                });
            } else {
                tracing::warn!(error = %e, "auto_title: pass failed");
            }
            if session.claim_title_failure_notice() {
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: auto_title_failure_notice(&e).to_string(),
                    })
                    .await;
            }
        }
    }
}

fn is_utility_model_unset_error(e: &anyhow::Error) -> bool {
    e.to_string() == "utility_model is not configured"
}

fn is_title_call_timeout_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<tokio::time::error::Elapsed>().is_some()
        || e.to_string().contains("deadline has elapsed")
}

fn auto_title_failure_notice(e: &anyhow::Error) -> &'static str {
    if is_utility_model_unset_error(e) {
        "Auto-title skipped: configure `utility_model` to enable session titles."
    } else if is_title_call_timeout_error(e) {
        "Auto-title skipped: utility model request timed out."
    } else {
        "Auto-title skipped: utility model request failed."
    }
}

/// Outcome of a successful (non-erroring) title pass.
enum TitleOutcome {
    /// A slug was produced and stored (or refused only by the
    /// user-renamed guard).
    Titled(String),
    /// The model answered but produced no usable slug.
    Deferred,
}

/// Generate a title for an explicit user command and report the slug to the
/// caller. Unlike [`generate_session_title`], this does not swallow provider
/// errors and can use [`TitleAction::Explicit`] to replace a previous manual
/// title.
pub async fn generate_session_title_once(
    session: Arc<Session>,
    extended: ExtendedConfig,
    providers: ProvidersConfig,
    redact: Arc<crate::redact::RedactionTable>,
    content_prefix: String,
    action: TitleAction,
) -> Result<Option<String>> {
    match generate_inner(
        &session,
        extended,
        providers,
        redact,
        content_prefix,
        action,
    )
    .await?
    {
        TitleOutcome::Titled(title) => Ok(Some(title)),
        TitleOutcome::Deferred => Ok(None),
    }
}

async fn generate_inner(
    session: &Session,
    extended: ExtendedConfig,
    providers: ProvidersConfig,
    redact: Arc<crate::redact::RedactionTable>,
    content_prefix: String,
    action: TitleAction,
) -> Result<TitleOutcome> {
    let Some(model_ref) = extended.auto_title_model_ref() else {
        anyhow::bail!("utility_model is not configured");
    };
    let model = crate::engine::model::Model::from_ref_trusted_only(
        &providers,
        model_ref,
        redact,
        session.trusted_only_flag(),
    )?;

    let content = match action {
        TitleAction::Eager => content_prefix,
        TitleAction::None | TitleAction::Refine | TitleAction::Explicit => {
            accumulated_user_content(session, &content_prefix)
        }
    };
    let prompt = build_title_prompt(&content);
    let response =
        tokio::time::timeout(TITLE_CALL_TIMEOUT, model.text_completion(&prompt)).await??;

    // A reasoning utility model may wrap its answer in `<think>…</think>`;
    // strip that before slugifying so the title is the answer, not the
    // chain of thought (and isn't forced empty).
    let (body, _reasoning) = crate::engine::think::split_think(&response);

    let Some(slug) = slugify_title(&body) else {
        // The model answered but nothing slug-worthy survived. On the
        // eager path this is a clean deferral, not a failure; on refine
        // (a one-shot) we likewise just leave the eager title in place.
        return Ok(TitleOutcome::Deferred);
    };

    let stored = if matches!(action, TitleAction::Explicit) {
        session.set_explicit_auto_title(&slug)
    } else {
        session.set_auto_title(&slug)
    };
    match stored {
        Ok(updated) => {
            if updated && matches!(action, TitleAction::Eager) {
                // The eager title stuck — advance past an unclaimed slot 1 for
                // compatibility with older callers.
                session.mark_eager_titled();
            }
            Ok(TitleOutcome::Titled(slug))
        }
        Err(e) => {
            tracing::warn!(error = %e, "auto_title: persist failed");
            Ok(TitleOutcome::Titled(slug))
        }
    }
}

/// Build the refresh pass's richer context: the session's accumulated
/// user-authored turns (oldest first), capped to
/// [`REFINE_CONTEXT_TOKEN_BUDGET`]. Falls back to `content_prefix` when
/// the recorded turns can't be read or are empty, so a refresh pass is
/// never worse than the eager one.
fn accumulated_user_content(session: &Session, content_prefix: &str) -> String {
    let turns = match session.db.thread_turns(session.id) {
        Ok(turns) => turns,
        Err(e) => {
            tracing::debug!(error = %e, "auto_title: reading user turns failed; using prefix");
            return content_prefix.to_string();
        }
    };
    let mut acc = String::new();
    for turn in turns.iter().filter(|t| t.role == "user") {
        let text = turn.text.trim();
        if text.is_empty() {
            continue;
        }
        if !acc.is_empty() {
            acc.push_str("\n\n");
        }
        acc.push_str(text);
        if estimate_tokens(&acc) >= REFINE_CONTEXT_TOKEN_BUDGET {
            break;
        }
    }
    if acc.trim().is_empty() {
        content_prefix.to_string()
    } else {
        acc
    }
}

/// Load the effective layered `config.json` views from `cwd`. The driver hook
/// calls this from inside the spawned auto-title task so config IO doesn't
/// block the inference loop.
pub fn load_configs_for(cwd: &Path) -> (ExtendedConfig, ProvidersConfig) {
    let extended = crate::config::extended::load_for_cwd(cwd);
    let providers = crate::secret_ref::load_effective(cwd);
    (extended, providers)
}

/// One-shot prompt asking the utility model for a title. Kept terse:
/// the model gets the prefix of user-authored content plus a one-line
/// instruction. Total prompt token cost ≈ (prefix tokens) + ~30 for
/// the instruction.
fn build_title_prompt(content_prefix: &str) -> String {
    format!(
        "Produce a short kebab-case title (2-6 words, lowercase, \
         hyphens only) summarising this conversation. Return ONLY \
         the title — no quotes, no explanation, no trailing punctuation.\n\n\
         <content>\n{content_prefix}\n</content>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_tokens_delegates_to_tiktoken() {
        assert_eq!(estimate_tokens(""), 0);
        // Real cl100k_base counts; just sanity-check that non-empty
        // input produces a positive count and grows with length.
        assert!(estimate_tokens("abcdefgh") > 0);
        assert!(estimate_tokens(&"hello ".repeat(100)) > estimate_tokens("hello"));
    }

    #[test]
    fn slugify_basic_phrase() {
        assert_eq!(
            slugify_title("Fix redact allowlist regression").as_deref(),
            Some("fix-redact-allowlist-regression")
        );
    }

    #[test]
    fn slugify_strips_punctuation_and_lowercases() {
        assert_eq!(
            slugify_title("Add: pixel banner!!!").as_deref(),
            Some("add-pixel-banner")
        );
    }

    #[test]
    fn slugify_collapses_runs() {
        assert_eq!(slugify_title("a   b\n\nc").as_deref(), Some("a-b-c"));
    }

    #[test]
    fn slugify_caps_at_max() {
        let raw = "this is a very long title that should be truncated at exactly the maximum allowed length and not beyond";
        let s = slugify_title(raw).unwrap();
        assert!(s.len() <= TITLE_MAX_CHARS, "{s} (len {})", s.len());
        assert!(!s.ends_with('-'), "trailing hyphen survived the cap: {s}");
    }

    #[test]
    fn slugify_returns_none_for_empty() {
        assert_eq!(slugify_title(""), None);
        assert_eq!(slugify_title("!@#$%^&*()"), None);
        assert_eq!(slugify_title("   "), None);
    }

    #[test]
    fn slugify_trims_leading_garbage() {
        assert_eq!(
            slugify_title("\"some title\"").as_deref(),
            Some("some-title")
        );
    }

    // ---- end-to-end stage tests (stubbed utility model) -----------------

    use crate::config::providers::ProviderEntry;
    use crate::db::Db;
    use crate::session::Session;
    use std::path::PathBuf;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// A local server that replies to every chat-completions POST with a
    /// non-streaming response carrying `content`. `None` content makes the
    /// server refuse the connection (close immediately) so the model call
    /// errors — the "genuine failure" path. Returns the `base_url`.
    async fn stub_model_server(content: Option<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                // Consume the full HTTP request (headers + Content-Length
                // body) before replying, so reqwest sees a clean exchange.
                use tokio::io::AsyncReadExt;
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = match stream.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    let s = String::from_utf8_lossy(&buf);
                    if let Some(idx) = s.find("\r\n\r\n") {
                        let header = &s[..idx];
                        let content_len = header
                            .lines()
                            .find_map(|l| {
                                let l = l.to_ascii_lowercase();
                                l.strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= idx + 4 + content_len {
                            break;
                        }
                    }
                }
                match &content {
                    None => {
                        // Hard failure: reply 500 so the call errors out.
                        let resp = "HTTP/1.1 500 Internal Server Error\r\n\
                                    Content-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                    Some(c) => {
                        // rig's openai CompletionsClient expects the assistant
                        // `content` as an array of typed text blocks.
                        let escaped = c
                            .replace('\\', "\\\\")
                            .replace('"', "\\\"")
                            .replace('\n', "\\n")
                            .replace('\r', "\\r");
                        let payload = format!(
                            "{{\"id\":\"c\",\"object\":\"chat.completion\",\"created\":0,\
                             \"model\":\"m\",\"system_fingerprint\":null,\
                             \"choices\":[{{\"index\":0,\"message\":{{\"role\":\"assistant\",\
                             \"content\":[{{\"type\":\"text\",\"text\":\"{escaped}\"}}]}},\
                             \"logprobs\":null,\"finish_reason\":\"stop\"}}],\
                             \"usage\":{{\"prompt_tokens\":1,\"total_tokens\":2,\
                             \"prompt_tokens_details\":{{\"cached_tokens\":0}}}}}}"
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                            payload.len(),
                            payload
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                }
                let _ = stream.flush().await;
            }
        });
        format!("http://{addr}/v1")
    }

    /// A local server that accepts model requests and never answers, allowing
    /// paused-time tests to drive the title-call timeout without sleeping.
    async fn hanging_model_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _stream = stream;
                    std::future::pending::<()>().await;
                });
            }
        });
        format!("http://{addr}/v1")
    }

    /// `(ExtendedConfig, ProvidersConfig)` whose utility model points at
    /// `base_url`, plus an empty redaction table.
    fn stub_configs(
        base_url: &str,
    ) -> (
        ExtendedConfig,
        ProvidersConfig,
        Arc<crate::redact::RedactionTable>,
    ) {
        let extended = ExtendedConfig {
            utility_model: Some("p:m".to_string()),
            ..ExtendedConfig::default()
        };
        let mut providers = ProvidersConfig::default();
        providers.providers.insert(
            "p".to_string(),
            ProviderEntry {
                url: base_url.to_string(),
                ..ProviderEntry::default()
            },
        );
        (
            extended,
            providers,
            Arc::new(crate::redact::RedactionTable::empty()),
        )
    }

    fn expect_notice(rx: &mut mpsc::Receiver<TurnEvent>) -> String {
        match rx.try_recv() {
            Ok(TurnEvent::Notice { text }) => text,
            other => panic!("expected a failure Notice, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn eager_titles_first_short_message_no_token_gate() {
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(Session::create(db, PathBuf::from("/x"), "a").unwrap());
        // A ~short message — far under the 500-token refine threshold.
        let msg = "Hi! Can you do a deep dive on my harness?";
        let action = session.note_user_content(msg);
        assert_eq!(action, TitleAction::Eager, "eager fires with no token gate");

        let url = stub_model_server(Some("Deep Dive Harness".to_string())).await;
        let (ext, prov, redact) = stub_configs(&url);
        let (tx, mut rx) = mpsc::channel(8);
        generate_session_title(
            session.clone(),
            ext,
            prov,
            redact,
            msg.to_string(),
            action,
            tx,
        )
        .await;

        // Title stored and rendered through the /sessions path.
        assert_eq!(session.title().as_deref(), Some("deep-dive-harness"));
        assert_eq!(session.title_stage(), 1, "slot 1 was consumed");
        // No failure Notice on the success path.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn eager_defers_when_model_yields_no_slug() {
        // A trivial/slash-only first message: the model answers but with
        // nothing slug-worthy, so the title stays unset and the next
        // scheduled slot gets the next chance (no failure Notice).
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(Session::create(db, PathBuf::from("/x"), "a").unwrap());
        let action = session.note_user_content("/help");
        assert_eq!(action, TitleAction::Eager);

        let url = stub_model_server(Some("!!!".to_string())).await;
        let (ext, prov, redact) = stub_configs(&url);
        let (tx, mut rx) = mpsc::channel(8);
        generate_session_title(
            session.clone(),
            ext,
            prov,
            redact,
            "/help".into(),
            action,
            tx,
        )
        .await;

        assert!(session.title().is_none(), "no title stuck");
        assert_eq!(session.title_stage(), 1, "slot 1 is still consumed");
        assert!(rx.try_recv().is_err(), "a clean deferral is not a failure");
    }

    #[tokio::test]
    async fn refine_overwrites_eager_title() {
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(Session::create(db, PathBuf::from("/x"), "a").unwrap());
        // An eager title is already in place.
        assert!(session.set_auto_title("eager-title").unwrap());
        session.mark_eager_titled();

        let url = stub_model_server(Some("Refined Title".to_string())).await;
        let (ext, prov, redact) = stub_configs(&url);
        let (tx, _rx) = mpsc::channel(8);
        generate_session_title(
            session.clone(),
            ext,
            prov,
            redact,
            "accumulated context".into(),
            TitleAction::Refine,
            tx,
        )
        .await;
        assert_eq!(
            session.title().as_deref(),
            Some("refined-title"),
            "refine overwrites the eager auto-title"
        );
    }

    #[tokio::test]
    async fn refine_does_not_overwrite_user_set_title() {
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(Session::create(db, PathBuf::from("/x"), "a").unwrap());
        session.rename("user-chosen").unwrap();

        let url = stub_model_server(Some("Refined Title".to_string())).await;
        let (ext, prov, redact) = stub_configs(&url);
        let (tx, _rx) = mpsc::channel(8);
        generate_session_title(
            session.clone(),
            ext,
            prov,
            redact,
            "accumulated context".into(),
            TitleAction::Refine,
            tx,
        )
        .await;
        assert_eq!(
            session.title().as_deref(),
            Some("user-chosen"),
            "a user-set title is never clobbered"
        );
    }

    #[tokio::test]
    async fn explicit_generated_title_replaces_manual_title_as_auto() {
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(Session::create(db, PathBuf::from("/x"), "a").unwrap());
        session
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("a"),
                None,
                &serde_json::json!({"text": "Diagnose Codex model fetch failures"}),
            )
            .unwrap();
        session.rename("manual-title").unwrap();
        assert!(session.user_renamed());

        let url = stub_model_server(Some("Codex Model Fetch".to_string())).await;
        let (ext, prov, redact) = stub_configs(&url);
        let title = generate_session_title_once(
            session.clone(),
            ext,
            prov,
            redact,
            String::new(),
            TitleAction::Explicit,
        )
        .await
        .unwrap();

        assert_eq!(title.as_deref(), Some("codex-model-fetch"));
        assert_eq!(session.title().as_deref(), Some("codex-model-fetch"));
        assert!(
            !session.user_renamed(),
            "explicit utility rename is stored as an auto-generated title"
        );
        assert!(session.set_auto_title("later-auto").unwrap());
        assert_eq!(session.title().as_deref(), Some("later-auto"));
    }

    #[tokio::test]
    async fn reasoning_output_is_think_stripped_before_slugify() {
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(Session::create(db, PathBuf::from("/x"), "a").unwrap());
        let action = session.note_user_content("title me");
        // The model emits a leading <think> block then the real title.
        let url = stub_model_server(Some(
            "<think>let me ponder a good name</think>\nGood Name".to_string(),
        ))
        .await;
        let (ext, prov, redact) = stub_configs(&url);
        let (tx, _rx) = mpsc::channel(8);
        generate_session_title(
            session.clone(),
            ext,
            prov,
            redact,
            "title me".into(),
            action,
            tx,
        )
        .await;
        assert_eq!(
            session.title().as_deref(),
            Some("good-name"),
            "slug comes from the answer, never the think text or empty"
        );
    }

    #[tokio::test]
    async fn missing_utility_model_emits_setup_notice_once() {
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(Session::create(db, PathBuf::from("/x"), "a").unwrap());
        let action = session.note_user_content("title me");
        let (tx, mut rx) = mpsc::channel(8);

        generate_session_title(
            session.clone(),
            ExtendedConfig::default(),
            ProvidersConfig::default(),
            Arc::new(crate::redact::RedactionTable::empty()),
            "title me".into(),
            action,
            tx,
        )
        .await;

        let text = expect_notice(&mut rx);
        assert_eq!(
            text,
            "Auto-title skipped: configure `utility_model` to enable session titles."
        );
        assert!(session.title().is_none());
        assert!(rx.try_recv().is_err(), "missing config emits one notice");
    }

    #[tokio::test]
    async fn configured_model_failure_emits_generic_notice_once_without_raw_error() {
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(Session::create(db, PathBuf::from("/x"), "a").unwrap());
        let action = session.note_user_content("title me");

        // Erroring model (500s).
        let url = stub_model_server(None).await;
        let (ext, prov, redact) = stub_configs(&url);
        let (tx, mut rx) = mpsc::channel(8);
        generate_session_title(
            session.clone(),
            ext.clone(),
            prov.clone(),
            redact.clone(),
            "title me".into(),
            action,
            tx,
        )
        .await;

        let text = expect_notice(&mut rx);
        assert_eq!(text, "Auto-title skipped: utility model request failed.");
        assert!(!text.contains("configure `utility_model`"), "got {text:?}");
        assert!(
            !text.contains("500"),
            "raw provider status leaked: {text:?}"
        );
        assert!(
            !text.contains("Internal Server Error"),
            "raw provider body leaked: {text:?}"
        );
        assert!(!text.contains(&url), "raw provider URL leaked: {text:?}");
        assert!(session.title().is_none());

        // A second failed pass does NOT emit another Notice (one per session).
        let url2 = stub_model_server(None).await;
        let (ext2, prov2, redact2) = stub_configs(&url2);
        let (tx2, mut rx2) = mpsc::channel(8);
        generate_session_title(
            session.clone(),
            ext2,
            prov2,
            redact2,
            "title me again".into(),
            TitleAction::Eager,
            tx2,
        )
        .await;
        assert!(rx2.try_recv().is_err(), "failure Notice is one-per-session");
    }

    #[tokio::test(start_paused = true)]
    async fn configured_model_timeout_emits_timeout_notice_once() {
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(Session::create(db, PathBuf::from("/x"), "a").unwrap());
        let action = session.note_user_content("title me");
        let url = hanging_model_server().await;
        let (ext, prov, redact) = stub_configs(&url);
        let (tx, mut rx) = mpsc::channel(8);
        let task = tokio::spawn({
            let session = session.clone();
            async move {
                generate_session_title(session, ext, prov, redact, "title me".into(), action, tx)
                    .await;
            }
        });

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::time::advance(TITLE_CALL_TIMEOUT).await;
        tokio::task::yield_now().await;
        task.await.unwrap();

        let text = expect_notice(&mut rx);
        assert_eq!(text, "Auto-title skipped: utility model request timed out.");
        assert!(!text.contains("configure `utility_model`"), "got {text:?}");
        assert!(session.title().is_none());

        let url2 = stub_model_server(None).await;
        let (ext2, prov2, redact2) = stub_configs(&url2);
        let (tx2, mut rx2) = mpsc::channel(8);
        generate_session_title(
            session.clone(),
            ext2,
            prov2,
            redact2,
            "title me again".into(),
            TitleAction::Eager,
            tx2,
        )
        .await;
        assert!(rx2.try_recv().is_err(), "timeout Notice is one-per-session");
    }
}
