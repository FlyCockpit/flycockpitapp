//! Round-trip utility-model translation (implementation note).
//!
//! Lets a user work in their own language while the coding model works in
//! another: the inbound user prompt is translated into the model's
//! language before it reaches the main agent (after the prompt-injection
//! scan, before outbound redaction); the agent's complete final response
//! is translated back into the user's language before it is shown.
//!
//! Both directions are history-free, one-shot
//! [`Model::text_completion`](crate::engine::model::Model::text_completion)
//! calls against [`ExtendedConfig::utility_model`]. The translation prompt
//! instructs the utility model to translate **only** natural-language
//! prose and leave code blocks, inline code, file paths, identifiers,
//! commands, and CLI flags untouched — this is a coding harness, and
//! mistranslating those would corrupt the agent's input/output.
//!
//! Every failure path degrades: an unset/unavailable/erroring utility
//! model, inactive languages, or a timeout all return the input
//! unchanged rather than blocking the turn.

use std::time::Duration;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::ProvidersConfig;

/// Timeout for one translation call. Translation is best-effort; if the
/// provider stalls we'd rather pass the text through untranslated than
/// hang the turn.
const TRANSLATE_TIMEOUT: Duration = Duration::from_secs(30);

/// Translate the inbound `text` from the user's language into the model's
/// language. Returns the input unchanged when translation is inactive
/// (languages unset/equal), the utility model is unset/unavailable, or
/// the call errors/times out.
pub async fn inbound(
    text: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> String {
    translate_direction(
        text,
        &extended.translation.user_language,
        &extended.translation.model_language,
        extended,
        providers,
        redact,
        trusted_only,
    )
    .await
}

/// Translate the agent's complete final response from the model's
/// language back into the user's language. Same degrade contract as
/// [`inbound`].
pub async fn outbound(
    text: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> String {
    translate_direction(
        text,
        &extended.translation.model_language,
        &extended.translation.user_language,
        extended,
        providers,
        redact,
        trusted_only,
    )
    .await
}

/// Core: translate `text` from `source` into `target` using the utility
/// model. Pass-through (returns `text` owned) on every disabled/degrade
/// path so callers never have to special-case failure.
async fn translate_direction(
    text: &str,
    source: &str,
    target: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> String {
    // Inactive feature (unset/equal languages) → no translation.
    if !extended.translation.is_active() {
        return text.to_string();
    }
    // Nothing to translate.
    if text.trim().is_empty() {
        return text.to_string();
    }
    match try_translate(
        text,
        source,
        target,
        extended,
        providers,
        redact,
        trusted_only,
    )
    .await
    {
        Some(out) => out,
        None => text.to_string(),
    }
}

/// Attempt the utility-model translation, returning `None` on every
/// failure path (unset/unparseable/unbuildable model, send error, timeout,
/// empty response) so the caller degrades to pass-through.
async fn try_translate(
    text: &str,
    source: &str,
    target: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Option<String> {
    let model_ref = extended.translation_model_ref()?;
    let model = match crate::engine::model::Model::from_ref_trusted_only(
        providers,
        model_ref,
        redact,
        trusted_only,
    ) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(error = %e, "translate: model build failed; passing through");
            return None;
        }
    };

    let prompt = build_translation_prompt(source, target, text);
    let response =
        match tokio::time::timeout(TRANSLATE_TIMEOUT, model.text_completion(&prompt)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "translate: call failed; passing through");
                return None;
            }
            Err(_) => {
                tracing::debug!("translate: call timed out; passing through");
                return None;
            }
        };

    if response.trim().is_empty() {
        return None;
    }
    Some(response)
}

/// Build the one-shot translation prompt. Names the source and target
/// languages and instructs the utility model to translate only natural-
/// language prose, leaving code and machine-readable tokens verbatim. The
/// untrusted text is fenced so the model treats it as content, not
/// instructions, and is told to return only the translation.
pub fn build_translation_prompt(source: &str, target: &str, text: &str) -> String {
    format!(
        "Translate the natural-language prose in the text below from {source} to {target}. \
         This is text from a software-engineering coding tool: leave all code blocks, inline \
         code, file paths, identifiers, commands, and CLI flags exactly as written — translate \
         only the surrounding prose. Return ONLY the translated text, with no preamble, no \
         explanation, and no code fences around the whole answer.\n\n\
         <text>\n{text}\n</text>",
        source = source.trim(),
        target = target.trim(),
    )
}

/// Remove `<think>…</think>` reasoning blocks from `text`, returning only
/// the body. Used before outbound translation so the utility model never
/// translates the model's inline chain-of-thought. Delegates to the single
/// shared parser ([`crate::engine::think::split_think`]) so the strip
/// semantics are byte-identical to the streamed and finalization splits
/// (no third tag-parsing implementation).
pub fn strip_think_blocks(text: &str) -> String {
    crate::engine::think::split_think(text).0
}

/// Resolve `(ExtendedConfig, ProvidersConfig)` for `cwd` and check whether
/// translation is configured active. A thin convenience over
/// [`crate::auto_title::load_configs_for`] used by call sites that only
/// translate when the feature is on (so they can skip the config load on
/// the common path). Returns the loaded configs alongside the flag so the
/// caller reuses them for the actual call.
pub fn load_if_active(cwd: &std::path::Path) -> Option<(ExtendedConfig, ProvidersConfig)> {
    let (extended, providers) = crate::auto_title::load_configs_for(cwd);
    if extended.translation.is_active() {
        Some((extended, providers))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extended::TranslationConfig;

    fn cfg_with(user: &str, model: &str, utility: Option<&str>) -> ExtendedConfig {
        ExtendedConfig {
            utility_model: utility.map(|s| s.to_string()),
            translation: TranslationConfig {
                user_language: user.to_string(),
                model_language: model.to_string(),
            },
            ..ExtendedConfig::default()
        }
    }

    #[test]
    fn prompt_includes_languages_and_preserve_instruction() {
        let p = build_translation_prompt("Spanish", "English", "hola mundo");
        assert!(p.contains("Spanish"), "{p}");
        assert!(p.contains("English"), "{p}");
        assert!(p.contains("hola mundo"), "{p}");
        // The defining instruction: leave code/paths/identifiers/commands/
        // flags untouched.
        assert!(p.contains("code blocks"), "{p}");
        assert!(p.contains("inline"), "{p}");
        assert!(p.contains("file paths"), "{p}");
        assert!(p.contains("identifiers"), "{p}");
        assert!(p.contains("commands"), "{p}");
        assert!(p.contains("CLI flags"), "{p}");
    }

    #[tokio::test]
    async fn inactive_languages_pass_through_unchanged() {
        // Equal languages → inactive → no translation even with a utility
        // model set. Degrades to the input verbatim (no network).
        let extended = cfg_with("English", "English", Some("anthropic:claude-haiku-4-5"));
        let providers = ProvidersConfig::default();
        let out = inbound(
            "hello",
            &extended,
            &providers,
            std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .await;
        assert_eq!(out, "hello");
        let out = outbound(
            "hello",
            &extended,
            &providers,
            std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .await;
        assert_eq!(out, "hello");
    }

    #[tokio::test]
    async fn unset_utility_model_passes_through_unchanged() {
        // Active languages but no utility model → degrade to pass-through
        // with no error.
        let extended = cfg_with("Spanish", "English", None);
        let providers = ProvidersConfig::default();
        let out = inbound(
            "hola",
            &extended,
            &providers,
            std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .await;
        assert_eq!(out, "hola");
        let out = outbound(
            "hello",
            &extended,
            &providers,
            std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .await;
        assert_eq!(out, "hello");
    }

    #[test]
    fn strip_think_blocks_removes_reasoning() {
        assert_eq!(
            strip_think_blocks("<think>reasoning here</think>\nThe answer."),
            "The answer."
        );
        // No think block → untouched.
        assert_eq!(strip_think_blocks("just an answer"), "just an answer");
        // Leading UNTERMINATED block (no close) is NOT reasoning — the whole
        // content, open tag included, stays as body so a missing close tag
        // never swallows the answer (shared splitter's priority-#1 rule).
        assert_eq!(
            strip_think_blocks("<think>still thinking"),
            "<think>still thinking"
        );
        // Non-leading block: real body text precedes the tag, so it is
        // literal content and kept verbatim (leading-only stripping).
        assert_eq!(
            strip_think_blocks("before <think>still thinking"),
            "before <think>still thinking"
        );
        // Only the leading block is stripped; a later block stays literal.
        assert_eq!(
            strip_think_blocks("<think>a</think>X<think>b</think>Y"),
            "X<think>b</think>Y"
        );
    }

    #[tokio::test]
    async fn empty_text_passes_through() {
        let extended = cfg_with("Spanish", "English", Some("anthropic:claude-haiku-4-5"));
        let providers = ProvidersConfig::default();
        assert_eq!(
            inbound(
                "   ",
                &extended,
                &providers,
                std::sync::Arc::new(crate::redact::RedactionTable::empty()),
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .await,
            "   "
        );
    }
}
