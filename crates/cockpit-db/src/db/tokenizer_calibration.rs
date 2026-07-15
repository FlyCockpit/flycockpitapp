//! Per-`(provider, model)` tokenizer calibration storage.
//!
//! Holds the learned `(strategy, scale)` that maps a local tiktoken
//! estimate onto a provider's real token counts, with a 90-day expiry.
//! The resolver returns a row even when expired — a stale fit still
//! beats the global cl100k_base default, and a fresh calibration window
//! recomputes and overwrites it in the background (never dropping to the
//! default mid-recompute, which would visibly jump the displayed
//! estimate).

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};

use crate::db::Db;

/// A tiktoken encoding strategy persisted by tokenizer calibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenizerStrategy {
    R50k,
    P50k,
    P50kEdit,
    Cl100k,
    O200k,
}

impl TokenizerStrategy {
    /// The string persisted in `tokenizer_calibration.strategy`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::R50k => "r50k_base",
            Self::P50k => "p50k_base",
            Self::P50kEdit => "p50k_edit",
            Self::Cl100k => "cl100k_base",
            Self::O200k => "o200k_base",
        }
    }

    /// Parse a persisted strategy name; unknown names fall back to the
    /// cl100k_base floor rather than erroring.
    pub fn from_name(name: &str) -> Self {
        match name {
            "r50k_base" => Self::R50k,
            "p50k_base" => Self::P50k,
            "p50k_edit" => Self::P50kEdit,
            "o200k_base" => Self::O200k,
            _ => Self::Cl100k,
        }
    }
}

/// Calibration lifetime: 90 days in seconds.
pub const CALIBRATION_TTL_SECS: i64 = 90 * 24 * 60 * 60;

impl Db {
    /// Resolve the tokenizer for `(provider, model)`. Returns the stored
    /// `(strategy, scale)` even if expired; falls back to
    /// `(cl100k_base, 1.0)` when there's no row.
    pub fn resolve_tokenizer(&self, provider: &str, model: &str) -> (TokenizerStrategy, f64) {
        let row = match self.read_blocking(|conn| {
            conn.query_row(
                "SELECT strategy, scale FROM tokenizer_calibration
                      WHERE provider = ?1 AND model = ?2",
                params![provider, model],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?)),
            )
            .optional()
            .context("reading tokenizer_calibration")
        }) {
            Ok(row) => row,
            Err(error) => {
                tracing::warn!(
                    provider,
                    model,
                    error = %error,
                    "tokenizer calibration lookup failed; using default tokenizer"
                );
                None
            }
        };
        match row {
            Some((strategy, scale)) => (TokenizerStrategy::from_name(&strategy), scale),
            None => (TokenizerStrategy::Cl100k, 1.0),
        }
    }

    /// Whether a non-expired calibration row exists for `(provider,
    /// model)`. The calibration accumulator skips recomputing while one
    /// does.
    pub fn tokenizer_calibration_fresh(&self, provider: &str, model: &str, now: i64) -> bool {
        match self.read_blocking(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM tokenizer_calibration
                  WHERE provider = ?1 AND model = ?2 AND expires_at > ?3",
                params![provider, model, now],
                |r| r.get(0),
            )?;
            Ok(count > 0)
        }) {
            Ok(fresh) => fresh,
            Err(error) => {
                tracing::warn!(
                    provider,
                    model,
                    error = %error,
                    "tokenizer calibration freshness check failed; treating calibration as stale"
                );
                false
            }
        }
    }

    /// Insert or replace the calibration row for `(provider, model)`.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_tokenizer_calibration(
        &self,
        provider: &str,
        model: &str,
        strategy: &str,
        scale: f64,
        computed_at: i64,
        expires_at: i64,
        sample_total_tokens: i64,
        sample_calls: i64,
    ) -> Result<()> {
        let provider = provider.to_owned();
        let model = model.to_owned();
        let strategy = strategy.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO tokenizer_calibration
                   (provider, model, strategy, scale, computed_at, expires_at,
                    sample_total_tokens, sample_calls)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(provider, model) DO UPDATE SET
                    strategy = excluded.strategy,
                    scale = excluded.scale,
                    computed_at = excluded.computed_at,
                    expires_at = excluded.expires_at,
                    sample_total_tokens = excluded.sample_total_tokens,
                    sample_calls = excluded.sample_calls",
                params![
                    provider,
                    model,
                    strategy,
                    scale,
                    computed_at,
                    expires_at,
                    sample_total_tokens,
                    sample_calls
                ],
            )
            .context("upserting tokenizer_calibration")?;
            Ok(())
        })
    }
}

#[cfg(test)]
fn resolve_tokenizer_fallback_for_test(
    provider: &str,
    model: &str,
    result: Result<Option<(String, f64)>>,
) -> (TokenizerStrategy, f64) {
    let row = match result {
        Ok(row) => row,
        Err(error) => {
            tracing::warn!(
                provider,
                model,
                error = %error,
                "tokenizer calibration lookup failed; using default tokenizer"
            );
            None
        }
    };
    match row {
        Some((strategy, scale)) => (TokenizerStrategy::from_name(&strategy), scale),
        None => (TokenizerStrategy::Cl100k, 1.0),
    }
}

#[cfg(test)]
fn tokenizer_calibration_fresh_fallback_for_test(
    provider: &str,
    model: &str,
    result: Result<bool>,
) -> bool {
    match result {
        Ok(fresh) => fresh,
        Err(error) => {
            tracing::warn!(
                provider,
                model,
                error = %error,
                "tokenizer calibration freshness check failed; treating calibration as stale"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Mutex as StdMutex;
    use tracing::Level;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CaptureWriter(std::sync::Arc<StdMutex<Vec<u8>>>);

    struct CaptureGuard(std::sync::Arc<StdMutex<Vec<u8>>>);

    impl io::Write for CaptureGuard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureGuard;

        fn make_writer(&'a self) -> Self::Writer {
            CaptureGuard(self.0.clone())
        }
    }

    fn capture_warn_log(f: impl FnOnce()) -> String {
        let bytes = std::sync::Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::WARN)
            .with_ansi(false)
            .with_writer(CaptureWriter(bytes.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn resolver_falls_back_to_cl100k_default() {
        let db = Db::open_in_memory().unwrap();
        let (strategy, scale) = db.resolve_tokenizer("anthropic", "claude");
        assert_eq!(strategy, TokenizerStrategy::Cl100k);
        assert_eq!(scale, 1.0);
    }

    #[test]
    fn resolver_returns_expired_row_over_default() {
        let db = Db::open_in_memory().unwrap();
        let now = 2_000_000_000i64;
        // computed long ago; already expired.
        db.upsert_tokenizer_calibration(
            "openai",
            "gpt",
            "o200k_base",
            1.25,
            now - CALIBRATION_TTL_SECS - 10,
            now - 10,
            50_000,
            12,
        )
        .unwrap();
        assert!(!db.tokenizer_calibration_fresh("openai", "gpt", now));
        // Still returned despite being expired — beats the default.
        let (strategy, scale) = db.resolve_tokenizer("openai", "gpt");
        assert_eq!(strategy, TokenizerStrategy::O200k);
        assert_eq!(scale, 1.25);
    }

    #[test]
    fn fresh_row_is_reported_fresh_and_upsert_overwrites() {
        let db = Db::open_in_memory().unwrap();
        let now = 2_000_000_000i64;
        db.upsert_tokenizer_calibration(
            "p",
            "m",
            "cl100k_base",
            1.0,
            now,
            now + CALIBRATION_TTL_SECS,
            20_000,
            5,
        )
        .unwrap();
        assert!(db.tokenizer_calibration_fresh("p", "m", now));
        // Overwrite with a new fit.
        db.upsert_tokenizer_calibration(
            "p",
            "m",
            "p50k_base",
            0.9,
            now,
            now + CALIBRATION_TTL_SECS,
            25_000,
            7,
        )
        .unwrap();
        let (strategy, scale) = db.resolve_tokenizer("p", "m");
        assert_eq!(strategy, TokenizerStrategy::P50k);
        assert_eq!(scale, 0.9);
    }

    #[test]
    fn calibration_query_errors_warn_and_keep_defaults() {
        let log = capture_warn_log(|| {
            let (strategy, scale) = resolve_tokenizer_fallback_for_test(
                "provider-a",
                "model-b",
                Err(anyhow::anyhow!("table unavailable")),
            );
            assert_eq!(strategy, TokenizerStrategy::Cl100k);
            assert_eq!(scale, 1.0);
            assert!(!tokenizer_calibration_fresh_fallback_for_test(
                "provider-a",
                "model-b",
                Err(anyhow::anyhow!("count failed"))
            ));
        });

        assert!(log.contains("tokenizer calibration lookup failed"));
        assert!(log.contains("tokenizer calibration freshness check failed"));
        assert!(log.contains("provider-a"));
        assert!(log.contains("model-b"));
    }
}
