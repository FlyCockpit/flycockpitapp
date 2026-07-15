//! Token counting.
//!
//! Two sources, in this order of preference:
//!
//! 1. **Provider-reported usage** ([`TokenUsage`], populated from the
//!    response after each round-trip). Authoritative for the call that
//!    just completed.
//! 2. **Local cl100k_base estimate** ([`count`], via `tiktoken-rs`'s
//!    lazy singleton). Used pre-flight — composer context indicator,
//!    auto-title threshold gate, anywhere we need a number before the
//!    next inference returns.
//!
//! The user-facing contract for any token-budget enforcement remains
//! "≈" — exactness is not promised across providers.

use tiktoken_rs::{
    cl100k_base_singleton, o200k_base_singleton, p50k_base_singleton, p50k_edit_singleton,
    r50k_base_singleton,
};

pub use crate::db::tokenizer_calibration::TokenizerStrategy;

#[cfg(test)]
thread_local! {
    static COUNT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_count_call_count() {
    COUNT_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn count_call_count() -> usize {
    COUNT_CALLS.with(std::cell::Cell::get)
}

/// Warm the default cl100k tokenizer singleton without counting user text.
pub fn warm_cl100k() {
    let _ = cl100k_base_singleton();
}

/// Count tokens in `text` using cl100k_base — the documented global
/// default / fallback (GOALS §10).
pub fn count(text: &str) -> usize {
    #[cfg(test)]
    COUNT_CALLS.with(|calls| calls.set(calls.get() + 1));
    count_with(text, TokenizerStrategy::Cl100k)
}

/// Every strategy, in a fixed order — the calibration loop tries each.
pub const STRATEGIES: [TokenizerStrategy; 5] = [
    TokenizerStrategy::R50k,
    TokenizerStrategy::P50k,
    TokenizerStrategy::P50kEdit,
    TokenizerStrategy::Cl100k,
    TokenizerStrategy::O200k,
];

/// Count tokens in `text` with a specific [`TokenizerStrategy`].
pub fn count_with(text: &str, strategy: TokenizerStrategy) -> usize {
    if text.is_empty() {
        return 0;
    }
    let bpe = match strategy {
        TokenizerStrategy::R50k => r50k_base_singleton(),
        TokenizerStrategy::P50k => p50k_base_singleton(),
        TokenizerStrategy::P50kEdit => p50k_edit_singleton(),
        TokenizerStrategy::Cl100k => cl100k_base_singleton(),
        TokenizerStrategy::O200k => o200k_base_singleton(),
    };
    bpe.encode_with_special_tokens(text).len()
}

/// Apply a calibrated `(strategy, scale)` to `text`: `count_with * scale`,
/// rounded. This is the model-aware estimate once a calibration row (or
/// the `(cl100k, 1.0)` default) has been resolved.
pub fn scaled_estimate(text: &str, strategy: TokenizerStrategy, scale: f64) -> u64 {
    let raw = count_with(text, strategy) as f64 * scale;
    raw.round().max(0.0) as u64
}

/// Per-call provider-reported token usage. Mirrors the columns we
/// persist into `inference_calls`.
///
/// `input_tokens` is the provider's reported prompt-token *total* and
/// **includes** cached reads (verified against rig's provider mappings):
/// `cached_input_tokens` (Anthropic `cache_read`, OpenAI
/// `prompt_tokens_details.cached_tokens`) is the subset of `input_tokens`
/// served from cache. `cache_creation_input_tokens` (Anthropic
/// `cache_creation`) is the portion written *into* the cache on a miss.
/// All three are recorded per inference call so the prune predicate's
/// cache-hit expectation (GOALS §10) is validatable against measured reality.
/// The TUI's blended context total subtracts the cached subset
/// ([`Self::blended_total`]) so cached reads don't inflate the headline
/// number (codex precedent, prompt `prompt-caching-strategy.md`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    /// Input tokens written *into* the prompt cache on a miss (the write
    /// cost of the cached prefix). Mapped from `rig`'s normalized
    /// `cache_creation_input_tokens` (Anthropic `cache_creation`). Zero on
    /// providers/turns with no cache write.
    pub cache_creation_input_tokens: u64,
}

impl TokenUsage {
    /// The displayed context total with cached reads excluded
    /// (`non_cached_input + output`, codex precedent — prompt
    /// `prompt-caching-strategy.md`). `cached_input_tokens` is a subset of
    /// `input_tokens`, so subtracting it yields the freshly-processed input
    /// plus output; cached tokens are surfaced separately rather than folded
    /// into the headline number.
    pub fn blended_total(&self) -> u64 {
        self.input_tokens
            .saturating_sub(self.cached_input_tokens)
            .saturating_add(self.output_tokens)
    }

    /// Cache hit rate over input: `cached_input_tokens / input_tokens`, in
    /// `0.0..=1.0`. `None` when there were no input tokens (nothing to rate).
    pub fn hit_rate(&self) -> Option<f64> {
        if self.input_tokens == 0 {
            None
        } else {
            Some(self.cached_input_tokens as f64 / self.input_tokens as f64)
        }
    }

    /// `true` if the provider reported nothing meaningful (rig signals
    /// this by leaving every field at 0 — see `rig::completion::Usage`
    /// docs).
    pub fn is_empty(&self) -> bool {
        self.input_tokens == 0
            && self.output_tokens == 0
            && self.cached_input_tokens == 0
            && self.cache_creation_input_tokens == 0
    }
}

impl From<rig::completion::Usage> for TokenUsage {
    fn from(u: rig::completion::Usage) -> Self {
        Self {
            input_tokens: u.input_tokens,
            output_tokens: u.output_tokens,
            cached_input_tokens: u.cached_input_tokens,
            cache_creation_input_tokens: u.cache_creation_input_tokens,
        }
    }
}

// ---- per-model tokenizer calibration ---------------------------------------

/// Close the calibration window once cumulative actual tokens reach this
/// and the call-count floor is met. The floor stops one giant outlier
/// call from deciding the fit. Both tunable.
pub const CALIBRATION_TOKEN_TARGET: u64 = 20_000;
pub const CALIBRATION_MIN_CALLS: usize = 5;

/// One sampled inference call: the provider's `input + output` total and
/// the estimate each strategy produced for the same text basis.
#[derive(Debug, Clone)]
struct CalSample {
    actual: u64,
    ests: [usize; STRATEGIES.len()],
}

/// Accumulates inference samples in memory (per session, never
/// persisted in-progress) and, once the window closes, picks the
/// strategy with the lowest mean *relative* error and the scale factor
/// that maps its estimate onto the provider's real count. See GOALS §15
/// / the calibration spec.
#[derive(Debug, Clone, Default)]
pub struct Calibrator {
    samples: Vec<CalSample>,
    cumulative_actual: u64,
}

impl Calibrator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a sample: estimate `basis` under every strategy and record it
    /// against the provider's `actual` (= input + output) tokens.
    pub fn add_sample(&mut self, basis: &str, actual: u64) {
        let ests = STRATEGIES.map(|s| count_with(basis, s));
        self.cumulative_actual = self.cumulative_actual.saturating_add(actual);
        self.samples.push(CalSample { actual, ests });
    }

    /// True once enough volume has accumulated to trust a fit.
    pub fn window_closed(&self) -> bool {
        self.cumulative_actual >= CALIBRATION_TOKEN_TARGET
            && self.samples.len() >= CALIBRATION_MIN_CALLS
    }

    pub fn sample_calls(&self) -> usize {
        self.samples.len()
    }

    pub fn cumulative_actual(&self) -> u64 {
        self.cumulative_actual
    }

    /// Compute the fit: `argmin_s mean_i |est - actual| / actual` (mean
    /// relative error, so big calls don't dominate), then
    /// `scale = mean_i actual / est_chosen` so `est * scale ≈ actual`.
    /// `None` when there are no samples. Estimates of 0 are clamped to 1
    /// to keep the ratios finite.
    pub fn result(&self) -> Option<(TokenizerStrategy, f64)> {
        if self.samples.is_empty() {
            return None;
        }
        let n = self.samples.len() as f64;
        let mut best: Option<(usize, f64)> = None;
        for si in 0..STRATEGIES.len() {
            let mut sum_rel = 0.0;
            for s in &self.samples {
                let est = s.ests[si].max(1) as f64;
                let actual = s.actual.max(1) as f64;
                sum_rel += (est - actual).abs() / actual;
            }
            let mean_rel = sum_rel / n;
            if best.is_none_or(|(_, b)| mean_rel < b) {
                best = Some((si, mean_rel));
            }
        }
        let (chosen, _) = best?;
        let mut sum_scale = 0.0;
        for s in &self.samples {
            let est = s.ests[chosen].max(1) as f64;
            sum_scale += s.actual as f64 / est;
        }
        Some((STRATEGIES[chosen], sum_scale / n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_is_zero() {
        assert_eq!(count(""), 0);
    }

    #[test]
    fn count_with_matches_default_cl100k() {
        let t = "The quick brown fox jumps over the lazy dog.";
        assert_eq!(count(t), count_with(t, TokenizerStrategy::Cl100k));
    }

    #[test]
    fn strategy_name_round_trips() {
        for s in STRATEGIES {
            assert_eq!(TokenizerStrategy::from_name(s.as_str()), s);
        }
        // Unknown names fall back to the cl100k floor.
        assert_eq!(
            TokenizerStrategy::from_name("bogus"),
            TokenizerStrategy::Cl100k
        );
    }

    #[test]
    fn calibrator_window_needs_volume_and_calls() {
        let mut c = Calibrator::new();
        c.add_sample("hello world", 100_000); // one giant call
        assert!(!c.window_closed(), "call-count floor not met");
        for _ in 0..5 {
            c.add_sample("hello world", 1);
        }
        assert!(c.window_closed());
    }

    #[test]
    fn calibrator_picks_lowest_relative_error_strategy() {
        // Synthesize samples whose actual equals the cl100k count, so
        // cl100k has zero relative error and must win with scale ≈ 1.
        let texts = [
            "fn main() { println!(\"hello\"); }",
            "The quick brown fox jumps over the lazy dog, repeatedly.",
            "lorem ipsum dolor sit amet consectetur adipiscing elit",
            "alpha beta gamma delta epsilon zeta eta theta iota kappa",
            "one two three four five six seven eight nine ten eleven",
        ];
        let mut c = Calibrator::new();
        for t in texts {
            let actual = count_with(t, TokenizerStrategy::Cl100k) as u64;
            c.add_sample(t, actual);
        }
        let (strategy, scale) = c.result().expect("samples present");
        assert_eq!(strategy, TokenizerStrategy::Cl100k);
        assert!(
            (scale - 1.0).abs() < 1e-9,
            "scale should be ~1.0, got {scale}"
        );
    }

    #[test]
    fn hello_world_is_a_few_tokens() {
        let n = count("Hello, world!");
        assert!((1..=10).contains(&n), "got {n}");
    }

    #[test]
    fn longer_text_is_more_tokens_than_short() {
        let short = count("hi");
        let long = count("The quick brown fox jumps over the lazy dog.");
        assert!(long > short);
    }

    /// The `From<rig::completion::Usage>` impl carries both cache fields
    /// (`cached_input_tokens` read + `cache_creation_input_tokens` write)
    /// so the prune predicate's cache-hit expectation is validatable against
    /// measured reality (GOALS §10).
    #[test]
    fn token_usage_from_rig_carries_cache_creation() {
        let rig = rig::completion::Usage {
            input_tokens: 100,
            output_tokens: 20,
            total_tokens: 120,
            cached_input_tokens: 80,
            cache_creation_input_tokens: 15,
            tool_use_prompt_tokens: 0,
            reasoning_tokens: 0,
        };
        let usage = TokenUsage::from(rig);
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 20);
        assert_eq!(usage.cached_input_tokens, 80);
        assert_eq!(usage.cache_creation_input_tokens, 15);
        assert!(!usage.is_empty());
    }

    /// A turn that wrote a cache prefix but reported no read/IO totals is
    /// still non-empty — `cache_creation_input_tokens` counts toward
    /// `is_empty` so a cache-write-only turn isn't dropped as "no usage".
    #[test]
    fn token_usage_cache_creation_only_is_not_empty() {
        let usage = TokenUsage {
            cache_creation_input_tokens: 42,
            ..TokenUsage::default()
        };
        assert!(!usage.is_empty());
    }

    /// The blended context total excludes cached reads (codex precedent,
    /// prompt `prompt-caching-strategy.md`): `non_cached_input + output`,
    /// not `input + output`. Cached tokens are a subset of `input_tokens`.
    #[test]
    fn blended_total_excludes_cached_input() {
        let usage = TokenUsage {
            input_tokens: 1000,
            output_tokens: 200,
            cached_input_tokens: 800,
            cache_creation_input_tokens: 0,
        };
        // blended subtracts the cached subset from input.
        assert_eq!(usage.blended_total(), 1000 - 800 + 200);
        // Hit rate is the cached fraction of input.
        assert_eq!(usage.hit_rate(), Some(0.8));
    }

    /// No input tokens → no hit rate (nothing to rate); blended falls back to
    /// output only.
    #[test]
    fn blended_total_and_hit_rate_with_no_input() {
        let usage = TokenUsage {
            output_tokens: 50,
            ..TokenUsage::default()
        };
        assert_eq!(usage.blended_total(), 50);
        assert_eq!(usage.hit_rate(), None);
    }
}
