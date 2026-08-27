//! OpenRouter dedicated Image API generation adapter.
//!
//! Implements OpenRouter's direct Image API against the configured canonical
//! origin with exact discovery, reference, routing, attribution, cost, and
//! base64-output contracts. There is no Responses/Chat route, server tool,
//! streaming partial, remote-output URL, or active-model fallback path.
//!
//! Every discovery, submission, and same-origin follow-up uses the attribution
//! header merge contract from `openrouter-attribution-headers`. Automatic
//! redirects are disabled for all authenticated OpenRouter Image API requests;
//! every 3xx is a stable failure, so credentials and attribution cannot cross
//! origins.
//!
//! The pure request/response logic (discovery, preflight, pricing, parsing)
//! produces bounded read-only request descriptions and parses already-bounded
//! responses. The dispatch wiring at the bottom of this module implements
//! [`crate::image_generation_job::ImageGenerationAdapter`] over a production
//! pinned/vetted transport seam ([`OpenrouterImagesHttpTransport`]) that reports
//! the shared billing-safe [`crate::image_generation::transport`] vocabulary;
//! the job/artifact foundation owns immutable plans, attempts, artifacts, and
//! spend.

use std::fmt;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::providers::registry::ResolvedProviderOrigin;

/// Maximum number of output images a single request may ask for (OpenRouter
/// Image API global bound). Individual endpoints may advertise a tighter cap.
pub const MAX_N: u8 = 10;
/// Minimum number of output images a single request may ask for.
pub const MIN_N: u8 = 1;
/// Canonical OpenRouter Image API paths, relative to the configured origin.
pub const DISCOVERY_MODELS_PATH: &str = "/api/v1/images/models";
pub const SUBMIT_PATH: &str = "/api/v1/images";
/// Per-reference and aggregate byte bounds for input image data URLs.
pub const MAX_PER_REFERENCE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_AGGREGATE_REFERENCE_BYTES: usize = 64 * 1024 * 1024;
/// Bounded response limits.
pub const MAX_OUTPUT_BASE64_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_USAGE_METADATA_BYTES: usize = 4 * 1024;
/// Microdollars per dollar.
const MICROS_PER_DOLLAR: u64 = 1_000_000;

/// Adapter kind identifier for plan/audit identity.
pub const ADAPTER_KIND: &str = "openrouter_images";

/// Exact tier-size tokens accepted by the dimension grammar (case-sensitive).
pub const TIER_SIZE_TOKENS: &[&str] = &["512", "1K", "2K", "4K"];

/// Canonical allowed output MIME types for raster outputs.
pub const ALLOWED_RASTER_MIME_TYPES: &[&str] =
    &["image/png", "image/jpeg", "image/webp", "image/gif"];

// ---------------------------------------------------------------------------
// Checked decimal/rational money arithmetic (no binary floating point).
// ---------------------------------------------------------------------------

/// A checked nonnegative amount in microdollars, held as the exact rational
/// `micros_num / micros_den` where `micros_den` is a power of ten. Keeping the
/// sub-micro residual (rather than ceiling at parse time) lets multiplication
/// by a count and summation of billable lines stay exact; the ceiling to
/// integer microdollars is deferred to [`ceiling_microdollars`] / [`as_micros`]
/// so a fractional unit price does not round up once per unit. All pricing
/// `cost_usd` values are parsed from the JSON number's lexical decimal form
/// with checked arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedMicrodollars {
    micros_num: u128,
    /// Always a power of ten (>= 1).
    micros_den: u128,
}

impl CheckedMicrodollars {
    /// Parse a lexical decimal string (as emitted by JSON numbers) into a
    /// checked microdollar amount. Rejects signs, exponents, whitespace,
    /// missing fraction digits, and overflow.
    pub fn from_lexical_decimal(text: &str) -> Option<Self> {
        let text = text.strip_prefix('+').unwrap_or(text);
        if text.starts_with('-') || text.is_empty() {
            return None;
        }
        if text.bytes().any(|b| b.eq_ignore_ascii_case(&b'e')) {
            return None;
        }
        let (int_part, frac_part) = match text.split_once('.') {
            Some((i, f)) => (i, f),
            None => (text, ""),
        };
        if int_part.is_empty() && frac_part.is_empty() {
            return None;
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if !frac_part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Leading zeros are allowed in the integer part (e.g. "007"), but the
        // whole token must not be empty.
        let int_value: u128 = if int_part.is_empty() {
            0
        } else {
            int_part.parse().ok()?
        };
        // Exact microdollar amount: the dollar value is
        //   int_value + frac_value / 10^L    (L = number of fractional digits)
        // and micros = dollars * 10^6 = int_value*10^6 + frac_value*10^(6-L).
        // For L <= 6 this is an integer (den = 1); for L > 6 the sub-micro
        // residual is preserved exactly as den = 10^(L-6) so the ceiling can be
        // deferred until after multiplication and summation. Overflow (e.g. a
        // pathologically long fraction) yields `None` (unknown), never a wrong
        // finite maximum.
        let frac_len = frac_part.len() as u32;
        let frac_value: u128 = if frac_part.is_empty() {
            0
        } else {
            frac_part.parse().ok()?
        };
        let int_micros = int_value.checked_mul(MICROS_PER_DOLLAR as u128)?;
        let (micros_num, micros_den) = if frac_len <= 6 {
            let scale = 6u32 - frac_len;
            let scaled_frac = frac_value.checked_mul(10u128.checked_pow(scale)?)?;
            (int_micros.checked_add(scaled_frac)?, 1u128)
        } else {
            let den = 10u128.checked_pow(frac_len - 6)?;
            let scaled_int = int_micros.checked_mul(den)?;
            (scaled_int.checked_add(frac_value)?, den)
        };
        Some(Self {
            micros_num,
            micros_den,
        })
    }

    /// Construct from already-validated integer microdollars.
    pub const fn from_micros(micros: u128) -> Self {
        Self {
            micros_num: micros,
            micros_den: 1,
        }
    }

    /// Checked addition of two microdollar amounts. Both denominators are powers
    /// of ten, so the larger is an exact multiple of the smaller.
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        if self.micros_den == other.micros_den {
            return Some(Self {
                micros_num: self.micros_num.checked_add(other.micros_num)?,
                micros_den: self.micros_den,
            });
        }
        let (den, hi, lo) = if self.micros_den > other.micros_den {
            (self.micros_den, self, other)
        } else {
            (other.micros_den, other, self)
        };
        let factor = den / lo.micros_den;
        let lo_scaled = lo.micros_num.checked_mul(factor)?;
        Some(Self {
            micros_num: hi.micros_num.checked_add(lo_scaled)?,
            micros_den: den,
        })
    }

    /// Checked multiplication of a microdollar unit price by an integer count.
    pub fn checked_mul_count(&self, count: u128) -> Option<Self> {
        Some(Self {
            micros_num: self.micros_num.checked_mul(count)?,
            micros_den: self.micros_den,
        })
    }

    /// The integer microdollar value, ceiling of the exact rational amount.
    pub fn as_micros(&self) -> u128 {
        self.micros_num.div_ceil(self.micros_den)
    }
}

/// Convert a complete known USD maximum to integer microdollars by checked
/// ceiling after summing the exact amount. Returns `None` on overflow.
pub fn ceiling_microdollars(amount: &CheckedMicrodollars) -> Option<u128> {
    Some(amount.as_micros())
}

// ---------------------------------------------------------------------------
// Exact-decimal ratio consistency for explicit pixels + aspect ratio.
// ---------------------------------------------------------------------------

/// A checked exact-decimal ratio `R:R` where each `R` matches
/// `[1-9][0-9]*(\.[0-9]+)?`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactRatio {
    numerator: u128,
    denominator: u128,
}

impl ExactRatio {
    /// Parse a ratio string `R:R`. Rejects whitespace, signs, zero
    /// components, leading-zero components, exponents, missing fraction
    /// digits, and `auto`.
    pub fn parse(text: &str) -> Option<Self> {
        let (left, right) = text.split_once(':')?;
        let (num_digits, num_scale) = Self::parse_decimal_component(left)?;
        let (den_digits, den_scale) = Self::parse_decimal_component(right)?;
        if num_digits == 0 || den_digits == 0 {
            return None;
        }
        // Each component carries its own fractional scale (number of decimal
        // places). To store an exact ratio, cross-scale the components so both
        // share a common power-of-ten denominator:
        //   num_value/den_value
        //     = (num_digits / 10^num_scale) / (den_digits / 10^den_scale)
        //     = (num_digits * 10^den_scale) / (den_digits * 10^num_scale).
        let numerator = num_digits.checked_mul(10u128.checked_pow(den_scale)?)?;
        let denominator = den_digits.checked_mul(10u128.checked_pow(num_scale)?)?;
        Some(Self {
            numerator,
            denominator,
        })
    }

    /// Parse a single decimal component matching `[1-9][0-9]*(\.[0-9]+)?` into
    /// its integer digits (with the decimal point removed) and the fractional
    /// scale (number of fractional digits). The caller normalizes scales.
    fn parse_decimal_component(text: &str) -> Option<(u128, u32)> {
        if text.is_empty() {
            return None;
        }
        let (int_part, frac_part) = match text.split_once('.') {
            Some((i, f)) => (i, f),
            None => (text, ""),
        };
        // Reject leading zeros in the integer part unless the integer part is
        // exactly "0" (but zero is rejected later; a leading-zero non-zero
        // like "09" is invalid per the grammar `[1-9][0-9]*`).
        if int_part.is_empty() {
            return None;
        }
        if int_part == "0" {
            // "0" alone is not a valid `[1-9]`-leading component.
            return None;
        }
        if int_part.starts_with('0') {
            return None;
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if frac_part.is_empty() {
            // A bare integer is allowed (matches `[1-9][0-9]*` with no
            // fractional part): zero fractional scale.
            return Some((int_part.parse().ok()?, 0));
        }
        if !frac_part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Combine into a single integer by removing the decimal point; the
        // fractional scale is the number of fractional digits, normalized by
        // the caller via cross multiplication.
        let combined = format!("{int_part}{frac_part}");
        Some((combined.parse().ok()?, frac_part.len() as u32))
    }

    /// Returns `true` when `width / height` exactly equals this ratio, proved
    /// by exact-rational cross multiplication. Each component's fractional
    /// scale is normalized so the comparison is exact.
    pub fn matches_pixels(&self, width: u64, height: u64) -> bool {
        if width == 0 || height == 0 {
            return false;
        }
        // Cross multiplication is the exact-rational proof:
        // width/height == num/den  <=>  width*den == height*num.
        let w = width as u128;
        let h = height as u128;
        w.checked_mul(self.denominator) == h.checked_mul(self.numerator)
    }
}

// ---------------------------------------------------------------------------
// Model ID and endpoint link validation.
// ---------------------------------------------------------------------------

/// A validated OpenRouter model ID containing exactly two nonempty path
/// segments: `{author}/{slug}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelId {
    author: String,
    slug: String,
}

impl ModelId {
    /// Parse and validate a model ID. Rejects anything that is not exactly two
    /// nonempty path segments.
    pub fn parse(id: &str) -> Option<Self> {
        let (author, slug) = id.split_once('/')?;
        if author.is_empty() || slug.is_empty() {
            return None;
        }
        if author.contains('/') || slug.contains('/') {
            return None;
        }
        Some(Self {
            author: author.to_string(),
            slug: slug.to_string(),
        })
    }

    /// The canonical `{author}/{slug}` string.
    pub fn as_str(&self) -> String {
        format!("{}/{}", self.author, self.slug)
    }

    /// The exact canonical relative endpoint link for this model:
    /// `/api/v1/images/models/{author}/{slug}/endpoints`.
    pub fn endpoint_link(&self) -> String {
        format!(
            "/api/v1/images/models/{}/{}/endpoints",
            self.author, self.slug
        )
    }

    pub fn author(&self) -> &str {
        &self.author
    }
    pub fn slug(&self) -> &str {
        &self.slug
    }
}

/// Validate an endpoint link against the selected model's exact canonical path.
///
/// Rejects absolute URLs, protocol-relative URLs, foreign-authority links,
/// userinfo/query/fragment, dot/traversal or encoded separator components, and
/// any path that is not the selected model's exact canonical endpoint link.
pub fn validate_endpoint_link(link: &str, model: &ModelId) -> Result<(), EndpointLinkError> {
    if link.is_empty() {
        return Err(EndpointLinkError::Empty);
    }
    // Reject absolute or protocol-relative URLs.
    if link.contains("://") || link.starts_with("//") {
        return Err(EndpointLinkError::AbsoluteOrProtocolRelative);
    }
    // Reject userinfo, query, or fragment.
    if link.contains('@') || link.contains('?') || link.contains('#') {
        return Err(EndpointLinkError::UserinfoQueryFragment);
    }
    // Reject dot/traversal or encoded separator components.
    for segment in link.split('/') {
        if segment == ".." || segment == "." {
            return Err(EndpointLinkError::Traversal);
        }
        if segment.contains("%2F")
            || segment.contains("%2f")
            || segment.contains("%5C")
            || segment.contains("%5c")
        {
            return Err(EndpointLinkError::EncodedSeparator);
        }
    }
    let canonical = model.endpoint_link();
    if link != canonical {
        return Err(EndpointLinkError::NotCanonical);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointLinkError {
    Empty,
    AbsoluteOrProtocolRelative,
    UserinfoQueryFragment,
    Traversal,
    EncodedSeparator,
    NotCanonical,
}

impl fmt::Display for EndpointLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "endpoint link is empty"),
            Self::AbsoluteOrProtocolRelative => {
                write!(f, "endpoint link is absolute or protocol-relative")
            }
            Self::UserinfoQueryFragment => {
                write!(f, "endpoint link contains userinfo, query, or fragment")
            }
            Self::Traversal => write!(f, "endpoint link contains dot or traversal components"),
            Self::EncodedSeparator => {
                write!(f, "endpoint link contains encoded separator components")
            }
            Self::NotCanonical => write!(f, "endpoint link is not the model's canonical path"),
        }
    }
}

impl std::error::Error for EndpointLinkError {}

// ---------------------------------------------------------------------------
// Size / dimension grammar.
// ---------------------------------------------------------------------------

/// A validated `size` field value: either an exact tier token or canonical
/// explicit pixels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeValue {
    /// One of the exact case-sensitive documented tier tokens: `512`, `1K`,
    /// `2K`, or `4K`.
    Tier(&'static str),
    /// Canonical explicit pixels `WxH` where each dimension parses into `u32`
    /// and the product fits `u64`.
    Pixels {
        width: u32,
        height: u32,
        product: u64,
    },
}

impl SizeValue {
    /// Parse and validate a `size` field per the dimension grammar.
    pub fn parse(text: &str) -> Option<Self> {
        if let Some(tier) = TIER_SIZE_TOKENS.iter().find(|t| **t == text) {
            return Some(Self::Tier(tier));
        }
        // Canonical explicit pixels: `[1-9][0-9]{0,9}x[1-9][0-9]{0,9}` with a
        // lowercase `x`.
        let (w_str, h_str) = text.split_once('x')?;
        // Reject uppercase X.
        if text.contains('X') {
            return None;
        }
        if !is_canonical_dim(w_str) || !is_canonical_dim(h_str) {
            return None;
        }
        let width: u32 = w_str.parse().ok()?;
        let height: u32 = h_str.parse().ok()?;
        let product = (width as u64).checked_mul(height as u64)?;
        Some(Self::Pixels {
            width,
            height,
            product,
        })
    }

    /// Returns the canonical pixel string for explicit pixels, or the tier
    /// token.
    pub fn as_str(&self) -> String {
        match self {
            Self::Tier(t) => (*t).to_string(),
            Self::Pixels { width, height, .. } => format!("{width}x{height}"),
        }
    }
}

fn is_canonical_dim(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_digit() && b != b'0' => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_digit()) && s.len() <= 10
}

// ---------------------------------------------------------------------------
// Routing policy.
// ---------------------------------------------------------------------------

/// Scalar sort policy. Object sort forms are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortPolicy {
    Price,
    Throughput,
    Latency,
}

impl SortPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Price => "price",
            Self::Throughput => "throughput",
            Self::Latency => "latency",
        }
    }
}

/// The closed initial routing policy. `deny_unknown_fields` rejects arbitrary
/// `provider.options`, unknown routing keys, and provider passthrough.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingPolicy {
    /// Retain only endpoints whose non-null tag is named (excluding null-tag
    /// endpoints). Order is semantic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only: Vec<String>,
    /// Remove all endpoints in each named tag group, leaving null-tag
    /// endpoints eligible. Order is semantic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<String>,
    /// Preserve the relative priority of the one-to-many tag groups named by
    /// `order` without excluding unlisted or null-tag endpoints. Order is
    /// semantic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order: Vec<String>,
    /// Scalar sort policy. Object sort forms are rejected at parse time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<SortPolicy>,
    /// With `true`, every eligible endpoint is selectable. With `false`,
    /// reservation still covers every endpoint that could be primary.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_fallbacks: bool,
}

/// Validate a routing policy against discovered endpoint tags. Returns the
/// ordered eligible tag groups after applying `only`, `ignore`, and `order`.
pub fn validate_routing_policy(
    policy: &RoutingPolicy,
    endpoint_tags: &[Option<String>],
) -> Result<RoutingDecision, RoutingError> {
    // Reject duplicate entries within each configured list.
    for list in [&policy.only, &policy.ignore, &policy.order] {
        let mut seen = std::collections::BTreeSet::new();
        for name in list {
            if !seen.insert(name.clone()) {
                return Err(RoutingError::DuplicateConfiguredEntry);
            }
        }
    }
    // Validate discovered tags: reject a non-null tag with empty content,
    // leading/trailing whitespace, or ASCII controls.
    let mut valid_tags: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for t in endpoint_tags.iter().flatten() {
        if t.is_empty() || t != t.trim() || t.bytes().any(|b| b.is_ascii_control()) {
            return Err(RoutingError::InvalidDiscoveredTag);
        }
        valid_tags.insert(t.clone());
    }
    // Reject unknown names in only/ignore/order.
    for list in [&policy.only, &policy.ignore, &policy.order] {
        for name in list {
            if !valid_tags.contains(name) {
                return Err(RoutingError::UnknownName);
            }
        }
    }
    // Contradiction: a name in both only and ignore.
    for name in &policy.only {
        if policy.ignore.contains(name) {
            return Err(RoutingError::Contradiction);
        }
    }
    // Apply only: retain every endpoint whose non-null tag is named.
    let mut eligible: Vec<usize> = endpoint_tags
        .iter()
        .enumerate()
        .filter(|(_, tag)| {
            tag.as_ref()
                .is_some_and(|t| policy.only.iter().any(|n| n == t))
        })
        .map(|(i, _)| i)
        .collect();
    if !policy.only.is_empty() && eligible.is_empty() {
        return Err(RoutingError::EmptyEligibleSet);
    }
    // If only is empty, every endpoint is initially eligible (including
    // null-tag endpoints).
    if policy.only.is_empty() {
        eligible = (0..endpoint_tags.len()).collect();
    }
    // Apply ignore: remove all endpoints in each named tag group, leaving
    // null-tag endpoints eligible.
    if !policy.ignore.is_empty() {
        eligible.retain(|i| {
            endpoint_tags[*i]
                .as_ref()
                .is_none_or(|t| !policy.ignore.iter().any(|n| n == t))
        });
    }
    // Reject names in order made ineligible by only/ignore.
    for name in &policy.order {
        let any_eligible = eligible
            .iter()
            .any(|i| endpoint_tags[*i].as_ref().is_some_and(|t| t == name));
        if !any_eligible {
            // The name is a valid tag but no eligible endpoint carries it.
            return Err(RoutingError::OrderNameIneligible);
        }
    }
    if eligible.is_empty() {
        return Err(RoutingError::EmptyEligibleSet);
    }
    // Apply order: preserve the relative priority of the one-to-many tag
    // groups named by order without excluding unlisted or null-tag endpoints.
    let mut ordered: Vec<usize> = Vec::new();
    if !policy.order.is_empty() {
        for name in &policy.order {
            for &i in &eligible {
                if endpoint_tags[i].as_ref().is_some_and(|t| t == name) {
                    ordered.push(i);
                }
            }
        }
        // Append remaining eligible endpoints (unlisted or null-tag) preserving
        // their relative order.
        for &i in &eligible {
            if !ordered.contains(&i) {
                ordered.push(i);
            }
        }
    } else {
        ordered = eligible.clone();
    }
    Ok(RoutingDecision {
        eligible_indices: ordered,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingDecision {
    pub eligible_indices: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    DuplicateConfiguredEntry,
    UnknownName,
    Contradiction,
    OrderNameIneligible,
    EmptyEligibleSet,
    InvalidDiscoveredTag,
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateConfiguredEntry => write!(f, "duplicate configured routing entry"),
            Self::UnknownName => write!(f, "unknown routing name"),
            Self::Contradiction => write!(f, "contradictory only/ignore routing"),
            Self::OrderNameIneligible => write!(f, "order names an ineligible tag"),
            Self::EmptyEligibleSet => write!(f, "routing produces an empty eligible set"),
            Self::InvalidDiscoveredTag => write!(f, "invalid discovered provider tag"),
        }
    }
}

impl std::error::Error for RoutingError {}

// ---------------------------------------------------------------------------
// Discovery model and endpoint records.
// ---------------------------------------------------------------------------

/// A discovered image model from `GET /api/v1/images/models`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredModel {
    pub id: String,
    pub name: Option<String>,
    pub supported_parameters: Vec<String>,
    pub modalities: Option<DiscoveredModalities>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredModalities {
    #[serde(default)]
    pub input: Vec<String>,
    #[serde(default)]
    pub output: Vec<String>,
}

/// A discovered endpoint record from the model's endpoint link. Each endpoint
/// carries its own capability and pricing records; the model-level aggregate
/// is only a hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    pub provider_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_slug: Option<String>,
    #[serde(default)]
    pub supported_parameters: Vec<String>,
    #[serde(default)]
    pub pricing: Option<EndpointPricing>,
    #[serde(default)]
    pub n: Option<EndpointNCap>,
    #[serde(default)]
    pub seed: Option<bool>,
    #[serde(default)]
    pub resolution: Vec<String>,
    #[serde(default)]
    pub aspect_ratio: Vec<String>,
    #[serde(default)]
    pub size: Vec<SizeDescriptor>,
    #[serde(default)]
    pub input_references: Option<EndpointReferenceCap>,
}

/// A `size` enum descriptor advertised by an endpoint. The current live
/// records advertise no such descriptor, so explicit pixels are unavailable
/// against those records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeDescriptor {
    pub canonical: String,
}

/// Endpoint `n` capability descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointNCap {
    pub max: u8,
}

/// Endpoint input-reference capability descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointReferenceCap {
    #[serde(default)]
    pub max_count: Option<u16>,
    #[serde(default)]
    pub max_bytes_per_reference: Option<u64>,
    #[serde(default)]
    pub max_aggregate_bytes: Option<u64>,
}

/// Endpoint pricing record. Each billable line is parsed from the JSON
/// number's lexical decimal form with checked arithmetic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointPricing {
    #[serde(default)]
    pub prompt: Option<CostLine>,
    #[serde(default)]
    pub image_request: Option<CostLine>,
    #[serde(default)]
    pub image_output: Option<CostLine>,
    #[serde(default)]
    pub image_megapixel: Option<CostLine>,
    #[serde(default)]
    pub variants: Vec<PricingVariant>,
}

/// A single billable cost line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostLine {
    /// The unit price as a lexical decimal string (e.g. "0.000001").
    pub cost_usd: String,
    /// The billing unit (e.g. "image", "megapixel", "token").
    #[serde(default)]
    pub unit: Option<String>,
}

/// A named pricing variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingVariant {
    pub name: String,
    pub cost_usd: String,
    #[serde(default)]
    pub unit: Option<String>,
}

/// Discovery provenance for freshness tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryProvenance {
    Live,
    Stale,
    Unknown,
}

// ---------------------------------------------------------------------------
// Canonical endpoint identity and duplicate-record rejection.
// ---------------------------------------------------------------------------

/// Canonical endpoint evidence identity: `(provider_tag, provider_slug,
/// endpoint_record_digest)`. Used for stable hashing and duplicate detection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointIdentity {
    pub provider_tag: Option<String>,
    pub provider_slug: Option<String>,
    pub record_digest: String,
}

/// Compute the canonical endpoint record digest over the sorted evidence.
pub fn endpoint_record_digest(endpoint: &DiscoveredEndpoint) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"openrouter-endpoint-v1\0");
    hasher.update(endpoint.provider_tag.as_deref().unwrap_or("\0").as_bytes());
    hasher.update(b"\0");
    hasher.update(endpoint.provider_slug.as_deref().unwrap_or("\0").as_bytes());
    hasher.update(b"\0");
    let mut params = endpoint.supported_parameters.clone();
    params.sort();
    for p in &params {
        hasher.update(p.as_bytes());
        hasher.update(b"\0");
    }
    let mut resolution = endpoint.resolution.clone();
    resolution.sort();
    for r in &resolution {
        hasher.update(r.as_bytes());
        hasher.update(b"\0");
    }
    let mut aspect = endpoint.aspect_ratio.clone();
    aspect.sort();
    for a in &aspect {
        hasher.update(a.as_bytes());
        hasher.update(b"\0");
    }
    for s in &endpoint.size {
        hasher.update(s.canonical.as_bytes());
        hasher.update(b"\0");
    }
    if let Some(n) = &endpoint.n {
        hasher.update([n.max]);
        hasher.update(b"\0");
    }
    if let Some(seed) = endpoint.seed {
        hasher.update([seed as u8]);
        hasher.update(b"\0");
    }
    if let Some(refs) = &endpoint.input_references {
        if let Some(c) = refs.max_count {
            hasher.update(c.to_be_bytes());
        }
        if let Some(b) = refs.max_bytes_per_reference {
            hasher.update(b.to_be_bytes());
        }
        if let Some(a) = refs.max_aggregate_bytes {
            hasher.update(a.to_be_bytes());
        }
    }
    crate::intel::hex_lower(&hasher.finalize())
}

/// Compute the canonical endpoint identity for evidence ordering and duplicate
/// detection.
pub fn endpoint_identity(endpoint: &DiscoveredEndpoint) -> EndpointIdentity {
    EndpointIdentity {
        provider_tag: endpoint.provider_tag.clone(),
        provider_slug: endpoint.provider_slug.clone(),
        record_digest: endpoint_record_digest(endpoint),
    }
}

/// Reject duplicate canonical endpoint identities/records, not repeated tags.
/// Distinct records sharing one valid tag are preserved.
pub fn reject_duplicate_identities(
    endpoints: &[DiscoveredEndpoint],
) -> Result<Vec<EndpointIdentity>, DuplicateEndpointError> {
    let mut seen = std::collections::HashSet::new();
    let mut identities = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let identity = endpoint_identity(endpoint);
        if !seen.insert(identity.clone()) {
            return Err(DuplicateEndpointError);
        }
        identities.push(identity);
    }
    Ok(identities)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateEndpointError;

impl fmt::Display for DuplicateEndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "duplicate canonical endpoint identity/record")
    }
}

impl std::error::Error for DuplicateEndpointError {}

// ---------------------------------------------------------------------------
// Closed request DTO.
// ---------------------------------------------------------------------------

/// An input reference built from an already-authorized typed attachment. Each
/// reference is exactly `{ type: "image_url", image_url: { url: <data URL> } }`.
/// Cockpit never accepts or emits an agent-supplied remote URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputReference {
    pub mime_type: String,
    pub base64_bytes: Vec<u8>,
}

impl InputReference {
    /// Build the canonical data URL for this reference.
    pub fn data_url(&self) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.base64_bytes);
        format!("data:{};base64,{}", self.mime_type, encoded)
    }

    /// Construct the wire JSON object for this reference.
    pub fn wire_object(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "image_url",
            "image_url": { "url": self.data_url() }
        })
    }
}

/// The closed initial request DTO. `deny_unknown_fields` rejects unknown
/// request fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenrouterImageRequest {
    pub model: String,
    pub prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aspect_ratio: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_compression: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
    #[serde(default = "default_n", skip_serializing_if = "is_default_n")]
    pub n: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_references: Vec<InputReferenceWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<RoutingPolicy>,
}

fn default_n() -> u8 {
    1
}
fn is_default_n(n: &u8) -> bool {
    *n == 1
}

/// Wire representation of an input reference, matching
/// `{ type: "image_url", image_url: { url: <data URL> } }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputReferenceWire {
    #[serde(rename = "type")]
    pub kind: String,
    pub image_url: InputReferenceImageUrl,
}

impl InputReferenceWire {
    /// Construct from a validated `InputReference`.
    pub fn from_reference(reference: &InputReference) -> Self {
        Self {
            kind: "image_url".to_string(),
            image_url: InputReferenceImageUrl {
                url: reference.data_url(),
            },
        }
    }

    /// Validate that this is a canonical data URL reference, not a remote URL.
    pub fn validate(&self) -> Result<(), ReferenceError> {
        if self.kind != "image_url" {
            return Err(ReferenceError::WrongType);
        }
        if !self.image_url.url.starts_with("data:") {
            return Err(ReferenceError::RemoteUrl);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputReferenceImageUrl {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceError {
    WrongType,
    RemoteUrl,
    Oversized,
    UnknownLimit,
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongType => write!(f, "reference type is not image_url"),
            Self::RemoteUrl => write!(f, "remote reference URLs are not accepted"),
            Self::Oversized => write!(f, "reference exceeds byte bound"),
            Self::UnknownLimit => write!(f, "reference limit is unknown or unparseable"),
        }
    }
}

impl std::error::Error for ReferenceError {}

// ---------------------------------------------------------------------------
// Parameter intersection and preflight validation.
// ---------------------------------------------------------------------------

/// The strict intersection of a parameter/value across every possible
/// endpoint. A request is available only when the requested parameter/value is
/// in the strict intersection across every endpoint OpenRouter could select.
pub fn parameter_intersection(
    endpoints: &[DiscoveredEndpoint],
    extract: impl Fn(&DiscoveredEndpoint) -> Vec<String>,
) -> Vec<String> {
    if endpoints.is_empty() {
        return Vec::new();
    }
    let mut iter = endpoints.iter().map(&extract);
    let first: std::collections::BTreeSet<String> = iter.next().unwrap().into_iter().collect();
    iter.fold(first, |acc, vals| {
        acc.intersection(&vals.into_iter().collect())
            .cloned()
            .collect()
    })
    .into_iter()
    .collect()
}

/// Preflight validation outcome for a request against discovered endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightOutcome {
    Accept,
    Reject(PreflightReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightReason {
    InvalidModelId,
    ResolutionNotInEveryEndpoint,
    AspectNotInEveryEndpoint,
    TierSizeNotInEveryResolution,
    ExplicitPixelsNoSizeDescriptor,
    ExplicitPixelsPlusResolution,
    AspectInconsistentWithPixels,
    NOutOfRange,
    NAboveEndpointCap,
    SeedUnavailable,
    SeedNonInteger,
    UnsupportedParameter,
    ReferencesUnavailable,
    ReferenceOversized,
    UnknownLimit,
}

/// Run preflight validation of a request against the strict intersection of
/// every possible endpoint's capabilities. Fails closed before dispatch.
pub fn preflight(
    request: &OpenrouterImageRequest,
    endpoints: &[DiscoveredEndpoint],
) -> PreflightOutcome {
    // Model ID must be exactly two nonempty path segments.
    if ModelId::parse(&request.model).is_none() {
        return PreflightOutcome::Reject(PreflightReason::InvalidModelId);
    }
    // n must be 1 through 10.
    if request.n < MIN_N || request.n > MAX_N {
        return PreflightOutcome::Reject(PreflightReason::NOutOfRange);
    }
    // n must not exceed any possible endpoint's discovered maximum.
    for endpoint in endpoints {
        if let Some(cap) = &endpoint.n
            && request.n > cap.max
        {
            return PreflightOutcome::Reject(PreflightReason::NAboveEndpointCap);
        }
    }
    // resolution must be advertised by every possible endpoint.
    if let Some(res) = &request.resolution {
        let intersection = parameter_intersection(endpoints, |e| e.resolution.clone());
        if !intersection.iter().any(|r| r == res) {
            return PreflightOutcome::Reject(PreflightReason::ResolutionNotInEveryEndpoint);
        }
    }
    // aspect_ratio must be advertised by every possible endpoint (when set).
    if let Some(aspect) = &request.aspect_ratio {
        let intersection = parameter_intersection(endpoints, |e| e.aspect_ratio.clone());
        if !intersection.iter().any(|a| a == aspect) {
            return PreflightOutcome::Reject(PreflightReason::AspectNotInEveryEndpoint);
        }
    }
    // size validation.
    if let Some(size_text) = &request.size {
        let size_value = match SizeValue::parse(size_text) {
            Some(v) => v,
            None => {
                return PreflightOutcome::Reject(PreflightReason::UnsupportedParameter);
            }
        };
        match size_value {
            SizeValue::Tier(tier) => {
                // A tier size is a wire-level alias for resolution: authorized
                // only when that exact tier appears in every possible
                // endpoint's resolution enum.
                let intersection = parameter_intersection(endpoints, |e| e.resolution.clone());
                if !intersection.iter().any(|r| r == tier) {
                    return PreflightOutcome::Reject(PreflightReason::TierSizeNotInEveryResolution);
                }
                // A tier may combine only with an independently supported
                // aspect_ratio. explicit pixels plus resolution always fails.
                if request.resolution.is_some() {
                    return PreflightOutcome::Reject(PreflightReason::ExplicitPixelsPlusResolution);
                }
            }
            SizeValue::Pixels { width, height, .. } => {
                // Explicit-pixel size is authorized only when every possible
                // endpoint advertises that exact canonical pixel string in a
                // size enum descriptor. The current live records advertise no
                // such descriptor.
                let intersection = parameter_intersection(endpoints, |e| {
                    e.size
                        .iter()
                        .map(|d| d.canonical.clone())
                        .collect::<Vec<_>>()
                });
                let canonical = format!("{width}x{height}");
                if !intersection.contains(&canonical) {
                    return PreflightOutcome::Reject(
                        PreflightReason::ExplicitPixelsNoSizeDescriptor,
                    );
                }
                // Explicit pixels plus resolution always fails closed.
                if request.resolution.is_some() {
                    return PreflightOutcome::Reject(PreflightReason::ExplicitPixelsPlusResolution);
                }
                // Explicit pixels plus a non-auto aspect ratio must be
                // consistent: ratio supported by every endpoint and matches
                // via exact-rational cross multiplication.
                if let Some(aspect) = &request.aspect_ratio {
                    if aspect == "auto" {
                        return PreflightOutcome::Reject(
                            PreflightReason::AspectInconsistentWithPixels,
                        );
                    }
                    let ratio = match ExactRatio::parse(aspect) {
                        Some(r) => r,
                        None => {
                            return PreflightOutcome::Reject(
                                PreflightReason::AspectInconsistentWithPixels,
                            );
                        }
                    };
                    if !ratio.matches_pixels(width as u64, height as u64) {
                        return PreflightOutcome::Reject(
                            PreflightReason::AspectInconsistentWithPixels,
                        );
                    }
                    let aspect_intersection =
                        parameter_intersection(endpoints, |e| e.aspect_ratio.clone());
                    if !aspect_intersection.iter().any(|a| a == aspect) {
                        return PreflightOutcome::Reject(PreflightReason::AspectNotInEveryEndpoint);
                    }
                }
            }
        }
    } else if request.resolution.is_some() && request.aspect_ratio.is_some() {
        // No size, but both resolution and aspect: aspect must still be in
        // every endpoint (already checked above). This is the resolution-only
        // + aspect combination, which is allowed.
    }
    // seed: integer request field available only when every possible endpoint
    // advertises the boolean seed capability descriptor.
    if request.seed.is_some() && !endpoints.iter().all(|e| e.seed == Some(true)) {
        return PreflightOutcome::Reject(PreflightReason::SeedUnavailable);
    }
    // input_references: availability and count limited by image input
    // modality, model record, every possible endpoint, target policy,
    // per-reference bounds, and aggregate request bounds. An absent or
    // unparseable limit makes references unavailable.
    if !request.input_references.is_empty() {
        for endpoint in endpoints {
            let cap = match &endpoint.input_references {
                Some(c) => c,
                None => return PreflightOutcome::Reject(PreflightReason::UnknownLimit),
            };
            let max_count = match cap.max_count {
                Some(c) => c,
                None => return PreflightOutcome::Reject(PreflightReason::UnknownLimit),
            };
            if request.input_references.len() > max_count as usize {
                return PreflightOutcome::Reject(PreflightReason::ReferencesUnavailable);
            }
            let max_per = match cap.max_bytes_per_reference {
                Some(b) => b as usize,
                None => return PreflightOutcome::Reject(PreflightReason::UnknownLimit),
            };
            let max_agg = match cap.max_aggregate_bytes {
                Some(b) => b as usize,
                None => return PreflightOutcome::Reject(PreflightReason::UnknownLimit),
            };
            let mut total = 0usize;
            for reference in &request.input_references {
                if let Err(ReferenceError::RemoteUrl) | Err(ReferenceError::WrongType) =
                    reference.validate()
                {
                    return PreflightOutcome::Reject(PreflightReason::ReferencesUnavailable);
                }
                // Decode the data URL to check byte bounds.
                let bytes = decode_data_url_bytes(&reference.image_url.url);
                let bytes = match bytes {
                    Some(b) => b,
                    None => {
                        return PreflightOutcome::Reject(PreflightReason::ReferencesUnavailable);
                    }
                };
                if bytes.len() > max_per.min(MAX_PER_REFERENCE_BYTES) {
                    return PreflightOutcome::Reject(PreflightReason::ReferenceOversized);
                }
                total = match total.checked_add(bytes.len()) {
                    Some(t) => t,
                    None => return PreflightOutcome::Reject(PreflightReason::ReferenceOversized),
                };
            }
            if total > max_agg.min(MAX_AGGREGATE_REFERENCE_BYTES) {
                return PreflightOutcome::Reject(PreflightReason::ReferenceOversized);
            }
        }
    }
    PreflightOutcome::Accept
}

/// Decode bytes from a `data:{mime};base64,{payload}` data URL.
pub fn decode_data_url_bytes(url: &str) -> Option<Vec<u8>> {
    let payload = url.strip_prefix("data:")?;
    let payload = payload.split_once(';')?.1;
    let payload = payload.strip_prefix("base64,")?;
    base64::engine::general_purpose::STANDARD
        .decode(payload)
        .ok()
}

// ---------------------------------------------------------------------------
// Pricing: additive billable lines and conservative spend calculation.
// ---------------------------------------------------------------------------

/// Compute the conservative maximum cost in microdollars for a single endpoint
/// given the exact request. Returns `None` when the maximum is unknown.
pub fn endpoint_max_microdollars(
    endpoint: &DiscoveredEndpoint,
    request: &OpenrouterImageRequest,
) -> Option<u128> {
    let pricing = endpoint.pricing.as_ref()?;
    let mut total = CheckedMicrodollars::from_micros(0);
    // Prompt/text billable line (token-priced input without a proven finite
    // token maximum makes the maximum unknown).
    if let Some(line) = &pricing.prompt {
        let unit = line.unit.as_deref().unwrap_or("");
        if unit == "token" {
            // No proven finite token maximum in the initial contract.
            return None;
        }
        let price = CheckedMicrodollars::from_lexical_decimal(&line.cost_usd)?;
        total = total.checked_add(&price)?;
    }
    // Each input reference.
    if let Some(line) = &pricing.image_request {
        let price = CheckedMicrodollars::from_lexical_decimal(&line.cost_usd)?;
        let count = request.input_references.len() as u128;
        let line_total = price.checked_mul_count(count)?;
        total = total.checked_add(&line_total)?;
    }
    // Each output (image count).
    if let Some(line) = &pricing.image_output {
        let price = CheckedMicrodollars::from_lexical_decimal(&line.cost_usd)?;
        let count = request.n as u128;
        let line_total = price.checked_mul_count(count)?;
        total = total.checked_add(&line_total)?;
    }
    // Exact pixel/megapixel rational quantity. Explicit pixels use checked
    // width*height/1_000_000. A tier or omitted dimension cannot be assigned a
    // megapixel quantity without documented exact endpoint mapping.
    if let Some(line) = &pricing.image_megapixel {
        let megapixels = explicit_pixel_megapixels(request)?;
        let price = CheckedMicrodollars::from_lexical_decimal(&line.cost_usd)?;
        let line_total = price.checked_mul_count(megapixels)?;
        total = total.checked_add(&line_total)?;
    }
    // Exact selected variant where the record defines variants.
    if !pricing.variants.is_empty() {
        // Variants require a selected variant name in the request, which the
        // closed initial DTO does not carry; missing/ambiguous variants make
        // the maximum unknown.
        return None;
    }
    ceiling_microdollars(&total)
}

/// Compute the exact megapixel quantity for explicit pixels using checked
/// `width * height / 1_000_000` (ceiling). Returns `None` when the request
/// does not use explicit pixels (tier or omitted dimension).
pub fn explicit_pixel_megapixels(request: &OpenrouterImageRequest) -> Option<u128> {
    let size_text = request.size.as_ref()?;
    let size = SizeValue::parse(size_text)?;
    match size {
        SizeValue::Pixels { product, .. } => {
            // Megapixels are width*height / 1_000_000, rounded up (ceiling).
            let count = product.div_ceil(1_000_000);
            Some(count as u128)
        }
        SizeValue::Tier(_) => None,
    }
}

/// Plan maximum: the greatest known endpoint maximum. If any possible endpoint
/// is unknown, finite-budget authorization blocks.
pub fn plan_max_microdollars(
    endpoints: &[DiscoveredEndpoint],
    request: &OpenrouterImageRequest,
) -> PlanMax {
    let mut max: Option<u128> = None;
    let mut any_unknown = false;
    for endpoint in endpoints {
        match endpoint_max_microdollars(endpoint, request) {
            Some(m) => {
                max = Some(max.map_or(m, |prev| prev.max(m)));
            }
            None => {
                any_unknown = true;
            }
        }
    }
    if any_unknown {
        PlanMax::Unknown
    } else {
        match max {
            Some(m) => PlanMax::Known(m),
            None => PlanMax::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanMax {
    Known(u128),
    Unknown,
}

impl PlanMax {
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

// ---------------------------------------------------------------------------
// Response parsing: bounded data[].b64_json, optional media_type, usage.
// ---------------------------------------------------------------------------

/// Bounded parsed image generation response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedImageResponse {
    pub outputs: Vec<ParsedOutput>,
    pub usage: ParsedUsage,
}

/// A single parsed output slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedOutput {
    pub bytes: Vec<u8>,
    pub media_type: String,
}

/// Parsed usage. `cost` is authoritative when present as a valid nonnegative
/// JSON number; absent/wrong-typed/negative/overflowing cost is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUsage {
    pub cost: Option<u128>,
}

/// Parse a bounded response body. Canonically detects bytes first. A present
/// `media_type` must match detection; an absent `media_type` is accepted only
/// when canonical detection identifies an allowed format. Raster formats pass
/// canonical validation; `image/svg+xml` additionally passes the closed SVG
/// sanitizer before retention.
pub fn parse_response(body: &[u8]) -> Result<ParsedImageResponse, ResponseParseError> {
    if body.len() > MAX_OUTPUT_BASE64_BYTES + MAX_USAGE_METADATA_BYTES + 1024 {
        return Err(ResponseParseError::OversizedResponse);
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| ResponseParseError::InvalidJson)?;
    let data = value
        .get("data")
        .ok_or(ResponseParseError::MissingData)?
        .as_array()
        .ok_or(ResponseParseError::MissingData)?;
    if data.is_empty() {
        return Err(ResponseParseError::MissingOutputs);
    }
    let mut outputs = Vec::with_capacity(data.len());
    for item in data {
        let b64 = item
            .get("b64_json")
            .ok_or(ResponseParseError::MissingB64Json)?
            .as_str()
            .ok_or(ResponseParseError::InvalidB64Json)?;
        if b64.len() > MAX_OUTPUT_BASE64_BYTES {
            return Err(ResponseParseError::OversizedOutput);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| ResponseParseError::InvalidB64Json)?;
        // Canonically detect bytes first.
        let detected =
            canonical_detect_media_type(&bytes).ok_or(ResponseParseError::UndetectableBytes)?;
        // A present media_type must match detection.
        if let Some(media) = item.get("media_type").and_then(|v| v.as_str())
            && media != detected
        {
            return Err(ResponseParseError::MediaTypeConflict);
        }
        // Raster formats pass canonical validation. SVG is sanitized once and
        // the sanitizer's CANONICAL output is retained in place of the raw
        // provider bytes: the sanitizer transforms (strips a leading XML
        // declaration, comments, and any non-canonical form), so retaining the
        // raw bytes would leak un-sanitized content past the boundary. Never
        // sanitize-then-discard.
        let bytes = if detected == "image/svg+xml" {
            crate::generated_svg::sanitize_generated_svg(&bytes)
                .map_err(|_| ResponseParseError::SvgSanitizationFailed)?
                .into_bytes()
        } else {
            bytes
        };
        outputs.push(ParsedOutput {
            bytes,
            media_type: detected,
        });
    }
    // Parse optional bounded usage.
    let usage = parse_usage(value.get("usage"))?;
    Ok(ParsedImageResponse { outputs, usage })
}

/// Parse the optional `usage` object. `usage.cost` when present as a valid
/// nonnegative JSON number is authoritative.
pub fn parse_usage(usage: Option<&serde_json::Value>) -> Result<ParsedUsage, ResponseParseError> {
    let Some(usage) = usage else {
        return Ok(ParsedUsage { cost: None });
    };
    let Some(usage_obj) = usage.as_object() else {
        return Ok(ParsedUsage { cost: None });
    };
    if let Some(cost) = usage_obj.get("cost") {
        match cost {
            serde_json::Value::Number(n) => {
                let text = n.to_string();
                let micros = CheckedMicrodollars::from_lexical_decimal(&text)
                    .ok_or(ResponseParseError::InvalidUsageCost)?;
                Ok(ParsedUsage {
                    cost: Some(micros.as_micros()),
                })
            }
            _ => Err(ResponseParseError::InvalidUsageCost),
        }
    } else {
        Ok(ParsedUsage { cost: None })
    }
}

/// Canonically detect the media type of image bytes by sniffing magic bytes.
/// Never trusts a declared MIME. Returns the canonical allowed MIME type.
pub fn canonical_detect_media_type(bytes: &[u8]) -> Option<String> {
    // SVG detection: XML/SVG root element.
    if bytes.starts_with(b"<?xml") || bytes.starts_with(b"<svg") || bytes.starts_with(b"<!--") {
        let text = std::str::from_utf8(bytes).ok()?;
        if text.contains("<svg") {
            return Some("image/svg+xml".to_string());
        }
        return None;
    }
    // Raster detection via image crate.
    let format = image::guess_format(bytes).ok()?;
    match format {
        image::ImageFormat::Png => Some("image/png".to_string()),
        image::ImageFormat::Jpeg => Some("image/jpeg".to_string()),
        image::ImageFormat::WebP => Some("image/webp".to_string()),
        image::ImageFormat::Gif => Some("image/gif".to_string()),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseParseError {
    OversizedResponse,
    InvalidJson,
    MissingData,
    MissingOutputs,
    MissingB64Json,
    InvalidB64Json,
    OversizedOutput,
    UndetectableBytes,
    MediaTypeConflict,
    SvgSanitizationFailed,
    InvalidUsageCost,
    OversizedUsage,
}

impl fmt::Display for ResponseParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OversizedResponse => write!(f, "response exceeds bounded size"),
            Self::InvalidJson => write!(f, "response is not valid JSON"),
            Self::MissingData => write!(f, "response missing data array"),
            Self::MissingOutputs => write!(f, "response has no outputs"),
            Self::MissingB64Json => write!(f, "output missing b64_json"),
            Self::InvalidB64Json => write!(f, "output b64_json is invalid"),
            Self::OversizedOutput => write!(f, "output exceeds bounded size"),
            Self::UndetectableBytes => {
                write!(f, "output bytes undetectable with absent media type")
            }
            Self::MediaTypeConflict => write!(f, "present media type conflicts with detection"),
            Self::SvgSanitizationFailed => write!(f, "SVG sanitization failed"),
            Self::InvalidUsageCost => write!(f, "usage cost is invalid"),
            Self::OversizedUsage => write!(f, "usage metadata exceeds bounded size"),
        }
    }
}

impl std::error::Error for ResponseParseError {}

// ---------------------------------------------------------------------------
// Attribution headers (reuses the shared openrouter-attribution contract).
// ---------------------------------------------------------------------------
//
// The canonical `HTTP-Referer` / `X-OpenRouter-Title` pair and the collision-safe
// merge live in `crate::providers::openrouter_attribution`. This adapter does
// NOT define its own attribution constants; it calls the shared helper so
// rotating the referer URL or title stays in sync with chat/catalog.

/// Validate provider-supplied header overrides before building a request
/// description. Names must be valid HTTP header names; non-empty values must
/// be valid HTTP header values; duplicate names (case-insensitive) are
/// rejected. Empty values are valid suppression markers (they suppress the
/// matching attribution default). Invalid headers fail before building a
/// description with a stable redacted error — no secret value is surfaced.
fn validate_provider_header_overrides(
    provider_headers: &[(String, String)],
) -> Result<(), RuntimeError> {
    let mut names = std::collections::BTreeSet::new();
    for (name, value) in provider_headers {
        let normalized = name.to_ascii_lowercase();
        if !names.insert(normalized)
            || reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err()
            || (!value.is_empty() && reqwest::header::HeaderValue::from_str(value).is_err())
        {
            return Err(RuntimeError::InvalidHeaders);
        }
    }
    Ok(())
}

/// The single attribution-enforcing constructor for this adapter.
///
/// All three request builders ([`build_submit_request`],
/// [`build_discovery_request`], [`build_endpoint_request`]) route their
/// header assembly through this function. It is the **only** call site of
/// the shared `merge_openrouter_attribution_pairs` helper in the adapter, and
/// it gates on the resolved provider origin: attribution is merged **only**
/// when `provider_origin` is `ResolvedProviderOrigin::Template("openrouter")`.
///
/// Identity is decided here, not at the merger: a non-template origin (e.g. a
/// custom OpenAI-compatible endpoint, or a special provider like Codex/Copilot
/// that happens to share the OpenRouter image base URL) gets no OpenRouter
/// attribution headers. This matches the chat/catalog gate in `models_fetch`
/// (`origin.is_template("openrouter")`).
fn apply_openrouter_attribution(
    provider_origin: &ResolvedProviderOrigin,
    headers: &mut Vec<(String, String)>,
) {
    if provider_origin.is_template("openrouter") {
        crate::providers::openrouter_attribution::merge_openrouter_attribution_pairs(headers);
    }
}

/// Build the canonical `POST /api/v1/images` submission request description
/// for the configured origin. Non-streaming; no `/images/generations`,
/// Responses, Chat, server-tool, streaming, remote-output URL, or
/// active-model fallback path.
///
/// `provider_headers` carries validated user/provider header overrides. The
/// canonical OpenRouter attribution pair is merged collision-safe via the
/// shared helper: a non-empty override wins; an empty override suppresses
/// that header; a missing header gets the canonical default.
///
/// Attribution is applied **only** when `provider_origin` is
/// `ResolvedProviderOrigin::Template("openrouter")`, matching the chat/catalog
/// identity gate in `models_fetch`. A non-template origin gets no OpenRouter
/// attribution headers.
pub(crate) fn build_submit_request(
    origin: &str,
    provider_origin: &ResolvedProviderOrigin,
    request: &OpenrouterImageRequest,
    provider_headers: &[(String, String)],
) -> Result<SubmitRequestDescription, RuntimeError> {
    validate_provider_header_overrides(provider_headers)?;
    let origin = origin.trim_end_matches('/');
    let url = format!("{origin}{SUBMIT_PATH}");
    let body = serde_json::to_value(request).map_err(|_| RuntimeError::Serialization)?;
    let mut headers: Vec<(String, String)> = provider_headers
        .iter()
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    apply_openrouter_attribution(provider_origin, &mut headers);
    Ok(SubmitRequestDescription {
        url,
        method: "POST".to_string(),
        body,
        streaming: false,
        headers,
    })
}

/// Build the canonical `GET /api/v1/images/models` discovery request
/// description.
///
/// `provider_headers` carries validated user/provider header overrides; the
/// canonical attribution pair is merged via the shared helper when
/// `provider_origin` is `ResolvedProviderOrigin::Template("openrouter")`.
#[allow(dead_code)]
pub(crate) fn build_discovery_request(
    origin: &str,
    provider_origin: &ResolvedProviderOrigin,
    provider_headers: &[(String, String)],
) -> Result<DiscoveryRequestDescription, RuntimeError> {
    validate_provider_header_overrides(provider_headers)?;
    let origin = origin.trim_end_matches('/');
    let url = format!("{origin}{DISCOVERY_MODELS_PATH}");
    let mut headers: Vec<(String, String)> = provider_headers
        .iter()
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    apply_openrouter_attribution(provider_origin, &mut headers);
    Ok(DiscoveryRequestDescription {
        url,
        method: "GET".to_string(),
        streaming: false,
        headers,
    })
}

/// Build the canonical same-origin endpoint follow-up request description for
/// a selected model.
///
/// `provider_headers` carries validated user/provider header overrides; the
/// canonical attribution pair is merged via the shared helper when
/// `provider_origin` is `ResolvedProviderOrigin::Template("openrouter")`.
#[allow(dead_code)]
pub(crate) fn build_endpoint_request(
    origin: &str,
    provider_origin: &ResolvedProviderOrigin,
    model: &ModelId,
    provider_headers: &[(String, String)],
) -> Result<EndpointRequestDescription, RuntimeError> {
    validate_provider_header_overrides(provider_headers)?;
    let origin = origin.trim_end_matches('/');
    let url = format!("{}{}", origin, model.endpoint_link());
    let mut headers: Vec<(String, String)> = provider_headers
        .iter()
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    apply_openrouter_attribution(provider_origin, &mut headers);
    Ok(EndpointRequestDescription {
        url,
        method: "GET".to_string(),
        streaming: false,
        headers,
    })
}

/// Read-only request description for `POST /api/v1/images`.
#[derive(Debug, Clone)]
pub struct SubmitRequestDescription {
    pub url: String,
    pub method: String,
    pub body: serde_json::Value,
    pub streaming: bool,
    pub headers: Vec<(String, String)>,
}

/// Read-only request description for `GET /api/v1/images/models`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRequestDescription {
    pub url: String,
    pub method: String,
    pub streaming: bool,
    pub headers: Vec<(String, String)>,
}

/// Read-only request description for the selected model's endpoint link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRequestDescription {
    pub url: String,
    pub method: String,
    pub streaming: bool,
    pub headers: Vec<(String, String)>,
}

/// A local runtime error for the adapter contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    Serialization,
    /// Invalid or duplicate provider header overrides. No secret value is
    /// surfaced; the error is a stable redacted class.
    InvalidHeaders,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization => write!(f, "request serialization failed"),
            Self::InvalidHeaders => write!(
                f,
                "provider header overrides are invalid or duplicate; edit provider headers before retrying."
            ),
        }
    }
}

impl std::error::Error for RuntimeError {}

// ---------------------------------------------------------------------------
// Attempt safety: redirect rejection, secret redaction, no blind retry.
// ---------------------------------------------------------------------------

/// Classify an HTTP status for attempt safety. Every 3xx is a stable failure;
/// credentials and attribution cannot cross origins.
pub fn classify_status(status: u16) -> AttemptStatus {
    if (300..400).contains(&status) {
        return AttemptStatus::RedirectFailure;
    }
    if (200..300).contains(&status) {
        return AttemptStatus::Accepted;
    }
    if (400..500).contains(&status) {
        AttemptStatus::DefinitivelyRejected
    } else {
        AttemptStatus::SubmissionUnknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStatus {
    Accepted,
    DefinitivelyRejected,
    SubmissionUnknown,
    RedirectFailure,
}

/// A bounded, structured, secret-free summary of a provider error response.
///
/// Aligned with the OpenAI and Gemini image adapters: a stable error class
/// plus a short non-secret detail. The raw provider body is never retained;
/// no API key, bearer token, response body, or reference image bytes cross
/// this boundary. Detail is a stable, class-derived string — it is NOT
/// extracted from the raw provider response, so it can never leak a secret
/// that the provider echoed back in an error message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRouterRedactedSummary {
    /// Stable machine-readable error class (never contains secrets).
    pub class: OpenRouterErrorClass,
    /// Bounded human-readable detail (stable, class-derived, never contains
    /// a raw secret or raw response body).
    pub detail: &'static str,
}

/// Stable error classes for OpenRouter provider responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenRouterErrorClass {
    /// HTTP 4xx — the request was rejected (auth, quota, validation, etc.).
    ClientError,
    /// HTTP 5xx — the server failed or is unavailable.
    ServerError,
    /// HTTP 3xx — redirect rejected (credentials/attribution cannot cross
    /// origins).
    RedirectRejected,
    /// The response was not valid JSON or did not match the expected shape.
    Unparseable,
    /// A timeout or transport-level failure.
    Transport,
    /// Any other failure not covered above.
    Unknown,
}

impl fmt::Display for OpenRouterErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientError => write!(f, "client_error"),
            Self::ServerError => write!(f, "server_error"),
            Self::RedirectRejected => write!(f, "redirect_rejected"),
            Self::Unparseable => write!(f, "unparseable"),
            Self::Transport => write!(f, "transport"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Maximum length of the `detail` field in a [`OpenRouterRedactedSummary`].
pub const REDACTED_DETAIL_MAX_CHARS: usize = 512;

/// Typed failure cause for provider-response redaction.
///
/// Carries the kind of failure that produced a redacted summary so the
/// classifier can distinguish a transport failure, an HTTP-status-based
/// classification, and a decode failure (a 2xx body that did not parse into
/// the expected shape). The former two were already representable via
/// `Option<u16>`; the decode-failure cause is what makes
/// [`OpenRouterErrorClass::Unparseable`] producible — a bare non-3xx/4xx/5xx
/// status (e.g. a 2xx that arrived but was never decoded) maps to
/// [`OpenRouterErrorClass::Unknown`], while an actual decode failure maps to
/// `Unparseable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionCause {
    /// An HTTP response was received; classify by status code. A 2xx here
    /// (with no decode failure) maps to [`OpenRouterErrorClass::Unknown`]
    /// since there is no error body to redact.
    Status(u16),
    /// A transport-level failure (no HTTP response, timeout, connection
    /// reset). Maps to [`OpenRouterErrorClass::Transport`].
    Transport,
    /// The response body could not be parsed into the expected shape — e.g.
    /// malformed JSON on a 2xx, or a body that did not match the contract.
    /// Maps to [`OpenRouterErrorClass::Unparseable`] regardless of status.
    DecodeFailure,
}

/// Build a bounded, structured, secret-free summary of a provider error.
///
/// Replaces the former regex-over-raw-text scrubbing. The typed
/// [`RedactionCause`] is classified into a stable [`OpenRouterErrorClass`]
/// and a short, stable, class-derived detail. No raw body is retained; no
/// API key, bearer token, or secret-bearing substring survives into the
/// summary — the detail is a fixed string per class, never extracted from
/// the provider response, so a secret echoed back in an error message cannot
/// leak.
///
/// Classification:
/// - [`RedactionCause::Status`] with 3xx → [`RedirectRejected`], 4xx →
///   [`ClientError`], 5xx → [`ServerError`], any other status (incl. 2xx
///   without a decode failure) → [`Unknown`].
/// - [`RedactionCause::Transport`] → [`Transport`].
/// - [`RedactionCause::DecodeFailure`] → [`Unparseable`] (this is the only
///   way to produce `Unparseable`; a bare 2xx status is `Unknown`).
///
/// [`RedirectRejected`]: OpenRouterErrorClass::RedirectRejected
/// [`ClientError`]: OpenRouterErrorClass::ClientError
/// [`ServerError`]: OpenRouterErrorClass::ServerError
/// [`Unknown`]: OpenRouterErrorClass::Unknown
/// [`Transport`]: OpenRouterErrorClass::Transport
/// [`Unparseable`]: OpenRouterErrorClass::Unparseable
pub fn redact_provider_error(cause: RedactionCause, _payload: &str) -> OpenRouterRedactedSummary {
    let class = match cause {
        RedactionCause::DecodeFailure => OpenRouterErrorClass::Unparseable,
        RedactionCause::Transport => OpenRouterErrorClass::Transport,
        RedactionCause::Status(s) if (300..400).contains(&s) => {
            OpenRouterErrorClass::RedirectRejected
        }
        RedactionCause::Status(s) if (400..500).contains(&s) => OpenRouterErrorClass::ClientError,
        RedactionCause::Status(s) if (500..600).contains(&s) => OpenRouterErrorClass::ServerError,
        RedactionCause::Status(_) => OpenRouterErrorClass::Unknown,
    };

    let detail = match class {
        OpenRouterErrorClass::ClientError => {
            "provider rejected the request (auth, quota, or validation)"
        }
        OpenRouterErrorClass::ServerError => "provider server error or unavailable",
        OpenRouterErrorClass::RedirectRejected => {
            "redirect rejected; credentials and attribution cannot cross origins"
        }
        OpenRouterErrorClass::Unparseable => "provider response was not parseable",
        OpenRouterErrorClass::Transport => "transport-level failure or timeout",
        OpenRouterErrorClass::Unknown => "unknown provider failure",
    };

    OpenRouterRedactedSummary { class, detail }
}

/// Determine whether a blind second request is forbidden after an ambiguous
/// handoff. Generic inference retry and a blind second request are forbidden;
/// a submission timeout after possible handoff becomes `submission_unknown`.
pub fn blind_retry_forbidden(previous: AttemptStatus) -> bool {
    matches!(
        previous,
        AttemptStatus::SubmissionUnknown | AttemptStatus::Accepted
    )
}

// ---------------------------------------------------------------------------
// Dispatch wiring: ImageGenerationAdapter + production transport seam (AC3/AC8).
// ---------------------------------------------------------------------------

use std::sync::Arc;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Url};

use crate::image_generation::http_transport::{
    ProviderTransportConfigError, VettedHttpClient, validate_https_origin,
};
use crate::image_generation::transport::{
    ProviderTransportError, ProviderTransportOutcome, SubmissionDisposition,
};
use crate::image_generation_job::{
    ImageGenerationAdapter, ImageGenerationHandoffRequest, ImageGenerationHandoffResult,
    image_generation_adapter_sealed,
};
use crate::image_generation_runtime::{AddressClass, DnsResolver};

/// The response-body bound for `POST /api/v1/images`, enforced while reading.
/// Matches the [`parse_response`] admission bound so a body the parser would
/// reject as oversized is refused at the transport before it is buffered.
pub const MAX_SUBMIT_RESPONSE_BYTES: usize =
    MAX_OUTPUT_BASE64_BYTES + MAX_USAGE_METADATA_BYTES + 1024;

mod openrouter_adapter_sealed {
    pub trait Sealed {}
}

/// Transport seam for the OpenRouter Image API. Production wires this to
/// [`OpenrouterImagesHttpTransport`] (a pinned/vetted reqwest client); tests
/// wire a scripted transport. The seam is the only place a request byte leaves
/// the process, and the attribution/provider headers the adapter merged on
/// submit are applied here alongside the caller-supplied bearer credential.
#[async_trait::async_trait]
pub trait OpenrouterImagesTransport: openrouter_adapter_sealed::Sealed + Send + Sync {
    /// Submit the encoded request body with the merged (attribution + provider)
    /// headers. Returns the bounded response on a 2xx, or a
    /// [`ProviderTransportError`] on the shared billing-safe vocabulary.
    async fn submit(
        &self,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> Result<ProviderTransportOutcome, ProviderTransportError>;
}

/// A production pinned HTTPS transport bound to one OpenRouter origin.
///
/// Constructible only through [`OpenrouterImagesHttpTransport::vetted`], so no
/// caller can assemble one that skips the vetted posture. The bearer credential
/// is caller-supplied (never hardcoded), held sensitive, and redacted in
/// `Debug`. A `POST` is always sent to the fixed [`SUBMIT_PATH`] on the
/// configured origin: the adapter cannot redirect the request elsewhere.
pub struct OpenrouterImagesHttpTransport {
    origin: Url,
    authorization: HeaderValue,
    dns: Arc<dyn DnsResolver>,
    body_limit: usize,
}

impl std::fmt::Debug for OpenrouterImagesHttpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenrouterImagesHttpTransport")
            .field("origin", &self.origin.as_str())
            .field("authorization", &"<redacted>")
            .field("body_limit", &self.body_limit)
            .finish()
    }
}

impl OpenrouterImagesHttpTransport {
    /// The single vetted constructor. Validates the `https` origin, binds the
    /// caller-supplied bearer credential as a sensitive header, and fixes the
    /// required peer location class to the public internet.
    pub fn vetted(
        origin: &str,
        bearer_token: &str,
        dns: Arc<dyn DnsResolver>,
        body_limit: usize,
    ) -> Result<Self, ProviderTransportConfigError> {
        let origin = validate_https_origin(origin)?;
        if body_limit == 0 {
            return Err(ProviderTransportConfigError::EmptyBodyLimit);
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {bearer_token}"))
            .map_err(|_| ProviderTransportConfigError::InvalidCredential)?;
        authorization.set_sensitive(true);
        Ok(Self {
            origin,
            authorization,
            dns,
            body_limit,
        })
    }
}

impl openrouter_adapter_sealed::Sealed for OpenrouterImagesHttpTransport {}

#[async_trait::async_trait]
impl OpenrouterImagesTransport for OpenrouterImagesHttpTransport {
    async fn submit(
        &self,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
        let url = self
            .origin
            .join(SUBMIT_PATH.trim_start_matches('/'))
            .map_err(|_| ProviderTransportError::Connect)?;
        let mut header_map = HeaderMap::new();
        // Attribution + provider headers first; the credential and content-type
        // are inserted last so a provider header can never override them. A
        // provider `authorization` override is dropped outright so it can never
        // replace the vetted bearer credential.
        for (name, value) in &headers {
            if name.eq_ignore_ascii_case("authorization") {
                continue;
            }
            // An empty value is a suppression marker: do not emit the header.
            if value.is_empty() {
                continue;
            }
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ProviderTransportError::Connect)?;
            let header_value =
                HeaderValue::from_str(value).map_err(|_| ProviderTransportError::Connect)?;
            header_map.insert(header_name, header_value);
        }
        header_map.insert(AUTHORIZATION, self.authorization.clone());
        header_map.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        VettedHttpClient::new(self.dns.clone(), AddressClass::PublicNetwork)
            .execute(Method::POST, &url, header_map, Some(body), self.body_limit)
            .await
    }
}

/// The immutable per-attempt inputs the OpenRouter adapter needs to build one
/// submission. The daemon-integration layer resolves these from the opaque
/// dispatch identity; this crate ships the seam plus a scripted resolver.
#[derive(Debug, Clone)]
pub struct OpenrouterImagesAttemptInput {
    /// Configured endpoint origin (used only to build the request description;
    /// the transport owns the actual dial to its own configured origin).
    pub origin: String,
    /// Whether OpenRouter attribution headers should be merged on submit
    /// (true only when the resolved provider identity is the `openrouter`
    /// template origin). Keeps the crate-private origin type out of this
    /// public plan surface.
    pub apply_openrouter_attribution: bool,
    /// The validated closed request DTO.
    pub request: OpenrouterImageRequest,
    /// Validated user/provider header overrides.
    pub provider_headers: Vec<(String, String)>,
}

/// Resolves the immutable per-attempt plan from a dispatch handoff request.
#[async_trait::async_trait]
pub trait OpenrouterImagesPlanSource: openrouter_adapter_sealed::Sealed + Send + Sync {
    async fn resolve(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> OpenrouterImagesPlanResolution;
}

/// Outcome of resolving the per-attempt plan.
#[derive(Debug, Clone)]
pub enum OpenrouterImagesPlanResolution {
    Resolved(Box<OpenrouterImagesAttemptInput>),
    Unresolvable { safe_reason: String },
}

/// The OpenRouter Images dispatch adapter. Implements the sealed
/// [`ImageGenerationAdapter`]: a plan is resolved from the dispatch identity,
/// one bounded request is submitted through the pinned transport with
/// attribution applied, and the transport classification maps onto the shared
/// billing-safe handoff vocabulary. `reconcile`/`cancel` inherit the honest
/// no-authoritative defaults (the OpenRouter Image API is synchronous).
pub struct OpenrouterImagesAdapter {
    transport: Arc<dyn OpenrouterImagesTransport>,
    plan_source: Arc<dyn OpenrouterImagesPlanSource>,
}

impl OpenrouterImagesAdapter {
    pub fn new(
        transport: Arc<dyn OpenrouterImagesTransport>,
        plan_source: Arc<dyn OpenrouterImagesPlanSource>,
    ) -> Self {
        Self {
            transport,
            plan_source,
        }
    }
}

impl image_generation_adapter_sealed::Sealed for OpenrouterImagesAdapter {}

#[async_trait::async_trait]
impl ImageGenerationAdapter for OpenrouterImagesAdapter {
    async fn handoff(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> ImageGenerationHandoffResult {
        let mut input = match self.plan_source.resolve(request).await {
            OpenrouterImagesPlanResolution::Resolved(input) => *input,
            OpenrouterImagesPlanResolution::Unresolvable { safe_reason } => {
                // No request was built or sent: definitive rejection, never
                // submission-unknown.
                return ImageGenerationHandoffResult::DefinitivelyRejected {
                    evidence: openrouter_redacted_evidence(b"plan_unresolvable", &safe_reason),
                };
            }
        };
        input.request.prompt = request.sealed_prompt.payload.clone();
        let provider_origin = if input.apply_openrouter_attribution {
            ResolvedProviderOrigin::template("openrouter")
        } else {
            ResolvedProviderOrigin::default()
        };
        let description = match build_submit_request(
            &input.origin,
            &provider_origin,
            &input.request,
            &input.provider_headers,
        ) {
            Ok(description) => description,
            Err(error) => {
                return ImageGenerationHandoffResult::DefinitivelyRejected {
                    evidence: openrouter_redacted_evidence(b"request_build", &error.to_string()),
                };
            }
        };
        let body = match serde_json::to_vec(&description.body) {
            Ok(body) => body,
            Err(_) => {
                return ImageGenerationHandoffResult::DefinitivelyRejected {
                    evidence: openrouter_redacted_evidence(
                        b"request_serialize",
                        "serialize failed",
                    ),
                };
            }
        };
        match self.transport.submit(body, description.headers).await {
            Ok(outcome) => match parse_response(&outcome.body) {
                Ok(_parsed) => ImageGenerationHandoffResult::Accepted {
                    evidence: openrouter_redacted_evidence(
                        b"accepted",
                        &format!("status={}", outcome.status),
                    ),
                },
                Err(error) => {
                    // A 2xx that fails to parse still means the provider accepted
                    // (and likely charged): a stable accepted-with-invalid-output,
                    // never a resubmittable rejection.
                    ImageGenerationHandoffResult::Accepted {
                        evidence: openrouter_redacted_evidence(
                            b"accepted_invalid_output",
                            &error.to_string(),
                        ),
                    }
                }
            },
            Err(error) => match error.submission_disposition() {
                SubmissionDisposition::DefinitivelyRejected => {
                    // Includes a 3xx (redirect never followed) which is a stable
                    // failure so credentials/attribution cannot cross origins.
                    let detail = openrouter_error_detail(&error);
                    ImageGenerationHandoffResult::DefinitivelyRejected {
                        evidence: openrouter_redacted_evidence(b"definitive_nonacceptance", detail),
                    }
                }
                SubmissionDisposition::SubmissionUnknown => {
                    ImageGenerationHandoffResult::SubmissionUnknown {
                        evidence: openrouter_redacted_evidence(
                            b"post_handoff_ambiguous",
                            "handoff accepted",
                        ),
                    }
                }
            },
        }
    }
}

/// A stable, class-derived, secret-free detail for a transport error. Never
/// extracted from the raw provider response, so a secret echoed in an error
/// body cannot leak.
fn openrouter_error_detail(error: &ProviderTransportError) -> &'static str {
    match error {
        ProviderTransportError::Status { status, .. } => match classify_status(*status) {
            AttemptStatus::RedirectFailure => "redirect rejected; credentials cannot cross origins",
            AttemptStatus::DefinitivelyRejected => "provider rejected the request",
            AttemptStatus::Accepted | AttemptStatus::SubmissionUnknown => "provider non-2xx status",
        },
        ProviderTransportError::Connect => "no byte accepted (connect refused)",
        ProviderTransportError::Tls => "no byte accepted (tls)",
        ProviderTransportError::BodyLimit => "response exceeded bound",
        ProviderTransportError::Malformed => "response unparseable",
        ProviderTransportError::Timeout | ProviderTransportError::AmbiguousAcceptance => {
            "handoff ambiguous"
        }
    }
}

fn openrouter_redacted_evidence(class: &[u8], detail: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(class);
    out.push(0);
    let bounded = detail
        .chars()
        .take(REDACTED_DETAIL_MAX_CHARS)
        .collect::<String>();
    out.extend_from_slice(bounded.as_bytes());
    out
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Crate-internal test doubles for the OpenRouter dispatch path, usable by
    //! the dispatcher integration tests in `image_generation_job`.
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::image_generation_job::ImageGenerationHandoffRequest;

    /// A recorded submission: the encoded request body and the merged headers.
    pub(crate) type RecordedSubmission = (Vec<u8>, Vec<(String, String)>);

    /// A transport returning scripted outcomes in FIFO order and recording every
    /// submission so a test can prove the adapter built and sent a request.
    pub(crate) struct ScriptedOpenrouterTransport {
        outcomes: Mutex<VecDeque<Result<ProviderTransportOutcome, ProviderTransportError>>>,
        submissions: Mutex<Vec<RecordedSubmission>>,
    }

    impl ScriptedOpenrouterTransport {
        pub(crate) fn new(
            outcomes: Vec<Result<ProviderTransportOutcome, ProviderTransportError>>,
        ) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                submissions: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn submissions(&self) -> Vec<RecordedSubmission> {
            self.submissions.lock().unwrap().clone()
        }
    }

    impl openrouter_adapter_sealed::Sealed for ScriptedOpenrouterTransport {}

    #[async_trait::async_trait]
    impl OpenrouterImagesTransport for ScriptedOpenrouterTransport {
        async fn submit(
            &self,
            body: Vec<u8>,
            headers: Vec<(String, String)>,
        ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
            self.submissions.lock().unwrap().push((body, headers));
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted transport exhausted")
        }
    }

    /// A plan source resolving every request to the same fixed attempt input.
    pub(crate) struct FixedOpenrouterPlanSource {
        input: OpenrouterImagesAttemptInput,
    }

    impl FixedOpenrouterPlanSource {
        pub(crate) fn new(input: OpenrouterImagesAttemptInput) -> Self {
            Self { input }
        }
    }

    impl openrouter_adapter_sealed::Sealed for FixedOpenrouterPlanSource {}

    #[async_trait::async_trait]
    impl OpenrouterImagesPlanSource for FixedOpenrouterPlanSource {
        async fn resolve(
            &self,
            _request: &ImageGenerationHandoffRequest,
        ) -> OpenrouterImagesPlanResolution {
            OpenrouterImagesPlanResolution::Resolved(Box::new(self.input.clone()))
        }
    }

    /// A valid prompt-only OpenRouter attempt input against the template
    /// `openrouter` origin (so attribution headers are merged on submit).
    pub(crate) fn sample_attempt_input() -> OpenrouterImagesAttemptInput {
        OpenrouterImagesAttemptInput {
            origin: "https://openrouter.ai".to_string(),
            apply_openrouter_attribution: true,
            request: OpenrouterImageRequest {
                model: "black-forest-labs/flux-1.1-pro".to_string(),
                prompt: "a serene mountain lake at dawn".to_string(),
                resolution: None,
                aspect_ratio: None,
                size: None,
                quality: None,
                output_format: None,
                background: None,
                output_compression: None,
                seed: None,
                n: 1,
                input_references: Vec::new(),
                provider: None,
            },
            provider_headers: Vec::new(),
        }
    }

    /// A successful single-image OpenRouter response body for the sample plan.
    pub(crate) fn sample_success_body() -> Vec<u8> {
        let mut png = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgb8(1, 1)
            .write_to(&mut png, image::ImageFormat::Png)
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(png.into_inner());
        serde_json::to_vec(&serde_json::json!({ "data": [{ "b64_json": b64 }] })).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_bytes() -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgb8(1, 1)
            .write_to(&mut out, image::ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }

    fn jpeg_bytes() -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgb8(1, 1)
            .write_to(&mut out, image::ImageFormat::Jpeg)
            .unwrap();
        out.into_inner()
    }

    fn endpoint_with_tag(tag: Option<&str>) -> DiscoveredEndpoint {
        DiscoveredEndpoint {
            provider_tag: tag.map(|s| s.to_string()),
            provider_slug: Some("slug-a".to_string()),
            supported_parameters: vec!["prompt".into(), "model".into()],
            pricing: Some(EndpointPricing {
                prompt: None,
                image_request: None,
                image_output: Some(CostLine {
                    cost_usd: "0.01".into(),
                    unit: Some("image".into()),
                }),
                image_megapixel: None,
                variants: vec![],
            }),
            n: Some(EndpointNCap { max: 4 }),
            seed: Some(true),
            resolution: vec!["512".into(), "1K".into(), "2K".into()],
            aspect_ratio: vec!["1:1".into(), "16:9".into(), "auto".into()],
            size: vec![],
            input_references: Some(EndpointReferenceCap {
                max_count: Some(2),
                max_bytes_per_reference: Some(1024),
                max_aggregate_bytes: Some(2048),
            }),
        }
    }

    // -------------------------------------------------------------------------
    // Acceptance test 1: image_generation_openrouter_direct
    // -------------------------------------------------------------------------

    #[test]
    fn image_generation_openrouter_direct() {
        // Constructs exact POST /api/v1/images wire fixtures for every closed
        // request field and proves no /images/generations, Responses, Chat,
        // server-tool, streaming, remote-output URL, or active-model fallback
        // path exists.
        let request = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "a red cube".into(),
            resolution: Some("1K".into()),
            aspect_ratio: Some("16:9".into()),
            size: None,
            quality: Some("high".into()),
            output_format: Some("png".into()),
            background: Some("transparent".into()),
            output_compression: Some(80),
            seed: Some(42),
            n: 2,
            input_references: vec![],
            provider: Some(RoutingPolicy {
                only: vec!["qwen".into()],
                ignore: vec![],
                order: vec![],
                sort: Some(SortPolicy::Price),
                allow_fallbacks: true,
            }),
        };
        let desc =
            build_submit_request("https://openrouter.ai", &openrouter_origin(), &request, &[])
                .unwrap();
        assert_eq!(desc.method, "POST");
        assert!(desc.url.ends_with("/api/v1/images"));
        assert!(!desc.url.contains("/images/generations"));
        assert!(!desc.url.contains("/responses"));
        assert!(!desc.url.contains("/chat"));
        assert!(!desc.streaming);
        let body = desc.body.as_object().unwrap();
        assert_eq!(body["model"], "qwen/qwen-image-3-pro");
        assert_eq!(body["prompt"], "a red cube");
        assert_eq!(body["resolution"], "1K");
        assert_eq!(body["aspect_ratio"], "16:9");
        assert_eq!(body["quality"], "high");
        assert_eq!(body["output_format"], "png");
        assert_eq!(body["background"], "transparent");
        assert_eq!(body["output_compression"], 80);
        assert_eq!(body["seed"], 42);
        assert_eq!(body["n"], 2);
        assert!(body["provider"].is_object());
        // No server-tool, tool_choice, stream, or fallback_model fields.
        assert!(body.get("tools").is_none());
        assert!(body.get("tool_choice").is_none());
        assert!(body.get("stream").is_none());
        assert!(body.get("fallback_model").is_none());
        assert!(body.get("model_fallback").is_none());
        // deny_unknown_fields rejects unknown fields.
        let bad = serde_json::json!({
            "model": "qwen/qwen-image-3-pro",
            "prompt": "x",
            "bogus_field": true
        });
        assert!(serde_json::from_value::<OpenrouterImageRequest>(bad).is_err());
    }

    // -------------------------------------------------------------------------
    // Acceptance test 2: image_generation_openrouter_parameter_matrix
    // -------------------------------------------------------------------------

    #[test]
    fn image_generation_openrouter_parameter_matrix() {
        let eps = vec![endpoint_with_tag(Some("qwen"))];

        // resolution-only.
        let req = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: Some("1K".into()),
            aspect_ratio: None,
            size: None,
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![],
            provider: None,
        };
        assert_eq!(preflight(&req, &eps), PreflightOutcome::Accept);

        // aspect-only.
        let req = OpenrouterImageRequest {
            resolution: None,
            aspect_ratio: Some("16:9".into()),
            ..req
        };
        assert_eq!(preflight(&req, &eps), PreflightOutcome::Accept);

        // every exact tier-size token plus aspect.
        for tier in TIER_SIZE_TOKENS {
            let req = OpenrouterImageRequest {
                model: "qwen/qwen-image-3-pro".into(),
                prompt: "x".into(),
                resolution: None,
                aspect_ratio: Some("16:9".into()),
                size: Some((*tier).into()),
                quality: None,
                output_format: None,
                background: None,
                output_compression: None,
                seed: None,
                n: 1,
                input_references: vec![],
                provider: None,
            };
            // Tier must appear in every endpoint's resolution enum.
            let outcome = preflight(&req, &eps);
            if eps.iter().all(|e| e.resolution.iter().any(|r| r == *tier)) {
                assert_eq!(outcome, PreflightOutcome::Accept, "tier {tier} should pass");
            } else {
                assert_eq!(
                    outcome,
                    PreflightOutcome::Reject(PreflightReason::TierSizeNotInEveryResolution),
                    "tier {tier} should be rejected"
                );
            }
        }

        // rejection of a tier absent from any endpoint's resolution enum.
        let mut eps_missing = eps.clone();
        eps_missing[0].resolution = vec!["512".into()];
        let req = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: None,
            aspect_ratio: Some("16:9".into()),
            size: Some("2K".into()),
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![],
            provider: None,
        };
        assert_eq!(
            preflight(&req, &eps_missing),
            PreflightOutcome::Reject(PreflightReason::TierSizeNotInEveryResolution)
        );

        // canonical explicit-pixel grammar and checked u32/u64/target limits.
        // The current live records advertise no size descriptor, so explicit
        // pixels are unavailable.
        let req = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: None,
            aspect_ratio: None,
            size: Some("2048x1152".into()),
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![],
            provider: None,
        };
        assert_eq!(
            preflight(&req, &eps),
            PreflightOutcome::Reject(PreflightReason::ExplicitPixelsNoSizeDescriptor)
        );

        // exact advertised size-enum authorization: when every endpoint
        // advertises the exact canonical pixel string.
        let mut eps_with_size = eps.clone();
        eps_with_size[0].size = vec![SizeDescriptor {
            canonical: "2048x1152".into(),
        }];
        let req = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: None,
            aspect_ratio: None,
            size: Some("2048x1152".into()),
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![],
            provider: None,
        };
        assert_eq!(preflight(&req, &eps_with_size), PreflightOutcome::Accept);

        // absent/wrong descriptor fail-closed behavior.
        let mut eps_wrong_size = eps.clone();
        eps_wrong_size[0].size = vec![SizeDescriptor {
            canonical: "1024x1024".into(),
        }];
        assert_eq!(
            preflight(&req, &eps_wrong_size),
            PreflightOutcome::Reject(PreflightReason::ExplicitPixelsNoSizeDescriptor)
        );

        // exact-decimal ratios including 9:19.5, matching/mismatching/auto.
        let mut eps_ratio = eps.clone();
        eps_ratio[0].size = vec![SizeDescriptor {
            canonical: "1440x3120".into(),
        }];
        eps_ratio[0].aspect_ratio = vec!["9:19.5".into(), "1:1".into(), "auto".into()];
        let req_match = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: None,
            aspect_ratio: Some("9:19.5".into()),
            size: Some("1440x3120".into()),
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![],
            provider: None,
        };
        assert_eq!(preflight(&req_match, &eps_ratio), PreflightOutcome::Accept);

        // mismatching aspect.
        let req_mismatch = OpenrouterImageRequest {
            aspect_ratio: Some("1:1".into()),
            ..req_match.clone()
        };
        assert_eq!(
            preflight(&req_mismatch, &eps_ratio),
            PreflightOutcome::Reject(PreflightReason::AspectInconsistentWithPixels)
        );

        // auto aspect with explicit pixels is rejected.
        let req_auto = OpenrouterImageRequest {
            aspect_ratio: Some("auto".into()),
            ..req_match.clone()
        };
        assert_eq!(
            preflight(&req_auto, &eps_ratio),
            PreflightOutcome::Reject(PreflightReason::AspectInconsistentWithPixels)
        );

        // unconditional rejection of explicit pixels plus resolution.
        let req_res = OpenrouterImageRequest {
            resolution: Some("1K".into()),
            ..req_match.clone()
        };
        assert_eq!(
            preflight(&req_res, &eps_ratio),
            PreflightOutcome::Reject(PreflightReason::ExplicitPixelsPlusResolution)
        );

        // n global bounds: n=0 and n=11 rejected.
        let req_n0 = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: Some("1K".into()),
            aspect_ratio: None,
            size: None,
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 0,
            input_references: vec![],
            provider: None,
        };
        assert_eq!(
            preflight(&req_n0, &eps),
            PreflightOutcome::Reject(PreflightReason::NOutOfRange)
        );
        let req_n11 = OpenrouterImageRequest {
            n: 11,
            ..req_n0.clone()
        };
        assert_eq!(
            preflight(&req_n11, &eps),
            PreflightOutcome::Reject(PreflightReason::NOutOfRange)
        );

        // n above an endpoint cap.
        let req_n5 = OpenrouterImageRequest {
            n: 5,
            ..req_n0.clone()
        };
        assert_eq!(
            preflight(&req_n5, &eps),
            PreflightOutcome::Reject(PreflightReason::NAboveEndpointCap)
        );

        // integer seed versus discovered boolean capability descriptor.
        let req_seed = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: Some("1K".into()),
            aspect_ratio: None,
            size: None,
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: Some(7),
            n: 1,
            input_references: vec![],
            provider: None,
        };
        assert_eq!(preflight(&req_seed, &eps), PreflightOutcome::Accept);
        let mut eps_no_seed = eps.clone();
        eps_no_seed[0].seed = Some(false);
        assert_eq!(
            preflight(&req_seed, &eps_no_seed),
            PreflightOutcome::Reject(PreflightReason::SeedUnavailable)
        );
        let mut eps_seed_none = eps.clone();
        eps_seed_none[0].seed = None;
        assert_eq!(
            preflight(&req_seed, &eps_seed_none),
            PreflightOutcome::Reject(PreflightReason::SeedUnavailable)
        );

        // strict model-plus-all-possible-endpoint intersections: resolution
        // absent from one endpoint rejects.
        let mut eps_two = eps.clone();
        eps_two.push(endpoint_with_tag(Some("openai")));
        eps_two[1].resolution = vec!["512".into()];
        let req_one_k = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: Some("1K".into()),
            aspect_ratio: None,
            size: None,
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![],
            provider: None,
        };
        assert_eq!(
            preflight(&req_one_k, &eps_two),
            PreflightOutcome::Reject(PreflightReason::ResolutionNotInEveryEndpoint)
        );

        // rejection before dispatch: invalid model ID.
        let req_bad_model = OpenrouterImageRequest {
            model: "not-two-segments-here".into(),
            ..req_one_k.clone()
        };
        assert_eq!(
            preflight(&req_bad_model, &eps),
            PreflightOutcome::Reject(PreflightReason::InvalidModelId)
        );
    }

    // -------------------------------------------------------------------------
    // Acceptance test 3: image_generation_openrouter_discovery
    // -------------------------------------------------------------------------

    #[test]
    fn image_generation_openrouter_discovery() {
        // exact model and endpoint routes.
        let discovery =
            build_discovery_request("https://openrouter.ai", &openrouter_origin(), &[]).unwrap();
        assert_eq!(discovery.method, "GET");
        assert!(discovery.url.ends_with(DISCOVERY_MODELS_PATH));

        let model = ModelId::parse("qwen/qwen-image-3-pro").unwrap();
        let endpoint_req =
            build_endpoint_request("https://openrouter.ai", &openrouter_origin(), &model, &[])
                .unwrap();
        assert_eq!(endpoint_req.method, "GET");
        assert!(
            endpoint_req
                .url
                .ends_with("/api/v1/images/models/qwen/qwen-image-3-pro/endpoints")
        );

        // two-segment model grammar.
        assert!(ModelId::parse("qwen/qwen-image-3-pro").is_some());
        assert!(ModelId::parse("single").is_none());
        assert!(ModelId::parse("a/b/c").is_none());
        assert!(ModelId::parse("/slug").is_none());
        assert!(ModelId::parse("author/").is_none());
        assert!(ModelId::parse("").is_none());

        // same-origin canonical-link validation.
        let link = model.endpoint_link();
        assert!(validate_endpoint_link(&link, &model).is_ok());
        // absolute URL rejected.
        assert_eq!(
            validate_endpoint_link(
                "https://evil.com/api/v1/images/models/qwen/qwen-image-3-pro/endpoints",
                &model
            )
            .unwrap_err(),
            EndpointLinkError::AbsoluteOrProtocolRelative
        );
        // protocol-relative rejected.
        assert_eq!(
            validate_endpoint_link("//evil.com/x", &model).unwrap_err(),
            EndpointLinkError::AbsoluteOrProtocolRelative
        );
        // foreign-authority / non-canonical rejected.
        assert_eq!(
            validate_endpoint_link("/api/v1/images/models/other/model/endpoints", &model)
                .unwrap_err(),
            EndpointLinkError::NotCanonical
        );
        // query/fragment rejected.
        assert_eq!(
            validate_endpoint_link(&format!("{link}?x=1"), &model).unwrap_err(),
            EndpointLinkError::UserinfoQueryFragment
        );
        assert_eq!(
            validate_endpoint_link(&format!("{link}#frag"), &model).unwrap_err(),
            EndpointLinkError::UserinfoQueryFragment
        );
        // traversal rejected.
        assert_eq!(
            validate_endpoint_link(
                "/api/v1/images/models/../qwen/qwen-image-3-pro/endpoints",
                &model
            )
            .unwrap_err(),
            EndpointLinkError::Traversal
        );
        // encoded separator rejected.
        assert_eq!(
            validate_endpoint_link(
                "/api/v1/images/models/qwen%2Fqwen-image-3-pro/endpoints",
                &model
            )
            .unwrap_err(),
            EndpointLinkError::EncodedSeparator
        );

        // redirect rejection with zero credential/header forwarding: every 3xx
        // is a stable failure.
        for status in [301u16, 302, 303, 307, 308] {
            assert_eq!(classify_status(status), AttemptStatus::RedirectFailure);
        }

        // modalities and endpoint capability records.
        let model_record = DiscoveredModel {
            id: "qwen/qwen-image-3-pro".into(),
            name: Some("Qwen".into()),
            supported_parameters: vec!["prompt".into(), "seed".into()],
            modalities: Some(DiscoveredModalities {
                input: vec!["text".into(), "image".into()],
                output: vec!["image".into()],
            }),
        };
        assert!(
            model_record
                .modalities
                .unwrap()
                .input
                .contains(&"image".to_string())
        );

        // nullable routing tags versus provider-slug evidence.
        let ep_null_tag = endpoint_with_tag(None);
        assert!(ep_null_tag.provider_tag.is_none());
        assert!(ep_null_tag.provider_slug.is_some());

        // provenance/freshness.
        let provenance = DiscoveryProvenance::Live;
        assert_eq!(provenance, DiscoveryProvenance::Live);

        // stable evidence ordering and exact duplicate-record rejection.
        let ep_a = endpoint_with_tag(Some("qwen"));
        let ep_b = endpoint_with_tag(Some("openai"));
        let identities = reject_duplicate_identities(&[ep_a, ep_b]).unwrap();
        assert_eq!(identities.len(), 2);
        // exact duplicate rejected.
        let ep_a2 = endpoint_with_tag(Some("qwen"));
        assert!(reject_duplicate_identities(&[endpoint_with_tag(Some("qwen")), ep_a2]).is_err());

        // distinct shared-tag record preservation.
        let mut ep_shared1 = endpoint_with_tag(Some("qwen"));
        ep_shared1.provider_slug = Some("slug-x".into());
        let mut ep_shared2 = endpoint_with_tag(Some("qwen"));
        ep_shared2.provider_slug = Some("slug-y".into());
        assert!(reject_duplicate_identities(&[ep_shared1, ep_shared2]).is_ok());

        // stale/unknown behavior.
        assert_eq!(DiscoveryProvenance::Stale, DiscoveryProvenance::Stale);
        assert_eq!(DiscoveryProvenance::Unknown, DiscoveryProvenance::Unknown);
    }

    // -------------------------------------------------------------------------
    // Acceptance test 4: image_generation_openrouter_references
    // -------------------------------------------------------------------------

    #[test]
    fn image_generation_openrouter_references() {
        let png = png_bytes();
        let reference = InputReference {
            mime_type: "image/png".to_string(),
            base64_bytes: png.clone(),
        };
        let data_url = reference.data_url();
        assert!(data_url.starts_with("data:image/png;base64,"));

        let wire = InputReferenceWire::from_reference(&reference);
        assert_eq!(wire.kind, "image_url");
        assert!(wire.image_url.url.starts_with("data:"));
        assert!(wire.validate().is_ok());

        // constructs exact canonical input_references[].type/image_url.url.
        let obj = wire.wire_object_for_test();
        assert_eq!(obj["type"], "image_url");
        assert_eq!(obj["image_url"]["url"], data_url);

        // enforces target/model/endpoint and byte bounds: oversized reference.
        let mut big = png.clone();
        big.resize(2049, 0x42);
        let big_reference = InputReferenceWire {
            kind: "image_url".into(),
            image_url: InputReferenceImageUrl {
                url: format!(
                    "data:image/png;base64,{}",
                    base64::engine::general_purpose::STANDARD.encode(png.repeat(100))
                ),
            },
        };
        let req = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: Some("1K".into()),
            aspect_ratio: None,
            size: None,
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![big_reference],
            provider: None,
        };
        let eps = vec![endpoint_with_tag(Some("qwen"))];
        assert_eq!(
            preflight(&req, &eps),
            PreflightOutcome::Reject(PreflightReason::ReferenceOversized)
        );

        // rejects unknown limits.
        let mut eps_unknown = eps.clone();
        eps_unknown[0].input_references = Some(EndpointReferenceCap {
            max_count: None,
            max_bytes_per_reference: Some(1024),
            max_aggregate_bytes: Some(2048),
        });
        let small_reference = InputReferenceWire::from_reference(&reference);
        let req = OpenrouterImageRequest {
            input_references: vec![small_reference],
            ..req.clone()
        };
        assert_eq!(
            preflight(&req, &eps_unknown),
            PreflightOutcome::Reject(PreflightReason::UnknownLimit)
        );

        // proves no agent-supplied remote URL is accepted.
        let remote = InputReferenceWire {
            kind: "image_url".into(),
            image_url: InputReferenceImageUrl {
                url: "https://evil.com/image.png".into(),
            },
        };
        assert_eq!(remote.validate().unwrap_err(), ReferenceError::RemoteUrl);
        let req = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: Some("1K".into()),
            aspect_ratio: None,
            size: None,
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![remote],
            provider: None,
        };
        assert_eq!(
            preflight(&req, &eps),
            PreflightOutcome::Reject(PreflightReason::ReferencesUnavailable)
        );
    }

    // -------------------------------------------------------------------------
    // Acceptance test 5: image_generation_openrouter_routing
    // -------------------------------------------------------------------------

    #[test]
    fn image_generation_openrouter_routing() {
        // two distinct endpoints sharing one tag, plus a null-tag endpoint.
        let tags: Vec<Option<String>> = vec![
            Some("qwen".into()),
            Some("qwen".into()),
            Some("openai".into()),
            None,
        ];

        // no policy: every endpoint eligible.
        let policy = RoutingPolicy::default();
        let decision = validate_routing_policy(&policy, &tags).unwrap();
        assert_eq!(decision.eligible_indices, vec![0, 1, 2, 3]);

        // only: excludes null tags.
        let policy = RoutingPolicy {
            only: vec!["qwen".into()],
            ..Default::default()
        };
        let decision = validate_routing_policy(&policy, &tags).unwrap();
        assert_eq!(decision.eligible_indices, vec![0, 1]);

        // ignore: leaves null tags unless another policy excludes them.
        let policy = RoutingPolicy {
            ignore: vec!["openai".into()],
            ..Default::default()
        };
        let decision = validate_routing_policy(&policy, &tags).unwrap();
        assert_eq!(decision.eligible_indices, vec![0, 1, 3]);

        // order: prioritizes one-to-many groups without excluding unlisted/null.
        let policy = RoutingPolicy {
            order: vec!["openai".into(), "qwen".into()],
            ..Default::default()
        };
        let decision = validate_routing_policy(&policy, &tags).unwrap();
        assert_eq!(decision.eligible_indices, vec![2, 0, 1, 3]);

        // repeated record tags are accepted (two qwen endpoints both eligible).
        let policy = RoutingPolicy {
            only: vec!["qwen".into()],
            ..Default::default()
        };
        let decision = validate_routing_policy(&policy, &tags).unwrap();
        assert_eq!(decision.eligible_indices.len(), 2);

        // duplicate configured entries rejected.
        let policy = RoutingPolicy {
            only: vec!["qwen".into(), "qwen".into()],
            ..Default::default()
        };
        assert_eq!(
            validate_routing_policy(&policy, &tags).unwrap_err(),
            RoutingError::DuplicateConfiguredEntry
        );

        // unknown names rejected.
        let policy = RoutingPolicy {
            only: vec!["bogus".into()],
            ..Default::default()
        };
        assert_eq!(
            validate_routing_policy(&policy, &tags).unwrap_err(),
            RoutingError::UnknownName
        );

        // contradictions rejected.
        let policy = RoutingPolicy {
            only: vec!["qwen".into()],
            ignore: vec!["qwen".into()],
            ..Default::default()
        };
        assert_eq!(
            validate_routing_policy(&policy, &tags).unwrap_err(),
            RoutingError::Contradiction
        );

        // provider_tag alone routes while provider_slug remains evidence.
        // (provider_slug is not part of routing policy; only tags route.)
        let policy = RoutingPolicy {
            only: vec!["qwen".into()],
            ..Default::default()
        };
        let decision = validate_routing_policy(&policy, &tags).unwrap();
        assert!(decision.eligible_indices.contains(&0));
        assert!(decision.eligible_indices.contains(&1));

        // object sort rejected: SortPolicy is a scalar enum, so object sort
        // cannot be deserialized.
        let bad_sort = serde_json::json!({ "sort": { "field": "price" } });
        let bad_policy: Result<RoutingPolicy, _> = serde_json::from_value(bad_sort);
        assert!(bad_policy.is_err());

        // unknown routing keys rejected (deny_unknown_fields).
        let bad = serde_json::json!({ "provider_options": {} });
        let bad_policy: Result<RoutingPolicy, _> = serde_json::from_value(bad);
        assert!(bad_policy.is_err());

        // scalar sort accepted.
        let policy = RoutingPolicy {
            sort: Some(SortPolicy::Price),
            ..Default::default()
        };
        assert_eq!(policy.sort, Some(SortPolicy::Price));

        // allow_fallbacks true/false recorded.
        let policy = RoutingPolicy {
            allow_fallbacks: true,
            ..Default::default()
        };
        assert!(policy.allow_fallbacks);
        let policy = RoutingPolicy {
            allow_fallbacks: false,
            ..Default::default()
        };
        assert!(!policy.allow_fallbacks);

        // empty eligible set rejected.
        let policy = RoutingPolicy {
            only: vec!["qwen".into()],
            ignore: vec!["qwen".into()],
            ..Default::default()
        };
        let _ = validate_routing_policy(&policy, &tags).unwrap_err();

        // invalid discovered tag rejected.
        let bad_tags: Vec<Option<String>> = vec![Some("  ".into())];
        let policy = RoutingPolicy::default();
        assert_eq!(
            validate_routing_policy(&policy, &bad_tags).unwrap_err(),
            RoutingError::InvalidDiscoveredTag
        );
    }

    // -------------------------------------------------------------------------
    // Acceptance test 6: image_generation_openrouter_pricing
    // -------------------------------------------------------------------------

    #[test]
    fn image_generation_openrouter_pricing() {
        // additive billable lines: image_output + image_request + megapixel.
        let mut ep = endpoint_with_tag(Some("qwen"));
        ep.pricing = Some(EndpointPricing {
            prompt: None,
            image_request: Some(CostLine {
                cost_usd: "0.001".into(),
                unit: Some("image".into()),
            }),
            image_output: Some(CostLine {
                cost_usd: "0.01".into(),
                unit: Some("image".into()),
            }),
            image_megapixel: None,
            variants: vec![],
        });
        let req = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: Some("1K".into()),
            aspect_ratio: None,
            size: None,
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 2,
            input_references: vec![],
            provider: None,
        };
        // 2 outputs * 0.01 = 0.02 => 20000 microdollars.
        let max = endpoint_max_microdollars(&ep, &req).unwrap();
        assert_eq!(max, 20_000);

        // with 1 input reference: + 0.001 => 0.021 => 21000 microdollars.
        let png = png_bytes();
        let reference = InputReference {
            mime_type: "image/png".to_string(),
            base64_bytes: png,
        };
        let wire = InputReferenceWire::from_reference(&reference);
        let mut eps = [ep.clone()];
        eps[0].input_references = Some(EndpointReferenceCap {
            max_count: Some(2),
            max_bytes_per_reference: Some(1024 * 1024),
            max_aggregate_bytes: Some(2 * 1024 * 1024),
        });
        let req_with_ref = OpenrouterImageRequest {
            input_references: vec![wire],
            ..req.clone()
        };
        let max = endpoint_max_microdollars(&eps[0], &req_with_ref).unwrap();
        assert_eq!(max, 21_000);

        // exact explicit-pixel megapixel rationals.
        let mut ep_mp = endpoint_with_tag(Some("qwen"));
        ep_mp.pricing = Some(EndpointPricing {
            prompt: None,
            image_request: None,
            image_output: None,
            image_megapixel: Some(CostLine {
                cost_usd: "0.001".into(),
                unit: Some("megapixel".into()),
            }),
            variants: vec![],
        });
        ep_mp.size = vec![SizeDescriptor {
            canonical: "2048x1152".into(),
        }];
        let req_mp = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: None,
            aspect_ratio: None,
            size: Some("2048x1152".into()),
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![],
            provider: None,
        };
        // 2048*1152 = 2359296 pixels = 2.359296 megapixels => ceil = 3 megapixels.
        // 3 * 0.001 = 0.003 => 3000 microdollars.
        let max = endpoint_max_microdollars(&ep_mp, &req_mp).unwrap();
        assert_eq!(max, 3_000);

        // tier/omitted-dimension megapixel pricing becomes unknown.
        let req_tier = OpenrouterImageRequest {
            size: Some("2K".into()),
            ..req_mp.clone()
        };
        assert!(endpoint_max_microdollars(&ep_mp, &req_tier).is_none());

        // exact variants: missing/ambiguous variants make maximum unknown.
        let mut ep_var = endpoint_with_tag(Some("qwen"));
        ep_var.pricing = Some(EndpointPricing {
            prompt: None,
            image_request: None,
            image_output: Some(CostLine {
                cost_usd: "0.01".into(),
                unit: Some("image".into()),
            }),
            image_megapixel: None,
            variants: vec![PricingVariant {
                name: "hd".into(),
                cost_usd: "0.02".into(),
                unit: Some("image".into()),
            }],
        });
        assert!(endpoint_max_microdollars(&ep_var, &req).is_none());

        // lexical decimals with more than six fractional digits.
        let mut ep_frac = endpoint_with_tag(Some("qwen"));
        ep_frac.pricing = Some(EndpointPricing {
            prompt: None,
            image_request: None,
            image_output: Some(CostLine {
                cost_usd: "0.0000001".into(),
                unit: Some("image".into()),
            }),
            image_megapixel: None,
            variants: vec![],
        });
        // 0.0000001 per image * 2 = 0.0000002 => ceiling to microdollars:
        // 0.0000002 USD = 0.2 microdollars => ceil = 1 microdollar total.
        let max = endpoint_max_microdollars(&ep_frac, &req).unwrap();
        assert_eq!(max, 1);

        // checked overflow: a huge cost_usd overflows the microdollar
        // conversion. This integer fits in u128 but its checked multiply by
        // 1_000_000 micros/dollar does not, so the maximum is unknown (None).
        let mut ep_overflow = endpoint_with_tag(Some("qwen"));
        ep_overflow.pricing = Some(EndpointPricing {
            prompt: None,
            image_request: None,
            image_output: Some(CostLine {
                cost_usd: "9999999999999999999999999999999999".into(),
                unit: Some("image".into()),
            }),
            image_megapixel: None,
            variants: vec![],
        });
        assert!(endpoint_max_microdollars(&ep_overflow, &req).is_none());

        // unknown billable/unit/variant/token bounds: token-priced input.
        let mut ep_token = endpoint_with_tag(Some("qwen"));
        ep_token.pricing = Some(EndpointPricing {
            prompt: Some(CostLine {
                cost_usd: "0.0001".into(),
                unit: Some("token".into()),
            }),
            image_request: None,
            image_output: None,
            image_megapixel: None,
            variants: vec![],
        });
        assert!(endpoint_max_microdollars(&ep_token, &req).is_none());

        // null-tag and shared-tag endpoints in fallback-true possible-route sets.
        let ep_null = endpoint_with_tag(None);
        let ep_shared1 = endpoint_with_tag(Some("qwen"));
        let mut ep_shared2 = endpoint_with_tag(Some("qwen"));
        ep_shared2.provider_slug = Some("slug-y".into());
        let endpoints = vec![ep_null, ep_shared1, ep_shared2];
        let plan = plan_max_microdollars(&endpoints, &req);
        // All endpoints have known pricing => plan is known.
        assert!(matches!(plan, PlanMax::Known(_)));

        // greatest-route selection.
        let mut ep_cheap = endpoint_with_tag(Some("cheap"));
        ep_cheap.pricing = Some(EndpointPricing {
            prompt: None,
            image_request: None,
            image_output: Some(CostLine {
                cost_usd: "0.001".into(),
                unit: Some("image".into()),
            }),
            image_megapixel: None,
            variants: vec![],
        });
        let mut ep_pricey = endpoint_with_tag(Some("pricey"));
        ep_pricey.pricing = Some(EndpointPricing {
            prompt: None,
            image_request: None,
            image_output: Some(CostLine {
                cost_usd: "0.05".into(),
                unit: Some("image".into()),
            }),
            image_megapixel: None,
            variants: vec![],
        });
        let endpoints = vec![ep_cheap.clone(), ep_pricey.clone()];
        let plan = plan_max_microdollars(&endpoints, &req);
        // greatest = 0.05 * 2 = 0.10 => 100000 microdollars.
        assert_eq!(plan, PlanMax::Known(100_000));

        // finite-budget blocking on any unknown.
        let mut ep_unknown = ep_cheap.clone();
        ep_unknown.pricing = Some(EndpointPricing {
            prompt: Some(CostLine {
                cost_usd: "0.0001".into(),
                unit: Some("token".into()),
            }),
            image_request: None,
            image_output: None,
            image_megapixel: None,
            variants: vec![],
        });
        let endpoints = vec![ep_pricey.clone(), ep_unknown];
        let plan = plan_max_microdollars(&endpoints, &req);
        assert_eq!(plan, PlanMax::Unknown);

        // Unlimited authorization: when plan is unknown, only Unlimited may
        // authorize dispatch. (Modeled here as PlanMax::Unknown.)
        assert!(plan.is_unknown());
    }

    // -------------------------------------------------------------------------
    // Acceptance test 7: image_generation_openrouter_response
    // -------------------------------------------------------------------------

    #[test]
    fn image_generation_openrouter_response() {
        let png = png_bytes();
        let png_b64 = base64::engine::general_purpose::STANDARD.encode(&png);
        let jpeg = jpeg_bytes();
        let jpeg_b64 = base64::engine::general_purpose::STANDARD.encode(&jpeg);

        // valid response with matching media_type.
        let body = serde_json::json!({
            "data": [{ "b64_json": png_b64, "media_type": "image/png" }],
            "usage": { "cost": 0.01 }
        });
        let parsed = parse_response(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(parsed.outputs.len(), 1);
        assert_eq!(parsed.outputs[0].media_type, "image/png");
        assert_eq!(parsed.usage.cost, Some(10_000));

        // present matching media_type for jpeg.
        let body = serde_json::json!({
            "data": [{ "b64_json": jpeg_b64, "media_type": "image/jpeg" }]
        });
        let parsed = parse_response(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(parsed.outputs[0].media_type, "image/jpeg");

        // present conflicting media type.
        let body = serde_json::json!({
            "data": [{ "b64_json": png_b64, "media_type": "image/jpeg" }]
        });
        assert_eq!(
            parse_response(&serde_json::to_vec(&body).unwrap()).unwrap_err(),
            ResponseParseError::MediaTypeConflict
        );

        // absent media_type with canonically detected allowed bytes succeeds.
        let body = serde_json::json!({
            "data": [{ "b64_json": png_b64 }]
        });
        let parsed = parse_response(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(parsed.outputs[0].media_type, "image/png");

        // undetectable bytes with absent media type fails.
        let garbage_b64 = base64::engine::general_purpose::STANDARD.encode(b"\xff\xff\xff\xff");
        let body = serde_json::json!({
            "data": [{ "b64_json": garbage_b64 }]
        });
        assert_eq!(
            parse_response(&serde_json::to_vec(&body).unwrap()).unwrap_err(),
            ResponseParseError::UndetectableBytes
        );

        // validates SVG outputs (sanitizer).
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><path d="M0 0h1v1z"/></svg>"#;
        let svg_b64 = base64::engine::general_purpose::STANDARD.encode(svg);
        let body = serde_json::json!({
            "data": [{ "b64_json": svg_b64, "media_type": "image/svg+xml" }]
        });
        let parsed = parse_response(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(parsed.outputs[0].media_type, "image/svg+xml");

        // SVG sanitization failure (script tag).
        let bad_svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
        let bad_svg_b64 = base64::engine::general_purpose::STANDARD.encode(bad_svg);
        let body = serde_json::json!({
            "data": [{ "b64_json": bad_svg_b64, "media_type": "image/svg+xml" }]
        });
        assert_eq!(
            parse_response(&serde_json::to_vec(&body).unwrap()).unwrap_err(),
            ResponseParseError::SvgSanitizationFailed
        );

        // valid usage.cost.
        let body = serde_json::json!({
            "data": [{ "b64_json": png_b64 }],
            "usage": { "cost": 0.001 }
        });
        let parsed = parse_response(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(parsed.usage.cost, Some(1_000));

        // absent usage.cost: unknown (None), not zero.
        let body = serde_json::json!({
            "data": [{ "b64_json": png_b64 }]
        });
        let parsed = parse_response(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(parsed.usage.cost, None);

        // wrong-typed usage.cost.
        let body = serde_json::json!({
            "data": [{ "b64_json": png_b64 }],
            "usage": { "cost": "not-a-number" }
        });
        assert_eq!(
            parse_response(&serde_json::to_vec(&body).unwrap()).unwrap_err(),
            ResponseParseError::InvalidUsageCost
        );

        // negative usage.cost.
        let body = serde_json::json!({
            "data": [{ "b64_json": png_b64 }],
            "usage": { "cost": -0.01 }
        });
        assert_eq!(
            parse_response(&serde_json::to_vec(&body).unwrap()).unwrap_err(),
            ResponseParseError::InvalidUsageCost
        );

        // overflowing usage.cost.
        let body = serde_json::json!({
            "data": [{ "b64_json": png_b64 }],
            "usage": { "cost": "99999999999999999999999999" }
        });
        assert_eq!(
            parse_response(&serde_json::to_vec(&body).unwrap()).unwrap_err(),
            ResponseParseError::InvalidUsageCost
        );

        // missing outputs.
        let body = serde_json::json!({ "data": [] });
        assert_eq!(
            parse_response(&serde_json::to_vec(&body).unwrap()).unwrap_err(),
            ResponseParseError::MissingOutputs
        );

        // missing b64_json.
        let body = serde_json::json!({ "data": [{ "media_type": "image/png" }] });
        assert_eq!(
            parse_response(&serde_json::to_vec(&body).unwrap()).unwrap_err(),
            ResponseParseError::MissingB64Json
        );

        // invalid base64.
        let body = serde_json::json!({ "data": [{ "b64_json": "!!!not-base64!!!" }] });
        assert_eq!(
            parse_response(&serde_json::to_vec(&body).unwrap()).unwrap_err(),
            ResponseParseError::InvalidB64Json
        );
    }

    // -------------------------------------------------------------------------
    // Acceptance test 8: image_generation_openrouter_attempt_safety
    // -------------------------------------------------------------------------

    #[test]
    fn image_generation_openrouter_attempt_safety() {
        // all 3xx statuses are stable failures.
        for status in [300u16, 301, 302, 303, 304, 305, 307, 308] {
            assert_eq!(classify_status(status), AttemptStatus::RedirectFailure);
        }

        // ambiguous handoff: submission_unknown.
        assert_eq!(classify_status(500), AttemptStatus::SubmissionUnknown);
        assert_eq!(classify_status(503), AttemptStatus::SubmissionUnknown);

        // no blind retry: forbidden after submission_unknown and accepted.
        assert!(blind_retry_forbidden(AttemptStatus::SubmissionUnknown));
        assert!(blind_retry_forbidden(AttemptStatus::Accepted));
        assert!(!blind_retry_forbidden(AttemptStatus::DefinitivelyRejected));
        assert!(!blind_retry_forbidden(AttemptStatus::RedirectFailure));

        // planned/actual output count: parse_response returns exactly the
        // outputs in data[].
        let png = png_bytes();
        let png_b64 = base64::engine::general_purpose::STANDARD.encode(&png);
        let body = serde_json::json!({
            "data": [{ "b64_json": png_b64 }, { "b64_json": png_b64 }]
        });
        let parsed = parse_response(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(parsed.outputs.len(), 2);

        // missing outputs produces a stable failure.
        let body = serde_json::json!({ "data": [] });
        assert!(parse_response(&serde_json::to_vec(&body).unwrap()).is_err());

        // extra outputs: the response is parsed as-is; the caller validates
        // the count against the planned n. Here we assert deterministic
        // zero-or-one dispatch: classify_status maps to exactly one status.
        let statuses = [
            (200u16, AttemptStatus::Accepted),
            (400, AttemptStatus::DefinitivelyRejected),
            (401, AttemptStatus::DefinitivelyRejected),
            (500, AttemptStatus::SubmissionUnknown),
            (301, AttemptStatus::RedirectFailure),
        ];
        for (status, expected) in statuses {
            assert_eq!(classify_status(status), expected);
        }

        // changed discovery/config races: a changed endpoint set invalidates
        // an undispatched plan (modeled by re-running preflight against a
        // different endpoint set).
        let req = OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "x".into(),
            resolution: Some("1K".into()),
            aspect_ratio: None,
            size: None,
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![],
            provider: None,
        };
        let eps = vec![endpoint_with_tag(Some("qwen"))];
        assert_eq!(preflight(&req, &eps), PreflightOutcome::Accept);
        // Config changed: endpoint removed => empty set fails closed.
        assert_eq!(
            preflight(&req, &[]),
            PreflightOutcome::Reject(PreflightReason::ResolutionNotInEveryEndpoint)
        );

        // deterministic zero-or-one dispatch assertion: blind_retry_forbidden
        // returns a deterministic bool.
        let dispatched = !blind_retry_forbidden(AttemptStatus::DefinitivelyRejected);
        assert!(dispatched); // a definitive rejection allows exactly one dispatch.
    }

    // -------------------------------------------------------------------------
    // Acceptance: openrouter_image_submit_request_carries_attribution
    // -------------------------------------------------------------------------

    fn minimal_submit_request() -> OpenrouterImageRequest {
        OpenrouterImageRequest {
            model: "qwen/qwen-image-3-pro".into(),
            prompt: "a red cube".into(),
            resolution: None,
            aspect_ratio: None,
            size: None,
            quality: None,
            output_format: None,
            background: None,
            output_compression: None,
            seed: None,
            n: 1,
            input_references: vec![],
            provider: None,
        }
    }

    fn openrouter_origin() -> ResolvedProviderOrigin {
        ResolvedProviderOrigin::template("openrouter")
    }

    fn non_template_origin() -> ResolvedProviderOrigin {
        ResolvedProviderOrigin::default()
    }

    fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn openrouter_image_submit_request_carries_attribution() {
        // No overrides: both canonical headers present with default values.
        let request = minimal_submit_request();
        let desc =
            build_submit_request("https://openrouter.ai", &openrouter_origin(), &request, &[])
                .unwrap();
        assert_eq!(
            header_value(&desc.headers, "HTTP-Referer"),
            Some("https://flycockpit.dev")
        );
        assert_eq!(
            header_value(&desc.headers, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );
    }

    // -------------------------------------------------------------------------
    // Acceptance: openrouter_image_discovery_and_endpoint_carry_attribution
    // -------------------------------------------------------------------------

    #[test]
    fn openrouter_image_discovery_and_endpoint_carry_attribution() {
        let discovery =
            build_discovery_request("https://openrouter.ai", &openrouter_origin(), &[]).unwrap();
        assert_eq!(
            header_value(&discovery.headers, "HTTP-Referer"),
            Some("https://flycockpit.dev")
        );
        assert_eq!(
            header_value(&discovery.headers, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );

        let model = ModelId::parse("qwen/qwen-image-3-pro").unwrap();
        let endpoint_req =
            build_endpoint_request("https://openrouter.ai", &openrouter_origin(), &model, &[])
                .unwrap();
        assert_eq!(
            header_value(&endpoint_req.headers, "HTTP-Referer"),
            Some("https://flycockpit.dev")
        );
        assert_eq!(
            header_value(&endpoint_req.headers, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );
    }

    // -------------------------------------------------------------------------
    // Acceptance: openrouter_image_header_override_and_empty_suppress
    // -------------------------------------------------------------------------

    #[test]
    fn openrouter_image_header_override_and_empty_suppress() {
        let request = minimal_submit_request();
        let origin = openrouter_origin();

        // Non-empty override replaces the default.
        let overrides = vec![("HTTP-Referer".to_string(), "https://custom.dev".to_string())];
        let desc =
            build_submit_request("https://openrouter.ai", &origin, &request, &overrides).unwrap();
        assert_eq!(
            header_value(&desc.headers, "HTTP-Referer"),
            Some("https://custom.dev")
        );
        // Title still gets the default.
        assert_eq!(
            header_value(&desc.headers, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );

        // Empty value suppresses that header only.
        let suppress = vec![("HTTP-Referer".to_string(), String::new())];
        let desc =
            build_submit_request("https://openrouter.ai", &origin, &request, &suppress).unwrap();
        assert!(header_value(&desc.headers, "HTTP-Referer").is_none());
        // Title is unaffected.
        assert_eq!(
            header_value(&desc.headers, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );

        // Unrelated headers are preserved.
        let unrelated = vec![
            ("X-Custom".to_string(), "value".to_string()),
            ("HTTP-Referer".to_string(), "https://custom.dev".to_string()),
        ];
        let desc =
            build_submit_request("https://openrouter.ai", &origin, &request, &unrelated).unwrap();
        assert_eq!(header_value(&desc.headers, "X-Custom"), Some("value"));
        assert_eq!(
            header_value(&desc.headers, "HTTP-Referer"),
            Some("https://custom.dev")
        );
    }

    // -------------------------------------------------------------------------
    // Acceptance: openrouter_image_redaction_is_structured
    // -------------------------------------------------------------------------

    #[test]
    fn openrouter_image_redaction_is_structured() {
        // A fake provider error payload containing a bearer token and an
        // sk-style API key, plus a long body. The redaction API returns a
        // structured summary with a stable class, bounded detail, and no
        // substring of the raw secret.
        let secret = "sk-1234567890abcdef1234567890abcdef";
        let bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret.part";
        let long_body = "x".repeat(8192);
        let payload = serde_json::json!({
            "error": {
                "message": format!("auth failed: {bearer} {secret}"),
                "body": long_body,
            }
        })
        .to_string();

        let summary = redact_provider_error(RedactionCause::Status(401), &payload);

        // Stable class derived from HTTP status.
        assert_eq!(summary.class, OpenRouterErrorClass::ClientError);

        // Detail is bounded.
        assert!(summary.detail.len() <= REDACTED_DETAIL_MAX_CHARS);

        // No substring of the raw secret survives into the summary.
        assert!(!summary.detail.contains(secret));
        assert!(!summary.detail.contains(bearer));
        assert!(
            !summary
                .detail
                .contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        );

        // The raw body is not retained.
        assert!(!summary.detail.contains(&long_body));

        // Detail is a stable, class-derived string (not the raw error.message).
        assert!(!summary.detail.contains("auth failed"));

        // Server error class.
        let server_summary = redact_provider_error(RedactionCause::Status(503), &payload);
        assert_eq!(server_summary.class, OpenRouterErrorClass::ServerError);
        assert!(!server_summary.detail.contains(secret));

        // Redirect rejected class.
        let redirect_summary = redact_provider_error(RedactionCause::Status(301), &payload);
        assert_eq!(
            redirect_summary.class,
            OpenRouterErrorClass::RedirectRejected
        );
        assert!(!redirect_summary.detail.contains(secret));

        // Transport failure (no status).
        let transport_summary = redact_provider_error(RedactionCause::Transport, &payload);
        assert_eq!(transport_summary.class, OpenRouterErrorClass::Transport);
        assert!(!transport_summary.detail.contains(secret));

        // A bare 2xx status (no decode failure) maps to Unknown, NOT
        // Unparseable — there is no error body to redact.
        let bare_2xx = redact_provider_error(RedactionCause::Status(200), &payload);
        assert_eq!(bare_2xx.class, OpenRouterErrorClass::Unknown);
        assert!(!bare_2xx.detail.contains(secret));

        // The raw free-text regex function is gone: redact_provider_error
        // returns a structured summary, not a String.
        // (This is enforced by the return type — the old `-> String` signature
        // no longer compiles.)
    }

    /// Finding 3: a decode failure (malformed 2xx output) must classify as
    /// `Unparseable`, not `Unknown`. The typed `RedactionCause::DecodeFailure`
    /// is the only way to produce `Unparseable`; a bare 2xx status stays
    /// `Unknown`. The summary still carries no secret substring.
    #[test]
    fn openrouter_image_redaction_classifies_decode_failure_as_unparseable() {
        let secret = "***********************************";
        let bearer = "Bearer ************************************************";
        // A malformed 2xx body: not valid JSON, and it echoes a secret.
        let malformed_body = format!("{{ not json: {bearer} {secret} }}");

        let summary = redact_provider_error(RedactionCause::DecodeFailure, &malformed_body);

        assert_eq!(summary.class, OpenRouterErrorClass::Unparseable);
        assert!(summary.detail.len() <= REDACTED_DETAIL_MAX_CHARS);
        // No secret substring survives into the class-derived detail.
        assert!(!summary.detail.contains(secret));
        assert!(!summary.detail.contains(bearer));
        assert!(!summary.detail.contains("not json"));
        assert_eq!(summary.detail, "provider response was not parseable");

        // Even a decode failure on a 2xx-shaped status must be Unparseable:
        // the cause is what decides the class, not the status.
        let cause_with_status = RedactionCause::DecodeFailure;
        let summary2 = redact_provider_error(cause_with_status, &malformed_body);
        assert_eq!(summary2.class, OpenRouterErrorClass::Unparseable);
    }

    // -------------------------------------------------------------------------
    // Acceptance: openrouter_adapter_cannot_bypass_shared_attribution
    // -------------------------------------------------------------------------

    /// Finding 2 conformance: replace the source-grep test with executable
    /// conformance. All three builders route header assembly through the
    /// single `apply_openrouter_attribution` constructor, which is the only
    /// call site of the shared `merge_openrouter_attribution_pairs` helper in
    /// this adapter. This test exercises the builders' actual output to prove
    /// attribution is enforced (for the openrouter template origin) and
    /// withheld (for a non-template origin) — it cannot be satisfied by an
    /// uncalled helper.
    #[test]
    fn openrouter_adapter_cannot_bypass_shared_attribution() {
        // Positive conformance: every builder, with the openrouter template
        // origin, must carry the canonical attribution pair. A builder that
        // bypassed `apply_openrouter_attribution` would emit no attribution
        // headers and fail here.
        let request = minimal_submit_request();
        let origin = openrouter_origin();

        let submit = build_submit_request("https://openrouter.ai", &origin, &request, &[]).unwrap();
        assert_eq!(
            header_value(&submit.headers, "HTTP-Referer"),
            Some("https://flycockpit.dev")
        );
        assert_eq!(
            header_value(&submit.headers, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );

        let discovery = build_discovery_request("https://openrouter.ai", &origin, &[]).unwrap();
        assert_eq!(
            header_value(&discovery.headers, "HTTP-Referer"),
            Some("https://flycockpit.dev")
        );
        assert_eq!(
            header_value(&discovery.headers, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );

        let model = ModelId::parse("qwen/qwen-image-3-pro").unwrap();
        let endpoint =
            build_endpoint_request("https://openrouter.ai", &origin, &model, &[]).unwrap();
        assert_eq!(
            header_value(&endpoint.headers, "HTTP-Referer"),
            Some("https://flycockpit.dev")
        );
        assert_eq!(
            header_value(&endpoint.headers, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );

        // The single constructor is itself the gate: with a non-template
        // origin it must NOT add attribution headers, even on an
        // openrouter.ai-shaped base URL. This is the identity decision
        // (Finding 1): attribution follows the resolved provider origin,
        // not the URL string.
        let non_template = non_template_origin();
        let mut headers: Vec<(String, String)> = Vec::new();
        apply_openrouter_attribution(&non_template, &mut headers);
        assert!(
            headers.is_empty(),
            "non-template origin must not get attribution"
        );

        let mut headers: Vec<(String, String)> = Vec::new();
        apply_openrouter_attribution(&origin, &mut headers);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "HTTP-Referer");
        assert_eq!(headers[0].1, "https://flycockpit.dev");
        assert_eq!(headers[1].0, "X-OpenRouter-Title");
        assert_eq!(headers[1].1, "FlyCockpit");

        // Structural conformance (AC6 anti-duplication clause): the behavioral
        // assertions above prove attribution reaches built requests, but they
        // would still pass if a builder locally hard-coded the canonical
        // constants and merged them inline (bypassing the shared helper). Guard
        // against that by scanning the adapter's *production* source (everything
        // before the `#[cfg(test)]` module, so this test's own literals are
        // excluded): it must not reintroduce the canonical attribution literals.
        // All attribution flows through `providers::openrouter_attribution`, so
        // any reintroduced default constant here fails the build. A deliberate
        // bypass — e.g. a builder emitting `("HTTP-Referer",
        // "https://flycockpit.dev")` directly instead of calling
        // `apply_openrouter_attribution` — would put one of these literals back
        // into production code and trip this scan.
        let source = include_str!("openrouter.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("adapter source has a production region before its test module");
        for forbidden in [
            "https://flycockpit.dev",
            "\"FlyCockpit\"",
            "\"HTTP-Referer\"",
            "\"X-OpenRouter-Title\"",
        ] {
            assert!(
                !production.contains(forbidden),
                "openrouter image adapter production code must not hardcode the attribution \
                 literal {forbidden}; route attribution through \
                 providers::openrouter_attribution's shared helper instead"
            );
        }
    }

    /// Finding 1 negative test: a non-template origin must not receive
    /// OpenRouter attribution headers from any builder, even when the base
    /// URL looks like openrouter.ai. Identity is decided by the resolved
    /// provider origin, not by the URL string.
    #[test]
    fn openrouter_image_builders_skip_attribution_for_non_template_origin() {
        let request = minimal_submit_request();
        let origin = non_template_origin();

        let submit = build_submit_request("https://openrouter.ai", &origin, &request, &[]).unwrap();
        assert!(header_value(&submit.headers, "HTTP-Referer").is_none());
        assert!(header_value(&submit.headers, "X-OpenRouter-Title").is_none());

        let discovery = build_discovery_request("https://openrouter.ai", &origin, &[]).unwrap();
        assert!(header_value(&discovery.headers, "HTTP-Referer").is_none());
        assert!(header_value(&discovery.headers, "X-OpenRouter-Title").is_none());

        let model = ModelId::parse("qwen/qwen-image-3-pro").unwrap();
        let endpoint =
            build_endpoint_request("https://openrouter.ai", &origin, &model, &[]).unwrap();
        assert!(header_value(&endpoint.headers, "HTTP-Referer").is_none());
        assert!(header_value(&endpoint.headers, "X-OpenRouter-Title").is_none());
    }

    impl InputReferenceWire {
        /// Test helper: construct the wire JSON object for this reference.
        fn wire_object_for_test(&self) -> serde_json::Value {
            serde_json::json!({
                "type": self.kind,
                "image_url": { "url": self.image_url.url }
            })
        }
    }

    // --- dispatch adapter (AC3 / AC8) ---

    fn openrouter_handoff_request() -> ImageGenerationHandoffRequest {
        ImageGenerationHandoffRequest {
            job_id: uuid::Uuid::now_v7(),
            slot_id: uuid::Uuid::now_v7(),
            attempt_number: 1,
            external_operation_id: uuid::Uuid::now_v7(),
            provider_request_identity: "request:1".into(),
            provider_idempotency_identity: "idempotency:1".into(),
            sealed_prompt: crate::image_generation_job::SealedImageGenerationPromptV1::bind(
                "fixture prompt".into(),
            )
            .unwrap(),
        }
    }

    fn openrouter_adapter_with(
        outcome: Result<ProviderTransportOutcome, ProviderTransportError>,
    ) -> (
        OpenrouterImagesAdapter,
        Arc<test_support::ScriptedOpenrouterTransport>,
    ) {
        let transport = Arc::new(test_support::ScriptedOpenrouterTransport::new(vec![
            outcome,
        ]));
        let adapter = OpenrouterImagesAdapter::new(
            transport.clone(),
            Arc::new(test_support::FixedOpenrouterPlanSource::new(
                test_support::sample_attempt_input(),
            )),
        );
        (adapter, transport)
    }

    #[tokio::test]
    async fn openrouter_adapter_accepts_2xx_and_applies_attribution_on_submit() {
        let (adapter, transport) = openrouter_adapter_with(Ok(ProviderTransportOutcome {
            status: 200,
            body: test_support::sample_success_body(),
        }));
        let result = adapter.handoff(&openrouter_handoff_request()).await;
        assert!(matches!(
            result,
            ImageGenerationHandoffResult::Accepted { .. }
        ));
        let submissions = transport.submissions();
        assert_eq!(submissions.len(), 1, "one request was built and submitted");
        let (body, headers) = &submissions[0];
        // Attribution headers are still merged on submit (AC3).
        assert!(
            headers.iter().any(|(name, _)| name == "HTTP-Referer"),
            "attribution HTTP-Referer must be applied on submit"
        );
        assert!(
            headers.iter().any(|(name, _)| name == "X-OpenRouter-Title"),
            "attribution title must be applied on submit"
        );
        // Non-vacuity: the serialized request body carries the prompt.
        assert!(body.windows(6).any(|w| w == b"prompt"));
    }

    #[tokio::test]
    async fn openrouter_adapter_3xx_is_definitive_rejection() {
        // A redirect (never followed) is a stable failure so credentials and
        // attribution cannot cross origins.
        let (adapter, _t) = openrouter_adapter_with(Err(ProviderTransportError::Status {
            status: 302,
            body: Vec::new(),
        }));
        assert!(matches!(
            adapter.handoff(&openrouter_handoff_request()).await,
            ImageGenerationHandoffResult::DefinitivelyRejected { .. }
        ));
    }

    #[tokio::test]
    async fn openrouter_adapter_ambiguous_is_submission_unknown() {
        let (adapter, _t) =
            openrouter_adapter_with(Err(ProviderTransportError::AmbiguousAcceptance));
        assert!(matches!(
            adapter.handoff(&openrouter_handoff_request()).await,
            ImageGenerationHandoffResult::SubmissionUnknown { .. }
        ));
    }

    // --- exhaustive transport-error mapping onto the shared vocabulary (AC8) ---

    #[test]
    fn openrouter_submission_disposition_is_billing_safe_for_every_variant() {
        use crate::image_generation::transport::SubmissionDisposition::*;
        assert_eq!(
            ProviderTransportError::Connect.submission_disposition(),
            DefinitivelyRejected
        );
        assert_eq!(
            ProviderTransportError::Tls.submission_disposition(),
            DefinitivelyRejected
        );
        assert_eq!(
            ProviderTransportError::Status {
                status: 404,
                body: Vec::new()
            }
            .submission_disposition(),
            DefinitivelyRejected
        );
        assert_eq!(
            ProviderTransportError::BodyLimit.submission_disposition(),
            DefinitivelyRejected
        );
        assert_eq!(
            ProviderTransportError::Malformed.submission_disposition(),
            DefinitivelyRejected
        );
        assert_eq!(
            ProviderTransportError::Timeout.submission_disposition(),
            SubmissionUnknown
        );
        assert_eq!(
            ProviderTransportError::AmbiguousAcceptance.submission_disposition(),
            SubmissionUnknown
        );
    }

    struct OpenrouterFixedDns {
        answers: Vec<std::net::IpAddr>,
    }

    impl DnsResolver for OpenrouterFixedDns {
        fn resolve<'a>(
            &'a self,
            _hostname: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Vec<std::net::IpAddr>,
                            crate::image_generation_runtime::RuntimeError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            let answers = self.answers.clone();
            Box::pin(async move { Ok(answers) })
        }
    }

    #[test]
    fn openrouter_vetted_transport_redacts_bearer_in_debug() {
        let transport = OpenrouterImagesHttpTransport::vetted(
            "https://openrouter.ai",
            "sk-or-super-secret",
            Arc::new(OpenrouterFixedDns {
                answers: vec!["93.184.216.34".parse().unwrap()],
            }),
            MAX_SUBMIT_RESPONSE_BYTES,
        )
        .expect("vetted builder accepts a clean https origin");
        let rendered = format!("{transport:?}");
        assert!(
            !rendered.contains("sk-or-super-secret"),
            "credential leaked in Debug: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
    }
}
