//! Closed, provider-neutral configuration for image-generation targets.
//!
//! Parsing and validation are pure. This module owns no probes, network
//! requests, filesystem reads, job execution, or inference-model selection.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::media_budget::MediaResourceLimits;
use super::providers::{CapabilityStatus, HeaderSpec};

pub const IMAGE_GENERATION_ROUTE_PROFILE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageAdapterKind {
    OpenaiImages,
    OpenrouterImages,
    GeminiImages,
    Comfyui,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRoute {
    Generate,
    Edit,
    DiscoverModels,
    DiscoverEndpoints,
    Submit,
    Events,
    History,
    Artifact,
    Queue,
    Job,
    Cancel,
}

impl ImageAdapterKind {
    pub const fn routes(self) -> &'static [(ImageRoute, &'static str)] {
        match self {
            Self::OpenaiImages => &[
                (ImageRoute::Generate, "/v1/images/generations"),
                (ImageRoute::Edit, "/v1/images/edits"),
            ],
            Self::OpenrouterImages => &[
                (ImageRoute::Generate, "/api/v1/images"),
                (ImageRoute::DiscoverModels, "/api/v1/images/models"),
                (
                    ImageRoute::DiscoverEndpoints,
                    "/api/v1/images/models/{author}/{slug}/endpoints",
                ),
            ],
            Self::GeminiImages => &[(ImageRoute::Generate, "/v1beta/interactions")],
            Self::Comfyui => &[
                (ImageRoute::Submit, "/prompt"),
                (ImageRoute::Events, "/ws"),
                (ImageRoute::History, "/history/{prompt_id}"),
                (ImageRoute::Artifact, "/view"),
                (ImageRoute::Queue, "/queue"),
                (ImageRoute::Job, "/api/jobs/{job_id}"),
                (ImageRoute::Cancel, "/api/jobs/{job_id}/cancel"),
            ],
        }
    }

    pub fn route(self, route: ImageRoute) -> Option<&'static str> {
        self.routes()
            .iter()
            .find_map(|(kind, value)| (*kind == route).then_some(*value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageLocationClass {
    Local,
    PrivateNetwork,
    PublicCloud,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageEndpoint {
    pub id: String,
    pub adapter: ImageAdapterKind,
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HeaderSpec>,
    #[serde(default)]
    pub allow_insecure_transport: bool,
    pub location: ImageLocationClass,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub route_profile_version: u32,
    /// Exclusive-server opt-in for no-ID `POST /interrupt`. Defaults to false
    /// because no-ID interrupt is process-global and unsafe on shared servers.
    #[serde(default, skip_serializing_if = "is_false")]
    pub exclusive_server: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn default_true() -> bool {
    true
}

impl ImageEndpoint {
    pub fn normalized(mut self) -> Result<Self, ImageGenerationConfigError> {
        validate_id("endpoint", &self.id)?;
        self.origin = normalize_origin(&self.origin, self.allow_insecure_transport)?;
        let parsed = reqwest::Url::parse(&self.origin)
            .map_err(|_| ImageGenerationConfigError::InvalidOrigin)?;
        let loopback = parsed.host_str().is_some_and(is_loopback_host);
        if (self.location == ImageLocationClass::Local && !loopback)
            || (self.location == ImageLocationClass::PublicCloud && loopback)
            || (self.allow_insecure_transport && parsed.scheme() == "https")
        {
            return Err(ImageGenerationConfigError::InvalidLocation);
        }
        self.path_prefix = normalize_path_prefix(self.path_prefix.as_deref())?;
        if self.route_profile_version != IMAGE_GENERATION_ROUTE_PROFILE_VERSION {
            return Err(ImageGenerationConfigError::UnsupportedRouteProfile {
                endpoint: self.id.clone(),
                version: self.route_profile_version,
            });
        }
        validate_headers(&self.headers)?;
        if self.credential_ref.as_deref().is_some_and(str::is_empty) {
            return Err(ImageGenerationConfigError::EmptyValue("credential_ref"));
        }
        Ok(self)
    }

    pub fn route_url(&self, route: ImageRoute) -> Result<String, ImageGenerationConfigError> {
        let relative = self
            .adapter
            .route(route)
            .ok_or(ImageGenerationConfigError::UnsupportedRoute)?;
        Ok(format!(
            "{}{}{}",
            self.origin,
            self.path_prefix.as_deref().unwrap_or(""),
            relative
        ))
    }

    pub fn immutable_identity(&self) -> String {
        digest_serializable(&(
            &self.id,
            self.adapter,
            &self.origin,
            &self.path_prefix,
            &self.credential_ref,
            &self.headers,
            self.allow_insecure_transport,
            self.location,
            self.route_profile_version,
            self.exclusive_server,
        ))
    }
}

fn validate_headers(headers: &[HeaderSpec]) -> Result<(), ImageGenerationConfigError> {
    let mut names = BTreeSet::new();
    for header in headers {
        if header.name.is_empty() || header.value.is_empty() {
            return Err(ImageGenerationConfigError::EmptyValue("header"));
        }
        let folded = header.name.to_ascii_lowercase();
        if !names.insert(folded) {
            return Err(ImageGenerationConfigError::Duplicate("header"));
        }
    }
    Ok(())
}

pub fn normalize_origin(
    value: &str,
    allow_insecure: bool,
) -> Result<String, ImageGenerationConfigError> {
    let url = reqwest::Url::parse(value).map_err(|_| ImageGenerationConfigError::InvalidOrigin)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ImageGenerationConfigError::InvalidOrigin);
    }
    if url.scheme() == "http"
        && !is_loopback_host(url.host_str().unwrap_or_default())
        && !allow_insecure
    {
        return Err(ImageGenerationConfigError::InsecureTransportRequiresOptIn);
    }
    let mut normalized = url;
    normalized.set_path("");
    Ok(normalized.as_str().trim_end_matches('/').to_owned())
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub fn normalize_path_prefix(
    value: Option<&str>,
) -> Result<Option<String>, ImageGenerationConfigError> {
    let Some(value) = value else { return Ok(None) };
    if value.is_empty() || value.contains('?') || value.contains('#') || value.contains('\\') {
        return Err(ImageGenerationConfigError::InvalidPathPrefix);
    }
    let trimmed = value.strip_prefix('/').unwrap_or(value);
    let trimmed = trimmed.strip_suffix('/').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Ok(None);
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.starts_with('/')
        || trimmed.ends_with('/')
        || lower.contains('%')
        || !trimmed.split('/').all(|segment| {
            segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
        })
        || trimmed
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ImageGenerationConfigError::InvalidPathPrefix);
    }
    Ok(Some(format!("/{trimmed}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageFormat {
    Png,
    Jpeg,
    Webp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceImageSupport {
    Unsupported,
    Optional,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum ImageTargetIdentity {
    HostedModel {
        model: String,
    },
    Workflow {
        workflow_id: String,
        workflow_digest: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageParameter {
    Seed,
    Steps,
    GuidanceScaleMilli,
    NegativePrompt,
    Quality,
    Style,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum ImageParameterDescriptor {
    Integer {
        parameter: ImageParameter,
        min: i64,
        max: i64,
    },
    Text {
        parameter: ImageParameter,
        max_bytes: u64,
    },
    Choice {
        parameter: ImageParameter,
        values: Vec<String>,
    },
}

impl ImageParameterDescriptor {
    fn parameter(&self) -> ImageParameter {
        match self {
            Self::Integer { parameter, .. }
            | Self::Text { parameter, .. }
            | Self::Choice { parameter, .. } => *parameter,
        }
    }
    fn validate(&self) -> Result<(), ImageGenerationConfigError> {
        match self {
            Self::Integer { min, max, .. } if min > max => {
                Err(ImageGenerationConfigError::InvalidParameter)
            }
            Self::Text { max_bytes: 0, .. } => Err(ImageGenerationConfigError::InvalidParameter),
            Self::Choice { values, .. } if values.is_empty() || has_empty_or_duplicates(values) => {
                Err(ImageGenerationConfigError::InvalidParameter)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageDimensionCandidate {
    pub width: u64,
    pub height: u64,
    pub provider_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum ImageDimensionDescriptor {
    Discrete {
        candidates: Vec<ImageDimensionCandidate>,
    },
    RangeStep {
        min_width: u64,
        max_width: u64,
        width_step: u64,
        min_height: u64,
        max_height: u64,
        height_step: u64,
        provider_value_format: RangeProviderValueFormat,
    },
    AspectTier {
        tiers: Vec<ImageDimensionCandidate>,
    },
    ProviderDefault,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RangeProviderValueFormat {
    WidthXHeight,
}

impl RangeProviderValueFormat {
    fn format(self, width: u64, height: u64) -> String {
        match self {
            Self::WidthXHeight => format!("{width}x{height}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageDimensionRequestPolicy {
    #[default]
    Exact,
    Nearest,
    ProviderDefault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageDimensionResolution {
    Resolved(ImageDimensionCandidate),
    ProviderDefault,
    Unsupported {
        alternatives: Vec<ImageDimensionCandidate>,
    },
    Unknown,
}

impl ImageDimensionDescriptor {
    fn validate(&self) -> Result<(), ImageGenerationConfigError> {
        match self {
            Self::Discrete { candidates } | Self::AspectTier { tiers: candidates } => {
                if candidates.is_empty() {
                    return Err(ImageGenerationConfigError::InvalidDimensions);
                }
                let mut values = BTreeSet::new();
                for candidate in candidates {
                    validate_candidate(candidate)?;
                    if !values.insert(&candidate.provider_value) {
                        return Err(ImageGenerationConfigError::Duplicate(
                            "dimension provider value",
                        ));
                    }
                }
            }
            Self::RangeStep {
                min_width,
                max_width,
                width_step,
                min_height,
                max_height,
                height_step,
                provider_value_format: _,
            } => {
                if *min_width == 0
                    || *min_height == 0
                    || *width_step == 0
                    || *height_step == 0
                    || min_width > max_width
                    || min_height > max_height
                    || (*max_width - *min_width) % *width_step != 0
                    || (*max_height - *min_height) % *height_step != 0
                    || *max_width > MediaResourceLimits::hard_ceilings().decoded_edge_pixels
                    || *max_height > MediaResourceLimits::hard_ceilings().decoded_edge_pixels
                    || max_width.checked_mul(*max_height).is_none_or(|pixels| {
                        pixels > MediaResourceLimits::hard_ceilings().decoded_image_pixels
                    })
                {
                    return Err(ImageGenerationConfigError::InvalidDimensions);
                }
            }
            Self::ProviderDefault | Self::Unknown => {}
        }
        Ok(())
    }

    pub fn resolve(
        &self,
        policy: ImageDimensionRequestPolicy,
        width: Option<u64>,
        height: Option<u64>,
    ) -> Result<ImageDimensionResolution, ImageGenerationConfigError> {
        self.validate()?;
        if policy == ImageDimensionRequestPolicy::ProviderDefault {
            return Ok(ImageDimensionResolution::ProviderDefault);
        }
        let (Some(width), Some(height)) = (width, height) else {
            return Ok(match self {
                Self::ProviderDefault => ImageDimensionResolution::ProviderDefault,
                Self::Unknown => ImageDimensionResolution::Unknown,
                _ => ImageDimensionResolution::Unsupported {
                    alternatives: self.alternatives(),
                },
            });
        };
        let requested_pixels = width
            .checked_mul(height)
            .ok_or(ImageGenerationConfigError::ArithmeticOverflow)?;
        let ceilings = MediaResourceLimits::hard_ceilings();
        if width == 0
            || height == 0
            || width > ceilings.decoded_edge_pixels
            || height > ceilings.decoded_edge_pixels
            || requested_pixels > ceilings.decoded_image_pixels
        {
            return Err(ImageGenerationConfigError::InvalidDimensions);
        }
        match self {
            Self::ProviderDefault => Ok(ImageDimensionResolution::ProviderDefault),
            Self::Unknown => Ok(ImageDimensionResolution::Unknown),
            Self::Discrete { candidates } | Self::AspectTier { tiers: candidates } => {
                if let Some(exact) = candidates
                    .iter()
                    .find(|c| c.width == width && c.height == height)
                {
                    return Ok(ImageDimensionResolution::Resolved(exact.clone()));
                }
                if policy == ImageDimensionRequestPolicy::Exact {
                    return Ok(ImageDimensionResolution::Unsupported {
                        alternatives: candidates.clone(),
                    });
                }
                Ok(ImageDimensionResolution::Resolved(
                    nearest(candidates, width, height)?.clone(),
                ))
            }
            Self::RangeStep {
                min_width,
                max_width,
                width_step,
                min_height,
                max_height,
                height_step,
                provider_value_format,
            } => {
                let exact = in_step(width, *min_width, *max_width, *width_step)
                    && in_step(height, *min_height, *max_height, *height_step);
                if exact {
                    return Ok(ImageDimensionResolution::Resolved(
                        ImageDimensionCandidate {
                            width,
                            height,
                            provider_value: provider_value_format.format(width, height),
                        },
                    ));
                }
                if policy == ImageDimensionRequestPolicy::Exact {
                    let widths = nearest_step_values(width, *min_width, *max_width, *width_step)?;
                    let heights =
                        nearest_step_values(height, *min_height, *max_height, *height_step)?;
                    let mut candidates = Vec::new();
                    for w in widths {
                        for h in &heights {
                            candidates.push(ImageDimensionCandidate {
                                width: w,
                                height: *h,
                                provider_value: provider_value_format.format(w, *h),
                            });
                        }
                    }
                    return Ok(ImageDimensionResolution::Unsupported {
                        alternatives: candidates,
                    });
                }
                let spec = RangeStepSpec {
                    min_width: *min_width,
                    max_width: *max_width,
                    width_step: *width_step,
                    min_height: *min_height,
                    max_height: *max_height,
                    height_step: *height_step,
                    format: *provider_value_format,
                };
                let candidates = range_nearest_candidates(width, height, spec)?;
                Ok(ImageDimensionResolution::Resolved(
                    nearest(&candidates, width, height)?.clone(),
                ))
            }
        }
    }

    fn alternatives(&self) -> Vec<ImageDimensionCandidate> {
        match self {
            Self::Discrete { candidates } | Self::AspectTier { tiers: candidates } => {
                candidates.clone()
            }
            Self::RangeStep {
                min_width,
                max_width,
                min_height,
                max_height,
                provider_value_format,
                ..
            } => {
                let mut out = Vec::new();
                for width in [*min_width, *max_width] {
                    for height in [*min_height, *max_height] {
                        let candidate = ImageDimensionCandidate {
                            width,
                            height,
                            provider_value: provider_value_format.format(width, height),
                        };
                        if !out.contains(&candidate) {
                            out.push(candidate);
                        }
                    }
                }
                out
            }
            Self::ProviderDefault | Self::Unknown => Vec::new(),
        }
    }
}

#[derive(Clone, Copy)]
struct RangeStepSpec {
    min_width: u64,
    max_width: u64,
    width_step: u64,
    min_height: u64,
    max_height: u64,
    height_step: u64,
    format: RangeProviderValueFormat,
}

fn range_nearest_candidates(
    requested_width: u64,
    requested_height: u64,
    spec: RangeStepSpec,
) -> Result<Vec<ImageDimensionCandidate>, ImageGenerationConfigError> {
    let mut candidates = Vec::new();
    let mut width = spec.min_width;
    loop {
        let ideal_height = width
            .checked_mul(requested_height)
            .ok_or(ImageGenerationConfigError::ArithmeticOverflow)?
            / requested_width;
        for height in nearest_step_values(
            ideal_height,
            spec.min_height,
            spec.max_height,
            spec.height_step,
        )? {
            candidates.push(ImageDimensionCandidate {
                width,
                height,
                provider_value: spec.format.format(width, height),
            });
        }
        if width == spec.max_width {
            break;
        }
        width = width
            .checked_add(spec.width_step)
            .ok_or(ImageGenerationConfigError::ArithmeticOverflow)?;
        if width > spec.max_width {
            break;
        }
    }
    Ok(candidates)
}

fn validate_candidate(
    candidate: &ImageDimensionCandidate,
) -> Result<(), ImageGenerationConfigError> {
    let ceiling = MediaResourceLimits::hard_ceilings();
    if candidate.width == 0
        || candidate.height == 0
        || candidate.provider_value.is_empty()
        || candidate.width > ceiling.decoded_edge_pixels
        || candidate.height > ceiling.decoded_edge_pixels
        || candidate
            .width
            .checked_mul(candidate.height)
            .is_none_or(|pixels| pixels > ceiling.decoded_image_pixels)
    {
        return Err(ImageGenerationConfigError::InvalidDimensions);
    }
    Ok(())
}

fn in_step(value: u64, min: u64, max: u64, step: u64) -> bool {
    (min..=max).contains(&value) && (value - min).is_multiple_of(step)
}

fn nearest_step_values(
    requested: u64,
    min: u64,
    max: u64,
    step: u64,
) -> Result<Vec<u64>, ImageGenerationConfigError> {
    let clamped = requested.clamp(min, max);
    let offset = clamped - min;
    let lower = min
        .checked_add(
            (offset / step)
                .checked_mul(step)
                .ok_or(ImageGenerationConfigError::ArithmeticOverflow)?,
        )
        .ok_or(ImageGenerationConfigError::ArithmeticOverflow)?;
    let upper = lower.checked_add(step).filter(|v| *v <= max);
    let mut out = vec![lower];
    if let Some(upper) = upper.filter(|v| *v != lower) {
        out.push(upper);
    }
    Ok(out)
}

fn nearest(
    candidates: &[ImageDimensionCandidate],
    width: u64,
    height: u64,
) -> Result<&ImageDimensionCandidate, ImageGenerationConfigError> {
    let requested_pixels = width
        .checked_mul(height)
        .ok_or(ImageGenerationConfigError::ArithmeticOverflow)?;
    candidates
        .iter()
        .min_by(|a, b| compare_candidate(a, b, width, height, requested_pixels))
        .ok_or(ImageGenerationConfigError::InvalidDimensions)
}

fn compare_candidate(
    a: &ImageDimensionCandidate,
    b: &ImageDimensionCandidate,
    width: u64,
    height: u64,
    requested_pixels: u64,
) -> Ordering {
    let aspect_a = (u128::from(a.width) * u128::from(height))
        .abs_diff(u128::from(width) * u128::from(a.height));
    let aspect_b = (u128::from(b.width) * u128::from(height))
        .abs_diff(u128::from(width) * u128::from(b.height));
    let pixels_a = u128::from(a.width) * u128::from(a.height);
    let pixels_b = u128::from(b.width) * u128::from(b.height);
    let requested_pixels = u128::from(requested_pixels);
    (aspect_a * u128::from(b.height))
        .cmp(&(aspect_b * u128::from(a.height)))
        .then_with(|| {
            pixels_a
                .abs_diff(requested_pixels)
                .cmp(&pixels_b.abs_diff(requested_pixels))
        })
        .then_with(|| pixels_a.cmp(&pixels_b))
        .then_with(|| a.provider_value.cmp(&b.provider_value))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenRouterSort {
    Price,
    Throughput,
    Latency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenRouterImageRouting {
    #[serde(default)]
    pub only: Vec<String>,
    #[serde(default)]
    pub order: Vec<String>,
    #[serde(default)]
    pub ignore: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<OpenRouterSort>,
    pub allow_fallbacks: bool,
}

impl OpenRouterImageRouting {
    pub fn validate_provider_allowlist(
        &self,
        allowlist: &[String],
    ) -> Result<(), ImageGenerationConfigError> {
        if has_empty_or_duplicates(allowlist) {
            return Err(ImageGenerationConfigError::InvalidOpenRouterRouting);
        }
        self.validate(&allowlist.iter().cloned().collect())
    }

    fn validate(&self, allowlist: &BTreeSet<String>) -> Result<(), ImageGenerationConfigError> {
        for values in [&self.only, &self.order, &self.ignore] {
            if has_empty_or_duplicates(values)
                || values
                    .iter()
                    .any(|v| !valid_provider_slug(v) || !allowlist.contains(v))
            {
                return Err(ImageGenerationConfigError::InvalidOpenRouterRouting);
            }
        }
        if self.only.iter().any(|v| self.ignore.contains(v))
            || self.order.iter().any(|v| self.ignore.contains(v))
            || (!self.only.is_empty() && self.order.iter().any(|v| !self.only.contains(v)))
            || (!self.allow_fallbacks && self.only.is_empty() && self.order.is_empty())
        {
            return Err(ImageGenerationConfigError::InvalidOpenRouterRouting);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum ImageEvidence {
    CheckedIn {
        source_url: String,
        last_verified: DateTime<Utc>,
    },
    Discovered {
        source_url: String,
        fetched_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        endpoint_identity: String,
    },
    WorkflowDeclared {
        workflow_digest: String,
    },
    UserOverride {
        configured_at: DateTime<Utc>,
    },
}

impl ImageEvidence {
    pub fn is_stale_at(&self, now: DateTime<Utc>) -> bool {
        matches!(self, Self::Discovered { expires_at, .. } if *expires_at <= now)
    }
    fn validate(&self) -> Result<(), ImageGenerationConfigError> {
        match self {
            Self::CheckedIn { source_url, .. } if !valid_source_url(source_url) => {
                Err(ImageGenerationConfigError::InvalidEvidence)
            }
            Self::Discovered {
                source_url,
                fetched_at,
                expires_at,
                endpoint_identity,
            } if !valid_source_url(source_url)
                || fetched_at >= expires_at
                || endpoint_identity.is_empty() =>
            {
                Err(ImageGenerationConfigError::InvalidEvidence)
            }
            Self::WorkflowDeclared { workflow_digest } if !is_sha256(workflow_digest) => {
                Err(ImageGenerationConfigError::InvalidEvidence)
            }
            _ => Ok(()),
        }
    }
}

fn valid_source_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageCapabilityEvidence {
    #[serde(rename = "status")]
    declared_status: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ImageEvidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImageCapabilityEvidence {
    status: CapabilityStatus,
    #[serde(default)]
    evidence: Option<ImageEvidence>,
}

impl<'de> Deserialize<'de> for ImageCapabilityEvidence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawImageCapabilityEvidence::deserialize(deserializer)?;
        Self::new(raw.status, raw.evidence).map_err(serde::de::Error::custom)
    }
}

impl ImageCapabilityEvidence {
    pub fn new(
        status: CapabilityStatus,
        evidence: Option<ImageEvidence>,
    ) -> Result<Self, ImageGenerationConfigError> {
        let value = Self {
            declared_status: status,
            evidence,
        };
        value.validate()?;
        Ok(value)
    }
    pub const fn declared_status(&self) -> CapabilityStatus {
        self.declared_status
    }
    pub fn effective_status_at(&self, now: DateTime<Utc>) -> CapabilityStatus {
        if self.evidence.as_ref().is_some_and(|e| e.is_stale_at(now)) {
            CapabilityStatus::Unknown
        } else {
            self.declared_status
        }
    }
    fn validate(&self) -> Result<(), ImageGenerationConfigError> {
        if self.declared_status == CapabilityStatus::Supported && self.evidence.is_none() {
            return Err(ImageGenerationConfigError::MissingEvidence);
        }
        if let Some(evidence) = &self.evidence {
            evidence.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageBillableUnit {
    Image,
    Megapixel,
    Second,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImagePriceMethod {
    ConservativeMaximum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum ImagePrice {
    Unknown,
    Known {
        usd_micros: u64,
        unit: ImageBillableUnit,
        variant: String,
        method: ImagePriceMethod,
        evidence: ImageEvidence,
    },
}

impl ImagePrice {
    pub fn effective_at(&self, now: DateTime<Utc>) -> Self {
        match self {
            Self::Known { evidence, .. } if evidence.is_stale_at(now) => Self::Unknown,
            _ => self.clone(),
        }
    }
    fn validate(&self) -> Result<(), ImageGenerationConfigError> {
        if let Self::Known {
            usd_micros,
            variant,
            evidence,
            ..
        } = self
        {
            if *usd_micros == 0 || variant.is_empty() {
                return Err(ImageGenerationConfigError::InvalidPrice);
            }
            evidence.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageGenerationTarget {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub endpoint_id: String,
    pub identity: ImageTargetIdentity,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub is_default: bool,
    pub formats: Vec<ImageFormat>,
    pub reference_support: ReferenceImageSupport,
    pub max_reference_images: u64,
    pub max_samples: u64,
    pub max_outputs: u64,
    pub dimensions: ImageDimensionDescriptor,
    #[serde(default)]
    pub dimension_policy: ImageDimensionRequestPolicy,
    #[serde(default)]
    pub parameters: Vec<ImageParameterDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openrouter_routing: Option<OpenRouterImageRouting>,
    pub generation_capability: ImageCapabilityEvidence,
    pub price: ImagePrice,
}

impl ImageGenerationTarget {
    fn immutable_identity(
        &self,
        endpoint: &ImageEndpoint,
        workflow: Option<&RegisteredComfyWorkflow>,
    ) -> String {
        digest_serializable(&(
            &self.id,
            endpoint.immutable_identity(),
            &self.identity,
            &self.formats,
            self.reference_support,
            self.max_reference_images,
            self.max_samples,
            self.max_outputs,
            &self.dimensions,
            self.dimension_policy,
            &self.parameters,
            &self.openrouter_routing,
            workflow.map(RegisteredComfyWorkflow::binding_digest),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowValueType {
    Integer,
    DecimalMilli,
    Text,
    Image,
    Latent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowBinding {
    pub parameter: ImageParameter,
    pub node_id: String,
    pub input: String,
    pub value_type: WorkflowValueType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowOutput {
    pub node_id: String,
    pub output: String,
    pub value_type: WorkflowValueType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredComfyWorkflow {
    pub id: String,
    pub graph_json: String,
    pub graph_digest: String,
    pub bindings: Vec<WorkflowBinding>,
    pub outputs: Vec<WorkflowOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeWorkflowProjection {
    pub id: String,
    pub graph_digest: String,
    pub parameters: Vec<SafeWorkflowParameter>,
    pub output_types: Vec<WorkflowValueType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeWorkflowParameter {
    pub parameter: ImageParameter,
    pub value_type: WorkflowValueType,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

impl RegisteredComfyWorkflow {
    pub fn safe_projection(&self) -> SafeWorkflowProjection {
        SafeWorkflowProjection {
            id: self.id.clone(),
            graph_digest: self.graph_digest.clone(),
            parameters: self
                .bindings
                .iter()
                .map(|b| SafeWorkflowParameter {
                    parameter: b.parameter,
                    value_type: b.value_type,
                    min: b.min,
                    max: b.max,
                })
                .collect(),
            output_types: self.outputs.iter().map(|o| o.value_type).collect(),
        }
    }
    pub fn binding_digest(&self) -> String {
        digest_serializable(&(&self.bindings, &self.outputs))
    }
    fn validate(&self) -> Result<(), ImageGenerationConfigError> {
        validate_id("workflow", &self.id)?;
        let graph: serde_json::Value = serde_json::from_str(&self.graph_json)
            .map_err(|_| ImageGenerationConfigError::InvalidWorkflow)?;
        let nodes = graph
            .as_object()
            .ok_or(ImageGenerationConfigError::InvalidWorkflow)?;
        if nodes.is_empty() {
            return Err(ImageGenerationConfigError::InvalidWorkflow);
        }
        if canonical_workflow_digest(&self.graph_json)? != self.graph_digest {
            return Err(ImageGenerationConfigError::WorkflowDigestMismatch(
                self.id.clone(),
            ));
        }
        if self.bindings.is_empty() || self.outputs.is_empty() {
            return Err(ImageGenerationConfigError::InvalidWorkflow);
        }
        let mut params = BTreeSet::new();
        for binding in &self.bindings {
            if binding.node_id.is_empty()
                || binding.input.is_empty()
                || !params.insert(binding.parameter)
                || binding
                    .min
                    .zip(binding.max)
                    .is_some_and(|(min, max)| min > max)
            {
                return Err(ImageGenerationConfigError::InvalidWorkflow);
            }
            let inputs = nodes
                .get(&binding.node_id)
                .and_then(|node| node.get("inputs"))
                .and_then(serde_json::Value::as_object)
                .ok_or(ImageGenerationConfigError::InvalidWorkflow)?;
            if !inputs.contains_key(&binding.input) {
                return Err(ImageGenerationConfigError::InvalidWorkflow);
            }
        }
        for output in &self.outputs {
            if output.node_id.is_empty()
                || output.output.is_empty()
                || !nodes.contains_key(&output.node_id)
            {
                return Err(ImageGenerationConfigError::InvalidWorkflow);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageGenerationConfig {
    endpoints: Vec<ImageEndpoint>,
    targets: Vec<ImageGenerationTarget>,
    workflows: Vec<RegisteredComfyWorkflow>,
    openrouter_provider_allowlist: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImageGenerationConfig {
    #[serde(default)]
    endpoints: Vec<ImageEndpoint>,
    #[serde(default)]
    targets: Vec<ImageGenerationTarget>,
    #[serde(default)]
    workflows: Vec<RegisteredComfyWorkflow>,
    #[serde(default)]
    openrouter_provider_allowlist: Vec<String>,
}

impl<'de> Deserialize<'de> for ImageGenerationConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawImageGenerationConfig::deserialize(deserializer)?;
        Self::new(
            raw.endpoints,
            raw.targets,
            raw.workflows,
            raw.openrouter_provider_allowlist,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ImageGenerationConfig {
    pub fn endpoints(&self) -> &[ImageEndpoint] {
        &self.endpoints
    }
    pub fn targets(&self) -> &[ImageGenerationTarget] {
        &self.targets
    }
    pub fn workflows(&self) -> &[RegisteredComfyWorkflow] {
        &self.workflows
    }
    pub fn openrouter_provider_allowlist(&self) -> &[String] {
        &self.openrouter_provider_allowlist
    }

    /// The registry as it may appear in a config SNAPSHOT that crosses a trust
    /// boundary (e.g. the daemon session config snapshot): the empty registry.
    ///
    /// Image-generation config is secret-bearing in several places — endpoint
    /// header values and `credential_ref`s, capability/price evidence
    /// `source_url` query strings, and opaque workflow `graph_json` where a
    /// token can hide anywhere — so it cannot be selectively scrubbed. Partial
    /// in-place redaction is also unsafe: blanking an endpoint's
    /// header/credential fields changes its immutable identity, which the
    /// discovered-evidence `endpoint_identity` binding then rejects, so a
    /// reconstruct-through-[`Self::new`] redaction would fail. Until a future
    /// settings-UI prompt owns a safe non-secret projection, the snapshot omits
    /// image-generation content entirely by emitting the empty registry.
    pub fn redacted_for_snapshot(&self) -> ImageGenerationConfig {
        ImageGenerationConfig::default()
    }

    pub fn target_immutable_identity(
        &self,
        target_id: &str,
    ) -> Result<String, ImageGenerationConfigError> {
        let target = self
            .targets
            .iter()
            .find(|target| target.id == target_id)
            .ok_or_else(|| ImageGenerationConfigError::MissingTarget(target_id.to_owned()))?;
        let endpoint = self
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id == target.endpoint_id)
            .ok_or_else(|| {
                ImageGenerationConfigError::MissingEndpoint(target.endpoint_id.clone())
            })?;
        let workflow = match &target.identity {
            ImageTargetIdentity::Workflow {
                workflow_id,
                workflow_digest,
            } => {
                let workflow = self
                    .workflows
                    .iter()
                    .find(|workflow| workflow.id == *workflow_id)
                    .ok_or_else(|| {
                        ImageGenerationConfigError::MissingWorkflow(workflow_id.clone())
                    })?;
                if workflow.graph_digest != *workflow_digest {
                    return Err(ImageGenerationConfigError::WorkflowDigestMismatch(
                        workflow_id.clone(),
                    ));
                }
                Some(workflow)
            }
            ImageTargetIdentity::HostedModel { .. } => None,
        };
        Ok(target.immutable_identity(endpoint, workflow))
    }

    pub fn new(
        endpoints: Vec<ImageEndpoint>,
        targets: Vec<ImageGenerationTarget>,
        workflows: Vec<RegisteredComfyWorkflow>,
        allowlist: Vec<String>,
    ) -> Result<Self, ImageGenerationConfigError> {
        if allowlist.iter().any(String::is_empty) {
            return Err(ImageGenerationConfigError::EmptyValue(
                "OpenRouter provider",
            ));
        }
        if allowlist.iter().any(|value| !valid_provider_slug(value)) {
            return Err(ImageGenerationConfigError::InvalidId("OpenRouter provider"));
        }
        if has_duplicates(&allowlist) {
            return Err(ImageGenerationConfigError::Duplicate("OpenRouter provider"));
        }
        let allowset: BTreeSet<String> = allowlist.iter().cloned().collect();
        let endpoints: Vec<_> = endpoints
            .into_iter()
            .map(ImageEndpoint::normalized)
            .collect::<Result<_, _>>()?;
        ensure_unique(endpoints.iter().map(|v| v.id.as_str()), "endpoint")?;
        ensure_unique(targets.iter().map(|v| v.id.as_str()), "target")?;
        ensure_unique(workflows.iter().map(|v| v.id.as_str()), "workflow")?;
        for workflow in &workflows {
            workflow.validate()?;
        }
        let endpoint_map: BTreeMap<_, _> = endpoints.iter().map(|v| (v.id.as_str(), v)).collect();
        let workflow_map: BTreeMap<_, _> = workflows.iter().map(|v| (v.id.as_str(), v)).collect();
        let mut enabled = 0_u64;
        let mut defaults = 0_u64;
        for target in &targets {
            validate_id("target", &target.id)?;
            if target.enabled {
                enabled = enabled
                    .checked_add(1)
                    .ok_or(ImageGenerationConfigError::ArithmeticOverflow)?;
            }
            if target.is_default {
                defaults = defaults
                    .checked_add(1)
                    .ok_or(ImageGenerationConfigError::ArithmeticOverflow)?;
            }
            if target.is_default && !target.enabled {
                return Err(ImageGenerationConfigError::DefaultTargetDisabled);
            }
            let endpoint = endpoint_map.get(target.endpoint_id.as_str());
            if target.enabled && endpoint.is_none() {
                return Err(ImageGenerationConfigError::MissingEndpoint(
                    target.endpoint_id.clone(),
                ));
            }
            if target.enabled && endpoint.is_some_and(|e| !e.enabled) {
                return Err(ImageGenerationConfigError::DisabledEndpoint(
                    target.endpoint_id.clone(),
                ));
            }
            validate_target(target, endpoint.copied(), &workflow_map, &allowset)?;
        }
        if (enabled == 0 && defaults != 0) || (enabled != 0 && defaults != 1) {
            return Err(ImageGenerationConfigError::InvalidDefaultCount { enabled, defaults });
        }
        Ok(Self {
            endpoints,
            targets,
            workflows,
            openrouter_provider_allowlist: allowlist,
        })
    }
}

impl Default for ImageGenerationConfig {
    /// The empty registry: zero endpoints, targets, and workflows, and an
    /// empty OpenRouter allowlist. Always valid (`enabled == 0 && defaults
    /// == 0`), so `ExtendedConfig::default()` and a bare `{}` deserialize to
    /// the same value. "Empty" means *no generation targets configured*; it
    /// never invents endpoints.
    fn default() -> Self {
        Self::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
            .expect("empty image-generation registry is always valid")
    }
}

fn validate_target(
    target: &ImageGenerationTarget,
    endpoint: Option<&ImageEndpoint>,
    workflows: &BTreeMap<&str, &RegisteredComfyWorkflow>,
    allowlist: &BTreeSet<String>,
) -> Result<(), ImageGenerationConfigError> {
    let ceilings = MediaResourceLimits::hard_ceilings();
    if target.formats.is_empty()
        || has_duplicates(&target.formats)
        || target.max_samples == 0
        || target.max_samples > ceilings.generated_outputs_per_request
        || target.max_outputs == 0
        || target.max_outputs > ceilings.generated_outputs_per_request
        || target.max_reference_images > ceilings.reference_images_per_request
        || (target.reference_support == ReferenceImageSupport::Unsupported
            && target.max_reference_images != 0)
        || (target.reference_support != ReferenceImageSupport::Unsupported
            && target.max_reference_images == 0)
    {
        return Err(ImageGenerationConfigError::InvalidTargetLimits);
    }
    target.dimensions.validate()?;
    let mut parameters = BTreeSet::new();
    for descriptor in &target.parameters {
        descriptor.validate()?;
        if !parameters.insert(descriptor.parameter()) {
            return Err(ImageGenerationConfigError::Duplicate("parameter"));
        }
    }
    target.generation_capability.validate()?;
    target.price.validate()?;
    if let Some(endpoint) = endpoint {
        validate_evidence_endpoint(target.generation_capability.evidence.as_ref(), endpoint)?;
        if let ImagePrice::Known { evidence, .. } = &target.price {
            validate_evidence_endpoint(Some(evidence), endpoint)?;
        }
    }
    match (&target.identity, endpoint.map(|e| e.adapter)) {
        (
            ImageTargetIdentity::Workflow {
                workflow_id,
                workflow_digest,
            },
            Some(ImageAdapterKind::Comfyui),
        ) => {
            if target.enabled {
                let workflow = workflows.get(workflow_id.as_str()).ok_or_else(|| {
                    ImageGenerationConfigError::MissingWorkflow(workflow_id.clone())
                })?;
                if &workflow.graph_digest != workflow_digest {
                    return Err(ImageGenerationConfigError::WorkflowDigestMismatch(
                        workflow_id.clone(),
                    ));
                }
                if target.parameters.len() != workflow.bindings.len()
                    || target.parameters.iter().any(|descriptor| {
                        workflow
                            .bindings
                            .iter()
                            .find(|binding| binding.parameter == descriptor.parameter())
                            .is_none_or(|binding| !binding_accepts(binding, descriptor))
                    })
                {
                    return Err(ImageGenerationConfigError::InvalidWorkflow);
                }
                if let Some(ImageEvidence::WorkflowDeclared {
                    workflow_digest: evidence_digest,
                }) = &target.generation_capability.evidence
                    && evidence_digest != workflow_digest
                {
                    return Err(ImageGenerationConfigError::InvalidEvidence);
                }
            }
        }
        (ImageTargetIdentity::HostedModel { model }, Some(adapter))
            if adapter != ImageAdapterKind::Comfyui =>
        {
            if model.is_empty() {
                return Err(ImageGenerationConfigError::EmptyValue("model"));
            }
            if adapter == ImageAdapterKind::OpenrouterImages {
                let mut parts = model.split('/');
                if parts.next().is_none_or(str::is_empty)
                    || parts.next().is_none_or(str::is_empty)
                    || parts.next().is_some()
                {
                    return Err(ImageGenerationConfigError::WrongAdapterIdentity);
                }
            }
        }
        (_, None) if !target.enabled => {}
        _ => return Err(ImageGenerationConfigError::WrongAdapterIdentity),
    }
    match (&target.openrouter_routing, endpoint.map(|e| e.adapter)) {
        (Some(routing), Some(ImageAdapterKind::OpenrouterImages)) => routing.validate(allowlist)?,
        (Some(_), None) if !target.enabled => {}
        (None, _) => {}
        _ => return Err(ImageGenerationConfigError::WrongAdapterIdentity),
    }
    Ok(())
}

fn validate_evidence_endpoint(
    evidence: Option<&ImageEvidence>,
    endpoint: &ImageEndpoint,
) -> Result<(), ImageGenerationConfigError> {
    if let Some(ImageEvidence::Discovered {
        endpoint_identity, ..
    }) = evidence
        && endpoint_identity != &endpoint.immutable_identity()
    {
        return Err(ImageGenerationConfigError::InvalidEvidence);
    }
    Ok(())
}

fn binding_accepts(binding: &WorkflowBinding, descriptor: &ImageParameterDescriptor) -> bool {
    match (binding.value_type, descriptor) {
        (WorkflowValueType::Integer, ImageParameterDescriptor::Integer { min, max, .. })
        | (WorkflowValueType::DecimalMilli, ImageParameterDescriptor::Integer { min, max, .. }) => {
            binding.min.is_none_or(|bound| *min >= bound)
                && binding.max.is_none_or(|bound| *max <= bound)
        }
        (WorkflowValueType::Text, ImageParameterDescriptor::Text { .. })
        | (WorkflowValueType::Text, ImageParameterDescriptor::Choice { .. }) => true,
        _ => false,
    }
}

fn validate_id(kind: &'static str, value: &str) -> Result<(), ImageGenerationConfigError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(ImageGenerationConfigError::InvalidId(kind));
    }
    Ok(())
}

fn ensure_unique<'a>(
    values: impl Iterator<Item = &'a str>,
    kind: &'static str,
) -> Result<(), ImageGenerationConfigError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_id(kind, value)?;
        if !seen.insert(value) {
            return Err(ImageGenerationConfigError::Duplicate(kind));
        }
    }
    Ok(())
}

fn has_empty_or_duplicates(values: &[String]) -> bool {
    values.iter().any(String::is_empty) || has_duplicates(values)
}
fn valid_provider_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn has_duplicates<T: Ord>(values: &[T]) -> bool {
    let mut set = BTreeSet::new();
    values.iter().any(|v| !set.insert(v))
}
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String");
    }
    output
}
pub fn canonical_workflow_digest(graph_json: &str) -> Result<String, ImageGenerationConfigError> {
    let value: serde_json::Value = serde_json::from_str(graph_json)
        .map_err(|_| ImageGenerationConfigError::InvalidWorkflow)?;
    if !value.is_object() {
        return Err(ImageGenerationConfigError::InvalidWorkflow);
    }
    let mut canonical = String::new();
    write_canonical_json(&value, &mut canonical)?;
    Ok(sha256_hex(canonical.as_bytes()))
}
fn write_canonical_json(
    value: &serde_json::Value,
    output: &mut String,
) -> Result<(), ImageGenerationConfigError> {
    match value {
        serde_json::Value::Object(values) => {
            output.push('{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|_| ImageGenerationConfigError::InvalidWorkflow)?,
                );
                output.push(':');
                write_canonical_json(value, output)?;
            }
            output.push('}');
        }
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        _ => output.push_str(
            &serde_json::to_string(value)
                .map_err(|_| ImageGenerationConfigError::InvalidWorkflow)?,
        ),
    }
    Ok(())
}
fn digest_serializable(value: &impl Serialize) -> String {
    sha256_hex(&serde_json::to_vec(value).expect("closed image-generation identity must serialize"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationConfigError {
    InvalidId(&'static str),
    Duplicate(&'static str),
    EmptyValue(&'static str),
    InvalidOrigin,
    InvalidLocation,
    InsecureTransportRequiresOptIn,
    InvalidPathPrefix,
    UnsupportedRoute,
    UnsupportedRouteProfile { endpoint: String, version: u32 },
    MissingEndpoint(String),
    MissingTarget(String),
    DisabledEndpoint(String),
    MissingWorkflow(String),
    WorkflowDigestMismatch(String),
    WrongAdapterIdentity,
    DefaultTargetDisabled,
    InvalidDefaultCount { enabled: u64, defaults: u64 },
    InvalidTargetLimits,
    InvalidDimensions,
    InvalidParameter,
    InvalidWorkflow,
    InvalidOpenRouterRouting,
    InvalidEvidence,
    MissingEvidence,
    InvalidPrice,
    ArithmeticOverflow,
}

impl fmt::Display for ImageGenerationConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid image generation configuration: {self:?}")
    }
}
impl std::error::Error for ImageGenerationConfigError {}
