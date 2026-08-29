//! Serializable media resource policy and pure admission evaluation.
//!
//! This module deliberately owns no counters, clocks, or persistence.  It
//! describes what a ledger must count and produces immutable reservation
//! plans which include the policy version used for admission.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

pub const MEDIA_RESOURCE_POLICY_VERSION: u64 = 1;
pub const PASTE_IMAGE_PROFILE: &str = "paste_image";

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
pub const PASTE_MAX_SINGLE_IMAGE_BYTES: usize = 4 * 1024 * 1024;
pub const PASTE_MAX_TOTAL_IMAGE_BYTES: usize = 8 * 1024 * 1024;
pub const PASTE_MAX_IMAGES_PER_REQUEST: usize = 4;
pub const PASTE_MAX_EDGE_PIXELS: u32 = 8_192;

/// Every independently limited media resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaDimension {
    ReferenceImagesPerRequest,
    GenerationTargetsPerRequest,
    GeneratedOutputsPerRequest,
    EncodedBytesPerObject,
    DecodedEdgePixels,
    DecodedImagePixels,
    AggregateDecodedPixelsPerRequest,
    DurationSecondsPerObject,
    RetainedBytesPerSession,
    LocalCpuJobsGlobal,
    OutboundSubmissionsGlobal,
    SidecarInvocationsPerSession,
    TranscriptionInvocationsPerSession,
    QueuedOperationsGlobal,
    QueuedOperationsPerSession,
    RedirectsPerRequest,
    ResponseHeaderBytesPerRequest,
    OperationDeadlineSeconds,
}

/// The owner whose usage is aggregated for a dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaAggregationScope {
    ImmutableRequest,
    Object,
    Derivative,
    RequestSum,
    Session,
    Global,
    RequestLocal,
    Operation,
}

/// When a resource enters the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaCharge {
    ReserveAtEnqueue,
    BeforeAllocation,
    BeforeDecode,
    WhileBytesExist,
    AcquireAtPromotion,
    AcceptedOrPossiblyAccepted,
    AtHandoff,
    WhileQueued,
    CountDuringRequest,
    InjectAtOperationStart,
}

/// The only event which releases (or reconciles) a charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaRelease {
    Terminal,
    BytesDestroyed,
    DerivativeCleanup,
    AfterTransforms,
    AfterOperation,
    VerifiedDeletion,
    ExecutionFinished,
    AfterReconciliation,
    Never,
    LeavesQueuedState,
    RequestFinished,
    OperationFinished,
}

impl MediaRelease {
    pub const fn is_reclaimable(self) -> bool {
        matches!(
            self,
            Self::DerivativeCleanup
                | Self::AfterTransforms
                | Self::AfterOperation
                | Self::VerifiedDeletion
                | Self::ExecutionFinished
                | Self::AfterReconciliation
                | Self::LeavesQueuedState
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaScopePolicy {
    pub scope: MediaAggregationScope,
    pub charge: MediaCharge,
    pub release: MediaRelease,
    /// Actual decoded/probed values replace an enqueue estimate for this
    /// dimension. Overuse is still a denial; a ledger may only lower unused
    /// reservation through reconciliation.
    pub reconcile_actual: bool,
    pub accumulation: MediaAccumulation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaAccumulation {
    Additive,
    Maximum,
}

impl MediaDimension {
    /// Authoritative aggregation and lifecycle matrix consumed by ledgers.
    pub const fn scope_policy(self) -> MediaScopePolicy {
        use MediaAccumulation as A;
        use MediaAggregationScope as S;
        use MediaCharge as C;
        use MediaRelease as R;
        match self {
            Self::ReferenceImagesPerRequest
            | Self::GenerationTargetsPerRequest
            | Self::GeneratedOutputsPerRequest => MediaScopePolicy {
                scope: S::ImmutableRequest,
                charge: C::ReserveAtEnqueue,
                release: R::Terminal,
                reconcile_actual: false,
                accumulation: A::Additive,
            },
            Self::EncodedBytesPerObject => MediaScopePolicy {
                scope: S::Object,
                charge: C::BeforeAllocation,
                release: R::BytesDestroyed,
                reconcile_actual: true,
                accumulation: A::Maximum,
            },
            Self::DecodedEdgePixels | Self::DecodedImagePixels => MediaScopePolicy {
                scope: S::Derivative,
                charge: C::BeforeDecode,
                release: R::DerivativeCleanup,
                reconcile_actual: true,
                accumulation: A::Maximum,
            },
            Self::AggregateDecodedPixelsPerRequest => MediaScopePolicy {
                scope: S::RequestSum,
                charge: C::ReserveAtEnqueue,
                release: R::AfterTransforms,
                reconcile_actual: true,
                accumulation: A::Additive,
            },
            Self::DurationSecondsPerObject => MediaScopePolicy {
                scope: S::Object,
                charge: C::ReserveAtEnqueue,
                release: R::AfterOperation,
                reconcile_actual: true,
                accumulation: A::Maximum,
            },
            Self::RetainedBytesPerSession => MediaScopePolicy {
                scope: S::Session,
                charge: C::WhileBytesExist,
                release: R::VerifiedDeletion,
                reconcile_actual: true,
                accumulation: A::Additive,
            },
            Self::LocalCpuJobsGlobal => MediaScopePolicy {
                scope: S::Global,
                charge: C::AcquireAtPromotion,
                release: R::ExecutionFinished,
                reconcile_actual: false,
                accumulation: A::Additive,
            },
            Self::OutboundSubmissionsGlobal => MediaScopePolicy {
                scope: S::Global,
                charge: C::AcceptedOrPossiblyAccepted,
                release: R::AfterReconciliation,
                reconcile_actual: false,
                accumulation: A::Additive,
            },
            Self::SidecarInvocationsPerSession | Self::TranscriptionInvocationsPerSession => {
                MediaScopePolicy {
                    scope: S::Session,
                    charge: C::AtHandoff,
                    release: R::Never,
                    reconcile_actual: false,
                    accumulation: A::Additive,
                }
            }
            Self::QueuedOperationsGlobal => MediaScopePolicy {
                scope: S::Global,
                charge: C::WhileQueued,
                release: R::LeavesQueuedState,
                reconcile_actual: false,
                accumulation: A::Additive,
            },
            Self::QueuedOperationsPerSession => MediaScopePolicy {
                scope: S::Session,
                charge: C::WhileQueued,
                release: R::LeavesQueuedState,
                reconcile_actual: false,
                accumulation: A::Additive,
            },
            Self::RedirectsPerRequest | Self::ResponseHeaderBytesPerRequest => MediaScopePolicy {
                scope: S::RequestLocal,
                charge: C::CountDuringRequest,
                release: R::RequestFinished,
                reconcile_actual: false,
                accumulation: A::Additive,
            },
            Self::OperationDeadlineSeconds => MediaScopePolicy {
                scope: S::Operation,
                charge: C::InjectAtOperationStart,
                release: R::OperationFinished,
                reconcile_actual: false,
                accumulation: A::Maximum,
            },
        }
    }

    pub const ALL: [Self; 18] = [
        Self::ReferenceImagesPerRequest,
        Self::GenerationTargetsPerRequest,
        Self::GeneratedOutputsPerRequest,
        Self::EncodedBytesPerObject,
        Self::DecodedEdgePixels,
        Self::DecodedImagePixels,
        Self::AggregateDecodedPixelsPerRequest,
        Self::DurationSecondsPerObject,
        Self::RetainedBytesPerSession,
        Self::LocalCpuJobsGlobal,
        Self::OutboundSubmissionsGlobal,
        Self::SidecarInvocationsPerSession,
        Self::TranscriptionInvocationsPerSession,
        Self::QueuedOperationsGlobal,
        Self::QueuedOperationsPerSession,
        Self::RedirectsPerRequest,
        Self::ResponseHeaderBytesPerRequest,
        Self::OperationDeadlineSeconds,
    ];
}

/// Concrete limits. Units are encoded in field names; integer arithmetic is
/// used throughout so serialization is exact on every platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaResourceLimits {
    pub reference_images_per_request: u64,
    pub generation_targets_per_request: u64,
    pub generated_outputs_per_request: u64,
    pub encoded_bytes_per_object: u64,
    pub decoded_edge_pixels: u64,
    pub decoded_image_pixels: u64,
    pub aggregate_decoded_pixels_per_request: u64,
    pub duration_seconds_per_object: u64,
    pub retained_bytes_per_session: u64,
    pub local_cpu_jobs_global: u64,
    pub outbound_submissions_global: u64,
    pub sidecar_invocations_per_session: u64,
    pub transcription_invocations_per_session: u64,
    pub queued_operations_global: u64,
    pub queued_operations_per_session: u64,
    pub redirects_per_request: u64,
    pub response_header_bytes_per_request: u64,
    pub operation_deadline_seconds: u64,
}

impl MediaResourceLimits {
    pub const fn defaults() -> Self {
        Self {
            reference_images_per_request: 4,
            generation_targets_per_request: 4,
            generated_outputs_per_request: 4,
            encoded_bytes_per_object: 256 * MIB,
            decoded_edge_pixels: 8_192,
            decoded_image_pixels: 40_000_000,
            aggregate_decoded_pixels_per_request: 80_000_000,
            duration_seconds_per_object: 2 * 60 * 60,
            retained_bytes_per_session: 2 * GIB,
            local_cpu_jobs_global: 2,
            outbound_submissions_global: 4,
            sidecar_invocations_per_session: 16,
            transcription_invocations_per_session: 8,
            queued_operations_global: 32,
            queued_operations_per_session: 8,
            redirects_per_request: 5,
            response_header_bytes_per_request: 64 * 1024,
            operation_deadline_seconds: 120,
        }
    }

    pub const fn hard_ceilings() -> Self {
        Self {
            reference_images_per_request: 16,
            generation_targets_per_request: 8,
            generated_outputs_per_request: 16,
            encoded_bytes_per_object: 2 * GIB,
            decoded_edge_pixels: 16_384,
            decoded_image_pixels: 100_000_000,
            aggregate_decoded_pixels_per_request: 400_000_000,
            duration_seconds_per_object: 12 * 60 * 60,
            retained_bytes_per_session: 20 * GIB,
            local_cpu_jobs_global: 8,
            outbound_submissions_global: 16,
            sidecar_invocations_per_session: 128,
            transcription_invocations_per_session: 64,
            queued_operations_global: 256,
            queued_operations_per_session: 32,
            redirects_per_request: 10,
            response_header_bytes_per_request: 256 * 1024,
            operation_deadline_seconds: 600,
        }
    }

    pub const fn get(&self, dimension: MediaDimension) -> u64 {
        match dimension {
            MediaDimension::ReferenceImagesPerRequest => self.reference_images_per_request,
            MediaDimension::GenerationTargetsPerRequest => self.generation_targets_per_request,
            MediaDimension::GeneratedOutputsPerRequest => self.generated_outputs_per_request,
            MediaDimension::EncodedBytesPerObject => self.encoded_bytes_per_object,
            MediaDimension::DecodedEdgePixels => self.decoded_edge_pixels,
            MediaDimension::DecodedImagePixels => self.decoded_image_pixels,
            MediaDimension::AggregateDecodedPixelsPerRequest => {
                self.aggregate_decoded_pixels_per_request
            }
            MediaDimension::DurationSecondsPerObject => self.duration_seconds_per_object,
            MediaDimension::RetainedBytesPerSession => self.retained_bytes_per_session,
            MediaDimension::LocalCpuJobsGlobal => self.local_cpu_jobs_global,
            MediaDimension::OutboundSubmissionsGlobal => self.outbound_submissions_global,
            MediaDimension::SidecarInvocationsPerSession => self.sidecar_invocations_per_session,
            MediaDimension::TranscriptionInvocationsPerSession => {
                self.transcription_invocations_per_session
            }
            MediaDimension::QueuedOperationsGlobal => self.queued_operations_global,
            MediaDimension::QueuedOperationsPerSession => self.queued_operations_per_session,
            MediaDimension::RedirectsPerRequest => self.redirects_per_request,
            MediaDimension::ResponseHeaderBytesPerRequest => self.response_header_bytes_per_request,
            MediaDimension::OperationDeadlineSeconds => self.operation_deadline_seconds,
        }
    }

    pub fn validate(&self) -> Result<(), MediaPolicyError> {
        let ceilings = Self::hard_ceilings();
        for dimension in MediaDimension::ALL {
            let value = self.get(dimension);
            if value == 0 {
                return Err(MediaPolicyError::Zero { dimension });
            }
            let ceiling = ceilings.get(dimension);
            if value > ceiling {
                return Err(MediaPolicyError::AboveHardCeiling {
                    dimension,
                    value,
                    ceiling,
                });
            }
        }
        if self.aggregate_decoded_pixels_per_request < self.decoded_image_pixels {
            return Err(MediaPolicyError::InconsistentAggregate {
                aggregate: MediaDimension::AggregateDecodedPixelsPerRequest,
                aggregate_value: self.aggregate_decoded_pixels_per_request,
                per_item_value: self.decoded_image_pixels,
            });
        }
        if self.queued_operations_global < self.queued_operations_per_session {
            return Err(MediaPolicyError::InconsistentAggregate {
                aggregate: MediaDimension::QueuedOperationsGlobal,
                aggregate_value: self.queued_operations_global,
                per_item_value: self.queued_operations_per_session,
            });
        }
        Ok(())
    }
}

impl Default for MediaResourceLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Optional limits contributed by profiles and adapters. Missing means the
/// source has no opinion, never unlimited.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MediaResourceLimitPatch {
    pub reference_images_per_request: Option<u64>,
    pub generation_targets_per_request: Option<u64>,
    pub generated_outputs_per_request: Option<u64>,
    pub encoded_bytes_per_object: Option<u64>,
    pub decoded_edge_pixels: Option<u64>,
    pub decoded_image_pixels: Option<u64>,
    pub aggregate_decoded_pixels_per_request: Option<u64>,
    pub duration_seconds_per_object: Option<u64>,
    pub retained_bytes_per_session: Option<u64>,
    pub local_cpu_jobs_global: Option<u64>,
    pub outbound_submissions_global: Option<u64>,
    pub sidecar_invocations_per_session: Option<u64>,
    pub transcription_invocations_per_session: Option<u64>,
    pub queued_operations_global: Option<u64>,
    pub queued_operations_per_session: Option<u64>,
    pub redirects_per_request: Option<u64>,
    pub response_header_bytes_per_request: Option<u64>,
    pub operation_deadline_seconds: Option<u64>,
}

impl MediaResourceLimitPatch {
    pub const fn get(&self, d: MediaDimension) -> Option<u64> {
        match d {
            MediaDimension::ReferenceImagesPerRequest => self.reference_images_per_request,
            MediaDimension::GenerationTargetsPerRequest => self.generation_targets_per_request,
            MediaDimension::GeneratedOutputsPerRequest => self.generated_outputs_per_request,
            MediaDimension::EncodedBytesPerObject => self.encoded_bytes_per_object,
            MediaDimension::DecodedEdgePixels => self.decoded_edge_pixels,
            MediaDimension::DecodedImagePixels => self.decoded_image_pixels,
            MediaDimension::AggregateDecodedPixelsPerRequest => {
                self.aggregate_decoded_pixels_per_request
            }
            MediaDimension::DurationSecondsPerObject => self.duration_seconds_per_object,
            MediaDimension::RetainedBytesPerSession => self.retained_bytes_per_session,
            MediaDimension::LocalCpuJobsGlobal => self.local_cpu_jobs_global,
            MediaDimension::OutboundSubmissionsGlobal => self.outbound_submissions_global,
            MediaDimension::SidecarInvocationsPerSession => self.sidecar_invocations_per_session,
            MediaDimension::TranscriptionInvocationsPerSession => {
                self.transcription_invocations_per_session
            }
            MediaDimension::QueuedOperationsGlobal => self.queued_operations_global,
            MediaDimension::QueuedOperationsPerSession => self.queued_operations_per_session,
            MediaDimension::RedirectsPerRequest => self.redirects_per_request,
            MediaDimension::ResponseHeaderBytesPerRequest => self.response_header_bytes_per_request,
            MediaDimension::OperationDeadlineSeconds => self.operation_deadline_seconds,
        }
    }
    fn validate(&self) -> Result<(), MediaPolicyError> {
        let ceiling = MediaResourceLimits::hard_ceilings();
        for d in MediaDimension::ALL {
            if let Some(v) = self.get(d) {
                if v == 0 {
                    return Err(MediaPolicyError::Zero { dimension: d });
                }
                if v > ceiling.get(d) {
                    return Err(MediaPolicyError::AboveHardCeiling {
                        dimension: d,
                        value: v,
                        ceiling: ceiling.get(d),
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaOperationProfile {
    pub limits: MediaResourceLimitPatch,
    /// Some operation families need an encoded request sum in addition to the
    /// central per-object dimension. It is checked with the same arithmetic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_encoded_bytes_per_request: Option<u64>,
}

impl MediaOperationProfile {
    pub fn paste_image() -> Self {
        Self {
            limits: MediaResourceLimitPatch {
                reference_images_per_request: Some(PASTE_MAX_IMAGES_PER_REQUEST as u64),
                encoded_bytes_per_object: Some(PASTE_MAX_SINGLE_IMAGE_BYTES as u64),
                decoded_edge_pixels: Some(PASTE_MAX_EDGE_PIXELS as u64),
                ..Default::default()
            },
            aggregate_encoded_bytes_per_request: Some(PASTE_MAX_TOTAL_IMAGE_BYTES as u64),
        }
    }
    fn validate(&self) -> Result<(), MediaPolicyError> {
        self.limits.validate()?;
        if let Some(v) = self.aggregate_encoded_bytes_per_request {
            if v == 0 {
                return Err(MediaPolicyError::InvalidProfileAggregate {
                    value: v,
                    minimum: None,
                    maximum: MediaResourceLimits::hard_ceilings().encoded_bytes_per_object,
                });
            }
            if v > MediaResourceLimits::hard_ceilings().encoded_bytes_per_object {
                return Err(MediaPolicyError::InvalidProfileAggregate {
                    value: v,
                    minimum: None,
                    maximum: MediaResourceLimits::hard_ceilings().encoded_bytes_per_object,
                });
            }
            if let Some(per_object) = self.limits.encoded_bytes_per_object
                && v < per_object
            {
                return Err(MediaPolicyError::InvalidProfileAggregate {
                    value: v,
                    minimum: Some(per_object),
                    maximum: MediaResourceLimits::hard_ceilings().encoded_bytes_per_object,
                });
            }
        }
        Ok(())
    }

    fn validate_against(&self, base: &MediaResourceLimits) -> Result<(), MediaPolicyError> {
        self.validate()?;
        for dimension in MediaDimension::ALL {
            if let Some(value) = self.limits.get(dimension)
                && value > base.get(dimension)
            {
                return Err(MediaPolicyError::ProfileRaisesLimit {
                    dimension,
                    value,
                    base: base.get(dimension),
                });
            }
        }
        if let Some(aggregate) = self.aggregate_encoded_bytes_per_request {
            let per_object = self
                .limits
                .encoded_bytes_per_object
                .unwrap_or(base.encoded_bytes_per_object);
            if aggregate < per_object {
                return Err(MediaPolicyError::InconsistentAggregate {
                    aggregate: MediaDimension::EncodedBytesPerObject,
                    aggregate_value: aggregate,
                    per_item_value: per_object,
                });
            }
        }
        let image = self
            .limits
            .decoded_image_pixels
            .unwrap_or(base.decoded_image_pixels);
        let aggregate = self
            .limits
            .aggregate_decoded_pixels_per_request
            .unwrap_or(base.aggregate_decoded_pixels_per_request);
        if aggregate < image {
            return Err(MediaPolicyError::InconsistentAggregate {
                aggregate: MediaDimension::AggregateDecodedPixelsPerRequest,
                aggregate_value: aggregate,
                per_item_value: image,
            });
        }
        let global = self
            .limits
            .queued_operations_global
            .unwrap_or(base.queued_operations_global);
        let session = self
            .limits
            .queued_operations_per_session
            .unwrap_or(base.queued_operations_per_session);
        if global < session {
            return Err(MediaPolicyError::InconsistentAggregate {
                aggregate: MediaDimension::QueuedOperationsGlobal,
                aggregate_value: global,
                per_item_value: session,
            });
        }
        Ok(())
    }

    pub fn checked_encoded_total<I>(&self, objects: I) -> Result<u64, MediaDenial>
    where
        I: IntoIterator<Item = u64>,
    {
        let limit = self.aggregate_encoded_bytes_per_request.ok_or_else(|| {
            MediaDenial::invalid(
                MediaDenialReason::InvalidConstraint,
                MediaDimension::EncodedBytesPerObject,
                None,
                0,
                MediaLimitSource::Profile,
                None,
            )
        })?;
        let total = checked_sum(objects).ok_or_else(|| {
            MediaDenial::arithmetic(
                MediaDimension::EncodedBytesPerObject,
                None,
                limit,
                0,
                MediaLimitSource::Profile,
                None,
            )
        })?;
        if total > limit {
            return Err(MediaDenial::profile_aggregate(Some(total), limit));
        }
        Ok(total)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaResourcePolicy {
    version: u64,
    limits: MediaResourceLimits,
    profiles: BTreeMap<String, MediaOperationProfile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMediaResourcePolicy {
    version: u64,
    limits: MediaResourceLimits,
    profiles: BTreeMap<String, MediaOperationProfile>,
}

impl<'de> Deserialize<'de> for MediaResourcePolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawMediaResourcePolicy::deserialize(deserializer)?;
        Self::new(raw.version, raw.limits, raw.profiles).map_err(serde::de::Error::custom)
    }
}

impl Default for MediaResourcePolicy {
    fn default() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            PASTE_IMAGE_PROFILE.to_owned(),
            MediaOperationProfile::paste_image(),
        );
        Self {
            version: MEDIA_RESOURCE_POLICY_VERSION,
            limits: MediaResourceLimits::defaults(),
            profiles,
        }
    }
}

impl MediaResourcePolicy {
    /// The configured base limit before optional profile, adapter, or
    /// per-request tightening.
    pub const fn configured_limit(&self, dimension: MediaDimension) -> u64 {
        self.limits.get(dimension)
    }

    pub fn new(
        version: u64,
        limits: MediaResourceLimits,
        profiles: BTreeMap<String, MediaOperationProfile>,
    ) -> Result<Self, MediaPolicyError> {
        if version == 0 || version > MEDIA_RESOURCE_POLICY_VERSION {
            return Err(MediaPolicyError::InvalidVersion { version });
        }
        limits.validate()?;
        if !profiles.contains_key(PASTE_IMAGE_PROFILE) {
            return Err(MediaPolicyError::MissingPasteProfile);
        }
        for (name, profile) in &profiles {
            if name.is_empty() {
                return Err(MediaPolicyError::InvalidProfileName);
            }
            profile
                .validate_against(&limits)
                .map_err(|source| MediaPolicyError::Profile {
                    name: name.clone(),
                    source: Box::new(source),
                })?;
        }
        Ok(Self {
            version,
            limits,
            profiles,
        })
    }

    pub const fn version(&self) -> u64 {
        self.version
    }
    pub const fn limits(&self) -> &MediaResourceLimits {
        &self.limits
    }
    pub fn profiles(&self) -> &BTreeMap<String, MediaOperationProfile> {
        &self.profiles
    }

    pub fn checked_decoded_pixels(
        &self,
        constraints: MediaConstraintContext<'_>,
        width: u64,
        height: u64,
    ) -> Result<u64, MediaDenial> {
        for edge in [width, height] {
            self.evaluate(constraints.request(MediaDimension::DecodedEdgePixels, edge))?;
        }
        let limit = self.limits.decoded_image_pixels;
        let pixels = checked_multiply(width, height).ok_or_else(|| {
            MediaDenial::arithmetic(
                MediaDimension::DecodedImagePixels,
                Some(width),
                limit,
                0,
                MediaLimitSource::Configured,
                constraints.profile,
            )
        })?;
        self.evaluate(constraints.request(MediaDimension::DecodedImagePixels, pixels))?;
        Ok(pixels)
    }

    pub fn checked_decoded_pixel_total<I>(&self, pixels: I) -> Result<u64, MediaDenial>
    where
        I: IntoIterator<Item = u64>,
    {
        self.checked_decoded_pixel_total_with(MediaConstraintContext::default(), pixels)
    }

    pub fn checked_decoded_pixel_total_with<I>(
        &self,
        constraints: MediaConstraintContext<'_>,
        pixels: I,
    ) -> Result<u64, MediaDenial>
    where
        I: IntoIterator<Item = u64>,
    {
        let limit = self.limits.aggregate_decoded_pixels_per_request;
        let total = checked_sum(pixels).ok_or_else(|| {
            MediaDenial::arithmetic(
                MediaDimension::AggregateDecodedPixelsPerRequest,
                None,
                limit,
                0,
                MediaLimitSource::Configured,
                constraints.profile,
            )
        })?;
        self.evaluate(
            constraints.request(MediaDimension::AggregateDecodedPixelsPerRequest, total),
        )?;
        Ok(total)
    }

    pub fn evaluate(
        &self,
        request: MediaEvaluationRequest<'_>,
    ) -> Result<MediaReservationPlan, MediaDenial> {
        let d = request.dimension;
        let requested = request
            .requested
            .ok_or_else(|| MediaDenial::unknown(d, request.current_scope, request.profile))?;
        if requested == 0 {
            return Err(MediaDenial::invalid(
                MediaDenialReason::ZeroRequested,
                d,
                Some(requested),
                request.current_scope,
                MediaLimitSource::Request,
                request.profile,
            ));
        }
        if d.scope_policy().accumulation == MediaAccumulation::Maximum && request.current_scope != 0
        {
            return Err(MediaDenial::invalid(
                MediaDenialReason::InvalidCurrentScope,
                d,
                Some(requested),
                request.current_scope,
                MediaLimitSource::Request,
                request.profile,
            ));
        }
        let mut limit = MediaResourceLimits::hard_ceilings().get(d);
        let mut source = MediaLimitSource::CompiledCeiling;
        tighten(
            &mut limit,
            &mut source,
            self.limits.get(d),
            MediaLimitSource::Configured,
        );
        if let Some(name) = request.profile {
            let profile = self.profiles.get(name).ok_or_else(|| {
                MediaDenial::invalid(
                    MediaDenialReason::UnknownProfile,
                    d,
                    Some(requested),
                    request.current_scope,
                    MediaLimitSource::Profile,
                    Some(name),
                )
            })?;
            if let Some(value) = profile.limits.get(d) {
                tighten(&mut limit, &mut source, value, MediaLimitSource::Profile);
            }
        }
        if let Some(value) = request.adapter_limit {
            if value == 0 {
                return Err(MediaDenial::invalid(
                    MediaDenialReason::InvalidConstraint,
                    d,
                    Some(requested),
                    request.current_scope,
                    MediaLimitSource::Adapter,
                    request.profile,
                ));
            }
            tighten(&mut limit, &mut source, value, MediaLimitSource::Adapter);
        }
        if let Some(value) = request.request_limit {
            if value == 0 {
                return Err(MediaDenial::invalid(
                    MediaDenialReason::InvalidConstraint,
                    d,
                    Some(requested),
                    request.current_scope,
                    MediaLimitSource::Request,
                    request.profile,
                ));
            }
            tighten(&mut limit, &mut source, value, MediaLimitSource::Request);
        }
        let projected = match d.scope_policy().accumulation {
            MediaAccumulation::Maximum => requested,
            MediaAccumulation::Additive => request
                .current_scope
                .checked_add(requested)
                .ok_or_else(|| {
                    MediaDenial::arithmetic(
                        d,
                        Some(requested),
                        limit,
                        request.current_scope,
                        source,
                        request.profile,
                    )
                })?,
        };
        if projected > limit {
            return Err(MediaDenial::exceeded(
                d,
                requested,
                limit,
                request.current_scope,
                source,
                request.profile,
            ));
        }
        Ok(MediaReservationPlan {
            policy_version: self.version,
            dimension: d,
            requested,
            effective_limit: limit,
            current_scope: request.current_scope,
            source,
            profile: request.profile.map(str::to_owned),
            scope_policy: d.scope_policy(),
        })
    }
}

fn tighten(
    limit: &mut u64,
    source: &mut MediaLimitSource,
    candidate: u64,
    candidate_source: MediaLimitSource,
) {
    if candidate < *limit {
        *limit = candidate;
        *source = candidate_source;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaEvaluationRequest<'a> {
    pub dimension: MediaDimension,
    pub requested: Option<u64>,
    pub current_scope: u64,
    pub profile: Option<&'a str>,
    pub adapter_limit: Option<u64>,
    pub request_limit: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MediaConstraintContext<'a> {
    pub profile: Option<&'a str>,
    pub adapter_limits: Option<&'a MediaResourceLimitPatch>,
    pub request_limits: Option<&'a MediaResourceLimitPatch>,
}

impl<'a> MediaConstraintContext<'a> {
    fn request(self, dimension: MediaDimension, requested: u64) -> MediaEvaluationRequest<'a> {
        MediaEvaluationRequest {
            dimension,
            requested: Some(requested),
            current_scope: 0,
            profile: self.profile,
            adapter_limit: self.adapter_limits.and_then(|limits| limits.get(dimension)),
            request_limit: self.request_limits.and_then(|limits| limits.get(dimension)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MediaReservationPlan {
    pub policy_version: u64,
    pub dimension: MediaDimension,
    pub requested: u64,
    pub effective_limit: u64,
    pub current_scope: u64,
    pub source: MediaLimitSource,
    pub profile: Option<String>,
    pub scope_policy: MediaScopePolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMediaReservationPlan {
    policy_version: u64,
    dimension: MediaDimension,
    requested: u64,
    effective_limit: u64,
    current_scope: u64,
    source: MediaLimitSource,
    profile: Option<String>,
    scope_policy: MediaScopePolicy,
}

impl<'de> Deserialize<'de> for MediaReservationPlan {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawMediaReservationPlan::deserialize(deserializer)?;
        if raw.policy_version == 0 || raw.policy_version > MEDIA_RESOURCE_POLICY_VERSION {
            return Err(serde::de::Error::custom("unsupported media policy version"));
        }
        if raw.requested == 0 || raw.effective_limit == 0 {
            return Err(serde::de::Error::custom("zero media reservation"));
        }
        if raw.scope_policy != raw.dimension.scope_policy() {
            return Err(serde::de::Error::custom("media reservation scope mismatch"));
        }
        let projected = match raw.scope_policy.accumulation {
            MediaAccumulation::Maximum if raw.current_scope == 0 => Some(raw.requested),
            MediaAccumulation::Maximum => None,
            MediaAccumulation::Additive => raw.current_scope.checked_add(raw.requested),
        };
        if projected.is_none_or(|value| value > raw.effective_limit) {
            return Err(serde::de::Error::custom("invalid media reservation amount"));
        }
        Ok(Self {
            policy_version: raw.policy_version,
            dimension: raw.dimension,
            requested: raw.requested,
            effective_limit: raw.effective_limit,
            current_scope: raw.current_scope,
            source: raw.source,
            profile: raw.profile,
            scope_policy: raw.scope_policy,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaLimitSource {
    CompiledCeiling,
    Configured,
    Profile,
    Adapter,
    Request,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaDenialReason {
    UnknownRequiredValue,
    UnknownProfile,
    InvalidConstraint,
    ZeroRequested,
    InvalidCurrentScope,
    ProfileAggregateExceeded,
    LimitExceeded,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaDenial {
    pub reason: MediaDenialReason,
    pub dimension: MediaDimension,
    pub requested: Option<u64>,
    pub effective_limit: Option<u64>,
    pub current_scope: u64,
    pub source: MediaLimitSource,
    pub profile: Option<String>,
    pub retryable: bool,
}

impl MediaDenial {
    fn profile_aggregate(requested: Option<u64>, limit: u64) -> Self {
        Self {
            reason: MediaDenialReason::ProfileAggregateExceeded,
            dimension: MediaDimension::EncodedBytesPerObject,
            requested,
            effective_limit: Some(limit),
            current_scope: 0,
            source: MediaLimitSource::Profile,
            profile: None,
            retryable: false,
        }
    }
    fn unknown(dimension: MediaDimension, current_scope: u64, profile: Option<&str>) -> Self {
        Self {
            reason: MediaDenialReason::UnknownRequiredValue,
            dimension,
            requested: None,
            effective_limit: None,
            current_scope,
            source: MediaLimitSource::Request,
            profile: profile.map(str::to_owned),
            retryable: false,
        }
    }
    fn invalid(
        reason: MediaDenialReason,
        dimension: MediaDimension,
        requested: Option<u64>,
        current_scope: u64,
        source: MediaLimitSource,
        profile: Option<&str>,
    ) -> Self {
        Self {
            reason,
            dimension,
            requested,
            effective_limit: None,
            current_scope,
            source,
            profile: profile.map(str::to_owned),
            retryable: false,
        }
    }
    fn arithmetic(
        dimension: MediaDimension,
        requested: Option<u64>,
        limit: u64,
        current_scope: u64,
        source: MediaLimitSource,
        profile: Option<&str>,
    ) -> Self {
        Self {
            reason: MediaDenialReason::ArithmeticOverflow,
            dimension,
            requested,
            effective_limit: Some(limit),
            current_scope,
            source,
            profile: profile.map(str::to_owned),
            retryable: false,
        }
    }
    fn exceeded(
        dimension: MediaDimension,
        requested: u64,
        limit: u64,
        current_scope: u64,
        source: MediaLimitSource,
        profile: Option<&str>,
    ) -> Self {
        Self {
            reason: MediaDenialReason::LimitExceeded,
            dimension,
            requested: Some(requested),
            effective_limit: Some(limit),
            current_scope,
            source,
            profile: profile.map(str::to_owned),
            retryable: dimension.scope_policy().accumulation == MediaAccumulation::Additive
                && dimension.scope_policy().release.is_reclaimable(),
        }
    }
}

impl fmt::Display for MediaDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "media resource denied: {:?} for {:?} (source {:?})",
            self.reason, self.dimension, self.source
        )
    }
}
impl std::error::Error for MediaDenial {}

pub const fn checked_multiply(left: u64, right: u64) -> Option<u64> {
    left.checked_mul(right)
}
pub fn checked_sum<I: IntoIterator<Item = u64>>(values: I) -> Option<u64> {
    values.into_iter().try_fold(0_u64, u64::checked_add)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaPolicyError {
    InvalidVersion {
        version: u64,
    },
    InvalidProfileName,
    MissingPasteProfile,
    InvalidProfileAggregate {
        value: u64,
        minimum: Option<u64>,
        maximum: u64,
    },
    Profile {
        name: String,
        source: Box<MediaPolicyError>,
    },
    ProfileRaisesLimit {
        dimension: MediaDimension,
        value: u64,
        base: u64,
    },
    Zero {
        dimension: MediaDimension,
    },
    AboveHardCeiling {
        dimension: MediaDimension,
        value: u64,
        ceiling: u64,
    },
    InconsistentAggregate {
        aggregate: MediaDimension,
        aggregate_value: u64,
        per_item_value: u64,
    },
}

impl fmt::Display for MediaPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid media resource policy: {self:?}")
    }
}
impl std::error::Error for MediaPolicyError {}
