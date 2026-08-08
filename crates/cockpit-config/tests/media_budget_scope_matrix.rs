use cockpit_config::config::media_budget::{
    MediaAccumulation, MediaAggregationScope as S, MediaCharge as C, MediaDimension as D,
    MediaRelease as R, MediaScopePolicy,
};

#[test]
fn media_budget_scope_matrix_covers_exact_aggregation_and_lifecycle() {
    let cases = [
        (
            D::ReferenceImagesPerRequest,
            S::ImmutableRequest,
            C::ReserveAtEnqueue,
            R::Terminal,
            false,
        ),
        (
            D::GenerationTargetsPerRequest,
            S::ImmutableRequest,
            C::ReserveAtEnqueue,
            R::Terminal,
            false,
        ),
        (
            D::GeneratedOutputsPerRequest,
            S::ImmutableRequest,
            C::ReserveAtEnqueue,
            R::Terminal,
            false,
        ),
        (
            D::EncodedBytesPerObject,
            S::Object,
            C::BeforeAllocation,
            R::BytesDestroyed,
            true,
        ),
        (
            D::DecodedEdgePixels,
            S::Derivative,
            C::BeforeDecode,
            R::DerivativeCleanup,
            true,
        ),
        (
            D::DecodedImagePixels,
            S::Derivative,
            C::BeforeDecode,
            R::DerivativeCleanup,
            true,
        ),
        (
            D::AggregateDecodedPixelsPerRequest,
            S::RequestSum,
            C::ReserveAtEnqueue,
            R::AfterTransforms,
            true,
        ),
        (
            D::DurationSecondsPerObject,
            S::Object,
            C::ReserveAtEnqueue,
            R::AfterOperation,
            true,
        ),
        (
            D::RetainedBytesPerSession,
            S::Session,
            C::WhileBytesExist,
            R::VerifiedDeletion,
            true,
        ),
        (
            D::LocalCpuJobsGlobal,
            S::Global,
            C::AcquireAtPromotion,
            R::ExecutionFinished,
            false,
        ),
        (
            D::OutboundSubmissionsGlobal,
            S::Global,
            C::AcceptedOrPossiblyAccepted,
            R::AfterReconciliation,
            false,
        ),
        (
            D::SidecarInvocationsPerSession,
            S::Session,
            C::AtHandoff,
            R::Never,
            false,
        ),
        (
            D::TranscriptionInvocationsPerSession,
            S::Session,
            C::AtHandoff,
            R::Never,
            false,
        ),
        (
            D::QueuedOperationsGlobal,
            S::Global,
            C::WhileQueued,
            R::LeavesQueuedState,
            false,
        ),
        (
            D::QueuedOperationsPerSession,
            S::Session,
            C::WhileQueued,
            R::LeavesQueuedState,
            false,
        ),
        (
            D::RedirectsPerRequest,
            S::RequestLocal,
            C::CountDuringRequest,
            R::RequestFinished,
            false,
        ),
        (
            D::ResponseHeaderBytesPerRequest,
            S::RequestLocal,
            C::CountDuringRequest,
            R::RequestFinished,
            false,
        ),
        (
            D::OperationDeadlineSeconds,
            S::Operation,
            C::InjectAtOperationStart,
            R::OperationFinished,
            false,
        ),
    ];
    assert_eq!(cases.len(), D::ALL.len());
    for (dimension, scope, charge, release, reconcile_actual) in cases {
        let accumulation = if matches!(
            dimension,
            D::EncodedBytesPerObject
                | D::DecodedEdgePixels
                | D::DecodedImagePixels
                | D::DurationSecondsPerObject
                | D::OperationDeadlineSeconds
        ) {
            MediaAccumulation::Maximum
        } else {
            MediaAccumulation::Additive
        };
        assert_eq!(
            dimension.scope_policy(),
            MediaScopePolicy {
                scope,
                charge,
                release,
                reconcile_actual,
                accumulation,
            }
        );
        assert_eq!(
            release.is_reclaimable(),
            matches!(
                release,
                R::DerivativeCleanup
                    | R::AfterTransforms
                    | R::AfterOperation
                    | R::VerifiedDeletion
                    | R::ExecutionFinished
                    | R::AfterReconciliation
                    | R::LeavesQueuedState
            )
        );
    }
}
