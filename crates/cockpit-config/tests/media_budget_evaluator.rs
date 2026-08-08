use cockpit_config::config::media_budget::*;

fn request(dimension: MediaDimension, requested: Option<u64>) -> MediaEvaluationRequest<'static> {
    MediaEvaluationRequest {
        dimension,
        requested,
        current_scope: 0,
        profile: None,
        adapter_limit: None,
        request_limit: None,
    }
}

#[test]
fn media_budget_evaluator_applies_compiled_config_profile_adapter_request_precedence() {
    let defaults = MediaResourcePolicy::default();
    let mut limits = MediaResourceLimits::defaults();
    limits.redirects_per_request = 9;
    let mut profiles = defaults.profiles().clone();
    profiles.insert(
        "tight".into(),
        MediaOperationProfile {
            limits: MediaResourceLimitPatch {
                redirects_per_request: Some(8),
                ..Default::default()
            },
            aggregate_encoded_bytes_per_request: None,
        },
    );
    let policy = MediaResourcePolicy::new(MEDIA_RESOURCE_POLICY_VERSION, limits, profiles).unwrap();
    let configured = policy
        .evaluate(request(MediaDimension::RedirectsPerRequest, Some(1)))
        .unwrap();
    assert_eq!(
        (configured.effective_limit, configured.source),
        (9, MediaLimitSource::Configured)
    );

    let mut input = request(MediaDimension::RedirectsPerRequest, Some(1));
    input.profile = Some("tight");
    input.adapter_limit = Some(7);
    input.request_limit = Some(6);
    let plan = policy.evaluate(input).unwrap();
    assert_eq!(
        (plan.effective_limit, plan.source),
        (6, MediaLimitSource::Request)
    );
    assert_eq!(plan.policy_version, policy.version());

    let mut input = request(MediaDimension::RedirectsPerRequest, Some(1));
    input.profile = Some("tight");
    input.adapter_limit = Some(100);
    let plan = policy.evaluate(input).unwrap();
    assert_eq!(
        (plan.effective_limit, plan.source),
        (8, MediaLimitSource::Profile)
    );
}

#[test]
fn media_budget_evaluator_has_stable_source_aware_redacted_denials() {
    let policy = MediaResourcePolicy::default();
    let unknown = policy
        .evaluate(request(MediaDimension::DurationSecondsPerObject, None))
        .unwrap_err();
    assert_eq!(unknown.reason, MediaDenialReason::UnknownRequiredValue);
    assert_eq!(unknown.source, MediaLimitSource::Request);
    assert!(!unknown.retryable);

    let mut input = request(MediaDimension::OutboundSubmissionsGlobal, Some(2));
    input.current_scope = 3;
    input.adapter_limit = Some(4);
    let denied = policy.evaluate(input).unwrap_err();
    assert_eq!(
        denied,
        MediaDenial {
            reason: MediaDenialReason::LimitExceeded,
            dimension: MediaDimension::OutboundSubmissionsGlobal,
            requested: Some(2),
            effective_limit: Some(4),
            current_scope: 3,
            source: MediaLimitSource::Configured,
            profile: None,
            retryable: true
        }
    );
    let json = serde_json::to_string(&denied).unwrap();
    assert!(!json.contains("path") && !json.contains("url") && !json.contains("credential"));
}

#[test]
fn media_budget_evaluator_checks_boundaries_and_arithmetic_for_every_numeric_family() {
    let policy = MediaResourcePolicy::default();
    for dimension in MediaDimension::ALL {
        let limit = policy.limits().get(dimension);
        assert_eq!(
            policy
                .evaluate(request(dimension, Some(0)))
                .unwrap_err()
                .reason,
            MediaDenialReason::ZeroRequested,
        );
        assert!(
            policy.evaluate(request(dimension, Some(limit - 1))).is_ok(),
            "{dimension:?}"
        );
        assert!(
            policy.evaluate(request(dimension, Some(limit))).is_ok(),
            "{dimension:?}"
        );
        assert_eq!(
            policy
                .evaluate(request(dimension, Some(limit + 1)))
                .unwrap_err()
                .reason,
            MediaDenialReason::LimitExceeded,
            "{dimension:?}"
        );
        if dimension.scope_policy().accumulation == MediaAccumulation::Maximum {
            assert!(
                !policy
                    .evaluate(request(dimension, Some(limit + 1)))
                    .unwrap_err()
                    .retryable,
                "{dimension:?}"
            );
        }
    }
    assert_eq!(checked_sum([u64::MAX, 1]), None);
    assert_eq!(checked_sum([1, 2, 3]), Some(6));
    assert_eq!(checked_multiply(u64::MAX, 2), None);
    assert_eq!(checked_multiply(40_000_000, 2), Some(80_000_000));
    assert_eq!(
        policy
            .checked_decoded_pixels(MediaConstraintContext::default(), 8_000, 5_000)
            .unwrap(),
        40_000_000
    );
    assert_eq!(
        policy
            .checked_decoded_pixel_total([40_000_000, 40_000_000])
            .unwrap(),
        80_000_000
    );
    let oversized_edge = policy
        .checked_decoded_pixels(MediaConstraintContext::default(), u64::MAX, 2)
        .unwrap_err();
    assert_eq!(oversized_edge.dimension, MediaDimension::DecodedEdgePixels);
    assert_eq!(oversized_edge.reason, MediaDenialReason::LimitExceeded);

    let mut overflow = request(MediaDimension::RetainedBytesPerSession, Some(1));
    overflow.current_scope = u64::MAX;
    let denied = policy.evaluate(overflow).unwrap_err();
    assert_eq!(denied.reason, MediaDenialReason::ArithmeticOverflow);
    assert_eq!(denied.requested, Some(1));
    assert_eq!(denied.current_scope, u64::MAX);
}

#[test]
fn media_budget_named_paste_profile_matches_observable_limits_and_checks_sum() {
    let policy = MediaResourcePolicy::default();
    let paste = &policy.profiles()[PASTE_IMAGE_PROFILE];
    assert_eq!(paste.limits.reference_images_per_request, Some(4));
    assert_eq!(paste.limits.encoded_bytes_per_object, Some(4 * 1024 * 1024));
    assert_eq!(
        paste.aggregate_encoded_bytes_per_request,
        Some(8 * 1024 * 1024)
    );
    assert_eq!(paste.limits.decoded_edge_pixels, Some(8_192));
    assert_eq!(
        paste
            .checked_encoded_total([4 * 1024 * 1024, 4 * 1024 * 1024])
            .unwrap(),
        8 * 1024 * 1024
    );
    assert_eq!(
        paste
            .checked_encoded_total([4 * 1024 * 1024, 4 * 1024 * 1024 + 1])
            .unwrap_err()
            .reason,
        MediaDenialReason::ProfileAggregateExceeded
    );
    assert_eq!(
        paste
            .checked_encoded_total([u64::MAX, 1])
            .unwrap_err()
            .reason,
        MediaDenialReason::ArithmeticOverflow
    );
}

#[test]
fn media_budget_geometry_honors_edges_profiles_and_adapter_constraints() {
    let defaults = MediaResourcePolicy::default();
    let mut profiles = defaults.profiles().clone();
    profiles.insert(
        "pixels".into(),
        MediaOperationProfile {
            limits: MediaResourceLimitPatch {
                decoded_image_pixels: Some(10_000_000),
                ..Default::default()
            },
            aggregate_encoded_bytes_per_request: None,
        },
    );
    let policy = MediaResourcePolicy::new(
        MEDIA_RESOURCE_POLICY_VERSION,
        MediaResourceLimits::defaults(),
        profiles,
    )
    .unwrap();
    assert_eq!(
        policy
            .checked_decoded_pixels(MediaConstraintContext::default(), 20_000, 1_000)
            .unwrap_err()
            .dimension,
        MediaDimension::DecodedEdgePixels
    );
    assert!(
        policy
            .checked_decoded_pixels(
                MediaConstraintContext {
                    profile: Some("pixels"),
                    ..Default::default()
                },
                4_000,
                3_000,
            )
            .is_err()
    );
    assert!(
        policy
            .checked_decoded_pixel_total_with(
                MediaConstraintContext {
                    adapter_limits: Some(&MediaResourceLimitPatch {
                        aggregate_decoded_pixels_per_request: Some(1),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                [2],
            )
            .is_err()
    );
    let edge_limits = MediaResourceLimitPatch {
        decoded_edge_pixels: Some(4_096),
        ..Default::default()
    };
    assert_eq!(
        policy
            .checked_decoded_pixels(
                MediaConstraintContext {
                    adapter_limits: Some(&edge_limits),
                    ..Default::default()
                },
                100,
                100,
            )
            .unwrap(),
        10_000
    );
}

#[test]
fn media_budget_compiled_ceiling_is_attributed_when_configuration_ties_it() {
    let defaults = MediaResourcePolicy::default();
    let mut limits = MediaResourceLimits::defaults();
    limits.redirects_per_request = MediaResourceLimits::hard_ceilings().redirects_per_request;
    let policy = MediaResourcePolicy::new(
        MEDIA_RESOURCE_POLICY_VERSION,
        limits,
        defaults.profiles().clone(),
    )
    .unwrap();
    let plan = policy
        .evaluate(request(MediaDimension::RedirectsPerRequest, Some(1)))
        .unwrap();
    assert_eq!(plan.source, MediaLimitSource::CompiledCeiling);
}

#[test]
fn media_budget_unknown_probe_fails_and_adapter_only_tightens() {
    let policy = MediaResourcePolicy::default();
    let unknown = request(MediaDimension::DecodedImagePixels, None);
    assert!(policy.evaluate(unknown).is_err());
    let mut adapter = request(MediaDimension::DecodedImagePixels, Some(1));
    adapter.adapter_limit = Some(99_000_000);
    let plan = policy.evaluate(adapter).unwrap();
    assert_eq!(plan.effective_limit, 40_000_000);
    assert_eq!(plan.source, MediaLimitSource::Configured);
}
