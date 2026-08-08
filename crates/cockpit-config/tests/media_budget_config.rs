use cockpit_config::config::media_budget::*;

#[test]
fn media_budget_config_round_trips_every_value_and_profile() {
    let policy = MediaResourcePolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let decoded: MediaResourcePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, policy);
    assert!(decoded.profiles().contains_key(PASTE_IMAGE_PROFILE));
    for dimension in MediaDimension::ALL {
        assert!(decoded.limits().get(dimension) > 0);
    }
}

fn changed_policy(field: &str, value: serde_json::Value) -> String {
    let mut raw = serde_json::to_value(MediaResourcePolicy::default()).unwrap();
    raw["limits"][field] = value;
    serde_json::to_string(&raw).unwrap()
}

#[test]
fn media_budget_config_rejects_zero_one_over_inconsistent_unknown_and_overflow() {
    assert!(
        serde_json::from_str::<MediaResourcePolicy>(&changed_policy(
            "redirects_per_request",
            0.into()
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<MediaResourcePolicy>(&changed_policy(
            "redirects_per_request",
            11.into()
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<MediaResourcePolicy>(&changed_policy(
            "aggregate_decoded_pixels_per_request",
            39_999_999.into()
        ))
        .is_err()
    );

    let mut raw = serde_json::to_value(MediaResourcePolicy::default()).unwrap();
    raw["limits"]["surprise"] = 1.into();
    assert!(serde_json::from_value::<MediaResourcePolicy>(raw).is_err());
    let valid = serde_json::to_string(&MediaResourcePolicy::default()).unwrap();
    let json = valid.replace("2147483648", "18446744073709551616");
    assert!(serde_json::from_str::<MediaResourcePolicy>(&json).is_err());
}

#[test]
fn media_budget_all_defaults_are_within_exact_hard_ceilings() {
    let defaults = MediaResourceLimits::defaults();
    let ceilings = MediaResourceLimits::hard_ceilings();
    for dimension in MediaDimension::ALL {
        assert!(defaults.get(dimension) > 0);
        assert!(defaults.get(dimension) <= ceilings.get(dimension));
    }
    assert_eq!(defaults.encoded_bytes_per_object, 256 * 1024 * 1024);
    assert_eq!(ceilings.encoded_bytes_per_object, 2 * 1024 * 1024 * 1024);
    assert_eq!(defaults.retained_bytes_per_session, 2 * 1024 * 1024 * 1024);
    assert_eq!(ceilings.retained_bytes_per_session, 20 * 1024 * 1024 * 1024);
    assert_eq!(
        defaults,
        MediaResourceLimits {
            reference_images_per_request: 4,
            generation_targets_per_request: 4,
            generated_outputs_per_request: 4,
            encoded_bytes_per_object: 256 * 1024 * 1024,
            decoded_edge_pixels: 8_192,
            decoded_image_pixels: 40_000_000,
            aggregate_decoded_pixels_per_request: 80_000_000,
            duration_seconds_per_object: 7_200,
            retained_bytes_per_session: 2 * 1024 * 1024 * 1024,
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
    );
    assert_eq!(
        ceilings,
        MediaResourceLimits {
            reference_images_per_request: 16,
            generation_targets_per_request: 8,
            generated_outputs_per_request: 16,
            encoded_bytes_per_object: 2 * 1024 * 1024 * 1024,
            decoded_edge_pixels: 16_384,
            decoded_image_pixels: 100_000_000,
            aggregate_decoded_pixels_per_request: 400_000_000,
            duration_seconds_per_object: 43_200,
            retained_bytes_per_session: 20 * 1024 * 1024 * 1024,
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
    );
}

#[test]
fn media_budget_config_rejects_unknown_policy_versions() {
    let mut raw = serde_json::to_value(MediaResourcePolicy::default()).unwrap();
    raw["version"] = 0.into();
    assert!(serde_json::from_value::<MediaResourcePolicy>(raw.clone()).is_err());
    raw["version"] =
        (cockpit_config::config::media_budget::MEDIA_RESOURCE_POLICY_VERSION + 1).into();
    assert!(serde_json::from_value::<MediaResourcePolicy>(raw).is_err());
}

#[test]
fn media_budget_reservation_plan_round_trips_and_rejects_tampering() {
    let policy = MediaResourcePolicy::default();
    let plan = policy
        .evaluate(MediaEvaluationRequest {
            dimension: MediaDimension::RedirectsPerRequest,
            requested: Some(1),
            current_scope: 0,
            profile: None,
            adapter_limit: None,
            request_limit: None,
        })
        .unwrap();
    let raw = serde_json::to_value(&plan).unwrap();
    assert_eq!(
        serde_json::from_value::<MediaReservationPlan>(raw.clone()).unwrap(),
        plan
    );

    for (field, value) in [
        ("policy_version", serde_json::json!(0)),
        ("requested", serde_json::json!(0)),
        ("effective_limit", serde_json::json!(0)),
    ] {
        let mut tampered = raw.clone();
        tampered[field] = value;
        assert!(serde_json::from_value::<MediaReservationPlan>(tampered).is_err());
    }
    let mut mismatch = raw.clone();
    mismatch["scope_policy"] =
        serde_json::to_value(MediaDimension::OperationDeadlineSeconds.scope_policy()).unwrap();
    assert!(serde_json::from_value::<MediaReservationPlan>(mismatch).is_err());

    let maximum = policy
        .evaluate(MediaEvaluationRequest {
            dimension: MediaDimension::EncodedBytesPerObject,
            requested: Some(1),
            current_scope: 0,
            profile: None,
            adapter_limit: None,
            request_limit: None,
        })
        .unwrap();
    let mut invalid_maximum = serde_json::to_value(maximum).unwrap();
    invalid_maximum["current_scope"] = serde_json::json!(1);
    assert!(serde_json::from_value::<MediaReservationPlan>(invalid_maximum).is_err());

    let mut overflow = raw;
    overflow["current_scope"] = serde_json::json!(u64::MAX);
    overflow["effective_limit"] = serde_json::json!(u64::MAX);
    assert!(serde_json::from_value::<MediaReservationPlan>(overflow).is_err());
}

#[test]
fn media_budget_profiles_cannot_raise_central_limits_or_break_encoded_aggregate() {
    let defaults = MediaResourcePolicy::default();
    let mut profiles = defaults.profiles().clone();
    profiles.insert(
        "raises".into(),
        MediaOperationProfile {
            limits: MediaResourceLimitPatch {
                redirects_per_request: Some(6),
                ..Default::default()
            },
            aggregate_encoded_bytes_per_request: None,
        },
    );
    assert!(
        MediaResourcePolicy::new(
            MEDIA_RESOURCE_POLICY_VERSION,
            MediaResourceLimits::defaults(),
            profiles,
        )
        .is_err()
    );

    let mut profiles = defaults.profiles().clone();
    profiles.insert(
        "impossible_sum".into(),
        MediaOperationProfile {
            limits: MediaResourceLimitPatch::default(),
            aggregate_encoded_bytes_per_request: Some(1),
        },
    );
    assert!(
        MediaResourcePolicy::new(
            MEDIA_RESOURCE_POLICY_VERSION,
            MediaResourceLimits::defaults(),
            profiles,
        )
        .is_err()
    );
}
