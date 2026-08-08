use chrono::{TimeZone, Utc};
use cockpit_config::config::image_generation::*;
use cockpit_config::config::providers::{CapabilityStatus, HeaderSpec, ProvidersConfig};

fn workflow() -> RegisteredComfyWorkflow {
    let graph_json = r#"{"1":{"inputs":{"seed":1}},"2":{"inputs":{}}}"#.to_owned();
    RegisteredComfyWorkflow {
        id: "portrait-v1".into(),
        graph_digest: canonical_workflow_digest(&graph_json).unwrap(),
        graph_json,
        bindings: vec![WorkflowBinding {
            parameter: ImageParameter::Seed,
            node_id: "1".into(),
            input: "seed".into(),
            value_type: WorkflowValueType::Integer,
            min: Some(0),
            max: Some(1_000_000),
        }],
        outputs: vec![WorkflowOutput {
            node_id: "2".into(),
            output: "images".into(),
            value_type: WorkflowValueType::Image,
        }],
    }
}

fn config() -> ImageGenerationConfig {
    let workflow = workflow();
    let verified = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();
    ImageGenerationConfig::new(
        vec![ImageEndpoint {
            id: "local-comfy".into(),
            adapter: ImageAdapterKind::Comfyui,
            origin: "http://127.0.0.1:8188/".into(),
            path_prefix: Some("/tenant/a/".into()),
            credential_ref: Some("comfy-token".into()),
            headers: vec![HeaderSpec {
                name: "X-Token".into(),
                value: "$secret:comfy-token".into(),
            }],
            allow_insecure_transport: false,
            location: ImageLocationClass::Local,
            enabled: true,
            route_profile_version: IMAGE_GENERATION_ROUTE_PROFILE_VERSION,
        }],
        vec![ImageGenerationTarget {
            id: "portrait".into(),
            display_name: Some("Portrait Studio".into()),
            endpoint_id: "local-comfy".into(),
            identity: ImageTargetIdentity::Workflow {
                workflow_id: workflow.id.clone(),
                workflow_digest: workflow.graph_digest.clone(),
            },
            enabled: true,
            is_default: true,
            formats: vec![ImageFormat::Png, ImageFormat::Webp],
            reference_support: ReferenceImageSupport::Optional,
            max_reference_images: 2,
            max_samples: 2,
            max_outputs: 2,
            dimensions: ImageDimensionDescriptor::Discrete {
                candidates: vec![ImageDimensionCandidate {
                    width: 1024,
                    height: 1024,
                    provider_value: "square".into(),
                }],
            },
            dimension_policy: ImageDimensionRequestPolicy::Nearest,
            parameters: vec![ImageParameterDescriptor::Integer {
                parameter: ImageParameter::Seed,
                min: 0,
                max: 1_000_000,
            }],
            openrouter_routing: None,
            generation_capability: ImageCapabilityEvidence::new(
                CapabilityStatus::Supported,
                Some(ImageEvidence::WorkflowDeclared {
                    workflow_digest: workflow.graph_digest.clone(),
                }),
            )
            .unwrap(),
            price: ImagePrice::Known {
                usd_micros: 25_000,
                unit: ImageBillableUnit::Image,
                variant: "1024-square".into(),
                method: ImagePriceMethod::ConservativeMaximum,
                evidence: ImageEvidence::CheckedIn {
                    source_url: "https://example.com/pricing".into(),
                    last_verified: verified,
                },
            },
        }],
        vec![workflow],
        vec!["fal".into(), "together".into()],
    )
    .unwrap()
}

#[test]
fn image_generation_config_round_trips_all_fields_and_normalizes() {
    let config = config();
    assert_eq!(config.endpoints()[0].origin, "http://127.0.0.1:8188");
    assert_eq!(
        config.endpoints()[0].path_prefix.as_deref(),
        Some("/tenant/a")
    );
    assert_eq!(
        config.endpoints()[0].route_url(ImageRoute::Submit).unwrap(),
        "http://127.0.0.1:8188/tenant/a/prompt"
    );
    let json = serde_json::to_string(&config).unwrap();
    let decoded: ImageGenerationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, config);
    assert_eq!(
        decoded.endpoints()[0].immutable_identity(),
        config.endpoints()[0].immutable_identity()
    );
    assert_eq!(
        decoded.target_immutable_identity("portrait").unwrap(),
        config.target_immutable_identity("portrait").unwrap()
    );
}

#[test]
fn image_generation_config_enforces_ids_references_and_exact_default_rule() {
    let raw = serde_json::to_value(config()).unwrap();
    for mutate in [
        (
            "duplicate",
            serde_json::json!([raw["targets"][0].clone(), raw["targets"][0].clone()]),
        ),
        ("no_default", {
            let mut targets = raw["targets"].clone();
            targets[0]["is_default"] = false.into();
            targets
        }),
        ("disabled_default", {
            let mut targets = raw["targets"].clone();
            targets[0]["enabled"] = false.into();
            targets
        }),
    ] {
        let mut invalid = raw.clone();
        invalid["targets"] = mutate.1;
        assert!(
            serde_json::from_value::<ImageGenerationConfig>(invalid).is_err(),
            "{}",
            mutate.0
        );
    }
    let mut missing = raw.clone();
    missing["targets"][0]["endpoint_id"] = "missing".into();
    assert!(serde_json::from_value::<ImageGenerationConfig>(missing).is_err());
    let mut unknown = raw;
    unknown["server_tool"] = true.into();
    assert!(serde_json::from_value::<ImageGenerationConfig>(unknown).is_err());
    let mut hosted_on_comfy = serde_json::to_value(config()).unwrap();
    hosted_on_comfy["targets"][0]["identity"] =
        serde_json::json!({"type":"hosted_model", "model":"author/model"});
    assert!(serde_json::from_value::<ImageGenerationConfig>(hosted_on_comfy).is_err());

    for section in ["endpoints", "targets", "workflows"] {
        let mut duplicate = serde_json::to_value(config()).unwrap();
        let item = duplicate[section][0].clone();
        duplicate[section].as_array_mut().unwrap().push(item);
        assert!(
            serde_json::from_value::<ImageGenerationConfig>(duplicate).is_err(),
            "{section}"
        );
    }
    for bad in ["", "bad/id", "bad id"] {
        let mut invalid = serde_json::to_value(config()).unwrap();
        invalid["targets"][0]["id"] = bad.into();
        assert!(
            serde_json::from_value::<ImageGenerationConfig>(invalid).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn image_generation_identity_ignores_display_and_captures_plan_fields() {
    let base = config();
    let identity = base.target_immutable_identity("portrait").unwrap();
    let mut renamed = serde_json::to_value(&base).unwrap();
    renamed["targets"][0]["display_name"] = "Renamed".into();
    let renamed: ImageGenerationConfig = serde_json::from_value(renamed).unwrap();
    assert_eq!(
        renamed.target_immutable_identity("portrait").unwrap(),
        identity
    );

    for (field, value) in [
        ("origin", serde_json::json!("http://localhost:8188")),
        ("credential_ref", serde_json::json!("another-token")),
        ("location", serde_json::json!("private_network")),
    ] {
        let mut changed = serde_json::to_value(&base).unwrap();
        changed["endpoints"][0][field] = value;
        let changed: ImageGenerationConfig = serde_json::from_value(changed).unwrap();
        assert_ne!(
            changed.target_immutable_identity("portrait").unwrap(),
            identity,
            "{field}"
        );
    }
    let mut endpoint = base.endpoints()[0].clone();
    let endpoint_identity = endpoint.immutable_identity();
    endpoint.route_profile_version += 1;
    assert_ne!(endpoint.immutable_identity(), endpoint_identity);
}

#[test]
fn image_generation_workflow_binding_digest_and_safe_projection_are_private() {
    let workflow = workflow();
    let safe = serde_json::to_string(&workflow.safe_projection()).unwrap();
    assert!(!safe.contains("graph_json") && !safe.contains("node_id"));
    assert!(!safe.contains("\"1\"") && !safe.contains("\"2\""));
    assert!(safe.contains(&workflow.graph_digest));
    let cfg = config();
    let original = cfg.target_immutable_identity("portrait").unwrap();
    let mut rebound = serde_json::to_value(&cfg).unwrap();
    rebound["workflows"][0]["bindings"][0]["max"] = 900_000.into();
    rebound["targets"][0]["parameters"][0]["max"] = 900_000.into();
    let rebound: ImageGenerationConfig = serde_json::from_value(rebound).unwrap();
    assert_ne!(
        original,
        rebound.target_immutable_identity("portrait").unwrap()
    );
    assert_eq!(
        canonical_workflow_digest(r#"{"a":1,"b":2}"#).unwrap(),
        canonical_workflow_digest(r#"{"b":2,"a":1}"#).unwrap()
    );

    let mut raw = serde_json::to_value(config()).unwrap();
    raw["workflows"][0]["graph_digest"] = "0".repeat(64).into();
    assert!(serde_json::from_value::<ImageGenerationConfig>(raw).is_err());
    let mut raw = serde_json::to_value(config()).unwrap();
    raw["workflows"][0]["bindings"][0]["input"] = "missing".into();
    assert!(serde_json::from_value::<ImageGenerationConfig>(raw).is_err());
    let mut raw = serde_json::to_value(config()).unwrap();
    raw["workflows"][0]["outputs"][0]["node_id"] = "missing".into();
    assert!(serde_json::from_value::<ImageGenerationConfig>(raw).is_err());
    let mut raw = serde_json::to_value(config()).unwrap();
    raw["targets"][0]["parameters"][0] = serde_json::json!({
        "type":"text", "parameter":"seed", "max_bytes":100
    });
    assert!(serde_json::from_value::<ImageGenerationConfig>(raw).is_err());
    let mut raw = serde_json::to_value(config()).unwrap();
    raw["targets"][0]["parameters"][0]["max"] = 1_000_001.into();
    assert!(serde_json::from_value::<ImageGenerationConfig>(raw).is_err());
    let mut raw = serde_json::to_value(config()).unwrap();
    raw["targets"][0]["parameters"] = serde_json::json!([]);
    assert!(serde_json::from_value::<ImageGenerationConfig>(raw).is_err());
}

#[test]
fn image_generation_provenance_preserves_data_and_stale_is_unknown_not_free() {
    let fetched = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
    let expires = Utc.with_ymd_and_hms(2026, 8, 2, 0, 0, 0).unwrap();
    let now = Utc.with_ymd_and_hms(2026, 8, 3, 0, 0, 0).unwrap();
    let evidence = ImageEvidence::Discovered {
        source_url: "https://example.com/models".into(),
        fetched_at: fetched,
        expires_at: expires,
        endpoint_identity: "endpoint-digest".into(),
    };
    let capability =
        ImageCapabilityEvidence::new(CapabilityStatus::Supported, Some(evidence.clone())).unwrap();
    assert_eq!(
        capability.effective_status_at(now),
        CapabilityStatus::Unknown
    );
    let price = ImagePrice::Known {
        usd_micros: 99,
        unit: ImageBillableUnit::Megapixel,
        variant: "standard".into(),
        method: ImagePriceMethod::ConservativeMaximum,
        evidence,
    };
    assert_eq!(price.effective_at(now), ImagePrice::Unknown);
    assert!(
        serde_json::to_string(&price)
            .unwrap()
            .contains("endpoint-digest")
    );
    let all = vec![
        ImageEvidence::CheckedIn {
            source_url: "https://example.com/checked".into(),
            last_verified: fetched,
        },
        ImageEvidence::Discovered {
            source_url: "https://example.com/discovered".into(),
            fetched_at: fetched,
            expires_at: expires,
            endpoint_identity: "endpoint-digest".into(),
        },
        ImageEvidence::WorkflowDeclared {
            workflow_digest: "a".repeat(64),
        },
        ImageEvidence::UserOverride {
            configured_at: fetched,
        },
    ];
    let encoded = serde_json::to_string(&all).unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<ImageEvidence>>(&encoded).unwrap(),
        all
    );
    let unknown = ImageCapabilityEvidence::new(CapabilityStatus::Unknown, None).unwrap();
    assert_eq!(unknown.effective_status_at(now), CapabilityStatus::Unknown);
    assert_eq!(ImagePrice::Unknown.effective_at(now), ImagePrice::Unknown);
    assert!(serde_json::from_str::<ImageCapabilityEvidence>(r#"{"status":"supported"}"#).is_err());
}

#[test]
fn inference_config_round_trips_without_generation_aliases() {
    let inference: ProvidersConfig = serde_json::from_value(serde_json::json!({
        "providers": {
            "vision-chat": {
                "url": "https://example.com/v1",
                "models": [{
                    "id": "chat-with-images",
                    "capabilities": { "image_input": "supported" }
                }]
            }
        },
        "active_model": { "provider": "vision-chat", "model": "chat-with-images" }
    }))
    .unwrap();
    let value = serde_json::to_value(&inference).unwrap();
    let round_trip: ProvidersConfig = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(round_trip).unwrap(), value);
    let text = serde_json::to_string(&inference).unwrap();
    assert!(!text.contains("image_generation") && !text.contains("generation_targets"));
}
