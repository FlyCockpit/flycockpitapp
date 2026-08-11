use cockpit_config::config::image_generation::*;
use cockpit_config::config::providers::CapabilityStatus;

#[test]
fn image_generation_openrouter_routing_config_is_closed() {
    let good = serde_json::json!({
        "only":["fal","together"], "order":["together","fal"], "ignore":[],
        "sort":"throughput", "allow_fallbacks":false
    });
    let routing: OpenRouterImageRouting = serde_json::from_value(good.clone()).unwrap();
    assert_eq!(routing.order, vec!["together", "fal"]);
    for key in ["provider_options", "passthrough", "extra", "arbitrary_json"] {
        let mut invalid = good.clone();
        invalid[key] = serde_json::json!({"x":1});
        assert!(serde_json::from_value::<OpenRouterImageRouting>(invalid).is_err());
    }
}

#[test]
fn image_generation_openrouter_routing_is_wired_through_registry() {
    let endpoint = ImageEndpoint {
        id: "openrouter-images".into(),
        adapter: ImageAdapterKind::OpenrouterImages,
        origin: "https://openrouter.ai".into(),
        path_prefix: None,
        credential_ref: Some("openrouter".into()),
        headers: vec![],
        allow_insecure_transport: false,
        location: ImageLocationClass::PublicCloud,
        enabled: true,
        route_profile_version: IMAGE_GENERATION_ROUTE_PROFILE_VERSION,
        exclusive_server: false,
    };
    let target = ImageGenerationTarget {
        id: "flux".into(),
        display_name: None,
        endpoint_id: endpoint.id.clone(),
        identity: ImageTargetIdentity::HostedModel {
            model: "black-forest-labs/flux".into(),
        },
        enabled: true,
        is_default: true,
        formats: vec![ImageFormat::Png],
        reference_support: ReferenceImageSupport::Unsupported,
        max_reference_images: 0,
        max_samples: 1,
        max_outputs: 1,
        dimensions: ImageDimensionDescriptor::ProviderDefault,
        dimension_policy: ImageDimensionRequestPolicy::ProviderDefault,
        parameters: vec![],
        openrouter_routing: Some(OpenRouterImageRouting {
            only: vec!["fal".into()],
            order: vec!["fal".into()],
            ignore: vec![],
            sort: Some(OpenRouterSort::Latency),
            allow_fallbacks: false,
        }),
        generation_capability: ImageCapabilityEvidence::new(CapabilityStatus::Unknown, None)
            .unwrap(),
        price: ImagePrice::Unknown,
    };
    let config = ImageGenerationConfig::new(
        vec![endpoint.clone()],
        vec![target.clone()],
        vec![],
        vec!["fal".into()],
    )
    .unwrap();
    let encoded = serde_json::to_string(&config).unwrap();
    assert_eq!(
        serde_json::from_str::<ImageGenerationConfig>(&encoded).unwrap(),
        config
    );
    let mut disabled = config.targets()[0].clone();
    disabled.enabled = false;
    disabled.is_default = false;
    assert!(ImageGenerationConfig::new(vec![], vec![disabled], vec![], vec!["fal".into()]).is_ok());

    for model in ["flux", "a/b/c"] {
        let mut invalid = target.clone();
        invalid.identity = ImageTargetIdentity::HostedModel {
            model: model.into(),
        };
        assert!(
            ImageGenerationConfig::new(
                vec![endpoint.clone()],
                vec![invalid],
                vec![],
                vec!["fal".into()]
            )
            .is_err()
        );
    }
    let mut wrong_adapter = endpoint;
    wrong_adapter.adapter = ImageAdapterKind::OpenaiImages;
    assert!(
        ImageGenerationConfig::new(
            vec![wrong_adapter],
            vec![target],
            vec![],
            vec!["fal".into()]
        )
        .is_err()
    );
}

#[test]
fn image_generation_openrouter_routing_validates_lists_via_registry() {
    let allowlist = vec!["fal".into(), "together".into()];
    let valid = OpenRouterImageRouting {
        only: vec!["fal".into()],
        order: vec!["fal".into()],
        ignore: vec!["together".into()],
        sort: Some(OpenRouterSort::Price),
        allow_fallbacks: true,
    };
    assert!(valid.validate_provider_allowlist(&allowlist).is_ok());
    for invalid in [
        OpenRouterImageRouting {
            only: vec!["unknown".into()],
            ..valid.clone()
        },
        OpenRouterImageRouting {
            only: vec!["fal".into(), "fal".into()],
            ..valid.clone()
        },
        OpenRouterImageRouting {
            only: vec!["fal".into()],
            ignore: vec!["fal".into()],
            ..valid.clone()
        },
        OpenRouterImageRouting {
            only: vec!["fal".into()],
            order: vec!["together".into()],
            ..valid.clone()
        },
        OpenRouterImageRouting {
            only: vec![],
            order: vec!["fal".into()],
            ignore: vec!["fal".into()],
            ..valid.clone()
        },
        OpenRouterImageRouting {
            only: vec![],
            order: vec![],
            allow_fallbacks: false,
            ..valid.clone()
        },
    ] {
        assert!(invalid.validate_provider_allowlist(&allowlist).is_err());
    }
}
