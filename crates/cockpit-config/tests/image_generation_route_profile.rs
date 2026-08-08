use cockpit_config::config::image_generation::*;

#[test]
fn image_generation_route_profile_has_every_exact_fixed_route() {
    let rows = [
        (
            ImageAdapterKind::OpenaiImages,
            ImageRoute::Generate,
            "/v1/images/generations",
        ),
        (
            ImageAdapterKind::OpenaiImages,
            ImageRoute::Edit,
            "/v1/images/edits",
        ),
        (
            ImageAdapterKind::OpenrouterImages,
            ImageRoute::Generate,
            "/api/v1/images",
        ),
        (
            ImageAdapterKind::OpenrouterImages,
            ImageRoute::DiscoverModels,
            "/api/v1/images/models",
        ),
        (
            ImageAdapterKind::OpenrouterImages,
            ImageRoute::DiscoverEndpoints,
            "/api/v1/images/models/{author}/{slug}/endpoints",
        ),
        (
            ImageAdapterKind::GeminiImages,
            ImageRoute::Generate,
            "/v1beta/interactions",
        ),
        (ImageAdapterKind::Comfyui, ImageRoute::Submit, "/prompt"),
        (ImageAdapterKind::Comfyui, ImageRoute::Events, "/ws"),
        (
            ImageAdapterKind::Comfyui,
            ImageRoute::History,
            "/history/{prompt_id}",
        ),
        (ImageAdapterKind::Comfyui, ImageRoute::Artifact, "/view"),
        (ImageAdapterKind::Comfyui, ImageRoute::Queue, "/queue"),
        (
            ImageAdapterKind::Comfyui,
            ImageRoute::Job,
            "/api/jobs/{job_id}",
        ),
        (
            ImageAdapterKind::Comfyui,
            ImageRoute::Cancel,
            "/api/jobs/{job_id}/cancel",
        ),
    ];
    for (adapter, route, expected) in rows {
        assert_eq!(adapter.route(route), Some(expected));
    }
    assert_eq!(ImageAdapterKind::GeminiImages.route(ImageRoute::Edit), None);
}

#[test]
fn image_generation_url_policy_normalizes_contained_prefixes_and_transport() {
    assert_eq!(
        normalize_origin("https://EXAMPLE.com/", false).unwrap(),
        "https://example.com"
    );
    assert_eq!(
        normalize_origin("http://localhost:8188", false).unwrap(),
        "http://localhost:8188"
    );
    assert_eq!(
        normalize_origin("http://[::1]:8188", false).unwrap(),
        "http://[::1]:8188"
    );
    assert!(normalize_origin("http://example.com", false).is_err());
    assert_eq!(
        normalize_origin("http://example.com", true).unwrap(),
        "http://example.com"
    );
    assert_eq!(
        normalize_path_prefix(Some("/a/b/")).unwrap().as_deref(),
        Some("/a/b")
    );
    for bad in [
        "//a", "/a//b", "/a/../b", "/a/./b", "/a%2fb", "/a?x=1", "/a#f", "/a\\b", "/a b",
        "/a\r\nb", "/a\tb",
    ] {
        assert!(normalize_path_prefix(Some(bad)).is_err(), "{bad}");
    }
    for bad in [
        "https://user@example.com",
        "https://example.com/base",
        "https://example.com?x=1",
        "ftp://example.com",
    ] {
        assert!(normalize_origin(bad, true).is_err(), "{bad}");
    }
}

#[test]
fn image_generation_route_config_rejects_custom_and_chat_fields() {
    let endpoint = serde_json::json!({
        "id":"openai", "adapter":"openai_images", "origin":"https://api.openai.com",
        "location":"public_cloud", "route_profile_version":1
    });
    let parsed: ImageEndpoint = serde_json::from_value(endpoint.clone()).unwrap();
    assert_eq!(
        parsed
            .normalized()
            .unwrap()
            .route_url(ImageRoute::Generate)
            .unwrap(),
        "https://api.openai.com/v1/images/generations"
    );
    for key in [
        "route",
        "generation_route",
        "chat",
        "server_tool",
        "responses_api",
    ] {
        let mut invalid = endpoint.clone();
        invalid[key] = "/custom".into();
        assert!(
            serde_json::from_value::<ImageEndpoint>(invalid).is_err(),
            "{key}"
        );
    }
}
