//! Real transport → daemon → catalog writes, with independent persisted read-back.
use super::*;
use crate::config::providers::{
    AuthKind, ConfigDoc, HeaderSpec, ModelEntry, OnUnlistedModelsFetch, ProviderEntry,
    ProviderModelCatalog, ProvidersConfig,
};
use crate::daemon::proto::{ProviderModelFetchOutcome, ProviderModelVerification};
use std::collections::HashSet;

fn seed(path: &Path, id: &str, entry: ProviderEntry) {
    let mut config = ProvidersConfig::default();
    config.providers.insert(id.into(), entry);
    ConfigDoc::load(path).unwrap().write(&config).unwrap();
}

async fn fetch(
    ctx: &DaemonContext,
    workspace: &Path,
    id: &str,
    policy: Option<OnUnlistedModelsFetch>,
    consent: bool,
    env: HashMap<String, String>,
) -> proto::ProviderModelFetchResult {
    let response = provider_models_fetch(
        ctx,
        &workspace.to_string_lossy(),
        Some(id),
        None,
        false,
        policy,
        consent,
        env,
    )
    .await
    .unwrap();
    let Response::ProviderModelsFetched { mut results, .. } = response else {
        panic!("wrong daemon response: {response:?}");
    };
    assert_eq!(results.len(), 1);
    results.remove(0)
}

fn read_entry(path: &Path, id: &str) -> ProviderEntry {
    ConfigDoc::providers_from_paths(&[path.to_path_buf()])
        .providers
        .remove(id)
        .unwrap()
}

#[tokio::test]
async fn fetched_catalog_duplicates_are_coalesced_before_preview_summary_and_save() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let body = r#"{"data":[{"id":"same","name":"first"},{"id":"same","name":"second"},{"id":"Same"},{"id":"模型"},{"id":"模型"}]}"#;
    for existing_catalog in [false, true] {
        let requests = if existing_catalog { 2 } else { 1 };
        let (url, server) = crate::providers::provider_http::serve_test_bodies(
            (0..requests).map(|_| (200, body.into(), true)).collect(),
        )
        .await;
        seed(
            &path,
            "local",
            ProviderEntry {
                url,
                allow_insecure_http: true,
                auth: Some(AuthKind::None),
                models: if existing_catalog {
                    vec![ModelEntry {
                        id: "old".into(),
                        ..Default::default()
                    }]
                } else {
                    vec![]
                },
                ..Default::default()
            },
        );
        if existing_catalog {
            let before = std::fs::read(global_provider_path("local")).unwrap();
            let preview = fetch(
                &ctx,
                &workspace,
                "local",
                Some(OnUnlistedModelsFetch::Ask),
                false,
                HashMap::new(),
            )
            .await;
            let ProviderModelFetchOutcome::UnlistedModelsPreview { unlisted } = preview.outcome
            else {
                panic!("{preview:?}");
            };
            assert_eq!(unlisted.count, 1);
            assert_eq!(unlisted.ids, ["old"]);
            assert_eq!(
                std::fs::read(global_provider_path("local")).unwrap(),
                before
            );
        }
        let result = fetch(
            &ctx,
            &workspace,
            "local",
            Some(OnUnlistedModelsFetch::Keep),
            false,
            HashMap::new(),
        )
        .await;
        let ProviderModelFetchOutcome::Models { models, kept, .. } = result.outcome else {
            panic!("{result:?}");
        };
        assert_eq!(
            models.count, 3,
            "duplicate IDs must not inflate the summary"
        );
        assert_eq!(models.ids, ["same", "Same", "模型"]);
        assert_eq!(kept, 3);
        let saved = read_entry(&path, "local");
        let expected = if existing_catalog {
            vec!["same", "Same", "模型", "old"]
        } else {
            vec!["same", "Same", "模型"]
        };
        assert_eq!(
            saved
                .models
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(saved.models[0].name.as_deref(), Some("first"));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn fetched_catalog_scrub_collisions_are_unique_without_dropping_distinct_ids() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    const SECRET: &str = "synthetic-catalog-credential-0042";
    let body =
        serde_json::json!({"data":[{"id":SECRET},{"id":SECRET},{"id":"distinct"}]}).to_string();
    let (url, server) =
        crate::providers::provider_http::serve_test_bodies(vec![(200, body, true)]).await;
    seed(
        &path,
        "local",
        ProviderEntry {
            url,
            allow_insecure_http: true,
            auth: Some(AuthKind::None),
            headers: vec![HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $CATALOG_KEY".into(),
            }],
            ..Default::default()
        },
    );
    let result = fetch(
        &ctx,
        &workspace,
        "local",
        None,
        false,
        HashMap::from([("CATALOG_KEY".into(), SECRET.into())]),
    )
    .await;
    let encoded = serde_json::to_string(&result).unwrap();
    assert!(!encoded.contains(SECRET));
    let ProviderModelFetchOutcome::Models { models, .. } = result.outcome else {
        panic!("{result:?}");
    };
    assert_eq!(models.count, 2);
    assert_eq!(models.ids.len(), 2);
    assert_eq!(models.ids[1], "distinct");
    assert_ne!(models.ids[0], models.ids[1]);
    let saved = read_entry(&path, "local");
    assert_eq!(
        saved
            .models
            .iter()
            .map(|m| m.id.clone())
            .collect::<Vec<_>>(),
        models.ids
    );
    assert!(
        !std::fs::read_to_string(global_provider_path("local"))
            .unwrap()
            .contains(SECRET)
    );
    server.await.unwrap();
}

#[tokio::test]
async fn catalog_parse_class_is_independent_of_body_text_and_shape() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for template in [None, Some("openai-compatible")] {
        for body in [
            "hello",
            "not found",
            "DNS connect timeout",
            "returned 401",
            "42",
            "{}",
            r#"{"data":7}"#,
        ] {
            let (url, server) =
                crate::providers::provider_http::serve_test_bodies(vec![(200, body.into(), true)])
                    .await;
            seed(
                &path,
                "local",
                ProviderEntry {
                    template: template.map(str::to_string),
                    url,
                    allow_insecure_http: true,
                    auth: Some(AuthKind::None),
                    models: vec![ModelEntry {
                        id: "existing".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
            let before = std::fs::read(global_provider_path("local")).unwrap();
            let result = fetch(&ctx, &workspace, "local", None, false, HashMap::new()).await;
            assert!(
                matches!(
                    result.verification,
                    Some(ProviderModelVerification::Parse { .. })
                ),
                "{template:?} {body}: {result:?}"
            );
            assert!(matches!(
                result.outcome,
                ProviderModelFetchOutcome::Error { .. }
            ));
            assert_eq!(read_entry(&path, "local").models[0].id, "existing");
            assert_eq!(
                std::fs::read(global_provider_path("local")).unwrap(),
                before
            );
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn catalog_observed_status_survives_long_url_scrubbing_and_body_spoofing() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for template in [Some("openai-compatible"), None, Some("z-ai")] {
        for status in [403, 401, 404, 418] {
            let (url, server) = crate::providers::provider_http::serve_test_bodies(vec![(
                status,
                "returned HTTP 401 not found DNS timeout".into(),
                true,
            )])
            .await;
            seed(
                &path,
                "local",
                ProviderEntry {
                    template: template.map(str::to_string),
                    url: format!("{url}/{}", "long-segment/".repeat(30)),
                    allow_insecure_http: true,
                    auth: Some(AuthKind::None),
                    models: vec![ModelEntry {
                        id: "existing".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
            let before = std::fs::read(global_provider_path("local")).unwrap();
            let result = fetch(&ctx, &workspace, "local", None, false, HashMap::new()).await;
            assert!(
                match (status, &result.verification) {
                    (
                        401 | 403,
                        Some(ProviderModelVerification::Unauthorized { status: observed }),
                    ) => *observed == status,
                    (404, Some(ProviderModelVerification::NotFound)) => true,
                    (418, Some(ProviderModelVerification::HttpStatus { status: 418, .. })) => true,
                    _ => false,
                },
                "{template:?} observed {status}: {result:?}"
            );
            assert_eq!(read_entry(&path, "local").models[0].id, "existing");
            assert_eq!(
                std::fs::read(global_provider_path("local")).unwrap(),
                before
            );
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn codex_network_fallback_retains_kind_privacy_and_explicit_consent() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    const SECRET: &str = "synthetic-codex-fallback-access-0042";
    ctx.mutate_owner_vault_item(cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
        crate::auth::codex_oauth::CREDENTIAL_KEY,
        Some(&serde_json::to_vec(&serde_json::json!({"access_token":SECRET,"refresh_token":"synthetic-refresh","account_id":"synthetic-account","expires_at":i64::MAX})).unwrap())
    ).await.unwrap();
    // Reserve an address and close it: real connection refusal, no HTTP status.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    seed(
        &path,
        "codex-oauth",
        ProviderEntry {
            url: format!("http://{address}/{SECRET}"),
            allow_insecure_http: true,
            auth: Some(AuthKind::None),
            credential_ref: Some(crate::auth::codex_oauth::CREDENTIAL_KEY.into()),
            models: vec![ModelEntry {
                id: "existing".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    for consent in [false, true] {
        let result = fetch(
            &ctx,
            &workspace,
            "codex-oauth",
            None,
            consent,
            HashMap::new(),
        )
        .await;
        assert!(
            matches!(
                result.verification,
                Some(ProviderModelVerification::Network { .. })
            ),
            "{result:?}"
        );
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(
            !encoded.contains(SECRET),
            "fallback diagnostics must scrub the actual resolved credential"
        );
        let ProviderModelFetchOutcome::FallbackAvailable {
            models,
            catalog,
            reason,
        } = result.outcome
        else {
            panic!("{result:?}");
        };
        assert_eq!(catalog, ProviderModelCatalog::CodexFallback);
        assert_eq!(models.count, 3);
        assert!(!reason.is_empty());
        let saved = read_entry(&path, "codex-oauth");
        if consent {
            assert_eq!(saved.model_catalog, ProviderModelCatalog::CodexFallback);
            for id in models.ids {
                assert!(saved.models.iter().any(|m| m.id == id));
            }
        } else {
            assert_eq!(
                saved
                    .models
                    .iter()
                    .map(|m| m.id.as_str())
                    .collect::<Vec<_>>(),
                ["existing"]
            );
            assert_ne!(saved.model_catalog, ProviderModelCatalog::CodexFallback);
        }
        assert!(
            !saved
                .last_model_fetch
                .unwrap()
                .reason
                .unwrap()
                .contains(SECRET)
        );
    }
}

#[tokio::test]
async fn codex_fallback_parse_and_status_are_observations_not_diagnostic_keywords() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    const SECRET: &str = "synthetic-codex-fallback-status-0042";
    ctx.mutate_owner_vault_item(cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
        crate::auth::codex_oauth::CREDENTIAL_KEY,
        Some(&serde_json::to_vec(&serde_json::json!({"access_token":SECRET,"refresh_token":"synthetic-refresh","account_id":"synthetic-account","expires_at":i64::MAX})).unwrap())
    ).await.unwrap();
    for (status, body) in [
        (200, "hello"),
        (200, "not found"),
        (200, "42"),
        (200, r#"{"data":[]}"#),
        (404, "DNS timeout"),
        (418, "returned 401"),
        (401, "hello"),
        (403, "hello"),
    ] {
        let (url, server) =
            crate::providers::provider_http::serve_test_bodies(vec![(status, body.into(), true)])
                .await;
        seed(
            &path,
            "codex-oauth",
            ProviderEntry {
                url: format!("{url}/{SECRET}/{}", "long-segment/".repeat(30)),
                allow_insecure_http: true,
                auth: Some(AuthKind::None),
                credential_ref: Some(crate::auth::codex_oauth::CREDENTIAL_KEY.into()),
                models: vec![ModelEntry {
                    id: "existing".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let result = fetch(&ctx, &workspace, "codex-oauth", None, false, HashMap::new()).await;
        assert!(
            match (status, &result.verification) {
                (200, Some(ProviderModelVerification::Parse { .. })) => true,
                (404, Some(ProviderModelVerification::NotFound)) => true,
                (418, Some(ProviderModelVerification::HttpStatus { status: 418, .. })) => true,
                (401 | 403, Some(ProviderModelVerification::Unauthorized { status: observed })) =>
                    *observed == status,
                _ => false,
            },
            "observed {status} / {body}: {result:?}"
        );
        assert!(!serde_json::to_string(&result).unwrap().contains(SECRET));
        if status == 401 || status == 403 {
            assert!(
                matches!(result.outcome, ProviderModelFetchOutcome::Error { .. }),
                "rejected credentials cannot activate fallback"
            );
        } else {
            assert!(matches!(
                result.outcome,
                ProviderModelFetchOutcome::FallbackAvailable { .. }
            ));
        }
        assert_eq!(read_entry(&path, "codex-oauth").models[0].id, "existing");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn distinct_catalog_ids_survive_the_final_response_scrubber_unchanged() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let prefix = format!("vendor/{}", "long-prefix/".repeat(30));
    let ids = vec![
        "a".repeat(48),
        "b".repeat(48),
        format!("{prefix}first"),
        format!("{prefix}second"),
        "~ordinary".into(),
        format!("~{}", "G".repeat(64)),
        r#"{"payload":" {\"n\": 1} "}"#.into(),
        r#"{"payload":"{\"n\":1}"}"#.into(),
    ];
    for envelope in ["data", "models", "array"] {
        let rows = ids
            .iter()
            .map(|id| serde_json::json!({"id":id}))
            .collect::<Vec<_>>();
        let body = match envelope {
            "data" => serde_json::json!({"data":rows}),
            "models" => serde_json::json!({"models":rows}),
            _ => serde_json::json!(rows),
        }
        .to_string();
        let (url, server) =
            crate::providers::provider_http::serve_test_bodies(vec![(200, body, true)]).await;
        seed(
            &path,
            "local",
            ProviderEntry {
                url,
                allow_insecure_http: true,
                auth: Some(AuthKind::None),
                ..Default::default()
            },
        );
        let result = fetch(&ctx, &workspace, "local", None, false, HashMap::new()).await;
        let ProviderModelFetchOutcome::Models { models, .. } = result.outcome else {
            panic!("{result:?}");
        };
        assert_eq!(models.count, 8);
        assert_eq!(
            models.ids, ids,
            "final diagnostics must not collapse or truncate distinct catalog IDs"
        );
        assert_eq!(
            read_entry(&path, "local")
                .models
                .iter()
                .map(|m| m.id.clone())
                .collect::<Vec<_>>(),
            ids
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn final_catalog_identity_projection_preserves_secret_and_marker_distinctions() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    const ONE: &str = "synthetic-r16-catalog-private-one-0042";
    const TWO: &str = "COCKPIT";
    const THREE: &str = "synthetic-r16-catalog-private-three-0042";
    let marker = cockpit_config::config::extended::RedactConfig::default().placeholder;
    let projected_marker = marker.replace(TWO, "[redacted]");
    let encoded_secret = ONE
        .chars()
        .map(|ch| format!("\\u{:04x}", ch as u32))
        .collect::<String>();
    let nested = format!("{{\"credential\":\"{encoded_secret}\"}}");
    let spaced_nested = format!(" {{\"credential\": \"{encoded_secret}\"}} ");
    let rows = serde_json::json!([
        {"id":ONE,"name":"first"}, {"id":ONE,"name":"duplicate"},
        {"id":THREE,"name":"other secret"}, {"id":marker,"name":"marker"},
        {"id":projected_marker,"name":"literal"}, {"id":"ordinary-distinct","name":"ordinary"},
        {"id":nested,"name":"nested"}, {"id":spaced_nested,"name":"spaced nested"}
    ]);
    for policy in [OnUnlistedModelsFetch::Keep, OnUnlistedModelsFetch::Remove] {
        for body in [
            serde_json::json!({"data":rows}),
            serde_json::json!({"models":rows}),
            rows.clone(),
        ] {
            let (url, server) = crate::providers::provider_http::serve_test_bodies(vec![(
                200,
                body.to_string(),
                true,
            )])
            .await;
            seed(
                &path,
                "local",
                ProviderEntry {
                    url,
                    allow_insecure_http: true,
                    auth: Some(AuthKind::None),
                    headers: vec![
                        HeaderSpec {
                            name: "X-Private-One".into(),
                            value: "$R16_ONE".into(),
                        },
                        HeaderSpec {
                            name: "X-Private-Two".into(),
                            value: "$R16_TWO".into(),
                        },
                        HeaderSpec {
                            name: "X-Private-Three".into(),
                            value: "$R16_THREE".into(),
                        },
                    ],
                    ..Default::default()
                },
            );
            let result = fetch(
                &ctx,
                &workspace,
                "local",
                Some(policy),
                false,
                HashMap::from([
                    ("R16_ONE".into(), ONE.into()),
                    ("R16_TWO".into(), TWO.into()),
                    ("R16_THREE".into(), THREE.into()),
                ]),
            )
            .await;
            let encoded = serde_json::to_string(&result).unwrap();
            for secret in [ONE, TWO, THREE] {
                assert!(!encoded.contains(secret), "credential in published result");
            }
            let ProviderModelFetchOutcome::Models { models, kept, .. } = result.outcome else {
                panic!("{result:?}");
            };
            assert_eq!(
                models.count, 7,
                "distinct secret/marker IDs must survive projection"
            );
            assert_eq!(kept, 7);
            assert_eq!(
                models.ids.iter().collect::<HashSet<_>>().len(),
                7,
                "final published IDs must be unique"
            );
            assert_eq!(models.ids[3], projected_marker);
            assert_eq!(models.ids[4], "ordinary-distinct");
            assert_ne!(
                models.ids[5], nested,
                "nested JSON Unicode escapes must not carry a credential"
            );
            assert_ne!(models.ids[6], spaced_nested);
            assert!(!models.ids.iter().any(|id| id.contains(&encoded_secret)));
            let saved = read_entry(&path, "local");
            assert_eq!(
                saved
                    .models
                    .iter()
                    .map(|model| model.id.clone())
                    .collect::<Vec<_>>(),
                models.ids,
                "published identities must equal independently loaded persisted identities"
            );
            assert_eq!(
                saved
                    .models
                    .iter()
                    .map(|model| model.name.as_deref().unwrap())
                    .collect::<Vec<_>>(),
                [
                    "first",
                    "other secret",
                    "marker",
                    "literal",
                    "ordinary",
                    "nested",
                    "spaced nested"
                ]
            );
            let saved_text = std::fs::read_to_string(global_provider_path("local")).unwrap();
            for secret in [ONE, TWO, THREE] {
                assert!(
                    !saved_text.contains(secret),
                    "credential in persisted catalog"
                );
            }
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn final_unlisted_preview_identity_projection_is_unique_and_matches_later_write() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let marker = cockpit_config::config::extended::RedactConfig::default().placeholder;
    let projected_marker = marker.replace("COCKPIT", "[redacted]");
    let (url, server) = crate::providers::provider_http::serve_test_bodies(vec![
        (200, r#"{"data":[{"id":"live"}]}"#.into(), true),
        (200, r#"{"data":[{"id":"live"}]}"#.into(), true),
    ])
    .await;
    seed(
        &path,
        "local",
        ProviderEntry {
            url,
            allow_insecure_http: true,
            auth: Some(AuthKind::None),
            headers: vec![HeaderSpec {
                name: "X-Private".into(),
                value: "$R16_MARKER".into(),
            }],
            models: vec![
                ModelEntry {
                    id: marker,
                    name: Some("first".into()),
                    ..Default::default()
                },
                ModelEntry {
                    id: projected_marker.clone(),
                    name: Some("second".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    );
    let before = std::fs::read(global_provider_path("local")).unwrap();
    let env = HashMap::from([("R16_MARKER".into(), "COCKPIT".into())]);
    let preview = fetch(
        &ctx,
        &workspace,
        "local",
        Some(OnUnlistedModelsFetch::Ask),
        false,
        env.clone(),
    )
    .await;
    assert!(!serde_json::to_string(&preview).unwrap().contains("COCKPIT"));
    let ProviderModelFetchOutcome::UnlistedModelsPreview { unlisted } = preview.outcome else {
        panic!("{preview:?}");
    };
    assert_eq!(unlisted.count, 2);
    assert_eq!(
        unlisted.ids.iter().collect::<HashSet<_>>().len(),
        2,
        "preview IDs must remain distinct after final scrubbing"
    );
    assert_eq!(unlisted.ids[1], projected_marker);
    assert_eq!(
        std::fs::read(global_provider_path("local")).unwrap(),
        before,
        "Ask must not write projected identities"
    );
    assert_eq!(read_entry(&path, "local").models.len(), 2);
    let result = fetch(
        &ctx,
        &workspace,
        "local",
        Some(OnUnlistedModelsFetch::Keep),
        false,
        env,
    )
    .await;
    assert!(matches!(
        result.outcome,
        ProviderModelFetchOutcome::Models { .. }
    ));
    let saved = read_entry(&path, "local");
    assert_eq!(
        saved
            .models
            .iter()
            .skip(1)
            .map(|model| model.id.clone())
            .collect::<Vec<_>>(),
        unlisted.ids,
        "preview must use the same safe identities as the later merge/write"
    );
    assert_eq!(saved.models[1].name.as_deref(), Some("first"));
    assert_eq!(saved.models[2].name.as_deref(), Some("second"));
    server.await.unwrap();
}

#[tokio::test]
async fn persisted_fallback_failure_category_ignores_credential_rejection_prose() {
    use crate::config::providers::{ModelFetchSource, ModelFetchStatusKind};
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    ctx.mutate_owner_vault_item(cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
        crate::auth::codex_oauth::CREDENTIAL_KEY,
        Some(&serde_json::to_vec(&serde_json::json!({"access_token":"synthetic-r16-codex-key","refresh_token":"synthetic-r16-refresh","account_id":"synthetic-r16-account","expires_at":i64::MAX})).unwrap())
    ).await.unwrap();
    for body in [
        "credentials rejected",
        "returned 401",
        "returned 403",
        "subscription auth",
        "authorization for provider",
        "requires an official github token",
        "missing chatgpt-account-id",
    ] {
        let (url, server) =
            crate::providers::provider_http::serve_test_bodies(vec![(200, body.into(), true)])
                .await;
        let mut entry = ProviderEntry {
            url,
            allow_insecure_http: true,
            auth: Some(AuthKind::None),
            credential_ref: Some(crate::auth::codex_oauth::CREDENTIAL_KEY.into()),
            models: vec![ModelEntry {
                id: "existing".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        // A previous real rejection must not contaminate this new Parse attempt.
        entry.mark_model_fetch_failed_kept_existing(
            "earlier rejection",
            crate::config::providers::ModelFetchFailure::CredentialsRejected,
        );
        seed(&path, "codex-oauth", entry);
        let result = fetch(&ctx, &workspace, "codex-oauth", None, false, HashMap::new()).await;
        assert!(
            matches!(
                result.verification,
                Some(ProviderModelVerification::Parse { .. })
            ),
            "{result:?}"
        );
        assert!(matches!(
            result.outcome,
            ProviderModelFetchOutcome::FallbackAvailable { .. }
        ));
        let saved = read_entry(&path, "codex-oauth");
        assert_eq!(saved.models[0].id, "existing");
        let status = saved.last_model_fetch.unwrap();
        assert_eq!(
            status.status,
            ModelFetchStatusKind::FailedKeptExisting,
            "HTTP 200 malformed {body:?} is not credential rejection"
        );
        assert_eq!(status.source, ModelFetchSource::Live);
        assert!(status.reason.is_some());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn fallback_catalog_id_projection_is_unique_private_and_persisted_exactly() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    ctx.mutate_owner_vault_item(cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
        crate::auth::codex_oauth::CREDENTIAL_KEY,
        Some(&serde_json::to_vec(&serde_json::json!({"access_token":"gpt-","refresh_token":"synthetic-r16-refresh","account_id":"synthetic-r16-account","expires_at":i64::MAX})).unwrap())
    ).await.unwrap();
    let (url, server) = crate::providers::provider_http::serve_test_bodies(vec![
        (200, "hello".into(), true),
        (200, "hello".into(), true),
    ])
    .await;
    seed(
        &path,
        "codex-oauth",
        ProviderEntry {
            url,
            allow_insecure_http: true,
            auth: Some(AuthKind::None),
            credential_ref: Some(crate::auth::codex_oauth::CREDENTIAL_KEY.into()),
            models: vec![ModelEntry {
                id: "existing".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let mut offered = None;
    for consent in [false, true] {
        let result = fetch(
            &ctx,
            &workspace,
            "codex-oauth",
            Some(OnUnlistedModelsFetch::Remove),
            consent,
            HashMap::new(),
        )
        .await;
        assert!(!serde_json::to_string(&result).unwrap().contains("gpt-"));
        let ProviderModelFetchOutcome::FallbackAvailable { models, .. } = result.outcome else {
            panic!("{result:?}");
        };
        assert_eq!(models.count, 3);
        assert_eq!(models.ids.iter().collect::<HashSet<_>>().len(), 3);
        let saved = read_entry(&path, "codex-oauth");
        if consent {
            assert_eq!(
                saved
                    .models
                    .iter()
                    .map(|model| model.id.clone())
                    .collect::<Vec<_>>(),
                models.ids
            );
            assert_eq!(Some(models.ids), offered);
        } else {
            assert_eq!(saved.models[0].id, "existing");
            offered = Some(models.ids);
        }
    }
    server.await.unwrap();
}

#[tokio::test]
async fn upstream_catalog_cannot_impersonate_an_opaque_identity() {
    use crate::providers::models_fetch::ResolvedHeader;
    const SECRET: &str = "synthetic-r16-token-collision-0042";
    let headers = [ResolvedHeader {
        name: "X-Private".into(),
        value: SECRET.into(),
    }];
    let initial = crate::providers::provider_http::scrub_catalog_models(
        vec![ModelEntry {
            id: SECRET.into(),
            ..Default::default()
        }],
        &headers,
    )
    .unwrap();
    let literal = initial[0].id.clone();
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let body=serde_json::json!({"data":[{"id":SECRET,"name":"private"},{"id":literal,"name":"literal"}]}).to_string();
    let (url, server) =
        crate::providers::provider_http::serve_test_bodies(vec![(200, body, true)]).await;
    seed(
        &path,
        "local",
        ProviderEntry {
            url,
            allow_insecure_http: true,
            auth: Some(AuthKind::None),
            headers: vec![HeaderSpec {
                name: "X-Private".into(),
                value: "$R16_COLLISION".into(),
            }],
            ..Default::default()
        },
    );
    let before = std::fs::read(global_provider_path("local")).unwrap();
    let result = fetch(
        &ctx,
        &workspace,
        "local",
        None,
        false,
        HashMap::from([("R16_COLLISION".into(), SECRET.into())]),
    )
    .await;
    assert!(!serde_json::to_string(&result).unwrap().contains(SECRET));
    assert!(matches!(
        result.verification,
        Some(ProviderModelVerification::Parse { .. })
    ));
    assert!(matches!(
        result.outcome,
        ProviderModelFetchOutcome::Error { .. }
    ));
    assert_eq!(
        std::fs::read(global_provider_path("local")).unwrap(),
        before,
        "token impersonation must fail before writing"
    );
    assert!(read_entry(&path, "local").models.is_empty());
    server.await.unwrap();
}

#[test]
fn final_response_identity_barrier_rejects_unsafe_ids_without_renaming() {
    let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home();
    let mut store = crate::credentials::CredentialStore::open_default().unwrap();
    const SECRET: &str = "synthetic-r16-unsafe-id";
    store.set_named_secret("identity", SECRET);
    let encoded = SECRET
        .chars()
        .map(|ch| format!("\\u{:04x}", ch as u32))
        .collect::<String>();
    let nested = format!("{{\"key\":\"{encoded}\"}}");
    for (provider, encoded) in [(true, false), (false, false), (false, true)] {
        let response = Response::ProviderModelsFetched {
            results: vec![proto::ProviderModelFetchResult {
                provider_id: if provider {
                    "synthetic-r16-unsafe-id"
                } else {
                    "local"
                }
                .into(),
                outcome: ProviderModelFetchOutcome::Models {
                    models: proto::ProviderModelIdSummary {
                        count: 2,
                        ids: vec![
                            if provider {
                                "ordinary-first".into()
                            } else if encoded {
                                nested.clone()
                            } else {
                                SECRET.into()
                            },
                            "ordinary-second".into(),
                        ],
                    },
                    catalog: ProviderModelCatalog::Live,
                    kept: 2,
                },
                verification: None,
            }],
            config_generation: 0,
        };
        let error = scrub_provider_response(
            response,
            &ProvidersConfig::default(),
            &store,
            &HashMap::new(),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::BadRequest);
        assert!(!error.message.contains("synthetic-r16-unsafe-id"));
    }
}

#[tokio::test]
async fn deep_summary_identity_projection_is_unique_and_keeps_no_target_fetch_read_only() {
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let marker = cockpit_config::config::extended::RedactConfig::default().placeholder;
    let other = marker.replace("COCKPIT", "[redacted]");
    seed(
        &path,
        "local",
        ProviderEntry {
            auth: Some(AuthKind::None),
            headers: vec![HeaderSpec {
                name: "X-Private".into(),
                value: "$R16_DEEP".into(),
            }],
            models: vec![
                ModelEntry {
                    id: marker,
                    embeddings: Some(true),
                    ..Default::default()
                },
                ModelEntry {
                    id: other.clone(),
                    embeddings: Some(true),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    );
    let before = std::fs::read(global_provider_path("local")).unwrap();
    let response = provider_models_fetch(
        &ctx,
        &workspace.to_string_lossy(),
        Some("local"),
        None,
        true,
        None,
        false,
        HashMap::from([("R16_DEEP".into(), "COCKPIT".into())]),
    )
    .await
    .unwrap();
    assert!(
        !serde_json::to_string(&response)
            .unwrap()
            .contains("COCKPIT")
    );
    let Response::ProviderModelsFetched { mut results, .. } = response else {
        panic!("{response:?}");
    };
    let ProviderModelFetchOutcome::Models { models, kept, .. } = results.remove(0).outcome else {
        panic!("wrong deep summary");
    };
    assert_eq!(models.count, 2);
    assert_eq!(kept, 2);
    assert_eq!(models.ids.iter().collect::<HashSet<_>>().len(), 2);
    assert_eq!(models.ids[1], other);
    assert_eq!(
        std::fs::read(global_provider_path("local")).unwrap(),
        before
    );
    assert_eq!(read_entry(&path, "local").models.len(), 2);
}

#[tokio::test]
async fn catalog_identity_projection_preserves_owner_controls_and_native_capabilities() {
    use crate::config::providers::{CapabilityStatus, WireApi};
    let (_env, _tmp, ctx, _state, workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for secret in ["manual", "supported"] {
        let body = serde_json::json!({"data":[
            {"id":"live","name":secret,"tool_calling":true,"inputs":{"images":true}},
            {"id":"{\"v\": 1}"},{"id":"{\"v\":1}"}
        ]})
        .to_string();
        let (url, server) =
            crate::providers::provider_http::serve_test_bodies(vec![(200, body, true)]).await;
        let owner = ModelEntry {
            id: "owner".into(),
            manual: true,
            favorite: true,
            wire_api: WireApi::Responses,
            ..Default::default()
        };
        seed(
            &path,
            "local",
            ProviderEntry {
                url,
                allow_insecure_http: true,
                auth: Some(AuthKind::None),
                headers: vec![HeaderSpec {
                    name: "X-Private".into(),
                    value: "$R16_SCHEMA".into(),
                }],
                models: vec![owner.clone()],
                ..Default::default()
            },
        );
        let result = fetch(
            &ctx,
            &workspace,
            "local",
            Some(OnUnlistedModelsFetch::Keep),
            false,
            HashMap::from([("R16_SCHEMA".into(), secret.into())]),
        )
        .await;
        let ProviderModelFetchOutcome::Models { models, kept, .. } = result.outcome else {
            panic!("credential equal to schema word {secret}: {result:?}");
        };
        assert_eq!(
            models.count, 3,
            "diagnostic JSON normalization must not drop distinct raw identity strings"
        );
        assert_eq!(kept, 3);
        assert_eq!(
            models.ids,
            ["live", "{\"v\": 1}", "{\"v\":1}"],
            "decoded diagnostics must not canonicalize distinct identity strings"
        );
        let saved = read_entry(&path, "local");
        assert_eq!(saved.models.len(), 4);
        assert_eq!(
            serde_json::to_value(saved.models.last().unwrap()).unwrap(),
            serde_json::to_value(&owner).unwrap(),
            "identity projection must preserve every owner control"
        );
        let name = saved.models[0]
            .name
            .as_deref()
            .expect("scrubbed upstream label");
        assert!(
            !name.contains(secret),
            "free-form upstream text must still be scrubbed"
        );
        assert_eq!(
            saved.models[0].capabilities.tool_calling,
            CapabilityStatus::Supported
        );
        assert_eq!(
            saved.models[0].capabilities.image_input,
            CapabilityStatus::Supported
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn unusable_fallback_projection_cannot_replace_live_success_or_observed_auth_rejection() {
    use crate::providers::models_fetch::{
        self, FetchOutcome, ModelFetchFailureKind, ResolvedRequest,
    };
    use crate::providers::provider_http::{diagnostic_scope, scrub_catalog_models_with_table};
    let (_env, _tmp, ctx, _state, _workspace) = fresh_untrusted_workspace().await;
    let path = cockpit_config::config::dirs::global_config_file().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    ctx.mutate_owner_vault_item(cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
        crate::auth::codex_oauth::CREDENTIAL_KEY,
        Some(&serde_json::to_vec(&serde_json::json!({"access_token":"synthetic-r16-real-auth","refresh_token":"synthetic-r16-refresh","account_id":"synthetic-r16-account","expires_at":i64::MAX})).unwrap())
    ).await.unwrap();
    let fallback = vec![ModelEntry {
        id: "gpt-5.5".into(),
        ..Default::default()
    }];
    let mut literals = vec!["gpt-".to_string()];
    // Obtain each next candidate through the production allocator, then make
    // it unsafe. This proves the irrelevant fallback really cannot project.
    for _ in 0..64 {
        let table =
            crate::redact::RedactionTable::for_provider_credentials(literals.clone()).unwrap();
        let candidate = scrub_catalog_models_with_table(fallback.clone(), &table).unwrap();
        literals.push(candidate[0].id.clone());
    }
    let blocked = crate::redact::RedactionTable::for_provider_credentials(literals).unwrap();
    assert!(scrub_catalog_models_with_table(fallback, &blocked).is_err());
    for status in [401, 403, 200] {
        let (url, server) = crate::providers::provider_http::serve_test_bodies(vec![(
            status,
            r#"{"data":[{"id":"ordinary-live"}]}"#.into(),
            true,
        )])
        .await;
        let mut entry = ProviderEntry {
            url: url.clone(),
            allow_insecure_http: true,
            auth: Some(AuthKind::None),
            credential_ref: Some(crate::auth::codex_oauth::CREDENTIAL_KEY.into()),
            ..Default::default()
        };
        let store =
            crate::credentials::CredentialStore::from_vault(ctx.secret_vault.clone()).unwrap();
        let resolved = ResolvedRequest {
            base_url: url,
            headers: vec![],
            is_codex_credential: false,
        };
        let result = diagnostic_scope(
            blocked.clone(),
            models_fetch::fetch_models_for_provider_with_store(
                "codex-oauth",
                &entry,
                &resolved,
                std::time::Duration::from_secs(5),
                Some(store),
                |_| None,
            ),
        )
        .await;
        if status == 200 {
            let FetchOutcome::Models { models, .. } =
                result.expect("a usable live catalog must not validate an irrelevant fallback")
            else {
                panic!("expected live catalog");
            };
            assert_eq!(
                models
                    .iter()
                    .map(|model| model.id.as_str())
                    .collect::<Vec<_>>(),
                ["ordinary-live"]
            );
        } else {
            let error = result.unwrap_err();
            let kind = models_fetch::model_fetch_failure_kind(&error);
            assert_eq!(
                kind,
                ModelFetchFailureKind::HttpStatus(reqwest::StatusCode::from_u16(status).unwrap()),
                "fallback safety must not replace an observed authentication status"
            );
            entry
                .mark_model_fetch_failed_kept_existing(error.to_string(), kind.persisted_failure());
            seed(&path, "codex-oauth", entry);
            assert_eq!(
                read_entry(&path, "codex-oauth")
                    .last_model_fetch
                    .unwrap()
                    .status,
                crate::config::providers::ModelFetchStatusKind::AuthFailed
            );
        }
        server.await.unwrap();
    }
}
