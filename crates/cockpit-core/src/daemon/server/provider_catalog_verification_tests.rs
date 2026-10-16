//! Real transport → daemon → catalog writes, with independent persisted read-back.
use super::*;
use crate::config::providers::{
    AuthKind, ConfigDoc, HeaderSpec, ModelEntry, OnUnlistedModelsFetch, ProviderEntry,
    ProviderModelCatalog, ProvidersConfig,
};
use crate::daemon::proto::{ProviderModelFetchOutcome, ProviderModelVerification};

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
        assert_eq!(models.count, 4);
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
