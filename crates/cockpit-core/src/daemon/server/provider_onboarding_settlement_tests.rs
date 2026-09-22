use super::*;

enum Scenario {
    Catalog,
    InterveningBeforeCatalog,
    InterveningAfterCatalog,
    ForgedGeneration,
    ReboundGeneration,
    SupersededOperation,
    InvalidCheckpoint,
    WorkerRecovery,
}

async fn provider_settlement_sequence(scenario: Scenario) {
    let (_env, _tmp, ctx, mut state, workspace) = fresh_untrusted_workspace().await;
    let capabilities = cockpit_proto::HostCapabilitySnapshot::unpublished();
    let (mut snapshot, _) = ctx
        .onboarding
        .begin_or_reopen(
            proto::BeginOrReopenOnboarding {
                expected_revision: None,
                client_operation_id: "begin-provider-settlement".into(),
                reentry: false,
            },
            capabilities.clone(),
        )
        .await
        .unwrap();
    for operation in ["welcome", "profile"] {
        (snapshot, _) = ctx
            .onboarding
            .apply_transition(
                proto::ApplyOnboardingTransition {
                    run_id: snapshot.run_id,
                    attempt_id: snapshot.attempt_id,
                    expected_revision: snapshot.revision,
                    client_operation_id: operation.into(),
                    transition: proto::OnboardingTransitionKind::Advance,
                    settlement: None,
                },
                capabilities.clone(),
            )
            .await
            .unwrap();
    }
    // This fixture already owns a materialized vault. Use its production
    // ready publication, then exercise all provider writes through dispatch.
    // The timing case deliberately commits before entering Provider; it must
    // not be usable at the later checkpoint, even after worker recovery.
    if !matches!(scenario, Scenario::SupersededOperation) {
        (snapshot, _) = ctx
            .onboarding
            .mark_secure_store_ready(&snapshot, "secure-ready".into(), capabilities.clone())
            .await
            .unwrap();
        assert_eq!(snapshot.stage, proto::OnboardingStage::Provider);
    }
    let stage_generation = inventory::current_config_generation();
    super::super::recover_before_socket_publish(&ctx)
        .await
        .unwrap();
    assert_eq!(inventory::current_config_generation(), stage_generation);

    let url = one_shot_models_response(
        200,
        "OK",
        r#"{"data":[{"id":"verified-model","object":"model"}]}"#,
    )
    .await;
    let catalog = take_onboarding_catalog(&ctx, &mut state, &workspace, "provider-verify").await;
    let mutation = proto::ProviderMutationBatch {
        upserts: vec![proto::ProviderMutationUpsert {
            provider_id: "onboard".into(),
            entry: crate::config::providers::ProviderEntry {
                template: Some("openai-compatible".into()),
                url,
                allow_insecure_http: true,
                auth: Some(crate::config::providers::AuthKind::None),
                ..Default::default()
            },
            header_secrets: Vec::new(),
        }],
        deletes: Vec::new(),
        metadata: None,
    };
    let response =
        apply_onboarding_mutation(&ctx, &mut state, &catalog, "provider-verify", mutation).await;
    let Response::ProviderMutationCommitted {
        config_generation: receipt_generation,
        mutation_intent_hash,
        status: proto::ConfigCommitStatus::Committed,
        ..
    } = response
    else {
        panic!("expected a committed provider mutation: {response:?}");
    };
    assert!(receipt_generation > stage_generation);

    if matches!(scenario, Scenario::InterveningBeforeCatalog) {
        inventory::publish_committed_config_generation();
    }
    let response = handle_request(
        Request::FetchProviderModels {
            project_root: workspace.to_string_lossy().into_owned(),
            provider_id: Some("onboard".into()),
            model_id: None,
            deep: false,
            // Match the production Verify request, including its Keep policy.
            on_unlisted: Some(crate::config::providers::OnUnlistedModelsFetch::Keep),
            allow_fallback: false,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("verification must persist its catalog");
    let Response::ProviderModelsFetched {
        config_generation: catalog_generation,
        results,
        ..
    } = response
    else {
        panic!("expected fetched models: {response:?}");
    };
    assert!(catalog_generation > receipt_generation);
    assert!(matches!(
        &results[0].outcome,
        proto::ProviderModelFetchOutcome::Models { models, .. }
            if models.iter().any(|model| model.id == "verified-model")
    ));

    if matches!(scenario, Scenario::InterveningAfterCatalog) {
        inventory::publish_committed_config_generation();
    }
    if matches!(
        scenario,
        Scenario::WorkerRecovery | Scenario::SupersededOperation | Scenario::InvalidCheckpoint
    ) {
        // Simulate the only state lost by a worker replacement. The mutation
        // and onboarding receipts remain in the real database.
        inventory::reset_config_generation_for_test(0);
        super::super::recover_before_socket_publish(&ctx)
            .await
            .unwrap();
        assert_eq!(inventory::current_config_generation(), stage_generation);
    }
    if matches!(scenario, Scenario::SupersededOperation) {
        (snapshot, _) = ctx
            .onboarding
            .mark_secure_store_ready(&snapshot, "secure-ready".into(), capabilities)
            .await
            .unwrap();
        assert_eq!(snapshot.stage, proto::OnboardingStage::Provider);
    }
    let generation_before_advance = inventory::current_config_generation();
    let mut settlement = proto::OnboardingStageSettlement {
        run_id: snapshot.run_id,
        attempt_id: snapshot.attempt_id,
        stage_revision: snapshot.revision,
        settlement_operation_id: "provider-verify".into(),
        provider_id: Some("onboard".into()),
        mutation_intent_hash: Some(mutation_intent_hash),
        provider_mutation_config_generation: Some(receipt_generation),
        wizard_id: None,
        config_generation: receipt_generation,
    };
    match scenario {
        Scenario::ForgedGeneration => settlement.config_generation = receipt_generation + 999,
        Scenario::ReboundGeneration => {
            settlement.config_generation = catalog_generation;
            settlement.provider_mutation_config_generation = Some(catalog_generation);
        }
        Scenario::InvalidCheckpoint => settlement.stage_revision += 1,
        _ => {}
    }
    let result = handle_request(
        Request::ApplyOnboardingTransition(proto::ApplyOnboardingTransition {
            run_id: snapshot.run_id,
            attempt_id: snapshot.attempt_id,
            expected_revision: settlement.stage_revision,
            client_operation_id: "provider-done".into(),
            transition: proto::OnboardingTransitionKind::Advance,
            settlement: Some(settlement),
        }),
        &mut state,
        &ctx,
    )
    .await;
    if matches!(scenario, Scenario::Catalog | Scenario::WorkerRecovery) {
        let Response::OnboardingTransition(result) = result.expect("Provider Done must advance")
        else {
            panic!("expected onboarding transition");
        };
        assert_eq!(result.snapshot.stage, proto::OnboardingStage::Model);
        assert_eq!(result.snapshot.revision, snapshot.revision + 1);
    } else {
        let error = result.expect_err("unrelated or invalid settlement must fail closed");
        assert_eq!(
            error.code,
            if matches!(scenario, Scenario::InvalidCheckpoint) {
                ErrorCode::Conflict
            } else {
                ErrorCode::BadRequest
            }
        );
        if matches!(scenario, Scenario::SupersededOperation) {
            assert!(error.message.contains("superseded checkpoint"), "{error:?}");
        }
        assert_eq!(
            inventory::current_config_generation(),
            generation_before_advance,
            "a rejected transition must not publish authority"
        );
        assert_eq!(
            ctx.db
                .onboarding_snapshot()
                .await
                .unwrap()
                .unwrap()
                .revision,
            snapshot.revision
        );
    }
}

#[tokio::test]
async fn provider_settlement_accepts_mutation_catalog_advance() {
    provider_settlement_sequence(Scenario::Catalog).await;
}

#[tokio::test]
async fn provider_settlement_rejects_publication_before_catalog() {
    provider_settlement_sequence(Scenario::InterveningBeforeCatalog).await;
}

#[tokio::test]
async fn provider_settlement_rejects_publication_after_catalog() {
    provider_settlement_sequence(Scenario::InterveningAfterCatalog).await;
}

#[tokio::test]
async fn provider_settlement_rejects_forged_generation() {
    provider_settlement_sequence(Scenario::ForgedGeneration).await;
}

#[tokio::test]
async fn provider_settlement_rejects_client_rebinding_to_catalog() {
    provider_settlement_sequence(Scenario::ReboundGeneration).await;
}

#[tokio::test]
async fn provider_settlement_timing_rejection_does_not_restore_authority() {
    provider_settlement_sequence(Scenario::SupersededOperation).await;
}

#[tokio::test]
async fn provider_settlement_survives_worker_recovery() {
    provider_settlement_sequence(Scenario::WorkerRecovery).await;
}

#[tokio::test]
async fn provider_settlement_checkpoint_rejection_does_not_restore_authority() {
    provider_settlement_sequence(Scenario::InvalidCheckpoint).await;
}
