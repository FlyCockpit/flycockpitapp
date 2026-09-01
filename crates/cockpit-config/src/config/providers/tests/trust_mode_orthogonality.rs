//! Trust and agent-definition posture are orthogonal policy dimensions.
//!
//! `ModelTrust` is a provider/model data-custody filter; agent-definition
//! posture is an independent harness-steering concern. Neither may be inferred
//! from the other, and custody may never act as a ranking signal.

use super::*;

/// Provider entry with an explicit trust class and one ranked model.
fn combo_provider(trust: ModelTrust, quality: i64, cost: i64) -> ProviderEntry {
    let mut entry = ProviderEntry {
        url: "https://example.invalid/v1".into(),
        trust: Some(trust),
        ..ProviderEntry::default()
    };
    let mut m = model("m", false);
    m.subagent_invokable = Some(true);
    m.quality_rank = Some(quality);
    m.cost_rank = Some(cost);
    m.capabilities.tool_calling = CapabilityStatus::Supported;
    m.capabilities.context_tokens = Some(64_000);
    entry.models.push(m);
    entry
}

/// AC1. Two equal-rank candidates of opposite trust sort solely by stable
/// provider/model identity, for every optimization.
///
/// The removed tie-break preferred the trusted candidate, which made a custody
/// choice leak into ordinary routing: identical models would silently route to
/// a capture-capable provider nobody asked for. Identity is the only remaining
/// tie-break, so flipping *which* side is trusted must not move the
/// winner.
#[test]
fn model_policy_default_ranking_is_trust_neutral() {
    for (trusted_provider, untrusted_provider) in [("alpha", "zulu"), ("zulu", "alpha")] {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            trusted_provider.to_string(),
            combo_provider(ModelTrust::Trusted, 7, 3),
        );
        cfg.providers.insert(
            untrusted_provider.to_string(),
            combo_provider(ModelTrust::Untrusted, 7, 3),
        );

        for optimize in [
            ModelOptimization::Quality,
            ModelOptimization::Balanced,
            ModelOptimization::Cost,
        ] {
            let chosen = cfg
                .resolve_non_sensitive_model_policy(
                    &NonSensitiveModelPolicyRequest::proven_non_sensitive(ModelPolicyCriteria {
                        optimize,
                        ..policy_criteria(ModelPolicySelector::Any)
                    }),
                )
                .unwrap();
            assert_eq!(
                chosen.selector(),
                "alpha:m",
                "{optimize:?} must break the tie on identity, not trust \
                 (trusted provider was `{trusted_provider}`)"
            );
        }

        // The winner's own custody class is reported, never ranked on, and the
        // diagnostics say no custody filter was applied.
        let chosen = cfg
            .resolve_non_sensitive_model_policy(
                &NonSensitiveModelPolicyRequest::proven_non_sensitive(policy_criteria(
                    ModelPolicySelector::Any,
                )),
            )
            .unwrap();
        let diagnostics = chosen.routing_diagnostics();
        assert_eq!(diagnostics.custody_filter, None);
        assert!(diagnostics.custody_filter_reason.contains("non-sensitive"));
        assert_eq!(
            diagnostics.trust,
            if trusted_provider == "alpha" {
                "trusted"
            } else {
                "untrusted"
            }
        );
    }
}

/// AC2. Explicit custody filters select only the requested class and keep every
/// other eligibility check.
#[test]
fn model_policy_explicit_trust_filter_is_preserved() {
    let mut cfg = ProvidersConfig::default();

    let mut trusted_entry = ProviderEntry {
        url: "https://trusted.invalid/v1".into(),
        trust: Some(ModelTrust::Trusted),
        ..ProviderEntry::default()
    };
    let mut trusted_best = model("best", false);
    trusted_best.subagent_invokable = Some(true);
    trusted_best.quality_rank = Some(9);
    trusted_best.cost_rank = Some(9);
    trusted_best.capabilities.tool_calling = CapabilityStatus::Supported;
    trusted_best.capabilities.context_tokens = Some(128_000);
    let mut trusted_cheap = model("cheap", false);
    trusted_cheap.subagent_invokable = Some(true);
    trusted_cheap.quality_rank = Some(1);
    trusted_cheap.cost_rank = Some(1);
    trusted_cheap.capabilities.tool_calling = CapabilityStatus::Supported;
    trusted_cheap.capabilities.context_tokens = Some(128_000);
    // Trusted, but not subagent-invokable and with no tool calling: the custody
    // filter must not rescue it.
    let mut trusted_hidden = model("hidden", false);
    trusted_hidden.subagent_invokable = Some(false);
    trusted_hidden.quality_rank = Some(100);
    trusted_hidden.capabilities.tool_calling = CapabilityStatus::Unsupported;
    trusted_hidden.capabilities.context_tokens = Some(8_000);
    trusted_entry.models = vec![trusted_best, trusted_cheap, trusted_hidden];
    cfg.providers.insert("t".into(), trusted_entry);

    let mut untrusted_entry = ProviderEntry {
        url: "https://untrusted.invalid/v1".into(),
        trust: Some(ModelTrust::Untrusted),
        ..ProviderEntry::default()
    };
    let mut untrusted_best = model("best", false);
    untrusted_best.subagent_invokable = Some(true);
    untrusted_best.quality_rank = Some(50);
    untrusted_best.cost_rank = Some(50);
    untrusted_best.capabilities.tool_calling = CapabilityStatus::Supported;
    untrusted_best.capabilities.context_tokens = Some(128_000);
    untrusted_entry.models = vec![untrusted_best];
    cfg.providers.insert("u".into(), untrusted_entry);

    // Trusted filter: only trusted candidates, and the untrusted model that
    // outranks all of them on quality is never considered.
    let trusted = resolve_sensitive(
        &cfg,
        ModelCustody::Trusted,
        ModelPolicyCriteria {
            require_subagent_invokable: true,
            required_capabilities: vec![RequiredModelCapability::ToolCalling],
            min_context_tokens: Some(64_000),
            optimize: ModelOptimization::Quality,
            ..policy_criteria(ModelPolicySelector::Any)
        },
    )
    .unwrap();
    assert_eq!(trusted.policy.selector(), "t:best");
    assert_eq!(trusted.policy.trust, ModelTrust::Trusted);
    assert_eq!(
        trusted.policy.custody_filter,
        Some(ModelCustody::Trusted),
        "the explicit filter is reported in diagnostics"
    );
    assert!(
        trusted
            .policy
            .routing_diagnostics()
            .custody_filter_reason
            .contains("capture-capable")
    );

    // Cost optimization still applies inside the filtered set.
    let cheapest = resolve_sensitive(
        &cfg,
        ModelCustody::Trusted,
        ModelPolicyCriteria {
            require_subagent_invokable: true,
            optimize: ModelOptimization::Cost,
            ..policy_criteria(ModelPolicySelector::Any)
        },
    )
    .unwrap();
    assert_eq!(cheapest.policy.selector(), "t:cheap");

    // Untrusted filter: only untrusted candidates.
    let untrusted = resolve_sensitive(
        &cfg,
        ModelCustody::Untrusted,
        ModelPolicyCriteria {
            require_subagent_invokable: true,
            optimize: ModelOptimization::Quality,
            ..policy_criteria(ModelPolicySelector::Any)
        },
    )
    .unwrap();
    assert_eq!(untrusted.policy.selector(), "u:best");
    assert_eq!(untrusted.policy.trust, ModelTrust::Untrusted);
    assert!(untrusted.trusted_custody_grant().is_none());

    // Capability, context, and subagent-invokable checks survive the filter.
    let err = resolve_sensitive(
        &cfg,
        ModelCustody::Trusted,
        ModelPolicyCriteria {
            require_subagent_invokable: true,
            min_context_tokens: Some(256_000),
            ..policy_criteria(ModelPolicySelector::Any)
        },
    )
    .unwrap_err();
    assert!(matches!(err, ModelPolicyError::NoEligibleModel(_)));

    let err = resolve_sensitive(
        &cfg,
        ModelCustody::Trusted,
        ModelPolicyCriteria {
            require_subagent_invokable: true,
            required_capabilities: vec![RequiredModelCapability::Embeddings],
            ..policy_criteria(ModelPolicySelector::Any)
        },
    )
    .unwrap_err();
    assert!(matches!(err, ModelPolicyError::NoEligibleModel(_)));

    let err = resolve_sensitive(
        &cfg,
        ModelCustody::Trusted,
        ModelPolicyCriteria {
            require_subagent_invokable: true,
            ..policy_criteria(ModelPolicySelector::Exact("t:hidden"))
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ModelPolicyError::NotSubagentInvokable { provider, model }
            if provider == "t" && model == "hidden"
    ));
}

/// AC3. Every trust class is a valid configuration and harness-steering
/// posture never rewrites or rejects it.
#[test]
fn trust_mode_cartesian_configuration() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.json");
    std::fs::write(&config_path, "{}").unwrap();

    let trusts = [ModelTrust::Trusted, ModelTrust::Untrusted];
    assert_eq!(
        trusts.len(),
        2,
        "both custody classes must stay representable"
    );

    for (index, trust) in trusts.iter().enumerate() {
        let provider_id = format!("p{index}");
        let trust_id = match trust {
            ModelTrust::Trusted => "trusted",
            ModelTrust::Untrusted => "untrusted",
        };
        // 1. Parsing: trust round-trips from disk independently of posture.
        write_provider_file(
            &config_path,
            &provider_id,
            &format!(
                r#"{{
                    "url": "https://{provider_id}.invalid/v1",
                    "trust": "{trust_id}",
                    "models": [{{ "id": "m", "subagent_invokable": true }}]
                }}"#
            ),
        );
    }

    let cfg = ConfigDoc::providers_from_paths(std::slice::from_ref(&config_path));

    for (index, trust) in trusts.iter().enumerate() {
        let provider_id = format!("p{index}");

        // 2. Resolution: trust resolves to exactly what was written.
        assert_eq!(
            cfg.resolve_trust(&provider_id, "m"),
            *trust,
            "{provider_id}: steering posture must not change trust"
        );

        // 3. Persistence / config display: the on-disk document keeps trust
        //    verbatim; it is not normalized away by posture.
        let persisted = read_provider_file(&config_path, &provider_id);
        assert_eq!(
            persisted.get("trust").and_then(Value::as_str),
            Some(match trust {
                ModelTrust::Trusted => "trusted",
                ModelTrust::Untrusted => "untrusted",
            })
        );
        let entry = &cfg.providers[&provider_id];
        assert_eq!(entry.trust, Some(*trust));
        let reserialized = serde_json::to_value(entry).unwrap();
        assert_eq!(
            reserialized.get("trust").and_then(Value::as_str),
            Some(trust_id_of(*trust)),
            "config display must keep trust"
        );

        // 4. Routing diagnostics: a custody filter matching this entry's class
        //    selects it, independent of harness-steering posture.
        let custody = match trust {
            ModelTrust::Trusted => ModelCustody::Trusted,
            ModelTrust::Untrusted => ModelCustody::Untrusted,
        };
        let payload = redacted_payload(custody);
        let selector = format!("{provider_id}:m");
        let resolved = cfg
            .resolve_sensitive_model_policy(
                &SensitiveModelPolicyRequest::new(
                    ModelPolicyCriteria {
                        require_subagent_invokable: true,
                        availability: AvailabilityScope::Discovery,
                        ..policy_criteria(ModelPolicySelector::Exact(&selector))
                    },
                    custody,
                    payload,
                )
                .unwrap(),
            )
            .unwrap();
        let diagnostics = resolved.policy.routing_diagnostics();
        assert_eq!(diagnostics.trust, trust_id_of(*trust));
        assert_eq!(diagnostics.custody_filter, Some(custody.as_str()));
        assert!(
            !diagnostics.custody_filter_reason.is_empty(),
            "the explicit trust filter carries its reason"
        );
    }

    // 5. Picker/setup defaults may apply frontier riders, but never silently
    //    change trust: trust stays conservatively unset, which resolves to
    //    `untrusted` unless the user configures otherwise.
    let mut vendor = model("claude-fable-5", false);
    vendor.trust = None;
    apply_known_frontier_model_defaults(Some("anthropic"), &mut vendor);
    assert_eq!(vendor.auto_prune, Some(false));
    assert_eq!(
        vendor.cache.as_ref().map(|c| c.mode),
        Some(CacheMode::Ephemeral)
    );
    assert_eq!(
        vendor.trust, None,
        "a frontier default must never assert trust"
    );

    let mut copilot = model("gpt-5.5", false);
    copilot.trust = None;
    crate::config::model_defaults::apply_copilot_model_defaults(Some("copilot"), &mut copilot);
    assert_eq!(copilot.auto_prune, Some(false));
    assert_eq!(
        copilot.cache.as_ref().map(|c| c.mode),
        Some(CacheMode::Ephemeral)
    );
    assert_eq!(
        copilot.trust, None,
        "a frontier default must never assert trust"
    );

    let mut templated = model("claude-fable-5", false);
    templated.trust = None;
    apply_template_model_defaults(Some("anthropic"), &mut templated);
    assert_eq!(templated.auto_prune, Some(false));
    assert_eq!(
        templated.cache.as_ref().map(|c| c.mode),
        Some(CacheMode::Ephemeral)
    );
    assert_eq!(templated.trust, None);
    let mut entry = ProviderEntry {
        url: "https://vendor.invalid/v1".into(),
        models: vec![templated],
        ..ProviderEntry::default()
    };
    entry.trust = None;
    let mut cfg_defaults = ProvidersConfig::default();
    cfg_defaults.providers.insert("vendor".into(), entry);
    assert_eq!(
        cfg_defaults.resolve_trust("vendor", "claude-fable-5"),
        ModelTrust::Untrusted,
        "a frontier default must not imply trust"
    );
}

fn trust_id_of(trust: ModelTrust) -> &'static str {
    match trust {
        ModelTrust::Trusted => "trusted",
        ModelTrust::Untrusted => "untrusted",
    }
}

/// AC4. Custody is type-enforced.
///
/// The compile-time half is structural and cannot be expressed as a runtime
/// assertion: [`SensitiveModelPolicyRequest::new`] takes [`ModelCustody`] by
/// value (no `Option`, no `Default`), and the old
/// `ModelPolicyRequest.trust: Option<ModelTrust>` field no longer exists, so a
/// potentially sensitive caller cannot construct a request without choosing
/// `Trusted` or `Untrusted`. Only
/// [`NonSensitiveModelPolicyRequest::proven_non_sensitive`] omits custody.
/// This test pins the runtime consequences of that shape at the API level.
///
/// The other half of AC4 — that the *real* construction paths cannot bypass
/// this API — lives where those paths do, in
/// `cockpit-core::engine::model::custody_boundary_tests` (active model,
/// configured utility targets, grant/destination binding, fall-closed) and
/// `cockpit-core::embeddings` (the embedding send boundary).
#[test]
fn model_policy_custody_requirements_are_type_enforced() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers
        .insert("t".into(), combo_provider(ModelTrust::Trusted, 5, 5));
    cfg.providers
        .insert("u".into(), combo_provider(ModelTrust::Untrusted, 5, 5));

    // A payload built for one class can never be routed under the other.
    let mismatch = SensitiveModelPolicyRequest::new(
        policy_criteria(ModelPolicySelector::Any),
        ModelCustody::Trusted,
        redacted_payload(ModelCustody::Untrusted),
    )
    .unwrap_err();
    assert!(matches!(
        mismatch,
        ModelPolicyError::CustodyPayloadMismatch {
            requested: ModelCustody::Trusted,
            payload: ModelCustody::Untrusted,
        }
    ));

    // The non-sensitive type is the only one that omits custody.
    let non_sensitive = cfg
        .resolve_non_sensitive_model_policy(&NonSensitiveModelPolicyRequest::proven_non_sensitive(
            policy_criteria(ModelPolicySelector::Any),
        ))
        .unwrap();
    assert_eq!(non_sensitive.custody_filter, None);

    // A trusted selection mints a capture grant, never a raw egress grant.
    let trusted = cfg
        .resolve_sensitive_model_policy(
            &SensitiveModelPolicyRequest::new(
                ModelPolicyCriteria {
                    availability: AvailabilityScope::Discovery,
                    ..policy_criteria(ModelPolicySelector::Exact("t:m"))
                },
                ModelCustody::Trusted,
                redacted_payload(ModelCustody::Trusted),
            )
            .unwrap(),
        )
        .unwrap();
    let grant = trusted
        .trusted_custody_grant()
        .expect("a trusted selection mints a grant");
    assert_eq!(grant.provider(), "t");
    assert_eq!(grant.model(), "m");
    let rendered =
        redacted_payload(ModelCustody::Trusted).render(&trusted.policy, CUSTODY_TEST_SECRET);
    assert!(rendered.contains("t:m"), "{rendered}");
    assert!(!rendered.contains(CUSTODY_TEST_SECRET), "{rendered}");
    let untrusted = cfg
        .resolve_sensitive_model_policy(
            &SensitiveModelPolicyRequest::new(
                ModelPolicyCriteria {
                    availability: AvailabilityScope::Discovery,
                    ..policy_criteria(ModelPolicySelector::Exact("u:m"))
                },
                ModelCustody::Untrusted,
                redacted_payload(ModelCustody::Untrusted),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(untrusted.trusted_custody_grant().is_none());
    let rendered =
        redacted_payload(ModelCustody::Untrusted).render(&untrusted.policy, CUSTODY_TEST_SECRET);
    assert!(rendered.contains("u:m"), "{rendered}");
    assert!(!rendered.contains(CUSTODY_TEST_SECRET));

    // Exact selection: a custody mismatch rejects before dispatch and never
    // falls back to the other, otherwise-eligible model.
    for (selector, custody, actual) in [
        ("t:m", ModelCustody::Untrusted, ModelTrust::Trusted),
        ("u:m", ModelCustody::Trusted, ModelTrust::Untrusted),
    ] {
        let payload = redacted_payload(custody);
        let err = cfg
            .resolve_sensitive_model_policy(
                &SensitiveModelPolicyRequest::new(
                    ModelPolicyCriteria {
                        availability: AvailabilityScope::Discovery,
                        ..policy_criteria(ModelPolicySelector::Exact(selector))
                    },
                    custody,
                    payload,
                )
                .unwrap(),
            )
            .unwrap_err();
        let ModelPolicyError::CustodyMismatch {
            provider,
            model,
            required,
            actual: reported,
        } = err
        else {
            panic!("expected a custody mismatch for {selector}, got {err:?}");
        };
        assert_eq!(format!("{provider}:{model}"), selector);
        assert_eq!(required, custody);
        assert_eq!(reported, actual);
    }

    // The capture grant is bound to the destination it was minted for.
    let mut two_trusted = ProvidersConfig::default();
    two_trusted
        .providers
        .insert("t".into(), combo_provider(ModelTrust::Trusted, 5, 5));
    two_trusted
        .providers
        .insert("t2".into(), combo_provider(ModelTrust::Trusted, 5, 5));
    let first = resolve_sensitive(
        &two_trusted,
        ModelCustody::Trusted,
        policy_criteria(ModelPolicySelector::Exact("t:m")),
    )
    .unwrap();
    let second = resolve_sensitive(
        &two_trusted,
        ModelCustody::Trusted,
        policy_criteria(ModelPolicySelector::Exact("t2:m")),
    )
    .unwrap();
    let first_grant = first.trusted_custody_grant().unwrap();
    assert!(first_grant.authorizes(&first.policy));
    assert!(
        !first_grant.authorizes(&second.policy),
        "a grant must not authorize a different destination"
    );
    // An untrusted destination can never be authorized by any capture grant.
    let untrusted_route = cfg
        .resolve_non_sensitive_model_policy(&NonSensitiveModelPolicyRequest::proven_non_sensitive(
            policy_criteria(ModelPolicySelector::Exact("u:m")),
        ))
        .unwrap();
    assert!(!first_grant.authorizes(&untrusted_route));
}

/// Regression, both directions: `availability` scopes **discovery**, not an
/// explicit host reference.
///
/// A category allowlist must not make a model unresolvable when the host names
/// it exactly (agent-file frontmatter, a configured role default, a configured
/// backup) — that broke every allowlisted model. It must still gate
/// model-originated category selection, which is what the allowlist is for.
#[test]
fn availability_allowlists_scope_discovery_not_host_named_targets() {
    let mut cfg = ProvidersConfig::default();
    let mut entry = ProviderEntry {
        url: "https://p.invalid/v1".into(),
        trust: Some(ModelTrust::Untrusted),
        ..ProviderEntry::default()
    };
    let mut scoped = model("scoped", false);
    scoped.subagent_invokable = Some(true);
    scoped.availability = ModelAvailability {
        categories: vec!["reasoning".to_string()],
        ..ModelAvailability::default()
    };
    let mut open = model("open", false);
    open.subagent_invokable = Some(true);
    entry.models = vec![scoped, open];
    cfg.providers.insert("p".into(), entry);

    // Direction 1: the host names the allowlisted model exactly — it resolves.
    let resolved = resolve_sensitive(
        &cfg,
        ModelCustody::Untrusted,
        ModelPolicyCriteria {
            availability: AvailabilityScope::HostNamedTarget,
            ..policy_criteria(ModelPolicySelector::Exact("p:scoped"))
        },
    )
    .expect("a host-named exact target is not gated by a category allowlist");
    assert_eq!(resolved.policy.selector(), "p:scoped");

    // The same reference under discovery scoping is refused, which is the
    // regression this test pins: that refusal must not reach host-named paths.
    let err = resolve_sensitive(
        &cfg,
        ModelCustody::Untrusted,
        policy_criteria(ModelPolicySelector::Exact("p:scoped")),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ModelPolicyError::RestrictedByAvailability { .. }
    ));

    // Direction 2: model-originated category selection still respects the
    // allowlist — `p:scoped` is reachable via `reasoning`, never via
    // `cheap_code`.
    let reasoning = resolve_sensitive(
        &cfg,
        ModelCustody::Untrusted,
        ModelPolicyCriteria {
            require_subagent_invokable: true,
            role: Some("reasoning"),
            ..policy_criteria(ModelPolicySelector::Category("reasoning"))
        },
    )
    .unwrap();
    assert_eq!(reasoning.policy.selector(), "p:scoped");

    let cheap = resolve_sensitive(
        &cfg,
        ModelCustody::Untrusted,
        ModelPolicyCriteria {
            require_subagent_invokable: true,
            role: Some("cheap_code"),
            ..policy_criteria(ModelPolicySelector::Category("cheap_code"))
        },
    )
    .unwrap();
    assert_eq!(
        cheap.policy.selector(),
        "p:open",
        "the allowlisted model must not be discoverable outside its category"
    );

    // A host-named target that does not exist still fails loudly.
    assert!(matches!(
        resolve_sensitive(
            &cfg,
            ModelCustody::Untrusted,
            ModelPolicyCriteria {
                availability: AvailabilityScope::HostNamedTarget,
                ..policy_criteria(ModelPolicySelector::Exact("p:missing"))
            },
        )
        .unwrap_err(),
        ModelPolicyError::UnknownModel { .. }
    ));

    // Host-naming bypasses discovery scoping only. Custody still applies.
    let mut trusted_cfg = cfg.clone();
    trusted_cfg
        .providers
        .get_mut("p")
        .unwrap()
        .models
        .iter_mut()
        .for_each(|m| m.trust = Some(ModelTrust::Trusted));
    assert!(matches!(
        resolve_sensitive(
            &trusted_cfg,
            ModelCustody::Untrusted,
            ModelPolicyCriteria {
                availability: AvailabilityScope::HostNamedTarget,
                ..policy_criteria(ModelPolicySelector::Exact("p:scoped"))
            },
        )
        .unwrap_err(),
        ModelPolicyError::CustodyMismatch { .. }
    ));
}

/// The payload-less eligibility API decides *whether* a route exists without
/// constructing a payload or minting a grant, so an eligibility check can never
/// be used to render or release anything.
#[test]
fn eligibility_api_takes_no_payload_and_mints_no_grant() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers
        .insert("t".into(), combo_provider(ModelTrust::Trusted, 5, 5));

    let eligible = cfg
        .resolve_sensitive_model_policy_eligibility(
            &ModelPolicyCriteria {
                availability: AvailabilityScope::HostNamedTarget,
                ..policy_criteria(ModelPolicySelector::Exact("t:m"))
            },
            ModelCustody::Trusted,
        )
        .unwrap();
    assert_eq!(eligible.trust, ModelTrust::Trusted);
    assert_eq!(eligible.custody_filter, Some(ModelCustody::Trusted));

    // There is no grant anywhere in the returned value, so no raw bytes can be
    // released from an eligibility decision.
    let err = cfg
        .resolve_sensitive_model_policy_eligibility(
            &ModelPolicyCriteria {
                availability: AvailabilityScope::HostNamedTarget,
                ..policy_criteria(ModelPolicySelector::Exact("t:m"))
            },
            ModelCustody::Untrusted,
        )
        .unwrap_err();
    assert!(matches!(err, ModelPolicyError::CustodyMismatch { .. }));
}

/// Decision (B): backup/failover custody is upgrade-only.
///
/// An untrusted primary may fail over to an untrusted or a trusted candidate —
/// moving work onto a self-hosted/no-log endpoint is never a regression. A
/// trusted primary may only fail over to another trusted candidate; a
/// downgrade is a typed refusal so it can never happen silently.
#[test]
fn failover_custody_is_upgrade_only() {
    let untrusted_primary = FailoverCustody::for_primary(ModelTrust::Untrusted);
    assert!(untrusted_primary.admits(ModelTrust::Untrusted));
    assert!(
        untrusted_primary.admits(ModelTrust::Trusted),
        "an upgrade onto a trusted endpoint is permitted"
    );
    assert_eq!(
        untrusted_primary
            .custody_for("p", "m", ModelTrust::Untrusted)
            .unwrap(),
        ModelCustody::Untrusted
    );
    assert_eq!(
        untrusted_primary
            .custody_for("p", "m", ModelTrust::Trusted)
            .unwrap(),
        ModelCustody::Trusted
    );

    let trusted_primary = FailoverCustody::for_primary(ModelTrust::Trusted);
    assert!(trusted_primary.admits(ModelTrust::Trusted));
    assert!(
        !trusted_primary.admits(ModelTrust::Untrusted),
        "a trusted primary must never silently downgrade"
    );
    assert_eq!(
        trusted_primary
            .custody_for("p", "m", ModelTrust::Trusted)
            .unwrap(),
        ModelCustody::Trusted
    );
    let refusal = trusted_primary
        .custody_for("cloud", "m", ModelTrust::Untrusted)
        .unwrap_err();
    let ModelPolicyError::CustodyDowngradeRefused {
        provider,
        model,
        primary,
        candidate,
    } = &refusal
    else {
        panic!("expected a typed downgrade refusal, got {refusal:?}");
    };
    assert_eq!(provider, "cloud");
    assert_eq!(model, "m");
    assert_eq!(*primary, ModelTrust::Trusted);
    assert_eq!(*candidate, ModelTrust::Untrusted);
    let message = refusal.to_string();
    assert!(message.contains("upgrade-only"), "{message}");
    assert!(message.contains("never downgrades custody"), "{message}");
}
