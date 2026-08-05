//! Multimodal input capability types, precedence, requirement errors, and
//! generation-keyed refresh/switch behavior.

use super::*;
use crate::config::model_policy::{
    EffectiveCapabilitySource, ModelPolicyError, RequiredModelCapabilityOutcome,
    required_model_capability_outcome, status_to_required_outcome,
};

#[test]
fn multimodal_capability_types_round_trip_independent_states() {
    let entry = ProviderEntry {
        capabilities: ProviderCapabilities {
            image_input: CapabilityStatus::Supported,
            audio_input: CapabilityStatus::Unsupported,
            video_input: CapabilityStatus::RequiresEntitlement,
            ..ProviderCapabilities::default()
        },
        models: vec![ModelEntry {
            id: "m".into(),
            capabilities: ModelCapabilities {
                image_input: CapabilityStatus::Unsupported,
                audio_input: CapabilityStatus::Supported,
                video_input: CapabilityStatus::Unknown,
                ..ModelCapabilities::default()
            },
            capability_overrides: ModelCapabilityOverrides {
                image_input: Some(CapabilityStatus::Supported),
                audio_input: Some(CapabilityStatus::Unsupported),
                // RequiresEntitlement is not a valid manual override and must
                // not be asserted here — omitted means Auto.
                video_input: None,
                ..ModelCapabilityOverrides::default()
            },
            inputs: Some(Inputs {
                images: Some(true),
                audio: Some(true),
                video: Some(true),
            }),
            ..ModelEntry::default()
        }],
        ..ProviderEntry::default()
    };

    let json = serde_json::to_string(&entry).unwrap();
    let back: ProviderEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.capabilities.image_input, CapabilityStatus::Supported);
    assert_eq!(back.capabilities.audio_input, CapabilityStatus::Unsupported);
    assert_eq!(
        back.capabilities.video_input,
        CapabilityStatus::RequiresEntitlement
    );
    let model = &back.models[0];
    assert_eq!(
        model.capability_overrides.image_input,
        Some(CapabilityStatus::Supported)
    );
    assert_eq!(
        model.capability_overrides.audio_input,
        Some(CapabilityStatus::Unsupported)
    );
    assert_eq!(model.capability_overrides.video_input, None);
    assert!(model.capabilities.video_input.is_unknown());

    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert("p".into(), entry.clone());
    let config_gen = 42;
    let caps = cfg.resolve_effective_model_capabilities("p", "m", config_gen);
    assert_eq!(caps.config_generation, config_gen);
    assert_eq!(caps.image_input.source_generation, config_gen);
    assert_eq!(caps.audio_input.source_generation, config_gen);
    assert_eq!(caps.video_input.source_generation, config_gen);
    assert_eq!(caps.image_input.source, EffectiveCapabilitySource::Override);
    assert_eq!(caps.audio_input.source, EffectiveCapabilitySource::Override);
    // Auto video falls through model Unknown → provider RequiresEntitlement.
    assert_eq!(
        caps.video_input.status,
        CapabilityStatus::RequiresEntitlement
    );
    assert_eq!(caps.video_input.source, EffectiveCapabilitySource::Provider);

    // Omitted capability fields deserialize as Unknown, not Supported/Unsupported.
    let bare: ModelCapabilities = serde_json::from_str("{}").unwrap();
    assert!(bare.image_input.is_unknown());
    assert!(bare.audio_input.is_unknown());
    assert!(bare.video_input.is_unknown());
    let _ = entry;
}

#[test]
fn multimodal_capability_precedence_table_for_all_modalities() {
    #[derive(Clone, Copy)]
    struct Case {
        name: &'static str,
        override_status: Option<CapabilityStatus>,
        model: CapabilityStatus,
        provider: CapabilityStatus,
        legacy_true: bool,
        expect_status: CapabilityStatus,
        expect_source: EffectiveCapabilitySource,
    }

    let cases = [
        Case {
            name: "explicit override Supported",
            override_status: Some(CapabilityStatus::Supported),
            model: CapabilityStatus::Unsupported,
            provider: CapabilityStatus::Unsupported,
            legacy_true: false,
            expect_status: CapabilityStatus::Supported,
            expect_source: EffectiveCapabilitySource::Override,
        },
        Case {
            name: "explicit override Unsupported",
            override_status: Some(CapabilityStatus::Unsupported),
            model: CapabilityStatus::Supported,
            provider: CapabilityStatus::Supported,
            legacy_true: true,
            expect_status: CapabilityStatus::Unsupported,
            expect_source: EffectiveCapabilitySource::Override,
        },
        Case {
            name: "model metadata wins over provider and legacy",
            override_status: None,
            model: CapabilityStatus::RequiresEntitlement,
            provider: CapabilityStatus::Supported,
            legacy_true: true,
            expect_status: CapabilityStatus::RequiresEntitlement,
            expect_source: EffectiveCapabilitySource::Model,
        },
        Case {
            name: "provider default when model unknown",
            override_status: None,
            model: CapabilityStatus::Unknown,
            provider: CapabilityStatus::Unsupported,
            legacy_true: true,
            expect_status: CapabilityStatus::Unsupported,
            expect_source: EffectiveCapabilitySource::Provider,
        },
        Case {
            name: "legacy listed only when higher sources unknown",
            override_status: None,
            model: CapabilityStatus::Unknown,
            provider: CapabilityStatus::Unknown,
            legacy_true: true,
            expect_status: CapabilityStatus::Supported,
            expect_source: EffectiveCapabilitySource::Legacy,
        },
        Case {
            name: "legacy absence is Unknown never Unsupported",
            override_status: None,
            model: CapabilityStatus::Unknown,
            provider: CapabilityStatus::Unknown,
            legacy_true: false,
            expect_status: CapabilityStatus::Unknown,
            expect_source: EffectiveCapabilitySource::None,
        },
        Case {
            name: "RequiresEntitlement override is ignored as Auto",
            override_status: Some(CapabilityStatus::RequiresEntitlement),
            model: CapabilityStatus::Supported,
            provider: CapabilityStatus::Unknown,
            legacy_true: false,
            expect_status: CapabilityStatus::Supported,
            expect_source: EffectiveCapabilitySource::Model,
        },
        Case {
            name: "contradictory lower sources do not override winner",
            override_status: None,
            model: CapabilityStatus::Supported,
            provider: CapabilityStatus::Unsupported,
            legacy_true: false,
            expect_status: CapabilityStatus::Supported,
            expect_source: EffectiveCapabilitySource::Model,
        },
    ];

    for case in cases {
        for modality in ["image", "audio", "video"] {
            let mut model_caps = ModelCapabilities::default();
            let mut provider_caps = ProviderCapabilities::default();
            let mut overrides = ModelCapabilityOverrides::default();
            let mut inputs = Inputs::default();
            match modality {
                "image" => {
                    model_caps.image_input = case.model;
                    provider_caps.image_input = case.provider;
                    overrides.image_input = case.override_status;
                    inputs.images = case.legacy_true.then_some(true);
                }
                "audio" => {
                    model_caps.audio_input = case.model;
                    provider_caps.audio_input = case.provider;
                    overrides.audio_input = case.override_status;
                    inputs.audio = case.legacy_true.then_some(true);
                }
                "video" => {
                    model_caps.video_input = case.model;
                    provider_caps.video_input = case.provider;
                    overrides.video_input = case.override_status;
                    inputs.video = case.legacy_true.then_some(true);
                }
                _ => unreachable!(),
            }
            // Contradictory lower sources for diagnostics only: seed the other
            // two modalities with opposite statuses; they must not leak.
            match modality {
                "image" => {
                    model_caps.audio_input = CapabilityStatus::Unsupported;
                    model_caps.video_input = CapabilityStatus::Unsupported;
                }
                "audio" => {
                    model_caps.image_input = CapabilityStatus::Unsupported;
                    model_caps.video_input = CapabilityStatus::Unsupported;
                }
                "video" => {
                    model_caps.image_input = CapabilityStatus::Unsupported;
                    model_caps.audio_input = CapabilityStatus::Unsupported;
                }
                _ => unreachable!(),
            }

            let mut cfg = ProvidersConfig::default();
            cfg.providers.insert(
                "p".into(),
                ProviderEntry {
                    capabilities: provider_caps,
                    models: vec![ModelEntry {
                        id: "m".into(),
                        capabilities: model_caps,
                        capability_overrides: overrides,
                        inputs: Some(inputs),
                        ..ModelEntry::default()
                    }],
                    ..ProviderEntry::default()
                },
            );
            let caps = cfg.resolve_effective_model_capabilities("p", "m", 7);
            let resolved = match modality {
                "image" => caps.image_input,
                "audio" => caps.audio_input,
                "video" => caps.video_input,
                _ => unreachable!(),
            };
            assert_eq!(
                resolved.status, case.expect_status,
                "{} / {modality} status",
                case.name
            );
            assert_eq!(
                resolved.source, case.expect_source,
                "{} / {modality} source",
                case.name
            );
            assert_eq!(resolved.source_generation, 7);
        }
    }
}

#[test]
fn multimodal_capability_required_error_mapping() {
    let statuses = [
        (
            CapabilityStatus::Supported,
            RequiredModelCapabilityOutcome::Allow,
            None,
        ),
        (
            CapabilityStatus::Unsupported,
            RequiredModelCapabilityOutcome::Unsupported,
            Some("model_capability_unsupported"),
        ),
        (
            CapabilityStatus::RequiresEntitlement,
            RequiredModelCapabilityOutcome::RequiresEntitlement,
            Some("model_capability_requires_entitlement"),
        ),
        (
            CapabilityStatus::Unknown,
            RequiredModelCapabilityOutcome::Unknown,
            Some("model_capability_unknown"),
        ),
    ];

    for (status, expect_outcome, expect_code) in statuses {
        assert_eq!(status_to_required_outcome(status), expect_outcome);
        for required in [
            RequiredModelCapability::ImageInput,
            RequiredModelCapability::AudioInput,
            RequiredModelCapability::VideoInput,
            RequiredModelCapability::ToolCalling,
            RequiredModelCapability::Reasoning,
            RequiredModelCapability::StructuredOutputs,
        ] {
            let mut caps = EffectiveModelCapabilities::default();
            match required {
                RequiredModelCapability::ImageInput => caps.image_input.status = status,
                RequiredModelCapability::AudioInput => caps.audio_input.status = status,
                RequiredModelCapability::VideoInput => caps.video_input.status = status,
                RequiredModelCapability::ToolCalling => caps.tool_calling = status,
                RequiredModelCapability::Reasoning => caps.reasoning = status,
                RequiredModelCapability::StructuredOutputs => caps.structured_outputs = status,
                RequiredModelCapability::Embeddings => unreachable!(),
            }
            let outcome = required_model_capability_outcome(&caps, required);
            assert_eq!(outcome, expect_outcome, "{required:?} / {status:?}");
            assert_eq!(required.error_code(outcome), expect_code);

            // Live policy conversion must preserve distinct error variants /
            // remediation codes (not collapse to a single MissingCapability).
            let policy_err =
                ModelPolicyError::from_required_capability("prov", "mod", required, outcome);
            match (expect_outcome, policy_err) {
                (RequiredModelCapabilityOutcome::Allow, None) => {}
                (
                    RequiredModelCapabilityOutcome::Unsupported,
                    Some(ModelPolicyError::CapabilityUnsupported { capability, .. }),
                ) => {
                    assert_eq!(capability, required);
                    assert_eq!(
                        ModelPolicyError::CapabilityUnsupported {
                            provider: "prov".into(),
                            model: "mod".into(),
                            capability: required,
                        }
                        .capability_error_code(),
                        expect_code
                    );
                }
                (
                    RequiredModelCapabilityOutcome::Unknown,
                    Some(ModelPolicyError::CapabilityUnknown { capability, .. }),
                ) => {
                    assert_eq!(capability, required);
                    assert_eq!(
                        ModelPolicyError::CapabilityUnknown {
                            provider: "prov".into(),
                            model: "mod".into(),
                            capability: required,
                        }
                        .capability_error_code(),
                        expect_code
                    );
                }
                (
                    RequiredModelCapabilityOutcome::RequiresEntitlement,
                    Some(ModelPolicyError::CapabilityRequiresEntitlement { capability, .. }),
                ) => {
                    assert_eq!(capability, required);
                    assert_eq!(
                        ModelPolicyError::CapabilityRequiresEntitlement {
                            provider: "prov".into(),
                            model: "mod".into(),
                            capability: required,
                        }
                        .capability_error_code(),
                        expect_code
                    );
                }
                (outcome, err) => {
                    panic!("unexpected policy mapping for {required:?}: {outcome:?} → {err:?}")
                }
            }
        }
    }

    // Embeddings remains bool-shaped but maps through the same outcome table.
    let mut caps = EffectiveModelCapabilities {
        embeddings: Some(true),
        ..EffectiveModelCapabilities::default()
    };
    assert_eq!(
        required_model_capability_outcome(&caps, RequiredModelCapability::Embeddings),
        RequiredModelCapabilityOutcome::Allow
    );
    caps.embeddings = Some(false);
    assert_eq!(
        required_model_capability_outcome(&caps, RequiredModelCapability::Embeddings),
        RequiredModelCapabilityOutcome::Unsupported
    );
    caps.embeddings = None;
    assert_eq!(
        required_model_capability_outcome(&caps, RequiredModelCapability::Embeddings),
        RequiredModelCapabilityOutcome::Unknown
    );
}

#[test]
fn multimodal_capability_refresh_switch_and_stale_generation() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "p".into(),
        ProviderEntry {
            models: vec![ModelEntry {
                id: "m".into(),
                capabilities: ModelCapabilities {
                    image_input: CapabilityStatus::Unsupported,
                    audio_input: CapabilityStatus::Unknown,
                    ..ModelCapabilities::default()
                },
                capability_overrides: ModelCapabilityOverrides {
                    image_input: Some(CapabilityStatus::Supported),
                    ..ModelCapabilityOverrides::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );

    let gen1 = cfg.resolve_effective_model_capabilities("p", "m", 1);
    assert!(gen1.supports_image_input());
    assert_eq!(gen1.image_input.source, EffectiveCapabilitySource::Override);
    assert_eq!(gen1.audio_input.status, CapabilityStatus::Unknown);

    // Refresh updates detected metadata; explicit override survives.
    cfg.providers.get_mut("p").unwrap().models[0]
        .capabilities
        .image_input = CapabilityStatus::Unsupported;
    cfg.providers.get_mut("p").unwrap().models[0]
        .capabilities
        .audio_input = CapabilityStatus::Supported;
    let gen2 = cfg.resolve_effective_model_capabilities("p", "m", 2);
    assert!(gen2.supports_image_input());
    assert_eq!(gen2.image_input.source, EffectiveCapabilitySource::Override);
    assert!(gen2.supports_audio_input());
    assert_eq!(gen2.audio_input.source, EffectiveCapabilitySource::Model);
    assert_eq!(gen2.config_generation, 2);

    // Auto (clear override) follows new metadata.
    cfg.providers.get_mut("p").unwrap().models[0]
        .capability_overrides
        .image_input = None;
    let gen3 = cfg.resolve_effective_model_capabilities("p", "m", 3);
    assert!(!gen3.supports_image_input());
    assert_eq!(gen3.image_input.status, CapabilityStatus::Unsupported);
    assert_eq!(gen3.image_input.source, EffectiveCapabilitySource::Model);

    // Active-model switch recomputes from the new identity; prior generation
    // results are inert and must not be mixed in by callers.
    cfg.providers.get_mut("p").unwrap().models.push(ModelEntry {
        id: "other".into(),
        capabilities: ModelCapabilities {
            image_input: CapabilityStatus::Supported,
            ..ModelCapabilities::default()
        },
        ..ModelEntry::default()
    });
    let other = cfg.resolve_effective_model_capabilities("p", "other", 4);
    assert!(other.supports_image_input());
    assert_eq!(other.image_input.source_generation, 4);
    assert_ne!(
        other.image_input.source_generation,
        gen3.image_input.source_generation
    );

    // Provider removal yields Unknown / none for that identity at the caller's
    // generation (not gen-0), for every input dimension.
    cfg.providers.remove("p");
    let gone = cfg.resolve_effective_model_capabilities("p", "m", 5);
    assert_eq!(gone.image_input.status, CapabilityStatus::Unknown);
    assert_eq!(gone.image_input.source, EffectiveCapabilitySource::None);
    assert_eq!(gone.image_input.source_generation, 5);
    assert_eq!(gone.audio_input.source_generation, 5);
    assert_eq!(gone.video_input.source_generation, 5);
    assert_eq!(gone.config_generation, 5);
}

#[test]
fn multimodal_capability_no_modality_implies_another_or_computer_use() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "p".into(),
        ProviderEntry {
            models: vec![ModelEntry {
                id: "m".into(),
                capabilities: ModelCapabilities {
                    image_input: CapabilityStatus::Supported,
                    audio_input: CapabilityStatus::Unknown,
                    video_input: CapabilityStatus::Unknown,
                    computer_use: ComputerUseCapability::default(),
                    ..ModelCapabilities::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    let caps = cfg.resolve_effective_model_capabilities("p", "m", 1);
    assert!(caps.supports_image_input());
    assert!(!caps.supports_audio_input());
    assert!(!caps.supports_video_input());
    assert!(caps.computer_use.is_none());

    // Video alone does not enable image or audio.
    cfg.providers.get_mut("p").unwrap().models[0]
        .capabilities
        .image_input = CapabilityStatus::Unknown;
    cfg.providers.get_mut("p").unwrap().models[0]
        .capabilities
        .video_input = CapabilityStatus::Supported;
    let caps = cfg.resolve_effective_model_capabilities("p", "m", 2);
    assert!(!caps.supports_image_input());
    assert!(!caps.supports_audio_input());
    assert!(caps.supports_video_input());
    assert!(caps.computer_use.is_none());
}
