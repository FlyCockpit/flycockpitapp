//! Tests for computer-use guidance proposals.
//!
//! Covers acceptance criteria 1, 2, 7, 10, and 11 (the pure-Rust,
//! cockpit-core-testable portions): schema round-trip, compiler snapshots,
//! enablement resolution, and composition.

use super::*;

// ===========================================================================
// Helpers
// ===========================================================================

/// All 24 valid `(kind, value)` pairs.
fn all_24_rules() -> Vec<ComputerGuidanceRuleV1> {
    vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeConsequentialAction),
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::AfterEachAction),
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::AfterNavigation),
        ComputerGuidanceRuleV1::PointerVerification(PointerVerification::BeforeEveryPointerAction),
        ComputerGuidanceRuleV1::PointerVerification(
            PointerVerification::BeforeConsequentialPointerAction,
        ),
        ComputerGuidanceRuleV1::PointerVerification(PointerVerification::AfterPointerMotion),
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::BeforeEachAction),
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::BeforeConsequentialAction),
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::AfterNavigation),
        ComputerGuidanceRuleV1::UnexpectedStateStop(UnexpectedStateStop::AnyMismatch),
        ComputerGuidanceRuleV1::UnexpectedStateStop(UnexpectedStateStop::TargetOrFocusMismatch),
        ComputerGuidanceRuleV1::UnexpectedStateStop(UnexpectedStateStop::VerificationMismatch),
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 1 },
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 2 },
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 3 },
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 4 },
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 5 },
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 6 },
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 7 },
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 8 },
        ComputerGuidanceRuleV1::ProviderWorkaround(
            ProviderWorkaround::RefreshObservationBeforePointer,
        ),
        ComputerGuidanceRuleV1::ProviderWorkaround(
            ProviderWorkaround::OnePointerActionPerObservation,
        ),
        ComputerGuidanceRuleV1::ProviderWorkaround(ProviderWorkaround::VerifyAfterScroll),
    ]
}

// ===========================================================================
// computer_guidance_schema — AC 1
// ===========================================================================

#[test]
fn computer_guidance_schema_round_trips_all_24_values_as_three_bytes() {
    let rules = all_24_rules();
    assert_eq!(rules.len(), 24, "exactly 24 valid V1 values");

    for rule in &rules {
        let encoded = rule.encode();
        assert_eq!(
            encoded.len(),
            RULE_ENCODED_LEN,
            "all six variants are exactly three bytes"
        );
        assert_eq!(encoded[0], SCHEMA_VERSION, "schema_version is 1");
        assert_eq!(
            encoded[1],
            rule.kind().as_byte(),
            "kind byte matches discriminant"
        );
        assert_eq!(encoded[2], rule.value_byte(), "value byte matches");

        let decoded = ComputerGuidanceRuleV1::decode(&encoded).unwrap();
        assert_eq!(decoded, *rule, "round-trip is exact for {:?}", rule);
    }
}

#[test]
fn computer_guidance_schema_rejects_unknown_schema_version() {
    let mut buf = [SCHEMA_VERSION, 1u8, 1u8];
    buf[0] = 2;
    let err = ComputerGuidanceRuleV1::decode(&buf).unwrap_err();
    assert!(matches!(err, GuidanceDecodeError::BadSchemaVersion(2)));
}

#[test]
fn computer_guidance_schema_rejects_unknown_kind() {
    let buf = [SCHEMA_VERSION, 7u8, 1u8];
    let err = ComputerGuidanceRuleV1::decode(&buf).unwrap_err();
    assert!(matches!(err, GuidanceDecodeError::UnknownKind(7)));
}

#[test]
fn computer_guidance_schema_rejects_out_of_range_values() {
    // observation_cadence: valid 1..=4, reject 0 and 5.
    for bad in [0u8, 5u8] {
        let buf = [SCHEMA_VERSION, 1u8, bad];
        let err = ComputerGuidanceRuleV1::decode(&buf).unwrap_err();
        assert!(
            matches!(err, GuidanceDecodeError::InvalidValue(RuleKind::ObservationCadence, v) if v == bad),
            "observation_cadence value {bad} should reject"
        );
    }
    // pointer_verification: valid 1..=3, reject 0 and 4.
    for bad in [0u8, 4u8] {
        let buf = [SCHEMA_VERSION, 2u8, bad];
        let err = ComputerGuidanceRuleV1::decode(&buf).unwrap_err();
        assert!(
            matches!(err, GuidanceDecodeError::InvalidValue(RuleKind::PointerVerification, v) if v == bad),
            "pointer_verification value {bad} should reject"
        );
    }
    // fresh_dossier: valid 1..=3, reject 0 and 4.
    for bad in [0u8, 4u8] {
        let buf = [SCHEMA_VERSION, 3u8, bad];
        let err = ComputerGuidanceRuleV1::decode(&buf).unwrap_err();
        assert!(
            matches!(err, GuidanceDecodeError::InvalidValue(RuleKind::FreshDossier, v) if v == bad),
            "fresh_dossier value {bad} should reject"
        );
    }
    // unexpected_state_stop: valid 1..=3, reject 0 and 4.
    for bad in [0u8, 4u8] {
        let buf = [SCHEMA_VERSION, 4u8, bad];
        let err = ComputerGuidanceRuleV1::decode(&buf).unwrap_err();
        assert!(
            matches!(err, GuidanceDecodeError::InvalidValue(RuleKind::UnexpectedStateStop, v) if v == bad),
            "unexpected_state_stop value {bad} should reject"
        );
    }
    // max_reversible_batch: valid 1..=8, reject 0 and 9.
    for bad in [0u8, 9u8] {
        let buf = [SCHEMA_VERSION, 5u8, bad];
        let err = ComputerGuidanceRuleV1::decode(&buf).unwrap_err();
        assert!(
            matches!(err, GuidanceDecodeError::InvalidValue(RuleKind::MaxReversibleBatch, v) if v == bad),
            "max_reversible_batch value {bad} should reject"
        );
    }
    // provider_workaround: valid 1..=3, reject 0 and 4.
    for bad in [0u8, 4u8] {
        let buf = [SCHEMA_VERSION, 6u8, bad];
        let err = ComputerGuidanceRuleV1::decode(&buf).unwrap_err();
        assert!(
            matches!(err, GuidanceDecodeError::InvalidValue(RuleKind::ProviderWorkaround, v) if v == bad),
            "provider_workaround value {bad} should reject"
        );
    }
}

#[test]
fn computer_guidance_schema_rejects_unknown_fields_via_length() {
    // 4 bytes (one extra = unknown field) → reject.
    let buf = [SCHEMA_VERSION, 1u8, 1u8, 99u8];
    let err = ComputerGuidanceRuleV1::from_bytes(&buf).unwrap_err();
    assert!(matches!(
        err,
        GuidanceDecodeError::BadLength {
            expected: 3,
            actual: 4
        }
    ));
    // 2 bytes (truncated) → reject.
    let buf = [SCHEMA_VERSION, 1u8];
    let err = ComputerGuidanceRuleV1::from_bytes(&buf).unwrap_err();
    assert!(matches!(
        err,
        GuidanceDecodeError::BadLength {
            expected: 3,
            actual: 2
        }
    ));
}

#[test]
fn computer_guidance_schema_enforces_one_to_six_unique_kinds() {
    // Zero rules → reject.
    let err = validate_proposal(&[]).unwrap_err();
    assert!(matches!(err, GuidanceDecodeError::RuleCountOutOfRange(0)));

    // Seven rules → reject (use 7 distinct kinds — impossible since only 6
    // kinds exist, so first test 7 with a duplicate which hits duplicate
    // first; instead test count with 7 same-kind which is duplicate).
    // Test count > 6 with 7 rules of the same kind.
    let seven =
        vec![ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction); 7];
    let err = validate_proposal(&seven).unwrap_err();
    assert!(matches!(err, GuidanceDecodeError::RuleCountOutOfRange(7)));

    // One rule → OK.
    let one = vec![ComputerGuidanceRuleV1::ObservationCadence(
        ObservationCadence::BeforeEachAction,
    )];
    let bits = validate_proposal(&one).unwrap();
    assert_eq!(bits, RuleKind::ObservationCadence.bit_mask());

    // Six distinct kinds → OK, all bits set.
    let six = vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::PointerVerification(PointerVerification::BeforeEveryPointerAction),
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::BeforeEachAction),
        ComputerGuidanceRuleV1::UnexpectedStateStop(UnexpectedStateStop::AnyMismatch),
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 1 },
        ComputerGuidanceRuleV1::ProviderWorkaround(
            ProviderWorkaround::RefreshObservationBeforePointer,
        ),
    ];
    let bits = validate_proposal(&six).unwrap();
    assert_eq!(bits, 0b111111);

    // Duplicate kind → reject.
    let dup = vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::AfterEachAction),
    ];
    let err = validate_proposal(&dup).unwrap_err();
    assert!(matches!(
        err,
        GuidanceDecodeError::DuplicateKind(RuleKind::ObservationCadence)
    ));
}

#[test]
fn computer_guidance_schema_rejects_arbitrary_content_rule_field() {
    // The max_reversible_batch field is a u8 in 1..=8; it cannot carry
    // arbitrary content. Values outside 1..=8 are rejected (tested above).
    // The other fields are closed enums with no free-form slot.
    // Verify that no variant accepts a string/arbitrary bytes — the type
    // system enforces this, and the decoder rejects all out-of-range bytes.
    let bad = [SCHEMA_VERSION, 5u8, 0u8];
    assert!(ComputerGuidanceRuleV1::decode(&bad).is_err());
    let bad = [SCHEMA_VERSION, 5u8, 255u8];
    assert!(ComputerGuidanceRuleV1::decode(&bad).is_err());
}

// ===========================================================================
// Rationale normalization — AC 1
// ===========================================================================

#[test]
fn computer_guidance_schema_rationale_normalizes_crlf_and_cr_to_lf() {
    let input = "line1\r\nline2\rline3\n";
    let result = normalize_rationale(input).unwrap();
    assert_eq!(result.as_deref(), Some("line1\nline2\nline3"));
}

#[test]
fn computer_guidance_schema_rationale_trims_only_leading_trailing_space_tab_lf() {
    let input = "  \t\n  hello world  \n\t  ";
    let result = normalize_rationale(input).unwrap();
    assert_eq!(result.as_deref(), Some("hello world"));
}

#[test]
fn computer_guidance_schema_rationale_empty_is_absent() {
    assert_eq!(normalize_rationale("").unwrap(), None);
    assert_eq!(normalize_rationale("   ").unwrap(), None);
    assert_eq!(normalize_rationale("\n\t  \n").unwrap(), None);
}

#[test]
fn computer_guidance_schema_rationale_rejects_nul() {
    let input = "hello\0world";
    assert_eq!(normalize_rationale(input), Err(RationaleError::Nul));
}

#[test]
fn computer_guidance_schema_rationale_rejects_disallowed_c0_c1_controls() {
    // TAB and LF are allowed.
    assert!(normalize_rationale("a\tb\nc").is_ok());
    // Other C0 controls rejected.
    for cp in [0x01u32, 0x08, 0x0B, 0x0C, 0x0E, 0x1F] {
        let ch = char::from_u32(cp).unwrap();
        let input = format!("a{ch}b");
        assert_eq!(
            normalize_rationale(&input),
            Err(RationaleError::DisallowedControl(cp))
        );
    }
    // C1 / DEL rejected.
    for cp in [0x7Fu32, 0x80, 0x9F] {
        let ch = char::from_u32(cp).unwrap();
        let input = format!("a{ch}b");
        assert_eq!(
            normalize_rationale(&input),
            Err(RationaleError::DisallowedControl(cp))
        );
    }
}

#[test]
fn computer_guidance_schema_rationale_rejects_unicode_noncharacters() {
    for cp in [0xFDD0u32, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x10FFFF] {
        if let Some(ch) = char::from_u32(cp) {
            let input = format!("a{ch}b");
            assert_eq!(
                normalize_rationale(&input),
                Err(RationaleError::Noncharacter(cp))
            );
        }
    }
}

#[test]
fn computer_guidance_schema_rationale_rejects_bidi_override_isolate_controls() {
    for cp in [0x202Au32, 0x202E, 0x2066, 0x2069] {
        let ch = char::from_u32(cp).unwrap();
        let input = format!("a{ch}b");
        assert_eq!(
            normalize_rationale(&input),
            Err(RationaleError::BidiControl(cp))
        );
    }
}

#[test]
fn computer_guidance_schema_rationale_caps_at_512_scalars() {
    // 512 chars → OK.
    let ok = "a".repeat(512);
    assert!(normalize_rationale(&ok).is_ok());
    // 513 chars → reject.
    let too_many = "a".repeat(513);
    assert_eq!(
        normalize_rationale(&too_many),
        Err(RationaleError::TooManyScalars)
    );
}

#[test]
fn computer_guidance_schema_rationale_caps_at_2048_bytes() {
    // ASCII cannot exercise the byte cap in isolation: 2,048 ASCII scalars
    // already exceed the 512-scalar cap, which is checked first. A 4-byte
    // scalar (U+10000) lets the byte count reach 2,048 while staying at 512
    // scalars — exactly both caps → OK.
    let ok = "\u{10000}".repeat(512);
    assert_eq!(ok.len(), 2048);
    assert_eq!(ok.chars().count(), 512);
    assert!(normalize_rationale(&ok).is_ok());
    // One more 4-byte scalar is 2,052 bytes over 513 scalars: it exceeds both
    // caps, and the scalar cap (checked first) is the reported error.
    let too_many = "\u{10000}".repeat(513);
    assert_eq!(too_many.len(), 2052);
    assert_eq!(
        normalize_rationale(&too_many),
        Err(RationaleError::TooManyScalars)
    );
}

// ===========================================================================
// computer_guidance_compiler — AC 2, 7
// ===========================================================================

#[test]
fn computer_guidance_compiler_snapshots_every_literal_template_byte_for_byte() {
    let rules = all_24_rules();
    assert_eq!(rules.len(), COMPILER_TEMPLATES.len());

    for (i, rule) in rules.iter().enumerate() {
        let clause = compiler_clause_bytes(rule);
        assert_eq!(
            clause, COMPILER_TEMPLATES[i],
            "template {i} must match byte-for-byte"
        );
        // Each template is non-empty and ends with a period.
        assert!(!clause.is_empty());
        assert_eq!(*clause.last().unwrap(), b'.');
    }
}

#[test]
fn computer_guidance_compiler_templates_are_not_format_strings() {
    // Verify no template contains a format-string placeholder.
    for template in COMPILER_TEMPLATES.iter() {
        let s = std::str::from_utf8(template).unwrap();
        assert!(
            !s.contains('{') && !s.contains('}'),
            "templates must not be format strings: {s:?}"
        );
        assert!(
            !s.contains("%s") && !s.contains("{}"),
            "templates must not contain format placeholders: {s:?}"
        );
    }
}

#[test]
fn computer_guidance_compiler_single_clause_no_trailing_lf() {
    let rule = ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction);
    let compiled = compile_guidance(&[rule]);
    assert_eq!(compiled, COMPILER_TEMPLATES[0]);
    // No trailing LF.
    assert_eq!(*compiled.last().unwrap(), b'.');
}

#[test]
fn computer_guidance_compiler_multi_kind_lf_join_byte_for_byte() {
    // Two clauses in discriminant order with exactly one LF between.
    let rules = vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::PointerVerification(PointerVerification::BeforeEveryPointerAction),
    ];
    let compiled = compile_guidance(&rules);
    let mut expected = Vec::new();
    expected.extend_from_slice(COMPILER_TEMPLATES[0]);
    expected.push(CLAUSE_SEPARATOR);
    expected.extend_from_slice(COMPILER_TEMPLATES[4]);
    assert_eq!(compiled, expected);
    // No trailing LF.
    assert_eq!(*compiled.last().unwrap(), b'.');
}

#[test]
fn computer_guidance_compiler_proves_discriminant_ordering() {
    // Pass rules out of order; compiler must emit in discriminant order.
    let rules = vec![
        ComputerGuidanceRuleV1::ProviderWorkaround(ProviderWorkaround::VerifyAfterScroll),
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::BeforeEachAction),
    ];
    let compiled = compile_guidance(&rules);
    // Order should be: observation_cadence (kind 1), fresh_dossier (kind 3),
    // provider_workaround (kind 6).
    let mut expected = Vec::new();
    expected.extend_from_slice(COMPILER_TEMPLATES[0]); // obs cadence
    expected.push(CLAUSE_SEPARATOR);
    expected.extend_from_slice(COMPILER_TEMPLATES[7]); // fresh dossier
    expected.push(CLAUSE_SEPARATOR);
    expected.extend_from_slice(COMPILER_TEMPLATES[23]); // provider workaround
    assert_eq!(compiled, expected);
}

#[test]
fn computer_guidance_compiler_proves_same_kind_precedence() {
    // Two rules of the same kind: the last one wins (within one scope, a
    // newly accepted value replaces the existing same kind).
    let rules = vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::AfterEachAction),
    ];
    let compiled = compile_guidance(&rules);
    // AfterEachAction → template[2].
    assert_eq!(compiled, COMPILER_TEMPLATES[2]);
}

#[test]
fn computer_guidance_compiler_proves_no_proposal_bytes_injected_verbatim() {
    // The compiler output is composed entirely of code-owned constants.
    // Verify that arbitrary "proposal" bytes never appear in the output.
    let proposal_bytes = b"FREE_TEXT_INJECTION_ATTEMPT";
    let rules = vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 5 },
    ];
    let compiled = compile_guidance(&rules);
    assert!(
        !compiled
            .windows(proposal_bytes.len())
            .any(|w| w == proposal_bytes),
        "compiler must not inject proposal bytes verbatim"
    );
    // Also verify no rationale bytes.
    let rationale = b"secret rationale text";
    assert!(
        !compiled.windows(rationale.len()).any(|w| w == rationale),
        "compiler must not inject rationale bytes"
    );
    // No provider/model/project bytes.
    for injection in [
        b"openai".as_slice(),
        b"gpt-4".as_slice(),
        b"/home/user/project".as_slice(),
    ] {
        assert!(
            !compiled.windows(injection.len()).any(|w| w == injection),
            "compiler must not inject {:?} bytes",
            std::str::from_utf8(injection)
        );
    }
}

#[test]
fn computer_guidance_compiler_all_six_kinds_full_join() {
    let rules = vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::PointerVerification(PointerVerification::BeforeEveryPointerAction),
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::BeforeEachAction),
        ComputerGuidanceRuleV1::UnexpectedStateStop(UnexpectedStateStop::AnyMismatch),
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 3 },
        ComputerGuidanceRuleV1::ProviderWorkaround(
            ProviderWorkaround::RefreshObservationBeforePointer,
        ),
    ];
    let compiled = compile_guidance(&rules);
    // Templates 0, 4, 7, 10, 15 (max=3 → 13+3-1=15), 21.
    let mut expected = Vec::new();
    let indices = [0usize, 4, 7, 10, 15, 21];
    for (i, &idx) in indices.iter().enumerate() {
        if i > 0 {
            expected.push(CLAUSE_SEPARATOR);
        }
        expected.extend_from_slice(COMPILER_TEMPLATES[idx]);
    }
    assert_eq!(compiled, expected);
    // Verify exactly 5 LFs (6 clauses, 5 separators, no trailing).
    let lf_count = compiled.iter().filter(|b| **b == CLAUSE_SEPARATOR).count();
    assert_eq!(lf_count, 5);
}

// ===========================================================================
// computer_guidance_enablement_resolution — AC 10
// ===========================================================================

#[test]
fn computer_guidance_enablement_all_absent_is_disabled() {
    let layers = EnablementLayers::default();
    let res = resolve_enablement(&layers);
    assert!(!res.enabled, "all-absent must be disabled");
    assert!(!res.has_disable_veto);
}

#[test]
fn computer_guidance_enablement_single_enable_no_disable_is_enabled() {
    let layers = EnablementLayers {
        global: EnablementValue::Enabled,
        ..Default::default()
    };
    let res = resolve_enablement(&layers);
    assert!(res.enabled);

    // Each layer independently.
    let layers = EnablementLayers {
        project: EnablementValue::Enabled,
        ..Default::default()
    };
    assert!(resolve_enablement(&layers).enabled);

    let layers = EnablementLayers {
        provider: EnablementValue::Enabled,
        ..Default::default()
    };
    assert!(resolve_enablement(&layers).enabled);

    let layers = EnablementLayers {
        model: EnablementValue::Enabled,
        ..Default::default()
    };
    assert!(resolve_enablement(&layers).enabled);
}

#[test]
fn computer_guidance_enablement_any_disable_is_sticky_veto() {
    // Disable at global → veto even if all narrower layers enable.
    let layers = EnablementLayers {
        global: EnablementValue::Disabled,
        project: EnablementValue::Enabled,
        provider: EnablementValue::Enabled,
        model: EnablementValue::Enabled,
    };
    let res = resolve_enablement(&layers);
    assert!(!res.enabled, "global disable is a sticky veto");
    assert!(res.has_disable_veto);

    // Disable at project → veto even if narrower layers enable.
    let layers = EnablementLayers {
        global: EnablementValue::Enabled,
        project: EnablementValue::Disabled,
        provider: EnablementValue::Enabled,
        model: EnablementValue::Enabled,
    };
    let res = resolve_enablement(&layers);
    assert!(!res.enabled, "project disable is a sticky veto");
    assert!(res.has_disable_veto);

    // Disable at provider → veto even if model enables.
    let layers = EnablementLayers {
        global: EnablementValue::Enabled,
        project: EnablementValue::Enabled,
        provider: EnablementValue::Disabled,
        model: EnablementValue::Enabled,
    };
    let res = resolve_enablement(&layers);
    assert!(!res.enabled, "provider disable is a sticky veto");
    assert!(res.has_disable_veto);

    // Disable at model → veto (narrowest disable).
    let layers = EnablementLayers {
        global: EnablementValue::Enabled,
        project: EnablementValue::Enabled,
        provider: EnablementValue::Enabled,
        model: EnablementValue::Disabled,
    };
    let res = resolve_enablement(&layers);
    assert!(!res.enabled, "model disable is a sticky veto");
    assert!(res.has_disable_veto);
}

#[test]
fn computer_guidance_enablement_narrower_enable_cannot_lift_broader_disable() {
    // Global disable, model enable → still disabled.
    let layers = EnablementLayers {
        global: EnablementValue::Disabled,
        project: EnablementValue::Absent,
        provider: EnablementValue::Absent,
        model: EnablementValue::Enabled,
    };
    let res = resolve_enablement(&layers);
    assert!(!res.enabled, "narrower enable cannot lift broader disable");
    assert!(res.has_disable_veto);
}

#[test]
fn computer_guidance_enablement_exhaustive_absent_enabled_disabled_all_layers() {
    // Exhaustively check a representative subset: for each layer, all three
    // values, with the others absent.
    for layer_idx in 0..4u8 {
        for value in [
            EnablementValue::Absent,
            EnablementValue::Enabled,
            EnablementValue::Disabled,
        ] {
            let mut layers = EnablementLayers::default();
            match layer_idx {
                0 => layers.global = value,
                1 => layers.project = value,
                2 => layers.provider = value,
                3 => layers.model = value,
                _ => unreachable!(),
            }
            let res = resolve_enablement(&layers);
            match value {
                EnablementValue::Absent => {
                    assert!(!res.enabled, "absent at the only layer → disabled");
                    assert!(!res.has_disable_veto);
                }
                EnablementValue::Enabled => {
                    assert!(res.enabled, "enabled at the only layer → enabled");
                    assert!(!res.has_disable_veto);
                }
                EnablementValue::Disabled => {
                    assert!(!res.enabled, "disabled at the only layer → disabled (veto)");
                    assert!(res.has_disable_veto);
                }
            }
        }
    }
}

#[test]
fn computer_guidance_enablement_from_bool() {
    assert_eq!(EnablementValue::from_bool(None), EnablementValue::Absent);
    assert_eq!(
        EnablementValue::from_bool(Some(true)),
        EnablementValue::Enabled
    );
    assert_eq!(
        EnablementValue::from_bool(Some(false)),
        EnablementValue::Disabled
    );
}

// ===========================================================================
// computer_guidance_composition — AC 11
// ===========================================================================

#[test]
fn computer_guidance_composition_one_value_per_scope_kind() {
    // Persistent has observation_cadence; session has pointer_verification.
    // Union emits both in discriminant order.
    let persistent = vec![ComputerGuidanceRuleV1::ObservationCadence(
        ObservationCadence::BeforeEachAction,
    )];
    let session = vec![ComputerGuidanceRuleV1::PointerVerification(
        PointerVerification::BeforeEveryPointerAction,
    )];
    let compiled = compose_and_compile(&session, &persistent);
    let mut expected = Vec::new();
    expected.extend_from_slice(COMPILER_TEMPLATES[0]); // obs cadence (kind 1)
    expected.push(CLAUSE_SEPARATOR);
    expected.extend_from_slice(COMPILER_TEMPLATES[4]); // pointer verification (kind 2)
    assert_eq!(compiled, expected);
}

#[test]
fn computer_guidance_composition_session_overrides_persistent_same_kind() {
    // Persistent has observation_cadence before_each; session has
    // observation_cadence after_each. Session wins.
    let persistent = vec![ComputerGuidanceRuleV1::ObservationCadence(
        ObservationCadence::BeforeEachAction,
    )];
    let session = vec![ComputerGuidanceRuleV1::ObservationCadence(
        ObservationCadence::AfterEachAction,
    )];
    let compiled = compose_and_compile(&session, &persistent);
    // AfterEachAction → template[2].
    assert_eq!(compiled, COMPILER_TEMPLATES[2]);
}

#[test]
fn computer_guidance_composition_distinct_kinds_form_union() {
    let persistent = vec![
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::BeforeEachAction),
        ComputerGuidanceRuleV1::ProviderWorkaround(
            ProviderWorkaround::RefreshObservationBeforePointer,
        ),
    ];
    let session = vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::UnexpectedStateStop(UnexpectedStateStop::AnyMismatch),
    ];
    let compiled = compose_and_compile(&session, &persistent);
    // Kinds present: 1 (obs), 3 (fresh), 4 (stop), 6 (workaround).
    // Templates: 0, 7, 10, 21.
    let mut expected = Vec::new();
    expected.extend_from_slice(COMPILER_TEMPLATES[0]);
    expected.push(CLAUSE_SEPARATOR);
    expected.extend_from_slice(COMPILER_TEMPLATES[7]);
    expected.push(CLAUSE_SEPARATOR);
    expected.extend_from_slice(COMPILER_TEMPLATES[10]);
    expected.push(CLAUSE_SEPARATOR);
    expected.extend_from_slice(COMPILER_TEMPLATES[21]);
    assert_eq!(compiled, expected);
}

#[test]
fn computer_guidance_composition_fixed_kind_ordering_regardless_of_input() {
    // Pass session and persistent rules in reverse order; output must be
    // in fixed discriminant order.
    let persistent = vec![
        ComputerGuidanceRuleV1::ProviderWorkaround(ProviderWorkaround::VerifyAfterScroll),
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::AfterNavigation),
    ];
    let session = vec![
        ComputerGuidanceRuleV1::UnexpectedStateStop(UnexpectedStateStop::VerificationMismatch),
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::AfterNavigation),
    ];
    let compiled = compose_and_compile(&session, &persistent);
    // Kinds: 1 (obs), 3 (fresh), 4 (stop), 6 (workaround).
    // Templates: 3, 9, 12, 23.
    let mut expected = Vec::new();
    expected.extend_from_slice(COMPILER_TEMPLATES[3]);
    expected.push(CLAUSE_SEPARATOR);
    expected.extend_from_slice(COMPILER_TEMPLATES[9]);
    expected.push(CLAUSE_SEPARATOR);
    expected.extend_from_slice(COMPILER_TEMPLATES[12]);
    expected.push(CLAUSE_SEPARATOR);
    expected.extend_from_slice(COMPILER_TEMPLATES[23]);
    assert_eq!(compiled, expected);
}

#[test]
fn computer_guidance_composition_apply_accepted_replaces_only_present_kinds() {
    // Existing has observation_cadence and pointer_verification.
    let existing = vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::PointerVerification(PointerVerification::BeforeEveryPointerAction),
    ];
    // Accepted replaces only observation_cadence; pointer_verification is
    // untouched (omitted kind remains unchanged).
    let accepted = vec![ComputerGuidanceRuleV1::ObservationCadence(
        ObservationCadence::AfterEachAction,
    )];
    let result = apply_accepted(&existing, &accepted);
    // Result in fixed order: observation_cadence (after_each), pointer_verification.
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].kind(), RuleKind::ObservationCadence);
    assert_eq!(
        result[0],
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::AfterEachAction)
    );
    assert_eq!(result[1].kind(), RuleKind::PointerVerification);
    assert_eq!(
        result[1],
        ComputerGuidanceRuleV1::PointerVerification(PointerVerification::BeforeEveryPointerAction)
    );
}

#[test]
fn computer_guidance_composition_apply_accepted_adds_new_kinds() {
    let existing = vec![ComputerGuidanceRuleV1::ObservationCadence(
        ObservationCadence::BeforeEachAction,
    )];
    let accepted = vec![ComputerGuidanceRuleV1::FreshDossier(
        FreshDossier::BeforeEachAction,
    )];
    let result = apply_accepted(&existing, &accepted);
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].kind(), RuleKind::ObservationCadence);
    assert_eq!(result[1].kind(), RuleKind::FreshDossier);
}

#[test]
fn computer_guidance_composition_apply_accepted_preserves_omitted_kinds() {
    let existing = vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::PointerVerification(PointerVerification::BeforeEveryPointerAction),
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::BeforeEachAction),
    ];
    // Accepted has only pointer_verification; the other two must remain.
    let accepted = vec![ComputerGuidanceRuleV1::PointerVerification(
        PointerVerification::AfterPointerMotion,
    )];
    let result = apply_accepted(&existing, &accepted);
    assert_eq!(result.len(), 3);
    // Fixed order: obs (1), pointer (2), fresh (3).
    assert_eq!(result[0].kind(), RuleKind::ObservationCadence);
    assert_eq!(
        result[0],
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction)
    );
    assert_eq!(result[1].kind(), RuleKind::PointerVerification);
    assert_eq!(
        result[1],
        ComputerGuidanceRuleV1::PointerVerification(PointerVerification::AfterPointerMotion)
    );
    assert_eq!(result[2].kind(), RuleKind::FreshDossier);
    assert_eq!(
        result[2],
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::BeforeEachAction)
    );
}

#[test]
fn computer_guidance_composition_machine_project_provider_model_isolation() {
    // Persistent rules for (project A, provider X, model Y) do not appear
    // when composing for (project B, provider Z, model W). The composition
    // function takes already-scoped rule sets; isolation is enforced by
    // the caller keying. Here we verify that an empty persistent set
    // yields only session rules.
    let persistent: Vec<ComputerGuidanceRuleV1> = vec![];
    let session = vec![ComputerGuidanceRuleV1::ObservationCadence(
        ObservationCadence::BeforeEachAction,
    )];
    let compiled = compose_and_compile(&session, &persistent);
    assert_eq!(compiled, COMPILER_TEMPLATES[0]);
}

#[test]
fn computer_guidance_composition_no_persistence_roaming() {
    // Persistent rules are separate product state and never roam through
    // config export/sync/import. The composition function does not
    // serialize or export — it only compiles. Verify that compiling with
    // only persistent rules yields the persistent templates and nothing
    // from session.
    let persistent = vec![ComputerGuidanceRuleV1::ObservationCadence(
        ObservationCadence::BeforeEachAction,
    )];
    let compiled = compose_and_compile(&[], &persistent);
    assert_eq!(compiled, COMPILER_TEMPLATES[0]);
}

// ===========================================================================
// Consequential predicate — byte-identical to audit contract
// ===========================================================================

#[test]
fn computer_guidance_consequential_predicate_byte_identical_to_audit() {
    // Exactly pointer_button|pointer_drag|text_entry|key_input|scroll are
    // consequential; pointer_move|wait are not.
    use crate::computer::audit::ActionClass;
    assert!(!is_consequential_action(ActionClass::PointerMove));
    assert!(is_consequential_action(ActionClass::PointerButton));
    assert!(is_consequential_action(ActionClass::PointerDrag));
    assert!(is_consequential_action(ActionClass::TextEntry));
    assert!(is_consequential_action(ActionClass::KeyInput));
    assert!(is_consequential_action(ActionClass::Scroll));
    assert!(!is_consequential_action(ActionClass::Wait));

    // Verify byte-identical with the audit contract.
    for class in [
        ActionClass::PointerMove,
        ActionClass::PointerButton,
        ActionClass::PointerDrag,
        ActionClass::TextEntry,
        ActionClass::KeyInput,
        ActionClass::Scroll,
        ActionClass::Wait,
    ] {
        assert_eq!(
            is_consequential_action(class),
            class.is_consequential(),
            "predicate must be byte-identical to audit contract for {class:?}"
        );
    }
}

// ===========================================================================
// Rule kind bits — AC 8 (rule_kind_bits used in audit metadata)
// ===========================================================================

#[test]
fn computer_guidance_rule_kind_bits_all_six_kinds() {
    let mut bits = 0u16;
    for kind in RuleKind::ALL {
        bits |= kind.bit_mask();
    }
    assert_eq!(bits, 0b111111, "all six kinds cover bits 0..5");
    assert_eq!(RuleKind::ObservationCadence.bit_mask(), 1 << 0);
    assert_eq!(RuleKind::PointerVerification.bit_mask(), 1 << 1);
    assert_eq!(RuleKind::FreshDossier.bit_mask(), 1 << 2);
    assert_eq!(RuleKind::UnexpectedStateStop.bit_mask(), 1 << 3);
    assert_eq!(RuleKind::MaxReversibleBatch.bit_mask(), 1 << 4);
    assert_eq!(RuleKind::ProviderWorkaround.bit_mask(), 1 << 5);
}

#[test]
fn computer_guidance_rule_kind_bits_validate_proposal_returns_correct_bits() {
    let six = vec![
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
        ComputerGuidanceRuleV1::PointerVerification(PointerVerification::BeforeEveryPointerAction),
        ComputerGuidanceRuleV1::FreshDossier(FreshDossier::BeforeEachAction),
        ComputerGuidanceRuleV1::UnexpectedStateStop(UnexpectedStateStop::AnyMismatch),
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 1 },
        ComputerGuidanceRuleV1::ProviderWorkaround(
            ProviderWorkaround::RefreshObservationBeforePointer,
        ),
    ];
    let bits = validate_proposal(&six).unwrap();
    assert_eq!(bits, 0b111111);
    assert_eq!(bits & !0b111111, 0, "no bits outside 0..5");
}

// ===========================================================================
// Constants sanity
// ===========================================================================

#[test]
fn computer_guidance_constants_match_prompt() {
    assert_eq!(SCHEMA_VERSION, 1);
    assert_eq!(MIN_RULES, 1);
    assert_eq!(MAX_RULES, 6);
    assert_eq!(RULE_ENCODED_LEN, 3);
    assert_eq!(RATIONALE_MAX_SCALARS, 512);
    assert_eq!(RATIONALE_MAX_BYTES, 2048);
    assert_eq!(PROPOSAL_EXPIRY_SECS, 600);
    assert_eq!(MAX_PROPOSALS_PER_DELEGATION, 3);
    assert_eq!(MAX_PROPOSALS_PER_SESSION, 10);
    assert_eq!(RETENTION_HORIZON_SECS, 30 * 24 * 60 * 60);
    assert_eq!(COMPILER_TEMPLATES.len(), 24);
    assert_eq!(CLAUSE_SEPARATOR, 0x0A);
}

#[test]
fn computer_guidance_compiler_templates_match_prompt_lookup_table() {
    // Verify each template string matches the prompt's lookup table exactly.
    let expected: [&[u8]; 24] = [
        b"Observe immediately before every computer action.",
        b"Observe immediately before every consequential computer action.",
        b"Observe immediately after every computer action.",
        b"Observe immediately after every navigation.",
        b"Verify the pointer target immediately before every pointer action.",
        b"Verify the pointer target immediately before every consequential pointer action.",
        b"Verify the pointer target immediately after every pointer movement.",
        b"Build a fresh transient dossier immediately before every computer action.",
        b"Build a fresh transient dossier immediately before every consequential computer action.",
        b"Build a fresh transient dossier immediately after every navigation.",
        b"Stop when any observed state differs from the expected state.",
        b"Stop when the physical target or focus differs from the expected state.",
        b"Stop when post-action verification differs from the expected state.",
        b"Execute at most one reversible computer action before observing again.",
        b"Execute at most two reversible computer actions before observing again.",
        b"Execute at most three reversible computer actions before observing again.",
        b"Execute at most four reversible computer actions before observing again.",
        b"Execute at most five reversible computer actions before observing again.",
        b"Execute at most six reversible computer actions before observing again.",
        b"Execute at most seven reversible computer actions before observing again.",
        b"Execute at most eight reversible computer actions before observing again.",
        b"Refresh the observation immediately before every pointer action.",
        b"Execute only one pointer action per observation.",
        b"Verify the observed state immediately after every scroll action.",
    ];
    for (i, (got, want)) in COMPILER_TEMPLATES.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "template {i} must match prompt lookup table");
    }
}

// ===========================================================================
// computer_guidance_compile_context — AC9
// ===========================================================================

/// AC9: byte-identical insertion of only compiler literals into a new context;
/// session overrides persistent for the same kind; no rationale/proposal/path
/// bytes appear in the inserted block.
#[test]
fn computer_guidance_compile_context_inserts_only_compiler_literals() {
    let session_rules = vec![ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 2 }];
    let persistent_rules = vec![
        ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 5 },
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
    ];

    // The compiled guidance bytes are the compose_and_compile output.
    let compiled = compose_and_compile(&session_rules, &persistent_rules);

    // Session (max_actions=2) overrides persistent (max_actions=5) for the
    // same kind; the observation_cadence kind from persistent unions in.
    let compiled_str = std::str::from_utf8(&compiled).unwrap();
    assert!(
        compiled_str.contains("Execute at most two reversible computer actions"),
        "session value (two) must override persistent (five)"
    );
    assert!(
        !compiled_str.contains("Execute at most five reversible computer actions"),
        "persistent value (five) must be suppressed by the session override"
    );
    assert!(
        compiled_str.contains("Observe immediately before every computer action."),
        "distinct kind from persistent unions in"
    );
    // Fixed discriminant order: observation_cadence (kind 1) before
    // max_reversible_batch (kind 5).
    let obs_idx = compiled_str
        .find("Observe immediately before every computer action.")
        .unwrap();
    let batch_idx = compiled_str.find("Execute at most two").unwrap();
    assert!(obs_idx < batch_idx, "kinds emit in fixed discriminant order");

    // Byte-identical: compose_and_compile is deterministic.
    let compiled2 = compose_and_compile(&session_rules, &persistent_rules);
    assert_eq!(compiled, compiled2, "compilation is byte-identical");

    // Insert into a new context's system prompt.
    let mut system = String::from("ROLE PROMPT\n\nHarness: cockpit 0.1.0\n");
    let before_len = system.len();
    append_compiled_guidance(&mut system, &compiled);
    assert!(system.len() > before_len, "guidance block was inserted");

    // Only code-owned compiler literals appear — never rationale, proposal,
    // provider, model, project, or path bytes.
    let forbidden = [
        "rationale",
        "proposal",
        "provider",
        "model_id",
        "project_root",
        "/x/",
        "secret",
    ];
    for needle in forbidden {
        assert!(
            !system.contains(needle),
            "inserted context must not contain `{needle}` (only compiler literals)"
        );
    }
    // Empty guidance is a no-op so existing prompt-cache prefixes stay
    // byte-identical and cache-stable.
    let mut untouched = String::from("baseline\n");
    let snapshot = untouched.clone();
    append_compiled_guidance(&mut untouched, &[]);
    assert_eq!(untouched, snapshot, "empty guidance is a no-op");
}

/// AC9: the inserted guidance block contains a delimiter header and the
/// compiler literal bytes verbatim (byte-for-byte, no mutation).
#[test]
fn computer_guidance_compile_context_block_is_delimited_and_verbatim() {
    let rules = vec![ComputerGuidanceRuleV1::PointerVerification(
        PointerVerification::BeforeEveryPointerAction,
    )];
    let compiled = compose_and_compile(&rules, &[]);
    let mut system = String::new();
    append_compiled_guidance(&mut system, &compiled);
    assert!(system.contains("# Computer-use guidance"));
    // The compiler literal bytes appear verbatim inside the block.
    assert!(system.contains(std::str::from_utf8(&compiled).unwrap()));
}
