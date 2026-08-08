//! AC3 `trust_and_mode_are_orthogonal_for_sealed_values`
//!
//! Provider-wire rendering is owned by
//! `sealed-value-untrusted-inference-marker`. This proves only the foundation's
//! typed custody predicate.

use crate::config::extended::LlmMode;
use crate::config::providers::ModelTrust;
use crate::sealed::custody::{ALL_LLM_MODES, ALL_MODEL_TRUSTS};
use crate::sealed::{SealedCustodyRequest, SealedLiteralCustody, sealed_literal_custody};

#[test]
fn trust_and_mode_are_orthogonal_for_sealed_values() {
    // ---- the predicate resolves trust independently for every mode --------
    for trust in ALL_MODEL_TRUSTS {
        for mode in ALL_LLM_MODES {
            let custody = sealed_literal_custody(SealedCustodyRequest::new(trust, mode));
            let expected = match trust {
                ModelTrust::Trusted => SealedLiteralCustody::RawLiteralPermitted,
                ModelTrust::Untrusted => SealedLiteralCustody::ReferenceOnly,
            };
            assert_eq!(
                custody, expected,
                "custody for {trust:?} in {mode:?} must follow trust alone"
            );
        }
    }

    // ---- a mode-only change never changes the predicate --------------------
    for trust in ALL_MODEL_TRUSTS {
        let baseline = sealed_literal_custody(SealedCustodyRequest::new(trust, LlmMode::Defensive));
        for mode in ALL_LLM_MODES {
            assert_eq!(
                sealed_literal_custody(SealedCustodyRequest::new(trust, mode)),
                baseline,
                "changing only the mode must not move custody for {trust:?}"
            );
        }
    }

    // ---- a trust-only change always changes the predicate ------------------
    for mode in ALL_LLM_MODES {
        let trusted = sealed_literal_custody(SealedCustodyRequest::new(ModelTrust::Trusted, mode));
        let untrusted =
            sealed_literal_custody(SealedCustodyRequest::new(ModelTrust::Untrusted, mode));
        assert_ne!(
            trusted, untrusted,
            "trust is the axis that decides custody, in every mode"
        );
        assert!(trusted.permits_raw_literal());
        assert!(untrusted.is_reference_only());
    }

    // ---- the one-directional invariant -------------------------------------
    // No mode, in any combination, ever grants an untrusted caller a raw
    // literal. This is the property that must never invert.
    for mode in ALL_LLM_MODES {
        assert!(
            !sealed_literal_custody(SealedCustodyRequest::new(ModelTrust::Untrusted, mode))
                .permits_raw_literal(),
            "an untrusted model must never receive a raw literal, including in {mode:?}"
        );
    }

    // Fail-closed default: an unconfigured model is untrusted.
    assert_eq!(ModelTrust::default(), ModelTrust::Untrusted);
    assert!(
        crate::sealed::sealed_literal_custody_for_trust(ModelTrust::default()).is_reference_only(),
        "the default trust posture is reference-only"
    );

    // ---- structural: the resolver reads trust and only trust ---------------
    let source = include_str!("../custody.rs");
    let body_start = source
        .find("pub fn sealed_literal_custody(")
        .expect("custody resolver exists");
    let body = &source[body_start..];
    let body_end = body.find("\n}\n").expect("resolver body terminates");
    let body = &body[..body_end];
    assert!(
        body.contains("match request.trust"),
        "custody must be decided by a match on trust"
    );
    assert!(
        !body.contains("request.mode"),
        "custody must never read the harness-steering mode"
    );

    // The predicate is a pure function of two Copy fields — it has no access
    // to a provider, a session, or a grant, so it cannot be widened by one.
    assert_eq!(
        std::mem::size_of::<SealedCustodyRequest>(),
        std::mem::size_of::<ModelTrust>() + std::mem::size_of::<LlmMode>()
    );
}
