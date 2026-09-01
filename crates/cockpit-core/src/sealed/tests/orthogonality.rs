//! AC3 `all_models_are_reference_only_for_sealed_values`
//!
//! Provider-wire rendering is owned by
//! `sealed-value-untrusted-inference-marker`. This proves only the foundation's
//! typed custody predicate: no policy axis, including trust, widens custody.

use crate::config::providers::ModelTrust;
use crate::sealed::custody::ALL_MODEL_TRUSTS;
use crate::sealed::{SealedCustodyRequest, SealedLiteralCustody, sealed_literal_custody};

#[test]
fn all_models_are_reference_only_for_sealed_values() {
    // ---- the predicate resolves every trust class identically -------------
    for trust in ALL_MODEL_TRUSTS {
        let custody = sealed_literal_custody(SealedCustodyRequest::new(trust));
        let expected = SealedLiteralCustody::ReferenceOnly;
        assert_eq!(
            custody, expected,
            "custody for {trust:?} must remain reference-only"
        );
    }

    // ---- a trust-only change never changes literal custody -----------------
    let trusted = sealed_literal_custody(SealedCustodyRequest::new(ModelTrust::Trusted));
    let untrusted = sealed_literal_custody(SealedCustodyRequest::new(ModelTrust::Untrusted));
    assert_eq!(
        trusted, untrusted,
        "trust never widens sealed-value custody"
    );
    assert!(!trusted.permits_raw_literal());
    assert!(untrusted.is_reference_only());

    // ---- the invariant ------------------------------------------------------
    // No caller receives a raw literal.
    assert!(
        !sealed_literal_custody(SealedCustodyRequest::new(ModelTrust::Trusted))
            .permits_raw_literal(),
        "a trusted model must never receive a raw literal"
    );

    // Fail-closed default: an unconfigured model is untrusted.
    assert_eq!(ModelTrust::default(), ModelTrust::Untrusted);
    assert!(
        crate::sealed::sealed_literal_custody_for_trust(ModelTrust::default()).is_reference_only(),
        "the default trust posture is reference-only"
    );

    // ---- structural: the resolver ignores trust ----------------------------
    let source = include_str!("../custody.rs");
    let body_start = source
        .find("pub fn sealed_literal_custody(")
        .expect("custody resolver exists");
    let body = &source[body_start..];
    let body_end = body.find("\n}\n").expect("resolver body terminates");
    let body = &body[..body_end];
    assert!(
        body.contains("let _ = request"),
        "custody must not consult trust"
    );
    // The request carries only `trust` now; there is no steering field to read.
    assert!(
        !body.contains("request.mode"),
        "custody must never read a steering/mode axis"
    );

    // The predicate is a pure function of one Copy field — it has no access
    // to a provider, a session, or a grant, so it cannot be widened by one.
    assert_eq!(
        std::mem::size_of::<SealedCustodyRequest>(),
        std::mem::size_of::<ModelTrust>()
    );
}
