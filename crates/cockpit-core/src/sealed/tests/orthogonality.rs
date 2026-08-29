//! AC3 `trust_alone_decides_sealed_value_custody`
//!
//! Provider-wire rendering is owned by
//! `sealed-value-untrusted-inference-marker`. This proves only the foundation's
//! typed custody predicate: trust is the sole axis, and steering posture never
//! widens custody (issue #75 removed the mode axis from the request).

use crate::config::providers::ModelTrust;
use crate::sealed::custody::ALL_MODEL_TRUSTS;
use crate::sealed::{SealedCustodyRequest, SealedLiteralCustody, sealed_literal_custody};

#[test]
fn trust_alone_decides_sealed_value_custody() {
    // ---- the predicate resolves trust independently -----------------------
    for trust in ALL_MODEL_TRUSTS {
        let custody = sealed_literal_custody(SealedCustodyRequest::new(trust));
        let expected = match trust {
            ModelTrust::Trusted => SealedLiteralCustody::RawLiteralPermitted,
            ModelTrust::Untrusted => SealedLiteralCustody::ReferenceOnly,
        };
        assert_eq!(
            custody, expected,
            "custody for {trust:?} must follow trust alone"
        );
    }

    // ---- a trust-only change always changes the predicate ------------------
    let trusted = sealed_literal_custody(SealedCustodyRequest::new(ModelTrust::Trusted));
    let untrusted = sealed_literal_custody(SealedCustodyRequest::new(ModelTrust::Untrusted));
    assert_ne!(trusted, untrusted, "trust is the axis that decides custody");
    assert!(trusted.permits_raw_literal());
    assert!(untrusted.is_reference_only());

    // ---- the one-directional invariant -------------------------------------
    // An untrusted caller never receives a raw literal.
    assert!(
        !sealed_literal_custody(SealedCustodyRequest::new(ModelTrust::Untrusted))
            .permits_raw_literal(),
        "an untrusted model must never receive a raw literal"
    );

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
