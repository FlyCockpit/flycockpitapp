//! Shared OpenRouter attribution header contract.
//!
//! The canonical `HTTP-Referer` / `X-OpenRouter-Title` attribution pair is
//! defined exactly once here. Both the chat/catalog path (`models_fetch`) and
//! the image-generation OpenRouter adapter consume this module so rotating
//! the referer URL or title cannot desync across surfaces.
//!
//! Merge semantics (matching `openrouter-attribution-headers`):
//! - A **missing** canonical header gets the canonical default.
//! - A **non-empty** configured value is preserved (override).
//! - An **empty** configured value suppresses that header (it is removed and
//!   not re-added) — attribution is opt-out per header, not mandatory.
//!
//! Identity is decided by the caller: only a provider whose resolved origin is
//! `ResolvedProviderOrigin::Template("openrouter")` calls
//! [`merge_openrouter_attribution`]. This module never inspects provenance; it
//! is a pure header-merge utility.

/// Canonical OpenRouter attribution referer URL.
pub const DEFAULT_REFERER: &str = "https://flycockpit.dev";
/// Canonical OpenRouter attribution title.
pub const DEFAULT_TITLE: &str = "FlyCockpit";
/// Canonical attribution header name for the referer URL.
pub const REFERER_HEADER: &str = "HTTP-Referer";
/// Canonical attribution header name for the application title.
pub const TITLE_HEADER: &str = "X-OpenRouter-Title";

/// The canonical OpenRouter attribution header pair as `(name, default)`.
///
/// Defined once here so no other module needs to hardcode the defaults.
pub fn attribution_defaults() -> [(&'static str, &'static str); 2] {
    [
        (REFERER_HEADER, DEFAULT_REFERER),
        (TITLE_HEADER, DEFAULT_TITLE),
    ]
}

/// Merge the canonical OpenRouter attribution headers into a generic
/// `(String, String)` header set, collision-safe:
/// - A **missing** canonical header is pushed with the canonical default.
/// - A **non-empty** configured value is preserved (override wins).
/// - An **empty** configured value **suppresses** that header: it is removed
///   and not re-added, so an explicit empty `HTTP-Referer` omits the referer
///   entirely (attribution is opt-out per header).
///
/// This is the **single** shared implementation. Chat/catalog (`models_fetch`)
/// and the image-generation OpenRouter adapter both call it (directly or via
/// [`merge_openrouter_attribution`]); neither defines its own attribution
/// constants or merge logic. [`merge_openrouter_attribution`] delegates here
/// so there is exactly one merge implementation to maintain.
pub fn merge_openrouter_attribution_pairs(headers: &mut Vec<(String, String)>) {
    for (name, default) in attribution_defaults() {
        match headers
            .iter()
            .position(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            Some(index) if headers[index].1.is_empty() => {
                headers.remove(index);
            }
            Some(_) => {}
            None => headers.push((name.to_string(), default.to_string())),
        }
    }
}

/// Merge the canonical OpenRouter attribution headers into a resolved header
/// set with the same collision-safe semantics as
/// [`merge_openrouter_attribution_pairs`]. Used by surfaces (e.g.
/// `models_fetch`) that carry headers as `Vec<ResolvedHeader>` rather than
/// `Vec<(String, String)>`.
///
/// This is a thin adapter over the single implementation
/// [`merge_openrouter_attribution_pairs`]: it projects `ResolvedHeader` into
/// `(String, String)` pairs, delegates, and projects back. There is exactly
/// one merge implementation; a fix to the merge semantics in
/// [`merge_openrouter_attribution_pairs`] propagates to both surfaces.
pub fn merge_openrouter_attribution(
    headers: &mut Vec<crate::providers::models_fetch::ResolvedHeader>,
) {
    let mut pairs: Vec<(String, String)> = headers
        .iter()
        .map(|header| (header.name.clone(), header.value.clone()))
        .collect();
    merge_openrouter_attribution_pairs(&mut pairs);
    headers.clear();
    for (name, value) in pairs {
        headers.push(crate::providers::models_fetch::ResolvedHeader { name, value });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::models_fetch::ResolvedHeader;

    fn header(name: &str, value: &str) -> ResolvedHeader {
        ResolvedHeader {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn openrouter_attribution_single_source() {
        // The shared module is the single source of the canonical pair.
        let defaults = attribution_defaults();
        assert_eq!(defaults.len(), 2);
        assert_eq!(defaults[0].0, REFERER_HEADER);
        assert_eq!(defaults[0].1, DEFAULT_REFERER);
        assert_eq!(defaults[1].0, TITLE_HEADER);
        assert_eq!(defaults[1].1, DEFAULT_TITLE);
        assert_eq!(DEFAULT_REFERER, "https://flycockpit.dev");
        assert_eq!(DEFAULT_TITLE, "FlyCockpit");
    }

    #[test]
    fn merge_adds_defaults_when_missing() {
        let mut headers: Vec<ResolvedHeader> = Vec::new();
        merge_openrouter_attribution(&mut headers);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].name, "HTTP-Referer");
        assert_eq!(headers[0].value, "https://flycockpit.dev");
        assert_eq!(headers[1].name, "X-OpenRouter-Title");
        assert_eq!(headers[1].value, "FlyCockpit");
    }

    #[test]
    fn merge_preserves_nonempty_override() {
        let mut headers = vec![header("HTTP-Referer", "https://custom.dev")];
        merge_openrouter_attribution(&mut headers);
        assert_eq!(headers.len(), 2);
        let referer = headers.iter().find(|h| h.name == "HTTP-Referer").unwrap();
        assert_eq!(referer.value, "https://custom.dev");
        let title = headers
            .iter()
            .find(|h| h.name == "X-OpenRouter-Title")
            .unwrap();
        assert_eq!(title.value, "FlyCockpit");
    }

    #[test]
    fn merge_suppresses_empty_value() {
        let mut headers = vec![header("HTTP-Referer", "")];
        merge_openrouter_attribution(&mut headers);
        // Empty value removed, not re-added.
        assert!(headers.iter().all(|h| h.name != "HTTP-Referer"));
        // Title still added.
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, "X-OpenRouter-Title");
    }

    #[test]
    fn merge_pairs_adds_defaults_when_missing() {
        let mut headers: Vec<(String, String)> = Vec::new();
        merge_openrouter_attribution_pairs(&mut headers);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "HTTP-Referer");
        assert_eq!(headers[0].1, "https://flycockpit.dev");
        assert_eq!(headers[1].0, "X-OpenRouter-Title");
        assert_eq!(headers[1].1, "FlyCockpit");
    }

    #[test]
    fn merge_pairs_preserves_nonempty_override() {
        let mut headers = vec![("HTTP-Referer".to_string(), "https://custom.dev".to_string())];
        merge_openrouter_attribution_pairs(&mut headers);
        assert_eq!(headers.len(), 2);
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "HTTP-Referer" && v == "https://custom.dev")
        );
    }

    #[test]
    fn merge_pairs_suppresses_empty_value() {
        let mut headers = vec![("HTTP-Referer".to_string(), String::new())];
        merge_openrouter_attribution_pairs(&mut headers);
        assert!(headers.iter().all(|(n, _)| n != "HTTP-Referer"));
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "X-OpenRouter-Title");
    }

    /// Finding 4 conformance: the two entry points must stay in lockstep.
    /// `merge_openrouter_attribution` delegates to
    /// `merge_openrouter_attribution_pairs`, so for any input the resolved
    /// and pair forms must produce the same name/value set in the same order.
    /// A future divergence (e.g. someone re-inlines a second implementation)
    /// trips this test.
    #[test]
    fn merge_resolved_and_pairs_stay_in_lockstep() {
        let cases: Vec<Vec<(&str, &str)>> = vec![
            vec![],
            vec![("HTTP-Referer", "https://custom.dev")],
            vec![("X-OpenRouter-Title", "My App")],
            vec![("HTTP-Referer", "")],
            vec![("X-OpenRouter-Title", "")],
            vec![
                ("Authorization", "Bearer token"),
                ("HTTP-Referer", "https://override.dev"),
                ("X-OpenRouter-Title", "Override Title"),
            ],
            vec![("HTTP-Referer", ""), ("X-OpenRouter-Title", "")],
            vec![
                ("X-Custom", "value"),
                ("http-referer", "https://case-insensitive.dev"),
            ],
        ];

        for (i, case) in cases.into_iter().enumerate() {
            let mut resolved: Vec<ResolvedHeader> =
                case.iter().map(|(n, v)| header(n, v)).collect();
            merge_openrouter_attribution(&mut resolved);
            let resolved_pairs: Vec<(String, String)> = resolved
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect();

            let mut pairs: Vec<(String, String)> = case
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect();
            merge_openrouter_attribution_pairs(&mut pairs);

            assert_eq!(resolved_pairs, pairs, "divergence on case #{i}: {case:?}");
        }
    }
}
