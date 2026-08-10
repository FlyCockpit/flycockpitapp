use super::*;

fn ok(body: &str) -> SanitizedSvgArtifact {
    sanitize_generated_svg(
        format!(r##"<svg xmlns="{SVG_NS}" width="10" height="10">{body}</svg>"##).as_bytes(),
    )
    .unwrap()
}
fn bad(svg: &str) -> SvgSanitizeCode {
    sanitize_generated_svg(svg.as_bytes()).unwrap_err().code()
}

#[test]
fn generated_svg_allowlist() {
    let artifact = ok(
        r##"<title>safe</title><desc>description</desc><defs><linearGradient id="paint"><stop offset="0" stop-color="red"/><stop offset="100%" stop-color="#ABC"/></linearGradient><clipPath id="clip"><rect width="1" height="1"/></clipPath><mask id="mask"><path d="M 0 0 L 1 1 Z"/></mask></defs><g fill="url(#paint)" clip-path="url(#clip)" mask="url(#mask)" transform="translate(1,2)"><rect id="shape" x="0" y="0" width="10" height="10" rx="1" fill-opacity="0.5"/></g>"##,
    );
    let text = std::str::from_utf8(artifact.as_bytes()).unwrap();
    assert!(text.contains("svg_000001"));
    assert!(text.contains("#ff0000"));
    assert!(!text.contains("paint"));
    for element in [
        "script",
        "style",
        "foreignObject",
        "animate",
        "image",
        "use",
        "filter",
        "metadata",
        "a",
    ] {
        assert_eq!(
            bad(&format!(r##"<svg xmlns="{SVG_NS}"><{element}/></svg>"##)),
            SvgSanitizeCode::Element
        )
    }
    for attr in [
        "onclick",
        "style",
        "href",
        "xlink:href",
        "src",
        "xml:base",
        "unknown",
    ] {
        assert!(
            sanitize_generated_svg(format!(r##"<svg xmlns="{SVG_NS}" {attr}="x"/>"##).as_bytes())
                .is_err()
        )
    }
    assert_eq!(
        bad(&format!(r##"<svg xmlns="{SVG_NS}"><defs/><defs/></svg>"##)),
        SvgSanitizeCode::ParentChild
    );
    assert!(
        !ok("<polyline points=\"0 0 1 1\"/><polygon points=\"0,0 1,1 2,2\"/>")
            .as_bytes()
            .is_empty()
    );
}

#[test]
fn generated_svg_url_css_policy() {
    for value in [
        "http://x",
        "https://x",
        "data:image/png,x",
        "file:///x",
        "blob:x",
        "url( #x)",
        "url('#x')",
        "url(#x )",
        "url(#x) tail",
    ] {
        let svg = format!(r##"<svg xmlns="{SVG_NS}"><path fill="{value}"/></svg>"##);
        assert!(sanitize_generated_svg(svg.as_bytes()).is_err(), "{value}");
    }
    assert!(!ok(r##"<defs><radialGradient id="p"><stop/></radialGradient></defs><path fill="url(#p)"/>"##).as_bytes().is_empty());
    assert!(sanitize_generated_svg(format!(r##"<svg xmlns="{SVG_NS}"><defs><clipPath id="c"/></defs><path fill="url(#c)"/></svg>"##).as_bytes()).is_err());
}

#[test]
fn generated_svg_malicious_corpus() {
    for raw in [
        r##"<!DOCTYPE svg><svg/>"##,
        r##"<?xml version="1.0"?><svg/>"##,
        r##"<svg>&xxe;</svg>"##,
        r##"<svg xmlns="urn:evil"/>"##,
        r##"<svg xmlns:xlink="http://www.w3.org/1999/xlink"/>"##,
    ] {
        assert!(sanitize_generated_svg(raw.as_bytes()).is_err())
    }
    assert_eq!(
        bad(&vec![b'x'; MAX_RAW_BYTES + 1]
            .iter()
            .map(|b| *b as char)
            .collect::<String>()),
        SvgSanitizeCode::RawBytes
    );
    assert!(sanitize_generated_svg(format!(r##"<svg xmlns="{SVG_NS}"><defs><linearGradient id="x"><stop/></linearGradient><linearGradient id="x"><stop/></linearGradient></defs></svg>"##).as_bytes()).is_err());
    assert!(
        sanitize_generated_svg(
            format!(r##"<svg xmlns="{SVG_NS}"><path d="M0-1"/></svg>"##).as_bytes()
        )
        .is_err()
    );
    assert_eq!(
        sanitize_generated_svg(format!(r##"<svg xmlns="{SVG_NS}"><defs><mask id="m"><path mask="url(#m)"/></mask></defs></svg>"##).as_bytes()).unwrap_err().code(),
        SvgSanitizeCode::ReferenceCycle
    );
    for number in ["+1", ".5", "1.", "01", "1e3", "1.0000001", "NaN"] {
        assert!(
            sanitize_generated_svg(
                format!(r##"<svg xmlns="{SVG_NS}"><rect width="{number}" height="1"/></svg>"##)
                    .as_bytes()
            )
            .is_err()
        );
    }
    let stops = "<stop/>".repeat(256);
    assert!(sanitize_generated_svg(format!(r##"<svg xmlns="{SVG_NS}"><defs><linearGradient id="g">{stops}</linearGradient></defs></svg>"##).as_bytes()).is_ok());
    let stops = "<stop/>".repeat(257);
    assert!(sanitize_generated_svg(format!(r##"<svg xmlns="{SVG_NS}"><defs><linearGradient id="g">{stops}</linearGradient></defs></svg>"##).as_bytes()).is_err());
    let mut deep = format!(r##"<svg xmlns="{SVG_NS}">"##);
    deep.push_str(&"<g>".repeat(MAX_DEPTH));
    deep.push_str(&"</g>".repeat(MAX_DEPTH));
    deep.push_str("</svg>");
    assert_eq!(
        sanitize_generated_svg(deep.as_bytes()).unwrap_err().code(),
        SvgSanitizeCode::Depth
    );
}

#[test]
fn generated_svg_structural_verify() {
    let a = ok(r##"<rect id="different" width="1" height="1" fill="transparent"/>"##);
    let b = ok(r##"<rect id="source" width="1.000000" height="1" fill="#00000000"/>"##);
    assert_eq!(a, b);
    assert_eq!(
        std::str::from_utf8(a.as_bytes()).unwrap(),
        format!(
            r##"<svg xmlns="{SVG_NS}" height="10" width="10"><rect fill="#00000000" height="1" id="svg_000001" width="1"/></svg>"##
        )
    );
    assert_eq!(
        a.as_bytes(),
        sanitize_generated_svg(a.as_bytes()).unwrap().as_bytes()
    );
    assert_eq!(
        verify_defense_output(a.as_bytes(), br#"<svg><script/></svg>"#)
            .unwrap_err()
            .code(),
        SvgSanitizeCode::DefenseMismatch
    );
}

#[test]
fn generated_svg_defense_disagreement_is_never_projected_away() {
    let raw = format!(r##"<svg xmlns="{SVG_NS}"><title xml:space="preserve">x</title></svg>"##);
    assert_eq!(
        sanitize_generated_svg(raw.as_bytes()).unwrap_err().code(),
        SvgSanitizeCode::DefenseMismatch
    );
}

#[test]
fn generated_svg_transform_argument_roles_and_radial_radius_are_exact() {
    assert!(!ok(r#"<g transform="translate(1000000 -1000000) rotate(360000 1000000 -1000000) scale(1000000)"/>"#).as_bytes().is_empty());
    assert!(
        sanitize_generated_svg(
            format!(r#"<svg xmlns="{SVG_NS}"><g transform="rotate(360001)"/></svg>"#).as_bytes()
        )
        .is_err()
    );
    assert!(sanitize_generated_svg(format!(r#"<svg xmlns="{SVG_NS}"><defs><radialGradient id="g" r="0"><stop/></radialGradient></defs></svg>"#).as_bytes()).is_err());
    assert!(
        !ok(r#"<defs><radialGradient id="g" r="0.000001" fr="0"><stop/></radialGradient></defs>"#)
            .as_bytes()
            .is_empty()
    );
}

#[test]
fn generated_svg_deterministic_canonical_output() {
    let a = ok(
        r##"<defs><linearGradient id="z"><stop offset="0.0" stop-color="red"/></linearGradient></defs>"##,
    );
    assert_eq!(a, sanitize_generated_svg(a.as_bytes()).unwrap());
}

#[test]
fn generated_svg_path_canonicalization_preserves_absolute_subpaths() {
    let artifact = ok(r##"<path d="M 0 0 L 100 50 M 5 6 h 2 v 3"/>"##);
    assert!(
        std::str::from_utf8(artifact.as_bytes())
            .unwrap()
            .contains("d=\"M 0 0 L 100 50 M 5 6 L 7 6 L 7 9\"")
    );
    assert!(
        sanitize_generated_svg(
            format!(r##"<svg xmlns="{SVG_NS}"><path d="M 1000001 0 L 0 0"/></svg>"##).as_bytes()
        )
        .is_err()
    );
    let artifact =
        ok(r##"<path d="M 0 0 C 0 10 10 10 10 0 T 20 0 M 0 0 Q 0 10 10 10 S 20 10 20 0"/>"##);
    let canonical = std::str::from_utf8(artifact.as_bytes()).unwrap();
    assert!(canonical.contains("Q 10 0 20 0"));
    assert!(canonical.contains("C 10 10 20 10 20 0"));
}

#[test]
fn generated_svg_text_fragments_and_transform_separators() {
    let valid = format!("<title>{}&amp;</title>", "a".repeat(1023));
    assert!(!ok(&valid).as_bytes().is_empty());
    let invalid = format!("<title>{}&amp;b</title>", "a".repeat(1023));
    assert_eq!(
        sanitize_generated_svg(format!(r##"<svg xmlns="{SVG_NS}">{invalid}</svg>"##).as_bytes())
            .unwrap_err()
            .code(),
        SvgSanitizeCode::TextScalars
    );
    let transformed = ok(r##"<g transform="translate(1),scale(2)"/>"##);
    assert!(
        std::str::from_utf8(transformed.as_bytes())
            .unwrap()
            .contains("transform=\"translate(1) scale(2)\"")
    );
}
