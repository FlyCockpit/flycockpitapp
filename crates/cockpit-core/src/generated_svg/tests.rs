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
    use ElementKind::*;
    let kinds = [
        Svg,
        G,
        Defs,
        Title,
        Desc,
        Path,
        Rect,
        Circle,
        Ellipse,
        Line,
        Polyline,
        Polygon,
        ClipPath,
        Mask,
        LinearGradient,
        RadialGradient,
        Stop,
    ];
    for parent in kinds {
        for child in kinds {
            let expected = match parent {
                Svg => matches!(
                    child,
                    Title
                        | Desc
                        | Defs
                        | G
                        | Path
                        | Rect
                        | Circle
                        | Ellipse
                        | Line
                        | Polyline
                        | Polygon
                ),
                G | ClipPath | Mask => matches!(
                    child,
                    Title | Desc | G | Path | Rect | Circle | Ellipse | Line | Polyline | Polygon
                ),
                Defs => matches!(child, ClipPath | Mask | LinearGradient | RadialGradient),
                LinearGradient | RadialGradient => child == Stop,
                _ => false,
            };
            assert_eq!(
                allowed_child(parent, child),
                expected,
                "{} -> {}",
                parent.name(),
                child.name()
            );
        }
    }
    let attribute_universe = [
        "id",
        "width",
        "height",
        "viewBox",
        "preserveAspectRatio",
        "transform",
        "xml:space",
        "d",
        "pathLength",
        "x",
        "y",
        "rx",
        "ry",
        "cx",
        "cy",
        "r",
        "x1",
        "y1",
        "x2",
        "y2",
        "points",
        "clipPathUnits",
        "maskUnits",
        "maskContentUnits",
        "gradientUnits",
        "spreadMethod",
        "gradientTransform",
        "fx",
        "fy",
        "fr",
        "offset",
        "stop-color",
        "stop-opacity",
        "fill",
        "fill-opacity",
        "stroke",
        "stroke-width",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-miterlimit",
        "stroke-dasharray",
        "stroke-dashoffset",
        "stroke-opacity",
        "opacity",
        "color",
        "display",
        "visibility",
        "clip-path",
        "mask",
    ];
    for kind in kinds {
        for attribute in attribute_universe {
            let common = matches!(
                attribute,
                "fill"
                    | "fill-opacity"
                    | "stroke"
                    | "stroke-width"
                    | "stroke-linecap"
                    | "stroke-linejoin"
                    | "stroke-miterlimit"
                    | "stroke-dasharray"
                    | "stroke-dashoffset"
                    | "stroke-opacity"
                    | "opacity"
                    | "color"
                    | "display"
                    | "visibility"
                    | "clip-path"
                    | "mask"
            ) && matches!(
                kind,
                G | Path | Rect | Circle | Ellipse | Line | Polyline | Polygon
            );
            let owned = match kind {
                Svg => matches!(
                    attribute,
                    "id" | "width" | "height" | "viewBox" | "preserveAspectRatio"
                ),
                G => matches!(attribute, "id" | "transform"),
                Defs => false,
                Title | Desc => attribute == "xml:space",
                Path => matches!(attribute, "id" | "d" | "pathLength" | "transform"),
                Rect => matches!(
                    attribute,
                    "id" | "x"
                        | "y"
                        | "width"
                        | "height"
                        | "rx"
                        | "ry"
                        | "pathLength"
                        | "transform"
                ),
                Circle => matches!(
                    attribute,
                    "id" | "cx" | "cy" | "r" | "pathLength" | "transform"
                ),
                Ellipse => matches!(
                    attribute,
                    "id" | "cx" | "cy" | "rx" | "ry" | "pathLength" | "transform"
                ),
                Line => matches!(
                    attribute,
                    "id" | "x1" | "y1" | "x2" | "y2" | "pathLength" | "transform"
                ),
                Polyline | Polygon => {
                    matches!(attribute, "id" | "points" | "pathLength" | "transform")
                }
                ClipPath => matches!(attribute, "id" | "clipPathUnits" | "transform"),
                Mask => matches!(
                    attribute,
                    "id" | "x"
                        | "y"
                        | "width"
                        | "height"
                        | "maskUnits"
                        | "maskContentUnits"
                        | "transform"
                ),
                LinearGradient => matches!(
                    attribute,
                    "id" | "x1"
                        | "y1"
                        | "x2"
                        | "y2"
                        | "gradientUnits"
                        | "spreadMethod"
                        | "gradientTransform"
                ),
                RadialGradient => matches!(
                    attribute,
                    "id" | "cx"
                        | "cy"
                        | "r"
                        | "fx"
                        | "fy"
                        | "fr"
                        | "gradientUnits"
                        | "spreadMethod"
                        | "gradientTransform"
                ),
                Stop => matches!(attribute, "offset" | "stop-color" | "stop-opacity"),
            };
            assert_eq!(
                allowed_attr(kind, attribute),
                owned || common,
                "{} {attribute}",
                kind.name()
            );
        }
        assert!(!allowed_attr(kind, "style"));
        assert!(!allowed_attr(kind, "onclick"));
        assert!(!allowed_attr(kind, "href"));
    }
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
        // A single leading declaration is now interoperable (see
        // generated_svg_xml_declaration_policy), so the malicious variant is a
        // second declaration, which must still reject.
        r##"<?xml version="1.0"?><?xml version="1.0"?><svg/>"##,
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
    for mutation in [
        format!(r#"<svg xmlns="{SVG_NS}"><script/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}" width="javascript:alert(1)"/>"#),
        format!(
            r#"<svg xmlns="{SVG_NS}"><defs><clipPath id="svg_000001"/></defs><path fill="url(#svg_000001)"/></svg>"#
        ),
        format!(r#"<svg xmlns="{SVG_NS}"><path d="M 0 0 H 1"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}" width="1" width="1"/>"#),
    ] {
        assert!(super::verify::verify_canonical_svg(mutation.as_bytes()).is_err());
    }
}

#[test]
fn generated_svg_independent_verifier_rejects_adversarial_canonical_mutations() {
    let mutations = [
        format!(
            r#"<svg xmlns="{SVG_NS}"><defs><clipPath clipPathUnits="objectBoundingBox" id="svg_000001"><rect height="1" width="1" x="2"/></clipPath></defs></svg>"#
        ),
        format!(r#"<svg xmlns="{SVG_NS}"><polygon points="0 0 bad 1 1 2 2"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><path stroke-dasharray="1 bad 2"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}" viewBox="0 0 bad 10 10"/>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><path d="M 0 0 A -1 1 0 0 0 1 1"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><rect id="svg_000000"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><rect id="svg_000002"/><rect id="svg_000001"/></svg>"#),
    ];
    for mutation in mutations {
        assert!(
            super::verify::verify_canonical_svg(mutation.as_bytes()).is_err(),
            "{mutation}"
        );
    }

    for accepted in [
        format!(
            r#"<svg xmlns="{SVG_NS}"><defs><clipPath clipPathUnits="objectBoundingBox" id="svg_000001"><rect height="1" width="1" x="0"/></clipPath></defs></svg>"#
        ),
        format!(r#"<svg xmlns="{SVG_NS}"><path d="M 0 0 A 0 1 0 0 0 1 1"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><rect id="svg_000001"/><rect id="svg_000002"/></svg>"#),
    ] {
        assert!(
            super::verify::verify_canonical_svg(accepted.as_bytes()).is_ok(),
            "{accepted}"
        );
    }
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

#[test]
fn generated_svg_incremental_writers_and_decoders_stop_at_exact_ceiling() {
    let mut writer = BoundedBytes::new(4);
    std::io::Write::write_all(&mut writer, b"1234").unwrap();
    assert_eq!(writer.as_slice(), b"1234");
    assert!(std::io::Write::write_all(&mut writer, b"5").is_err());
    assert!(writer.overflowed);
    assert_eq!(writer.as_slice(), b"1234");

    assert_eq!(decode_attribute_bounded(b"&amp;&lt;", 2).unwrap(), "&<");
    assert_eq!(
        decode_attribute_bounded(b"&amp;&lt;", 1)
            .unwrap_err()
            .code(),
        SvgSanitizeCode::AttributeBytes
    );
}

#[test]
fn generated_svg_raw_depth_element_id_reference_and_text_ceilings_are_exact() {
    let document_at_depth = |depth: usize| {
        format!(
            "<svg>{}{}</svg>",
            "<g>".repeat(depth - 1),
            "</g>".repeat(depth - 1)
        )
    };
    assert!(parse_validate(document_at_depth(MAX_DEPTH).as_bytes(), false).is_ok());
    assert_eq!(
        parse_validate(document_at_depth(MAX_DEPTH + 1).as_bytes(), false)
            .unwrap_err()
            .code(),
        SvgSanitizeCode::Depth
    );

    let sibling_document =
        |elements: usize| format!("<svg>{}</svg>", "<path/>".repeat(elements - 1));
    assert!(parse_validate(sibling_document(MAX_ELEMENTS).as_bytes(), false).is_ok());
    assert_eq!(
        parse_validate(sibling_document(MAX_ELEMENTS + 1).as_bytes(), false)
            .unwrap_err()
            .code(),
        SvgSanitizeCode::ElementCount
    );

    let id_document = |ids: usize| {
        let mut raw = String::from("<svg>");
        for id in 0..ids {
            raw.push_str(&format!("<path id=\"i{id}\"/>"));
        }
        raw.push_str("</svg>");
        raw
    };
    assert!(parse_validate(id_document(MAX_IDS).as_bytes(), false).is_ok());
    assert_eq!(
        parse_validate(id_document(MAX_IDS + 1).as_bytes(), false)
            .unwrap_err()
            .code(),
        SvgSanitizeCode::IdCount
    );

    let reference_document = |references: usize| {
        let mut raw = String::from(
            "<svg><defs><linearGradient id=\"p\"><stop/></linearGradient><clipPath id=\"c\"/><mask id=\"m\"/></defs>",
        );
        let full = references / 4;
        for _ in 0..full {
            raw.push_str("<path fill=\"url(#p)\" stroke=\"url(#p)\" clip-path=\"url(#c)\" mask=\"url(#m)\"/>");
        }
        for attribute in ["fill", "stroke", "clip-path", "mask"]
            .into_iter()
            .take(references % 4)
        {
            let target = if matches!(attribute, "fill" | "stroke") {
                "p"
            } else if attribute == "clip-path" {
                "c"
            } else {
                "m"
            };
            raw.push_str(&format!("<path {attribute}=\"url(#{target})\"/>"));
        }
        raw.push_str("</svg>");
        raw
    };
    assert!(parse_validate(reference_document(MAX_REFERENCES).as_bytes(), false).is_ok());
    assert_eq!(
        parse_validate(reference_document(MAX_REFERENCES + 1).as_bytes(), false)
            .unwrap_err()
            .code(),
        SvgSanitizeCode::ReferenceCount
    );

    let text_document = |scalars: usize| {
        let mut raw = String::from("<svg>");
        let mut remaining = scalars;
        while remaining > 0 {
            let count = remaining.min(1024);
            raw.push_str("<g><title>");
            raw.push_str(&"x".repeat(count));
            raw.push_str("</title></g>");
            remaining -= count;
        }
        raw.push_str("</svg>");
        raw
    };
    assert!(parse_validate(text_document(MAX_TEXT_SCALARS).as_bytes(), false).is_ok());
    assert_eq!(
        parse_validate(text_document(MAX_TEXT_SCALARS + 1).as_bytes(), false)
            .unwrap_err()
            .code(),
        SvgSanitizeCode::TextScalars
    );
    let unicode_text_document = |scalars: usize| {
        let mut raw = String::from("<svg>");
        let mut remaining = scalars;
        while remaining > 0 {
            let count = remaining.min(1024);
            raw.push_str("<g><title>");
            raw.push_str(&"😀".repeat(count));
            raw.push_str("</title></g>");
            remaining -= count;
        }
        raw.push_str("</svg>");
        raw
    };
    assert!(parse_validate(unicode_text_document(MAX_TEXT_SCALARS).as_bytes(), false).is_ok());
    assert_eq!(
        parse_validate(
            unicode_text_document(MAX_TEXT_SCALARS + 1).as_bytes(),
            false
        )
        .unwrap_err()
        .code(),
        SvgSanitizeCode::TextBytes
    );
}

#[test]
fn generated_svg_raw_attribute_and_path_aggregate_ceilings_are_exact() {
    let attributes_document = |root_attributes: &str, groups: usize| {
        format!("<svg {root_attributes}>{}</svg>","<g transform=\"\" fill=\"none\" fill-opacity=\"1\" stroke=\"none\" stroke-width=\"0\" stroke-linecap=\"butt\" stroke-linejoin=\"miter\" stroke-miterlimit=\"1\" stroke-dasharray=\"none\" stroke-dashoffset=\"0\" stroke-opacity=\"1\" opacity=\"1\" color=\"black\" display=\"inline\" visibility=\"visible\"/>".repeat(groups))
    };
    // 13,333 * 15 ordinary attributes plus five root attributes, including xmlns.
    let equal = attributes_document(
        &format!(
            "xmlns=\"{SVG_NS}\" width=\"1\" height=\"1\" viewBox=\"0 0 1 1\" preserveAspectRatio=\"none\""
        ),
        13_333,
    );
    assert!(parse_validate(equal.as_bytes(), false).is_ok());
    let above = attributes_document(
        &format!(
            "xmlns=\"{SVG_NS}\" id=\"root\" width=\"1\" height=\"1\" viewBox=\"0 0 1 1\" preserveAspectRatio=\"none\""
        ),
        13_333,
    );
    assert_eq!(
        parse_validate(above.as_bytes(), false).unwrap_err().code(),
        SvgSanitizeCode::TotalAttributeCount
    );

    let path_document = |extra: bool| {
        let mut raw = String::from("<svg>");
        for _ in 0..8 {
            let mut path = String::from("M 0 0 L 0 0");
            path.push_str(&" ".repeat(MAX_PATH_ATTRIBUTE_BYTES - path.len()));
            raw.push_str("<path d=\"");
            raw.push_str(&path);
            raw.push_str("\"/>");
        }
        if extra {
            raw.push_str("<path d=\" \"/>");
        }
        raw.push_str("</svg>");
        raw
    };
    assert!(parse_validate(path_document(false).as_bytes(), false).is_ok());
    assert_eq!(
        parse_validate(path_document(true).as_bytes(), false)
            .unwrap_err()
            .code(),
        SvgSanitizeCode::PathBytes
    );
}

#[test]
fn generated_svg_path_command_ceiling_is_exact_across_attributes() {
    let document = |commands: usize| {
        let mut raw = String::from("<svg>");
        let mut remaining = commands;
        while remaining > 0 {
            let chunk = remaining.min(150_000);
            raw.push_str("<path d=\"M 0 0");
            raw.push_str(&" L 0 0".repeat(chunk - 1));
            raw.push_str("\"/>");
            remaining -= chunk;
        }
        raw.push_str("</svg>");
        raw
    };
    assert!(parse_validate(document(MAX_PATH_COMMANDS).as_bytes(), false).is_ok());
    assert_eq!(
        parse_validate(document(MAX_PATH_COMMANDS + 1).as_bytes(), false)
            .unwrap_err()
            .code(),
        SvgSanitizeCode::PathCommands
    );
}

#[test]
fn generated_svg_raw_byte_ceiling_is_checked_before_parse() {
    for length in [MAX_RAW_BYTES - 1, MAX_RAW_BYTES] {
        let mut raw = Vec::with_capacity(length);
        raw.extend_from_slice(b"<svg/>");
        raw.resize(length, b' ');
        if let Err(error) = sanitize_generated_svg(&raw) {
            assert_ne!(error.code(), SvgSanitizeCode::RawBytes);
        }
    }
    assert_eq!(
        sanitize_generated_svg(&vec![b' '; MAX_RAW_BYTES + 1])
            .unwrap_err()
            .code(),
        SvgSanitizeCode::RawBytes
    );
}

#[test]
fn generated_svg_namespace_and_active_content_matrix_is_closed() {
    for raw in [
        format!(r#"<svg xmlns="{SVG_NS}"><g xmlns="{SVG_NS}"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><g xmlns=""/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}" xmlns:evil="urn:evil"/>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><evil:path/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><path onload="x"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><path style="fill:red"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><path filter="url(#x)"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><path fill="url(&#35;x)"/></svg>"#),
    ] {
        assert!(sanitize_generated_svg(raw.as_bytes()).is_err(), "{raw}");
    }
}

#[test]
fn generated_svg_canonical_number_color_and_reference_fixtures_are_source_independent() {
    let first = ok(
        r##"<defs><linearGradient id="first"><stop offset="0.500000" stop-color="#AbC"/></linearGradient></defs><path id="shape-a" d="m 0 0 h 1 v 1 z" fill="url(#first)" transform="translate(1.000000,2)"/>"##,
    );
    let second = ok(
        r##"<defs><linearGradient id="different"><stop offset="0.5" stop-color="#aabbcc"/></linearGradient></defs><path id="shape-b" d="M 0 0 L 1 0 L 1 1 Z" fill="url(#different)" transform="translate(1 2)"/>"##,
    );
    assert_eq!(first, second);
    let canonical = std::str::from_utf8(first.as_bytes()).unwrap();
    assert!(canonical.contains("id=\"svg_000001\""));
    assert!(canonical.contains("id=\"svg_000002\""));
    assert!(canonical.contains("fill=\"url(#svg_000001)\""));
    assert!(canonical.contains("stop-color=\"#aabbcc\""));
}

#[test]
fn generated_svg_xml_declaration_policy() {
    // AC1: a single leading XML declaration is accepted and discarded — with an
    // encoding, with a standalone flag, and bare — and the canonical output
    // never re-emits a declaration.
    for decl in [
        r#"<?xml version="1.0" encoding="UTF-8"?>"#,
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
        r#"<?xml version="1.0"?>"#,
    ] {
        let raw = format!(
            r#"{decl}<svg xmlns="{SVG_NS}" width="10" height="10"><rect width="1" height="1"/></svg>"#
        );
        let artifact = sanitize_generated_svg(raw.as_bytes()).unwrap();
        let text = std::str::from_utf8(artifact.as_bytes()).unwrap();
        assert!(
            !text.contains("<?xml"),
            "declaration must not survive canonicalization: {text}"
        );
        assert!(text.starts_with("<svg"), "{text}");
    }

    // AC2 + AC6: a second declaration, a mid-stream declaration, a declaration
    // after the root, a processing instruction, a DTD, and CData all reject with
    // the stable `Xml` code.
    for raw in [
        // second declaration, immediately following the first
        format!(r#"<?xml version="1.0"?><?xml version="1.0"?><svg xmlns="{SVG_NS}"/>"#),
        // second declaration after intervening whitespace
        format!(r#"<?xml version="1.0"?> <?xml version="1.0"?><svg xmlns="{SVG_NS}"/>"#),
        // declaration nested inside the root element
        format!(r#"<svg xmlns="{SVG_NS}"><?xml version="1.0"?></svg>"#),
        // processing instruction (quick-xml emits PI, not Decl, for `xml-...`)
        format!(r#"<?xml-stylesheet href="x.css"?><svg xmlns="{SVG_NS}"/>"#),
        // DTD / DocType
        format!(r#"<!DOCTYPE svg><svg xmlns="{SVG_NS}"/>"#),
        // CData
        format!(r#"<svg xmlns="{SVG_NS}"><![CDATA[x]]></svg>"#),
    ] {
        assert_eq!(
            sanitize_generated_svg(raw.as_bytes()).unwrap_err().code(),
            SvgSanitizeCode::Xml,
            "{raw}"
        );
    }
}

#[test]
fn generated_svg_non_path_d_attribute_does_not_consume_path_budget() {
    // AC3: a `d` attribute is granted the oversized path-data budget only on a
    // `path` element. On a `rect` it is bounded by the ordinary attribute
    // ceiling, so a `d` just over that ceiling (but well under the path ceiling)
    // now fails with `AttributeBytes`. Under the old name-only budget keying it
    // decoded fine and was only rejected later as a disallowed attribute
    // (`Attribute`), so this input distinguishes the two behaviours.
    const { assert!(MAX_ATTRIBUTE_BYTES + 1 < MAX_PATH_ATTRIBUTE_BYTES) };
    let oversized = "0".repeat(MAX_ATTRIBUTE_BYTES + 1);
    let rect = format!(r#"<svg xmlns="{SVG_NS}"><rect d="{oversized}"/></svg>"#);
    assert_eq!(
        sanitize_generated_svg(rect.as_bytes()).unwrap_err().code(),
        SvgSanitizeCode::AttributeBytes
    );

    // A genuine `path` `d` of the same oversized length — larger than the
    // ordinary attribute ceiling — still succeeds precisely because the path
    // element keeps the larger path-data budget.
    let commands = "L 0 0 ".repeat(20_000);
    assert!(commands.len() > MAX_ATTRIBUTE_BYTES && commands.len() < MAX_PATH_ATTRIBUTE_BYTES);
    let path = format!(r#"<svg xmlns="{SVG_NS}"><path d="M 0 0 {commands}"/></svg>"#);
    assert!(sanitize_generated_svg(path.as_bytes()).is_ok());
}

#[test]
fn generated_svg_gradient_stop_count_ignores_non_node_children() {
    // AC4: gradient stop cardinality counts only `stop` element nodes, never any
    // non-node (text) child. The production parser cannot itself place a
    // `Child::Text` under a gradient (character data is only retained under
    // title/desc), so this defence-in-depth invariant is exercised by driving
    // the real `validate_node` entry point with a tree that carries injected
    // text children — the exact shape a serializer/parser regression could one
    // day produce.
    let stop = |index: usize| Node {
        kind: ElementKind::Stop,
        attrs: BTreeMap::new(),
        children: Vec::new(),
        source_index: index,
    };
    let gradient_with = |stops: usize, texts: usize| {
        let mut node = Node {
            kind: ElementKind::LinearGradient,
            attrs: BTreeMap::from([("id".to_owned(), "grad".to_owned())]),
            children: Vec::new(),
            source_index: 0,
        };
        for index in 0..stops {
            node.children.push(Child::Node(stop(index + 1)));
        }
        for _ in 0..texts {
            node.children.push(Child::Text(" ".to_owned()));
        }
        node
    };
    let run = |mut node: Node| -> Result<()> {
        let mut ids = HashMap::new();
        let mut refs: Vec<Reference> = Vec::new();
        let mut counts = Counts::default();
        let mut defs_seen = false;
        validate_node(
            &mut node,
            Some(ElementKind::Defs),
            None,
            false,
            &mut ids,
            &mut refs,
            &mut counts,
            &mut defs_seen,
        )
    };

    // 256 stop nodes plus 8 text children: only the 256 stops count, so this is
    // in range. Counting `children.len()` (264) would over-count and reject.
    assert!(run(gradient_with(256, 8)).is_ok());
    // Text-only children never satisfy the minimum: the stop count is 0, so an
    // otherwise-empty gradient padded with text still rejects. Counting
    // `children.len()` would treat the text as stops and wrongly accept it.
    assert_eq!(
        run(gradient_with(0, 5)).unwrap_err().code(),
        SvgSanitizeCode::ParentChild
    );
    // 257 real stop nodes still exceeds the ceiling on node count.
    assert_eq!(
        run(gradient_with(257, 0)).unwrap_err().code(),
        SvgSanitizeCode::ParentChild
    );

    // Front-door robustness: a gradient whose stops are separated by whitespace
    // text sanitizes, and 256 stops with interspersed whitespace stays in range.
    let stops = "\n  <stop/>".repeat(256);
    assert!(
        sanitize_generated_svg(
            format!(
                r#"<svg xmlns="{SVG_NS}"><defs><linearGradient id="g">{stops}
</linearGradient></defs></svg>"#
            )
            .as_bytes()
        )
        .is_ok()
    );
}

#[test]
fn generated_svg_fuzz_harness_smoke() {
    // `-runs=0`-equivalent smoke for the cargo-fuzz targets under
    // `crates/cockpit-core/fuzz/`: replay seed corpus and structural mutations
    // through the exact entry points the libfuzzer targets drive and assert the
    // fuzzing invariant — no input panics, aborts, or hangs.
    let mut seeds: Vec<Vec<u8>> = [
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="1" height="1"/></svg>"#,
        r#"<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg"><path d="M 0 0 L 1 1 Z"/></svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg" onload="x"><script>alert(1)</script></svg>"#,
        r#"<!DOCTYPE svg [<!ENTITY x "y">]><svg>&x;</svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="99999999999999999999999"/></svg>"#,
        r##"<svg xmlns="http://www.w3.org/2000/svg" height="10" width="10"><rect fill="#00000000" height="1" id="svg_000001" width="1"/></svg>"##,
        r#"<svg"#,
        "",
    ]
    .iter()
    .map(|seed| seed.as_bytes().to_vec())
    .collect();
    // Deeply nested (but unterminated) structural mutation.
    let mut deep = br#"<svg xmlns="http://www.w3.org/2000/svg">"#.to_vec();
    for _ in 0..1_000 {
        deep.extend_from_slice(b"<g>");
    }
    seeds.push(deep);
    // Non-UTF-8 bytes must be handled without panicking.
    seeds.push(vec![0xff, 0xfe, 0x3c, 0x73, 0x76, 0x67, 0x3e, 0x00]);

    for seed in &seeds {
        let _ = sanitize_generated_svg(seed);
        fuzz_verify_canonical_svg(seed);
    }
}

#[test]
fn generated_svg_sentinel_raw_malicious_svg_cannot_reach_artifact_boundary() {
    // The provider-response ingestion boundary
    // (`image_generation::adapters::openrouter::parse_response`) admits an SVG
    // output only after it passes the closed-policy sanitizer, and the artifact
    // serving route (`image_generation_artifact_routes`) serves exactly those
    // admitted bytes. This is the concrete serialization boundary the sanitizer
    // guards, so a sentinel-bearing malicious SVG must never survive to a
    // retained `ParsedOutput`.
    use crate::image_generation::adapters::openrouter::parse_response;
    use base64::Engine as _;

    const SENTINEL: &str = "SVG_RAW_SENTINEL_MUST_NOT_SERIALIZE";

    let malicious = [
        format!(r#"<svg xmlns="{SVG_NS}"><script>{SENTINEL}</script></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}" onload="{SENTINEL}"/>"#),
        format!(r#"<?xml-stylesheet href="{SENTINEL}"?><svg xmlns="{SVG_NS}"/>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><path fill="url(javascript:{SENTINEL})"/></svg>"#),
        format!(r#"<svg xmlns="{SVG_NS}"><foreignObject>{SENTINEL}</foreignObject></svg>"#),
    ];

    for svg in malicious {
        // Precondition: the raw bytes really do carry the sentinel we claim to
        // keep off the boundary.
        assert!(svg.contains(SENTINEL), "{svg}");
        // The single sanitizer funnel every boundary shares rejects it.
        assert!(sanitize_generated_svg(svg.as_bytes()).is_err(), "{svg}");

        // The real ingestion boundary must reject before any retention, so no
        // `ParsedOutput` ever carries the sentinel bytes.
        let body = serde_json::json!({
            "data": [{
                "b64_json": base64::engine::general_purpose::STANDARD.encode(svg.as_bytes()),
            }],
        })
        .to_string();
        match parse_response(body.as_bytes()) {
            Err(_) => {}
            Ok(parsed) => {
                for output in &parsed.outputs {
                    assert!(
                        !output
                            .bytes
                            .windows(SENTINEL.len())
                            .any(|window| window == SENTINEL.as_bytes()),
                        "sentinel reached serialization boundary: {svg}"
                    );
                }
                panic!("malicious SVG was admitted to the artifact boundary: {svg}");
            }
        }
    }

    // A benign provider output — including one with a leading XML declaration —
    // is admitted, and the retained bytes carry no sentinel.
    let benign = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><svg xmlns="{SVG_NS}" width="10" height="10"><rect width="1" height="1"/></svg>"#
    );
    let body = serde_json::json!({
        "data": [{
            "b64_json": base64::engine::general_purpose::STANDARD.encode(benign.as_bytes()),
        }],
    })
    .to_string();
    // Precondition: the raw provider payload really carries a leading
    // declaration that the boundary must transform away, not retain.
    assert!(benign.contains("<?xml"));
    let parsed = parse_response(body.as_bytes()).expect("benign SVG must be admitted");
    assert_eq!(parsed.outputs.len(), 1);
    assert_eq!(parsed.outputs[0].media_type, "image/svg+xml");
    // The boundary retains the sanitizer's CANONICAL output, not the raw bytes:
    // the stored bytes are byte-identical to the sanitized artifact, carry no
    // XML declaration, and begin at the `<svg` root — proving the sanitizer
    // transformed the leading-declaration input rather than merely gating it.
    let sanitized = sanitize_generated_svg(benign.as_bytes()).unwrap();
    assert_eq!(parsed.outputs[0].bytes, sanitized.as_bytes());
    assert!(
        !parsed.outputs[0]
            .bytes
            .windows(5)
            .any(|window| window == b"<?xml")
    );
    assert!(
        std::str::from_utf8(&parsed.outputs[0].bytes)
            .unwrap()
            .starts_with("<svg")
    );
    assert!(
        !parsed.outputs[0]
            .bytes
            .windows(SENTINEL.len())
            .any(|window| window == SENTINEL.as_bytes())
    );
    // The sanitizer itself also never emits the sentinel for benign input.
    assert!(
        !std::str::from_utf8(sanitized.as_bytes())
            .unwrap()
            .contains(SENTINEL)
    );
}
