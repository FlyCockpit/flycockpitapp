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
    assert!(parse_validate(document_at_depth(MAX_DEPTH).as_bytes(), false, false).is_ok());
    assert_eq!(
        parse_validate(document_at_depth(MAX_DEPTH + 1).as_bytes(), false, false)
            .unwrap_err()
            .code(),
        SvgSanitizeCode::Depth
    );

    let sibling_document =
        |elements: usize| format!("<svg>{}</svg>", "<path/>".repeat(elements - 1));
    assert!(parse_validate(sibling_document(MAX_ELEMENTS).as_bytes(), false, false).is_ok());
    assert_eq!(
        parse_validate(sibling_document(MAX_ELEMENTS + 1).as_bytes(), false, false)
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
    assert!(parse_validate(id_document(MAX_IDS).as_bytes(), false, false).is_ok());
    assert_eq!(
        parse_validate(id_document(MAX_IDS + 1).as_bytes(), false, false)
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
    assert!(parse_validate(reference_document(MAX_REFERENCES).as_bytes(), false, false).is_ok());
    assert_eq!(
        parse_validate(
            reference_document(MAX_REFERENCES + 1).as_bytes(),
            false,
            false
        )
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
    assert!(parse_validate(text_document(MAX_TEXT_SCALARS).as_bytes(), false, false).is_ok());
    assert_eq!(
        parse_validate(text_document(MAX_TEXT_SCALARS + 1).as_bytes(), false, false)
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
    assert!(
        parse_validate(
            unicode_text_document(MAX_TEXT_SCALARS).as_bytes(),
            false,
            false
        )
        .is_ok()
    );
    assert_eq!(
        parse_validate(
            unicode_text_document(MAX_TEXT_SCALARS + 1).as_bytes(),
            false,
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
    assert!(parse_validate(equal.as_bytes(), false, false).is_ok());
    let above = attributes_document(
        &format!(
            "xmlns=\"{SVG_NS}\" id=\"root\" width=\"1\" height=\"1\" viewBox=\"0 0 1 1\" preserveAspectRatio=\"none\""
        ),
        13_333,
    );
    assert_eq!(
        parse_validate(above.as_bytes(), false, false)
            .unwrap_err()
            .code(),
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
    assert!(parse_validate(path_document(false).as_bytes(), false, false).is_ok());
    assert_eq!(
        parse_validate(path_document(true).as_bytes(), false, false)
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
    assert!(parse_validate(document(MAX_PATH_COMMANDS).as_bytes(), false, false).is_ok());
    assert_eq!(
        parse_validate(document(MAX_PATH_COMMANDS + 1).as_bytes(), false, false)
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
