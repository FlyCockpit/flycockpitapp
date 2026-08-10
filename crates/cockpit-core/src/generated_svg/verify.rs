//! Independent streaming verifier for canonical generated SVG bytes.
//!
//! This deliberately does not construct or reuse the sanitizer's `Node` tree,
//! parent/attribute tables, counters, or reference graph. A serializer or raw
//! validator regression therefore cannot certify its own output.

use std::collections::{HashMap, HashSet};

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use super::{
    MAX_ATTRIBUTE_BYTES, MAX_ATTRIBUTES, MAX_ATTRIBUTES_PER_ELEMENT, MAX_CANONICAL_BYTES,
    MAX_DEPTH, MAX_ELEMENTS, MAX_IDS, MAX_PATH_ATTRIBUTE_BYTES, MAX_PATH_BYTES, MAX_PATH_COMMANDS,
    MAX_REFERENCES, MAX_TEXT_BYTES, MAX_TEXT_SCALARS, SVG_NS, SvgSanitizeCode, SvgSanitizeError,
};

type Result<T> = std::result::Result<T, SvgSanitizeError>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
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
}

impl Kind {
    fn parse(name: &[u8]) -> Result<Self> {
        Ok(match name {
            b"svg" => Self::Svg,
            b"g" => Self::G,
            b"defs" => Self::Defs,
            b"title" => Self::Title,
            b"desc" => Self::Desc,
            b"path" => Self::Path,
            b"rect" => Self::Rect,
            b"circle" => Self::Circle,
            b"ellipse" => Self::Ellipse,
            b"line" => Self::Line,
            b"polyline" => Self::Polyline,
            b"polygon" => Self::Polygon,
            b"clipPath" => Self::ClipPath,
            b"mask" => Self::Mask,
            b"linearGradient" => Self::LinearGradient,
            b"radialGradient" => Self::RadialGradient,
            b"stop" => Self::Stop,
            _ => return fail(SvgSanitizeCode::StructuralVerify, "element"),
        })
    }

    fn reference_kind(self) -> Option<u8> {
        match self {
            Self::LinearGradient | Self::RadialGradient => Some(1),
            Self::ClipPath => Some(2),
            Self::Mask => Some(3),
            _ => None,
        }
    }
}

struct Frame {
    kind: Kind,
    title: bool,
    desc: bool,
    stops: usize,
    definition: Option<usize>,
    radial_r: Option<(i64, bool)>,
    radial_fr: Option<(i64, bool)>,
    text_bytes: usize,
    text_scalars: usize,
}

#[derive(Default)]
struct Limits {
    elements: usize,
    attributes: usize,
    path_bytes: usize,
    path_commands: usize,
    ids: usize,
    references: usize,
    text_bytes: usize,
    text_scalars: usize,
}

struct Reference {
    owner: usize,
    target: String,
    kind: u8,
}

pub(super) fn verify_canonical_svg(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_CANONICAL_BYTES
        || bytes.starts_with(b"\xef\xbb\xbf")
        || bytes.contains(&b'\r')
    {
        return fail(SvgSanitizeCode::StructuralVerify, "encoding");
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().check_end_names = true;
    reader.config_mut().allow_unmatched_ends = false;
    let mut stack = Vec::<Frame>::new();
    let mut limits = Limits::default();
    let mut ids = HashMap::<String, (u8, usize)>::new();
    let mut references = Vec::new();
    let mut root = false;
    let mut defs = false;
    loop {
        match reader.read_event().map_err(|_| error("xml"))? {
            Event::Start(event) => verify_start(
                &reader,
                &event,
                false,
                &mut stack,
                &mut limits,
                &mut ids,
                &mut references,
                &mut root,
                &mut defs,
            )?,
            Event::Empty(event) => verify_start(
                &reader,
                &event,
                true,
                &mut stack,
                &mut limits,
                &mut ids,
                &mut references,
                &mut root,
                &mut defs,
            )?,
            Event::End(_) => finish(stack.pop().ok_or_else(|| error("end"))?)?,
            Event::Text(text) => {
                let value = text.decode().map_err(|_| error("text"))?;
                let value = quick_xml::escape::unescape(&value).map_err(|_| error("text"))?;
                verify_text(&value, stack.last_mut(), &mut limits)?;
            }
            Event::GeneralRef(reference) => {
                let reference = reference.decode().map_err(|_| error("entity"))?;
                let text = match reference.as_ref() {
                    "amp" => "&",
                    "lt" => "<",
                    "gt" => ">",
                    "quot" => "\"",
                    "apos" => "'",
                    _ => return fail(SvgSanitizeCode::StructuralVerify, "entity"),
                };
                verify_text(text, stack.last_mut(), &mut limits)?;
            }
            Event::Eof => break,
            _ => return fail(SvgSanitizeCode::StructuralVerify, "construct"),
        }
    }
    if !root || !stack.is_empty() {
        return fail(SvgSanitizeCode::StructuralVerify, "root");
    }
    for reference in &references {
        let Some((kind, _)) = ids.get(&reference.target) else {
            return fail(SvgSanitizeCode::StructuralVerify, "reference");
        };
        if *kind != reference.kind {
            return fail(SvgSanitizeCode::StructuralVerify, "reference-kind");
        }
    }
    verify_acyclic(&ids, &references)
}

#[allow(clippy::too_many_arguments)]
fn verify_start(
    reader: &Reader<&[u8]>,
    event: &BytesStart<'_>,
    empty: bool,
    stack: &mut Vec<Frame>,
    limits: &mut Limits,
    ids: &mut HashMap<String, (u8, usize)>,
    references: &mut Vec<Reference>,
    root_seen: &mut bool,
    defs_seen: &mut bool,
) -> Result<()> {
    limits.elements = limits
        .elements
        .checked_add(1)
        .ok_or_else(|| error("elements"))?;
    if limits.elements > MAX_ELEMENTS || stack.len() + 1 > MAX_DEPTH {
        return fail(SvgSanitizeCode::StructuralVerify, "bounds");
    }
    let kind = Kind::parse(event.name().as_ref())?;
    if !*root_seen {
        if kind != Kind::Svg || !stack.is_empty() {
            return fail(SvgSanitizeCode::StructuralVerify, "root");
        }
        *root_seen = true;
    } else if stack.is_empty() {
        return fail(SvgSanitizeCode::StructuralVerify, "multiple-root");
    }
    if let Some(parent) = stack.last_mut() {
        if !child_allowed(parent.kind, kind) {
            return fail(SvgSanitizeCode::StructuralVerify, "parent-child");
        }
        match kind {
            Kind::Title if std::mem::replace(&mut parent.title, true) => {
                return fail(SvgSanitizeCode::StructuralVerify, "title-cardinality");
            }
            Kind::Desc if std::mem::replace(&mut parent.desc, true) => {
                return fail(SvgSanitizeCode::StructuralVerify, "desc-cardinality");
            }
            Kind::Stop => parent.stops += 1,
            _ => {}
        }
    }
    if kind == Kind::Defs {
        if std::mem::replace(defs_seen, true) {
            return fail(SvgSanitizeCode::StructuralVerify, "defs-cardinality");
        }
    }
    let definition = if stack.last().is_some_and(|frame| frame.kind == Kind::Defs)
        && kind.reference_kind().is_some()
    {
        Some(limits.elements - 1)
    } else {
        stack.last().and_then(|frame| frame.definition)
    };
    let mut prior_key: Option<Vec<u8>> = None;
    let mut attributes = 0usize;
    let mut has_id = false;
    let mut saw_xmlns = false;
    let mut radial_r = None;
    let mut radial_fr = None;
    for attribute in event.attributes().with_checks(true) {
        let attribute = attribute.map_err(|_| error("attribute"))?;
        attributes += 1;
        limits.attributes = limits
            .attributes
            .checked_add(1)
            .ok_or_else(|| error("attributes"))?;
        if attributes > MAX_ATTRIBUTES_PER_ELEMENT || limits.attributes > MAX_ATTRIBUTES {
            return fail(SvgSanitizeCode::StructuralVerify, "attribute-bounds");
        }
        let key = attribute.key.as_ref();
        let raw_limit = if key == b"d" {
            MAX_PATH_ATTRIBUTE_BYTES
        } else {
            MAX_ATTRIBUTE_BYTES
        };
        if attribute.value.len() > raw_limit {
            return fail(SvgSanitizeCode::StructuralVerify, "attribute-bytes");
        }
        let value = attribute
            .decode_and_unescape_value(reader.decoder())
            .map_err(|_| error("attribute"))?;
        if key == b"xmlns" {
            if kind != Kind::Svg || saw_xmlns || value.as_ref() != SVG_NS {
                return fail(SvgSanitizeCode::StructuralVerify, "namespace");
            }
            saw_xmlns = true;
            continue;
        }
        if kind == Kind::Svg && !saw_xmlns {
            return fail(SvgSanitizeCode::StructuralVerify, "xmlns-order");
        }
        let sort_key = if key == b"xml:space" {
            [
                b"http://www.w3.org/XML/1998/namespace\0".as_slice(),
                b"space",
            ]
            .concat()
        } else {
            key.to_vec()
        };
        if prior_key.as_ref().is_some_and(|prior| prior >= &sort_key) {
            return fail(SvgSanitizeCode::StructuralVerify, "attribute-order");
        }
        prior_key = Some(sort_key);
        let name = std::str::from_utf8(key).map_err(|_| error("attribute"))?;
        if !attribute_allowed(kind, name) || !canonical_value(kind, name, &value, limits)? {
            return fail(SvgSanitizeCode::StructuralVerify, "attribute-value");
        }
        if name == "id" {
            has_id = true;
            limits.ids += 1;
            if limits.ids > MAX_IDS || !canonical_id(&value) {
                return fail(SvgSanitizeCode::StructuralVerify, "id");
            }
            let reference_kind = kind.reference_kind().unwrap_or(0);
            if ids
                .insert(value.into_owned(), (reference_kind, limits.elements - 1))
                .is_some()
            {
                return fail(SvgSanitizeCode::StructuralVerify, "duplicate-id");
            }
        } else if let Some((target, reference_kind)) = canonical_reference(name, &value) {
            limits.references += 1;
            if limits.references > MAX_REFERENCES {
                return fail(SvgSanitizeCode::StructuralVerify, "references");
            }
            references.push(Reference {
                owner: definition.unwrap_or(limits.elements - 1),
                target: target.to_owned(),
                kind: reference_kind,
            });
        }
        if kind == Kind::RadialGradient && matches!(name, "r" | "fr") {
            let percent = value.ends_with('%');
            let number = canonical_scaled(value.strip_suffix('%').unwrap_or(value.as_ref()))
                .ok_or_else(|| error("radial"))?;
            if name == "r" {
                radial_r = Some((number, percent));
            } else {
                radial_fr = Some((number, percent));
            }
        }
    }
    if kind == Kind::Svg && !saw_xmlns {
        return fail(SvgSanitizeCode::StructuralVerify, "xmlns");
    }
    if kind.reference_kind().is_some() && !has_id {
        return fail(SvgSanitizeCode::StructuralVerify, "definition-id");
    }
    let frame = Frame {
        kind,
        title: false,
        desc: false,
        stops: 0,
        definition,
        radial_r,
        radial_fr,
        text_bytes: 0,
        text_scalars: 0,
    };
    if empty {
        finish(frame)
    } else {
        stack.push(frame);
        Ok(())
    }
}

fn finish(frame: Frame) -> Result<()> {
    if matches!(frame.kind, Kind::LinearGradient | Kind::RadialGradient)
        && !(1..=256).contains(&frame.stops)
    {
        return fail(SvgSanitizeCode::StructuralVerify, "gradient-stops");
    }
    if frame.kind == Kind::RadialGradient
        && let (Some((radius, radius_percent)), Some((focal, focal_percent))) =
            (frame.radial_r, frame.radial_fr)
        && (radius_percent != focal_percent || focal > radius)
    {
        return fail(SvgSanitizeCode::StructuralVerify, "radial-fr");
    }
    Ok(())
}

fn child_allowed(parent: Kind, child: Kind) -> bool {
    match parent {
        Kind::Svg => matches!(
            child,
            Kind::Title
                | Kind::Desc
                | Kind::Defs
                | Kind::G
                | Kind::Path
                | Kind::Rect
                | Kind::Circle
                | Kind::Ellipse
                | Kind::Line
                | Kind::Polyline
                | Kind::Polygon
        ),
        Kind::G | Kind::ClipPath | Kind::Mask => matches!(
            child,
            Kind::Title
                | Kind::Desc
                | Kind::G
                | Kind::Path
                | Kind::Rect
                | Kind::Circle
                | Kind::Ellipse
                | Kind::Line
                | Kind::Polyline
                | Kind::Polygon
        ),
        Kind::Defs => matches!(
            child,
            Kind::ClipPath | Kind::Mask | Kind::LinearGradient | Kind::RadialGradient
        ),
        Kind::LinearGradient | Kind::RadialGradient => child == Kind::Stop,
        _ => false,
    }
}

fn attribute_allowed(kind: Kind, name: &str) -> bool {
    let common = matches!(
        name,
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
    );
    let own = match kind {
        Kind::Svg => matches!(
            name,
            "id" | "width" | "height" | "viewBox" | "preserveAspectRatio"
        ),
        Kind::G => matches!(name, "id" | "transform"),
        Kind::Defs => false,
        Kind::Title | Kind::Desc => name == "xml:space",
        Kind::Path => matches!(name, "id" | "d" | "pathLength" | "transform"),
        Kind::Rect => matches!(
            name,
            "id" | "x" | "y" | "width" | "height" | "rx" | "ry" | "pathLength" | "transform"
        ),
        Kind::Circle => matches!(name, "id" | "cx" | "cy" | "r" | "pathLength" | "transform"),
        Kind::Ellipse => matches!(
            name,
            "id" | "cx" | "cy" | "rx" | "ry" | "pathLength" | "transform"
        ),
        Kind::Line => matches!(
            name,
            "id" | "x1" | "y1" | "x2" | "y2" | "pathLength" | "transform"
        ),
        Kind::Polyline | Kind::Polygon => {
            matches!(name, "id" | "points" | "pathLength" | "transform")
        }
        Kind::ClipPath => matches!(name, "id" | "clipPathUnits" | "transform"),
        Kind::Mask => matches!(
            name,
            "id" | "x" | "y" | "width" | "height" | "maskUnits" | "maskContentUnits" | "transform"
        ),
        Kind::LinearGradient => matches!(
            name,
            "id" | "x1"
                | "y1"
                | "x2"
                | "y2"
                | "gradientUnits"
                | "spreadMethod"
                | "gradientTransform"
        ),
        Kind::RadialGradient => matches!(
            name,
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
        Kind::Stop => matches!(name, "offset" | "stop-color" | "stop-opacity"),
    };
    own || (common
        && matches!(
            kind,
            Kind::G
                | Kind::Path
                | Kind::Rect
                | Kind::Circle
                | Kind::Ellipse
                | Kind::Line
                | Kind::Polyline
                | Kind::Polygon
        ))
}

fn canonical_value(kind: Kind, name: &str, value: &str, limits: &mut Limits) -> Result<bool> {
    if name == "id" {
        return Ok(canonical_id(value));
    }
    if name == "d" {
        limits.path_bytes = limits
            .path_bytes
            .checked_add(value.len())
            .ok_or_else(|| error("path-bytes"))?;
        let commands = value
            .split(' ')
            .filter(|token| matches!(*token, "M" | "L" | "C" | "Q" | "A" | "Z"))
            .count();
        limits.path_commands = limits
            .path_commands
            .checked_add(commands)
            .ok_or_else(|| error("path-commands"))?;
        return Ok(limits.path_bytes <= MAX_PATH_BYTES
            && limits.path_commands <= MAX_PATH_COMMANDS
            && canonical_path_shape(value));
    }
    if matches!(name, "transform" | "gradientTransform") {
        return Ok(canonical_transform_shape(value));
    }
    if name == "points" {
        let values = value
            .split(' ')
            .filter_map(canonical_scaled)
            .collect::<Vec<_>>();
        return Ok(values.len() >= (if kind == Kind::Polygon { 6 } else { 4 })
            && values.len() <= 131_072
            && values.len() % 2 == 0
            && values
                .iter()
                .all(|number| number.abs() <= 1_000_000_000_000));
    }
    if name == "stroke-dasharray" {
        if value == "none" {
            return Ok(true);
        }
        let values = value
            .split(' ')
            .filter_map(canonical_scaled)
            .collect::<Vec<_>>();
        return Ok((1..=64).contains(&values.len())
            && values.iter().all(|value| *value >= 0)
            && values.iter().any(|value| *value > 0));
    }
    if canonical_reference(name, value).is_some() {
        return Ok(true);
    }
    if matches!(name, "fill" | "stroke") {
        return Ok(canonical_color(value, true));
    }
    if matches!(name, "clip-path" | "mask") {
        return Ok(value == "none");
    }
    if matches!(name, "color" | "stop-color") {
        return Ok(canonical_color(value, false));
    }
    if matches!(name, "xml:space") {
        return Ok(matches!(value, "default" | "preserve"));
    }
    if name == "preserveAspectRatio" {
        let mut parts = value.split(' ');
        let first = parts.next().unwrap_or("");
        return Ok(value == "none"
            || (matches!(
                first,
                "xMinYMin"
                    | "xMinYMid"
                    | "xMinYMax"
                    | "xMidYMin"
                    | "xMidYMid"
                    | "xMidYMax"
                    | "xMaxYMin"
                    | "xMaxYMid"
                    | "xMaxYMax"
            ) && parts
                .next()
                .is_none_or(|part| matches!(part, "meet" | "slice"))
                && parts.next().is_none()));
    }
    if matches!(
        name,
        "clipPathUnits" | "maskUnits" | "maskContentUnits" | "gradientUnits"
    ) {
        return Ok(matches!(value, "userSpaceOnUse" | "objectBoundingBox"));
    }
    if name == "spreadMethod" {
        return Ok(matches!(value, "pad" | "reflect" | "repeat"));
    }
    if name == "stroke-linecap" {
        return Ok(matches!(value, "butt" | "round" | "square"));
    }
    if name == "stroke-linejoin" {
        return Ok(matches!(value, "miter" | "round" | "bevel"));
    }
    if name == "display" {
        return Ok(matches!(value, "inline" | "none"));
    }
    if name == "visibility" {
        return Ok(matches!(value, "visible" | "hidden" | "collapse"));
    }
    if name == "viewBox" {
        let values = value
            .split(' ')
            .filter_map(canonical_scaled)
            .collect::<Vec<_>>();
        return Ok(values.len() == 4
            && values[2] > 0
            && values[3] > 0
            && values.iter().all(|n| n.abs() <= 1_000_000_000_000));
    }
    if name == "offset" {
        return Ok(canonical_percent_range(value, 0, 100_000_000).is_some()
            || canonical_range(value, 0, 1_000_000));
    }
    if matches!(
        name,
        "fill-opacity" | "stroke-opacity" | "opacity" | "stop-opacity"
    ) {
        return Ok(canonical_range(value, 0, 1_000_000));
    }
    if name == "stroke-miterlimit" {
        return Ok(canonical_range(value, 1_000_000, 1_000_000_000));
    }
    if matches!(name, "width" | "height") && kind == Kind::Svg {
        let bare = value.strip_suffix("px").unwrap_or(value);
        return Ok(canonical_range(bare, 1, 1_000_000_000_000));
    }
    let positive = matches!(name, "pathLength")
        || matches!(
            (kind, name),
            (Kind::Rect, "width" | "height") | (Kind::Circle, "r") | (Kind::RadialGradient, "r")
        );
    let percent = matches!(
        (kind, name),
        (Kind::Mask, "x" | "y" | "width" | "height")
            | (Kind::LinearGradient, "x1" | "y1" | "x2" | "y2")
            | (Kind::RadialGradient, "cx" | "cy" | "fx" | "fy" | "r" | "fr")
    );
    if percent && value.ends_with('%') {
        let min = if positive { 1 } else { -1_000_000_000 };
        return Ok(canonical_percent_range(value, min, 1_000_000_000).is_some());
    }
    let coordinate = matches!(
        name,
        "x" | "y" | "cx" | "cy" | "x1" | "y1" | "x2" | "y2" | "fx" | "fy"
    );
    Ok(canonical_range(
        value,
        if coordinate {
            -1_000_000_000_000
        } else if positive {
            1
        } else {
            0
        },
        1_000_000_000_000,
    ))
}

fn canonical_id(value: &str) -> bool {
    value.len() == 10 && value.starts_with("svg_") && value[4..].bytes().all(|b| b.is_ascii_digit())
}
fn canonical_fixed(value: &str) -> bool {
    if value == "0" {
        return true;
    }
    if value.is_empty()
        || value.starts_with('+')
        || value.starts_with("-0")
        || value.ends_with('0') && value.contains('.')
    {
        return false;
    }
    let body = value.strip_prefix('-').unwrap_or(value);
    let mut parts = body.split('.');
    let whole = parts.next().unwrap_or("");
    let frac = parts.next();
    !whole.is_empty()
        && (whole == "0" || !whole.starts_with('0'))
        && whole.bytes().all(|b| b.is_ascii_digit())
        && parts.next().is_none()
        && frac
            .is_none_or(|f| !f.is_empty() && f.len() <= 6 && f.bytes().all(|b| b.is_ascii_digit()))
}
fn canonical_scaled(value: &str) -> Option<i64> {
    if !canonical_fixed(value) {
        return None;
    }
    let negative = value.starts_with('-');
    let body = value.strip_prefix('-').unwrap_or(value);
    let mut parts = body.split('.');
    let whole = parts.next()?.parse::<i64>().ok()?;
    let mut scaled = whole.checked_mul(1_000_000)?;
    if let Some(frac) = parts.next() {
        let fraction = frac.parse::<i64>().ok()?;
        scaled = scaled.checked_add(fraction.checked_mul(10_i64.pow(6 - frac.len() as u32))?)?;
    }
    Some(if negative { -scaled } else { scaled })
}
fn canonical_range(value: &str, min: i64, max: i64) -> bool {
    canonical_scaled(value).is_some_and(|number| (min..=max).contains(&number))
}
fn canonical_percent_range(value: &str, min: i64, max: i64) -> Option<i64> {
    let number = canonical_scaled(value.strip_suffix('%')?)?;
    (min..=max).contains(&number).then_some(number)
}
fn canonical_color(value: &str, allow_none: bool) -> bool {
    value == "currentColor"
        || (allow_none && value == "none")
        || (matches!(value.len(), 7 | 9)
            && value.starts_with('#')
            && value[1..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}
fn canonical_reference<'a>(name: &str, value: &'a str) -> Option<(&'a str, u8)> {
    let kind = match name {
        "fill" | "stroke" => 1,
        "clip-path" => 2,
        "mask" => 3,
        _ => return None,
    };
    let id = value.strip_prefix("url(#")?.strip_suffix(')')?;
    canonical_id(id).then_some((id, kind))
}
fn canonical_transform_shape(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let mut rest = value;
    let mut functions = 0usize;
    let mut arguments = 0usize;
    while !rest.is_empty() {
        let Some(open) = rest.find('(') else {
            return false;
        };
        let name = &rest[..open];
        if name.is_empty() || name.contains(' ') {
            return false;
        }
        let Some(relative_close) = rest[open + 1..].find(')') else {
            return false;
        };
        let close = open + 1 + relative_close;
        let args = &rest[open + 1..close];
        let values = if args.is_empty() {
            Vec::new()
        } else {
            args.split(' ').collect::<Vec<_>>()
        };
        let expected = match name {
            "matrix" => (6, 6),
            "translate" | "scale" => (1, 2),
            "rotate" => (1, 3),
            "skewX" | "skewY" => (1, 1),
            _ => (usize::MAX, 0),
        };
        if values.len() < expected.0
            || values.len() > expected.1
            || (name == "rotate" && values.len() == 2)
        {
            return false;
        }
        for (index, value) in values.iter().enumerate() {
            let angle = matches!(name, "skewX" | "skewY") || (name == "rotate" && index == 0);
            let bound = if angle {
                360_000_000_000
            } else {
                1_000_000_000_000
            };
            if !canonical_range(value, -bound, bound) {
                return false;
            }
        }
        functions += 1;
        arguments += values.len();
        if functions > 128 || arguments > 768 {
            return false;
        }
        rest = &rest[close + 1..];
        if rest.is_empty() {
            break;
        }
        let Some(next) = rest.strip_prefix(' ') else {
            return false;
        };
        rest = next;
    }
    true
}
fn canonical_path_shape(value: &str) -> bool {
    let tokens = value.split(' ').collect::<Vec<_>>();
    if tokens.is_empty() {
        return false;
    }
    let mut index = 0usize;
    let mut commands = 0usize;
    let mut drew = false;
    let mut closed = false;
    while index < tokens.len() {
        let command = tokens[index];
        if index == 0 && command != "M" {
            return false;
        }
        let argc = match command {
            "M" | "L" => 2,
            "C" => 6,
            "Q" => 4,
            "A" => 7,
            "Z" => 0,
            _ => return false,
        };
        index += 1;
        if index + argc > tokens.len() {
            return false;
        }
        if command == "Z" {
            if !drew {
                return false;
            }
            drew = false;
            closed = true;
        } else {
            for offset in 0..argc {
                let token = tokens[index + offset];
                if command == "A" && matches!(offset, 3 | 4) {
                    if !matches!(token, "0" | "1") {
                        return false;
                    }
                } else if !canonical_scaled(token).is_some_and(|number| {
                    number.abs()
                        <= if command == "A" && offset == 2 {
                            360_000_000_000
                        } else {
                            1_000_000_000_000
                        }
                }) {
                    return false;
                }
            }
            if command == "M" {
                if commands > 0 && !drew && !closed {
                    return false;
                }
                drew = false
            } else {
                drew = true
            }
            closed = false;
        }
        index += argc;
        commands += 1;
    }
    commands > 0 && (drew || tokens.last() == Some(&"Z"))
}

fn verify_text(value: &str, parent: Option<&mut Frame>, limits: &mut Limits) -> Result<()> {
    let Some(parent) = parent else {
        return fail(SvgSanitizeCode::StructuralVerify, "text-placement");
    };
    if !matches!(parent.kind, Kind::Title | Kind::Desc) {
        return fail(SvgSanitizeCode::StructuralVerify, "text-placement");
    }
    parent.text_bytes = parent
        .text_bytes
        .checked_add(value.len())
        .ok_or_else(|| error("text"))?;
    parent.text_scalars = parent
        .text_scalars
        .checked_add(value.chars().count())
        .ok_or_else(|| error("text"))?;
    limits.text_bytes = limits
        .text_bytes
        .checked_add(value.len())
        .ok_or_else(|| error("text"))?;
    limits.text_scalars = limits
        .text_scalars
        .checked_add(value.chars().count())
        .ok_or_else(|| error("text"))?;
    if parent.text_bytes > 4096
        || parent.text_scalars > 1024
        || limits.text_bytes > MAX_TEXT_BYTES
        || limits.text_scalars > MAX_TEXT_SCALARS
    {
        return fail(SvgSanitizeCode::StructuralVerify, "text-bounds");
    }
    if value.chars().any(|c| {
        let n = c as u32;
        (n < 0x20 && !matches!(c, '\t' | '\n'))
            || (0x7f..=0x9f).contains(&n)
            || (0x202a..=0x202e).contains(&n)
            || (0x2066..=0x2069).contains(&n)
            || (0xfdd0..=0xfdef).contains(&n)
            || (n & 0xffff >= 0xfffe)
    }) {
        return fail(SvgSanitizeCode::StructuralVerify, "text-character");
    }
    Ok(())
}
fn verify_acyclic(ids: &HashMap<String, (u8, usize)>, refs: &[Reference]) -> Result<()> {
    let mut graph = HashMap::<usize, Vec<usize>>::new();
    for r in refs {
        if let Some((_, target)) = ids.get(&r.target) {
            graph.entry(r.owner).or_default().push(*target)
        }
    }
    fn visit(
        node: usize,
        graph: &HashMap<usize, Vec<usize>>,
        active: &mut HashSet<usize>,
        done: &mut HashSet<usize>,
    ) -> bool {
        if done.contains(&node) {
            return true;
        }
        if !active.insert(node) {
            return false;
        }
        for next in graph.get(&node).into_iter().flatten() {
            if !visit(*next, graph, active, done) {
                return false;
            }
        }
        active.remove(&node);
        done.insert(node);
        true
    }
    let mut done = HashSet::new();
    for node in graph.keys() {
        if !visit(*node, &graph, &mut HashSet::new(), &mut done) {
            return fail(SvgSanitizeCode::StructuralVerify, "reference-cycle");
        }
    }
    Ok(())
}
fn error(kind: &'static str) -> SvgSanitizeError {
    SvgSanitizeError::new(SvgSanitizeCode::StructuralVerify, kind)
}
fn fail<T>(code: SvgSanitizeCode, kind: &'static str) -> Result<T> {
    Err(SvgSanitizeError::new(code, kind))
}
