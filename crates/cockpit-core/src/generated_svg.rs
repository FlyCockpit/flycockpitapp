//! Closed-policy sanitizer for untrusted generated SVG artifacts.
//!
//! Raw XML never leaves this module. Acceptance, defense-in-depth filtering,
//! canonicalization, and an independent reparse all complete before the
//! trusted wrapper can be constructed.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::io::{self, Write};

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use sha2::{Digest as _, Sha256};

use cockpit_db::image_generation_plan::VectorSanitizerProvenanceV1;

mod verify;

const SVG_NS: &str = "http://www.w3.org/2000/svg";
pub const MAX_RAW_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CANONICAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ELEMENTS: usize = 50_000;
pub const MAX_DEPTH: usize = 128;
pub const MAX_ATTRIBUTES_PER_ELEMENT: usize = 32;
pub const MAX_ATTRIBUTES: usize = 200_000;
pub const MAX_ATTRIBUTE_BYTES: usize = 64 * 1024;
pub const MAX_PATH_ATTRIBUTE_BYTES: usize = 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PATH_COMMANDS: usize = 1_000_000;
pub const MAX_IDS: usize = 16_384;
pub const MAX_REFERENCES: usize = 65_536;
pub const MAX_TEXT_BYTES: usize = 32_768;
pub const MAX_TEXT_SCALARS: usize = 8_192;

pub fn sanitizer_provenance() -> VectorSanitizerProvenanceV1 {
    let policy = format!(
        "generated-svg-v1:{MAX_RAW_BYTES}:{MAX_CANONICAL_BYTES}:{MAX_ELEMENTS}:{MAX_DEPTH}:{MAX_ATTRIBUTES}:{MAX_PATH_COMMANDS}:{MAX_IDS}:{MAX_REFERENCES}:{MAX_TEXT_BYTES}:{MAX_TEXT_SCALARS}"
    );
    VectorSanitizerProvenanceV1 {
        schema_version: 1,
        sanitizer_kind: "generated_svg_closed_policy".into(),
        policy_digest: crate::intel::hex_lower(&Sha256::digest(policy.as_bytes())),
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SanitizedSvgArtifact(Vec<u8>);

impl SanitizedSvgArtifact {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SanitizedSvgArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SanitizedSvgArtifact")
            .field("byte_len", &self.0.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvgSanitizeCode {
    RawBytes,
    CanonicalBytes,
    Xml,
    Namespace,
    Element,
    ParentChild,
    Depth,
    ElementCount,
    AttributeCount,
    TotalAttributeCount,
    AttributeBytes,
    PathBytes,
    PathCommands,
    IdCount,
    ReferenceCount,
    TextBytes,
    TextScalars,
    TextCharacter,
    TextPlacement,
    DuplicateId,
    MissingId,
    ReferenceTarget,
    ReferenceCycle,
    Attribute,
    Number,
    Points,
    Path,
    Transform,
    DefenseMismatch,
    StructuralVerify,
}

impl SvgSanitizeCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RawBytes => "generated_svg_raw_bytes",
            Self::CanonicalBytes => "generated_svg_canonical_bytes",
            Self::Xml => "generated_svg_xml",
            Self::Namespace => "generated_svg_namespace",
            Self::Element => "generated_svg_element",
            Self::ParentChild => "generated_svg_parent_child",
            Self::Depth => "generated_svg_depth",
            Self::ElementCount => "generated_svg_element_count",
            Self::AttributeCount => "generated_svg_attribute_count",
            Self::TotalAttributeCount => "generated_svg_total_attribute_count",
            Self::AttributeBytes => "generated_svg_attribute_bytes",
            Self::PathBytes => "generated_svg_path_bytes",
            Self::PathCommands => "generated_svg_path_commands",
            Self::IdCount => "generated_svg_id_count",
            Self::ReferenceCount => "generated_svg_reference_count",
            Self::TextBytes => "generated_svg_text_bytes",
            Self::TextScalars => "generated_svg_text_scalars",
            Self::TextCharacter => "generated_svg_text_character",
            Self::TextPlacement => "generated_svg_text_placement",
            Self::DuplicateId => "generated_svg_duplicate_id",
            Self::MissingId => "generated_svg_missing_id",
            Self::ReferenceTarget => "generated_svg_reference_target",
            Self::ReferenceCycle => "generated_svg_reference_cycle",
            Self::Attribute => "generated_svg_attribute",
            Self::Number => "generated_svg_number",
            Self::Points => "generated_svg_points",
            Self::Path => "generated_svg_path",
            Self::Transform => "generated_svg_transform",
            Self::DefenseMismatch => "generated_svg_defense_mismatch",
            Self::StructuralVerify => "generated_svg_structural_verify",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvgSanitizeError {
    code: SvgSanitizeCode,
    kind: &'static str,
}
impl SvgSanitizeError {
    fn new(code: SvgSanitizeCode, kind: &'static str) -> Self {
        Self { code, kind }
    }
    pub const fn code(&self) -> SvgSanitizeCode {
        self.code
    }
    pub const fn kind(&self) -> &'static str {
        self.kind
    }
}
impl fmt::Display for SvgSanitizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code.as_str(), self.kind)
    }
}
impl std::error::Error for SvgSanitizeError {}
type Result<T> = std::result::Result<T, SvgSanitizeError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ElementKind {
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
impl ElementKind {
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "svg" => Self::Svg,
            "g" => Self::G,
            "defs" => Self::Defs,
            "title" => Self::Title,
            "desc" => Self::Desc,
            "path" => Self::Path,
            "rect" => Self::Rect,
            "circle" => Self::Circle,
            "ellipse" => Self::Ellipse,
            "line" => Self::Line,
            "polyline" => Self::Polyline,
            "polygon" => Self::Polygon,
            "clipPath" => Self::ClipPath,
            "mask" => Self::Mask,
            "linearGradient" => Self::LinearGradient,
            "radialGradient" => Self::RadialGradient,
            "stop" => Self::Stop,
            _ => return Err(SvgSanitizeError::new(SvgSanitizeCode::Element, "element")),
        })
    }
    const fn name(self) -> &'static str {
        match self {
            Self::Svg => "svg",
            Self::G => "g",
            Self::Defs => "defs",
            Self::Title => "title",
            Self::Desc => "desc",
            Self::Path => "path",
            Self::Rect => "rect",
            Self::Circle => "circle",
            Self::Ellipse => "ellipse",
            Self::Line => "line",
            Self::Polyline => "polyline",
            Self::Polygon => "polygon",
            Self::ClipPath => "clipPath",
            Self::Mask => "mask",
            Self::LinearGradient => "linearGradient",
            Self::RadialGradient => "radialGradient",
            Self::Stop => "stop",
        }
    }
    const fn reference_kind(self) -> Option<RefKind> {
        match self {
            Self::LinearGradient | Self::RadialGradient => Some(RefKind::Paint),
            Self::ClipPath => Some(RefKind::Clip),
            Self::Mask => Some(RefKind::Mask),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefKind {
    Paint,
    Clip,
    Mask,
}
#[derive(Clone, Debug)]
struct Reference {
    source_node: usize,
    target: String,
    kind: RefKind,
}
#[derive(Clone, Debug)]
enum Child {
    Node(Node),
    Text(String),
}
#[derive(Clone, Debug)]
struct Node {
    kind: ElementKind,
    attrs: BTreeMap<String, String>,
    children: Vec<Child>,
    source_index: usize,
}
#[derive(Default)]
struct Counts {
    elements: usize,
    attrs: usize,
    path_bytes: usize,
    path_commands: usize,
    ids: usize,
    refs: usize,
    text_bytes: usize,
    text_scalars: usize,
}

pub fn sanitize_generated_svg(raw: &[u8]) -> Result<SanitizedSvgArtifact> {
    if raw.len() > MAX_RAW_BYTES {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::RawBytes, "document"));
    }
    let accepted = parse_validate(raw, false, false)?;
    let canonical = canonicalize(accepted)?;
    if canonical.len() > MAX_CANONICAL_BYTES {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::CanonicalBytes,
            "document",
        ));
    }
    let mut hush = BoundedBytes::new(MAX_CANONICAL_BYTES);
    let defense_result = svg_hush::Filter::new().filter(canonical.as_slice(), &mut hush);
    if hush.overflowed {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::CanonicalBytes,
            "svg-hush",
        ));
    }
    defense_result
        .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::DefenseMismatch, "svg-hush"))?;
    verify_defense_output(&canonical, hush.as_slice())?;
    verify::verify_canonical_svg(&canonical)?;
    let verified = canonicalize(
        parse_validate(&canonical, true, false)
            .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::StructuralVerify, "canonical"))?,
    )?;
    if verified != canonical {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::StructuralVerify,
            "canonical",
        ));
    }
    Ok(SanitizedSvgArtifact(canonical))
}

struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl BoundedBytes {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|len| len > self.limit)
        {
            self.overflowed = true;
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "generated SVG defense output exceeds limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn verify_defense_output(canonical: &[u8], hush: &[u8]) -> Result<()> {
    let hush_canonical = canonicalize(
        parse_validate(hush, false, true)
            .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::DefenseMismatch, "svg-hush"))?,
    )
    .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::DefenseMismatch, "svg-hush"))?;
    if hush_canonical != canonical {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::DefenseMismatch,
            "svg-hush",
        ));
    }
    Ok(())
}

fn parse_validate(raw: &[u8], canonical_pass: bool, allow_declaration: bool) -> Result<Node> {
    let mut reader = Reader::from_reader(raw);
    reader.config_mut().check_end_names = true;
    reader.config_mut().allow_unmatched_ends = false;
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut counts = Counts::default();
    let mut saw_root = false;
    loop {
        match reader
            .read_event()
            .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::Xml, "document"))?
        {
            Event::Start(e) => {
                start_node(&e, &mut stack, &mut root, &mut counts, &mut saw_root, false)?
            }
            Event::Empty(e) => {
                start_node(&e, &mut stack, &mut root, &mut counts, &mut saw_root, true)?
            }
            Event::End(_) => {
                let node = stack
                    .pop()
                    .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::Xml, "end"))?;
                attach(node, &mut stack, &mut root)?;
            }
            Event::Text(t) => {
                let text = decode_attribute_bounded(t.as_ref(), 4096).map_err(|error| {
                    if error.code() == SvgSanitizeCode::AttributeBytes {
                        SvgSanitizeError::new(SvgSanitizeCode::TextBytes, "text-node")
                    } else {
                        error
                    }
                })?;
                let text = text.replace("\r\n", "\n").replace('\r', "\n");
                add_text(&text, &mut stack, &mut counts)?;
            }
            Event::GeneralRef(reference) => {
                let decoded = reference
                    .decode()
                    .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::Xml, "entity"))?;
                add_text(&decode_reference(&decoded)?, &mut stack, &mut counts)?;
            }
            Event::Decl(_) if allow_declaration => {}
            Event::CData(_)
            | Event::Comment(_)
            | Event::Decl(_)
            | Event::PI(_)
            | Event::DocType(_) => {
                return Err(SvgSanitizeError::new(SvgSanitizeCode::Xml, "construct"));
            }
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::Xml, "unclosed"));
    }
    let mut root = root.ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::Xml, "root"))?;
    validate_tree(&mut root, &mut counts, canonical_pass)?;
    Ok(root)
}

fn start_node(
    e: &BytesStart<'_>,
    stack: &mut Vec<Node>,
    root: &mut Option<Node>,
    counts: &mut Counts,
    saw_root: &mut bool,
    empty: bool,
) -> Result<()> {
    counts.elements = counts
        .elements
        .checked_add(1)
        .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::ElementCount, "element"))?;
    if counts.elements > MAX_ELEMENTS {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::ElementCount,
            "element",
        ));
    }
    if stack.len() + 1 > MAX_DEPTH {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::Depth, "element"));
    }
    let element_name = e.name();
    let raw_name = std::str::from_utf8(element_name.as_ref())
        .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::Namespace, "element"))?;
    if raw_name.contains(':') {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::Namespace, "element"));
    }
    let kind = ElementKind::parse(raw_name)?;
    if !*saw_root {
        if kind != ElementKind::Svg {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::ParentChild, "root"));
        }
        *saw_root = true;
    } else if stack.is_empty() {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::Xml, "multiple-root"));
    }
    if let Some(parent) = stack.last()
        && !allowed_child(parent.kind, kind)
    {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::ParentChild,
            "element",
        ));
    }
    let mut attrs = BTreeMap::new();
    let mut xmlns = None;
    let mut attr_count = 0usize;
    for a in e.attributes().with_checks(true) {
        let a = a.map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::Attribute, "attribute"))?;
        attr_count += 1;
        if attr_count > MAX_ATTRIBUTES_PER_ELEMENT {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::AttributeCount,
                "attribute",
            ));
        }
        counts.attrs = counts.attrs.checked_add(1).ok_or_else(|| {
            SvgSanitizeError::new(SvgSanitizeCode::TotalAttributeCount, "attribute")
        })?;
        if counts.attrs > MAX_ATTRIBUTES {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::TotalAttributeCount,
                "attribute",
            ));
        }
        let name = std::str::from_utf8(a.key.as_ref())
            .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::Attribute, "attribute"))?;
        let limit = if name == "d" {
            MAX_PATH_ATTRIBUTE_BYTES
        } else {
            MAX_ATTRIBUTE_BYTES
        };
        if matches!(name, "fill" | "stroke" | "clip-path" | "mask")
            && a.value.as_ref().contains(&b'&')
        {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::Attribute,
                "url-escape",
            ));
        }
        let value = decode_attribute_bounded(a.value.as_ref(), limit)?;
        if name == "xmlns" {
            if kind != ElementKind::Svg || !stack.is_empty() || xmlns.is_some() || value != SVG_NS {
                return Err(SvgSanitizeError::new(SvgSanitizeCode::Namespace, "xmlns"));
            }
            xmlns = Some(value);
            continue;
        }
        if name.starts_with("xmlns") || (name.contains(':') && name != "xml:space") {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::Namespace,
                "attribute",
            ));
        }
        if attrs.insert(name.to_owned(), value).is_some() {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::Attribute,
                "duplicate",
            ));
        }
    }
    let node = Node {
        kind,
        attrs,
        children: Vec::new(),
        source_index: counts.elements - 1,
    };
    if empty {
        attach(node, stack, root)?;
    } else {
        stack.push(node);
    }
    Ok(())
}

fn decode_attribute_bounded(raw: &[u8], limit: usize) -> Result<String> {
    let raw = std::str::from_utf8(raw)
        .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::Xml, "attribute"))?;
    let mut output = String::with_capacity(raw.len().min(limit));
    let mut rest = raw;
    while let Some(index) = rest.find('&') {
        push_attribute_fragment(&mut output, &rest[..index], limit)?;
        let after = &rest[index + 1..];
        let end = after
            .find(';')
            .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::Xml, "entity"))?;
        let decoded = decode_reference(&after[..end])?;
        push_attribute_fragment(&mut output, &decoded, limit)?;
        rest = &after[end + 1..];
    }
    push_attribute_fragment(&mut output, rest, limit)?;
    Ok(output)
}

fn push_attribute_fragment(output: &mut String, value: &str, limit: usize) -> Result<()> {
    if output
        .len()
        .checked_add(value.len())
        .is_none_or(|length| length > limit)
    {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::AttributeBytes,
            "attribute",
        ));
    }
    output.push_str(value);
    Ok(())
}

fn decode_reference(reference: &str) -> Result<String> {
    let scalar = if let Some(hex) = reference.strip_prefix("#x") {
        (!hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| u32::from_str_radix(hex, 16).ok().and_then(char::from_u32))
            .flatten()
    } else if let Some(decimal) = reference.strip_prefix('#') {
        (!decimal.is_empty() && decimal.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| decimal.parse::<u32>().ok().and_then(char::from_u32))
            .flatten()
    } else {
        match reference {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => None,
        }
    };
    scalar
        .map(|value| value.to_string())
        .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::Xml, "entity"))
}

fn attach(node: Node, stack: &mut [Node], root: &mut Option<Node>) -> Result<()> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(Child::Node(node));
    } else if root.replace(node).is_some() {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::Xml, "multiple-root"));
    }
    Ok(())
}
fn add_text(text: &str, stack: &mut [Node], counts: &mut Counts) -> Result<()> {
    let Some(parent) = stack.last_mut() else {
        if text.bytes().all(is_xml_space) {
            return Ok(());
        }
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::TextPlacement,
            "root",
        ));
    };
    if !matches!(parent.kind, ElementKind::Title | ElementKind::Desc) {
        if text.bytes().all(is_xml_space) {
            return Ok(());
        }
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::TextPlacement,
            "text",
        ));
    }
    validate_text(text)?;
    let scalars = text.chars().count();
    let prior_bytes = parent
        .children
        .iter()
        .filter_map(|child| match child {
            Child::Text(text) => Some(text.len()),
            _ => None,
        })
        .try_fold(0usize, usize::checked_add)
        .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::TextBytes, "text-node"))?;
    let prior_scalars = parent
        .children
        .iter()
        .filter_map(|child| match child {
            Child::Text(text) => Some(text.chars().count()),
            _ => None,
        })
        .try_fold(0usize, usize::checked_add)
        .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::TextScalars, "text-node"))?;
    if prior_bytes
        .checked_add(text.len())
        .is_none_or(|bytes| bytes > 4096)
    {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::TextBytes,
            "text-node",
        ));
    }
    if prior_scalars
        .checked_add(scalars)
        .is_none_or(|scalars| scalars > 1024)
    {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::TextScalars,
            "text-node",
        ));
    }
    counts.text_bytes = counts
        .text_bytes
        .checked_add(text.len())
        .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::TextBytes, "text"))?;
    counts.text_scalars = counts
        .text_scalars
        .checked_add(scalars)
        .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::TextScalars, "text"))?;
    if counts.text_bytes > MAX_TEXT_BYTES {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::TextBytes, "text"));
    }
    if counts.text_scalars > MAX_TEXT_SCALARS {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::TextScalars, "text"));
    }
    parent.children.push(Child::Text(text.to_owned()));
    Ok(())
}
fn validate_text(s: &str) -> Result<()> {
    for c in s.chars() {
        let n = c as u32;
        if (n < 0x20 && !matches!(c, '\t' | '\n' | '\r'))
            || (0x7f..=0x9f).contains(&n)
            || (0x202a..=0x202e).contains(&n)
            || (0x2066..=0x2069).contains(&n)
            || (0xfdd0..=0xfdef).contains(&n)
            || (n & 0xffff == 0xfffe)
            || (n & 0xffff == 0xffff)
        {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::TextCharacter,
                "text",
            ));
        }
    }
    Ok(())
}
const fn is_xml_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn allowed_child(p: ElementKind, c: ElementKind) -> bool {
    use ElementKind::*;
    match p {
        Svg => matches!(
            c,
            Title | Desc | Defs | G | Path | Rect | Circle | Ellipse | Line | Polyline | Polygon
        ),
        G | ClipPath | Mask => matches!(
            c,
            Title | Desc | G | Path | Rect | Circle | Ellipse | Line | Polyline | Polygon
        ),
        Defs => matches!(c, ClipPath | Mask | LinearGradient | RadialGradient),
        LinearGradient | RadialGradient => c == Stop,
        _ => false,
    }
}

fn validate_tree(root: &mut Node, counts: &mut Counts, canonical_pass: bool) -> Result<()> {
    let mut ids = HashMap::<String, (ElementKind, usize)>::new();
    let mut refs = Vec::new();
    let mut defs_seen = false;
    validate_node(
        root,
        None,
        None,
        false,
        &mut ids,
        &mut refs,
        counts,
        &mut defs_seen,
    )?;
    for r in &refs {
        let Some((kind, _)) = ids.get(&r.target) else {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::MissingId,
                "reference",
            ));
        };
        if kind.reference_kind() != Some(r.kind) {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::ReferenceTarget,
                "reference",
            ));
        }
    }
    detect_cycles(&refs, &ids)?;
    if canonical_pass {
        for id in ids.keys() {
            if !is_canonical_id(id) {
                return Err(SvgSanitizeError::new(
                    SvgSanitizeCode::StructuralVerify,
                    "id",
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_node(
    node: &mut Node,
    parent: Option<ElementKind>,
    definition_owner: Option<usize>,
    object_bbox: bool,
    ids: &mut HashMap<String, (ElementKind, usize)>,
    refs: &mut Vec<Reference>,
    counts: &mut Counts,
    defs_seen: &mut bool,
) -> Result<()> {
    let definition_owner =
        if parent == Some(ElementKind::Defs) && node.kind.reference_kind().is_some() {
            Some(node.source_index)
        } else {
            definition_owner
        };
    let object_bbox = object_bbox
        || match node.kind {
            ElementKind::ClipPath => node
                .attrs
                .get("clipPathUnits")
                .is_some_and(|v| v == "objectBoundingBox"),
            ElementKind::Mask => {
                node.attrs
                    .get("maskUnits")
                    .is_some_and(|v| v == "objectBoundingBox")
                    || node
                        .attrs
                        .get("maskContentUnits")
                        .is_some_and(|v| v == "objectBoundingBox")
            }
            ElementKind::LinearGradient | ElementKind::RadialGradient => node
                .attrs
                .get("gradientUnits")
                .is_some_and(|v| v == "objectBoundingBox"),
            _ => false,
        };
    if node.kind == ElementKind::Defs {
        if *defs_seen {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::ParentChild, "defs"));
        }
        *defs_seen = true;
    }
    if matches!(
        node.kind,
        ElementKind::ClipPath
            | ElementKind::Mask
            | ElementKind::LinearGradient
            | ElementKind::RadialGradient
    ) && parent != Some(ElementKind::Defs)
    {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::ParentChild,
            "definition",
        ));
    }
    let title_count = node
        .children
        .iter()
        .filter(|c| matches!(c,Child::Node(n) if n.kind==ElementKind::Title))
        .count();
    let desc_count = node
        .children
        .iter()
        .filter(|c| matches!(c,Child::Node(n) if n.kind==ElementKind::Desc))
        .count();
    if title_count > 1 || desc_count > 1 {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::ParentChild,
            "text-cardinality",
        ));
    }
    if matches!(
        node.kind,
        ElementKind::LinearGradient | ElementKind::RadialGradient
    ) {
        let n = node.children.len();
        if !(1..=256).contains(&n) {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::ParentChild,
                "gradient-stops",
            ));
        }
    }
    let required_id = matches!(
        node.kind,
        ElementKind::ClipPath
            | ElementKind::Mask
            | ElementKind::LinearGradient
            | ElementKind::RadialGradient
    );
    if required_id && !node.attrs.contains_key("id") {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::MissingId,
            "definition",
        ));
    }
    let keys = node.attrs.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        if !allowed_attr(node.kind, &key) {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::Attribute,
                "attribute",
            ));
        }
        let raw = node.attrs[&key].clone();
        let value = validate_attr(
            node.kind,
            &key,
            &raw,
            refs,
            definition_owner.unwrap_or(node.source_index),
            counts,
        )?;
        if object_bbox && is_bbox_numeric_attribute(&key) && !value.ends_with('%') {
            let numeric = parse_fixed(&value)?;
            if !(0..=1_000_000).contains(&numeric) {
                return Err(SvgSanitizeError::new(
                    SvgSanitizeCode::Number,
                    "objectBoundingBox",
                ));
            }
        }
        node.attrs.insert(key.clone(), value);
        if key == "id" {
            if !valid_id(&raw) {
                return Err(SvgSanitizeError::new(SvgSanitizeCode::Attribute, "id"));
            }
            counts.ids = counts
                .ids
                .checked_add(1)
                .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::IdCount, "id"))?;
            if counts.ids > MAX_IDS {
                return Err(SvgSanitizeError::new(SvgSanitizeCode::IdCount, "id"));
            }
            if ids.insert(raw, (node.kind, node.source_index)).is_some() {
                return Err(SvgSanitizeError::new(SvgSanitizeCode::DuplicateId, "id"));
            }
        }
    }
    if node.kind == ElementKind::RadialGradient
        && let (Some(radius), Some(focal)) = (node.attrs.get("r"), node.attrs.get("fr"))
    {
        let radius_percent = radius.ends_with('%');
        if radius_percent != focal.ends_with('%') {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::Number,
                "radial-unit-class",
            ));
        }
        let r = parse_fixed(radius.strip_suffix('%').unwrap_or(radius))?;
        let fr = parse_fixed(focal.strip_suffix('%').unwrap_or(focal))?;
        if fr > r {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::Number, "radial-fr"));
        }
    }
    for child in &mut node.children {
        if let Child::Node(child) = child {
            validate_node(
                child,
                Some(node.kind),
                definition_owner,
                object_bbox,
                ids,
                refs,
                counts,
                defs_seen,
            )?;
        }
    }
    Ok(())
}

fn is_bbox_numeric_attribute(attribute: &str) -> bool {
    matches!(
        attribute,
        "x" | "y"
            | "cx"
            | "cy"
            | "x1"
            | "y1"
            | "x2"
            | "y2"
            | "fx"
            | "fy"
            | "width"
            | "height"
            | "rx"
            | "ry"
            | "r"
            | "fr"
            | "pathLength"
            | "stroke-width"
            | "stroke-dashoffset"
    )
}

const COMMON: &[&str] = &[
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
fn allowed_attr(k: ElementKind, a: &str) -> bool {
    use ElementKind::*;
    let own = match k {
        Svg => &["id", "width", "height", "viewBox", "preserveAspectRatio"][..],
        G => &["id", "transform"][..],
        Defs => &[][..],
        Title | Desc => &["xml:space"][..],
        Path => &["id", "d", "pathLength", "transform"][..],
        Rect => &[
            "id",
            "x",
            "y",
            "width",
            "height",
            "rx",
            "ry",
            "pathLength",
            "transform",
        ][..],
        Circle => &["id", "cx", "cy", "r", "pathLength", "transform"][..],
        Ellipse => &["id", "cx", "cy", "rx", "ry", "pathLength", "transform"][..],
        Line => &["id", "x1", "y1", "x2", "y2", "pathLength", "transform"][..],
        Polyline | Polygon => &["id", "points", "pathLength", "transform"][..],
        ClipPath => &["id", "clipPathUnits", "transform"][..],
        Mask => &[
            "id",
            "x",
            "y",
            "width",
            "height",
            "maskUnits",
            "maskContentUnits",
            "transform",
        ][..],
        LinearGradient => &[
            "id",
            "x1",
            "y1",
            "x2",
            "y2",
            "gradientUnits",
            "spreadMethod",
            "gradientTransform",
        ][..],
        RadialGradient => &[
            "id",
            "cx",
            "cy",
            "r",
            "fx",
            "fy",
            "fr",
            "gradientUnits",
            "spreadMethod",
            "gradientTransform",
        ][..],
        Stop => &["offset", "stop-color", "stop-opacity"][..],
    };
    own.contains(&a)
        || (matches!(
            k,
            G | Path | Rect | Circle | Ellipse | Line | Polyline | Polygon
        ) && COMMON.contains(&a))
}

fn validate_attr(
    k: ElementKind,
    a: &str,
    v: &str,
    refs: &mut Vec<Reference>,
    source: usize,
    counts: &mut Counts,
) -> Result<String> {
    if a == "id" {
        return Ok(v.to_owned());
    }
    if matches!(a, "transform" | "gradientTransform") {
        return canonical_transform(v);
    }
    if a == "d" {
        counts.path_bytes = counts
            .path_bytes
            .checked_add(v.len())
            .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::PathBytes, "path"))?;
        if counts.path_bytes > MAX_PATH_BYTES {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::PathBytes, "path"));
        }
        let (out, n) = canonical_path(v)?;
        counts.path_commands = counts
            .path_commands
            .checked_add(n)
            .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::PathCommands, "path"))?;
        if counts.path_commands > MAX_PATH_COMMANDS {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::PathCommands, "path"));
        }
        return Ok(out);
    }
    if a == "points" {
        let min = if k == ElementKind::Polygon { 6 } else { 4 };
        return canonical_list(v, min, 131_072, true);
    }
    if a == "stroke-dasharray" {
        if v == "none" {
            return Ok(v.into());
        }
        let out = canonical_list(v, 1, 64, false)?;
        let members = out
            .split(' ')
            .map(parse_fixed)
            .collect::<Result<Vec<_>>>()?;
        if members.iter().any(|value| *value < 0) || members.iter().all(|value| *value == 0) {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::Number, "dasharray"));
        }
        return Ok(out);
    }
    if matches!(a, "fill" | "stroke" | "clip-path" | "mask") {
        if let Some(id) = parse_url(v) {
            let kind = if matches!(a, "fill" | "stroke") {
                RefKind::Paint
            } else if a == "clip-path" {
                RefKind::Clip
            } else {
                RefKind::Mask
            };
            counts.refs = counts.refs.checked_add(1).ok_or_else(|| {
                SvgSanitizeError::new(SvgSanitizeCode::ReferenceCount, "reference")
            })?;
            if counts.refs > MAX_REFERENCES {
                return Err(SvgSanitizeError::new(
                    SvgSanitizeCode::ReferenceCount,
                    "reference",
                ));
            }
            refs.push(Reference {
                source_node: source,
                target: id.to_owned(),
                kind,
            });
            return Ok(v.to_owned());
        }
        if a == "clip-path" || a == "mask" {
            return keyword(v, &["none"]);
        }
        return color(v, true);
    }
    if matches!(a, "color" | "stop-color") {
        return color(v, false);
    }
    if matches!(
        a,
        "fill-opacity" | "stroke-opacity" | "opacity" | "stop-opacity"
    ) {
        return number_range(v, 0, 1_000_000, false, "opacity");
    }
    if a == "stroke-miterlimit" {
        return number_range(v, 1_000_000, 1_000_000_000, false, "miter");
    }
    if a == "offset" {
        return percent_or(v, 0, 100_000_000, 0, 1_000_000, false);
    }
    if a == "viewBox" {
        let out = canonical_list(v, 4, 4, false)?;
        let n = out
            .split(' ')
            .map(parse_fixed)
            .collect::<Result<Vec<_>>>()?;
        if n[2] <= 0 || n[3] <= 0 {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::Number, "viewBox"));
        }
        return Ok(out);
    }
    if matches!(a, "width" | "height") && k == ElementKind::Svg {
        let raw = v.strip_suffix("px").unwrap_or(v);
        let out = number_range(raw, 1, 1_000_000_000_000, false, "length")?;
        return Ok(if v.ends_with("px") {
            format!("{out}px")
        } else {
            out
        });
    }
    if matches!(a, "preserveAspectRatio") {
        return preserve_aspect(v);
    }
    if matches!(
        a,
        "clipPathUnits" | "maskUnits" | "maskContentUnits" | "gradientUnits"
    ) {
        return keyword(v, &["userSpaceOnUse", "objectBoundingBox"]);
    }
    if a == "spreadMethod" {
        return keyword(v, &["pad", "reflect", "repeat"]);
    }
    if a == "stroke-linecap" {
        return keyword(v, &["butt", "round", "square"]);
    }
    if a == "stroke-linejoin" {
        return keyword(v, &["miter", "round", "bevel"]);
    }
    if a == "display" {
        return keyword(v, &["inline", "none"]);
    }
    if a == "visibility" {
        return keyword(v, &["visible", "hidden", "collapse"]);
    }
    if a == "xml:space" {
        return keyword(v, &["default", "preserve"]);
    }
    let positive = matches!(a, "pathLength")
        || matches!(
            (k, a),
            (ElementKind::Rect, "width" | "height") | (ElementKind::Circle, "r")
        );
    if matches!(a, "x" | "y") && k == ElementKind::Mask
        || matches!(a, "x1" | "y1" | "x2" | "y2" | "cx" | "cy" | "fx" | "fy")
            && matches!(k, ElementKind::LinearGradient | ElementKind::RadialGradient)
    {
        return percent_or(
            v,
            -1_000_000_000,
            1_000_000_000,
            -1_000_000_000_000,
            1_000_000_000_000,
            false,
        );
    }
    if matches!(a, "width" | "height") && k == ElementKind::Mask {
        return percent_or(v, 1, 1_000_000_000, 1, 1_000_000_000_000, true);
    }
    if matches!(a, "r" | "fr") && k == ElementKind::RadialGradient {
        let positive = a == "r";
        return percent_or(
            v,
            if positive { 1 } else { 0 },
            1_000_000_000,
            if positive { 1 } else { 0 },
            1_000_000_000_000,
            positive,
        );
    }
    let coordinate = matches!(
        a,
        "x" | "y" | "cx" | "cy" | "x1" | "y1" | "x2" | "y2" | "fx" | "fy"
    );
    number_range(
        v,
        if coordinate {
            -1_000_000_000_000
        } else if positive {
            1
        } else {
            0
        },
        1_000_000_000_000,
        false,
        "number",
    )
}

fn valid_id(s: &str) -> bool {
    let mut b = s.bytes();
    matches!(b.next(),Some(c)if c.is_ascii_alphabetic()||c==b'_')
        && s.len() <= 64
        && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}
fn is_canonical_id(s: &str) -> bool {
    s.len() == 10 && s.starts_with("svg_") && s[4..].bytes().all(|b| b.is_ascii_digit())
}
fn parse_url(v: &str) -> Option<&str> {
    let id = v.strip_prefix("url(#")?.strip_suffix(')')?;
    valid_id(id).then_some(id)
}
fn keyword(v: &str, set: &[&str]) -> Result<String> {
    if set.contains(&v) {
        Ok(v.into())
    } else {
        Err(SvgSanitizeError::new(SvgSanitizeCode::Attribute, "keyword"))
    }
}
fn preserve_aspect(v: &str) -> Result<String> {
    if v == "none" {
        return Ok(v.into());
    }
    let p = v.split(' ').collect::<Vec<_>>();
    if p.len() > 2
        || p.is_empty()
        || !matches!(
            p[0],
            "xMinYMin"
                | "xMinYMid"
                | "xMinYMax"
                | "xMidYMin"
                | "xMidYMid"
                | "xMidYMax"
                | "xMaxYMin"
                | "xMaxYMid"
                | "xMaxYMax"
        )
        || p.get(1).is_some_and(|x| !matches!(*x, "meet" | "slice"))
    {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::Attribute,
            "preserveAspectRatio",
        ));
    }
    Ok(p.join(" "))
}
fn parse_fixed(v: &str) -> Result<i64> {
    if v.is_empty() || v.len() > 32 || v.starts_with('+') {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::Number, "number"));
    }
    let neg = v.starts_with('-');
    let body = v.strip_prefix('-').unwrap_or(v);
    let mut parts = body.split('.');
    let int = parts.next().unwrap();
    let frac = parts.next();
    if parts.next().is_some()
        || int.is_empty()
        || (int.len() > 1 && int.starts_with('0'))
        || !int.bytes().all(|b| b.is_ascii_digit())
        || frac
            .is_some_and(|f| f.is_empty() || f.len() > 6 || !f.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::Number, "number"));
    }
    let whole = int
        .parse::<i64>()
        .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::Number, "number"))?;
    let mut scaled = whole
        .checked_mul(1_000_000)
        .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::Number, "number"))?;
    if let Some(f) = frac {
        let n = f
            .parse::<i64>()
            .map_err(|_| SvgSanitizeError::new(SvgSanitizeCode::Number, "number"))?;
        scaled = scaled
            .checked_add(n * 10_i64.pow(6 - f.len() as u32))
            .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::Number, "number"))?;
    }
    Ok(if neg { -scaled } else { scaled })
}
fn fixed(v: i64) -> String {
    if v == 0 {
        return "0".into();
    }
    let neg = v < 0;
    let n = v.unsigned_abs();
    let whole = n / 1_000_000;
    let frac = n % 1_000_000;
    let mut s = if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{frac:06}")
            .trim_end_matches('0')
            .to_owned()
    };
    if neg {
        s.insert(0, '-')
    }
    s
}
fn number_range(v: &str, min: i64, max: i64, _percent: bool, kind: &'static str) -> Result<String> {
    let n = parse_fixed(v)?;
    if n < min || n > max {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::Number, kind));
    }
    Ok(fixed(n))
}
fn percent_or(
    v: &str,
    pmin: i64,
    pmax: i64,
    nmin: i64,
    nmax: i64,
    positive: bool,
) -> Result<String> {
    if let Some(p) = v.strip_suffix('%') {
        let n = parse_fixed(p)?;
        if n < pmin || n > pmax || (positive && n == 0) {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::Number, "percent"));
        }
        return Ok(format!("{}%", fixed(n)));
    }
    number_range(v, nmin, nmax, false, "number")
}
fn split_numbers(v: &str) -> Result<Vec<&str>> {
    if v.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for p in v
        .split(|c: char| c == ',' || (c.is_ascii() && is_xml_space(c as u8)))
        .filter(|s| !s.is_empty())
    {
        if !p.is_ascii() {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::Number, "list"));
        }
        out.push(p)
    }
    Ok(out)
}
fn canonical_list(v: &str, min: usize, max: usize, even: bool) -> Result<String> {
    let p = split_numbers(v)?;
    if p.len() < min || p.len() > max || (even && p.len() % 2 != 0) {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::Points, "list"));
    }
    p.into_iter()
        .map(|n| number_range(n, -1_000_000_000_000, 1_000_000_000_000, false, "list"))
        .collect::<Result<Vec<_>>>()
        .map(|x| x.join(" "))
}

fn color(v: &str, allow_none: bool) -> Result<String> {
    if v == "currentColor" || (allow_none && v == "none") {
        return Ok(v.into());
    }
    if v == "transparent" {
        return Ok("#00000000".into());
    }
    let named = match v {
        "aqua" => "#00ffff",
        "black" => "#000000",
        "blue" => "#0000ff",
        "fuchsia" => "#ff00ff",
        "gray" => "#808080",
        "green" => "#008000",
        "lime" => "#00ff00",
        "maroon" => "#800000",
        "navy" => "#000080",
        "olive" => "#808000",
        "purple" => "#800080",
        "red" => "#ff0000",
        "silver" => "#c0c0c0",
        "teal" => "#008080",
        "white" => "#ffffff",
        "yellow" => "#ffff00",
        _ => "",
    };
    if !named.is_empty() {
        return Ok(named.into());
    }
    if let Some(h) = v.strip_prefix('#')
        && matches!(h.len(), 3 | 4 | 6 | 8)
        && h.bytes().all(|b| b.is_ascii_hexdigit())
    {
        let lower = h.to_ascii_lowercase();
        return Ok(if h.len() < 6 {
            format!(
                "#{}",
                lower.chars().flat_map(|c| [c, c]).collect::<String>()
            )
        } else {
            format!("#{lower}")
        });
    }
    Err(SvgSanitizeError::new(SvgSanitizeCode::Attribute, "color"))
}

fn canonical_transform(v: &str) -> Result<String> {
    if v.is_empty() {
        return Ok(String::new());
    }
    let mut rest = v.trim();
    let mut out = Vec::new();
    let mut funcs = 0;
    let mut args_total = 0;
    while !rest.is_empty() {
        let open = rest
            .find('(')
            .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::Transform, "transform"))?;
        let name = &rest[..open];
        let close = rest[open + 1..]
            .find(')')
            .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::Transform, "transform"))?
            + open
            + 1;
        let args = split_numbers(&rest[open + 1..close])?;
        let range = match name {
            "matrix" => (6, 6),
            "translate" | "scale" => (1, 2),
            "rotate" => (1, 3),
            "skewX" | "skewY" => (1, 1),
            _ => (usize::MAX, 0),
        };
        if args.len() < range.0 || args.len() > range.1 || (name == "rotate" && args.len() == 2) {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::Transform,
                "transform",
            ));
        }
        funcs += 1;
        args_total += args.len();
        if funcs > 128 || args_total > 768 {
            return Err(SvgSanitizeError::new(
                SvgSanitizeCode::Transform,
                "transform",
            ));
        }
        let vals = args
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                let angle = matches!(name, "skewX" | "skewY") || (name == "rotate" && index == 0);
                let bound = if angle {
                    360_000_000_000
                } else {
                    1_000_000_000_000
                };
                number_range(value, -bound, bound, false, "transform")
            })
            .collect::<Result<Vec<_>>>()?;
        out.push(format!("{name}({})", vals.join(" ")));
        rest = rest[close + 1..].trim_start_matches(|character: char| {
            character == ',' || (character.is_ascii() && is_xml_space(character as u8))
        });
    }
    Ok(out.join(" "))
}

// Strict tokenization plus canonical absolute expansion. Smooth commands are
// expanded using reflected controls; horizontal/vertical commands become L.
fn canonical_path(v: &str) -> Result<(String, usize)> {
    let toks = path_tokens(v)?;
    if toks.is_empty() {
        return Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "path"));
    }
    let mut i = 0;
    let mut cmd = ' ';
    let mut first = true;
    let mut cur = (0i64, 0i64);
    let mut start = cur;
    let mut cubic_ctrl = None;
    let mut quadratic_ctrl = None;
    let mut out = Vec::new();
    let mut output_bytes = 0usize;
    let mut count = 0;
    let mut subpath_drawn = false;
    while i < toks.len() {
        let mut explicit = false;
        if toks[i].len() == 1 && toks[i].as_bytes()[0].is_ascii_alphabetic() {
            cmd = toks[i].chars().next().unwrap();
            i += 1;
            explicit = true;
        } else if cmd == ' ' {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "path"));
        }
        if first && !matches!(cmd, 'M' | 'm') {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "path"));
        }
        if matches!(cmd, 'Z' | 'z') {
            if !subpath_drawn {
                return Err(SvgSanitizeError::new(
                    SvgSanitizeCode::Path,
                    "empty-subpath",
                ));
            }
            push_path_output(&mut out, &mut output_bytes, "Z".into())?;
            cur = start;
            cmd = ' ';
            cubic_ctrl = None;
            quadratic_ctrl = None;
            count += 1;
            if count > MAX_PATH_COMMANDS {
                return Err(SvgSanitizeError::new(SvgSanitizeCode::PathCommands, "path"));
            }
            first = false;
            continue;
        }
        let argc = match cmd.to_ascii_uppercase() {
            'M' | 'L' | 'T' => 2,
            'H' | 'V' => 1,
            'C' => 6,
            'S' | 'Q' => 4,
            'A' => 7,
            _ => return Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "path")),
        };
        if i + argc > toks.len()
            || toks[i..i + argc]
                .iter()
                .any(|t| t.len() == 1 && t.as_bytes()[0].is_ascii_alphabetic())
        {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "path"));
        }
        let n = toks[i..i + argc]
            .iter()
            .map(|x| parse_fixed(x))
            .collect::<Result<Vec<_>>>()?;
        i += argc;
        let rel = cmd.is_ascii_lowercase();
        let add = |p: i64, b: i64| {
            if rel {
                p.checked_add(b)
                    .filter(|n| n.abs() <= 1_000_000_000_000)
                    .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::Path, "coordinate"))
            } else if p.abs() <= 1_000_000_000_000 {
                Ok(p)
            } else {
                Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "coordinate"))
            }
        };
        match cmd.to_ascii_uppercase() {
            'M' | 'L' => {
                let p = (add(n[0], cur.0)?, add(n[1], cur.1)?);
                let moveto = matches!(cmd, 'M' | 'm') && explicit;
                if moveto && !first && !subpath_drawn {
                    return Err(SvgSanitizeError::new(
                        SvgSanitizeCode::Path,
                        "empty-subpath",
                    ));
                }
                push_path_output(
                    &mut out,
                    &mut output_bytes,
                    format!(
                        "{} {} {}",
                        if moveto { "M" } else { "L" },
                        fixed(p.0),
                        fixed(p.1)
                    ),
                )?;
                cur = p;
                if moveto {
                    start = p;
                    cmd = if rel { 'l' } else { 'L' };
                    subpath_drawn = false;
                } else {
                    subpath_drawn = true;
                }
                cubic_ctrl = None;
                quadratic_ctrl = None;
            }
            'H' => {
                cur.0 = add(n[0], cur.0)?;
                push_path_output(
                    &mut out,
                    &mut output_bytes,
                    format!("L {} {}", fixed(cur.0), fixed(cur.1)),
                )?;
                cubic_ctrl = None;
                quadratic_ctrl = None;
                subpath_drawn = true;
            }
            'V' => {
                cur.1 = add(n[0], cur.1)?;
                push_path_output(
                    &mut out,
                    &mut output_bytes,
                    format!("L {} {}", fixed(cur.0), fixed(cur.1)),
                )?;
                cubic_ctrl = None;
                quadratic_ctrl = None;
                subpath_drawn = true;
            }
            'C' => {
                let c1 = (add(n[0], cur.0)?, add(n[1], cur.1)?);
                let c2 = (add(n[2], cur.0)?, add(n[3], cur.1)?);
                let p = (add(n[4], cur.0)?, add(n[5], cur.1)?);
                push_path_output(
                    &mut out,
                    &mut output_bytes,
                    format!(
                        "C {} {} {} {} {} {}",
                        fixed(c1.0),
                        fixed(c1.1),
                        fixed(c2.0),
                        fixed(c2.1),
                        fixed(p.0),
                        fixed(p.1)
                    ),
                )?;
                cur = p;
                cubic_ctrl = Some(c2);
                quadratic_ctrl = None;
                subpath_drawn = true;
            }
            'S' => {
                let c1 = cubic_ctrl
                    .map(|c| reflect(cur, c))
                    .transpose()?
                    .unwrap_or(cur);
                let c2 = (add(n[0], cur.0)?, add(n[1], cur.1)?);
                let p = (add(n[2], cur.0)?, add(n[3], cur.1)?);
                push_path_output(
                    &mut out,
                    &mut output_bytes,
                    format!(
                        "C {} {} {} {} {} {}",
                        fixed(c1.0),
                        fixed(c1.1),
                        fixed(c2.0),
                        fixed(c2.1),
                        fixed(p.0),
                        fixed(p.1)
                    ),
                )?;
                cur = p;
                cubic_ctrl = Some(c2);
                quadratic_ctrl = None;
                subpath_drawn = true;
            }
            'Q' => {
                let c = (add(n[0], cur.0)?, add(n[1], cur.1)?);
                let p = (add(n[2], cur.0)?, add(n[3], cur.1)?);
                push_path_output(
                    &mut out,
                    &mut output_bytes,
                    format!(
                        "Q {} {} {} {}",
                        fixed(c.0),
                        fixed(c.1),
                        fixed(p.0),
                        fixed(p.1)
                    ),
                )?;
                cur = p;
                quadratic_ctrl = Some(c);
                cubic_ctrl = None;
                subpath_drawn = true;
            }
            'T' => {
                let c = quadratic_ctrl
                    .map(|x| reflect(cur, x))
                    .transpose()?
                    .unwrap_or(cur);
                let p = (add(n[0], cur.0)?, add(n[1], cur.1)?);
                push_path_output(
                    &mut out,
                    &mut output_bytes,
                    format!(
                        "Q {} {} {} {}",
                        fixed(c.0),
                        fixed(c.1),
                        fixed(p.0),
                        fixed(p.1)
                    ),
                )?;
                cur = p;
                quadratic_ctrl = Some(c);
                cubic_ctrl = None;
                subpath_drawn = true;
            }
            'A' => {
                if n[0] < 0
                    || n[1] < 0
                    || n[0] > 1_000_000_000_000
                    || n[1] > 1_000_000_000_000
                    || n[2].abs() > 360_000_000_000
                    || !matches!(toks[i - 4].as_str(), "0" | "1")
                    || !matches!(toks[i - 3].as_str(), "0" | "1")
                {
                    return Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "arc"));
                }
                let p = (add(n[5], cur.0)?, add(n[6], cur.1)?);
                push_path_output(
                    &mut out,
                    &mut output_bytes,
                    format!(
                        "A {} {} {} {} {} {} {}",
                        fixed(n[0]),
                        fixed(n[1]),
                        fixed(n[2]),
                        toks[i - 4],
                        toks[i - 3],
                        fixed(p.0),
                        fixed(p.1)
                    ),
                )?;
                cur = p;
                cubic_ctrl = None;
                quadratic_ctrl = None;
                subpath_drawn = true;
            }
            _ => unreachable!(),
        }
        count += 1;
        first = false;
        if count > MAX_PATH_COMMANDS {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::PathCommands, "path"));
        }
    }
    if !subpath_drawn && !out.last().is_some_and(|command| command == "Z") {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::Path,
            "empty-subpath",
        ));
    }
    Ok((out.join(" "), count))
}

fn push_path_output(out: &mut Vec<String>, bytes: &mut usize, value: String) -> Result<()> {
    *bytes = bytes
        .checked_add(value.len())
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::CanonicalBytes, "path"))?;
    if *bytes > MAX_CANONICAL_BYTES {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::CanonicalBytes,
            "path",
        ));
    }
    out.push(value);
    Ok(())
}

fn reflect(current: (i64, i64), control: (i64, i64)) -> Result<(i64, i64)> {
    let x = current
        .0
        .checked_mul(2)
        .and_then(|v| v.checked_sub(control.0));
    let y = current
        .1
        .checked_mul(2)
        .and_then(|v| v.checked_sub(control.1));
    match (x, y) {
        (Some(x), Some(y)) if x.abs() <= 1_000_000_000_000 && y.abs() <= 1_000_000_000_000 => {
            Ok((x, y))
        }
        _ => Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "reflection")),
    }
}
fn path_tokens(v: &str) -> Result<Vec<String>> {
    let b = v.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        if is_xml_space(b[i]) || b[i] == b',' {
            i += 1;
            continue;
        }
        if b[i].is_ascii_alphabetic() {
            if !b"MmLlHhVvCcSsQqTtAaZz".contains(&b[i]) {
                return Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "command"));
            }
            out.push((b[i] as char).to_string());
            i += 1;
            continue;
        }
        let start = i;
        if b[i] == b'-' {
            i += 1
        }
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1
        }
        if i < b.len() && b[i] == b'.' {
            i += 1;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1
            }
        }
        if start == i {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "token"));
        }
        out.push(v[start..i].to_owned());
        if i < b.len() && !is_xml_space(b[i]) && b[i] != b',' && !b[i].is_ascii_alphabetic() {
            return Err(SvgSanitizeError::new(SvgSanitizeCode::Path, "separator"));
        }
    }
    Ok(out)
}

fn detect_cycles(refs: &[Reference], ids: &HashMap<String, (ElementKind, usize)>) -> Result<()> {
    let mut graph = HashMap::<usize, Vec<usize>>::new();
    for r in refs {
        if let Some((_, target)) = ids.get(&r.target) {
            graph.entry(r.source_node).or_default().push(*target)
        }
    }
    let mut done = HashSet::new();
    for &root in graph.keys() {
        if done.contains(&root) {
            continue;
        }
        let mut active = HashSet::new();
        let mut stack = vec![(root, 0usize)];
        while let Some((node, edge_index)) = stack.last_mut() {
            if *edge_index == 0 && !active.insert(*node) {
                return Err(SvgSanitizeError::new(
                    SvgSanitizeCode::ReferenceCycle,
                    "reference",
                ));
            }
            let edges = graph.get(node).map(Vec::as_slice).unwrap_or_default();
            if *edge_index < edges.len() {
                let next = edges[*edge_index];
                *edge_index += 1;
                if active.contains(&next) {
                    return Err(SvgSanitizeError::new(
                        SvgSanitizeCode::ReferenceCycle,
                        "reference",
                    ));
                }
                if !done.contains(&next) {
                    stack.push((next, 0));
                }
            } else {
                let finished = *node;
                stack.pop();
                active.remove(&finished);
                done.insert(finished);
            }
        }
    }
    Ok(())
}

fn canonicalize(mut root: Node) -> Result<Vec<u8>> {
    let mut ids = Vec::new();
    collect_ids(&root, &mut ids);
    let map = ids
        .into_iter()
        .enumerate()
        .map(|(i, id)| (id, format!("svg_{:06}", i + 1)))
        .collect::<HashMap<_, _>>();
    rewrite(&mut root, &map)?;
    let mut out = String::new();
    serialize(&root, &mut out, true)?;
    Ok(out.into_bytes())
}
fn collect_ids(n: &Node, out: &mut Vec<String>) {
    if let Some(id) = n.attrs.get("id") {
        out.push(id.clone())
    }
    for c in &n.children {
        if let Child::Node(n) = c {
            collect_ids(n, out)
        }
    }
}
fn rewrite(n: &mut Node, map: &HashMap<String, String>) -> Result<()> {
    for (a, v) in &mut n.attrs {
        if a == "id" {
            *v = map
                .get(v)
                .ok_or_else(|| SvgSanitizeError::new(SvgSanitizeCode::MissingId, "id"))?
                .clone()
        } else if let Some(id) = parse_url(v) {
            *v = format!(
                "url(#{})",
                map.get(id).ok_or_else(|| SvgSanitizeError::new(
                    SvgSanitizeCode::MissingId,
                    "reference"
                ))?
            )
        }
    }
    for c in &mut n.children {
        if let Child::Node(n) = c {
            rewrite(n, map)?
        }
    }
    Ok(())
}
fn serialize(n: &Node, out: &mut String, root: bool) -> Result<()> {
    push_canonical(out, "<")?;
    push_canonical(out, n.kind.name())?;
    if root {
        push_canonical(out, " xmlns=\"")?;
        push_canonical(out, SVG_NS)?;
        push_canonical(out, "\"")?;
    }
    for (a, v) in &n.attrs {
        push_canonical(out, " ")?;
        push_canonical(out, a)?;
        push_canonical(out, "=\"")?;
        escape_attr(v, out)?;
        push_canonical(out, "\"")?;
    }
    if n.children.is_empty() {
        push_canonical(out, "/>")?;
        return Ok(());
    }
    push_canonical(out, ">")?;
    for c in &n.children {
        match c {
            Child::Node(n) => serialize(n, out, false)?,
            Child::Text(t) => escape_text(t, out)?,
        }
    }
    push_canonical(out, "</")?;
    push_canonical(out, n.kind.name())?;
    push_canonical(out, ">")
}
fn push_canonical(out: &mut String, value: &str) -> Result<()> {
    if out
        .len()
        .checked_add(value.len())
        .is_none_or(|length| length > MAX_CANONICAL_BYTES)
    {
        return Err(SvgSanitizeError::new(
            SvgSanitizeCode::CanonicalBytes,
            "document",
        ));
    }
    out.push_str(value);
    Ok(())
}
fn escape_attr(s: &str, out: &mut String) -> Result<()> {
    for c in s.chars() {
        match c {
            '&' => push_canonical(out, "&amp;")?,
            '<' => push_canonical(out, "&lt;")?,
            '"' => push_canonical(out, "&quot;")?,
            _ => push_canonical(out, c.encode_utf8(&mut [0; 4]))?,
        }
    }
    Ok(())
}
fn escape_text(s: &str, out: &mut String) -> Result<()> {
    for c in s.chars() {
        match c {
            '&' => push_canonical(out, "&amp;")?,
            '<' => push_canonical(out, "&lt;")?,
            '>' => push_canonical(out, "&gt;")?,
            _ => push_canonical(out, c.encode_utf8(&mut [0; 4]))?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
