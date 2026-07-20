//! Pure-Rust unicode pretty-printer for a bounded LaTeX-math subset.
//!
//! This is a standalone, reusable typesetter: it takes a LaTeX(-subset)
//! string and returns typeset unicode lines, laid out with
//! [`unicode_width`] so stacked constructs (fractions, super/subscripts,
//! roots) column-align in any terminal. No terminal-graphics protocol is
//! used — output is plain unicode that renders everywhere.
//!
//! The TUI markdown renderer detects `$…$`/`$$…$$`/`\(…\)`/`\[…\]` spans and
//! feeds the inner LaTeX here. The public surface is therefore just
//! "LaTeX-subset in, unicode out".
//!
//! ## Contract
//!
//! Both entry points return `None` rather than ever panicking or dropping
//! content. `None` means "I cannot typeset this faithfully" — either an
//! unsupported command/construct was hit, or (display only) the laid-out
//! block is wider than the caller's viewport. Callers fall back to
//! showing the raw source verbatim. A `Some` result is always a complete,
//! width-respecting layout.
//!
//! ## Supported subset
//!
//! - fractions `\frac{a}{b}` — stacked vertically with a rule
//! - superscripts `x^{2}` / `x^2` — raised, unicode superscripts when the
//!   exponent is digits/simple, otherwise a raised line
//! - subscripts `x_{i}` / `x_0` — lowered, unicode subscripts when simple
//! - roots `\sqrt{x}` — drawn under a radical with an overline
//! - greek letters (`\alpha`, `\beta`, … `\Omega`)
//! - common operators / relations (`\times`, `\cdot`, `\leq`, `\to`, …)
//! - large operators `\sum`, `\int`, `\prod` with optional `_lower`/`^upper`
//! - grouping `{…}`, parentheses, spacing escapes (`\,` `\;` `\ ` `\!`)

use unicode_width::UnicodeWidthStr;

const MAX_PARSE_DEPTH: usize = 256;

/// Typeset an inline LaTeX-subset span to a single visual line of
/// unicode. Returns `None` if the span uses anything outside the
/// supported subset or if the typeset form would need more than one row
/// (e.g. a fraction inside inline math) — the caller then shows the raw
/// source. The result never spans multiple lines.
pub fn render_inline(latex: &str) -> Option<String> {
    let nodes = parse(latex)?;
    let block = layout_sequence(&nodes)?;
    if block.lines.len() != 1 {
        // Multi-row constructs (stacked fractions, raised roots) cannot
        // sit on a single inline row without breaking surrounding text —
        // fall back to raw rather than mangle the line.
        return None;
    }
    Some(block.lines.into_iter().next().unwrap_or_default())
}

/// Typeset a display LaTeX-subset span to one or more visual lines of
/// unicode. `max_width` is the available viewport width in columns.
/// Returns `None` if the span is unsupported, or if the laid-out block is
/// wider than `max_width` (the caller then shows the raw source rather
/// than emit broken/wrapped typesetting).
pub fn render_display(latex: &str, max_width: usize) -> Option<Vec<String>> {
    let nodes = parse(latex)?;
    let block = layout_sequence(&nodes)?;
    if block.width > max_width {
        return None;
    }
    Some(block.lines)
}

// ===========================================================================
// Parsing
// ===========================================================================

/// One token of the math subset. `parse` produces a flat sequence; the
/// layout pass interprets adjacency (super/subscripts attach to the
/// preceding atom).
#[derive(Debug, Clone)]
enum Node {
    /// Literal text run (identifiers, digits, already-substituted symbols).
    Text(String),
    /// `\frac{num}{den}`.
    Frac(Vec<Node>, Vec<Node>),
    /// `\sqrt{radicand}`.
    Sqrt(Vec<Node>),
    /// A superscript attaches to the atom before it: `^{…}` / `^x`.
    Sup(Vec<Node>),
    /// A subscript attaches to the atom before it: `_{…}` / `_x`.
    Sub(Vec<Node>),
    /// A large operator (`\sum`/`\int`/`\prod`) whose limits may follow as
    /// `Sub`/`Sup` nodes.
    BigOp(char),
    /// A `{…}` group — parsed as a sub-sequence so super/subscripts can
    /// attach to it as one atom.
    Group(Vec<Node>),
}

/// Parse a LaTeX-subset string into a node sequence, or `None` on any
/// unsupported command/construct. Never panics.
fn parse(src: &str) -> Option<Vec<Node>> {
    let chars: Vec<char> = src.chars().collect();
    let mut pos = 0;
    let nodes = parse_seq(&chars, &mut pos, false, 0)?;
    if pos != chars.len() {
        // Trailing unconsumed input (e.g. an unmatched `}`) — unsupported.
        return None;
    }
    Some(nodes)
}

/// Parse a sequence of nodes. When `in_group` is true, stops at (and
/// consumes) a closing `}`; otherwise stops at end of input. Returns
/// `None` on any unsupported construct.
fn parse_seq(chars: &[char], pos: &mut usize, in_group: bool, depth: usize) -> Option<Vec<Node>> {
    if depth > MAX_PARSE_DEPTH {
        return None;
    }
    let mut out = Vec::new();
    while *pos < chars.len() {
        let c = chars[*pos];
        match c {
            '}' => {
                if in_group {
                    *pos += 1;
                    return Some(out);
                }
                // Unmatched close brace outside a group: unsupported.
                return None;
            }
            '{' => {
                *pos += 1;
                let inner = parse_seq(chars, pos, true, depth + 1)?;
                out.push(Node::Group(inner));
            }
            '^' => {
                *pos += 1;
                let arg = parse_script_arg(chars, pos, depth)?;
                out.push(Node::Sup(arg));
            }
            '_' => {
                *pos += 1;
                let arg = parse_script_arg(chars, pos, depth)?;
                out.push(Node::Sub(arg));
            }
            '\\' => {
                let node = parse_command(chars, pos, depth)?;
                out.push(node);
            }
            ' ' | '\t' | '\n' | '\r' => {
                // Collapse runs of whitespace to a single space token; LaTeX
                // ignores source whitespace in math mode but a single space
                // keeps adjacent identifiers visually separated.
                *pos += 1;
                push_text(&mut out, ' ');
            }
            _ => {
                *pos += 1;
                push_text(&mut out, c);
            }
        }
    }
    if in_group {
        // Reached end of input with an open group: unclosed — unsupported.
        return None;
    }
    Some(out)
}

/// Append a single char to the trailing `Text` node, creating one if the
/// previous node isn't text.
fn push_text(out: &mut Vec<Node>, c: char) {
    if let Some(Node::Text(s)) = out.last_mut() {
        s.push(c);
    } else {
        out.push(Node::Text(c.to_string()));
    }
}

/// Parse the argument of a `^` or `_`: either a braced group, a single
/// command (`x^\alpha`), or a single character.
fn parse_script_arg(chars: &[char], pos: &mut usize, depth: usize) -> Option<Vec<Node>> {
    if *pos >= chars.len() {
        return None;
    }
    match chars[*pos] {
        '{' => {
            *pos += 1;
            parse_seq(chars, pos, true, depth + 1)
        }
        '\\' => Some(vec![parse_command(chars, pos, depth)?]),
        c => {
            *pos += 1;
            Some(vec![Node::Text(c.to_string())])
        }
    }
}

/// Parse a `\command` (and its braced args, where applicable). `pos`
/// points at the backslash. Returns `None` for any command outside the
/// supported subset.
fn parse_command(chars: &[char], pos: &mut usize, depth: usize) -> Option<Node> {
    debug_assert_eq!(chars[*pos], '\\');
    *pos += 1;
    if *pos >= chars.len() {
        return None;
    }
    // Single-char control symbols: spacing escapes and `\{` `\}`.
    let c = chars[*pos];
    if !c.is_ascii_alphabetic() {
        *pos += 1;
        return match c {
            ',' | ';' | ' ' | ':' | '>' => Some(Node::Text(" ".to_string())),
            '!' => Some(Node::Text(String::new())), // negative thin space → nothing
            '{' => Some(Node::Text("{".to_string())),
            '}' => Some(Node::Text("}".to_string())),
            '\\' => Some(Node::Text(String::new())), // line break → ignore (single-line subset)
            _ => None,
        };
    }
    // Alphabetic command name.
    let start = *pos;
    while *pos < chars.len() && chars[*pos].is_ascii_alphabetic() {
        *pos += 1;
    }
    let name: String = chars[start..*pos].iter().collect();
    match name.as_str() {
        "frac" => {
            let num = parse_required_group(chars, pos, depth)?;
            let den = parse_required_group(chars, pos, depth)?;
            Some(Node::Frac(num, den))
        }
        "sqrt" => {
            let rad = parse_required_group(chars, pos, depth)?;
            Some(Node::Sqrt(rad))
        }
        "sum" => Some(Node::BigOp('∑')),
        "int" => Some(Node::BigOp('∫')),
        "iint" => Some(Node::BigOp('∬')),
        "oint" => Some(Node::BigOp('∮')),
        "prod" => Some(Node::BigOp('∏')),
        "coprod" => Some(Node::BigOp('∐')),
        "bigcup" => Some(Node::BigOp('⋃')),
        "bigcap" => Some(Node::BigOp('⋂')),
        _ => symbol(&name).map(|s| Node::Text(s.to_string())),
    }
}

/// Parse a brace-delimited `{…}` group required as a command argument
/// (e.g. the numerator of `\frac`). `None` if the next token isn't `{`.
fn parse_required_group(chars: &[char], pos: &mut usize, depth: usize) -> Option<Vec<Node>> {
    // Skip a single optional space between command and its `{`.
    if *pos < chars.len() && chars[*pos] == ' ' {
        *pos += 1;
    }
    if *pos >= chars.len() || chars[*pos] != '{' {
        return None;
    }
    *pos += 1;
    parse_seq(chars, pos, true, depth + 1)
}

/// Map a LaTeX command name to its unicode symbol, or `None` if unknown.
fn symbol(name: &str) -> Option<&'static str> {
    Some(match name {
        // Lowercase greek
        "alpha" => "α",
        "beta" => "β",
        "gamma" => "γ",
        "delta" => "δ",
        "epsilon" => "ε",
        "varepsilon" => "ε",
        "zeta" => "ζ",
        "eta" => "η",
        "theta" => "θ",
        "vartheta" => "ϑ",
        "iota" => "ι",
        "kappa" => "κ",
        "lambda" => "λ",
        "mu" => "μ",
        "nu" => "ν",
        "xi" => "ξ",
        "omicron" => "ο",
        "pi" => "π",
        "varpi" => "ϖ",
        "rho" => "ρ",
        "varrho" => "ϱ",
        "sigma" => "σ",
        "varsigma" => "ς",
        "tau" => "τ",
        "upsilon" => "υ",
        "phi" => "φ",
        "varphi" => "ϕ",
        "chi" => "χ",
        "psi" => "ψ",
        "omega" => "ω",
        // Uppercase greek
        "Gamma" => "Γ",
        "Delta" => "Δ",
        "Theta" => "Θ",
        "Lambda" => "Λ",
        "Xi" => "Ξ",
        "Pi" => "Π",
        "Sigma" => "Σ",
        "Upsilon" => "Υ",
        "Phi" => "Φ",
        "Psi" => "Ψ",
        "Omega" => "Ω",
        // Binary operators
        "times" => "×",
        "div" => "÷",
        "cdot" => "·",
        "ast" => "∗",
        "star" => "⋆",
        "pm" => "±",
        "mp" => "∓",
        "oplus" => "⊕",
        "ominus" => "⊖",
        "otimes" => "⊗",
        "circ" => "∘",
        "bullet" => "•",
        "cap" => "∩",
        "cup" => "∪",
        "wedge" => "∧",
        "vee" => "∨",
        "setminus" => "∖",
        // Relations
        "leq" | "le" => "≤",
        "geq" | "ge" => "≥",
        "neq" | "ne" => "≠",
        "equiv" => "≡",
        "approx" => "≈",
        "sim" => "∼",
        "simeq" => "≃",
        "cong" => "≅",
        "propto" => "∝",
        "ll" => "≪",
        "gg" => "≫",
        "subset" => "⊂",
        "supset" => "⊃",
        "subseteq" => "⊆",
        "supseteq" => "⊇",
        "in" => "∈",
        "notin" => "∉",
        "ni" => "∋",
        "perp" => "⊥",
        "parallel" => "∥",
        "mid" => "∣",
        // Arrows
        "to" | "rightarrow" => "→",
        "leftarrow" | "gets" => "←",
        "leftrightarrow" => "↔",
        "Rightarrow" => "⇒",
        "Leftarrow" => "⇐",
        "Leftrightarrow" => "⇔",
        "mapsto" => "↦",
        "uparrow" => "↑",
        "downarrow" => "↓",
        // Misc symbols
        "infty" => "∞",
        "partial" => "∂",
        "nabla" => "∇",
        "forall" => "∀",
        "exists" => "∃",
        "nexists" => "∄",
        "emptyset" | "varnothing" => "∅",
        "neg" | "lnot" => "¬",
        "angle" => "∠",
        "triangle" => "△",
        "square" => "□",
        "dagger" => "†",
        "ddagger" => "‡",
        "ldots" | "dots" => "…",
        "cdots" => "⋯",
        "vdots" => "⋮",
        "ddots" => "⋱",
        "prime" => "′",
        "hbar" => "ℏ",
        "ell" => "ℓ",
        "Re" => "ℜ",
        "Im" => "ℑ",
        "aleph" => "ℵ",
        "wp" => "℘",
        "surd" => "√",
        "checkmark" => "✓",
        // Named functions / operators (rendered upright as text).
        "sin" => "sin",
        "cos" => "cos",
        "tan" => "tan",
        "cot" => "cot",
        "sec" => "sec",
        "csc" => "csc",
        "log" => "log",
        "ln" => "ln",
        "exp" => "exp",
        "lim" => "lim",
        "max" => "max",
        "min" => "min",
        "det" => "det",
        "gcd" => "gcd",
        "deg" => "deg",
        "arg" => "arg",
        "dim" => "dim",
        "ker" => "ker",
        "sinh" => "sinh",
        "cosh" => "cosh",
        "tanh" => "tanh",
        "sqrt" => "√", // bare \sqrt with no group handled by command parser; defensive
        _ => return None,
    })
}

// ===========================================================================
// Layout
// ===========================================================================

/// A laid-out box: a rectangle of text lines plus the index of the
/// baseline row (used to vertically align adjacent boxes of differing
/// height). `width` is the column count (via `unicode-width`), and every
/// line in `lines` is padded to exactly `width` columns.
#[derive(Debug, Clone)]
struct Block {
    lines: Vec<String>,
    width: usize,
    /// Row index (0-based into `lines`) that sits on the math baseline.
    baseline: usize,
}

impl Block {
    fn empty() -> Block {
        Block {
            lines: vec![String::new()],
            width: 0,
            baseline: 0,
        }
    }

    fn height(&self) -> usize {
        self.lines.len()
    }

    /// Rows above the baseline.
    fn ascent(&self) -> usize {
        self.baseline
    }

    /// Rows at or below the baseline.
    fn descent(&self) -> usize {
        self.height() - self.baseline
    }

    /// A single-line block from a string.
    fn from_text(s: &str) -> Block {
        Block {
            width: s.width(),
            lines: vec![s.to_string()],
            baseline: 0,
        }
    }
}

/// Pad a line on the right with spaces to reach `width` columns (measured
/// by `unicode-width`).
fn pad_to(line: &str, width: usize) -> String {
    let w = line.width();
    if w >= width {
        line.to_string()
    } else {
        let mut s = line.to_string();
        s.push_str(&" ".repeat(width - w));
        s
    }
}

/// Lay out a node sequence into one block, attaching super/subscripts to
/// the preceding atom and stacking big-operator limits. Returns `None` if
/// any sub-construct is unsupported.
fn layout_sequence(nodes: &[Node]) -> Option<Block> {
    // First pass: turn the flat node list into "atoms" where each atom is
    // a base box plus optional sub/superscript and (for big ops) limits.
    let mut atoms: Vec<Block> = Vec::new();
    let mut i = 0;
    while i < nodes.len() {
        let base = &nodes[i];
        match base {
            Node::Sup(_) | Node::Sub(_) => {
                // A script with no preceding atom: attach to an empty base.
                let mut sup: Option<&[Node]> = None;
                let mut sub: Option<&[Node]> = None;
                collect_scripts(nodes, &mut i, &mut sup, &mut sub);
                atoms.push(attach_scripts(Block::empty(), sup, sub, false)?);
            }
            _ => {
                let (base_block, is_bigop) = layout_atom_base(base)?;
                i += 1;
                let mut sup: Option<&[Node]> = None;
                let mut sub: Option<&[Node]> = None;
                collect_scripts(nodes, &mut i, &mut sup, &mut sub);
                atoms.push(attach_scripts(base_block, sup, sub, is_bigop)?);
            }
        }
    }
    if atoms.is_empty() {
        return Some(Block::empty());
    }
    Some(hcat(&atoms))
}

/// Collect any run of `Sup`/`Sub` nodes starting at `*i`, advancing `*i`
/// past them. At most one of each is honored (a later one overrides).
fn collect_scripts<'a>(
    nodes: &'a [Node],
    i: &mut usize,
    sup: &mut Option<&'a [Node]>,
    sub: &mut Option<&'a [Node]>,
) {
    while *i < nodes.len() {
        match &nodes[*i] {
            Node::Sup(inner) => {
                *sup = Some(inner);
                *i += 1;
            }
            Node::Sub(inner) => {
                *sub = Some(inner);
                *i += 1;
            }
            _ => break,
        }
    }
}

/// Lay out the base of an atom (everything except its scripts). Returns
/// the block and whether it is a big operator (limits stack above/below
/// rather than sitting as super/subscripts).
fn layout_atom_base(node: &Node) -> Option<(Block, bool)> {
    match node {
        Node::Text(s) => Some((Block::from_text(s), false)),
        Node::Group(inner) => Some((layout_sequence(inner)?, false)),
        Node::Frac(num, den) => Some((layout_frac(num, den)?, false)),
        Node::Sqrt(rad) => Some((layout_sqrt(rad)?, false)),
        Node::BigOp(c) => Some((Block::from_text(&c.to_string()), true)),
        // Scripts are handled by the caller; a bare script here is a bug.
        Node::Sup(_) | Node::Sub(_) => None,
    }
}

/// Attach sub/superscripts to a base block. For ordinary atoms the
/// superscript is raised and the subscript lowered as separate rows. For
/// big operators the scripts become stacked limits (above/below).
fn attach_scripts(
    base: Block,
    sup: Option<&[Node]>,
    sub: Option<&[Node]>,
    is_bigop: bool,
) -> Option<Block> {
    if sup.is_none() && sub.is_none() {
        return Some(base);
    }
    let sup_block = match sup {
        Some(s) => Some(layout_sequence(s)?),
        None => None,
    };
    let sub_block = match sub {
        Some(s) => Some(layout_sequence(s)?),
        None => None,
    };
    if is_bigop {
        Some(stack_limits(base, sup_block, sub_block))
    } else {
        Some(attach_inline_scripts(base, sup_block, sub_block))
    }
}

/// Try to render a simple sequence as unicode super/subscript glyphs (so
/// `x^2` becomes `x²` on one row). Returns the glyph string if every char
/// maps, else `None`.
fn unicode_script(block: &Block, table: fn(char) -> Option<char>) -> Option<String> {
    if block.height() != 1 {
        return None;
    }
    let line = &block.lines[0];
    let mut out = String::new();
    for ch in line.chars() {
        out.push(table(ch)?);
    }
    Some(out)
}

fn superscript_char(c: char) -> Option<char> {
    Some(match c {
        '0' => '⁰',
        '1' => '¹',
        '2' => '²',
        '3' => '³',
        '4' => '⁴',
        '5' => '⁵',
        '6' => '⁶',
        '7' => '⁷',
        '8' => '⁸',
        '9' => '⁹',
        '+' => '⁺',
        '-' => '⁻',
        '=' => '⁼',
        '(' => '⁽',
        ')' => '⁾',
        'n' => 'ⁿ',
        'i' => 'ⁱ',
        ' ' => ' ',
        _ => return None,
    })
}

fn subscript_char(c: char) -> Option<char> {
    Some(match c {
        '0' => '₀',
        '1' => '₁',
        '2' => '₂',
        '3' => '₃',
        '4' => '₄',
        '5' => '₅',
        '6' => '₆',
        '7' => '₇',
        '8' => '₈',
        '9' => '₉',
        '+' => '₊',
        '-' => '₋',
        '=' => '₌',
        '(' => '₍',
        ')' => '₎',
        ' ' => ' ',
        _ => return None,
    })
}

/// Attach inline scripts to an ordinary atom. Prefers compact unicode
/// super/subscript glyphs (single row); otherwise builds a multi-row
/// layout with the superscript raised and the subscript lowered.
fn attach_inline_scripts(base: Block, sup: Option<Block>, sub: Option<Block>) -> Block {
    // Fast path: single-row base with unicode-mappable scripts → one row.
    if base.height() == 1 {
        let sup_uni = sup
            .as_ref()
            .and_then(|b| unicode_script(b, superscript_char));
        let sub_uni = sub.as_ref().and_then(|b| unicode_script(b, subscript_char));
        let sup_ok = sup.is_none() || sup_uni.is_some();
        let sub_ok = sub.is_none() || sub_uni.is_some();
        if sup_ok && sub_ok {
            let mut s = base.lines[0].clone();
            // Subscript sits closer to the base in print; order sub then
            // sup keeps `x_i^2` reading left-to-right as `xᵢ²`.
            if let Some(sb) = sub_uni {
                s.push_str(&sb);
            }
            if let Some(sp) = sup_uni {
                s.push_str(&sp);
            }
            return Block::from_text(&s);
        }
    }
    // General path: stack the scripts as raised/lowered rows beside the
    // base. The base keeps its baseline; the superscript block sits above,
    // the subscript below.
    let sup = sup.unwrap_or_else(Block::empty);
    let sub = sub.unwrap_or_else(Block::empty);
    let has_sup = !sup.lines.iter().all(|l| l.trim().is_empty());
    let has_sub = !sub.lines.iter().all(|l| l.trim().is_empty());

    let script_w = sup.width.max(sub.width);
    // Compose the scripts column: superscript rows, then a blank row band
    // for the base baseline, then subscript rows.
    let base_h = base.height();
    let mut script_lines: Vec<String> = Vec::new();
    if has_sup {
        for l in &sup.lines {
            script_lines.push(pad_to(l, script_w));
        }
    }
    // Base occupies `base_h` rows aligned to its baseline.
    for _ in 0..base_h {
        script_lines.push(" ".repeat(script_w));
    }
    if has_sub {
        for l in &sub.lines {
            script_lines.push(pad_to(l, script_w));
        }
    }
    let sup_rows = if has_sup { sup.height() } else { 0 };
    // Build the base column padded to the same total height.
    let mut base_lines: Vec<String> = Vec::new();
    for _ in 0..sup_rows {
        base_lines.push(" ".repeat(base.width));
    }
    for l in &base.lines {
        base_lines.push(pad_to(l, base.width));
    }
    if has_sub {
        for _ in 0..sub.height() {
            base_lines.push(" ".repeat(base.width));
        }
    }
    let total_h = base_lines.len();
    let width = base.width + script_w;
    let mut lines = Vec::with_capacity(total_h);
    for r in 0..total_h {
        let b = base_lines
            .get(r)
            .cloned()
            .unwrap_or_else(|| " ".repeat(base.width));
        let s = script_lines
            .get(r)
            .cloned()
            .unwrap_or_else(|| " ".repeat(script_w));
        lines.push(format!("{b}{s}"));
    }
    let baseline = sup_rows + base.baseline;
    Block {
        lines,
        width,
        baseline,
    }
}

/// Stack big-operator limits above (superscript) and below (subscript) the
/// operator glyph, centered.
fn stack_limits(base: Block, sup: Option<Block>, sub: Option<Block>) -> Block {
    let mut parts: Vec<Block> = Vec::new();
    let mut baseline_offset = 0;
    if let Some(s) = sup {
        parts.push(s);
    }
    let base_index = parts.len();
    parts.push(base);
    if let Some(s) = sub {
        parts.push(s);
    }
    let width = parts.iter().map(|b| b.width).max().unwrap_or(0);
    let mut lines = Vec::new();
    for (idx, b) in parts.iter().enumerate() {
        if idx == base_index {
            baseline_offset = lines.len() + b.baseline;
        }
        for l in &b.lines {
            lines.push(center(l, l.width(), width));
        }
    }
    Block {
        lines,
        width,
        baseline: baseline_offset,
    }
}

/// Center `line` (which occupies `line_w` columns) within `width` columns.
fn center(line: &str, line_w: usize, width: usize) -> String {
    if line_w >= width {
        return line.to_string();
    }
    let total = width - line_w;
    let left = total / 2;
    let right = total - left;
    format!("{}{}{}", " ".repeat(left), line, " ".repeat(right))
}

/// Lay out `\frac{num}{den}` as a vertically stacked fraction: numerator,
/// a rule of `─`, denominator — each centered to the max width.
fn layout_frac(num: &[Node], den: &[Node]) -> Option<Block> {
    let n = layout_sequence(num)?;
    let d = layout_sequence(den)?;
    let inner = n.width.max(d.width);
    let width = inner + 2; // one space of padding each side of the rule
    let bar = format!(" {} ", "─".repeat(inner));
    let mut lines = Vec::with_capacity(n.height() + 1 + d.height());
    for l in &n.lines {
        lines.push(center_padded(l, inner, width));
    }
    let baseline = lines.len();
    lines.push(bar);
    for l in &d.lines {
        lines.push(center_padded(l, inner, width));
    }
    Some(Block {
        lines,
        width,
        baseline,
    })
}

/// Center `line` within `inner` columns, then add one space of side
/// padding to reach `inner + 2` (matching the fraction rule's overhang).
fn center_padded(line: &str, inner: usize, width: usize) -> String {
    let centered = center(line, line.width(), inner);
    let s = format!(" {centered} ");
    pad_to(&s, width)
}

/// Lay out `\sqrt{radicand}` as the radicand under an overline preceded by
/// a radical glyph. Multi-row radicands get a taller radical stroke.
fn layout_sqrt(rad: &[Node]) -> Option<Block> {
    let r = layout_sequence(rad)?;
    let h = r.height();
    let overline = "─".repeat(r.width);
    let mut lines = Vec::with_capacity(h + 1);
    // Top row: the radical's hook over the overline.
    // For a single-row radicand we use the compact `√` form: `√‾‾‾`.
    if h == 1 {
        // `√` then a combining/standalone overline above the content.
        let top = format!(" {overline}");
        lines.push(top);
        lines.push(format!("√{}", pad_to(&r.lines[0], r.width)));
        return Some(Block {
            width: r.width + 1,
            lines,
            baseline: 1,
        });
    }
    // Multi-row: draw a radical column on the left.
    lines.push(format!("  {overline}"));
    for (idx, l) in r.lines.iter().enumerate() {
        let prefix = if idx + 1 == h { "╲╱" } else { "  " };
        lines.push(format!("{prefix}{}", pad_to(l, r.width)));
    }
    Some(Block {
        width: r.width + 2,
        lines,
        baseline: 1 + r.baseline,
    })
}

/// Horizontally concatenate atom blocks, aligning them on a common
/// baseline so super/subscripts and fractions sit at the right height.
fn hcat(blocks: &[Block]) -> Block {
    if blocks.is_empty() {
        return Block::empty();
    }
    if blocks.len() == 1 {
        return blocks[0].clone();
    }
    let max_ascent = blocks.iter().map(|b| b.ascent()).max().unwrap_or(0);
    let max_descent = blocks.iter().map(|b| b.descent()).max().unwrap_or(1);
    let total_h = max_ascent + max_descent;
    let total_w: usize = blocks.iter().map(|b| b.width).sum();
    let mut lines = vec![String::new(); total_h];
    for b in blocks {
        // Top padding so this block's baseline lands on `max_ascent`.
        let top_pad = max_ascent - b.ascent();
        for (row, line) in lines.iter_mut().enumerate() {
            if row >= top_pad && row < top_pad + b.height() {
                let src = &b.lines[row - top_pad];
                line.push_str(&pad_to(src, b.width));
            } else {
                line.push_str(&" ".repeat(b.width));
            }
        }
    }
    Block {
        lines,
        width: total_w,
        baseline: max_ascent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_simple_text() {
        assert_eq!(render_inline("a + b").as_deref(), Some("a + b"));
    }

    #[test]
    fn inline_superscript_digits() {
        assert_eq!(render_inline("x^2").as_deref(), Some("x²"));
        assert_eq!(render_inline("x^{2}").as_deref(), Some("x²"));
    }

    #[test]
    fn inline_subscript_digits() {
        assert_eq!(render_inline("x_0").as_deref(), Some("x₀"));
        assert_eq!(render_inline("a_{12}").as_deref(), Some("a₁₂"));
    }

    #[test]
    fn inline_greek_and_ops() {
        assert_eq!(render_inline("\\alpha").as_deref(), Some("α"));
        assert_eq!(render_inline("a \\leq b").as_deref(), Some("a ≤ b"));
        assert_eq!(render_inline("a \\times b").as_deref(), Some("a × b"));
    }

    #[test]
    fn inline_fraction_is_multiline_so_none() {
        // A fraction needs 3 rows; it cannot render inline → None (raw).
        assert!(render_inline("\\frac{1}{2}").is_none());
    }

    #[test]
    fn display_fraction_stacks() {
        let lines = render_display("\\frac{1}{2}", 80).expect("frac typesets");
        assert_eq!(lines.len(), 3);
        // numerator / rule / denominator, centered.
        assert!(lines[0].contains('1'));
        assert!(lines[1].contains('─'));
        assert!(lines[2].contains('2'));
    }

    #[test]
    fn display_integral_with_bounds() {
        let lines = render_display("\\int_0^1 x^2\\,dx", 80).expect("integral typesets");
        let joined = lines.join("\n");
        assert!(joined.contains('∫'), "has integral sign: {joined:?}");
        assert!(joined.contains('0'), "has lower bound");
        assert!(joined.contains('1'), "has upper bound");
        assert!(joined.contains('²'), "has x squared");
        assert!(joined.contains("dx"), "has dx");
    }

    #[test]
    fn display_sqrt_has_radical() {
        let lines = render_display("\\sqrt{x}", 80).expect("sqrt typesets");
        let joined = lines.join("\n");
        assert!(joined.contains('√'));
        assert!(joined.contains('─'));
    }

    #[test]
    fn display_sum_stacks_limits() {
        let lines = render_display("\\sum_{i=0}^{n} i", 80).expect("sum typesets");
        let joined = lines.join("\n");
        assert!(joined.contains('∑'));
        assert!(joined.contains('n'));
    }

    #[test]
    fn unsupported_command_is_none() {
        // `\foobar` is not in the subset → None so caller shows raw.
        assert!(render_inline("\\foobar{x}").is_none());
        assert!(render_display("\\foobar{x}", 80).is_none());
    }

    #[test]
    fn unmatched_brace_is_none() {
        assert!(render_inline("a}").is_none());
        assert!(render_display("{a", 80).is_none());
    }

    #[test]
    fn deeply_nested_braces_return_none_instead_of_overflowing_stack() {
        let mut latex = String::new();
        for _ in 0..(MAX_PARSE_DEPTH + 10) {
            latex.push('{');
        }
        latex.push('x');
        for _ in 0..(MAX_PARSE_DEPTH + 10) {
            latex.push('}');
        }
        assert!(render_inline(&latex).is_none());
        assert!(render_display(&latex, 80).is_none());
    }

    #[test]
    fn overwide_display_is_none() {
        // A fraction has width >= numerator/denominator width; give it a
        // tiny max_width so it must degrade to raw.
        assert!(render_display("\\frac{1}{2}", 1).is_none());
    }

    #[test]
    fn never_panics_on_lone_backslash() {
        assert!(render_inline("\\").is_none());
        assert!(render_display("x \\", 80).is_none());
    }

    #[test]
    fn lines_are_padded_to_block_width() {
        // Every line of a multi-row block must be the same column count so
        // downstream alignment holds. Verify via unicode-width.
        let lines = render_display("\\frac{abc}{d}", 80).unwrap();
        let widths: Vec<usize> = lines.iter().map(|l| l.width()).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "ragged widths: {widths:?}"
        );
    }
}
