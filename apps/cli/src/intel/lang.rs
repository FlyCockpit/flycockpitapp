//! Language detection + tree-sitter extraction for the intel index.
//!
//! One [`Language`] per supported grammar (+ `Unknown` for everything
//! else). For known languages we run tree-sitter queries to pull
//! symbols + imports, and a manual full-tree walk to pull identifiers
//! (the inverted index `word` reads) and call-sites (consumed by the
//! call-graph layer — `impact` + centrality ranking,
//! `src/intel/callgraph.rs`). `Unknown` files get a regex outline
//! fallback so `outline` never hard-errors and `tree`/`hot`/`search`
//! still see them.
//!
//! A fresh [`tree_sitter::Parser`] is built per call (cheap) so the
//! extraction is `Send` and runs inside a rayon worker without sharing
//! a parser across threads.

use std::path::Path;

use anyhow::Result;
use tree_sitter::{Language as TsLanguage, Parser, Query, QueryCursor, StreamingIterator};

/// A symbol extracted from a file (function, type, etc.).
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub line: i64,
    pub end_line: i64,
    pub parent: Option<String>,
    pub visibility: Option<String>,
    pub signature: Option<String>,
}

/// A raw import statement target (unresolved at extraction time).
#[derive(Debug, Clone)]
pub struct Import {
    pub target: String,
    pub line: i64,
}

/// An identifier occurrence (token + line). Feeds the `word` inverted
/// index.
#[derive(Debug, Clone)]
pub struct Identifier {
    pub token: String,
    pub line: i64,
}

/// A call-site. `callee_kind` ∈ {`call`, `type_ref`, `macro`}.
#[derive(Debug, Clone)]
pub struct CallSite {
    pub caller_line: i64,
    pub caller_symbol: Option<String>,
    pub callee_name: String,
    pub callee_kind: String,
}

/// Everything pulled from one parsed file.
#[derive(Debug, Default, Clone)]
pub struct Extraction {
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub identifiers: Vec<Identifier>,
    pub callsites: Vec<CallSite>,
}

/// Supported languages plus an `Unknown` catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Rust,
    TypeScript,
    Tsx,
    JavaScript,
    Python,
    Go,
    C,
    Cpp,
    Unknown,
}

impl Language {
    /// Map a file extension (no leading dot, lowercased by the caller is
    /// fine but we lowercase defensively) to a language.
    pub fn from_path(path: &Path) -> Language {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();
        match ext.as_str() {
            "rs" => Language::Rust,
            "ts" | "mts" | "cts" => Language::TypeScript,
            "tsx" => Language::Tsx,
            "js" | "mjs" | "cjs" | "jsx" => Language::JavaScript,
            "py" | "pyi" => Language::Python,
            "go" => Language::Go,
            "c" | "h" => Language::C,
            "cc" | "cpp" | "cxx" | "hpp" | "hxx" | "hh" => Language::Cpp,
            _ => Language::Unknown,
        }
    }

    /// Stable string stored in `intel_files.language`.
    pub fn as_str(self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::TypeScript => "typescript",
            Language::Tsx => "tsx",
            Language::JavaScript => "javascript",
            Language::Python => "python",
            Language::Go => "go",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Unknown => "unknown",
        }
    }

    /// The tree-sitter grammar, or `None` for `Unknown`.
    fn grammar(self) -> Option<TsLanguage> {
        let lang: TsLanguage = match self {
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::C => tree_sitter_c::LANGUAGE.into(),
            Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
            Language::Unknown => return None,
        };
        Some(lang)
    }
}

/// Parse `source` as `lang` and pull symbols/imports/identifiers/
/// callsites. `Unknown` (and any file the grammar can't parse) returns
/// an empty extraction — callers fall back to the regex outline for
/// `outline` and simply index zero structure otherwise.
pub fn extract(lang: Language, source: &[u8]) -> Result<Extraction> {
    let Some(grammar) = lang.grammar() else {
        return Ok(Extraction::default());
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return Ok(Extraction::default());
    }
    let Some(tree) = parser.parse(source, None) else {
        return Ok(Extraction::default());
    };
    let root = tree.root_node();

    let mut ex = Extraction::default();
    extract_symbols(lang, &grammar, root, source, &mut ex);
    extract_imports(lang, &grammar, root, source, &mut ex);
    walk_identifiers_and_calls(lang, root, source, &mut ex);
    Ok(ex)
}

/// 1-indexed start line of a node.
fn node_line(node: tree_sitter::Node) -> i64 {
    node.start_position().row as i64 + 1
}

/// 1-indexed end line of a node.
fn node_end_line(node: tree_sitter::Node) -> i64 {
    node.end_position().row as i64 + 1
}

/// First line of the node's text — used as a terse signature.
fn first_line<'a>(node: tree_sitter::Node, source: &'a [u8]) -> Option<&'a str> {
    let text = node.utf8_text(source).ok()?;
    Some(text.lines().next().unwrap_or(text).trim_end())
}

// ---- symbols ---------------------------------------------------------------

/// The tree-sitter query that captures a language's top-level symbol
/// definitions plus, where applicable, the enclosing container name so
/// methods get a `parent`.
fn symbol_query(lang: Language) -> &'static str {
    match lang {
        Language::Rust => {
            r#"
            (struct_item name: (type_identifier) @name) @def
            (enum_item name: (type_identifier) @name) @def
            (trait_item name: (type_identifier) @name) @def
            (mod_item name: (identifier) @name) @def
            (type_item name: (type_identifier) @name) @def
            (const_item name: (identifier) @name) @def
            (static_item name: (identifier) @name) @def
            (function_item name: (identifier) @name) @def
            (impl_item
                type: (type_identifier) @impl_type
                body: (declaration_list
                    (function_item name: (identifier) @method) @method_def))
            "#
        }
        Language::TypeScript | Language::Tsx | Language::JavaScript => {
            r#"
            (function_declaration name: (identifier) @name) @def
            (class_declaration name: (type_identifier) @name) @def
            (interface_declaration name: (type_identifier) @name) @def
            (type_alias_declaration name: (type_identifier) @name) @def
            (lexical_declaration (variable_declarator name: (identifier) @name)) @def
            (variable_declaration (variable_declarator name: (identifier) @name)) @def
            (class_declaration
                name: (type_identifier) @class_name
                body: (class_body
                    (method_definition name: (property_identifier) @method) @method_def))
            "#
        }
        Language::Python => {
            r#"
            (function_definition name: (identifier) @name) @def
            (class_definition name: (identifier) @name) @def
            (class_definition
                name: (identifier) @class_name
                body: (block
                    (function_definition name: (identifier) @method) @method_def))
            "#
        }
        Language::Go => {
            r#"
            (function_declaration name: (identifier) @name) @def
            (type_declaration (type_spec name: (type_identifier) @name)) @def
            (const_declaration (const_spec name: (identifier) @name)) @def
            (var_declaration (var_spec name: (identifier) @name)) @def
            (method_declaration
                receiver: (parameter_list
                    (parameter_declaration type: (_) @recv))
                name: (field_identifier) @method) @method_def
            "#
        }
        Language::C => {
            r#"
            (function_definition declarator: (function_declarator declarator: (identifier) @name)) @def
            (struct_specifier name: (type_identifier) @name) @def
            (enum_specifier name: (type_identifier) @name) @def
            "#
        }
        Language::Cpp => {
            r#"
            (function_definition declarator: (function_declarator declarator: (identifier) @name)) @def
            (struct_specifier name: (type_identifier) @name) @def
            (enum_specifier name: (type_identifier) @name) @def
            (class_specifier name: (type_identifier) @name) @def
            (namespace_definition name: (namespace_identifier) @name) @def
            "#
        }
        Language::Unknown => "",
    }
}

/// Node-kind → symbol kind label for the simple `@def`/`@name` matches.
fn symbol_kind_for(lang: Language, node_kind: &str) -> &'static str {
    match (lang, node_kind) {
        (Language::Rust, "struct_item") => "struct",
        (Language::Rust, "enum_item") => "enum",
        (Language::Rust, "trait_item") => "trait",
        (Language::Rust, "mod_item") => "mod",
        (Language::Rust, "type_item") => "type",
        (Language::Rust, "const_item") => "const",
        (Language::Rust, "static_item") => "static",
        (Language::Rust, "function_item") => "function",
        (_, "function_declaration") => "function",
        (_, "function_definition") => "function",
        (_, "class_declaration") => "class",
        (_, "class_specifier") => "class",
        (_, "interface_declaration") => "interface",
        (_, "type_alias_declaration") => "type",
        (_, "type_declaration") => "type",
        (_, "lexical_declaration") => "const",
        (_, "variable_declaration") => "var",
        (Language::Python, "class_definition") => "class",
        (Language::Go, "const_declaration") => "const",
        (Language::Go, "var_declaration") => "var",
        (_, "struct_specifier") => "struct",
        (_, "enum_specifier") => "enum",
        (_, "namespace_definition") => "namespace",
        _ => "symbol",
    }
}

fn rust_visibility(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" {
            return child.utf8_text(source).ok().map(|s| s.to_string());
        }
    }
    None
}

fn extract_symbols(
    lang: Language,
    grammar: &TsLanguage,
    root: tree_sitter::Node,
    source: &[u8],
    ex: &mut Extraction,
) {
    let q = symbol_query(lang);
    if q.is_empty() {
        return;
    }
    let Ok(query) = Query::new(grammar, q) else {
        return;
    };
    let idx_name = query.capture_index_for_name("name");
    let idx_def = query.capture_index_for_name("def");
    let idx_method = query.capture_index_for_name("method");
    let idx_method_def = query.capture_index_for_name("method_def");
    let idx_impl_type = query.capture_index_for_name("impl_type");
    let idx_class_name = query.capture_index_for_name("class_name");
    let idx_recv = query.capture_index_for_name("recv");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, source);
    while let Some(m) = matches.next() {
        // Simple top-level definition: name + def captures present.
        if let (Some(ni), Some(di)) = (idx_name, idx_def) {
            let name_cap = m.captures.iter().find(|c| c.index == ni);
            let def_cap = m.captures.iter().find(|c| c.index == di);
            if let (Some(nc), Some(dc)) = (name_cap, def_cap)
                && let Ok(name) = nc.node.utf8_text(source)
            {
                let def = dc.node;
                let visibility = if lang == Language::Rust {
                    rust_visibility(def, source)
                } else {
                    None
                };
                ex.symbols.push(Symbol {
                    name: name.to_string(),
                    kind: symbol_kind_for(lang, def.kind()).to_string(),
                    line: node_line(def),
                    end_line: node_end_line(def),
                    parent: None,
                    visibility,
                    signature: first_line(def, source).map(|s| s.to_string()),
                });
                continue;
            }
        }
        // Method nested in a container — parent comes from the container
        // capture (impl_type / class_name / recv).
        if let (Some(mi), Some(mdi)) = (idx_method, idx_method_def) {
            let method_cap = m.captures.iter().find(|c| c.index == mi);
            let method_def_cap = m.captures.iter().find(|c| c.index == mdi);
            if let (Some(mc), Some(mdc)) = (method_cap, method_def_cap)
                && let Ok(name) = mc.node.utf8_text(source)
            {
                let parent = idx_impl_type
                    .and_then(|i| m.captures.iter().find(|c| c.index == i))
                    .or_else(|| {
                        idx_class_name.and_then(|i| m.captures.iter().find(|c| c.index == i))
                    })
                    .or_else(|| idx_recv.and_then(|i| m.captures.iter().find(|c| c.index == i)))
                    .and_then(|c| c.node.utf8_text(source).ok())
                    .map(|s| s.trim_start_matches(['*', '&']).to_string());
                let def = mdc.node;
                let visibility = if lang == Language::Rust {
                    rust_visibility(def, source)
                } else {
                    None
                };
                ex.symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "method".to_string(),
                    line: node_line(def),
                    end_line: node_end_line(def),
                    parent,
                    visibility,
                    signature: first_line(def, source).map(|s| s.to_string()),
                });
            }
        }
    }

    // Python: UPPERCASE module-level assignments → const. Tree-sitter
    // assignment nodes are common; only promote the all-caps ones.
    if lang == Language::Python {
        extract_python_consts(root, source, ex);
    }
}

fn extract_python_consts(root: tree_sitter::Node, source: &[u8], ex: &mut Extraction) {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        // module-level `expression_statement (assignment)`.
        if child.kind() != "expression_statement" {
            continue;
        }
        let mut inner = child.walk();
        for a in child.children(&mut inner) {
            if a.kind() != "assignment" {
                continue;
            }
            if let Some(lhs) = a.child_by_field_name("left")
                && lhs.kind() == "identifier"
                && let Ok(name) = lhs.utf8_text(source)
                && !name.is_empty()
                && name.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                && name.chars().any(|c| c.is_ascii_uppercase())
            {
                ex.symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "const".to_string(),
                    line: node_line(a),
                    end_line: node_end_line(a),
                    parent: None,
                    visibility: None,
                    signature: first_line(a, source).map(|s| s.to_string()),
                });
            }
        }
    }
}

// ---- imports ---------------------------------------------------------------

fn import_node_kinds(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Rust => &["use_declaration"],
        Language::TypeScript | Language::Tsx | Language::JavaScript => {
            &["import_statement", "export_statement"]
        }
        Language::Python => &["import_statement", "import_from_statement"],
        Language::Go => &["import_declaration"],
        Language::C | Language::Cpp => &["preproc_include"],
        Language::Unknown => &[],
    }
}

fn extract_imports(
    lang: Language,
    _grammar: &TsLanguage,
    root: tree_sitter::Node,
    source: &[u8],
    ex: &mut Extraction,
) {
    let kinds = import_node_kinds(lang);
    if kinds.is_empty() {
        return;
    }
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if kinds.contains(&node.kind()) {
            collect_import_targets(lang, node, source, ex);
            // Don't descend into an import node's children.
            continue;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Pull the raw module path(s) out of an import-ish node. The raw text
/// is stored verbatim in `intel_imports.target`; the resolver later
/// normalizes it into an `intel_deps` edge.
fn collect_import_targets(
    lang: Language,
    node: tree_sitter::Node,
    source: &[u8],
    ex: &mut Extraction,
) {
    let line = node_line(node);
    match lang {
        Language::Rust => {
            // Store the whole use-tree text after `use ` minus the
            // trailing `;`; the resolver handles `crate::`, braces, etc.
            if let Ok(text) = node.utf8_text(source) {
                let t = text
                    .trim()
                    .trim_start_matches("pub")
                    .trim()
                    .trim_start_matches("use")
                    .trim()
                    .trim_end_matches(';')
                    .trim();
                if !t.is_empty() {
                    ex.imports.push(Import {
                        target: t.to_string(),
                        line,
                    });
                }
            }
        }
        Language::TypeScript | Language::Tsx | Language::JavaScript => {
            // Find the string literal source ("…"/'…').
            if let Some(s) = find_first_string(node, source) {
                ex.imports.push(Import { target: s, line });
            }
        }
        Language::Python => {
            if let Ok(text) = node.utf8_text(source) {
                let t = text.trim();
                if let Some(rest) = t.strip_prefix("from ") {
                    // `from X import ...` → X
                    let module = rest.split_whitespace().next().unwrap_or("").to_string();
                    if !module.is_empty() {
                        ex.imports.push(Import {
                            target: module,
                            line,
                        });
                    }
                } else if let Some(rest) = t.strip_prefix("import ") {
                    for part in rest.split(',') {
                        let module = part.split_whitespace().next().unwrap_or("");
                        if !module.is_empty() {
                            ex.imports.push(Import {
                                target: module.to_string(),
                                line,
                            });
                        }
                    }
                }
            }
        }
        Language::Go => {
            // import_declaration wraps one or more import_spec; each spec
            // has an interpreted_string_literal path.
            let mut stack = vec![node];
            while let Some(n) = stack.pop() {
                if n.kind() == "import_spec"
                    && let Some(s) = find_first_string(n, source)
                {
                    ex.imports.push(Import {
                        target: s,
                        line: node_line(n),
                    });
                    continue;
                }
                let mut c = n.walk();
                for child in n.children(&mut c) {
                    stack.push(child);
                }
            }
            // Single-spec form: `import "fmt"` with no wrapping spec node.
            if ex.imports.iter().all(|i| i.line != line)
                && let Some(s) = find_first_string(node, source)
            {
                ex.imports.push(Import { target: s, line });
            }
        }
        Language::C | Language::Cpp => {
            if let Ok(text) = node.utf8_text(source) {
                // `#include "foo.h"` or `#include <foo.h>`
                if let Some(start) = text.find(['"', '<']) {
                    let close = if text.as_bytes()[start] == b'"' {
                        '"'
                    } else {
                        '>'
                    };
                    if let Some(end) = text[start + 1..].find(close) {
                        let inner = &text[start + 1..start + 1 + end];
                        ex.imports.push(Import {
                            target: inner.to_string(),
                            line,
                        });
                    }
                }
            }
        }
        Language::Unknown => {}
    }
}

/// First string-literal descendant's *content* (quotes stripped).
fn find_first_string(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        let k = n.kind();
        if (k == "string"
            || k == "string_literal"
            || k == "interpreted_string_literal"
            || k == "raw_string_literal")
            && let Ok(text) = n.utf8_text(source)
        {
            let trimmed = text.trim_matches(['"', '\'', '`']);
            return Some(trimmed.to_string());
        }
        let mut c = n.walk();
        // Push children in reverse so we visit earliest-first (stack).
        let children: Vec<_> = n.children(&mut c).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

// ---- identifiers + callsites (manual walk) ---------------------------------

const IDENTIFIER_KINDS: &[&str] = &[
    "identifier",
    "type_identifier",
    "field_identifier",
    "property_identifier",
    "namespace_identifier",
    "scoped_identifier",
    "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
];

/// One manual full-tree walk that captures identifier tokens (for the
/// `word` inverted index) and call-sites (for the call-graph layer —
/// `impact` + centrality, `src/intel/callgraph.rs`). Doing
/// both in one pass avoids two traversals.
fn walk_identifiers_and_calls(
    lang: Language,
    root: tree_sitter::Node,
    source: &[u8],
    ex: &mut Extraction,
) {
    // Stack of (node, enclosing-symbol-name).
    let mut stack: Vec<(tree_sitter::Node, Option<String>)> = vec![(root, None)];
    while let Some((node, enclosing)) = stack.pop() {
        let kind = node.kind();

        // Track the enclosing named definition so call-sites get a
        // `caller_symbol`.
        let next_enclosing = enclosing_for(lang, node, source).or(enclosing.clone());

        if IDENTIFIER_KINDS.contains(&kind)
            && let Ok(text) = node.utf8_text(source)
            && !text.is_empty()
            && text.len() <= 128
        {
            ex.identifiers.push(Identifier {
                token: text.to_string(),
                line: node_line(node),
            });
        }

        if let Some(cs) = callsite_for(node, source, &next_enclosing) {
            ex.callsites.push(cs);
        }

        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push((child, next_enclosing.clone()));
        }
    }
}

/// If `node` introduces a named definition, return its name so nested
/// call-sites can attribute their caller.
fn enclosing_for(lang: Language, node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let is_def = matches!(
        node.kind(),
        "function_item"
            | "function_declaration"
            | "function_definition"
            | "method_declaration"
            | "method_definition"
    );
    if !is_def {
        return None;
    }
    let _ = lang;
    let name = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(source).ok());
    // C/C++ function name lives under a function_declarator.
    let name = name.or_else(|| {
        node.child_by_field_name("declarator").and_then(|d| {
            d.child_by_field_name("declarator")
                .and_then(|n| n.utf8_text(source).ok())
        })
    });
    name.map(|s| s.to_string())
}

/// Classify a call-site node. Returns `None` for non-call nodes.
fn callsite_for(
    node: tree_sitter::Node,
    source: &[u8],
    enclosing: &Option<String>,
) -> Option<CallSite> {
    let kind = node.kind();
    let (callee_name, callee_kind) = match kind {
        "call_expression" | "call" | "new_expression" => {
            let func = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("constructor"))
                .or_else(|| node.named_child(0))?;
            (rightmost_identifier(func, source)?, "call")
        }
        "macro_invocation" => {
            let m = node
                .child_by_field_name("macro")
                .or_else(|| node.named_child(0))?;
            (m.utf8_text(source).ok()?.to_string(), "macro")
        }
        "composite_literal" => {
            // Go struct/type literal: `Foo{...}`. Skip if it's not a
            // bare type_identifier (avoid def sites / map/slice literals).
            let ty = node.child_by_field_name("type")?;
            if ty.kind() != "type_identifier" {
                return None;
            }
            (ty.utf8_text(source).ok()?.to_string(), "type_ref")
        }
        _ => return None,
    };
    Some(CallSite {
        caller_line: node_line(node),
        caller_symbol: enclosing.clone(),
        callee_name,
        callee_kind: callee_kind.to_string(),
    })
}

/// For `a.b.c()` the callee is `c`; for `a::b::c()` it's `c`. Walks
/// member/scoped expressions to the rightmost identifier.
fn rightmost_identifier(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cur = node;
    loop {
        match cur.kind() {
            "identifier" | "type_identifier" | "field_identifier" | "property_identifier" => {
                return cur.utf8_text(source).ok().map(|s| s.to_string());
            }
            "member_expression" | "field_expression" => {
                cur = cur
                    .child_by_field_name("property")
                    .or_else(|| cur.child_by_field_name("field"))?;
            }
            "scoped_identifier" | "scoped_type_identifier" | "qualified_identifier" => {
                cur = cur.child_by_field_name("name")?;
            }
            "selector_expression" => {
                cur = cur.child_by_field_name("field")?;
            }
            _ => {
                // Fall back to the last named child if it looks like an id.
                let count = cur.named_child_count() as u32;
                if count == 0 {
                    return None;
                }
                let last = cur.named_child(count - 1)?;
                if last == cur {
                    return None;
                }
                cur = last;
            }
        }
    }
}

// ---- regex outline fallback (Unknown languages) ----------------------------

/// A best-effort outline for files with no tree-sitter grammar. Returns
/// `(name, line)` pairs matched by simple def-like patterns so `outline`
/// can still say something useful instead of hard-erroring.
pub fn regex_outline(source: &str) -> Vec<(String, i64)> {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        // function / def / class / fn / func / type / struct definitions
        // across a grab-bag of curly/indent languages.
        Regex::new(
            r"(?m)^\s*(?:export\s+)?(?:public\s+|private\s+|protected\s+)?(?:async\s+)?(?:def|function|fn|func|class|struct|interface|type|enum|module|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
        )
        .expect("static regex compiles")
    });
    let mut out = Vec::new();
    for (i, line) in source.lines().enumerate() {
        if let Some(caps) = re.captures(line)
            && let Some(m) = caps.get(1)
        {
            out.push((m.as_str().to_string(), i as i64 + 1));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_languages_by_extension() {
        assert_eq!(Language::from_path(Path::new("a.rs")), Language::Rust);
        assert_eq!(Language::from_path(Path::new("a.ts")), Language::TypeScript);
        assert_eq!(Language::from_path(Path::new("a.tsx")), Language::Tsx);
        assert_eq!(Language::from_path(Path::new("a.py")), Language::Python);
        assert_eq!(Language::from_path(Path::new("a.go")), Language::Go);
        assert_eq!(Language::from_path(Path::new("a.cpp")), Language::Cpp);
        assert_eq!(Language::from_path(Path::new("a.txt")), Language::Unknown);
    }

    #[test]
    fn extracts_rust_symbols_and_imports() {
        let src = br#"
use std::collections::HashMap;
pub struct Widget { n: u32 }
impl Widget {
    pub fn frob(&self) -> u32 { self.n }
}
fn helper() {}
"#;
        let ex = extract(Language::Rust, src).unwrap();
        let names: Vec<_> = ex.symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"Widget"));
        assert!(names.contains(&"frob"));
        assert!(names.contains(&"helper"));
        let frob = ex.symbols.iter().find(|s| s.name == "frob").unwrap();
        assert_eq!(frob.parent.as_deref(), Some("Widget"));
        assert!(ex.imports.iter().any(|i| i.target.contains("HashMap")));
        assert!(ex.identifiers.iter().any(|i| i.token == "HashMap"));
    }

    #[test]
    fn extracts_python_symbols() {
        let src = br#"
import os
from collections import OrderedDict
MAX_SIZE = 10
def top(): pass
class Thing:
    def method(self): pass
"#;
        let ex = extract(Language::Python, src).unwrap();
        let names: Vec<_> = ex.symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"top"));
        assert!(names.contains(&"Thing"));
        assert!(names.contains(&"method"));
        assert!(names.contains(&"MAX_SIZE"));
        assert!(ex.imports.iter().any(|i| i.target == "os"));
        assert!(ex.imports.iter().any(|i| i.target == "collections"));
        let method = ex.symbols.iter().find(|s| s.name == "method").unwrap();
        assert_eq!(method.parent.as_deref(), Some("Thing"));
    }

    #[test]
    fn unknown_language_extracts_nothing() {
        let ex = extract(Language::Unknown, b"anything at all").unwrap();
        assert!(ex.symbols.is_empty());
        assert!(ex.imports.is_empty());
    }

    #[test]
    fn regex_outline_finds_defs() {
        let out = regex_outline("def foo():\n    pass\nclass Bar:\n    pass\n");
        let names: Vec<_> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"Bar"));
    }
}
