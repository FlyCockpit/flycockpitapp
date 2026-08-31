use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[path = "support/schema_parser.rs"]
mod schema_parser;

const SCHEMA: &str = include_str!("../src/db/migrations/0001_initial.sql");
const EXTENDED_SCHEMA: &str = include_str!("../src/db/migrations/0001_extended_profile.sql");
const RELATIONSHIP_INVENTORY: &str = include_str!("support/relationship_inventory.tsv");
const LOCAL_SCHEMA_REVIEW_DIGEST: &str =
    "5b76b3cf9fa5a27e60bdfdd7f6f1f0d43ea2efd45837876d4f1a382e404748e6";
const EXTENDED_SCHEMA_REVIEW_DIGEST: &str =
    "36644ef610a8281c08bd86ad531566d1672d6184bb9e0514e079ff2a934565f5";
const RELATIONSHIP_INVENTORY_REVIEW_DIGEST: &str =
    "c0900b1faf06a514fa326f7cc0f21cc1db6174c3dc350a778638493fe73cd0df";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RelationshipClass {
    NonRelationship,
    Primary,
    LocalIdentity,
    Foreign,
    External,
    Polymorphic,
    Denormalized,
}

fn relationship_inventory()
-> std::collections::BTreeMap<(String, String, String), RelationshipClass> {
    assert_eq!(
        RELATIONSHIP_INVENTORY.lines().next(),
        Some("# profile\ttable\tcolumn\tclass"),
        "relationship inventory header drifted"
    );
    let reviewed_rows = RELATIONSHIP_INVENTORY
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert!(
        reviewed_rows.windows(2).all(|rows| rows[0] < rows[1]),
        "relationship inventory must be strictly sorted"
    );
    let mut inventory = std::collections::BTreeMap::new();
    for line in reviewed_rows {
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(
            fields.len(),
            4,
            "invalid relationship inventory row: {line}"
        );
        assert!(
            matches!(fields[0], "local" | "extended"),
            "unknown schema profile in relationship inventory: {line}"
        );
        let class = match fields[3] {
            "non_relationship" => RelationshipClass::NonRelationship,
            "primary" => RelationshipClass::Primary,
            "local_identity" => RelationshipClass::LocalIdentity,
            "foreign" => RelationshipClass::Foreign,
            "external" => RelationshipClass::External,
            "polymorphic" => RelationshipClass::Polymorphic,
            "denormalized" => RelationshipClass::Denormalized,
            value => panic!("unknown relationship class {value}: {line}"),
        };
        let prior = inventory.insert(
            (
                fields[0].to_owned(),
                fields[1].to_owned(),
                fields[2].to_owned(),
            ),
            class,
        );
        assert!(
            prior.is_none(),
            "duplicate relationship inventory row: {line}"
        );
    }
    inventory
}

fn classified_columns(
    schema: &schema_parser::Schema,
    objects: &std::collections::BTreeSet<String>,
) -> std::collections::BTreeSet<(String, String)> {
    schema_parser::classified_objects(schema)
        .filter(|(object, _)| objects.contains(*object))
        .flat_map(|(object, columns)| {
            columns
                .iter()
                .cloned()
                .map(move |column| (object.to_owned(), column))
        })
        .collect()
}

fn source(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(path).expect("read production query owner")
}

#[derive(Clone, Copy)]
struct SourceSpan {
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

fn literal_spans(source: &str) -> Vec<SourceSpan> {
    fn record_macro_literals(tokens: proc_macro2::TokenStream, output: &mut Vec<SourceSpan>) {
        for token in tokens {
            match token {
                proc_macro2::TokenTree::Group(group) => {
                    record_macro_literals(group.stream(), output);
                }
                proc_macro2::TokenTree::Literal(literal) => {
                    let start = literal.span().start();
                    let end = literal.span().end();
                    output.push(SourceSpan {
                        start_line: start.line,
                        start_column: start.column,
                        end_line: end.line,
                        end_column: end.column,
                    });
                }
                _ => {}
            }
        }
    }

    struct Literals(Vec<SourceSpan>);
    impl<'ast> syn::visit::Visit<'ast> for Literals {
        fn visit_lit(&mut self, literal: &'ast syn::Lit) {
            let start = syn::spanned::Spanned::span(literal).start();
            let end = syn::spanned::Spanned::span(literal).end();
            self.0.push(SourceSpan {
                start_line: start.line,
                start_column: start.column,
                end_line: end.line,
                end_column: end.column,
            });
        }

        fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
            record_macro_literals(invocation.tokens.clone(), &mut self.0);
        }
    }
    let mut literals = Literals(Vec::new());
    syn::visit::Visit::visit_file(&mut literals, &syn::parse_file(source).unwrap());
    literals.0
}

fn span_contains(span: SourceSpan, line: usize, column: usize) -> bool {
    (line > span.start_line || line == span.start_line && column >= span.start_column)
        && (line < span.end_line || line == span.end_line && column < span.end_column)
}

fn hot_query_comments(source: &str) -> Vec<(usize, String)> {
    let literal_spans = literal_spans(source);
    let mut markers = Vec::new();
    let mut block_comment_depth = 0_u32;
    for (line_offset, line) in source.lines().enumerate() {
        let line_number = line_offset + 1;
        let bytes = line.as_bytes();
        let mut column = 0;
        while column + 1 < bytes.len() {
            if literal_spans
                .iter()
                .any(|span| span_contains(*span, line_number, column))
            {
                column += 1;
                continue;
            }
            match (bytes[column], bytes[column + 1], block_comment_depth) {
                (b'/', b'*', _) => {
                    block_comment_depth = block_comment_depth
                        .checked_add(1)
                        .expect("Rust block-comment nesting overflow");
                    column += 2;
                }
                (b'*', b'/', depth) if depth > 0 => {
                    block_comment_depth -= 1;
                    column += 2;
                }
                (b'/', b'/', 0) => {
                    if let Some(marker) =
                        line[column + 2..].trim().strip_prefix("schema-hot-query:")
                    {
                        assert!(
                            line[..column].trim().is_empty(),
                            "hot-query marker must be a standalone line comment"
                        );
                        let marker = marker.trim();
                        assert!(!marker.is_empty(), "hot-query marker cannot be empty");
                        markers.push((line_number, marker.to_owned()));
                    }
                    break;
                }
                _ => column += 1,
            }
        }
    }
    assert_eq!(
        block_comment_depth, 0,
        "unterminated Rust block comment in query owner"
    );
    markers
}

fn annotated_sql_literal(source: &str, marker: &str) -> String {
    struct Literals(Vec<(usize, String)>);
    impl<'ast> syn::visit::Visit<'ast> for Literals {
        fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
            self.0.push((literal.span().start().line, literal.value()));
        }
    }
    let marker_lines = hot_query_comments(source)
        .into_iter()
        .filter(|(_, candidate)| candidate == marker)
        .map(|(line, _)| line)
        .collect::<Vec<_>>();
    assert_eq!(
        marker_lines.len(),
        1,
        "marker must occur exactly once: {marker}"
    );
    let syntax = syn::parse_file(source).unwrap();
    let mut literals = Literals(Vec::new());
    syn::visit::Visit::visit_file(&mut literals, &syntax);
    let bound = literals
        .0
        .into_iter()
        .filter(|(line, _)| *line == marker_lines[0] + 1)
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    assert_eq!(
        bound.len(),
        1,
        "hot-query marker must immediately precede exactly one Rust SQL literal: {marker}"
    );
    let bound = bound.into_iter().next().unwrap();

    struct ContainsLiteral {
        line: usize,
        found: bool,
    }
    impl<'ast> syn::visit::Visit<'ast> for ContainsLiteral {
        fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
            self.found |= literal.span().start().line == self.line;
        }
    }
    fn exact_literal_value(expression: &syn::Expr, line: usize) -> bool {
        matches!(
            expression,
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(literal),
                ..
            }) if literal.span().start().line == line
        )
    }
    fn block_contains_literal(block: &syn::Block, line: usize) -> bool {
        let mut visitor = ContainsLiteral { line, found: false };
        syn::visit::Visit::visit_block(&mut visitor, block);
        visitor.found
    }
    fn path_identifier(expression: &syn::Expr) -> Option<String> {
        let syn::Expr::Path(path) = expression else {
            return None;
        };
        (path.path.segments.len() == 1).then(|| path.path.segments[0].ident.to_string())
    }
    fn macro_tokens_touch_any(
        tokens: proc_macro2::TokenStream,
        names: &std::collections::BTreeSet<String>,
    ) -> bool {
        tokens.into_iter().any(|token| match token {
            proc_macro2::TokenTree::Ident(identifier) => names.contains(&identifier.to_string()),
            proc_macro2::TokenTree::Group(group) => macro_tokens_touch_any(group.stream(), names),
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
        })
    }
    fn canonical_connection_imports(syntax: &syn::File) -> std::collections::BTreeSet<String> {
        fn inspect(
            tree: &syn::UseTree,
            prefix: &mut Vec<String>,
            output: &mut std::collections::BTreeSet<String>,
        ) {
            match tree {
                syn::UseTree::Path(path) => {
                    prefix.push(path.ident.to_string());
                    inspect(&path.tree, prefix, output);
                    prefix.pop();
                }
                syn::UseTree::Name(name)
                    if prefix.len() == 1
                        && prefix[0] == "rusqlite"
                        && name.ident == "Connection" =>
                {
                    output.insert("Connection".to_owned());
                }
                syn::UseTree::Rename(rename)
                    if prefix.len() == 1
                        && prefix[0] == "rusqlite"
                        && rename.ident == "Connection" =>
                {
                    output.insert(rename.rename.to_string());
                }
                syn::UseTree::Group(group) => {
                    for item in &group.items {
                        inspect(item, prefix, output);
                    }
                }
                syn::UseTree::Name(_) | syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {}
            }
        }
        fn binds_name(tree: &syn::UseTree, target: &str, prefix: &mut Vec<String>) -> bool {
            match tree {
                syn::UseTree::Path(path) => {
                    prefix.push(path.ident.to_string());
                    let found = binds_name(&path.tree, target, prefix);
                    prefix.pop();
                    found
                }
                syn::UseTree::Name(name) => {
                    name.ident == target
                        || name.ident == "self" && prefix.last().is_some_and(|name| name == target)
                }
                syn::UseTree::Rename(rename) => rename.rename == target,
                syn::UseTree::Group(group) => group
                    .items
                    .iter()
                    .any(|item| binds_name(item, target, prefix)),
                syn::UseTree::Glob(_) => false,
            }
        }
        let mut output = std::collections::BTreeSet::new();
        for item in &syntax.items {
            if let syn::Item::Use(item) = item {
                inspect(&item.tree, &mut Vec::new(), &mut output);
            }
        }
        let reserved = output
            .iter()
            .cloned()
            .chain(std::iter::once("rusqlite".to_owned()))
            .collect::<std::collections::BTreeSet<_>>();
        for item in &syntax.items {
            if let syn::Item::Use(item) = item {
                assert!(
                    !binds_name(&item.tree, "rusqlite", &mut Vec::new()),
                    "external rusqlite path is shadowed by a use binding"
                );
            }
            let shadow = match item {
                syn::Item::Type(item) => Some(item.ident.to_string()),
                syn::Item::Struct(item) => Some(item.ident.to_string()),
                syn::Item::Enum(item) => Some(item.ident.to_string()),
                syn::Item::Union(item) => Some(item.ident.to_string()),
                syn::Item::Mod(item) => Some(item.ident.to_string()),
                syn::Item::Trait(item) => Some(item.ident.to_string()),
                syn::Item::TraitAlias(item) => Some(item.ident.to_string()),
                syn::Item::ExternCrate(item) => Some(
                    item.rename
                        .as_ref()
                        .map_or_else(|| item.ident.to_string(), |(_, name)| name.to_string()),
                ),
                _ => None,
            };
            assert!(
                !shadow.as_ref().is_some_and(|name| reserved.contains(name)),
                "canonical rusqlite::Connection import is shadowed by a local item"
            );
        }
        output
    }
    struct SqlBinding<'a> {
        line: usize,
        connections: &'a std::collections::BTreeSet<String>,
        variable: Option<&'a str>,
        direct_only: bool,
        nested_depth: usize,
        uses: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for SqlBinding<'_> {
        fn visit_block(&mut self, block: &'ast syn::Block) {
            self.nested_depth += 1;
            syn::visit::visit_block(self, block);
            self.nested_depth -= 1;
        }

        fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
            self.nested_depth += 1;
            syn::visit::visit_expr_closure(self, closure);
            self.nested_depth -= 1;
        }

        fn visit_expr_async(&mut self, block: &'ast syn::ExprAsync) {
            self.nested_depth += 1;
            syn::visit::visit_expr_async(self, block);
            self.nested_depth -= 1;
        }

        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            if self.variable.is_some_and(|variable| {
                path.path.segments.len() == 1 && path.path.is_ident(variable)
            }) {
                self.uses += 1;
            }
            syn::visit::visit_expr_path(self, path);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            let method = call.method.to_string();
            if matches!(
                method.as_str(),
                "prepare" | "prepare_cached" | "execute" | "query_row" | "query_row_and_then"
            ) && path_identifier(&call.receiver)
                .is_some_and(|identifier| self.connections.contains(&identifier))
                && let Some(sql) = call.args.first()
            {
                let exact_argument = exact_literal_value(sql, self.line)
                    || self
                        .variable
                        .is_some_and(|variable| path_identifier(sql).as_deref() == Some(variable));
                if exact_argument && (!self.direct_only || self.nested_depth == 0) {
                    self.uses += 1;
                }
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    struct BindingScope {
        line: usize,
        consumed: bool,
        imported_connections: std::collections::BTreeSet<String>,
        enclosing_generic_shadow: bool,
    }
    impl BindingScope {
        fn is_connection_type(&self, ty: &syn::Type) -> bool {
            match ty {
                syn::Type::Reference(reference) => self.is_connection_type(&reference.elem),
                syn::Type::Path(path) => {
                    let segments = path
                        .path
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect::<Vec<_>>();
                    segments == ["rusqlite", "Connection"]
                        || segments.len() == 1 && self.imported_connections.contains(&segments[0])
                }
                _ => false,
            }
        }

        fn inspect(&mut self, signature: &syn::Signature, block: &syn::Block) {
            if !block_contains_literal(block, self.line) {
                return;
            }
            if self.enclosing_generic_shadow
                || signature.generics.params.iter().any(|parameter| {
                    matches!(parameter, syn::GenericParam::Type(parameter)
                    if parameter.ident == "rusqlite"
                        || self.imported_connections.contains(&parameter.ident.to_string()))
                })
            {
                return;
            }
            let connections = signature
                .inputs
                .iter()
                .filter_map(|argument| {
                    let syn::FnArg::Typed(argument) = argument else {
                        return None;
                    };
                    let syn::Pat::Ident(binding) = argument.pat.as_ref() else {
                        return None;
                    };
                    self.is_connection_type(&argument.ty)
                        .then(|| binding.ident.to_string())
                })
                .collect::<std::collections::BTreeSet<_>>();
            if connections.is_empty() {
                return;
            }
            struct ConnectionMutation<'a> {
                names: &'a std::collections::BTreeSet<String>,
                found: bool,
            }
            impl<'ast> syn::visit::Visit<'ast> for ConnectionMutation<'_> {
                fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
                    self.found |= self.names.contains(&pattern.ident.to_string());
                    syn::visit::visit_pat_ident(self, pattern);
                }

                fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
                    self.found |= path_identifier(&assignment.left)
                        .is_some_and(|identifier| self.names.contains(&identifier));
                    syn::visit::visit_expr_assign(self, assignment);
                }

                fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
                    self.found |= macro_tokens_touch_any(invocation.tokens.clone(), self.names);
                    syn::visit::visit_macro(self, invocation);
                }
            }
            let mut connection_mutation = ConnectionMutation {
                names: &connections,
                found: false,
            };
            syn::visit::Visit::visit_block(&mut connection_mutation, block);
            if connection_mutation.found {
                return;
            }

            let reviewed_locals = block
                .stmts
                .iter()
                .enumerate()
                .filter_map(|(index, statement)| match statement {
                    syn::Stmt::Local(local)
                        if local
                            .init
                            .as_ref()
                            .is_some_and(|init| exact_literal_value(&init.expr, self.line)) =>
                    {
                        Some((index, local))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            if reviewed_locals.is_empty() {
                let mut binding = SqlBinding {
                    line: self.line,
                    connections: &connections,
                    variable: None,
                    direct_only: true,
                    nested_depth: 0,
                    uses: 0,
                };
                for statement in &block.stmts {
                    syn::visit::Visit::visit_stmt(&mut binding, statement);
                }
                self.consumed |= binding.uses == 1;
                return;
            }
            if reviewed_locals.len() != 1 {
                return;
            }
            let (definition, local) = reviewed_locals[0];
            let syn::Pat::Ident(pattern) = &local.pat else {
                return;
            };
            if pattern.by_ref.is_some() || pattern.mutability.is_some() || pattern.subpat.is_some()
            {
                return;
            }
            let variable = pattern.ident.to_string();
            let pattern_count = {
                struct Patterns<'a> {
                    name: &'a str,
                    count: usize,
                }
                impl<'ast> syn::visit::Visit<'ast> for Patterns<'_> {
                    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
                        self.count += usize::from(pattern.ident == self.name);
                        syn::visit::visit_pat_ident(self, pattern);
                    }

                    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
                        let names = std::collections::BTreeSet::from([self.name.to_owned()]);
                        self.count +=
                            usize::from(macro_tokens_touch_any(invocation.tokens.clone(), &names));
                        syn::visit::visit_macro(self, invocation);
                    }
                }
                let mut patterns = Patterns {
                    name: &variable,
                    count: 0,
                };
                syn::visit::Visit::visit_block(&mut patterns, block);
                patterns.count
            };
            if pattern_count != 1 {
                return;
            }
            let mut binding = SqlBinding {
                line: self.line,
                connections: &connections,
                variable: Some(&variable),
                direct_only: true,
                nested_depth: 0,
                uses: 0,
            };
            for statement in &block.stmts[definition + 1..] {
                syn::visit::Visit::visit_stmt(&mut binding, statement);
            }
            // One path occurrence plus one exact SQL-argument recognition.
            // Any shadow, reassignment, alias, wrapper, or second use changes
            // this count and fails closed.
            self.consumed |= binding.uses == 2;
        }
    }
    impl<'ast> syn::visit::Visit<'ast> for BindingScope {
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let prior = self.enclosing_generic_shadow;
            self.enclosing_generic_shadow |= item.generics.params.iter().any(|parameter| {
                matches!(parameter, syn::GenericParam::Type(parameter)
                    if parameter.ident == "rusqlite"
                        || self.imported_connections.contains(&parameter.ident.to_string()))
            });
            syn::visit::visit_item_impl(self, item);
            self.enclosing_generic_shadow = prior;
        }

        fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
            let prior = self.enclosing_generic_shadow;
            self.enclosing_generic_shadow |= item.generics.params.iter().any(|parameter| {
                matches!(parameter, syn::GenericParam::Type(parameter)
                    if parameter.ident == "rusqlite"
                        || self.imported_connections.contains(&parameter.ident.to_string()))
            });
            syn::visit::visit_item_trait(self, item);
            self.enclosing_generic_shadow = prior;
        }

        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            self.inspect(&function.sig, &function.block);
        }

        fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
            self.inspect(&function.sig, &function.block);
        }

        fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
            if let Some(block) = &function.default {
                self.inspect(&function.sig, block);
            }
        }

        fn visit_item_mod(&mut self, _module: &'ast syn::ItemMod) {
            // An unqualified import at the file root cannot prove the type
            // binding inside an independently scoped inline module.
        }
    }
    let mut sql_binding = BindingScope {
        line: marker_lines[0] + 1,
        consumed: false,
        imported_connections: canonical_connection_imports(&syntax),
        enclosing_generic_shadow: false,
    };
    syn::visit::Visit::visit_file(&mut sql_binding, &syntax);
    assert!(
        sql_binding.consumed,
        "hot-query marker must bind to the SQL argument of a rusqlite query method: {marker}"
    );
    bound
}

fn normalized_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn hot_query_binding_rejects_duplicate_and_ignores_unrelated_literals() {
    let stale = r#"
        use rusqlite::Connection;
        fn owner(conn: &Connection) {
            let unrelated = "SELECT stale FROM elsewhere";
            conn.prepare(
                // schema-hot-query: reviewed.shape
                "SELECT exact FROM owned WHERE id=?1"
            );
        }
    "#;
    assert_eq!(
        annotated_sql_literal(stale, "reviewed.shape"),
        "SELECT exact FROM owned WHERE id=?1"
    );
    let duplicate = r#"
        fn owner(conn: &Connection) {
            // schema-hot-query: reviewed.shape
            let one = "SELECT 1";
            // schema-hot-query: reviewed.shape
            let two = "SELECT 2";
        }
    "#;
    assert!(
        std::panic::catch_unwind(|| annotated_sql_literal(duplicate, "reviewed.shape")).is_err()
    );
    let dead = r#"
        use rusqlite::Connection;
        fn owner(conn: &Connection) {
            // schema-hot-query: reviewed.shape
            let reviewed = "SELECT exact FROM owned WHERE id=?1";
            conn.prepare("SELECT drifted FROM owned");
        }
    "#;
    assert!(
        std::panic::catch_unwind(|| annotated_sql_literal(dead, "reviewed.shape")).is_err(),
        "dead reviewed literal was mistaken for the executed query"
    );
    let fake_connection = r#"
        fn owner(fake: &FakeConnection) {
            fake.prepare(
                // schema-hot-query: reviewed.shape
                "SELECT exact FROM owned WHERE id=?1"
            );
        }
    "#;
    assert!(
        std::panic::catch_unwind(|| { annotated_sql_literal(fake_connection, "reviewed.shape") })
            .is_err(),
        "non-rusqlite prepare-like method was mistaken for a database query"
    );
    let imported_alias = r#"
        use rusqlite::Connection as DbConnection;
        fn owner(conn: &DbConnection) {
            conn.prepare(
                // schema-hot-query: reviewed.shape
                "SELECT exact FROM owned WHERE id=?1"
            );
        }
    "#;
    assert_eq!(
        annotated_sql_literal(imported_alias, "reviewed.shape"),
        "SELECT exact FROM owned WHERE id=?1"
    );
    for adversarial in [
        r#"
            struct Connection;
            fn owner(conn: &Connection) {
                conn.prepare(
                    // schema-hot-query: reviewed.shape
                    "SELECT exact FROM owned WHERE id=?1"
                );
            }
        "#,
        r#"
            use rusqlite::Connection as DbConnection;
            type DbConnection = FakeConnection;
            fn owner(conn: &DbConnection) {
                conn.prepare(
                    // schema-hot-query: reviewed.shape
                    "SELECT exact FROM owned WHERE id=?1"
                );
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let sql = "SELECT exact FROM owned WHERE id=?1";
                let sql = "SELECT drifted FROM owned";
                conn.prepare(sql);
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection, choose_reviewed: bool) {
                // schema-hot-query: reviewed.shape
                let sql = if choose_reviewed { "SELECT exact FROM owned WHERE id=?1" } else { "SELECT drifted FROM owned" };
                conn.prepare(sql);
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection, choice: u8) {
                // schema-hot-query: reviewed.shape
                let sql = match choice { 0 => "SELECT exact FROM owned WHERE id=?1", _ => "SELECT drifted FROM owned" };
                conn.prepare(sql);
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let sql = ("SELECT exact FROM owned WHERE id=?1");
                conn.prepare(sql);
            }
        "#,
        r#"
            use rusqlite::Connection;
            struct Owner<T>(T);
            impl<Connection> Owner<Connection> {
                fn owner(conn: &Connection) {
                    conn.prepare(
                        // schema-hot-query: reviewed.shape
                        "SELECT exact FROM owned WHERE id=?1"
                    );
                }
            }
        "#,
        r#"
            use rusqlite::Connection as DbConnection;
            trait Owner<DbConnection> {
                fn owner(conn: &DbConnection) {
                    conn.prepare(
                        // schema-hot-query: reviewed.shape
                        "SELECT exact FROM owned WHERE id=?1"
                    );
                }
            }
        "#,
        r#"
            use rusqlite::Connection;
            macro_rules! shadow { ($name:ident) => { let $name = FakeConnection; }; }
            fn owner(conn: &Connection) {
                shadow!(conn);
                conn.prepare(
                    // schema-hot-query: reviewed.shape
                    "SELECT exact FROM owned WHERE id=?1"
                );
            }
        "#,
        r#"
            use rusqlite::Connection;
            macro_rules! shadow { ($name:ident) => { let $name = "SELECT drifted FROM owned"; }; }
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let sql = "SELECT exact FROM owned WHERE id=?1";
                shadow!(sql);
                conn.prepare(sql);
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let sql = ("SELECT exact FROM owned WHERE id=?1", "SELECT drifted FROM owned").1;
                conn.prepare(sql);
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                conn.prepare(
                    // schema-hot-query: reviewed.shape
                    ("SELECT exact FROM owned WHERE id=?1", "SELECT drifted FROM owned").1
                );
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let sql = choose("SELECT exact FROM owned WHERE id=?1", "SELECT drifted FROM owned");
                conn.prepare(sql);
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let sql = { let ignored = "SELECT exact FROM owned WHERE id=?1"; "SELECT drifted FROM owned" };
                conn.prepare(sql);
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let sql = format!("SELECT exact FROM owned WHERE id={}", 1);
                conn.prepare(&sql);
            }
        "#,
        r#"
            mod rusqlite {
                pub struct Connection;
            }
            fn owner(conn: &rusqlite::Connection) {
                conn.prepare(
                    // schema-hot-query: reviewed.shape
                    "SELECT exact FROM owned WHERE id=?1"
                );
            }
        "#,
        r#"
            use fake_database as rusqlite;
            fn owner(conn: &rusqlite::Connection) {
                conn.prepare(
                    // schema-hot-query: reviewed.shape
                    "SELECT exact FROM owned WHERE id=?1"
                );
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner<Connection>(conn: &Connection) {
                conn.prepare(
                    // schema-hot-query: reviewed.shape
                    "SELECT exact FROM owned WHERE id=?1"
                );
            }
        "#,
        r#"
            use rusqlite::Connection;
            mod nested {
                struct Connection;
                fn owner(conn: &Connection) {
                    conn.prepare(
                        // schema-hot-query: reviewed.shape
                        "SELECT exact FROM owned WHERE id=?1"
                    );
                }
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let mut sql = "SELECT exact FROM owned WHERE id=?1";
                sql = "SELECT drifted FROM owned";
                conn.prepare(sql);
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let sql = "SELECT exact FROM owned WHERE id=?1";
                { let sql = "SELECT drifted FROM owned"; conn.prepare(sql); }
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let sql = "SELECT exact FROM owned WHERE id=?1";
                let moved = sql;
                conn.prepare(moved);
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                // schema-hot-query: reviewed.shape
                let sql = "SELECT exact FROM owned WHERE id=?1";
                let deferred = || conn.prepare(sql);
                deferred();
            }
        "#,
        r#"
            use rusqlite::Connection;
            fn owner(conn: &Connection) {
                let conn = FakeConnection;
                conn.prepare(
                    // schema-hot-query: reviewed.shape
                    "SELECT exact FROM owned WHERE id=?1"
                );
            }
        "#,
    ] {
        assert!(
            std::panic::catch_unwind(|| annotated_sql_literal(adversarial, "reviewed.shape"))
                .is_err(),
            "accepted spoofed, shadowed, reassigned, or moved SQL binding: {adversarial}"
        );
    }
    let spoofed = r###"
        use rusqlite::Connection;
        fn owner(conn: &Connection) {
            let raw = r#"
                // schema-hot-query: reviewed.shape
            "#;
            /*
                // schema-hot-query: reviewed.shape
            */
            println!(r#"
                // schema-hot-query: reviewed.shape
            "#);
            conn.prepare(
                // schema-hot-query: reviewed.shape
                "SELECT exact FROM owned WHERE id=?1"
            );
        }
    "###;
    assert_eq!(
        hot_query_comments(spoofed),
        vec![(14, "reviewed.shape".to_owned())]
    );
    assert_eq!(
        annotated_sql_literal(spoofed, "reviewed.shape"),
        "SELECT exact FROM owned WHERE id=?1"
    );
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_sources_below(root: &Path, relative: &Path, output: &mut Vec<PathBuf>) {
    let directory = root.join(relative);
    for entry in std::fs::read_dir(&directory).expect("read production source directory") {
        let entry = entry.expect("read production source entry");
        let path = entry.path();
        let child = relative.join(entry.file_name());
        if path.is_dir() {
            rust_sources_below(root, &child, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(child);
        }
    }
}

fn production_rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut output = Vec::new();
    for family in ["apps", "crates"] {
        let family_root = root.join(family);
        for entry in std::fs::read_dir(&family_root).expect("read Rust workspace family") {
            let entry = entry.expect("read Rust workspace member");
            if !entry.path().is_dir() {
                continue;
            }
            let relative_src = Path::new(family).join(entry.file_name()).join("src");
            if root.join(&relative_src).is_dir() {
                rust_sources_below(root, &relative_src, &mut output);
            }
        }
    }
    output.sort();
    output
}

fn portable_relative_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn effective_profiles() -> [(&'static str, schema_parser::Schema); 2] {
    [
        ("local", schema_parser::parse(&[SCHEMA])),
        ("extended", schema_parser::parse(&[SCHEMA, EXTENDED_SCHEMA])),
    ]
}

fn schema_digest(schema: &str) -> String {
    Sha256::digest(schema.as_bytes())
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[test]
fn effective_schema_profiles_are_ordered_closed_and_indexed() {
    let [(local_name, local), (extended_name, extended)] = effective_profiles();
    assert_eq!(local_name, "local");
    assert_eq!(extended_name, "extended");
    assert!(
        local
            .tables
            .keys()
            .all(|table| extended.tables.contains_key(table)),
        "extended must apply after, and retain every table from, local 0001"
    );
    assert!(
        extended.tables.len() > local.tables.len(),
        "extended profile must add its deferred-domain inventory"
    );
    assert_eq!(
        local.objects.len(),
        658,
        "local ordered object inventory drifted"
    );
    assert_eq!(
        extended.objects.len(),
        883,
        "extended ordered object inventory drifted"
    );
    assert!(
        extended.objects.starts_with(&local.objects),
        "extended objects must retain the exact ordered local prefix"
    );
    let view = local
        .objects
        .iter()
        .find(|object| object.name == "tool_call_stats")
        .expect("reviewed tool_call_stats view");
    assert_eq!(view.kind, schema_parser::ObjectKind::View);
    assert_eq!(view.owner.as_deref(), Some("tool_call_events"));
    assert_eq!(
        view.columns.as_slice(),
        [
            "event_id",
            "session_id",
            "call_id",
            "timestamp",
            "model",
            "provider",
            "project_id",
            "project_root",
            "tool",
            "path",
            "language",
            "recovery_kind",
            "recovery_stage",
            "hard_fail",
            "shape_fingerprint",
            "recoverable",
            "severity",
        ]
    );
    let fts = local
        .objects
        .iter()
        .find(|object| object.name == "session_fts")
        .expect("reviewed session_fts virtual table");
    assert_eq!(fts.kind, schema_parser::ObjectKind::VirtualTable);
    assert_eq!(fts.columns.as_slice(), ["body"]);

    for (profile, schema) in [(local_name, &local), (extended_name, &extended)] {
        for (table_name, table) in &schema.tables {
            for foreign_key in &table.foreign_keys {
                assert!(
                    matches!(
                        foreign_key.on_delete.as_deref(),
                        Some("cascade" | "restrict" | "set null" | "set default" | "no action")
                    ),
                    "{profile}.{table_name} lacks an explicit ON DELETE action: {foreign_key:?}"
                );
                assert_eq!(
                    foreign_key.on_update.as_deref(),
                    Some("restrict"),
                    "{profile}.{table_name} permits referenced identity mutation: {foreign_key:?}"
                );
                assert!(
                    schema.tables.contains_key(&foreign_key.target_table),
                    "{profile}.{table_name} references absent target {}",
                    foreign_key.target_table
                );
                assert!(
                    schema_parser::exact_target_keys(schema, &foreign_key.target_table)
                        .contains(&foreign_key.target_columns),
                    "{profile}.{table_name} references non-key {}({:?})",
                    foreign_key.target_table,
                    foreign_key.target_columns
                );
                assert!(
                    schema_parser::child_leading_keys(
                        schema,
                        table_name,
                        &foreign_key.target_table,
                        &foreign_key.child_columns,
                        &foreign_key.target_columns,
                    )
                    .iter()
                    .any(|key| key.starts_with(&foreign_key.child_columns)),
                    "{profile}.{table_name} foreign key {:?} lacks a usable leading child index",
                    foreign_key.child_columns
                );
            }
        }
    }

    assert!(
        std::panic::catch_unwind(|| schema_parser::parse(&[EXTENDED_SCHEMA])).is_err(),
        "the extended layer unexpectedly became a standalone or first-applied schema"
    );
}

fn validate_relationship_inventory(
    profile: &str,
    schema: &schema_parser::Schema,
    owned_objects: std::collections::BTreeSet<String>,
    effective_rows: &std::collections::BTreeMap<(String, String), RelationshipClass>,
) -> Result<(), String> {
    let expected = classified_columns(schema, &owned_objects);
    let actual = effective_rows
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{profile} relationship inventory differs: missing={:?}, stale={:?}",
            expected.difference(&actual).collect::<Vec<_>>(),
            actual.difference(&expected).collect::<Vec<_>>()
        ));
    }
    for (table, column) in &actual {
        if !owned_objects.contains(table) || !expected.contains(&(table.clone(), column.clone())) {
            return Err(format!(
                "{profile} inventory names absent column {table}.{column}"
            ));
        }
    }

    let foreign = owned_objects
        .iter()
        .filter(|table_name| schema.tables.contains_key(*table_name))
        .flat_map(|table_name| {
            schema.tables[table_name]
                .foreign_keys
                .iter()
                .flat_map(|foreign_key| {
                    foreign_key
                        .child_columns
                        .iter()
                        .map(|column| (table_name.clone(), column.clone()))
                })
        })
        .collect::<std::collections::BTreeSet<_>>();
    let classified_foreign = effective_rows
        .iter()
        .filter(|(_, class)| **class == RelationshipClass::Foreign)
        .map(|(identity, _)| identity.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if classified_foreign != foreign {
        return Err(format!(
            "{profile} Foreign classification is not bidirectional: classified={classified_foreign:?}, parsed={foreign:?}"
        ));
    }

    for ((table_name, column), class) in effective_rows {
        let table = schema.tables.get(table_name);
        let primary = table.is_some_and(|table| {
            table
                .primary_keys
                .iter()
                .any(|key| key.terms.iter().any(|term| term.column == column.as_str()))
        });
        let unique = table.is_some_and(|table| {
            table
                .unique_keys
                .iter()
                .any(|key| key.terms.len() == 1 && key.terms[0].column == column.as_str())
        }) || schema.indexes.iter().any(|index| {
            index.table == table_name.as_str()
                && index.unique
                && index.predicate.is_none()
                && index.terms.len() == 1
                && index.terms[0].column == column.as_str()
        });
        match class {
            RelationshipClass::Primary if !primary => {
                return Err(format!("{profile}.{table_name}.{column} is not PK-owned"));
            }
            RelationshipClass::LocalIdentity if primary || !unique => {
                return Err(format!(
                    "{profile}.{table_name}.{column} is not solely nonpartial-UNIQUE-owned"
                ));
            }
            RelationshipClass::Foreign
                if !foreign.contains(&(table_name.clone(), column.clone())) =>
            {
                return Err(format!(
                    "{profile}.{table_name}.{column} is not an FK child"
                ));
            }
            RelationshipClass::NonRelationship
                if primary || unique || foreign.contains(&(table_name.clone(), column.clone())) =>
            {
                return Err(format!(
                    "{profile}.{table_name}.{column} hides a structural relationship as non_relationship"
                ));
            }
            _ => {}
        }
        if primary
            && !foreign.contains(&(table_name.clone(), column.clone()))
            && *class != RelationshipClass::Primary
        {
            return Err(format!(
                "{profile}.{table_name}.{column} hides primary identity as {class:?}"
            ));
        }
        if unique
            && !primary
            && !foreign.contains(&(table_name.clone(), column.clone()))
            && *class != RelationshipClass::LocalIdentity
        {
            return Err(format!(
                "{profile}.{table_name}.{column} hides local unique identity as {class:?}"
            ));
        }
    }
    Ok(())
}

#[test]
fn identifier_relationship_map_is_exhaustive_and_schema_owned() {
    assert_eq!(schema_digest(SCHEMA), LOCAL_SCHEMA_REVIEW_DIGEST);
    assert_eq!(
        schema_digest(EXTENDED_SCHEMA),
        EXTENDED_SCHEMA_REVIEW_DIGEST
    );
    assert_eq!(
        schema_digest(RELATIONSHIP_INVENTORY),
        RELATIONSHIP_INVENTORY_REVIEW_DIGEST
    );
    let [(_, local), (_, extended)] = effective_profiles();
    let inventory = relationship_inventory();
    let local_objects = schema_parser::classified_objects(&local)
        .map(|(object, _)| object.to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let extended_objects = schema_parser::classified_objects(&extended)
        .map(|(object, _)| object.to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let deferred_objects = extended_objects
        .difference(&local_objects)
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();

    let manifest_local = inventory
        .iter()
        .filter(|((owner, _, _), _)| owner == "local")
        .map(|((_, table, column), class)| ((table.clone(), column.clone()), *class))
        .collect::<std::collections::BTreeMap<_, _>>();
    let manifest_deferred = inventory
        .iter()
        .filter(|((owner, _, _), _)| owner == "extended")
        .map(|((_, table, column), class)| ((table.clone(), column.clone()), *class))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut manifest_effective_extended = manifest_local.clone();
    assert!(
        manifest_deferred
            .keys()
            .all(|key| manifest_effective_extended
                .insert(key.clone(), manifest_deferred[key])
                .is_none()),
        "extended identifier ownership must be an additive table layer"
    );

    validate_relationship_inventory("local", &local, local_objects.clone(), &manifest_local)
        .expect("local identifier inventory must be exact");
    validate_relationship_inventory(
        "extended-owned",
        &extended,
        deferred_objects,
        &manifest_deferred,
    )
    .expect("extended identifier inventory must be exact");
    validate_relationship_inventory(
        "extended-effective",
        &extended,
        extended_objects,
        &manifest_effective_extended,
    )
    .expect("effective extended identifier inventory must be exact");
}

#[test]
fn identifier_inventory_rejects_unannotated_and_misclassified_schema_changes() {
    let [(_, mut local), _] = effective_profiles();
    let objects = schema_parser::classified_objects(&local)
        .map(|(object, _)| object.to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let inventory = relationship_inventory()
        .into_iter()
        .filter(|((owner, _, _), _)| owner == "local")
        .map(|((_, table, column), class)| ((table, column), class))
        .collect::<std::collections::BTreeMap<_, _>>();

    local
        .tables
        .get_mut("sessions")
        .unwrap()
        .columns
        .insert("unreviewed_authority_ref".to_owned());
    local
        .objects
        .iter_mut()
        .find(|object| object.name == "sessions")
        .unwrap()
        .columns
        .push("unreviewed_authority_ref".to_owned());
    local
        .tables
        .get_mut("sessions")
        .unwrap()
        .unique_keys
        .push(schema_parser::Key {
            terms: vec![schema_parser::IndexedColumn {
                column: "unreviewed_authority_ref".to_owned(),
                collation: None,
                direction: schema_parser::Direction::Asc,
            }],
        });
    assert!(
        validate_relationship_inventory("adversarial", &local, objects.clone(), &inventory)
            .unwrap_err()
            .contains("missing")
    );
    local
        .tables
        .get_mut("sessions")
        .unwrap()
        .columns
        .remove("unreviewed_authority_ref");
    local
        .objects
        .iter_mut()
        .find(|object| object.name == "sessions")
        .unwrap()
        .columns
        .retain(|column| column != "unreviewed_authority_ref");
    local.tables.get_mut("sessions").unwrap().unique_keys.pop();

    local
        .tables
        .get_mut("sessions")
        .unwrap()
        .columns
        .insert("unreviewed_soft_identity".to_owned());
    local
        .objects
        .iter_mut()
        .find(|object| object.name == "sessions")
        .unwrap()
        .columns
        .push("unreviewed_soft_identity".to_owned());
    assert!(
        validate_relationship_inventory("adversarial", &local, objects.clone(), &inventory)
            .unwrap_err()
            .contains("missing"),
        "non-key soft identity must not fall through the explicit manifest"
    );
    local
        .tables
        .get_mut("sessions")
        .unwrap()
        .columns
        .remove("unreviewed_soft_identity");
    local
        .objects
        .iter_mut()
        .find(|object| object.name == "sessions")
        .unwrap()
        .columns
        .retain(|column| column != "unreviewed_soft_identity");

    let foreign_identity = inventory
        .iter()
        .find(|(_, class)| **class == RelationshipClass::Foreign)
        .map(|(identity, _)| identity.clone())
        .unwrap();
    let mut missing = inventory.clone();
    missing.remove(&foreign_identity);
    assert!(
        validate_relationship_inventory("adversarial", &local, objects.clone(), &missing)
            .unwrap_err()
            .contains("missing")
    );

    for (from, to, expected_error) in [
        (
            RelationshipClass::Foreign,
            RelationshipClass::External,
            "bidirectional",
        ),
        (
            RelationshipClass::Primary,
            RelationshipClass::External,
            "hides primary",
        ),
        (
            RelationshipClass::LocalIdentity,
            RelationshipClass::External,
            "hides local unique",
        ),
        (
            RelationshipClass::External,
            RelationshipClass::Primary,
            "is not PK-owned",
        ),
    ] {
        let identity = inventory
            .iter()
            .find(|(_, class)| **class == from)
            .map(|(identity, _)| identity.clone())
            .unwrap();
        let mut misclassified = inventory.clone();
        misclassified.insert(identity, to);
        assert!(
            validate_relationship_inventory("adversarial", &local, objects.clone(), &misclassified)
                .unwrap_err()
                .contains(expected_error),
            "{from:?} -> {to:?} did not fail with {expected_error}"
        );
    }
}

#[test]
fn scoped_session_relationships_are_database_enforced_and_indexed() {
    for contract in [
        "FOREIGN KEY (parent_session_id, fork_point_turn_id)\n        REFERENCES session_events(session_id, seq)\n        ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED",
        "CREATE INDEX idx_sessions_parent_fork_point ON sessions(parent_session_id, fork_point_turn_id)",
        "FOREIGN KEY (session_id, parent_call_id)\n        REFERENCES tool_call_events(session_id, call_id)\n        ON DELETE CASCADE ON UPDATE RESTRICT",
        "CREATE UNIQUE INDEX uq_tce_session_call ON tool_call_events(session_id, call_id)",
        "CREATE INDEX idx_tce_parent     ON tool_call_events (session_id, parent_call_id)",
    ] {
        assert!(
            SCHEMA.contains(contract),
            "missing scoped FK contract: {contract}"
        );
    }
}

#[test]
fn intentional_session_soft_relationships_are_classified_in_schema() {
    for classification in [
        "[relationship:foreign] parent_session_id",
        "[relationship:foreign] Optional historical event sequence",
        "[relationship:foreign] Same-session parent tool call",
        "[relationship:denormalized] Immutable-attribution display snapshots",
        "[relationship:denormalized] Historical assistant label",
        "[relationship:external] Provider-owned opaque wire identifiers",
    ] {
        assert!(
            SCHEMA.contains(classification),
            "missing relationship classification: {classification}"
        );
    }

    let inventory = relationship_inventory();
    for (table, column, expected) in [
        ("sessions", "provider", RelationshipClass::Denormalized),
        ("sessions", "model", RelationshipClass::Denormalized),
        (
            "sessions",
            "assistant_name",
            RelationshipClass::Denormalized,
        ),
        (
            "tool_call_events",
            "provider_call_id",
            RelationshipClass::External,
        ),
        (
            "write_scope_leases",
            "owner_id",
            RelationshipClass::Polymorphic,
        ),
    ] {
        assert_eq!(
            inventory.get(&("local".to_owned(), table.to_owned(), column.to_owned())),
            Some(&expected),
            "soft relationship policy drifted for {table}.{column}"
        );
    }
}

#[test]
fn hot_query_inventory_is_exact_and_keeps_reviewed_leading_indexes() {
    let root = workspace();
    let shapes = [
        (
            "local.sessions.open",
            "crates/cockpit-db/src/db/sessions.rs",
            "WHERE ended_at_unix_ms IS NULL AND ephemeral = 0",
            "e676358dd6092ff77aa5915f430806d623c0987afd982014542b4e9cb4ea55c9",
            false,
            "sessions",
            "idx_sessions_open",
            &[
                ("ephemeral", None, schema_parser::Direction::Asc),
                (
                    "last_active_at_unix_ms",
                    None,
                    schema_parser::Direction::Desc,
                ),
            ][..],
            false,
            Some("ended_at_unix_ms is null"),
        ),
        (
            "local.agent-preparation.terminalize",
            "crates/cockpit-db/src/db/agent_installations.rs",
            "WHERE session_id=?1 AND claim_state IN ('claimed', 'running')",
            "529c9bf816b241c309b49f2e54c8ae0f398e87c117103eb4063d98eceb0d129a",
            false,
            "agent_session_preparation_claims",
            "idx_agent_session_preparation_claims_recovery",
            &[
                ("claim_state", None, schema_parser::Direction::Asc),
                ("session_id", None, schema_parser::Direction::Asc),
            ],
            false,
            None,
        ),
        (
            "extended.scheduler.by-owner",
            "crates/cockpit-db/src/db/scheduler.rs",
            "WHERE owner = ?1",
            "4c04bc561abef009306ec51c13858d2a4c801c130781eeda44a1cff97abfacd1",
            true,
            "scheduled_jobs",
            "idx_scheduled_jobs_owner",
            &[("owner", None, schema_parser::Direction::Asc)],
            false,
            None,
        ),
        (
            "extended.image-generation.dispatch-scan",
            "crates/cockpit-db/src/db/image_generation.rs",
            "WHERE j.state='queued' AND s.state='queued' AND a.state='planned'",
            "5235dd10724aef22eb5daf2e4e543db47aac88d0f0b5d7a4eb603522684df7bf",
            true,
            "image_generation_jobs",
            "idx_image_generation_jobs_dispatch_scan",
            &[
                ("state", None, schema_parser::Direction::Asc),
                ("created_at_unix_ms", None, schema_parser::Direction::Asc),
                ("job_id", None, schema_parser::Direction::Asc),
            ],
            false,
            None,
        ),
    ];
    let expected_markers = shapes
        .iter()
        .map(|(marker, owner, ..)| (marker.to_string(), owner.to_string()))
        .collect::<std::collections::BTreeSet<_>>();
    let actual_marker_rows = production_rust_sources(&root)
        .into_iter()
        .flat_map(|owner| {
            let contents = source(root.join(&owner));
            if !contents.contains("schema-hot-query:") {
                return Vec::new();
            }
            hot_query_comments(&contents)
                .into_iter()
                .map(|(_, marker)| (marker, portable_relative_path(&owner)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let actual_markers = actual_marker_rows
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        actual_marker_rows.len(),
        actual_markers.len(),
        "duplicate hot-query annotation"
    );
    assert_eq!(
        actual_markers, expected_markers,
        "hot-query annotations drifted"
    );

    let [(_, local), (_, extended)] = effective_profiles();
    for (
        marker,
        owner,
        query,
        query_digest,
        uses_extended,
        table,
        index_name,
        terms,
        unique,
        predicate,
    ) in shapes
    {
        let owner_source = source(root.join(owner));
        let bound_query = normalized_sql(&annotated_sql_literal(&owner_source, marker));
        assert!(
            bound_query.contains(&normalized_sql(query)),
            "bound query shape drifted for {marker}: {bound_query}"
        );
        assert_eq!(
            schema_digest(&bound_query),
            query_digest,
            "full bound query drifted for {marker}"
        );
        let schema = if uses_extended { &extended } else { &local };
        assert!(
            schema.indexes.iter().any(|index| index.name == index_name
                && index.table == table
                && index.unique == unique
                && index.terms.len() == terms.len()
                && index
                    .terms
                    .iter()
                    .zip(terms)
                    .all(|(actual, expected)| actual.column == expected.0
                        && actual.collation.as_deref() == expected.1
                        && actual.direction == expected.2)
                && index.predicate.as_deref() == predicate),
            "exact reviewed index missing for {marker}: {index_name} on {table}{terms:?} unique={unique} predicate={predicate:?}"
        );
    }
}
