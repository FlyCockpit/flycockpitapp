use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    QuotedName(String),
    Literal,
    Mark(char),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignKey {
    pub child_columns: Vec<String>,
    pub target_table: String,
    pub target_columns: Vec<String>,
    pub on_delete: Option<String>,
    pub on_update: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    pub columns: BTreeSet<String>,
    pub collations: BTreeMap<String, String>,
    pub primary_keys: Vec<Key>,
    pub unique_keys: Vec<Key>,
    pub foreign_keys: Vec<ForeignKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub columns: Vec<String>,
    pub collations: Vec<Option<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    pub name: String,
    pub table: String,
    pub columns: Vec<String>,
    pub unique: bool,
    pub partial: bool,
    pub collations: Vec<Option<String>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Schema {
    pub tables: BTreeMap<String, Table>,
    pub indexes: Vec<Index>,
}

fn lex(sql: &str) -> Vec<Token> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            byte if byte.is_ascii_whitespace() => at += 1,
            b'-' if bytes.get(at + 1) == Some(&b'-') => {
                at += 2;
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                at += 2;
                while at + 1 < bytes.len() && (bytes[at], bytes[at + 1]) != (b'*', b'/') {
                    at += 1;
                }
                assert!(at + 1 < bytes.len(), "unterminated SQL block comment");
                at += 2;
            }
            b'\'' => {
                at += 1;
                loop {
                    assert!(at < bytes.len(), "unterminated SQL string literal");
                    if bytes[at] != b'\'' {
                        at += 1;
                    } else if bytes.get(at + 1) == Some(&b'\'') {
                        at += 2;
                    } else {
                        at += 1;
                        break;
                    }
                }
                tokens.push(Token::Literal);
            }
            quote @ (b'"' | b'`' | b'[') => {
                let close = if quote == b'[' { b']' } else { quote };
                let mut identifier = Vec::new();
                at += 1;
                loop {
                    assert!(at < bytes.len(), "unterminated quoted SQL identifier");
                    if bytes[at] != close {
                        identifier.push(bytes[at]);
                        at += 1;
                    } else if quote != b'[' && bytes.get(at + 1) == Some(&close) {
                        identifier.push(close);
                        at += 2;
                    } else {
                        at += 1;
                        break;
                    }
                }
                tokens.push(Token::QuotedName(
                    String::from_utf8(identifier)
                        .expect("quoted SQL identifier must be UTF-8")
                        .to_ascii_lowercase(),
                ));
            }
            mark @ (b'(' | b')' | b',' | b';' | b'.') => {
                tokens.push(Token::Mark(mark as char));
                at += 1;
            }
            b']' => panic!("unexpected closing SQL identifier bracket"),
            _ => {
                let start = at;
                while at < bytes.len()
                    && !bytes[at].is_ascii_whitespace()
                    && !b"(),;.\"'`[]".contains(&bytes[at])
                    && !(bytes[at] == b'-' && bytes.get(at + 1) == Some(&b'-'))
                    && !(bytes[at] == b'/' && bytes.get(at + 1) == Some(&b'*'))
                {
                    at += 1;
                }
                tokens.push(Token::Word(
                    String::from_utf8_lossy(&bytes[start..at]).to_ascii_lowercase(),
                ));
            }
        }
    }
    tokens
}

fn is(token: Option<&Token>, keyword: &str) -> bool {
    matches!(token, Some(Token::Word(value)) if value == keyword)
}

fn name(token: Option<&Token>) -> Option<String> {
    match token {
        Some(Token::Word(value) | Token::QuotedName(value)) => Some(value.clone()),
        _ => None,
    }
}

fn word(token: Option<&Token>) -> Option<String> {
    match token {
        Some(Token::Word(value)) => Some(value.clone()),
        _ => None,
    }
}

fn closing(tokens: &[Token], open: usize) -> usize {
    let mut depth = 0_i32;
    for (offset, token) in tokens[open..].iter().enumerate() {
        match token {
            Token::Mark('(') => depth += 1,
            Token::Mark(')') => {
                depth -= 1;
                if depth == 0 {
                    return open + offset;
                }
            }
            _ => {}
        }
    }
    panic!("unterminated SQL parenthesis")
}

fn clauses(tokens: &[Token]) -> Vec<&[Token]> {
    let mut result = Vec::new();
    let (mut start, mut depth) = (0, 0_i32);
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Mark('(') => depth += 1,
            Token::Mark(')') => depth -= 1,
            Token::Mark(',') if depth == 0 => {
                result.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    result.push(&tokens[start..]);
    result
}

fn names_in_parens(tokens: &[Token], open: usize) -> Vec<String> {
    let close = closing(tokens, open);
    clauses(&tokens[open + 1..close])
        .into_iter()
        .map(|part| {
            assert_eq!(part.len(), 1, "foreign-key term must be one identifier");
            name(part.first()).expect("foreign-key term must be an identifier")
        })
        .collect()
}

fn key_in_parens(tokens: &[Token], open: usize) -> Key {
    let close = closing(tokens, open);
    let terms = clauses(&tokens[open + 1..close])
        .into_iter()
        .map(|part| {
            let column = name(part.first()).expect("key term must start with an identifier");
            let mut collation = None;
            let mut cursor = 1;
            while cursor < part.len() {
                if is(part.get(cursor), "collate") {
                    assert!(collation.is_none(), "duplicate key-term COLLATE");
                    collation =
                        Some(name(part.get(cursor + 1)).expect("COLLATE requires an identifier"));
                    cursor += 2;
                } else if is(part.get(cursor), "asc") || is(part.get(cursor), "desc") {
                    cursor += 1;
                } else {
                    panic!("key/index expressions are unsupported: {part:?}");
                }
            }
            (column, collation)
        })
        .collect::<Vec<_>>();
    Key {
        columns: terms.iter().map(|(column, _)| column.clone()).collect(),
        collations: terms.into_iter().map(|(_, collation)| collation).collect(),
    }
}

fn reject_unsupported_schema_forms(tokens: &[Token]) {
    for (index, token) in tokens.iter().enumerate() {
        let statement_start =
            index == 0 || tokens.get(index.wrapping_sub(1)) == Some(&Token::Mark(';'));
        if statement_start
            && (is(Some(token), "alter") && is(tokens.get(index + 1), "table")
                || is(Some(token), "drop")
                    && matches!(
                        name(tokens.get(index + 1)).as_deref(),
                        Some("table" | "index")
                    )
                || is(Some(token), "create")
                    && matches!(
                        name(tokens.get(index + 1)).as_deref(),
                        Some("temp" | "temporary")
                    ))
        {
            panic!("unsupported schema-changing statement near token {index}");
        }
        if statement_start && is(Some(token), "create") {
            let kind = name(tokens.get(index + 1));
            assert!(
                matches!(
                    kind.as_deref(),
                    Some("table" | "index" | "unique" | "trigger" | "view" | "virtual")
                ),
                "unsupported CREATE form near token {index}"
            );
            if kind.as_deref() == Some("unique") {
                assert!(
                    is(tokens.get(index + 2), "index"),
                    "UNIQUE must create an index"
                );
            }
            if kind.as_deref() == Some("virtual") {
                assert!(
                    is(tokens.get(index + 2), "table"),
                    "VIRTUAL must create a table"
                );
            }
        }
        if matches!(token, Token::Mark('.')) {
            let schema_context = index >= 2
                && ["table", "index", "references", "on"]
                    .iter()
                    .any(|keyword| is(tokens.get(index - 2), keyword));
            assert!(
                !schema_context,
                "schema-qualified object names are unsupported"
            );
        }
    }
}

fn top_level_position(tokens: &[Token], keyword: &str) -> Option<usize> {
    let mut depth = 0_i32;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Mark('(') => depth += 1,
            Token::Mark(')') => depth -= 1,
            _ if depth == 0 && is(Some(token), keyword) => return Some(index),
            _ => {}
        }
    }
    None
}

fn top_level_pair(tokens: &[Token], first: &str, second: &str) -> bool {
    let mut depth = 0_i32;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Mark('(') => depth += 1,
            Token::Mark(')') => depth -= 1,
            _ if depth == 0 && is(Some(token), first) && is(tokens.get(index + 1), second) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn action(tokens: &[Token], kind: &str) -> Option<String> {
    let mut depth = 0_i32;
    let mut on = None;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Mark('(') => depth += 1,
            Token::Mark(')') => depth -= 1,
            _ if depth == 0 && is(Some(token), "on") && is(tokens.get(index + 1), kind) => {
                assert!(on.replace(index).is_none(), "duplicate ON {kind} action");
            }
            _ => {}
        }
    }
    let on = on?;
    let first = word(tokens.get(on + 2))?;
    Some(if matches!(first.as_str(), "no" | "set") {
        format!(
            "{first} {}",
            word(tokens.get(on + 3)).expect("two-word FK action")
        )
    } else {
        first
    })
}

fn foreign_key(tokens: &[Token], inline: Option<String>) -> Option<ForeignKey> {
    let reference = top_level_position(tokens, "references")?;
    let child_columns = match inline {
        Some(column) => vec![column],
        None => {
            let foreign = top_level_position(tokens, "foreign")?;
            let open = tokens[foreign..]
                .iter()
                .position(|token| *token == Token::Mark('('))?
                + foreign;
            names_in_parens(tokens, open)
        }
    };
    let target_table = name(tokens.get(reference + 1)).expect("REFERENCES target table");
    let open = reference + 2;
    assert_eq!(
        tokens.get(open),
        Some(&Token::Mark('(')),
        "REFERENCES must declare exact target columns"
    );
    Some(ForeignKey {
        child_columns,
        target_table,
        target_columns: names_in_parens(tokens, open),
        on_delete: action(tokens, "delete"),
        on_update: action(tokens, "update"),
    })
}

fn apply_script(schema: &mut Schema, sql: &str) {
    let tokens = lex(sql);
    reject_unsupported_schema_forms(&tokens);
    let mut at = 0;
    while at < tokens.len() {
        let statement_start = at == 0 || tokens.get(at.wrapping_sub(1)) == Some(&Token::Mark(';'));
        if !statement_start || !is(tokens.get(at), "create") {
            at += 1;
            continue;
        }
        let mut cursor = at + 1;
        let unique = is(tokens.get(cursor), "unique");
        cursor += usize::from(unique);
        if is(tokens.get(cursor), "table") {
            cursor += 1;
            if is(tokens.get(cursor), "if") {
                assert!(
                    is(tokens.get(cursor + 1), "not") && is(tokens.get(cursor + 2), "exists"),
                    "CREATE TABLE IF must be IF NOT EXISTS"
                );
                cursor += 3;
            }
            let table_name = name(tokens.get(cursor)).expect("CREATE TABLE name");
            let open = cursor + 1;
            assert_eq!(
                tokens.get(open),
                Some(&Token::Mark('(')),
                "CREATE TABLE must declare a structural body"
            );
            let close = closing(&tokens, open);
            let mut table = Table::default();
            for original in clauses(&tokens[open + 1..close]) {
                let clause = if is(original.first(), "constraint") {
                    assert!(original.len() >= 3, "named constraint has no body");
                    assert!(
                        name(original.get(1)).is_some(),
                        "constraint name is missing"
                    );
                    assert!(
                        matches!(
                            name(original.get(2)).as_deref(),
                            Some("foreign" | "primary" | "unique" | "check")
                        ) && matches!(original.get(2), Some(Token::Word(_))),
                        "named constraint has an unsupported body"
                    );
                    &original[2..]
                } else {
                    original
                };
                if is(clause.first(), "foreign") {
                    table.foreign_keys.push(foreign_key(clause, None).unwrap());
                } else if is(clause.first(), "primary") || is(clause.first(), "unique") {
                    let key_open = clause
                        .iter()
                        .position(|token| *token == Token::Mark('('))
                        .unwrap();
                    let key = key_in_parens(clause, key_open);
                    if is(clause.first(), "primary") {
                        table.primary_keys.push(key);
                    } else {
                        table.unique_keys.push(key);
                    }
                } else if is(clause.first(), "check") {
                    assert_eq!(
                        clause.get(1),
                        Some(&Token::Mark('(')),
                        "table CHECK requires a parenthesized expression"
                    );
                } else if let Some(column) = name(clause.first()) {
                    assert!(
                        table.columns.insert(column.clone()),
                        "duplicate column {table_name}.{column}"
                    );
                    if let Some(collation_at) = top_level_position(clause, "collate") {
                        let collation = name(clause.get(collation_at + 1))
                            .expect("COLLATE requires an identifier");
                        table.collations.insert(column.clone(), collation);
                    }
                    if top_level_pair(clause, "primary", "key") {
                        table.primary_keys.push(Key {
                            columns: vec![column.clone()],
                            collations: vec![None],
                        });
                    } else if top_level_position(clause, "unique").is_some() {
                        table.unique_keys.push(Key {
                            columns: vec![column.clone()],
                            collations: vec![None],
                        });
                    }
                    if let Some(reference) = foreign_key(clause, Some(column)) {
                        table.foreign_keys.push(reference);
                    }
                } else {
                    panic!("unsupported CREATE TABLE clause: {clause:?}");
                }
            }
            assert!(
                schema.tables.insert(table_name, table).is_none(),
                "duplicate table in ordered effective schema"
            );
            at = close + 1;
        } else if is(tokens.get(cursor), "index") {
            cursor += 1;
            if is(tokens.get(cursor), "if") {
                assert!(
                    is(tokens.get(cursor + 1), "not") && is(tokens.get(cursor + 2), "exists"),
                    "CREATE INDEX IF must be IF NOT EXISTS"
                );
                cursor += 3;
            }
            let index_name = name(tokens.get(cursor)).expect("CREATE INDEX name");
            let on = cursor + 1;
            assert!(is(tokens.get(on), "on"), "CREATE INDEX requires ON");
            let table = name(tokens.get(on + 1)).unwrap();
            let open = on + 2;
            assert_eq!(
                tokens.get(open),
                Some(&Token::Mark('(')),
                "CREATE INDEX requires structural terms"
            );
            let close = closing(&tokens, open);
            let end = tokens[close + 1..]
                .iter()
                .position(|token| *token == Token::Mark(';'))
                .map_or(tokens.len(), |offset| close + 1 + offset);
            let key = key_in_parens(&tokens, open);
            assert!(
                schema.indexes.iter().all(|index| index.name != index_name),
                "duplicate index in ordered effective schema: {index_name}"
            );
            schema.indexes.push(Index {
                name: index_name,
                table,
                columns: key.columns,
                unique,
                partial: tokens[close + 1..end]
                    .iter()
                    .any(|token| is(Some(token), "where")),
                collations: key.collations,
            });
            at = end + 1;
        } else {
            at += 1;
        }
    }
}

fn validate_schema(schema: &Schema) {
    for (table_name, table) in &schema.tables {
        assert!(
            table.primary_keys.len() <= 1,
            "{table_name} declares multiple primary keys"
        );
        for key in table.primary_keys.iter().chain(&table.unique_keys) {
            assert!(
                !key.columns.is_empty(),
                "{table_name} declares an empty key"
            );
            assert_eq!(key.columns.len(), key.collations.len());
            for column in &key.columns {
                assert!(
                    table.columns.contains(column),
                    "{table_name} key names absent column {column}"
                );
            }
        }
        for foreign_key in &table.foreign_keys {
            assert_eq!(
                foreign_key.child_columns.len(),
                foreign_key.target_columns.len(),
                "{table_name} FK arity differs from {}",
                foreign_key.target_table
            );
            for column in &foreign_key.child_columns {
                assert!(
                    table.columns.contains(column),
                    "{table_name} FK names absent child column {column}"
                );
            }
            let target = schema
                .tables
                .get(&foreign_key.target_table)
                .unwrap_or_else(|| {
                    panic!(
                        "{table_name} references absent target {}",
                        foreign_key.target_table
                    )
                });
            for column in &foreign_key.target_columns {
                assert!(
                    target.columns.contains(column),
                    "{table_name} FK names absent target column {}.{column}",
                    foreign_key.target_table
                );
            }
            assert!(
                exact_target_keys(schema, &foreign_key.target_table)
                    .contains(&foreign_key.target_columns),
                "{table_name} references non-key {}({:?})",
                foreign_key.target_table,
                foreign_key.target_columns
            );
        }
    }
    for index in &schema.indexes {
        let table = schema
            .tables
            .get(&index.table)
            .unwrap_or_else(|| panic!("index {} owns absent table {}", index.name, index.table));
        assert_eq!(index.columns.len(), index.collations.len());
        for column in &index.columns {
            assert!(
                table.columns.contains(column),
                "index {} names absent column {}.{column}",
                index.name,
                index.table
            );
        }
    }
}

pub fn parse(scripts: &[&str]) -> Schema {
    assert!(
        !scripts.is_empty(),
        "effective schema needs at least one ordered script"
    );
    let mut schema = Schema::default();
    for script in scripts {
        apply_script(&mut schema, script);
    }
    validate_schema(&schema);
    schema
}

pub fn exact_target_keys(schema: &Schema, table: &str) -> Vec<Vec<String>> {
    let owner = &schema.tables[table];
    let mut keys = owner
        .primary_keys
        .iter()
        .chain(&owner.unique_keys)
        .filter(|key| {
            key.columns
                .iter()
                .zip(&key.collations)
                .all(|(column, collation)| {
                    collation.as_deref().unwrap_or_else(|| {
                        owner
                            .collations
                            .get(column)
                            .map_or("binary", String::as_str)
                    }) == owner
                        .collations
                        .get(column)
                        .map_or("binary", String::as_str)
                })
        })
        .map(|key| key.columns.clone())
        .collect::<Vec<_>>();
    keys.extend(
        schema
            .indexes
            .iter()
            .filter(|index| {
                index.table == table
                    && index.unique
                    && !index.partial
                    && index
                        .columns
                        .iter()
                        .zip(&index.collations)
                        .all(|(column, collation)| {
                            collation.as_deref().unwrap_or_else(|| {
                                schema.tables[table]
                                    .collations
                                    .get(column)
                                    .map_or("binary", String::as_str)
                            }) == schema.tables[table]
                                .collations
                                .get(column)
                                .map_or("binary", String::as_str)
                        })
            })
            .map(|index| index.columns.clone()),
    );
    keys
}

pub fn child_leading_keys(schema: &Schema, table: &str) -> Vec<Vec<String>> {
    let mut keys = schema.tables[table]
        .primary_keys
        .iter()
        .chain(&schema.tables[table].unique_keys)
        .map(|key| key.columns.clone())
        .collect::<Vec<_>>();
    keys.extend(
        schema
            .indexes
            .iter()
            .filter(|index| index.table == table && !index.partial)
            .map(|index| index.columns.clone()),
    );
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_named_inline_quoted_multiline_and_opaque_text() {
        let schema = parse(&[r#"
            -- REFERENCES ignored(id)
            CREATE TABLE "parent table" ("left id" TEXT UNIQUE, right_id TEXT,
              CONSTRAINT "named primary" PRIMARY KEY ("left id", right_id));
            CREATE TABLE child (
              child_id TEXT REFERENCES "parent table"("left id") ON DELETE RESTRICT ON UPDATE RESTRICT,
              right_id TEXT, note TEXT DEFAULT 'REFERENCES ignored(id)',
              "foreign" TEXT, "check" TEXT,
              CHECK (note IS NULL OR references(note) = 0),
              CONSTRAINT named_fk FOREIGN KEY(child_id, right_id)
                REFERENCES "parent table"("left id", right_id) ON DELETE CASCADE ON UPDATE RESTRICT);
            CREATE INDEX child_fk ON child(child_id, right_id);
            CREATE INDEX "on" ON child("foreign", "check");
            CREATE UNIQUE INDEX partial_not_target ON child(child_id) WHERE right_id IS NOT NULL;
            CREATE VIEW child_view AS SELECT * FROM child;
            CREATE VIRTUAL TABLE child_search USING fts5(note);
            /* REFERENCES also_ignored(id) */
        "#]);
        assert_eq!(schema.tables.len(), 2);
        assert_eq!(schema.tables["child"].columns.len(), 5);
        assert!(schema.tables["child"].columns.contains("foreign"));
        assert!(schema.tables["child"].columns.contains("check"));
        assert_eq!(schema.tables["child"].foreign_keys.len(), 2);
        assert_eq!(
            schema.tables["child"].foreign_keys[1].child_columns,
            ["child_id", "right_id"]
        );
        assert!(
            schema
                .indexes
                .iter()
                .any(|index| index.unique && index.partial)
        );
        assert!(!exact_target_keys(&schema, "child").contains(&vec!["child_id".into()]));
    }

    #[test]
    fn rejects_unsupported_schema_mutations_and_qualified_objects() {
        for sql in [
            "ALTER TABLE child ADD COLUMN parent_id TEXT REFERENCES parent(id);",
            "DROP TABLE child;",
            "CREATE TEMP TABLE child(id TEXT);",
            "CREATE TABLE main.child(id TEXT);",
        ] {
            assert!(
                std::panic::catch_unwind(|| parse(&[sql])).is_err(),
                "accepted {sql}"
            );
        }
    }

    #[test]
    fn parent_unique_index_collation_must_match_the_column() {
        let schema = parse(&["CREATE TABLE parent(id TEXT COLLATE nocase); \
             CREATE UNIQUE INDEX parent_id_binary ON parent(id COLLATE binary);"]);
        assert!(exact_target_keys(&schema, "parent").is_empty());
        let inherited = parse(&["CREATE TABLE parent(id TEXT COLLATE nocase); \
             CREATE UNIQUE INDEX parent_id_nocase ON parent(id);"]);
        assert_eq!(exact_target_keys(&inherited, "parent"), [vec!["id".into()]]);
    }

    #[test]
    fn table_key_collation_and_composite_order_are_exact() {
        let schema = parse(&[r#"
            CREATE TABLE parent (
                left_id TEXT COLLATE nocase,
                right_id TEXT,
                UNIQUE (left_id COLLATE binary, right_id),
                UNIQUE (right_id, left_id)
            );
        "#]);
        assert_eq!(
            exact_target_keys(&schema, "parent"),
            vec![vec!["right_id".to_owned(), "left_id".to_owned()]]
        );
    }

    #[test]
    fn rejects_malformed_relationship_and_index_shapes() {
        for sql in [
            "CREATE TABLE parent(left_id TEXT, right_id TEXT, UNIQUE(left_id,right_id)); \
             CREATE TABLE child(left_id TEXT, FOREIGN KEY(left_id) REFERENCES parent(left_id,right_id));",
            "CREATE TABLE parent(id TEXT PRIMARY KEY); \
             CREATE TABLE child(other_id TEXT, FOREIGN KEY(missing_id) REFERENCES parent(id));",
            "CREATE TABLE parent(id TEXT PRIMARY KEY); \
             CREATE TABLE child(parent_id TEXT REFERENCES parent(missing_id));",
            "CREATE TABLE parent(left_id TEXT, right_id TEXT, UNIQUE(left_id,right_id)); \
             CREATE TABLE child(left_id TEXT, right_id TEXT, FOREIGN KEY(left_id,right_id) REFERENCES parent(right_id,left_id));",
            "CREATE TABLE parent(id TEXT); \
             CREATE UNIQUE INDEX parent_partial ON parent(id) WHERE id IS NOT NULL; \
             CREATE TABLE child(parent_id TEXT REFERENCES parent(id));",
            "CREATE TABLE child(id TEXT); CREATE INDEX child_missing ON child(missing_id);",
            "CREATE TABLE child(id TEXT); CREATE INDEX child_expression ON child(lower(id));",
        ] {
            assert!(
                std::panic::catch_unwind(|| parse(&[sql])).is_err(),
                "accepted malformed relationship/index shape: {sql}"
            );
        }
    }

    #[test]
    fn ordered_scripts_reject_duplicate_objects_and_incomplete_layers() {
        let local = "CREATE TABLE parent(id TEXT PRIMARY KEY);";
        let extended = "CREATE TABLE child(parent_id TEXT REFERENCES parent(id)); \
                        CREATE INDEX child_parent ON child(parent_id);";
        assert_eq!(parse(&[local, extended]).tables.len(), 2);
        assert!(std::panic::catch_unwind(|| parse(&[extended])).is_err());
        assert!(
            std::panic::catch_unwind(|| {
                parse(&[local, "CREATE TABLE parent(other_id TEXT PRIMARY KEY);"])
            })
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| {
                parse(&[
                    "CREATE TABLE child(id TEXT); CREATE INDEX same_name ON child(id);",
                    "CREATE INDEX same_name ON child(id);",
                ])
            })
            .is_err()
        );
    }
}
