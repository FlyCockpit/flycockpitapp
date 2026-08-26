use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Name(String),
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
    pub primary_keys: Vec<Vec<String>>,
    pub unique_keys: Vec<Vec<String>>,
    pub foreign_keys: Vec<ForeignKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
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
                let mut name = String::new();
                at += 1;
                loop {
                    assert!(at < bytes.len(), "unterminated quoted SQL identifier");
                    if bytes[at] != close {
                        name.push(bytes[at] as char);
                        at += 1;
                    } else if quote != b'[' && bytes.get(at + 1) == Some(&close) {
                        name.push(close as char);
                        at += 2;
                    } else {
                        at += 1;
                        break;
                    }
                }
                tokens.push(Token::Name(name.to_ascii_lowercase()));
            }
            mark @ (b'(' | b')' | b',' | b';' | b'.') => {
                tokens.push(Token::Mark(mark as char));
                at += 1;
            }
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
                tokens.push(Token::Name(
                    String::from_utf8_lossy(&bytes[start..at]).to_ascii_lowercase(),
                ));
            }
        }
    }
    tokens
}

fn is(token: Option<&Token>, keyword: &str) -> bool {
    matches!(token, Some(Token::Name(value)) if value == keyword)
}

fn name(token: Option<&Token>) -> Option<String> {
    match token {
        Some(Token::Name(value)) => Some(value.clone()),
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
        .map(|part| name(part.first()).expect("key/index term must start with an identifier"))
        .collect()
}

fn terms_in_parens(tokens: &[Token], open: usize) -> Vec<(String, Option<String>)> {
    let close = closing(tokens, open);
    clauses(&tokens[open + 1..close])
        .into_iter()
        .map(|part| {
            let column = name(part.first()).expect("index term must start with an identifier");
            let collation = part
                .windows(2)
                .find(|pair| is(pair.first(), "collate"))
                .and_then(|pair| name(pair.get(1)));
            (column, collation)
        })
        .collect()
}

fn reject_unsupported_schema_forms(tokens: &[Token]) {
    for (index, token) in tokens.iter().enumerate() {
        if is(Some(token), "alter") && is(tokens.get(index + 1), "table")
            || is(Some(token), "drop")
                && matches!(
                    name(tokens.get(index + 1)).as_deref(),
                    Some("table" | "index")
                )
            || is(Some(token), "create")
                && matches!(
                    name(tokens.get(index + 1)).as_deref(),
                    Some("temp" | "temporary")
                )
        {
            panic!("unsupported schema-changing statement near token {index}");
        }
        if is(Some(token), "create") {
            let kind = name(tokens.get(index + 1));
            assert!(
                matches!(
                    kind.as_deref(),
                    Some("table" | "index" | "unique" | "trigger")
                ),
                "unsupported CREATE form near token {index}"
            );
            if kind.as_deref() == Some("unique") {
                assert!(
                    is(tokens.get(index + 2), "index"),
                    "UNIQUE must create an index"
                );
            }
        }
        if matches!(token, Token::Mark('.')) {
            let schema_context = index >= 2
                && matches!(
                    name(tokens.get(index - 2)).as_deref(),
                    Some("table" | "references" | "on")
                );
            assert!(
                !schema_context,
                "schema-qualified object names are unsupported"
            );
        }
    }
}

fn action(tokens: &[Token], kind: &str) -> Option<String> {
    let on = tokens
        .windows(2)
        .position(|pair| is(pair.first(), "on") && is(pair.get(1), kind))?;
    let first = name(tokens.get(on + 2))?;
    Some(if matches!(first.as_str(), "no" | "set") {
        format!(
            "{first} {}",
            name(tokens.get(on + 3)).expect("two-word FK action")
        )
    } else {
        first
    })
}

fn foreign_key(tokens: &[Token], inline: Option<String>) -> Option<ForeignKey> {
    let reference = tokens
        .iter()
        .position(|token| is(Some(token), "references"))?;
    let child_columns = match inline {
        Some(column) => vec![column],
        None => {
            let foreign = tokens.iter().position(|token| is(Some(token), "foreign"))?;
            let open = tokens[foreign..]
                .iter()
                .position(|token| *token == Token::Mark('('))?
                + foreign;
            names_in_parens(tokens, open)
        }
    };
    let target_table = name(tokens.get(reference + 1)).expect("REFERENCES target table");
    let open = tokens[reference + 2..]
        .iter()
        .position(|token| *token == Token::Mark('('))?
        + reference
        + 2;
    Some(ForeignKey {
        child_columns,
        target_table,
        target_columns: names_in_parens(tokens, open),
        on_delete: action(tokens, "delete"),
        on_update: action(tokens, "update"),
    })
}

pub fn parse(scripts: &[&str]) -> Schema {
    let tokens = lex(&scripts.concat());
    reject_unsupported_schema_forms(&tokens);
    let mut schema = Schema::default();
    let mut at = 0;
    while at < tokens.len() {
        if !is(tokens.get(at), "create") {
            at += 1;
            continue;
        }
        let mut cursor = at + 1;
        let unique = is(tokens.get(cursor), "unique");
        cursor += usize::from(unique);
        if is(tokens.get(cursor), "table") {
            cursor += 1;
            if is(tokens.get(cursor), "if") {
                cursor += 3;
            }
            let table_name = name(tokens.get(cursor)).expect("CREATE TABLE name");
            let open = tokens[cursor + 1..]
                .iter()
                .position(|token| *token == Token::Mark('('))
                .expect("CREATE TABLE body")
                + cursor
                + 1;
            let close = closing(&tokens, open);
            let mut table = Table::default();
            for original in clauses(&tokens[open + 1..close]) {
                let clause = if is(original.first(), "constraint") {
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
                    let key = names_in_parens(clause, key_open);
                    if is(clause.first(), "primary") {
                        table.primary_keys.push(key);
                    } else {
                        table.unique_keys.push(key);
                    }
                } else if let Some(column) = name(clause.first()) {
                    table.columns.insert(column.clone());
                    if let Some(collation) = clause
                        .windows(2)
                        .find(|pair| is(pair.first(), "collate"))
                        .and_then(|pair| name(pair.get(1)))
                    {
                        table.collations.insert(column.clone(), collation);
                    }
                    if clause
                        .windows(2)
                        .any(|pair| is(pair.first(), "primary") && is(pair.get(1), "key"))
                    {
                        table.primary_keys.push(vec![column.clone()]);
                    } else if clause.iter().any(|token| is(Some(token), "unique")) {
                        table.unique_keys.push(vec![column.clone()]);
                    }
                    if let Some(reference) = foreign_key(clause, Some(column)) {
                        table.foreign_keys.push(reference);
                    }
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
                cursor += 3;
            }
            let on = tokens[cursor + 1..]
                .iter()
                .position(|token| is(Some(token), "on"))
                .expect("CREATE INDEX ON")
                + cursor
                + 1;
            let table = name(tokens.get(on + 1)).unwrap();
            let open = tokens[on + 2..]
                .iter()
                .position(|token| *token == Token::Mark('('))
                .unwrap()
                + on
                + 2;
            let close = closing(&tokens, open);
            let end = tokens[close + 1..]
                .iter()
                .position(|token| *token == Token::Mark(';'))
                .map_or(tokens.len(), |offset| close + 1 + offset);
            let terms = terms_in_parens(&tokens, open);
            schema.indexes.push(Index {
                table,
                columns: terms.iter().map(|(column, _)| column.clone()).collect(),
                unique,
                partial: tokens[close + 1..end]
                    .iter()
                    .any(|token| is(Some(token), "where")),
                collations: terms.into_iter().map(|(_, collation)| collation).collect(),
            });
            at = end + 1;
        } else {
            at += 1;
        }
    }
    schema
}

pub fn exact_target_keys(schema: &Schema, table: &str) -> Vec<Vec<String>> {
    let mut keys = schema.tables[table].primary_keys.clone();
    keys.extend(schema.tables[table].unique_keys.clone());
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
                            collation.as_deref().unwrap_or("binary")
                                == schema.tables[table]
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
    let mut keys = schema.tables[table].primary_keys.clone();
    keys.extend(schema.tables[table].unique_keys.clone());
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
            CREATE TABLE "parent table" ("left id" TEXT, right_id TEXT,
              CONSTRAINT "named primary" PRIMARY KEY ("left id", right_id));
            CREATE TABLE child (
              child_id TEXT REFERENCES "parent table"("left id") ON DELETE RESTRICT ON UPDATE RESTRICT,
              right_id TEXT, note TEXT DEFAULT 'REFERENCES ignored(id)',
              CONSTRAINT named_fk FOREIGN KEY(child_id, right_id)
                REFERENCES "parent table"("left id", right_id) ON DELETE CASCADE ON UPDATE RESTRICT);
            CREATE INDEX child_fk ON child(child_id, right_id);
            CREATE UNIQUE INDEX partial_not_target ON child(child_id) WHERE right_id IS NOT NULL;
            /* REFERENCES also_ignored(id) */
        "#]);
        assert_eq!(schema.tables.len(), 2);
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
            "CREATE VIEW children AS SELECT * FROM child;",
            "CREATE VIRTUAL TABLE search USING fts5(body);",
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
    }
}
