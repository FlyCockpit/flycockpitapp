use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    QuotedName(String),
    Literal(String),
    Mark(char),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Asc,
    Desc,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedColumn {
    pub column: String,
    pub collation: Option<String>,
    pub direction: Direction,
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
    pub terms: Vec<IndexedColumn>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    pub name: String,
    pub table: String,
    pub terms: Vec<IndexedColumn>,
    pub unique: bool,
    pub predicate: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Table,
    Index,
    View,
    VirtualTable,
    Trigger,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub kind: ObjectKind,
    pub name: String,
    pub owner: Option<String>,
    pub columns: Vec<String>,
    pub definition: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Schema {
    pub tables: BTreeMap<String, Table>,
    pub indexes: Vec<Index>,
    pub objects: Vec<Object>,
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
                let mut value = Vec::new();
                at += 1;
                loop {
                    assert!(at < bytes.len(), "unterminated SQL string literal");
                    if bytes[at] != b'\'' {
                        value.push(bytes[at]);
                        at += 1;
                    } else if bytes.get(at + 1) == Some(&b'\'') {
                        value.push(b'\'');
                        at += 2;
                    } else {
                        at += 1;
                        break;
                    }
                }
                tokens.push(Token::Literal(
                    String::from_utf8(value).expect("SQL string literal must be UTF-8"),
                ));
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
            let mut direction = Direction::Asc;
            let mut cursor = 1;
            while cursor < part.len() {
                if is(part.get(cursor), "collate") {
                    assert!(collation.is_none(), "duplicate key-term COLLATE");
                    collation =
                        Some(name(part.get(cursor + 1)).expect("COLLATE requires an identifier"));
                    cursor += 2;
                } else if is(part.get(cursor), "asc") {
                    direction = Direction::Asc;
                    cursor += 1;
                } else if is(part.get(cursor), "desc") {
                    direction = Direction::Desc;
                    cursor += 1;
                } else {
                    panic!("key/index expressions are unsupported: {part:?}");
                }
            }
            IndexedColumn {
                column,
                collation,
                direction,
            }
        })
        .collect::<Vec<_>>();
    Key { terms }
}

fn token_sql(token: &Token) -> String {
    match token {
        Token::Word(value) => value.clone(),
        Token::QuotedName(value) => format!("\"{}\"", value.replace('"', "\"\"")),
        Token::Literal(value) => format!("'{}'", value.replace('\'', "''")),
        Token::Mark(mark) => mark.to_string(),
    }
}

fn normalized_tokens(tokens: &[Token]) -> String {
    tokens.iter().map(token_sql).collect::<Vec<_>>().join(" ")
}

fn reject_unsupported_schema_forms(tokens: &[Token]) {
    fn source_context_before(tokens: &[Token], boundary: usize) -> bool {
        if boundary == 0 {
            return false;
        }
        // Walk backward at this table-or-subquery group's depth. An opening
        // parenthesis can itself be a FROM/JOIN source group, so recurse into
        // its surrounding scope. Function/scalar-expression parentheses reach
        // a clause/SELECT boundary instead and fail closed as non-sources.
        let mut nested = 0_u32;
        for (index, token) in tokens[..boundary].iter().enumerate().rev() {
            match token {
                Token::Mark(')') => nested = nested.checked_add(1).expect("SQL nesting overflow"),
                Token::Mark('(') if nested > 0 => nested -= 1,
                Token::Mark('(') => {
                    return match tokens.get(index.wrapping_sub(1)) {
                        // A table-or-subquery group inherits the surrounding
                        // FROM list only when a relation introducer (or an
                        // already-inherited relation group) opened it.
                        Some(Token::Word(keyword))
                            if matches!(keyword.as_str(), "from" | "join") =>
                        {
                            true
                        }
                        Some(Token::Mark(',') | Token::Mark('(')) => {
                            source_context_before(tokens, index)
                        }
                        // Identifier/path/call/expression tokens introduce a
                        // function or scalar-expression scope. A comma inside
                        // it must never become another FROM relation.
                        Some(
                            Token::Word(_)
                            | Token::QuotedName(_)
                            | Token::Literal(_)
                            | Token::Mark(')'),
                        )
                        | None => false,
                        Some(Token::Mark(_)) => false,
                    };
                }
                Token::Mark(';') if nested == 0 => return false,
                Token::Word(keyword) if nested == 0 => match keyword.as_str() {
                    "from" | "join" => return true,
                    "select" | "where" | "group" | "having" | "order" | "limit" | "union"
                    | "intersect" | "except" | "values" | "returning" | "on" | "using" | "set"
                    | "when" => {
                        return false;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        false
    }

    fn grouped_or_comma_from_relation(tokens: &[Token], dot: usize) -> bool {
        dot >= 3
            && matches!(
                tokens.get(dot - 2),
                Some(Token::Mark('(')) | Some(Token::Mark(','))
            )
            && source_context_before(tokens, dot - 2)
    }

    for (index, token) in tokens.iter().enumerate() {
        let statement_start =
            index == 0 || tokens.get(index.wrapping_sub(1)) == Some(&Token::Mark(';'));
        if statement_start
            && (is(Some(token), "alter") && is(tokens.get(index + 1), "table")
                || is(Some(token), "drop")
                    && matches!(
                        name(tokens.get(index + 1)).as_deref(),
                        Some("table" | "index" | "view" | "trigger")
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
            let direct_schema_context = index >= 2
                && [
                    "table",
                    "index",
                    "view",
                    "trigger",
                    "references",
                    "on",
                    "from",
                    "into",
                    "update",
                    "join",
                ]
                .iter()
                .any(|keyword| is(tokens.get(index - 2), keyword));
            let update_conflict_schema_context = index >= 4
                && is(tokens.get(index - 4), "update")
                && is(tokens.get(index - 3), "or")
                && matches!(
                    word(tokens.get(index - 2)).as_deref(),
                    Some("rollback" | "abort" | "fail" | "ignore" | "replace")
                );
            assert!(
                !direct_schema_context
                    && !update_conflict_schema_context
                    && !grouped_or_comma_from_relation(tokens, index),
                "schema-qualified object names are unsupported"
            );
        }
        if matches!(word(Some(token)).as_deref(), Some("update" | "insert"))
            && is(tokens.get(index + 1), "or")
        {
            assert!(
                matches!(
                    word(tokens.get(index + 2)).as_deref(),
                    Some("rollback" | "abort" | "fail" | "ignore" | "replace")
                ),
                "unsupported SQLite conflict action"
            );
        }
    }
}

fn statement_end(tokens: &[Token], start: usize, kind: &str) -> usize {
    if kind == "trigger" {
        let begin = tokens[start..]
            .iter()
            .position(|token| is(Some(token), "begin"))
            .map(|offset| start + offset)
            .expect("CREATE TRIGGER requires BEGIN");
        let mut case_depth = 0_u32;
        for index in begin + 1..tokens.len().saturating_sub(1) {
            if is(tokens.get(index), "case") {
                case_depth = case_depth.checked_add(1).expect("CASE nesting overflow");
            } else if is(tokens.get(index), "end") {
                if case_depth > 0 {
                    case_depth -= 1;
                } else if tokens.get(index + 1) == Some(&Token::Mark(';')) {
                    return index + 1;
                }
            }
        }
        panic!("CREATE TRIGGER requires terminal END;");
    }
    tokens[start..]
        .iter()
        .position(|token| *token == Token::Mark(';'))
        .map(|offset| start + offset)
        .expect("schema statement requires a terminating semicolon")
}

fn assert_unique_object(schema: &Schema, name: &str) {
    assert!(
        schema.objects.iter().all(|object| object.name != name),
        "duplicate ordered schema object: {name}"
    );
}

fn object_columns(schema: &Schema, name: &str) -> Option<BTreeSet<String>> {
    schema
        .objects
        .iter()
        .find(|object| object.name == name)
        .map(|object| object.columns.iter().cloned().collect())
}

fn view_columns(schema: &Schema, tokens: &[Token]) -> (Vec<String>, String) {
    let select = top_level_position(tokens, "select").expect("CREATE VIEW requires SELECT");
    let from = top_level_position(&tokens[select + 1..], "from")
        .map(|offset| select + 1 + offset)
        .expect("CREATE VIEW requires FROM");
    let owner = name(tokens.get(from + 1)).expect("CREATE VIEW source relation");
    assert_eq!(
        from + 2,
        tokens.len(),
        "only the reviewed single-source CREATE VIEW grammar is supported"
    );
    let source_columns = object_columns(schema, &owner)
        .unwrap_or_else(|| panic!("view source relation {owner} is not available yet"));
    let columns = clauses(&tokens[select + 1..from])
        .into_iter()
        .flat_map(|term| {
            if word(term.first()).as_deref() == Some("*") {
                return source_columns.iter().cloned().collect::<Vec<_>>();
            }
            if let Some(alias) = top_level_position(term, "as") {
                vec![name(term.get(alias + 1)).expect("view AS alias")]
            } else {
                let names = term
                    .iter()
                    .filter_map(|token| name(Some(token)))
                    .collect::<Vec<_>>();
                assert_eq!(
                    names.len(),
                    1,
                    "view output needs an explicit AS alias: {term:?}"
                );
                vec![names[0].clone()]
            }
        })
        .collect();
    (columns, owner)
}

fn virtual_table_columns(tokens: &[Token]) -> Vec<String> {
    let using = top_level_position(tokens, "using").expect("virtual table requires USING");
    assert_eq!(
        name(tokens.get(using + 1)).as_deref(),
        Some("fts5"),
        "only the reviewed FTS5 virtual-table grammar is supported"
    );
    let open = using + 2;
    assert_eq!(tokens.get(open), Some(&Token::Mark('(')));
    let close = closing(tokens, open);
    assert_eq!(
        close + 1,
        tokens.len(),
        "unsupported trailing virtual-table grammar"
    );
    let parts = clauses(&tokens[open + 1..close]);
    let mut columns = Vec::new();
    let mut options = Vec::new();
    for part in parts {
        if part.len() == 1 {
            columns.push(name(part.first()).expect("FTS5 column name"));
        } else {
            assert!(
                word(part.first()).is_some_and(|option| option.ends_with('=')),
                "FTS5 option must be an explicit name=value term: {part:?}"
            );
            options.push(normalized_tokens(part));
        }
    }
    assert!(
        !columns.is_empty(),
        "FTS5 requires at least one indexed column"
    );
    assert_eq!(
        options.len(),
        options.iter().collect::<BTreeSet<_>>().len(),
        "duplicate FTS5 option"
    );
    columns
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

fn validate_checks(tokens: &[Token]) {
    let mut depth = 0_i32;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Mark('(') => depth += 1,
            Token::Mark(')') => depth -= 1,
            _ if depth == 0 && is(Some(token), "check") => {
                assert_eq!(
                    tokens.get(index + 1),
                    Some(&Token::Mark('(')),
                    "CHECK requires a parenthesized expression"
                );
                let close = closing(tokens, index + 1);
                assert!(close > index + 1, "CHECK expression cannot be empty");
            }
            _ => {}
        }
    }
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
    let mut depth = 0_i32;
    let mut reference_count = 0_usize;
    for token in tokens {
        match token {
            Token::Mark('(') => {
                depth += 1;
            }
            Token::Mark(')') => {
                depth -= 1;
            }
            _ if depth == 0 && is(Some(token), "references") => reference_count += 1,
            _ => {}
        }
    }
    assert_eq!(
        reference_count, 1,
        "one FK clause must declare one REFERENCES"
    );
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
            let end = statement_end(&tokens, at, "table");
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
            assert_eq!(close + 1, end, "unsupported trailing CREATE TABLE grammar");
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
                validate_checks(clause);
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
                    assert_eq!(
                        closing(clause, 1),
                        clause.len() - 1,
                        "table CHECK has trailing unsupported grammar"
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
                            terms: vec![IndexedColumn {
                                column: column.clone(),
                                collation: None,
                                direction: Direction::Asc,
                            }],
                        });
                    } else if top_level_position(clause, "unique").is_some() {
                        table.unique_keys.push(Key {
                            terms: vec![IndexedColumn {
                                column: column.clone(),
                                collation: None,
                                direction: Direction::Asc,
                            }],
                        });
                    }
                    if let Some(reference) = foreign_key(clause, Some(column)) {
                        table.foreign_keys.push(reference);
                    }
                } else {
                    panic!("unsupported CREATE TABLE clause: {clause:?}");
                }
            }
            assert_unique_object(schema, &table_name);
            let columns = table.columns.iter().cloned().collect::<Vec<_>>();
            assert!(
                schema.tables.insert(table_name.clone(), table).is_none(),
                "duplicate table in ordered effective schema"
            );
            schema.objects.push(Object {
                kind: ObjectKind::Table,
                name: table_name,
                owner: None,
                columns,
                definition: normalized_tokens(&tokens[at..end]),
            });
            at = end + 1;
        } else if is(tokens.get(cursor), "index") {
            let end = statement_end(&tokens, at, "index");
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
            let key = key_in_parens(&tokens, open);
            let owner = schema
                .tables
                .get(&table)
                .unwrap_or_else(|| panic!("index {index_name} precedes or lacks table {table}"));
            for term in &key.terms {
                assert!(
                    owner.columns.contains(&term.column),
                    "index {index_name} names absent column {table}.{}",
                    term.column
                );
            }
            let predicate = top_level_position(&tokens[close + 1..end], "where")
                .map(|offset| close + 1 + offset)
                .map(|where_at| {
                    assert_eq!(where_at, close + 1, "unexpected tokens before index WHERE");
                    assert!(where_at + 1 < end, "partial index predicate is empty");
                    normalized_tokens(&tokens[where_at + 1..end])
                });
            if predicate.is_none() {
                assert_eq!(close + 1, end, "unexpected tokens after index terms");
            }
            assert_unique_object(schema, &index_name);
            schema.indexes.push(Index {
                name: index_name.clone(),
                table: table.clone(),
                terms: key.terms.clone(),
                unique,
                predicate,
            });
            schema.objects.push(Object {
                kind: ObjectKind::Index,
                name: index_name,
                owner: Some(table),
                columns: key.terms.into_iter().map(|term| term.column).collect(),
                definition: normalized_tokens(&tokens[at..end]),
            });
            at = end + 1;
        } else if is(tokens.get(cursor), "view") {
            let end = statement_end(&tokens, at, "view");
            let view_name = name(tokens.get(cursor + 1)).expect("CREATE VIEW name");
            assert!(
                is(tokens.get(cursor + 2), "as"),
                "CREATE VIEW name must be one unqualified identifier followed by AS"
            );
            assert_unique_object(schema, &view_name);
            let (columns, owner) = view_columns(schema, &tokens[at..end]);
            assert!(
                object_columns(schema, &owner).is_some(),
                "view {view_name} precedes or lacks source relation {owner}"
            );
            schema.objects.push(Object {
                kind: ObjectKind::View,
                name: view_name,
                owner: Some(owner),
                columns,
                definition: normalized_tokens(&tokens[at..end]),
            });
            at = end + 1;
        } else if is(tokens.get(cursor), "virtual") {
            let end = statement_end(&tokens, at, "virtual");
            assert!(is(tokens.get(cursor + 1), "table"));
            let table_name = name(tokens.get(cursor + 2)).expect("CREATE VIRTUAL TABLE name");
            assert!(
                is(tokens.get(cursor + 3), "using"),
                "CREATE VIRTUAL TABLE name must be one unqualified identifier followed by USING"
            );
            assert_unique_object(schema, &table_name);
            let columns = virtual_table_columns(&tokens[at..end]);
            schema.objects.push(Object {
                kind: ObjectKind::VirtualTable,
                name: table_name,
                owner: None,
                columns,
                definition: normalized_tokens(&tokens[at..end]),
            });
            at = end + 1;
        } else if is(tokens.get(cursor), "trigger") {
            let end = statement_end(&tokens, at, "trigger");
            let trigger_name = name(tokens.get(cursor + 1)).expect("CREATE TRIGGER name");
            assert_ne!(
                tokens.get(cursor + 2),
                Some(&Token::Mark('.')),
                "CREATE TRIGGER name must be one unqualified identifier"
            );
            let begin = top_level_position(&tokens[at..end], "begin")
                .map(|offset| at + offset)
                .expect("CREATE TRIGGER BEGIN");
            let on = (cursor + 2..begin)
                .find(|index| is(tokens.get(*index), "on"))
                .expect("CREATE TRIGGER owner");
            let owner = name(tokens.get(on + 1)).expect("CREATE TRIGGER owner name");
            assert!(
                object_columns(schema, &owner).is_some(),
                "trigger {trigger_name} precedes or lacks owner {owner}"
            );
            assert_unique_object(schema, &trigger_name);
            schema.objects.push(Object {
                kind: ObjectKind::Trigger,
                name: trigger_name,
                owner: Some(owner),
                columns: Vec::new(),
                definition: normalized_tokens(&tokens[at..end]),
            });
            at = end + 1;
        } else {
            panic!("unconsumed CREATE statement near token {at}");
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
            assert!(!key.terms.is_empty(), "{table_name} declares an empty key");
            for term in &key.terms {
                assert!(
                    table.columns.contains(&term.column),
                    "{table_name} key names absent column {}",
                    term.column
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
        for term in &index.terms {
            assert!(
                table.columns.contains(&term.column),
                "index {} names absent column {}.{}",
                index.name,
                index.table,
                term.column
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
            key.terms.iter().all(|term| {
                term.collation.as_deref().unwrap_or_else(|| {
                    owner
                        .collations
                        .get(&term.column)
                        .map_or("binary", String::as_str)
                }) == owner
                    .collations
                    .get(&term.column)
                    .map_or("binary", String::as_str)
            })
        })
        .map(|key| key.terms.iter().map(|term| term.column.clone()).collect())
        .collect::<Vec<_>>();
    keys.extend(
        schema
            .indexes
            .iter()
            .filter(|index| {
                index.table == table
                    && index.unique
                    && index.predicate.is_none()
                    && index.terms.iter().all(|term| {
                        term.collation.as_deref().unwrap_or_else(|| {
                            schema.tables[table]
                                .collations
                                .get(&term.column)
                                .map_or("binary", String::as_str)
                        }) == schema.tables[table]
                            .collations
                            .get(&term.column)
                            .map_or("binary", String::as_str)
                    })
            })
            .map(|index| index.terms.iter().map(|term| term.column.clone()).collect()),
    );
    keys
}

pub fn child_leading_keys(
    schema: &Schema,
    table: &str,
    target_table: &str,
    child_columns: &[String],
    target_columns: &[String],
) -> Vec<Vec<String>> {
    let child = &schema.tables[table];
    let parent = &schema.tables[target_table];
    let compatible = |terms: &[IndexedColumn]| {
        terms.len() >= child_columns.len()
            && terms
                .iter()
                .zip(child_columns.iter().zip(target_columns))
                .all(|(term, (child_column, target_column))| {
                    term.column == child_column.as_str()
                        && term.collation.as_deref().unwrap_or_else(|| {
                            child
                                .collations
                                .get(child_column)
                                .map_or("binary", String::as_str)
                        }) == parent
                            .collations
                            .get(target_column)
                            .map_or("binary", String::as_str)
                })
    };
    let mut keys = schema.tables[table]
        .primary_keys
        .iter()
        .chain(&schema.tables[table].unique_keys)
        .filter(|key| compatible(&key.terms))
        .map(|key| key.terms.iter().map(|term| term.column.clone()).collect())
        .collect::<Vec<_>>();
    keys.extend(
        schema
            .indexes
            .iter()
            .filter(|index| {
                index.table == table && index.predicate.is_none() && compatible(&index.terms)
            })
            .map(|index| index.terms.iter().map(|term| term.column.clone()).collect()),
    );
    keys
}

pub fn classified_objects(schema: &Schema) -> impl Iterator<Item = (&str, &[String])> {
    schema
        .objects
        .iter()
        .filter_map(|object| match object.kind {
            ObjectKind::Table | ObjectKind::View | ObjectKind::VirtualTable => {
                Some((object.name.as_str(), object.columns.as_slice()))
            }
            ObjectKind::Index | ObjectKind::Trigger => None,
        })
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
            CREATE TRIGGER child_guard BEFORE UPDATE ON child
              BEGIN
                -- DELETE FROM main.child is inert comment text.
                SELECT RAISE(ABORT, 'FROM main.child is inert literal text');
              END;
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
                .any(|index| index.unique && index.predicate.is_some())
        );
        let partial = schema
            .indexes
            .iter()
            .find(|index| index.name == "partial_not_target")
            .unwrap();
        assert_eq!(partial.predicate.as_deref(), Some("right_id is not null"));
        assert_eq!(partial.terms[0].direction, Direction::Asc);
        assert!(!exact_target_keys(&schema, "child").contains(&vec!["child_id".into()]));
        assert_eq!(schema.objects.len(), 8);
        assert_eq!(
            object_columns(&schema, "child_search").unwrap(),
            BTreeSet::from(["note".to_owned()])
        );
        assert_eq!(
            object_columns(&schema, "child_view").unwrap(),
            schema.tables["child"].columns.clone()
        );
        assert_eq!(
            schema
                .objects
                .iter()
                .find(|object| object.name == "child_guard")
                .unwrap()
                .owner
                .as_deref(),
            Some("child")
        );
    }

    #[test]
    fn rejects_unsupported_schema_mutations_and_qualified_objects() {
        for sql in [
            "ALTER TABLE child ADD COLUMN parent_id TEXT REFERENCES parent(id);",
            "DROP TABLE child;",
            "CREATE TEMP TABLE child(id TEXT);",
            "CREATE TABLE main.child(id TEXT);",
            "CREATE TABLE child(id TEXT); CREATE VIEW main.child_view AS SELECT * FROM child;",
            "CREATE VIRTUAL TABLE main.child_search USING fts5(body);",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER main.child_guard BEFORE UPDATE ON child BEGIN SELECT 1; END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER DELETE ON child BEGIN DELETE FROM main.child; END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER INSERT ON child BEGIN INSERT INTO main.child(id) VALUES (1); END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER INSERT ON child BEGIN INSERT OR REPLACE INTO main.child(id) VALUES (1); END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN UPDATE main.child SET id=1; END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN UPDATE OR ROLLBACK main.child SET id=1; END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN UPDATE OR ABORT main.child SET id=1; END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN UPDATE OR FAIL main.child SET id=1; END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN UPDATE OR IGNORE main.child SET id=1; END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN UPDATE OR REPLACE main.child SET id=1; END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN UPDATE OR UNSUPPORTED child SET id=1; END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER INSERT ON child BEGIN INSERT OR UNSUPPORTED INTO child(id) VALUES (1); END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN SELECT id FROM main.child; END;",
            "CREATE TABLE child(id TEXT); CREATE TABLE other(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN SELECT child.id FROM child JOIN main.other ON other.id=child.id; END;",
            "CREATE TABLE child(id TEXT); CREATE TABLE other(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN SELECT child.id FROM child, main.other; END;",
            "CREATE TABLE child(id TEXT); CREATE TABLE other(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN SELECT child.id FROM child, (SELECT other.id FROM other, main.child); END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN SELECT * FROM (main.child); END;",
            "CREATE TABLE child(id TEXT); CREATE TABLE other(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN SELECT * FROM (child, main.other) AS grouped; END;",
            "CREATE TABLE child(id TEXT); CREATE TABLE other(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN SELECT * FROM child JOIN (other, main.child) AS grouped; END;",
            "CREATE TABLE child(id TEXT); CREATE TRIGGER child_guard AFTER UPDATE ON child BEGIN SELECT * FROM ((main.child)) AS grouped; END;",
        ] {
            assert!(
                std::panic::catch_unwind(|| parse(&[sql])).is_err(),
                "accepted {sql}"
            );
        }
    }

    #[test]
    fn trigger_from_commas_are_distinct_from_expression_and_nested_scope_commas() {
        let schema = parse(&[r#"
            CREATE TABLE child(id TEXT);
            CREATE TABLE other(id TEXT);
            CREATE TRIGGER child_comma_sources AFTER UPDATE ON child BEGIN
                SELECT child.id, other.id FROM child, other
                 WHERE coalesce(child.id, other.id) IN (
                    SELECT coalesce(child.id, other.id) FROM child, other
                 );
                SELECT (child.id), coalesce(child.id, other.id)
                  FROM (child, other) AS grouped;
                SELECT child.id FROM child JOIN other
                  ON coalesce(child.id, other.id) = coalesce(other.id, child.id);
                SELECT * FROM json_each(coalesce(child.id, other.id));
                SELECT * FROM json_each(lower(coalesce(child.id, other.id)));
                INSERT INTO child(id) VALUES (coalesce(NEW.id, OLD.id));
            END;
        "#]);
        assert!(
            schema
                .objects
                .iter()
                .any(|object| object.name == "child_comma_sources")
        );
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
    fn child_index_collation_must_match_parent_comparison() {
        let binary = parse(
            &["CREATE TABLE parent(id TEXT COLLATE nocase PRIMARY KEY); \
             CREATE TABLE child(parent_id TEXT REFERENCES parent(id) ON DELETE RESTRICT ON UPDATE RESTRICT); \
             CREATE INDEX child_parent_binary ON child(parent_id COLLATE binary);"],
        );
        assert!(
            child_leading_keys(
                &binary,
                "child",
                "parent",
                &["parent_id".to_owned()],
                &["id".to_owned()]
            )
            .is_empty()
        );
        let matching = parse(
            &["CREATE TABLE parent(id TEXT COLLATE nocase PRIMARY KEY); \
             CREATE TABLE child(parent_id TEXT REFERENCES parent(id) ON DELETE RESTRICT ON UPDATE RESTRICT); \
             CREATE INDEX child_parent_nocase ON child(parent_id COLLATE nocase);"],
        );
        assert_eq!(
            child_leading_keys(
                &matching,
                "child",
                "parent",
                &["parent_id".to_owned()],
                &["id".to_owned()]
            ),
            [vec!["parent_id".to_owned()]]
        );
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
            "CREATE INDEX child_early ON child(id); CREATE TABLE child(id TEXT);",
            "CREATE VIEW child_view AS SELECT id FROM child; CREATE TABLE child(id TEXT);",
            "CREATE TRIGGER child_guard BEFORE UPDATE ON child BEGIN SELECT 1; END; \
             CREATE TABLE child(id TEXT);",
            "CREATE TABLE parent(id TEXT PRIMARY KEY); \
             CREATE TABLE child(parent_id TEXT REFERENCES parent(id) ON DELETE RESTRICT ON UPDATE RESTRICT \
             REFERENCES parent(id));",
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
