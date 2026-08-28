//! Order-preserving JSON parser that rejects duplicate object member names.
//!
//! serde_json is last-wins; this parser is not. A duplicate is a malformed
//! frame at every object depth, including the JSON-RPC envelope and every
//! `session/new` / `session/load` admission object.

use std::collections::HashSet;

const MAX_JSON_NESTING_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawJsonError {
    pub kind: RawJsonErrorKind,
    pub unambiguous_request_id: Option<JsonRpcId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawJsonErrorKind {
    Syntax(&'static str),
    DuplicateMember { path: String, name: String },
    TrailingJunk,
}

impl std::fmt::Display for RawJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            RawJsonErrorKind::Syntax(msg) => write!(f, "malformed JSON: {msg}"),
            RawJsonErrorKind::DuplicateMember { path, name } => {
                write!(f, "duplicate JSON member {name:?} at {path}")
            }
            RawJsonErrorKind::TrailingJunk => f.write_str("trailing bytes after JSON value"),
        }
    }
}

impl std::error::Error for RawJsonError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawNode {
    pub kind: RawKind,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawKind {
    Null,
    Bool(bool),
    Number,
    String(String),
    Array(Vec<RawNode>),
    Object(Vec<(String, RawNode)>),
}

impl RawNode {
    pub fn raw<'a>(&self, input: &'a str) -> &'a str {
        &input[self.start..self.end]
    }

    pub fn as_object(&self) -> Option<&[(String, RawNode)]> {
        match &self.kind {
            RawKind::Object(members) => Some(members),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[RawNode]> {
        match &self.kind {
            RawKind::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match &self.kind {
            RawKind::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn member(&self, name: &str) -> Option<&RawNode> {
        self.as_object()?
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, node)| node)
    }

    pub fn member_count(&self, name: &str) -> usize {
        self.as_object()
            .map(|members| members.iter().filter(|(key, _)| key == name).count())
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFrame {
    pub root: RawNode,
    pub unambiguous_request_id: Option<JsonRpcId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonRpcId {
    Null,
    Number(String),
    String(String),
}

impl JsonRpcId {
    pub fn to_json(&self) -> String {
        match self {
            Self::Null => "null".to_string(),
            Self::Number(n) => n.clone(),
            Self::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "null".to_string()),
        }
    }
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
    root_id: Option<JsonRpcId>,
    root_id_seen: bool,
    root_id_ambiguous: bool,
    first_duplicate: Option<RawJsonErrorKind>,
}

pub fn parse_frame(input: &str) -> Result<ParsedFrame, RawJsonError> {
    let mut parser = Parser {
        input,
        pos: 0,
        root_id: None,
        root_id_seen: false,
        root_id_ambiguous: false,
        first_duplicate: None,
    };
    parser.skip_ws();
    let root = parser.parse_value("", 0)?;
    parser.skip_ws();
    if parser.pos != parser.input.len() {
        return Err(parser.fail(RawJsonErrorKind::TrailingJunk));
    }
    if let Some(kind) = parser.first_duplicate.take() {
        return Err(parser.fail(kind));
    }
    let unambiguous_request_id = if parser.root_id_ambiguous {
        None
    } else {
        parser.root_id
    };
    Ok(ParsedFrame {
        root,
        unambiguous_request_id,
    })
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while let Some(ch) = self.peek_char() {
            if ch == ' ' || ch == '\t' || ch == '\r' {
                self.bump();
            } else {
                break;
            }
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn parse_value(&mut self, path: &str, depth: usize) -> Result<RawNode, RawJsonError> {
        if depth > MAX_JSON_NESTING_DEPTH {
            return Err(self.fail(RawJsonErrorKind::Syntax("JSON nesting limit exceeded")));
        }
        self.skip_ws();
        let start = self.pos;
        match self.peek_char() {
            Some('n') => {
                self.expect_ident("null")?;
                Ok(RawNode {
                    kind: RawKind::Null,
                    start,
                    end: self.pos,
                })
            }
            Some('t') => {
                self.expect_ident("true")?;
                Ok(RawNode {
                    kind: RawKind::Bool(true),
                    start,
                    end: self.pos,
                })
            }
            Some('f') => {
                self.expect_ident("false")?;
                Ok(RawNode {
                    kind: RawKind::Bool(false),
                    start,
                    end: self.pos,
                })
            }
            Some('"') => {
                let decoded = self.parse_string()?;
                Ok(RawNode {
                    kind: RawKind::String(decoded),
                    start,
                    end: self.pos,
                })
            }
            Some('[') => self.parse_array(path, start, depth),
            Some('{') => self.parse_object(path, start, depth),
            Some('-') | Some('0'..='9') => {
                self.parse_number()?;
                Ok(RawNode {
                    kind: RawKind::Number,
                    start,
                    end: self.pos,
                })
            }
            _ => Err(self.fail(RawJsonErrorKind::Syntax("expected JSON value"))),
        }
    }

    fn fail(&self, kind: RawJsonErrorKind) -> RawJsonError {
        RawJsonError {
            kind,
            unambiguous_request_id: if self.root_id_ambiguous {
                None
            } else {
                self.root_id.clone()
            },
        }
    }

    fn expect_ident(&mut self, ident: &str) -> Result<(), RawJsonError> {
        if self.input[self.pos..].starts_with(ident) {
            self.pos += ident.len();
            Ok(())
        } else {
            Err(self.fail(RawJsonErrorKind::Syntax("invalid literal")))
        }
    }

    fn parse_number(&mut self) -> Result<(), RawJsonError> {
        if self.peek_char() == Some('-') {
            self.bump();
        }
        match self.peek_char() {
            Some('0') => {
                self.bump();
            }
            Some('1'..='9') => {
                while matches!(self.peek_char(), Some('0'..='9')) {
                    self.bump();
                }
            }
            _ => return Err(self.fail(RawJsonErrorKind::Syntax("invalid number"))),
        }
        if self.peek_char() == Some('.') {
            self.bump();
            if !matches!(self.peek_char(), Some('0'..='9')) {
                return Err(self.fail(RawJsonErrorKind::Syntax("invalid number fraction")));
            }
            while matches!(self.peek_char(), Some('0'..='9')) {
                self.bump();
            }
        }
        if matches!(self.peek_char(), Some('e' | 'E')) {
            self.bump();
            if matches!(self.peek_char(), Some('+' | '-')) {
                self.bump();
            }
            if !matches!(self.peek_char(), Some('0'..='9')) {
                return Err(self.fail(RawJsonErrorKind::Syntax("invalid number exponent")));
            }
            while matches!(self.peek_char(), Some('0'..='9')) {
                self.bump();
            }
        }
        Ok(())
    }

    fn parse_string(&mut self) -> Result<String, RawJsonError> {
        if self.bump() != Some('"') {
            return Err(self.fail(RawJsonErrorKind::Syntax("expected string")));
        }
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(self.fail(RawJsonErrorKind::Syntax("unterminated string"))),
                Some('"') => return Ok(out),
                Some('\\') => match self.bump() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('b') => out.push('\u{0008}'),
                    Some('f') => out.push('\u{000c}'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('u') => self.parse_unicode_escape(&mut out)?,
                    _ => return Err(self.fail(RawJsonErrorKind::Syntax("invalid string escape"))),
                },
                Some(ch) if ch.is_control() => {
                    return Err(self.fail(RawJsonErrorKind::Syntax("unescaped control in string")));
                }
                Some(ch) => out.push(ch),
            }
        }
    }

    fn parse_hex_code_unit(&mut self) -> Result<u16, RawJsonError> {
        let mut code = 0u32;
        for _ in 0..4 {
            let ch = self
                .bump()
                .ok_or_else(|| self.fail(RawJsonErrorKind::Syntax("short unicode escape")))?;
            code <<= 4;
            code += ch
                .to_digit(16)
                .ok_or_else(|| self.fail(RawJsonErrorKind::Syntax("invalid unicode escape")))?;
        }
        Ok(code as u16)
    }

    fn parse_unicode_escape(&mut self, out: &mut String) -> Result<(), RawJsonError> {
        let first = self.parse_hex_code_unit()?;
        let scalar = if (0xD800..=0xDBFF).contains(&first) {
            if self.bump() != Some('\\') || self.bump() != Some('u') {
                return Err(self.fail(RawJsonErrorKind::Syntax("unpaired high surrogate")));
            }
            let second = self.parse_hex_code_unit()?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(self.fail(RawJsonErrorKind::Syntax("invalid low surrogate")));
            }
            0x1_0000 + (((first as u32 - 0xD800) << 10) | (second as u32 - 0xDC00))
        } else if (0xDC00..=0xDFFF).contains(&first) {
            return Err(self.fail(RawJsonErrorKind::Syntax("unpaired low surrogate")));
        } else {
            first as u32
        };
        out.push(
            char::from_u32(scalar)
                .ok_or_else(|| self.fail(RawJsonErrorKind::Syntax("invalid unicode scalar")))?,
        );
        Ok(())
    }

    fn parse_array(
        &mut self,
        path: &str,
        start: usize,
        depth: usize,
    ) -> Result<RawNode, RawJsonError> {
        self.bump();
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek_char() == Some(']') {
            self.bump();
            return Ok(RawNode {
                kind: RawKind::Array(items),
                start,
                end: self.pos,
            });
        }
        let mut index = 0usize;
        loop {
            let child_path = format!("{path}[{index}]");
            items.push(self.parse_value(&child_path, depth + 1)?);
            self.skip_ws();
            match self.peek_char() {
                Some(',') => {
                    self.bump();
                    index += 1;
                }
                Some(']') => {
                    self.bump();
                    break;
                }
                _ => return Err(self.fail(RawJsonErrorKind::Syntax("expected comma or array end"))),
            }
        }
        Ok(RawNode {
            kind: RawKind::Array(items),
            start,
            end: self.pos,
        })
    }

    fn parse_object(
        &mut self,
        path: &str,
        start: usize,
        depth: usize,
    ) -> Result<RawNode, RawJsonError> {
        self.bump();
        self.skip_ws();
        let mut members = Vec::new();
        let mut seen = HashSet::new();
        if self.peek_char() == Some('}') {
            self.bump();
            return Ok(RawNode {
                kind: RawKind::Object(members),
                start,
                end: self.pos,
            });
        }
        loop {
            self.skip_ws();
            if self.peek_char() != Some('"') {
                return Err(self.fail(RawJsonErrorKind::Syntax("expected object member name")));
            }
            let name = self.parse_string()?;
            self.skip_ws();
            if self.bump() != Some(':') {
                return Err(self.fail(RawJsonErrorKind::Syntax("expected colon")));
            }
            if !seen.insert(name.clone()) && self.first_duplicate.is_none() {
                self.first_duplicate = Some(RawJsonErrorKind::DuplicateMember {
                    path: if path.is_empty() {
                        "<root>".to_string()
                    } else {
                        path.to_string()
                    },
                    name: name.clone(),
                });
            }
            let child_path = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };
            let value = self.parse_value(&child_path, depth + 1)?;
            if path.is_empty() && name == "id" {
                if self.root_id_seen {
                    self.root_id_ambiguous = true;
                    self.root_id = None;
                } else if !self.root_id_ambiguous {
                    self.root_id_seen = true;
                    self.root_id = json_rpc_id_from_node(&value, self.input);
                }
            }
            members.push((name, value));
            self.skip_ws();
            match self.peek_char() {
                Some(',') => {
                    self.bump();
                }
                Some('}') => {
                    self.bump();
                    break;
                }
                _ => {
                    return Err(self.fail(RawJsonErrorKind::Syntax("expected comma or object end")));
                }
            }
        }
        Ok(RawNode {
            kind: RawKind::Object(members),
            start,
            end: self.pos,
        })
    }
}

fn json_rpc_id_from_node(node: &RawNode, input: &str) -> Option<JsonRpcId> {
    match &node.kind {
        RawKind::Null => Some(JsonRpcId::Null),
        RawKind::Number => Some(JsonRpcId::Number(node.raw(input).to_string())),
        RawKind::String(value) => Some(JsonRpcId::String(value.clone())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acp_transport_raw_rejects_outer_duplicate_jsonrpc() {
        let err = parse_frame(r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"initialize"}"#)
            .unwrap_err();
        match err.kind {
            RawJsonErrorKind::DuplicateMember { path, name } => {
                assert_eq!(path, "<root>");
                assert_eq!(name, "jsonrpc");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn acp_transport_raw_rejects_params_duplicate_cwd() {
        let err = parse_frame(
            r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/a","cwd":"/b","mcpServers":[]}}"#,
        )
        .unwrap_err();
        match err.kind {
            RawJsonErrorKind::DuplicateMember { path, name } => {
                assert_eq!(path, "params");
                assert_eq!(name, "cwd");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn acp_transport_raw_keeps_member_order() {
        let parsed = parse_frame(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#).unwrap();
        let names: Vec<_> = parsed
            .root
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(names, ["jsonrpc", "id", "method"]);
    }

    #[test]
    fn acp_transport_raw_unambiguous_id_survives_nested_duplicate() {
        let err = parse_frame(
            r#"{"jsonrpc":"2.0","id":7,"method":"session/new","params":{"cwd":"/a","mcpServers":[{"name":"x","name":"y","command":"c"}]}}"#,
        )
        .unwrap_err();
        assert!(matches!(
            err.kind,
            RawJsonErrorKind::DuplicateMember { ref name, .. } if name == "name"
        ));
        assert_eq!(
            err.unambiguous_request_id,
            Some(JsonRpcId::Number("7".into()))
        );
    }

    #[test]
    fn acp_transport_raw_records_nested_duplicate_before_later_root_id() {
        let err = parse_frame(
            r#"{"jsonrpc":"2.0","method":"session/new","params":{"cwd":"/a","cwd":"/b","mcpServers":[]},"id":7}"#,
        )
        .unwrap_err();
        assert_eq!(
            &err.kind,
            &RawJsonErrorKind::DuplicateMember {
                path: "params".into(),
                name: "cwd".into(),
            }
        );
        assert_eq!(
            err.unambiguous_request_id,
            Some(JsonRpcId::Number("7".into()))
        );
    }

    #[test]
    fn acp_transport_raw_duplicate_root_id_is_ambiguous() {
        let err =
            parse_frame(r#"{"jsonrpc":"2.0","id":7,"method":"initialize","id":8}"#).unwrap_err();
        assert!(matches!(
            &err.kind,
            RawJsonErrorKind::DuplicateMember { path, name }
                if path == "<root>" && name == "id"
        ));
        assert_eq!(err.unambiguous_request_id, None);
    }

    #[test]
    fn acp_transport_raw_accepts_surrogate_pair_and_rejects_unpaired_surrogate() {
        let parsed = parse_frame(r#"{"value":"\uD83D\uDE00"}"#).unwrap();
        assert_eq!(
            parsed.root.member("value").and_then(RawNode::as_str),
            Some("😀")
        );
        assert!(parse_frame(r#"{"value":"\uD83D"}"#).is_err());
        assert!(parse_frame(r#"{"value":"\uDE00"}"#).is_err());
    }

    #[test]
    fn acp_transport_raw_rejects_excessive_nesting() {
        let nested = format!(
            "{}null{}",
            "[".repeat(MAX_JSON_NESTING_DEPTH + 1),
            "]".repeat(MAX_JSON_NESTING_DEPTH + 1)
        );
        assert!(parse_frame(&nested).is_err());
    }
}
