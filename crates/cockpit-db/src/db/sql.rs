//! Small helpers for dynamic SQL fragments used by DB queries.

use rusqlite::ToSql;

pub struct PredicateBuilder {
    clauses: Vec<String>,
    params: Vec<Box<dyn ToSql>>,
}

impl PredicateBuilder {
    pub fn new() -> Self {
        Self {
            clauses: Vec::new(),
            params: Vec::new(),
        }
    }

    pub fn push_static(&mut self, clause: impl Into<String>) {
        self.clauses.push(clause.into());
    }

    pub fn push_value<T>(&mut self, prefix: impl AsRef<str>, value: T)
    where
        T: ToSql + 'static,
    {
        let placeholder = self.next_placeholder();
        self.clauses
            .push(format!("{} {placeholder}", prefix.as_ref()));
        self.params.push(Box::new(value));
    }

    pub fn push_eq<T>(&mut self, column: SqlColumn, value: T)
    where
        T: ToSql + 'static,
    {
        self.push_value(format!("{} =", column.sql()), value);
    }

    pub fn push_param<T>(&mut self, value: T) -> String
    where
        T: ToSql + 'static,
    {
        let placeholder = self.next_placeholder();
        self.params.push(Box::new(value));
        placeholder
    }

    pub fn next_placeholder(&self) -> String {
        format!("?{}", self.params.len() + 1)
    }

    pub fn finish(self) -> (String, Vec<Box<dyn ToSql>>) {
        (self.clauses.join(" AND "), self.params)
    }
}

impl Default for PredicateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlColumn {
    ToolCallTimestamp,
    Tool,
    Model,
    ProjectId,
    InferenceCallTimestamp,
}

impl SqlColumn {
    pub fn sql(self) -> &'static str {
        match self {
            Self::ToolCallTimestamp => "timestamp",
            Self::Tool => "tool",
            Self::Model => "model",
            Self::ProjectId => "project_id",
            Self::InferenceCallTimestamp => "ic.timestamp",
        }
    }
}

pub fn placeholders(start: usize, count: usize) -> String {
    (start..start + count)
        .map(|n| format!("?{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate_builder_handles_zero_filters() {
        let builder = PredicateBuilder::new();
        let (sql, params) = builder.finish();
        assert_eq!(sql, "");
        assert_eq!(params.len(), 0);
    }

    #[test]
    fn predicate_builder_numbers_required_and_optional_filters() {
        let mut builder = PredicateBuilder::new();
        builder.push_value("timestamp >=", 100_i64);
        builder.push_eq(SqlColumn::Tool, "bash".to_string());
        builder.push_eq(SqlColumn::ProjectId, "project".to_string());
        let (sql, params) = builder.finish();
        assert_eq!(sql, "timestamp >= ?1 AND tool = ?2 AND project_id = ?3");
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn push_param_reserves_placeholder_without_predicate_clause() {
        let mut builder = PredicateBuilder::new();
        builder.push_value("timestamp >=", 100_i64);
        let limit = builder.push_param(25_i64);
        let (sql, params) = builder.finish();
        assert_eq!(limit, "?2");
        assert_eq!(sql, "timestamp >= ?1");
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn predicate_builder_mixes_static_clauses_without_consuming_placeholders() {
        let mut builder = PredicateBuilder::new();
        builder.push_value("timestamp >=", 100_i64);
        builder.push_static("(hard_fail = 1 OR recovery_kind IS NOT NULL)");
        builder.push_eq(SqlColumn::Model, "gpt".to_string());
        let (sql, params) = builder.finish();
        assert_eq!(
            sql,
            "timestamp >= ?1 AND (hard_fail = 1 OR recovery_kind IS NOT NULL) AND model = ?2"
        );
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn whitelisted_columns_render_expected_identifiers() {
        assert_eq!(SqlColumn::ToolCallTimestamp.sql(), "timestamp");
        assert_eq!(SqlColumn::InferenceCallTimestamp.sql(), "ic.timestamp");
    }

    #[test]
    fn placeholder_list_uses_requested_start_and_count() {
        assert_eq!(placeholders(2, 3), "?2, ?3, ?4");
        assert_eq!(placeholders(1, 0), "");
    }
}
