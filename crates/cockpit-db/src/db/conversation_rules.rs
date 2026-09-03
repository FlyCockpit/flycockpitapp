//! Lineage-scoped conversation rules — agent-settable advisory directives
//! that must survive compaction verbatim.
//!
//! Rules attach to the compaction lineage root, not an individual window.
//! Forks mint their own lineage and do not inherit these rows. Distinct from
//! `/pin` (user free-text must-survive messages); there is no silent
//! conversion between them.

use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::Db;
use crate::db::session_log::now_ms;

/// Maximum UTF-8 byte length of a rule body.
pub const MAX_CONVERSATION_RULE_TEXT_BYTES: usize = 4000;
/// Maximum number of active rules on one conversation lineage.
pub const MAX_CONVERSATION_RULES_PER_LINEAGE: usize = 32;

/// Who authored the rule. Attribution is user-visible; it is not an
/// authorization boundary — both sides may set, edit, and revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationRuleCreatedBy {
    User,
    Agent,
}

impl ConversationRuleCreatedBy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "user" => Ok(Self::User),
            "agent" => Ok(Self::Agent),
            _ => bail!("invalid conversation-rule created_by `{value}`"),
        }
    }
}

/// Source-trust provenance for the rule text. Untrusted marks derivation
/// from untrusted model/tool output so injection can fence it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationRuleSourceTrust {
    Trusted,
    Untrusted,
}

impl ConversationRuleSourceTrust {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "trusted" => Ok(Self::Trusted),
            "untrusted" => Ok(Self::Untrusted),
            _ => bail!("invalid conversation-rule source_trust `{value}`"),
        }
    }
}

/// One conversation rule row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationRule {
    pub rule_id: Uuid,
    pub lineage_id: Uuid,
    pub text: String,
    pub created_by: ConversationRuleCreatedBy,
    pub source_trust: ConversationRuleSourceTrust,
    pub created_at_unix_ms: i64,
    pub active: bool,
}

impl Db {
    /// Insert or replace a conversation rule on the lineage that contains
    /// `session_id`. `rule_id = None` creates a new row. `Some` updates the
    /// text of an existing active rule on that lineage.
    pub async fn set_conversation_rule(
        &self,
        session_id: Uuid,
        rule_id: Option<Uuid>,
        text: &str,
        created_by: ConversationRuleCreatedBy,
        source_trust: ConversationRuleSourceTrust,
    ) -> Result<ConversationRule> {
        let text = normalize_rule_text(text)?;
        let created_by_s = created_by.as_str().to_string();
        let source_trust_s = source_trust.as_str().to_string();
        self.transaction(move |conn| {
            let lineage_id = lineage_id_conn(conn, session_id)?;
            if let Some(rule_id) = rule_id {
                update_rule_text_conn(conn, lineage_id, rule_id, &text)
            } else {
                insert_rule_conn(
                    conn,
                    lineage_id,
                    &text,
                    &created_by_s,
                    &source_trust_s,
                    now_ms(),
                )
            }
        })
        .await
    }

    pub fn set_conversation_rule_conn(
        conn: &rusqlite::Connection,
        session_id: Uuid,
        rule_id: Option<Uuid>,
        text: &str,
        created_by: ConversationRuleCreatedBy,
        source_trust: ConversationRuleSourceTrust,
        created_at_unix_ms: i64,
    ) -> Result<ConversationRule> {
        let text = normalize_rule_text(text)?;
        let lineage_id = lineage_id_conn(conn, session_id)?;
        if let Some(rule_id) = rule_id {
            update_rule_text_conn(conn, lineage_id, rule_id, &text)
        } else {
            insert_rule_conn(
                conn,
                lineage_id,
                &text,
                created_by.as_str(),
                source_trust.as_str(),
                created_at_unix_ms,
            )
        }
    }

    /// Active rules for the lineage that contains `session_id`, oldest first.
    pub async fn list_active_conversation_rules(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ConversationRule>> {
        self.read(move |conn| list_rules_conn(conn, session_id, true))
            .await
    }

    pub fn list_active_conversation_rules_conn(
        conn: &rusqlite::Connection,
        session_id: Uuid,
    ) -> Result<Vec<ConversationRule>> {
        list_rules_conn(conn, session_id, true)
    }

    /// All rules for the lineage (including revoked), oldest first.
    pub async fn list_conversation_rules(&self, session_id: Uuid) -> Result<Vec<ConversationRule>> {
        self.read(move |conn| list_rules_conn(conn, session_id, false))
            .await
    }

    pub fn list_conversation_rules_conn(
        conn: &rusqlite::Connection,
        session_id: Uuid,
    ) -> Result<Vec<ConversationRule>> {
        list_rules_conn(conn, session_id, false)
    }

    /// Load one rule by id if it belongs to the lineage of `session_id`.
    pub async fn get_conversation_rule(
        &self,
        session_id: Uuid,
        rule_id: Uuid,
    ) -> Result<Option<ConversationRule>> {
        self.read(move |conn| get_rule_conn(conn, session_id, rule_id))
            .await
    }

    /// Soft-revoke. Returns `true` when an active row was deactivated.
    pub async fn remove_conversation_rule(&self, session_id: Uuid, rule_id: Uuid) -> Result<bool> {
        self.transaction(move |conn| remove_rule_conn(conn, session_id, rule_id))
            .await
    }

    pub fn remove_conversation_rule_conn(
        conn: &rusqlite::Connection,
        session_id: Uuid,
        rule_id: Uuid,
    ) -> Result<bool> {
        remove_rule_conn(conn, session_id, rule_id)
    }
}

fn lineage_id_conn(conn: &rusqlite::Connection, session_id: Uuid) -> Result<Uuid> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT COALESCE(compaction_lineage_root_id, session_id)
               FROM sessions
              WHERE session_id = ?1",
            [session_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .context("resolving conversation lineage")?;
    let Some(raw) = raw else {
        bail!("unknown session {session_id}");
    };
    Uuid::parse_str(&raw).context("parsing conversation lineage id")
}

fn insert_rule_conn(
    conn: &rusqlite::Connection,
    lineage_id: Uuid,
    text: &str,
    created_by: &str,
    source_trust: &str,
    created_at_unix_ms: i64,
) -> Result<ConversationRule> {
    let active: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM conversation_rules
              WHERE lineage_id = ?1 AND active = 1",
            [lineage_id.to_string()],
            |row| row.get(0),
        )
        .context("counting conversation rules")?;
    if active as usize >= MAX_CONVERSATION_RULES_PER_LINEAGE {
        bail!("conversation lineage already has {MAX_CONVERSATION_RULES_PER_LINEAGE} active rules");
    }
    let rule_id = Uuid::now_v7();
    conn.execute(
        "INSERT INTO conversation_rules
            (rule_id, lineage_id, text, created_by, source_trust, created_at_unix_ms, active)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
        params![
            rule_id.to_string(),
            lineage_id.to_string(),
            text,
            created_by,
            source_trust,
            created_at_unix_ms,
        ],
    )
    .context("inserting conversation rule")?;
    Ok(ConversationRule {
        rule_id,
        lineage_id,
        text: text.to_string(),
        created_by: ConversationRuleCreatedBy::parse(created_by)?,
        source_trust: ConversationRuleSourceTrust::parse(source_trust)?,
        created_at_unix_ms,
        active: true,
    })
}

fn update_rule_text_conn(
    conn: &rusqlite::Connection,
    lineage_id: Uuid,
    rule_id: Uuid,
    text: &str,
) -> Result<ConversationRule> {
    let n = conn
        .execute(
            "UPDATE conversation_rules
                SET text = ?1
              WHERE rule_id = ?2 AND lineage_id = ?3 AND active = 1",
            params![text, rule_id.to_string(), lineage_id.to_string()],
        )
        .context("updating conversation rule")?;
    if n != 1 {
        bail!("conversation rule {rule_id} is not an active rule on this lineage");
    }
    get_rule_by_id_conn(conn, rule_id)?
        .ok_or_else(|| anyhow::anyhow!("conversation rule {rule_id} missing after update"))
}

fn remove_rule_conn(conn: &rusqlite::Connection, session_id: Uuid, rule_id: Uuid) -> Result<bool> {
    let lineage_id = lineage_id_conn(conn, session_id)?;
    let n = conn
        .execute(
            "UPDATE conversation_rules
                SET active = 0
              WHERE rule_id = ?1 AND lineage_id = ?2 AND active = 1",
            params![rule_id.to_string(), lineage_id.to_string()],
        )
        .context("revoking conversation rule")?;
    Ok(n == 1)
}

fn list_rules_conn(
    conn: &rusqlite::Connection,
    session_id: Uuid,
    active_only: bool,
) -> Result<Vec<ConversationRule>> {
    let lineage_id = lineage_id_conn(conn, session_id)?;
    let sql = if active_only {
        "SELECT rule_id, lineage_id, text, created_by, source_trust, created_at_unix_ms, active
           FROM conversation_rules
          WHERE lineage_id = ?1 AND active = 1
          ORDER BY created_at_unix_ms ASC, rule_id ASC"
    } else {
        "SELECT rule_id, lineage_id, text, created_by, source_trust, created_at_unix_ms, active
           FROM conversation_rules
          WHERE lineage_id = ?1
          ORDER BY created_at_unix_ms ASC, rule_id ASC"
    };
    let mut stmt = conn.prepare(sql).context("preparing conversation rules")?;
    let rows = stmt
        .query_map([lineage_id.to_string()], decode_rule_row)
        .context("querying conversation rules")?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.context("decoding conversation rule")??);
    }
    Ok(out)
}

fn get_rule_conn(
    conn: &rusqlite::Connection,
    session_id: Uuid,
    rule_id: Uuid,
) -> Result<Option<ConversationRule>> {
    let lineage_id = lineage_id_conn(conn, session_id)?;
    let mut stmt = conn
        .prepare(
            "SELECT rule_id, lineage_id, text, created_by, source_trust, created_at_unix_ms, active
               FROM conversation_rules
              WHERE rule_id = ?1 AND lineage_id = ?2",
        )
        .context("preparing conversation rule get")?;
    let row = stmt
        .query_row(
            [rule_id.to_string(), lineage_id.to_string()],
            decode_rule_row,
        )
        .optional()
        .context("loading conversation rule")?;
    row.transpose()
}

fn get_rule_by_id_conn(
    conn: &rusqlite::Connection,
    rule_id: Uuid,
) -> Result<Option<ConversationRule>> {
    let mut stmt = conn
        .prepare(
            "SELECT rule_id, lineage_id, text, created_by, source_trust, created_at_unix_ms, active
               FROM conversation_rules
              WHERE rule_id = ?1",
        )
        .context("preparing conversation rule by id")?;
    let row = stmt
        .query_row([rule_id.to_string()], decode_rule_row)
        .optional()
        .context("loading conversation rule by id")?;
    row.transpose()
}

fn decode_rule_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<ConversationRule>> {
    let rule_id: String = row.get(0)?;
    let lineage_id: String = row.get(1)?;
    let text: String = row.get(2)?;
    let created_by: String = row.get(3)?;
    let source_trust: String = row.get(4)?;
    let created_at_unix_ms: i64 = row.get(5)?;
    let active: i64 = row.get(6)?;
    Ok((|| {
        Ok(ConversationRule {
            rule_id: Uuid::parse_str(&rule_id).context("parsing rule_id")?,
            lineage_id: Uuid::parse_str(&lineage_id).context("parsing lineage_id")?,
            text,
            created_by: ConversationRuleCreatedBy::parse(&created_by)?,
            source_trust: ConversationRuleSourceTrust::parse(&source_trust)?,
            created_at_unix_ms,
            active: active != 0,
        })
    })())
}

fn normalize_rule_text(text: &str) -> Result<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("conversation rule text must not be empty");
    }
    if trimmed.len() > MAX_CONVERSATION_RULE_TEXT_BYTES {
        bail!("conversation rule text exceeds {MAX_CONVERSATION_RULE_TEXT_BYTES} bytes");
    }
    if trimmed
        .chars()
        .any(|ch| ch.is_control() && ch != '\n' && ch != '\t')
    {
        bail!("conversation rule text must not contain control characters");
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_list_remove_and_lineage_scope() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "Build").await.unwrap();
        let successor = db
            .create_compaction_successor(root.session_id)
            .await
            .unwrap();
        let fork = db.create_fork(root.session_id, None).await.unwrap();

        let created = db
            .set_conversation_rule(
                root.session_id,
                None,
                "prefer pnpm, not npm",
                ConversationRuleCreatedBy::Agent,
                ConversationRuleSourceTrust::Trusted,
            )
            .await
            .unwrap();
        assert_eq!(created.text, "prefer pnpm, not npm");
        assert_eq!(created.created_by, ConversationRuleCreatedBy::Agent);
        assert!(created.active);
        assert_eq!(created.lineage_id, root.compaction_lineage_root());

        let on_successor = db
            .list_active_conversation_rules(successor.session_id)
            .await
            .unwrap();
        assert_eq!(on_successor.len(), 1);
        assert_eq!(on_successor[0].rule_id, created.rule_id);

        let on_fork = db
            .list_active_conversation_rules(fork.session_id)
            .await
            .unwrap();
        assert!(
            on_fork.is_empty(),
            "forks mint their own lineage and must not inherit rules"
        );

        let edited = db
            .set_conversation_rule(
                successor.session_id,
                Some(created.rule_id),
                "prefer pnpm; never npm",
                ConversationRuleCreatedBy::User,
                ConversationRuleSourceTrust::Trusted,
            )
            .await
            .unwrap();
        assert_eq!(edited.rule_id, created.rule_id);
        assert_eq!(edited.text, "prefer pnpm; never npm");
        assert_eq!(
            edited.created_by,
            ConversationRuleCreatedBy::Agent,
            "edit must not rewrite attribution"
        );

        assert!(
            db.remove_conversation_rule(successor.session_id, created.rule_id)
                .await
                .unwrap()
        );
        assert!(
            db.list_active_conversation_rules(root.session_id)
                .await
                .unwrap()
                .is_empty()
        );
        let all = db.list_conversation_rules(root.session_id).await.unwrap();
        assert_eq!(all.len(), 1);
        assert!(!all[0].active);
        assert!(
            !db.remove_conversation_rule(root.session_id, created.rule_id)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn rejects_empty_oversize_and_control_chars() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();

        let empty = db
            .set_conversation_rule(
                session.session_id,
                None,
                "   ",
                ConversationRuleCreatedBy::User,
                ConversationRuleSourceTrust::Trusted,
            )
            .await
            .unwrap_err();
        assert!(format!("{empty:#}").contains("must not be empty"));

        let control = db
            .set_conversation_rule(
                session.session_id,
                None,
                "never\u{0007}touch prod",
                ConversationRuleCreatedBy::User,
                ConversationRuleSourceTrust::Trusted,
            )
            .await
            .unwrap_err();
        assert!(format!("{control:#}").contains("control characters"));

        let oversize = "x".repeat(MAX_CONVERSATION_RULE_TEXT_BYTES + 1);
        let err = db
            .set_conversation_rule(
                session.session_id,
                None,
                &oversize,
                ConversationRuleCreatedBy::User,
                ConversationRuleSourceTrust::Trusted,
            )
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("exceeds"));
    }

    #[tokio::test]
    async fn caps_active_rules_per_lineage() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        for i in 0..MAX_CONVERSATION_RULES_PER_LINEAGE {
            db.set_conversation_rule(
                session.session_id,
                None,
                &format!("rule {i}"),
                ConversationRuleCreatedBy::Agent,
                ConversationRuleSourceTrust::Untrusted,
            )
            .await
            .unwrap();
        }
        let err = db
            .set_conversation_rule(
                session.session_id,
                None,
                "one too many",
                ConversationRuleCreatedBy::Agent,
                ConversationRuleSourceTrust::Trusted,
            )
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("already has"));
    }

    #[tokio::test]
    async fn unknown_session_and_missing_rule_fail_closed() {
        let db = Db::open_in_memory().unwrap();
        let missing = Uuid::now_v7();
        let err = db
            .list_active_conversation_rules(missing)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("unknown session"));

        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let err = db
            .set_conversation_rule(
                session.session_id,
                Some(Uuid::now_v7()),
                "no such rule",
                ConversationRuleCreatedBy::User,
                ConversationRuleSourceTrust::Trusted,
            )
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("not an active rule"));
    }
}
