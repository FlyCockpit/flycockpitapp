//! Resolver-agnostic sealed references embedded in knowledge-base markdown.
//!
//! # Token format
//!
//! A committed concept carries a symbolic token only:
//!
//! ```text
//! {{sealed:v1:knowledge_base:<kb_attachment_uuid>:<record_uuid>}}
//! ```
//!
//! The grammar has no vault locator, ciphertext detail, installation identity,
//! or resolver name. The KB field is the immutable attachment identity, never
//! the reusable registry label. `v1` fixes the token grammar, not a transport protocol.
//! A future hosted resolver can therefore resolve the exact same token for an
//! authorized consumer without rewriting committed markdown. Remote reference
//! travel is deliberately deferred to the hosted server.
//!
//! The local implementation stores KB literals as encrypted
//! `secret_vault_items(kind = knowledge_base_sealed_value)` and never writes
//! them to a KB, its disposable SQLite sidecar, or git.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use cockpit_db::secret_vault::SecretVaultKind;
use uuid::Uuid;

use super::compartment::SealedLiteral;
use super::identity::{SealedKnowledgeBaseId, SealedRecordId, SealedScopeKind, SealedScopeRef};

const TOKEN_PREFIX: &str = "{{sealed:v1:";
const TOKEN_SUFFIX: &str = "}}";
const UNTRUSTED_REDACTION: &str = "[sealed value redacted]";

/// A parsed, safe symbolic reference. It is deliberately independent of the
/// implementation that will resolve it: no field is a vault key or ciphertext
/// locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedReference {
    scope: SealedScopeKind,
    scope_key: String,
    record_id: SealedRecordId,
}

impl SealedReference {
    pub fn new(scope: SealedScopeRef, record_id: SealedRecordId) -> Self {
        Self {
            scope: scope.kind(),
            scope_key: scope.scope_key(),
            record_id,
        }
    }

    pub fn scope(&self) -> SealedScopeKind {
        self.scope
    }

    pub fn scope_key(&self) -> &str {
        &self.scope_key
    }

    pub fn record_id(&self) -> SealedRecordId {
        self.record_id
    }

    pub fn knowledge_base_id(&self) -> Result<SealedKnowledgeBaseId> {
        if self.scope != SealedScopeKind::KnowledgeBase {
            bail!("sealed reference is not knowledge-base scoped");
        }
        SealedKnowledgeBaseId::parse(&self.scope_key)
    }

    /// Render the stable token written to markdown. Only KB-scoped references
    /// are markdown-capable; other scopes can be copied into a KB through the
    /// local resolver but must not be committed directly.
    pub fn token(&self) -> Result<String> {
        if self.scope != SealedScopeKind::KnowledgeBase {
            bail!("only knowledge-base sealed references may be written to markdown");
        }
        let kb_id = self.knowledge_base_id()?;
        Ok([
            TOKEN_PREFIX,
            "knowledge_base:",
            &kb_id.to_string(),
            ":",
            &self.record_id.to_string(),
            TOKEN_SUFFIX,
        ]
        .concat())
    }

    pub fn parse_token(token: &str) -> Result<Self> {
        let raw = token
            .strip_prefix(TOKEN_PREFIX)
            .and_then(|value| value.strip_suffix(TOKEN_SUFFIX))
            .context("sealed reference token has an invalid envelope")?;
        let mut parts = raw.split(':');
        let scope =
            SealedScopeKind::parse(parts.next().context("sealed reference scope missing")?)?;
        let scope_key = parts
            .next()
            .context("sealed reference scope key missing")?
            .to_string();
        let record_id =
            SealedRecordId::parse(parts.next().context("sealed reference record id missing")?)?;
        if parts.next().is_some() {
            bail!("sealed reference token has too many fields");
        }
        if scope != SealedScopeKind::KnowledgeBase {
            bail!("only knowledge-base sealed references may appear in markdown");
        }
        SealedKnowledgeBaseId::parse(&scope_key)?;
        Ok(Self {
            scope,
            scope_key,
            record_id,
        })
    }
}

/// The resolution seam used by KB reads. A hosted `RemoteResolver` can
/// implement this trait later without changing markdown or its parser.
#[async_trait]
pub trait SealedResolver: Send + Sync {
    /// Resolve exactly one symbolic reference, or fail closed. Implementations
    /// must never fall back to a similarly named local value.
    async fn resolve(&self, reference: &SealedReference) -> Result<SealedLiteral>;
}

/// Local daemon-vault resolver. It performs an exact vault-item lookup for a
/// KB value. Existing session/project/global values are deliberately excluded:
/// their only resolution path is the authorized sealed runtime.
#[derive(Clone)]
pub struct LocalVaultResolver {
    vault: Arc<crate::secure_key::SecretVault>,
}

impl LocalVaultResolver {
    pub fn new(vault: Arc<crate::secure_key::SecretVault>) -> Self {
        Self { vault }
    }
}

#[async_trait]
impl SealedResolver for LocalVaultResolver {
    async fn resolve(&self, reference: &SealedReference) -> Result<SealedLiteral> {
        match reference.scope {
            SealedScopeKind::KnowledgeBase => {
                let kb_id = reference.knowledge_base_id()?;
                let secret = self
                    .vault
                    .get_item(
                        SecretVaultKind::KnowledgeBaseSealedValue,
                        &knowledge_base_item_id(&kb_id, reference.record_id),
                    )
                    .map_err(|_| {
                        anyhow::anyhow!("sealed knowledge-base reference is unresolved")
                    })?;
                let value = String::from_utf8(secret.as_slice().to_vec())
                    .context("sealed knowledge-base value is not UTF-8")?;
                Ok(SealedLiteral::new(value))
            }
            SealedScopeKind::Session | SealedScopeKind::Project | SealedScopeKind::Global => {
                bail!("only knowledge-base references resolve through the local KB resolver")
            }
        }
    }
}

/// Owner-side local storage for KB-scoped values. It has no enumeration API:
/// creation returns a capability-like symbolic reference and all reads require
/// that exact reference.
#[derive(Clone)]
pub struct KnowledgeBaseSealedStore {
    vault: Arc<crate::secure_key::SecretVault>,
}

impl KnowledgeBaseSealedStore {
    pub fn new(vault: Arc<crate::secure_key::SecretVault>) -> Self {
        Self { vault }
    }

    pub fn create(
        &self,
        kb_id: SealedKnowledgeBaseId,
        literal: SealedLiteral,
    ) -> Result<SealedReference> {
        let reference = SealedReference::new(
            SealedScopeRef::KnowledgeBase(kb_id.clone()),
            SealedRecordId::from_uuid(Uuid::new_v4()),
        );
        self.vault
            .put_item(
                SecretVaultKind::KnowledgeBaseSealedValue,
                &knowledge_base_item_id(&kb_id, reference.record_id),
                literal.expose_for_redaction().as_bytes(),
            )
            .map_err(|error| anyhow::anyhow!("storing knowledge-base sealed value: {error}"))?;
        Ok(reference)
    }
}

/// Resolve KB tokens in one concept body at read time. For untrusted readers
/// the resolver is still consulted (so a dangling/foreign reference fails
/// closed), but the literal is dropped and a fixed redaction marker is emitted.
/// Thus no untrusted response can contain plaintext even when global redaction
/// is disabled.
pub async fn resolve_kb_markdown(
    markdown: &str,
    kb_id: &SealedKnowledgeBaseId,
    resolver: &dyn SealedResolver,
    trusted_reader: bool,
) -> Result<String> {
    let mut output = String::with_capacity(markdown.len());
    let mut rest = markdown;
    while let Some(start) = rest.find(TOKEN_PREFIX) {
        output.push_str(&rest[..start]);
        let token_start = &rest[start..];
        let end = token_start
            .find(TOKEN_SUFFIX)
            .context("unterminated sealed reference token in knowledge markdown")?
            + TOKEN_SUFFIX.len();
        let token = &token_start[..end];
        let reference = SealedReference::parse_token(token)?;
        if reference.knowledge_base_id()? != *kb_id {
            bail!("knowledge markdown contains a sealed reference for a different knowledge base");
        }
        let literal = resolver.resolve(&reference).await?;
        if trusted_reader {
            output.push_str(literal.expose_for_redaction());
        } else {
            output.push_str(UNTRUSTED_REDACTION);
        }
        rest = &token_start[end..];
    }
    output.push_str(rest);
    Ok(output)
}

pub(crate) fn knowledge_base_item_id(
    kb_id: &SealedKnowledgeBaseId,
    record_id: SealedRecordId,
) -> String {
    format!("kb:{kb_id}:{record_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEEDED_SECRET: &str = "seeded-kb-secret-must-never-enter-markdown";

    struct SeededResolver;

    #[async_trait]
    impl SealedResolver for SeededResolver {
        async fn resolve(&self, _reference: &SealedReference) -> Result<SealedLiteral> {
            Ok(SealedLiteral::new(SEEDED_SECRET))
        }
    }

    #[test]
    fn kb_token_is_symbolic_and_round_trips() {
        let reference = SealedReference::new(
            SealedScopeRef::KnowledgeBase(
                SealedKnowledgeBaseId::parse("4b3a7cd2-2af9-4f1f-bf8f-7f4cb32b59a9").unwrap(),
            ),
            SealedRecordId::from_uuid(Uuid::nil()),
        );
        let token = reference.token().unwrap();
        assert_eq!(
            token,
            "{{sealed:v1:knowledge_base:4b3a7cd2-2af9-4f1f-bf8f-7f4cb32b59a9:00000000-0000-0000-0000-000000000000}}"
        );
        assert_eq!(SealedReference::parse_token(&token).unwrap(), reference);
        assert!(!token.contains("ciphertext"));
        assert!(!token.contains("vault"));
    }

    #[test]
    fn markdown_rejects_non_kb_tokens() {
        assert!(
            SealedReference::parse_token(
                "{{sealed:v1:project:project:00000000-0000-0000-0000-000000000000}}"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn seeded_secret_stays_out_of_serialized_markdown_and_untrusted_reads() {
        let kb_id = SealedKnowledgeBaseId::parse("4b3a7cd2-2af9-4f1f-bf8f-7f4cb32b59a9").unwrap();
        let reference = SealedReference::new(
            SealedScopeRef::KnowledgeBase(kb_id.clone()),
            SealedRecordId::from_uuid(Uuid::nil()),
        );
        let markdown = format!("Deploy with {}.", reference.token().unwrap());

        let concept = crate::knowledge::KnowledgeConcept {
            id: "deploy".to_string(),
            path: "concepts/deploy.md".into(),
            concept_type: "procedure".to_string(),
            frontmatter: Default::default(),
            body: markdown,
            citations: Vec::new(),
            valid_from: None,
            supersedes: Vec::new(),
            invalidated_by: None,
        };
        // This is the exact value a concept writer commits. The seeded secret
        // exists only behind the resolver and therefore cannot enter git.
        let committed = crate::knowledge::serialize_concept(&concept);
        assert!(!committed.contains(SEEDED_SECRET));
        let untrusted = concept
            .body_for_reader(&kb_id, &SeededResolver, false)
            .await
            .unwrap();
        assert!(!untrusted.contains(SEEDED_SECRET));
        assert!(untrusted.contains(UNTRUSTED_REDACTION));
        assert_eq!(
            concept
                .body_for_reader(&kb_id, &SeededResolver, true)
                .await
                .unwrap(),
            format!("Deploy with {SEEDED_SECRET}.")
        );
    }

    #[tokio::test]
    async fn foreign_kb_reference_fails_closed() {
        let source_kb =
            SealedKnowledgeBaseId::parse("4b3a7cd2-2af9-4f1f-bf8f-7f4cb32b59a9").unwrap();
        let destination_kb =
            SealedKnowledgeBaseId::parse("e7c697b4-c3eb-47b6-8a33-b52dd6d4d282").unwrap();
        let reference = SealedReference::new(
            SealedScopeRef::KnowledgeBase(source_kb),
            SealedRecordId::from_uuid(Uuid::nil()),
        );
        assert!(
            resolve_kb_markdown(
                &reference.token().unwrap(),
                &destination_kb,
                &SeededResolver,
                false,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn local_vault_resolves_a_created_knowledge_base_reference() {
        let db = cockpit_db::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let local = LocalVaultResolver::new(vault.clone());
        let store = KnowledgeBaseSealedStore::new(vault);
        let kb_id = SealedKnowledgeBaseId::parse("4b3a7cd2-2af9-4f1f-bf8f-7f4cb32b59a9").unwrap();
        let reference = store
            .create(kb_id.clone(), SealedLiteral::new(SEEDED_SECRET))
            .unwrap();
        let markdown = reference.token().unwrap();
        assert!(!markdown.contains(SEEDED_SECRET));
        assert_eq!(
            resolve_kb_markdown(&markdown, &kb_id, &local, true)
                .await
                .unwrap(),
            SEEDED_SECRET
        );
    }
}
