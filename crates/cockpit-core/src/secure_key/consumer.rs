//! Consumer reference reconciliation seam and transaction-scoped hooks.
//!
//! Consumers must not use check-then-write across separate SQLite transactions.
//! Compose reachability mutations with [`activate_ref_in_tx`] /
//! [`begin_release_in_tx`] on the same `rusqlite::Connection`:
//!
//! ```ignore
//! db.write(|conn| {
//!     insert_consumer_ciphertext_row(conn, ...)?;  // makes ciphertext reachable
//!     activate_ref_in_tx(conn, &reference_id)?;     // Reserved -> Active
//!     Ok(())
//! })?;
//!
//! db.write(|conn| {
//!     delete_consumer_ciphertext_row(conn, ...)?;  // makes ciphertext unreachable
//!     begin_release_in_tx(conn, &reference_id)?;    // Active -> Releasing
//!     Ok(())
//! })?;
//! ```

use crate::db::secure_key::{activate_consumer_ref_conn, begin_release_consumer_ref_conn};

use super::error::SecureKeyError;

/// Injected consumer table probe for Reserved/Releasing reconciliation.
///
/// Unknown consumer kinds must fail closed (retain the reference).
pub trait ConsumerReconciler: Send + Sync {
    /// Whether a consumer record still exists for `(kind, id)`.
    ///
    /// Returns `Err` for unknown kinds (fail closed).
    fn consumer_exists(&self, kind: &str, id: &str) -> Result<bool, SecureKeyError>;
}

/// Default reconciler with no registered kinds — every kind fails closed.
pub struct FailClosedReconciler;

impl ConsumerReconciler for FailClosedReconciler {
    fn consumer_exists(&self, kind: &str, _id: &str) -> Result<bool, SecureKeyError> {
        Err(SecureKeyError::Invalid(format!(
            "unknown consumer kind: {kind}"
        )))
    }
}

/// Predicate for whether a consumer_id still exists (test reconciler).
type ConsumerExistsPred = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// Test reconciler: known kinds map to an existence predicate.
pub struct MapReconciler {
    pub known: std::collections::HashMap<String, ConsumerExistsPred>,
}

impl MapReconciler {
    pub fn new() -> Self {
        Self {
            known: std::collections::HashMap::new(),
        }
    }

    pub fn with_kind<F>(mut self, kind: impl Into<String>, f: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.known.insert(kind.into(), Box::new(f));
        self
    }
}

impl Default for MapReconciler {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsumerReconciler for MapReconciler {
    fn consumer_exists(&self, kind: &str, id: &str) -> Result<bool, SecureKeyError> {
        match self.known.get(kind) {
            Some(f) => Ok(f(id)),
            None => Err(SecureKeyError::Invalid(format!(
                "unknown consumer kind: {kind}"
            ))),
        }
    }
}

/// Reserved → Active inside the caller's open SQLite write transaction.
///
/// Must run in the same transaction that makes the consumer record reachable.
pub fn activate_ref_in_tx(
    conn: &rusqlite::Connection,
    reference_id: &str,
) -> Result<(), SecureKeyError> {
    if activate_consumer_ref_conn(conn, reference_id)
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?
    {
        Ok(())
    } else {
        Err(SecureKeyError::NotFound("reference not activatable".into()))
    }
}

/// Active → Releasing inside the caller's open SQLite write transaction.
///
/// Must run in the same transaction that makes the consumer record unreachable.
/// Stale/wrong IDs return NotFound without revealing key metadata.
pub fn begin_release_in_tx(
    conn: &rusqlite::Connection,
    reference_id: &str,
) -> Result<(), SecureKeyError> {
    if begin_release_consumer_ref_conn(conn, reference_id)
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?
    {
        Ok(())
    } else {
        Err(SecureKeyError::NotFound("reference not found".into()))
    }
}

/// A composite reconciler that routes `consumer_exists` by `consumer_kind`
/// to one of two sub-reconcilers, failing closed for unknown kinds.
///
/// Used by daemon/server production composition to extend the existing
/// `ExternalJournalSpoolReconciler` with a `tool_media_subject_binding`
/// existence probe.
pub struct CompositeConsumerReconciler<A: ConsumerReconciler, B: ConsumerReconciler> {
    pub external: A,
    pub tool_media_subject_binding: B,
}

impl<A: ConsumerReconciler, B: ConsumerReconciler> CompositeConsumerReconciler<A, B> {
    pub fn new(external: A, tool_media_subject_binding: B) -> Self {
        Self {
            external,
            tool_media_subject_binding,
        }
    }
}

impl<A: ConsumerReconciler, B: ConsumerReconciler> ConsumerReconciler
    for CompositeConsumerReconciler<A, B>
{
    fn consumer_exists(&self, kind: &str, id: &str) -> Result<bool, SecureKeyError> {
        match kind {
            crate::tool_media_authority::TOOL_MEDIA_SUBJECT_BINDING_CONSUMER_KIND => {
                self.tool_media_subject_binding.consumer_exists(kind, id)
            }
            _ => self.external.consumer_exists(kind, id),
        }
    }
}

impl<A: ConsumerReconciler, B: ConsumerReconciler> std::fmt::Debug
    for CompositeConsumerReconciler<A, B>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeConsumerReconciler")
            .finish_non_exhaustive()
    }
}

/// A DB-existence probe for `tool_media_subject_binding` consumer refs.
///
/// Checks whether a `message_tool_media_subject_bindings` row exists for
/// the consumer id (`<session>/<client-submission>`). Runs on the secure-key
/// actor's own OS thread (blocking read).
pub struct ToolMediaSubjectBindingDbProbe {
    db: crate::db::Db,
}

impl ToolMediaSubjectBindingDbProbe {
    pub fn new(db: crate::db::Db) -> Self {
        Self { db }
    }
}

impl std::fmt::Debug for ToolMediaSubjectBindingDbProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ToolMediaSubjectBindingDbProbe")
    }
}

impl ConsumerReconciler for ToolMediaSubjectBindingDbProbe {
    fn consumer_exists(&self, kind: &str, id: &str) -> Result<bool, SecureKeyError> {
        if kind != crate::tool_media_authority::TOOL_MEDIA_SUBJECT_BINDING_CONSUMER_KIND {
            return FailClosedReconciler.consumer_exists(kind, id);
        }
        let consumer_id = id.to_string();
        self.db
            .blocking_read_for_sync_ui(move |conn| {
                let exists: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM message_tool_media_subject_bindings
                         WHERE secure_key_reference_id = ?1)",
                        rusqlite::params![&consumer_id],
                        |row| row.get(0),
                    )
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok(exists)
            })
            .map_err(|e| SecureKeyError::Internal(format!("{e}")))
    }
}
