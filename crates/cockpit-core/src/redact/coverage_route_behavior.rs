//! Behavioral invariants shared by production coverage route tests.

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use anyhow::Result;

    use super::super::coverage_authority::{CoverageBinding, RedactionCoverageKey};
    use super::super::{
        RedactionTable,
        coverage_authority::{
            COVERAGE_LIMITS, CoverageBuild, CoverageError, CoverageOwnerMode, CoverageScope,
            RedactionCoverageAuthority,
        },
        coverage_bindings::OwnedSourceRevisions,
    };

    const REDACTED: &str = "**REDACTED BY COCKPIT - DO NOT TRY TO OBTAIN BY WORKAROUND**";
    const CANARY: &str = "coverage-canary-secret";

    fn binding(value: u8) -> CoverageBinding {
        CoverageBinding::from_daemon_bytes([value; 16])
    }

    fn key(parts: [u8; 10]) -> RedactionCoverageKey {
        RedactionCoverageKey::session(
            binding(parts[0]),
            binding(parts[1]),
            binding(parts[2]),
            binding(parts[3]),
            binding(parts[4]),
            binding(parts[5]),
            binding(parts[6]),
            binding(parts[7]),
            binding(parts[8]),
            binding(parts[9]),
        )
    }

    fn boundary_for(parts: [u8; 10]) -> OwnedSourceRevisions {
        OwnedSourceRevisions {
            environment: binding(parts[4]),
            credential_vault: binding(parts[5]),
            policy: binding(parts[6]),
            sealed: binding(parts[7]),
            override_revision: binding(parts[8]),
            machine_sources: binding(parts[9]),
        }
    }

    fn capture(
        counter: Arc<AtomicUsize>,
        parts: [u8; 10],
    ) -> impl FnOnce() -> Result<CoverageBuild> + Send + 'static {
        let boundary = boundary_for(parts);
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
            let table = RedactionTable::empty()
                .with_forced_literal(CANARY.to_string(), "$test:coverage".to_string())?;
            Ok(CoverageBuild::from_complete_table(table, boundary))
        }
    }

    pub(crate) async fn assert_unbound_tables_support_derived_transforms() {
        let authority = RedactionCoverageAuthority::default();
        let captures = Arc::new(AtomicUsize::new(0));
        let base = [8, 8, 8, 8, 8, 8, 8, 8, 8, 8];
        let base_table = authority
            .acquire(
                key(base),
                CoverageScope::SessionStart,
                capture(captures.clone(), base),
            )
            .await
            .expect("session-start capture")
            .install_table()
            .expect("install session table at sink");
        let forced = base_table
            .clone()
            .with_forced_literal("provider-auth-extra".into(), "$provider:auth".into())
            .expect("provider guard extension");
        assert_eq!(forced.scrub(CANARY), REDACTED);

        let refreshed = authority
            .acquire(
                key(base),
                CoverageScope::SessionSubmission,
                capture(captures.clone(), base),
            )
            .await
            .expect("submission refresh capture")
            .install_table()
            .expect("refreshed table at sink");
        let unioned = base_table
            .clone()
            .union(&refreshed)
            .expect("same-binding union of generation-bound tables");
        assert_eq!(unioned.scrub(CANARY), REDACTED);

        let sealed_derived = unioned.with_sealed_replacements(&Default::default());
        assert_eq!(sealed_derived.scrub(CANARY), REDACTED);
    }

    pub(crate) async fn assert_one_shot_admission_refuses_after_invalidation() {
        let authority = RedactionCoverageAuthority::default();
        let captures = Arc::new(AtomicUsize::new(0));
        let parts = [7, 7, 7, 7, 7, 7, 7, 7, 7, 7];
        let admission = authority
            .acquire(
                key(parts),
                CoverageScope::SessionStart,
                capture(captures.clone(), parts),
            )
            .await
            .expect("pinned generation");
        authority.invalidate();
        assert!(matches!(
            admission.use_at_sink(|table| {
                assert_eq!(table.scrub(CANARY), REDACTED);
                Ok(())
            }),
            Err(CoverageError::Invalidated)
        ));
    }

    pub(crate) async fn assert_bound_sink_scrub_refuses_stale_binding() {
        let authority = RedactionCoverageAuthority::default();
        let captures = Arc::new(AtomicUsize::new(0));
        let parts = [6, 6, 6, 6, 6, 6, 6, 6, 6, 6];
        let result = authority
            .acquire(
                key(parts),
                CoverageScope::DriverTurn,
                capture(captures.clone(), parts),
            )
            .await
            .expect("fresh generation")
            .use_at_sink(|table| {
                authority.invalidate();
                assert!(table.ensure_binding_current().is_err());
                Ok(())
            });
        // #390 requires the consuming lease to revalidate before its result
        // escapes. The callback ran, but invalidation makes the operation's
        // terminal result fail closed.
        assert_eq!(result, Err(CoverageError::Invalidated));
    }

    pub(crate) async fn assert_resident_generation_survives_lru_while_admitted() {
        let authority = RedactionCoverageAuthority::new(CoverageOwnerMode::InProcess);
        let captures = Arc::new(AtomicUsize::new(0));
        let pinned = [7, 7, 7, 7, 7, 7, 7, 7, 7, 7];
        let admission = authority
            .acquire(
                key(pinned),
                CoverageScope::SessionStart,
                capture(captures.clone(), pinned),
            )
            .await
            .expect("pinned generation");
        for index in 0..COVERAGE_LIMITS.resident_generations {
            let eviction_parts = [70 + index as u8; 10];
            authority
                .acquire(
                    key(eviction_parts),
                    CoverageScope::DriverTurn,
                    capture(captures.clone(), eviction_parts),
                )
                .await
                .expect("LRU insertion")
                .use_at_sink(|_| Ok(()))
                .expect("one-shot sink");
        }
        admission
            .use_at_sink(|table| {
                assert_eq!(table.scrub(CANARY), REDACTED);
                Ok(())
            })
            .expect("resident generation still admitted at sink");
    }

    pub(crate) async fn assert_publish_fence_rejects_stale_owned_revisions() {
        let authority = RedactionCoverageAuthority::default();
        let captures = Arc::new(AtomicUsize::new(0));
        let base = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        let boundary = boundary_for(base);
        let mismatched = OwnedSourceRevisions {
            environment: binding(99),
            credential_vault: boundary.credential_vault,
            policy: boundary.policy,
            sealed: boundary.sealed,
            override_revision: boundary.override_revision,
            machine_sources: boundary.machine_sources,
        };
        let publish_revisions = mismatched.clone();
        let result = authority
            .acquire(key(base), CoverageScope::SessionSubmission, move || {
                captures.fetch_add(1, Ordering::SeqCst);
                let table = RedactionTable::empty()
                    .with_forced_literal(CANARY.to_string(), "$test:coverage".to_string())?;
                Ok(CoverageBuild::from_complete_table(table, boundary)
                    .with_publish_fence(Box::new(move |_| Ok(publish_revisions.clone()))))
            })
            .await;
        assert!(matches!(result, Err(CoverageError::Invalidated)));
    }

    pub(crate) async fn assert_union_refuses_mismatched_bindings() {
        let authority = RedactionCoverageAuthority::default();
        let captures = Arc::new(AtomicUsize::new(0));
        let left_parts = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let right_parts = [2, 2, 2, 2, 2, 2, 2, 2, 2, 2];
        let left = authority
            .acquire(
                key(left_parts),
                CoverageScope::SessionSubmission,
                capture(captures.clone(), left_parts),
            )
            .await
            .expect("left capture")
            .install_table()
            .expect("left sink");
        let right = authority
            .acquire(
                key(right_parts),
                CoverageScope::DriverTurn,
                capture(captures.clone(), right_parts),
            )
            .await
            .expect("right capture")
            .install_table()
            .expect("right sink");
        assert!(left.union(&right).is_err());

        // Authority-local epoch/revision counters are not a shared clock. Even
        // an identical source key from another authority is incomparable.
        let foreign_authority = RedactionCoverageAuthority::default();
        let foreign = foreign_authority
            .acquire(
                key(left_parts),
                CoverageScope::SessionSubmission,
                capture(captures, left_parts),
            )
            .await
            .expect("foreign capture")
            .install_table()
            .expect("foreign sink");
        assert!(left.union(&foreign).is_err());
    }

    pub(crate) async fn assert_union_adopts_newer_binding_not_right_operand() {
        let authority = RedactionCoverageAuthority::default();
        let captures = Arc::new(AtomicUsize::new(0));
        let parts = [3, 3, 3, 3, 3, 3, 3, 3, 3, 3];
        let coverage_key = key(parts);
        let older = authority
            .acquire(
                coverage_key.clone(),
                CoverageScope::SessionSubmission,
                capture(captures.clone(), parts),
            )
            .await
            .expect("older capture")
            .install_table()
            .expect("older sink");
        authority.invalidate_key(&coverage_key);
        let newer = authority
            .acquire(
                coverage_key,
                CoverageScope::DriverTurn,
                capture(captures.clone(), parts),
            )
            .await
            .expect("newer capture")
            .install_table()
            .expect("newer sink");
        let older_binding = older.coverage_binding().expect("older binding");
        let newer_binding = newer.coverage_binding().expect("newer binding");
        assert!(
            newer_binding.binding_ordering(&older_binding) == Some(std::cmp::Ordering::Greater)
        );

        let forward = older.union(&newer).expect("older union newer");
        assert_eq!(
            forward
                .coverage_binding()
                .expect("forward binding")
                .binding_ordering(&newer_binding),
            Some(std::cmp::Ordering::Equal)
        );

        let reverse = newer.union(&older).expect("newer union older");
        assert_eq!(
            reverse
                .coverage_binding()
                .expect("reverse binding")
                .binding_ordering(&newer_binding),
            Some(std::cmp::Ordering::Equal)
        );

        // Issue #390's generation-safe historical-fold contract permits
        // newer mutable source revisions within the same immutable
        // principal/session/workspace lineage. The union must adopt that
        // generation even though its complete source key differs.
        let revised_parts = [3, 3, 3, 3, 4, 4, 4, 4, 4, 4];
        let revised = authority
            .acquire(
                key(revised_parts),
                CoverageScope::RedactedExport,
                capture(captures, revised_parts),
            )
            .await
            .expect("revised capture")
            .install_table()
            .expect("revised sink");
        let revised_binding = revised.coverage_binding().expect("revised binding");
        let folded = older.union(&revised).expect("historical revision fold");
        assert_eq!(
            folded
                .coverage_binding()
                .expect("folded binding")
                .binding_ordering(&revised_binding),
            Some(std::cmp::Ordering::Equal)
        );
    }

    pub(crate) async fn assert_async_sink_revalidates_before_result_escapes() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        use tokio::sync::Notify;

        let authority = RedactionCoverageAuthority::default();
        let captures = Arc::new(AtomicUsize::new(0));
        let parts = [4, 4, 4, 4, 4, 4, 4, 4, 4, 4];
        let admission = authority
            .acquire(
                key(parts),
                CoverageScope::SessionSubmission,
                capture(captures.clone(), parts),
            )
            .await
            .expect("async sink admission");
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let persisted = Arc::new(AtomicBool::new(false));
        let persisted_for_sink = persisted.clone();
        let entered_for_sink = entered.clone();
        let release_for_sink = release.clone();
        let sink_task = tokio::spawn(async move {
            let result = admission
                .consume_at_async_sink(|table| {
                    let entered = entered_for_sink.clone();
                    let release = release_for_sink.clone();
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        Ok(table)
                    }
                })
                .await;
            if result.is_ok() {
                persisted_for_sink.store(true, Ordering::SeqCst);
            }
            result
        });
        entered.notified().await;
        authority.invalidate();
        release.notify_one();
        assert!(matches!(
            sink_task.await.expect("sink task"),
            Err(CoverageError::Invalidated)
        ));
        assert!(!persisted.load(Ordering::SeqCst));
    }
}
