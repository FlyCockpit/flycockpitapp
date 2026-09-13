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
            .consume_at_sink(|table| Ok(table))
            .expect("install session table at sink");
        let forced = base_table
            .as_ref()
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
            .consume_at_sink(|table| Ok(table))
            .expect("refreshed table at sink");
        let unioned = base_table
            .as_ref()
            .clone()
            .union(refreshed.as_ref())
            .expect("same-binding union of unbound tables");
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
        authority
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
            })
            .expect("one-shot sink reached");
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
        let result = authority
            .acquire(key(base), CoverageScope::SessionSubmission, move || {
                captures.fetch_add(1, Ordering::SeqCst);
                let table = RedactionTable::empty()
                    .with_forced_literal(CANARY.to_string(), "$test:coverage".to_string())?;
                Ok(CoverageBuild::from_complete_table(table, boundary)
                    .with_publish_fence(Box::new(|_| Ok(mismatched.clone()))))
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
            .consume_at_sink(|table| Ok(table.as_ref().clone()))
            .expect("left sink");
        let right = authority
            .acquire(
                key(right_parts),
                CoverageScope::DriverTurn,
                capture(captures.clone(), right_parts),
            )
            .await
            .expect("right capture")
            .consume_at_sink(|table| Ok(table.as_ref().clone()))
            .expect("right sink");
        assert!(left.union(&right).is_err());
    }
}
