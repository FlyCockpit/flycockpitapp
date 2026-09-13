use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use anyhow::Result;

use super::super::{
    RedactionTable,
    coverage_authority::{
        CoverageBinding, CoverageBuild, CoverageError, CoverageScope, RedactionCoverageAuthority,
        RedactionCoverageKey,
    },
};

fn binding(value: u8) -> CoverageBinding {
    CoverageBinding::from_daemon_bytes([value; 16])
}

fn key(principal: u8, session: u8, workspace: u8, environment: u8) -> RedactionCoverageKey {
    RedactionCoverageKey::session(
        binding(principal),
        binding(2),
        binding(session),
        binding(workspace),
        binding(environment),
        binding(6),
        binding(7),
        binding(8),
        binding(9),
        binding(10),
        CoverageScope::SessionSubmission,
    )
}

fn capture(counter: Arc<AtomicUsize>) -> impl FnOnce() -> Result<CoverageBuild> + Send + 'static {
    move || {
        counter.fetch_add(1, Ordering::SeqCst);
        let table = RedactionTable::empty().with_forced_literal(
            "coverage-canary-secret".to_string(),
            "$test:coverage".to_string(),
        )?;
        Ok(CoverageBuild::from_complete_table(table, 64))
    }
}

#[tokio::test]
async fn bound_keys_never_coalesce_across_principal_session_root_env_vault_policy_or_sealed() {
    let authority = RedactionCoverageAuthority::new();
    let captures = Arc::new(AtomicUsize::new(0));
    let first = authority
        .acquire(key(1, 3, 4, 5), capture(captures.clone()))
        .await
        .expect("first complete capture is admitted");
    let same = authority
        .acquire(key(1, 3, 4, 5), capture(captures.clone()))
        .await
        .expect("same bound capture reuses its generation");
    let other_principal = authority
        .acquire(key(11, 3, 4, 5), capture(captures.clone()))
        .await
        .expect("principal change requires a distinct generation");

    assert_eq!(captures.load(Ordering::SeqCst), 2);
    first
        .use_at_sink(|table| {
            assert_eq!(table.scrub("coverage-canary-secret"), "***REDACT***");
            Ok(())
        })
        .expect("bound lease admits exactly its sink");
    same.use_at_sink(|table| {
        assert_eq!(table.scrub("coverage-canary-secret"), "***REDACT***");
        Ok(())
    })
    .expect("same binding remains independently leased");
    other_principal
        .use_at_sink(|table| {
            assert_eq!(table.scrub("coverage-canary-secret"), "***REDACT***");
            Ok(())
        })
        .expect("different binding has its own admitted capture");
}

#[tokio::test]
async fn coverage_admission_is_one_operation_and_stale_results_are_inert() {
    let authority = RedactionCoverageAuthority::new();
    let captures = Arc::new(AtomicUsize::new(0));
    let admission = authority
        .acquire(key(1, 3, 4, 5), capture(captures.clone()))
        .await
        .expect("complete capture is admitted");

    authority.invalidate();
    let result = admission.use_at_sink(|_| Ok(()));
    assert_eq!(result, Err(CoverageError::Invalidated));

    authority
        .acquire(key(1, 3, 4, 5), capture(captures.clone()))
        .await
        .expect("invalidated work requires a fresh complete capture")
        .use_at_sink(|table| {
            assert_eq!(table.scrub("coverage-canary-secret"), "***REDACT***");
            Ok(())
        })
        .expect("fresh generation is admitted at its sink");
    assert_eq!(captures.load(Ordering::SeqCst), 2);
}
