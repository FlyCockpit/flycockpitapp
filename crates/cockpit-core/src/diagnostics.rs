//! Compact read-only diagnostics snapshot for CLI and TUI surfaces.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::StreamExt as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsInput {
    pub cwd: PathBuf,
    pub session_id: Option<uuid::Uuid>,
    pub session_short_id: Option<String>,
    pub active_agent: String,
    pub active_model: Option<(String, String)>,
    /// Redacted TUI-only model-selection lifecycle state.
    pub pending_model_selection: Option<String>,
    pub sandbox_enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsSnapshot {
    pub session: String,
    pub active_agent: String,
    pub active_model: String,
    pub pending_model_selection: String,
    pub cwd: String,
    pub project_root: String,
    pub workspace_trust: String,
    pub sandbox: String,
    pub container_runtime: String,
    pub container_harness: String,
    pub container_available: String,
    pub approval_mode: String,
    pub database: Vec<String>,
    pub daemon: Vec<String>,
    pub providers: Vec<String>,
    pub git: Vec<String>,
    pub network: Vec<String>,
    pub harnesses: Vec<String>,
    pub delegation: Vec<String>,
    /// Pending effective-default journals, if any. This is the actionable
    /// half of every "run `cockpit doctor`" repair diagnostic the daemon
    /// emits: it names the file to inspect, its phase, and whether a running
    /// daemon is required to finish it. Never any configuration content.
    pub default_model_journals: Vec<String>,
    /// Exact external side-effect journal record/byte/age counts.
    pub external_journal: Vec<String>,
    pub dependencies: crate::external_runtime::DependencyProjection,
    pub has_failures: bool,
}

/// The database a diagnostics snapshot renders against. Diagnostics never opens
/// SQLite from this module: a running daemon injects its already-open handle,
/// and the offline `doctor` path opens the DB through the single daemon-layer
/// [`crate::daemon::diagnostics_probe`] opener, threading the open result
/// (success or failure) through here so the database section can report
/// openability / schema-rejection accurately.
enum DiagnosticDb<'a> {
    /// An already-open, healthy handle (the daemon's `ctx.db`, or a successful
    /// offline probe open). Real reads are performed.
    Open(&'a crate::db::Db),
    /// An offline probe open that failed; the error drives the openability /
    /// schema lines (a schema rejection vs. an unopenable database).
    OpenFailed(&'a anyhow::Error),
    /// No database is available at all (e.g. a TUI client, which never opens
    /// one). DB-internal fields render "unavailable".
    Unavailable,
}

impl<'a> DiagnosticDb<'a> {
    /// The healthy handle to read through, if any. `OpenFailed`/`Unavailable`
    /// yield `None`, so journal/trust readers degrade to "unavailable".
    fn handle(&self) -> Option<&'a crate::db::Db> {
        match self {
            DiagnosticDb::Open(db) => Some(db),
            DiagnosticDb::OpenFailed(_) | DiagnosticDb::Unavailable => None,
        }
    }
}

/// Optional closure that resolves a `$secret:<name>` reference to its plaintext
/// value. The daemon supplies a vault-backed lookup; offline/in-process paths
/// pass `None`.
pub type SecretLookup<'a> = Option<&'a dyn Fn(&str) -> Option<String>>;

/// Hidden `daemon diagnostic-failed-calls` worker. Opens the ledger through
/// the single diagnostic probe; never starts or promotes a daemon.
pub async fn failed_tool_calls_json(
    since_epoch: i64,
    tool: Option<String>,
    model: Option<String>,
    project_id: Option<String>,
    include_recovered: bool,
    limit: usize,
) -> Result<String> {
    crate::daemon::diagnostics_probe::failed_tool_calls_json(
        crate::db::tool_calls::FailedCallsFilter {
            since_epoch,
            tool,
            model,
            project_id,
            include_recovered,
            limit,
        },
    )
    .await
}

pub async fn cli_snapshot(
    path: Option<&Path>,
    no_sandbox: bool,
    offline: bool,
    db: Option<&crate::db::Db>,
    secret_lookup: SecretLookup<'_>,
) -> Result<DiagnosticsSnapshot> {
    #[cfg(feature = "test-support")]
    if std::env::var_os("COCKPIT_TEST_DOCTOR_FORCE_FAILURE").is_some() {
        anyhow::bail!("doctor snapshot forced to fail by test support");
    }

    let launch = crate::welcome::load_bundle_bootstrap(path, false);
    let dependency_cwd = launch.launch.cwd.clone();
    let extended = launch.extended;
    // A running daemon injects its already-open `ctx.db` handle, so the snapshot
    // never opens a second DB. When no handle is injected this is the offline
    // in-process `doctor`, which cannot route through a daemon; it opens the DB
    // exactly once via the single daemon-layer probe (never the default-path
    // opener from this module) and reports its open result — a failed open too.
    let offline_probe = match db {
        Some(_) => None,
        None => Some(crate::daemon::diagnostics_probe::open_diagnostic_db()),
    };
    let db_source = match (db, offline_probe.as_ref()) {
        (Some(handle), _) => DiagnosticDb::Open(handle),
        (None, Some(Ok(opened))) => DiagnosticDb::Open(opened),
        (None, Some(Err(error))) => DiagnosticDb::OpenFailed(error),
        (None, None) => DiagnosticDb::Unavailable,
    };
    let mut snapshot = build_snapshot(
        DiagnosticsInput {
            cwd: launch.launch.cwd,
            session_id: None,
            session_short_id: None,
            // A fresh daemon session resolves its root primary through the LLM
            // mode, which makes the default Defensive mode start as Careful
            // rather than the narrower `default_primary_agent` config value.
            active_agent: effective_default_agent(&extended),
            active_model: launch.launch.active_model,
            pending_model_selection: None,
            sandbox_enabled: Some(!no_sandbox),
        },
        db_source.handle(),
        secret_lookup,
    )?;
    snapshot.dependencies = tokio::task::spawn_blocking(move || {
        dependency_projection_with_deadline_for_run(
            dependency_cwd,
            Duration::from_secs(2),
            !no_sandbox,
        )
    })
    .await
    .context("dependency diagnostics worker join")??;
    snapshot.has_failures |= snapshot.dependencies.has_required_failures();
    let providers = crate::config::providers::ConfigDoc::load_effective(Path::new(&snapshot.cwd));
    let (network, network_failed) = provider_network_lines(&providers, offline).await;
    snapshot.network = network;
    snapshot.has_failures |= network_failed;
    let (database, database_failed) = database_lines(&db_source, &extended).await;
    snapshot.database = database;
    snapshot.has_failures |= database_failed;
    let (mut daemon, _) = daemon_lines().await;
    daemon.insert(
        0,
        "diagnostic authority: in-process; daemon is not required".to_string(),
    );
    snapshot.daemon = daemon;
    Ok(snapshot)
}

pub fn tui_snapshot(input: DiagnosticsInput) -> Result<DiagnosticsSnapshot> {
    let cwd = input.cwd.clone();
    let sandbox_enabled = input.sandbox_enabled.unwrap_or(true);
    // The TUI is a daemon client and never opens the DB itself.
    let mut snapshot = build_snapshot(input, None, None)?;
    snapshot.dependencies =
        dependency_projection_with_deadline_for_run(cwd, Duration::from_secs(2), sandbox_enabled)?;
    snapshot.has_failures |= snapshot.dependencies.has_required_failures();
    Ok(snapshot)
}

pub fn render(snapshot: &DiagnosticsSnapshot) -> String {
    let mut out = String::new();
    out.push_str("Cockpit diagnostics\n");
    out.push_str(&format!("session: {}\n", snapshot.session));
    out.push_str(&format!("agent: {}\n", snapshot.active_agent));
    out.push_str(&format!("model: {}\n", snapshot.active_model));
    out.push_str(&format!(
        "model selection: {}\n",
        snapshot.pending_model_selection
    ));
    out.push_str(&format!("cwd: {}\n", snapshot.cwd));
    out.push_str(&format!("project root: {}\n", snapshot.project_root));
    out.push_str(&format!("workspace trust: {}\n", snapshot.workspace_trust));
    out.push_str(&format!("sandbox: {}\n", snapshot.sandbox));
    push_section(
        &mut out,
        "container",
        &[
            format!("runtime: {}", snapshot.container_runtime),
            format!("harness: {}", snapshot.container_harness),
            format!("available: {}", snapshot.container_available),
        ],
    );
    out.push_str(&format!("approval: {}\n", snapshot.approval_mode));
    push_section(&mut out, "database", &snapshot.database);
    push_section(&mut out, "daemon", &snapshot.daemon);
    push_section(&mut out, "providers", &snapshot.providers);
    push_section(&mut out, concat!("net", "work"), &snapshot.network);
    push_section(&mut out, "git", &snapshot.git);
    push_section(&mut out, "harnesses", &snapshot.harnesses);
    push_section(&mut out, "delegation", &snapshot.delegation);
    if !snapshot.default_model_journals.is_empty() {
        push_section(
            &mut out,
            "default model journal",
            &snapshot.default_model_journals,
        );
    }
    push_section(&mut out, "external journal", &snapshot.external_journal);
    push_section(
        &mut out,
        "dependencies",
        &snapshot.dependencies.render_lines(),
    );
    out
}

fn build_snapshot(
    input: DiagnosticsInput,
    db: Option<&crate::db::Db>,
    secret_lookup: SecretLookup<'_>,
) -> Result<DiagnosticsSnapshot> {
    let trust_root = crate::config::trust::resolve_trust_root(&input.cwd).ok();
    let provider_config = crate::config::providers::ConfigDoc::load_effective(&input.cwd);
    let extended = crate::config::extended::load_for_cwd(&input.cwd);
    let harnesses = crate::config::extended::resolve_harnesses(&input.cwd);
    let trust_mode = workspace_trust_mode(db, &input.cwd);
    let trust_resolved = trust_mode != "unresolved";
    let container = crate::container::availability_snapshot();
    let container_reason = container
        .reason
        .map(|reason| reason.as_str())
        .unwrap_or("none");

    let delegation_enabled = delegation_enabled_for_coverage(&provider_config, &extended, &input);
    let (mut providers, provider_failures) = provider_lines(
        &provider_config,
        &extended,
        delegation_enabled,
        secret_lookup,
    );
    providers.extend(media_model_availability_lines(
        &provider_config,
        input.active_model.as_ref(),
    ));
    let (external_journal, external_journal_failed) = external_journal_lines(db);

    let dependencies = match crate::external_runtime::global_health_store().current_bundle() {
        Some((snapshot, descriptors)) => {
            crate::external_runtime::project_dependencies(Some(snapshot.as_ref()), &descriptors)
        }
        None => crate::external_runtime::project_dependencies(
            None,
            &crate::external_runtime::global_registry().descriptors(),
        ),
    };

    Ok(DiagnosticsSnapshot {
        session: session_label(input.session_id, input.session_short_id.as_deref()),
        active_agent: input.active_agent.clone(),
        active_model: input
            .active_model
            .as_ref()
            .map(|(p, m)| format!("{p}/{m}"))
            .unwrap_or_else(|| "none".to_string()),
        pending_model_selection: input
            .pending_model_selection
            .clone()
            .unwrap_or_else(|| "none".to_string()),
        cwd: input.cwd.display().to_string(),
        project_root: trust_root
            .as_ref()
            .map(|root| root.root.display().to_string())
            .unwrap_or_else(|| input.cwd.display().to_string()),
        workspace_trust: trust_root
            .as_ref()
            .map(|root| {
                format!(
                    "{trust_mode} ({}: {})",
                    root.kind.as_str(),
                    root.root.display()
                )
            })
            .unwrap_or_else(|| {
                "unresolved (workspace trust root could not be resolved)".to_string()
            }),
        sandbox: input
            .sandbox_enabled
            .map(|enabled| if enabled { "on" } else { "off" }.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        container_runtime: container
            .runtime
            .map(|runtime| runtime.as_str().to_string())
            .unwrap_or_else(|| "none".to_string()),
        container_harness: container.harness_in_container.to_string(),
        container_available: if container.available {
            "true".to_string()
        } else {
            format!("false ({container_reason})")
        },
        approval_mode: extended.default_approval_mode.as_str().to_string(),
        database: Vec::new(),
        daemon: Vec::new(),
        providers,
        git: git_lines(&input.cwd),
        network: Vec::new(),
        harnesses: harness_lines(&harnesses, trust_resolved),
        delegation: delegation_lines(
            &input.active_agent,
            &input.cwd,
            !harnesses.is_empty(),
            &extended,
        ),
        default_model_journals: default_model_journal_lines(&input.cwd),
        external_journal,
        dependencies,
        has_failures: provider_failures || external_journal_failed,
    })
}

fn media_model_availability_lines(
    providers: &crate::config::providers::ProvidersConfig,
    active_model: Option<&(String, String)>,
) -> Vec<String> {
    let Some((provider, model)) = active_model else {
        return Vec::new();
    };
    let caps = providers.resolve_effective_model_capabilities(
        provider,
        model,
        providers.resolution_generation,
    );
    let availability = crate::tool_media_authority::MediaToolAvailability::available_with(
        crate::tool_media_authority::AvRuntimeProfile::FullClip,
        caps.audio_input.status,
        caps.video_input.status,
    );
    ["inspect_audio", "inspect_video"]
        .into_iter()
        .map(|tool| {
            format!(
                "{tool} model gate: {}",
                availability.reason_for(tool).as_str()
            )
        })
        .collect()
}

/// One safe line per pending effective-default journal.
///
/// A journal only exists while a default-model transaction is unfinished, so
/// an empty list is the normal state. Each line names the journal file, its
/// phase, and whether a daemon is required to finish it — enough to act on,
/// with no configuration content, credentials, or model bodies.
fn default_model_journal_lines(cwd: &Path) -> Vec<String> {
    crate::config::providers::journal_diagnostics(cwd)
        .into_iter()
        .map(|journal| {
            // Only a pass that can supply the missing capability finishes a
            // journal, so the guidance has to match its kind exactly.
            let needs = match (journal.needs_session_authority, journal.correlated) {
                (true, _) => "needs a running daemon: it has a session participant",
                (false, true) => {
                    "needs a running daemon: a client is waiting for its terminal result"
                }
                (false, false) => "config-only; the next config read finishes it",
            };
            let context = if journal.out_of_context {
                "; out of context — recovery refuses it, remove it by hand after checking the layer"
            } else {
                ""
            };
            format!(
                "{} [{} scope, phase {}, txn {}] {needs}{context}",
                journal.journal_path.display(),
                journal.scope_label,
                journal.phase,
                journal.transaction_id
            )
        })
        .collect()
}

/// What the doctor could learn about the capsule spool on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalJournalSpoolHealth {
    /// Owner-only, containment-checked, with these on-disk facts.
    Healthy {
        allocated_bytes: u64,
        quarantined_entries: usize,
    },
    /// Never created. Nothing has been dispatched on this installation.
    Absent,
    /// Present but unusable: insecure permissions, a containment failure, or
    /// an unreadable directory. New external work must be refused.
    Unhealthy { detail: String },
}

/// Render the external side-effect journal section.
///
/// Pure so the failure branches doctor must exit non-zero on — quarantine, a
/// full partition, unresolved work past 24h, and an insecure spool — are
/// directly testable without a real database or filesystem.
pub fn external_journal_section(
    capacity: crate::db::external_journal::ExternalJournalCapacity,
    age: crate::db::external_journal::ExternalJournalAgeReport,
    spool: &ExternalJournalSpoolHealth,
    integrity_failure: Option<String>,
) -> (Vec<String>, bool) {
    let (allocated_bytes, quarantined_entries, spool_line, spool_failed) = match spool {
        ExternalJournalSpoolHealth::Healthy {
            allocated_bytes,
            quarantined_entries,
        } => (
            *allocated_bytes,
            *quarantined_entries,
            "spool: ok (owner-only)".to_string(),
            false,
        ),
        ExternalJournalSpoolHealth::Absent => {
            (0, 0, "spool: none (not yet created)".to_string(), false)
        }
        ExternalJournalSpoolHealth::Unhealthy { detail } => {
            (0, 0, format!("spool: FAILED ({})", one_line(detail)), true)
        }
    };
    let status = crate::external_journal::ExternalJournalStatus {
        capacity,
        age,
        spool_allocated_bytes: allocated_bytes,
        quarantined_entries,
        integrity_failure,
    };
    let mut lines = status.render_lines();
    lines.push(spool_line);
    (lines, status.is_critical() || spool_failed)
}

/// External side-effect journal capacity/age status for doctor, headless, and
/// TUI surfaces.
///
/// Reporting needs no spool HMAC key material, so this deliberately reads only
/// SQLite counts plus on-disk capsule/quarantine sizes and never resolves a
/// key: diagnostics output can never disclose one.
fn external_journal_lines(db: Option<&crate::db::Db>) -> (Vec<String>, bool) {
    let Some(db) = db else {
        return (
            vec!["status: unavailable (requires daemon)".to_string()],
            false,
        );
    };
    let now_wall_ms = chrono::Utc::now().timestamp_millis();
    // The journal's integrity latch is persisted, so a doctor run that holds
    // no journal instance — and one after a restart — still reports critical.
    let counts = db.blocking_read_for_sync_ui(move |conn| {
        Ok((
            crate::db::external_journal::external_journal_capacity_conn(conn)?,
            crate::db::external_journal::external_journal_age_report_conn(conn, now_wall_ms)?,
            crate::db::external_journal::external_journal_integrity_fault_conn(conn)?,
        ))
    });
    let (capacity, age, integrity_failure) = match counts {
        Ok(counts) => counts,
        Err(error) => {
            return (
                vec![format!(
                    "status: FAILED ({})",
                    one_line(&format!("{error:#}"))
                )],
                true,
            );
        }
    };

    // Inspection is read-only: it creates nothing and repairs nothing, so an
    // insecure spool is reported rather than silently fixed.
    let spool = match crate::external_journal::spool::Spool::inspect_default() {
        Ok(Some(spool)) => match (spool.allocated_bytes(), spool.list_quarantined()) {
            (Ok(allocated_bytes), Ok(quarantined)) => ExternalJournalSpoolHealth::Healthy {
                allocated_bytes,
                quarantined_entries: quarantined.len(),
            },
            (Err(error), _) | (_, Err(error)) => ExternalJournalSpoolHealth::Unhealthy {
                detail: error.to_string(),
            },
        },
        Ok(None) => ExternalJournalSpoolHealth::Absent,
        Err(error) => ExternalJournalSpoolHealth::Unhealthy {
            detail: error.to_string(),
        },
    };
    external_journal_section(capacity, age, &spool, integrity_failure)
}

fn effective_default_agent(extended: &crate::config::extended::ExtendedConfig) -> String {
    crate::daemon::session_worker::initial_active_agent_for_llm_mode(extended, extended.llm_mode)
}

async fn database_lines(
    db: &DiagnosticDb<'_>,
    extended: &crate::config::extended::ExtendedConfig,
) -> (Vec<String>, bool) {
    // `default_path` only resolves the on-disk location; it does NOT open,
    // create, or migrate anything, so the real path is always safe to report.
    let resolved_path = match db {
        DiagnosticDb::Open(db) => db.path().map(ToOwned::to_owned),
        DiagnosticDb::OpenFailed(_) | DiagnosticDb::Unavailable => None,
    };
    let path = if let Some(path) = resolved_path {
        path
    } else {
        match crate::db::Db::default_path() {
            Ok(path) => path,
            Err(error) => {
                return (
                    vec![format!(
                        "path: unavailable ({})",
                        one_line(&format!("{error:#}"))
                    )],
                    true,
                );
            }
        }
    };
    let mut lines = vec![format!("path: {}", path.display())];
    let db = match db {
        DiagnosticDb::Open(db) => db,
        // The offline probe attempted an open and it FAILED. Distinguish a
        // schema/migration rejection (SQLite opened, Cockpit rejected it) from a
        // database that could not be opened at all.
        DiagnosticDb::OpenFailed(error) => {
            let message = format!("{error:#}");
            if is_schema_rejection(&message) {
                lines.push(
                    "openability: ok (SQLite opened, but Cockpit rejected its schema)".to_string(),
                );
                lines.push(format!("schema: FAILED ({})", one_line(&message)));
                lines.push(
                    "integrity: unavailable because Cockpit rejected the schema before integrity checks"
                        .to_string(),
                );
            } else if is_absent_database(&message) {
                // Fresh install / never-used home: doctor is read-only and
                // must not create SQLite. Absence is informational, not a
                // failed open of an existing file.
                lines.push(format!(
                    "openability: informational ({})",
                    one_line(&message)
                ));
                lines.push("schema: unavailable because no database file exists yet".to_string());
                lines
                    .push("integrity: unavailable because no database file exists yet".to_string());
                append_database_failure_guidance(&mut lines, &extended.retention);
                return (lines, false);
            } else {
                lines.push(format!("openability: FAILED ({})", one_line(&message)));
                lines.push(
                    "schema: unavailable because the database could not be opened".to_string(),
                );
                lines.push("integrity: unavailable because SQLite did not open".to_string());
            }
            append_database_failure_guidance(&mut lines, &extended.retention);
            return (lines, true);
        }
        // No DB at all (e.g. a TUI client): the resolved path stays visible but
        // the DB-internal fields are unavailable. Diagnostics opens nothing.
        DiagnosticDb::Unavailable => {
            lines.push("openability: unavailable (daemon not running)".to_string());
            lines.push("schema: unavailable".to_string());
            lines.push("integrity: unavailable (daemon not running)".to_string());
            append_database_failure_guidance(&mut lines, &extended.retention);
            return (lines, true);
        }
    };
    lines.push("openability: ok".to_string());
    match (
        db.schema_version().await,
        db.applied_migration_version().await,
    ) {
        (Ok(schema), Ok(migration)) => {
            lines.push(format!(
                "schema: ok (actual {schema}, expected {})",
                crate::db::EXPECTED_SCHEMA_VERSION
            ));
            lines.push(format!(
                "ledger: migration {migration}; checksum verification enabled"
            ));
        }
        (schema, migration) => {
            let error = schema
                .err()
                .or(migration.err())
                .expect("one database read failed");
            lines.push(format!("schema: FAILED ({})", one_line(&error.to_string())));
            lines.push("integrity: unavailable because schema reads failed".to_string());
            append_database_failure_guidance(&mut lines, &extended.retention);
            return (lines, true);
        }
    }
    match db.storage_report().await {
        Ok(report) => {
            lines.push(format!(
                "storage: {} live bytes; {} reclaimable bytes; {} allocated bytes",
                report.live_bytes, report.reclaimable_bytes, report.allocated_bytes
            ));
            lines.push(format!(
                "files: {} main bytes; {} WAL bytes; {} shared-memory bytes",
                report.main_file_bytes, report.wal_file_bytes, report.shared_memory_file_bytes
            ));
            lines.push(format!(
                "pages: {} total; {} free; {} bytes each",
                report.page_count, report.freelist_page_count, report.page_size_bytes
            ));
        }
        Err(error) => {
            lines.push(format!(
                "storage: FAILED ({})",
                one_line(&error.to_string())
            ));
            append_database_failure_guidance(&mut lines, &extended.retention);
            return (lines, true);
        }
    }
    match db.diagnostic_integrity_check().await {
        Ok(()) => lines.push(
            "integrity: ok (quick_check and foreign_key_check passed for this snapshot)"
                .to_string(),
        ),
        Err(error) => {
            lines.push(format!(
                "integrity: FAILED ({})",
                one_line(&format!("{error:#}"))
            ));
            append_database_failure_guidance(&mut lines, &extended.retention);
            return (lines, true);
        }
    }
    match db.retention_protection_report().await {
        Ok(report) => lines.push(format!(
            "retention protection: {} session rows; {} directly pinned sessions protecting {} root subtrees",
            report.total_session_rows,
            report.directly_pinned_sessions,
            report.pin_protected_root_sessions
        )),
        Err(error) => {
            lines.push(format!(
                "retention protection: FAILED ({})",
                one_line(&format!("{error:#}"))
            ));
            append_database_failure_guidance(&mut lines, &extended.retention);
            return (lines, true);
        }
    }
    lines.push(
        "export: use `cockpit export <session>`; exports are assembled by the daemon and redacted by default"
            .to_string(),
    );
    lines.push(
        "repair: read-only doctor never edits SQLite; restore a validated sibling *.backup-*.sqlite or move the database aside and restart"
            .to_string(),
    );
    lines.push(retention_line(&extended.retention));
    (lines, false)
}

fn is_absent_database(message: &str) -> bool {
    message.contains("database does not exist at")
}

#[allow(dead_code)]
fn is_schema_rejection(message: &str) -> bool {
    [
        crate::db::SCHEMA_PROFILE_MISMATCH_CODE,
        crate::db::SCHEMA_REJECTION_AFTER_OPEN_CODE,
        "incompatible prerelease database schema",
        "incompatible legacy prerelease database schema",
        "database migration ledger is corrupt",
        "database schema version mismatch",
        "database schema version is inconsistent",
        "database migration ledger is newer than this binary",
        "migration checksum mismatch",
        "database schema fingerprint mismatch",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

#[allow(dead_code)]
fn retention_line(retention: &crate::db::retention::RetentionConfig) -> String {
    let sessions = if retention.session_window_days == 0 {
        "unlimited".to_string()
    } else {
        format!("{} days", retention.session_window_days)
    };
    let window = |days| {
        if days == 0 {
            "unlimited".to_string()
        } else {
            format!("{days} days")
        }
    };
    format!(
        "retention: sessions {sessions}; transcripts {}; raw/wire {}; terminal evidence {}",
        window(retention.transcript_window_days),
        window(retention.raw_wire_window_days),
        window(retention.terminal_evidence_window_days)
    )
}

fn append_database_failure_guidance(
    lines: &mut Vec<String>,
    retention: &crate::db::retention::RetentionConfig,
) {
    lines.push(
        "export: unavailable while database health is failed; do not bypass daemon validation"
            .to_string(),
    );
    lines.push(
        "repair: read-only doctor never edits SQLite; restore a validated sibling *.backup-*.sqlite or move the database aside and restart"
            .to_string(),
    );
    lines.push(retention_line(retention));
}

async fn daemon_lines() -> (Vec<String>, bool) {
    let probe = crate::daemon::discover().await;
    let socket = probe.paths.socket.display();
    let pid_file = probe.paths.pid_file.display();
    match probe.status {
        crate::daemon::DaemonStatus::Running => {
            let version = probe
                .hello
                .as_ref()
                .map(|hello| {
                    format!(
                        " (daemon {}, protocol v{})",
                        hello.daemon_version, hello.protocol_version
                    )
                })
                .unwrap_or_default();
            (
                vec![
                    format!("status: running{version}"),
                    format!("socket: {socket}"),
                    format!("pid file: {pid_file}"),
                ],
                false,
            )
        }
        crate::daemon::DaemonStatus::IncompatibleProtocol => (
            vec![
                "status: informational (daemon protocol is incompatible; doctor remains in-process; run `cockpit daemon restart`)"
                    .to_string(),
                format!("socket: {socket}"),
            ],
            true,
        ),
        crate::daemon::DaemonStatus::NotRunning => (
            vec![
                "status: informational (canonical daemon is not running; doctor did not start it or require it)"
                    .to_string(),
                format!("socket: {socket}"),
                format!("pid file: {pid_file}"),
            ],
            true,
        ),
        status => (
            vec![
                format!("status: informational ({})", daemon_status_label(status)),
                format!("socket: {socket}"),
                format!("pid file: {pid_file}"),
            ],
            true,
        ),
    }
}

fn daemon_status_label(status: crate::daemon::DaemonStatus) -> &'static str {
    match status {
        crate::daemon::DaemonStatus::Running => "running",
        crate::daemon::DaemonStatus::IncompatibleProtocol => "incompatible protocol",
        crate::daemon::DaemonStatus::LivePidSocketUnreachable => {
            "live daemon pid but socket is unreachable"
        }
        crate::daemon::DaemonStatus::UnverifiedPid => "pid identity could not be verified",
        crate::daemon::DaemonStatus::Stale => "stale daemon pid or socket",
        crate::daemon::DaemonStatus::NotRunning => "not running",
    }
}

fn push_section(out: &mut String, label: &str, lines: &[String]) {
    out.push_str(label);
    out.push_str(":\n");
    if lines.is_empty() {
        out.push_str("  none\n");
    } else {
        for line in lines {
            out.push_str("  - ");
            out.push_str(line);
            out.push('\n');
        }
    }
}

fn session_label(id: Option<uuid::Uuid>, short_id: Option<&str>) -> String {
    match (id, short_id.filter(|s| !s.is_empty())) {
        (Some(id), Some(short)) => format!("{short} ({id})"),
        (Some(id), None) => id.to_string(),
        (None, Some(short)) => short.to_string(),
        (None, None) => "none".to_string(),
    }
}

fn workspace_trust_mode(db: Option<&crate::db::Db>, cwd: &Path) -> String {
    let Some(db) = db else {
        return "unresolved".to_string();
    };
    let Ok(root) = crate::config::trust::resolve_trust_root(cwd) else {
        return "unresolved".to_string();
    };
    db.blocking_read_for_sync_ui(move |conn| {
        crate::db::Db::workspace_trust_by_root_conn(conn, &root.root)
    })
    .ok()
    .flatten()
    .map(|decision| decision.mode.as_str().to_string())
    .unwrap_or_else(|| "unresolved".to_string())
}

fn provider_lines(
    cfg: &crate::config::providers::ProvidersConfig,
    extended: &crate::config::extended::ExtendedConfig,
    delegation_enabled: bool,
    secret_lookup: SecretLookup<'_>,
) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    let mut failed = false;
    match cfg.resolve_embedding_model(extended) {
        Ok(resolved) => out.push(format!(
            "embedding_model: resolved {}/{}{}",
            resolved.provider,
            resolved.model,
            resolved
                .embedding_dimensions
                .map(|dims| format!(" ({dims} dims)"))
                .unwrap_or_default()
        )),
        Err(err) => out.push(format!("embedding_model: unresolved ({err})")),
    }
    if cfg.providers.is_empty() {
        out.push("no providers configured; run: cockpit provider add".to_string());
        return (out, true);
    }
    let mut total_invokable = 0usize;
    for (id, provider) in &cfg.providers {
        let fetch = provider
            .last_model_fetch
            .as_ref()
            .map(|status| model_fetch_status_label(status.status))
            .unwrap_or("not fetched");
        let model_count = provider.models.len();
        let trusted_count = provider
            .models
            .iter()
            .filter(|model| cfg.resolve_trust(id, &model.id).is_trusted())
            .count();
        let subagent_count = provider
            .models
            .iter()
            .filter(|model| cfg.resolve_subagent_invokable(id, &model.id))
            .count();
        let eligible_subagent_count = provider
            .models
            .iter()
            .filter(|model| cfg.resolve_subagent_invokable(id, &model.id))
            .count();
        total_invokable += eligible_subagent_count;
        let can_delegate_count = provider
            .models
            .iter()
            .filter(|model| cfg.resolve_can_delegate(id, &model.id))
            .count();
        let mut computer_disabled = 0usize;
        let mut computer_ask = 0usize;
        let mut computer_yolo = 0usize;
        let mut computer_vision_models = 0usize;
        for model in &provider.models {
            let tier =
                cfg.resolve_computer_use_effective(id, &model.id, extended.computer_use, None);
            match tier {
                crate::config::extended::ComputerUseMode::Disabled => {
                    computer_disabled += 1;
                }
                crate::config::extended::ComputerUseMode::Ask => {
                    computer_ask += 1;
                }
                crate::config::extended::ComputerUseMode::Yolo => {
                    computer_yolo += 1;
                }
            }
            let caps =
                cfg.resolve_effective_model_capabilities(id, &model.id, cfg.resolution_generation);
            if tier != crate::config::extended::ComputerUseMode::Disabled
                && caps.supports_image_input()
                && caps
                    .computer_use
                    .as_ref()
                    .is_some_and(|c| c.contract.is_some())
            {
                computer_vision_models += 1;
            }
        }
        let embedding_count = provider
            .models
            .iter()
            .filter(|model| {
                cfg.resolve_effective_model_capabilities(id, &model.id, cfg.resolution_generation)
                    .embeddings
                    == Some(true)
            })
            .count();
        let hidden_count = model_count.saturating_sub(subagent_count);
        let ranked_count = provider
            .models
            .iter()
            .filter(|model| {
                cfg.resolve_quality_rank(id, &model.id) != 0
                    || cfg.resolve_cost_rank(id, &model.id) != 0
            })
            .count();
        let mut notes = vec![
            format!("trusted {trusted_count}/{model_count}"),
            format!("subagent-invokable {subagent_count}/{model_count}"),
            format!("can-delegate {can_delegate_count}/{model_count}"),
            format!(
                "computer-use disabled/ask/yolo {computer_disabled}/{computer_ask}/{computer_yolo}"
            ),
            format!("computer-vision {computer_vision_models}/{model_count}"),
            format!("embedding-capable {embedding_count}/{model_count}"),
            format!("ranked {ranked_count}/{model_count}"),
        ];
        if hidden_count > 0 {
            notes.push(format!("{hidden_count} hidden from subagent routing"));
        }
        out.push(format!(
            "{id}: {model_count} model(s), fetch {fetch}, {}",
            notes.join(", ")
        ));
        let (credential, credential_failed) = credential_line(id, provider, secret_lookup);
        failed |= credential_failed;
        out.push(credential);
    }
    match (delegation_enabled, total_invokable) {
        (true, 0) => {
            out.push(
                "subagent failover coverage: FAILED; delegation is available but no eligible subagent-invokable models are configured"
                    .to_string(),
            );
            failed = true;
        }
        (false, 0) => out.push(
            "subagent failover coverage: informational; delegation is unavailable and no subagent-invokable models are configured"
                .to_string(),
        ),
        (true, 1) => out.push(
            "subagent failover coverage: WARNING; exactly one eligible subagent-invokable model is configured, so delegation has no model failover"
                .to_string(),
        ),
        _ => out.push(format!(
            "subagent failover coverage: {total_invokable} eligible subagent-invokable models"
        )),
    }
    out.push("subagent failover reachability: not probed in this snapshot; run online `cockpit doctor` network checks for provider reachability".to_string());
    (out, failed)
}

fn delegation_enabled_for_coverage(
    cfg: &crate::config::providers::ProvidersConfig,
    _extended: &crate::config::extended::ExtendedConfig,
    input: &DiagnosticsInput,
) -> bool {
    let active_can_delegate = input
        .active_model
        .as_ref()
        .map(|(provider, model)| cfg.resolve_can_delegate(provider, model))
        .unwrap_or(true);
    active_can_delegate && agent_has_tool(&input.cwd, &input.active_agent, "task")
}

fn credential_line(
    provider_id: &str,
    provider: &crate::config::providers::ProviderEntry,
    secret_lookup: SecretLookup<'_>,
) -> (String, bool) {
    credential_line_with_sources(
        provider_id,
        provider,
        |name| std::env::var(name).ok(),
        |name| secret_lookup.and_then(|lookup| lookup(name)),
        |_| false,
    )
}

fn credential_line_with_sources<E, S, C>(
    provider_id: &str,
    provider: &crate::config::providers::ProviderEntry,
    env_lookup: E,
    secret_lookup: S,
    credential_present: C,
) -> (String, bool)
where
    E: Fn(&str) -> Option<String>,
    S: Fn(&str) -> Option<String>,
    C: Fn(&str) -> bool,
{
    if provider.auth == Some(crate::config::providers::AuthKind::None) {
        return (format!("{provider_id} credentials: not required"), false);
    }
    if let Some(credential_ref) = provider.credential_ref.as_deref() {
        if credential_present(credential_ref) {
            return (
                format!("{provider_id} credentials: ok (credential {credential_ref})"),
                false,
            );
        }
        return (
            format!(
                "{provider_id} credentials: MISSING — credential `{credential_ref}` not found; run: cockpit provider add {}",
                provider
                    .effective_template(provider_id)
                    .unwrap_or(provider_id)
            ),
            true,
        );
    }

    if provider.headers.is_empty() {
        return (
            format!(
                "{provider_id} credentials: none configured; run: cockpit provider add {provider_id}"
            ),
            true,
        );
    }

    let mut refs = Vec::new();
    let mut missing = Vec::new();
    let mut has_literal = false;
    for header in &provider.headers {
        let resolved = crate::envref::resolve_with_sources(
            &header.value,
            |name| env_lookup(name).filter(|value| !value.trim().is_empty()),
            |name| secret_lookup(name).filter(|value| !value.trim().is_empty()),
        );
        if resolved.referenced.is_empty() {
            has_literal = true;
        }
        refs.extend(resolved.referenced);
        missing.extend(resolved.missing);
        missing.extend(resolved.errors);
    }
    refs.sort();
    refs.dedup();
    missing.sort();
    missing.dedup();

    if !missing.is_empty() {
        let rendered = missing
            .iter()
            .map(|name| {
                if let Some(secret) = name.strip_prefix("secret:") {
                    format!("$secret:{secret} not found")
                } else if name.starts_with("invalid ") {
                    name.clone()
                } else {
                    format!("${name} not set")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        return (
            format!(
                "{provider_id} credentials: MISSING — {rendered}; run: cockpit provider add {}",
                provider
                    .effective_template(provider_id)
                    .unwrap_or(provider_id)
            ),
            true,
        );
    }

    let source = if refs.is_empty() {
        if has_literal {
            "literal header".to_string()
        } else {
            "configured headers".to_string()
        }
    } else {
        refs.iter()
            .map(|name| {
                if let Some(secret) = name.strip_prefix("secret:") {
                    format!("secret {secret}")
                } else {
                    format!("env {name}")
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    (format!("{provider_id} credentials: ok ({source})"), false)
}

async fn provider_network_lines(
    cfg: &crate::config::providers::ProvidersConfig,
    offline: bool,
) -> (Vec<String>, bool) {
    if offline {
        return (
            vec!["network checks: skipped (--offline)".to_string()],
            false,
        );
    }
    if cfg.providers.is_empty() {
        return (
            vec!["network checks: no providers configured; run: cockpit provider add".to_string()],
            true,
        );
    }
    let mut results = futures::stream::iter(cfg.providers.iter().enumerate().map(
        |(idx, (id, provider))| {
            let has_invokable_models = provider
                .models
                .iter()
                .any(|model| cfg.resolve_subagent_invokable(id, &model.id));
            async move {
        let Some(template_id) = provider.effective_template(id) else {
            return (
                idx,
                format!("{id}: skipped (custom provider has no built-in auth check)"),
                false,
            );
        };
        let Some(template) = crate::providers::template_by_id(template_id) else {
            return (
                idx,
                format!("{id}: skipped (unknown provider template {template_id})"),
                false,
            );
        };
        let (line, failed) = match crate::providers::auth_check::check_provider_auth(
            id,
            provider,
            template,
            Duration::from_secs(5),
        )
        .await
        {
            Ok(_) => (format!("{id}: reachable · credentials verified"), false),
            Err(crate::providers::auth_check::AuthCheckError::CredentialsRejected(error)) => (
                format!(
                    "{id}: reachable · credentials REJECTED ({}) — run: cockpit provider add {template_id}",
                    one_line(&error)
            ),
            true,
            ),
            Err(crate::providers::auth_check::AuthCheckError::Network(error))
                if has_invokable_models =>
            {
                (
                    format!(
                        "{id}: WARNING unreachable for subagent failover ({}) — check network/proxy; run: cockpit provider add {template_id}",
                        one_line(&error)
                    ),
                    false,
                )
            }
            Err(crate::providers::auth_check::AuthCheckError::Network(error)) => (
                format!(
                    "{id}: UNREACHABLE ({}) — check network/proxy; run: cockpit provider add {template_id}",
                    one_line(&error)
                ),
                true,
            ),
            Err(crate::providers::auth_check::AuthCheckError::Other(error)) => (
                format!(
                    "{id}: check failed ({}) — run: cockpit provider add {template_id}",
                    one_line(&error)
                ),
                true,
            ),
        };
        (idx, line, failed)
            }
        },
    ))
    .buffer_unordered(4)
    .collect::<Vec<_>>()
    .await;
    results.sort_by_key(|(idx, _, _)| *idx);
    let failed = results.iter().any(|(_, _, failed)| *failed);
    let out = results
        .into_iter()
        .map(|(_, line, _)| line)
        .collect::<Vec<_>>();
    (out, failed)
}

fn one_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Production Settings/doctor composition entry: upserts every configured
/// custom harness, builtin/configured LSP command, and stdio MCP server into
/// the shared health store and refreshes a generation-tagged snapshot.
fn compose_doctor_integration_health(
    cwd: &Path,
    compose: &crate::external_runtime::IntegrationHealthComposeInput,
    cancel: &crate::external_runtime::CancelToken,
    generation: u64,
    observer: impl FnMut(&crate::external_runtime::ExternalRuntimeSnapshot),
) -> Result<std::sync::Arc<crate::external_runtime::ExternalRuntimeSnapshot>> {
    crate::external_runtime::compose_settings_doctor_health_for_invocation(
        cwd, compose, cancel, generation, observer,
    )
    .map_err(anyhow::Error::new)
}

fn doctor_integration_input(
    cwd: &Path,
    harnesses: &std::collections::HashMap<String, crate::config::extended::HarnessConfig>,
    sandbox_enabled: bool,
) -> crate::external_runtime::IntegrationHealthComposeInput {
    // Resolve mutable layered configuration once at this diagnostics boundary;
    // the worker receives an invocation-owned, frozen view.
    let (extended, computer_use_mode) =
        crate::config::extended::load_for_cwd_with_computer_use_policy(cwd);
    let mut compose = crate::external_runtime::IntegrationHealthComposeInput {
        harnesses: crate::external_runtime::harness_compose_inputs(harnesses),
        lsp_servers: Vec::new(),
        stdio_mcp: Vec::new(),
        sandbox_enabled: Some(sandbox_enabled),
        sandbox_mode: extended.sandbox.default_mode,
        computer_use_mode,
        selected_features: harnesses
            .iter()
            .filter(|(name, config)| {
                crate::external_runtime::known_harness_preset_names().contains(&name.as_str())
                    && config.command.as_str() == name.as_str()
            })
            .map(|(name, _)| format!("harness.{name}"))
            .collect(),
        container_engine_mode: None,
    };
    // Builtin + configured LSP recipes (command argv only; install stays feature-local).
    for view in crate::daemon::lsp::builtin_server_views(cwd, &extended) {
        if !extended.lsp.servers.contains_key(&view.id)
            || matches!(view.status, crate::daemon::lsp::LspServerStatus::Disabled)
        {
            continue;
        }
        if let Some(input) = crate::external_runtime::lsp_command_input(&view.id, &view.command) {
            compose.lsp_servers.push(input);
        }
    }
    // Stdio MCP servers from layered mcp.json.
    let mcp = crate::mcp::config::McpConfig::discover(cwd);
    for (name, server) in &mcp.servers {
        if !server.enabled {
            continue;
        }
        if server.transport != crate::mcp::config::Transport::Stdio {
            continue;
        }
        let Some(command) = server.command.as_deref() else {
            continue;
        };
        compose
            .stdio_mcp
            .push(crate::external_runtime::mcp_stdio_input(
                name,
                command,
                &server.args,
            ));
    }
    compose
}

/// Bounded, daemon-independent dependency snapshot used by CLI doctor and the
/// TUI background refresh. The returned value is frozen; late worker results
/// are dropped and cannot mutate the caller's printed/rendered projection.
pub fn dependency_projection_with_deadline(
    cwd: PathBuf,
    deadline: Duration,
) -> Result<crate::external_runtime::DependencyProjection> {
    dependency_projection_with_deadline_internal(cwd, deadline, true, false)
}

/// Settings refresh variant: the bounded, frozen result becomes the shared
/// latest complete in-memory snapshot used by contextual projections.
pub fn dependency_projection_with_deadline_and_publish(
    cwd: PathBuf,
    deadline: Duration,
) -> Result<crate::external_runtime::DependencyProjection> {
    dependency_projection_with_deadline_internal(cwd, deadline, true, true)
}

pub fn dependency_projection_with_deadline_and_publish_for_run(
    cwd: PathBuf,
    deadline: Duration,
    sandbox_enabled: bool,
) -> Result<crate::external_runtime::DependencyProjection> {
    dependency_projection_with_deadline_internal(cwd, deadline, sandbox_enabled, true)
}

pub fn dependency_projection_with_deadline_for_run(
    cwd: PathBuf,
    deadline: Duration,
    sandbox_enabled: bool,
) -> Result<crate::external_runtime::DependencyProjection> {
    dependency_projection_with_deadline_internal(cwd, deadline, sandbox_enabled, false)
}

fn dependency_projection_with_deadline_internal(
    cwd: PathBuf,
    deadline: Duration,
    sandbox_enabled: bool,
    publish_complete: bool,
) -> Result<crate::external_runtime::DependencyProjection> {
    let expires = std::time::Instant::now() + deadline;
    enum WorkerUpdate {
        Progress {
            completed_at: std::time::Instant,
            snapshot: crate::external_runtime::ExternalRuntimeSnapshot,
        },
        Complete {
            completed_at: std::time::Instant,
            result: Result<std::sync::Arc<crate::external_runtime::ExternalRuntimeSnapshot>>,
        },
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let cancel = std::sync::Arc::new(crate::external_runtime::CancelToken::new());
    let worker_cancel = cancel.clone();
    let worker_cwd = cwd.clone();
    let harnesses = crate::config::extended::resolve_harnesses(&worker_cwd);
    let mut compose = doctor_integration_input(&worker_cwd, &harnesses, sandbox_enabled);
    compose.container_engine_mode = Some(crate::external_runtime::resolved_container_engine_mode(
        &compose,
    ));
    let descriptors = crate::external_runtime::invocation_descriptor_roster(&cwd, &compose)
        .map_err(anyhow::Error::new)?;
    let generation = if publish_complete {
        crate::external_runtime::global_health_store().begin_refresh()
    } else {
        crate::external_runtime::global_health_store()
            .current()
            .map_or(1, |value| value.generation.saturating_add(1))
    };
    let selected_harnesses: std::collections::BTreeSet<String> = harnesses
        .iter()
        .filter(|(name, config)| {
            crate::external_runtime::known_harness_preset_names().contains(&name.as_str())
                && config.command.as_str() == name.as_str()
        })
        .map(|(name, _)| format!("harness.{name}"))
        .collect();
    std::thread::Builder::new()
        .name("dependency-doctor".into())
        .spawn(move || {
            let progress_tx = tx.clone();
            let result = compose_doctor_integration_health(
                &worker_cwd,
                &compose,
                &worker_cancel,
                generation,
                move |snapshot| {
                    let _ = progress_tx.send(WorkerUpdate::Progress {
                        completed_at: std::time::Instant::now(),
                        snapshot: snapshot.clone(),
                    });
                },
            );
            let _ = tx.send(WorkerUpdate::Complete {
                completed_at: std::time::Instant::now(),
                result,
            });
        })
        .context("starting dependency diagnostics worker")?;
    let mut latest = None;
    loop {
        let remaining = expires.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(WorkerUpdate::Progress {
                completed_at,
                snapshot,
            }) if completed_at <= expires => {
                latest = Some(snapshot);
                continue;
            }
            Ok(WorkerUpdate::Complete {
                completed_at,
                result,
            }) if completed_at <= expires => {
                let snapshot = result?;
                if publish_complete {
                    let _ = crate::external_runtime::global_health_store()
                        .publish_complete_bundle(snapshot.as_ref().clone(), descriptors.clone());
                }
                return Ok(crate::external_runtime::project_dependencies(
                    Some(snapshot.as_ref()),
                    &descriptors,
                ));
            }
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                cancel.cancel();
                // Preserve every row that completed on time even if scheduler
                // latency left its message queued at the deadline.
                while let Ok(update) = rx.try_recv() {
                    match update {
                        WorkerUpdate::Progress {
                            completed_at,
                            snapshot,
                        } if completed_at <= expires => latest = Some(snapshot),
                        WorkerUpdate::Complete {
                            completed_at,
                            result,
                        } if completed_at <= expires => {
                            let snapshot = result?;
                            if publish_complete {
                                let _ = crate::external_runtime::global_health_store()
                                    .publish_complete_bundle(
                                        snapshot.as_ref().clone(),
                                        descriptors.clone(),
                                    );
                            }
                            return Ok(crate::external_runtime::project_dependencies(
                                Some(snapshot.as_ref()),
                                &descriptors,
                            ));
                        }
                        _ => {}
                    }
                }
                let platform = crate::external_runtime::detect_host_platform();
                let mut snapshot = latest.unwrap_or_else(|| {
                    crate::external_runtime::ExternalRuntimeSnapshot::empty(generation, platform)
                });
                for descriptor in &descriptors {
                    snapshot
                        .entries
                        .entry(descriptor.id.as_str().to_owned())
                        .or_insert_with(|| crate::external_runtime::HealthEntry {
                            id: descriptor.id.clone(),
                            state: if dependency_descriptor_applicable(
                                descriptor,
                                &cwd,
                                platform,
                                sandbox_enabled,
                                &selected_harnesses,
                            ) {
                                crate::external_runtime::HealthState::Pending
                            } else {
                                crate::external_runtime::HealthState::NotApplicable
                            },
                            importance: descriptor.importance,
                            target: descriptor.target,
                            remedy: Some(descriptor.remedy.clone()),
                            platform,
                        });
                }
                let snapshot = crate::external_runtime::freeze_pending_as_timed_out(&snapshot);
                if publish_complete {
                    let _ = crate::external_runtime::global_health_store()
                        .publish_complete_bundle(snapshot.clone(), descriptors.clone());
                }
                return Ok(crate::external_runtime::project_dependencies(
                    Some(&snapshot),
                    &descriptors,
                ));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("dependency diagnostics worker disconnected");
            }
        }
    }
}

fn dependency_descriptor_applicable(
    descriptor: &crate::external_runtime::ExternalRuntimeDescriptor,
    cwd: &Path,
    platform: crate::external_runtime::HostPlatform,
    sandbox_enabled: bool,
    selected_features: &std::collections::BTreeSet<String>,
) -> bool {
    use crate::external_runtime::{Applicability, ProbePolicy};
    let extended = crate::config::extended::load_for_cwd(cwd);
    let selected = matches!(
        descriptor.probe_policy,
        ProbePolicy::ConfiguredCommand { .. }
    ) || selected_features.contains(&descriptor.owner.feature)
        || (descriptor.owner.feature == "shell-sandbox"
            && sandbox_enabled
            && extended.sandbox.default_mode.enabled()
            && !extended.sandbox.default_mode.is_container())
        || (descriptor.owner.feature == "container-sandbox"
            // Engine descriptors enter this invocation-private roster only
            // when the sandbox/container selection was frozen as applicable.
            // Do not re-read mutable config at the deadline.
            && sandbox_enabled)
        || (descriptor.owner.feature == "computer-use"
            && crate::config::extended::resolve_computer_use_policy_for_cwd(cwd).is_some_and(
                |mode| !matches!(mode, crate::config::extended::ComputerUseMode::Disabled),
            ));
    match &descriptor.applicability {
        Applicability::Always => true,
        Applicability::WhenFeatureSelected => selected,
        Applicability::Platforms(platforms) => platforms.contains(&platform),
        Applicability::WhenFeatureSelectedOnPlatforms { platforms } => {
            selected && (platforms.is_empty() || platforms.contains(&platform))
        }
    }
}

fn git_lines(cwd: &Path) -> Vec<String> {
    if crate::external_runtime::require_live_available_for_launch(
        crate::external_runtime::ID_GIT,
        cwd,
    )
    .is_err()
    {
        return vec![
            "git: not Available (informational; shared external-runtime health)".to_string(),
        ];
    }
    let Some(version) = command_output(Command::new("git").arg("--version")) else {
        return vec!["git: not found (informational)".to_string()];
    };
    let mut out = vec![format!("git: {}", version.trim())];
    let Some(is_repo) = command_output(
        Command::new("git")
            .arg("-C")
            .arg(cwd)
            .arg("rev-parse")
            .arg("--is-inside-work-tree"),
    ) else {
        out.push("repo: no (informational)".to_string());
        return out;
    };
    if is_repo.trim() != "true" {
        out.push("repo: no (informational)".to_string());
        return out;
    }
    out.push("repo: yes".to_string());
    let branch = command_output(
        Command::new("git")
            .arg("-C")
            .arg(cwd)
            .arg("branch")
            .arg("--show-current"),
    )
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
    .unwrap_or_else(|| "detached".to_string());
    let dirty = command_output(
        Command::new("git")
            .arg("-C")
            .arg(cwd)
            .arg("status")
            .arg("--short"),
    )
    .map(|value| value.lines().count())
    .unwrap_or(0);
    out.push(format!("branch: {branch}"));
    out.push(format!("dirty: {dirty} changed path(s)"));
    out
}

fn command_output(command: &mut Command) -> Option<String> {
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn model_fetch_status_label(
    status: crate::config::providers::ModelFetchStatusKind,
) -> &'static str {
    match status {
        crate::config::providers::ModelFetchStatusKind::Live => "live",
        crate::config::providers::ModelFetchStatusKind::FailedKeptExisting => {
            "failed_kept_existing"
        }
        crate::config::providers::ModelFetchStatusKind::Fallback => "fallback",
        crate::config::providers::ModelFetchStatusKind::Unsupported => "unsupported",
        crate::config::providers::ModelFetchStatusKind::AuthFailed => "auth_failed",
    }
}

fn harness_lines(
    harnesses: &std::collections::HashMap<String, crate::config::extended::HarnessConfig>,
    trust_resolved: bool,
) -> Vec<String> {
    let mut ids: Vec<&String> = harnesses.keys().collect();
    ids.sort();
    ids.into_iter()
        .map(|id| {
            let harness = &harnesses[id];
            let path = if !trust_resolved {
                "trust-blocked".to_string()
            } else if command_on_path(&harness.command) {
                "on PATH, auth not probed".to_string()
            } else {
                "NOT on PATH".to_string()
            };
            let default = harness.default_model.as_deref().unwrap_or("none");
            // Surface the resolved custody posture per harness, read from the
            // SAME `HarnessConfig.trust` field production spawn resolves
            // (`crate::harness::run::run_harness`). Shown even when the
            // workspace trust root is unresolved, so the configured enum is
            // always visible and labeled consistently.
            let trust = harness.trust.as_str();
            format!(
                "{id}: trust={trust}, {path}, command `{}`, default {default}, {} model(s)",
                harness.command,
                harness.models.len()
            )
        })
        .collect()
}

fn delegation_lines(
    active_agent: &str,
    cwd: &Path,
    harness_configured: bool,
    extended: &crate::config::extended::ExtendedConfig,
) -> Vec<String> {
    vec![
        format!(
            "task: {}",
            availability(agent_has_tool(cwd, active_agent, "task"))
        ),
        format!(
            "external harness tools: {}",
            availability(
                harness_configured
                    && (agent_has_tool(cwd, active_agent, "harness_invoke")
                        || matches!(active_agent, "Build" | "Plan"))
            )
        ),
        format!(
            "deepthink: {} (tool-free reasoning-only)",
            if extended.deepthink.enabled {
                "enabled"
            } else {
                "disabled"
            }
        ),
        format!(
            "task recursion: {}, default child budget {}, batch max {}",
            if extended.delegation.recursion_enabled {
                "enabled"
            } else {
                "disabled"
            },
            extended.delegation.default_recursion_depth,
            extended.delegation.max_parallel
        ),
    ]
}

fn availability(ok: bool) -> &'static str {
    if ok { "available" } else { "unavailable" }
}

fn agent_has_tool(cwd: &Path, agent: &str, tool: &str) -> bool {
    match crate::agents::resolve(cwd, agent) {
        Ok(Some(def)) => def
            .tools
            .as_ref()
            .is_some_and(|tools| tools.iter().any(|t| t == tool)),
        _ => false,
    }
}

fn command_on_path(command: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    let names: Vec<String> = if cfg!(windows) {
        vec![format!("{command}.exe"), command.to_string()]
    } else {
        vec![command.to_string()]
    };
    std::env::split_paths(&paths).any(|dir| names.iter().any(|name| dir.join(name).is_file()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{AuthKind, HeaderSpec, ProviderEntry, ProvidersConfig};

    fn base_input(cwd: &Path) -> DiagnosticsInput {
        DiagnosticsInput {
            cwd: cwd.to_path_buf(),
            session_id: Some(uuid::Uuid::nil()),
            session_short_id: Some("abc123".to_string()),
            active_agent: "Build".to_string(),
            active_model: Some(("p".to_string(), "m".to_string())),
            pending_model_selection: None,
            sandbox_enabled: Some(true),
        }
    }

    fn trusted_snapshot(input: DiagnosticsInput) -> DiagnosticsSnapshot {
        let cwd = input.cwd.clone();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(&cwd);
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&cwd).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::with_workspace_trust_policy(policy, || {
            build_snapshot(input, None, None).unwrap()
        })
    }

    fn trusted_tui_snapshot(input: DiagnosticsInput) -> DiagnosticsSnapshot {
        let cwd = input.cwd.clone();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(&cwd);
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&cwd).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::with_workspace_trust_policy(policy, || tui_snapshot(input).unwrap())
    }

    fn provider_with_header(value: &str) -> ProviderEntry {
        ProviderEntry {
            url: "https://example.test/v1".to_string(),
            auth: Some(AuthKind::ApiKey),
            headers: vec![HeaderSpec {
                name: "Authorization".to_string(),
                value: value.to_string(),
            }],
            ..ProviderEntry::default()
        }
    }

    #[test]
    fn tui_doctor_refreshes_dependency_projection() {
        let tmp = tempfile::tempdir().unwrap();
        let input = base_input(tmp.path());

        let tui = trusted_tui_snapshot(input.clone());
        assert_eq!(
            tui.dependencies.schema_version,
            crate::external_runtime::DEPENDENCY_HEADLESS_SCHEMA_VERSION
        );
        assert!(!tui.dependencies.rows.is_empty());
        assert!(render(&tui).contains("Cockpit diagnostics"));
    }

    #[test]
    fn unresolved_trust_ignores_project_harness_config() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            r#"{"harnesses":{"codex-oauth":{"command":"definitely-missing-codex","models":["codex"]}}}"#,
        )
        .unwrap();

        let snapshot = build_snapshot(base_input(tmp.path()), None, None).unwrap();

        assert!(snapshot.workspace_trust.contains("unresolved"));
        assert!(
            snapshot.harnesses.is_empty(),
            "untrusted project harness definitions must not be loaded: {:?}",
            snapshot.harnesses
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    /// AC1: the harness diagnostics section surfaces each harness's resolved
    /// custody posture (`trust=trusted|untrusted`), read from the same
    /// `HarnessConfig.trust` field production spawn resolves. Pre-change
    /// behavior emitted no trust token, so every `trust=` assertion here
    /// rejects it.
    #[test]
    fn harness_lines_surface_resolved_trust_per_harness() {
        use crate::config::extended::HarnessConfig;
        let trusted: HarnessConfig =
            serde_json::from_str(r#"{"command":"codex","trust":"trusted"}"#).unwrap();
        // Omitting `trust` must resolve to the untrusted default.
        let untrusted: HarnessConfig = serde_json::from_str(r#"{"command":"claude"}"#).unwrap();
        assert_eq!(
            trusted.trust,
            crate::config::extended::HarnessTrust::Trusted,
            "precondition: the trusted fixture is actually trusted"
        );
        assert_eq!(
            untrusted.trust,
            crate::config::extended::HarnessTrust::Untrusted,
            "precondition: an unconfigured harness defaults to untrusted"
        );

        let mut harnesses = std::collections::HashMap::new();
        harnesses.insert("aye".to_string(), trusted);
        harnesses.insert("bee".to_string(), untrusted);

        let resolved = harness_lines(&harnesses, true).join("\n");
        assert!(resolved.contains("aye: trust=trusted,"), "{resolved}");
        assert!(resolved.contains("bee: trust=untrusted,"), "{resolved}");

        // Edge case: when the workspace trust root is unresolved, the path is
        // trust-blocked but the configured custody enum is still shown and
        // labeled the same way.
        let unresolved = harness_lines(&harnesses, false).join("\n");
        assert!(
            unresolved.contains("aye: trust=trusted, trust-blocked,"),
            "{unresolved}"
        );
        assert!(
            unresolved.contains("bee: trust=untrusted, trust-blocked,"),
            "{unresolved}"
        );
    }

    #[test]
    fn diagnostics_surface_model_policy_and_delegation_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        let config_path = cockpit.join("config.json");
        std::fs::write(
            &config_path,
            r#"{
                "deepthink": { "enabled": true },
                "delegation": {
                    "maxParallel": 3,
                    "recursionEnabled": true,
                    "defaultRecursionDepth": 2
                }
            }"#,
        )
        .unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "mixed").unwrap();
        std::fs::write(
            provider_path,
            r#"{
                "url": "https://mixed.example/v1",
                "trust": "untrusted",
                "models": [
                    { "id": "parent-untrusted", "subagent_invokable": true },
                    { "id": "child-trusted", "trust": "trusted", "subagent_invokable": true, "quality_rank": 9, "cost_rank": 3 },
                    { "id": "hidden-trusted", "trust": "trusted", "subagent_invokable": false }
                ]
            }"#,
        )
        .unwrap();

        let snapshot = trusted_snapshot(base_input(tmp.path()));
        let rendered = render(&snapshot);

        assert!(
            rendered.contains(
                "mixed: 3 model(s), fetch not fetched, trusted 2/3, subagent-invokable 2/3"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains("1 hidden from subagent routing"),
            "{rendered}"
        );
        assert!(
            rendered.contains("deepthink: enabled (tool-free reasoning-only)"),
            "{rendered}"
        );
        assert!(
            rendered.contains("task recursion: enabled, default child budget 2, batch max 3"),
            "{rendered}"
        );
    }

    #[test]
    fn can_delegate_doctor_reports_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        let config_path = cockpit.join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "mixed").unwrap();
        std::fs::write(
            provider_path,
            r#"{
                "url": "https://mixed.example/v1",
                "can_delegate": false,
                "models": [
                    { "id": "provider-off" },
                    { "id": "model-on", "can_delegate": true },
                    { "id": "model-off", "can_delegate": false }
                ]
            }"#,
        )
        .unwrap();

        let snapshot = trusted_snapshot(base_input(tmp.path()));
        let rendered = render(&snapshot);

        assert!(rendered.contains("can-delegate 1/3"), "{rendered}");
    }

    fn coverage_cfg(model: crate::config::providers::ModelEntry) -> ProvidersConfig {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p".to_string(),
            ProviderEntry {
                url: "https://p.example/v1".to_string(),
                auth: Some(AuthKind::None),
                models: vec![model],
                ..ProviderEntry::default()
            },
        );
        cfg
    }

    #[test]
    fn doctor_fails_when_delegation_enabled_and_no_invokable_models() {
        let cfg = coverage_cfg(crate::config::providers::ModelEntry {
            id: "m".to_string(),
            can_delegate: Some(true),
            ..Default::default()
        });
        let (lines, failed) = provider_lines(
            &cfg,
            &crate::config::extended::ExtendedConfig::default(),
            true,
            None,
        );
        let rendered = lines.join("\n");
        assert!(failed, "{rendered}");
        assert!(
            rendered.contains("subagent failover coverage: FAILED"),
            "{rendered}"
        );
    }

    #[test]
    fn doctor_does_not_fail_when_delegation_disabled_and_no_invokable_models() {
        let cfg = coverage_cfg(crate::config::providers::ModelEntry {
            id: "m".to_string(),
            can_delegate: Some(false),
            ..Default::default()
        });
        let (lines, failed) = provider_lines(
            &cfg,
            &crate::config::extended::ExtendedConfig::default(),
            false,
            None,
        );
        let rendered = lines.join("\n");
        assert!(!failed, "{rendered}");
        assert!(
            rendered.contains("subagent failover coverage: informational"),
            "{rendered}"
        );
    }

    #[test]
    fn doctor_warns_but_does_not_fail_with_single_invokable_model() {
        let cfg = coverage_cfg(crate::config::providers::ModelEntry {
            id: "m".to_string(),
            can_delegate: Some(true),
            subagent_invokable: Some(true),
            ..Default::default()
        });
        let (lines, failed) = provider_lines(
            &cfg,
            &crate::config::extended::ExtendedConfig::default(),
            true,
            None,
        );
        let rendered = lines.join("\n");
        assert!(!failed, "{rendered}");
        assert!(
            rendered.contains("subagent failover coverage: WARNING"),
            "{rendered}"
        );
    }

    #[test]
    fn doctor_offline_skips_invokable_reachability_probe() {
        let mut cfg = coverage_cfg(crate::config::providers::ModelEntry {
            id: "m".to_string(),
            can_delegate: Some(true),
            subagent_invokable: Some(true),
            ..Default::default()
        });
        cfg.providers
            .get_mut("p")
            .unwrap()
            .models
            .push(crate::config::providers::ModelEntry {
                id: "n".to_string(),
                subagent_invokable: Some(true),
                ..Default::default()
            });
        let (lines, failed) = provider_lines(
            &cfg,
            &crate::config::extended::ExtendedConfig::default(),
            true,
            None,
        );
        let rendered = lines.join("\n");
        assert!(
            rendered.contains("subagent failover reachability: not probed"),
            "{rendered}"
        );
        assert!(!failed, "{rendered}");
    }

    #[test]
    fn doctor_reports_computer_use() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        let config_path = cockpit.join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "mixed").unwrap();
        std::fs::write(
            provider_path,
            r#"{
                "url": "https://mixed.example/v1",
                "computer_use": "yolo",
                "models": [
                    {
                        "id": "provider-yolo",
                        "capabilities": { "image_input": "unsupported" }
                    },
                    {
                        "id": "model-ask",
                        "computer_use": "ask",
                        "capabilities": {
                            "image_input": "supported",
                            "computer_use": { "contract": "open_ai_responses" }
                        }
                    },
                    {
                        "id": "model-disabled",
                        "computer_use": "disabled",
                        "capabilities": {
                            "image_input": "supported",
                            "computer_use": { "contract": "open_ai_responses" }
                        }
                    }
                ]
            }"#,
        )
        .unwrap();

        let snapshot = trusted_snapshot(base_input(tmp.path()));
        let rendered = render(&snapshot);

        assert!(
            rendered.contains("computer-use disabled/ask/yolo 1/1/1"),
            "{rendered}"
        );
        assert!(rendered.contains("computer-vision 1/3"), "{rendered}");
    }

    #[test]
    fn doctor_renders_container_block() {
        let tmp = tempfile::tempdir().unwrap();
        let rendered = render(&trusted_snapshot(base_input(tmp.path())));

        assert!(rendered.contains("container:"), "{rendered}");
        assert!(rendered.contains("runtime:"), "{rendered}");
        assert!(rendered.contains("harness:"), "{rendered}");
        assert!(rendered.contains("available:"), "{rendered}");
    }

    #[test]
    fn doctor_credential_resolvability_states() {
        let cases = [
            (
                "env-ok",
                provider_with_header("Bearer $COCKPIT_DOCTOR_PRESENT_KEY"),
            ),
            (
                "env-missing",
                provider_with_header("Bearer $COCKPIT_DOCTOR_MISSING_KEY"),
            ),
            (
                "secret-ok",
                provider_with_header("Bearer $secret:doctor-present"),
            ),
            (
                "secret-missing",
                provider_with_header("Bearer $secret:doctor-missing"),
            ),
        ];
        let mut lines = Vec::new();
        let mut failed = false;
        for (id, provider) in cases {
            let (line, line_failed) = credential_line_with_sources(
                id,
                &provider,
                |name| {
                    (name == "COCKPIT_DOCTOR_PRESENT_KEY").then(|| "sk-present-secret".to_string())
                },
                |name| (name == "doctor-present").then(|| "sk-named-secret-value".to_string()),
                |_| false,
            );
            lines.push(line);
            failed |= line_failed;
        }
        let rendered = lines.join("\n");

        assert!(failed);
        assert!(
            rendered.contains("env-ok credentials: ok (env COCKPIT_DOCTOR_PRESENT_KEY)"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "env-missing credentials: MISSING — $COCKPIT_DOCTOR_MISSING_KEY not set; run:"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains("secret-ok credentials: ok (secret doctor-present)"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "secret-missing credentials: MISSING — $secret:doctor-missing not found; run:"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains("sk-present-secret"), "{rendered}");
        assert!(!rendered.contains("sk-named-secret-value"), "{rendered}");
    }

    #[test]
    fn doctor_renders_redacted_pending_model_selection() {
        let tmp = tempfile::tempdir().unwrap();
        let input = DiagnosticsInput {
            pending_model_selection: Some(
                "pending 00000000-0000-0000-0000-000000000000: p/m".to_string(),
            ),
            ..base_input(tmp.path())
        };
        let rendered = render(&trusted_snapshot(input));
        assert!(
            rendered.contains("model selection: pending 00000000-0000-0000-0000-000000000000: p/m"),
            "{rendered}"
        );
    }

    #[test]
    fn reports_effective_default_agent() {
        let extended = crate::config::extended::ExtendedConfig::default();
        assert_eq!(effective_default_agent(&extended), "Careful");
    }

    #[test]
    fn delegation_coverage_uses_effective_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let extended = crate::config::extended::ExtendedConfig::default();
        let effective = effective_default_agent(&extended);
        let input = DiagnosticsInput {
            active_agent: effective.clone(),
            ..base_input(tmp.path())
        };
        assert_eq!(effective, "Careful");
        assert!(delegation_enabled_for_coverage(
            &ProvidersConfig::default(),
            &extended,
            &input
        ));
    }

    async fn one_shot_server(status: &'static str, body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buf = vec![0; 4096];
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        format!("http://{addr}/v1")
    }

    fn network_cfg(base_url: String) -> ProvidersConfig {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "zai-test".to_string(),
            ProviderEntry {
                url: base_url,
                template: Some("z-ai".to_string()),
                auth: Some(AuthKind::ApiKey),
                headers: vec![HeaderSpec {
                    name: "Authorization".to_string(),
                    value: "Bearer literal-test-token".to_string(),
                }],
                ..ProviderEntry::default()
            },
        );
        cfg
    }

    fn network_cfg_with_invokable(base_url: String) -> ProvidersConfig {
        let mut cfg = network_cfg(base_url);
        cfg.providers.get_mut("zai-test").unwrap().models.push(
            crate::config::providers::ModelEntry {
                id: "child".to_string(),
                subagent_invokable: Some(true),
                ..Default::default()
            },
        );
        cfg
    }

    #[tokio::test]
    async fn doctor_network_states_and_mutates_nothing() {
        let ok_url = one_shot_server("200 OK", r#"{"ok":true}"#).await;
        let cfg = network_cfg(ok_url);
        let before = serde_json::to_value(&cfg).unwrap();
        let (lines, failed) = provider_network_lines(&cfg, false).await;
        assert!(!failed, "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("reachable · credentials verified")),
            "{lines:?}"
        );
        assert_eq!(serde_json::to_value(&cfg).unwrap(), before);

        let rejected_url = one_shot_server("401 Unauthorized", r#"{"error":"bad key"}"#).await;
        let cfg = network_cfg(rejected_url);
        let (lines, failed) = provider_network_lines(&cfg, false).await;
        assert!(failed, "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("credentials REJECTED")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn doctor_offline_skips_network() {
        let cfg = network_cfg("http://127.0.0.1:9/v1".to_string());
        let (lines, failed) = provider_network_lines(&cfg, true).await;

        assert!(!failed);
        assert_eq!(lines, ["network checks: skipped (--offline)"]);
    }

    #[tokio::test]
    async fn doctor_unreachable_invokable_host_warns_without_failing() {
        let cfg = network_cfg_with_invokable("http://127.0.0.1:9/v1".to_string());
        let (lines, failed) = provider_network_lines(&cfg, false).await;

        assert!(!failed, "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("WARNING unreachable for subagent failover")),
            "{lines:?}"
        );
    }

    #[test]
    fn doctor_git_states() {
        let tmp = tempfile::tempdir().unwrap();
        let lines = git_lines(tmp.path());
        let rendered = lines.join("\n");

        assert!(
            rendered.contains("git: not found") || rendered.contains("git version"),
            "{rendered}"
        );
        assert!(
            rendered.contains("repo: no") || rendered.contains("repo: yes"),
            "{rendered}"
        );
    }

    #[test]
    fn doctor_exit_codes() {
        let tmp = tempfile::tempdir().unwrap();
        let snapshot = trusted_snapshot(base_input(tmp.path()));
        assert!(snapshot.has_failures);

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "local".to_string(),
            ProviderEntry {
                url: "http://127.0.0.1:11434/v1".to_string(),
                auth: Some(AuthKind::None),
                ..ProviderEntry::default()
            },
        );
        let (_lines, failed) = provider_lines(
            &cfg,
            &crate::config::extended::ExtendedConfig::default(),
            false,
            None,
        );
        assert!(!failed);
    }

    #[test]
    fn embedding_doctor_reports_resolution() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        let config_path = cockpit.join("config.json");
        std::fs::write(&config_path, r#"{"embedding_model":"openai/embed"}"#).unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "openai")
                .unwrap();
        std::fs::write(
            provider_path,
            r#"{
                "url": "https://openai.example/v1",
                "models": [
                    { "id": "embed", "embeddings": true, "embedding_dimensions": 1536 },
                    { "id": "chat" }
                ]
            }"#,
        )
        .unwrap();

        let rendered = render(&trusted_snapshot(base_input(tmp.path())));

        assert!(
            rendered.contains("embedding_model: resolved openai/embed (1536 dims)"),
            "{rendered}"
        );
        assert!(
            rendered.contains("openai: 2 model(s), fetch not fetched"),
            "{rendered}"
        );
        assert!(rendered.contains("embedding-capable 1/2"), "{rendered}");
    }

    /// The daemon's repair diagnostic tells the user to run `cockpit doctor`,
    /// so doctor must actually describe the pending journal — and describe it
    /// without leaking configuration content.
    #[test]
    fn doctor_reports_a_pending_default_model_journal_and_omits_it_when_clean() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        std::fs::write(
            &config_path,
            r#"{"api_key":"sk-not-in-doctor-output","providers":{}}"#,
        )
        .unwrap();

        let clean = render(&trusted_snapshot(base_input(tmp.path())));
        assert!(
            !clean.contains("default model journal"),
            "no journal, no section: {clean}"
        );

        let journal_path = crate::config::providers::journal_path_for_layer(&config_path);
        std::fs::write(&journal_path, b"{ not a journal record").unwrap();

        let rendered = render(&trusted_snapshot(base_input(tmp.path())));
        assert!(rendered.contains("default model journal"), "{rendered}");
        assert!(
            rendered.contains(&journal_path.display().to_string()),
            "the report must name the file to inspect: {rendered}"
        );
        assert!(rendered.contains("unreadable"), "{rendered}");
        assert!(
            !rendered.contains("sk-not-in-doctor-output"),
            "doctor must never render configuration content: {rendered}"
        );
    }

    // ---- external side-effect journal doctor coverage --------------------

    use crate::db::external_journal::{
        EXTERNAL_JOURNAL_ADMISSION_BYTES, EXTERNAL_JOURNAL_ADMISSION_CAPSULES,
        EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES, ExternalJournalAgeReport,
        ExternalJournalCapacity,
    };

    fn healthy_spool() -> ExternalJournalSpoolHealth {
        ExternalJournalSpoolHealth::Healthy {
            allocated_bytes: 65_536,
            quarantined_entries: 0,
        }
    }

    #[test]
    fn external_journal_doctor_section_is_clean_when_nothing_is_wrong() {
        let (lines, failed) = external_journal_section(
            ExternalJournalCapacity {
                admission_capsules: 1,
                admission_bytes: 65_536,
                ..ExternalJournalCapacity::default()
            },
            ExternalJournalAgeReport::default(),
            &healthy_spool(),
            None,
        );
        assert!(!failed, "{lines:?}");
        assert!(lines.iter().any(|line| line == "admission: ok"));
        assert!(lines.iter().any(|line| line == "age: ok"));
        assert!(lines.iter().any(|line| line == "spool: ok (owner-only)"));
    }

    #[test]
    fn external_journal_doctor_section_fails_on_quarantine() {
        let (lines, failed) = external_journal_section(
            ExternalJournalCapacity::default(),
            ExternalJournalAgeReport::default(),
            &ExternalJournalSpoolHealth::Healthy {
                allocated_bytes: 65_536,
                quarantined_entries: 2,
            },
            None,
        );
        assert!(failed, "quarantine must make doctor exit non-zero");
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("quarantine: FAILED")),
            "{lines:?}"
        );
    }

    #[test]
    fn external_journal_doctor_section_fails_on_full_admission_partition() {
        let (lines, failed) = external_journal_section(
            ExternalJournalCapacity {
                admission_capsules: EXTERNAL_JOURNAL_ADMISSION_CAPSULES,
                admission_bytes: EXTERNAL_JOURNAL_ADMISSION_BYTES,
                ..ExternalJournalCapacity::default()
            },
            ExternalJournalAgeReport::default(),
            &healthy_spool(),
            None,
        );
        assert!(failed);
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("admission: FAILED")),
            "{lines:?}"
        );
    }

    #[test]
    fn external_journal_doctor_section_fails_on_full_recovery_reserve() {
        // The reserve exists so a successful handoff always has somewhere to
        // write its fallback; exhausting it must block new work too.
        let (lines, failed) = external_journal_section(
            ExternalJournalCapacity {
                recovery_capsules: EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES,
                ..ExternalJournalCapacity::default()
            },
            ExternalJournalAgeReport::default(),
            &healthy_spool(),
            None,
        );
        assert!(failed);
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("admission: FAILED")),
            "{lines:?}"
        );
    }

    #[test]
    fn external_journal_doctor_section_fails_on_unresolved_work_past_24h() {
        let (lines, failed) = external_journal_section(
            ExternalJournalCapacity::default(),
            ExternalJournalAgeReport {
                unresolved: 3,
                warning: 1,
                critical: 2,
                oldest_age_ms: 90_000_000,
            },
            &healthy_spool(),
            None,
        );
        assert!(failed);
        assert!(
            lines.iter().any(|line| line.starts_with("age: FAILED")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("3 record(s); 1 warning, 2 critical")),
            "{lines:?}"
        );
    }

    #[test]
    fn external_journal_doctor_section_warns_without_failing_at_15m() {
        let (lines, failed) = external_journal_section(
            ExternalJournalCapacity::default(),
            ExternalJournalAgeReport {
                unresolved: 1,
                warning: 1,
                critical: 0,
                oldest_age_ms: 900_000,
            },
            &healthy_spool(),
            None,
        );
        assert!(!failed, "a 15m warning must not fail the doctor run");
        assert!(
            lines.iter().any(|line| line.starts_with("age: WARNING")),
            "{lines:?}"
        );
    }

    #[test]
    fn external_journal_doctor_section_fails_on_insecure_spool() {
        let (lines, failed) = external_journal_section(
            ExternalJournalCapacity::default(),
            ExternalJournalAgeReport::default(),
            &ExternalJournalSpoolHealth::Unhealthy {
                detail: "spool directory /x/capsules has mode 755".to_string(),
            },
            None,
        );
        assert!(failed, "an insecure spool must make doctor exit non-zero");
        assert!(
            lines.iter().any(|line| line.starts_with("spool: FAILED")),
            "{lines:?}"
        );
    }

    /// The durable latch is the delivery mechanism: a simultaneous
    /// database-and-spool failure recorded by some earlier process must make a
    /// later doctor run critical even though nothing here holds a journal
    /// instance and everything else looks healthy.
    #[test]
    fn external_journal_doctor_section_fails_on_a_persisted_integrity_fault() {
        let (lines, failed) = external_journal_section(
            ExternalJournalCapacity::default(),
            ExternalJournalAgeReport::default(),
            &healthy_spool(),
            Some("database and spool both failed after handoff".to_string()),
        );
        assert!(
            failed,
            "a persisted integrity fault must fail the doctor run"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("integrity: FAILED")),
            "{lines:?}"
        );
    }

    #[test]
    fn external_journal_doctor_section_reports_absent_spool_without_failing() {
        let (lines, failed) = external_journal_section(
            ExternalJournalCapacity::default(),
            ExternalJournalAgeReport::default(),
            &ExternalJournalSpoolHealth::Absent,
            None,
        );
        assert!(!failed);
        assert!(
            lines
                .iter()
                .any(|line| line == "spool: none (not yet created)"),
            "{lines:?}"
        );
    }

    #[test]
    fn database_schema_rejection_classifier_covers_every_boot_rejection_family() {
        for message in [
            "FCDB_SCHEMA_PROFILE_MISMATCH: wrong profile",
            "FCDB_SCHEMA_REJECTED_AFTER_OPEN: backup ledger differs from compiled schema",
            "incompatible prerelease database schema v2",
            "incompatible legacy prerelease database schema v1",
            "database migration ledger is corrupt: gap",
            "database schema version is inconsistent: user_version drift",
            "migration checksum mismatch for 0001_initial.sql",
            "database schema fingerprint mismatch at migration 1",
        ] {
            assert!(is_schema_rejection(message), "not classified: {message}");
        }
        assert!(!is_schema_rejection(
            "opening SQLite read-only: permission denied"
        ));
    }

    #[test]
    fn database_failure_guidance_is_actionable_and_zero_windows_are_unlimited() {
        let retention = crate::db::retention::RetentionConfig {
            transcript_window_days: 0,
            raw_wire_window_days: 0,
            terminal_evidence_window_days: 0,
            session_window_days: 0,
            ..crate::db::retention::RetentionConfig::default()
        };
        let mut lines = Vec::new();
        append_database_failure_guidance(&mut lines, &retention);

        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("export: unavailable"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("repair: read-only doctor"))
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some(
                "retention: sessions unlimited; transcripts unlimited; raw/wire unlimited; terminal evidence unlimited"
            )
        );
    }
}
