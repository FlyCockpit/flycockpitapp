//! Deterministic Agent Skills curator.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::extended::SkillsConfig;
use crate::daemon::proto::{
    MissedRunPolicy, ScheduledJobCreate, ScheduledJobPayload, ScheduledJobSchedule,
};
use crate::db::Db;
use crate::db::skill_usage::{
    SkillCreatedBy, SkillCuratorSnapshotRow, SkillUsageRow, SkillUsageState,
};

use super::manage::{SkillLifecycleMetadata, lifecycle_metadata_for_skill, usage_seed_for_skill};

pub const CURATOR_JOB_ID: &str = "system-skill-curator";
pub const CURATOR_OWNER: &str = "system:skill-curator";
pub const CURATOR_SUBSYSTEM: &str = "skill-curator";
pub const CURATOR_INTERVAL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const CURATOR_MIN_IDLE_SECONDS: u64 = 2 * 60 * 60;
const STALE_AFTER_SECONDS: i64 = 30 * 24 * 60 * 60;
const ARCHIVE_AFTER_SECONDS: i64 = 90 * 24 * 60 * 60;
const SNAPSHOT_RETENTION: usize = 10;
const SNAPSHOT_LEDGER_FILE: &str = "skill_usage.json";

pub trait CuratorClock: Send + Sync {
    fn now(&self) -> i64;
}

#[derive(Debug, Default)]
pub struct SystemCuratorClock;

impl CuratorClock for SystemCuratorClock {
    fn now(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorRunOptions {
    pub dry_run: bool,
    pub consolidate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorRunReport {
    pub dry_run: bool,
    pub scanned: usize,
    pub stale: Vec<String>,
    pub archived: Vec<String>,
    pub reactivated: Vec<String>,
    pub skipped: Vec<String>,
    pub snapshot_id: Option<String>,
    pub consolidation: Option<String>,
}

impl CuratorRunReport {
    pub fn summary(&self) -> String {
        format!(
            "skill curator scanned {}; stale={}, archived={}, reactivated={}, skipped={}",
            self.scanned,
            self.stale.len(),
            self.archived.len(),
            self.reactivated.len(),
            self.skipped.len()
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorStatus {
    pub skills: Vec<CuratorSkillStatus>,
    pub snapshots: Vec<CuratorSnapshotStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorSkillStatus {
    pub name: String,
    pub state: String,
    pub created_by: String,
    pub use_count: u64,
    pub view_count: u64,
    pub pinned: bool,
    pub source_path: String,
    pub archive_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorSnapshotStatus {
    pub id: String,
    pub path: String,
    pub reason: String,
    pub created_at: i64,
}

pub struct SkillCurator {
    db: Db,
    cwd: PathBuf,
    config: SkillsConfig,
    clock: Arc<dyn CuratorClock>,
}

impl SkillCurator {
    pub fn new(db: Db, cwd: PathBuf, config: SkillsConfig) -> Self {
        Self::with_clock(db, cwd, config, Arc::new(SystemCuratorClock))
    }

    pub fn with_clock(
        db: Db,
        cwd: PathBuf,
        config: SkillsConfig,
        clock: Arc<dyn CuratorClock>,
    ) -> Self {
        Self {
            db,
            cwd,
            config,
            clock,
        }
    }

    pub fn status(&self) -> Result<CuratorStatus> {
        self.sync_discovered()?;
        Ok(CuratorStatus {
            skills: self
                .db
                .list_skill_usage()?
                .into_iter()
                .map(CuratorSkillStatus::from)
                .collect(),
            snapshots: self
                .db
                .list_skill_curator_snapshots()?
                .into_iter()
                .map(CuratorSnapshotStatus::from)
                .collect(),
        })
    }

    pub fn run(&self, options: CuratorRunOptions) -> Result<CuratorRunReport> {
        self.sync_discovered()?;
        let now = self.clock.now();
        let discovered = self.discovered_with_metadata()?;
        let cron_refs = cron_referenced_skills(&self.db)?;
        let mut report = CuratorRunReport {
            dry_run: options.dry_run,
            scanned: discovered.len(),
            stale: Vec::new(),
            archived: Vec::new(),
            reactivated: Vec::new(),
            skipped: Vec::new(),
            snapshot_id: None,
            consolidation: None,
        };

        let mut changes = Vec::new();
        for discovered in discovered {
            let row = self
                .db
                .get_skill_usage(&discovered.name)?
                .context("discovered skill missing usage row")?;
            match transition_for(
                &row,
                &discovered,
                &cron_refs,
                self.config.prune_builtins,
                now,
            ) {
                Transition::Skip(reason) => report.skipped.push(format!("{}:{reason}", row.name)),
                Transition::None => {}
                Transition::Reactivate => {
                    report.reactivated.push(row.name.clone());
                    changes.push((row, SkillUsageState::Active));
                }
                Transition::Stale => {
                    report.stale.push(row.name.clone());
                    changes.push((row, SkillUsageState::Stale));
                }
                Transition::Archive => {
                    report.archived.push(row.name.clone());
                    changes.push((row, SkillUsageState::Archived));
                }
            }
        }

        if options.consolidate || self.config.consolidate {
            report.consolidation = Some(consolidation_prompt(&self.db)?);
        }

        let will_mutate = !options.dry_run
            && (!changes.is_empty()
                || report.consolidation.as_ref().is_some_and(|s| !s.is_empty()));
        if will_mutate {
            report.snapshot_id = Some(self.snapshot("curator-run")?.id);
        }

        if !options.dry_run {
            for (row, state) in changes {
                match state {
                    SkillUsageState::Active => {
                        self.db
                            .set_skill_usage_state(&row.name, state, None, None, now)?;
                    }
                    SkillUsageState::Stale => {
                        self.db
                            .set_skill_usage_state(&row.name, state, None, None, now)?;
                    }
                    SkillUsageState::Archived => {
                        let archive_path = self.archive_skill(&row, now)?;
                        self.db.set_skill_usage_state(
                            &row.name,
                            state,
                            Some(archive_path.display().to_string()),
                            Some(now),
                            now,
                        )?;
                    }
                }
            }
        }

        Ok(report)
    }

    pub fn pin(&self, name: &str, pinned: bool) -> Result<()> {
        self.sync_discovered()?;
        if self.db.get_skill_usage(name)?.is_none() {
            bail!("unknown skill `{name}`");
        }
        self.db
            .set_skill_usage_pinned(name, pinned, self.clock.now())
    }

    pub fn restore(&self, name: &str) -> Result<()> {
        self.snapshot("restore")?;
        let row = self
            .db
            .get_skill_usage(name)?
            .with_context(|| format!("unknown skill `{name}`"))?;
        let archive_path = row
            .archive_path
            .as_deref()
            .map(PathBuf::from)
            .with_context(|| format!("skill `{name}` has no archive path"))?;
        if !archive_path.join("SKILL.md").is_file() {
            bail!(
                "archive for `{name}` is missing: {}",
                archive_path.display()
            );
        }
        let source = PathBuf::from(&row.source_path);
        let target = source
            .parent()
            .with_context(|| format!("skill `{name}` source path has no package"))?
            .to_path_buf();
        if target.exists() {
            bail!("cannot restore `{name}` over existing {}", target.display());
        }
        let parent = target.parent().context("restore target has no parent")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        std::fs::rename(&archive_path, &target).with_context(|| {
            format!(
                "restoring archived skill from {} to {}",
                archive_path.display(),
                target.display()
            )
        })?;
        self.db
            .set_skill_usage_state(name, SkillUsageState::Active, None, None, self.clock.now())
    }

    pub fn snapshot(&self, reason: &str) -> Result<CuratorSnapshotStatus> {
        let now = self.clock.now();
        let id = format!("{now}-{}", uuid::Uuid::new_v4());
        let dir = snapshot_root(&self.db, &self.cwd).join(&id);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let ledger = serde_json::to_vec_pretty(&self.db.list_skill_usage()?)?;
        std::fs::write(dir.join(SNAPSHOT_LEDGER_FILE), ledger)
            .with_context(|| format!("writing {}", dir.join(SNAPSHOT_LEDGER_FILE).display()))?;
        for root in super::resolve_scan_dirs(&self.cwd, &self.config) {
            if !root.exists() {
                continue;
            }
            let root_name = stable_root_name(&root);
            copy_dir_recursive(&root, &dir.join(root_name))?;
        }
        self.db
            .insert_skill_curator_snapshot(&id, &dir.display().to_string(), reason, now)?;
        self.enforce_snapshot_retention()?;
        Ok(CuratorSnapshotStatus {
            id,
            path: dir.display().to_string(),
            reason: reason.to_string(),
            created_at: now,
        })
    }

    pub fn snapshots(&self) -> Result<Vec<CuratorSnapshotStatus>> {
        Ok(self
            .db
            .list_skill_curator_snapshots()?
            .into_iter()
            .map(CuratorSnapshotStatus::from)
            .collect())
    }

    pub fn rollback(&self, id: Option<&str>) -> Result<CuratorSnapshotStatus> {
        let before = self.snapshot("rollback-before")?;
        let snapshots = self.db.list_skill_curator_snapshots()?;
        let target = match id {
            Some(id) => snapshots
                .into_iter()
                .find(|snapshot| snapshot.id == id)
                .with_context(|| format!("snapshot `{id}` not found"))?,
            None => snapshots
                .into_iter()
                .find(|snapshot| snapshot.id != before.id)
                .context("no previous skill curator snapshot to roll back to")?,
        };
        restore_snapshot_to_roots(Path::new(&target.path), &self.cwd, &self.config)?;
        if !restore_snapshot_ledger(&self.db, Path::new(&target.path))? {
            self.sync_discovered()?;
        }
        Ok(CuratorSnapshotStatus::from(target))
    }

    fn sync_discovered(&self) -> Result<()> {
        let now = self.clock.now();
        for discovered in self.discovered_with_metadata()? {
            self.db.ensure_skill_usage(discovered.seed, now)?;
        }
        Ok(())
    }

    fn discovered_with_metadata(&self) -> Result<Vec<DiscoveredSkill>> {
        super::discover(&self.cwd, &self.config)?
            .into_iter()
            .map(|skill| {
                let metadata = lifecycle_metadata_for_skill(&skill)?;
                let seed = usage_seed_for_skill(&skill)?;
                Ok(DiscoveredSkill {
                    name: skill.frontmatter.name,
                    seed,
                    metadata,
                })
            })
            .collect()
    }

    fn archive_skill(&self, row: &SkillUsageRow, now: i64) -> Result<PathBuf> {
        let source = PathBuf::from(&row.source_path);
        let package = source.parent().context("skill source has no package")?;
        if !package.join("SKILL.md").is_file() {
            bail!("skill package for `{}` is missing", row.name);
        }
        let parent = package.parent().context("skill package has no parent")?;
        let archive_dir = parent.join(".cockpit-skill-archive");
        std::fs::create_dir_all(&archive_dir)
            .with_context(|| format!("creating {}", archive_dir.display()))?;
        let target = archive_dir.join(format!("{}-{now}", row.name));
        std::fs::rename(package, &target).with_context(|| {
            format!(
                "archiving skill `{}` from {} to {}",
                row.name,
                package.display(),
                target.display()
            )
        })?;
        Ok(target)
    }

    fn enforce_snapshot_retention(&self) -> Result<()> {
        let snapshots = self.db.list_skill_curator_snapshots()?;
        if snapshots.len() <= SNAPSHOT_RETENTION {
            return Ok(());
        }
        let stale: Vec<SkillCuratorSnapshotRow> =
            snapshots.into_iter().skip(SNAPSHOT_RETENTION).collect();
        for snapshot in &stale {
            let path = PathBuf::from(&snapshot.path);
            if path.exists() {
                std::fs::remove_dir_all(&path)
                    .with_context(|| format!("removing old snapshot {}", path.display()))?;
            }
        }
        self.db
            .delete_skill_curator_snapshot_rows(stale.into_iter().map(|s| s.id).collect())
    }
}

struct DiscoveredSkill {
    name: String,
    seed: crate::db::skill_usage::SkillUsageSeed,
    metadata: SkillLifecycleMetadata,
}

enum Transition {
    None,
    Stale,
    Archive,
    Reactivate,
    Skip(&'static str),
}

fn transition_for(
    row: &SkillUsageRow,
    discovered: &DiscoveredSkill,
    cron_refs: &HashSet<String>,
    prune_builtins: bool,
    now: i64,
) -> Transition {
    if row.pinned || discovered.metadata.pinned {
        return Transition::Skip("pinned");
    }
    if row.created_by != SkillCreatedBy::Background {
        return Transition::Skip("foreground");
    }
    if cron_refs.contains(&row.name) {
        return Transition::Skip("cron");
    }
    if discovered.metadata.protected && !prune_builtins {
        return Transition::Skip("protected");
    }

    let anchor = row.last_used_at.unwrap_or(row.created_at);
    let age = now.saturating_sub(anchor);
    if row.use_count == 0 && age < STALE_AFTER_SECONDS {
        return Transition::None;
    }
    if age > ARCHIVE_AFTER_SECONDS {
        Transition::Archive
    } else if age > STALE_AFTER_SECONDS {
        Transition::Stale
    } else if row.state != SkillUsageState::Active {
        Transition::Reactivate
    } else {
        Transition::None
    }
}

fn cron_referenced_skills(db: &Db) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    for job in db.list_scheduled_jobs(None)? {
        let schedule: serde_json::Value = serde_json::from_str(&job.schedule_json)
            .with_context(|| format!("decoding schedule for `{}`", job.id))?;
        if schedule.get("type").and_then(|v| v.as_str()) != Some("cron") {
            continue;
        }
        let payload: serde_json::Value = serde_json::from_str(&job.payload_json)
            .with_context(|| format!("decoding payload for `{}`", job.id))?;
        collect_skill_references(&payload, &mut out);
    }
    Ok(out)
}

fn collect_skill_references(value: &serde_json::Value, out: &mut HashSet<String>) {
    match value {
        serde_json::Value::String(s) => {
            for token in s.split(|ch: char| !matches!(ch, 'a'..='z' | '0'..='9' | '.' | '_' | '-'))
            {
                if super::managed_skill_name_valid(token) {
                    out.insert(token.to_string());
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_skill_references(value, out);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values() {
                collect_skill_references(value, out);
            }
        }
        _ => {}
    }
}

fn consolidation_prompt(db: &Db) -> Result<String> {
    let skills = db
        .list_skill_usage()?
        .into_iter()
        .filter(|row| row.created_by == SkillCreatedBy::Background && !row.pinned)
        .map(|row| format!("- {} ({})", row.name, row.state.as_str()))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        "LLM consolidation is enabled. Run a caged recursive subagent with `task` from the \
         with_recursive_subagents path, allowing only `skill` and `skill_manage`. Any delete \
         must carry absorbed_into=<existing umbrella>; bare deletes fail closed.\n\n{skills}"
    ))
}

pub fn register_scheduler(
    handle: &crate::daemon::scheduler::DaemonSchedulerHandle,
    db: Db,
) -> Result<()> {
    let db_for_callback = db.clone();
    handle.register_callback(CURATOR_SUBSYSTEM, move |_job| {
        let db = db_for_callback.clone();
        async move {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let cfg = crate::config::extended::load_for_cwd(&cwd).skills;
            let report = SkillCurator::new(db, cwd, cfg).run(CuratorRunOptions::default())?;
            Ok(report.summary())
        }
    })?;
    ensure_default_job(handle, &db)
}

pub fn ensure_default_job(
    handle: &crate::daemon::scheduler::DaemonSchedulerHandle,
    db: &Db,
) -> Result<()> {
    if handle
        .list_jobs(Some(CURATOR_OWNER))?
        .into_iter()
        .any(|job| job.id == CURATOR_JOB_ID)
    {
        return Ok(());
    }
    handle.create_job(ScheduledJobCreate {
        id: CURATOR_JOB_ID.to_string(),
        owner: CURATOR_OWNER.to_string(),
        schedule: ScheduledJobSchedule::Idle {
            min_idle_seconds: CURATOR_MIN_IDLE_SECONDS,
            max_age_seconds: CURATOR_INTERVAL_SECONDS,
        },
        payload: ScheduledJobPayload::Callback {
            subsystem: CURATOR_SUBSYSTEM.to_string(),
        },
        enabled: true,
        missed_run_policy: MissedRunPolicy::Skip,
    })?;
    let now = chrono::Utc::now().timestamp();
    db.update_scheduled_job_next_run(
        CURATOR_JOB_ID,
        Some(now.saturating_add(CURATOR_INTERVAL_SECONDS as i64)),
        now,
    )?;
    Ok(())
}

fn snapshot_root(db: &Db, cwd: &Path) -> PathBuf {
    db.path()
        .and_then(Path::parent)
        .map(|dir| dir.join("skill-curator").join("snapshots"))
        .unwrap_or_else(|| cwd.join(".cockpit").join("skill-curator").join("snapshots"))
}

fn stable_root_name(root: &Path) -> String {
    let mut hash = 1469598103934665603_u64;
    for byte in root.display().to_string().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(1099511628211);
    }
    format!("root-{hash:016x}")
}

fn copy_dir_recursive(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to).with_context(|| format!("creating {}", to.display()))?;
    for entry in std::fs::read_dir(from).with_context(|| format!("reading {}", from.display()))? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            copy_dir_recursive(&src, &dst)?;
        } else if file_type.is_file() {
            std::fs::copy(&src, &dst)
                .with_context(|| format!("copying {} to {}", src.display(), dst.display()))?;
        }
    }
    Ok(())
}

fn restore_snapshot_to_roots(snapshot: &Path, cwd: &Path, cfg: &SkillsConfig) -> Result<()> {
    let roots = super::resolve_scan_dirs(cwd, cfg);
    for root in roots {
        let src = snapshot.join(stable_root_name(&root));
        if !src.exists() {
            continue;
        }
        if root.exists() {
            std::fs::remove_dir_all(&root)
                .with_context(|| format!("clearing skill root {}", root.display()))?;
        }
        copy_dir_recursive(&src, &root)?;
    }
    Ok(())
}

fn restore_snapshot_ledger(db: &Db, snapshot: &Path) -> Result<bool> {
    let ledger = snapshot.join(SNAPSHOT_LEDGER_FILE);
    if !ledger.is_file() {
        return Ok(false);
    }
    let rows: Vec<SkillUsageRow> = serde_json::from_slice(
        &std::fs::read(&ledger).with_context(|| format!("reading {}", ledger.display()))?,
    )
    .with_context(|| format!("parsing {}", ledger.display()))?;
    db.restore_skill_usage_rows(rows)?;
    Ok(true)
}

impl From<SkillUsageRow> for CuratorSkillStatus {
    fn from(row: SkillUsageRow) -> Self {
        Self {
            name: row.name,
            state: row.state.as_str().to_string(),
            created_by: row.created_by.as_str().to_string(),
            use_count: row.use_count,
            view_count: row.view_count,
            pinned: row.pinned,
            source_path: row.source_path,
            archive_path: row.archive_path,
        }
    }
}

impl From<SkillCuratorSnapshotRow> for CuratorSnapshotStatus {
    fn from(row: SkillCuratorSnapshotRow) -> Self {
        Self {
            id: row.id,
            path: row.path,
            reason: row.reason,
            created_at: row.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use super::*;
    use crate::db::skill_usage::SkillUsageSeed;

    #[derive(Debug)]
    struct FixedClock(AtomicI64);

    impl FixedClock {
        fn new(now: i64) -> Arc<Self> {
            Arc::new(Self(AtomicI64::new(now)))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl CuratorClock for FixedClock {
        fn now(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn cfg(root: &Path) -> SkillsConfig {
        SkillsConfig {
            scan_dirs: vec![root.display().to_string()],
            ancestor_walk: false,
            ..Default::default()
        }
    }

    fn write_skill(root: &Path, name: &str, origin: &str, created_at: i64) {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: test skill\n---\n\nUse it.\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join(".cockpit-provenance.json"),
            format!(
                r#"{{
  "created_origin": "{origin}",
  "writes": [{{"action":"create","origin":"{origin}","unix_seconds":{created_at}}}],
  "pinned": false
}}"#
            ),
        )
        .unwrap();
    }

    fn curator(
        db: Db,
        cwd: &Path,
        cfg: SkillsConfig,
        clock: Arc<dyn CuratorClock>,
    ) -> SkillCurator {
        SkillCurator::with_clock(db, cwd.to_path_buf(), cfg, clock)
    }

    #[test]
    fn curator_transitions_matrix() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let now = 10_000_000;
        write_skill(&root, "fresh", "background_review", now - 10);
        write_skill(
            &root,
            "old-stale",
            "background_review",
            now - STALE_AFTER_SECONDS - 1,
        );
        write_skill(
            &root,
            "old-archive",
            "background_review",
            now - ARCHIVE_AFTER_SECONDS - 1,
        );
        write_skill(
            &root,
            "foreground",
            "foreground",
            now - ARCHIVE_AFTER_SECONDS - 1,
        );
        write_skill(
            &root,
            "pinned",
            "background_review",
            now - ARCHIVE_AFTER_SECONDS - 1,
        );
        write_skill(
            &root,
            "cron-ref",
            "background_review",
            now - ARCHIVE_AFTER_SECONDS - 1,
        );

        let db = Db::open_in_memory().unwrap();
        db.insert_scheduled_job(crate::db::scheduler::NewScheduledJobRow {
            id: "cron".into(),
            owner: "system:test".into(),
            schedule_json: serde_json::to_string(&ScheduledJobSchedule::Cron {
                expr: "0 0 * * *".into(),
            })
            .unwrap(),
            payload_json: serde_json::json!({"prompt": "/skill cron-ref"}).to_string(),
            enabled: true,
            missed_run_policy: "skip".into(),
            created_at: now,
            updated_at: now,
            next_run_at: Some(now + 60),
        })
        .unwrap();
        let clock = FixedClock::new(now);
        let c = curator(db.clone(), tmp.path(), cfg(&root), clock.clone());
        c.status().unwrap();
        db.set_skill_usage_pinned("pinned", true, now).unwrap();
        let report = c
            .run(CuratorRunOptions {
                dry_run: false,
                consolidate: false,
            })
            .unwrap();

        assert!(report.stale.contains(&"old-stale".to_string()));
        assert!(report.archived.contains(&"old-archive".to_string()));
        assert!(
            root.join(".cockpit-skill-archive")
                .join(format!("old-archive-{now}"))
                .exists()
        );
        for skipped in ["foreground:foreground", "pinned:pinned", "cron-ref:cron"] {
            assert!(report.skipped.contains(&skipped.to_string()), "{report:?}");
        }
        assert_eq!(
            db.get_skill_usage("fresh").unwrap().unwrap().state,
            SkillUsageState::Active
        );
        assert_eq!(
            db.get_skill_usage("old-stale").unwrap().unwrap().state,
            SkillUsageState::Stale
        );
        assert_eq!(
            db.get_skill_usage("old-archive").unwrap().unwrap().state,
            SkillUsageState::Archived
        );

        clock.set(now + 1);
        let seed = SkillUsageSeed {
            name: "old-stale".into(),
            source_path: root.join("old-stale/SKILL.md").display().to_string(),
            created_by: SkillCreatedBy::Background,
            created_at: now - STALE_AFTER_SECONDS - 1,
            pinned: false,
        };
        db.record_skill_use(seed, true, now + 1).unwrap();
        db.set_skill_usage_state("old-stale", SkillUsageState::Stale, None, None, now + 1)
            .unwrap();
        let report = c.run(CuratorRunOptions::default()).unwrap();
        assert!(report.reactivated.contains(&"old-stale".to_string()));
        assert_eq!(
            db.get_skill_usage("old-stale").unwrap().unwrap().state,
            SkillUsageState::Active
        );
    }

    #[tokio::test]
    async fn curator_first_run_defers() {
        let db = Db::open_in_memory().unwrap();
        let registry = crate::daemon::registry::SessionRegistry::new(
            db.clone(),
            Arc::new(crate::locks::LockManager::from_db(db.clone()).unwrap()),
            crate::daemon::shutdown::ShutdownSignal::new(),
            None,
            crate::daemon::config_source::ConfigSource::production(),
        );
        let executor = Arc::new(crate::daemon::scheduler::ProductionJobExecutor::new(
            db.clone(),
            registry,
        ));
        let scheduler = Arc::new(crate::daemon::scheduler::DaemonScheduler::new(
            db.clone(),
            Arc::new(crate::daemon::scheduler::SystemClock),
            executor.clone(),
        ));
        let handle = scheduler.start_with_sleeper(
            crate::daemon::shutdown::ShutdownSignal::new(),
            Arc::new(crate::daemon::scheduler::TokioSchedulerSleeper),
            Some(executor.callback_registry()),
        );

        ensure_default_job(&handle, &db).unwrap();

        let job = handle
            .list_jobs(Some(CURATOR_OWNER))
            .unwrap()
            .into_iter()
            .find(|job| job.id == CURATOR_JOB_ID)
            .unwrap();
        assert!(job.next_run_at.unwrap() - chrono::Utc::now().timestamp() > 6 * 24 * 60 * 60);
    }

    #[test]
    fn curator_never_deletes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let now = 10_000_000;
        write_skill(
            &root,
            "archive-me",
            "background_review",
            now - ARCHIVE_AFTER_SECONDS - 1,
        );
        let db = Db::open_in_memory().unwrap();
        let c = curator(db, tmp.path(), cfg(&root), FixedClock::new(now));

        c.run(CuratorRunOptions::default()).unwrap();

        assert!(!root.join("archive-me").exists());
        assert!(
            root.join(".cockpit-skill-archive/archive-me-10000000/SKILL.md")
                .is_file()
        );
    }

    #[test]
    fn curator_snapshot_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let now = 10_000_000;
        write_skill(&root, "keep", "background_review", now);
        let db = Db::open_in_memory().unwrap();
        let clock = FixedClock::new(now);
        let c = curator(db.clone(), tmp.path(), cfg(&root), clock.clone());
        c.status().unwrap();
        let snap = c.snapshot("manual").unwrap();
        std::fs::write(root.join("keep/SKILL.md"), "changed").unwrap();
        db.set_skill_usage_state(
            "keep",
            SkillUsageState::Archived,
            Some("/tmp/archive/keep".to_string()),
            Some(now + 1),
            now + 1,
        )
        .unwrap();
        clock.set(now + 1);

        let restored = c.rollback(Some(&snap.id)).unwrap();

        assert_eq!(restored.id, snap.id);
        let body = std::fs::read_to_string(root.join("keep/SKILL.md")).unwrap();
        assert!(body.contains("description: test skill"));
        assert_eq!(
            db.get_skill_usage("keep").unwrap().unwrap().state,
            SkillUsageState::Active
        );
        assert!(
            c.snapshots()
                .unwrap()
                .iter()
                .any(|s| s.reason == "rollback-before")
        );
    }
}
