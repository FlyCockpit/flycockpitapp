use std::collections::HashSet;
#[cfg(test)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};

use super::{
    Skill, SkillFrontmatter, find_by_name, managed_skill_name_valid,
    validate_managed_skill_contents,
};
use crate::config::extended::SkillsConfig;
use crate::db::skill_usage::{SkillCreatedBy, SkillUsageSeed};

const PROVENANCE_FILE: &str = ".cockpit-provenance.json";
pub use crate::db::needs_attention::InterruptCallOrigin as SkillWriteOrigin;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillManageAction {
    Create,
    Delete,
    RemoveFile,
}

impl SkillManageAction {
    pub const ALL: [Self; 3] = [Self::Create, Self::Delete, Self::RemoveFile];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Delete => "delete",
            Self::RemoveFile => "remove_file",
        }
    }
}

impl Serialize for SkillManageAction {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SkillManageAction {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "create" => Ok(Self::Create),
            "delete" => Ok(Self::Delete),
            "remove_file" => Ok(Self::RemoveFile),
            "patch" | "edit" | "write_file" => Err(serde::de::Error::custom(format!(
                "skill_manage `{value}` is retired; load the skill with `skill`, then use `read` plus `edit` or `write` on the package file instead"
            ))),
            _ => Err(serde::de::Error::custom(format!(
                "unknown skill_manage action `{value}`; expected one of: {}",
                SkillManageAction::ALL
                    .into_iter()
                    .map(SkillManageAction::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SkillManageArgs {
    pub action: SkillManageAction,
    pub name: String,
    pub description: Option<String>,
    pub content: Option<String>,
    pub category: Option<String>,
    pub root: Option<String>,
    pub path: Option<String>,
    pub absorbed_into: Option<String>,
}

impl SkillManageArgs {
    fn empty(action: SkillManageAction, name: String) -> Self {
        Self {
            action,
            name,
            description: None,
            content: None,
            category: None,
            root: None,
            path: None,
            absorbed_into: None,
        }
    }

    fn params_value(&self) -> Value {
        match self.action {
            SkillManageAction::Create => {
                let mut params = serde_json::Map::new();
                if let Some(description) = &self.description {
                    params.insert("description".to_string(), json!(description));
                }
                if let Some(content) = &self.content {
                    params.insert("content".to_string(), json!(content));
                }
                if let Some(category) = &self.category {
                    params.insert("category".to_string(), json!(category));
                }
                if let Some(root) = &self.root {
                    params.insert("root".to_string(), json!(root));
                }
                Value::Object(params)
            }
            SkillManageAction::Delete => {
                let mut params = serde_json::Map::new();
                if let Some(absorbed_into) = &self.absorbed_into {
                    params.insert("absorbed_into".to_string(), json!(absorbed_into));
                }
                Value::Object(params)
            }
            SkillManageAction::RemoveFile => {
                let mut params = serde_json::Map::new();
                if let Some(path) = &self.path {
                    params.insert("path".to_string(), json!(path));
                }
                Value::Object(params)
            }
        }
    }
}

impl Serialize for SkillManageArgs {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SkillManageArgs", 3)?;
        state.serialize_field("action", &self.action)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("params", &self.params_value())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SkillManageArgs {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireArgs {
            action: SkillManageAction,
            name: String,
            params: Value,
        }

        let wire = WireArgs::deserialize(deserializer)?;
        let action = wire.action;
        let mut args = SkillManageArgs::empty(action, wire.name);
        match action {
            SkillManageAction::Create => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Params {
                    description: String,
                    content: String,
                    #[serde(default)]
                    category: Option<String>,
                    #[serde(default)]
                    root: Option<String>,
                }
                let params: Params =
                    params_for_action(action, wire.params).map_err(serde::de::Error::custom)?;
                args.description = Some(params.description);
                args.content = Some(params.content);
                args.category = params.category;
                args.root = params.root;
            }
            SkillManageAction::Delete => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Params {
                    absorbed_into: String,
                }
                let params: Params =
                    params_for_action(action, wire.params).map_err(serde::de::Error::custom)?;
                args.absorbed_into = Some(params.absorbed_into);
            }
            SkillManageAction::RemoveFile => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Params {
                    path: String,
                }
                let params: Params =
                    params_for_action(action, wire.params).map_err(serde::de::Error::custom)?;
                args.path = Some(params.path);
            }
        }
        Ok(args)
    }
}

fn params_for_action<T: serde::de::DeserializeOwned>(
    action: SkillManageAction,
    value: Value,
) -> std::result::Result<T, String> {
    serde_json::from_value(value)
        .map_err(|error| format!("skill_manage `{}` params: {error}", action.as_str()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillMutationResult {
    pub changed: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SkillProvenance {
    created_origin: SkillWriteOrigin,
    #[serde(default)]
    writes: Vec<SkillProvenanceWrite>,
    #[serde(default)]
    pinned: bool,
    #[serde(default)]
    protection: Option<SkillProtection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SkillProvenanceWrite {
    action: SkillManageAction,
    origin: SkillWriteOrigin,
    unix_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SkillProtection {
    Bundled,
    HubInstalled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkillLifecycleMetadata {
    pub created_by: SkillCreatedBy,
    pub pinned: bool,
    pub protected: bool,
    pub created_at: i64,
}

pub struct SkillMutationService<'a> {
    cwd: &'a Path,
    config: &'a SkillsConfig,
    origin: SkillWriteOrigin,
    db: Option<&'a crate::db::Db>,
}

/// A fully checked but not-yet-mutated skill operation.  Construction may do
/// durable/read-only preflight (notably the delete pin lookup); execution is
/// intentionally synchronous so an approval effect claim is adjacent to the
/// first irreversible filesystem mutation.
#[derive(Debug)]
pub(crate) enum PreparedSkillMutation {
    Create(PreparedCreate),
    Delete(PreparedDelete),
    RemoveFile(PreparedRemoveFile),
}

#[derive(Debug)]
pub(crate) struct PreparedCreate {
    name: String,
    root: PreparedSkillRoot,
    category: Option<String>,
    manifest: Vec<u8>,
    provenance: Vec<u8>,
    usage_seed: SkillUsageSeed,
}

#[derive(Debug)]
pub(crate) struct PreparedDelete {
    name: String,
    absorbed_into: String,
    target: ManagedTarget,
    tombstone: String,
}

#[derive(Debug)]
pub(crate) struct PreparedRemoveFile {
    name: String,
    target: ManagedTarget,
    relative: PathBuf,
    parent: PreparedSupportParent,
    leaf: String,
    staged: String,
    provenance: Vec<u8>,
    usage_seed: SkillUsageSeed,
}

/// The operational authority for a prepared skill mutation.  The diagnostic
/// path is used only for the native-approval record and errors; final writes
/// use a held directory descriptor (on Unix) and never resolve this path
/// again.  That distinction is deliberate: a symlink or ancestor replacement
/// while an approval is parked must not redirect the later effect.
#[derive(Debug)]
struct PreparedSkillRoot {
    diagnostic_path: PathBuf,
    #[cfg(unix)]
    capability: UnixPreparedSkillRoot,
}

/// A direct parent descriptor for a support-file mutation.  It is captured
/// while the package is known-good, so a later replacement of `references/`
/// (or any other support ancestor) cannot alter where staging or unlinking
/// occurs.
#[derive(Debug)]
struct PreparedSupportParent {
    #[cfg(unix)]
    directory: std::fs::File,
    #[cfg(unix)]
    bindings: Vec<UnixDirectoryBinding>,
}

impl<'a> SkillMutationService<'a> {
    pub fn new(cwd: &'a Path, config: &'a SkillsConfig) -> Self {
        Self {
            cwd,
            config,
            origin: SkillWriteOrigin::Foreground,
            db: None,
        }
    }

    pub fn with_origin(mut self, origin: SkillWriteOrigin) -> Self {
        self.origin = origin;
        self
    }

    pub fn with_db(mut self, db: &'a crate::db::Db) -> Self {
        self.db = Some(db);
        self
    }

    /// Every configured directory that an operation preflight can inspect.
    ///
    /// `skill_manage` has to discover package metadata before it can build a
    /// typed mutation plan.  Keep this projection separate from
    /// [`Self::writable_roots`]: `external_dirs` are read-only as mutation
    /// destinations, but discovery still traverses them and therefore still
    /// needs native read authority when they lie outside the session boundary.
    /// The tool layer turns these into syscall-effective paths and applies the
    /// native-access fence immediately before calling [`Self::prepare`].
    pub(crate) fn preflight_scan_roots(&self) -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        super::resolve_scan_dirs(self.cwd, self.config)
            .into_iter()
            .filter(|path| seen.insert(lexical_normalize(path)))
            .collect()
    }

    /// Perform every fallible validation and every async/durable preflight
    /// before an approval is requested.  The caller must execute the returned
    /// plan through [`Self::apply_prepared`] immediately after its exact host
    /// effect fence.
    pub(crate) async fn prepare(&self, args: &SkillManageArgs) -> Result<PreparedSkillMutation> {
        if args.name != args.name.trim() || !managed_skill_name_valid(&args.name) {
            bail!("skill name must match ^[a-z0-9][a-z0-9._-]*$ and contain at most 64 characters");
        }
        match args.action {
            SkillManageAction::Create => self.prepare_create(args),
            SkillManageAction::Delete => self.prepare_delete(args).await,
            SkillManageAction::RemoveFile => self.prepare_remove_file(args),
        }
    }

    /// Execute a prepared mutation without awaiting.  Do not make this async:
    /// callers rely on that type-level boundary to ensure a cancellation or
    /// revision cannot win after an approved effect is claimed but before the
    /// selected filesystem mutation begins.
    pub(crate) fn apply_prepared(
        &self,
        prepared: &PreparedSkillMutation,
    ) -> Result<SkillMutationResult> {
        let result = match prepared {
            PreparedSkillMutation::Create(prepared) => self.create_prepared(prepared),
            PreparedSkillMutation::Delete(prepared) => self.delete_prepared(prepared),
            PreparedSkillMutation::RemoveFile(prepared) => self.remove_file_prepared(prepared),
        }?;
        if result.changed {
            super::invalidate_catalog_cache(self.cwd, self.config);
        }
        Ok(result)
    }

    /// The configured writable root that owns every synchronous mutation in a
    /// prepared plan.  The caller claims a `ReadWrite` native access grant for
    /// this exact root together with the `skill_manage_mutation` capability,
    /// then calls [`Self::apply_prepared`] without awaiting.  A root-level
    /// grant deliberately covers the staging sibling and provenance file as
    /// well as the named package, all of which are inside this configured
    /// root and can be touched by one atomic lifecycle operation.
    pub(crate) fn prepared_mutation_root<'b>(
        &self,
        prepared: &'b PreparedSkillMutation,
    ) -> &'b Path {
        match prepared {
            PreparedSkillMutation::Create(prepared) => &prepared.root.diagnostic_path,
            PreparedSkillMutation::Delete(prepared) => {
                &prepared.target.writable_root.diagnostic_path
            }
            PreparedSkillMutation::RemoveFile(prepared) => {
                &prepared.target.writable_root.diagnostic_path
            }
        }
    }

    /// Best-effort durable usage bookkeeping happens only after the selected
    /// synchronous mutation is complete.  It is not part of the authorization
    /// window and cannot delay or reopen a destructive filesystem effect.
    pub(crate) async fn record_post_mutation(
        &self,
        prepared: &PreparedSkillMutation,
        result: &SkillMutationResult,
    ) {
        if result.changed {
            if let Err(error) = self.record_usage(prepared).await {
                tracing::warn!(
                    error = %error,
                    action = ?prepared.action(),
                    "skill usage ledger update failed"
                );
            }
        }
    }

    pub async fn apply(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        let prepared = self.prepare(args).await?;
        let result = self.apply_prepared(&prepared)?;
        self.record_post_mutation(&prepared, &result).await;
        Ok(result)
    }

    fn prepare_create(&self, args: &SkillManageArgs) -> Result<PreparedSkillMutation> {
        let description = required(&args.description, "`description` is required for create")?;
        let body = required(&args.content, "`content` is required for create")?;
        let category = args
            .category
            .as_deref()
            .map(validate_category)
            .transpose()?;
        let root = self.select_create_root(args.root.as_deref())?;
        // Match the source spelling emitted by `create_prepared` when this
        // root already exists (including configured symlink aliases), while
        // still allowing a new root to be created after the final ReadWrite
        // capability claim. This probe is part of the read-fenced preflight;
        // post-mutation bookkeeping never rediscovers the catalogue.
        let usage_root = root.canonicalize().unwrap_or_else(|_| root.clone());
        let usage_package = category.as_ref().map_or_else(
            || usage_root.join(&args.name),
            |category| usage_root.join(category).join(&args.name),
        );
        let manifest = format!(
            "---\nname: {}\ndescription: {}\n---\n\n{}\n",
            args.name,
            serde_json::to_string(description.trim())?,
            body.trim_end()
        );
        // Content validation is pure and must finish before approval.  The
        // final capability handoff only opens/creates descriptor-anchored
        // entries; it never discovers or validates user content anew.
        validate_managed_skill_contents(&manifest, &args.name)?;
        let root = PreparedSkillRoot::prepare_for_create(&root)?;
        let provenance =
            provenance_bytes(None, self.origin, SkillManageAction::Create, true, false)?;
        Ok(PreparedSkillMutation::Create(PreparedCreate {
            name: args.name.clone(),
            root,
            category,
            manifest: manifest.into_bytes(),
            provenance,
            // Post-mutation usage bookkeeping must not rediscover the whole
            // configured skill catalogue after the native root capability
            // was consumed. This seed is fully determined by the immutable
            // prepared create plan and the selected write origin.
            usage_seed: SkillUsageSeed {
                name: args.name.clone(),
                source_path: usage_package.join("SKILL.md").display().to_string(),
                created_by: created_by_from_origin(self.origin),
                created_at: chrono::Utc::now().timestamp(),
                pinned: false,
            },
        }))
    }

    fn create_prepared(&self, prepared: &PreparedCreate) -> Result<SkillMutationResult> {
        // `PreparedSkillRoot` owns the root descriptor (or an anchored
        // missing-root plan). From here on, no operation resolves a configured
        // root, category, package, staging path, or manifest through a path.
        // An approval may have waited arbitrarily long; that cannot turn a
        // symlink swap into an out-of-root write.
        prepared.root.create_skill_package(
            &prepared.name,
            prepared.category.as_deref(),
            &prepared.manifest,
            &prepared.provenance,
        )?;
        Ok(changed(format!("Created skill `{}`", prepared.name)))
    }

    async fn prepare_delete(&self, args: &SkillManageArgs) -> Result<PreparedSkillMutation> {
        let target = self.resolve_target(&args.name)?;
        if target.pinned {
            bail!("pinned skill `{}` may not be deleted by tools", args.name);
        }
        let absorbed_into = args
            .absorbed_into
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .context(
                "delete requires `absorbed_into=<existing skill>` for guarded consolidation",
            )?;
        if absorbed_into == args.name {
            bail!("`absorbed_into` must name a different existing umbrella skill");
        }
        let skills = super::discover(self.cwd, self.config)?;
        let umbrella = find_by_name(&skills, absorbed_into)
            .with_context(|| format!("absorbed_into skill `{absorbed_into}` does not exist"))?;
        let umbrella_package = umbrella
            .source
            .parent()
            .context("absorbed_into SKILL.md has no package directory")?;
        if std::fs::symlink_metadata(umbrella_package)?
            .file_type()
            .is_symlink()
        {
            bail!("refusing consolidation into a symlinked skill package");
        }
        if std::fs::symlink_metadata(&target.package)?
            .file_type()
            .is_symlink()
        {
            bail!("refusing to delete a symlinked skill package");
        }
        validate_consolidation_forward(&target.skill, umbrella)?;
        // The actual staging name is intentionally just a one-component
        // descriptor-relative name.  `rename_noreplace` below makes a hostile
        // collision fail rather than overwriting it, so no path probe is left
        // to race an approval wait.
        let tombstone = format!(".{}.delete-{}", args.name, uuid::Uuid::new_v4());
        // Every filesystem read/traversal above is behind the caller's final
        // native read fence. Keep the sole durable await last: returning from
        // it cannot lead to another unchecked probe before the later
        // read-write/mutation fence and synchronous rename.
        if let Some(db) = self.db
            && db
                .get_skill_usage(&args.name)
                .await?
                .is_some_and(|row| row.pinned)
        {
            bail!("pinned skill `{}` may not be deleted by tools", args.name);
        }
        Ok(PreparedSkillMutation::Delete(PreparedDelete {
            name: args.name.clone(),
            absorbed_into: absorbed_into.to_string(),
            target,
            tombstone,
        }))
    }

    fn delete_prepared(&self, prepared: &PreparedDelete) -> Result<SkillMutationResult> {
        prepared.target.delete_package(&prepared.tombstone)?;
        Ok(changed(format!(
            "Deleted skill `{}` after consolidation into `{}`",
            prepared.name, prepared.absorbed_into
        )))
    }

    fn prepare_remove_file(&self, args: &SkillManageArgs) -> Result<PreparedSkillMutation> {
        let target = self.resolve_target(&args.name)?;
        let relative = Path::new(required(&args.path, "`path` is required for remove_file")?);
        let (parent, leaf) = target.prepare_support_file(relative)?;
        let staged = format!(".{}.delete-{}", leaf, uuid::Uuid::new_v4());
        let usage_seed = usage_seed_for_skill(&target.skill)?;
        let provenance = provenance_bytes(
            read_provenance(&target.package)?,
            self.origin,
            SkillManageAction::RemoveFile,
            false,
            target.pinned,
        )?;
        Ok(PreparedSkillMutation::RemoveFile(PreparedRemoveFile {
            name: args.name.clone(),
            target,
            relative: relative.to_path_buf(),
            parent,
            leaf,
            staged,
            provenance,
            usage_seed,
        }))
    }

    fn remove_file_prepared(&self, prepared: &PreparedRemoveFile) -> Result<SkillMutationResult> {
        prepared.target.remove_support_file(
            &prepared.parent,
            &prepared.leaf,
            &prepared.staged,
            &prepared.provenance,
        )?;
        Ok(changed(format!(
            "Removed `{}` from skill `{}`",
            prepared.relative.display(),
            prepared.name
        )))
    }

    fn resolve_target(&self, name: &str) -> Result<ManagedTarget> {
        let skills = super::discover(self.cwd, self.config)?;
        let skill = find_by_name(&skills, name)
            .cloned()
            .with_context(|| format!("unknown skill `{name}`"))?;
        let source = skill
            .source
            .canonicalize()
            .with_context(|| format!("canonicalizing {}", skill.source.display()))?;
        let package = source
            .parent()
            .context("SKILL.md has no package directory")?
            .to_path_buf();
        let writable_root = self
            .writable_roots()
            .into_iter()
            .filter_map(|root| root.canonicalize().ok())
            .find(|root| package.starts_with(root) && package != *root)
            .with_context(|| format!("skill `{name}` is not under a writable skills root"))?;
        if package
            .strip_prefix(&writable_root)
            .ok()
            .is_some_and(|relative| relative.components().any(is_hub_component))
        {
            bail!("hub-installed skill `{name}` is read-only");
        }
        let provenance = read_provenance(&package)?;
        let pinned = provenance.as_ref().is_some_and(|value| value.pinned)
            || frontmatter_flag(&skill.frontmatter, "pinned");
        let protection = provenance.as_ref().and_then(|value| value.protection);
        if let Some(protection) = protection.or_else(|| frontmatter_protection(&skill.frontmatter))
        {
            let kind = match protection {
                SkillProtection::Bundled => "bundled",
                SkillProtection::HubInstalled => "hub-installed",
            };
            bail!("{kind} skill `{name}` is read-only");
        }
        #[cfg(unix)]
        {
            let writable_root = PreparedSkillRoot::open_existing(&writable_root)?;
            let package_parent = writable_root.package_parent(&package)?;
            let package_name = package
                .file_name()
                .context("skill package has no name")?
                .to_os_string();
            // Capture and retain the package descriptor while preflight is still
            // under its native read fence.  The final mutation later compares a
            // freshly no-follow-opened package to this identity before staging;
            // an already-swapped package or symlink is rejected rather than
            // silently receiving a prepared operation.
            let package_directory = open_directory_child(&package_parent, &package_name)
                .with_context(|| format!("opening prepared skill package {}", package.display()))?;
            return Ok(ManagedTarget {
                skill,
                package,
                writable_root,
                pinned,
                package_parent,
                package_name,
                package_directory,
            });
        }
        #[cfg(not(unix))]
        {
            let _ = (skill, package, writable_root, pinned);
            bail!("skill mutations require descriptor-anchored filesystem support on this platform")
        }
    }

    fn select_create_root(&self, requested: Option<&str>) -> Result<PathBuf> {
        let roots = self.writable_roots();
        if roots.is_empty() {
            bail!("no writable skills root is configured in `skills.scan_dirs`");
        }
        let Some(requested) = requested else {
            return Ok(roots[0].clone());
        };
        let requested = expand_path(requested, self.cwd);
        roots
            .into_iter()
            .find(|root| equivalent_path(root, &requested))
            .with_context(|| {
                format!(
                    "requested root `{}` is not a configured writable skills root",
                    requested.display()
                )
            })
    }

    fn writable_roots(&self) -> Vec<PathBuf> {
        let mut config = self.config.clone();
        config.external_dirs.clear();
        let mut seen = HashSet::new();
        super::resolve_scan_dirs(self.cwd, &config)
            .into_iter()
            .filter(|path| seen.insert(lexical_normalize(path)))
            .collect()
    }

    async fn record_usage(&self, prepared: &PreparedSkillMutation) -> Result<()> {
        let Some(db) = self.db else {
            return Ok(());
        };
        let now = chrono::Utc::now().timestamp();
        match prepared {
            PreparedSkillMutation::Create(prepared) => {
                db.ensure_skill_usage(prepared.usage_seed.clone(), now)
                    .await?;
            }
            PreparedSkillMutation::RemoveFile(prepared) => {
                db.record_skill_patch(prepared.usage_seed.clone(), now)
                    .await?;
            }
            PreparedSkillMutation::Delete(_) => {}
        }
        Ok(())
    }
}

impl PreparedSkillMutation {
    const fn action(&self) -> SkillManageAction {
        match self {
            Self::Create(_) => SkillManageAction::Create,
            Self::Delete(_) => SkillManageAction::Delete,
            Self::RemoveFile(_) => SkillManageAction::RemoveFile,
        }
    }
}

impl PreparedSkillRoot {
    /// Build the mutation capability during read-fenced preparation.  Unix
    /// uses an open descriptor rooted at the canonical directory (or a held
    /// nearest-existing ancestor plus missing suffix for a new root).  The
    /// post-approval path is diagnostic-only and is never re-resolved.
    fn prepare_for_create(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            return UnixPreparedSkillRoot::prepare_for_create(path).map(|capability| Self {
                diagnostic_path: capability.diagnostic_path(),
                capability,
            });
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            bail!("skill mutations require descriptor-anchored filesystem support on this platform")
        }
    }

    #[cfg(unix)]
    fn open_existing(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let canonical = path.canonicalize().with_context(|| {
                format!("canonicalizing writable skills root {}", path.display())
            })?;
            let capability = UnixPreparedSkillRoot::open_existing(&canonical)?;
            return Ok(Self {
                diagnostic_path: canonical,
                capability,
            });
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            bail!("skill mutations require descriptor-anchored filesystem support on this platform")
        }
    }

    #[cfg(unix)]
    fn package_parent(&self, package: &Path) -> Result<std::fs::File> {
        let relative = package
            .strip_prefix(&self.diagnostic_path)
            .with_context(|| {
                format!(
                    "skill package {} escapes writable root {}",
                    package.display(),
                    self.diagnostic_path.display()
                )
            })?;
        let parent = relative.parent().context("skill package has no parent")?;
        let root = self.capability.open_existing_root()?;
        open_directory_chain(&root, parent)
    }

    #[cfg(unix)]
    fn create_skill_package(
        &self,
        name: &str,
        category: Option<&str>,
        manifest: &[u8],
        provenance: &[u8],
    ) -> Result<()> {
        let root = self.capability.open_or_create_root()?;
        let parent = match category {
            Some(category) => open_or_create_directory_child(&root, category)
                .with_context(|| format!("creating skill category {category}"))?,
            None => root,
        };
        let package_name = component_cstring(name)?;
        if entry_exists_nofollow(&parent, &package_name)? {
            bail!("skill package already exists: {name}");
        }
        cockpit_host::private_fs::held_fd::mkdirat(parent.as_raw_fd(), &package_name, 0o755)
            .with_context(|| format!("creating skill package {name}"))?;
        let package = cockpit_host::private_fs::held_fd::openat(
            parent.as_raw_fd(),
            &package_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .with_context(|| format!("opening created skill package {name}"))?;
        if let Err(error) = atomic_write_at(&package, "SKILL.md", manifest)
            .and_then(|_| atomic_write_at(&package, PROVENANCE_FILE, provenance))
        {
            let _ = remove_tree_nofollow(&package);
            let _ = cockpit_host::private_fs::held_fd::unlinkat(
                parent.as_raw_fd(),
                &package_name,
                libc::AT_REMOVEDIR,
            );
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(not(unix))]
impl PreparedSkillRoot {
    fn create_skill_package(
        &self,
        _name: &str,
        _category: Option<&str>,
        _manifest: &[u8],
        _provenance: &[u8],
    ) -> Result<()> {
        let _ = self;
        bail!("skill mutations require descriptor-anchored filesystem support on this platform")
    }
}

#[cfg(unix)]
#[derive(Debug)]
enum UnixPreparedSkillRoot {
    Existing {
        root: std::fs::File,
        bindings: Vec<UnixDirectoryBinding>,
        diagnostic_path: PathBuf,
    },
    Missing {
        parent: std::fs::File,
        bindings: Vec<UnixDirectoryBinding>,
        missing_components: Vec<std::ffi::OsString>,
        diagnostic_path: PathBuf,
    },
}

/// Every existing component between `/` and the prepared root.  Retaining the
/// parent and child descriptors lets the final capability prove that the
/// approved root is still published at the same no-follow component chain;
/// replacement with either a symlink or another directory is rejected without
/// re-walking an attacker-controlled path spelling.
#[cfg(unix)]
#[derive(Debug)]
struct UnixDirectoryBinding {
    parent: std::fs::File,
    name: std::ffi::OsString,
    child: std::fs::File,
}

#[cfg(unix)]
impl UnixPreparedSkillRoot {
    fn diagnostic_path(&self) -> PathBuf {
        match self {
            Self::Existing {
                diagnostic_path, ..
            }
            | Self::Missing {
                diagnostic_path, ..
            } => diagnostic_path.clone(),
        }
    }

    fn open_existing(path: &Path) -> Result<Self> {
        let held = open_absolute_directory_nofollow(path)?;
        Ok(Self::Existing {
            root: held.directory,
            bindings: held.bindings,
            diagnostic_path: path.to_path_buf(),
        })
    }

    fn prepare_for_create(path: &Path) -> Result<Self> {
        match path.canonicalize() {
            Ok(canonical) => return Self::open_existing(&canonical),
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error).with_context(|| {
                    format!("canonicalizing writable skills root {}", path.display())
                });
            }
            Err(_) => {}
        }

        let mut cursor = path;
        let mut missing_components = Vec::new();
        loop {
            match std::fs::symlink_metadata(cursor) {
                Ok(_) => {
                    let canonical = cursor.canonicalize().with_context(|| {
                        format!("canonicalizing skills root ancestor {}", cursor.display())
                    })?;
                    let mut diagnostic_path = canonical.clone();
                    for component in missing_components.iter().rev() {
                        diagnostic_path.push(component);
                    }
                    let held = open_absolute_directory_nofollow(&canonical)?;
                    return Ok(Self::Missing {
                        // The parent capability and its publication chain are
                        // preserved below; retain the root descriptor itself
                        // as the direct anchor for missing suffixes.
                        parent: held.directory,
                        bindings: held.bindings,
                        missing_components: missing_components.into_iter().rev().collect(),
                        diagnostic_path,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let name = cursor
                        .file_name()
                        .context("writable skills root has no missing component")?;
                    missing_components.push(name.to_os_string());
                    cursor = cursor
                        .parent()
                        .context("writable skills root has no ancestor")?;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("checking skills root {}", cursor.display()));
                }
            }
        }
    }

    fn open_existing_root(&self) -> Result<std::fs::File> {
        match self {
            Self::Existing { root, bindings, .. } => {
                validate_directory_bindings(bindings)?;
                root.try_clone()
                    .context("cloning held writable skills root descriptor")
            }
            Self::Missing { .. } => bail!("prepared skill root disappeared before package lookup"),
        }
    }

    fn open_or_create_root(&self) -> Result<std::fs::File> {
        match self {
            Self::Existing { root, bindings, .. } => {
                validate_directory_bindings(bindings)?;
                root.try_clone()
                    .context("cloning held writable skills root descriptor")
            }
            Self::Missing {
                parent,
                bindings,
                missing_components,
                ..
            } => {
                validate_directory_bindings(bindings)?;
                let mut current = parent
                    .try_clone()
                    .context("cloning held skills-root ancestor descriptor")?;
                for component in missing_components {
                    current = open_or_create_directory_child_os(&current, component)?;
                }
                Ok(current)
            }
        }
    }
}

#[cfg(unix)]
impl ManagedTarget {
    fn open_verified_package(&self) -> Result<std::fs::File> {
        // Validate the complete root publication chain through held parent and
        // child descriptors before touching the separately-held package
        // parent. This rejects an ancestor/root replacement even though that
        // replacement cannot redirect the descriptor-rooted operation.
        let _root = self.writable_root.capability.open_existing_root()?;
        let current = open_directory_child(&self.package_parent, &self.package_name)
            .with_context(|| format!("opening current skill package {}", self.package.display()))?;
        ensure!(
            same_directory_identity(&current, &self.package_directory)?,
            "skill package changed after preparation; refusing mutation"
        );
        Ok(current)
    }

    fn prepare_support_file(&self, relative: &Path) -> Result<(PreparedSupportParent, String)> {
        super::validate_support_relative(relative)?;
        let package = self.open_verified_package()?;
        let parent = open_directory_chain_with_bindings(
            &package,
            relative.parent().unwrap_or_else(|| Path::new("")),
        )?;
        let leaf = relative
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .context("support file path must end in a UTF-8 file name")?
            .to_owned();
        let leaf_c = component_cstring(&leaf)?;
        let stat = cockpit_host::private_fs::held_fd::fstatat_nofollow(
            parent.directory.as_raw_fd(),
            &leaf_c,
        )
        .with_context(|| format!("checking support file {}", relative.display()))?;
        ensure!(
            stat.st_mode & libc::S_IFMT == libc::S_IFREG,
            "support file must be a regular non-symlink file: {}",
            relative.display()
        );
        Ok((parent, leaf))
    }

    fn delete_package(&self, tombstone: &str) -> Result<()> {
        let package = self.open_verified_package()?;
        let source = component_cstring_os(&self.package_name)?;
        let tombstone = component_cstring(tombstone)?;
        move_noreplace(
            &self.package_parent,
            &source,
            &self.package_parent,
            &tombstone,
        )
        .with_context(|| format!("staging deletion of {}", self.package.display()))?;
        let staged = match open_directory_child_cstr(&self.package_parent, &tombstone) {
            Ok(staged) if same_directory_identity(&staged, &package)? => staged,
            Ok(_) => {
                let _ = move_noreplace(
                    &self.package_parent,
                    &tombstone,
                    &self.package_parent,
                    &source,
                );
                bail!("skill package changed while staging deletion; refusing mutation");
            }
            Err(error) => {
                let _ = move_noreplace(
                    &self.package_parent,
                    &tombstone,
                    &self.package_parent,
                    &source,
                );
                return Err(error).context("opening staged skill package without following links");
            }
        };
        if let Err(error) = remove_tree_nofollow(&staged) {
            let _ = move_noreplace(
                &self.package_parent,
                &tombstone,
                &self.package_parent,
                &source,
            );
            return Err(error).context("removing staged skill package");
        }
        cockpit_host::private_fs::held_fd::unlinkat(
            self.package_parent.as_raw_fd(),
            &tombstone,
            libc::AT_REMOVEDIR,
        )
        .context("removing empty staged skill package")?;
        Ok(())
    }

    fn remove_support_file(
        &self,
        parent: &PreparedSupportParent,
        leaf: &str,
        staged: &str,
        provenance: &[u8],
    ) -> Result<()> {
        // This verifies the package identity from descriptors only.  The held
        // support-parent descriptor below is the actual authority for every
        // rename/unlink, so a later `references` symlink swap cannot redirect
        // either staging or deletion.
        let _package = self.open_verified_package()?;
        validate_directory_bindings(&parent.bindings)?;
        let leaf = component_cstring(leaf)?;
        let staged = component_cstring(staged)?;
        let stat = cockpit_host::private_fs::held_fd::fstatat_nofollow(
            parent.directory.as_raw_fd(),
            &leaf,
        )
        .context("checking prepared support file before staging")?;
        ensure!(
            stat.st_mode & libc::S_IFMT == libc::S_IFREG,
            "support file changed after preparation; refusing mutation"
        );
        move_noreplace(&parent.directory, &leaf, &parent.directory, &staged)
            .context("staging support-file removal")?;
        let staged_stat = cockpit_host::private_fs::held_fd::fstatat_nofollow(
            parent.directory.as_raw_fd(),
            &staged,
        )
        .context("checking staged support file")?;
        if staged_stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            let _ = move_noreplace(&parent.directory, &staged, &parent.directory, &leaf);
            bail!("support file changed while staging; refusing mutation");
        }
        if let Err(error) =
            cockpit_host::private_fs::held_fd::unlinkat(parent.directory.as_raw_fd(), &staged, 0)
        {
            let _ = move_noreplace(&parent.directory, &staged, &parent.directory, &leaf);
            return Err(error).context("removing staged support file");
        }
        atomic_write_at(&self.package_directory, PROVENANCE_FILE, provenance)
    }
}

#[cfg(not(unix))]
impl ManagedTarget {
    fn prepare_support_file(&self, _relative: &Path) -> Result<(PreparedSupportParent, String)> {
        bail!("skill mutations require descriptor-anchored filesystem support on this platform")
    }

    fn delete_package(&self, _tombstone: &str) -> Result<()> {
        bail!("skill mutations require descriptor-anchored filesystem support on this platform")
    }

    fn remove_support_file(
        &self,
        _parent: &PreparedSupportParent,
        _leaf: &str,
        _staged: &str,
        _provenance: &[u8],
    ) -> Result<()> {
        bail!("skill mutations require descriptor-anchored filesystem support on this platform")
    }
}

/// Materialize provenance before approval so post-claim mutation never reads
/// package paths again.  The resulting bytes are written through the held
/// package descriptor only.
fn provenance_bytes(
    prior: Option<SkillProvenance>,
    origin: SkillWriteOrigin,
    action: SkillManageAction,
    created: bool,
    preserve_pinned: bool,
) -> Result<Vec<u8>> {
    let mut provenance = prior.unwrap_or(SkillProvenance {
        created_origin: if created {
            origin
        } else {
            SkillWriteOrigin::Foreground
        },
        writes: Vec::new(),
        pinned: preserve_pinned,
        protection: None,
    });
    if created {
        provenance.created_origin = origin;
    }
    provenance.pinned |= preserve_pinned;
    provenance.writes.push(SkillProvenanceWrite {
        action,
        origin,
        unix_seconds: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });
    let mut bytes = serde_json::to_vec_pretty(&provenance)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// The Unix implementation is intentionally small and local to managed skills:
// it carries no ownership/permission policy, only the descriptor-rooted
// containment guarantee.  Raw syscalls themselves remain centralized in
// `private_fs::held_fd`.
#[cfg(unix)]
fn component_cstring(name: &str) -> Result<std::ffi::CString> {
    component_cstring_os(std::ffi::OsStr::new(name))
}

#[cfg(unix)]
fn component_cstring_os(name: &std::ffi::OsStr) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt as _;

    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.as_bytes().contains(&b'/'),
        "skill filesystem component is unsafe"
    );
    std::ffi::CString::new(name.as_bytes()).context("skill filesystem component contains NUL")
}

#[cfg(unix)]
#[derive(Debug)]
struct HeldDirectoryPath {
    directory: std::fs::File,
    bindings: Vec<UnixDirectoryBinding>,
}

#[cfg(unix)]
fn open_absolute_directory_nofollow(path: &Path) -> Result<HeldDirectoryPath> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStringExt as _;

    ensure!(path.is_absolute(), "skills root must be absolute");
    let mut current = cockpit_host::private_fs::held_fd::open_fs_root()
        .context("opening filesystem root for skill mutation")?;
    let mut bindings = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                let name = component_cstring_os(name)?;
                let child = cockpit_host::private_fs::held_fd::openat(
                    current.as_raw_fd(),
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
                .with_context(|| format!("opening skills-root component {:?}", name))?;
                bindings.push(UnixDirectoryBinding {
                    parent: current
                        .try_clone()
                        .context("cloning held skills-root parent descriptor")?,
                    name: std::ffi::OsString::from_vec(name.into_bytes()),
                    child: child
                        .try_clone()
                        .context("cloning held skills-root child descriptor")?,
                });
                current = child;
            }
            Component::ParentDir | Component::Prefix(_) => {
                bail!("skills root contains an unsafe path component")
            }
        }
    }
    Ok(HeldDirectoryPath {
        directory: current,
        bindings,
    })
}

#[cfg(unix)]
fn open_directory_chain(root: &std::fs::File, relative: &Path) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd as _;

    let mut current = root
        .try_clone()
        .context("cloning held skill-directory descriptor")?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::CurDir) {
                continue;
            }
            bail!("skill support path may not contain traversal components");
        };
        let name = component_cstring_os(name)?;
        current = cockpit_host::private_fs::held_fd::openat(
            current.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .with_context(|| format!("opening skill directory component {:?}", name))?;
    }
    Ok(current)
}

#[cfg(unix)]
fn open_directory_chain_with_bindings(
    root: &std::fs::File,
    relative: &Path,
) -> Result<PreparedSupportParent> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStringExt as _;

    let mut current = root
        .try_clone()
        .context("cloning held skill-package descriptor")?;
    let mut bindings = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::CurDir) {
                continue;
            }
            bail!("skill support path may not contain traversal components");
        };
        let name = component_cstring_os(name)?;
        let child = cockpit_host::private_fs::held_fd::openat(
            current.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .with_context(|| format!("opening skill support directory component {:?}", name))?;
        bindings.push(UnixDirectoryBinding {
            parent: current
                .try_clone()
                .context("cloning held skill-support parent descriptor")?,
            name: std::ffi::OsString::from_vec(name.into_bytes()),
            child: child
                .try_clone()
                .context("cloning held skill-support child descriptor")?,
        });
        current = child;
    }
    Ok(PreparedSupportParent {
        directory: current,
        bindings,
    })
}

#[cfg(unix)]
fn open_directory_child(parent: &std::fs::File, name: &std::ffi::OsStr) -> Result<std::fs::File> {
    let name = component_cstring_os(name)?;
    open_directory_child_cstr(parent, &name)
}

#[cfg(unix)]
fn open_directory_child_cstr(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd as _;

    cockpit_host::private_fs::held_fd::openat(
        parent.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
    .map_err(Into::into)
}

#[cfg(unix)]
fn open_or_create_directory_child(parent: &std::fs::File, name: &str) -> Result<std::fs::File> {
    open_or_create_directory_child_os(parent, std::ffi::OsStr::new(name))
}

#[cfg(unix)]
fn open_or_create_directory_child_os(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd as _;

    let name = component_cstring_os(name)?;
    match open_directory_child_cstr(parent, &name) {
        Ok(directory) => Ok(directory),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            match cockpit_host::private_fs::held_fd::mkdirat(parent.as_raw_fd(), &name, 0o755) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error).context("creating skill directory component"),
            }
            open_directory_child_cstr(parent, &name)
                .context("opening created skill directory without following links")
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn entry_exists_nofollow(parent: &std::fs::File, name: &std::ffi::CStr) -> Result<bool> {
    use std::os::fd::AsRawFd as _;

    match cockpit_host::private_fs::held_fd::fstatat_nofollow(parent.as_raw_fd(), name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("checking held skill directory entry"),
    }
}

#[cfg(unix)]
fn same_directory_identity(left: &std::fs::File, right: &std::fs::File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let left = left
        .metadata()
        .context("reading held skill directory identity")?;
    let right = right
        .metadata()
        .context("reading prepared skill directory identity")?;
    Ok(left.is_dir() && right.is_dir() && left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(unix)]
fn validate_directory_bindings(bindings: &[UnixDirectoryBinding]) -> Result<()> {
    for binding in bindings {
        let current = open_directory_child(&binding.parent, &binding.name)
            .context("skill root changed after preparation; refusing mutation")?;
        ensure!(
            same_directory_identity(&current, &binding.child)?,
            "skill root changed after preparation; refusing mutation"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn move_noreplace(
    source_parent: &std::fs::File,
    source: &std::ffi::CStr,
    destination_parent: &std::fs::File,
    destination: &std::ffi::CStr,
) -> Result<()> {
    use std::os::fd::AsRawFd as _;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        return cockpit_host::private_fs::held_fd::rename_noreplace(
            source_parent.as_raw_fd(),
            source,
            destination_parent.as_raw_fd(),
            destination,
        )
        .map_err(Into::into);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (source_parent, source, destination_parent, destination);
        bail!("skill mutation staging requires an atomic no-replace rename on this platform")
    }
}

#[cfg(unix)]
fn atomic_write_at(parent: &std::fs::File, name: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;

    let destination = component_cstring(name)?;
    // A random one-component temporary remains below the held package fd.
    // O_EXCL + O_NOFOLLOW makes an attacker collision a failure, never a
    // redirection. It also means a provenance leaf symlink is rejected by the
    // no-follow stat before the replacement step.
    let temporary_name = format!(".{name}.tmp-{}", uuid::Uuid::new_v4());
    let temporary = component_cstring(&temporary_name)?;
    let mut file = cockpit_host::private_fs::held_fd::openat_mode(
        parent.as_raw_fd(),
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .with_context(|| format!("creating held skill temporary {temporary_name}"))?;
    let write_result = file.write_all(bytes).and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let _ = cockpit_host::private_fs::held_fd::unlinkat(parent.as_raw_fd(), &temporary, 0);
        return Err(error).context("writing held skill file");
    }
    match cockpit_host::private_fs::held_fd::fstatat_nofollow(parent.as_raw_fd(), &destination) {
        Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFLNK => {
            let _ = cockpit_host::private_fs::held_fd::unlinkat(parent.as_raw_fd(), &temporary, 0);
            bail!("refusing to replace symlinked skill metadata")
        }
        Ok(stat) if stat.st_mode & libc::S_IFMT != libc::S_IFREG => {
            let _ = cockpit_host::private_fs::held_fd::unlinkat(parent.as_raw_fd(), &temporary, 0);
            bail!("refusing to replace non-file skill metadata")
        }
        Ok(_) => cockpit_host::private_fs::held_fd::renameat(
            parent.as_raw_fd(),
            &temporary,
            parent.as_raw_fd(),
            &destination,
        )
        .with_context(|| format!("replacing held skill file {name}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // `linkat` publishes without replacement. A collision after the
            // absence probe fails closed rather than replacing another entry.
            if let Err(error) = cockpit_host::private_fs::held_fd::linkat(
                parent.as_raw_fd(),
                &temporary,
                parent.as_raw_fd(),
                &destination,
                0,
            ) {
                let _ =
                    cockpit_host::private_fs::held_fd::unlinkat(parent.as_raw_fd(), &temporary, 0);
                return Err(error).context("publishing held skill file without replacement");
            }
            cockpit_host::private_fs::held_fd::unlinkat(parent.as_raw_fd(), &temporary, 0)
                .context("removing published held skill temporary")?;
        }
        Err(error) => {
            let _ = cockpit_host::private_fs::held_fd::unlinkat(parent.as_raw_fd(), &temporary, 0);
            return Err(error).context("checking held skill metadata destination");
        }
    }
    parent
        .sync_all()
        .context("syncing held skill package directory")?;
    Ok(())
}

#[cfg(unix)]
fn remove_tree_nofollow(directory: &std::fs::File) -> Result<()> {
    use std::os::fd::{AsRawFd as _, IntoRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    let duplicate = directory
        .try_clone()
        .context("cloning held skill directory for traversal")?;
    // SAFETY: `duplicate` is uniquely consumed by `fdopendir`; `closedir`
    // below owns and closes the descriptor on every path after success.
    let raw_fd = duplicate.into_raw_fd();
    // SAFETY: `raw_fd` is a live, uniquely owned descriptor. On success the
    // DIR stream owns it; on failure we close it immediately below.
    let stream = unsafe { libc::fdopendir(raw_fd) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: fdopendir did not consume the descriptor on failure.
        unsafe { libc::close(raw_fd) };
        return Err(error).context("opening held skill directory stream");
    }
    loop {
        set_readdir_errno_zero();
        // SAFETY: `stream` remains valid until the single `closedir` below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            // SAFETY: `stream` is still owned here and must be closed once.
            unsafe { libc::closedir(stream) };
            if error.raw_os_error() == Some(0) {
                return Ok(());
            }
            return Err(error).context("reading held skill directory");
        }
        // SAFETY: `readdir` returned a non-null pointer whose d_name is a
        // NUL-terminated name valid until the next `readdir` call.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = std::ffi::OsStr::from_bytes(name.to_bytes());
        if name == "." || name == ".." {
            continue;
        }
        let name_c = match component_cstring_os(name) {
            Ok(name) => name,
            Err(error) => {
                // SAFETY: stream still has one owner.
                unsafe { libc::closedir(stream) };
                return Err(error);
            }
        };
        let stat = match cockpit_host::private_fs::held_fd::fstatat_nofollow(
            directory.as_raw_fd(),
            &name_c,
        ) {
            Ok(stat) => stat,
            Err(error) => {
                // SAFETY: stream still has one owner.
                unsafe { libc::closedir(stream) };
                return Err(error).context("checking held skill tree entry");
            }
        };
        let kind = stat.st_mode & libc::S_IFMT;
        let result = if kind == libc::S_IFDIR {
            match open_directory_child_cstr(directory, &name_c)
                .context("opening held skill child without following links")
            {
                Ok(child) => remove_tree_nofollow(&child).and_then(|_| {
                    cockpit_host::private_fs::held_fd::unlinkat(
                        directory.as_raw_fd(),
                        &name_c,
                        libc::AT_REMOVEDIR,
                    )
                    .map_err(Into::into)
                }),
                Err(error) => Err(error),
            }
        } else if kind == libc::S_IFLNK {
            Err(anyhow::anyhow!(
                "refusing to traverse symlink while deleting skill package"
            ))
        } else {
            cockpit_host::private_fs::held_fd::unlinkat(directory.as_raw_fd(), &name_c, 0)
                .map_err(Into::into)
        };
        if let Err(error) = result {
            // SAFETY: stream still has one owner.
            unsafe { libc::closedir(stream) };
            return Err(error);
        }
    }
}

#[cfg(all(unix, target_os = "linux"))]
fn set_readdir_errno_zero() {
    // SAFETY: errno is thread-local and this thread is about to call readdir.
    unsafe { *libc::__errno_location() = 0 }
}

#[cfg(all(unix, target_os = "macos"))]
fn set_readdir_errno_zero() {
    // SAFETY: errno is thread-local and this thread is about to call readdir.
    unsafe { *libc::__error() = 0 }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn set_readdir_errno_zero() {}

fn validate_consolidation_forward(deleted: &Skill, umbrella: &Skill) -> Result<()> {
    let umbrella_raw = crate::resource_limits::read_project_text(&umbrella.source)
        .with_context(|| format!("reading umbrella skill {}", umbrella.source.display()))?
        .ok_or_else(|| anyhow::anyhow!("reading umbrella skill {}", umbrella.source.display()))?;
    if !umbrella_raw.contains(&deleted.frontmatter.name) {
        bail!(
            "absorbed_into skill `{}` must reference absorbed skill `{}` before delete",
            umbrella.frontmatter.name,
            deleted.frontmatter.name
        );
    }
    Ok(())
}

#[derive(Debug)]
struct ManagedTarget {
    skill: Skill,
    package: PathBuf,
    /// Canonical configured `scan_dirs` root which owns `package`.  This is
    /// intentionally retained in the prepared plan so the final native
    /// `ReadWrite` capability covers every rename/remove/provenance write
    /// without widening to an arbitrary ancestor.
    writable_root: PreparedSkillRoot,
    pinned: bool,
    #[cfg(unix)]
    package_parent: std::fs::File,
    #[cfg(unix)]
    package_name: std::ffi::OsString,
    #[cfg(unix)]
    package_directory: std::fs::File,
}

fn required<'a>(value: &'a Option<String>, message: &str) -> Result<&'a str> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .context(message.to_string())
}

#[cfg(test)]
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("write target has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating atomic temp file in {}", parent.display()))?;
    temp.write_all(bytes)?;
    temp.as_file_mut().flush()?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("atomically replacing {}", path.display()))?;
    Ok(())
}

fn validate_category(category: &str) -> Result<String> {
    let path = Path::new(category);
    let mut components = path.components();
    let Some(Component::Normal(segment)) = components.next() else {
        bail!("category must be one non-hidden path segment");
    };
    if components.next().is_some()
        || segment.to_string_lossy().starts_with('.')
        || segment.is_empty()
    {
        bail!("category must be one non-hidden path segment");
    }
    Ok(segment.to_string_lossy().into_owned())
}

pub(crate) fn ensure_plain_write_allowed(skill: &Skill, package: &Path) -> Result<()> {
    let name = &skill.frontmatter.name;
    if package.components().any(is_hub_component) {
        bail!("hub-installed skill `{name}` is read-only");
    }
    let provenance = read_provenance(package)?;
    if provenance.as_ref().is_some_and(|value| value.pinned)
        || frontmatter_flag(&skill.frontmatter, "pinned")
    {
        bail!("pinned skill `{name}` is read-only");
    }
    let protection = provenance.as_ref().and_then(|value| value.protection);
    if let Some(protection) = protection.or_else(|| frontmatter_protection(&skill.frontmatter)) {
        let kind = match protection {
            SkillProtection::Bundled => "bundled",
            SkillProtection::HubInstalled => "hub-installed",
        };
        bail!("{kind} skill `{name}` is read-only");
    }
    Ok(())
}

fn read_provenance(package: &Path) -> Result<Option<SkillProvenance>> {
    let path = package.join(PROVENANCE_FILE);
    match crate::resource_limits::read_for_tool(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {}", path.display()))
            .map(Some),
        Err(error) if error.is_not_found() => Ok(None),
        Err(error) => {
            Err(anyhow::Error::from(error).context(format!("reading {}", path.display())))
        }
    }
}

pub fn lifecycle_metadata_for_skill(skill: &Skill) -> Result<SkillLifecycleMetadata> {
    let package = skill
        .source
        .parent()
        .context("SKILL.md has no package directory")?;
    let provenance = read_provenance(package)?;
    let created_by = provenance
        .as_ref()
        .map(|p| created_by_from_origin(p.created_origin))
        .unwrap_or(SkillCreatedBy::Foreground);
    let pinned = provenance.as_ref().is_some_and(|value| value.pinned)
        || frontmatter_flag(&skill.frontmatter, "pinned");
    let protected = provenance
        .as_ref()
        .and_then(|value| value.protection)
        .or_else(|| frontmatter_protection(&skill.frontmatter))
        .is_some()
        || package
            .components()
            .any(|component| matches!(component, Component::Normal(name) if name == ".hub"));
    let created_at = provenance
        .as_ref()
        .and_then(|p| p.writes.iter().map(|w| w.unix_seconds as i64).min())
        .or_else(|| {
            std::fs::metadata(&skill.source)
                .ok()
                .and_then(|m| m.created().or_else(|_| m.modified()).ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
        })
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    Ok(SkillLifecycleMetadata {
        created_by,
        pinned,
        protected,
        created_at,
    })
}

pub fn usage_seed_for_skill(skill: &Skill) -> Result<SkillUsageSeed> {
    let metadata = lifecycle_metadata_for_skill(skill)?;
    Ok(SkillUsageSeed {
        name: skill.frontmatter.name.clone(),
        source_path: skill.source.display().to_string(),
        created_by: metadata.created_by,
        created_at: metadata.created_at,
        pinned: metadata.pinned,
    })
}

fn created_by_from_origin(origin: SkillWriteOrigin) -> SkillCreatedBy {
    match origin {
        SkillWriteOrigin::Foreground => SkillCreatedBy::Foreground,
        SkillWriteOrigin::BackgroundReview => SkillCreatedBy::Background,
    }
}

fn frontmatter_flag(frontmatter: &SkillFrontmatter, key: &str) -> bool {
    yaml_bool(frontmatter.extra.get(key)) || yaml_bool(frontmatter.metadata.extra.get(key))
}

fn frontmatter_protection(frontmatter: &SkillFrontmatter) -> Option<SkillProtection> {
    if frontmatter_flag(frontmatter, "bundled") {
        Some(SkillProtection::Bundled)
    } else if frontmatter_flag(frontmatter, "hub-installed")
        || frontmatter_flag(frontmatter, "hub_installed")
    {
        Some(SkillProtection::HubInstalled)
    } else {
        None
    }
}

fn yaml_bool(value: Option<&serde_yaml::Value>) -> bool {
    matches!(value, Some(serde_yaml::Value::Bool(true)))
}

fn is_hub_component(component: Component<'_>) -> bool {
    matches!(component, Component::Normal(name) if name == ".hub")
}

fn expand_path(value: &str, cwd: &Path) -> PathBuf {
    let expanded = crate::envref::resolve(value).value;
    let expanded = shellexpand::tilde(expanded.trim()).into_owned();
    let path = PathBuf::from(expanded);
    let absolute = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    lexical_normalize(&absolute)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn equivalent_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => lexical_normalize(left) == lexical_normalize(right),
    }
}

fn changed(message: String) -> SkillMutationResult {
    SkillMutationResult {
        changed: true,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &Path) -> SkillsConfig {
        SkillsConfig {
            scan_dirs: vec![root.to_string_lossy().into_owned()],
            ..Default::default()
        }
    }

    fn create_args(name: &str) -> SkillManageArgs {
        SkillManageArgs {
            action: SkillManageAction::Create,
            name: name.to_string(),
            description: Some("Reusable workflow".to_string()),
            content: Some("Follow these steps.\n".to_string()),
            category: None,
            root: None,
            path: None,
            absorbed_into: None,
        }
    }

    fn service<'a>(cwd: &'a Path, cfg: &'a SkillsConfig) -> SkillMutationService<'a> {
        SkillMutationService::new(cwd, cfg)
    }

    fn manifest(root: &Path, name: &str) -> PathBuf {
        root.join(name).join("SKILL.md")
    }

    fn append_to_manifest(root: &Path, name: &str, line: &str) {
        let path = manifest(root, name);
        let mut raw = std::fs::read_to_string(&path).unwrap();
        raw.push('\n');
        raw.push_str(line);
        raw.push('\n');
        atomic_write(&path, raw.as_bytes()).unwrap();
    }

    #[tokio::test]
    async fn consolidation_delete_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let root = tmp.path().join("skills");
            let cfg = config(&root);
            let svc = service(tmp.path(), &cfg);
            svc.apply(&create_args("umbrella")).await.unwrap();
            svc.apply(&create_args("specific")).await.unwrap();

            let mut bare = create_args("specific");
            bare.action = SkillManageAction::Delete;
            bare.description = None;
            bare.content = None;
            let err = svc.apply(&bare).await.unwrap_err();
            assert!(err.to_string().contains("absorbed_into"));
            assert!(root.join("specific/SKILL.md").is_file());

            let mut still_invalid = bare.clone();
            still_invalid.absorbed_into = Some("umbrella".to_string());
            let err = svc.apply(&still_invalid).await.unwrap_err();
            assert!(err.to_string().contains("must reference absorbed skill"));
            assert!(root.join("specific/SKILL.md").is_file());

            append_to_manifest(&root, "umbrella", "Forward absorbed skill: specific.");

            let mut valid = bare;
            valid.absorbed_into = Some("umbrella".to_string());
            let out = svc.apply(&valid).await.unwrap();
            assert!(out.message.contains("consolidation into `umbrella`"));
            assert!(!root.join("specific").exists());
            assert!(root.join("umbrella/SKILL.md").is_file());
        })
        .await;
    }

    #[tokio::test]
    async fn db_pinned_skill_delete_is_blocked() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let root = tmp.path().join("skills");
            let cfg = config(&root);
            let db = crate::db::Db::open_in_memory().unwrap();
            let svc = service(tmp.path(), &cfg).with_db(&db);
            svc.apply(&create_args("umbrella")).await.unwrap();
            svc.apply(&create_args("pinned-db")).await.unwrap();

            append_to_manifest(&root, "umbrella", "Forward absorbed skill: pinned-db.");
            db.set_skill_usage_pinned("pinned-db", true, 100)
                .await
                .unwrap();

            let mut delete = create_args("pinned-db");
            delete.action = SkillManageAction::Delete;
            delete.description = None;
            delete.content = None;
            delete.absorbed_into = Some("umbrella".to_string());
            let err = svc.apply(&delete).await.unwrap_err();
            assert!(err.to_string().contains("pinned skill"));
            assert!(root.join("pinned-db/SKILL.md").is_file());
        })
        .await;
    }

    #[tokio::test]
    async fn skill_manage_retained_actions_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let root = tmp.path().join("skills");
            let cfg = config(&root);
            let svc = service(tmp.path(), &cfg);

            svc.apply(&create_args("roundtrip")).await.unwrap();
            assert!(manifest(&root, "roundtrip").is_file());

            std::fs::create_dir_all(root.join("roundtrip/references")).unwrap();
            std::fs::write(root.join("roundtrip/references/guide.md"), "support").unwrap();

            let mut remove = create_args("roundtrip");
            remove.action = SkillManageAction::RemoveFile;
            remove.description = None;
            remove.content = None;
            remove.path = Some("references/guide.md".to_string());
            svc.apply(&remove).await.unwrap();
            assert!(!root.join("roundtrip/references/guide.md").exists());

            svc.apply(&create_args("roundtrip-umbrella")).await.unwrap();
            append_to_manifest(
                &root,
                "roundtrip-umbrella",
                "Forward absorbed skill: roundtrip.",
            );
            let mut delete = create_args("roundtrip");
            delete.action = SkillManageAction::Delete;
            delete.description = None;
            delete.content = None;
            delete.absorbed_into = Some("roundtrip-umbrella".to_string());
            svc.apply(&delete).await.unwrap();
            assert!(!root.join("roundtrip").exists());
        })
        .await;
    }

    #[tokio::test]
    async fn skill_protection_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let root = tmp.path().join("skills");
            let external = tmp.path().join("external");
            let mut cfg = config(&root);
            cfg.external_dirs
                .push(external.to_string_lossy().into_owned());
            let svc = service(tmp.path(), &cfg);

            svc.apply(&create_args("pinned")).await.unwrap();
            let mut provenance = read_provenance(&root.join("pinned")).unwrap().unwrap();
            provenance.pinned = true;
            atomic_write(
                &root.join("pinned").join(PROVENANCE_FILE),
                &serde_json::to_vec(&provenance).unwrap(),
            )
            .unwrap();
            let mut delete = create_args("pinned");
            delete.action = SkillManageAction::Delete;
            delete.description = None;
            delete.content = None;
            assert!(svc.apply(&delete).await.is_err());

            let mut frontmatter_pinned = create_args("frontmatter-pinned");
            frontmatter_pinned.content = Some("Pinned body.".to_string());
            svc.apply(&frontmatter_pinned).await.unwrap();
            let pinned_path = manifest(&root, "frontmatter-pinned");
            let raw = std::fs::read_to_string(&pinned_path).unwrap().replacen(
                "description: \"Reusable workflow\"",
                "description: \"Reusable workflow\"\npinned: true",
                1,
            );
            atomic_write(&pinned_path, raw.as_bytes()).unwrap();
            std::fs::write(
                &pinned_path,
                "---\nname: frontmatter-pinned\ndescription: Still pinned\n---\n\nUpdated body.\n",
            )
            .unwrap();
            let mut delete_pinned = create_args("frontmatter-pinned");
            delete_pinned.action = SkillManageAction::Delete;
            delete_pinned.description = None;
            delete_pinned.content = None;
            assert!(svc.apply(&delete_pinned).await.is_err());

            std::fs::write(
                root.join("frontmatter-pinned").join(PROVENANCE_FILE),
                b"not json",
            )
            .unwrap();
            let before_corrupt = std::fs::read_to_string(&pinned_path).unwrap();
            assert!(svc.apply(&delete_pinned).await.is_err());
            assert_eq!(
                std::fs::read_to_string(&pinned_path).unwrap(),
                before_corrupt
            );

            std::fs::create_dir_all(external.join("shared")).unwrap();
            std::fs::write(
                external.join("shared/SKILL.md"),
                "---\nname: shared\ndescription: Shared skill\n---\n\nRead only.\n",
            )
            .unwrap();
            let mut external_delete = create_args("shared");
            external_delete.action = SkillManageAction::Delete;
            external_delete.description = None;
            external_delete.content = None;
            assert!(svc.apply(&external_delete).await.is_err());

            let mut bundled = create_args("bundled");
            bundled.content = Some("Bundled body.".to_string());
            svc.apply(&bundled).await.unwrap();
            let path = manifest(&root, "bundled");
            let raw = std::fs::read_to_string(&path).unwrap().replacen(
                "description: \"Reusable workflow\"",
                "description: \"Reusable workflow\"\nbundled: true",
                1,
            );
            atomic_write(&path, raw.as_bytes()).unwrap();
            let mut bundled_delete = create_args("bundled");
            bundled_delete.action = SkillManageAction::Delete;
            bundled_delete.description = None;
            bundled_delete.content = None;
            assert!(svc.apply(&bundled_delete).await.is_err());
        })
        .await;
    }

    #[tokio::test]
    async fn skill_write_invalidates_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let root = tmp.path().join("skills");
            let cfg = config(&root);
            assert!(super::super::discover(tmp.path(), &cfg).unwrap().is_empty());
            assert!(super::super::catalog_cache_contains(tmp.path(), &cfg));
            let before = super::super::catalog_generation();
            service(tmp.path(), &cfg)
                .apply(&create_args("generation"))
                .await
                .unwrap();
            assert!(super::super::catalog_generation() > before);
            assert!(!super::super::catalog_cache_contains(tmp.path(), &cfg));
            assert!(
                super::super::discover(tmp.path(), &cfg)
                    .unwrap()
                    .iter()
                    .any(|skill| skill.frontmatter.name == "generation")
            );
        })
        .await;
    }

    #[tokio::test]
    async fn skill_write_records_origin() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let root = tmp.path().join("skills");
            let cfg = config(&root);
            service(tmp.path(), &cfg)
                .apply(&create_args("foreground"))
                .await
                .unwrap();
            let foreground = read_provenance(&root.join("foreground")).unwrap().unwrap();
            assert_eq!(foreground.created_origin, SkillWriteOrigin::Foreground);
            assert_eq!(foreground.writes[0].origin, SkillWriteOrigin::Foreground);

            SkillMutationService::new(tmp.path(), &cfg)
                .with_origin(SkillWriteOrigin::BackgroundReview)
                .apply(&create_args("background"))
                .await
                .unwrap();
            let background = read_provenance(&root.join("background")).unwrap().unwrap();
            assert_eq!(
                background.created_origin,
                SkillWriteOrigin::BackgroundReview
            );
            assert_eq!(
                background.writes[0].origin,
                SkillWriteOrigin::BackgroundReview
            );

            std::fs::create_dir_all(root.join("background/references")).unwrap();
            std::fs::write(root.join("background/references/old.md"), "obsolete").unwrap();
            let mut remove = create_args("background");
            remove.action = SkillManageAction::RemoveFile;
            remove.description = None;
            remove.content = None;
            remove.path = Some("references/old.md".to_string());
            SkillMutationService::new(tmp.path(), &cfg)
                .with_origin(SkillWriteOrigin::BackgroundReview)
                .apply(&remove)
                .await
                .unwrap();
            let background = read_provenance(&root.join("background")).unwrap().unwrap();
            assert_eq!(
                background.writes.last().unwrap().origin,
                SkillWriteOrigin::BackgroundReview
            );
        })
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepared_create_rejects_a_root_ancestor_symlink_swap() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let container = tmp.path().join("container");
            let root = container.join("skills");
            let cfg = config(&root);
            let svc = service(tmp.path(), &cfg);
            svc.apply(&create_args("existing")).await.unwrap();

            let prepared = svc.prepare(&create_args("must-not-escape")).await.unwrap();
            let outside = tmp.path().join("outside");
            std::fs::create_dir_all(outside.join("skills")).unwrap();
            std::fs::rename(&container, tmp.path().join("container-held")).unwrap();
            symlink(&outside, &container).unwrap();

            let error = svc.apply_prepared(&prepared).unwrap_err();
            assert!(
                error.to_string().contains("skill root changed")
                    || error.to_string().contains("refusing mutation"),
                "{error:#}"
            );
            assert!(!outside.join("skills/must-not-escape/SKILL.md").exists());
            assert!(
                tmp.path()
                    .join("container-held/skills/existing/SKILL.md")
                    .is_file()
            );
            assert!(
                !tmp.path()
                    .join("container-held/skills/must-not-escape/SKILL.md")
                    .exists()
            );
        })
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepared_delete_rejects_a_package_symlink_swap() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let root = tmp.path().join("skills");
            let cfg = config(&root);
            let svc = service(tmp.path(), &cfg);
            svc.apply(&create_args("umbrella")).await.unwrap();
            svc.apply(&create_args("specific")).await.unwrap();
            append_to_manifest(&root, "umbrella", "Forward absorbed skill: specific.");

            let mut delete = create_args("specific");
            delete.action = SkillManageAction::Delete;
            delete.description = None;
            delete.content = None;
            delete.absorbed_into = Some("umbrella".to_string());
            let prepared = svc.prepare(&delete).await.unwrap();

            let outside = tmp.path().join("outside-specific");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("SKILL.md"), "outside must remain").unwrap();
            std::fs::rename(root.join("specific"), root.join("specific-held")).unwrap();
            symlink(&outside, root.join("specific")).unwrap();

            assert!(svc.apply_prepared(&prepared).is_err());
            assert_eq!(
                std::fs::read_to_string(outside.join("SKILL.md")).unwrap(),
                "outside must remain"
            );
            assert!(root.join("specific-held/SKILL.md").is_file());
        })
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepared_remove_file_rejects_a_references_ancestor_symlink_swap() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let root = tmp.path().join("skills");
            let cfg = config(&root);
            let svc = service(tmp.path(), &cfg);
            svc.apply(&create_args("target")).await.unwrap();
            let package = root.join("target");
            std::fs::create_dir_all(package.join("references")).unwrap();
            std::fs::write(package.join("references/old.md"), "held content").unwrap();

            let mut remove = create_args("target");
            remove.action = SkillManageAction::RemoveFile;
            remove.description = None;
            remove.content = None;
            remove.path = Some("references/old.md".to_string());
            let prepared = svc.prepare(&remove).await.unwrap();

            let outside = tmp.path().join("outside-references");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("old.md"), "outside must remain").unwrap();
            std::fs::rename(package.join("references"), package.join("references-held")).unwrap();
            symlink(&outside, package.join("references")).unwrap();

            assert!(svc.apply_prepared(&prepared).is_err());
            assert_eq!(
                std::fs::read_to_string(outside.join("old.md")).unwrap(),
                "outside must remain"
            );
            assert_eq!(
                std::fs::read_to_string(package.join("references-held/old.md")).unwrap(),
                "held content"
            );
        })
        .await;
    }
}
