use std::collections::HashSet;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
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

    pub async fn apply(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        if args.name != args.name.trim() || !managed_skill_name_valid(&args.name) {
            bail!("skill name must match ^[a-z0-9][a-z0-9._-]*$ and contain at most 64 characters");
        }
        let result = match args.action {
            SkillManageAction::Create => self.create(args),
            SkillManageAction::Delete => self.delete(args).await,
            SkillManageAction::RemoveFile => self.remove_file(args),
        }?;
        if result.changed {
            if let Err(error) = self.record_usage(args).await {
                tracing::warn!(
                    error = %error,
                    skill = %args.name,
                    action = ?args.action,
                    "skill usage ledger update failed"
                );
            }
            super::invalidate_catalog_cache(self.cwd, self.config);
        }
        Ok(result)
    }

    fn create(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        let description = required(&args.description, "`description` is required for create")?;
        let body = required(&args.content, "`content` is required for create")?;
        let root = self.select_create_root(args.root.as_deref())?;
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating writable skills root {}", root.display()))?;
        let root = root
            .canonicalize()
            .with_context(|| format!("canonicalizing writable skills root {}", root.display()))?;
        let category = args
            .category
            .as_deref()
            .map(validate_category)
            .transpose()?;
        let package = category.as_ref().map_or_else(
            || root.join(&args.name),
            |category| root.join(category).join(&args.name),
        );
        if package.exists() {
            bail!("skill package already exists: {}", package.display());
        }
        let parent = package.parent().context("skill package has no parent")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating skill category {}", parent.display()))?;
        let canonical_parent = parent
            .canonicalize()
            .with_context(|| format!("canonicalizing skill category {}", parent.display()))?;
        if !canonical_parent.starts_with(&root) {
            bail!("skill category escapes the writable skills root");
        }
        std::fs::create_dir(&package)
            .with_context(|| format!("creating skill package {}", package.display()))?;

        let raw = format!(
            "---\nname: {}\ndescription: {}\n---\n\n{}\n",
            args.name,
            serde_json::to_string(description.trim())?,
            body.trim_end()
        );
        if let Err(error) = validate_managed_skill_contents(&raw, &args.name)
            .and_then(|_| atomic_write(&package.join("SKILL.md"), raw.as_bytes()))
            .and_then(|_| self.record_provenance(&package, args.action, true, false))
        {
            let _ = std::fs::remove_dir_all(&package);
            return Err(error);
        }
        Ok(changed(format!("Created skill `{}`", args.name)))
    }

    async fn delete(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        let target = self.resolve_target(&args.name)?;
        if target.pinned {
            bail!("pinned skill `{}` may not be deleted by tools", args.name);
        }
        if let Some(db) = self.db
            && db
                .get_skill_usage(&args.name)
                .await?
                .is_some_and(|row| row.pinned)
        {
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
        let parent = target
            .package
            .parent()
            .context("skill package has no parent")?;
        let tombstone = parent.join(format!(".{}.delete-{}", args.name, uuid::Uuid::new_v4()));
        std::fs::rename(&target.package, &tombstone)
            .with_context(|| format!("staging deletion of {}", target.package.display()))?;
        if let Err(error) = std::fs::remove_dir_all(&tombstone) {
            let _ = std::fs::rename(&tombstone, &target.package);
            return Err(error).context("removing staged skill package");
        }
        Ok(changed(format!(
            "Deleted skill `{}` after consolidation into `{absorbed_into}`",
            args.name
        )))
    }

    fn remove_file(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        let target = self.resolve_target(&args.name)?;
        let relative = Path::new(required(&args.path, "`path` is required for remove_file")?);
        let path = safe_support_target(&target.package, relative)?;
        if !path.is_file() {
            bail!("support file does not exist: {}", relative.display());
        }
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            bail!("refusing to remove a symlinked support file");
        }
        let staged = path.with_file_name(format!(
            ".{}.delete-{}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("support"),
            uuid::Uuid::new_v4()
        ));
        std::fs::rename(&path, &staged)
            .with_context(|| format!("staging removal of {}", relative.display()))?;
        if let Err(error) = std::fs::remove_file(&staged) {
            let _ = std::fs::rename(&staged, &path);
            return Err(error).context("removing staged support file");
        }
        self.record_provenance(&target.package, args.action, false, target.pinned)?;
        Ok(changed(format!(
            "Removed `{}` from skill `{}`",
            relative.display(),
            args.name
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
        Ok(ManagedTarget {
            skill,
            package,
            pinned,
        })
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

    fn record_provenance(
        &self,
        package: &Path,
        action: SkillManageAction,
        created: bool,
        preserve_pinned: bool,
    ) -> Result<()> {
        let mut provenance = read_provenance(package)?.unwrap_or(SkillProvenance {
            created_origin: if created {
                self.origin
            } else {
                SkillWriteOrigin::Foreground
            },
            writes: Vec::new(),
            pinned: preserve_pinned,
            protection: None,
        });
        if created {
            provenance.created_origin = self.origin;
        }
        provenance.pinned |= preserve_pinned;
        provenance.writes.push(SkillProvenanceWrite {
            action,
            origin: self.origin,
            unix_seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });
        let mut bytes = serde_json::to_vec_pretty(&provenance)?;
        bytes.push(b'\n');
        atomic_write(&package.join(PROVENANCE_FILE), &bytes)
    }

    async fn record_usage(&self, args: &SkillManageArgs) -> Result<()> {
        let Some(db) = self.db else {
            return Ok(());
        };
        if matches!(args.action, SkillManageAction::Delete) {
            return Ok(());
        }
        let target = self.resolve_target(&args.name)?;
        let seed = usage_seed_for_skill(&target.skill)?;
        let now = chrono::Utc::now().timestamp();
        match args.action {
            SkillManageAction::Create => {
                db.ensure_skill_usage(seed, now).await?;
            }
            SkillManageAction::RemoveFile => {
                db.record_skill_patch(seed, now).await?;
            }
            SkillManageAction::Delete => {}
        }
        Ok(())
    }
}

fn validate_consolidation_forward(deleted: &Skill, umbrella: &Skill) -> Result<()> {
    let umbrella_raw = std::fs::read_to_string(&umbrella.source)
        .with_context(|| format!("reading umbrella skill {}", umbrella.source.display()))?;
    if !umbrella_raw.contains(&deleted.frontmatter.name) {
        bail!(
            "absorbed_into skill `{}` must reference absorbed skill `{}` before delete",
            umbrella.frontmatter.name,
            deleted.frontmatter.name
        );
    }
    Ok(())
}

struct ManagedTarget {
    skill: Skill,
    package: PathBuf,
    pinned: bool,
}

fn required<'a>(value: &'a Option<String>, message: &str) -> Result<&'a str> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .context(message.to_string())
}

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

fn safe_support_target(package: &Path, relative: &Path) -> Result<PathBuf> {
    super::validate_support_relative(relative)?;
    let package = package
        .canonicalize()
        .context("canonicalizing skill package")?;
    let target = package.join(relative);
    let mut cursor = package.clone();
    for component in relative.parent().into_iter().flat_map(Path::components) {
        let Component::Normal(segment) = component else {
            bail!("support file path may not contain traversal components");
        };
        cursor.push(segment);
        match std::fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("support file path may not traverse symlinks")
            }
            Ok(metadata) if !metadata.is_dir() => bail!("support file parent is not a directory"),
            Ok(_) => {}
            Err(error) => {
                return Err(error).with_context(|| format!("checking {}", cursor.display()));
            }
        }
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&target)
        && metadata.file_type().is_symlink()
    {
        bail!("support file target may not be a symlink");
    }
    Ok(target)
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
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
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
    }

    #[tokio::test]
    async fn db_pinned_skill_delete_is_blocked() {
        let tmp = tempfile::tempdir().unwrap();
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
    }

    #[tokio::test]
    async fn skill_manage_retained_actions_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
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
    }

    #[tokio::test]
    async fn skill_protection_rules() {
        let tmp = tempfile::tempdir().unwrap();
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
    }

    #[tokio::test]
    async fn skill_write_invalidates_cache() {
        let tmp = tempfile::tempdir().unwrap();
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
    }

    #[tokio::test]
    async fn skill_write_records_origin() {
        let tmp = tempfile::tempdir().unwrap();
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
    }
}
