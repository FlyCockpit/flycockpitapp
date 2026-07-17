use std::collections::HashSet;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::{
    Skill, SkillFrontmatter, find_by_name, managed_skill_name_valid,
    validate_managed_skill_contents, validate_support_relative,
};
use crate::config::extended::SkillsConfig;

const PROVENANCE_FILE: &str = ".cockpit-provenance.json";
const PREVIEW_CHARS: usize = 800;

pub use crate::db::needs_attention::InterruptCallOrigin as SkillWriteOrigin;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillManageAction {
    Create,
    Patch,
    Edit,
    Delete,
    WriteFile,
    RemoveFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManageArgs {
    pub action: SkillManageAction,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub old_string: Option<String>,
    #[serde(default)]
    pub new_string: Option<String>,
    #[serde(default)]
    pub replace_all: bool,
    #[serde(default)]
    pub path: Option<String>,
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

pub struct SkillMutationService<'a> {
    cwd: &'a Path,
    config: &'a SkillsConfig,
    origin: SkillWriteOrigin,
}

impl<'a> SkillMutationService<'a> {
    pub fn new(cwd: &'a Path, config: &'a SkillsConfig) -> Self {
        Self {
            cwd,
            config,
            origin: SkillWriteOrigin::Foreground,
        }
    }

    pub fn with_origin(mut self, origin: SkillWriteOrigin) -> Self {
        self.origin = origin;
        self
    }

    pub fn apply(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        if args.name != args.name.trim() || !managed_skill_name_valid(&args.name) {
            bail!("skill name must match ^[a-z0-9][a-z0-9._-]*$ and contain at most 64 characters");
        }
        let result = match args.action {
            SkillManageAction::Create => self.create(args),
            SkillManageAction::Patch => self.patch(args),
            SkillManageAction::Edit => self.edit(args),
            SkillManageAction::Delete => self.delete(args),
            SkillManageAction::WriteFile => self.write_file(args),
            SkillManageAction::RemoveFile => self.remove_file(args),
        }?;
        if result.changed {
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

    fn patch(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        let target = self.resolve_target(&args.name)?;
        let old = required(&args.old_string, "`old_string` is required for patch")?;
        if old.is_empty() {
            bail!("`old_string` must not be empty");
        }
        let new = args.new_string.as_deref().unwrap_or("");
        let original = std::fs::read_to_string(&target.skill.source)
            .with_context(|| format!("reading {}", target.skill.source.display()))?;
        let Some(updated) = fuzzy_replace(&original, old, new, args.replace_all)? else {
            return Ok(SkillMutationResult {
                changed: false,
                message: format!(
                    "No fuzzy match for `old_string` in `{}`. Copy a smaller exact passage from this preview and retry:\n{}",
                    args.name,
                    preview(&original)
                ),
            });
        };
        validate_managed_skill_contents(&updated, &args.name)
            .context("patch refused; original SKILL.md left intact")?;
        atomic_write(&target.skill.source, updated.as_bytes())?;
        self.record_provenance(&target.package, args.action, false, target.pinned)?;
        Ok(changed(format!("Patched skill `{}`", args.name)))
    }

    fn edit(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        let target = self.resolve_target(&args.name)?;
        let content = required(&args.content, "`content` is required for edit")?;
        validate_managed_skill_contents(content, &args.name)
            .context("edit refused; original SKILL.md left intact")?;
        atomic_write(&target.skill.source, content.as_bytes())?;
        self.record_provenance(&target.package, args.action, false, target.pinned)?;
        Ok(changed(format!("Rewrote skill `{}`", args.name)))
    }

    fn delete(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        let target = self.resolve_target(&args.name)?;
        if target.pinned {
            bail!("pinned skill `{}` may not be deleted by tools", args.name);
        }
        if std::fs::symlink_metadata(&target.package)?
            .file_type()
            .is_symlink()
        {
            bail!("refusing to delete a symlinked skill package");
        }
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
        Ok(changed(format!("Deleted skill `{}`", args.name)))
    }

    fn write_file(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        let target = self.resolve_target(&args.name)?;
        let relative = Path::new(required(&args.path, "`path` is required for write_file")?);
        let content = required(&args.content, "`content` is required for write_file")?;
        if content.chars().count() > 100_000 {
            bail!("support file exceeds 100000 character limit");
        }
        let path = safe_support_target(&target.package, relative, true)?;
        atomic_write(&path, content.as_bytes())?;
        self.record_provenance(&target.package, args.action, false, target.pinned)?;
        Ok(changed(format!(
            "Wrote `{}` in skill `{}`",
            relative.display(),
            args.name
        )))
    }

    fn remove_file(&self, args: &SkillManageArgs) -> Result<SkillMutationResult> {
        let target = self.resolve_target(&args.name)?;
        let relative = Path::new(required(&args.path, "`path` is required for remove_file")?);
        let path = safe_support_target(&target.package, relative, false)?;
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

fn safe_support_target(package: &Path, relative: &Path, create_parents: bool) -> Result<PathBuf> {
    validate_support_relative(relative)?;
    let package = package
        .canonicalize()
        .context("canonicalizing skill package")?;
    let target = package.join(relative);
    let parent = target.parent().context("support file has no parent")?;
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
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create_parents => {
                std::fs::create_dir(&cursor)
                    .with_context(|| format!("creating support directory {}", cursor.display()))?;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("checking {}", cursor.display()));
            }
        }
    }
    if create_parents && !parent.exists() {
        bail!("support file parent could not be created");
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&target)
        && metadata.file_type().is_symlink()
    {
        bail!("support file target may not be a symlink");
    }
    Ok(target)
}

fn fuzzy_replace(content: &str, old: &str, new: &str, replace_all: bool) -> Result<Option<String>> {
    let content_chars = normalized_chars(content);
    let needle: Vec<char> = normalized_chars(old)
        .into_iter()
        .map(|entry| entry.ch)
        .collect();
    if needle.is_empty() {
        bail!("`old_string` must contain non-whitespace text");
    }
    if needle.len() > content_chars.len() {
        return Ok(None);
    }
    let mut matches = Vec::new();
    let mut start = 0;
    while start + needle.len() <= content_chars.len() {
        if content_chars[start..start + needle.len()]
            .iter()
            .map(|entry| entry.ch)
            .eq(needle.iter().copied())
        {
            matches.push((
                content_chars[start].start,
                content_chars[start + needle.len() - 1].end,
            ));
            start += needle.len();
        } else {
            start += 1;
        }
    }
    if matches.is_empty() {
        return Ok(None);
    }
    if matches.len() > 1 && !replace_all {
        bail!(
            "fuzzy patch matched {} spans; provide a more specific `old_string` or set `replace_all: true`",
            matches.len()
        );
    }
    let mut updated = content.to_string();
    for (start, end) in matches.into_iter().rev() {
        updated.replace_range(start..end, new);
        if !replace_all {
            break;
        }
    }
    Ok(Some(updated))
}

#[derive(Clone, Copy)]
struct NormalizedChar {
    ch: char,
    start: usize,
    end: usize,
}

fn normalized_chars(input: &str) -> Vec<NormalizedChar> {
    let mut out = Vec::new();
    let mut whitespace: Option<(usize, usize)> = None;
    for (start, ch) in input.char_indices() {
        let end = start + ch.len_utf8();
        if ch.is_whitespace() {
            whitespace = Some(match whitespace {
                Some((first, _)) => (first, end),
                None => (start, end),
            });
            continue;
        }
        if let Some((start, end)) = whitespace.take()
            && !out.is_empty()
        {
            out.push(NormalizedChar {
                ch: ' ',
                start,
                end,
            });
        }
        out.push(NormalizedChar { ch, start, end });
    }
    out
}

fn preview(content: &str) -> String {
    let preview: String = content.chars().take(PREVIEW_CHARS).collect();
    if content.chars().count() > PREVIEW_CHARS {
        format!("{preview}\n…")
    } else {
        preview
    }
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
            old_string: None,
            new_string: None,
            replace_all: false,
            path: None,
        }
    }

    fn service<'a>(cwd: &'a Path, cfg: &'a SkillsConfig) -> SkillMutationService<'a> {
        SkillMutationService::new(cwd, cfg)
    }

    fn manifest(root: &Path, name: &str) -> PathBuf {
        root.join(name).join("SKILL.md")
    }

    #[test]
    fn skill_manage_ops_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let cfg = config(&root);
        let svc = service(tmp.path(), &cfg);

        svc.apply(&create_args("roundtrip")).unwrap();
        assert!(manifest(&root, "roundtrip").is_file());

        let mut write = create_args("roundtrip");
        write.action = SkillManageAction::WriteFile;
        write.description = None;
        write.content = Some("support".to_string());
        write.path = Some("references/guide.md".to_string());
        svc.apply(&write).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("roundtrip/references/guide.md")).unwrap(),
            "support"
        );

        let mut patch = create_args("roundtrip");
        patch.action = SkillManageAction::Patch;
        patch.description = None;
        patch.content = None;
        patch.old_string = Some("Follow these steps.".to_string());
        patch.new_string = Some("Follow the revised steps.".to_string());
        svc.apply(&patch).unwrap();

        let mut edit = create_args("roundtrip");
        edit.action = SkillManageAction::Edit;
        edit.description = None;
        edit.content = Some(
            "---\nname: roundtrip\ndescription: Rewritten workflow\n---\n\nEntirely new body.\n"
                .to_string(),
        );
        svc.apply(&edit).unwrap();
        assert!(
            std::fs::read_to_string(manifest(&root, "roundtrip"))
                .unwrap()
                .contains("Entirely new body")
        );

        let mut remove = write.clone();
        remove.action = SkillManageAction::RemoveFile;
        remove.content = None;
        svc.apply(&remove).unwrap();
        assert!(!root.join("roundtrip/references/guide.md").exists());

        let mut delete = create_args("roundtrip");
        delete.action = SkillManageAction::Delete;
        delete.description = None;
        delete.content = None;
        svc.apply(&delete).unwrap();
        assert!(!root.join("roundtrip").exists());
    }

    #[test]
    fn patch_fuzzy_match() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let cfg = config(&root);
        let svc = service(tmp.path(), &cfg);
        let mut create = create_args("fuzzy");
        create.content = Some("Steps:\n    - alpha\n    - beta\n".to_string());
        svc.apply(&create).unwrap();

        let mut patch = create_args("fuzzy");
        patch.action = SkillManageAction::Patch;
        patch.description = None;
        patch.content = None;
        patch.old_string = Some("Steps:\n- alpha\n- beta".to_string());
        patch.new_string = Some("Steps:\n- alpha\n- gamma".to_string());
        svc.apply(&patch).unwrap();
        assert!(
            std::fs::read_to_string(manifest(&root, "fuzzy"))
                .unwrap()
                .contains("gamma")
        );
    }

    #[test]
    fn patch_replace_all_uses_non_overlapping_spans() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let cfg = config(&root);
        let svc = service(tmp.path(), &cfg);
        let mut create = create_args("replace-all");
        create.content = Some("aaaa tail".to_string());
        svc.apply(&create).unwrap();

        let mut patch = create_args("replace-all");
        patch.action = SkillManageAction::Patch;
        patch.description = None;
        patch.content = None;
        patch.old_string = Some("aa".to_string());
        patch.new_string = Some(String::new());
        patch.replace_all = true;
        svc.apply(&patch).unwrap();
        let raw = std::fs::read_to_string(manifest(&root, "replace-all")).unwrap();
        assert!(raw.contains("tail"));
        assert!(!raw.contains("aaaa"));
    }

    #[test]
    fn patch_no_match_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let cfg = config(&root);
        let svc = service(tmp.path(), &cfg);
        svc.apply(&create_args("hint")).unwrap();
        let before = std::fs::read_to_string(manifest(&root, "hint")).unwrap();
        let mut patch = create_args("hint");
        patch.action = SkillManageAction::Patch;
        patch.description = None;
        patch.content = None;
        patch.old_string = Some("not present".to_string());
        patch.new_string = Some("replacement".to_string());
        let result = svc.apply(&patch).unwrap();
        assert!(!result.changed);
        assert!(result.message.contains("preview"));
        assert!(result.message.contains("retry"));
        assert_eq!(
            std::fs::read_to_string(manifest(&root, "hint")).unwrap(),
            before
        );
    }

    #[test]
    fn patch_preserves_frontmatter_or_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let cfg = config(&root);
        let svc = service(tmp.path(), &cfg);
        svc.apply(&create_args("guarded")).unwrap();
        let path = manifest(&root, "guarded");
        let before = std::fs::read_to_string(&path).unwrap();
        let mut patch = create_args("guarded");
        patch.action = SkillManageAction::Patch;
        patch.description = None;
        patch.content = None;
        patch.old_string = Some("name: guarded".to_string());
        patch.new_string = Some("name:".to_string());
        let error = svc.apply(&patch).unwrap_err().to_string();
        assert!(error.contains("original SKILL.md left intact"), "{error}");
        assert_eq!(std::fs::read_to_string(path).unwrap(), before);
    }

    #[test]
    fn skill_file_path_allowlist() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let cfg = config(&root);
        let svc = service(tmp.path(), &cfg);
        svc.apply(&create_args("paths")).unwrap();
        for invalid in ["notes/file.md", "references/../SKILL.md", "/tmp/file"] {
            let mut args = create_args("paths");
            args.action = SkillManageAction::WriteFile;
            args.description = None;
            args.content = Some("bad".to_string());
            args.path = Some(invalid.to_string());
            assert!(svc.apply(&args).is_err(), "accepted {invalid}");
        }
        assert!(!root.join("paths/notes/file.md").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let outside = tmp.path().join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            symlink(&outside, root.join("paths/references")).unwrap();
            let mut through_parent_link = create_args("paths");
            through_parent_link.action = SkillManageAction::WriteFile;
            through_parent_link.description = None;
            through_parent_link.content = Some("bad".to_string());
            through_parent_link.path = Some("references/escape.md".to_string());
            assert!(svc.apply(&through_parent_link).is_err());
            assert!(!outside.join("escape.md").exists());

            std::fs::remove_file(root.join("paths/references")).unwrap();
            std::fs::create_dir(root.join("paths/references")).unwrap();
            let outside_file = outside.join("target.md");
            std::fs::write(&outside_file, "safe").unwrap();
            symlink(&outside_file, root.join("paths/references/target.md")).unwrap();
            through_parent_link.path = Some("references/target.md".to_string());
            assert!(svc.apply(&through_parent_link).is_err());
            assert_eq!(std::fs::read_to_string(outside_file).unwrap(), "safe");
        }
    }

    #[test]
    fn skill_protection_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let external = tmp.path().join("external");
        let mut cfg = config(&root);
        cfg.external_dirs
            .push(external.to_string_lossy().into_owned());
        let svc = service(tmp.path(), &cfg);

        svc.apply(&create_args("pinned")).unwrap();
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
        assert!(svc.apply(&delete).is_err());
        let mut patch = delete.clone();
        patch.action = SkillManageAction::Patch;
        patch.old_string = Some("Follow these steps.".to_string());
        patch.new_string = Some("Still pinned but patchable.".to_string());
        svc.apply(&patch).unwrap();

        let mut frontmatter_pinned = create_args("frontmatter-pinned");
        frontmatter_pinned.content = Some("Pinned body.".to_string());
        svc.apply(&frontmatter_pinned).unwrap();
        let pinned_path = manifest(&root, "frontmatter-pinned");
        let raw = std::fs::read_to_string(&pinned_path).unwrap().replacen(
            "description: \"Reusable workflow\"",
            "description: \"Reusable workflow\"\npinned: true",
            1,
        );
        atomic_write(&pinned_path, raw.as_bytes()).unwrap();
        let mut strip_pin = create_args("frontmatter-pinned");
        strip_pin.action = SkillManageAction::Edit;
        strip_pin.description = None;
        strip_pin.content = Some(
            "---\nname: frontmatter-pinned\ndescription: Still pinned\n---\n\nUpdated body.\n"
                .to_string(),
        );
        svc.apply(&strip_pin).unwrap();
        let mut delete_stripped = create_args("frontmatter-pinned");
        delete_stripped.action = SkillManageAction::Delete;
        delete_stripped.description = None;
        delete_stripped.content = None;
        assert!(svc.apply(&delete_stripped).is_err());

        std::fs::write(
            root.join("frontmatter-pinned").join(PROVENANCE_FILE),
            b"not json",
        )
        .unwrap();
        let before_corrupt = std::fs::read_to_string(&pinned_path).unwrap();
        let mut corrupt_patch = patch.clone();
        corrupt_patch.name = "frontmatter-pinned".to_string();
        corrupt_patch.old_string = Some("Updated body.".to_string());
        assert!(svc.apply(&corrupt_patch).is_err());
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
        let mut external_patch = patch.clone();
        external_patch.name = "shared".to_string();
        external_patch.old_string = Some("Read only.".to_string());
        assert!(svc.apply(&external_patch).is_err());

        let mut bundled = create_args("bundled");
        bundled.content = Some("Bundled body.".to_string());
        svc.apply(&bundled).unwrap();
        let path = manifest(&root, "bundled");
        let raw = std::fs::read_to_string(&path).unwrap().replacen(
            "description: \"Reusable workflow\"",
            "description: \"Reusable workflow\"\nbundled: true",
            1,
        );
        atomic_write(&path, raw.as_bytes()).unwrap();
        let mut bundled_patch = patch;
        bundled_patch.name = "bundled".to_string();
        assert!(svc.apply(&bundled_patch).is_err());
    }

    #[test]
    fn skill_write_invalidates_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let cfg = config(&root);
        assert!(super::super::discover(tmp.path(), &cfg).unwrap().is_empty());
        assert!(super::super::catalog_cache_contains(tmp.path(), &cfg));
        let before = super::super::catalog_generation();
        service(tmp.path(), &cfg)
            .apply(&create_args("generation"))
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

    #[test]
    fn skill_write_records_origin() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let cfg = config(&root);
        service(tmp.path(), &cfg)
            .apply(&create_args("foreground"))
            .unwrap();
        let foreground = read_provenance(&root.join("foreground")).unwrap().unwrap();
        assert_eq!(foreground.created_origin, SkillWriteOrigin::Foreground);
        assert_eq!(foreground.writes[0].origin, SkillWriteOrigin::Foreground);

        SkillMutationService::new(tmp.path(), &cfg)
            .with_origin(SkillWriteOrigin::BackgroundReview)
            .apply(&create_args("background"))
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

        let preexisting = root.join("preexisting");
        std::fs::create_dir_all(&preexisting).unwrap();
        std::fs::write(
            preexisting.join("SKILL.md"),
            "---\nname: preexisting\ndescription: Existing workflow\n---\n\nOriginal body.\n",
        )
        .unwrap();
        let mut patch = create_args("preexisting");
        patch.action = SkillManageAction::Patch;
        patch.description = None;
        patch.content = None;
        patch.old_string = Some("Original body.".to_string());
        patch.new_string = Some("Reviewed body.".to_string());
        SkillMutationService::new(tmp.path(), &cfg)
            .with_origin(SkillWriteOrigin::BackgroundReview)
            .apply(&patch)
            .unwrap();
        let preexisting = read_provenance(&preexisting).unwrap().unwrap();
        assert_eq!(preexisting.created_origin, SkillWriteOrigin::Foreground);
        assert_eq!(
            preexisting.writes[0].origin,
            SkillWriteOrigin::BackgroundReview
        );
    }
}
