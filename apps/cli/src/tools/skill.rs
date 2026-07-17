//! `skill` — load a named skill's body on demand (manual selection path).
//!
//! The main interactive agents (`Build`, `builder`) call this
//! to pull a skill into context by name. The body is read on demand and
//! run through the same auto-`!`-command processing as the cheap-model
//! auto-selection path (GOALS §5): Claude mode runs `` !`command` ``
//! directives (output scrubbed, GOALS §7); Codex mode injects them
//! verbatim. The available catalog is derived per-call from the layered
//! `config.json` discovered at `ctx.cwd`.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::config::extended::ExtendedConfig;
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

pub struct SkillTool;

#[async_trait]
impl Tool for SkillTool {
    fn name(&self) -> &str {
        "skill"
    }

    fn description(&self) -> &str {
        "Load a named skill or one of its package support files"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Pull a named skill's full instructions into your context on demand. Skills are \
             reusable, task-specific playbooks the user has installed; the system prompt lists \
             each available skill by name and one-line summary, but NOT its body. When a task \
             matches a listed skill, call this with that skill's exact name to load its detailed \
             steps before you proceed — don't guess the procedure. Only names shown in the \
             available-skills list will load."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Skill name" },
                "path": { "type": "string", "description": "Optional package-relative file under references/, templates/, scripts/, or assets/" }
            },
            "required": ["name"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "The exact name of the skill to load, as shown in the available-skills list in your context; unknown names do not load" },
                "path": { "type": "string", "description": "Optional relative support-file path under references/, templates/, scripts/, or assets/; traversal is rejected" }
            },
            "required": ["name"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_input("`name` is required"))?;
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let extended = load_extended(&ctx.cwd);
        let activation = crate::skills::ActivationContext::from_tool_names(
            ctx.available_tools.iter().map(String::as_str),
        );
        let store = crate::credentials::CredentialStore::open_default().ok();
        load_skill_for_session(
            name,
            path,
            &ctx.cwd,
            &extended,
            &ctx.redact,
            &activation,
            &ctx.env_overlay,
            store.as_ref(),
        )
    }
}

/// Discover + load + render the named skill. Split out from [`call`] so
/// tests can supply an explicit [`ExtendedConfig`] instead of depending
/// on the host's layered config discovery.
#[cfg(test)]
fn load_skill_into_output(
    name: &str,
    cwd: &std::path::Path,
    extended: &ExtendedConfig,
    redact: &crate::redact::RedactionTable,
) -> Result<ToolOutput> {
    let activation = crate::skills::ActivationContext {
        platform: if cfg!(target_os = "macos") {
            "macos".to_string()
        } else if cfg!(target_os = "windows") {
            "windows".to_string()
        } else {
            std::env::consts::OS.to_string()
        },
        ..Default::default()
    };
    load_skill_for_session(
        name,
        None,
        cwd,
        extended,
        redact,
        &activation,
        &std::sync::RwLock::new(std::collections::HashMap::new()),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn load_skill_for_session(
    name: &str,
    path: Option<&str>,
    cwd: &std::path::Path,
    extended: &ExtendedConfig,
    redact: &crate::redact::RedactionTable,
    activation: &crate::skills::ActivationContext,
    env_overlay: &std::sync::RwLock<std::collections::HashMap<String, String>>,
    store: Option<&crate::credentials::CredentialStore>,
) -> Result<ToolOutput> {
    let skills =
        crate::skills::discover_for_session(cwd, &extended.skills, activation).unwrap_or_default();

    let Some(skill) = crate::skills::find_by_name(&skills, name) else {
        let available = if skills.is_empty() {
            "(none discovered)".to_string()
        } else {
            skills
                .iter()
                .map(|s| s.frontmatter.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(invalid_input(format!(
            "unknown skill `{name}`; available: {available}"
        )));
    };

    let missing = hydrate_required_environment(skill, env_overlay, store);
    let setup_note = if missing.is_empty() {
        String::new()
    } else {
        format!(
            "\n\n[skill setup: named secrets not configured: {}]",
            missing.join(", ")
        )
    };

    if let Some(path) = path {
        let body = crate::skills::load_support_file(skill, std::path::Path::new(path))
            .map_err(|e| invalid_input(format!("loading support file `{path}`: {e}")))?;
        return Ok(ToolOutput::text(format!(
            "Skill `{name}` support file `{path}`:\n\n{body}{setup_note}"
        )));
    }

    let body = crate::skills::load_body(skill)
        .map_err(|e| anyhow::anyhow!("loading skill `{name}`: {e}"))?;
    let rendered =
        crate::skills::render_body(&body, cwd, extended.skills.auto_bang_commands, redact);
    Ok(ToolOutput::text(format!(
        "Skill `{name}`:\n\n{rendered}{setup_note}"
    )))
}

/// Resolve declared skill credentials through the existing named-secret store
/// and place them in the session overlay used by shell tools. Raw values never
/// enter tool output or model context; absent entries remain non-blocking.
fn hydrate_required_environment(
    skill: &crate::skills::Skill,
    env_overlay: &std::sync::RwLock<std::collections::HashMap<String, String>>,
    store: Option<&crate::credentials::CredentialStore>,
) -> Vec<String> {
    let mut missing = Vec::new();
    let mut overlay = env_overlay.write().unwrap_or_else(|err| err.into_inner());
    for declaration in &skill.frontmatter.required_environment_variables {
        let name = declaration.name.trim();
        if name.is_empty() || overlay.contains_key(name) || std::env::var_os(name).is_some() {
            continue;
        }
        if let Some(value) = store.and_then(|store| store.named_secret(name)) {
            overlay.insert(name.to_string(), value.to_string());
        } else {
            missing.push(name.to_string());
        }
    }
    missing
}

/// Load the effective `config.json` for `cwd` (first existing on
/// the layered-config path; seeded skills defaults on a fresh install with
/// none on disk). See [`crate::config::extended::load_for_cwd`].
fn load_extended(cwd: &std::path::Path) -> ExtendedConfig {
    crate::config::extended::load_for_cwd(cwd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extended::SkillsConfig;

    fn no_redact(root: &std::path::Path) -> crate::redact::RedactionTable {
        crate::redact::RedactionTable::build(
            &crate::config::extended::RedactConfig::default(),
            root,
        )
        .unwrap()
    }

    fn write_skill(root: &std::path::Path, name: &str, frontmatter: &str, body: &str) {
        let sub = root.join(name);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("SKILL.md"), format!("{frontmatter}{body}")).unwrap();
    }

    fn cfg_for(scan: &std::path::Path, auto_bang: bool) -> ExtendedConfig {
        ExtendedConfig {
            skills: SkillsConfig {
                scan_dirs: vec![scan.to_string_lossy().into_owned()],
                external_dirs: Vec::new(),
                auto_bang_commands: auto_bang,
                ancestor_walk: false,
                write_approval: false,
            },
            ..Default::default()
        }
    }

    #[test]
    fn loads_skill_body_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(
            &scan,
            "deploy",
            "---\nname: deploy\ndescription: deploy steps\n---\n",
            "Run the deploy checklist.",
        );
        let out = load_skill_into_output(
            "deploy",
            tmp.path(),
            &cfg_for(&scan, false),
            &no_redact(tmp.path()),
        )
        .unwrap();
        assert!(out.content.contains("Skill `deploy`"));
        assert!(out.content.contains("Run the deploy checklist."));
    }

    #[test]
    fn unknown_skill_is_invocation_error() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        let err = load_skill_into_output(
            "nope",
            tmp.path(),
            &cfg_for(&scan, false),
            &no_redact(tmp.path()),
        )
        .unwrap_err();
        assert_eq!(
            crate::engine::tool::classify_failure(&err),
            crate::engine::tool::ToolFailKind::Invocation
        );
    }

    #[test]
    fn codex_mode_injects_bang_command_verbatim() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(
            &scan,
            "ver",
            "---\nname: ver\ndescription: version\n---\n",
            "current: !`echo SHOULD_NOT_RUN`",
        );
        let out = load_skill_into_output(
            "ver",
            tmp.path(),
            &cfg_for(&scan, false),
            &no_redact(tmp.path()),
        )
        .unwrap();
        assert!(
            out.content.contains("!`echo SHOULD_NOT_RUN`"),
            "Codex mode keeps the directive verbatim, got {:?}",
            out.content
        );
    }

    #[test]
    fn claude_mode_runs_bang_command() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(
            &scan,
            "ver",
            "---\nname: ver\ndescription: version\n---\n",
            "current: !`echo RAN_OK`",
        );
        let out = load_skill_into_output(
            "ver",
            tmp.path(),
            &cfg_for(&scan, true),
            &no_redact(tmp.path()),
        )
        .unwrap();
        assert!(
            out.content.contains("current: RAN_OK"),
            "Claude mode substitutes stdout, got {:?}",
            out.content
        );
        assert!(!out.content.contains("!`echo"));
    }

    #[test]
    fn support_file_loads_through_skill_tool_path() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        write_skill(
            &scan,
            "package",
            "---\nname: package\ndescription: Package\n---\n",
            "Body",
        );
        std::fs::create_dir_all(scan.join("package/references")).unwrap();
        std::fs::write(scan.join("package/references/foo.md"), "Reference body").unwrap();
        let activation =
            crate::skills::ActivationContext::from_tool_names(std::iter::empty::<&str>());
        let overlay = std::sync::RwLock::new(std::collections::HashMap::new());

        let out = load_skill_for_session(
            "package",
            Some("references/foo.md"),
            tmp.path(),
            &cfg_for(&scan, false),
            &no_redact(tmp.path()),
            &activation,
            &overlay,
            None,
        )
        .unwrap();
        assert!(out.content.contains("Reference body"));

        let err = load_skill_for_session(
            "package",
            Some("references/../SKILL.md"),
            tmp.path(),
            &cfg_for(&scan, false),
            &no_redact(tmp.path()),
            &activation,
            &overlay,
            None,
        )
        .unwrap_err();
        assert_eq!(
            crate::engine::tool::classify_failure(&err),
            crate::engine::tool::ToolFailKind::Invocation
        );
    }

    #[test]
    fn skill_secret_env_uses_secret_ref_store() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        write_skill(
            &scan,
            "credentialed",
            "---\nname: credentialed\ndescription: Credentialed\nrequired_environment_variables:\n  - name: SKILL_API_KEY\n    prompt: API key\n---\n",
            "Use $SKILL_API_KEY without printing it.",
        );
        let mut store =
            crate::credentials::CredentialStore::open(tmp.path().join("credentials.json")).unwrap();
        store.set_named_secret("SKILL_API_KEY", "secret-from-store");
        let activation =
            crate::skills::ActivationContext::from_tool_names(std::iter::empty::<&str>());
        let overlay = std::sync::RwLock::new(std::collections::HashMap::new());

        let out = load_skill_for_session(
            "credentialed",
            None,
            tmp.path(),
            &cfg_for(&scan, false),
            &no_redact(tmp.path()),
            &activation,
            &overlay,
            Some(&store),
        )
        .unwrap();
        assert_eq!(
            overlay
                .read()
                .unwrap()
                .get("SKILL_API_KEY")
                .map(String::as_str),
            Some("secret-from-store")
        );
        assert!(!out.content.contains("secret-from-store"));
        assert!(!out.content.contains("named secrets not configured"));
    }
}
