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
        "Load a named skill's instructions into context"
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
                "name": { "type": "string", "description": "Skill name" }
            },
            "required": ["name"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "The exact name of the skill to load, as shown in the available-skills list in your context; unknown names do not load" }
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

        let extended = load_extended(&ctx.cwd);
        load_skill_into_output(name, &ctx.cwd, &extended, &ctx.redact)
    }
}

/// Discover + load + render the named skill. Split out from [`call`] so
/// tests can supply an explicit [`ExtendedConfig`] instead of depending
/// on the host's layered config discovery.
fn load_skill_into_output(
    name: &str,
    cwd: &std::path::Path,
    extended: &ExtendedConfig,
    redact: &crate::redact::RedactionTable,
) -> Result<ToolOutput> {
    let skills = crate::skills::discover(cwd, &extended.skills).unwrap_or_default();

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

    let body = crate::skills::load_body(skill)
        .map_err(|e| anyhow::anyhow!("loading skill `{name}`: {e}"))?;
    let rendered =
        crate::skills::render_body(&body, cwd, extended.skills.auto_bang_commands, redact);
    Ok(ToolOutput::text(format!("Skill `{name}`:\n\n{rendered}")))
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

    fn no_redact() -> crate::redact::RedactionTable {
        crate::redact::RedactionTable::build(
            &crate::config::extended::RedactConfig::default(),
            std::path::Path::new("/"),
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
                auto_bang_commands: auto_bang,
                ancestor_walk: false,
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
        let out =
            load_skill_into_output("deploy", tmp.path(), &cfg_for(&scan, false), &no_redact())
                .unwrap();
        assert!(out.content.contains("Skill `deploy`"));
        assert!(out.content.contains("Run the deploy checklist."));
    }

    #[test]
    fn unknown_skill_is_invocation_error() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        let err = load_skill_into_output("nope", tmp.path(), &cfg_for(&scan, false), &no_redact())
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
        let out = load_skill_into_output("ver", tmp.path(), &cfg_for(&scan, false), &no_redact())
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
        let out =
            load_skill_into_output("ver", tmp.path(), &cfg_for(&scan, true), &no_redact()).unwrap();
        assert!(
            out.content.contains("current: RAN_OK"),
            "Claude mode substitutes stdout, got {:?}",
            out.content
        );
        assert!(!out.content.contains("!`echo"));
    }
}
