//! User-defined bash-command tools (`webfetch`, `websearch`, …).
//!
//! Built from a [`crate::config::extended::ToolCommandTemplate`]: the
//! `command` field is a shell template with `{placeholder}` markers; each
//! distinct placeholder becomes a string parameter the model must supply.
//! At call time we substitute the args back in (shell-escaped) and run
//! the result through `/bin/sh -c`.
//! Custom tools are user-authored, unconfined shell templates; `sh -c`
//! templates are dangerous.
//!
//! Token economy (project guidance): ordinary custom-tool descriptions are whatever
//! the user typed in `config.json`'s `tools.<name>.description`. The built-in
//! web tools are the exception: their model-facing descriptions stay
//! backend-neutral even when their runtime command is Firecrawl/TinyFish/etc.

use std::collections::BTreeSet;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::config::extended::ToolCommandTemplate;
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, ToolOutputSidecar};
use crate::tools::common::{OUTPUT_BYTE_CAP, truncate_head_tail};

const SHELL_TIMEOUT_SECS: u64 = 30;
pub(crate) const WEBFETCH: &str = "webfetch";
pub(crate) const WEBSEARCH: &str = "websearch";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolTemplateProvenance {
    Configured { source: String },
}

impl ToolTemplateProvenance {
    fn kind(&self) -> &'static str {
        match self {
            ToolTemplateProvenance::Configured { .. } => "configured",
        }
    }

    fn source(&self) -> String {
        match self {
            ToolTemplateProvenance::Configured { source } => source.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct SelectedTemplate {
    tpl: ToolCommandTemplate,
    provenance: ToolTemplateProvenance,
}

pub struct CustomBashTool {
    name: String,
    description: String,
    template: String,
    build_provenance: ToolTemplateProvenance,
    /// Stable-ordered list of placeholder names the template uses.
    params: Vec<String>,
}

impl CustomBashTool {
    pub fn from_template_with_provenance(
        name: &str,
        tpl: &ToolCommandTemplate,
        provenance: ToolTemplateProvenance,
    ) -> Self {
        let params = extract_placeholders(&tpl.command);
        let description = neutral_web_description(name)
            .map(str::to_string)
            .or_else(|| tpl.description.clone().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| synth_description(name, &params));
        Self {
            name: name.to_string(),
            description,
            template: tpl.command.clone(),
            build_provenance: provenance,
            params,
        }
    }

    fn build_schema(&self) -> Value {
        let mut props = serde_json::Map::new();
        for p in &self.params {
            props.insert(
                p.clone(),
                serde_json::json!({
                    "type": "string",
                    "description": self.param_description(p)
                }),
            );
        }
        serde_json::json!({
            "type": "object",
            "properties": props,
            "required": self.params.clone(),
        })
    }

    fn param_description(&self, param: &str) -> String {
        match (self.name.as_str(), param) {
            (WEBFETCH, "url") => "URL to fetch.".to_string(),
            (WEBSEARCH, "query") => "Search query.".to_string(),
            _ => format!("Value substituted for `{{{param}}}` in the bash template."),
        }
    }

    fn selected_template(&self) -> SelectedTemplate {
        SelectedTemplate {
            tpl: ToolCommandTemplate {
                enabled: true,
                command: self.template.clone(),
                description: Some(self.description.clone()),
            },
            provenance: self.build_provenance.clone(),
        }
    }
}

#[async_trait]
impl Tool for CustomBashTool {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn parameters(&self) -> Value {
        self.build_schema()
    }

    fn binary_requirements(&self) -> Vec<crate::capabilities::BinaryRequirement> {
        first_template_program(&self.template)
            .filter(|program| !program.contains('/') && !program.contains('\\'))
            .filter(|program| !program.contains('{') && !program.contains('}'))
            .map(|program| {
                vec![crate::capabilities::BinaryRequirement::required(
                    program,
                    crate::capabilities::common_remedy(program),
                )]
            })
            .unwrap_or_default()
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let selected = self.selected_template();
        if !selected.tpl.enabled || selected.tpl.command.trim().is_empty() {
            return Ok(ToolOutput::text(format!(
                "Error: tool `{}` is disabled or has no command in the current effective config.\nprovenance: {}\nsource: {}",
                self.name,
                selected.provenance.kind(),
                selected.provenance.source(),
            ))
            .with_output_sidecar(self.provenance_sidecar(&selected, None, false)));
        }

        let params = extract_placeholders(&selected.tpl.command);
        let mut cmd = selected.tpl.command.clone();
        for p in &params {
            let raw = args.get(p).and_then(Value::as_str).unwrap_or("");
            let quoted = shell_quote(raw);
            cmd = cmd.replace(&format!("{{{p}}}"), &quoted);
        }

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(SHELL_TIMEOUT_SECS),
            tokio::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&cmd)
                .output(),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("tool `{}` timed out after {SHELL_TIMEOUT_SECS}s", self.name)
        })??;

        let mut combined = String::new();
        combined.push_str(&String::from_utf8_lossy(&output.stdout));
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let missing_binary = output.status.code().and_then(|code| {
                crate::tools::bash::missing_binary_from_shell_failure(code, &stderr)
            });
            combined.push_str(&render_failure_diagnostic(
                &self.name,
                &selected,
                output.status.code(),
                ctx,
            ));
            combined.push_str(
                &crate::tools::bash::cockpit_command_environment_block_with_requirements(
                    &cmd,
                    &ctx.cwd,
                    output
                        .status
                        .code()
                        .as_ref()
                        .map(|code| code.to_string())
                        .as_deref(),
                    None,
                    missing_binary.as_deref(),
                    self.binary_requirements(),
                ),
            );
            combined.push_str("\n[stderr]\n");
            combined.push_str(&stderr);
        }

        let changed_after_build = false;
        if combined.len() > OUTPUT_BYTE_CAP {
            // Byte-boundary-safe; `String::truncate` would panic on a
            // multibyte boundary. Head+tail keeps any appended stderr.
            return Ok(
                ToolOutput::truncated_text(truncate_head_tail(&combined, OUTPUT_BYTE_CAP))
                    .with_output_sidecar(self.provenance_sidecar(
                        &selected,
                        output.status.code(),
                        changed_after_build,
                    )),
            );
        }
        Ok(
            ToolOutput::text(combined).with_output_sidecar(self.provenance_sidecar(
                &selected,
                output.status.code(),
                changed_after_build,
            )),
        )
    }
}

impl CustomBashTool {
    fn provenance_sidecar(
        &self,
        selected: &SelectedTemplate,
        exit_code: Option<i32>,
        settings_changed_after_toolbox_build: bool,
    ) -> ToolOutputSidecar {
        ToolOutputSidecar {
            payload: serde_json::json!({
                "kind": "custom_bash_tool",
                "tool": self.name,
                "model_description": self.description,
                "selected_command_template": selected.tpl.command,
                "provenance": selected.provenance.kind(),
                "source": selected.provenance.source(),
                "toolbox_build_command_template": self.template,
                "toolbox_build_provenance": self.build_provenance.kind(),
                "toolbox_build_source": self.build_provenance.source(),
                "settings_changed_after_toolbox_build": settings_changed_after_toolbox_build,
                "exit_code": exit_code,
            }),
        }
    }
}

fn render_failure_diagnostic(
    name: &str,
    selected: &SelectedTemplate,
    exit_code: Option<i32>,
    _ctx: &ToolCtx,
) -> String {
    format!(
        "\n[tool diagnostic]\ntool: {name}\nselected_command_template: {}\nprovenance: {}\nsource: {}\nexit_code: {}\n",
        selected.tpl.command,
        selected.provenance.kind(),
        selected.provenance.source(),
        exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_string()),
    )
}

fn first_template_program(template: &str) -> Option<&str> {
    template.split_whitespace().next().filter(|s| !s.is_empty())
}

pub(crate) fn neutral_web_description(name: &str) -> Option<&'static str> {
    match name {
        WEBFETCH => Some(
            "Fetch a URL. Returns page content. Prefer docs for dependency APIs when available.",
        ),
        WEBSEARCH => Some(
            "Search the web. Returns search results. Prefer docs for dependency APIs when available.",
        ),
        _ => None,
    }
}

/// Pull every `{placeholder}` token from the template. Order = first
/// appearance, deduplicated.
fn extract_placeholders(template: &str) -> Vec<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(end) = template[i + 1..].find('}')
        {
            let name = &template[i + 1..i + 1 + end];
            if is_ident(name) && !seen.contains(name) {
                seen.insert(name.to_string());
                out.push(name.to_string());
            }
            i += end + 2;
            continue;
        }
        i += 1;
    }
    out
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// POSIX single-quote escape. The model-supplied value lands inside the
/// template verbatim — no shell expansion, no env interpolation.
fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | ':' | '.' | '@' | '+' | '%')
    }) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

fn synth_description(name: &str, params: &[String]) -> String {
    if params.is_empty() {
        format!("Run the configured `{name}` command.")
    } else {
        let plist = params
            .iter()
            .map(|p| format!("`{p}`"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("Run the configured `{name}` command. Args: {plist}.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::engine::tool::Tool;

    #[test]
    fn placeholder_extraction_finds_named_tokens_once() {
        let tpl = "curl -sSL --max-time {timeout} {url} | head -c {bytes} # ignore {timeout}";
        let p = extract_placeholders(tpl);
        assert_eq!(
            p,
            vec![
                "timeout".to_string(),
                "url".to_string(),
                "bytes".to_string()
            ]
        );
    }

    #[test]
    fn placeholder_extraction_skips_non_ident() {
        // `{ }` and `{a b}` aren't valid placeholders; we leave them as
        // literal command text.
        let tpl = "echo {a b} {valid} {}";
        let p = extract_placeholders(tpl);
        assert_eq!(p, vec!["valid".to_string()]);
    }

    #[test]
    fn custom_bash_declares_first_template_program_as_required_binary() {
        let tpl = ToolCommandTemplate {
            enabled: true,
            command: "firecrawl search {query}".into(),
            description: None,
        };
        let tool = CustomBashTool::from_template_with_provenance(
            "websearch",
            &tpl,
            ToolTemplateProvenance::Configured {
                source: "test".to_string(),
            },
        );

        let requirements = tool.binary_requirements();

        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].name, "firecrawl");
        assert_eq!(
            requirements[0].kind,
            crate::capabilities::BinaryRequirementKind::Required
        );
    }

    #[test]
    fn shell_quote_passes_through_safe_chars() {
        assert_eq!(shell_quote("hello"), "hello");
        assert_eq!(shell_quote("path/to-file.rs"), "path/to-file.rs");
        assert_eq!(shell_quote("user@host"), "user@host");
    }

    #[test]
    fn shell_quote_wraps_dangerous_chars() {
        assert_eq!(shell_quote("hi there"), "'hi there'");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(shell_quote("it's a trap"), "'it'\\''s a trap'");
    }

    #[test]
    fn schema_has_required_string_params() {
        let tpl = ToolCommandTemplate {
            enabled: true,
            command: "echo {who}".into(),
            description: None,
        };
        let tool = CustomBashTool::from_template_with_provenance(
            "greet",
            &tpl,
            ToolTemplateProvenance::Configured {
                source: "test".to_string(),
            },
        );
        let schema = tool.build_schema();
        assert_eq!(schema["required"], serde_json::json!(["who"]));
        assert_eq!(schema["properties"]["who"]["type"], "string");
    }

    #[test]
    fn web_tool_schema_is_backend_neutral_for_configured_template() {
        let tpl = ToolCommandTemplate {
            enabled: true,
            command: "firecrawl search --json --limit 8 {query}".into(),
            description: Some("Search using Firecrawl and DuckDuckGo fallback.".into()),
        };
        let tool = CustomBashTool::from_template_with_provenance(
            "websearch",
            &tpl,
            ToolTemplateProvenance::Configured {
                source: "test".to_string(),
            },
        );
        let desc = tool.description().to_lowercase();
        assert!(!desc.contains("firecrawl"));
        assert!(!desc.contains("duckduckgo"));
        assert!(!desc.contains("curl"));

        let schema = tool.parameters();
        let param_desc = schema["properties"]["query"]["description"]
            .as_str()
            .unwrap()
            .to_lowercase();
        assert_eq!(param_desc, "search query.");
        assert!(!param_desc.contains("bash"));
        assert!(!param_desc.contains("template"));
    }

    #[test]
    fn web_tool_schema_is_backend_neutral_for_registered_web_template() {
        let tpl = ToolCommandTemplate {
            enabled: true,
            command: "custom-search {query}".into(),
            description: None,
        };
        let tool = CustomBashTool::from_template_with_provenance(
            "websearch",
            &tpl,
            ToolTemplateProvenance::Configured {
                source: "web.custom.search_command".to_string(),
            },
        );
        let desc = tool.description().to_lowercase();
        assert_eq!(
            desc,
            neutral_web_description("websearch").unwrap().to_lowercase()
        );
        assert_eq!(
            tool.parameters()["properties"]["query"]["description"],
            serde_json::json!("Search query.")
        );
    }

    #[tokio::test]
    async fn custom_web_call_uses_registered_template_without_runtime_refresh() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let ctx = crate::tools::common::test_ctx(cwd);
        let bin_dir = cwd.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let registered = bin_dir.join("registered-fetch");
        std::fs::write(&registered, "#!/bin/sh\nprintf 'registered:%s\\n' \"$*\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&registered).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&registered, perms).unwrap();
        }
        let tpl = ToolCommandTemplate {
            enabled: true,
            command: format!("{} {{url}}", registered.display()),
            description: None,
        };
        let tool = CustomBashTool::from_template_with_provenance(
            "webfetch",
            &tpl,
            ToolTemplateProvenance::Configured {
                source: "web.custom.fetch_command".to_string(),
            },
        );

        let cockpit = cwd.join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "web": {
                    "provider": "custom",
                    "custom": {
                        "fetch_command": "different-fetch {url}"
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let out = tool
            .call(serde_json::json!({"url": "https://example.test"}), &ctx)
            .await
            .unwrap();

        assert!(out.content.contains("registered:"));
        let sidecar = out.output_sidecar.unwrap().payload;
        assert_eq!(sidecar["provenance"], "configured");
        assert_eq!(sidecar["settings_changed_after_toolbox_build"], false);
    }

    #[tokio::test]
    async fn missing_configured_executable_reports_template_provenance_and_stderr() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let ctx = crate::tools::common::test_ctx(cwd);
        let tpl = ToolCommandTemplate {
            enabled: true,
            command: "cockpit-definitely-missing-websearch {query}".into(),
            description: None,
        };
        let tool = CustomBashTool::from_template_with_provenance(
            "websearch",
            &tpl,
            ToolTemplateProvenance::Configured {
                source: "web.custom.search_command".to_string(),
            },
        );

        let out = tool
            .call(serde_json::json!({"query": "weather"}), &ctx)
            .await
            .unwrap();

        assert!(out.content.contains("[tool diagnostic]"));
        assert!(out.content.contains("tool: websearch"));
        assert!(
            out.content.contains(
                "selected_command_template: cockpit-definitely-missing-websearch {query}"
            )
        );
        assert!(out.content.contains("provenance: configured"));
        assert!(
            out.content
                .contains("missing_binary: cockpit-definitely-missing-websearch")
        );
        assert!(out.content.contains(
            "remedy: Install `cockpit-definitely-missing-websearch` and ensure it is on PATH."
        ));
        assert!(out.content.contains("[stderr]"));
        assert!(out.content.contains("cockpit-definitely-missing-websearch"));
    }
}
