//! Built-in custom-tool templates shared by runtime tool registration and settings UI.

use crate::config::extended::ToolCommandTemplate;

/// Built-in custom-tool names surfaced in settings and registered by the
/// agent runtime.
pub fn builtin_tool_names() -> &'static [&'static str] {
    &["webfetch", "websearch"]
}

/// Default bash command + description for a built-in custom tool. The
/// defaults rely only on widely-available CLI utilities (`curl`, `ddgr`) so a
/// user can land a working tool without configuring anything.
pub fn default_template_for(name: &str) -> ToolCommandTemplate {
    match name {
        "webfetch" => ToolCommandTemplate {
            enabled: true,
            command:
                "curl -sSL --max-time 20 --max-filesize 2000000 --user-agent 'cockpit-cli' {url}"
                    .to_string(),
            description: Some(
                "Fetch a URL. Pass `url` (the target). Returns the response body. For dependency API usage, use docs when uncertain; web is for what `docs` can't answer (news, non-package info).".to_string(),
            ),
        },
        "websearch" => ToolCommandTemplate {
            enabled: true,
            command: "ddgr --json --num 8 -- {query}".to_string(),
            description: Some(
                "Search the web. Pass `query`. Returns JSON results from DuckDuckGo. For dependency API usage, use docs when uncertain; web is for what `docs` can't answer (news, non-package info).".to_string(),
            ),
        },
        _ => ToolCommandTemplate {
            enabled: true,
            command: String::new(),
            description: None,
        },
    }
}
