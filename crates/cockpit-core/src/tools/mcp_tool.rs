//! The `mcp` tool — executes a model-authored Python script in the Monty
//! sandbox (GOALS §18a, monty mode).
//!
//! The script reaches enabled MCP servers through host functions
//! exposed inside the sandbox: `mcp.search(query)`,
//! `mcp.grep_tool_names(regex)`, `mcp.grep_tool_definitions(regex)`,
//! `mcp.describe(server, tool)`, and `mcp.invoke(server, tool, args)`.
//! `emit`, `show`, `notify`, and `attach` project values into host-owned lanes.
//! If `emit` is unused, the final value or captured `print(...)` output remains
//! the model fallback. The VM has no direct
//! filesystem, network, or environment access; host functions remain subject to the same
//! authorization as native tool calls.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::engine::agent::TurnEvent;
use crate::engine::tool::{Tool, ToolArtifactLane, ToolBox, ToolCtx, ToolOutput, invalid_input};
use crate::intel::budget::capture_text_artifact_body;
use crate::tools::common::{OUTPUT_BYTE_CAP, truncate_head_tail};

pub struct McpTool;

/// A cancelled tool future drops its stack-local state before the dispatcher
/// invokes [`Tool::on_abandon`]. Keep opaque-effect accounting here, keyed by
/// the dispatcher-owned context, so the abandonment hook can synchronously
/// refresh identity hashes before the dispatcher reports completion.
static ABANDONED_MCP_IDENTITY_ACCOUNTING: LazyLock<
    Mutex<HashMap<usize, crate::assistants::identity::IdentityShellAccounting>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn identity_accounting_key(ctx: &ToolCtx) -> usize {
    // The timeout dispatcher owns this exact context for one in-flight call
    // and passes the same reference to `call` and `on_abandon`. Unlike an
    // optional provider call id, it is present on every dispatcher entry.
    ctx as *const ToolCtx as usize
}

const NORMAL_DESCRIPTION: &str = "Run Python over native tools. Example: r=mcp.invoke('cockpit','read',{'path':'README.md'}); emit(r). Discover with mcp.search, mcp.grep_tool_names, mcp.grep_tool_definitions, or mcp.describe.";
const DEFENSIVE_DESCRIPTION: &str = "Execute a Python script in an isolated sandbox to reach MCP tools. Inside the \
     script call `mcp.search(query)` for cheap discovery (returns dicts with server, tool, \
     and description), `mcp.grep_tool_names(regex)` for cheap name-only regex discovery, \
     `mcp.grep_tool_definitions(regex)` for heavier regex discovery across names, descriptions, \
     and serialized input schemas, `mcp.describe(server, tool)` when you need one tool's full \
     input schema, and `mcp.invoke(server, tool, args)` to call one. Search or grep before \
     concluding a capability is missing. Native cockpit tools are always scriptable, for example \
     `mcp.invoke(\"cockpit\", \"read\", {\"path\": \"README.md\"})`; non-cockpit servers require \
     the `mcp` grant. Raw invoke results stay in the sandbox. Project only what the model needs \
     with `emit(x)`; the host serializes strings or JSON-able objects. For example: \
     `r = mcp.invoke(\"cockpit\", \"read\", {\"path\": \"README.md\"}); emit(r)`. Use \
     `show(x)` for persisted display-only content, `notify(s)` for a human-only notice, and \
     `attach(x)` for an artifact. If no value is emitted, the final expression is returned. \
     For batch invokes, wrap each `mcp.invoke` in try/except and collect per-item \
     `{ok|err}` results so one failure does not abort the loop. If the script returns `None`, \
     printed output is captured and returned as a fallback. The VM has no direct filesystem, \
     network, or environment access; every host function remains subject to the same authorization as a native tool call.";

pub(crate) async fn turn_start_advert_message(
    _toolbox: &ToolBox,
    session: &crate::session::Session,
) -> Option<String> {
    let mut adverts = Vec::new();
    if session
        .db
        .current_session_goal(session.id, false)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        adverts.push(
            "A goal is active; if context pressure builds (check mcp.invoke(\"cockpit\", \"context_usage\", {})), you may schedule compaction via mcp.invoke(\"cockpit\", \"request_compact\", {})."
                .to_string(),
        );
    }
    advert_message_from_lines(&adverts)
}

pub(crate) fn advert_message_from_lines(adverts: &[String]) -> Option<String> {
    if adverts.is_empty() {
        return None;
    }
    let advert_text = adverts
        .iter()
        .map(|line| format!("- {}", line.trim()))
        .collect::<Vec<_>>()
        .join("\n");
    Some(format!(
        "Available built-in cockpit functions:\n{advert_text}"
    ))
}

#[async_trait]
impl Tool for McpTool {
    fn name(&self) -> &str {
        "mcp"
    }

    fn description(&self) -> &str {
        NORMAL_DESCRIPTION
    }

    fn verbose_description(&self) -> Option<String> {
        Some(DEFENSIVE_DESCRIPTION.to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "script": { "type": "string", "description": "Python script; use emit(x) to project model context" }
            },
            "required": ["script"]
        })
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "script": {
                    "type": "string",
                    "description": "Python source using mcp.search, mcp.describe, and mcp.invoke; use emit(x) for model context, show(x) for display only, notify(s) for a human-only notice, and attach(x) for an artifact; with no emit, the final expression is returned and print(...) is the fallback when it is None"
                }
            },
            "required": ["script"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        // The normal tool dispatcher applies this fence too, but retain it at
        // the opaque MCP host boundary: a model-authored script can invoke any
        // configured third-party server, including one with filesystem or
        // command access. This also protects direct Tool callers from
        // bypassing the common dispatcher.
        crate::knowledge::ensure_workspace_tool_access(ctx, self.name()).await?;

        // The script may perform discovery as well as invocation. External
        // discovery can start a configured stdio MCP server, while native
        // cockpit calls stay within the ordinary native authority path.
        let identity_accounting =
            crate::assistants::identity::check_identity_opaque_host_effect(ctx, "MCP tools")
                .await?;

        let script = args
            .get("script")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`script` (a Python string) is required"))?;

        let accounting_key = identity_accounting_key(ctx);
        if let Some(accounting) = identity_accounting {
            let mut pending = ABANDONED_MCP_IDENTITY_ACCOUNTING
                .lock()
                .expect("MCP identity accounting mutex poisoned");
            anyhow::ensure!(
                !pending.contains_key(&accounting_key),
                "MCP identity accounting already registered for active tool call"
            );
            pending.insert(accounting_key, accounting);
        }

        let catalog = ctx.mcp_resolver.catalog();
        if catalog.has_reserved_builtin_server_config()
            && let Some(text) = ctx.session.mcp_reserved_cockpit_server_notice()
            && let Some(events) = &ctx.events
        {
            let _ = events.send(TurnEvent::Notice { text }).await;
        }
        let host = crate::mcp::builtin::HostContext::from_tool_ctx(ctx);
        let cfg = catalog.to_mcp_config();
        let result = match crate::mcp::sandbox::run_envelope_with_host(script, &cfg, &host).await {
            Ok(envelope) => Ok(rendered_result_output(envelope, ctx)),
            // Unhandled Monty compile/runtime/OS denial/import/host
            // exceptions are failed parent tool calls (`hard_fail`). Authored
            // try/except that returns a value remains Ok above. Do not infer
            // failure by inspecting successful result text.
            Err(e) => Err(e),
        };
        let accounting = ABANDONED_MCP_IDENTITY_ACCOUNTING
            .lock()
            .expect("MCP identity accounting mutex poisoned")
            .remove(&accounting_key);
        if let Some(accounting) = accounting {
            accounting.publish().await?;
        }
        result
    }

    async fn on_abandon(&self, ctx: &ToolCtx) -> Result<()> {
        let accounting = ABANDONED_MCP_IDENTITY_ACCOUNTING
            .lock()
            .expect("MCP identity accounting mutex poisoned")
            .remove(&identity_accounting_key(ctx));
        // `run_abandon_hook` bounds every tool hook. Retain the token in an
        // abort-safe guard so that bound cannot discard accounting after the
        // MCP server may already have committed a write.
        let accounting = crate::assistants::identity::IdentityAccountingGuard::new(accounting);
        let scope = crate::mcp::transport::stdio::StdioAbandonScope {
            session_id: ctx.session.id,
            tool_call_id: ctx.current_tool_call_id.clone(),
        };
        crate::mcp::transport::stdio::poison_active_for_scope(&scope, "MCP tool abandon").await;
        // The server may already have committed an identity-file edit before
        // transport poisoning reaches it. Publish while the dispatcher still
        // owns abandonment so a subsequent session load cannot call that
        // model-owned partial effect an external edit.
        accounting.publish().await?;
        Ok(())
    }
}

fn rendered_result_output(
    envelope: crate::mcp::sandbox::ProjectionEnvelope,
    ctx: &ToolCtx,
) -> ToolOutput {
    let model = ctx.redact.scrub(&envelope.model_text()).into_owned();
    let display_lane = ctx.redact.scrub(&envelope.display_text()).into_owned();
    let attached = ctx
        .redact
        .scrub(&envelope.artifacts.join("\n"))
        .into_owned();
    let display = (!display_lane.is_empty()).then(|| {
        if model.is_empty() {
            display_lane
        } else {
            format!("{model}\n{display_lane}")
        }
    });

    let model_over_cap = model.len() > OUTPUT_BYTE_CAP;
    let model_inline = if model_over_cap {
        truncate_head_tail(&model, OUTPUT_BYTE_CAP)
    } else {
        model.clone()
    };
    let mut output = if model_over_cap {
        ToolOutput::truncated_text(model_inline)
    } else {
        ToolOutput::text(model_inline)
    };
    // Keep each envelope lane independent through dispatch. Model and display
    // candidates are automatic (threshold controlled by the host policy),
    // while `attach` is an explicit durable request. This prevents either
    // non-model lane from replacing what `emit` selected for model history.
    if !model.is_empty() {
        output = output.with_text_artifact_lane(
            ToolArtifactLane::Model,
            capture_text_artifact_body(&model),
            model_over_cap,
        );
    }
    if !display_lane.is_empty() {
        output = output.with_text_artifact_lane(
            ToolArtifactLane::Display,
            capture_text_artifact_body(&display_lane),
            display_lane.len() > OUTPUT_BYTE_CAP,
        );
    }
    if !attached.is_empty() {
        output = output.with_text_artifact_lane(
            ToolArtifactLane::Attachment,
            capture_text_artifact_body(&attached),
            true,
        );
    }

    if let Some(display) = display {
        output = output.with_model_ephemeral_display(truncate_head_tail(&display, OUTPUT_BYTE_CAP));
    }
    output.with_notices(envelope.notifications)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn projection_redaction_table(root: &std::path::Path) -> crate::redact::RedactionTable {
        let cfg = crate::config::extended::RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            placeholder: "[redacted]".to_string(),
            ..Default::default()
        };
        crate::redact::RedactionTable::build_with_env_and_secrets(
            &cfg,
            root,
            &HashMap::from([("API_TOKEN".to_string(), "monty-secret-value".to_string())]),
            Vec::<(String, String)>::new(),
        )
        .unwrap()
    }

    fn mcp_description(toolbox: &ToolBox, steering: crate::agents::ToolSteering) -> String {
        toolbox
            .definitions(steering)
            .into_iter()
            .find(|definition| definition.name == "mcp")
            .unwrap()
            .description
    }

    #[tokio::test]
    async fn mcp_does_not_spawn_configured_server_for_attached_local_kb() {
        let tmp = tempfile::tempdir().unwrap();
        let protected_root = tmp.path().join(".cockpit/knowledge");
        std::fs::create_dir_all(&protected_root).unwrap();
        let marker = tmp.path().join("mcp-server-spawned");

        let mut mcp_config = crate::mcp::config::McpConfig::default();
        mcp_config.servers.insert(
            "sentinel".to_string(),
            crate::mcp::config::ServerConfig {
                transport: crate::mcp::config::Transport::Stdio,
                endpoint: None,
                command: Some("sh".to_string()),
                args: vec!["-c".to_string(), format!("touch {}", marker.display())],
                env: Default::default(),
                env_credential_refs: Default::default(),
                auth: Default::default(),
                mode: Default::default(),
                enabled: true,
                cache_ttl_secs: 0,
                connect_timeout_secs: None,
                timeout_secs: None,
                profiles: Default::default(),
            },
        );

        let entry = crate::config::extended::KnowledgeBaseRegistryEntry::new(
            "private".to_string(),
            "Private".to_string(),
            "Private local knowledge".to_string(),
            crate::config::extended::KnowledgeBaseSource::Local {
                path: std::path::PathBuf::from(".cockpit/knowledge"),
            },
            crate::config::extended::KnowledgeBaseEmbeddingOwnership::Local,
            None,
            None,
            false,
            crate::config::extended::KnowledgeBaseMergePolicy::Auto,
        );
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.mcp_resolver = crate::mcp::resolver::EffectiveCatalogResolver::from_catalog(
            crate::mcp::resolver::EffectiveCatalog::from_mcp_config(&mcp_config),
        );
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                crate::config::extended::ExtendedConfig {
                    knowledge_bases: vec![entry],
                    ..Default::default()
                },
            ),
        );

        let error = McpTool
            .call(
                serde_json::json!({ "script": "mcp.invoke('sentinel', 'read', {})" }),
                &ctx,
            )
            .await
            .expect_err("MCP must be fenced before a configured server is spawned");

        assert!(error.to_string().contains("access denied"), "{error:#}");
        assert!(error.to_string().contains("mcp"), "{error:#}");
        assert!(
            error.to_string().contains(
                "MCP is unavailable because this workspace contains a local knowledge base"
            ),
            "{error:#}"
        );
        assert!(
            !marker.exists(),
            "the configured MCP server must not spawn before the local-KB host fence rejects it"
        );
    }

    #[test]
    fn tool_dispatch_does_not_call_mcp_config_discover() {
        let source = include_str!("mcp_tool.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(
            !production.contains("McpConfig::discover("),
            "mcp tool dispatch must use the effective-catalog resolver, not McpConfig::discover"
        );
    }

    #[test]
    fn description_is_one_sentence_terse() {
        let t = McpTool;
        assert!(t.description().len() <= 200, "terse budget");
        assert!(t.description().contains("mcp.search"));
        assert!(t.description().contains("mcp.grep_tool_names"));
        assert!(t.description().contains("mcp.grep_tool_definitions"));
        assert!(t.description().contains("mcp.describe"));
        assert!(t.description().contains("mcp.invoke"));
        assert!(t.description().contains("Python"));
    }

    #[test]
    fn parameters_require_script_string() {
        let p = McpTool.parameters();
        assert_eq!(p["required"], serde_json::json!(["script"]));
        assert_eq!(p["properties"]["script"]["type"], "string");
    }

    #[test]
    fn mcp_tool_over_cap_result_carries_text_artifact_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let body = "m".repeat(OUTPUT_BYTE_CAP + 32);

        let output = rendered_result_output(
            crate::mcp::sandbox::ProjectionEnvelope {
                model: vec![body.clone()],
                ..Default::default()
            },
            &ctx,
        );

        assert!(output.truncated);
        let capture = output
            .text_artifact_captures
            .iter()
            .find(|capture| capture.lane == ToolArtifactLane::Model)
            .expect("model capture for over-cap mcp result");
        assert_eq!(capture.capture.host_original_bytes, body.len());
        assert_eq!(capture.capture.content, body);
    }

    #[test]
    fn mcp_tool_under_cap_result_has_no_text_artifact_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let output = rendered_result_output(
            crate::mcp::sandbox::ProjectionEnvelope {
                model: vec!["small result".to_string()],
                ..Default::default()
            },
            &ctx,
        );

        assert!(!output.truncated);
        assert_eq!(output.text_artifact_captures.len(), 1);
        assert_eq!(
            output.text_artifact_captures[0].lane,
            ToolArtifactLane::Model
        );
    }

    #[test]
    fn projection_mapping_redacts_model_display_and_artifact_lanes() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.redact = Arc::new(projection_redaction_table(tmp.path()));
        let output = rendered_result_output(
            crate::mcp::sandbox::ProjectionEnvelope {
                model: vec!["model monty-secret-value".to_string()],
                display: vec!["display monty-secret-value".to_string()],
                artifacts: vec!["artifact monty-secret-value".to_string()],
                ..Default::default()
            },
            &ctx,
        );

        assert_eq!(output.content, "model [redacted]");
        let display = output.display_content.as_deref().unwrap();
        assert!(display.contains("model [redacted]"), "{display}");
        assert!(display.contains("display [redacted]"), "{display}");
        assert!(!display.contains("monty-secret-value"), "{display}");
        assert!(output.text_artifact_captures.iter().any(|capture| {
            capture.lane == ToolArtifactLane::Attachment
                && capture.capture.content == "artifact [redacted]"
        }));
    }

    #[test]
    fn oversized_display_lane_spills_without_changing_model_projection() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let display = "d".repeat(OUTPUT_BYTE_CAP + 64);
        let output = rendered_result_output(
            crate::mcp::sandbox::ProjectionEnvelope {
                model: vec!["small model result".to_string()],
                display: vec![display.clone()],
                ..Default::default()
            },
            &ctx,
        );

        assert_eq!(output.content, "small model result");
        assert!(output.display_content.as_ref().unwrap().len() <= OUTPUT_BYTE_CAP);
        assert!(output.text_artifact_captures.iter().any(|capture| {
            capture.lane == ToolArtifactLane::Display && capture.capture.content == display
        }));
    }

    #[test]
    fn attachment_and_automatic_lanes_do_not_replace_emit_projection() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let output = rendered_result_output(
            crate::mcp::sandbox::ProjectionEnvelope {
                model: vec!["exact model answer".to_owned()],
                display: vec!["display body".to_owned()],
                artifacts: vec!["attached body".to_owned()],
                ..Default::default()
            },
            &ctx,
        );

        assert_eq!(output.content, "exact model answer");
        assert!(
            output
                .text_artifact_captures
                .iter()
                .any(|capture| { capture.lane == ToolArtifactLane::Model && !capture.explicit })
        );
        assert!(
            output
                .text_artifact_captures
                .iter()
                .any(|capture| { capture.lane == ToolArtifactLane::Display && !capture.explicit })
        );
        assert!(output.text_artifact_captures.iter().any(|capture| {
            capture.lane == ToolArtifactLane::Attachment
                && capture.explicit
                && capture.capture.content == "attached body"
        }));
    }

    #[tokio::test]
    async fn show_and_notify_stay_out_of_model_content() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let output = McpTool
            .call(
                serde_json::json!({
                    "script": "emit('model only')\nshow({'detail': 'display only'})\nnotify('human only')"
                }),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(output.content, "model only");
        assert!(!output.content.contains("display only"));
        assert!(!output.content.contains("human only"));
        assert!(
            output
                .display_content
                .as_deref()
                .is_some_and(|display| display.contains("display only"))
        );
        assert_eq!(output.notices, vec!["human only"]);
    }

    #[test]
    fn defensive_text_mentions_final_expression_and_print_fallback() {
        let t = McpTool;
        let desc = t.verbose_description().unwrap();
        assert!(desc.contains("final expression"), "{desc}");
        assert!(desc.contains("printed output"), "{desc}");
        assert!(desc.contains("fallback"), "{desc}");

        let p = t.verbose_parameters().unwrap();
        let script_desc = p["properties"]["script"]["description"].as_str().unwrap();
        assert!(script_desc.contains("final expression"), "{script_desc}");
        assert!(script_desc.contains("print"), "{script_desc}");
        assert!(script_desc.contains("fallback"), "{script_desc}");
    }

    #[test]
    fn mcp_description_is_static_across_catalog_change() {
        let disabled = ToolBox::new().with(Arc::new(McpTool));
        let discoverable = ToolBox::new()
            .with(Arc::new(McpTool))
            .with_discoverable_mcp(Arc::new(crate::tools::intel::CodeTool));

        assert_eq!(
            mcp_description(&disabled, crate::agents::ToolSteering::Terse),
            mcp_description(&discoverable, crate::agents::ToolSteering::Terse)
        );
        assert_eq!(
            mcp_description(&disabled, crate::agents::ToolSteering::Verbose),
            mcp_description(&discoverable, crate::agents::ToolSteering::Verbose)
        );
    }

    #[test]
    fn mcp_description_has_no_advert_suffix() {
        let toolbox = ToolBox::new()
            .with(Arc::new(McpTool))
            .with_discoverable_mcp(Arc::new(crate::tools::intel::CodeTool));

        let normal = mcp_description(&toolbox, crate::agents::ToolSteering::Terse);
        let defensive = mcp_description(&toolbox, crate::agents::ToolSteering::Verbose);

        assert_eq!(normal, NORMAL_DESCRIPTION);
        assert_eq!(defensive, DEFENSIVE_DESCRIPTION);
        assert!(!normal.contains("Available built-in cockpit functions"));
        assert!(!defensive.contains("Available built-in cockpit functions"));
    }

    #[test]
    fn mcp_descriptions_teach_grep_functions() {
        for description in [NORMAL_DESCRIPTION, DEFENSIVE_DESCRIPTION] {
            assert!(description.contains("grep_tool_names"), "{description}");
            assert!(
                description.contains("grep_tool_definitions"),
                "{description}"
            );
        }
        assert!(
            DEFENSIVE_DESCRIPTION
                .contains("Search or grep before concluding a capability is missing"),
            "{DEFENSIVE_DESCRIPTION}"
        );
    }

    #[test]
    fn mcp_descriptions_teach_batch_isolation() {
        for description in [NORMAL_DESCRIPTION, DEFENSIVE_DESCRIPTION] {
            assert!(description.contains("try/except"), "{description}");
            assert!(description.contains("invoke"), "{description}");
        }
    }

    #[tokio::test]
    async fn model_context_invariance_with_child_events() {
        let tmp = tempfile::tempdir().unwrap();
        let tool = McpTool;
        let args = serde_json::json!({ "script": "mcp.search('context_usage')" });
        let plain_ctx = crate::tools::common::test_ctx(tmp.path());
        let mut child_ctx = crate::tools::common::test_ctx(tmp.path());
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        child_ctx.current_tool_call_id = Some("outer-mcp".to_string());
        child_ctx.events = Some(tx);

        let plain = tool.call(args.clone(), &plain_ctx).await.unwrap();
        let with_children = tool.call(args, &child_ctx).await.unwrap();

        assert_eq!(tool.description(), NORMAL_DESCRIPTION);
        assert_eq!(
            tool.verbose_description().as_deref(),
            Some(DEFENSIVE_DESCRIPTION)
        );
        assert_eq!(plain.content, with_children.content);
        assert_eq!(plain.truncated, with_children.truncated);
    }

    #[tokio::test]
    async fn advert_compact_follows_goal_state() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let toolbox = ToolBox::new().with(Arc::new(McpTool));

        ctx.session
            .db
            .create_session_goal(
                ctx.session.id,
                &ctx.session.project_id,
                "ship feature",
                None,
                None,
            )
            .await
            .unwrap();
        let message = turn_start_advert_message(&toolbox, &ctx.session)
            .await
            .unwrap();
        assert!(message.contains("request_compact"), "{message}");
        assert!(message.contains("context_usage"), "{message}");

        ctx.session
            .db
            .clear_session_goal(ctx.session.id)
            .await
            .unwrap();
        assert!(
            turn_start_advert_message(&toolbox, &ctx.session)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn config_cockpit_server_id_is_reserved() {
        let tmp = tempfile::tempdir().unwrap();
        let mcp_dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&mcp_dir).unwrap();
        std::fs::write(
            mcp_dir.join("mcp.json"),
            r#"{
              "servers": {
                "cockpit": {
                  "transport": "streamable",
                  "endpoint": "https://example.invalid/mcp"
                }
              }
            }"#,
        )
        .unwrap();

        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let mut ctx = crate::tools::common::test_ctx(tmp.path());
            let (tx, mut rx) = tokio::sync::mpsc::channel(4);
            ctx.events = Some(tx);

            let tool = McpTool;
            let output = tool
                .call(
                    serde_json::json!({ "script": "mcp.search('context_usage')" }),
                    &ctx,
                )
                .await
                .unwrap();
            let hits: Value = serde_json::from_str(&output.content).unwrap_or_else(|error| {
                panic!(
                    "mcp.search output should be JSON: {error}; output bytes: {:?}",
                    output.content.as_bytes()
                )
            });
            assert_no_configured_cockpit_hits(&hits, &output.content);
            let notice = rx.try_recv().expect("expected reserved-id notice");
            assert!(
                matches!(notice, TurnEvent::Notice { ref text } if text.contains("reserved")),
                "unexpected notice: {notice:?}"
            );

            let output = tool
                .call(
                    serde_json::json!({ "script": "mcp.search('context_usage')" }),
                    &ctx,
                )
                .await
                .unwrap();
            let hits: Value = serde_json::from_str(&output.content).unwrap_or_else(|error| {
                panic!(
                    "mcp.search output should be JSON: {error}; output bytes: {:?}",
                    output.content.as_bytes()
                )
            });
            assert_no_configured_cockpit_hits(&hits, &output.content);
            assert!(rx.try_recv().is_err(), "notice should be once per session");
        })
        .await;
    }

    fn assert_no_configured_cockpit_hits(hits: &Value, output: &str) {
        let configured_cockpit_hits = hits
            .as_array()
            .unwrap()
            .iter()
            .filter(|hit| hit["server"] == "cockpit")
            .filter(|hit| {
                !matches!(
                    hit["tool"].as_str(),
                    Some("rename_session" | "request_compact" | "context_usage")
                )
            })
            .count();
        assert_eq!(configured_cockpit_hits, 0, "{output}");
    }

    async fn call_script(script: &str) -> Result<ToolOutput> {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        McpTool
            .call(serde_json::json!({ "script": script }), &ctx)
            .await
    }

    async fn expect_parent_err(script: &str, label: &str) -> String {
        match call_script(script).await {
            Ok(out) => panic!(
                "{label}: expected Err parent, got Ok content={}",
                out.content
            ),
            Err(e) => e.to_string(),
        }
    }

    /// AC1: unhandled sandbox failures surface as parent Err through
    /// `McpTool::call` (not Ok text with a sandbox-error prefix).
    #[tokio::test]
    async fn sandbox_denies_filesystem() {
        let msg = expect_parent_err("open('/etc/passwd').read()", "filesystem")
            .await
            .to_lowercase();
        assert!(
            msg.contains("denied") || msg.contains("permission"),
            "filesystem must be denied via Err, got: {msg}"
        );
        assert!(
            !msg.contains("[mcp sandbox error]"),
            "must not wrap as Ok text: {msg}"
        );
    }

    #[tokio::test]
    async fn search_arg_must_be_string() {
        let msg = expect_parent_err("mcp.search(123)", "search arg").await;
        assert!(
            !msg.contains("[mcp sandbox error]"),
            "must not wrap as Ok text: {msg}"
        );
    }

    /// AC4: unhandled compile/runtime/denied/name/import/uncaught host
    /// errors fail the parent tool call. hard_fail / export state /
    /// ToolError lifecycle follow from parent Err classification.
    #[tokio::test]
    async fn mcp_unhandled_parent_failure() {
        let compile = expect_parent_err("def (", "compile").await;
        assert!(
            compile.to_lowercase().contains("compile")
                || compile.to_lowercase().contains("syntax")
                || compile.contains("Python"),
            "{compile}"
        );

        let runtime = expect_parent_err("1 / 0", "runtime").await;
        assert!(
            runtime.to_lowercase().contains("zero")
                || runtime.to_lowercase().contains("division")
                || runtime.to_lowercase().contains("sandbox"),
            "{runtime}"
        );

        let denied = expect_parent_err("open('/etc/passwd')", "denied").await;
        assert!(
            denied.to_lowercase().contains("denied")
                || denied.to_lowercase().contains("permission"),
            "{denied}"
        );

        let name = expect_parent_err("undefined_name", "name").await;
        assert!(
            name.contains("not defined") || name.to_lowercase().contains("name"),
            "{name}"
        );

        let import = expect_parent_err("import mcp", "import").await;
        assert!(
            import.contains("ModuleNotFoundError") || import.to_lowercase().contains("module"),
            "{import}"
        );
        assert!(
            import.contains(crate::mcp::sandbox::MCP_IMPORT_GUIDANCE)
                || import.contains("prebound"),
            "{import}"
        );

        let host = expect_parent_err("mcp.describe('nope', 'tool')", "uncaught host").await;
        assert!(
            host.to_lowercase().contains("describe")
                || host.to_lowercase().contains("sandbox")
                || host.to_lowercase().contains("unknown")
                || host.to_lowercase().contains("nope"),
            "{host}"
        );

        // Mirror tool_dispatch's Err branch: hard_fail=true, no exit_code,
        // export/TUI state "bad_call", ToolError event.
        let tmp = tempfile::tempdir().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.events = Some(tx);
        let session = ctx.session.clone();
        let call_id = "parent-mcp-fail".to_string();
        let err = McpTool
            .call(serde_json::json!({ "script": "1 / 0" }), &ctx)
            .await
            .expect_err("parent must Err");
        let raw_output = format!("Error: {err}");
        let hard_fail = true;
        // tool_dispatch maps every Err to hard_fail + ToolFailKind::Execution
        // (unless InvalidToolInput). In-process Monty has no process exit code.
        assert_eq!(
            crate::engine::tool::classify_failure(&err),
            crate::engine::tool::ToolFailKind::Execution
        );
        assert!(hard_fail);
        session
            .record_tool_call(crate::session::ToolCallRow {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                agent: "test".into(),
                call_id: call_id.clone(),
                parent_call_id: None,
                parent_child_index: None,
                identity: crate::session::ToolCallProviderIdentity::synthetic_cockpit_call(
                    &call_id, None,
                ),
                tool: "mcp".into(),
                mcp_server: None,
                path: None,
                original_input_json: serde_json::json!({ "script": "1 / 0" }),
                wire_input_json: serde_json::json!({ "script": "1 / 0" }),
                recovery: crate::db::tool_calls::Recovery::Clean,
                hard_fail,
                exit_code: None,
                sandbox_enabled: false,
                sandboxed: false,
                sandbox_unavailable_reason: None,
                output: raw_output.clone(),
                truncated: false,
                duration_ms: 0,
                shape_fingerprint: None,
                hint: None,
            })
            .await
            .unwrap();
        let _ = ctx
            .events
            .as_ref()
            .unwrap()
            .send(TurnEvent::ToolError {
                agent: "test".into(),
                call_id: call_id.clone(),
                tool: "mcp".into(),
                error: raw_output,
                kind: crate::engine::tool::ToolFailKind::Execution,
                seq: None,
            })
            .await;

        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap();
        let parent = rows.iter().find(|r| r.call_id == call_id).unwrap();
        assert!(parent.hard_fail, "lifecycle hard_fail");
        assert!(
            parent.exit_code.is_none(),
            "in-process Monty has no exit code"
        );
        // Export/TUI failed state (session/export/mod.rs tool_state_str).
        let export_state = if parent.hard_fail {
            "bad_call"
        } else {
            "success"
        };
        assert_eq!(export_state, "bad_call");
        let event = rx.try_recv().expect("ToolError lifecycle event");
        assert!(
            matches!(event, TurnEvent::ToolError { ref tool, .. } if tool == "mcp"),
            "{event:?}"
        );
    }

    /// AC7: successful results and MCP protocol error *payloads* stay Ok —
    /// no output-string heuristics that reclassify success as failure.
    #[tokio::test]
    async fn mcp_success_and_protocol_result_unchanged() {
        let ok = call_script("{'ok': True, 'error': 'looks scary but is data'}")
            .await
            .expect("success must stay Ok");
        assert!(ok.content.contains("\"ok\":true"), "{}", ok.content);
        assert!(
            ok.content.contains("looks scary"),
            "must not strip error-looking data: {}",
            ok.content
        );

        let caught = call_script(
            "\
try:
    mcp.describe('nope', 'tool')
    r = 'no-error'
except Exception:
    r = 'caught'
r",
        )
        .await
        .expect("caught host error is parent success");
        assert!(caught.content.contains("caught"), "{}", caught.content);
    }
}
