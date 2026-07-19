//! Host-owned MCP functions exposed through the reserved `cockpit` server id.
//!
//! These entries are never loaded from `.cockpit/mcp.json`: they are native
//! cockpit capabilities reached through Monty's existing `mcp.search`,
//! `mcp.describe`, and `mcp.invoke` path. The sandbox only sees JSON results;
//! session and database handles stay host-side in [`HostContext`].

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::engine::tool::{ContextUsageSnapshot, ToolCtx};
use crate::mcp::catalog::SearchHit;
use crate::mcp::protocol::{
    ToolDescriptor, sanitize_tool_description, sanitize_tool_descriptor, sanitize_tool_name,
};
use crate::session::Session;

pub const BUILTIN_SERVER_ID: &str = "cockpit";

#[derive(Clone)]
pub struct HostContext {
    #[allow(dead_code)]
    pub db: Option<crate::db::Db>,
    #[allow(dead_code)]
    pub session_id: Option<uuid::Uuid>,
    #[allow(dead_code)]
    pub cwd: PathBuf,
    pub session: Option<Arc<Session>>,
    pub root_agent_frame: bool,
    pub context_usage: Option<ContextUsageSnapshot>,
    #[cfg(test)]
    test_builtin_gate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl HostContext {
    pub fn from_tool_ctx(ctx: &ToolCtx) -> Self {
        Self {
            db: Some(ctx.session.db.clone()),
            session_id: Some(ctx.session.id),
            cwd: ctx.cwd.clone(),
            session: Some(ctx.session.clone()),
            root_agent_frame: ctx.root_agent_frame,
            context_usage: ctx.context_usage,
            #[cfg(test)]
            test_builtin_gate: None,
        }
    }

    #[allow(dead_code)]
    pub fn empty_for_tests() -> Self {
        Self {
            db: None,
            session_id: None,
            cwd: PathBuf::new(),
            session: None,
            root_agent_frame: true,
            context_usage: None,
            #[cfg(test)]
            test_builtin_gate: None,
        }
    }

    #[cfg(test)]
    pub fn with_test_builtin_gate(
        mut self,
        gate: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        self.test_builtin_gate = Some(gate);
        self
    }
}

#[derive(Debug, Clone)]
pub struct Availability {
    available: bool,
    reason: Option<String>,
}

impl Availability {
    #[allow(dead_code)]
    fn available() -> Self {
        Self {
            available: true,
            reason: None,
        }
    }

    #[allow(dead_code)]
    fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            available: false,
            reason: Some(reason.into()),
        }
    }
}

type BuiltinHandler =
    for<'a> fn(&'a HostContext, Value) -> Pin<Box<dyn Future<Output = Result<Value>> + Send + 'a>>;

struct BuiltinFunction {
    name: &'static str,
    description: &'static str,
    input_schema: fn() -> Value,
    availability: fn(&HostContext) -> Availability,
    check_availability_on_invoke: bool,
    handler: BuiltinHandler,
}

impl BuiltinFunction {
    fn descriptor(&self) -> ToolDescriptor {
        sanitize_tool_descriptor(ToolDescriptor {
            name: self.name.to_string(),
            description: self.description.to_string(),
            input_schema: (self.input_schema)(),
        })
    }
}

pub fn is_builtin_server(server: &str) -> bool {
    server == BUILTIN_SERVER_ID
}

pub fn search(ctx: &HostContext, query: &str) -> Vec<SearchHit> {
    let q = query.trim().to_lowercase();
    registry()
        .into_iter()
        .filter(|func| (func.availability)(ctx).available)
        .filter(|func| {
            q.is_empty()
                || BUILTIN_SERVER_ID.contains(&q)
                || func.name.to_lowercase().contains(&q)
                || func.description.to_lowercase().contains(&q)
        })
        .map(|func| SearchHit {
            server: BUILTIN_SERVER_ID.to_string(),
            tool: sanitize_tool_name(func.name),
            description: first_line(&sanitize_tool_description(func.description)),
        })
        .collect()
}

pub fn available_descriptors(ctx: &HostContext) -> Vec<ToolDescriptor> {
    registry()
        .into_iter()
        .filter(|func| (func.availability)(ctx).available)
        .map(|func| func.descriptor())
        .collect()
}

pub fn describe(ctx: &HostContext, tool: &str) -> Result<ToolDescriptor> {
    let Some(func) = registry().into_iter().find(|func| func.name == tool) else {
        bail!("unknown MCP tool `{BUILTIN_SERVER_ID}.{tool}`");
    };
    ensure_available(ctx, &func)?;
    Ok(func.descriptor())
}

pub async fn invoke(ctx: &HostContext, tool: &str, args: Value) -> Result<Value> {
    let Some(func) = registry().into_iter().find(|func| func.name == tool) else {
        bail!("unknown MCP tool `{BUILTIN_SERVER_ID}.{tool}`");
    };
    if func.check_availability_on_invoke {
        ensure_available(ctx, &func)?;
    }
    (func.handler)(ctx, args).await
}

fn ensure_available(ctx: &HostContext, func: &BuiltinFunction) -> Result<()> {
    let availability = (func.availability)(ctx);
    if availability.available {
        return Ok(());
    }
    bail!(
        "builtin MCP tool `{BUILTIN_SERVER_ID}.{}` is not available: {}",
        func.name,
        availability
            .reason
            .unwrap_or_else(|| "host gate is closed".to_string())
    )
}

fn registry() -> Vec<BuiltinFunction> {
    let mut funcs = vec![
        BuiltinFunction {
            name: "rename_session",
            description: "Set an auto-generated session title when this session needs one",
            input_schema: rename_session_schema,
            availability: rename_session_availability,
            check_availability_on_invoke: false,
            handler: rename_session,
        },
        BuiltinFunction {
            name: "request_compact",
            description: "Schedule compaction of the root context at the next safe boundary",
            input_schema: empty_object_schema,
            availability: |_ctx| Availability::available(),
            check_availability_on_invoke: true,
            handler: request_compact,
        },
        BuiltinFunction {
            name: "context_usage",
            description: "Return the turn-start context-pressure snapshot for this agent frame",
            input_schema: empty_object_schema,
            availability: |_ctx| Availability::available(),
            check_availability_on_invoke: true,
            handler: context_usage,
        },
    ];
    register_test_builtin(&mut funcs);
    funcs
}

fn empty_object_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {},
        "additionalProperties": false
    })
}

fn rename_session_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Auto-generated session title, 1 to 200 characters after trimming"
            }
        },
        "required": ["name"],
        "additionalProperties": false
    })
}

fn rename_session_availability(ctx: &HostContext) -> Availability {
    let Some(session) = ctx.session.as_ref() else {
        return Availability::unavailable("rename_session requires a live session");
    };
    if !session.agent_rename_session_available(auto_title_model_configured(ctx)) {
        return Availability::unavailable(
            "session auto-titling is configured; the utility model owns titles",
        );
    }
    Availability::available()
}

fn auto_title_model_configured(ctx: &HostContext) -> bool {
    crate::config::extended::load_for_cwd(&ctx.cwd)
        .auto_title_model_ref()
        .is_some()
}

fn rename_session<'a>(
    ctx: &'a HostContext,
    args: Value,
) -> Pin<Box<dyn Future<Output = Result<Value>> + Send + 'a>> {
    Box::pin(async move {
        let raw = args
            .get("name")
            .and_then(Value::as_str)
            .context("`cockpit.rename_session` requires `name` as a string")?;
        let name = raw.trim();
        if name.is_empty() {
            bail!("`cockpit.rename_session` requires a non-empty title");
        }
        if name.chars().count() > 200 {
            bail!("`cockpit.rename_session` title must be 200 characters or fewer");
        }
        let session = ctx
            .session
            .as_ref()
            .context("`cockpit.rename_session` requires a live session")?;
        let row = session
            .db
            .get_session(session.id)
            .context("loading session before rename")?
            .context("session row is missing")?;
        if row.user_renamed {
            bail!(
                "`cockpit.rename_session` is unavailable: the user has manually named this session"
            );
        }
        if row.ephemeral {
            bail!("`cockpit.rename_session` is unavailable: ephemeral sessions are never titled");
        }
        if !session.agent_rename_session_invoke_allowed(auto_title_model_configured(ctx)) {
            bail!(
                "`cockpit.rename_session` is unavailable: session auto-titling is configured; the utility model owns titles"
            );
        }
        let updated = session.set_explicit_auto_title(name)?;
        if !updated {
            bail!("`cockpit.rename_session` did not update the session title");
        }
        Ok(serde_json::json!({
            "renamed": true,
            "title": name
        }))
    })
}

fn request_compact<'a>(
    ctx: &'a HostContext,
    _args: Value,
) -> Pin<Box<dyn Future<Output = Result<Value>> + Send + 'a>> {
    Box::pin(async move {
        if !ctx.root_agent_frame {
            bail!(
                "`cockpit.request_compact` is unavailable: compaction can only be requested from the root agent frame"
            );
        }
        let session = ctx
            .session
            .as_ref()
            .context("`cockpit.request_compact` requires a live session")?;
        session.request_agent_compact();
        Ok(serde_json::json!({
            "scheduled": true,
            "message": "Compaction is scheduled for the next safe boundary."
        }))
    })
}

fn context_usage<'a>(
    ctx: &'a HostContext,
    _args: Value,
) -> Pin<Box<dyn Future<Output = Result<Value>> + Send + 'a>> {
    Box::pin(async move {
        let Some(snapshot) = ctx.context_usage else {
            return Ok(serde_json::json!({
                "ctx_pct": null,
                "used_tokens": null,
                "total_tokens": null,
                "auto_compact_pct": null,
                "snapshot": "unavailable"
            }));
        };
        Ok(serde_json::json!({
            "ctx_pct": snapshot.ctx_pct,
            "used_tokens": snapshot.used_tokens,
            "total_tokens": snapshot.total_tokens,
            "auto_compact_pct": snapshot.auto_compact_pct,
            "snapshot": "turn_start"
        }))
    })
}

#[cfg(test)]
fn register_test_builtin(funcs: &mut Vec<BuiltinFunction>) {
    funcs.push(BuiltinFunction {
        name: "test_count",
        description: "Count test values",
        input_schema: || {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "count": { "type": "integer" }
                },
                "required": ["count"]
            })
        },
        availability: |ctx| {
            let Some(gate) = &ctx.test_builtin_gate else {
                return Availability::unavailable("test builtin gate is absent");
            };
            if gate.load(std::sync::atomic::Ordering::SeqCst) {
                Availability::available()
            } else {
                Availability::unavailable("test builtin gate is closed")
            }
        },
        check_availability_on_invoke: true,
        handler: |_ctx, args| {
            Box::pin(async move {
                let count = args.get("count").cloned().unwrap_or(Value::Null);
                let count_type = if count.is_i64() || count.is_u64() {
                    "int"
                } else {
                    count.type_name()
                };
                Ok(serde_json::json!({
                    "count": count,
                    "count_type": count_type
                }))
            })
        },
    });
}

#[cfg(not(test))]
fn register_test_builtin(_funcs: &mut Vec<BuiltinFunction>) {}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").trim().to_string()
}

#[cfg(test)]
trait ValueTypeName {
    fn type_name(&self) -> &'static str;
}

#[cfg(test)]
impl ValueTypeName for Value {
    fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(root: &std::path::Path, body: &str) {
        let dir = root.join(".cockpit");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), body).unwrap();
    }

    fn host(root: &std::path::Path) -> HostContext {
        let ctx = crate::tools::common::test_ctx(root);
        HostContext::from_tool_ctx(&ctx)
    }

    fn advance_title_turns(session: &Session, turns: usize) {
        for turn in 1..=turns {
            let _ = session.note_user_content(&format!("turn {turn}"));
        }
    }

    #[tokio::test]
    async fn rename_session_available_when_untitled_past_threshold() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"{ "utility_model": null, "auto_title": null }"#,
        );
        let host = host(tmp.path());
        assert!(
            search(&host, "rename_session")
                .iter()
                .any(|hit| hit.tool == "rename_session")
        );
        let desc = describe(&host, "rename_session").unwrap();
        assert_eq!(desc.name, "rename_session");

        write_config(tmp.path(), r#"{ "utility_model": "openai:gpt-4.1-mini" }"#);
        let session = host.session.as_ref().unwrap();
        advance_title_turns(session, 3);
        assert!(
            !search(&host, "rename_session")
                .iter()
                .any(|hit| hit.tool == "rename_session")
        );
        let err = describe(&host, "rename_session").unwrap_err();
        assert!(err.to_string().contains("auto-titling is configured"));

        advance_title_turns(session, 8);
        assert!(
            search(&host, "rename_session")
                .iter()
                .any(|hit| hit.tool == "rename_session")
        );
        let out = invoke(
            &host,
            "rename_session",
            serde_json::json!({ "name": "A title" }),
        )
        .await
        .unwrap();
        assert_eq!(out["title"], "A title");
    }

    #[tokio::test]
    async fn rename_session_unavailable_when_titled() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(tmp.path(), r#"{ "utility_model": "openai:gpt-4.1-mini" }"#);
        let host = host(tmp.path());
        let session = host.session.as_ref().unwrap();
        advance_title_turns(session, 8);
        assert!(session.set_auto_title("robot title").unwrap());

        assert!(
            !search(&host, "rename_session")
                .iter()
                .any(|hit| hit.tool == "rename_session")
        );
        let err = describe(&host, "rename_session").unwrap_err();
        assert!(err.to_string().contains("auto-titling is configured"));
    }

    #[tokio::test]
    async fn rename_session_invoke_allows_titled_after_threshold_race() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(tmp.path(), r#"{ "utility_model": "openai:gpt-4.1-mini" }"#);
        let host = host(tmp.path());
        let session = host.session.as_ref().unwrap();
        advance_title_turns(session, 8);
        assert!(session.set_auto_title("late utility title").unwrap());
        assert!(
            !search(&host, "rename_session")
                .iter()
                .any(|hit| hit.tool == "rename_session"),
            "search/describe availability should still hide already-titled sessions"
        );

        let out = invoke(
            &host,
            "rename_session",
            serde_json::json!({ "name": "agent race title" }),
        )
        .await
        .unwrap();

        assert_eq!(out["title"], "agent race title");
        let row = session.db.get_session(session.id).unwrap().unwrap();
        assert_eq!(row.title.as_deref(), Some("agent race title"));
        assert!(!row.user_renamed);
    }

    #[tokio::test]
    async fn rename_session_still_refuses_user_renamed_and_ephemeral() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(tmp.path(), r#"{ "utility_model": "openai:gpt-4.1-mini" }"#);
        let host = host(tmp.path());
        let session = host.session.as_ref().unwrap();
        advance_title_turns(session, 8);
        session.db.rename_session(session.id, "manual").unwrap();
        let err = rename_session(&host, serde_json::json!({ "name": "agent" }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("manually named"), "{err}");

        let db = crate::db::Db::open_in_memory().unwrap();
        let parent =
            crate::session::Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();
        let side = db.create_ephemeral_fork(parent.id, None).unwrap();
        let session = Arc::new(
            crate::session::Session::resume(db, side.session_id)
                .unwrap()
                .unwrap(),
        );
        advance_title_turns(&session, 8);
        let host = HostContext {
            db: Some(session.db.clone()),
            session_id: Some(session.id),
            cwd: tmp.path().to_path_buf(),
            session: Some(session),
            root_agent_frame: true,
            context_usage: None,
            test_builtin_gate: None,
        };
        let err = rename_session(&host, serde_json::json!({ "name": "agent" }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ephemeral"));
    }

    #[tokio::test]
    async fn rename_session_writes_explicit_auto_title() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"{ "utility_model": null, "auto_title": null }"#,
        );
        let host = host(tmp.path());
        let session = host.session.as_ref().unwrap();

        let out = invoke(
            &host,
            "rename_session",
            serde_json::json!({ "name": "  agent title  " }),
        )
        .await
        .unwrap();
        assert_eq!(out["title"], "agent title");
        let row = session.db.get_session(session.id).unwrap().unwrap();
        assert_eq!(row.title.as_deref(), Some("agent title"));
        assert!(!row.user_renamed);

        session
            .db
            .rename_session(session.id, "manual title")
            .unwrap();
        let row = session.db.get_session(session.id).unwrap().unwrap();
        assert_eq!(row.title.as_deref(), Some("manual title"));
        assert!(row.user_renamed);
    }

    #[tokio::test]
    async fn rename_session_refuses_user_renamed() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(tmp.path(), r#"{ "utility_model": "openai:gpt-4.1-mini" }"#);
        let host = host(tmp.path());
        let session = host.session.as_ref().unwrap();
        advance_title_turns(session, 8);
        session.db.rename_session(session.id, "manual").unwrap();

        let err = rename_session(&host, serde_json::json!({ "name": "agent" }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("manually named"));
    }

    #[tokio::test]
    async fn rename_session_refuses_ephemeral() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(tmp.path(), r#"{ "utility_model": "openai:gpt-4.1-mini" }"#);
        let db = crate::db::Db::open_in_memory().unwrap();
        let parent =
            crate::session::Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();
        let side = db.create_ephemeral_fork(parent.id, None).unwrap();
        let session = Arc::new(
            crate::session::Session::resume(db, side.session_id)
                .unwrap()
                .unwrap(),
        );
        let host = HostContext {
            db: Some(session.db.clone()),
            session_id: Some(session.id),
            cwd: tmp.path().to_path_buf(),
            session: Some(session),
            root_agent_frame: true,
            context_usage: None,
            test_builtin_gate: None,
        };
        advance_title_turns(host.session.as_ref().unwrap(), 8);

        let err = rename_session(&host, serde_json::json!({ "name": "agent" }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ephemeral"));
    }

    #[tokio::test]
    async fn rename_session_validates_name() {
        let tmp = tempfile::tempdir().unwrap();
        write_config(
            tmp.path(),
            r#"{ "utility_model": null, "auto_title": null }"#,
        );
        let host = host(tmp.path());

        let err = invoke(
            &host,
            "rename_session",
            serde_json::json!({ "name": "   " }),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("non-empty"));

        let too_long = "x".repeat(201);
        let err = invoke(
            &host,
            "rename_session",
            serde_json::json!({ "name": too_long }),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("200 characters"));
    }

    #[tokio::test]
    async fn request_compact_refused_in_subagent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut host = host(tmp.path());
        host.root_agent_frame = false;
        let session = host.session.as_ref().unwrap();

        let err = invoke(&host, "request_compact", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("root agent"));
        assert!(!session.agent_compact_requested());
    }

    #[tokio::test]
    async fn request_compact_sets_one_shot_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let host = host(tmp.path());
        let session = host.session.as_ref().unwrap();

        let out = invoke(&host, "request_compact", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(out["scheduled"], true);
        assert!(session.agent_compact_requested());
        assert!(session.take_agent_compact_request());
        assert!(!session.take_agent_compact_request());
    }

    #[tokio::test]
    async fn context_usage_reports_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let mut host = host(tmp.path());
        host.context_usage = Some(ContextUsageSnapshot {
            ctx_pct: Some(42.5),
            used_tokens: Some(425),
            total_tokens: Some(1000),
            auto_compact_pct: 80,
        });

        let out = invoke(&host, "context_usage", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(out["ctx_pct"], 42.5);
        assert_eq!(out["used_tokens"], 425);
        assert_eq!(out["total_tokens"], 1000);
        assert_eq!(out["auto_compact_pct"], 80);
        assert_eq!(out["snapshot"], "turn_start");
    }
}
