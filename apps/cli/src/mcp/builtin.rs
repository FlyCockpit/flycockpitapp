//! Host-owned MCP functions exposed through the reserved `cockpit` server id.
//!
//! These entries are never loaded from `.cockpit/mcp.json`: they are native
//! cockpit capabilities reached through Monty's existing `mcp.search`,
//! `mcp.describe`, and `mcp.invoke` path. The sandbox only sees JSON results;
//! session and database handles stay host-side in [`HostContext`].

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use anyhow::{Result, bail};
use serde_json::Value;

use crate::engine::tool::ToolCtx;
use crate::mcp::catalog::SearchHit;
use crate::mcp::protocol::{
    ToolDescriptor, sanitize_tool_description, sanitize_tool_descriptor, sanitize_tool_name,
};

pub const BUILTIN_SERVER_ID: &str = "cockpit";

#[derive(Clone)]
pub struct HostContext {
    #[allow(dead_code)]
    pub db: Option<crate::db::Db>,
    #[allow(dead_code)]
    pub session_id: Option<uuid::Uuid>,
    #[allow(dead_code)]
    pub cwd: PathBuf,
    #[cfg(test)]
    test_builtin_gate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl HostContext {
    pub fn from_tool_ctx(ctx: &ToolCtx) -> Self {
        Self {
            db: Some(ctx.session.db.clone()),
            session_id: Some(ctx.session.id),
            cwd: ctx.cwd.clone(),
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
    ensure_available(ctx, &func)?;
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
    let mut funcs = Vec::new();
    register_test_builtin(&mut funcs);
    funcs
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
