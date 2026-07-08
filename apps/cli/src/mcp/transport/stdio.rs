//! Stdio transport (local subprocess MCP servers).
//!
//! Spawns the configured command and speaks line-delimited JSON-RPC over
//! the child's stdin/stdout. Extra env (from `env` + `Auth::Env`) is
//! injected into the child. The process is killed on drop.

use std::collections::BTreeMap;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};

use crate::mcp::protocol::{
    JsonRpcRequest, JsonRpcResponse, McpClient, ToolDescriptor, initialize_params, parse_tools_list,
};

pub struct StdioClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl StdioClient {
    pub fn spawn(command: &str, args: &[String], env: &BTreeMap<String, String>) -> Result<Self> {
        let mut cmd = tokio::process::Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear()
            .envs(stdio_child_env(std::env::vars(), env));
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawning MCP stdio server `{command}`"))?;
        let stdin = child.stdin.take().context("child stdin missing")?;
        let stdout = child.stdout.take().context("child stdout missing")?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        })
    }

    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let id = self.next_id;
        self.next_id += 1;
        let req = JsonRpcRequest::new(id, method, params);
        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;

        // Read lines until we get one that parses as a response carrying
        // our id (servers may emit notifications without an `id`).
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = self.stdout.read_line(&mut buf).await?;
            if n == 0 {
                bail!("MCP stdio server closed the connection");
            }
            let trimmed = buf.trim();
            if trimmed.is_empty() {
                continue;
            }
            let val: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Skip notifications / mismatched ids.
            match val.get("id").and_then(Value::as_u64) {
                Some(rid) if rid == id => {}
                _ => continue,
            }
            return Ok(serde_json::from_value(val)?);
        }
    }
}

fn stdio_child_env(
    parent: impl IntoIterator<Item = (String, String)>,
    explicit: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut child = BTreeMap::new();
    for (key, value) in parent {
        if inherit_stdio_env_var(&key) {
            child.insert(key, value);
        }
    }
    for (key, value) in explicit {
        child.insert(key.clone(), value.clone());
    }
    child
}

pub(crate) fn inherit_stdio_env_var(key: &str) -> bool {
    matches!(
        key,
        "PATH"
            | "HOME"
            | "USER"
            | "LOGNAME"
            | "USERPROFILE"
            | "HOMEDRIVE"
            | "HOMEPATH"
            | "APPDATA"
            | "LOCALAPPDATA"
            | "TEMP"
            | "TMP"
            | "TMPDIR"
            | "LANG"
            | "TERM"
            | "NO_COLOR"
            | "COLORTERM"
    ) || key.starts_with("LC_")
}

impl Drop for StdioClient {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

#[async_trait]
impl McpClient for StdioClient {
    async fn initialize(&mut self) -> Result<()> {
        self.request("initialize", Some(initialize_params()))
            .await?
            .into_result()?;
        Ok(())
    }

    async fn list_tools(&mut self) -> Result<Vec<ToolDescriptor>> {
        let result = self.request("tools/list", None).await?.into_result()?;
        parse_tools_list(&result)
    }

    async fn call_tool(&mut self, name: &str, args: Value) -> Result<Value> {
        let params = serde_json::json!({ "name": name, "arguments": args });
        self.request("tools/call", Some(params))
            .await?
            .into_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdio_child_env_excludes_ambient_secrets_and_keeps_basics() {
        let parent = [
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/alice".to_string()),
            ("LC_ALL".to_string(), "C.UTF-8".to_string()),
            ("OPENAI_API_KEY".to_string(), "ambient-secret".to_string()),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "ambient-secret".to_string(),
            ),
        ];
        let child = stdio_child_env(parent, &BTreeMap::new());

        assert_eq!(child.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(child.get("HOME").map(String::as_str), Some("/home/alice"));
        assert_eq!(child.get("LC_ALL").map(String::as_str), Some("C.UTF-8"));
        assert!(!child.contains_key("OPENAI_API_KEY"));
        assert!(!child.contains_key("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn stdio_child_env_includes_explicit_configured_env() {
        let parent = [("OPENAI_API_KEY".to_string(), "ambient-secret".to_string())];
        let mut explicit = BTreeMap::new();
        explicit.insert("SERVER_TOKEN".to_string(), "configured-secret".to_string());
        explicit.insert("PATH".to_string(), "/custom/bin".to_string());

        let child = stdio_child_env(parent, &explicit);

        assert!(!child.contains_key("OPENAI_API_KEY"));
        assert_eq!(
            child.get("SERVER_TOKEN").map(String::as_str),
            Some("configured-secret")
        );
        assert_eq!(child.get("PATH").map(String::as_str), Some("/custom/bin"));
    }
}
