//! Retrieve durable delegation payloads by sha256 hash.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

pub struct DelegationPayloadRetrieveTool;

#[async_trait]
impl Tool for DelegationPayloadRetrieveTool {
    fn name(&self) -> &str {
        "delegation_payload_retrieve"
    }

    fn description(&self) -> &str {
        "Retrieve this subagent's exact delegation payload by 64-hex hash"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Retrieve the exact redacted delegation brief stored for this session. \
             Use the 64-character lowercase sha256 hash from the delegation-payload marker; \
             do not guess or shorten the hash, and do not use this for unrelated tool results."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "hash": { "type": "string", "description": "64 lowercase hex chars" }
            },
            "required": ["hash"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "hash": { "type": "string", "description": "Required 64-character lowercase sha256 hash from a delegation-payload marker" }
            },
            "required": ["hash"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let hash = args
            .get("hash")
            .and_then(Value::as_str)
            .map(str::trim)
            .ok_or_else(|| invalid_input("`hash` is required"))?;
        if !valid_full_hash(hash) {
            return Err(invalid_input(
                "`hash` must be exactly 64 lowercase hexadecimal characters",
            ));
        }

        let Some(payload) = ctx
            .session
            .db
            .load_task_delegation_payload_by_hash(ctx.session.id, hash)?
        else {
            return Ok(ToolOutput::text(format!(
                "No delegation payload with hash `{hash}` is available in this session."
            )));
        };

        Ok(ToolOutput::text(payload.body))
    }
}

pub(crate) fn valid_full_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_lowercase_sha256() {
        assert!(valid_full_hash(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!valid_full_hash("abc"));
        assert!(!valid_full_hash(
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }
}
