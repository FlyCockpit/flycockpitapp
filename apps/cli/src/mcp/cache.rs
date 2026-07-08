//! On-disk MCP tool-catalog cache (GOALS §18a, §21 on-demand philosophy).
//!
//! Catalogs are keyed by a SHA256 of the server's identity (transport +
//! endpoint/command) and stored under the cockpit cache dir. Each entry
//! records the fetch time so a TTL re-fetch can be decided without a
//! watcher: a stale entry is simply ignored and the caller re-fetches.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::config::ServerConfig;
use super::protocol::ToolDescriptor;

/// A cached catalog: the tools plus the unix-seconds fetch time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCatalog {
    pub fetched_at: u64,
    pub tools: Vec<ToolDescriptor>,
}

/// SHA256-derived cache key for a server identity. Uses the first 16 hex
/// chars (matching mcp2cli-rs), namespaced by server name so two servers
/// sharing an endpoint don't collide.
pub fn cache_key(name: &str, cfg: &ServerConfig) -> String {
    let ident = match cfg.transport {
        super::config::Transport::Stdio => format!(
            "stdio|{}|{}",
            cfg.command.as_deref().unwrap_or(""),
            cfg.args.join(" ")
        ),
        _ => format!(
            "{}|{}",
            cfg.transport.as_str(),
            cfg.endpoint.as_deref().unwrap_or("")
        ),
    };
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(ident.as_bytes());
    let hex = crate::intel::hex_lower(&hasher.finalize());
    format!("{name}-{}", &hex[..16])
}

/// The cache directory: `$XDG_CACHE_HOME/cockpit/mcp/` (or the platform
/// cache dir), honoring `COCKPIT_MCP_CACHE_DIR` for tests.
pub fn cache_dir() -> Option<PathBuf> {
    if let Ok(over) = std::env::var("COCKPIT_MCP_CACHE_DIR")
        && !over.trim().is_empty()
    {
        return Some(PathBuf::from(over));
    }
    dirs::cache_dir().map(|d| d.join("cockpit/mcp"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load a cached catalog if present and not older than `ttl_secs`.
/// Returns `None` on miss, parse failure, or expiry — the caller then
/// re-fetches.
pub fn load(key: &str, ttl_secs: u64) -> Option<CachedCatalog> {
    load_in(cache_dir().as_deref()?, key, ttl_secs)
}

/// Persist a freshly-fetched catalog under `key`, stamped now.
pub fn save(key: &str, tools: &[ToolDescriptor]) -> Result<()> {
    let Some(dir) = cache_dir() else {
        return Ok(());
    };
    save_in(&dir, key, tools)
}

/// [`load`] against an explicit base directory (testable seam, avoids a
/// process-wide env var that races under the multithreaded test runner).
pub fn load_in(dir: &std::path::Path, key: &str, ttl_secs: u64) -> Option<CachedCatalog> {
    let path = dir.join(format!("{key}.json"));
    let raw = std::fs::read_to_string(&path).ok()?;
    let cached: CachedCatalog = serde_json::from_str(&raw).ok()?;
    if now_unix().saturating_sub(cached.fetched_at) > ttl_secs {
        return None;
    }
    Some(cached)
}

/// [`save`] against an explicit base directory (testable seam).
pub fn save_in(dir: &std::path::Path, key: &str, tools: &[ToolDescriptor]) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{key}.json"));
    let entry = CachedCatalog {
        fetched_at: now_unix(),
        tools: tools.to_vec(),
    };
    std::fs::write(&path, serde_json::to_string(&entry)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::config::{ServerConfig, Transport};
    use std::collections::BTreeMap;

    fn server() -> ServerConfig {
        ServerConfig {
            transport: Transport::Streamable,
            endpoint: Some("https://x/mcp".into()),
            command: None,
            args: vec![],
            env: BTreeMap::new(),
            env_credential_refs: BTreeMap::new(),
            auth: Default::default(),
            mode: Default::default(),
            enabled: true,
            cache_ttl_secs: 3600,
            connect_timeout_secs: None,
            timeout_secs: None,
        }
    }

    #[test]
    fn cache_key_is_stable_and_name_scoped() {
        let a = cache_key("s1", &server());
        let b = cache_key("s1", &server());
        let c = cache_key("s2", &server());
        assert_eq!(a, b, "same server → same key");
        assert_ne!(a, c, "different name → different key");
        assert!(a.starts_with("s1-"));
    }

    #[test]
    fn save_then_load_round_trips_within_ttl_but_expires_after() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let key = "ttltest-abc";
        let tools = vec![ToolDescriptor {
            name: "t".into(),
            description: "d".into(),
            input_schema: serde_json::json!({"type": "object"}),
        }];
        save_in(dir, key, &tools).unwrap();

        // Within TTL → hit.
        let loaded = load_in(dir, key, 3600).expect("within ttl should load");
        assert_eq!(loaded.tools, tools);

        // Force expiry by rewriting fetched_at far in the past, then a 1s
        // TTL must miss (re-fetch path).
        let path = dir.join(format!("{key}.json"));
        let mut entry: CachedCatalog =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        entry.fetched_at = now_unix().saturating_sub(10_000);
        std::fs::write(&path, serde_json::to_string(&entry).unwrap()).unwrap();
        assert!(load_in(dir, key, 1).is_none(), "expired entry must miss");
        // A large TTL still loads the same (old) entry.
        assert!(load_in(dir, key, 100_000).is_some(), "huge ttl still loads");
    }

    #[test]
    fn load_miss_on_absent_key() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(load_in(tmp.path(), "does-not-exist", 3600).is_none());
    }
}
