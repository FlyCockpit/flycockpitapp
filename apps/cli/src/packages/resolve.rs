//! Resolve a dependency's source repo from official package-registry
//! metadata (prompt `docs-agent.md` decision 4).
//!
//! The guardrail: cockpit clones a repo URL **only** when an official
//! registry declares it — crates.io `repository`, the npm registry
//! `repository`, or PyPI `project_urls`/`Source`. A URL the model merely
//! guessed is never cloned. This protects weaker models (priority #1)
//! and limits supply-chain surface. Unresolvable → a clear refusal, not
//! a guess.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde_json::Value;

use crate::packages::Ecosystem;

/// Network timeout for a single registry lookup.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

/// Outcome of a repo-URL resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoResolution {
    /// The registry declared exactly one source repo.
    Resolved(String),
    /// The registry was reachable but declares no usable source repo.
    NotDeclared,
}

/// Resolve `name`'s source-repo URL from `eco`'s official registry.
/// Returns [`RepoResolution::NotDeclared`] when the registry has no
/// repository field (caller must refuse to clone, not guess). Network
/// or parse failures bubble up as `Err`.
pub async fn resolve_repo_url(eco: Ecosystem, name: &str) -> Result<RepoResolution> {
    let client = reqwest::Client::builder()
        .timeout(LOOKUP_TIMEOUT)
        .user_agent("cockpit-cli")
        .build()
        .context("building reqwest client")?;
    match eco {
        Ecosystem::Cargo => resolve_crates_io(&client, name).await,
        Ecosystem::Npm => resolve_npm(&client, name).await,
        Ecosystem::Pip => resolve_pypi(&client, name).await,
    }
}

async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<Option<Value>> {
    let resp = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("{url} returned {}", resp.status());
    }
    let body = resp
        .text()
        .await
        .with_context(|| format!("reading {url}"))?;
    let value = serde_json::from_str(&body).with_context(|| format!("parsing {url}"))?;
    Ok(Some(value))
}

async fn resolve_crates_io(client: &reqwest::Client, name: &str) -> Result<RepoResolution> {
    let url = format!("https://crates.io/api/v1/crates/{name}");
    let Some(json) = fetch_json(client, &url).await? else {
        anyhow::bail!("crate `{name}` not found on crates.io");
    };
    let repo = json
        .get("crate")
        .and_then(|c| c.get("repository"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    Ok(match repo {
        Some(url) => RepoResolution::Resolved(normalize_declared_repo_url(url)?),
        None => RepoResolution::NotDeclared,
    })
}

async fn resolve_npm(client: &reqwest::Client, name: &str) -> Result<RepoResolution> {
    // The package name may be scoped (`@tanstack/query`); the registry
    // accepts the raw name in the path.
    let url = format!("https://registry.npmjs.org/{name}");
    let Some(json) = fetch_json(client, &url).await? else {
        anyhow::bail!("package `{name}` not found on the npm registry");
    };
    // `repository` is either a string or an object with a `url` field.
    let repo = json.get("repository").and_then(|r| match r {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Object(o) => o
            .get("url")
            .and_then(Value::as_str)
            .map(|s| s.trim().to_string()),
        _ => None,
    });
    Ok(match repo.filter(|s| !s.is_empty()) {
        Some(url) => RepoResolution::Resolved(normalize_declared_repo_url(&url)?),
        None => RepoResolution::NotDeclared,
    })
}

async fn resolve_pypi(client: &reqwest::Client, name: &str) -> Result<RepoResolution> {
    let url = format!("https://pypi.org/pypi/{name}/json");
    let Some(json) = fetch_json(client, &url).await? else {
        anyhow::bail!("project `{name}` not found on PyPI");
    };
    let info = json.get("info");
    // Prefer an explicit `Source`/`Repository` entry in project_urls;
    // fall back to `home_page` only when it points at a known forge.
    let project_urls = info.and_then(|i| i.get("project_urls"));
    if let Some(Value::Object(map)) = project_urls {
        for key in ["Source", "Source Code", "Repository", "Code"] {
            if let Some(url) = map.get(key).and_then(Value::as_str)
                && !url.trim().is_empty()
            {
                return Ok(RepoResolution::Resolved(normalize_declared_repo_url(
                    url.trim(),
                )?));
            }
        }
        // Any project_url that looks like a forge repo.
        for v in map.values() {
            if let Some(s) = v.as_str()
                && is_forge_repo(s)
            {
                return Ok(RepoResolution::Resolved(normalize_declared_repo_url(
                    s.trim(),
                )?));
            }
        }
    }
    let home = info
        .and_then(|i| i.get("home_page"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| is_forge_repo(s));
    Ok(match home {
        Some(url) => RepoResolution::Resolved(normalize_declared_repo_url(url)?),
        None => RepoResolution::NotDeclared,
    })
}

/// True when `url` points at a well-known code-forge repo (used as a
/// conservative registry gate — we only accept these, never a generic
/// docs/homepage URL).
fn is_forge_repo(url: &str) -> bool {
    normalize_repo_url(url)
        .ok()
        .and_then(|normalized| Url::parse(&normalized).ok())
        .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|host| {
            matches!(
                host.as_str(),
                "github.com" | "gitlab.com" | "bitbucket.org" | "codeberg.org"
            )
        })
}

/// Normalize a declared repo URL into something `git clone` accepts:
/// strip a trailing `.git`-less fragment / `#readme`, drop `git+`
/// prefixes (npm uses `git+https://…`), trim trailing slashes, and reject
/// dangerous git remote-helper transports.
pub(crate) fn normalize_repo_url(url: &str) -> Result<String> {
    let mut u = url.trim();
    if u.is_empty() {
        bail!("repository URL is empty");
    }
    u = u.strip_prefix("git+").unwrap_or(u);
    // Drop a URL fragment (`#readme`, `#main`) some registries append.
    let u = u.split('#').next().unwrap_or(u);
    let u = u.trim_end_matches('/');
    if u.contains("::") {
        let transport = u.split("::").next().unwrap_or("unknown");
        bail!("repository URL uses forbidden transport `{transport}::`");
    }
    if looks_like_scp_transport(u) {
        bail!("repository URL uses forbidden transport `scp-like`");
    }
    let parsed =
        Url::parse(u).with_context(|| format!("repository URL is not a valid URL `{u}`"))?;
    match parsed.scheme() {
        "https" | "git" | "ssh" => Ok(u.to_string()),
        "http" => bail!("repository URL uses forbidden scheme `http`"),
        "file" => bail!("repository URL uses forbidden scheme `file`"),
        scheme => bail!("repository URL uses forbidden scheme `{scheme}`"),
    }
}

fn normalize_declared_repo_url(url: &str) -> Result<String> {
    let normalized = normalize_repo_url(url)?;
    if !is_forge_repo(&normalized) {
        bail!("repository URL host is not an allowed forge `{normalized}`");
    }
    Ok(normalized)
}

fn looks_like_scp_transport(url: &str) -> bool {
    if url.contains("://") {
        return false;
    }
    let before_slash = url.split('/').next().unwrap_or(url);
    before_slash.contains(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_git_plus_and_fragment() {
        assert_eq!(
            normalize_repo_url("git+https://github.com/tanstack/query.git#readme").unwrap(),
            "https://github.com/tanstack/query.git"
        );
        assert_eq!(
            normalize_repo_url("https://github.com/tokio-rs/tokio/").unwrap(),
            "https://github.com/tokio-rs/tokio"
        );
    }

    #[test]
    fn forge_detection() {
        assert!(is_forge_repo("https://github.com/foo/bar"));
        assert!(is_forge_repo("https://gitlab.com/foo/bar"));
        assert!(is_forge_repo("ssh://git@github.com/foo/bar.git"));
        assert!(!is_forge_repo("https://example.com/docs"));
    }

    #[test]
    fn normalize_rejects_dangerous_git_transports() {
        for input in [
            "ext::sh -c 'evil'",
            "http://github.com/org/repo.git",
            "file:///etc/passwd",
            "evil.com:repo.git",
            "git@github.com:org/repo.git",
            "",
            "not a url",
        ] {
            let err = normalize_repo_url(input).unwrap_err().to_string();
            assert!(
                err.contains("repository URL"),
                "input {input:?} error should name repository URL: {err}"
            );
        }
    }

    #[test]
    fn normalize_accepts_allowed_url_schemes() {
        assert_eq!(
            normalize_repo_url("https://github.com/org/repo.git").unwrap(),
            "https://github.com/org/repo.git"
        );
        assert_eq!(
            normalize_repo_url("git+https://github.com/org/repo.git#readme").unwrap(),
            "https://github.com/org/repo.git"
        );
        assert_eq!(
            normalize_repo_url("ssh://git@github.com/org/repo.git").unwrap(),
            "ssh://git@github.com/org/repo.git"
        );
        assert_eq!(
            normalize_repo_url("git://github.com/org/repo.git").unwrap(),
            "git://github.com/org/repo.git"
        );
    }

    #[test]
    fn declared_repo_urls_must_be_known_forges() {
        let err = normalize_declared_repo_url("https://example.com/org/repo.git")
            .unwrap_err()
            .to_string();
        assert!(err.contains("allowed forge"), "{err}");
        assert_eq!(
            normalize_declared_repo_url("https://github.com/org/repo.git").unwrap(),
            "https://github.com/org/repo.git"
        );
    }
}
