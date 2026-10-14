//! Secrets I1 class guard: no type that carries environment values, header
//! values, credential literals or a raw copy of a credential-bearing document
//! may DERIVE `Debug` unless it is reviewed below.
//!
//! The walk covers every non-test Rust source under `crates/*/src` and
//! `apps/cli/src`. A `struct`/`enum` with `#[derive(.. Debug ..)]` is a
//! candidate carrier when one of its fields is named like an environment,
//! header, token, secret, password or raw-document field (or is a
//! `HeaderMap`), or when it pairs `name` and `value` strings. Each candidate
//! must either get a value-free hand-written `Debug` or appear in
//! [`REVIEWED`] with the reason its derived output cannot carry a value
//! (its field types already print value-free, or the field holds a name).
//! A new carrier therefore fails this test until it is fixed or reviewed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `(file, type)` → why the derived Debug is value-free.
const REVIEWED: &[(&str, &str, &str)] = &[
    (
        "crates/cockpit-config/src/config/extended.rs",
        "CommandResourceProfileRoot",
        "env holds an environment variable NAME, not its value",
    ),
    (
        "crates/cockpit-config/src/config/image_generation.rs",
        "ImageEndpoint",
        "headers are HeaderSpec, whose Debug prints names only",
    ),
    (
        "crates/cockpit-config/src/config/providers.rs",
        "ProviderEntry",
        "headers are HeaderSpec, whose Debug prints names only",
    ),
    (
        "crates/cockpit-config/src/config/providers.rs",
        "OAuthDescriptor",
        "headers are OAuthHeaderMapping, whose Debug prints names only",
    ),
    (
        "crates/cockpit-core/src/daemon/org_sync.rs",
        "OrgLogSyncPolicy",
        "raw is the server-issued sync policy document (no credentials)",
    ),
    (
        "crates/cockpit-core/src/daemon/principal.rs",
        "RemotePrincipal",
        "authorization is a grant/scope ceiling, not a bearer credential",
    ),
    (
        "crates/cockpit-core/src/daemon/transport_selection.rs",
        "TransportSelectionState",
        "authorization is a set of transport booleans/tri-states",
    ),
    (
        "crates/cockpit-core/src/daemon/turn_socket_provider.rs",
        "TurnCredentials",
        "password is TurnPassword, whose hand-written Debug is redacted",
    ),
    (
        "crates/cockpit-core/src/daemon/turn_socket_provider.rs",
        "AuthorizedIceEntry",
        "credentials are TurnCredentials (see above)",
    ),
    (
        "crates/cockpit-core/src/intel/lang.rs",
        "Identifier",
        "token is a source-code lexer token",
    ),
    (
        "crates/cockpit-core/src/providers/mod.rs",
        "ProviderTemplate",
        "api_key is a static header/format template, not a key",
    ),
    (
        "crates/cockpit-db/src/db/wire.rs",
        "SandboxDenialEvidence",
        "raw is the model-visible sandbox denial record",
    ),
    (
        "crates/cockpit-proto/src/lib.rs",
        "ProviderEntryView",
        "headers are ProviderHeaderView, whose Debug prints names only",
    ),
    (
        "crates/cockpit-proto/src/lib.rs",
        "GitStatusEntry",
        "raw is a git status line",
    ),
    (
        "crates/cockpit-proto/src/remote_turn_ice_policy.rs",
        "SecretsFile",
        "secrets are SecretEntry, whose Debug omits the encoded secret",
    ),
    (
        "crates/cockpit-proto/src/response.rs",
        "Response",
        "token is OwnerCapabilityToken, whose hand-written Debug is redacted",
    ),
    (
        "crates/cockpit-test-support/src/provider.rs",
        "CapturedRequest",
        "test-support fixture capturing fake provider requests",
    ),
    (
        "crates/cockpit-tui/src/tui/primary_paste.rs",
        "PrimaryPasteController",
        "env is PrimaryPasteEnv, a set of capability booleans",
    ),
    (
        "apps/cli/src/cli.rs",
        "AgentCommand",
        "continuation_token is ContinuationTokenArg, whose Debug prints <redacted>",
    ),
    (
        "crates/cockpit-tui/src/tui/settings/shell.rs",
        "SettingsPointerSurface",
        "page_token is a u64 render-generation counter",
    ),
    (
        "crates/cockpit-tui/src/tui/primary_paste.rs",
        "FakeHeldPrimaryAdapter",
        "last_token is a u64 paste-request counter",
    ),
    (
        "crates/cockpit-core/src/write_scope/coordinator.rs",
        "DelegationHandle",
        "WriteScopeToken is an in-process lease handle (ids and a generation, no secret)",
    ),
    (
        "crates/cockpit-core/src/agents/profile.rs",
        "AgentProfilePrepareRequest",
        "existing_session_claim_token is a daemon-allocated preparation fencing UUID, checked only against the daemon's own DB row",
    ),
    (
        "crates/cockpit-db/src/db/agent_installations.rs",
        "PrepareAgentSessionInput",
        "existing_session_claim_token is a daemon-allocated preparation fencing UUID, checked only against the daemon's own DB row",
    ),
    (
        "crates/cockpit-db/src/db/agent_installations.rs",
        "ReleasedPreparationClaimRow",
        "claim_token is a daemon-allocated preparation fencing UUID, checked only against the daemon's own DB row",
    ),
    (
        "crates/cockpit-db/src/db/text_artifacts.rs",
        "TextArtifactReservation",
        "lease_token is a daemon-allocated reservation fencing UUID, checked only against the daemon's own DB row",
    ),
    (
        "crates/cockpit-db/src/db/agent_tree_decisions.rs",
        "HostCapabilityRefreshExecutionLease",
        "owner_token is a worker-allocated lease fencing UUID, checked only against the daemon's own DB row",
    ),
];

const CARRIER_FIELD_NAMES: &[&str] = &[
    "env",
    "envs",
    "env_vars",
    "vars",
    "headers",
    "header_value",
    "secrets",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "access_token",
    "refresh_token",
    "id_token",
    "instance_token",
    "api_key",
    "token",
    "raw_params",
    "raw",
    "raw_frame",
    "credential",
    "credentials",
    "authorization",
    "cookie",
];

/// Field-name suffixes that mark a credential-like value (`continuation_token`,
/// `client_secret`, `db_password`, …).
const CARRIER_FIELD_SUFFIXES: &[&str] = &[
    "_token",
    "_secret",
    "_password",
    "_passphrase",
    "_api_key",
    "_credential",
    "_cookie",
];

fn is_carrier_field(field: &str) -> bool {
    CARRIER_FIELD_NAMES.contains(&field)
        || CARRIER_FIELD_SUFFIXES
            .iter()
            .any(|suffix| field.ends_with(suffix))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("cockpit-core sits two levels below the repo root")
        .to_path_buf()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "tests") {
                continue;
            }
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let name = path.file_name().unwrap().to_string_lossy();
            if !name.ends_with("tests.rs") {
                out.push(path);
            }
        }
    }
}

/// The source with every `#[cfg(test)]`-gated item blanked out.
fn without_test_items(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut pending = false;
    let mut skip: Option<i64> = None;
    for line in source.lines() {
        if let Some(depth) = skip.as_mut() {
            *depth += brace_delta(line);
            if *depth <= 0 {
                skip = None;
            }
            out.push('\n');
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            pending = true;
            out.push('\n');
            continue;
        }
        if pending {
            pending = false;
            let depth = brace_delta(line);
            if !trimmed.ends_with(';') && depth > 0 {
                skip = Some(depth);
            }
            out.push('\n');
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn brace_delta(line: &str) -> i64 {
    line.chars().fold(0, |depth, c| match c {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}

fn is_primitive(ty: &str) -> bool {
    let ty = ty
        .strip_prefix("Option<")
        .and_then(|inner| inner.strip_suffix('>'))
        .unwrap_or(ty);
    matches!(
        ty,
        "bool" | "u8" | "u16" | "u32" | "u64" | "usize" | "i32" | "i64" | "f64"
    )
}

/// `(type name, carrier fields)` of every derived-Debug candidate in `source`.
fn candidates(source: &str) -> Vec<(String, Vec<String>)> {
    let mut found = Vec::new();
    let bytes = source.as_bytes();
    let mut search = 0;
    while let Some(rel) = source[search..].find(|c: char| c == 's' || c == 'e') {
        let at = search + rel;
        search = at + 1;
        let keyword = if source[at..].starts_with("struct ") {
            "struct "
        } else if source[at..].starts_with("enum ") {
            "enum "
        } else {
            continue;
        };
        if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
            continue;
        }
        let name_start = at + keyword.len();
        let name_end = source[name_start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(source.len(), |rel| name_start + rel);
        let name = &source[name_start..name_end];
        let Some(open_rel) = source[name_end..].find(['{', ';', '(']) else {
            continue;
        };
        let open = name_end + open_rel;
        if bytes[open] != b'{' || name.is_empty() {
            continue;
        }
        let attrs_start = source[..at].rfind("\n\n").unwrap_or(0);
        let attrs = &source[attrs_start..at];
        let derives_debug = attrs.split("#[derive(").skip(1).any(|derive| {
            derive
                .split(')')
                .next()
                .is_some_and(|list| list.split(',').any(|item| item.trim() == "Debug"))
        });
        if !derives_debug {
            continue;
        }
        let mut depth = 0i64;
        let mut end = open;
        for (idx, c) in source[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + idx;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &source[open + 1..end];
        let mut fields = Vec::new();
        let mut string_fields = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            let line = line
                .strip_prefix("pub(crate) ")
                .or_else(|| line.strip_prefix("pub(super) "))
                .or_else(|| line.strip_prefix("pub "))
                .unwrap_or(line);
            let Some((field, ty)) = line.split_once(':') else {
                continue;
            };
            if field.is_empty() || !field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let ty = ty.trim().trim_end_matches(',').trim();
            if ty == "String" {
                string_fields.push(field.to_string());
            }
            if (is_carrier_field(field) || ty.contains("HeaderMap")) && !is_primitive(ty) {
                fields.push(format!("{field}: {ty}"));
            }
        }
        if string_fields.iter().any(|f| f == "name") && string_fields.iter().any(|f| f == "value") {
            fields.push("name/value string pair".to_string());
        }
        if !fields.is_empty() {
            found.push((name.to_string(), fields));
        }
        search = end.max(search);
    }
    found
}

#[test]
fn no_unreviewed_derived_debug_carries_env_header_or_credential_values() {
    let root = repo_root();
    let mut files = Vec::new();
    for base in ["crates", "apps/cli/src"] {
        let dir = root.join(base);
        if base == "crates" {
            let Ok(crates) = std::fs::read_dir(&dir) else {
                continue;
            };
            for krate in crates.flatten() {
                collect(&krate.path().join("src"), &mut files);
            }
        } else {
            collect(&dir, &mut files);
        }
    }
    let reviewed: BTreeMap<(String, String), &str> = REVIEWED
        .iter()
        .map(|(file, ty, why)| ((file.to_string(), ty.to_string()), *why))
        .collect();
    let mut unreviewed = Vec::new();
    let mut seen_reviewed = 0usize;
    for file in files {
        let relative = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&file).unwrap();
        for (name, fields) in candidates(&without_test_items(&source)) {
            if reviewed.contains_key(&(relative.clone(), name.clone())) {
                seen_reviewed += 1;
            } else {
                unreviewed.push(format!("{relative}::{name} [{}]", fields.join("; ")));
            }
        }
    }
    assert!(
        unreviewed.is_empty(),
        "types deriving Debug over env/header/credential/raw-document fields need a value-free \
         hand-written Debug (or a reviewed entry with its reason):\n{}",
        unreviewed.join("\n")
    );
    assert_eq!(
        seen_reviewed,
        REVIEWED.len(),
        "a reviewed carrier no longer exists or no longer derives Debug; prune REVIEWED"
    );
}
