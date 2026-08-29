//! Ratchets for load-bearing vNext slots.
//!
//! Fully closed properties:
//! - Every production conversational-model *resolution* seam for a vNext
//!   agent listed below either calls `resolve_vnext_slot_model` or is a
//!   documented inherit/fallback that consumes an already-resolved model.
//! - Durable model bindings (SQL + `AgentBindingInput` / `AgentBindingRow` /
//!   `StoredModelBinding`) never persist `choice_id`.
//! - After the empty-models inherit, `resolve_unprepared_vnext_primary_slot`
//!   returns `args.model` on `!args.delegated` before any `default_model`
//!   (unprepared roots keep the session/persisted selection; only delegated
//!   children with a non-empty list take the authored default).
//!
//! Remaining class: a brand-new conversational resolver in an unlisted file
//! that neither mentions the watched symbols, or a semantic bypass that keeps
//! those tokens (`default_model()` result ignored after the child arm; pin
//! gated on `frame_idx != 0` / `frame_idx > 0`). Clones of an already-resolved
//! `Agent.model` (forks, background review) are inherit paths, not resolvers,
//! and are out of the ratchet on purpose.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn db_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../cockpit-db/src")
}

fn relative_src(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if name == "tests" {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if !name.contains("test") {
                out.push(path);
            }
        }
    }
}

fn strip_test_modules(src: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    let bytes = src.as_bytes();
    while i < src.len() {
        if let Some(rel) = src[i..].find("#[cfg(test)]") {
            out.push_str(&src[i..i + rel]);
            let after = i + rel + "#[cfg(test)]".len();
            if let Some(mod_rel) = src[after..].find('{') {
                let mut depth = 0;
                let mut j = after + mod_rel;
                while j < src.len() {
                    match bytes[j] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j;
            } else {
                i = after;
            }
            continue;
        }
        out.push_str(&src[i..]);
        break;
    }
    out
}

fn file_source(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

fn production_source(path: &Path) -> String {
    strip_test_modules(&file_source(path))
}

fn require_contains(source: &str, needles: &[&str], label: &str) {
    for needle in needles {
        assert!(source.contains(needle), "{label} must contain `{needle}`");
    }
}

fn require_order(source: &str, first: &str, second: &str, label: &str) {
    let first_idx = source
        .find(first)
        .unwrap_or_else(|| panic!("{label} must contain `{first}`"));
    let second_idx = source
        .find(second)
        .unwrap_or_else(|| panic!("{label} must contain `{second}`"));
    assert!(
        first_idx < second_idx,
        "{label}: `{first}` must precede `{second}`"
    );
}

fn function_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing `{signature}`"));
    let rel_brace = source[start..]
        .find('{')
        .unwrap_or_else(|| panic!("`{signature}` has no body"));
    let bytes = source.as_bytes();
    let mut depth = 0;
    let mut j = start + rel_brace;
    while j < source.len() {
        match bytes[j] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=j];
                }
            }
            _ => {}
        }
        j += 1;
    }
    panic!("unclosed `{signature}`");
}

fn collect_symbol_files(root: &Path, needle: &str) -> Vec<String> {
    let mut files = Vec::new();
    collect_rs_files(root, &mut files);
    let mut hits = Vec::new();
    for path in files {
        if production_source(&path).contains(needle) {
            hits.push(relative_src(root, &path));
        }
    }
    hits.sort();
    hits
}

#[test]
fn vnext_conversational_model_resolves_through_slot_resolution() {
    let builtin = production_source(&repo_src().join("engine/builtin/mod.rs"));
    require_contains(
        &builtin,
        &[
            "fn resolve_agent_model",
            "if def.vnext.is_some()",
            "return resolve_vnext_slot_model(def, args)",
            "fn resolve_vnext_slot_model",
            "fn resolve_unprepared_vnext_primary_slot",
        ],
        "engine/builtin/mod.rs",
    );
    let resolve_agent_model = function_body(&builtin, "fn resolve_agent_model");
    require_order(
        resolve_agent_model,
        "if def.vnext.is_some()",
        "return resolve_vnext_slot_model(def, args)",
        "resolve_agent_model vNext gate",
    );
    require_order(
        resolve_agent_model,
        "return resolve_vnext_slot_model(def, args)",
        "resolve_delegated_model_with_store",
        "legacy role ladder must stay behind the vNext return",
    );
    for factory in [
        "fn agent_from_def",
        "fn default_build",
        "fn embedded_agent",
        "pub fn build",
        "pub fn deepthink",
        "pub fn scout",
        "pub fn plan",
        "pub fn multireview",
        "pub fn bee",
        "pub fn goal_control",
    ] {
        assert!(
            builtin.contains(factory),
            "expected factory `{factory}` in builtin production source"
        );
    }
    assert!(
        builtin.matches("resolve_agent_model(").count() >= 10,
        "vNext factories and agent_from_def must resolve through resolve_agent_model"
    );
    require_contains(
        function_body(&builtin, "fn default_build"),
        &["agent_from_def"],
        "default_build",
    );
    require_contains(
        function_body(&builtin, "fn embedded_agent"),
        &["agent_from_def"],
        "embedded_agent",
    );
    require_contains(
        function_body(&builtin, "fn rebuild_from_pinned_definition"),
        &["load_resolved_def"],
        "rebuild_from_pinned_definition",
    );
    require_contains(
        function_body(&builtin, "fn load_resolved_def"),
        &["agent_from_def"],
        "load_resolved_def",
    );
    require_contains(
        function_body(&builtin, "fn agent_from_def"),
        &["resolve_agent_model"],
        "agent_from_def",
    );

    let unprepared = function_body(&builtin, "fn resolve_unprepared_vnext_primary_slot");
    require_contains(
        unprepared,
        &["slot.models.is_empty()", "default_model"],
        "unprepared vNext primary slot",
    );
    require_order(
        unprepared,
        "slot.models.is_empty()",
        "default_model",
        "empty models inherit the session model before any authored default",
    );
    let after_empty = unprepared
        .split_once("slot.models.is_empty()")
        .map(|(_, rest)| rest)
        .expect("unprepared empty-models inherit gate");
    let after_root = after_empty
        .split_once("if !args.delegated")
        .map(|(_, rest)| rest)
        .expect("unprepared non-empty roots must split on !args.delegated before default_model");
    require_order(
        after_root,
        "return Ok(args.model.clone())",
        "default_model",
        "unprepared roots must return args.model; only delegated children use the authored default",
    );

    let driver = file_source(&repo_src().join("engine/driver/mod.rs"));
    let rebuild = function_body(&driver, "fn try_rebuild_frame_with_model");
    require_contains(
        rebuild,
        &["rebuild_from_pinned_definition"],
        "SetActiveModel rebuild",
    );
    let rebuild_args = function_body(&driver, "fn rebuild_frame_args");
    require_contains(
        rebuild_args,
        &["definition.vnext.is_some()", "new_model.clone()"],
        "rebuild_frame_args vNext running-model pin",
    );
    assert!(
        !rebuild_args.contains("frame_idx == 0"),
        "vNext running-model pin must apply to every stack frame, not only the root"
    );

    let registry = file_source(&repo_src().join("daemon/registry.rs"));
    let session_model = function_body(&registry, "fn resolve_session_active_model");
    let session_model_inner = session_model
        .split_once('{')
        .map(|(_, rest)| rest)
        .expect("resolve_session_active_model body");
    require_contains(
        session_model_inner,
        &["session.active_model_ref()", "providers_cfg"],
        "daemon/registry.rs unprepared/resume fallback",
    );
    require_order(
        session_model_inner,
        "session.active_model_ref()",
        "providers_cfg",
        "session active_model must win over providers.active_model",
    );

    let session_worker = file_source(&repo_src().join("daemon/session_worker/run.rs"));
    let align = function_body(&session_worker, "fn align_fresh_installed_root_model");
    require_contains(
        align,
        &["prepared_primary_default_selection"],
        "session worker prepared-root alignment",
    );

    let intercept = file_source(&repo_src().join("engine/verification/intercept.rs"));
    require_contains(
        &intercept,
        &[
            "profile_snapshot_id.is_nil()",
            "input.agent.model.clone()",
            "resolve_profile_utility_model",
        ],
        "verification intercept",
    );
    let generate = file_source(&repo_src().join("engine/verification/generate.rs"));
    require_contains(
        &generate,
        &[
            "input.profile_snapshot_id.is_nil()",
            "input.agent.model.clone()",
            "resolve_profile_utility_model",
        ],
        "verification generate",
    );

    let slot_callers = collect_symbol_files(&repo_src(), "resolve_vnext_slot_model(");
    assert_eq!(
        slot_callers,
        vec!["engine/builtin/mod.rs".to_string()],
        "resolve_vnext_slot_model must stay the builtin spawn seam, found {slot_callers:?}"
    );
    let delegated_callers =
        collect_symbol_files(&repo_src(), "resolve_delegated_model_with_store(");
    assert_eq!(
        delegated_callers,
        vec![
            "engine/builtin/mod.rs".to_string(),
            "engine/model_roles.rs".to_string(),
        ],
        "legacy role-ladder resolution must stay in resolve_agent_model plus its definition, found {delegated_callers:?}"
    );
}

#[test]
fn choice_id_is_not_persisted_on_durable_bindings() {
    let mut files = Vec::new();
    collect_rs_files(&repo_src().join("daemon"), &mut files);
    collect_rs_files(&repo_src().join("agents"), &mut files);
    collect_rs_files(&db_src().join("db"), &mut files);
    let mut hits = Vec::new();
    for path in files {
        let source = production_source(&path);
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            if trimmed.contains("choice_id")
                && (trimmed.contains("INSERT")
                    || trimmed.contains("binding_revision")
                    || trimmed.contains("AgentBindingInput")
                    || trimmed.contains("AgentBindingRow")
                    || trimmed.contains("StoredModelBinding")
                    || trimmed.contains("agent_model_bindings"))
            {
                hits.push(format!("{}: {trimmed}", path.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "choice_id must not be persisted on durable bindings:\n{}",
        hits.join("\n")
    );

    let binding_input = file_source(&db_src().join("db/agent_installations.rs"));
    let input_idx = binding_input
        .find("pub struct AgentBindingInput")
        .expect("AgentBindingInput");
    let row_idx = binding_input
        .find("pub struct AgentBindingRow")
        .expect("AgentBindingRow");
    let input_body = &binding_input[input_idx..row_idx];
    assert!(
        !input_body.contains("choice_id"),
        "AgentBindingInput must not grow a choice_id field"
    );
    let row_body = binding_input[row_idx..]
        .split("pub enum BindAgentOutcome")
        .next()
        .expect("AgentBindingRow body");
    assert!(
        !row_body.contains("choice_id"),
        "AgentBindingRow must not grow a choice_id field"
    );

    let stored = file_source(&db_src().join("db/agent_tree_decisions.rs"));
    let stored_idx = stored
        .find("pub struct StoredModelBinding")
        .expect("StoredModelBinding");
    let stored_body = stored[stored_idx..]
        .split("pub struct StoredVerificationReduction")
        .next()
        .expect("StoredModelBinding body");
    assert!(
        !stored_body.contains("choice_id"),
        "StoredModelBinding must not grow a choice_id field"
    );

    let sql = fs::read_to_string(db_src().join("db/migrations/0001_initial.sql")).unwrap();
    let table_idx = sql
        .find("CREATE TABLE agent_model_bindings")
        .expect("agent_model_bindings table");
    let table = sql[table_idx..]
        .split("CREATE UNIQUE INDEX agent_model_bindings_current_slot")
        .next()
        .expect("agent_model_bindings body");
    assert!(
        !table.contains("choice_id"),
        "agent_model_bindings must not persist a choice_id column"
    );
}
