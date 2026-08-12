//! AC1 + AC12 — `spawn_write_scope_tests_corrected_first` and
//! `spawn_output_dir_removal_compile_inventory`.
//!
//! Every named spawn anchor requires `write_scope` and rejects `output_dir`.
//! A qualified inventory proves no spawn field / JSON / schema / description
//! retains the old name, while the intentionally unrelated identifiers — the
//! task-delegation persistence column and the CLI manpage output directory —
//! remain semantically unchanged.
//!
//! The inventory reads the crate sources at test time, so a future edit that
//! reintroduces a compatibility alias fails here rather than silently shipping.

use std::path::{Path, PathBuf};

/// Root of the `cockpit-core` crate source tree.
fn core_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Repository root (two levels up from `crates/cockpit-core`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf()
}

fn read(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Whether `text` contains the forbidden `output_dir` identifier as a whole
/// token. The renamed spawn anchor was named exactly `output_dir`; a longer
/// identifier that merely shares the prefix (e.g. `output_directory`, the
/// image-generation output directory) is a different name and not a
/// regression.
fn contains_output_dir_identifier(text: &str) -> bool {
    let needle = "output_dir";
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(pos) = text[start..].find(needle) {
        let idx = start + pos;
        let after = idx + needle.len();
        let next_is_ident_continuation = bytes
            .get(after)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        if !next_is_ident_continuation {
            return true;
        }
        start = after;
    }
    false
}

// ---------------------------------------------------------------------------
// AC1: the spawn surface requires write_scope
// ---------------------------------------------------------------------------

#[test]
fn spawn_tool_schema_requires_write_scope_and_has_no_output_dir() {
    let tool = crate::tools::spawn::SpawnTool::for_depth(1, 4);
    let schema = crate::engine::tool::Tool::parameters(&tool);
    let rendered = serde_json::to_string(&schema).unwrap();

    let properties = schema
        .get("properties")
        .and_then(|p| p.as_object())
        .expect("schema has properties");
    assert!(
        properties.contains_key("write_scope"),
        "spawn must expose `write_scope`: {rendered}"
    );
    assert!(
        !properties.contains_key("output_dir"),
        "spawn must not expose `output_dir`: {rendered}"
    );

    let required: Vec<&str> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .expect("schema has required")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        required.contains(&"write_scope"),
        "`write_scope` must be required, not optional: {rendered}"
    );
    assert!(required.contains(&"prompt"));

    // No trace of the old name anywhere in the serialized schema, including
    // inside description strings.
    assert!(
        !rendered.contains("output_dir"),
        "no serialized spawn schema may mention output_dir: {rendered}"
    );
}

#[test]
fn spawn_descriptions_teach_write_scope_as_an_authority_transfer() {
    let tool = crate::tools::spawn::SpawnTool::for_depth(1, 4);
    let description = crate::engine::tool::Tool::description(&tool).to_string();
    let defensive = crate::engine::tool::Tool::defensive_description(&tool).unwrap_or_default();

    for text in [&description, &defensive] {
        assert!(
            text.contains("write_scope"),
            "description must name write_scope: {text}"
        );
        assert!(
            !text.contains("output_dir"),
            "description must not mention output_dir: {text}"
        );
    }
    // It is a scope, not an output suggestion.
    assert!(
        description.contains("subtree"),
        "the description must present write_scope as a subtree: {description}"
    );
}

#[test]
fn spawn_gate_refusal_names_write_scope() {
    // The gate is `pub(super)` to the driver, so assert on the built-in prompt
    // and schema surface plus the source of the refusal text.
    let source = read(core_src().join("engine/driver/delegation_helpers.rs"));
    let gate = source
        .split("pub(super) fn spawn_gate")
        .nth(1)
        .expect("spawn_gate exists");
    let gate_body = &gate[..gate.find("\n}\n").unwrap_or(gate.len())];
    assert!(
        gate_body.contains("write_scope"),
        "the spawn gate must check write_scope"
    );
    assert!(
        !gate_body.contains("output_dir"),
        "the spawn gate must not mention output_dir"
    );
}

#[test]
fn builtin_prompts_require_write_scope_on_spawn() {
    let builtin = core_src().join("engine/builtin");
    for name in [
        "bee.md",
        "bee.normal.md",
        "bee.frontier.md",
        "scout.md",
        "multireview.md",
    ] {
        let text = read(builtin.join(name));
        assert!(
            !text.contains("output_dir"),
            "{name} must not mention output_dir"
        );
        assert!(
            text.contains("write_scope"),
            "{name} must teach write_scope"
        );
    }

    // The bee prompts must present `write_scope` as a binding boundary rather
    // than a folder hint — AND must not assert an enforcement the engine does
    // not actually provide.
    //
    // This assertion used to require the literal phrase "hard write boundary",
    // which made a false claim mandatory. Two things are true today:
    //
    //   * A write outside the scope is NOT refused for a `bee`. The check
    //     itself is real (`tools::write::enforce_write_scope`), but
    //     `ToolCtx::write_scope` is never populated for a bee, because every
    //     write-capable spawn is refused before dispatch by
    //     `delegation_helpers::scoped_write_refusal` over the always-
    //     `Unsupported` `DirectWorkspaceBackend`.
    //   * "your parent cannot write inside it while you hold it" had no
    //     mechanism at all — nothing anywhere reserves a subtree against the
    //     parent. That was not an unwired guarantee, it was an imaginary one.
    //
    // So the prompts now carry the directive, and this test pins the directive
    // while forbidding the enforcement claim from coming back.
    for name in ["bee.md", "bee.normal.md", "bee.frontier.md"] {
        let text = read(builtin.join(name));
        assert!(
            text.contains("write boundary"),
            "{name} must present write_scope as a boundary, not a folder hint"
        );
        assert!(
            text.contains("never write outside it"),
            "{name} must direct the bee to keep every write inside its write_scope"
        );
        // Deliberately the full phrase: `bee.md` and `bee.normal.md` legitimately
        // say "an over-ceiling spawn is refused", which IS enforced by
        // `delegation_helpers::spawn_gate`.
        assert!(
            !text.contains("a write outside it is refused"),
            "{name} must not claim writes outside write_scope are refused: \
             `ToolCtx::write_scope` is never set for a bee, so nothing refuses them"
        );
        assert!(
            !text.contains("parent cannot write"),
            "{name} must not claim the parent is excluded from the scope: \
             no mechanism reserves a subtree against the parent"
        );
    }
}

// ---------------------------------------------------------------------------
// AC12: qualified inventory
// ---------------------------------------------------------------------------

/// Walk every `.rs` and `.md` file under a directory.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs") | Some("md")
        ) {
            out.push(path);
        }
    }
}

/// Files that are *allowed* to contain `output_dir`, with the reason. Anything
/// else containing it is a regression.
const ALLOWED_OUTPUT_DIR_FILES: &[(&str, &str)] = &[
    (
        "engine/driver/mod.rs",
        "DelegationChildInit.output_dir — the separate task-delegation persistence column",
    ),
    (
        "session/import.rs",
        "task-delegation child import: persistence column",
    ),
    (
        "session/export/mod.rs",
        "task-delegation child export: persistence column",
    ),
    (
        "session/export/tests.rs",
        "task-delegation export fixture: persistence column",
    ),
    (
        "daemon/session_worker/tests.rs",
        "task-delegation persistence fixture",
    ),
    ("tools/task.rs", "task tool: unrelated to spawn"),
    (
        "tools/delegation_payload_retrieve.rs",
        "task-delegation payload: persistence column",
    ),
    (
        "engine/driver/noninteractive.rs",
        "task-delegation persistence column",
    ),
    (
        "engine/driver/tests/mod.rs",
        "DelegationChildInit fixture — task-delegation persistence column",
    ),
    (
        "write_scope/tests/spawn_rename_inventory.rs",
        "this inventory test names the forbidden identifier on purpose",
    ),
];

#[test]
fn no_spawn_anchor_retains_output_dir_anywhere_in_cockpit_core() {
    let mut files = Vec::new();
    walk(&core_src(), &mut files);
    assert!(files.len() > 50, "the walk should find the crate sources");

    let mut offenders = Vec::new();
    for file in &files {
        let text = read(file);
        if !contains_output_dir_identifier(&text) {
            continue;
        }
        let relative = file
            .strip_prefix(core_src())
            .unwrap()
            .display()
            .to_string()
            .replace('\\', "/");
        if ALLOWED_OUTPUT_DIR_FILES
            .iter()
            .any(|(allowed, _)| *allowed == relative)
        {
            continue;
        }
        offenders.push(relative);
    }
    assert!(
        offenders.is_empty(),
        "these files still contain `output_dir` but are not on the qualified \
         task-delegation/CLI allowlist: {offenders:#?}"
    );
}

#[test]
fn named_spawn_anchors_are_clean() {
    // The exact anchors the spec enumerates.
    for anchor in [
        "tools/spawn.rs",
        "engine/agent/turn_phases.rs",
        "engine/agent/outcome.rs",
        "engine/driver/delegation_helpers.rs",
        "engine/driver/tests/reports.rs",
        "engine/schedule/authority.rs",
        "engine/schedule/swarm.rs",
        "engine/builtin/mod.rs",
    ] {
        let text = read(core_src().join(anchor));
        assert!(
            !text.contains("output_dir"),
            "{anchor} must not contain output_dir"
        );
        assert!(
            text.contains("write_scope"),
            "{anchor} should reference write_scope"
        );
    }
}

#[test]
fn no_compatibility_alias_or_serde_fallback_exists() {
    let mut files = Vec::new();
    walk(&core_src(), &mut files);
    for file in &files {
        let relative = file
            .strip_prefix(core_src())
            .unwrap()
            .display()
            .to_string()
            .replace('\\', "/");
        // The qualified allowlist owns the task-delegation persistence column
        // and legitimately reads it out of serialized session JSON.
        if ALLOWED_OUTPUT_DIR_FILES
            .iter()
            .any(|(allowed, _)| *allowed == relative)
        {
            continue;
        }
        let text = read(file);
        // A serde alias or rename that maps the old name onto the new one is
        // exactly the pre-release compatibility shim this prompt forbids.
        for forbidden in [
            r#"alias = "output_dir""#,
            r#"rename = "output_dir""#,
            r#""output_dir" =>"#,
            r#"get("output_dir")"#,
        ] {
            assert!(
                !text.contains(forbidden),
                "{} contains a compatibility shim `{forbidden}`",
                file.display()
            );
        }
    }
}

#[test]
fn unrelated_output_dir_identifiers_remain_semantically_unchanged() {
    // 1. The task-delegation persistence column keeps its name in SQL...
    let migration = read(repo_root().join("crates/cockpit-db/src/db/migrations/0001_initial.sql"));
    assert!(
        migration.contains("output_dir"),
        "the task-delegation persistence column must keep its name"
    );

    // ...and in the db module that owns it.
    let delegations = read(repo_root().join("crates/cockpit-db/src/db/task_delegations.rs"));
    assert!(
        delegations.contains("output_dir"),
        "task_delegations must keep its output_dir column"
    );

    // 2. The CLI manpage output directory is untouched.
    let cli = read(repo_root().join("apps/cli/src/lib.rs"));
    assert!(
        cli.contains("output_dir"),
        "the CLI manpage output directory variable must be left alone"
    );

    // 3. Neither of them acquired a spawn-flavoured write_scope by accident.
    assert!(
        !delegations.contains("write_scope"),
        "the task-delegation persistence column must not be renamed to write_scope"
    );
}

#[test]
fn the_write_scope_tables_are_defined_only_in_the_initial_migration() {
    // The schema uses an append-only migration set (0001_initial.sql plus later
    // upgrade migrations). The write-scope tables are foundational: they are
    // defined in 0001_initial.sql and never redefined by a later migration.
    let migrations_dir = repo_root().join("crates/cockpit-db/src/db/migrations");
    let initial = read(migrations_dir.join("0001_initial.sql"));
    let later_migrations: Vec<String> = {
        let mut v: Vec<String> = std::fs::read_dir(&migrations_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("sql"))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "0001_initial.sql")
            .collect();
        v.sort();
        v
    };
    for table in [
        "CREATE TABLE write_scope_leases",
        "CREATE TABLE write_scope_transfers",
        "CREATE TABLE write_scope_permits",
    ] {
        assert!(
            initial.contains(table),
            "0001_initial.sql must define {table}"
        );
        for later in &later_migrations {
            assert!(
                !read(migrations_dir.join(later)).contains(table),
                "{table} must be defined only in 0001_initial.sql, not {later}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Negative-claim inventory: agent-facing text must not assert unenforced
// write-scope enforcement.
// ---------------------------------------------------------------------------

/// Phrases that assert an enforcement the engine does not provide, each with
/// the reason it is false.
///
/// Deliberately full phrases, not single words. The engine has many *real*
/// refusals whose messages legitimately say "cannot write" — the lock manager
/// (`locks/acquire.rs`), the read-before-write hint (`engine/validation_hint.rs`),
/// the bash allowlist — and an over-ceiling spawn genuinely "is refused" by
/// `engine::driver::delegation_helpers::spawn_gate`. The goal is accuracy, not
/// deleting every strong statement.
const FORBIDDEN_ENFORCEMENT_CLAIMS: &[(&str, &str)] = &[
    (
        "cannot write inside",
        "nothing reserves a child's subtree against its parent",
    ),
    (
        "parent cannot write",
        "nothing reserves a child's subtree against its parent",
    ),
    (
        "a write outside it is refused",
        "`ToolCtx::write_scope` is never populated for a bee, because every \
         write-capable spawn is refused before dispatch — so nothing refuses the write",
    ),
    (
        "hard write boundary",
        "presents an unenforced scope as an enforced one",
    ),
];

/// Covers **tool descriptions as well as prompt markdown**.
///
/// The first sweep for these claims was scoped with `--include="*.md"` and so
/// never looked at `.rs` at all. That is exactly how `tools/spawn.rs`'s
/// `defensive_description` went on asserting that the parent could not write in
/// a child's scope after the `bee` prompts had been corrected — the claim was
/// not in a prompt file, it was in a Rust string literal. Walking both
/// extensions is the point of this test.
#[test]
fn no_agent_facing_text_claims_unenforced_write_scope_enforcement() {
    let mut files = Vec::new();
    walk(&core_src(), &mut files);
    assert!(files.len() > 50, "the walk should find the crate sources");

    let mut offenders = Vec::new();
    for file in &files {
        let relative = file
            .strip_prefix(core_src())
            .unwrap()
            .display()
            .to_string()
            .replace('\\', "/");
        // This inventory names the forbidden phrases on purpose.
        if relative == "write_scope/tests/spawn_rename_inventory.rs" {
            continue;
        }
        let text = read(file);
        for (phrase, why) in FORBIDDEN_ENFORCEMENT_CLAIMS {
            if text.contains(phrase) {
                offenders.push(format!("{relative}: claims \"{phrase}\" — {why}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "agent-facing text must not assert write-scope enforcement the code does not \
         provide; phrase it as a directive instead:\n{}",
        offenders.join("\n")
    );
}

/// Pins the derived-operation-id contract at its production source.
///
/// The recovery regression test in `restart_recovery` inserts its orphan row
/// with a hard-coded `write-scope-{transfer_id}`, which pins the *lookup* side
/// to the documented format. This pins the *producer* side: production
/// `ContainmentBarrier::create` must derive its operation id from the witness
/// and must not accept a free-form one. Without this, changing `create` to use
/// an unlinked operation id would leave the recovery tests green while silently
/// reopening the crash window they exist to close.
#[test]
fn production_create_derives_the_containment_operation_id_from_the_transfer() {
    let coordinator = read(core_src().join("write_scope/coordinator.rs"));
    assert!(
        coordinator.contains("format!(\"write-scope-{transfer_id}\")"),
        "the documented operation-id format must stay `write-scope-{{transfer_id}}`; \
         recovery and its tests depend on this exact derivation"
    );

    let containment = read(core_src().join("write_scope/containment.rs"));
    assert!(
        containment.contains("reserved.containment_operation_id()"),
        "production `create` must derive the containment operation id from the \
         `OwnershipReserved` witness, or a containment created before the ownership \
         attach becomes unfindable by recovery"
    );
    assert!(
        !containment.contains("operation_id: &str"),
        "`ContainmentBarrier::create` must not take a free-form operation id: it could \
         disagree with the durable transfer row, which is what made the containment \
         unfindable in the first place"
    );
}
