//! Repository-wide gate: runtime consumers must call the generation-explicit
//! multimodal capability resolver and must not inspect legacy `inputs` for
//! capability decisions.

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if matches!(name, "target" | ".git" | "node_modules") {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Forbidden patterns for runtime capability consumers (not detection/projection).
fn line_reads_legacy_inputs_for_capability(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with("//") {
        return false;
    }
    // Detection may still project legacy inputs into typed metadata.
    if trimmed.contains("legacy_input_listed")
        || trimmed.contains("input_capability_from_metadata")
        || trimmed.contains("inputs_from")
        || trimmed.contains("parse_models")
        || trimmed.contains("mod multimodal_capability")
        || trimmed.contains("multimodal_capability_")
    {
        return false;
    }
    // Capability decision via legacy inputs membership.
    let capability_context = trimmed.contains("images")
        || trimmed.contains("audio")
        || trimmed.contains("video")
        || trimmed.contains("supports_");
    if !capability_context {
        return false;
    }
    trimmed.contains(".inputs.as_ref()")
        || trimmed.contains("inputs.as_ref()?.images")
        || trimmed.contains("inputs.as_ref()?.audio")
        || trimmed.contains("inputs.as_ref()?.video")
        || trimmed.contains("m.inputs.as_ref()?.images")
        || trimmed.contains("model.inputs.as_ref()?.images")
}

#[test]
fn multimodal_capability_consumers_use_effective_resolver_not_legacy_inputs() {
    let root = workspace_root();
    // Exact runtime seams listed by the multimodal capability prompt.
    let required_consumer_files = [
        "crates/cockpit-core/src/engine/model/build.rs",
        "crates/cockpit-core/src/engine/builtin/mod.rs",
        "crates/cockpit-core/src/engine/model_roles.rs",
        "crates/cockpit-core/src/providers/models_fetch.rs",
        "crates/cockpit-core/src/wizard/apply.rs",
        "crates/cockpit-core/src/wizard/mod.rs",
        "crates/cockpit-core/src/diagnostics.rs",
        "crates/cockpit-core/src/welcome.rs",
        "crates/cockpit-core/src/engine/driver/mod.rs",
    ];
    let consumer_dirs = [
        root.join("crates/cockpit-core/src"),
        root.join("crates/cockpit-tui/src"),
        root.join("apps/cli/src"),
    ];
    // Detection/projection paths that may still read raw inputs for merge only.
    let allow_substr = [
        "providers/models_fetch.rs",
        "config/model_policy.rs",
        "config/providers/tests/",
        "multimodal_capability_consumer_gate.rs",
    ];

    let mut offenders = Vec::new();
    let mut wrapper_offenders = Vec::new();
    for dir in &consumer_dirs {
        let mut files = Vec::new();
        collect_rs_files(dir, &mut files);
        for path in files {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if allow_substr.iter().any(|a| rel.contains(a)) {
                continue;
            }
            let Ok(src) = fs::read_to_string(&path) else {
                continue;
            };
            if src.contains("resolve_capabilities(") {
                wrapper_offenders.push(rel.clone());
            }
            for (idx, line) in src.lines().enumerate() {
                if line_reads_legacy_inputs_for_capability(line) {
                    offenders.push(format!("{rel}:{}: {line}", idx + 1));
                }
            }
        }
    }

    let mut missing_required = Vec::new();
    for rel in required_consumer_files {
        let path = root.join(rel);
        let Ok(src) = fs::read_to_string(&path) else {
            missing_required.push(format!("{rel}: missing file"));
            continue;
        };
        if !src.contains("resolve_effective_model_capabilities") && !rel.contains("models_fetch.rs")
        {
            // models_fetch is detection/projection only; others must call the resolver.
            missing_required.push(format!(
                "{rel}: must call resolve_effective_model_capabilities"
            ));
        }
        if src.contains("resolve_capabilities(") {
            missing_required.push(format!(
                "{rel}: must not use the removed resolve_capabilities wrapper"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "runtime consumers must not inspect legacy inputs for capability decisions:\n{}",
        offenders.join("\n")
    );
    assert!(
        wrapper_offenders.is_empty(),
        "runtime consumers must not call resolve_capabilities; use resolve_effective_model_capabilities with an explicit generation:\n{}",
        wrapper_offenders.join("\n")
    );
    assert!(
        missing_required.is_empty(),
        "listed runtime consumers must call the generation-explicit effective resolver:\n{}",
        missing_required.join("\n")
    );
}
