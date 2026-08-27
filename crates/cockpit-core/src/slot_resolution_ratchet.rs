//! Ratchets for load-bearing vNext slots: conversational model resolution
//! must go through slot resolution, and `choice_id` must not be persisted.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
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

#[test]
fn vnext_conversational_model_resolves_through_slot_resolution() {
    let builtin = fs::read_to_string(repo_src().join("engine/builtin/mod.rs")).unwrap();
    let production = strip_test_modules(&builtin);
    assert!(
        production.contains("resolve_vnext_slot_model"),
        "vNext spawn must resolve models through resolve_vnext_slot_model"
    );
    assert!(
        production.contains("if def.vnext.is_some()"),
        "vNext defs must not fall through the name-keyed role ladder"
    );
}

#[test]
fn choice_id_is_not_persisted_on_durable_bindings() {
    let mut files = Vec::new();
    collect_rs_files(&repo_src().join("daemon"), &mut files);
    collect_rs_files(&repo_src().join("agents"), &mut files);
    let mut hits = Vec::new();
    for path in files {
        let source = strip_test_modules(&fs::read_to_string(&path).unwrap());
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            if trimmed.contains("choice_id")
                && (trimmed.contains("INSERT")
                    || trimmed.contains("binding_revision")
                    || trimmed.contains("AgentBindingInput")
                    || trimmed.contains("StoredModelBinding"))
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
}
