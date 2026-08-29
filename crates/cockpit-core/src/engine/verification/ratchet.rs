//! No-bypass ratchet: ordinary write/edit dispatch must go through
//! verification resolution. Direct `dispatch_one_timed` callers outside the
//! verification intercept seam are forbidden. The sibling Monty native
//! path must resolve ArtifactWrite through `gate_sibling_artifact_write`
//! before `dispatch_arc_with_default_timeout`.

use std::{fs, path::Path};

#[test]
fn write_edit_cannot_reach_dispatch_one_timed_without_verification_intercept() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let dispatch = fs::read_to_string(src.join("engine/agent/tool_dispatch.rs")).unwrap();
    let production = strip_test_modules(&dispatch);
    assert!(
        production.contains("intercept_ordinary_call"),
        "ordinary dispatch must call verification intercept"
    );
    let intercept_idx = production
        .find("intercept_ordinary_call")
        .expect("intercept call site");
    let dispatch_idx = production
        .find("dispatch_one_timed(")
        .expect("dispatch_one_timed call");
    assert!(
        intercept_idx < dispatch_idx,
        "verification intercept must precede dispatch_one_timed"
    );

    let mut extra = Vec::new();
    collect_symbol_callers(&src, "dispatch_one_timed(", &mut extra);
    extra.retain(|path| {
        let rel = path.replace('\\', "/");
        !rel.ends_with("engine/agent/tool_dispatch.rs")
            && !rel.ends_with("engine/agent/mod.rs")
            && !rel.contains("/verification/")
    });
    assert!(
        extra.is_empty(),
        "production dispatch_one_timed callers must stay on the intercept seam, found {extra:?}"
    );
}

#[test]
fn sibling_artifact_write_cannot_reach_dispatch_arc_without_verification_gate() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let monty = fs::read_to_string(src.join("mcp/builtin.rs")).unwrap();
    let production = strip_test_modules(&monty);
    let gate_idx = production
        .find("gate_sibling_artifact_write")
        .expect("Monty native dispatch must resolve ArtifactWrite verification");
    let dispatch_idx = production
        .find("dispatch_arc_with_default_timeout")
        .expect("Monty native dispatch_arc site");
    assert!(
        gate_idx < dispatch_idx,
        "sibling ArtifactWrite gate must precede dispatch_arc_with_default_timeout"
    );

    let mut extra = Vec::new();
    collect_symbol_callers(&src, "dispatch_arc_with_default_timeout(", &mut extra);
    extra.retain(|path| {
        let rel = path.replace('\\', "/");
        !rel.ends_with("engine/agent/tool_timeout.rs")
            && !rel.ends_with("engine/agent/mod.rs")
            && !rel.ends_with("mcp/builtin.rs")
            && !rel.ends_with("engine/verification/ratchet.rs")
    });
    assert!(
        extra.is_empty(),
        "production dispatch_arc_with_default_timeout callers must stay on the gated Monty seam, found {extra:?}"
    );
}

fn collect_symbol_callers(dir: &Path, needle: &str, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_symbol_callers(&path, needle, out);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        if strip_test_modules(&raw).contains(needle) {
            out.push(path.display().to_string());
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
            let rest = src[after..].trim_start();
            if !rest.starts_with("mod ") {
                i = after;
                continue;
            }
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
