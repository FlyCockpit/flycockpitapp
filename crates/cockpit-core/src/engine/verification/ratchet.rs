//! No-bypass ratchet: ordinary write/edit dispatch must go through
//! verification resolution. Direct `dispatch_one_timed` callers outside the
//! verification intercept seam are forbidden.

use std::fs;
use std::path::Path;

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
    collect_callers(&src, &mut extra);
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

fn collect_callers(dir: &Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_callers(&path, out);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        if strip_test_modules(&raw).contains("dispatch_one_timed(") {
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
