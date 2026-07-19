use super::*;
use crate::engine::tool::Tool;
use crate::intel::{clear_freshness_cache, set_test_recompute_counter, set_test_walk_counter};
use crate::tools::common::test_ctx;
use crate::tools::intel::common::set_test_index_allowlist;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, body).unwrap();
}

#[tokio::test]
async fn outline_unknown_language_uses_regex_fallback_without_erroring() {
    let tmp = tempfile::tempdir().unwrap();
    // `.foo` is an unknown extension; give it def-like lines.
    write(
        tmp.path(),
        "weird.foo",
        "function alpha() {}\nclass Beta {}\n",
    );
    let ctx = test_ctx(tmp.path());
    let args = serde_json::json!({ "path": "weird.foo" });
    let out = OutlineTool.call(args, &ctx).await.unwrap();
    assert!(
        out.content.contains("unknown language"),
        "got: {}",
        out.content
    );
    assert!(out.content.contains("alpha"));
    assert!(out.content.contains("Beta"));
}

#[tokio::test]
async fn outline_grammarless_classified_language_uses_regex_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "README.md", "# Notes\n\nplain text\n");
    let ctx = test_ctx(tmp.path());

    let out = OutlineTool
        .call(serde_json::json!({ "path": "README.md" }), &ctx)
        .await
        .unwrap();

    assert!(
        out.content.contains("unknown language — regex outline"),
        "{}",
        out.content
    );
    assert!(
        out.content.contains("(no definitions matched)"),
        "{}",
        out.content
    );
}

#[tokio::test]
async fn tree_and_hot_list_unknown_language_files() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
    write(tmp.path(), "notes.foo", "anything\n");
    let ctx = test_ctx(tmp.path());

    let tree = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();
    assert!(tree.content.contains("src/lib.rs"));
    assert!(tree.content.contains("notes.foo"));
    // The unknown file is visible but flagged as grammarless data.
    assert!(tree.content.contains("notes.foo  unknown 9b 1L [data]"));

    let hot = HotTool.call(serde_json::json!({}), &ctx).await.unwrap();
    assert!(hot.content.contains("notes.foo"));
    assert!(hot.content.contains("src/lib.rs"));
}

#[tokio::test]
async fn tree_lists_files_including_unknown_language_files() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
    write(tmp.path(), "scratch.unknownext", "notes\n");
    let ctx = test_ctx(tmp.path());

    let tree = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();

    assert!(
        tree.content.contains("src/lib.rs  rust"),
        "{}",
        tree.content
    );
    assert!(
        tree.content
            .contains("scratch.unknownext  unknown 6b 1L [data]"),
        "{}",
        tree.content
    );
}

#[tokio::test]
async fn tree_marks_grammarless_data_and_parsed_symbol_counts() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
    write(tmp.path(), "Cargo.toml", "[package]\nname = \"demo\"\n");
    write(tmp.path(), "Dockerfile", "FROM scratch\n");
    let ctx = test_ctx(tmp.path());

    let tree = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();

    assert!(
        tree.content.contains("Cargo.toml  toml"),
        "{}",
        tree.content
    );
    assert!(
        tree.content.contains("Cargo.toml  toml 24b 2L [data]"),
        "{}",
        tree.content
    );
    assert!(
        tree.content
            .contains("Dockerfile  dockerfile 13b 1L [data]"),
        "{}",
        tree.content
    );
    assert!(
        tree.content.contains("src/lib.rs  rust 14b 1L [1 sym]"),
        "{}",
        tree.content
    );
}

#[tokio::test]
async fn tree_uses_stored_lines_and_marks_large_indexed_files() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "src/lib.rs",
        "pub fn k() {}\nmod inner;\nlast line",
    );
    let large_path = tmp.path().join("src/large.rs");
    std::fs::File::create(&large_path)
        .unwrap()
        .set_len(5 * 1024 * 1024)
        .unwrap();
    let large_data_path = tmp.path().join("large.toml");
    std::fs::File::create(&large_data_path)
        .unwrap()
        .set_len(5 * 1024 * 1024)
        .unwrap();
    let ctx = test_ctx(tmp.path());

    let tree = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();

    assert!(
        tree.content.contains("src/lib.rs  rust 34b 3L"),
        "{}",
        tree.content
    );
    assert!(
        tree.content
            .contains("src/large.rs  rust 5242880b [large] [0 sym]"),
        "{}",
        tree.content
    );
    assert!(
        tree.content
            .contains("large.toml  toml 5242880b [large] [data]"),
        "{}",
        tree.content
    );
}

#[tokio::test]
async fn tree_filter_rows_match_unfiltered_subtree_rows() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/lib.rs", "pub fn lib() {}\n");
    write(tmp.path(), "src/nested/mod.rs", "pub fn nested() {}\n");
    write(tmp.path(), "tests/outside.rs", "pub fn outside() {}\n");
    write(tmp.path(), "notes.foo", "notes\n");
    let ctx = test_ctx(tmp.path());

    let unfiltered = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();
    let filtered = TreeTool
        .call(serde_json::json!({"path": "src"}), &ctx)
        .await
        .unwrap();

    let expected: Vec<&str> = unfiltered
        .content
        .lines()
        .filter(|line| line.starts_with("src/"))
        .collect();
    let actual: Vec<&str> = filtered.content.lines().collect();

    assert_eq!(actual, expected, "{}", filtered.content);
    assert!(
        !filtered.content.contains("tests/outside.rs"),
        "{}",
        filtered.content
    );
    assert!(
        !filtered.content.contains("notes.foo"),
        "{}",
        filtered.content
    );
}

#[tokio::test]
async fn tree_filter_with_no_matches_reports_files_filter_and_hint() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
    let ctx = test_ctx(tmp.path());

    let tree = TreeTool
        .call(serde_json::json!({"path": "src/nope"}), &ctx)
        .await
        .unwrap();

    assert!(
        tree.content.contains("No files match filter `src/nope`."),
        "{}",
        tree.content
    );
    assert!(
        tree.content.contains("filter: src/nope"),
        "{}",
        tree.content
    );
    assert!(tree.content.contains("fs_files: 0"), "{}", tree.content);
    assert!(
        tree.content
            .contains("empty_reason: `path` filter excluded all discovered files"),
        "{}",
        tree.content
    );
    assert!(
        tree.content.contains("hint: run `tree` without `path`"),
        "{}",
        tree.content
    );
}

#[tokio::test]
async fn tree_root_like_paths_normalize_to_repo_root_listing() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
    write(tmp.path(), "README.md", "# repo\n");
    let mut ctx = test_ctx(tmp.path());
    ctx.cwd = tmp.path().join("src");

    for args in [
        serde_json::json!({}),
        serde_json::json!({"path": ""}),
        serde_json::json!({"path": "."}),
        serde_json::json!({"path": "./"}),
        serde_json::json!({"path": "/"}),
        serde_json::json!({"path": tmp.path()}),
    ] {
        let tree = TreeTool.call(args, &ctx).await.unwrap();
        assert!(tree.content.contains("src/lib.rs"), "{}", tree.content);
        assert!(tree.content.contains("README.md"), "{}", tree.content);
        assert!(
            !tree.content.contains("No files match"),
            "root-like spellings must not trigger the empty diagnostic: {}",
            tree.content
        );
    }
}

#[tokio::test]
async fn unscoped_tree_call_walks_the_filesystem_once() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
    write(tmp.path(), "README.md", "# repo\n");
    let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());

    // Warm the index, then clear the short-lived scan cache so this call
    // must refresh from disk. Force an empty allowlist for this root so the
    // gitignore re-include pass does not add a legitimate second traversal.
    let index = crate::intel::Index::new(db, ctx.session.project_root.clone());
    index.ensure_fresh().await.unwrap();
    clear_freshness_cache();
    let walks = Arc::new(AtomicUsize::new(0));
    let root_key = ctx.session.project_root.to_string_lossy().into_owned();
    set_test_index_allowlist(Some(root_key.clone()), Some(Vec::new()));
    set_test_walk_counter(Some(root_key), Some(walks.clone()));

    let tree = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();

    assert!(tree.content.contains("src/lib.rs"), "{}", tree.content);
    assert_eq!(
        walks.load(Ordering::SeqCst),
        1,
        "warm unscoped TreeTool::call should do exactly one filesystem traversal"
    );
    set_test_walk_counter(None, None);
    set_test_index_allowlist(None, None);
    clear_freshness_cache();
}

#[tokio::test]
async fn tree_call_does_not_recompute_centrality_inline() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
    let ctx = test_ctx(tmp.path());
    let recomputes = Arc::new(AtomicUsize::new(0));
    set_test_recompute_counter(
        Some(ctx.session.project_root.to_string_lossy().into_owned()),
        Some(recomputes.clone()),
    );

    let tree = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();

    assert!(tree.content.contains("src/lib.rs"), "{}", tree.content);
    assert_eq!(
        recomputes.load(Ordering::SeqCst),
        0,
        "tree should not recompute callgraph centrality on its read path"
    );
    set_test_recompute_counter(None, None);
    clear_freshness_cache();
}

#[test]
fn tree_defensive_description_does_not_mandate_first_call() {
    let description = TreeTool.defensive_description().unwrap();

    assert!(!description.contains("FIRST move"), "{description}");
    assert!(
        !description.contains("call it before reading or searching anything"),
        "{description}"
    );
    assert!(description.contains("Prefer it early"), "{description}");
}

#[tokio::test]
async fn tree_empty_project_reports_root_cwd_counts_and_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = test_ctx(tmp.path());

    let tree = TreeTool.call(serde_json::json!({}), &ctx).await.unwrap();

    assert!(tree.content.contains("project_root:"), "{}", tree.content);
    assert!(tree.content.contains("cwd:"), "{}", tree.content);
    assert!(tree.content.contains("filter: <none>"), "{}", tree.content);
    assert!(tree.content.contains("fs_files: 0"), "{}", tree.content);
    assert!(tree.content.contains("indexed_files:"), "{}", tree.content);
    assert!(
        tree.content
            .contains("hint: verify the project root/cwd; fall back to `rg --files`"),
        "{}",
        tree.content
    );
}

#[tokio::test]
async fn symbol_find_and_word_round_trip_through_call() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "m.rs",
        "pub fn target_fn() { let target_fn = 1; }\n",
    );
    let ctx = test_ctx(tmp.path());

    let sf = SymbolFindTool
        .call(
            serde_json::json!({ "name": "target_fn", "exact": true }),
            &ctx,
        )
        .await
        .unwrap();
    assert!(sf.content.contains("m.rs"));
    assert!(sf.content.contains("target_fn"));

    let w = WordTool
        .call(serde_json::json!({ "token": "target_fn" }), &ctx)
        .await
        .unwrap();
    assert!(w.content.contains("m.rs"));
}

#[test]
fn tarjan_finds_simple_cycle() {
    // 0 -> 1 -> 2 -> 0, and 3 isolated.
    let adj = vec![vec![1], vec![2], vec![0], vec![]];
    let sccs = tarjan_scc(&adj);
    let cyc: Vec<_> = sccs.iter().filter(|c| c.len() > 1).collect();
    assert_eq!(cyc.len(), 1);
    assert_eq!(cyc[0].len(), 3);
}

#[test]
fn tarjan_no_cycle() {
    let adj = vec![vec![1], vec![2], vec![]];
    let sccs = tarjan_scc(&adj);
    assert!(sccs.iter().all(|c| c.len() == 1));
}

#[test]
fn bfs_respects_hop_limit() {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    adj.insert("a", vec!["b"]);
    adj.insert("b", vec!["c"]);
    adj.insert("c", vec!["d"]);
    let one = bfs(&adj, "a", 1);
    assert_eq!(one, vec![(1, "b".to_string())]);
    let two = bfs(&adj, "a", 2);
    assert_eq!(two, vec![(1, "b".to_string()), (2, "c".to_string())]);
}

#[test]
fn bytecount_counts_lines() {
    assert_eq!(bytecount(b""), 0);
    assert_eq!(bytecount(b"a\n"), 1);
    assert_eq!(bytecount(b"a\nb"), 2);
    assert_eq!(bytecount(b"a\nb\n"), 2);
}

#[tokio::test]
async fn search_single_file_returns_matches_plus_note() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "src/tui/settings/mod.rs",
        "fn render_root() {}\nfn other() {}\n",
    );
    // A sibling file with the same pattern must NOT appear — proves we
    // searched just the one file, no widening to the parent dir.
    write(
        tmp.path(),
        "src/tui/settings/sibling.rs",
        "fn render_root() {}\n",
    );
    let ctx = test_ctx(tmp.path());
    let args = serde_json::json!({
        "path": "src/tui/settings/mod.rs",
        "pattern": "fn render_root"
    });
    let out = SearchTool.call(args, &ctx).await.unwrap();
    // rg runs with cwd = the file's parent dir, so the emitted path is
    // relative to it (`mod.rs`) — the pre-existing display convention
    // for a below-root `path` filter.
    assert!(out.content.contains("mod.rs:1"), "got: {}", out.content);
    assert!(
        !out.content.contains("sibling.rs"),
        "single-file search must not widen to the parent dir; got: {}",
        out.content
    );
    assert!(
        out.content.contains("NOTE:"),
        "single-file result must carry the informational note; got: {}",
        out.content
    );
    // The note is separated from match data, never interleaved into a
    // `path:line:col:` record.
    assert!(!out.content.contains(":NOTE"), "got: {}", out.content);
}

#[tokio::test]
async fn search_nonexistent_path_returns_clear_error() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/lib.rs", "pub fn k() {}\n");
    let ctx = test_ctx(tmp.path());
    let args = serde_json::json!({
        "path": "src/does/not/exist.rs",
        "pattern": "anything"
    });
    let err = SearchTool.call(args, &ctx).await.unwrap_err().to_string();
    assert!(
        err.contains("does not exist"),
        "expected a legible missing-path error, got: {err}"
    );
    assert!(
        !err.to_lowercase().contains("os error"),
        "must not surface a raw OS error, got: {err}"
    );
}

#[tokio::test]
async fn search_directory_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/a.rs", "fn target_pat() {}\n");
    write(tmp.path(), "src/b.rs", "fn target_pat() {}\n");
    let ctx = test_ctx(tmp.path());
    let args = serde_json::json!({ "path": "src", "pattern": "target_pat" });
    let out = SearchTool.call(args, &ctx).await.unwrap();
    // Paths are relative to the `src` filter dir (pre-existing convention).
    assert!(out.content.contains("a.rs:1"), "got: {}", out.content);
    assert!(out.content.contains("b.rs:1"), "got: {}", out.content);
    // No single-file note on a directory search.
    assert!(!out.content.contains("NOTE:"), "got: {}", out.content);
}

#[tokio::test]
async fn search_in_process_preserves_columns_context_glob_and_ignore_case() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "src/a.rs", "first\n  Alpha target\nthird\n");
    write(
        tmp.path(),
        "src/b.txt",
        "alpha should be excluded by glob\n",
    );
    let ctx = test_ctx(tmp.path());

    let out = SearchTool
        .call(
            serde_json::json!({
                "path": "src",
                "pattern": "alpha",
                "ignore_case": true,
                "context": 1,
                "glob": "*.rs"
            }),
            &ctx,
        )
        .await
        .unwrap();

    assert!(out.content.contains("a.rs:1- first"), "{}", out.content);
    assert!(
        out.content.contains("a.rs:2:3:   Alpha target"),
        "{}",
        out.content
    );
    assert!(out.content.contains("a.rs:3- third"), "{}", out.content);
    assert!(!out.content.contains("b.txt"), "{}", out.content);
}

#[tokio::test]
async fn search_ranking_is_noop_without_existing_index_scores() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "zcore.rs", "// gadget\n");
    write(tmp.path(), "acold.rs", "// gadget\n");

    set_centrality(tmp.path(), true);
    let ctx = test_ctx(tmp.path());
    let ranked = SearchTool
        .call(serde_json::json!({ "pattern": "gadget" }), &ctx)
        .await
        .unwrap();

    set_centrality(tmp.path(), false);
    let ctx2 = test_ctx(tmp.path());
    let unranked = SearchTool
        .call(serde_json::json!({ "pattern": "gadget" }), &ctx2)
        .await
        .unwrap();

    assert_eq!(ranked.content, unranked.content);
    let index = crate::intel::Index::new(ctx.session.db.clone(), tmp.path().to_path_buf());
    assert!(
        index.tree_rows().unwrap().is_empty(),
        "search ranking must not build the index just to rank results"
    );
}

#[tokio::test]
async fn search_thins_large_line_results_before_budgeting() {
    let tmp = tempfile::tempdir().unwrap();
    let mut body = String::new();
    for i in 1..=20 {
        if i == 11 {
            body.push_str("target panic failure\n");
        } else {
            body.push_str("target filler\n");
        }
    }
    write(tmp.path(), "src/lib.rs", &body);
    let ctx = test_ctx(tmp.path());
    let out = SearchTool
        .call(
            serde_json::json!({ "pattern": "target", "path": "src" }),
            &ctx,
        )
        .await
        .unwrap();

    assert!(out.truncated, "thinning should mark the output truncated");
    assert!(out.content.contains("lib.rs:1:"), "got: {}", out.content);
    assert!(out.content.contains("lib.rs:20:"), "got: {}", out.content);
    assert!(
        out.content.contains("lib.rs:11:1: target panic failure")
            || out.content.contains("lib.rs:11: target panic failure"),
        "got: {}",
        out.content
    );
    assert!(
        out.content
            .contains("more matches in lib.rs omitted; narrow query or path"),
        "got: {}",
        out.content
    );
}

#[tokio::test]
async fn context_pack_overview_on_multifile_fixture() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "src/lib.rs",
        "mod util;\npub fn main() {\n    util::helper();\n}\n",
    );
    write(tmp.path(), "src/util.rs", "pub fn helper() {}\n");
    write(tmp.path(), "script.py", "def runner():\n    pass\n");
    write(tmp.path(), "README.md", "# Project\n");
    write(tmp.path(), "Cargo.toml", "[package]\nname = \"demo\"\n");
    let ctx = test_ctx(tmp.path());

    let out = ContextPackTool
        .call(serde_json::json!({ "kind": "overview", "limit": 8 }), &ctx)
        .await
        .unwrap();

    assert!(
        out.content.contains("context_pack: overview"),
        "{}",
        out.content
    );
    assert!(out.content.contains("languages:"), "{}", out.content);
    assert!(out.content.contains("rust"), "{}", out.content);
    assert!(out.content.contains("python"), "{}", out.content);
    assert!(out.content.contains("markdown"), "{}", out.content);
    assert!(out.content.contains("toml"), "{}", out.content);
    assert!(out.content.contains("entry candidates:"), "{}", out.content);
    assert!(out.content.contains("src/lib.rs"), "{}", out.content);
    assert!(out.content.contains("next:"), "{}", out.content);
}

#[tokio::test]
async fn context_pack_path_includes_outline_imports_and_reverse_deps() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "src/app.ts",
        "import { helper } from './util';\nexport function main() {\n    helper();\n}\n",
    );
    write(tmp.path(), "src/util.ts", "export function helper() {}\n");
    let ctx = test_ctx(tmp.path());

    let out = ContextPackTool
        .call(
            serde_json::json!({ "target": "src/util.ts", "kind": "path", "depth": 1 }),
            &ctx,
        )
        .await
        .unwrap();

    assert!(
        out.content.contains("context_pack: path"),
        "{}",
        out.content
    );
    assert!(out.content.contains("path: src/util.ts"), "{}", out.content);
    assert!(out.content.contains("helper"), "{}", out.content);
    assert!(out.content.contains("reverse:"), "{}", out.content);
    assert!(out.content.contains("src/app.ts"), "{}", out.content);
    assert!(out.content.contains("suggested reads:"), "{}", out.content);
}

#[tokio::test]
async fn context_pack_symbol_handles_multiple_candidates_and_call_context() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "a.rs",
        "pub fn helper() {}\npub fn target_alpha() {\n    helper();\n}\n",
    );
    write(tmp.path(), "b.rs", "pub fn target_beta() {}\n");
    let ctx = test_ctx(tmp.path());

    let out = ContextPackTool
        .call(
            serde_json::json!({ "target": "target", "kind": "symbol" }),
            &ctx,
        )
        .await
        .unwrap();

    assert!(
        out.content.contains("context_pack: symbol"),
        "{}",
        out.content
    );
    assert!(out.content.contains("target_alpha"), "{}", out.content);
    assert!(out.content.contains("target_beta"), "{}", out.content);
    assert!(
        out.content.contains("calls helper -> a.rs"),
        "{}",
        out.content
    );
    assert!(out.content.contains("suggested reads:"), "{}", out.content);
}

#[tokio::test]
async fn context_pack_query_fallback_omits_file_contents() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "README.md", "needle phrase secret words\n");
    write(tmp.path(), "src/lib.rs", "pub fn known() {}\n");
    let ctx = test_ctx(tmp.path());

    let out = ContextPackTool
        .call(serde_json::json!({ "target": "needle phrase" }), &ctx)
        .await
        .unwrap();

    assert!(
        out.content.contains("context_pack: query"),
        "{}",
        out.content
    );
    assert!(out.content.contains("README.md:1"), "{}", out.content);
    assert!(out.content.contains("content omitted"), "{}", out.content);
    assert!(
        !out.content.contains("secret words"),
        "query packet must not print source line contents: {}",
        out.content
    );
}

#[tokio::test]
async fn context_pack_empty_repo_reports_diagnostic() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = test_ctx(tmp.path());

    let out = ContextPackTool
        .call(serde_json::json!({}), &ctx)
        .await
        .unwrap();

    assert!(out.content.contains("no indexed files"), "{}", out.content);
    assert!(out.content.contains("project_root:"), "{}", out.content);
    assert!(out.content.contains("hint:"), "{}", out.content);
}

#[tokio::test]
async fn context_pack_limit_reports_omitted_rows() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "many.rs",
        "pub fn one() {}\npub fn two() {}\npub fn three() {}\n",
    );
    let ctx = test_ctx(tmp.path());

    let out = ContextPackTool
        .call(
            serde_json::json!({ "target": "many.rs", "kind": "path", "limit": 1 }),
            &ctx,
        )
        .await
        .unwrap();

    assert!(out.content.contains("one"), "{}", out.content);
    assert!(
        out.content.contains("more symbols omitted"),
        "{}",
        out.content
    );
}

// ---- centrality ranking + impact (code-graph layer) ----------------

/// Write a project `.cockpit/config.json` toggling centrality ranking.
/// The layered resolver makes the project layer win over any home
/// config, so these tool tests are deterministic on a dev machine.
fn set_centrality(root: &Path, enabled: bool) {
    write(
        root,
        ".cockpit/config.json",
        &format!("{{\"intelCentralityRanking\":{enabled}}}"),
    );
}

/// Fixture: `core.rs` is heavily called (high centrality), `util.rs`
/// barely. Both define `widget`, so `symbol_find("widget")` returns
/// both and centrality decides the order. `anchor` is unique to
/// `core.rs` and called many times to lift its score.
fn write_centrality_fixture(root: &Path) {
    write(root, "core.rs", "pub fn widget() {}\npub fn anchor() {}\n");
    write(root, "util.rs", "pub fn widget() {}\n");
    // A caller that invokes `anchor` (→ core.rs) many times.
    let mut body = String::from("pub fn driver() {\n");
    for _ in 0..10 {
        body.push_str("    anchor();\n");
    }
    body.push_str("}\n");
    write(root, "callers.rs", &body);
}

#[tokio::test]
async fn symbol_find_ranks_central_file_first_and_reverts_when_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    write_centrality_fixture(tmp.path());

    // Ranking ON: the heavily-called `core.rs` definition ranks above
    // the rarely-called `util.rs` one.
    set_centrality(tmp.path(), true);
    let ctx = test_ctx(tmp.path());
    let out = SymbolFindTool
        .call(serde_json::json!({ "name": "widget", "exact": true }), &ctx)
        .await
        .unwrap();
    let core_at = out.content.find("core.rs").expect("core.rs present");
    let util_at = out.content.find("util.rs").expect("util.rs present");
    assert!(
        core_at < util_at,
        "central core.rs must rank first when ranking is on; got:\n{}",
        out.content
    );

    // Ranking OFF: revert to exact (path, line) alphabetical order, so
    // `core.rs` still precedes `util.rs` alphabetically — pick a name
    // where disabling flips the order to prove the switch bites.
    set_centrality(tmp.path(), false);
    let ctx2 = test_ctx(tmp.path());
    let off = SymbolFindTool
        .call(
            serde_json::json!({ "name": "widget", "exact": true }),
            &ctx2,
        )
        .await
        .unwrap();
    // Same SET of results regardless of switch (additive — recall
    // unchanged).
    assert!(off.content.contains("core.rs"));
    assert!(off.content.contains("util.rs"));
}

/// A name where the central file sorts LAST alphabetically, so ranking
/// must reorder it to the front — and disabling must flip it back to
/// alphabetical. Proves the switch genuinely changes order.
#[tokio::test]
async fn symbol_find_ranking_flips_order_vs_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    // `zcore.rs` (sorts last) is heavily called; `acold.rs` (sorts
    // first) is not. Both define `gadget`.
    write(
        tmp.path(),
        "zcore.rs",
        "pub fn gadget() {}\npub fn beacon() {}\n",
    );
    write(tmp.path(), "acold.rs", "pub fn gadget() {}\n");
    let mut body = String::from("pub fn run() {\n");
    for _ in 0..10 {
        body.push_str("    beacon();\n");
    }
    body.push_str("}\n");
    write(tmp.path(), "callers.rs", &body);

    // ON: central `zcore.rs` ranked first despite sorting last.
    set_centrality(tmp.path(), true);
    let ctx = test_ctx(tmp.path());
    let on = SymbolFindTool
        .call(serde_json::json!({ "name": "gadget", "exact": true }), &ctx)
        .await
        .unwrap();
    assert!(
        on.content.find("zcore.rs").unwrap() < on.content.find("acold.rs").unwrap(),
        "ranking must lift central zcore.rs above acold.rs; got:\n{}",
        on.content
    );

    // OFF: alphabetical → `acold.rs` first.
    set_centrality(tmp.path(), false);
    let ctx2 = test_ctx(tmp.path());
    let off = SymbolFindTool
        .call(
            serde_json::json!({ "name": "gadget", "exact": true }),
            &ctx2,
        )
        .await
        .unwrap();
    assert!(
        off.content.find("acold.rs").unwrap() < off.content.find("zcore.rs").unwrap(),
        "disabled must revert to alphabetical (acold.rs first); got:\n{}",
        off.content
    );
}

#[tokio::test]
async fn search_ranks_central_file_first_and_is_additive() {
    let tmp = tempfile::tempdir().unwrap();
    // Both files contain the search term `gadget`; `zcore.rs` is
    // central (sorts last alphabetically), `acold.rs` is not.
    write(tmp.path(), "zcore.rs", "// gadget\npub fn beacon() {}\n");
    write(tmp.path(), "acold.rs", "// gadget\n");
    let mut body = String::from("pub fn run() {\n");
    for _ in 0..10 {
        body.push_str("    beacon();\n");
    }
    body.push_str("}\n");
    write(tmp.path(), "callers.rs", &body);

    // ON: central zcore.rs's match emitted before acold.rs's.
    set_centrality(tmp.path(), true);
    let ctx = test_ctx(tmp.path());
    let on = SearchTool
        .call(serde_json::json!({ "pattern": "gadget" }), &ctx)
        .await
        .unwrap();
    let on_lines: Vec<&str> = on
        .content
        .lines()
        .filter(|l| l.contains("gadget"))
        .collect();
    assert!(
        on_lines.iter().position(|l| l.contains("zcore.rs"))
            < on_lines.iter().position(|l| l.contains("acold.rs")),
        "central zcore.rs match must come first; got:\n{}",
        on.content
    );

    // OFF: file order (alphabetical from rg) → acold.rs first.
    set_centrality(tmp.path(), false);
    let ctx2 = test_ctx(tmp.path());
    let off = SearchTool
        .call(serde_json::json!({ "pattern": "gadget" }), &ctx2)
        .await
        .unwrap();

    // Additive: the SET of matched files is identical on vs off.
    let files_of = |s: &str| -> std::collections::BTreeSet<String> {
        s.lines()
            .filter(|l| l.contains("gadget"))
            .filter_map(|l| l.split_once(':').map(|(p, _)| p.to_string()))
            .collect()
    };
    assert_eq!(
        files_of(&on.content),
        files_of(&off.content),
        "ranking must be additive — same set of matches, only order differs"
    );
}

#[tokio::test]
async fn impact_reports_caller_to_callee_in_both_directions() {
    let tmp = tempfile::tempdir().unwrap();
    // `helper` is defined once and called from `driver`'s body.
    write(
        tmp.path(),
        "lib.rs",
        "pub fn helper() {}\npub fn driver() {\n    helper();\n}\n",
    );
    let ctx = test_ctx(tmp.path());

    // Direction 1: callers of `helper` includes `driver`.
    let callers = ImpactTool
        .call(serde_json::json!({ "name": "helper" }), &ctx)
        .await
        .unwrap();
    assert!(
        callers.content.contains("Callers"),
        "got:\n{}",
        callers.content
    );
    assert!(
        callers.content.contains("lib.rs") && callers.content.contains("driver"),
        "helper's callers must list driver at lib.rs; got:\n{}",
        callers.content
    );

    // Direction 2: calls inside `driver` include `helper -> lib.rs`.
    let calls = ImpactTool
        .call(serde_json::json!({ "name": "driver" }), &ctx)
        .await
        .unwrap();
    assert!(calls.content.contains("Calls"), "got:\n{}", calls.content);
    assert!(
        calls.content.contains("helper -> lib.rs"),
        "driver's calls must resolve helper to lib.rs; got:\n{}",
        calls.content
    );
}

#[tokio::test]
async fn impact_omits_ambiguous_callee() {
    let tmp = tempfile::tempdir().unwrap();
    // `dup` is defined in TWO files → ambiguous → high-precision omit.
    write(tmp.path(), "a.rs", "pub fn dup() {}\n");
    write(tmp.path(), "b.rs", "pub fn dup() {}\n");
    write(tmp.path(), "c.rs", "pub fn caller() {\n    dup();\n}\n");
    let ctx = test_ctx(tmp.path());

    // `caller`'s outgoing call to `dup` resolves to 2 defs → omitted.
    let calls = ImpactTool
        .call(serde_json::json!({ "name": "caller" }), &ctx)
        .await
        .unwrap();
    assert!(
        calls.content.contains("Calls: none"),
        "ambiguous callee must be omitted (no guessed edge); got:\n{}",
        calls.content
    );

    // And `dup` reports no callers (the edge is ambiguous either way).
    let callers = ImpactTool
        .call(serde_json::json!({ "name": "dup", "path": "a.rs" }), &ctx)
        .await
        .unwrap();
    assert!(
        callers.content.contains("Callers: none"),
        "ambiguous edge must not be asserted as a caller; got:\n{}",
        callers.content
    );
}

#[tokio::test]
async fn impact_filters_ubiquitous_name() {
    let tmp = tempfile::tempdir().unwrap();
    // `get` is on the denylist — even a unique def + call is filtered.
    write(
        tmp.path(),
        "lib.rs",
        "pub fn get() {}\npub fn user() {\n    get();\n}\n",
    );
    let ctx = test_ctx(tmp.path());

    let calls = ImpactTool
        .call(serde_json::json!({ "name": "user" }), &ctx)
        .await
        .unwrap();
    assert!(
        calls.content.contains("Calls: none"),
        "denylisted `get` must be filtered from edges; got:\n{}",
        calls.content
    );
    let callers = ImpactTool
        .call(serde_json::json!({ "name": "get" }), &ctx)
        .await
        .unwrap();
    assert!(
        callers.content.contains("Callers: none"),
        "denylisted `get` must report no callers; got:\n{}",
        callers.content
    );
}

#[tokio::test]
async fn impact_renders_empty_sections_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    // `lonely` has no callers and an empty body (no calls).
    write(tmp.path(), "lib.rs", "pub fn lonely() {}\n");
    let ctx = test_ctx(tmp.path());
    let out = ImpactTool
        .call(serde_json::json!({ "name": "lonely" }), &ctx)
        .await
        .unwrap();
    assert!(
        out.content.contains("Callers: none"),
        "got:\n{}",
        out.content
    );
    assert!(out.content.contains("Calls: none"), "got:\n{}", out.content);
}

#[tokio::test]
async fn impact_unknown_symbol_reports_no_match() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "lib.rs", "pub fn known() {}\n");
    let ctx = test_ctx(tmp.path());
    let out = ImpactTool
        .call(serde_json::json!({ "name": "nope" }), &ctx)
        .await
        .unwrap();
    assert!(
        out.content.contains("No symbol matches"),
        "got:\n{}",
        out.content
    );
}

fn git(root: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn git_commit(root: &Path, message: &str) {
    let status = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=Cockpit Test",
            "-c",
            "user.email=cockpit@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            message,
        ])
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success(), "git commit failed");
}

fn init_git(root: &Path) {
    git(root, &["init", "-q"]);
    git(root, &["add", "."]);
    git_commit(root, "init");
}

#[tokio::test]
async fn change_impact_worktree_diff_maps_changed_function() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "lib.rs",
        "pub fn helper() {\n    let value = 1;\n}\n",
    );
    init_git(tmp.path());
    write(
        tmp.path(),
        "lib.rs",
        "pub fn helper() {\n    let value = 2;\n}\n",
    );
    let ctx = test_ctx(tmp.path());
    let out = ChangeImpactTool
        .call(serde_json::json!({}), &ctx)
        .await
        .unwrap();
    assert!(out.content.contains("M lib.rs"), "{}", out.content);
    assert!(out.content.contains("helper"), "{}", out.content);
    assert!(out.content.contains("symbols:"), "{}", out.content);
}

#[tokio::test]
async fn change_impact_includes_caller_context_and_high_risk() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "lib.rs",
        "pub fn helper() {\n    let value = 1;\n}\npub fn driver() {\n    helper();\n}\n",
    );
    init_git(tmp.path());
    write(
        tmp.path(),
        "lib.rs",
        "pub fn helper() {\n    let value = 2;\n}\npub fn driver() {\n    helper();\n}\n",
    );
    let ctx = test_ctx(tmp.path());
    let out = ChangeImpactTool
        .call(serde_json::json!({}), &ctx)
        .await
        .unwrap();
    assert!(out.content.contains("risk=high"), "{}", out.content);
    assert!(out.content.contains("caller lib.rs"), "{}", out.content);
    assert!(out.content.contains("driver"), "{}", out.content);
}

#[tokio::test]
async fn change_impact_reports_added_deleted_and_renamed_files() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "deleted.rs", "pub fn removed() {}\n");
    write(tmp.path(), "old.rs", "pub fn moved() {}\n");
    init_git(tmp.path());
    write(tmp.path(), "added.rs", "pub fn added() {}\n");
    std::fs::remove_file(tmp.path().join("deleted.rs")).unwrap();
    git(tmp.path(), &["mv", "old.rs", "new.rs"]);
    let ctx = test_ctx(tmp.path());
    let out = ChangeImpactTool
        .call(serde_json::json!({}), &ctx)
        .await
        .unwrap();
    assert!(out.content.contains("A added.rs"), "{}", out.content);
    assert!(out.content.contains("D deleted.rs"), "{}", out.content);
    assert!(out.content.contains("R new.rs"), "{}", out.content);
    assert!(out.content.contains("from old.rs"), "{}", out.content);
}

#[tokio::test]
async fn change_impact_invalid_ref_returns_invalid_input() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "lib.rs", "pub fn known() {}\n");
    init_git(tmp.path());
    let ctx = test_ctx(tmp.path());
    let err = ChangeImpactTool
        .call(serde_json::json!({ "base": "definitely-not-a-ref" }), &ctx)
        .await
        .unwrap_err();
    assert!(
        format!("{err}").contains("invalid git diff request"),
        "{err}"
    );
}

#[tokio::test]
async fn change_impact_non_git_directory_reports_diagnostic() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "lib.rs", "pub fn known() {}\n");
    let ctx = test_ctx(tmp.path());
    let out = ChangeImpactTool
        .call(serde_json::json!({}), &ctx)
        .await
        .unwrap();
    assert!(out.content.contains("no git worktree"), "{}", out.content);
}

#[tokio::test]
async fn change_impact_path_filter_limits_changed_files() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "src/a.rs",
        "pub fn a() {\n    let value = 1;\n}\n",
    );
    write(
        tmp.path(),
        "tests/b.rs",
        "pub fn b() {\n    let value = 1;\n}\n",
    );
    init_git(tmp.path());
    write(
        tmp.path(),
        "src/a.rs",
        "pub fn a() {\n    let value = 2;\n}\n",
    );
    write(
        tmp.path(),
        "tests/b.rs",
        "pub fn b() {\n    let value = 2;\n}\n",
    );
    let ctx = test_ctx(tmp.path());
    let out = ChangeImpactTool
        .call(serde_json::json!({ "path": "src" }), &ctx)
        .await
        .unwrap();
    assert!(out.content.contains("M src/a.rs"), "{}", out.content);
    assert!(!out.content.contains("tests/b.rs"), "{}", out.content);
}

#[tokio::test]
async fn change_impact_risk_tiers_are_deterministic() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "leaf.rs",
        "pub fn leaf() {\n    let value = 1;\n}\n",
    );
    write(
        tmp.path(),
        "called.rs",
        "pub fn called() {\n    let value = 1;\n}\npub fn user() {\n    called();\n}\n",
    );
    init_git(tmp.path());
    write(
        tmp.path(),
        "leaf.rs",
        "pub fn leaf() {\n    let value = 2;\n}\n",
    );
    write(
        tmp.path(),
        "called.rs",
        "pub fn called() {\n    let value = 2;\n}\npub fn user() {\n    called();\n}\n",
    );
    let ctx = test_ctx(tmp.path());
    let first = ChangeImpactTool
        .call(serde_json::json!({}), &ctx)
        .await
        .unwrap()
        .content;
    let second = ChangeImpactTool
        .call(serde_json::json!({}), &ctx)
        .await
        .unwrap()
        .content;
    assert_eq!(first, second);
    assert!(first.contains("called.rs risk=high"), "{}", first);
    assert!(first.contains("leaf.rs risk=medium"), "{}", first);
}
