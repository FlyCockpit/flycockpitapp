-- Call-graph centrality materialization (GOALS §21, prompt
-- `code-graph-centrality-and-context.md`). A small per-file score table
-- recomputed wholesale once per `ensure_fresh` pass that wrote any chunk
-- (a cheap SQL aggregate join over intel_callsites ⋈ intel_symbols — no
-- re-parse). Read on the `search`/`symbol_find` ranking hot path.
--
-- `score` is the weighted in-degree per file: every resolved callsite
-- contributes 1/M (M = number of non-test definitions its callee_name
-- resolves to) onto the file that contains each resolved def. An
-- absent/empty row set degrades gracefully to unranked order — this
-- table is purely an additive ranking signal, never a filter.
--
-- Project-scoped (`root`) like every other intel_* table so multi-project
-- (§M6) stays an additive change. No FK to intel_files: the table is
-- rebuilt wholesale each pass, so a stale row can never outlive the
-- rebuild, and skipping the cascade keeps the wholesale DELETE cheap.

CREATE TABLE intel_centrality (
    root  TEXT NOT NULL,
    path  TEXT NOT NULL,
    score REAL NOT NULL,
    PRIMARY KEY (root, path)
);
